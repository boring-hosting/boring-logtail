// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]
#![no_main]

//! Kernel-side capture, kept intentionally small and bounded.
//!
//! Plain version: remember a write when a thread enters the syscall, wait for
//! the kernel to say how many bytes really got written, then copy only those
//! bytes into fixed-size ring-buffer messages. `writev` does the same walk
//! across several user buffers.
//!
//! eBPF programs cannot loop or allocate like normal Rust. Maps hold state
//! between syscall entry and exit; tail calls split chunk copying into bounded
//! verifier-sized steps. Every limit is visible in `blt-abi`. Userspace does
//! reconstruction, framing, and Kubernetes enrichment. See `learn/ebpf.org`.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{CgroupArray, HashMap, ProgramArray, RingBuf},
    programs::TracePointContext,
};
use blt_abi::{
    CAPTURE_SOURCE_APPLICATION_SYSCALL, FLAG_FD_KNOWN, FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK,
    FLAG_READ_FAILED, FLAG_RESULT_KNOWN, FLAG_TRUNCATED, MAX_BYTES_PER_WRITE,
    MAX_IOVECS_PER_WRITEV, OPERATION_WRITE, OPERATION_WRITEV, WRITE_CHUNK_SIZE,
    WRITE_EVENT_VERSION, WriteChunk, WriteEvent, next_write_chunk,
};

#[repr(C)]
#[derive(Clone, Copy)]

struct WriteStart {
    timestamp_ns: u64,
    cgroup_id: u64,
    buffer: u64,
    requested_len: u64,
    fd: u32,
    pid: u32,
    tid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]

struct WriteJob {
    start: WriteStart,
    result: i64,
    chunk_number: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]

struct UserIovec {
    base: u64,
    len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]

struct WritevStart {
    timestamp_ns: u64,
    cgroup_id: u64,
    vectors: u64,
    requested_len: u64,
    fd: u32,
    vector_count: u32,
    pid: u32,
    tid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]

struct WritevJob {
    start: WritevStart,
    result: i64,
    vector_offset: u64,
    vector_index: u32,
    data_offset: u32,
    remaining: u32,
    chunk_number: u32,
}

#[repr(C)]

struct EventMeta {
    timestamp_ns: u64,
    cgroup_id: u64,
    requested_len: u64,
    result: i64,
    fd: u32,
    pid: u32,
    tid: u32,
    operation_kind: u16,
}

#[map]
/// The host writes its own cgroup here so capture can reject collector output.
/// Without this guard, printing a captured log could capture that print again.

static COLLECTOR_CGROUP: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map]
/// Descriptor numbers admitted by userspace; currently conventional fd 1/2.
/// This is a candidate-stream filter, not proof of durable stdout identity.

static ALLOWED_FDS: HashMap<u32, u8> = HashMap::with_max_entries(2, 0);

#[map]
/// Entry facts waiting for the matching `sys_exit_write` on the same thread.

static WRITE_STARTS: HashMap<u64, WriteStart> = HashMap::with_max_entries(16_384, 0);

#[map]
/// Completed `write` results being emitted one bounded chunk at a time.

static WRITE_JOBS: HashMap<u64, WriteJob> = HashMap::with_max_entries(16_384, 0);

#[map]
/// Tail-call target used to continue a large `write` without one huge program.

static WRITE_WORKER: ProgramArray = ProgramArray::with_max_entries(1, 0);

#[map]
/// Entry facts waiting for the matching `sys_exit_writev`.

static WRITEV_STARTS: HashMap<u64, WritevStart> = HashMap::with_max_entries(16_384, 0);

#[map]
/// Completed `writev` results plus the current position in its iovec array.

static WRITEV_JOBS: HashMap<u64, WritevJob> = HashMap::with_max_entries(16_384, 0);

#[map]
/// Tail-call target used to advance through bounded `writev` chunks.

static WRITEV_WORKER: ProgramArray = ProgramArray::with_max_entries(1, 0);

#[map]
/// Fixed-size messages consumed by the userspace ring-buffer task.

static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Reject collector recursion first, then accept only configured descriptors.

fn admitted(fd: u32) -> bool {
    matches!(COLLECTOR_CGROUP.current_task_under_cgroup(0), Ok(false))
        // SAFETY: eBPF map lookup returns a verifier-tracked pointer. We only
        // test for presence during this expression and never retain the value.
        && unsafe { ALLOWED_FDS.get(fd) }.is_some()
}

#[tracepoint]
/// Saves arguments from `sys_enter_write`; no payload is copied yet.
///
/// Copying at entry would be dishonest because the syscall may fail or perform
/// a partial write. `pid_tgid` keys the state by thread until syscall exit.

pub fn boring_logtail_enter(ctx: TracePointContext) -> u32 {
    // SAFETY: these offsets are the x86_64 `sys_enter` tracepoint ABI fields
    // for fd, buffer, and count. `read_at` asks the verifier to bounds-check
    // each read and failure drops this observation.
    let fd: u32 = match unsafe { ctx.read_at(16) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    if !admitted(fd) {
        return 0;
    }

    // SAFETY: same tracepoint layout argument as the fd read above.
    let buffer: usize = match unsafe { ctx.read_at(24) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    // SAFETY: same tracepoint layout argument as the fd read above.
    let requested_len: usize = match unsafe { ctx.read_at(32) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();

    let start = WriteStart {
        // SAFETY: these helpers read current-task kernel metadata and do not
        // dereference caller-provided pointers.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        // SAFETY: same current-task helper contract as the timestamp above.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        buffer: buffer as u64,
        requested_len: requested_len as u64,
        fd,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
    };

    let _ = WRITE_STARTS.insert(pid_tgid, start, 0);

    0
}

#[tracepoint]
/// Pairs `sys_exit_write` with its saved entry and starts bounded emission.

pub fn boring_logtail_exit(ctx: TracePointContext) -> u32 {
    // SAFETY: offset 16 is the signed result field in the x86_64 `sys_exit`
    // tracepoint layout; a failed checked read drops the observation.
    let result: i64 = match unsafe { ctx.read_at(16) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: the map pointer is copied immediately before any mutation can
    // invalidate it; no reference escapes this expression.
    let Some(start) = (unsafe { WRITE_STARTS.get(pid_tgid).copied() }) else {
        return 0;
    };

    let _ = WRITE_STARTS.remove(pid_tgid);

    let _ = WRITE_JOBS.insert(
        pid_tgid,
        WriteJob {
            start,
            result,
            chunk_number: 0,
        },
        0,
    );

    // SAFETY: userspace installs the chunk-worker program at index 0 before
    // attaching entry hooks. A missing target simply makes the tail call fail.
    unsafe { WRITE_WORKER.tail_call(&ctx, 0) };

    0
}

#[tracepoint]
/// Emits one `write` chunk and tail-calls itself when more bounded work remains.

pub fn boring_logtail_send_write_chunk(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: copy the verifier-tracked map value immediately; retain no map
    // reference across removal, insertion, or the tail call.
    let Some(mut job) = (unsafe { WRITE_JOBS.get(pid_tgid).copied() }) else {
        return 0;
    };

    let Some(chunk) = next_write_chunk(job.result, job.chunk_number) else {
        let _ = WRITE_JOBS.remove(pid_tgid);

        return 0;
    };

    emit_event(
        &EventMeta {
            timestamp_ns: job.start.timestamp_ns,
            cgroup_id: job.start.cgroup_id,
            requested_len: job.start.requested_len,
            result: job.result,
            fd: job.start.fd,
            pid: job.start.pid,
            tid: job.start.tid,
            operation_kind: OPERATION_WRITE,
        },
        (job.start.buffer + chunk.offset as u64) as *const u8,
        chunk,
    );

    if chunk.is_complete || chunk.is_truncated {
        let _ = WRITE_JOBS.remove(pid_tgid);

        return 0;
    }

    job.chunk_number += 1;

    let _ = WRITE_JOBS.insert(pid_tgid, job, 0);

    // SAFETY: index 0 is configured as this worker by userspace; failure ends
    // this attempt without executing an arbitrary program.
    unsafe { WRITE_WORKER.tail_call(&ctx, 0) };

    0
}

#[tracepoint]
/// Saves and bounds the `writev` vector description at syscall entry.
///
/// We read vector lengths now to preserve the requested total, but defer byte
/// copying until exit tells us how much of the logical vector stream succeeded.

pub fn boring_logtail_enter_writev(ctx: TracePointContext) -> u32 {
    // SAFETY: offsets 16/24/32 are fd, iovec pointer, and iovec count in the
    // x86_64 `sys_enter_writev` tracepoint layout. Checked reads fail closed.
    let fd: u32 = match unsafe { ctx.read_at(16) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    if !admitted(fd) {
        return 0;
    }

    // SAFETY: same checked tracepoint-layout argument as the fd read above.
    let vectors: usize = match unsafe { ctx.read_at(24) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    // SAFETY: same checked tracepoint-layout argument as the fd read above.
    let vector_count: usize = match unsafe { ctx.read_at(32) } {
        Ok(value) if value <= MAX_IOVECS_PER_WRITEV => value,
        _ => return 0,
    };

    let mut requested_len = 0u64;

    for index in 0..MAX_IOVECS_PER_WRITEV {
        if index >= vector_count {
            break;
        }

        let address = vectors + index * core::mem::size_of::<UserIovec>();

        // SAFETY: `address` names one element in the caller-provided iovec
        // array. The helper performs the kernel-supported checked user-memory
        // read; failure aborts capture rather than trusting partial metadata.
        let vector = match unsafe { bpf_probe_read_user(address as *const UserIovec) } {
            Ok(value) => value,
            Err(_) => return 0,
        };

        requested_len = requested_len.saturating_add(vector.len);
    }

    let pid_tgid = bpf_get_current_pid_tgid();

    let start = WritevStart {
        // SAFETY: current-task metadata helpers; no user pointer is involved.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        // SAFETY: same current-task helper contract as the timestamp above.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        vectors: vectors as u64,
        requested_len,
        fd,
        vector_count: vector_count as u32,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
    };

    let _ = WRITEV_STARTS.insert(pid_tgid, start, 0);

    0
}

#[tracepoint]
/// Pairs `sys_exit_writev` with entry state and seeds the bounded vector walk.

pub fn boring_logtail_exit_writev(ctx: TracePointContext) -> u32 {
    // SAFETY: offset 16 is the signed result in the x86_64 `sys_exit` layout;
    // `read_at` is checked and failure drops the observation.
    let result: i64 = match unsafe { ctx.read_at(16) } {
        Ok(value) => value,
        Err(_) => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: copy the map value immediately; no reference survives removal.
    let Some(start) = (unsafe { WRITEV_STARTS.get(pid_tgid).copied() }) else {
        return 0;
    };

    let _ = WRITEV_STARTS.remove(pid_tgid);

    let remaining = if result > 0 {
        (result as u64).min(MAX_BYTES_PER_WRITE as u64) as u32
    } else {
        0
    };

    let _ = WRITEV_JOBS.insert(
        pid_tgid,
        WritevJob {
            start,
            result,
            vector_offset: 0,
            vector_index: 0,
            data_offset: 0,
            remaining,
            chunk_number: 0,
        },
        0,
    );

    // SAFETY: userspace installs the writev worker at index 0 before hooks are
    // attached. A missing program means a failed tail call, not arbitrary code.
    unsafe { WRITEV_WORKER.tail_call(&ctx, 0) };

    0
}

#[tracepoint]
/// Emits one logical slice of `writev`, advancing across empty/exhausted iovecs.

pub fn boring_logtail_send_writev_chunk(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    // SAFETY: copy the verifier-tracked map value before mutating the map.
    let Some(mut job) = (unsafe { WRITEV_JOBS.get(pid_tgid).copied() }) else {
        return 0;
    };

    if job.result <= 0 {
        emit_event(
            &EventMeta {
                timestamp_ns: job.start.timestamp_ns,
                cgroup_id: job.start.cgroup_id,
                requested_len: job.start.requested_len,
                result: job.result,
                fd: job.start.fd,
                pid: job.start.pid,
                tid: job.start.tid,
                operation_kind: OPERATION_WRITEV,
            },
            core::ptr::null(),
            WriteChunk {
                offset: 0,
                captured_len: 0,
                is_first: true,
                is_complete: true,
                is_truncated: false,
            },
        );

        let _ = WRITEV_JOBS.remove(pid_tgid);

        return 0;
    }

    let mut vector = UserIovec { base: 0, len: 0 };

    let mut found = false;

    for _ in 0..MAX_IOVECS_PER_WRITEV {
        if job.vector_index >= job.start.vector_count {
            break;
        }

        let address =
            job.start.vectors + job.vector_index as u64 * core::mem::size_of::<UserIovec>() as u64;

        // SAFETY: the vector index is bounded by both the saved count and
        // MAX_IOVECS_PER_WRITEV. The helper checks the user-memory read.
        vector = match unsafe { bpf_probe_read_user(address as *const UserIovec) } {
            Ok(value) => value,
            Err(_) => {
                let _ = WRITEV_JOBS.remove(pid_tgid);

                return 0;
            }
        };

        if job.vector_offset < vector.len {
            found = true;

            break;
        }

        job.vector_index += 1;

        job.vector_offset = 0;
    }

    if !found {
        let _ = WRITEV_JOBS.remove(pid_tgid);

        return 0;
    }

    let captured_len = vector
        .len
        .saturating_sub(job.vector_offset)
        .min(job.remaining as u64)
        .min(WRITE_CHUNK_SIZE as u64) as u32;

    let complete = captured_len == job.remaining;

    let chunk_limit = job.chunk_number as usize + 1 == blt_abi::MAX_CHUNKS_PER_WRITE;

    let truncated =
        (complete && job.result as u64 > MAX_BYTES_PER_WRITE as u64) || (chunk_limit && !complete);

    emit_event(
        &EventMeta {
            timestamp_ns: job.start.timestamp_ns,
            cgroup_id: job.start.cgroup_id,
            requested_len: job.start.requested_len,
            result: job.result,
            fd: job.start.fd,
            pid: job.start.pid,
            tid: job.start.tid,
            operation_kind: OPERATION_WRITEV,
        },
        (vector.base + job.vector_offset) as *const u8,
        WriteChunk {
            offset: job.data_offset,
            captured_len,
            is_first: job.data_offset == 0,
            is_complete: complete && !truncated,
            is_truncated: truncated,
        },
    );

    if complete || truncated {
        let _ = WRITEV_JOBS.remove(pid_tgid);

        return 0;
    }

    job.vector_offset += captured_len as u64;

    job.data_offset += captured_len;

    job.remaining -= captured_len;

    job.chunk_number += 1;

    let _ = WRITEV_JOBS.insert(pid_tgid, job, 0);

    // SAFETY: index 0 is the host-configured continuation for this worker.
    unsafe { WRITEV_WORKER.tail_call(&ctx, 0) };

    0
}

#[inline(never)]
/// Reserves one ABI record, copies a bounded payload, and publishes atomically.
///
/// Ring-buffer reservation failure is an explicit capture loss boundary: no
/// partially initialized event is visible. A failed user-memory read publishes
/// metadata plus `FLAG_READ_FAILED` so userspace can mark the gap honestly.

fn emit_event(meta: &EventMeta, payload: *const u8, chunk: WriteChunk) {
    let Some(mut entry) = EVENTS.reserve::<WriteEvent>(0) else {
        return;
    };

    let mut flags = FLAG_RESULT_KNOWN | FLAG_FD_KNOWN;

    if chunk.is_first {
        flags |= FLAG_FIRST_CHUNK;
    }

    if chunk.is_complete {
        flags |= FLAG_LAST_CHUNK;
    }

    if chunk.is_truncated {
        flags |= FLAG_TRUNCATED;
    }

    let event = entry.write(WriteEvent {
        abi_version: WRITE_EVENT_VERSION,
        flags,
        capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
        operation_kind: meta.operation_kind,
        timestamp_ns: meta.timestamp_ns,
        cgroup_id: meta.cgroup_id,
        operation_id: meta.timestamp_ns,
        source_id: 0,
        result: meta.result,
        pid: meta.pid,
        tid: meta.tid,
        fd: meta.fd,
        requested_len: meta.requested_len.min(u32::MAX as u64) as u32,
        data_offset: chunk.offset,
        captured_len: 0,
        data: [0; WRITE_CHUNK_SIZE],
    });

    let captured_len = (chunk.captured_len as usize).min(WRITE_CHUNK_SIZE);

    // SAFETY: `event.data` is a live 256-byte array inside our reserved entry,
    // and `captured_len` was clamped to that exact capacity above.
    let target = unsafe { core::slice::from_raw_parts_mut(event.data.as_mut_ptr(), captured_len) };

    // SAFETY: payload is a syscall-supplied userspace address. The eBPF helper
    // performs the checked copy into the bounded kernel-owned target slice.
    if captured_len > 0 && unsafe { bpf_probe_read_user_buf(payload, target) }.is_err() {
        event.flags |= FLAG_READ_FAILED;
    } else {
        event.captured_len = chunk.captured_len;
    }

    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
/// eBPF has no unwinder or process to abort; verifier-safe code should not panic.

fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]

static LICENSE: [u8; 4] = *b"GPL\0";
