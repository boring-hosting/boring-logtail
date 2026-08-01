// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{HashMap, ProgramArray, RingBuf},
    programs::TracePointContext,
};
use boring_logtail_common::{
    FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK, FLAG_READ_FAILED, FLAG_RESULT_KNOWN, FLAG_TRUNCATED,
    SYSCALL_WRITE, WRITE_CHUNK_SIZE, WRITE_EVENT_VERSION, WriteChunk, WriteEvent, next_write_chunk,
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

#[map]
static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static ALLOWED_FDS: HashMap<u32, u8> = HashMap::with_max_entries(2, 0);

#[map]
static WRITE_STARTS: HashMap<u64, WriteStart> = HashMap::with_max_entries(16_384, 0);

// write entry -> WRITE_STARTS -> write exit -> WRITE_JOBS
//     -> tail call WRITE_CHUNK_WORKER[0] once per emitted chunk
#[map]
static WRITE_JOBS: HashMap<u64, WriteJob> = HashMap::with_max_entries(16_384, 0);

#[map]
static WRITE_CHUNK_WORKER: ProgramArray = ProgramArray::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn boring_logtail_enter(ctx: TracePointContext) -> u32 {
    match try_boring_logtail_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_boring_logtail_enter(ctx: TracePointContext) -> Result<u32, u32> {
    // sys_enter_write signature: int write(unsigned int fd, const char *buf, size_t count)
    // arg(0) = fd, arg(1) = buf, arg(2) = count
    // These offsets describe the 64-bit tracepoint ABI. Supporting a 32-bit
    // userspace ABI requires decoding its argument layout separately.
    let fd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1_u32)? };

    // buf is a userspace pointer...
    let buf: usize = unsafe { ctx.read_at(24).map_err(|_| 1_u32)? };
    let count: usize = unsafe { ctx.read_at(32).map_err(|_| 1_u32)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Ignore the logger itself and accept only configured output descriptors.
    if unsafe { IGNORED_PIDS.get(pid) }.is_some() || unsafe { ALLOWED_FDS.get(fd) }.is_none() {
        return Ok(0);
    }

    let start = WriteStart {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        buffer: buf as u64,
        requested_len: count as u64,
        fd,
        pid,
        tid: pid_tgid as u32,
    };
    WRITE_STARTS.insert(pid_tgid, start, 0).map_err(|_| 1_u32)?;

    Ok(0)
}

#[tracepoint]
pub fn boring_logtail_exit(ctx: TracePointContext) -> u32 {
    match try_boring_logtail_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_boring_logtail_exit(ctx: TracePointContext) -> Result<u32, u32> {
    // sys_exit_write exposes the syscall return value at byte offset 16.
    let result: i64 = unsafe { ctx.read_at(16).map_err(|_| 1_u32)? };
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(start) = (unsafe { WRITE_STARTS.get(pid_tgid).copied() }) else {
        return Ok(0);
    };
    // Remove entry state on every exit, including failed and zero-byte writes.
    WRITE_STARTS.remove(pid_tgid).map_err(|_| 1_u32)?;

    let job = WriteJob {
        start,
        result,
        chunk_number: 0,
    };
    WRITE_JOBS.insert(pid_tgid, job, 0).map_err(|_| 1_u32)?;

    unsafe { WRITE_CHUNK_WORKER.tail_call(&ctx, 0) };
    // Reached only if userspace did not configure the jump table or the
    // runtime tail-call bound was exhausted.
    let _ = WRITE_JOBS.remove(pid_tgid);
    Ok(0)
}

#[tracepoint]
pub fn boring_logtail_send_write_chunk(ctx: TracePointContext) -> u32 {
    match try_send_write_chunk(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_send_write_chunk(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(mut job) = (unsafe { WRITE_JOBS.get(pid_tgid).copied() }) else {
        return Ok(0);
    };

    let Some(chunk) = next_write_chunk(job.result, job.chunk_number) else {
        let _ = WRITE_JOBS.remove(pid_tgid);
        return Err(1);
    };

    if send_write_event(&job.start, job.result, chunk).is_err() {
        let _ = WRITE_JOBS.remove(pid_tgid);
        return Err(1);
    }

    if chunk.is_complete || chunk.is_truncated {
        WRITE_JOBS.remove(pid_tgid).map_err(|_| 1_u32)?;
        return Ok(0);
    }

    job.chunk_number += 1;
    WRITE_JOBS.insert(pid_tgid, job, 0).map_err(|_| 1_u32)?;
    unsafe { WRITE_CHUNK_WORKER.tail_call(&ctx, 0) };
    let _ = WRITE_JOBS.remove(pid_tgid);

    Ok(0)
}

fn send_write_event(start: &WriteStart, result: i64, chunk: WriteChunk) -> Result<(), u32> {
    let Some(mut entry) = EVENTS.reserve::<WriteEvent>(0) else {
        return Err(1);
    };

    let mut flags = FLAG_RESULT_KNOWN;
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
        syscall: SYSCALL_WRITE,
        timestamp_ns: start.timestamp_ns,
        cgroup_id: start.cgroup_id,
        operation_id: start.timestamp_ns,
        result,
        pid: start.pid,
        tid: start.tid,
        fd: start.fd,
        requested_len: start.requested_len.min(u32::MAX as u64) as u32,
        data_offset: chunk.offset,
        captured_len: 0,
        data: [0; WRITE_CHUNK_SIZE],
    });

    let captured_len = chunk.captured_len as usize;
    if captured_len > 0
        && unsafe {
            bpf_probe_read_user_buf(
                (start.buffer + chunk.offset as u64) as *const u8,
                &mut event.data[..captured_len],
            )
        }
        .is_err()
    {
        event.flags |= FLAG_READ_FAILED;
    } else {
        event.captured_len = captured_len as u32;
    }
    entry.submit(0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
