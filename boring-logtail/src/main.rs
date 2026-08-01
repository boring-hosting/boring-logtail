// SPDX-License-Identifier: GPL-3.0-or-later

use aya::{
    Ebpf,
    maps::{HashMap, ProgramArray, RingBuf},
    programs::TracePoint,
};
use boring_logtail::{decode_event, pipeline::ChunkChunker};

#[rustfmt::skip]
use log::debug;
use tokio::{
    signal::{self, unix::SignalKind},
    task::JoinHandle,
};

struct LogTailApplication {
    // Keeping Ebpf alive keeps its programs, links, and maps alive.
    _ebpf: Ebpf,
    // The task owns the ring buffer because tokio::spawn requires 'static data.
    event_task: Option<JoinHandle<anyhow::Result<()>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let application = LogTailApplication::start()?;
    println!("Waiting for a shutdown signal...");
    shutdown_signal().await?;
    println!("Exiting...");
    application.shutdown().await;

    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        result = signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

impl LogTailApplication {
    fn start() -> anyhow::Result<Self> {
        raise_memlock_limit();

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/boring-logtail"
        )))?;

        configure_capture_filters(&mut ebpf)?;
        configure_chunk_worker(&mut ebpf)?;
        // Attach exit first so no entry can be recorded without its matching exit
        // handler already being available.
        load_and_attach_exit_program(&mut ebpf)?;
        load_and_attach_enter_program(&mut ebpf)?;
        let event_task = spawn_event_task(&mut ebpf)?;

        Ok(Self {
            _ebpf: ebpf,
            event_task: Some(event_task),
        })
    }

    async fn shutdown(mut self) {
        if let Some(event_task) = self.event_task.take() {
            event_task.abort();
            let _ = event_task.await;
        }
    }
}

fn raise_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn configure_capture_filters(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    // Do not trace this process: rendering an event writes to stdout and would
    // otherwise feed the logger's own output back into the tracepoint.
    let mut ignored_pids = HashMap::<_, u32, u8>::try_from(ebpf.map_mut("IGNORED_PIDS").unwrap())?;
    ignored_pids.insert(std::process::id(), 1, 0)?;

    let mut allowed_fds = HashMap::<_, u32, u8>::try_from(ebpf.map_mut("ALLOWED_FDS").unwrap())?;
    allowed_fds.insert(1, 1, 0)?;
    allowed_fds.insert(2, 1, 0)?;
    Ok(())
}

fn configure_chunk_worker(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let chunk_worker: &mut TracePoint = ebpf
        .program_mut("boring_logtail_send_write_chunk")
        .unwrap()
        .try_into()?;
    chunk_worker.load()?;
    let chunk_worker_fd = chunk_worker.fd()?.try_clone()?;
    // This worker is not attached to an event. The write-exit program starts
    // it through slot 0, then it calls itself until the whole write is sent.
    // Borrow the map rather than taking ownership of it. The exit program has
    // not been loaded yet and still needs the map FD for its relocation. If a
    // locally owned map is dropped here, that FD is closed before the later
    // BPF_PROG_LOAD call.
    let mut chunk_worker_slot =
        ProgramArray::try_from(ebpf.map_mut("WRITE_CHUNK_WORKER").unwrap())?;
    chunk_worker_slot.set(0, &chunk_worker_fd, 0)?;
    Ok(())
}

fn spawn_event_task(ebpf: &mut Ebpf) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let mut chunker = ChunkChunker::new();

    Ok(tokio::spawn(async move {
        loop {
            let mut guard = ring_buf.readable_mut().await?;
            while let Some(item) = guard.get_inner_mut().next() {
                match decode_event(&item) {
                    Ok(event) => {
                        match chunker.accept(event) {
                            Ok(r) => {
                                let r = match r {
                                    Some(v) => v,
                                    None => continue,
                                };

                                let s = match str::from_utf8(&r) {
                                    Ok(v) => v,
                                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                                };

                                println!("payload: {}", s)
                            }
                            Err(err) => {
                                println!("join error {}", err)
                            }
                        };
                    }
                    Err(error) => debug!("discarding malformed ring-buffer record: {error}"),
                }
            }
            guard.clear_ready();
        }
    }))
}

fn load_and_attach_enter_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let enter_program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_enter")
        .unwrap()
        .try_into()?;
    enter_program.load()?;
    enter_program.attach("syscalls", "sys_enter_write")?;
    Ok(())
}

fn load_and_attach_exit_program(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let exit_program: &mut TracePoint = ebpf
        .program_mut("boring_logtail_exit")
        .unwrap()
        .try_into()?;
    exit_program.load()?;
    exit_program.attach("syscalls", "sys_exit_write")?;
    Ok(())
}
