pub mod pipeline;

use std::{fmt, fs, io};

use boring_logtail_common::WriteEvent;

#[derive(Debug, Eq, PartialEq)]
pub struct InvalidEventSize {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for InvalidEventSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid log event size: got {}, expected {}",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for InvalidEventSize {}

/// Decode one fixed-size record received from the kernel ring buffer.
pub fn decode_event(bytes: &[u8]) -> Result<WriteEvent, InvalidEventSize> {
    let expected = size_of::<WriteEvent>();
    if bytes.len() != expected {
        return Err(InvalidEventSize {
            expected,
            actual: bytes.len(),
        });
    }

    // Every bit pattern is valid for WriteEvent's integer and byte-array fields.
    // read_unaligned avoids requiring the ring-buffer byte slice to be aligned.
    Ok(unsafe { bytes.as_ptr().cast::<WriteEvent>().read_unaligned() })
}

pub fn render_event(event: &WriteEvent) -> String {
    let proces_name = match get_process_name(event.pid) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("unable to get process_name");
            String::new()
        }
    };

    format!(
        "pid={} tid={} cgroup={} fd={} syscall={} operation={} offset={} first={} last={} result={:?} truncated={} text={:?}",
        proces_name,
        event.tid,
        event.cgroup_id,
        event.fd,
        event.syscall,
        event.operation_id,
        event.data_offset,
        event.is_first_chunk(),
        event.is_last_chunk(),
        event.result(),
        event.is_truncated(),
        String::from_utf8_lossy(event.payload())
    )
}

fn get_process_name(pid: u32) -> Result<String, io::Error> {
    let path = format!("/proc/{}/cmdline", pid);
    let cmdline = fs::read_to_string(path)?;

    // Linux cmdline arguments are null-separated ('\0').
    // Replace them with spaces for human readability.
    let readable = cmdline.replace('\0', " ").trim().to_string();

    Ok(readable)
}

#[cfg(test)]
mod tests {
    use boring_logtail_common::{
        FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK, SYSCALL_WRITE, WRITE_CHUNK_SIZE, WRITE_EVENT_VERSION,
    };

    use super::*;

    fn event_bytes(event: &WriteEvent) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(event).cast::<u8>(),
                size_of::<WriteEvent>(),
            )
        }
    }

    #[test]
    fn decodes_an_unaligned_ring_buffer_record() {
        let mut event = WriteEvent {
            abi_version: WRITE_EVENT_VERSION,
            flags: FLAG_FIRST_CHUNK | FLAG_LAST_CHUNK,
            syscall: SYSCALL_WRITE,
            timestamp_ns: 1,
            cgroup_id: 456,
            operation_id: 789,
            result: 0,
            pid: 123,
            tid: 124,
            fd: 2,
            requested_len: 3,
            data_offset: 0,
            captured_len: 3,
            data: [0; WRITE_CHUNK_SIZE],
        };
        event.data[..3].copy_from_slice(b"hi\n");
        let mut storage = vec![0xaa];
        storage.extend_from_slice(event_bytes(&event));

        let decoded = decode_event(&storage[1..]).unwrap();

        assert_eq!(decoded, event);
        assert_eq!(decoded.payload(), b"hi\n");
    }

    #[test]
    fn rejects_records_with_the_wrong_size() {
        let error = decode_event(&[0; 12]).unwrap_err();

        assert_eq!(error.actual, 12);
        assert_eq!(error.expected, size_of::<WriteEvent>());
    }

    #[test]
    fn renders_invalid_utf8_without_changing_the_payload() {
        let mut event = WriteEvent {
            abi_version: WRITE_EVENT_VERSION,
            flags: FLAG_FIRST_CHUNK | FLAG_LAST_CHUNK,
            syscall: SYSCALL_WRITE,
            timestamp_ns: 1,
            cgroup_id: 456,
            operation_id: 789,
            result: 0,
            pid: 123,
            tid: 124,
            fd: 1,
            requested_len: 2,
            data_offset: 0,
            captured_len: 2,
            data: [0; WRITE_CHUNK_SIZE],
        };
        event.data[..2].copy_from_slice(&[0xff, b'a']);

        assert_eq!(event.payload(), &[0xff, b'a']);
        assert_eq!(
            render_event(&event),
            "pid=123 tid=124 cgroup=456 fd=1 syscall=1 operation=789 offset=0 first=true last=true result=None truncated=false text=\"�a\""
        );
    }
}
