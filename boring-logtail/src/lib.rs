// SPDX-License-Identifier: GPL-3.0-or-later

pub mod cgroup_resolver;
pub mod enrichment;
pub mod k8s_watch;
pub mod pipeline;
pub mod sampling;

use std::fmt;

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

#[derive(Debug, Eq, PartialEq)]
pub enum InvalidEvent {
    Size(InvalidEventSize),
    UnsupportedVersion { expected: u16, actual: u16 },
}

impl fmt::Display for InvalidEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size(error) => error.fmt(formatter),
            Self::UnsupportedVersion { expected, actual } => write!(
                formatter,
                "unsupported log event ABI version {actual}, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for InvalidEvent {}

/// Decode one fixed-size record received from the kernel ring buffer.
pub fn decode_event(bytes: &[u8]) -> Result<WriteEvent, InvalidEvent> {
    let expected = size_of::<WriteEvent>();
    if bytes.len() != expected {
        return Err(InvalidEvent::Size(InvalidEventSize {
            expected,
            actual: bytes.len(),
        }));
    }

    // Every bit pattern is valid for WriteEvent's integer and byte-array fields.
    // read_unaligned avoids requiring the ring-buffer byte slice to be aligned.
    let event = unsafe { bytes.as_ptr().cast::<WriteEvent>().read_unaligned() };
    if event.abi_version != boring_logtail_common::WRITE_EVENT_VERSION {
        return Err(InvalidEvent::UnsupportedVersion {
            expected: boring_logtail_common::WRITE_EVENT_VERSION,
            actual: event.abi_version,
        });
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use boring_logtail_common::{
        CAPTURE_SOURCE_APPLICATION_SYSCALL, FLAG_FD_KNOWN, FLAG_FIRST_CHUNK, FLAG_LAST_CHUNK,
        OPERATION_WRITE, WRITE_CHUNK_SIZE, WRITE_EVENT_VERSION,
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
            flags: FLAG_FD_KNOWN | FLAG_FIRST_CHUNK | FLAG_LAST_CHUNK,
            capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
            operation_kind: OPERATION_WRITE,
            timestamp_ns: 1,
            cgroup_id: 456,
            operation_id: 789,
            source_id: 0,
            result: 0,
            pid: 123,
            tid: 124,
            fd: 2,
            requested_len: 3,
            data_offset: 0,
            captured_len: 3,
            data: [0; WRITE_CHUNK_SIZE],
        };
        event.data[..3_usize].copy_from_slice(b"hi\n");
        let mut storage = vec![0xaa];
        storage.extend_from_slice(event_bytes(&event));

        let decoded = decode_event(&storage[1..]).unwrap();

        assert_eq!(decoded, event);
        assert_eq!(decoded.payload(), b"hi\n");
    }

    #[test]
    fn rejects_records_with_the_wrong_size() {
        let error = decode_event(&[0u8; 12]).unwrap_err();

        assert_eq!(
            error,
            InvalidEvent::Size(InvalidEventSize {
                expected: size_of::<WriteEvent>(),
                actual: 12,
            })
        );
    }

    #[test]
    fn rejects_records_from_an_unknown_abi_version() {
        let mut event = WriteEvent {
            abi_version: WRITE_EVENT_VERSION + 1,
            flags: FLAG_FD_KNOWN | FLAG_FIRST_CHUNK | FLAG_LAST_CHUNK,
            capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
            operation_kind: OPERATION_WRITE,
            timestamp_ns: 1,
            cgroup_id: 2,
            operation_id: 3,
            source_id: 0,
            result: 0,
            pid: 4,
            tid: 5,
            fd: 1,
            requested_len: 0,
            data_offset: 0,
            captured_len: 0,
            data: [0; WRITE_CHUNK_SIZE],
        };

        assert!(matches!(
            decode_event(event_bytes(&event)),
            Err(InvalidEvent::UnsupportedVersion { .. })
        ));
        event.abi_version = WRITE_EVENT_VERSION;
        assert!(decode_event(event_bytes(&event)).is_ok());
    }
}
