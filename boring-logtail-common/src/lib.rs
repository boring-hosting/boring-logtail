// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]

#[cfg(test)]
extern crate std;

pub const WRITE_EVENT_VERSION: u16 = 1;
pub const WRITE_CHUNK_SIZE: usize = 256;
pub const MAX_CHUNKS_PER_WRITE: usize = 32;
pub const MAX_BYTES_PER_WRITE: usize = WRITE_CHUNK_SIZE * MAX_CHUNKS_PER_WRITE;
pub const SYSCALL_WRITE: u32 = 1;
pub const SYSCALL_WRITEV: u32 = 2;

pub const FLAG_RESULT_KNOWN: u16 = 1 << 0;
pub const FLAG_FIRST_CHUNK: u16 = 1 << 1;
pub const FLAG_LAST_CHUNK: u16 = 1 << 2;
pub const FLAG_TRUNCATED: u16 = 1 << 3;
pub const FLAG_READ_FAILED: u16 = 1 << 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteChunk {
    pub offset: u32,
    pub captured_len: u32,
    pub is_first: bool,
    pub is_complete: bool,
    pub is_truncated: bool,
}

/// Describes the next small piece of a write that is safe for eBPF to copy.
///
/// Non-positive syscall results still produce one empty event so
/// userspace can observe failed and empty writes. Positive results produce at
/// most [`MAX_CHUNKS_PER_WRITE`] chunks.
#[inline(always)]
pub fn next_write_chunk(result: i64, chunk_number: u32) -> Option<WriteChunk> {
    if chunk_number as usize >= MAX_CHUNKS_PER_WRITE {
        return None;
    }

    let written_len = if result > 0 { result as u64 } else { 0 };
    let offset = chunk_number as u64 * WRITE_CHUNK_SIZE as u64;
    if offset >= written_len && !(chunk_number == 0 && written_len == 0) {
        return None;
    }

    let remaining = written_len.saturating_sub(offset);
    let captured_len = remaining.min(WRITE_CHUNK_SIZE as u64);
    let is_complete = offset + captured_len == written_len;
    let is_truncated = chunk_number as usize + 1 == MAX_CHUNKS_PER_WRITE && !is_complete;

    Some(WriteChunk {
        offset: offset as u32,
        captured_len: captured_len as u32,
        is_first: chunk_number == 0,
        is_complete,
        is_truncated,
    })
}

/// One small, versioned message describing part of a `write` syscall.
///
/// This is the versioned kernel/userspace transport ABI. It deliberately
/// describes syscall facts and opaque bytes, not an application log entry.
/// Userspace is responsible for joining chunks, framing records, decoding
/// content, and enriching it with Kubernetes metadata.
///
/// Version 1 reserves syscall kinds for `write` and `writev`. Observations that
/// omit [`FLAG_RESULT_KNOWN`] must not have `result` interpreted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteEvent {
    pub abi_version: u16,
    pub flags: u16,
    pub syscall: u32,

    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    /// Joins chunks belonging to the same syscall.
    pub operation_id: u64,
    /// Raw syscall result: bytes written when non-negative, otherwise `-errno`.
    pub result: i64,

    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub requested_len: u32,
    pub data_offset: u32,
    pub captured_len: u32,
    pub data: [u8; WRITE_CHUNK_SIZE],
}

impl WriteEvent {
    pub fn payload(&self) -> &[u8] {
        let len = (self.captured_len as usize).min(self.data.len());
        &self.data[..len]
    }

    pub fn has_flag(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    pub fn result(&self) -> Option<i64> {
        self.has_flag(FLAG_RESULT_KNOWN).then_some(self.result)
    }

    pub fn is_truncated(&self) -> bool {
        self.has_flag(FLAG_TRUNCATED)
    }

    pub fn is_first_chunk(&self) -> bool {
        self.has_flag(FLAG_FIRST_CHUNK)
    }

    pub fn is_last_chunk(&self) -> bool {
        self.has_flag(FLAG_LAST_CHUNK)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use std::{vec, vec::Vec};

    use super::*;

    fn event() -> WriteEvent {
        WriteEvent {
            abi_version: WRITE_EVENT_VERSION,
            flags: FLAG_FIRST_CHUNK | FLAG_LAST_CHUNK,
            syscall: SYSCALL_WRITE,
            timestamp_ns: 123,
            cgroup_id: 456,
            operation_id: 789,
            result: 0,
            pid: 42,
            tid: 43,
            fd: 1,
            requested_len: 4,
            data_offset: 0,
            captured_len: 4,
            data: [0; WRITE_CHUNK_SIZE],
        }
    }

    #[test]
    fn event_has_a_stable_c_layout() {
        assert_eq!(align_of::<WriteEvent>(), 8);
        assert_eq!(size_of::<WriteEvent>(), 320);
    }

    #[test]
    fn payload_is_raw_bytes() {
        let mut event = event();
        event.data[..4].copy_from_slice(&[0, 0xff, b'a', b'\n']);

        assert_eq!(event.payload(), &[0, 0xff, b'a', b'\n']);
        assert_eq!(event.result(), None);
        assert!(!event.is_truncated());
    }

    #[test]
    fn reports_known_results_and_explicit_truncation() {
        let mut event = event();
        event.flags |= FLAG_RESULT_KNOWN | FLAG_TRUNCATED;
        event.result = 300;

        assert_eq!(event.result(), Some(300));
        assert!(event.is_truncated());
    }

    #[test]
    fn reports_chunk_boundaries() {
        let event = event();

        assert!(event.is_first_chunk());
        assert!(event.is_last_chunk());
    }

    #[test]
    fn malformed_captured_length_is_clamped() {
        let mut event = event();
        event.captured_len = u32::MAX;

        assert_eq!(event.payload().len(), WRITE_CHUNK_SIZE);
    }

    #[test]
    fn makes_non_positive_results_one_empty_chunk() {
        for result in [i64::MIN, -1, 0] {
            assert_eq!(
                next_write_chunk(result, 0),
                Some(WriteChunk {
                    offset: 0,
                    captured_len: 0,
                    is_first: true,
                    is_complete: true,
                    is_truncated: false,
                })
            );
            assert_eq!(next_write_chunk(result, 1), None);
        }
    }

    #[test]
    fn splits_writes_at_chunk_boundaries() {
        let cases = [
            (1, vec![(0, 1)]),
            (255, vec![(0, 255)]),
            (256, vec![(0, 256)]),
            (257, vec![(0, 256), (256, 1)]),
            (
                1_215,
                vec![(0, 256), (256, 256), (512, 256), (768, 256), (1_024, 191)],
            ),
        ];

        for (result, expected) in cases {
            let chunks: Vec<_> = (0..MAX_CHUNKS_PER_WRITE as u32)
                .map_while(|index| next_write_chunk(result, index))
                .collect();
            let actual: Vec<_> = chunks
                .iter()
                .map(|chunk| (chunk.offset, chunk.captured_len))
                .collect();

            assert_eq!(actual, expected, "result={result}");
            assert!(chunks[0].is_first);
            assert!(chunks.last().unwrap().is_complete);
            assert!(!chunks.last().unwrap().is_truncated);
        }
    }

    #[test]
    fn marks_only_over_limit_writes_as_truncated() {
        let limit = MAX_BYTES_PER_WRITE as i64;
        let exact = next_write_chunk(limit, MAX_CHUNKS_PER_WRITE as u32 - 1).unwrap();
        assert_eq!(exact.captured_len, WRITE_CHUNK_SIZE as u32);
        assert!(exact.is_complete);
        assert!(!exact.is_truncated);

        let over = next_write_chunk(limit + 1, MAX_CHUNKS_PER_WRITE as u32 - 1).unwrap();
        assert_eq!(over.captured_len, WRITE_CHUNK_SIZE as u32);
        assert!(!over.is_complete);
        assert!(over.is_truncated);
        assert_eq!(
            next_write_chunk(limit + 1, MAX_CHUNKS_PER_WRITE as u32),
            None
        );
    }

    #[test]
    fn every_chunk_is_contiguous_and_bounded() {
        for result in [
            1,
            255,
            256,
            257,
            511,
            512,
            513,
            1_215,
            8_191,
            8_192,
            8_193,
            i64::MAX,
        ] {
            let mut expected_offset = 0;
            for index in 0..MAX_CHUNKS_PER_WRITE as u32 {
                let Some(chunk) = next_write_chunk(result, index) else {
                    break;
                };
                assert_eq!(
                    chunk.offset, expected_offset,
                    "result={result}, index={index}"
                );
                assert!(chunk.captured_len as usize <= WRITE_CHUNK_SIZE);
                expected_offset += chunk.captured_len;
                if chunk.is_complete || chunk.is_truncated {
                    break;
                }
            }
            assert_eq!(
                expected_offset as u64,
                (result as u64).min(MAX_BYTES_PER_WRITE as u64)
            );
        }
    }
}
