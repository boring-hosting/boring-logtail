// SPDX-License-Identifier: GPL-3.0-or-later

//! Deterministic, I/O-free sampling of complete reconstructed writes.

use crate::pipeline::WriteOperation;
use std::{
    fmt,
    str::FromStr,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SamplePercent(u8);

impl SamplePercent {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(100);

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidSamplePercent {
    NotAnInteger(String),
    OutOfRange(u16),
}

impl fmt::Display for InvalidSamplePercent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnInteger(value) => {
                write!(formatter, "sample percent is not an integer: {value:?}")
            }
            Self::OutOfRange(value) => {
                write!(formatter, "sample percent {value} is outside 0..=100")
            }
        }
    }
}

impl std::error::Error for InvalidSamplePercent {}

impl TryFrom<u8> for SamplePercent {
    type Error = InvalidSamplePercent;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(InvalidSamplePercent::OutOfRange(value.into()))
        }
    }
}

impl FromStr for SamplePercent {
    type Err = InvalidSamplePercent;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = value
            .parse::<u16>()
            .map_err(|_| InvalidSamplePercent::NotAnInteger(value.to_owned()))?;
        if parsed > u16::from(Self::MAX.0) {
            return Err(InvalidSamplePercent::OutOfRange(parsed));
        }
        Self::try_from(parsed as u8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputPolicy {
    Always,
    Never,
    WithSample(SamplePercent),
}

impl OutputPolicy {
    pub fn from_config(value: Option<&str>) -> Result<Self, InvalidSamplePercent> {
        Ok(Self::WithSample(match value {
            Some(value) => value.parse()?,
            None => SamplePercent::MAX,
        }))
    }

    pub const fn sample_percent(self) -> SamplePercent {
        match self {
            Self::Always => SamplePercent::MAX,
            Self::Never => SamplePercent::MIN,
            Self::WithSample(percent) => percent,
        }
    }

    pub fn should_emit(self, operation: &WriteOperation) -> bool {
        let percent = self.sample_percent().get();
        match percent {
            0 => false,
            100 => true,
            percent => sampling_hash(operation) % 100 < u64::from(percent),
        }
    }
}

fn sampling_hash(operation: &WriteOperation) -> u64 {
    let mut state = operation.cgroup_id;
    state = mix64(state ^ operation.timestamp_ns.rotate_left(7));
    state = mix64(state ^ operation.operation_id.rotate_left(17));
    state = mix64(state ^ u64::from(operation.pid).rotate_left(29));
    state = mix64(state ^ u64::from(operation.tid).rotate_left(41));
    state
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}


#[cfg(test)]
mod tests {
    use super::*;
    use boring_logtail_common::{CAPTURE_SOURCE_APPLICATION_SYSCALL, OPERATION_WRITE};

    fn operation(number: u64) -> WriteOperation {
        WriteOperation {
            capture_source: CAPTURE_SOURCE_APPLICATION_SYSCALL,
            operation_kind: OPERATION_WRITE,
            timestamp_ns: number.wrapping_mul(17),
            cgroup_id: 456,
            operation_id: number,
            source_id: 0,
            result: Some(3),
            pid: 123,
            tid: 124,
            fd: Some(2),
            requested_len: 3,
            truncated: false,
            read_failed: false,
            bytes: b"hi\n".to_vec(),
        }
    }

    #[test]
    fn validates_every_u8_value() {
        for value in 0..=u8::MAX {
            assert_eq!(SamplePercent::try_from(value).is_ok(), value <= 100);
        }
    }

    #[test]
    fn zero_never_emits_and_one_hundred_always_emits() {
        let operation = operation(1);
        assert!(!OutputPolicy::WithSample(SamplePercent::MIN).should_emit(&operation));
        assert!(OutputPolicy::WithSample(SamplePercent::MAX).should_emit(&operation));
        assert!(!OutputPolicy::Never.should_emit(&operation));
        assert!(OutputPolicy::Always.should_emit(&operation));
    }

    #[test]
    fn intermediate_decisions_are_repeatable() {
        let policy = OutputPolicy::WithSample(SamplePercent::try_from(37).unwrap());
        let operation = operation(42);
        assert_eq!(
            policy.should_emit(&operation),
            policy.should_emit(&operation)
        );
    }

    #[test]
    fn parses_configuration_and_defaults_to_all() {
        assert_eq!(
            OutputPolicy::from_config(None)
                .unwrap()
                .sample_percent()
                .get(),
            100
        );
        assert_eq!(
            OutputPolicy::from_config(Some("1"))
                .unwrap()
                .sample_percent()
                .get(),
            1
        );
        assert!(OutputPolicy::from_config(Some("nope")).is_err());
        assert!(OutputPolicy::from_config(Some("101")).is_err());
    }

    #[test]
    fn one_percent_has_a_sane_distribution() {
        let policy = OutputPolicy::WithSample(SamplePercent::try_from(1).unwrap());
        let emitted = (0..10_000)
            .filter(|number| policy.should_emit(&operation(*number)))
            .count();
        assert!((50..=150).contains(&emitted), "emitted {emitted}");
    }
}
