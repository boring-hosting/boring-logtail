// SPDX-License-Identifier: GPL-3.0-or-later

//! Deterministic, I/O-free sampling of complete framed records.

use crate::record::LogRecord;
use std::{fmt, str::FromStr};

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

    pub fn should_emit(self, record: &LogRecord) -> bool {
        let percent = self.sample_percent().get();
        match percent {
            0 => false,
            100 => true,
            percent => sampling_hash(record) % 100 < u64::from(percent),
        }
    }
}

fn sampling_hash(record: &LogRecord) -> u64 {
    let mut state = record.sampling_seed;
    state = mix64(state ^ record.first_timestamp_ns.rotate_left(7));
    state = mix64(state ^ record.last_timestamp_ns.rotate_left(13));
    state = mix64(state ^ record.first_operation_id.rotate_left(17));
    state = mix64(state ^ record.last_operation_id.rotate_left(29));
    state = mix64(state ^ (record.bytes().len() as u64).rotate_left(41));
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
    use crate::{
        enrichment::Enrichment,
        pipeline::StreamFileDescriptor,
        record::{RecordIntegrity, Severity},
    };
    use std::sync::Arc;

    fn record(number: u64) -> LogRecord {
        LogRecord {
            observed_at: "2026-08-12T18:00:00Z".parse().unwrap(),
            sampling_seed: 456,
            stream: StreamFileDescriptor::Stderr,
            enrichment: Enrichment::UnresolvedCgroup,
            first_timestamp_ns: number.wrapping_mul(17),
            last_timestamp_ns: number.wrapping_mul(17),
            first_operation_id: number,
            last_operation_id: number,
            bytes: Arc::from(&b"hi\n"[..]),
            integrity: RecordIntegrity::default(),
            sample_percent: 100,
            severity: Severity::Unknown,
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
        let record = record(1);
        assert!(!OutputPolicy::WithSample(SamplePercent::MIN).should_emit(&record));
        assert!(OutputPolicy::WithSample(SamplePercent::MAX).should_emit(&record));
        assert!(!OutputPolicy::Never.should_emit(&record));
        assert!(OutputPolicy::Always.should_emit(&record));
    }

    #[test]
    fn intermediate_decisions_are_repeatable() {
        let policy = OutputPolicy::WithSample(SamplePercent::try_from(37).unwrap());
        let record = record(42);
        assert_eq!(policy.should_emit(&record), policy.should_emit(&record));
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
            .filter(|number| policy.should_emit(&record(*number)))
            .count();
        assert!((50..=150).contains(&emitted), "emitted {emitted}");
    }
}
