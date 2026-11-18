//! Finite diagnostic retention for the sustained session. The limit bounds
//! evidence, never the number of legitimate operations the OS may perform.
//! No allocation, I/O, authority decision or scheduler credit lives here.
use core::fmt;

pub const DETAIL_BYTES: u64 = 384 * 1024;
pub const FINAL_BYTES: u64 = 64 * 1024;
const RECORD_BYTES: u64 = 8192;

/// Count the actual COM1 byte cost, including its LF -> CRLF conversion, before
/// emitting a complete observation. Formatting twice avoids a stack log buffer.
#[derive(Default)]
pub struct Measure {
    bytes: u64,
    complete: bool,
}
impl fmt::Write for Measure {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.bytes = self
            .bytes
            .checked_add(value.len() as u64)
            .and_then(|n| n.checked_add(value.bytes().filter(|&b| b == b'\n').count() as u64))
            .ok_or(fmt::Error)?;
        if !value.is_empty() {
            self.complete = value.ends_with('\n');
        }
        Ok(())
    }
}
impl Measure {
    pub fn finish(self) -> Result<u64, fmt::Error> {
        if !self.complete || self.bytes == 0 || self.bytes > RECORD_BYTES {
            Err(fmt::Error)
        } else {
            Ok(self.bytes)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Retention {
    pub observed: u64,
    pub retained: u64,
    pub omitted: u64,
    pub detail_bytes: u64,
    pub final_bytes: u64,
    pub omitted_bytes: u64,
    pub prefix_closed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Emit,
    /// Emit one separate boundary record, then omit this complete observation.
    FirstOmission,
    Omit,
}
impl Retention {
    pub const fn new() -> Self {
        Self {
            observed: 0,
            retained: 0,
            omitted: 0,
            detail_bytes: 0,
            final_bytes: 0,
            omitted_bytes: 0,
            prefix_closed: false,
        }
    }

    /// Only fixed final ownership snapshots, the final finish state and the
    /// bounded UI totals use the reserve. Ordinary owner commands, faults and
    /// lifecycle events remain part of the finite retained prefix.
    pub fn record(&mut self, bytes: u64, final_record: bool) -> Result<Decision, fmt::Error> {
        if bytes == 0 || bytes > RECORD_BYTES {
            return Err(fmt::Error);
        }
        let observed = self.observed.checked_add(1).ok_or(fmt::Error)?;
        if final_record {
            let used = self.final_bytes.checked_add(bytes).ok_or(fmt::Error)?;
            if used > FINAL_BYTES {
                return Err(fmt::Error);
            }
            self.retained = self.retained.checked_add(1).ok_or(fmt::Error)?;
            self.final_bytes = used;
            self.observed = observed;
            return Ok(Decision::Emit);
        }
        if !self.prefix_closed && self.detail_bytes + bytes <= DETAIL_BYTES {
            self.retained = self.retained.checked_add(1).ok_or(fmt::Error)?;
            self.detail_bytes += bytes;
            self.observed = observed;
            return Ok(Decision::Emit);
        }
        let decision = if self.prefix_closed {
            Decision::Omit
        } else {
            Decision::FirstOmission
        };
        self.omitted = self.omitted.checked_add(1).ok_or(fmt::Error)?;
        self.omitted_bytes = self.omitted_bytes.checked_add(bytes).ok_or(fmt::Error)?;
        self.prefix_closed = true;
        self.observed = observed;
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    #[test]
    fn measures_complete_observations_in_actual_wire_bytes() {
        let mut measure = Measure::default();
        writeln!(measure, "first {}", 42).unwrap();
        measure.write_str("second\n").unwrap();
        assert_eq!(measure.finish().unwrap(), 18);
        let mut partial = Measure::default();
        partial.write_str("partial").unwrap();
        assert!(partial.finish().is_err());
        assert!(Measure::default().finish().is_err());
    }

    #[test]
    fn normal_work_continues_after_complete_prefix_is_full() {
        let mut log = Retention::new();
        for _ in 0..DETAIL_BYTES / RECORD_BYTES {
            assert_eq!(log.record(RECORD_BYTES, false), Ok(Decision::Emit));
        }
        assert_eq!(log.record(100, false), Ok(Decision::FirstOmission));
        // Even a smaller following observation cannot silently resume a broken
        // history. Final ownership snapshots still have separate reserved room.
        assert_eq!(log.record(2, false), Ok(Decision::Omit));
        assert_eq!(log.record(300, true), Ok(Decision::Emit));
        for _ in 0..10_000 {
            assert_eq!(log.record(400, false), Ok(Decision::Omit));
        }
        assert_eq!(log.observed, log.retained + log.omitted);
        assert_eq!(log.detail_bytes, DETAIL_BYTES);
        assert_eq!(log.final_bytes, 300);
        assert_eq!(log.omitted, 10_002);
        assert_eq!(log.omitted_bytes, 4_000_102);
    }

    #[test]
    fn invalid_format_or_final_reserve_exhaustion_is_an_internal_error() {
        let mut log = Retention::new();
        assert!(log.record(0, false).is_err());
        assert!(log.record(RECORD_BYTES + 1, false).is_err());
        assert_eq!(log, Retention::new());
        for _ in 0..FINAL_BYTES / RECORD_BYTES {
            assert_eq!(log.record(RECORD_BYTES, true), Ok(Decision::Emit));
        }
        let before = log;
        assert!(log.record(1, true).is_err());
        assert_eq!(log, before);
    }
}
