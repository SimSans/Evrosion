//! Read-only, coarse calendar elapsed source for the exact reviewed Q35 VM.
//! No UTC assertion, minimum rate, suspend behavior or host qualification is
//! inferred from calendar syntax. PIT ticks bound each operation only.
use ev_userspace_contract::root_v4::{
    RTC_CENTURY, RTC_MAX_SNAPSHOTS, RTC_READ_MAX_TICKS, RTC_UIP_POLLS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Deadline,
    Clock,
    Configuration,
    Calendar,
    Inconsistent,
    Overflow,
    Failed,
}
/// An exclusive actual index/data capability adapter. Implementing this trait
/// does not qualify its hardware, host, rate or output as UTC.
pub trait Io {
    fn tick(&mut self) -> u64;
    fn read(&mut self, register: u8, original_cut: u64) -> Result<u8, Error>;
}
/// Actual coarse elapsed seconds and the PIT observation bounding its capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub elapsed_seconds: u64,
    pub captured_tick: u64,
}
pub struct Clock {
    origin: Option<u64>,
    last: Option<u64>,
    tick: u64,
    failed: bool,
}
impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock {
    pub const fn new() -> Self {
        Self {
            origin: None,
            last: None,
            tick: 0,
            failed: false,
        }
    }
    /// Every attempt is bounded by one captured cut; failure permanently fences
    /// this actual Root-incarnation source. No stale sample/fallback is returned.
    pub fn sample(&mut self, io: &mut impl Io) -> Result<Sample, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.failed = true;
        let start = io.tick();
        if start < self.tick {
            return Err(Error::Clock);
        }
        self.tick = start;
        let cut = start
            .checked_add(RTC_READ_MAX_TICKS)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        let mut reader = Reader {
            io,
            last: start,
            cut,
        };
        let result = reader.coherent();
        self.tick = reader.last;
        let seconds = result?;
        if self.last.is_some_and(|v| seconds < v) {
            return Err(Error::Clock);
        }
        let origin = *self.origin.get_or_insert(seconds);
        let elapsed_seconds = seconds.checked_sub(origin).ok_or(Error::Clock)?;
        self.last = Some(seconds);
        self.failed = false;
        Ok(Sample {
            elapsed_seconds,
            captured_tick: self.tick,
        })
    }
}
struct Reader<'a, I> {
    io: &'a mut I,
    last: u64,
    cut: u64,
}
impl<I: Io> Reader<'_, I> {
    fn check(&mut self) -> Result<(), Error> {
        let now = self.io.tick();
        if now < self.last {
            return Err(Error::Clock);
        }
        self.last = now;
        if now >= self.cut {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn read(&mut self, register: u8) -> Result<u8, Error> {
        self.check()?;
        let value = self.io.read(register, self.cut)?;
        self.check()?;
        Ok(value)
    }
    fn snapshot(&mut self) -> Result<Option<[u8; 8]>, Error> {
        let mut ready = false;
        for _ in 0..RTC_UIP_POLLS {
            let a = self.read(0x0a)?;
            if a & 0x70 != 0x20 {
                return Err(Error::Configuration);
            }
            if a & 0x80 == 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Ok(None);
        }
        if self.read(0x0d)? != 0x80 {
            return Err(Error::Unavailable);
        }
        let b = self.read(0x0b)?;
        if b & 0x80 != 0 {
            return Err(Error::Configuration);
        }
        let mut value = [0; 8];
        value[0] = b;
        for (n, register) in [0, 2, 4, 7, 8, 9, RTC_CENTURY].into_iter().enumerate() {
            value[n + 1] = self.read(register)?;
        }
        let after_b = self.read(0x0b)?;
        let after_a = self.read(0x0a)?;
        if after_a & 0x70 != 0x20 || after_b & 0x80 != 0 {
            return Err(Error::Configuration);
        }
        if self.read(0x0d)? != 0x80 {
            return Err(Error::Unavailable);
        }
        Ok((after_a & 0x80 == 0 && b == after_b).then_some(value))
    }
    fn coherent(&mut self) -> Result<u64, Error> {
        let mut previous = None;
        for _ in 0..RTC_MAX_SNAPSHOTS {
            let current = self.snapshot()?;
            if let Some(value) = current
                && previous == Some(value)
            {
                return calendar(value);
            }
            previous = current;
        }
        Err(Error::Inconsistent)
    }
}
fn number(raw: u8, binary: bool) -> Result<u64, Error> {
    if binary {
        return Ok(u64::from(raw));
    }
    if raw & 15 > 9 || raw >> 4 > 9 {
        return Err(Error::Calendar);
    }
    Ok(u64::from(raw >> 4) * 10 + u64::from(raw & 15))
}
fn leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
fn calendar(v: [u8; 8]) -> Result<u64, Error> {
    let binary = v[0] & 4 != 0;
    let second = number(v[1], binary)?;
    let minute = number(v[2], binary)?;
    let hour = if v[0] & 2 != 0 {
        number(v[3], binary)?
    } else {
        let h = number(v[3] & 0x7f, binary)?;
        if !(1..=12).contains(&h) {
            return Err(Error::Calendar);
        }
        h % 12 + if v[3] & 0x80 != 0 { 12 } else { 0 }
    };
    let day = number(v[4], binary)?;
    let month = number(v[5], binary)?;
    let short = number(v[6], binary)?;
    let century = number(v[7], binary)?;
    let year = century * 100 + short;
    if second > 59
        || minute > 59
        || hour > 23
        || !(1..=12).contains(&month)
        || short > 99
        || !(1970..=9999).contains(&year)
    {
        return Err(Error::Calendar);
    }
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > lengths[month as usize - 1] {
        return Err(Error::Calendar);
    }
    // Gregorian days since1970. Bounded year range makes each operation exact;
    // this absolute label is discarded except for coarse elapsed differences.
    let before = |y: u64| {
        let x = y - 1;
        365 * x + x / 4 - x / 100 + x / 400
    };
    let days =
        before(year) - before(1970) + lengths[..month as usize - 1].iter().sum::<u64>() + day - 1;
    Ok(((days * 24 + hour) * 60 + minute) * 60 + second)
}
#[cfg(test)]
mod tests;
