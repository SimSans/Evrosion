//! Conservative UTC interval checks. RTC/NTP/IRQ ticks are not authenticated UTC.
use crate::{Error as ClockError, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownTime,
    UnqualifiedTime,
    InvalidInterval,
    StaleSample,
    Clock(ClockError),
    Rollback,
    NotYetValid,
    Expired,
    Uncertain,
}

/// Inclusive possible UTC seconds across the provider's whole validity window.
/// No interpolation assumes that emulated IRQ ticks measure elapsed wall time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtcInterval {
    earliest: u64,
    latest: u64,
}

impl UtcInterval {
    pub fn new(earliest: u64, latest: u64) -> Result<Self, Error> {
        if earliest > latest {
            return Err(Error::InvalidInterval);
        }
        Ok(Self { earliest, latest })
    }

    pub fn earliest(self) -> u64 {
        self.earliest
    }

    pub fn latest(self) -> u64 {
        self.latest
    }
}

/// This label describes an already authenticated provider result; constructing
/// it is not proof of trusted time. The provider must handle pause, drift and
/// source authentication before issuing Qualified, or report Unknown instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Time {
    Unknown,
    Tentative(UtcInterval),
    Qualified(QualifiedWindow),
}

/// The provider's UTC interval must contain every possible UTC value across
/// [observed, through], including drift/measurement/transport uncertainty. An
/// old UTC sample plus an arbitrary age allowance cannot establish this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QualifiedWindow {
    observed: Instant,
    through: Instant,
    utc: UtcInterval,
}

impl QualifiedWindow {
    pub fn new(observed: Instant, through: Instant, utc: UtcInterval) -> Result<Self, Error> {
        through.elapsed_since(observed).map_err(Error::Clock)?;
        Ok(Self {
            observed,
            through,
            utc,
        })
    }
}

/// Metadata validity is [not_before, expires), as independently verified by the
/// caller's release-trust verifier. Signatures and replay floors are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    not_before: u64,
    expires: u64,
}

impl Validity {
    pub fn new(not_before: u64, expires: u64) -> Result<Self, Error> {
        if not_before >= expires {
            return Err(Error::InvalidInterval);
        }
        Ok(Self {
            not_before,
            expires,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Only persist with the exact accepted trust transaction. This helper
    /// neither writes nor resists malicious rollback of the entire medium.
    pub next_floor: u64,
}

pub fn check(
    time: Time,
    validity: Validity,
    now: Instant,
    durable_floor: u64,
) -> Result<Decision, Error> {
    let qualified = match time {
        Time::Unknown => return Err(Error::UnknownTime),
        Time::Tentative(_) => return Err(Error::UnqualifiedTime),
        Time::Qualified(qualified) => qualified,
    };
    now.elapsed_since(qualified.observed)
        .map_err(Error::Clock)?;
    if now.tick() > qualified.through.tick() {
        return Err(Error::StaleSample);
    }
    let utc = qualified.utc;
    // No possible accepted time may precede the previously committed floor.
    if utc.earliest < durable_floor {
        return Err(Error::Rollback);
    }
    if utc.latest < validity.not_before {
        return Err(Error::NotYetValid);
    }
    if utc.earliest >= validity.expires {
        return Err(Error::Expired);
    }
    if utc.earliest < validity.not_before || utc.latest >= validity.expires {
        return Err(Error::Uncertain);
    }
    Ok(Decision {
        next_floor: durable_floor.max(utc.earliest),
    })
}
