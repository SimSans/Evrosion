//! Pure bounds from an already authenticated time assertion and actual elapsed
//! observations. A model rate and this proposal do NOT qualify a provider.
use crate::{Error, packet::SignedTime};
use ev_time_contract::{Instant, freshness::UtcInterval};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockModel {
    minimum_num: u32,
    denominator: u32,
}
impl ClockModel {
    /// Floor-quantized one-second cells, with a separately justified minimum
    /// rate of num/den clock seconds per UTCsecond. No PIT conversion is inferred.
    pub fn one_second_floor(minimum_num: u32, denominator: u32) -> Result<Self, Error> {
        if minimum_num == 0 || minimum_num > denominator || denominator > 1_000_000 {
            return Err(Error::Policy);
        }
        Ok(Self {
            minimum_num,
            denominator,
        })
    }
    fn upper(self, origin: Instant, end: Instant) -> Result<u64, Error> {
        let ticks = end
            .elapsed_since(origin)?
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let n = u128::from(ticks) * u128::from(self.denominator);
        u64::try_from(n.div_ceil(u128::from(self.minimum_num))).map_err(|_| Error::Overflow)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    clock: ClockModel,
    max_exchange: u64,
    max_age: u64,
    max_window: u64,
    max_radius: u32,
}
impl Policy {
    pub fn new(
        clock: ClockModel,
        max_exchange_secs: u64,
        max_anchor_age_secs: u64,
        max_window_ticks: u64,
        max_radius_secs: u32,
    ) -> Result<Self, Error> {
        if !(1..=3600).contains(&max_exchange_secs)
            || max_anchor_age_secs < max_exchange_secs
            || max_anchor_age_secs > 86400
            || max_window_ticks > max_anchor_age_secs
            || !(1..=3600).contains(&max_radius_secs)
        {
            return Err(Error::Policy);
        }
        Ok(Self {
            clock,
            max_exchange: max_exchange_secs,
            max_age: max_anchor_age_secs,
            max_window: max_window_ticks,
            max_radius: max_radius_secs,
        })
    }
    pub(crate) fn exchange(self, origin: Instant, end: Instant) -> Result<(), Error> {
        if self.clock.upper(origin, end)? > self.max_exchange {
            Err(Error::Age)
        } else {
            Ok(())
        }
    }
    pub(crate) fn max_radius(self) -> u32 {
        self.max_radius
    }
}
/// No public constructor/Clone/restore. Fresh post-crypto elapsed observations
/// are mandatory; every failed window attempt permanently closes this anchor.
pub struct Anchor {
    time: SignedTime,
    origin: Instant,
    last: Instant,
    policy: Policy,
    first: bool,
    failed: bool,
}
impl Anchor {
    pub(crate) fn new(
        time: SignedTime,
        origin: Instant,
        received: Instant,
        policy: Policy,
    ) -> Self {
        Self {
            time,
            origin,
            last: received,
            policy,
            first: true,
            failed: false,
        }
    }
    fn check_observation(&self, observed: Instant) -> Result<(), Error> {
        observed.elapsed_since(self.last)?;
        let age = self.policy.clock.upper(self.origin, observed)?;
        if age > self.policy.max_age || (self.first && age > self.policy.max_exchange) {
            return Err(Error::Age);
        }
        Ok(())
    }
    /// Record an actual fresh elapsed read after response verification. This
    /// checks the original whole-exchange bound without inventing a durable UTC
    /// floor, returning an interval, or qualifying any clock/provider. A later
    /// window still requires its real committed floor and fresh observation.
    pub fn observe_post_crypto(&mut self, observed: Instant) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        self.failed = true;
        self.check_observation(observed)?;
        self.last = observed;
        self.first = false;
        self.failed = false;
        Ok(())
    }
    pub fn window(
        &mut self,
        observed: Instant,
        through: Instant,
        durable_floor: u64,
    ) -> Result<IntervalProposal, Error> {
        if self.failed {
            return Err(Error::State);
        }
        self.failed = true;
        self.check_observation(observed)?;
        let width = through.elapsed_since(observed)?;
        if width > self.policy.max_window {
            return Err(Error::Age);
        }
        let elapsed = self.policy.clock.upper(self.origin, through)?;
        if elapsed > self.policy.max_age {
            return Err(Error::Age);
        }
        if self.time.earliest < durable_floor {
            return Err(Error::Rollback);
        }
        let latest = self
            .time
            .latest
            .checked_add(elapsed)
            .ok_or(Error::Overflow)?;
        let utc = UtcInterval::new(self.time.earliest, latest).map_err(|_| Error::Overflow)?;
        self.last = observed;
        self.first = false;
        self.failed = false;
        Ok(IntervalProposal {
            utc,
            observed,
            through,
            next_floor: durable_floor.max(self.time.earliest),
        })
    }
}
/// Authenticated assertion plus conditional elapsed math, NOT Time::Qualified.
/// Only an adapter with the actual qualified source/profile/lifecycle evidence
/// may build the consumer contract's QualifiedWindow from these exact values.
pub struct IntervalProposal {
    utc: UtcInterval,
    observed: Instant,
    through: Instant,
    next_floor: u64,
}
impl IntervalProposal {
    pub fn utc(&self) -> UtcInterval {
        self.utc
    }
    pub fn observed(&self) -> Instant {
        self.observed
    }
    pub fn through(&self) -> Instant {
        self.through
    }
    pub fn next_floor(&self) -> u64 {
        self.next_floor
    }
}
