//! Typed consumer contracts for separately authenticated clock/random services.
//!
//! This crate is not a clock, entropy collector, CSPRNG, capability authority or
//! persistence layer. A trust label is not authentication: adapters must bind
//! these values to the actual authorized provider and its lifecycle. Existing
//! kernel monotonic scheduling remains the mechanism for operation deadlines.
#![no_std]
#![forbid(unsafe_code)]

pub mod entropy;
pub mod freshness;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDomain,
    DifferentBoot,
    ClockRegression,
    Overflow,
}

/// A provider-bound boot clock domain. Nonzero does not imply random/secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain(u64);

impl Domain {
    /// Supply the actual provider's boot identity, never an untrusted claim.
    pub fn new(boot: u64) -> Result<Self, Error> {
        if boot == 0 {
            Err(Error::InvalidDomain)
        } else {
            Ok(Self(boot))
        }
    }

    pub fn at(self, tick: u64) -> Instant {
        Instant { domain: self, tick }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instant {
    domain: Domain,
    tick: u64,
}

impl Instant {
    pub fn domain(self) -> Domain {
        self.domain
    }

    pub fn tick(self) -> u64 {
        self.tick
    }

    pub fn elapsed_since(self, earlier: Self) -> Result<u64, Error> {
        if self.domain != earlier.domain {
            return Err(Error::DifferentBoot);
        }
        self.tick
            .checked_sub(earlier.tick)
            .ok_or(Error::ClockRegression)
    }
}

/// Absolute same-boot deadline; no UTC conversion or retry-based extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    start: Instant,
    end: u64,
}

impl Deadline {
    pub fn after(start: Instant, ticks: u64) -> Result<Self, Error> {
        Ok(Self {
            start,
            end: start.tick.checked_add(ticks).ok_or(Error::Overflow)?,
        })
    }

    pub fn reached(self, now: Instant) -> Result<bool, Error> {
        now.elapsed_since(self.start)?;
        Ok(now.tick >= self.end)
    }
}

#[cfg(test)]
mod tests;
