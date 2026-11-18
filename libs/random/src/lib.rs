//! Bounded private ChaCha20 generator owned by the security service.
//!
//! This is a real generator, not an entropy collector or capability service.
//! The trusted adapter must qualify/authenticate the actual source before
//! calling `reseed_after_authorized_source`. Seed bytes, statistical tests and
//! the generation counter cannot establish that qualification themselves.
#![no_std]
#![forbid(unsafe_code)]

use ev_time_contract::{Domain, Instant, entropy};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use zeroize::Zeroize;

pub mod seed;

/// Finite output and same-boot monotonic reseed policy. Ticks are supplied by
/// the admitted clock; this does not assert UTC or a particular tick frequency.
pub const OUTPUT_PER_SEED: u64 = 1024 * 1024;
pub const RESEED_TICKS: u64 = 60_000;
pub const MAX_REQUEST_BYTES: usize = entropy::MAX_REQUEST_BYTES as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Accounting(entropy::Error),
    RequestSequenceExhausted,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub request: u64,
    pub seed_generation: u64,
    pub bytes: u16,
}

/// No Clone/Debug/raw-state/seek API: callers cannot duplicate or rewind a
/// live stream. Disabling a generator removes output eligibility immediately;
/// physical private-RAM scrubbing remains the actual service owner's retirement
/// obligation, not a claim about third-party opaque state on Rust Drop.
pub struct Generator {
    budget: entropy::Budget,
    rng: Option<ChaCha20Rng>,
    request: u64,
}
impl Generator {
    pub fn unavailable(domain: Domain) -> Self {
        Self {
            budget: entropy::Budget::unavailable(domain),
            rng: None,
            request: 0,
        }
    }

    /// Called only after actual approved-source acquisition, freshness and
    /// success checks. No untrusted request is allowed to nominate these bytes.
    /// The input buffer is erased on success AND refusal. A newer generation
    /// selects the upstream generator's distinct substream; this prevents a
    /// repeated input from rewinding an earlier generation within this boot,
    /// but does not manufacture entropy or fix an unqualified source.
    pub fn reseed_after_authorized_source(
        &mut self,
        now: Instant,
        generation: u64,
        seed: &mut [u8; 32],
    ) -> Result<(), Error> {
        let result = self
            .budget
            .reseeded(now, generation, OUTPUT_PER_SEED, RESEED_TICKS);
        match result {
            Ok(()) => {
                let mut rng = ChaCha20Rng::from_seed(*seed);
                rng.set_stream(generation);
                seed.zeroize();
                self.rng = Some(rng);
                Ok(())
            }
            Err(error) => {
                seed.zeroize();
                // A clock fault invalidates all earlier readiness. Other
                // invalid reseed attempts retain the old stream's original
                // finite eligibility; they never refresh its cut or budget.
                if matches!(error, entropy::Error::Clock(_)) {
                    self.rng = None;
                }
                Err(Error::Accounting(error))
            }
        }
    }

    /// Reserve before generating/exposing output. Failed or refused requests
    /// leave the caller buffer untouched. A delivery failure after success
    /// consumes this output; there is intentionally no refund/replay operation.
    pub fn fill(&mut self, now: Instant, output: &mut [u8]) -> Result<Receipt, Error> {
        let next = self.request.checked_add(1).ok_or_else(|| {
            self.source_failed();
            Error::RequestSequenceExhausted
        })?;
        let generation = self
            .budget
            .reserve(now, output.len() as u64)
            .map_err(|error| {
                if !matches!(error, entropy::Error::InvalidRequest) {
                    self.rng = None;
                }
                Error::Accounting(error)
            })?;
        let Some(rng) = &mut self.rng else {
            self.budget.fail();
            return Err(Error::Unavailable);
        };
        rng.fill_bytes(output);
        self.request = next;
        Ok(Receipt {
            request: next,
            seed_generation: generation,
            bytes: output.len() as u16,
        })
    }

    /// Provider failure, revocation or generation retirement: output stays
    /// unavailable until a genuine newer successful reseed. Does not rewind the
    /// lifetime request sequence or refund an already reserved output range.
    pub fn source_failed(&mut self) {
        self.budget.fail();
        self.rng = None;
    }
}

#[cfg(test)]
mod tests;
