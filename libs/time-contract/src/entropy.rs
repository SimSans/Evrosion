//! Output/reseed accounting after a real provider has seeded a reviewed CSPRNG.
//! No entropy estimate, raw random bytes or cryptographic generator lives here.
use crate::{Domain, Error as ClockError, Instant};

pub const MAX_REQUEST_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidRequest,
    ReseedRequired,
    StaleGeneration,
    Clock(ClockError),
}

struct Ready {
    generation: u64,
    seeded: Instant,
    deadline: u64,
    remaining: u64,
}

/// Nonsecret accounting only. The actual security service owns its CSPRNG state,
/// source validation, capability checks and serialized delivery. Call reseeded
/// only after the approved source and real generator have successfully reseeded.
pub struct Budget {
    last: Instant,
    last_generation: u64,
    ready: Option<Ready>,
}

impl Budget {
    pub fn unavailable(domain: Domain) -> Self {
        Self {
            last: domain.at(0),
            last_generation: 0,
            ready: None,
        }
    }

    /// Generations increase within the actual boot; cold creation is unavailable
    /// again. A saved counter/seed or a successful health test is not fresh entropy.
    pub fn reseeded(
        &mut self,
        now: Instant,
        generation: u64,
        output_limit: u64,
        validity_ticks: u64,
    ) -> Result<(), Error> {
        if let Err(error) = now.elapsed_since(self.last) {
            self.ready = None;
            return Err(Error::Clock(error));
        }
        // Every real clock observation advances the high-water, including a
        // refused reseed. Invalid arguments cannot hide a later regression.
        self.last = now;
        if generation <= self.last_generation {
            return Err(Error::StaleGeneration);
        }
        if output_limit == 0 || validity_ticks == 0 {
            return Err(Error::InvalidRequest);
        }
        let deadline = now
            .tick()
            .checked_add(validity_ticks)
            .ok_or(Error::Clock(ClockError::Overflow))?;
        self.last_generation = generation;
        self.ready = Some(Ready {
            generation,
            seeded: now,
            deadline,
            remaining: output_limit,
        });
        Ok(())
    }

    /// Consume before generating or exposing bytes. Failed delivery does not
    /// refund this reservation or permit regeneration under the same request.
    /// Returns the exact seed generation for an independently authenticated log.
    pub fn reserve(&mut self, now: Instant, bytes: u64) -> Result<u64, Error> {
        if let Err(error) = now.elapsed_since(self.last) {
            self.ready = None;
            return Err(Error::Clock(error));
        }
        self.last = now;
        // Even malformed requests cannot hide an actual provider-clock
        // observation and permit a later regressed instant to look fresh.
        if bytes == 0 || bytes > MAX_REQUEST_BYTES {
            return Err(Error::InvalidRequest);
        }
        let ready = self.ready.as_mut().ok_or(Error::Unavailable)?;
        if let Err(error) = now.elapsed_since(ready.seeded) {
            self.ready = None;
            return Err(Error::Clock(error));
        }
        if now.tick() >= ready.deadline || bytes > ready.remaining {
            self.ready = None;
            return Err(Error::ReseedRequired);
        }
        ready.remaining -= bytes;
        Ok(ready.generation)
    }

    /// The provider's declared fail-closed policy after source/DRBG failure.
    /// A new successful actual reseed with a newer generation is required.
    pub fn fail(&mut self) {
        self.ready = None;
    }
}
