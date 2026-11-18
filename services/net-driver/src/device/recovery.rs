//! Physical STOP after an independently excluded previous device graph. This
//! owner never starts/resets the NIC, assumes a previous driver's Rust state,
//! closes a capability or releases a packet/window/image owner.
use super::*;

/// The coordinator must first exclude every previous CPU/PIO holder and drain
/// its canonical accepted calls. Ports still carries the actual scoped device
/// capability. Construction supplies no exclusion or retirement authority.
pub struct Recovery<P> {
    pub(super) driver: Driver<P>,
}

/// Move-only local physical completion, produced only by all128 successful
/// chunks and the final fresh STOP/bounds readback. Not a serialized Core
/// authority token; that separate join must bind the actual excluded graph.
pub struct Stopped<P> {
    driver: Driver<P>,
}

impl<P: Ports> Recovery<P> {
    pub fn new(ports: P) -> Self {
        Self {
            driver: Driver::new(ports),
        }
    }
    /// Same8192 aggregate/1024 child maximum, same physical STOP, exact restored
    /// byte mode/wrap bounds and128-byte readback loop as cooperative shutdown.
    /// This begins once from a fresh recovery owner; no old driver metadata is
    /// accepted as the physical device state.
    pub fn begin(&mut self, aggregate: u64, child: u64) -> Result<StopProgress, Failure<P::Error>> {
        if self.driver.state != State::Fresh || self.driver.stop.is_some() {
            return Err(Driver::<P>::failure(Error::State));
        }
        self.driver.begin_stop(aggregate, child)
    }
    pub fn step(&mut self, child: u64) -> Result<StopProgress, Failure<P::Error>> {
        self.driver.stop_step(child)
    }
    /// Incomplete/unknown failure returns this exact owner. No marker, caller
    /// byte count or elapsed deadline can manufacture physical completion.
    pub fn finish(self) -> Result<Stopped<P>, Self> {
        if self.driver.state == State::Stopped
            && self
                .driver
                .stop
                .as_ref()
                .is_some_and(|stop| stop.done == nic::PACKET_RAM_BYTES)
        {
            Ok(Stopped {
                driver: self.driver,
            })
        } else {
            Err(self)
        }
    }
}

impl<P: Ports> Stopped<P> {
    pub fn bytes(&self) -> u16 {
        self.driver.stop.as_ref().unwrap().done
    }
}
