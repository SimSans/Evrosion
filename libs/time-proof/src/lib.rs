//! Stateful bounded Cloudflare draft11 time proof, not clock qualification.
//! Absolute UTC assertions and measured elapsed uncertainty remain separate.
#![no_std]
#![forbid(unsafe_code)]
mod packet;
mod window;
use ev_release_trust::signature::PublicKey;
use ev_time_contract::{Error as ClockError, Instant};
pub use packet::{MAX_PATH_DEPTH, MAX_REPLY_BYTES, PROTOCOL, PUBLIC_KEY, PacketError};
pub use window::{Anchor, ClockModel, IntervalProposal, Policy};

/// Encode public query bytes for an untrusted relay. This neither creates a
/// private Client request nor verifies a caller-chosen challenge or time.
/// The guest retains its independently generated nonce and affine request.
pub fn encode_relay_request(nonce: &[u8; 32], out: &mut [u8; 1024]) {
    packet::request(nonce, out);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Entropy,
    Challenge,
    Clock(ClockError),
    Policy,
    Overflow,
    Age,
    Rollback,
    Packet(PacketError),
}
impl From<ClockError> for Error {
    fn from(e: ClockError) -> Self {
        Self::Clock(e)
    }
}
impl From<PacketError> for Error {
    fn from(e: PacketError) -> Self {
        Self::Packet(e)
    }
}
/// The adapter must own and authenticate an actual qualified fresh source.
/// Implementing this trait or returning nonzero bytes does not qualify entropy.
pub trait NonceSource {
    type Error;
    fn fresh_nonce(&mut self, out: &mut [u8; 32]) -> Result<(), Self::Error>;
}
struct Pending {
    nonce: [u8; 32],
    sequence: u64,
    origin: Instant,
}
/// A public request, affine local token. It cannot create a trusted anchor.
pub struct Request {
    nonce: [u8; 32],
    sequence: u64,
}
impl Request {
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact observed provider profile: ROUGHTIM framing, draft11, pinned SRV,
    /// fresh nonce and zero padding to1024 bytes. No RFC10049 TYPE/version1.
    pub fn encode(&self, out: &mut [u8; 1024]) {
        encode_relay_request(&self.nonce, out);
    }
}
/// Unique local challenge owner. No caller-supplied nonce verification API,
/// Clone/restore/default-ready path or downloaded key replacement exists.
pub struct Client<R> {
    source: R,
    key: PublicKey,
    policy: Policy,
    last: Instant,
    sequence: u64,
    pending: Option<Pending>,
    last_nonce: Option<[u8; 32]>,
    failed: bool,
}
impl<R: NonceSource> Client<R> {
    pub fn new(source: R, initial: Instant, policy: Policy) -> Result<Self, Error> {
        let key = PublicKey::parse(PUBLIC_KEY).map_err(|_| Error::Policy)?;
        Ok(Self {
            source,
            key,
            policy,
            last: initial,
            sequence: 0,
            pending: None,
            last_nonce: None,
            failed: false,
        })
    }
    fn observe(&mut self, now: Instant) -> Result<(), Error> {
        if let Err(e) = now.elapsed_since(self.last) {
            self.failed = true;
            return Err(e.into());
        }
        self.last = now;
        Ok(())
    }
    /// Capture the actual elapsed source BEFORE RNG work/publication. No Busy
    /// attempt regenerates an existing accepted challenge or extends its origin.
    pub fn begin(&mut self, issued: Instant) -> Result<Request, Error> {
        self.begin_after(issued, |_| Ok(()))
    }
    /// Prepare the retained source after the actual origin capture, without
    /// replacing this Client or resetting sequence/nonce/clock history. The
    /// adapter remains responsible for qualifying its actual source; this
    /// callback grants no time authority or caller-chosen verification path.
    /// A pending challenge refuses before the callback can run. Preparation
    /// failure fences this Client just like a failed source output.
    pub fn begin_after(
        &mut self,
        issued: Instant,
        prepare: impl FnOnce(&mut R) -> Result<(), R::Error>,
    ) -> Result<Request, Error> {
        if self.failed {
            return Err(Error::State);
        }
        self.observe(issued)?;
        if self.pending.is_some() {
            return Err(Error::State);
        }
        self.failed = true;
        self.sequence = self
            .sequence
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        prepare(&mut self.source).map_err(|_| Error::Entropy)?;
        let mut nonce = [0; 32];
        self.source
            .fresh_nonce(&mut nonce)
            .map_err(|_| Error::Entropy)?;
        if nonce == [0; 32] || self.last_nonce == Some(nonce) {
            return Err(Error::Entropy);
        }
        self.last_nonce = Some(nonce);
        self.pending = Some(Pending {
            nonce,
            sequence: self.sequence,
            origin: issued,
        });
        self.failed = false;
        Ok(Request {
            nonce,
            sequence: self.sequence,
        })
    }
    /// Consumes the pending challenge on EVERY attempted response, including
    /// malformed packets, failed signatures and clock failure. A later query
    /// needs a new actual source output and a newly captured origin.
    pub fn finish(
        &mut self,
        request: Request,
        received: Instant,
        bytes: &[u8],
    ) -> Result<Anchor, Error> {
        let pending = self.pending.take().ok_or(Error::State)?;
        if self.failed {
            return Err(Error::State);
        }
        self.observe(received)?;
        if request.sequence != pending.sequence || request.nonce != pending.nonce {
            return Err(Error::Challenge);
        }
        self.policy.exchange(pending.origin, received)?;
        let time = packet::verify(self.key, &pending.nonce, bytes, self.policy.max_radius())?;
        Ok(Anchor::new(time, pending.origin, received, self.policy))
    }
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    /// Explicit owner recovery only. It does not unconsume a nonce or qualify
    /// the returned source; callers must reestablish its actual source contract.
    pub fn into_source(self) -> R {
        self.source
    }
}
#[cfg(test)]
mod tests;
