//! Pure trusted-picker policy metadata. Identity, consent and nonce data are
//! NOT capabilities. Actual provenance and atomic kernel delivery remain the
//! mandatory trusted Handoff implementation's responsibility.
#![no_std]
#![forbid(unsafe_code)]
pub use ev_app_identity::AppId;
use sha2::{Digest, Sha256};

pub mod intent;
pub const MAX_PENDING: usize = 8;

macro_rules! stable_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name([u8; 16]);
        impl $name {
            /// Opaque identity data allocated/resolved by a trusted registry;
            /// constructing this value establishes no identity or authority.
            pub fn new(bytes: [u8; 16]) -> Option<Self> {
                bytes.iter().any(|b| *b != 0).then_some(Self(bytes))
            }
            pub const fn bytes(self) -> [u8; 16] {
                self.0
            }
        }
    };
}
stable_id!(UserId);
stable_id!(VolumeId);
stable_id!(SessionId);
stable_id!(PickerEpoch);
stable_id!(BootEpoch);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentDigest([u8; 32]);
impl ContentDigest {
    pub fn new(bytes: [u8; 32]) -> Option<Self> {
        bytes.iter().any(|b| *b != 0).then_some(Self(bytes))
    }
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Stable application identity survives rename/update. Immutable package content
/// is separate and pinned by this initial policy; publisher/name/signature are
/// separate registry metadata and never substitute for a capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppRef {
    pub app: AppId,
    pub package: ContentDigest,
}

/// Trusted adapter derives this actual boot/process generation from the live
/// scheduler/registry, never an app packet. It is diagnostic identity, not a cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incarnation {
    epoch: BootEpoch,
    process_generation: u64,
}
impl Incarnation {
    pub fn new(epoch: BootEpoch, process_generation: u64) -> Option<Self> {
        valid_number(process_generation).then_some(Self {
            epoch,
            process_generation,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId {
    volume: VolumeId,
    local: u64,
}
impl ObjectId {
    pub fn new(volume: VolumeId, local: u64) -> Option<Self> {
        valid_number(local).then_some(Self { volume, local })
    }
    pub const fn volume(self) -> VolumeId {
        self.volume
    }
    pub const fn local(self) -> u64 {
        self.local
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision {
    counter: u64,
    content: ContentDigest,
}
impl Revision {
    pub fn new(counter: u64, content: ContentDigest) -> Option<Self> {
        (counter != u64::MAX).then_some(Self { counter, content })
    }
    pub const fn counter(self) -> u64 {
        self.counter
    }
    pub const fn content(self) -> ContentDigest {
        self.content
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requester {
    pub user: UserId,
    pub session: SessionId,
    pub app: AppRef,
    pub incarnation: Incarnation,
    pub policy_revision: u64,
    pub alive: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectView {
    pub object: ObjectId,
    pub revision: Revision,
    pub permission_revision: u64,
    pub readable: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persistence {
    ThisIncarnation,
    RememberPerUser,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    TrustedPicker,
    ExplicitOwnerAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    requester: Requester,
    object: ObjectView,
    persistence: Persistence,
    expiry: u64,
    created: u64,
    digest: [u8; 32],
}
impl Selection {
    pub const fn requester(&self) -> Requester {
        self.requester
    }
    pub const fn object(&self) -> ObjectView {
        self.object
    }
    pub const fn persistence(&self) -> Persistence {
        self.persistence
    }
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }
    pub const fn action_digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Nonce {
    epoch: PickerEpoch,
    serial: u64,
}
/// Non-Copy pending approval owned by the trusted picker. It is not wire
/// authority, a secret bearer token, or a permission to mint a capability.
#[derive(Debug)]
pub struct Approval {
    nonce: Nonce,
    selection: Selection,
}
impl Approval {
    /// Copyable display/audit metadata; this view alone cannot commit/mint.
    pub const fn selection(&self) -> Selection {
        self.selection
    }
}

/// Data from the authenticated protected input/approval route. The trusted
/// service MUST verify provenance before supplying it; a struct is not consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consent {
    pub displayed_action: [u8; 32],
    pub approver: UserId,
    pub origin: Origin,
}

pub struct ReadDelivery<'a> {
    selection: &'a Selection,
    consent: Consent,
}
impl ReadDelivery<'_> {
    pub const fn selection(&self) -> &Selection {
        self.selection
    }
    pub const fn consent(&self) -> Consent {
        self.consent
    }
}

/// Actual authority handoff is a separate validated integration. Implementors
/// must atomically re-resolve the expected object/revision, current user/policy,
/// actual live recipient incarnation and READ authority immediately before
/// deriving/transferring a scoped read endpoint to the exact protected call.
/// Neither action digest, tuple, identity nor this callback manufactures caps.
/// The current clock must still precede expiry at actual handoff. If state can
/// race, hold the service's serialization/ownership boundary or refuse.
pub trait Handoff {
    type Delivered;
    type Error;
    fn revalidate_and_deliver_read(
        &mut self,
        request: ReadDelivery<'_>,
    ) -> Delivery<Self::Delivered, Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery<T, E> {
    Delivered(T),
    Refused(E),
    Indeterminate(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPolicy,
    Capacity,
    Exhausted,
    StaleApproval,
    ClockReversed,
    Expired,
    RequesterDied,
    RequesterChanged,
    ObjectChanged,
    PermissionChanged,
    Denied,
    WrongApprover,
    DifferentDisplayedAction,
}
#[derive(Clone, Copy)]
struct Pending {
    nonce: Nonce,
    selection: Selection,
}
pub struct Picker {
    epoch: PickerEpoch,
    sequence: u64,
    max_lifetime: u64,
    pending: [Option<Pending>; MAX_PENDING],
}
const fn valid_number(n: u64) -> bool {
    n != 0 && n != u64::MAX
}
impl Picker {
    /// Epoch must differ across picker restarts, as assigned by the trusted
    /// boot/instance registry. This library cannot certify epoch uniqueness.
    pub fn new(epoch: PickerEpoch, max_lifetime: u64) -> Result<Self, Error> {
        if !valid_number(max_lifetime) {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self {
            epoch,
            sequence: 0,
            max_lifetime,
            pending: [None; MAX_PENDING],
        })
    }
    pub fn pending(&self) -> usize {
        self.pending.iter().flatten().count()
    }
    pub fn prepare(
        &mut self,
        requester: Requester,
        object: ObjectView,
        persistence: Persistence,
        now: u64,
        expiry: u64,
    ) -> Result<Approval, Error> {
        if !requester.alive {
            return Err(Error::RequesterDied);
        }
        if !object.readable {
            return Err(Error::Denied);
        }
        if !valid_number(requester.policy_revision)
            || !valid_number(object.permission_revision)
            || expiry == u64::MAX
            || expiry <= now
            || expiry - now > self.max_lifetime
        {
            return Err(Error::InvalidPolicy);
        }
        let slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self
            .sequence
            .checked_add(1)
            .filter(|n| valid_number(*n))
            .ok_or(Error::Exhausted)?;
        let nonce = Nonce {
            epoch: self.epoch,
            serial,
        };
        let mut selection = Selection {
            requester,
            object,
            persistence,
            expiry,
            created: now,
            digest: [0; 32],
        };
        selection.digest = digest(nonce, &selection);
        self.pending[slot] = Some(Pending { nonce, selection });
        self.sequence = serial;
        Ok(Approval { nonce, selection })
    }
    pub fn cancel(&mut self, approval: Approval) -> Result<(), Error> {
        let slot = self.slot(&approval)?;
        self.pending[slot] = None;
        Ok(())
    }
    fn slot(&self, approval: &Approval) -> Result<usize, Error> {
        if approval.nonce.epoch != self.epoch {
            return Err(Error::StaleApproval);
        }
        self.pending
            .iter()
            .position(|entry| {
                entry
                    .is_some_and(|p| p.nonce == approval.nonce && p.selection == approval.selection)
            })
            .ok_or(Error::StaleApproval)
    }
    /// Current views must come from actual live authorities and the current
    /// policy/object owner, never the request packet. A validation failure or
    /// handoff attempt consumes this approval. No automatic retry can duplicate
    /// a delivered cap after an indeterminate result; ask for a fresh action.
    pub fn commit<H: Handoff>(
        &mut self,
        approval: Approval,
        consent: Consent,
        current: Requester,
        object: ObjectView,
        now: u64,
        handoff: &mut H,
    ) -> Result<Delivery<H::Delivered, H::Error>, Error> {
        let slot = self.slot(&approval)?;
        self.pending[slot] = None;
        let selection = approval.selection;
        if now < selection.created {
            return Err(Error::ClockReversed);
        }
        if now >= selection.expiry {
            return Err(Error::Expired);
        }
        if !current.alive {
            return Err(Error::RequesterDied);
        }
        if current.user != selection.requester.user
            || current.session != selection.requester.session
            || current.app != selection.requester.app
            || current.incarnation != selection.requester.incarnation
        {
            return Err(Error::RequesterChanged);
        }
        if current.policy_revision != selection.requester.policy_revision
            || object.permission_revision != selection.object.permission_revision
        {
            return Err(Error::PermissionChanged);
        }
        if object.object != selection.object.object || object.revision != selection.object.revision
        {
            return Err(Error::ObjectChanged);
        }
        if !object.readable {
            return Err(Error::Denied);
        }
        if consent.approver != selection.requester.user {
            return Err(Error::WrongApprover);
        }
        if consent.displayed_action != selection.digest {
            return Err(Error::DifferentDisplayedAction);
        }
        Ok(handoff.revalidate_and_deliver_read(ReadDelivery {
            selection: &selection,
            consent,
        }))
    }
    /// Pending metadata only: actual already-delivered caps require their own
    /// kernel revocation/closed-domain lifecycle, not this table operation.
    pub fn requester_died(&mut self, incarnation: Incarnation) -> usize {
        self.remove(|p| p.selection.requester.incarnation == incarnation)
    }
    pub fn session_closed(&mut self, session: SessionId) -> usize {
        self.remove(|p| p.selection.requester.session == session)
    }
    pub fn expire(&mut self, now: u64) -> usize {
        self.remove(|p| now >= p.selection.expiry)
    }
    fn remove(&mut self, mut predicate: impl FnMut(Pending) -> bool) -> usize {
        let mut removed = 0;
        for entry in &mut self.pending {
            if entry.is_some_and(&mut predicate) {
                *entry = None;
                removed += 1;
            }
        }
        removed
    }
}

fn digest(nonce: Nonce, s: &Selection) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"evrosion.picker.read.v1\0");
    for id in [
        s.requester.user.0,
        s.requester.session.0,
        s.requester.app.app.bytes(),
        s.requester.incarnation.epoch.0,
        s.object.object.volume.0,
        nonce.epoch.0,
    ] {
        hash.update(id);
    }
    hash.update(s.requester.app.package.0);
    for n in [
        s.requester.incarnation.process_generation,
        s.requester.policy_revision,
        s.object.object.local,
        s.object.revision.counter,
        s.object.permission_revision,
        nonce.serial,
        s.expiry,
    ] {
        hash.update(n.to_le_bytes());
    }
    hash.update(s.object.revision.content.0);
    hash.update([
        1,
        match s.persistence {
            Persistence::ThisIncarnation => 0,
            Persistence::RememberPerUser => 1,
        },
    ]);
    hash.finalize().into()
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
