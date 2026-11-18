//! Pure proposed trust-state transitions. Callers must atomically persist exact
//! accepted metadata and this state; returning a value does not commit anything.
use crate::{
    metadata::{self, Binding, Common, Identity, Linked, Root, Target, Targets},
    signature::{Envelope, Role},
};
use ev_time_contract::{
    Instant,
    freshness::{self, Time, Validity},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Metadata(metadata::Error),
    Signature(crate::signature::Error),
    Time(freshness::Error),
    Binding,
    RootCheckpoint,
    RootStep,
    Rollback,
    SameVersionConflict,
    FastForward,
    Link,
    State,
    Capacity,
    Bounds,
}
impl From<metadata::Error> for Error {
    fn from(e: metadata::Error) -> Self {
        Self::Metadata(e)
    }
}
impl From<crate::signature::Error> for Error {
    fn from(e: crate::signature::Error) -> Self {
        Self::Signature(e)
    }
}
impl From<freshness::Error> for Error {
    fn from(e: freshness::Error) -> Self {
        Self::Time(e)
    }
}

/// An explicit finite caller-selected jump bound limits online counter poisoning.
/// A client farther behind must obtain an authorized checkpoint/recovery; this
/// profile does not silently reset floors or pretend to implement all TUF flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    max_version_step: u64,
    max_artifact_bytes: u64,
}
impl Policy {
    pub fn new(max_version_step: u64, max_artifact_bytes: u64) -> Result<Self, Error> {
        if !(1..=1_000_000).contains(&max_version_step)
            || matches!(max_artifact_bytes, 0 | u64::MAX)
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            max_version_step,
            max_artifact_bytes,
        })
    }
}
/// Caller-provisioned trust, not downloaded self-authorization or Official status.
/// Provisioning requires an independently authenticated exact root. Its self
/// quorum is consistency checking, not bootstrap authentication.
pub struct TrustedRoot<'a> {
    root: Root<'a>,
}
impl<'a> TrustedRoot<'a> {
    pub fn provisioned(bytes: &'a [u8], expected: Binding) -> Result<Self, Error> {
        expected.validate()?;
        let envelope = Envelope::parse(bytes)?;
        let root = Root::parse(&envelope)?;
        if root.common().binding != expected {
            return Err(Error::Binding);
        }
        root.authenticate(&envelope)?;
        Ok(Self { root })
    }
    pub fn common(&self) -> Common {
        self.root.common()
    }
    pub fn identity(&self) -> Identity {
        self.root.identity()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.root.bytes()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetFloor {
    pub name: [u8; 32],
    pub version: u64,
    pub identity: [u8; 32],
}
/// Trusted retained state. No field is automatically durable; a lost state must
/// not be recreated as initial state merely because some root bytes still parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayState {
    binding: Binding,
    root: Identity,
    roles: [Option<Identity>; 3],
    targets: [Option<TargetFloor>; metadata::MAX_TARGETS],
    utc_floor: u64,
}
impl ReplayState {
    /// Initial independent provisioning only, never a rotation or recovery reset.
    pub fn initial(root: &TrustedRoot<'_>) -> Self {
        Self {
            binding: root.common().binding,
            root: root.identity(),
            roles: [None; 3],
            targets: [None; metadata::MAX_TARGETS],
            utc_floor: 0,
        }
    }
    /// Syntax-check an already trusted atomic stored checkpoint. This does not
    /// authenticate the medium or resist rollback of the entire storage device.
    pub fn restored(
        root: &TrustedRoot<'_>,
        roles: [Option<Identity>; 3],
        targets: [Option<TargetFloor>; metadata::MAX_TARGETS],
        utc_floor: u64,
    ) -> Result<Self, Error> {
        if roles.iter().any(Option::is_none) && roles.iter().any(Option::is_some) {
            return Err(Error::State);
        }
        for identity in roles.iter().flatten() {
            identity.validate()?;
        }
        if roles[0].is_none() && targets.iter().any(Option::is_some) {
            return Err(Error::State);
        }
        for (i, floor) in targets.iter().enumerate() {
            if let Some(floor) = floor
                && (floor.name == [0; 32]
                    || floor.identity == [0; 32]
                    || matches!(floor.version, 0 | u64::MAX)
                    || targets[..i]
                        .iter()
                        .flatten()
                        .any(|prior| prior.name == floor.name))
            {
                return Err(Error::State);
            }
        }
        Ok(Self {
            binding: root.common().binding,
            root: root.identity(),
            roles,
            targets,
            utc_floor,
        })
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    pub fn root(&self) -> Identity {
        self.root
    }
    pub fn roles(&self) -> &[Option<Identity>; 3] {
        &self.roles
    }
    pub fn targets(&self) -> &[Option<TargetFloor>; metadata::MAX_TARGETS] {
        &self.targets
    }
    pub fn utc_floor(&self) -> u64 {
        self.utc_floor
    }
    fn bound_to(&self, root: &TrustedRoot<'_>) -> Result<(), Error> {
        if self.binding != root.common().binding {
            return Err(Error::Binding);
        }
        if self.root != root.identity() {
            return Err(Error::RootCheckpoint);
        }
        Ok(())
    }
}
pub struct RootAdvance<'a> {
    pub root: TrustedRoot<'a>,
    pub proposed: ReplayState,
    pub changed: bool,
}
/// Root continuity only. Expired historical intermediate roots are permitted;
/// no target is accepted until verify_bundle checks the final root and every
/// current role against a qualified time window. Root and state must be committed
/// together by the caller before a further durable transition is acknowledged.
pub fn advance_root<'a>(
    old: &TrustedRoot<'_>,
    state: &ReplayState,
    candidate: &'a [u8],
) -> Result<RootAdvance<'a>, Error> {
    state.bound_to(old)?;
    let envelope = Envelope::parse(candidate)?;
    let next = Root::parse(&envelope)?;
    if next.common().binding != state.binding {
        return Err(Error::Binding);
    }
    let same = next.identity() == state.root;
    // Also reject a re-signed/different payload at the current version.
    if next.common().version == state.root.version && !same {
        return Err(Error::SameVersionConflict);
    }
    if !same && next.common().version != state.root.version.checked_add(1).ok_or(Error::RootStep)? {
        return Err(Error::RootStep);
    }
    old.root.authenticate(&envelope)?;
    next.authenticate(&envelope)?;
    let mut proposed = *state;
    proposed.root = next.identity();
    Ok(RootAdvance {
        root: TrustedRoot { root: next },
        proposed,
        changed: !same,
    })
}
fn version(prior: Option<Identity>, next: Identity, policy: Policy) -> Result<(), Error> {
    let before = prior.map_or(0, |p| p.version);
    if next.version < before {
        return Err(Error::Rollback);
    }
    if next.version == before {
        if prior != Some(next) {
            return Err(Error::SameVersionConflict);
        }
    } else if next.version - before > policy.max_version_step {
        return Err(Error::FastForward);
    }
    Ok(())
}
fn time(common: Common, sample: Time, now: Instant, floor: u64) -> Result<u64, Error> {
    Ok(freshness::check(
        sample,
        Validity::new(common.not_before, common.expires)?,
        now,
        floor,
    )?
    .next_floor)
}
fn role(
    root: &TrustedRoot<'_>,
    envelope: &Envelope<'_>,
    common: Common,
    state: &ReplayState,
    sample: Time,
    now: Instant,
) -> Result<u64, Error> {
    if common.binding != state.binding {
        return Err(Error::Binding);
    }
    if common.root_version != state.root.version {
        return Err(Error::RootCheckpoint);
    }
    root.root.authenticate(envelope)?;
    root.root.check_lifetime(envelope.role(), common)?;
    time(common, sample, now, state.utc_floor)
}
pub struct Verified<'a> {
    targets: Targets<'a>,
    proposed: ReplayState,
    policy: Policy,
}
impl<'a> Verified<'a> {
    pub fn targets(&self) -> impl ExactSizeIterator<Item = Target<'a>> + '_ {
        self.targets.iter()
    }
    pub fn proposed(&self) -> &ReplayState {
        &self.proposed
    }
    /// Authentic bytes remain neither a loaded image nor runtime authority.
    pub fn verify_artifact(&self, name: [u8; 32], bytes: &[u8]) -> Result<Target<'a>, Error> {
        let target = self
            .targets
            .iter()
            .find(|t| t.spec().name == name)
            .ok_or(Error::Binding)?;
        target.verify_bytes(bytes, self.policy.max_artifact_bytes)?;
        Ok(target)
    }
}
/// Complete immutable envelope references; transport ownership stays external.
pub struct Bundle<'a> {
    pub timestamp: &'a [u8],
    pub snapshot: &'a [u8],
    pub targets: &'a [u8],
}
/// Authenticate all roles and exact links before returning a proposed checkpoint.
/// Every failure leaves the caller's replay state byte-for-byte unchanged.
pub fn verify_bundle<'a>(
    root: &TrustedRoot<'_>,
    state: &ReplayState,
    bundle: Bundle<'a>,
    sample: Time,
    now: Instant,
    policy: Policy,
) -> Result<Verified<'a>, Error> {
    state.bound_to(root)?;
    let timestamp = Envelope::parse(bundle.timestamp)?;
    let snapshot = Envelope::parse(bundle.snapshot)?;
    let targets = Envelope::parse(bundle.targets)?;
    if timestamp.role() != Role::Timestamp
        || snapshot.role() != Role::Snapshot
        || targets.role() != Role::Targets
    {
        return Err(Error::Metadata(metadata::Error::Role));
    }
    let ts = Linked::parse(&timestamp)?;
    let sn = Linked::parse(&snapshot)?;
    let tg = Targets::parse(&targets)?;
    // Whole links include exact signed-envelope length and hash; signature
    // success by itself cannot splice a different authorized repository state.
    if !ts.link().matches(&snapshot, sn.common().version)
        || !sn.link().matches(&targets, tg.common().version)
    {
        return Err(Error::Link);
    }
    let mut proposed = *state;
    proposed.utc_floor = time(root.common(), sample, now, state.utc_floor)?;
    for (envelope, common, id, index) in [
        (&targets, tg.common(), tg.identity(), 0),
        (&snapshot, sn.common(), sn.identity(), 1),
        (&timestamp, ts.common(), ts.identity(), 2),
    ] {
        proposed.utc_floor = proposed
            .utc_floor
            .max(role(root, envelope, common, state, sample, now)?);
        version(state.roles[index], id, policy)?;
        proposed.roles[index] = Some(id);
    }
    for target in tg.iter() {
        let spec = target.spec();
        if spec.length > policy.max_artifact_bytes {
            return Err(Error::Bounds);
        }
        let slot = state
            .targets
            .iter()
            .position(|f| f.is_some_and(|v| v.name == spec.name))
            .or_else(|| proposed.targets.iter().position(Option::is_none))
            .ok_or(Error::Capacity)?;
        let prior = state.targets[slot];
        if let Some(prior) = prior {
            if spec.version < prior.version {
                return Err(Error::Rollback);
            }
            if spec.version == prior.version && target.identity() != prior.identity {
                return Err(Error::SameVersionConflict);
            }
            if spec.version > prior.version
                && spec.version - prior.version > policy.max_version_step
            {
                return Err(Error::FastForward);
            }
        } else if spec.version > policy.max_version_step {
            return Err(Error::FastForward);
        }
        proposed.targets[slot] = Some(TargetFloor {
            name: spec.name,
            version: spec.version,
            identity: target.identity(),
        });
    }
    Ok(Verified {
        targets: tg,
        proposed,
        policy,
    })
}
