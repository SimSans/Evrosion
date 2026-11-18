//! New remote authorization is affine and distinct from later durable IO.
use super::*;
use ev_content_store::Backend;
use ev_release_trust::{
    metadata as md,
    signature::Envelope,
    verifier::{self, ReplayState, TrustedRoot},
};
use ev_time_contract::{
    Instant,
    freshness::{self, QualifiedWindow, Time, Validity},
};
#[derive(Clone, Copy)]
pub struct Material<'a> {
    pub object: Object,
    pub bytes: &'a [u8],
}
pub struct Remote<'a> {
    pub current_root: &'a [u8],
    pub root_updates: &'a [Material<'a>],
    pub metadata: [Material<'a>; 3],
    pub candidate: Material<'a>,
}
/// The private actual Root adapter must independently qualify its provider.
/// No network argument, saved ready flag or author timestamp implements this.
pub trait QualifiedClock {
    type Error;
    fn fresh(&mut self) -> Result<(QualifiedWindow, Instant), Self::Error>;
}
#[must_use = "a decision must be consumed into its exact bounded persistence or explicitly discarded"]
pub struct Decision {
    pub(super) next: Snapshot,
    pub(super) prior: Object,
    pub(super) head: [u8; 32],
    pub(super) revision: u64,
}
impl Decision {
    pub fn proposed(&self) -> &ReplayState {
        &self.next.replay
    }
    pub fn candidate(&self) -> Content {
        self.next.record.candidate.unwrap()
    }
}
fn material(m: Material<'_>, max: usize) -> Result<(), Fault> {
    if m.bytes.len() > max
        || m.bytes.len() as u64 != m.object.length()
        || digest(m.bytes) != m.object.sha256()
    {
        return Err(Fault::Metadata);
    }
    Ok(())
}
fn package(bytes: &[u8], target: md::TargetSpec) -> Result<(), Fault> {
    if target.name != logical_target_name() || !matches!(target.version, 2 | 3) {
        return Err(Fault::Candidate);
    }
    let p = ev_zion::Package::parse(bytes).map_err(|_| Fault::Candidate)?;
    p.check_requirements(
        1,
        ev_userspace_contract::ABI,
        &crate::native_plan::Contracts,
    )
    .map_err(|_| Fault::Candidate)?;
    let a = p.app();
    if a.claimed_app.bytes() != HELLO_APP
        || a.build_id != target.build
        || a.abi != ev_userspace_contract::ABI
        || a.data_schema.current != 1
        || a.data_schema.oldest_readable != 1
        || a.version.major != 0
        || !matches!(a.version.minor, 2 | 3)
        || u64::from(a.version.patch) + 1 != target.version
        || p.id().bytes() != target.sha256
    {
        return Err(Fault::Candidate);
    }
    let prefix = if target.version == 2 {
        b"Evrosion DEV B ".as_slice()
    } else {
        b"Evrosion DEV C ".as_slice()
    };
    let text = a.developer_source.as_bytes();
    if text.len() != prefix.len() + 64 || !text.starts_with(prefix) {
        return Err(Fault::Candidate);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in target.source_revision.iter().enumerate() {
        if text[prefix.len() + 2 * i] != HEX[(b >> 4) as usize]
            || text[prefix.len() + 2 * i + 1] != HEX[(b & 15) as usize]
        {
            return Err(Fault::Candidate);
        }
    }
    if !crate::native_package_profile::downloaded(a) {
        return Err(Fault::Candidate);
    }
    let mut h = Sha256::new();
    ev_userspace_contract::root_v4::dynamic::app_descriptor_transcript(
        &p.executable().digest,
        |b| h.update(b),
    );
    if <[u8; 32]>::from(h.finalize()) != target.contract {
        return Err(Fault::Candidate);
    }
    // Object coordinates are supplied only after the full package association
    // above. Persistence separately rehashes that exact actual stored object.
    Ok(())
}
impl<B: Backend> Store<B> {
    /// All slices are private immutable scoped material (or actual sealed RO
    /// bytes), never independently mutable shared RPC windows. A fresh provider
    /// callback after crypto defines the authorization decision. Subsequent
    /// persistence is completion of that same decision, not fresh authorization.
    pub fn authorize<C: QualifiedClock>(
        &self,
        remote: Remote<'_>,
        clock: &mut C,
    ) -> Result<Decision, Fault> {
        let mut next = None;
        self.authorize_snapshot(remote, clock, &mut next)?;
        Ok(Decision {
            next: next.expect("successful authorization fills its affine output"),
            prior: self
                .arena
                .published_metadata()
                .ok_or(Fault::Unprovisioned)?,
            head: self.arena.head_digest(),
            revision: self.state.as_ref().ok_or(Fault::Unprovisioned)?.revision(),
        })
    }
    /// Same verifier and fresh decision boundary, with resident output. No IO
    /// or ownership transfer occurs until the prepared Commit is consumed.
    pub(super) fn authorize_snapshot<C: QualifiedClock>(
        &self,
        remote: Remote<'_>,
        clock: &mut C,
        next: &mut Option<Snapshot>,
    ) -> Result<(), Fault> {
        if next.is_some() || self.has_unresolved_io() {
            return Err(Fault::Phase);
        }
        let current = self.state.as_ref().ok_or(Fault::Unprovisioned)?;
        self.arena
            .published_metadata()
            .ok_or(Fault::Unprovisioned)?;
        let count = current.record.root_count();
        let object = current.record.roots[count - 1].ok_or(Fault::Root)?;
        if remote.current_root.len() as u64 != object.length()
            || digest(remote.current_root) != object.sha256()
            || remote.root_updates.len() > MAX_ROOT_MATERIALS
        {
            return Err(Fault::Root);
        }
        let mut root =
            TrustedRoot::provisioned(remote.current_root, binding()).map_err(|_| Fault::Root)?;
        if root.identity() != current.replay.root() {
            return Err(Fault::Root);
        }
        let mut replay = current.replay;
        let mut roots = current.record.roots;
        let mut n = count;
        for m in remote.root_updates {
            material(*m, cold::ROOT_BUFFER)?;
            let next = verifier::advance_root(&root, &replay, m.bytes).map_err(|_| Fault::Root)?;
            if next.changed {
                if n == MAX_ROOT_MATERIALS {
                    return Err(Fault::Capacity);
                }
                roots[n] = Some(m.object);
                n += 1;
            }
            replay = next.proposed;
            root = next.root;
        }
        for (i, m) in remote.metadata.iter().enumerate() {
            material(
                *m,
                if i == 0 {
                    cold::TARGET_BUFFER
                } else {
                    cold::LINK_BUFFER
                },
            )?;
        }
        material(
            remote.candidate,
            ev_content_store::MAX_OBJECT_BYTES as usize,
        )?;
        let (first, first_at) = clock.fresh().map_err(|_| Fault::Time)?;
        let verified = verifier::verify_bundle(
            &root,
            &replay,
            verifier::Bundle {
                targets: remote.metadata[0].bytes,
                snapshot: remote.metadata[1].bytes,
                timestamp: remote.metadata[2].bytes,
            },
            Time::Qualified(first),
            first_at,
            verifier::Policy::new(8, ev_content_store::MAX_OBJECT_BYTES)
                .map_err(|_| Fault::Metadata)?,
        )
        .map_err(|_| Fault::Metadata)?;
        if verified.targets().len() != 1 {
            return Err(Fault::Candidate);
        }
        let target = verified
            .verify_artifact(logical_target_name(), remote.candidate.bytes)
            .map_err(|_| Fault::Candidate)?
            .spec();
        // Closed package/descriptor checks are completed before the final
        // provider read. No signature or storage check sets active/healthy/KG.
        package(remote.candidate.bytes, target)?;
        let content = Content {
            object: remote.candidate.object,
            version: target.version,
            app: HELLO_APP,
            package: target.sha256,
            build: target.build,
            descriptor: target.contract,
            source: target.source_revision,
        };
        let proposed = verified.proposed();
        let floor = post_crypto_floor(
            &root,
            verifier::Bundle {
                targets: remote.metadata[0].bytes,
                snapshot: remote.metadata[1].bytes,
                timestamp: remote.metadata[2].bytes,
            },
            proposed,
            first_at,
            clock,
        )?;
        self.finish_authorization(
            &root,
            proposed,
            floor,
            &roots,
            remote.metadata.map(|m| Some(m.object)),
            content,
            next,
        )
    }
    // Record/Snapshot construction is completed AFTER all actual crypto and
    // fresh provider observations, on a separate small branch call chain.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)] // Closed immutable facts, no new owner or authority.
    fn finish_authorization(
        &self,
        root: &TrustedRoot<'_>,
        proposed: &ReplayState,
        floor: u64,
        roots: &[Option<Object>; MAX_ROOT_MATERIALS],
        metadata: [Option<Object>; 3],
        content: Content,
        next: &mut Option<Snapshot>,
    ) -> Result<(), Fault> {
        if next.is_some() {
            return Err(Fault::Phase);
        }
        let current = self.state.as_ref().ok_or(Fault::Unprovisioned)?;
        let replay = ReplayState::restored(root, *proposed.roles(), *proposed.targets(), floor)
            .map_err(|_| Fault::Metadata)?;
        let mut encoded = [0; 1024];
        ev_release_trust::checkpoint::encode(&replay, &mut encoded);
        let record = codec::Record {
            revision: current
                .record
                .revision
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .ok_or(Fault::Capacity)?,
            replay: encoded,
            roots: *roots,
            metadata,
            candidate: Some(content),
            active: current.record.active,
            known_good: current.record.known_good,
            authorizations: [
                Some(Authorization {
                    root: roots.iter().flatten().last().copied().ok_or(Fault::Root)?,
                    targets: metadata[0].ok_or(Fault::Metadata)?,
                }),
                current.record.authorizations[1],
                current.record.authorizations[2],
            ],
        };
        record.validate()?;
        *next = Some(Snapshot { record, replay });
        Ok(())
    }
}

/// Same final actual observation for metadata preparation and full candidate
/// authorization. It preserves the first verifier proposal floor, never
/// converts durability completion into a fresh authorization decision.
pub(super) fn post_crypto_floor<C: QualifiedClock>(
    root: &TrustedRoot<'_>,
    bundle: verifier::Bundle<'_>,
    proposed: &ReplayState,
    first_at: Instant,
    clock: &mut C,
) -> Result<u64, Fault> {
    let te = Envelope::parse(bundle.targets).map_err(|_| Fault::Metadata)?;
    let se = Envelope::parse(bundle.snapshot).map_err(|_| Fault::Metadata)?;
    let tse = Envelope::parse(bundle.timestamp).map_err(|_| Fault::Metadata)?;
    let tc = md::Targets::parse(&te)
        .map_err(|_| Fault::Metadata)?
        .common();
    let sc = md::Linked::parse(&se)
        .map_err(|_| Fault::Metadata)?
        .common();
    let tsc = md::Linked::parse(&tse)
        .map_err(|_| Fault::Metadata)?
        .common();
    let (fresh, at) = clock.fresh().map_err(|_| Fault::Time)?;
    at.elapsed_since(first_at).map_err(|_| Fault::Time)?;
    let mut floor = proposed.utc_floor();
    for c in [root.common(), tc, sc, tsc] {
        floor = floor.max(
            freshness::check(
                Time::Qualified(fresh),
                Validity::new(c.not_before, c.expires).map_err(|_| Fault::Time)?,
                at,
                proposed.utc_floor(),
            )
            .map_err(|_| Fault::Time)?
            .next_floor,
        );
    }
    Ok(floor)
}
