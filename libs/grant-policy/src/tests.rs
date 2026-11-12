//! Actual Store/Picker component tests and explicit modeled handoff callbacks.
//! Counters/unit tickets here are NOT physical capabilities or consent proof.
use super::{consent, policy::*};
use ev_picker::{
    self as picker, AppId, AppRef, BootEpoch, Consent, ContentDigest, Delivery, Handoff,
    Incarnation, ObjectView, Origin, Persistence, Picker, PickerEpoch, ReadDelivery, Requester,
    Revision, SessionId, UserId, VolumeId, intent,
};
use ev_store::{
    BootPolicy, GenerationId, GenerationManifest, SECTOR_BYTES, Sector, SectorIo, Store,
};
use sha2::{Digest as _, Sha256};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    vec,
    vec::Vec,
};

const DEADLINE: u64 = 100_000;
const START: usize = 96;
const END: usize = START + ev_store::REQUIRED_SECTORS as usize;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Power,
    Offline,
    Bounds,
    Deadline,
    Readonly,
}
#[derive(Clone, Copy, Debug)]
enum Cut {
    Before,
    After,
    Torn,
}
#[derive(Default)]
struct Probe {
    trace: RefCell<Vec<char>>,
    cut: Cell<Option<(usize, Cut)>>,
}
#[derive(Clone)]
struct Disk {
    cache: Vec<Sector>,
    durable: Vec<Sector>,
    offline: bool,
    readonly: bool,
    probe: Rc<Probe>,
}
impl Disk {
    fn blank() -> Self {
        let mut bytes = vec![[0xa7; SECTOR_BYTES]; 128];
        bytes[START..END].fill([0; SECTOR_BYTES]);
        Self {
            cache: bytes.clone(),
            durable: bytes,
            offline: false,
            readonly: false,
            probe: Rc::new(Probe::default()),
        }
    }
    fn cold(mut self) -> Self {
        self.cache = self.durable.clone();
        self.offline = false;
        self.probe = Rc::new(Probe::default());
        self
    }
    fn enter(&mut self, kind: char, local: u64, deadline: u64) -> Result<Option<Cut>, Fault> {
        if self.offline {
            return Err(Fault::Offline);
        }
        if deadline == 0 || deadline == u64::MAX {
            return Err(Fault::Deadline);
        }
        if local >= ev_store::REQUIRED_SECTORS {
            return Err(Fault::Bounds);
        }
        if self.readonly && matches!(kind, 'w' | 'f') {
            return Err(Fault::Readonly);
        }
        let mut trace = self.probe.trace.borrow_mut();
        trace.push(kind);
        Ok(self
            .probe
            .cut
            .get()
            .filter(|(n, _)| *n == trace.len())
            .map(|(_, cut)| cut))
    }
    fn lost(&mut self) -> Result<(), Fault> {
        self.offline = true;
        Err(Fault::Power)
    }
    fn guards(&self) {
        for (i, b) in self.durable.iter().enumerate() {
            if !(START..END).contains(&i) {
                assert_eq!(*b, [0xa7; SECTOR_BYTES], "outside policy region{i}");
            }
        }
    }
}
impl SectorIo for Disk {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Fault> {
        if self.enter('r', lba, deadline)?.is_some() {
            self.lost()?;
        }
        *out = self.cache[START + lba as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Fault> {
        let cut = self.enter('w', lba, deadline)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        let at = START + lba as usize;
        self.cache[at] = *bytes;
        match cut {
            Some(Cut::After) => self.durable[at] = *bytes,
            Some(Cut::Torn) => self.durable[at][..257].copy_from_slice(&bytes[..257]),
            Some(Cut::Before) | None => {}
        }
        if cut.is_some() {
            self.lost()?;
        }
        Ok(())
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Fault> {
        let cut = self.enter('f', 0, deadline)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        if matches!(cut, Some(Cut::Torn)) {
            for at in (START..END).step_by(2) {
                self.durable[at] = self.cache[at];
            }
        } else {
            self.durable = self.cache.clone();
        }
        if cut.is_some() {
            self.lost()?;
        }
        Ok(())
    }
}
fn scope() -> Scope {
    Scope {
        user: UserId::new(*b"EVROSION-OWNER01").unwrap(),
        app: AppId::new([3; 16]).unwrap(),
    }
}
fn requester(revision: u64, process: u64) -> Requester {
    Requester {
        user: scope().user,
        session: SessionId::new([2; 16]).unwrap(),
        app: AppRef {
            app: scope().app,
            package: ContentDigest::new([4; 32]).unwrap(),
        },
        incarnation: Incarnation::new(BootEpoch::new([5; 16]).unwrap(), process).unwrap(),
        policy_revision: revision,
        alive: true,
    }
}
fn object() -> ObjectView {
    ObjectView {
        object: picker::ObjectId::new(VolumeId::new([7; 16]).unwrap(), 1).unwrap(),
        revision: Revision::new(0, ContentDigest::new([8; 32]).unwrap()).unwrap(),
        permission_revision: 1,
        readable: true,
    }
}
fn context() -> GenerationManifest {
    // Fixture creation provenance only; no healthy generation or known-good.
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: Sha256::digest(b"policy namespace fixture").into(),
        supervisor_image: [2; 32],
        abi: [3; 32],
        health_contract: Sha256::digest(b"format-context-only; no admitted health").into(),
        health_version: 1,
        required_checks: 3,
    }
}
fn empty() -> PolicyOwner<Disk> {
    PolicyOwner::format_empty(Disk::blank(), scope(), context(), DEADLINE)
        .unwrap_or_else(|r| panic!("format {:?}", r.error))
}
struct CaptureProposal<'a> {
    owner: &'a PolicyOwner<Disk>,
    expected: Expected,
    prepared: Option<Prepared>,
}
impl Handoff for CaptureProposal<'_> {
    type Delivered = ();
    type Error = Error<Fault>;
    fn revalidate_and_deliver_read(
        &mut self,
        request: ReadDelivery<'_>,
    ) -> Delivery<(), Self::Error> {
        match self.owner.prepare_remember(self.expected, &request) {
            Ok(p) => {
                self.prepared = Some(p);
                Delivery::Delivered(())
            }
            Err(error) => Delivery::Refused(error),
        }
    }
}
fn proposal(owner: &PolicyOwner<Disk>, persistence: Persistence) -> Result<Prepared, Error<Fault>> {
    let req = requester(owner.requester_policy_revision().unwrap(), 6);
    let mut picker = Picker::new(PickerEpoch::new([9; 16]).unwrap(), 32).unwrap();
    let approval = picker.prepare(req, object(), persistence, 10, 30).unwrap();
    let consent = Consent {
        displayed_action: approval.selection().action_digest(),
        approver: req.user,
        origin: Origin::ExplicitOwnerAction,
    };
    let mut capture = CaptureProposal {
        owner,
        expected: owner.expected().unwrap(),
        prepared: None,
    };
    match picker
        .commit(approval, consent, req, object(), 11, &mut capture)
        .unwrap()
    {
        Delivery::Delivered(()) => Ok(capture.prepared.unwrap()),
        Delivery::Refused(error) | Delivery::Indeterminate(error) => Err(error),
    }
}
fn active() -> PolicyOwner<Disk> {
    let mut owner = empty();
    let intent = proposal(&owner, Persistence::RememberPerUser).unwrap();
    owner.publish(intent, DEADLINE).unwrap();
    owner
}
#[derive(Default)]
struct ModeledHandoff {
    calls: usize,
    requesters: Vec<Requester>,
}
impl FreshReadHandoff for ModeledHandoff {
    type Ticket = ();
    type Error = ();
    fn enqueue_fresh_read(&mut self, eligible: Eligible<'_>) -> Delivery<(), ()> {
        assert_eq!(eligible.record().head(), eligible.head());
        assert!(eligible.object().readable);
        self.calls += 1;
        self.requesters.push(eligible.requester());
        Delivery::Delivered(())
    }
}

#[test]
fn cold_policy_recreates_eligibility_for_new_incarnation_without_saved_session_or_handle() {
    let owner = active();
    let bytes = owner.record().unwrap().unwrap().encode();
    let (disk, binding, pending) = owner.into_parts();
    assert!(pending.is_none());
    disk.guards();
    let mut owner =
        PolicyOwner::open(disk.cold(), binding, DEADLINE).unwrap_or_else(|_| panic!("cold"));
    let mut current = requester(1, 91);
    current.session = SessionId::new([0x31; 16]).unwrap();
    current.incarnation = Incarnation::new(BootEpoch::new([0x32; 16]).unwrap(), 91).unwrap();
    let mut handoff = ModeledHandoff::default();
    assert_eq!(
        owner.remint(current, object(), DEADLINE, &mut handoff),
        Ok(Delivery::Delivered(()))
    );
    assert_eq!(handoff.requesters, vec![current]);
    assert_eq!(bytes, owner.record().unwrap().unwrap().encode());
    assert!(bytes[208..224].iter().all(|b| *b == 0));
    assert_eq!(bytes[13], 1); // UntilRevoked; no monotonic lease serialized.
}

#[test]
fn cold_subject_object_and_revision_negatives_never_invoke_handoff() {
    for case in 0..11 {
        let mut owner = active();
        let mut current = requester(1, 91);
        let mut view = object();
        match case {
            0 => current.alive = false,
            1 => current.user = UserId::new([0x10; 16]).unwrap(),
            2 => current.app.app = AppId::new([0x10; 16]).unwrap(),
            3 => current.app.package = ContentDigest::new([0x10; 32]).unwrap(),
            4 => current.policy_revision = 2,
            5 => {
                view.object = picker::ObjectId::new(VolumeId::new([0x10; 16]).unwrap(), 1).unwrap()
            }
            6 => view.object = picker::ObjectId::new(view.object.volume(), 2).unwrap(),
            7 => view.revision = Revision::new(1, view.revision.content()).unwrap(),
            8 => view.revision = Revision::new(0, ContentDigest::new([0x10; 32]).unwrap()).unwrap(),
            9 => view.readable = false,
            _ => view.permission_revision += 1,
        }
        let mut handoff = ModeledHandoff::default();
        assert!(
            owner.remint(current, view, DEADLINE, &mut handoff).is_err(),
            "case{case}"
        );
        assert_eq!(handoff.calls, 0);
    }
}

#[test]
fn tombstone_cold_reopen_denies_old_policy_and_regrant_advances_both_numbers() {
    let mut owner = active();
    let old = owner.record().unwrap().unwrap();
    assert!(matches!(
        proposal(&owner, Persistence::RememberPerUser),
        Err(Error::Active)
    ));
    let revoke = owner.prepare_revoke(owner.expected().unwrap()).unwrap();
    owner.publish(revoke, DEADLINE).unwrap();
    let tombstone = owner.record().unwrap().unwrap();
    assert!(tombstone.revoked());
    assert_eq!(tombstone.policy_revision(), 2);
    assert_eq!(
        old.validate_activation(tombstone.head(), requester(2, 9), object()),
        Err(intent::Error::StalePolicy)
    );
    let (disk, binding, _) = owner.into_parts();
    let mut owner =
        PolicyOwner::open(disk.cold(), binding, DEADLINE).unwrap_or_else(|_| panic!("cold"));
    let mut handoff = ModeledHandoff::default();
    assert!(matches!(
        owner.remint(requester(2, 10), object(), DEADLINE, &mut handoff),
        Err(Error::Policy(intent::Error::Revoked))
    ));
    assert_eq!(handoff.calls, 0);
    let intent = proposal(&owner, Persistence::RememberPerUser).unwrap();
    owner.publish(intent, DEADLINE).unwrap();
    let new = owner.record().unwrap().unwrap();
    assert_eq!(new.grant_serial(), 2);
    assert_eq!(new.policy_revision(), 3);
    assert!(!new.revoked());
    owner
        .remint(requester(3, 12), object(), DEADLINE, &mut handoff)
        .unwrap();
    assert_eq!(handoff.calls, 1);
}

#[test]
fn temporary_delivery_cannot_be_promoted_without_remember_consent() {
    assert!(matches!(
        proposal(&empty(), Persistence::ThisIncarnation),
        Err(Error::Policy(intent::Error::Temporary))
    ));
}

#[test]
fn every_publication_boundary_cold_recovers_old_or_new_policy_without_guard_writes() {
    // Establish exact actual operation trace, then cut before/after/torn at
    // every real read/write/flush. Test both remember and revoke publication.
    for revoking in [false, true] {
        let baseline = if revoking { active() } else { empty() };
        let old = baseline.record().unwrap();
        let (disk, binding, _) = baseline.into_parts();
        let initial = disk.cold();
        let traced_disk = initial.clone().cold();
        let trace_probe = traced_disk.probe.clone();
        let mut traced =
            PolicyOwner::open(traced_disk, binding, DEADLINE).unwrap_or_else(|_| panic!("trace"));
        // Use newly prepared exact intent for this actual owner.
        let traced_intent = if revoking {
            traced.prepare_revoke(traced.expected().unwrap()).unwrap()
        } else {
            proposal(&traced, Persistence::RememberPerUser).unwrap()
        };
        let after = traced_intent.after();
        trace_probe.trace.borrow_mut().clear();
        traced.publish(traced_intent, DEADLINE).unwrap();
        let boundaries = trace_probe.trace.borrow().len();
        assert!(boundaries > 8);
        for nth in 1..=boundaries {
            for cut in [Cut::Before, Cut::After, Cut::Torn] {
                let disk = initial.clone().cold();
                let probe = disk.probe.clone();
                let mut owner = PolicyOwner::open(disk, binding, DEADLINE)
                    .unwrap_or_else(|_| panic!("cut setup"));
                let intent = if revoking {
                    owner.prepare_revoke(owner.expected().unwrap()).unwrap()
                } else {
                    proposal(&owner, Persistence::RememberPerUser).unwrap()
                };
                probe.trace.borrow_mut().clear();
                probe.cut.set(Some((nth, cut)));
                let outcome = owner.publish(intent, DEADLINE);
                if outcome.is_err() {
                    assert!(matches!(owner.expected(), Err(Error::NeedsRecovery)));
                }
                let (disk, binding, pending) = owner.into_parts();
                disk.guards();
                let (mut recovered, resolution) =
                    PolicyOwner::resume(disk.cold(), binding, pending, DEADLINE).unwrap_or_else(
                        |r| {
                            panic!(
                                "recovery revoke={revoking} nth={nth} {cut:?}: {:?}",
                                r.error
                            )
                        },
                    );
                let actual = recovered.record().unwrap();
                assert!(
                    actual == old || actual == Some(after),
                    "half policy revoke={revoking} nth={nth}"
                );
                let mut handoff = ModeledHandoff::default();
                let rev = recovered.requester_policy_revision().unwrap();
                let _ = recovered.remint(requester(rev, 80), object(), DEADLINE, &mut handoff);
                if actual.is_none_or(|r| r.revoked()) {
                    assert_eq!(handoff.calls, 0);
                }
                if let Resolution::Unpublished(same) = resolution {
                    assert_eq!(same.operation(), recovered.expected().unwrap().operation);
                    recovered.publish(same, DEADLINE).unwrap();
                    assert_eq!(recovered.record().unwrap(), Some(after));
                }
                recovered.into_parts().0.guards();
            }
        }
    }
}

#[test]
fn readonly_cold_policy_open_cannot_repair_a_committed_pending_journal() {
    let mut owner = empty();
    let p = proposal(&owner, Persistence::RememberPerUser).unwrap();
    let (disk, binding, _) = owner.into_parts();
    let probe = disk.probe.clone();
    owner = PolicyOwner::open(disk, binding, DEADLINE).unwrap_or_else(|_| panic!("open"));
    probe.trace.borrow_mut().clear();
    owner.publish(p, DEADLINE).unwrap();
    let trace = probe.trace.borrow().clone();
    let first_commit_flush = trace
        .iter()
        .enumerate()
        .filter(|(_, k)| **k == 'f')
        .nth(1)
        .unwrap()
        .0
        + 1;
    let mut owner = empty();
    let intent = proposal(&owner, Persistence::RememberPerUser).unwrap();
    let (disk, binding, _) = owner.into_parts();
    let probe = disk.probe.clone();
    owner = PolicyOwner::open(disk, binding, DEADLINE).unwrap_or_else(|_| panic!("open"));
    probe.trace.borrow_mut().clear();
    probe.cut.set(Some((first_commit_flush, Cut::After)));
    assert!(owner.publish(intent, DEADLINE).is_err());
    let (disk, binding, _) = owner.into_parts();
    let mut cold = disk.cold();
    cold.readonly = true;
    assert!(PolicyOwner::open(cold, binding, DEADLINE).is_err());
}

#[test]
fn corrupt_wrong_scope_and_blank_policy_are_refused_without_formatting() {
    let blank = Disk::blank();
    let before = blank.durable.clone();
    let denied = PolicyOwner::open(blank, scope(), DEADLINE).err().unwrap();
    assert_eq!(denied.device.durable, before);
    let owner = empty();
    let (disk, _, _) = owner.into_parts();
    let mut wrong = scope();
    wrong.user = UserId::new([0x49; 16]).unwrap();
    assert!(matches!(
        PolicyOwner::open(disk, wrong, DEADLINE)
            .err()
            .unwrap()
            .error,
        Error::Corrupt
    ));
    let store = Store::format_new(
        Disk::blank(),
        context(),
        &[0x42; 256],
        BootPolicy::new(1).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("format invalid policy data"));
    let disk = store.into_device();
    let before = disk.durable.clone();
    let refused = PolicyOwner::open(disk, scope(), DEADLINE).err().unwrap();
    assert_eq!(refused.error, Error::Corrupt);
    assert_eq!(refused.device.durable, before);
}

#[test]
fn a_resealed_old_record_cannot_become_the_latest_policy_under_a_fresh_store_operation() {
    let owner = active();
    let record = owner.record().unwrap().unwrap();
    let (disk, binding, _) = owner.into_parts();
    let mut store = Store::open(disk, DEADLINE).unwrap_or_else(|_| panic!("store"));
    store
        .execute(
            store.next_operation().unwrap(),
            ev_store::Request::WriteMutable {
                object: ev_store::ObjectId::user_data(),
                bytes: &record.encode(),
            },
            DEADLINE,
        )
        .unwrap();
    let refused = PolicyOwner::open(store.into_device(), binding, DEADLINE)
        .err()
        .unwrap();
    assert_eq!(refused.error, Error::Corrupt);
    refused.device.guards();
}

#[test]
fn an_active_grant_formatted_without_a_policy_publication_is_not_a_latest_head() {
    let record = active().record().unwrap().unwrap();
    let store = Store::format_new(
        Disk::blank(),
        context(),
        &record.encode(),
        BootPolicy::new(1).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("store"));
    let refused = PolicyOwner::open(store.into_device(), scope(), DEADLINE)
        .err()
        .unwrap();
    assert_eq!(refused.error, Error::Corrupt);
    refused.device.guards();
}

#[test]
fn interrupted_first_allocation_fails_closed_and_never_formats_over_partial_bytes() {
    let disk = Disk::blank();
    let probe = disk.probe.clone();
    // Fourteen blank reads, then a genuine accepted format-data write whose
    // reply is lost before any Store root exists. This is not a journaled op.
    probe.cut.set(Some((15, Cut::After)));
    let refused = PolicyOwner::format_empty(disk, scope(), context(), DEADLINE)
        .err()
        .unwrap();
    let disk = refused.device.cold();
    let before = disk.durable.clone();
    assert!(before[START..END].iter().flatten().any(|b| *b != 0));
    let refused = PolicyOwner::open(disk, scope(), DEADLINE).err().unwrap();
    assert_eq!(refused.device.durable, before);
    refused.device.guards();
    let refused = PolicyOwner::format_empty(refused.device, scope(), context(), DEADLINE)
        .err()
        .unwrap();
    assert_eq!(refused.error, Error::Store(ev_store::Error::NotBlank));
    assert_eq!(refused.device.durable, before);
}

#[test]
fn uncertain_read_latches_recovery_before_another_remint() {
    let owner = active();
    let (disk, binding, _) = owner.into_parts();
    let probe = disk.probe.clone();
    let mut owner = PolicyOwner::open(disk, binding, DEADLINE).unwrap_or_else(|_| panic!("open"));
    probe.trace.borrow_mut().clear();
    probe.cut.set(Some((1, Cut::Before)));
    let mut handoff = ModeledHandoff::default();
    assert!(
        owner
            .remint(requester(1, 44), object(), DEADLINE, &mut handoff)
            .is_err()
    );
    assert!(matches!(owner.expected(), Err(Error::NeedsRecovery)));
    let before = probe.trace.borrow().len();
    assert!(matches!(
        owner.remint(requester(1, 44), object(), DEADLINE, &mut handoff),
        Err(Error::NeedsRecovery)
    ));
    assert_eq!(probe.trace.borrow().len(), before);
    assert_eq!(handoff.calls, 0);
}

#[test]
fn scoped_owner_does_not_drop_an_unresolved_publication_or_device_on_refusal() {
    let empty = empty();
    let (disk, binding, _) = empty.into_parts();
    let probe = disk.probe.clone();
    let rejected = PolicyOwner::with_open(disk, binding, DEADLINE, |owner| {
        let p = proposal(owner, Persistence::RememberPerUser).unwrap();
        probe.trace.borrow_mut().clear();
        probe.cut.set(Some((1, Cut::Before)));
        owner.publish(p, DEADLINE)
    })
    .err()
    .unwrap();
    assert!(rejected.pending.is_some());
    rejected.device.guards();
    let (owner, resolution) =
        PolicyOwner::resume(rejected.device.cold(), binding, rejected.pending, DEADLINE)
            .unwrap_or_else(|_| panic!("scope resume"));
    assert!(matches!(resolution, Resolution::Unpublished(_)));
    assert!(owner.record().unwrap().is_none());
}

fn accepted_lost_reply() -> (Disk, Scope, Prepared) {
    let baseline = empty();
    let (disk, binding, _) = baseline.into_parts();
    let snapshot = disk.cold();
    let trace_disk = snapshot.clone().cold();
    let probe = trace_disk.probe.clone();
    let mut traced =
        PolicyOwner::open(trace_disk, binding, DEADLINE).unwrap_or_else(|_| panic!("trace"));
    let prepared = proposal(&traced, Persistence::RememberPerUser).unwrap();
    probe.trace.borrow_mut().clear();
    traced.publish(prepared, DEADLINE).unwrap();
    let last_flush = probe
        .trace
        .borrow()
        .iter()
        .rposition(|kind| *kind == 'f')
        .unwrap()
        + 1;
    let disk = snapshot.cold();
    let probe = disk.probe.clone();
    let mut owner = PolicyOwner::open(disk, binding, DEADLINE).unwrap_or_else(|_| panic!("lost"));
    let prepared = proposal(&owner, Persistence::RememberPerUser).unwrap();
    probe.trace.borrow_mut().clear();
    probe.cut.set(Some((last_flush, Cut::After)));
    assert!(owner.publish(prepared, DEADLINE).is_err());
    let (disk, binding, pending) = owner.into_parts();
    (disk.cold(), binding, pending.unwrap())
}

#[test]
fn accepted_but_lost_reply_resolves_original_operation_without_double_publication() {
    let (disk, binding, pending) = accepted_lost_reply();
    let expected_bytes = pending.after().encode();
    let original = pending.operation();
    let (owner, resolution) = PolicyOwner::resume(disk, binding, Some(pending), DEADLINE)
        .unwrap_or_else(|r| panic!("resume {:?}", r.error));
    let Resolution::Committed(published) = resolution else {
        panic!("must be committed")
    };
    assert!(published.recovered);
    assert_eq!(published.operation, original);
    assert_eq!(published.revision, 1);
    assert_eq!(published.sequence, 2);
    assert_eq!(owner.expected().unwrap().operation.get(), 2);
    assert_eq!(owner.record().unwrap().unwrap().encode(), expected_bytes);
    owner.into_parts().0.guards();
}

#[test]
fn unresolved_original_intent_conflicts_with_a_different_later_authoritative_head() {
    let (disk, binding, old_pending) = accepted_lost_reply();
    let mut owner = PolicyOwner::open(disk, binding, DEADLINE).unwrap_or_else(|_| panic!("open"));
    let expected = owner.expected().unwrap();
    let revoke = owner.prepare_revoke(expected).unwrap();
    let stale_copy = owner.prepare_revoke(expected).unwrap();
    owner.publish(revoke, DEADLINE).unwrap();
    assert!(matches!(
        owner.publish(stale_copy, DEADLINE),
        Err(Error::Stale)
    ));
    let (disk, binding, pending) = owner.into_parts();
    assert!(pending.is_none());
    let refused = PolicyOwner::resume(disk.cold(), binding, Some(old_pending), DEADLINE)
        .err()
        .unwrap();
    assert_eq!(refused.error, Error::RecoveryConflict);
    assert_eq!(refused.pending.unwrap().operation().get(), 1);
    refused.device.guards();
}

fn gate() -> consent::Gate {
    let mut gate = consent::Gate::prepare([0x71; 32], scope().user, 1).unwrap();
    gate.arm_after_actual_prompt(10, 30).unwrap();
    gate
}
fn approval_line(gate: &consent::Gate) -> Vec<u8> {
    let mut line = b"approve ".to_vec();
    line.extend_from_slice(gate.token());
    line.push(b'\n');
    line
}
#[test]
fn actual_prompt_parser_requires_complete_exact_fresh_line_and_explicit_origin() {
    let mut gate = gate();
    let line = approval_line(&gate);
    for byte in &line[..line.len() - 1] {
        assert_eq!(gate.byte(*byte, 11), Ok(None));
    }
    let consent = gate.byte(b'\n', 12).unwrap().unwrap();
    assert_eq!(consent.origin, Origin::ExplicitOwnerAction);
    assert_eq!(consent.displayed_action, [0x71; 32]);
    assert_eq!(gate.byte(b'\n', 13), Err(consent::Error::Inactive));
    for case in 0..6 {
        let mut gate = self::gate();
        let mut line = approval_line(&gate);
        match case {
            0 => line[10] ^= 1,
            1 => line.insert(0, b' '),
            2 => line.insert(line.len() - 1, b' '),
            3 => line.insert(0, 0x1b),
            4 => {
                line.pop();
            }
            _ => line[0] = b'A',
        }
        let mut approved = false;
        for b in line {
            if let Ok(Some(_)) = gate.byte(b, 11) {
                approved = true;
            }
        }
        assert!(!approved, "case{case}");
        assert_eq!(gate.end_of_input(), Err(consent::Error::Incomplete));
    }
    assert_eq!(self::gate().byte(b'a', 30), Err(consent::Error::Expired));
    assert_eq!(self::gate().byte(b'a', 9), Err(consent::Error::Clock));
    let mut unarmed = consent::Gate::prepare([1; 32], scope().user, 2).unwrap();
    assert_eq!(unarmed.byte(b'a', 11), Err(consent::Error::Inactive));
    unarmed.arm_after_actual_prompt(10, 30).unwrap();
    assert_eq!(
        unarmed.arm_after_actual_prompt(11, 31),
        Err(consent::Error::Inactive)
    );
}

#[test]
fn revoke_confirmation_binds_latest_grant_subject_revision_and_distinct_action() {
    let latest = active().record().unwrap().unwrap();
    let head = latest.head();
    let action = consent::revoke_action(
        head.user,
        scope().app,
        head.grant_serial,
        head.revision,
        head.record_digest,
    )
    .unwrap();
    for case in 0..5 {
        let mut owner = head.user;
        let mut app = scope().app;
        let mut serial = head.grant_serial;
        let mut revision = head.revision;
        let mut digest = head.record_digest;
        match case {
            0 => owner = UserId::new([0x60; 16]).unwrap(),
            1 => app = AppId::new([0x60; 16]).unwrap(),
            2 => serial += 1,
            3 => revision += 1,
            _ => digest[0] ^= 1,
        }
        assert_ne!(
            action,
            consent::revoke_action(owner, app, serial, revision, digest).unwrap()
        );
    }
    assert!(consent::revoke_action(head.user, scope().app, 0, 1, head.record_digest).is_err());
    let read_action: [u8; 32] = latest.encode()[176..208].try_into().unwrap();
    assert_ne!(action, read_action);
    assert_ne!(
        consent::Gate::prepare(action, head.user, 1)
            .unwrap()
            .token(),
        consent::Gate::prepare(read_action, head.user, 1)
            .unwrap()
            .token()
    );
}
