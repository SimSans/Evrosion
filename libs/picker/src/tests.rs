//! Portable policy models only; model delivery values are not capabilities.
use super::*;
mod edit;

fn requester() -> Requester {
    Requester {
        user: UserId::new([1; 16]).unwrap(),
        session: SessionId::new([2; 16]).unwrap(),
        app: AppRef {
            app: AppId::new([3; 16]).unwrap(),
            package: ContentDigest::new([4; 32]).unwrap(),
        },
        incarnation: Incarnation::new(BootEpoch::new([5; 16]).unwrap(), 6).unwrap(),
        policy_revision: 1,
        alive: true,
    }
}
fn object() -> ObjectView {
    ObjectView {
        object: ObjectId::new(VolumeId::new([7; 16]).unwrap(), 1).unwrap(),
        revision: Revision::new(0, ContentDigest::new([8; 32]).unwrap()).unwrap(),
        permission_revision: 1,
        readable: true,
    }
}
fn picker() -> Picker {
    Picker::new(PickerEpoch::new([9; 16]).unwrap(), 32).unwrap()
}
fn consent(a: &Approval) -> Consent {
    Consent {
        displayed_action: a.selection().action_digest(),
        approver: requester().user,
        origin: Origin::TrustedPicker,
    }
}
fn duplicate_for_adversary(a: &Approval) -> Approval {
    Approval {
        nonce: a.nonce,
        selection: a.selection,
    }
}
struct Probe {
    calls: u64,
    outcome: Delivery<u64, u8>,
    intent: Option<intent::Record>,
}
impl Probe {
    fn new() -> Self {
        Self {
            calls: 0,
            outcome: Delivery::Delivered(42),
            intent: None,
        }
    }
}
impl Handoff for Probe {
    type Delivered = u64;
    type Error = u8;
    fn revalidate_and_deliver_read(&mut self, request: ReadDelivery<'_>) -> Delivery<u64, u8> {
        self.calls += 1;
        self.intent = intent::Record::proposed(&request, 1, 1).ok();
        core::mem::replace(&mut self.outcome, Delivery::Indeterminate(9))
    }
}

#[test]
fn exact_displayed_selection_calls_separate_handoff_once_and_no_token_can_replay() {
    let mut p = picker();
    let a = p
        .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
        .unwrap();
    let old = duplicate_for_adversary(&a);
    let c = consent(&a);
    let mut h = Probe::new();
    assert_eq!(
        p.commit(a, c, requester(), object(), 11, &mut h),
        Ok(Delivery::Delivered(42))
    );
    assert_eq!(h.calls, 1);
    assert_eq!(p.pending(), 0);
    assert!(h.intent.is_none());
    assert_eq!(
        p.commit(old, c, requester(), object(), 12, &mut h),
        Err(Error::StaleApproval)
    );
    assert_eq!(h.calls, 1);
}

#[test]
fn every_requester_incarnation_session_package_and_policy_change_refuses_before_handoff() {
    for case in 0..7 {
        let mut p = picker();
        let a = p
            .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap();
        let c = consent(&a);
        let mut r = requester();
        match case {
            0 => r.alive = false,
            1 => r.user = UserId::new([10; 16]).unwrap(),
            2 => r.session = SessionId::new([10; 16]).unwrap(),
            3 => r.app.app = AppId::new([10; 16]).unwrap(),
            4 => r.app.package = ContentDigest::new([10; 32]).unwrap(),
            5 => r.incarnation = Incarnation::new(BootEpoch::new([5; 16]).unwrap(), 7).unwrap(),
            _ => r.policy_revision += 1,
        }
        let mut h = Probe::new();
        assert!(p.commit(a, c, r, object(), 11, &mut h).is_err());
        assert_eq!(h.calls, 0);
        assert_eq!(p.pending(), 0);
    }
}

#[test]
fn object_identity_revision_digest_permission_and_user_action_are_all_bound() {
    for case in 0..7 {
        let mut p = picker();
        let a = p
            .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap();
        let mut c = consent(&a);
        let mut o = object();
        match case {
            0 => o.object = ObjectId::new(VolumeId::new([10; 16]).unwrap(), 1).unwrap(),
            1 => o.object = ObjectId::new(VolumeId::new([7; 16]).unwrap(), 2).unwrap(),
            2 => o.revision = Revision::new(1, o.revision.content).unwrap(),
            3 => o.revision = Revision::new(0, ContentDigest::new([10; 32]).unwrap()).unwrap(),
            4 => o.permission_revision += 1,
            5 => o.readable = false,
            _ => c.displayed_action[0] ^= 1,
        }
        let mut h = Probe::new();
        assert!(p.commit(a, c, requester(), o, 11, &mut h).is_err());
        assert_eq!(h.calls, 0);
    }
    let mut p = picker();
    let a = p
        .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
        .unwrap();
    let mut c = consent(&a);
    c.approver = UserId::new([10; 16]).unwrap();
    let mut h = Probe::new();
    assert_eq!(
        p.commit(a, c, requester(), object(), 11, &mut h),
        Err(Error::WrongApprover)
    );
    assert_eq!(h.calls, 0);
}

#[test]
fn absolute_expiry_clock_reversal_death_and_picker_restart_cannot_extend_approval() {
    for now in [9, 30, 31, u64::MAX] {
        let mut p = picker();
        let a = p
            .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap();
        let c = consent(&a);
        let mut h = Probe::new();
        assert!(p.commit(a, c, requester(), object(), now, &mut h).is_err());
        assert_eq!(h.calls, 0);
    }
    for session in [false, true] {
        let mut p = picker();
        let a = p
            .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap();
        let c = consent(&a);
        assert_eq!(
            if session {
                p.session_closed(requester().session)
            } else {
                p.requester_died(requester().incarnation)
            },
            1
        );
        let mut h = Probe::new();
        assert_eq!(
            p.commit(a, c, requester(), object(), 11, &mut h),
            Err(Error::StaleApproval)
        );
    }
    let mut p = picker();
    let a = p
        .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
        .unwrap();
    let c = consent(&a);
    let mut replacement = Picker::new(PickerEpoch::new([10; 16]).unwrap(), 32).unwrap();
    let mut h = Probe::new();
    assert_eq!(
        replacement.commit(a, c, requester(), object(), 11, &mut h),
        Err(Error::StaleApproval)
    );
}

#[test]
fn bounds_and_nonwrapping_ids_fail_before_allocation_and_reuse_does_not_reuse_nonce() {
    let mut p = picker();
    let mut approvals: [Option<Approval>; MAX_PENDING] = core::array::from_fn(|_| None);
    for a in &mut approvals {
        *a = Some(
            p.prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
                .unwrap(),
        );
    }
    let sequence = p.sequence;
    assert_eq!(
        p.prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap_err(),
        Error::Capacity
    );
    assert_eq!(p.sequence, sequence);
    assert_eq!(p.pending(), MAX_PENDING);
    for a in approvals {
        p.cancel(a.unwrap()).unwrap();
    }
    for _ in 0..100 {
        let a = p
            .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap();
        assert!(a.nonce.serial > sequence);
        p.cancel(a).unwrap();
    }
    p.sequence = u64::MAX - 1;
    assert_eq!(
        p.prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap_err(),
        Error::Exhausted
    );
    assert_eq!(p.pending(), 0);
    assert_eq!(p.sequence, u64::MAX - 1);
}

#[test]
fn backend_refusal_or_indeterminate_delivery_consumes_nonce_without_inventing_a_grant() {
    for outcome in [Delivery::Refused(1), Delivery::Indeterminate(2)] {
        let mut p = picker();
        let a = p
            .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
            .unwrap();
        let old = duplicate_for_adversary(&a);
        let c = consent(&a);
        let mut h = Probe {
            calls: 0,
            outcome,
            intent: None,
        };
        assert!(matches!(
            p.commit(a, c, requester(), object(), 11, &mut h),
            Ok(Delivery::Refused(_) | Delivery::Indeterminate(_))
        ));
        assert_eq!(
            p.commit(old, c, requester(), object(), 12, &mut h),
            Err(Error::StaleApproval)
        );
        assert_eq!(h.calls, 1);
    }
}

fn remembered() -> intent::Record {
    let mut p = picker();
    let a = p
        .prepare(requester(), object(), Persistence::RememberPerUser, 10, 30)
        .unwrap();
    let c = consent(&a);
    let mut h = Probe::new();
    p.commit(a, c, requester(), object(), 11, &mut h).unwrap();
    h.intent.unwrap()
}
#[test]
fn durable_intent_is_stable_per_user_data_and_restores_only_after_fresh_checks() {
    let record = remembered();
    let bytes = record.encode();
    let decoded = intent::Record::decode(&bytes).unwrap();
    assert_eq!(decoded, record);
    let mut new = requester();
    new.incarnation = Incarnation::new(BootEpoch::new([11; 16]).unwrap(), 1).unwrap();
    new.session = SessionId::new([11; 16]).unwrap();
    assert_eq!(
        decoded.validate_activation(decoded.head(), new, object()),
        Ok(())
    );
    assert!(
        !bytes
            .windows(16)
            .any(|slice| slice == requester().session.0)
    );
    assert!(
        !bytes
            .windows(16)
            .any(|slice| slice == requester().incarnation.epoch.0)
    );
    new.app.package = ContentDigest::new([12; 32]).unwrap();
    assert_eq!(
        decoded.validate_activation(decoded.head(), new, object()),
        Err(intent::Error::Subject)
    );
    assert_eq!(
        decoded.validate_activation(
            intent::PolicyHead {
                revision: 2,
                ..decoded.head()
            },
            requester(),
            object()
        ),
        Err(intent::Error::StalePolicy)
    );
    let mut revoked = decoded;
    revoked.revoke().unwrap();
    assert_eq!(
        revoked.validate_activation(revoked.head(), requester(), object()),
        Err(intent::Error::Revoked)
    );
    assert_eq!(
        decoded.validate_activation(revoked.head(), requester(), object()),
        Err(intent::Error::StalePolicy)
    );
}

#[test]
fn durable_codec_rejects_corruption_resealed_widening_unknown_versions_and_reserved_fields() {
    let bytes = remembered().encode();
    for i in 0..bytes.len() {
        let mut bad = bytes;
        bad[i] ^= 0x80;
        assert!(intent::Record::decode(&bad).is_err());
    }
    for (offset, value) in [
        (8, 2),
        (10, 3),
        (11, 0),
        (12, 0),
        (13, 2),
        (14, 1),
        (15, 1),
        (208, 1),
        (223, 1),
    ] {
        let mut bad = bytes;
        bad[offset] = value;
        let sum: [u8; 32] = Sha256::digest(&bad[..224]).into();
        bad[224..].copy_from_slice(&sum);
        assert!(intent::Record::decode(&bad).is_err());
    }
    for length in 0..intent::BYTES {
        assert!(intent::Record::decode(&bytes[..length]).is_err());
    }
    for n in [0, u64::MAX] {
        let mut bad = bytes;
        bad[24..32].copy_from_slice(&n.to_le_bytes());
        let sum: [u8; 32] = Sha256::digest(&bad[..224]).into();
        bad[224..].copy_from_slice(&sum);
        assert!(intent::Record::decode(&bad).is_err());
    }
}

#[test]
fn durable_reboot_revalidation_rejects_dead_incarnation_changed_revision_and_wrong_policy_head() {
    let record = remembered();
    let head = record.head();
    let mut old = requester();
    old.alive = false;
    assert_eq!(
        record.validate_activation(head, old, object()),
        Err(intent::Error::Subject)
    );
    let mut next = requester();
    next.incarnation = Incarnation::new(BootEpoch::new([12; 16]).unwrap(), 12).unwrap();
    assert_eq!(record.validate_activation(head, next, object()), Ok(()));
    let mut revised = object();
    revised.revision = Revision::new(1, revised.revision.content).unwrap();
    assert_eq!(
        record.validate_activation(head, next, revised),
        Err(intent::Error::Resource)
    );
    revised = object();
    revised.readable = false;
    assert_eq!(
        record.validate_activation(head, next, revised),
        Err(intent::Error::Denied)
    );
    for field in 0..4 {
        let mut wrong = head;
        match field {
            0 => wrong.user = UserId::new([13; 16]).unwrap(),
            1 => wrong.grant_serial += 1,
            2 => wrong.revision += 1,
            _ => wrong.record_digest[0] ^= 1,
        }
        assert_eq!(
            record.validate_activation(wrong, next, object()),
            Err(intent::Error::StalePolicy)
        );
    }
    let mut bytes = record.encode();
    bytes[24..32].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    let sum: [u8; 32] = Sha256::digest(&bytes[..224]).into();
    bytes[224..].copy_from_slice(&sum);
    let mut exhausted = intent::Record::decode(&bytes).unwrap();
    let before = exhausted.encode();
    assert_eq!(exhausted.revoke(), Err(intent::Error::Exhausted));
    assert_eq!(exhausted.encode(), before);
}

#[test]
fn arbitrary_bounded_operation_sequences_do_not_exceed_metadata_or_call_on_stale_approval() {
    let mut p = picker();
    let mut slots: [Option<Approval>; MAX_PENDING] = core::array::from_fn(|_| None);
    let mut random = 1u64;
    let mut h = Probe::new();
    for now in 0..2048 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let index = (random as usize) % MAX_PENDING;
        match (random >> 8) % 5 {
            0 => {
                if slots[index].is_none() {
                    slots[index] = p
                        .prepare(
                            requester(),
                            object(),
                            Persistence::ThisIncarnation,
                            now,
                            now + 8,
                        )
                        .ok();
                }
            }
            1 => {
                if let Some(a) = slots[index].take() {
                    let c = consent(&a);
                    let _ = p.commit(a, c, requester(), object(), now, &mut h);
                }
            }
            2 => {
                if let Some(a) = slots[index].take() {
                    let _ = p.cancel(a);
                }
            }
            3 => {
                p.expire(now);
            }
            _ => {
                p.requester_died(requester().incarnation);
            }
        }
        assert!(p.pending() <= MAX_PENDING);
    }
}
