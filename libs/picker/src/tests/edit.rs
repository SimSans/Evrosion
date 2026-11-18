//! Shared picker ownership with distinct read/edit approval semantics.
use super::*;

fn editable() -> EditObjectView {
    EditObjectView {
        object: object(),
        writable: true,
    }
}
struct EditProbe {
    calls: u64,
    selection: Option<Selection>,
    outcome: Delivery<u64, u8>,
}
impl EditProbe {
    fn new() -> Self {
        Self {
            calls: 0,
            selection: None,
            outcome: Delivery::Delivered(52),
        }
    }
}
impl EditHandoff for EditProbe {
    type Delivered = u64;
    type Error = u8;
    fn revalidate_and_deliver_edit(&mut self, request: EditDelivery<'_>) -> Delivery<u64, u8> {
        assert_eq!(request.selection().access(), Access::Edit);
        assert_eq!(
            request.selection().persistence(),
            Persistence::ThisIncarnation
        );
        assert_eq!(
            request.consent().displayed_action,
            request.selection().action_digest()
        );
        self.calls += 1;
        self.selection = Some(*request.selection());
        core::mem::replace(&mut self.outcome, Delivery::Indeterminate(9))
    }
}

#[test]
fn legacy_read_action_is_byte_exact_and_edit_intent_has_an_independent_domain() {
    let a = picker()
        .prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
        .unwrap();
    let encoded = a
        .selection()
        .action_digest()
        .iter()
        .map(|b| std::format!("{b:02x}"))
        .collect::<std::string::String>();
    // Independently encoded from the pre-M7 read.v1 field order/profile.
    assert_eq!(
        encoded,
        "756c25409bbcbd849fd27ca4f99a14a4daeb2cef2211ddcf55467094083530cd"
    );
    let edit = picker()
        .prepare_edit(requester(), editable(), 10, 30)
        .unwrap();
    assert_eq!(a.selection().access(), Access::Read);
    assert_eq!(edit.selection().access(), Access::Edit);
    assert_ne!(
        a.selection().action_digest(),
        edit.selection().action_digest()
    );
}

#[test]
fn exact_edit_approval_calls_only_edit_handoff_once_and_cannot_be_replayed() {
    let mut p = picker();
    let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
    let old = duplicate_for_adversary(&a);
    let c = consent(&a);
    let mut h = EditProbe::new();
    assert_eq!(
        p.commit_edit(a, c, requester(), editable(), 11, &mut h),
        Ok(Delivery::Delivered(52))
    );
    assert_eq!(h.calls, 1);
    assert_eq!(p.pending(), 0);
    assert_eq!(h.selection.unwrap().object(), object());
    assert_eq!(
        p.commit_edit(old, c, requester(), editable(), 12, &mut h),
        Err(Error::StaleApproval)
    );
    assert_eq!(h.calls, 1);
}

#[test]
fn read_approval_never_becomes_edit_and_edit_approval_never_becomes_a_read_intent() {
    let mut p = picker();
    let a = p
        .prepare(requester(), object(), Persistence::RememberPerUser, 10, 30)
        .unwrap();
    let c = consent(&a);
    let mut edit = EditProbe::new();
    assert_eq!(
        p.commit_edit(a, c, requester(), editable(), 11, &mut edit),
        Err(Error::Denied)
    );
    assert_eq!(edit.calls, 0);
    assert_eq!(p.pending(), 0);
    let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
    let c = consent(&a);
    let mut read = Probe::new();
    assert_eq!(
        p.commit(a, c, requester(), object(), 11, &mut read),
        Err(Error::Denied)
    );
    assert_eq!(read.calls, 0);
    assert!(read.intent.is_none());
    assert_eq!(p.pending(), 0);
}

#[test]
fn edit_requires_both_current_read_and_write_policy_before_allocating_approval() {
    let mut p = picker();
    assert_eq!(
        p.prepare_edit(
            requester(),
            EditObjectView {
                writable: false,
                ..editable()
            },
            10,
            30
        )
        .unwrap_err(),
        Error::Denied
    );
    assert_eq!(p.pending(), 0);
    let mut view = editable();
    view.object.readable = false;
    assert_eq!(
        p.prepare_edit(requester(), view, 10, 30).unwrap_err(),
        Error::Denied
    );
    assert_eq!(p.pending(), 0);
    let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
    assert_eq!(a.nonce.serial, 1);
}

#[test]
fn every_edit_requester_session_package_incarnation_or_policy_change_consumes_without_handoff() {
    for case in 0..8 {
        let mut p = picker();
        let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
        let c = consent(&a);
        let mut current = requester();
        match case {
            0 => current.alive = false,
            1 => current.user = UserId::new([10; 16]).unwrap(),
            2 => current.session = SessionId::new([10; 16]).unwrap(),
            3 => current.app.app = AppId::new([10; 16]).unwrap(),
            4 => current.app.package = ContentDigest::new([10; 32]).unwrap(),
            5 => {
                current.incarnation =
                    Incarnation::new(BootEpoch::new([10; 16]).unwrap(), 6).unwrap()
            }
            6 => {
                current.incarnation = Incarnation::new(BootEpoch::new([5; 16]).unwrap(), 7).unwrap()
            }
            _ => current.policy_revision = 2,
        }
        let mut h = EditProbe::new();
        assert!(
            p.commit_edit(a, c, current, editable(), 11, &mut h)
                .is_err()
        );
        assert_eq!(h.calls, 0);
        assert_eq!(p.pending(), 0);
    }
}

#[test]
fn changed_edit_object_revision_permissions_and_consent_refuse_before_handoff() {
    for case in 0..10 {
        let mut p = picker();
        let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
        let mut c = consent(&a);
        let mut view = editable();
        let mut now = 11;
        match case {
            0 => view.writable = false,
            1 => view.object.readable = false,
            2 => view.object.permission_revision = 2,
            3 => view.object.object = ObjectId::new(VolumeId::new([7; 16]).unwrap(), 2).unwrap(),
            4 => {
                view.object.revision =
                    Revision::new(1, ContentDigest::new([8; 32]).unwrap()).unwrap()
            }
            5 => {
                view.object.revision =
                    Revision::new(0, ContentDigest::new([9; 32]).unwrap()).unwrap()
            }
            6 => now = 30,
            7 => now = 9,
            8 => c.approver = UserId::new([10; 16]).unwrap(),
            _ => c.displayed_action = [0; 32],
        }
        let mut h = EditProbe::new();
        assert!(p.commit_edit(a, c, requester(), view, now, &mut h).is_err());
        assert_eq!(h.calls, 0);
        assert_eq!(p.pending(), 0);
    }
}

#[test]
fn read_and_edit_share_one_bounded_pending_table_and_invalidation_rules() {
    let mut p = picker();
    let mut last = None;
    for i in 0..MAX_PENDING {
        last = Some(if i % 2 == 0 {
            p.prepare(requester(), object(), Persistence::ThisIncarnation, 10, 30)
                .unwrap()
        } else {
            p.prepare_edit(requester(), editable(), 10, 30).unwrap()
        });
    }
    assert_eq!(p.pending(), MAX_PENDING);
    assert_eq!(
        p.prepare_edit(requester(), editable(), 10, 30).unwrap_err(),
        Error::Capacity
    );
    p.cancel(last.unwrap()).unwrap();
    assert_eq!(p.pending(), MAX_PENDING - 1);
    let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
    let c = consent(&a);
    assert_eq!(p.requester_died(requester().incarnation), MAX_PENDING);
    let mut h = EditProbe::new();
    assert_eq!(
        p.commit_edit(a, c, requester(), editable(), 11, &mut h),
        Err(Error::StaleApproval)
    );
    assert_eq!(h.calls, 0);
}

#[test]
fn refused_or_indeterminate_edit_delivery_consumes_the_approval_without_automatic_retry() {
    for outcome in [Delivery::Refused(7), Delivery::Indeterminate(8)] {
        let mut p = picker();
        let a = p.prepare_edit(requester(), editable(), 10, 30).unwrap();
        let duplicate = duplicate_for_adversary(&a);
        let c = consent(&a);
        let mut h = EditProbe::new();
        h.outcome = outcome;
        let result = p
            .commit_edit(a, c, requester(), editable(), 11, &mut h)
            .unwrap();
        assert!(matches!(
            result,
            Delivery::Refused(7) | Delivery::Indeterminate(8)
        ));
        assert_eq!(h.calls, 1);
        assert_eq!(p.pending(), 0);
        assert_eq!(
            p.commit_edit(duplicate, c, requester(), editable(), 12, &mut h),
            Err(Error::StaleApproval)
        );
        assert_eq!(h.calls, 1);
    }
}
