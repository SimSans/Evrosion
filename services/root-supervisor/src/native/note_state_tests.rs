//! Actual in-memory SectorIo/Store publications, not guest/device durability.
extern crate std;
use super::super::tests as fixture;
use super::*;
use ev_userspace_contract::session_note;
use std::{cell::RefCell, rc::Rc, vec::Vec};
const DEADLINE: u64 = 1500;
const WHO: Identity = Identity {
    process: 7,
    thread: 8,
};
type ModelState = State<fixture::Link, fixture::Buffer>;
fn setup(packages: &Packages<'_>) -> (Rc<RefCell<fixture::Media>>, ModelState) {
    let media = fixture::composed_disk();
    {
        let mut m = media.borrow_mut();
        m.cache[112..126].fill([0; 512]);
        m.durable = m.cache.clone();
    }
    let mut state = fixture::state_session(media.clone());
    state.open(packages, DEADLINE).unwrap();
    state.install(packages, DEADLINE).unwrap();
    fixture::transition(&mut state, packages, Change::Activate);
    state.admit(packages, Slot::A, WHO).unwrap();
    (media, state)
}
fn req(operation: Operation, nonce: u32) -> NoteRequest {
    NoteRequest::new(operation, nonce).unwrap()
}
fn read(
    state: &mut ModelState,
    packages: &Packages<'_>,
    who: Identity,
    nonce: u32,
) -> NoteDataEnvelope {
    let result = state.note_request(packages, who, req(Operation::Read, nonce), None, DEADLINE);
    assert_eq!(result.response.outcome(), Outcome::Read);
    assert_eq!(result.response.nonce(), nonce);
    NoteDataEnvelope::decode(&result.bytes.unwrap()).unwrap()
}
fn outside_note(bytes: &[ev_store::Sector]) -> Vec<ev_store::Sector> {
    bytes[..112].iter().chain(&bytes[126..]).copied().collect()
}
#[test]
fn read_blank_write_exact_cas_and_cold_reopen_preserve_every_other_region() {
    let fixture = fixture::Fixture::session_note();
    let packages = fixture.packages();
    let (media, mut state) = setup(&packages);
    let before = outside_note(&media.borrow().cache);
    let old = read(&mut state, &packages, WHO, 1);
    assert_eq!(old.note(), "");
    assert_eq!(old.counter(), 0);
    let next = old
        .checked_replace(packages.app(), 0, "saved through actual Store")
        .unwrap();
    let reply = state.note_request(
        &packages,
        WHO,
        req(Operation::Write, 2),
        Some(&next.encode()),
        DEADLINE,
    );
    assert_eq!(reply.response.outcome(), Outcome::Written);
    assert_eq!(
        session_note::Response::decode(&reply.response.encode(), 0),
        Ok(reply.response)
    );
    assert_eq!(reply.bytes, Some(next.encode()));
    assert_eq!(outside_note(&media.borrow().cache), before);
    assert!(
        media
            .borrow()
            .writes
            .iter()
            .any(|lba| (112..126).contains(lba))
    );
    drop(state);
    fixture::cold(&media);
    let mut cold = fixture::state_session(media.clone());
    cold.open(&packages, DEADLINE).unwrap();
    let identity = Identity {
        process: 9,
        thread: 10,
    };
    cold.admit(&packages, Slot::A, identity).unwrap();
    assert_eq!(read(&mut cold, &packages, identity, 1), next);
    assert_eq!(outside_note(&media.borrow().cache), before);
}
#[test]
fn nonce_replay_stale_cas_wrong_identity_and_fence_never_publish_another_write() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    let (media, mut s) = setup(&p);
    let denied = s.note_request(
        &p,
        Identity {
            process: 99,
            thread: 8,
        },
        req(Operation::Read, 1),
        None,
        DEADLINE,
    );
    assert_eq!(denied.response.outcome(), Outcome::Refused(Refusal::Denied));
    let old = read(&mut s, &p, WHO, 1);
    let next = old.checked_replace(p.app(), 0, "one commit").unwrap();
    let request = req(Operation::Write, 2);
    assert_eq!(
        s.note_request(&p, WHO, request, Some(&next.encode()), DEADLINE)
            .response
            .outcome(),
        Outcome::Written
    );
    media.borrow_mut().writes.clear();
    let before = media.borrow().cache.clone();
    for request in [request, req(Operation::Write, 3)] {
        let reply = s.note_request(&p, WHO, request, Some(&next.encode()), DEADLINE);
        assert_eq!(reply.response.outcome(), Outcome::Refused(Refusal::Stale));
        assert!(reply.bytes.is_none());
    }
    assert_eq!(media.borrow().cache, before);
    assert!(media.borrow().writes.is_empty());
    assert_eq!(read(&mut s, &p, WHO, 4), next);
    s.fence();
    assert_eq!(
        s.note_request(&p, WHO, req(Operation::Read, 5), None, DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(Refusal::Denied)
    );
}
#[test]
fn legacy_profile_and_missing_actual_note_contract_are_denied_before_note_io() {
    for fixture in [
        fixture::Fixture::new(),
        fixture::Fixture::session_without_note(),
    ] {
        let p = fixture.packages();
        let (media, mut s) = setup(&p);
        let before = media.borrow().cache.clone();
        media.borrow_mut().writes.clear();
        assert_eq!(
            s.note_request(&p, WHO, req(Operation::Read, 1), None, DEADLINE)
                .response
                .outcome(),
            Outcome::Refused(Refusal::Denied)
        );
        assert_eq!(media.borrow().cache, before);
        assert!(media.borrow().writes.is_empty());
    }
}
#[test]
fn every_nonblank_sector_partial_namespace_and_read_error_refuse_without_format() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    for local in 0..14 {
        let (media, mut s) = setup(&p);
        {
            let mut m = media.borrow_mut();
            m.cache[112 + local][7] = 1;
            m.durable = m.cache.clone();
            m.writes.clear();
        }
        let before = media.borrow().cache.clone();
        let reply = s.note_request(&p, WHO, req(Operation::Read, 1), None, DEADLINE);
        assert_eq!(
            reply.response.outcome(),
            Outcome::Refused(Refusal::Recovery)
        );
        assert!(reply.bytes.is_none());
        assert!(s.recovery_required());
        assert!(s.session.is_none());
        assert!(media.borrow().writes.is_empty());
        assert_eq!(media.borrow().cache, before);
    }
    let (media, mut s) = setup(&p);
    media.borrow_mut().fail_next = true;
    let before = media.borrow().cache.clone();
    media.borrow_mut().writes.clear();
    assert_eq!(
        s.note_request(&p, WHO, req(Operation::Read, 1), None, DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(Refusal::Recovery)
    );
    assert!(s.recovery_required());
    assert!(media.borrow().writes.is_empty());
    assert_eq!(media.borrow().cache, before);
}
#[test]
fn valid_store_with_foreign_app_or_scalar_v1_body_is_not_reinitialized() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    let bodies = [
        NoteDataEnvelope::initial(ev_zion::AppId::new([99; 16]).unwrap(), "foreign")
            .unwrap()
            .encode(),
        AppDataEnvelope::initial(p.app(), 1, 1001).unwrap().encode(),
    ];
    for body in bodies {
        let (media, mut s) = setup(&p);
        {
            let device = s.backend.device(Region::SessionNote, true);
            Store::format_new(
                device,
                p.note_format_manifest(),
                &body,
                BootPolicy::new(1).unwrap(),
                DEADLINE,
            )
            .map_err(|_| ())
            .unwrap();
        }
        let before = media.borrow().cache.clone();
        media.borrow_mut().writes.clear();
        assert_eq!(
            s.note_request(&p, WHO, req(Operation::Read, 1), None, DEADLINE)
                .response
                .outcome(),
            Outcome::Refused(Refusal::Recovery)
        );
        assert!(s.recovery_required());
        assert_eq!(media.borrow().cache, before);
        assert!(media.borrow().writes.is_empty());
    }
}
#[test]
fn accepted_unknown_writes_fence_live_retry_and_cold_recover_one_original_operation() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    for lost_flush in [false, true] {
        let (media, mut s) = setup(&p);
        let old = read(&mut s, &p, WHO, 1);
        let next = old
            .checked_replace(p.app(), 0, "one uncertain write")
            .unwrap();
        let outside = outside_note(&media.borrow().cache);
        {
            let mut m = media.borrow_mut();
            m.lose_write_reply = !lost_flush;
            m.lose_flush_reply = lost_flush;
            m.writes.clear();
        }
        let request = req(Operation::Write, 2);
        let reply = s.note_request(&p, WHO, request, Some(&next.encode()), DEADLINE);
        assert_eq!(
            reply.response.outcome(),
            Outcome::Refused(Refusal::Recovery)
        );
        assert!(reply.bytes.is_none());
        assert!(s.recovery_required());
        let writes = media.borrow().writes.clone();
        assert_eq!(
            s.note_request(&p, WHO, request, Some(&next.encode()), DEADLINE)
                .response
                .outcome(),
            Outcome::Refused(Refusal::Recovery)
        );
        assert_eq!(media.borrow().writes, writes);
        drop(s);
        fixture::cold(&media);
        let mut cold = fixture::state_session(media.clone());
        cold.open(&p, DEADLINE).unwrap();
        let who = Identity {
            process: 11,
            thread: 12,
        };
        cold.admit(&p, Slot::A, who).unwrap();
        let actual = read(&mut cold, &p, who, 1);
        assert_eq!(actual.counter(), u64::from(lost_flush));
        assert_eq!(
            actual.note(),
            if lost_flush {
                "one uncertain write"
            } else {
                ""
            }
        );
        {
            let device = cold.backend.device(Region::SessionNote, false);
            let store = Store::open(device, DEADLINE).map_err(|_| ()).unwrap();
            assert_eq!(store.next_operation().unwrap().get(), actual.counter() + 1);
        }
        assert_eq!(outside_note(&media.borrow().cache), outside);
    }
}
#[test]
fn same_app_a_b_and_rollback_keep_one_note_namespace_with_fresh_incarnation_nonces() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    let (media, mut s) = setup(&p);
    let initial = read(&mut s, &p, WHO, 1);
    let a = initial
        .checked_replace(p.app(), 0, "owner edits in A")
        .unwrap();
    assert_eq!(
        s.note_request(
            &p,
            WHO,
            req(Operation::Write, 2),
            Some(&a.encode()),
            DEADLINE
        )
        .response
        .outcome(),
        Outcome::Written
    );
    let legacy = media.borrow().cache[80..94].to_vec();
    fixture::transition(
        &mut s,
        &p,
        Change::Stage {
            package: p.digest(Slot::B),
        },
    );
    fixture::transition(&mut s, &p, Change::Activate);
    let b_identity = Identity {
        process: 21,
        thread: 22,
    };
    s.admit(&p, Slot::B, b_identity).unwrap();
    assert_eq!(read(&mut s, &p, b_identity, 1), a);
    let b = a.checked_replace(p.app(), 1, "newer edits in B").unwrap();
    assert_eq!(
        s.note_request(
            &p,
            b_identity,
            req(Operation::Write, 2),
            Some(&b.encode()),
            DEADLINE
        )
        .response
        .outcome(),
        Outcome::Written
    );
    fixture::transition(&mut s, &p, Change::Rollback);
    let a_identity = Identity {
        process: 23,
        thread: 24,
    };
    s.admit(&p, Slot::A, a_identity).unwrap();
    assert_eq!(read(&mut s, &p, a_identity, 1), b);
    assert_eq!(media.borrow().cache[80..94], legacy);
}
#[test]
fn malformed_body_consumes_nonce_but_stale_first_write_cannot_format_blank_region() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    let (media, mut s) = setup(&p);
    let before = media.borrow().cache.clone();
    media.borrow_mut().writes.clear();
    let request = req(Operation::Write, 1);
    assert_eq!(
        s.note_request(&p, WHO, request, Some(&[0; 256]), DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(Refusal::Malformed)
    );
    assert_eq!(
        s.note_request(&p, WHO, request, Some(&[0; 256]), DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(Refusal::Stale)
    );
    let one = NoteDataEnvelope::initial(p.app(), "")
        .unwrap()
        .checked_replace(p.app(), 0, "one")
        .unwrap();
    let two = one.checked_replace(p.app(), 1, "stale assumption").unwrap();
    assert_eq!(
        s.note_request(
            &p,
            WHO,
            req(Operation::Write, 2),
            Some(&two.encode()),
            DEADLINE
        )
        .response
        .outcome(),
        Outcome::Refused(Refusal::Stale)
    );
    assert_eq!(media.borrow().cache, before);
    assert!(media.borrow().writes.is_empty());
    assert!(!s.recovery_required());
}

#[test]
fn historical_creator_is_retained_but_foreign_namespace_context_refuses() {
    let fixture = fixture::Fixture::session_note();
    let p = fixture.packages();
    for foreign in [false, true] {
        let (media, mut s) = setup(&p);
        let body = NoteDataEnvelope::initial(p.app(), "existing data")
            .unwrap()
            .encode();
        let mut creation = p.note_format_manifest();
        creation.supervisor_image = [0x5a; 32];
        if foreign {
            creation.cohort[0] ^= 1;
        }
        {
            let device = s.backend.device(Region::SessionNote, true);
            Store::format_new(
                device,
                creation,
                &body,
                BootPolicy::new(1).unwrap(),
                DEADLINE,
            )
            .map_err(|_| ())
            .unwrap();
        }
        let before = media.borrow().cache.clone();
        media.borrow_mut().writes.clear();
        let reply = s.note_request(&p, WHO, req(Operation::Read, 1), None, DEADLINE);
        if foreign {
            assert_eq!(
                reply.response.outcome(),
                Outcome::Refused(Refusal::Recovery)
            );
            assert!(s.recovery_required());
        } else {
            assert_eq!(reply.response.outcome(), Outcome::Read);
            assert_eq!(reply.bytes, Some(body));
        }
        assert_eq!(media.borrow().cache, before);
        assert!(media.borrow().writes.is_empty());
    }
}

#[cfg(feature = "native-network")]
#[test]
fn owned_content_busy_consumes_only_authenticated_note_nonce_without_io() {
    let fixture = fixture::Fixture::session_note();
    let packages = fixture.packages();
    let (media, mut state) = setup(&packages);
    let old = read(&mut state, &packages, WHO, 1);
    let owner = state.take_content_backend(true).unwrap();
    media.borrow_mut().fail_next = true;
    assert_eq!(
        state.data_request(&packages, WHO, DataRequest::Read, DEADLINE),
        Response::Refused(ev_userspace_contract::app_data::Refusal::Denied)
    );
    let reply = state.note_request(&packages, WHO, req(Operation::Read, 2), None, DEADLINE);
    assert_eq!(
        reply.response.outcome(),
        Outcome::Refused(session_note::Refusal::Busy)
    );
    assert!(reply.bytes.is_none());
    let wrong = Identity {
        process: WHO.process + 99,
        ..WHO
    };
    assert_eq!(
        state
            .note_request(&packages, wrong, req(Operation::Read, 3), None, DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(session_note::Refusal::Denied)
    );
    assert_eq!(
        state
            .note_request(&packages, WHO, req(Operation::Read, 2), None, DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(session_note::Refusal::Stale)
    );
    assert_eq!(state.open(&packages, DEADLINE), Err(Error::State));
    assert_eq!(
        state.system_readonly_snapshot(DEADLINE).err(),
        Some(Error::State)
    );
    assert!(media.borrow().fail_next); // No operation reached the actual wire.
    media.borrow_mut().fail_next = false;
    assert!(state.restore_content_backend(owner).is_ok());
    assert_eq!(read(&mut state, &packages, WHO, 3), old); // New authenticated request after Busy.
    media.borrow_mut().fail_next = true;
    let refused = state.note_busy(&packages, WHO, req(Operation::Read, 4));
    assert_eq!(
        refused.response.outcome(),
        Outcome::Refused(session_note::Refusal::Busy)
    );
    assert!(refused.bytes.is_none());
    assert!(media.borrow().fail_next);
    assert_eq!(
        state
            .note_request(&packages, WHO, req(Operation::Read, 4), None, DEADLINE)
            .response
            .outcome(),
        Outcome::Refused(session_note::Refusal::Stale)
    );
    assert!(media.borrow().fail_next);
    media.borrow_mut().fail_next = false;
    assert_eq!(read(&mut state, &packages, WHO, 5), old);
    assert_eq!(
        state.data_request(&packages, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
}
