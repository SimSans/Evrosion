//! Real in-memory Store and signed-content composition, not guest durability.
extern crate std;
use super::*;
use crate::native_plan::state::tests::{
    self as fixture,
    downloaded_sources::{content_transfer, persist_content, selection_tests},
};
use crate::native_sources::{DownloadedSlot, Member, Resolver};
use ev_userspace_contract::{
    app_data::{Request as DataRequest, Response},
    session_note::{Operation, Outcome, Refusal, Request as NoteRequest},
};
use std::{cell::RefCell, rc::Rc};
type ModelState = State<fixture::Link, fixture::Buffer>;
const WHO: Identity = Identity {
    process: 700,
    thread: 710,
};
const SOURCE: Source = Source::Downloaded(DownloadedSlot::B);

fn scenario(
    saved_note: bool,
    test: impl FnOnce(
        &mut ModelState,
        &Resolver<'_, '_, crate::native_sources::tests::Model>,
        &Rc<RefCell<fixture::Media>>,
    ),
) {
    let (mut state, store, [selected], media) = selection_tests::selected_with_media::<1>();
    let mut store = persist_content(
        store
            .reconcile_selection(&state, selected)
            .unwrap()
            .unwrap()
            .begin(store, &state, content_transfer(), 100)
            .unwrap_or_else(|_| panic!()),
    );
    let snapshot = store.take_snapshot().unwrap();
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!());
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let mut images = crate::native_sources::tests::sealed_images(true);
    images.register(0, 100).unwrap();
    images.register(1, 100).unwrap();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let sources = Resolver::from_members(&banks, &images, [Some(member), None]).unwrap();
    state.open(&sources, 500).unwrap();
    if saved_note {
        state.admit_source(&sources, SOURCE, WHO).unwrap();
        let reply = state.note_request(&sources, WHO, request(Operation::Read, 1), None, 500);
        let old = NoteDataEnvelope::decode(&reply.bytes.unwrap()).unwrap();
        let next = old
            .checked_replace(sources.app(), old.counter(), "retained owner work")
            .unwrap();
        assert_eq!(
            state
                .note_request(
                    &sources,
                    WHO,
                    request(Operation::Write, 2),
                    Some(&next.encode()),
                    500
                )
                .response
                .outcome(),
            Outcome::Written
        );
        state.fence();
    }
    test(&mut state, &sources, &media);
}
fn request(operation: Operation, nonce: u32) -> NoteRequest {
    NoteRequest::new(operation, nonce).unwrap()
}
fn admit(state: &mut ModelState, sources: &impl Sources) {
    let reads = state.prepare_health_reads(sources, SOURCE, 500).unwrap();
    state
        .admit_health_subject(sources, SOURCE, WHO, reads)
        .unwrap();
}
#[test]
fn exact_preload_serves_scalar_and_note_without_any_transport_io_or_nonce_advance() {
    scenario(true, |state, sources, media| {
        let before = media.borrow().durable.clone();
        let calls_before = fixture::storage_calls(media);
        admit(state, sources);
        assert!(
            fixture::storage_calls(media) > calls_before,
            "preload must read the real Store"
        );
        assert_eq!(media.borrow().durable, before);
        let calls = fixture::storage_calls(media);
        // A transport failure would fail a fresh read. It remains unconsumed.
        media.borrow_mut().fail_next = true;
        assert_eq!(
            state.data_request(sources, WHO, DataRequest::Read, 500),
            Response::Value(1001)
        );
        let reply = state.note_request(sources, WHO, request(Operation::Read, 1), None, 500);
        assert_eq!(reply.response.outcome(), Outcome::Read);
        assert_eq!(
            NoteDataEnvelope::decode(&reply.bytes.unwrap())
                .unwrap()
                .note(),
            "retained owner work"
        );
        assert_eq!(fixture::storage_calls(media), calls);
        assert!(media.borrow().fail_next);
        assert_eq!(media.borrow().durable, before);
        let replay = state.note_request(sources, WHO, request(Operation::Read, 1), None, 500);
        assert_eq!(replay.response.outcome(), Outcome::Refused(Refusal::Stale));
        let invalidated = state.note_request(sources, WHO, request(Operation::Read, 2), None, 500);
        assert_eq!(
            invalidated.response.outcome(),
            Outcome::Refused(Refusal::Denied)
        );
        assert_eq!(fixture::storage_calls(media), calls);
    });
}
#[test]
fn authenticated_probation_write_busy_consumes_nonce_and_preserves_exact_read_authority() {
    scenario(true, |state, sources, media| {
        admit(state, sources);
        let before = media.borrow().durable.clone();
        let calls = fixture::storage_calls(media);
        media.borrow_mut().fail_next = true;
        let busy = state.note_request(sources, WHO, request(Operation::Write, 1), None, 500);
        assert_eq!(busy.response.outcome(), Outcome::Refused(Refusal::Busy));
        assert!(busy.bytes.is_none());
        assert_eq!(state.session.as_ref().unwrap().note_nonce, 1);
        assert_eq!(
            state.data_request(sources, WHO, DataRequest::Read, 500),
            Response::Value(1001)
        );
        let read = state.note_request(sources, WHO, request(Operation::Read, 2), None, 500);
        assert_eq!(read.response.outcome(), Outcome::Read);
        assert_eq!(
            NoteDataEnvelope::decode(&read.bytes.unwrap())
                .unwrap()
                .note(),
            "retained owner work"
        );
        assert_eq!(fixture::storage_calls(media), calls);
        assert!(media.borrow().fail_next);
        assert_eq!(media.borrow().durable, before);
    });
}
#[test]
fn contention_busy_cannot_restore_a_read_receipt_invalidated_by_a_backend_loan() {
    scenario(true, |state, sources, media| {
        admit(state, sources);
        let owner = state.take_content_backend(false).unwrap();
        let before = media.borrow().durable.clone();
        let calls = fixture::storage_calls(media);
        let busy = state.note_request(sources, WHO, request(Operation::Read, 1), None, 500);
        assert_eq!(busy.response.outcome(), Outcome::Refused(Refusal::Busy));
        state
            .restore_content_backend(owner)
            .unwrap_or_else(|_| panic!());
        let refused = state.note_request(sources, WHO, request(Operation::Read, 2), None, 500);
        assert_eq!(
            refused.response.outcome(),
            Outcome::Refused(Refusal::Denied)
        );
        assert!(refused.bytes.is_none());
        assert_eq!(fixture::storage_calls(media), calls);
        assert_eq!(media.borrow().durable, before);
    });
}
#[test]
fn unformatted_note_stays_an_honest_refusal_without_creation_or_io_during_probation() {
    scenario(false, |state, sources, media| {
        let before = media.borrow().durable.clone();
        admit(state, sources);
        let calls = fixture::storage_calls(media);
        let reply = state.note_request(sources, WHO, request(Operation::Read, 1), None, 500);
        assert_eq!(reply.response.outcome(), Outcome::Refused(Refusal::Stale));
        assert!(reply.bytes.is_none());
        assert_eq!(fixture::storage_calls(media), calls);
        assert_eq!(media.borrow().durable, before);
    });
}
#[test]
fn direct_content_reborrow_loan_fence_and_registry_change_reject_outstanding_receipts() {
    for cause in 0..4 {
        scenario(true, |state, sources, media| {
            let reads = state.prepare_health_reads(sources, SOURCE, 500).unwrap();
            match cause {
                0 => {
                    let _borrow = state.content_backend(false).unwrap();
                }
                1 => {
                    let loan = state.take_content_backend(false).unwrap();
                    state
                        .restore_content_backend(loan)
                        .unwrap_or_else(|_| panic!());
                }
                2 => state.fence(),
                _ => {
                    state
                        .prepare_source(
                            sources,
                            Change::Stage {
                                package: sources.source_digest(Source::Bank(Slot::A)).unwrap(),
                            },
                            500,
                        )
                        .unwrap();
                    state.commit(sources, 500).unwrap();
                }
            }
            let calls = fixture::storage_calls(media);
            assert!(
                state
                    .admit_health_subject(sources, SOURCE, WHO, reads)
                    .is_err()
            );
            assert!(state.session.is_none());
            assert_eq!(fixture::storage_calls(media), calls);
        });
    }
}
#[test]
fn exact_backend_owner_cache_and_current_identity_are_required_and_refusals_fence_reads() {
    scenario(true, |state, sources, media| {
        let reads = state.prepare_health_reads(sources, SOURCE, 500).unwrap();
        let mut other = fixture::state_network(media.clone());
        other.open(sources, 500).unwrap();
        assert!(
            other
                .admit_health_subject(sources, SOURCE, WHO, reads)
                .is_err()
        );
        let reads = state.prepare_health_reads(sources, SOURCE, 500).unwrap();
        let old = state.data.unwrap();
        state.data = Some(
            old.checked_replace(sources.app(), 1, old.counter(), 2026)
                .unwrap(),
        );
        assert!(
            state
                .admit_health_subject(sources, SOURCE, WHO, reads)
                .is_err()
        );
        admit(state, sources); // Refreshes exact durable scalar, never changed by cache tampering.
        let calls = fixture::storage_calls(media);
        assert!(matches!(
            state.data_request(
                sources,
                Identity {
                    process: 701,
                    thread: 710
                },
                DataRequest::Read,
                500
            ),
            Response::Refused(_)
        ));
        assert!(matches!(
            state.data_request(sources, WHO, DataRequest::Read, 500),
            Response::Refused(_)
        ));
        assert_eq!(fixture::storage_calls(media), calls);
        state.fence();
        admit(state, sources);
        let calls = fixture::storage_calls(media);
        assert_eq!(
            state.data_request(sources, WHO, DataRequest::Read, 500),
            Response::Value(1001)
        );
        assert!(matches!(
            state.data_request(sources, WHO, DataRequest::SetValue(2026), 500),
            Response::Refused(_)
        ));
        assert_eq!(
            state
                .note_request(sources, WHO, request(Operation::Read, 1), None, 500)
                .response
                .outcome(),
            Outcome::Refused(Refusal::Denied)
        );
        assert_eq!(fixture::storage_calls(media), calls);
    });
}
#[test]
fn unknown_preload_io_fences_without_writes_or_a_receipt() {
    scenario(true, |state, sources, media| {
        let before = media.borrow().durable.clone();
        media.borrow_mut().fail_next = true;
        assert!(state.prepare_health_reads(sources, SOURCE, 500).is_err());
        assert!(state.recovery_required());
        assert!(state.session.is_none());
        assert_eq!(media.borrow().durable, before);
    });
}

#[test]
fn corrupt_note_never_becomes_empty_and_preload_never_writes_or_formats() {
    scenario(true, |state, sources, media| {
        {
            let mut m = media.borrow_mut();
            m.cache[112..126].fill([0x91; 512]);
            m.durable = m.cache.clone();
        }
        let before = media.borrow().cache.clone();
        let writes = media.borrow().writes.len();
        assert!(state.prepare_health_reads(sources, SOURCE, 500).is_err());
        assert!(state.recovery_required());
        assert!(state.session.is_none());
        assert_eq!(media.borrow().cache, before);
        assert_eq!(media.borrow().writes.len(), writes);
    });
}
