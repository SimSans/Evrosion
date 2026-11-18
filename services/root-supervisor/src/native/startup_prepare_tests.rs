//! Explicit protected owner preparation models over real signed Sources/Store.
extern crate std;
use super::*;
use crate::native_plan::state::tests::{
    self as fixture,
    downloaded_sources::{content_transfer, persist_content, selection_tests},
};
use crate::native_sources::{DownloadedSlot, Member, Resolver};
use ev_app_registry::note_data::NoteDataEnvelope;
use ev_userspace_contract::session_note::{Operation, Outcome, Request as NoteRequest};
use std::{cell::RefCell, rc::Rc, vec::Vec};
type Model = State<fixture::Link, fixture::Buffer>;
const CUT: u64 = 500;
const WHO: Identity = Identity {
    process: 700,
    thread: 710,
};
fn req(op: Operation, n: u32) -> NoteRequest {
    NoteRequest::new(op, n).unwrap()
}
fn outside_note(bytes: &[ev_store::Sector]) -> Vec<ev_store::Sector> {
    bytes[..112].iter().chain(&bytes[126..]).copied().collect()
}
fn scenario(
    test: impl FnOnce(
        &mut Model,
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
    state.open(&sources, CUT).unwrap();
    // The candidate remains actual signed downloaded B, while ordinary bank A
    // is the real Registry head. Requiring Registry.active==B would be wrong.
    state
        .prepare_source(
            &sources,
            Change::Replace {
                package: banks.digest(Slot::A),
            },
            CUT,
        )
        .unwrap();
    state.commit(&sources, CUT).unwrap();
    state
        .admit_source(&sources, Source::Bank(Slot::A), WHO)
        .unwrap();
    test(&mut state, &sources, &media);
}
fn intent(state: &Model, sources: &impl Sources) -> StartupSelection {
    StartupSelection::new(
        state.record().unwrap().revision(),
        sources
            .source_digest(Source::Downloaded(DownloadedSlot::B))
            .unwrap(),
    )
}
fn actual_note(state: &mut Model, sources: &impl Sources) -> NoteDataEnvelope {
    let device = state.backend.device(Region::SessionNote, false);
    let mut store = Store::open(device, CUT).map_err(|_| ()).unwrap();
    note_state::validated_note(&mut store, sources, CUT)
        .map_err(|_| ())
        .unwrap()
}
#[test]
fn protected_system_intent_creates_only_blank_note_for_actual_candidate_b_while_a_stays_live() {
    scenario(|state, sources, media| {
        let before = outside_note(&media.borrow().cache);
        let durable = outside_note(&media.borrow().durable);
        let head = state.record().unwrap().encode();
        let scalar = state.data().unwrap();
        let selection = intent(state, sources);
        assert_eq!(
            state.active_source(sources),
            Ok(Some(Source::Bank(Slot::A)))
        );
        assert_eq!(state.session.as_ref().unwrap().note_nonce, 0);
        assert_eq!(
            state.prepare_startup_setup(sources, selection, CUT),
            Ok(SetupHint::Ready)
        );
        assert_eq!(outside_note(&media.borrow().cache), before);
        assert_eq!(outside_note(&media.borrow().durable), durable);
        assert!(
            media
                .borrow()
                .writes
                .iter()
                .rev()
                .take_while(|lba| **lba >= 112 && **lba < 126)
                .count()
                > 0
        );
        assert_eq!(state.record().unwrap().encode(), head);
        assert_eq!(state.data(), Some(scalar));
        let session = state.session.as_ref().unwrap();
        assert_eq!(session.identity, WHO);
        assert_eq!(session.note_nonce, 0);
        assert!(!session.read && !session.set && !session.health_probation);
        let note = actual_note(state, sources);
        assert_eq!(note, NoteDataEnvelope::initial(sources.app(), "").unwrap());
        assert_eq!(
            state.check_startup_setup(sources, CUT),
            Ok(SetupHint::Ready)
        );
    });
}
#[test]
fn existing_saved_note_is_freshly_validated_and_never_replaced_by_preparation() {
    scenario(|state, sources, media| {
        let read = state.note_request(sources, WHO, req(Operation::Read, 1), None, CUT);
        let old = NoteDataEnvelope::decode(&read.bytes.unwrap()).unwrap();
        let saved = old.checked_replace(sources.app(), 0, "M6 keep42").unwrap();
        assert_eq!(
            state
                .note_request(
                    sources,
                    WHO,
                    req(Operation::Write, 2),
                    Some(&saved.encode()),
                    CUT
                )
                .response
                .outcome(),
            Outcome::Written
        );
        let before = media.borrow().cache.clone();
        let durable = media.borrow().durable.clone();
        let mutations = state.mutations();
        let selection = intent(state, sources);
        let calls = fixture::storage_calls(media);
        assert_eq!(
            state.prepare_startup_setup(sources, selection, CUT),
            Ok(SetupHint::Ready)
        );
        assert!(fixture::storage_calls(media) > calls);
        assert_eq!(state.mutations(), mutations);
        assert_eq!(media.borrow().cache, before);
        assert_eq!(media.borrow().durable, durable);
        assert_eq!(state.session.as_ref().unwrap().note_nonce, 2);
        assert_eq!(actual_note(state, sources), saved);
    });
}
#[test]
fn stale_revision_foreign_or_bank_candidate_refuses_before_io_without_consuming_live_a() {
    scenario(|state, sources, media| {
        let revision = state.record().unwrap().revision();
        let candidate = sources
            .source_digest(Source::Downloaded(DownloadedSlot::B))
            .unwrap();
        for (revision, digest) in [
            (revision + 1, candidate),
            (0, candidate),
            (revision, [0; 32]),
            (revision, [99; 32]),
            (revision, sources.banks().digest(Slot::A)),
        ] {
            let before = media.borrow().cache.clone();
            let calls = fixture::storage_calls(media);
            media.borrow_mut().fail_next = true;
            assert!(
                state
                    .prepare_startup_setup(sources, StartupSelection::new(revision, digest), CUT)
                    .is_err()
            );
            assert_eq!(fixture::storage_calls(media), calls);
            assert!(media.borrow().fail_next);
            media.borrow_mut().fail_next = false;
            assert_eq!(media.borrow().cache, before);
            assert!(!state.recovery_required());
            assert_eq!(state.session.as_ref().unwrap().identity, WHO);
        }
    });
}
#[test]
fn full_region_nonblank_tail_is_preserved_and_cannot_become_an_empty_note() {
    scenario(|state, sources, media| {
        media.borrow_mut().cache[125][511] = 1;
        let before = media.borrow().cache.clone();
        let writes = media.borrow().writes.clone();
        let selection = intent(state, sources);
        assert!(
            state
                .prepare_startup_setup(sources, selection, CUT)
                .is_err()
        );
        assert!(state.recovery_required());
        assert_eq!(media.borrow().cache, before);
        assert_eq!(media.borrow().writes, writes);
    });
}
#[test]
fn unknown_creation_write_or_flush_completion_fences_same_owner_without_retry() {
    for lose_flush in [false, true] {
        scenario(|state, sources, media| {
            {
                let mut m = media.borrow_mut();
                m.lose_flush_reply = lose_flush;
                m.lose_write_reply = !lose_flush;
            }
            let before = outside_note(&media.borrow().cache);
            let selection = intent(state, sources);
            assert!(
                state
                    .prepare_startup_setup(sources, selection, CUT)
                    .is_err()
            );
            assert!(state.recovery_required());
            assert_eq!(outside_note(&media.borrow().cache), before);
            let partial = media.borrow().cache.clone();
            let calls = fixture::storage_calls(media);
            let selection = intent(state, sources);
            assert!(
                state
                    .prepare_startup_setup(sources, selection, CUT)
                    .is_err()
            );
            assert_eq!(fixture::storage_calls(media), calls);
            assert_eq!(media.borrow().cache, partial);
        });
    }
}
#[test]
fn explicit_fetch_initializes_only_private_verified_blank_baseline_and_then_is_noop() {
    let f = fixture::Fixture::session_note();
    let packages = f.packages();
    let media = fixture::composed_disk();
    let mut state = fixture::state_session(media.clone());
    state.open(&packages, 1500).unwrap();
    let note_before = media.borrow().cache[112..126].to_vec();
    let system_before = media.borrow().cache[16..30].to_vec();
    state.prepare_fetch_setup(&packages, 1500).unwrap();
    assert!(state.installed_for_fetch());
    assert_eq!(state.data().unwrap().value(), 1001);
    assert_eq!(state.data().unwrap().counter(), 0);
    assert_eq!(
        state.record().unwrap().staged().unwrap().digest(),
        packages.digest(Slot::A)
    );
    assert!(state.session.is_none());
    assert_eq!(media.borrow().cache[112..126], note_before);
    assert_eq!(media.borrow().cache[16..30], system_before);
    let calls = fixture::storage_calls(&media);
    media.borrow_mut().fail_next = true;
    state.prepare_fetch_setup(&packages, 1500).unwrap();
    assert_eq!(fixture::storage_calls(&media), calls);
    assert!(media.borrow().fail_next);
}
#[test]
fn unknown_or_removed_registry_is_not_private_blank_install_credit() {
    let f = fixture::Fixture::session_note();
    let packages = f.packages();
    for removed in [false, true] {
        let media = fixture::composed_disk();
        let mut state = fixture::state_session(media.clone());
        if removed {
            state.open(&packages, 1500).unwrap();
            state.install(&packages, 1500).unwrap();
            fixture::transition(&mut state, &packages, Change::Remove);
        }
        let before = media.borrow().cache.clone();
        let calls = fixture::storage_calls(&media);
        media.borrow_mut().fail_next = true;
        assert_eq!(
            state.prepare_fetch_setup(&packages, 1500),
            Err(Error::State)
        );
        assert_eq!(fixture::storage_calls(&media), calls);
        assert!(media.borrow().fail_next);
        assert_eq!(media.borrow().cache, before);
    }
}

#[test]
fn actual_note_creation_invalidates_a_pre_start_receipt_minted_before_the_namespace_existed() {
    scenario(|state, sources, _media| {
        state.fence();
        let source = Source::Downloaded(DownloadedSlot::B);
        state
            .prepare_source(
                sources,
                Change::Replace {
                    package: sources.source_digest(source).unwrap(),
                },
                CUT,
            )
            .unwrap();
        state.commit(sources, CUT).unwrap();
        let reads = state.prepare_health_reads(sources, source, CUT).unwrap();
        let selection = intent(state, sources);
        assert_eq!(
            state.prepare_startup_setup(sources, selection, CUT),
            Ok(SetupHint::Ready)
        );
        assert_eq!(
            state.admit_health_subject(sources, source, WHO, reads),
            Err(Error::State)
        );
        assert!(state.session.is_none());
    });
}
