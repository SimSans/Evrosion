//! Real in-memory Store and authenticated ordinary Note operations; no guest IO.
extern crate std;
use super::*;
use crate::native_plan::state::tests as fixture;
use ev_app_registry::note_data::NoteDataEnvelope;
use ev_userspace_contract::session_note::{Operation, Outcome, Request as NoteRequest};
use std::{cell::RefCell, rc::Rc};
type Model = State<fixture::Link, fixture::Buffer>;
const CUT: u64 = 1500;
const WHO: Identity = Identity {
    process: 7,
    thread: 8,
};
fn request(op: Operation, nonce: u32) -> NoteRequest {
    NoteRequest::new(op, nonce).unwrap()
}
fn blank() -> (Rc<RefCell<fixture::Media>>, Model) {
    let media = fixture::composed_disk();
    {
        let mut m = media.borrow_mut();
        m.cache[112..126].fill([0; 512]);
        m.durable = m.cache.clone();
    }
    let state = fixture::state_session(media.clone());
    (media, state)
}
fn installed(p: &Packages<'_>) -> (Rc<RefCell<fixture::Media>>, Model) {
    let (media, mut state) = blank();
    state.open(p, CUT).unwrap();
    state.install(p, CUT).unwrap();
    fixture::transition(&mut state, p, Change::Activate);
    state.admit(p, Slot::A, WHO).unwrap();
    (media, state)
}
fn normal_read(state: &mut Model, p: &Packages<'_>) -> NoteDataEnvelope {
    let reply = state.note_request(p, WHO, request(Operation::Read, 1), None, CUT);
    assert_eq!(reply.response.outcome(), Outcome::Read);
    NoteDataEnvelope::decode(&reply.bytes.unwrap()).unwrap()
}
#[test]
fn unknown_and_verified_blank_fetch_guards_have_zero_io_even_after_a_returned_loan() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    let (media, mut state) = blank();
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    assert!(!state.installed_for_fetch());
    assert_eq!(fixture::storage_calls(&media), 0);
    state.open(&p, CUT).unwrap();
    let before = media.borrow().cache.clone();
    let calls = fixture::storage_calls(&media);
    media.borrow_mut().fail_next = true;
    assert!(!state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::OpenHello);
    let loan = state.take_content_backend(false).unwrap();
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    state
        .restore_content_backend(loan)
        .unwrap_or_else(|_| panic!());
    assert!(!state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::OpenHello);
    assert_eq!(fixture::storage_calls(&media), calls);
    assert!(media.borrow().fail_next);
    assert_eq!(media.borrow().cache, before);
}
#[test]
fn fresh_verified_blank_and_missing_note_never_mutate_system_or_format_a_namespace() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    for has_install in [false, true] {
        let (media, mut state) = if has_install {
            installed(&p)
        } else {
            let (media, mut state) = blank();
            state.open(&p, CUT).unwrap();
            (media, state)
        };
        let before = media.borrow().cache.clone();
        let durable = media.borrow().durable.clone();
        let writes = media.borrow().writes.clone();
        let mutations = state.mutations();
        let calls = fixture::storage_calls(&media);
        assert_eq!(state.check_startup_setup(&p, CUT), Ok(SetupHint::OpenHello));
        assert_ne!(state.startup_setup_hint(), SetupHint::Ready);
        assert!(fixture::storage_calls(&media) > calls);
        assert_eq!(media.borrow().cache, before);
        assert_eq!(media.borrow().durable, durable);
        assert_eq!(media.borrow().writes, writes);
        assert_eq!(state.mutations(), mutations);
        assert!(!state.recovery_required());
        if has_install {
            assert_eq!(state.session.as_ref().unwrap().identity, WHO);
        }
    }
}
#[test]
fn actual_ordinary_note_read_and_write_cache_ready_and_fresh_check_preserves_live_a() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    let (media, mut state) = installed(&p);
    assert!(state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    let old = normal_read(&mut state, &p);
    assert_eq!(state.startup_setup_hint(), SetupHint::Ready);
    let next = old
        .checked_replace(p.app(), old.counter(), "owner saved work")
        .unwrap();
    assert_eq!(
        state
            .note_request(
                &p,
                WHO,
                request(Operation::Write, 2),
                Some(&next.encode()),
                CUT
            )
            .response
            .outcome(),
        Outcome::Written
    );
    assert_eq!(state.startup_setup_hint(), SetupHint::Ready);
    let before = media.borrow().cache.clone();
    let mutations = state.mutations();
    let calls = fixture::storage_calls(&media);
    assert_eq!(state.check_startup_setup(&p, CUT), Ok(SetupHint::Ready));
    assert!(fixture::storage_calls(&media) > calls);
    assert_eq!(state.session.as_ref().unwrap().identity, WHO);
    assert_eq!(state.session.as_ref().unwrap().note_nonce, 2);
    assert_eq!(media.borrow().cache, before);
    assert_eq!(state.mutations(), mutations);
    let calls = fixture::storage_calls(&media);
    media.borrow_mut().fail_next = true;
    assert!(state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::Ready);
    assert_eq!(fixture::storage_calls(&media), calls);
    assert!(media.borrow().fail_next);
}
#[test]
fn nonblank_missing_and_corrupt_regions_are_fenced_without_format_or_replay() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    for region in [64..78, 80..94, 112..126] {
        let (media, mut state) = installed(&p);
        {
            let mut m = media.borrow_mut();
            m.cache[region].fill([0x7d; 512]);
            m.durable = m.cache.clone();
        }
        let before = media.borrow().cache.clone();
        let mutations = state.mutations();
        let writes = media.borrow().writes.clone();
        assert!(state.check_startup_setup(&p, CUT).is_err());
        assert!(state.recovery_required());
        assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
        assert!(!state.installed_for_fetch());
        assert_eq!(media.borrow().cache, before);
        assert_eq!(media.borrow().writes, writes);
        assert_eq!(state.mutations(), mutations);
    }
    let (media, mut state) = installed(&p);
    media.borrow_mut().cache[125][511] = 1;
    let before = media.borrow().cache.clone();
    let mutations = state.mutations();
    assert!(state.check_startup_setup(&p, CUT).is_err());
    assert_eq!(media.borrow().cache, before);
    assert_eq!(state.mutations(), mutations);
}
#[test]
fn true_accepted_unknown_note_intent_cannot_be_replayed_by_prerequisite_inspection() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    let (media, mut state) = installed(&p);
    let old = normal_read(&mut state, &p);
    let next = old
        .checked_replace(p.app(), 0, "uncertain owner operation")
        .unwrap();
    media.borrow_mut().lose_flush_reply = true;
    assert!(matches!(
        state
            .note_request(
                &p,
                WHO,
                request(Operation::Write, 2),
                Some(&next.encode()),
                CUT
            )
            .response
            .outcome(),
        Outcome::Refused(_)
    ));
    assert!(state.recovery_required());
    drop(state);
    fixture::cold(&media);
    let mut state = fixture::state_session(media.clone());
    state.open(&p, CUT).unwrap();
    let before = media.borrow().cache.clone();
    let durable = media.borrow().durable.clone();
    let writes = media.borrow().writes.clone();
    let mutations = state.mutations();
    assert!(state.check_startup_setup(&p, CUT).is_err());
    assert!(state.recovery_required());
    assert_eq!(media.borrow().cache, before);
    assert_eq!(media.borrow().durable, durable);
    assert_eq!(media.borrow().writes, writes);
    assert_eq!(state.mutations(), mutations);
}
#[test]
fn content_loan_head_change_and_fence_invalidate_ready_and_tombstone_cannot_fetch() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    let (_media, mut state) = installed(&p);
    normal_read(&mut state, &p);
    let owner = state.take_content_backend(false).unwrap();
    assert!(!state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    state
        .restore_content_backend(owner)
        .unwrap_or_else(|_| panic!());
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    assert_eq!(state.check_startup_setup(&p, CUT), Ok(SetupHint::Ready));
    state.fence();
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    state.prepare(&p, Change::Remove, CUT).unwrap();
    state.commit(&p, CUT).unwrap();
    assert!(!state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
}
#[test]
fn missing_note_contract_never_becomes_ready_from_installed_scalar() {
    let f = fixture::Fixture::session_without_note();
    let p = f.packages();
    let (media, mut state) = installed(&p);
    let before = media.borrow().cache.clone();
    assert_eq!(state.check_startup_setup(&p, CUT), Err(Error::Package));
    assert!(state.recovery_required());
    assert_eq!(media.borrow().cache, before);
}

#[test]
fn actual_downloaded_probation_refuses_fresh_inspection_without_io_or_losing_retained_reads() {
    use crate::native_sources::{DownloadedSlot, Member, Resolver};
    use ev_userspace_contract::app_data::{Request as DataRequest, Response};
    use fixture::downloaded_sources::{content_transfer, persist_content, selection_tests};
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
    let source = Source::Downloaded(DownloadedSlot::B);
    state.open(&sources, 500).unwrap();
    state.admit_source(&sources, source, WHO).unwrap();
    assert_eq!(
        state
            .note_request(&sources, WHO, request(Operation::Read, 1), None, 500)
            .response
            .outcome(),
        Outcome::Read
    );
    state.fence();
    let reads = state.prepare_health_reads(&sources, source, 500).unwrap();
    state
        .admit_health_subject(&sources, source, WHO, reads)
        .unwrap();
    let calls = fixture::storage_calls(&media);
    let before = media.borrow().durable.clone();
    media.borrow_mut().fail_next = true;
    assert_eq!(state.check_startup_setup(&sources, 500), Err(Error::State));
    let selection = StartupSelection::new(
        state.record().unwrap().revision(),
        sources.source_digest(source).unwrap(),
    );
    assert_eq!(
        state.prepare_startup_setup(&sources, selection, 500),
        Err(Error::State)
    );
    assert_eq!(
        state.prepare_fetch_setup(sources.banks(), 500),
        Err(Error::State)
    );
    assert!(!state.installed_for_fetch());
    assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
    assert_eq!(
        state.data_request(&sources, WHO, DataRequest::Read, 500),
        Response::Value(1001)
    );
    assert_eq!(
        state
            .note_request(&sources, WHO, request(Operation::Read, 1), None, 500)
            .response
            .outcome(),
        Outcome::Read
    );
    assert_eq!(fixture::storage_calls(&media), calls);
    assert!(media.borrow().fail_next);
    assert_eq!(media.borrow().durable, before);
    assert!(!state.recovery_required());
}

#[test]
fn cached_blank_hint_cannot_authorize_after_nonblank_tail_appears_in_either_full_region() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    for tail in [77, 93] {
        let (media, mut state) = blank();
        state.open(&p, CUT).unwrap();
        media.borrow_mut().cache[tail][511] = 1;
        // Even a still-cached private historical blank observation is only UI.
        assert_eq!(state.startup_setup_hint(), SetupHint::OpenHello);
        let before = media.borrow().cache.clone();
        let writes = media.borrow().writes.clone();
        assert!(state.check_startup_setup(&p, CUT).is_err());
        assert!(state.recovery_required());
        assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
        assert_eq!(media.borrow().cache, before);
        assert_eq!(media.borrow().writes, writes);
    }
}
#[test]
fn cached_missing_foreign_or_wrong_epoch_scalar_refuses_fetch_without_io() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    for kind in 0..3 {
        let (media, mut state) = installed(&p);
        state.data = match kind {
            0 => None,
            1 => Some(
                AppDataEnvelope::initial(ev_zion::AppId::new([99; 16]).unwrap(), 1, 1001).unwrap(),
            ),
            _ => Some(AppDataEnvelope::initial(p.app(), 2, 1001).unwrap()),
        };
        let calls = fixture::storage_calls(&media);
        media.borrow_mut().fail_next = true;
        assert!(!state.installed_for_fetch());
        assert_eq!(state.startup_setup_hint(), SetupHint::Unknown);
        assert_eq!(fixture::storage_calls(&media), calls);
        assert!(media.borrow().fail_next);
    }
}

#[test]
fn fresh_valid_record_with_different_full_head_refuses_stale_cache_without_writes() {
    let f = fixture::Fixture::session_note();
    let p = f.packages();
    let (media, mut state) = installed(&p);
    normal_read(&mut state, &p);
    let stale = Record::decode(&state.record.as_ref().unwrap().encode()).unwrap();
    fixture::transition(
        &mut state,
        &p,
        Change::Stage {
            package: p.digest(Slot::B),
        },
    );
    assert_ne!(state.record.as_ref(), Some(&stale));
    // Model a stale in-memory observation; the actual Store head is a genuine
    // valid publication, not malformed bytes or a caller's claimed scalar.
    state.record = Some(stale);
    let before = media.borrow().cache.clone();
    let durable = media.borrow().durable.clone();
    let writes = media.borrow().writes.clone();
    let mutations = state.mutations();
    assert_eq!(state.check_startup_setup(&p, CUT), Err(Error::State));
    assert!(state.recovery_required());
    assert_eq!(media.borrow().cache, before);
    assert_eq!(media.borrow().durable, durable);
    assert_eq!(media.borrow().writes, writes);
    assert_eq!(state.mutations(), mutations);
}
