//! Actual signed Store +Registry +same-backend selection composition. Only the
//! transport/media/qualified clock are models; no hand-built trusted Snapshot.
use super::*;
use crate::native_acquisition as acq;
use crate::native_plan::state::RegistrySelection;
use ev_content_store::{Arena, Provisioner};

const PACKAGE: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/hello.zion");
const TARGETS: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/targets.bin");
const SNAPSHOT: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/snapshot.bin");
const TIMESTAMP: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/timestamp.bin");

pub(crate) fn inspect(owner: ActualOwner) -> acq::Store<ActualOwner> {
    let t = content_transfer();
    let arena = Arena::open(
        owner,
        crate::native_update::creation_manifest(),
        t.metadata(100).unwrap(),
    )
    .unwrap_or_else(|_| panic!("same actual arena"));
    let mut cold = acq::Store::from_arena(arena)
        .begin_cold(t, 100)
        .unwrap_or_else(|_| panic!("actual cold authorization"));
    let mut b = acq::Buffers::empty();
    for _ in 0..2048 {
        if cold
            .step(&mut b, 100)
            .unwrap_or_else(|_| panic!("bounded cold"))
        {
            return cold
                .finish()
                .unwrap_or_else(|_| panic!("authenticated snapshot"));
        }
    }
    panic!("cold budget")
}

// Mint multiple move-only receipts while the same genuine selection and the
// next loan are current, so refusal cases never need a test receipt factory.
type SelectedWithMedia<const N: usize> = (
    State<Link, Buffer>,
    acq::Store<ActualOwner>,
    [RegistrySelection; N],
    std::rc::Rc<std::cell::RefCell<Media>>,
);
pub(crate) fn selected_with_media<const N: usize>() -> SelectedWithMedia<N> {
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let media = composed_disk();
    {
        let mut m = media.borrow_mut();
        m.cache.resize(8192, [0x9b; 512]);
        m.cache[112..126].fill([0; 512]);
        m.cache[128..142].fill([0; 512]);
        m.cache[256..].fill([0; 512]);
        m.durable = m.cache.clone();
    }
    let mut state = state_network(media.clone());
    // Genuine blank Registry/bank state cannot mint a downloaded selection.
    state.open(&banks, DEADLINE).unwrap();
    assert!(state.registry_selection(&banks).unwrap().is_none());
    let t = content_transfer();
    let mut p = Provisioner::new(
        state.take_content_backend(true).unwrap(),
        crate::native_update::creation_manifest(),
        t,
    )
    .unwrap_or_else(|_| panic!());
    while p.remaining() != 0 {
        p.scan(t.child(100, 1024).unwrap()).unwrap();
    }
    let arena = p
        .finish(t.metadata(100).unwrap())
        .unwrap_or_else(|_| panic!());
    let root = store_object(acq::Store::from_arena(arena), acq::ROM_ROOT);
    let mut store = persist_content(
        root.store
            .provision(root.object, t, 100)
            .unwrap_or_else(|_| panic!()),
    );
    let mut objects = Vec::new();
    for bytes in [TARGETS, SNAPSHOT, TIMESTAMP, PACKAGE] {
        let stored = store_object(store, bytes);
        objects.push(stored.object);
        store = stored.store;
    }
    let env = ev_release_trust::signature::Envelope::parse(TARGETS).unwrap();
    let author = ev_release_trust::metadata::Targets::parse(&env)
        .unwrap()
        .common()
        .not_before;
    let decision = store
        .authorize(
            acq::Remote {
                current_root: acq::ROM_ROOT,
                root_updates: &[],
                metadata: core::array::from_fn(|i| acq::Material {
                    object: objects[i],
                    bytes: [TARGETS, SNAPSHOT, TIMESTAMP][i],
                }),
                candidate: acq::Material {
                    object: objects[3],
                    bytes: PACKAGE,
                },
            },
            &mut ModelClock { author, calls: 0 },
        )
        .unwrap();
    let mut store = persist_content(decision.begin(store, t, 100).unwrap_or_else(|_| panic!()));
    let trusted = store.take_snapshot().unwrap();
    assert!(
        state
            .restore_content_backend(store.into_arena().into_backend())
            .is_ok()
    );
    let content = trusted.candidate().unwrap();
    let images = crate::native_sources::tests::sealed_packages(&[PACKAGE]);
    let view = View::new(
        &banks,
        &images,
        &trusted,
        [
            Some(Downloaded::from_images(&images, 0, &trusted, content).unwrap()),
            None,
        ],
    )
    .unwrap();
    state.open(&view, DEADLINE).unwrap();
    state.install(&banks, DEADLINE).unwrap();
    transition(&mut state, &banks, Change::Activate);
    state
        .metadata(
            &view,
            Change::Stage {
                package: content.package,
            },
            DEADLINE,
        )
        .unwrap();
    assert!(
        state.registry_selection(&view).unwrap().is_none(),
        "staging is not selection"
    );
    state.fence();
    state
        .prepare_source(&view, Change::Activate, DEADLINE)
        .unwrap();
    assert!(
        state.registry_selection(&view).is_err(),
        "unpublished intent cannot mint"
    );
    state.commit(&view, DEADLINE).unwrap();
    let receipts = core::array::from_fn(|_| state.registry_selection(&view).unwrap().unwrap());
    let store = inspect(state.take_content_backend(true).unwrap());
    (state, store, receipts, media)
}

#[test]
fn actual_selected_b_commits_active_only_and_cold_reopens_without_time() {
    let (state, store, [selected]) = selected::<1>();
    let before = store.snapshot().unwrap();
    let (revision, replay, candidate, kg) = (
        before.revision(),
        *before.replay(),
        before.candidate(),
        before.known_good(),
    );
    assert!(before.active().is_none());
    let decision = store
        .reconcile_selection(&state, selected)
        .unwrap()
        .unwrap();
    let store = persist_content(
        decision
            .begin(store, &state, content_transfer(), 100)
            .unwrap_or_else(|_| panic!()),
    );
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.revision(), revision + 1);
    assert_eq!(*snapshot.replay(), replay);
    assert_eq!(snapshot.candidate(), candidate);
    assert_eq!(snapshot.active(), candidate);
    assert_eq!(snapshot.known_good(), kg);
    let store = inspect(store.into_arena().into_backend());
    assert_eq!(store.snapshot().unwrap().active(), candidate);
    assert_eq!(*store.snapshot().unwrap().replay(), replay);
}

#[test]
fn receipt_requires_same_actual_state_owner_current_record_and_exact_loan() {
    let (mut state, store, [foreign, other_owner, stale, old_loan, missing]) = selected::<5>();
    let (other, other_store, _) = selected::<0>();
    assert!(store.reconcile_selection(&other, foreign).is_err());
    assert!(
        other_store
            .reconcile_selection(&state, other_owner)
            .is_err()
    );
    let record = state.record.take().unwrap();
    assert!(store.reconcile_selection(&state, missing).is_err());
    // TEST-only local record substitution simulates a stale receipt; normal
    // State mutation methods refuse while the actual backend is away.
    state.record = Some(
        record
            .data_migrated(record.revision(), record.data_epoch())
            .unwrap(),
    );
    assert!(store.reconcile_selection(&state, stale).is_err());
    state.record = Some(record);
    assert!(
        state
            .restore_content_backend(store.into_arena().into_backend())
            .is_ok()
    );
    let store = inspect(state.take_content_backend(true).unwrap());
    assert!(
        store.reconcile_selection(&state, old_loan).is_err(),
        "same owner, later loan"
    );
}

#[test]
fn already_retained_active_is_a_checked_noop_and_recovery_fence_refuses() {
    let (mut state, store, [first, noop, fenced]) = selected::<3>();
    let decision = store.reconcile_selection(&state, first).unwrap().unwrap();
    let store = persist_content(
        decision
            .begin(store, &state, content_transfer(), 100)
            .unwrap_or_else(|_| panic!()),
    );
    let before = store.authorization_binding();
    assert!(store.reconcile_selection(&state, noop).unwrap().is_none());
    assert_eq!(store.authorization_binding(), before);
    state.refuse_content_startup();
    assert!(store.reconcile_selection(&state, fenced).is_err());
}

#[test]
fn selection_decision_consumption_rechecks_owner_even_for_identical_authenticated_media() {
    let (state, store, [receipt]) = selected::<1>();
    let (_other, other_store, _) = selected::<0>();
    assert_eq!(
        store.authorization_binding(),
        other_store.authorization_binding()
    );
    let decision = store.reconcile_selection(&state, receipt).unwrap().unwrap();
    let rejected = decision
        .begin(other_store, &state, content_transfer(), 100)
        .err()
        .expect("same bytes cannot substitute another actual owner");
    assert!(matches!(
        rejected.error,
        acq::Failure::Policy(acq::Fault::Phase)
    ));
    assert!(!rejected.owner.has_unresolved_io());
    assert_eq!(
        rejected.owner.authorization_binding(),
        store.authorization_binding()
    );
}

#[test]
fn selection_decision_consumption_rechecks_current_fences_and_original_head() {
    let (mut state, store, [receipt, later]) = selected::<2>();
    let decision = store.reconcile_selection(&state, receipt).unwrap().unwrap();
    let stored = store_object(store, b"a distinct legitimate reservation changes the head");
    let rejected = decision
        .begin(stored.store, &state, content_transfer(), 100)
        .err()
        .expect("old head cannot publish");
    assert!(matches!(
        rejected.error,
        acq::Failure::Policy(acq::Fault::Phase)
    ));
    let store = rejected.owner;
    let decision = store.reconcile_selection(&state, later).unwrap().unwrap();
    state.refuse_content_startup();
    let rejected = decision
        .begin(store, &state, content_transfer(), 100)
        .err()
        .expect("new actual State fence cannot be bypassed by a prior receipt");
    assert!(matches!(
        rejected.error,
        acq::Failure::Policy(acq::Fault::Phase)
    ));
    assert!(rejected.owner.snapshot().unwrap().active().is_none());
}

fn selected<const N: usize>() -> (
    State<Link, Buffer>,
    acq::Store<ActualOwner>,
    [RegistrySelection; N],
) {
    let (a, b, c, _) = selected_with_media::<N>();
    (a, b, c)
}
