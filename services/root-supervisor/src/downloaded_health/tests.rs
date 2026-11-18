extern crate std;
use super::*;
use crate::native_plan::state::tests::downloaded_sources::{
    content_transfer, persist_content, store_object,
};
use crate::{
    native_acquisition as acq,
    native_plan::state::{
        Identity as SessionId,
        tests::{downloaded_sources::selection_tests, health_bytes},
    },
    native_sources::{DownloadedSlot, Resolver, Source},
};
use ev_app_registry::Change;
use ev_userspace_contract::session_note::{Operation, Outcome, Request as NoteRequest};
use std::vec::Vec;
const CUT: u64 = 1000;
struct Live {
    ids: [Identity; 7],
    now: u64,
    fail: Option<usize>,
}
impl Observer for Live {
    type Error = ();
    fn observe(&mut self, i: usize) -> Result<(Identity, u64), ()> {
        if self.fail == Some(i) {
            Err(())
        } else {
            Ok((self.ids[i], self.now))
        }
    }
}
fn live(c: &Cohort, root: u64, subject: u64) -> Live {
    Live {
        ids: core::array::from_fn(|i| Identity {
            process: if i == 0 {
                root
            } else if i == 6 {
                subject
            } else {
                200 + i as u64
            },
            thread: if i == 0 {
                root + 10
            } else if i == 6 {
                subject + 10
            } else {
                300 + i as u64
            },
            image: c.images[i],
        }),
        now: 100,
        fail: None,
    }
}
fn ready(p: &mut Probation, l: &Live) {
    for i in 0..7 {
        p.progress(i, l.ids[i], Progress::Generic, 101).unwrap();
        if CRITICAL_MASK & (1 << i) != 0 {
            p.progress(i, l.ids[i], Progress::Critical, 101).unwrap();
        } else {
            assert!(p.progress(i, l.ids[i], Progress::Critical, 101).is_err());
        }
    }
}
fn images() -> Images<crate::native_sources::tests::Model> {
    let mut i = crate::native_sources::tests::sealed_images(true);
    i.register(0, 100).unwrap();
    i.register(1, 100).unwrap();
    i
}
fn note<T: Wire, W: Window>(
    state: &mut State<T, W>,
    sources: &impl crate::native_sources::Sources,
    who: SessionId,
    text: &str,
    nonce: u32,
) {
    let old = state.note_request(
        sources,
        who,
        NoteRequest::new(Operation::Read, nonce).unwrap(),
        None,
        500,
    );
    assert_eq!(old.response.outcome(), Outcome::Read);
    let old = ev_app_registry::note_data::NoteDataEnvelope::decode(&old.bytes.unwrap()).unwrap();
    let next = old
        .checked_replace(sources.app(), old.counter(), text)
        .unwrap();
    let saved = state.note_request(
        sources,
        who,
        NoteRequest::new(Operation::Write, nonce + 1).unwrap(),
        Some(&next.encode()),
        500,
    );
    assert_eq!(saved.response.outcome(), Outcome::Written);
}
#[test]
fn real_signed_b_health_promotes_only_after_probe_and_persists_protected_local_reference() {
    let (mut state, store, [selected], media) = selection_tests::selected_with_media::<1>();
    let store = persist_content(
        store
            .reconcile_selection(&state, selected)
            .unwrap()
            .unwrap()
            .begin(store, &state, content_transfer(), 100)
            .unwrap_or_else(|_| panic!("selected")),
    );
    let mut store = store;
    let snapshot = store.take_snapshot().unwrap();
    let replay = *snapshot.replay();
    assert!(snapshot.known_good().is_none());
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!("restore"));
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let sources = Resolver::from_members(&banks, &images, [Some(member), None]).unwrap();
    state.open(&sources, 500).unwrap();
    let who = SessionId {
        process: 700,
        thread: 710,
    };
    state
        .admit_source(&sources, Source::Downloaded(DownloadedSlot::B), who)
        .unwrap();
    note(&mut state, &sources, who, "before B health", 1);
    let cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    assert!(
        state
            .retained_downloaded_health(&cohort, &sources, 500)
            .is_err()
    );
    state.system_initialize_downloaded(&cohort, 500).unwrap();
    let ticket = state.system_begin_downloaded(cohort, 500).unwrap();
    let mut live = live(&cohort, context.process, 700);
    let admitted = state
        .system_admit_downloaded(ticket, context, live.ids[0], live.ids[6], 500)
        .unwrap();
    let mut p = admitted.probation(&mut live, CUT).unwrap();
    assert!(
        p.health(&mut live).is_err(),
        "Generic/GUI readiness cannot promote"
    );
    ready(&mut p, &live);
    assert!(
        p.health(&mut live).is_err(),
        "progress without durable probe cannot promote"
    );
    let saved = health_bytes(&media);
    // The one512tick v2 contract governs critical progress. A real storage probe
    // and fresh LIVE may finish later, within the original operation cut.
    p.commit_probe(&mut state, 650, 900).unwrap();
    live.now = 660;
    {
        let _system_ack_receipt = p
            .commit_health(&mut state, &mut live, &sources, 900)
            .unwrap();
        let view = state.system_snapshot(500).unwrap().unwrap();
        assert_eq!(view.known_good, Some(2));
    }
    // Power may stop this Root after the genuine System ACK and before the
    // acquisition KnownGood commit. Reopen actual bytes, load retained active
    // B afresh without a remote clock, and mint only the durable local receipt.
    drop(state);
    crate::native_plan::state::tests::cold(&media);
    let mut state = crate::native_plan::state::tests::state_network(media.clone());
    let (snapshot, loaded, members) = cold_loaded(&mut state);
    assert!(snapshot.known_good().is_none());
    let sources = Resolver::from_members(&banks, &loaded, members).unwrap();
    state.open(&sources, 500).unwrap();
    let reopened = Cohort::checked(&banks, &snapshot, &loaded, members[0].unwrap()).unwrap();
    assert!(reopened.matches(&cohort.manifest()));
    let receipt = state
        .retained_downloaded_health(&reopened, &sources, 500)
        .unwrap();
    let io = state.take_content_backend(true).unwrap();
    let mut engine = crate::native_update::Update::new();
    engine
        .begin(io, crate::native_update::Command::Local, 661)
        .unwrap_or_else(|_| panic!("local original Inspect cut"));
    assert_eq!(
        engine.original_cut(),
        Some(661 + crate::native_update::INSPECT_TICKS)
    );
    let mut buffers = acq::Buffers::empty();
    for _ in 0..4096 {
        if !engine.active() {
            break;
        }
        engine.step(&mut buffers, 661);
    }
    assert!(engine.authorization_store().is_some());
    assert!(engine.begin_known_good(receipt, &state, 661).unwrap());
    for _ in 0..4096 {
        if !engine.active() {
            break;
        }
        engine.step(&mut buffers, 661);
    }
    let store = selection_tests::inspect(engine.take_completed().unwrap());
    let s = store.snapshot().unwrap();
    assert_eq!(s.known_good(), s.active());
    assert_eq!(*s.replay(), replay);
    let store = selection_tests::inspect(store.into_arena().into_backend());
    assert_eq!(store.snapshot().unwrap().known_good().unwrap().version, 2);
    assert_eq!(*store.snapshot().unwrap().replay(), replay);
    for (sector, (before, after)) in saved.iter().zip(health_bytes(&media)).enumerate() {
        if !(16..30).contains(&sector) && !(128..142).contains(&sector) && sector < 256 {
            assert_eq!(before, &after, "unrelated sector{sector}")
        }
    }
}
#[test]
fn forged_progress_stale_identity_clock_and_missing_liveness_refuse_health() {
    let (mut state, mut store, [selected], _) = selection_tests::selected_with_media::<1>();
    let store2 = persist_content(
        store
            .reconcile_selection(&state, selected)
            .unwrap()
            .unwrap()
            .begin(store, &state, content_transfer(), 100)
            .unwrap_or_else(|_| panic!()),
    );
    store = store2;
    let snapshot = store.take_snapshot().unwrap();
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!());
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let c = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    state.system_initialize_downloaded(&c, 500).unwrap();
    let ticket = state.system_begin_downloaded(c, 500).unwrap();
    let mut l = live(&c, context.process, 700);
    let admitted = state
        .system_admit_downloaded(ticket, context, l.ids[0], l.ids[6], 500)
        .unwrap();
    l.fail = Some(6);
    assert!(
        admitted.probation(&mut l, CUT).is_err(),
        "no subject LIVE inferred"
    );
    let mut early = admitted.probation_bound(l.ids, 100, CUT).unwrap();
    let capsule = early
        .fault(
            6,
            l.ids[6],
            Fault {
                tick: 101,
                vector: 6,
                error: 0,
                address: 0,
                instruction: 0x8000001234,
            },
            101,
        )
        .unwrap();
    assert_eq!(&capsule.encode()[..8], b"EVCFAULT");
    assert!(early.health(&mut l).is_err());
    // Canonical protected fault presence is distinct from zero-valued actual
    // vector or RIP fields. Divide error and null execution remain truthful.
    for (vector, instruction) in [(0, 0x8000001234), (14, 0)] {
        let mut exact = admitted.probation_bound(l.ids, 100, CUT).unwrap();
        let capsule = exact
            .fault(
                6,
                l.ids[6],
                Fault {
                    tick: 101,
                    vector,
                    error: 0,
                    address: 0,
                    instruction,
                },
                101,
            )
            .unwrap();
        let bytes = capsule.encode();
        assert_eq!(
            u64::from_le_bytes(bytes[152..160].try_into().unwrap()),
            vector
        );
        assert_eq!(
            u64::from_le_bytes(bytes[176..184].try_into().unwrap()),
            instruction
        );
    }
    let mut late = admitted.probation_bound(l.ids, 100, CUT).unwrap();
    assert!(late.progress(6, l.ids[6], Progress::Generic, 612).is_err());
    let incomplete = || {
        let mut p = admitted.probation_bound(l.ids, 100, CUT).unwrap();
        for (i, id) in l.ids.iter().copied().enumerate() {
            p.progress(i, id, Progress::Generic, 101).unwrap();
        }
        for i in [0, 1] {
            p.progress(i, l.ids[i], Progress::Critical, 101).unwrap();
        }
        assert!(!p.ready());
        p
    };
    let mut before_cut = incomplete();
    assert_eq!(
        before_cut.progress(6, l.ids[6], Progress::Critical, 611),
        Ok(())
    );
    assert!(before_cut.ready());
    let mut at_cut = incomplete();
    // Both states have the same identity, Generic and prerequisite Critical
    // bits; only the actual handler clock differs. An earlier queue arrival
    // cannot stand in for the original512 cutoff at612.
    assert_eq!(
        at_cut.progress(6, l.ids[6], Progress::Critical, 612),
        Err(Error::Progress)
    );
    assert!(!at_cut.ready());
    assert_eq!(
        at_cut.missing_progress(612).unwrap().outcome,
        HealthOutcome::MissingProgress
    );
    assert_eq!(
        late.missing_progress(612).unwrap().outcome,
        HealthOutcome::MissingProgress
    );
    l.fail = None;
    let mut p = admitted.probation(&mut l, CUT).unwrap();
    assert!(p.progress(6, l.ids[6], Progress::Critical, 101).is_err());
    let mut wrong = l.ids[6];
    wrong.thread += 1;
    assert!(p.progress(6, wrong, Progress::Generic, 101).is_err());
    ready(&mut p, &l);
    p.commit_probe(&mut state, 102, 500).unwrap();
    l.now = 103;
    l.fail = Some(4);
    assert!(p.health(&mut l).is_err());
    // A fresh liveness refusal cannot create health; an ensuing protected
    // genuine child fault can still be captured from the retained admission.
    let captured = p
        .fault(
            4,
            l.ids[4],
            Fault {
                tick: 104,
                vector: 14,
                error: 4,
                address: 0,
                instruction: 0,
            },
            104,
        )
        .unwrap();
    assert_eq!(&captured.encode()[..8], b"EVCFAULT");
    assert_eq!(
        state.system_snapshot(500).unwrap().unwrap().known_good,
        None
    );
}
// Only this online fixture-construction provider supplies synthetic qualified
// author time. All subsequent cold/recovery reads run with no such provider.
struct TestClock {
    author: u64,
    calls: u64,
}
impl acq::QualifiedClock for TestClock {
    type Error = ();
    fn fresh(
        &mut self,
    ) -> Result<
        (
            ev_time_contract::freshness::QualifiedWindow,
            ev_time_contract::Instant,
        ),
        (),
    > {
        use ev_time_contract::{
            Domain,
            freshness::{QualifiedWindow, UtcInterval},
        };
        self.calls += 1;
        let d = Domain::new(79).unwrap();
        Ok((
            QualifiedWindow::new(
                d.at(1),
                d.at(3),
                UtcInterval::new(self.author + 1, self.author + 2).unwrap(),
            )
            .unwrap(),
            d.at(self.calls),
        ))
    }
}
fn cold_loaded(
    state: &mut State<
        crate::native_plan::state::tests::Link,
        crate::native_plan::state::tests::Buffer,
    >,
) -> (
    Snapshot,
    Images<crate::native_sources::tests::Model>,
    [Option<Member>; 2],
) {
    let mut engine = crate::native_update::Update::new();
    let mut buffers = acq::Buffers::empty();
    engine
        .begin(
            state.take_content_backend(true).unwrap(),
            crate::native_update::Command::Inspect,
            100,
        )
        .unwrap_or_else(|_| panic!("cold loan"));
    for _ in 0..4096 {
        if !engine.active() {
            break;
        }
        engine.step(&mut buffers, 100);
        engine.observe_after(100);
    }
    assert!(matches!(
        engine.outcome(),
        Some(crate::native_update::Outcome::Complete(_))
    ));
    let mut loader = crate::native_cold::Loader::new();
    let mut images = crate::native_sources::tests::empty_images();
    let mut done = false;
    for _ in 0..4096 {
        if loader
            .step(&mut engine, &mut images, &mut buffers, 100)
            .unwrap()
        {
            done = true;
            break;
        }
    }
    assert!(done);
    let members = loader.members().unwrap();
    let mut snapshot = None;
    assert!(engine.snapshot_into(&mut snapshot));
    state
        .restore_content_backend(engine.take_completed().unwrap())
        .unwrap_or_else(|_| panic!("cold return"));
    (snapshot.unwrap(), images, members)
}
#[test]
fn actual_b_good_c_fault_and_offline_cold_restore_b_keep_later_note_and_all_replay_floors() {
    use crate::native_plan::state::tests::{cold, state_network};
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
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let sources = Resolver::from_members(&banks, &images, [Some(member), None]).unwrap();
    let b_cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    state.open(&sources, 500).unwrap();
    let who = SessionId {
        process: 700,
        thread: 710,
    };
    state
        .admit_source(&sources, Source::Downloaded(DownloadedSlot::B), who)
        .unwrap();
    note(&mut state, &sources, who, "before health", 1);
    state.system_initialize_downloaded(&b_cohort, 500).unwrap();
    let ticket = state.system_begin_downloaded(b_cohort, 500).unwrap();
    let mut l = live(&b_cohort, context.process, 700);
    let admitted = state
        .system_admit_downloaded(ticket, context, l.ids[0], l.ids[6], 500)
        .unwrap();
    let mut p = admitted.probation(&mut l, CUT).unwrap();
    ready(&mut p, &l);
    p.commit_probe(&mut state, 102, 500).unwrap();
    l.now = 103;
    let health = p.commit_health(&mut state, &mut l, &sources, 500).unwrap();
    let store = selection_tests::inspect(state.take_content_backend(true).unwrap());
    let mut work = acq::Commit::empty();
    store
        .reconcile_known_good(&state, health)
        .unwrap()
        .unwrap()
        .begin_into(store, &state, &mut work, content_transfer(), 100)
        .unwrap_or_else(|_| panic!());
    let store = persist_content(work);
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!());
    note(&mut state, &sources, who, "later edit survives C", 3);
    let preserved = health_bytes(&media);
    // Fresh signed C is accepted into the SAME actual Arena, preserving B's
    // previously authorized active/KnownGood identities and every replay floor.
    const C_T: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/targets.bin");
    const C_S: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/snapshot.bin");
    const C_TS: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/timestamp.bin");
    const C_P: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/hello.zion");
    let mut store = selection_tests::inspect(state.take_content_backend(true).unwrap());
    let before = *store.snapshot().unwrap().replay();
    let mut objects = Vec::new();
    for bytes in [C_T, C_S, C_TS, C_P] {
        let stored = store_object(store, bytes);
        objects.push(stored.object);
        store = stored.store;
    }
    let e = ev_release_trust::signature::Envelope::parse(C_T).unwrap();
    let author = ev_release_trust::metadata::Targets::parse(&e)
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
                    bytes: [C_T, C_S, C_TS][i],
                }),
                candidate: acq::Material {
                    object: objects[3],
                    bytes: C_P,
                },
            },
            &mut TestClock { author, calls: 0 },
        )
        .unwrap();
    let proposed = *decision.proposed();
    assert!(proposed.utc_floor() >= before.utc_floor());
    let mut store = persist_content(
        decision
            .begin(store, content_transfer(), 100)
            .unwrap_or_else(|_| panic!()),
    );
    let c_snapshot = store.take_snapshot().unwrap();
    assert_eq!(c_snapshot.known_good().unwrap().version, 2);
    assert_eq!(c_snapshot.active().unwrap().version, 2);
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!());
    let c_member =
        Member::capture(&images, 1, &c_snapshot, c_snapshot.candidate().unwrap()).unwrap();
    let sources = Resolver::from_members(&banks, &images, [Some(member), Some(c_member)]).unwrap();
    state
        .metadata(
            &sources,
            Change::Stage {
                package: c_member.content().package,
            },
            500,
        )
        .unwrap();
    state.fence();
    state
        .prepare_source(&sources, Change::Activate, 500)
        .unwrap();
    state.commit(&sources, 500).unwrap();
    let c_cohort = Cohort::checked(&banks, &c_snapshot, &images, c_member).unwrap();
    state
        .system_apply(SystemChange::Stage(c_cohort.manifest()), 500)
        .unwrap();
    state
        .system_apply(SystemChange::Activate(c_cohort.manifest().generation), 500)
        .unwrap();
    drop(state);
    // Simulated reboot: no package bytes are seeded into the new Images owner.
    // Actual production Inspect and Loader stream both from the persisted Arena.
    cold(&media);
    let mut state = state_network(media.clone());
    let (snapshot, images, members) = cold_loaded(&mut state);
    let c_member = members[1].unwrap();
    let b_member = members[0].unwrap();
    let sources = Resolver::from_members(&banks, &images, members).unwrap();
    state.open(&sources, 500).unwrap();
    assert_eq!(
        state.active_source(&sources).unwrap(),
        Some(Source::Downloaded(DownloadedSlot::C))
    );
    let c_cohort = Cohort::checked(&banks, &snapshot, &images, c_member).unwrap();
    let ticket = state.system_begin_downloaded(c_cohort, 500).unwrap();
    let mut context2 = context;
    context2.process = 43;
    context2.incarnation += 1;
    let mut l = live(&c_cohort, 43, 800);
    let admitted = state
        .system_admit_downloaded(ticket, context2, l.ids[0], l.ids[6], 500)
        .unwrap();
    let mut p = admitted.probation(&mut l, CUT).unwrap();
    let fault = Fault {
        tick: 104,
        vector: 6,
        error: 0,
        address: 0,
        instruction: 0x8000001234,
    };
    let capsule = p.fault(6, l.ids[6], fault, 105).unwrap();
    assert!(p.health(&mut l).is_err());
    let mut engine = crate::native_update::Update::new();
    engine
        .begin(
            state.take_content_backend(true).unwrap(),
            crate::native_update::Command::Local,
            110,
        )
        .unwrap_or_else(|_| panic!("local actual owner"));
    let mut buffers = acq::Buffers::empty();
    for _ in 0..4096 {
        if !engine.active() {
            break;
        }
        engine.step(&mut buffers, 110);
    }
    assert!(engine.authorization_store().is_some());
    let bytes = capsule.encode();
    engine.begin_fetch_put(256, hash(&bytes), 110).unwrap();
    engine.write_fetch_chunk(&bytes, 110).unwrap();
    assert_eq!(engine.fetch_put_remaining(), Some(0));
    engine.seal_fetch_object(110).unwrap();
    assert_eq!(
        engine.read_retained_chunk(&mut buffers.chunk, 110).unwrap(),
        256
    );
    let report = engine.finish_fault_capsule(&capsule, 110).unwrap();
    let reference = report.evidence;
    state
        .restore_content_backend(engine.take_completed().unwrap())
        .unwrap_or_else(|_| panic!("exact fault owner return"));
    state.system_fail_component(report, 500).unwrap();
    let system = state.system_snapshot(500).unwrap().unwrap();
    assert_eq!(system.selected.unwrap(), b_cohort.manifest());
    assert_eq!(system.known_good, Some(2));
    let failure = system.last_failure.unwrap();
    assert_eq!(
        failure.reason,
        ev_store::LastFailureReason::CriticalComponentFault
    );
    assert_eq!(failure.evidence, Some(reference));
    assert_eq!(
        failure.supervisor_image,
        c_cohort.manifest().supervisor_image
    );
    assert_ne!(failure.supervisor_image, l.ids[6].image);
    drop(state);
    cold(&media);
    let mut state = state_network(media.clone());
    let (snapshot, images, members) = cold_loaded(&mut state);
    assert_eq!(*snapshot.replay(), proposed);
    assert_eq!(snapshot.known_good().unwrap().version, 2);
    let sources = Resolver::from_members(&banks, &images, members).unwrap();
    state.open(&sources, 500).unwrap();
    // Root cold adapter has created NO App yet. Recover only the actual protected
    // selected coherent B and use ordinary Registry rollback to its exact ref.
    let b_cohort = Cohort::checked(&banks, &snapshot, &images, members[0].unwrap()).unwrap();
    let system = state.system_snapshot(500).unwrap().unwrap();
    assert_eq!(system.selected, Some(b_cohort.manifest()));
    assert_eq!(system.known_good, Some(2));
    state.fence();
    assert_eq!(
        state
            .prepare_source(&sources, Change::Rollback, 500)
            .unwrap(),
        Some(Source::Downloaded(DownloadedSlot::B))
    );
    state.commit(&sources, 500).unwrap();
    state
        .admit_source(
            &sources,
            Source::Downloaded(DownloadedSlot::B),
            SessionId {
                process: 900,
                thread: 910,
            },
        )
        .unwrap();
    let saved = state.note_request(
        &sources,
        SessionId {
            process: 900,
            thread: 910,
        },
        NoteRequest::new(Operation::Read, 1).unwrap(),
        None,
        500,
    );
    let note = ev_app_registry::note_data::NoteDataEnvelope::decode(&saved.bytes.unwrap()).unwrap();
    assert_eq!(note.note(), "later edit survives C");
    assert_eq!(note.counter(), 2);
    let after = health_bytes(&media);
    for sector in [
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 112, 113, 114, 115, 116, 117, 118,
        119, 120, 121, 122, 123, 124, 125,
    ] {
        assert_eq!(
            after[sector], preserved[sector],
            "saved data sector{sector}"
        )
    }
    let receipt = state
        .retained_downloaded_health(&b_cohort, &sources, 500)
        .unwrap();
    let store = selection_tests::inspect(state.take_content_backend(true).unwrap());
    assert!(
        store
            .reconcile_known_good(&state, receipt)
            .unwrap()
            .is_none()
    );
    assert_eq!(*store.snapshot().unwrap().replay(), proposed);
    let _ = b_member; // The old-incarnation receipt never substitutes for new Loader members.
}
#[test]
fn health_subject_can_read_saved_state_but_cannot_write_before_real_known_good() {
    use ev_userspace_contract::app_data::{Refusal, Request as D, Response};
    let (mut state, mut store, [selection], media) = selection_tests::selected_with_media::<1>();
    store = persist_content(
        store
            .reconcile_selection(&state, selection)
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
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let sources = Resolver::from_members(&banks, &images, [Some(member), None]).unwrap();
    state.open(&sources, 500).unwrap();
    let who = SessionId {
        process: 700,
        thread: 710,
    };
    state
        .admit_source(&sources, Source::Downloaded(DownloadedSlot::B), who)
        .unwrap();
    note(&mut state, &sources, who, "existing owner work", 1);
    state.fence();
    let reads = state
        .prepare_health_reads(&sources, Source::Downloaded(DownloadedSlot::B), 500)
        .unwrap();
    state
        .admit_health_subject(&sources, Source::Downloaded(DownloadedSlot::B), who, reads)
        .unwrap();
    let before = health_bytes(&media);
    assert_eq!(
        state.data_request(&sources, who, D::Read, 500),
        Response::Value(1001)
    );
    let r = state.note_request(
        &sources,
        who,
        NoteRequest::new(Operation::Read, 1).unwrap(),
        None,
        500,
    );
    let old = ev_app_registry::note_data::NoteDataEnvelope::decode(&r.bytes.unwrap()).unwrap();
    let next = old
        .checked_replace(banks.app(), old.counter(), "must refuse during probation")
        .unwrap();
    assert_eq!(
        state.data_request(&sources, who, D::SetValue(2026), 500),
        Response::Refused(Refusal::Denied)
    );
    let busy = state.note_request(
        &sources,
        who,
        NoteRequest::new(Operation::Write, 2).unwrap(),
        Some(&next.encode()),
        500,
    );
    assert_eq!(
        busy.response.outcome(),
        Outcome::Refused(ev_userspace_contract::session_note::Refusal::Busy)
    );
    assert_eq!(health_bytes(&media), before);
    let cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    assert!(
        state
            .release_health_subject(&cohort, &sources, 500)
            .is_err()
    );
    state.system_initialize_downloaded(&cohort, 500).unwrap();
    let ticket = state.system_begin_downloaded(cohort, 500).unwrap();
    let mut l = live(&cohort, context.process, 700);
    let admitted = state
        .system_admit_downloaded(ticket, context, l.ids[0], l.ids[6], 500)
        .unwrap();
    let mut p = admitted.probation(&mut l, CUT).unwrap();
    ready(&mut p, &l);
    p.commit_probe(&mut state, 102, 500).unwrap();
    l.now = 103;
    let _receipt = p.commit_health(&mut state, &mut l, &sources, 500).unwrap();
    state
        .release_health_subject(&cohort, &sources, 500)
        .unwrap();
    let after_health = health_bytes(&media);
    let replay = state.note_request(
        &sources,
        who,
        NoteRequest::new(Operation::Write, 2).unwrap(),
        Some(&next.encode()),
        500,
    );
    assert_eq!(
        replay.response.outcome(),
        Outcome::Refused(ev_userspace_contract::session_note::Refusal::Stale)
    );
    assert_eq!(health_bytes(&media), after_health);
    let explicit_retry = state.note_request(
        &sources,
        who,
        NoteRequest::new(Operation::Write, 3).unwrap(),
        Some(&next.encode()),
        500,
    );
    assert_eq!(explicit_retry.response.outcome(), Outcome::Written);
    assert_eq!(
        ev_app_registry::note_data::NoteDataEnvelope::decode(&explicit_retry.bytes.unwrap())
            .unwrap(),
        next
    );
    assert_eq!(
        state.data_request(&sources, who, D::SetValue(2026), 500),
        Response::Value(2026)
    );
}

#[test]
fn genuine_note_read_before_first_saved_present_and_critical_preserves_all_health_joins() {
    use crate::native_plan::state::tests::storage_calls;
    use ev_desktop::{
        compositor_policy::{Producer, SessionReset, State as Compositor},
        protocol::RootControl,
    };
    use ev_userspace_contract::app_data::{Request as Data, Response as DataResponse};
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
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let source = Source::Downloaded(DownloadedSlot::B);
    let sources = Resolver::from_members(&banks, &images, [Some(member), None]).unwrap();
    let cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    state.open(&sources, 500).unwrap();
    let who = SessionId {
        process: 700,
        thread: 710,
    };
    state.admit_source(&sources, source, who).unwrap();
    note(&mut state, &sources, who, "real saved owner note", 1);
    state.fence();
    state.system_initialize_downloaded(&cohort, 500).unwrap();
    let reads = state.prepare_health_reads(&sources, source, 500).unwrap();
    let ticket = state.system_begin_downloaded(cohort, 500).unwrap();
    state
        .admit_health_subject(&sources, source, who, reads)
        .unwrap();
    let mut l = live(&cohort, context.process, who.process);
    let admitted = state
        .system_admit_downloaded(ticket, context, l.ids[0], l.ids[6], 500)
        .unwrap();
    let mut p = admitted.probation(&mut l, CUT).unwrap();
    for i in 0..6 {
        p.progress(i, l.ids[i], Progress::Generic, 101).unwrap();
    }
    for i in [0, 1] {
        p.progress(i, l.ids[i], Progress::Critical, 101).unwrap();
    }
    let calls = storage_calls(&media);
    assert_eq!(
        state.data_request(&sources, who, Data::Read, 500),
        DataResponse::Value(1001)
    );
    let mut display = Compositor::new();
    display
        .reset(SessionReset {
            producer: Producer::Shell,
            epoch: 1,
        })
        .unwrap();
    display
        .reset(SessionReset {
            producer: Producer::App,
            epoch: 1,
        })
        .unwrap();
    assert!(!display.visible());
    let scope = notice::Subject::checked(&cohort, source, who, 900, 1).unwrap();
    let mut deferred = notice::Pending::new();
    // The old immediate control creates the exact settlement debt whose Root
    // gate prevents all staged work. The deferred path publishes no such control.
    assert!(crate::desktop_outbox::control_needs_settlement(
        RootControl::AppRestored(1).encode().unwrap()
    ));
    let mut client = ev_userspace_contract::session_note::Client::new();
    let req = client.prepare(Operation::Read, 101, 500).unwrap();
    client.accepted(req, 101).unwrap();
    use crate::desktop_outbox::{
        Ingress, Kind, Outbox, Outcome as DeliveryOutcome, Peer, RetainedReply, Target,
        dispatch::{Budget, Work, classify},
    };
    use crate::desktop_profile::Child;
    let mut ingress = Ingress::new();
    for bytes in [*b"EVGARDY1", req.encode()] {
        ingress.push(Peer::App, bytes).unwrap();
    }
    let target = Target {
        peer: Peer::App,
        endpoint: 70,
        control: 900,
        process: who.process,
        thread: who.thread,
    };
    let mut outbox = Outbox::new();
    let mut budget = Budget::new();
    let mut reply = None;
    let mut retained = None;
    let mut dispatched = 0;
    while budget.next(false, outbox.pending()) {
        let Some((index, bytes)) = ingress.first_ready([true, true]) else {
            break;
        };
        outbox.begin([Some(target), None], [1, 0]).unwrap();
        let ticket = outbox.reserved(target).unwrap();
        ingress.remove(index);
        let work = classify(Child::App, bytes);
        if bytes == *b"EVGARDY1" {
            p.progress(6, l.ids[6], Progress::Generic, 101).unwrap();
        } else {
            assert_eq!(work, Work::MayBlock);
            let actual = state.note_request(&sources, who, req, None, 500);
            retained = Some(RetainedReply::new(ticket, target, actual.bytes));
            outbox
                .publish(ticket, actual.response.encode(), 500, Kind::Note)
                .unwrap();
            reply = Some(actual);
        }
        outbox.end();
        budget.completed(work);
        dispatched += 1;
    }
    assert_eq!(dispatched, 2);
    assert!(!ingress.pending());
    assert!(
        !deferred.pending(),
        "Note read requires neither prior Present nor AppDone"
    );
    // The sole outbound attempt follows newly retained work, with the same
    // exact body/ticket/target and FIFO head; it is not a fabricated completion.
    let entry = outbox.next_attempt().unwrap();
    let retained = retained.as_mut().unwrap();
    assert!(retained.ready(entry));
    assert_eq!(retained.body(), reply.as_ref().unwrap().bytes.as_ref());
    outbox
        .finish(entry.ticket, DeliveryOutcome::Accepted)
        .unwrap();
    assert!(retained.complete(entry, DeliveryOutcome::Accepted));
    assert!(outbox.next_attempt().is_none());
    assert_eq!(outbox.stats().accepted, 1);
    let reply = reply.unwrap();
    assert_eq!(reply.response.outcome(), Outcome::Read);
    let completed = client
        .accept(&reply.response.encode(), 0, 102, |outcome| {
            if outcome != Outcome::Read {
                return Err(());
            }
            let actual =
                ev_app_registry::note_data::NoteDataEnvelope::decode(&reply.bytes.unwrap())
                    .map_err(|_| ())?;
            if actual.app() != banks.app() {
                return Err(());
            }
            Ok(actual)
        })
        .unwrap();
    let ev_userspace_contract::session_note::Completion::Read(actual) = completed else {
        panic!("real read completion");
    };
    assert_eq!(actual.note(), "real saved owner note");
    assert_eq!(
        storage_calls(&media),
        calls,
        "probation scalar/Note path must do no Store I/O"
    );
    struct Canvas(Vec<ev_graphics::Color>);
    impl ev_graphics::Pixels for Canvas {
        fn dimensions(&self) -> (usize, usize) {
            (ev_graphics::WIDTH, ev_graphics::HEIGHT)
        }
        fn write(
            &mut self,
            x: usize,
            y: usize,
            value: ev_graphics::Color,
        ) -> Result<(), ev_graphics::Error> {
            if x >= ev_graphics::WIDTH || y >= ev_graphics::HEIGHT {
                return Err(ev_graphics::Error::Bounds);
            }
            self.0[y * ev_graphics::WIDTH + x] = value;
            Ok(())
        }
    }
    let mut canvas =
        Canvas(std::vec![ev_graphics::Color(0);ev_graphics::WIDTH*ev_graphics::HEIGHT]);
    ev_graphics::session::render(
        &mut canvas,
        ev_graphics::session::View {
            build: ev_graphics::native::Build::B,
            focus: ev_graphics::session::Focus::Note,
            note: actual.note().as_bytes(),
            state: ev_graphics::session::SaveState::Saved,
            file: None,
        },
    )
    .unwrap();
    assert!(canvas.0.iter().any(|p| p.0 != 0));
    let header = ev_graphics::SurfaceHeader { sequence: 1 }.encode().unwrap();
    let header = ev_graphics::SurfaceHeader::parse(&header).unwrap();
    display.present(Producer::App, 1, header.sequence).unwrap(); // Same actual Present policy used by the adapter.
    assert!(
        !display.visible(),
        "health Present is not a user-visible composition claim"
    );
    // Only this first genuine saved-data Present permits AppDone/Critical.
    deferred.capture(scope, true);
    assert!(deferred.pending());
    assert!(!deferred.ready(scope));
    p.progress(6, l.ids[6], Progress::Critical, 102).unwrap();
    assert!(p.ready());
    assert!(!deferred.ready(scope));
    p.commit_probe(&mut state, 102, 500).unwrap();
    l.now = 103;
    let receipt = p.commit_health(&mut state, &mut l, &sources, 500).unwrap();
    assert!(
        !deferred.ready(scope),
        "System health alone cannot release the cosmetic notice"
    );
    let store = selection_tests::inspect(state.take_content_backend(true).unwrap());
    let decision = store
        .reconcile_known_good(&state, receipt)
        .unwrap()
        .unwrap();
    let mut commit = acq::Commit::empty();
    decision
        .begin_into(store, &state, &mut commit, content_transfer(), 100)
        .unwrap_or_else(|_| panic!());
    let mut store = persist_content(commit);
    let joined = store.take_snapshot().unwrap();
    assert_eq!(joined.known_good().unwrap().version, 2);
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!());
    state
        .release_health_subject(&cohort, &sources, 500)
        .unwrap();
    deferred.release(scope);
    assert!(deferred.ready(scope));
    assert_eq!(deferred.take(scope), Some(RootControl::AppRestored(1)));
    assert!(!deferred.pending());
    assert!(deferred.take(scope).is_none());
}

#[test]
fn deferred_notice_rejects_stale_identity_source_epoch_and_discards_failure_or_replacement() {
    use ev_desktop::protocol::RootControl;
    let (mut state, store, [selected], _) = selection_tests::selected_with_media::<1>();
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
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    let source = Source::Downloaded(DownloadedSlot::B);
    let who = SessionId {
        process: 700,
        thread: 710,
    };
    let current = notice::Subject::checked(&cohort, source, who, 900, 1).unwrap();
    assert!(
        notice::Subject::checked(
            &cohort,
            Source::Bank(crate::native_plan::Slot::A),
            who,
            900,
            1
        )
        .is_none()
    );
    assert!(
        notice::Subject::checked(&cohort, Source::Downloaded(DownloadedSlot::C), who, 900, 1)
            .is_none()
    );
    let mut q = notice::Pending::new();
    for (identity, control, epoch) in [
        (
            SessionId {
                process: 701,
                thread: 710,
            },
            900,
            1,
        ),
        (
            SessionId {
                process: 700,
                thread: 711,
            },
            900,
            1,
        ),
        (who, 901, 1),
        (who, 900, 2),
    ] {
        let stale = notice::Subject::checked(&cohort, source, identity, control, epoch).unwrap();
        q.capture(current, true);
        q.release(stale);
        assert!(!q.pending());
        assert!(q.take(current).is_none());
        q.capture(current, true);
        q.release(current);
        assert!(!q.ready(stale));
        assert!(!q.pending());
    }
    use crate::desktop_outbox::{
        Error as DeliveryError, Kind, Outbox, Outcome as DeliveryOutcome, Peer, Target,
    };
    let app = Target {
        peer: Peer::App,
        endpoint: 70,
        control: 900,
        process: who.process,
        thread: who.thread,
    };
    let shell = Target {
        peer: Peer::Shell,
        endpoint: 71,
        control: 901,
        process: 720,
        thread: 730,
    };
    let mut outbox = Outbox::new();
    q.capture(current, true);
    q.release(current);
    assert!(outbox.reserved(shell).is_none());
    assert!(q.ready(current));
    assert!(q.pending(), "no outer Shell credit must retain notice");
    outbox.begin([Some(app), Some(shell)], [1, 1]).unwrap();
    let outer_ticket = outbox.reserved(shell).unwrap();
    assert_eq!(
        outbox.begin([Some(app), Some(shell)], [0, 1]),
        Err(DeliveryError::Batch)
    );
    let message = q.take(current).unwrap();
    assert_eq!(message, RootControl::AppRestored(1));
    outbox
        .publish(outer_ticket, message.encode().unwrap(), 512, Kind::Control)
        .unwrap();
    assert!(q.take(current).is_none());
    outbox.end();
    let entry = outbox.next_attempt().unwrap();
    assert_eq!(entry.ticket, outer_ticket);
    assert_eq!(entry.target, shell);
    assert_eq!(entry.bytes, message.encode().unwrap());
    outbox
        .finish(entry.ticket, DeliveryOutcome::Accepted)
        .unwrap();
    assert!(outbox.next_attempt().is_none());
    q.capture(current, true);
    q.release(current);
    outbox.begin([Some(app), Some(shell)], [1, 1]).unwrap();
    let stale = notice::Subject::checked(&cohort, source, who, 900, 2).unwrap();
    assert!(!q.ready(stale));
    assert!(!q.pending());
    outbox.end();
    assert!(!outbox.pending());
    q.capture(current, false);
    q.discard();
    q.release(current);
    assert!(q.take(current).is_none());
    q.capture(current, false);
    q.release(current);
    assert_eq!(q.take(current), Some(RootControl::AppStarted(1)));
    assert!(q.take(current).is_none());
}

#[test]
fn queued_output_blocks_ordinary_dispatch_but_not_actual_deadline_failure_system_io() {
    use crate::desktop_outbox::{Kind, Outbox, Peer, Target, dispatch::Budget};
    let (mut state, store, [selected], _media) = selection_tests::selected_with_media::<1>();
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
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    state.system_initialize_downloaded(&cohort, 500).unwrap();
    let ticket = state.system_begin_downloaded(cohort, 500).unwrap();
    let l = live(&cohort, context.process, 700);
    let admitted = state
        .system_admit_downloaded(ticket, context, l.ids[0], l.ids[6], 500)
        .unwrap();
    let mut probation = admitted.probation_bound(l.ids, 100, CUT).unwrap();
    let target = Target {
        peer: Peer::Shell,
        endpoint: 7,
        control: 90,
        process: 20,
        thread: 21,
    };
    let mut out = Outbox::new();
    out.begin([None, Some(target)], [0, 1]).unwrap();
    let reply = out.reserved(target).unwrap();
    out.publish(reply, [1; 8], 512, Kind::Control).unwrap();
    out.end();
    assert!(!Budget::new().next(false, out.pending()));
    // The required System path samples its actual original deadline and writes
    // the honest failure under the existing operation cut despite output debt.
    let failure = probation.missing_progress(612).unwrap();
    assert_eq!(failure.outcome, HealthOutcome::MissingProgress);
    let view = state
        .system_apply(
            crate::native_plan::state::SystemChange::Health(failure),
            900,
        )
        .unwrap();
    assert!(view.known_good.is_none());
    assert!(out.pending());
    assert_eq!(out.next_attempt().unwrap().ticket, reply);
    let snapshot = state.system_snapshot(500).unwrap().unwrap();
    assert_eq!(
        snapshot.last_failure.unwrap().reason,
        ev_store::LastFailureReason::MissingProgress
    );
}

fn policy_admission() -> (Cohort, Admitted, Live, Context) {
    let (mut state, store, [selected], _) = selection_tests::selected_with_media::<1>();
    let mut store = persist_content(
        store
            .reconcile_selection(&state, selected)
            .unwrap()
            .unwrap()
            .begin(store, &state, content_transfer(), 100)
            .unwrap_or_else(|_| panic!("selected")),
    );
    let snapshot = store.take_snapshot().unwrap();
    state
        .restore_content_backend(store.into_arena().into_backend())
        .unwrap_or_else(|_| panic!("restore"));
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let images = images();
    let member = Member::capture(&images, 0, &snapshot, snapshot.active().unwrap()).unwrap();
    let cohort = Cohort::checked(&banks, &snapshot, &images, member).unwrap();
    state.system_initialize_downloaded(&cohort, 500).unwrap();
    let ticket = state.system_begin_downloaded(cohort, 500).unwrap();
    let l = live(&cohort, context.process, 700);
    let admitted = state
        .system_admit_downloaded(ticket, context, l.ids[0], l.ids[6], 500)
        .unwrap();
    (cohort, admitted, l, context)
}

#[test]
fn health_v2_fixed_window_both_constructors_clip_original_cut_without_renewal() {
    let (_, admitted, mut l, _) = policy_admission();
    for cut in [CUT, 612, 550] {
        let expected = 612.min(cut);
        let mut p = admitted.probation(&mut l, cut).unwrap();
        assert_eq!(p.deadline(), expected);
        assert_eq!(
            admitted
                .probation_bound(l.ids, 100, cut)
                .unwrap()
                .deadline(),
            expected
        );
        for (i, id) in l.ids.iter().copied().enumerate() {
            p.progress(i, id, Progress::Generic, 101).unwrap();
        }
        for i in [0, 1] {
            p.progress(i, l.ids[i], Progress::Critical, 102).unwrap();
        }
        assert!(!p.ready());
        assert_eq!(p.deadline(), expected);
        assert_eq!(
            p.progress(6, l.ids[6], Progress::Critical, expected - 1),
            Ok(())
        );
        assert!(p.ready());
        let mut late = admitted.probation_bound(l.ids, 100, cut).unwrap();
        for (i, id) in l.ids.iter().copied().enumerate() {
            late.progress(i, id, Progress::Generic, 101).unwrap();
        }
        for i in [0, 1] {
            late.progress(i, l.ids[i], Progress::Critical, 102).unwrap();
        }
        assert!(!late.ready());
        assert_eq!(
            late.progress(6, l.ids[6], Progress::Critical, expected),
            Err(Error::Progress)
        );
        assert!(!late.ready());
        assert_eq!(late.deadline(), expected);
        assert_eq!(
            late.missing_progress(expected).unwrap().outcome,
            HealthOutcome::MissingProgress
        );
    }
    for cut in [0, 99, 100] {
        assert!(admitted.probation_bound(l.ids, 100, cut).is_err());
        assert!(admitted.probation(&mut l, cut).is_err());
    }
    for first in [u64::MAX, u64::MAX - 511] {
        assert!(admitted.probation_bound(l.ids, first, u64::MAX).is_err());
    }
    let mut p = admitted.probation_bound(l.ids, 100, CUT).unwrap();
    p.progress(0, l.ids[0], Progress::Generic, 101).unwrap();
    assert_eq!(
        p.progress(1, l.ids[1], Progress::Generic, 100),
        Err(Error::Clock)
    );
    assert!(p.phase == Phase::Fenced);
}

#[test]
fn health_v2_does_not_reinterpret_legacy64_or_a_checksum_valid_v1_plan() {
    use ev_block_service::critical_progress::{Decision, Window};
    assert_eq!((HEALTH_VERSION, PROGRESS_TICKS), (2, 512));
    let mut before = Window::new(CUT);
    assert_eq!(before.observe_live(100, false), Ok(Decision::Waiting));
    assert_eq!(before.observe_live(163, true), Ok(Decision::Ready));
    let mut at = Window::new(CUT);
    assert_eq!(at.observe_live(100, false), Ok(Decision::Waiting));
    assert_eq!(at.observe_live(164, true), Ok(Decision::MissingProgress));
    let (cohort, admitted, l, context) = policy_admission();
    assert_eq!(cohort.manifest.health_version, 2);
    let plan = BootPlan {
        manifest: cohort.manifest,
        serial: 1,
        candidate: true,
        attempt: 1,
    };
    assert!(cohort.admission(context, l.ids[0], l.ids[6], plan).is_ok());
    let actual = cohort.admission(context, l.ids[0], l.ids[6], plan).unwrap();
    for field in 0..2 {
        let mut changed = cohort;
        if field == 0 {
            changed.manifest.health_version = 1;
        } else {
            changed.manifest.health_contract[0] ^= 1;
        }
        // Private construction is test-only: this checks transcript separation,
        // not production permission to instantiate a foreign health contract.
        let changed_plan = BootPlan {
            manifest: changed.manifest,
            ..plan
        };
        let other = changed
            .admission(context, l.ids[0], l.ids[6], changed_plan)
            .unwrap();
        assert_ne!(actual.process_stamp, other.process_stamp);
    }
    let old_hash = [
        0xe7, 0xf3, 0x10, 0x46, 0xc5, 0xa5, 0xe4, 0xc0, 0x6d, 0xad, 0xc7, 0x14, 0x23, 0xd6, 0x19,
        0xf4, 0x34, 0x7a, 0xa4, 0xfe, 0x7f, 0x2b, 0x12, 0xa7, 0xd5, 0x37, 0x01, 0x61, 0x76, 0xfb,
        0xa3, 0xfa,
    ];
    for field in 0..3 {
        let mut old = plan;
        match field {
            0 => old.manifest.health_version = 1,
            1 => old.manifest.health_contract = old_hash,
            _ => {
                old.manifest.health_version = 1;
                old.manifest.health_contract = old_hash;
            }
        }
        // General Store support for v1 is not current downloaded admission.
        assert!(old.manifest.valid());
        assert!(!cohort.matches(&old.manifest));
        assert_eq!(
            cohort.admission(context, l.ids[0], l.ids[6], old),
            Err(Error::Identity)
        );
    }
    let mut p = admitted.probation_bound(l.ids, 100, CUT).unwrap();
    for (i, id) in l.ids.iter().copied().enumerate() {
        p.progress(i, id, Progress::Generic, 101).unwrap();
    }
    for i in [0, 1] {
        p.progress(i, l.ids[i], Progress::Critical, 102).unwrap();
    }
    // The actual05 subject emitted at+71. This models its policy classification,
    // not proof of Note/Present authority or a replay of that failed VM.
    assert_eq!(p.progress(6, l.ids[6], Progress::Critical, 171), Ok(()));
    assert!(p.ready());
}

#[test]
fn health_v2_admission_matches_external_canonical_vector_and_independent_host_fixture() {
    let (mut cohort, _, _, mut context) = policy_admission();
    cohort.manifest.cohort = [0x11; 32];
    cohort.manifest.supervisor_image = [0x22; 32];
    cohort.images[0] = [0x22; 32];
    cohort.images[6] = [0x66; 32];
    context.process = 20;
    context.epoch = 4;
    context.incarnation = 2;
    context.manifest = [0x55; 32];
    let root = Identity {
        process: 20,
        thread: 120,
        image: [0x22; 32],
    };
    let subject = Identity {
        process: 30,
        thread: 130,
        image: [0x66; 32],
    };
    let plan = BootPlan {
        manifest: cohort.manifest,
        serial: 1,
        candidate: true,
        attempt: 1,
    };
    let actual = cohort.admission(context, root, subject, plan).unwrap();
    // Independent Python hashlib/struct vector, also used by Host's separate
    // source-bound reconstruction fixture. This is not production admission.
    assert_eq!(
        actual.process_stamp,
        [
            0xcc, 0x1c, 0xe1, 0xf7, 0x42, 0x42, 0xb8, 0xfb, 0xc3, 0x1d, 0xbf, 0xfa, 0x50, 0xe6,
            0x7a, 0x0e, 0x57, 0x5f, 0x77, 0xf7, 0xaa, 0x8a, 0xd0, 0x05, 0xf8, 0x16, 0x18, 0x4f,
            0x97, 0x49, 0xb0, 0x4f
        ]
    );
}
