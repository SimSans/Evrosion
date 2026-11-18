use super::*;
use crate::native_sources::{Downloaded, DownloadedSlot, Source, Sources, View};
#[path = "selection_tests.rs"]
pub(crate) mod selection_tests;
#[test]
fn real_registry_data_note_and_policy_keep_actual_downloaded_identity_across_cold_open() {
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let p = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let images = crate::native_sources::tests::sealed_images(false);
    let content = snapshot.candidate().unwrap();
    let view = View::new(
        &p,
        &images,
        &snapshot,
        [
            Some(Downloaded::from_images(&images, 0, &snapshot, content).unwrap()),
            None,
        ],
    )
    .unwrap();
    let media = composed_disk();
    {
        let mut m = media.borrow_mut();
        m.cache[112..126].fill([0; 512]);
        m.durable = m.cache.clone();
    }
    let mut s = state_session(media.clone());
    s.open(&p, DEADLINE).unwrap();
    s.install(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    s.grant_initialize(&p, grant_user(), DEADLINE).unwrap();
    assert!(remember_grant(&mut s, &p));
    s.metadata(
        &view,
        Change::Stage {
            package: content.package,
        },
        DEADLINE,
    )
    .unwrap();
    assert_eq!(s.active_source(&view).unwrap(), Some(Source::Bank(Slot::A)));
    s.fence();
    let source = Source::Downloaded(DownloadedSlot::B);
    assert_eq!(
        s.prepare_source(&view, Change::Activate, DEADLINE).unwrap(),
        Some(source)
    );
    assert_eq!(s.admit_source(&view, source, WHO), Err(Error::State));
    s.commit(&view, DEADLINE).unwrap();
    assert_eq!(s.active_source(&view).unwrap(), Some(source));
    assert_eq!(s.active(&p), Err(Error::Package));
    assert_eq!(s.admit(&p, Slot::B, WHO), Err(Error::Package));
    s.admit_source(&view, source, WHO).unwrap();
    let missing = View::new(&p, &images, &snapshot, [None, None]).unwrap();
    assert_eq!(
        s.data_request(&missing, WHO, DataRequest::Read, DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    assert!(matches!(
        s.data_request(&view, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    ));
    assert!(matches!(
        s.data_request(&view, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Value(2026)
    ));
    let head = s.grant_snapshot(&view, grant_user(), DEADLINE).unwrap();
    let mut current = grant_requester(&p, head.requester_revision(), 90);
    current.app.package = ev_picker::ContentDigest::new(content.package).unwrap();
    let mut probe = RemintProbe::default();
    assert!(matches!(
        s.grant_remint(
            &view,
            grant_user(),
            current,
            grant_object(),
            DEADLINE,
            &mut probe
        ),
        Err(Error::State)
    ));
    assert_eq!(probe.calls, 0);
    use ev_userspace_contract::session_note::{Operation, Outcome, Request as N};
    let first = s.note_request(
        &view,
        WHO,
        N::new(Operation::Read, 1).unwrap(),
        None,
        DEADLINE,
    );
    assert_eq!(first.response.outcome(), Outcome::Read);
    let old = ev_app_registry::note_data::NoteDataEnvelope::decode(&first.bytes.unwrap()).unwrap();
    let next = old
        .checked_replace(p.app(), 0, "actual downloaded B keeps these edits")
        .unwrap();
    let saved = s.note_request(
        &view,
        WHO,
        N::new(Operation::Write, 2).unwrap(),
        Some(&next.encode()),
        DEADLINE,
    );
    assert_eq!(saved.response.outcome(), Outcome::Written);
    drop(s);
    cold(&media);
    let mut s = state_session(media.clone());
    s.open(&view, DEADLINE).unwrap();
    assert_eq!(s.active_source(&view).unwrap(), Some(source));
    s.admit_source(&view, source, WHO).unwrap();
    assert!(matches!(
        s.data_request(&view, WHO, DataRequest::Read, DEADLINE),
        Response::Value(2026)
    ));
    let reopened = s.note_request(
        &view,
        WHO,
        N::new(Operation::Read, 1).unwrap(),
        None,
        DEADLINE,
    );
    assert_eq!(reopened.bytes, Some(next.encode()));
    assert_eq!(
        view.checked_source(source).unwrap().id().bytes(),
        content.package
    );
    assert!(snapshot.active().is_none() && snapshot.known_good().is_none());
}

type ActualOwner = crate::native_plan::storage::content::OwnedBackend<Link, Buffer>;
pub(crate) fn content_transfer() -> ev_content_store::TransferCut {
    ev_content_store::TransferCut::new(100, 1_000_000).unwrap()
}
pub(crate) fn store_object(
    store: crate::native_acquisition::Store<ActualOwner>,
    bytes: &[u8],
) -> crate::native_acquisition::Stored<ActualOwner> {
    let t = content_transfer();
    let mut put = store
        .begin_put(bytes.len() as u64, Sha256::digest(bytes).into(), t, 100)
        .unwrap_or_else(|_| panic!("object reserve"));
    for b in bytes.chunks(4096) {
        put.write_chunk(b, 100)
            .unwrap_or_else(|_| panic!("object write"));
    }
    let read = put.seal(100).unwrap_or_else(|_| panic!("object seal"));
    let (store, object, _) = read_object(read);
    crate::native_acquisition::Stored { store, object }
}
pub(crate) fn read_object(
    mut read: crate::native_acquisition::Read<ActualOwner>,
) -> (
    crate::native_acquisition::Store<ActualOwner>,
    ev_content_store::Object,
    Vec<u8>,
) {
    let mut bytes = Vec::new();
    let mut b = [0; 4096];
    while read.remaining() != 0 {
        let n = read.remaining().min(4096) as usize;
        read.read_chunk(&mut b[..n], 100)
            .unwrap_or_else(|_| panic!("object read"));
        bytes.extend_from_slice(&b[..n]);
    }
    let stored = read.finish().unwrap_or_else(|_| panic!("object verified"));
    (stored.store, stored.object, bytes)
}
pub(crate) fn persist_content(
    mut commit: crate::native_acquisition::Commit<ActualOwner>,
) -> crate::native_acquisition::Store<ActualOwner> {
    let mut b = crate::native_acquisition::Buffers::empty();
    while !commit
        .step(&mut b, 100)
        .unwrap_or_else(|_| panic!("content commit"))
    {}
    commit
        .publication()
        .unwrap_or_else(|_| panic!())
        .publish(100, &mut b.checkpoint)
        .unwrap_or_else(|_| panic!())
}
struct ModelClock {
    author: u64,
    calls: u64,
}
impl crate::native_acquisition::QualifiedClock for ModelClock {
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
        let d = Domain::new(77).unwrap();
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
#[test]
fn same_disk_cold_saved_b_authenticates_on_preopen_backend_before_registry_lookup() {
    use crate::native_acquisition as acq;
    use ev_content_store::Provisioner;
    const PACKAGE: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/hello.zion");
    const TARGETS: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/targets.bin");
    const SNAPSHOT: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/snapshot.bin");
    const TIMESTAMP: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/timestamp.bin");
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
    let creation = crate::native_update::creation_manifest();
    let t = content_transfer();
    {
        let mut state = state_network(media.clone());
        assert!(state.record().is_none());
        let before = media.borrow().calls.len();
        let owner = state.take_content_backend(true).unwrap();
        assert_eq!(media.borrow().calls.len(), before);
        assert!(state.content_busy());
        let mut p = Provisioner::new(owner, creation, t).unwrap_or_else(|_| panic!());
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
        // Synthetic qualified TEST clock only; source/crypto/storage composition
        // is real, not a live time-provider or physical-image claim.
        let remote = acq::Remote {
            current_root: acq::ROM_ROOT,
            root_updates: &[],
            metadata: [
                acq::Material {
                    object: objects[0],
                    bytes: TARGETS,
                },
                acq::Material {
                    object: objects[1],
                    bytes: SNAPSHOT,
                },
                acq::Material {
                    object: objects[2],
                    bytes: TIMESTAMP,
                },
            ],
            candidate: acq::Material {
                object: objects[3],
                bytes: PACKAGE,
            },
        };
        let decision = store
            .authorize(remote, &mut ModelClock { author, calls: 0 })
            .unwrap();
        store = persist_content(decision.begin(store, t, 100).unwrap_or_else(|_| panic!()));
        let content = store.snapshot().unwrap().candidate().unwrap();
        let read = store
            .begin_read(content.object, t, 100)
            .unwrap_or_else(|_| panic!());
        let (mut store, _, bytes) = read_object(read);
        let trusted = store.take_snapshot().unwrap();
        let owner = store.into_arena().into_backend();
        assert!(state.restore_content_backend(owner).is_ok());
        let images = crate::native_sources::tests::sealed_packages(&[&bytes]);
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
        state.fence();
        state
            .prepare_source(&view, Change::Activate, DEADLINE)
            .unwrap();
        state.commit(&view, DEADLINE).unwrap();
        state
            .admit_source(&view, Source::Downloaded(DownloadedSlot::B), WHO)
            .unwrap();
        assert_eq!(
            state.data_request(&view, WHO, DataRequest::Read, DEADLINE),
            Response::Value(1001)
        );
        assert_eq!(
            state.data_request(&view, WHO, DataRequest::SetValue(2077), DEADLINE),
            Response::Value(2077)
        );
        use ev_userspace_contract::session_note::{Operation, Request as N};
        let old = state.note_request(
            &view,
            WHO,
            N::new(Operation::Read, 1).unwrap(),
            None,
            DEADLINE,
        );
        let note = ev_app_registry::note_data::NoteDataEnvelope::decode(&old.bytes.unwrap())
            .unwrap()
            .checked_replace(banks.app(), 0, "saved B on the same owned disk")
            .unwrap();
        assert!(
            state
                .note_request(
                    &view,
                    WHO,
                    N::new(Operation::Write, 2).unwrap(),
                    Some(&note.encode()),
                    DEADLINE
                )
                .bytes
                .is_some()
        );
    }
    cold(&media);
    let mut state = state_network(media.clone());
    assert!(state.record().is_none() && state.data().is_none());
    let before = media.borrow().calls.len();
    let owner = state.take_content_backend(false).unwrap();
    assert_eq!(media.borrow().calls.len(), before);
    assert!(state.content_busy());
    assert!(!state.recovery_required());
    let mut update = crate::native_update::Update::new();
    assert!(
        update
            .begin(owner, crate::native_update::Command::Inspect, 100)
            .is_ok()
    );
    let mut buffers = acq::Buffers::empty();
    for _ in 0..2048 {
        update.step(&mut buffers, 100);
        update.observe_after(100);
        if update.outcome().is_some() {
            break;
        }
    }
    assert!(matches!(
        update.outcome(),
        Some(crate::native_update::Outcome::Complete(_))
    ));
    let mut images = crate::native_sources::tests::empty_images();
    let mut loader = crate::native_cold::Loader::new();
    for _ in 0..1024 {
        let done = loader
            .step(&mut update, &mut images, &mut buffers, 100)
            .unwrap();
        update.observe_after(100);
        if done {
            break;
        }
    }
    let bindings = loader
        .bindings()
        .expect("production streaming loader completes");
    let content = bindings[0].unwrap().1;
    assert!(
        images
            .registered_capability(bindings[0].unwrap().0)
            .is_some()
    );
    let mut trusted = None;
    assert!(update.snapshot_into(&mut trusted));
    let trusted = trusted.unwrap();
    assert!(
        state
            .restore_content_backend(update.take_completed().unwrap())
            .is_ok()
    );
    assert!(!state.recovery_required());
    let view =
        crate::native_sources::Resolver::new(&banks, &images, Some(&trusted), bindings).unwrap();
    state.open(&view, DEADLINE).unwrap();
    assert_eq!(
        state.active_source(&view).unwrap(),
        Some(Source::Downloaded(DownloadedSlot::B))
    );
    state
        .admit_source(&view, Source::Downloaded(DownloadedSlot::B), WHO)
        .unwrap();
    assert_eq!(
        state.data_request(&view, WHO, DataRequest::Read, DEADLINE),
        Response::Value(2077)
    );
    use ev_userspace_contract::session_note::{Operation, Request as N};
    let note = state.note_request(
        &view,
        WHO,
        N::new(Operation::Read, 1).unwrap(),
        None,
        DEADLINE,
    );
    assert_eq!(
        ev_app_registry::note_data::NoteDataEnvelope::decode(&note.bytes.unwrap())
            .unwrap()
            .note(),
        "saved B on the same owned disk"
    );
    assert!(banks.slot(content.package).is_none());
    assert!(trusted.active().is_none() && trusted.known_good().is_none());
}

#[test]
fn retained_downloaded_identity_keeps_saved_data_after_clean_refusal_but_not_unknown_io() {
    use crate::{native_acquisition as acq, native_update as update};
    use ev_content_store::{Arena, Provisioner};
    use ev_userspace_contract::session_note::{Operation, Outcome, Request as N};
    const PACKAGE: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/hello.zion");
    const TARGETS: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/targets.bin");
    const SNAPSHOT: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/snapshot.bin");
    const TIMESTAMP: &[u8] =
        include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/timestamp.bin");
    fn run<B: ev_content_store::Backend>(engine: &mut update::Update<B>) -> update::Outcome {
        let mut buffers = acq::Buffers::empty();
        for _ in 0..4096 {
            engine.step(&mut buffers, 100);
            engine.observe_after(100);
            if let Some(outcome) = engine.outcome() {
                return outcome;
            }
        }
        panic!("bounded production update continuation");
    }
    for refusal in 0..4 {
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
        let t = content_transfer();
        let mut provision = Provisioner::new(
            state.take_content_backend(true).unwrap(),
            update::creation_manifest(),
            t,
        )
        .unwrap_or_else(|_| panic!());
        while provision.remaining() != 0 {
            provision.scan(t.child(100, 1024).unwrap()).unwrap();
        }
        let arena = provision
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
            let material = store_object(store, bytes);
            objects.push(material.object);
            store = material.store;
        }
        let envelope = ev_release_trust::signature::Envelope::parse(TARGETS).unwrap();
        let author = ev_release_trust::metadata::Targets::parse(&envelope)
            .unwrap()
            .common()
            .not_before;
        // Synthetic qualified TEST clock, with real signatures/Store bytes.
        let decision = store
            .authorize(
                acq::Remote {
                    current_root: acq::ROM_ROOT,
                    root_updates: &[],
                    metadata: [
                        acq::Material {
                            object: objects[0],
                            bytes: TARGETS,
                        },
                        acq::Material {
                            object: objects[1],
                            bytes: SNAPSHOT,
                        },
                        acq::Material {
                            object: objects[2],
                            bytes: TIMESTAMP,
                        },
                    ],
                    candidate: acq::Material {
                        object: objects[3],
                        bytes: PACKAGE,
                    },
                },
                &mut ModelClock { author, calls: 0 },
            )
            .unwrap();
        store = persist_content(decision.begin(store, t, 100).unwrap_or_else(|_| panic!()));
        assert!(
            state
                .restore_content_backend(store.into_arena().into_backend())
                .is_ok()
        );
        // Authenticate and seal from this same actual backend before the FIRST
        // Registry lookup. No test-provided Snapshot or compiledB bytes substitute.
        let mut engine = update::Update::new();
        assert!(
            engine
                .begin(
                    state.take_content_backend(true).unwrap(),
                    update::Command::Inspect,
                    100
                )
                .is_ok()
        );
        assert!(matches!(run(&mut engine), update::Outcome::Complete(_)));
        let mut images = crate::native_sources::tests::empty_images();
        let mut loader = crate::native_cold::Loader::new();
        let mut buffers = acq::Buffers::empty();
        for _ in 0..1024 {
            let done = loader
                .step(&mut engine, &mut images, &mut buffers, 100)
                .unwrap();
            engine.observe_after(100);
            if done {
                break;
            }
        }
        let bindings = loader.bindings().unwrap();
        let content = bindings[0].unwrap().1;
        let mut retained = None;
        assert!(engine.snapshot_into(&mut retained));
        let retained = retained.unwrap();
        assert!(
            state
                .restore_content_backend(engine.take_completed().unwrap())
                .is_ok()
        );
        let view = crate::native_sources::Resolver::new(&banks, &images, Some(&retained), bindings)
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
        state.fence();
        let source = Source::Downloaded(DownloadedSlot::B);
        state
            .prepare_source(&view, Change::Activate, DEADLINE)
            .unwrap();
        state.commit(&view, DEADLINE).unwrap();
        state.admit_source(&view, source, WHO).unwrap();
        assert_eq!(
            state.data_request(&view, WHO, DataRequest::Read, DEADLINE),
            Response::Value(1001)
        );
        assert_eq!(
            state.data_request(&view, WHO, DataRequest::SetValue(2077), DEADLINE),
            Response::Value(2077)
        );
        let old = state.note_request(
            &view,
            WHO,
            N::new(Operation::Read, 1).unwrap(),
            None,
            DEADLINE,
        );
        let note = ev_app_registry::note_data::NoteDataEnvelope::decode(&old.bytes.unwrap())
            .unwrap()
            .checked_replace(
                banks.app(),
                0,
                "downloaded B survives a clean update refusal",
            )
            .unwrap()
            .encode();
        assert_eq!(
            state
                .note_request(
                    &view,
                    WHO,
                    N::new(Operation::Write, 2).unwrap(),
                    Some(&note),
                    DEADLINE
                )
                .response
                .outcome(),
            Outcome::Written
        );
        state.fence();
        state.admit_source(&view, source, WHO).unwrap();
        if refusal == 1 {
            // Append/hash/readback/publish invalid acquisition syntax through
            // the real generic Arena, which provides bytes but no trust.
            let owner = state.take_content_backend(true).unwrap();
            let arena = Arena::open(owner, update::creation_manifest(), t.metadata(100).unwrap())
                .unwrap_or_else(|_| panic!());
            let head = arena.head_digest();
            let bad = [0; acq::CHECKPOINT_BYTES];
            let mut stage = arena
                .begin_owned(
                    head,
                    bad.len() as u64,
                    Sha256::digest(bad).into(),
                    t,
                    t.metadata(100).unwrap(),
                )
                .unwrap_or_else(|_| panic!());
            stage
                .write_chunk(&bad, t.child(100, 1024).unwrap())
                .unwrap();
            let head = stage.reserved_head();
            let mut read = stage
                .seal(t.child(100, 1024).unwrap())
                .unwrap_or_else(|_| panic!());
            let mut bytes = [1; acq::CHECKPOINT_BYTES];
            read.read_chunk(&mut bytes, t.child(100, 1024).unwrap())
                .unwrap();
            assert_eq!(bytes, bad);
            let verified = read.finish().unwrap_or_else(|_| panic!());
            let (arena, _) = verified
                .publish(head, t.metadata(100).unwrap())
                .unwrap_or_else(|_| panic!());
            assert!(state.restore_content_backend(arena.into_backend()).is_ok());
        }
        let before = media.borrow().durable.clone();
        let writes = media.borrow().writes.len();
        if refusal == 2 {
            media.borrow_mut().fail_next = true;
        }
        let mut attempt = update::Update::new();
        assert!(
            attempt
                .begin(
                    state.take_content_backend(true).unwrap(),
                    if refusal == 0 || refusal == 3 {
                        update::Command::Initialize
                    } else {
                        update::Command::Inspect
                    },
                    100
                )
                .is_ok()
        );
        // Immutable provenance remains resolvable while the sole Backend is
        // away. This grants no data access and no fresh repository authority.
        let unavailable =
            crate::native_sources::Resolver::new(&banks, &images, Some(&retained), bindings)
                .unwrap();
        assert_eq!(
            unavailable.checked_source(source).unwrap().id().bytes(),
            content.package
        );
        assert_eq!(
            state.data_request(&unavailable, WHO, DataRequest::Read, DEADLINE),
            Response::Refused(Refusal::Denied)
        );
        let expected = match refusal {
            0 => update::Outcome::Failed(update::Failure::NotBlank),
            1 => update::Outcome::Failed(update::Failure::Authentication),
            2 => update::Outcome::Failed(update::Failure::Storage),
            _ => update::Outcome::Cancelled,
        };
        if refusal == 3 {
            assert!(attempt.cancel());
            assert_eq!(attempt.outcome(), Some(expected));
        } else {
            assert_eq!(run(&mut attempt), expected);
        }
        // Neither failed nor cancelled engines expose current authenticated
        // ready state, even though prior immutable identity remains local.
        assert!(attempt.retained_snapshot().is_none());
        let mut current = None;
        assert!(!attempt.snapshot_into(&mut current));
        assert!(current.is_none());
        if refusal != 2 {
            let owner = if refusal == 3 {
                attempt.take_completed().unwrap()
            } else {
                attempt.release_settled_refusal().unwrap()
            };
            assert!(state.restore_content_backend(owner).is_ok());
            assert_eq!(attempt.outcome(), Some(expected));
            // The separately retained Snapshot serves LOCAL immutable identity
            // only. It cannot be reinjected into the failed remote coordinator.
            let local =
                crate::native_sources::Resolver::new(&banks, &images, Some(&retained), bindings)
                    .unwrap();
            assert_eq!(state.active_source(&local).unwrap(), Some(source));
            assert_eq!(
                state.data_request(&local, WHO, DataRequest::Read, DEADLINE),
                Response::Value(2077)
            );
            assert_eq!(
                state
                    .note_request(
                        &local,
                        WHO,
                        N::new(Operation::Read, 1).unwrap(),
                        None,
                        DEADLINE
                    )
                    .bytes,
                Some(note)
            );
            assert_eq!(media.borrow().writes.len(), writes);
            assert_eq!(media.borrow().durable, before);
        } else {
            assert!(attempt.release_settled_refusal().is_none());
            assert!(state.content_busy());
            let unavailable =
                crate::native_sources::Resolver::new(&banks, &images, Some(&retained), bindings)
                    .unwrap();
            assert_eq!(
                unavailable.checked_source(source).unwrap().id().bytes(),
                content.package
            );
            assert_eq!(
                state.data_request(&unavailable, WHO, DataRequest::Read, DEADLINE),
                Response::Refused(Refusal::Denied)
            );
            assert!(
                state
                    .note_request(
                        &unavailable,
                        WHO,
                        N::new(Operation::Read, 1).unwrap(),
                        None,
                        DEADLINE
                    )
                    .bytes
                    .is_none()
            );
            assert_eq!(media.borrow().writes.len(), writes);
            assert_eq!(media.borrow().durable, before);
        }
    }
}
