extern crate std;
use super::*;
use ev_content_store::{Area, Arena, Backend, Provisioner, Sector, TransferCut};
use ev_release_trust::verifier::{ReplayState, TrustedRoot};
use ev_store::{GenerationId, GenerationManifest, SectorIo};
use std::{vec, vec::Vec};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Io {
    Power,
    Bounds,
    Offline,
}
#[derive(Clone, Copy)]
enum Cut {
    Before,
    After,
    Torn,
}
#[derive(Clone)]
pub(crate) struct Disk {
    durable: Vec<Sector>,
    cache: Vec<Sector>,
    step: usize,
    fail: Option<(usize, Cut)>,
    offline: bool,
    trace: Vec<char>,
}
impl Disk {
    pub(crate) fn blank() -> Self {
        let mut b = vec![[0xa9; 512]; 8192];
        for s in &mut b[128..142] {
            s.fill(0)
        }
        for s in &mut b[256..] {
            s.fill(0)
        }
        Self {
            durable: b.clone(),
            cache: b,
            step: 0,
            fail: None,
            offline: false,
            trace: vec![],
        }
    }
    pub(crate) fn cold(mut self) -> Self {
        self.cache.clone_from(&self.durable);
        self.step = 0;
        self.fail = None;
        self.offline = false;
        self.trace.clear();
        self
    }
    fn boundary(&mut self, kind: char) -> Result<Option<Cut>, Io> {
        if self.offline {
            return Err(Io::Offline);
        }
        self.step += 1;
        self.trace.push(kind);
        Ok(self.fail.filter(|(n, _)| *n == self.step).map(|(_, c)| c))
    }
    fn lost(&mut self) -> Result<(), Io> {
        self.offline = true;
        Err(Io::Power)
    }
}
pub(crate) struct Device<'a> {
    d: &'a mut Disk,
    start: usize,
    len: u64,
}
impl SectorIo for Device<'_> {
    type Error = Io;
    fn sectors(&self) -> u64 {
        self.len
    }
    fn read(&mut self, lba: u64, out: &mut Sector, cut: u64) -> Result<(), Io> {
        assert!(cut > 0 && cut != u64::MAX);
        if lba >= self.len {
            return Err(Io::Bounds);
        }
        if self.d.boundary('r')?.is_some() {
            return self.d.lost();
        }
        *out = self.d.cache[self.start + lba as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, b: &Sector, cut: u64) -> Result<(), Io> {
        assert!(cut > 0 && cut != u64::MAX);
        if lba >= self.len {
            return Err(Io::Bounds);
        }
        let at = self.start + lba as usize;
        let fail = self.d.boundary('w')?;
        if matches!(fail, Some(Cut::Before)) {
            return self.d.lost();
        }
        self.d.cache[at] = *b;
        if let Some(c) = fail {
            match c {
                Cut::After => self.d.durable[at] = *b,
                Cut::Torn => self.d.durable[at][..257].copy_from_slice(&b[..257]),
                Cut::Before => unreachable!(),
            }
            return self.d.lost();
        }
        Ok(())
    }
    fn flush(&mut self, cut: u64) -> Result<(), Io> {
        assert!(cut > 0 && cut != u64::MAX);
        let fail = self.d.boundary('f')?;
        if matches!(fail, Some(Cut::Before)) {
            return self.d.lost();
        }
        if matches!(fail, Some(Cut::Torn)) {
            for i in (0..8192).step_by(2) {
                self.d.durable[i] = self.d.cache[i]
            }
            return self.d.lost();
        }
        self.d.durable.clone_from(&self.d.cache);
        if fail.is_some() {
            return self.d.lost();
        }
        Ok(())
    }
}
impl Backend for Disk {
    type Error = Io;
    type Device<'a> = Device<'a>;
    fn has_unresolved_io(&self) -> bool {
        // Each modeled operation completes synchronously. A lost response
        // permanently leaves this exact instance offline until a cold reboot.
        self.offline
    }
    fn device(&mut self, a: Area) -> Device<'_> {
        let (start, len) = match a {
            Area::Checkpoint => (128, 14),
            Area::Objects => (256, ev_content_store::OBJECT_SECTORS),
        };
        Device {
            d: self,
            start,
            len,
        }
    }
}
fn manifest() -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [1; 32],
        supervisor_image: [2; 32],
        abi: ev_content_store::FORMAT_ABI,
        health_contract: [3; 32],
        health_version: 1,
        required_checks: 3,
    }
}
pub(crate) fn transfer() -> TransferCut {
    TransferCut::new(1, 100_000).unwrap()
}
pub(crate) fn format() -> Store<Disk> {
    let t = transfer();
    let mut p =
        Provisioner::new(Disk::blank(), manifest(), t).unwrap_or_else(|_| panic!("provision"));
    while p.remaining() != 0 {
        p.scan(t.child(1, 1024).unwrap()).unwrap()
    }
    Store::from_arena(
        p.finish(t.metadata(1).unwrap())
            .unwrap_or_else(|_| panic!("format")),
    )
}
#[allow(clippy::result_large_err)] // Test drives the real affine production owner without boxing it.
fn put(store: Store<Disk>, bytes: &[u8]) -> Result<Stored<Disk>, Rejected<Disk>> {
    let mut p = store.begin_put(bytes.len() as u64, digest(bytes), transfer(), 1)?;
    for c in bytes.chunks(4096) {
        if let Err(error) = p.write_chunk(c, 1) {
            return Err(Rejected {
                owner: p.abandon(),
                error,
            });
        }
    }
    let mut r = p.seal(1)?;
    let mut b = [0; 4096];
    while r.remaining() != 0 {
        if let Err(error) = r.read_chunk(&mut b, 1) {
            return Err(Rejected {
                owner: r.abandon(),
                error,
            });
        }
    }
    r.finish()
}
fn snapshot(root: Object, revision: u64, floor: u64) -> Snapshot {
    // TEST-only prepared trusted decision for exercising the actual Store
    // commit protocol; these values never implement remote authorization.
    let trusted = TrustedRoot::provisioned(ROM_ROOT, binding()).unwrap();
    let initial = ReplayState::initial(&trusted);
    let replay =
        ReplayState::restored(&trusted, *initial.roles(), *initial.targets(), floor).unwrap();
    let mut checkpoint = [0; 1024];
    ev_release_trust::checkpoint::encode(&replay, &mut checkpoint);
    let mut roots = [None; MAX_ROOT_MATERIALS];
    roots[0] = Some(root);
    Snapshot {
        replay,
        record: codec::Record {
            revision,
            replay: checkpoint,
            roots,
            metadata: [None; 3],
            candidate: None,
            active: None,
            known_good: None,
            authorizations: [None; 3],
        },
    }
}
#[allow(clippy::result_large_err)] // Test preserves the same actual backend on every rejected commit.
fn publish(store: Store<Disk>, next: Snapshot) -> Result<Store<Disk>, Rejected<Disk>> {
    let mut b = [0; CHECKPOINT_BYTES];
    next.record.encode(&mut b).unwrap();
    let mut p = store.begin_put(b.len() as u64, digest(&b), transfer(), 1)?;
    if let Err(error) = p.write_chunk(&b, 1) {
        return Err(Rejected {
            owner: p.abandon(),
            error,
        });
    }
    let mut r = p.seal(1)?;
    while r.remaining() != 0 {
        if let Err(error) = r.read_chunk(&mut b, 1) {
            return Err(Rejected {
                owner: r.abandon(),
                error,
            });
        }
    }
    Publication { read: r, next }.publish(1, &mut b)
}
fn cold(disk: Disk) -> (Store<Disk>, u64) {
    let arena = Arena::open(disk.cold(), manifest(), transfer().metadata(1).unwrap())
        .unwrap_or_else(|_| panic!("cold metadata"));
    let object = arena.published_metadata().unwrap();
    let mut read = Store::from_arena(arena)
        .begin_read(object, transfer(), 1)
        .unwrap_or_else(|_| panic!("cold reader"));
    let mut b = [0; 4096];
    assert_eq!(
        read.read_chunk(&mut b, 1).unwrap_or_else(|_| panic!()),
        4096
    );
    let result = read.finish().unwrap_or_else(|_| panic!("cold hash"));
    let record = codec::Record::decode(&b).unwrap();
    let root = TrustedRoot::provisioned(ROM_ROOT, binding()).unwrap();
    let replay = ev_release_trust::checkpoint::decode(&root, &record.replay).unwrap();
    (result.store, replay.utc_floor())
}

#[test]
fn streamed_actual_objects_and_one_checkpoint_commit_survive_every_storage_interruption() {
    let root = put(format(), ROM_ROOT).unwrap_or_else(|_| panic!("root"));
    let rootref = root.object;
    let old =
        publish(root.store, snapshot(rootref, 1, 0)).unwrap_or_else(|_| panic!("initial decision"));
    let initial = old.into_arena().into_backend().cold();
    let a = Arena::open(initial.clone(), manifest(), transfer().metadata(1).unwrap())
        .unwrap_or_else(|_| panic!());
    let start = a.into_backend().step;
    let full = publish(
        Store::from_arena(
            Arena::open(initial.clone(), manifest(), transfer().metadata(1).unwrap())
                .unwrap_or_else(|_| panic!()),
        ),
        snapshot(rootref, 2, 10),
    )
    .unwrap_or_else(|_| panic!("next decision"));
    let end = full.into_arena().into_backend().step;
    for step in start + 1..=end {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let mut d = initial.clone();
            d.fail = Some((step, cut));
            let arena = Arena::open(d, manifest(), transfer().metadata(1).unwrap())
                .unwrap_or_else(|_| panic!("pre-cut open"));
            let result = publish(Store::from_arena(arena), snapshot(rootref, 2, 10));
            let d = match result {
                Ok(s) => s.into_arena().into_backend(),
                Err(r) => r.owner.into_arena().into_backend(),
            };
            let (opened, floor) = cold(d);
            assert!(floor == 0 || floor == 10);
            let d = opened.into_arena().into_backend();
            assert!(
                d.durable[..128]
                    .iter()
                    .chain(d.durable[142..256].iter())
                    .all(|s| *s == [0xa9; 512])
            );
        }
    }
}

#[test]
fn unknown_write_keeps_same_poisoned_owner_and_no_retry_or_published_ref() {
    let mut d = format().into_arena().into_backend().cold();
    let a = Arena::open(d.clone(), manifest(), transfer().metadata(1).unwrap())
        .unwrap_or_else(|_| panic!());
    let start = a.into_backend().step;
    let baseline = put(
        Store::from_arena(
            Arena::open(d.clone(), manifest(), transfer().metadata(1).unwrap())
                .unwrap_or_else(|_| panic!()),
        ),
        &[7; 8192],
    )
    .unwrap_or_else(|_| panic!());
    let trace = baseline.store.into_arena().into_backend().trace;
    let write = trace
        .iter()
        .enumerate()
        .find(|(i, c)| *i >= start && **c == 'w')
        .unwrap()
        .0
        + 1;
    d.fail = Some((write, Cut::After));
    let arena =
        Arena::open(d, manifest(), transfer().metadata(1).unwrap()).unwrap_or_else(|_| panic!());
    let r = put(Store::from_arena(arena), &[7; 8192]).err().unwrap();
    assert!(r.owner.poisoned());
    assert!(r.owner.arena.published_metadata().is_none());
    let before = r.owner.arena.reserved_sectors();
    let r = r
        .owner
        .begin_put(512, [8; 32], transfer(), 1)
        .err()
        .unwrap();
    assert_eq!(r.owner.arena.reserved_sectors(), before);
}

#[test]
fn checkpoint_codec_binds_fields_and_publication_refuses_a_mixed_snapshot() {
    let root = put(format(), ROM_ROOT).unwrap_or_else(|_| panic!());
    let object = root.object;
    let a = snapshot(object, 1, 0);
    let mut bytes = [0; 4096];
    a.record.encode(&mut bytes).unwrap();
    assert_eq!(codec::Record::decode(&bytes).unwrap().revision, 1);
    for at in [8, 9, 10, 11, 12, 24, 2296, 4095] {
        let mut corrupt = bytes;
        corrupt[at] ^= 0x80;
        assert!(codec::Record::decode(&corrupt).is_err());
    }
    let mut p = root
        .store
        .begin_put(4096, digest(&bytes), transfer(), 1)
        .unwrap_or_else(|_| panic!());
    p.write_chunk(&bytes, 1).unwrap_or_else(|_| panic!());
    let mut read = p.seal(1).unwrap_or_else(|_| panic!());
    read.read_chunk(&mut bytes, 1).unwrap_or_else(|_| panic!());
    let r = Publication {
        read,
        next: snapshot(object, 2, 10),
    }
    .publish(1, &mut bytes)
    .err()
    .unwrap();
    assert!(r.owner.arena.published_metadata().is_none());
}

const B_TARGETS: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/targets.bin");
const B_SNAPSHOT: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/snapshot.bin");
const B_TIMESTAMP: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/timestamp.bin");
const B_PACKAGE: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/hello.zion");
const C_TARGETS: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/targets.bin");
const C_SNAPSHOT: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/snapshot.bin");
const C_TIMESTAMP: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/timestamp.bin");
const C_PACKAGE: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/hello.zion");
fn accepted(prior: &ReplayState, targets: &[u8], snapshot: &[u8], timestamp: &[u8]) -> ReplayState {
    use ev_release_trust::{metadata, signature::Envelope, verifier};
    use ev_time_contract::{
        Domain,
        freshness::{QualifiedWindow, Time, UtcInterval},
    };
    let root = TrustedRoot::provisioned(ROM_ROOT, binding()).unwrap();
    let e = Envelope::parse(targets).unwrap();
    let at = metadata::Targets::parse(&e).unwrap().common().not_before;
    let d = Domain::new(77).unwrap();
    // Explicit TEST provider, not a runtime qualification implementation.
    let time = Time::Qualified(
        QualifiedWindow::new(d.at(1), d.at(2), UtcInterval::new(at + 1, at + 2).unwrap()).unwrap(),
    );
    *verifier::verify_bundle(
        &root,
        prior,
        verifier::Bundle {
            targets,
            snapshot,
            timestamp,
        },
        time,
        d.at(1),
        verifier::Policy::new(8, 262144).unwrap(),
    )
    .unwrap()
    .proposed()
}
fn materials(mut store: Store<Disk>, bytes: [&[u8]; 3]) -> (Store<Disk>, [Option<Object>; 3]) {
    let mut refs = [None; 3];
    for (i, b) in bytes.into_iter().enumerate() {
        let r = put(store, b).unwrap_or_else(|_| panic!("metadata object"));
        store = r.store;
        refs[i] = Some(r.object)
    }
    (store, refs)
}
fn descriptor(targets: &[u8], object: Object) -> Content {
    use ev_release_trust::{metadata, signature::Envelope};
    let e = Envelope::parse(targets).unwrap();
    let target = metadata::Targets::parse(&e)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .spec();
    Content {
        object,
        version: target.version,
        app: HELLO_APP,
        package: target.sha256,
        build: target.build,
        descriptor: target.contract,
        source: target.source_revision,
    }
}
fn authenticated(mut store: Store<Disk>) -> Store<Disk> {
    let mut cold = store
        .begin_cold(transfer(), 1)
        .unwrap_or_else(|_| panic!("begin authenticated reopen"));
    let mut buffers = Buffers::empty();
    loop {
        if cold
            .step(&mut buffers, 1)
            .unwrap_or_else(|_| panic!("authenticated step"))
        {
            break;
        }
    }
    store = cold
        .finish()
        .unwrap_or_else(|_| panic!("authenticated finish"));
    store
}

#[test]
fn actual_signed_cold_reopen_preserves_floors_and_prior_local_content_without_network_or_utc() {
    let stored_root = put(format(), ROM_ROOT).unwrap_or_else(|_| panic!());
    let rootref = stored_root.object;
    let prior = ReplayState::initial(&TrustedRoot::provisioned(ROM_ROOT, binding()).unwrap());
    let (store, b_refs) = materials(stored_root.store, [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]);
    let b = put(store, B_PACKAGE).unwrap_or_else(|_| panic!());
    let local = descriptor(B_TARGETS, b.object);
    let replay_b = accepted(&prior, B_TARGETS, B_SNAPSHOT, B_TIMESTAMP);
    // TEST prior authorization for a target absent from the current signed
    // bundle. Remote withdrawal must not erase this retained rollback floor.
    let withdrawn = ev_release_trust::verifier::TargetFloor {
        name: [0x71; 32],
        version: 7,
        identity: [0x72; 32],
    };
    let mut floors = *replay_b.targets();
    floors[1] = Some(withdrawn);
    let root = TrustedRoot::provisioned(ROM_ROOT, binding()).unwrap();
    let replay_b =
        ReplayState::restored(&root, *replay_b.roles(), floors, replay_b.utc_floor()).unwrap();
    let mut first = snapshot(rootref, 1, 0);
    first.record.metadata = b_refs;
    first.record.candidate = Some(local);
    first.record.active = Some(local);
    first.record.known_good = Some(local);
    first.record.authorizations = [Some(Authorization {
        root: rootref,
        targets: b_refs[0].unwrap(),
    }); 3];
    // TEST fixture of previously independently authorized local lifecycle
    // references. Signatures/storage do not construct that health authority.
    first.replay = replay_b;
    ev_release_trust::checkpoint::encode(&replay_b, &mut first.record.replay);
    let first = publish(b.store, first).unwrap_or_else(|_| panic!());
    let first = authenticated(Store::from_arena(
        Arena::open(
            first.into_arena().into_backend().cold(),
            manifest(),
            transfer().metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!()),
    ));
    assert_eq!(first.snapshot().unwrap().known_good(), Some(local));
    let (store, c_refs) = materials(first, [C_TARGETS, C_SNAPSHOT, C_TIMESTAMP]);
    let c = put(store, C_PACKAGE).unwrap_or_else(|_| panic!());
    let candidate = descriptor(C_TARGETS, c.object);
    let replay_c = accepted(&replay_b, C_TARGETS, C_SNAPSHOT, C_TIMESTAMP);
    let mut next = snapshot(rootref, 2, 0);
    next.record.metadata = c_refs;
    next.record.candidate = Some(candidate);
    next.record.active = Some(local);
    next.record.known_good = Some(local);
    next.record.authorizations = [
        Some(Authorization {
            root: rootref,
            targets: c_refs[0].unwrap(),
        }),
        Some(Authorization {
            root: rootref,
            targets: b_refs[0].unwrap(),
        }),
        Some(Authorization {
            root: rootref,
            targets: b_refs[0].unwrap(),
        }),
    ];
    next.replay = replay_c;
    ev_release_trust::checkpoint::encode(&replay_c, &mut next.record.replay);
    let next = publish(c.store, next).unwrap_or_else(|_| panic!());
    let next = authenticated(Store::from_arena(
        Arena::open(
            next.into_arena().into_backend().cold(),
            manifest(),
            transfer().metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!()),
    ));
    let state = next.snapshot().unwrap();
    assert_eq!(*state.replay(), replay_c);
    assert_eq!(state.known_good(), Some(local));
    assert_eq!(state.active(), Some(local));
    assert_eq!(state.candidate(), Some(candidate));
    assert_eq!(state.replay().targets()[1], Some(withdrawn));
    assert_eq!(
        state
            .replay()
            .targets()
            .iter()
            .flatten()
            .next()
            .unwrap()
            .version,
        3
    );
}

#[test]
fn corrupt_or_unpublished_cold_state_never_initializes_trust_or_formats() {
    let empty = format();
    let error = empty.begin_cold(transfer(), 1).err().unwrap();
    assert!(matches!(error.error, Failure::Policy(Fault::Unprovisioned)));
    assert!(error.owner.snapshot().is_none());
    let r = put(error.owner, ROM_ROOT).unwrap_or_else(|_| panic!());
    let object = r.object;
    let store = publish(r.store, snapshot(object, 1, 0)).unwrap_or_else(|_| panic!());
    let mut disk = store.into_arena().into_backend().cold();
    disk.durable[(256 + object.start() + 1) as usize][19] ^= 1;
    disk = disk.cold();
    let arena =
        Arena::open(disk, manifest(), transfer().metadata(1).unwrap()).unwrap_or_else(|_| panic!());
    let before = arena.published_metadata();
    let mut cold = Store::from_arena(arena)
        .begin_cold(transfer(), 1)
        .unwrap_or_else(|_| panic!());
    let mut b = Buffers::empty();
    loop {
        match cold.step(&mut b, 1) {
            Ok(false) => (),
            Ok(true) => panic!("corrupt Root trusted"),
            Err(_) => break,
        }
    }
    let rejected = cold.finish().err().unwrap();
    assert!(rejected.owner.snapshot().is_none());
    assert_eq!(rejected.owner.arena.published_metadata(), before);
    assert!(rejected.owner.poisoned());
}

fn persist(mut c: Commit<Disk>) -> Store<Disk> {
    let mut b = Buffers::empty();
    for _ in 0..256 {
        if c.step(&mut b, 1).unwrap_or_else(|_| panic!("commit step")) {
            return c
                .publication()
                .unwrap_or_else(|_| panic!("prepared publication"))
                .publish(1, &mut b.checkpoint)
                .unwrap_or_else(|_| panic!("publish decision"));
        }
    }
    panic!("bounded commit did not complete")
}
fn initial() -> Store<Disk> {
    let root = put(format(), ROM_ROOT).unwrap_or_else(|_| panic!());
    persist(
        root.store
            .provision(root.object, transfer(), 1)
            .unwrap_or_else(|_| panic!("explicit owner provision")),
    )
}
#[test]
fn clock_binding_requires_actual_authenticated_store_and_tracks_head_not_local_cache() {
    assert!(format().authorization_binding().is_none());
    let mut store = initial();
    let binding = store.authorization_binding().unwrap();
    assert_eq!(
        binding.utc_floor(),
        store.snapshot().unwrap().replay().utc_floor()
    );
    let detached = store.take_snapshot().unwrap();
    assert!(store.authorization_binding().is_none());
    assert_eq!(detached.replay().utc_floor(), binding.utc_floor());

    let store = initial();
    let prior = store.authorization_binding().unwrap();
    let pending = store
        .begin_put(512, [7; 32], transfer(), 1)
        .unwrap_or_else(|_| panic!("reserve"));
    let mut store = pending.abandon();
    assert_ne!(store.authorization_binding(), Some(prior));
    assert_eq!(
        store.authorization_binding().unwrap().utc_floor(),
        prior.utc_floor()
    );
    store.fenced = true;
    assert!(store.authorization_binding().is_none());
    for withdrawn in [false, true] {
        let store = retained_store(initial(), withdrawn);
        let floor = store.snapshot().unwrap().replay().utc_floor();
        assert!(floor > 0);
        assert_eq!(store.authorization_binding().unwrap().utc_floor(), floor);
    }
}
pub(crate) struct TestClock {
    calls: u8,
    mode: u8,
    author: u64,
}
impl TestClock {
    pub(crate) fn new(mode: u8) -> Self {
        let e = ev_release_trust::signature::Envelope::parse(B_TARGETS).unwrap();
        let author = ev_release_trust::metadata::Targets::parse(&e)
            .unwrap()
            .common()
            .not_before;
        Self {
            calls: 0,
            mode,
            author,
        }
    }
}
impl QualifiedClock for TestClock {
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
        if self.mode == 1 || self.mode == 2 && self.calls == 2 {
            return Err(());
        }
        let d = Domain::new(77).unwrap();
        let tick = if self.mode == 3 && self.calls == 2 {
            0
        } else {
            u64::from(self.calls)
        };
        let earliest = if self.mode == 4 && self.calls == 1 {
            self.author + 2
        } else {
            self.author + 1
        };
        Ok((
            QualifiedWindow::new(
                d.at(1),
                d.at(3),
                UtcInterval::new(earliest, self.author + 2).unwrap(),
            )
            .unwrap(),
            d.at(tick),
        ))
    }
}
fn remote<'a>(refs: [Option<Object>; 3], candidate: Object, c: bool) -> Remote<'a> {
    let bytes = if c {
        [C_TARGETS, C_SNAPSHOT, C_TIMESTAMP]
    } else {
        [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]
    };
    Remote {
        current_root: ROM_ROOT,
        root_updates: &[],
        metadata: core::array::from_fn(|i| Material {
            object: refs[i].unwrap(),
            bytes: bytes[i],
        }),
        candidate: Material {
            object: candidate,
            bytes: if c { C_PACKAGE } else { B_PACKAGE },
        },
    }
}

#[test]
fn real_signed_decisions_require_post_crypto_time_and_only_publish_remote_candidate() {
    let store = initial();
    let state = store.snapshot().unwrap();
    assert_eq!(state.replay().utc_floor(), 0);
    assert!(
        state.active().is_none() && state.known_good().is_none() && state.candidate().is_none()
    );
    let (store, refs) = materials(store, [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]);
    let b = put(store, B_PACKAGE).unwrap_or_else(|_| panic!());
    let before = b.store.arena.published_metadata();
    for mode in 1..=4 {
        let mut clock = TestClock::new(mode);
        assert!(
            b.store
                .authorize(remote(refs, b.object, false), &mut clock)
                .is_err()
        );
        assert_eq!(b.store.arena.published_metadata(), before);
        assert_eq!(b.store.snapshot().unwrap().replay().utc_floor(), 0);
    }
    let mut clock = TestClock::new(0);
    let decision = b
        .store
        .authorize(remote(refs, b.object, false), &mut clock)
        .unwrap();
    assert_eq!(clock.calls, 2);
    assert_eq!(
        decision.candidate().descriptor,
        [
            0xe9, 0x2b, 0x03, 0x6c, 0x8c, 0x62, 0x67, 0xc5, 0xf7, 0xeb, 0x33, 0xe6, 0x52, 0x38,
            0xc4, 0x2a, 0xed, 0x16, 0x6c, 0xf4, 0x68, 0xd3, 0xff, 0x77, 0xdb, 0x32, 0x0a, 0xff,
            0xb7, 0xc0, 0x83, 0xf5
        ]
    );
    let store = persist(
        decision
            .begin(b.store, transfer(), 1)
            .unwrap_or_else(|_| panic!()),
    );
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.candidate().unwrap().version, 2);
    assert!(snapshot.active().is_none() && snapshot.known_good().is_none());
    let (store, refs) = materials(store, [C_TARGETS, C_SNAPSHOT, C_TIMESTAMP]);
    let c = put(store, C_PACKAGE).unwrap_or_else(|_| panic!());
    let decision = c
        .store
        .authorize(remote(refs, c.object, true), &mut TestClock::new(0))
        .unwrap();
    let expected = *decision.proposed();
    let store = persist(
        decision
            .begin(c.store, transfer(), 1)
            .unwrap_or_else(|_| panic!()),
    );
    assert_eq!(*store.snapshot().unwrap().replay(), expected);
    let store = authenticated(Store::from_arena(
        Arena::open(
            store.into_arena().into_backend().cold(),
            manifest(),
            transfer().metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!()),
    ));
    let state = store.snapshot().unwrap();
    assert_eq!(state.candidate().unwrap().version, 3);
    assert!(state.active().is_none() && state.known_good().is_none());
    assert_eq!(*state.replay(), expected);
}

#[test]
fn a_decision_cannot_be_rebound_to_changed_head_or_mixed_material() {
    let (store, refs) = materials(initial(), [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]);
    let b = put(store, B_PACKAGE).unwrap_or_else(|_| panic!());
    let mut wrong = remote(refs, b.object, false);
    wrong.metadata[0].bytes = C_TARGETS;
    assert!(b.store.authorize(wrong, &mut TestClock::new(0)).is_err());
    let decision = b
        .store
        .authorize(remote(refs, b.object, false), &mut TestClock::new(0))
        .unwrap();
    let old = b.store.arena.published_metadata();
    let changed = put(b.store, b"unrelated appended reservation").unwrap_or_else(|_| panic!());
    let refused = decision.begin(changed.store, transfer(), 1).err().unwrap();
    assert_eq!(refused.owner.arena.published_metadata(), old);
    assert_eq!(refused.owner.snapshot().unwrap().revision(), 1);
}

/// TEST-only retained state from actual signed fixtures and real Arena/Store
/// publication. Local B Active/KnownGood is a synthetic prior lifecycle carrier;
/// this helper and its callers claim no actual process or health execution.
pub(crate) fn retained_snapshot(c: bool) -> Snapshot {
    retained_store(initial(), c).state.take().unwrap()
}
pub(crate) fn candidate_only_snapshot(c: bool) -> Snapshot {
    let mut snapshot = retained_snapshot(c);
    snapshot.record.active = None;
    snapshot.record.known_good = None;
    snapshot
}
#[test]
fn metadata_preparation_checks_signatures_replay_and_post_crypto_time_without_publishing() {
    let store = initial();
    let before = store.authorization_binding();
    let reserved = store.arena.reserved_sectors();
    let bundle = || ev_release_trust::verifier::Bundle {
        targets: B_TARGETS,
        snapshot: B_SNAPSHOT,
        timestamp: B_TIMESTAMP,
    };
    let mut clock = TestClock::new(0);
    let prepared = store
        .prepare_metadata(ROM_ROOT, bundle(), &mut clock)
        .unwrap();
    assert_eq!(clock.calls, 2);
    assert_eq!(prepared.target().name, logical_target_name());
    assert_eq!(prepared.target().sha256, digest(B_PACKAGE));
    assert_eq!(prepared.prior(), before.unwrap());
    assert_eq!(prepared.metadata(0).unwrap().sha256, digest(B_TARGETS));
    assert_eq!(store.authorization_binding(), before);
    assert_eq!(store.arena.reserved_sectors(), reserved);
    assert!(store.snapshot().unwrap().candidate().is_none());
    for mode in [1, 2, 3, 4] {
        assert!(
            store
                .prepare_metadata(ROM_ROOT, bundle(), &mut TestClock::new(mode))
                .is_err(),
            "mode{mode}"
        );
        assert_eq!(store.authorization_binding(), before);
    }
    let mut corrupt = B_TIMESTAMP.to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(
        store
            .prepare_metadata(
                ROM_ROOT,
                ev_release_trust::verifier::Bundle {
                    timestamp: &corrupt,
                    ..bundle()
                },
                &mut TestClock::new(0)
            )
            .is_err()
    );
    assert!(
        store
            .prepare_metadata(
                ROM_ROOT,
                ev_release_trust::verifier::Bundle {
                    targets: C_TARGETS,
                    ..bundle()
                },
                &mut TestClock::new(0)
            )
            .is_err()
    );
    let mut wrong_root = ROM_ROOT.to_vec();
    wrong_root[0] ^= 1;
    assert!(
        store
            .prepare_metadata(&wrong_root, bundle(), &mut TestClock::new(0))
            .is_err()
    );
    assert_eq!(store.authorization_binding(), before);
    assert_eq!(store.arena.reserved_sectors(), reserved);
    let after_c = retained_store(initial(), true);
    assert!(
        after_c
            .prepare_metadata(ROM_ROOT, bundle(), &mut TestClock::new(0))
            .is_err()
    );
    assert_eq!(after_c.snapshot().unwrap().candidate().unwrap().version, 3);
}
/// Same real signed material over the caller's actual initialized Arena. TEST
/// only: permits controller composition under the production creation identity.
pub(crate) fn retained_store(store: Store<Disk>, c: bool) -> Store<Disk> {
    let (store, refs) = materials(store, [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]);
    let b = put(store, B_PACKAGE).unwrap_or_else(|_| panic!("fixture B object"));
    let decision = b
        .store
        .authorize(remote(refs, b.object, false), &mut TestClock::new(0))
        .unwrap();
    let mut store = persist(
        decision
            .begin(b.store, transfer(), 1)
            .unwrap_or_else(|_| panic!("fixture B decision")),
    );
    if c {
        let prior = store.state.as_mut().unwrap();
        let b = prior.candidate().unwrap();
        prior.record.active = Some(b);
        prior.record.known_good = Some(b);
        prior.record.authorizations[1] = prior.record.authorizations[0];
        prior.record.authorizations[2] = prior.record.authorizations[0];
        let (next, refs) = materials(store, [C_TARGETS, C_SNAPSHOT, C_TIMESTAMP]);
        let c = put(next, C_PACKAGE).unwrap_or_else(|_| panic!("fixture C object"));
        let decision = c
            .store
            .authorize(remote(refs, c.object, true), &mut TestClock::new(0))
            .unwrap();
        store = persist(
            decision
                .begin(c.store, transfer(), 1)
                .unwrap_or_else(|_| panic!("fixture C decision")),
        );
    }
    store
}

/// TEST-only image-loader precondition, not release authentication evidence.
/// The Arena object is real and fully read back; only the already-admitted
/// in-memory snapshot is substituted to exercise later structural fences.
pub(crate) fn image_loader_candidate(
    store: Store<Disk>,
    bytes: &[u8],
    required: bool,
    required_good: bool,
    wrong_descriptor: bool,
) -> Store<Disk> {
    use sha2::{Digest, Sha256};
    let stored = put(store, bytes).unwrap_or_else(|_| panic!("image-loader object"));
    let mut store = stored.store;
    let snapshot = store.state.as_mut().unwrap();
    let mut candidate = snapshot.candidate().unwrap();
    candidate.object = stored.object;
    candidate.package = stored.object.sha256();
    // The first entry digest remains available even for a deliberately bad
    // outer magic or ELF. This helper must not parse away the negative case.
    let table = 96 + u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    let elf: [u8; 32] = bytes[table + 16..table + 48].try_into().unwrap();
    let mut descriptor = Sha256::new();
    ev_userspace_contract::root_v4::dynamic::app_descriptor_transcript(&elf, |b| {
        descriptor.update(b)
    });
    candidate.descriptor = descriptor.finalize().into();
    if wrong_descriptor {
        candidate.descriptor[0] ^= 1;
    }
    snapshot.record.candidate = Some(candidate);
    if required {
        snapshot.record.active = Some(candidate);
    }
    if required_good {
        snapshot.record.known_good = Some(candidate);
    }
    store
}

/// Corrupt an already-admitted model object's later sector, or lose its next
/// actual read response. Neither is a clean package-compatibility refusal.
pub(crate) fn damage_image_loader_candidate(store: Store<Disk>, lost_io: bool) -> Store<Disk> {
    let object = store.state.as_ref().unwrap().candidate().unwrap().object;
    let Store {
        arena,
        state,
        last,
        fenced,
    } = store;
    let mut disk = arena.into_backend();
    let open = |disk| {
        Arena::open(
            disk,
            crate::native_update::creation_manifest(),
            transfer().metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!("restore model Arena"))
    };
    if lost_io {
        let first_read = open(disk.clone()).backend().step + 1;
        disk.fail = Some((first_read, Cut::Before));
    } else {
        let sector = 256 + object.start() as usize + object.sectors() as usize - 1;
        disk.cache[sector][0] ^= 1;
    }
    Store {
        arena: open(disk),
        state,
        last,
        fenced,
    }
}

#[test]
fn resident_authorization_matches_consuming_path_and_rejects_occupied_or_stale_output() {
    let (store, refs) = materials(initial(), [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]);
    let stored = put(store, B_PACKAGE).unwrap_or_else(|_| panic!("candidate"));
    let mut store = stored.store;
    let candidate = stored.object;
    let mut workspace = Commit::empty();
    for mode in [1, 2, 3, 4] {
        assert!(
            store
                .authorize_into(
                    remote(refs, candidate, false),
                    &mut TestClock::new(mode),
                    &mut workspace
                )
                .is_err()
        );
        assert!(workspace.is_empty());
        assert!(!workspace.has_authorized());
    }
    let expected = store
        .authorize(remote(refs, candidate, false), &mut TestClock::new(0))
        .unwrap();
    store
        .authorize_into(
            remote(refs, candidate, false),
            &mut TestClock::new(0),
            &mut workspace,
        )
        .unwrap();
    assert!(workspace.has_authorized());
    let mut clock = TestClock::new(0);
    assert_eq!(
        store.authorize_into(remote(refs, candidate, false), &mut clock, &mut workspace),
        Err(Fault::Phase)
    );
    assert_eq!(clock.calls, 0);
    // An appended reservation changes the actual head even without publication.
    store = put(store, b"new unrelated reservation")
        .unwrap_or_else(|_| panic!("append"))
        .store;
    let rejected = workspace
        .begin_authorized(store, transfer(), 1)
        .err()
        .unwrap();
    store = rejected.owner;
    assert!(workspace.has_authorized());
    assert!(workspace.abandon_in_place().is_none()); // Prepared output owns no Backend.
    assert!(workspace.is_empty());
    store
        .authorize_into(
            remote(refs, candidate, false),
            &mut TestClock::new(0),
            &mut workspace,
        )
        .unwrap();
    workspace
        .begin_authorized(store, transfer(), 1)
        .unwrap_or_else(|_| panic!("bound owner"));
    let committed = persist(workspace);
    assert_eq!(committed.snapshot().unwrap().replay(), expected.proposed());
    assert_eq!(
        committed.snapshot().unwrap().candidate(),
        Some(expected.candidate())
    );
    assert!(committed.snapshot().unwrap().active().is_none());
    assert!(committed.snapshot().unwrap().known_good().is_none());
}

#[test]
fn fresh_resident_authorization_reuses_only_the_settled_abandoned_workspace() {
    let (store, refs) = materials(initial(), [B_TARGETS, B_SNAPSHOT, B_TIMESTAMP]);
    let stored = put(store, B_PACKAGE).unwrap_or_else(|_| panic!("candidate"));
    let candidate = stored.object;
    let mut workspace = Commit::empty();
    stored
        .store
        .authorize_into(
            remote(refs, candidate, false),
            &mut TestClock::new(0),
            &mut workspace,
        )
        .unwrap();
    workspace
        .begin_authorized(stored.store, transfer(), 1)
        .unwrap_or_else(|_| panic!("begin"));
    let mut buffers = Buffers::empty();
    let mut failed = false;
    for _ in 0..1024 {
        match workspace.step(&mut buffers, 1) {
            Ok(false) => buffers.targets.fill(0), // Corrupt only caller-private read buffer before deferred auth.
            Err(_) => {
                failed = true;
                break;
            }
            Ok(true) => panic!("corrupt metadata buffer accepted"),
        }
    }
    assert!(failed);
    let store = workspace.abandon_in_place().unwrap();
    assert!(!store.has_unresolved_io());
    assert!(workspace.is_empty());
    // Explicit new authorization rereads original immutable material, not a
    // reset of an accepted write or of the actual Arena/Backend's fences.
    store
        .authorize_into(
            remote(refs, candidate, false),
            &mut TestClock::new(0),
            &mut workspace,
        )
        .unwrap();
    assert!(workspace.has_authorized());
    workspace
        .begin_authorized(store, transfer(), 1)
        .unwrap_or_else(|_| panic!("reuse"));
    assert!(persist(workspace).snapshot().unwrap().candidate().is_some());
}

#[test]
fn resealed_unsigned_retained_b_is_rejected_even_when_current_c_signatures_are_valid() {
    use ev_zion::{
        Capability, CapabilityRequest, Contract, DataSchema, Platform, Version, producer::Spec,
    };
    let legitimate = ev_zion::Package::parse(B_PACKAGE).unwrap();
    let bad = ev_zion::Package::parse(C_PACKAGE).unwrap();
    let source = [0x81; 32];
    let mut source_text = std::string::String::from("Evrosion DEV B ");
    for b in source {
        use core::fmt::Write;
        write!(source_text, "{b:02x}").unwrap();
    }
    let names = [
        "ev.app.private-data",
        "ev.app.session-note",
        "ev.internal.file",
        "ev.internal.focused-input",
        "ev.internal.surface-present",
    ];
    let contracts = names.map(|name| Contract {
        name,
        major: 1,
        minimum_minor: 0,
        features: 0,
    });
    let caps = [
        Capability::SelectedFileRead,
        Capability::AppPrivateData,
        Capability::OwnSurfacePresent,
        Capability::FocusedInput,
        Capability::Diagnostics,
    ];
    let capabilities = core::array::from_fn::<_, 5, _>(|i| CapabilityRequest {
        capability: caps[i],
        required: i != 0,
    });
    let build = [0x82; 32];
    let forged = ev_zion::producer::build(
        &Spec {
            app: legitimate.app().claimed_app,
            name: "unsigned resealed retained B",
            source: &source_text,
            publisher: None,
            version: Version {
                major: 0,
                minor: 2,
                patch: 1,
            },
            build_id: build,
            platform: Platform {
                minimum: 1,
                target: 1,
            },
            abi: ev_userspace_contract::ABI,
            data_schema: DataSchema {
                current: 1,
                oldest_readable: 1,
            },
            entrypoint: "bin/main.elf",
            contracts: &contracts,
            capabilities: &capabilities,
        },
        bad.executable().bytes,
        &[],
    )
    .unwrap();
    let ready = retained_store(initial(), true);
    let stored = put(ready, &forged).unwrap_or_else(|_| panic!("forged immutable body"));
    let mut store = stored.store;
    let mut next = store.state.take().unwrap();
    let mut fake = next.active().unwrap();
    fake.object = stored.object;
    fake.package = digest(&forged);
    fake.source = source;
    fake.build = build;
    let mut d = Sha256::new();
    ev_userspace_contract::root_v4::dynamic::app_descriptor_transcript(
        &bad.executable().digest,
        |b| d.update(b),
    );
    fake.descriptor = d.finalize().into();
    next.record.active = Some(fake);
    next.record.known_good = Some(fake);
    // TEST attacker reseals journal/checkpoint checksums, leaving real C signatures
    // and all durable replay floors intact. No production constructor is used.
    let store = publish(store, next).unwrap_or_else(|_| panic!("resealed checkpoint"));
    let arena = Arena::open(
        store.into_arena().into_backend().cold(),
        manifest(),
        transfer().metadata(1).unwrap(),
    )
    .unwrap_or_else(|_| panic!());
    let (owner, error) = reject_cold(Store::from_arena(arena));
    assert_eq!(error, Fault::Metadata);
    assert!(owner.snapshot().is_none());
    // Even well-formed/sealable bytes cannot reach an authenticated Snapshot,
    // local Member, Registry admission or health from this forged checkpoint.
}

/// TEST-only attacker writes a complete hash-consistent object and journal
/// pointer without invoking the trusted acquisition authorization constructors.
/// A raw Store checksum is deliberately not accepted publisher evidence.
fn publish_untrusted_checkpoint(store: Store<Disk>, bytes: &[u8; CHECKPOINT_BYTES]) -> Store<Disk> {
    let t = transfer();
    let arena = store.into_arena();
    let head = arena.head_digest();
    let mut stage = arena
        .begin_owned(
            head,
            bytes.len() as u64,
            digest(bytes),
            t,
            t.metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!("raw reservation"));
    stage.write_chunk(bytes, t.child(1, 1024).unwrap()).unwrap();
    let mut reader = stage
        .seal(t.child(1, 1024).unwrap())
        .unwrap_or_else(|_| panic!("raw seal"));
    let mut body = [0; CHECKPOINT_BYTES];
    while reader.remaining() != 0 {
        reader
            .read_chunk(&mut body, t.child(1, 1024).unwrap())
            .unwrap();
    }
    let verified = reader.finish().unwrap_or_else(|_| panic!("raw hash"));
    assert_eq!(&body, bytes);
    let head = verified.current_head();
    let (arena, _) = verified
        .publish(head, t.metadata(1).unwrap())
        .unwrap_or_else(|_| panic!("raw pointer"));
    Store::from_arena(arena)
}
fn reject_cold(store: Store<Disk>) -> (Store<Disk>, Fault) {
    let disk = store.into_arena().into_backend().cold();
    let durable = disk.durable.clone();
    let arena = Arena::open(disk, manifest(), transfer().metadata(1).unwrap())
        .unwrap_or_else(|_| panic!("cold readable journal"));
    let head = arena.published_metadata();
    let mut cold = Store::from_arena(arena)
        .begin_cold(transfer(), 1)
        .unwrap_or_else(|_| panic!("cold entry"));
    let mut buffers = Buffers::empty();
    let mut failure = None;
    for _ in 0..2048 {
        match cold.step(&mut buffers, 1) {
            Err(Failure::Policy(error)) => {
                failure = Some(error);
                break;
            }
            Err(Failure::Storage(_)) => panic!("readable test media failed"),
            Ok(true) => panic!("untrusted checkpoint was accepted"),
            Ok(false) => (),
        }
    }
    let failure = failure.expect("bounded cold refusal");
    let rejected = cold
        .finish()
        .err()
        .expect("failed cold cannot yield Snapshot");
    assert!(rejected.owner.snapshot().is_none());
    assert_eq!(rejected.owner.arena.published_metadata(), head);
    assert_eq!(rejected.owner.arena.backend().durable, durable);
    (rejected.owner, failure)
}
#[test]
fn checkpoint_v2_requires_exact_member_evidence_and_keeps_content_encoding_unchanged() {
    let mut store = retained_store(initial(), true);
    let next = store.state.take().unwrap();
    assert_eq!(core::mem::size_of::<Content>(), 208);
    let mut encoded = [0; CHECKPOINT_BYTES];
    next.record.encode(&mut encoded).unwrap();
    assert_eq!(&encoded[..9], b"EVACQ002\x02");
    let decoded = codec::Record::decode(&encoded).unwrap();
    assert_eq!(decoded.candidate, next.record.candidate);
    assert_eq!(decoded.active, next.record.active);
    assert_eq!(decoded.known_good, next.record.known_good);
    assert_eq!(decoded.authorizations, next.record.authorizations);
    // Every absent or spurious proof row is rejected by ordinary cold open,
    // even after the attacker recomputes complete object+journal checksums.
    for mode in 0..7 {
        let mut bytes = encoded;
        match mode {
            0..=2 => bytes[2296 + mode * 112..2296 + (mode + 1) * 112].fill(0),
            3 => {
                bytes[..8].copy_from_slice(b"EVACQ001");
                bytes[8] = 1;
            }
            4 => bytes[2632] = 1,
            5 => {
                // A valid immutable Targets Object is not an authenticated
                // continuity Root, even when its reference is hash-consistent.
                let targets: [u8; 56] = bytes[2464..2520].try_into().unwrap();
                bytes[2408..2464].copy_from_slice(&targets);
            }
            _ => {
                bytes[9] &= !4;
                bytes[2088..2296].fill(0); // No KnownGood, but its proof remains.
            }
        }
        assert!(codec::Record::decode(&bytes).is_err());
        let current = retained_store(initial(), true);
        let resealed = publish_untrusted_checkpoint(current, &bytes);
        assert_eq!(reject_cold(resealed).1, Fault::Checkpoint);
    }
    // The original authenticated B proof is retained separately from current C.
    assert_ne!(next.record.authorizations[0], next.record.authorizations[1]);
    assert_eq!(next.record.authorizations[1], next.record.authorizations[2]);
    assert_eq!(
        next.authorization(next.active().unwrap()),
        next.record.authorizations[1]
    );
}
#[test]
fn ordinary_cold_rejects_mismatched_corrupt_or_never_accepted_local_targets_evidence() {
    for mode in 0..4 {
        let mut store = retained_store(initial(), true);
        let extra = if mode >= 2 {
            let bytes = if mode == 2 {
                let mut bytes = B_TARGETS.to_vec();
                let n = bytes.len();
                bytes[n - 1] ^= 1;
                bytes
            } else {
                include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/targets.bin")
                    .to_vec()
            };
            let stored = put(store, &bytes).unwrap_or_else(|_| panic!("proof input"));
            store = stored.store;
            Some(stored.object)
        } else {
            None
        };
        let mut next = store.state.take().unwrap();
        let original_replay = next.replay;
        let root = next.record.authorizations[1].unwrap().root;
        let targets = match mode {
            0 => next.record.metadata[0].unwrap(), // Genuine current C signs no B.
            1 => next.record.metadata[1].unwrap(), // Genuine wrong-role envelope.
            _ => extra.unwrap(),
        };
        next.record.authorizations[1] = Some(Authorization { root, targets });
        next.record.authorizations[2] = next.record.authorizations[1];
        assert_eq!(next.replay, original_replay);
        let mut encoded = [0; CHECKPOINT_BYTES];
        next.record.encode(&mut encoded).unwrap();
        let resealed = publish_untrusted_checkpoint(store, &encoded);
        assert_eq!(reject_cold(resealed).1, Fault::Metadata, "mode{mode}");
    }
}
#[test]
fn accepted_old_b_keeps_signed_evidence_and_all_floors_after_c_without_fresh_utc() {
    let store = retained_store(initial(), true);
    let expected = store.snapshot().unwrap();
    let b = expected.active().unwrap();
    let c = expected.candidate().unwrap();
    let b_proof = expected.authorization(b).unwrap();
    let c_proof = expected.authorization(c).unwrap();
    let floors = *expected.replay();
    assert_ne!(b_proof.targets(), c_proof.targets());
    let te = ev_release_trust::signature::Envelope::parse(B_TARGETS).unwrap();
    let old = ev_release_trust::metadata::Targets::parse(&te).unwrap();
    assert!(old.common().version < floors.roles()[0].unwrap().version);
    let cold = authenticated(Store::from_arena(
        Arena::open(
            store.into_arena().into_backend().cold(),
            manifest(),
            transfer().metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!("cold")),
    ));
    let ready = cold.snapshot().unwrap();
    assert_eq!(ready.authorization(b), Some(b_proof));
    assert_eq!(ready.authorization(c), Some(c_proof));
    assert_eq!(*ready.replay(), floors);
    assert_eq!(ready.active(), Some(b));
    assert_eq!(ready.known_good(), Some(b));
    assert_eq!(ready.candidate(), Some(c));
    // No QualifiedClock/UTC/network input exists on this cold path. These are
    // prior synthetic lifecycle carriers, not a health assertion from signing.
}
