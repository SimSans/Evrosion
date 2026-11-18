use super::*;
use std::{boxed::Box, cell::RefCell, collections::BTreeMap, rc::Rc, vec::Vec};

const DEADLINE: u64 = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Injected,
    Bounds,
}
#[derive(Clone, Copy)]
enum Cut {
    Before,
    After,
    Torn,
}
struct State {
    stable: BTreeMap<u64, Sector>,
    cache: BTreeMap<u64, Sector>,
    calls: usize,
    reads: usize,
    fault: Option<(usize, Cut)>,
    write_through: bool,
    writes: usize,
    flushes: usize,
}
#[derive(Clone)]
struct Memory(Rc<RefCell<State>>);
impl Memory {
    fn new() -> Self {
        Self::image(BTreeMap::new(), false)
    }
    fn image(stable: BTreeMap<u64, Sector>, write_through: bool) -> Self {
        Self(Rc::new(RefCell::new(State {
            stable,
            cache: BTreeMap::new(),
            calls: 0,
            reads: 0,
            fault: None,
            write_through,
            writes: 0,
            flushes: 0,
        })))
    }
    fn snapshot(&self) -> BTreeMap<u64, Sector> {
        self.0.borrow().stable.clone()
    }
    fn arm(&self, call: usize, cut: Cut) {
        let mut state = self.0.borrow_mut();
        state.calls = 0;
        state.fault = Some((call, cut));
    }
    fn crash(&self) {
        let mut state = self.0.borrow_mut();
        state.cache.clear();
        state.fault = None;
        state.calls = 0;
    }
    fn counts(&self) -> (usize, usize) {
        let s = self.0.borrow();
        (s.writes, s.flushes)
    }
    fn calls(&self) -> usize {
        self.0.borrow().calls
    }
    fn totals(&self) -> (usize, usize, usize) {
        let s = self.0.borrow();
        (s.reads, s.writes, s.flushes)
    }
    fn tick(state: &mut State) -> Option<Cut> {
        state.calls += 1;
        state
            .fault
            .and_then(|(call, cut)| (call == state.calls).then_some(cut))
    }
}
impl SectorIo for Memory {
    type Error = Failure;
    fn sectors(&self) -> u64 {
        REQUIRED_SECTORS + 8
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), Failure> {
        if lba >= self.sectors() {
            return Err(Failure::Bounds);
        }
        let mut state = self.0.borrow_mut();
        state.reads += 1;
        let cut = Self::tick(&mut state);
        if matches!(cut, Some(Cut::Before | Cut::Torn)) {
            return Err(Failure::Injected);
        }
        *out = *state
            .cache
            .get(&lba)
            .or_else(|| state.stable.get(&lba))
            .unwrap_or(&[0; 512]);
        if cut.is_some() {
            Err(Failure::Injected)
        } else {
            Ok(())
        }
    }
    fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> Result<(), Failure> {
        if lba >= self.sectors() {
            return Err(Failure::Bounds);
        }
        let mut state = self.0.borrow_mut();
        state.writes += 1;
        let cut = Self::tick(&mut state);
        if matches!(cut, Some(Cut::Before)) {
            return Err(Failure::Injected);
        }
        let stored = if matches!(cut, Some(Cut::Torn)) {
            let mut torn = *state
                .cache
                .get(&lba)
                .or_else(|| state.stable.get(&lba))
                .unwrap_or(&[0; 512]);
            torn[..173].copy_from_slice(&bytes[..173]);
            torn
        } else {
            *bytes
        };
        state.cache.insert(lba, stored);
        if state.write_through {
            state.stable.insert(lba, stored);
        }
        if cut.is_some() {
            Err(Failure::Injected)
        } else {
            Ok(())
        }
    }
    fn flush(&mut self, _: u64) -> Result<(), Failure> {
        let mut state = self.0.borrow_mut();
        state.flushes += 1;
        let cut = Self::tick(&mut state);
        if matches!(cut, Some(Cut::Before | Cut::Torn)) {
            return Err(Failure::Injected);
        }
        let cache = core::mem::take(&mut state.cache);
        state.stable.extend(cache);
        if cut.is_some() {
            Err(Failure::Injected)
        } else {
            Ok(())
        }
    }
}
fn scratch() -> Box<Scratch> {
    Box::new(Scratch::empty())
}
fn format(memory: Memory, scratch: &mut Scratch) -> Dataset<'_, Memory> {
    Dataset::format_new(
        memory,
        scratch,
        DatasetId::new([0x71; 16]).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|e| panic!("format: {:?}", e.error))
}
fn open(memory: Memory, scratch: &mut Scratch) -> Dataset<'_, Memory> {
    Dataset::open(memory, scratch, DEADLINE).unwrap_or_else(|e| panic!("open: {:?}", e.error))
}
fn name(text: &str) -> Name {
    Name::new(text).unwrap()
}
fn create(dataset: &mut Dataset<'_, Memory>, parent: ObjectId, text: &str, kind: Kind) -> ObjectId {
    dataset
        .create(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            parent,
            name(text),
            kind,
            DEADLINE,
        )
        .unwrap()
        .object
}
fn save(dataset: &mut Dataset<'_, Memory>, object: ObjectId, bytes: &[u8]) -> Receipt {
    let begin = dataset
        .begin_write(
            dataset.next_operation().unwrap(),
            object,
            dataset.metadata(object).unwrap().revision,
            bytes.len() as u64,
            codec::hash(bytes),
            DEADLINE,
        )
        .unwrap();
    for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        dataset
            .write_chunk(
                dataset.next_operation().unwrap(),
                begin.stage,
                index as u64 * CHUNK_BYTES as u64,
                chunk,
                DEADLINE,
            )
            .unwrap();
    }
    dataset
        .commit(dataset.next_operation().unwrap(), begin.stage, DEADLINE)
        .unwrap()
}
fn contents(dataset: &mut Dataset<'_, Memory>, object: ObjectId) -> Vec<u8> {
    let meta = dataset.metadata(object).unwrap();
    let mut output = std::vec![0;meta.length as usize];
    for (index, chunk) in output.chunks_mut(CHUNK_BYTES).enumerate() {
        assert_eq!(
            dataset
                .read(
                    object,
                    meta.revision,
                    index as u64 * CHUNK_BYTES as u64,
                    chunk,
                    DEADLINE
                )
                .unwrap(),
            chunk.len()
        );
    }
    output
}

#[test]
fn real_namespace_identity_trash_restore_cold_bytes_and_independent_guards() {
    let memory = Memory::new();
    memory
        .0
        .borrow_mut()
        .stable
        .insert(REQUIRED_SECTORS, [0x55; 512]);
    let mut resident = scratch();
    let mut dataset = format(memory.clone(), &mut resident);
    assert_eq!(
        dataset.metadata(ObjectId::ROOT).unwrap().parent,
        ObjectId::ROOT
    );
    let documents = create(&mut dataset, ObjectId::ROOT, "Documents", Kind::Directory);
    let ideas = create(&mut dataset, documents, "Ideas", Kind::Directory);
    let file = create(&mut dataset, ideas, "first.txt", Kind::File);
    let payload: Vec<_> = (0..17_013).map(|i| (i % 251) as u8).collect();
    save(&mut dataset, file, &payload);
    dataset
        .rename(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            file,
            name("renamed.txt"),
            DEADLINE,
        )
        .unwrap();
    dataset
        .move_object(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            file,
            documents,
            name("moved.txt"),
            DEADLINE,
        )
        .unwrap();
    assert_eq!(dataset.metadata(file).unwrap().id, file);
    dataset
        .trash(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            documents,
            DEADLINE,
        )
        .unwrap();
    assert!(dataset.is_trashed(file).unwrap());
    assert_eq!(dataset.list(ObjectId::ROOT, 0, false).unwrap(), None);
    dataset
        .restore(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            documents,
            DEADLINE,
        )
        .unwrap();
    let mut device = dataset.into_device();
    device.crash();
    let counts = device.counts();
    let mut dataset = open(device.clone(), &mut resident);
    assert_eq!(dataset.dataset_id().bytes(), [0x71; 16]);
    assert_eq!(dataset.name(file).unwrap(), "moved.txt");
    assert_eq!(dataset.metadata(file).unwrap().parent, documents);
    assert_eq!(contents(&mut dataset, file), payload);
    assert_eq!(
        device.counts(),
        counts,
        "cold open/read may not write or flush"
    );
    assert_eq!(device.snapshot().get(&REQUIRED_SECTORS), Some(&[0x55; 512]));
    device = dataset.into_device();
    assert!(device.snapshot().keys().all(|lba| *lba <= REQUIRED_SECTORS));
}

#[test]
fn stale_writers_stage_boundaries_and_exact_last_receipt() {
    let mut resident = scratch();
    let mut d = format(Memory::new(), &mut resident);
    let file = create(&mut d, ObjectId::ROOT, "a", Kind::File);
    let first = d.next_operation().unwrap();
    let begin = d
        .begin_write(first, file, 1, 5, codec::hash(b"hello"), DEADLINE)
        .unwrap();
    assert!(
        d.begin_write(
            d.next_operation().unwrap(),
            file,
            1,
            5,
            codec::hash(b"hello"),
            DEADLINE
        )
        .is_err()
    );
    assert_eq!(
        d.commit(d.next_operation().unwrap(), begin.stage, DEADLINE),
        Err(Error::Incomplete)
    );
    assert_eq!(
        d.write_chunk(
            d.next_operation().unwrap(),
            begin.stage,
            1,
            b"hello",
            DEADLINE
        ),
        Err(Error::InvalidChunk)
    );
    let written = d
        .write_chunk(
            d.next_operation().unwrap(),
            begin.stage,
            0,
            b"hello",
            DEADLINE,
        )
        .unwrap();
    assert!(
        d.write_chunk(written.operation, begin.stage, 0, b"hello", DEADLINE)
            .unwrap()
            .replayed
    );
    assert_eq!(
        d.write_chunk(written.operation, begin.stage, 0, b"other", DEADLINE),
        Err(Error::Conflict)
    );
    assert_eq!(
        d.begin_write(first, file, 1, 5, codec::hash(b"hello"), DEADLINE),
        Err(Error::StaleOperation)
    );
    let receipt = d
        .commit(d.next_operation().unwrap(), begin.stage, DEADLINE)
        .unwrap();
    assert_eq!(receipt.object_revision, 2);
    assert!(
        d.commit(receipt.operation, begin.stage, DEADLINE)
            .unwrap()
            .replayed
    );
    assert_eq!(
        d.begin_write(
            d.next_operation().unwrap(),
            file,
            1,
            5,
            codec::hash(b"hello"),
            DEADLINE
        ),
        Err(Error::Conflict)
    );
    assert_eq!(contents(&mut d, file), b"hello");
    let mut out = [0; 7];
    assert_eq!(d.read(file, 2, 3, &mut out, DEADLINE).unwrap(), 2);
    assert_eq!(&out[..2], b"lo");
}

#[test]
fn actual_authenticated_client_scope_is_distinct_from_global_id_and_client_nonce() {
    let mut resident = scratch();
    let mut d = format(Memory::new(), &mut resident);
    let a = ClientRequest::new([0xa1; 16], 7, 1).unwrap();
    let b = ClientRequest::new([0xb1; 16], 7, 1).unwrap();
    let global = d.next_operation().unwrap().for_request(a);
    let receipt = d
        .create(
            global,
            1,
            ObjectId::ROOT,
            name("first"),
            Kind::File,
            DEADLINE,
        )
        .unwrap();
    assert_eq!(receipt.operation.client_request(), Some(a));
    let wrong = OperationId::new(global.get()).unwrap().for_request(b);
    assert_eq!(
        d.create(
            wrong,
            1,
            ObjectId::ROOT,
            name("first"),
            Kind::File,
            DEADLINE
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        d.create(
            d.next_operation().unwrap().for_request(a),
            d.namespace_revision(),
            ObjectId::ROOT,
            name("first"),
            Kind::File,
            DEADLINE
        ),
        Err(Error::Conflict)
    );
    let device = d.into_device();
    let mut d = open(device, &mut resident);
    assert!(
        d.create(
            global,
            1,
            ObjectId::ROOT,
            name("first"),
            Kind::File,
            DEADLINE
        )
        .unwrap()
        .replayed
    );
    let second = d.next_operation().unwrap().for_request(b);
    d.create(
        second,
        d.namespace_revision(),
        ObjectId::ROOT,
        name("second"),
        Kind::File,
        DEADLINE,
    )
    .unwrap();
    assert_eq!(
        d.last_receipt()
            .unwrap()
            .unwrap()
            .operation
            .client_request(),
        Some(b)
    );
    assert_eq!(
        d.create(
            global,
            1,
            ObjectId::ROOT,
            name("first"),
            Kind::File,
            DEADLINE
        ),
        Err(Error::StaleOperation)
    );
}

#[test]
fn hash_failure_abort_releases_only_staging_and_cross_chunk_reads_verify() {
    let mut resident = scratch();
    let mut d = format(Memory::new(), &mut resident);
    let file = create(&mut d, ObjectId::ROOT, "f", Kind::File);
    let original = std::vec![0x41;8193];
    save(&mut d, file, &original);
    let mut range = [0; 4096];
    assert_eq!(d.read(file, 2, 4090, &mut range, DEADLINE).unwrap(), 4096);
    assert_eq!(range, [0x41; 4096]);
    let begin = d
        .begin_write(
            d.next_operation().unwrap(),
            file,
            2,
            3,
            codec::hash(b"xxx"),
            DEADLINE,
        )
        .unwrap();
    d.write_chunk(
        d.next_operation().unwrap(),
        begin.stage,
        0,
        b"bad",
        DEADLINE,
    )
    .unwrap();
    let op = d.next_operation().unwrap();
    assert_eq!(
        d.commit(op, begin.stage, DEADLINE),
        Err(Error::HashMismatch)
    );
    assert_eq!(contents(&mut d, file), original);
    assert_eq!(d.next_operation().unwrap(), op);
    d.abort(op, begin.stage, DEADLINE).unwrap();
    assert!(d.pending_stage().unwrap().is_none());
    assert_eq!(contents(&mut d, file), original);
    std::println!(
        "resident Scratch={} Dataset={} bytes; region={} sectors/{} bytes",
        core::mem::size_of::<Scratch>(),
        core::mem::size_of::<Dataset<'_, Memory>>(),
        REQUIRED_SECTORS,
        REQUIRED_SECTORS * 512
    );
}

#[test]
fn late_nonblank_and_partial_provisioning_are_preserved_without_auto_format() {
    let disk = Memory::new();
    disk.0
        .borrow_mut()
        .stable
        .insert(REQUIRED_SECTORS - 1, [0x77; 512]);
    let mut resident = scratch();
    let image = disk.snapshot();
    assert!(matches!(
        Dataset::format_new(disk.clone(), &mut resident, DatasetId([7; 16]), DEADLINE),
        Err(RejectedDevice {
            error: Error::NotBlank,
            ..
        })
    ));
    assert_eq!(disk.counts(), (0, 0));
    assert_eq!(disk.snapshot(), image);
    let disk = Memory::new();
    disk.0.borrow_mut().write_through = true;
    // All blank reads, then a successful first catalog write, then failure.
    disk.arm(REQUIRED_SECTORS as usize + 2, Cut::Before);
    assert!(matches!(
        Dataset::format_new(disk.clone(), &mut resident, DatasetId([7; 16]), DEADLINE),
        Err(RejectedDevice {
            error: Error::Io(Failure::Injected),
            ..
        })
    ));
    disk.crash();
    let partial = disk.snapshot();
    let counts = disk.counts();
    assert!(matches!(
        Dataset::open(disk.clone(), &mut resident, DEADLINE),
        Err(RejectedDevice {
            error: Error::ProvisioningRequired,
            ..
        })
    ));
    assert!(matches!(
        Dataset::format_new(disk.clone(), &mut resident, DatasetId([7; 16]), DEADLINE),
        Err(RejectedDevice {
            error: Error::NotBlank,
            ..
        })
    ));
    assert_eq!(disk.counts(), counts);
    assert_eq!(disk.snapshot(), partial);
    // Resume is a separately invoked NEW-only operation with exact expected
    // DatasetId. It never treats legacy/unidentified nonblank data as empty.
    assert!(matches!(
        Provisioning::resume(disk.clone(), &mut resident, DatasetId([8; 16]), DEADLINE),
        Err(RejectedDevice {
            error: Error::Conflict,
            ..
        })
    ));
    let mut provision =
        Provisioning::resume(disk.clone(), &mut resident, DatasetId([7; 16]), DEADLINE)
            .unwrap_or_else(|e| panic!("resume: {:?}", e.error));
    while provision.progress().verified_sectors < REQUIRED_SECTORS {
        let before = disk.totals();
        let progress = provision.scan_step(127, DEADLINE).unwrap();
        assert!(disk.totals().0 - before.0 <= 127);
        assert!(progress.durably_marked);
    }
    let d = provision
        .finish(DEADLINE)
        .unwrap_or_else(|e| panic!("finish: {:?}", e.error));
    assert_eq!(d.dataset_id(), DatasetId([7; 16]));
    assert_eq!(d.list(ObjectId::ROOT, 0, false).unwrap(), None);
}

#[test]
fn incremental_provisioning_marker_cuts_resume_or_preserve_unidentified_partial_bytes() {
    let mut checked = 0;
    let mut resumable = 0;
    let mut preserved = 0;
    for through in [false, true] {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            for at in [
                1, 2, 3, 4, 5, 6, 7, 8, 134, 135, 136, 263, 264, 265, 266, 267, 268, 269,
            ] {
                let disk = Memory::new();
                disk.0.borrow_mut().write_through = through;
                disk.0
                    .borrow_mut()
                    .stable
                    .insert(REQUIRED_SECTORS, [0x53; 512]);
                let mut resident = scratch();
                let id = DatasetId([0x61; 16]);
                let mut provision = Provisioning::new(disk.clone(), &mut resident, id)
                    .unwrap_or_else(|e| panic!("new: {:?}", e.error));
                assert_eq!(disk.counts(), (0, 0));
                while provision.progress().verified_sectors < REQUIRED_SECTORS {
                    provision.scan_step(4096, DEADLINE).unwrap();
                }
                disk.arm(at, cut);
                assert!(matches!(
                    provision.finish(DEADLINE),
                    Err(RejectedDevice {
                        error: Error::Io(Failure::Injected),
                        ..
                    })
                ));
                disk.crash();
                let before = disk.snapshot();
                let counts = disk.counts();
                match Dataset::open(disk.clone(), &mut resident, DEADLINE) {
                    Ok(mut d) => {
                        assert_eq!(d.dataset_id(), id);
                        assert_eq!(disk.counts(), counts);
                        d.recover_metadata(DEADLINE).unwrap();
                    }
                    Err(RejectedDevice {
                        error: Error::ProvisioningRequired,
                        ..
                    }) => {
                        assert_eq!(disk.counts(), counts);
                        let mut provision =
                            Provisioning::resume(disk.clone(), &mut resident, id, DEADLINE)
                                .unwrap_or_else(|e| panic!("resume: {:?}", e.error));
                        while provision.progress().verified_sectors < REQUIRED_SECTORS {
                            provision.scan_step(4096, DEADLINE).unwrap();
                        }
                        provision
                            .finish(DEADLINE)
                            .unwrap_or_else(|e| panic!("finish: {:?}", e.error));
                        resumable += 1;
                    }
                    Err(RejectedDevice {
                        error: Error::Unformatted,
                        ..
                    }) => {
                        assert_eq!(disk.counts(), counts);
                        assert_eq!(disk.snapshot(), before);
                    }
                    Err(RejectedDevice {
                        error: Error::Corrupt,
                        ..
                    }) => {
                        assert_eq!(disk.counts(), counts);
                        assert_eq!(disk.snapshot(), before);
                        assert!(matches!(
                            Dataset::format_new(disk.clone(), &mut resident, id, DEADLINE),
                            Err(RejectedDevice {
                                error: Error::NotBlank,
                                ..
                            })
                        ));
                        assert_eq!(disk.counts(), counts);
                        preserved += 1;
                    }
                    Err(e) => panic!("unexpected recovery result {:?}", e.error),
                }
                assert_eq!(disk.snapshot().get(&REQUIRED_SECTORS), Some(&[0x53; 512]));
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 108);
    assert!(resumable > 0);
    assert!(preserved > 0);
    std::println!(
        "verified {checked} NEW provisioning cuts; {resumable} explicitly resumed, {preserved} unknown/torn first markers retained for owner action"
    );
}

#[test]
fn hard_bounds_are_real_and_refusals_do_not_consume_operations_or_io() {
    let memory = Memory::new();
    let mut resident = scratch();
    let mut d = format(memory.clone(), &mut resident);
    assert!(Name::new("").is_none());
    assert!(Name::new("..").is_none());
    assert!(Name::new("x/y").is_none());
    assert!(Name::new("x\\y").is_none());
    assert!(Name::new("a\n").is_none());
    assert!(Name::new("Δ.txt").is_some());
    let mut parent = ObjectId::ROOT;
    for index in 0..MAX_DEPTH {
        parent = create(&mut d, parent, &std::format!("d{index}"), Kind::Directory);
    }
    let calls = memory.calls();
    let op = d.next_operation().unwrap();
    assert_eq!(
        d.create(
            op,
            d.namespace_revision(),
            parent,
            name("too-deep"),
            Kind::File,
            DEADLINE
        ),
        Err(Error::Depth)
    );
    assert_eq!(
        d.move_object(
            op,
            d.namespace_revision(),
            d.metadata(parent).unwrap().parent,
            parent,
            name("cycle"),
            DEADLINE
        ),
        Err(Error::Depth)
    );
    assert_eq!(memory.calls(), calls);
    assert_eq!(d.next_operation().unwrap(), op);
    for index in MAX_DEPTH..MAX_DIRECTORIES {
        create(
            &mut d,
            ObjectId::ROOT,
            &std::format!("d{index}"),
            Kind::Directory,
        );
    }
    assert_eq!(
        d.create(
            d.next_operation().unwrap(),
            d.namespace_revision(),
            ObjectId::ROOT,
            name("excess-dir"),
            Kind::Directory,
            DEADLINE
        ),
        Err(Error::DirectoryLimit)
    );
    for index in MAX_DIRECTORIES..MAX_ENTRIES {
        create(
            &mut d,
            ObjectId::ROOT,
            &std::format!("f{index}"),
            Kind::File,
        );
    }
    assert_eq!(
        d.create(
            d.next_operation().unwrap(),
            d.namespace_revision(),
            ObjectId::ROOT,
            name("excess-entry"),
            Kind::File,
            DEADLINE
        ),
        Err(Error::EntryLimit)
    );
    let mut cursor = 0;
    let mut count = 0;
    while let Some(entry) = d.list(ObjectId::ROOT, cursor, false).unwrap() {
        cursor = entry.id.slot;
        count += 1;
    }
    assert_eq!(count, MAX_ENTRIES - (MAX_DEPTH - 1));
    let device = d.into_device();
    let d = open(device, &mut resident);
    for slot in 1..=MAX_ENTRIES {
        assert!(
            d.metadata(ObjectId {
                slot: slot as u16,
                generation: 1
            })
            .is_ok()
        );
    }
}

#[test]
fn reclaim_requires_fence_preserves_restore_and_never_aliases_old_identity() {
    let mut resident = scratch();
    let mut d = format(Memory::new(), &mut resident);
    let folder = create(&mut d, ObjectId::ROOT, "folder", Kind::Directory);
    let file = create(&mut d, folder, "file", Kind::File);
    save(&mut d, file, b"retained");
    d.trash(
        d.next_operation().unwrap(),
        d.namespace_revision(),
        folder,
        DEADLINE,
    )
    .unwrap();
    let fence = ReclaimFence {
        object: folder,
        namespace_revision: d.namespace_revision(),
        authority_epoch: 1,
    };
    assert_eq!(
        d.purge(d.next_operation().unwrap(), fence, DEADLINE),
        Err(Error::NotEmpty)
    );
    let mut fence = ReclaimFence {
        object: file,
        namespace_revision: d.namespace_revision(),
        authority_epoch: 0,
    };
    assert_eq!(
        d.purge(d.next_operation().unwrap(), fence, DEADLINE),
        Err(Error::FenceRequired)
    );
    assert_eq!(d.allocated_bytes().unwrap(), CHUNK_BYTES as u64);
    assert_eq!(contents(&mut d, file), b"retained");
    fence.authority_epoch = 7;
    d.purge(d.next_operation().unwrap(), fence, DEADLINE)
        .unwrap();
    assert_eq!(d.allocated_bytes().unwrap(), 0);
    assert_eq!(d.metadata(file), Err(Error::StaleObject));
    let new = create(&mut d, ObjectId::ROOT, "different", Kind::File);
    assert_eq!(new.slot, file.slot);
    assert!(new.generation > file.generation);
    assert_eq!(
        d.begin_write(
            d.next_operation().unwrap(),
            file,
            1,
            0,
            codec::hash(&[]),
            DEADLINE
        ),
        Err(Error::StaleObject)
    );
    assert_eq!(
        d.purge(d.next_operation().unwrap(), fence, DEADLINE),
        Err(Error::Conflict)
    );
    let device = d.into_device();
    let d = open(device, &mut resident);
    assert_eq!(d.metadata(file), Err(Error::StaleObject));
    assert_eq!(d.metadata(new).unwrap().id, new);
}

// Every I/O boundary of these actual storage operations is cut with volatile
// write-cache and write-through media models. After cuts, a different owner is
// cold-opened, exact same IDs/intent retried, then cold-opened again. This is
// portable host sector-model evidence, not a VM/device/power-loss certification.
fn cuts<F, V>(base: &Memory, operation: OperationId, action: F, verify: V) -> usize
where
    F: for<'a> Fn(&mut Dataset<'a, Memory>, OperationId) -> Result<Receipt, Error<Failure>>,
    V: for<'a> Fn(&mut Dataset<'a, Memory>),
{
    let image = base.snapshot();
    let trial = Memory::image(image.clone(), false);
    let mut resident = scratch();
    let mut d = open(trial.clone(), &mut resident);
    trial.0.borrow_mut().calls = 0;
    action(&mut d, operation).unwrap();
    let calls = trial.calls();
    drop(d);
    let mut checked = 0;
    for through in [false, true] {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            for at in 1..=calls {
                let disk = Memory::image(image.clone(), through);
                let mut d = open(disk.clone(), &mut resident);
                disk.arm(at, cut);
                assert_eq!(
                    action(&mut d, operation),
                    Err(Error::Io(Failure::Injected)),
                    "cut {at}/{calls}"
                );
                assert_eq!(d.next_operation(), Err(Error::NeedsRecovery));
                assert!(d.last_receipt().is_err());
                let disk = d.into_device();
                disk.crash();
                let counts = disk.counts();
                let mut d = open(disk.clone(), &mut resident);
                assert_eq!(disk.counts(), counts);
                verify(&mut d);
                d.recover_metadata(DEADLINE).unwrap();
                action(&mut d, operation).unwrap();
                verify(&mut d);
                let disk = d.into_device();
                disk.crash();
                let counts = disk.counts();
                let mut d = open(disk.clone(), &mut resident);
                verify(&mut d);
                assert_eq!(disk.counts(), counts);
                checked += 1;
            }
        }
    }
    checked
}

#[test]
fn every_create_chunk_commit_abort_and_reclaim_io_cut_cold_retries_same_intent() {
    let disk = Memory::new();
    let mut resident = scratch();
    let d = format(disk.clone(), &mut resident);
    drop(d);
    let n = cuts(
        &disk,
        OperationId::new(1).unwrap(),
        |d, op| d.create(op, 1, ObjectId::ROOT, name("file"), Kind::File, DEADLINE),
        |d| {
            assert!(
                d.list(ObjectId::ROOT, 0, false)
                    .unwrap()
                    .is_none_or(|m| m.id
                        == ObjectId {
                            slot: 1,
                            generation: 1
                        })
            );
        },
    );
    let mut d = open(disk.clone(), &mut resident);
    let file = create(&mut d, ObjectId::ROOT, "file", Kind::File);
    let allocation = d.next_operation().unwrap();
    let disk = d.into_device();
    let n = n + cuts(
        &disk,
        allocation,
        |d, op| d.begin_write(op, file, 1, 123, codec::hash(&[0x81; 123]), DEADLINE),
        |d| {
            assert!(contents(d, file).is_empty());
            if let Some(stage) = d.pending_stage().unwrap() {
                assert_eq!(stage.object, file);
                assert_eq!(stage.written, 0);
            }
        },
    );
    let mut d = open(disk.clone(), &mut resident);
    let begin = d
        .begin_write(
            d.next_operation().unwrap(),
            file,
            1,
            123,
            codec::hash(&[0x81; 123]),
            DEADLINE,
        )
        .unwrap();
    let disk = d.into_device();
    let n = n + cuts(
        &disk,
        OperationId::new(3).unwrap(),
        |d, op| d.write_chunk(op, begin.stage, 0, &[0x81; 123], DEADLINE),
        |d| {
            assert_eq!(contents(d, file), Vec::<u8>::new());
            let stage = d.pending_stage().unwrap().unwrap();
            assert!(stage.written == 0 || stage.written == 123);
        },
    );
    let mut d = open(disk.clone(), &mut resident);
    d.write_chunk(
        d.next_operation().unwrap(),
        begin.stage,
        0,
        &[0x81; 123],
        DEADLINE,
    )
    .unwrap();
    let disk = d.into_device();
    let n = n + cuts(
        &disk,
        OperationId::new(4).unwrap(),
        |d, op| d.commit(op, begin.stage, DEADLINE),
        |d| {
            let bytes = contents(d, file);
            assert!(bytes.is_empty() || bytes == [0x81; 123]);
        },
    );
    let n = n + cuts(
        &disk,
        OperationId::new(4).unwrap(),
        |d, op| d.abort(op, begin.stage, DEADLINE),
        |d| {
            assert!(contents(d, file).is_empty());
        },
    );
    let mut d = open(disk.clone(), &mut resident);
    d.commit(d.next_operation().unwrap(), begin.stage, DEADLINE)
        .unwrap();
    d.trash(
        d.next_operation().unwrap(),
        d.namespace_revision(),
        file,
        DEADLINE,
    )
    .unwrap();
    let fence = ReclaimFence {
        object: file,
        namespace_revision: d.namespace_revision(),
        authority_epoch: 7,
    };
    let operation = d.next_operation().unwrap();
    let disk = d.into_device();
    let n = n + cuts(
        &disk,
        operation,
        |d, op| d.purge(op, fence, DEADLINE),
        |d| {
            if d.metadata(file).is_ok() {
                assert!(d.is_trashed(file).unwrap());
                assert_eq!(contents(d, file), [0x81; 123]);
            } else {
                assert_eq!(d.metadata(file), Err(Error::StaleObject));
            }
        },
    );
    std::println!(
        "verified {n} sector I/O cuts across create/allocation/chunk/commit/abort/reclaim"
    );
    assert!(n > 4500);
}

#[test]
fn atomic_restore_destination_is_bound_and_every_io_cut_preserves_one_namespace_state() {
    let disk = Memory::new();
    let mut resident = scratch();
    let mut d = format(disk.clone(), &mut resident);
    let source = create(&mut d, ObjectId::ROOT, "source", Kind::Directory);
    let destination = create(&mut d, ObjectId::ROOT, "destination", Kind::Directory);
    let child = create(&mut d, source, "child", Kind::File);
    let colliding = create(&mut d, destination, "collision", Kind::File);
    d.trash(
        d.next_operation().unwrap(),
        d.namespace_revision(),
        source,
        DEADLINE,
    )
    .unwrap();
    let operation = d.next_operation().unwrap();
    let namespace = d.namespace_revision();
    let counts = disk.totals();
    assert_eq!(
        d.restore_at(
            operation,
            namespace,
            source,
            destination,
            name("collision"),
            DEADLINE
        ),
        Err(Error::Collision)
    );
    assert_eq!(
        d.restore_at(
            operation,
            namespace,
            source,
            child,
            name("restored"),
            DEADLINE
        ),
        Err(Error::NotDirectory)
    );
    assert_eq!(
        d.restore_at(
            operation,
            namespace,
            source,
            source,
            name("restored"),
            DEADLINE
        ),
        Err(Error::Hidden)
    );
    assert_eq!(
        d.restore_at(
            operation,
            namespace - 1,
            source,
            destination,
            name("restored"),
            DEADLINE
        ),
        Err(Error::Conflict)
    );
    assert_eq!(disk.totals(), counts);
    assert_eq!(d.next_operation().unwrap(), operation);
    let disk = d.into_device();
    let checked = cuts(
        &disk,
        operation,
        |d, op| {
            d.restore_at(
                op,
                namespace,
                source,
                destination,
                name("restored"),
                DEADLINE,
            )
        },
        |d| {
            let entry = d.metadata(source).unwrap();
            assert_eq!(d.metadata(child).unwrap().parent, source);
            assert_eq!(d.metadata(colliding).unwrap().parent, destination);
            if d.is_trashed(source).unwrap() {
                assert_eq!(entry.parent, ObjectId::ROOT);
                assert_eq!(d.name(source).unwrap(), "source");
                assert_eq!(d.namespace_revision(), namespace);
                assert!(d.is_trashed(child).unwrap());
            } else {
                assert_eq!(entry.parent, destination);
                assert_eq!(d.name(source).unwrap(), "restored");
                assert_eq!(d.namespace_revision(), namespace + 1);
                assert!(!d.is_trashed(child).unwrap());
            }
        },
    );
    let mut d = open(disk, &mut resident);
    let receipt = d
        .restore_at(
            operation,
            namespace,
            source,
            destination,
            name("restored"),
            DEADLINE,
        )
        .unwrap();
    assert_eq!(receipt.kind, ReceiptKind::Restored);
    assert_eq!(
        d.restore_at(
            operation,
            namespace,
            source,
            destination,
            name("other"),
            DEADLINE
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        d.restore(operation, namespace, source, DEADLINE),
        Err(Error::Conflict)
    );
    let disk = d.into_device();
    disk.crash();
    let mut d = open(disk, &mut resident);
    assert!(
        d.restore_at(
            operation,
            namespace,
            source,
            destination,
            name("restored"),
            DEADLINE
        )
        .unwrap()
        .replayed
    );
    std::println!("verified {checked} atomic restore-at sector I/O cuts");
}

#[test]
fn corruption_and_legacy_or_unknown_format_refuse_without_repair() {
    let disk = Memory::new();
    let mut resident = scratch();
    let mut d = format(disk.clone(), &mut resident);
    let file = create(&mut d, ObjectId::ROOT, "file", Kind::File);
    save(&mut d, file, b"protected");
    let disk = d.into_device();
    let pristine = disk.snapshot();
    let counts = disk.counts();
    // One damaged root after acknowledged publication retains the SAME revision.
    disk.0.borrow_mut().stable.get_mut(&0).unwrap()[90] ^= 1;
    let mut d = open(disk.clone(), &mut resident);
    assert_eq!(contents(&mut d, file), b"protected");
    drop(d);
    assert_eq!(disk.counts(), counts);
    let mut corrupt = pristine.clone();
    corrupt.get_mut(&(DATA_START + 1)).unwrap()[7] ^= 1;
    let disk = Memory::image(corrupt, false);
    let before = disk.snapshot();
    let mut d = open(disk.clone(), &mut resident);
    assert_eq!(d.scrub_file(file, DEADLINE), Err(Error::Corrupt));
    drop(d);
    assert_eq!(disk.counts(), (0, 0));
    assert_eq!(disk.snapshot(), before);
    let mut unknown = pristine;
    unknown.get_mut(&0).unwrap()[8] = 99;
    let disk = Memory::image(unknown, false);
    assert!(matches!(
        Dataset::open(disk.clone(), &mut resident, DEADLINE),
        Err(RejectedDevice {
            error: Error::Unsupported,
            ..
        })
    ));
    assert_eq!(disk.counts(), (0, 0));
    let disk = Memory::new();
    disk.0.borrow_mut().stable.insert(0, [0x55; 512]);
    let before = disk.snapshot();
    assert!(matches!(
        Dataset::format_new(disk.clone(), &mut resident, DatasetId([7; 16]), DEADLINE),
        Err(RejectedDevice {
            error: Error::NotBlank,
            ..
        })
    ));
    assert_eq!(disk.snapshot(), before);
    assert_eq!(disk.counts(), (0, 0));
}

#[test]
fn one_mib_and_full_64_mib_quota_stage_reserve_reclaim_and_reuse() {
    let disk = Memory::new();
    let mut resident = scratch();
    let mut d = format(disk.clone(), &mut resident);
    let bytes = std::vec![0x91;MAX_FILE_BYTES as usize];
    let mut files = Vec::new();
    for index in 0..64 {
        let file = create(
            &mut d,
            ObjectId::ROOT,
            &std::format!("file{index}"),
            Kind::File,
        );
        save(&mut d, file, &bytes);
        files.push(file);
    }
    assert_eq!(d.allocated_bytes().unwrap(), USABLE_BYTES);
    let extra = create(&mut d, ObjectId::ROOT, "extra", Kind::File);
    let calls = disk.calls();
    assert_eq!(
        d.begin_write(
            d.next_operation().unwrap(),
            extra,
            1,
            1,
            codec::hash(&[1]),
            DEADLINE
        ),
        Err(Error::NoSpace)
    );
    assert_eq!(disk.calls(), calls);
    // At full committed quota a complete1MiB replacement still has isolated
    // staging capacity; it does not overwrite the visible old revision.
    let first = files[0];
    let receipt = save(&mut d, first, &bytes);
    assert_eq!(receipt.object_revision, 3);
    d.trash(
        d.next_operation().unwrap(),
        d.namespace_revision(),
        first,
        DEADLINE,
    )
    .unwrap();
    assert_eq!(
        d.allocated_bytes().unwrap(),
        USABLE_BYTES,
        "trash remains a retention root"
    );
    d.restore(
        d.next_operation().unwrap(),
        d.namespace_revision(),
        first,
        DEADLINE,
    )
    .unwrap();
    assert_eq!(contents(&mut d, first), bytes);
    d.trash(
        d.next_operation().unwrap(),
        d.namespace_revision(),
        first,
        DEADLINE,
    )
    .unwrap();
    d.purge(
        d.next_operation().unwrap(),
        ReclaimFence {
            object: first,
            namespace_revision: d.namespace_revision(),
            authority_epoch: 9,
        },
        DEADLINE,
    )
    .unwrap();
    save(&mut d, extra, &bytes);
    assert_eq!(d.allocated_bytes().unwrap(), USABLE_BYTES);
    let disk = d.into_device();
    disk.crash();
    let counts = disk.counts();
    let mut d = open(disk.clone(), &mut resident);
    assert_eq!(contents(&mut d, extra), bytes);
    assert_eq!(d.metadata(first), Err(Error::StaleObject));
    assert_eq!(disk.counts(), counts);
    assert_eq!(d.allocated_bytes().unwrap(), USABLE_BYTES);
}

#[test]
fn metadata_mirror_recovery_preserves_the_sole_good_root_at_every_io_cut() {
    let disk = Memory::new();
    let mut resident = scratch();
    let mut d = format(disk.clone(), &mut resident);
    let file = create(&mut d, ObjectId::ROOT, "retained", Kind::File);
    save(&mut d, file, b"latest acknowledged content");
    drop(d);
    let pristine = disk.snapshot();
    let mut cuts_checked = 0;
    for bad_slot in 0..2 {
        for through in [false, true] {
            for cut in [Cut::Before, Cut::After, Cut::Torn] {
                for at in 1..=6 {
                    let mut damaged = pristine.clone();
                    damaged.get_mut(&bad_slot).unwrap()[90] ^= 1;
                    let disk = Memory::image(damaged, through);
                    let mut d = open(disk.clone(), &mut resident);
                    assert!(d.needs_mirror_recovery());
                    assert_eq!(d.next_operation(), Err(Error::NeedsRecovery));
                    disk.arm(at, cut);
                    assert_eq!(
                        d.recover_metadata(DEADLINE),
                        Err(Error::Io(Failure::Injected))
                    );
                    let disk = d.into_device();
                    disk.crash();
                    let counts = disk.counts();
                    let mut d = open(disk.clone(), &mut resident);
                    assert_eq!(disk.counts(), counts);
                    assert_eq!(contents(&mut d, file), b"latest acknowledged content");
                    d.recover_metadata(DEADLINE).unwrap();
                    assert!(!d.needs_mirror_recovery());
                    let device = d.into_device();
                    device.crash();
                    let mut d = open(device, &mut resident);
                    assert_eq!(contents(&mut d, file), b"latest acknowledged content");
                    assert!(!d.needs_mirror_recovery());
                    cuts_checked += 1;
                }
            }
        }
    }
    assert_eq!(cuts_checked, 72);
    std::println!("verified {cuts_checked} interrupted metadata mirror recovery cuts");
}

#[test]
fn actual_portable_sector_costs_and_lazy_checked_open_are_recorded() {
    fn delta(after: (usize, usize, usize), before: (usize, usize, usize)) -> (usize, usize, usize) {
        (after.0 - before.0, after.1 - before.1, after.2 - before.2)
    }
    let disk = Memory::new();
    let mut resident = scratch();
    let d = format(disk.clone(), &mut resident);
    let formatted = disk.totals();
    assert_eq!(formatted, (152454, 132, 5));
    std::println!("SectorIo (read,write,flush): format={formatted:?}");
    let device = d.into_device();
    let mut d = open(device, &mut resident);
    let opened = disk.totals();
    assert_eq!(delta(opened, formatted), (130, 0, 0));
    let file = create(&mut d, ObjectId::ROOT, "large", Kind::File);
    let created = disk.totals();
    assert_eq!(delta(created, opened), (130, 130, 3));
    save(&mut d, file, &std::vec![0x31;MAX_FILE_BYTES as usize]);
    let saved = disk.totals();
    assert_eq!(delta(saved, created), (5252, 2948, 1029));
    let device = d.into_device();
    let mut d = open(device, &mut resident);
    let cold = disk.totals();
    assert_eq!(
        delta(cold, saved),
        (130, 0, 0),
        "open must not synchronously scrub every file"
    );
    d.scrub_file(file, DEADLINE).unwrap();
    let scrubbed = disk.totals();
    assert_eq!(delta(scrubbed, cold), (2304, 0, 0));
    drop(d);
    disk.0.borrow_mut().stable.get_mut(&0).unwrap()[90] ^= 1;
    let mut d = open(disk.clone(), &mut resident);
    let before_recovery = disk.totals();
    d.recover_metadata(DEADLINE).unwrap();
    assert_eq!(delta(disk.totals(), before_recovery), (2, 2, 2));
    std::println!(
        "SectorIo (read,write,flush): open={:?} create={:?}1MiBSave={:?}1MiBExplicitScrub={:?} mirrorRecovery={:?}",
        delta(opened, formatted),
        delta(created, opened),
        delta(saved, created),
        delta(scrubbed, cold),
        delta(disk.totals(), before_recovery)
    );
}

#[test]
fn opaque_commit_verification_yields_between_chunks_and_rejects_aborted_stage() {
    let disk = Memory::new();
    let mut resident = scratch();
    let mut d = format(disk.clone(), &mut resident);
    let file = create(&mut d, ObjectId::ROOT, "f", Kind::File);
    let bytes = std::vec![0x83;9001];
    let begin = d
        .begin_write(
            d.next_operation().unwrap(),
            file,
            1,
            bytes.len() as u64,
            codec::hash(&bytes),
            DEADLINE,
        )
        .unwrap();
    for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        d.write_chunk(
            d.next_operation().unwrap(),
            begin.stage,
            index as u64 * CHUNK_BYTES as u64,
            chunk,
            DEADLINE,
        )
        .unwrap();
    }
    let mut verifier = d.begin_verification(begin.stage).unwrap();
    let global = d.next_operation().unwrap();
    assert_eq!(
        d.commit_verified(global, &verifier, DEADLINE),
        Err(Error::Incomplete)
    );
    while !verifier.progress().complete {
        let before = disk.totals();
        let progress = d.verify_step(&mut verifier, 1, DEADLINE).unwrap();
        let after = disk.totals();
        assert_eq!(
            (after.0 - before.0, after.1 - before.1, after.2 - before.2),
            (9, 0, 0)
        );
        assert!(progress.verified_bytes <= bytes.len() as u64);
        assert_eq!(d.next_operation().unwrap(), global);
    }
    // Unrelated namespace work may proceed while this immutable stage is
    // verified. Allocate its publication ID only when ready to commit.
    create(&mut d, ObjectId::ROOT, "other", Kind::File);
    d.commit_verified(d.next_operation().unwrap(), &verifier, DEADLINE)
        .unwrap();
    assert_eq!(contents(&mut d, file), bytes);
    let begin = d
        .begin_write(
            d.next_operation().unwrap(),
            file,
            2,
            0,
            codec::hash(&[]),
            DEADLINE,
        )
        .unwrap();
    let mut verifier = d.begin_verification(begin.stage).unwrap();
    assert!(d.verify_step(&mut verifier, 1, DEADLINE).unwrap().complete);
    d.abort(d.next_operation().unwrap(), begin.stage, DEADLINE)
        .unwrap();
    assert_eq!(
        d.commit_verified(d.next_operation().unwrap(), &verifier, DEADLINE),
        Err(Error::InvalidStage)
    );
    std::println!(
        "CommitVerifier resident continuation={} bytes",
        core::mem::size_of::<CommitVerifier>()
    );
}
