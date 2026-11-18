extern crate std;
use super::*;
use crate::{Envelope, Payload};
use ev_store::{
    AdmissionReport, BootPolicy, GenerationId, GenerationManifest, HealthOutcome, HealthReport,
    ObjectId, OperationId, Request as StoreRequest, Sector, desktop::Region,
};
use std::{cell::RefCell, rc::Rc, vec, vec::Vec};
const DEADLINE: u64 = 100_000;
struct State {
    bytes: Vec<Sector>,
    reads: u64,
    writes: Vec<u32>,
    flushes: u64,
    fail_read: bool,
}
struct Device {
    state: Rc<RefCell<State>>,
    region: Region,
}
impl SectorIo for Device {
    type Error = ();
    fn sectors(&self) -> u64 {
        14
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), ()> {
        if lba >= 14 {
            return Err(());
        }
        let mut s = self.state.borrow_mut();
        s.reads += 1;
        if s.fail_read {
            return Err(());
        }
        *out = s.bytes[(u64::from(self.region.physical_start()) + lba) as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, input: &Sector, _: u64) -> Result<(), ()> {
        if lba >= 14 {
            return Err(());
        }
        let mut s = self.state.borrow_mut();
        let physical = self.region.physical_start() + lba as u32;
        s.bytes[physical as usize] = *input;
        s.writes.push(physical);
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), ()> {
        self.state.borrow_mut().flushes += 1;
        Ok(())
    }
}
fn manifest(id: u64) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(id).unwrap(),
        cohort: [id as u8; 32],
        supervisor_image: [id as u8 + 3; 32],
        abi: [4; 32],
        health_contract: [5; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn state() -> Rc<RefCell<State>> {
    Rc::new(RefCell::new(State {
        bytes: vec![[0; 512]; 64],
        reads: 0,
        writes: Vec::new(),
        flushes: 0,
        fail_read: false,
    }))
}
fn device(state: &Rc<RefCell<State>>, region: Region) -> Device {
    Device {
        state: state.clone(),
        region,
    }
}
fn user_store(state: &Rc<RefCell<State>>, region: Region, seed: &[u8]) -> Store<Device> {
    let mut envelope = [0; 256];
    let length = Envelope::initial(seed).unwrap().encode(&mut envelope);
    Store::format_new(
        device(state, region),
        manifest(1),
        &envelope[..length],
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|e| panic!("model format: {:?}", e.error))
}
fn gateway(state: &Rc<RefCell<State>>) -> DesktopGateway<Device> {
    DesktopGateway::new(
        user_store(state, Region::FileA, SEED_NOTES),
        user_store(state, Region::FileB, SEED_PRIVATE),
        DesktopBindings::new(10, 11, 12, 13).unwrap(),
    )
}
fn replace(counter: u64, payload: &[u8]) -> [u8; 256] {
    Request::Replace {
        counter,
        payload: Payload::new(payload).unwrap(),
    }
    .encode()
}
fn read(g: &mut DesktopGateway<Device>, route: u64) -> (u64, Vec<u8>) {
    match g
        .handle_frame(route, &Request::Read.encode(), DEADLINE)
        .unwrap()
    {
        Response::Read { counter, payload } => (counter, payload.as_slice().to_vec()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn endpoint_fixed_object_and_rights_survive_replace_duplicate_and_cold_reopen() {
    let state = state();
    let mut g = gateway(&state);
    assert_eq!(read(&mut g, 10), (0, SEED_NOTES.to_vec()));
    assert_eq!(read(&mut g, 12), (0, SEED_PRIVATE.to_vec()));
    let system = state.borrow().bytes[16..30].to_vec();
    let private = state.borrow().bytes[48..62].to_vec();
    let content = b"Private is only a word in this Notes payload";
    assert_eq!(
        g.handle_frame(11, &replace(1, content), DEADLINE),
        Ok(Response::Replaced {
            counter: 1,
            replayed: false
        })
    );
    assert_eq!(state.borrow().bytes[48..62], private);
    assert_eq!(state.borrow().bytes[16..30], system);
    assert!(
        state
            .borrow()
            .writes
            .iter()
            .all(|lba| (32..46).contains(lba) || (48..62).contains(lba))
    );
    let writes = state.borrow().writes.len();
    assert_eq!(
        g.handle_frame(11, &replace(1, content), DEADLINE),
        Ok(Response::Replaced {
            counter: 1,
            replayed: true
        })
    );
    assert_eq!(state.borrow().writes.len(), writes);
    let (notes, private) = g.into_stores();
    let notes = notes.into_device();
    let private = private.into_device();
    let mut g = DesktopGateway::new(
        Store::open(notes, DEADLINE).unwrap_or_else(|_| panic!("Notes cold open")),
        Store::open(private, DEADLINE).unwrap_or_else(|_| panic!("Private cold open")),
        DesktopBindings::new(10, 11, 12, 13).unwrap(),
    );
    assert_eq!(read(&mut g, 10), (1, content.to_vec()));
    assert_eq!(read(&mut g, 12), (0, SEED_PRIVATE.to_vec()));
    assert_eq!(
        g.handle_frame(13, &replace(1, b"separate private payload"), DEADLINE),
        Ok(Response::Replaced {
            counter: 1,
            replayed: false
        })
    );
    assert_eq!(read(&mut g, 10), (1, content.to_vec()));
}

#[test]
fn scalar_metadata_reads_actual_content_with_no_mutation_and_no_cross_object_selector() {
    let state = state();
    let mut g = gateway(&state);
    let before = state.borrow().bytes.clone();
    let writes = state.borrow().writes.len();
    let flushes = state.borrow().flushes;
    assert_eq!(
        g.metadata_word(10, MetadataQuery::counter(), DEADLINE),
        Ok(0)
    );
    let mut digest = [0; 32];
    for index in 0..4 {
        let word = g
            .metadata_word(10, MetadataQuery::digest_word(index).unwrap(), DEADLINE)
            .unwrap();
        digest[index as usize * 8..index as usize * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(SEED_NOTES)));
    assert_eq!(state.borrow().bytes, before);
    assert_eq!(state.borrow().writes.len(), writes);
    assert_eq!(state.borrow().flushes, flushes);
    let reads = state.borrow().reads;
    assert_eq!(
        g.metadata_word(11, MetadataQuery::counter(), DEADLINE),
        Err(Error::Denied)
    );
    assert_eq!(
        g.metadata_word(999, MetadataQuery::counter(), DEADLINE),
        Err(Error::Denied)
    );
    assert_eq!(state.borrow().reads, reads);
    g.handle_frame(11, &replace(1, b"new current Notes"), DEADLINE)
        .unwrap();
    assert_eq!(
        g.metadata_word(10, MetadataQuery::counter(), DEADLINE),
        Ok(1)
    );
    let first = g
        .metadata_word(10, MetadataQuery::digest_word(0).unwrap(), DEADLINE)
        .unwrap();
    assert_eq!(
        first,
        u64::from_le_bytes(
            Sha256::digest(b"new current Notes")[..8]
                .try_into()
                .unwrap()
        )
    );
    assert_eq!(
        g.metadata_word(12, MetadataQuery::counter(), DEADLINE),
        Ok(0)
    );
}

#[test]
fn failed_metadata_read_returns_no_word_and_store_poison_prevents_later_reuse() {
    let state = state();
    let mut gateway = gateway(&state);
    let writes = state.borrow().writes.len();
    let flushes = state.borrow().flushes;
    state.borrow_mut().fail_read = true;
    let failure = gateway
        .metadata_word(10, MetadataQuery::counter(), DEADLINE)
        .unwrap_err();
    assert_eq!(failure, Error::Backend(ev_store::Error::Io(())));
    assert_eq!(failure.code(), crate::ErrorCode::Io);
    let reads = state.borrow().reads;
    state.borrow_mut().fail_read = false;
    let failure = gateway
        .metadata_word(10, MetadataQuery::digest_word(0).unwrap(), DEADLINE)
        .unwrap_err();
    assert_eq!(failure, Error::Backend(ev_store::Error::NeedsRecovery));
    assert_eq!(failure.code(), crate::ErrorCode::NeedsRecovery);
    assert_eq!(state.borrow().reads, reads);
    assert_eq!(state.borrow().writes.len(), writes);
    assert_eq!(state.borrow().flushes, flushes);
}

#[test]
fn malformed_unknown_ro_and_exhaustion_attempts_reject_before_backend_access() {
    let state = state();
    let mut g = gateway(&state);
    let counts = (
        state.borrow().reads,
        state.borrow().writes.len(),
        state.borrow().flushes,
    );
    for frame in [[0; 256], replace(0, b"x"), replace(u64::MAX, b"x")] {
        assert!(g.handle_frame(11, &frame, DEADLINE).is_err());
    }
    assert_eq!(
        g.handle_frame(10, &replace(1, b"write through RO"), DEADLINE),
        Err(Error::Denied)
    );
    assert_eq!(
        g.handle_frame(12, &replace(1, b"write Notes through Private RO"), DEADLINE),
        Err(Error::Denied)
    );
    assert_eq!(
        g.handle_frame(999, &Request::Read.encode(), DEADLINE),
        Err(Error::Denied)
    );
    assert_eq!(
        (
            state.borrow().reads,
            state.borrow().writes.len(),
            state.borrow().flushes
        ),
        counts
    );
    assert!(DesktopBindings::new(10, 11, 10, 13).is_none());
    assert!(DesktopBindings::new(0, 11, 12, 13).is_none());
}

#[test]
fn metadata_codec_total_fields_and_reserved_combinations_are_fail_closed() {
    for field in 0..5 {
        let mut b = *b"FMQ1\0\0\0\0";
        b[4] = field;
        let query = MetadataQuery::decode(b).unwrap();
        assert_eq!(query.encode(), b);
    }
    assert!(MetadataQuery::digest_word(4).is_none());
    for index in 0..8 {
        let mut b = MetadataQuery::counter().encode();
        b[index] = 255;
        assert!(MetadataQuery::decode(b).is_err());
    }
    for field in 5..=255 {
        let mut b = MetadataQuery::counter().encode();
        b[4] = field;
        assert!(MetadataQuery::decode(b).is_err());
    }
    for n in 0..2048u64 {
        let _ = MetadataQuery::decode(n.wrapping_mul(0x9e3779b97f4a7c15).to_le_bytes());
    }
}

fn execute(store: &mut Store<Device>, request: StoreRequest<'_>) {
    let operation = store.next_operation().unwrap();
    store.execute(operation, request, DEADLINE).unwrap();
}
fn admit(store: &mut Store<Device>) -> AdmissionReport {
    let manifest = store.selected_manifest(DEADLINE).unwrap();
    execute(store, StoreRequest::BeginBoot(manifest.generation));
    let plan = store.boot_plan(DEADLINE).unwrap();
    let report = AdmissionReport {
        generation: plan.manifest.generation,
        boot_serial: plan.serial,
        process_stamp: [plan.serial as u8; 32],
        cohort: plan.manifest.cohort,
        supervisor_image: plan.manifest.supervisor_image,
        abi: plan.manifest.abi,
        health_contract: plan.manifest.health_contract,
        health_version: plan.manifest.health_version,
    };
    execute(store, StoreRequest::Admission(report));
    report
}
#[test]
fn system_generation_health_failure_and_rollback_never_write_file_bytes() {
    // Host model supplies synthetic admission/health evidence; this test proves
    // cross-region isolation only, never actual boot/health/hardware execution.
    let state = state();
    let mut files = gateway(&state);
    files
        .handle_frame(11, &replace(1, b"owner Notes preserved"), DEADLINE)
        .unwrap();
    files
        .handle_frame(13, &replace(1, b"private data preserved"), DEADLINE)
        .unwrap();
    let a = state.borrow().bytes[32..46].to_vec();
    let b = state.borrow().bytes[48..62].to_vec();
    let guards = [
        state.borrow().bytes[30],
        state.borrow().bytes[31],
        state.borrow().bytes[46],
        state.borrow().bytes[47],
    ];
    let mut system = Store::format_new(
        device(&state, Region::System),
        manifest(1),
        b"system-only-data",
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("system format"));
    let admitted = admit(&mut system);
    execute(
        &mut system,
        StoreRequest::Health(HealthReport {
            admitted,
            outcome: HealthOutcome::CriticalPassed,
            observed_checks: 3,
            storage_probe: Sha256::digest(b"system-only-data").into(),
        }),
    );
    execute(
        &mut system,
        StoreRequest::WriteMutable {
            object: ObjectId::user_data(),
            bytes: b"changed system state",
        },
    );
    execute(&mut system, StoreRequest::Stage(&manifest(2)));
    execute(
        &mut system,
        StoreRequest::Activate(GenerationId::new(2).unwrap()),
    );
    let failed = admit(&mut system);
    execute(
        &mut system,
        StoreRequest::Health(HealthReport {
            admitted: failed,
            outcome: HealthOutcome::ProcessFault,
            observed_checks: 0,
            storage_probe: Sha256::digest(b"changed system state").into(),
        }),
    );
    assert_eq!(
        system.selected_manifest(DEADLINE).unwrap().generation.get(),
        1
    );
    assert_eq!(system.last_failure().unwrap().unwrap().generation.get(), 2);
    assert_eq!(state.borrow().bytes[32..46], a);
    assert_eq!(state.borrow().bytes[48..62], b);
    assert_eq!(
        [
            state.borrow().bytes[30],
            state.borrow().bytes[31],
            state.borrow().bytes[46],
            state.borrow().bytes[47]
        ],
        guards
    );
    assert_eq!(read(&mut files, 10), (1, b"owner Notes preserved".to_vec()));
    assert_eq!(
        read(&mut files, 12),
        (1, b"private data preserved".to_vec())
    );
    // Both user volumes keep independent original mutation receipts/counters.
    let (notes, private) = files.into_stores();
    assert_eq!(
        notes.next_operation().unwrap(),
        OperationId::new(2).unwrap()
    );
    assert_eq!(
        private.next_operation().unwrap(),
        OperationId::new(2).unwrap()
    );
}
