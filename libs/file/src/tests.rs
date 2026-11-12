extern crate std;
use super::*;
use ev_store::{BootPolicy, GenerationId, GenerationManifest, Sector};
use std::{cell::Cell, rc::Rc, vec::Vec};
const DEADLINE: u64 = 100_000;
const RO: u64 = 11;
const RW: u64 = 22;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Power,
    Offline,
    Bounds,
}
#[derive(Clone, Copy, Debug)]
enum Cut {
    Before,
    After,
    Torn,
}
#[derive(Default)]
struct Hook {
    boundary: Cell<usize>,
    cut: Cell<Option<(usize, Cut)>>,
}
#[derive(Clone)]
struct Disk {
    durable: [Sector; 14],
    cache: [Sector; 14],
    boundary: usize,
    writes: usize,
    flushes: usize,
    trace: Vec<char>,
    hook: Rc<Hook>,
    offline: bool,
}
impl Disk {
    fn blank() -> Self {
        Self {
            durable: [[0; 512]; 14],
            cache: [[0; 512]; 14],
            boundary: 0,
            writes: 0,
            flushes: 0,
            trace: Vec::new(),
            hook: Rc::new(Hook::default()),
            offline: false,
        }
    }
    fn cold(mut self) -> Self {
        self.cache = self.durable;
        self.offline = false;
        self.hook = Rc::new(Hook::default());
        self.boundary = 0;
        self.trace.clear();
        self
    }
    fn begin(&mut self, kind: char, lba: u64) -> Result<Option<Cut>, Fault> {
        if self.offline {
            return Err(Fault::Offline);
        }
        if lba >= 14 {
            return Err(Fault::Bounds);
        }
        self.boundary += 1;
        self.hook.boundary.set(self.boundary);
        self.trace.push(kind);
        Ok(self
            .hook
            .cut
            .get()
            .filter(|(step, _)| *step == self.boundary)
            .map(|(_, cut)| cut))
    }
    fn lost(&mut self) -> Result<(), Fault> {
        self.offline = true;
        Err(Fault::Power)
    }
}
impl SectorIo for Disk {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        14
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), Fault> {
        if self.begin('r', lba)?.is_some() {
            self.lost()?;
        }
        *out = self.cache[lba as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> Result<(), Fault> {
        let cut = self.begin('w', lba)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        self.writes += 1;
        self.cache[lba as usize] = *bytes;
        if let Some(cut) = cut {
            match cut {
                Cut::After => self.durable[lba as usize] = *bytes,
                Cut::Torn => self.durable[lba as usize][..257].copy_from_slice(&bytes[..257]),
                Cut::Before => {}
            }
            return self.lost();
        }
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), Fault> {
        let cut = self.begin('f', 0)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        self.flushes += 1;
        if matches!(cut, Some(Cut::Torn)) {
            for i in (0..14).step_by(2) {
                self.durable[i] = self.cache[i];
            }
            return self.lost();
        }
        self.durable = self.cache;
        if cut.is_some() {
            return self.lost();
        }
        Ok(())
    }
}
fn bindings() -> Bindings {
    Bindings::new(RO, RW).unwrap()
}
fn initial(payload: &[u8]) -> Store<Disk> {
    initial_with_hook(payload).0
}
fn initial_with_hook(payload: &[u8]) -> (Store<Disk>, Rc<Hook>) {
    let mut bytes = [0; 256];
    let length = Envelope::initial(payload).unwrap().encode(&mut bytes);
    let manifest = GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [1; 32],
        supervisor_image: [2; 32],
        abi: [3; 32],
        health_contract: [4; 32],
        health_version: 1,
        required_checks: 3,
    };
    let disk = Disk::blank();
    let hook = disk.hook.clone();
    let store = Store::format_new(
        disk,
        manifest,
        &bytes[..length],
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("new model volume"));
    (store, hook)
}
fn opened(disk: Disk) -> Store<Disk> {
    opened_with_hook(disk).0
}
fn opened_with_hook(disk: Disk) -> (Store<Disk>, Rc<Hook>) {
    let disk = disk.cold();
    let hook = disk.hook.clone();
    (
        Store::open(disk, DEADLINE).unwrap_or_else(|e| panic!("open: {:?}", e.error)),
        hook,
    )
}
fn store_with_armed_device(disk: Disk, step: usize, cut: Cut) -> Store<Disk> {
    let (store, hook) = opened_with_hook(disk);
    hook.cut.set(Some((hook.boundary.get() + step, cut)));
    store
}
fn replace(counter: u64, bytes: &[u8]) -> Request {
    Request::Replace {
        counter,
        payload: Payload::new(bytes).unwrap(),
    }
}
fn contents(store: &mut Store<Disk>) -> (u64, u64, Vec<u8>) {
    let mut bytes = [0; 256];
    let n = store
        .read_mutable(ObjectId::user_data(), &mut bytes, DEADLINE)
        .unwrap();
    let decoded = Envelope::decode(&bytes[..n]).unwrap();
    (
        decoded.counter,
        decoded.global_operation,
        decoded.payload.to_vec(),
    )
}

#[test]
fn initial_read_and_server_assigned_global_ids_are_separate_from_client_counter() {
    let mut store = initial(b"A");
    assert_eq!(contents(&mut store), (0, 0, b"A".to_vec()));
    let mut gateway = Gateway::new(store, bindings());
    assert_eq!(
        gateway.handle(RO, Request::Read, DEADLINE),
        Ok(Response::Read {
            counter: 0,
            payload: Payload::new(b"A").unwrap()
        })
    );
    assert_eq!(
        gateway.handle(RW, replace(1, b"B"), DEADLINE),
        Ok(Response::Replaced {
            counter: 1,
            replayed: false
        })
    );
    let mut store = gateway.into_store();
    assert_eq!(contents(&mut store), (1, 1, b"B".to_vec()));
    let mut raw = [0; 256];
    let n = store
        .read_mutable(ObjectId::user_data(), &mut raw, DEADLINE)
        .unwrap();
    // Trusted volume housekeeping checkpoints preserve the same logical file
    // envelope while consuming global journal IDs. No fabricated boot health.
    for _ in 0..12 {
        store
            .execute(
                store.next_operation().unwrap(),
                StoreRequest::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &raw[..n],
                },
                DEADLINE,
            )
            .unwrap();
    }
    assert_eq!(
        store.execute(
            OperationId::new(1).unwrap(),
            StoreRequest::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &raw[..n]
            },
            DEADLINE
        ),
        Err(ev_store::Error::StaleOperation)
    );
    let disk = store.into_device();
    let before = disk.writes;
    let mut gateway = Gateway::new(opened(disk), bindings());
    assert_eq!(
        gateway.handle(RW, replace(1, b"B"), DEADLINE),
        Ok(Response::Replaced {
            counter: 1,
            replayed: true
        })
    );
    let store = gateway.into_store();
    let disk = store.into_device();
    assert_eq!(disk.writes, before);
    let mut gateway = Gateway::new(opened(disk), bindings());
    assert_eq!(
        gateway.handle(RW, replace(2, b"C"), DEADLINE),
        Ok(Response::Replaced {
            counter: 2,
            replayed: false
        })
    );
    let mut store = opened(gateway.into_store().into_device());
    assert_eq!(contents(&mut store), (2, 14, b"C".to_vec()));
    assert_eq!(store.next_operation().unwrap().get(), 15);
}

#[test]
fn malformed_readonly_unknown_route_and_zero_max_counter_deny_before_backend_io() {
    for (endpoint, request) in [
        (RO, replace(1, b"B")),
        (999, Request::Read),
        (RW, replace(0, b"A")),
        (RW, replace(u64::MAX, b"B")),
    ] {
        let (store, hook) = initial_with_hook(b"A");
        let mark = hook.boundary.get();
        let mut gateway = Gateway::new(store, bindings());
        assert!(gateway.handle(endpoint, request, DEADLINE).is_err());
        let disk = gateway.into_store().into_device();
        assert_eq!(disk.boundary, mark);
    }
}

#[test]
fn stale_skip_conflict_and_exact_payload_length_never_advance_global_operation() {
    let mut gateway = Gateway::new(initial(b"A"), bindings());
    gateway.handle(RW, replace(1, b"B"), DEADLINE).unwrap();
    gateway.handle(RW, replace(2, b"C"), DEADLINE).unwrap();
    let before = gateway.store.next_operation().unwrap();
    for (request, error) in [
        (replace(1, b"B"), Error::Stale),
        (replace(4, b"D"), Error::Skipped),
        (replace(2, b"C\0"), Error::Conflict),
        (replace(2, b"different"), Error::Conflict),
    ] {
        assert_eq!(gateway.handle(RW, request, DEADLINE), Err(error));
        assert_eq!(gateway.store.next_operation().unwrap(), before);
    }
    assert_eq!(
        gateway.handle(RW, replace(2, b"C"), DEADLINE),
        Ok(Response::Replaced {
            counter: 2,
            replayed: true
        })
    );
}

#[test]
fn replacement_and_recovery_retry_are_atomic_at_every_backend_boundary() {
    let original = initial(b"A").into_device().cold();
    let (store, hook) = opened_with_hook(original.clone());
    let mut full = Gateway::new(store, bindings());
    let start = hook.boundary.get();
    full.handle(RW, replace(1, b"complete B"), DEADLINE)
        .unwrap();
    let total = full.into_store().into_device().boundary - start;
    for step in 1..=total {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            // Retain the already mounted root while arming the backend. This
            // helper below constructs no parallel Store or backend alias.
            let mut gateway = Gateway::new(
                store_with_armed_device(original.clone(), step, cut),
                bindings(),
            );
            assert!(
                gateway
                    .handle(RW, replace(1, b"complete B"), DEADLINE)
                    .is_err()
            );
            let mut store = opened(gateway.into_store().into_device());
            let (counter, _, payload) = contents(&mut store);
            assert!(
                (counter == 0 && payload == b"A") || (counter == 1 && payload == b"complete B")
            );
            let mut gateway = Gateway::new(store, bindings());
            gateway
                .handle(RW, replace(1, b"complete B"), DEADLINE)
                .unwrap();
            let mut store = gateway.into_store();
            assert_eq!(contents(&mut store), (1, 1, b"complete B".to_vec()));
            assert_eq!(store.next_operation().unwrap().get(), 2);
        }
    }
}

#[test]
fn canonical_envelope_bounds_initial_receipt_and_version_are_fail_closed() {
    for length in [0, 1, 224] {
        let payload = [0x61; 224];
        let envelope = Envelope::initial(&payload[..length]).unwrap();
        let mut bytes = [0; 256];
        let n = envelope.encode(&mut bytes);
        assert_eq!(n, 32 + length);
        assert_eq!(Envelope::decode(&bytes[..n]), Ok(envelope));
        assert!(Envelope::decode(&bytes[..n - 1]).is_err());
    }
    let mut bytes = [0; 256];
    let n = Envelope::initial(b"A").unwrap().encode(&mut bytes);
    for offset in [8, 9, 12, 15, 16, 24] {
        let mut bad = bytes;
        bad[offset] = 7;
        assert!(Envelope::decode(&bad[..n]).is_err());
    }
    assert!(Envelope::initial(&[0; 225]).is_err());
    let mut gateway = Gateway::new(initial(b"A"), bindings());
    let mut bad = Request::Read.encode();
    bad[24] = 1;
    assert!(gateway.handle_frame(RO, &bad, DEADLINE).is_err());
    let mut store = gateway.into_store();
    assert_eq!(contents(&mut store), (0, 0, b"A".to_vec()));
}

#[test]
fn malformed_frames_and_zero_max_wire_counters_perform_no_backend_reads() {
    let (store, hook) = initial_with_hook(b"A");
    let mut gateway = Gateway::new(store, bindings());
    for counter in [0, u64::MAX] {
        let frame = replace(counter, b"B").encode();
        let mark = hook.boundary.get();
        let error = gateway.handle_frame(RW, &frame, DEADLINE).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidCounter);
        assert_eq!(hook.boundary.get(), mark);
    }
    let mut bad = Request::Read.encode();
    bad[24] = 1;
    let mark = hook.boundary.get();
    assert!(gateway.handle_frame(RO, &bad, DEADLINE).is_err());
    assert_eq!(hook.boundary.get(), mark);
    assert_eq!(gateway.store.next_operation().unwrap().get(), 1);
}

#[test]
fn maximum_payload_and_empty_replacement_keep_exact_persistent_length() {
    let mut gateway = Gateway::new(initial(&[0x57; 224]), bindings());
    gateway.handle(RW, replace(1, &[]), DEADLINE).unwrap();
    assert_eq!(
        gateway.handle(RO, Request::Read, DEADLINE),
        Ok(Response::Read {
            counter: 1,
            payload: Payload::new(&[]).unwrap()
        })
    );
    let mut store = opened(gateway.into_store().into_device());
    let mut bytes = [0xff; 256];
    let n = store
        .read_mutable(ObjectId::user_data(), &mut bytes, DEADLINE)
        .unwrap();
    assert_eq!(n, 32);
    assert!(bytes[32..].iter().all(|&b| b == 0));
    assert_eq!(Envelope::decode(&bytes[..n]).unwrap().payload(), b"");
}

#[test]
fn invalid_stored_receipt_is_quarantined_without_silent_reformat() {
    let mut store = initial(b"A");
    let mut bytes = [0; 256];
    let bad = Envelope {
        counter: 1,
        global_operation: 999,
        payload: b"B",
    };
    let n = bad.encode(&mut bytes);
    store
        .execute(
            store.next_operation().unwrap(),
            StoreRequest::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &bytes[..n],
            },
            DEADLINE,
        )
        .unwrap();
    let disk = store.into_device();
    let writes = disk.writes;
    let data = disk.durable;
    let mut gateway = Gateway::new(opened(disk), bindings());
    assert_eq!(
        gateway.handle(RO, Request::Read, DEADLINE),
        Err(Error::Envelope(EnvelopeError::Operation))
    );
    let disk = gateway.into_store().into_device();
    assert_eq!(disk.writes, writes);
    assert_eq!(disk.durable, data);
}

#[test]
fn recovery_interruption_preserves_the_same_logical_counter_and_receipt() {
    let original = initial(b"A").into_device().cold();
    let (store, hook) = opened_with_hook(original.clone());
    let start = hook.boundary.get();
    let mut full = Gateway::new(store, bindings());
    full.handle(RW, replace(1, b"B"), DEADLINE).unwrap();
    let full = full.into_store().into_device();
    let prepare_flush = full.trace[start..]
        .iter()
        .position(|&kind| kind == 'f')
        .unwrap()
        + 1;
    let mut interrupted = Gateway::new(
        store_with_armed_device(original, prepare_flush, Cut::After),
        bindings(),
    );
    assert!(interrupted.handle(RW, replace(1, b"B"), DEADLINE).is_err());
    let prepared = interrupted.into_store().into_device().cold();
    let (recovered, hook) = opened_with_hook(prepared.clone());
    let total = hook.boundary.get();
    assert_eq!(
        contents(&mut Gateway::new(recovered, bindings()).into_store()),
        (1, 1, b"B".to_vec())
    );
    for step in 1..=total {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let disk = prepared.clone().cold();
            disk.hook.cut.set(Some((step, cut)));
            let rejected = Store::open(disk, DEADLINE)
                .err()
                .expect("actual recovery cut");
            let store = opened(rejected.device);
            let disk = store.into_device();
            let writes = disk.writes;
            let mut gateway = Gateway::new(opened(disk), bindings());
            assert_eq!(
                gateway.handle(RW, replace(1, b"B"), DEADLINE),
                Ok(Response::Replaced {
                    counter: 1,
                    replayed: true
                })
            );
            let mut store = gateway.into_store();
            assert_eq!(contents(&mut store), (1, 1, b"B".to_vec()));
            assert_eq!(store.next_operation().unwrap().get(), 2);
            assert_eq!(store.into_device().writes, writes);
        }
    }
}
