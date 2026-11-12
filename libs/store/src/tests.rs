extern crate std;
use super::*;
use std::{vec, vec::Vec};
const DEADLINE: u64 = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Power,
    Offline,
    Bounds,
    Deadline,
}
#[derive(Clone, Copy, Debug)]
enum Cut {
    Before,
    After,
    Torn,
}
#[derive(Clone)]
struct Disk {
    corrupt_write_once: Option<u64>,
    sectors: u64,
    durable: [Sector; REQUIRED_SECTORS as usize],
    cache: [Sector; REQUIRED_SECTORS as usize],
    boundary: usize,
    writes: usize,
    flushes: usize,
    trace: Vec<char>,
    cut: Option<(usize, Cut)>,
    offline: bool,
}
impl Disk {
    fn blank() -> Self {
        Self {
            corrupt_write_once: None,
            sectors: REQUIRED_SECTORS,
            durable: [[0; SECTOR_BYTES]; REQUIRED_SECTORS as usize],
            cache: [[0; SECTOR_BYTES]; REQUIRED_SECTORS as usize],
            boundary: 0,
            writes: 0,
            flushes: 0,
            trace: vec![],
            cut: None,
            offline: false,
        }
    }
    fn cold(mut self) -> Self {
        self.cache = self.durable;
        self.offline = false;
        self.cut = None;
        self.boundary = 0;
        self.trace.clear();
        self
    }
    fn begin(&mut self, kind: char, lba: u64, deadline: u64) -> Result<Option<Cut>, Fault> {
        if self.offline {
            return Err(Fault::Offline);
        }
        if deadline == 0 || deadline == u64::MAX {
            return Err(Fault::Deadline);
        }
        if lba >= REQUIRED_SECTORS {
            return Err(Fault::Bounds);
        }
        self.boundary += 1;
        self.trace.push(kind);
        Ok(self
            .cut
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
        self.sectors
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Fault> {
        let cut = self.begin('r', lba, deadline)?;
        if cut.is_some() {
            self.lost()?;
        }
        *out = self.cache[lba as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Fault> {
        let cut = self.begin('w', lba, deadline)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        self.writes += 1;
        self.cache[lba as usize] = *bytes;
        if self.corrupt_write_once == Some(lba) {
            self.cache[lba as usize][70] ^= 1;
            self.corrupt_write_once = None;
        }
        if let Some(cut) = cut {
            match cut {
                Cut::After => self.durable[lba as usize] = *bytes,
                Cut::Torn => self.durable[lba as usize][..257].copy_from_slice(&bytes[..257]),
                Cut::Before => unreachable!(),
            };
            return self.lost();
        }
        Ok(())
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Fault> {
        let cut = self.begin('f', 0, deadline)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        self.flushes += 1;
        if matches!(cut, Some(Cut::Torn)) {
            for i in (0..REQUIRED_SECTORS as usize).step_by(2) {
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
fn generation(id: u64) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(id).unwrap(),
        cohort: digest(&id.to_le_bytes()),
        supervisor_image: digest(&[id as u8, 1]),
        abi: digest(b"internal ABI1"),
        health_contract: digest(b"storage+root health1"),
        health_version: 1,
        required_checks: 3,
    }
}
fn formatted() -> Store<Disk> {
    Store::format_new(
        Disk::blank(),
        generation(1),
        b"owner-data",
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("format"))
}
fn opened(disk: Disk) -> Store<Disk> {
    Store::open(disk.cold(), DEADLINE).unwrap_or_else(|failure| panic!("open: {:?}", failure.error))
}
fn execute(store: &mut Store<Disk>, request: Request<'_>) -> Receipt {
    let id = store.next_operation().unwrap();
    store.execute(id, request, DEADLINE).unwrap()
}
fn report(plan: BootPlan) -> AdmissionReport {
    AdmissionReport {
        generation: plan.manifest.generation,
        boot_serial: plan.serial,
        process_stamp: digest(&plan.serial.to_le_bytes()),
        cohort: plan.manifest.cohort,
        supervisor_image: plan.manifest.supervisor_image,
        abi: plan.manifest.abi,
        health_contract: plan.manifest.health_contract,
        health_version: plan.manifest.health_version,
    }
}
fn boot(store: &mut Store<Disk>) -> AdmissionReport {
    let selected = store.selected_manifest(DEADLINE).unwrap();
    execute(store, Request::BeginBoot(selected.generation));
    let plan = store.boot_plan(DEADLINE).unwrap();
    let evidence = report(plan);
    execute(store, Request::Admission(evidence));
    evidence
}
fn healthy(store: &mut Store<Disk>, admitted: AdmissionReport) {
    let probe = store.root.user_digest;
    execute(
        store,
        Request::Health(HealthReport {
            admitted,
            outcome: HealthOutcome::CriticalPassed,
            observed_checks: 3,
            storage_probe: probe,
        }),
    );
}
fn accepted_a() -> Store<Disk> {
    let mut store = formatted();
    let admitted = boot(&mut store);
    healthy(&mut store, admitted);
    store
}
fn read_user(store: &mut Store<Disk>) -> Vec<u8> {
    let mut out = [0; PAYLOAD_BYTES];
    let len = store
        .read_mutable(ObjectId::user_data(), &mut out, DEADLINE)
        .unwrap();
    out[..len].to_vec()
}
fn pending_b() -> Store<Disk> {
    let mut store = accepted_a();
    execute(&mut store, Request::Stage(&generation(2)));
    execute(&mut store, Request::Activate(GenerationId::new(2).unwrap()));
    store
}

fn failed_b(outcome: HealthOutcome) -> (Store<Disk>, AdmissionReport, Receipt) {
    let mut store = pending_b();
    let admitted = boot(&mut store);
    let receipt = execute(
        &mut store,
        Request::Health(HealthReport {
            admitted,
            outcome,
            observed_checks: 0,
            storage_probe: ZERO,
        }),
    );
    (store, admitted, receipt)
}

#[test]
fn last_failure_starts_none_and_survives_health_ring_and_manifest_slot_reuse() {
    assert_eq!(formatted().last_failure().unwrap(), None);
    assert_eq!(accepted_a().last_failure().unwrap(), None);
    for (outcome, reason) in [
        (HealthOutcome::ProcessFault, LastFailureReason::ProcessFault),
        (
            HealthOutcome::MissingProgress,
            LastFailureReason::MissingProgress,
        ),
        (
            HealthOutcome::StorageFailure,
            LastFailureReason::StorageFailure,
        ),
    ] {
        let (mut store, admitted, receipt) = failed_b(outcome);
        let failure = store.last_failure().unwrap().unwrap();
        assert_eq!(failure.generation, generation(2).generation);
        assert_eq!(failure.supervisor_image, generation(2).supervisor_image);
        assert_eq!(failure.process_stamp, Some(admitted.process_stamp));
        assert_eq!(failure.boot_serial, admitted.boot_serial);
        assert_eq!(failure.attempts, 1);
        assert_eq!(failure.reason, reason);
        assert_eq!(failure.operation, receipt.operation);
        assert_eq!(failure.sequence, receipt.sequence);
        let a = boot(&mut store);
        healthy(&mut store, a);
        for value in 0u64..24 {
            execute(
                &mut store,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &value.to_le_bytes(),
                },
            );
        }
        execute(&mut store, Request::Stage(&generation(3)));
        assert!(!store.root.generations.iter().any(|entry| entry.id == 2));
        execute(&mut store, Request::SelectKnownGood);
        let mut store = opened(store.into_device());
        assert_eq!(store.last_failure().unwrap(), Some(failure));
        assert_eq!(store.selected_manifest(DEADLINE).unwrap(), generation(1));
        assert_eq!(read_user(&mut store), 23u64.to_le_bytes());
        let reads = store.device.boundary;
        assert_eq!(store.last_failure().unwrap(), Some(failure));
        assert_eq!(store.device.boundary, reads);
    }
}

#[test]
fn exhausted_candidate_records_its_identity_before_a_is_charged_with_optional_stamp() {
    for admitted_last in [false, true] {
        let mut store = pending_b();
        for _ in 0..3 {
            execute(&mut store, Request::BeginBoot(generation(2).generation));
        }
        let b = store.boot_plan(DEADLINE).unwrap();
        let stamp = if admitted_last {
            let observed = report(b);
            execute(&mut store, Request::Admission(observed));
            Some(observed.process_stamp)
        } else {
            None
        };
        assert_eq!(store.last_failure().unwrap(), None);
        let receipt = execute(&mut store, Request::BeginBoot(generation(2).generation));
        let a = store.boot_plan(DEADLINE).unwrap();
        assert_eq!(a.manifest, generation(1));
        assert_eq!(a.attempt, 1);
        assert_eq!(a.serial, b.serial + 1);
        let failure = store.last_failure().unwrap().unwrap();
        assert_eq!(failure.generation, generation(2).generation);
        assert_eq!(failure.supervisor_image, generation(2).supervisor_image);
        assert_eq!(failure.boot_serial, b.serial);
        assert_eq!(failure.attempts, 3);
        assert_eq!(failure.process_stamp, stamp);
        assert_eq!(failure.reason, LastFailureReason::AttemptBudgetExhausted);
        assert_eq!(failure.operation, receipt.operation);
        assert_eq!(failure.sequence, receipt.sequence);
        let mut store = opened(store.into_device());
        assert_eq!(store.last_failure().unwrap(), Some(failure));
        assert_eq!(store.boot_plan(DEADLINE).unwrap(), a);
        assert_eq!(read_user(&mut store), b"owner-data");
    }
}

#[test]
fn exhaustion_without_any_known_good_latches_recovery_with_truthful_capsule() {
    let mut store = formatted();
    for _ in 0..3 {
        execute(&mut store, Request::BeginBoot(generation(1).generation));
    }
    let old = store.boot_plan(DEADLINE).unwrap();
    execute(&mut store, Request::BeginBoot(generation(1).generation));
    let failure = store.last_failure().unwrap().unwrap();
    assert_eq!(failure.generation, generation(1).generation);
    assert_eq!(failure.boot_serial, old.serial);
    assert_eq!(failure.process_stamp, None);
    assert_eq!(failure.reason, LastFailureReason::AttemptBudgetExhausted);
    assert_eq!(store.known_good(), None);
    let mut store = opened(store.into_device());
    assert_eq!(store.boot_plan(DEADLINE), Err(Error::RecoveryRequired));
    assert_eq!(store.last_failure().unwrap(), Some(failure));
    assert_eq!(read_user(&mut store), b"owner-data");
}

#[test]
fn newer_actual_report_replaces_only_the_one_last_failure_and_stale_report_cannot() {
    let (mut store, old_admitted, _) = failed_b(HealthOutcome::ProcessFault);
    let first = store.last_failure().unwrap().unwrap();
    execute(&mut store, Request::Stage(&generation(3)));
    execute(&mut store, Request::Activate(generation(3).generation));
    let new_admitted = boot(&mut store);
    let before = store.device.durable;
    let writes = store.device.writes;
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::Health(HealthReport {
                admitted: old_admitted,
                outcome: HealthOutcome::StorageFailure,
                observed_checks: 0,
                storage_probe: ZERO,
            }),
            DEADLINE
        ),
        Err(Error::StaleHealth)
    );
    assert_eq!(store.last_failure().unwrap(), Some(first));
    assert_eq!(store.device.writes, writes);
    assert_eq!(store.device.durable, before);
    execute(
        &mut store,
        Request::Health(HealthReport {
            admitted: new_admitted,
            outcome: HealthOutcome::MissingProgress,
            observed_checks: 0,
            storage_probe: ZERO,
        }),
    );
    let second = store.last_failure().unwrap().unwrap();
    assert_eq!(second.generation, generation(3).generation);
    assert_eq!(second.supervisor_image, generation(3).supervisor_image);
    assert_eq!(second.reason, LastFailureReason::MissingProgress);
    assert!(second.boot_serial > first.boot_serial);
    assert!(second.operation.get() > first.operation.get());
    assert!(second.sequence > first.sequence);
}

fn failure_publication_matrix(base: Store<Disk>, request: Request<'_>) {
    let previous = base.last_failure().unwrap();
    let original = base.into_device().cold();
    let mut full = opened(original.clone());
    let id = full.next_operation().unwrap();
    let start = full.device.boundary;
    full.execute(id, request, DEADLINE).unwrap();
    let total = full.device.boundary - start;
    let expected = full.last_failure().unwrap().unwrap();
    for step in 1..=total {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let mut store = opened(original.clone());
            let start = store.device.boundary;
            store.device.cut = Some((start + step, cut));
            assert!(store.execute(id, request, DEADLINE).is_err());
            if store.poisoned {
                assert_eq!(store.last_failure(), Err(Error::NeedsRecovery));
            }
            let mut store = opened(store.into_device());
            let actual = store.last_failure().unwrap();
            assert!(actual == previous || actual == Some(expected));
            store.execute(id, request, DEADLINE).unwrap();
            assert_eq!(store.last_failure().unwrap(), Some(expected));
            assert_eq!(store.root.last_operation, id.get());
            assert_eq!(read_user(&mut store), b"owner-data");
            let writes = store.device.writes;
            assert!(store.execute(id, request, DEADLINE).unwrap().replayed);
            assert_eq!(store.last_failure().unwrap(), Some(expected));
            assert_eq!(store.device.writes, writes);
        }
    }
}

#[test]
fn failure_capsule_publication_is_atomic_at_every_io_boundary_and_torn_write() {
    for outcome in [
        HealthOutcome::ProcessFault,
        HealthOutcome::MissingProgress,
        HealthOutcome::StorageFailure,
    ] {
        let mut store = pending_b();
        let admitted = boot(&mut store);
        failure_publication_matrix(
            store,
            Request::Health(HealthReport {
                admitted,
                outcome,
                observed_checks: 0,
                storage_probe: ZERO,
            }),
        );
    }
    for with_stamp in [false, true] {
        let mut store = pending_b();
        for _ in 0..3 {
            execute(&mut store, Request::BeginBoot(generation(2).generation));
        }
        if with_stamp {
            let admitted = report(store.boot_plan(DEADLINE).unwrap());
            execute(&mut store, Request::Admission(admitted));
        }
        failure_publication_matrix(store, Request::BeginBoot(generation(2).generation));
    }
    let (mut store, _, _) = failed_b(HealthOutcome::ProcessFault);
    execute(&mut store, Request::Stage(&generation(3)));
    execute(&mut store, Request::Activate(generation(3).generation));
    let admitted = boot(&mut store);
    failure_publication_matrix(
        store,
        Request::Health(HealthReport {
            admitted,
            outcome: HealthOutcome::MissingProgress,
            observed_checks: 0,
            storage_probe: ZERO,
        }),
    );
}

#[test]
fn failure_capsule_recovery_can_itself_be_interrupted_without_losing_identity() {
    let mut base = pending_b();
    let admitted = boot(&mut base);
    let request = Request::Health(HealthReport {
        admitted,
        outcome: HealthOutcome::ProcessFault,
        observed_checks: 0,
        storage_probe: ZERO,
    });
    let original = base.into_device().cold();
    let mut full = opened(original.clone());
    let id = full.next_operation().unwrap();
    let start = full.device.boundary;
    full.execute(id, request, DEADLINE).unwrap();
    let prepare_flush = full.device.trace[start..]
        .iter()
        .position(|&kind| kind == 'f')
        .unwrap()
        + 1;
    let expected = full.last_failure().unwrap().unwrap();
    let mut interrupted = opened(original);
    let start = interrupted.device.boundary;
    interrupted.device.cut = Some((start + prepare_flush, Cut::After));
    assert!(interrupted.execute(id, request, DEADLINE).is_err());
    let prepared = interrupted.into_device().cold();
    let recovered = opened(prepared.clone());
    assert_eq!(recovered.last_failure().unwrap(), Some(expected));
    for step in 1..=recovered.device.boundary {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let mut disk = prepared.clone();
            disk.cut = Some((step, cut));
            let rejected = Store::open(disk, DEADLINE)
                .err()
                .expect("actual recovery interruption");
            let mut store = opened(rejected.device);
            assert_eq!(store.last_failure().unwrap(), Some(expected));
            let writes = store.device.writes;
            assert!(store.execute(id, request, DEADLINE).unwrap().replayed);
            assert_eq!(store.device.writes, writes);
        }
    }
}

fn reseal_record(bytes: &mut Sector) {
    let checksum = digest(&bytes[..480]);
    bytes[480..].copy_from_slice(&checksum);
}

#[test]
fn capsule_checksum_reserved_flags_optional_stamp_and_counter_relations_fail_closed() {
    let (store, _, _) = failed_b(HealthOutcome::ProcessFault);
    let good = codec::root(&store.root);
    assert_eq!(codec::decode_root(&good), Some(store.root));
    for offset in 64 + 272..64 + 384 {
        for bit in 0..8 {
            let mut bad = good;
            bad[offset] ^= 1 << bit;
            assert!(codec::decode_root(&bad).is_none());
        }
    }
    for (offset, value) in [
        (272, 2),
        (273, 0),
        (273, 5),
        (274, 0),
        (274, 4),
        (275, 2),
        (276, 1),
        (279, 1),
        (376, 1),
        (383, 1),
    ] {
        let mut bad = good;
        bad[64 + offset] = value;
        reseal_record(&mut bad);
        assert!(codec::decode_root(&bad).is_none(), "offset{offset}");
    }
    for (offset, value) in [
        (280, 0),
        (280, u64::MAX),
        (288, 0),
        (288, store.root.boot_serial + 1),
        (296, 0),
        (296, store.root.last_operation + 1),
        (304, store.root.sequence + 1),
    ] {
        let mut bad = good;
        bad[64 + offset..64 + offset + 8].copy_from_slice(&value.to_le_bytes());
        reseal_record(&mut bad);
        assert!(codec::decode_root(&bad).is_none(), "wide{offset}");
    }
    for range in [344..376, 312..344] {
        let mut bad = good;
        bad[64 + range.start..64 + range.end].fill(0);
        reseal_record(&mut bad);
        assert!(codec::decode_root(&bad).is_none());
    }
    let mut bad = good;
    bad[64 + 275] = 0;
    bad[64 + 344..64 + 376].fill(0);
    reseal_record(&mut bad);
    assert!(
        codec::decode_root(&bad).is_none(),
        "report failure needs admission"
    );
    let initial = formatted();
    let empty = codec::root(&initial.root);
    for offset in 64 + 272..64 + 384 {
        let mut bad = empty;
        bad[offset] = 1;
        reseal_record(&mut bad);
        assert!(
            codec::decode_root(&bad).is_none(),
            "noncanonical None byte{offset}"
        );
    }
}

#[test]
fn damaged_capsule_uses_only_valid_root_recovery_and_never_reformats_userdata() {
    let (mut store, _, _) = failed_b(HealthOutcome::ProcessFault);
    let expected = store.last_failure().unwrap();
    for byte in 0..24 {
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &[byte],
            },
        );
    }
    let sequence = store.root.sequence;
    let mut disk = store.into_device().cold();
    disk.durable[(sequence % 2) as usize][64 + 344] ^= 1;
    let mut recovered = opened(disk.clone());
    assert_eq!(recovered.last_failure().unwrap(), expected);
    assert_eq!(read_user(&mut recovered), [23]);
    for slot in 0..2 {
        disk.durable[slot][64 + 275] = 0;
        // A false absent flag with a retained nonzero stamp is noncanonical,
        // even if an untrusted party recomputes its integrity checksum.
        reseal_record(&mut disk.durable[slot]);
    }
    let disk = disk.cold();
    let before = disk.durable;
    let writes = disk.writes;
    let rejected = Store::open(disk, DEADLINE)
        .err()
        .expect("both root capsules invalid");
    assert_eq!(rejected.error, Error::Corrupt);
    assert_eq!(rejected.device.durable, before);
    assert_eq!(rejected.device.writes, writes);
    let refused = Store::format_new(
        rejected.device,
        generation(1),
        b"",
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    )
    .err()
    .expect("no destructive fallback formatter");
    assert_eq!(refused.error, Error::NotBlank);
    assert_eq!(refused.device.durable, before);
}

#[test]
fn version_one_future_and_mixed_roots_are_refused_without_migration_or_writes() {
    for version in [0u16, 1, 3, u16::MAX] {
        let disk = accepted_a().into_device().cold();
        for mixed in [false, true] {
            let mut disk = disk.clone();
            for slot in 0..if mixed { 1 } else { 2 } {
                disk.durable[slot][8..10].copy_from_slice(&version.to_le_bytes());
                if version == 1 {
                    disk.durable[slot][32..34].copy_from_slice(&272u16.to_le_bytes());
                    disk.durable[slot][336..480].fill(0);
                }
                reseal_record(&mut disk.durable[slot]);
            }
            let disk = disk.cold();
            let before = disk.durable;
            let writes = disk.writes;
            let rejected = Store::open(disk, DEADLINE)
                .err()
                .expect("unsupported format");
            assert_eq!(rejected.error, Error::Unsupported);
            assert_eq!(rejected.device.durable, before);
            assert_eq!(rejected.device.writes, writes);
            let refused = Store::format_new(
                rejected.device,
                generation(1),
                b"",
                BootPolicy::new(3).unwrap(),
                DEADLINE,
            )
            .err()
            .expect("never autoformat legacy data");
            assert_eq!(refused.error, Error::NotBlank);
            assert_eq!(refused.device.durable, before);
        }
    }
}

#[test]
fn capsule_operation_sequence_reaches_last_valid_id_without_wrap_or_reuse() {
    let mut store = pending_b();
    let admitted = boot(&mut store);
    store.root.last_operation = u64::MAX - 2;
    store.root.sequence = u64::MAX - 1;
    let id = store.next_operation().unwrap();
    assert_eq!(id.get(), u64::MAX - 1);
    let request = Request::Health(HealthReport {
        admitted,
        outcome: HealthOutcome::ProcessFault,
        observed_checks: 0,
        storage_probe: ZERO,
    });
    let receipt = store.execute(id, request, DEADLINE).unwrap();
    assert_eq!(receipt.sequence, u64::MAX);
    let failure = store.last_failure().unwrap().unwrap();
    assert_eq!(failure.operation, id);
    assert_eq!(failure.sequence, u64::MAX);
    let mut store = opened(store.into_device());
    assert_eq!(store.next_operation(), Err(Error::Exhausted));
    assert_eq!(store.last_failure().unwrap(), Some(failure));
    let writes = store.device.writes;
    assert!(store.execute(id, request, DEADLINE).unwrap().replayed);
    assert_eq!(store.device.writes, writes);
}

#[test]
fn exhausted_boot_serial_does_not_publish_a_partial_new_capsule_or_selection() {
    let mut store = pending_b();
    for _ in 0..3 {
        execute(&mut store, Request::BeginBoot(generation(2).generation));
    }
    store.root.boot_serial = u64::MAX;
    let before = store.root;
    let disk = store.device.durable;
    let writes = store.device.writes;
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::BeginBoot(generation(2).generation),
            DEADLINE
        ),
        Err(Error::Exhausted)
    );
    assert_eq!(store.root, before);
    assert_eq!(store.last_failure().unwrap(), None);
    assert_eq!(store.device.durable, disk);
    assert_eq!(store.device.writes, writes);
}

#[test]
fn durable_counter_getters_survive_health_rollback_manual_selection_without_io() {
    fn assert_counters(store: &Store<Disk>, serial: u64, highest: u64) {
        let boundary = store.device.boundary;
        let writes = store.device.writes;
        let flushes = store.device.flushes;
        assert_eq!(store.committed_boot_serial(), Ok(serial));
        assert_eq!(store.highest_generation(), Ok(highest));
        assert_eq!(store.device.boundary, boundary);
        assert_eq!(store.device.writes, writes);
        assert_eq!(store.device.flushes, flushes);
    }
    let mut store = formatted();
    assert_counters(&store, 0, 1);
    let a = boot(&mut store);
    healthy(&mut store, a);
    let mut store = opened(store.into_device());
    assert_counters(&store, 1, 1);
    execute(&mut store, Request::Stage(&generation(2)));
    execute(&mut store, Request::Activate(generation(2).generation));
    let b = boot(&mut store);
    execute(
        &mut store,
        Request::Health(HealthReport {
            admitted: b,
            outcome: HealthOutcome::ProcessFault,
            observed_checks: 0,
            storage_probe: ZERO,
        }),
    );
    let mut store = opened(store.into_device());
    assert_counters(&store, 2, 2);
    assert_eq!(store.selected_manifest(DEADLINE).unwrap(), generation(1));
    let a = boot(&mut store);
    healthy(&mut store, a);
    execute(&mut store, Request::Stage(&generation(3)));
    execute(&mut store, Request::Activate(generation(3).generation));
    execute(&mut store, Request::SelectKnownGood);
    let a = boot(&mut store);
    healthy(&mut store, a);
    let store = opened(store.into_device());
    assert_counters(&store, 4, 3);
}

#[test]
fn durable_counter_getters_refuse_uncertain_execution_without_touching_backend() {
    let mut store = accepted_a();
    let id = store.next_operation().unwrap();
    let start = store.device.boundary;
    store.device.cut = Some((start + 5, Cut::After));
    assert!(
        store
            .execute(
                id,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: b"uncertain publication",
                },
                DEADLINE
            )
            .is_err()
    );
    assert!(store.poisoned);
    let boundary = store.device.boundary;
    assert_eq!(store.committed_boot_serial(), Err(Error::NeedsRecovery));
    assert_eq!(store.highest_generation(), Err(Error::NeedsRecovery));
    assert_eq!(store.device.boundary, boundary);
}

#[test]
fn format_does_not_fabricate_known_good_or_health() {
    let mut store = formatted();
    assert_eq!(store.known_good(), None);
    assert_eq!(store.boot_plan(DEADLINE), Err(Error::Phase));
    let original = store.device.writes;
    let id = store.next_operation().unwrap();
    assert_eq!(
        store.execute(id, Request::Stage(&generation(2)), DEADLINE),
        Err(Error::NoSpace)
    );
    assert_eq!(store.device.writes, original);
    let admitted = boot(&mut store);
    assert_eq!(store.known_good(), None);
    let mut forged = admitted;
    forged.process_stamp = digest(b"foreign process");
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::Admission(forged),
            DEADLINE
        ),
        Err(Error::Phase)
    );
    let writes = store.device.writes;
    for field in 0..8 {
        let mut stale = admitted;
        match field {
            0 => stale.boot_serial += 1,
            1 => stale.generation = GenerationId::new(2).unwrap(),
            2 => stale.process_stamp = ZERO,
            3 => stale.cohort = ZERO,
            4 => stale.supervisor_image = ZERO,
            5 => stale.abi = ZERO,
            6 => stale.health_contract = ZERO,
            _ => stale.health_version = 2,
        };
        assert_eq!(
            store.execute(
                store.next_operation().unwrap(),
                Request::Health(HealthReport {
                    admitted: stale,
                    outcome: HealthOutcome::CriticalPassed,
                    observed_checks: 3,
                    storage_probe: store.root.user_digest
                }),
                DEADLINE
            ),
            Err(Error::StaleHealth)
        );
    }
    assert_eq!(store.device.writes, writes);
    healthy(&mut store, admitted);
    assert_eq!(store.known_good(), GenerationId::new(1));
}
#[test]
fn modeled_failure_before_any_known_good_latches_recovery_and_preserves_data() {
    let mut store = formatted();
    let admitted = boot(&mut store);
    execute(
        &mut store,
        Request::Health(HealthReport {
            admitted,
            outcome: HealthOutcome::ProcessFault,
            observed_checks: 0,
            storage_probe: ZERO,
        }),
    );
    assert_eq!(store.known_good(), None);
    assert_eq!(store.boot_plan(DEADLINE), Err(Error::RecoveryRequired));
    assert_eq!(read_user(&mut store), b"owner-data");
    let mut store = opened(store.into_device());
    assert_eq!(
        store.selected_manifest(DEADLINE),
        Err(Error::RecoveryRequired)
    );
    assert_eq!(read_user(&mut store), b"owner-data");
}
#[test]
fn modeled_a_health_mutable_b_failure_and_a_reboot_fit_without_reset() {
    let mut store = accepted_a();
    let mut ids = Vec::new();
    ids.push(execute(
        &mut store,
        Request::WriteMutable {
            object: ObjectId::user_data(),
            bytes: b"new owner data",
        },
    ));
    ids.push(execute(&mut store, Request::Stage(&generation(2))));
    ids.push(execute(
        &mut store,
        Request::Activate(GenerationId::new(2).unwrap()),
    ));
    let admitted_b = boot(&mut store);
    assert_eq!(store.known_good(), GenerationId::new(1));
    let probe = store.root.user_digest;
    ids.push(execute(
        &mut store,
        Request::Health(HealthReport {
            admitted: admitted_b,
            outcome: HealthOutcome::MissingProgress,
            observed_checks: 1,
            storage_probe: probe,
        }),
    ));
    assert_eq!(store.selected_manifest(DEADLINE).unwrap(), generation(1));
    assert_eq!(read_user(&mut store), b"new owner data");
    let mut store = opened(store.into_device());
    let admitted_a = boot(&mut store);
    assert!(admitted_a.boot_serial > admitted_b.boot_serial);
    healthy(&mut store, admitted_a);
    assert_eq!(store.known_good(), GenerationId::new(1));
    assert_eq!(read_user(&mut store), b"new owner data");
    assert!(store.root.last_operation > JOURNAL_SLOTS);
    let latest = store.root.last_operation;
    let repeated = store
        .execute(
            OperationId::new(ids.last().unwrap().operation.get()).unwrap(),
            Request::Health(HealthReport {
                admitted: admitted_b,
                outcome: HealthOutcome::MissingProgress,
                observed_checks: 1,
                storage_probe: store.root.user_digest,
            }),
            DEADLINE,
        )
        .unwrap();
    assert!(repeated.replayed);
    assert_eq!(repeated.sequence, ids.last().unwrap().sequence);
    assert_eq!(store.root.last_operation, latest);
}
#[test]
fn bounded_pending_and_known_good_boots_never_loop_forever() {
    let mut store = pending_b();
    for attempt in 1..=3 {
        execute(
            &mut store,
            Request::BeginBoot(GenerationId::new(2).unwrap()),
        );
        let plan = store.boot_plan(DEADLINE).unwrap();
        assert_eq!(plan.attempt, attempt);
        assert_eq!(plan.manifest.generation, GenerationId::new(2).unwrap());
    }
    execute(
        &mut store,
        Request::BeginBoot(GenerationId::new(2).unwrap()),
    );
    let plan = store.boot_plan(DEADLINE).unwrap();
    assert_eq!(plan.manifest, generation(1));
    assert_eq!(plan.attempt, 1);
    assert!(!plan.candidate);
    for _ in 0..2 {
        execute(
            &mut store,
            Request::BeginBoot(GenerationId::new(1).unwrap()),
        );
    }
    execute(
        &mut store,
        Request::BeginBoot(GenerationId::new(1).unwrap()),
    );
    assert_eq!(store.boot_plan(DEADLINE), Err(Error::RecoveryRequired));
    execute(&mut store, Request::SelectKnownGood);
    assert_eq!(store.selected_manifest(DEADLINE).unwrap(), generation(1));
    let admitted = boot(&mut store);
    healthy(&mut store, admitted);
}
#[test]
fn duplicate_conflict_stale_and_out_of_order_requests_never_write() {
    let mut store = accepted_a();
    let id = store.next_operation().unwrap();
    let receipt = store
        .execute(
            id,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: b"first",
            },
            DEADLINE,
        )
        .unwrap();
    let writes = store.device.writes;
    assert_eq!(
        store
            .execute(
                id,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: b"first"
                },
                DEADLINE
            )
            .unwrap(),
        Receipt {
            replayed: true,
            ..receipt
        }
    );
    assert_eq!(
        store.execute(
            id,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: b"different"
            },
            DEADLINE
        ),
        Err(Error::Conflict)
    );
    assert_eq!(store.device.writes, writes);
    for i in 0..24 {
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &[i],
            },
        );
    }
    let writes = store.device.writes;
    assert_eq!(
        store.execute(
            id,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: b"first"
            },
            DEADLINE
        ),
        Err(Error::StaleOperation)
    );
    let future = OperationId::new(store.root.last_operation + 2).unwrap();
    assert_eq!(
        store.execute(future, Request::SelectKnownGood, DEADLINE),
        Err(Error::OutOfOrder)
    );
    assert_eq!(store.device.writes, writes);
}

// A cut may happen before/after any operation or while a sector/flush tears.
// Recovery must preserve referenced state, never expose partial payloads, and a
// retry of a durably committed ID cannot publish a second logical operation.
fn interruption_matrix(base: Store<Disk>, request: Request<'_>, old: &[u8], new: &[u8]) {
    let original = base.into_device().cold();
    let mut full = opened(original.clone());
    let id = full.next_operation().unwrap();
    let start = full.device.boundary;
    full.execute(id, request, DEADLINE).unwrap();
    let total = full.device.boundary - start;
    for step in 1..=total {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let mut store = opened(original.clone());
            let start = store.device.boundary;
            store.device.cut = Some((start + step, cut));
            let result = store.execute(id, request, DEADLINE);
            assert!(
                matches!(result, Err(Error::Io(Fault::Power))),
                "step{step} {cut:?}"
            );
            if store.poisoned {
                assert_eq!(
                    store.execute(id, request, DEADLINE),
                    Err(Error::NeedsRecovery)
                );
            }
            let mut reopened = opened(store.into_device());
            let actual = read_user(&mut reopened);
            assert!(
                actual == old || actual == new,
                "partial state step{step} {cut:?}"
            );
            let receipt = reopened.execute(id, request, DEADLINE).unwrap();
            assert_eq!(receipt.operation, id);
            assert_eq!(reopened.root.last_operation, id.get());
            let writes = reopened.device.writes;
            assert!(reopened.execute(id, request, DEADLINE).unwrap().replayed);
            assert_eq!(reopened.device.writes, writes);
            assert_eq!(read_user(&mut reopened), new);
        }
    }
}
#[test]
fn every_read_write_flush_and_torn_boundary_preserves_old_or_new_mutable_data() {
    interruption_matrix(
        accepted_a(),
        Request::WriteMutable {
            object: ObjectId::user_data(),
            bytes: b"new complete state",
        },
        b"owner-data",
        b"new complete state",
    );
}
#[test]
fn journal_reuse_interruption_does_not_reset_highwater_or_duplicate_commit() {
    let mut store = accepted_a();
    for i in 0..32 {
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &[i],
            },
        );
    }
    let old = [31];
    interruption_matrix(
        store,
        Request::WriteMutable {
            object: ObjectId::user_data(),
            bytes: b"after ring reuse",
        },
        &old,
        b"after ring reuse",
    );
}
#[test]
fn generation_stage_activate_failure_and_success_are_atomic_at_each_boundary() {
    for scenario in 0..4 {
        let mut base = accepted_a();
        let request = match scenario {
            0 => Request::Stage(&generation(2)),
            1 => {
                execute(&mut base, Request::Stage(&generation(2)));
                Request::Activate(GenerationId::new(2).unwrap())
            }
            _ => {
                execute(&mut base, Request::Stage(&generation(2)));
                execute(&mut base, Request::Activate(GenerationId::new(2).unwrap()));
                let admitted = boot(&mut base);
                Request::Health(HealthReport {
                    admitted,
                    outcome: if scenario == 2 {
                        HealthOutcome::ProcessFault
                    } else {
                        HealthOutcome::CriticalPassed
                    },
                    observed_checks: 3,
                    storage_probe: base.root.user_digest,
                })
            }
        };
        let disk = base.into_device().cold();
        let mut full = opened(disk.clone());
        let id = full.next_operation().unwrap();
        let start = full.device.boundary;
        full.execute(id, request, DEADLINE).unwrap();
        let steps = full.device.boundary - start;
        let expected = full.root;
        for step in 1..=steps {
            for cut in [Cut::Before, Cut::After, Cut::Torn] {
                let mut store = opened(disk.clone());
                let start = store.device.boundary;
                store.device.cut = Some((start + step, cut));
                assert!(store.execute(id, request, DEADLINE).is_err());
                let mut store = opened(store.into_device());
                assert_eq!(read_user(&mut store), b"owner-data");
                store.execute(id, request, DEADLINE).unwrap();
                assert_eq!(store.root, expected);
            }
        }
    }
}
#[test]
fn active_known_good_content_is_not_overwritten_or_blessed_by_stale_health() {
    let mut store = pending_b();
    let writes = store.device.writes;
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::Stage(&generation(3)),
            DEADLINE
        ),
        Err(Error::NoSpace)
    );
    assert_eq!(store.device.writes, writes);
    let admitted = boot(&mut store);
    let mut bad = admitted;
    bad.boot_serial -= 1;
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::Health(HealthReport {
                admitted: bad,
                outcome: HealthOutcome::CriticalPassed,
                observed_checks: 3,
                storage_probe: store.root.user_digest
            }),
            DEADLINE
        ),
        Err(Error::StaleHealth)
    );
    for (checks, probe) in [
        (0, store.root.user_digest),
        (1, store.root.user_digest),
        (3, ZERO),
    ] {
        assert_eq!(
            store.execute(
                store.next_operation().unwrap(),
                Request::Health(HealthReport {
                    admitted,
                    outcome: HealthOutcome::CriticalPassed,
                    observed_checks: checks,
                    storage_probe: probe
                }),
                DEADLINE
            ),
            Err(Error::StaleHealth)
        );
    }
    assert_eq!(store.known_good(), GenerationId::new(1));
    healthy(&mut store, admitted);
    assert_eq!(store.known_good(), GenerationId::new(2));
    execute(&mut store, Request::Stage(&generation(3)));
    assert_eq!(store.selected_manifest(DEADLINE).unwrap(), generation(2));
}
#[test]
fn corrupt_records_and_short_media_fail_closed_without_formatting_over_data() {
    let store = accepted_a();
    let disk = store.into_device().cold();
    assert!(matches!(
        Store::format_new(
            disk.clone(),
            generation(1),
            b"",
            BootPolicy::new(3).unwrap(),
            DEADLINE
        ),
        Err(RejectedDevice {
            error: Error::NotBlank,
            ..
        })
    ));
    let mut damaged = disk.clone();
    for slot in [0, 1] {
        damaged.durable[slot][40] ^= 1;
    }
    assert!(matches!(
        Store::open(damaged.cold(), DEADLINE),
        Err(RejectedDevice {
            error: Error::Corrupt,
            ..
        })
    ));
    for slot in [GEN_BASE, USER_BASE] {
        let mut damaged = disk.clone();
        damaged.durable[slot as usize][70] ^= 1;
        let writes = damaged.writes;
        match Store::open(damaged.cold(), DEADLINE) {
            Err(rejected) => {
                assert_eq!(rejected.error, Error::Corrupt);
                assert_eq!(rejected.device.writes, writes);
            }
            Ok(_) => panic!("accepted corrupt reference"),
        }
    }
    assert!(matches!(
        Store::open(Disk::blank(), DEADLINE),
        Err(RejectedDevice {
            error: Error::Unformatted,
            ..
        })
    ));
}
#[test]
fn checksums_decoders_are_total_reserved_fields_and_each_bit_are_rejected() {
    let store = accepted_a();
    let root = codec::root(&store.root);
    let op = Operation::from_request::<Fault>(Request::Stage(&generation(2))).unwrap();
    let journal = codec::journal(4, 4, &op);
    let data = codec::data(GEN_KIND, 2, 0, &codec::manifest(&generation(2)));
    for i in 0..SECTOR_BYTES {
        for bit in 0..8 {
            let mut bad = root;
            bad[i] ^= 1 << bit;
            assert!(codec::decode_root(&bad).is_none());
            let mut bad = journal;
            bad[i] ^= 1 << bit;
            assert!(codec::decode_operation(&bad).is_none());
            let mut bad = data;
            bad[i] ^= 1 << bit;
            assert!(codec::decode_data(&bad, GEN_KIND, 2, 0).is_none());
        }
    }
    let mut state = 0x8ad124ffu64;
    for _ in 0..4096 {
        let mut bytes = [0; SECTOR_BYTES];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let _ = codec::decode_root(&bytes);
        let _ = codec::decode_operation(&bytes);
        let _ = codec::decode_data(&bytes, GEN_KIND, 2, 0);
        for len in [0, 1, MANIFEST_BYTES - 1, MANIFEST_BYTES, SECTOR_BYTES] {
            let _ = codec::decode_manifest(&bytes[..len]);
        }
    }
}
#[test]
fn invalid_deadlines_lengths_and_exhausted_ids_reject_before_writes() {
    let mut store = accepted_a();
    let writes = store.device.writes;
    for deadline in [0, u64::MAX] {
        assert_eq!(
            store.execute(
                store.next_operation().unwrap(),
                Request::SelectKnownGood,
                deadline
            ),
            Err(Error::InvalidDeadline)
        );
    }
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &[1; PAYLOAD_BYTES + 1]
            },
            DEADLINE
        ),
        Err(Error::Capacity)
    );
    store.root.last_operation = u64::MAX - 1;
    store.root.sequence = u64::MAX;
    assert_eq!(store.next_operation(), Err(Error::Exhausted));
    assert_eq!(store.device.writes, writes);
}

#[test]
fn many_complete_generation_cycles_reuse_only_completed_history_without_resets() {
    let mut store = accepted_a();
    let first = OperationId::new(1).unwrap();
    let mut prior = store.root.last_operation;
    for generation_id in 2..=20 {
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &[generation_id as u8],
            },
        );
        execute(&mut store, Request::Stage(&generation(generation_id)));
        execute(
            &mut store,
            Request::Activate(GenerationId::new(generation_id).unwrap()),
        );
        let admitted_b = boot(&mut store);
        execute(
            &mut store,
            Request::Health(HealthReport {
                admitted: admitted_b,
                outcome: HealthOutcome::ProcessFault,
                observed_checks: 0,
                storage_probe: ZERO,
            }),
        );
        store = opened(store.into_device());
        assert_eq!(store.selected_manifest(DEADLINE).unwrap(), generation(1));
        let admitted_a = boot(&mut store);
        let probe = store.root.user_digest;
        let receipt = execute(
            &mut store,
            Request::Health(HealthReport {
                admitted: admitted_a,
                outcome: HealthOutcome::CriticalPassed,
                observed_checks: 3,
                storage_probe: probe,
            }),
        );
        let writes = store.device.writes;
        assert_eq!(
            store
                .execute(
                    receipt.operation,
                    Request::Health(HealthReport {
                        admitted: admitted_a,
                        outcome: HealthOutcome::CriticalPassed,
                        observed_checks: 3,
                        storage_probe: probe
                    }),
                    DEADLINE
                )
                .unwrap(),
            Receipt {
                replayed: true,
                ..receipt
            }
        );
        assert_eq!(store.device.writes, writes);
        assert_eq!(read_user(&mut store), [generation_id as u8]);
        assert!(store.root.last_operation > prior);
        prior = store.root.last_operation;
    }
    assert!(store.root.last_operation > 20 * JOURNAL_SLOTS);
    let writes = store.device.writes;
    assert_eq!(
        store.execute(
            first,
            Request::BeginBoot(GenerationId::new(1).unwrap()),
            DEADLINE
        ),
        Err(Error::StaleOperation)
    );
    assert_eq!(store.device.writes, writes);
}
#[test]
fn valid_checksum_does_not_bypass_reserved_fields_or_bounded_root_semantics() {
    let store = accepted_a();
    let good = codec::root(&store.root);
    for (offset, value) in [
        (11, 1),
        (34, 1),
        (64, 255),
        (65, 255),
        (66, 255),
        (67, 255),
        (68, 9),
        (69, 0),
        (70, 255),
        (71, 2),
        (242, 1),
    ] {
        let mut bad = good;
        bad[offset] = value;
        let hash = digest(&bad[..480]);
        bad[480..].copy_from_slice(&hash);
        assert!(codec::decode_root(&bad).is_none(), "offset {offset}");
    }
    let op = Operation::from_request::<Fault>(Request::SelectKnownGood).unwrap();
    let good = codec::journal(4, 4, &op);
    for (offset, value) in [(64, 255), (66, 255), (67, 255), (68, 1), (375, 1), (479, 1)] {
        let mut bad = good;
        bad[offset] = value;
        let hash = digest(&bad[..480]);
        bad[480..].copy_from_slice(&hash);
        assert!(codec::decode_operation(&bad).is_none());
    }
}
#[test]
fn mutable_revision_and_boot_serial_exhaustion_preserve_durable_bytes() {
    let mut store = accepted_a();
    let before = store.device.durable;
    let writes = store.device.writes;
    store.root.user_revision = u64::MAX;
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: b"overflow"
            },
            DEADLINE
        ),
        Err(Error::Corrupt)
    );
    // A forged in-memory root/ref mismatch cannot publish. Test the transition's
    // actual overflow preflight separately while its data record remains valid.
    let op = Operation::from_request::<Fault>(Request::WriteMutable {
        object: ObjectId::user_data(),
        bytes: b"overflow",
    })
    .unwrap();
    assert_eq!(store.transition(&op, DEADLINE), Err(Error::Exhausted));
    store.root.user_revision = 1;
    store.poisoned = false;
    store.root.boot_serial = u64::MAX;
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::BeginBoot(GenerationId::new(1).unwrap()),
            DEADLINE
        ),
        Err(Error::Exhausted)
    );
    assert_eq!(store.device.durable, before);
    assert_eq!(store.device.writes, writes);
}

#[test]
fn interrupted_recovery_itself_is_idempotent_across_every_io_boundary() {
    let mut store = accepted_a();
    for byte in 0..24 {
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &[byte],
            },
        );
    }
    let id = store.next_operation().unwrap();
    let request = Request::WriteMutable {
        object: ObjectId::user_data(),
        bytes: b"recovery survives recovery",
    };
    let start = store.device.boundary;
    // Three reference reads, journal write, then durable PREPARE flush. The
    // acknowledged root is still old; no staging or publish has happened yet.
    store.device.cut = Some((start + 5, Cut::After));
    assert!(matches!(
        store.execute(id, request, DEADLINE),
        Err(Error::Io(Fault::Power))
    ));
    let prepared = store.into_device().cold();
    let successful = opened(prepared.clone());
    let recovery_steps = successful.device.boundary;
    assert_eq!(successful.root.last_operation, id.get());
    for step in 1..=recovery_steps {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let mut disk = prepared.clone();
            disk.cut = Some((step, cut));
            let failure = match Store::open(disk, DEADLINE) {
                Err(failure) => failure,
                Ok(_) => panic!("recovery cut did not execute at {step}"),
            };
            assert!(matches!(failure.error, Error::Io(Fault::Power)));
            let mut store = opened(failure.device);
            assert_eq!(store.root.last_operation, id.get());
            assert_eq!(read_user(&mut store), b"recovery survives recovery");
            let writes = store.device.writes;
            assert!(store.execute(id, request, DEADLINE).unwrap().replayed);
            assert_eq!(store.device.writes, writes);
        }
    }
}
#[test]
fn single_root_copy_damage_recovers_and_short_media_is_never_written() {
    let store = accepted_a();
    let disk = store.into_device().cold();
    for copy in [0, 1] {
        let mut damaged = disk.clone();
        damaged.durable[copy][200] ^= 1;
        let mut store = opened(damaged);
        assert_eq!(store.known_good(), GenerationId::new(1));
        assert_eq!(read_user(&mut store), b"owner-data");
    }
    let mut short = Disk::blank();
    short.sectors = REQUIRED_SECTORS - 1;
    match Store::format_new(
        short,
        generation(1),
        b"",
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    ) {
        Err(failure) => {
            assert_eq!(failure.error, Error::Capacity);
            assert_eq!(failure.device.writes, 0);
            assert_eq!(failure.device.boundary, 0);
        }
        Ok(_) => panic!("short disk accepted"),
    }
}

#[test]
fn acknowledged_corrupt_sector_is_detected_before_claiming_commit() {
    for target in 0..3 {
        let mut store = accepted_a();
        let id = store.next_operation().unwrap();
        let lba = match target {
            0 => 2 + id.get() % JOURNAL_SLOTS,
            1 => USER_BASE + 1,
            _ => (store.root.sequence + 1) % 2,
        };
        store.device.corrupt_write_once = Some(lba);
        let request = Request::WriteMutable {
            object: ObjectId::user_data(),
            bytes: b"verified new state",
        };
        assert_eq!(store.execute(id, request, DEADLINE), Err(Error::Corrupt));
        assert!(store.poisoned);
        assert_eq!(store.root.last_operation, id.get() - 1);
        let mut store = opened(store.into_device());
        let visible = read_user(&mut store);
        assert!(visible == b"owner-data" || visible == b"verified new state");
        store.execute(id, request, DEADLINE).unwrap();
        assert_eq!(read_user(&mut store), b"verified new state");
    }
}
