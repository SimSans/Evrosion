//! Physical journal experiment with independent, read-only snapshot checks.
//! Only runner-created disks are attached; no external disk path is accepted.
use crate::{
    boot::{self, StorageBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    storage::{self, Disk},
};
use ev_store::{GenerationId, GenerationManifest, ObjectId, OperationId, Sector, SectorIo, Store};
use ev_userspace_contract::store_test::{Control, Mode, STORE_BASE, STORE_BLOCKS};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const FIXTURE: &str = "m3-store";
const LIMIT_SECONDS: u64 = 120;
pub(crate) const SNAPSHOT_DEADLINE: u64 = 1;
const EXPECTED_BOOTS: u64 = 15;
const OWNER_A: &[u8] = b"owner-data-A";
const OWNER_B: &[u8] = b"owner-data-B";

#[derive(Clone, Copy, Debug)]
enum Expected {
    Initial,
    Committed,
}

fn pending_a() -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [0x11; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    }
}

#[derive(Debug)]
pub(crate) enum SnapshotError {
    Bounds,
    Deadline,
    ReadOnly,
}

/// This backend cannot repair a snapshot. A committed result is accepted only
/// when opening, checking references and replaying the receipt need no writes.
pub(crate) struct ReadOnlyRegion<'a> {
    bytes: &'a [u8],
    reads: u64,
    mutation_attempts: u64,
}
impl<'a> ReadOnlyRegion<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != storage::DISK_BYTES
            || u64::from(STORE_BLOCKS) != ev_store::REQUIRED_SECTORS
        {
            return Err("journal snapshot has the wrong disk size or store extent".into());
        }
        Ok(Self {
            bytes,
            reads: 0,
            mutation_attempts: 0,
        })
    }
    pub(crate) fn counts(&self) -> (u64, u64) {
        (self.reads, self.mutation_attempts)
    }
}
impl SectorIo for ReadOnlyRegion<'_> {
    type Error = SnapshotError;
    fn sectors(&self) -> u64 {
        u64::from(STORE_BLOCKS)
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        deadline: u64,
    ) -> std::result::Result<(), Self::Error> {
        if deadline != SNAPSHOT_DEADLINE {
            return Err(SnapshotError::Deadline);
        }
        if lba >= self.sectors() {
            return Err(SnapshotError::Bounds);
        }
        let start = (u64::from(STORE_BASE) + lba) as usize * storage::SECTOR_BYTES;
        let bytes = self
            .bytes
            .get(start..start + storage::SECTOR_BYTES)
            .ok_or(SnapshotError::Bounds)?;
        out.copy_from_slice(bytes);
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> std::result::Result<(), Self::Error> {
        self.mutation_attempts += 1;
        Err(SnapshotError::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> std::result::Result<(), Self::Error> {
        self.mutation_attempts += 1;
        Err(SnapshotError::ReadOnly)
    }
}

fn inspect_snapshot(bytes: &[u8], expected: Expected) -> Result<Value> {
    let device = ReadOnlyRegion::new(bytes)?;
    let mut store = Store::open(device, SNAPSHOT_DEADLINE).map_err(|failure| {
        format!(
            "raw snapshot failed read-only open: {:?}; mutation_attempts={}",
            failure.error, failure.device.mutation_attempts
        )
    })?;
    if store.known_good().is_some()
        || store
            .selected_manifest(SNAPSHOT_DEADLINE)
            .map_err(|error| format!("snapshot manifest: {error:?}"))?
            != pending_a()
        || !matches!(
            store.boot_plan(SNAPSHOT_DEADLINE),
            Err(ev_store::Error::Phase)
        )
    {
        return Err(
            "snapshot must retain exact unresolved PendingA with no boot or KnownGood".into(),
        );
    }
    let mut body = [0; ev_store::PAYLOAD_BYTES];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut body, SNAPSHOT_DEADLINE)
        .map_err(|error| format!("snapshot mutable object: {error:?}"))?;
    let (payload, operation, sequence) = match expected {
        Expected::Initial => (OWNER_A, 0, 1),
        Expected::Committed => (OWNER_B, 1, 2),
    };
    if body[..length] != *payload
        || store
            .next_operation()
            .map_err(|error| format!("snapshot high-water: {error:?}"))?
            .get()
            != operation + 1
    {
        return Err("snapshot payload or persistent operation high-water differs".into());
    }
    let mut replayed = false;
    if operation != 0 {
        let receipt = store
            .execute(
                OperationId::new(operation).unwrap(),
                ev_store::Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: OWNER_B,
                },
                SNAPSHOT_DEADLINE,
            )
            .map_err(|error| format!("snapshot original operation replay: {error:?}"))?;
        if !receipt.replayed || receipt.operation.get() != operation || receipt.sequence != sequence
        {
            return Err("snapshot has no exact committed original-operation receipt".into());
        }
        replayed = true;
    }
    let device = store.into_device();
    if device.mutation_attempts != 0 {
        return Err("independent snapshot validation attempted a repair or flush".into());
    }
    Ok(
        json!({"backend":"read-only raw sectors","reads":device.reads,
        "mutation_attempts":device.mutation_attempts,"pending":true,"known_good":null,
        "generation":1,"operation":operation,"sequence":sequence,"replayed":replayed,
        "payload_sha256":format!("{:x}",Sha256::digest(payload))}),
    )
}

/// The control sector is set before a VM starts, so it too must remain unchanged
/// during that VM. Only the dedicated store region may change in the guest.
pub(crate) fn unchanged_guards(before: &[u8], after: &[u8]) -> Result<()> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("journal guard comparison requires exact full disk snapshots".into());
    }
    let region = STORE_BASE as usize * storage::SECTOR_BYTES
        ..(STORE_BASE + STORE_BLOCKS) as usize * storage::SECTOR_BYTES;
    if let Some(index) = before
        .iter()
        .zip(after)
        .enumerate()
        .find_map(|(index, (old, new))| (!region.contains(&index) && old != new).then_some(index))
    {
        return Err(format!(
            "journal changed protected byte {index} (sector {})",
            index / storage::SECTOR_BYTES
        ));
    }
    Ok(())
}

fn snapshot_validation(
    before: &[u8],
    after: &[u8],
    expected: Option<Expected>,
    unchanged: bool,
) -> Result<Value> {
    unchanged_guards(before, after)?;
    if unchanged && before != after {
        return Err("cold Verify changed the persistent disk after its control was set".into());
    }
    let observer = expected
        .map(|state| inspect_snapshot(after, state))
        .transpose()?;
    Ok(json!({"guards_unchanged":true,"control_unchanged":true,
        "verify_unchanged":unchanged,"observer":observer}))
}

fn link(path: &Path, base: &Path) -> Result<Value> {
    let relative = path
        .strip_prefix(base)
        .map_err(|_| "journal evidence escaped its directory")?;
    Ok(json!({"path":relative,"sha256":build::hash_file(path)?}))
}

fn existing_link(path: &Path, base: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            link(path, base).map(Some)
        }
        Ok(_) => Err("journal evidence is not a regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

struct Suite<'a> {
    root: &'a Path,
    evidence: &'a Path,
    manifest: &'a Path,
    phases: Vec<Value>,
    cases: Vec<Value>,
    boots: u64,
}
impl Suite<'_> {
    fn phase(
        &mut self,
        case: &Path,
        disk: &mut Disk,
        name: &str,
        control: Control,
        expected: Option<Expected>,
        unchanged: bool,
    ) -> Result<()> {
        let directory = storage::directory_beneath(
            self.root,
            case.join(name)
                .strip_prefix(self.root)
                .map_err(|_| "journal phase escaped repository")?,
        )?;
        let mut stage = "control";
        let mut initial = None;
        let operation: Result<Value> = (|| {
            disk.journal_control(control)?;
            stage = "before_snapshot";
            let before = disk.bytes()?;
            initial = Some(disk.capture(&directory, "data-before.raw")?);
            stage = "boot";
            self.boots += 1;
            boot::boot_storage(
                &BootOptions {
                    root: Some(self.root.to_owned()),
                    timeout_seconds: LIMIT_SECONDS,
                    ..BootOptions::default()
                },
                StorageBoot {
                    manifest: self.manifest,
                    evidence: &directory,
                    disk,
                    phase: storage::Phase::Write,
                    store: Some(control),
                },
            )?;
            stage = "independent_snapshot_validation";
            let after = disk.bytes()?;
            snapshot_validation(&before, &after, expected, unchanged)
        })();
        // The synchronous boot API reaps its own QEMU child on every path.
        // Preserve actual bytes even if boot/protocol/raw validation failed.
        let captured = disk.capture(&directory, "data-after.raw");
        let boot_record = existing_link(&directory.join("boot/results.json"), &directory);
        let passed = operation.is_ok() && captured.is_ok() && boot_record.is_ok();
        let summary = json!({"schema":1,"kind":"storage-journal-phase","phase":name,
            "mode":control.mode as u8,"cut":control.cut,"passed":passed,"last_stage":stage,
            "before":initial,"after":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),
            "boot":boot_record.as_ref().ok(),"boot_link_error":boot_record.as_ref().err(),
            "validation":operation.as_ref().ok(),"error":operation.as_ref().err()});
        let path = directory.join("phase-result.json");
        storage::json_new(&path, &summary)?;
        self.phases.push(link(&path, self.evidence)?);
        operation?;
        captured?;
        boot_record?;
        Ok(())
    }

    fn case(
        &mut self,
        name: &str,
        baseline: Option<&[u8]>,
        phases: &[(Control, Option<Expected>, bool)],
    ) -> Result<Vec<u8>> {
        let directory = storage::directory_beneath(
            self.root,
            self.evidence
                .join(name)
                .strip_prefix(self.root)
                .map_err(|_| "journal case escaped repository")?,
        )?;
        let mut disk = None;
        let mut final_bytes = None;
        let mut stage = "prepare";
        let operation: Result<()> = (|| {
            disk = Some(Disk::create(self.root, &directory)?);
            let disk = disk.as_mut().ok_or("journal disk missing")?;
            if let Some(baseline) = baseline {
                stage = "restore_baseline";
                disk.restore_snapshot(baseline)?;
                if disk.bytes()? != baseline {
                    return Err(
                        "new journal case did not reproduce its exact initial snapshot".into(),
                    );
                }
            }
            for (index, &(control, expected, unchanged)) in phases.iter().enumerate() {
                stage = "phase";
                let name = format!(
                    "{:02}-{}",
                    index + 1,
                    match control.mode {
                        Mode::Init => "init",
                        Mode::Cut => "cut",
                        Mode::Recover => "recover",
                        Mode::Commit => "commit",
                        Mode::Verify => "verify",
                    }
                );
                self.phase(&directory, disk, &name, control, expected, unchanged)?;
            }
            stage = "final_snapshot";
            final_bytes = Some(disk.bytes()?);
            Ok(())
        })();
        let captured = disk
            .as_ref()
            .map(|disk| disk.capture(&directory, "data-final.raw"))
            .transpose();
        let sealed = disk.as_ref().map(Disk::seal).transpose();
        let path = directory.join("case-result.json");
        storage::json_new(
            &path,
            &json!({"schema":1,"kind":"storage-journal-case","case":name,
                "passed":operation.is_ok() && captured.is_ok() && sealed.is_ok(),
                "last_stage":stage,"error":operation.as_ref().err(),
                "final_disk":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),
                "seal_error":sealed.as_ref().err()}),
        )?;
        self.cases.push(link(&path, self.evidence)?);
        operation?;
        captured?;
        sealed?;
        final_bytes.ok_or_else(|| "journal final snapshot is missing".into())
    }

    fn cases(&mut self) -> Result<()> {
        let baseline = self.case(
            "initial",
            None,
            &[(
                Control::new(Mode::Init, 0).unwrap(),
                Some(Expected::Initial),
                false,
            )],
        )?;
        storage::immutable_new(&self.evidence.join("initial-baseline.raw"), &baseline)?;
        for cut in 1..=6 {
            self.case(
                &format!("cut-{cut}"),
                Some(&baseline),
                &[
                    (Control::new(Mode::Cut, cut).unwrap(), None, false),
                    (
                        Control::new(Mode::Recover, 0).unwrap(),
                        Some(Expected::Committed),
                        false,
                    ),
                ],
            )?;
        }
        self.case(
            "normal-commit",
            Some(&baseline),
            &[
                (
                    Control::new(Mode::Commit, 0).unwrap(),
                    Some(Expected::Committed),
                    false,
                ),
                (
                    Control::new(Mode::Verify, 0).unwrap(),
                    Some(Expected::Committed),
                    true,
                ),
            ],
        )?;
        if self.boots != EXPECTED_BOOTS {
            return Err("journal suite did not execute exactly fifteen boot invocations".into());
        }
        Ok(())
    }
}

/// Build once, then reuse the exact retained boot image and kernel across all
/// fifteen fresh VMs. Control is diagnostic test policy, never a volume handle.
pub fn run() -> Result<()> {
    let current = std::env::current_dir().map_err(|error| error.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m3/evidence"))?;
    let evidence = build::unique_directory(&parent, "storage-journal")?;
    println!("Evidence: {}", evidence.display());
    let manifest_path = evidence.join("manifest.json");
    let mut suite = Suite {
        root: &root,
        evidence: &evidence,
        manifest: &manifest_path,
        phases: Vec::new(),
        cases: Vec::new(),
        boots: 0,
    };
    let mut stage = "build";
    let mut manifest_summary = None;
    let result = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some(FIXTURE.into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_manifest";
        let bytes =
            fs::read(root.join("build/m0/manifest.json")).map_err(|error| error.to_string())?;
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some(FIXTURE) {
            return Err("selected build is not the journal fixture".into());
        }
        manifest_summary = Some(json!({"record":link(&manifest_path,&evidence)?,
            "build_id":manifest.build_id,"source_sha256":manifest.source_sha256,
            "kernel":manifest.kernel,"image":manifest.image}));
        stage = "cases";
        suite.cases()
    })();
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"storage-journal","passed":result.is_ok(),
            "last_stage":stage,"error":result.as_ref().err(),"build":manifest_summary,
            "expected_boots":EXPECTED_BOOTS,"boot_invocations":suite.boots,
            "cases":suite.cases,"phases":suite.phases,
            "baseline":existing_link(&evidence.join("initial-baseline.raw"),&evidence)?,
            "control_lba":2,"store_lba":STORE_BASE,"store_sectors":STORE_BLOCKS,
            "pending_only":true,"known_good":null,
            "method":"One retained source-built kernel/boot image; fifteen fresh Q35/TCG/OVMF VMs; actual client UD2 followed by validated abrupt QEMU kill/reap at six write/flush boundaries; cold reopen and independent read-only disk checks. This does not certify host physical power loss or generation execution."}),
    )?;
    println!("Evidence: {}", evidence.display());
    result?;
    println!(
        "PASS storage-journal: six abrupt interruption/reopen cases, durable original-ID replay and unchanged cold Verify."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Model(Vec<u8>);
    impl SectorIo for Model {
        type Error = ();
        fn sectors(&self) -> u64 {
            u64::from(STORE_BLOCKS)
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> std::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = (u64::from(STORE_BASE) + lba) as usize * storage::SECTOR_BYTES;
            out.copy_from_slice(&self.0[start..start + storage::SECTOR_BYTES]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> std::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = (u64::from(STORE_BASE) + lba) as usize * storage::SECTOR_BYTES;
            self.0[start..start + storage::SECTOR_BYTES].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> std::result::Result<(), ()> {
            Ok(())
        }
    }
    fn initial() -> Vec<u8> {
        Store::format_new(
            Model(vec![0; storage::DISK_BYTES]),
            pending_a(),
            OWNER_A,
            ev_store::BootPolicy::new(3).unwrap(),
            SNAPSHOT_DEADLINE,
        )
        .unwrap_or_else(|_| panic!("model format"))
        .into_device()
        .0
    }
    fn committed() -> Vec<u8> {
        let mut store = Store::open(Model(initial()), SNAPSHOT_DEADLINE)
            .unwrap_or_else(|_| panic!("model open"));
        store
            .execute(
                OperationId::new(1).unwrap(),
                ev_store::Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: OWNER_B,
                },
                SNAPSHOT_DEADLINE,
            )
            .unwrap();
        store.into_device().0
    }

    #[test]
    fn independently_validates_exact_pending_manifest_payload_and_original_receipt() {
        let a = initial();
        let b = committed();
        assert_eq!(
            inspect_snapshot(&a, Expected::Initial).unwrap()["operation"],
            0
        );
        assert_eq!(
            inspect_snapshot(&b, Expected::Committed).unwrap()["sequence"],
            2
        );
        assert!(inspect_snapshot(&a, Expected::Committed).is_err());
        assert!(inspect_snapshot(&b, Expected::Initial).is_err());
        let mut corrupt = b.clone();
        corrupt[(STORE_BASE as usize + 13) * storage::SECTOR_BYTES + 70] ^= 1;
        assert!(inspect_snapshot(&corrupt, Expected::Committed).is_err());
        assert!(inspect_snapshot(&b[..b.len() - 1], Expected::Committed).is_err());
        assert_eq!(b, committed());
    }

    #[test]
    fn prepared_snapshot_cannot_be_silently_repaired_by_the_host_observer() {
        let mut prepared = committed();
        // Remove only the latest committed root, leaving a valid prepared op1
        // and its staged data. Real recovery is possible; read-only open refuses.
        let start = STORE_BASE as usize * storage::SECTOR_BYTES;
        prepared[start..start + storage::SECTOR_BYTES].fill(0);
        let before = prepared.clone();
        let error = inspect_snapshot(&prepared, Expected::Committed).unwrap_err();
        assert!(error.contains("ReadOnly"), "{error}");
        assert_eq!(prepared, before);
    }

    #[test]
    fn seed_legacy_record_control_and_all_guard_sectors_are_preserved() {
        let before = initial();
        for sector in [0, 1, 2, 3, 15, 30, storage::SECTORS - 1] {
            let mut after = before.clone();
            after[sector * storage::SECTOR_BYTES + 33] ^= 1;
            assert!(
                unchanged_guards(&before, &after).is_err(),
                "sector {sector}"
            );
        }
        let mut allowed = before.clone();
        for sector in STORE_BASE..STORE_BASE + STORE_BLOCKS {
            allowed[sector as usize * storage::SECTOR_BYTES + 33] ^= 1;
        }
        unchanged_guards(&before, &allowed).unwrap();
        assert!(unchanged_guards(&before, &allowed[..allowed.len() - 1]).is_err());
    }

    #[test]
    fn cold_verify_requires_the_entire_post_control_snapshot_to_be_identical() {
        let a = initial();
        let b = committed();
        snapshot_validation(&b, &b, Some(Expected::Committed), true).unwrap();
        assert!(snapshot_validation(&a, &b, Some(Expected::Committed), true).is_err());
        snapshot_validation(&a, &b, Some(Expected::Committed), false).unwrap();
    }

    #[test]
    fn read_only_backend_denies_mutation_flush_bounds_and_wrong_deadline() {
        let bytes = initial();
        let mut region = ReadOnlyRegion::new(&bytes).unwrap();
        assert!(region.write(0, &[0; 512], SNAPSHOT_DEADLINE).is_err());
        assert!(region.flush(SNAPSHOT_DEADLINE).is_err());
        assert_eq!(region.mutation_attempts, 2);
        assert!(
            region
                .read(u64::from(STORE_BLOCKS), &mut [0; 512], SNAPSHOT_DEADLINE)
                .is_err()
        );
        assert!(region.read(0, &mut [0; 512], 0).is_err());
        assert_eq!(region.reads, 0);
    }

    #[test]
    fn preparation_failure_preserves_the_existing_file_and_records_partial_evidence() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent =
            storage::directory_beneath(&root, Path::new("build/test-tmp/journal-host-tests"))
                .unwrap();
        let evidence = build::unique_directory(&parent, "prepare-failure").unwrap();
        let case = storage::directory_beneath(
            &root,
            evidence.join("existing").strip_prefix(&root).unwrap(),
        )
        .unwrap();
        let old_bytes = b"preexisting data must not be erased";
        fs::write(case.join("data.raw"), old_bytes).unwrap();
        let manifest = evidence.join("unused-manifest.json");
        let mut suite = Suite {
            root: &root,
            evidence: &evidence,
            manifest: &manifest,
            phases: vec![json!({"path":"prior-phase-result.json","sha256":"retained"})],
            cases: Vec::new(),
            boots: 0,
        };
        assert!(suite.case("existing", None, &[]).is_err());
        assert_eq!(fs::read(case.join("data.raw")).unwrap(), old_bytes);
        let first = fs::read(case.join("case-result.json")).unwrap();
        let summary: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(summary["passed"], false);
        assert_eq!(summary["last_stage"], "prepare");
        assert!(summary["error"].as_str().is_some());
        assert_eq!(suite.cases.len(), 1);
        assert_eq!(suite.phases[0]["sha256"], "retained");
        assert_eq!(suite.boots, 0);
        // A retry cannot overwrite either the old data or the original failure.
        assert!(suite.case("existing", None, &[]).is_err());
        assert_eq!(fs::read(case.join("case-result.json")).unwrap(), first);
        assert_eq!(fs::read(case.join("data.raw")).unwrap(), old_bytes);
        fs::remove_dir_all(evidence).unwrap();
    }
}
