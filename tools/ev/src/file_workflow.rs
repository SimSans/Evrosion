//! One retained image, two cold VMs and an independent read-only File observer.
use crate::{
    boot::{self, FileBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    file_protocol::{self, Record},
    journal::{ReadOnlyRegion, SNAPSHOT_DEADLINE, unchanged_guards},
    storage::{self, Disk},
};
use ev_file::Envelope;
use ev_store::{GenerationId, GenerationManifest, ObjectId, OperationId, Store};
use ev_userspace_contract::file_test::{Control, DATA_B, Mode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const FIXTURE: &str = "m3-file";
const LIMIT_SECONDS: u64 = 120;

fn pending_a() -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [0x11; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn inspect_snapshot(bytes: &[u8], report: &Record) -> Result<Value> {
    let device = ReadOnlyRegion::new(bytes)?;
    let mut store = Store::open(device, SNAPSHOT_DEADLINE).map_err(|e| {
        format!(
            "File snapshot cannot open without repair: {:?}; backend={:?}",
            e.error,
            e.device.counts()
        )
    })?;
    if store
        .selected_manifest(SNAPSHOT_DEADLINE)
        .map_err(|e| format!("File selected generation: {e:?}"))?
        != pending_a()
        || store.known_good().is_some()
        || !matches!(
            store.boot_plan(SNAPSHOT_DEADLINE),
            Err(ev_store::Error::Phase)
        )
        || store
            .committed_boot_serial()
            .map_err(|e| format!("File boot serial: {e:?}"))?
            != 0
        || store
            .highest_generation()
            .map_err(|e| format!("File generation high-water: {e:?}"))?
            != 1
        || store
            .last_failure()
            .map_err(|e| format!("File failure capsule: {e:?}"))?
            .is_some()
        || store
            .next_operation()
            .map_err(|e| format!("File operation high-water: {e:?}"))?
            .get()
            != 2
    {
        return Err("File snapshot must retain unresolved PendingA, no admission/health/failure, and exactly one committed volume operation".into());
    }
    let mut body = [0; ev_store::PAYLOAD_BYTES];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut body, SNAPSHOT_DEADLINE)
        .map_err(|e| format!("File mutable envelope: {e:?}"))?;
    let envelope =
        Envelope::decode(&body[..length]).map_err(|e| format!("File envelope: {e:?}"))?;
    let payload_hash: [u8; 32] = Sha256::digest(envelope.payload()).into();
    if envelope.counter() != 1
        || envelope.global_operation() != 1
        || envelope.payload() != DATA_B
        || report.report.counter != envelope.counter()
        || report.report.payload != payload_hash
    {
        return Err("File cold envelope, logical counter, retained volume receipt or actual app payload differs".into());
    }
    // The original volume receipt must describe the exact durable envelope.
    // This read-only replay is an inspector test, never an application-selected
    // global operation or a write/repair performed on the guest's behalf.
    let receipt = store
        .execute(
            OperationId::new(1).unwrap(),
            ev_store::Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &body[..length],
            },
            SNAPSHOT_DEADLINE,
        )
        .map_err(|e| format!("File committed original receipt: {e:?}"))?;
    if !receipt.replayed || receipt.operation.get() != 1 || receipt.sequence != 2 {
        return Err("File snapshot does not retain the exact committed envelope receipt".into());
    }
    let device = store.into_device();
    let (reads, mutations) = device.counts();
    if mutations != 0 {
        return Err("File independent observer attempted a write, flush or repair".into());
    }
    Ok(
        json!({"backend":"read-only raw sectors","reads":reads,"mutation_attempts":mutations,
        "format":ev_store::FORMAT_VERSION,"pending":true,"known_good":null,"generation":1,
        "boot_serial":0,"last_failure":null,"object":1,"client_counter":1,
        "volume_operation":1,"sequence":2,"replayed":true,"envelope_bytes":length,
        "payload_sha256":payload_hash.iter().map(|b|format!("{b:02x}")).collect::<String>()}),
    )
}

fn snapshot_validation(before: &[u8], after: &[u8], record: &Record) -> Result<Value> {
    unchanged_guards(before, after)?;
    let verify = record.report.mode == Mode::Verify;
    if verify && before != after {
        return Err("cold File Verify changed the disk after its control was set".into());
    }
    let raw = inspect_snapshot(after, record)?;
    Ok(
        json!({"raw":raw,"guards_unchanged":true,"control_unchanged":true,"verify_unchanged":verify}),
    )
}
fn name(mode: Mode) -> &'static str {
    if mode == Mode::Write {
        "write"
    } else {
        "verify"
    }
}
fn link(path: &Path, base: &Path) -> Result<Value> {
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"File evidence escaped directory")?,"sha256":build::hash_file(path)?}),
    )
}
fn existing_link(path: &Path, base: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => link(path, base).map(Some),
        Ok(_) => Err("File evidence is not a regular file".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn retain_components(root: &Path, evidence: &Path, manifest: &Manifest) -> Result<Value> {
    let output = root.join("build/m0");
    build::verify_artifact(&output, &manifest.kernel)?;
    build::verify_artifact(&output, &manifest.image)?;
    let mut components = Vec::new();
    for name in [
        "m3-file-server.elf",
        "m3-file-app.elf",
        "m3-block-driver.elf",
    ] {
        let mut found = manifest
            .supervisor
            .iter()
            .filter(|a| Path::new(&a.path).file_name().is_some_and(|p| p == name));
        let artifact = found
            .next()
            .ok_or_else(|| format!("missing File artifact {name}"))?;
        if found.next().is_some() {
            return Err(format!("ambiguous File artifact {name}"));
        }
        let path = build::verify_artifact(&output, artifact)?;
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let retained = evidence.join(name);
        storage::immutable_new(&retained, &bytes)?;
        components.push(json!({"component":name,"build_artifact":artifact,"retained":link(&retained,evidence)?}));
    }
    let value = json!({"schema":1,"passed":true,"build_input_id":manifest.build_id,
        "kernel":manifest.kernel,"boot_image":manifest.image,"components":components,
        "binding":"retained exact source-built images; not publisher authentication"});
    storage::json_new(&evidence.join("component-binding.json"), &value)?;
    Ok(value)
}

struct Suite<'a> {
    root: &'a Path,
    evidence: &'a Path,
    manifest: &'a Path,
    phases: Vec<Value>,
    boots: u64,
}
impl Suite<'_> {
    fn phase(&mut self, disk: &mut Disk, mode: Mode) -> Result<()> {
        let directory = storage::directory_beneath(
            self.root,
            self.evidence
                .join(name(mode))
                .strip_prefix(self.root)
                .map_err(|_| "File phase escaped repository")?,
        )?;
        let mut stage = "control";
        let mut initial = None;
        let operation: Result<Value> = (|| {
            disk.file_control(Control::new(mode))?;
            stage = "before_snapshot";
            let before = disk.bytes()?;
            initial = Some(disk.capture(&directory, "data-before.raw")?);
            stage = "boot";
            self.boots += 1;
            boot::boot_file(
                &BootOptions {
                    root: Some(self.root.to_owned()),
                    timeout_seconds: LIMIT_SECONDS,
                    ..BootOptions::default()
                },
                FileBoot {
                    manifest: self.manifest,
                    evidence: &directory,
                    disk,
                    control: Control::new(mode),
                },
            )?;
            stage = "actual_records";
            let serial =
                fs::read(directory.join("boot/run-001/serial.log")).map_err(|e| e.to_string())?;
            let actual = file_protocol::record(&serial)?;
            let budget = file_protocol::budget(&serial)?;
            if actual.report.mode != mode {
                return Err("actual File report has the wrong phase".into());
            }
            stage = "independent_snapshot";
            let after = disk.bytes()?;
            let validation = snapshot_validation(&before, &after, &actual)?;
            Ok(json!({"actual":actual.evidence(),"budget":budget,"snapshot":validation}))
        })();
        // boot_file synchronously kills/reaps its own VM on every return path.
        let captured = disk.capture(&directory, "data-after.raw");
        let boot = existing_link(&directory.join("boot/results.json"), &directory);
        let path = directory.join("phase-result.json");
        storage::json_new(
            &path,
            &json!({"schema":1,"kind":"storage-file-phase","phase":name(mode),
            "passed":operation.is_ok()&&captured.is_ok()&&boot.is_ok(),"last_stage":stage,
            "before":initial,"after":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),
            "boot":boot.as_ref().ok(),"boot_link_error":boot.as_ref().err(),
            "validation":operation.as_ref().ok(),"error":operation.as_ref().err()}),
        )?;
        self.phases.push(link(&path, self.evidence)?);
        operation?;
        captured?;
        boot?;
        Ok(())
    }
}

pub fn run() -> Result<()> {
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m3/evidence"))?;
    let evidence = build::unique_directory(&parent, "storage-file")?;
    println!("Evidence: {}", evidence.display());
    let manifest_path = evidence.join("manifest.json");
    let mut stage = "build";
    let mut build_record = None;
    let mut components = None;
    let mut suite = None;
    let mut disk = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some(FIXTURE.into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_manifest";
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if manifest.fixture.as_deref() != Some(FIXTURE) {
            return Err("selected build is not the File fixture".into());
        }
        build_record = Some(
            json!({"record":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,
            "source_sha256":manifest.source_sha256,"kernel":manifest.kernel,"boot_image":manifest.image}),
        );
        stage = "component_binding";
        components = Some(retain_components(&root, &evidence, &manifest)?);
        suite = Some(Suite {
            root: &root,
            evidence: &evidence,
            manifest: &manifest_path,
            phases: Vec::new(),
            boots: 0,
        });
        stage = "prepare";
        disk = Some(Disk::create(&root, &evidence)?);
        let disk = disk.as_mut().ok_or("File disk missing")?;
        disk.capture(&evidence, "data-initial.raw")?;
        stage = "phases";
        let suite = suite.as_mut().ok_or("File suite missing")?;
        for mode in [Mode::Write, Mode::Verify] {
            suite.phase(disk, mode)?;
        }
        if suite.boots != 2 {
            return Err("File suite did not perform exactly two cold VM invocations".into());
        }
        Ok(())
    })();
    let captured = disk
        .as_ref()
        .map(|disk| disk.capture(&evidence, "data-final.raw"))
        .transpose();
    let sealed = disk.as_ref().map(Disk::seal).transpose();
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"storage-file",
        "passed":result.is_ok()&&captured.is_ok()&&sealed.is_ok(),"last_stage":stage,"error":result.as_ref().err(),
        "build":build_record,"components":components,"expected_boots":2,"boot_invocations":suite.as_ref().map_or(0,|s|s.boots),
        "phases":suite.as_ref().map(|s|&s.phases),"format":ev_store::FORMAT_VERSION,
        "final_disk":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),"seal_error":sealed.as_ref().err(),
        "control_lba":2,"store_lba":16,"store_sectors":14,
        "method":"One retained source-built image, two fresh Q35/TCG/OVMF VMs; actual capability-bound app/File/block RPC and independent read-only raw Store/envelope/receipt checks. Bounded internal Object1 interface, not whole M3 acceptance or production filesystem/power-loss certification."}),
    )?;
    println!("Evidence: {}", evidence.display());
    result?;
    captured?;
    sealed?;
    println!(
        "PASS storage-file: actual app/File/block calls and cold preserved object/receipt across two fresh VMs."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_file::{Bindings, Gateway, Request};
    use ev_store::{BootPolicy, Sector, SectorIo};
    use ev_userspace_contract::{
        file::Payload,
        file_test::{Completion, DATA_A},
    };

    // This mutable host model constructs adversarial observer inputs. It is not
    // evidence of physical File service execution or disk durability.
    struct Model {
        bytes: Vec<u8>,
        mutations: u64,
        fail_at: Option<u64>,
    }
    impl Model {
        fn mutation(&mut self) -> std::result::Result<(), ()> {
            self.mutations += 1;
            if self.fail_at == Some(self.mutations) {
                Err(())
            } else {
                Ok(())
            }
        }
    }
    impl SectorIo for Model {
        type Error = ();
        fn sectors(&self) -> u64 {
            ev_store::REQUIRED_SECTORS
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> std::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let offset = (16 + lba) as usize * 512;
            out.copy_from_slice(&self.bytes[offset..offset + 512]);
            Ok(())
        }
        fn write(&mut self, lba: u64, input: &Sector, _: u64) -> std::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            self.mutation()?;
            let offset = (16 + lba) as usize * 512;
            self.bytes[offset..offset + 512].copy_from_slice(input);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> std::result::Result<(), ()> {
            self.mutation()
        }
    }
    fn initial() -> Store<Model> {
        initial_manifest(pending_a())
    }
    fn initial_manifest(manifest: GenerationManifest) -> Store<Model> {
        let mut encoded = [0; 256];
        let length = Envelope::initial(DATA_A).unwrap().encode(&mut encoded);
        Store::format_new(
            Model {
                bytes: vec![0; storage::DISK_BYTES],
                mutations: 0,
                fail_at: None,
            },
            manifest,
            &encoded[..length],
            BootPolicy::new(3).unwrap(),
            SNAPSHOT_DEADLINE,
        )
        .unwrap_or_else(|e| panic!("host model format: {:?}", e.error))
    }
    fn record(mode: Mode) -> Record {
        let write = u64::from(mode == Mode::Write);
        Record {
            report: Completion {
                mode,
                object: 1,
                counter: 1,
                requests: if write == 1 { 11 } else { 7 },
                ro_denied: 1,
                malformed: 2,
                invalid_counter: 2,
                skipped: write,
                conflicting: write,
                duplicates: write,
                port_denied: 1,
                block_denied: 1,
                private_snapshot: write,
                payload: Sha256::digest(DATA_B).into(),
            },
            calls: 50,
            backend: 39,
            nested: 20,
            startup: 19,
            pre_delivery: 0,
            delivered_nested: 20,
            mutations: 11 * write,
        }
    }
    fn replaced() -> Vec<u8> {
        let mut gateway = Gateway::new(initial(), Bindings::new(101, 102).unwrap());
        gateway
            .handle(
                102,
                Request::Replace {
                    counter: 1,
                    payload: Payload::new(DATA_B).unwrap(),
                },
                SNAPSHOT_DEADLINE,
            )
            .unwrap();
        gateway.into_store().into_device().bytes
    }
    #[test]
    fn independent_cold_observer_requires_exact_envelope_receipt_and_truthful_pending_metadata() {
        let bytes = replaced();
        let report = record(Mode::Verify);
        let observed = inspect_snapshot(&bytes, &report).unwrap();
        assert_eq!(observed["mutation_attempts"], 0);
        assert_eq!(observed["client_counter"], 1);
        assert_eq!(observed["volume_operation"], 1);
        assert_eq!(observed["known_good"], Value::Null);
        assert_eq!(observed["boot_serial"], 0);
        assert!(observed["reads"].as_u64().unwrap() > 0);
        let mut false_report = report;
        false_report.report.payload = [0x55; 32];
        assert!(inspect_snapshot(&bytes, &false_report).is_err());
        assert!(inspect_snapshot(&initial().into_device().bytes, &record(Mode::Write)).is_err());
        assert!(inspect_snapshot(&bytes[..bytes.len() - 1], &record(Mode::Write)).is_err());
    }
    #[test]
    fn valid_checksums_do_not_bless_wrong_logical_counter_receipt_or_generation() {
        for (counter, operation) in [(2u64, 1u64), (1, 2)] {
            let mut store = initial();
            let mut body = [0; 256];
            let length = Envelope::initial(DATA_B).unwrap().encode(&mut body);
            body[16..24].copy_from_slice(&counter.to_le_bytes());
            body[24..32].copy_from_slice(&operation.to_le_bytes());
            store
                .execute(
                    OperationId::new(1).unwrap(),
                    ev_store::Request::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: &body[..length],
                    },
                    SNAPSHOT_DEADLINE,
                )
                .unwrap();
            assert!(inspect_snapshot(&store.into_device().bytes, &record(Mode::Write)).is_err());
        }
        let mut candidate = pending_a();
        candidate.cohort = [0x99; 32];
        let mut gateway = Gateway::new(
            initial_manifest(candidate),
            Bindings::new(101, 102).unwrap(),
        );
        gateway
            .handle(
                102,
                Request::Replace {
                    counter: 1,
                    payload: Payload::new(DATA_B).unwrap(),
                },
                SNAPSHOT_DEADLINE,
            )
            .unwrap();
        assert!(
            inspect_snapshot(
                &gateway.into_store().into_device().bytes,
                &record(Mode::Write)
            )
            .is_err()
        );
    }
    #[test]
    fn prepared_or_corrupt_snapshot_is_rejected_without_host_repair() {
        let store = initial();
        let mut device = store.into_device();
        device.mutations = 0;
        device.fail_at = Some(4);
        let mut store =
            Store::open(device, SNAPSHOT_DEADLINE).unwrap_or_else(|_| panic!("host model reopen"));
        let mut body = [0; 256];
        let length = Envelope::initial(DATA_B).unwrap().encode(&mut body);
        body[16..24].copy_from_slice(&1u64.to_le_bytes());
        body[24..32].copy_from_slice(&1u64.to_le_bytes());
        assert!(
            store
                .execute(
                    OperationId::new(1).unwrap(),
                    ev_store::Request::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: &body[..length]
                    },
                    SNAPSHOT_DEADLINE
                )
                .is_err()
        );
        let bytes = store.into_device().bytes;
        let result = Store::open(ReadOnlyRegion::new(&bytes).unwrap(), SNAPSHOT_DEADLINE);
        let failure = match result {
            Ok(_) => panic!("prepared journal unexpectedly needed no repair"),
            Err(e) => e,
        };
        assert!(failure.device.counts().1 > 0);
        assert!(inspect_snapshot(&bytes, &record(Mode::Write)).is_err());
        let mut corrupt = replaced();
        for offset in [16 * 512 + 48, 17 * 512 + 48, 18 * 512 + 48] {
            corrupt[offset] ^= 1;
        }
        assert!(inspect_snapshot(&corrupt, &record(Mode::Write)).is_err());
    }
    #[test]
    fn guest_control_guard_and_verify_mutations_cannot_be_hidden_in_valid_store() {
        let bytes = replaced();
        let report = record(Mode::Verify);
        assert!(snapshot_validation(&bytes, &bytes, &report).is_ok());
        for sector in [0usize, 1, 2, 15, 30, 8191] {
            let mut changed = bytes.clone();
            changed[sector * 512] ^= 1;
            assert!(snapshot_validation(&bytes, &changed, &report).is_err());
        }
        let mut changed = bytes.clone();
        changed[29 * 512 + 511] ^= 1;
        // Even an otherwise unused byte within the authorized volume must stay
        // unchanged during a Verify-only boot.
        assert!(snapshot_validation(&bytes, &changed, &report).is_err());
    }
}
