//! One retained image, five fresh VMs, real generation execution and cold data.
//! Host snapshot validation cannot write, flush or repair the guest's store.
use crate::{
    boot::{self, GenerationBoot, GenerationVariant},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    journal::{ReadOnlyRegion, SNAPSHOT_DEADLINE, unchanged_guards},
    storage::{self, Disk},
};
use ev_store::{
    AdmissionReport, GenerationId, GenerationManifest, HealthOutcome, HealthReport, LastFailure,
    LastFailureReason, ObjectId, OperationId, Store,
};
use ev_userspace_contract::generation::{
    Catalogue, Completion, Control, Digest, HEALTH_DESCRIPTION, Mode, Slot,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{fs, path::Path};

const FIXTURE: &str = "m3-generation";
const PROGRESS_FIXTURE: &str = "m3-progress";
const LIMIT_SECONDS: u64 = 120;
const OWNER_A: &[u8] = b"owner-data-A";
const OWNER_B: &[u8] = b"owner-data-B";
const MODES: [Mode; 5] = [
    Mode::ProvisionA,
    Mode::FailB,
    Mode::AutoA,
    Mode::ManualA,
    Mode::Verify,
];

pub(crate) fn hash(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(text: &str) -> Result<Digest> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("generation identity must be exactly32 hexadecimal bytes".into());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(bytes)
}
fn name(mode: Mode) -> &'static str {
    match mode {
        Mode::ProvisionA => "provision-a",
        Mode::FailB => "fail-b",
        Mode::AutoA => "auto-a",
        Mode::ManualA => "manual-a",
        Mode::Verify => "verify",
        Mode::OwnerPrepare3 => "owner-prepare3",
        Mode::OwnerRecover => "owner-recover",
    }
}
fn expected(mode: Mode) -> (u64, u64, u64, u64) {
    // Highest committed operation, durable boot serial, highest generation and
    // completed physical write/flush count. Verify performs no new boot.
    match mode {
        Mode::ProvisionA => (4, 1, 1, 23),
        Mode::FailB => (10, 2, 2, 28),
        Mode::AutoA => (14, 3, 2, 18),
        Mode::ManualA => (21, 4, 3, 32),
        Mode::Verify => (21, 4, 3, 0),
        Mode::OwnerPrepare3 => (16, 3, 3, 10),
        Mode::OwnerRecover => (21, 4, 3, 22),
    }
}
pub(crate) fn manifest(catalogue: Catalogue, slot: Slot, generation: u64) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(generation).unwrap(),
        cohort: hash(&catalogue.cohort_input_for(slot, generation)),
        supervisor_image: catalogue.image(slot),
        abi: catalogue.abi,
        health_contract: catalogue.health,
        health_version: catalogue.health_version,
        required_checks: u32::from(catalogue.required_checks),
    }
}

#[derive(Clone, Copy)]
struct RoleHashes {
    controller: Digest,
    driver: Digest,
    good: Digest,
    bad: Digest,
}
fn check_catalogue(catalogue: Catalogue, build_id: &str, roles: RoleHashes) -> Result<()> {
    if catalogue.kernel_build != digest(build_id)?
        || catalogue.controller != roles.controller
        || catalogue.driver != roles.driver
        || catalogue.image_a != roles.good
        || catalogue.image_b != roles.bad
        || catalogue.abi != ev_userspace_contract::ABI
        || catalogue.health != hash(HEALTH_DESCRIPTION)
        || catalogue.health_version != 1
        || catalogue.required_checks != 3
        || roles.good == roles.bad
    {
        return Err("catalogue differs from the retained build input, actual component images or health contract".into());
    }
    Ok(())
}
fn artifact<'a>(manifest: &'a Manifest, name: &str) -> Result<&'a build::Artifact> {
    let mut matches = manifest.supervisor.iter().filter(|artifact| {
        Path::new(&artifact.path)
            .file_name()
            .is_some_and(|file| file == name)
    });
    let found = matches
        .next()
        .ok_or_else(|| format!("missing generation artifact {name}"))?;
    if matches.next().is_some() {
        return Err(format!("ambiguous generation artifact {name}"));
    }
    Ok(found)
}
pub(crate) fn retain_catalogue(
    root: &Path,
    evidence: &Path,
    manifest: &Manifest,
    owner: bool,
) -> Result<(Catalogue, Digest)> {
    retain_selected_catalogue(
        root,
        evidence,
        manifest,
        if owner {
            CatalogueKind::Owner
        } else {
            CatalogueKind::Fault
        },
    )
}

#[derive(Clone, Copy)]
enum CatalogueKind {
    Fault,
    Owner,
    Progress,
}
impl CatalogueKind {
    fn artifacts(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Fault => (
                "m3-generation-catalogue.bin",
                "m3-generation-client.elf",
                "supervisor-generation-bad.elf",
            ),
            Self::Owner => (
                "m3-owner-catalogue.bin",
                "m3-owner-client.elf",
                "supervisor-generation-bad.elf",
            ),
            Self::Progress => (
                "m3-progress-catalogue.bin",
                "m3-progress-client.elf",
                "supervisor-generation-silent.elf",
            ),
        }
    }
}
fn retain_selected_catalogue(
    root: &Path,
    evidence: &Path,
    manifest: &Manifest,
    kind: CatalogueKind,
) -> Result<(Catalogue, Digest)> {
    let output = root.join("build/m0");
    let (catalogue_name, controller_name, bad_name) = kind.artifacts();
    let catalogue_artifact = artifact(manifest, catalogue_name)?;
    let path = build::verify_artifact(&output, catalogue_artifact)?;
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let catalogue = Catalogue::decode(&bytes)
        .map_err(|error| format!("generation catalogue format: {error:?}"))?;
    let mut components = Vec::new();
    let mut actual = |name: &str| -> Result<Digest> {
        let recorded = artifact(manifest, name)?;
        let path = build::verify_artifact(&output, recorded)?;
        let actual = build::hash_file(&path)?;
        components.push(json!({"component":name,"path":recorded.path,"sha256":actual}));
        digest(&actual)
    };
    let roles = RoleHashes {
        controller: actual(controller_name)?,
        driver: actual("m3-block-driver.elf")?,
        good: actual("supervisor-generation-good.elf")?,
        bad: actual(bad_name)?,
    };
    check_catalogue(catalogue, &manifest.build_id, roles)?;
    build::verify_artifact(&output, &manifest.kernel)?;
    build::verify_artifact(&output, &manifest.image)?;
    storage::immutable_new(&evidence.join("catalogue.bin"), &bytes)?;
    storage::json_new(
        &evidence.join("catalogue-binding.json"),
        &json!({
            "schema":1,"passed":true,"catalogue_sha256":hex(&hash(&bytes)),
            "build_input_id":manifest.build_id,"kernel":manifest.kernel,"boot_image":manifest.image,
            "components":components,"cohort_a":hex(&hash(&catalogue.cohort_input(Slot::A))),
            "cohort_b":hex(&hash(&catalogue.cohort_input(Slot::B))),
            "kernel_identity":"immutable build input ID; exact final kernel/boot hashes retained separately",
            "publisher_authenticated":false,
        }),
    )?;
    Ok((catalogue, hash(&bytes)))
}

fn stamp(catalogue: Catalogue, report: &Completion) -> Digest {
    let slot = if report.mode == Mode::FailB {
        Slot::B
    } else {
        Slot::A
    };
    let selected = manifest(catalogue, slot, slot.generation());
    let mut hash = Sha256::new();
    hash.update(b"evrosion.actual.generation.admission.v1\0");
    hash.update(catalogue.kernel_build);
    hash.update(report.booted.to_le_bytes());
    hash.update(report.boot_serial.to_le_bytes());
    hash.update(report.process.to_le_bytes());
    hash.update(report.thread.to_le_bytes());
    hash.update(selected.cohort);
    hash.update(selected.supervisor_image);
    hash.finalize().into()
}
fn unexecuted_owner(report: &Completion) -> bool {
    report.mode == Mode::OwnerPrepare3
        || report.mode == Mode::OwnerRecover
            && report.owner_decision != ev_userspace_contract::generation::OwnerDecision::Continue
}
fn expected_report(report: &Completion) -> (u64, u64, u64, u64) {
    if report.mode == Mode::OwnerRecover && unexecuted_owner(report) {
        (16, 3, 3, 0)
    } else {
        expected(report.mode)
    }
}
pub(crate) fn report_shape(
    report: &Completion,
    catalogue: Catalogue,
    catalogue_hash: Digest,
) -> Result<()> {
    let (operation, serial, _, mutations) = expected_report(report);
    let payload = if report.mode == Mode::ProvisionA {
        OWNER_A
    } else {
        OWNER_B
    };
    if report.operation != operation
        || report.sequence != operation + 1
        || report.selected != if unexecuted_owner(report) { 3 } else { 1 }
        || report.known_good != 1
        || report.mutations != mutations
        || report.catalogue != catalogue_hash
        || report.storage_probe != hash(payload)
    {
        return Err("generation completion differs from its exact phase, receipt, catalogue or storage probe".into());
    }
    if report.mode == Mode::Verify || unexecuted_owner(report) {
        if report.booted != 0
            || report.boot_serial != 0
            || report.process != 0
            || report.thread != 0
            || report.process_stamp != [0; 32]
            || report.booted_cohort != [0; 32]
            || report.negatives != 0
        {
            return Err("Verify cannot claim an executed process or health event".into());
        }
    } else {
        let slot = if report.mode == Mode::FailB {
            Slot::B
        } else {
            Slot::A
        };
        if report.booted != slot.generation()
            || report.boot_serial != serial
            || report.process == 0
            || report.thread == 0
            || report.negatives != 4
            || report.process_stamp != stamp(catalogue, report)
            || report.booted_cohort != manifest(catalogue, slot, slot.generation()).cohort
        {
            return Err("generation admission diagnostics differ from measured cohort/attempt/process binding".into());
        }
    }
    let failure = if report.mode == Mode::ProvisionA {
        (0, 0, 0, 0, 0)
    } else {
        if !matches!(report.failure_reason, 1 | 2) {
            return Err("generation completion reports an unsupported failure reason".into());
        }
        (2, 2, report.failure_reason, 10, 11)
    };
    if (
        report.failure_generation,
        report.failure_serial,
        report.failure_reason,
        report.failure_operation,
        report.failure_sequence,
    ) != failure
    {
        return Err("completion reports the wrong durable last failure".into());
    }
    Ok(())
}

fn variant_reason(variant: GenerationVariant) -> u64 {
    match variant {
        GenerationVariant::Fault => 1,
        GenerationVariant::MissingProgress => 2,
    }
}
fn report_variant(report: &Completion, variant: GenerationVariant) -> Result<()> {
    let expected = if report.mode == Mode::ProvisionA {
        0
    } else {
        variant_reason(variant)
    };
    if report.failure_reason != expected {
        return Err(
            "generation failure reason differs from the selected physical experiment".into(),
        );
    }
    Ok(())
}
fn report_failure_reason(report: &Completion) -> Result<Option<LastFailureReason>> {
    if report.mode == Mode::ProvisionA {
        return if report.failure_reason == 0 {
            Ok(None)
        } else {
            Err("initial healthy A cannot report a failure reason".into())
        };
    }
    match report.failure_reason {
        1 => Ok(Some(LastFailureReason::ProcessFault)),
        2 => Ok(Some(LastFailureReason::MissingProgress)),
        _ => Err("generation observer refuses an unsupported failure reason".into()),
    }
}

pub(crate) struct Observation {
    pub(crate) evidence: Value,
    pub(crate) failure: Option<LastFailure>,
}
pub(crate) fn inspect_snapshot(
    bytes: &[u8],
    catalogue: Catalogue,
    report: &Completion,
    previous_failure: Option<LastFailure>,
) -> Result<Observation> {
    let expected_failure = report_failure_reason(report)?;
    let region = ReadOnlyRegion::new(bytes)?;
    let mut store = Store::open(region, SNAPSHOT_DEADLINE).map_err(|rejected| {
        format!(
            "generation raw snapshot cannot open without repair: {:?}",
            rejected.error
        )
    })?;
    let (operation, serial, highest, _) = expected_report(report);
    let selected = if unexecuted_owner(report) {
        manifest(catalogue, Slot::B, 3)
    } else {
        manifest(catalogue, Slot::A, 1)
    };
    if ev_store::FORMAT_VERSION != 2
        || store.known_good() != GenerationId::new(1)
        || store
            .selected_manifest(SNAPSHOT_DEADLINE)
            .map_err(|e| format!("snapshot selection: {e:?}"))?
            != selected
        || !matches!(
            store.boot_plan(SNAPSHOT_DEADLINE),
            Err(ev_store::Error::Phase)
        )
        || store
            .committed_boot_serial()
            .map_err(|e| format!("snapshot serial: {e:?}"))?
            != serial
        || store
            .highest_generation()
            .map_err(|e| format!("snapshot generation high-water: {e:?}"))?
            != highest
        || store
            .next_operation()
            .map_err(|e| format!("snapshot operation high-water: {e:?}"))?
            .get()
            != operation + 1
    {
        return Err(
            "raw committed selection/health/serial/generation/operation state differs".into(),
        );
    }
    let payload = if report.mode == Mode::ProvisionA {
        OWNER_A
    } else {
        OWNER_B
    };
    let mut output = [0; ev_store::PAYLOAD_BYTES];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut output, SNAPSHOT_DEADLINE)
        .map_err(|e| format!("raw mutable object: {e:?}"))?;
    if output[..length] != *payload || hash(&output[..length]) != report.storage_probe {
        return Err(
            "raw owner data was changed or did not match actual storage observation".into(),
        );
    }
    let failure = store
        .last_failure()
        .map_err(|e| format!("raw failure capsule: {e:?}"))?;
    if report.mode == Mode::ProvisionA {
        if failure.is_some() {
            return Err("fresh healthy A unexpectedly has a failure capsule".into());
        }
    } else {
        let found = failure.ok_or("raw snapshot lost its durable B failure capsule")?;
        if found.generation != GenerationId::new(2).unwrap()
            || found.boot_serial != 2
            || found.attempts != 1
            || Some(found.reason) != expected_failure
            || found.supervisor_image != catalogue.image_b
            || found.process_stamp.is_none()
            || found.operation.get() != 10
            || found.sequence != 11
            || (report.mode == Mode::FailB && found.process_stamp != Some(report.process_stamp))
            || (report.mode != Mode::FailB && previous_failure != Some(found))
        {
            return Err(
                "raw B failure capsule differs from its actual failure or was overwritten".into(),
            );
        }
    }
    // Check the original latest receipt using its actual observed admission.
    // Replays must succeed through a backend which rejects every mutation.
    if report.process != 0 {
        let slot = if report.mode == Mode::FailB {
            Slot::B
        } else {
            Slot::A
        };
        let selected = manifest(catalogue, slot, slot.generation());
        let admitted = AdmissionReport {
            generation: selected.generation,
            boot_serial: report.boot_serial,
            process_stamp: report.process_stamp,
            cohort: selected.cohort,
            supervisor_image: selected.supervisor_image,
            abi: selected.abi,
            health_contract: selected.health_contract,
            health_version: selected.health_version,
        };
        let receipt = store
            .execute(
                OperationId::new(operation).unwrap(),
                ev_store::Request::Health(HealthReport {
                    admitted,
                    outcome: if report.mode == Mode::FailB {
                        match expected_failure {
                            Some(LastFailureReason::ProcessFault) => HealthOutcome::ProcessFault,
                            Some(LastFailureReason::MissingProgress) => {
                                HealthOutcome::MissingProgress
                            }
                            _ => {
                                return Err(
                                    "failure receipt has no supported health outcome".into()
                                );
                            }
                        }
                    } else {
                        HealthOutcome::CriticalPassed
                    },
                    observed_checks: if report.mode == Mode::FailB { 0 } else { 3 },
                    storage_probe: report.storage_probe,
                }),
                SNAPSHOT_DEADLINE,
            )
            .map_err(|e| format!("raw latest original-ID receipt: {e:?}"))?;
        if !receipt.replayed
            || receipt.sequence != operation + 1
            || receipt.operation.get() != operation
        {
            return Err("raw receipt is not the exact original committed operation".into());
        }
    }
    let (reads, mutations) = store.into_device().counts();
    if mutations != 0 {
        return Err("raw generation observer attempted a write, flush or repair".into());
    }
    Ok(Observation {
        failure,
        evidence: json!({"backend":"read-only raw snapshot","format":2,
        "reads":reads,"mutation_attempts":mutations,"selected":selected.generation.get(),"known_good":1,
        "operation":operation,"sequence":operation+1,"durable_boot_serial":serial,
        "highest_generation":highest,"storage_probe":hex(&hash(payload)),
        "failure":failure.map(failure_json),"capsule_survives_journal_reuse":operation>=21}),
    })
}
fn failure_json(failure: LastFailure) -> Value {
    let reason = match failure.reason {
        LastFailureReason::ProcessFault => "ProcessFault",
        LastFailureReason::MissingProgress => "MissingProgress",
        LastFailureReason::StorageFailure => "StorageFailure",
        LastFailureReason::AttemptBudgetExhausted => "AttemptBudgetExhausted",
        LastFailureReason::CriticalComponentFault => "CriticalComponentFault",
    };
    json!({"generation":failure.generation.get(),"boot_serial":failure.boot_serial,
        "attempts":failure.attempts,"reason":reason,"supervisor_image":hex(&failure.supervisor_image),
        "process_stamp":failure.process_stamp.map(|stamp|hex(&stamp)),
        "operation":failure.operation.get(),"sequence":failure.sequence})
}
pub(crate) fn report_json(report: &Completion) -> Value {
    json!({"mode":name(report.mode),"owner_decision":report.owner_decision as u8,"booted":report.booted,"selected":report.selected,
        "known_good":report.known_good,"boot_serial":report.boot_serial,"process":report.process,
        "thread":report.thread,"negatives":report.negatives,"mutations":report.mutations,
        "operation":report.operation,"sequence":report.sequence,
        "catalogue":hex(&report.catalogue),"process_stamp":hex(&report.process_stamp),
        "storage_probe":hex(&report.storage_probe),"booted_cohort":hex(&report.booted_cohort),
        "failure_generation":report.failure_generation,"failure_serial":report.failure_serial,
        "failure_reason":report.failure_reason,"failure_operation":report.failure_operation,
        "failure_sequence":report.failure_sequence})
}
fn link(path: &Path, base: &Path) -> Result<Value> {
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"generation evidence escaped its directory")?,
        "sha256":build::hash_file(path)?}),
    )
}
fn existing_link(path: &Path, base: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => link(path, base).map(Some),
        Ok(_) => Err("generation evidence is not a regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

struct Suite<'a> {
    root: &'a Path,
    evidence: &'a Path,
    manifest: &'a Path,
    catalogue: Catalogue,
    catalogue_hash: Digest,
    phases: Vec<Value>,
    failure: Option<LastFailure>,
    operation: u64,
    sequence: u64,
    boots: u64,
    variant: GenerationVariant,
}
impl Suite<'_> {
    fn phase(&mut self, disk: &mut Disk, mode: Mode) -> Result<()> {
        let directory = storage::directory_beneath(
            self.root,
            self.evidence
                .join(name(mode))
                .strip_prefix(self.root)
                .map_err(|_| "generation phase escaped repository")?,
        )?;
        let mut stage = "control";
        let mut initial = None;
        let operation: Result<Value> = (|| {
            disk.generation_control(Control::new(mode))?;
            stage = "before_snapshot";
            let before = disk.bytes()?;
            initial = Some(disk.capture(&directory, "data-before.raw")?);
            stage = "boot";
            self.boots += 1;
            boot::boot_generation(
                &BootOptions {
                    root: Some(self.root.to_owned()),
                    timeout_seconds: LIMIT_SECONDS,
                    ..BootOptions::default()
                },
                GenerationBoot {
                    manifest: self.manifest,
                    evidence: &directory,
                    disk,
                    control: Control::new(mode),
                    variant: self.variant,
                },
            )?;
            stage = "actual_record";
            let serial =
                fs::read(directory.join("boot/run-001/serial.log")).map_err(|e| e.to_string())?;
            if serial.len() > 1024 * 1024 {
                return Err("generation serial exceeded its bounded boot log".into());
            }
            let report = crate::boot_protocol::generation_record(&serial)?;
            let budget = crate::boot_protocol::generation_budget_record(&serial)?;
            let progress = if matches!(self.variant, GenerationVariant::MissingProgress)
                && mode == Mode::FailB
            {
                Some(crate::boot_protocol::progress_record(&serial)?)
            } else {
                None
            };
            if report.mode != mode {
                return Err("actual generation record has the wrong phase".into());
            }
            report_shape(&report, self.catalogue, self.catalogue_hash)?;
            report_variant(&report, self.variant)?;
            stage = "independent_snapshot";
            let after = disk.bytes()?;
            unchanged_guards(&before, &after)?;
            if mode == Mode::Verify && before != after {
                return Err("cold generation Verify changed its persistent disk".into());
            }
            let observed = inspect_snapshot(&after, self.catalogue, &report, self.failure)?;
            if mode == Mode::Verify {
                if report.operation != self.operation || report.sequence != self.sequence {
                    return Err("Verify changed persistent operation counters".into());
                }
            } else if report.operation <= self.operation || report.sequence <= self.sequence {
                return Err("generation operations/sequence did not strictly increase".into());
            }
            self.failure = observed.failure;
            self.operation = report.operation;
            self.sequence = report.sequence;
            Ok(
                json!({"actual":report_json(&report),"budget":budget,"progress":progress,"raw":observed.evidence,
                "guards_unchanged":true,"control_unchanged":true,"verify_unchanged":mode==Mode::Verify}),
            )
        })();
        let captured = disk.capture(&directory, "data-after.raw");
        let boot = existing_link(&directory.join("boot/results.json"), &directory);
        let path = directory.join("phase-result.json");
        storage::json_new(
            &path,
            &json!({"schema":1,"kind":"generation-phase","phase":name(mode),
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
    run_variant(GenerationVariant::Fault)
}
pub fn run_progress() -> Result<()> {
    run_variant(GenerationVariant::MissingProgress)
}
fn run_variant(variant: GenerationVariant) -> Result<()> {
    let (fixture, prefix) = match variant {
        GenerationVariant::Fault => (FIXTURE, "generation"),
        GenerationVariant::MissingProgress => (PROGRESS_FIXTURE, "generation-progress"),
    };
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m3/evidence"))?;
    let evidence = build::unique_directory(&parent, prefix)?;
    println!("Evidence: {}", evidence.display());
    let manifest_path = evidence.join("manifest.json");
    let mut stage = "build";
    let mut build_record = None;
    let mut suite = None;
    let mut disk = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some(fixture.into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_manifest";
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some(fixture) {
            return Err("selected build is not the generation fixture".into());
        }
        build_record = Some(
            json!({"record":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,
            "source_sha256":manifest.source_sha256,"kernel":manifest.kernel,"boot_image":manifest.image}),
        );
        stage = "catalogue_binding";
        let (catalogue, catalogue_hash) = match variant {
            GenerationVariant::Fault => retain_catalogue(&root, &evidence, &manifest, false)?,
            GenerationVariant::MissingProgress => {
                retain_selected_catalogue(&root, &evidence, &manifest, CatalogueKind::Progress)?
            }
        };
        suite = Some(Suite {
            root: &root,
            evidence: &evidence,
            manifest: &manifest_path,
            catalogue,
            catalogue_hash,
            phases: Vec::new(),
            failure: None,
            operation: 0,
            sequence: 1,
            boots: 0,
            variant,
        });
        stage = "prepare";
        disk = Some(Disk::create(&root, &evidence)?);
        let disk = disk.as_mut().ok_or("generation disk missing")?;
        disk.capture(&evidence, "data-initial.raw")?;
        stage = "phases";
        let suite = suite.as_mut().ok_or("generation suite missing")?;
        for mode in MODES {
            suite.phase(disk, mode)?;
        }
        if suite.boots != 5 {
            return Err("generation suite did not perform exactly five boot invocations".into());
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
        &json!({"schema":1,"kind":prefix,"fixture":fixture,"failure_reason":variant_reason(variant),
        "passed":result.is_ok()&&captured.is_ok()&&sealed.is_ok(),"last_stage":stage,
        "error":result.as_ref().err(),"build":build_record,
        "catalogue":existing_link(&evidence.join("catalogue.bin"),&evidence)?,
        "catalogue_binding":existing_link(&evidence.join("catalogue-binding.json"),&evidence)?,
        "expected_boots":5,"boot_invocations":suite.as_ref().map_or(0,|suite|suite.boots),
        "phases":suite.as_ref().map(|suite|&suite.phases),"format":ev_store::FORMAT_VERSION,
        "final_disk":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),"seal_error":sealed.as_ref().err(),
        "control_lba":2,"store_lba":16,"store_sectors":14,
        "method":"One retained source-built kernel/boot image and complete measured catalogue, five fresh Q35/TCG/OVMF VMs; actual userspace lifecycle/health observation with independent read-only cold Store snapshots. Selected experiment requires either actual process fault or live missing critical progress. Not production authenticated boot or host physical power-loss certification."}),
    )?;
    println!("Evidence: {}", evidence.display());
    result?;
    captured?;
    sealed?;
    println!(
        "PASS {prefix}: actual A health, B {}, automatic/manual A execution and preserved owner data across five fresh VMs.",
        match variant {
            GenerationVariant::Fault => "fault",
            GenerationVariant::MissingProgress => "missing progress",
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_store::{BootPolicy, Sector, SectorIo};

    fn catalogue() -> Catalogue {
        Catalogue {
            kernel_build: [1; 32],
            controller: [2; 32],
            driver: [3; 32],
            image_a: [4; 32],
            image_b: [5; 32],
            abi: ev_userspace_contract::ABI,
            health: hash(HEALTH_DESCRIPTION),
            health_version: 1,
            required_checks: 3,
        }
    }
    fn roles(c: Catalogue) -> RoleHashes {
        RoleHashes {
            controller: c.controller,
            driver: c.driver,
            good: c.image_a,
            bad: c.image_b,
        }
    }
    struct Model {
        bytes: Vec<u8>,
        mutations: u64,
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
            let start = (16 + lba) as usize * storage::SECTOR_BYTES;
            out.copy_from_slice(&self.bytes[start..start + 512]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> std::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = (16 + lba) as usize * storage::SECTOR_BYTES;
            self.bytes[start..start + 512].copy_from_slice(bytes);
            self.mutations += 1;
            Ok(())
        }
        fn flush(&mut self, _: u64) -> std::result::Result<(), ()> {
            self.mutations += 1;
            Ok(())
        }
    }
    fn opened(disk: Model) -> Store<Model> {
        Store::open(disk, SNAPSHOT_DEADLINE).unwrap_or_else(|e| panic!("model open: {:?}", e.error))
    }
    fn initial(c: Catalogue) -> Store<Model> {
        Store::format_new(
            Model {
                bytes: vec![0; storage::DISK_BYTES],
                mutations: 0,
            },
            manifest(c, Slot::A, 1),
            OWNER_A,
            BootPolicy::new(3).unwrap(),
            SNAPSHOT_DEADLINE,
        )
        .unwrap_or_else(|_| panic!("model format"))
    }
    fn execute(store: &mut Store<Model>, request: ev_store::Request<'_>) {
        store
            .execute(store.next_operation().unwrap(), request, SNAPSHOT_DEADLINE)
            .unwrap();
    }
    // Explicitly constructed host observations exercise the validator, not
    // process execution or hardware health. Actual runner claims need real VMs.
    fn model_phase(store: Store<Model>, c: Catalogue, mode: Mode) -> (Store<Model>, Completion) {
        model_phase_for_variant(store, c, mode, GenerationVariant::Fault)
    }
    fn model_phase_for_variant(
        store: Store<Model>,
        c: Catalogue,
        mode: Mode,
        variant: GenerationVariant,
    ) -> (Store<Model>, Completion) {
        let disk = store.into_device();
        let start = if mode == Mode::ProvisionA {
            0
        } else {
            disk.mutations
        };
        let mut store = opened(disk);
        let (operation, serial, _, _) = expected(mode);
        let payload = if mode == Mode::ProvisionA {
            OWNER_A
        } else {
            OWNER_B
        };
        let mut report = Completion {
            mode,
            owner_decision: ev_userspace_contract::generation::OwnerDecision::None,
            booted: if mode == Mode::FailB { 2 } else { 1 },
            selected: 1,
            known_good: 1,
            boot_serial: serial,
            process: 7,
            thread: 9,
            failure_generation: 0,
            failure_serial: 0,
            failure_reason: 0,
            negatives: 4,
            mutations: 0,
            operation,
            sequence: operation + 1,
            failure_operation: 0,
            failure_sequence: 0,
            catalogue: hash(&c.encode()),
            process_stamp: [0; 32],
            storage_probe: hash(payload),
            booted_cohort: manifest(
                c,
                if mode == Mode::FailB {
                    Slot::B
                } else {
                    Slot::A
                },
                if mode == Mode::FailB { 2 } else { 1 },
            )
            .cohort,
        };
        if mode == Mode::FailB {
            execute(
                &mut store,
                ev_store::Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: OWNER_B,
                },
            );
            execute(
                &mut store,
                ev_store::Request::Stage(&manifest(c, Slot::B, 2)),
            );
            execute(
                &mut store,
                ev_store::Request::Activate(GenerationId::new(2).unwrap()),
            );
        } else if mode == Mode::ManualA {
            execute(
                &mut store,
                ev_store::Request::Stage(&manifest(c, Slot::B, 3)),
            );
            execute(
                &mut store,
                ev_store::Request::Activate(GenerationId::new(3).unwrap()),
            );
            execute(&mut store, ev_store::Request::SelectKnownGood);
        }
        if mode != Mode::Verify {
            report.process_stamp = stamp(c, &report);
            let selected = store.selected_manifest(SNAPSHOT_DEADLINE).unwrap();
            execute(
                &mut store,
                ev_store::Request::BeginBoot(selected.generation),
            );
            let plan = store.boot_plan(SNAPSHOT_DEADLINE).unwrap();
            assert_eq!(plan.serial, serial);
            let admitted = AdmissionReport {
                generation: selected.generation,
                boot_serial: plan.serial,
                process_stamp: report.process_stamp,
                cohort: selected.cohort,
                supervisor_image: selected.supervisor_image,
                abi: selected.abi,
                health_contract: selected.health_contract,
                health_version: selected.health_version,
            };
            execute(&mut store, ev_store::Request::Admission(admitted));
            if mode != Mode::FailB {
                execute(
                    &mut store,
                    ev_store::Request::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: payload,
                    },
                );
            }
            execute(
                &mut store,
                ev_store::Request::Health(HealthReport {
                    admitted,
                    outcome: if mode == Mode::FailB {
                        match variant {
                            GenerationVariant::Fault => HealthOutcome::ProcessFault,
                            GenerationVariant::MissingProgress => HealthOutcome::MissingProgress,
                        }
                    } else {
                        HealthOutcome::CriticalPassed
                    },
                    observed_checks: if mode == Mode::FailB { 0 } else { 3 },
                    storage_probe: hash(payload),
                }),
            );
        } else {
            report.booted = 0;
            report.boot_serial = 0;
            report.process = 0;
            report.thread = 0;
            report.negatives = 0;
            report.process_stamp = [0; 32];
            report.booted_cohort = [0; 32];
        }
        if let Some(failure) = store.last_failure().unwrap() {
            report.failure_generation = failure.generation.get();
            report.failure_serial = failure.boot_serial;
            report.failure_reason = match failure.reason {
                LastFailureReason::ProcessFault => 1,
                LastFailureReason::MissingProgress => 2,
                LastFailureReason::StorageFailure => 3,
                LastFailureReason::AttemptBudgetExhausted => 4,
                LastFailureReason::CriticalComponentFault => 5,
            };
            report.failure_operation = failure.operation.get();
            report.failure_sequence = failure.sequence;
        }
        assert_eq!(store.next_operation().unwrap().get(), operation + 1);
        let disk = store.into_device();
        report.mutations = disk.mutations - start;
        (opened(disk), report)
    }

    #[test]
    fn read_only_snapshots_cover_exact_five_phase_flow_counters_and_capsule_reuse() {
        let c = catalogue();
        let mut store = initial(c);
        let mut failure = None;
        let mut previous = Vec::new();
        for mode in MODES {
            let (next, report) = model_phase(store, c, mode);
            report_shape(&report, c, hash(&c.encode())).unwrap();
            let disk = next.into_device();
            let before = disk.bytes.clone();
            let observed = inspect_snapshot(&disk.bytes, c, &report, failure).unwrap();
            failure = observed.failure;
            assert_eq!(disk.bytes, before);
            assert_eq!(observed.evidence["mutation_attempts"], 0);
            if mode == Mode::Verify {
                assert_eq!(disk.bytes, previous);
            }
            previous = disk.bytes.clone();
            store = opened(disk);
        }
        assert_eq!(failure.unwrap().supervisor_image, c.image_b);
        assert_eq!(store.highest_generation(), Ok(3));
        assert!(21 - failure.unwrap().operation.get() > ev_store::JOURNAL_SLOTS);
    }

    #[test]
    fn exact_build_input_component_and_health_binding_cannot_be_mixed() {
        let c = catalogue();
        let build = hex(&c.kernel_build);
        check_catalogue(c, &build, roles(c)).unwrap();
        for index in 0..7 {
            let mut bytes = c.encode();
            bytes[16 + index * 32] ^= 0x80;
            let changed = Catalogue::decode(&bytes).unwrap();
            assert!(check_catalogue(changed, &build, roles(c)).is_err());
        }
        assert!(check_catalogue(c, &hex(&[9; 32]), roles(c)).is_err());
        assert!(digest("short").is_err());
        assert!(digest(&"é".repeat(32)).is_err());
        let mut wrong = roles(c);
        wrong.bad = wrong.good;
        assert!(check_catalogue(c, &build, wrong).is_err());
    }

    #[test]
    fn live_missing_progress_cold_snapshots_replay_the_exact_distinct_health_receipt() {
        let mut c = catalogue();
        c.image_b = [0x66; 32];
        let mut store = initial(c);
        let mut failure = None;
        let mut previous = Vec::new();
        for mode in MODES {
            let (next, report) =
                model_phase_for_variant(store, c, mode, GenerationVariant::MissingProgress);
            report_shape(&report, c, hash(&c.encode())).unwrap();
            report_variant(&report, GenerationVariant::MissingProgress).unwrap();
            if mode != Mode::ProvisionA {
                assert_eq!(report.failure_reason, 2);
                assert!(report_variant(&report, GenerationVariant::Fault).is_err());
            }
            let disk = next.into_device();
            let bytes = disk.bytes.clone();
            let observed = inspect_snapshot(&bytes, c, &report, failure).unwrap();
            assert_eq!(observed.evidence["mutation_attempts"], 0);
            if mode != Mode::ProvisionA {
                assert_eq!(observed.evidence["failure"]["reason"], "MissingProgress");
                assert_eq!(observed.failure.unwrap().supervisor_image, c.image_b);
                let mut wrong = report;
                wrong.failure_reason = 1;
                assert!(report_shape(&wrong, c, hash(&c.encode())).is_ok());
                assert!(inspect_snapshot(&bytes, c, &wrong, failure).is_err());
            }
            if mode == Mode::Verify {
                assert_eq!(bytes, previous);
            }
            failure = observed.failure;
            previous = bytes;
            store = opened(disk);
        }
        assert_eq!(failure.unwrap().reason, LastFailureReason::MissingProgress);
        assert_eq!(failure.unwrap().operation.get(), 10);
        assert_eq!(store.next_operation().unwrap().get(), 22);
    }

    #[test]
    fn fault_snapshot_cannot_be_relabelled_progress_and_owner_artifacts_stay_separate() {
        assert_eq!(
            CatalogueKind::Owner.artifacts(),
            (
                "m3-owner-catalogue.bin",
                "m3-owner-client.elf",
                "supervisor-generation-bad.elf"
            )
        );
        assert_eq!(
            CatalogueKind::Progress.artifacts(),
            (
                "m3-progress-catalogue.bin",
                "m3-progress-client.elf",
                "supervisor-generation-silent.elf"
            )
        );
        let c = catalogue();
        let (store, _) = model_phase(initial(c), c, Mode::ProvisionA);
        let (store, report) = model_phase(store, c, Mode::FailB);
        let bytes = store.into_device().bytes;
        report_variant(&report, GenerationVariant::Fault).unwrap();
        assert!(report_variant(&report, GenerationVariant::MissingProgress).is_err());
        let mut wrong = report;
        wrong.failure_reason = 2;
        assert!(report_shape(&wrong, c, hash(&c.encode())).is_ok());
        assert!(inspect_snapshot(&bytes, c, &wrong, None).is_err());
        for reason in [0, 3, 4, u64::MAX] {
            wrong.failure_reason = reason;
            assert!(report_shape(&wrong, c, hash(&c.encode())).is_err());
            assert!(inspect_snapshot(&bytes, c, &wrong, None).is_err());
        }
    }

    #[test]
    fn wrong_probe_stamp_fault_identity_and_mutation_counts_are_rejected() {
        let c = catalogue();
        let (store, _) = model_phase(initial(c), c, Mode::ProvisionA);
        let (store, good) = model_phase(store, c, Mode::FailB);
        let disk = store.into_device();
        for field in 0..5 {
            let mut report = good;
            match field {
                0 => report.process_stamp[0] ^= 1,
                1 => report.storage_probe[0] ^= 1,
                2 => report.failure_serial = 1,
                3 => report.mutations -= 1,
                _ => report.operation -= 1,
            }
            assert!(report_shape(&report, c, hash(&c.encode())).is_err());
        }
        let mut wrong = c;
        wrong.image_b[0] ^= 0x80;
        assert!(inspect_snapshot(&disk.bytes, wrong, &good, None).is_err());
        let mut corrupt = disk.bytes;
        // Provision's successful health probe used slot1; FailB's owner-data
        // update then publishes slot0. Corrupt the CURRENT referenced bytes.
        corrupt[(16 + 12) * 512 + 70] ^= 1;
        assert!(inspect_snapshot(&corrupt, c, &good, None).is_err());
    }

    #[test]
    fn committed_claim_cannot_depend_on_the_host_repairing_prepared_health() {
        let c = catalogue();
        let (store, report) = model_phase(initial(c), c, Mode::ProvisionA);
        let mut disk = store.into_device();
        // Latest seq5 root is removed; seq4 plus durable prepared Health4 can
        // recover, but the host observer MUST NOT perform that recovery write.
        disk.bytes[17 * 512..18 * 512].fill(0);
        let before = disk.bytes.clone();
        let error = inspect_snapshot(&disk.bytes, c, &report, None)
            .err()
            .expect("read-only repair refusal");
        assert!(error.contains("ReadOnly"), "{error}");
        assert_eq!(disk.bytes, before);
    }

    #[test]
    fn phase_preparation_failure_preserves_bytes_and_immutable_failure_evidence() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent =
            storage::directory_beneath(&root, Path::new("build/test-tmp/generation-host-tests"))
                .unwrap();
        let evidence = build::unique_directory(&parent, "prepare-failure").unwrap();
        let mut disk = Disk::create(&root, &evidence).unwrap();
        let retained = b"wrong size must be preserved";
        fs::write(evidence.join("data.raw"), retained).unwrap();
        let manifest = evidence.join("unused-manifest.json");
        let c = catalogue();
        let mut suite = Suite {
            root: &root,
            evidence: &evidence,
            manifest: &manifest,
            catalogue: c,
            catalogue_hash: hash(&c.encode()),
            phases: Vec::new(),
            failure: None,
            operation: 0,
            sequence: 1,
            boots: 0,
            variant: GenerationVariant::Fault,
        };
        assert!(suite.phase(&mut disk, Mode::ProvisionA).is_err());
        assert_eq!(fs::read(evidence.join("data.raw")).unwrap(), retained);
        let path = evidence.join("provision-a/phase-result.json");
        let first = fs::read(&path).unwrap();
        let result: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(result["passed"], false);
        assert_eq!(result["last_stage"], "control");
        assert_eq!(suite.phases.len(), 1);
        assert_eq!(suite.boots, 0);
        assert!(suite.phase(&mut disk, Mode::ProvisionA).is_err());
        assert_eq!(fs::read(path).unwrap(), first);
        assert_eq!(fs::read(evidence.join("data.raw")).unwrap(), retained);
        fs::remove_dir_all(evidence).unwrap();
    }
}
