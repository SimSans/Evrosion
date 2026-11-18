//! Owner recovery on a retained coherent bundle and a private persistent disk.
use crate::{
    boot::{self, OwnerBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    generation as g,
    journal::unchanged_guards,
    owner_io::Input,
    owner_protocol,
    storage::{self, Disk},
};
use ev_store::LastFailure;
use ev_userspace_contract::generation::{Catalogue, Completion, Control, Mode, OwnerDecision};
use serde_json::{Value, json};
use std::{fs, path::Path};

fn link(path: &Path, base: &Path) -> Result<Value> {
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"owner evidence escaped its directory")?,"sha256":build::hash_file(path)?}),
    )
}
fn maybe_link(path: &Path, base: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => link(path, base).map(Some),
        Ok(_) => Err("owner evidence must be a regular non-symlink file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[derive(Clone, Copy)]
struct Phase {
    name: &'static str,
    control: Control,
    input: Option<Input>,
    decision: Option<OwnerDecision>,
    unchanged: bool,
}
impl Phase {
    fn ordinary(name: &'static str, mode: Mode) -> Self {
        Self {
            name,
            control: Control::new(mode),
            input: None,
            decision: Some(OwnerDecision::None),
            unchanged: mode == Mode::Verify,
        }
    }
    fn recover(
        name: &'static str,
        input: Input,
        decision: Option<OwnerDecision>,
        ticks: u64,
    ) -> Self {
        Self {
            name,
            control: Control::owner_recover(ticks).unwrap(),
            input: Some(input),
            decision,
            unchanged: !matches!(decision, Some(OwnerDecision::Continue)),
        }
    }
}

struct Suite<'a> {
    root: &'a Path,
    evidence: &'a Path,
    manifest_path: &'a Path,
    manifest: &'a Manifest,
    catalogue: Catalogue,
    catalogue_hash: [u8; 32],
    failure: Option<LastFailure>,
    prepared: Option<Completion>,
    operation: u64,
    sequence: u64,
    boots: u64,
    phases: Vec<Value>,
}
impl Suite<'_> {
    fn phase(&mut self, spec: Phase, disk: &mut Disk) -> Result<()> {
        let directory = storage::directory_beneath(self.evidence, Path::new(spec.name))?;
        let mut stage = "control";
        let mut before_record = None;
        let operation: Result<Value> = (|| {
            disk.generation_control(spec.control)?;
            stage = "before_snapshot";
            let before = disk.bytes()?;
            before_record = Some(disk.capture(&directory, "data-before.raw")?);
            stage = "boot";
            self.boots += 1;
            let eof = boot::boot_owner(
                &BootOptions {
                    root: Some(self.root.to_owned()),
                    timeout_seconds: 160,
                    ..BootOptions::default()
                },
                OwnerBoot {
                    manifest: self.manifest_path,
                    evidence: &directory,
                    disk,
                    control: spec.control,
                    catalogue: &g::hex(&self.catalogue_hash),
                    input: spec.input,
                },
            )?;
            stage = "raw_readback";
            let after = disk.bytes()?;
            unchanged_guards(&before, &after)?;
            let serial =
                fs::read(directory.join("boot/run-001/serial.log")).map_err(|e| e.to_string())?;
            if eof {
                if !matches!(spec.input, Some(Input::Eof | Input::Owner)) || before != after {
                    return Err(
                        "owner EOF either submitted an action or changed the persistent disk"
                            .into(),
                    );
                }
                if owner_protocol::text(&serial)?.contains("EVROSION_M3_OWNER status=") {
                    return Err("host EOF cannot claim a completed guest owner proof".into());
                }
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or("owner EOF has no earlier measured prepared baseline")?;
                // This is the earlier REAL Prepare3 report, solely a baseline
                // for unchanged bytes. No completion/health is invented for EOF.
                let raw = g::inspect_snapshot(&after, self.catalogue, prepared, self.failure)?;
                return Ok(
                    json!({"guest_completed":false,"eof_no_action":true,"raw":raw.evidence,
                    "whole_disk_unchanged":true,"guest_report":null}),
                );
            }
            stage = "guest_record";
            let actual = owner_protocol::record(&serial)?;
            let report = actual.report;
            let budget = owner_protocol::budget(&serial)?;
            if report.mode != spec.control.mode
                || spec
                    .decision
                    .is_some_and(|decision| decision != report.owner_decision)
            {
                return Err(
                    "owner phase or actual decision differs from its requested test".into(),
                );
            }
            if report.mode != Mode::ProvisionA && report.failure_reason != 1 {
                return Err(
                    "owner fixture did not retain its actual original B process fault".into(),
                );
            }
            if spec.unchanged && report.owner_decision != OwnerDecision::Continue && before != after
            {
                return Err("cancel/no-action/Verify changed persistent bytes".into());
            }
            if report.operation < self.operation || report.sequence < self.sequence {
                return Err("owner recovery reset durable operation history".into());
            }
            if report.mutations > 0 && report.operation <= self.operation {
                return Err("owner mutation failed to advance operation history".into());
            }
            let prompt = if report.mode == Mode::OwnerRecover {
                let prompt = owner_protocol::prompt(
                    &serial,
                    &self.manifest.build_id,
                    &g::hex(&self.catalogue_hash),
                )?
                .ok_or("owner action has no current prompt")?;
                let image = format!("Failed image: {}", g::hex(&self.catalogue.image_b));
                if !owner_protocol::text(&serial)?
                    .lines()
                    .any(|line| line == image)
                {
                    return Err("owner explanation names the wrong failed image".into());
                }
                let input: Value = serde_json::from_slice(
                    &fs::read(directory.join("boot/run-001/owner-input.json"))
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let written = input["written"]
                    .as_array()
                    .ok_or("owner input record missing actual bytes")?
                    .iter()
                    .map(|row| {
                        row.get(1)
                            .and_then(Value::as_u64)
                            .and_then(|n| u8::try_from(n).ok())
                            .ok_or_else(|| "malformed actual owner input byte".to_owned())
                    })
                    .collect::<Result<Vec<_>>>()?;
                let fresh = &actual.received[actual.before_tx..];
                if written != fresh {
                    return Err("actual UART data differs from the retained submitted input".into());
                }
                Some(json!({"prompt":prompt,"input":input}))
            } else {
                None
            };
            g::report_shape(&report, self.catalogue, self.catalogue_hash)?;
            let observed = g::inspect_snapshot(&after, self.catalogue, &report, self.failure)?;
            self.failure = observed.failure;
            self.operation = report.operation;
            self.sequence = report.sequence;
            if report.mode == Mode::OwnerPrepare3 {
                self.prepared = Some(report);
            }
            Ok(
                json!({"guest_completed":true,"actual":g::report_json(&report),"raw":observed.evidence,
                "budget":budget,"uart":{"inputs":actual.uart_inputs,"outputs":actual.uart_outputs,
                    "received":actual.received,"before_tx":actual.before_tx},"owner":prompt,
                "guards_unchanged":true,"whole_disk_unchanged":before==after}),
            )
        })();
        let captured = disk.capture(&directory, "data-after.raw");
        let boot = maybe_link(&directory.join("boot/results.json"), &directory);
        let path = directory.join("phase-result.json");
        storage::json_new(
            &path,
            &json!({"schema":1,"kind":"owner-recovery-phase","phase":spec.name,
            "passed":operation.is_ok()&&captured.is_ok()&&boot.is_ok(),"last_stage":stage,"before":before_record,
            "after":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),"boot":boot.as_ref().ok(),
            "boot_link_error":boot.as_ref().err(),"validation":operation.as_ref().ok(),"error":operation.as_ref().err()}),
        )?;
        self.phases.push(link(&path, self.evidence)?);
        operation?;
        captured?;
        boot?;
        Ok(())
    }
}

pub(crate) fn run() -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m3/evidence"))?;
    let evidence = build::unique_directory(&parent, "owner-recovery")?;
    println!("Evidence: {}", evidence.display());
    let manifest_path = evidence.join("manifest.json");
    let mut stage = "build";
    let mut build_record = None;
    let mut suite = None;
    let mut disk = None;
    let mut final_disk = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some("m3-owner".into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_manifest";
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some("m3-owner") {
            return Err("owner workflow selected wrong fixture".into());
        }
        let (catalogue, catalogue_hash) = g::retain_catalogue(&root, &evidence, &manifest, true)?;
        build_record = Some(
            json!({"record":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,"kernel":manifest.kernel,"boot_image":manifest.image}),
        );
        stage = "disk";
        disk = Some(Disk::create(&root, &evidence)?);
        let mut running = Suite {
            root: &root,
            evidence: &evidence,
            manifest_path: &manifest_path,
            manifest: &manifest,
            catalogue,
            catalogue_hash,
            failure: None,
            prepared: None,
            operation: 0,
            sequence: 0,
            boots: 0,
            phases: Vec::new(),
        };
        stage = "phases";
        let experiment = (|| {
            for phase in [
                Phase::ordinary("provision-a", Mode::ProvisionA),
                Phase::ordinary("fail-b", Mode::FailB),
                Phase::ordinary("auto-a", Mode::AutoA),
                Phase::ordinary("owner-prepare3", Mode::OwnerPrepare3),
                Phase::recover(
                    "cancel",
                    Input::Script(b"q\n"),
                    Some(OwnerDecision::Cancel),
                    1024,
                ),
                Phase::recover("timeout", Input::Silent, Some(OwnerDecision::Timeout), 128),
                Phase::recover(
                    "invalid-cancel",
                    Input::Script(b"noise r\nq\n"),
                    Some(OwnerDecision::Cancel),
                    1024,
                ),
                Phase::recover("eof", Input::Eof, None, 60000),
                Phase::recover(
                    "continue",
                    Input::Script(b"r\n"),
                    Some(OwnerDecision::Continue),
                    1024,
                ),
                Phase::ordinary("verify", Mode::Verify),
            ] {
                running.phase(phase, disk.as_mut().unwrap())?;
            }
            if running.boots != 10 {
                return Err("owner suite did not execute all ten required fresh VMs".into());
            }
            final_disk = Some(
                disk.as_ref()
                    .unwrap()
                    .capture(&evidence, "final-disk.raw")?,
            );
            Ok(())
        })();
        suite = Some(
            json!({"boot_invocations":running.boots,"phases":running.phases,"last_operation":running.operation,"last_sequence":running.sequence}),
        );
        experiment
    })();
    let sealed = disk.as_ref().map(Disk::seal).transpose();
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"owner-recovery","passed":result.is_ok()&&sealed.is_ok(),"final_disk":final_disk,
        "last_stage":stage,"build":build_record,"suite":suite,"error":result.as_ref().err(),"seal_error":sealed.as_ref().err(),
        "method":"One retained owner bundle; ten fresh VMs; real UART complete lines, no-action timeout/EOF, independent read-only snapshots and mutable-data preservation. EOF is a host kill/reap proof, not guest PASS."}),
    )?;
    result?;
    sealed?;
    println!(
        "PASS owner recovery: actual cancel/continue, invalid input, timeout and EOF; protected A and owner data survive."
    );
    Ok(())
}

pub(crate) fn resume(source: &Path) -> Result<()> {
    let current = std::env::current_dir().map_err(|error| error.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let source = if source.is_absolute() {
        source.to_owned()
    } else {
        current.join(source)
    };
    let prepared = crate::owner_import::load(&root, &source)?;
    let parent = storage::directory_beneath(&root, Path::new("build/m3/evidence"))?;
    let evidence = build::unique_directory(&parent, "owner-resume")?;
    println!("Using a private copy of the prepared recovery snapshot.");
    println!("Evidence: {}", evidence.display());
    let manifest_path = evidence.join("manifest.json");
    storage::immutable_new(&manifest_path, &prepared.manifest_bytes)?;
    let (catalogue, catalogue_hash) =
        g::retain_catalogue(&root, &evidence, &prepared.manifest, true)?;
    if (catalogue, catalogue_hash) != (prepared.catalogue, prepared.catalogue_hash) {
        return Err("prepared recovery catalogue changed".into());
    }
    let mut disk = Disk::create(&root, &evidence)?;
    disk.restore_snapshot(&prepared.snapshot)?;
    let mut suite = Suite {
        root: &root,
        evidence: &evidence,
        manifest_path: &manifest_path,
        manifest: &prepared.manifest,
        catalogue,
        catalogue_hash,
        failure: Some(prepared.failure),
        prepared: Some(prepared.report),
        operation: 16,
        sequence: 17,
        boots: 0,
        phases: Vec::new(),
    };
    let result = suite.phase(
        Phase::recover("interactive", Input::Owner, None, 60000),
        &mut disk,
    );
    let capture = disk.capture(&evidence, "final-disk.raw");
    let sealed = disk.seal();
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"owner-resume",
        "passed":result.is_ok()&&capture.is_ok()&&sealed.is_ok(),"origin":prepared.origin,
        "build":{"build_id":prepared.manifest.build_id,"record":link(&manifest_path,&evidence)?},
        "boot_invocations":suite.boots,"phases":suite.phases,"final_disk":capture.as_ref().ok(),
        "error":result.as_ref().err(),"capture_error":capture.as_ref().err(),"seal_error":sealed.as_ref().err(),
        "source_snapshot_modified":false}),
    )?;
    result?;
    capture?;
    sealed?;
    let completed: Value = serde_json::from_slice(
        &fs::read(evidence.join("interactive/phase-result.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if completed["validation"]["actual"]["owner_decision"] == 1 {
        println!("Known-good generation A was booted and verified. Your files are preserved.");
    } else {
        println!("No recovery action was taken. Your files and source snapshot are unchanged.");
    }
    Ok(())
}
