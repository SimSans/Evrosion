//! Source-bound six-boot downloaded System health/recovery qualification.
use crate::{
    acquisition_io::{self, Plan},
    boot::{self, AcquisitionBoot, SystemHealthBoot},
    build::{self, Manifest, Result},
    cli::{AcquisitionOptions, BootOptions, BuildOptions},
    download_fixture,
    network_io::{
        acquisition_disk::{self as disk_check, system_health as system_disk},
        components::Context,
    },
    network_mode::Mode,
    storage,
    system_health_io::{self, Phase},
};
use serde_json::json;
use std::{fs, path::Path};

fn manifest(
    root: &Path,
    evidence: &Path,
    mode: Mode,
    source: &(String, Vec<build::SourceInput>),
) -> Result<(std::path::PathBuf, Manifest, Context)> {
    build::build(&BuildOptions {
        root: Some(root.to_owned()),
        release: true,
        fixture: Some(mode.fixture().into()),
    })?;
    let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
    let m: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    m.validate_policy_rows()?;
    if m.profile != "release"
        || m.fixture.as_deref() != Some(mode.fixture())
        || m.source_sha256 != source.0
        || m.source_inputs != source.1
    {
        return Err("System exact mode/source/profile differs".into());
    }
    let dir = storage::directory_beneath(evidence, Path::new(mode.fixture()))?;
    let path = dir.join("manifest.json");
    storage::immutable_new(&path, &bytes)?;
    let kernel = build::verify_artifact(&root.join("build/m0"), &m.kernel)?;
    let status = std::process::Command::new("python3")
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg(kernel)
        .arg(dir.join("kernel-stack.json"))
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("System selected actual Kernel linked stack refuses".into());
    }
    let context = Context::retain_mode(
        root,
        &m,
        &storage::directory_beneath(&dir, Path::new("component-preflight"))?,
        mode,
        false,
    )?;
    Ok((path, m, context))
}
pub(crate) fn run(options: &AcquisitionOptions) -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let signer = options.authority_root.as_ref().map_or_else(
        || Ok(root.clone()),
        |p| fs::canonicalize(p).map_err(|e| e.to_string()),
    )?;
    let _authority = acquisition_io::authority(&root, &signer)?;
    let parent = storage::directory_beneath(&root, Path::new("build/m6/evidence"))?;
    let evidence = build::unique_directory(&parent, "system-health")?;
    println!("Evidence: {}", evidence.display());
    let source = build::source_inputs(&root)?;
    storage::json_new(
        &evidence.join("source-before.json"),
        &json!({"sha256":source.0,"inputs":source.1}),
    )?;
    let mut owned_disk = None;
    let mut phases = Vec::new();
    let result: Result<()> = (|| {
        let (standalone_path, standalone, context) =
            manifest(&root, &evidence, Mode::Standalone, &source)?;
        let (managed_path, managed, managed_context) =
            manifest(&root, &evidence, Mode::SystemManaged, &source)?;
        let (recovery_path, recovery, recovery_context) =
            manifest(&root, &evidence, Mode::Recovery, &source)?;
        if context.images != managed_context.images || context.images != recovery_context.images {
            return Err("System mode set changes protected actual component images".into());
        }
        let bundle_dir = root
            .join("build/m6/downloads")
            .join(evidence.file_name().ok_or("System evidence name")?);
        let bundle = download_fixture::produce(&root, &bundle_dir, &source.0)?;
        acquisition_io::absent_from_banks(&context, &bundle)?;
        let make_plan = |m: &Manifest| Plan {
            schema: 1,
            source_sha256: m.source_sha256.clone(),
            build_id: m.build_id.clone(),
            bundle_directory: bundle_dir.clone(),
            authority_workspace: signer.clone(),
            public_root_sha256: acquisition_io::hash(_authority.root()),
            downloaded_elf_sha256: bundle.downloads[0]
                .component
                .image_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            downloaded_package_sha256: bundle.downloads[0]
                .package_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        };
        let (seed, seed_proof) = crate::native_seed::checkpoint(&root, &evidence)?;
        storage::json_new(&evidence.join("seed-proof.json"), &seed_proof)?;
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&seed)?;
        owned_disk = Some(disk);
        let disk = owned_disk.as_ref().unwrap();
        let options = BootOptions {
            timeout_seconds: acquisition_io::TIMEOUT_SECONDS,
            ..BootOptions::default()
        };
        let setup = storage::directory_beneath(&evidence, Path::new("online-b-acquisition"))?;
        storage::json_new(
            &setup.join("acquisition-plan.json"),
            &serde_json::to_value(make_plan(&standalone)).map_err(|e| e.to_string())?,
        )?;
        disk.capture(&setup, "data-before.raw")?;
        let boot = boot::boot_acquisition(
            &options,
            AcquisitionBoot {
                manifest: &standalone_path,
                evidence: &setup,
                disk,
                phase: acquisition_io::Phase::Online,
            },
        );
        let capture = disk.capture(&setup, "data-after.raw");
        phases.push(json!({"phase":"actual-online-B-acquisition","passed":boot.is_ok(),"error":boot.as_ref().err(),"capture_error":capture.as_ref().err()}));
        boot?;
        capture?;
        let baseline = fs::read(setup.join("setup-baseline.raw")).map_err(|e| e.to_string())?;
        let b = fs::read(bundle.downloads[0].package.clone()).map_err(|e| e.to_string())?;
        let c = fs::read(bundle.downloads[1].package.clone()).map_err(|e| e.to_string())?;
        let release_bytes = ["root.bin", "targets.bin", "snapshot.bin", "timestamp.bin"]
            .map(|name| fs::read(setup.join("phase-b").join(name)).map_err(|e| e.to_string()));
        let [rb, tb, sb, tsb] = release_bytes;
        let (rb, tb, sb, tsb) = (rb?, tb?, sb?, tsb?);
        let audit = disk_check::online(
            &baseline,
            &disk.bytes()?,
            &context.packages()?,
            disk_check::Release {
                root: &rb,
                targets: &tb,
                snapshot: &sb,
                timestamp: &tsb,
                artifact: &b,
            },
            disk_check::Expected {
                registry_revision: 4,
                registry_active: bundle.downloads[0].package_id,
                registry_staged: None,
                registry_previous: Some(
                    context
                        .packages()?
                        .digest(ev_root_supervisor::native_plan::Slot::A),
                ),
                trust_active: Some(2),
                known_good: None,
                saved: disk_check::Saved {
                    note: acquisition_io::NOTE,
                    note_counter: 1,
                    value: 1001,
                    data_counter: 0,
                },
            },
        )?;
        storage::json_new(&setup.join("acquisition-disk-audit.json"), &audit.proof)?;
        let mut previous_replay = Some(audit.replay());
        let mut failure = None;
        let mut healthy_b = None;
        for phase in [
            Phase::SelectB,
            Phase::HealthyAndStageC,
            Phase::FaultC,
            Phase::Recovery,
            Phase::FinalB,
        ] {
            let (mp, m, ctx) = match phase.mode() {
                Mode::Standalone => (&standalone_path, &standalone, &context),
                Mode::SystemManaged => (&managed_path, &managed, &managed_context),
                Mode::Recovery => (&recovery_path, &recovery, &recovery_context),
            };
            let dir = storage::directory_beneath(&evidence, Path::new(phase.name()))?;
            storage::json_new(
                &dir.join("acquisition-plan.json"),
                &serde_json::to_value(make_plan(m)).map_err(|e| e.to_string())?,
            )?;
            storage::immutable_new(
                &dir.join("namespace-origin-manifest.json"),
                &fs::read(&standalone_path).map_err(|e| e.to_string())?,
            )?;
            disk.capture(&dir, "data-before.raw")?;
            let before = disk.bytes()?;
            let boot = boot::boot_system_health(
                &options,
                SystemHealthBoot {
                    manifest: mp,
                    evidence: &dir,
                    disk,
                    phase,
                },
            );
            let captured = disk.capture(&dir, "data-after.raw");
            let after = disk.bytes();
            phases.push(json!({"phase":phase,"passed":boot.is_ok(),"error":boot.as_ref().err(),"capture_error":captured.as_ref().err()}));
            boot?;
            captured?;
            let after = after?;
            let (
                selected,
                known_good,
                active,
                candidate,
                boot_serial,
                failed_child,
                note,
                note_counter,
            ) = match phase {
                Phase::SelectB => (2, None, 2, 2, 0, false, acquisition_io::NOTE, 1),
                Phase::HealthyAndStageC => {
                    (3, Some(2), 2, 3, 1, false, system_health_io::LATER_NOTE, 2)
                }
                Phase::FaultC | Phase::Recovery => {
                    (2, Some(2), 3, 3, 2, true, system_health_io::LATER_NOTE, 2)
                }
                Phase::FinalB => (2, Some(2), 2, 3, 3, true, system_health_io::LATER_NOTE, 2),
            };
            let creation =
                disk_check::NamespaceCreation::checked(&context.packages()?, &ctx.packages()?)?;
            let mut audited = system_disk::inspect(
                &before,
                &after,
                &ctx.packages()?,
                &creation,
                &[&b, &c],
                system_disk::Expected {
                    selected,
                    known_good,
                    active,
                    candidate,
                    boot_serial,
                    failed_child,
                    saved: disk_check::Saved {
                        note,
                        note_counter,
                        value: 1001,
                        data_counter: 0,
                    },
                },
                phase == Phase::HealthyAndStageC,
            )?;
            let serial =
                acquisition_io::bounded(&dir.join("boot/run-001/serial.log"), 1024 * 1024)?;
            let admitted = system_health_io::admission_join(
                ctx,
                &serial,
                &m.build_id,
                phase,
                &audited.selected,
                &audited.active,
                audited.failure,
            )?;
            audited.proof["actual_current_admission"] = json!(
                admitted.map(|a| json!({
                "generation":a.generation.get(),"boot_serial":a.boot_serial,
                "process_stamp":a.process_stamp,"actual_Root_and_downloaded_subject_joined":true}))
            );
            if phase == Phase::HealthyAndStageC {
                healthy_b = admitted;
            }
            let probe_admission = match phase {
                Phase::SelectB => None,
                Phase::FinalB => admitted,
                _ => healthy_b,
            };
            if phase != Phase::SelectB && probe_admission.is_none() {
                return Err("System exact healthy B probe admission absent".into());
            }
            system_disk::verify_probe(&mut audited, probe_admission)?;
            if phase == Phase::FaultC {
                let summary = audited
                    .child_summary
                    .as_ref()
                    .ok_or("System child summary absent")?;
                crate::system_health_io::fault_summary_join(
                    &dir.join("boot/run-001/serial.log"),
                    &m.build_id,
                    summary,
                )?;
            }
            if let Some(old) = previous_replay
                && phase != Phase::HealthyAndStageC
                && old != audited.replay
            {
                return Err("System local boot/recovery changed remote replay floors".into());
            }
            if let Some(old) = failure
                && audited.failure != Some(old)
            {
                return Err("System recovery lost original LAST child-fault facts".into());
            }
            if failed_child {
                failure = audited.failure;
            }
            previous_replay = Some(audited.replay);
            if audited.selected.generation.get() != selected {
                return Err("System selected identity mismatch".into());
            }
            storage::json_new(
                &dir.join("System-and-content-disk-audit.json"),
                &audited.proof,
            )?;
        }
        Ok(())
    })();
    let seal = owned_disk.as_ref().map_or(Ok(()), storage::Disk::seal);
    let postflight = build::source_inputs(&root).and_then(|actual| {
        storage::json_new(
            &evidence.join("source-after.json"),
            &json!({"sha256":actual.0,"inputs":actual.1,"unchanged":actual==source}),
        )?;
        if actual == source {
            Ok(())
        } else {
            Err("System source changed during execution".into())
        }
    });
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"actual-downloaded-System-six-boot-health-recovery",
        "passed":result.is_ok()&&seal.is_ok()&&postflight.is_ok(),"error":result.as_ref().err(),"seal_error":seal.as_ref().err(),
        "source_postflight_error":postflight.as_ref().err(),"phases":phases,"scripted_input":true,"human_consent_claim":false,
        "same_owned_disk":true,"same_source_three_explicit_mode_images":true,"whole_M6_acceptance":false,"physical_qualification":false}),
    )?;
    result?;
    seal?;
    postflight
}
