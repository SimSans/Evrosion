//! Separate finite UI qualification on a new owned disk. Manual cargo network
//! never calls this or receives automatic input.
use crate::{
    boot::{self, OwnerUiProbeBoot},
    build::{self, Result},
    cli::{AcquisitionOptions, BootOptions},
    network_mode::Mode,
    network_session::BootSet,
    owner_ui_io::Phase,
    storage,
};
use serde_json::json;
use std::{fs, path::Path};
pub(crate) fn run(options: &AcquisitionOptions) -> Result<()> {
    run_scoped(options, true, false)
}
pub(crate) fn exercise(options: &AcquisitionOptions) -> Result<()> {
    run_scoped(options, false, false)
}
pub(crate) fn first_use(options: &AcquisitionOptions) -> Result<()> {
    run_scoped(options, true, true)
}
fn run_scoped(options: &AcquisitionOptions, managed_cold: bool, first_use: bool) -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m6/evidence"))?;
    let evidence = build::unique_directory(
        &parent,
        if first_use {
            "owner-ui-first-use-probe"
        } else if managed_cold {
            "owner-ui-probe"
        } else {
            "owner-ui-exercise-probe"
        },
    )?;
    println!("Evidence: {}", evidence.display());
    let source = build::source_inputs(&root)?;
    let set = BootSet::fresh(&root, &evidence)?;
    let signer = options.authority_root.as_ref().map_or_else(
        || Ok(root.clone()),
        |p| fs::canonicalize(p).map_err(|e| e.to_string()),
    )?;
    let (seed, seed_proof) = crate::native_seed::checkpoint(&root, &evidence)?;
    let mut disk = storage::Disk::create(&root, &evidence)?;
    disk.restore_snapshot(&seed)?;
    let fixture = crate::download_fixture::Server::pending()?;
    fixture.replace_phase(
        set.publish_b_from(&root, &signer, &seed, &evidence)?
            .ok_or("new UI probe has unexpected target floor")?,
    )?;
    let settings = BootOptions {
        timeout_seconds: 600,
        ..BootOptions::default()
    };
    let mut rounds = Vec::new();
    let result: Result<()> = (|| {
        let exercise = storage::directory_beneath(
            &evidence,
            Path::new(if first_use { "first-use" } else { "exercise" }),
        )?;
        disk.capture(&exercise, "data-before.raw")?;
        let intent = boot::boot_owner_ui_probe(
            &settings,
            OwnerUiProbeBoot {
                manifest: set.path(Mode::Standalone),
                evidence: &exercise,
                disk: &disk,
                mode: Mode::Standalone,
                phase: if first_use {
                    Phase::FirstUse {
                        package: set.bundle.downloads[0].package_sha256,
                    }
                } else {
                    Phase::Exercise
                },
            },
        );
        let after = disk.capture(&exercise, "data-after.raw");
        rounds.push(json!({"phase":if first_use {"first-use-no-App"} else {"exercise"},"intent":intent.as_ref().ok(),"error":intent.as_ref().err(),"after":after.as_ref().ok()}));
        after?;
        let intent =
            intent?.ok_or("confirmed owner UI produced no authenticated restart intent")?;
        let mode = set.restart_mode(&disk.bytes()?, &intent)?;
        if mode != Mode::SystemManaged {
            return Err("confirmed owner UI selected wrong next mode".into());
        }
        if !managed_cold {
            let saved = crate::network_io::acquisition_disk::saved_state(
                &disk.bytes()?,
                &set.context(Mode::Standalone).packages()?,
                crate::network_io::acquisition_disk::Saved {
                    note: crate::owner_ui_io::NOTE,
                    note_counter: 1,
                    value: 1001,
                    data_counter: 0,
                },
            )?;
            storage::json_new(
                &exercise.join("warm-selection.json"),
                &json!({"saved":saved,"durable_selected_generation":intent.generation,"source_bound_mode":mode.owner_fixture(),"known_good_or_managed_health_claim":false,"relaunch_performed":false}),
            )?;
            drop(fixture);
            return Ok(());
        }
        drop(fixture); // the next actual VM must use authenticated local bytes offline.
        let expected_saved = crate::network_io::acquisition_disk::Saved {
            note: if first_use {
                ""
            } else {
                crate::owner_ui_io::NOTE
            },
            note_counter: if first_use { 0 } else { 1 },
            value: 1001,
            data_counter: 0,
        };
        let cold = storage::directory_beneath(&evidence, Path::new("cold"))?;
        disk.capture(&cold, "data-before.raw")?;
        let cold_before = disk.bytes()?;
        let result = boot::boot_owner_ui_probe(
            &settings,
            OwnerUiProbeBoot {
                manifest: set.path(mode),
                evidence: &cold,
                disk: &disk,
                mode,
                phase: if first_use {
                    Phase::FirstUseCold
                } else {
                    Phase::Cold
                },
            },
        );
        let after = disk.capture(&cold, "data-after.raw");
        rounds.push(json!({"phase":"cold","intent":result.as_ref().ok(),"error":result.as_ref().err(),"after":after.as_ref().ok()}));
        after?;
        if result?.is_some() {
            return Err("cold Finish invented another restart intent".into());
        }
        let creation = crate::network_io::acquisition_disk::NamespaceCreation::checked(
            &set.context(Mode::Standalone).packages()?,
            &set.context(mode).packages()?,
        )?;
        let saved = crate::network_io::acquisition_disk::saved_state_with_creation(
            &disk.bytes()?,
            &set.context(mode).packages()?,
            &creation,
            expected_saved,
        )?;
        storage::json_new(&cold.join("saved-data.json"), &saved)?;
        let b = fs::read(&set.bundle.downloads[0].package).map_err(|e| e.to_string())?;
        let c = fs::read(&set.bundle.downloads[1].package).map_err(|e| e.to_string())?;
        let mut checked = crate::network_io::acquisition_disk::system_health::inspect(
            &cold_before,
            &disk.bytes()?,
            &set.context(mode).packages()?,
            &creation,
            &[&b, &c],
            crate::network_io::acquisition_disk::system_health::Expected {
                selected: 2,
                known_good: Some(2),
                active: 2,
                candidate: 2,
                failed_child: false,
                boot_serial: 1,
                saved: expected_saved,
            },
            false,
        )?;
        let serial =
            crate::acquisition_io::bounded(&cold.join("boot/run-001/serial.log"), 1024 * 1024)?;
        let admitted = crate::system_health_io::admission_join(
            set.context(mode),
            &serial,
            &set.manifests[mode.index()].build_id,
            crate::system_health_io::Phase::HealthyAndStageC,
            &checked.selected,
            &checked.active,
            checked.failure,
        )?;
        crate::network_io::acquisition_disk::system_health::verify_probe(&mut checked, admitted)?;
        storage::json_new(
            &cold.join("system-health-captured.json"),
            &json!({"captured":checked.proof,"replay_sha256":crate::acquisition_io::hash(&checked.replay),"selected_generation":checked.selected.generation.get(),"selected_manifest":ev_root_supervisor::native_plan::system::manifest_digest(&checked.selected),"failure_present":checked.failure.is_some(),"child_summary":checked.child_summary.map(|b|crate::acquisition_io::hash(&b)),"GUI_is_health_claim":false}),
        )?;
        Ok(())
    })();
    let unchanged = build::source_inputs(&root)? == source;
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":if first_use {"finite-owned-real-device-owner-ui-first-use"} else if managed_cold {"finite-owned-real-device-owner-ui"} else {"finite-owned-real-device-owner-ui-exercise"},"managed_cold_exercised":managed_cold&&result.is_ok(),"passed":result.is_ok()&&unchanged,"error":result.as_ref().err(),"rounds":rounds,"seed":seed_proof,"source_unchanged":unchanged,"scripted_input":true,"human_consent_claim":false,"whole_M6_acceptance":false}),
    )?;
    disk.seal()?;
    result?;
    if !unchanged {
        return Err("owner UI probe source changed".into());
    }
    Ok(())
}
