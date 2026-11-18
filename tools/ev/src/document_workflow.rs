//! Offline document qualification on a newly owned disk; never resets an owner
//! session or labels a model test as a VM workflow.
use crate::{
    boot::{self, DocumentBoot, DocumentInterruptionBoot},
    build::{self, Manifest, Result},
    cli::BootOptions,
    document_interruption::{self, Phase as InterruptionPhase},
    document_io::{self, Phase},
    storage,
};
use serde_json::json;
use std::{fs, path::Path};
pub(crate) fn run() -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let manifest_bytes = fs::read(root.join("build/m0/manifest.json"))
        .map_err(|e| format!("build m7-document first: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.fixture.as_deref() != Some("m7-document") {
        return Err("explicit m7-document build required".into());
    }
    let parent = storage::directory_beneath(&root, Path::new("build/m7/evidence"))?;
    let evidence = build::unique_directory(&parent, "document")?;
    println!("Evidence: {}", evidence.display());
    let path = evidence.join("manifest.json");
    storage::immutable_new(&path, &manifest_bytes)?;
    let (seed, provenance) = crate::native_seed::checkpoint(&root, &evidence)?;
    let mut disk = storage::Disk::create(&root, &evidence)?;
    disk.restore_snapshot(&seed)?;
    let options = BootOptions {
        timeout_seconds: 240,
        ..BootOptions::default()
    };
    boot::boot_document(
        &options,
        DocumentBoot {
            manifest: &path,
            evidence: &evidence,
            disk: &disk,
            phase: Some(Phase::Exercise),
        },
    )?;
    let saved = disk.bytes()?;
    let proof = crate::native3_disk::document(&saved, 1, document_io::SAVED)?;
    let cold = evidence.join("cold");
    fs::create_dir(&cold).map_err(|e| e.to_string())?;
    boot::boot_document(
        &options,
        DocumentBoot {
            manifest: &path,
            evidence: &cold,
            disk: &disk,
            phase: Some(Phase::Cold),
        },
    )?;
    let after = disk.bytes()?;
    if after != saved {
        return Err("cold reopen changed the retained disk".into());
    }
    let cancelled = evidence.join("cancel");
    fs::create_dir(&cancelled).map_err(|e| e.to_string())?;
    boot::boot_document(
        &options,
        DocumentBoot {
            manifest: &path,
            evidence: &cancelled,
            disk: &disk,
            phase: Some(Phase::Cancel),
        },
    )?;
    if disk.bytes()? != saved {
        return Err("cancelled picker changed retained disk".into());
    }
    let crashed = evidence.join("crash");
    fs::create_dir(&crashed).map_err(|e| e.to_string())?;
    boot::boot_document(
        &options,
        DocumentBoot {
            manifest: &path,
            evidence: &crashed,
            disk: &disk,
            phase: Some(Phase::Crash),
        },
    )?;
    if disk.bytes()? != saved {
        return Err("actual app fault/relaunch changed retained disk".into());
    }
    // Continue on this same current-build disk after all four normal phases.
    // The cut writes a distinct later proposal, then cold recovery reopens the
    // exact stopped disk. There is no restore, host repair or Save retry here.
    storage::immutable_new(&evidence.join("document-before-interruption.raw"), &saved)?;
    let interrupted = evidence.join("interruption");
    fs::create_dir(&interrupted).map_err(|e| e.to_string())?;
    boot::boot_document_interruption(
        &options,
        DocumentInterruptionBoot {
            manifest: &path,
            evidence: &interrupted,
            disk: &disk,
            phase: InterruptionPhase::Cut,
        },
    )?;
    let stopped = disk.bytes()?;
    storage::immutable_new(&evidence.join("document-after-interruption.raw"), &stopped)?;
    let recovery = evidence.join("interruption-cold");
    fs::create_dir(&recovery).map_err(|e| e.to_string())?;
    boot::boot_document_interruption(
        &options,
        DocumentInterruptionBoot {
            manifest: &path,
            evidence: &recovery,
            disk: &disk,
            phase: InterruptionPhase::Cold,
        },
    )?;
    let recovered = disk.bytes()?;
    storage::immutable_new(&evidence.join("document-after-recovery.raw"), &recovered)?;
    let interruption_proof = document_interruption::recovery(&saved, &recovered)?;
    storage::json_new(
        &evidence.join("document-workflow.json"),
        &json!({"schema":1,"passed":true,"fixture":"m7-document","source_sha256":manifest.source_sha256,"build":manifest.build_id,"seed_provenance":provenance,"file":proof,"cold_disk_unchanged":true,"cancel_disk_unchanged":true,"read_only_input_preserved":true,"dirty_navigation_keep_and_discard":true,"actual_app_fault_and_relaunch_disk_unchanged":true,"interrupted_unconfirmed_save_cold_recovery":interruption_proof,"scope":"Actual offline owned-VM open/edit/commit/readback/close/reopen, cold reopen, cancel/refusal/app fault, and one SIGKILL while Save lacked visible confirmation followed by actual cold old-or-new recovery. Not File-ACK/acceptance inference, physical power-loss proof, human acceptance, failed-update recovery or full M7 completion."}),
    )?;
    println!(
        "PASS actual offline document workflow and unconfirmed-Save interruption/cold recovery: {}",
        evidence.display()
    );
    Ok(())
}
