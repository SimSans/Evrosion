// SPDX-License-Identifier: GPL-3.0-only
//! Manual session and an explicitly separate finite regression driver.
use crate::{
    boot::{self, SessionBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    storage,
};
use serde_json::json;
use std::{fs, path::Path};

pub(crate) fn run(conformance: bool) -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?;
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let options = BootOptions {
        timeout_seconds: 240,
        ..BootOptions::default()
    };
    if !conformance {
        crate::native_workflow::preview_host(&options)?;
    }
    let parent = storage::directory_beneath(&root, Path::new("build/m6/evidence"))?;
    let evidence = build::unique_directory(
        &parent,
        if conformance {
            "session-conformance"
        } else {
            "session"
        },
    )?;
    println!("Evidence: {}", evidence.display());
    build::build(&BuildOptions {
        root: Some(root.clone()),
        fixture: Some("m6-session".into()),
        ..BuildOptions::default()
    })?;
    let manifest_path = evidence.join("manifest.json");
    let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
    storage::immutable_new(&manifest_path, &bytes)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.fixture.as_deref() != Some("m6-session") {
        return Err("wrong retained session profile".into());
    }
    let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
    let status = std::process::Command::new("python3")
        .current_dir(&root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg(&kernel)
        .arg(evidence.join("kernel-stack.json"))
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("session linked-stack preflight failed".into());
    }
    let (seed, provenance) = crate::native_seed::checkpoint(&root, &evidence)?;
    let retained;
    let mut temporary;
    let (disk, created) = if conformance {
        temporary = storage::Disk::create(&root, &evidence)?;
        temporary.restore_snapshot(&seed)?;
        (&temporary, true)
    } else {
        retained = storage::SessionDisk::open(&root, &seed)?;
        (&retained.disk, retained.created)
    };
    let before = disk.capture(&evidence, "data-before.raw")?;
    if !conformance {
        println!(
            "Evrosion interactive development session. Use the keyboard and pointer to open the app and edit its note.\nThe developer disk is retained between sessions. Owner commands may also be typed in this terminal; 'finish' requests checked shutdown. Closing the window interrupts the VM."
        );
    }
    let mut result = boot::boot_session(
        &options,
        SessionBoot {
            manifest: &manifest_path,
            evidence: &evidence,
            disk,
            phase: conformance.then_some(crate::session_io::Phase::Exercise),
        },
    );
    let mut exercise_note = None;
    let mut cold_note = None;
    let mut initialization = None;
    if conformance && result.is_ok() {
        result = (|| {
            let artifact = |name: &str| -> Result<Vec<u8>> {
                let item = manifest
                    .supervisor
                    .iter()
                    .find(|a| Path::new(&a.path).file_name().is_some_and(|n| n == name))
                    .ok_or_else(|| format!("session creation artifact absent: {name}"))?;
                fs::read(build::verify_artifact(&root.join("build/m0"), item)?)
                    .map_err(|e| e.to_string())
            };
            let catalogue = artifact("m5-native-catalogue.bin")?;
            let packages = [
                artifact("m5-native-Hello-A.zion")?,
                artifact("m5-native-Hello-B.zion")?,
            ];
            let baseline = fs::read(evidence.join("boot/run-001/note-baseline.raw"))
                .map_err(|e| e.to_string())?;
            initialization = Some(crate::session_reference::initialization(
                &seed,
                &baseline,
                &catalogue,
                [&packages[0], &packages[1]],
            )?);
            let after_exercise = disk.bytes()?;
            exercise_note = Some(crate::session_reference::note_disk(
                &baseline,
                &after_exercise,
                &catalogue,
                1,
                crate::session_io::SAVED,
            )?);
            let cold = evidence.join("cold-reopen");
            fs::create_dir(&cold).map_err(|e| e.to_string())?;
            boot::boot_session(
                &options,
                SessionBoot {
                    manifest: &manifest_path,
                    evidence: &cold,
                    disk,
                    phase: Some(crate::session_io::Phase::ColdReopen),
                },
            )?;
            let after_cold = disk.bytes()?;
            if after_cold != after_exercise {
                return Err("read-only cold session changed the retained disk".into());
            }
            cold_note = Some(crate::session_reference::note_disk(
                &after_exercise,
                &after_cold,
                &catalogue,
                1,
                crate::session_io::SAVED,
            )?);
            Ok(())
        })();
    }
    let after = disk.capture(&evidence, "data-after.raw");
    storage::json_new(
        &evidence.join("results.json"),
        &json!({
            "schema":1,"kind":if conformance { "session-profile-finite-regression" } else { "manual-developer-session" },
            "passed":result.is_ok() && after.is_ok(),"scripted_input":conformance,"human_consent_claim":false,
            "created_disk":created,"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,
            "seed":provenance,"before":before,"after":after.as_ref().ok(),"error":result.as_ref().err(),
            "initialization":initialization,"exercise_note":exercise_note,"cold_note":cold_note,
            "scope":"Separate sustained execution profile with accounted CPU windows. The finite regression driver is not human interaction or proof of the whole M6-02 gate."
        }),
    )?;
    result?;
    after?;
    if conformance {
        disk.seal()?;
    }
    Ok(())
}
