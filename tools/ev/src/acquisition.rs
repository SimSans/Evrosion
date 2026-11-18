//! Fresh DEV B acquisition followed by same-source/image/disk isolated reload.
//! No accepted remote decision or downloaded bytes are seeded into the guest.
use crate::{
    acquisition_io::{self, Phase, Plan},
    boot::{self, AcquisitionBoot},
    build::{self, Manifest, Result},
    cli::{AcquisitionOptions, BootOptions, BuildOptions},
    download_fixture,
    network_io::{acquisition_disk as disk_check, components::Context},
    storage,
};
use serde_json::json;
use std::{fs, path::Path};

fn saved() -> disk_check::Saved<'static> {
    disk_check::Saved {
        note: acquisition_io::NOTE,
        note_counter: 1,
        value: 1001,
        data_counter: 0,
    }
}
pub(crate) fn run(options: &AcquisitionOptions) -> Result<()> {
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let authority_workspace = options.authority_root.as_ref().map_or_else(
        || Ok(root.clone()),
        |path| fs::canonicalize(path).map_err(|e| e.to_string()),
    )?;
    let authority = acquisition_io::authority(&root, &authority_workspace)?;
    let parent = storage::directory_beneath(&root, Path::new("build/m6/evidence"))?;
    let evidence = build::unique_directory(&parent, "acquisition-probe")?;
    println!("Evidence: {}", evidence.display());
    let source = build::source_inputs(&root)?;
    storage::json_new(
        &evidence.join("source-before.json"),
        &json!({"source_sha256":source.0,"source_inputs":source.1}),
    )?;
    let mut online_record = None;
    let mut cold_record = None;
    let mut manifest_record = None;
    let mut seed_record = None;
    let mut disk_created = false;
    let mut owned_disk = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            release: true,
            fixture: Some("m6-network".into()),
        })?;
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some("m6-network")
            || manifest.profile != "release"
            || manifest.source_sha256 != source.0
            || manifest.source_inputs != source.1
        {
            return Err("acquisition source/profile mismatch".into());
        }
        let manifest_path = evidence.join("manifest.json");
        storage::immutable_new(&manifest_path, &bytes)?;
        manifest_record = Some(
            json!({"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,"sha256":build::hash_file(&manifest_path)?}),
        );
        let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
        let status = std::process::Command::new("python3")
            .current_dir(&root)
            .arg(root.join("tools/m5/stack_audit.py"))
            .arg(&kernel)
            .arg(evidence.join("kernel-stack.json"))
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("acquisition selected release linked-stack preflight failed".into());
        }
        let preflight = storage::directory_beneath(&evidence, Path::new("component-preflight"))?;
        let context = Context::retain(&root, &manifest, &preflight)?;
        let packages = context.packages()?;
        let bundle_directory = root
            .join("build/m6/downloads")
            .join(evidence.file_name().ok_or("acquisition evidence name")?);
        let bundle = download_fixture::produce(&root, &bundle_directory, &manifest.source_sha256)?;
        acquisition_io::absent_from_banks(&context, &bundle)?;
        let plan = Plan {
            schema: 1,
            source_sha256: manifest.source_sha256.clone(),
            build_id: manifest.build_id.clone(),
            bundle_directory: bundle_directory.clone(),
            authority_workspace: authority_workspace.clone(),
            public_root_sha256: acquisition_io::hash(authority.root()),
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
        seed_record = Some(seed_proof);
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk_created = true;
        disk.restore_snapshot(&seed)?;
        owned_disk = Some(disk);
        let disk = owned_disk.as_ref().unwrap();
        let online_dir = storage::directory_beneath(&evidence, Path::new("online"))?;
        storage::json_new(
            &online_dir.join("acquisition-plan.json"),
            &serde_json::to_value(&plan).map_err(|e| e.to_string())?,
        )?;
        disk.capture(&online_dir, "data-before.raw")?;
        let options = BootOptions {
            timeout_seconds: acquisition_io::TIMEOUT_SECONDS,
            ..BootOptions::default()
        };
        let online = boot::boot_acquisition(
            &options,
            AcquisitionBoot {
                manifest: &manifest_path,
                evidence: &online_dir,
                disk,
                phase: Phase::Online,
            },
        );
        let online_capture = disk.capture(&online_dir, "data-after.raw");
        let after = disk.bytes();
        online_record = Some(
            json!({"passed":online.is_ok(),"error":online.as_ref().err(),"after":online_capture.as_ref().ok(),"capture_error":online_capture.as_ref().err()}),
        );
        online?;
        online_capture?;
        let after = after?;
        let baseline =
            fs::read(online_dir.join("setup-baseline.raw")).map_err(|e| e.to_string())?;
        let root_bytes =
            fs::read(online_dir.join("phase-b/root.bin")).map_err(|e| e.to_string())?;
        let targets =
            fs::read(online_dir.join("phase-b/targets.bin")).map_err(|e| e.to_string())?;
        let snapshot =
            fs::read(online_dir.join("phase-b/snapshot.bin")).map_err(|e| e.to_string())?;
        let timestamp =
            fs::read(online_dir.join("phase-b/timestamp.bin")).map_err(|e| e.to_string())?;
        let artifact =
            fs::read(online_dir.join("phase-b/hello.zion")).map_err(|e| e.to_string())?;
        let release = || disk_check::Release {
            root: &root_bytes,
            targets: &targets,
            snapshot: &snapshot,
            timestamp: &timestamp,
            artifact: &artifact,
        };
        let expected = || disk_check::Expected {
            registry_revision: 4,
            registry_active: bundle.downloads[0].package_id,
            registry_staged: None,
            registry_previous: Some(packages.digest(ev_root_supervisor::native_plan::Slot::A)),
            trust_active: Some(2),
            known_good: None,
            saved: saved(),
        };
        let proof = disk_check::online(&baseline, &after, &packages, release(), expected())?;
        storage::json_new(
            &online_dir.join("acquisition-disk-audit.json"),
            &proof.proof,
        )?;
        // The very same disk and exact retained image are used. No fixture is
        // started in this second VM, and its fixed NIC is down before cont.
        let cold_dir = storage::directory_beneath(&evidence, Path::new("cold"))?;
        storage::json_new(
            &cold_dir.join("acquisition-plan.json"),
            &serde_json::to_value(&plan).map_err(|e| e.to_string())?,
        )?;
        disk.capture(&cold_dir, "data-before.raw")?;
        let cold = boot::boot_acquisition(
            &options,
            AcquisitionBoot {
                manifest: &manifest_path,
                evidence: &cold_dir,
                disk,
                phase: Phase::Cold,
            },
        );
        let cold_capture = disk.capture(&cold_dir, "data-after.raw");
        let cold_bytes = disk.bytes();
        cold_record = Some(
            json!({"passed":cold.is_ok(),"error":cold.as_ref().err(),"after":cold_capture.as_ref().ok(),"capture_error":cold_capture.as_ref().err()}),
        );
        cold?;
        cold_capture?;
        let cold_bytes = cold_bytes?;
        let cold_proof = disk_check::cold(
            &after,
            &cold_bytes,
            &packages,
            release(),
            expected(),
            &proof,
        )?;
        storage::json_new(&cold_dir.join("acquisition-disk-audit.json"), &cold_proof)?;
        Ok(())
    })();
    let sealed = owned_disk.as_ref().map_or(Ok(()), storage::Disk::seal);
    let postflight = build::source_inputs(&root).and_then(|actual| {
        let unchanged = actual == source;
        storage::json_new(
            &evidence.join("source-after.json"),
            &json!({"source_sha256":actual.0,"source_inputs":actual.1,"unchanged":unchanged}),
        )?;
        if unchanged {
            Ok(())
        } else {
            Err("acquisition source changed during execution".into())
        }
    });
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"actual-DEV-B-acquisition-and-isolated-cold-reload","passed":result.is_ok()&&postflight.is_ok()&&sealed.is_ok(),"error":result.as_ref().err(),"source_postflight_error":postflight.as_ref().err(),"disk_seal_error":sealed.as_ref().err(),"manifest":manifest_record,"seed":seed_record,"owned_disk_created":disk_created,"online":online_record,"cold":cold_record,"authority_workspace":authority_workspace,"private_keys_copied":false,"original_per_VM_timeout_seconds":acquisition_io::TIMEOUT_SECONDS,"scripted_input":true,"human_consent_claim":false,"whole_M6_acceptance":false,"scope":"Fresh signed DEV transport, guest authorization, candidate publication, actual B selection/execution, preserved nonempty data and same-disk isolated cold reload. No Official release, C rollback, physical offline, or whole M6 acceptance."}),
    )?;
    result?;
    sealed?;
    postflight
}
