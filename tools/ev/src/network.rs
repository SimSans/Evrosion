//! Manual V4 developer session, using an independently owned persistent disk.
//! Source qualification is a launch prerequisite; it is not release acceptance.
use crate::{
    boot::{self, NetworkBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    storage,
};
use std::{fs, path::Path};

pub(crate) fn run() -> Result<()> {
    crate::manualnetwork::run()
}

/// Explicit finite headless acceptance of the initial V4 network route. The
/// manual session above never chooses this driver or supplies automatic input.
pub(crate) fn probe(goal: crate::network_io::Goal) -> Result<()> {
    use serde_json::json;
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m6/evidence"))?;
    let evidence = build::unique_directory(
        &parent,
        match goal {
            crate::network_io::Goal::Hello => "network-probe",
            crate::network_io::Goal::Time => "time-probe",
            crate::network_io::Goal::TimePause => "time-pause-probe",
            crate::network_io::Goal::TimeRefresh => "time-refresh-probe",
            crate::network_io::Goal::UpdateNamespace => "update-namespace-probe",
            crate::network_io::Goal::TimeCorrupt => "time-corrupt-probe",
            crate::network_io::Goal::MissingEntropy => "entropy-missing-probe",
        },
    )?;
    println!("Evidence: {}", evidence.display());
    let source_before = build::source_inputs(&root)?;
    storage::json_new(
        &evidence.join("source-before.json"),
        &json!({"source_sha256":source_before.0,"source_inputs":source_before.1}),
    )?;
    let mut manifest_record = None;
    let mut seed_record = None;
    let mut before = None;
    let mut after = None;
    let mut disk_equal = false;
    let mut namespace = None;
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
            || manifest.source_sha256 != source_before.0
            || manifest.source_inputs != source_before.1
        {
            return Err("network probe built a different source/profile".into());
        }
        let manifest_path = evidence.join("manifest.json");
        storage::immutable_new(&manifest_path, &bytes)?;
        manifest_record = Some(
            json!({"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,"manifest_sha256":build::hash_file(&manifest_path)?}),
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
            return Err("network probe linked-stack preflight failed".into());
        }
        let (seed, provenance) = crate::native_seed::checkpoint(&root, &evidence)?;
        seed_record = Some(provenance);
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&seed)?;
        before = Some(disk.capture(&evidence, "data-before.raw")?);
        let boot = boot::boot_network(
            &BootOptions {
                timeout_seconds: 240,
                ..BootOptions::default()
            },
            NetworkBoot {
                manifest: &manifest_path,
                evidence: &evidence,
                disk: &disk,
                probe: Some(goal),
            },
        );
        let capture = disk.capture(&evidence, "data-after.raw");
        after = capture.as_ref().ok().cloned();
        let actual = disk.bytes();
        disk_equal = actual.as_ref().is_ok_and(|bytes| *bytes == seed);
        let namespace_check = if goal == crate::network_io::Goal::UpdateNamespace {
            Some(
                actual
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|bytes| crate::network_io::namespace_probe::disk(&seed, bytes)),
            )
        } else {
            None
        };
        if let Some(check) = &namespace_check {
            storage::json_new(
                &evidence.join("namespace-disk-audit.json"),
                &json!({"schema":1,"passed":check.is_ok(),"audit":check.as_ref().ok(),"error":check.as_ref().err(),"scope":"Read-only authentication of actual post-run captured bytes; guest cleanup is verified separately."}),
            )?;
        }
        let sealed = disk.seal();
        boot?;
        capture?;
        actual?;
        sealed?;
        if let Some(check) = namespace_check {
            namespace = Some(check?);
        }
        if !disk_equal && goal != crate::network_io::Goal::UpdateNamespace {
            return Err("no-App network probe changed actual disk bytes".into());
        }
        Ok(())
    })();
    let postflight = build::source_inputs(&root).and_then(|actual| {
        let equal = actual == source_before;
        storage::json_new(
            &evidence.join("source-after.json"),
            &json!({"source_sha256":actual.0,"source_inputs":actual.1,"unchanged":equal}),
        )?;
        if equal {
            Ok(())
        } else {
            Err("network probe source changed during execution".into())
        }
    });
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"finite-headless-V4-network-probe","goal":goal,"kernel_profile":"release","optimized_V4_reference_profile":true,"passed":result.is_ok()&&postflight.is_ok(),"error":result.as_ref().err(),"source_postflight_error":postflight.as_ref().err(),"manifest":manifest_record,"seed":seed_record,"before":before,"after":after,"entire_disk_unchanged":disk_equal,"namespace":namespace,"guest_cleanup_verified":result.is_ok()&&postflight.is_ok(),"scripted_input":true,"human_consent_claim":false,"whole_M6_acceptance":false,"scope":"Source-admitted V4 graph, actual DHCP/DNS/scoped plaintext HTTP, optional explicit private unqualified time proof and checked full shutdown. No TLS/update trust/qualified UTC/physical hardware or whole M6 acceptance."}),
    )?;
    result?;
    postflight
}
