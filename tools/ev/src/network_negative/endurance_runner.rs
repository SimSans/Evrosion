use super::{endurance_disk, endurance_flow::Flow, final_check, fixture::Fixture};
use crate::{
    boot::{self, ChildGuard, NetworkNegativeBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    network_io::components::Context,
    network_negative_contract::Goal,
    qmp::Qmp,
    storage, vm_clock,
};
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(1200);
pub(super) fn run(goal: Goal) -> Result<()> {
    if goal != Goal::Endurance {
        return Err("Endurance runner requires exact sustained-use goal; no VM started".into());
    }
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let options = BootOptions {
        timeout_seconds: TIMEOUT.as_secs(),
        ..BootOptions::default()
    };
    crate::native_workflow::preview_host(&options)?;
    let evidence = build::unique_directory(
        &storage::directory_beneath(&root, Path::new("build/m6/evidence"))?,
        goal.name(),
    )?;
    println!("Evidence: {}", evidence.display());
    let source = build::source_inputs(&root)?;
    storage::json_new(
        &evidence.join("source-before.json"),
        &json!({"source_sha256":source.0,"source_inputs":source.1}),
    )?;
    let mut manifest_record = None;
    let mut disk_record = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            release: true,
            fixture: Some(goal.fixture().into()),
        })?;
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some(goal.fixture())
            || manifest.profile != "release"
            || manifest.source_sha256 != source.0
            || manifest.source_inputs != source.1
        {
            return Err("negative selected source/profile mismatch".into());
        }
        let manifest_path = evidence.join("manifest.json");
        storage::immutable_new(&manifest_path, &bytes)?;
        manifest_record = Some(
            json!({"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,"manifest_sha256":build::hash_file(&manifest_path)?}),
        );
        let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
        let status = Command::new("python3")
            .current_dir(&root)
            .arg(root.join("tools/m5/stack_audit.py"))
            .arg(&kernel)
            .arg(evidence.join("kernel-stack.json"))
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("negative linked-stack preflight failed".into());
        }
        let context = Context::retain_negative(
            &root,
            &manifest,
            &storage::directory_beneath(&evidence, Path::new("component-preflight"))?,
        )?;
        let (seed, provenance) = crate::native_seed::checkpoint(&root, &evidence)?;
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&seed)?;
        disk.capture(&evidence, "data-before.raw")?;
        let boot = boot::boot_network_negative(
            &options,
            NetworkNegativeBoot {
                manifest: &manifest_path,
                evidence: &evidence,
                disk: &disk,
                goal,
            },
        );
        let capture = disk.capture(&evidence, "data-after.raw");
        let actual = disk.bytes();
        let sealed = disk.seal();
        disk_record = Some(
            json!({"seed":provenance,"boot_error":boot.as_ref().err(),"capture":capture.as_ref().ok(),"capture_error":capture.as_ref().err(),"seal_error":sealed.as_ref().err()}),
        );
        boot?;
        capture?;
        sealed?;
        let actual = actual?;
        let audit = endurance_disk::from_seed(&seed, &actual, &context.packages()?)?;
        storage::json_new(&evidence.join("readonly-final-disk-audit.json"), &audit)?;
        Ok(())
    })();
    let after = build::source_inputs(&root).and_then(|actual| {
        storage::json_new(
            &evidence.join("source-after.json"),
            &json!({"source_sha256":actual.0,"source_inputs":actual.1,"unchanged":actual==source}),
        )?;
        if actual == source {
            Ok(())
        } else {
            Err("negative source changed during qualification".into())
        }
    });
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"goal":goal,"passed":result.is_ok()&&after.is_ok(),"error":result.as_ref().err(),"source_error":after.as_ref().err(),"manifest":manifest_record,"disk":disk_record,"scripted_input":true,"human_consent_claim":false,"whole_M6_acceptance":false,"scope":"Actual sustained-use fixture: protected WORK, Scheduler Boot/Root/Shell/App CPU deltas, same Shell Home/Input/Present/scanout during abusive App, ordinary stopped/reaped replacement, reopened saved Note and read-only media checks. Complete ordinary physical retirement and strict calls==replies required. A failed or host-killed VM proves no cleanup."}),
    )?;
    result?;
    after
}
use super::runner::bounded;
fn complete(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(&[], |n| &bytes[..=n])
}
#[allow(clippy::too_many_arguments)]
pub(super) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    goal: Goal,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    if timeout != TIMEOUT || goal != Goal::Endurance {
        return Err("Endurance exact1200s observation profile required; no VM started".into());
    }
    let context = Context::retain_negative(root, manifest, directory)?;
    let fixture = Fixture::start()?;
    let origin = Instant::now();
    let deadline = origin
        .checked_add(timeout)
        .ok_or("negative host deadline overflow")?;
    let mut flow = Flow::new();
    let mut failure: Option<String> = None;
    let mut qmp = None;
    let mut actual = None;
    let result = (|| {
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| format!("owned negative QEMU spawn:{e}"))?,
        );
        clock.verify_and_start(&mut child.0, directory)?;
        qmp = Some(Qmp::connect_at(directory, deadline, origin)?);
        let mut input = child.0.stdin.take().ok_or("negative owner UART absent")?;
        loop {
            let bytes = bounded(serial)?;
            let _ = bounded(errors)?;
            if failure.is_none()
                && let Err(error) = flow.advance(
                    complete(&bytes),
                    build,
                    &context,
                    &fixture.snapshot()?,
                    &mut input,
                    qmp.as_mut().unwrap(),
                    disk,
                    directory,
                )
            {
                failure = Some(error);
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                // Read only AFTER actual process exit; an earlier iteration is
                // not the complete guest or device-retirement history.
                let final_bytes = bounded(serial)?;
                let _ = bounded(errors)?;
                if let Some(error) = &failure {
                    return Err(error.clone());
                }
                if !flow.finish_sent {
                    return Err("negative QEMU exited before explicit checked Finish".into());
                }
                let snapshot = fixture.snapshot()?;
                flow.verify_final(&final_bytes, build, &context, &snapshot)?;
                if qmp.as_ref().unwrap().transcript().iter().any(|row| {
                    row.get("sent")
                        .and_then(|s| s.get("execute"))
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| {
                            matches!(
                                name,
                                "set_link"
                                    | "device_add"
                                    | "device_del"
                                    | "netdev_add"
                                    | "netdev_del"
                                    | "system_reset"
                            )
                        })
                }) {
                    return Err(
                        "Endurance changed actual NIC/model instead of sustained-use".into(),
                    );
                }
                let checked = final_check(
                    &final_bytes,
                    build,
                    status.code(),
                    goal,
                    Some(&context.images),
                )?;
                actual = Some(checked);
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "Endurance original1200s observation bound; prior failure:{failure:?}"
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    storage::json_new(
        &directory.join("endurance-probe.json"),
        &json!({"schema":1,"goal":goal,"passed":result.is_ok(),"error":result.as_ref().err(),"first_failure":failure,"flow":flow.receipt(),"fixture":fixture.snapshot()?,"qmp":qmp.as_ref().map(|q|q.transcript()),"actual_retirement":actual,"complete_Kernel_retirement_receipt":result.is_ok(),"original_timeout_seconds":1200,"observation_scope":"Greater than262144 actual Scheduler Boot CPU ticks within unchanged900000tick finite worker horizon; no IO/RPC cut, quota or resource raise","scripted_input":true,"human_consent_claim":false,"whole_probe_acceptance_requires_caller_postflights":true}),
    )?;
    result
}
