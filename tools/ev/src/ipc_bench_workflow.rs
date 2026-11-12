//! One actual ordinary-startup IPC-switch VM and independent source/serial
//! verification. No disk attachment or host repair belongs to this fixture.
use crate::{
    boot::{self, IpcBenchBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    ipc_bench_components, ipc_bench_protocol, ipc_bench_timing, storage,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
};
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err("IPC input nonregular/oversized".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("IPC input grew beyond bound".into());
    }
    Ok(bytes)
}
fn link(path: &Path, base: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err("IPC evidence must be an owned regular file".into());
    }
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"IPC evidence escaped directory")?,"sha256":build::hash_file(path)?,"bytes":m.len()}),
    )
}
fn stack(root: &Path, evidence: &Path, manifest: &Manifest) -> Result<()> {
    let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
    let status = Command::new("python3")
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg(kernel)
        .arg(evidence.join("kernel-stack.json"))
        .stdin(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!(
            "IPC actual linked kernel stack preflight failed: {status}"
        ));
    }
    for actor in ["root", "client", "server"] {
        let exact = format!("m5-ipc-{actor}.unstripped.elf");
        let mut candidates = manifest.supervisor.iter().filter(|a| {
            Path::new(&a.path)
                .file_name()
                .is_some_and(|n| n == exact.as_str())
        });
        let artifact = candidates.next().ok_or("IPC source ELF symbols missing")?;
        if candidates.next().is_some() {
            return Err("ambiguous IPC source ELF symbols".into());
        }
        let elf = build::verify_artifact(&root.join("build/m0"), artifact)?;
        let status = Command::new("python3")
            .current_dir(root)
            .arg(root.join("tools/m5/stack_audit.py"))
            .arg("--userspace")
            .arg(elf)
            .arg(evidence.join(format!("{actor}-stack.json")))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!(
                "IPC actual {actor} stack preflight failed: {status}"
            ));
        }
    }
    Ok(())
}
pub fn run() -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m5/evidence"))?;
    let evidence = build::unique_directory(&parent, "ipc-bench")?;
    println!("Evidence: {}", evidence.display());
    let mut stage = "build";
    let mut retained = None;
    let mut components = None;
    let mut execution = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some("m5-ipc-bench".into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_build";
        let bytes = bounded(&root.join("build/m0/manifest.json"), 16 * 1024 * 1024)?;
        let manifest_path = evidence.join("manifest.json");
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if manifest.fixture.as_deref() != Some("m5-ipc-bench") {
            return Err("wrong retained IPC fixture".into());
        }
        retained = Some(
            json!({"manifest":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,"kernel":manifest.kernel,"image":manifest.image,"source_sha256":manifest.source_sha256,"source_inputs":manifest.source_inputs}),
        );
        stage = "actual_components";
        let bound = ipc_bench_components::retain(&root, &evidence, &manifest)?;
        components = Some(bound.record);
        stage = "linked_stack_preflight";
        stack(&root, &evidence, &manifest)?;
        let mut samples = Vec::new();
        for ordinal in 1..=5 {
            stage = "actual_owned_sdk_rpc_sample";
            let run = evidence.join(format!("sample-{ordinal:03}"));
            fs::create_dir(&run).map_err(|e| e.to_string())?;
            boot::boot_ipc_bench(
                &BootOptions {
                    root: Some(root.clone()),
                    timeout_seconds: 180,
                    ..BootOptions::default()
                },
                IpcBenchBoot {
                    manifest: &manifest_path,
                    evidence: &run,
                    images: bound.images,
                },
            )?;
            let serial = bounded(&run.join("boot/run-001/serial.log"), 1024 * 1024)?;
            let checked = ipc_bench_protocol::record(&serial, &manifest.build_id, bound.images)?;
            storage::json_new(&run.join("functional-proof.json"), &checked)?;
            stage = "host_serial_batch_timing";
            let timing_path = run.join("boot/run-001/ipc-host-timing.json");
            let timing: Value = serde_json::from_slice(&bounded(&timing_path, 64 * 1024)?)
                .map_err(|e| e.to_string())?;
            let host = ipc_bench_timing::check(&timing, &serial, &manifest.build_id)?;
            storage::json_new(&run.join("host-batch-proof.json"), &host)?;
            samples.push(json!({"ordinal":ordinal,"sample":checked,"host_batch":host,"host_observation":link(&timing_path,&evidence)?,"serial":link(&run.join("boot/run-001/serial.log"),&evidence)?}));
        }
        let mut spans: Vec<_> = samples
            .iter()
            .map(|s| {
                s["sample"]["client_span_delivered_irq_ticks"]
                    .as_u64()
                    .ok_or_else(|| "IPC measured sample missing span".to_owned())
            })
            .collect::<Result<_>>()?;
        spans.sort_unstable();
        // Coordinate-wise medians conservatively enclose the median of the
        // actual five host boundary durations. They are not client-only latency.
        let median_host = |key: &str| -> Result<u64> {
            let mut values = samples
                .iter()
                .map(|s| {
                    s["host_batch"][key]
                        .as_u64()
                        .ok_or_else(|| "IPC host sample bound missing".to_owned())
                })
                .collect::<Result<Vec<_>>>()?;
            values.sort_unstable();
            Ok(values[2])
        };
        let host_lower = median_host("batch_duration_lower_ns")?;
        let host_upper = median_host("batch_duration_upper_ns")?;
        execution = Some(
            json!({"host_batch_median_duration_bounds_ns":{"lower":host_lower,"upper":host_upper},"host_amortized_median_batch_ns_per_checked_rpc_bounds":{"lower_numerator":host_lower,"upper_numerator":host_upper,"denominator":4096},"irq_median_below_resolution":spans[2]==0,"samples":samples,"sample_count":5,"median_client_span_delivered_irq_ticks":spans[2],"median_mean_sdk_roundtrip_ticks":{"numerator":spans[2],"denominator":4096},"scope":"five fresh owned single-CPU Q35/TCG VMs; complete checked SDK RPC; delivered guest IRQ ticks, no calibrated physical latency or raw trap-cycle claim"}),
        );
        Ok(())
    })();
    let mut artifacts = Vec::new();
    fn visit(path: &Path, base: &Path, out: &mut Vec<Value>) -> Result<()> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let m = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if m.is_dir() {
                visit(&path, base, out)?;
            } else if m.is_file() {
                out.push(link(&path, base)?);
            } else if m.file_type().is_symlink() {
                return Err("IPC evidence contains a symlink".into());
            }
        }
        Ok(())
    }
    let links = visit(&evidence, &evidence, &mut artifacts);
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"actual-checked-sdk-rpc-baseline","passed":result.is_ok()&&links.is_ok(),"stage":stage,
        "error":result.as_ref().err(),"link_error":links.as_ref().err(),"build":retained,"components":components,"execution":execution,"expected_boots":5,"artifacts":artifacts,
        "scope":"five actual source-built ordinary Root/client/server VMs, each64warmups+4096checkedRPCs, Kernelcounter/routebrackets and actualclient sample, Root/clientExit0+serverStop/allreap+fullownershipcleanup; TCG host serial-availability bounds and separate delivered-IRQ sample only"}),
    )?;
    links?;
    result
}
