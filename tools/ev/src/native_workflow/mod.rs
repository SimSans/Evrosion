//! Actual Native lifecycle/cold-reopen workflow. Every guest owns one private
//! disk; host observers only read retained snapshots and never repair data.
pub(crate) mod components;
mod disk;
use crate::{
    boot::{self, NativeBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    native_io::Phase,
    storage,
};
use ev_root_supervisor::native_plan::Slot;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
};
fn link(path: &Path, base: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err("Native evidence must be a regular file".into());
    }
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"Native evidence escaped directory")?,"sha256":build::hash_file(path)?,"bytes":m.len()}),
    )
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > limit {
        return Err("Native input nonregular/oversized".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Native input grew beyond bound".into());
    }
    Ok(bytes)
}
fn expected(phase: Phase, catalogue: &[u8]) -> disk::Expected<'_> {
    let (revision, installed, active, previous, registry_operation, value) = match phase {
        Phase::InstallFull => (2, true, Some(Slot::A), None, 2, 1001),
        Phase::ActivateB => (4, true, Some(Slot::B), Some(Slot::A), 4, 2026),
        Phase::RollbackA => (5, true, Some(Slot::A), Some(Slot::B), 5, 2026),
        Phase::Remove => (6, false, None, Some(Slot::A), 6, 2026),
        Phase::ReinstallA | Phase::VerifyCancel => (8, true, Some(Slot::A), Some(Slot::A), 8, 2026),
    };
    disk::Expected {
        catalogue,
        revision,
        installed,
        active,
        previous,
        staged: None,
        data_epoch: 1,
        registry_operation,
        data_operation: u64::from(value == 2026),
        data_counter: u64::from(value == 2026),
        value,
    }
}
fn process_facts(
    serial: &[u8],
    build: &str,
    recipe: &str,
    phase: Phase,
    packages: [&[u8]; 2],
    catalogue: &[u8],
    directory: &Path,
) -> Result<Value> {
    let record = crate::native_protocol::record(serial, build)?;
    let mode = ev_userspace_contract::root_v2::native::catalogue::Catalogue::decode(catalogue)
        .map_err(|e| format!("Native retained catalogue mode: {e:?}"))?
        .boot_mode();
    let profile =
        crate::native_profile::finished(serial, build, record.counts["faults"], Some(mode as u64))?;
    let diagnostics = crate::native_diagnostics::retain(
        serial, build, recipe, phase, packages, catalogue, directory,
    )?;
    let hashes = packages.map(|b| {
        ev_zion::Package::parse(b)
            .map(|p| format!("{:x}", Sha256::digest(p.executable().bytes)))
            .map_err(|e| format!("Native package observer: {e:?}"))
    });
    let [a, b] = hashes;
    let hashes = [a?, b?];
    for (slot, package) in ["a", "b"].into_iter().zip(packages) {
        let expected_pages =
            ev_userspace_contract::root_v2::native::catalogue::package_pages(package.len() as u64)
                .ok_or("Native retained package exceeds bank bound")?;
        if record.counts[&format!("package_{slot}_pages")] != expected_pages {
            return Err(
                "Native physical bank accounting differs from exact retained package length".into(),
            );
        }
    }
    let mut counts = [[0u64; 3]; 2];
    for action in &record.actions {
        let slot = hashes
            .iter()
            .position(|sha| *sha == action.image_sha256)
            .ok_or("actual Native App action uses an unmeasured image")?;
        let kind = match action.kind.as_str() {
            "start" => 0,
            "stop" => 1,
            "reap" => 2,
            _ => unreachable!(),
        };
        counts[slot][kind] += 1;
    }
    for (slot, label) in ["a", "b"].into_iter().enumerate() {
        for (kind, name) in ["starts", "stops", "reaps"].into_iter().enumerate() {
            if counts[slot][kind] != record.counts[&format!("app_{label}_{name}")] {
                return Err("Native actual action image/count association differs".into());
            }
        }
    }
    let expected = match phase {
        Phase::InstallFull => [2, 0],
        Phase::ActivateB => [1, 1],
        Phase::RollbackA => [1, 1],
        Phase::Remove => [1, 0],
        Phase::ReinstallA | Phase::VerifyCancel => [1, 0],
    };
    if counts.map(|c| c[0]) != expected {
        return Err(format!(
            "Native {} actual incarnation counts differ",
            phase.name()
        ));
    }
    if phase == Phase::InstallFull
        && (record.counts["faults"] != 2
            || record.counts["restarts"] != 2
            || record.counts["grants"] != 3
            || record.counts["readonly_rejections"] != 3)
    {
        return Err("Native full consent/fault/read-only proof incomplete".into());
    }
    Ok(
        json!({"record":record,"diagnostics":diagnostics,"scheduling_profile":profile,"source_images":hashes,"actual_image_actions":counts,"scope":"actual kernel identity/image actions matched to retained complete packages; durable state independently inspected; trap counters aggregate fixed actor slots across incarnations, current Job CPU is a separate hierarchical snapshot"}),
    )
}
/// Source-frozen build precedes exact linked stack preflight and every owned VM.
pub fn run() -> Result<()> {
    run_selected(None)
}

pub(crate) fn preview(options: &BootOptions) -> Result<()> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.batch
    {
        return Err("Native preview requires one non-debug single-CPU demonstration".into());
    }
    preview_host(options)?;
    println!(
        "Evrosion Developer Preview — scripted Native demonstration.\nThis run uses a new private demo disk. The runner sends recorded owner commands and keyboard events for install, scoped file selection, cancellation, crashes and restart.\nClosing the window interrupts the run; evidence is retained."
    );
    run_selected(Some(options))
}

fn preview_host(options: &BootOptions) -> Result<()> {
    if ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .all(|key| std::env::var_os(key).is_none_or(|v| v.is_empty()))
    {
        return Err("Native preview needs a graphical Linux session; use cargo ev test native-platform for headless conformance".into());
    }
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = crate::doctor::workspace(&current, options.root.as_deref())?;
    let qemu = crate::doctor::Host::detect(&current).executable("qemu-system-x86_64")?;
    let directory = build::unique_directory(
        &storage::directory_beneath(&root, Path::new("build/m5/evidence"))?,
        "preview-host",
    )?;
    let output = directory.join("qemu-display-help.log");
    let error = directory.join("qemu-display-help.stderr.log");
    let mut command = Command::new(qemu);
    command
        .args(["-display", "help"])
        .stdin(Stdio::null())
        .stdout(fs::File::create(&output).map_err(|e| e.to_string())?)
        .stderr(fs::File::create(&error).map_err(|e| e.to_string())?);
    let status = crate::boot::supervised(
        &mut command,
        &[&output, &error],
        std::time::Duration::from_secs(10),
    )?;
    let bytes = bounded(&output, 1024 * 1024)?;
    if !status.success()
        || !std::str::from_utf8(&bytes)
            .map_err(|_| "QEMU display help not UTF8")?
            .lines()
            .any(|line| line.split_whitespace().next() == Some("gtk"))
    {
        return Err("QEMU lacks the GTK display backend required by the Native preview; use cargo ev test native-platform for headless conformance".into());
    }
    Ok(())
}

fn run_selected(preview: Option<&BootOptions>) -> Result<()> {
    let root = crate::doctor::workspace(
        &std::env::current_dir().map_err(|e| e.to_string())?,
        preview.and_then(|p| p.root.as_deref()),
    )?
    .canonicalize()
    .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m5/evidence"))?;
    let evidence = build::unique_directory(
        &parent,
        if preview.is_some() {
            "native-preview"
        } else {
            "native-platform"
        },
    )?;
    println!("Evidence: {}", evidence.display());
    let mut stage = "build";
    let mut phases = Vec::<Value>::new();
    let mut retained = None;
    let mut binding = None;
    let mut seed = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some("m5-native".into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_build";
        let bytes = bounded(&root.join("build/m0/manifest.json"), 16 * 1024 * 1024)?;
        let manifest_path = evidence.join("manifest.json");
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if manifest.fixture.as_deref() != Some("m5-native") {
            return Err("wrong retained Native fixture".into());
        }
        retained = Some(
            json!({"manifest":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,"source_inputs":manifest.source_inputs,"source_sha256":manifest.source_sha256,"kernel":manifest.kernel,"image":manifest.image}),
        );
        stage = "actual_components";
        let components = components::retain(&root, &evidence, &manifest)?;
        binding = Some(components.record.clone());
        stage = "linked_stack_preflight";
        let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
        let status = Command::new("python3")
            .current_dir(&root)
            .arg(root.join("tools/m5/stack_audit.py"))
            .arg(&kernel)
            .arg(evidence.join("kernel-stack.json"))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("Native linked stack preflight failed: {status}"));
        }
        stage = "import_m4_checkpoint";
        let (baseline, source) = crate::native_seed::checkpoint(&root, &evidence)?;
        seed = Some(source);
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&baseline)?;
        disk.capture(&evidence, "native-before.raw")?;
        let all = [
            Phase::InstallFull,
            Phase::ActivateB,
            Phase::RollbackA,
            Phase::Remove,
            Phase::ReinstallA,
            Phase::VerifyCancel,
        ];
        let selected = if preview.is_some() {
            &all[..1]
        } else {
            &all[..]
        };
        for &phase in selected {
            stage = phase.name();
            let directory = evidence.join(phase.name());
            fs::create_dir(&directory).map_err(|e| e.to_string())?;
            let before = disk.bytes()?;
            let before_record = disk.capture(&directory, "data-before.raw")?;
            let default_options = BootOptions {
                root: Some(root.clone()),
                timeout_seconds: 240,
                ..BootOptions::default()
            };
            let boot = boot::boot_native_presented(
                preview.unwrap_or(&default_options),
                NativeBoot {
                    manifest: &manifest_path,
                    evidence: &directory,
                    disk: &disk,
                    phase,
                },
                preview.is_some(),
            );
            let after = disk.bytes()?;
            let after_record = disk.capture(&directory, "data-after.raw")?;
            let mut validation = None;
            let checked=boot.and_then(|()|{
                let serial=bounded(&directory.join("boot/run-001/serial.log"),1024*1024)?;
                let disk=disk::inspect(&before,&after,components.packages(),expected(phase,&components.catalogue))?;
                if phase==Phase::VerifyCancel && before!=after{return Err("read-only inspection/cancel changed actual disk bytes".into());}
                let performance = if phase == Phase::InstallFull {
                    Some(crate::desktop_io::validate_performance(&directory.join("boot/run-001"))?)
                } else { None };
                validation=Some(json!({"disk":disk,"performance":performance,"memory_image_baseline":crate::native_baselines::retain(&root,&manifest,&serial,&directory)?,"execution":process_facts(&serial,&manifest.build_id,&manifest.source_sha256,phase,components.packages(),&components.catalogue,&directory)?}));Ok(())
            });
            let phase_record = json!({"phase":phase.name(),"passed":checked.is_ok(),"error":checked.as_ref().err(),"before":before_record,"after":after_record,"validation":validation});
            storage::json_new(&directory.join("phase-results.json"), &phase_record)?;
            phases.push(phase_record);
            checked?;
        }
        disk.capture(&evidence, "native-after.raw")?;
        disk.seal()?;
        Ok(())
    })();
    let mut artifacts = Vec::new();
    fn visit(path: &Path, base: &Path, out: &mut Vec<Value>) -> Result<()> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let m = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if m.is_dir() {
                visit(&path, base, out)?;
            } else if m.is_file() && path.file_name().is_some_and(|n| n != "data.raw") {
                out.push(link(&path, base)?);
            }
        }
        Ok(())
    }
    let links = visit(&evidence, &evidence, &mut artifacts);
    let passed = result.is_ok() && links.is_ok();
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":if preview.is_some() {"visible-bounded-native-developer-demo"} else {"actual-native-lifecycle-cold-reopen"},"passed":passed,"scripted_input":true,"human_consent_claim":false,"stage":stage,"error":result.as_ref().err(),"link_error":links.as_ref().err(),"build":retained,"components":binding,"seed":seed,"expected_boots":if preview.is_some() {1} else {6},"completed_phase_records":phases.len(),"phases":phases,"artifacts":artifacts,"scope":"actual Native22-source Root, distinct A/B ELF and complete package banks, explicit owned VM phases, independent read-only disk and pixel/identity validation; System-generation health and durable owner policy remain separate"}),
    )?;
    links?;
    result
}
