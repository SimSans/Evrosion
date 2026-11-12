//! One actual ordinary-startup provider-switch VM and independent source/serial
//! verification. No disk attachment or host repair belongs to this fixture.
use crate::{
    boot::{self, ProviderBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    provider_components, provider_protocol, storage,
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
        return Err("provider input nonregular/oversized".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("provider input grew beyond bound".into());
    }
    Ok(bytes)
}
fn link(path: &Path, base: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err("provider evidence must be an owned regular file".into());
    }
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"provider evidence escaped directory")?,"sha256":build::hash_file(path)?,"bytes":m.len()}),
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
            "provider actual linked kernel stack preflight failed: {status}"
        ));
    }
    for actor in ["root", "consumer", "a", "b"] {
        let exact = format!("m5-provider-{actor}.unstripped.elf");
        let mut candidates = manifest.supervisor.iter().filter(|a| {
            Path::new(&a.path)
                .file_name()
                .is_some_and(|n| n == exact.as_str())
        });
        let artifact = candidates
            .next()
            .ok_or("provider source ELF symbols missing")?;
        if candidates.next().is_some() {
            return Err("ambiguous provider source ELF symbols".into());
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
                "provider actual {actor} stack preflight failed: {status}"
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
    let evidence = build::unique_directory(&parent, "provider-switch")?;
    println!("Evidence: {}", evidence.display());
    let mut stage = "build";
    let mut retained = None;
    let mut components = None;
    let mut execution = None;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some("m5-provider".into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_build";
        let bytes = bounded(&root.join("build/m0/manifest.json"), 16 * 1024 * 1024)?;
        let manifest_path = evidence.join("manifest.json");
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if manifest.fixture.as_deref() != Some("m5-provider") {
            return Err("wrong retained provider fixture".into());
        }
        retained = Some(
            json!({"manifest":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,"kernel":manifest.kernel,"image":manifest.image,"source_sha256":manifest.source_sha256,"source_inputs":manifest.source_inputs}),
        );
        stage = "actual_components";
        let bound = provider_components::retain(&root, &evidence, &manifest)?;
        components = Some(bound.record);
        stage = "linked_stack_preflight";
        stack(&root, &evidence, &manifest)?;
        stage = "actual_provider_switch";
        boot::boot_provider(
            &BootOptions {
                root: Some(root.clone()),
                timeout_seconds: 180,
                ..BootOptions::default()
            },
            ProviderBoot {
                manifest: &manifest_path,
                evidence: &evidence,
                images: bound.images,
            },
        )?;
        stage = "independent_source_bound_execution";
        let serial = bounded(&evidence.join("boot/run-001/serial.log"), 1024 * 1024)?;
        execution = Some(provider_protocol::record(
            &serial,
            &manifest.build_id,
            bound.images,
        )?);
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
                return Err("provider evidence contains a symlink".into());
            }
        }
        Ok(())
    }
    let links = visit(&evidence, &evidence, &mut artifacts);
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"actual-userspace-provider-replacement","passed":result.is_ok()&&links.is_ok(),"stage":stage,
        "error":result.as_ref().err(),"link_error":links.as_ref().err(),"build":retained,"components":components,"execution":execution,"expected_boots":1,"artifacts":artifacts,
        "scope":"one actual source-built Root/consumer/providerA/providerB fixture,10opaque protected call/reply receipts, same consumer endpoint/SEND and actual Root+consumerExit0 with physical retirement; not durable provider-preference or public ecosystem proof"}),
    )?;
    links?;
    result
}
