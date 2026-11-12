//! Exact retained artifacts for the ordinary336 IPC benchmark fixture. A producer
//! metadata PASS is never treated as actual process/endpoint replacement.
use crate::{
    build::{self, Manifest, Result},
    ipc_bench_protocol::Images,
    storage,
};
use ev_ipc_bench as actors;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path},
};
pub(super) struct Components {
    pub record: Value,
    pub images: Images,
}
fn required<'a>(source: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8]> {
    source
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("actual IPC benchmark artifact missing: {name}"))
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn validate(source: &BTreeMap<String, Vec<u8>>) -> Result<Components> {
    let root = required(source, "m5-ipc-root.elf")?;
    let manifest = required(source, "m5-ipc-root.manifest.bin")?;
    let root_frames = crate::supervisor::ipc_bench_graph::admit_root(root, manifest)?;
    let client = required(source, "m5-ipc-client.elf")?;
    let server = required(source, "m5-ipc-server.elf")?;
    let mut children = Vec::new();
    for (name, bytes, roles) in [
        ("client", client, &actors::CLIENT_ROLES[..]),
        ("server", server, &actors::SERVER_ROLES[..]),
    ] {
        let (descriptor, frames) =
            crate::supervisor::provider_graph::admit_provider_child(bytes, roles)?;
        children.push(json!({"actor":name,"image":hash(bytes),"descriptor":descriptor,"roles":roles,"limits":actors::CHILD_LIMITS,"frames":frames,"stack_bytes":16384}));
    }
    let images = Images {
        root: hash(root),
        client: hash(client),
        server: hash(server),
    };
    if images.root == images.client
        || images.root == images.server
        || images.client == images.server
    {
        return Err("IPC requires distinct actual source actor images".into());
    }
    Ok(Components {
        images,
        record: json!({"schema":1,"root_image":images.root,"root_manifest":hash(manifest),"root_frames":root_frames,"root_roles":actors::ROOT_ROLES,"startup_bytes":336,"manifest_bytes":328,"children":children,"scope":"exact source/ELF/role admission only; no runtime or performance result"}),
    })
}
pub(super) fn retain(root: &Path, evidence: &Path, manifest: &Manifest) -> Result<Components> {
    if manifest.fixture.as_deref() != Some("m5-ipc-bench") || manifest.supervisor.len() > 512 {
        return Err(
            "IPC benchmark collector requires bounded explicit m5-ipc-bench source manifest".into(),
        );
    }
    let output = storage::directory_beneath(root, Path::new("build/m0"))?;
    let directory = evidence.join("components");
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let mut source = BTreeMap::new();
    let mut links = Vec::new();
    let mut total = 0usize;
    for (index, artifact) in manifest.supervisor.iter().enumerate() {
        let relative = Path::new(&artifact.path);
        if relative.is_absolute()
            || !relative
                .components()
                .all(|p| matches!(p, Component::Normal(_)))
        {
            return Err("IPC benchmark artifact path escapes build output".into());
        }
        let mut checked = output.clone();
        for part in relative.components() {
            checked.push(part);
            if fs::symlink_metadata(&checked)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("IPC benchmark artifact parent is symlink".into());
            }
        }
        let path = build::verify_artifact(&output, artifact)?;
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
            return Err("IPC benchmark artifact is nonregular/over8MiB".into());
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        if format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256 {
            return Err("IPC benchmark artifact changed after preflight".into());
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("IPC benchmark retained size overflow")?;
        if total > 256 * 1024 * 1024 {
            return Err("IPC benchmark component set exceeds256MiB".into());
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("IPC benchmark artifact filename invalid")?;
        if source.contains_key(name) {
            return Err("IPC benchmark duplicate exact artifact basename".into());
        }
        let retained = directory.join(format!("{index:03}-{name}"));
        storage::immutable_new(&retained, &bytes)?;
        links.push(json!({"artifact":artifact,"retained":retained.strip_prefix(evidence).map_err(|e|e.to_string())?,"sha256":hash(&bytes)}));
        source.insert(name.to_owned(), bytes);
    }
    let mut components = validate(&source)?;
    components.record["retained_components"] = json!(links);
    components.record["build_id"] = json!(manifest.build_id);
    storage::json_new(&evidence.join("component-binding.json"), &components.record)?;
    Ok(components)
}
