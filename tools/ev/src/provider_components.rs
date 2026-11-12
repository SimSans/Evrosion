//! Exact retained artifacts for the ordinary336 provider fixture. A producer
//! metadata PASS is never treated as actual process/endpoint replacement.
use crate::{
    build::{self, Manifest, Result},
    provider_protocol::Images,
    storage,
};
use ev_provider_test as actors;
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
        .ok_or_else(|| format!("actual provider artifact missing: {name}"))
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn validate(source: &BTreeMap<String, Vec<u8>>) -> Result<Components> {
    let root = required(source, "m5-provider-root.elf")?;
    let manifest = required(source, "m5-provider-root.manifest.bin")?;
    let root_frames = crate::supervisor::provider_graph::admit_provider_root(root, manifest)?;
    let consumer = required(source, "m5-provider-consumer.elf")?;
    let a = required(source, "m5-provider-a.elf")?;
    let b = required(source, "m5-provider-b.elf")?;
    let mut children = Vec::new();
    for (name, bytes, shape) in [
        ("consumer", consumer, &actors::CONSUMER_ROLES[..]),
        ("a", a, &actors::PROVIDER_ROLES[..]),
        ("b", b, &actors::PROVIDER_ROLES[..]),
    ] {
        let (descriptor, frames) =
            crate::supervisor::provider_graph::admit_provider_child(bytes, shape)?;
        children.push(
            json!({"actor":name,"image_sha256":hash(bytes),"descriptor_sha256":descriptor,
            "roles":shape,"limits":actors::CHILD_LIMITS,"frames":frames,"stack_bytes":16384}),
        );
    }
    if !crate::supervisor::provider_graph::different_provider_loads(a, b)? {
        return Err("actual provider A/B LOAD bytes are identical".into());
    }
    let images = Images {
        root: hash(root),
        consumer: hash(consumer),
        a: hash(a),
        b: hash(b),
    };
    let record = json!({"schema":1,"startup_bytes":ev_userspace_contract::SIZE,"root_manifest_bytes":manifest.len(),
        "root_roles":actors::ROOT_ROLES,"root_limits":actors::ROOT_LIMITS,"root_image_sha256":images.root,
        "root_manifest_sha256":hash(manifest),"root_frames":root_frames,"children":children,
        "scope":"Exact ordinary Root manifest, actual source-built actor ELF/descriptor/content admission; no running replacement or publisher authentication"});
    Ok(Components { record, images })
}
pub(super) fn retain(root: &Path, evidence: &Path, manifest: &Manifest) -> Result<Components> {
    if manifest.fixture.as_deref() != Some("m5-provider") || manifest.supervisor.len() > 512 {
        return Err(
            "provider collector requires bounded explicit m5-provider source manifest".into(),
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
            return Err("provider artifact path escapes build output".into());
        }
        let mut checked = output.clone();
        for part in relative.components() {
            checked.push(part);
            if fs::symlink_metadata(&checked)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("provider artifact parent is symlink".into());
            }
        }
        let path = build::verify_artifact(&output, artifact)?;
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
            return Err("provider artifact is nonregular/over8MiB".into());
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        if format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256 {
            return Err("provider artifact changed after preflight".into());
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("provider retained size overflow")?;
        if total > 256 * 1024 * 1024 {
            return Err("provider component set exceeds256MiB".into());
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("provider artifact filename invalid")?;
        if source.contains_key(name) {
            return Err("provider duplicate exact artifact basename".into());
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

#[cfg(test)]
mod tests {
    use super::*;
    fn image(label: u8) -> Vec<u8> {
        let mut bytes = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf").to_vec();
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
        bytes[8192] = label;
        let header = 64 + 2 * 56;
        bytes[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[header + 4..header + 8].copy_from_slice(&6u32.to_le_bytes());
        for (field, value) in [
            (8, 8192u64),
            (16, (1u64 << 39) + 0x100000),
            (24, 0),
            (32, 0),
            (40, 16384),
            (48, 4096),
        ] {
            bytes[header + field..header + field + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    fn fixture() -> BTreeMap<String, Vec<u8>> {
        let root = image(1);
        let manifest = crate::supervisor::provider_graph::provider_root_manifest(&root);
        [
            ("m5-provider-root.elf", root),
            ("m5-provider-root.manifest.bin", manifest),
            ("m5-provider-consumer.elf", image(2)),
            ("m5-provider-a.elf", image(3)),
            ("m5-provider-b.elf", image(4)),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
    }
    #[test]
    fn component_admission_requires_exact_names_all_four_images_and_matching_manifest() {
        let source = fixture();
        let actual = validate(&source).unwrap();
        assert_eq!(actual.record["startup_bytes"], 336);
        assert_eq!(actual.record["root_manifest_bytes"], 360);
        assert_ne!(actual.images.a, actual.images.b);
        let mut wrong = source.clone();
        wrong.remove("m5-provider-b.elf");
        assert!(validate(&wrong).is_err());
        let mut wrong = source.clone();
        wrong.insert(
            "m5-provider-b.elf".into(),
            source["m5-provider-a.elf"].clone(),
        );
        assert!(validate(&wrong).is_err());
        let mut wrong = source.clone();
        wrong.get_mut("m5-provider-root.elf").unwrap()[8192] ^= 1;
        assert!(validate(&wrong).is_err());
        let mut wrong = source.clone();
        let root = wrong.remove("m5-provider-root.elf").unwrap();
        wrong.insert("renamed-provider-root.elf".into(), root);
        assert!(validate(&wrong).is_err());
    }
}
