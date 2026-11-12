//! Explicit ordinary-startup provider fixture. This producer builds/admit bytes;
//! actual receiver selection, replacement and success remain separate runtime facts.
use super::desktop_graph::{ActorBuild, build_actor, retain, stack};
use super::*;
use ev_kernel::{
    bootstrap_manifest,
    capability::{Kind, Rights},
    executable::Image,
    scheduler::Limits,
    service::{Role, ServiceImage},
};
use ev_provider_test as actors;

pub(crate) const PROVIDER_RESTART_ATTEMPTS: u8 = 3;
pub(crate) const PROVIDER_RESTART_WINDOW: u64 = 60_000;
fn limits(values: [u64; 4]) -> Limits {
    let [cpu, frames, processes, threads] = values;
    Limits::new(cpu, frames, processes, threads)
}
fn kind(tag: u8) -> Result<Kind, String> {
    match tag {
        1 => Ok(Kind::Memory),
        2 => Ok(Kind::Endpoint),
        5 => Ok(Kind::Job),
        _ => Err("unknown closed provider role kind".into()),
    }
}
pub(crate) fn provider_roles(shape: &[(u8, u16)]) -> Result<Vec<Role>, String> {
    shape
        .iter()
        .enumerate()
        .map(|(index, &(tag, rights))| {
            Ok(Role {
                selector: index as u64 + 1,
                kind: kind(tag)?,
                rights: Rights::from_bits(rights).ok_or("provider role rights invalid")?,
            })
        })
        .collect()
}
/// Assumes the fixture factory will realize six distinct roots in this exact
/// order. The live kernel binding MUST recompute full generation identities;
/// these deterministic producer inputs cannot grant or certify real authority.
pub(crate) fn provider_root_manifest(image: &[u8]) -> Vec<u8> {
    manifest_profile(
        image,
        &actors::ROOT_ROLES,
        0,
        actors::ROOT_LIMITS,
        PROVIDER_RESTART_ATTEMPTS,
        PROVIDER_RESTART_WINDOW,
    )
}
pub(crate) fn admit_provider_root(bytes: &[u8], manifest: &[u8]) -> Result<u64, String> {
    let expected = provider_root_manifest(bytes);
    if manifest != expected {
        return Err("provider Root manifest/limits/source identities differ".into());
    }
    let measurement = Sha256::digest(manifest).into();
    let parsed =
        bootstrap_manifest::verify(manifest, measurement, bytes, ev_userspace_contract::ABI)
            .map_err(|e| format!("ordinary336 provider Root manifest: {e:?}"))?;
    if parsed.grants().count() != actors::ROOT_ROLES.len() || manifest.len() != 360 {
        return Err("provider Root must retain ordinary6-role/360-manifest profile".into());
    }
    for (grant, &(tag, rights)) in parsed.grants().zip(actors::ROOT_ROLES.iter()) {
        if grant.kind != kind(tag)? || grant.rights.bits() != rights {
            return Err("provider Root explicit role differs".into());
        }
    }
    let plan =
        Image::from_manifest(&parsed).map_err(|e| format!("provider Root ELF admission: {e:?}"))?;
    stack(&plan)?;
    if plan.required_frames() > actors::ROOT_LIMITS[1] {
        return Err("provider Root frames exceed its manifest".into());
    }
    Ok(plan.required_frames())
}
pub(crate) fn admit_provider_child(
    bytes: &[u8],
    shape: &[(u8, u16)],
) -> Result<([u8; 32], u64), String> {
    let sha = Sha256::digest(bytes).into();
    let image = ServiceImage::verify(
        bytes,
        sha,
        limits(actors::CHILD_LIMITS),
        &provider_roles(shape)?,
    )
    .map_err(|e| format!("actual provider actor descriptor: {e:?}"))?;
    let plan = image
        .plan()
        .map_err(|e| format!("actual provider load plan: {e:?}"))?;
    stack(&plan)?;
    Ok((image.digest(), plan.required_frames()))
}
fn constant(out: &mut String, name: &str, path: &Path) -> Result<(), String> {
    *out += &format!(
        "#[cfg(feature=\"test-m5-provider\")]pub const {name}:&[u8]=include_bytes!({});\n",
        serde_json::to_string(path).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn digest(out: &mut String, name: &str, sha: [u8; 32]) {
    *out += &format!("#[cfg(feature=\"test-m5-provider\")]pub const {name}:[u8;32]={sha:?};\n");
}
/// One coordinated source snapshot precedes these four actual builds. Reuses
/// existing logged offline/link/strip/PT_LOAD-preservation machinery unchanged.
pub(crate) fn extend_provider_graph(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    build_id: &str,
    artifacts: &mut Vec<Artifact>,
    bundle: &Path,
) -> Result<(), String> {
    if build_id.len() != 64
        || !build_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("provider fixture requires canonical64hex source identity".into());
    }
    let tool = desktop_tool(root, directory, toolchain)?;
    let mut generated = fs::read_to_string(bundle).map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    let mut actual = Vec::new();
    for (stem, feature, name, shape) in [
        (
            "m5-provider-consumer",
            "consumer",
            "M5_PROVIDER_CONSUMER",
            &actors::CONSUMER_ROLES[..],
        ),
        (
            "m5-provider-a",
            "provider-a",
            "M5_PROVIDER_A",
            &actors::PROVIDER_ROLES[..],
        ),
        (
            "m5-provider-b",
            "provider-b",
            "M5_PROVIDER_B",
            &actors::PROVIDER_ROLES[..],
        ),
    ] {
        let bytes = build_actor(
            root,
            directory,
            toolchain,
            &tool,
            ActorBuild {
                package: "ev-provider-test",
                feature,
                name: stem,
            },
            artifacts,
        )?;
        let sha = Sha256::digest(&bytes).into();
        let (descriptor, frames) = admit_provider_child(&bytes, shape)?;
        constant(
            &mut generated,
            &format!("{name}_IMAGE"),
            &directory.join(format!("{stem}.elf")),
        )?;
        digest(&mut generated, &format!("{name}_SHA"), sha);
        digest(&mut generated, &format!("{name}_DESCRIPTOR"), descriptor);
        records.push(serde_json::json!({"artifact":format!("{stem}.elf"),"feature":feature,"image_sha256":sha,"descriptor_sha256":descriptor,"limits":actors::CHILD_LIMITS,"roles":shape,"private_frames":frames,"stack_bytes":16384}));
        actual.push(bytes);
    }
    if actual[1] == actual[2] || load_identity(&actual[1])? == load_identity(&actual[2])? {
        return Err(
            "provider A/B must have different actual initialized load bytes/identity".into(),
        );
    }
    let root_bytes = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-root-supervisor",
            feature: "provider-switch",
            name: "m5-provider-root",
        },
        artifacts,
    )?;
    let manifest = provider_root_manifest(&root_bytes);
    let frames = admit_provider_root(&root_bytes, &manifest)?;
    let manifest_path = directory.join("m5-provider-root.manifest.bin");
    fs::write(&manifest_path, &manifest).map_err(|e| e.to_string())?;
    retain(root, &manifest_path, artifacts)?;
    constant(
        &mut generated,
        "M5_PROVIDER_ROOT_IMAGE",
        &directory.join("m5-provider-root.elf"),
    )?;
    constant(&mut generated, "M5_PROVIDER_ROOT_MANIFEST", &manifest_path)?;
    digest(
        &mut generated,
        "M5_PROVIDER_ROOT_MEASUREMENT",
        Sha256::digest(&manifest).into(),
    );
    let record = directory.join("m5-provider-measurements.json");
    build::write_json(
        &record,
        &serde_json::json!({"schema":1,"kind":"source-built-ordinary-provider-fixture","source_build_id":build_id,
        "scope":"ELF/manifest/descriptor integrity and admission only; no live replacement or endpoint-stability proof",
        "startup_bytes":ev_userspace_contract::SIZE,"interface":actors::wire::INTERFACE,"interface_version":actors::wire::VERSION,
        "root":{"artifact":"m5-provider-root.elf","image_sha256":<[u8;32]>::from(Sha256::digest(&root_bytes)),"manifest_sha256":<[u8;32]>::from(Sha256::digest(&manifest)),"manifest_bytes":manifest.len(),"limits":actors::ROOT_LIMITS,"roles":actors::ROOT_ROLES,"private_frames":frames,"stack_bytes":16384},
        "children":records,"different_provider_load_identity":true,"llvm_objcopy":tool,"llvm_objcopy_sha256":build::hash_file(&tool)?}),
    )?;
    retain(root, &record, artifacts)?;
    fs::write(bundle, generated).map_err(|e| e.to_string())?;
    Ok(())
}

/// Compare admitted initialized LOAD identity, not debug/section/file metadata.
pub(crate) fn different_provider_loads(a: &[u8], b: &[u8]) -> Result<bool, String> {
    Ok(load_identity(a)? != load_identity(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image(label: u8) -> Vec<u8> {
        let mut bytes =
            include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf").to_vec();
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
    #[test]
    fn root_profile_is_ordinary336_six_roles_and_exact360_manifest() {
        let image = image(9);
        let manifest = provider_root_manifest(&image);
        assert_eq!(manifest.len(), 360);
        assert!(admit_provider_root(&image, &manifest).is_ok());
        assert_eq!(ev_userspace_contract::SIZE, 336);
        let parsed = bootstrap_manifest::verify(
            &manifest,
            Sha256::digest(&manifest).into(),
            &image,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        for (index, (grant, expected)) in parsed.grants().zip(actors::ROOT_ROLES).enumerate() {
            assert_eq!(grant.selector.value(), index as u64 + 1);
            assert_eq!(grant.rights.bits(), expected.1);
        }
        let mut changed = manifest.clone();
        changed[168 + 2 * 32 + 10] ^= 1;
        assert!(admit_provider_root(&image, &changed).is_err());
        assert!(admit_provider_root(&image, &manifest[..manifest.len() - 1]).is_err());
    }
    #[test]
    fn actual_guarded_child_frames_and_load_identity_are_checked_without_running_actor() {
        let a = image(1);
        let b = image(2);
        for roles in [&actors::CONSUMER_ROLES[..], &actors::PROVIDER_ROLES[..]] {
            assert!(admit_provider_child(&a, roles).is_ok());
        }
        assert!(different_provider_loads(&a, &b).unwrap());
        assert!(!different_provider_loads(&a, &a).unwrap());
        let mut metadata_only = a.clone();
        metadata_only.extend_from_slice(b"unloaded metadata");
        assert_ne!(Sha256::digest(&a), Sha256::digest(&metadata_only));
        assert!(!different_provider_loads(&a, &metadata_only).unwrap());
        let mut wrong = a;
        let header = 64 + 2 * 56;
        wrong[header + 40..header + 48].copy_from_slice(&12288u64.to_le_bytes());
        assert!(admit_provider_child(&wrong, &actors::PROVIDER_ROLES).is_err());
    }
}
