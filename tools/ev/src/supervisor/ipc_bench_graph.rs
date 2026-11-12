//! Exact three-ELF ordinary-startup IPC benchmark producer; execution is separate.
use super::provider_graph::provider_roles;
use super::{
    desktop_graph::{ActorBuild, build_actor, retain, stack},
    *,
};
use ev_ipc_bench as actors;
use ev_kernel::{bootstrap_manifest, executable::Image, scheduler::Limits, service::ServiceImage};
fn limits(v: [u64; 4]) -> Limits {
    let [a, b, c, d] = v;
    Limits::new(a, b, c, d)
}
pub(crate) fn root_manifest(image: &[u8]) -> Vec<u8> {
    manifest_profile(image, &actors::ROOT_ROLES, 0, actors::ROOT_LIMITS, 3, 60000)
}
pub(crate) fn admit_root(bytes: &[u8], manifest: &[u8]) -> Result<u64, String> {
    if manifest != root_manifest(bytes) || manifest.len() != 328 {
        return Err("IPC benchmark must retain exact ordinary5-role/328manifest".into());
    }
    let parsed = bootstrap_manifest::verify(
        manifest,
        Sha256::digest(manifest).into(),
        bytes,
        ev_userspace_contract::ABI,
    )
    .map_err(|e| format!("IPC Root admission: {e:?}"))?;
    if parsed.grants().count() != 5 {
        return Err("IPC Root rolecount differs".into());
    }
    let image = Image::from_manifest(&parsed).map_err(|e| format!("IPC Root plan: {e:?}"))?;
    stack(&image)?;
    if image.required_frames() > actors::ROOT_LIMITS[1] {
        return Err("IPC Root frame quota exceeded".into());
    }
    Ok(image.required_frames())
}
fn constant(out: &mut String, name: &str, path: &Path) -> Result<(), String> {
    *out += &format!(
        "#[cfg(feature=\"test-m5-ipc-bench\")]pub const {name}:&[u8]=include_bytes!({});\n",
        serde_json::to_string(path).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn digest(out: &mut String, name: &str, hash: [u8; 32]) {
    *out += &format!("#[cfg(feature=\"test-m5-ipc-bench\")]pub const {name}:[u8;32]={hash:?};\n");
}
pub(crate) fn extend(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    bundle: &Path,
) -> Result<(), String> {
    let tool = desktop_tool(root, directory, toolchain)?;
    let mut generated = fs::read_to_string(bundle).map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    for (stem, feature, name, shape) in [
        (
            "m5-ipc-server",
            "server",
            "M5_IPC_SERVER",
            &actors::SERVER_ROLES[..],
        ),
        (
            "m5-ipc-client",
            "client",
            "M5_IPC_CLIENT",
            &actors::CLIENT_ROLES[..],
        ),
    ] {
        let bytes = build_actor(
            root,
            directory,
            toolchain,
            &tool,
            ActorBuild {
                package: "ev-ipc-bench",
                feature,
                name: stem,
            },
            artifacts,
        )?;
        let sha = Sha256::digest(&bytes).into();
        let image = ServiceImage::verify(
            &bytes,
            sha,
            limits(actors::CHILD_LIMITS),
            &provider_roles(shape)?,
        )
        .map_err(|e| format!("IPC actual child: {e:?}"))?;
        let plan = image.plan().map_err(|e| format!("IPC child plan: {e:?}"))?;
        stack(&plan)?;
        constant(
            &mut generated,
            &format!("{name}_IMAGE"),
            &directory.join(format!("{stem}.elf")),
        )?;
        digest(&mut generated, &format!("{name}_SHA"), sha);
        digest(
            &mut generated,
            &format!("{name}_DESCRIPTOR"),
            image.digest(),
        );
        records.push(serde_json::json!({"artifact":format!("{stem}.elf"),"image":sha,"descriptor":image.digest(),"roles":shape,"frames":plan.required_frames(),"stack_bytes":16384}));
    }
    let bytes = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-root-supervisor",
            feature: "ipc-bench-root",
            name: "m5-ipc-root",
        },
        artifacts,
    )?;
    let manifest = root_manifest(&bytes);
    let frames = admit_root(&bytes, &manifest)?;
    let path = directory.join("m5-ipc-root.manifest.bin");
    fs::write(&path, &manifest).map_err(|e| e.to_string())?;
    retain(root, &path, artifacts)?;
    constant(
        &mut generated,
        "M5_IPC_ROOT_IMAGE",
        &directory.join("m5-ipc-root.elf"),
    )?;
    constant(&mut generated, "M5_IPC_ROOT_MANIFEST", &path)?;
    digest(
        &mut generated,
        "M5_IPC_ROOT_MEASUREMENT",
        Sha256::digest(&manifest).into(),
    );
    let path = directory.join("m5-ipc-components.json");
    fs::write(&path,serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"scope":"actual source/admission only; no performance or runtime success claim","root_frames":frames,"root_roles":actors::ROOT_ROLES,"root_stack":16384,"components":records,"warmups":actors::WARMUP,"measured_rounds":actors::ROUNDS})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    retain(root, &path, artifacts)?;
    fs::write(bundle, generated).map_err(|e| e.to_string())
}
