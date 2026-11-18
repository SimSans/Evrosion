//! Additive source-built seven-process desktop bundle. Legacy producers remain
//! unchanged; only the explicit m4-desktop fixture invokes this extension.
use super::*;
use ev_kernel::{
    capability::{Kind, Rights},
    executable::LayoutReservation,
    root_producer_v2::{Description as RootDescription, Identity},
    scheduler::Limits,
    service::{Role as ServiceRole, ServiceImage},
};
use ev_userspace_contract::root_v2::{
    self,
    catalogue::{self, Catalogue, Description, Image, Provenance},
    graph::{self, Child},
};
pub(super) fn kind(tag: u8) -> Kind {
    match tag {
        1 => Kind::Memory,
        2 => Kind::Endpoint,
        5 => Kind::Job,
        7 => Kind::IoPorts,
        8 => Kind::Display,
        _ => unreachable!("closed graph kind"),
    }
}
pub(super) fn limits() -> Limits {
    let v = catalogue::CHILD_LIMITS;
    Limits::new(v[0], v[1], v[2], v[3])
}
pub(super) fn roles(child: Child) -> Vec<ServiceRole> {
    graph::grants(child)
        .iter()
        .enumerate()
        .map(|(i, g)| ServiceRole {
            selector: i as u64 + 1,
            kind: kind(g.kind),
            rights: Rights::from_bits(g.rights).unwrap(),
        })
        .collect()
}
pub(super) fn retain(
    root: &Path,
    path: &Path,
    artifacts: &mut Vec<Artifact>,
) -> Result<(), String> {
    artifacts.push(Artifact {
        path: path
            .strip_prefix(root.join("build/m0"))
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("nonUTF8desktopgraphartifact")?
            .into(),
        sha256: build::hash_file(path)?,
    });
    Ok(())
}
pub(super) fn stack(plan: &ev_kernel::executable::Image<'_>) -> Result<(), String> {
    use ev_kernel::user::UserPermission;
    for relative in [0xff000, 0x104000, 507 * 4096, 508 * 4096] {
        if plan.pages().any(|p| p.address == plan.base() + relative) {
            return Err("desktop private LOAD overlaps fixed guard/window".into());
        }
    }
    for relative in (0x100000..0x104000).step_by(4096) {
        let p = plan
            .pages()
            .find(|p| p.address == plan.base() + relative)
            .ok_or("missing measured desktop stack page")?;
        let mut actual = [0u8; 4096];
        p.copy_into(&mut actual);
        if p.permission != UserPermission::ReadWrite || actual.iter().any(|&byte| byte != 0) {
            return Err("desktop stack must be zero-init RW/NX".into());
        }
    }
    Ok(())
}
pub(super) struct ActorBuild<'a> {
    pub package: &'a str,
    pub feature: &'a str,
    pub name: &'a str,
}
pub(super) fn build_actor(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    tool: &Path,
    spec: ActorBuild<'_>,
    artifacts: &mut Vec<Artifact>,
) -> Result<Vec<u8>, String> {
    let binary = spec.package;
    build_actor_bin(root, directory, toolchain, tool, spec, binary, artifacts)
}
/// Some packages expose two independent service executables. Retain and admit
/// the selected binary, rather than assuming Cargo package and binary names
/// coincide or copying a previously built actor into a new role.
pub(super) fn build_actor_bin(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    tool: &Path,
    spec: ActorBuild<'_>,
    binary: &str,
    artifacts: &mut Vec<Artifact>,
) -> Result<Vec<u8>, String> {
    let ActorBuild {
        package,
        feature,
        name,
    } = spec;
    let target = root.join(format!("target/{name}"));
    let mut command = Command::new("rustup");
    command.current_dir(root).args(["run",&toolchain.channel,"cargo","build","--locked","--offline","-p",package,"--bin",binary,"--release","--features",feature,"--target","x86_64-unknown-none","--target-dir"]).arg(&target)
        .env("CARGO_ENCODED_RUSTFLAGS",format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--cfg\x1fcurve25519_dalek_backend=\"serial\"\x1f--remap-path-prefix={}=/evrosion",root.display())).env("RUSTUP_AUTO_INSTALL","0").env("CARGO_TERM_COLOR","never");
    let document = feature.split(',').any(|f| f == "document-workflow");
    let network_root =
        package == "ev-root-supervisor" && feature.split(',').any(|f| f == "native-network");
    // V4 retains its measured ordinary O3/16-unit profile. The smaller Native3
    // Root has a different image bound and uses its separately measured O2
    // profile. Applying that profile to V4 overlaps its fixed stack; size-only
    // V4 fits the image but exceeds the guarded stack census.
    if document && !network_root {
        command.env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1");
        command.env(
            "CARGO_PROFILE_RELEASE_OPT_LEVEL",
            if package == "ev-root-supervisor" {
                "2"
            } else {
                "s"
            },
        );
    }
    build::logged(&mut command, &directory.join(format!("{name}-build.log")))?;
    let raw_path = directory.join(format!("{name}.unstripped.elf"));
    fs::copy(
        target.join("x86_64-unknown-none/release").join(binary),
        &raw_path,
    )
    .map_err(|e| e.to_string())?;
    let raw = fs::read(&raw_path).map_err(|e| e.to_string())?;
    let before = load_identity(&raw)?;
    let path = directory.join(format!("{name}.elf"));
    let mut strip = Command::new(tool);
    strip
        .current_dir(root)
        .arg("--strip-debug")
        .arg(&raw_path)
        .arg(&path);
    build::logged(&mut strip, &directory.join(format!("{name}-strip.log")))?;
    let image = fs::read(&path).map_err(|e| e.to_string())?;
    if before != load_identity(&image)? {
        return Err(format!("{name}: strip changed PT_LOAD/entry identity"));
    }
    retain(root, &raw_path, artifacts)?;
    retain(root, &path, artifacts)?;
    Ok(image)
}
fn image_constant(
    generated: &mut String,
    directory: &Path,
    stem: &str,
    name: &str,
    sha: [u8; 32],
) -> Result<(), String> {
    *generated += &format!(
        "#[cfg(feature=\"test-m4-desktop\")]pub const {name}_IMAGE:&[u8]=include_bytes!({});\n#[cfg(feature=\"test-m4-desktop\")]pub const {name}_SHA:[u8;32]={sha:?};\n",
        serde_json::to_string(&directory.join(format!("{stem}.elf"))).map_err(|e| e.to_string())?
    );
    Ok(())
}
/// Pinned/logged source builds precede catalogue, then Root manifest. Catalogue
/// contains actual Root SHA; Root manifest binds its SHA, avoiding self-reference.
pub(crate) fn extend_desktop_graph(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    build_id: &str,
    artifacts: &mut Vec<Artifact>,
    bundle: &Path,
) -> Result<(), String> {
    if build_id.len() != 64 || !build_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("desktop graph requires64hex build input identity".into());
    }
    let mut build_input = [0; 32];
    for (i, b) in build_input.iter_mut().enumerate() {
        *b = u8::from_str_radix(&build_id[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let tool = desktop_tool(root, directory, toolchain)?;
    let mut generated = fs::read_to_string(bundle).map_err(|e| e.to_string())?;
    let mut measurements = Vec::new();
    let mut rows = Vec::new();
    let mut app_bytes = None;
    for (child, package, feature, stem, name) in [
        (
            Child::Shell,
            "ev-desktop",
            "shell",
            "m4-desktop-shell",
            "M4_DESKTOP_SHELL",
        ),
        (
            Child::Input,
            "ev-desktop",
            "input",
            "m4-desktop-input",
            "M4_DESKTOP_INPUT",
        ),
        (
            Child::File,
            "ev-file-service",
            "desktop-provision",
            "m4-desktop-file",
            "M4_DESKTOP_FILE",
        ),
        (
            Child::Block,
            "ev-block-service",
            "desktop-driver",
            "m4-desktop-block",
            "M4_DESKTOP_BLOCK",
        ),
        (
            Child::App,
            "ev-desktop",
            "interactive",
            "m4-desktop-app",
            "M4_DESKTOP_APP",
        ),
        (
            Child::Display,
            "ev-desktop",
            "compositor",
            "m4-desktop-display",
            "M4_DESKTOP_DISPLAY",
        ),
    ] {
        let bytes = build_actor(
            root,
            directory,
            toolchain,
            &tool,
            ActorBuild {
                package,
                feature,
                name: stem,
            },
            artifacts,
        )?;
        let sha: [u8; 32] = Sha256::digest(&bytes).into();
        let layout = if child == Child::Display {
            LayoutReservation::DisplayApertureV1
        } else {
            LayoutReservation::Legacy
        };
        let descriptor = ServiceImage::verify_layout(&bytes, sha, limits(), &roles(child), layout)
            .map_err(|e| format!("{stem} actual descriptor: {e:?}"))?;
        let plan = descriptor
            .plan()
            .map_err(|e| format!("{stem} load plan: {e:?}"))?;
        stack(&plan)?;
        for page in (303..=367).chain(383..=447) {
            if plan.pages().any(|p| p.address == plan.base() + page * 4096) {
                return Err(format!(
                    "{stem} private page overlaps reserved surface/guard{page}"
                ));
            }
        }
        rows.push(Image {
            role: child.image(),
            image: sha,
            descriptor: descriptor.digest(),
            abi: ev_userspace_contract::ABI,
            limits: catalogue::CHILD_LIMITS,
            display_layout: child == Child::Display,
            grants: graph::grants(child).len() as u8,
            roles: ev_root_supervisor::desktop_plan::roles_measurement(child),
        });
        image_constant(&mut generated, directory, stem, name, sha)?;
        measurements.push(serde_json::json!({"child":format!("{child:?}"),"artifact":format!("{stem}.elf"),"feature":feature,"image_sha256":sha,"descriptor_sha256":descriptor.digest(),"limits":catalogue::CHILD_LIMITS,"private_frames":plan.private_required_frames(),"additional_table_frames":layout.additional_table_frames(),"total_frames":plan.required_frames(),"pt_load_identity_preserved":true,"measured_stack_bytes":16384}));
        if child == Child::App {
            app_bytes = Some(bytes);
        }
    }
    let root_image = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-root-supervisor",
            feature: "desktop-root",
            name: "m4-desktop-root",
        },
        artifacts,
    )?;
    let root_sha: [u8; 32] = Sha256::digest(&root_image).into();
    let package = crate::native_package::hello(
        app_bytes.as_ref().ok_or("missing sourceAppELF")?,
        build_input,
    )?;
    if rows[Child::App.index()].descriptor != package.descriptor
        || rows[Child::App.index()].image != package.executable
    {
        return Err("native package differs from admitted actualAppELF".into());
    }
    let package_path = directory.join("m4-desktop-Hello.zion");
    fs::write(&package_path, &package.bytes).map_err(|e| e.to_string())?;
    retain(root, &package_path, artifacts)?;
    let package_json = directory.join("m4-desktop-package.json");
    build::write_json(
        &package_json,
        &serde_json::json!({"schema":1,"kind":"source-built-native-development-package","app":package.app,"package":package.package,"executable":package.executable,"descriptor":package.descriptor,"build":package.build,"scope":"Actual packaged content/requirements; no installer or authority claim"}),
    )?;
    retain(root, &package_json, artifacts)?;
    generated += &format!(
        "#[cfg(feature=\"test-m4-desktop\")]pub const M4_DESKTOP_APP_PACKAGE:&[u8]=include_bytes!({});\n",
        serde_json::to_string(&package_path).map_err(|e| e.to_string())?
    );
    let images: [Image; 6] = rows.try_into().map_err(|_| "desktop catalogue count")?;
    let description = Description {
        root_image: root_sha,
        kernel_input: build_input,
        graph: [0; 32],
        app_id: package.app,
        package: package.package,
        app_build: package.build,
        provenance: Provenance::Zion,
        restart_attempts: ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        restart_window: ev_root_supervisor::desktop_plan::RESTART_WINDOW,
        images,
    };
    let first = catalogue::encode(description)
        .map_err(|e| format!("desktop catalogue description: {e:?}"))?;
    let first = Catalogue::decode(&first).map_err(|e| format!("desktop catalogue parse: {e:?}"))?;
    let graph_measurement = ev_root_supervisor::desktop_plan::graph_measurement(&first);
    let bytes = catalogue::encode(Description {
        root_image: first.root_image(),
        kernel_input: first.kernel_input(),
        graph: graph_measurement,
        app_id: first.app_id(),
        package: first.package(),
        app_build: first.app_build(),
        provenance: first.provenance(),
        restart_attempts: first.restart_attempts(),
        restart_window: first.restart_window(),
        images,
    })
    .map_err(|e| format!("desktop measured catalogue: {e:?}"))?;
    let catalogue_sha: [u8; 32] = Sha256::digest(bytes).into();
    let catalogue_path = directory.join("m4-desktop-catalogue.bin");
    fs::write(&catalogue_path, bytes).map_err(|e| e.to_string())?;
    retain(root, &catalogue_path, artifacts)?;
    let root_description = RootDescription::full_graph(
        ev_root_supervisor::desktop_plan::ROOT_LIMITS,
        ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        ev_root_supervisor::desktop_plan::RESTART_WINDOW,
        core::array::from_fn(|i| Identity {
            object: i as u64,
            lineage: i as u64,
        }),
    )
    .map_err(|e| format!("desktop Root source plan: {e:?}"))?
    .bind_catalogue(catalogue_sha);
    let encoded = ev_kernel::root_producer_v2::encode_current(&root_image, &root_description)
        .map_err(|e| format!("desktop Root manifest: {e:?}"))?;
    let manifest =
        ev_kernel::root_manifest_v2::verify(encoded.bytes(), encoded.digest(), &root_image)
            .map_err(|e| format!("desktop Root verification: {e:?}"))?
            .current_profile()
            .map_err(|e| format!("desktop Root profile: {e:?}"))?;
    let plan = ev_kernel::executable::Image::from_root_manifest_v2(&manifest)
        .map_err(|e| format!("desktop Root ELF: {e:?}"))?;
    stack(&plan)?;
    if plan.required_frames() > 64 {
        return Err(format!(
            "desktop Root measured{}frames exceeds declared private64 bound",
            plan.required_frames()
        ));
    }
    let root_manifest = directory.join("m4-desktop-root.manifest.bin");
    fs::write(&root_manifest, encoded.bytes()).map_err(|e| e.to_string())?;
    retain(root, &root_manifest, artifacts)?;
    generated += &format!(
        "#[cfg(feature=\"test-m4-desktop\")]pub const M4_DESKTOP_ROOT_IMAGE:&[u8]=include_bytes!({});\n#[cfg(feature=\"test-m4-desktop\")]pub const M4_DESKTOP_ROOT_MANIFEST:&[u8]=include_bytes!({});\n#[cfg(feature=\"test-m4-desktop\")]pub const M4_DESKTOP_ROOT_MEASUREMENT:[u8;32]={:?};\n#[cfg(feature=\"test-m4-desktop\")]pub const M4_DESKTOP_CATALOGUE:&[u8]=include_bytes!({});\n#[cfg(feature=\"test-m4-desktop\")]pub const M4_DESKTOP_CATALOGUE_SHA:[u8;32]={catalogue_sha:?};\n",
        serde_json::to_string(&directory.join("m4-desktop-root.elf")).map_err(|e| e.to_string())?,
        serde_json::to_string(&root_manifest).map_err(|e| e.to_string())?,
        encoded.digest(),
        serde_json::to_string(&catalogue_path).map_err(|e| e.to_string())?
    );
    let measurement = directory.join("m4-desktop-measurements.json");
    build::write_json(
        &measurement,
        &serde_json::json!({"schema":1,"kind":"source-built-full-desktop-bundle","scope":"Actual ELF/descriptor/package/Root ABI2/cohort admission; no hardware/fullM4 PASS claim","root":{"image":root_sha,"manifest":encoded.digest(),"catalogue":catalogue_sha,"graph":graph_measurement,"startup_bytes":root_v2::SIZE,"manifest_bytes":encoded.bytes().len(),"private_frames":plan.required_frames(),"limits":ev_root_supervisor::desktop_plan::ROOT_LIMITS},"children":measurements,"shared_ram_pages":130,"llvm_objcopy":tool,"llvm_objcopy_sha256":build::hash_file(&tool)?}),
    )?;
    retain(root, &measurement, artifacts)?;
    fs::write(bundle, generated).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_descriptors_use_actual_rights_and_only_display_reserves_device_tables() {
        let elf = include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf");
        for child in graph::CHILDREN {
            let roles = roles(child);
            assert!(roles.len() <= ev_userspace_contract::MAX_GRANTS);
            for (actual, declared) in roles.iter().zip(graph::grants(child)) {
                assert_eq!(actual.kind, kind(declared.kind));
                assert_eq!(actual.rights.bits(), declared.rights);
            }
            let layout = if child == Child::Display {
                LayoutReservation::DisplayApertureV1
            } else {
                LayoutReservation::Legacy
            };
            let image = ServiceImage::verify_layout(
                elf,
                Sha256::digest(elf).into(),
                limits(),
                &roles,
                layout,
            )
            .unwrap();
            let plan = image.plan().unwrap();
            assert_eq!(
                plan.required_frames() - plan.private_required_frames(),
                if child == Child::Display { 2 } else { 0 }
            );
            assert_eq!(
                roles.iter().any(|r| r.kind == Kind::Display),
                child == Child::Display
            );
        }
        assert!(graph::grants(Child::App).iter().all(|g| !matches!(
            g.source,
            graph::Source::Endpoint(
                graph::Channel::NotesRead
                    | graph::Channel::NotesWrite
                    | graph::Channel::PrivateRead
                    | graph::Channel::PrivateWrite
            )
        )));
    }

    /// Explicitly invoked source-build admission check; does not build a kernel
    /// or run a VM and cannot establish a desktop hardware acceptance result.
    #[test]
    #[ignore = "builds all seven measured desktop executables"]
    fn source_built_desktop_bundle_admission() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let directory = root.join(format!(
            "build/m0/artifacts/desktop-producer-check-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let bundle = directory.join("desktop-bundle.rs");
        fs::write(&bundle, "// isolated source-producer admission check\n").unwrap();
        let mut artifacts = Vec::new();
        extend_desktop_graph(
            root,
            &directory,
            &Toolchain::load(root).unwrap(),
            &"42".repeat(32),
            &mut artifacts,
            &bundle,
        )
        .unwrap();
        for artifact in artifacts {
            assert_eq!(
                build::hash_file(&root.join("build/m0").join(artifact.path)).unwrap(),
                artifact.sha256
            );
        }
        let generated = fs::read_to_string(bundle).unwrap();
        assert_eq!(generated.matches("pub const M4_DESKTOP_").count(), 18);
        let catalogue = fs::read(directory.join("m4-desktop-catalogue.bin")).unwrap();
        let catalogue = Catalogue::decode(&catalogue).unwrap();
        assert_eq!(catalogue.provenance(), Provenance::Zion);
        assert_eq!(
            ev_root_supervisor::desktop_plan::graph_measurement(&catalogue),
            catalogue.graph_measurement()
        );
        eprintln!(
            "desktop source admission artifacts: {}",
            directory.display()
        );
    }
}
