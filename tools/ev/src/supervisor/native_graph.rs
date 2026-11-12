//! Native profile producer. Actual source-built ELF/container bytes are retained;
//! metadata creates neither authority nor a runtime/lifecycle success receipt.
use super::desktop_graph::{ActorBuild, build_actor, limits, retain, roles, stack};
use super::*;
use ev_kernel::{
    executable::LayoutReservation,
    root_producer_v2::{Description as RootDescription, Identity},
    service::ServiceImage,
};
use ev_userspace_contract::root_v2::{
    catalogue::{self as base, Description, Image, Provenance},
    graph::Child,
    native::{
        self,
        catalogue::{self, AppImage, Catalogue},
    },
};

fn constant(out: &mut String, name: &str, path: &Path) -> Result<(), String> {
    *out += &format!(
        "#[cfg(feature=\"test-m5-native\")]pub const {name}:&[u8]=include_bytes!({});\n",
        serde_json::to_string(path).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn digest(out: &mut String, name: &str, sha: [u8; 32]) {
    *out += &format!("#[cfg(feature=\"test-m5-native\")]pub const {name}:[u8;32]={sha:?};\n");
}
fn admit(bytes: &[u8], child: Child) -> Result<(Image, u64), String> {
    let sha = Sha256::digest(bytes).into();
    let layout = if child == Child::Display {
        LayoutReservation::DisplayApertureV1
    } else {
        LayoutReservation::Legacy
    };
    let grants = roles(child);
    let descriptor = ServiceImage::verify_layout(bytes, sha, limits(), &grants, layout)
        .map_err(|e| format!("Native {child:?} descriptor: {e:?}"))?;
    let plan = descriptor
        .plan()
        .map_err(|e| format!("Native {child:?} load: {e:?}"))?;
    stack(&plan)?;
    for page in (303..=367).chain(383..=447) {
        if plan.pages().any(|p| p.address == plan.base() + page * 4096) {
            return Err(format!(
                "Native {child:?} LOAD overlaps reserved window/guard {page}"
            ));
        }
    }
    Ok((
        Image {
            role: child.image(),
            image: sha,
            descriptor: descriptor.digest(),
            abi: ev_userspace_contract::ABI,
            limits: base::CHILD_LIMITS,
            display_layout: child == Child::Display,
            grants: grants.len() as u8,
            roles: ev_root_supervisor::desktop_plan::roles_measurement(child),
        },
        plan.required_frames(),
    ))
}
fn admit_root_stack(plan: &ev_kernel::executable::Image<'_>) -> Result<(), String> {
    let first = native::ROOT_STACK_FIRST_PAGE;
    let end = first + native::ROOT_STACK_PAGES;
    for guard in [first - 1, end, 507, 508] {
        if plan
            .pages()
            .any(|p| p.address == plan.base() + guard * 4096)
        {
            return Err("Native Root LOAD overlaps measured stack guard/window".into());
        }
    }
    for index in first..end {
        let page = plan
            .pages()
            .find(|p| p.address == plan.base() + index * 4096)
            .ok_or("Native Root measured32KiB stack page missing")?;
        let mut bytes = [0xff; 4096];
        page.copy_into(&mut bytes);
        if page.permission != ev_kernel::user::UserPermission::ReadWrite || bytes != [0; 4096] {
            return Err("Native Root stack must be zero-init RW/NX".into());
        }
    }
    Ok(())
}
fn base_catalogue(
    root_image: [u8; 32],
    input: [u8; 32],
    package: &crate::native_package::BuiltPackage,
    images: [Image; 6],
) -> Result<[u8; base::SIZE], String> {
    let make = |graph| Description {
        root_image,
        kernel_input: input,
        graph,
        app_id: package.app,
        package: package.package,
        app_build: package.build,
        provenance: Provenance::Zion,
        restart_attempts: ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        restart_window: ev_root_supervisor::desktop_plan::RESTART_WINDOW,
        images,
    };
    let initial = base::encode(make([0; 32])).map_err(|e| format!("Native base: {e:?}"))?;
    let graph = ev_root_supervisor::desktop_plan::graph_measurement(
        &base::Catalogue::decode(&initial).map_err(|e| format!("Native base readback: {e:?}"))?,
    );
    base::encode(make(graph)).map_err(|e| format!("Native measured base: {e:?}"))
}

pub(crate) fn extend_native_graph(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    recipe_input: &str,
    boot_mode: native::catalogue::BootMode,
    artifacts: &mut Vec<Artifact>,
    bundle: &Path,
) -> Result<(), String> {
    if recipe_input.len() != 64
        || !recipe_input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Native graph requires canonical64-hex source identity".into());
    }
    let mut input = [0; 32];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&recipe_input[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let tool = desktop_tool(root, directory, toolchain)?;
    let mut generated = fs::read_to_string(bundle).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    let mut measured = Vec::new();
    let mut app_a = None;
    for (child, package, feature, stem, name) in [
        (
            Child::Shell,
            "ev-desktop",
            "native-shell",
            "m5-native-shell",
            "M5_NATIVE_SHELL",
        ),
        (
            Child::Input,
            "ev-desktop",
            "input",
            "m5-native-input",
            "M5_NATIVE_INPUT",
        ),
        (
            Child::File,
            "ev-file-service",
            "desktop",
            "m5-native-file",
            "M5_NATIVE_FILE",
        ),
        (
            Child::Block,
            "ev-block-service",
            "native-driver",
            "m5-native-block",
            "M5_NATIVE_BLOCK",
        ),
        (
            Child::App,
            "ev-native-hello",
            "native-a",
            "m5-native-app-a",
            "M5_NATIVE_APP_A",
        ),
        (
            Child::Display,
            "ev-desktop",
            "compositor",
            "m5-native-display",
            "M5_NATIVE_DISPLAY",
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
        let (row, frames) = admit(&bytes, child)?;
        constant(
            &mut generated,
            &format!("{name}_IMAGE"),
            &directory.join(format!("{stem}.elf")),
        )?;
        digest(&mut generated, &format!("{name}_SHA"), row.image);
        measured.push(serde_json::json!({"child":format!("{child:?}"),"artifact":format!("{stem}.elf"),"feature":feature,"image":row.image,"descriptor":row.descriptor,"frames":frames,"stack_bytes":16384}));
        rows.push(row);
        if child == Child::App {
            app_a = Some(bytes);
        }
    }
    let b = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-native-hello",
            feature: "native-b",
            name: "m5-native-app-b",
        },
        artifacts,
    )?;
    let (b_row, b_frames) = admit(&b, Child::App)?;
    let a = crate::native_package::native_hello(&app_a.ok_or("Native A image missing")?, input)?;
    let b = crate::native_package::native_hello(&b, input)?;
    if a.app != b.app
        || a.executable == b.executable
        || a.package == b.package
        || a.build == b.build
    {
        return Err(
            "Native A/B must share AppId and have distinct actual ELF/package/build bytes".into(),
        );
    }
    for (slot, package) in [("A", &a), ("B", &b)] {
        if native::catalogue::package_pages(package.bytes.len() as u64).is_none() {
            return Err(format!("Native Package{slot} exceeds its real63-page bank"));
        }
        let stem = format!("m5-native-Hello-{slot}.zion");
        let path = directory.join(stem);
        fs::write(&path, &package.bytes).map_err(|e| e.to_string())?;
        retain(root, &path, artifacts)?;
        constant(&mut generated, &format!("M5_NATIVE_PACKAGE_{slot}"), &path)?;
    }
    constant(
        &mut generated,
        "M5_NATIVE_APP_B_IMAGE",
        &directory.join("m5-native-app-b.elf"),
    )?;
    digest(&mut generated, "M5_NATIVE_APP_B_SHA", b_row.image);
    let bad_shell = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-desktop",
            feature: "native-bad-shell",
            name: "m5-native-bad-shell",
        },
        artifacts,
    )?;
    let (bad_shell_row, bad_shell_frames) = admit(&bad_shell, Child::Shell)?;
    constant(
        &mut generated,
        "M5_NATIVE_BAD_SHELL_IMAGE",
        &directory.join("m5-native-bad-shell.elf"),
    )?;
    digest(
        &mut generated,
        "M5_NATIVE_BAD_SHELL_SHA",
        bad_shell_row.image,
    );
    let root_image = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-root-supervisor",
            feature: "native-root",
            name: "m5-native-root",
        },
        artifacts,
    )?;
    let root_stack = directory.join("m5-native-root.stack.json");
    let root_stack_log = directory.join("m5-native-root-stack.log");
    let mut audit = Command::new("python3");
    audit
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg("--userspace")
        .args(["--stack-bytes", "32768"])
        .arg(directory.join("m5-native-root.elf"))
        .arg(&root_stack);
    build::logged(&mut audit, &root_stack_log)?;
    retain(root, &root_stack, artifacts)?;
    retain(root, &root_stack_log, artifacts)?;
    let root_sha = Sha256::digest(&root_image).into();
    let images: [Image; 6] = rows.try_into().map_err(|_| "Native six-child count")?;
    if images[Child::App.index()].descriptor != a.descriptor || b_row.descriptor != b.descriptor {
        return Err("Native package differs from actual admitted App descriptor".into());
    }
    let base = base_catalogue(root_sha, input, &a, images)?;
    let description = |layout_measurement| catalogue::Description {
        base: &base,
        app_b: AppImage {
            image: b_row.image,
            descriptor: b_row.descriptor,
            abi: b_row.abi,
            limits: b_row.limits,
            roles: b_row.roles,
        },
        bad_shell: AppImage {
            image: bad_shell_row.image,
            descriptor: bad_shell_row.descriptor,
            abi: bad_shell_row.abi,
            limits: bad_shell_row.limits,
            roles: bad_shell_row.roles,
        },
        boot_mode,
        package_b: b.package,
        package_b_build: b.build,
        package_a_bytes: a.bytes.len() as u64,
        package_b_bytes: b.bytes.len() as u64,
        layout_measurement,
    };
    let draft = catalogue::encode(description([1; 32]))
        .map_err(|e| format!("Native catalogue draft: {e:?}"))?;
    let layout = ev_root_supervisor::native_plan::layout_measurement(
        &Catalogue::decode(&draft).map_err(|e| format!("Native draft readback: {e:?}"))?,
    );
    let bytes =
        catalogue::encode(description(layout)).map_err(|e| format!("Native catalogue: {e:?}"))?;
    let catalogue_sha = Sha256::digest(bytes).into();
    let catalogue_path = directory.join("m5-native-catalogue.bin");
    fs::write(&catalogue_path, bytes).map_err(|e| e.to_string())?;
    retain(root, &catalogue_path, artifacts)?;
    let description = RootDescription::full_native_graph(
        ev_root_supervisor::desktop_plan::ROOT_LIMITS,
        ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        ev_root_supervisor::desktop_plan::RESTART_WINDOW,
        core::array::from_fn(|i| Identity {
            object: i as u64,
            lineage: i as u64,
        }),
    )
    .map_err(|e| format!("Native sources: {e:?}"))?
    .bind_catalogue(catalogue_sha);
    let encoded = ev_kernel::root_producer_v2::encode_native(&root_image, &description)
        .map_err(|e| format!("Native Root encode: {e:?}"))?;
    let manifest =
        ev_kernel::root_manifest_v2::verify(encoded.bytes(), encoded.digest(), &root_image)
            .map_err(|e| format!("Native Root verify: {e:?}"))?
            .native_profile()
            .map_err(|e| format!("Native Root profile: {e:?}"))?;
    let plan = ev_kernel::executable::Image::from_native_root(&manifest)
        .map_err(|e| format!("Native Root load: {e:?}"))?;
    admit_root_stack(&plan)?;
    for page in (303..=367).chain(383..=447) {
        if plan.pages().any(|p| p.address == plan.base() + page * 4096) {
            return Err(format!(
                "Native Root LOAD overlaps immutable bank/guard {page}"
            ));
        }
    }
    if plan.required_frames() > ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES {
        return Err(format!(
            "Native Root private{}frames exceeds{}",
            plan.required_frames(),
            ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES
        ));
    }
    let manifest_path = directory.join("m5-native-root.manifest.bin");
    fs::write(&manifest_path, encoded.bytes()).map_err(|e| e.to_string())?;
    retain(root, &manifest_path, artifacts)?;
    constant(
        &mut generated,
        "M5_NATIVE_ROOT_IMAGE",
        &directory.join("m5-native-root.elf"),
    )?;
    constant(&mut generated, "M5_NATIVE_ROOT_MANIFEST", &manifest_path)?;
    digest(
        &mut generated,
        "M5_NATIVE_ROOT_MEASUREMENT",
        encoded.digest(),
    );
    constant(&mut generated, "M5_NATIVE_CATALOGUE", &catalogue_path)?;
    digest(&mut generated, "M5_NATIVE_CATALOGUE_SHA", catalogue_sha);
    let measurements = directory.join("m5-native-measurements.json");
    build::write_json(
        &measurements,
        &serde_json::json!({"schema":1,"kind":"source-built-native-profile3-bundle","scope":"Actual source/ELF/container/descriptor admission only; no execution/lifecycle PASS claim","recipe_input":recipe_input,"boot_mode":format!("{boot_mode:?}"),"root":{"image":root_sha,"manifest":encoded.digest(),"catalogue":catalogue_sha,"layout":layout,"manifest_bytes":encoded.bytes().len(),"private_frames":plan.required_frames(),"image_pages":plan.pages().count(),"private_frame_bound":ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES,"stack_bytes":native::ROOT_STACK_BYTES},"children":measured,"app_b_frames":b_frames,"bad_shell":{"image":bad_shell_row.image,"descriptor":bad_shell_row.descriptor,"frames":bad_shell_frames,"stack_bytes":16384},"packages":[{"slot":"A","app":a.app,"package":a.package,"image":a.executable,"build":a.build,"bytes":a.bytes.len()},{"slot":"B","app":b.app,"package":b.package,"image":b.executable,"build":b.build,"bytes":b.bytes.len()}],"shared_frames_without_banks":130,"system_health":"not asserted by producer","file_mode":"open-existing-only","llvm_objcopy":tool,"llvm_objcopy_sha256":build::hash_file(&tool)?}),
    )?;
    retain(root, &measurements, artifacts)?;
    fs::write(bundle, generated).map_err(|e| e.to_string())?;
    Ok(())
}
