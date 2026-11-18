//! Source-built V4 VM bundle. Descriptors and source witnesses are admission
//! inputs; they do not establish traffic, entropy, device cleanup or health.
use super::desktop_graph::{ActorBuild, build_actor, build_actor_bin, kind, retain, stack};
use super::*;
use ev_kernel::{
    capability::Rights,
    executable::LayoutReservation,
    root_producer_v2::Identity,
    root_producer_v4::Description as RootDescription,
    scheduler::Limits,
    service::{Role, ServiceImage},
};
use ev_userspace_contract::{
    root_v2::{catalogue as base, graph as old},
    root_v4::{
        self, catalogue as cat,
        graph::{self, Child},
    },
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    allowed_ipv4: [u8; 4],
    remote_port: u16,
    local_port: u16,
    dns_name: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    schema: u16,
    purpose: String,
    version: String,
    binary_sha256: String,
    model_source_url: String,
    model_source_sha256: String,
    downstream_equivalence_qualified: bool,
    mac: [u8; 6],
    policy: Policy,
}
fn hash32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("V4 digest must be canonical lowercase64hex".into());
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    if out == [0; 32] {
        return Err("V4 digest cannot be zero".into());
    }
    Ok(out)
}
fn roles(child: Child) -> Vec<Role> {
    graph::grants(child)
        .enumerate()
        .map(|(i, g)| Role {
            selector: i as u64 + 1,
            kind: kind(g.kind),
            rights: Rights::from_bits(g.rights).unwrap(),
        })
        .collect()
}
fn admit(bytes: &[u8], child: Child) -> Result<(cat::Image, u64), String> {
    let [cpu, frames, processes, threads] = child.limits();
    let image = Sha256::digest(bytes).into();
    let descriptor = ServiceImage::verify_layout(
        bytes,
        image,
        Limits::new(cpu, frames, processes, threads),
        &roles(child),
        if child == Child::Display {
            LayoutReservation::DisplayApertureV1
        } else {
            LayoutReservation::Legacy
        },
    )
    .map_err(|e| format!("V4 {child:?} descriptor: {e:?}"))?;
    let plan = descriptor
        .plan()
        .map_err(|e| format!("V4 {child:?} load: {e:?}"))?;
    stack(&plan)?;
    for page in (303..=367).chain(383..=447) {
        if plan.pages().any(|p| p.address == plan.base() + page * 4096) {
            return Err(format!(
                "V4 {child:?} LOAD overlaps immutable bank/guard {page}"
            ));
        }
    }
    if plan.required_frames() > frames {
        return Err(format!(
            "V4 {child:?} private frames exceed actual Job limit"
        ));
    }
    Ok((
        cat::Image {
            image,
            descriptor: descriptor.digest(),
            abi: ev_userspace_contract::ABI,
            limits: child.limits(),
            roles: ev_root_supervisor::native_plan::network_roles_measurement(child),
        },
        plan.required_frames(),
    ))
}
fn constant(out: &mut String, name: &str, path: &Path) -> Result<(), String> {
    *out += &format!(
        "#[cfg(feature=\"test-m5-native\")]pub const {name}:&[u8]=include_bytes!({});\n",
        serde_json::to_string(path).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn digest(out: &mut String, name: &str, value: [u8; 32]) {
    *out += &format!("#[cfg(feature=\"test-m5-native\")]pub const {name}:[u8;32]={value:?};\n");
}
fn audit_child(
    root: &Path,
    directory: &Path,
    stem: &str,
    artifacts: &mut Vec<Artifact>,
) -> Result<(), String> {
    let report = directory.join(format!("{stem}.stack.json"));
    let log = directory.join(format!("{stem}-stack.log"));
    let mut audit = Command::new("python3");
    audit
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .args(["--userspace", "--stack-bytes", "16384"])
        .arg(directory.join(format!("{stem}.elf")))
        .arg(&report);
    build::logged(&mut audit, &log)?;
    retain(root, &report, artifacts)?;
    retain(root, &log, artifacts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn extend(
    negative: bool,
    document: bool,
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    recipe_input: &str,
    mode: crate::network_mode::Mode,
    owner_ui: bool,
    artifacts: &mut Vec<Artifact>,
    bundle: &Path,
) -> Result<(), String> {
    if negative && owner_ui {
        return Err("owner UI and scripted negative actor features are separate fixtures".into());
    }
    let input = hash32(recipe_input)?;
    let reference_path = root.join("tools/m6/fixtures/qemu-reference.json");
    let reference_bytes = fs::read(&reference_path).map_err(|e| e.to_string())?;
    if reference_bytes.len() > 16384 {
        return Err("V4 reference witness too large".into());
    }
    let reference: Reference =
        serde_json::from_slice(&reference_bytes).map_err(|e| e.to_string())?;
    if reference.schema != 1
        || reference.purpose.is_empty()
        || reference.version.is_empty()
        || !reference
            .model_source_url
            .starts_with("https://raw.githubusercontent.com/qemu/qemu/")
        || reference.mac != cat::REFERENCE_MAC
    {
        return Err("V4 reference witness profile mismatch".into());
    }
    // The reference is a tracked input. Reading the build host's current QEMU
    // binary into catalogue bytes would make otherwise identical OS sources
    // produce different executables across the required Linux build contexts.
    let device = cat::DeviceWitness {
        mac: reference.mac,
        model_source_sha256: hash32(&reference.model_source_sha256)?,
        emulator_binary_sha256: hash32(&reference.binary_sha256)?,
    };
    let tool = desktop_tool(root, directory, toolchain)?;
    let mut generated = fs::read_to_string(bundle).map_err(|e| e.to_string())?;
    let mut images = Vec::new();
    let mut measures = Vec::new();
    let mut app_a = None;
    for (child, package, binary, feature, stem, name) in [
        (
            Child::Shell,
            "ev-desktop",
            "ev-desktop",
            if owner_ui {
                "native-shell,native-owner-ui"
            } else if negative {
                "native-shell,native-session,network-negative-worker"
            } else {
                "native-shell,native-session"
            },
            "m5-native-shell",
            "SHELL",
        ),
        (
            Child::Input,
            "ev-desktop",
            "ev-desktop",
            "input,native-session",
            "m5-native-input",
            "INPUT",
        ),
        (
            Child::File,
            "ev-file-service",
            "ev-file-service",
            "desktop,native-session",
            "m5-native-file",
            "FILE",
        ),
        (
            Child::Block,
            "ev-block-service",
            "ev-block-service",
            "native-driver,native-network",
            "m5-native-block",
            "BLOCK",
        ),
        (
            Child::App,
            "ev-native-hello",
            "ev-native-hello",
            if negative {
                "native-a,native-session,network-negative-probe"
            } else {
                "native-a,native-session"
            },
            "m5-native-app-a",
            "APP_A",
        ),
        (
            Child::Display,
            "ev-desktop",
            "ev-desktop",
            "compositor,native-session",
            "m5-native-display",
            "DISPLAY",
        ),
        (
            Child::NetDriver,
            "ev-net-driver",
            "ev-net-driver",
            "driver-service",
            "m6-net-driver",
            "NET_DRIVER",
        ),
        (
            Child::NetService,
            "ev-net-driver",
            "ev-net-service",
            "stack-executable",
            "m6-net-service",
            "NET_SERVICE",
        ),
    ] {
        let selected_feature = if document && child == Child::Shell {
            format!("{feature},document-workflow")
        } else {
            feature.to_owned()
        };
        let feature = selected_feature.as_str();
        let bytes = if document && child == Child::App {
            let (image, _) = crate::document_compatibility::load_legacy_a(root)?;
            let path = directory.join(format!("{stem}.elf"));
            fs::write(&path, &image).map_err(|e| e.to_string())?;
            retain(root, &path, artifacts)?;
            image
        } else {
            build_actor_bin(
                root,
                directory,
                toolchain,
                &tool,
                ActorBuild {
                    package,
                    feature,
                    name: stem,
                },
                binary,
                artifacts,
            )?
        };
        let (row, frames) = admit(&bytes, child)?;
        audit_child(root, directory, stem, artifacts)?;
        constant(
            &mut generated,
            &format!("M5_NATIVE_{name}_IMAGE"),
            &directory.join(format!("{stem}.elf")),
        )?;
        digest(&mut generated, &format!("M5_NATIVE_{name}_SHA"), row.image);
        if child == Child::App {
            app_a = Some(bytes);
        }
        measures.push(serde_json::json!({"child":format!("{child:?}"),"image":row.image,"descriptor":row.descriptor,"roles":row.roles,"limits":row.limits,"private_frames":frames}));
        images.push(row);
    }
    let b_image = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-native-hello",
            feature: if document {
                "native-b,document-workflow"
            } else {
                "native-b,native-session"
            },
            name: "m5-native-app-b",
        },
        artifacts,
    )?;
    let (b_row, b_frames) = admit(&b_image, Child::App)?;
    audit_child(root, directory, "m5-native-app-b", artifacts)?;
    let a_image = app_a.ok_or("V4 actual App A missing")?;
    let a = crate::native_package::network_hello(&a_image, input)?;
    if document && a.bytes != crate::document_compatibility::load_legacy_a(root)?.1 {
        return Err("qualified legacy bankA package reconstruction differs".into());
    }
    let b = if document {
        crate::native_package::document_network_hello(&b_image, input)?
    } else {
        crate::native_package::network_hello(&b_image, input)?
    };
    let packages = [a, b];
    let [a, b] = &packages;
    if a.descriptor != images[Child::App.index()].descriptor || b.descriptor != b_row.descriptor {
        return Err("V4 package differs from actual admitted App descriptor".into());
    }
    if a.app != b.app
        || a.package == b.package
        || a.executable == b.executable
        || a.build == b.build
    {
        return Err("V4 A/B must share AppId and have distinct actual content identities".into());
    }
    for (slot, p) in [("A", a), ("B", b)] {
        if cat::package_pages(p.bytes.len() as u64).is_none() {
            return Err("V4 package exceeds finite bank".into());
        }
        let path = directory.join(format!("m5-native-Hello-{slot}.zion"));
        fs::write(&path, &p.bytes).map_err(|e| e.to_string())?;
        retain(root, &path, artifacts)?;
        constant(&mut generated, &format!("M5_NATIVE_PACKAGE_{slot}"), &path)?;
    }
    constant(
        &mut generated,
        "M5_NATIVE_APP_B_IMAGE",
        &directory.join("m5-native-app-b.elf"),
    )?;
    digest(&mut generated, "M5_NATIVE_APP_B_SHA", b_row.image);
    let bad = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-desktop",
            feature: if document {
                "native-bad-shell,document-workflow"
            } else {
                "native-bad-shell,native-session"
            },
            name: "m5-native-bad-shell",
        },
        artifacts,
    )?;
    let (bad_shell, _) = admit(&bad, Child::Shell)?;
    audit_child(root, directory, "m5-native-bad-shell", artifacts)?;
    constant(
        &mut generated,
        "M5_NATIVE_BAD_SHELL_IMAGE",
        &directory.join("m5-native-bad-shell.elf"),
    )?;
    digest(&mut generated, "M5_NATIVE_BAD_SHELL_SHA", bad_shell.image);
    let root_image = build_actor(
        root,
        directory,
        toolchain,
        &tool,
        ActorBuild {
            package: "ev-root-supervisor",
            feature: if document {
                "native-network,document-workflow"
            } else if negative {
                "native-network-negative"
            } else if owner_ui {
                "native-owner-ui"
            } else {
                "native-network"
            },
            name: "m5-native-root",
        },
        artifacts,
    )?;
    let root_sha = Sha256::digest(&root_image).into();
    let make_base = |measurement| base::Description {
        root_image: root_sha,
        kernel_input: input,
        graph: measurement,
        app_id: a.app,
        package: a.package,
        app_build: a.build,
        provenance: base::Provenance::Zion,
        restart_attempts: ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        restart_window: ev_root_supervisor::desktop_plan::RESTART_WINDOW,
        images: core::array::from_fn(|i| base::Image {
            role: old::CHILDREN[i].image(),
            image: images[i].image,
            descriptor: images[i].descriptor,
            abi: images[i].abi,
            limits: images[i].limits,
            display_layout: i == 5,
            grants: cat::BASE_ROLE_COUNTS[i],
            roles: images[i].roles,
        }),
    };
    let encode = |base: &[u8], layout_measurement| {
        cat::encode(cat::Description {
            base,
            app_b: b_row,
            bad_shell,
            boot_mode: mode.boot_mode(),
            package_b: b.package,
            package_b_build: b.build,
            package_a_bytes: a.bytes.len() as u64,
            package_b_bytes: b.bytes.len() as u64,
            net_driver: images[6],
            net_service: images[7],
            device,
            network_policy: cat::NetworkPolicy {
                allowed_ipv4: reference.policy.allowed_ipv4,
                remote_port: reference.policy.remote_port,
                local_port: reference.policy.local_port,
                dns_name: &reference.policy.dns_name,
            },
            layout_measurement,
        })
        .map_err(|e| format!("V4 catalogue: {e:?}"))
    };
    let base_draft = cat::encode_base(make_base([1; 32])).map_err(|e| format!("V4 base: {e:?}"))?;
    let draft = encode(&base_draft, [1; 32])?;
    let parsed = cat::Catalogue::decode(&draft).map_err(|e| format!("V4 draft decode: {e:?}"))?;
    let base_hash = ev_root_supervisor::native_plan::network_base_graph_measurement(parsed.base());
    let base =
        cat::encode_base(make_base(base_hash)).map_err(|e| format!("V4 measured base: {e:?}"))?;
    let draft = encode(&base, [1; 32])?;
    let parsed = cat::Catalogue::decode(&draft).map_err(|e| format!("V4 measured draft: {e:?}"))?;
    let layout = ev_root_supervisor::native_plan::network_layout_measurement(&parsed);
    let catalogue = encode(&base, layout)?;
    let catalogue_sha = Sha256::digest(catalogue).into();
    let description = RootDescription::full_graph(
        root_v4::ROOT_LIMITS,
        ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        ev_root_supervisor::desktop_plan::RESTART_WINDOW,
        core::array::from_fn(|i| Identity {
            object: i as u64,
            lineage: i as u64,
        }),
    )
    .map_err(|e| format!("V4 Root source identities: {e:?}"))?
    .bind_catalogue(catalogue_sha);
    let encoded = ev_kernel::root_producer_v4::encode_current(&root_image, &description)
        .map_err(|e| format!("V4 Root encode: {e:?}"))?;
    let manifest =
        ev_kernel::root_manifest_v4::verify(encoded.bytes(), encoded.digest(), &root_image)
            .map_err(|e| format!("V4 Root verify: {e:?}"))?;
    let plan = ev_kernel::executable::Image::from_root_v4(&manifest)
        .map_err(|e| format!("V4 Root load: {e:?}"))?;
    if plan.required_frames() > ev_kernel::executable::ROOT_V4_MAX_PRIVATE_FRAMES {
        return Err(format!(
            "V4 Root private{}frames exceeds{}",
            plan.required_frames(),
            ev_kernel::executable::ROOT_V4_MAX_PRIVATE_FRAMES
        ));
    }
    super::native_graph::admit_root_stack(&plan)?;
    for page in (303..=367).chain(383..=447).chain(505..=509) {
        if plan.pages().any(|p| p.address == plan.base() + page * 4096) {
            return Err(format!("V4 Root LOAD overlaps reserved {page}"));
        }
    }
    let root_stack = directory.join("m5-native-root.stack.json");
    let root_log = directory.join("m5-native-root-stack.log");
    let mut audit = Command::new("python3");
    audit
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .args(["--userspace", "--stack-bytes", "32768"])
        .arg(directory.join("m5-native-root.elf"))
        .arg(&root_stack);
    build::logged(&mut audit, &root_log)?;
    retain(root, &root_stack, artifacts)?;
    retain(root, &root_log, artifacts)?;
    let catalogue_path = directory.join("m5-native-catalogue.bin");
    fs::write(&catalogue_path, catalogue).map_err(|e| e.to_string())?;
    retain(root, &catalogue_path, artifacts)?;
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
    let measurements = directory.join("m6-network-measurements.json");
    build::write_json(
        &measurements,
        &serde_json::json!({"schema":1,"kind":"source-built-v4-network-profile","execution_pass":false,"recipe_input":recipe_input,
        "root":{"image":root_sha,"manifest":encoded.digest(),"catalogue":catalogue_sha,"layout":layout,"limits":root_v4::ROOT_LIMITS,"image_pages":plan.pages().count(),"image_page_bound":root_v4::ROOT_MAX_IMAGE_PAGES,"private_owner_slots":root_v4::ROOT_MAX_PRIVATE_PAGES,"private_frames":plan.required_frames(),"private_frame_bound":ev_kernel::executable::ROOT_V4_MAX_PRIVATE_FRAMES,
        "dynamic_layout":root_v4::dynamic::layout_record(),"dynamic_external_frame_bound":root_v4::dynamic::EXTERNAL_FRAMES,
        "dynamic_code_owner_frame_bound":root_v4::dynamic::OWNERS*root_v4::dynamic::WINDOW_PAGES,
        "dynamic_capacity_scope":"Lazy separately charged owners under the unchanged actual Root/Boot ancestor quotas; initial LoadedImage bound excludes these frames. Simultaneous maxima are not a reservation or admission guarantee."},
        "children":measures,"app_b_frames":b_frames,"reference_sha256":build::hash_file(&reference_path)?,
        "downstream_equivalence_qualified":reference.downstream_equivalence_qualified,
        "scope":"Actual source-built descriptor/package admission only. Whole-Kernel linked stack, real8-actor capacity, NIC traffic, entropy and hardware retirement require separate execution evidence."}),
    )?;
    retain(root, &measurements, artifacts)?;
    fs::write(bundle, generated).map_err(|e| e.to_string())
}
