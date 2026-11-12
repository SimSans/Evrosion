//! Retained Native profile3 cohort. Exact names/full formats select artifacts;
//! the shared legacy EVGRAPH1 prefix alone never selects a Native catalogue.
use crate::{
    build::{self, Manifest, Result},
    storage,
};
use ev_kernel::{
    capability::{Kind, Rights},
    executable::LayoutReservation,
    root_producer_v2::{Description, Identity},
    scheduler::Limits,
    service::{Role, ServiceImage},
};
use ev_userspace_contract::{
    Context,
    root_v2::{
        self,
        catalogue::Provenance,
        graph::{self, CHILDREN, Child},
        native::{self, catalogue::Catalogue},
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path},
};
pub(crate) struct Components {
    pub(crate) record: Value,
    pub(crate) packages: [Vec<u8>; 2],
    pub(crate) catalogue: Vec<u8>,
    pub(crate) root_manifest: Vec<u8>,
}
impl Components {
    pub(crate) fn packages(&self) -> [&[u8]; 2] {
        [&self.packages[0], &self.packages[1]]
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn input(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Native build input is not canonical64hex".into());
    }
    let mut result = [0; 32];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(result)
}
fn required<'a>(source: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8]> {
    source
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Native retained source artifact missing: {name}"))
}
fn roles(child: Child) -> Result<Vec<Role>> {
    graph::grants(child)
        .iter()
        .enumerate()
        .map(|(i, g)| {
            Ok(Role {
                selector: (i + 1) as u64,
                kind: match g.kind {
                    1 => Kind::Memory,
                    2 => Kind::Endpoint,
                    7 => Kind::IoPorts,
                    8 => Kind::Display,
                    _ => return Err("Native child kind invalid".into()),
                },
                rights: Rights::from_bits(g.rights).ok_or("Native child rights invalid")?,
            })
        })
        .collect()
}
fn stack(plan: &ev_kernel::executable::Image<'_>, native_root: bool) -> Result<()> {
    let first = 256;
    let end = first
        + if native_root {
            native::ROOT_STACK_PAGES
        } else {
            4
        };
    for p in plan.pages() {
        let index = (p.address - plan.base()) / 4096;
        if [255, end, 507, 508, 509, 510, 511].contains(&index)
            || (303..368).contains(&index)
            || (383..448).contains(&index)
        {
            return Err("Native LOAD overlaps guarded bank/bootstrap/window".into());
        }
    }
    for index in first..end {
        let p = plan
            .pages()
            .find(|p| p.address == plan.base() + index * 4096)
            .ok_or("Native declared private stack page absent")?;
        let mut bytes = [0xff; 4096];
        p.copy_into(&mut bytes);
        if p.permission != ev_kernel::user::UserPermission::ReadWrite || bytes != [0; 4096] {
            return Err("Native stack is not initialized RW/NX".into());
        }
    }
    Ok(())
}
fn admit(bytes: &[u8], child: Child, expected: [u8; 32], descriptor: [u8; 32]) -> Result<Value> {
    if hash(bytes) != expected {
        return Err(format!("Native {child:?} ELF hash differs"));
    }
    let [cpu, frames, processes, threads] = root_v2::catalogue::CHILD_LIMITS;
    let layout = if child == Child::Display {
        LayoutReservation::DisplayApertureV1
    } else {
        LayoutReservation::Legacy
    };
    let image = ServiceImage::verify_layout(
        bytes,
        expected,
        Limits::new(cpu, frames, processes, threads),
        &roles(child)?,
        layout,
    )
    .map_err(|e| format!("Native retained descriptor: {e:?}"))?;
    if image.digest() != descriptor {
        return Err("Native descriptor/roles/limits/layout differ".into());
    }
    let plan = image
        .plan()
        .map_err(|e| format!("Native retained load plan: {e:?}"))?;
    stack(&plan, false)?;
    Ok(
        json!({"child":format!("{child:?}"),"image":expected,"descriptor":descriptor,"private_frames":plan.required_frames(),"stack_bytes":16384,"actual_admission_only":true}),
    )
}
fn validate(source: &BTreeMap<String, Vec<u8>>, build_input: [u8; 32]) -> Result<Value> {
    let cat = required(source, "m5-native-catalogue.bin")?;
    if cat.len() != native::catalogue::SIZE
        || native::CURRENT_GRANTS != 22
        || native::MANIFEST_CURRENT_BYTES != 912
    {
        return Err("Native full2560/catalogue912manifest/22source profile differs".into());
    }
    let catalogue = Catalogue::decode(cat).map_err(|e| format!("Native full catalogue: {e:?}"))?;
    let base = catalogue.base();
    if base.kernel_input() != build_input
        || base.app_id() != crate::native_package::HELLO_APP_ID
        || base.provenance() != Provenance::Zion
        || ev_root_supervisor::native_plan::layout_measurement(&catalogue)
            != catalogue.layout_measurement()
        || ev_root_supervisor::desktop_plan::graph_measurement(base) != base.graph_measurement()
    {
        return Err("Native source identity/layout/base graph differs".into());
    }
    if base.restart_attempts() != ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS
        || base.restart_window() != ev_root_supervisor::desktop_plan::RESTART_WINDOW
    {
        return Err("Native restart policy differs from measured source profile".into());
    }
    let root = required(source, "m5-native-root.elf")?;
    if hash(root) != base.root_image() {
        return Err("Native Root ELF differs from catalogue".into());
    }
    let description = Description::full_native_graph(
        ev_root_supervisor::desktop_plan::ROOT_LIMITS,
        base.restart_attempts(),
        base.restart_window(),
        core::array::from_fn(|i| Identity {
            object: i as u64,
            lineage: i as u64,
        }),
    )
    .map_err(|e| format!("Native explicit22sources: {e:?}"))?
    .bind_catalogue(hash(cat));
    let expected = ev_kernel::root_producer_v2::encode_native(root, &description)
        .map_err(|e| format!("Native canonical manifest: {e:?}"))?;
    let manifest = required(source, "m5-native-root.manifest.bin")?;
    if manifest != expected.bytes() {
        return Err("Native actual Root manifest/source identities differ".into());
    }
    let measured = ev_kernel::root_manifest_v2::verify(manifest, hash(manifest), root)
        .map_err(|e| format!("Native Root manifest: {e:?}"))?
        .native_profile()
        .map_err(|e| format!("Native Root profile: {e:?}"))?;
    let root_plan = ev_kernel::executable::Image::from_native_root(&measured)
        .map_err(|e| format!("Native Root load: {e:?}"))?;
    stack(&root_plan, true)?;
    if root_plan.required_frames() > ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES {
        return Err("Native Root exceeds its versioned loader private-frame bound".into());
    }
    let mut cohort = Vec::new();
    for (child, image) in CHILDREN.into_iter().zip(base.images()) {
        if image.role != child.image()
            || image.roles != ev_root_supervisor::desktop_plan::roles_measurement(child)
            || image.limits != root_v2::catalogue::CHILD_LIMITS
            || image.abi != ev_userspace_contract::ABI
            || image.display_layout != (child == Child::Display)
            || image.grants as usize != graph::grants(child).len()
        {
            return Err("Native declared child wiring differs from actual profile".into());
        }
        let name = match child {
            Child::Shell => "shell",
            Child::Input => "input",
            Child::File => "file",
            Child::Block => "block",
            Child::App => "app-a",
            Child::Display => "display",
        };
        cohort.push(admit(
            required(source, &format!("m5-native-{name}.elf"))?,
            child,
            image.image,
            image.descriptor,
        )?);
    }
    let app_b = catalogue.app_b();
    cohort.push(admit(
        required(source, "m5-native-app-b.elf")?,
        Child::App,
        app_b.image,
        app_b.descriptor,
    )?);
    let bad_shell = catalogue.bad_shell();
    cohort.push(admit(
        required(source, "m5-native-bad-shell.elf")?,
        Child::Shell,
        bad_shell.image,
        bad_shell.descriptor,
    )?);
    let a = required(source, "m5-native-Hello-A.zion")?;
    let b = required(source, "m5-native-Hello-B.zion")?;
    let context = Context {
        epoch: 1,
        incarnation: 1,
        process: 1,
        limits: ev_root_supervisor::desktop_plan::ROOT_LIMITS,
        manifest: hash(manifest),
        authority: measured.manifest().expected_authority_digest(),
    };
    let checked = ev_root_supervisor::native_plan::Packages::verify(cat, context, a, b)
        .map_err(|e| format!("Native complete package banks: {e:?}"))?;
    let mut packages = Vec::new();
    for (slot, name, bytes) in [
        (
            ev_root_supervisor::native_plan::Slot::A,
            "m5-native-app-a.elf",
            a,
        ),
        (
            ev_root_supervisor::native_plan::Slot::B,
            "m5-native-app-b.elf",
            b,
        ),
    ] {
        let actual = checked
            .checked(slot)
            .map_err(|e| format!("Native package resolution: {e:?}"))?;
        let built = crate::native_package::native_hello(required(source, name)?, build_input)?;
        if actual.executable().bytes != required(source, name)? || built.bytes != bytes {
            return Err(
                "Native package is not exact source-built self-contained App/cohort".into(),
            );
        }
        packages.push(json!({"slot":format!("{slot:?}"),"app":actual.app().claimed_app.bytes(),"package":actual.id().bytes(),"build":actual.app().build_id,"image":actual.executable().digest,"bytes":bytes.len(),"data_schema":actual.app().data_schema.current}));
    }
    if catalogue.package_a() == catalogue.package_b()
        || base.images().nth(Child::App.index()).unwrap().image == app_b.image
    {
        return Err("Native A/B must have distinct actual packages and ELFs".into());
    }
    Ok(
        json!({"schema":1,"profile":3,"catalogue_bytes":cat.len(),"manifest_bytes":manifest.len(),"source_roles":22,"build_input":build_input,"catalogue_sha256":hash(cat),"root_image":hash(root),"root_manifest":hash(manifest),"root_private_frames":root_plan.required_frames(),"cohort":cohort,"packages":packages,"scope":"retained full Native integrity/admission/source association only; no runtime or publisher-authentication receipt"}),
    )
}
pub(crate) fn retain(root: &Path, evidence: &Path, manifest: &Manifest) -> Result<Components> {
    if !matches!(
        manifest.fixture.as_deref(),
        Some("m5-native" | "m5-native-system" | "m5-native-recovery")
    ) || manifest.supervisor.len() > 512
    {
        return Err("Native collector requires exact bounded m5-native manifest".into());
    }
    let output = storage::directory_beneath(root, Path::new("build/m0"))?;
    let directory = evidence.join("components");
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let mut source = BTreeMap::new();
    let mut links = Vec::new();
    let mut total = 0usize;
    for (i, artifact) in manifest.supervisor.iter().enumerate() {
        let relative = Path::new(&artifact.path);
        if relative.is_absolute()
            || !relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
        {
            return Err("Native artifact path escapes output".into());
        }
        let mut checked = output.clone();
        for part in relative.components() {
            checked.push(part);
            let meta = fs::symlink_metadata(&checked).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err("Native artifact/supervisor parent is a symlink".into());
            }
        }
        let path = build::verify_artifact(&output, artifact)?;
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
            return Err("Native source component nonregular or oversized".into());
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        if format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256 {
            return Err("Native component changed after artifact preflight".into());
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("Native size overflow")?;
        if total > 256 * 1024 * 1024 {
            return Err("Native retained source set exceeds256MiB".into());
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("Native component name invalid")?
            .to_owned();
        if source.contains_key(&name) {
            return Err("Native duplicate artifact basename".into());
        }
        let retained = directory.join(format!("{i:03}-{name}"));
        storage::immutable_new(&retained, &bytes)?;
        links.push(json!({"build_artifact":artifact,"retained":retained.strip_prefix(evidence).map_err(|e|e.to_string())?,"sha256":hash(&bytes)}));
        source.insert(name, bytes);
    }
    let mut record = validate(&source, input(&manifest.source_sha256)?)?;
    let actual_mode = Catalogue::decode(required(&source, "m5-native-catalogue.bin")?)
        .map_err(|e| format!("Native mode catalogue: {e:?}"))?
        .boot_mode();
    let expected_mode = match manifest.fixture.as_deref() {
        Some("m5-native") => native::catalogue::BootMode::Standalone,
        Some("m5-native-system") => native::catalogue::BootMode::SystemManaged,
        Some("m5-native-recovery") => native::catalogue::BootMode::Recovery,
        _ => return Err("Native unknown mode".into()),
    };
    if actual_mode != expected_mode {
        return Err("Native selected fixture mode differs from retained actual catalogue".into());
    }
    record["mode"] = json!(format!("{actual_mode:?}"));
    record["retained_components"] = json!(links);
    storage::json_new(&evidence.join("component-binding.json"), &record)?;
    Ok(Components {
        record,
        packages: [
            required(&source, "m5-native-Hello-A.zion")?.to_vec(),
            required(&source, "m5-native-Hello-B.zion")?.to_vec(),
        ],
        catalogue: required(&source, "m5-native-catalogue.bin")?.to_vec(),
        root_manifest: required(&source, "m5-native-root.manifest.bin")?.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::root_v2::catalogue::{
        self as base, Description as BaseDescription, Image,
    };
    /// Host admission fixture only. No source actor execution or linked runtime
    /// stack bound is claimed by synthesizing this guarded-stack ELF fixture.
    fn image(label: u8) -> Vec<u8> {
        let mut bytes =
            include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf").to_vec();
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
        bytes[8192] = label;
        let program = 64 + 2 * 56;
        bytes[program..program + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[program + 4..program + 8].copy_from_slice(&6u32.to_le_bytes());
        for (offset, value) in [
            (8, 8192u64),
            (16, (1u64 << 39) + 0x100000),
            (24, 0),
            (32, 0),
            (40, 16384),
            (48, 4096),
        ] {
            bytes[program + offset..program + offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn only_native_root_uses_eight_stack_pages_and_guard264() {
        let check = |bytes: &[u8], root: bool| {
            let [cpu, frames, processes, threads] = base::CHILD_LIMITS;
            let roles = roles(Child::App).unwrap();
            let measured = ServiceImage::verify(
                bytes,
                hash(bytes),
                Limits::new(cpu, frames, processes, threads),
                &roles,
            )
            .unwrap();
            stack(&measured.plan().unwrap(), root)
        };
        let old = image(77);
        assert!(check(&old, false).is_ok());
        assert!(check(&old, true).is_err());
        let mut native = old;
        let offset = 64 + 2 * 56 + 40;
        native[offset..offset + 8].copy_from_slice(&native::ROOT_STACK_BYTES.to_le_bytes());
        assert!(check(&native, true).is_ok());
        assert!(check(&native, false).is_err());
    }
    fn fixture() -> (BTreeMap<String, Vec<u8>>, [u8; 32]) {
        let input = [9; 32];
        let mut source = BTreeMap::new();
        let mut images = Vec::new();
        for child in CHILDREN {
            let bytes = image(child.index() as u8 + 10);
            let layout = if child == Child::Display {
                LayoutReservation::DisplayApertureV1
            } else {
                LayoutReservation::Legacy
            };
            let [cpu, frames, processes, threads] = base::CHILD_LIMITS;
            let roles = roles(child).unwrap();
            let measured = ServiceImage::verify_layout(
                &bytes,
                hash(&bytes),
                Limits::new(cpu, frames, processes, threads),
                &roles,
                layout,
            )
            .unwrap();
            stack(&measured.plan().unwrap(), false).unwrap();
            images.push(Image {
                role: child.image(),
                image: hash(&bytes),
                descriptor: measured.digest(),
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                display_layout: child == Child::Display,
                grants: graph::grants(child).len() as u8,
                roles: ev_root_supervisor::desktop_plan::roles_measurement(child),
            });
            let stem = match child {
                Child::Shell => "shell",
                Child::Input => "input",
                Child::File => "file",
                Child::Block => "block",
                Child::App => "app-a",
                Child::Display => "display",
            };
            source.insert(format!("m5-native-{stem}.elf"), bytes);
        }
        let bytes = image(88);
        let [cpu, frames, processes, threads] = base::CHILD_LIMITS;
        let roles = roles(Child::App).unwrap();
        let measured = ServiceImage::verify(
            &bytes,
            hash(&bytes),
            Limits::new(cpu, frames, processes, threads),
            &roles,
        )
        .unwrap();
        let b_image = native::catalogue::AppImage {
            image: hash(&bytes),
            descriptor: measured.digest(),
            abi: ev_userspace_contract::ABI,
            limits: base::CHILD_LIMITS,
            roles: ev_root_supervisor::desktop_plan::roles_measurement(Child::App),
        };
        source.insert("m5-native-app-b.elf".into(), bytes);
        let bad_shell = image(89);
        let bad_roles = super::roles(Child::Shell).unwrap();
        let measured = ServiceImage::verify(
            &bad_shell,
            hash(&bad_shell),
            Limits::new(cpu, frames, processes, threads),
            &bad_roles,
        )
        .unwrap();
        let bad_shell_image = native::catalogue::AppImage {
            image: hash(&bad_shell),
            descriptor: measured.digest(),
            abi: ev_userspace_contract::ABI,
            limits: base::CHILD_LIMITS,
            roles: ev_root_supervisor::desktop_plan::roles_measurement(Child::Shell),
        };
        source.insert("m5-native-bad-shell.elf".into(), bad_shell);
        let mut root_image = image(99);
        let stack_size = 64 + 2 * 56 + 40;
        root_image[stack_size..stack_size + 8]
            .copy_from_slice(&native::ROOT_STACK_BYTES.to_le_bytes());
        source.insert("m5-native-root.elf".into(), root_image);
        let a = crate::native_package::native_hello(
            required(&source, "m5-native-app-a.elf").unwrap(),
            input,
        )
        .unwrap();
        let b = crate::native_package::native_hello(
            required(&source, "m5-native-app-b.elf").unwrap(),
            input,
        )
        .unwrap();
        let images: [Image; 6] = images.try_into().ok().unwrap();
        let make = |graph| BaseDescription {
            root_image: hash(required(&source, "m5-native-root.elf").unwrap()),
            kernel_input: input,
            graph,
            app_id: a.app,
            package: a.package,
            app_build: a.build,
            provenance: Provenance::Zion,
            restart_attempts: ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
            restart_window: ev_root_supervisor::desktop_plan::RESTART_WINDOW,
            images,
        };
        let initial = base::encode(make([0; 32])).unwrap();
        let graph = ev_root_supervisor::desktop_plan::graph_measurement(
            &base::Catalogue::decode(&initial).unwrap(),
        );
        let base = base::encode(make(graph)).unwrap();
        let make = |layout_measurement| native::catalogue::Description {
            base: &base,
            app_b: b_image,
            bad_shell: bad_shell_image,
            boot_mode: native::catalogue::BootMode::Standalone,
            package_b: b.package,
            package_b_build: b.build,
            package_a_bytes: a.bytes.len() as u64,
            package_b_bytes: b.bytes.len() as u64,
            layout_measurement,
        };
        let first = native::catalogue::encode(make([1; 32])).unwrap();
        let layout = ev_root_supervisor::native_plan::layout_measurement(
            &Catalogue::decode(&first).unwrap(),
        );
        let catalogue = native::catalogue::encode(make(layout)).unwrap();
        let description = Description::full_native_graph(
            ev_root_supervisor::desktop_plan::ROOT_LIMITS,
            ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
            ev_root_supervisor::desktop_plan::RESTART_WINDOW,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap()
        .bind_catalogue(hash(&catalogue));
        let encoded = ev_kernel::root_producer_v2::encode_native(
            required(&source, "m5-native-root.elf").unwrap(),
            &description,
        )
        .unwrap();
        source.insert(
            "m5-native-root.manifest.bin".into(),
            encoded.bytes().to_vec(),
        );
        source.insert("m5-native-catalogue.bin".into(), catalogue.to_vec());
        source.insert("m5-native-Hello-A.zion".into(), a.bytes);
        source.insert("m5-native-Hello-B.zion".into(), b.bytes);
        (source, input)
    }
    #[test]
    fn exact_native_catalogue_cohort_and_actual_package_bytes_are_independently_admitted() {
        let (mut source, input) = fixture();
        let actual = validate(&source, input).unwrap();
        assert_eq!(actual["profile"], 3);
        assert_eq!(actual["catalogue_bytes"], 2560);
        assert_eq!(actual["manifest_bytes"], 912);
        assert_eq!(actual["source_roles"], 22);
        assert_eq!(actual["cohort"].as_array().unwrap().len(), 8);
        let legacy = source["m5-native-catalogue.bin"][..base::SIZE].to_vec();
        source.insert("unrelated-legacy-catalogue.bin".into(), legacy);
        assert!(
            validate(&source, input).is_ok(),
            "an unrelated EVGRAPH1 prefix must not select or confuse the exact Native catalogue"
        );
    }
    #[test]
    fn altered_source_input_image_package_manifest_or_ambiguous_names_cannot_pass() {
        let (source, input) = fixture();
        assert!(validate(&source, [8; 32]).is_err());
        for name in [
            "m5-native-root.elf",
            "m5-native-app-a.elf",
            "m5-native-app-b.elf",
            "m5-native-bad-shell.elf",
            "m5-native-Hello-A.zion",
            "m5-native-Hello-B.zion",
            "m5-native-root.manifest.bin",
            "m5-native-catalogue.bin",
        ] {
            let mut bad = source.clone();
            let bytes = bad.get_mut(name).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            assert!(
                validate(&bad, input).is_err(),
                "altered exact source {name}"
            );
        }
        let mut bad = source.clone();
        let native = bad.remove("m5-native-catalogue.bin").unwrap();
        bad.insert("renamed-with-valid-EVGRAPH1-prefix.bin".into(), native);
        assert!(validate(&bad, input).is_err());
        let mut bad = source.clone();
        bad.get_mut("m5-native-catalogue.bin")
            .unwrap()
            .truncate(base::SIZE);
        assert!(validate(&bad, input).is_err());
        let mut bad = source.clone();
        let a = bad["m5-native-Hello-A.zion"].clone();
        bad.insert("m5-native-Hello-B.zion".into(), a);
        assert!(validate(&bad, input).is_err());
    }
}
