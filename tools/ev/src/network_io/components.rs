//! Read-only binding of the actual V4 source cohort; never a runtime receipt.
use crate::{
    build::{self, Manifest, Result},
    storage,
};
use ev_kernel::{
    capability::{Kind, Rights},
    executable::{Image, LayoutReservation},
    root_producer_v2::Identity,
    scheduler::Limits,
    service::{Role, ServiceImage},
};
use ev_userspace_contract::{
    Context as BootstrapContext,
    root_v4::{
        self,
        catalogue::Catalogue,
        graph::{self, Child},
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path},
};

pub(crate) struct Context {
    pub images: [String; 9],
    pub root_manifest: String,
    pub root_frames: u64,
    pub block_frames: u64,
    pub package_pages: [u64; 2],
    pub(crate) banks: Option<Banks>,
}
pub(crate) struct Banks {
    catalogue: Vec<u8>,
    context: BootstrapContext,
    packages: [Vec<u8>; 2],
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn source_digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("network source digest is not canonical".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
fn load(root: &Path, manifest: &Manifest, name: &str) -> Result<Vec<u8>> {
    let mut matches = manifest
        .supervisor
        .iter()
        .filter(|a| Path::new(&a.path).file_name().is_some_and(|n| n == name));
    let item = matches
        .next()
        .ok_or_else(|| format!("network source component missing: {name}"))?;
    if matches.next().is_some() {
        return Err("network source component basename duplicated".into());
    }
    let relative = Path::new(&item.path);
    if relative.is_absolute()
        || !relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        || relative.parent() != Path::new(&manifest.kernel.path).parent()
    {
        return Err("network component path/cohort differs".into());
    }
    let output = storage::directory_beneath(root, Path::new("build/m0"))?;
    let mut path = output.clone();
    for part in relative.components() {
        path.push(part);
        if fs::symlink_metadata(&path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("network component has symlink ancestry".into());
        }
    }
    let path = build::verify_artifact(&output, item)?;
    let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
        return Err("network source component extent/type".into());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if hex(&hash(&bytes)) != item.sha256 {
        return Err("network source component changed".into());
    }
    Ok(bytes)
}
fn stack(plan: &Image<'_>, pages: u64) -> Result<()> {
    for page in plan.pages() {
        let n = (page.address - plan.base()) / 4096;
        if [255, 256 + pages, 505, 506, 507, 508, 509, 510, 511].contains(&n)
            || (303..368).contains(&n)
            || (383..448).contains(&n)
        {
            return Err("network ELF overlaps private guard/window/bank".into());
        }
    }
    for n in 256..256 + pages {
        let page = plan
            .pages()
            .find(|p| p.address == plan.base() + n * 4096)
            .ok_or("network private stack page missing")?;
        let mut bytes = [0xff; 4096];
        page.copy_into(&mut bytes);
        if page.permission != ev_kernel::user::UserPermission::ReadWrite || bytes != [0; 4096] {
            return Err("network private stack not initialized RW/NX".into());
        }
    }
    Ok(())
}
fn admit(bytes: &[u8], child: Child, digest: [u8; 32], descriptor: [u8; 32]) -> Result<u64> {
    let roles = graph::grants(child)
        .enumerate()
        .map(|(i, g)| {
            Ok(Role {
                selector: i as u64 + 1,
                kind: match g.kind {
                    1 => Kind::Memory,
                    2 => Kind::Endpoint,
                    7 => Kind::IoPorts,
                    8 => Kind::Display,
                    _ => return Err("network child kind".to_owned()),
                },
                rights: Rights::from_bits(g.rights).ok_or("network child rights")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let [cpu, frames, processes, threads] = child.limits();
    let layout = if child == Child::Display {
        LayoutReservation::DisplayApertureV1
    } else {
        LayoutReservation::Legacy
    };
    let image = ServiceImage::verify_layout(
        bytes,
        digest,
        Limits::new(cpu, frames, processes, threads),
        &roles,
        layout,
    )
    .map_err(|e| format!("network actual {child:?} ELF: {e:?}"))?;
    if image.digest() != descriptor {
        return Err("network actual child descriptor differs".into());
    }
    let plan = image
        .plan()
        .map_err(|e| format!("network child plan: {e:?}"))?;
    stack(&plan, 4)?;
    Ok(plan.required_frames())
}
impl Context {
    pub(crate) fn packages(&self) -> Result<ev_root_supervisor::native_plan::Packages<'_>> {
        let banks = self
            .banks
            .as_ref()
            .ok_or("retained network creation context absent")?;
        ev_root_supervisor::native_plan::Packages::verify_network(
            &banks.catalogue,
            banks.context,
            &banks.packages[0],
            &banks.packages[1],
        )
        .map_err(|e| format!("retained network packages: {e:?}"))
    }
    pub(crate) fn retain(root: &Path, manifest: &Manifest, directory: &Path) -> Result<Self> {
        Self::retain_mode(
            root,
            manifest,
            directory,
            crate::network_mode::Mode::Standalone,
            false,
        )
    }
    pub(crate) fn retain_mode(
        root: &Path,
        manifest: &Manifest,
        directory: &Path,
        mode: crate::network_mode::Mode,
        owner_ui: bool,
    ) -> Result<Self> {
        let fixture = if owner_ui {
            mode.owner_fixture()
        } else {
            mode.fixture()
        };
        Self::retain_for(root, manifest, directory, mode, fixture)
    }
    pub(crate) fn retain_document_mode(
        root: &Path,
        manifest: &Manifest,
        directory: &Path,
        mode: crate::network_mode::Mode,
    ) -> Result<Self> {
        Self::retain_for(root, manifest, directory, mode, mode.document_fixture())
    }
    pub(crate) fn retain_negative(
        root: &Path,
        manifest: &Manifest,
        directory: &Path,
    ) -> Result<Self> {
        Self::retain_for(
            root,
            manifest,
            directory,
            crate::network_mode::Mode::Standalone,
            "m6-network-negative",
        )
    }
    fn retain_for(
        root: &Path,
        manifest: &Manifest,
        directory: &Path,
        mode: crate::network_mode::Mode,
        fixture: &str,
    ) -> Result<Self> {
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some(fixture) || manifest.supervisor.len() > 512 {
            return Err("network probe requires exact V4 fixture".into());
        }
        let document = fixture == mode.document_fixture();
        let source = source_digest(&manifest.source_sha256)?;
        let raw = load(root, manifest, "m5-native-catalogue.bin")?;
        let catalogue =
            Catalogue::decode(&raw).map_err(|e| format!("network actual catalogue: {e:?}"))?;
        if catalogue.base().kernel_input() != source
            || catalogue.boot_mode() != mode.boot_mode()
            || catalogue.base().app_id() != crate::native_package::HELLO_APP_ID
        {
            return Err("network catalogue source/mode/App identity".into());
        }
        let policy = catalogue.network_policy();
        if policy.allowed_ipv4 != [10, 0, 2, 2]
            || policy.remote_port != 8080
            || policy.local_port != 49152
            || policy.dns_name != "example.org"
        {
            return Err("network probe target differs from exact scoped fixture".into());
        }
        let root_image = load(root, manifest, "m5-native-root.elf")?;
        if hash(&root_image) != catalogue.base().root_image() {
            return Err("network actual Root image differs".into());
        }
        let description = ev_kernel::root_producer_v4::Description::full_graph(
            root_v4::ROOT_LIMITS,
            ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
            ev_root_supervisor::desktop_plan::RESTART_WINDOW,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .map_err(|e| format!("network Root sources: {e:?}"))?
        .bind_catalogue(hash(&raw));
        let encoded = ev_kernel::root_producer_v4::encode_current(&root_image, &description)
            .map_err(|e| format!("network Root manifest encoding: {e:?}"))?;
        let root_manifest = load(root, manifest, "m5-native-root.manifest.bin")?;
        if root_manifest != encoded.bytes() {
            return Err("network Root actual manifest differs from canonical sources".into());
        }
        let measured =
            ev_kernel::root_manifest_v4::verify(&root_manifest, hash(&root_manifest), &root_image)
                .map_err(|e| format!("network Root manifest admission: {e:?}"))?;
        let root_plan =
            Image::from_root_v4(&measured).map_err(|e| format!("network Root plan: {e:?}"))?;
        stack(&root_plan, 8)?;
        if root_plan.required_frames() > ev_kernel::executable::ROOT_V4_MAX_PRIVATE_FRAMES {
            return Err("network Root exceeds actual loader frame bound".into());
        }
        let context = BootstrapContext {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: root_v4::ROOT_LIMITS,
            manifest: hash(&root_manifest),
            authority: measured.manifest().expected_authority_digest(),
        };
        let a = load(root, manifest, "m5-native-Hello-A.zion")?;
        let b = load(root, manifest, "m5-native-Hello-B.zion")?;
        let packages =
            ev_root_supervisor::native_plan::Packages::verify_network(&raw, context, &a, &b)
                .map_err(|e| format!("network complete packages: {e:?}"))?;
        let directory = directory.join("network-components");
        fs::create_dir(&directory).map_err(|e| e.to_string())?;
        let mut retained = Vec::new();
        let mut save = |name: &str, bytes: &[u8]| -> Result<()> {
            storage::immutable_new(&directory.join(name), bytes)?;
            retained.push(json!({"name":name,"sha256":hex(&hash(bytes)),"bytes":bytes.len()}));
            Ok(())
        };
        for (name, bytes) in [
            ("m5-native-root.elf", root_image.as_slice()),
            ("m5-native-root.manifest.bin", root_manifest.as_slice()),
            ("m5-native-catalogue.bin", raw.as_slice()),
            ("m5-native-Hello-A.zion", a.as_slice()),
            ("m5-native-Hello-B.zion", b.as_slice()),
        ] {
            save(name, bytes)?;
        }
        let mut images = core::array::from_fn(|_| String::new());
        images[0] = hex(&hash(&root_image));
        let mut frames = BTreeMap::new();
        for (child, name) in [
            (Child::Shell, "m5-native-shell.elf"),
            (Child::Input, "m5-native-input.elf"),
            (Child::File, "m5-native-file.elf"),
            (Child::Block, "m5-native-block.elf"),
            (Child::App, "m5-native-app-a.elf"),
            (Child::Display, "m5-native-display.elf"),
            (Child::NetDriver, "m6-net-driver.elf"),
            (Child::NetService, "m6-net-service.elf"),
        ] {
            let image = if child.index() < 6 {
                let i = catalogue.base().images().nth(child.index()).unwrap();
                (i.image, i.descriptor)
            } else {
                let i = if child == Child::NetDriver {
                    catalogue.net_driver()
                } else {
                    catalogue.net_service()
                };
                (i.image, i.descriptor)
            };
            let bytes = load(root, manifest, name)?;
            let private = admit(&bytes, child, image.0, image.1)?;
            images[child.index() + 1] = hex(&hash(&bytes));
            frames.insert(child.index(), private);
            save(name, &bytes)?;
            if child == Child::App
                && (crate::native_package::network_hello(&bytes, source)?.bytes != a
                    || packages
                        .checked(ev_root_supervisor::native_plan::Slot::A)
                        .map_err(|e| format!("network A: {e:?}"))?
                        .executable()
                        .bytes
                        != bytes)
            {
                return Err("network A package/source image association".into());
            }
        }
        for (name, child, image) in [
            ("m5-native-app-b.elf", Child::App, catalogue.app_b()),
            (
                "m5-native-bad-shell.elf",
                Child::Shell,
                catalogue.bad_shell(),
            ),
        ] {
            let bytes = load(root, manifest, name)?;
            admit(&bytes, child, image.image, image.descriptor)?;
            save(name, &bytes)?;
            if child == Child::App
                && ((if document {
                    crate::native_package::document_network_hello(&bytes, source)?
                } else {
                    crate::native_package::network_hello(&bytes, source)?
                })
                .bytes
                    != b
                    || packages
                        .checked(ev_root_supervisor::native_plan::Slot::B)
                        .map_err(|e| format!("network B: {e:?}"))?
                        .executable()
                        .bytes
                        != bytes)
            {
                return Err("network B package/source image association".into());
            }
        }
        let result = Self {
            images,
            root_manifest: hex(&hash(&root_manifest)),
            root_frames: root_plan.required_frames(),
            block_frames: frames[&Child::Block.index()],
            package_pages: [a.len() as u64, b.len() as u64].map(|n| n.div_ceil(4096)),
            banks: Some(Banks {
                catalogue: raw,
                context,
                packages: [a, b],
            }),
        };
        storage::json_new(
            &directory.join("binding.json"),
            &json!({"schema":1,"scope":"Actual retained V4 source/component/manifest/package admission only; synthetic preflight Context IDs are not runtime facts, capabilities or entropy/UTC trust","source_sha256":manifest.source_sha256,"root_image":result.images[0],"root_manifest":result.root_manifest,"root_private_frames":result.root_frames,"child_private_frames":frames,"retained":retained,"startup_roles":root_v4::CURRENT_GRANTS,"catalogue_bytes":result.banks.as_ref().unwrap().catalogue.len()}),
        )?;
        Ok(result)
    }
}
