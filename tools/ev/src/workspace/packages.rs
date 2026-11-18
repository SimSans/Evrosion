//! Real self-contained Zion packages over measured M8 ELF bytes. No signing,
//! installation, generic permission support or dynamic update admission follows.
use super::{Options, SemanticDeclarations};
use ev_kernel::service::ServiceImage;
use ev_userspace_contract::file_v2;
use ev_userspace_contract::root_v5::{
    self as v5,
    catalogue::{PackageBank, PackageKind},
    graph::ImageSlot,
};
use ev_workspace_client::semantic;
use ev_zion::{
    AppId, Capability, CapabilityRequest, Contract, ContractSupport, Contracts, DataSchema,
    Package, Platform, Version,
    producer::{Resource, Spec},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
pub const UI_CONTRACT: &str = "ev.internal.workspace-ui";
pub const PLATFORM: u32 = 1;
pub struct Supported;
impl Contracts for Supported {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        // Producer declarations describe the actual new Editor implementation;
        // native Root still probes its real loaded Workspace independently.
        if name == file_v2::INTERFACE && major == file_v2::VERSION {
            return Some(ContractSupport {
                minor: file_v2::MINOR,
                features: file_v2::FEATURES,
            });
        }
        if name == semantic::INTERFACE && major == semantic::MAJOR {
            return Some(ContractSupport {
                minor: semantic::MINOR,
                features: semantic::FEATURES,
            });
        }
        matches!(
            (name, major),
            ("ev.internal.workspace", 1) | ("ev.internal.surface-present", 5) | (UI_CONTRACT, 1)
        )
        .then_some(ContractSupport {
            minor: 0,
            features: 0,
        })
    }
}
#[derive(Serialize)]
pub struct Built {
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub app: [u8; 16],
    pub package: [u8; 32],
    pub executable: [u8; 32],
    pub descriptor: [u8; 32],
    pub build: [u8; 32],
    pub version: [u32; 3],
    pub kind: String,
    pub semantic_source: Option<[u8; 32]>,
    pub supplied_software: Option<serde_json::Value>,
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn label(kind: PackageKind) -> (&'static str, &'static str, ImageSlot, &'static str) {
    match kind {
        PackageKind::Files => (
            "Files",
            "bin/files.elf",
            ImageSlot::Files,
            "evrosion.internal.application.files",
        ),
        PackageKind::Editor | PackageKind::EditorCandidate => (
            "Editor",
            "bin/editor.elf",
            ImageSlot::Editor,
            "evrosion.internal.application.editor",
        ),
        PackageKind::Inspector => (
            "Inspector",
            "bin/inspector.elf",
            ImageSlot::Inspector,
            "evrosion.internal.application.inspector",
        ),
    }
}
fn requirements(slot: ImageSlot, semantic_tree: bool) -> Vec<Contract<'static>> {
    let mut result = vec![
        Contract {
            name: UI_CONTRACT,
            major: 1,
            minimum_minor: 0,
            features: 0,
        },
        Contract {
            name: "ev.internal.surface-present",
            major: 5,
            minimum_minor: 0,
            features: 0,
        },
    ];
    if slot == ImageSlot::Files {
        result.push(Contract {
            name: "ev.internal.workspace",
            major: 1,
            minimum_minor: 0,
            features: 0,
        });
    } else if slot == ImageSlot::Editor {
        result.push(Contract {
            name: "ev.internal.file",
            major: 2,
            minimum_minor: file_v2::MINOR,
            features: file_v2::FEATURE_STAGED_VERIFY,
        });
    }
    if semantic_tree {
        result.push(Contract {
            name: semantic::INTERFACE,
            major: semantic::MAJOR,
            minimum_minor: semantic::MINOR,
            features: semantic::FEATURES,
        });
    }
    result.sort_by_key(|r| (r.name, r.major));
    result
}
pub fn make(
    kind: PackageKind,
    image: &[u8],
    ui_source: [u8; 32],
    semantic_source: Option<[u8; 32]>,
) -> Result<Built, String> {
    let (name, entry, slot, id) = label(kind);
    let executable = hash(image);
    let admitted = ServiceImage::verify_m8(image, executable, slot)
        .map_err(|e| format!("M8 {name} typed ELF admission:{e:?}"))?;
    let descriptor = admitted.digest();
    let mut app = [0; 16];
    app.copy_from_slice(&hash(id.as_bytes())[..16]);
    let requirements = requirements(slot, semantic_source.is_some());
    let mut capabilities = vec![
        CapabilityRequest {
            capability: Capability::OwnSurfacePresent,
            required: true,
        },
        CapabilityRequest {
            capability: Capability::FocusedInput,
            required: true,
        },
        CapabilityRequest {
            capability: Capability::Diagnostics,
            required: true,
        },
    ];
    if slot == ImageSlot::Editor {
        capabilities.insert(
            0,
            CapabilityRequest {
                capability: Capability::SelectedFileRead,
                required: false,
            },
        );
        capabilities.push(CapabilityRequest {
            capability: Capability::SelectedFileEdit,
            required: false,
        });
    }
    let version = Version {
        major: 0,
        minor: 4,
        patch: u32::from(kind == PackageKind::EditorCandidate),
    };
    let source = format!(
        "Internal M8 ELF {}",
        executable
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut resources = vec![
        Resource {
            path: "res/descriptor.sha256",
            bytes: &descriptor,
        },
        Resource {
            path: "res/producer-ui-source.sha256",
            bytes: &ui_source,
        },
    ];
    if let Some(digest) = semantic_source.as_ref() {
        resources.push(Resource {
            path: "res/producer-semantic-source.sha256",
            bytes: digest,
        });
    }
    resources.sort_by_key(|resource| resource.path);
    let encode = |build| {
        ev_zion::producer::build(
            &Spec {
                app: AppId::new(app).unwrap(),
                name,
                source: &source,
                publisher: None,
                version,
                build_id: build,
                platform: Platform {
                    minimum: PLATFORM,
                    target: PLATFORM,
                },
                abi: v5::child::abi(slot.representative()),
                data_schema: DataSchema {
                    current: 1,
                    oldest_readable: 1,
                },
                entrypoint: entry,
                contracts: &requirements,
                capabilities: &capabilities,
            },
            image,
            &resources,
        )
        .map_err(|e| format!("M8 {name} Zion encode:{e:?}"))
    };
    let draft = encode([1; 32])?;
    let mut h = Sha256::new();
    h.update(b"evrosion.workspace.package.content-build.v1\0");
    h.update(draft);
    let build = h.finalize().into();
    let bytes = encode(build)?;
    let parsed = Package::parse(&bytes).map_err(|e| format!("M8 {name} package readback:{e:?}"))?;
    parsed
        .check_requirements(PLATFORM, v5::child::abi(slot.representative()), &Supported)
        .map_err(|e| format!("M8 {name} requirements:{e:?}"))?;
    if parsed.executable().bytes != image
        || parsed.app().claimed_app.bytes() != app
        || parsed.app().build_id != build
        || parsed.app().version != version
        || parsed.resources().count() != resources.len()
        || parsed.app().contracts().collect::<Vec<_>>() != requirements
        || parsed.resources().any(|r| {
            resources
                .iter()
                .all(|expected| r.path != expected.path || r.bytes != expected.bytes)
        })
    {
        return Err("M8 Zion exact content readback differs".into());
    }
    let package = parsed.id().bytes();
    if package != hash(&bytes) {
        return Err("M8 package digest differs from actual bytes".into());
    }
    if bytes.len() as u64 > v5::resources::PACKAGE_MAX_BYTES {
        return Err("M8 package exceeds unchanged individual63-page limit".into());
    }
    Ok(Built {
        bytes,
        app,
        package,
        executable,
        descriptor,
        build,
        version: [version.major, version.minor, version.patch],
        kind: format!("{kind:?}"),
        semantic_source,
        supplied_software: None,
    })
}
fn supplied(
    kind: PackageKind,
    bytes: &[u8],
    image: &[u8],
    semantic_tree: bool,
) -> Result<Built, String> {
    if !matches!(kind, PackageKind::Editor | PackageKind::EditorCandidate) || semantic_tree {
        return Err("supplied FileApp6 packages currently require their exact public three-contract profile, without inferred A1 support".into());
    }
    if bytes.len() as u64 > v5::resources::PACKAGE_MAX_BYTES {
        return Err("supplied package exceeds unchanged individual63-page limit".into());
    }
    let mut software = super::apps::verify_bytes(bytes)?;
    let parsed = Package::parse(bytes).map_err(|e| format!("supplied external package:{e:?}"))?;
    if parsed.executable().bytes != image {
        return Err(
            "supplied external package executable differs from exact selected FileApp6 image"
                .into(),
        );
    }
    let app = parsed.app();
    let version = app.version;
    let descriptor = ServiceImage::verify_m8(image, hash(image), ImageSlot::Editor)
        .map_err(|e| format!("supplied FileApp6 shape:{e:?}"))?
        .digest();
    software["developer_source"] = app.developer_source.into();
    software["entrypoint"] = app.entrypoint.into();
    software["exact_supplied_bytes_preserved"] = true.into();
    Ok(Built {
        bytes: bytes.to_vec(),
        app: app.claimed_app.bytes(),
        package: parsed.id().bytes(),
        executable: hash(image),
        descriptor,
        build: app.build_id,
        version: [version.major, version.minor, version.patch],
        kind: format!("{kind:?}"),
        semantic_source: None,
        supplied_software: Some(software),
    })
}
pub fn align(value: usize) -> Result<usize, String> {
    value
        .checked_add(15)
        .map(|v| v & !15)
        .ok_or_else(|| "package placement overflow".into())
}
/// Preserve a standalone complete package independently of the four startup
/// packages. Availability, permission and installation remain later Root gates.
pub fn external_ingress(
    bytes: &[u8],
    packages: [v5::catalogue::Package; 4],
) -> Result<v5::catalogue::ExternalIngress, String> {
    use v5::catalogue::{ExternalIngress, IngressProvenance, Package, ingress_offset};
    if bytes.is_empty() || bytes.len() as u64 > v5::resources::PACKAGE_MAX_BYTES {
        return Err("external ingress exceeds unchanged package limit".into());
    }
    let parsed =
        ev_zion::Package::parse(bytes).map_err(|e| format!("external ingress Zion:{e:?}"))?;
    let app = parsed.app();
    let image = hash(parsed.executable().bytes);
    if parsed.id().bytes() != hash(bytes)
        || app.abi != v5::child::abi(ImageSlot::Editor.representative())
    {
        return Err("external ingress full hash or FileApp6 ABI differs".into());
    }
    ServiceImage::verify_m8(parsed.executable().bytes, image, ImageSlot::Editor)
        .map_err(|e| format!("external ingress FileApp6 descriptor:{e:?}"))?;
    let external = ExternalIngress {
        package: Package {
            app_id: app.claimed_app.bytes(),
            digest: parsed.id().bytes(),
            build: app.build_id,
            image,
            bytes: bytes.len() as u64,
            bank: PackageBank::Candidate,
            offset: ingress_offset(packages[PackageKind::EditorCandidate.index()])
                .map_err(|e| format!("external ingress tail:{e:?}"))?,
        },
        provenance: IngressProvenance::LocalOwnerDevelopment,
    };
    external
        .validate(packages)
        .map_err(|e| format!("external ingress bank/identity:{e:?}"))?;
    Ok(external)
}
pub fn placements(packages: &[Built; 4]) -> Result<[(u8, u32); 4], String> {
    let mut result = [(0, 0); 4];
    let mut current = 0;
    for i in 0..4 {
        if packages[i].bytes.len() as u64 > v5::resources::PACKAGE_MAX_BYTES {
            return Err("individual package exceeds its unchanged63-page limit".into());
        }
        let bank = if i == 3 {
            PackageBank::Candidate
        } else {
            PackageBank::Current
        };
        let offset = if i == 3 { 0 } else { align(current)? };
        let end = offset
            .checked_add(packages[i].bytes.len())
            .ok_or("package extent overflow")?;
        if end as u64 > bank.capacity_bytes() {
            return Err(format!("actual packages do not fit {bank:?} bank"));
        }
        result[i] = (
            u8::from(i == 3),
            offset.try_into().map_err(|_| "package offset overflow")?,
        );
        if i != 3 {
            current = end;
        }
    }
    Ok(result)
}
pub fn build_four_declared(
    images: [&[u8]; 4],
    ui: [u8; 32],
    declared: SemanticDeclarations,
    semantic_source: [u8; 32],
) -> Result<[Built; 4], String> {
    build_four_inputs(images, ui, declared, semantic_source, None)
}
pub fn build_four_inputs(
    images: [&[u8]; 4],
    ui: [u8; 32],
    declared: SemanticDeclarations,
    semantic_source: [u8; 32],
    supplied_pair: Option<[&[u8]; 2]>,
) -> Result<[Built; 4], String> {
    let kinds = [
        PackageKind::Files,
        PackageKind::Editor,
        PackageKind::Inspector,
        PackageKind::EditorCandidate,
    ];
    let declarations = declared.ordered();
    let mut built = Vec::with_capacity(4);
    for i in 0..4 {
        built.push(
            if let Some(pair) = supplied_pair.filter(|_| matches!(i, 1 | 3)) {
                supplied(
                    kinds[i],
                    pair[usize::from(i == 3)],
                    images[i],
                    declarations[i],
                )?
            } else {
                make(
                    kinds[i],
                    images[i],
                    ui,
                    declarations[i].then_some(semantic_source),
                )?
            },
        );
    }
    if supplied_pair.is_some() {
        let (a, b) = (&built[1], &built[3]);
        if a.app != b.app
            || a.app == built[0].app
            || a.app == built[2].app
            || a.package == b.package
            || a.executable == b.executable
            || a.build == b.build
            || b.version <= a.version
        {
            return Err("supplied external pair must preserve one distinct AppId with newer version, different actual ELF/package/build and exact FileApp6 joins".into());
        }
    }
    built
        .try_into()
        .map_err(|_| "closed package count differs".into())
}
/// Hash the exact handwritten A1 codec and operation source, not generated IDL.
pub fn semantic_source(root: &Path) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    h.update(b"evrosion.workspace.semantic-codec-source.v1\0");
    for relative in [
        "libs/workspace-client/src/semantic.rs",
        "libs/workspace-client/src/semantic/operation.rs",
    ] {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 512 * 1024 {
            return Err("semantic codec source must be bounded regular input".into());
        }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        h.update((relative.len() as u64).to_le_bytes());
        h.update(relative.as_bytes());
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    Ok(h.finalize().into())
}
pub fn write(directory: &Path, packages: &[Built; 4]) -> Result<[(u8, u32); 4], String> {
    // Preserve real encoded bytes and sizes even when bank placement refuses.
    // No location/admission claim follows from this independent encoding step.
    let mut encoded = Vec::new();
    for package in packages {
        let file = directory.join(format!("{}.zion", package.kind));
        super::bundle::write_new(&file, &package.bytes)?;
        encoded.push(
            serde_json::json!({"package":package,"actual_bytes":package.bytes.len(),"path":file}),
        );
    }
    super::bundle::write_json_new(
        &directory.join("package-sizes.json"),
        &serde_json::json!({"schema":1,"scope":"Actual encoded/readback-verified package bytes; no bank placement or runtime admission claim","packages":encoded}),
    )?;
    let placements = placements(packages)?;
    let mut rows = vec![];
    for (i, p) in packages.iter().enumerate() {
        let file = directory.join(format!("{}.zion", p.kind));
        rows.push(serde_json::json!({"package":p,"actual_bytes":p.bytes.len(),"path":file,"bank":placements[i].0,"offset":placements[i].1}));
    }
    let occupancy = [
        (0..3)
            .map(|i| placements[i].1 as usize + packages[i].bytes.len())
            .max()
            .unwrap(),
        packages[3].bytes.len(),
    ];
    super::bundle::write_json_new(
        &directory.join("packages.json"),
        &serde_json::json!({"schema":1,"status":"Internal unsigned actual packages; no generic installer or update qualification","candidate_same_executable":packages[1].executable==packages[3].executable,"individual_package_max_bytes":v5::resources::PACKAGE_MAX_BYTES,"bank_bytes":{"Current":PackageBank::Current.capacity_bytes(),"Candidate":PackageBank::Candidate.capacity_bytes()},"bank_pages":{"Current":PackageBank::Current.pages(),"Candidate":PackageBank::Candidate.pages()},"occupancy":occupancy,"packages":rows}),
    )?;
    Ok(placements)
}
pub fn command(options: &Options) -> Result<(), String> {
    let root = options.root.canonicalize().map_err(|e| e.to_string())?;
    let directory = super::bundle::new_output(options.output.as_ref().unwrap())?;
    let ui =
        hash(&fs::read(root.join("libs/workspace-client/src/ui.rs")).map_err(|e| e.to_string())?);
    let files = super::bundle::read_elf(options.files.as_ref().unwrap())?;
    let editor = super::bundle::read_elf(options.editor.as_ref().unwrap())?;
    let inspector = super::bundle::read_elf(options.inspector.as_ref().unwrap())?;
    let candidate = if let Some(p) = &options.editor_candidate {
        super::bundle::read_elf(p)?
    } else {
        editor.clone()
    };
    let packages = build_four_declared(
        [&files, &editor, &inspector, &candidate],
        ui,
        options.semantic_tree,
        semantic_source(&root)?,
    )?;
    write(&directory, &packages)?;
    println!(
        "M8 actual Zion packages: {}",
        directory.join("packages.json").display()
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ingress_fixture(app: [u8; 16], stack: bool) -> Vec<u8> {
        let mut image = vec![0; 8192];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2u16), (18, 62), (52, 64), (54, 56), (56, 2)] {
            image[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        for (at, value) in [(24, (1u64 << 39) + 4096), (32, 64)] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, (page, length)) in [(1u64, 1u64), (if stack { 480 } else { 2 }, 8)]
            .into_iter()
            .enumerate()
        {
            let at = 64 + index * 56;
            image[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            image[at + 4..at + 8]
                .copy_from_slice(&(if index == 0 { 5u32 } else { 6 }).to_le_bytes());
            for (offset, value) in [
                (8, if index == 0 { 4096 } else { 8192 }),
                (16, (1u64 << 39) + page * 4096),
                (32, u64::from(index == 0)),
                (40, length * 4096),
                (48, 4096),
            ] {
                image[at + offset..at + offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        image[4096] = 0xc3;
        ev_zion::producer::build(
            &Spec {
                app: AppId::new(app).unwrap(),
                name: "Ingress fixture",
                source: "test fixture",
                publisher: None,
                version: Version {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                build_id: [88; 32],
                platform: Platform {
                    minimum: 1,
                    target: 1,
                },
                abi: v5::child::abi(ImageSlot::Editor.representative()),
                data_schema: DataSchema {
                    current: 1,
                    oldest_readable: 1,
                },
                entrypoint: "bin/ingress.elf",
                contracts: &[],
                capabilities: &[],
            },
            &image,
            &[],
        )
        .unwrap()
    }
    #[test]
    fn full_standalone_ingress_keeps_candidate_and_requires_actual_zion_and_fileapp6() {
        let packages = core::array::from_fn(|index| v5::catalogue::Package {
            app_id: [index as u8 + 1; 16],
            digest: [index as u8 + 11; 32],
            build: [21; 32],
            image: [31; 32],
            bytes: 16,
            bank: if index == 3 {
                PackageBank::Candidate
            } else {
                PackageBank::Current
            },
            offset: if index == 3 { 0 } else { index as u32 * 16 },
        });
        let bytes = ingress_fixture([99; 16], true);
        let value = external_ingress(&bytes, packages).unwrap();
        assert_eq!(value.package.digest, hash(&bytes));
        assert_eq!(value.package.app_id, [99; 16]);
        assert_eq!(value.package.offset, 16);
        assert_eq!(value.package.bytes, bytes.len() as u64);
        assert!(external_ingress(&bytes[..bytes.len() - 1], packages).is_err());
        let mut bad = bytes.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(external_ingress(&bad, packages).is_err());
        assert!(external_ingress(&ingress_fixture(packages[3].app_id, true), packages).is_err());
        assert!(external_ingress(&ingress_fixture([99; 16], false), packages).is_err());
        let mut full = packages;
        full[3].bytes = PackageBank::Candidate.capacity_bytes();
        assert!(external_ingress(&bytes, full).is_err());
    }
    #[test]
    fn semantic_requirement_is_explicit_and_uses_the_actual_sdk_boundary() {
        let prior = requirements(ImageSlot::Editor, false);
        assert_eq!(prior.len(), 3);
        assert!(prior.iter().all(|r| r.name != semantic::INTERFACE));
        let current = requirements(ImageSlot::Editor, true);
        assert_eq!(current.len(), 4);
        let a1 = current
            .iter()
            .find(|r| r.name == semantic::INTERFACE)
            .unwrap();
        assert_eq!(
            (a1.major, a1.minimum_minor, a1.features),
            (semantic::MAJOR, semantic::MINOR, semantic::FEATURES)
        );
        assert_eq!(
            current
                .iter()
                .filter(|r| r.name != semantic::INTERFACE)
                .copied()
                .collect::<Vec<_>>(),
            prior
        );
        assert!(
            Supported
                .supported(semantic::INTERFACE, semantic::MAJOR + 1)
                .is_none()
        );
        assert!(Supported.supported("ev.semantic-tree", 1).is_none());
        let supported = Supported
            .supported(semantic::INTERFACE, semantic::MAJOR)
            .unwrap();
        assert_eq!(
            (supported.minor, supported.features),
            (semantic::MINOR, semantic::FEATURES)
        );
    }
    #[test]
    fn actual_new_editor_declares_staged_verify_and_old_support_cannot_satisfy_it() {
        let declarations = requirements(ImageSlot::Editor, false);
        let required = declarations
            .iter()
            .find(|r| r.name == file_v2::INTERFACE)
            .unwrap();
        assert_eq!(
            (required.major, required.minimum_minor, required.features),
            (2, 1, file_v2::FEATURE_STAGED_VERIFY)
        );
        assert!(
            !file_v2::Support {
                major: 2,
                minor: 0,
                features: 0
            }
            .supports(required.major, required.minimum_minor, required.features)
        );
        let support = Supported.supported(required.name, required.major).unwrap();
        assert!(
            file_v2::Support {
                major: required.major,
                minor: support.minor,
                features: support.features
            }
            .supports(required.major, required.minimum_minor, required.features)
        );
        assert!(
            requirements(ImageSlot::Files, false)
                .iter()
                .all(|r| r.name != file_v2::INTERFACE)
        );
    }
    #[test]
    fn current_and_candidate_banks_have_independent_limits_and_individual_bound() {
        // Geometry fixtures only; these bytes are not package/admission proofs.
        let fixture = |bytes| Built {
            bytes: vec![0; bytes],
            app: [1; 16],
            package: [2; 32],
            executable: [3; 32],
            descriptor: [4; 32],
            build: [5; 32],
            version: [0, 4, 0],
            kind: "geometry-only".into(),
            semantic_source: None,
            supplied_software: None,
        };
        let measured = [
            fixture(104770),
            fixture(118932),
            fixture(84386),
            fixture(118932),
        ];
        assert_eq!(
            placements(&measured).unwrap(),
            [(0, 0), (0, 104784), (0, 223728), (1, 0)]
        );
        assert_eq!(PackageBank::Current.pages(), 79);
        assert_eq!(PackageBank::Candidate.pages(), 63);
        let max = v5::resources::PACKAGE_MAX_BYTES as usize;
        let too_large_current_individual = [fixture(max + 1), fixture(1), fixture(1), fixture(1)];
        assert!(placements(&too_large_current_individual).is_err());
        let too_large_candidate = [fixture(1), fixture(1), fixture(1), fixture(max + 1)];
        assert!(placements(&too_large_candidate).is_err());
        let overflow_current = [
            fixture(max),
            fixture(PackageBank::Current.capacity_bytes() as usize - max + 16),
            fixture(1),
            fixture(1),
        ];
        assert!(placements(&overflow_current).is_err());
    }
}
