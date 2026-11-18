//! Source-built native development package, not a privileged installer. Actual
//! Root launch still resolves the measured descriptor and narrowly grants each
//! role. Package declarations/digests do not grant namespace or file authority.
use ev_kernel::{
    capability::{Kind, Rights},
    scheduler::Limits,
    service::{Role, ServiceImage},
};
use ev_zion::{
    AppId, Capability, CapabilityRequest, Contract, ContractSupport, Contracts, DataSchema,
    Package, Platform, Version,
    producer::{Resource, Spec},
};
use sha2::{Digest, Sha256};

pub const HELLO_APP_ID: [u8; 16] = ev_native_hello::APP_ID;
pub const PLATFORM_LEVEL: u32 = 1;
pub const WELCOME: &[u8] = b"Hello from Evrosion.\n";
const REQUIREMENTS: [Contract<'static>; 3] = [
    Contract {
        name: "ev.internal.file",
        major: 1,
        minimum_minor: 0,
        features: 0,
    },
    Contract {
        name: "ev.internal.focused-input",
        major: 1,
        minimum_minor: 0,
        features: 0,
    },
    Contract {
        name: "ev.internal.surface-present",
        major: 1,
        minimum_minor: 0,
        features: 0,
    },
];
const REQUESTS: [CapabilityRequest; 4] = [
    CapabilityRequest {
        capability: Capability::SelectedFileRead,
        required: false,
    },
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
pub struct NativeContracts;
impl Contracts for NativeContracts {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        (major == 1 && REQUIREMENTS.iter().any(|r| r.name == name)).then_some(ContractSupport {
            minor: 0,
            features: 0,
        })
    }
}
/// Native lifecycle clients additionally declare private app data. These
/// declarations still grant no endpoint, disk address or policy epoch.
pub struct NativePlatformContracts;
impl Contracts for NativePlatformContracts {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        NativeContracts.supported(name, major).or_else(|| {
            (matches!(name, "ev.app.private-data" | "ev.app.session-note") && major == 1).then_some(
                ContractSupport {
                    minor: 0,
                    features: 0,
                },
            )
        })
    }
}
const NATIVE_REQUIREMENTS: [Contract<'static>; 4] = [
    Contract {
        name: "ev.app.private-data",
        major: 1,
        minimum_minor: 0,
        features: 0,
    },
    REQUIREMENTS[0],
    REQUIREMENTS[1],
    REQUIREMENTS[2],
];
const SESSION_REQUIREMENTS: [Contract<'static>; 5] = [
    NATIVE_REQUIREMENTS[0],
    Contract {
        name: "ev.app.session-note",
        major: 1,
        minimum_minor: 0,
        features: 0,
    },
    NATIVE_REQUIREMENTS[1],
    NATIVE_REQUIREMENTS[2],
    NATIVE_REQUIREMENTS[3],
];
const NATIVE_REQUESTS: [CapabilityRequest; 5] = [
    REQUESTS[0],
    CapabilityRequest {
        capability: Capability::AppPrivateData,
        required: true,
    },
    REQUESTS[1],
    REQUESTS[2],
    REQUESTS[3],
];
pub struct BuiltPackage {
    pub bytes: Vec<u8>,
    pub app: [u8; 16],
    pub package: [u8; 32],
    pub executable: [u8; 32],
    pub descriptor: [u8; 32],
    pub build: [u8; 32],
}
pub fn hello_roles() -> [Role; 6] {
    let shape = [
        (Kind::Memory, 7),
        (Kind::Endpoint, 8),
        (Kind::Endpoint, 8),
        (Kind::Endpoint, 272),
        (Kind::Memory, 7),
        (Kind::Endpoint, 272),
    ];
    core::array::from_fn(|i| Role {
        selector: i as u64 + 1,
        kind: shape[i].0,
        rights: Rights::from_bits(shape[i].1).unwrap(),
    })
}
pub fn network_hello_roles() -> [Role; 7] {
    let old = hello_roles();
    core::array::from_fn(|i| {
        if i < old.len() {
            old[i]
        } else {
            Role {
                selector: 7,
                kind: Kind::Memory,
                rights: Rights::from_bits(7).unwrap(),
            }
        }
    })
}
/// Producer checks the same actual ELF/ABI/role/stack admission as this graph's
/// App. It then re-parses its self-contained package and checks requirements.
/// The output never installs, activates, runs code or grants a selected File.
pub fn hello(image: &[u8], build: [u8; 32]) -> Result<BuiltPackage, String> {
    package(image, build, &REQUIREMENTS, &REQUESTS, &NativeContracts)
}
/// Same AppId/schema for A/B. App build identity binds its actual executable,
/// canonical metadata and resources, independently of unrelated OS/docs input.
/// The caller retains that complete source provenance in the outer catalogue.
pub fn native_hello(image: &[u8], source: [u8; 32]) -> Result<BuiltPackage, String> {
    native_hello_profile(image, source, false)
}
pub fn session_hello(image: &[u8], source: [u8; 32]) -> Result<BuiltPackage, String> {
    native_hello_profile(image, source, true)
}
/// V4's actual descriptor includes its distinct, explicitly delegated Note
/// MemoryObject. The package requests no additional ambient capabilities.
/// Explicit M7 producer; declaration is not a selected-file grant.
pub fn document_hello(image: &[u8], source: [u8; 32]) -> Result<BuiltPackage, String> {
    document_profile(
        image,
        source,
        &hello_roles(),
        Version {
            major: 0,
            minor: 3,
            patch: 0,
        },
        "Evrosion native Documents",
    )
}
pub fn document_network_hello(image: &[u8], source: [u8; 32]) -> Result<BuiltPackage, String> {
    document_profile(
        image,
        source,
        &network_hello_roles(),
        Version {
            major: 0,
            minor: 3,
            patch: 0,
        },
        "Evrosion native Documents",
    )
}
pub fn downloaded_document_hello(
    image: &[u8],
    source: [u8; 32],
    variant: Downloaded,
) -> Result<BuiltPackage, String> {
    let label = if variant == Downloaded::B { "B" } else { "C" };
    let provenance = format!(
        "Evrosion DEV {label} {}",
        source
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    document_profile(
        image,
        source,
        &network_hello_roles(),
        Version {
            major: 0,
            minor: 3,
            patch: if variant == Downloaded::B { 1 } else { 2 },
        },
        &provenance,
    )
}
fn document_profile(
    image: &[u8],
    source: [u8; 32],
    roles: &[Role],
    version: Version,
    provenance: &str,
) -> Result<BuiltPackage, String> {
    if source == [0; 32] {
        return Err("document package requires source provenance".into());
    }
    struct DocumentContracts;
    impl Contracts for DocumentContracts {
        fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
            if major == 1
                && matches!(
                    name,
                    "ev.app.document" | "ev.ui.document" | "ev.test.document"
                )
            {
                return Some(ContractSupport {
                    minor: 0,
                    features: 0,
                });
            }
            if major == 1 && name == "ev.internal.focused-input" {
                return Some(ContractSupport {
                    minor: 1,
                    features: 0,
                });
            }
            NativePlatformContracts.supported(name, major)
        }
    }
    let requirements = [
        Contract {
            name: "ev.app.document",
            major: 1,
            minimum_minor: 0,
            features: 0,
        },
        SESSION_REQUIREMENTS[0],
        SESSION_REQUIREMENTS[1],
        SESSION_REQUIREMENTS[2],
        Contract {
            minimum_minor: 1,
            ..SESSION_REQUIREMENTS[3]
        },
        SESSION_REQUIREMENTS[4],
        Contract {
            name: "ev.test.document",
            major: 1,
            minimum_minor: 0,
            features: 0,
        },
        Contract {
            name: "ev.ui.document",
            major: 1,
            minimum_minor: 0,
            features: 0,
        },
    ];
    let requests = [
        NATIVE_REQUESTS[0],
        NATIVE_REQUESTS[1],
        NATIVE_REQUESTS[2],
        NATIVE_REQUESTS[3],
        NATIVE_REQUESTS[4],
        CapabilityRequest {
            capability: Capability::SelectedFileEdit,
            required: false,
        },
    ];
    let make = |build| {
        package_with_profile(
            image,
            build,
            &requirements,
            &requests,
            &DocumentContracts,
            roles,
            PackageProfile {
                version,
                source: provenance,
            },
        )
    };
    let draft = make([1; 32])?;
    let mut hash = Sha256::new();
    hash.update(b"evrosion.native.document.content-build.v1\0");
    hash.update(&draft.bytes);
    make(hash.finalize().into())
}
pub fn network_hello(image: &[u8], source: [u8; 32]) -> Result<BuiltPackage, String> {
    native_hello_with_roles(image, source, true, &network_hello_roles())
}
/// Host-only download artifacts. These retain the same AppId, scalar and Note
/// contracts/schema, but have distinct versions and exact source provenance.
/// No caller of this builder installs a Kernel image bank or grants authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Downloaded {
    B,
    C,
}
pub fn downloaded_hello(
    image: &[u8],
    source: [u8; 32],
    variant: Downloaded,
) -> Result<BuiltPackage, String> {
    if source == [0; 32] {
        return Err("download package requires exact source provenance".into());
    }
    let label = if variant == Downloaded::B { "B" } else { "C" };
    let source = format!(
        "Evrosion DEV {label} {}",
        source
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let version = Version {
        major: 0,
        minor: 2,
        patch: if variant == Downloaded::B { 1 } else { 2 },
    };
    let make = |build| {
        package_with_profile(
            image,
            build,
            &SESSION_REQUIREMENTS,
            &NATIVE_REQUESTS,
            &NativePlatformContracts,
            &network_hello_roles(),
            PackageProfile {
                version,
                source: &source,
            },
        )
    };
    let draft = make([1; 32])?;
    let mut hash = Sha256::new();
    hash.update(b"evrosion.development.downloaded-hello.content-build.v1\0");
    hash.update(&draft.bytes);
    make(hash.finalize().into())
}
fn native_hello_profile(
    image: &[u8],
    source: [u8; 32],
    session: bool,
) -> Result<BuiltPackage, String> {
    native_hello_with_roles(image, source, session, &hello_roles())
}
fn native_hello_with_roles(
    image: &[u8],
    source: [u8; 32],
    session: bool,
    roles: &[Role],
) -> Result<BuiltPackage, String> {
    if source == [0; 32] {
        return Err("Native package requires retained source provenance".into());
    }
    // Use one canonical nonzero build placeholder to include every app-specific
    // field in the build transcript without a self-referential digest.
    let requirements: &[Contract<'_>] = if session {
        &SESSION_REQUIREMENTS
    } else {
        &NATIVE_REQUIREMENTS
    };
    let draft = package_with_roles(
        image,
        [1; 32],
        requirements,
        &NATIVE_REQUESTS,
        &NativePlatformContracts,
        roles,
    )?;
    let mut hash = Sha256::new();
    hash.update(b"evrosion.native.hello.content-build.v2\0");
    hash.update(&draft.bytes);
    package_with_roles(
        image,
        hash.finalize().into(),
        requirements,
        &NATIVE_REQUESTS,
        &NativePlatformContracts,
        roles,
    )
}
fn package(
    image: &[u8],
    build: [u8; 32],
    requirements: &[Contract<'_>],
    requests: &[CapabilityRequest],
    contracts: &impl Contracts,
) -> Result<BuiltPackage, String> {
    package_with_roles(
        image,
        build,
        requirements,
        requests,
        contracts,
        &hello_roles(),
    )
}
fn package_with_roles(
    image: &[u8],
    build: [u8; 32],
    requirements: &[Contract<'_>],
    requests: &[CapabilityRequest],
    contracts: &impl Contracts,
    roles: &[Role],
) -> Result<BuiltPackage, String> {
    package_with_profile(
        image,
        build,
        requirements,
        requests,
        contracts,
        roles,
        PackageProfile {
            version: Version {
                major: 0,
                minor: 1,
                patch: 0,
            },
            source: "Evrosion repository development source",
        },
    )
}
struct PackageProfile<'a> {
    version: Version,
    source: &'a str,
}
#[allow(clippy::too_many_arguments)] // Existing closed package shape plus explicit edition metadata.
fn package_with_profile(
    image: &[u8],
    build: [u8; 32],
    requirements: &[Contract<'_>],
    requests: &[CapabilityRequest],
    contracts: &impl Contracts,
    roles: &[Role],
    profile: PackageProfile<'_>,
) -> Result<BuiltPackage, String> {
    let executable = Sha256::digest(image).into();
    let measured = ServiceImage::verify(
        image,
        executable,
        {
            let [cpu, frames, processes, threads] =
                ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS;
            Limits::new(cpu, frames, processes, threads)
        },
        roles,
    )
    .map_err(|e| format!("native Hello executable admission: {e:?}"))?;
    let descriptor = measured.digest();
    let spec = Spec {
        app: AppId::new(HELLO_APP_ID).unwrap(),
        name: "Evrosion Hello",
        source: profile.source,
        publisher: None,
        version: profile.version,
        build_id: build,
        platform: Platform {
            minimum: PLATFORM_LEVEL,
            target: PLATFORM_LEVEL,
        },
        abi: ev_userspace_contract::ABI,
        data_schema: DataSchema {
            current: 1,
            oldest_readable: 1,
        },
        entrypoint: "bin/hello.elf",
        contracts: requirements,
        capabilities: requests,
    };
    let bytes = ev_zion::producer::build(
        &spec,
        image,
        &[Resource {
            path: "res/welcome.txt",
            bytes: WELCOME,
        }],
    )
    .map_err(|e| format!("native Hello package: {e:?}"))?;
    let parsed =
        Package::parse(&bytes).map_err(|e| format!("native Hello package readback: {e:?}"))?;
    parsed
        .check_requirements(PLATFORM_LEVEL, ev_userspace_contract::ABI, contracts)
        .map_err(|e| format!("native Hello requirements: {e:?}"))?;
    if parsed.app().claimed_app.bytes() != HELLO_APP_ID
        || parsed.executable().bytes != image
        || parsed.resources().count() != 1
        || parsed.resources().next().unwrap().bytes != WELCOME
    {
        return Err("native Hello package readback differs".into());
    }
    let package = parsed.id().bytes();
    Ok(BuiltPackage {
        bytes,
        app: HELLO_APP_ID,
        package,
        executable,
        descriptor,
        build,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn downloaded_document_metadata_requires_its_closed_profile_and_new_input_minor() {
        use ev_root_supervisor::native_package_profile::{KnownContracts, downloaded};
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let legacy = downloaded_hello(elf, [9; 32], Downloaded::B).unwrap();
        assert!(downloaded(Package::parse(&legacy.bytes).unwrap().app()));
        for edition in [Downloaded::B, Downloaded::C] {
            let built = downloaded_document_hello(elf, [9; 32], edition).unwrap();
            let parsed = Package::parse(&built.bytes).unwrap();
            let app = parsed.app();
            assert!(downloaded(app));
            assert!(
                parsed
                    .check_requirements(1, ev_userspace_contract::ABI, &KnownContracts)
                    .is_ok()
            );
            assert!(
                parsed
                    .check_requirements(1, ev_userspace_contract::ABI, &NativePlatformContracts)
                    .is_err()
            );
            assert_eq!(app.claimed_app.bytes(), HELLO_APP_ID);
            assert_eq!(app.data_schema.current, 1);
            assert_eq!(app.data_schema.oldest_readable, 1);
            assert_eq!(app.version.minor, 3);
            assert_ne!(built.package, legacy.package);
            for variant in 0..4 {
                let mut requirements: Vec<_> = app.contracts().collect();
                let mut requests: Vec<_> = app.capability_requests().collect();
                let mut version = app.version;
                match variant {
                    0 => {
                        requirements
                            .iter_mut()
                            .find(|c| c.name == "ev.internal.focused-input")
                            .unwrap()
                            .minimum_minor = 0
                    }
                    1 => requirements.retain(|c| c.name != "ev.ui.document"),
                    2 => requests.last_mut().unwrap().required = true,
                    _ => version.minor = 2,
                }
                let spec = Spec {
                    app: app.claimed_app,
                    name: app.display_name,
                    source: app.developer_source,
                    publisher: None,
                    version,
                    build_id: app.build_id,
                    platform: app.platform,
                    abi: app.abi,
                    data_schema: app.data_schema,
                    entrypoint: app.entrypoint,
                    contracts: &requirements,
                    capabilities: &requests,
                };
                let altered = ev_zion::producer::build(
                    &spec,
                    elf,
                    &[Resource {
                        path: "res/welcome.txt",
                        bytes: WELCOME,
                    }],
                )
                .unwrap();
                assert!(
                    !downloaded(Package::parse(&altered).unwrap().app()),
                    "altered metadata {variant}"
                );
            }
        }
    }
    #[test]
    fn downloaded_editions_bind_source_version_without_widening_app_or_schema() {
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let old = network_hello(elf, [9; 32]).unwrap();
        let b = downloaded_hello(elf, [9; 32], Downloaded::B).unwrap();
        let c = downloaded_hello(elf, [9; 32], Downloaded::C).unwrap();
        let changed = downloaded_hello(elf, [10; 32], Downloaded::B).unwrap();
        assert!(downloaded_hello(elf, [0; 32], Downloaded::B).is_err());
        assert_eq!((old.app, b.app), (b.app, c.app));
        assert_eq!(old.descriptor, b.descriptor);
        assert_eq!(b.descriptor, c.descriptor);
        assert_ne!(old.package, b.package);
        assert_ne!(b.package, c.package);
        assert_ne!(b.package, changed.package);
        assert_ne!(b.build, changed.build);
        let b = Package::parse(&b.bytes).unwrap();
        let c = Package::parse(&c.bytes).unwrap();
        assert_eq!((b.app().version.minor, b.app().version.patch), (2, 1));
        assert_eq!((c.app().version.minor, c.app().version.patch), (2, 2));
        assert_eq!(
            (
                b.app().data_schema.current,
                b.app().data_schema.oldest_readable
            ),
            (1, 1)
        );
        assert_eq!(b.app().contracts().count(), 5);
        assert_eq!(b.app().capability_requests().count(), 5);
        assert!(b.app().developer_source.starts_with("Evrosion DEV B "));
        assert_eq!(b.executable().bytes, elf);
    }
    #[test]
    fn v4_descriptor_adds_only_the_separate_note_role() {
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let prototype = session_hello(elf, [9; 32]).unwrap();
        let dedicated = network_hello(elf, [9; 32]).unwrap();
        assert_eq!(prototype.bytes, dedicated.bytes);
        assert_eq!(prototype.app, dedicated.app);
        assert_ne!(prototype.descriptor, dedicated.descriptor);
        assert_eq!(&network_hello_roles()[..6], &hello_roles());
        let role = network_hello_roles()[6];
        assert_eq!(
            (role.selector, role.kind, role.rights.bits()),
            (7, Kind::Memory, 7)
        );
    }
    #[test]
    fn session_note_is_an_explicit_package_requirement_without_wider_grants() {
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let old = native_hello(elf, [9; 32]).unwrap();
        let new = session_hello(elf, [9; 32]).unwrap();
        let legacy = Package::parse(&old.bytes).unwrap();
        let session = Package::parse(&new.bytes).unwrap();
        assert_eq!(new.app, old.app);
        assert_eq!(new.executable, old.executable);
        assert_ne!(new.package, old.package);
        assert!(
            session
                .app()
                .contracts()
                .any(|r| r.name == "ev.app.session-note" && r.major == 1)
        );
        assert!(
            !legacy
                .app()
                .contracts()
                .any(|r| r.name == "ev.app.session-note")
        );
        assert_eq!(
            session.app().capability_requests().collect::<Vec<_>>(),
            legacy.app().capability_requests().collect::<Vec<_>>()
        );
    }
    #[test]
    fn source_built_package_retains_actual_measured_elf_and_no_global_file_grant() {
        // Actual retained measured ELF fixture; this is a host container/admission
        // check, not a claim that this fixture executes the Hello UI.
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let built = hello(elf, [9; 32]).unwrap();
        let parsed = Package::parse(&built.bytes).unwrap();
        assert_eq!(parsed.executable().bytes, elf);
        assert_eq!(built.package, parsed.id().bytes());
        assert_eq!(parsed.app().claimed_app.bytes(), built.app);
        assert_eq!(parsed.app().build_id, built.build);
        assert_eq!(hello(elf, [9; 32]).unwrap().bytes, built.bytes);
        assert!(
            parsed
                .app()
                .capability_requests()
                .all(|r| !matches!(r.capability, Capability::AppPrivateData))
        );
        assert!(hello(b"not an executable", [9; 32]).is_err());
        let changed = hello(elf, [8; 32]).unwrap();
        assert_eq!(changed.app, built.app);
        assert_ne!(changed.package, built.package);
        assert_eq!(changed.executable, built.executable);
    }
    #[test]
    fn native_data_package_explicitly_requires_data_contract_and_preserves_identity() {
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let old = hello(elf, [9; 32]).unwrap();
        let native = native_hello(elf, [9; 32]).unwrap();
        let parsed = Package::parse(&native.bytes).unwrap();
        assert_eq!(old.app, native.app);
        assert_ne!(old.package, native.package);
        assert_eq!(old.executable, native.executable);
        assert!(
            parsed
                .app()
                .capability_requests()
                .any(|r| r.capability == Capability::AppPrivateData && r.required)
        );
        assert!(
            parsed
                .check_requirements(PLATFORM_LEVEL, ev_userspace_contract::ABI, &NativeContracts)
                .is_err()
        );
        assert!(
            parsed
                .check_requirements(
                    PLATFORM_LEVEL,
                    ev_userspace_contract::ABI,
                    &NativePlatformContracts
                )
                .is_ok()
        );
        assert_eq!(native_hello(elf, [9; 32]).unwrap().bytes, native.bytes);
        assert_eq!(native_hello(elf, [8; 32]).unwrap().bytes, native.bytes);
        assert!(native_hello(elf, [0; 32]).is_err());
        let mut changed_elf = elf.to_vec();
        changed_elf.push(0); // Valid extra ELF bytes still change container identity.
        let changed = native_hello(&changed_elf, [8; 32]).unwrap();
        assert_ne!(changed.build, native.build);
        assert_ne!(changed.package, native.package);
    }
    #[test]
    fn required_contract_major_and_features_are_not_inferred_from_a_name() {
        assert!(NativeContracts.supported("ev.internal.file", 2).is_none());
        assert!(NativeContracts.supported("unknown", 1).is_none());
        let supported = NativeContracts.supported("ev.internal.file", 1).unwrap();
        assert_eq!(supported.minor, 0);
        assert_eq!(supported.features, 0);
        assert!(
            hello_roles()
                .iter()
                .all(|r| r.kind != Kind::Display && r.kind != Kind::IoPorts)
        );
    }
}
