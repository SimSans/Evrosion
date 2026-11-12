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

pub const HELLO_APP_ID: [u8; 16] = [
    0x62, 0xc0, 0x76, 0x7e, 0x6c, 0x18, 0x45, 0x9c, 0x91, 0xe6, 0xeb, 0x8b, 0x94, 0x89, 0x58, 0xf2,
];
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
            (name == "ev.app.private-data" && major == 1).then_some(ContractSupport {
                minor: 0,
                features: 0,
            })
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
    if source == [0; 32] {
        return Err("Native package requires retained source provenance".into());
    }
    // Use one canonical nonzero build placeholder to include every app-specific
    // field in the build transcript without a self-referential digest.
    let draft = package(
        image,
        [1; 32],
        &NATIVE_REQUIREMENTS,
        &NATIVE_REQUESTS,
        &NativePlatformContracts,
    )?;
    let mut hash = Sha256::new();
    hash.update(b"evrosion.native.hello.content-build.v2\0");
    hash.update(&draft.bytes);
    package(
        image,
        hash.finalize().into(),
        &NATIVE_REQUIREMENTS,
        &NATIVE_REQUESTS,
        &NativePlatformContracts,
    )
}
fn package(
    image: &[u8],
    build: [u8; 32],
    requirements: &[Contract<'_>],
    requests: &[CapabilityRequest],
    contracts: &impl Contracts,
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
        &hello_roles(),
    )
    .map_err(|e| format!("native Hello executable admission: {e:?}"))?;
    let descriptor = measured.digest();
    let spec = Spec {
        app: AppId::new(HELLO_APP_ID).unwrap(),
        name: "Evrosion Hello",
        source: "Evrosion repository development source",
        publisher: None,
        version: Version {
            major: 0,
            minor: 1,
            patch: 0,
        },
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
