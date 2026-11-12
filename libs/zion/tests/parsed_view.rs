#![cfg(feature = "std")]
//! External API tests: no private same-crate access is available here.
use ev_zion::{
    AppId, Contract, ContractSupport, Contracts, DataSchema, Error, Package, Platform, Version,
    lifecycle::{Record, VersionRef},
    producer::{self, Resource, Spec},
};
struct Supported;
impl Contracts for Supported {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        (name == "ev.file.object" && major == 1).then_some(ContractSupport {
            minor: 2,
            features: 3,
        })
    }
}
struct Unsupported;
impl Contracts for Unsupported {
    fn supported(&self, _: &str, _: u16) -> Option<ContractSupport> {
        None
    }
}
fn fixture() -> Vec<u8> {
    let contracts = [Contract {
        name: "ev.file.object",
        major: 1,
        minimum_minor: 2,
        features: 3,
    }];
    let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
    producer::build(
        &Spec {
            app: AppId::new([7; 16]).unwrap(),
            name: "Hello",
            source: "Owner source",
            publisher: None,
            version: Version {
                major: 0,
                minor: 1,
                patch: 2,
            },
            build_id: [9; 32],
            platform: Platform {
                minimum: 7,
                target: 9,
            },
            abi: [8; 32],
            data_schema: DataSchema {
                current: 2,
                oldest_readable: 1,
            },
            entrypoint: "bin/main.elf",
            contracts: &contracts,
            capabilities: &[],
        },
        elf,
        &[Resource {
            path: "res/welcome.txt",
            bytes: b"Owner data",
        }],
    )
    .unwrap()
}
#[test]
fn detached_descriptor_and_entry_edits_cannot_relabel_validated_package_or_receipt() {
    let bytes = fixture();
    let package = Package::parse(&bytes).unwrap();
    let id = package.id();
    let original = *package.app();
    let executable = package.executable();
    let mut detached = *package.app();
    detached.claimed_app = AppId::new([99; 16]).unwrap();
    detached.abi = [11; 32];
    detached.platform.minimum = 0;
    detached.data_schema = DataSchema {
        current: 9,
        oldest_readable: 9,
    };
    let mut entry = package.executable();
    entry.bytes = b"notELF";
    entry.digest = [0; 32];
    assert_ne!(detached.claimed_app, package.app().claimed_app);
    assert_ne!(entry.bytes, package.executable().bytes);
    assert_eq!(package.id(), id);
    assert_eq!(package.app().claimed_app, original.claimed_app);
    assert_eq!(package.app().abi, [8; 32]);
    assert_eq!(package.executable(), executable);
    assert_eq!(package.format_minor(), 0);
    assert!(matches!(
        package.compatible(0, [8; 32], &Supported),
        Err(Error::Platform)
    ));
    assert!(matches!(
        package.compatible(7, [11; 32], &Supported),
        Err(Error::Abi)
    ));
    assert!(matches!(
        package.compatible(7, [8; 32], &Unsupported),
        Err(Error::UnsupportedContract)
    ));
    let compatible = package.compatible(7, [8; 32], &Supported).unwrap();
    let record = Record::install(&compatible, 1).unwrap();
    assert_eq!(record.app(), original.claimed_app);
    assert_eq!(record.staged().unwrap().digest(), id.bytes());
    assert!(VersionRef::from_package(&compatible).matches(&compatible));
}
#[test]
fn getters_preserve_zero_copy_views_raw_integrity_and_lifecycle_facts() {
    let bytes = fixture();
    let package = Package::parse(&bytes).unwrap();
    let executable = package.executable();
    let start = bytes.as_ptr() as usize;
    let end = start + bytes.len();
    assert!((start..end).contains(&(executable.bytes.as_ptr() as usize)));
    assert!(executable.bytes.as_ptr() as usize + executable.bytes.len() <= end);
    assert_eq!(package.app().display_name, "Hello");
    assert_eq!(package.app().entrypoint, "bin/main.elf");
    assert_eq!(package.app().contracts().count(), 1);
    assert_eq!(package.resources().next().unwrap().bytes, b"Owner data");
    let compatibility = package.compatible(7, [8; 32], &Supported).unwrap();
    let installed = Record::install(&compatibility, 1).unwrap();
    let active = installed.activate(installed.revision()).unwrap();
    let removed = active.remove(active.revision()).unwrap();
    assert_eq!(removed.app(), package.app().claimed_app);
    assert_eq!(removed.data_epoch(), 1);
    assert!(!removed.installed());
    assert_eq!(Package::parse(&bytes).unwrap().id(), package.id());
}
