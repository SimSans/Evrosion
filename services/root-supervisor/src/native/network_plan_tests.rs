extern crate std;
use super::*;
use crate::native_plan::{PackageError, Packages, Slot};
use root_v2::catalogue as base;
use root_v4::{
    catalogue as nc,
    graph::{self, Child},
};
use std::vec::Vec;
fn fixture() -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    use ev_zion::{
        AppId, Capability, CapabilityRequest, Contract, DataSchema, Platform, Version,
        producer::{Resource, Spec},
    };
    let elf = include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf");
    let app = AppId::new([4; 16]).unwrap();
    let package = |label| {
        ev_zion::producer::build(
            &Spec {
                app,
                name: "V4 borrowed metadata model",
                source: "Repository model only",
                publisher: None,
                version: Version {
                    major: 0,
                    minor: 2,
                    patch: label as u32,
                },
                build_id: [label; 32],
                platform: Platform {
                    minimum: 1,
                    target: 1,
                },
                abi: ev_userspace_contract::ABI,
                data_schema: DataSchema {
                    current: 1,
                    oldest_readable: 1,
                },
                entrypoint: "bin/main.elf",
                contracts: &[
                    Contract {
                        name: "ev.app.private-data",
                        major: 1,
                        minimum_minor: 0,
                        features: 0,
                    },
                    Contract {
                        name: "ev.app.session-note",
                        major: 1,
                        minimum_minor: 0,
                        features: 0,
                    },
                ],
                capabilities: &[CapabilityRequest {
                    capability: Capability::AppPrivateData,
                    required: true,
                }],
            },
            elf,
            &[Resource {
                path: "res/model.txt",
                bytes: b"V4 actual serialized package model",
            }],
        )
        .unwrap()
    };
    let (a, b) = (package(5), package(6));
    let image: [u8; 32] = Sha256::digest(elf).into();
    let im = |child: Child, tag: u8| nc::Image {
        image: [tag; 32],
        descriptor: [tag + 1; 32],
        abi: ev_userspace_contract::ABI,
        limits: child.limits(),
        roles: network_roles_measurement(child),
    };
    let base_description = base::Description {
        root_image: [1; 32],
        kernel_input: [2; 32],
        graph: [3; 32],
        app_id: app.bytes(),
        package: Sha256::digest(&a).into(),
        app_build: [5; 32],
        provenance: base::Provenance::Zion,
        restart_attempts: 3,
        restart_window: 60000,
        images: core::array::from_fn(|i| {
            let child = graph::CHILDREN[i];
            base::Image {
                role: root_v2::graph::CHILDREN[i].image(),
                image: if i == 4 { image } else { [i as u8 + 10; 32] },
                descriptor: [i as u8 + 20; 32],
                abi: ev_userspace_contract::ABI,
                limits: child.limits(),
                display_layout: i == 5,
                grants: graph::GRANT_COUNTS[i] as u8,
                roles: network_roles_measurement(child),
            }
        }),
    };
    let mut base = nc::encode_base(base_description).unwrap();
    let encode = |base: &[u8], layout| {
        nc::encode(nc::Description {
            base,
            app_b: nc::Image {
                image,
                ..im(Child::App, 40)
            },
            bad_shell: im(Child::Shell, 50),
            net_driver: im(Child::NetDriver, 60),
            net_service: im(Child::NetService, 70),
            package_b: Sha256::digest(&b).into(),
            package_b_build: [6; 32],
            package_a_bytes: a.len() as u64,
            package_b_bytes: b.len() as u64,
            boot_mode: nc::BootMode::Standalone,
            layout_measurement: layout,
            device: nc::DeviceWitness {
                mac: nc::REFERENCE_MAC,
                model_source_sha256: [80; 32],
                emulator_binary_sha256: [81; 32],
            },
            network_policy: nc::NetworkPolicy {
                allowed_ipv4: [10, 0, 2, 2],
                remote_port: 8080,
                local_port: 49152,
                dns_name: "example.org",
            },
        })
        .unwrap()
    };
    let draft = encode(&base, [1; 32]);
    let base_hash = network_base_graph_measurement(nc::Catalogue::decode(&draft).unwrap().base());
    base[base::MEASUREMENT_OFFSET..base::MEASUREMENT_OFFSET + 32].copy_from_slice(&base_hash);
    let draft = encode(&base, [1; 32]);
    let bytes = encode(
        &base,
        network_layout_measurement(&nc::Catalogue::decode(&draft).unwrap()),
    );
    let mut context = Context {
        epoch: 1,
        incarnation: 2,
        process: 3,
        limits: root_v4::ROOT_LIMITS,
        authority: [4; 32],
        manifest: [0; 32],
    };
    bind(&bytes, &mut context);
    (bytes, context, a, b)
}
fn bind(bytes: &[u8], context: &mut Context) {
    let c = nc::Catalogue::decode(bytes).unwrap();
    context.manifest = Sha256::digest(
        root_v4::manifest_profile(root_v2::ManifestInputs {
            root_image: c.base().root_image(),
            catalogue: Sha256::digest(bytes).into(),
            authority: context.authority,
            limits: context.limits,
            restart_attempts: 3,
            restart_window: 60000,
        })
        .unwrap(),
    )
    .into();
}
#[test]
fn actual_v4_base_and_full_views_never_claim_legacy_validation() {
    let (bytes, context, a, b) = fixture();
    let c = verify_network(&bytes, context).unwrap();
    assert!(super::super::verify(&bytes, context).is_err());
    assert!(super::super::verify_session(&bytes, context).is_err());
    assert!(base::Catalogue::decode(c.base().bytes()).is_err());
    assert_eq!(c.base().images().nth(4).unwrap().grants, 7);
    let p = Packages::verify_network(&bytes, context, &a, &b).unwrap();
    assert!(p.is_network() && p.is_session());
    assert_eq!(p.catalogue().bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(p.catalogue().base().bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(p.catalogue().root_abi(), root_v4::ABI);
    assert_eq!(p.checked(Slot::A).unwrap().bytes().as_ptr(), a.as_ptr());
    assert_eq!(p.checked(Slot::B).unwrap().bytes().as_ptr(), b.as_ptr());
    for r in [
        ev_store::native::Region::AppRegistry,
        ev_store::native::Region::AppData,
    ] {
        assert_eq!(p.format_manifest(r).abi, root_v4::ABI);
    }
    assert_eq!(
        p.grant_format_manifest(*b"EVROSION-OWNER01").abi,
        root_v4::ABI
    );
    assert_eq!(
        p.note_format_manifest().abi,
        ev_app_registry::note_data::FORMAT_ABI
    );
    assert!(matches!(
        super::super::system::manifest(&p, super::super::system::Slot::Good, 1),
        Err(super::super::system::Error::Manifest)
    ));
}
#[test]
fn hashes_roles_actual_limits_and_mode_do_not_become_ambient_compatibility() {
    let (bytes, context, a, b) = fixture();
    let mut wrong = context;
    wrong.limits = crate::desktop_plan::ROOT_LIMITS;
    assert!(matches!(verify_network(&bytes, wrong), Err(Error::Limits)));
    wrong = context;
    wrong.authority[0] ^= 1;
    assert!(matches!(
        verify_network(&bytes, wrong),
        Err(Error::Manifest)
    ));
    let mut changed = bytes;
    changed[nc::MEASUREMENT_OFFSET] ^= 1;
    assert!(matches!(
        verify_network(&changed, context),
        Err(Error::Layout)
    ));
    // Even a canonical, remeasured, manifest-bound critical role substitution
    // is refused against the actual closed V4 graph.
    let mut changed = bytes;
    changed[base::HEADER + base::IMAGE_BYTES + 144] ^= 1;
    let c = nc::Catalogue::decode(&changed).unwrap();
    let base_hash = network_base_graph_measurement(c.base());
    changed[base::MEASUREMENT_OFFSET..base::MEASUREMENT_OFFSET + 32].copy_from_slice(&base_hash);
    let layout = network_layout_measurement(&nc::Catalogue::decode(&changed).unwrap());
    changed[nc::MEASUREMENT_OFFSET..nc::MEASUREMENT_OFFSET + 32].copy_from_slice(&layout);
    let mut bound = context;
    bind(&changed, &mut bound);
    assert!(matches!(verify_network(&changed, bound), Err(Error::Roles)));
    for mode in [nc::BootMode::SystemManaged, nc::BootMode::Recovery] {
        let mut changed = bytes;
        changed[nc::BOOT_MODE_OFFSET..nc::BOOT_MODE_OFFSET + 2]
            .copy_from_slice(&(mode as u16).to_le_bytes());
        assert!(verify_network(&changed, context).is_err());
        let c = nc::Catalogue::decode(&changed).unwrap();
        let layout = network_layout_measurement(&c);
        changed[nc::MEASUREMENT_OFFSET..nc::MEASUREMENT_OFFSET + 32].copy_from_slice(&layout);
        let mut bound = context;
        bind(&changed, &mut bound);
        assert_eq!(verify_network(&changed, bound).unwrap().boot_mode(), mode);
    }
    let mut changed_a = a.clone();
    *changed_a.last_mut().unwrap() ^= 1;
    assert!(matches!(
        Packages::verify_network(&bytes, context, &changed_a, &b),
        Err(PackageError::Package(_))
    ));
    assert!(matches!(
        Packages::verify_network(&bytes, context, &a, &a),
        Err(PackageError::Length | PackageError::Digest | PackageError::Build)
    ));
}
