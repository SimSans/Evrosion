//! Structural catalogue context for read-only disk tests, not a guest receipt.
use super::*;
use ev_root_supervisor::native_plan::{
    network_base_graph_measurement, network_layout_measurement, network_roles_measurement,
};
use ev_userspace_contract::{Context, root_v2, root_v4};
use root_v2::catalogue as base;
use root_v4::{
    catalogue as nc,
    graph::{self, Child},
};
pub(crate) fn fixture() -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_profile(5)
}
pub(crate) fn alternate() -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_profile(7)
}
pub(crate) fn compatible_source(source: [u8; 32]) -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_source(5, source)
}
fn fixture_profile(label: u8) -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_source(label, [2; 32])
}
pub(crate) fn for_mode(mode: nc::BootMode) -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_source_mode(5, [2; 32], mode)
}
fn fixture_source(label: u8, source: [u8; 32]) -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_source_mode(label, source, nc::BootMode::Standalone)
}
fn fixture_source_mode(
    label: u8,
    source: [u8; 32],
    mode: nc::BootMode,
) -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    use ev_zion::{
        AppId, Capability, CapabilityRequest, Contract, DataSchema, Platform, Version,
        producer::{Resource, Spec},
    };
    let elf = include_bytes!("../../../../../kernel/fixtures/bootstrap-static-v1.elf");
    let app = AppId::new(acq::HELLO_APP).unwrap();
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
    let (a, b) = (package(label), package(label + 1));
    let image = ev_zion::Package::parse(&a).unwrap().executable().digest;
    let image_b = ev_zion::Package::parse(&b).unwrap().executable().digest;
    let build_a = ev_zion::Package::parse(&a).unwrap().app().build_id;
    let im = |child: Child, tag: u8| nc::Image {
        image: [tag; 32],
        descriptor: [tag + 1; 32],
        abi: ev_userspace_contract::ABI,
        limits: child.limits(),
        roles: network_roles_measurement(child),
    };
    let base_description = base::Description {
        root_image: [1; 32],
        kernel_input: source,
        graph: [3; 32],
        app_id: app.bytes(),
        package: Sha256::digest(&a).into(),
        app_build: build_a,
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
                image: image_b,
                ..im(Child::App, 40)
            },
            bad_shell: im(Child::Shell, 50),
            net_driver: im(Child::NetDriver, 60),
            net_service: im(Child::NetService, 70),
            package_b: Sha256::digest(&b).into(),
            package_b_build: [label + 1; 32],
            package_a_bytes: a.len() as u64,
            package_b_bytes: b.len() as u64,
            boot_mode: mode,
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
