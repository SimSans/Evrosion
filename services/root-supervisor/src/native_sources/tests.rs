extern crate std;
use super::*;
use crate::native_image::{Images, Io, IoError};
use crate::native_plan::{
    network_base_graph_measurement, network_layout_measurement, network_roles_measurement,
};
use crate::native_sources::downloaded::validate;
use ev_userspace_contract::{Context, root_v2, root_v4};
use ev_userspace_runtime::CapReply;
use root_v2::catalogue as base;
use root_v4::{
    catalogue as nc,
    graph::{self, Child},
};
use sha2::{Digest, Sha256};
use std::vec::Vec;
const BASE: u64 = 0x8000000000;
const B: &[u8] = include_bytes!("../../fixtures/acquisition/old-b-fresh-metadata/hello.zion");
const C: &[u8] = include_bytes!("../../fixtures/acquisition/phase-c/hello.zion");
pub(crate) fn fixture() -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    fixture_profile(false)
}
fn fixture_profile(collide: bool) -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
    use ev_zion::{
        AppId, Capability, CapabilityRequest, Contract, DataSchema, Platform, Version,
        producer::{Resource, Spec},
    };
    let elf = include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf");
    let app = AppId::new(crate::native_acquisition::HELLO_APP).unwrap();
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
    let (a, b) = (if collide { B.to_vec() } else { package(5) }, package(6));
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
        kernel_input: [2; 32],
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
// Pure physical-I/O model only. Real Images continuation owns and checks all
// phases; this does not prove actual Kernel mappings, IRQ or executable load.
pub(crate) struct Model {
    header: Option<root_v4::dynamic::Header>,
    bodies: [Vec<u8>; 2],
    active: usize,
    used: usize,
    remaining: u64,
}
impl Io for Model {
    fn control(&mut self, op: root_v4::dynamic::Operation, a: u64, b: u64) -> CapReply {
        use root_v4::dynamic::{self as d, Operation::*};
        let (value, capability) = match op {
            Initialize => (d::VERSION, 0),
            Inspect => (
                match b {
                    0 => BASE + d::REGION + d::CONTROL as u64 * 4096,
                    1 => d::VERSION,
                    2 => 2,
                    _ => panic!(),
                },
                0,
            ),
            Begin => {
                self.active = self.used;
                self.used += 1;
                (self.used as u64, 20 + self.active as u64)
            }
            Written => ((b as u32 as u64) + (b >> 32), 0),
            Seal => {
                assert_eq!(a, self.active as u64 + 1);
                self.remaining = self.header.unwrap().bytes.div_ceil(4096) * 4096;
                (self.remaining, 0)
            }
            Verify => {
                assert_eq!(a, self.active as u64 + 1);
                self.remaining -= 4096;
                (
                    self.remaining,
                    if self.remaining == 0 {
                        100 + self.active as u64
                    } else {
                        0
                    },
                )
            }
            Register => (0, 0),
            _ => panic!(),
        };
        CapReply {
            status: 0,
            value,
            capability,
            serial: 0,
        }
    }
    fn write_header(&mut self, b: &[u8; 256]) -> Result<(), IoError> {
        self.header = Some(root_v4::dynamic::Header::decode(b).ok_or(IoError)?);
        self.bodies[self.used].resize(self.header.unwrap().bytes as usize, 0);
        Ok(())
    }
    fn write_staging(&mut self, at: usize, b: &[u8]) -> Result<(), IoError> {
        self.bodies[self.active][at..at + b.len()].copy_from_slice(b);
        Ok(())
    }
    fn readonly(&self, s: usize, n: usize) -> Result<&[u8], IoError> {
        self.bodies.get(s).and_then(|b| b.get(..n)).ok_or(IoError)
    }
}
pub(crate) fn sealed_images(c: bool) -> Images<Model> {
    if c {
        sealed_packages(&[B, C])
    } else {
        sealed_packages(&[B])
    }
}
pub(crate) fn sealed_packages(packages: &[&[u8]]) -> Images<Model> {
    let mut images = empty_images();
    for (index, bytes) in packages.iter().copied().enumerate() {
        let now = 2 + index as u64 * 10;
        let p = ev_zion::Package::parse(bytes).unwrap();
        let mut desc = Sha256::new();
        root_v4::dynamic::app_descriptor_transcript(&p.executable().digest, |b| desc.update(b));
        let h = root_v4::dynamic::Header {
            bytes: bytes.len() as u64,
            elf_offset: (p.executable().bytes.as_ptr() as usize - p.bytes().as_ptr() as usize)
                as u64,
            elf_bytes: p.executable().bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            elf_sha256: p.executable().digest,
            package: p.id().bytes(),
            abi: ev_userspace_contract::ABI,
            descriptor: desc.finalize().into(),
        };
        let slot = images.begin(h, now, 1000).unwrap();
        for b in bytes.chunks(4096) {
            images.write_chunk(slot, now + 1, b).unwrap()
        }
        images.seal(slot, now + 2).unwrap();
        while !images.verify_step(slot, now + 3).unwrap() {}
    }
    images
}
pub(crate) fn empty_images() -> Images<Model> {
    let mut images = Images::new(empty_model(), BASE).unwrap();
    images.initialize(1).unwrap();
    images
}
pub(crate) fn empty_model() -> Model {
    Model {
        header: None,
        bodies: [Vec::new(), Vec::new()],
        active: 0,
        used: 0,
        remaining: 0,
    }
}

#[test]
fn actual_sealed_package_snapshot_and_scoped_cache_preserve_distinct_downloaded_identity() {
    use ev_app_registry::Packages as _;
    let (cat, ctx, a, b) = fixture();
    let banks = Packages::verify_network(&cat, ctx, &a, &b).unwrap();
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let images = sealed_images(false);
    let content = snapshot.candidate().unwrap();
    let d = Downloaded::from_images(&images, 0, &snapshot, content).unwrap();
    assert_eq!(d.slot(), DownloadedSlot::B);
    assert_eq!(d.kernel_slot(), 0);
    assert_eq!(
        d.package().bytes().as_ptr(),
        images.bytes(0).unwrap().as_ptr()
    );
    let view = View::new(&banks, &images, &snapshot, [Some(d), None]).unwrap();
    assert_eq!(
        view.source(content.package),
        Some(Source::Downloaded(DownloadedSlot::B))
    );
    assert_eq!(banks.slot(content.package), None);
    assert!(banks.resolve(content.package).is_none());
    assert!(core::ptr::eq(
        view.resolve(content.package).unwrap(),
        view.parsed(content.package).unwrap().bytes()
    ));
    assert_ne!(
        view.source_digest(Source::Bank(Slot::B)),
        Some(content.package)
    );
    assert_eq!(
        view.checked_source(Source::Downloaded(DownloadedSlot::B))
            .unwrap()
            .app()
            .claimed_app,
        banks.app()
    );
    std::println!(
        "scoped View metadata bytes={}, Downloaded bytes={}",
        core::mem::size_of_val(&view),
        core::mem::size_of::<Downloaded<'_, Model>>()
    );
    assert!(core::mem::size_of_val(&view) <= 1536);
    assert!(snapshot.active().is_none() && snapshot.known_good().is_none());
}
#[test]
fn two_downloads_require_the_same_actual_image_and_current_snapshot_owners() {
    let (cat, ctx, a, b) = fixture();
    let banks = Packages::verify_network(&cat, ctx, &a, &b).unwrap();
    let snapshot = crate::native_acquisition::tests::retained_snapshot(true);
    let other = crate::native_acquisition::tests::retained_snapshot(true);
    let images = sealed_images(true);
    let other_images = sealed_images(true);
    let b = snapshot.known_good().unwrap();
    let c = snapshot.candidate().unwrap();
    let make_b = || Downloaded::from_images(&images, 0, &snapshot, b).unwrap();
    let make_c = || Downloaded::from_images(&images, 1, &snapshot, c).unwrap();
    let view = View::new(&banks, &images, &snapshot, [Some(make_b()), Some(make_c())]).unwrap();
    assert_eq!(
        view.source(c.package),
        Some(Source::Downloaded(DownloadedSlot::C))
    );
    assert!(matches!(
        View::new(
            &banks,
            &images,
            &snapshot,
            [
                Some(make_b()),
                Some(Downloaded::from_images(&other_images, 1, &snapshot, c).unwrap())
            ]
        ),
        Err(Error::Owner)
    ));
    assert!(matches!(
        View::new(
            &banks,
            &images,
            &snapshot,
            [
                Some(make_b()),
                Some(Downloaded::from_images(&images, 1, &other, c).unwrap())
            ]
        ),
        Err(Error::Owner)
    ));
    assert!(matches!(
        View::new(&banks, &images, &snapshot, [Some(make_c()), None]),
        Err(Error::Slot)
    ));
    assert!(matches!(
        Downloaded::from_images(&images, 0, &snapshot, c),
        Err(Error::Identity)
    ));
    let mut foreign = b;
    foreign.build[0] ^= 1;
    assert!(matches!(
        Downloaded::from_images(&images, 0, &snapshot, foreign),
        Err(Error::Snapshot)
    ));
}
#[test]
fn every_retained_identity_source_build_descriptor_and_version_mismatch_refuses() {
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let good = snapshot.candidate().unwrap();
    let package = ev_zion::Package::parse(B).unwrap();
    assert_eq!(validate(&package, good), Ok(()));
    for field in 0..7 {
        let mut bad = good;
        match field {
            0 => bad.app[0] ^= 1,
            1 => bad.package[0] ^= 1,
            2 => bad.build[0] ^= 1,
            3 => bad.source[0] ^= 1,
            4 => bad.descriptor[0] ^= 1,
            5 => bad.version = 3,
            6 => {
                bad.object = ev_content_store::Object::checked(
                    good.object.start(),
                    good.object.length() - 1,
                    good.object.sha256(),
                )
                .unwrap()
            }
            _ => unreachable!(),
        }
        assert!(validate(&package, bad).is_err(), "field{field}");
    }
    let mut corrupted = B.to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(ev_zion::Package::parse(&corrupted).is_err());
}
#[test]
fn a_download_already_in_any_compiled_bank_cannot_masquerade_as_absent_bank_content() {
    let (cat, context, a, b) = fixture_profile(true);
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let images = sealed_images(false);
    let d = Downloaded::from_images(&images, 0, &snapshot, snapshot.candidate().unwrap()).unwrap();
    assert!(matches!(
        View::new(&banks, &images, &snapshot, [Some(d), None]),
        Err(Error::Collision)
    ));
}
#[test]
fn changed_real_package_abi_schema_contract_capability_and_source_never_inherit_cached_eligibility()
{
    use ev_zion::producer::{Resource, Spec};
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let good = snapshot.candidate().unwrap();
    let p = ev_zion::Package::parse(B).unwrap();
    let a = p.app();
    let resources: Vec<_> = p
        .resources()
        .map(|e| Resource {
            path: e.path,
            bytes: e.bytes,
        })
        .collect();
    for field in 0..7 {
        let mut contracts: Vec<_> = a.contracts().collect();
        let mut capabilities: Vec<_> = a.capability_requests().collect();
        match field {
            2 => contracts[0].major = 2,
            3 => capabilities[1].required = false,
            4 => {
                contracts.remove(1);
            }
            _ => (),
        }
        let mut spec = Spec {
            app: a.claimed_app,
            name: a.display_name,
            source: a.developer_source,
            publisher: None,
            version: a.version,
            build_id: a.build_id,
            platform: a.platform,
            abi: a.abi,
            data_schema: a.data_schema,
            entrypoint: a.entrypoint,
            contracts: &contracts,
            capabilities: &capabilities,
        };
        match field {
            0 => spec.abi = [9; 32],
            1 => spec.data_schema.current = 2,
            5 => spec.source = "changed developer provenance",
            6 => spec.version.patch = 99,
            _ => (),
        }
        let bytes = ev_zion::producer::build(&spec, p.executable().bytes, &resources).unwrap();
        let changed = ev_zion::Package::parse(&bytes).unwrap();
        let mut c = good;
        c.package = changed.id().bytes();
        c.object =
            ev_content_store::Object::checked(good.object.start(), bytes.len() as u64, c.package)
                .unwrap();
        assert!(validate(&changed, c).is_err(), "field{field}");
    }
}
