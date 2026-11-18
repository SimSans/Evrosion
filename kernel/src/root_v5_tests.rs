//! Portable V5 authority/format/admission tests. These exercise real Authority
//! tables and owned host loader models, never physical loading or guest boot.
extern crate std;
use crate::{
    bootstrap_binding::CatalogEntry,
    capability::{Authority, Rights, SpaceId},
    custodian::Custodian,
    executable::{Image, StartupLayout},
    incarnation,
    loaded_image::{Information, LoadedExecutable, Startup},
    root_binding_v2::{self, Source},
    root_factory_v2::RootDomains,
    root_manifest_v2, root_manifest_v4, root_manifest_v5,
    root_producer_v5::{self, Description, Identity},
    scheduler::Scheduler,
};
use core::num::NonZeroU64;
use ev_userspace_contract::root_v5::{self as v5, catalogue as cat, graph};
use sha2::{Digest, Sha256};
const BRANCH: Rights = Rights::from_bits(224).unwrap();
pub(crate) fn elf() -> std::vec::Vec<u8> {
    crate::executable::m8::tests::elf(&[(2, 1), (256, 8)])
}
fn seed(image: &[u8]) -> [u8; v5::MANIFEST_CURRENT_BYTES] {
    v5::manifest_profile(v5::ManifestInputs {
        root_image: Sha256::digest(image).into(),
        catalogue: [7; 32],
        authority: [8; 32],
        restart_attempts: 3,
        restart_window: 60_000,
    })
    .unwrap()
}
fn sources(a: &mut Authority, c: SpaceId) -> [Source; v5::CURRENT_GRANTS] {
    core::array::from_fn(|i| {
        let r = v5::ROLES[i];
        let kind = root_manifest_v2::kind(r.kind).unwrap();
        Source {
            selector: r.role.selector(),
            kind,
            handle: a
                .create_root(
                    c,
                    kind,
                    Rights::from_bits(r.rights).unwrap() | BRANCH | Rights::CONTROL,
                )
                .unwrap(),
        }
    })
}
pub(crate) fn setup(image: &[u8]) -> (Authority, RootDomains, [Source; v5::CURRENT_GRANTS]) {
    // The seed is a trusted, measured profile description, not a live authority
    // witness. Only the later exact live digest/install can bind a Root token.
    let b = seed(image);
    let m = root_manifest_v5::verify(&b, Sha256::digest(b).into(), image).unwrap();
    let mut a = Authority::for_workspace_profile();
    let domains = RootDomains::allocate_workspace(&mut a, &m).unwrap();
    let mut s = sources(&mut a, domains.custody());
    // Force actual object-slot generation reuse; a slot-only fake must differ
    // from at least one live source identity in this host authority fixture.
    let c = domains.custody();
    a.destroy(c, s[36].handle).unwrap();
    a.close(c, s[36].handle).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    s[36].handle = a
        .create_root(
            c,
            s[36].kind,
            Rights::from_bits(v5::ROLES[36].rights).unwrap() | BRANCH | Rights::CONTROL,
        )
        .unwrap();
    (a, domains, s)
}
fn identities(
    a: &Authority,
    c: SpaceId,
    s: &[Source; v5::CURRENT_GRANTS],
) -> [Identity; v5::CURRENT_GRANTS] {
    core::array::from_fn(|i| {
        let x = a
            .authorize(c, s[i].handle, s[i].kind, Rights::DERIVE)
            .unwrap();
        Identity {
            object: x.identity() as u64,
            lineage: x.lineage_root() as u64,
        }
    })
}
fn description(
    a: &Authority,
    c: SpaceId,
    s: &[Source; v5::CURRENT_GRANTS],
    catalogue: [u8; 32],
) -> Description {
    Description::full_graph(v5::ROOT_LIMITS, 3, 60_000, identities(a, c, s))
        .unwrap()
        .bind_catalogue(catalogue)
}
pub(crate) fn encoded(
    image: &[u8],
    a: &Authority,
    c: SpaceId,
    s: &[Source; v5::CURRENT_GRANTS],
) -> root_producer_v5::Encoded {
    root_producer_v5::encode_current(image, &description(a, c, s, [7; 32])).unwrap()
}
fn catalogue(image: &[u8]) -> [u8; cat::SIZE] {
    let images = core::array::from_fn(|i| {
        let slot = graph::IMAGES[i];
        cat::Image {
            image: [i as u8 + 10; 32],
            descriptor: [i as u8 + 30; 32],
            abi: v5::child::abi(slot.representative()),
            limits: slot.representative().limits(),
            role_shape: [i as u8 + 50; 32],
        }
    });
    let packages = core::array::from_fn(|i| {
        let kind = cat::PACKAGES[i];
        cat::Package {
            app_id: if i == 3 { [2; 16] } else { [i as u8 + 1; 16] },
            digest: [i as u8 + 80; 32],
            build: [i as u8 + 90; 32],
            image: if i == 3 {
                [110; 32]
            } else {
                images[kind.image().index()].image
            },
            bytes: 8192,
            bank: if i == 3 {
                cat::PackageBank::Candidate
            } else {
                cat::PackageBank::Current
            },
            offset: if i == 3 { 0 } else { i as u32 * 8192 },
        }
    });
    cat::encode(cat::Description {
        root_image: Sha256::digest(image).into(),
        kernel_input: [2; 32],
        graph_measurement: [3; 32],
        layout_measurement: [4; 32],
        measurement: [5; 32],
        boot_mode: cat::BootMode::SystemManaged,
        restart_attempts: 3,
        restart_window: 60_000,
        images,
        instance_bindings: core::array::from_fn(|i| [i as u8 + 120; 32]),
        packages,
        device: cat::DeviceWitness {
            mac: cat::REFERENCE_MAC,
            model_source_sha256: [6; 32],
            emulator_binary_sha256: [7; 32],
        },
        network: cat::NetworkPolicy {
            allowed_ipv4: [10, 0, 2, 2],
            remote_port: 443,
            local_port: 49152,
            dns_name: "workspace.test",
        },
    })
    .unwrap()
}
#[test]
fn independent_v5_producer_binds_every_manifest_bit_and_never_crosses_old_formats() {
    let image = elf();
    let (a, d, s) = setup(&image);
    let e = encoded(&image, &a, d.custody(), &s);
    assert_eq!(e.bytes().len(), 1392);
    let m = root_manifest_v5::verify(e.bytes(), e.digest(), &image).unwrap();
    assert_eq!(m.manifest().grants().count(), 37);
    assert_eq!(m.manifest().startup_bytes(), 1104);
    assert_eq!(m.manifest().authority_domain(), v5::AUTHORITY_DOMAIN);
    assert_eq!(
        m.manifest().expected_authority_digest(),
        description(&a, d.custody(), &s, [7; 32]).authority_digest()
    );
    assert!(root_manifest_v2::verify(e.bytes(), e.digest(), &image).is_err());
    assert!(root_manifest_v4::verify(e.bytes(), e.digest(), &image).is_err());
    let old = ev_userspace_contract::root_v4::manifest_profile(
        ev_userspace_contract::root_v2::ManifestInputs {
            root_image: Sha256::digest(&image).into(),
            catalogue: [7; 32],
            authority: [8; 32],
            limits: ev_userspace_contract::root_v4::ROOT_LIMITS,
            restart_attempts: 3,
            restart_window: 60_000,
        },
    )
    .unwrap();
    assert!(root_manifest_v4::verify(&old, Sha256::digest(old).into(), &image).is_ok());
    assert!(root_manifest_v5::verify(&old, Sha256::digest(old).into(), &image).is_err());
    for bit in 0..e.bytes().len() * 8 {
        let mut b = e.bytes().to_vec();
        b[bit / 8] ^= 1 << (bit % 8);
        assert!(matches!(
            root_manifest_v5::verify(&b, e.digest(), &image),
            Err(root_manifest_v5::Error::Measurement)
        ));
    }
    for at in [
        0, 8, 48, 80, 88, 96, 104, 160, 168, 170, 172, 174, 208, 216, 218,
    ] {
        let mut b = e.bytes().to_vec();
        b[at] ^= 1;
        assert!(
            root_manifest_v5::verify(&b, Sha256::digest(&b).into(), &image).is_err(),
            "semantic byte{at}"
        );
    }
    for range in [128..160, 176..208] {
        let mut b = e.bytes().to_vec();
        b[range].fill(0);
        assert!(root_manifest_v5::verify(&b, Sha256::digest(&b).into(), &image).is_err());
    }
    let mut b = e.bytes().to_vec();
    b[0..8].copy_from_slice(b"EVBM0004");
    assert!(root_manifest_v5::verify(&b, Sha256::digest(&b).into(), &image).is_err());
}
#[test]
fn producer_rejects_alias_limits_and_missing_catalogue_before_any_live_install() {
    let image = elf();
    let (a, d, s) = setup(&image);
    let ids = identities(&a, d.custody(), &s);
    let mut alias = ids;
    alias[36] = ids[0];
    assert!(matches!(
        Description::full_graph(v5::ROOT_LIMITS, 3, 60, alias),
        Err(root_producer_v5::Error::Alias)
    ));
    let mut limits = v5::ROOT_LIMITS;
    limits[1] += 1;
    assert!(matches!(
        Description::full_graph(limits, 3, 60, ids),
        Err(root_producer_v5::Error::Limits)
    ));
    let desc = Description::full_graph(v5::ROOT_LIMITS, 3, 60, ids).unwrap();
    assert!(matches!(
        root_producer_v5::encode_current(&image, &desc),
        Err(root_producer_v5::Error::Catalogue)
    ));
}
#[test]
fn catalogue_join_requires_actual_twelve_kib_digest_canonical_graph_and_matching_root() {
    let image = elf();
    let (a, d, s) = setup(&image);
    let mut bytes = catalogue(&image);
    let e = root_producer_v5::encode_current(
        &image,
        &description(&a, d.custody(), &s, Sha256::digest(bytes).into()),
    )
    .unwrap();
    let m = root_manifest_v5::verify(e.bytes(), e.digest(), &image).unwrap();
    assert_eq!(m.catalogue(&bytes).unwrap().images().len(), 10);
    bytes[cat::GRAPH_AT + 8] ^= 1;
    assert!(m.catalogue(&bytes).is_err());
    let e = root_producer_v5::encode_current(
        &image,
        &description(&a, d.custody(), &s, Sha256::digest(bytes).into()),
    )
    .unwrap();
    let m = root_manifest_v5::verify(e.bytes(), e.digest(), &image).unwrap();
    assert!(m.catalogue(&bytes).is_err());
    let other = crate::executable::m8::tests::elf(&[(2, 2), (256, 8)]);
    let bytes = catalogue(&other);
    let e = root_producer_v5::encode_current(
        &image,
        &description(&a, d.custody(), &s, Sha256::digest(bytes).into()),
    )
    .unwrap();
    assert!(matches!(
        root_manifest_v5::verify(e.bytes(), e.digest(), &image)
            .unwrap()
            .catalogue(&bytes),
        Err(root_manifest_v5::Error::Image)
    ));
}
#[test]
fn typed_workspace_factory_and_binding_require_real_selected_ninety_six_slot_banks() {
    let image = elf();
    let b = seed(&image);
    let m = root_manifest_v5::verify(&b, Sha256::digest(b).into(), &image).unwrap();
    let mut legacy = Authority::new();
    let before = legacy.metadata_usage();
    assert!(matches!(
        RootDomains::allocate_workspace(&mut legacy, &m),
        Err(crate::capability::Error::Denied)
    ));
    assert_eq!(legacy.metadata_usage(), before);
    let mut exhausted = Authority::for_workspace_profile();
    exhausted.create_workspace_control_space().unwrap();
    exhausted.create_workspace_control_space().unwrap();
    let before = exhausted.metadata_usage();
    assert!(matches!(
        RootDomains::allocate_workspace(&mut exhausted, &m),
        Err(crate::capability::Error::Capacity)
    ));
    assert_eq!(exhausted.metadata_usage(), before);
    exhausted.create_workspace_control_space().unwrap();
    exhausted.create_workspace_control_space().unwrap();
    assert_eq!(
        exhausted.create_workspace_control_space(),
        Err(crate::capability::Error::Capacity)
    );
    let (a, d, s) = setup(&image);
    let c = d.custody();
    let e = encoded(&image, &a, c, &s);
    let m = root_manifest_v5::verify(e.bytes(), e.digest(), &image).unwrap();
    let mut a = a;
    let mut scheduler = Scheduler::new();
    let job = scheduler
        .create_job_with_limits(m.manifest().limits())
        .unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    let (c, target) = d.into_target(process, job);
    assert_eq!(a.slot_capacity(c), Ok(96));
    assert_eq!(a.slot_capacity(target.branches), Ok(96));
    assert_eq!(a.slot_capacity(target.destination), Ok(96));
    let ordinary = a.create_space().unwrap();
    let before = a.metadata_usage();
    assert!(matches!(
        root_binding_v2::install_v5(&mut a, c, target.branches, ordinary, &s, &m),
        Err(root_binding_v2::Error::Capacity)
    ));
    assert_eq!(a.metadata_usage(), before);
    let mut alias = s;
    alias[36].handle = s[0].handle;
    assert!(matches!(
        root_binding_v2::install_v5(&mut a, c, target.branches, target.destination, &alias, &m),
        Err(root_binding_v2::Error::Alias)
    ));
    assert_eq!(a.metadata_usage(), before);
    let mut name_only = identities(&a, c, &s);
    for id in &mut name_only {
        id.object &= 255;
        id.lineage &= 255;
    }
    assert_ne!(name_only, identities(&a, c, &s));
    let forged = root_producer_v5::encode_current(
        &image,
        &Description::full_graph(v5::ROOT_LIMITS, 3, 60_000, name_only)
            .unwrap()
            .bind_catalogue([7; 32]),
    )
    .unwrap();
    let forged = root_manifest_v5::verify(forged.bytes(), forged.digest(), &image).unwrap();
    assert!(matches!(
        root_binding_v2::install_v5(&mut a, c, target.branches, target.destination, &s, &forged),
        Err(root_binding_v2::Error::Measurement)
    ));
    assert_eq!(a.metadata_usage(), before);
    let installed =
        root_binding_v2::install_v5(&mut a, c, target.branches, target.destination, &s, &m)
            .unwrap();
    assert_eq!(installed.grants.grants.handles().len(), 37);
    assert_eq!(installed.grants.branches.handles().len(), 37);
    let view = || crate::bootstrap_binding::InstalledView {
        branches: target.branches,
        destination: target.destination,
        private: installed.grants.branches.handles(),
        grants: installed.grants.grants.handles(),
    };
    root_binding_v2::revalidate_v5(&a, c, &s, &m, view()).unwrap();
    a.revoke(c, s[36].handle).unwrap();
    assert!(root_binding_v2::revalidate_v5(&a, c, &s, &m, view()).is_err());
}
fn foreign_epoch_token(image: &[u8]) -> incarnation::Token {
    let (mut a, d, s) = setup(image);
    let c = d.custody();
    let e = encoded(image, &a, c, &s);
    let m = root_manifest_v5::verify(e.bytes(), e.digest(), image).unwrap();
    let mut scheduler = Scheduler::new();
    let job = scheduler
        .create_job_with_limits(m.manifest().limits())
        .unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    let (c, target) = d.into_target(process, job);
    let catalogue = s.map(|s| CatalogEntry {
        selector: s.selector,
        root: s.handle,
        kind: s.kind,
    });
    let mut custodian = Custodian::new_root_v5(NonZeroU64::new(72).unwrap(), &m, c, &catalogue);
    let attempt = custodian.begin(0).unwrap();
    custodian
        .prepare(attempt, &mut a, &scheduler, target)
        .unwrap()
        .1
}
struct Model(Information);
// SAFETY: host-only owned admission metadata. No address is dereferenced and
// no physical frame ownership, guest execution or teardown is claimed.
#[allow(unsafe_code)]
unsafe impl LoadedExecutable for Model {
    fn information(&self) -> Information {
        self.0
    }
}
#[test]
fn same_custodian_publishes_exact_captured_v5_startup_and_refuses_replay_wrong_formats() {
    for corrupt in 0..6 {
        let image = elf();
        let (mut a, d, sources) = setup(&image);
        let c = d.custody();
        let e = encoded(&image, &a, c, &sources);
        let m = root_manifest_v5::verify(e.bytes(), e.digest(), &image).unwrap();
        let mut scheduler = Scheduler::new();
        let job = scheduler
            .create_job_with_limits(m.manifest().limits())
            .unwrap();
        let process = scheduler.create_held_process(job).unwrap();
        let thread = scheduler.create_thread(process).unwrap();
        let (c, target) = d.into_target(process, job);
        let catalogue = sources.map(|s| CatalogEntry {
            selector: s.selector,
            root: s.handle,
            kind: s.kind,
        });
        let mut custodian = Custodian::new_root_v5(NonZeroU64::new(71).unwrap(), &m, c, &catalogue);
        let attempt = custodian.begin(0).unwrap();
        let (mut binding, token) = custodian
            .prepare(attempt, &mut a, &scheduler, target)
            .unwrap();
        assert_eq!(
            binding
                .bootstrap_record_v5(foreign_epoch_token(&image))
                .err(),
            Some(incarnation::Error::StaleToken)
        );
        assert!(custodian.begin(1).is_err());
        assert!(binding.prepare(&mut a, &scheduler, target).is_err());
        let bytes = binding.bootstrap_record_v5(token).unwrap();
        let parsed = v5::FullGraph::parse(&bytes).unwrap();
        assert_eq!(
            (
                parsed.context().epoch,
                parsed.context().incarnation,
                parsed.context().process
            ),
            (71, 1, process.diagnostic_id())
        );
        assert_eq!(
            parsed.context().authority,
            m.manifest().expected_authority_digest()
        );
        assert_eq!(parsed.grants().len(), 37);
        assert_eq!(
            binding
                .grants(token)
                .unwrap()
                .iter()
                .map(|h| h.0)
                .collect::<std::vec::Vec<_>>(),
            parsed
                .grants()
                .map(|g| g.handle)
                .collect::<std::vec::Vec<_>>()
        );
        assert!(binding.bootstrap_record_v4(token).is_err());
        assert!(binding.bootstrap_record_v2(token).is_err());
        assert!(binding.bootstrap_record_native(token).is_err());
        assert_eq!(binding.bootstrap_record(token).unwrap(), None);
        let record = crate::startup_record::Record::root_v5(&bytes).unwrap();
        record.check_layout(StartupLayout::RootV5).unwrap();
        for layout in [
            StartupLayout::RootV4,
            StartupLayout::RootV2,
            StartupLayout::ServiceV1,
            StartupLayout::ServiceV5,
        ] {
            assert!(record.check_layout(layout).is_err());
        }
        assert!(ev_userspace_contract::root_v4::FullGraph::parse(&bytes).is_err());
        let plan = binding.executable(token).unwrap();
        assert_eq!(plan.startup_layout().bytes(), Some(1104));
        scheduler
            .charge_frames(job, plan.required_frames())
            .unwrap();
        let mut info = Information {
            process,
            manifest: m.manifest().digest(),
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames: plan.required_frames(),
            startup: Some(Startup {
                address: plan.bootstrap_page().unwrap(),
                bytes: 1104,
                digest: Sha256::digest(bytes).into(),
            }),
        };
        match corrupt {
            1 => info.startup.as_mut().unwrap().bytes = 912,
            2 => info.startup.as_mut().unwrap().digest[0] ^= 1,
            3 => info.startup = None,
            4 => info.startup.as_mut().unwrap().address += 4096,
            5 => {
                a.revoke(c, sources[36].handle).unwrap();
            }
            _ => (),
        }
        let result = binding.activate(&a, &mut scheduler, token, thread, Model(info));
        if corrupt == 0 {
            let active = result.unwrap_or_else(|r| panic!("{:?}", r.error));
            custodian.confirm_active(&active).unwrap();
            assert_eq!(scheduler.dispatch(0).unwrap().unwrap().process, process);
            assert!(custodian.begin(2).is_err());
        } else {
            let rejected = result.err().unwrap();
            assert!(matches!(
                rejected.error,
                incarnation::Error::ImageMismatch | incarnation::Error::Binding(_)
            ));
            custodian.report_failure(&rejected.binding).unwrap();
            assert!(custodian.begin(2).is_err());
            assert!(scheduler.held_process_job(process).is_ok());
            assert_eq!(scheduler.dispatch(0), Ok(None));
        }
    }
}
#[test]
fn v5_root_240_ceiling_and_reserved_shared_ranges_refuse_before_physical_allocation() {
    for (count, expected) in [(231, None), (232, Some(crate::executable::Error::Capacity))] {
        let image = crate::executable::m8::tests::elf(&[(2, count), (256, 8)]);
        let b = seed(&image);
        let m = root_manifest_v5::verify(&b, Sha256::digest(b).into(), &image).unwrap();
        let plan = Image::from_root_v5(&m);
        assert_eq!(plan.as_ref().err().copied(), expected);
        if let Ok(plan) = plan {
            assert_eq!(plan.pages().count(), 240);
            assert_eq!(plan.required_frames(), 246);
            assert_eq!(plan.layout(), crate::executable::LayoutReservation::Legacy);
        }
    }
    for page in [
        255, 264, 303, 304, 366, 367, 368, 382, 383, 384, 446, 447, 448, 498, 499, 500, 501, 502,
        503, 504, 505, 508, 509,
    ] {
        let segments = if page < 256 {
            std::vec![(page, 1), (256, 8)]
        } else {
            std::vec![(256, 8), (page, 1)]
        };
        let image = crate::executable::m8::tests::elf(&segments);
        let b = seed(&image);
        let m = root_manifest_v5::verify(&b, Sha256::digest(b).into(), &image).unwrap();
        assert_eq!(
            Image::from_root_v5(&m).err(),
            Some(crate::executable::Error::Address),
            "page{page}"
        );
    }
}

struct SharedRam(std::vec::Vec<u8>);
// SAFETY: host-only byte pages are indexed by the exact allocator-owned frame
// identities. This validates actual portable ownership/readback, not hardware.
#[allow(unsafe_code)]
unsafe impl crate::memory_extent::RamAccess for SharedRam {
    type Error = ();
    fn write(
        &mut self,
        frame: &crate::memory::PhysicalFrame,
        byte: usize,
        value: u8,
    ) -> Result<(), ()> {
        let at = (frame.start() - 4096) as usize + byte;
        self.0[at] = value;
        Ok(())
    }
    fn read(&mut self, frame: &crate::memory::PhysicalFrame, byte: usize) -> Result<u8, ()> {
        Ok(self.0[(frame.start() - 4096) as usize + byte])
    }
}
#[test]
fn selected_root_admission_accounts_only_exact_live_shared_owners_and_preserves_old_frame_rule() {
    use crate::{
        memory::BootstrapFrames,
        memory_extent::{
            M8SharedExtent as MemoryExtent, M8SharedUninitializedRam as UninitializedRam,
        },
        scheduler::Limits,
    };
    use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
    //0 exact,1wrongJob,2omittedOwner,3unchangedlegacyAPI,4unownedCharge,
    //5ownerUnderWrongSource,6actual79pageCurrentBank. Failures retain held Root.
    for case in 0..7 {
        let count = if case == 6 { 79 } else { 2 };
        let owner_index = if case == 6 {
            v5::Role::PackageCurrent.selector() as usize - 1
        } else {
            0
        };
        let image = elf();
        let (mut a, domains, mut sources) = setup(&image);
        let c = domains.custody();
        let mut scheduler = Scheduler::new();
        let l = v5::ROOT_LIMITS;
        let job = scheduler
            .create_job_with_limits(Limits::new(l[0], l[1], l[2], l[3]))
            .unwrap();
        let charged = if case == 1 {
            scheduler
                .create_job_with_limits(Limits::new(1000, 8, 1, 1))
                .unwrap()
        } else {
            job
        };
        let mut allocator = BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: 4096,
                end: (count as u64 + 1) * 4096,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        );
        let mut ram = SharedRam(std::vec![0xa5; count * 4096]);
        let initialized =
            UninitializedRam::allocate(&mut allocator, &mut scheduler, charged, count)
                .unwrap_or_else(|e| panic!("{:?}", e.error))
                .initialize(&mut ram)
                .unwrap_or_else(|e| panic!("{:?}", e.error));
        a.destroy(c, sources[owner_index].handle).unwrap();
        a.close(c, sources[owner_index].handle).unwrap();
        let (extent, cap) = MemoryExtent::publish(&mut a, c, initialized, &allocator, &scheduler)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        sources[owner_index].handle = cap;
        let encoded = encoded(&image, &a, c, &sources);
        let manifest = root_manifest_v5::verify(encoded.bytes(), encoded.digest(), &image).unwrap();
        let process = scheduler.create_held_process(job).unwrap();
        let thread = scheduler.create_thread(process).unwrap();
        let (c, target) = domains.into_target(process, job);
        let catalogue = sources.map(|x| CatalogEntry {
            selector: x.selector,
            root: x.handle,
            kind: x.kind,
        });
        let mut custodian =
            Custodian::new_root_v5(NonZeroU64::new(805).unwrap(), &manifest, c, &catalogue);
        let attempt = custodian.begin(0).unwrap();
        let (mut binding, token) = custodian
            .prepare(attempt, &mut a, &scheduler, target)
            .unwrap();
        let startup = binding.bootstrap_record_v5(token).unwrap();
        let plan = binding.executable(token).unwrap();
        scheduler
            .charge_frames(job, plan.required_frames())
            .unwrap();
        if case == 4 {
            scheduler.charge_frames(job, 1).unwrap();
        }
        let model = Model(Information {
            process,
            manifest: manifest.manifest().digest(),
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames: plan.required_frames(),
            startup: Some(Startup {
                address: plan.bootstrap_page().unwrap(),
                bytes: startup.len(),
                digest: Sha256::digest(startup).into(),
            }),
        });
        let mut owners: [Option<MemoryExtent>; 37] = core::array::from_fn(|_| None);
        owners[if case == 5 { 1 } else { owner_index }] = Some(extent);
        let empty = core::array::from_fn(|_| None);
        let result = if case == 3 {
            binding.activate(&a, &mut scheduler, token, thread, model)
        } else {
            binding.activate_root_v5(
                &a,
                &mut scheduler,
                token,
                thread,
                model,
                &allocator,
                if case == 2 { &empty } else { &owners },
            )
        };
        if case == 0 || case == 6 {
            let active = result.unwrap_or_else(|e| panic!("{:?}", e.error));
            custodian.confirm_active(&active).unwrap();
            assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, thread);
        } else {
            let rejected = result
                .err()
                .expect("unproved shared charge must preserve hold");
            assert!(matches!(
                rejected.error,
                incarnation::Error::SharedBacking
                    | incarnation::Error::Scheduler(crate::scheduler::Error::Admission)
            ));
            assert_eq!(scheduler.held_process_job(process), Ok(job));
            assert_eq!(scheduler.dispatch(0), Ok(None));
        }
        assert_eq!(allocator.remaining_frames(), 0);
        assert_eq!(
            owners
                .iter()
                .flatten()
                .map(MemoryExtent::pages)
                .sum::<usize>(),
            count
        );
    }
}

#[test]
fn v5_factory_identity_dry_run_and_instance_transcripts_are_independently_closed() {
    use crate::capability::Kind;
    let expected = root_producer_v5::planned_identities().unwrap();
    let mut a = Authority::for_workspace_profile();
    let c = a.create_workspace_control_space().unwrap();
    a.create_workspace_control_space().unwrap();
    a.create_workspace_control_space().unwrap();
    let actual = core::array::from_fn(|index| {
        let spec = v5::ROLES[index];
        let kind = root_manifest_v2::kind(spec.kind).unwrap();
        let cap = a
            .create_root(c, kind, root_producer_v5::source_rights(spec.role))
            .unwrap();
        let access = a.authorize(c, cap, kind, Rights::DERIVE).unwrap();
        Identity {
            object: access.identity() as u64,
            lineage: access.lineage_root() as u64,
        }
    });
    assert_eq!(actual, expected);
    assert_eq!(a.metadata_usage().3, 37);
    assert_eq!(
        root_producer_v5::source_rights(v5::Role::CreatorJob),
        Rights::from_bits(481).unwrap()
    );
    assert_ne!(
        root_producer_v5::role_shape_digest(graph::ImageSlot::Editor),
        root_producer_v5::role_shape_digest(graph::ImageSlot::Shell)
    );
    assert_ne!(
        root_producer_v5::instance_binding_digest(graph::Child::EditorOne),
        root_producer_v5::instance_binding_digest(graph::Child::EditorTwo)
    );
    assert!(
        v5::ROLES
            .iter()
            .any(|r| root_manifest_v2::kind(r.kind) == Some(Kind::IoPorts))
    );
}
