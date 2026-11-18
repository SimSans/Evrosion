//! Portable authority/admission policy tests, not a real V4 loader/VM proof.
use crate::{
    bootstrap_binding::CatalogEntry,
    capability::{Authority, Kind, Rights, SpaceId},
    custodian::Custodian,
    incarnation,
    loaded_image::{Information, LoadedExecutable, Startup},
    root_binding_v2::{self, Source},
    root_factory_v2::RootDomains,
    root_manifest_v2, root_manifest_v4, root_producer_v4,
    scheduler::Scheduler,
};
use core::num::NonZeroU64;
use ev_userspace_contract::root_v4;
use sha2::{Digest, Sha256};
const IMAGE: &[u8] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
fn sources(a: &mut Authority, custody: SpaceId) -> [Source; root_v4::CURRENT_GRANTS] {
    core::array::from_fn(|i| {
        let spec = root_v4::ROLES[i];
        let kind = root_manifest_v2::kind(spec.kind).unwrap();
        let rights = Rights::from_bits(spec.rights).unwrap();
        Source {
            selector: spec.role.selector(),
            kind,
            handle: a
                .create_root(
                    custody,
                    kind,
                    rights | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL,
                )
                .unwrap(),
        }
    })
}
fn description(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source; root_v4::CURRENT_GRANTS],
) -> root_producer_v4::Description {
    root_producer_v4::Description::full_graph(
        root_v4::ROOT_LIMITS,
        3,
        60_000,
        core::array::from_fn(|i| {
            let access = a
                .authorize(custody, sources[i].handle, sources[i].kind, Rights::DERIVE)
                .unwrap();
            root_producer_v4::Identity {
                object: access.identity() as u64,
                lineage: access.lineage_root() as u64,
            }
        }),
    )
    .unwrap()
    .bind_catalogue([7; 32])
}
#[test]
fn v4_manifest_producer_is_canonical_and_legacy_verifier_never_accepts_it() {
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let custody = domains.custody();
    let sources = sources(&mut a, custody);
    let d = description(&a, custody, &sources);
    let e = root_producer_v4::encode_current(IMAGE, &d).unwrap();
    assert_eq!(e.bytes().len(), 1136);
    let m = root_manifest_v4::verify(e.bytes(), e.digest(), IMAGE).unwrap();
    assert_eq!(m.manifest().grants().count(), 29);
    assert_eq!(m.manifest().startup_bytes(), 912);
    assert_eq!(
        m.manifest().expected_authority_digest(),
        d.authority_digest()
    );
    assert_eq!(
        m.manifest().authority_domain(),
        root_manifest_v4::AUTHORITY_DOMAIN
    );
    assert!(root_manifest_v2::verify(e.bytes(), e.digest(), IMAGE).is_err());
    assert!(root_manifest_v4::verify(e.bytes(), [0; 32], IMAGE).is_err());
    assert!(root_manifest_v4::verify(e.bytes(), e.digest(), b"other actual image").is_err());
    let old = crate::root_producer_v2::Description::full_native_graph(
        [16_384, 512, 1, 1],
        3,
        60_000,
        core::array::from_fn(|i| root_producer_v4::Identity {
            object: i as u64,
            lineage: i as u64,
        }),
    )
    .unwrap()
    .bind_catalogue([7; 32]);
    let old = crate::root_producer_v2::encode_native(IMAGE, &old).unwrap();
    assert!(root_manifest_v4::verify(old.bytes(), old.digest(), IMAGE).is_err());
}
#[test]
fn v4_manifest_rejects_reserved_constraints_roles_and_spare_count_after_rehash() {
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let c = domains.custody();
    let s = sources(&mut a, c);
    let d = description(&a, c, &s);
    let e = root_producer_v4::encode_current(IMAGE, &d).unwrap();
    for at in [
        0,
        48,
        113,
        119,
        161,
        167,
        168,
        170,
        172,
        174,
        root_v4::MANIFEST_HEADER + 8,
        root_v4::MANIFEST_HEADER + 9,
        root_v4::MANIFEST_HEADER + 10,
        root_v4::MANIFEST_HEADER + 12,
        root_v4::MANIFEST_HEADER + 16,
        e.bytes().len() - 1,
    ] {
        let mut b = [0; root_v4::MANIFEST_CURRENT_BYTES];
        b.copy_from_slice(e.bytes());
        b[at] ^= 0x80;
        assert!(
            root_manifest_v4::verify(&b, Sha256::digest(b).into(), IMAGE).is_err(),
            "offset={at}"
        );
    }
    let mut b = [0u8; root_manifest_v4::MAX_BYTES];
    b[..e.bytes().len()].copy_from_slice(e.bytes());
    b[160] = 32;
    for i in 29..32 {
        let at = root_v4::MANIFEST_HEADER + i * 32;
        b[at..at + 8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        b[at + 8] = 1;
        b[at + 10] = 1;
    }
    assert!(matches!(
        root_manifest_v4::verify(&b, Sha256::digest(b).into(), IMAGE),
        Err(root_manifest_v4::Error::Roles)
    ));
}
#[test]
fn actual_twenty_nine_sources_install_atomically_and_revalidate_live_lineage() {
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let c = domains.custody();
    let s = sources(&mut a, c);
    let d = description(&a, c, &s);
    let e = root_producer_v4::encode_current(IMAGE, &d).unwrap();
    let m = root_manifest_v4::verify(e.bytes(), e.digest(), IMAGE).unwrap();
    let mut scheduler = Scheduler::new();
    let job = scheduler
        .create_job_with_limits(m.manifest().limits())
        .unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    let (c, target) = domains.into_target(process, job);
    let installed =
        root_binding_v2::install_v4(&mut a, c, target.branches, target.destination, &s, &m)
            .unwrap();
    assert_eq!(installed.grants.grants.handles().len(), 29);
    let view = || crate::bootstrap_binding::InstalledView {
        branches: target.branches,
        destination: target.destination,
        private: installed.grants.branches.handles(),
        grants: installed.grants.grants.handles(),
    };
    root_binding_v2::revalidate_v4(&a, c, &s, &m, view()).unwrap();
    a.revoke(c, s[26].handle).unwrap();
    assert!(root_binding_v2::revalidate_v4(&a, c, &s, &m, view()).is_err());
}
#[test]
fn v4_capacity_alias_and_forged_generations_refuse_without_partial_install() {
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let c = domains.custody();
    let s = sources(&mut a, c);
    let d = description(&a, c, &s);
    let e = root_producer_v4::encode_current(IMAGE, &d).unwrap();
    let m = root_manifest_v4::verify(e.bytes(), e.digest(), IMAGE).unwrap();
    let branches = a.create_space().unwrap();
    let destination = a.create_space().unwrap();
    let before = a.metadata_usage();
    assert!(matches!(
        root_binding_v2::install_v4(&mut a, c, branches, destination, &s, &m),
        Err(root_binding_v2::Error::Capacity)
    ));
    assert_eq!(a.metadata_usage(), before);
    let mut scheduler = Scheduler::new();
    let job = scheduler
        .create_job_with_limits(m.manifest().limits())
        .unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    let (c, target) = domains.into_target(process, job);
    let mut alias = s;
    // An old AppFile object cannot stand in for dedicated NoteWindow merely
    // because it is supplied under a different numeric selector.
    alias[27].handle = s[11].handle;
    assert!(matches!(
        root_binding_v2::install_v4(&mut a, c, target.branches, target.destination, &alias, &m),
        Err(root_binding_v2::Error::Alias)
    ));
    assert_eq!(a.metadata_usage(), before);
    let alternate = a
        .derive(
            c,
            s[11].handle,
            c,
            Rights::from_bits(root_v4::ROLES[27].rights).unwrap() | Rights::CONTROL,
        )
        .unwrap();
    let before = a.metadata_usage();
    let mut alternate_note = s;
    alternate_note[27].handle = alternate;
    assert_ne!(alternate_note[27].handle, s[11].handle);
    assert!(matches!(
        root_binding_v2::install_v4(
            &mut a,
            c,
            target.branches,
            target.destination,
            &alternate_note,
            &m
        ),
        Err(root_binding_v2::Error::NotRoot)
    ));
    assert_eq!(a.metadata_usage(), before);
    let mut forged = s;
    forged[27].selector = 99;
    assert!(
        root_binding_v2::install_v4(&mut a, c, target.branches, target.destination, &forged, &m)
            .is_err()
    );
    assert_eq!(a.metadata_usage(), before);
    a.destroy(c, s[27].handle).unwrap();
    a.close(c, s[27].handle).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    let replacement = a
        .create_root(
            c,
            Kind::Memory,
            Rights::from_bits(root_v4::ROLES[27].rights).unwrap()
                | Rights::DERIVE
                | Rights::TRANSFER
                | Rights::REVOKE
                | Rights::CONTROL,
        )
        .unwrap();
    let mut stale = s;
    stale[27].handle = replacement;
    let before = a.metadata_usage();
    assert!(matches!(
        root_binding_v2::install_v4(&mut a, c, target.branches, target.destination, &stale, &m),
        Err(root_binding_v2::Error::Measurement)
    ));
    assert_eq!(a.metadata_usage(), before);
}
struct Model(Information, bool);
// SAFETY: host-only admission policy facts. No real CR3/frame permissions,
// hardware page ownership, device quiescence or executing V4 Root is claimed.
#[allow(unsafe_code)]
unsafe impl LoadedExecutable for Model {
    fn information(&self) -> Information {
        self.0
    }
    fn layout(&self) -> crate::executable::LayoutReservation {
        if self.1 {
            crate::executable::LayoutReservation::DisplayApertureV1
        } else {
            crate::executable::LayoutReservation::Legacy
        }
    }
}
#[test]
fn same_custodian_admits_only_exact_loaded_v4_record_and_preserves_single_root() {
    for corrupt in 0..6 {
        let mut a = Authority::new();
        let domains = RootDomains::allocate(&mut a).unwrap();
        let c = domains.custody();
        let s = sources(&mut a, c);
        let d = description(&a, c, &s);
        let e = root_producer_v4::encode_current(IMAGE, &d).unwrap();
        let m = root_manifest_v4::verify(e.bytes(), e.digest(), IMAGE).unwrap();
        let mut scheduler = Scheduler::new();
        let job = scheduler
            .create_job_with_limits(m.manifest().limits())
            .unwrap();
        let process = scheduler.create_held_process(job).unwrap();
        let thread = scheduler.create_thread(process).unwrap();
        let (c, target) = domains.into_target(process, job);
        let catalogue = s.map(|source| CatalogEntry {
            selector: source.selector,
            root: source.handle,
            kind: source.kind,
        });
        let mut custodian = Custodian::new_root_v4(NonZeroU64::new(44).unwrap(), &m, c, &catalogue);
        let attempt = custodian.begin(0).unwrap();
        let (mut binding, token) = custodian
            .prepare(attempt, &mut a, &scheduler, target)
            .unwrap();
        let bytes = binding.bootstrap_record_v4(token).unwrap();
        let parsed = root_v4::FullGraph::parse(&bytes).unwrap();
        assert_eq!(parsed.context().process, process.diagnostic_id());
        assert_eq!(parsed.context().incarnation, 1);
        assert!(binding.bootstrap_record_v2(token).is_err());
        assert!(binding.bootstrap_record_native(token).is_err());
        assert_eq!(binding.bootstrap_record(token).unwrap(), None);
        let plan = binding.executable(token).unwrap();
        assert_eq!(
            plan.startup_layout(),
            crate::executable::StartupLayout::RootV4
        );
        assert_eq!(plan.startup_layout().bytes(), Some(912));
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
                bytes: 912,
                digest: Sha256::digest(bytes).into(),
            }),
        };
        match corrupt {
            1 => info.startup.as_mut().unwrap().bytes = 720,
            2 => info.startup.as_mut().unwrap().digest[0] ^= 1,
            3 => info.startup = None,
            4 => info.startup.as_mut().unwrap().address += 4096,
            _ => {}
        }
        let result = binding.activate(&a, &mut scheduler, token, thread, Model(info, corrupt == 5));
        if corrupt == 0 {
            let active = result.unwrap_or_else(|r| panic!("modelv4 rejected:{:?}", r.error));
            custodian.confirm_active(&active).unwrap();
            assert_eq!(scheduler.dispatch(0).unwrap().unwrap().process, process);
            assert!(custodian.begin(1).is_err());
        } else {
            let rejected = match result {
                Err(rejected) => rejected,
                Ok(_) => panic!("corrupt v4 model admitted"),
            };
            assert_eq!(rejected.error, incarnation::Error::ImageMismatch);
            custodian.report_failure(&rejected.binding).unwrap();
            assert!(custodian.begin(1).is_err());
            assert_eq!(scheduler.dispatch(0), Ok(None));
        }
    }
}
#[test]
fn typed_startup_record_v4_cannot_cross_legacy_loader_layouts() {
    let context = ev_userspace_contract::Context {
        epoch: 1,
        incarnation: 1,
        process: 1,
        limits: root_v4::ROOT_LIMITS,
        manifest: [4; 32],
        authority: [5; 32],
    };
    let bytes =
        root_v4::encode_full_graph(context, core::array::from_fn(|i| 100 + i as u64)).unwrap();
    let record = crate::startup_record::Record::root_v4(&bytes).unwrap();
    assert_eq!(record.bytes().len(), 912);
    assert!(
        record
            .check_layout(crate::executable::StartupLayout::RootV4)
            .is_ok()
    );
    assert!(
        record
            .check_layout(crate::executable::StartupLayout::RootV2)
            .is_err()
    );
    assert!(
        record
            .check_layout(crate::executable::StartupLayout::ServiceV1)
            .is_err()
    );
}

#[test]
fn v4_boot_sibling_accounting_admits_graph_and_one_held_replacement_only() {
    use crate::scheduler::{Error, Limits, Resource};
    let mut s = Scheduler::new();
    let boot = s
        .create_job_with_limits(Limits::new(262144, 1024, 10, 10))
        .unwrap();
    let [cpu, frames, processes, threads] = root_v4::ROOT_LIMITS;
    let root = s
        .create_child_job(boot, Limits::new(cpu, frames, processes, threads))
        .unwrap();
    let rp = s.create_held_process(root).unwrap();
    s.create_thread(rp).unwrap();
    for child in root_v4::graph::CHILDREN {
        let [a, b, c, d] = child.limits();
        let job = s.create_child_job(boot, Limits::new(a, b, c, d)).unwrap();
        s.charge_frames(job, child.frame_limit()).unwrap();
        let p = s.create_held_process(job).unwrap();
        s.create_thread(p).unwrap();
    }
    assert_eq!(s.usage(boot, Resource::Processes), Ok(9));
    assert_eq!(s.usage(boot, Resource::Threads), Ok(9));
    assert_eq!(s.usage(root, Resource::Processes), Ok(1));
    assert_eq!(s.usage(root, Resource::Threads), Ok(1));
    let replacement = s
        .create_child_job(boot, Limits::new(16384, 32, 1, 1))
        .unwrap();
    s.charge_frames(replacement, 32).unwrap();
    let p = s.create_held_process(replacement).unwrap();
    s.create_thread(p).unwrap();
    let extra = s
        .create_child_job(boot, Limits::new(16384, 32, 1, 1))
        .unwrap();
    let before = s.metadata_usage();
    assert_eq!(s.create_held_process(extra), Err(Error::Budget));
    assert_eq!(s.metadata_usage(), before);
    assert_eq!(s.create_thread(rp), Err(Error::Budget));
    assert_eq!(s.metadata_usage(), before);
    assert_eq!(s.usage(boot, Resource::Processes), Ok(10));
    assert_eq!(s.usage(boot, Resource::Threads), Ok(10));
    assert_eq!(s.usage(root, Resource::Processes), Ok(1));
    assert_eq!(s.usage(root, Resource::Threads), Ok(1));
    // The actual trusted Registry CreatorJob names Boot: child Jobs are
    // siblings of RootJob. This is only the Boot private-image subtotal, not
    // a Root512 reservation or a complete physical/shared/peak RAM proof.
    let bound = crate::executable::ROOT_V4_MAX_PRIVATE_FRAMES
        + root_v4::graph::CHILDREN
            .into_iter()
            .map(|c| c.frame_limit())
            .sum::<u64>()
        + 32;
    assert_eq!(bound, 566);
    assert!(bound < 1024);
    let own = crate::executable::ROOT_V4_MAX_PRIVATE_FRAMES;
    s.charge_frames(root, own).unwrap();
    assert_eq!(s.usage(root, Resource::Frames), Ok(own));
    assert_eq!(s.usage(boot, Resource::Frames), Ok(bound));
    assert!(own < root_v4::ROOT_LIMITS[1]);
    // Model only these separately charged owners, not all physical peak RAM.
    // Dynamic owners do not consume the initial loader ceiling or grant quota.
    let dynamic = root_v4::dynamic::EXTERNAL_FRAMES
        + (root_v4::dynamic::OWNERS * root_v4::dynamic::WINDOW_PAGES) as u64;
    s.charge_frames(root, dynamic).unwrap();
    assert_eq!(s.usage(root, Resource::Frames), Ok(376));
    assert_eq!(s.usage(boot, Resource::Frames), Ok(696));
    // Exact remaining Root capacity succeeds; the very next frame refuses
    // without a partial ancestor charge or metadata mutation.
    assert_eq!(root_v4::ROOT_LIMITS[1] - 376, 136);
    s.charge_frames(root, 136).unwrap();
    assert_eq!(s.usage(root, Resource::Frames), Ok(512));
    assert_eq!(s.usage(boot, Resource::Frames), Ok(832));
    let before = s.metadata_usage();
    assert_eq!(s.charge_frames(root, 1), Err(Error::Budget));
    assert_eq!(s.metadata_usage(), before);
    assert_eq!(s.usage(root, Resource::Frames), Ok(512));
    assert_eq!(s.usage(boot, Resource::Frames), Ok(832));
    s.release_frames(root, 136).unwrap();
    assert_eq!(s.usage(root, Resource::Frames), Ok(376));
    assert_eq!(s.usage(boot, Resource::Frames), Ok(696));
    // Saturating the real ancestor must also refuse an otherwise legal child.
    s.charge_frames(boot, 1024 - 696).unwrap();
    assert_eq!(s.charge_frames(root, 1), Err(Error::Budget));
    assert_eq!(s.usage(root, Resource::Frames), Ok(376));
    assert_eq!(s.usage(boot, Resource::Frames), Ok(1024));
}

#[test]
fn only_exact_v4_manifest_admits_240_pages_and_241_refuses_before_loading() {
    use crate::executable::{self, Image};
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let c = domains.custody();
    let s = sources(&mut a, c);
    let description = description(&a, c, &s);
    for pages in [
        64u64, 65, 96, 97, 101, 104, 105, 108, 109, 121, 124, 125, 165, 176, 177, 197, 198, 208,
        209, 219, 224, 225, 227, 232, 239, 240, 241,
    ] {
        let mut elf = [0; 8200];
        elf.copy_from_slice(IMAGE);
        // Keep exact file bytes, entry and nonoverlapping segment addresses;
        // expand only the RW segment's declared zero-initialized tail.
        elf[160..168].copy_from_slice(&((pages - 1) * 4096).to_le_bytes());
        let encoded = root_producer_v4::encode_current(&elf, &description).unwrap();
        let v4 = root_manifest_v4::verify(encoded.bytes(), encoded.digest(), &elf).unwrap();
        if pages <= 240 {
            let image = Image::from_root_v4(&v4).unwrap();
            assert_eq!(image.pages().count(), pages as usize);
            assert_eq!(image.required_frames(), pages + 6);
        } else {
            assert_eq!(
                Image::from_root_v4(&v4).err(),
                Some(executable::Error::Capacity)
            );
        }
        assert!(root_manifest_v2::verify(encoded.bytes(), encoded.digest(), &elf).is_err());

        let ordinary = crate::root_producer_v2::Description::full_graph(
            [16384, 512, 1, 1],
            3,
            60000,
            core::array::from_fn(|i| root_producer_v4::Identity {
                object: i as u64 + 1,
                lineage: i as u64 + 1,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        let ordinary = crate::root_producer_v2::encode_current(&elf, &ordinary).unwrap();
        let ordinary = root_manifest_v2::verify(ordinary.bytes(), ordinary.digest(), &elf)
            .unwrap()
            .current_profile()
            .unwrap();
        if pages <= 64 {
            assert_eq!(
                Image::from_root_manifest_v2(&ordinary)
                    .unwrap()
                    .pages()
                    .count(),
                pages as usize
            );
        } else {
            assert_eq!(
                Image::from_root_manifest_v2(&ordinary).err(),
                Some(executable::Error::Capacity)
            );
        }
        let native = crate::root_producer_v2::Description::full_native_graph(
            [16384, 512, 1, 1],
            3,
            60000,
            core::array::from_fn(|i| root_producer_v4::Identity {
                object: i as u64 + 1,
                lineage: i as u64 + 1,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        let native = crate::root_producer_v2::encode_native(&elf, &native).unwrap();
        let native = root_manifest_v2::verify(native.bytes(), native.digest(), &elf)
            .unwrap()
            .native_profile()
            .unwrap();
        if pages <= 96 {
            assert_eq!(
                Image::from_native_root(&native).unwrap().pages().count(),
                pages as usize
            );
        } else {
            assert_eq!(
                Image::from_native_root(&native).err(),
                Some(executable::Error::Capacity)
            );
        }
    }
    assert_eq!(
        (executable::MAX_IMAGE_PAGES, crate::user::MAX_PRIVATE_PAGES),
        (64, 68)
    );
    assert_eq!(
        (
            executable::NATIVE_ROOT_MAX_IMAGE_PAGES,
            executable::NATIVE_ROOT_MAX_PRIVATE_PAGES,
            executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES
        ),
        (96, 100, 102)
    );
    assert_eq!(
        (
            executable::ROOT_V4_MAX_IMAGE_PAGES,
            executable::ROOT_V4_MAX_PRIVATE_PAGES,
            executable::ROOT_V4_MAX_PRIVATE_FRAMES
        ),
        (240, 244, 246)
    );
}

#[test]
fn v4_mapping_owner_keeps_every_claim_on_full_refusal_unmap_and_retirement() {
    use crate::{
        mapping::MapError,
        memory::BootstrapFrames,
        user::{PrivateUserMappings, UserPermission},
    };
    use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
    let mut frames = BootstrapFrames::new(
        MemoryMap::validate([MemoryRegion {
            start: 4096,
            end: 248 * 4096,
            kind: MemoryKind::Usable,
        }])
        .unwrap(),
    );
    let total = frames.remaining_frames();
    let mut owner =
        PrivateUserMappings::<{ crate::executable::ROOT_V4_MAX_PRIVATE_PAGES }>::new(1).unwrap();
    for i in 0..244 {
        owner
            .map(
                owner.base() + (i + 1) * 4096,
                frames.allocate().unwrap(),
                UserPermission::ReadWrite,
            )
            .unwrap_or_else(|_| panic!("bounded V4 mapping"));
    }
    let extra = frames.allocate().unwrap();
    let physical = extra.start();
    let (error, extra) = owner
        .map(owner.base() + 245 * 4096, extra, UserPermission::ReadOnly)
        .unwrap_err();
    assert_eq!(error, MapError::Capacity);
    assert_eq!(extra.start(), physical);
    assert!(frames.owns(&extra));
    frames.reclaim(extra).unwrap();
    let removed = owner.unmap(owner.base() + 55 * 4096).unwrap();
    assert!(frames.owns(&removed));
    frames.reclaim(removed).unwrap();
    assert_eq!(owner.frames().count(), 243);
    for frame in owner.into_frames().into_iter().flatten() {
        frames.reclaim(frame).unwrap();
    }
    assert_eq!(frames.remaining_frames(), total);
}

#[test]
fn current_capacity_hashes_bind_metadata_and_rehashing_old_224_abi_cannot_admit_it() {
    const OLD_ABI: [u8; 32] = [
        0x9e, 0x90, 0x06, 0xbc, 0xb7, 0xdc, 0xf8, 0xbd, 0x61, 0xe7, 0xa4, 0xff, 0xcb, 0x6f, 0x32,
        0x1c, 0x3d, 0xe9, 0xd9, 0x33, 0x53, 0xc5, 0xce, 0x0e, 0x38, 0x29, 0xee, 0x6c, 0x89, 0x42,
        0x65, 0x50,
    ];
    const ADR94_ABI: [u8; 32] = [
        0xb8, 0x6c, 0x1e, 0x5c, 0x6f, 0xea, 0xe4, 0xb8, 0x6e, 0xc2, 0x01, 0x5e, 0xa9, 0xfe, 0xb5,
        0x89, 0xe7, 0x70, 0x19, 0x9d, 0xf9, 0xfb, 0x01, 0xf0, 0x34, 0xba, 0xdb, 0xe0, 0x22, 0x0a,
        0x1a, 0xde,
    ];
    const OLD_LAYOUT_SHA: [u8; 32] = [
        0xab, 0x0f, 0x05, 0x95, 0xb1, 0x40, 0x01, 0x16, 0x78, 0x73, 0xb8, 0xae, 0xd6, 0x0f, 0x32,
        0x65, 0x06, 0x20, 0xf0, 0xc7, 0xc8, 0x5b, 0xda, 0x51, 0x73, 0xd5, 0xf3, 0xe8, 0xa5, 0x9b,
        0xe4, 0xb2,
    ];
    assert_eq!(
        root_v4::ABI,
        <[u8; 32]>::from(Sha256::digest(root_v4::ABI_DESCRIPTION))
    );
    assert_eq!(
        root_v4::dynamic::DESCRIPTION_SHA256,
        <[u8; 32]>::from(Sha256::digest(root_v4::dynamic::DESCRIPTION))
    );
    let mut old_layout = root_v4::layout_description();
    old_layout[16..48].copy_from_slice(&OLD_ABI);
    for (offset, value) in [(952, 224u64), (960, 228), (968, 230)] {
        old_layout[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    // This was emitted by the actual old224 SDK, not derived as an expected
    // hash from the new function. Every other physical layout byte is bound.
    assert_eq!(<[u8; 32]>::from(Sha256::digest(old_layout)), OLD_LAYOUT_SHA);
    assert_eq!(
        root_v4::dynamic::layout_record(),
        [
            b'E', b'V', b'D', b'Y', b'N', b'P', b'0', b'1', 1, 0, 1, 0, 67, 0, 192, 0, 0, 1, 64, 0,
            2, 0, 52, 0
        ]
    );
    assert_eq!(
        ev_userspace_contract::ABI,
        [
            0x72, 0xcd, 0xbf, 0xdb, 0x85, 0xd6, 0xf8, 0xe1, 0x3e, 0xa3, 0xde, 0xac, 0xd9, 0x40,
            0xa4, 0x1a, 0xa9, 0x19, 0x04, 0x8c, 0x83, 0x7e, 0xe0, 0xda, 0x3e, 0xf6, 0x39, 0x48,
            0xa0, 0xbc, 0x71, 0x78
        ]
    );
    assert_eq!(root_v4::ROOT_LIMITS, [65536, 512, 10, 10]);
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let custody = domains.custody();
    let sources = sources(&mut a, custody);
    let encoded =
        root_producer_v4::encode_current(IMAGE, &description(&a, custody, &sources)).unwrap();
    assert!(root_manifest_v4::verify(encoded.bytes(), encoded.digest(), IMAGE).is_ok());
    for old_abi in [OLD_ABI, ADR94_ABI] {
        let mut bytes = [0; root_v4::MANIFEST_CURRENT_BYTES];
        bytes.copy_from_slice(encoded.bytes());
        bytes[48..80].copy_from_slice(&old_abi);
        assert!(matches!(
            root_manifest_v4::verify(&bytes, Sha256::digest(bytes).into(), IMAGE),
            Err(root_manifest_v4::Error::Abi)
        ));
    }
}

#[test]
fn exact_240_boundary_with_real_eight_page_stack_keeps_every_guard_and_permission() {
    use crate::{
        executable::{Error, Image},
        user::UserPermission,
    };
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let custody = domains.custody();
    let sources = sources(&mut a, custody);
    let description = description(&a, custody, &sources);
    for pages in [240u64, 241] {
        let mut elf = [0; 8200];
        elf.copy_from_slice(IMAGE);
        let base = u64::from_le_bytes(elf[80..88].try_into().unwrap()) & !((1u64 << 39) - 1);
        // Original RX page + enlarged RW zero tail + exact8-page RW stack.
        elf[56..58].copy_from_slice(&3u16.to_le_bytes());
        elf[160..168].copy_from_slice(&((pages - 1 - 8) * 4096).to_le_bytes());
        let at = 64 + 2 * 56;
        elf[at..at + 56].fill(0);
        elf[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        elf[at + 4..at + 8].copy_from_slice(&6u32.to_le_bytes());
        // Empty BSS still has a valid aligned file extent after the headers.
        elf[at + 8..at + 16].copy_from_slice(&8192u64.to_le_bytes());
        let stack = base + root_v4::ROOT_STACK_FIRST_PAGE * 4096;
        elf[at + 16..at + 24].copy_from_slice(&stack.to_le_bytes());
        elf[at + 24..at + 32].copy_from_slice(&stack.to_le_bytes());
        elf[at + 40..at + 48].copy_from_slice(&(root_v4::ROOT_STACK_PAGES * 4096).to_le_bytes());
        elf[at + 48..at + 56].copy_from_slice(&4096u64.to_le_bytes());
        let encoded = root_producer_v4::encode_current(&elf, &description).unwrap();
        let current = root_manifest_v4::verify(encoded.bytes(), encoded.digest(), &elf).unwrap();
        if pages == 241 {
            assert_eq!(Image::from_root_v4(&current).err(), Some(Error::Capacity));
            continue;
        }
        let plan = Image::from_root_v4(&current).unwrap();
        assert_eq!(plan.pages().count(), 240);
        assert_eq!(plan.required_frames(), 246);
        for index in (303..=367)
            .chain(383..=447)
            .chain([0, 255, 264, 505, 506, 507, 508, 509, 510, 511])
        {
            assert!(plan.pages().all(|p| p.address != base + index * 4096));
        }
        let mut zeros = [0; 4096];
        for index in 256..264 {
            let page = plan
                .pages()
                .find(|p| p.address == base + index * 4096)
                .unwrap();
            assert_eq!(page.permission, UserPermission::ReadWrite);
            page.copy_into(&mut zeros);
            assert_eq!(zeros, [0; 4096]);
        }
        assert!(
            plan.pages()
                .any(|p| p.permission == UserPermission::ReadExecute)
        );
    }
}
