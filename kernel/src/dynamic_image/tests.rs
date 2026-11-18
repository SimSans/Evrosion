extern crate std;
use super::*;
use crate::{
    bootstrap_binding::CatalogEntry,
    custodian::Custodian,
    incarnation::Active,
    loaded_image::{Information, LoadedExecutable, Startup},
    memory::PhysicalFrame,
    root_factory_v2::RootDomains,
    root_manifest_v4, root_producer_v4,
    scheduler::{Limits, Resource},
    service::{Registry, Role, ServiceImage},
};
use core::num::NonZeroU64;
use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
use ev_userspace_contract::root_v4;
use std::{collections::BTreeMap, vec, vec::Vec};
const ELF: &[u8] = include_bytes!("../../fixtures/bootstrap-static-v1.elf");
struct Model(Information);
// SAFETY: portable policy model only; no actual hardware/admitted Root claim.
#[allow(unsafe_code)]
unsafe impl LoadedExecutable for Model {
    fn information(&self) -> Information {
        self.0
    }
}
fn active(
    test: impl FnOnce(
        &mut Authority,
        &mut Scheduler,
        SpaceId,
        SpaceId,
        Handle,
        JobId,
        Active<'_, Model>,
    ),
) {
    let mut a = Authority::new();
    let domains = RootDomains::allocate(&mut a).unwrap();
    let c = domains.custody();
    let sources = core::array::from_fn::<_, { root_v4::CURRENT_GRANTS }, _>(|i| {
        let spec = root_v4::ROLES[i];
        let kind = crate::root_manifest_v2::kind(spec.kind).unwrap();
        let rights = Rights::from_bits(spec.rights).unwrap();
        crate::root_binding_v2::Source {
            selector: spec.role.selector(),
            kind,
            handle: a
                .create_root(
                    c,
                    kind,
                    rights | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL,
                )
                .unwrap(),
        }
    });
    let description = root_producer_v4::Description::full_graph(
        root_v4::ROOT_LIMITS,
        3,
        60_000,
        core::array::from_fn(|i| {
            let x = a
                .authorize(c, sources[i].handle, sources[i].kind, Rights::DERIVE)
                .unwrap();
            root_producer_v4::Identity {
                object: x.identity() as u64,
                lineage: x.lineage_root() as u64,
            }
        }),
    )
    .unwrap()
    .bind_catalogue([7; 32]);
    let encoded = root_producer_v4::encode_current(ELF, &description).unwrap();
    let manifest = root_manifest_v4::verify(encoded.bytes(), encoded.digest(), ELF).unwrap();
    let mut s = Scheduler::new();
    let boot = s
        .create_job_with_limits(Limits::new(262144, 1024, 10, 10))
        .unwrap();
    let job = s
        .create_child_job(boot, manifest.manifest().limits())
        .unwrap();
    let process = s.create_held_process(job).unwrap();
    let thread = s.create_thread(process).unwrap();
    let (c, target) = domains.into_target(process, job);
    let root = target.destination;
    let catalogue = sources.map(|x| CatalogEntry {
        selector: x.selector,
        root: x.handle,
        kind: x.kind,
    });
    let mut custodian =
        Custodian::new_root_v4(NonZeroU64::new(1).unwrap(), &manifest, c, &catalogue);
    let attempt = custodian.begin(0).unwrap();
    let (mut binding, token) = custodian.prepare(attempt, &mut a, &s, target).unwrap();
    let record = binding.bootstrap_record_v4(token).unwrap();
    let parsed = root_v4::FullGraph::parse(&record).unwrap();
    let creator = Handle(parsed.handle(root_v4::Role::CreatorJob));
    let plan = binding.executable(token).unwrap();
    s.charge_frames(job, plan.required_frames()).unwrap();
    let info = Information {
        process,
        manifest: manifest.manifest().digest(),
        entry: plan.entry(),
        stack: plan.stack_top(),
        root: 4096,
        frames: plan.required_frames(),
        startup: Some(Startup {
            address: plan.bootstrap_page().unwrap(),
            bytes: record.len(),
            digest: Sha256::digest(record).into(),
        }),
    };
    let root_image = binding
        .activate(&a, &mut s, token, thread, Model(info))
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    test(&mut a, &mut s, c, root, creator, job, root_image);
}
#[derive(Default)]
struct Ram {
    bytes: BTreeMap<u64, Vec<u8>>,
    fail: bool,
}
// SAFETY: model storage identifies each actual allocator frame by start; no MMIO.
#[allow(unsafe_code)]
unsafe impl RamAccess for Ram {
    type Error = ();
    fn write(&mut self, f: &PhysicalFrame, at: usize, b: u8) -> Result<(), ()> {
        if self.fail {
            return Err(());
        }
        self.bytes.entry(f.start()).or_insert_with(|| vec![0; 4096])[at] = b;
        Ok(())
    }
    fn read(&mut self, f: &PhysicalFrame, at: usize) -> Result<u8, ()> {
        if self.fail {
            return Err(());
        }
        Ok(self.bytes.get(&f.start()).ok_or(())?[at])
    }
}
struct View {
    physical: u64,
    bytes: Vec<u8>,
}
// SAFETY: immutable model snapshot exactly assembled from retained frame IDs
// after model writer detachment; not actual page tables, TLB or execution proof.
#[allow(unsafe_code)]
unsafe impl ReadOnlyRam for View {
    type Error = ();
    fn bytes(&self, p: u64, n: usize) -> Result<&[u8], ()> {
        if p != self.physical || n != self.bytes.len() {
            return Err(());
        }
        Ok(&self.bytes)
    }
}
#[derive(Default)]
struct Maps {
    installed: bool,
    fail_install: bool,
    fail_remove: bool,
    remove_calls: usize,
}
// SAFETY: explicit portable alias/debt model; no physical quiescence claim.
#[allow(unsafe_code)]
unsafe impl Mappings for Maps {
    type Error = ();
    fn install(&mut self, _: &MemoryExtent, _: &ExtentLease) -> Result<(), ()> {
        self.installed = true;
        if self.fail_install { Err(()) } else { Ok(()) }
    }
    fn remove_writers(&mut self, _: &MemoryExtent, _: &ExtentLease) -> Result<(), ()> {
        self.remove_calls += 1;
        if self.fail_remove {
            return Err(());
        }
        self.installed = false;
        Ok(())
    }
}
fn allocator(pages: u64) -> BootstrapFrames {
    BootstrapFrames::new(
        MemoryMap::validate([MemoryRegion {
            start: 4096,
            end: (pages + 1) * 4096,
            kind: MemoryKind::Usable,
        }])
        .unwrap(),
    )
}
fn app_descriptor() -> [u8; 32] {
    let mut grants = root_v4::graph::grants(root_v4::graph::Child::App);
    let roles: [Role; 7] = core::array::from_fn(|i| {
        let g = grants.next().unwrap();
        Role {
            selector: i as u64 + 1,
            kind: match g.kind {
                1 => Kind::Memory,
                2 => Kind::Endpoint,
                _ => panic!(),
            },
            rights: Rights::from_bits(g.rights).unwrap(),
        }
    });
    ServiceImage::verify(
        ELF,
        Sha256::digest(ELF).into(),
        Limits::new(16384, 32, 1, 1),
        &roles,
    )
    .unwrap()
    .digest()
}
#[test]
fn sdk_closed_app7_transcript_matches_independently_checked_core_service_policy() {
    let image_sha = Sha256::digest(ELF).into();
    let mut h = Sha256::new();
    root_v4::dynamic::app_descriptor_transcript(&image_sha, |b| h.update(b));
    assert_eq!(<[u8; 32]>::from(h.finalize()), app_descriptor());
    let mut changed = image_sha;
    changed[0] ^= 1;
    let mut h = Sha256::new();
    root_v4::dynamic::app_descriptor_transcript(&changed, |b| h.update(b));
    assert_ne!(<[u8; 32]>::from(h.finalize()), app_descriptor());
}
fn package() -> (Specification, Vec<u8>) {
    let mut bytes = vec![0x42; 64];
    bytes.extend_from_slice(ELF);
    let spec = Specification {
        bytes: bytes.len(),
        sha256: Sha256::digest(&bytes).into(),
        elf_offset: 64,
        elf_bytes: ELF.len(),
        elf_sha256: Sha256::digest(ELF).into(),
        package: [8; 32],
        abi: ev_userspace_contract::ABI,
        descriptor: app_descriptor(),
    };
    (spec, bytes)
}
fn fill(stage: &Staging, ram: &mut Ram, payload: &[u8]) {
    let lease = stage.lease.as_ref().unwrap();
    let pages: Vec<_> = stage.extent.physical_pages(lease).unwrap().collect();
    for (i, byte) in payload.iter().copied().enumerate() {
        ram.bytes.get_mut(&pages[i / 4096]).unwrap()[i % 4096] = byte;
    }
}
fn seal(
    a: &mut Authority,
    s: &Scheduler,
    permit: &RootPermit<'_, '_>,
    mut stage: Staging,
    ram: &mut Ram,
    maps: &mut Maps,
    payload: &[u8],
) -> SealedImage {
    stage.attach(a, s, permit, 1, maps).unwrap();
    fill(&stage, ram, payload);
    for (i, chunk) in payload.chunks(CHUNK_BYTES).enumerate() {
        stage
            .chunk_written(a, s, permit, 2, i * CHUNK_BYTES, chunk.len())
            .unwrap();
    }
    let mut sealing = stage
        .seal(a, s, permit, 3, maps)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    while sealing.remaining() != 0 {
        sealing.step(a, s, permit, 4, ram).unwrap();
    }
    sealing
        .finish(a, s, permit, 5)
        .unwrap_or_else(|r| panic!("{:?}", r.error))
}
fn view(image: &SealedImage, ram: &Ram) -> View {
    let mut bytes = Vec::new();
    for i in 0..image.pages() {
        bytes.extend_from_slice(&ram.bytes[&(image.physical() + i as u64 * 4096)]);
    }
    View {
        physical: image.physical(),
        bytes,
    }
}
#[test]
fn actual_v4_gate_stream_seal_register_and_call_scoped_plan_preserve_affine_frames() {
    active(|a, s, c, root, creator, job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, payload) = package();
        let mut f = allocator(128);
        let initial = f.remaining_frames();
        let charged = s.usage(job, Resource::Frames).unwrap();
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let stage = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let old = stage.writer().unwrap();
        assert!(a.authorize(root, old, Kind::Memory, Rights::WRITE).is_ok());
        let pages = stage.pages();
        let mut image = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
        assert!(!maps.installed);
        assert!(a.authorize(root, old, Kind::Memory, Rights::READ).is_err());
        assert!(
            a.authorize(root, image.root_handle(), Kind::Memory, Rights::WRITE)
                .is_err()
        );
        let image_view = view(&image, &ram);
        assert_eq!(image.bytes(&image_view).unwrap(), payload);
        assert_eq!(image.elf(&image_view).unwrap(), ELF);
        let mut registry = Registry::with_service_limits(
            NonZeroU64::new(1).unwrap(),
            Limits::new(16384, 32, 1, 1),
        )
        .unwrap();
        registry.register_job(a, root, creator, job).unwrap();
        registry
            .register_sealed(a, s, &permit, &mut image, &image_view)
            .unwrap();
        assert!(image.registered());
        assert!(
            registry
                .register_sealed(a, s, &permit, &mut image, &image_view)
                .is_err()
        );
        let child_job = registry.create_job(a, s, root, creator, 0).unwrap();
        let process = registry
            .create_process(a, s, root, child_job, image.root_handle())
            .unwrap();
        assert!(registry.plan(a, root, process).is_err());
        // Two independently sealed, byte-identical objects are not the same
        // owner. Both are genuinely registered, so this exercises identity
        // binding rather than merely refusing an unregistered argument.
        let other_stage = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        let mut other = seal(a, s, &permit, other_stage, &mut ram, &mut maps, &payload);
        let other_view = view(&other, &ram);
        registry
            .register_sealed(a, s, &permit, &mut other, &other_view)
            .unwrap();
        assert!(matches!(
            registry.plan_sealed(a, root, process, &other, &other_view),
            Err(crate::service::Error::ImageMismatch)
        ));
        registry
            .unregister_sealed(a, s, &permit, &mut other)
            .unwrap();
        other
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        let plan_frames = {
            let plan = registry
                .plan_sealed(a, root, process, &image, &image_view)
                .unwrap();
            assert_eq!(plan.manifest_digest(), spec.descriptor);
            assert_eq!(
                plan.startup_layout(),
                crate::executable::StartupLayout::ServiceV1
            );
            plan.required_frames()
        };
        assert!(
            registry
                .unregister_sealed(a, s, &permit, &mut image)
                .is_err()
        );
        assert_eq!(
            s.usage(job, Resource::Frames).unwrap(),
            charged + pages as u64 + plan_frames
        );
        assert_eq!(f.remaining_frames(), initial - pages as u64);
        let metadata = registry.metadata(a, root, process).unwrap();
        for (i, grant) in root_v4::graph::grants(root_v4::graph::Child::App).enumerate() {
            let kind = match grant.kind {
                1 => Kind::Memory,
                2 => Kind::Endpoint,
                _ => panic!(),
            };
            let source = a
                .create_root(
                    root,
                    kind,
                    Rights::from_bits(grant.rights).unwrap()
                        | Rights::DERIVE
                        | Rights::TRANSFER
                        | Rights::REVOKE,
                )
                .unwrap();
            registry
                .delegate(a, root, process, source, i as u64 + 1)
                .unwrap();
        }
        let epoch = NonZeroU64::new(7).unwrap();
        let record = registry.startup(a, root, process, epoch).unwrap();
        let (entry, stack, bootstrap) = {
            let plan = registry
                .plan_sealed(a, root, process, &image, &image_view)
                .unwrap();
            (
                plan.entry(),
                plan.stack_top(),
                plan.bootstrap_page().unwrap(),
            )
        };
        let loaded = Model(Information {
            process: metadata.process,
            manifest: spec.descriptor,
            entry,
            stack,
            root: 8192,
            frames: plan_frames,
            startup: Some(Startup {
                address: bootstrap,
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            }),
        });
        let mut running = registry
            .start(a, s, root, process, epoch, loaded)
            .unwrap_or_else(|r| panic!("dynamic start: {:?}", r.error));
        assert!(
            registry
                .unregister_sealed(a, s, &permit, &mut image)
                .is_err()
        );
        running.stop(a, s).unwrap();
        s.terminate_process(metadata.process).unwrap();
        let _returned = running
            .finish(s)
            .unwrap_or_else(|_| panic!("model stopped ownership"));
        s.release_frames(metadata.job, metadata.frames).unwrap();
        registry.retire_stopped(a, s, metadata.process).unwrap();
        // Even a retired row pins its source until canonical forget succeeds.
        assert!(
            registry
                .unregister_sealed(a, s, &permit, &mut image)
                .is_err()
        );
        a.close(root, process).unwrap();
        registry.forget_retired(a, s, metadata.process).unwrap();
        registry
            .unregister_sealed(a, s, &permit, &mut image)
            .unwrap();
        assert!(!image.registered());
        let lease = image.map_readonly(a).unwrap();
        let failed = image.retire(a, &mut maps).err().unwrap();
        assert_eq!(failed.error, Error::Busy);
        let Retained::Sealed(mut image) = failed.owner.unwrap() else {
            panic!()
        };
        image.return_readonly(lease).unwrap();
        let retired = image
            .retire(a, &mut maps)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        retired
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged);
        assert_eq!(f.remaining_frames(), initial);
    });
}
#[test]
fn wrong_root_gate_live_revoke_specification_and_fragmentation_refuse_without_losing_owner() {
    active(|a, s, c, root, creator, job, active| {
        let foreign = a.create_space().unwrap();
        assert!(active.dynamic_image_permit(a, s, foreign, creator).is_err());
        assert!(active.dynamic_image_permit(a, s, root, Handle(0)).is_err());
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, _) = package();
        let mut ram = Ram::default();
        let mut f = allocator(128);
        let before = f.remaining_frames();
        let mut bad = spec;
        bad.abi = [0; 32];
        assert!(
            Staging::allocate(a, s, &mut f, &mut ram, &permit, c, bad, 0, 100)
                .err()
                .unwrap()
                .owner
                .is_none()
        );
        assert_eq!(f.remaining_frames(), before);
        let mut fragmented = BootstrapFrames::new(
            MemoryMap::validate([
                MemoryRegion {
                    start: 4096,
                    end: 8192,
                    kind: MemoryKind::Usable,
                },
                MemoryRegion {
                    start: 16384,
                    end: 1024 * 1024,
                    kind: MemoryKind::Usable,
                },
            ])
            .unwrap(),
        );
        let prior = s.usage(job, Resource::Frames).unwrap();
        let rejected = Staging::allocate(a, s, &mut fragmented, &mut ram, &permit, c, spec, 0, 100)
            .err()
            .unwrap();
        assert_eq!(
            rejected.error,
            Error::Extent(crate::memory_extent::Error::Fragmented)
        );
        let Retained::Staging(owner) = rejected.owner.unwrap() else {
            panic!()
        };
        let mut maps = Maps::default();
        let retired = owner
            .abort(a, &mut maps)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        retired
            .release(&mut fragmented, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), prior);
        a.close(root, creator).unwrap();
        assert!(
            Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .err()
                .unwrap()
                .owner
                .is_none()
        );
        assert_eq!(f.remaining_frames(), before);
    });
}
#[test]
fn partial_mapping_unknown_detach_and_clock_failure_retain_debt_until_actual_cleanup() {
    active(|a, s, c, root, creator, job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, payload) = package();
        let mut f = allocator(128);
        let before = f.remaining_frames();
        let charged = s.usage(job, Resource::Frames).unwrap();
        let mut ram = Ram::default();
        let mut maps = Maps {
            fail_install: true,
            ..Maps::default()
        };
        let mut owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        assert_eq!(
            owner.attach(a, s, &permit, 1, &mut maps),
            Err(Error::Mapping)
        );
        assert!(maps.installed);
        assert_eq!(
            owner.chunk_written(a, s, &permit, 2, 0, 1),
            Err(Error::Phase)
        );
        maps.fail_remove = true;
        let failed = owner.abort(a, &mut maps).err().unwrap();
        let Retained::Staging(owner) = failed.owner.unwrap() else {
            panic!()
        };
        assert!(maps.installed);
        assert!(f.remaining_frames() < before);
        assert!(s.usage(job, Resource::Frames).unwrap() > charged);
        maps.fail_remove = false;
        let retired = owner.abort(a, &mut maps).unwrap_or_else(|_| panic!());
        retired
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert!(!maps.installed);
        assert_eq!(f.remaining_frames(), before);
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged);
        maps.fail_install = false;
        let mut owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        owner.attach(a, s, &permit, 1, &mut maps).unwrap();
        fill(&owner, &mut ram, &payload);
        assert_eq!(
            owner.chunk_written(a, s, &permit, 100, 0, 1),
            Err(Error::Deadline)
        );
        assert_eq!(
            owner.chunk_written(a, s, &permit, 2, 0, 1),
            Err(Error::Phase)
        );
        owner
            .abort(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(f.remaining_frames(), before);
    });
}
#[test]
fn immutable_full_readback_rejects_payload_tail_or_io_failure_and_never_unseals() {
    for mode in 0..3 {
        active(|a, s, c, root, creator, job, active| {
            let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
            let (spec, payload) = package();
            let mut f = allocator(128);
            let initial = f.remaining_frames();
            let charged = s.usage(job, Resource::Frames).unwrap();
            let mut ram = Ram::default();
            let mut maps = Maps::default();
            let mut owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            owner.attach(a, s, &permit, 1, &mut maps).unwrap();
            fill(&owner, &mut ram, &payload);
            for (i, b) in payload.chunks(CHUNK_BYTES).enumerate() {
                owner
                    .chunk_written(a, s, &permit, 2, i * CHUNK_BYTES, b.len())
                    .unwrap();
            }
            let physical = owner.physical;
            let pages = owner.pages();
            if mode == 0 {
                ram.bytes.get_mut(&physical).unwrap()[64] ^= 1;
            } else if mode == 1 {
                let last = physical + (pages as u64 - 1) * 4096;
                ram.bytes.get_mut(&last).unwrap()[4095] = 3;
            }
            let mut progress = owner
                .seal(a, s, &permit, 3, &mut maps)
                .unwrap_or_else(|_| panic!());
            assert!(!maps.installed);
            let failed = if mode == 2 {
                ram.fail = true;
                assert_eq!(
                    progress.step(a, s, &permit, 4, &mut ram),
                    Err(Error::Access)
                );
                ram.fail = false;
                assert_eq!(progress.step(a, s, &permit, 4, &mut ram), Err(Error::Phase));
                progress.finish(a, s, &permit, 5).err().unwrap()
            } else {
                while progress.remaining() != 0 {
                    let r = progress.step(a, s, &permit, 4, &mut ram);
                    if mode == 1 && r.is_err() {
                        assert_eq!(r, Err(Error::Hash));
                        break;
                    }
                    r.unwrap();
                }
                progress.finish(a, s, &permit, 5).err().unwrap()
            };
            assert!(matches!(failed.error, Error::Hash | Error::Phase));
            let Retained::Sealing(progress) = failed.owner.unwrap() else {
                panic!()
            };
            progress
                .abort(a, &mut maps)
                .unwrap_or_else(|_| panic!())
                .release(&mut f, s, &mut ram)
                .unwrap_or_else(|_| panic!());
            assert_eq!(f.remaining_frames(), initial);
            assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged);
        });
    }
}
#[test]
fn same_slot_readonly_conversion_succeeds_at_actual_sixty_four_handle_object_capacity() {
    active(|a, s, c, root, creator, _job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, payload) = package();
        let mut f = allocator(128);
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        let old = owner.writer().unwrap();
        while a.create_root(root, Kind::Memory, Rights::READ).is_ok() {}
        assert_eq!(a.metadata_usage().3, 64);
        assert!(a.create_root(root, Kind::Memory, Rights::READ).is_err());
        let image = seal(a, s, &permit, owner, &mut ram, &mut maps, &payload);
        assert_eq!(image.root_handle().0 & 255, old.0 & 255);
        assert_ne!(image.root_handle(), old);
        assert_eq!(a.metadata_usage().3, 64);
        assert!(
            a.authorize(
                root,
                image.root_handle(),
                Kind::Memory,
                Rights::READ | Rights::MAP
            )
            .is_ok()
        );
        assert!(a.authorize(root, old, Kind::Memory, Rights::WRITE).is_err());
    });
}
#[test]
fn root_frame_limit_refusal_precedes_allocation_and_maximum_sixty_four_pages_are_actual() {
    active(|a, s, c, root, creator, job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (mut spec, mut payload) = package();
        let mut f = allocator(256);
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let charged = s.usage(job, Resource::Frames).unwrap();
        let before = f.remaining_frames();
        s.charge_frames(job, 512 - charged - 1).unwrap();
        let rejected = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .err()
            .unwrap();
        assert!(rejected.owner.is_none());
        assert!(matches!(
            rejected.error,
            Error::Extent(crate::memory_extent::Error::Scheduler(_))
        ));
        assert_eq!(f.remaining_frames(), before);
        s.release_frames(job, 512 - charged - 1).unwrap();
        payload.resize(MAX_BYTES, 0x17);
        spec.bytes = payload.len();
        spec.sha256 = Sha256::digest(&payload).into();
        let owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        assert_eq!(owner.pages(), 64);
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged + 64);
        let image = seal(a, s, &permit, owner, &mut ram, &mut maps, &payload);
        image
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged);
        assert_eq!(f.remaining_frames(), before);
    });
}
#[test]
fn descriptor_rights_and_malformed_elf_never_publish_a_registry_row() {
    for mode in 0..3 {
        active(|a, s, c, root, creator, _job, active| {
            let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
            let (mut spec, mut payload) = package();
            if mode == 0 {
                spec.descriptor[0] ^= 1;
            } else if mode == 1 {
                payload[64] = 0;
                spec.sha256 = Sha256::digest(&payload).into();
                spec.elf_sha256 = Sha256::digest(&payload[64..]).into();
            } else {
                payload[64 + 64 + 4] = 7;
                spec.sha256 = Sha256::digest(&payload).into();
                spec.elf_sha256 = Sha256::digest(&payload[64..]).into();
            }
            let mut f = allocator(128);
            let mut ram = Ram::default();
            let mut maps = Maps::default();
            let owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            let mut image = seal(a, s, &permit, owner, &mut ram, &mut maps, &payload);
            let v = view(&image, &ram);
            let mut registry = Registry::new();
            let before = registry.metadata_usage();
            assert!(
                registry
                    .register_sealed(a, s, &permit, &mut image, &v)
                    .is_err()
            );
            assert!(!image.registered());
            assert_eq!(registry.metadata_usage(), before);
            image
                .retire(a, &mut maps)
                .unwrap_or_else(|_| panic!())
                .release(&mut f, s, &mut ram)
                .unwrap_or_else(|_| panic!());
        });
    }
}
#[test]
fn full_existing_registry_refuses_without_pinning_or_losing_the_sealed_owner() {
    active(|a, s, c, root, creator, job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, payload) = package();
        let mut f = allocator(128);
        let before_frames = f.remaining_frames();
        let before_charge = s.usage(job, Resource::Frames).unwrap();
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let stage = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        let mut image = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
        let v = view(&image, &ram);
        let mut registry = Registry::new();
        for _ in 0..crate::service::MAX_IMAGE_RECORDS {
            let cap = a.create_root(root, Kind::Memory, Rights::READ).unwrap();
            let compiled = ServiceImage::verify(
                ELF,
                Sha256::digest(ELF).into(),
                Limits::new(16384, 32, 1, 1),
                &[Role {
                    selector: 1,
                    kind: Kind::Memory,
                    rights: Rights::READ,
                }],
            )
            .unwrap();
            registry.register_image(a, root, cap, compiled).unwrap();
        }
        let before_rows = registry.metadata_usage();
        let before_caps = a.metadata_usage();
        assert_eq!(
            registry.register_sealed(a, s, &permit, &mut image, &v),
            Err(crate::service::Error::Capacity)
        );
        assert_eq!(registry.metadata_usage(), before_rows);
        assert_eq!(a.metadata_usage(), before_caps);
        assert!(!image.registered());
        assert_eq!(image.bytes(&v).unwrap(), payload);
        image
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(f.remaining_frames(), before_frames);
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), before_charge);
    });
}
#[test]
fn actual_root_revocation_and_domain_closure_cannot_mint_or_rearm_a_loader_permit() {
    active(|a, s, _c, root, creator, _job, active| {
        s.inhibit_process(active.token().process()).unwrap();
        assert!(active.dynamic_image_permit(a, s, root, creator).is_err());
    });
    active(|a, s, c, root, creator, _job, mut active| {
        let (spec, _) = package();
        let mut f = allocator(128);
        let mut ram = Ram::default();
        let owner = {
            let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
            Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!())
        };
        let before = f.remaining_frames();
        let token = active.token();
        active.revoke(a, s, token).unwrap();
        assert!(active.dynamic_image_permit(a, s, root, creator).is_err());
        assert_eq!(f.remaining_frames(), before);
        let mut maps = Maps::default();
        owner
            .abort(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
    });
    active(|a, s, c, root, creator, _job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, _) = package();
        let mut f = allocator(128);
        let mut ram = Ram::default();
        let mut owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        a.close_space(root).unwrap();
        let mut maps = Maps::default();
        assert!(owner.attach(a, s, &permit, 1, &mut maps).is_err());
        assert!(!maps.installed);
        owner
            .abort(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
    });
}
#[test]
fn pure_progress_replay_incomplete_seal_and_post_read_deadline_never_grant_immutable_code() {
    active(|a, s, c, root, creator, _job, active| {
        let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
        let (spec, payload) = package();
        let mut f = allocator(128);
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let mut owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        owner.attach(a, s, &permit, 1, &mut maps).unwrap();
        assert_eq!(
            owner.chunk_written(a, s, &permit, 2, 1, 1),
            Err(Error::Bounds)
        );
        owner.chunk_written(a, s, &permit, 2, 0, 1).unwrap();
        assert_eq!(
            owner.chunk_written(a, s, &permit, 2, 0, 1),
            Err(Error::Bounds)
        );
        let failed = owner.seal(a, s, &permit, 3, &mut maps).err().unwrap();
        assert_eq!(failed.error, Error::Phase);
        assert!(maps.installed);
        let Retained::Staging(owner) = failed.owner.unwrap() else {
            panic!()
        };
        owner
            .abort(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        let mut owner = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
            .unwrap_or_else(|_| panic!());
        owner.attach(a, s, &permit, 1, &mut maps).unwrap();
        fill(&owner, &mut ram, &payload);
        for (i, b) in payload.chunks(CHUNK_BYTES).enumerate() {
            owner
                .chunk_written(a, s, &permit, 2, i * CHUNK_BYTES, b.len())
                .unwrap();
        }
        let mut progress = owner
            .seal(a, s, &permit, 3, &mut maps)
            .unwrap_or_else(|_| panic!());
        while progress.remaining() != 0 {
            progress.step(a, s, &permit, 4, &mut ram).unwrap();
        }
        let failed = progress.finish(a, s, &permit, 100).err().unwrap();
        assert_eq!(failed.error, Error::Deadline);
        let Retained::Sealing(progress) = failed.owner.unwrap() else {
            panic!()
        };
        progress
            .abort(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
    });
}

#[test]
fn stopped_root_cleanup_keeps_exact_rows_jobs_and_readers_until_their_actual_gates() {
    active(|a, s, c, root, creator, job, active| {
        let (spec, payload) = package();
        let mut f = allocator(128);
        let free = f.remaining_frames();
        let charged = s.usage(job, Resource::Frames).unwrap();
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let (mut image, mut other, mut registry, mut foreign, metadata, lease) = {
            let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
            let one = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            let mut image = seal(a, s, &permit, one, &mut ram, &mut maps, &payload);
            let two = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            let mut other = seal(a, s, &permit, two, &mut ram, &mut maps, &payload);
            let mut registry = Registry::with_service_limits(
                NonZeroU64::new(1).unwrap(),
                Limits::new(16384, 32, 1, 1),
            )
            .unwrap();
            let mut foreign = Registry::new();
            let image_view = view(&image, &ram);
            let other_view = view(&other, &ram);
            registry
                .register_sealed(a, s, &permit, &mut image, &image_view)
                .unwrap();
            foreign
                .register_sealed(a, s, &permit, &mut other, &other_view)
                .unwrap();
            registry.register_job(a, root, creator, job).unwrap();
            let child_job = registry.create_job(a, s, root, creator, 0).unwrap();
            let process = registry
                .create_process(a, s, root, child_job, image.root_handle())
                .unwrap();
            let metadata = registry.metadata(a, root, process).unwrap();
            let lease = image.map_readonly(a).unwrap();
            (image, other, registry, foreign, metadata, lease)
        };
        let rows = registry.metadata_usage();
        let foreign_rows = foreign.metadata_usage();
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::Phase)
        );
        assert_eq!(registry.metadata_usage(), rows);
        assert!(image.registered());
        let root_process = active.token().process();
        s.terminate_process(root_process).unwrap();
        // A terminated process alone does not prove that its authority domain
        // closed; no pin or readonly-reader credit is released here.
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::Phase)
        );
        a.close_space(root).unwrap();
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut other),
            Err(crate::service::Error::UnknownObject)
        );
        assert_eq!(
            foreign.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::UnknownObject)
        );
        assert_eq!(foreign.metadata_usage(), foreign_rows);
        assert!(other.registered() && image.registered());
        // Private fixture tampering checks the cleanup guard against a real
        // different Scheduler Job, not a caller-supplied cleanup operand.
        let saved_job = image.owner.root.job;
        let wrong_job = s.create_job().unwrap();
        image.owner.root.job = wrong_job;
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::JobLimits)
        );
        image.owner.root.job = saved_job;
        s.reclaim_job(wrong_job).unwrap();
        // Actual held and then retired rows both pin their source until the
        // existing stopped physical-charge/forget transaction completes.
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::Phase)
        );
        s.terminate_process(metadata.process).unwrap();
        s.release_frames(metadata.job, metadata.frames).unwrap(); // model never loaded private RAM
        registry.retire_stopped(a, s, metadata.process).unwrap();
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::Phase)
        );
        registry.forget_retired(a, s, metadata.process).unwrap();
        registry
            .unregister_sealed_stopped(a, s, &mut image)
            .unwrap();
        assert!(!image.registered());
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::UnknownObject)
        );
        foreign.unregister_sealed_stopped(a, s, &mut other).unwrap();
        other
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        let rejected = image.retire(a, &mut maps).err().unwrap();
        assert_eq!(rejected.error, Error::Busy);
        let Retained::Sealed(mut image) = rejected.owner.unwrap() else {
            panic!()
        };
        // Portable model has no installed RO PTE; actual HAL must detach it
        // before returning this logical lease. Root death is not that proof.
        image.return_readonly(lease).unwrap();
        image
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(f.remaining_frames(), free);
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged);
    });
}

#[test]
fn unregistered_rejected_reader_and_independent_registered_image_retire_without_early_credit() {
    active(|a, s, c, root, creator, job, active| {
        let (spec, payload) = package();
        let mut frames = allocator(128);
        let free = frames.remaining_frames();
        let charged = s.usage(job, Resource::Frames).unwrap();
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let (mut rejected, mut accepted, mut registry, rejected_lease, accepted_lease) = {
            let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
            let staged = Staging::allocate(a, s, &mut frames, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            let mut rejected = seal(a, s, &permit, staged, &mut ram, &mut maps, &payload);
            let staged = Staging::allocate(a, s, &mut frames, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            let mut accepted = seal(a, s, &permit, staged, &mut ram, &mut maps, &payload);
            let mut registry = Registry::new();
            let accepted_view = view(&accepted, &ram);
            registry
                .register_sealed(a, s, &permit, &mut accepted, &accepted_view)
                .unwrap();
            let rejected_lease = rejected.map_readonly(a).unwrap();
            let accepted_lease = accepted.map_readonly(a).unwrap();
            (rejected, accepted, registry, rejected_lease, accepted_lease)
        };
        assert!(!rejected.registered());
        assert!(accepted.registered());
        assert!(frames.remaining_frames() < free);
        // A clean Root parse refusal never releases a still-installed reader.
        let refused = rejected.retire(a, &mut maps).err().unwrap();
        assert_eq!(refused.error, Error::Busy);
        let Retained::Sealed(owner) = refused.owner.unwrap() else {
            panic!()
        };
        rejected = owner;
        s.terminate_process(active.token().process()).unwrap();
        a.close_space(root).unwrap();
        registry
            .unregister_sealed_stopped(a, s, &mut accepted)
            .unwrap();
        // Portable lease return models the later actual HAL PTE detach; Root
        // stop alone supplies no lease, physical-frame or Job credit.
        assert!(frames.remaining_frames() < free);
        rejected.return_readonly(rejected_lease).unwrap();
        accepted.return_readonly(accepted_lease).unwrap();
        rejected
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut frames, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        accepted
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut frames, s, &mut ram)
            .unwrap_or_else(|_| panic!());
        assert_eq!(frames.remaining_frames(), free);
        assert_eq!(s.usage(job, Resource::Frames).unwrap(), charged);
    });
}

#[test]
fn closed_domain_alone_does_not_release_code_of_a_live_root() {
    active(|a, s, c, root, creator, _job, active| {
        let (spec, payload) = package();
        let mut f = allocator(128);
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let mut registry = Registry::new();
        let mut image = {
            let permit = active.dynamic_image_permit(a, s, root, creator).unwrap();
            let stage = Staging::allocate(a, s, &mut f, &mut ram, &permit, c, spec, 0, 100)
                .unwrap_or_else(|_| panic!());
            let mut image = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
            let v = view(&image, &ram);
            registry
                .register_sealed(a, s, &permit, &mut image, &v)
                .unwrap();
            image
        };
        a.close_space(root).unwrap();
        assert_eq!(
            registry.unregister_sealed_stopped(a, s, &mut image),
            Err(crate::service::Error::Phase)
        );
        assert!(image.registered());
        s.terminate_process(active.token().process()).unwrap();
        registry
            .unregister_sealed_stopped(a, s, &mut image)
            .unwrap();
        image
            .retire(a, &mut maps)
            .unwrap_or_else(|_| panic!())
            .release(&mut f, s, &mut ram)
            .unwrap_or_else(|_| panic!());
    });
}

#[cfg(feature = "workspace-authority")]
fn active_workspace(
    test: impl FnOnce(
        &mut Authority,
        &mut Scheduler,
        SpaceId,
        SpaceId,
        Handle,
        JobId,
        crate::scheduler::ThreadId,
        Handle,
        Active<'_, Model>,
    ),
) {
    let image = crate::root_v5_tests::elf();
    let (mut a, domains, sources) = crate::root_v5_tests::setup(&image);
    let c = domains.custody();
    let encoded = crate::root_v5_tests::encoded(&image, &a, c, &sources);
    let manifest =
        crate::root_manifest_v5::verify(encoded.bytes(), encoded.digest(), &image).unwrap();
    let mut s = Scheduler::new();
    let limits = ev_userspace_contract::root_v5::ROOT_LIMITS;
    let job = s
        .create_job_with_limits(Limits::new(limits[0], limits[1], limits[2], limits[3]))
        .unwrap();
    let process = s.create_held_process(job).unwrap();
    let thread = s.create_thread(process).unwrap();
    let (c, target) = domains.into_target(process, job);
    let root = target.destination;
    let last_source = sources[36].handle;
    let catalogue = sources.map(|x| CatalogEntry {
        selector: x.selector,
        root: x.handle,
        kind: x.kind,
    });
    let mut custodian =
        Custodian::new_root_v5(NonZeroU64::new(805).unwrap(), &manifest, c, &catalogue);
    let attempt = custodian.begin(0).unwrap();
    let (mut binding, token) = custodian.prepare(attempt, &mut a, &s, target).unwrap();
    let record = binding.bootstrap_record_v5(token).unwrap();
    let parsed = ev_userspace_contract::root_v5::FullGraph::parse(&record).unwrap();
    let creator = Handle(parsed.handle(ev_userspace_contract::root_v5::Role::CreatorJob));
    let plan = binding.executable(token).unwrap();
    s.charge_frames(job, plan.required_frames()).unwrap();
    let model = Model(Information {
        process,
        manifest: manifest.manifest().digest(),
        entry: plan.entry(),
        stack: plan.stack_top(),
        root: 4096,
        frames: plan.required_frames(),
        startup: Some(Startup {
            address: plan.bootstrap_page().unwrap(),
            bytes: record.len(),
            digest: Sha256::digest(record).into(),
        }),
    });
    let active = binding
        .activate(&a, &mut s, token, thread, model)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    custodian.confirm_active(&active).unwrap();
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
    test(
        &mut a,
        &mut s,
        c,
        root,
        creator,
        job,
        thread,
        last_source,
        active,
    );
}

#[cfg(feature = "workspace-authority")]
#[test]
fn v5_factory_requires_current_captured_root_and_pins_actual_file_app6_sealed_owner() {
    use ev_userspace_contract::root_v5::graph::{Child, ImageSlot};
    active_workspace(
        |a, s, custody, root, creator, root_job, thread, _, active| {
            assert!(active.dynamic_image_permit(a, s, root, creator).is_err());
            let ordinary = a.create_space().unwrap();
            assert!(
                active
                    .workspace_dynamic_image_permit(a, s, ordinary, creator, thread)
                    .is_err()
            );
            let alias = a.derive(root, creator, root, Rights::CONTROL).unwrap();
            assert!(
                active
                    .workspace_dynamic_image_permit(a, s, root, alias, thread)
                    .is_err()
            );
            let permit = active
                .workspace_dynamic_image_permit(a, s, root, creator, thread)
                .unwrap();
            let elf = crate::executable::m8::tests::elf(&[(2, 2), (64, 256), (480, 8)]);
            let sha = Sha256::digest(&elf).into();
            let checked = ServiceImage::verify_m8(&elf, sha, ImageSlot::Editor).unwrap();
            let mut payload = vec![0x61; 64];
            payload.extend_from_slice(&elf);
            let spec = Specification {
                bytes: payload.len(),
                sha256: Sha256::digest(&payload).into(),
                elf_offset: 64,
                elf_bytes: elf.len(),
                elf_sha256: sha,
                package: [0x93; 32],
                abi: ev_userspace_contract::ABI,
                descriptor: checked.digest(),
            };
            let mut frames = allocator(128);
            let initial = frames.remaining_frames();
            let before_charge = s.usage(root_job, Resource::Frames).unwrap();
            let mut ram = Ram::default();
            let mut maps = Maps::default();
            let stage =
                Staging::allocate(a, s, &mut frames, &mut ram, &permit, custody, spec, 0, 100)
                    .unwrap_or_else(|r| panic!("{:?}", r.error));
            let pages = stage.pages();
            let writer = stage.writer().unwrap();
            assert!(
                a.derive(
                    root,
                    writer,
                    root,
                    Rights::READ | Rights::WRITE | Rights::MAP
                )
                .is_err()
            );
            let mut sealed = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
            let view = view(&sealed, &ram);
            assert!(
                a.authorize(root, writer, Kind::Memory, Rights::WRITE)
                    .is_err()
            );
            assert_eq!(sealed.elf(&view).unwrap(), elf);
            let mut legacy = Registry::new();
            assert!(
                legacy
                    .register_sealed(a, s, &permit, &mut sealed, &view)
                    .is_err()
            );
            assert!(
                legacy
                    .register_workspace_sealed(a, s, &permit, &mut sealed, &view)
                    .is_err()
            );
            let mut registry = Registry::for_m8_services(NonZeroU64::new(1).unwrap());
            registry.register_job(a, root, creator, root_job).unwrap();
            registry
                .register_workspace_sealed(a, s, &permit, &mut sealed, &view)
                .unwrap();
            assert!(sealed.is_registered());
            let job = registry.create_job(a, s, root, creator, 3).unwrap();
            let process = registry
                .create_process(a, s, root, job, sealed.root_handle())
                .unwrap();
            let meta = registry.metadata(a, root, process).unwrap();
            assert_eq!(s.held_process_job(meta.process), Ok(meta.job));
            assert!(registry.plan(a, root, process).is_err());
            assert!(
                registry
                    .plan_sealed(a, root, process, &sealed, &view)
                    .is_err()
            );
            let plan = registry
                .plan_workspace_sealed(a, root, process, &sealed, &view)
                .unwrap();
            assert!(plan.pages().count() > 256);
            assert_eq!(
                plan.startup_layout(),
                crate::executable::StartupLayout::ServiceV1
            );
            assert_eq!(meta.frames, plan.required_frames());
            let charged_private = plan.required_frames();
            assert!(
                registry
                    .unregister_sealed(a, s, &permit, &mut sealed)
                    .is_err()
            );
            for (i, grant) in
                ev_userspace_contract::root_v5::graph::grants(Child::EditorOne).enumerate()
            {
                let kind = if grant.kind == 1 {
                    Kind::Memory
                } else {
                    Kind::Endpoint
                };
                let source = a
                    .create_root(
                        root,
                        kind,
                        Rights::from_bits(grant.rights).unwrap()
                            | Rights::DERIVE
                            | Rights::TRANSFER
                            | Rights::REVOKE,
                    )
                    .unwrap();
                registry
                    .delegate(a, root, process, source, i as u64 + 1)
                    .unwrap();
            }
            let startup = registry
                .startup_m8(a, root, process, NonZeroU64::new(805).unwrap())
                .unwrap();
            assert_eq!(startup.bytes().len(), ev_userspace_contract::SIZE);
            let parsed = ev_userspace_contract::Bootstrap::parse(startup.bytes()).unwrap();
            assert_eq!(parsed.grants().count(), 6);
            let limits: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(startup.bytes()[40 + i * 8..48 + i * 8].try_into().unwrap())
            });
            assert_eq!(limits, Child::EditorOne.limits());
            assert_eq!(
                s.usage(root_job, Resource::Frames).unwrap(),
                before_charge + pages as u64 + charged_private
            );
            assert_eq!(frames.remaining_frames(), initial - pages as u64);
            // A previously issued permit rechecks actual captured scheduling state;
            // merely retaining the same descriptive Root token does not suffice.
            s.yield_cpu(0).unwrap();
            assert!(permit.check(a, s).is_err());
            assert!(
                registry
                    .unregister_sealed(a, s, &permit, &mut sealed)
                    .is_err()
            );
            assert!(sealed.is_registered());
            assert_eq!(s.held_process_job(meta.process), Ok(meta.job));
        },
    );
}

#[cfg(feature = "workspace-authority")]
#[test]
fn v5_file_app_factory_rejects_descriptor_substitution_without_registration_or_refund() {
    active_workspace(|a, s, custody, root, creator, job, thread, _, active| {
        let permit = active
            .workspace_dynamic_image_permit(a, s, root, creator, thread)
            .unwrap();
        let elf = crate::executable::m8::tests::elf(&[(2, 2), (480, 8)]);
        let sha = Sha256::digest(&elf).into();
        let descriptor = ServiceImage::verify_m8(
            &elf,
            sha,
            ev_userspace_contract::root_v5::graph::ImageSlot::Editor,
        )
        .unwrap()
        .digest();
        let mut payload = vec![0x5b; 64];
        payload.extend_from_slice(&elf);
        let mut spec = Specification {
            bytes: payload.len(),
            sha256: Sha256::digest(&payload).into(),
            elf_offset: 64,
            elf_bytes: elf.len(),
            elf_sha256: sha,
            package: [0x94; 32],
            abi: ev_userspace_contract::ABI,
            descriptor,
        };
        spec.descriptor[0] ^= 1;
        let before = s.usage(job, Resource::Frames).unwrap();
        let mut frames = allocator(64);
        let mut ram = Ram::default();
        let mut maps = Maps::default();
        let stage = Staging::allocate(a, s, &mut frames, &mut ram, &permit, custody, spec, 0, 100)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let pages = stage.pages();
        let mut sealed = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
        let view = view(&sealed, &ram);
        let mut registry = Registry::for_m8_services(NonZeroU64::new(1).unwrap());
        assert_eq!(
            registry.register_workspace_sealed(a, s, &permit, &mut sealed, &view),
            Err(crate::service::Error::Measurement)
        );
        assert!(!sealed.is_registered());
        assert_eq!(
            s.usage(job, Resource::Frames).unwrap(),
            before + pages as u64
        );
        assert!(
            a.authorize(root, sealed.root_handle(), Kind::Memory, Rights::WRITE)
                .is_err()
        );
    });
}

#[cfg(feature = "workspace-authority")]
#[test]
fn v5_timed_registration_fences_expired_or_backward_admission_but_retains_sealed_readers() {
    for admission in [4, 100, u64::MAX] {
        active_workspace(
            |a, s, custody, root, creator, root_job, thread, _, active| {
                let permit = active
                    .workspace_dynamic_image_permit(a, s, root, creator, thread)
                    .unwrap();
                let elf = crate::executable::m8::tests::elf(&[(2, 2), (480, 8)]);
                let elf_sha = Sha256::digest(&elf).into();
                let descriptor = ServiceImage::verify_m8(
                    &elf,
                    elf_sha,
                    ev_userspace_contract::root_v5::graph::ImageSlot::Editor,
                )
                .unwrap()
                .digest();
                let mut payload = vec![0x62; 64];
                payload.extend_from_slice(&elf);
                let spec = Specification {
                    bytes: payload.len(),
                    sha256: Sha256::digest(&payload).into(),
                    elf_offset: 64,
                    elf_bytes: elf.len(),
                    elf_sha256: elf_sha,
                    package: [0x95; 32],
                    abi: ev_userspace_contract::ABI,
                    descriptor,
                };
                let mut frames = allocator(64);
                let mut ram = Ram::default();
                let mut maps = Maps::default();
                let stage =
                    Staging::allocate(a, s, &mut frames, &mut ram, &permit, custody, spec, 0, 100)
                        .unwrap_or_else(|r| panic!("{:?}", r.error));
                let mut sealed = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
                let view = view(&sealed, &ram);
                let reader = sealed.map_readonly(a).unwrap();
                let mut registry = Registry::for_m8_services(NonZeroU64::new(1).unwrap());
                registry.register_job(a, root, creator, root_job).unwrap();
                let job = registry.create_job(a, s, root, creator, 3).unwrap();
                let charged = s.usage(root_job, Resource::Frames).unwrap();
                let processes = s.usage(root_job, Resource::Processes).unwrap();
                assert_eq!(
                    registry.register_workspace_sealed_at(
                        a,
                        s,
                        &permit,
                        &mut sealed,
                        &view,
                        admission
                    ),
                    Err(crate::service::Error::Phase)
                );
                assert!(!sealed.is_registered());
                // Neither returning to an earlier live tick nor the old API may
                // revive an owner whose original cut/clock fence has failed.
                assert_eq!(
                    registry.register_workspace_sealed_at(a, s, &permit, &mut sealed, &view, 6),
                    Err(crate::service::Error::Phase)
                );
                assert_eq!(
                    registry.register_workspace_sealed(a, s, &permit, &mut sealed, &view),
                    Err(crate::service::Error::Phase)
                );
                assert!(
                    registry
                        .create_process(a, s, root, job, sealed.root_handle())
                        .is_err()
                );
                assert_eq!(s.usage(root_job, Resource::Frames).unwrap(), charged);
                assert_eq!(s.usage(root_job, Resource::Processes).unwrap(), processes);
                assert_eq!(sealed.elf(&view).unwrap(), elf);
                assert!(
                    a.authorize(root, sealed.root_handle(), Kind::Memory, Rights::WRITE)
                        .is_err()
                );
                sealed
                    .return_readonly(reader)
                    .unwrap_or_else(|_| panic!("retained reader must return"));
            },
        );
    }
}

#[cfg(feature = "workspace-authority")]
#[test]
fn v5_registered_immutable_image_remains_usable_after_original_transfer_cut() {
    active_workspace(
        |a, s, custody, root, creator, root_job, thread, _, active| {
            let permit = active
                .workspace_dynamic_image_permit(a, s, root, creator, thread)
                .unwrap();
            let elf = crate::executable::m8::tests::elf(&[(2, 2), (480, 8)]);
            let elf_sha = Sha256::digest(&elf).into();
            let descriptor = ServiceImage::verify_m8(
                &elf,
                elf_sha,
                ev_userspace_contract::root_v5::graph::ImageSlot::Editor,
            )
            .unwrap()
            .digest();
            let mut payload = vec![0x63; 64];
            payload.extend_from_slice(&elf);
            let spec = Specification {
                bytes: payload.len(),
                sha256: Sha256::digest(&payload).into(),
                elf_offset: 64,
                elf_bytes: elf.len(),
                elf_sha256: elf_sha,
                package: [0x96; 32],
                abi: ev_userspace_contract::ABI,
                descriptor,
            };
            let mut frames = allocator(64);
            let mut ram = Ram::default();
            let mut maps = Maps::default();
            let stage =
                Staging::allocate(a, s, &mut frames, &mut ram, &permit, custody, spec, 0, 100)
                    .unwrap_or_else(|r| panic!("{:?}", r.error));
            let mut sealed = seal(a, s, &permit, stage, &mut ram, &mut maps, &payload);
            let view = view(&sealed, &ram);
            let reader = sealed.map_readonly(a).unwrap();
            let mut registry = Registry::for_m8_services(NonZeroU64::new(1).unwrap());
            registry.register_job(a, root, creator, root_job).unwrap();
            registry
                .register_workspace_sealed_at(a, s, &permit, &mut sealed, &view, 6)
                .unwrap();
            assert_eq!(
                registry.register_workspace_sealed_at(a, s, &permit, &mut sealed, &view, 100),
                Err(crate::service::Error::AlreadyRegistered)
            );
            assert!(sealed.is_registered());
            assert_eq!(sealed.elf(&view).unwrap(), elf);
            let job = registry.create_job(a, s, root, creator, 3).unwrap();
            let process = registry
                .create_process(a, s, root, job, sealed.root_handle())
                .unwrap();
            assert!(
                registry
                    .plan_workspace_sealed(a, root, process, &sealed, &view)
                    .is_ok()
            );
            sealed
                .return_readonly(reader)
                .unwrap_or_else(|_| panic!("retained reader must return"));
        },
    );
}

#[cfg(feature = "workspace-authority")]
#[test]
fn sdk_file_app6_transcript_matches_independent_selected_kernel_descriptor() {
    use ev_userspace_contract::root_v5::{dynamic, graph::ImageSlot};
    let elf = crate::executable::m8::tests::elf(&[(2, 2), (64, 256), (480, 8)]);
    let sha = Sha256::digest(&elf).into();
    let mut hash = Sha256::new();
    dynamic::app_descriptor_transcript(&sha, |b| hash.update(b));
    let actual = ServiceImage::verify_m8(&elf, sha, ImageSlot::Editor).unwrap();
    assert_eq!(<[u8; 32]>::from(hash.finalize()), actual.digest());
    assert_eq!(
        dynamic::PROFILE_VALUES,
        crate::executable::m8::ServiceProfile::for_slot(ImageSlot::Editor)
            .unwrap()
            .values()
    );
    assert_eq!(
        dynamic::DESCRIPTION_SHA256,
        <[u8; 32]>::from(Sha256::digest(dynamic::DESCRIPTION))
    );
    let mut legacy = Sha256::new();
    root_v4::dynamic::app_descriptor_transcript(&sha, |b| legacy.update(b));
    assert_ne!(<[u8; 32]>::from(legacy.finalize()), actual.digest());
}

#[cfg(feature = "workspace-authority")]
#[test]
fn v5_dynamic_permit_rechecks_all_original_full_generation_source_branches() {
    active_workspace(|a, s, custody, root, creator, _, thread, source, active| {
        let permit = active
            .workspace_dynamic_image_permit(a, s, root, creator, thread)
            .unwrap();
        assert!(permit.check(a, s).is_ok());
        // Revoke an unrelated original source, while actual Root/Creator stay
        // live and Running. The retained same token cannot revive the graph.
        a.revoke(custody, source).unwrap();
        assert!(
            a.authorize(root, creator, Kind::Job, Rights::CONTROL)
                .is_ok()
        );
        assert!(matches!(
            s.state(thread),
            Ok(crate::scheduler::State::Running(_))
        ));
        assert!(permit.check(a, s).is_err());
        assert!(
            active
                .workspace_dynamic_image_permit(a, s, root, creator, thread)
                .is_err()
        );
    });
}
