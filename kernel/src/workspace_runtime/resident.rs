//! Exclusive once-per-boot residency. Whole graph/resource owners are never
//! returned through the256KiB Kernel stack. Initialized fields stay pinned.
use super::*;
use core::{
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
pub(super) static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut AUTHORITY: MaybeUninit<Authority> = MaybeUninit::uninit();
static mut SCHEDULER: MaybeUninit<Scheduler> = MaybeUninit::uninit();
static mut REGISTRY: MaybeUninit<Registry<'static>> = MaybeUninit::uninit();
static mut RPC: MaybeUninit<Rpc> = MaybeUninit::uninit();
static mut BACKING: MaybeUninit<Backing> = MaybeUninit::uninit();
static mut MANIFEST: MaybeUninit<ev_kernel::root_manifest_v5::CurrentRoot<'static>> =
    MaybeUninit::uninit();
static mut CATALOG: [ev_kernel::bootstrap_binding::CatalogEntry; 37] =
    [ev_kernel::bootstrap_binding::CatalogEntry {
        selector: 0,
        root: Handle(0),
        kind: Kind::Memory,
    }; 37];
static mut IMAGES: [MaybeUninit<PhysicalImage>; 13] = [const { MaybeUninit::uninit() }; 13];
pub(super) struct Core {
    pub a: &'static mut Authority,
    pub s: &'static mut Scheduler,
    pub registry: &'static mut Registry<'static>,
    pub rpc: &'static mut Rpc,
    pub manifest: &'static ev_kernel::root_manifest_v5::CurrentRoot<'static>,
    pub catalog: &'static [ev_kernel::bootstrap_binding::CatalogEntry; 37],
    pub backing: &'static mut Backing,
    pub domains: Option<ev_kernel::root_factory_v2::RootDomains>,
    pub boot: JobId,
    pub root_job: JobId,
}
// Each fresh constructor returns only its resident reference. Its bounded
// value temporary ends before another constructor or a staged transaction is
// entered; LLVM may not merge those lifetimes into initialize's fixed frame.
// All helpers are private and called exactly once after the shared claim and
// typed actual asset validation. No reference exists before its slot is written.
#[inline(never)]
unsafe fn construct_authority() -> &'static mut Authority {
    // SAFETY: uniquely claimed uninitialized slot, complete fresh value write.
    unsafe {
        let p = ptr::addr_of_mut!(AUTHORITY).cast::<Authority>();
        p.write(Authority::for_workspace_profile());
        &mut *p
    }
}
#[inline(never)]
unsafe fn construct_scheduler() -> &'static mut Scheduler {
    // SAFETY: uniquely claimed uninitialized slot, complete fresh value write.
    unsafe {
        let p = ptr::addr_of_mut!(SCHEDULER).cast::<Scheduler>();
        p.write(Scheduler::new());
        &mut *p
    }
}
#[inline(never)]
unsafe fn construct_registry() -> &'static mut Registry<'static> {
    // SAFETY: uniquely claimed uninitialized slot, complete fresh value write.
    unsafe {
        let p = ptr::addr_of_mut!(REGISTRY).cast::<Registry<'static>>();
        p.write(Registry::for_m8_services(NonZeroU64::new(1).unwrap()));
        &mut *p
    }
}
#[inline(never)]
unsafe fn construct_rpc() -> &'static mut Rpc {
    // SAFETY: uniquely claimed uninitialized slot, complete fresh value write.
    unsafe {
        let p = ptr::addr_of_mut!(RPC).cast::<Rpc>();
        p.write(Rpc::new(EPOCH));
        &mut *p
    }
}
#[inline(never)]
unsafe fn construct_backing(custody: SpaceId, job: JobId, hw: Hardware) -> &'static mut Backing {
    // SAFETY: uniquely claimed uninitialized slot, complete fresh value write.
    unsafe {
        let p = ptr::addr_of_mut!(BACKING).cast::<Backing>();
        p.write(Backing::empty(custody, job, hw));
        &mut *p
    }
}
/// # Safety
/// Sole selected BSP boot path after actual typed artifact validation. All
/// statics are exclusively claimed once; no user or AP can access these slots.
#[inline(never)] // Large fresh metadata temporaries end before Root/child load.
pub(super) unsafe fn initialize(
    hw: Hardware,
    frames: &mut BootstrapFrames,
    fb: ev_boot_contract::Framebuffer,
    assets: &Assets,
) -> Core {
    assert!(
        !CLAIMED.swap(true, Ordering::AcqRel),
        "V5 resident world once per boot"
    );
    let measured = assets.verify();
    // SAFETY: unique static owners initialized individually, no graph temporary.
    unsafe {
        ptr::addr_of_mut!(MANIFEST)
            .cast::<ev_kernel::root_manifest_v5::CurrentRoot<'static>>()
            .write(measured);
        let manifest =
            &*ptr::addr_of!(MANIFEST).cast::<ev_kernel::root_manifest_v5::CurrentRoot<'static>>();
        let a = construct_authority();
        let s = construct_scheduler();
        let registry = construct_registry();
        let rpc = construct_rpc();
        let domains =
            ev_kernel::root_factory_v2::RootDomains::allocate_workspace(a, manifest).unwrap();
        let b = v5::resources::BOOT_LIMITS;
        let boot = s
            .create_job_with_limits(Limits::new(b[0], b[1], b[2], b[3]))
            .unwrap();
        let root_job = s
            .create_child_job(boot, manifest.manifest().limits())
            .unwrap();
        s.configure_cpu_budget(
            boot,
            v5::resources::PERIOD_TICKS,
            v5::resources::PERIOD_TICKS,
        )
        .unwrap();
        s.configure_cpu_budget(
            root_job,
            v5::resources::ROOT_QUOTA_TICKS,
            v5::resources::PERIOD_TICKS,
        )
        .unwrap();
        let backing = construct_backing(domains.custody(), root_job, hw);
        backing.populate(a, s, frames, fb, assets);
        let catalog = &mut *ptr::addr_of_mut!(CATALOG);
        for (i, spec) in v5::ROLES.into_iter().enumerate() {
            catalog[i] = ev_kernel::bootstrap_binding::CatalogEntry {
                selector: spec.role.selector(),
                root: backing.sources[i],
                kind: kind(spec.kind),
            };
        }
        registry
            .register_job(
                a,
                backing.custody,
                backing.source(Role::CreatorJob),
                root_job,
            )
            .unwrap();
        for slot in graph::IMAGES {
            let artifact = assets.images[slot.index()];
            registry
                .register_image(
                    a,
                    backing.custody,
                    backing.source(slot.role()),
                    ServiceImage::verify_m8(artifact.bytes, artifact.sha256, slot).unwrap(),
                )
                .unwrap();
        }
        Core {
            a,
            s,
            registry,
            rpc,
            manifest,
            catalog,
            backing,
            domains: Some(domains),
            boot,
            root_job,
        }
    }
}
/// # Safety
/// The slot has no admitted or returned ImageLease. Caller immediately retains
/// its exclusive lease; it may never call this twice for a still-owned slot.
pub(super) unsafe fn place_image(index: usize, image: PhysicalImage) -> &'static mut PhysicalImage {
    assert!(index < 13);
    // SAFETY: exact claimed stable slot under caller's affine ownership proof.
    unsafe {
        let slot = ptr::addr_of_mut!(IMAGES)
            .cast::<MaybeUninit<PhysicalImage>>()
            .add(index);
        (*slot).write(image)
    }
}
