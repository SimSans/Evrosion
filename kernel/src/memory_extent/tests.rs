extern crate std;
use super::*;
use crate::{memory::MAX_RECYCLED, scheduler::Limits};
use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
use std::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
struct Ram {
    pages: BTreeMap<u64, Box<[u8; FRAME_SIZE as usize]>>,
    writes: u64,
    reads: u64,
    corrupt: bool,
}
impl Ram {
    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            writes: 0,
            reads: 0,
            corrupt: false,
        }
    }
}
// SAFETY: this explicit host RAM model assigns one exclusive byte page to each
// retained frame identity. It makes no claim to have accessed hardware RAM.
#[allow(unsafe_code)]
unsafe impl RamAccess for Ram {
    type Error = ();
    fn write(&mut self, f: &PhysicalFrame, byte: usize, value: u8) -> Result<(), ()> {
        assert!(byte < FRAME_SIZE as usize);
        self.writes += 1;
        self.pages
            .entry(f.start())
            .or_insert_with(|| Box::new([0xa5; FRAME_SIZE as usize]))[byte] = value;
        Ok(())
    }
    fn read(&mut self, f: &PhysicalFrame, byte: usize) -> Result<u8, ()> {
        assert!(byte < FRAME_SIZE as usize);
        self.reads += 1;
        Ok(if self.corrupt {
            1
        } else {
            self.pages.get(&f.start()).unwrap()[byte]
        })
    }
}
fn allocator(pages: usize) -> BootstrapFrames {
    BootstrapFrames::new(
        MemoryMap::validate([MemoryRegion {
            start: FRAME_SIZE,
            end: (pages as u64 + 1) * FRAME_SIZE,
            kind: MemoryKind::Usable,
        }])
        .unwrap(),
    )
}
fn scheduler(quota: u64) -> (Scheduler, JobId) {
    let mut s = Scheduler::new();
    let job = s
        .create_job_with_limits(Limits::new(1000, quota, 1, 1))
        .unwrap();
    (s, job)
}
fn initialized(
    a: &mut BootstrapFrames,
    s: &mut Scheduler,
    j: JobId,
    n: usize,
    ram: &mut Ram,
) -> InitializedRam {
    UninitializedRam::allocate(a, s, j, n)
        .unwrap_or_else(|e| panic!("{:?}", e.error))
        .initialize(ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error))
}
fn publish(
    a: &mut Authority,
    domain: SpaceId,
    ram: InitializedRam,
    f: &BootstrapFrames,
    s: &Scheduler,
) -> (MemoryExtent, Handle) {
    MemoryExtent::publish(a, domain, ram, f, s).unwrap_or_else(|e| panic!("{:?}", e.error))
}
#[test]
fn sixty_four_real_owned_frames_are_initialized_and_released_under_one_cap() {
    let mut f = allocator(128);
    let before = f.remaining_frames();
    let (mut s, j) = scheduler(64);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 64, &mut ram);
    assert_eq!((ram.writes, ram.reads), (64 * FRAME_SIZE, 64 * FRAME_SIZE));
    assert_eq!(s.usage(j, Resource::Frames), Ok(64));
    let mut a = Authority::new();
    let domain = a.create_space().unwrap();
    let (mut object, cap) = publish(&mut a, domain, owner, &f, &s);
    assert_eq!(a.metadata_usage(), (1, 1, 1, 1));
    let lease = object.map(&a, domain, cap, true).unwrap();
    let addresses: Vec<_> = object.physical_pages(&lease).unwrap().collect();
    assert_eq!(addresses.len(), 64);
    assert_eq!(addresses.iter().copied().collect::<BTreeSet<_>>().len(), 64);
    assert_eq!(object.destroy(&mut a, domain, cap).err(), Some(Error::Busy));
    assert_eq!(f.remaining_frames(), before - 64);
    object.unmap(lease).unwrap();
    let owner = object.destroy(&mut a, domain, cap).unwrap();
    owner
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
    assert_eq!(f.remaining_frames(), before);
}
#[test]
fn invalid_size_exhaustion_and_quota_refuse_before_allocating_or_publishing() {
    let mut f = allocator(64);
    let (mut s, j) = scheduler(2);
    let before = f.remaining_frames();
    for count in [0, 65] {
        let e = UninitializedRam::allocate(&mut f, &mut s, j, count)
            .err()
            .unwrap();
        assert_eq!(e.error, Error::Count);
        assert!(e.owner.is_none());
    }
    let e = UninitializedRam::allocate(&mut f, &mut s, j, 3)
        .err()
        .unwrap();
    assert!(matches!(e.error, Error::Scheduler(_)));
    assert!(e.owner.is_none());
    assert_eq!(f.remaining_frames(), before);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
    let (mut s, j) = scheduler(64);
    let mut small = allocator(2);
    let e = UninitializedRam::allocate(&mut small, &mut s, j, 3)
        .err()
        .unwrap();
    assert_eq!(e.error, Error::Exhausted);
    assert_eq!(small.remaining_frames(), 2);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
}
#[test]
fn failed_readback_retains_all_claims_and_charge_without_a_capability() {
    let mut f = allocator(8);
    let (mut s, j) = scheduler(8);
    let mut ram = Ram::new();
    ram.corrupt = true;
    let raw = UninitializedRam::allocate(&mut f, &mut s, j, 3)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    let rejected = raw.initialize(&mut ram).err().unwrap();
    assert_eq!(rejected.error, InitError::Readback);
    assert_eq!(rejected.owner.pages(), 3);
    assert_eq!(f.remaining_frames(), 5);
    assert_eq!(s.usage(j, Resource::Frames), Ok(3));
    ram.corrupt = false;
    let initialized = rejected
        .owner
        .initialize(&mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    initialized
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(f.remaining_frames(), 8);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
}
#[test]
fn late_authority_capacity_failure_returns_initialized_owner_unchanged() {
    let mut f = allocator(8);
    let (mut s, j) = scheduler(8);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 3, &mut ram);
    let mut a = Authority::new();
    let domain = a.create_control_space().unwrap();
    for _ in 0..crate::capability::MAX_OBJECTS {
        a.create_root(domain, Kind::Endpoint, Rights::SEND).unwrap();
    }
    let before = a.metadata_usage();
    let rejected = MemoryExtent::publish(&mut a, domain, owner, &f, &s)
        .err()
        .unwrap();
    assert!(matches!(rejected.error, Error::Authority(_)));
    assert_eq!(a.metadata_usage(), before);
    assert_eq!(s.usage(j, Resource::Frames), Ok(3));
    rejected
        .owner
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(f.remaining_frames(), 8);
}
#[test]
fn another_allocator_cannot_publish_or_reclaim_the_retained_ram() {
    let mut f = allocator(8);
    let mut foreign = allocator(8);
    let (mut s, j) = scheduler(8);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 3, &mut ram);
    let mut a = Authority::new();
    let domain = a.create_space().unwrap();
    let before = a.metadata_usage();
    let rejected = MemoryExtent::publish(&mut a, domain, owner, &foreign, &s)
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::WrongAllocator);
    assert_eq!(a.metadata_usage(), before);
    let rejected = rejected
        .owner
        .release(&mut foreign, &mut s, &mut ram)
        .err()
        .unwrap();
    assert_eq!(rejected.error, ReleaseError::State(Error::WrongAllocator));
    assert_eq!(foreign.remaining_frames(), 8);
    rejected
        .owner
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(f.remaining_frames(), 8);
}
#[test]
fn rights_revocation_domain_death_and_retained_cleanup_are_separate() {
    let mut f = allocator(8);
    let (mut s, j) = scheduler(8);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 3, &mut ram);
    let mut a = Authority::new();
    let root = a.create_space().unwrap();
    let peer = a.create_space().unwrap();
    let (mut object, cap) = publish(&mut a, root, owner, &f, &s);
    let child = a
        .derive(root, cap, peer, Rights::READ | Rights::MAP | Rights::REVOKE)
        .unwrap();
    assert!(matches!(
        object.map(&a, peer, child, true),
        Err(Error::Authority(_))
    ));
    let lease = object.map(&a, peer, child, false).unwrap();
    assert_eq!(object.validate(&a, &lease), Ok(()));
    a.revoke(peer, child).unwrap();
    assert_eq!(
        object.validate(&a, &lease),
        Err(Error::Authority(CapError::Revoked))
    );
    assert_eq!(object.destroy(&mut a, root, cap).err(), Some(Error::Busy));
    object.unmap(lease).unwrap();
    let child = a
        .derive(root, cap, peer, Rights::READ | Rights::MAP)
        .unwrap();
    let lease = object.map(&a, peer, child, false).unwrap();
    a.close_space(peer).unwrap();
    assert!(matches!(
        object.validate(&a, &lease),
        Err(Error::Authority(_))
    ));
    object.unmap(lease).unwrap();
    object
        .destroy(&mut a, root, cap)
        .unwrap()
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(f.remaining_frames(), 8);
}
#[test]
fn token_capacity_overflow_and_forgery_change_nothing() {
    let mut f = allocator(8);
    let (mut s, j) = scheduler(8);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 3, &mut ram);
    let mut a = Authority::new();
    let d = a.create_space().unwrap();
    let (mut o, cap) = publish(&mut a, d, owner, &f, &s);
    let mut leases: Vec<_> = (0..MAX_LEASES)
        .map(|_| o.map(&a, d, cap, false).unwrap())
        .collect();
    let before = a.metadata_usage();
    assert_eq!(o.map(&a, d, cap, false).err(), Some(Error::Capacity));
    assert_eq!(a.metadata_usage(), before);
    let real = leases.pop().unwrap();
    forged_checks(&o, &a, &real);
    o.unmap(real).unwrap();
    for lease in leases {
        o.unmap(lease).unwrap();
    }
    o.sequence = u64::MAX;
    assert_eq!(o.map(&a, d, cap, false).err(), Some(Error::Overflow));
    assert_eq!(o.live_leases(), 0);
    o.destroy(&mut a, d, cap)
        .unwrap()
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
}
fn forged_checks(o: &MemoryExtent, a: &Authority, real: &ExtentLease) {
    for lease in [
        ExtentLease {
            object: real.object + 1,
            record: real.record,
        },
        ExtentLease {
            object: real.object,
            record: LeaseRecord {
                token: real.record.token + 1,
                ..real.record
            },
        },
        ExtentLease {
            object: real.object,
            record: LeaseRecord {
                backing: real.record.backing + 1,
                ..real.record
            },
        },
        ExtentLease {
            object: real.object,
            record: LeaseRecord {
                pages: real.record.pages - 1,
                ..real.record
            },
        },
        ExtentLease {
            object: real.object,
            record: LeaseRecord {
                writable: true,
                ..real.record
            },
        },
    ] {
        assert!(o.validate(a, &lease).is_err());
        assert!(o.physical_pages(&lease).is_err());
    }
}
#[test]
fn noncontiguous_ram_frames_remain_one_object_and_one_exact_lease() {
    let mut f = allocator(192);
    let before = f.remaining_frames();
    let mut held = Vec::new();
    for i in 0..128 {
        let frame = f.allocate().unwrap();
        if i % 2 == 0 {
            held.push((true, frame));
        } else {
            held.push((false, frame));
        }
    }
    let mut odd = Vec::new();
    for (even, frame) in held {
        if even {
            f.reclaim(frame).unwrap();
        } else {
            odd.push(frame);
        }
    }
    let (mut s, j) = scheduler(64);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 64, &mut ram);
    let mut a = Authority::new();
    let d = a.create_space().unwrap();
    let (mut object, cap) = publish(&mut a, d, owner, &f, &s);
    let lease = object.map(&a, d, cap, false).unwrap();
    let pages: Vec<_> = object.physical_pages(&lease).unwrap().collect();
    assert_eq!(pages.len(), 64);
    assert!(
        pages
            .windows(2)
            .all(|p| p[0].abs_diff(p[1]) == 2 * FRAME_SIZE)
    );
    object.unmap(lease).unwrap();
    object
        .destroy(&mut a, d, cap)
        .unwrap()
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    for frame in odd {
        f.reclaim(frame).unwrap();
    }
    assert_eq!(f.remaining_frames(), before);
}
#[test]
fn bootstrap_recycle_limit_refuses_owner_without_freeing_any_prefix() {
    let mut f = allocator(2 * MAX_RECYCLED + 2 * MAX_PAGES);
    let (mut s, j) = scheduler(MAX_PAGES as u64);
    let mut ram = Ram::new();
    // Hold real intervening claims so512 returns genuinely fill512 distinct
    // runs. Contiguous returns deliberately no longer model metadata exhaustion.
    let frames: Vec<_> = (0..2 * MAX_RECYCLED)
        .map(|_| f.allocate().unwrap())
        .collect();
    let retained = initialized(&mut f, &mut s, j, MAX_PAGES, &mut ram);
    let mut held = Vec::new();
    for (index, frame) in frames.into_iter().enumerate() {
        if index % 2 == 0 {
            f.reclaim(frame).unwrap();
        } else {
            held.push(frame);
        }
    }
    assert_eq!(f.recycle_capacity(), 0);
    let before = (
        f.remaining_frames(),
        s.usage(j, Resource::Frames).unwrap(),
        ram.writes,
        ram.reads,
    );
    let rejected = retained.release(&mut f, &mut s, &mut ram).err().unwrap();
    assert_eq!(rejected.error, ReleaseError::State(Error::Capacity));
    assert_eq!(
        (
            f.remaining_frames(),
            s.usage(j, Resource::Frames).unwrap(),
            ram.writes,
            ram.reads
        ),
        before
    );
    assert_eq!(rejected.owner.0.count(), MAX_PAGES);
    // Freeing the real intervening claims creates room; retrying this rejected
    // preflight now releases the SAME owner, without a prior scrub/free prefix.
    for frame in held {
        f.reclaim(frame).unwrap();
    }
    rejected
        .owner
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(s.usage(j, Resource::Frames).unwrap(), 0);
    assert_eq!(f.recycled_frames(), (2 * MAX_RECYCLED + MAX_PAGES) as u64);
    assert_eq!(f.recycle_capacity(), MAX_RECYCLED - 1);
}

#[test]
fn destroyed_writable_ram_must_reinitialize_before_republication() {
    let mut f = allocator(8);
    let (mut s, j) = scheduler(8);
    let mut ram = Ram::new();
    let owner = initialized(&mut f, &mut s, j, 3, &mut ram);
    let mut a = Authority::new();
    let d = a.create_space().unwrap();
    let (mut object, cap) = publish(&mut a, d, owner, &f, &s);
    let lease = object.map(&a, d, cap, true).unwrap();
    let physical = object.physical_pages(&lease).unwrap().next().unwrap();
    ram.pages.get_mut(&physical).unwrap().fill(0x5a);
    object.unmap(lease).unwrap();
    let retired = object.destroy(&mut a, d, cap).unwrap();
    let before = ram.writes;
    let owner = retired
        .initialize(&mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(ram.writes - before, 3 * FRAME_SIZE);
    assert!(ram.pages.get(&physical).unwrap().iter().all(|&b| b == 0));
    owner
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
}
#[test]
fn compact_lease_metadata_has_no_sixty_four_address_array() {
    assert!(core::mem::size_of::<ExtentLease>() <= 64);
    assert!(core::mem::size_of::<MemoryExtent>() < 4096);
    assert_eq!(core::mem::size_of::<PhysicalFrame>(), 16);
}
#[test]
fn legacy_alias_layout_and_64_page_factory_remain_exact_under_every_profile() {
    #[allow(dead_code)]
    struct LegacyOwner {
        frames: [Option<PhysicalFrame>; 64],
        pages: usize,
        job: JobId,
        charge: u64,
        backing: u64,
    }
    #[allow(dead_code)]
    struct LegacyExtent {
        object: usize,
        owner: Option<LegacyOwner>,
        leases: [Option<LeaseRecord>; MAX_LEASES],
        sequence: u64,
    }
    assert_eq!(MAX_PAGES, 64);
    assert_eq!(
        core::mem::size_of::<UninitializedRam>(),
        core::mem::size_of::<LegacyOwner>()
    );
    assert_eq!(
        core::mem::size_of::<InitializedRam>(),
        core::mem::size_of::<LegacyOwner>()
    );
    assert_eq!(
        core::mem::size_of::<RetiredRam>(),
        core::mem::size_of::<LegacyOwner>()
    );
    assert_eq!(
        core::mem::size_of::<MemoryExtent>(),
        core::mem::size_of::<LegacyExtent>()
    );
    assert_eq!(
        core::mem::align_of::<MemoryExtent>(),
        core::mem::align_of::<LegacyExtent>()
    );
    let mut f = allocator(96);
    let (mut s, j) = scheduler(96);
    let before = f.remaining_frames();
    for count in [0, 65, 79, 80, usize::MAX] {
        let rejected = UninitializedRam::allocate(&mut f, &mut s, j, count)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::Count);
        assert!(rejected.owner.is_none());
        assert_eq!(f.remaining_frames(), before);
        assert_eq!(s.usage(j, Resource::Frames), Ok(0));
    }
    assert_eq!(
        BoundedUninitializedRam::<0>::allocate(&mut f, &mut s, j, 1)
            .err()
            .unwrap()
            .error,
        Error::Count
    );
    assert_eq!(
        BoundedUninitializedRam::<81>::allocate(&mut f, &mut s, j, 1)
            .err()
            .unwrap()
            .error,
        Error::Count
    );
    #[cfg(not(feature = "workspace-authority"))]
    assert_eq!(
        BoundedUninitializedRam::<80>::allocate(&mut f, &mut s, j, 1)
            .err()
            .unwrap()
            .error,
        Error::Count
    );
}
#[cfg(feature = "workspace-authority")]
#[test]
fn selected_shared_79_pages_have_real_charge_exact_lease_identity_and_complete_retirement() {
    let mut f = allocator(96);
    let before = f.remaining_frames();
    let (mut s, j) = scheduler(96);
    let mut ram = Ram::new();
    let owner = M8SharedUninitializedRam::allocate(&mut f, &mut s, j, 79)
        .unwrap_or_else(|e| panic!("{:?}", e.error))
        .initialize(&mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!((ram.writes, ram.reads), (79 * FRAME_SIZE, 79 * FRAME_SIZE));
    assert_eq!(s.usage(j, Resource::Frames), Ok(79));
    let mut a = Authority::new();
    let root = a.create_space().unwrap();
    let reader = a.create_space().unwrap();
    let (mut extent, cap) = M8SharedExtent::publish(&mut a, root, owner, &f, &s)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(extent.pages(), 79);
    assert_eq!(a.metadata_usage(), (2, 1, 1, 1));
    let writer = extent.map(&a, root, cap, true).unwrap();
    let read_cap = a
        .derive(
            root,
            cap,
            reader,
            Rights::READ | Rights::MAP | Rights::REVOKE,
        )
        .unwrap();
    assert!(extent.map(&a, reader, read_cap, true).is_err());
    let read = extent.map(&a, reader, read_cap, false).unwrap();
    assert_eq!(read.pages(), 79);
    let ids: Vec<_> = extent.physical_pages(&read).unwrap().collect();
    assert_eq!(ids.len(), 79);
    assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>().len(), 79);
    assert_eq!(extent.destroy(&mut a, root, cap).err(), Some(Error::Busy));
    // A genuine legacy extent receipt cannot alias the selected backing.
    let small = initialized(&mut f, &mut s, j, 1, &mut ram);
    let (mut other, other_cap) = publish(&mut a, root, small, &f, &s);
    let foreign = other.map(&a, root, other_cap, true).unwrap();
    assert_eq!(extent.validate(&a, &foreign), Err(Error::WrongObject));
    let (error, foreign) = extent.unmap(foreign).unwrap_err();
    assert_eq!(error, Error::WrongObject);
    other.unmap(foreign).unwrap();
    other
        .destroy(&mut a, root, other_cap)
        .unwrap()
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    a.revoke(reader, read_cap).unwrap();
    assert!(extent.validate(&a, &read).is_err());
    extent.unmap(read).unwrap();
    extent.unmap(writer).unwrap();
    let retired = extent.destroy(&mut a, root, cap).unwrap();
    retired
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(f.remaining_frames(), before);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
}
#[cfg(feature = "workspace-authority")]
#[test]
fn selected_shared_capacity_and_quota_refusals_precede_allocation_or_publication() {
    let mut f = allocator(96);
    let before = f.remaining_frames();
    let (mut s, j) = scheduler(78);
    for count in [0, 81, usize::MAX] {
        let r = M8SharedUninitializedRam::allocate(&mut f, &mut s, j, count)
            .err()
            .unwrap();
        assert_eq!(r.error, Error::Count);
        assert!(r.owner.is_none());
    }
    let r = M8SharedUninitializedRam::allocate(&mut f, &mut s, j, 79)
        .err()
        .unwrap();
    assert!(matches!(r.error, Error::Scheduler(_)));
    assert!(r.owner.is_none());
    assert_eq!(f.remaining_frames(), before);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
    let (mut s, j) = scheduler(80);
    let mut small = allocator(78);
    let r = M8SharedUninitializedRam::allocate(&mut small, &mut s, j, 79)
        .err()
        .unwrap();
    assert_eq!(r.error, Error::Exhausted);
    assert!(r.owner.is_none());
    assert_eq!(small.remaining_frames(), 78);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
}
#[cfg(feature = "workspace-authority")]
#[test]
fn selected_shared_failed_readback_retains_all_79_claims_and_charge_until_checked_release() {
    let mut f = allocator(79);
    let (mut s, j) = scheduler(79);
    let mut ram = Ram::new();
    ram.corrupt = true;
    let owner = M8SharedUninitializedRam::allocate(&mut f, &mut s, j, 79)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    let rejected = owner.initialize(&mut ram).err().unwrap();
    assert_eq!(rejected.error, InitError::Readback);
    assert_eq!(rejected.owner.pages(), 79);
    assert_eq!(f.remaining_frames(), 0);
    assert_eq!(s.usage(j, Resource::Frames), Ok(79));
    let release = rejected
        .owner
        .release(&mut f, &mut s, &mut ram)
        .err()
        .unwrap();
    assert_eq!(release.error, ReleaseError::Scrub(InitError::Readback));
    assert_eq!(f.remaining_frames(), 0);
    assert_eq!(s.usage(j, Resource::Frames), Ok(79));
    ram.corrupt = false;
    release
        .owner
        .release(&mut f, &mut s, &mut ram)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(f.remaining_frames(), 79);
    assert_eq!(s.usage(j, Resource::Frames), Ok(0));
}
#[cfg(feature = "workspace-authority")]
#[test]
fn selected_shared_metadata_growth_is_resident_only_and_keeps_legacy_lease_geometry() {
    let extra = core::mem::size_of::<M8SharedExtent>() - core::mem::size_of::<MemoryExtent>();
    assert_eq!(extra, 16 * core::mem::size_of::<Option<PhysicalFrame>>());
    let slots = core::mem::size_of::<[Option<M8SharedExtent>; 37]>()
        - core::mem::size_of::<[Option<MemoryExtent>; 37]>();
    assert_eq!(slots, 37 * extra);
    assert_eq!(slots, 14_208);
    assert!(core::mem::size_of::<ExtentLease>() <= 64);
    std::println!(
        "M8_SHARED_METADATA extent64={} extent80={} option_frame={} resident37_delta={} no_stack_or_frame_quota_claim=true",
        core::mem::size_of::<MemoryExtent>(),
        core::mem::size_of::<M8SharedExtent>(),
        core::mem::size_of::<Option<PhysicalFrame>>(),
        slots
    );
}

#[test]
fn independent_surfaces_keep_display_read_claims_across_one_writer_replacement() {
    // Portable ownership model only: no CPU, PTE or quiescence is fabricated.
    let mut frames = allocator(128);
    let before = frames.remaining_frames();
    let (mut scheduler, parent) = scheduler(128);
    let mut ram = Ram::new();
    let first = initialized(&mut frames, &mut scheduler, parent, 63, &mut ram);
    let second = initialized(&mut frames, &mut scheduler, parent, 63, &mut ram);
    let mut a = Authority::new();
    let owner = a.create_space().unwrap();
    let display = a.create_space().unwrap();
    let app = a.create_space().unwrap();
    let shell = a.create_space().unwrap();
    let replacement = a.create_space().unwrap();
    let (mut app_surface, app_root) = publish(&mut a, owner, first, &frames, &scheduler);
    let (mut shell_surface, shell_root) = publish(&mut a, owner, second, &frames, &scheduler);
    let rw = Rights::READ | Rights::WRITE | Rights::MAP;
    let ro = Rights::READ | Rights::MAP;
    let revoker = a
        .derive(
            owner,
            app_root,
            owner,
            rw | Rights::REVOKE | Rights::DERIVE | Rights::TRANSFER,
        )
        .unwrap();
    let app_cap = a.derive(owner, revoker, app, rw).unwrap();
    let app_display = a.derive(owner, app_root, display, ro).unwrap();
    let shell_cap = a.derive(owner, shell_root, shell, rw).unwrap();
    let shell_display = a.derive(owner, shell_root, display, ro).unwrap();
    let old_writer = app_surface.map(&a, app, app_cap, true).unwrap();
    let old_token = old_writer.record.token;
    let app_reader = app_surface.map(&a, display, app_display, false).unwrap();
    let shell_writer = shell_surface.map(&a, shell, shell_cap, true).unwrap();
    let shell_reader = shell_surface
        .map(&a, display, shell_display, false)
        .unwrap();
    assert_eq!(
        shell_surface.validate(&a, &app_reader),
        Err(Error::WrongObject)
    );
    a.revoke(owner, revoker).unwrap();
    assert_eq!(
        app_surface.validate(&a, &old_writer),
        Err(Error::Authority(CapError::Revoked))
    );
    app_surface.validate(&a, &app_reader).unwrap();
    shell_surface.validate(&a, &shell_reader).unwrap();
    app_surface.unmap(old_writer).unwrap();
    assert_eq!(
        app_surface.destroy(&mut a, owner, app_root).err(),
        Some(Error::Busy)
    );
    let fresh = a.derive(owner, app_root, replacement, rw).unwrap();
    let writer = app_surface.map(&a, replacement, fresh, true).unwrap();
    assert_ne!(writer.record.token, old_token);
    app_surface.validate(&a, &app_reader).unwrap();
    assert_eq!(scheduler.usage(parent, Resource::Frames), Ok(126));
    app_surface.unmap(writer).unwrap();
    app_surface.unmap(app_reader).unwrap();
    shell_surface.unmap(shell_writer).unwrap();
    shell_surface.unmap(shell_reader).unwrap();
    for (surface, cap) in [
        (&mut app_surface, app_root),
        (&mut shell_surface, shell_root),
    ] {
        surface
            .destroy(&mut a, owner, cap)
            .unwrap()
            .release(&mut frames, &mut scheduler, &mut ram)
            .unwrap_or_else(|error| panic!("{:?}", error.error));
    }
    assert_eq!(frames.remaining_frames(), before);
    assert_eq!(scheduler.usage(parent, Resource::Frames), Ok(0));
}

#[cfg(feature = "workspace-authority")]
#[test]
#[allow(unsafe_code)]
fn captured_scrub_checks_exact_live_write_lease_and_retains_partial_error_debt() {
    struct Failing<'a> {
        ram: &'a mut Ram,
        writes_left: usize,
        read_error: bool,
    }
    // SAFETY: same exact host frame model, with explicit truthful access errors.
    unsafe impl RamAccess for Failing<'_> {
        type Error = ();
        fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), ()> {
            if self.writes_left == 0 {
                return Err(());
            }
            self.writes_left -= 1;
            self.ram.write(frame, byte, value)
        }
        fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, ()> {
            if self.read_error {
                Err(())
            } else {
                self.ram.read(frame, byte)
            }
        }
    }
    let mut frames = allocator(8);
    let (mut s, job) = scheduler(8);
    let mut ram = Ram::new();
    let mut a = Authority::new();
    let domain = a.create_space().unwrap();
    let first = initialized(&mut frames, &mut s, job, 2, &mut ram);
    let second = initialized(&mut frames, &mut s, job, 2, &mut ram);
    let (mut object, cap) = publish(&mut a, domain, first, &frames, &s);
    let (mut other, other_cap) = publish(&mut a, domain, second, &frames, &s);
    let write = object.map(&a, domain, cap, true).unwrap();
    let read = object.map(&a, domain, cap, false).unwrap();
    let foreign = other.map(&a, domain, other_cap, true).unwrap();
    let owned: Vec<_> = object.physical_pages(&write).unwrap().collect();
    let unrelated: Vec<_> = other.physical_pages(&foreign).unwrap().collect();
    for p in &owned {
        ram.pages.get_mut(p).unwrap().fill(0xa5);
    }
    for p in &unrelated {
        ram.pages.get_mut(p).unwrap().fill(0x77);
    }
    let writes = ram.writes;
    // SAFETY: explicit single-threaded host RAM model has no executing alias.
    assert!(matches!(
        // SAFETY: this exclusive host frame model has no executing aliases.
        unsafe { object.scrub_captured(&a, &foreign, &mut ram) },
        Err(ScrubError::State(Error::WrongObject))
    ));
    // SAFETY: same model exclusion; readonly refusal must precede all writes.
    assert_eq!(
        // SAFETY: this exclusive host frame model has no executing aliases.
        unsafe { object.scrub_captured(&a, &read, &mut ram) },
        Err(ScrubError::ReadOnly)
    );
    assert_eq!(ram.writes, writes);
    // SAFETY: same model exclusion. This real access error intentionally occurs
    // after partial zeroing, and must leave all claims/leases/quota retained.
    assert_eq!(
        // SAFETY: this exclusive host frame model has no executing aliases.
        unsafe {
            object.scrub_captured(
                &a,
                &write,
                &mut Failing {
                    ram: &mut ram,
                    writes_left: 17,
                    read_error: false,
                },
            )
        },
        Err(ScrubError::Memory(InitError::Access(())))
    );
    assert_eq!(ram.pages[&owned[0]][..17], [0; 17]);
    assert_eq!(ram.pages[&owned[0]][17], 0xa5);
    // SAFETY: host RAM model; failure of actual readback is distinct from a
    // successful wipe and releases no backing or lease on the error path.
    assert_eq!(
        // SAFETY: this exclusive host frame model has no executing aliases.
        unsafe {
            object.scrub_captured(
                &a,
                &write,
                &mut Failing {
                    ram: &mut ram,
                    writes_left: usize::MAX,
                    read_error: true,
                },
            )
        },
        Err(ScrubError::Memory(InitError::Access(())))
    );
    ram.corrupt = true;
    // SAFETY: same model; corrupt readback is detected rather than fabricated.
    assert_eq!(
        // SAFETY: this exclusive host frame model has no executing aliases.
        unsafe { object.scrub_captured(&a, &write, &mut ram) },
        Err(ScrubError::Memory(InitError::Readback))
    );
    ram.corrupt = false;
    assert_eq!((object.live_leases(), other.live_leases()), (2, 1));
    assert_eq!(s.usage(job, Resource::Frames), Ok(4));
    assert_eq!(frames.remaining_frames(), 4);
    assert!(object.validate(&a, &write).is_ok());
    // SAFETY: same exclusive model boundary and exact live writable claim.
    unsafe { object.scrub_captured(&a, &write, &mut ram) }.unwrap();
    for p in owned {
        assert!(ram.pages[&p].iter().all(|b| *b == 0));
    }
    for p in unrelated {
        assert!(ram.pages[&p].iter().all(|b| *b == 0x77));
    }
    a.revoke(domain, cap).unwrap();
    let writes = ram.writes;
    // SAFETY: same model; a revoked exact retained lease still cannot authorize
    // new writes, even though cleanup retains its affine receipt and frames.
    assert!(matches!(
        // SAFETY: this exclusive host frame model has no executing aliases.
        unsafe { object.scrub_captured(&a, &write, &mut ram) },
        Err(ScrubError::State(Error::Authority(_)))
    ));
    assert_eq!(ram.writes, writes);
    assert_eq!(object.pages(), 2);
    assert_eq!(
        (object.live_leases(), s.usage(job, Resource::Frames)),
        (2, Ok(4))
    );
}
