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
    assert!(MAX_RECYCLED.is_multiple_of(MAX_PAGES));
    let mut f = allocator(MAX_RECYCLED + 2 * MAX_PAGES);
    let (mut s, j) = scheduler((MAX_RECYCLED + MAX_PAGES) as u64);
    let mut ram = Ram::new();
    // Allocate every real owner before returning any, so recycling cannot
    // accidentally replace the capacity test with repeated reuse of one extent.
    let owners: Vec<_> = (0..MAX_RECYCLED / MAX_PAGES)
        .map(|_| initialized(&mut f, &mut s, j, MAX_PAGES, &mut ram))
        .collect();
    let retained = initialized(&mut f, &mut s, j, MAX_PAGES, &mut ram);
    for owner in owners {
        owner
            .release(&mut f, &mut s, &mut ram)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
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
    // Explicitly retained claim, not a false complete-graph retirement claim.
    let _retained_owner = rejected.owner;
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
