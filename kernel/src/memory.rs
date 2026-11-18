//! Allocation-free bootstrap bookkeeping. Addresses are not mappings or authority.
use core::sync::atomic::{AtomicU64, Ordering};
use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
static NEXT_ALLOCATOR: AtomicU64 = AtomicU64::new(1);
/// Fixed metadata entries, each retaining one contiguous owned RAM run.
pub const MAX_RECYCLED: usize = 512;

pub const FRAME_SIZE: u64 = 4096;

/// A selected frame, not a reference to its contents. Deliberately not Copy/Clone.
#[derive(Debug, PartialEq, Eq)]
pub struct PhysicalFrame {
    start: u64,
    allocator: u64,
}

impl PhysicalFrame {
    pub fn start(&self) -> u64 {
        self.start
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Exhausted;
#[derive(Debug, PartialEq, Eq)]
pub enum ReclaimError {
    WrongAllocator,
    Capacity,
    Overlap,
}

// Packed sorted owned free-run metadata. No mapping or authority is inferred.
struct FreeRun {
    first: u64,
    pages: u64,
}
impl FreeRun {
    fn end(&self) -> u64 {
        self.first + self.pages * FRAME_SIZE
    }
}

/// One owner during bootstrap, before interrupts or other CPUs allocate.
///
/// Consumes the validated map to prevent accidentally resetting a borrowed map's
/// cursor. Creating another map for the same RAM does not confer ownership.
/// Retain this state until a later allocator explicitly imports its claims.
/// Reclamation accepts only owned claims from this allocator. The hardware
/// boundary must remove mappings and prove quiescence first; bookkeeping never
/// touches physical bytes. Returned frames require zeroing before user exposure.
pub struct BootstrapFrames {
    identity: u64,
    recycled: [Option<FreeRun>; MAX_RECYCLED],
    recycled_frames: u64,
    recycled_count: usize,
    reuse_count: u64,
    map: MemoryMap,
    region: usize,
    next: u64,
    total: u64,
    remaining: u64,
}

fn whole_frames(region: &MemoryRegion) -> (u64, u64) {
    // MemoryMap validation bounds both addresses by 2^52, so rounding cannot
    // overflow. Never allocate page zero, even if firmware labels it usable.
    let start = ((region.start + FRAME_SIZE - 1) & !(FRAME_SIZE - 1)).max(FRAME_SIZE);
    let end = region.end & !(FRAME_SIZE - 1);
    (start, end)
}

impl BootstrapFrames {
    pub fn new(map: MemoryMap) -> Self {
        let total = map
            .regions()
            .iter()
            .filter(|region| region.kind == MemoryKind::Usable)
            .map(|region| {
                let (start, end) = whole_frames(region);
                end.saturating_sub(start) / FRAME_SIZE
            })
            .sum();
        Self {
            identity: NEXT_ALLOCATOR
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .expect("allocator identity exhausted"),
            recycled: [const { None }; MAX_RECYCLED],
            recycled_count: 0,
            recycled_frames: 0,
            reuse_count: 0,
            map,
            region: 0,
            next: FRAME_SIZE,
            total,
            remaining: total,
        }
    }

    pub fn total_frames(&self) -> u64 {
        self.total
    }
    /// Read-only retained boot classification for trusted device/table walks.
    /// This conveys no RAM claim and cannot reset or clone the allocator.
    pub fn memory_map(&self) -> &MemoryMap {
        &self.map
    }

    pub fn remaining_frames(&self) -> u64 {
        self.remaining
    }
    pub fn contains_reserved(&self, physical: u64, length: u64) -> bool {
        self.map.contains_reserved(physical, length)
    }

    /// Used to verify that the inherited CR3 root is never in our usable pool.
    pub fn is_reserved_frame(&self, physical: u64) -> bool {
        physical.is_multiple_of(FRAME_SIZE)
            && physical.checked_add(FRAME_SIZE).is_some_and(|end| {
                self.map.regions().iter().any(|region| {
                    region.kind == MemoryKind::Reserved
                        && physical >= region.start
                        && end <= region.end
                })
            })
    }

    pub fn owns(&self, frame: &PhysicalFrame) -> bool {
        frame.allocator == self.identity
    }
    /// Conservative minimum additional independent claims guaranteed to fit.
    /// Adjacent returns may coalesce even when this lower bound is zero.
    pub fn recycle_capacity(&self) -> usize {
        MAX_RECYCLED - self.recycled_count
    }
    pub fn recycled_frames(&self) -> u64 {
        self.recycled_frames
    }
    pub fn reused_frames(&self) -> u64 {
        self.reuse_count
    }
    fn remove_run(&mut self, index: usize) -> FreeRun {
        let run = self.recycled[index].take().expect("packed recycle runs");
        for i in index..self.recycled_count - 1 {
            self.recycled[i] = self.recycled[i + 1].take();
        }
        self.recycled_count -= 1;
        run
    }
    pub fn reclaim(&mut self, frame: PhysicalFrame) -> Result<(), (ReclaimError, PhysicalFrame)> {
        if frame.allocator != self.identity {
            return Err((ReclaimError::WrongAllocator, frame));
        }
        let start = frame.start;
        let end = start + FRAME_SIZE;
        let mut index = 0;
        while index < self.recycled_count && self.recycled[index].as_ref().unwrap().first < start {
            index += 1;
        }
        let left = index.checked_sub(1).and_then(|i| self.recycled[i].as_ref());
        let right = self.recycled.get(index).and_then(Option::as_ref);
        if left.is_some_and(|r| r.end() > start) || right.is_some_and(|r| r.first < end) {
            return Err((ReclaimError::Overlap, frame));
        }
        let joins_left = left.is_some_and(|r| r.end() == start);
        let joins_right = right.is_some_and(|r| r.first == end);
        match (joins_left, joins_right) {
            (true, true) => {
                let right = self.remove_run(index);
                self.recycled[index - 1].as_mut().unwrap().pages += 1 + right.pages;
            }
            (true, false) => self.recycled[index - 1].as_mut().unwrap().pages += 1,
            (false, true) => {
                let run = self.recycled[index].as_mut().unwrap();
                run.first = start;
                run.pages += 1;
            }
            (false, false) => {
                if self.recycled_count == MAX_RECYCLED {
                    return Err((ReclaimError::Capacity, frame));
                }
                for i in (index..self.recycled_count).rev() {
                    self.recycled[i + 1] = self.recycled[i].take();
                }
                self.recycled[index] = Some(FreeRun {
                    first: start,
                    pages: 1,
                });
                self.recycled_count += 1;
            }
        }
        self.recycled_frames += 1;
        self.remaining += 1;
        Ok(())
    }
    pub fn allocate(&mut self) -> Result<PhysicalFrame, Exhausted> {
        if self.recycled_count > 0 {
            let reuse_count = self.reuse_count.checked_add(1).ok_or(Exhausted)?;
            let run = self.recycled[0].as_mut().expect("packed recycle runs");
            let start = run.first;
            run.first += FRAME_SIZE;
            run.pages -= 1;
            if run.pages == 0 {
                self.remove_run(0);
            }
            self.recycled_frames -= 1;
            self.remaining -= 1;
            self.reuse_count = reuse_count;
            return Ok(PhysicalFrame {
                start,
                allocator: self.identity,
            });
        }
        while let Some(region) = self.map.regions().get(self.region) {
            if region.kind == MemoryKind::Usable {
                let (start, end) = whole_frames(region);
                self.next = self.next.max(start);
                if self.next < end {
                    let frame = PhysicalFrame {
                        start: self.next,
                        allocator: self.identity,
                    };
                    self.next += FRAME_SIZE;
                    self.remaining -= 1;
                    return Ok(frame);
                }
            }
            self.region += 1;
        }
        Err(Exhausted)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ev_boot_contract::{BootError, MAX_MEMORY_REGIONS};
    use std::{vec, vec::Vec};
    #[test]
    fn free_run_keeps_the_existing_metadata_entry_layout() {
        assert_eq!(
            core::mem::size_of::<Option<FreeRun>>(),
            core::mem::size_of::<Option<PhysicalFrame>>()
        );
        assert_eq!(core::mem::size_of::<Option<FreeRun>>(), 24);
    }

    #[test]
    fn extent_preflight_counts_all_frames_in_a_run_before_reuse_overflow() {
        use crate::{
            memory_extent::{Error, MAX_PAGES, UninitializedRam},
            scheduler::{Limits, Resource, Scheduler},
        };
        let mut a = BootstrapFrames::new(
            MemoryMap::validate([usable(FRAME_SIZE, (MAX_PAGES as u64 + 1) * FRAME_SIZE)]).unwrap(),
        );
        let frames: Vec<_> = (0..MAX_PAGES).map(|_| a.allocate().unwrap()).collect();
        for frame in frames {
            a.reclaim(frame).unwrap();
        }
        assert_eq!(a.recycle_capacity(), MAX_RECYCLED - 1);
        assert_eq!(a.recycled_frames(), MAX_PAGES as u64);
        // Test-only private boundary injection; production has no reset API.
        a.reuse_count = u64::MAX - (MAX_PAGES as u64 - 1);
        let mut scheduler = Scheduler::new();
        let job = scheduler
            .create_job_with_limits(Limits::new(1000, MAX_PAGES as u64, 1, 1))
            .unwrap();
        let before = (
            a.remaining_frames(),
            a.recycled_frames(),
            a.reused_frames(),
            a.recycle_capacity(),
            scheduler.usage(job, Resource::Frames).unwrap(),
        );
        let rejected = UninitializedRam::allocate(&mut a, &mut scheduler, job, MAX_PAGES)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::Exhausted);
        assert!(rejected.owner.is_none());
        assert_eq!(
            (
                a.remaining_frames(),
                a.recycled_frames(),
                a.reused_frames(),
                a.recycle_capacity(),
                scheduler.usage(job, Resource::Frames).unwrap()
            ),
            before
        );
    }

    fn usable(start: u64, end: u64) -> MemoryRegion {
        MemoryRegion {
            start,
            end,
            kind: MemoryKind::Usable,
        }
    }

    fn reserved(start: u64, end: u64) -> MemoryRegion {
        MemoryRegion {
            start,
            end,
            kind: MemoryKind::Reserved,
        }
    }

    fn check(regions: &[MemoryRegion], expected: &[u64]) {
        let mut allocator =
            BootstrapFrames::new(MemoryMap::validate(regions.iter().copied()).unwrap());
        assert_eq!(allocator.total_frames(), expected.len() as u64);
        for (index, address) in expected.iter().enumerate() {
            assert_eq!(allocator.allocate().unwrap().start(), *address);
            assert_eq!(
                allocator.remaining_frames(),
                (expected.len() - index - 1) as u64
            );
        }
        for _ in 0..3 {
            assert_eq!(allocator.allocate(), Err(Exhausted));
            assert_eq!(allocator.remaining_frames(), 0);
            assert_eq!(allocator.total_frames(), expected.len() as u64);
        }
    }

    #[test]
    fn recycled_claims_preserve_counts_and_cannot_cross_allocator_identity() {
        let map = || MemoryMap::validate([usable(4096, 16384)]).unwrap();
        let mut a = BootstrapFrames::new(map());
        let mut b = BootstrapFrames::new(map());
        let frame = a.allocate().unwrap();
        let address = frame.start();
        let (error, frame) = b.reclaim(frame).unwrap_err();
        assert_eq!(error, ReclaimError::WrongAllocator);
        assert_eq!(b.remaining_frames(), 3);
        assert_eq!(a.remaining_frames(), 2);
        a.reclaim(frame).unwrap();
        assert_eq!(a.remaining_frames(), 3);
        for cycle in 1..100 {
            let frame = a.allocate().unwrap();
            assert_eq!(frame.start(), address);
            assert_eq!(a.remaining_frames(), 2);
            assert_eq!(a.reused_frames(), cycle);
            a.reclaim(frame).unwrap();
        }
    }
    #[test]
    fn full_fragmented_metadata_returns_exact_owner_and_merge_restores_capacity() {
        let count = 2 * (MAX_RECYCLED + 1);
        let mut a = BootstrapFrames::new(
            MemoryMap::validate([usable(4096, (count as u64 + 1) * 4096)]).unwrap(),
        );
        let mut all: Vec<_> = (0..count).map(|_| Some(a.allocate().unwrap())).collect();
        for i in 0..MAX_RECYCLED {
            a.reclaim(all[2 * i].take().unwrap()).unwrap();
        }
        let extra = all[2 * MAX_RECYCLED].take().unwrap();
        assert_eq!(a.recycle_capacity(), 0);
        let address = extra.start();
        let (error, extra) = a.reclaim(extra).unwrap_err();
        assert_eq!(error, ReclaimError::Capacity);
        assert_eq!(extra.start(), address);
        assert_eq!(a.remaining_frames(), MAX_RECYCLED as u64);
        a.reclaim(all[1].take().unwrap()).unwrap(); // bridges two existing runs
        assert_eq!(a.recycle_capacity(), 1);
        a.reclaim(extra).unwrap();
        for frame in all.into_iter().flatten() {
            a.reclaim(frame).unwrap();
        }
        assert_eq!(a.recycled_frames(), count as u64);
        assert_eq!(a.recycled_count, 1);
        let addresses: Vec<_> = (0..count).map(|_| a.allocate().unwrap().start()).collect();
        assert!(addresses.windows(2).all(|v| v[1] == v[0] + 4096));
        assert_eq!(a.allocate(), Err(Exhausted));
        assert_eq!(a.remaining_frames(), 0);
    }
    #[test]
    fn more_than512_contiguous_returns_use_one_metadata_entry_without_losing_identity() {
        let count = 4096;
        let mut a =
            BootstrapFrames::new(MemoryMap::validate([usable(4096, (count + 1) * 4096)]).unwrap());
        let mut all: Vec<_> = (0..count).map(|_| a.allocate().unwrap()).collect();
        while let Some(frame) = all.pop() {
            a.reclaim(frame).unwrap();
        }
        assert_eq!(a.recycled_count, 1);
        assert_eq!(a.recycle_capacity(), MAX_RECYCLED - 1);
        assert_eq!(a.recycled_frames(), count);
        assert_eq!(a.remaining_frames(), count);
        for i in 1..=count {
            assert_eq!(a.allocate().unwrap().start(), i * 4096);
        }
        assert_eq!(a.reused_frames(), count);
        assert_eq!(a.recycled_frames(), 0);
        assert_eq!(a.recycle_capacity(), MAX_RECYCLED);
        assert_eq!(a.allocate(), Err(Exhausted));
    }
    #[test]
    fn reuse_counter_overflow_cannot_consume_the_retained_claim() {
        let mut a = BootstrapFrames::new(MemoryMap::validate([usable(4096, 8192)]).unwrap());
        let frame = a.allocate().unwrap();
        a.reclaim(frame).unwrap();
        a.reuse_count = u64::MAX;
        assert_eq!(a.allocate(), Err(Exhausted));
        assert_eq!(a.remaining_frames(), 1);
        assert_eq!(a.recycled_count, 1);
    }
    #[test]
    fn overlapping_return_preserves_the_rejected_token_and_entire_run() {
        let mut a = BootstrapFrames::new(MemoryMap::validate([usable(4096, 16384)]).unwrap());
        let mut frames: Vec<_> = (0..3).map(|_| a.allocate().unwrap()).collect();
        // Private adversarial fabrication is unavailable to production callers.
        let duplicate = PhysicalFrame {
            start: frames[1].start,
            allocator: frames[1].allocator,
        };
        while let Some(frame) = frames.pop() {
            a.reclaim(frame).unwrap();
        }
        let before = (
            a.remaining_frames(),
            a.recycled_frames(),
            a.reused_frames(),
            a.recycle_capacity(),
        );
        let (error, rejected) = a.reclaim(duplicate).unwrap_err();
        assert_eq!(error, ReclaimError::Overlap);
        assert_eq!(rejected.start, 8192);
        assert_eq!(rejected.allocator, a.identity);
        assert_eq!(
            (
                a.remaining_frames(),
                a.recycled_frames(),
                a.reused_frames(),
                a.recycle_capacity(),
            ),
            before
        );
        for expected in [4096, 8192, 12288] {
            assert_eq!(a.allocate().unwrap().start(), expected);
        }
        assert_eq!(a.allocate(), Err(Exhausted));
    }
    #[test]
    fn skips_reserved_regions_holes_and_sorts_the_handoff() {
        check(
            &[
                usable(0x9000, 0xb000),
                reserved(0x3000, 0x8000),
                usable(0x1000, 0x3000),
            ],
            &[0x1000, 0x2000, 0x9000, 0xa000],
        );
    }

    #[test]
    fn rounds_inward_and_never_allocates_page_zero() {
        check(
            &[usable(0, 0x2801), usable(0x4001, 0x7001)],
            &[0x1000, 0x5000, 0x6000],
        );
        check(&[usable(0, FRAME_SIZE)], &[]);
        check(&[usable(0x1001, 0x2000)], &[]);
        check(&[usable(0x1000, 0x2000)], &[0x1000]);
    }

    #[test]
    fn a_page_crossing_a_region_boundary_is_not_assembled_from_fragments() {
        check(
            &[usable(0x1000, 0x2800), usable(0x2800, 0x4000)],
            &[0x1000, 0x3000],
        );
        check(
            &[usable(0x1000, 0x2800), reserved(0x2800, 0x3000)],
            &[0x1000],
        );
    }

    #[test]
    fn no_usable_pages_is_explicit_exhaustion() {
        check(&[reserved(0, 1 << 52)], &[]);
        check(&[usable(1, 2)], &[]);
    }

    #[test]
    fn inherited_table_check_requires_a_whole_aligned_reserved_frame() {
        let allocator = BootstrapFrames::new(
            MemoryMap::validate([reserved(0x1000, 0x3100), usable(0x4000, 0x8000)]).unwrap(),
        );
        assert!(allocator.is_reserved_frame(0x1000));
        assert!(allocator.is_reserved_frame(0x2000));
        for invalid in [0, 0x1001, 0x3000, 0x4000, u64::MAX - 4095] {
            assert!(!allocator.is_reserved_frame(invalid));
        }
    }

    #[test]
    fn highest_valid_frame_and_large_extent_do_not_overflow() {
        let limit = 1 << 52;
        check(
            &[usable(limit - 2 * FRAME_SIZE + 1, limit)],
            &[limit - FRAME_SIZE],
        );
        let mut allocator = BootstrapFrames::new(MemoryMap::validate([usable(0, limit)]).unwrap());
        assert_eq!(allocator.total_frames(), limit / FRAME_SIZE - 1);
        assert_eq!(allocator.allocate().unwrap().start(), FRAME_SIZE);
        assert_eq!(allocator.allocate().unwrap().start(), 2 * FRAME_SIZE);
        assert_eq!(allocator.remaining_frames(), limit / FRAME_SIZE - 3);
    }

    #[test]
    fn maximum_fragmented_map_has_unique_frames_and_exact_counts() {
        let regions: Vec<_> = (0..MAX_MEMORY_REGIONS as u64)
            .map(|i| usable((2 * i + 1) * FRAME_SIZE, (2 * i + 2) * FRAME_SIZE))
            .collect();
        let expected: Vec<_> = (0..MAX_MEMORY_REGIONS as u64)
            .map(|i| (2 * i + 1) * FRAME_SIZE)
            .collect();
        check(&regions, &expected);
    }

    #[test]
    fn small_maps_match_independent_whole_page_containment_oracle() {
        // Exercise all sub-page offsets for gaps and a reserved middle region.
        for left in 0..16 {
            for right in 17..32 {
                for reserved_middle in [false, true] {
                    let regions = [
                        usable(0, left * 1024 + 1),
                        if reserved_middle {
                            reserved(left * 1024 + 1, right * 1024)
                        } else {
                            usable(left * 1024 + 1, right * 1024)
                        },
                        usable(right * 1024, 9 * FRAME_SIZE),
                    ];
                    let expected: Vec<_> = (1..9)
                        .map(|i| i * FRAME_SIZE)
                        .filter(|page| {
                            regions.iter().any(|r| {
                                r.kind == MemoryKind::Usable
                                    && *page >= r.start
                                    && *page + FRAME_SIZE <= r.end
                            })
                        })
                        .collect();
                    check(&regions, &expected);
                }
            }
        }
    }

    #[test]
    fn malformed_input_cannot_construct_the_required_validated_map() {
        assert_eq!(
            MemoryMap::validate([usable(10, 10)]).unwrap_err(),
            BootError::InvalidMemoryRange
        );
        assert_eq!(
            MemoryMap::validate([usable(0, (1 << 52) + 1)]).unwrap_err(),
            BootError::InvalidMemoryRange
        );
        assert_eq!(
            MemoryMap::validate([usable(0x1000, 0x3000), reserved(0x2000, 0x4000)]).unwrap_err(),
            BootError::OverlappingMemory
        );
        assert_eq!(
            MemoryMap::validate(vec![usable(1, 2); MAX_MEMORY_REGIONS + 1]).unwrap_err(),
            BootError::TooManyRegions
        );
    }
}
