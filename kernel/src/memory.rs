//! Allocation-free bootstrap bookkeeping. Addresses are not mappings or authority.
use core::sync::atomic::{AtomicU64, Ordering};
use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
static NEXT_ALLOCATOR: AtomicU64 = AtomicU64::new(1);
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
    recycled: [Option<PhysicalFrame>; MAX_RECYCLED],
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
    pub fn recycle_capacity(&self) -> usize {
        MAX_RECYCLED - self.recycled_count
    }
    pub fn reused_frames(&self) -> u64 {
        self.reuse_count
    }
    pub fn reclaim(&mut self, frame: PhysicalFrame) -> Result<(), (ReclaimError, PhysicalFrame)> {
        if frame.allocator != self.identity {
            return Err((ReclaimError::WrongAllocator, frame));
        }
        if self.recycled_count == MAX_RECYCLED {
            return Err((ReclaimError::Capacity, frame));
        }
        self.recycled[self.recycled_count] = Some(frame);
        self.recycled_count += 1;
        self.remaining += 1;
        Ok(())
    }
    pub fn allocate(&mut self) -> Result<PhysicalFrame, Exhausted> {
        if self.recycled_count > 0 {
            let reuse_count = self.reuse_count.checked_add(1).ok_or(Exhausted)?;
            self.recycled_count -= 1;
            self.remaining -= 1;
            self.reuse_count = reuse_count;
            return Ok(self.recycled[self.recycled_count]
                .take()
                .expect("packed recycle pool"));
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
    fn full_recycle_metadata_returns_owned_frame_without_losing_accounting() {
        let mut a = BootstrapFrames::new(
            MemoryMap::validate([usable(4096, (MAX_RECYCLED as u64 + 2) * 4096)]).unwrap(),
        );
        let mut frames: Vec<_> = (0..=MAX_RECYCLED).map(|_| a.allocate().unwrap()).collect();
        let extra = frames.pop().unwrap();
        for frame in frames {
            a.reclaim(frame).unwrap();
        }
        assert_eq!(a.recycle_capacity(), 0);
        let (error, extra) = a.reclaim(extra).unwrap_err();
        assert_eq!(error, ReclaimError::Capacity);
        assert_eq!(a.remaining_frames(), MAX_RECYCLED as u64);
        let outstanding = a.allocate().unwrap();
        a.reclaim(extra).unwrap();
        assert_eq!(a.remaining_frames(), MAX_RECYCLED as u64);
        let mut addresses: Vec<_> = (0..MAX_RECYCLED)
            .map(|_| a.allocate().unwrap().start())
            .collect();
        addresses.push(outstanding.start());
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), MAX_RECYCLED + 1);
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
