//! Safe, bounded ownership model for a private bootstrap user window.
use crate::{
    mapping::{ENTRIES, MapError, NO_EXECUTE, PRESENT, WRITABLE},
    memory::{FRAME_SIZE, PhysicalFrame},
};
pub const USER: u64 = 4;
/// Owned private-page metadata for bounded bringup: at most 64 loader image
/// pages, one bootstrap page, one stack and two spare private pages. Hardware
/// leaf tables still cover all 512 virtual pages. This is not a permanent VM or
/// product limit; shared Memory Object leases are tracked separately.
pub const MAX_PRIVATE_PAGES: usize = 68;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPermission {
    ReadOnly,
    ReadWrite,
    ReadExecute,
}
#[cfg(all(test, feature = "workspace-authority"))]
#[path = "user_io_buffer_tests.rs"]
mod io_buffer_tests;

struct OwnedPage {
    frame: PhysicalFrame,
    index: u16,
    permission: UserPermission,
}
pub type UserMappings = PrivateUserMappings<MAX_PRIVATE_PAGES>;
/// Fixed-capacity ownership; the ordinary alias retains its original layout.
pub struct PrivateUserMappings<const N: usize> {
    base: u64,
    // Sorted occupied prefix preserves the dense map's ascending virtual-page
    // frame iteration/retirement order without 512 owned-frame slots per root.
    pages: [Option<OwnedPage>; N],
}
/// A fixed sector span borrowed from actual affine private RAM claims. Shared
/// mappings have no claim in this ledger and cannot become an I/O buffer.
#[cfg(feature = "workspace-authority")]
pub struct PrivateIoBuffer<'a> {
    parts: [Option<(&'a PhysicalFrame, usize, usize)>; 2],
}
/// Exact three-level path to the owned private PT for this2MiB window. The
/// physical HAL reads these entries from retained PML4/PDPT/PD frames at IF0.
#[cfg(feature = "workspace-authority")]
pub fn private_io_walk(tables: &[PhysicalFrame; 4], actual: [u64; 3]) -> Result<(), MapError> {
    for (entry, child) in actual.into_iter().zip(&tables[1..]) {
        if entry & !((1 << 5) | (1 << 6)) != child.start() | PRESENT | WRITABLE | USER {
            return Err(MapError::Address);
        }
    }
    Ok(())
}
#[cfg(feature = "workspace-authority")]
impl PrivateIoBuffer<'_> {
    pub fn frames(&self) -> impl Iterator<Item = &PhysicalFrame> {
        self.parts.iter().flatten().map(|p| p.0)
    }
    pub fn read<R: crate::memory_extent::RamAccess>(
        &self,
        ram: &mut R,
        bytes: &mut [u8; 512],
    ) -> Result<(), R::Error> {
        let mut at = 0;
        for &(frame, offset, count) in self.parts.iter().flatten() {
            for i in 0..count {
                bytes[at] = ram.read(frame, offset + i)?;
                at += 1;
            }
        }
        Ok(())
    }
    pub fn write<R: crate::memory_extent::RamAccess>(
        &self,
        ram: &mut R,
        bytes: &[u8; 512],
    ) -> Result<(), R::Error> {
        let mut at = 0;
        for &(frame, offset, count) in self.parts.iter().flatten() {
            for i in 0..count {
                ram.write(frame, offset + i, bytes[at])?;
                at += 1;
            }
        }
        Ok(())
    }
}
impl<const N: usize> PrivateUserMappings<N> {
    /// Preflight the entire byte-addressed sector before any copy or port I/O.
    /// The callback reads actual retained hardware PTEs; A/D changes alone are
    /// ignored. Both pages must match exclusive private RW/NX ownership exactly.
    #[cfg(feature = "workspace-authority")]
    pub fn io_buffer(
        &self,
        address: u64,
        mut actual: impl FnMut(usize) -> Result<u64, MapError>,
    ) -> Result<PrivateIoBuffer<'_>, MapError> {
        let offset = address.checked_sub(self.base).ok_or(MapError::Address)?;
        let end = offset.checked_add(512).ok_or(MapError::Address)?;
        if end > ENTRIES as u64 * FRAME_SIZE {
            return Err(MapError::Address);
        }
        let first = (offset / FRAME_SIZE) as usize;
        let last = ((end - 1) / FRAME_SIZE) as usize;
        let mut parts = [None; 2];
        let mut remaining = 512;
        for index in first..=last {
            let page = self
                .pages
                .iter()
                .flatten()
                .find(|p| usize::from(p.index) == index)
                .ok_or(MapError::Missing)?;
            if page.permission != UserPermission::ReadWrite {
                return Err(MapError::Address);
            }
            let expected = page.frame.start() | PRESENT | USER | WRITABLE | NO_EXECUTE;
            if actual(index)? & !((1 << 5) | (1 << 6)) != expected {
                return Err(MapError::Address);
            }
            let byte = if index == first {
                (offset % FRAME_SIZE) as usize
            } else {
                0
            };
            let count = remaining.min(FRAME_SIZE as usize - byte);
            parts[index - first] = Some((&page.frame, byte, count));
            remaining -= count;
        }
        Ok(PrivateIoBuffer { parts })
    }
    pub fn new(slot: usize) -> Result<Self, MapError> {
        if !(1..256).contains(&slot) || N == 0 || N > ENTRIES {
            return Err(MapError::Address);
        }
        Ok(Self {
            base: (slot as u64) << 39,
            pages: [const { None }; N],
        })
    }
    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn index(&self, address: u64) -> Result<usize, MapError> {
        let offset = address.checked_sub(self.base).ok_or(MapError::Address)?;
        if offset >= ENTRIES as u64 * FRAME_SIZE || !offset.is_multiple_of(FRAME_SIZE) {
            return Err(MapError::Address);
        }
        Ok((offset / FRAME_SIZE) as usize)
    }
    pub fn map(
        &mut self,
        address: u64,
        frame: PhysicalFrame,
        permission: UserPermission,
    ) -> Result<(), (MapError, PhysicalFrame)> {
        let index = match self.index(address) {
            Ok(i) => i,
            Err(e) => return Err((e, frame)),
        };
        if self
            .pages
            .iter()
            .flatten()
            .any(|page| usize::from(page.index) == index)
        {
            return Err((MapError::Occupied, frame));
        }
        let Some(vacant) = self.pages.iter().position(Option::is_none) else {
            return Err((MapError::Capacity, frame));
        };
        let insert = self.pages[..vacant]
            .iter()
            .position(|page| usize::from(page.as_ref().unwrap().index) > index)
            .unwrap_or(vacant);
        for i in (insert + 1..=vacant).rev() {
            self.pages[i] = self.pages[i - 1].take();
        }
        // index() bounds the leaf index below 512, so this conversion is exact.
        self.pages[insert] = Some(OwnedPage {
            frame,
            index: index as u16,
            permission,
        });
        Ok(())
    }
    pub fn frames(&self) -> impl Iterator<Item = &PhysicalFrame> {
        self.pages.iter().flatten().map(|page| &page.frame)
    }
    /// Consume software mapping ownership after the hardware boundary has
    /// removed access and invalidated translations. Frames remain in ascending
    /// virtual-page order, followed by empty metadata slots. No claim is copied.
    pub fn into_frames(self) -> [Option<PhysicalFrame>; N] {
        self.pages.map(|page| page.map(|page| page.frame))
    }
    /// Return software ownership only after the hardware owner removed this
    /// mapping and invalidated translations. This does not edit a hardware PTE.
    pub fn unmap(&mut self, address: u64) -> Result<PhysicalFrame, MapError> {
        let index = self.index(address)?;
        let position = self
            .pages
            .iter()
            .position(|page| {
                page.as_ref()
                    .is_some_and(|page| usize::from(page.index) == index)
            })
            .ok_or(MapError::Missing)?;
        let page = self.pages[position].take().unwrap();
        for i in position..N - 1 {
            self.pages[i] = self.pages[i + 1].take();
        }
        Ok(page.frame)
    }
    pub fn entry(&self, address: u64) -> Result<u64, MapError> {
        let index = self.index(address)?;
        Ok(
            match self
                .pages
                .iter()
                .flatten()
                .find(|page| usize::from(page.index) == index)
            {
                None => 0,
                Some(page) => {
                    page.frame.start()
                        | PRESENT
                        | USER
                        | match page.permission {
                            UserPermission::ReadOnly => NO_EXECUTE,
                            UserPermission::ReadWrite => NO_EXECUTE | WRITABLE,
                            UserPermission::ReadExecute => 0,
                        }
                }
            },
        )
    }
}

/// Exact end-of-fixture trap, never a userspace-selected kernel continuation.
#[derive(Clone, Copy)]
pub struct UserTrap {
    pub vector: u64,
    pub error: u64,
    pub ip: u64,
    pub address: u64,
    pub stack_top: u64,
}
impl UserTrap {
    pub fn matches(&self, actual: &Self, cs: u64, ss: u64, flags: u64) -> bool {
        cs == 35
            && ss == 27
            && flags & ((3 << 12) | (1 << 9) | (1 << 8) | (1 << 17)) == 0
            && self.vector == actual.vector
            && self.error == actual.error
            && self.ip == actual.ip
            && (self.vector != 14 || self.address == actual.address)
            && actual.stack_top <= self.stack_top
            && actual.stack_top > self.stack_top.saturating_sub(FRAME_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BootstrapFrames;
    use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
    fn allocator() -> BootstrapFrames {
        BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: FRAME_SIZE,
                end: 1024 * 1024,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        )
    }
    fn expected_entry(physical: u64, permission: UserPermission) -> u64 {
        physical
            | PRESENT
            | USER
            | match permission {
                UserPermission::ReadOnly => NO_EXECUTE,
                UserPermission::ReadWrite => NO_EXECUTE | WRITABLE,
                UserPermission::ReadExecute => 0,
            }
    }
    #[test]
    fn separate_native_capacity_preserves_old_layout_and_reclaims_every_claim() {
        struct OldLayout {
            _base: u64,
            _pages: [Option<OwnedPage>; 68],
        }
        assert_eq!(MAX_PRIVATE_PAGES, 68);
        assert_eq!(
            core::mem::size_of::<UserMappings>(),
            core::mem::size_of::<OldLayout>()
        );
        assert_eq!(
            core::mem::align_of::<UserMappings>(),
            core::mem::align_of::<OldLayout>()
        );
        let mut frames = allocator();
        let total = frames.remaining_frames();
        let mut map = PrivateUserMappings::<100>::new(1).unwrap();
        for index in (0..100).rev() {
            map.map(
                map.base() + index * FRAME_SIZE,
                frames.allocate().unwrap(),
                UserPermission::ReadOnly,
            )
            .unwrap();
        }
        assert_eq!(map.frames().count(), 100);
        let spare = frames.allocate().unwrap();
        let physical = spare.start();
        let (error, spare) = map
            .map(
                map.base() + 511 * FRAME_SIZE,
                spare,
                UserPermission::ReadWrite,
            )
            .unwrap_err();
        assert_eq!(error, MapError::Capacity);
        assert_eq!(spare.start(), physical);
        let removed = map.unmap(map.base() + 70 * FRAME_SIZE).unwrap();
        frames.reclaim(removed).unwrap();
        map.map(
            map.base() + 511 * FRAME_SIZE,
            spare,
            UserPermission::ReadWrite,
        )
        .unwrap();
        assert_eq!(map.entry(map.base() + 70 * FRAME_SIZE), Ok(0));
        assert_eq!(
            map.entry(map.base() + 511 * FRAME_SIZE),
            Ok(expected_entry(physical, UserPermission::ReadWrite))
        );
        for frame in map.into_frames().into_iter().flatten() {
            frames.reclaim(frame).unwrap();
        }
        assert_eq!(frames.remaining_frames(), total);
        assert!(PrivateUserMappings::<0>::new(1).is_err());
        assert!(PrivateUserMappings::<513>::new(1).is_err());
    }
    #[test]
    fn sparse_metadata_keeps_full_leaf_geometry_and_reduces_owned_storage() {
        let dense_bytes = core::mem::size_of::<u64>()
            + core::mem::size_of::<[Option<(PhysicalFrame, UserPermission)>; ENTRIES]>();
        let sparse_bytes = core::mem::size_of::<UserMappings>();
        assert!(
            sparse_bytes <= 2048,
            "private mapping bytes: {sparse_bytes}"
        );
        assert!(
            sparse_bytes * 7 < dense_bytes,
            "sparse={sparse_bytes} dense={dense_bytes}"
        );
        const { assert!(MAX_PRIVATE_PAGES >= crate::executable::MAX_IMAGE_PAGES + 2) };
        assert_eq!(ENTRIES, 512);
        let map = UserMappings::new(1).unwrap();
        for index in 0..ENTRIES {
            let address = map.base() + index as u64 * FRAME_SIZE;
            assert_eq!(map.index(address), Ok(index));
            assert_eq!(map.entry(address), Ok(0));
        }
    }
    #[test]
    fn sparse_high_pages_and_holes_preserve_sorted_frame_retirement_order() {
        let mut frames = allocator();
        let total = frames.remaining_frames();
        let mut map = UserMappings::new(255).unwrap();
        for index in [511, 7, 509, 1] {
            let frame = frames.allocate().unwrap();
            map.map(
                map.base() + index * FRAME_SIZE,
                frame,
                UserPermission::ReadWrite,
            )
            .unwrap();
        }
        let mut starts = [0; 4];
        for (index, frame) in map.frames().enumerate() {
            starts[index] = frame.start();
        }
        assert_eq!(
            starts,
            [4 * FRAME_SIZE, 2 * FRAME_SIZE, 3 * FRAME_SIZE, FRAME_SIZE]
        );
        let record = map.unmap(map.base() + 509 * FRAME_SIZE).unwrap();
        assert_eq!(record.start(), 3 * FRAME_SIZE);
        assert_eq!(map.entry(map.base() + 509 * FRAME_SIZE), Ok(0));
        assert_eq!(
            map.unmap(map.base() + 509 * FRAME_SIZE),
            Err(MapError::Missing)
        );
        map.map(
            map.base() + 222 * FRAME_SIZE,
            record,
            UserPermission::ReadOnly,
        )
        .unwrap();
        assert_eq!(map.entry(map.base()), Ok(0));
        assert_eq!(map.entry(map.base() + 510 * FRAME_SIZE), Ok(0));
        assert_eq!(
            map.entry(map.base() + 511 * FRAME_SIZE),
            Ok(expected_entry(FRAME_SIZE, UserPermission::ReadWrite))
        );
        let retired = map.into_frames();
        assert!(retired[4..].iter().all(Option::is_none));
        for (frame, expected) in retired.into_iter().flatten().zip(starts) {
            assert_eq!(frame.start(), expected);
            frames.reclaim(frame).unwrap();
        }
        assert_eq!(frames.remaining_frames(), total);
    }
    #[test]
    fn sparse_capacity_and_failed_replacement_never_consume_or_lose_frame_ownership() {
        let mut frames = allocator();
        let total = frames.remaining_frames();
        let mut map = UserMappings::new(1).unwrap();
        for index in 0..MAX_PRIVATE_PAGES {
            map.map(
                map.base() + index as u64 * FRAME_SIZE,
                frames.allocate().unwrap(),
                UserPermission::ReadExecute,
            )
            .unwrap();
        }
        let frame = frames.allocate().unwrap();
        let physical = frame.start();
        let (error, frame) = map
            .map(
                map.base() + 511 * FRAME_SIZE,
                frame,
                UserPermission::ReadWrite,
            )
            .unwrap_err();
        assert_eq!(error, MapError::Capacity);
        assert_eq!(frame.start(), physical);
        assert!(frames.owns(&frame));
        let (error, frame) = map
            .map(
                map.base() + 10 * FRAME_SIZE,
                frame,
                UserPermission::ReadWrite,
            )
            .unwrap_err();
        assert_eq!(error, MapError::Occupied);
        assert_eq!(frame.start(), physical);
        let (error, frame) = map
            .map(u64::MAX, frame, UserPermission::ReadWrite)
            .unwrap_err();
        assert_eq!(error, MapError::Address);
        assert_eq!(frame.start(), physical);
        assert_eq!(map.frames().count(), MAX_PRIVATE_PAGES);
        assert_eq!(map.entry(map.base() + 511 * FRAME_SIZE), Ok(0));
        let removed = map.unmap(map.base() + 10 * FRAME_SIZE).unwrap();
        assert_eq!(removed.start(), 11 * FRAME_SIZE);
        frames.reclaim(removed).unwrap();
        assert_eq!(
            map.unmap(map.base() + 10 * FRAME_SIZE),
            Err(MapError::Missing)
        );
        assert_eq!(map.unmap(map.base() + 1), Err(MapError::Address));
        map.map(
            map.base() + 511 * FRAME_SIZE,
            frame,
            UserPermission::ReadWrite,
        )
        .unwrap();
        assert_eq!(map.frames().count(), MAX_PRIVATE_PAGES);
        assert_eq!(
            map.entry(map.base() + 511 * FRAME_SIZE),
            Ok(expected_entry(physical, UserPermission::ReadWrite))
        );
        for frame in map.into_frames().into_iter().flatten() {
            assert!(frames.owns(&frame));
            frames.reclaim(frame).unwrap();
        }
        assert_eq!(frames.remaining_frames(), total);
    }
    #[test]
    fn arbitrary_sparse_insert_remove_sequences_match_a_dense_lookup_oracle() {
        let mut frames = allocator();
        let total = frames.remaining_frames();
        let mut map = UserMappings::new(127).unwrap();
        let mut oracle = [None; ENTRIES];
        let mut seed = 0x5721_e418_0abc_302du64;
        for _ in 0..4096 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let index = ((seed >> 16) % ENTRIES as u64) as usize;
            let address = map.base() + index as u64 * FRAME_SIZE;
            if seed & 3 != 0 {
                let permission = match (seed >> 32) % 3 {
                    0 => UserPermission::ReadOnly,
                    1 => UserPermission::ReadWrite,
                    _ => UserPermission::ReadExecute,
                };
                let frame = frames.allocate().unwrap();
                let physical = frame.start();
                let failure = if oracle[index].is_some() {
                    Some(MapError::Occupied)
                } else if oracle.iter().flatten().count() == MAX_PRIVATE_PAGES {
                    Some(MapError::Capacity)
                } else {
                    None
                };
                match (map.map(address, frame, permission), failure) {
                    (Ok(()), None) => oracle[index] = Some((physical, permission)),
                    (Err((error, frame)), Some(expected)) => {
                        assert_eq!(error, expected);
                        assert_eq!(frame.start(), physical);
                        assert!(frames.owns(&frame));
                        frames.reclaim(frame).unwrap();
                    }
                    _ => panic!("sparse insertion disagreed with dense oracle"),
                }
            } else {
                match (map.unmap(address), oracle[index].take()) {
                    (Ok(frame), Some((physical, _))) => {
                        assert_eq!(frame.start(), physical);
                        assert!(frames.owns(&frame));
                        frames.reclaim(frame).unwrap();
                    }
                    (Err(MapError::Missing), None) => (),
                    _ => panic!("sparse removal disagreed with dense oracle"),
                }
            }
            for (index, expected) in oracle.iter().enumerate() {
                let entry = expected.map_or(0, |(physical, permission)| {
                    expected_entry(physical, permission)
                });
                assert_eq!(map.entry(map.base() + index as u64 * FRAME_SIZE), Ok(entry));
            }
            assert_eq!(map.frames().count(), oracle.iter().flatten().count());
            for (frame, &(physical, _)) in map.frames().zip(oracle.iter().flatten()) {
                assert_eq!(frame.start(), physical);
            }
        }
        for frame in map.into_frames().into_iter().flatten() {
            frames.reclaim(frame).unwrap();
        }
        assert_eq!(frames.remaining_frames(), total);
    }
    #[test]
    fn user_pages_are_bounded_move_owned_and_never_writable_executable() {
        for slot in [0, 256, 511, usize::MAX] {
            assert!(UserMappings::new(slot).is_err());
        }
        let mut frames = BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: 4096,
                end: 32768,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        );
        let mut map = UserMappings::new(255).unwrap();
        for (index, permission) in [
            UserPermission::ReadOnly,
            UserPermission::ReadWrite,
            UserPermission::ReadExecute,
        ]
        .into_iter()
        .enumerate()
        {
            let address = map.base() + index as u64 * FRAME_SIZE;
            map.map(address, frames.allocate().unwrap(), permission)
                .unwrap();
            let entry = map.entry(address).unwrap();
            assert_eq!(entry & (USER | PRESENT), USER | PRESENT);
            assert!(entry & WRITABLE == 0 || entry & NO_EXECUTE != 0);
            assert_eq!(
                entry & NO_EXECUTE == 0,
                permission == UserPermission::ReadExecute
            );
        }
        let frame = frames.allocate().unwrap();
        let original = frame.start();
        let (error, frame) = map
            .map(map.base(), frame, UserPermission::ReadWrite)
            .unwrap_err();
        assert_eq!(error, MapError::Occupied);
        assert_eq!(frame.start(), original);
        for invalid in [
            map.base() - 1,
            map.base() + 1,
            map.base() + 512 * 4096,
            u64::MAX,
        ] {
            assert!(map.index(invalid).is_err());
        }
        assert_eq!(map.entry(map.base() + 511 * 4096).unwrap(), 0);
    }
    #[test]
    fn user_trap_rejects_wrong_privilege_flags_fault_fields_and_stack() {
        let expected = UserTrap {
            vector: 14,
            error: 5,
            ip: 0x1000,
            address: 0x2000,
            stack_top: 0x8000,
        };
        assert!(expected.matches(&expected, 35, 27, 2));
        for bad in [
            UserTrap {
                vector: 13,
                ..expected
            },
            UserTrap {
                error: 4,
                ..expected
            },
            UserTrap {
                ip: 0x1001,
                ..expected
            },
            UserTrap {
                address: 0x2001,
                ..expected
            },
            UserTrap {
                stack_top: 0x8001,
                ..expected
            },
            UserTrap {
                stack_top: 0x7000,
                ..expected
            },
        ] {
            assert!(!expected.matches(&bad, 35, 27, 2));
        }
        for (cs, ss, flags) in [
            (8, 27, 2),
            (35, 16, 2),
            (35, 27, 0x3002),
            (35, 27, 0x202),
            (35, 27, 0x102),
            (35, 27, 0x20002),
        ] {
            assert!(!expected.matches(&expected, cs, ss, flags));
        }
    }
}
