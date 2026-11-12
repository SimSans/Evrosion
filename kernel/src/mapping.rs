//! Safe ownership and encoding for the bounded bootstrap scratch window.
use crate::memory::{FRAME_SIZE, PhysicalFrame};
use ev_boot_contract::{AddressRange, validate_virtual_range};

pub const ENTRIES: usize = 512;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
pub const NO_EXECUTE: u64 = 1 << 63;
pub const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    Capacity,
    Address,
    Occupied,
    Missing,
}

/// Only a fresh upper-half PML4 slot (excluding the kernel's last slot).
pub fn window_base(slot: usize) -> Result<u64, MapError> {
    if !(256..511).contains(&slot) {
        return Err(MapError::Address);
    }
    Ok(0xffff_0000_0000_0000 | ((slot as u64) << 39))
}

/// Checked arithmetic is necessary but does not prove a physical mapping exists.
pub fn direct_address(offset: u64, physical: u64, physical_bits: u8) -> Result<u64, MapError> {
    if !(32..=52).contains(&physical_bits)
        || !offset.is_multiple_of(FRAME_SIZE)
        || !physical.is_multiple_of(FRAME_SIZE)
        || physical >= (1u64 << physical_bits)
    {
        return Err(MapError::Address);
    }
    let start = offset.checked_add(physical).ok_or(MapError::Address)?;
    let end = start.checked_add(FRAME_SIZE).ok_or(MapError::Address)?;
    validate_virtual_range(AddressRange { start, end }).map_err(|_| MapError::Address)?;
    Ok(start)
}

pub struct LeafMappings {
    base: u64,
    pages: [Option<(PhysicalFrame, Permission)>; ENTRIES],
}

impl LeafMappings {
    pub fn new(slot: usize) -> Result<Self, MapError> {
        Ok(Self {
            base: window_base(slot)?,
            pages: [const { None }; ENTRIES],
        })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn index(&self, address: u64) -> Result<usize, MapError> {
        let delta = address.checked_sub(self.base).ok_or(MapError::Address)?;
        if delta >= ENTRIES as u64 * FRAME_SIZE || !delta.is_multiple_of(FRAME_SIZE) {
            return Err(MapError::Address);
        }
        Ok((delta / FRAME_SIZE) as usize)
    }

    pub fn map(
        &mut self,
        address: u64,
        frame: PhysicalFrame,
        permission: Permission,
    ) -> Result<(), (MapError, PhysicalFrame)> {
        let index = match self.index(address) {
            Ok(index) => index,
            Err(error) => return Err((error, frame)),
        };
        if self.pages[index].is_some() {
            return Err((MapError::Occupied, frame));
        }
        self.pages[index] = Some((frame, permission));
        Ok(())
    }

    pub fn entry(&self, address: u64) -> Result<u64, MapError> {
        Ok(match &self.pages[self.index(address)?] {
            Some((frame, permission)) => {
                frame.start()
                    | PRESENT
                    | NO_EXECUTE
                    | if *permission == Permission::ReadWrite {
                        WRITABLE
                    } else {
                        0
                    }
            }
            None => 0,
        })
    }

    pub fn protect(&mut self, address: u64, permission: Permission) -> Result<(), MapError> {
        let index = self.index(address)?;
        self.pages[index].as_mut().ok_or(MapError::Missing)?.1 = permission;
        Ok(())
    }

    pub fn unmap(&mut self, address: u64) -> Result<PhysicalFrame, MapError> {
        let index = self.index(address)?;
        self.pages[index]
            .take()
            .map(|(frame, _)| frame)
            .ok_or(MapError::Missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BootstrapFrames;
    use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};

    fn frames() -> BootstrapFrames {
        BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: 0x1000,
                end: 0x400000,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        )
    }

    #[test]
    fn permission_changes_preserve_identity_and_never_grant_user_execute_or_global() {
        let mut allocator = frames();
        let mut leaves = LeafMappings::new(256).unwrap();
        let address = leaves.base();
        leaves
            .map(
                address,
                allocator.allocate().unwrap(),
                Permission::ReadWrite,
            )
            .unwrap();
        assert_eq!(
            leaves.entry(address),
            Ok(0x1000 | PRESENT | WRITABLE | NO_EXECUTE)
        );
        leaves.protect(address, Permission::ReadOnly).unwrap();
        assert_eq!(leaves.entry(address), Ok(0x1000 | PRESENT | NO_EXECUTE));
        let frame = leaves.unmap(address).unwrap();
        assert_eq!(frame.start(), 0x1000);
        assert_eq!(leaves.entry(address), Ok(0));
        assert_eq!(leaves.unmap(address), Err(MapError::Missing));
        assert_eq!(
            leaves.protect(address, Permission::ReadWrite),
            Err(MapError::Missing)
        );
        leaves.map(address, frame, Permission::ReadOnly).unwrap();
    }

    #[test]
    fn failed_maps_return_the_frame_and_leave_existing_mapping_intact() {
        let mut allocator = frames();
        let mut leaves = LeafMappings::new(510).unwrap();
        let address = leaves.base();
        leaves
            .map(address, allocator.allocate().unwrap(), Permission::ReadOnly)
            .unwrap();
        let (error, frame) = leaves
            .map(
                address,
                allocator.allocate().unwrap(),
                Permission::ReadWrite,
            )
            .unwrap_err();
        assert_eq!(error, MapError::Occupied);
        assert_eq!(frame.start(), 0x2000);
        for invalid in [
            address - 4096,
            address + 1,
            address + 512 * 4096,
            0,
            0x800000000000,
        ] {
            let (error, returned) = leaves
                .map(
                    invalid,
                    allocator.allocate().unwrap(),
                    Permission::ReadWrite,
                )
                .unwrap_err();
            assert_eq!(error, MapError::Address);
            assert!(returned.start() > frame.start());
        }
        assert_eq!(leaves.entry(address), Ok(0x1000 | PRESENT | NO_EXECUTE));
    }

    #[test]
    fn entire_window_roundtrips_without_aliasing_or_crossing_its_boundary() {
        let mut allocator = frames();
        let mut leaves = LeafMappings::new(300).unwrap();
        for i in 0..512u64 {
            leaves
                .map(
                    leaves.base() + i * 4096,
                    allocator.allocate().unwrap(),
                    Permission::ReadWrite,
                )
                .unwrap();
        }
        for i in (0..512u64).rev() {
            let frame = leaves.unmap(leaves.base() + i * 4096).unwrap();
            assert_eq!(frame.start(), (i + 1) * 4096);
        }
        for invalid in [0, 255, 511, 512, usize::MAX] {
            assert!(LeafMappings::new(invalid).is_err());
        }
    }

    #[test]
    fn direct_map_rejects_overflow_holes_alignment_and_cpu_width_violations() {
        let offset = 0xffff_8000_0000_0000;
        assert_eq!(direct_address(offset, 0x1000, 40), Ok(offset + 0x1000));
        for (o, p, bits) in [
            (offset + 1, 0, 40),
            (offset, 1, 40),
            (offset, 1 << 40, 40),
            (u64::MAX - 4095, 0x1000, 52),
            (0x0000_8000_0000_0000, 0, 52),
            (offset, 0, 53),
            (offset, 0, 31),
        ] {
            assert_eq!(direct_address(o, p, bits), Err(MapError::Address));
        }
    }
}
