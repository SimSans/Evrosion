//! Evrosion's Internal boot contract. Only `loader` understands the temporary backend.
#![no_std]

mod loader;
#[doc(hidden)]
pub use loader::bridge as __loader_bridge;
pub use loader::entry_point;

pub const MAGIC: u64 = u64::from_le_bytes(*b"EVBOOT00");
pub const SCHEMA_VERSION: u32 = 0;
pub const MAX_MEMORY_REGIONS: usize = 512;
pub const MAX_FRAMEBUFFER_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    LoaderVersion,
    EmptyMemoryMap,
    TooManyRegions,
    InvalidMemoryRange,
    OverlappingMemory,
    MemoryOverflow,
    InvalidKernelRange,
    InvalidFramebuffer,
    UnsupportedPixelFormat,
    InvalidVirtualAddress,
    InvalidAcpiAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub fn from_length(start: u64, length: u64) -> Result<Self, BootError> {
        let end = start
            .checked_add(length)
            .ok_or(BootError::InvalidKernelRange)?;
        if start == 0 || length == 0 {
            return Err(BootError::InvalidKernelRange);
        }
        Ok(Self { start, end })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryKind {
    Usable,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub kind: MemoryKind,
}

const EMPTY_REGION: MemoryRegion = MemoryRegion {
    start: 0,
    end: 0,
    kind: MemoryKind::Reserved,
};

#[derive(Debug)]
pub struct MemoryMap {
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    count: usize,
    usable_bytes: u64,
}

impl MemoryMap {
    fn empty() -> Self {
        Self {
            regions: [EMPTY_REGION; MAX_MEMORY_REGIONS],
            count: 0,
            usable_bytes: 0,
        }
    }

    pub fn validate(regions: impl IntoIterator<Item = MemoryRegion>) -> Result<Self, BootError> {
        let mut map = Self::empty();
        for region in regions {
            if map.count == MAX_MEMORY_REGIONS {
                return Err(BootError::TooManyRegions);
            }
            if region.start >= region.end || region.end > (1 << 52) {
                return Err(BootError::InvalidMemoryRange);
            }
            if region.kind == MemoryKind::Usable {
                map.usable_bytes = map
                    .usable_bytes
                    .checked_add(region.end - region.start)
                    .ok_or(BootError::MemoryOverflow)?;
            }
            map.regions[map.count] = region;
            map.count += 1;
        }
        if map.count == 0 {
            return Err(BootError::EmptyMemoryMap);
        }
        map.regions[..map.count].sort_unstable_by_key(|region| region.start);
        if map
            .regions()
            .windows(2)
            .any(|pair| pair[0].end > pair[1].start)
        {
            return Err(BootError::OverlappingMemory);
        }
        Ok(map)
    }

    /// Transfer the validated map once to its allocator owner. The borrowed
    /// handoff retains an empty placeholder, which conveys no RAM and cannot
    /// produce another owned map. Other boot metadata remains available.
    pub fn take(&mut self) -> Result<Self, BootError> {
        if self.count == 0 {
            return Err(BootError::EmptyMemoryMap);
        }
        Ok(core::mem::replace(self, Self::empty()))
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.count]
    }
    pub fn usable_bytes(&self) -> u64 {
        self.usable_bytes
    }
    /// Bootstrap table reads must remain within one retained reserved region.
    /// This is an ownership/range check, not proof that firmware data is trusted.
    pub fn contains_reserved(&self, start: u64, length: u64) -> bool {
        start != 0
            && length != 0
            && start.checked_add(length).is_some_and(|end| {
                self.regions()
                    .iter()
                    .any(|r| r.kind == MemoryKind::Reserved && start >= r.start && end <= r.end)
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    Rgb,
    Bgr,
    Gray,
}

impl PixelFormat {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rgb => "rgb",
            Self::Bgr => "bgr",
            Self::Gray => "gray",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framebuffer {
    pub address: u64,
    pub byte_length: usize,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub bytes_per_pixel: usize,
    pub format: PixelFormat,
}

impl Framebuffer {
    pub fn validate(self) -> Result<Self, BootError> {
        let required = self
            .stride
            .checked_mul(self.height)
            .and_then(|size| size.checked_mul(self.bytes_per_pixel))
            .ok_or(BootError::InvalidFramebuffer)?;
        if self.width == 0
            || self.height == 0
            || self.width > 16384
            || self.height > 16384
            || self.stride < self.width
            || required > self.byte_length
            || self.byte_length > MAX_FRAMEBUFFER_BYTES
            || !match self.format {
                PixelFormat::Rgb | PixelFormat::Bgr => matches!(self.bytes_per_pixel, 3 | 4),
                PixelFormat::Gray => self.bytes_per_pixel == 1,
            }
        {
            return Err(BootError::InvalidFramebuffer);
        }
        let range = AddressRange::from_length(self.address, self.byte_length as u64)
            .map_err(|_| BootError::InvalidFramebuffer)?;
        validate_virtual_range(range)?;
        Ok(self)
    }
}

pub fn validate_virtual_range(range: AddressRange) -> Result<(), BootError> {
    fn canonical(address: u64) -> bool {
        (((address << 16) as i64 >> 16) as u64) == address
    }
    if range.start == 0
        || range.start >= range.end
        || !canonical(range.start)
        || !canonical(range.end - 1)
        || range.start >> 47 != (range.end - 1) >> 47
    {
        return Err(BootError::InvalidVirtualAddress);
    }
    Ok(())
}

/// Internal Rust structure, not a stable ABI. Memory is copied and validated once.
/// The entry handler borrows this structure and transfers `memory` once into the
/// sole allocator; that consumed field then reports no regions or usable bytes.
/// Missing generation/command line values are explicit for the temporary loader.
#[derive(Debug)]
pub struct BootInfoV0 {
    pub magic: u64,
    pub schema_version: u32,
    pub structure_size: usize,
    pub boot_generation_id: Option<[u8; 32]>,
    pub memory: MemoryMap,
    pub framebuffer: Option<Framebuffer>,
    pub physical_memory_offset: Option<u64>,
    pub acpi_rsdp: Option<u64>,
    pub kernel_physical_range: AddressRange,
    pub kernel_virtual_range: AddressRange,
    pub command_line: &'static [u8],
    pub bootloader_identity: &'static str,
}

#[cfg(test)]
mod transfer_tests {
    use super::*;

    #[test]
    fn consumed_handoff_cannot_return_a_second_owned_map() {
        let reserved = MemoryRegion {
            start: 0x1000,
            end: 0x4000,
            kind: MemoryKind::Reserved,
        };
        let usable = MemoryRegion {
            start: 0x4000,
            end: 0xa000,
            kind: MemoryKind::Usable,
        };
        let mut handoff = MemoryMap::validate([usable, reserved]).unwrap();
        let mut owner = handoff.take().unwrap();
        assert_eq!(owner.regions(), &[reserved, usable]);
        assert_eq!(owner.usable_bytes(), 0x6000);
        assert!(owner.contains_reserved(0x1000, 0x3000));
        assert!(handoff.regions().is_empty());
        assert_eq!(handoff.usable_bytes(), 0);
        assert!(!handoff.contains_reserved(0x1000, 1));
        for _ in 0..3 {
            assert_eq!(handoff.take().unwrap_err(), BootError::EmptyMemoryMap);
            assert!(handoff.regions().is_empty());
            assert_eq!(handoff.usable_bytes(), 0);
        }
        // A later explicit transfer moves custody again; it never restores the
        // previous owner or permits two owned validated maps from one handoff.
        let next_owner = owner.take().unwrap();
        assert_eq!(next_owner.regions(), &[reserved, usable]);
        assert_eq!(owner.take().unwrap_err(), BootError::EmptyMemoryMap);
    }

    #[test]
    fn maximum_region_transfer_preserves_every_validated_classification() {
        let regions = core::array::from_fn::<_, MAX_MEMORY_REGIONS, _>(|index| MemoryRegion {
            start: (index as u64 + 1) * 4096,
            end: (index as u64 + 2) * 4096,
            kind: if index.is_multiple_of(2) {
                MemoryKind::Reserved
            } else {
                MemoryKind::Usable
            },
        });
        let mut handoff = MemoryMap::validate(regions.iter().rev().copied()).unwrap();
        let owner = handoff.take().unwrap();
        assert_eq!(owner.regions(), &regions);
        assert_eq!(owner.usable_bytes(), (MAX_MEMORY_REGIONS as u64 / 2) * 4096);
        assert!(handoff.regions().is_empty());
        assert_eq!(handoff.take().unwrap_err(), BootError::EmptyMemoryMap);
    }
}
