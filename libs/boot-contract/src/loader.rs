use crate::*;
use bootloader_api::info::{MemoryRegionKind, PixelFormat as LoaderPixelFormat};

fn adapt(raw: &bootloader_api::BootInfo, start: u64, end: u64) -> Result<BootInfoV0, BootError> {
    let version = &raw.api_version;
    if (
        version.version_major(),
        version.version_minor(),
        version.version_patch(),
    ) != (0, 11, 17)
        || version.pre_release()
    {
        return Err(BootError::LoaderVersion);
    }
    // The temporary loader supplies valid Rust references (EXC-0001). These checks
    // validate the referenced metadata; they cannot validate arbitrary page mappings.
    let memory = MemoryMap::validate(raw.memory_regions.iter().map(|region| MemoryRegion {
        start: region.start,
        end: region.end,
        kind: match region.kind {
            MemoryRegionKind::Usable => MemoryKind::Usable,
            _ => MemoryKind::Reserved,
        },
    }))?;
    let kernel_physical_range = AddressRange::from_length(raw.kernel_addr, raw.kernel_len)?;
    if !memory.regions().iter().any(|region| {
        region.kind == MemoryKind::Reserved
            && region.start <= kernel_physical_range.start
            && region.end >= kernel_physical_range.end
    }) {
        return Err(BootError::InvalidKernelRange);
    }
    let kernel_virtual_range = AddressRange { start, end };
    validate_virtual_range(kernel_virtual_range)?;
    let framebuffer = raw
        .framebuffer
        .as_ref()
        .map(|framebuffer| {
            let info = framebuffer.info();
            // Bound the slice length before asking the backend for its buffer pointer.
            if info.byte_len == 0 || info.byte_len > MAX_FRAMEBUFFER_BYTES {
                return Err(BootError::InvalidFramebuffer);
            }
            let format = match info.pixel_format {
                LoaderPixelFormat::Rgb => PixelFormat::Rgb,
                LoaderPixelFormat::Bgr => PixelFormat::Bgr,
                LoaderPixelFormat::U8 => PixelFormat::Gray,
                _ => return Err(BootError::UnsupportedPixelFormat),
            };
            Framebuffer {
                address: framebuffer.buffer().as_ptr() as u64,
                byte_length: info.byte_len,
                width: info.width,
                height: info.height,
                stride: info.stride,
                bytes_per_pixel: info.bytes_per_pixel,
                format,
            }
            .validate()
        })
        .transpose()?;
    let physical_memory_offset = raw.physical_memory_offset.into_option();
    if let Some(offset) = physical_memory_offset {
        if offset % 4096 != 0 {
            return Err(BootError::InvalidVirtualAddress);
        }
        for region in memory.regions() {
            let start = offset
                .checked_add(region.start)
                .ok_or(BootError::InvalidVirtualAddress)?;
            let end = offset
                .checked_add(region.end)
                .ok_or(BootError::InvalidVirtualAddress)?;
            validate_virtual_range(AddressRange { start, end })?;
        }
    }
    let acpi_rsdp = raw.rsdp_addr.into_option();
    if acpi_rsdp.is_some_and(|address| !memory.contains_reserved(address, 36)) {
        return Err(BootError::InvalidAcpiAddress);
    }
    Ok(BootInfoV0 {
        magic: MAGIC,
        schema_version: SCHEMA_VERSION,
        structure_size: core::mem::size_of::<BootInfoV0>(),
        boot_generation_id: None,
        memory,
        framebuffer,
        physical_memory_offset,
        acpi_rsdp,
        kernel_physical_range,
        kernel_virtual_range,
        command_line: b"",
        bootloader_identity: "rust-osdev/bootloader 0.11.17 (temporary; EXC-0001)",
    })
}

/// Only entry-point macro glue uses this module; external types end at `adapt`.
#[doc(hidden)]
pub mod bridge {
    pub use bootloader_api::config::Mapping;
    pub use bootloader_api::{BootInfo, BootloaderConfig, entry_point};
    pub fn adapt(
        raw: &BootInfo,
        start: u64,
        end: u64,
    ) -> Result<crate::BootInfoV0, crate::BootError> {
        super::adapt(raw, start, end)
    }
}

#[macro_export]
macro_rules! ev_entry_point {
    ($handler:path) => {
        mod __evrosion_loader_adapter {
            use $crate::__loader_bridge as backend;
            const CONFIG: backend::BootloaderConfig = {
                let mut config = backend::BootloaderConfig::new_default();
                config.kernel_stack_size = 256 * 1024;
                config.mappings.physical_memory = Some(backend::Mapping::Dynamic);
                config
            };
            backend::entry_point!(enter, config = &CONFIG);
            fn enter(raw: &'static mut backend::BootInfo) -> ! {
                // SAFETY: the UEFI loader enters ring 0; no interrupt handlers exist yet.
                unsafe {
                    core::arch::asm!("cli", options(nomem, nostack));
                }
                unsafe extern "C" {
                    static __ev_kernel_start: u8;
                    static __ev_kernel_end: u8;
                }
                let start = core::ptr::addr_of!(__ev_kernel_start) as u64;
                let end = core::ptr::addr_of!(__ev_kernel_end) as u64;
                let boot = backend::adapt(raw, start, end);
                $handler(boot)
            }
        }
    };
}

pub use crate::ev_entry_point as entry_point;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, vec};

    fn handoff() -> bootloader_api::BootInfo {
        use bootloader_api::info::MemoryRegion;
        let regions = vec![
            MemoryRegion {
                start: 0x1000,
                end: 0x4000,
                kind: MemoryRegionKind::Bootloader,
            },
            MemoryRegion {
                start: 0x4000,
                end: 0x8000,
                kind: MemoryRegionKind::Usable,
            },
        ];
        let mut raw = bootloader_api::BootInfo::new(Box::leak(regions.into_boxed_slice()).into());
        raw.kernel_addr = 0x1000;
        raw.kernel_len = 0x2000;
        raw
    }

    #[test]
    fn real_adapter_accepts_absent_framebuffer_and_owns_memory_copy() {
        let mut raw = handoff();
        let boot = adapt(&raw, 0xffff_ffff_8000_0000, 0xffff_ffff_8000_4000).unwrap();
        raw.memory_regions[0].start = 0;
        assert_eq!(boot.memory.regions()[0].start, 0x1000);
        assert_eq!(boot.memory.usable_bytes(), 0x4000);
        assert!(boot.framebuffer.is_none());
        assert!(boot.boot_generation_id.is_none());
        assert_eq!(boot.magic, MAGIC);
        assert_eq!(boot.schema_version, SCHEMA_VERSION);
        assert_eq!(boot.structure_size, core::mem::size_of::<BootInfoV0>());
    }

    #[test]
    fn adapter_rejects_kernel_in_usable_memory_and_overlapping_handoff() {
        let mut raw = handoff();
        raw.kernel_addr = 0x4000;
        assert_eq!(
            adapt(&raw, 0x1000, 0x2000).unwrap_err(),
            BootError::InvalidKernelRange
        );
        raw.memory_regions[1].start = 0x2000;
        assert_eq!(
            adapt(&raw, 0x1000, 0x2000).unwrap_err(),
            BootError::OverlappingMemory
        );
    }

    #[test]
    fn unknown_memory_is_reserved_and_offset_arithmetic_is_checked() {
        let mut raw = handoff();
        raw.memory_regions[0].kind = MemoryRegionKind::UnknownUefi(99);
        let boot = adapt(&raw, 0x1000, 0x2000).unwrap();
        assert_eq!(boot.memory.regions()[0].kind, MemoryKind::Reserved);
        raw.physical_memory_offset = Some(u64::MAX - 10).into();
        assert_eq!(
            adapt(&raw, 0x1000, 0x2000).unwrap_err(),
            BootError::InvalidVirtualAddress
        );
    }

    #[test]
    fn physical_offset_must_be_aligned_and_cover_canonical_ranges() {
        let mut raw = handoff();
        raw.physical_memory_offset = Some(0xffff_8000_0000_0000).into();
        let boot = adapt(&raw, 0x1000, 0x2000).unwrap();
        assert_eq!(boot.physical_memory_offset, Some(0xffff_8000_0000_0000));
        for invalid in [
            0xffff_8000_0000_0001,
            0x0000_7fff_ffff_d000,
            0xffff_ffff_ffff_f000,
        ] {
            raw.physical_memory_offset = Some(invalid).into();
            assert_eq!(
                adapt(&raw, 0x1000, 0x2000).unwrap_err(),
                BootError::InvalidVirtualAddress
            );
        }
    }

    #[test]
    fn rsdp_must_fit_retained_reserved_memory_and_cannot_overflow() {
        let mut raw = handoff();
        raw.rsdp_addr = Some(0x3000).into();
        assert_eq!(adapt(&raw, 0x1000, 0x2000).unwrap().acpi_rsdp, Some(0x3000));
        for address in [0, 0x3fff, 0x4000, u64::MAX - 16] {
            raw.rsdp_addr = Some(address).into();
            assert_eq!(
                adapt(&raw, 0x1000, 0x2000).unwrap_err(),
                BootError::InvalidAcpiAddress
            );
        }
        let map = adapt(&handoff(), 0x1000, 0x2000).unwrap().memory;
        assert!(!map.contains_reserved(0x1000, 0));
        assert!(!map.contains_reserved(0x1000, u64::MAX));
    }
}
