use ev_boot_contract::*;

fn region(start: u64, end: u64) -> MemoryRegion {
    MemoryRegion {
        start,
        end,
        kind: MemoryKind::Usable,
    }
}

#[test]
fn disordered_adjacent_memory_is_sorted_without_losing_bytes() {
    let map = MemoryMap::validate([region(4096, 8192), region(0, 4096)]).unwrap();
    assert_eq!(map.regions()[0].start, 0);
    assert_eq!(map.usable_bytes(), 8192);
}

#[test]
fn rejects_overlap_empty_inverted_and_excessive_memory() {
    assert_eq!(
        MemoryMap::validate([region(0, 8192), region(4096, 12288)]).unwrap_err(),
        BootError::OverlappingMemory
    );
    assert_eq!(
        MemoryMap::validate([]).unwrap_err(),
        BootError::EmptyMemoryMap
    );
    for invalid in [region(4096, 4096), region(4096, 0), region(0, u64::MAX)] {
        assert_eq!(
            MemoryMap::validate([invalid]).unwrap_err(),
            BootError::InvalidMemoryRange
        );
    }
    assert_eq!(
        MemoryMap::validate((0..=MAX_MEMORY_REGIONS).map(|i| region(i as u64, i as u64 + 1)))
            .unwrap_err(),
        BootError::TooManyRegions
    );
}

#[test]
fn virtual_ranges_cannot_wrap_or_cross_the_canonical_hole() {
    assert!(AddressRange::from_length(u64::MAX - 1, 4).is_err());
    assert!(AddressRange::from_length(4096, 0).is_err());
    for (start, end) in [
        (0, 4096),
        (0x0000_8000_0000_0000, 0x0000_8000_0000_1000),
        (0x0000_7fff_ffff_f000, 0xffff_8000_0000_1000),
        (8192, 4096),
    ] {
        assert!(validate_virtual_range(AddressRange { start, end }).is_err());
    }
    assert!(
        validate_virtual_range(AddressRange {
            start: 0xffff_ffff_8000_0000,
            end: 0xffff_ffff_8000_1000
        })
        .is_ok()
    );
}

#[test]
fn framebuffer_bounds_formats_and_stride_are_checked() {
    let valid = Framebuffer {
        address: 0x8000_0000,
        byte_length: 4096,
        width: 16,
        height: 16,
        stride: 32,
        bytes_per_pixel: 4,
        format: PixelFormat::Bgr,
    };
    assert!(valid.validate().is_ok());
    for invalid in [
        Framebuffer { width: 0, ..valid },
        Framebuffer { stride: 8, ..valid },
        Framebuffer {
            stride: usize::MAX,
            ..valid
        },
        Framebuffer {
            byte_length: 1024,
            ..valid
        },
        Framebuffer {
            byte_length: MAX_FRAMEBUFFER_BYTES + 1,
            ..valid
        },
        Framebuffer {
            bytes_per_pixel: 8,
            ..valid
        },
        Framebuffer {
            address: u64::MAX - 1,
            ..valid
        },
        Framebuffer {
            format: PixelFormat::Gray,
            ..valid
        },
    ] {
        assert!(invalid.validate().is_err(), "accepted {invalid:?}");
    }
}
