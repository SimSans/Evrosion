//! Portable ownership/PTE and actual byte-copy model; no host port-I/O claim.
extern crate std;
use super::*;
use crate::{memory::BootstrapFrames, memory_extent::RamAccess};
use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
use std::{vec, vec::Vec};
fn allocator() -> BootstrapFrames {
    BootstrapFrames::new(
        MemoryMap::validate([MemoryRegion {
            start: FRAME_SIZE,
            end: 128 * FRAME_SIZE,
            kind: MemoryKind::Usable,
        }])
        .unwrap(),
    )
}
struct Ram {
    bytes: Vec<u8>,
    calls: usize,
    fail: Option<usize>,
}
#[allow(unsafe_code)]
// SAFETY: truthful host RAM model keyed by the exact borrowed allocator frame
// and bounded byte; no actual hardware/direct-map acceptance is claimed.
unsafe impl RamAccess for Ram {
    type Error = ();
    fn read(&mut self, f: &PhysicalFrame, byte: usize) -> Result<u8, ()> {
        self.calls += 1;
        if self.fail == Some(self.calls) {
            return Err(());
        }
        assert!(byte < 4096);
        Ok(self.bytes[f.start() as usize + byte])
    }
    fn write(&mut self, f: &PhysicalFrame, byte: usize, value: u8) -> Result<(), ()> {
        self.calls += 1;
        if self.fail == Some(self.calls) {
            return Err(());
        }
        assert!(byte < 4096);
        self.bytes[f.start() as usize + byte] = value;
        Ok(())
    }
}
#[test]
fn unaligned_two_page_sector_uses_both_exact_noncontiguous_frame_claims() {
    let mut a = allocator();
    let total = a.remaining_frames();
    let mut m = PrivateUserMappings::<4>::new(1).unwrap();
    let first = a.allocate().unwrap();
    let skipped = a.allocate().unwrap();
    let second = a.allocate().unwrap();
    let physical = [first.start(), second.start()];
    assert_ne!(physical[0] + FRAME_SIZE, physical[1]);
    for (index, frame) in [(3, first), (4, second)] {
        m.map(
            m.base() + index * FRAME_SIZE,
            frame,
            UserPermission::ReadWrite,
        )
        .unwrap();
    }
    let address = m.base() + 4 * FRAME_SIZE - 1;
    let mut reads = 0;
    let span = m
        .io_buffer(address, |i| {
            reads += 1;
            m.entry(m.base() + i as u64 * FRAME_SIZE)
                .map(|p| p | (1 << 5) | (1 << 6))
        })
        .unwrap();
    assert_eq!(reads, 2);
    assert_eq!(
        span.frames().map(PhysicalFrame::start).collect::<Vec<_>>(),
        physical
    );
    let mut ram = Ram {
        bytes: vec![0xa5; 128 * 4096],
        calls: 0,
        fail: None,
    };
    let bytes: [u8; 512] = core::array::from_fn(|i| (i * 37) as u8);
    span.write(&mut ram, &bytes).unwrap();
    assert_eq!(ram.bytes[physical[0] as usize + 4095], bytes[0]);
    assert_eq!(
        &ram.bytes[physical[1] as usize..physical[1] as usize + 511],
        &bytes[1..]
    );
    assert_eq!(ram.bytes[physical[0] as usize + 4094], 0xa5);
    assert_eq!(ram.bytes[physical[1] as usize + 511], 0xa5);
    let mut readback = [0; 512];
    span.read(&mut ram, &mut readback).unwrap();
    assert_eq!(readback, bytes);
    assert_eq!(ram.calls, 1024);
    for frame in m.into_frames().into_iter().flatten() {
        a.reclaim(frame).unwrap();
    }
    a.reclaim(skipped).unwrap();
    assert_eq!(a.remaining_frames(), total);
}
#[test]
fn code_readonly_bootstrap_shared_guards_and_foreign_window_never_supply_private_rw_claims() {
    let mut a = allocator();
    let mut m = PrivateUserMappings::<4>::new(1).unwrap();
    for (index, permission) in [
        (1, UserPermission::ReadExecute),
        (3, UserPermission::ReadWrite),
        (509, UserPermission::ReadOnly),
        (511, UserPermission::ReadWrite),
    ] {
        m.map(
            m.base() + index * FRAME_SIZE,
            a.allocate().unwrap(),
            permission,
        )
        .unwrap();
    }
    for address in [
        m.base() + FRAME_SIZE,
        m.base() + 509 * FRAME_SIZE,
        m.base() + 508 * FRAME_SIZE,
        m.base() + 2 * FRAME_SIZE,
        m.base() + 4 * FRAME_SIZE - 1,
        (2 << 39) + 3 * FRAME_SIZE,
        0,
        u64::MAX,
        m.base() + 512 * FRAME_SIZE - 511,
    ] {
        assert!(
            m.io_buffer(address, |_| Ok(0x1000
                | PRESENT
                | USER
                | WRITABLE
                | NO_EXECUTE))
                .is_err(),
            "{address:#x}"
        );
    }
    // A legitimately owned RW/NX initial stack is allowed, independently of
    // its numeric page; policy cannot substitute a special VA for ownership.
    assert!(
        m.io_buffer(m.base() + 511 * FRAME_SIZE + 1, |i| m
            .entry(m.base() + i as u64 * FRAME_SIZE))
            .is_ok()
    );
}
#[test]
fn full_second_page_preflight_refuses_physical_flag_and_readback_mismatches_before_copy() {
    let mut a = allocator();
    let mut m = PrivateUserMappings::<2>::new(1).unwrap();
    for index in [3, 4] {
        m.map(
            m.base() + index * FRAME_SIZE,
            a.allocate().unwrap(),
            UserPermission::ReadWrite,
        )
        .unwrap();
    }
    for mismatch in [
        0,
        0x7000 | PRESENT | USER | WRITABLE | NO_EXECUTE,
        PRESENT | USER | WRITABLE,
        PRESENT | USER | NO_EXECUTE,
        PRESENT | WRITABLE | NO_EXECUTE,
    ] {
        let mut inspected = 0;
        let result = m.io_buffer(m.base() + 4 * FRAME_SIZE - 127, |i| {
            inspected += 1;
            if i == 4 {
                Ok(mismatch)
            } else {
                m.entry(m.base() + i as u64 * FRAME_SIZE)
            }
        });
        assert!(result.is_err());
        assert_eq!(inspected, 2);
    }
    assert!(
        m.io_buffer(m.base() + 4 * FRAME_SIZE - 1, |i| if i == 4 {
            Err(MapError::Missing)
        } else {
            m.entry(m.base() + i as u64 * FRAME_SIZE)
        })
        .is_err()
    );
    assert_eq!(m.frames().count(), 2);
}
#[test]
fn access_error_retains_all_private_frame_claims_and_never_invents_success() {
    let mut a = allocator();
    let mut m = PrivateUserMappings::<1>::new(1).unwrap();
    m.map(
        m.base() + 3 * FRAME_SIZE,
        a.allocate().unwrap(),
        UserPermission::ReadWrite,
    )
    .unwrap();
    let span = m
        .io_buffer(m.base() + 3 * FRAME_SIZE, |i| {
            m.entry(m.base() + i as u64 * FRAME_SIZE)
        })
        .unwrap();
    let mut ram = Ram {
        bytes: vec![0; 128 * 4096],
        calls: 0,
        fail: Some(5),
    };
    assert_eq!(span.write(&mut ram, &[7; 512]), Err(()));
    assert_eq!(ram.calls, 5);
    assert_eq!(m.frames().count(), 1);
}
#[test]
fn detached_rebound_large_or_restricted_parent_entries_deny_the_owned_leaf_path() {
    let mut a = allocator();
    let tables = core::array::from_fn(|_| a.allocate().unwrap());
    let expected = core::array::from_fn(|i| tables[i + 1].start() | PRESENT | WRITABLE | USER);
    assert_eq!(private_io_walk(&tables, expected), Ok(()));
    assert_eq!(
        private_io_walk(&tables, expected.map(|p| p | (1 << 5) | (1 << 6))),
        Ok(())
    );
    for level in 0..3 {
        for replacement in [
            0,
            tables[0].start() | PRESENT | WRITABLE | USER,
            expected[level] | (1 << 7),
            expected[level] | NO_EXECUTE,
            expected[level] & !WRITABLE,
            expected[level] & !USER,
        ] {
            let mut actual = expected;
            actual[level] = replacement;
            assert_eq!(private_io_walk(&tables, actual), Err(MapError::Address));
        }
    }
}
