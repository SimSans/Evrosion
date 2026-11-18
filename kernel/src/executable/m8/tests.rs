extern crate std;
use super::*;
use crate::scheduler::Limits;
use std::vec::Vec;
pub(crate) const BASE: u64 = 1 << 39;
fn put16(b: &mut [u8], i: usize, n: u16) {
    b[i..i + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], i: usize, n: u32) {
    b[i..i + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], i: usize, n: u64) {
    b[i..i + 8].copy_from_slice(&n.to_le_bytes());
}
/// Small immutable ELF with sparse zero-fill segments; no model RAM allocator.
pub(crate) fn elf(zero_segments: &[(u64, u64)]) -> Vec<u8> {
    let mut b = std::vec![0;8192];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut b, 16, 2);
    put16(&mut b, 18, 62);
    put32(&mut b, 20, 1);
    put64(&mut b, 24, BASE + 4096);
    put64(&mut b, 32, 64);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, (1 + zero_segments.len()) as u16);
    for (index, (first, pages)) in core::iter::once((1, 1))
        .chain(zero_segments.iter().copied())
        .enumerate()
    {
        let p = 64 + index * 56;
        put32(&mut b, p, 1);
        put32(&mut b, p + 4, if index == 0 { 5 } else { 6 });
        put64(&mut b, p + 8, if index == 0 { 4096 } else { 8192 });
        put64(&mut b, p + 16, BASE + first * 4096);
        put64(&mut b, p + 32, u64::from(index == 0));
        put64(&mut b, p + 40, pages * 4096);
        put64(&mut b, p + 48, 4096);
    }
    b[4096] = 0xc3;
    b
}
fn selected<'a>(b: &'a [u8], slot: ImageSlot) -> Result<Image<'a>, Error> {
    let l = slot.representative().limits();
    Image::from_m8_descriptor(b, [7; 32], slot, Limits::new(l[0], l[1], l[2], l[3]))
}
#[test]
fn one_mib_editor_zero_fill_is_closed_to_old_descriptor_and_core_classes() {
    let b = elf(&[(64, 256), (480, 8)]);
    assert_eq!(
        Image::from_descriptor(
            &b,
            [7; 32],
            ev_userspace_contract::ABI,
            Limits::new(16384, 512, 1, 1)
        )
        .err(),
        Some(Error::Capacity)
    );
    assert_eq!(selected(&b, ImageSlot::Block).err(), Some(Error::Capacity));
    let image = selected(&b, ImageSlot::Editor).unwrap();
    assert_eq!(image.pages().count(), 265);
    assert_eq!(image.required_frames(), 271);
    assert_eq!(image.startup_layout(), StartupLayout::ServiceV1);
    let mut chunk = [0xff; 4096];
    for page in image
        .pages()
        .filter(|p| p.permission == UserPermission::ReadWrite)
    {
        page.copy_into(&mut chunk);
        assert!(chunk.iter().all(|v| *v == 0));
    }
}
#[test]
fn closed_limits_include_bootstrap_stack_tables_and_display_aperture_tables() {
    for (slot, segments, count, frames, record) in [
        (ImageSlot::Shell, std::vec![(2, 87), (480, 8)], 96, 102, 336),
        (
            ImageSlot::Workspace,
            std::vec![(2, 87), (480, 8)],
            96,
            102,
            528,
        ),
        (
            ImageSlot::Editor,
            std::vec![(2, 375), (480, 8)],
            384,
            390,
            336,
        ),
        (
            ImageSlot::Display,
            std::vec![(2, 61), (436, 10), (480, 8)],
            80,
            88,
            528,
        ),
    ] {
        let b = elf(&segments);
        let image = selected(&b, slot).unwrap();
        assert_eq!(image.pages().count(), count);
        assert_eq!(image.required_frames(), frames);
        assert_eq!(image.startup_layout().bytes(), Some(record));
        assert_eq!(resources::max_private_pages(slot), count as u64 + 4);
        let mut over = segments;
        over[0].1 += 1;
        assert_eq!(selected(&elf(&over), slot).err(), Some(Error::Capacity));
        assert_eq!(
            Image::from_m8_descriptor(&b, [7; 32], slot, Limits::new(16384, frames - 1, 1, 1))
                .err(),
            Some(Error::FrameBudget)
        );
    }
}
#[test]
fn selected_stack_guards_surfaces_and_workspace_windows_refuse_image_overlap() {
    for (slot, blocked) in [
        (ImageSlot::Editor, 383),
        (ImageSlot::Editor, 384),
        (ImageSlot::Editor, 447),
        (ImageSlot::Editor, 505),
        (ImageSlot::Editor, 506),
        (ImageSlot::Editor, 508),
        (ImageSlot::Workspace, 493),
        (ImageSlot::Workspace, 494),
        (ImageSlot::Workspace, 506),
        (ImageSlot::Display, 63),
        (ImageSlot::Display, 64),
        (ImageSlot::Display, 435),
        (ImageSlot::Shell, 479),
        (ImageSlot::Shell, 488),
        (ImageSlot::Shell, 509),
    ] {
        let segments = if blocked < 480 {
            std::vec![(blocked, 1), (480, 8)]
        } else {
            std::vec![(480, 8), (blocked, 1)]
        };
        assert_eq!(
            selected(&elf(&segments), slot).err(),
            Some(Error::Address),
            "{slot:?} page{blocked}"
        );
    }
    assert_eq!(
        selected(&elf(&[(480, 7)]), ImageSlot::Editor).err(),
        Some(Error::Address)
    );
    let mut b = elf(&[(480, 8)]);
    put32(&mut b, 64 + 56 + 4, 4);
    assert_eq!(
        selected(&b, ImageSlot::Editor).err(),
        Some(Error::Permission)
    );
    put32(&mut b, 64 + 56 + 4, 6);
    put64(&mut b, 64 + 56 + 8, 4096);
    put64(&mut b, 64 + 56 + 32, 1);
    assert_eq!(
        selected(&b, ImageSlot::Editor).err(),
        Some(Error::Permission)
    );
}
