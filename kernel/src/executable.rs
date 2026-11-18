//! Bounded Internal ELF64 load plan for a measured, static x86-64 image.
//! Hardware frame allocation, copying and activation belong to the runtime.
use crate::{bootstrap_manifest::Manifest, memory::FRAME_SIZE, user::UserPermission};
#[cfg(feature = "workspace-authority")]
pub mod m8;

pub const MAX_SEGMENTS: usize = 8;
pub const MAX_IMAGE_PAGES: usize = 64;
/// Native profile3 Root alone: measured79-page owner needs a separate bounded
/// load plan. Ordinary descriptors and Desktop Root retain64 image pages.
pub const NATIVE_ROOT_MAX_IMAGE_PAGES: usize = 96;
/// Same two-spare ownership formula as the ordinary68-slot mapping owner.
pub const NATIVE_ROOT_MAX_PRIVATE_PAGES: usize = NATIVE_ROOT_MAX_IMAGE_PAGES + 4;
/// Four page tables plus image, bootstrap and separate final stack frame.
pub const NATIVE_ROOT_MAX_PRIVATE_FRAMES: u64 = NATIVE_ROOT_MAX_IMAGE_PAGES as u64 + 6;
/// Selected V4 Root only; legacy/service and Native3 constructors retain their
/// original separate bounds. Canonical SDK metadata binds these exact values.
pub const ROOT_V4_MAX_IMAGE_PAGES: usize = ev_userspace_contract::root_v4::ROOT_MAX_IMAGE_PAGES;
pub const ROOT_V4_MAX_PRIVATE_PAGES: usize = ev_userspace_contract::root_v4::ROOT_MAX_PRIVATE_PAGES;
pub const ROOT_V4_MAX_PRIVATE_FRAMES: u64 = ev_userspace_contract::root_v4::ROOT_MAX_PRIVATE_FRAMES;
pub const WINDOW_BYTES: u64 = 512 * FRAME_SIZE;
pub const BOOTSTRAP_PAGE: u64 = 509 * FRAME_SIZE;
pub const STACK_PAGE: u64 = 511 * FRAME_SIZE;
const STACK_GUARD: u64 = 510 * FRAME_SIZE;
pub const DISPLAY_RELATIVE_START: u64 = 4 * 1024 * 1024;
pub const DISPLAY_MAXIMUM_BYTES: u64 = 4 * 1024 * 1024;
pub const DISPLAY_LOWER_GUARD: u64 = DISPLAY_RELATIVE_START - FRAME_SIZE;
pub const DISPLAY_UPPER_GUARD: u64 = DISPLAY_RELATIVE_START + DISPLAY_MAXIMUM_BYTES;
pub const DISPLAY_TABLE_FRAMES: u64 = 2;

/// Trusted, descriptor-bound external layout. It does not authorize mapping a
/// device and never turns its backing into private allocator RAM. Legacy ELF
/// parsing/limits remain unchanged, including the private2MiB window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutReservation {
    Legacy,
    DisplayApertureV1,
}
impl LayoutReservation {
    pub const fn additional_table_frames(self) -> u64 {
        match self {
            Self::Legacy => 0,
            Self::DisplayApertureV1 => DISPLAY_TABLE_FRAMES,
        }
    }
    pub const fn display_relative_start(self) -> Option<u64> {
        match self {
            Self::Legacy => None,
            Self::DisplayApertureV1 => Some(DISPLAY_RELATIVE_START),
        }
    }
    pub const fn display_maximum_bytes(self) -> Option<u64> {
        match self {
            Self::Legacy => None,
            Self::DisplayApertureV1 => Some(DISPLAY_MAXIMUM_BYTES),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    ProgramHeaders,
    Unsupported,
    SectionHeaders,
    Extent,
    Alignment,
    Permission,
    Address,
    Overlap,
    Capacity,
    Entry,
    FrameBudget,
}
#[derive(Clone, Copy)]
struct Segment {
    address: u64,
    offset: usize,
    file_bytes: usize,
    pages: usize,
    permission: UserPermission,
}

/// Measured startup selection. Ordinary descriptors may select only ServiceV1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupLayout {
    None,
    ServiceV1,
    #[cfg(feature = "workspace-authority")]
    ServiceV5,
    RootV2,
    RootV4,
    #[cfg(feature = "workspace-authority")]
    RootV5,
}
impl StartupLayout {
    pub const fn bytes(self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::ServiceV1 => Some(ev_userspace_contract::SIZE),
            #[cfg(feature = "workspace-authority")]
            Self::ServiceV5 => Some(ev_userspace_contract::root_v5::child::SIZE),
            Self::RootV2 => Some(ev_userspace_contract::root_v2::SIZE),
            Self::RootV4 => Some(ev_userspace_contract::root_v4::SIZE),
            #[cfg(feature = "workspace-authority")]
            Self::RootV5 => Some(ev_userspace_contract::root_v5::SIZE),
        }
    }
}

/// Immutable bytes are the same image measured by Manifest. No public unchecked
/// constructor, writable view, rebase or relocation interface exists.
pub struct Image<'a> {
    bytes: &'a [u8],
    manifest_digest: [u8; 32],
    base: u64,
    entry: u64,
    segments: [Option<Segment>; MAX_SEGMENTS],
    pages: usize,
    bootstrap: StartupLayout,
    layout: LayoutReservation,
}
impl<'a> Image<'a> {
    /// Root-only constructor, requiring a measured, exact current Root profile.
    /// Does not affect the ordinary ServiceImage verifier or v1 digest path.
    pub fn from_root_manifest_v2(
        root: &crate::root_manifest_v2::CurrentRoot<'a>,
    ) -> Result<Self, Error> {
        Self::from_checked_root(root.manifest())
    }
    /// Native profile3 uses the same bounded physical720-byte startup layout,
    /// while its verified manifest/record digest remains ABI/profile distinct.
    pub fn from_native_root(root: &crate::root_manifest_v2::NativeRoot<'a>) -> Result<Self, Error> {
        Self::from_checked_root_with_limit(root.manifest(), NATIVE_ROOT_MAX_IMAGE_PAGES)
    }
    pub fn from_root_v4(root: &crate::root_manifest_v4::CurrentRoot<'a>) -> Result<Self, Error> {
        Self::from_checked_root_layout(
            root.manifest(),
            ROOT_V4_MAX_IMAGE_PAGES,
            StartupLayout::RootV4,
        )
    }
    /// Independent V5 Root plan, retaining the selected240-image-page ceiling.
    #[cfg(feature = "workspace-authority")]
    pub fn from_root_v5(root: &crate::root_manifest_v5::CurrentRoot<'a>) -> Result<Self, Error> {
        use ev_userspace_contract::root_v5::resources as r;
        let image = Self::from_checked_root_layout(
            root.manifest(),
            r::ROOT_MAX_IMAGE_PAGES as usize,
            StartupLayout::RootV5,
        )?;
        let mut stack = 0;
        for page in image.pages() {
            let n = (page.address - image.base()) / FRAME_SIZE;
            // Root's externally backed package windows, protected producer,
            // catalogue, Workspace frame, network windows and their guards.
            if (r::PACKAGE_B_FIRST_PAGE - 1..=r::PACKAGE_B_FIRST_PAGE + r::PACKAGE_MAX_PAGES)
                .contains(&n)
                || (r::PACKAGE_A_FIRST_PAGE - 1
                    ..=r::PACKAGE_A_FIRST_PAGE + r::PACKAGE_CURRENT_PAGES)
                    .contains(&n)
                || (r::ROOT_PROTECTED_FIRST_PAGE - 1..=r::ROOT_NIC_PAGE).contains(&n)
                || n == r::ROOT_STACK_FIRST_PAGE - 1
                || n == r::ROOT_STACK_FIRST_PAGE + r::ROOT_STACK_PAGES
            {
                return Err(Error::Address);
            }
            if (r::ROOT_STACK_FIRST_PAGE..r::ROOT_STACK_FIRST_PAGE + r::ROOT_STACK_PAGES)
                .contains(&n)
            {
                if page.permission != UserPermission::ReadWrite
                    || page.initialized.iter().any(|b| *b != 0)
                {
                    return Err(Error::Permission);
                }
                stack += 1;
            }
        }
        if stack != r::ROOT_STACK_PAGES {
            return Err(Error::Address);
        }
        Ok(image)
    }
    fn from_checked_root(manifest: &crate::root_manifest_v2::Manifest<'a>) -> Result<Self, Error> {
        Self::from_checked_root_with_limit(manifest, MAX_IMAGE_PAGES)
    }
    fn from_checked_root_with_limit(
        manifest: &crate::root_manifest_v2::Manifest<'a>,
        image_pages: usize,
    ) -> Result<Self, Error> {
        Self::from_checked_root_layout(manifest, image_pages, StartupLayout::RootV2)
    }
    fn from_checked_root_layout(
        manifest: &crate::root_manifest_v2::Manifest<'a>,
        image_pages: usize,
        startup: StartupLayout,
    ) -> Result<Self, Error> {
        let mut image = parse_with_limit(manifest.root_image(), manifest.digest(), image_pages)?;
        image.bootstrap = startup;
        if image
            .segments
            .iter()
            .flatten()
            .any(|s| s.address + s.pages as u64 * FRAME_SIZE > image.base + BOOTSTRAP_PAGE)
        {
            return Err(Error::Address);
        }
        if image.required_frames() > manifest.limits().limit(crate::scheduler::Resource::Frames) {
            return Err(Error::FrameBudget);
        }
        Ok(image)
    }
    pub fn startup_layout(&self) -> StartupLayout {
        self.bootstrap
    }

    pub fn from_manifest(manifest: &Manifest<'a>) -> Result<Self, Error> {
        Self::from_descriptor(
            manifest.root_image(),
            manifest.digest(),
            manifest.abi_fingerprint(),
            manifest.limits(),
        )
    }
    /// Crate-private plan for already measured immutable service descriptors.
    /// The service verifier owns image measurement and canonical descriptor
    /// binding; this helper never accepts a userspace assertion of readiness.
    pub(crate) fn from_descriptor(
        bytes: &'a [u8],
        descriptor: [u8; 32],
        abi: [u8; 32],
        limits: crate::scheduler::Limits,
    ) -> Result<Self, Error> {
        Self::from_descriptor_with_layout(bytes, descriptor, abi, limits, LayoutReservation::Legacy)
    }
    pub(crate) fn from_descriptor_with_layout(
        bytes: &'a [u8],
        descriptor: [u8; 32],
        abi: [u8; 32],
        limits: crate::scheduler::Limits,
        layout: LayoutReservation,
    ) -> Result<Self, Error> {
        let mut image = parse(bytes, descriptor)?;
        image.layout = layout;
        image.bootstrap = if abi == ev_userspace_contract::ABI {
            StartupLayout::ServiceV1
        } else {
            StartupLayout::None
        };
        if image.bootstrap != StartupLayout::None
            && image
                .segments
                .iter()
                .flatten()
                .any(|s| s.address + s.pages as u64 * FRAME_SIZE > image.base + BOOTSTRAP_PAGE)
        {
            return Err(Error::Address);
        }
        if image.required_frames() > limits.limit(crate::scheduler::Resource::Frames) {
            return Err(Error::FrameBudget);
        }
        Ok(image)
    }
    /// Selected closed M8 class. This does not widen from_descriptor or any
    /// Root constructor. The service descriptor already binds exact slot/ABI.
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn from_m8_descriptor(
        bytes: &'a [u8],
        descriptor: [u8; 32],
        slot: ev_userspace_contract::root_v5::graph::ImageSlot,
        limits: crate::scheduler::Limits,
    ) -> Result<Self, Error> {
        m8::plan(bytes, descriptor, slot, limits)
    }
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    pub const fn layout(&self) -> LayoutReservation {
        self.layout
    }
    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn slot(&self) -> usize {
        (self.base >> 39) as usize
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn bootstrap_page(&self) -> Option<u64> {
        (self.bootstrap != StartupLayout::None).then_some(self.base + BOOTSTRAP_PAGE)
    }
    pub fn stack_page(&self) -> u64 {
        self.base + STACK_PAGE
    }
    pub fn stack_top(&self) -> u64 {
        self.base + WINDOW_BYTES
    }
    /// Private image + one NX stack + four page-table frames, plus any measured
    /// layout's extra RAM tables. Device backing is never counted as RAM.
    /// Resource admission
    /// must charge this before allocating; no physical allocation occurs here.
    pub fn required_frames(&self) -> u64 {
        self.private_required_frames() + self.layout.additional_table_frames()
    }
    /// The private loader owns this portion; a graphics wrapper must retain the
    /// additional tables before it can report the full layout for admission.
    pub fn private_required_frames(&self) -> u64 {
        self.pages as u64 + 5 + u64::from(self.bootstrap != StartupLayout::None)
    }
    pub fn pages(&self) -> impl Iterator<Item = Page<'a>> + '_ {
        self.segments.iter().flatten().flat_map(move |s| {
            (0..s.pages).map(move |i| {
                let offset = i * FRAME_SIZE as usize;
                let start = offset.min(s.file_bytes);
                let end = (offset + FRAME_SIZE as usize).min(s.file_bytes);
                Page {
                    address: s.address + offset as u64,
                    permission: s.permission,
                    initialized: &self.bytes[s.offset + start..s.offset + end],
                }
            })
        })
    }
}
/// All bytes not explicitly initialized, including rounded page tails, are zero.
pub struct Page<'a> {
    pub address: u64,
    pub permission: UserPermission,
    initialized: &'a [u8],
}
impl Page<'_> {
    pub fn copy_into(&self, destination: &mut [u8; FRAME_SIZE as usize]) {
        destination.fill(0);
        destination[..self.initialized.len()].copy_from_slice(self.initialized);
    }
}
fn half(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn wide(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn extent(offset: u64, size: u64, length: usize) -> Result<(), Error> {
    if offset
        .checked_add(size)
        .is_none_or(|end| end > length as u64)
    {
        Err(Error::Extent)
    } else {
        Ok(())
    }
}
fn parse(bytes: &[u8], manifest_digest: [u8; 32]) -> Result<Image<'_>, Error> {
    parse_with_limit(bytes, manifest_digest, MAX_IMAGE_PAGES)
}
fn parse_with_limit(
    bytes: &[u8],
    manifest_digest: [u8; 32],
    image_pages: usize,
) -> Result<Image<'_>, Error> {
    if bytes.len() < 64
        || bytes.len() > crate::bootstrap_manifest::MAX_IMAGE_BYTES
        || &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || bytes[7] != 0
        || bytes[8] != 0
        || half(bytes, 16) != 2
        || half(bytes, 18) != 62
        || word(bytes, 20) != 1
        || word(bytes, 48) != 0
        || half(bytes, 52) != 64
    {
        return Err(Error::Header);
    }
    let count = usize::from(half(bytes, 56));
    if !(1..=MAX_SEGMENTS).contains(&count) || wide(bytes, 32) != 64 || half(bytes, 54) != 56 {
        return Err(Error::ProgramHeaders);
    }
    let headers_end = 64 + 56 * count;
    extent(64, (56 * count) as u64, bytes.len())?;
    let sections = half(bytes, 60);
    let section_offset = wide(bytes, 40);
    if sections == 0 {
        if section_offset != 0 || half(bytes, 58) != 0 || half(bytes, 62) != 0 {
            return Err(Error::SectionHeaders);
        }
    } else {
        if sections > 256
            || half(bytes, 58) != 64
            || section_offset < headers_end as u64
            || half(bytes, 62) >= sections
        {
            return Err(Error::SectionHeaders);
        }
        extent(section_offset, u64::from(sections) * 64, bytes.len())?;
    }
    let mut image = Image {
        bytes,
        manifest_digest,
        base: 0,
        entry: wide(bytes, 24),
        segments: [None; MAX_SEGMENTS],
        pages: 0,
        bootstrap: StartupLayout::None,
        layout: LayoutReservation::Legacy,
    };
    let mut used = 0;
    let mut previous_end = 0;
    for index in 0..count {
        let b = &bytes[64 + index * 56..64 + (index + 1) * 56];
        match word(b, 0) {
            0 => continue, // PT_NULL has no semantics, including its other fields.
            1 => (),
            _ => return Err(Error::Unsupported), // No interpreter, dynamic linking, TLS or metadata extensions yet.
        }
        let permission = match word(b, 4) {
            4 => UserPermission::ReadOnly,
            5 => UserPermission::ReadExecute,
            6 => UserPermission::ReadWrite,
            _ => return Err(Error::Permission),
        };
        let offset = wide(b, 8);
        let address = wide(b, 16);
        // p_paddr deliberately has no effect on user physical allocation.
        let file_bytes = wide(b, 32);
        let memory_bytes = wide(b, 40);
        if wide(b, 48) != FRAME_SIZE
            || !address.is_multiple_of(FRAME_SIZE)
            || !offset.is_multiple_of(FRAME_SIZE)
        {
            return Err(Error::Alignment);
        }
        if memory_bytes == 0 || file_bytes > memory_bytes || offset < headers_end as u64 {
            return Err(Error::Extent);
        }
        extent(offset, file_bytes, bytes.len())?;
        let end = address.checked_add(memory_bytes).ok_or(Error::Address)?;
        let rounded_end =
            end.checked_add(FRAME_SIZE - 1).ok_or(Error::Address)? & !(FRAME_SIZE - 1);
        if used == 0 {
            let slot = address >> 39;
            if !(1..256).contains(&slot) {
                return Err(Error::Address);
            }
            image.base = slot << 39;
        }
        if address < image.base + FRAME_SIZE || rounded_end > image.base + STACK_GUARD {
            return Err(Error::Address);
        }
        if address < previous_end {
            return Err(Error::Overlap);
        }
        let pages = ((rounded_end - address) / FRAME_SIZE) as usize;
        if image.pages + pages > image_pages {
            return Err(Error::Capacity);
        }
        image.pages += pages;
        image.segments[used] = Some(Segment {
            address,
            offset: offset as usize,
            file_bytes: file_bytes as usize,
            pages,
            permission,
        });
        used += 1;
        previous_end = rounded_end;
    }
    if !image.segments.iter().flatten().any(|s| {
        s.permission == UserPermission::ReadExecute
            && image.entry >= s.address
            && image.entry - s.address < s.file_bytes as u64
    }) {
        return Err(Error::Entry);
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bootstrap_manifest;
    use sha2::{Digest, Sha256};
    const ELF: &[u8; 8200] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
    const MANIFEST: &[u8; 232] = include_bytes!("../fixtures/bootstrap-static-v1.bin");
    const BASE: u64 = 1 << 39;
    fn put(b: &mut [u8], i: usize, value: u64) {
        b[i..i + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn bad(bytes: &[u8]) -> Option<Error> {
        parse(bytes, [0; 32]).err()
    }
    #[test]
    fn measured_golden_image_produces_exact_wx_pages_zero_tails_and_guarded_stack() {
        let m =
            bootstrap_manifest::verify(MANIFEST, Sha256::digest(MANIFEST).into(), ELF, [42; 32])
                .unwrap();
        let image = Image::from_manifest(&m).unwrap();
        assert_eq!(image.manifest_digest(), m.digest());
        assert_eq!(image.base(), BASE);
        assert_eq!(image.slot(), 1);
        assert_eq!(image.entry(), BASE + 4096);
        assert_eq!(image.required_frames(), 9);
        assert_eq!(image.stack_page(), BASE + 511 * 4096);
        assert_eq!(image.stack_top(), BASE + 512 * 4096);
        let mut data = [0xff; 4096];
        let pages: std::vec::Vec<_> = image.pages().collect();
        assert_eq!(pages.len(), 4);
        for (i, page) in pages.iter().enumerate() {
            data.fill(0xff);
            page.copy_into(&mut data);
            let (address, permission) = if i == 0 {
                (BASE + 4096, UserPermission::ReadExecute)
            } else {
                (BASE + (i as u64 + 2) * 4096, UserPermission::ReadWrite)
            };
            assert_eq!(page.address, address);
            assert_eq!(page.permission, permission);
            match i {
                0 => {
                    assert_eq!(&data[..256], &ELF[4096..4352]);
                    assert!(data[256..].iter().all(|&b| b == 0));
                }
                1 => {
                    assert_eq!(&data[..8], &ELF[8192..]);
                    assert!(data[8..].iter().all(|&b| b == 0));
                }
                _ => assert!(data.iter().all(|&b| b == 0)),
            }
        }
    }
    #[test]
    fn executable_bytes_must_match_the_measured_manifest_before_parsing() {
        let mut bytes = *ELF;
        bytes[4096] ^= 1;
        assert!(matches!(
            bootstrap_manifest::verify(MANIFEST, Sha256::digest(MANIFEST).into(), &bytes, [42; 32]),
            Err(bootstrap_manifest::Error::ImageDigest)
        ));
    }
    #[test]
    fn manifest_frame_budget_includes_image_stack_and_all_page_tables() {
        for (frames, allowed) in [(8u64, false), (9, true)] {
            let mut bytes = *MANIFEST;
            put(&mut bytes, 88, frames);
            let m = bootstrap_manifest::verify(&bytes, Sha256::digest(bytes).into(), ELF, [42; 32])
                .unwrap();
            if allowed {
                assert_eq!(Image::from_manifest(&m).unwrap().required_frames(), frames);
            } else {
                assert_eq!(Image::from_manifest(&m).err(), Some(Error::FrameBudget));
            }
        }
    }
    #[test]
    fn bootstrap_abi_adds_one_charged_reserved_readonly_page() {
        for frames in [9u64, 10] {
            let mut bytes = *MANIFEST;
            bytes[48..80].copy_from_slice(&ev_userspace_contract::ABI);
            put(&mut bytes, 88, frames);
            let m = bootstrap_manifest::verify(
                &bytes,
                Sha256::digest(bytes).into(),
                ELF,
                ev_userspace_contract::ABI,
            )
            .unwrap();
            if frames == 9 {
                assert_eq!(Image::from_manifest(&m).err(), Some(Error::FrameBudget));
            } else {
                let image = Image::from_manifest(&m).unwrap();
                assert_eq!(image.required_frames(), 10);
                assert_eq!(image.bootstrap_page(), Some(BASE + BOOTSTRAP_PAGE));
                assert_eq!(image.stack_page(), BASE + STACK_PAGE);
            }
        }
        let mut elf = *ELF;
        put(&mut elf, 136, BASE + BOOTSTRAP_PAGE);
        put(&mut elf, 160, 4096);
        let mut bytes = *MANIFEST;
        bytes[16..48].copy_from_slice(&Sha256::digest(elf));
        bytes[48..80].copy_from_slice(&ev_userspace_contract::ABI);
        let m = bootstrap_manifest::verify(
            &bytes,
            Sha256::digest(bytes).into(),
            &elf,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        assert_eq!(Image::from_manifest(&m).err(), Some(Error::Address));
    }
    #[test]
    fn header_versions_machine_endian_type_and_bounded_tables_are_required() {
        for (offset, value) in [
            (0, 0),
            (4, 1),
            (5, 2),
            (6, 2),
            (7, 3),
            (8, 1),
            (16, 3),
            (18, 3),
            (20, 2),
            (48, 1),
            (52, 63),
        ] {
            let mut b = *ELF;
            b[offset] = value;
            assert_eq!(bad(&b), Some(Error::Header), "offset {offset}");
        }
        for (offset, value) in [(32, 65), (54, 55), (56, 0), (56, 9)] {
            let mut b = *ELF;
            b[offset] = value;
            assert_eq!(bad(&b), Some(Error::ProgramHeaders));
        }
        let mut b = *ELF;
        b[56] = 8;
        assert_eq!(bad(&b[..175]), Some(Error::Extent));
    }
    #[test]
    fn unsupported_program_semantics_and_permission_amplification_are_rejected() {
        for kind in [2u32, 3, 4, 5, 6, 7, 0x6474e551, u32::MAX] {
            let mut b = *ELF;
            b[120..124].copy_from_slice(&kind.to_le_bytes());
            assert_eq!(bad(&b), Some(Error::Unsupported));
        }
        for flags in 0..512u32 {
            let mut b = *ELF;
            b[124..128].copy_from_slice(&flags.to_le_bytes());
            if [4, 5, 6].contains(&flags) {
                assert!(parse(&b, [0; 32]).is_ok());
            } else {
                assert_eq!(bad(&b), Some(Error::Permission));
            }
        }
        // PT_NULL's unused words confer no semantics; physical addresses never drive allocation.
        let mut b = *ELF;
        b[120..176].fill(0xff);
        b[120..124].fill(0);
        assert_eq!(parse(&b, [0; 32]).unwrap().pages().count(), 1);
        let mut b = *ELF;
        put(&mut b, 88, u64::MAX);
        assert!(parse(&b, [0; 32]).is_ok());
    }
    #[test]
    fn checked_extents_alignment_and_page_capacity_prevent_overflow_or_partial_plans() {
        for (offset, value, error) in [
            (72, 4097, Error::Alignment),
            (80, BASE + 4097, Error::Alignment),
            (112, 1, Error::Alignment),
            (72, 0, Error::Extent),
            (96, 4097, Error::Extent),
            (104, 0, Error::Extent),
            (128, !4095u64, Error::Extent),
            (160, u64::MAX, Error::Address),
            (160, 64 * 4096, Error::Capacity),
        ] {
            let mut b = *ELF;
            put(&mut b, offset, value);
            assert_eq!(bad(&b), Some(error), "offset {offset}");
        }
        let mut b = *ELF;
        put(&mut b, 160, 63 * 4096);
        assert_eq!(parse(&b, [0; 32]).unwrap().pages().count(), 64);
    }
    #[test]
    fn low_high_kernel_guard_and_overlapping_memory_ranges_are_rejected() {
        for address in [
            0,
            4096,
            1 << 47,
            0xffff800000000000,
            BASE,
            BASE + 510 * 4096,
        ] {
            let mut b = *ELF;
            put(&mut b, 80, address);
            assert_eq!(bad(&b), Some(Error::Address));
        }
        let mut b = *ELF;
        put(&mut b, 136, BASE + 4096);
        assert_eq!(bad(&b), Some(Error::Overlap));
        let mut b = *ELF;
        put(&mut b, 104, 3 * 4096);
        assert_eq!(bad(&b), Some(Error::Overlap));
        let mut b = *ELF;
        put(&mut b, 136, BASE + 509 * 4096);
        assert_eq!(bad(&b), Some(Error::Address));
    }
    #[test]
    fn entry_must_be_in_file_backed_executable_bytes() {
        for entry in [
            0,
            BASE,
            BASE + 4096 + 256,
            BASE + 3 * 4096,
            BASE + 511 * 4096,
            u64::MAX,
        ] {
            let mut b = *ELF;
            put(&mut b, 24, entry);
            assert_eq!(bad(&b), Some(Error::Entry));
        }
        let mut b = *ELF;
        b[68] = 6;
        assert_eq!(bad(&b), Some(Error::Entry));
    }
    #[test]
    fn optional_section_tables_are_bounded_without_interpreting_them_as_loads() {
        let mut b = ELF.to_vec();
        b.resize(12352, 0);
        put(&mut b, 40, 12288);
        b[58] = 64;
        b[60] = 1;
        assert!(parse(&b, [0; 32]).is_ok());
        for (offset, value) in [(58, 63), (60, 0), (62, 1)] {
            let mut bad_bytes = b.clone();
            bad_bytes[offset] = value;
            assert_eq!(bad(&bad_bytes), Some(Error::SectionHeaders));
        }
        b[60..62].copy_from_slice(&257u16.to_le_bytes());
        assert_eq!(bad(&b), Some(Error::SectionHeaders));
        let mut b = *ELF;
        put(&mut b, 40, u64::MAX);
        b[58] = 64;
        b[60] = 1;
        assert_eq!(bad(&b), Some(Error::Extent));
    }
    #[test]
    fn every_truncation_and_bounded_mutated_header_is_total() {
        for size in 0..ELF.len() {
            assert!(parse(&ELF[..size], [0; 32]).is_err());
        }
        for sample in 0..8192usize {
            let mut b = *ELF;
            for n in 0..4 {
                let index = (sample * 17 + n * 43) % 176;
                b[index] ^= (sample.wrapping_mul(13).wrapping_add(n) as u8) | 1;
            }
            if let Ok(image) = parse(&b, [0; 32]) {
                assert!(image.pages().count() <= MAX_IMAGE_PAGES);
                for p in image.pages() {
                    let mut bytes = [255; 4096];
                    p.copy_into(&mut bytes);
                }
            }
        }
    }
}
