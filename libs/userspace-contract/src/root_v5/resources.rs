//! Proposed M8-only finite envelopes and source layout. None reserves RAM,
//! admits an image, resets accounting or proves a runtime high-water mark.
use super::{Role, graph, put};
// RootJob owns the full descendant/shared-backing subtree. Actual58,000ticks
// charged57,887aggregateCPU in the first observed graph; selected finite CPU
// ceilings are4M Root/8M Boot/1M child, never usage resets or legacy changes. Its4096-frame
// ceiling is distinct from the unchanged240-image/244-private/246-base loader.
pub const ROOT_LIMITS: [u64; 4] = [4_000_000, 4096, 13, 13];
pub const BOOT_LIMITS: [u64; 4] = [8_000_000, 8192, 14, 14];
pub const JOB_TEMPLATE_LIMITS: [[u64; 4]; 4] = [
    [1_000_000, 32, 1, 1], // Selected M8 Core only; legacy factories retain their old CPU limits.
    [1_000_000, 64, 1, 1], // Network service.
    [1_000_000, 128, 1, 1], // New UI, Workspace and Display; all require exact linked admission.
    [1_000_000, 512, 1, 1], // Each independent Editor; one1MiB .bss buffer is explicit.
];
pub const PERIOD_TICKS: u64 = 256;
pub const CHILD_QUOTA_TICKS: u64 = 64;
pub const ROOT_QUOTA_TICKS: u64 = 256;
pub const RPC_TICKS: u64 = 1024;
pub const FILE_TRANSACTION_TICKS: u64 = 8192;
pub const HELD_REPLACEMENTS: usize = 1;
pub const OBJECTS: usize = 96;
pub const LINEAGE: usize = 512;
pub const SPACES: usize = 64;
pub const ROOT_HANDLES: usize = 96;
pub const ORDINARY_HANDLES: usize = 16;
pub const LEGACY_OBJECTS: usize = 64;
pub const LEGACY_LINEAGE: usize = 256;
pub const LEGACY_SPACES: usize = 40;
pub const LEGACY_ROOT_HANDLES: usize = 64;
pub const STEADY_JOBS: usize = 13;
pub const STEADY_PROCESSES: usize = 12; // Boot is one Job, not a userspace process.
pub const STEADY_THREADS: usize = 12;
pub const HELD_JOBS: usize = 14;
pub const HELD_PROCESSES: usize = 13;
pub const HELD_THREADS: usize = 13;
pub const BASELINE_OBJECT_LOWER_BOUND: usize = 82;
pub const DYNAMIC_HELD_OBJECT_LOWER_BOUND: usize = 86; // +two image objects +held Job/Process.
pub const STEADY_SPACE_LOWER_BOUND: usize = 49;
pub const HELD_SPACE_LOWER_BOUND: usize = 51;
pub const CHANNEL_OVERLAP_SPACE_LOWER_BOUND: usize = 52;
pub const STEADY_LINEAGE_LOWER_BOUND: usize = 306;
pub const HELD_LINEAGE_LOWER_BOUND: usize = 340;
pub const STEADY_ROOT_HANDLE_LOWER_BOUND: usize = 71; //37sources+23channels+11ProcessCONTROL.
pub const DYNAMIC_HELD_SCRATCH_ROOT_HANDLES: usize = 76;
const _: () = {
    assert!(DYNAMIC_HELD_OBJECT_LOWER_BOUND < OBJECTS);
    assert!(CHANNEL_OVERLAP_SPACE_LOWER_BOUND < SPACES);
    assert!(HELD_LINEAGE_LOWER_BOUND < LINEAGE);
    assert!(DYNAMIC_HELD_SCRATCH_ROOT_HANDLES < ROOT_HANDLES);
};
pub const PRIVATE_WINDOW_PAGES: u64 = 512;
pub const ROOT_MAX_IMAGE_PAGES: u64 = 240;
pub const ROOT_MAX_PRIVATE_PAGES: u64 = 244;
pub const ROOT_MAX_PRIVATE_FRAMES: u64 = 246;
pub const LARGE_MAX_IMAGE_PAGES: u64 = 384;
pub const LARGE_MAX_PRIVATE_PAGES: u64 = 388;
pub const LARGE_MAX_PRIVATE_FRAMES: u64 = 390;
pub const ROOT_STACK_FIRST_PAGE: u64 = 256;
pub const ROOT_STACK_PAGES: u64 = 8;
pub const M8_STACK_FIRST_PAGE: u64 = 480;
pub const M8_STACK_PAGES: u64 = 8;
pub const LEGACY_STACK_FIRST_PAGE: u64 = 256;
pub const LEGACY_STACK_PAGES: u64 = 4;
pub const STARTUP_PAGE: u64 = 509;
pub const ENTRY_STACK_PAGE: u64 = 511;
pub const APP_SURFACE_FIRST_PAGE: u64 = 384;
pub const APP_SURFACE_PAGES: u64 = 63;
pub const APP_FILE_FIRST_PAGE: u64 = 506;
pub const APP_FILE_PAGES: u64 = 2;
pub const CONTROL_BYTES: usize = 256;
pub const BULK_BYTES: usize = 4096;
pub const ROOT_CATALOGUE_FIRST_PAGE: u64 = 500;
pub const ROOT_CATALOGUE_PAGES: u64 = 3;
pub const ROOT_WORKSPACE_FIRST_PAGE: u64 = 503;
pub const ROOT_WORKSPACE_PAGES: u64 = 2;
pub const ROOT_PROTECTED_FIRST_PAGE: u64 = 448;
pub const PROTECTED_PAGES: u64 = 51;
pub const ROOT_NET_CLIENT_PAGE: u64 = 505;
pub const ROOT_NIC_PAGE: u64 = 508;
/// Root's legacy System Block buffer. NicWindow stays in NetDriver's distinct
/// address space at the same relative page; Root holds its cap without mapping.
pub const ROOT_SYSTEM_IO_PAGE: u64 = 508;
pub const NIC_WINDOW_PAGE: u64 = 508;
pub const PACKAGE_A_FIRST_PAGE: u64 = 368;
pub const PACKAGE_B_FIRST_PAGE: u64 = 304;
/// Physical shared-bank envelope, distinct from the single-package limit.
pub const PACKAGE_CURRENT_PAGES: u64 = 79;
pub const PACKAGE_CURRENT_BYTES: u64 = PACKAGE_CURRENT_PAGES * 4096;
pub const PACKAGE_CANDIDATE_PAGES: u64 = 63;
pub const PACKAGE_CANDIDATE_BYTES: u64 = PACKAGE_CANDIDATE_PAGES * 4096;
/// One package and the sealed dynamic factory keep their original envelope.
pub const PACKAGE_MAX_PAGES: u64 = 63;
pub const PACKAGE_MAX_BYTES: u64 = PACKAGE_MAX_PAGES * 4096;
pub const DESKTOP_WIDTH: u32 = 640;
pub const DESKTOP_HEIGHT: u32 = 480;
pub const PROTECTED_WIDTH: u32 = 640;
pub const PROTECTED_HEIGHT: u32 = 80;
pub const APP_MAX_WIDTH: u32 = 320;
pub const APP_MAX_HEIGHT: u32 = 200;
pub const APP_REFERENCE_WIDTH: u32 = 320;
pub const APP_REFERENCE_HEIGHT: u32 = 180;
pub const SURFACE_HEADER_BYTES: usize = 256;
pub const ROOT_SURFACE_PIXEL_OFFSET: usize = 512;
pub const ROOT_PROTECTED_PIXEL_BYTES: usize =
    PROTECTED_WIDTH as usize * PROTECTED_HEIGHT as usize * 4;
/// READ-only mappings in Display. Ordinary producers cannot select these pages.
pub const DISPLAY_SURFACES: [(Role, u64, u64); 6] = [
    (Role::FilesSurface, 64, 63),
    (Role::EditorOneSurface, 128, 63),
    (Role::EditorTwoSurface, 192, 63),
    (Role::InspectorSurface, 256, 63),
    (Role::ShellSurface, 320, 63),
    (Role::ProtectedSurface, 384, 51),
];
/// Workspace sees each exact caller's independent two-page control/bulk window.
pub const WORKSPACE_WINDOWS: [(Role, u64, u64); 5] = [
    (Role::RootWorkspaceFrame, 494, 2),
    (Role::FilesFrame, 496, 2),
    (Role::EditorOneFrame, 498, 2),
    (Role::EditorTwoFrame, 500, 2),
    (Role::InspectorFrame, 502, 2),
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ImageLayout {
    LegacyCore = 0,
    Ui = 1,
    Workspace = 2,
    Editor = 3,
    Display = 4,
}
pub const fn image_layout(image: graph::ImageSlot) -> ImageLayout {
    match image {
        graph::ImageSlot::Block
        | graph::ImageSlot::Input
        | graph::ImageSlot::NetDriver
        | graph::ImageSlot::NetService => ImageLayout::LegacyCore,
        graph::ImageSlot::Workspace => ImageLayout::Workspace,
        graph::ImageSlot::Editor => ImageLayout::Editor,
        graph::ImageSlot::Display => ImageLayout::Display,
        _ => ImageLayout::Ui,
    }
}
pub const fn max_image_pages(image: graph::ImageSlot) -> u64 {
    match image_layout(image) {
        ImageLayout::LegacyCore => 64,
        ImageLayout::Ui | ImageLayout::Workspace => 96,
        ImageLayout::Editor => 384,
        ImageLayout::Display => 80,
    }
}
pub const fn max_private_pages(image: graph::ImageSlot) -> u64 {
    max_image_pages(image) + 4
}
pub const fn max_loader_frames(image: graph::ImageSlot) -> u64 {
    max_image_pages(image)
        + 6
        + if matches!(image, graph::ImageSlot::Display) {
            2
        } else {
            0
        }
}
pub const fn stack(image: graph::ImageSlot) -> (u64, u64) {
    if matches!(image_layout(image), ImageLayout::LegacyCore) {
        (LEGACY_STACK_FIRST_PAGE, LEGACY_STACK_PAGES)
    } else {
        (M8_STACK_FIRST_PAGE, M8_STACK_PAGES)
    }
}
pub const LAYOUT_BYTES: usize = 2048;
pub fn layout_description() -> [u8; LAYOUT_BYTES] {
    let mut b = [0; LAYOUT_BYTES];
    b[..8].copy_from_slice(b"EVWLAY05");
    b[8..10].copy_from_slice(&super::VERSION.to_le_bytes());
    b[10..12].copy_from_slice(&(LAYOUT_BYTES as u16).to_le_bytes());
    b[16..48].copy_from_slice(&super::ABI);
    b[48..80].copy_from_slice(&super::child::ABI);
    let values = [
        OBJECTS as u64,
        LINEAGE as u64,
        SPACES as u64,
        ROOT_HANDLES as u64,
        ORDINARY_HANDLES as u64,
        ROOT_MAX_IMAGE_PAGES,
        ROOT_MAX_PRIVATE_PAGES,
        ROOT_MAX_PRIVATE_FRAMES,
        LARGE_MAX_IMAGE_PAGES,
        LARGE_MAX_PRIVATE_PAGES,
        LARGE_MAX_PRIVATE_FRAMES,
        ROOT_STACK_FIRST_PAGE,
        ROOT_STACK_PAGES,
        M8_STACK_FIRST_PAGE,
        M8_STACK_PAGES,
        LEGACY_STACK_FIRST_PAGE,
        LEGACY_STACK_PAGES,
        PRIVATE_WINDOW_PAGES,
        APP_SURFACE_FIRST_PAGE,
        APP_SURFACE_PAGES,
        APP_FILE_FIRST_PAGE,
        APP_FILE_PAGES,
        ROOT_CATALOGUE_FIRST_PAGE,
        ROOT_CATALOGUE_PAGES,
        ROOT_WORKSPACE_FIRST_PAGE,
        ROOT_WORKSPACE_PAGES,
        ROOT_PROTECTED_FIRST_PAGE,
        PROTECTED_PAGES,
        ROOT_NET_CLIENT_PAGE,
        ROOT_NIC_PAGE,
        STARTUP_PAGE,
        ENTRY_STACK_PAGE,
        PACKAGE_A_FIRST_PAGE,
        PACKAGE_CURRENT_PAGES,
        PACKAGE_B_FIRST_PAGE,
        PACKAGE_CANDIDATE_PAGES,
        PACKAGE_MAX_PAGES,
        PERIOD_TICKS,
        CHILD_QUOTA_TICKS,
        ROOT_QUOTA_TICKS,
        RPC_TICKS,
        FILE_TRANSACTION_TICKS,
        DESKTOP_WIDTH as u64,
        DESKTOP_HEIGHT as u64,
        PROTECTED_WIDTH as u64,
        PROTECTED_HEIGHT as u64,
        APP_MAX_WIDTH as u64,
        APP_MAX_HEIGHT as u64,
        APP_REFERENCE_WIDTH as u64,
        APP_REFERENCE_HEIGHT as u64,
        SURFACE_HEADER_BYTES as u64,
    ];
    for (i, value) in values.into_iter().enumerate() {
        put(&mut b, 80 + i * 8, value);
    }
    for (i, image) in graph::IMAGES.into_iter().enumerate() {
        let at = 512 + i * 48;
        put(&mut b, at, image.role().selector());
        put(&mut b, at + 8, max_image_pages(image));
        let (first, pages) = stack(image);
        put(&mut b, at + 16, first);
        put(&mut b, at + 24, pages);
        put(
            &mut b,
            at + 32,
            super::child::startup_size(image.representative()) as u64,
        );
        put(&mut b, at + 40, image_layout(image) as u64);
    }
    for (i, (role, first, pages)) in DISPLAY_SURFACES.into_iter().enumerate() {
        let at = 1024 + i * 24;
        put(&mut b, at, role.selector());
        put(&mut b, at + 8, first);
        put(&mut b, at + 16, pages);
    }
    for (i, (role, first, pages)) in WORKSPACE_WINDOWS.into_iter().enumerate() {
        let at = 1184 + i * 24;
        put(&mut b, at, role.selector());
        put(&mut b, at + 8, first);
        put(&mut b, at + 16, pages);
    }
    for (i, limits) in JOB_TEMPLATE_LIMITS.into_iter().enumerate() {
        let at = 1344 + i * 40;
        put(&mut b, at, i as u64);
        for (j, v) in limits.into_iter().enumerate() {
            put(&mut b, at + 8 + j * 8, v);
        }
    }
    for (i, v) in ROOT_LIMITS.into_iter().chain(BOOT_LIMITS).enumerate() {
        put(&mut b, 1600 + i * 8, v);
    }
    put(&mut b, 1664, crate::syscall::PROCESS_JOB_INFO_V1);
    b[1672..1704].copy_from_slice(&crate::syscall::PROCESS_JOB_INFO_ABI);
    put(&mut b, 1704, crate::syscall::SERVING_ORIGIN_V1);
    b[1712..1744].copy_from_slice(&crate::syscall::SERVING_ORIGIN_ABI);
    for (i, image) in graph::IMAGES.into_iter().enumerate() {
        let at = 1760 + i * 16;
        put(&mut b, at, max_private_pages(image));
        put(&mut b, at + 8, max_loader_frames(image));
    }
    put(&mut b, 1920, ROOT_SURFACE_PIXEL_OFFSET as u64);
    b
}
pub const CENSUS_BYTES: usize = 256;
pub fn proposed_census() -> [u8; CENSUS_BYTES] {
    let mut b = [0; CENSUS_BYTES];
    b[..8].copy_from_slice(b"EVMCEN05");
    // status0 deliberately means proposed lower bounds, NEVER a runtime PASS.
    let values = [
        BASELINE_OBJECT_LOWER_BOUND as u64,
        DYNAMIC_HELD_OBJECT_LOWER_BOUND as u64,
        STEADY_SPACE_LOWER_BOUND as u64,
        HELD_SPACE_LOWER_BOUND as u64,
        CHANNEL_OVERLAP_SPACE_LOWER_BOUND as u64,
        STEADY_LINEAGE_LOWER_BOUND as u64,
        HELD_LINEAGE_LOWER_BOUND as u64,
        STEADY_ROOT_HANDLE_LOWER_BOUND as u64,
        DYNAMIC_HELD_SCRATCH_ROOT_HANDLES as u64,
        STEADY_JOBS as u64,
        STEADY_PROCESSES as u64,
        STEADY_THREADS as u64,
        HELD_JOBS as u64,
        HELD_PROCESSES as u64,
        HELD_THREADS as u64,
        OBJECTS as u64,
        LINEAGE as u64,
        SPACES as u64,
        ROOT_HANDLES as u64,
        ORDINARY_HANDLES as u64,
        LEGACY_OBJECTS as u64,
        LEGACY_LINEAGE as u64,
        LEGACY_SPACES as u64,
        LEGACY_ROOT_HANDLES as u64,
    ];
    for (i, value) in values.into_iter().enumerate() {
        put(&mut b, 32 + i * 8, value);
    }
    b
}
