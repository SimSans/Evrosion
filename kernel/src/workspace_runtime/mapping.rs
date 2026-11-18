//! Closed trusted V5 source/window joins. None is selected by a caller address.
use super::*;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Spec {
    pub role: Role,
    pub first: usize,
    pub pages: usize,
    pub writable: bool,
    pub guards: bool,
}
const fn s(role: Role, first: usize, pages: usize, writable: bool, guards: bool) -> Spec {
    Spec {
        role,
        first,
        pages,
        writable,
        guards,
    }
}
pub(super) const ROOT: [Spec; 7] = [
    s(
        Role::PackageCurrent,
        v5::resources::PACKAGE_A_FIRST_PAGE as usize,
        v5::resources::PACKAGE_CURRENT_PAGES as usize,
        false,
        true,
    ),
    s(Role::PackageCandidate, 304, 63, false, true),
    s(Role::ProtectedSurface, 448, 51, true, true),
    s(Role::Catalogue, 500, 3, false, false),
    s(Role::RootWorkspaceFrame, 503, 2, true, false),
    s(Role::NetClientWindow, 505, 1, true, false),
    s(Role::SystemIo, 508, 1, true, false),
];
pub(super) fn for_child(child: Child) -> impl Iterator<Item = Spec> {
    const DISPLAY: [Spec; 6] = [
        s(Role::FilesSurface, 64, 63, false, true),
        s(Role::EditorOneSurface, 128, 63, false, true),
        s(Role::EditorTwoSurface, 192, 63, false, true),
        s(Role::InspectorSurface, 256, 63, false, true),
        s(Role::ShellSurface, 320, 63, false, true),
        s(Role::ProtectedSurface, 384, 51, false, true),
    ];
    const WORKSPACE: [Spec; 7] = [
        s(Role::LegacyFileIo, 508, 1, true, false),
        s(Role::WorkspaceBlockWindow, 506, 1, true, false),
        s(Role::RootWorkspaceFrame, 494, 2, true, false),
        s(Role::FilesFrame, 496, 2, true, false),
        s(Role::EditorOneFrame, 498, 2, true, false),
        s(Role::EditorTwoFrame, 500, 2, true, false),
        s(Role::InspectorFrame, 502, 2, true, false),
    ];
    const BLOCK: [Spec; 3] = [
        s(Role::SystemIo, 508, 1, true, false),
        s(Role::LegacyFileIo, 507, 1, true, false),
        s(Role::WorkspaceBlockWindow, 506, 1, true, false),
    ];
    const NET_DRIVER: [Spec; 1] = [s(Role::NicWindow, 508, 1, true, false)];
    const NET_SERVICE: [Spec; 2] = [
        s(Role::NicWindow, 508, 1, true, false),
        s(Role::NetClientWindow, 507, 1, true, false),
    ];
    const SHELL: [Spec; 1] = [s(Role::ShellSurface, 384, 63, true, true)];
    const FILES: [Spec; 2] = [
        s(Role::FilesSurface, 384, 63, true, true),
        s(Role::FilesFrame, 506, 2, true, true),
    ];
    const EDITOR_ONE: [Spec; 2] = [
        s(Role::EditorOneSurface, 384, 63, true, true),
        s(Role::EditorOneFrame, 506, 2, true, true),
    ];
    const EDITOR_TWO: [Spec; 2] = [
        s(Role::EditorTwoSurface, 384, 63, true, true),
        s(Role::EditorTwoFrame, 506, 2, true, true),
    ];
    const INSPECTOR: [Spec; 2] = [
        s(Role::InspectorSurface, 384, 63, true, true),
        s(Role::InspectorFrame, 506, 2, true, true),
    ];
    let values: &'static [Spec] = match child {
        Child::Display => &DISPLAY,
        Child::Workspace => &WORKSPACE,
        Child::Block => &BLOCK,
        Child::NetDriver => &NET_DRIVER,
        Child::NetService => &NET_SERVICE,
        Child::Shell => &SHELL,
        Child::Files => &FILES,
        Child::EditorOne => &EDITOR_ONE,
        Child::EditorTwo => &EDITOR_TWO,
        Child::Inspector => &INSPECTOR,
        Child::Input => &[],
    };
    values.iter().copied()
}
