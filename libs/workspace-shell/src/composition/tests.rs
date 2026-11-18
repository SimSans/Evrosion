extern crate std;
use super::*;
use crate::{Actions, Label, Node, Role, Tree, TrustedAdapter, Value};
use std::vec;
use std::vec::Vec;

const SHELL: Owner = Owner {
    process: 1,
    incarnation: 1,
};
const ROOT: Owner = Owner {
    process: 2,
    incarnation: 1,
};
const COLORS: [u32; 4] = [0x00bb1100, 0x0000aa22, 0x000033cc, 0x00bb22aa];
fn owner(process: u64) -> Owner {
    Owner {
        process,
        incarnation: 1,
    }
}
fn surface(object: u64) -> Surface {
    Surface {
        object,
        generation: 1,
    }
}
fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
    Rect {
        x,
        y,
        width,
        height,
    }
}
fn node(bounds: Rect) -> Node {
    Node {
        local: 1,
        parent: None,
        role: Role::Window,
        label: Label::new("App").unwrap(),
        bounds,
        value: Value::None,
        actions: Actions::NONE,
        disabled: false,
        protected: false,
    }
}
fn publish(desktop: &mut Desktop, id: WindowId) {
    let window = *desktop.window(id).unwrap();
    let revision = window.view_revision + 1;
    desktop
        .publish_view(
            window.owner,
            id,
            revision,
            Tree::new(revision, &[node(window.bounds)]).unwrap(),
        )
        .unwrap();
}
fn four() -> (Desktop, TrustedAdapter, [WindowId; 4], [Vec<u32>; 4]) {
    let (mut desktop, adapter) = Desktop::new(SHELL, ROOT, rect(0, 0, 96, 72)).unwrap();
    let kinds = [
        WindowKind::Files,
        WindowKind::EditorOne,
        WindowKind::EditorTwo,
        WindowKind::Inspector,
    ];
    let bounds = [
        rect(2, 16, 48, 40),
        rect(20, 24, 50, 35),
        rect(45, 36, 42, 30),
        rect(68, 15, 26, 28),
    ];
    let ids = core::array::from_fn(|at| {
        desktop
            .install(
                kinds[at],
                owner(11 + at as u64),
                surface(101 + at as u64),
                bounds[at],
            )
            .unwrap()
    });
    for id in ids {
        publish(&mut desktop, id);
    }
    let buffers = core::array::from_fn(|at| storage(bounds[at], COLORS[at], 3));
    (desktop, adapter, ids, buffers)
}
fn storage(bounds: Rect, color: u32, padding: u32) -> Vec<u32> {
    let stride = bounds.width + padding;
    let mut pixels = vec![0x00deadbe; (stride * bounds.height) as usize];
    for y in 0..bounds.height {
        for x in 0..bounds.width {
            pixels[(y * stride + x) as usize] = color | 0xff000000;
        }
    }
    pixels
}
fn raster(bounds: Rect, padding: u32) -> Raster {
    Raster {
        width: bounds.width,
        height: bounds.height,
        stride_pixels: bounds.width + padding,
        extent_bytes: u64::from((bounds.width + padding) * bounds.height) * 4,
    }
}
fn frame<'a>(
    desktop: &Desktop,
    id: WindowId,
    pixels: &'a [u32],
    serial: u64,
    padding: u32,
) -> AppFrame<'a> {
    let window = desktop.window(id).unwrap();
    AppFrame::new(
        AppHeader {
            window: id,
            role: FrameRole::Window,
            owner: window.owner,
            surface: window.surface,
            model_revision: desktop.revision(),
            view_revision: window.view_revision,
            frame: serial,
            raster: raster(window.bounds, padding),
        },
        pixels,
    )
    .unwrap()
}
fn frames<'a>(
    desktop: &Desktop,
    ids: [WindowId; 4],
    buffers: &'a [Vec<u32>; 4],
    serial: u64,
) -> [AppFrame<'a>; 4] {
    core::array::from_fn(|at| frame(desktop, ids[at], &buffers[at], serial, 3))
}
struct Sink {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
    writes: usize,
    fail_after: Option<usize>,
}
impl Sink {
    fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            pixels: vec![0x12345678; width * height + 2],
            writes: 0,
            fail_after: None,
        }
    }
    fn at(&self, x: usize, y: usize) -> u32 {
        self.pixels[1 + y * self.width + x]
    }
    fn guards(&self) {
        assert_eq!(self.pixels[0], 0x12345678);
        assert_eq!(self.pixels[self.pixels.len() - 1], 0x12345678);
    }
}
impl Pixels for Sink {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), ev_graphics::Error> {
        if x >= self.width || y >= self.height || self.fail_after == Some(self.writes) {
            return Err(ev_graphics::Error::Bounds);
        }
        self.pixels[1 + y * self.width + x] = color.0;
        self.writes += 1;
        Ok(())
    }
}

#[test]
fn independent_surfaces_compose_exact_overlap_without_padding_or_root_area_leaks() {
    let (desktop, _, ids, buffers) = four();
    let mut compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let borrows = frames(&desktop, ids, &buffers, 1);
    let scene = compositor.prepare(&desktop, &borrows, None).unwrap();
    let mut output = Sink::new(96, 72);
    let committed = compositor.compose(&desktop, scene, &mut output).unwrap();
    for (x, y, color) in [
        (5, 40, COLORS[0]),
        (25, 30, COLORS[1]),
        (50, 50, COLORS[2]),
        (80, 20, COLORS[3]),
    ] {
        assert_eq!(output.at(x, y), color);
    }
    for y in 0..8 {
        for x in 0..96 {
            assert_eq!(output.at(x, y), 0x00080c12);
        }
    }
    assert!(!output.pixels.contains(&0x00deadbe));
    output.guards();
    assert_eq!(committed.model_revision, desktop.revision());
    for id in ids {
        let commit = committed
            .windows
            .iter()
            .flatten()
            .find(|commit| commit.window == id)
            .unwrap();
        let geometry = compositor.geometry(&desktop, id).unwrap();
        assert_eq!((commit.view_revision, geometry.view_revision), (1, 1));
        assert_eq!(
            geometry.content,
            desktop
                .window(id)
                .unwrap()
                .tree
                .unwrap()
                .nodes()
                .next()
                .unwrap()
                .bounds
        );
    }
}

#[test]
fn owner_surface_epoch_extent_and_duplicate_fail_before_any_output_write() {
    let (desktop, _, ids, buffers) = four();
    let compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let mut borrows = frames(&desktop, ids, &buffers, 1);
    let valid = borrows[1];
    let mut header = valid.header();
    header.owner = owner(13);
    borrows[1] = AppFrame::new(header, &buffers[1]).unwrap();
    assert!(matches!(
        compositor.prepare(&desktop, &borrows, None),
        Err(ComposeError::Owner)
    ));
    header.owner = owner(12);
    header.surface.generation += 1;
    borrows[1] = AppFrame::new(header, &buffers[1]).unwrap();
    assert!(matches!(
        compositor.prepare(&desktop, &borrows, None),
        Err(ComposeError::Surface)
    ));
    borrows[1] = valid;
    borrows[2] = valid;
    assert!(matches!(
        compositor.prepare(&desktop, &borrows, None),
        Err(ComposeError::Duplicate)
    ));
    let mut malformed = valid.header();
    malformed.raster.extent_bytes -= 4;
    assert!(matches!(
        AppFrame::new(malformed, &buffers[1]),
        Err(ComposeError::Extent)
    ));
    malformed = valid.header();
    malformed.raster.stride_pixels -= 4;
    assert!(matches!(
        AppFrame::new(malformed, &buffers[1]),
        Err(ComposeError::Geometry)
    ));
}

#[test]
fn stale_model_provider_and_preference_commits_do_not_touch_scanout() {
    let (mut desktop, _, ids, buffers) = four();
    let mut compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let borrows = frames(&desktop, ids, &buffers, 1);
    let scene = compositor.prepare(&desktop, &borrows, None).unwrap();
    desktop
        .provider(owner(80), crate::ProviderRights::READ)
        .unwrap();
    let mut output = Sink::new(96, 72);
    assert_eq!(
        compositor.compose(&desktop, scene, &mut output),
        Err(ComposeError::Stale)
    );
    assert_eq!(output.writes, 0);
    assert!(matches!(
        compositor.prepare(&desktop, &borrows, None),
        Err(ComposeError::Revision)
    ));
    let current = frames(&desktop, ids, &buffers, 1);
    let scene = compositor.prepare(&desktop, &current, None).unwrap();
    desktop
        .set_preferences(
            SHELL,
            Preferences {
                scale: 2,
                ..Preferences::DEFAULT
            },
        )
        .unwrap();
    assert_eq!(
        compositor.compose(&desktop, scene, &mut output),
        Err(ComposeError::Stale)
    );
    assert_eq!(output.writes, 0);
}

#[test]
fn resize_refuses_old_extent_and_same_frame_at_new_tree_then_paints_only_new_geometry() {
    let (mut desktop, _) = Desktop::new(SHELL, ROOT, rect(0, 0, 96, 72)).unwrap();
    let id = desktop
        .install(
            WindowKind::Files,
            owner(11),
            surface(101),
            rect(10, 20, 60, 40),
        )
        .unwrap();
    publish(&mut desktop, id);
    let old = storage(desktop.window(id).unwrap().bounds, COLORS[0], 0);
    let mut compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let mut output = Sink::new(96, 72);
    let initial = frame(&desktop, id, &old, 1, 0);
    let scene = compositor.prepare(&desktop, &[initial], None).unwrap();
    compositor.compose(&desktop, scene, &mut output).unwrap();
    desktop.geometry(SHELL, id, rect(10, 20, 20, 15)).unwrap();
    publish(&mut desktop, id);
    let mut stale_header = initial.header();
    stale_header.model_revision = desktop.revision();
    stale_header.view_revision = 2;
    let oversized = AppFrame::new(stale_header, &old).unwrap();
    assert!(matches!(
        compositor.prepare(&desktop, &[oversized], None),
        Err(ComposeError::Geometry)
    ));
    let smaller = storage(desktop.window(id).unwrap().bounds, COLORS[2], 0);
    let reused_frame = frame(&desktop, id, &smaller, 1, 0);
    assert!(matches!(
        compositor.prepare(&desktop, &[reused_frame], None),
        Err(ComposeError::Frame)
    ));
    let current = frame(&desktop, id, &smaller, 2, 0);
    let scene = compositor.prepare(&desktop, &[current], None).unwrap();
    compositor.compose(&desktop, scene, &mut output).unwrap();
    assert_eq!(output.at(15, 25), COLORS[2]);
    assert_eq!(output.at(40, 40), ev_graphics::BACKGROUND.0);
    output.guards();
}

#[test]
fn hidden_windows_have_no_borrow_or_paint_and_hidden_focus_is_refused() {
    let (mut desktop, _, ids, buffers) = four();
    desktop.set_visible(SHELL, ids[3], false).unwrap();
    let mut compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let all = frames(&desktop, ids, &buffers, 1);
    assert!(matches!(
        compositor.prepare(&desktop, &all, None),
        Err(ComposeError::Unexpected)
    ));
    let scene = compositor.prepare(&desktop, &all[..3], None).unwrap();
    let mut output = Sink::new(96, 72);
    compositor.compose(&desktop, scene, &mut output).unwrap();
    assert_eq!(output.at(80, 20), ev_graphics::BACKGROUND.0);
    assert!(!output.pixels.contains(&COLORS[3]));
    assert_eq!(desktop.activate(SHELL, ids[3]), Err(Error::Focus));
    assert_ne!(desktop.view().focused, Some(ids[3]));
}

#[test]
fn scaling_contrast_focus_and_inverse_hit_mapping_share_logical_geometry() {
    let (mut desktop, _, ids, buffers) = four();
    desktop
        .set_preferences(
            SHELL,
            Preferences {
                scale: 2,
                contrast: Contrast::High,
                focus: FocusStyle::ThickOutline,
            },
        )
        .unwrap();
    let mut compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let current = frames(&desktop, ids, &buffers, 1);
    let scene = compositor.prepare(&desktop, &current, None).unwrap();
    let mut output = Sink::new(192, 144);
    compositor.compose(&desktop, scene, &mut output).unwrap();
    for y in 0..72 {
        for x in 0..96 {
            let value = output.at(x * 2, y * 2);
            for dy in 0..2 {
                for dx in 0..2 {
                    assert_eq!(output.at(x * 2 + dx, y * 2 + dy), value);
                }
            }
        }
    }
    assert_eq!(
        compositor.logical_point(&desktop, 51, 61).unwrap(),
        Some((25, 30))
    );
    assert_eq!(compositor.logical_point(&desktop, 12, 4).unwrap(), None);
    let geometry = compositor.geometry(&desktop, ids[3]).unwrap();
    assert_eq!(geometry.outer.x, 66);
    assert_eq!(geometry.content.x, 68);
    let title = geometry.title.unwrap();
    let mut black = 0;
    let mut white = 0;
    for y in title.y.max(8)..title.y + title.height as i32 {
        for x in title.x..title.x + title.width as i32 {
            match output.at(x as usize * 2, y as usize * 2) {
                0 => black += 1,
                0xffffff => white += 1,
                _ => {}
            }
        }
    }
    assert!(
        black > 0 && white > 0,
        "focused title must retain a readable non-color focus marker"
    );
    output.guards();
}

#[test]
fn app_cannot_overwrite_root_region_or_present_a_foreign_protected_plane() {
    let (mut desktop, adapter) = Desktop::new(SHELL, ROOT, rect(0, 0, 32, 24)).unwrap();
    let id = desktop
        .install(
            WindowKind::Files,
            owner(11),
            surface(101),
            rect(0, 0, 32, 24),
        )
        .unwrap();
    publish(&mut desktop, id);
    let region = rect(0, 0, 32, 4);
    let app = storage(desktop.window(id).unwrap().bounds, COLORS[0], 0);
    let trusted = storage(region, 0x00a1b2c3, 0);
    let mut compositor = Compositor::new(&desktop, region).unwrap();
    let root_header = ProtectedHeader {
        owner: ROOT,
        surface: surface(900),
        model_revision: desktop.revision(),
        frame: 1,
        raster: raster(region, 0),
    };
    assert!(matches!(
        adapter.borrow_protected(
            &desktop,
            region,
            ProtectedHeader {
                owner: owner(11),
                ..root_header
            },
            &trusted
        ),
        Err(ComposeError::Owner)
    ));
    let (other, other_adapter) = Desktop::new(SHELL, ROOT, rect(0, 0, 32, 24)).unwrap();
    let foreign = other_adapter
        .borrow_protected(
            &other,
            region,
            ProtectedHeader {
                model_revision: other.revision(),
                ..root_header
            },
            &trusted,
        )
        .unwrap();
    let frame = frame(&desktop, id, &app, 1, 0);
    assert!(matches!(
        compositor.prepare(&desktop, &[frame], Some(foreign)),
        Err(ComposeError::Protected)
    ));
    let root = adapter
        .borrow_protected(&desktop, region, root_header, &trusted)
        .unwrap();
    let scene = compositor.prepare(&desktop, &[frame], Some(root)).unwrap();
    let mut output = Sink::new(32, 24);
    compositor.compose(&desktop, scene, &mut output).unwrap();
    for y in 0..24 {
        for x in 0..32 {
            assert_eq!(output.at(x, y), if y < 4 { 0x00a1b2c3 } else { COLORS[0] });
        }
    }
}

#[test]
fn clipped_offscreen_chrome_negative_origin_and_sink_failure_keep_guard_and_credit() {
    let bounds = rect(-5, -5, 32, 24);
    let (mut desktop, _) = Desktop::new(SHELL, ROOT, bounds).unwrap();
    let id = desktop
        .install(
            WindowKind::Files,
            owner(11),
            surface(101),
            rect(-100, -100, 100, 100),
        )
        .unwrap();
    publish(&mut desktop, id);
    assert_eq!(desktop.window(id).unwrap().bounds, bounds);
    let pixels = storage(bounds, COLORS[0], 2);
    let mut compositor = Compositor::new(&desktop, rect(-5, -5, 32, 2)).unwrap();
    assert_eq!(compositor.geometry(&desktop, id).unwrap().outer, bounds);
    let current = frame(&desktop, id, &pixels, 1, 2);
    let scene = compositor.prepare(&desktop, &[current], None).unwrap();
    let mut failed = Sink::new(32, 24);
    failed.fail_after = Some(5);
    assert_eq!(
        compositor.compose(&desktop, scene, &mut failed),
        Err(ComposeError::Sink(ev_graphics::Error::Bounds))
    );
    assert_eq!(compositor.sequence(), 0);
    failed.guards();
    let scene = compositor.prepare(&desktop, &[current], None).unwrap();
    let stale_duplicate = compositor.prepare(&desktop, &[current], None).unwrap();
    let mut output = Sink::new(32, 24);
    compositor.compose(&desktop, scene, &mut output).unwrap();
    let writes = output.writes;
    assert_eq!(
        compositor.compose(&desktop, stale_duplicate, &mut output),
        Err(ComposeError::Stale)
    );
    assert_eq!(output.writes, writes);
    output.guards();
    assert_eq!(output.at(31, 23), COLORS[0]);
}

#[test]
fn modal_requires_its_own_current_owner_surface_and_composes_inside_parent() {
    let (mut desktop, _) = Desktop::new(SHELL, ROOT, rect(0, 0, 96, 72)).unwrap();
    let id = desktop
        .install(
            WindowKind::Files,
            owner(11),
            surface(101),
            rect(10, 20, 60, 40),
        )
        .unwrap();
    let bounds = desktop.window(id).unwrap().bounds;
    let modal = Modal {
        node: 2,
        surface: surface(501),
        bounds: rect(10, 20, 30, 20),
    };
    let dialog = Node {
        local: 2,
        parent: Some(1),
        role: Role::Dialog,
        bounds: modal.bounds,
        ..node(bounds)
    };
    desktop
        .publish_view(
            owner(11),
            id,
            1,
            Tree::new(1, &[node(bounds), dialog]).unwrap(),
        )
        .unwrap();
    desktop.modal(owner(11), id, Some(modal)).unwrap();
    let app = storage(bounds, COLORS[0], 0);
    let dialog = storage(modal.bounds, COLORS[1], 0);
    let mut compositor = Compositor::new(&desktop, rect(0, 0, 96, 8)).unwrap();
    let parent = frame(&desktop, id, &app, 1, 0);
    assert!(matches!(
        compositor.prepare(&desktop, &[parent], None),
        Err(ComposeError::Missing)
    ));
    let header = AppHeader {
        window: id,
        role: FrameRole::Modal { node: 2 },
        owner: owner(11),
        surface: modal.surface,
        model_revision: desktop.revision(),
        view_revision: 1,
        frame: 1,
        raster: raster(modal.bounds, 0),
    };
    let wrong_owner = AppFrame::new(
        AppHeader {
            owner: owner(12),
            ..header
        },
        &dialog,
    )
    .unwrap();
    assert!(matches!(
        compositor.prepare(&desktop, &[parent, wrong_owner], None),
        Err(ComposeError::Owner)
    ));
    let child = AppFrame::new(header, &dialog).unwrap();
    let scene = compositor
        .prepare(&desktop, &[parent, child], None)
        .unwrap();
    let mut output = Sink::new(96, 72);
    compositor.compose(&desktop, scene, &mut output).unwrap();
    assert_eq!(output.at(15, 25), COLORS[1]);
    assert_eq!(output.at(50, 40), COLORS[0]);
    assert_eq!(output.at(5, 15), ev_graphics::BACKGROUND.0);
    output.guards();
}

#[test]
fn older_frames_window_generations_and_changed_root_scope_cannot_reuse_commit_credit() {
    let (mut desktop, mut adapter) = Desktop::new(SHELL, ROOT, rect(0, 0, 32, 24)).unwrap();
    let id = desktop
        .install(
            WindowKind::Files,
            owner(11),
            surface(101),
            rect(0, 0, 32, 24),
        )
        .unwrap();
    publish(&mut desktop, id);
    let region = rect(0, 0, 32, 4);
    let app = storage(desktop.window(id).unwrap().bounds, COLORS[0], 0);
    let trusted = storage(region, 0x00a1b2c3, 0);
    let mut compositor = Compositor::new(&desktop, region).unwrap();
    let root_header = ProtectedHeader {
        owner: ROOT,
        surface: surface(900),
        model_revision: desktop.revision(),
        frame: 3,
        raster: raster(region, 0),
    };
    let root = adapter
        .borrow_protected(&desktop, region, root_header, &trusted)
        .unwrap();
    let current = frame(&desktop, id, &app, 3, 0);
    let scene = compositor
        .prepare(&desktop, &[current], Some(root))
        .unwrap();
    let mut output = Sink::new(32, 24);
    compositor.compose(&desktop, scene, &mut output).unwrap();
    assert!(matches!(
        compositor.prepare(&desktop, &[frame(&desktop, id, &app, 2, 0)], None),
        Err(ComposeError::Frame)
    ));
    let mut stale_header = current.header();
    stale_header.window.generation += 1;
    let wrong_generation = AppFrame::new(stale_header, &app).unwrap();
    assert!(matches!(
        compositor.prepare(&desktop, &[wrong_generation], None),
        Err(ComposeError::Model(Error::Stale))
    ));
    let attention = adapter.attest_attention(&mut desktop, 10).unwrap();
    let action = crate::ActionScope {
        kind: crate::ProtectedKind::OwnerOverride,
        requester: owner(11),
        target: crate::ActionTarget::Window {
            id,
            owner: owner(11),
        },
        rights: crate::Rights::DELEGATE,
    };
    adapter.challenge(&mut desktop, attention, action).unwrap();
    let changed_scope = adapter
        .borrow_protected(
            &desktop,
            region,
            ProtectedHeader {
                model_revision: desktop.revision(),
                ..root_header
            },
            &trusted,
        )
        .unwrap();
    let current = frame(&desktop, id, &app, 3, 0);
    assert!(matches!(
        compositor.prepare(&desktop, &[current], Some(changed_scope)),
        Err(ComposeError::Frame)
    ));
    let fresh = adapter
        .borrow_protected(
            &desktop,
            region,
            ProtectedHeader {
                model_revision: desktop.revision(),
                frame: 4,
                ..root_header
            },
            &trusted,
        )
        .unwrap();
    let scene = compositor
        .prepare(&desktop, &[current], Some(fresh))
        .unwrap();
    adapter.cancel(&mut desktop).unwrap();
    let writes = output.writes;
    assert_eq!(
        compositor.compose(&desktop, scene, &mut output),
        Err(ComposeError::Stale)
    );
    assert_eq!(output.writes, writes);
}
