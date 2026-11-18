//! Bounded pixel composition of separately borrowed, immutable owner surfaces.
//! The actual adapter retains each writer's real read credit/mapping lifetime.
//! These safe borrows never manufacture that credit from a wire descriptor.
use crate::{
    Challenge, Desktop, Error, Modal, Owner, Rect, Surface, WINDOWS, WindowId, WindowKind, next,
};
use ev_graphics::{Canvas, Color, Pixels};

pub const MAX_SURFACES: usize = WINDOWS * 2;
pub const MAX_DIMENSION: u32 = 4096;
const TITLE_HEIGHT: i64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contrast {
    Normal,
    High,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusStyle {
    Outline,
    ThickOutline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preferences {
    pub scale: u8,
    pub contrast: Contrast,
    pub focus: FocusStyle,
}

/// Current producer only. An actual adapter may implement volatile sampling
/// while retaining that one blocked writer/read credit; it must never gather
/// shared Rust borrows from other runnable producers for a full recomposition.
pub trait FramePixels {
    fn raster(&self) -> Raster;
    fn checkpoint(&mut self) -> Result<(), ComposeError>;
    fn sample(&self, x: u32, y: u32) -> Result<Color, ComposeError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncrementalGeometry {
    pub viewport: Rect,
    pub reserved: Rect,
    pub preferences: Preferences,
    pub bounds: Rect,
    pub occluders: [Option<Rect>; 6],
    pub visible: bool,
    /// Only the actual adapter's separately authenticated Root producer sets
    /// this. A header/packet flag alone cannot authorize the protected pass.
    pub protected_plane: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChromeLayer {
    pub bounds: Rect,
    pub kind: WindowKind,
    pub focused: bool,
    pub visible: bool,
    pub z: u8,
}
/// Copy a single credited producer, never reading occluded/padding pixels or
/// any other owner's surface. Successful writes are not a hardware Present.
pub fn copy_incremental<P: Pixels, S: FramePixels>(
    geometry: IncrementalGeometry,
    source: &mut S,
    sink: &mut P,
) -> Result<(), ComposeError> {
    geometry.preferences.valid()?;
    if !geometry.viewport.encloses(geometry.bounds)
        || !geometry.viewport.encloses(geometry.reserved)
        || (geometry.protected_plane && geometry.bounds != geometry.reserved)
        || geometry
            .occluders
            .iter()
            .flatten()
            .any(|clip| !clip.valid())
    {
        return Err(ComposeError::Geometry);
    }
    let scale = usize::from(geometry.preferences.scale);
    if sink.dimensions()
        != (
            geometry.viewport.width as usize * scale,
            geometry.viewport.height as usize * scale,
        )
    {
        return Err(ComposeError::Geometry);
    }
    let raster = source.raster();
    if !raster.fits(geometry.bounds)
        || raster.width == 0
        || raster.height == 0
        || raster.width > MAX_DIMENSION
        || raster.height > MAX_DIMENSION
        || raster.stride_pixels < raster.width
        || raster.stride_pixels > MAX_DIMENSION
        || raster.extent_bytes != u64::from(raster.stride_pixels) * u64::from(raster.height) * 4
    {
        return Err(ComposeError::Extent);
    }
    let mut paint = Painter {
        sink,
        viewport: geometry.viewport,
        reserved: geometry.reserved,
        scale,
    };
    source.checkpoint()?;
    if geometry.visible {
        for y in 0..raster.height {
            source.checkpoint()?;
            for x in 0..raster.width {
                let dx = i64::from(geometry.bounds.x) + i64::from(x);
                let dy = i64::from(geometry.bounds.y) + i64::from(y);
                if paint.allowed(dx, dy, geometry.protected_plane)
                    && !geometry
                        .occluders
                        .iter()
                        .flatten()
                        .any(|clip| clip.contains(dx as i32, dy as i32))
                {
                    paint.pixel(dx, dy, source.sample(x, y)?, geometry.protected_plane)?;
                }
            }
        }
    }
    source.checkpoint()
}
/// Root-authorized geometry changes clear ordinary pixels to a neutral state
/// and draw only compositor-owned chrome. The broker must request fresh Presents
/// from exposed owners; this function cannot sample their runnable surfaces.
pub fn redraw_incremental<P: Pixels>(
    viewport: Rect,
    reserved: Rect,
    preferences: Preferences,
    layers: [Option<ChromeLayer>; WINDOWS],
    sink: &mut P,
) -> Result<(), ComposeError> {
    preferences.valid()?;
    if !viewport.encloses(reserved)
        || layers
            .iter()
            .flatten()
            .any(|layer| !viewport.encloses(layer.bounds) || layer.z >= WINDOWS as u8)
    {
        return Err(ComposeError::Geometry);
    }
    let scale = usize::from(preferences.scale);
    if sink.dimensions()
        != (
            viewport.width as usize * scale,
            viewport.height as usize * scale,
        )
    {
        return Err(ComposeError::Geometry);
    }
    let palette = Palette::new(preferences.contrast);
    let mut paint = Painter {
        sink,
        viewport,
        reserved,
        scale,
    };
    paint.fill(viewport, palette.background, false)?;
    for z in 0..WINDOWS as u8 {
        for layer in layers
            .iter()
            .flatten()
            .filter(|layer| layer.visible && layer.z == z)
        {
            paint.chrome(
                layer.bounds,
                layer.kind,
                layer.focused,
                preferences.focus,
                palette,
                None,
            )?;
        }
    }
    Ok(())
}

pub fn decoration_bounds(
    viewport: Rect,
    bounds: Rect,
    focused: bool,
    focus: FocusStyle,
) -> Result<Rect, ComposeError> {
    if !viewport.encloses(bounds) {
        return Err(ComposeError::Geometry);
    }
    let border = if focused && focus == FocusStyle::ThickOutline {
        2
    } else {
        1
    };
    clipped(
        viewport,
        i64::from(bounds.x) - border,
        i64::from(bounds.y) - TITLE_HEIGHT - border,
        i64::from(bounds.x) + i64::from(bounds.width) + border,
        i64::from(bounds.y) + i64::from(bounds.height) + border,
    )
    .ok_or(ComposeError::Geometry)
}
impl Preferences {
    pub const DEFAULT: Self = Self {
        scale: 1,
        contrast: Contrast::Normal,
        focus: FocusStyle::Outline,
    };
    pub fn valid(self) -> Result<(), Error> {
        if !(1..=4).contains(&self.scale) {
            return Err(Error::Geometry);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    Model(Error),
    Extent,
    Geometry,
    Missing,
    Unexpected,
    Duplicate,
    Owner,
    Surface,
    Revision,
    Frame,
    Protected,
    Stale,
    Sink(ev_graphics::Error),
}
impl From<Error> for ComposeError {
    fn from(error: Error) -> Self {
        Self::Model(error)
    }
}
impl From<ev_graphics::Error> for ComposeError {
    fn from(error: ev_graphics::Error) -> Self {
        Self::Sink(error)
    }
}

/// Exact XRGB u32 extent, including explicitly declared row padding. The high
/// byte has no alpha semantics and is masked before painting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Raster {
    pub width: u32,
    pub height: u32,
    pub stride_pixels: u32,
    pub extent_bytes: u64,
}
impl Raster {
    fn check(self, pixels: &[u32]) -> Result<(), ComposeError> {
        if self.width == 0
            || self.height == 0
            || self.width > MAX_DIMENSION
            || self.height > MAX_DIMENSION
            || self.stride_pixels < self.width
            || self.stride_pixels > MAX_DIMENSION
        {
            return Err(ComposeError::Geometry);
        }
        let expected = u64::from(self.stride_pixels)
            .checked_mul(u64::from(self.height))
            .and_then(|count| count.checked_mul(4))
            .ok_or(ComposeError::Extent)?;
        if self.extent_bytes != expected || (pixels.len() as u64).checked_mul(4) != Some(expected) {
            return Err(ComposeError::Extent);
        }
        Ok(())
    }
    fn fits(self, bounds: Rect) -> bool {
        self.width == bounds.width && self.height == bounds.height
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRole {
    Window,
    Modal { node: u16 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppHeader {
    pub window: WindowId,
    pub role: FrameRole,
    pub owner: Owner,
    pub surface: Surface,
    pub model_revision: u64,
    pub view_revision: u64,
    pub frame: u64,
    pub raster: Raster,
}
#[derive(Clone, Copy, Debug)]
pub struct AppFrame<'a> {
    header: AppHeader,
    pixels: &'a [u32],
}
impl<'a> AppFrame<'a> {
    /// Safe initialized memory only. Actual adapter must authenticate owner,
    /// mapping, frame header, stopped/blocked writer and immutable borrow credit.
    pub fn new(header: AppHeader, pixels: &'a [u32]) -> Result<Self, ComposeError> {
        header.raster.check(pixels)?;
        if !header.owner.valid()
            || !header.surface.valid()
            || header.frame == 0
            || header.frame == u64::MAX
            || header.view_revision == 0
            || header.view_revision == u64::MAX
            || header.model_revision == 0
            || header.model_revision == u64::MAX
        {
            return Err(ComposeError::Frame);
        }
        Ok(Self { header, pixels })
    }
    pub const fn header(&self) -> AppHeader {
        self.header
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectedHeader {
    pub owner: Owner,
    pub surface: Surface,
    pub model_revision: u64,
    pub frame: u64,
    pub raster: Raster,
}
/// No public constructor. Only the held TrustedAdapter issuer can bind this
/// immutable Root surface to the current protected scope and Desktop instance.
#[derive(Clone, Copy, Debug)]
pub struct ProtectedFrame<'a> {
    pub(crate) binding: u64,
    pub(crate) attention: Option<u64>,
    pub(crate) challenge: Option<Challenge>,
    header: ProtectedHeader,
    bounds: Rect,
    pixels: &'a [u32],
}
impl<'a> ProtectedFrame<'a> {
    pub(crate) fn from_adapter(
        binding: u64,
        desktop: &Desktop,
        bounds: Rect,
        header: ProtectedHeader,
        pixels: &'a [u32],
    ) -> Result<Self, ComposeError> {
        header.raster.check(pixels)?;
        if header.owner != desktop.control.owner() || !header.surface.valid() {
            return Err(ComposeError::Owner);
        }
        if header.model_revision != desktop.revision()
            || header.frame == 0
            || header.frame == u64::MAX
        {
            return Err(ComposeError::Revision);
        }
        if !desktop.bounds().encloses(bounds) || !header.raster.fits(bounds) {
            return Err(ComposeError::Geometry);
        }
        Ok(Self {
            binding,
            attention: desktop.control.attention(),
            challenge: desktop.pending_challenge(),
            header,
            bounds,
            pixels,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    id: WindowId,
    surface: Surface,
    view_revision: u64,
    frame: u64,
}
#[derive(Clone, Copy, Debug)]
struct PreparedWindow<'a> {
    id: WindowId,
    owner: Owner,
    bounds: Rect,
    kind: WindowKind,
    focused: bool,
    view_revision: u64,
    window: AppFrame<'a>,
    modal: Option<(Modal, AppFrame<'a>)>,
}
/// Carries only geometry/revisions and independent immutable slices. It neither
/// owns app buffers nor contains a copy of their semantic trees/documents.
pub struct PreparedScene<'a> {
    binding: u64,
    sequence: u64,
    model_revision: u64,
    provider_generation: u64,
    attention: Option<u64>,
    challenge: Option<Challenge>,
    preferences: Preferences,
    viewport: Rect,
    reserved: Rect,
    windows: [Option<PreparedWindow<'a>>; WINDOWS],
    protected: Option<ProtectedFrame<'a>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowCommit {
    pub window: WindowId,
    pub owner: Owner,
    pub view_revision: u64,
    pub frame: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecorationGeometry {
    pub model_revision: u64,
    pub view_revision: u64,
    pub content: Rect,
    pub outer: Rect,
    pub title: Option<Rect>,
    pub modal: Option<Rect>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Composed {
    pub sequence: u64,
    pub model_revision: u64,
    pub provider_generation: u64,
    pub windows: [Option<WindowCommit>; WINDOWS],
    pub protected_frame: Option<u64>,
    pub preferences: Preferences,
}
pub struct Compositor {
    binding: u64,
    sequence: u64,
    reserved: Rect,
    last: [Option<Record>; MAX_SURFACES],
    protected_last: Option<(Surface, u64, Option<u64>, Option<Challenge>)>,
}
impl Compositor {
    pub fn new(desktop: &Desktop, protected_region: Rect) -> Result<Self, ComposeError> {
        if !desktop.bounds().encloses(protected_region)
            || desktop.bounds().width > MAX_DIMENSION
            || desktop.bounds().height > MAX_DIMENSION
        {
            return Err(ComposeError::Geometry);
        }
        Ok(Self {
            binding: desktop.control.binding(),
            sequence: 0,
            reserved: protected_region,
            last: [None; MAX_SURFACES],
            protected_last: None,
        })
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Shell decoration semantics must use this same logical geometry/revision;
    /// app semantic nodes remain in the unscaled content rectangle. Chrome is
    /// Shell-owned and is never sampled from an application.
    pub fn geometry(
        &self,
        desktop: &Desktop,
        id: WindowId,
    ) -> Result<DecorationGeometry, ComposeError> {
        if self.binding != desktop.control.binding() {
            return Err(ComposeError::Owner);
        }
        let window = desktop.window(id)?;
        let border = if desktop.view().focused == Some(id)
            && desktop.preferences().focus == FocusStyle::ThickOutline
        {
            2
        } else {
            1
        };
        let x = i64::from(window.bounds.x);
        let y = i64::from(window.bounds.y);
        let right = x + i64::from(window.bounds.width);
        let bottom = y + i64::from(window.bounds.height);
        let outer = clipped(
            desktop.bounds(),
            x - border,
            y - TITLE_HEIGHT - border,
            right + border,
            bottom + border,
        )
        .ok_or(ComposeError::Geometry)?;
        let title = clipped(
            desktop.bounds(),
            x - border,
            y - TITLE_HEIGHT - border,
            right + border,
            y,
        );
        Ok(DecorationGeometry {
            model_revision: desktop.revision(),
            view_revision: window.view_revision,
            content: window.bounds,
            outer,
            title,
            modal: window.modal.map(|modal| modal.bounds),
        })
    }
    /// Inverse integer scaling for an actual adapter. Reserved Root pixels have
    /// no ordinary-window input destination, regardless of the App underneath.
    pub fn logical_point(
        &self,
        desktop: &Desktop,
        x: usize,
        y: usize,
    ) -> Result<Option<(i32, i32)>, ComposeError> {
        if self.binding != desktop.control.binding() {
            return Err(ComposeError::Owner);
        }
        let scale = usize::from(desktop.preferences().scale);
        let bounds = desktop.bounds();
        if x >= bounds.width as usize * scale || y >= bounds.height as usize * scale {
            return Err(ComposeError::Geometry);
        }
        let x = i64::from(bounds.x) + (x / scale) as i64;
        let y = i64::from(bounds.y) + (y / scale) as i64;
        if self.reserved.contains(x as i32, y as i32) {
            return Ok(None);
        }
        Ok(Some((x as i32, y as i32)))
    }
    fn frame_index(id: WindowId, role: FrameRole) -> usize {
        usize::from(id.slot) * 2 + usize::from(matches!(role, FrameRole::Modal { .. }))
    }
    fn current_frame(&self, frame: AppFrame<'_>) -> Result<(), ComposeError> {
        if let Some(last) = self.last[Self::frame_index(frame.header.window, frame.header.role)]
            && last.id == frame.header.window
            && (last.surface != frame.header.surface
                || frame.header.frame < last.frame
                || (frame.header.frame == last.frame
                    && frame.header.view_revision != last.view_revision))
        {
            return Err(ComposeError::Frame);
        }
        Ok(())
    }
    pub fn prepare<'a>(
        &self,
        desktop: &Desktop,
        frames: &[AppFrame<'a>],
        protected: Option<ProtectedFrame<'a>>,
    ) -> Result<PreparedScene<'a>, ComposeError> {
        if self.binding != desktop.control.binding() {
            return Err(ComposeError::Owner);
        }
        if frames.len() > MAX_SURFACES {
            return Err(ComposeError::Extent);
        }
        let preferences = desktop.preferences();
        preferences.valid()?;
        for (index, frame) in frames.iter().enumerate() {
            if frame.header.model_revision != desktop.revision() {
                return Err(ComposeError::Revision);
            }
            let window = desktop.window(frame.header.window)?;
            if !window.visible {
                return Err(ComposeError::Unexpected);
            }
            if frame.header.owner != window.owner {
                return Err(ComposeError::Owner);
            }
            let (surface, bounds) = match frame.header.role {
                FrameRole::Window => (window.surface, window.bounds),
                FrameRole::Modal { node } => {
                    let modal = window
                        .modal
                        .filter(|modal| modal.node == node)
                        .ok_or(ComposeError::Unexpected)?;
                    (modal.surface, modal.bounds)
                }
            };
            if frame.header.surface != surface {
                return Err(ComposeError::Surface);
            }
            if !frame.header.raster.fits(bounds) {
                return Err(ComposeError::Geometry);
            }
            if frame.header.view_revision != window.view_revision
                || window
                    .tree
                    .as_ref()
                    .is_none_or(|tree| tree.revision() != window.view_revision)
            {
                return Err(ComposeError::Revision);
            }
            if frames[..index].iter().any(|old| {
                old.header.surface == surface
                    || (old.header.window == window.id && old.header.role == frame.header.role)
            }) {
                return Err(ComposeError::Duplicate);
            }
            self.current_frame(*frame)?;
        }
        let mut windows = [None; WINDOWS];
        for (index, id) in desktop.view().windows.iter().flatten().enumerate() {
            let window = desktop.window(*id)?;
            if !window.visible {
                continue;
            }
            let find = |role| {
                frames
                    .iter()
                    .copied()
                    .find(|frame| frame.header.window == *id && frame.header.role == role)
                    .ok_or(ComposeError::Missing)
            };
            let frame = find(FrameRole::Window)?;
            let modal = window
                .modal
                .map(|modal| {
                    find(FrameRole::Modal { node: modal.node }).map(|frame| (modal, frame))
                })
                .transpose()?;
            windows[index] = Some(PreparedWindow {
                id: *id,
                owner: window.owner,
                bounds: window.bounds,
                kind: window.kind,
                focused: desktop.view().focused == Some(*id),
                view_revision: window.view_revision,
                window: frame,
                modal,
            });
        }
        if let Some(frame) = protected {
            if frame.binding != self.binding
                || frame.bounds != self.reserved
                || frame.attention != desktop.control.attention()
                || frame.challenge != desktop.pending_challenge()
                || frame.header.model_revision != desktop.revision()
            {
                return Err(ComposeError::Protected);
            }
            if frames
                .iter()
                .any(|app| app.header.surface == frame.header.surface)
            {
                return Err(ComposeError::Surface);
            }
            if self
                .protected_last
                .is_some_and(|(surface, serial, attention, challenge)| {
                    surface == frame.header.surface
                        && (frame.header.frame < serial
                            || (frame.header.frame == serial
                                && (frame.attention != attention || frame.challenge != challenge)))
                })
            {
                return Err(ComposeError::Frame);
            }
        }
        Ok(PreparedScene {
            binding: self.binding,
            sequence: next(self.sequence)?,
            model_revision: desktop.revision(),
            provider_generation: desktop.provider_generation,
            attention: desktop.control.attention(),
            challenge: desktop.pending_challenge(),
            preferences,
            viewport: desktop.bounds(),
            reserved: self.reserved,
            windows,
            protected,
        })
    }
    /// All metadata is revalidated before the first write. A sink error may
    /// leave partial pixels; no Composed receipt/frame clock is published then.
    pub fn compose<P: Pixels>(
        &mut self,
        desktop: &Desktop,
        scene: PreparedScene<'_>,
        sink: &mut P,
    ) -> Result<Composed, ComposeError> {
        if scene.binding != self.binding
            || scene.sequence != next(self.sequence)?
            || scene.model_revision != desktop.revision()
            || scene.provider_generation != desktop.provider_generation
            || scene.attention != desktop.control.attention()
            || scene.challenge != desktop.pending_challenge()
            || scene.preferences != desktop.preferences()
        {
            return Err(ComposeError::Stale);
        }
        let scale = usize::from(scene.preferences.scale);
        let dimensions = (
            scene.viewport.width as usize * scale,
            scene.viewport.height as usize * scale,
        );
        if sink.dimensions() != dimensions {
            return Err(ComposeError::Geometry);
        }
        let palette = Palette::new(scene.preferences.contrast);
        let mut paint = Painter {
            sink,
            viewport: scene.viewport,
            reserved: scene.reserved,
            scale,
        };
        paint.fill(scene.viewport, palette.background, true)?;
        // The protected region always starts with compositor-owned neutral
        // pixels. No ordinary app or chrome pass can write it, even without an overlay.
        paint.fill(scene.reserved, palette.protected, true)?;
        for window in scene.windows.iter().flatten() {
            paint.chrome(
                window.bounds,
                window.kind,
                window.focused,
                scene.preferences.focus,
                palette,
                None,
            )?;
            paint.raster(
                window.bounds,
                window.window.header.raster,
                window.window.pixels,
                false,
            )?;
            if let Some((modal, frame)) = window.modal {
                paint.chrome(
                    modal.bounds,
                    window.kind,
                    window.focused,
                    scene.preferences.focus,
                    palette,
                    Some(window.bounds),
                )?;
                paint.raster(modal.bounds, frame.header.raster, frame.pixels, false)?;
            }
        }
        if let Some(frame) = scene.protected {
            paint.raster(frame.bounds, frame.header.raster, frame.pixels, true)?;
        }
        let mut commits = [None; WINDOWS];
        for (index, window) in scene.windows.iter().enumerate() {
            let Some(window) = window else {
                continue;
            };
            for frame in [Some(window.window), window.modal.map(|(_, frame)| frame)]
                .into_iter()
                .flatten()
            {
                self.last[Self::frame_index(window.id, frame.header.role)] = Some(Record {
                    id: window.id,
                    surface: frame.header.surface,
                    view_revision: window.view_revision,
                    frame: frame.header.frame,
                });
            }
            commits[index] = Some(WindowCommit {
                window: window.id,
                owner: window.owner,
                view_revision: window.view_revision,
                frame: window.window.header.frame,
            });
        }
        if let Some(frame) = scene.protected {
            self.protected_last = Some((
                frame.header.surface,
                frame.header.frame,
                frame.attention,
                frame.challenge,
            ));
        }
        self.sequence = scene.sequence;
        Ok(Composed {
            sequence: scene.sequence,
            model_revision: scene.model_revision,
            provider_generation: scene.provider_generation,
            windows: commits,
            protected_frame: scene.protected.map(|frame| frame.header.frame),
            preferences: scene.preferences,
        })
    }
}

#[derive(Clone, Copy)]
struct Palette {
    background: Color,
    chrome: Color,
    focus: Color,
    text: Color,
    protected: Color,
}
impl Palette {
    fn new(contrast: Contrast) -> Self {
        match contrast {
            Contrast::Normal => Self {
                background: ev_graphics::BACKGROUND,
                chrome: ev_graphics::PANEL,
                focus: ev_graphics::ACCENT,
                text: ev_graphics::INK,
                protected: Color::rgb(8, 12, 18),
            },
            Contrast::High => Self {
                background: Color(0),
                chrome: Color(0),
                focus: Color(0xffffff),
                text: Color(0xffffff),
                protected: Color(0x161616),
            },
        }
    }
}
struct Painter<'a, P: Pixels> {
    sink: &'a mut P,
    viewport: Rect,
    reserved: Rect,
    scale: usize,
}
impl<P: Pixels> Painter<'_, P> {
    fn allowed(&self, x: i64, y: i64, protected: bool) -> bool {
        x >= i64::from(self.viewport.x)
            && y >= i64::from(self.viewport.y)
            && x < i64::from(self.viewport.x) + i64::from(self.viewport.width)
            && y < i64::from(self.viewport.y) + i64::from(self.viewport.height)
            && (protected || !self.reserved.contains(x as i32, y as i32))
    }
    fn pixel(&mut self, x: i64, y: i64, color: Color, protected: bool) -> Result<(), ComposeError> {
        if !self.allowed(x, y, protected) {
            return Ok(());
        }
        let px = (x - i64::from(self.viewport.x)) as usize * self.scale;
        let py = (y - i64::from(self.viewport.y)) as usize * self.scale;
        let color = Color(color.0 & 0x00ff_ffff);
        for dy in 0..self.scale {
            for dx in 0..self.scale {
                self.sink.write(px + dx, py + dy, color)?;
            }
        }
        Ok(())
    }
    fn box_fill(
        &mut self,
        bounds: [i64; 4],
        color: Color,
        protected: bool,
        clip: Option<Rect>,
    ) -> Result<(), ComposeError> {
        let [left, top, right, bottom] = bounds;
        let clip = clip.unwrap_or(self.viewport);
        let left = left.max(i64::from(self.viewport.x)).max(i64::from(clip.x));
        let top = top.max(i64::from(self.viewport.y)).max(i64::from(clip.y));
        let right = right
            .min(i64::from(self.viewport.x) + i64::from(self.viewport.width))
            .min(i64::from(clip.x) + i64::from(clip.width));
        let bottom = bottom
            .min(i64::from(self.viewport.y) + i64::from(self.viewport.height))
            .min(i64::from(clip.y) + i64::from(clip.height));
        for y in top..bottom {
            for x in left..right {
                self.pixel(x, y, color, protected)?;
            }
        }
        Ok(())
    }
    fn fill(&mut self, bounds: Rect, color: Color, protected: bool) -> Result<(), ComposeError> {
        self.box_fill(
            [
                i64::from(bounds.x),
                i64::from(bounds.y),
                i64::from(bounds.x) + i64::from(bounds.width),
                i64::from(bounds.y) + i64::from(bounds.height),
            ],
            color,
            protected,
            None,
        )
    }
    fn raster(
        &mut self,
        bounds: Rect,
        raster: Raster,
        pixels: &[u32],
        protected: bool,
    ) -> Result<(), ComposeError> {
        for y in 0..raster.height {
            for x in 0..raster.width {
                let dx = i64::from(bounds.x) + i64::from(x);
                let dy = i64::from(bounds.y) + i64::from(y);
                if self.allowed(dx, dy, protected) {
                    let offset = y as usize * raster.stride_pixels as usize + x as usize;
                    self.pixel(dx, dy, Color(pixels[offset]), protected)?;
                }
            }
        }
        Ok(())
    }
    fn chrome(
        &mut self,
        bounds: Rect,
        kind: WindowKind,
        focused: bool,
        focus: FocusStyle,
        palette: Palette,
        clip: Option<Rect>,
    ) -> Result<(), ComposeError> {
        let border = if focused && focus == FocusStyle::ThickOutline {
            2
        } else {
            1
        };
        let x = i64::from(bounds.x);
        let y = i64::from(bounds.y);
        let right = x + i64::from(bounds.width);
        let bottom = y + i64::from(bounds.height);
        let color = if focused {
            palette.focus
        } else {
            palette.chrome
        };
        self.box_fill(
            [x - border, y - TITLE_HEIGHT - border, right + border, y],
            color,
            false,
            clip,
        )?;
        self.box_fill([x - border, y, x, bottom + border], color, false, clip)?;
        self.box_fill(
            [right, y, right + border, bottom + border],
            color,
            false,
            clip,
        )?;
        self.box_fill([x, bottom, right, bottom + border], color, false, clip)?;
        let label: &[u8] = if clip.is_some() {
            b"Dialog"
        } else {
            match kind {
                WindowKind::Files => b"Files",
                WindowKind::EditorOne => b"Editor 1",
                WindowKind::EditorTwo => b"Editor 2",
                WindowKind::Inspector => b"Inspector",
            }
        };
        let title_width = bounds.width as usize;
        let mut local = ChromePixels {
            paint: self,
            x,
            y: y - TITLE_HEIGHT,
            width: title_width,
            clip,
        };
        let text_width = title_width.saturating_sub(10) / 6;
        let text = &label[..label.len().min(text_width)];
        let text_color = if focused {
            if palette.focus == ev_graphics::ACCENT {
                ev_graphics::BACKGROUND
            } else {
                Color(0)
            }
        } else {
            palette.text
        };
        if title_width >= 6 {
            Canvas::new(&mut local).text_exact(
                0,
                1,
                if focused { b">" } else { b" " },
                text_color,
            )?;
        }
        if !text.is_empty() {
            Canvas::new(&mut local).text_exact(8, 1, text, text_color)?;
        }
        Ok(())
    }
}

fn clipped(viewport: Rect, left: i64, top: i64, right: i64, bottom: i64) -> Option<Rect> {
    let left = left.max(i64::from(viewport.x));
    let top = top.max(i64::from(viewport.y));
    let right = right.min(i64::from(viewport.x) + i64::from(viewport.width));
    let bottom = bottom.min(i64::from(viewport.y) + i64::from(viewport.height));
    if right <= left || bottom <= top {
        return None;
    }
    Some(Rect {
        x: left as i32,
        y: top as i32,
        width: (right - left) as u32,
        height: (bottom - top) as u32,
    })
}
struct ChromePixels<'a, 'b, P: Pixels> {
    paint: &'a mut Painter<'b, P>,
    x: i64,
    y: i64,
    width: usize,
    clip: Option<Rect>,
}
impl<P: Pixels> Pixels for ChromePixels<'_, '_, P> {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, TITLE_HEIGHT as usize)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), ev_graphics::Error> {
        if x >= self.width || y >= TITLE_HEIGHT as usize {
            return Err(ev_graphics::Error::Bounds);
        }
        let dx = self.x + x as i64;
        let dy = self.y + y as i64;
        if self.clip.is_some_and(|clip| {
            dx < i64::from(clip.x)
                || dy < i64::from(clip.y)
                || dx >= i64::from(clip.x) + i64::from(clip.width)
                || dy >= i64::from(clip.y) + i64::from(clip.height)
        }) {
            return Ok(());
        }
        self.paint
            .pixel(dx, dy, color, false)
            .map_err(|error| match error {
                ComposeError::Sink(error) => error,
                _ => ev_graphics::Error::Bounds,
            })
    }
}

#[cfg(test)]
mod tests;
