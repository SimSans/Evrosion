//! Actual native M8 Display policy and incremental painting. Only one currently
//! blocked producer is sampled; other surfaces contribute geometry, never bytes.
#![no_std]
#![forbid(unsafe_code)]
use ev_graphics::Pixels;
use ev_userspace_contract::root_v5::{
    display_control::{self as control, Command, Envelope, Slot, Window},
    surface::Header,
};
use ev_workspace_shell::{
    Rect, WindowKind,
    composition::{
        self, ChromeLayer, ComposeError, Contrast, FocusStyle, FramePixels, IncrementalGeometry,
        Preferences,
    },
};

pub const VIEWPORT: Rect = Rect {
    x: 0,
    y: 0,
    width: 640,
    height: 480,
};
pub const PROTECTED: Rect = Rect {
    x: 0,
    y: 0,
    width: 640,
    height: 80,
};
pub const SHELL: Rect = Rect {
    x: 0,
    y: 462,
    width: 640,
    height: 18,
};
pub const READY: [u8; 8] = *b"EVDPRDY5";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Origin,
    Unknown,
    Codec,
    Transaction,
    Stale,
    Identity,
    Duplicate,
    Geometry,
    Header,
    Output,
    Missing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub process: u64,
    pub thread: u64,
    pub incarnation: u64,
    pub call_epoch: u64,
    pub serial: u64,
    pub endpoint: u64,
    pub deadline: u64,
    pub status: u64,
}
/// Scalar result of an actual ServingOrigin field7 query. The native boundary
/// supplies this only for the retained RECEIVE handle and full serving nonce;
/// Kernel independently authenticates that exact call on every query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditStatus {
    pub status: u64,
    pub value: u64,
    pub capability: u64,
    pub serial: u64,
}
impl Origin {
    pub fn validate(self, received_nonce: u64) -> Result<(), Error> {
        if [
            self.process,
            self.thread,
            self.call_epoch,
            self.serial,
            self.endpoint,
            self.deadline,
        ]
        .into_iter()
        .any(|v| matches!(v, 0 | u64::MAX))
            || self.serial != received_nonce
            || self.incarnation == u64::MAX
            || self.status != 0
        {
            return Err(Error::Origin);
        }
        Ok(())
    }
    fn same_call(self, other: Self) -> bool {
        self == other
    }
    /// Fields0..6 are immutable for an accepted call. Field7 remains a live
    /// cancellation/expiry/peer check, bounded by its original deadline. This
    /// does not replace full origin capture before and after source access.
    pub fn live_checkpoint(self, reply: CreditStatus, now: u64) -> bool {
        now < self.deadline && self.kernel_checkpoint(reply)
    }
    /// Result of the actual authenticated Kernel field7 query. Kernel checks
    /// its current time against the original cut even before expiry is swept.
    /// This samples one bounded row, not an execution lease past the deadline;
    /// the adapter retains its full before/after origin and final ACK checks.
    pub fn kernel_checkpoint(self, reply: CreditStatus) -> bool {
        self.status == 0
            && self.deadline != 0
            && self.deadline != u64::MAX
            && reply
                == (CreditStatus {
                    status: 0,
                    value: 0,
                    capability: 0,
                    serial: 0,
                })
    }
}
/// The actor derives this issuer only from its actual validated role10 handle.
/// No ordinary Present or packet field constructs a control origin.
pub struct ControlAuthority {
    receiver: u64,
}
pub struct ControlOrigin {
    origin: Origin,
}
impl ControlAuthority {
    pub fn from_validated_bootstrap(
        profile: &ev_userspace_contract::root_v5::child::Profile<'_>,
    ) -> Result<Self, Error> {
        if profile.child() != ev_userspace_contract::root_v5::graph::Child::Display {
            return Err(Error::Identity);
        }
        Ok(Self {
            receiver: profile.handle(10).ok_or(Error::Identity)?,
        })
    }
    pub fn capture(
        &self,
        actual_received_on: u64,
        received_nonce: u64,
        origin: Origin,
    ) -> Result<ControlOrigin, Error> {
        origin.validate(received_nonce)?;
        if self.receiver != actual_received_on {
            return Err(Error::Origin);
        }
        Ok(ControlOrigin { origin })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub window: Window,
    pub last_frame: u64,
    pub last_view: u64,
    pub ready: bool,
    pub presentation_epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scene {
    pub model_revision: u64,
    pub preferences: control::Preferences,
    pub slots: [Option<Binding>; 6],
}
impl Scene {
    pub const fn empty() -> Self {
        Self {
            model_revision: 0,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
            slots: [None; 6],
        }
    }
    pub fn preferences(&self) -> Preferences {
        Preferences {
            scale: self.preferences.scale,
            contrast: if self.preferences.high_contrast {
                Contrast::High
            } else {
                Contrast::Normal
            },
            focus: if self.preferences.thick_focus {
                FocusStyle::ThickOutline
            } else {
                FocusStyle::Outline
            },
        }
    }
    pub fn registered_mask(&self) -> u8 {
        self.slots.iter().enumerate().fold(0, |mask, (i, slot)| {
            mask | if slot.is_some() { 1 << i } else { 0 }
        })
    }
    pub fn ready_mask(&self) -> u8 {
        self.slots.iter().enumerate().fold(0, |mask, (i, slot)| {
            mask | if slot.is_some_and(|b| b.ready && b.window.visible) {
                1 << i
            } else {
                0
            }
        })
    }
    pub fn repaint_mask(&self) -> u8 {
        self.slots.iter().enumerate().fold(0, |mask, (i, slot)| {
            mask | if slot.is_some_and(|b| b.window.visible) {
                1 << i
            } else {
                0
            }
        })
    }
    pub fn layers(&self) -> [Option<ChromeLayer>; 4] {
        core::array::from_fn(|i| {
            self.slots[i].map(|binding| ChromeLayer {
                bounds: to_rect(binding.window.bounds),
                kind: match i {
                    0 => WindowKind::Files,
                    1 => WindowKind::EditorOne,
                    2 => WindowKind::EditorTwo,
                    _ => WindowKind::Inspector,
                },
                focused: binding.window.focused,
                visible: binding.window.visible,
                z: binding.window.z,
            })
        })
    }
}
#[derive(Clone, Copy)]
struct Pending {
    transaction: u64,
    origin: Origin,
    scene: Scene,
}
pub struct State {
    scene: Scene,
    pending: Option<Pending>,
    last_request: u64,
    last_transaction: u64,
    max_scale: u8,
    cursor: Option<(u16, u16)>,
    presentation_epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlEffect {
    pub reply: u64,
    pub redraw: bool,
    pub cursor: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentPlan {
    slot: Slot,
    origin: Origin,
    header: Header,
    model_revision: u64,
    geometry: IncrementalGeometry,
}
impl PresentPlan {
    pub const fn slot(&self) -> Slot {
        self.slot
    }
    pub const fn header(&self) -> Header {
        self.header
    }
    pub const fn geometry(&self) -> IncrementalGeometry {
        self.geometry
    }
}
impl State {
    pub fn new(max_scale: u8) -> Result<Self, Error> {
        if !(1..=4).contains(&max_scale) {
            return Err(Error::Geometry);
        }
        Ok(Self {
            scene: Scene::empty(),
            pending: None,
            last_request: 0,
            last_transaction: 0,
            max_scale,
            cursor: None,
            presentation_epoch: 1,
        })
    }
    pub const fn scene(&self) -> &Scene {
        &self.scene
    }
    pub const fn cursor(&self) -> Option<(u16, u16)> {
        self.cursor
    }
    fn advance_presentation(&mut self) -> Result<(), Error> {
        self.presentation_epoch = self
            .presentation_epoch
            .checked_add(1)
            .filter(|epoch| *epoch != u64::MAX)
            .ok_or(Error::Stale)?;
        Ok(())
    }
    pub fn control(
        &mut self,
        source: ControlOrigin,
        envelope: Envelope,
    ) -> Result<ControlEffect, Error> {
        source.origin.validate(source.origin.serial)?;
        envelope.encode().map_err(|_| Error::Codec)?;
        if envelope.request <= self.last_request {
            return Err(Error::Stale);
        }
        let origin = source.origin;
        let mut redraw = false;
        let mut cursor = false;
        let value = match envelope.command {
            Command::Begin {
                transaction,
                model_revision,
                preferences,
            } => {
                if self.pending.is_some()
                    || transaction <= self.last_transaction
                    || model_revision <= self.scene.model_revision
                    || preferences.scale > self.max_scale
                {
                    return Err(Error::Transaction);
                }
                let mut scene = self.scene;
                scene.model_revision = model_revision;
                scene.preferences = preferences;
                for binding in scene.slots.iter_mut().flatten() {
                    binding.ready = false;
                }
                self.pending = Some(Pending {
                    transaction,
                    origin,
                    scene,
                });
                self.last_transaction = transaction;
                control::reply(0).unwrap()
            }
            Command::Register {
                transaction,
                window,
            } => {
                let pending = self
                    .pending
                    .as_mut()
                    .filter(|p| {
                        p.transaction == transaction
                            && p.origin.process == origin.process
                            && p.origin.thread == origin.thread
                    })
                    .ok_or(Error::Transaction)?;
                if window.registration.surface_object != window.slot.source().selector()
                    || window.registration.surface_generation != window.registration.process
                    || (window.slot == Slot::ProtectedRoot
                        && (window.registration.process != origin.process
                            || window.registration.thread != origin.thread))
                {
                    return Err(Error::Identity);
                }
                if let Some(old) = pending.scene.slots[window.slot.index()]
                    && window.registration.sequence <= old.window.registration.sequence
                {
                    return Err(Error::Stale);
                }
                let last = self.scene.slots[window.slot.index()]
                    .filter(|old| same_owner(old.window, window));
                pending.scene.slots[window.slot.index()] = Some(Binding {
                    window,
                    last_frame: last.map_or(0, |b| b.last_frame),
                    last_view: last.map_or(0, |b| b.last_view),
                    ready: false,
                    presentation_epoch: self.presentation_epoch,
                });
                control::reply(0).unwrap()
            }
            Command::Remove { transaction, slot } => {
                let pending = self
                    .pending
                    .as_mut()
                    .filter(|p| {
                        p.transaction == transaction
                            && p.origin.process == origin.process
                            && p.origin.thread == origin.thread
                    })
                    .ok_or(Error::Transaction)?;
                pending.scene.slots[slot.index()] = None;
                control::reply(0).unwrap()
            }
            Command::Commit { transaction } => {
                let pending = self
                    .pending
                    .filter(|p| {
                        p.transaction == transaction
                            && p.origin.process == origin.process
                            && p.origin.thread == origin.thread
                    })
                    .ok_or(Error::Transaction)?;
                validate_scene(&pending.scene)?;
                self.advance_presentation()?;
                self.scene = pending.scene;
                for binding in self.scene.slots.iter_mut().flatten() {
                    binding.presentation_epoch = self.presentation_epoch;
                }
                self.pending = None;
                redraw = true;
                control::reply(self.scene.repaint_mask()).unwrap()
            }
            Command::Abort { transaction } => {
                if self.pending.is_none_or(|p| {
                    p.transaction != transaction
                        || p.origin.process != origin.process
                        || p.origin.thread != origin.thread
                }) {
                    return Err(Error::Transaction);
                }
                self.pending = None;
                control::reply(0).unwrap()
            }
            Command::Inspect { slot, field } => {
                let binding = self.scene.slots[slot.index()];
                match field {
                    0 => {
                        u64::from(self.scene.ready_mask())
                            | u64::from(self.scene.registered_mask()) << 8
                    }
                    1 => self.scene.model_revision,
                    2 => binding.map_or(0, |b| b.last_frame),
                    3 => binding.map_or(0, |b| b.last_view),
                    4 => binding.map_or(0, |b| b.window.registration.mapping_epoch),
                    5 => u64::from(self.max_scale),
                    6 => binding.map_or(0, |b| b.presentation_epoch),
                    _ => return Err(Error::Codec),
                }
            }
            Command::Cursor { x, y, visible } => {
                if self.pending.is_some() {
                    return Err(Error::Transaction);
                }
                self.cursor = if visible { Some((x, y)) } else { None };
                cursor = true;
                control::reply(0).unwrap()
            }
        };
        self.last_request = envelope.request;
        Ok(ControlEffect {
            reply: value,
            redraw,
            cursor,
        })
    }
    /// Resolve captured caller BEFORE reading any surface header/pixel. The
    /// ordinary request body is only a full frame counter, never a source slot.
    pub fn resolve(&self, origin: Origin, received_nonce: u64) -> Result<Slot, Error> {
        origin.validate(received_nonce)?;
        if self.pending.is_some() {
            return Err(Error::Transaction);
        }
        self.scene
            .slots
            .iter()
            .enumerate()
            .find(|(_, binding)| binding.is_some_and(|b| owner_matches(b.window, origin)))
            .map(|(i, _)| control::SLOTS[i])
            .ok_or(Error::Unknown)
    }
    pub fn prepare(
        &self,
        origin: Origin,
        received_nonce: u64,
        requested_frame: u64,
        slot: Slot,
        header: Header,
    ) -> Result<PresentPlan, Error> {
        if self.resolve(origin, received_nonce)? != slot {
            return Err(Error::Origin);
        }
        let binding = self.scene.slots[slot.index()].ok_or(Error::Unknown)?;
        let window = binding.window;
        if self.pending.is_some() {
            return Err(Error::Transaction);
        }
        header.encode().map_err(|_| Error::Header)?;
        if requested_frame == 0
            || requested_frame == u64::MAX
            || header.frame != requested_frame
            || header.frame <= binding.last_frame
            || header.model_revision != self.scene.model_revision
            || header.view_revision < binding.last_view
            || header.view_revision < window.view_revision
            || (window.strict_view && header.view_revision != window.view_revision)
            || header.width != window.bounds.width
            || header.height != window.bounds.height
            || !window.registration.matches(
                header,
                origin.process,
                origin.thread,
                if slot == Slot::ProtectedRoot && origin.incarnation == 0 {
                    window.registration.incarnation
                } else {
                    origin.incarnation
                },
            )
        {
            return Err(Error::Stale);
        }
        let mut occluders = [None; 6];
        if slot.index() < 4 {
            let mut at = 0;
            for other in self.scene.slots[..4]
                .iter()
                .flatten()
                .filter(|b| b.window.visible && b.window.z > window.z)
            {
                occluders[at] = Some(
                    composition::decoration_bounds(
                        VIEWPORT,
                        to_rect(other.window.bounds),
                        other.window.focused,
                        self.scene.preferences().focus,
                    )
                    .map_err(|_| Error::Geometry)?,
                );
                at += 1;
            }
            if self.scene.slots[Slot::Shell.index()].is_some_and(|b| b.window.visible) {
                occluders[at] = Some(SHELL);
            }
        }
        Ok(PresentPlan {
            slot,
            origin,
            header,
            model_revision: self.scene.model_revision,
            geometry: IncrementalGeometry {
                viewport: VIEWPORT,
                reserved: PROTECTED,
                preferences: self.scene.preferences(),
                bounds: to_rect(window.bounds),
                occluders,
                visible: window.visible,
                protected_plane: slot == Slot::ProtectedRoot,
            },
        })
    }
    pub fn commit_present(&mut self, plan: PresentPlan, origin: Origin) -> Result<u64, Error> {
        if !plan.origin.same_call(origin)
            || self.pending.is_some()
            || self.scene.model_revision != plan.model_revision
        {
            return Err(Error::Stale);
        }
        let checked = self.prepare(
            origin,
            origin.serial,
            plan.header.frame,
            plan.slot,
            plan.header,
        )?;
        if checked != plan {
            return Err(Error::Stale);
        }
        self.advance_presentation()?;
        let binding = self.scene.slots[plan.slot.index()]
            .as_mut()
            .ok_or(Error::Unknown)?;
        binding.last_frame = plan.header.frame;
        binding.last_view = plan.header.view_revision;
        binding.ready = binding.window.visible;
        binding.presentation_epoch = self.presentation_epoch;
        Ok(plan.header.frame)
    }
    pub fn redraw<P: Pixels>(&self, sink: &mut P) -> Result<(), ComposeError> {
        composition::redraw_incremental(
            VIEWPORT,
            PROTECTED,
            self.scene.preferences(),
            self.scene.layers(),
            sink,
        )
    }
    pub fn paint<P: Pixels, S: FramePixels>(
        &mut self,
        plan: PresentPlan,
        source: &mut S,
        sink: &mut P,
    ) -> Result<(), ComposeError> {
        if self.scene.model_revision != plan.model_revision || self.pending.is_some() {
            return Err(ComposeError::Stale);
        }
        if self
            .prepare(
                plan.origin,
                plan.origin.serial,
                plan.header.frame,
                plan.slot,
                plan.header,
            )
            .map_err(|_| ComposeError::Stale)?
            != plan
        {
            return Err(ComposeError::Stale);
        }
        // Incremental scanout cannot restore a previous frame after cancelled
        // copy. Once valid copying starts, the old view is no longer evidence
        // of current complete pixels. Only commit_present restores readiness.
        self.advance_presentation()
            .map_err(|_| ComposeError::Stale)?;
        let binding = self.scene.slots[plan.slot.index()]
            .as_mut()
            .ok_or(ComposeError::Stale)?;
        binding.ready = false;
        binding.presentation_epoch = self.presentation_epoch;
        composition::copy_incremental(plan.geometry, source, sink)
    }
}
fn same_owner(a: Window, b: Window) -> bool {
    let a = a.registration;
    let b = b.registration;
    (
        a.process,
        a.thread,
        a.incarnation,
        a.surface_object,
        a.surface_generation,
        a.mapping_epoch,
    ) == (
        b.process,
        b.thread,
        b.incarnation,
        b.surface_object,
        b.surface_generation,
        b.mapping_epoch,
    )
}
fn owner_matches(window: Window, origin: Origin) -> bool {
    let r = window.registration;
    r.process == origin.process
        && r.thread == origin.thread
        && (r.incarnation == origin.incarnation
            || (window.slot == Slot::ProtectedRoot && origin.incarnation == 0))
}
fn validate_scene(scene: &Scene) -> Result<(), Error> {
    let mut focused = 0;
    for (i, binding) in scene.slots.iter().enumerate() {
        let Some(binding) = binding else {
            continue;
        };
        binding.window.valid().map_err(|_| Error::Geometry)?;
        if binding.window.slot.index() != i {
            return Err(Error::Identity);
        }
        if binding.window.focused && binding.window.visible {
            focused += 1;
        }
        for old in scene.slots[..i].iter().flatten() {
            if old.window.registration.process == binding.window.registration.process
                || (old.window.visible
                    && binding.window.visible
                    && i < 4
                    && old.window.slot.index() < 4
                    && old.window.z == binding.window.z)
            {
                return Err(Error::Duplicate);
            }
        }
    }
    if focused > 1 {
        return Err(Error::Duplicate);
    }
    Ok(())
}
fn to_rect(bounds: control::Bounds) -> Rect {
    Rect {
        x: bounds.x,
        y: bounds.y,
        width: bounds.width,
        height: bounds.height,
    }
}

#[cfg(test)]
mod tests;
