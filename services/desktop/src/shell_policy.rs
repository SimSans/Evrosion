//! Actual adapters must authenticate Root/Input endpoints, retain the requester
//! incarnation, wait for real Present completion, and obtain the real Input
//! barrier. This reducer itself issues no syscall or authority. Its selection
//! request must still pass the separate current-object/live-recipient handoff.
use crate::protocol::CursorControl;
use ev_graphics::shell::{FileChoice, Screen};
use ev_input::{BarrierReply, Key, KeyEvent, protocol::FreshGate, text::TextEvent};
use ev_input::{
    SessionBarrierReply,
    pointer::{FreshGate as PointerGate, LEFT, PointerEvent, PositionEvent},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Stale,
    Counter,
    Input,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Render {
    pub frame: u32,
    pub screen: Screen,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    #[cfg(feature = "native-owner-ui")]
    Owner(crate::owner_ui::Request),
    Launch,
    Forward(KeyEvent),
    Text(TextEvent),
    Pointer(PositionEvent),
    Select {
        request: u32,
        app_epoch: u64,
        file: FileChoice,
    },
    Cancel {
        request: u32,
    },
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub render: Option<Render>,
    pub command: Option<Command>,
    pub barrier_after_frame: Option<u32>,
    pub cursor: Option<CursorControl>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootEvent {
    #[cfg(feature = "native-owner-ui")]
    Connection(crate::owner_ui::Presentation),
    AppStarted {
        epoch: u64,
    },
    AppRestored {
        epoch: u64,
    },
    AppStopped {
        epoch: u64,
    },
    PickFile {
        request: u32,
        app_epoch: u64,
    },
    FileDelivered {
        request: u32,
        app_epoch: u64,
    },
    FileRefused {
        request: u32,
        app_epoch: u64,
    },
    InputRestarted,
    LaunchRefused,
    OwnerFilePending {
        request: u32,
        app_epoch: u64,
    },
    OwnerFileDelivered {
        request: u32,
        app_epoch: u64,
    },
    OwnerFileRefused {
        request: u32,
        app_epoch: u64,
    },
    ManagedFilePending {
        request: u32,
        app_epoch: u64,
    },
    ManagedFileDelivered {
        request: u32,
        app_epoch: u64,
    },
    ManagedFileRefused {
        request: u32,
        app_epoch: u64,
    },
    OwnerActionPending {
        serial: u32,
        app_epoch: u64,
    },
    OwnerActionDone {
        serial: u32,
        app_epoch: u64,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    OwnerFile,
    ManagedFile,
    OwnerAction,
}
struct Managed {
    kind: PendingKind,
    request: u32,
    app_epoch: u64,
}
struct Picker {
    request: u32,
    app_epoch: u64,
    selected: FileChoice,
    gate: Option<FreshGate>,
    awaiting_display: Option<u32>,
    awaiting_barrier: Option<u32>,
    submitted: bool,
}
pub struct Policy {
    #[cfg(feature = "native-owner-ui")]
    owner_enabled: bool,
    #[cfg(feature = "native-owner-ui")]
    owner_wanted: bool,
    #[cfg(feature = "native-owner-ui")]
    owner: Option<crate::owner_ui::Policy>,
    screen: Screen,
    frame: u32,
    last_key: u32,
    last_request: u32,
    app_epoch: Option<u64>,
    launching: bool,
    focused_app: bool,
    picker: Option<Picker>,
    managed: Option<Managed>,
    pointer_enabled: bool,
    pointer_gate: Option<PointerGate>,
    pointer_display: Option<u32>,
    pointer_barrier: Option<u32>,
    pointer_x: u16,
    pointer_y: u8,
    cursor_revision: u32,
}
impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}
impl Policy {
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "native-owner-ui")]
            owner_enabled: false,
            #[cfg(feature = "native-owner-ui")]
            owner_wanted: false,
            #[cfg(feature = "native-owner-ui")]
            owner: None,
            screen: Screen::Home,
            frame: 0,
            last_key: 0,
            last_request: 0,
            app_epoch: None,
            launching: false,
            focused_app: false,
            picker: None,
            managed: None,
            pointer_enabled: false,
            pointer_gate: None,
            pointer_display: None,
            pointer_barrier: None,
            pointer_x: 160,
            pointer_y: 100,
            cursor_revision: 0,
        }
    }
    pub fn with_pointer() -> Self {
        Self {
            pointer_enabled: true,
            ..Self::new()
        }
    }
    #[cfg(feature = "native-owner-ui")]
    pub fn with_owner_ui() -> Self {
        Self {
            owner_enabled: true,
            ..Self::with_pointer()
        }
    }
    #[cfg(feature = "native-owner-ui")]
    fn owner_open(&mut self) -> Result<Effects, Error> {
        if !self.owner_enabled
            || self.owner_wanted
            || self.owner.is_some()
            || self.picker.is_some()
            || self.managed.is_some()
            || self.launching
        {
            return Ok(Effects::default());
        }
        self.owner_wanted = true;
        Ok(Effects {
            command: Some(Command::Owner(crate::owner_ui::Request {
                operation: crate::owner_ui::Operation::Open,
                revision: 0,
            })),
            ..Effects::default()
        })
    }
    #[cfg(feature = "native-owner-ui")]
    fn owner_request(
        &mut self,
        request: Option<crate::owner_ui::Request>,
    ) -> Result<Effects, Error> {
        let Some(request) = request else {
            return Ok(Effects::default());
        };
        let mut effects = Effects {
            command: Some(Command::Owner(request)),
            ..Effects::default()
        };
        if matches!(
            request.operation,
            crate::owner_ui::Operation::Back | crate::owner_ui::Operation::Cancel
        ) {
            self.owner = None;
            self.owner_wanted = false;
            self.focused_app = false;
            let frame = self.render(Screen::Home)?;
            effects.render = Some(frame);
            let published = self.publish(frame);
            effects.cursor = published.cursor;
        }
        Ok(effects)
    }
    pub fn screen(&self) -> Screen {
        self.screen
    }
    /// A footer-only busy redraw preserves focus/modal context and buffered
    /// input, but cannot establish a new input gate. Once that FIFO drains, the
    /// adapter requests a separate actual Present/barrier before new input.
    pub fn delivery_redraw(&mut self, rearm: bool) -> Result<Effects, Error> {
        let render = self.render(self.screen)?;
        let effects = self.publish(render);
        if let Some(p) = self.picker.as_mut() {
            p.gate = None;
            p.awaiting_display = (rearm && !p.submitted).then_some(render.frame);
            p.awaiting_barrier = None;
        }
        self.pointer_gate = None;
        self.pointer_display = (rearm && self.pointer_enabled).then_some(render.frame);
        self.pointer_barrier = None;
        Ok(effects)
    }
    /// Explicit new owner input after a real degraded-view barrier abandons
    /// unsent work. It never retries the old approval or claims Root completed it.
    pub fn delivery_home(&mut self, event: KeyEvent) -> Result<Effects, Error> {
        event.encode().map_err(|_| Error::Input)?;
        if event.key != Key::Escape || event.sequence <= self.last_key {
            return Err(Error::Stale);
        }
        let render = self.render(Screen::Home)?;
        self.last_key = event.sequence;
        let cancel = self
            .picker
            .take()
            .map(|p| Command::Cancel { request: p.request });
        self.managed = None;
        self.launching = false;
        self.focused_app = false;
        let mut effects = self.publish(render);
        effects.command = cancel;
        Ok(effects)
    }
    fn render(&self, screen: Screen) -> Result<Render, Error> {
        let frame = self
            .frame
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Counter)?;
        Ok(Render { frame, screen })
    }
    fn publish(&mut self, render: Render) -> Effects {
        self.frame = render.frame;
        self.screen = render.screen;
        if self.pointer_enabled {
            self.pointer_gate = None;
            self.pointer_display = (self.managed.is_none()
                && self.picker.as_ref().is_none_or(|p| !p.submitted))
            .then_some(render.frame);
            self.pointer_barrier = None;
        }
        Effects {
            render: Some(render),
            ..Effects::default()
        }
    }
    pub fn initial(&mut self) -> Result<Effects, Error> {
        let r = self.render(Screen::Home)?;
        let mut effects = self.publish(r);
        if self.pointer_enabled {
            effects.cursor = Some(self.cursor()?);
        }
        Ok(effects)
    }
    /// A Root message is accepted only through the adapter's fixed Root channel.
    /// Epochs/requests correlate state and are not ProcessCONTROL or File caps.
    pub fn root(&mut self, event: RootEvent) -> Result<Effects, Error> {
        #[cfg(feature = "native-owner-ui")]
        if !matches!(event, RootEvent::Connection(_)) {
            self.owner = None;
            self.owner_wanted = false;
        }
        match event {
            #[cfg(feature = "native-owner-ui")]
            RootEvent::Connection(p) => {
                if !self.owner_enabled {
                    return Err(Error::Input);
                }
                if !self.owner_wanted && self.owner.is_none() {
                    return Ok(Effects::default());
                }
                if p.status.app_running != self.app_epoch.is_some() {
                    return Err(Error::State);
                }
                let next = self.render(Screen::Home)?;
                let owner =
                    crate::owner_ui::Policy::new(p, next.frame).map_err(|_| Error::Input)?;
                let view = owner.view();
                self.owner = Some(owner);
                self.owner_wanted = false;
                self.focused_app = false;
                Ok(self.publish(Render {
                    screen: Screen::Connection(view),
                    ..next
                }))
            }
            RootEvent::LaunchRefused => {
                if !self.launching || self.app_epoch.is_some() || self.picker.is_some() {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::Home)?;
                self.launching = false;
                self.focused_app = false;
                Ok(self.publish(r))
            }
            RootEvent::AppRestored { epoch } => {
                if epoch == 0
                    || epoch == u64::MAX
                    || self.app_epoch.is_some()
                    || self.picker.is_some()
                {
                    return Err(Error::State);
                }
                let r = self.render(Screen::AppRunning)?;
                self.app_epoch = Some(epoch);
                self.launching = false;
                self.focused_app = true;
                Ok(self.publish(r))
            }
            RootEvent::AppStarted { epoch } => {
                if epoch == 0 || epoch == u64::MAX || !self.launching || self.app_epoch.is_some() {
                    return Err(Error::State);
                }
                let r = self.render(Screen::AppRunning)?;
                self.app_epoch = Some(epoch);
                self.launching = false;
                self.focused_app = true;
                Ok(self.publish(r))
            }
            RootEvent::AppStopped { epoch } => {
                if self.app_epoch != Some(epoch) {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::AppStopped)?;
                let old = self.picker.take();
                self.managed = None;
                self.app_epoch = None;
                self.focused_app = false;
                self.launching = false;
                let mut effects = self.publish(r);
                effects.command = old.map(|p| Command::Cancel { request: p.request });
                Ok(effects)
            }
            RootEvent::PickFile { request, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.picker.is_some()
                    || self.managed.is_some()
                    || request == 0
                    || request == u32::MAX
                    || request <= self.last_request
                {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::Picker {
                    selected: FileChoice::Notes,
                })?;
                self.last_request = request;
                self.focused_app = false;
                self.picker = Some(Picker {
                    request,
                    app_epoch,
                    selected: FileChoice::Notes,
                    gate: None,
                    awaiting_display: Some(r.frame),
                    awaiting_barrier: None,
                    submitted: false,
                });
                Ok(self.publish(r))
            }
            RootEvent::FileDelivered { request, app_epoch }
            | RootEvent::FileRefused { request, app_epoch } => {
                if !self.picker.as_ref().is_some_and(|p| {
                    p.request == request && p.app_epoch == app_epoch && p.submitted
                }) || self.app_epoch != Some(app_epoch)
                {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::AppRunning)?;
                self.picker = None;
                self.focused_app = true;
                Ok(self.publish(r))
            }
            RootEvent::InputRestarted => {
                let screen = if self.app_epoch.is_some() {
                    Screen::AppRunning
                } else {
                    Screen::Home
                };
                let r = self.render(screen)?;
                let old = self.picker.take();
                self.managed = None;
                self.last_key = 0;
                self.focused_app = self.app_epoch.is_some();
                let mut effects = self.publish(r);
                effects.command = old.map(|p| Command::Cancel { request: p.request });
                Ok(effects)
            }
            RootEvent::OwnerFilePending { request, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.managed.is_some()
                    || !self.picker.as_ref().is_some_and(|p| {
                        p.request == request && p.app_epoch == app_epoch && !p.submitted
                    })
                {
                    return Err(Error::Stale);
                }
                let render = self.render(Screen::AppRunning)?;
                self.picker = None;
                self.focused_app = false;
                self.managed = Some(Managed {
                    kind: PendingKind::OwnerFile,
                    request,
                    app_epoch,
                });
                Ok(self.publish(render))
            }
            RootEvent::ManagedFilePending { request, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.picker.is_some()
                    || self.managed.is_some()
                    || request == 0
                    || request == u32::MAX
                    || request <= self.last_request
                {
                    return Err(Error::Stale);
                }
                let render = self.render(Screen::AppRunning)?;
                self.last_request = request;
                self.focused_app = false;
                self.managed = Some(Managed {
                    kind: PendingKind::ManagedFile,
                    request,
                    app_epoch,
                });
                Ok(self.publish(render))
            }
            RootEvent::OwnerActionPending { serial, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.managed.is_some()
                    || serial == 0
                    || serial == u32::MAX
                {
                    return Err(Error::Stale);
                }
                let render = self.render(Screen::AppRunning)?;
                self.picker = None;
                self.focused_app = false;
                self.managed = Some(Managed {
                    kind: PendingKind::OwnerAction,
                    request: serial,
                    app_epoch,
                });
                Ok(self.publish(render))
            }
            RootEvent::OwnerFileDelivered { request, app_epoch }
            | RootEvent::OwnerFileRefused { request, app_epoch } => {
                self.managed_done(PendingKind::OwnerFile, request, app_epoch)
            }
            RootEvent::ManagedFileDelivered { request, app_epoch }
            | RootEvent::ManagedFileRefused { request, app_epoch } => {
                self.managed_done(PendingKind::ManagedFile, request, app_epoch)
            }
            RootEvent::OwnerActionDone { serial, app_epoch } => {
                self.managed_done(PendingKind::OwnerAction, serial, app_epoch)
            }
        }
    }
    fn managed_done(
        &mut self,
        kind: PendingKind,
        request: u32,
        app_epoch: u64,
    ) -> Result<Effects, Error> {
        if self.app_epoch != Some(app_epoch)
            || !self
                .managed
                .as_ref()
                .is_some_and(|p| p.kind == kind && p.request == request && p.app_epoch == app_epoch)
        {
            return Err(Error::Stale);
        }
        let render = self.render(Screen::AppRunning)?;
        self.managed = None;
        self.focused_app = true;
        Ok(self.publish(render))
    }
    /// Call only after the exact protected Present reply, never after enqueue or
    /// a user marker. An old/double reply cannot arm a newly displayed choice.
    pub fn displayed(&mut self, frame: u32) -> Result<Effects, Error> {
        if frame != self.frame {
            return Err(Error::Stale);
        }
        #[cfg(feature = "native-owner-ui")]
        if let Some(owner) = self.owner.as_mut() {
            owner.displayed(frame).map_err(|_| Error::Stale)?;
        }
        let pointer = self.pointer_display == Some(frame);
        if pointer {
            self.pointer_display = None;
            self.pointer_barrier = Some(frame);
        }
        let Some(p) = self.picker.as_mut() else {
            return Ok(Effects {
                barrier_after_frame: pointer.then_some(frame),
                ..Effects::default()
            });
        };
        if p.submitted {
            // A fresh approval emits an Opening redraw before the adapter sends
            // Select. Its actual Present still needs an acknowledgement, but
            // the completed selection must never acquire another input gate.
            return if self.screen
                == (Screen::Opening {
                    selected: p.selected,
                }) {
                Ok(Effects {
                    barrier_after_frame: pointer.then_some(frame),
                    ..Effects::default()
                })
            } else {
                Err(Error::State)
            };
        }
        if p.awaiting_display != Some(frame) {
            return Err(Error::Stale);
        }
        p.awaiting_display = None;
        p.awaiting_barrier = Some(frame);
        Ok(Effects {
            barrier_after_frame: Some(frame),
            ..Effects::default()
        })
    }
    /// The adapter cancels on Input replacement and drains obsolete sender
    /// messages before rebinding. Barrier flags remain freshness, not consent.
    pub fn barrier(&mut self, frame: u32, reply: BarrierReply) -> Result<(), Error> {
        let p = self.picker.as_mut().ok_or(Error::State)?;
        if p.submitted || p.awaiting_barrier != Some(frame) || frame != self.frame {
            return Err(Error::Stale);
        }
        let mut snapshot = reply;
        snapshot.sequence = snapshot.sequence.max(self.last_key);
        let gate = FreshGate::after_barrier(snapshot).map_err(|_| Error::Input)?;
        p.awaiting_barrier = None;
        p.gate = Some(gate);
        Ok(())
    }
    /// After a new Input incarnation or Shell replacement, the actual adapter
    /// drains Input after its protected redraw. No picker approval survives.
    /// Old queued frames remain untrusted data and cannot move focus or launch.
    pub fn input_drained(&mut self, reply: BarrierReply) -> Result<(), Error> {
        if self.picker.is_some() {
            return Err(Error::State);
        }
        reply.encode().map_err(|_| Error::Input)?;
        self.last_key = self.last_key.max(reply.sequence);
        Ok(())
    }
    /// Actual Present and KBR2 RPC only, with a separate held-button gate.
    pub fn session_barrier(
        &mut self,
        frame: u32,
        mut reply: SessionBarrierReply,
    ) -> Result<(), Error> {
        if !self.pointer_enabled || self.pointer_barrier != Some(frame) || frame != self.frame {
            return Err(Error::Stale);
        }
        reply.encode().map_err(|_| Error::Input)?;
        reply.sequence = reply.sequence.max(self.last_key);
        #[cfg(feature = "native-owner-ui")]
        if let Some(owner) = self.owner.as_mut() {
            owner.barrier(frame, reply).map_err(|_| Error::Input)?;
        }
        if self
            .picker
            .as_ref()
            .is_some_and(|p| p.awaiting_barrier == Some(frame))
        {
            self.barrier(frame, reply.keyboard())?;
        }
        self.pointer_gate = Some(PointerGate::after_barrier(reply).map_err(|_| Error::Input)?);
        self.pointer_barrier = None;
        self.last_key = reply.sequence;
        Ok(())
    }
    fn cursor(&mut self) -> Result<CursorControl, Error> {
        self.cursor_revision = self
            .cursor_revision
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Counter)?;
        Ok(CursorControl {
            x: self.pointer_x,
            y: self.pointer_y,
            sequence: self.cursor_revision,
        })
    }
    pub fn pointer(&mut self, event: PointerEvent) -> Result<Effects, Error> {
        if !self.pointer_enabled {
            return Err(Error::Input);
        }
        event.encode().map_err(|_| Error::Input)?;
        if event.sequence <= self.last_key {
            return Err(Error::Stale);
        }
        self.last_key = event.sequence;
        self.pointer_x = (i32::from(self.pointer_x) + i32::from(event.dx)).clamp(0, 319) as u16;
        self.pointer_y = (i32::from(self.pointer_y) - i32::from(event.dy)).clamp(0, 199) as u8;
        let cursor = self.cursor()?;
        let armed = self.pointer_gate.is_some();
        let fresh = match self.pointer_gate.as_mut() {
            Some(gate) => gate.observe(event).map_err(|_| Error::Input)? & LEFT != 0,
            None => false,
        };
        #[cfg(feature = "native-owner-ui")]
        if let Some(owner) = self.owner.as_mut() {
            let request = owner
                .pointer(event, self.pointer_x, self.pointer_y)
                .map_err(|_| Error::Input)?;
            let mut effects = self.owner_request(request)?;
            effects.cursor = Some(cursor);
            return Ok(effects);
        }
        #[cfg(feature = "native-owner-ui")]
        if self.owner_enabled
            && fresh
            && ev_graphics::connection::ENTRY
                .contains(usize::from(self.pointer_x), usize::from(self.pointer_y))
            && self.screen == Screen::Home
        {
            return self.owner_open();
        }
        let mut effects = Effects {
            cursor: Some(cursor),
            ..Effects::default()
        };
        if self.managed.is_some() {
            return Ok(effects);
        }
        let hit = ev_graphics::shell::hit_test(
            self.screen,
            usize::from(self.pointer_x),
            usize::from(self.pointer_y),
        );
        if let Some(p) = self.picker.as_mut() {
            if !fresh || p.submitted {
                return Ok(effects);
            }
            match hit {
                Some(ev_graphics::shell::Hit::Choice(file)) if file != p.selected => {
                    p.selected = file;
                    p.gate = None;
                    let selected = file;
                    let next = self.render(Screen::Picker { selected })?;
                    self.picker.as_mut().unwrap().awaiting_display = Some(next.frame);
                    self.picker.as_mut().unwrap().awaiting_barrier = None;
                    effects = self.publish(next);
                }
                Some(ev_graphics::shell::Hit::Open) => {
                    let command = Command::Select {
                        request: p.request,
                        app_epoch: p.app_epoch,
                        file: p.selected,
                    };
                    let selected = p.selected;
                    p.submitted = true;
                    p.gate = None;
                    let next = self.render(Screen::Opening { selected })?;
                    effects = self.publish(next);
                    effects.command = Some(command);
                }
                Some(ev_graphics::shell::Hit::Cancel) => {
                    let request = p.request;
                    self.picker = None;
                    self.focused_app = true;
                    let next = self.render(Screen::AppRunning)?;
                    effects = self.publish(next);
                    effects.command = Some(Command::Cancel { request });
                }
                _ => (),
            }
        } else if self.focused_app && self.app_epoch.is_some() {
            if fresh && hit == Some(ev_graphics::shell::Hit::Home) {
                self.focused_app = false;
                let next = self.render(Screen::Home)?;
                effects = self.publish(next);
            } else if armed {
                effects.command = Some(Command::Pointer(PositionEvent {
                    x: self.pointer_x,
                    y: self.pointer_y,
                    buttons: event.buttons,
                    fresh_left_press: fresh,
                    sequence: event.sequence,
                }));
            }
        } else if fresh && hit == Some(ev_graphics::shell::Hit::Launch) && !self.launching {
            if self.app_epoch.is_some() {
                self.focused_app = true;
                let next = self.render(Screen::AppRunning)?;
                effects = self.publish(next);
            } else {
                self.launching = true;
                effects.command = Some(Command::Launch);
            }
        }
        effects.cursor = Some(cursor);
        Ok(effects)
    }
    /// Text can reach only the currently focused live App. Consuming its common
    /// input sequence never arms a picker, launches an App or approves a grant.
    pub fn text(&mut self, event: TextEvent) -> Result<Effects, Error> {
        event.encode().map_err(|_| Error::Input)?;
        if event.sequence <= self.last_key {
            return Err(Error::Stale);
        }
        self.last_key = event.sequence;
        Ok(Effects {
            command: (self.focused_app
                && self.app_epoch.is_some()
                && self.picker.is_none()
                && self.managed.is_none())
            .then_some(Command::Text(event)),
            ..Effects::default()
        })
    }
    pub fn key(&mut self, event: KeyEvent) -> Result<Effects, Error> {
        event.encode().map_err(|_| Error::Input)?;
        if event.sequence <= self.last_key {
            return Err(Error::Stale);
        }
        // Reserve a visual revision before consuming a key that may change it.
        let next = self.render(self.screen)?;
        self.last_key = event.sequence;
        #[cfg(feature = "native-owner-ui")]
        if let Some(owner) = self.owner.as_mut() {
            let before = owner.view();
            let request = owner.key(event).map_err(|_| Error::Input)?;
            let changed = owner.view() != before;
            if changed && request.is_none() {
                owner.redraw(next.frame).map_err(|_| Error::Counter)?;
                let view = owner.view();
                return Ok(self.publish(Render {
                    screen: Screen::Connection(view),
                    ..next
                }));
            }
            return self.owner_request(request);
        }
        #[cfg(feature = "native-owner-ui")]
        if self.owner_enabled && self.screen == Screen::Home && event.key == Key::Tab {
            return self.owner_open();
        }
        if self.managed.is_some() {
            return Ok(Effects::default());
        }
        if let Some(p) = self.picker.as_mut() {
            if p.submitted {
                return Ok(Effects::default());
            }
            let Some(gate) = p.gate.as_mut() else {
                return Ok(Effects::default());
            };
            let Some(key) = gate.observe(event).map_err(|_| Error::Input)? else {
                return Ok(Effects::default());
            };
            return match key {
                Key::Left | Key::Right => Ok(Effects::default()),
                Key::Tab | Key::Up | Key::Down => {
                    p.selected = p.selected.next();
                    p.gate = None;
                    p.awaiting_display = Some(next.frame);
                    p.awaiting_barrier = None;
                    let screen = Screen::Picker {
                        selected: p.selected,
                    };
                    Ok(self.publish(Render { screen, ..next }))
                }
                Key::Enter => {
                    let command = Command::Select {
                        request: p.request,
                        app_epoch: p.app_epoch,
                        file: p.selected,
                    };
                    let screen = Screen::Opening {
                        selected: p.selected,
                    };
                    p.submitted = true;
                    p.gate = None;
                    let mut effects = self.publish(Render { screen, ..next });
                    effects.command = Some(command);
                    Ok(effects)
                }
                Key::Escape => {
                    let request = p.request;
                    self.picker = None;
                    self.focused_app = true;
                    let mut effects = self.publish(Render {
                        screen: Screen::AppRunning,
                        ..next
                    });
                    effects.command = Some(Command::Cancel { request });
                    Ok(effects)
                }
            };
        }
        if self.focused_app && self.app_epoch.is_some() {
            if event.key == Key::Escape {
                self.focused_app = false;
                return Ok(self.publish(Render {
                    screen: Screen::Home,
                    ..next
                }));
            }
            return Ok(Effects {
                command: Some(Command::Forward(event)),
                ..Effects::default()
            });
        }
        if event.key == Key::Enter && !self.launching {
            if self.app_epoch.is_some() {
                self.focused_app = true;
                return Ok(self.publish(Render {
                    screen: Screen::AppRunning,
                    ..next
                }));
            }
            self.launching = true;
            return Ok(Effects {
                command: Some(Command::Launch),
                ..Effects::default()
            });
        }
        if event.key == Key::Escape && self.app_epoch.is_none() {
            return Ok(self.publish(Render {
                screen: Screen::Home,
                ..next
            }));
        }
        Ok(Effects::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{RootControl, ShellCommand},
        shell_delivery::{Kind as DeliveryKind, Outbox},
    };
    fn motion(sequence: u32, dx: i16, dy: i16, buttons: u8) -> PointerEvent {
        PointerEvent {
            sequence,
            dx,
            dy,
            buttons,
        }
    }
    fn arm_pointer(p: &mut Policy, effects: Effects, sequence: u32, held: u8, released: u8) {
        let frame = effects.render.unwrap().frame;
        assert_eq!(p.displayed(frame).unwrap().barrier_after_frame, Some(frame));
        p.session_barrier(
            frame,
            SessionBarrierReply {
                sequence,
                enter: ev_input::EnterState::default(),
                pointer: ev_input::PointerState { held, released },
            },
        )
        .unwrap();
    }
    #[test]
    fn busy_footer_preserves_ordered_text_and_pointer_release_without_rearming_input() {
        let mut p = Policy::with_pointer();
        p.initial().unwrap();
        p.key(key(1, Key::Enter, false)).unwrap();
        let started = p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        arm_pointer(&mut p, started, 1, 0, 7);
        let mut queue = Outbox::new();
        for sequence in 2..32 {
            let command = p
                .text(TextEvent {
                    text: ev_input::text::Text::Ascii(b'a' + (sequence % 26) as u8),
                    sequence,
                })
                .unwrap()
                .command
                .unwrap();
            queue
                .enqueue(
                    11,
                    ShellCommand::from_policy(command).encode().unwrap(),
                    DeliveryKind::Input,
                    10,
                )
                .unwrap();
        }
        for (sequence, buttons) in [(32, 1), (33, 0)] {
            let command = p
                .pointer(motion(sequence, 0, 0, buttons))
                .unwrap()
                .command
                .unwrap();
            queue
                .enqueue(
                    11,
                    ShellCommand::from_policy(command).encode().unwrap(),
                    DeliveryKind::Input,
                    10,
                )
                .unwrap();
        }
        assert!(!queue.input_room());
        let first = queue.next_attempt().unwrap();
        let busy = p.delivery_redraw(false).unwrap();
        assert_eq!(busy.render.unwrap().screen, Screen::AppRunning);
        assert!(p.pointer_gate.is_none());
        assert_eq!(
            p.session_barrier(
                busy.render.unwrap().frame,
                SessionBarrierReply {
                    sequence: 40,
                    enter: ev_input::EnterState::default(),
                    pointer: ev_input::PointerState {
                        held: 0,
                        released: 7
                    },
                }
            ),
            Err(Error::Stale),
            "a status frame alone cannot arm input"
        );
        assert_eq!(queue.next_attempt(), Some(first));
        for expected_sequence in 2..34 {
            let entry = queue.next_attempt().unwrap();
            assert_eq!(entry.cut, 10 + 12_288);
            match ShellCommand::decode(entry.bytes).unwrap() {
                ShellCommand::Text(text) => assert_eq!(text.sequence, expected_sequence),
                ShellCommand::Pointer(pointer) => {
                    assert_eq!(pointer.sequence, expected_sequence);
                    assert_eq!(pointer.buttons, u8::from(expected_sequence == 32));
                    assert_eq!(pointer.fresh_left_press, expected_sequence == 32);
                }
                other => panic!("reordered or fabricated input: {other:?}"),
            }
            assert!(queue.complete(entry, None));
        }
        assert!(queue.next_attempt().is_none());
        let resumed = p.delivery_redraw(true).unwrap();
        arm_pointer(&mut p, resumed, 40, 1, 7);
        assert_eq!(
            p.text(TextEvent {
                text: ev_input::text::Text::Ascii(b'x'),
                sequence: 39
            }),
            Err(Error::Stale)
        );
        let held = p.pointer(motion(41, 0, 0, 1)).unwrap().command.unwrap();
        assert!(matches!(
            held,
            Command::Pointer(PositionEvent {
                fresh_left_press: false,
                ..
            })
        ));
        p.pointer(motion(42, 0, 0, 0)).unwrap();
        assert!(matches!(
            p.pointer(motion(43, 0, 0, 1)).unwrap().command,
            Some(Command::Pointer(PositionEvent {
                fresh_left_press: true,
                ..
            }))
        ));
    }
    #[test]
    fn expired_unsent_picker_approval_cannot_reappear_after_real_recovery_barrier() {
        let mut p = Policy::with_pointer();
        p.initial().unwrap();
        p.key(key(1, Key::Enter, false)).unwrap();
        let started = p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        arm_pointer(&mut p, started, 1, 0, 7);
        let picker = p
            .root(RootEvent::PickFile {
                request: 1,
                app_epoch: 1,
            })
            .unwrap();
        arm_pointer(&mut p, picker, 1, 0, 7);
        let mut queue = Outbox::new();
        queue
            .enqueue(
                11,
                ShellCommand::PickerReady(picker.render.unwrap().frame)
                    .encode()
                    .unwrap(),
                DeliveryKind::PickerReady,
                10,
            )
            .unwrap();
        queue
            .enqueue(
                11,
                ShellCommand::ControlSettled(RootControl::PickFile(1))
                    .encode()
                    .unwrap(),
                DeliveryKind::Settled,
                10,
            )
            .unwrap();
        p.pointer(motion(2, -60, -55, 0)).unwrap();
        let opening = p.pointer(motion(3, 0, 0, 1)).unwrap();
        assert!(matches!(
            opening.command,
            Some(Command::Select { request: 1, .. })
        ));
        queue.context_changed(false);
        let select = queue
            .enqueue(
                11,
                ShellCommand::from_policy(opening.command.unwrap())
                    .encode()
                    .unwrap(),
                DeliveryKind::Action,
                11,
            )
            .unwrap();
        let prerequisite = queue.next_attempt().unwrap();
        assert!(matches!(
            ShellCommand::decode(prerequisite.bytes),
            Ok(ShellCommand::PickerReady(_))
        ));
        assert!(queue.complete(prerequisite, Some(crate::shell_delivery::Error::Expired)));
        queue.context_changed(true);
        assert!(matches!(
            ShellCommand::decode(queue.next_attempt().unwrap().bytes),
            Ok(ShellCommand::ControlSettled(RootControl::PickFile(1)))
        ));
        assert_ne!(queue.next_attempt().unwrap().ticket, select);
        let paused = p.delivery_redraw(true).unwrap();
        arm_pointer(&mut p, paused, 40, 1, 7);
        assert!(
            p.picker.as_ref().unwrap().gate.is_none(),
            "delivery recovery cannot reissue a submitted approval"
        );
        assert!(p.pointer(motion(41, 0, 0, 0)).unwrap().command.is_none());
        assert!(p.pointer(motion(42, 0, 0, 1)).unwrap().command.is_none());
        assert_eq!(
            p.delivery_home(key(40, Key::Escape, false)),
            Err(Error::Stale)
        );
        let home = p.delivery_home(key(43, Key::Escape, false)).unwrap();
        assert_eq!(home.command, Some(Command::Cancel { request: 1 }));
        assert_eq!(home.render.unwrap().screen, Screen::Home);
        arm_pointer(&mut p, home, 43, 1, 7);
        queue.recovered_after_fresh_context();
        assert!(!queue.degraded());
        assert!(p.picker.is_none());
    }
    #[test]
    fn raw_clicks_cannot_launch_until_actual_present_barrier_and_real_post_cut_release() {
        let mut p = Policy::with_pointer();
        let initial = p.initial().unwrap();
        assert!(initial.cursor.is_some());
        let snapshot = SessionBarrierReply {
            sequence: 0,
            enter: ev_input::EnterState::default(),
            pointer: ev_input::PointerState {
                held: 0,
                released: 7,
            },
        };
        assert_eq!(
            p.session_barrier(initial.render.unwrap().frame, snapshot),
            Err(Error::Stale)
        );
        assert!(p.pointer(motion(1, 0, 0, 0)).unwrap().command.is_none());
        assert!(p.pointer(motion(2, 0, 0, 1)).unwrap().command.is_none());
        arm_pointer(&mut p, initial, 2, 1, 7);
        assert!(p.pointer(motion(3, 0, 0, 1)).unwrap().command.is_none());
        assert!(p.pointer(motion(4, 0, 0, 0)).unwrap().command.is_none());
        assert_eq!(
            p.pointer(motion(5, 0, 0, 1)).unwrap().command,
            Some(Command::Launch)
        );
        assert!(p.pointer(motion(6, 0, 0, 1)).unwrap().command.is_none());
        assert_eq!(p.pointer(motion(5, 0, 0, 0)), Err(Error::Stale));
        let mut p = Policy::new();
        assert_eq!(p.pointer(motion(1, 0, 0, 1)), Err(Error::Input));
    }
    #[test]
    fn picker_pointer_selection_requires_new_actual_ui_barrier_and_click_never_becomes_enter() {
        let mut p = Policy::with_pointer();
        p.initial().unwrap();
        assert_eq!(
            p.key(key(1, Key::Enter, false)).unwrap().command,
            Some(Command::Launch)
        );
        let started = p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        arm_pointer(&mut p, started, 1, 0, 7);
        let picker = p
            .root(RootEvent::PickFile {
                request: 1,
                app_epoch: 1,
            })
            .unwrap();
        arm_pointer(&mut p, picker, 1, 0, 7);
        assert!(p.pointer(motion(2, -60, -18, 0)).unwrap().command.is_none());
        let selected = p.pointer(motion(3, 0, 0, 1)).unwrap();
        assert_eq!(
            selected.render.unwrap().screen,
            Screen::Picker {
                selected: FileChoice::Private
            }
        );
        assert!(selected.command.is_none());
        assert!(p.pointer(motion(4, 0, -38, 1)).unwrap().command.is_none());
        assert_eq!(p.pointer_y, 156);
        arm_pointer(&mut p, selected, 4, 1, 7);
        assert!(p.pointer(motion(5, 0, 0, 0)).unwrap().command.is_none());
        let opened = p.pointer(motion(6, 0, 0, 1)).unwrap();
        assert_eq!(
            opened.command,
            Some(Command::Select {
                request: 1,
                app_epoch: 1,
                file: FileChoice::Private
            })
        );
        assert_eq!(
            opened.render.unwrap().screen,
            Screen::Opening {
                selected: FileChoice::Private
            }
        );
        assert!(p.pointer(motion(7, 0, 0, 0)).unwrap().command.is_none());
        assert!(p.pointer(motion(8, 0, 0, 1)).unwrap().command.is_none());
    }
    #[test]
    fn absolute_app_frames_survive_modal_movement_and_common_sequence_rejects_old_text_or_clicks() {
        let mut p = Policy::with_pointer();
        p.initial().unwrap();
        p.key(key(1, Key::Enter, false)).unwrap();
        let started = p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        arm_pointer(&mut p, started, 1, 0, 7);
        let first = p.pointer(motion(2, 10, -10, 0)).unwrap();
        assert_eq!(
            first.command,
            Some(Command::Pointer(PositionEvent {
                x: 170,
                y: 110,
                buttons: 0,
                fresh_left_press: false,
                sequence: 2
            }))
        );
        assert_eq!(
            p.text(TextEvent {
                text: ev_input::text::Text::Ascii(b'a'),
                sequence: 2
            }),
            Err(Error::Stale)
        );
        let picker = p
            .root(RootEvent::PickFile {
                request: 1,
                app_epoch: 1,
            })
            .unwrap();
        arm_pointer(&mut p, picker, 2, 0, 7);
        assert!(p.pointer(motion(3, 60, -45, 0)).unwrap().command.is_none());
        let cancel = p.pointer(motion(4, 0, 0, 1)).unwrap();
        assert_eq!(cancel.command, Some(Command::Cancel { request: 1 }));
        assert_eq!((p.pointer_x, p.pointer_y), (230, 155));
        arm_pointer(&mut p, cancel, 4, 1, 7);
        let release = p.pointer(motion(5, -200, 100, 0)).unwrap();
        assert_eq!(
            release.command,
            Some(Command::Pointer(PositionEvent {
                x: 30,
                y: 55,
                buttons: 0,
                fresh_left_press: false,
                sequence: 5
            }))
        );
        let click = p.pointer(motion(6, 0, 0, 1)).unwrap();
        assert_eq!(
            click.command,
            Some(Command::Pointer(PositionEvent {
                x: 30,
                y: 55,
                buttons: 1,
                fresh_left_press: true,
                sequence: 6
            }))
        );
        let old_cursor = click.cursor.unwrap().sequence;
        let restart = p.root(RootEvent::InputRestarted).unwrap();
        arm_pointer(&mut p, restart, 0, 0, 0);
        let unknown = p.pointer(motion(1, 255, -255, 1)).unwrap();
        assert_eq!(
            unknown.command,
            Some(Command::Pointer(PositionEvent {
                x: 285,
                y: 199,
                buttons: 1,
                fresh_left_press: false,
                sequence: 1
            }))
        );
        assert!(unknown.cursor.unwrap().sequence > old_cursor);
        assert_eq!(p.key(key(1, Key::Enter, true)), Err(Error::Stale));
    }
    #[test]
    fn text_never_launches_or_approves_and_modal_input_cannot_reappear() {
        let mut p = Policy::new();
        let text = |sequence| TextEvent {
            text: ev_input::text::Text::Ascii(b'a'),
            sequence,
        };
        p.initial().unwrap();
        assert_eq!(p.text(text(1)).unwrap(), Effects::default());
        assert_eq!(p.text(text(1)), Err(Error::Stale));
        p.key(key(2, Key::Enter, true)).unwrap();
        p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        assert_eq!(
            p.text(text(3)).unwrap().command,
            Some(Command::Text(text(3)))
        );
        let shown = p
            .root(RootEvent::PickFile {
                request: 1,
                app_epoch: 1,
            })
            .unwrap();
        assert_eq!(p.text(text(4)).unwrap(), Effects::default());
        assert!(p.picker.as_ref().unwrap().gate.is_none());
        let frame = shown.render.unwrap().frame;
        p.displayed(frame).unwrap();
        p.barrier(
            frame,
            BarrierReply {
                sequence: 4,
                enter: ev_input::EnterState::default(),
            },
        )
        .unwrap();
        assert_eq!(
            p.key(key(5, Key::Escape, false)).unwrap().command,
            Some(Command::Cancel { request: 1 })
        );
        assert_eq!(p.text(text(4)), Err(Error::Stale));
        assert_eq!(
            p.text(text(6)).unwrap().command,
            Some(Command::Text(text(6)))
        );
    }
    use ev_input::EnterState;
    fn key(sequence: u32, k: Key, eligible: bool) -> KeyEvent {
        KeyEvent {
            key: k,
            sequence,
            release_known: k == Key::Enter && eligible,
            approval_ready: k == Key::Enter && eligible,
        }
    }
    #[test]
    fn refused_missing_install_clears_only_a_pending_launch() {
        let mut p = Policy::new();
        p.initial().unwrap();
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(
            p.key(key(1, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
        let refused = p.root(RootEvent::LaunchRefused).unwrap();
        assert_eq!(refused.render.unwrap().screen, Screen::Home);
        assert_eq!(refused.command, None);
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(
            p.key(key(2, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
        p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(p.screen(), Screen::AppRunning);
    }
    #[test]
    fn authenticated_owner_launch_can_complete_a_concurrent_home_launch() {
        let mut p = Policy::new();
        p.initial().unwrap();
        assert_eq!(
            p.key(key(1, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
        let adopted = p.root(RootEvent::AppRestored { epoch: 7 }).unwrap();
        assert_eq!(adopted.render.unwrap().screen, Screen::AppRunning);
        assert_eq!(
            p.root(RootEvent::AppRestored { epoch: 7 }),
            Err(Error::State)
        );
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(
            p.key(key(2, Key::Enter, true)).unwrap().command,
            Some(Command::Forward(key(2, Key::Enter, true)))
        );
        p.root(RootEvent::AppStopped { epoch: 7 }).unwrap();
        assert_eq!(
            p.key(key(3, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
    }
    fn running() -> Policy {
        let mut p = Policy::new();
        p.initial().unwrap();
        assert_eq!(
            p.key(key(1, Key::Enter, false)).unwrap().command,
            Some(Command::Launch)
        );
        p.root(RootEvent::AppStarted { epoch: 257 }).unwrap();
        p
    }
    #[test]
    fn owner_consent_replaces_unsubmitted_picker_with_distinct_pending_state() {
        let mut p = running();
        p.root(RootEvent::PickFile {
            request: 4,
            app_epoch: 257,
        })
        .unwrap();
        let effects = p
            .root(RootEvent::OwnerFilePending {
                request: 4,
                app_epoch: 257,
            })
            .unwrap();
        assert_eq!(effects.render.unwrap().screen, Screen::AppRunning);
        assert!(p.picker.is_none());
        assert_eq!(p.key(key(2, Key::Enter, true)).unwrap().command, None);
        assert_eq!(
            p.root(RootEvent::FileDelivered {
                request: 4,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::ManagedFileDelivered {
                request: 4,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::OwnerFileDelivered {
                request: 4,
                app_epoch: 258
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::OwnerFileDelivered {
            request: 4,
            app_epoch: 257,
        })
        .unwrap();
        assert!(matches!(
            p.key(key(3, Key::Enter, true)).unwrap().command,
            Some(Command::Forward(_))
        ));
        assert_eq!(
            p.root(RootEvent::OwnerFileDelivered {
                request: 4,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
    }
    #[test]
    fn remembered_delivery_requires_exact_managed_request_and_stops_cancel_it() {
        let mut p = running();
        p.root(RootEvent::ManagedFilePending {
            request: 2,
            app_epoch: 257,
        })
        .unwrap();
        assert!(p.picker.is_none());
        assert_eq!(p.key(key(2, Key::Enter, true)).unwrap().command, None);
        assert_eq!(
            p.root(RootEvent::PickFile {
                request: 3,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::FileDelivered {
                request: 2,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::OwnerFileDelivered {
                request: 2,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::ManagedFileDelivered {
            request: 2,
            app_epoch: 257,
        })
        .unwrap();
        assert_eq!(
            p.root(RootEvent::ManagedFilePending {
                request: 2,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::ManagedFilePending {
            request: 3,
            app_epoch: 257,
        })
        .unwrap();
        p.root(RootEvent::AppStopped { epoch: 257 }).unwrap();
        assert!(p.managed.is_none());
        assert_eq!(
            p.root(RootEvent::ManagedFileDelivered {
                request: 3,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::AppRestored { epoch: 258 }).unwrap();
        p.root(RootEvent::ManagedFilePending {
            request: 4,
            app_epoch: 258,
        })
        .unwrap();
        p.root(RootEvent::InputRestarted).unwrap();
        assert!(p.managed.is_none());
        assert_eq!(
            p.root(RootEvent::ManagedFileDelivered {
                request: 4,
                app_epoch: 258
            }),
            Err(Error::Stale)
        );
    }
    #[test]
    fn shell_replacement_can_restore_actual_app_but_cannot_restore_old_approval() {
        let mut fresh = Policy::new();
        fresh.initial().unwrap();
        let effects = fresh.root(RootEvent::AppRestored { epoch: 257 }).unwrap();
        assert_eq!(effects.render.unwrap().screen, Screen::AppRunning);
        assert!(
            fresh
                .root(RootEvent::FileDelivered {
                    request: 1,
                    app_epoch: 257
                })
                .is_err()
        );
        assert!(fresh.root(RootEvent::AppRestored { epoch: 258 }).is_err());
        let effects = fresh
            .root(RootEvent::PickFile {
                request: 2,
                app_epoch: 257,
            })
            .unwrap();
        assert_eq!(fresh.key(key(1, Key::Enter, true)).unwrap().command, None);
        let frame = effects.render.unwrap().frame;
        arm(&mut fresh, frame, 1);
        assert!(matches!(
            fresh.key(key(2, Key::Enter, true)).unwrap().command,
            Some(Command::Select { request: 2, .. })
        ));
    }
    #[test]
    fn actual_restart_barrier_floor_discards_old_keys_without_forwarding_them() {
        let mut p = running();
        p.root(RootEvent::InputRestarted).unwrap();
        p.input_drained(BarrierReply {
            sequence: 10,
            enter: EnterState::default(),
        })
        .unwrap();
        assert_eq!(p.key(key(9, Key::Enter, true)), Err(Error::Stale));
        assert_eq!(p.key(key(10, Key::Tab, false)), Err(Error::Stale));
        assert_eq!(
            p.key(key(11, Key::Tab, false)).unwrap().command,
            Some(Command::Forward(key(11, Key::Tab, false)))
        );
    }
    fn picker() -> (Policy, u32) {
        let mut p = running();
        let effect = p
            .root(RootEvent::PickFile {
                request: 1,
                app_epoch: 257,
            })
            .unwrap();
        (p, effect.render.unwrap().frame)
    }
    fn arm(p: &mut Policy, frame: u32, sequence: u32) {
        assert_eq!(p.displayed(frame).unwrap().barrier_after_frame, Some(frame));
        p.barrier(
            frame,
            BarrierReply {
                sequence,
                enter: EnterState::default(),
            },
        )
        .unwrap();
    }
    #[test]
    fn stale_held_and_predisplay_keys_never_select_a_file() {
        let (mut p, frame) = picker();
        assert_eq!(p.key(key(2, Key::Enter, true)).unwrap().command, None);
        assert!(
            p.barrier(
                frame,
                BarrierReply {
                    sequence: 2,
                    enter: EnterState::default()
                }
            )
            .is_err()
        );
        arm(&mut p, frame, 5);
        assert_eq!(p.key(key(3, Key::Enter, true)).unwrap().command, None);
        assert_eq!(p.key(key(6, Key::Enter, false)).unwrap().command, None);
        assert_eq!(
            p.key(key(7, Key::Enter, true)).unwrap().command,
            Some(Command::Select {
                request: 1,
                app_epoch: 257,
                file: FileChoice::Notes
            })
        );
        assert_eq!(p.key(key(8, Key::Enter, true)).unwrap().command, None);
    }
    #[test]
    fn changing_choice_requires_new_display_and_barrier() {
        let (mut p, frame) = picker();
        arm(&mut p, frame, 2);
        let changed = p.key(key(3, Key::Down, false)).unwrap().render.unwrap();
        assert_eq!(
            changed.screen,
            Screen::Picker {
                selected: FileChoice::Private
            }
        );
        assert_eq!(p.key(key(4, Key::Enter, true)).unwrap().command, None);
        assert!(p.displayed(frame).is_err());
        arm(&mut p, changed.frame, 4);
        assert_eq!(
            p.key(key(5, Key::Enter, true)).unwrap().command,
            Some(Command::Select {
                request: 1,
                app_epoch: 257,
                file: FileChoice::Private
            })
        );
    }
    #[test]
    fn submission_redraw_acknowledges_without_rearming_or_selecting_again() {
        let (mut p, picker_frame) = picker();
        arm(&mut p, picker_frame, 2);
        let approval = p.key(key(3, Key::Enter, true)).unwrap();
        assert_eq!(
            approval.command,
            Some(Command::Select {
                request: 1,
                app_epoch: 257,
                file: FileChoice::Notes,
            })
        );
        let opening = approval.render.unwrap();
        assert_eq!(
            opening.screen,
            Screen::Opening {
                selected: FileChoice::Notes,
            }
        );
        assert_eq!(p.displayed(opening.frame), Ok(Effects::default()));
        assert_eq!(p.displayed(picker_frame), Err(Error::Stale));
        assert_eq!(
            p.barrier(
                opening.frame,
                BarrierReply {
                    sequence: 3,
                    enter: EnterState::default(),
                },
            ),
            Err(Error::Stale)
        );
        for event in [
            key(4, Key::Enter, true),
            key(5, Key::Enter, false),
            key(6, Key::Enter, true),
        ] {
            assert_eq!(p.key(event), Ok(Effects::default()));
        }
        let delivered = p
            .root(RootEvent::FileDelivered {
                request: 1,
                app_epoch: 257,
            })
            .unwrap()
            .render
            .unwrap();
        assert_eq!(delivered.screen, Screen::AppRunning);
        assert_eq!(p.displayed(delivered.frame), Ok(Effects::default()));
    }
    #[test]
    fn app_or_input_replacement_cancels_the_exact_pending_request() {
        for input in [false, true] {
            let (mut p, frame) = picker();
            arm(&mut p, frame, 2);
            let event = if input {
                RootEvent::InputRestarted
            } else {
                RootEvent::AppStopped { epoch: 257 }
            };
            assert_eq!(
                p.root(event).unwrap().command,
                Some(Command::Cancel { request: 1 })
            );
            assert!(
                p.barrier(
                    frame,
                    BarrierReply {
                        sequence: 3,
                        enter: EnterState::default()
                    }
                )
                .is_err()
            );
            assert!(!matches!(
                p.key(key(4, Key::Enter, true)).unwrap().command,
                Some(Command::Select { .. })
            ));
        }
    }
    #[test]
    fn an_old_app_or_request_cannot_be_substituted() {
        let (mut p, _) = picker();
        assert!(p.root(RootEvent::AppStopped { epoch: 258 }).is_err());
        assert!(
            p.root(RootEvent::PickFile {
                request: 2,
                app_epoch: 258
            })
            .is_err()
        );
        p.root(RootEvent::AppStopped { epoch: 257 }).unwrap();
        p.key(key(2, Key::Enter, false)).unwrap();
        p.root(RootEvent::AppStarted { epoch: 513 }).unwrap();
        assert!(
            p.root(RootEvent::PickFile {
                request: 1,
                app_epoch: 513
            })
            .is_err()
        );
        assert!(
            p.root(RootEvent::FileDelivered {
                request: 1,
                app_epoch: 257
            })
            .is_err()
        );
    }
    #[test]
    fn key_and_visual_counters_refuse_replay_or_wrap() {
        let mut p = running();
        assert!(p.key(key(1, Key::Tab, false)).is_err());
        assert!(p.key(key(u32::MAX, Key::Enter, true)).is_err());
        p.frame = u32::MAX - 1;
        assert_eq!(p.key(key(2, Key::Escape, false)), Err(Error::Counter));
        assert_eq!(p.screen(), Screen::AppRunning);
    }
    #[cfg(feature = "native-owner-ui")]
    #[test]
    fn submitted_owner_action_ignores_navigation_without_redraw_and_new_root_view_rearms() {
        use crate::owner_ui::{Operation, Presentation, Request};
        use ev_graphics::connection::{Action, Connection, Status, Update};
        let mut p = Policy::with_owner_ui();
        p.initial().unwrap();
        p.key(key(1, Key::Enter, true)).unwrap();
        p.root(RootEvent::AppStarted { epoch: 7 }).unwrap();
        p.key(key(2, Key::Escape, false)).unwrap();
        assert_eq!(
            p.key(key(3, Key::Tab, false)).unwrap().command,
            Some(Command::Owner(Request {
                operation: Operation::Open,
                revision: 0
            }))
        );
        let status = Status {
            connection: Connection::Online,
            update: Update::Ready,
            app_running: true,
            confirm: false,
            candidate_available: true,
        };
        let view = p
            .root(RootEvent::Connection(Presentation {
                revision: 7,
                status,
            }))
            .unwrap();
        arm_pointer(&mut p, view, 3, 0, 7);
        let focus = p.key(key(4, Key::Tab, false)).unwrap();
        arm_pointer(&mut p, focus, 4, 0, 7);
        assert_eq!(p.owner.as_ref().unwrap().view().focus, Action::SelectNext);
        assert_eq!(
            p.key(key(5, Key::Enter, true)).unwrap().command,
            Some(Command::Owner(Request {
                operation: Operation::SelectNext,
                revision: 7
            }))
        );
        let before = p.screen();
        for (sequence, k) in [
            (6, Key::Tab),
            (7, Key::Up),
            (8, Key::Down),
            (9, Key::Enter),
            (10, Key::Escape),
        ] {
            let ignored = p.key(key(sequence, k, true)).unwrap();
            assert!(ignored.render.is_none());
            assert!(ignored.command.is_none());
            assert_eq!(p.screen(), before);
        }
        let next = p
            .root(RootEvent::Connection(Presentation {
                revision: 8,
                status: Status {
                    update: Update::Selected,
                    ..status
                },
            }))
            .unwrap();
        let frame = next.render.unwrap().frame;
        assert!(p.key(key(11, Key::Enter, true)).unwrap().command.is_none());
        p.displayed(frame).unwrap();
        p.session_barrier(
            frame,
            SessionBarrierReply {
                sequence: 11,
                enter: EnterState {
                    main_held: true,
                    ..EnterState::default()
                },
                pointer: ev_input::PointerState {
                    held: 0,
                    released: 7,
                },
            },
        )
        .unwrap();
        assert!(p.key(key(12, Key::Enter, false)).unwrap().command.is_none());
        let focus = p.key(key(13, Key::Tab, false)).unwrap();
        arm_pointer(&mut p, focus, 13, 0, 7);
        assert_eq!(
            p.key(key(14, Key::Enter, true)).unwrap().command,
            Some(Command::Owner(Request {
                operation: Operation::Restart,
                revision: 8
            }))
        );
        assert!(p.key(key(15, Key::Enter, true)).unwrap().command.is_none());
    }
}
