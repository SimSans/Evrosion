use super::*;
use ev_graphics::{Color, Pixels};
use ev_userspace_contract::root_v5::{
    display_control::{self as control, Bounds, Slot, Window},
    surface::{Header, Producer, Registration},
};
use ev_workspace_root::render;
const SURFACE: usize = BASE + 448 * 4096;
#[derive(Clone, Copy)]
#[expect(
    clippy::large_enum_variant,
    reason = "Bounded owned accepted-frame metadata must remain immutable; no heap or self-referential buffer. The linked Root still must pass its guarded32KiB stack census."
)]
pub(super) enum Body {
    Desktop(render::View<'static>),
    Assistive(render::AssistiveView),
}
type ControlAttempt = (u64, control::Envelope, u64, Result<[u8; 8], rt::rpc::Error>);
type FrameAttempt = (u64, Header, u64, Result<[u8; 8], rt::rpc::Error>);
pub(super) struct Protected {
    pub identity: Identity,
    pub(super) header: Header,
    pub(super) body: Option<Body>,
    fenced: bool,
    control_attempt: Option<ControlAttempt>,
    frame_attempt: Option<FrameAttempt>,
    pending_body: Option<Body>,
}
impl Protected {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            header: Header {
                producer: Producer::ProtectedRoot,
                instance: 0,
                process: identity.process,
                thread: identity.thread,
                incarnation: identity.registered,
                surface_object: Role::ProtectedSurface.selector(),
                surface_generation: identity.process,
                frame: 0,
                view_revision: 1,
                model_revision: 1,
                width: 640,
                height: 80,
                stride_bytes: 2560,
                payload_bytes: 204800,
                mapping_epoch: 1,
                protected_scope_nonce: 0,
            },
            fenced: false,
            body: None,
            control_attempt: None,
            frame_attempt: None,
            pending_body: None,
        }
    }
    fn frame(&mut self, endpoint: u64, cut: u64) -> Result<u64, ()> {
        if self.fenced || now() >= cut {
            return Err(());
        }
        self.header.frame = self
            .header
            .frame
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(())?;
        let bytes = self.header.encode().map_err(|_| ())?;
        for (i, byte) in bytes.into_iter().enumerate() {
            // SAFETY: actual Root-only initialized51page source. Sole Root
            // thread serializes all control and pixel loans; no retained RPC.
            unsafe { ((SURFACE + i) as *mut u8).write_volatile(byte) };
        }
        let result = rt::rpc::call(endpoint, self.header.frame.to_le_bytes(), cut);
        self.frame_attempt = Some((endpoint, self.header, cut, result));
        if now() >= cut {
            self.fenced = true;
            return Err(());
        }
        match result {
            Ok(reply) if u64::from_le_bytes(reply) == self.header.frame => Ok(self.header.frame),
            Ok(reply) if u64::from_le_bytes(reply) == u64::MAX => Err(()),
            _ => {
                self.fenced = true;
                Err(())
            }
        }
    }
    fn control(&mut self, endpoint: u64, envelope: control::Envelope, cut: u64) -> Result<u64, ()> {
        if self.fenced || now() >= cut {
            return Err(());
        }
        let bytes = envelope.encode().map_err(|_| ())?;
        for (i, byte) in bytes.into_iter().enumerate() {
            // SAFETY: exact Root-only256..512 control extent, disjoint from
            // pixels and no retained protected Present/control read credit.
            unsafe { ((SURFACE + 256 + i) as *mut u8).write_volatile(byte) };
        }
        let result = rt::rpc::call(endpoint, envelope.request.to_le_bytes(), cut);
        self.control_attempt = Some((endpoint, envelope, cut, result));
        if now() >= cut {
            self.fenced = true;
            return Err(());
        }
        match result {
            Ok(reply) => {
                let value = u64::from_le_bytes(reply);
                if value == u64::MAX {
                    Err(())
                } else {
                    Ok(value)
                }
            }
            Err(_) => {
                self.fenced = true;
                Err(())
            }
        }
    }
}
impl Pixels for Protected {
    fn dimensions(&self) -> (usize, usize) {
        (640, 80)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), ev_graphics::Error> {
        if self.fenced || x >= 640 || y >= 80 {
            return Err(ev_graphics::Error::Bounds);
        }
        let offset = 512 + (y * 640 + x) * 4;
        require(offset + 4 <= 51 * 4096, 1633);
        // SAFETY: selected Root's own exact51page RW source, no loan retained.
        // It never maps ordinary App/Shell surfaces for pixel writes or reads.
        unsafe { ((SURFACE + offset) as *mut u32).write_volatile(color.0 & 0xffffff) };
        Ok(())
    }
}
impl Root<'_> {
    pub(super) fn update_cursor(&mut self) {
        let x = self.input.x as u16;
        let y = self.input.y as u16;
        let reply = self.display_command(control::Command::Cursor {
            x,
            y,
            visible: true,
        });
        require(control::decode_reply(reply) == Some(0), 1662);
    }
    pub(super) fn accepted_view(&mut self, slot: Slot) -> Option<(u64, u64)> {
        let policy = self.policy.as_ref()?;
        let model = policy.scene;
        let stamp = self.display_command(control::Command::Inspect { slot, field: 6 });
        if matches!(stamp, 0 | u64::MAX) {
            return None;
        }
        let masks = self.display_command(control::Command::Inspect { slot, field: 0 });
        if masks & (1 << slot.index()) == 0 {
            return None;
        }
        if self.display_command(control::Command::Inspect { slot, field: 1 }) != model {
            return None;
        }
        let frame = self.display_command(control::Command::Inspect { slot, field: 2 });
        let view = self.display_command(control::Command::Inspect { slot, field: 3 });
        let end = self.display_command(control::Command::Inspect { slot, field: 6 });
        if stamp != end || matches!(frame, 0 | u64::MAX) || matches!(view, 0 | u64::MAX) {
            None
        } else {
            Some((frame, view))
        }
    }
    pub(super) fn display_command(&mut self, command: control::Command) -> u64 {
        self.try_display_command(command)
            .unwrap_or_else(|code| rt::exit(code))
    }
    fn try_display_command(&mut self, command: control::Command) -> Result<u64, u64> {
        if self.protected.fenced {
            return Err(1635);
        }
        self.next_control = self
            .next_control
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(1634u64)?;
        let cut =
            deadline(v5::resources::RPC_TICKS).min(self.development.cut().unwrap_or(u64::MAX));
        self.protected
            .control(
                self.channel(Channel::DisplayControl),
                control::Envelope {
                    request: self.next_control,
                    command,
                },
                cut,
            )
            .map_err(|_| 1635u64)
    }
    pub(super) fn commit_scene(&mut self, _initial: bool) {
        self.try_commit_scene()
            .unwrap_or_else(|code| rt::exit(code));
    }
    pub(super) fn try_commit_scene(&mut self) -> Result<(), u64> {
        // A new model invalidates the current protected body. Never retain an
        // old frame/barrier witness across geometry or owner replacement.
        if self.owner.challenge.is_some() {
            self.cancel_owner();
            self.status = b"Desktop changed; the previous protected confirmation was cancelled";
        }
        let policy = self.policy.as_mut().ok_or(1636u64)?;
        let revision = policy.next_scene().map_err(|_| 1636u64)?;
        let preferences = policy.desktop.preferences();
        let reply = self.try_display_command(control::Command::Begin {
            transaction: revision,
            model_revision: revision,
            preferences: control::Preferences {
                scale: preferences.scale,
                high_contrast: preferences.contrast
                    == ev_workspace_shell::composition::Contrast::High,
                thick_focus: preferences.focus
                    == ev_workspace_shell::composition::FocusStyle::ThickOutline,
            },
        })?;
        if control::decode_reply(reply) != Some(0) {
            return Err(1637);
        }
        for slot in control::SLOTS {
            let (identity, epoch, bounds, z, visible, focused) = if slot == Slot::ProtectedRoot {
                (
                    self.protected.identity,
                    1,
                    Bounds {
                        x: 0,
                        y: 0,
                        width: 640,
                        height: 80,
                    },
                    5,
                    true,
                    false,
                )
            } else if slot == Slot::Shell {
                let actor = self.actor(Child::Shell);
                (
                    actor.identity,
                    actor.mapping_epoch,
                    Bounds {
                        x: 0,
                        y: 462,
                        width: 640,
                        height: 18,
                    },
                    4,
                    !actor.failed,
                    false,
                )
            } else {
                let index = slot.index();
                let policy = self.policy.as_ref().ok_or(1636u64)?;
                let Some(id) = policy.ids[index] else {
                    let r = self.try_display_command(control::Command::Remove {
                        transaction: revision,
                        slot,
                    })?;
                    if control::decode_reply(r) != Some(0) {
                        return Err(1638);
                    }
                    continue;
                };
                let window = policy.desktop.window(id).map_err(|_| 1636u64)?;
                let view = policy.desktop.view();
                let actor = self.actor(app_child(index).ok_or(1636u64)?);
                (
                    actor.identity,
                    actor.mapping_epoch,
                    policy.bounds(index).map_err(|_| 1636u64)?,
                    view.windows
                        .iter()
                        .flatten()
                        .position(|v| *v == id)
                        .ok_or(1636u64)? as u8,
                    window.visible,
                    view.focused == Some(id),
                )
            };
            self.registration = self.registration.checked_add(1).ok_or(1639u64)?;
            let window = Window {
                slot,
                registration: Registration {
                    sequence: self.registration,
                    source_role: slot.source(),
                    producer: slot.producer(),
                    instance: slot.instance(),
                    process: identity.process,
                    thread: identity.thread,
                    incarnation: identity.registered,
                    surface_object: slot.source().selector(),
                    surface_generation: identity.process,
                    mapping_epoch: u64::from(epoch),
                },
                bounds,
                z,
                visible,
                view_revision: 1,
                strict_view: false,
                focused,
            };
            let r = self.try_display_command(control::Command::Register {
                transaction: revision,
                window,
            })?;
            if control::decode_reply(r) != Some(0) {
                return Err(1640);
            }
        }
        let r = self.try_display_command(control::Command::Commit {
            transaction: revision,
        })?;
        if control::decode_reply(r).is_none() {
            return Err(1641);
        }
        self.protected.header.model_revision = revision;
        // These bytes are sent only after the actual Display scene commit ACK.
        for slot in [
            Slot::Files,
            Slot::EditorOne,
            Slot::EditorTwo,
            Slot::Inspector,
            Slot::Shell,
        ] {
            let child = if slot == Slot::Shell {
                Child::Shell
            } else {
                app_child(slot.index()).ok_or(1636u64)?
            };
            if self.actor(child).failed {
                continue;
            }
            let index = slot.index();
            let (width, height, focused) = if index < 4 {
                let policy = self.policy.as_ref().ok_or(1636u64)?;
                let Some(id) = policy.ids[index] else {
                    continue;
                };
                let bounds = policy.bounds(index).map_err(|_| 1636u64)?;
                (
                    bounds.width as u16,
                    bounds.height as u16,
                    policy.desktop.view().focused == Some(id),
                )
            } else {
                (640, 18, false)
            };
            if !self.outbox.scene(
                index,
                ev_workspace_root::outbox::Scene {
                    identity: self.actor(child).identity,
                    model: revision,
                    width,
                    height,
                    focused,
                    mapping_epoch: self.actor(child).mapping_epoch,
                },
            ) {
                return Err(1651);
            }
        }
        self.owner.dirty = true;
        Ok(())
    }
    pub(super) fn present_owner(&mut self) {
        self.try_present_owner()
            .unwrap_or_else(|code| rt::exit(code));
    }
    pub(super) fn try_present_owner(&mut self) -> Result<(), u64> {
        if self.policy.is_none() || !self.shutdown.permits_presentation() {
            return Ok(());
        }
        // Ordinary status traffic cannot replace the exact protected body while
        // its single-use witness is armed. A target change first cancels it.
        if self.shutdown.armed()
            || self.development.armed()
            || self.owner.challenge.is_some() && self.owner.witness.is_some() && !self.owner.rearm
        {
            self.owner.dirty = false;
            return Ok(());
        }
        let shutdown_view = self.shutdown.view();
        let development_view = self.development.view();
        let (mode, title, entry, writable) = if let Some((title, _)) = shutdown_view {
            (
                if self.shutdown.dialog() {
                    render::Mode::Shutdown
                } else {
                    render::Mode::ShutdownPending
                },
                title,
                None,
                false,
            )
        } else if let Some(development) = development_view {
            (
                if development.pending {
                    render::Mode::DevelopmentPending
                } else {
                    render::Mode::Development
                },
                if development.intent == ev_workspace_root::development::Intent::Install {
                    b"Confirm local development Install in Editor2".as_slice()
                } else {
                    b"Confirm local development Run in Editor2".as_slice()
                },
                None,
                false,
            )
        } else if let Some(grant) = self.grant.as_ref().filter(|g| g.modal()) {
            let (title, entry, writable) = grant.view();
            (render::Mode::System, title, Some(entry), writable)
        } else {
            self.owner.view()
        };
        let recipient = self
            .grant
            .as_ref()
            .filter(|g| g.modal())
            .map(|g| g.recipient())
            .or_else(|| {
                self.owner.pending.map(|p| render::Recipient {
                    editor: p.index as u8,
                    process: p.identity.process,
                    thread: p.identity.thread,
                    nonce: self.owner.nonce(),
                })
            });
        let dataset = self
            .grant
            .as_ref()
            .filter(|g| g.modal() && g.revoking())
            .map(|g| g.dataset())
            .or_else(|| {
                self.owner
                    .pending
                    .filter(|p| p.purpose == filegrant::Purpose::Revoke)
                    .and_then(|p| self.revoke_dataset(p))
                    .map(|d| d.0)
            })
            .unwrap_or([0; 16]);
        let layer = match self.policy.as_ref().unwrap().desktop.view().layer {
            Layer::Simple => 1,
            Layer::Advanced => 2,
            Layer::AbsoluteAccess => 3,
        };
        let body = if let Some(view) = self.semantic_consent_view(layer) {
            Body::Assistive(view)
        } else {
            Body::Desktop(render::View {
                mode,
                title,
                status: shutdown_view.map_or(self.status, |(_, status)| status),
                refusal: self.last_refusal,
                recipient,
                entry,
                writable,
                layer,
                dataset,
                development: if matches!(
                    mode,
                    render::Mode::Desktop
                        | render::Mode::Development
                        | render::Mode::DevelopmentPending
                ) {
                    development_view.or_else(|| self.development_offer())
                } else {
                    None
                },
            })
        };
        match body {
            Body::Desktop(view) => render::render(&mut self.protected, view),
            Body::Assistive(view) => render::assistive(&mut self.protected, view),
        }
        .map_err(|_| 1642u64)?;
        self.protected.header.view_revision = self
            .protected
            .header
            .view_revision
            .checked_add(1)
            .ok_or(1643u64)?;
        self.protected.header.protected_scope_nonce = if self.shutdown.active() {
            self.shutdown.nonce()
        } else if self.development.active() {
            self.development.nonce()
        } else {
            self.owner.nonce()
        };
        let cut =
            deadline(v5::resources::RPC_TICKS).min(self.development.cut().unwrap_or(u64::MAX));
        self.protected.pending_body = Some(body);
        let frame = self
            .protected
            .frame(self.channel(Channel::DisplayPresent), cut)
            .map_err(|_| 1644u64)?;
        // Capture exactly the immutable metadata used to draw this accepted
        // frame. Live Root status or chooser state may change while its body is
        // intentionally frozen behind an armed single-use witness.
        self.protected.body = Some(body);
        self.protected.pending_body = None;
        self.owner.dirty = false;
        if self.shutdown.needs_barrier() {
            self.shutdown_presented(frame);
        } else if self.development.needs_barrier() {
            self.development_presented(frame);
        } else if self.owner.needs_barrier() {
            self.arm_owner_after_present(frame);
        }
        Ok(())
    }
}
