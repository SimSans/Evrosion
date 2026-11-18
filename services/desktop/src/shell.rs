//! Trusted Shell adapter. Each input/control channel is an independently
//! installed fixed endpoint. Present and freshness barriers use protected RPC;
//! no pixel, message epoch or boolean is converted into a File capability here.
#[cfg(not(feature = "native-session"))]
use crate::event;
use crate::{grant, now, require, surface::Surface, yield_now};
#[cfg(feature = "native-session")]
use ev_desktop::shell_delivery::{Error as DeliveryError, Kind as DeliveryKind, Outbox};
use ev_desktop::{
    protocol::{CursorControl, RootControl, ShellCommand, WindowControl},
    shell_policy::{Effects, Policy, RootEvent},
};
#[cfg(feature = "native-session")]
use ev_graphics::shell::DeliveryNotice;
use ev_graphics::{Present, shell::Screen};
use ev_input::{
    BarrierReply, BarrierRequest, KeyEvent, SessionBarrierReply, SessionBarrierRequest,
};
use ev_userspace_runtime as rt;

struct Channels {
    #[cfg(feature = "document-workflow")]
    document_access: core::cell::Cell<ev_userspace_contract::document::Access>,
    present: u64,
    keys: u64,
    control: u64,
    commands: u64,
    barrier: u64,
    window: u64,
    events: u64,
    stop: u64,
    #[cfg(feature = "native-session")]
    delivery: core::cell::RefCell<Outbox>,
}
impl Channels {
    fn before(&self) {
        require(rt::execution::live(self.stop, now()), 780);
    }
    #[cfg(not(feature = "native-session"))]
    fn send(&self, cap: u64, bytes: [u8; 8]) {
        let retry_stop = if self.stop == 0 {
            rt::execution::deadline(self.stop, now(), 512).unwrap_or_else(|_| rt::exit(780))
        } else {
            self.stop
        };
        loop {
            self.before();
            require(now() < retry_stop, 780);
            let r = rt::send(cap, bytes);
            require(r.value == 0 && r.capability == 0, 781);
            match r.status {
                0 => return,
                2 => yield_now(),
                _ => rt::exit(782),
            }
        }
    }
    fn rpc(&self, cap: u64, bytes: [u8; 8]) -> [u8; 8] {
        self.before();
        let deadline = rt::execution::deadline(self.stop, now(), 512)
            .ok()
            .unwrap_or_else(|| rt::exit(804));
        let reply = rt::rpc::call(cap, bytes, deadline).unwrap_or_else(|_| rt::exit(783));
        self.before();
        reply
    }
    fn receive(&self, cap: u64) -> Option<[u8; 8]> {
        self.before();
        let r = rt::receive(cap);
        require(r.capability == 0, 784);
        match r.status {
            0 => Some(r.value.to_le_bytes()),
            2 if r.value == 0 => None,
            _ => rt::exit(785),
        }
    }
    fn command(&self, command: ShellCommand) {
        #[cfg(feature = "native-session")]
        {
            let kind = match command {
                ShellCommand::Forward(_) | ShellCommand::Text(_) | ShellCommand::Pointer(_) => {
                    DeliveryKind::Input
                }
                ShellCommand::Repaint => DeliveryKind::Repaint,
                ShellCommand::Cancel(_) => DeliveryKind::Cancel,
                ShellCommand::ControlSettled(_) => DeliveryKind::Settled,
                ShellCommand::PickerReady(_) => DeliveryKind::PickerReady,
                _ => DeliveryKind::Action,
            };
            self.enqueue(
                self.commands,
                command.encode().unwrap_or_else(|_| rt::exit(786)),
                kind,
            );
        }
        #[cfg(not(feature = "native-session"))]
        self.send(
            self.commands,
            command.encode().unwrap_or_else(|_| rt::exit(786)),
        );
    }
    #[cfg(feature = "native-session")]
    fn enqueue(&self, endpoint: u64, bytes: [u8; 8], kind: DeliveryKind) {
        let mut delivery = self.delivery.borrow_mut();
        if let Err(error) = delivery.enqueue(endpoint, bytes, kind, now())
            && error != DeliveryError::Degraded
        {
            delivery.fail(error);
        }
    }
    #[cfg(feature = "native-session")]
    fn delivery_tick(&self) {
        let entry = self.delivery.borrow().next_attempt();
        let Some(entry) = entry else { return };
        let at = now();
        if at >= entry.cut {
            self.delivery
                .borrow_mut()
                .complete(entry, Some(DeliveryError::Expired));
            return;
        }
        let reply = rt::send(entry.endpoint, entry.bytes);
        require(reply.value == 0 && reply.capability == 0, 781);
        match reply.status {
            0 => {
                self.delivery.borrow_mut().complete(entry, None);
            }
            2 => (), // Definitely unaccepted: original bytes and cut remain.
            _ => {
                self.delivery
                    .borrow_mut()
                    .complete(entry, Some(DeliveryError::Refused));
            }
        }
    }
    fn effects(
        &self,
        policy: &mut Policy,
        surface: &mut Surface,
        effects: Effects,
        control: Option<RootControl>,
    ) -> bool {
        self.apply(policy, surface, effects, control, None, true)
    }
    fn apply(
        &self,
        policy: &mut Policy,
        surface: &mut Surface,
        effects: Effects,
        control: Option<RootControl>,
        notice: Option<ev_graphics::shell::DeliveryNotice>,
        rearm: bool,
    ) -> bool {
        let mut fresh = false;
        let mut repaint = false;
        if let Some(render) = effects.render {
            #[cfg(feature = "native-session")]
            if rearm {
                // A footer-only Busy frame uses rearm=false so it does not
                // silently cancel the input already buffered for this context.
                self.delivery.borrow_mut().context_changed(false);
            }
            if cfg!(feature = "native-session") {
                ev_graphics::shell::render_session(surface, render.screen)
            } else {
                ev_graphics::shell::render(surface, render.screen)
            }
            .unwrap_or_else(|_| rt::exit(787));
            #[cfg(feature = "document-workflow")]
            ev_graphics::shell::document_intent(surface, render.screen, self.document_access.get())
                .unwrap_or_else(|_| rt::exit(787));
            #[cfg(feature = "native-owner-ui")]
            if render.screen == Screen::Home {
                ev_graphics::connection::entry(surface).unwrap_or_else(|_| rt::exit(787));
            }
            if let Some(notice) = notice {
                ev_graphics::shell::delivery_notice(surface, notice)
                    .unwrap_or_else(|_| rt::exit(787));
            }
            surface.publish(u64::from(render.frame));
            surface.tail();
            require(surface.header().sequence == u64::from(render.frame), 802);
            let window = WindowControl {
                visible: render.screen == Screen::AppRunning,
                sequence: render.frame,
            };
            let ack = self.rpc(self.window, window.request().unwrap());
            require(WindowControl::parse_reply(ack) == Ok(window), 788);
            let present = Present(render.frame);
            let ack = self.rpc(self.present, present.request().unwrap());
            require(Present::parse_reply(ack) == Ok(present), 789);
            // Only an actual matching protected reply permits the barrier. A
            // queued Present, marker or stale nonce cannot arm picker input.
            let displayed = if rearm {
                policy
                    .displayed(render.frame)
                    .unwrap_or_else(|_| rt::exit(790))
            } else {
                Effects::default()
            };
            if let Some(frame) = displayed.barrier_after_frame {
                if cfg!(feature = "native-session") {
                    let request = SessionBarrierRequest::new(frame).unwrap().encode();
                    let reply = SessionBarrierReply::decode(self.rpc(self.barrier, request))
                        .unwrap_or_else(|_| rt::exit(791));
                    policy
                        .session_barrier(frame, reply)
                        .unwrap_or_else(|_| rt::exit(792));
                    fresh = true;
                } else {
                    let request = BarrierRequest::new(frame).unwrap().encode();
                    let reply = BarrierReply::decode(self.rpc(self.barrier, request))
                        .unwrap_or_else(|_| rt::exit(791));
                    policy
                        .barrier(frame, reply)
                        .unwrap_or_else(|_| rt::exit(792));
                }
                if notice.is_none() && matches!(render.screen, Screen::Picker { .. }) {
                    self.command(ShellCommand::PickerReady(frame));
                }
            }
            if window.visible && rearm && notice.is_none() {
                // Never sample a runnable App's old surface to restore content.
                // Root requests another real App Present after the chrome ACK.
                repaint = true;
            }
        }
        if let Some(cursor) = effects.cursor {
            let reply = self.rpc(
                self.window,
                cursor.request().unwrap_or_else(|_| rt::exit(788)),
            );
            require(CursorControl::parse_reply(reply) == Ok(cursor), 788);
        }
        if let Some(command) = effects.command {
            self.command(ShellCommand::from_policy(command));
        }
        if !cfg!(feature = "native-session")
            && matches!(control, Some(RootControl::InputRestarted(_)))
        {
            let frame = effects.render.unwrap_or_else(|| rt::exit(805)).frame;
            let request = BarrierRequest::new(frame).unwrap().encode();
            let reply = BarrierReply::decode(self.rpc(self.barrier, request))
                .unwrap_or_else(|_| rt::exit(806));
            policy
                .input_drained(reply)
                .unwrap_or_else(|_| rt::exit(807));
        }
        if let Some(control) = control {
            self.command(ShellCommand::ControlSettled(control));
        }
        if repaint {
            self.command(ShellCommand::Repaint);
        }
        fresh
    }
}
fn bind(cap: u64) {
    let r = rt::call(rt::syscall::BIND_RECEIVER, cap, 0, 0);
    require(r.status == 0 && r.value == 0 && r.capability == 0, 793);
}
pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    require(b.grants().count() == 8, 794);
    let memory = grant(b, 1, 1, 7);
    let channels = Channels {
        #[cfg(feature = "document-workflow")]
        document_access: core::cell::Cell::new(ev_userspace_contract::document::Access::None),
        present: grant(b, 2, 2, 8),
        keys: grant(b, 3, 2, 272),
        control: grant(b, 4, 2, 272),
        commands: grant(b, 5, 2, 8),
        barrier: grant(b, 6, 2, 8),
        window: grant(b, 7, 2, 8),
        events: grant(b, 8, 2, 8),
        stop,
        #[cfg(feature = "native-session")]
        delivery: core::cell::RefCell::new(Outbox::new()),
    };
    let info = rt::inspect(memory, 1);
    require(info.status == 0 && info.capability == 0, 795);
    bind(channels.keys);
    bind(channels.control);
    #[cfg(feature = "native-owner-ui")]
    let mut policy = Policy::with_owner_ui();
    #[cfg(not(feature = "native-owner-ui"))]
    let mut policy = if cfg!(feature = "native-session") {
        Policy::with_pointer()
    } else {
        Policy::new()
    };
    let mut surface = Surface::at(record);
    let mut app_epoch = None;
    let effects = policy.initial().unwrap();
    channels.effects(&mut policy, &mut surface, effects, None);
    #[cfg(feature = "native-session")]
    {
        channels.enqueue(channels.events, *b"EVSHRDY1", DeliveryKind::Ready);
        if cfg!(feature = "native-shell") {
            channels.enqueue(channels.events, *b"EVSHCRD1", DeliveryKind::Ready);
        }
    }
    #[cfg(not(feature = "native-session"))]
    {
        event(channels.events, *b"EVSHRDY1", channels.stop);
        if cfg!(feature = "native-shell") {
            event(channels.events, *b"EVSHCRD1", channels.stop);
        }
    }
    #[cfg(feature = "native-session")]
    let mut busy_view = false;
    loop {
        channels.before();
        // Process lifecycle changes before queued input. Root is responsible
        // for purging the old Input sender before publishing InputRestarted.
        let control = channels.receive(channels.control);
        #[cfg(feature = "network-negative-worker")]
        let control = if control == Some(*b"EVNWORK1") {
            // A bounded legitimate worker turn preserves ordinary Input/UI
            // handling below, with unchanged64/256 periodic scheduling.
            let mut value = 1u64;
            for _ in 0..1_048_576 {
                value = value.wrapping_mul(6364136223846793005).wrapping_add(1);
                core::hint::black_box(value);
            }
            None
        } else {
            control
        };
        if let Some(bytes) = control {
            let message = RootControl::decode(bytes).unwrap_or_else(|_| rt::exit(796));
            if message == RootControl::CrashShell {
                #[cfg(not(feature = "native-session"))]
                event(channels.events, *b"EVSHFLT1", channels.stop);
                let address = record - 509 * 4096 + 4 * 1024 * 1024;
                // SAFETY: an explicit Root-only diagnostic command requests a
                // real contained Shell user fault at its absent device aperture.
                // Root already owns this process's CONTROL; no new authority.
                let value = unsafe { (address as *const u32).read_volatile() };
                rt::exit(803 + u64::from(value));
            }
            let current = || app_epoch.unwrap_or_else(|| rt::exit(797));
            let event = match message {
                #[cfg(feature = "document-workflow")]
                RootControl::DocumentPicker { request, access } => {
                    channels.document_access.set(access);
                    RootEvent::PickFile {
                        request,
                        app_epoch: current(),
                    }
                }
                RootControl::AppStarted(epoch) => RootEvent::AppStarted {
                    epoch: u64::from(epoch),
                },
                RootControl::AppRestored(epoch) => RootEvent::AppRestored {
                    epoch: u64::from(epoch),
                },
                RootControl::AppStopped(epoch) => RootEvent::AppStopped {
                    epoch: u64::from(epoch),
                },
                RootControl::PickFile(request) => {
                    #[cfg(feature = "document-workflow")]
                    channels
                        .document_access
                        .set(ev_userspace_contract::document::Access::Read);
                    RootEvent::PickFile {
                        request,
                        app_epoch: current(),
                    }
                }
                RootControl::FileDelivered(request) => RootEvent::FileDelivered {
                    request,
                    app_epoch: current(),
                },
                RootControl::FileRefused(request) => RootEvent::FileRefused {
                    request,
                    app_epoch: current(),
                },
                RootControl::InputRestarted(_) => RootEvent::InputRestarted,
                RootControl::LaunchRefused => RootEvent::LaunchRefused,
                RootControl::OwnerFilePending(request) => RootEvent::OwnerFilePending {
                    request,
                    app_epoch: current(),
                },
                RootControl::OwnerFileDelivered(request) => RootEvent::OwnerFileDelivered {
                    request,
                    app_epoch: current(),
                },
                RootControl::OwnerFileRefused(request) => RootEvent::OwnerFileRefused {
                    request,
                    app_epoch: current(),
                },
                RootControl::ManagedFilePending(request) => RootEvent::ManagedFilePending {
                    request,
                    app_epoch: current(),
                },
                RootControl::ManagedFileDelivered(request) => RootEvent::ManagedFileDelivered {
                    request,
                    app_epoch: current(),
                },
                RootControl::ManagedFileRefused(request) => RootEvent::ManagedFileRefused {
                    request,
                    app_epoch: current(),
                },
                RootControl::OwnerActionPending(serial) => RootEvent::OwnerActionPending {
                    serial,
                    app_epoch: current(),
                },
                RootControl::OwnerActionDone(serial) => RootEvent::OwnerActionDone {
                    serial,
                    app_epoch: current(),
                },
                #[cfg(feature = "native-owner-ui")]
                RootControl::Connection(word) => RootEvent::Connection(
                    ev_desktop::owner_ui::Presentation::decode(word)
                        .unwrap_or_else(|_| rt::exit(796)),
                ),
                RootControl::CrashShell => unreachable!(),
            };
            let effects = match policy.root(event) {
                Ok(effects) => effects,
                // A completed old request can arrive after a replacement. It
                // carries no new authority and cannot affect the current UI.
                Err(ev_desktop::shell_policy::Error::Stale) => continue,
                Err(_) => rt::exit(798),
            };
            match message {
                RootControl::AppStarted(epoch) | RootControl::AppRestored(epoch) => {
                    app_epoch = Some(u64::from(epoch))
                }
                RootControl::AppStopped(_) => app_epoch = None,
                _ => {}
            }
            #[cfg(feature = "native-session")]
            {
                channels.delivery.borrow_mut().context_changed(true);
                channels.delivery.borrow_mut().take_failure();
                let fresh = channels.effects(&mut policy, &mut surface, effects, Some(message));
                if fresh && !channels.delivery.borrow().failure_pending() {
                    channels
                        .delivery
                        .borrow_mut()
                        .recovered_after_fresh_context();
                }
                busy_view = false;
                channels.delivery_tick();
            }
            #[cfg(not(feature = "native-session"))]
            channels.effects(&mut policy, &mut surface, effects, Some(message));
            continue;
        }
        #[cfg(feature = "native-session")]
        {
            channels.delivery_tick();
            let failed = channels.delivery.borrow_mut().take_failure().is_some();
            if failed {
                channels.delivery.borrow_mut().context_changed(true);
                let effects = policy
                    .delivery_redraw(true)
                    .unwrap_or_else(|_| rt::exit(798));
                channels.apply(
                    &mut policy,
                    &mut surface,
                    effects,
                    None,
                    Some(DeliveryNotice::Degraded),
                    true,
                );
                busy_view = false;
            }
            let (room, pending, degraded) = {
                let d = channels.delivery.borrow();
                (d.input_room(), d.input_pending(), d.degraded())
            };
            if !degraded && !room && !busy_view {
                let effects = policy
                    .delivery_redraw(false)
                    .unwrap_or_else(|_| rt::exit(798));
                channels.apply(
                    &mut policy,
                    &mut surface,
                    effects,
                    None,
                    Some(DeliveryNotice::Busy),
                    false,
                );
                busy_view = true;
            }
            if busy_view {
                if pending || !room {
                    yield_now();
                    continue;
                }
                let effects = policy
                    .delivery_redraw(true)
                    .unwrap_or_else(|_| rt::exit(798));
                channels.effects(&mut policy, &mut surface, effects, None);
                busy_view = false;
            }
            if degraded {
                if let Some(bytes) = channels.receive(channels.keys)
                    && let Ok(event) = KeyEvent::decode(bytes)
                    && let Ok(effects) = policy.delivery_home(event)
                {
                    channels.delivery.borrow_mut().context_changed(true);
                    // This is explicit new owner input, not a retry of any old
                    // accepted operation or an automatically renewed approval.
                    let fresh = channels.effects(&mut policy, &mut surface, effects, None);
                    if fresh && !channels.delivery.borrow().failure_pending() {
                        channels
                            .delivery
                            .borrow_mut()
                            .recovered_after_fresh_context();
                    }
                }
                yield_now();
                continue;
            }
            if !room {
                yield_now();
                continue;
            }
        }
        if let Some(bytes) = channels.receive(channels.keys) {
            let effects = match if cfg!(feature = "native-session") && bytes[0] == b'P' {
                policy.pointer(
                    ev_input::pointer::PointerEvent::decode(bytes)
                        .unwrap_or_else(|_| rt::exit(800)),
                )
            } else if cfg!(feature = "native-session") && bytes[0] == b'T' {
                policy.text(
                    ev_input::text::TextEvent::decode(bytes).unwrap_or_else(|_| rt::exit(800)),
                )
            } else {
                policy.key(KeyEvent::decode(bytes).unwrap_or_else(|_| rt::exit(800)))
            } {
                Ok(effects) => effects,
                Err(ev_desktop::shell_policy::Error::Stale) => continue,
                Err(_) => rt::exit(801),
            };
            channels.effects(&mut policy, &mut surface, effects, None);
        }
        yield_now();
    }
}
