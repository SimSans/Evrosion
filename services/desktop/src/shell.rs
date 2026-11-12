//! Trusted Shell adapter. Each input/control channel is an independently
//! installed fixed endpoint. Present and freshness barriers use protected RPC;
//! no pixel, message epoch or boolean is converted into a File capability here.
use crate::{event, grant, now, require, surface::Surface, yield_now};
use ev_desktop::{
    protocol::{RootControl, ShellCommand, WindowControl},
    shell_policy::{Effects, Policy, RootEvent},
};
use ev_graphics::{Present, shell::Screen};
use ev_input::{BarrierReply, BarrierRequest, KeyEvent};
use ev_userspace_runtime as rt;

struct Channels {
    present: u64,
    keys: u64,
    control: u64,
    commands: u64,
    barrier: u64,
    window: u64,
    events: u64,
    stop: u64,
}
impl Channels {
    fn before(&self) {
        require(now() < self.stop, 780);
    }
    fn send(&self, cap: u64, bytes: [u8; 8]) {
        loop {
            self.before();
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
        let deadline = self.stop.checked_add(512).unwrap_or_else(|| rt::exit(804));
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
        self.send(
            self.commands,
            command.encode().unwrap_or_else(|_| rt::exit(786)),
        );
    }
    fn effects(
        &self,
        policy: &mut Policy,
        surface: &mut Surface,
        effects: Effects,
        control: Option<RootControl>,
    ) {
        let mut repaint = false;
        if let Some(render) = effects.render {
            ev_graphics::shell::render(surface, render.screen).unwrap_or_else(|_| rt::exit(787));
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
            let displayed = policy
                .displayed(render.frame)
                .unwrap_or_else(|_| rt::exit(790));
            if let Some(frame) = displayed.barrier_after_frame {
                let request = BarrierRequest::new(frame).unwrap().encode();
                let reply = BarrierReply::decode(self.rpc(self.barrier, request))
                    .unwrap_or_else(|_| rt::exit(791));
                policy
                    .barrier(frame, reply)
                    .unwrap_or_else(|_| rt::exit(792));
                self.command(ShellCommand::PickerReady(frame));
            }
            if window.visible {
                // Never sample a runnable App's old surface to restore content.
                // Root requests another real App Present after the chrome ACK.
                repaint = true;
            }
        }
        if let Some(command) = effects.command {
            self.command(ShellCommand::from_policy(command));
        }
        if matches!(control, Some(RootControl::InputRestarted(_))) {
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
        present: grant(b, 2, 2, 8),
        keys: grant(b, 3, 2, 272),
        control: grant(b, 4, 2, 272),
        commands: grant(b, 5, 2, 8),
        barrier: grant(b, 6, 2, 8),
        window: grant(b, 7, 2, 8),
        events: grant(b, 8, 2, 8),
        stop,
    };
    let info = rt::inspect(memory, 1);
    require(info.status == 0 && info.capability == 0, 795);
    bind(channels.keys);
    bind(channels.control);
    let mut policy = Policy::new();
    let mut surface = Surface::at(record);
    let mut app_epoch = None;
    let effects = policy.initial().unwrap();
    channels.effects(&mut policy, &mut surface, effects, None);
    event(channels.events, *b"EVSHRDY1", channels.stop);
    if cfg!(feature = "native-shell") {
        event(channels.events, *b"EVSHCRD1", channels.stop);
    }
    loop {
        channels.before();
        // Process lifecycle changes before queued input. Root is responsible
        // for purging the old Input sender before publishing InputRestarted.
        if let Some(bytes) = channels.receive(channels.control) {
            let message = RootControl::decode(bytes).unwrap_or_else(|_| rt::exit(796));
            if message == RootControl::CrashShell {
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
                RootControl::AppStarted(epoch) => RootEvent::AppStarted {
                    epoch: u64::from(epoch),
                },
                RootControl::AppRestored(epoch) => RootEvent::AppRestored {
                    epoch: u64::from(epoch),
                },
                RootControl::AppStopped(epoch) => RootEvent::AppStopped {
                    epoch: u64::from(epoch),
                },
                RootControl::PickFile(request) => RootEvent::PickFile {
                    request,
                    app_epoch: current(),
                },
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
            channels.effects(&mut policy, &mut surface, effects, Some(message));
            continue;
        }
        if let Some(bytes) = channels.receive(channels.keys) {
            let key = KeyEvent::decode(bytes).unwrap_or_else(|_| rt::exit(800));
            let effects = match policy.key(key) {
                Ok(effects) => effects,
                Err(ev_desktop::shell_policy::Error::Stale) => continue,
                Err(_) => rt::exit(801),
            };
            channels.effects(&mut policy, &mut surface, effects, None);
        }
        yield_now();
    }
}
