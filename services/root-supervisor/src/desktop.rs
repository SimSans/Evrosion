//! Actual desktop Root policy in userspace. Kernel owns mechanisms and checks;
//! diagnostic markers never substitute for process/capability/read receipts.
use crate::fail;
#[cfg(not(feature = "native-root"))]
use core::num::NonZeroU64;
use ev_desktop::{
    compositor_policy::{Producer, SessionReset},
    protocol::{RootControl, ShellCommand},
};
use ev_graphics::shell::FileChoice;
use ev_picker::{
    AppId, AppRef, BootEpoch, Consent, ContentDigest, Delivery, Handoff, Incarnation, ObjectId,
    ObjectView, Origin, Persistence, Picker, PickerEpoch, ReadDelivery, Requester, Revision,
    SessionId, UserId, VolumeId,
};
use ev_userspace_contract::{
    root_v2::{
        self, Role,
        catalogue::Catalogue,
        graph::{self, Channel, Child, Source},
    },
    syscall,
};
use ev_userspace_runtime as rt;
#[cfg(feature = "native-root")]
#[path = "native/mod.rs"]
mod native;

enum Bootstrap<'a> {
    #[cfg(not(feature = "native-root"))]
    Desktop(root_v2::FullGraph<'a>),
    #[cfg(feature = "native-root")]
    Native(root_v2::native::FullGraph<'a>),
}
impl Bootstrap<'_> {
    #[cfg(feature = "native-root")]
    fn context(&self) -> ev_userspace_contract::Context {
        let Self::Native(b) = self;
        b.context()
    }
    fn handle(&self, role: Role) -> u64 {
        match self {
            #[cfg(not(feature = "native-root"))]
            Self::Desktop(b) => b.handle(role),
            #[cfg(feature = "native-root")]
            Self::Native(b) => b.handle(role),
        }
    }
}
const COUNT: usize = 6;
const GRANT_SELECTED: u64 = 41;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    process: u64,
    thread: u64,
}
#[derive(Clone, Copy)]
struct Actor {
    job: u64,
    control: u64,
    identity: Identity,
    ready: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    request: u32,
    app: Actor,
    ready: bool,
    queued: bool,
    file: Option<FileChoice>,
    ready_tick: u64,
    held_reported: bool,
    mode: PendingMode,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingMode {
    InteractivePicker,
    #[cfg(feature = "native-root")]
    OwnerConsent,
    #[cfg(feature = "native-root")]
    RememberedPolicy,
}
fn require(ok: bool, code: u64) {
    if !ok {
        fail(code);
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 900);
    r.value
}
fn value(n: u64, a: u64, b: u64, c: u64) -> u64 {
    let r = rt::call(n, a, b, c);
    require(r.status == 0 && r.capability == 0, 901);
    r.value
}
fn checked(n: u64, a: u64, b: u64, c: u64) {
    require(value(n, a, b, c) == 0, 902);
}
fn rpc(endpoint: u64, bytes: [u8; 8], deadline: u64) -> [u8; 8] {
    rt::rpc::call(endpoint, bytes, deadline).unwrap_or_else(|_| fail(903))
}
fn pause() {
    checked(syscall::YIELD, 0, 0, 0);
}
fn send(endpoint: u64, bytes: [u8; 8], bound: u64) {
    loop {
        let r = rt::send(endpoint, bytes);
        require(r.value == 0 && r.capability == 0, 904);
        match r.status {
            0 => return,
            2 => {
                require(now() < bound, 905);
                pause();
            }
            _ => fail(906),
        }
    }
}
fn identity(control: u64) -> Identity {
    let r = rt::call(syscall::PROCESS_IDENTITY, control, 0, 0);
    require(r.status == 0 && r.value != 0 && r.capability != 0, 907);
    Identity {
        process: r.value,
        thread: r.capability,
    }
}
struct Root<'a> {
    bootstrap: Bootstrap<'a>,
    catalogue: Catalogue<'a>,
    channels: [u64; 15],
    actors: [Option<Actor>; COUNT],
    bound: u64,
    app_epoch: u32,
    shell_epoch: u32,
    request: u32,
    pending: Option<Pending>,
    picker: Picker,
    owner: UserId,
    session: SessionId,
    boot: BootEpoch,
    last_cancel: bool,
    hide_pending: bool,
    launch_pending: bool,
    app_notified: bool,
    input_epoch: u32,
    shell_recovering: bool,
    #[cfg(feature = "native-root")]
    native: Option<&'a mut native::Controller<'a>>,
    #[cfg(feature = "native-root")]
    owned_launch: bool,
}
impl Root<'_> {
    fn deadline(&self) -> u64 {
        self.bound.checked_add(512).unwrap_or_else(|| fail(938))
    }
    fn source(&self, source: Source) -> u64 {
        match source {
            Source::Root(role) => self.bootstrap.handle(role),
            Source::Endpoint(channel) => self.channels[channel.index()],
        }
    }
    fn child(&self, child: Child) -> Actor {
        self.actors[child.index()].unwrap_or_else(|| fail(908))
    }
    fn image(&self, child: Child) -> u64 {
        #[cfg(feature = "native-root")]
        if self.native.is_some()
            && let Some(image) = self.native_system_image(child)
        {
            return image;
        }
        #[cfg(feature = "native-root")]
        if child == Child::App && self.native.is_some() {
            return self.native_image();
        }
        self.bootstrap.handle(child.image())
    }
    fn prepare(&mut self, child: Child) {
        require(self.actors[child.index()].is_none(), 909);
        let job = value(
            syscall::CREATE_JOB,
            self.bootstrap.handle(Role::CreatorJob),
            0,
            0,
        );
        require(job != 0, 910);
        let control = value(syscall::CREATE_PROCESS, job, self.image(child), 0);
        require(control != 0, 911);
        for (i, g) in graph::grants(child).iter().enumerate() {
            let grant = value(
                syscall::DELEGATE,
                control,
                self.source(g.source),
                i as u64 + 1,
            );
            require(grant != 0, 912);
        }
        for g in graph::grants(child) {
            if g.kind == 2
                && g.rights & 16 != 0
                && let Source::Endpoint(channel) = g.source
            {
                checked(
                    syscall::BIND_RECEIVER,
                    self.channels[channel.index()],
                    control,
                    0,
                );
            }
        }
        self.actors[child.index()] = Some(Actor {
            job,
            control,
            identity: Identity {
                process: 0,
                thread: 0,
            },
            ready: false,
        });
    }
    fn start(&mut self, child: Child) {
        let a = self.child(child);
        checked(syscall::START, a.control, 0, 0);
        self.actors[child.index()].as_mut().unwrap().identity = identity(a.control);
    }
    fn reset(&self, producer: Producer, epoch: u32) {
        let reset = SessionReset { producer, epoch };
        let reply = rpc(
            self.channels[Channel::RootSession.index()],
            reset.request().unwrap_or_else(|_| fail(913)),
            self.deadline(),
        );
        require(SessionReset::parse_reply(reply) == Ok(reset), 914);
    }
    fn control_shell(&self, message: RootControl) {
        send(
            self.channels[Channel::ShellControl.index()],
            message.encode().unwrap_or_else(|_| fail(915)),
            self.bound,
        );
    }
    fn control_app(&self, message: RootControl) {
        send(
            self.channels[Channel::AppControl.index()],
            message.encode().unwrap_or_else(|_| fail(916)),
            self.bound,
        );
    }
    fn wait_ready(&mut self, child: Child) {
        while !self.child(child).ready {
            self.tick();
        }
    }
    #[cfg(not(feature = "native-root"))]
    fn boot(&mut self) {
        for channel in graph::CHANNELS {
            self.channels[channel.index()] = value(
                syscall::CREATE_ENDPOINT,
                self.bootstrap.handle(Role::CreatorJob),
                0,
                0,
            );
            require(self.channels[channel.index()] != 0, 917);
        }
        for child in [
            Child::Display,
            Child::Block,
            Child::File,
            Child::Input,
            Child::Shell,
        ] {
            self.prepare(child);
        }
        self.start(Child::Display);
        self.wait_ready(Child::Display);
        self.reset(Producer::Shell, self.shell_epoch);
        self.start(Child::Block);
        self.wait_ready(Child::Block);
        self.start(Child::File);
        self.wait_ready(Child::File);
        self.start(Child::Input);
        self.wait_ready(Child::Input);
        self.start(Child::Shell);
        self.wait_ready(Child::Shell);
    }
    fn launch(&mut self) {
        #[cfg(feature = "native-root")]
        if self.native.is_some() {
            self.native_launch(true);
            return;
        }
        if self.actors[Child::App.index()].is_some() {
            return;
        }
        if self.hide_pending {
            self.launch_pending = true;
            return;
        }
        self.app_notified = false;
        self.app_epoch = self
            .app_epoch
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .unwrap_or_else(|| fail(918));
        self.prepare(Child::App);
        self.reset(Producer::App, self.app_epoch);
        self.start(Child::App);
    }
    fn metadata(&self, file: FileChoice) -> ObjectView {
        let (channel, local) = if file == FileChoice::Notes {
            (Channel::NotesRead, 1)
        } else {
            (Channel::PrivateRead, 2)
        };
        let cap = self.channels[channel.index()];
        let counter = u64::from_le_bytes(rpc(
            cap,
            ev_file::desktop::MetadataQuery::counter().encode(),
            self.deadline(),
        ));
        let mut digest = [0; 32];
        for index in 0..4u8 {
            let query = ev_file::desktop::MetadataQuery::digest_word(index).unwrap();
            digest[usize::from(index) * 8..usize::from(index + 1) * 8].copy_from_slice(&rpc(
                cap,
                query.encode(),
                self.deadline(),
            ));
        }
        let after = u64::from_le_bytes(rpc(
            cap,
            ev_file::desktop::MetadataQuery::counter().encode(),
            self.deadline(),
        ));
        require(counter == after && counter != u64::MAX, 919);
        ObjectView {
            object: ObjectId::new(VolumeId::new(*b"EVRO-USERS-VOL01").unwrap(), local).unwrap(),
            revision: Revision::new(
                counter,
                ContentDigest::new(digest).unwrap_or_else(|| fail(920)),
            )
            .unwrap(),
            permission_revision: 1,
            readable: true,
        }
    }
    fn app_package(&self) -> [u8; 32] {
        #[cfg(feature = "native-root")]
        if let Some(n) = &self.native {
            return n.running_package().unwrap_or_else(|| fail(939));
        }
        self.catalogue.package()
    }
    fn requester(&self, app: Actor) -> Requester {
        let observed = rt::call(syscall::OBSERVE, app.control, 0, 0);
        Requester {
            user: self.owner,
            session: self.session,
            app: AppRef {
                app: AppId::new(self.catalogue.app_id()).unwrap(),
                package: ContentDigest::new(self.app_package()).unwrap_or_else(|| fail(921)),
            },
            incarnation: Incarnation::new(self.boot, app.identity.process).unwrap(),
            policy_revision: 1,
            alive: observed.status == 0 && observed.value == 0,
        }
    }
    fn select(&mut self, request: u32, file: FileChoice) {
        let Some(mut pending) = self.pending else {
            return;
        };
        if pending.request != request
            || !pending.ready
            || pending.queued
            || pending.mode != PendingMode::InteractivePicker
        {
            return;
        }
        #[cfg(feature = "native-root")]
        if self.native_grants_fenced() {
            self.pending = None;
            self.control_app(RootControl::FileRefused(request));
            self.control_shell(RootControl::FileRefused(request));
            return;
        }
        let app = self.child(Child::App);
        if app.control != pending.app.control || app.identity != pending.app.identity {
            return;
        }
        let current = self.requester(app);
        let view = self.metadata(file);
        let approval = self
            .picker
            .prepare(
                current,
                view,
                Persistence::ThisIncarnation,
                now(),
                self.deadline(),
            )
            .unwrap_or_else(|_| fail(922));
        let consent = Consent {
            displayed_action: approval.selection().action_digest(),
            approver: self.owner,
            origin: Origin::TrustedPicker,
        };
        let channel = if file == FileChoice::Notes {
            Channel::NotesRead
        } else {
            Channel::PrivateRead
        };
        let mut handoff = Grant {
            process: app.control,
            parent: self.channels[channel.index()],
            inbox: self.channels[Channel::GrantInbox.index()],
            request,
            bound: self.bound,
        };
        match self.picker.commit(
            approval,
            consent,
            self.requester(app),
            self.metadata(file),
            now(),
            &mut handoff,
        ) {
            Ok(Delivery::Delivered(_ticket)) => {
                pending.queued = true;
                pending.file = Some(file);
                self.pending = Some(pending);
            }
            _ => {
                self.pending = None;
                self.control_app(RootControl::FileRefused(request));
                self.control_shell(RootControl::FileRefused(request));
            }
        }
    }
    fn shell(&mut self, bytes: [u8; 8]) {
        let command = ShellCommand::decode(bytes).unwrap_or_else(|_| fail(923));
        match command {
            ShellCommand::Launch => self.launch(),
            ShellCommand::Forward(key) => {
                if self.actors[Child::App.index()].is_some() {
                    send(
                        self.channels[Channel::AppControl.index()],
                        key.encode().unwrap_or_else(|_| fail(924)),
                        self.bound,
                    );
                }
            }
            ShellCommand::Select { request, file } => self.select(request, file),
            ShellCommand::Cancel(request) => {
                if self.pending.is_some_and(|p| {
                    p.request == request && !p.queued && p.mode == PendingMode::InteractivePicker
                }) {
                    self.pending = None;
                    self.last_cancel = true;
                    self.control_app(RootControl::FileRefused(request));
                }
            }
            ShellCommand::Repaint => {
                if self.actors[Child::App.index()].is_some() {
                    send(
                        self.channels[Channel::AppControl.index()],
                        ShellCommand::Repaint.encode().unwrap(),
                        self.bound,
                    );
                }
            }
            ShellCommand::ControlSettled(message) => {
                #[cfg(feature = "native-root")]
                if self.native.is_some() {
                    self.native_owner_settled(message);
                }
                #[cfg(feature = "native-root")]
                if self.native.is_some() {
                    self.native_settled(message);
                }
                match message {
                    RootControl::AppStopped(epoch) if epoch == self.app_epoch => {
                        self.hide_pending = false;
                        if self.launch_pending {
                            self.launch_pending = false;
                            self.launch();
                        }
                    }
                    RootControl::InputRestarted(epoch)
                        if epoch == self.input_epoch && self.shell_recovering =>
                    {
                        if self.actors[Child::App.index()].is_some() {
                            self.control_shell(RootControl::AppRestored(self.app_epoch));
                        } else {
                            self.shell_recovering = false;
                        }
                    }
                    RootControl::AppRestored(epoch) if epoch == self.app_epoch => {
                        self.shell_recovering = false;
                    }
                    _ => (),
                }
            }
            ShellCommand::PickerReady(_frame) => {
                if let Some(p) = self.pending.as_mut()
                    && !p.queued
                    && p.mode == PendingMode::InteractivePicker
                {
                    p.ready = true;
                    p.ready_tick = now();
                    p.held_reported = false;
                }
            }
        }
    }
    fn event(&mut self, child: Child, bytes: [u8; 8]) {
        #[cfg(feature = "native-root")]
        if self.native.is_some() && self.native_system_event(child, bytes) {
            return;
        }
        #[cfg(feature = "native-root")]
        if child == Child::App && self.native.is_some() && bytes[..2] == *b"ND" {
            self.native_data(bytes);
            return;
        }
        let ready = match child {
            Child::Display => *b"EVGDRDY1",
            Child::Block => *b"EVBLRDY1",
            Child::File => *b"EVFLRDY1",
            Child::Input => *b"EVINRDY1",
            Child::Shell => *b"EVSHRDY1",
            Child::App => *b"EVGARDY1",
        };
        if bytes == ready {
            self.actors[child.index()].as_mut().unwrap().ready = true;
            if child == Child::Shell && self.shell_recovering {
                self.control_shell(RootControl::InputRestarted(self.input_epoch));
            }
            return;
        }
        match child {
            Child::Shell if bytes[0] == b'S' || bytes[0] == b'K' => self.shell(bytes),
            Child::App if bytes == *b"EVGADON1" => {
                if self.child(Child::App).ready && !self.app_notified {
                    self.app_notified = true;
                    #[cfg(feature = "native-root")]
                    let message = if self.owned_launch {
                        RootControl::AppRestored(self.app_epoch)
                    } else {
                        RootControl::AppStarted(self.app_epoch)
                    };
                    #[cfg(not(feature = "native-root"))]
                    let message = RootControl::AppStarted(self.app_epoch);
                    self.control_shell(message);
                }
            }
            Child::App if bytes == *b"EVOPEN01" => {
                if self.pending.is_none() {
                    self.request = self
                        .request
                        .checked_add(1)
                        .filter(|n| *n != u32::MAX)
                        .unwrap_or_else(|| fail(925));
                    self.pending = Some(Pending {
                        request: self.request,
                        app: self.child(Child::App),
                        ready: false,
                        queued: false,
                        file: None,
                        ready_tick: 0,
                        held_reported: false,
                        mode: PendingMode::InteractivePicker,
                    });
                    #[cfg(feature = "native-root")]
                    if self.native.is_some() && self.native_owner_open() {
                        return;
                    }
                    self.control_shell(RootControl::PickFile(self.request));
                }
            }
            Child::App if bytes == *b"EVFILRD1" => {
                if let Some(p) = self.pending.filter(|p| p.queued) {
                    self.pending = None;
                    if !self.shell_recovering && {
                        #[cfg(feature = "native-root")]
                        {
                            !self.native_owner_suppress_file_completion()
                        }
                        #[cfg(not(feature = "native-root"))]
                        {
                            true
                        }
                    } {
                        self.control_shell(match p.mode {
                            PendingMode::InteractivePicker => RootControl::FileDelivered(p.request),
                            #[cfg(feature = "native-root")]
                            PendingMode::OwnerConsent => RootControl::OwnerFileDelivered(p.request),
                            #[cfg(feature = "native-root")]
                            PendingMode::RememberedPolicy => {
                                RootControl::ManagedFileDelivered(p.request)
                            }
                        });
                    }
                }
            }
            Child::App if bytes == *b"EVFLCAN1" && self.last_cancel => {
                self.last_cancel = false;
            }
            _ => (),
        }
    }
    fn receive(&mut self) {
        let r = rt::call4(
            syscall::RECEIVE_EVENT,
            self.bootstrap.handle(Role::Events),
            0,
            0,
            0,
        );
        if r.status == 2 {
            require(r.value == 0 && r.capability == 0 && r.serial == 0, 926);
            return;
        }
        require(r.status == 0 && r.capability != 0 && r.serial != 0, 927);
        let who = Identity {
            process: r.capability,
            thread: r.serial,
        };
        if let Some(child) = graph::CHILDREN
            .into_iter()
            .find(|c| self.actors[c.index()].is_some_and(|a| a.identity == who))
        {
            self.event(child, r.value.to_le_bytes());
        }
    }
    fn stopped(&mut self, child: Child) {
        #[cfg(feature = "native-root")]
        if self.native.is_some() && !self.native_diagnostic_stopped(child) {
            return;
        }
        let old = self.child(child);
        let mut record = [0; 6];
        for (i, field) in record.iter_mut().enumerate() {
            let r = rt::call(syscall::OBSERVE, old.control, i as u64 + 1, 0);
            if r.status == 0 {
                *field = r.value;
            }
        }
        loop {
            let r = rt::call(syscall::REAP, old.control, 0, 0);
            if r.status == 0 {
                break;
            }
            require(r.status == 2 && now() < self.bound, 928);
            pause();
        }
        checked(syscall::CLOSE, old.control, 0, 0);
        checked(syscall::CLOSE, old.job, 0, 0);
        #[cfg(feature = "native-root")]
        if self.native.is_some() {
            let denied = rt::call(syscall::JOB_INFO, old.job, 0, 0);
            require(
                denied.status == 1 && denied.value == 0 && denied.capability == 0,
                984,
            );
        }
        self.actors[child.index()] = None;
        #[cfg(feature = "native-root")]
        if self.native.is_some() {
            self.native_owner_stopped(child);
        }
        match child {
            Child::App => {
                self.pending = None;
                self.picker
                    .requester_died(Incarnation::new(self.boot, old.identity.process).unwrap());
                #[cfg(feature = "native-root")]
                let notify = self.native.is_none() || self.app_notified;
                #[cfg(not(feature = "native-root"))]
                let notify = true;
                if notify {
                    self.hide_pending = true;
                    self.control_shell(RootControl::AppStopped(self.app_epoch));
                }
                #[cfg(feature = "native-root")]
                if let Some(n) = self.native.as_mut() {
                    n.app_stopped();
                }

                {
                    let channel = Channel::GrantInbox;
                    checked(syscall::CLOSE, self.channels[channel.index()], 0, 0);
                    self.channels[channel.index()] = value(
                        syscall::CREATE_ENDPOINT,
                        self.bootstrap.handle(Role::CreatorJob),
                        0,
                        0,
                    );
                }
            }
            Child::Shell => {
                #[cfg(feature = "native-root")]
                if self.native.is_some() && self.native_system_child_stopped(child) {
                    return;
                }
                self.shell_recovering = true;
                if self.pending.is_some_and(|p| !p.queued) {
                    let p = self.pending.take().unwrap();
                    self.control_app(RootControl::FileRefused(p.request));
                }
                self.shell_epoch = self
                    .shell_epoch
                    .checked_add(1)
                    .filter(|n| *n != u32::MAX)
                    .unwrap_or_else(|| fail(929));
                self.prepare(Child::Shell);
                self.reset(Producer::Shell, self.shell_epoch);
                self.start(Child::Shell);
                // Continue through the ordinary event loop: waiting recursively
                // here would retain another controller stack on every fault.
            }
            _ => {
                let _ = record;
                fail(930);
            }
        }
    }
    fn tick(&mut self) {
        require(now() < self.bound, 931);
        self.receive();
        for child in graph::CHILDREN {
            if let Some(actor) = self.actors[child.index()]
                && actor.identity.process != 0
            {
                let r = rt::call(syscall::OBSERVE, actor.control, 0, 0);
                require(r.status == 0 && r.value <= 1, 932);
                if r.value == 1 {
                    self.stopped(child);
                }
            }
        }
        let tick = now();
        if let Some(p) = self.pending.as_mut()
            && p.ready
            && p.mode == PendingMode::InteractivePicker
            && !p.queued
            && !p.held_reported
            && tick.saturating_sub(p.ready_tick) >= 64
        {
            // This is our own receive mailbox. Busy must return to the
            // ordinary receive loop, never wait here for ourselves to drain it.
            let r = rt::send(self.bootstrap.handle(Role::Events), *b"EVHOLD01");
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                904,
            );
            if r.status == 0 {
                p.held_reported = true;
            }
        }
        #[cfg(feature = "native-root")]
        if self.native.is_some() {
            self.native_tick();
        }
        #[cfg(not(feature = "native-root"))]
        self.desktop_uart_tick();
        pause();
    }
    #[cfg(not(feature = "native-root"))]
    fn desktop_uart_tick(&mut self) {
        // Explicit owner diagnostic route only; no byte approves a File grant.
        let uart = self.bootstrap.handle(Role::OwnerUart);
        let status = rt::call4(syscall::PORT_INPUT, uart, 0x3fd, 1, 0);
        require(
            status.status == 0
                && status.capability == 0
                && status.serial == 0
                && status.value <= 255,
            933,
        );
        if status.value & 1 != 0 {
            let byte = rt::call4(syscall::PORT_INPUT, uart, 0x3f8, 1, 0);
            require(
                byte.status == 0 && byte.capability == 0 && byte.serial == 0,
                934,
            );
            if byte.value == u64::from(b's') && self.actors[Child::Shell.index()].is_some() {
                self.control_shell(RootControl::CrashShell);
            }
        }
    }
}
struct Grant {
    process: u64,
    parent: u64,
    inbox: u64,
    request: u32,
    bound: u64,
}
impl Handoff for Grant {
    type Delivered = u64;
    type Error = u64;
    fn revalidate_and_deliver_read(&mut self, _: ReadDelivery<'_>) -> Delivery<u64, u64> {
        loop {
            if now() >= self.bound {
                return Delivery::Refused(4);
            }
            let r = rt::call4(
                GRANT_SELECTED,
                self.process,
                self.parent,
                self.inbox,
                u64::from(self.request),
            );
            match r.status {
                0 if r.value != 0 && r.capability == 0 && r.serial == 0 => {
                    return Delivery::Delivered(r.value);
                }
                2 if r.value == 0 && r.capability == 0 && r.serial == 0 => pause(),
                1 | 3 => return Delivery::Refused(r.status),
                _ => return Delivery::Indeterminate(r.status),
            }
        }
    }
}
/// # Safety
/// Named RootV2 ABI supplies actual retained readonly720 startup +1536 catalogue
/// at page507. Both are bounded below before any raw read; mappings remain owned.
#[cfg(not(feature = "native-root"))]
pub unsafe fn run(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == root_v2::SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record >= 2 * 4096
            && bound != 0
            && bound != u64::MAX,
        935,
    );
    // SAFETY: exact named RootV2 startup page, retained by Kernel owned image.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, root_v2::SIZE) };
    let bootstrap = root_v2::FullGraph::parse(bytes).unwrap_or_else(|_| fail(936));
    // SAFETY: independently verified readonly catalogue at fixed page507; no
    // AppFile shared page is ever aliased or read by this controller.
    let catbytes = unsafe {
        core::slice::from_raw_parts((record - 2 * 4096) as *const u8, root_v2::catalogue::SIZE)
    };
    let catalogue = ev_root_supervisor::desktop_plan::verify(catbytes, bootstrap.context())
        .unwrap_or_else(|_| fail(937));
    let context = bootstrap.context();
    let mut epoch = [0; 16];
    epoch[..8].copy_from_slice(&context.epoch.to_le_bytes());
    epoch[8..].copy_from_slice(&context.incarnation.to_le_bytes());
    let _ = NonZeroU64::new(context.process).unwrap();
    let owner = UserId::new(*b"EVROSION-OWNER01").unwrap();
    let mut root = Root {
        bootstrap: Bootstrap::Desktop(bootstrap),
        catalogue,
        channels: [0; 15],
        actors: [None; COUNT],
        bound,
        app_epoch: 0,
        shell_epoch: 1,
        request: 0,
        pending: None,
        picker: Picker::new(PickerEpoch::new(epoch).unwrap(), 131072).unwrap(),
        owner,
        session: SessionId::new(epoch).unwrap(),
        boot: BootEpoch::new(epoch).unwrap(),
        last_cancel: false,
        hide_pending: false,
        launch_pending: false,
        app_notified: false,
        input_epoch: 1,
        shell_recovering: false,
        #[cfg(feature = "native-root")]
        native: None,
        #[cfg(feature = "native-root")]
        owned_launch: false,
    };
    root.boot();
    loop {
        root.tick();
    }
}

/// # Safety
/// The named Native Root loader owns exact720/2048 startup/catalogue, both
/// readonly package banks and the sole System window through process lifetime.
#[cfg(feature = "native-root")]
pub unsafe fn run_native(record: u64, length: u64, bound: u64) -> ! {
    // SAFETY: caller supplies the named Native mapping contract; callee checks it.
    unsafe { native::run(record, length, bound) }
}
