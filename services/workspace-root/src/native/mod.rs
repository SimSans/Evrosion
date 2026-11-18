//! Actual V5 startup, lifecycle, protected pixels and input broker. Kernel
//! identities are captured through installed controls, never packet fields.
use ev_userspace_contract::{
    root_v5::{
        self as v5, FullGraph, Role,
        catalogue::Catalogue,
        graph::{self, Channel, Child, Source},
    },
    syscall as s,
};
use ev_userspace_runtime as rt;
use ev_workspace_client::ui::{Command, Event, State as AppState};
use ev_workspace_root::{
    Actor, Identity, app_child, child_slot, control_channel, policy::Policy, ready_bytes,
};
use ev_workspace_shell::Layer;
mod app_data;
mod development;
mod display;
mod filegrant;
mod input;
mod inspector;
mod inspector_self;
mod owner;
mod packages;
mod recovery;
mod resident;
mod semantic;
mod shutdown;
mod workspace;
use display::Protected;
use input::Input;
use owner::OwnerFlow;
use workspace::Workspace;
pub(super) const BASE: usize = 1 << 39;
pub(super) fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code);
    }
}
pub(super) fn now() -> u64 {
    let r = rt::monotonic();
    require(
        r.status == 0 && r.capability == 0 && r.value != u64::MAX,
        1600,
    );
    r.value
}
pub(super) fn value(n: u64, a: u64, b: u64, c: u64) -> u64 {
    let r = rt::call(n, a, b, c);
    require(r.status == 0 && r.capability == 0, 1601);
    r.value
}
pub(super) fn checked(n: u64, a: u64, b: u64, c: u64) {
    require(value(n, a, b, c) == 0, 1602);
}
pub(super) fn deadline(span: u64) -> u64 {
    now()
        .checked_add(span)
        .filter(|v| *v != u64::MAX)
        .unwrap_or_else(|| rt::exit(1603))
}
fn identity(control: u64, registered: u64) -> Identity {
    let r = rt::call4(s::PROCESS_IDENTITY, control, 0, 0, 0);
    require(r.status == 0 && r.value != 0 && r.capability != 0, 1604);
    Identity {
        process: r.value,
        thread: r.capability,
        registered,
    }
}
pub(super) fn send(endpoint: u64, bytes: [u8; 8]) -> Result<bool, ()> {
    let r = rt::send(endpoint, bytes);
    require(r.value == 0 && r.capability == 0, 1605);
    match r.status {
        0 => Ok(true),
        2 => Ok(false),
        1 | 3 => Err(()),
        _ => rt::exit(1606),
    }
}
pub(super) struct Root<'a> {
    bootstrap: FullGraph<'a>,
    catalogue: Catalogue<'a>,
    channels: [u64; 23],
    actors: [Option<Actor>; 11],
    policy: Option<Policy>,
    protected: Protected,
    workspace: Workspace,
    input: Input,
    owner: OwnerFlow,
    inspector: inspector::Snapshot,
    inspector_self: &'static mut inspector_self::State,
    semantic: &'static mut semantic::State,
    shutdown: shutdown::Controller,
    private_data: app_data::State,
    development: development::Controller,
    recovery: recovery::State,
    shell_gesture: Option<(u8, Identity, u64, u64)>,
    outbox: ev_workspace_root::outbox::Outbox,
    next_control: u64,
    registration: u64,
    states: [Option<AppState>; 4],
    leases: [Option<filegrant::Lease>; 4],
    paused: [Option<ev_workspace_client::ui::ReleaseMode>; 4],
    file_may_be_held: [bool; 4],
    grant: Option<filegrant::Pending>,
    next_release: u32,
    next_lease: u64,
    lease_rights: [u8; 4],
    closing: [bool; 4],
    relaunch: [bool; 4],
    scene_dirty: bool,
    status: &'static [u8],
    last_refusal: Option<ev_workspace_root::render::Refusal>,
    bound: u64,
}
impl Root<'_> {
    fn channel(&self, c: Channel) -> u64 {
        self.channels[c.index()]
    }
    fn actor(&self, c: Child) -> Actor {
        self.actors[c.index()].unwrap_or_else(|| rt::exit(1607))
    }
    fn source(&self, source: Source) -> u64 {
        match source {
            Source::Root(role) => self.bootstrap.handle(role),
            Source::Endpoint(c) => self.channel(c),
        }
    }
    fn prepare(&mut self, child: Child) {
        require(self.actors[child.index()].is_none(), 1608);
        let job = value(
            s::CREATE_JOB,
            self.bootstrap.handle(Role::CreatorJob),
            child.job_template(),
            0,
        );
        require(job != 0, 1609);
        let control = value(
            s::CREATE_PROCESS,
            job,
            self.bootstrap.handle(child.image()),
            0,
        );
        require(control != 0, 1610);
        for (i, g) in graph::grants(child).enumerate() {
            require(
                value(s::DELEGATE, control, self.source(g.source), i as u64 + 1) != 0,
                1611,
            );
        }
        for g in graph::grants(child) {
            if g.kind == 2
                && g.rights & 16 != 0
                && let Source::Endpoint(c) = g.source
            {
                checked(s::BIND_RECEIVER, self.channel(c), control, 0);
            }
        }
        checked(s::START, control, 0, 0);
        let actual = identity(control, self.bootstrap.context().incarnation);
        require(actual.valid(), 1612);
        // The actual selected Registry retains Job accounting. Closing this
        // setup-only handle never claims to release its Job/object/lineage.
        let info = rt::call4(s::PROCESS_JOB_INFO_INFO, 0, 0, 0, 0);
        require(
            info.status == 0
                && info.value == s::PROCESS_JOB_INFO_V1
                && info.capability == 0
                && info.serial == 0,
            1613,
        );
        let via_process = value(s::PROCESS_JOB_INFO, control, 0, 0);
        require(
            via_process != 0 && via_process == value(s::JOB_INFO, job, 0, 0),
            1614,
        );
        checked(s::CLOSE, job, 0, 0);
        self.actors[child.index()] = Some(Actor {
            control,
            identity: actual,
            ready: false,
            mapping_epoch: 1,
            failed: false,
        });
    }
    fn queue(&mut self, child: Child, command: Command) -> bool {
        let Some(slot) = child_slot(child) else {
            return false;
        };
        let model = self.policy.as_ref().map_or(0, |p| p.scene);
        if !self
            .outbox
            .input(slot.index(), self.actor(child).identity, model, command)
        {
            self.status = b"Target control queue is busy; other owners and Root remain available";
            self.owner.dirty = true;
            return false;
        }
        true
    }
    fn flush(&mut self) {
        self.app_data_flush();
        for index in 0..5 {
            let child = if index == 4 {
                Child::Shell
            } else {
                app_child(index).unwrap()
            };
            let Some(actor) = self.actors[child.index()] else {
                continue;
            };
            if actor.failed {
                self.outbox.retire(index);
                continue;
            }
            if let Some(command) = self.outbox.next(index) {
                let bytes = command.encode().unwrap_or_else(|_| rt::exit(1615));
                match send(self.channel(control_channel(child).unwrap()), bytes) {
                    Ok(true) => require(self.outbox.accepted(index), 1616),
                    Ok(false) => {}
                    Err(()) => {
                        self.outbox.retire(index);
                        self.status=b"An owner control refused delivery; Root and unrelated owners remain available";
                        self.owner.dirty = true;
                    }
                }
            }
        }
    }
    fn receive(&mut self) -> bool {
        // Reserve ND reply ownership before another shared RootEvents receive.
        // Backpressure never consumes a request whose reply cannot be retained.
        if !self.app_data_receive_ready() {
            return false;
        }
        let r = rt::call4(
            s::RECEIVE_EVENT,
            self.bootstrap.handle(Role::RootEvents),
            0,
            0,
            0,
        );
        if r.status == 2 {
            require(r.value == 0 && r.capability == 0 && r.serial == 0, 1617);
            self.app_data_events_empty();
            self.development_events_empty();
            return false;
        }
        require(r.status == 0 && r.capability != 0 && r.serial != 0, 1618);
        let who = graph::CHILDREN.into_iter().find(|c| {
            self.actors[c.index()].is_some_and(|a| {
                a.identity.process == r.capability && a.identity.thread == r.serial
            })
        });
        if let Some(child) = who {
            let bytes = r.value.to_le_bytes();
            if &bytes[..2] == b"ND" {
                self.app_data_event(child, bytes);
            } else {
                self.event(child, bytes);
            }
        }
        true
    }
    fn event(&mut self, child: Child, bytes: [u8; 8]) {
        if ready_bytes(child) == Some(bytes) {
            self.actors[child.index()].as_mut().unwrap().ready = true;
            return;
        }
        if child == Child::Input {
            // Input starts before all UI actors and the desktop model exist.
            // Physical activity during bounded startup is not a desktop action.
            if self.policy.is_some() {
                self.input_event(bytes);
            }
            return;
        }
        if self.inspector_self_event(child, bytes)
            || self.development_event(child, bytes)
            || self.shutdown_event(child, bytes)
            || self.semantic_event(child, bytes)
        {
            return;
        }
        let Some(slot) = child_slot(child) else {
            return;
        };
        if let Ok(event) = Event::decode(bytes) {
            match event {
                Event::Ready(instance)
                    if (slot == v5::display_control::Slot::Shell && instance == 0)
                        || (slot.index() < 4 && usize::from(instance) == slot.index() + 1) =>
                {
                    self.actors[child.index()].as_mut().unwrap().ready = true
                }
                Event::State(state) if slot.index() < 4 => {
                    self.states[slot.index()] = Some(state);
                }
                Event::Open if matches!(child, Child::EditorOne | Child::EditorTwo) => {
                    self.request_picker(slot.index())
                }
                Event::SaveAs if matches!(child, Child::EditorOne | Child::EditorTwo) => {
                    self.request_save_as(slot.index())
                }
                Event::Released { nonce }
                    if matches!(child, Child::EditorOne | Child::EditorTwo) =>
                {
                    self.grant_released(child, nonce)
                }
                Event::Open if child == Child::Files => self.request_picker(1),
                Event::CloseNeedsDiscard if slot.index() < 4 => self.request_discard(slot.index()),
                Event::Closed if slot.index() < 4 => self.closing[slot.index()] = true,
                Event::Window(window) if child == Child::Shell => {
                    if let Some((expected, identity, model, by)) = self.shell_gesture.take()
                        && expected == window
                        && identity == self.actor(child).identity
                        && now() < by
                        && self.policy.as_ref().is_some_and(|p| p.scene == model)
                        && self.owner.pending.is_none()
                        && self.grant.is_none()
                    {
                        let _ = self.policy.as_mut().unwrap().focus(usize::from(window - 1));
                        self.scene_dirty = true;
                    }
                }
                Event::InspectAction { action, row, view } if child == Child::Inspector => {
                    self.inspector_action(action, row, view)
                }
                Event::Refused(code) => {
                    let actual = self.actor(child).identity;
                    self.last_refusal = Some(ev_workspace_root::render::Refusal {
                        process: actual.process,
                        thread: actual.thread,
                        observed: now(),
                        count: self.last_refusal.map_or(1, |r| r.count.saturating_add(1)),
                        code,
                    });
                    self.status = b"Application refused the requested operation";
                    self.owner.dirty = true;
                    self.grant_refused(child, code);
                }
                _ => {}
            }
        }
    }
    fn wait_ready(&mut self, child: Child) {
        let cut = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        while !self.actor(child).ready {
            require(now() < cut, 1619);
            for _ in 0..32 {
                if !self.receive() {
                    break;
                }
            }
            self.flush();
            checked(s::YIELD, 0, 0, 0);
        }
    }
    #[inline(never)]
    fn boot(&mut self) {
        for c in graph::CHANNELS {
            self.channels[c.index()] = value(
                s::CREATE_ENDPOINT,
                self.bootstrap.handle(Role::CreatorJob),
                0,
                0,
            );
            require(self.channel(c) != 0, 1620);
        }
        // Independent services can become live before their dependent callers;
        // all endpoint receivers are bound before those callers are started.
        for child in [
            Child::Display,
            Child::Block,
            Child::Workspace,
            Child::Input,
            Child::NetDriver,
            Child::NetService,
            Child::Shell,
            Child::Files,
            Child::EditorOne,
            Child::EditorTwo,
            Child::Inspector,
        ] {
            self.prepare(child);
            if matches!(
                child,
                Child::Display | Child::Block | Child::Workspace | Child::Input | Child::NetDriver
            ) {
                self.wait_ready(child);
                if child == Child::Block {
                    self.app_data_claim();
                }
                if child == Child::Workspace {
                    self.negotiate_workspace_file_contract_and_packages();
                }
            }
        }
        self.install_policy();
        self.commit_scene(true);
        self.update_cursor();
        self.status = b"Native workspace: Focus with Tab; Esc opens independent Root controls";
        self.owner.dirty = true;
    }
    // Keep the large bounded Desktop construction out of the startup receive
    // call chain. No accepted stream is processed inside this isolated phase.
    #[inline(never)]
    fn install_policy(&mut self) {
        let root = Identity {
            process: self.protected.identity.process,
            thread: self.protected.identity.thread,
            registered: self.bootstrap.context().incarnation,
        };
        let mut policy =
            Policy::new(self.actor(Child::Shell).identity, root).unwrap_or_else(|_| rt::exit(1621));
        for index in 0..4 {
            policy
                .install(index, self.actor(app_child(index).unwrap()))
                .unwrap_or_else(|_| rt::exit(1622));
        }
        policy.focus(0).unwrap_or_else(|_| rt::exit(1623));
        self.policy = Some(policy);
    }
    fn tick(&mut self) {
        if self.shutdown_tick() {
            return;
        }
        if self.development_tick() {
            return;
        }
        for _ in 0..32 {
            if !self.receive() {
                break;
            }
        }
        self.flush();
        self.observe();
        if self.scene_dirty {
            self.commit_scene(false);
            self.scene_dirty = false;
        }
        self.recovery_tick();
        self.grant_tick();
        if self.owner.dirty {
            self.present_owner();
        }
        self.semantic_tick();
        self.inspector_tick();
        self.inspector_self_tick();
        checked(s::YIELD, 0, 0, 0);
    }
    fn observe(&mut self) {
        for child in graph::CHILDREN {
            let Some(actor) = self.actors[child.index()] else {
                continue;
            };
            if actor.failed {
                continue;
            }
            let r = rt::call(s::OBSERVE, actor.control, 0, 0);
            require(r.status == 0 && r.capability == 0 && r.value <= 1, 1624);
            if r.value == 1 {
                self.actors[child.index()].as_mut().unwrap().failed = true;
                self.status =
                    b"A process stopped; retained diagnostics available; recovery pending";
                self.owner.dirty = true;
                if let Some(slot) = child_slot(child)
                    && slot.index() < 4
                {
                    let _ = self
                        .policy
                        .as_mut()
                        .unwrap()
                        .retire(slot.index(), actor.identity);
                    self.scene_dirty = true;
                }
                if child == Child::Shell {
                    self.scene_dirty = true;
                }
                if child == Child::Input {
                    self.input.cancel();
                    self.owner.cancel();
                }
                self.cancel_requester(actor.identity);
            }
        }
    }
}

pub fn run(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == v5::SIZE as u64 && record as usize == BASE + 509 * 4096,
        1625,
    );
    // SAFETY: exact immutable Root1104 startup mapping from selected V5 loader.
    let bootstrap =
        FullGraph::parse(unsafe { core::slice::from_raw_parts(record as *const u8, v5::SIZE) })
            .unwrap_or_else(|_| rt::exit(1626));
    require(rt::execution::validate(bound, now(), true).is_ok(), 1627);
    // SAFETY: separate actual readonly three-page catalogue mapping500..502.
    let catalogue = Catalogue::decode(unsafe {
        core::slice::from_raw_parts((BASE + 500 * 4096) as *const u8, v5::catalogue::SIZE)
    })
    .unwrap_or_else(|_| rt::exit(1628));
    for g in bootstrap.grants() {
        for bit in [1u64, 2, 4, 8, 16, 32, 64, 128, 256] {
            let r = rt::inspect(g.handle, bit);
            require(
                r.value == 0
                    && r.capability == 0
                    && r.status == if u64::from(g.rights) & bit != 0 { 0 } else { 1 },
                1629,
            );
        }
    }
    let facts = ev_workspace_client::native::self_facts().unwrap_or_else(|_| rt::exit(1630));
    require(facts.process == bootstrap.context().process, 1631);
    let actual = Identity {
        process: facts.process,
        thread: facts.thread,
        registered: bootstrap.context().incarnation,
    };
    // SAFETY: sole measured Root entry claims stable residency once. Both
    // readonly records remain mapped for the entire admitted process lifetime.
    let root = unsafe { resident::initialize(bootstrap, catalogue, actual, bound) };
    root.check_catalogue_structure();
    root.boot();
    loop {
        if root.bound != 0 && now() >= root.bound {
            root.status = b"Session bound reached; checked shutdown is pending qualification";
            root.owner.dirty = true;
            root.present_owner();
            rt::exit(1632);
        }
        root.tick();
    }
}
