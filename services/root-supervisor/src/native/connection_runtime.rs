//! Owner UI over the existing Root command paths. Frames/status are not
//! publisher, storage, health, restart or capability authority.
use super::*;
use ev_desktop::owner_ui::{
    Operation, Request,
    root::{App, Context, Gate, Next, Outcome},
};
use ev_diagnostics::system::{Phase as HealthPhase, State as Metadata};
use ev_graphics::connection::{Connection, Status, Update};
use ev_userspace_contract::root_v4::owner_session::Restart;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    registry: u64,
    system: u64,
    network: ev_root_supervisor::native_network::Phase,
    command: Option<Command>,
    checking: bool,
    state_fenced: bool,
    setup_required: bool,
    system_blocked: bool,
    clock_fenced: bool,
    client_fenced: bool,
    images_fenced: bool,
    shell_epoch: u32,
    input_epoch: u32,
    app_epoch: u32,
    request: u32,
    app: Option<(u64, u64)>,
    health: Option<HealthPhase>,
}
pub(super) struct Owner {
    gate: Gate,
    open: bool,
    pending: Option<Request>,
    waiting: Option<Command>,
    next: Option<Command>,
    after_prepare: bool,
    confirm: bool,
    failed: bool,
    fenced: bool,
    last_key: Option<Key>,
    last: Option<(Status, Context)>,
    restart: Option<(Restart, Context, u64, Option<u64>)>,
}
impl Owner {
    pub(super) const fn new() -> Self {
        Self {
            gate: Gate::new(),
            open: false,
            pending: None,
            waiting: None,
            next: None,
            after_prepare: false,
            confirm: false,
            failed: false,
            fenced: false,
            last_key: None,
            last: None,
            restart: None,
        }
    }
    fn close(&mut self) {
        self.open = false;
        self.pending = None;
        self.confirm = false;
        self.last = None;
        self.last_key = None;
    }
    fn report(&mut self, operation: &str, result: &str, setup_refusal: bool) {
        let Some(command) = self.waiting.filter(|c| name(*c) == operation) else {
            return;
        };
        self.waiting = None;
        self.last_key = None;
        if result != "ok" {
            self.failed = !setup_refusal;
            self.fenced |= result == "recovery";
            self.after_prepare = false;
            self.next = None;
            return;
        }
        self.failed = false;
        self.next = match command {
            Command::UpdateInitialize if self.after_prepare => {
                self.after_prepare = false;
                Some(Command::UpdateFetch)
            }
            Command::SystemStage => Some(Command::SystemActivate),
            _ => None,
        };
    }
}
impl Root<'_> {
    /// This receives only inside the existing actual-current-Shell ingress path.
    /// It retains intent; ordinary tick starts work only after matching settle.
    pub(in crate::desktop) fn native_connection_request(&mut self, request: Request) {
        if request.encode().is_err()
            || self.pending.is_some()
            || self.hide_pending
            || self.shell_recovering
            || !self.delivery_healthy(delivery::Peer::Shell)
        {
            return;
        }
        let Some(shell) = self.actors[Child::Shell.index()] else {
            return;
        };
        let live = rt::call(syscall::OBSERVE, shell.control, 0, 0);
        if live.status != 0 || live.value != 0 || live.capability != 0 {
            return;
        }
        let owner = &mut self.native.as_mut().unwrap().connection;
        if owner.pending.is_none()
            && (owner.open || (request.operation == Operation::Open && request.revision == 0))
        {
            owner.pending = Some(request);
            owner.last_key = None;
        }
    }
    pub(in crate::desktop) fn native_connection_settled(&mut self, word: u32) {
        let Some((_, actual)) = self.connection_snapshot() else {
            return;
        };
        let _ = self
            .native
            .as_mut()
            .unwrap()
            .connection
            .gate
            .settled(word, actual);
    }
    pub(super) fn native_connection_report(&mut self, op: &str, result: &str) {
        let n = self.native.as_mut().unwrap();
        let setup_refusal = result == "refused"
            && n.state.startup_setup_hint() == native_plan::state::SetupHint::OpenHello;
        n.connection.report(op, result, setup_refusal)
    }
    fn connection_key(&self) -> Key {
        let n = self.native.as_ref().unwrap();
        Key {
            registry: n.state.record().map_or(0, |r| r.revision()),
            system: n.system.view.as_ref().map_or(0, |h| h.next_operation.get()),
            network: n.network.phase(),
            command: n.updates.command,
            checking: n.updates.connection_checking(),
            state_fenced: n.state.recovery_required(),
            setup_required: n.state.startup_setup_hint()
                == native_plan::state::SetupHint::OpenHello,
            system_blocked: n.system.blocked,
            clock_fenced: n.network_clock.failed(),
            client_fenced: n.network_client.quarantined(),
            images_fenced: n.images.failed(),
            shell_epoch: self.shell_epoch,
            input_epoch: self.input_epoch,
            app_epoch: self.app_epoch,
            request: self.request,
            app: self.actors[Child::App.index()].map(|a| (a.identity.process, a.identity.thread)),
            health: self.native_system_snapshot().map(|a| a.phase),
        }
    }
    /// No IO. The System getter resolves only on sparse state changes or an
    /// actual request, not on every idle loop. The real commands recheck owners.
    fn connection_snapshot(&self) -> Option<(Status, Context)> {
        let shell = self.actors[Child::Shell.index()]?;
        let n = self.native.as_ref()?;
        let system = self.native_downloaded_system_projection();
        if system.mode == abi::catalogue::BootMode::Recovery {
            return None;
        }
        let next = system.head.and_then(|h| h.selected.as_ref()).map(|m| Next {
            generation: m.generation.get(),
            manifest: native_plan::system::manifest_digest(m),
        });
        let candidate = n
            .state
            .record()
            .and_then(|r| r.staged())
            .map(|p| p.digest())
            .filter(|p| matches!(n.report_source(*p), Some(AppSource::Downloaded(_))));
        let fenced = n.connection.fenced
            || n.state.recovery_required()
            || n.updates.connection_fenced()
            || n.network_clock.failed()
            || n.network_client.quarantined()
            || n.images.failed()
            || system.blocked
            || matches!(
                system.metadata,
                Metadata::NeedsRecovery | Metadata::Unavailable
            );
        let setup_required =
            !fenced && n.state.startup_setup_hint() == native_plan::state::SetupHint::OpenHello;
        let already_selected = candidate.is_some() && candidate == system.selected_package;
        let awaiting_restart = next.is_some()
            && system.current.is_none_or(|a| {
                a.manifest != next.unwrap().manifest || a.phase != HealthPhase::Healthy
            });
        let update = if fenced {
            Update::Unavailable
        } else if let Some(command) = n.connection.waiting.or(n.updates.command) {
            match command {
                Command::UpdateInitialize => Update::Preparing,
                Command::UpdateFetch if n.updates.connection_checking() => Update::Checking,
                Command::UpdateFetch => Update::Downloading,
                Command::SystemInitialize | Command::SystemStage | Command::SystemActivate => {
                    Update::Selecting
                }
                _ => Update::Preparing,
            }
        } else if setup_required {
            Update::SetupRequired
        } else if n.connection.failed {
            Update::Failed
        } else if already_selected || (candidate.is_none() && awaiting_restart) {
            Update::Selected
        } else if candidate.is_some() {
            Update::Ready
        } else {
            Update::Idle
        };
        let app = self.actors[Child::App.index()].map(|a| App {
            process: a.identity.process,
            thread: a.identity.thread,
            epoch: self.app_epoch,
        });
        let status = Status {
            connection: match n.network.phase() {
                ev_root_supervisor::native_network::Phase::Running
                    if n.network_transfer.succeeded() =>
                {
                    Connection::Online
                }
                ev_root_supervisor::native_network::Phase::Unavailable
                | ev_root_supervisor::native_network::Phase::Stopped => Connection::Offline,
                _ => Connection::Connecting,
            },
            update,
            app_running: app.is_some(),
            confirm: n.connection.confirm && update == Update::Selected,
            candidate_available: candidate.is_some(),
        };
        Some((
            status,
            Context {
                shell_process: shell.identity.process,
                shell_thread: shell.identity.thread,
                shell_epoch: self.shell_epoch,
                input_epoch: self.input_epoch,
                modal: self.request,
                registry_revision: n.state.record().map_or(0, |r| r.revision()),
                app,
                candidate,
                next,
                unavailable: fenced,
                setup_required: update == Update::SetupRequired,
            },
        ))
    }
    /// At most one new effect or presentation per ordinary tick. The actual
    /// semantic debt postpones Store work until Shell's protected ACK.
    pub(super) fn native_connection_tick(&mut self) -> bool {
        if self.native.as_ref().unwrap().system.phase == Some(HealthPhase::Probation)
            || self.native.as_ref().unwrap().system.bootstrapping
        {
            return false;
        }
        if self.native.as_ref().unwrap().connection.waiting.is_none()
            && let Some(command) = self.native.as_mut().unwrap().connection.next.take()
        {
            self.native.as_mut().unwrap().connection.waiting = Some(command);
            self.native.as_mut().unwrap().connection.last_key = None;
            self.native_command(command);
            return true;
        }
        let n = self.native.as_ref().unwrap();
        if !n.connection.open && n.connection.pending.is_none() && n.connection.restart.is_none() {
            return false;
        }
        if let Some((packet, context, cut, last)) = n.connection.restart {
            if self
                .connection_snapshot()
                .is_none_or(|(_, actual)| actual != context || actual.unavailable)
            {
                self.native.as_mut().unwrap().connection.restart = None;
                self.native.as_mut().unwrap().connection.close();
                return false;
            }
            let tick = now();
            if tick >= cut || tick == u64::MAX || last.is_some_and(|previous| tick < previous) {
                let owner = &mut self.native.as_mut().unwrap().connection;
                owner.restart = None;
                owner.fenced = true;
                owner.last_key = None;
                return false;
            }
            if last == Some(tick) {
                return true;
            }
            let reply = rt::send(self.bootstrap.handle(Role::Events), packet.encode());
            let owner = &mut self.native.as_mut().unwrap().connection;
            if reply.value != 0 || reply.capability != 0 || !matches!(reply.status, 0 | 2) {
                owner.restart = None;
                owner.fenced = true;
                owner.last_key = None;
                return false;
            }
            if reply.status == 0 {
                owner.restart = None;
                owner.close();
                self.native_command(Command::Finish)
            } else {
                owner.restart = Some((packet, context, cut, Some(tick)))
            }
            return true;
        }
        let key = self.connection_key();
        let changed = n.connection.last_key != Some(key);
        if !changed {
            return false;
        }
        let Some((mut status, context)) = self.connection_snapshot() else {
            self.native.as_mut().unwrap().connection.close();
            return false;
        };
        let request = self.native.as_mut().unwrap().connection.pending.take();
        if let Some(request) = request {
            if request.operation == Operation::Open && request.revision == 0 {
                let owner = &mut self.native.as_mut().unwrap().connection;
                owner.open = true;
                owner.failed = false;
                owner.confirm = false;
                owner.last = None;
            } else {
                let outcome = self
                    .native
                    .as_mut()
                    .unwrap()
                    .connection
                    .gate
                    .request(request, context);
                match outcome {
                    Ok(Outcome::Leave) => {
                        self.native.as_mut().unwrap().connection.close();
                        return false;
                    }
                    Ok(Outcome::ConfirmRestart) => {
                        self.native.as_mut().unwrap().connection.confirm = true;
                        status.confirm = true
                    }
                    Ok(Outcome::Restart) => {
                        if let Some(next) = context.next
                            && let Ok(packet) = Restart::new(next.generation)
                            && let Ok(cut) = rt::execution::deadline(self.bound, now(), 512)
                        {
                            self.native.as_mut().unwrap().connection.restart =
                                Some((packet, context, cut, None));
                            return true;
                        }
                        self.native.as_mut().unwrap().connection.fenced = true;
                        self.native.as_mut().unwrap().connection.last_key = None;
                        return true;
                    }
                    Ok(Outcome::Fetch | Outcome::SelectNext) => {
                        let (system_busy, system_blocked, metadata) = {
                            let system = self.native_downloaded_system_projection();
                            (system.busy, system.blocked, system.metadata)
                        };
                        let blocked = system_busy
                            || system_blocked
                            || context.unavailable
                            || !self.native_connection_owner_idle()
                            || self.pending.is_some()
                            || self.hide_pending
                            || self.shell_recovering;
                        // The consumed current-context owner gesture authorizes only
                        // genuine blank protected-baseline preparation. No App runs.
                        let setup_failed =
                            !blocked && outcome == Ok(Outcome::Fetch) && !self.native_fetch_setup();
                        let command = if blocked || setup_failed {
                            None
                        } else if outcome == Ok(Outcome::Fetch) {
                            let updates = &*self.native.as_ref().unwrap().updates;
                            if updates.connection_unformatted() {
                                self.native.as_mut().unwrap().connection.after_prepare = true;
                                Some(Command::UpdateInitialize)
                            } else if updates.identity_snapshot().is_some() {
                                Some(Command::UpdateFetch)
                            } else {
                                None
                            }
                        } else {
                            match metadata {
                                Metadata::Unformatted => Some(Command::SystemInitialize),
                                Metadata::Committed => Some(Command::SystemStage),
                                _ => None,
                            }
                        };
                        if let Some(command) = command {
                            self.native.as_mut().unwrap().connection.next = Some(command)
                        } else {
                            let setup = self.native.as_ref().unwrap().state.startup_setup_hint()
                                == native_plan::state::SetupHint::OpenHello;
                            self.native.as_mut().unwrap().connection.failed = !setup;
                            self.native.as_mut().unwrap().connection.last_key = None;
                            return true;
                        }
                    }
                    Err(_) => {
                        self.native.as_mut().unwrap().connection.last_key = Some(key);
                        return false;
                    }
                }
            }
        }
        if self.native.as_ref().unwrap().connection.waiting.is_none()
            && let Some(command) = self.native.as_mut().unwrap().connection.next.take()
        {
            self.native.as_mut().unwrap().connection.waiting = Some(command);
            self.native.as_mut().unwrap().connection.last_key = None;
            self.native_command(command);
            return true;
        }
        // Source lifecycle invalidates an open local view. A package/next-head
        // change instead gets a new revision, never an old confirmation.
        if self
            .native
            .as_ref()
            .unwrap()
            .connection
            .last
            .is_some_and(|(_, old)| {
                old.shell_process != context.shell_process
                    || old.shell_thread != context.shell_thread
                    || old.shell_epoch != context.shell_epoch
                    || old.input_epoch != context.input_epoch
                    || old.app != context.app
                    || old.modal != context.modal
            })
        {
            self.native.as_mut().unwrap().connection.close();
            return false;
        }
        let owner = &mut self.native.as_mut().unwrap().connection;
        owner.last_key = Some(key);
        if owner.last == Some((status, context)) {
            return false;
        }
        let Ok(presentation) = owner.gate.present(status, context) else {
            owner.close();
            return false;
        };
        owner.last = Some((status, context));
        self.control_shell(RootControl::Connection(presentation.word().unwrap()));
        true
    }
}
