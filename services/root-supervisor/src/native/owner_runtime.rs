//! Real owner-channel consent and latest-policy recreation. Saved metadata is
//! never treated as fresh Picker input or as a live capability.
use super::*;
use ev_diagnostics::owner::{Action, Phase, Prompt};
use ev_grant_policy::{self as policy, Eligible, Expected, FreshReadHandoff, consent::Gate};
use ev_picker::{Approval, Handoff, ReadDelivery};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Terminal,
    #[cfg(feature = "native-session")]
    DeliveryRefused,
    Abandon,
    Idle,
    WaitUi,
    Display,
    Armed,
    Input,
    Confirmed,
    Commit,
    Hold,
    Stop,
    Publish,
    RetryRead,
    Finish,
    RemintUi,
    Remint,
}
pub(super) struct Owner {
    step: Step,
    prompt: Option<Prompt>,
    gate: Option<Gate>,
    approval: Option<Approval>,
    consent: Option<Consent>,
    expected: Option<Expected>,
    app: Option<Actor>,
    file: Option<FileChoice>,
    ui: u32,
    ui_ready: bool,
    report: u32,
    expiry: u64,
    serial: u64,
    success: bool,
    request: u32,
}
impl Owner {
    pub(super) const fn new() -> Self {
        Self {
            step: Step::Idle,
            prompt: None,
            gate: None,
            approval: None,
            consent: None,
            expected: None,
            app: None,
            file: None,
            ui: 0,
            ui_ready: false,
            report: 0,
            expiry: 0,
            serial: 0,
            success: false,
            request: 0,
        }
    }
    fn clear(&mut self) {
        self.step = Step::Idle;
        self.prompt = None;
        self.gate = None;
        self.approval = None;
        self.consent = None;
        self.expected = None;
        self.app = None;
        self.file = None;
        self.ui_ready = false;
        self.report = 0;
        self.expiry = 0;
        self.success = false;
        self.request = 0;
    }
}
#[derive(Clone, Copy)]
struct ManagedRead {
    process: u64,
    identity: Identity,
    parent: u64,
    inbox: u64,
    request: u32,
    current: Requester,
    object: ObjectView,
}
impl ManagedRead {
    fn enqueue(self) -> Delivery<u64, u64> {
        let id = rt::call(syscall::PROCESS_IDENTITY, self.process, 0, 0);
        let live = rt::call(syscall::OBSERVE, self.process, 0, 0);
        if id.status != 0
            || id.value != self.identity.process
            || id.capability != self.identity.thread
            || live.status != 0
            || live.value != 0
        {
            return Delivery::Refused(1);
        }
        let r = rt::call4(
            syscall::ENQUEUE_MANAGED_READ,
            self.process,
            self.parent,
            self.inbox,
            u64::from(self.request),
        );
        if r.capability != 0 || r.serial != 0 {
            return Delivery::Indeterminate(990);
        }
        match r.status {
            0 if r.value != 0 => Delivery::Delivered(r.value),
            2 if r.value == 0 => Delivery::Refused(2),
            1 | 3 | 4 if r.value == 0 => Delivery::Refused(r.status),
            _ => Delivery::Indeterminate(990),
        }
    }
}
impl FreshReadHandoff for ManagedRead {
    type Ticket = u64;
    type Error = u64;
    fn enqueue_fresh_read(&mut self, eligible: Eligible<'_>) -> Delivery<u64, u64> {
        if eligible.requester() != self.current || eligible.object() != self.object {
            return Delivery::Refused(1);
        }
        self.enqueue()
    }
}
struct RememberRead<'s, 'p, 'a, P: Sources> {
    state: &'s mut State<ev_block_service::store_io::DesktopEndpoint, storage::RootWindow<'a>>,
    packages: &'p P,
    owner: UserId,
    expected: Expected,
    deadline: u64,
    route: ManagedRead,
    published: bool,
}
impl<P: Sources> Handoff for RememberRead<'_, '_, '_, P> {
    type Delivered = u64;
    type Error = u64;
    fn revalidate_and_deliver_read(&mut self, delivery: ReadDelivery<'_>) -> Delivery<u64, u64> {
        if self
            .state
            .grant_remember(
                self.packages,
                self.owner,
                self.expected,
                &delivery,
                self.deadline,
            )
            .is_err()
        {
            return Delivery::Refused(991);
        }
        self.published = true;
        self.route.enqueue()
    }
}
fn file(record: ev_picker::intent::Record) -> Option<FileChoice> {
    if record.object().volume().bytes() != *b"EVRO-USERS-VOL01" {
        return None;
    }
    match record.object().local() {
        1 => Some(FileChoice::Notes),
        2 => Some(FileChoice::Private),
        _ => None,
    }
}
impl Root<'_> {
    #[cfg(feature = "native-owner-ui")]
    pub(super) fn native_connection_owner_idle(&self) -> bool {
        self.native
            .as_ref()
            .is_some_and(|n| n.owner_flow.step == Step::Idle)
    }
    fn owner_result(&self, success: bool) -> &'static str {
        if success {
            "ok"
        } else if self.native.as_ref().unwrap().state.recovery_required() {
            "recovery"
        } else {
            "refused"
        }
    }
    pub(in crate::desktop) fn native_grants_fenced(&self) -> bool {
        self.native
            .as_ref()
            .is_some_and(|n| n.state.grants_fenced())
    }
    fn owner_route(
        &self,
        app: Actor,
        file: FileChoice,
        request: u32,
        revision: u64,
    ) -> Option<ManagedRead> {
        let mut current = self.requester(app);
        current.policy_revision = revision;
        Some(ManagedRead {
            process: app.control,
            identity: app.identity,
            parent: self.channels[if file == FileChoice::Notes {
                Channel::NotesRead
            } else {
                Channel::PrivateRead
            }
            .index()],
            inbox: self.channels[Channel::GrantInbox.index()],
            request,
            current,
            object: self.metadata(file)?,
        })
    }
    pub(in crate::desktop) fn native_owner_settled(&mut self, message: RootControl) {
        let owner = &mut self.native.as_mut().unwrap().owner_flow;
        if matches!(message,RootControl::OwnerFilePending(n)|RootControl::OwnerActionPending(n)|RootControl::ManagedFilePending(n) if n==owner.ui)
        {
            owner.ui_ready = true;
        }
    }
    pub(in crate::desktop) fn native_owner_suppress_file_completion(&self) -> bool {
        self.native.as_ref().is_some_and(|n| {
            n.owner_flow.step != Step::Idle
                && n.owner_flow
                    .prompt
                    .is_some_and(|p| p.action == Action::RevokeRead)
        })
    }
    pub(in crate::desktop) fn native_owner_stopped(&mut self, child: Child) {
        if child != Child::App {
            return;
        }
        let owner = &mut self.native.as_mut().unwrap().owner_flow;
        if matches!(owner.step, Step::Hold | Step::Stop | Step::Publish) {
            return;
        }
        if owner.step != Step::Idle {
            owner.success = false;
            if let Some(mut p) = owner.prompt {
                p.phase = Phase::Refused;
                owner.prompt = Some(p);
                owner.step = Step::Abandon;
                owner.report = 0;
            } else {
                owner.clear();
            }
        }
    }
    /// Called for a real authenticated App Open BEFORE showing an interactive
    /// picker. A valid saved policy uses its own typed pending/completion path.
    pub(in crate::desktop) fn native_owner_open(&mut self) -> bool {
        if self.native.as_ref().unwrap().owner_flow.step != Step::Idle {
            return false;
        }
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let snapshot = match n
            .with_sources(|state, sources| state.grant_snapshot(sources, self.owner, deadline))
            .and_then(|r| r)
        {
            Ok(s) => s,
            Err(_) => return false,
        };
        let Some(record) = snapshot.record.filter(|r| !r.revoked()) else {
            return false;
        };
        let Some(file) = file(record) else {
            return false;
        };
        let pending = self.pending.unwrap();
        let Some(route) = self.owner_route(
            pending.app,
            file,
            pending.request,
            snapshot.requester_revision(),
        ) else {
            return false;
        };
        if record
            .validate_activation(record.head(), route.current, route.object)
            .is_err()
        {
            return false;
        }
        self.pending.as_mut().unwrap().mode = PendingMode::RememberedPolicy;
        let owner = &mut self.native.as_mut().unwrap().owner_flow;
        owner.step = Step::RemintUi;
        owner.file = Some(file);
        owner.app = Some(pending.app);
        owner.request = pending.request;
        owner.ui = pending.request;
        owner.ui_ready = false;
        self.control_shell(RootControl::ManagedFilePending(pending.request));
        true
    }
    pub(super) fn native_owner_command(&mut self, command: Command) {
        if self.native.as_ref().unwrap().owner_flow.step != Step::Idle {
            return;
        }
        if command == Command::InitializeGrants {
            let deadline = self.storage_deadline();
            let n = self.native.as_mut().unwrap();
            let ok = n
                .with_sources(|state, sources| {
                    state.grant_initialize(sources, self.owner, deadline)
                })
                .is_ok_and(|r| r.is_ok());
            self.native_report("initialize-grants", self.owner_result(ok));
            return;
        }
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let snapshot = if command == Command::RecoverGood {
            None
        } else {
            match n
                .with_sources(|state, sources| state.grant_snapshot(sources, self.owner, deadline))
                .and_then(|r| r)
            {
                Ok(s) => Some(s),
                Err(_) => {
                    self.native_report(
                        if command == Command::RevokeGrant {
                            "revoke"
                        } else {
                            "remember"
                        },
                        self.owner_result(false),
                    );
                    return;
                }
            }
        };
        let serial = {
            let o = &mut self.native.as_mut().unwrap().owner_flow;
            o.serial = o.serial.checked_add(1).unwrap_or_else(|| fail(992));
            o.serial
        };
        let current_system = self.native_system_snapshot().map_or(0, |s| s.generation);
        let system = self.native_system_head();
        let mut prompt = Prompt {
            action: Action::RecoverGood,
            phase: Phase::Display,
            prompt_serial: serial,
            open_nonce: 0,
            owner: self.owner.bytes(),
            app: [0; 16],
            package: [0; 32],
            process: 0,
            thread: 0,
            volume: [0; 16],
            object: 0,
            object_counter: 0,
            object_digest: [0; 32],
            permission_revision: 0,
            grant_serial: 0,
            policy_revision: 0,
            head_digest: [0; 32],
            action_digest: [0; 32],
            token: [b'0'; 64],
            current_admitted_gen: current_system,
            selected_next_gen: system
                .and_then(|v| v.selected)
                .map_or(0, |m| m.generation.get()),
            known_good: system.and_then(|v| v.known_good).unwrap_or(0),
            last_failed_gen: system
                .and_then(|v| v.last_failure)
                .map_or(0, |f| f.generation.get()),
            response_budget_ticks: 4096,
            current_package: [0; 32],
            app_epoch: 0,
        };
        let mut approval = None;
        let mut app = None;
        let mut chosen = None;
        let expected = snapshot.and_then(|s| s.expected);
        if command == Command::RecoverGood {
            let Some(view) = system.filter(|v| v.known_good.is_some()) else {
                self.native_report("recover-good", "refused");
                return;
            };
            prompt.head_digest = view.head_digest();
            let mut h = Sha256::new();
            h.update(b"evrosion.native.explicit-owner-select-good.v1\0");
            h.update(self.owner.bytes());
            h.update(prompt.head_digest);
            prompt.action_digest = h.finalize().into();
        } else if command == Command::RevokeGrant {
            let Some(record) = snapshot.and_then(|s| s.record).filter(|r| !r.revoked()) else {
                self.native_report("revoke", "refused");
                return;
            };
            let Some(file) = file(record) else {
                self.native_report("revoke", "refused");
                return;
            };
            chosen = Some(file);
            prompt.action = Action::RevokeRead;
            prompt.app = record.app().app.bytes();
            prompt.package = record.app().package.bytes();
            prompt.volume = record.object().volume().bytes();
            prompt.object = record.object().local();
            prompt.object_counter = record.revision().counter();
            prompt.object_digest = record.revision().content().bytes();
            prompt.permission_revision = 1;
            prompt.grant_serial = record.grant_serial();
            prompt.policy_revision = record.policy_revision();
            prompt.head_digest = expected.unwrap().digest;
            if let Some(actor) = self.actors[Child::App.index()] {
                app = Some(actor);
                prompt.process = actor.identity.process;
                prompt.thread = actor.identity.thread;
                prompt.current_package = self.app_package();
                prompt.app_epoch = u64::from(self.app_epoch);
            }
            let base = policy::consent::revoke_action(
                self.owner,
                record.app().app,
                record.grant_serial(),
                record.policy_revision(),
                prompt.head_digest,
            )
            .unwrap_or_else(|_| fail(993));
            let mut h = Sha256::new();
            h.update(b"evrosion.native.explicit-owner-revoke-current.v1\0");
            h.update(base);
            h.update(prompt.current_package);
            for v in [prompt.process, prompt.thread, prompt.app_epoch] {
                h.update(v.to_le_bytes());
            }
            prompt.action_digest = h.finalize().into();
        } else {
            let Some(pending) = self
                .pending
                .filter(|p| p.mode == PendingMode::InteractivePicker && p.ready && !p.queued)
            else {
                self.native_report("remember", "refused");
                return;
            };
            let Some(expected) = expected else {
                self.native_report("remember", "refused");
                return;
            };
            let file = if command == Command::RememberNotes {
                FileChoice::Notes
            } else {
                FileChoice::Private
            };
            chosen = Some(file);
            app = Some(pending.app);
            let Some(route) = self.owner_route(
                pending.app,
                file,
                pending.request,
                snapshot.unwrap().requester_revision(),
            ) else {
                self.native_report("remember", "refused");
                return;
            };
            let a = match self.picker.prepare(
                route.current,
                route.object,
                Persistence::RememberPerUser,
                now(),
                self.storage_deadline(),
            ) {
                Ok(a) => a,
                Err(_) => {
                    self.native_report("remember", "refused");
                    return;
                }
            };
            let selected = a.selection();
            prompt.action = Action::RememberRead;
            prompt.open_nonce = u64::from(pending.request);
            prompt.app = selected.requester().app.app.bytes();
            prompt.package = selected.requester().app.package.bytes();
            prompt.current_package = prompt.package;
            prompt.app_epoch = u64::from(self.app_epoch);
            prompt.process = pending.app.identity.process;
            prompt.thread = pending.app.identity.thread;
            prompt.volume = route.object.object.volume().bytes();
            prompt.object = route.object.object.local();
            prompt.object_counter = route.object.revision.counter();
            prompt.object_digest = route.object.revision.content().bytes();
            prompt.permission_revision = route.object.permission_revision;
            prompt.policy_revision = expected.revision;
            prompt.grant_serial = snapshot.and_then(|s| s.record).map_or(1, |r| {
                r.grant_serial().checked_add(1).unwrap_or_else(|| fail(995))
            });
            prompt.head_digest = expected.digest;
            prompt.action_digest = selected.action_digest();
            approval = Some(a);
            self.pending.as_mut().unwrap().mode = PendingMode::OwnerConsent;
        }
        let gate =
            Gate::prepare(prompt.action_digest, self.owner, serial).unwrap_or_else(|_| fail(996));
        prompt.token = *gate.token();
        let ui = if prompt.action == Action::RememberRead {
            prompt.open_nonce as u32
        } else {
            u32::try_from(serial).unwrap_or_else(|_| fail(997))
        };
        let owner = &mut self.native.as_mut().unwrap().owner_flow;
        owner.prompt = Some(prompt);
        owner.gate = Some(gate);
        owner.approval = approval;
        owner.expected = expected;
        owner.app = app;
        owner.file = chosen;
        owner.ui = ui;
        owner.request = prompt.open_nonce as u32;
        owner.ui_ready = app.is_none();
        owner.step = Step::WaitUi;
        if app.is_some() {
            if prompt.action == Action::RememberRead {
                self.control_shell(RootControl::OwnerFilePending(ui));
            } else {
                if let Some(p) = self.pending.filter(|p| !p.queued) {
                    self.pending = None;
                    self.control_app(RootControl::FileRefused(p.request));
                }
                self.control_shell(RootControl::OwnerActionPending(ui));
            }
        }
    }
    fn owner_byte(&mut self) -> Option<u8> {
        let uart = self.bootstrap.handle(Role::OwnerUart);
        let status = rt::call4(syscall::PORT_INPUT, uart, 0x3fd, 1, 0);
        require(
            status.status == 0
                && status.value <= 255
                && status.capability == 0
                && status.serial == 0,
            998,
        );
        if status.value & 1 == 0 {
            return None;
        }
        let n = self.native.as_mut().unwrap();
        let next_input = ev_root_supervisor::native_diagnostics::session::next_input_count(
            n.input_bytes,
            cfg!(feature = "native-session"),
        )
        .unwrap_or_else(|| fail(999));
        let r = rt::call4(syscall::PORT_INPUT, uart, 0x3f8, 1, 0);
        require(
            r.status == 0 && r.value <= 255 && r.capability == 0 && r.serial == 0,
            1000,
        );
        n.input_bytes = next_input;
        Some(r.value as u8)
    }
    fn owner_drain(&mut self) {
        while self.owner_byte().is_some() {}
    }
    fn owner_output(&mut self, phase: Phase, step: Step) {
        let mut p = self.native.as_ref().unwrap().owner_flow.prompt.unwrap();
        p.phase = phase;
        let serial = self.native_owner_report(p);
        let owner = &mut self.native.as_mut().unwrap().owner_flow;
        owner.prompt = Some(p);
        owner.report = serial;
        owner.step = step;
    }
    fn owner_finish(&mut self, success: bool) {
        let recovery = self.native.as_ref().unwrap().state.recovery_required();
        let o = &mut self.native.as_mut().unwrap().owner_flow;
        o.success = success;
        let mut p = o.prompt.unwrap();
        p.phase = if success {
            Phase::Completed
        } else if recovery {
            Phase::Recovery
        } else {
            Phase::Refused
        };
        o.prompt = Some(p);
        o.report = 0;
        o.step = Step::Terminal;
    }
    #[cfg(feature = "native-session")]
    pub(in crate::desktop) fn native_owner_delivery_failed(&mut self, message: RootControl) {
        let Some(n) = self.native.as_mut() else {
            return;
        };
        let owner = &mut n.owner_flow;
        let matches = match message {
            RootControl::OwnerFilePending(id) | RootControl::OwnerActionPending(id) => {
                id == owner.ui
            }
            RootControl::ManagedFilePending(id) => id == owner.request,
            _ => false,
        };
        if !matches || !matches!(owner.step, Step::WaitUi | Step::RemintUi) {
            return;
        }
        owner.success = false;
        owner.ui_ready = false;
        owner.report = 0;
        if let Some(prompt) = owner.prompt.as_mut() {
            prompt.phase = Phase::Expired;
            owner.step = Step::Terminal;
        } else {
            owner.step = Step::DeliveryRefused;
        }
    }
    pub(super) fn native_owner_tick(&mut self) -> bool {
        let step = self.native.as_ref().unwrap().owner_flow.step;
        if step == Step::Idle {
            return false;
        }
        if self.native_output_pending() {
            return true;
        }
        let report = self.native.as_ref().unwrap().owner_flow.report;
        if report != 0 && !self.native_output_completed(report) {
            return true;
        }
        match step {
            #[cfg(feature = "native-session")]
            Step::DeliveryRefused => {
                if let Some(p) = self.pending.take() {
                    self.control_app(RootControl::FileRefused(p.request));
                    self.control_shell(RootControl::ManagedFileRefused(p.request));
                }
                self.native.as_mut().unwrap().owner_flow.clear();
            }
            Step::Terminal => {
                let phase = self
                    .native
                    .as_ref()
                    .unwrap()
                    .owner_flow
                    .prompt
                    .unwrap()
                    .phase;
                self.owner_output(phase, Step::Finish);
            }
            Step::Abandon => self.owner_output(Phase::Refused, Step::Finish),
            Step::WaitUi => {
                if self.native.as_ref().unwrap().owner_flow.ui_ready {
                    self.owner_drain();
                    self.owner_output(Phase::Display, Step::Display);
                }
            }
            Step::Display => {
                self.owner_drain();
                let at = now();
                let budget = self
                    .native
                    .as_ref()
                    .unwrap()
                    .owner_flow
                    .prompt
                    .unwrap()
                    .response_budget_ticks;
                if at
                    .checked_add(budget)
                    .is_none_or(|end| self.bound != 0 && end >= self.bound)
                {
                    self.owner_output(Phase::Expired, Step::Finish);
                } else {
                    let o = &mut self.native.as_mut().unwrap().owner_flow;
                    o.expiry = at + budget;
                    o.gate
                        .as_mut()
                        .unwrap()
                        .arm_after_actual_prompt(at, o.expiry)
                        .unwrap_or_else(|_| fail(1001));
                    self.owner_output(Phase::Armed, Step::Armed);
                }
            }
            Step::Armed => self.native.as_mut().unwrap().owner_flow.step = Step::Input,
            Step::Input => {
                let at = now();
                if at >= self.native.as_ref().unwrap().owner_flow.expiry {
                    self.owner_output(Phase::Expired, Step::Finish);
                } else if let Some(byte) = self.owner_byte() {
                    let result = self
                        .native
                        .as_mut()
                        .unwrap()
                        .owner_flow
                        .gate
                        .as_mut()
                        .unwrap()
                        .byte(byte, at);
                    match result {
                        Ok(Some(consent)) => {
                            self.native.as_mut().unwrap().owner_flow.consent = Some(consent);
                            self.owner_output(Phase::Confirmed, Step::Confirmed);
                        }
                        Ok(None) => (),
                        Err(_) => self.owner_output(Phase::Refused, Step::Finish),
                    }
                }
            }
            Step::Confirmed => self.native.as_mut().unwrap().owner_flow.step = Step::Commit,
            Step::Commit => self.owner_commit(),
            Step::Hold => {
                if let Some(app) = self.actors[Child::App.index()] {
                    let r = rt::call(syscall::INHIBIT_MANAGED_PROCESS, app.control, 0, 0);
                    require(
                        r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                        1002,
                    );
                    if r.status == 0 {
                        self.native.as_mut().unwrap().owner_flow.step = Step::Stop;
                    }
                } else {
                    self.native.as_mut().unwrap().owner_flow.step = Step::Publish;
                }
            }
            Step::Stop => {
                if let Some(app) = self.actors[Child::App.index()] {
                    let r = rt::call(syscall::STOP_PROCESS, app.control, 0, 0);
                    require(
                        r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                        1003,
                    );
                } else {
                    self.native.as_mut().unwrap().owner_flow.step = Step::Publish;
                }
            }
            Step::Publish => {
                let deadline = self.storage_deadline();
                let n = self.native.as_mut().unwrap();
                let result = n
                    .with_sources(|state, sources| {
                        state.grant_commit_revoke(sources, self.owner, deadline)
                    })
                    .and_then(|r| r);
                self.owner_finish(result.is_ok());
            }
            Step::RetryRead | Step::Remint => self.owner_remint(),
            Step::RemintUi => {
                if self.native.as_ref().unwrap().owner_flow.ui_ready {
                    self.native.as_mut().unwrap().owner_flow.step = Step::Remint;
                }
            }
            Step::Finish => {
                let (action, success, ui, approval) = {
                    let o = &mut self.native.as_mut().unwrap().owner_flow;
                    (o.prompt.unwrap().action, o.success, o.ui, o.approval.take())
                };
                if let Some(a) = approval {
                    let _ = self.picker.cancel(a);
                }
                if action == Action::RevokeRead && self.actors[Child::App.index()].is_some() {
                    self.control_shell(RootControl::OwnerActionDone(ui));
                }
                if !success
                    && action == Action::RememberRead
                    && let Some(p) = self.pending.take()
                {
                    self.control_app(RootControl::FileRefused(p.request));
                    self.control_shell(RootControl::OwnerFileRefused(p.request));
                }
                self.native.as_mut().unwrap().owner_flow.clear();
                self.native_report(
                    match action {
                        Action::RememberRead => "remember",
                        Action::RevokeRead => "revoke",
                        Action::RecoverGood => "recover-good",
                    },
                    if success {
                        "ok"
                    } else if self.native.as_ref().unwrap().state.recovery_required() {
                        "recovery"
                    } else {
                        "refused"
                    },
                );
            }
            Step::Idle => (),
        }
        true
    }
    fn owner_commit(&mut self) {
        let prompt = self.native.as_ref().unwrap().owner_flow.prompt.unwrap();
        if prompt.action == Action::RecoverGood {
            let ok = self.native_system_recover(prompt.head_digest).is_ok();
            self.owner_finish(ok);
            return;
        }
        if prompt.action == Action::RevokeRead {
            if let Some(expected_app) = self.native.as_ref().unwrap().owner_flow.app
                && !self.actors[Child::App.index()].is_some_and(|a| {
                    a.control == expected_app.control && a.identity == expected_app.identity
                })
            {
                self.owner_finish(false);
                return;
            }
            let deadline = self.storage_deadline();
            let n = self.native.as_mut().unwrap();
            let expected = n.owner_flow.expected.unwrap();
            let ok = n
                .with_sources(|state, sources| {
                    state.grant_prepare_revoke(sources, self.owner, expected, deadline)
                })
                .is_ok_and(|r| r.is_ok());
            if ok {
                self.native.as_mut().unwrap().owner_flow.step = Step::Hold;
            } else {
                self.owner_finish(false);
            }
            return;
        }
        let Some(pending) = self
            .pending
            .filter(|p| p.mode == PendingMode::OwnerConsent && !p.queued)
        else {
            self.owner_finish(false);
            return;
        };
        let (chosen, expected, consent, approval) = {
            let o = &mut self.native.as_mut().unwrap().owner_flow;
            (
                o.file.unwrap(),
                o.expected.unwrap(),
                o.consent.unwrap(),
                o.approval.take().unwrap(),
            )
        };
        let Some(route) = self.owner_route(
            pending.app,
            chosen,
            pending.request,
            expected.revision.max(1),
        ) else {
            self.owner_finish(false);
            return;
        };
        let deadline = self.storage_deadline();
        let picker = &mut self.picker;
        let n = self.native.as_mut().unwrap();
        let result = n.with_sources(|state, sources| {
            let mut handoff = RememberRead {
                state,
                packages: sources,
                owner: self.owner,
                expected,
                deadline,
                route,
                published: false,
            };
            let result = picker.commit(
                approval,
                consent,
                route.current,
                route.object,
                now(),
                &mut handoff,
            );
            (result, handoff.published)
        });
        let Ok((result, published)) = result else {
            self.owner_finish(false);
            return;
        };
        match result {
            Ok(Delivery::Delivered(_)) => {
                let p = self.pending.as_mut().unwrap();
                p.queued = true;
                p.file = Some(chosen);
                self.owner_finish(true);
            }
            Ok(Delivery::Refused(2)) if published => {
                self.native.as_mut().unwrap().owner_flow.step = Step::RetryRead
            }
            _ => self.owner_finish(false),
        }
    }
    fn owner_remint(&mut self) {
        let Some(pending) = self.pending else {
            self.native.as_mut().unwrap().owner_flow.clear();
            return;
        };
        let chosen = self.native.as_ref().unwrap().owner_flow.file.unwrap();
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let snapshot = match n
            .with_sources(|state, sources| state.grant_snapshot(sources, self.owner, deadline))
            .and_then(|r| r)
        {
            Ok(s) => s,
            Err(_) => {
                self.owner_read_refused();
                return;
            }
        };
        let Some(mut route) = self.owner_route(
            pending.app,
            chosen,
            pending.request,
            snapshot.requester_revision(),
        ) else {
            self.owner_read_refused();
            return;
        };
        let n = self.native.as_mut().unwrap();
        let result = n
            .with_sources(|state, sources| {
                state.grant_remint(
                    sources,
                    self.owner,
                    route.current,
                    route.object,
                    deadline,
                    &mut route,
                )
            })
            .and_then(|r| r);
        match result {
            Ok(Delivery::Delivered(_)) => {
                let p = self.pending.as_mut().unwrap();
                p.queued = true;
                p.file = Some(chosen);
                if self.native.as_ref().unwrap().owner_flow.prompt.is_some() {
                    self.owner_finish(true);
                } else {
                    self.native.as_mut().unwrap().owner_flow.clear();
                }
            }
            Ok(Delivery::Refused(2)) => (),
            _ => self.owner_read_refused(),
        }
    }
    fn owner_read_refused(&mut self) {
        if self.native.as_ref().unwrap().owner_flow.prompt.is_some() {
            self.owner_finish(false);
            return;
        }
        if let Some(p) = self.pending.take() {
            self.control_app(RootControl::FileRefused(p.request));
            self.control_shell(RootControl::ManagedFileRefused(p.request));
        }
        self.native.as_mut().unwrap().owner_flow.clear();
    }
}
