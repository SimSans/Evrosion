//! Native owner policy adapter. Package bytes and System window have named
//! retained owners; actual execution IDs come only from ProcessIdentity38.
use super::*;
use ev_root_supervisor::native_plan::{
    self, Packages, Slot,
    owner::{Command, Lines},
    state::{Identity as DataIdentity, State},
};
use ev_userspace_contract::{
    app_data::{Refusal, Request as DataRequest, Response},
    root_v2::native as abi,
};
mod diagnostics;
mod owner_runtime;
mod storage;
mod system_runtime;

#[derive(Clone, Copy)]
struct Transition {
    target: Option<Slot>,
    command: Command,
}
pub(super) struct Controller<'a> {
    packages: Packages<'a>,
    state: State<ev_block_service::store_io::DesktopEndpoint, storage::RootWindow<'a>>,
    lines: Lines,
    transition: Option<Transition>,
    running: Option<Slot>,
    preparing: Option<Slot>,
    starting: bool,
    app_settled: bool,
    command_after_start: Option<Command>,
    input_bytes: usize,
    report: Option<abi::report::Frames>,
    report_frame: Option<[u8; 8]>,
    report_serial: u32,
    finish_after_report: bool,
    boot_launch_pending: bool,
    diagnostics: diagnostics::Diagnostics,
    system: system_runtime::System,
    owner_flow: owner_runtime::Owner,
}
impl Controller<'_> {
    pub(super) fn running_package(&self) -> Option<[u8; 32]> {
        self.running.map(|s| self.packages.digest(s))
    }
    pub(super) fn app_stopped(&mut self) {
        self.state.fence();
        self.running = None;
        self.starting = false;
        self.app_settled = false;
        self.command_after_start = None;
    }
}
fn name(c: Command) -> &'static str {
    match c {
        Command::InstallA => "install",
        Command::StageB => "stage",
        Command::Activate => "activate",
        Command::Rollback => "rollback",
        Command::Remove => "remove",
        Command::ReinstallA => "reinstall",
        Command::Inspect => "inspect",
        Command::Cancel => "cancel",
        Command::Finish => "finish",
        Command::CrashShell => "crash-shell",
        Command::InitializeGrants => "initialize-grants",
        Command::RememberNotes | Command::RememberPrivate => "remember",
        Command::RevokeGrant => "revoke",
        Command::SystemInitialize => "system-init",
        Command::SystemStage => "system-stage",
        Command::SystemActivate => "system-activate",
        Command::RecoverGood => "recover-good",
        Command::Continue => "cancel",
    }
}
fn report_slot(slot: Option<Slot>) -> abi::report::Slot {
    match slot {
        None => abi::report::Slot::None,
        Some(Slot::A) => abi::report::Slot::A,
        Some(Slot::B) => abi::report::Slot::B,
    }
}
impl Root<'_> {
    pub(super) fn native_image(&self) -> u64 {
        let n = self.native.as_ref().unwrap();
        match n.preparing.or(n.running).unwrap_or_else(|| fail(940)) {
            Slot::A => self.bootstrap.handle(Role::AppImage),
            Slot::B => {
                let Bootstrap::Native(b) = &self.bootstrap;
                b.extra(abi::ExtraRole::AppBImage)
            }
        }
    }
    fn native_report(&mut self, op: &str, result: &str) {
        let n = self.native.as_ref().unwrap();
        let record = n.state.record();
        let active = record
            .and_then(|r| r.active())
            .and_then(|v| n.packages.slot(v.digest()));
        let staged = record
            .and_then(|r| r.staged())
            .and_then(|v| n.packages.slot(v.digest()));
        let previous = record
            .and_then(|r| r.previous())
            .and_then(|v| n.packages.slot(v.digest()));
        let actor = self.actors[Child::App.index()];
        let id = actor.map(|a| a.identity).unwrap_or(Identity {
            process: 0,
            thread: 0,
        });
        let data = n.state.data();
        let operation = match op {
            "open" => abi::report::Operation::Open,
            "boot" => abi::report::Operation::Boot,
            "install" => abi::report::Operation::Install,
            "stage" => abi::report::Operation::Stage,
            "activate" => abi::report::Operation::Activate,
            "rollback" => abi::report::Operation::Rollback,
            "remove" => abi::report::Operation::Remove,
            "reinstall" => abi::report::Operation::Reinstall,
            "inspect" => abi::report::Operation::Inspect,
            "cancel" => abi::report::Operation::Cancel,
            "finish" => abi::report::Operation::Finish,
            "crash-shell" => abi::report::Operation::CrashShell,
            "initialize-grants" => abi::report::Operation::InitializeGrants,
            "remember" => abi::report::Operation::Remember,
            "revoke" => abi::report::Operation::Revoke,
            "system-init" => abi::report::Operation::SystemInitialize,
            "system-stage" => abi::report::Operation::SystemStage,
            "system-activate" => abi::report::Operation::SystemActivate,
            "recover-good" => abi::report::Operation::RecoverGood,
            _ => abi::report::Operation::Invalid,
        };
        let result = match result {
            "ok" => abi::report::ResultCode::Ok,
            "busy" => abi::report::ResultCode::Busy,
            "recovery" => abi::report::ResultCode::Recovery,
            _ => abi::report::ResultCode::Refused,
        };
        let snapshot = abi::report::Snapshot {
            operation,
            result,
            installed: record.is_some_and(|r| r.installed()),
            active: report_slot(active),
            staged: report_slot(staged),
            previous: report_slot(previous),
            process: id.process,
            thread: id.thread,
            revision: record.map_or(0, |r| r.revision()),
            data_epoch: data.map_or(0, |d| d.schema_epoch()),
            data_counter: data.map_or(0, |d| d.counter()),
            value: data.map_or(0, |d| d.value()),
            mutations: n.state.mutations(),
            recovery: n.state.recovery_required(),
        };
        let n = self.native.as_mut().unwrap();
        require(n.report.is_none(), 942);
        n.report_serial = n.report_serial.checked_add(1).unwrap_or_else(|| fail(943));
        n.report =
            Some(abi::report::Frames::new(n.report_serial, snapshot).unwrap_or_else(|_| fail(943)));
    }
    fn native_report_tick(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        let Some(report) = n.report.as_mut() else {
            return false;
        };
        if n.report_frame.is_none() {
            n.report_frame = report.next_frame();
        }
        let bytes = n.report_frame.unwrap_or_else(|| fail(962));
        let r = rt::send(self.bootstrap.handle(Role::Events), bytes);
        require(
            r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
            963,
        );
        if r.status == 0 {
            n.report_frame = None;
            if report.complete() {
                n.report = None;
            }
        }
        true
    }
    pub(super) fn native_launch(&mut self, from_shell: bool) {
        if !self.native_system_can_launch() {
            if from_shell && self.actors[Child::Shell.index()].is_some() {
                self.control_shell(RootControl::LaunchRefused);
            }
            return;
        }
        if self.actors[Child::App.index()].is_some() {
            return;
        }
        let n = self.native.as_ref().unwrap();
        if n.report.is_some() {
            // The queued snapshot binds the actual App at its first accepted
            // frame. Do not change that incarnation before its complete End.
            // A real Shell Launch remains pending until the snapshot drains.
            if from_shell {
                self.launch_pending = true;
            }
            return;
        }
        let active = n.state.active(&n.packages).ok().flatten();
        if n.transition.is_some() || n.starting || active.is_none() {
            if from_shell {
                self.control_shell(RootControl::LaunchRefused);
            }
            return;
        }
        if self.hide_pending {
            if from_shell {
                self.launch_pending = true;
            }
            return;
        }
        self.native_start(active.unwrap(), from_shell);
    }
    fn native_start(&mut self, slot: Slot, from_shell: bool) {
        self.app_notified = false;
        self.owned_launch = !from_shell;
        self.app_epoch = self
            .app_epoch
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .unwrap_or_else(|| fail(944));
        self.native.as_mut().unwrap().preparing = Some(slot);
        self.prepare(Child::App);
        self.reset(Producer::App, self.app_epoch);
        self.start(Child::App);
        let actual = self.child(Child::App).identity;
        let n = self.native.as_mut().unwrap();
        n.state
            .admit(
                &n.packages,
                slot,
                DataIdentity {
                    process: actual.process,
                    thread: actual.thread,
                },
            )
            .unwrap_or_else(|_| fail(945));
        n.preparing = None;
        n.running = Some(slot);
        n.starting = true;
        n.app_settled = false;
    }
    pub(super) fn native_data(&mut self, bytes: [u8; 8]) {
        let actual = self.child(Child::App).identity;
        let deadline = self.deadline();
        let n = self.native.as_mut().unwrap();
        let response = match DataRequest::decode(&bytes, 0) {
            Ok(request) => n.state.data_request(
                &n.packages,
                DataIdentity {
                    process: actual.process,
                    thread: actual.thread,
                },
                request,
                deadline,
            ),
            Err(_) => Response::Refused(Refusal::Malformed),
        };
        send(
            self.channels[Channel::AppControl.index()],
            response.encode(),
            self.bound,
        );
    }
    fn native_command(&mut self, command: Command) {
        if matches!(
            command,
            Command::InstallA
                | Command::StageB
                | Command::ReinstallA
                | Command::Activate
                | Command::Rollback
                | Command::Remove
        ) && !self.native_system_can_launch()
        {
            self.native_report(name(command), "refused");
            return;
        }
        match command {
            Command::SystemInitialize | Command::SystemStage | Command::SystemActivate => {
                self.native_system_command(command);
                return;
            }
            Command::InitializeGrants
            | Command::RememberNotes
            | Command::RememberPrivate
            | Command::RevokeGrant
            | Command::RecoverGood => {
                self.native_owner_command(command);
                return;
            }
            Command::Continue => {
                self.native_command(Command::Finish);
                return;
            }
            _ => (),
        }
        if self.native.as_ref().unwrap().system.mode == abi::catalogue::BootMode::Recovery
            && !matches!(
                command,
                Command::Finish | Command::Inspect | Command::Cancel
            )
        {
            self.native_report(name(command), "refused");
            return;
        }
        let deadline = self.deadline();
        let busy = self
            .native
            .as_ref()
            .is_some_and(|n| n.transition.is_some() || n.starting)
            || (command == Command::Finish
                && (self.pending.is_some() || self.hide_pending || self.shell_recovering));
        if busy {
            self.native_report(name(command), "busy");
            return;
        }
        match command {
            Command::SystemInitialize
            | Command::SystemStage
            | Command::SystemActivate
            | Command::InitializeGrants
            | Command::RememberNotes
            | Command::RememberPrivate
            | Command::RevokeGrant
            | Command::RecoverGood
            | Command::Continue => unreachable!(),
            Command::Inspect => self.native.as_mut().unwrap().diagnostics.inspect_next = Some(0),
            Command::Cancel => self.native_report(name(command), "ok"),
            Command::CrashShell => {
                if self.actors[Child::Shell.index()].is_some() {
                    self.control_shell(RootControl::CrashShell);
                    self.native_report(name(command), "ok");
                } else {
                    self.native_report(name(command), "refused");
                }
            }
            Command::Finish => {
                // This is a requested Native shutdown only. The executor must
                // still stop all actual peers, settle calls and retire owners.
                self.native_report("finish", "ok");
                self.native.as_mut().unwrap().finish_after_report = true;
            }
            Command::InstallA | Command::StageB | Command::ReinstallA => {
                let n = self.native.as_mut().unwrap();
                let result = match command {
                    Command::InstallA => n.state.install(&n.packages, deadline),
                    Command::StageB => n.state.metadata(
                        &n.packages,
                        ev_app_registry::Change::Stage {
                            package: n.packages.digest(Slot::B),
                        },
                        deadline,
                    ),
                    Command::ReinstallA => n.state.metadata(
                        &n.packages,
                        ev_app_registry::Change::Reinstall {
                            package: n.packages.digest(Slot::A),
                        },
                        deadline,
                    ),
                    _ => unreachable!(),
                };
                self.native_report(name(command), if result.is_ok() { "ok" } else { "refused" });
            }
            Command::Activate | Command::Rollback | Command::Remove => {
                let change = match command {
                    Command::Activate => ev_app_registry::Change::Activate,
                    Command::Rollback => ev_app_registry::Change::Rollback,
                    _ => ev_app_registry::Change::Remove,
                };
                let n = self.native.as_mut().unwrap();
                match n.state.prepare(&n.packages, change, deadline) {
                    Ok(target) => {
                        n.state.fence();
                        n.transition = Some(Transition { target, command });
                    }
                    Err(_) => self.native_report(name(command), "refused"),
                }
            }
        }
    }
    fn native_transition(&mut self) {
        let Some(t) = self.native.as_ref().unwrap().transition else {
            return;
        };
        // A prepared App mutation cannot bypass the same graph/admission gate
        // used by its command and ordinary Shell launch. Retain it until ready.
        if !self.native_system_can_launch() {
            return;
        }
        if let Some(app) = self.actors[Child::App.index()] {
            let r = rt::call(syscall::STOP_PROCESS, app.control, 0, 0);
            require(r.value == 0 && r.capability == 0, 946);
            require(matches!(r.status, 0 | 2), 947);
            return;
        }
        if self.hide_pending || self.shell_recovering {
            return;
        }
        // The exact held image is created BEFORE publication. Its mutable
        // executable owner remains kernel-retained, and it has not run yet.
        if let Some(slot) = t.target {
            self.app_notified = false;
            self.owned_launch = true;
            self.app_epoch = self
                .app_epoch
                .checked_add(1)
                .filter(|n| *n != u32::MAX)
                .unwrap_or_else(|| fail(948));
            self.native.as_mut().unwrap().preparing = Some(slot);
            self.prepare(Child::App);
            self.reset(Producer::App, self.app_epoch);
        }
        let deadline = self.deadline();
        let n = self.native.as_mut().unwrap();
        let success = n.state.commit(&n.packages, deadline).is_ok();
        n.transition = None;
        if !success {
            if self.actors[Child::App.index()].is_some() {
                self.native_discard_held();
            }
            self.native_report(name(t.command), "refused");
            return;
        }
        if let Some(slot) = t.target {
            self.start(Child::App);
            let actual = self.child(Child::App).identity;
            let n = self.native.as_mut().unwrap();
            n.state
                .admit(
                    &n.packages,
                    slot,
                    DataIdentity {
                        process: actual.process,
                        thread: actual.thread,
                    },
                )
                .unwrap_or_else(|_| fail(949));
            n.preparing = None;
            n.running = Some(slot);
            n.starting = true;
            n.app_settled = false;
            n.command_after_start = Some(t.command);
        } else {
            self.native_report(name(t.command), "ok");
        }
    }
    fn native_discard_held(&mut self) {
        let app = self.child(Child::App);
        require(app.identity.process == 0, 950);
        loop {
            let r = rt::call(syscall::STOP_PROCESS, app.control, 0, 0);
            if r.status == 0 {
                break;
            }
            require(r.status == 2 && now() < self.bound, 951);
            pause();
        }
        loop {
            let r = rt::call(syscall::REAP, app.control, 0, 0);
            if r.status == 0 {
                break;
            }
            require(r.status == 2 && now() < self.bound, 952);
            pause();
        }
        checked(syscall::CLOSE, app.control, 0, 0);
        checked(syscall::CLOSE, app.job, 0, 0);
        self.actors[Child::App.index()] = None;
        self.native.as_mut().unwrap().preparing = None;
    }
    pub(super) fn native_settled(&mut self, message: RootControl) {
        if matches!(message,RootControl::AppStarted(epoch)|RootControl::AppRestored(epoch) if epoch==self.app_epoch)
        {
            self.native.as_mut().unwrap().app_settled = true;
        }
    }
    pub(super) fn native_tick(&mut self) {
        // Health observes its original deadline even while a long diagnostic
        // is draining. Owner flow must run AFTER that drain, or its one-outbox
        // prompt completion wait would deadlock the very output it awaits.
        self.native_system_tick();
        if self.native_diagnostic_tick() {
            return;
        }
        if self.native_report_tick() {
            return;
        }
        if self.native.as_ref().unwrap().system.bootstrapping
            || self.native_system_defers_owner_work()
        {
            // Actual receive/lifecycle work ran in Root::tick; health and
            // pending diagnostics/reports above still drain during probation.
            // Do not let ordinary owner commands consume its fixed64tick cut.
            return;
        }
        if self.native_owner_tick() {
            return;
        }
        if self.native.as_ref().unwrap().finish_after_report {
            // Ordinary receive above drained one slot. Never block on a full
            // self-owned mailbox: retain the request and retry next tick.
            let r = rt::send(self.bootstrap.handle(Role::Events), *b"EVNFIN01");
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                964,
            );
            if r.status == 0 {
                rt::exit(0);
            }
            return;
        }
        if self.launch_pending && !self.hide_pending && self.native_system_can_launch() {
            self.launch_pending = false;
            self.native.as_mut().unwrap().boot_launch_pending = false;
            self.native_launch(true);
            return;
        }
        if self.native.as_ref().unwrap().boot_launch_pending && self.native_system_can_launch() {
            self.native.as_mut().unwrap().boot_launch_pending = false;
            self.native_launch(false);
            return;
        }
        self.native_transition();
        if self.native.as_ref().unwrap().report.is_some() {
            return;
        }
        // Report completion only after actual typed data replies, Ready and
        // first Present. A queued metadata publication is never a launch fact.
        if self.app_notified
            && self
                .native
                .as_ref()
                .is_some_and(|n| n.starting && n.app_settled)
        {
            let n = self.native.as_mut().unwrap();
            n.starting = false;
            let command = n.command_after_start.take();
            self.native_report(command.map_or("boot", name), "ok");
            return;
        }
        let uart = self.bootstrap.handle(Role::OwnerUart);
        let status = rt::call4(syscall::PORT_INPUT, uart, 0x3fd, 1, 0);
        require(
            status.status == 0
                && status.value <= 255
                && status.capability == 0
                && status.serial == 0,
            953,
        );
        if status.value & 1 == 0 {
            return;
        }
        let n = self.native.as_mut().unwrap();
        // Finite total input budget. Refuse before the next actual DATA read;
        // no truncated/partial command is turned into owner approval.
        require(n.input_bytes < 4096, 954);
        let input = rt::call4(syscall::PORT_INPUT, uart, 0x3f8, 1, 0);
        require(
            input.status == 0 && input.value <= 255 && input.capability == 0 && input.serial == 0,
            955,
        );
        n.input_bytes += 1;
        match n.lines.push(input.value as u8) {
            Ok(Some(command)) => self.native_command(command),
            Err(_) => self.native_report("invalid", "refused"),
            Ok(None) => (),
        }
    }
}
/// # Safety
/// Named Native loader owns readonly720 bootstrap/catalogue2560 and BOTH exact
/// immutable bank extents at the measured offsets, with guards and zero tails.
/// The unique System window is retained RW and never aliased into App.
pub(super) unsafe fn run(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == abi::SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record > 509 * 4096
            && record < (1 << 47) - 4096
            && bound != 0
            && bound.checked_add(1024).is_some(),
        956,
    );
    let base = record - 509 * 4096;
    // SAFETY: exact retained Native startup page, independently syntax checked.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, abi::SIZE) };
    let bootstrap = abi::FullGraph::parse(bytes).unwrap_or_else(|_| fail(957));
    // SAFETY: exact readonly catalogue at page507, no mutable App window alias.
    let catbytes = unsafe {
        core::slice::from_raw_parts((base + 507 * 4096) as *const u8, abi::catalogue::SIZE)
    };
    let parsed = native_plan::verify(catbytes, bootstrap.context()).unwrap_or_else(|_| fail(958));
    // SAFETY: named loader validated physical1..63-page banks, exact lengths,
    // guards, full hash and zero tails before dispatch. Parser rechecks contents.
    let a = unsafe {
        core::slice::from_raw_parts(
            (base + 384 * 4096) as *const u8,
            parsed.package_a_bytes() as usize,
        )
    };
    // SAFETY: same independently owned readonly B bank, disjoint from A.
    let b = unsafe {
        core::slice::from_raw_parts(
            (base + 304 * 4096) as *const u8,
            parsed.package_b_bytes() as usize,
        )
    };
    let packages =
        Packages::verify(catbytes, bootstrap.context(), a, b).unwrap_or_else(|_| fail(959));
    let catalogue = root_v2::catalogue::Catalogue::decode(packages.catalogue().base().bytes())
        .unwrap_or_else(|_| fail(960));
    let context = bootstrap.context();
    let mut epoch = [0; 16];
    epoch[..8].copy_from_slice(&context.epoch.to_le_bytes());
    epoch[8..].copy_from_slice(&context.incarnation.to_le_bytes());
    // SAFETY: this is the only Rust owner of the actual admitted System window;
    // all region stores exclusively reborrow its blocked transport.
    let window = unsafe { storage::RootWindow::new(record) };
    let owner = UserId::new(*b"EVROSION-OWNER01").unwrap();
    let mut root = Root {
        bootstrap: Bootstrap::Native(bootstrap),
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
        native: None,
        owned_launch: false,
    };
    root.native_boot_prefix();
    // Reuse the actual SystemBlock channel created in the unchanged canonical
    //15-channel order. A transport cannot fabricate an endpoint from a role tag.
    let backend = storage::backend(root.channels[Channel::SystemBlock.index()], window, bound)
        .unwrap_or_else(|| fail(961));
    // Retain this sole backend/controller owner in place. Root borrows it;
    // moving a duplicate Controller into the already-live Root inflated the
    // guarded userspace stack while package and Store validation nested below.
    let mode = packages.catalogue().boot_mode();
    let mut native = Controller {
        packages,
        state: State::new(backend),
        lines: Lines::new(),
        transition: None,
        running: None,
        preparing: None,
        starting: false,
        app_settled: false,
        command_after_start: None,
        input_bytes: 0,
        report: None,
        report_frame: None,
        report_serial: 0,
        finish_after_report: false,
        boot_launch_pending: false,
        diagnostics: diagnostics::Diagnostics::new(),
        system: system_runtime::System::new(mode, bound),
        owner_flow: owner_runtime::Owner::new(),
    };
    root.native = Some(&mut native);
    let opened = if mode == abi::catalogue::BootMode::Recovery {
        true
    } else {
        let deadline = root.deadline();
        let n = root.native.as_mut().unwrap();
        n.state.open(&n.packages, deadline).is_ok()
    };
    if mode != abi::catalogue::BootMode::Recovery {
        root.native_common_graph();
    }
    root.native_system_prepare();
    if mode == abi::catalogue::BootMode::Standalone {
        // The actual initial readonlySystem snapshot completes before Shell.
        while root.native_output_pending() {
            root.tick();
        }
        let _canary = root.native_self_live();
        root.native_start_system_shell();
        root.wait_ready(Child::Shell);
    }
    root.native.as_mut().unwrap().system.bootstrapping = false;
    root.native_report("open", if opened { "ok" } else { "recovery" });
    if opened && mode == abi::catalogue::BootMode::Standalone {
        root.native.as_mut().unwrap().boot_launch_pending = true;
    }
    loop {
        root.tick();
    }
}
