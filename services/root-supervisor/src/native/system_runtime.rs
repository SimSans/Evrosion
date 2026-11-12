//! Actual Native3 System admission and one anchored critical initialization
//! window. Store selection is next-boot state; this Root's admission never
//! changes when staging, failing, or selecting protected Good for a later boot.
use super::*;
use ev_block_service::critical_progress::{Decision, Window};
use ev_diagnostics::system::{Admission, Phase};
use ev_root_supervisor::native_plan::{
    state::{SystemChange, SystemView},
    system,
};
use ev_store::{AdmissionReport, GenerationId, GenerationManifest, HealthOutcome, HealthReport};
use ev_userspace_contract::root_v2::native::catalogue::BootMode;
use sha2::{Digest as _, Sha256};

pub(super) struct System {
    pub(super) mode: BootMode,
    pub(super) bootstrapping: bool,
    view: Option<SystemView>,
    current: Option<AdmissionReport>,
    manifest: Option<GenerationManifest>,
    slot: Option<system::Slot>,
    phase: Option<Phase>,
    progress: Window,
    first_tick: Option<u64>,
    generic: bool,
    critical: bool,
    shell_faulted: bool,
    common_ready: bool,
    shell_started: bool,
    needs_admission: bool,
    pending_snapshot: bool,
    probe_done: bool,
    probe_digest: Option<[u8; 32]>,
    blocked: bool,
}
impl System {
    pub(super) const fn new(mode: BootMode, bound: u64) -> Self {
        Self {
            mode,
            bootstrapping: true,
            view: None,
            current: None,
            manifest: None,
            slot: None,
            phase: None,
            progress: Window::new(bound),
            first_tick: None,
            generic: false,
            critical: false,
            shell_faulted: false,
            common_ready: false,
            shell_started: false,
            needs_admission: false,
            pending_snapshot: false,
            probe_done: false,
            probe_digest: None,
            blocked: false,
        }
    }
}
impl Root<'_> {
    /// Actual source ABI canary. cap0 Native3 explicitly declares R10 output;
    /// legacy childCONTROL/provider queries keep their separate old contract.
    pub(super) fn native_self_live(&self) -> (Identity, u64) {
        const CANARY: u64 = 0x63d1_f08a_974c_2be5;
        let r = rt::call4(syscall::PROCESS_IDENTITY, 0, 0, 0, CANARY);
        require(
            r.status == 0
                && r.value == self.bootstrap.context().process
                && r.capability != 0
                && r.serial != CANARY
                && r.serial <= now()
                && r.serial < self.bound,
            1000,
        );
        (
            Identity {
                process: r.value,
                thread: r.capability,
            },
            r.serial,
        )
    }
    /// Root+Block only. Recovery never depends on the normal graph becoming
    /// healthy. Preserve the same closed15-channel namespace for every mode.
    pub(super) fn native_boot_prefix(&mut self) {
        for channel in graph::CHANNELS {
            self.channels[channel.index()] = value(
                syscall::CREATE_ENDPOINT,
                self.bootstrap.handle(Role::CreatorJob),
                0,
                0,
            );
            require(self.channels[channel.index()] != 0, 1001);
        }
        self.prepare(Child::Block);
        self.start(Child::Block);
        self.wait_ready(Child::Block);
    }
    pub(super) fn native_common_graph(&mut self) {
        for child in [Child::Display, Child::File, Child::Input] {
            self.prepare(child);
            self.start(child);
            self.wait_ready(child);
        }
        self.reset(Producer::Shell, self.shell_epoch);
        self.native.as_mut().unwrap().system.common_ready = true;
    }
    pub(super) fn native_start_system_shell(&mut self) {
        if self.native.as_ref().unwrap().system.shell_started {
            return;
        }
        require(self.native.as_ref().unwrap().system.common_ready, 1002);
        self.prepare(Child::Shell);
        self.start(Child::Shell);
        self.native.as_mut().unwrap().system.shell_started = true;
    }
    pub(super) fn native_system_prepare(&mut self) {
        let mode = self.native.as_ref().unwrap().system.mode;
        if mode == BootMode::Standalone {
            // This is metadata only: no writable Store::open/recovery/format.
            self.native_queue_system_snapshot();
            return;
        }
        if mode == BootMode::Recovery {
            let _actual = self.native_self_live();
        }
        let deadline = self.deadline();
        let view = if mode == BootMode::Recovery {
            self.native
                .as_mut()
                .unwrap()
                .state
                .system_readonly_snapshot(deadline)
        } else {
            self.native
                .as_mut()
                .unwrap()
                .state
                .system_snapshot(deadline)
        };
        match view {
            Ok(view) => {
                let s = &mut self.native.as_mut().unwrap().system;
                s.view = view;
                s.needs_admission = mode == BootMode::SystemManaged && view.is_some();
            }
            Err(_) => self.native.as_mut().unwrap().system.blocked = true,
        }
        self.native_queue_system_snapshot();
    }
    fn native_system_begin(&mut self) {
        let deadline = self.deadline();
        let Some(selected) = self
            .native
            .as_ref()
            .unwrap()
            .system
            .view
            .and_then(|v| v.selected)
        else {
            return;
        };
        let slot = system::resolve(&self.native.as_ref().unwrap().packages, &selected)
            .unwrap_or_else(|_| fail(1003));
        let view = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_apply(SystemChange::BeginBoot(selected.generation), deadline)
            .unwrap_or_else(|_| fail(1004));
        let plan = view.boot_plan.unwrap_or_else(|| fail(1005));
        let (actual, _) = self.native_self_live();
        let admitted = system::admission(
            &self.native.as_ref().unwrap().packages,
            self.bootstrap.context(),
            actual.process,
            actual.thread,
            plan,
        )
        .unwrap_or_else(|_| fail(1006));
        let view = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_apply(SystemChange::Admission(admitted), deadline)
            .unwrap_or_else(|_| fail(1007));
        // The first fresh LIVE observation AFTER durable Admission anchors one
        //64tick interval. No report framing or readiness can reset this value.
        let (_, first) = self.native_self_live();
        require(
            first.checked_add(64).is_some_and(|end| end < self.bound),
            1008,
        );
        let s = &mut self.native.as_mut().unwrap().system;
        s.view = Some(view);
        s.current = Some(admitted);
        s.manifest = Some(plan.manifest);
        s.slot = Some(slot);
        s.phase = Some(Phase::Probation);
        s.first_tick = Some(first);
        s.needs_admission = false;
        require(
            s.progress.observe_live(first, false) == Ok(Decision::Waiting),
            1009,
        );
        // No metadata read/report wait is inserted inside the critical window.
        self.native_start_system_shell();
    }
    pub(in crate::desktop) fn native_system_image(&self, child: Child) -> Option<u64> {
        if child != Child::Shell {
            return None;
        }
        match self.native.as_ref()?.system.slot? {
            system::Slot::Good => Some(self.bootstrap.handle(Role::ShellImage)),
            system::Slot::Bad => {
                let Bootstrap::Native(b) = &self.bootstrap;
                Some(b.extra(abi::ExtraRole::BadShellImage))
            }
        }
    }
    pub(in crate::desktop) fn native_system_image_digest(&self, child: Child) -> Option<[u8; 32]> {
        if child != Child::Shell {
            return None;
        }
        let n = self.native.as_ref()?;
        match n.system.slot? {
            system::Slot::Good => Some(self.catalogue.images().nth(child.index()).unwrap().image),
            system::Slot::Bad => Some(n.packages.catalogue().bad_shell().image),
        }
    }
    pub(in crate::desktop) fn native_system_event(&mut self, child: Child, bytes: [u8; 8]) -> bool {
        if child != Child::Shell {
            return false;
        }
        let s = &mut self.native.as_mut().unwrap().system;
        if bytes == *b"EVSHRDY1" {
            if s.phase == Some(Phase::Probation) && !s.shell_faulted {
                s.generic = true;
            }
            return false; // ordinary actual Ready still updates the Actor row
        }
        if bytes == *b"EVSHCRD1" {
            if s.phase == Some(Phase::Probation) && s.generic && !s.shell_faulted {
                s.critical = true;
            }
            return true;
        }
        false
    }
    pub(in crate::desktop) fn native_system_child_stopped(&mut self, child: Child) -> bool {
        if child != Child::Shell {
            return false;
        }
        let s = &mut self.native.as_mut().unwrap().system;
        if s.phase == Some(Phase::Probation) || s.phase == Some(Phase::Failed) {
            s.shell_faulted = true;
            s.generic = false;
            s.critical = false;
            return true;
        }
        false
    }
    pub(in crate::desktop) fn native_system_provenance(&self) -> Option<[u8; 32]> {
        self.native
            .as_ref()?
            .system
            .manifest
            .as_ref()
            .map(system::manifest_digest)
    }
    pub(in crate::desktop) fn native_system_can_launch(&self) -> bool {
        let s = &self.native.as_ref().unwrap().system;
        system::can_launch(s.mode, s.bootstrapping, s.blocked, s.shell_started, s.phase)
    }
    pub(super) fn native_system_defers_owner_work(&self) -> bool {
        let s = &self.native.as_ref().unwrap().system;
        system::defer_owner_work(s.mode, s.phase)
    }
    pub(super) fn native_system_snapshot(&self) -> Option<Admission> {
        let s = &self.native.as_ref()?.system;
        Some(Admission {
            manifest: system::manifest_digest(s.manifest.as_ref()?),
            generation: s.current?.generation.get(),
            boot_serial: s.current?.boot_serial,
            process_stamp: s.current?.process_stamp,
            phase: s.phase?,
        })
    }
    pub(super) fn native_system_head(&mut self) -> Option<SystemView> {
        if self.native.as_ref().unwrap().system.mode != BootMode::Recovery {
            return self.native.as_ref().unwrap().system.view;
        }
        let deadline = self.deadline();
        self.native
            .as_mut()
            .unwrap()
            .state
            .system_readonly_snapshot(deadline)
            .ok()
            .flatten()
    }
    pub(super) fn native_system_recover(&mut self, expected: [u8; 32]) -> Result<(), ()> {
        let head = self.native_system_head().ok_or(())?;
        if head.head_digest() != expected || head.known_good.is_none() {
            return Err(());
        }
        let deadline = self.deadline();
        let view = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_apply(SystemChange::SelectKnownGood, deadline)
            .map_err(|_| ())?;
        if view
            .selected
            .is_none_or(|m| Some(m.generation.get()) != view.known_good)
        {
            return Err(());
        }
        let s = &mut self.native.as_mut().unwrap().system;
        s.view = Some(view);
        s.pending_snapshot = true;
        Ok(())
    }
    fn native_system_all_live(&self) -> bool {
        [
            Child::Block,
            Child::Display,
            Child::File,
            Child::Input,
            Child::Shell,
        ]
        .into_iter()
        .all(|child| {
            self.actors[child.index()].is_some_and(|a| {
                a.ready && a.identity.process != 0 && {
                    let r = rt::call(syscall::OBSERVE, a.control, 0, 0);
                    r.status == 0 && r.value == 0 && r.capability == 0
                }
            })
        })
    }
    pub(super) fn native_system_tick(&mut self) {
        if self.native.as_ref().unwrap().system.bootstrapping
            || self.native.as_ref().unwrap().system.blocked
        {
            return;
        }
        if self.native.as_ref().unwrap().system.phase == Some(Phase::Probation) {
            let first = self.native.as_ref().unwrap().system.first_tick.unwrap();
            let expired = now() >= first.checked_add(64).unwrap();
            let ready = {
                let s = &self.native.as_ref().unwrap().system;
                s.generic && s.critical && !s.shell_faulted
            };
            if expired || ready {
                let (_, tick) = self.native_self_live();
                let decision = self
                    .native
                    .as_mut()
                    .unwrap()
                    .system
                    .progress
                    .observe_live(tick, ready)
                    .unwrap_or_else(|_| fail(1010));
                if decision == Decision::MissingProgress {
                    self.native_system_health(HealthOutcome::MissingProgress);
                } else if decision == Decision::Ready {
                    if !self.native.as_ref().unwrap().system.probe_done {
                        let admitted = self.native.as_ref().unwrap().system.current.unwrap();
                        let deadline = self.deadline();
                        let payload = system::probe(admitted);
                        let result = self
                            .native
                            .as_mut()
                            .unwrap()
                            .state
                            .system_apply(SystemChange::Probe(payload), deadline);
                        match result {
                            Ok(view) => {
                                let n = self.native.as_mut().unwrap();
                                n.system.view = Some(view);
                                n.system.probe_done = true;
                                n.system.probe_digest = Some(Sha256::digest(payload).into());
                            }
                            Err(_) => {
                                self.native.as_mut().unwrap().system.blocked = true;
                                return;
                            }
                        }
                    }
                    let _fresh = self.native_self_live();
                    if self.native_system_all_live() {
                        self.native_system_health(HealthOutcome::CriticalPassed);
                    } else {
                        self.native.as_mut().unwrap().system.critical = false;
                    }
                }
            }
        }
        if self.native.as_ref().unwrap().system.pending_snapshot && !self.native_output_pending() {
            self.native.as_mut().unwrap().system.pending_snapshot = false;
            self.native_queue_system_snapshot();
            return;
        }
        if self.native.as_ref().unwrap().system.needs_admission
            && !self.native_output_pending()
            && self.native.as_ref().unwrap().report.is_none()
        {
            self.native_system_begin();
        }
    }
    fn native_system_health(&mut self, outcome: HealthOutcome) {
        let deadline = self.deadline();
        let digest = if outcome == HealthOutcome::CriticalPassed {
            self.native
                .as_ref()
                .unwrap()
                .system
                .probe_digest
                .unwrap_or_else(|| fail(1011))
        } else {
            self.native
                .as_mut()
                .unwrap()
                .state
                .system_probe_digest(deadline)
                .unwrap_or_else(|_| fail(1011))
        };
        let admitted = self.native.as_ref().unwrap().system.current.unwrap();
        let view = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_apply(
                SystemChange::Health(HealthReport {
                    admitted,
                    outcome,
                    observed_checks: if outcome == HealthOutcome::CriticalPassed {
                        ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR
                    } else {
                        0
                    },
                    storage_probe: digest,
                }),
                deadline,
            )
            .unwrap_or_else(|_| fail(1012));
        let s = &mut self.native.as_mut().unwrap().system;
        s.view = Some(view);
        s.phase = Some(if outcome == HealthOutcome::CriticalPassed {
            Phase::Healthy
        } else {
            Phase::Failed
        });
        s.probe_digest = Some(digest);
        s.pending_snapshot = true;
        if outcome == HealthOutcome::CriticalPassed {
            self.native.as_mut().unwrap().boot_launch_pending = true;
        }
    }
    pub(super) fn native_system_command(&mut self, command: Command) {
        let mode = self.native.as_ref().unwrap().system.mode;
        let busy = {
            let s = &self.native.as_ref().unwrap().system;
            s.bootstrapping || s.phase == Some(Phase::Probation) || s.blocked
        };
        if mode == BootMode::Recovery || busy {
            self.native_report(name(command), if busy { "busy" } else { "refused" });
            return;
        }
        let deadline = self.deadline();
        let result = match command {
            Command::SystemInitialize => {
                let n = self.native.as_mut().unwrap();
                n.state.system_initialize(&n.packages, deadline)
            }
            Command::SystemStage => {
                // This sole controller retains the last confirmed System head.
                // system_apply still reopens/validates Store before publication.
                let view = self.native.as_ref().unwrap().system.view;
                match view {
                    Some(view) => {
                        let generation = view
                            .highest_generation
                            .checked_add(1)
                            .and_then(GenerationId::new);
                        match generation {
                            Some(g) => {
                                let manifest = system::manifest(
                                    &self.native.as_ref().unwrap().packages,
                                    system::Slot::Bad,
                                    g.get(),
                                )
                                .unwrap_or_else(|_| fail(1013));
                                self.native
                                    .as_mut()
                                    .unwrap()
                                    .state
                                    .system_apply(SystemChange::Stage(manifest), deadline)
                            }
                            None => Err(native_plan::state::Error::State),
                        }
                    }
                    _ => Err(native_plan::state::Error::State),
                }
            }
            Command::SystemActivate => {
                // Reuse confirmed selection data; the durable operation below
                // independently checks the actual Store and rejects stale state.
                let view = self.native.as_ref().unwrap().system.view;
                match view {
                    Some(view) => match view.staged {
                        Some(staged) => self
                            .native
                            .as_mut()
                            .unwrap()
                            .state
                            .system_apply(SystemChange::Activate(staged.generation), deadline),
                        None => Err(native_plan::state::Error::State),
                    },
                    _ => Err(native_plan::state::Error::State),
                }
            }
            _ => unreachable!(),
        };
        let success = result.is_ok();
        if let Ok(view) = result {
            let s = &mut self.native.as_mut().unwrap().system;
            s.view = Some(view);
            s.pending_snapshot = true;
            if command == Command::SystemInitialize && mode == BootMode::SystemManaged {
                s.needs_admission = true;
            }
        }
        self.native_report(name(command), if success { "ok" } else { "refused" });
    }
}
