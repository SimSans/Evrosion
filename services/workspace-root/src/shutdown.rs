//! Finite shutdown sequencing, never a physical quiescence or power receipt.
//! The native adapter supplies observations only from exact held controls,
//! actual retirement/RPC replies and the negotiated Kernel power mechanism.
//! There is deliberately no model constructor for "safe shutdown complete".
use crate::{Actor, Identity};
use ev_userspace_contract::root_v5::graph::Child;
use ev_workspace_client::ui::State as AppState;
pub mod ata;

pub const TICKS: u64 = 8192;

/// Only Files and the two Editors own user document/namespace work. Inspector
/// reports presentation/observation state in the fourth slot; its uncertainty
/// must still pass the separate stream drain and actual Stop/Reap/debt gates.
pub fn unfinished_documents(states: &[Option<AppState>; 4]) -> bool {
    states[..3].iter().any(|state| {
        matches!(
            state,
            Some(
                AppState::Dirty
                    | AppState::Saving
                    | AppState::Uncertain
                    | AppState::Conflict
                    | AppState::Loading
            )
        )
    })
}
const CLOSE: [Child; 3] = [Child::EditorOne, Child::EditorTwo, Child::Files];
const APPS: [Child; 3] = CLOSE;
const SERVICES: [Child; 6] = [
    Child::Inspector,
    Child::Shell,
    Child::NetService,
    Child::Workspace,
    Child::Input,
    Child::Display,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    Shutdown,
    Restart,
}

/// Descriptive correlation retained beside actual capabilities in Root. A
/// target copied out of a packet is never accepted as authority by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub child: Child,
    pub control: u64,
    pub identity: Identity,
}
impl Target {
    pub fn captured(child: Child, actor: Actor) -> Option<Self> {
        (actor.identity.valid() && !matches!(actor.control, 0 | u64::MAX)).then_some(Self {
            child,
            control: actor.control,
            identity: actor.identity,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Identity,
    Clock,
    Expired,
    BusyDebt,
    Dirty(Child),
    Uncertain(Child),
    Refused(Child),
    Unsupported,
    Transport,
    Storage,
    Device,
    Power,
    UnexpectedReturn,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    DrainInspector,
    Close(Target),
    AwaitExit(Target),
    RetireFile(usize),
    Stop(Target),
    Reap(Target),
    ResetNamespace(Target),
    SealWorkspace { token: u64 },
    PowerBegin { block: Target, nic: Target },
    QuiesceDevices,
    PowerComplete { block: Target, nic: Target },
    Fenced(Failure),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    InspectorDrained,
    Submitted,
    Exited,
    FileRetired,
    Stopped,
    Reaped,
    NamespaceRetired,
    WorkspaceSealed,
    PowerPrepared,
    DevicesStopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Drain,
    Close(usize),
    Exit(usize),
    File(usize),
    StopApp(usize),
    ReapApp(usize),
    Namespace,
    Seal,
    StopService(usize),
    ReapService(usize),
    Begin,
    Devices,
    Power,
    Fenced(Failure),
}

/// Non-Clone so one actual adapter retains the original cut and partial work.
pub struct Flow {
    intent: Intent,
    token: u64,
    targets: [Option<Target>; 11],
    cut: u64,
    last: u64,
    phase: Phase,
    close_submitted: u16,
    exited: u16,
    reaped: u16,
    display_excluded: bool,
}
impl Flow {
    pub fn begin(
        intent: Intent,
        token: u64,
        now: u64,
        targets: [Option<Target>; 11],
    ) -> Result<Self, Failure> {
        if matches!(token, 0 | u64::MAX) || now == u64::MAX {
            return Err(Failure::Clock);
        }
        let cut = now
            .checked_add(TICKS)
            .filter(|cut| *cut != u64::MAX)
            .ok_or(Failure::Clock)?;
        for (index, target) in targets.iter().enumerate() {
            if let Some(target) = target
                && (target.child.index() != index
                    || !target.identity.valid()
                    || matches!(target.control, 0 | u64::MAX)
                    || targets[..index].iter().flatten().any(|old| {
                        old.control == target.control
                            || old.identity.process == target.identity.process
                            || old.identity.thread == target.identity.thread
                    }))
            {
                return Err(Failure::Identity);
            }
        }
        if targets[Child::Block.index()].is_none() || targets[Child::NetDriver.index()].is_none() {
            return Err(Failure::Identity);
        }
        Ok(Self {
            intent,
            token,
            targets,
            cut,
            last: now,
            phase: Phase::Drain,
            close_submitted: 0,
            exited: 0,
            reaped: 0,
            display_excluded: false,
        })
    }
    pub const fn intent(&self) -> Intent {
        self.intent
    }
    pub const fn cut(&self) -> u64 {
        self.cut
    }
    pub const fn token(&self) -> u64 {
        self.token
    }
    pub const fn partial_closed(&self) -> u16 {
        self.exited
    }
    pub fn target(&self, child: Child) -> Option<Target> {
        self.targets[child.index()]
    }
    pub fn failure(&self) -> Option<Failure> {
        if let Phase::Fenced(reason) = self.phase {
            Some(reason)
        } else {
            None
        }
    }
    pub fn fence(&mut self, reason: Failure) {
        if self.failure().is_none() {
            self.phase = Phase::Fenced(reason);
        }
    }
    fn clock(&mut self, now: u64) {
        if self.failure().is_some() {
            return;
        }
        if now == u64::MAX || now < self.last {
            self.fence(Failure::Clock);
        } else if now >= self.cut {
            self.fence(Failure::Expired);
        } else {
            self.last = now;
        }
    }
    pub fn action(&mut self, now: u64) -> Action {
        self.clock(now);
        loop {
            match self.phase {
                Phase::Drain => return Action::DrainInspector,
                Phase::Close(index) | Phase::Exit(index) => {
                    if index == CLOSE.len() {
                        self.phase = Phase::File(1);
                        continue;
                    }
                    if let Some(target) = self.target(CLOSE[index]) {
                        return if matches!(self.phase, Phase::Close(_)) {
                            Action::Close(target)
                        } else {
                            Action::AwaitExit(target)
                        };
                    }
                    self.phase = Phase::Close(index + 1);
                }
                Phase::File(index) => {
                    if index == 3 {
                        self.phase = Phase::StopApp(0);
                        continue;
                    }
                    if self
                        .target([Child::Files, Child::EditorOne, Child::EditorTwo][index])
                        .is_some()
                    {
                        return Action::RetireFile(index);
                    }
                    self.phase = Phase::File(index + 1);
                }
                Phase::StopApp(index) | Phase::ReapApp(index) => {
                    if index == APPS.len() {
                        self.phase = Phase::Namespace;
                        continue;
                    }
                    if let Some(target) = self.target(APPS[index]) {
                        return if matches!(self.phase, Phase::StopApp(_)) {
                            Action::Stop(target)
                        } else {
                            Action::Reap(target)
                        };
                    }
                    self.phase = Phase::StopApp(index + 1);
                }
                Phase::Namespace => {
                    if let Some(target) = self.target(Child::Files) {
                        return Action::ResetNamespace(target);
                    }
                    self.phase = Phase::Seal;
                }
                Phase::Seal => return Action::SealWorkspace { token: self.token },
                Phase::StopService(index) | Phase::ReapService(index) => {
                    if index == SERVICES.len() {
                        self.phase = Phase::Begin;
                        continue;
                    }
                    if let Some(target) = self.target(SERVICES[index]) {
                        if target.child == Child::Display {
                            self.display_excluded = true;
                        }
                        return if matches!(self.phase, Phase::StopService(_)) {
                            Action::Stop(target)
                        } else {
                            Action::Reap(target)
                        };
                    }
                    self.phase = Phase::StopService(index + 1);
                }
                Phase::Begin | Phase::Power => {
                    let block = self.target(Child::Block).unwrap();
                    let nic = self.target(Child::NetDriver).unwrap();
                    return if self.phase == Phase::Begin {
                        Action::PowerBegin { block, nic }
                    } else {
                        Action::PowerComplete { block, nic }
                    };
                }
                Phase::Devices => return Action::QuiesceDevices,
                Phase::Fenced(reason) => return Action::Fenced(reason),
            }
        }
    }
    /// Progress is descriptive only. The native adapter matches its one
    /// current action and actual private receipt before calling this method.
    pub fn observe(
        &mut self,
        now: u64,
        expected: Action,
        observation: Observation,
    ) -> Result<(), Failure> {
        let current = self.action(now);
        if let Action::Fenced(reason) = current {
            return Err(reason);
        }
        if current != expected {
            self.fence(Failure::Identity);
            return Err(Failure::Identity);
        }
        self.phase = match (self.phase, observation) {
            (Phase::Drain, Observation::InspectorDrained) => Phase::Close(0),
            (Phase::Close(i), Observation::Submitted) => {
                self.close_submitted |= 1 << CLOSE[i].index();
                Phase::Exit(i)
            }
            (Phase::Close(i) | Phase::Exit(i), Observation::Exited) => {
                self.exited |= 1 << CLOSE[i].index();
                Phase::Close(i + 1)
            }
            (Phase::File(i), Observation::FileRetired) => Phase::File(i + 1),
            (Phase::StopApp(i), Observation::Stopped) => Phase::ReapApp(i),
            (Phase::ReapApp(i), Observation::Reaped) => {
                self.reaped |= 1 << APPS[i].index();
                Phase::StopApp(i + 1)
            }
            (Phase::Namespace, Observation::NamespaceRetired) => Phase::Seal,
            (Phase::Seal, Observation::WorkspaceSealed) => Phase::StopService(0),
            (Phase::StopService(i), Observation::Stopped) => Phase::ReapService(i),
            (Phase::ReapService(i), Observation::Reaped) => {
                self.reaped |= 1 << SERVICES[i].index();
                Phase::StopService(i + 1)
            }
            (Phase::Begin, Observation::PowerPrepared) => Phase::Devices,
            (Phase::Devices, Observation::DevicesStopped) => Phase::Power,
            _ => {
                self.fence(Failure::Identity);
                return Err(Failure::Identity);
            }
        };
        Ok(())
    }
    pub fn refuse_close(&mut self, target: Target, dirty: bool) {
        if matches!(self.phase,Phase::Close(i)|Phase::Exit(i) if self.target(CLOSE[i])==Some(target))
        {
            self.fence(if dirty {
                Failure::Dirty(target.child)
            } else {
                Failure::Uncertain(target.child)
            });
        }
    }
    /// Actual Display/Input stay available through storage refusal. Once their
    /// real Stop is requested, no further compositor RPC is allowed by Root.
    pub fn permits_presentation(&self) -> bool {
        !self.display_excluded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_document_owner_refuses_every_unfinished_state_but_ui_is_separate() {
        for state in [
            AppState::Dirty,
            AppState::Saving,
            AppState::Uncertain,
            AppState::Conflict,
            AppState::Loading,
        ] {
            for index in 0..3 {
                let mut states = [Some(AppState::Saved); 4];
                states[index] = Some(state);
                assert!(
                    unfinished_documents(&states),
                    "document slot {index}: {state:?}"
                );
            }
            let mut states = [Some(AppState::Saved); 4];
            states[2] = Some(AppState::NoFile);
            states[3] = Some(state);
            assert!(
                !unfinished_documents(&states),
                "observational UI: {state:?}"
            );
        }
    }

    #[test]
    fn observational_ui_failure_still_requires_its_actual_stop_and_reap() {
        let mut flow = flow();
        for time in 100..200 {
            let action = flow.action(time);
            let observed = match action {
                Action::DrainInspector => Observation::InspectorDrained,
                Action::Close(_) => Observation::Exited,
                Action::RetireFile(_) => Observation::FileRetired,
                Action::Stop(target) if target.child == Child::Inspector => {
                    flow.observe(time, action, Observation::Stopped).unwrap();
                    assert_eq!(flow.action(time + 1), Action::Reap(target));
                    assert!(
                        flow.observe(time + 1, Action::Reap(target), Observation::PowerPrepared)
                            .is_err()
                    );
                    assert_eq!(flow.failure(), Some(Failure::Identity));
                    return;
                }
                Action::Stop(_) => Observation::Stopped,
                Action::Reap(_) => Observation::Reaped,
                Action::ResetNamespace(_) => Observation::NamespaceRetired,
                Action::SealWorkspace { .. } => Observation::WorkspaceSealed,
                _ => panic!("power or invalid action before Inspector retirement: {action:?}"),
            };
            flow.observe(time, action, observed).unwrap();
        }
        panic!("Inspector retirement was skipped");
    }
    fn flow() -> Flow {
        flow_for(Intent::Shutdown)
    }
    fn flow_for(intent: Intent) -> Flow {
        let targets = core::array::from_fn(|i| {
            Some(Target {
                child: ev_userspace_contract::root_v5::graph::CHILDREN[i],
                control: i as u64 + 100,
                identity: Identity {
                    process: i as u64 + 1,
                    thread: i as u64 + 20,
                    registered: 1,
                },
            })
        });
        Flow::begin(intent, 9, 100, targets).unwrap()
    }
    fn drained() -> Flow {
        let mut f = flow();
        let a = f.action(100);
        f.observe(100, a, Observation::InspectorDrained).unwrap();
        f
    }
    #[test]
    fn submission_or_app_ack_cannot_advance_past_actual_exit_and_retirement() {
        let mut f = drained();
        let close = f.action(101);
        f.observe(102, close, Observation::Submitted).unwrap();
        assert!(matches!(f.action(103), Action::AwaitExit(_)));
        let expected = f.action(103);
        assert!(f.observe(104, expected, Observation::FileRetired).is_err());
        assert_eq!(f.failure(), Some(Failure::Identity));
    }
    #[test]
    fn dirty_uncertain_and_identity_changes_fence_before_storage_or_power() {
        for dirty in [false, true] {
            let mut f = drained();
            let Action::Close(target) = f.action(101) else {
                panic!()
            };
            f.refuse_close(target, dirty);
            assert!(matches!(
                f.action(102),
                Action::Fenced(Failure::Dirty(_) | Failure::Uncertain(_))
            ));
        }
        let mut f = drained();
        let Action::Close(mut target) = f.action(101) else {
            panic!()
        };
        target.control += 1;
        assert!(
            f.observe(102, Action::Close(target), Observation::Exited)
                .is_err()
        );
    }
    #[test]
    fn original_cut_and_fenced_phase_never_renew() {
        let mut f = flow();
        let cut = f.cut();
        for time in [101, 150, cut - 1] {
            assert!(!matches!(f.action(time), Action::Fenced(_)));
            assert_eq!(f.cut(), cut);
        }
        assert_eq!(f.action(cut), Action::Fenced(Failure::Expired));
        assert_eq!(f.action(102), Action::Fenced(Failure::Expired));
        let mut backwards = flow();
        backwards.action(200);
        assert_eq!(backwards.action(199), Action::Fenced(Failure::Clock));
    }
    #[test]
    fn full_order_requires_seal_before_devices_and_has_no_model_safe_completion() {
        for intent in [Intent::Shutdown, Intent::Restart] {
            full_order_for(intent);
        }
    }
    fn full_order_for(intent: Intent) {
        let mut f = flow_for(intent);
        let mut saw_seal = false;
        let mut saw_begin = false;
        for time in 101..200 {
            assert_eq!(f.intent(), intent);
            let a = f.action(time);
            let observation = match a {
                Action::DrainInspector => Observation::InspectorDrained,
                Action::Close(_) | Action::AwaitExit(_) => Observation::Exited,
                Action::RetireFile(_) => Observation::FileRetired,
                Action::Stop(_) => Observation::Stopped,
                Action::Reap(_) => Observation::Reaped,
                Action::ResetNamespace(_) => Observation::NamespaceRetired,
                Action::SealWorkspace { .. } => {
                    saw_seal = true;
                    Observation::WorkspaceSealed
                }
                Action::PowerBegin { .. } => {
                    assert!(saw_seal);
                    assert!(!f.permits_presentation());
                    saw_begin = true;
                    Observation::PowerPrepared
                }
                Action::QuiesceDevices => {
                    assert!(saw_begin);
                    Observation::DevicesStopped
                }
                Action::PowerComplete { .. } => {
                    assert!(f.observe(time, a, Observation::DevicesStopped).is_err());
                    return;
                }
                Action::Fenced(reason) => panic!("unexpected {reason:?}"),
            };
            f.observe(time, a, observation).unwrap();
        }
        panic!("finite sequence failed to reach actual power boundary");
    }
}
