//! Actual Root control/RPC/device join. Generic EXIT is never used here.
//! Missing/failed platform work fences the original transaction and owners.
use super::*;
use ev_net_driver::{
    device::recovery::{Recovery, Stopped},
    mediated::Mediated,
};
use ev_workspace_root::shutdown::{
    Action, Failure, Flow, Intent, Observation, Target, ata, unfinished_documents,
};
use ev_workspace_service::control;
use ev_workspace_shell::{
    ActionScope, ActionTarget, Challenge, Effect, PresentedWitness, ProtectedKind, Rights,
};

struct Dialog {
    intent: Intent,
    challenge: Challenge,
    witness: Option<PresentedWitness>,
    rearm: bool,
    drain_cut: u64,
    drained: bool,
}
struct Pending {
    flow: Flow,
    frozen: bool,
    power_token: Option<u64>,
    nic: Option<Recovery<Mediated>>,
    nic_started: bool,
    stopped: Option<Stopped<Mediated>>,
    flushed: Option<ata::Flushed>,
}
pub(super) struct Controller {
    dialog: Option<Dialog>,
    pending: Option<Pending>,
    last: Option<Failure>,
}
impl Controller {
    pub const fn new() -> Self {
        Self {
            dialog: None,
            pending: None,
            last: None,
        }
    }
    pub fn active(&self) -> bool {
        self.dialog.is_some() || self.pending.is_some()
    }
    pub fn dialog(&self) -> bool {
        self.dialog.is_some()
    }
    pub fn nonce(&self) -> u64 {
        self.dialog.as_ref().map_or(0, |d| d.challenge.nonce)
    }
    pub fn needs_barrier(&self) -> bool {
        self.dialog.as_ref().is_some_and(|d| d.rearm && d.drained)
    }
    pub fn armed(&self) -> bool {
        self.dialog
            .as_ref()
            .is_some_and(|d| d.witness.is_some() && !d.rearm)
    }
    pub fn permits_presentation(&self) -> bool {
        self.pending
            .as_ref()
            .is_none_or(|p| !p.frozen && p.flow.permits_presentation())
    }
    pub fn view(&self) -> Option<(&'static [u8], &'static [u8])> {
        if let Some(dialog) = &self.dialog {
            return Some((
                if dialog.intent == Intent::Shutdown {
                    b"Confirm shutdown: committed files retained"
                } else {
                    b"Confirm restart: committed files retained"
                },
                if dialog.drained {
                    b"Enter confirms; Esc cancels. Unsaved or uncertain work refuses shutdown."
                } else {
                    b"Finishing an inspection request before confirmation. Esc cancels."
                },
            ));
        }
        self.pending.as_ref().map(|p| {
            if p.flow.failure().is_some() {
                (b"Shutdown incomplete; retained state requires attention".as_slice(),b"No safe power result. Save/recovery may be needed; accepted work is retained.".as_slice())
            } else {
                (b"Checking saved work and closing the native session".as_slice(),b"Shutdown is incomplete until actual storage/device and Kernel checks finish.".as_slice())
            }
        })
    }
}
fn scalar(reply: rt::CapReply) -> bool {
    reply.value == 0 && reply.capability == 0 && reply.serial == 0
}
fn held(target: Target) -> bool {
    let r = rt::call4(s::PROCESS_IDENTITY, target.control, 0, 0, 0);
    r.status == 0
        && r.value == target.identity.process
        && r.capability == target.identity.thread
        && r.serial == 0
}
fn exited(target: Target) -> Result<bool, Failure> {
    if !held(target) {
        return Err(Failure::Identity);
    }
    let r = rt::call4(s::OBSERVE, target.control, 0, 0, 0);
    if r.status != 0 || r.capability != 0 || r.serial != 0 || r.value > 1 {
        return Err(Failure::Transport);
    }
    Ok(r.value == 1)
}
struct AtaPorts {
    capability: u64,
}
impl ata::Ports for AtaPorts {
    type Error = ();
    fn now(&mut self) -> Result<u64, ()> {
        let r = rt::call4(s::MONOTONIC, 0, 0, 0, 0);
        (r.status == 0 && r.capability == 0 && r.serial == 0 && r.value != u64::MAX)
            .then_some(r.value)
            .ok_or(())
    }
    fn input(&mut self, port: u16) -> Result<u8, ()> {
        if !matches!(port, 0x1ef | 0x3ee) {
            return Err(());
        }
        let r = rt::call4(s::PORT_INPUT, self.capability, u64::from(port), 1, 0);
        (r.status == 0 && r.value <= 255 && r.capability == 0 && r.serial == 0)
            .then_some(r.value as u8)
            .ok_or(())
    }
    fn output(&mut self, port: u16, value: u8) -> Result<(), ()> {
        if !matches!((port, value), (0x1ee, 0xe0) | (0x1ef, 0xe7)) {
            return Err(());
        }
        let r = rt::call4(
            s::PORT_OUTPUT,
            self.capability,
            u64::from(port),
            1,
            u64::from(value),
        );
        (r.status == 0 && scalar(r)).then_some(()).ok_or(())
    }
    fn pause(&mut self) -> Result<(), ()> {
        let r = rt::call4(s::YIELD, 0, 0, 0, 0);
        (r.status == 0 && scalar(r)).then_some(()).ok_or(())
    }
}
impl Root<'_> {
    fn shutdown_scope(&self) -> ActionScope {
        let who = self.protected.identity;
        let owner = ev_workspace_root::policy::owner(who);
        ActionScope {
            kind: ProtectedKind::OwnerOverride,
            requester: owner,
            target: ActionTarget::ProtectedRoot {
                owner,
                thread: who.thread,
                mapping_epoch: 1,
            },
            rights: Rights::PROCESS_CONTROL,
        }
    }
    /// Called only by actual authenticated Root input. Ordinary App/semantic
    /// Activate cannot enter or confirm this private controller.
    pub(super) fn shutdown_request(&mut self, intent: Intent, serial: u32) {
        if self.shutdown.active()
            || self.development.active()
            || self.grant.is_some()
            || self.owner.pending.is_some()
        {
            return;
        }
        if !self.app_data_can_stop() {
            self.status = b"Private data or its reply is unsettled; no application was stopped";
            self.owner.dirty = true;
            return;
        }
        if unfinished_documents(&self.states) {
            self.status =
                b"Save or recover unfinished work before shutdown; no application was stopped";
            self.owner.dirty = true;
            return;
        }
        let (query, expected) = match intent {
            Intent::Shutdown => (0, s::SESSION_POWER_V1),
            Intent::Restart => (1, s::SESSION_POWER_RESTART_V1),
        };
        let info = rt::call4(s::SESSION_POWER_INFO, query, 0, 0, 0);
        if info.status != 0 || info.value != expected || info.capability != 0 || info.serial != 0 {
            self.shutdown.last = Some(Failure::Unsupported);
            self.status=b"Checked restart/shutdown is unavailable in the selected platform; nothing was stopped";
            self.owner.dirty = true;
            return;
        }
        self.cancel_owner();
        let scope = self.shutdown_scope();
        let policy = self.policy.as_mut().unwrap();
        let Ok(attention) = policy
            .trusted
            .attest_attention(&mut policy.desktop, self.input.serial(serial))
        else {
            return;
        };
        let Ok(challenge) = policy
            .trusted
            .challenge(&mut policy.desktop, attention, scope)
        else {
            return;
        };
        self.shutdown.dialog = Some(Dialog {
            intent,
            challenge,
            witness: None,
            rearm: true,
            drain_cut: deadline(v5::resources::FILE_TRANSACTION_TICKS),
            drained: false,
        });
        self.owner.dirty = true;
    }
    pub(super) fn shutdown_cancel(&mut self) {
        if self.shutdown.dialog.take().is_some() {
            if let Some(policy) = self.policy.as_mut() {
                let _ = policy.trusted.cancel(&mut policy.desktop);
            }
            self.input.cancel();
            self.owner.dirty = true;
        }
        // Confirmed work is never cancelled by dropping its pending operation,
        // old controls, original cut or accepted device ownership.
    }
    pub(super) fn shutdown_presented(&mut self, frame: u64) {
        if !self.shutdown.needs_barrier() {
            return;
        }
        self.owner.input_nonce = self
            .owner
            .input_nonce
            .checked_add(1)
            .filter(|v| *v != u32::MAX)
            .unwrap_or_else(|| rt::exit(1690));
        let request = ev_input::SessionBarrierRequest::new(self.owner.input_nonce).unwrap();
        let response = rt::rpc::call(
            self.channel(Channel::InputBarrier),
            request.encode(),
            deadline(v5::resources::RPC_TICKS),
        );
        let Some(barrier) = response
            .ok()
            .and_then(|b| ev_input::SessionBarrierReply::decode(b).ok())
        else {
            self.shutdown_cancel();
            self.status =
                b"Shutdown confirmation could not establish fresh input; nothing was stopped";
            return;
        };
        self.input.arm(barrier);
        let dialog = self.shutdown.dialog.as_mut().unwrap();
        let policy = self.policy.as_mut().unwrap();
        match policy.trusted.attest_presented(
            &mut policy.desktop,
            dialog.challenge,
            dialog.challenge.scope,
            frame,
            self.input.serial(barrier.sequence),
        ) {
            Ok(witness) => {
                dialog.witness = Some(witness);
                dialog.rearm = false;
                // Optional bounded Root-only pacing diagnostic. This is after
                // the real barrier and attestation; its reply never authorizes
                // confirmation and failure leaves the same armed witness.
                let input = u64::from(barrier.sequence)
                    | (u64::from(barrier.enter.main_held) << 32)
                    | (u64::from(barrier.enter.keypad_held) << 33)
                    | (u64::from(barrier.pointer.held) << 34)
                    | (u64::from(barrier.pointer.released) << 37)
                    | (u64::from(dialog.intent == Intent::Restart) << 40)
                    | (u64::from(barrier.enter.main_released) << 41)
                    | (u64::from(barrier.enter.keypad_released) << 42);
                let _ = rt::call4(
                    s::SESSION_POWER_INFO,
                    s::SESSION_POWER_READY_QUERY,
                    dialog.challenge.nonce,
                    frame,
                    input,
                );
            }
            Err(_) => self.shutdown_cancel(),
        }
    }
    pub(super) fn shutdown_confirm(&mut self, serial: u32) {
        if unfinished_documents(&self.states) {
            self.shutdown_cancel();
            self.status =
                b"Save or recover unfinished work before shutdown; no application was stopped";
            self.owner.dirty = true;
            return;
        }
        let Some(mut dialog) = self.shutdown.dialog.take() else {
            return;
        };
        if !dialog.drained {
            self.shutdown.dialog = Some(dialog);
            return;
        }
        let Some(witness) = dialog.witness.take() else {
            self.shutdown.dialog = Some(dialog);
            return;
        };
        let scope = self.shutdown_scope();
        let policy = self.policy.as_mut().unwrap();
        let confirmed = policy.trusted.attest_confirmation(
            &mut policy.desktop,
            witness,
            scope,
            self.input.serial(serial),
            ev_workspace_shell::ConfirmationSource::Physical,
        );
        let Ok(effect) = confirmed else {
            dialog.rearm = true;
            self.shutdown.dialog = Some(dialog);
            self.owner.dirty = true;
            return;
        };
        if effect.nonce() != dialog.challenge.nonce || effect.scope() != scope {
            self.shutdown.last = Some(Failure::Identity);
            return;
        }
        match self.shutdown_prepare(dialog.intent, effect) {
            Ok(pending) => self.shutdown.pending = Some(pending),
            Err(reason) => {
                self.shutdown.last = Some(reason);
                self.status = b"Shutdown preparation refused; nothing was reported safe";
            }
        }
        self.owner.dirty = true;
    }
    fn shutdown_prepare(&mut self, intent: Intent, effect: Effect) -> Result<Pending, Failure> {
        if self.grant.is_some()
            || self.owner.pending.is_some()
            || self.outbox.has_pending()
            || !self.app_data_can_stop()
            || effect.scope() != self.shutdown_scope()
        {
            return Err(Failure::BusyDebt);
        }
        let mut targets = [None; 11];
        for child in graph::CHILDREN {
            if let Some(actor) = self.actors[child.index()] {
                let target = Target::captured(child, actor).ok_or(Failure::Identity)?;
                if !held(target) {
                    return Err(Failure::Identity);
                }
                targets[child.index()] = Some(target);
            }
        }
        let ports = Mediated::new(self.bootstrap.handle(Role::NicPorts))
            .map_err(|_| Failure::Unsupported)?;
        let flow = Flow::begin(intent, effect.nonce(), now(), targets)?;
        self.app_data_seal(flow.cut())
            .map_err(|_| Failure::Storage)?;
        // Existing unsent input/scene pairs were delivered during the dialog,
        // never discarded. Accepted mailbox/RPC work remains Kernel-owned.
        self.semantic_cancel_confirmation();
        Ok(Pending {
            flow,
            frozen: false,
            power_token: None,
            nic: Some(Recovery::new(ports)),
            nic_started: false,
            stopped: None,
            flushed: None,
        })
    }
    pub(super) fn shutdown_event(&mut self, child: Child, bytes: [u8; 8]) -> bool {
        if !self.shutdown.active() {
            return false;
        }
        if let Ok(event) = Event::decode(bytes) {
            if let Some(slot) = child_slot(child)
                && slot.index() < 4
                && let Event::State(state) = event
            {
                self.states[slot.index()] = Some(state);
            }
            if let Some(pending) = self.shutdown.pending.as_mut()
                && let Some(target) = pending.flow.target(child)
            {
                match event {
                    Event::CloseNeedsDiscard => pending.flow.refuse_close(target, true),
                    Event::Refused(_) => pending.flow.refuse_close(target, false),
                    _ => (),
                }
            }
        }
        // No App Open/SaveAs/ordinary semantic action may start new Root I/O.
        true
    }
    pub(super) fn shutdown_tick(&mut self) -> bool {
        if !self.shutdown.active() {
            return false;
        }
        let frozen = self.shutdown.pending.as_ref().is_some_and(|p| p.frozen);
        if !frozen {
            for _ in 0..32 {
                if !self.receive() {
                    break;
                }
            }
        }
        if let Some((cut, false)) = self
            .shutdown
            .dialog
            .as_ref()
            .map(|d| (d.drain_cut, d.drained))
        {
            self.flush(); // preserve recent user input and exact scene pairs
            if now() >= cut {
                self.shutdown_cancel();
                self.status =
                    b"Recent actions did not settle; shutdown stopped before applications closed";
            } else if !self.outbox.has_pending() {
                match self.inspector_self_shutdown(cut) {
                    Ok(true) => {
                        self.shutdown.dialog.as_mut().unwrap().drained = true;
                        self.owner.dirty = true;
                    }
                    Ok(false) => (),
                    Err(()) => {
                        self.shutdown_cancel();
                        self.status=b"Inspection cleanup is unavailable; shutdown stopped before applications closed";
                        self.shutdown.last = Some(Failure::Transport);
                    }
                }
            }
        }
        if let Some(mut pending) = self.shutdown.pending.take() {
            let action = pending.flow.action(now());
            if !matches!(action, Action::Fenced(_)) {
                match self.shutdown_step(&mut pending, action) {
                    Ok(Some(observed)) => {
                        let _ = pending.flow.observe(now(), action, observed);
                        self.owner.dirty = true;
                    }
                    Ok(None) => (),
                    Err(reason) => {
                        pending.flow.fence(reason);
                        self.owner.dirty = true;
                    }
                }
            }
            self.shutdown.pending = Some(pending);
        }
        if self.owner.dirty && self.shutdown.permits_presentation() {
            self.present_owner();
        }
        let reply = rt::call4(s::YIELD, 0, 0, 0, 0);
        // A failed Yield is retained, never converted into a generic EXIT.
        if (reply.status != 0 || !scalar(reply))
            && let Some(p) = self.shutdown.pending.as_mut()
        {
            p.flow.fence(Failure::Transport);
        }
        true
    }
    fn shutdown_step(
        &mut self,
        pending: &mut Pending,
        action: Action,
    ) -> Result<Option<Observation>, Failure> {
        let cut = pending.flow.cut();
        match action {
            Action::DrainInspector => self
                .inspector_self_shutdown(cut)
                .map(|done| done.then_some(Observation::InspectorDrained))
                .map_err(|_| Failure::Transport),
            Action::Close(target) => {
                if exited(target)? {
                    return Ok(Some(Observation::Exited));
                }
                let endpoint =
                    self.channel(control_channel(target.child).ok_or(Failure::Identity)?);
                match send(
                    endpoint,
                    Command::Close { discard: false }.encode().unwrap(),
                ) {
                    Ok(true) => Ok(Some(Observation::Submitted)),
                    Ok(false) => Ok(None),
                    Err(()) => Err(Failure::Transport),
                }
            }
            Action::AwaitExit(target) => Ok(exited(target)?.then_some(Observation::Exited)),
            Action::RetireFile(index) => self
                .shutdown_retire_file(index, cut)
                .map(|done| done.then_some(Observation::FileRetired))
                .map_err(|_| Failure::Storage),
            Action::Stop(target) | Action::Reap(target) => {
                if !held(target) {
                    return Err(Failure::Identity);
                }
                let reap = matches!(action, Action::Reap(_));
                if !self.app_data_can_stop() {
                    return Err(Failure::BusyDebt);
                }
                let r = rt::call4(
                    if reap { s::REAP } else { s::STOP_PROCESS },
                    target.control,
                    0,
                    0,
                    0,
                );
                if !scalar(r) {
                    return Err(Failure::Transport);
                }
                if r.status == 2 {
                    return Ok(None);
                }
                if r.status != 0 {
                    return Err(Failure::Refused(target.child));
                }
                if reap {
                    let closed = rt::call4(s::CLOSE, target.control, 0, 0, 0);
                    if closed.status != 0 || !scalar(closed) {
                        return Err(Failure::Transport);
                    }
                    self.actors[target.child.index()] = None;
                    if let Some(slot) = child_slot(target.child) {
                        self.outbox.retire(slot.index());
                    }
                    Ok(Some(Observation::Reaped))
                } else {
                    self.app_data_stopped(target)
                        .map_err(|_| Failure::Storage)?;
                    Ok(Some(Observation::Stopped))
                }
            }
            Action::ResetNamespace(target) => {
                let response = self
                    .workspace
                    .control_until(
                        self.channel(Channel::RootWorkspaceControl),
                        control::Command::ResetFilesNamespace {
                            lease_epoch: self.bootstrap.context().epoch,
                            old: control::RetiredOwner {
                                process: target.identity.process,
                                thread: target.identity.thread,
                                registered: target.identity.registered,
                            },
                        },
                        cut,
                    )
                    .map_err(|_| Failure::Storage)?;
                match response.status {
                    control::Status::Applied => Ok(Some(Observation::NamespaceRetired)),
                    control::Status::Busy => Ok(None),
                    _ => Err(Failure::Storage),
                }
            }
            Action::SealWorkspace { token } => {
                if !self.app_data_quiescent() {
                    return Ok(None);
                }
                let response = self
                    .workspace
                    .control_until(
                        self.channel(Channel::RootWorkspaceControl),
                        control::Command::Quiesce { token },
                        cut,
                    )
                    .map_err(|_| Failure::Storage)?;
                if response.status == control::Status::Applied {
                    Ok(Some(Observation::WorkspaceSealed))
                } else {
                    Err(Failure::Storage)
                }
            }
            Action::PowerBegin { block, nic } => {
                let operation = match pending.flow.intent() {
                    Intent::Shutdown => 0,
                    Intent::Restart => 1,
                };
                let r = rt::call4(s::SESSION_POWER, operation, block.control, nic.control, cut);
                if r.capability != 0 || r.serial != 0 {
                    pending.frozen = true;
                    return Err(Failure::Power);
                }
                match (r.status, r.value) {
                    (0, 1) => {
                        pending.frozen = true;
                        pending.power_token = Some(1);
                        Ok(Some(Observation::PowerPrepared))
                    }
                    (2, 0) => Ok(None),
                    (1 | 4, 0) => Err(Failure::Unsupported),
                    _ => {
                        pending.frozen = true;
                        Err(Failure::Power)
                    }
                }
            }
            Action::QuiesceDevices => {
                if !pending.frozen || pending.power_token != Some(1) {
                    return Err(Failure::Power);
                }
                if pending.flushed.is_none() {
                    let mut ports = AtaPorts {
                        capability: self.bootstrap.handle(Role::AtaPorts),
                    };
                    pending.flushed =
                        Some(ata::flush(&mut ports, cut).map_err(|_| Failure::Device)?);
                    return Ok(None);
                }
                let child = now()
                    .checked_add(512)
                    .filter(|v| *v != u64::MAX)
                    .ok_or(Failure::Clock)?
                    .min(cut);
                let owner = pending.nic.as_mut().ok_or(Failure::Device)?;
                let progress = if !pending.nic_started {
                    pending.nic_started = true;
                    owner.begin(cut, child)
                } else {
                    owner.step(child)
                }
                .map_err(|_| Failure::Device)?;
                if !progress.complete() {
                    return Ok(None);
                }
                let owner = pending.nic.take().ok_or(Failure::Device)?;
                match owner.finish() {
                    Ok(stopped) => pending.stopped = Some(stopped),
                    Err(owner) => {
                        pending.nic = Some(owner);
                        return Err(Failure::Device);
                    }
                }
                Ok(Some(Observation::DevicesStopped))
            }
            Action::PowerComplete { block, nic } => {
                let flush = pending.flushed.as_ref().ok_or(Failure::Device)?;
                if flush.cut() != cut
                    || flush.status() & (0x80 | 0x20 | 8 | 1) != 0
                    || pending
                        .stopped
                        .as_ref()
                        .is_none_or(|s| s.bytes() != 16 * 1024)
                {
                    return Err(Failure::Device);
                }
                let token = pending.power_token.ok_or(Failure::Power)?;
                let _returned = rt::call4(s::SESSION_POWER, 2, block.control, nic.control, token);
                // A successful selected platform action does not resume this
                // context. Any returned reply stays incomplete, never EXIT0.
                Err(Failure::UnexpectedReturn)
            }
            Action::Fenced(reason) => Err(reason),
        }
    }
}
