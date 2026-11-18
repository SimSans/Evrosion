//! Sustained-only source delivery. No child RPC/lifecycle pump occurs while a
//! Store call owns its window. Root retains scalar work and real target identity.
use super::*;
pub(super) use ev_root_supervisor::desktop_outbox::{
    Entry, Ingress, Kind, Outbox, Outcome, Peer, Quarantine, RetainedReply, Target, Ticket,
    UiContext,
};
#[derive(Clone, Copy)]
struct Received {
    child: Child,
    actor: Actor,
    bytes: [u8; 8],
    ui: Option<UiContext>,
}
#[derive(Clone, Copy)]
struct Debt {
    entry: Entry,
    by: u64,
}
pub(super) struct State {
    outbox: Outbox,
    events: Ingress<Received>,
    failed: [Option<Target>; 2],
    settled: [Option<Debt>; 8],
    overload: u64,
    ui_revision: u64,
    refuse_app: Option<(Target, u32)>,
    quarantine: Option<Quarantine>,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            outbox: Outbox::new(),
            events: Ingress::new(),
            failed: [None; 2],
            settled: [None; 8],
            overload: 0,
            ui_revision: 0,
            refuse_app: None,
            quarantine: None,
        }
    }
}
impl Root<'_> {
    pub(super) fn delivery_target(&self, peer: Peer) -> Option<Target> {
        let (child, channel) = match peer {
            Peer::App => (Child::App, Channel::AppControl),
            Peer::Shell => (Child::Shell, Channel::ShellControl),
        };
        let actor = self.actors[child.index()]?;
        if actor.identity.process == 0 || actor.identity.thread == 0 {
            return None;
        }
        Some(Target {
            peer,
            endpoint: self.channels[channel.index()],
            control: actor.control,
            process: actor.identity.process,
            thread: actor.identity.thread,
        })
    }
    pub(super) fn delivery_begin(&self, needed: [usize; 2]) -> bool {
        let targets = [
            self.delivery_target(Peer::App),
            self.delivery_target(Peer::Shell),
        ];
        let mut d = self.delivery.borrow_mut();
        let waits = d.settled.iter().flatten().count();
        if targets[1].is_some() && d.outbox.available(Peer::Shell) < needed[1].saturating_add(waits)
        {
            return false;
        }
        d.outbox.begin(targets, needed).is_ok()
    }
    pub(super) fn delivery_end(&self) {
        self.delivery.borrow_mut().outbox.end();
    }
    pub(super) fn delivery_reservation(&self, peer: Peer) -> Option<(Target, Ticket)> {
        let target = self.delivery_target(peer)?;
        let ticket = self.delivery.borrow().outbox.reserved(target)?;
        Some((target, ticket))
    }
    pub(super) fn delivery_publish(
        &self,
        ticket: Ticket,
        bytes: [u8; 8],
        deadline: u64,
        kind: Kind,
    ) {
        self.delivery
            .borrow_mut()
            .outbox
            .publish(ticket, bytes, deadline, kind)
            .expect("reserved finite source response");
    }
    pub(super) fn queue_control(&self, peer: Peer, bytes: [u8; 8], kind: Kind) {
        let Some((_, ticket)) = self.delivery_reservation(peer) else {
            let mut d = self.delivery.borrow_mut();
            d.overload = d
                .overload
                .checked_add(1)
                .expect("source overload count exhausted");
            return;
        };
        self.delivery_publish(ticket, bytes, self.deadline(), kind);
    }
    pub(super) fn delivery_healthy(&self, peer: Peer) -> bool {
        let current = self.delivery_target(peer);
        let failed = self.delivery.borrow().failed[peer as usize];
        current.is_some() && (failed.is_none() || failed != current)
    }
    pub(super) fn delivery_degraded(&self) -> bool {
        [Peer::App, Peer::Shell].into_iter().any(|p| {
            self.delivery_target(p)
                .is_some_and(|t| self.delivery.borrow().failed[p as usize] == Some(t))
        })
    }
    /// Only published output, excluding ingress and unused reservation credit.
    /// A ready response/control must get its ordinary attempt before more work.
    pub(super) fn delivery_outbox_pending(&self) -> bool {
        self.delivery.borrow().outbox.pending()
    }
    pub(super) fn delivery_pending(&self) -> bool {
        self.delivery.borrow().outbox.pending()
            || self.delivery.borrow().events.pending()
            || self.delivery_quarantining()
            || self.delivery.borrow().refuse_app.is_some()
            || self.delivery.borrow().settled.iter().any(Option::is_some)
            || self.native_note_reply_pending()
    }
    pub(super) fn delivery_waiting_ui(&self) -> bool {
        self.delivery.borrow().settled.iter().any(Option::is_some)
    }
    pub(super) fn delivery_quarantining(&self) -> bool {
        self.delivery.borrow().quarantine.is_some()
    }
    pub(super) fn delivery_capture(&mut self, child: Child, actor: Actor, bytes: [u8; 8]) {
        if child == Child::Shell && semantic_ack(bytes) {
            // With no per-message ACK nonce in this fixed internal protocol,
            // a failed scope stays fenced until real Shell stop/replacement.
            if !self.delivery_healthy(Peer::Shell) {
                return;
            }
            let alive = rt::call(syscall::OBSERVE, actor.control, 0, 0);
            if alive.status == 0 && alive.value == 0 && alive.capability == 0 {
                let matched = match ShellCommand::decode(bytes) {
                    Ok(ShellCommand::ControlSettled(message)) => self.delivery_settled(message),
                    Ok(ShellCommand::PickerReady(_)) => self.delivery_picker_ready(),
                    _ => false,
                };
                // A matching debt frees one reserved Shell slot before this
                // transition. Unknown/late ACKs cannot establish new readiness.
                if matched && self.delivery_begin([0, 1]) {
                    self.event(child, bytes);
                    self.delivery_end();
                }
            }
            return;
        }
        let ui = if child == Child::Shell && ShellCommand::decode(bytes).is_ok() {
            Some(self.delivery_ui_context())
        } else {
            None
        };
        if child == Child::Shell && soft_input(bytes) && ui.is_none_or(|u| !u.ready) {
            return;
        }
        let target = self.delivery_target(Peer::App);
        let peer = if child == Child::App {
            Peer::App
        } else {
            Peer::Shell
        };
        let mut d = self.delivery.borrow_mut();
        if child == Child::App
            && let (Some(q), Some(target)) = (d.quarantine.as_mut(), target)
            && q.record(target)
        {
            return;
        }
        if d.events
            .push(
                peer,
                Received {
                    child,
                    actor,
                    bytes,
                    ui,
                },
            )
            .is_err()
        {
            if child == Child::App {
                if let Some(target) = target {
                    d.quarantine = Some(Quarantine::new(target, bytes));
                    drop(d);
                    if let Some(n) = self.native.as_mut() {
                        n.state_fence_for_delivery();
                    }
                }
            } else {
                // Unhandled UI input is refused under local overload. No
                // approval, storage effect, reply or accepted send is invented.
                d.overload = d
                    .overload
                    .checked_add(1)
                    .expect("source ingress overload count exhausted");
            }
        }
    }
    fn delivery_ui_context(&self) -> UiContext {
        UiContext {
            app: self.delivery_target(Peer::App),
            app_epoch: self.app_epoch,
            ui_revision: self.delivery.borrow().ui_revision,
            input_epoch: self.input_epoch,
            shell_epoch: self.shell_epoch,
            picker: self.pending.map(|p| (p.request, p.ready, p.queued)),
            ready: self.native.as_ref().is_some_and(|n| n.input_ready())
                && !self.delivery_waiting_ui()
                && !self.delivery_quarantining()
                && self.delivery_healthy(Peer::Shell),
        }
    }
    pub(super) fn delivery_process_event(
        &mut self,
    ) -> Option<ev_root_supervisor::desktop_outbox::dispatch::Work> {
        // ACKs bypass staging in delivery_capture. Never start potentially
        // blocking Store work while an accepted UI control awaits settlement.
        if self.delivery_waiting_ui() {
            return None;
        }
        let app_ready = !self.delivery_quarantining()
            && self.delivery.borrow().outbox.available(Peer::App) >= 1;
        let trusted_ready = self.delivery.borrow().outbox.available(Peer::Shell) >= 1;
        let (index, event) = self
            .delivery
            .borrow()
            .events
            .first_ready([app_ready, trusted_ready])?;
        if self.actors[event.child.index()]
            .is_none_or(|a| a.control != event.actor.control || a.identity != event.actor.identity)
            || event
                .ui
                .is_some_and(|u| !u.matches(self.delivery_ui_context()))
        {
            self.delivery.borrow_mut().events.remove(index);
            return Some(ev_root_supervisor::desktop_outbox::dispatch::Work::Local);
        }
        let alive = rt::call(syscall::OBSERVE, event.actor.control, 0, 0);
        if alive.status != 0 || alive.value != 0 || alive.capability != 0 {
            self.delivery.borrow_mut().events.remove(index);
            return Some(ev_root_supervisor::desktop_outbox::dispatch::Work::Local);
        }
        let needed = match event.child {
            Child::App if &event.bytes[..2] == b"ND" || &event.bytes[..2] == b"NT" => [1, 0],
            Child::App | Child::Shell => [1, 1],
            _ => [0, 0],
        };
        if !self.delivery_begin(needed) {
            return None;
        }
        self.delivery.borrow_mut().events.remove(index);
        let work = ev_root_supervisor::desktop_outbox::dispatch::classify(event.child, event.bytes);
        self.event(event.child, event.bytes);
        self.delivery_end();
        Some(work)
    }
    pub(super) fn delivery_quarantine_tick(&mut self) {
        let q = { self.delivery.borrow().quarantine };
        let Some(q) = q else { return };
        if self.actors[Child::App.index()].is_none_or(|a| {
            a.control != q.target.control
                || a.identity.process != q.target.process
                || a.identity.thread != q.target.thread
        }) {
            return;
        }
        if q.stopped {
            return;
        }
        if !q.inhibited {
            let r = rt::call(syscall::INHIBIT_MANAGED_PROCESS, q.target.control, 0, 0);
            if r.status != 0 || r.value != 0 || r.capability != 0 {
                return;
            }
            self.delivery
                .borrow_mut()
                .quarantine
                .as_mut()
                .unwrap()
                .inhibited = true;
        }
        let r = rt::call(syscall::STOP_PROCESS, q.target.control, 0, 0);
        if r.status == 0 && r.value == 0 && r.capability == 0 {
            self.delivery
                .borrow_mut()
                .quarantine
                .as_mut()
                .unwrap()
                .stopped = true;
        }
        // Busy preserves the actual child/loan reservation; next ordinary tick
        // still drains Shell ACKs. No receive/lifecycle pump occurs inside IO.
    }
    pub(super) fn delivery_tick(&mut self) {
        let refusal = { self.delivery.borrow().refuse_app };
        if let Some((target, _)) = refusal
            && self.delivery_target(Peer::App) != Some(target)
        {
            self.delivery.borrow_mut().refuse_app = None;
        }
        if let Some((target, request)) = refusal
            && self.delivery_target(Peer::App) == Some(target)
            && self.delivery_begin([1, 0])
        {
            self.control_app(RootControl::FileRefused(request));
            self.delivery.borrow_mut().refuse_app = None;
            self.delivery_end();
        }
        let entry = self.delivery.borrow_mut().outbox.next_attempt();
        let Some(entry) = entry else { return };
        if entry.target.peer == Peer::App && self.delivery_quarantining() {
            return;
        }
        let current = self.delivery_target(entry.target.peer);
        let alive = if current == Some(entry.target) {
            Some(rt::call(syscall::OBSERVE, entry.target.control, 0, 0))
        } else {
            None
        };
        let outcome = if current != Some(entry.target)
            || alive.is_some_and(|r| r.status == 0 && r.value == 1 && r.capability == 0)
        {
            Some(Outcome::Cancelled)
        } else if alive.is_none_or(|r| r.status != 0 || r.value != 0 || r.capability != 0) {
            Some(Outcome::Refused)
        } else if now() >= entry.deadline {
            Some(Outcome::Expired)
        } else {
            if entry.kind == Kind::Note && !self.native_prepare_note_reply(entry) {
                return;
            }
            let reply = rt::send(entry.target.endpoint, entry.bytes);
            match (reply.status, reply.value, reply.capability) {
                (0, 0, 0) => Some(Outcome::Accepted),
                (2, 0, 0) => None,
                _ => Some(Outcome::Refused),
            }
        };
        if let Some(outcome) = outcome {
            let actual = self
                .delivery
                .borrow_mut()
                .outbox
                .finish(entry.ticket, outcome)
                .expect("same source delivery ticket");
            self.delivery_outcome(actual, outcome);
        }
    }
    pub(super) fn delivery_outcome(&mut self, entry: Entry, outcome: Outcome) {
        if entry.kind == Kind::Note {
            self.native_note_delivery(entry, outcome);
        }
        let current = self.delivery_target(entry.target.peer) == Some(entry.target);
        if outcome == Outcome::Accepted {
            if entry.target.peer == Peer::Shell && entry.kind == Kind::Control {
                let mut d = self.delivery.borrow_mut();
                d.ui_revision = d
                    .ui_revision
                    .checked_add(1)
                    .expect("source UI revision exhausted");
            }
            if entry.target.peer == Peer::Shell
                && entry.kind == Kind::Control
                && ev_root_supervisor::desktop_outbox::control_needs_settlement(entry.bytes)
            {
                let mut d = self.delivery.borrow_mut();
                let slot = d
                    .settled
                    .iter_mut()
                    .find(|e| e.is_none())
                    .expect("reserved source settlement capacity");
                *slot = Some(Debt {
                    entry,
                    by: now()
                        .checked_add(4096)
                        .filter(|v| *v != u64::MAX)
                        .expect("finite source UI settlement cut"),
                });
            }
            return;
        }
        if !current {
            return;
        }
        self.delivery.borrow_mut().failed[entry.target.peer as usize] = Some(entry.target);
        if entry.kind == Kind::Control {
            self.delivery_control_failed(entry.bytes);
        }
    }
    pub(super) fn delivery_control_failed(&mut self, bytes: [u8; 8]) {
        let Ok(message) = RootControl::decode(bytes) else {
            return;
        };
        match message {
            RootControl::PickFile(request)
                if self
                    .pending
                    .is_some_and(|p| p.request == request && !p.queued) =>
            {
                self.pending = None;
                self.delivery.borrow_mut().refuse_app = self
                    .delivery_target(Peer::App)
                    .map(|target| (target, request));
            }
            RootControl::AppStarted(epoch) | RootControl::AppRestored(epoch)
                if epoch == self.app_epoch =>
            {
                self.app_notified = false;
                self.native_delivery_start_failed();
            }
            RootControl::AppStopped(epoch) if epoch == self.app_epoch => {
                self.hide_pending = false;
                self.launch_pending = false;
            }
            RootControl::InputRestarted(epoch) if epoch == self.input_epoch => {
                self.shell_recovering = false;
                self.launch_pending = false;
            }
            _ => (),
        }
        self.native_owner_delivery_failed(message);
    }
    pub(super) fn delivery_expire_settled(&mut self) {
        let at = now();
        let mut expired = [None; 8];
        {
            let mut d = self.delivery.borrow_mut();
            for (index, slot) in d.settled.iter_mut().enumerate() {
                if slot.is_some_and(|debt| at >= debt.by) {
                    expired[index] = slot.take().map(|debt| debt.entry);
                }
            }
        }
        for entry in expired.into_iter().flatten() {
            if self.delivery_target(entry.target.peer) == Some(entry.target) {
                self.delivery.borrow_mut().failed[entry.target.peer as usize] = Some(entry.target);
                self.delivery_control_failed(entry.bytes);
            }
        }
    }
    pub(super) fn delivery_settled(&mut self, message: RootControl) -> bool {
        let Some(target) = self.delivery_target(Peer::Shell) else {
            return false;
        };
        let bytes = match message.encode() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let mut d = self.delivery.borrow_mut();
        let front = ev_root_supervisor::desktop_outbox::matching_front(
            d.settled
                .iter()
                .enumerate()
                .filter_map(|(i, debt)| debt.as_ref().map(|v| (i, &v.entry))),
            target,
            bytes,
        );
        if let Some(index) = front {
            d.settled[index] = None;
            true
        } else {
            false
        }
    }
    pub(super) fn delivery_picker_ready(&mut self) -> bool {
        self.pending
            .is_some_and(|p| self.delivery_settled(p.mode.control(p.request)))
    }
    pub(super) fn delivery_cancel_actor(&mut self, child: Child, actor: Actor) {
        let peer = match child {
            Child::App => Peer::App,
            Child::Shell => Peer::Shell,
            _ => return,
        };
        let target = Target {
            peer,
            endpoint: self.channels[match peer {
                Peer::App => Channel::AppControl,
                Peer::Shell => Channel::ShellControl,
            }
            .index()],
            control: actor.control,
            process: actor.identity.process,
            thread: actor.identity.thread,
        };
        loop {
            let entry = self.delivery.borrow_mut().outbox.cancel_target(target);
            let Some(entry) = entry else { break };
            self.delivery_outcome(entry, Outcome::Cancelled);
        }
        {
            let mut d = self.delivery.borrow_mut();
            for debt in &mut d.settled {
                if debt.is_some_and(|v| v.entry.target == target) {
                    *debt = None;
                }
            }
            d.events
                .retain(|e| e.actor.control != actor.control || e.actor.identity != actor.identity);
            if d.quarantine.is_some_and(|q| q.is_target(target)) {
                d.quarantine = None;
            }
            if d.refuse_app.is_some_and(|(t, _)| t == target) {
                d.refuse_app = None;
            }
            if d.failed[peer as usize] == Some(target) {
                d.failed[peer as usize] = None;
            }
        }
        if peer == Peer::App {
            self.native_cancel_note_reply(target);
        }
    }
}

fn semantic_ack(bytes: [u8; 8]) -> bool {
    matches!(
        ShellCommand::decode(bytes),
        Ok(ShellCommand::ControlSettled(_) | ShellCommand::PickerReady(_))
    )
}

fn soft_input(bytes: [u8; 8]) -> bool {
    matches!(
        ShellCommand::decode(bytes),
        Ok(ShellCommand::Forward(_)
            | ShellCommand::Text(_)
            | ShellCommand::Pointer(_)
            | ShellCommand::Repaint)
    )
}
