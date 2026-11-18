use super::*;
use ev_kernel::{
    live_grant::{SelectedReadRoute, StoppedSelectedRoute},
    managed_send::{Context as RetireContext, Entry, StateCode},
};
pub(super) struct Selected {
    route: Option<SelectedReadRoute>,
    stopped: Option<StoppedSelectedRoute>,
    current: Option<Entry>,
    pending: Option<(Entry, Ticket)>,
    last_nonce: u32,
}
impl Selected {
    pub(super) fn power_drained(&self) -> bool {
        self.pending.is_none()
            && self
                .current
                .as_ref()
                .is_none_or(|e| e.is_drained() && e.queue_cleared())
    }
    pub const fn new() -> Self {
        Self {
            route: None,
            stopped: None,
            current: None,
            pending: None,
            last_nonce: 0,
        }
    }
}
fn slot(child: Child) -> Option<usize> {
    match child {
        Child::Files => Some(0),
        Child::EditorOne => Some(1),
        Child::EditorTwo => Some(2),
        Child::Inspector => Some(3),
        _ => None,
    }
}
fn file_channel(child: Child) -> Option<Channel> {
    match child {
        Child::Files => Some(Channel::FilesFileLease),
        Child::EditorOne => Some(Channel::EditorOneFileLease),
        Child::EditorTwo => Some(Channel::EditorTwoFileLease),
        Child::Inspector => Some(Channel::InspectorFileLease),
        _ => None,
    }
}
impl World {
    pub(super) fn selected_binding(&mut self, w: usize, target: Metadata, control: Handle) -> bool {
        let Some(channel) = Channel::from_wire_index(w) else {
            return false;
        };
        if channel.delivery() != DeliveryMode::Selected {
            return false;
        }
        let Some(s) = slot(channel.receiver()) else {
            return false;
        };
        if self.selected[s].stopped.is_some() {
            let wire = self.wires[w].as_mut().unwrap();
            wire.receiver = target.domain;
            wire.control = Some(control);
            wire.bound = Some(target.thread);
            wire.closed = false;
            return true;
        }
        false
    }
    pub(super) fn grant_selected(
        &mut self,
        index: usize,
        process: Handle,
        source: Handle,
        inbox: Handle,
        nonce: u32,
        frame: &mut UserContext,
    ) {
        if index != 0 || nonce == 0 || nonce == u32::MAX {
            extended(frame, 1, 0, 0);
            return;
        }
        let root = self.root.meta;
        let target_index = match self.find_control(root.domain, process) {
            Ok(i) => i,
            Err(e) => {
                extended(frame, e, 0, 0);
                return;
            }
        };
        let actor = self.actors[target_index - 1].as_ref().unwrap();
        let child = actor.child;
        let meta = actor.meta;
        let Some(s) = slot(child) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let target_channel = file_channel(child).unwrap();
        let inbox_channel = child.inbox().unwrap();
        let source_wire = self.wire(
            root,
            source,
            Rights::SEND | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
        );
        let inbox_wire = self.wire(root, inbox, Rights::SEND);
        if !actor.admitted
            || actor.retired
            || source_wire != Some(target_channel.index())
            || inbox_wire != Some(inbox_channel.index())
            || self
                .pending
                .iter()
                .flatten()
                .any(|p| p.caller == target_index || p.callee == target_index)
        {
            extended(frame, 1, 0, 0);
            return;
        }
        let Some(workspace) = self.actors[Child::Workspace.index()].as_ref() else {
            extended(frame, 2, 0, 0);
            return;
        };
        let source_route = self.wires[target_channel.index()].as_ref().unwrap();
        if source_route.receiver != workspace.meta.domain
            || source_route.bound != Some(workspace.meta.thread)
            || source_route.closed
        {
            extended(frame, 1, 0, 0);
            return;
        }
        let select = &mut self.selected[s];
        if nonce <= select.last_nonce
            || select.pending.is_some()
            || select
                .current
                .as_ref()
                .is_some_and(|entry| !entry.is_drained())
            || select.route.as_ref().is_some_and(|r| r.pending() != 0)
        {
            extended(frame, 2, 0, 0);
            return;
        }
        let receive_selector = graph::grants(child)
            .position(|g| g.source == graph::Source::Endpoint(inbox_channel) && g.rights == 272)
            .unwrap() as u64
            + 1;
        if select.route.is_none() {
            let wire = self.wires[inbox_channel.index()].as_mut().unwrap();
            let Some(control) = wire.control else {
                extended(frame, 1, 0, 0);
                return;
            };
            if let Some(stopped) = select.stopped.take() {
                match stopped.rebind(
                    self.core.a,
                    self.core.s,
                    self.core.registry,
                    self.token,
                    process,
                    receive_selector,
                    control,
                ) {
                    Ok(route) => select.route = Some(route),
                    Err(rejected) => {
                        select.stopped = Some(rejected.owner);
                        extended(frame, 1, 0, 0);
                        return;
                    }
                }
            } else {
                let Some(mailbox) = wire.mailbox.take() else {
                    extended(frame, 2, 0, 0);
                    return;
                };
                match SelectedReadRoute::from_managed(
                    self.core.a,
                    self.core.s,
                    self.core.registry,
                    self.token,
                    root.domain,
                    process,
                    receive_selector,
                    control,
                    mailbox,
                ) {
                    Ok(route) => select.route = Some(route),
                    Err(rejected) => {
                        wire.mailbox = Some(rejected.mailbox);
                        extended(frame, 1, 0, 0);
                        return;
                    }
                }
            }
        }
        if select.route.as_ref().unwrap().target_metadata() != meta {
            extended(frame, 1, 0, 0);
            return;
        }
        let (mut entry, one_shot) = match Entry::prepare(
            self.core.a,
            self.core.s,
            self.core.registry,
            RetireContext {
                caller: root,
                root,
                token: self.token,
            },
            process,
            source,
            nonce,
        ) {
            Ok(value) => value,
            Err(_) => {
                extended(frame, 1, 0, 0);
                return;
            }
        };
        let deadline = Deadline::after(crate::timer::now(), 8192).unwrap();
        let payload = u64::from(nonce).to_le_bytes();
        match select.route.as_mut().unwrap().enqueue(
            self.core.a,
            self.core.s,
            self.core.registry,
            self.token,
            inbox,
            one_shot,
            &payload,
            deadline,
            crate::timer::now(),
        ) {
            Ok(ticket) => {
                select.current = None;
                select.pending = Some((entry, ticket));
                select.last_nonce = nonce;
                self.facts.grants += 1;
                extended(frame, 0, ticket.0, 0);
            }
            Err(_) => {
                self.core.a.close(root.domain, one_shot).unwrap();
                assert_ne!(
                    entry.revoke_owned(self.core.a),
                    StateCode::Retained,
                    "V5 refused selected owner retained"
                );
                extended(frame, 2, 0, 0);
            }
        }
    }
    pub(super) fn receive_selected(
        &mut self,
        index: usize,
        cap: Handle,
        frame: &mut UserContext,
    ) -> bool {
        if index == 0 {
            return false;
        }
        let actor = self.actors[index - 1].as_ref().unwrap();
        let child = actor.child;
        let Some(s) = slot(child) else { return false };
        if self.wire(actor.meta, cap, RECEIVE) != child.inbox().map(Channel::index) {
            return false;
        }
        let select = &mut self.selected[s];
        let Some(route) = select.route.as_mut() else {
            scalar(frame, 2, 0);
            return true;
        };
        match route.receive(
            self.core.a,
            self.core.s,
            self.core.registry,
            self.token,
            actor.meta.thread,
            crate::timer::now(),
        ) {
            Ok(delivery) => {
                let (mut entry, ticket) = select
                    .pending
                    .take()
                    .expect("actual V5 pending selected branch");
                assert_eq!(delivery.ticket, ticket);
                assert_eq!(delivery.length, 8);
                let grant = delivery
                    .capability
                    .expect("actual attenuated endpoint SEND");
                entry.delivered(ticket, delivery.ticket);
                select.current = Some(entry);
                scalar(
                    frame,
                    0,
                    u64::from_le_bytes(delivery.bytes[..8].try_into().unwrap()),
                );
                frame.registers[11] = grant.0;
            }
            Err(ev_kernel::live_grant::Error::Ipc(IpcError::Empty)) => scalar(frame, 2, 0),
            Err(_) => scalar(frame, 1, 0),
        }
        true
    }
    pub(super) fn stop_selected(&mut self, index: usize) -> Result<(), u64> {
        let Some(actor) = self
            .actors
            .get(index.wrapping_sub(1))
            .and_then(Option::as_ref)
        else {
            return Ok(());
        };
        let Some(s) = slot(actor.child) else {
            return Ok(());
        };
        let select = &mut self.selected[s];
        if let Some((mut entry, ticket)) = select.pending.take() {
            let state = entry.withdraw_owned(
                self.core.a,
                select.route.as_mut().unwrap(),
                ticket,
                crate::timer::now(),
            );
            if state == StateCode::Retained || !entry.queue_cleared() {
                select.pending = Some((entry, ticket));
                return Err(2);
            }
            select.current = Some(entry);
        }
        if let Some(entry) = &mut select.current
            && entry.revoke_owned(self.core.a) == StateCode::Retained
        {
            return Err(2);
        }
        Ok(())
    }
    pub(super) fn retire_selected(&mut self, index: usize) -> Result<(), u64> {
        let Some(actor) = self
            .actors
            .get(index.wrapping_sub(1))
            .and_then(Option::as_ref)
        else {
            return Ok(());
        };
        let Some(s) = slot(actor.child) else {
            return Ok(());
        };
        let credits = self.pending.map(|p| p.map(|p| p.credit));
        let select = &mut self.selected[s];
        if select.pending.is_some() {
            return Err(2);
        }
        if let Some(route) = select.route.take() {
            match route.into_stopped_route(self.core.a, self.core.s, self.core.registry) {
                Ok(stopped) => {
                    select.stopped = Some(stopped);
                    if let Some(entry) = &mut select.current {
                        entry
                            .observe_stopped(
                                self.core.s,
                                self.core.registry,
                                select.stopped.as_ref().unwrap(),
                                &credits,
                            )
                            .map_err(|_| 2u64)?;
                    }
                }
                Err(rejected) => {
                    select.route = Some(rejected.route);
                    return Err(2);
                }
            }
        }
        Ok(())
    }
    pub(super) fn managed_send_retire(
        &mut self,
        index: usize,
        process: Handle,
        nonce: u32,
    ) -> Result<StateCode, u64> {
        if index != 0 {
            return Err(1);
        }
        let target = self.find_control(self.root.meta.domain, process)?;
        let Some(s) = slot(self.actors[target - 1].as_ref().unwrap().child) else {
            return Err(1);
        };
        let credits = self.pending.map(|p| p.map(|p| p.credit));
        let context = RetireContext {
            caller: self.current(index),
            root: self.root.meta,
            token: self.token,
        };
        let select = &mut self.selected[s];
        let route = select.route.as_mut().ok_or(1u64)?;
        let state = if let Some((entry, ticket)) = &mut select.pending {
            entry
                .retire(
                    self.core.a,
                    self.core.s,
                    self.core.registry,
                    context,
                    process,
                    nonce,
                    route,
                    Some(*ticket),
                    &credits,
                    crate::timer::now(),
                )
                .map_err(|_| 1u64)?
        } else {
            select
                .current
                .as_mut()
                .ok_or(1u64)?
                .retire(
                    self.core.a,
                    self.core.s,
                    self.core.registry,
                    context,
                    process,
                    nonce,
                    route,
                    None,
                    &credits,
                    crate::timer::now(),
                )
                .map_err(|_| 1u64)?
        };
        if select
            .pending
            .as_ref()
            .is_some_and(|(entry, _)| entry.queue_cleared())
        {
            let (entry, _) = select.pending.take().unwrap();
            select.current = Some(entry);
        }
        Ok(state)
    }
}
