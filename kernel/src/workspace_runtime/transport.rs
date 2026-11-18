use super::*;
mod wire;
pub(super) use wire::Wire;
#[derive(Clone, Copy)]
pub(super) struct Pending {
    pub id: CallId,
    pub caller: usize,
    pub callee: usize,
    pub wire: usize,
    pub wait: WaitTicket,
    pub ticket: Ticket,
    pub value: u64,
    pub delivered: bool,
    pub terminal: Option<Status>,
    pub deadline: u64,
    pub by: u64,
    pub credit: ev_kernel::rpc::AcceptedSnapshot,
}
fn status(status: Status) -> u64 {
    match status {
        Status::Ok => 0,
        Status::Cancelled => 6,
        Status::DeadlineExceeded => 4,
        Status::PeerDied => 5,
    }
}
impl World {
    fn block_denied(&mut self, wire: usize, status: u64, error: Option<ev_kernel::rpc::Error>) {
        if wire == Channel::WorkspaceBlock.index() {
            let trace = &mut self.facts.block;
            trace.outcome = if error.is_some() { 4 } else { 3 };
            trace.status = status;
            trace.error = error;
            trace.done = crate::timer::now();
        }
    }
    pub(super) fn bind_receiver(
        &mut self,
        index: usize,
        endpoint: Handle,
        process: Handle,
    ) -> Result<(), u64> {
        let caller = self.current(index);
        let w = self
            .wire(
                caller,
                endpoint,
                if process.0 == 0 {
                    RECEIVE
                } else {
                    Rights::CONTROL
                },
            )
            .ok_or(1u64)?;
        let (target, receive) = if process.0 == 0 {
            (caller, endpoint)
        } else {
            if index != 0 {
                return Err(1);
            }
            let target_index = self.find_control(caller.domain, process)?;
            let actor = self.actors[target_index - 1].as_ref().unwrap();
            if !actor.bound {
                return Err(1);
            }
            if graph::Channel::from_wire_index(w).is_none_or(|c| c.receiver() != actor.child) {
                return Err(1);
            }
            let selector = graph::grants(actor.child)
                .position(|g| {
                    g.source == graph::Source::Endpoint(Channel::from_wire_index(w).unwrap())
                        && g.rights == 272
                })
                .ok_or(1u64)? as u64
                + 1;
            (
                actor.meta,
                self.core
                    .registry
                    .grant(self.core.a, caller.domain, process, selector)
                    .map_err(|_| 1u64)?,
            )
        };
        if process.0 == 0 {
            if index == 0 {
                if w != graph::ROOT_EVENTS_WIRE {
                    return Err(1);
                }
            } else if w >= 23
                || Channel::from_wire_index(w).unwrap().receiver()
                    != self.actors[index - 1].as_ref().unwrap().child
            {
                return Err(1);
            }
        }
        if self.selected_binding(w, target, endpoint) {
            return Ok(());
        }
        let wire = self.wires[w].as_mut().unwrap();
        wire.bind(self.core.a, caller.domain, endpoint, target, receive)
            .map_err(|_| 2u64)?;
        if wire.delivery == DeliveryMode::Rpc && wire.bound != Some(target.thread) {
            self.core
                .rpc
                .bind_endpoint(
                    self.core.a,
                    target.domain,
                    receive,
                    target.thread,
                    Policy::new(8, 0).unwrap(),
                )
                .map_err(|_| 1u64)?;
        }
        wire.bound = Some(target.thread);
        Ok(())
    }
    pub(super) fn call(
        &mut self,
        index: usize,
        cap: Handle,
        value: u64,
        absolute: u64,
        frame: &mut UserContext,
    ) -> bool {
        let now = crate::timer::now();
        let meta = self.current(index);
        let Some(w) = self.wire(meta, cap, Rights::SEND) else {
            scalar(frame, 1, 0);
            return false;
        };
        let Some(channel) = Channel::from_wire_index(w) else {
            scalar(frame, 1, 0);
            return false;
        };
        if w == Channel::WorkspaceBlock.index() {
            let parent = self.core.rpc.serving(meta.thread);
            let trace = &mut self.facts.block;
            trace.attempts += 1;
            trace.at = now;
            trace.done = 0;
            trace.request = value;
            trace.deadline = absolute;
            trace.caller = index;
            trace.parent = parent;
            trace.id = None;
            trace.outcome = 0;
            trace.status = 0;
            trace.response = 0;
            trace.error = None;
        }
        let sender = if index == 0 {
            graph::Sender::Root
        } else {
            graph::Sender::Child(self.actors[index - 1].as_ref().unwrap().child)
        };
        if channel.delivery() != DeliveryMode::Rpc
            || !channel.allows(sender)
            || absolute <= now
            || absolute == u64::MAX
            || absolute > now.saturating_add(channel.session_rpc_ticks())
        {
            self.block_denied(w, 4, None);
            scalar(frame, 4, 0);
            return false;
        }
        let Some(callee) = self.wires[w]
            .as_ref()
            .unwrap()
            .bound
            .and_then(|t| self.index_thread(t))
        else {
            self.block_denied(w, 2, None);
            scalar(frame, 2, 0);
            return false;
        };
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            self.block_denied(w, 2, None);
            scalar(frame, 2, 0);
            return false;
        };
        if self.pending.iter().flatten().any(|p| p.caller == index)
            || self.wires[w].as_ref().unwrap().pending() != 0
        {
            self.block_denied(w, 2, None);
            scalar(frame, 2, 0);
            return false;
        }
        let deadline = Deadline::after(0, absolute).unwrap();
        if self.core.s.check_block(0, deadline).is_err() {
            self.block_denied(w, 4, None);
            scalar(frame, 4, 0);
            return false;
        }
        if self.wires[w]
            .as_ref()
            .unwrap()
            .mailbox
            .as_ref()
            .unwrap()
            .check_send(
                self.core.a,
                meta.domain,
                cap,
                &value.to_le_bytes(),
                deadline,
                now,
            )
            .is_err()
        {
            self.block_denied(w, 2, None);
            scalar(frame, 2, 0);
            return false;
        }
        let id = match self.core.rpc.begin(
            self.core.a,
            meta.thread,
            cap,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        ) {
            Ok(id) => id,
            Err(error) => {
                let code = match error {
                    ev_kernel::rpc::Error::DeadlineExceeded => 4,
                    ev_kernel::rpc::Error::PeerDied => 5,
                    ev_kernel::rpc::Error::Cancelled => 6,
                    ev_kernel::rpc::Error::WouldBlock | ev_kernel::rpc::Error::Overloaded => 2,
                    _ => 1,
                };
                self.block_denied(w, code, Some(error));
                scalar(
                    frame,
                    match error {
                        ev_kernel::rpc::Error::DeadlineExceeded => 4,
                        ev_kernel::rpc::Error::PeerDied => 5,
                        ev_kernel::rpc::Error::Cancelled => 6,
                        ev_kernel::rpc::Error::WouldBlock | ev_kernel::rpc::Error::Overloaded => 2,
                        _ => 1,
                    },
                    0,
                );
                return false;
            }
        };
        let ticket = self.wires[w]
            .as_mut()
            .unwrap()
            .send_rpc(self.core.a, meta, cap, value, deadline, now)
            .expect("V5 preflighted scalar queue");
        let wait = self
            .core
            .s
            .block_guarded(0, deadline)
            .expect("V5 preflighted guarded waiter");
        self.pending[slot] = Some(Pending {
            credit: self
                .core
                .rpc
                .accepted_snapshot(id)
                .expect("actual accepted V5 credit snapshot"),
            id,
            caller: index,
            callee,
            wire: w,
            wait,
            ticket,
            value,
            delivered: false,
            terminal: None,
            deadline: absolute,
            by: absolute
                .checked_add(1024)
                .expect("V5 finite quiescence cut"),
        });
        self.facts.calls += 1;
        if w == Channel::WorkspaceBlock.index() {
            let trace = &mut self.facts.block;
            trace.accepted += 1;
            trace.id = Some(id);
            trace.outcome = 1;
        }
        scalar(frame, 0, 0);
        true
    }
    pub(super) fn receive_rpc(&mut self, index: usize, cap: Handle, frame: &mut UserContext) {
        let meta = self.current(index);
        let Some(w) = self.wire(meta, cap, RECEIVE) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(slot) = self.pending.iter().position(|p| {
            p.is_some_and(|p| {
                p.wire == w && p.callee == index && !p.delivered && p.terminal.is_none()
            })
        }) else {
            extended(frame, 2, 0, 0);
            return;
        };
        let p = self.pending[slot].unwrap();
        if self.core.rpc.serving(meta.thread) != Some(p.id) || !self.core.s.waiting(p.wait) {
            extended(frame, 1, 0, 0);
            return;
        }
        let (d, _, _) = self.wires[w]
            .as_mut()
            .unwrap()
            .receive_rpc(self.core.a, meta, cap, crate::timer::now())
            .expect("V5 actual received RPC ticket");
        assert_eq!(d.ticket, p.ticket);
        assert_eq!(d.length, 8);
        assert_eq!(d.capability, None);
        assert_eq!(&d.bytes[..8], &p.value.to_le_bytes());
        self.pending[slot].as_mut().unwrap().delivered = true;
        extended(frame, 0, p.value, p.id.serial());
    }
    pub(super) fn reply_rpc(
        &mut self,
        index: usize,
        cap: Handle,
        value: u64,
        serial: u64,
        frame: &mut UserContext,
    ) {
        self.maintain_calls()
            .expect("V5 canonical pre-ACK outcomes");
        let meta = self.current(index);
        let Some(w) = self.wire(meta, cap, RECEIVE) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(slot) = self.pending.iter().position(|p| {
            p.is_some_and(|p| {
                p.wire == w && p.callee == index && p.delivered && p.id.serial() == serial
            })
        }) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let p = self.pending[slot].unwrap();
        let completion =
            match self
                .core
                .rpc
                .complete_scalar(meta.thread, p.id, crate::timer::now(), None)
            {
                Ok(done) => done,
                Err(_) => {
                    extended(frame, 2, 0, 0);
                    return;
                }
            };
        if p.terminal.is_none() {
            assert_eq!(completion.status, Status::Ok);
            assert!(completion.wake_caller && completion.deliver_reply);
        } else {
            assert_eq!(Some(completion.status), p.terminal);
            assert!(!completion.wake_caller && !completion.deliver_reply);
        }
        if self.core.s.state(self.current(p.caller).thread) != Ok(State::Exited) {
            assert!(self.core.s.wake(p.wait));
            scalar(
                self.context_mut(p.caller),
                status(completion.status),
                if completion.status == Status::Ok {
                    value
                } else {
                    0
                },
            );
        }
        self.pending[slot] = None;
        if w == Channel::WorkspaceBlock.index() {
            let trace = &mut self.facts.block;
            trace.replies += 1;
            trace.id = Some(p.id);
            trace.done = crate::timer::now();
            trace.outcome = 2;
            trace.status = status(completion.status);
            trace.response = value;
        }
        self.facts.replies += 1;
        extended(frame, 0, 0, 0);
    }
    /// Guarded caller credit remains blocked after expiry until actual queued
    /// withdrawal or callee acknowledgement. A1024tick missed quiescence cut
    /// aborts with all actual owners retained, never fabricates a successful reply.
    pub(super) fn maintain_calls(&mut self) -> Result<(), &'static str> {
        let now = crate::timer::now();
        let notifications = self
            .core
            .rpc
            .expire(now)
            .map_err(|_| "V5 RPC monotonic expiry")?;
        self.terminal_notifications(notifications, now)?;
        for _ in 0..8 {
            let mut progress = false;
            for slot in 0..8 {
                let Some(p) = self.pending[slot] else {
                    continue;
                };
                if p.terminal.is_none() {
                    continue;
                }
                let callee = self.current(p.callee);
                if self.core.s.state(callee.thread) == Ok(State::Exited) {
                    if self
                        .pending
                        .iter()
                        .flatten()
                        .any(|child| child.caller == p.callee)
                    {
                        continue;
                    }
                    self.wires[p.wire]
                        .as_mut()
                        .unwrap()
                        .close(self.core.a, now)
                        .map_err(|_| "V5 stopped actual RPC receiver drain")?;
                    self.finish_terminal(slot);
                    progress = true;
                } else if !p.delivered {
                    match self.wires[p.wire].as_mut().unwrap().withdraw_rpc(
                        self.core.a,
                        self.core.rpc,
                        callee.thread,
                        p.id,
                        p.ticket,
                        now,
                    ) {
                        Ok(()) => {
                            self.finish_terminal(slot);
                            progress = true;
                        }
                        Err(ev_kernel::rpc::ScalarError::Rpc(
                            ev_kernel::rpc::Error::AlreadyWaiting,
                        )) => continue,
                        Err(_) => return Err("V5 actual queued withdrawal"),
                    }
                }
            }
            if !progress {
                break;
            }
        }
        if self
            .pending
            .iter()
            .flatten()
            .any(|p| p.terminal.is_some() && now >= p.by)
        {
            return Err("V5 delivered call failed finite quiescence cut");
        }
        Ok(())
    }
    pub(super) fn terminal_notifications(
        &mut self,
        notifications: ev_kernel::rpc::Notifications,
        now: u64,
    ) -> Result<(), &'static str> {
        for event in notifications.iter() {
            let slot = self
                .pending
                .iter()
                .position(|p| p.is_some_and(|p| p.id == event.call))
                .ok_or("V5 unmatched RPC outcome")?;
            let p = self.pending[slot].as_mut().unwrap();
            if event.status == Status::Ok || !event.wake_caller || event.deliver_reply {
                return Err("V5 terminal outcome identity");
            }
            if let Some(previous) = p.terminal {
                if previous != event.status {
                    return Err("V5 changed terminal outcome");
                }
            } else {
                p.terminal = Some(event.status);
                if event.status != Status::DeadlineExceeded {
                    p.by = now.checked_add(1024).ok_or("V5 finite terminal cut")?;
                }
            }
        }
        Ok(())
    }
    fn finish_terminal(&mut self, slot: usize) {
        let p = self.pending[slot].unwrap();
        if p.wire == Channel::WorkspaceBlock.index() {
            let trace = &mut self.facts.block;
            trace.id = Some(p.id);
            trace.done = crate::timer::now();
            trace.outcome = 5;
            trace.status = status(p.terminal.unwrap());
        }
        if self.core.s.state(self.current(p.caller).thread) != Ok(State::Exited) {
            assert!(self.core.s.wake(p.wait));
            scalar(self.context_mut(p.caller), status(p.terminal.unwrap()), 0);
        }
        self.pending[slot] = None;
    }
}
