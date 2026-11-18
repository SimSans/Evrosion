//! Bounded opaque scalar RPC. Source identity comes from actual dispatch.
use super::*;
use graph::DeliveryMode;
#[cfg(feature = "test-m6-network")]
mod rejection;
mod wire;
#[cfg(feature = "test-m6-session")]
pub(super) use wire::AsyncExpiry;
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
    #[cfg(feature = "test-m6-session")]
    pub terminal: Option<cancellation::Terminal>,
    #[cfg(feature = "test-m6-session")]
    pub deadline: Deadline,
    #[cfg(feature = "test-m6-session")]
    pub started: u64,
    #[cfg(feature = "test-m6-session")]
    pub sampled: bool,
    #[cfg(feature = "test-m5-native")]
    pub file_replace: bool,
}
impl Runtime<'_, '_> {
    #[cfg(feature = "test-m6-network")]
    #[inline(never)]
    fn record_rpc_rejection(
        &mut self,
        index: usize,
        capability: Handle,
        wire: Option<usize>,
        deadline: u64,
        tick: u64,
        code: rejection::Code,
    ) {
        if self.rpc_rejection_seen[index] {
            return;
        }
        self.rpc_rejection_seen[index] = true;
        let meta = self.current(index);
        let parent = self
            .rpc
            .serving(meta.thread)
            .and_then(|id| self.rpc.context(id).ok().map(|context| (id, context)));
        let (parent_call, parent_deadline, parent_delivered) =
            parent.map_or((0, 0, 0), |(id, context)| {
                (
                    id.serial(),
                    context.deadline.tick(),
                    self.pending
                        .iter()
                        .flatten()
                        .find(|p| p.id == id)
                        .map_or(2, |p| u8::from(p.delivered)),
                )
            });
        (self.observations)(Observation::SessionRpcRejection(SessionRpcRejection {
            actor: index,
            process: meta.process.diagnostic_id(),
            thread: meta.thread.diagnostic_id(),
            capability: capability.0,
            wire: wire.unwrap_or(255),
            endpoint: wire.map_or(0, |w| self.wires[w].as_ref().unwrap().object),
            deadline,
            tick,
            branch: code.branch,
            reason: code.reason,
            detail: code.detail,
            parent_call,
            parent_deadline,
            parent_delivered,
        }));
    }
    #[cfg(feature = "test-m6-session")]
    pub(super) fn trace_rpc(&mut self, pending: Pending, phase: SessionRpcPhase, status: u64) {
        if matches!(phase, SessionRpcPhase::Terminal) {
            if self.rpc_trace[1] >= 32 {
                return;
            }
            self.rpc_trace[1] += 1;
        } else if !pending.sampled {
            return;
        }
        let caller = self.metadata(pending.caller).unwrap();
        let callee = self.metadata(pending.callee).unwrap();
        let budget = self
            .s
            .cpu_budget(callee.job)
            .unwrap()
            .expect("measured session budget");
        (self.observations)(Observation::SessionRpc(SessionRpc {
            phase,
            call_epoch: pending.id.epoch().get(),
            call: pending.id.serial(),
            caller_process: caller.process.diagnostic_id(),
            caller_thread: caller.thread.diagnostic_id(),
            callee_process: callee.process.diagnostic_id(),
            callee_thread: callee.thread.diagnostic_id(),
            endpoint: self.wires[pending.wire].as_ref().unwrap().object,
            request: pending.value,
            started: pending.started,
            tick: crate::timer::now(),
            deadline: pending.deadline.tick(),
            status,
            callee_cpu: self.s.usage(callee.job, Resource::CpuTicks).unwrap(),
            scheduler_tick: self.s.observed_tick(),
            budget,
        }));
    }
    pub(super) fn wire(&self, m: Metadata, cap: Handle, rights: Rights) -> Option<usize> {
        let object = self
            .a
            .authorize(m.domain, cap, Kind::Endpoint, rights)
            .ok()?
            .identity();
        self.wires
            .iter()
            .position(|w| w.as_ref().is_some_and(|w| w.object == object))
    }
    pub(super) fn call(
        &mut self,
        index: usize,
        cap: Handle,
        value: u64,
        absolute: u64,
        frame: &mut UserContext,
    ) -> bool {
        let m = self.current(index);
        let operation_origin = if cfg!(feature = "test-m6-session") {
            crate::timer::now()
        } else {
            self.stop.tick()
        };
        let span = if cfg!(feature = "test-m6-session") {
            self.wire(m, cap, Rights::SEND)
                .and_then(graph::channel)
                .map_or(1024, |channel| channel.session_rpc_ticks())
        } else {
            1024
        };
        let Some(operation_limit) = operation_origin.checked_add(span) else {
            scalar(frame, 4, 0);
            return false;
        };
        if absolute <= operation_origin || absolute == u64::MAX || absolute > operation_limit {
            scalar(frame, 4, 0);
            return false;
        }
        let Some(wire) = self.wire(m, cap, Rights::SEND) else {
            #[cfg(feature = "test-m6-network")]
            self.record_rpc_rejection(
                index,
                cap,
                None,
                absolute,
                crate::timer::now(),
                rejection::WIRE,
            );
            scalar(frame, 1, 0);
            #[cfg(feature = "test-m6-network-negative")]
            self.negative_denial(
                index,
                ev_userspace_contract::syscall::RPC_CALL,
                0,
                value,
                frame,
            );
            return false;
        };
        if self.wires[wire].as_ref().unwrap().delivery != DeliveryMode::Rpc {
            #[cfg(feature = "test-m6-network")]
            self.record_rpc_rejection(
                index,
                cap,
                Some(wire),
                absolute,
                crate::timer::now(),
                rejection::DELIVERY,
            );
            scalar(frame, 1, 0);
            return false;
        }
        let Some(callee) = self.wires[wire]
            .as_ref()
            .unwrap()
            .bound
            .and_then(|t| self.index_thread(t))
        else {
            scalar(frame, 2, 0);
            return false;
        };
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            scalar(frame, 2, 0);
            return false;
        };
        if self.wires[wire].as_ref().unwrap().pending() != 0 {
            scalar(frame, 2, 0);
            return false;
        }
        let deadline = Deadline::after(0, absolute).unwrap();
        if self.s.check_block(0, deadline).is_err() {
            scalar(frame, 4, 0);
            return false;
        }
        let now = crate::timer::now();
        if let Err(error) = self.wires[wire]
            .as_ref()
            .unwrap()
            .mailbox
            .as_ref()
            .unwrap()
            .check_send(self.a, m.domain, cap, &value.to_le_bytes(), deadline, now)
        {
            #[cfg(feature = "test-m6-network")]
            if error != IpcError::Full {
                self.record_rpc_rejection(
                    index,
                    cap,
                    Some(wire),
                    absolute,
                    now,
                    rejection::mailbox(error),
                );
            }
            scalar(frame, if error == IpcError::Full { 2 } else { 1 }, 0);
            return false;
        }
        let id = match self.rpc.begin(
            self.a,
            m.thread,
            cap,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        ) {
            Ok(id) => id,
            Err(
                ev_kernel::rpc::Error::WouldBlock
                | ev_kernel::rpc::Error::Overloaded
                | ev_kernel::rpc::Error::UnknownEndpoint,
            ) => {
                scalar(frame, 2, 0);
                return false;
            }
            Err(ev_kernel::rpc::Error::DeadlineExceeded) => {
                scalar(frame, 4, 0);
                return false;
            }
            Err(ev_kernel::rpc::Error::PeerDied) => {
                scalar(frame, 5, 0);
                return false;
            }
            Err(ev_kernel::rpc::Error::Cancelled) => {
                scalar(frame, 6, 0);
                return false;
            }
            Err(error) => {
                #[cfg(feature = "test-m6-network")]
                self.record_rpc_rejection(
                    index,
                    cap,
                    Some(wire),
                    absolute,
                    now,
                    rejection::rpc(error),
                );
                let _ = error;
                scalar(frame, 1, 0);
                return false;
            }
        };
        // Cap-free queue has reserved capacity and its exact live endpoint was
        // checked by Rpc.begin; serialized IF0 ownership prevents interleaving.
        let ticket = self.wires[wire]
            .as_mut()
            .unwrap()
            .send_rpc(self.a, m, cap, value, deadline, now)
            .expect("preflighted RPC queue");
        if matches!(wire, 12 | 14) {
            self.snapshots = [observation::Snapshot::default(); 2];
        }
        #[cfg(not(feature = "test-m6-session"))]
        let wait = self.s.block(0, deadline).unwrap();
        #[cfg(feature = "test-m6-session")]
        let wait = self.s.block_guarded(0, deadline).unwrap();
        #[cfg(feature = "test-m5-native")]
        let file_replace = if self.native.is_some()
            && index == Child::App.index() + 1
            && callee == Child::File.index() + 1
            && (wire == Channel::NotesRead.index() || wire == Channel::PrivateRead.index())
        {
            let address = self.backing.alias(Scalar::Application);
            let bytes = core::array::from_fn::<_, 256, _>(|offset| {
                // SAFETY: exact retained initialized shared scalar; actual
                // captured App is the sole current producer before delivery.
                unsafe { (address as *const u8).add(offset).read_volatile() }
            });
            matches!(
                ev_userspace_contract::file::Request::decode(&bytes),
                Ok(ev_userspace_contract::file::Request::Replace { .. })
            )
        } else {
            false
        };
        #[cfg(feature = "test-m6-session")]
        let sampled = if callee == Child::Block.index() + 1 && self.rpc_trace[0] < 32 {
            self.rpc_trace[0] += 1;
            true
        } else {
            false
        };
        self.pending[slot] = Some(Pending {
            id,
            caller: index,
            callee,
            wire,
            wait,
            ticket,
            value,
            delivered: false,
            #[cfg(feature = "test-m6-session")]
            terminal: None,
            #[cfg(feature = "test-m6-session")]
            deadline,
            #[cfg(feature = "test-m6-session")]
            started: now,
            #[cfg(feature = "test-m6-session")]
            sampled,
            #[cfg(feature = "test-m5-native")]
            file_replace,
        });
        #[cfg(feature = "test-m6-network")]
        if self.startup_recording()
            && index == Child::App.index() + 1
            && callee == Child::Display.index() + 1
            && wire == Channel::AppPresent.index()
            && ev_kernel::startup_trace::present_request(value)
            && self
                .startup_trace
                .select_present(id.epoch().get(), id.serial())
        {
            self.startup_present(self.pending[slot].unwrap(), 3, now);
        }
        #[cfg(feature = "test-m6-session")]
        self.trace_rpc(self.pending[slot].unwrap(), SessionRpcPhase::Accepted, 0);
        self.facts.calls += 1;
        self.facts.blocks += 1;
        self.facts.max_pending = self.facts.max_pending.max(self.rpc.outstanding() as u64);
        #[cfg(feature = "test-m6-network-negative")]
        self.negative_client(self.pending[slot].unwrap(), None);
        scalar(frame, 0, 0);
        true
    }
    pub(super) fn receive_rpc(&mut self, index: usize, cap: Handle, frame: &mut UserContext) {
        let m = self.current(index);
        let Some(wire) = self.wire(m, cap, RECEIVE) else {
            extended(frame, 1, 0, 0);
            return;
        };
        if self.wires[wire].as_ref().unwrap().delivery != DeliveryMode::Rpc {
            extended(frame, 1, 0, 0);
            return;
        }
        let Some(slot) = self
            .pending
            .iter()
            .position(|p| p.is_some_and(|p| p.wire == wire && p.callee == index && !p.delivered))
        else {
            extended(frame, 2, 0, 0);
            return;
        };
        let p = self.pending[slot].unwrap();
        if self.rpc.serving(m.thread) != Some(p.id) || !self.s.waiting(p.wait) {
            extended(frame, 1, 0, 0);
            return;
        }
        let (delivery, _, _) = self.wires[wire]
            .as_mut()
            .unwrap()
            .receive_rpc(self.a, m, cap, crate::timer::now())
            .unwrap();
        assert_eq!(delivery.ticket, p.ticket);
        assert_eq!(delivery.length, 8);
        assert_eq!(delivery.capability, None);
        assert_eq!(&delivery.bytes[..8], &p.value.to_le_bytes());
        self.pending[slot].as_mut().unwrap().delivered = true;
        #[cfg(feature = "test-m6-network")]
        self.startup_present_now(p, 4);
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
        #[cfg(feature = "test-m6-network")]
        let startup_reply_tick = (index == Child::Display.index() + 1 && self.startup_recording())
            .then(crate::timer::now);
        let m = self.current(index);
        #[cfg(feature = "test-m6-session")]
        self.observe_rpc_outcomes(crate::timer::now())
            .expect("actual RPC outcome joins");
        let Some(wire) = self.wire(m, cap, RECEIVE) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(slot) = self.pending.iter().position(|p| {
            p.is_some_and(|p| {
                p.wire == wire && p.callee == index && p.delivered && p.id.serial() == serial
            })
        }) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let p = self.pending[slot].unwrap();
        #[cfg(feature = "test-m6-session")]
        let retired_caller = self
            .metadata(p.caller)
            .is_some_and(|meta| self.s.state(meta.thread) == Ok(State::Exited));
        #[cfg(not(feature = "test-m6-session"))]
        let retired_caller = false;
        if !self.s.waiting(p.wait) && !retired_caller {
            extended(frame, 1, 0, 0);
            return;
        }
        #[cfg(feature = "test-m6-session")]
        if p.terminal.is_some() {
            match self
                .rpc
                .complete_scalar(m.thread, p.id, crate::timer::now(), None)
            {
                Ok(completion) => {
                    assert!(!completion.deliver_reply && !completion.wake_caller);
                    assert_eq!(Some(completion.status), p.terminal.map(|t| t.status));
                    self.finish_cancelled_call(slot);
                    self.facts.replies += 1;
                    // The actual callee acknowledges that it no longer touches
                    // this request. Its reply body is never delivered as success.
                    extended(frame, 0, 0, 0);
                }
                Err(_) => extended(frame, 1, 0, 0),
            }
            return;
        }
        #[cfg(feature = "test-m6-network")]
        if let Some(tick) = startup_reply_tick {
            self.startup_present(p, 5, tick);
        }
        let presented = self.before_reply(p, value);
        #[cfg(feature = "test-m6-network-negative")]
        self.negative_client(p, Some(value));
        let completion = self
            .rpc
            .complete(m.thread, p.id, crate::timer::now())
            .unwrap();
        assert!(completion.wake_caller);
        assert_eq!(completion.status, Status::Ok);
        assert!(self.s.wake(p.wait));
        scalar(self.context_mut(p.caller), 0, value);
        #[cfg(feature = "test-m6-network")]
        if presented.is_some() {
            self.startup_present_now(p, 8);
        }
        self.completed_opaque(p, value);
        #[cfg(feature = "test-m6-session")]
        self.trace_rpc(p, SessionRpcPhase::Completed, 0);
        if let Some(step) = presented {
            (self.observations)(Observation::Step(step));
        }
        self.pending[slot] = None;
        self.facts.replies += 1;
        self.facts.wakes += 1;
        extended(frame, 0, 0, 0);
    }
}
