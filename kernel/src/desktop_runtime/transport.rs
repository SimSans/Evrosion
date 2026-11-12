//! Bounded opaque eight-byte transport. Source identity comes from dispatch.
//! No File, graphics, input or selection policy is interpreted here.
use super::*;
use ev_kernel::ipc::{Delivery, MAX_MESSAGES, Reclaimed};
#[derive(Clone, Copy)]
struct Accepted {
    ticket: Ticket,
    sender: SpaceId,
    process: ProcessId,
    thread: ThreadId,
}
pub(super) struct Wire {
    pub object: usize,
    pub mailbox: Option<Mailbox>,
    pub receiver: SpaceId,
    pub bound: Option<ThreadId>,
    pub closed: bool,
    pub control: Option<Handle>,
    accepted: [Option<Accepted>; MAX_MESSAGES],
}
impl Wire {
    pub fn new(object: usize, receiver: SpaceId, mailbox: Mailbox) -> Self {
        Self {
            object,
            mailbox: Some(mailbox),
            receiver,
            bound: None,
            closed: false,
            control: None,
            accepted: [None; MAX_MESSAGES],
        }
    }
    pub fn pending(&self) -> usize {
        self.mailbox.as_ref().map_or(0, Mailbox::pending)
    }
    /// Retained accepted-send bookkeeping, read only on fatal Native diagnosis.
    /// These scalar IDs correlate the receipt; none conveys authority.
    #[cfg(feature = "test-m5-native")]
    pub fn accepted_senders(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.accepted.iter().flatten().map(|accepted| {
            (
                accepted.ticket.0,
                accepted.process.diagnostic_id(),
                accepted.thread.diagnostic_id(),
            )
        })
    }
    pub fn send(
        &mut self,
        a: &mut Authority,
        m: Metadata,
        cap: Handle,
        value: u64,
        deadline: Deadline,
        now: u64,
    ) -> Result<Ticket, IpcError> {
        let slot = self
            .accepted
            .iter()
            .position(Option::is_none)
            .ok_or(IpcError::Full)?;
        let ticket = self
            .mailbox
            .as_mut()
            .ok_or(IpcError::RestrictedBinding)?
            .send(
                a,
                m.domain,
                cap,
                Outgoing {
                    bytes: &value.to_le_bytes(),
                    capability: None,
                    deadline,
                },
                now,
            )?;
        self.accepted[slot] = Some(Accepted {
            ticket,
            sender: m.domain,
            process: m.process,
            thread: m.thread,
        });
        Ok(ticket)
    }
    pub fn receive(
        &mut self,
        a: &mut Authority,
        m: Metadata,
        cap: Handle,
        now: u64,
    ) -> Result<(Delivery, ProcessId, ThreadId), IpcError> {
        let mailbox = self.mailbox.as_mut().ok_or(IpcError::RestrictedBinding)?;
        let ticket = mailbox.peek_ticket(a, m.domain, cap, now)?;
        let slot = self
            .accepted
            .iter()
            .position(|x| x.is_some_and(|x| x.ticket == ticket))
            .ok_or(IpcError::InvalidTicket)?;
        let accepted = self.accepted[slot].unwrap();
        let delivery = mailbox.receive(a, m.domain, cap, now)?;
        assert_eq!(delivery.ticket, ticket);
        self.accepted[slot] = None;
        Ok((delivery, accepted.process, accepted.thread))
    }
    pub fn bind(
        &mut self,
        a: &Authority,
        controller: SpaceId,
        control: Handle,
        target: Metadata,
        receive: Handle,
    ) -> Result<(), IpcError> {
        if self.receiver == target.domain && !self.closed {
            return Ok(());
        }
        self.control = Some(control);
        let mailbox = self.mailbox.as_mut().ok_or(IpcError::RestrictedBinding)?;
        if self.closed {
            mailbox.reopen_empty(a, controller, control, target.domain, receive)?;
        } else {
            mailbox.rebind_empty(a, controller, control, target.domain, receive)?;
        }
        self.receiver = target.domain;
        self.closed = false;
        self.bound = None;
        Ok(())
    }
    pub fn close(&mut self, a: &mut Authority, now: u64) -> Result<(), IpcError> {
        let mailbox = self.mailbox.as_mut().ok_or(IpcError::RestrictedBinding)?;
        if !self.closed {
            mailbox.receiver_died(self.receiver)?;
            self.closed = true;
        }
        for entry in &mut self.accepted {
            if let Some(accepted) = *entry
                && a.is_live_space(accepted.sender)
            {
                assert_eq!(
                    mailbox.reclaim(a, accepted.sender, accepted.ticket, now)?,
                    Reclaimed::NoCapability
                );
                *entry = None;
            }
        }
        mailbox.reap_dead_senders(a, now)?;
        for entry in &mut self.accepted {
            if entry.is_some_and(|x| !a.is_live_space(x.sender)) {
                *entry = None;
            }
        }
        self.bound = None;
        assert_eq!(
            mailbox.pending(),
            0,
            "closed incarnation must drain every sender's queued payload"
        );
        assert!(self.accepted.iter().all(Option::is_none));
        Ok(())
    }
}
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
    #[cfg(feature = "test-m5-native")]
    pub file_replace: bool,
}
impl Runtime<'_, '_> {
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
        if absolute <= self.stop.tick() || absolute > self.stop.tick().checked_add(1024).unwrap() {
            scalar(frame, 4, 0);
            return false;
        }
        let Some(wire) = self.wire(m, cap, Rights::SEND) else {
            scalar(frame, 1, 0);
            return false;
        };
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
            Err(_) => {
                scalar(frame, 1, 0);
                return false;
            }
        };
        // Cap-free queue has reserved capacity and its exact live endpoint was
        // checked by Rpc.begin; serialized IF0 ownership prevents interleaving.
        let ticket = self.wires[wire]
            .as_mut()
            .unwrap()
            .send(self.a, m, cap, value, deadline, now)
            .expect("preflighted RPC queue");
        if matches!(wire, 12 | 14) {
            self.snapshots = [observation::Snapshot::default(); 2];
        }
        let wait = self.s.block(0, deadline).unwrap();
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
        self.pending[slot] = Some(Pending {
            id,
            caller: index,
            callee,
            wire,
            wait,
            ticket,
            value,
            delivered: false,
            #[cfg(feature = "test-m5-native")]
            file_replace,
        });
        self.facts.calls += 1;
        self.facts.blocks += 1;
        self.facts.max_pending = self.facts.max_pending.max(self.rpc.outstanding() as u64);
        scalar(frame, 0, 0);
        true
    }
    pub(super) fn receive_rpc(&mut self, index: usize, cap: Handle, frame: &mut UserContext) {
        let m = self.current(index);
        let Some(wire) = self.wire(m, cap, RECEIVE) else {
            extended(frame, 1, 0, 0);
            return;
        };
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
            .receive(self.a, m, cap, crate::timer::now())
            .unwrap();
        assert_eq!(delivery.ticket, p.ticket);
        assert_eq!(delivery.length, 8);
        assert_eq!(delivery.capability, None);
        assert_eq!(&delivery.bytes[..8], &p.value.to_le_bytes());
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
        let m = self.current(index);
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
        if !self.s.waiting(p.wait) {
            extended(frame, 1, 0, 0);
            return;
        }
        let presented = self.before_reply(p, value);
        let completion = self
            .rpc
            .complete(m.thread, p.id, crate::timer::now())
            .unwrap();
        assert!(completion.wake_caller);
        assert_eq!(completion.status, Status::Ok);
        assert!(self.s.wake(p.wait));
        scalar(self.context_mut(p.caller), 0, value);
        self.completed_opaque(p, value);
        if let Some(step) = presented {
            (self.observations)(Observation::Step(step));
        }
        self.pending[slot] = None;
        self.facts.replies += 1;
        self.facts.wakes += 1;
        extended(frame, 0, 0, 0);
    }
}
