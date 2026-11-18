//! Bounded opaque eight-byte transport. Source identity comes from dispatch.
//! No File, graphics, input or selection policy is interpreted here.
use super::*;
use ev_kernel::ipc::{Delivery, MAX_MESSAGES, Reclaimed};
use root_v2::graph::DeliveryMode;
#[derive(Clone, Copy)]
struct Accepted {
    ticket: Ticket,
    sender: SpaceId,
    process: ProcessId,
    thread: ThreadId,
}
pub(crate) struct Wire {
    pub object: usize,
    pub mailbox: Option<Mailbox>,
    pub receiver: SpaceId,
    pub bound: Option<ThreadId>,
    pub closed: bool,
    pub control: Option<Handle>,
    pub delivery: DeliveryMode,
    accepted: [Option<Accepted>; MAX_MESSAGES],
}
#[cfg(feature = "test-m6-session")]
#[derive(Clone, Copy)]
pub(crate) struct AsyncExpiry {
    pub message: ev_kernel::ipc::ExpiredScalar,
    pub process: ProcessId,
    pub thread: ThreadId,
}
#[cfg(feature = "test-m6-session")]
pub(crate) struct AsyncReceive {
    pub expired: [Option<AsyncExpiry>; MAX_MESSAGES],
    pub delivery: Option<(Delivery, ProcessId, ThreadId)>,
}
impl Wire {
    pub fn new(object: usize, receiver: SpaceId, mailbox: Mailbox, delivery: DeliveryMode) -> Self {
        Self {
            object,
            mailbox: Some(mailbox),
            receiver,
            bound: None,
            closed: false,
            control: None,
            delivery,
            accepted: [None; MAX_MESSAGES],
        }
    }
    pub fn pending(&self) -> usize {
        self.mailbox.as_ref().map_or(0, Mailbox::pending)
    }
    /// Pure executor preflight. Only an actually empty mailbox AND empty
    /// accepted ledger permit skipping this Async route. A missing mailbox or
    /// either unmatched debt must still reach the canonical checked path.
    /// Receive's current-capture deadline check remains independent of this.
    #[cfg(feature = "test-m6-session")]
    pub fn needs_async_expiry(&self) -> bool {
        self.delivery == DeliveryMode::Async
            && (!self
                .mailbox
                .as_ref()
                .is_some_and(|mailbox| mailbox.pending() == 0)
                || self.accepted.iter().any(Option::is_some))
    }
    #[cfg(feature = "test-m6-session")]
    pub fn expire_async(
        &mut self,
        authority: &mut Authority,
        now: u64,
    ) -> Result<[Option<AsyncExpiry>; MAX_MESSAGES], IpcError> {
        let mut expired = [None; MAX_MESSAGES];
        if self.delivery != DeliveryMode::Async {
            return Ok(expired);
        }
        // Check the entire batch before any message or accepted-row mutation.
        // A future capability-bearing protocol cannot be silently reinterpreted.
        for (slot, accepted) in self.accepted.into_iter().enumerate() {
            if let Some(accepted) = accepted {
                let message = self
                    .mailbox
                    .as_ref()
                    .ok_or(IpcError::RestrictedBinding)?
                    .expired_scalar(accepted.sender, accepted.ticket, now)?;
                expired[slot] = message.map(|message| AsyncExpiry {
                    message,
                    process: accepted.process,
                    thread: accepted.thread,
                });
            }
        }
        for (slot, receipt) in expired.into_iter().enumerate() {
            if let Some(receipt) = receipt {
                let actual = self
                    .mailbox
                    .as_mut()
                    .unwrap()
                    .expire_scalar(
                        authority,
                        receipt.message.sender,
                        receipt.message.ticket,
                        now,
                    )
                    .expect("preflighted scalar expiry")
                    .expect("same serialized queued deadline");
                assert_eq!(actual, receipt.message);
                self.accepted[slot] = None;
            }
        }
        Ok(expired)
    }
    #[cfg(feature = "test-m6-session")]
    pub fn withdraw_rpc(
        &mut self,
        authority: &mut Authority,
        rpc: &mut Rpc,
        callee: ThreadId,
        call: CallId,
        ticket: Ticket,
        now: u64,
    ) -> Result<(), ev_kernel::rpc::ScalarError> {
        let slot = self
            .accepted
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.ticket == ticket))
            .ok_or(ev_kernel::rpc::ScalarError::Ipc(IpcError::InvalidTicket))?;
        let mailbox = self
            .mailbox
            .as_mut()
            .ok_or(ev_kernel::rpc::ScalarError::Ipc(
                IpcError::RestrictedBinding,
            ))?;
        let completion = rpc.complete_scalar(
            callee,
            call,
            now,
            Some(ev_kernel::rpc::ScalarWithdrawal {
                authority,
                mailbox,
                ticket,
            }),
        )?;
        assert!(!completion.deliver_reply && !completion.wake_caller);
        self.accepted[slot] = None;
        Ok(())
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
        if self.delivery != DeliveryMode::Async {
            return Err(IpcError::RestrictedBinding);
        }
        self.send_message(a, m, cap, value, deadline, now)
    }
    pub fn send_rpc(
        &mut self,
        a: &mut Authority,
        m: Metadata,
        cap: Handle,
        value: u64,
        deadline: Deadline,
        now: u64,
    ) -> Result<Ticket, IpcError> {
        if self.delivery != DeliveryMode::Rpc {
            return Err(IpcError::RestrictedBinding);
        }
        self.send_message(a, m, cap, value, deadline, now)
    }
    fn send_message(
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
    #[cfg(any(not(feature = "test-m6-session"), test))]
    pub fn receive(
        &mut self,
        a: &mut Authority,
        m: Metadata,
        cap: Handle,
        now: u64,
    ) -> Result<(Delivery, ProcessId, ThreadId), IpcError> {
        if self.delivery != DeliveryMode::Async {
            return Err(IpcError::RestrictedBinding);
        }
        self.receive_message(a, m, cap, now)
    }
    /// Actual syscall-capture boundary. The executor may have observed a future
    /// ticket immediately before user execution crossed that ticket's cut.
    /// Reclaim its exact undelivered scalar credit before returning NoData;
    /// neither an expired frame nor a later live frame is reported as delivered.
    #[cfg(feature = "test-m6-session")]
    pub fn receive_async_at(
        &mut self,
        a: &mut Authority,
        m: Metadata,
        cap: Handle,
        now: u64,
    ) -> Result<AsyncReceive, IpcError> {
        if self.delivery != DeliveryMode::Async {
            return Err(IpcError::RestrictedBinding);
        }
        // Authorize the real receiver/endpoint before any expiry mutation.
        match self
            .mailbox
            .as_ref()
            .ok_or(IpcError::RestrictedBinding)?
            .peek_ticket(a, m.domain, cap, now)
        {
            Ok(_) | Err(IpcError::Empty | IpcError::Expired) => {}
            Err(error) => return Err(error),
        }
        let expired = self.expire_async(a, now)?;
        let delivery = if expired.iter().any(Option::is_some) {
            None
        } else {
            match self.receive_message(a, m, cap, now) {
                Ok(delivery) => Some(delivery),
                Err(IpcError::Empty) => None,
                Err(error) => return Err(error),
            }
        };
        Ok(AsyncReceive { expired, delivery })
    }
    pub fn receive_rpc(
        &mut self,
        a: &mut Authority,
        m: Metadata,
        cap: Handle,
        now: u64,
    ) -> Result<(Delivery, ProcessId, ThreadId), IpcError> {
        if self.delivery != DeliveryMode::Rpc {
            return Err(IpcError::RestrictedBinding);
        }
        self.receive_message(a, m, cap, now)
    }
    fn receive_message(
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
