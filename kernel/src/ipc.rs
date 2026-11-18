//! Internal asynchronous mailbox. A single owner serializes the queue and
//! authority table; always use the same Authority instance supplied at binding; no lock, wait, allocation, syscall decoder or user pointer.
//! Capability moves enter private escrow at acceptance and leave it on delivery.
use crate::{
    capability::{Authority, Error as CapError, Handle, Kind, Rights, SpaceId},
    time::Deadline,
};
pub const MAX_MESSAGES: usize = 4;
pub const MAX_BYTES: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority(CapError),
    WrongEndpoint,
    WrongOwner,
    Full,
    Empty,
    TooLarge,
    Expired,
    Closed,
    ClockReversed,
    SequenceExhausted,
    InvalidTicket,
    NotReclaimable,
    NotManaged,
    RestrictedBinding,
}
impl From<CapError> for Error {
    fn from(value: CapError) -> Self {
        Self::Authority(value)
    }
}
#[derive(Clone, Copy)]
struct Message {
    ticket: Ticket,
    sender: SpaceId,
    bytes: [u8; MAX_BYTES],
    length: usize,
    cap: Option<Handle>,
    deadline: Deadline,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Exact accepted message identity, retained across escrow/receiver changes.
    /// Diagnostic receipt only; possession never authorizes queue operations.
    pub ticket: Ticket,
    pub bytes: [u8; MAX_BYTES],
    pub length: usize,
    pub capability: Option<Handle>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Reclaimed {
    NoCapability,
    Capability(Handle),
    Invalidated,
}
/// Receipt for a never-delivered, expired eight-byte message with no attached
/// authority. It is neither a delivery receipt nor physical-memory quiescence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiredScalar {
    pub ticket: Ticket,
    pub sender: SpaceId,
    pub deadline: Deadline,
    pub bytes: [u8; 8],
}
pub struct Outgoing<'a> {
    pub bytes: &'a [u8],
    pub capability: Option<Handle>,
    pub deadline: Deadline,
}
/// Unique receipt for one retired Registry-managed mailbox's closed escrow.
/// No physical or graph-wide quiescence is certified. The sequence and clock
/// survive replacement so stale tickets cannot name newly accepted messages.
#[derive(Debug)]
pub struct RetiredMailbox {
    escrow: SpaceId,
    delivery_policy: DeliveryPolicy,
    sequence: u64,
    now: u64,
}
/// A failed consuming retirement returns the complete unchanged owner.
pub struct RejectedMailbox {
    pub mailbox: Mailbox,
    pub error: Error,
}
pub(crate) struct RejectedReuse {
    pub(crate) receipt: RetiredMailbox,
    pub(crate) error: Error,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryPolicy {
    Preserve,
    SelectedFileSend,
}
pub struct Mailbox {
    endpoint: usize,
    receiver: SpaceId,
    escrow: SpaceId,
    messages: [Option<Message>; MAX_MESSAGES],
    sequence: u64,
    now: u64,
    closed: bool,
    managed: bool,
    delivery_policy: DeliveryPolicy,
}
impl Mailbox {
    /// Trusted kernel binding. Caller must not create another mailbox for the
    /// same descriptor; a future object registry owns this uniqueness constraint.
    pub fn new(
        authority: &mut Authority,
        receiver: SpaceId,
        endpoint: Handle,
    ) -> Result<Self, Error> {
        let identity = authority
            .authorize(
                receiver,
                endpoint,
                Kind::Endpoint,
                Rights::RECEIVE | Rights::CONTROL,
            )?
            .identity();
        let escrow = authority.create_space()?;
        Ok(Self {
            endpoint: identity,
            receiver,
            escrow,
            messages: [None; MAX_MESSAGES],
            sequence: 0,
            now: 0,
            closed: false,
            managed: false,
            delivery_policy: DeliveryPolicy::Preserve,
        })
    }
    /// Explicit immutable kernel-only selected-file policy. The trusted live
    /// route wrapper binds this mailbox to an actual managed recipient under
    /// ProcessCONTROL. No normal Send2 operation changes its delivery policy.
    #[cfg(test)] // Legacy portable models only; production consumes managed ownership.
    pub(crate) fn new_selected_file(
        authority: &mut Authority,
        receiver: SpaceId,
        endpoint: Handle,
    ) -> Result<Self, Error> {
        let mut mailbox = Self::new(authority, receiver, endpoint)?;
        mailbox.delivery_policy = DeliveryPolicy::SelectedFileSend;
        Ok(mailbox)
    }
    /// Consume the one actual Registry mailbox after exact typed binding. No
    /// second escrow is allocated; sequence/clock/managed provenance survive.
    /// A selected owner can only escape its route after verified stopped close,
    /// so no live selected route can be rebound/declassified through this API.
    #[allow(clippy::result_large_err)] // Refusal returns the whole mailbox owner.
    pub(crate) fn into_selected_file(
        mut self,
        authority: &Authority,
        controller: SpaceId,
        control: Handle,
        destination: SpaceId,
        receive: Handle,
    ) -> Result<Self, RejectedMailbox> {
        let prepared = (|| -> Result<(), Error> {
            if !self.managed {
                return Err(Error::NotManaged);
            }
            if self.closed {
                return Err(Error::Closed);
            }
            if self.pending() != 0 {
                return Err(Error::NotReclaimable);
            }
            if self.receiver != controller && self.receiver != destination {
                return Err(Error::WrongOwner);
            }
            self.endpoint(authority, controller, control, Rights::CONTROL)?;
            self.endpoint(
                authority,
                destination,
                receive,
                Rights::RECEIVE | Rights::CONTROL,
            )?;
            authority.require_empty_space(self.escrow)?;
            Ok(())
        })();
        if let Err(error) = prepared {
            return Err(RejectedMailbox {
                mailbox: self,
                error,
            });
        }
        self.receiver = destination;
        self.delivery_policy = DeliveryPolicy::SelectedFileSend;
        Ok(self)
    }
    /// Only Registry-created endpoints carry retirement authority. Public
    /// binding of a sealed boot/event endpoint never acquires that provenance.
    pub(crate) fn new_managed(
        authority: &mut Authority,
        receiver: SpaceId,
        endpoint: Handle,
    ) -> Result<Self, Error> {
        let mut mailbox = Self::new(authority, receiver, endpoint)?;
        mailbox.managed = true;
        Ok(mailbox)
    }
    /// Trusted Registry path; the receipt belongs to this same Authority.
    pub(crate) fn new_reusing(
        authority: &mut Authority,
        receiver: SpaceId,
        endpoint: Handle,
        receipt: RetiredMailbox,
    ) -> Result<Self, RejectedReuse> {
        let prepared = (|| -> Result<_, Error> {
            let identity = authority
                .authorize(
                    receiver,
                    endpoint,
                    Kind::Endpoint,
                    Rights::RECEIVE | Rights::CONTROL,
                )?
                .identity();
            // recycle_space validates every precondition before its commit;
            // Registry already stages the endpoint creation in this same table.
            let escrow = authority.recycle_space(receipt.escrow)?;
            Ok((identity, escrow))
        })();
        match prepared {
            Ok((identity, escrow)) => Ok(Self {
                endpoint: identity,
                receiver,
                escrow,
                messages: [None; MAX_MESSAGES],
                sequence: receipt.sequence,
                now: receipt.now,
                closed: false,
                managed: true,
                delivery_policy: receipt.delivery_policy,
            }),
            Err(error) => Err(RejectedReuse { receipt, error }),
        }
    }
    pub(crate) fn check_settled(&self, authority: &Authority) -> Result<(), Error> {
        if self.pending() != 0 {
            return Err(Error::NotReclaimable);
        }
        authority.require_empty_space(self.escrow)?;
        Ok(())
    }
    /// Exact empty binding validation for the unique trusted transport owner.
    pub(crate) fn check_binding(
        &self,
        authority: &Authority,
        receiver: SpaceId,
        endpoint: Handle,
    ) -> Result<(), Error> {
        if receiver != self.receiver {
            return Err(Error::WrongOwner);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        if self.pending() != 0 {
            return Err(Error::NotReclaimable);
        }
        self.endpoint(
            authority,
            receiver,
            endpoint,
            Rights::RECEIVE | Rights::CONTROL,
        )
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::ClockReversed);
        }
        // Observing time is allowed on rejected operations; queue/authority stay
        // unchanged. Failed requests cannot make the clock run backward.
        self.now = now;
        Ok(())
    }
    fn endpoint(
        &self,
        authority: &Authority,
        owner: SpaceId,
        cap: Handle,
        rights: Rights,
    ) -> Result<(), Error> {
        if authority
            .authorize(owner, cap, Kind::Endpoint, rights)?
            .identity()
            != self.endpoint
        {
            return Err(Error::WrongEndpoint);
        }
        Ok(())
    }
    pub(crate) fn check_sender(
        &self,
        authority: &Authority,
        sender: SpaceId,
        cap: Handle,
    ) -> Result<(), Error> {
        self.endpoint(authority, sender, cap, Rights::SEND)
    }
    /// Read-only cap-free enqueue preflight for an exclusively serialized
    /// transaction. Keep the same Authority/mailbox owner through actual send;
    /// no acceptance, clock advance, ticket, escrow or queue mutation occurs.
    pub fn check_send(
        &self,
        authority: &Authority,
        sender: SpaceId,
        endpoint: Handle,
        payload: &[u8],
        deadline: Deadline,
        now: u64,
    ) -> Result<(), Error> {
        self.prepare_send(authority, sender, endpoint, payload.len(), deadline, now)?;
        if self.delivery_policy == DeliveryPolicy::SelectedFileSend {
            return Err(CapError::Denied.into());
        }
        Ok(())
    }
    /// immutable preflight for an actual selected-capability route.
    pub(crate) fn check_selected_send(
        &self,
        authority: &Authority,
        sender: SpaceId,
        endpoint: Handle,
        payload: &[u8],
        deadline: Deadline,
        now: u64,
    ) -> Result<(), Error> {
        if self.delivery_policy != DeliveryPolicy::SelectedFileSend {
            return Err(CapError::Denied.into());
        }
        self.prepare_send(authority, sender, endpoint, payload.len(), deadline, now)?;
        Ok(())
    }
    fn prepare_send(
        &self,
        authority: &Authority,
        sender: SpaceId,
        endpoint: Handle,
        length: usize,
        deadline: Deadline,
        now: u64,
    ) -> Result<(usize, u64), Error> {
        if now < self.now {
            return Err(Error::ClockReversed);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        self.endpoint(authority, sender, endpoint, Rights::SEND)?;
        if deadline.reached(now) {
            return Err(Error::Expired);
        }
        if length > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let slot = self
            .messages
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        Ok((slot, next))
    }
    pub fn send(
        &mut self,
        authority: &mut Authority,
        sender: SpaceId,
        endpoint: Handle,
        outgoing: Outgoing<'_>,
        now: u64,
    ) -> Result<Ticket, Error> {
        let Outgoing {
            bytes: payload,
            capability: cap,
            deadline,
        } = outgoing;
        self.observe(now)?;
        let (slot, next) =
            self.prepare_send(authority, sender, endpoint, payload.len(), deadline, now)?;
        if self.delivery_policy == DeliveryPolicy::SelectedFileSend {
            let attachment = cap.ok_or(CapError::Denied)?;
            // Escrow retains the ORIGINAL grant until delivery, so ordinary
            // reclaim restores original rights. Delivery alone derives SEND8.
            authority.authorize(
                sender,
                attachment,
                Kind::Endpoint,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )?;
        }
        let mut bytes = [0; MAX_BYTES];
        bytes[..payload.len()].copy_from_slice(payload);
        // All queue validation is complete. Transfer either fails unchanged or
        // commits a unique escrow handle. No fallible work follows that commit.
        let held = match cap {
            Some(h) => Some(authority.transfer(sender, h, self.escrow)?),
            None => None,
        };
        let ticket = Ticket(next);
        self.messages[slot] = Some(Message {
            ticket,
            sender,
            bytes,
            length: payload.len(),
            cap: held,
            deadline,
        });
        self.sequence = next;
        Ok(ticket)
    }
    /// Read-only preflight for an exclusively serialized receive transaction.
    /// An expired front remains owned by this mailbox for ordinary reclamation;
    /// neither escrow nor time is changed by this inspection.
    pub fn peek_ticket(
        &self,
        authority: &Authority,
        receiver: SpaceId,
        endpoint: Handle,
        now: u64,
    ) -> Result<Ticket, Error> {
        if now < self.now {
            return Err(Error::ClockReversed);
        }
        if receiver != self.receiver {
            return Err(Error::WrongOwner);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        self.endpoint(authority, receiver, endpoint, Rights::RECEIVE)?;
        let message = self
            .messages
            .iter()
            .flatten()
            .min_by_key(|m| m.ticket.0)
            .ok_or(Error::Empty)?;
        if message.deadline.reached(now) {
            return Err(Error::Expired);
        }
        Ok(message.ticket)
    }
    pub(crate) fn contains_ticket(&self, ticket: Ticket) -> bool {
        self.messages
            .iter()
            .flatten()
            .any(|message| message.ticket == ticket)
    }
    pub fn receive(
        &mut self,
        authority: &mut Authority,
        receiver: SpaceId,
        endpoint: Handle,
        now: u64,
    ) -> Result<Delivery, Error> {
        self.observe(now)?;
        if receiver != self.receiver {
            return Err(Error::WrongOwner);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        self.endpoint(authority, receiver, endpoint, Rights::RECEIVE)?;
        let slot = self
            .messages
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.map(|m| (i, m.ticket.0)))
            .min_by_key(|(_, id)| *id)
            .map(|(i, _)| i)
            .ok_or(Error::Empty)?;
        let message = self.messages[slot].ok_or(Error::Empty)?;
        if message.deadline.reached(now) {
            return Err(Error::Expired);
        }
        let received = match message.cap {
            Some(h) => Some(
                if self.delivery_policy == DeliveryPolicy::SelectedFileSend {
                    authority.transfer_attenuated(
                        self.escrow,
                        h,
                        receiver,
                        Kind::Endpoint,
                        Rights::SEND,
                    )?
                } else {
                    authority.transfer(self.escrow, h, receiver)?
                },
            ),
            None => None,
        };
        self.messages[slot] = None;
        Ok(Delivery {
            ticket: message.ticket,
            bytes: message.bytes,
            length: message.length,
            capability: received,
        })
    }
    /// Kernel lifecycle notification, not a userspace operation. Pending messages
    /// remain in escrow until their original sender reclaims or authority expires.
    pub fn receiver_died(&mut self, receiver: SpaceId) -> Result<(), Error> {
        if receiver != self.receiver {
            return Err(Error::WrongOwner);
        }
        self.closed = true;
        Ok(())
    }
    /// Transfer an empty endpoint's receive binding during held service setup.
    /// Both old and new receive/control grants must name this exact live object.
    /// No accepted message is moved, discarded or delivered to a different owner.
    pub fn rebind_empty(
        &mut self,
        authority: &Authority,
        owner: SpaceId,
        control: Handle,
        destination: SpaceId,
        receive: Handle,
    ) -> Result<(), Error> {
        if self.delivery_policy == DeliveryPolicy::SelectedFileSend {
            return Err(Error::RestrictedBinding);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        if owner != self.receiver {
            return Err(Error::WrongOwner);
        }
        self.endpoint(authority, owner, control, Rights::RECEIVE | Rights::CONTROL)?;
        self.endpoint(
            authority,
            destination,
            receive,
            Rights::RECEIVE | Rights::CONTROL,
        )?;
        if self.pending() != 0 {
            return Err(Error::NotReclaimable);
        }
        self.receiver = destination;
        Ok(())
    }
    /// Reopen a logical endpoint after its previous receiver has stopped and
    /// the trusted lifecycle owner closed/drained it. Retained endpoint CONTROL
    /// authorizes the new binding; the old revoked domain supplies no authority.
    /// The same escrow and monotonic message sequence survive the handoff, so a
    /// stale Ticket cannot reclaim a replacement receiver's first new message.
    pub fn reopen_empty(
        &mut self,
        authority: &Authority,
        owner: SpaceId,
        control: Handle,
        destination: SpaceId,
        receive: Handle,
    ) -> Result<(), Error> {
        if self.delivery_policy == DeliveryPolicy::SelectedFileSend {
            return Err(Error::RestrictedBinding);
        }
        if !self.closed || self.pending() != 0 {
            return Err(Error::NotReclaimable);
        }
        if !authority.is_live_space(self.escrow) {
            return Err(Error::Closed);
        }
        self.endpoint(authority, owner, control, Rights::CONTROL)?;
        self.endpoint(
            authority,
            destination,
            receive,
            Rights::RECEIVE | Rights::CONTROL,
        )?;
        self.receiver = destination;
        self.closed = false;
        Ok(())
    }
    /// Typed stopped-selected receipt only. Ordinary reopen/rebind deliberately
    /// remain forbidden for this immutable delivery policy.
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn reopen_selected_empty(
        &mut self,
        authority: &Authority,
        controller: SpaceId,
        control: Handle,
        destination: SpaceId,
        receive: Handle,
    ) -> Result<(), Error> {
        if !self.managed || self.delivery_policy != DeliveryPolicy::SelectedFileSend {
            return Err(Error::RestrictedBinding);
        }
        if !self.closed || self.pending() != 0 {
            return Err(Error::NotReclaimable);
        }
        authority.require_empty_space(self.escrow)?;
        self.endpoint(authority, controller, control, Rights::CONTROL)?;
        self.endpoint(
            authority,
            destination,
            receive,
            Rights::RECEIVE | Rights::CONTROL,
        )?;
        self.receiver = destination;
        self.closed = false;
        Ok(())
    }
    /// Trusted lifecycle maintenance. Accepted sends from dead senders remain
    /// deliverable to a live receiver until expiry. Once neither delivery nor
    /// sender reclamation is possible, close escrow and discard the message.
    /// Living senders retain reclamation rights after receiver death/timeout.
    pub fn reap_dead_senders(
        &mut self,
        authority: &mut Authority,
        now: u64,
    ) -> Result<usize, Error> {
        self.observe(now)?;
        let mut discarded = 0;
        for message in &mut self.messages {
            let Some(m) = *message else { continue };
            if !authority.is_live_space(m.sender) && (self.closed || m.deadline.reached(now)) {
                if let Some(cap) = m.cap {
                    authority.close(self.escrow, cap)?;
                }
                *message = None;
                discarded += 1;
            }
        }
        Ok(discarded)
    }
    /// Close private escrow only after receiver closure and complete draining.
    /// This retires handles/domain IDs, not physical descriptor storage.
    pub fn retire_empty(&mut self, authority: &mut Authority) -> Result<(), Error> {
        if !self.closed || self.messages.iter().any(Option::is_some) {
            return Err(Error::NotReclaimable);
        }
        authority.close_space(self.escrow)?;
        Ok(())
    }
    /// Consume a closed, drained Registry-managed mailbox. The lifecycle owner
    /// must first stop all physical/RPC consumers and close every public or
    /// escaped endpoint reference. Retirement never forcibly closes other
    /// owners. Any failure returns the mailbox and leaves Authority unchanged.
    /// This receipt proves only metadata retirement, not hardware quiescence.
    #[allow(clippy::result_large_err)] // Failure must return the unique queue owner.
    pub fn retire_managed(
        self,
        authority: &mut Authority,
    ) -> Result<RetiredMailbox, RejectedMailbox> {
        if !self.managed {
            return Err(RejectedMailbox {
                mailbox: self,
                error: Error::NotManaged,
            });
        }
        if !self.closed || self.pending() != 0 {
            return Err(RejectedMailbox {
                mailbox: self,
                error: Error::NotReclaimable,
            });
        }
        // One complete private metadata transaction. Return only its status:
        // returning Authority inside Result duplicates a large staged owner
        // slot above this frame. No live table changes until every check passes.
        let mut staged = authority.staged_copy();
        let retired = (|| -> Result<(), Error> {
            staged.close_space(self.escrow)?;
            staged.collect_lineage()?;
            staged.retire_unreferenced_object(self.endpoint, Kind::Endpoint)?;
            staged.collect_dead_objects()?;
            Ok(())
        })();
        match retired {
            Ok(()) => {
                *authority = staged;
                Ok(RetiredMailbox {
                    escrow: self.escrow,
                    delivery_policy: self.delivery_policy,
                    sequence: self.sequence,
                    now: self.now,
                })
            }
            Err(error) => Err(RejectedMailbox {
                mailbox: self,
                error,
            }),
        }
    }

    /// Timeout/death rollback: a full sender table leaves the message in escrow
    /// for retry after the sender closes a slot. No authority is duplicated/lost.
    /// Expiry does not imply the receiver never acted on an earlier delivery.
    pub fn reclaim(
        &mut self,
        authority: &mut Authority,
        sender: SpaceId,
        ticket: Ticket,
        now: u64,
    ) -> Result<Reclaimed, Error> {
        self.observe(now)?;
        let slot = self.reclaim_slot(authority, sender, ticket)?;
        let message = self.messages[slot].ok_or(Error::InvalidTicket)?;
        if !self.closed && !message.deadline.reached(now) {
            return Err(Error::NotReclaimable);
        }
        self.finish_reclaim(authority, sender, slot)
    }
    /// Pure bounded preflight for an owned cap-free expiry transaction. Unlike
    /// general capability reclamation, an actually dead sender needs no return
    /// handle slot. A matching original queued sender/Ticket remains mandatory.
    pub fn expired_scalar(
        &self,
        sender: SpaceId,
        ticket: Ticket,
        now: u64,
    ) -> Result<Option<ExpiredScalar>, Error> {
        if now < self.now {
            return Err(Error::ClockReversed);
        }
        let message = self
            .messages
            .iter()
            .flatten()
            .find(|message| message.ticket == ticket)
            .ok_or(Error::InvalidTicket)?;
        if message.sender != sender {
            return Err(Error::WrongOwner);
        }
        if message.length != 8 || message.cap.is_some() {
            return Err(Error::RestrictedBinding);
        }
        if !message.deadline.reached(now) {
            return Ok(None);
        }
        Ok(Some(ExpiredScalar {
            ticket,
            sender,
            deadline: message.deadline,
            bytes: message.bytes[..8].try_into().unwrap(),
        }))
    }
    /// Expire only this actual queued scalar. Capability-bearing escrow stays
    /// with the ordinary reclaim/death owner; it is never discarded here.
    /// Delivered/stale Tickets cannot release any later queue credit.
    pub fn expire_scalar(
        &mut self,
        authority: &mut Authority,
        sender: SpaceId,
        ticket: Ticket,
        now: u64,
    ) -> Result<Option<ExpiredScalar>, Error> {
        let Some(receipt) = self.expired_scalar(sender, ticket, now)? else {
            return Ok(None);
        };
        self.observe(now)?;
        let slot = self
            .messages
            .iter()
            .position(|message| message.is_some_and(|message| message.ticket == ticket))
            .unwrap();
        // Shape/sender/Ticket were checked without mutation. The sole &mut
        // owner excludes interleaving; this branch cannot transfer a grant.
        let reclaimed = self.finish_reclaim(authority, sender, slot)?;
        debug_assert_eq!(reclaimed, Reclaimed::NoCapability);
        Ok(Some(receipt))
    }
    /// Only a trusted protected-call transport may withdraw its exact queued
    /// request after independently observing actual Rpc cancellation/death.
    /// A delivered request has no message/Ticket and cannot be refunded here.
    pub(crate) fn withdraw_undelivered(
        &mut self,
        authority: &mut Authority,
        sender: SpaceId,
        ticket: Ticket,
        now: u64,
    ) -> Result<Reclaimed, Error> {
        self.observe(now)?;
        let slot = self.reclaim_slot(authority, sender, ticket)?;
        self.finish_reclaim(authority, sender, slot)
    }
    /// Pure preflight for Rpc's strict scalar completion transaction. Preserve
    /// attachments for their capability-bearing owner; never reinterpret them.
    pub(crate) fn check_scalar_request(
        &self,
        authority: &Authority,
        sender: SpaceId,
        endpoint: usize,
        ticket: Ticket,
    ) -> Result<(), Error> {
        if self.endpoint != endpoint {
            return Err(Error::WrongEndpoint);
        }
        let slot = self.reclaim_slot(authority, sender, ticket)?;
        let message = self.messages[slot].unwrap();
        if message.length != 8 || message.cap.is_some() {
            return Err(Error::RestrictedBinding);
        }
        Ok(())
    }
    fn reclaim_slot(
        &self,
        authority: &Authority,
        sender: SpaceId,
        ticket: Ticket,
    ) -> Result<usize, Error> {
        if !authority.is_live_space(sender) {
            return Err(CapError::InvalidSpace.into());
        }
        let slot = self
            .messages
            .iter()
            .position(|m| m.is_some_and(|m| m.ticket == ticket))
            .ok_or(Error::InvalidTicket)?;
        if self.messages[slot].ok_or(Error::InvalidTicket)?.sender != sender {
            return Err(Error::WrongOwner);
        }
        Ok(slot)
    }
    fn finish_reclaim(
        &mut self,
        authority: &mut Authority,
        sender: SpaceId,
        slot: usize,
    ) -> Result<Reclaimed, Error> {
        let message = self.messages[slot].ok_or(Error::InvalidTicket)?;
        let result = match message.cap {
            None => Reclaimed::NoCapability,
            Some(cap) => match authority.transfer(self.escrow, cap, sender) {
                Ok(cap) => Reclaimed::Capability(cap),
                Err(CapError::Revoked | CapError::DeadObject) => {
                    authority.close(self.escrow, cap)?;
                    Reclaimed::Invalidated
                }
                Err(error) => return Err(error.into()),
            },
        };
        self.messages[slot] = None;
        Ok(result)
    }
    pub fn pending(&self) -> usize {
        self.messages.iter().flatten().count()
    }
    /// Reports lifecycle closure only, not hardware/process quiescence.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_expiry_reclaims_only_the_exact_undelivered_credit_and_reports_its_payload() {
        let mut f = restart_fixture();
        let ticket = f
            .mailbox
            .send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"expire01",
                    capability: None,
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        assert_eq!(
            f.mailbox
                .expire_scalar(&mut f.authority, f.sender, ticket, 4),
            Ok(None)
        );
        assert_eq!(f.mailbox.pending(), 1);
        let receipt = f
            .mailbox
            .expire_scalar(&mut f.authority, f.sender, ticket, 5)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                receipt.ticket,
                receipt.sender,
                receipt.deadline,
                receipt.bytes
            ),
            (ticket, f.sender, deadline(5), *b"expire01")
        );
        assert_eq!(f.mailbox.pending(), 0);
        let next = f
            .mailbox
            .send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"later001",
                    capability: None,
                    deadline: deadline(10),
                },
                5,
            )
            .unwrap();
        assert_ne!(ticket, next);
        assert_eq!(
            f.mailbox
                .expire_scalar(&mut f.authority, f.sender, ticket, 5),
            Err(Error::InvalidTicket)
        );
        assert_eq!(
            f.mailbox.expire_scalar(&mut f.authority, f.sender, next, 4),
            Err(Error::ClockReversed)
        );
        assert_eq!(f.mailbox.pending(), 1);
        assert_eq!(
            f.mailbox
                .receive(&mut f.authority, f.receiver, f.receive, 5)
                .unwrap()
                .ticket,
            next
        );
        assert_eq!(
            f.mailbox
                .expire_scalar(&mut f.authority, f.sender, next, 10),
            Err(Error::InvalidTicket)
        );
    }

    #[test]
    fn scalar_expiry_never_steals_capability_escrow_or_masks_sender_capacity_pressure() {
        let mut f = restart_fixture();
        let cap = f
            .authority
            .create_root(f.sender, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = f
            .mailbox
            .send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"withcap1",
                    capability: Some(cap),
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        assert_eq!(
            f.mailbox
                .expire_scalar(&mut f.authority, f.sender, ticket, 5),
            Err(Error::RestrictedBinding)
        );
        let mut filled = None;
        for _ in 1..crate::capability::MAX_CAPS {
            filled = Some(
                f.authority
                    .derive(f.owner, f.control, f.sender, Rights::SEND)
                    .unwrap(),
            );
        }
        assert_eq!(
            f.mailbox.reclaim(&mut f.authority, f.sender, ticket, 5),
            Err(Error::Authority(CapError::Capacity))
        );
        assert_eq!(f.mailbox.pending(), 1);
        f.authority.close(f.sender, filled.unwrap()).unwrap();
        let Reclaimed::Capability(back) = f
            .mailbox
            .reclaim(&mut f.authority, f.sender, ticket, 5)
            .unwrap()
        else {
            panic!("actual escrowed capability must be returned")
        };
        assert_ne!(back, cap);
        assert!(
            f.authority
                .authorize(f.sender, back, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert!(
            f.authority
                .authorize(f.sender, cap, Kind::Memory, Rights::READ)
                .is_err()
        );
        assert_eq!(f.mailbox.pending(), 0);
    }

    #[test]
    fn scalar_expiry_retains_dead_sender_bytes_until_expiry_and_rejects_new_generation() {
        let mut f = restart_fixture();
        let ticket = f
            .mailbox
            .send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"dead0001",
                    capability: None,
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        f.authority.close_space(f.sender).unwrap();
        let replacement = f.authority.recycle_space(f.sender).unwrap();
        assert_ne!(replacement, f.sender);
        assert_eq!(
            f.mailbox
                .expire_scalar(&mut f.authority, replacement, ticket, 5),
            Err(Error::WrongOwner)
        );
        assert_eq!(
            f.mailbox
                .expire_scalar(&mut f.authority, f.sender, ticket, 4),
            Ok(None)
        );
        assert_eq!(f.mailbox.pending(), 1);
        assert!(
            f.mailbox
                .expire_scalar(&mut f.authority, f.sender, ticket, 5)
                .unwrap()
                .is_some()
        );
        assert_eq!(f.mailbox.pending(), 0);
    }
    struct RestartFixture {
        authority: Authority,
        mailbox: Mailbox,
        owner: SpaceId,
        sender: SpaceId,
        receiver: SpaceId,
        control: Handle,
        send: Handle,
        receive: Handle,
    }
    fn restart_fixture() -> RestartFixture {
        let mut authority = Authority::new();
        let owner = authority.create_space().unwrap();
        let sender = authority.create_space().unwrap();
        let receiver = authority.create_space().unwrap();
        let control = authority
            .create_root(
                owner,
                Kind::Endpoint,
                Rights::SEND
                    | Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::TRANSFER
                    | Rights::REVOKE,
            )
            .unwrap();
        let send = authority
            .derive(owner, control, sender, Rights::SEND)
            .unwrap();
        let receive = authority
            .derive(owner, control, receiver, Rights::RECEIVE | Rights::CONTROL)
            .unwrap();
        let mailbox = Mailbox::new(&mut authority, receiver, receive).unwrap();
        RestartFixture {
            authority,
            mailbox,
            owner,
            sender,
            receiver,
            control,
            send,
            receive,
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MessageSnapshot {
        ticket: Ticket,
        sender: SpaceId,
        bytes: [u8; MAX_BYTES],
        length: usize,
        capability: Option<Handle>,
        deadline: Deadline,
    }
    #[derive(Debug, PartialEq, Eq)]
    struct MailboxSnapshot {
        delivery_policy: DeliveryPolicy,
        endpoint: usize,
        receiver: SpaceId,
        escrow: SpaceId,
        messages: [Option<MessageSnapshot>; MAX_MESSAGES],
        sequence: u64,
        now: u64,
        closed: bool,
        managed: bool,
    }
    fn snapshot(mailbox: &Mailbox) -> MailboxSnapshot {
        MailboxSnapshot {
            delivery_policy: mailbox.delivery_policy,
            endpoint: mailbox.endpoint,
            receiver: mailbox.receiver,
            escrow: mailbox.escrow,
            messages: mailbox.messages.map(|message| {
                message.map(|message| MessageSnapshot {
                    ticket: message.ticket,
                    sender: message.sender,
                    bytes: message.bytes,
                    length: message.length,
                    capability: message.cap,
                    deadline: message.deadline,
                })
            }),
            sequence: mailbox.sequence,
            now: mailbox.now,
            closed: mailbox.closed,
            managed: mailbox.managed,
        }
    }
    fn managed_mailbox() -> (Authority, SpaceId, Handle, Mailbox) {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let job = a
            .create_root(owner, Kind::Job, Rights::from_bits(481).unwrap())
            .unwrap();
        let endpoint = a
            .create_managed(owner, job, Kind::Endpoint, Rights::from_bits(504).unwrap())
            .unwrap();
        let mailbox = Mailbox::new_managed(&mut a, owner, endpoint).unwrap();
        (a, owner, endpoint, mailbox)
    }
    #[test]
    fn managed_selected_configuration_preserves_sequence_and_returns_every_failed_owner() {
        let (mut a, owner, endpoint, mut mailbox) = managed_mailbox();
        let destination = a.create_space().unwrap();
        let receive = a
            .derive(
                owner,
                endpoint,
                destination,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let ticket = mailbox
            .send(
                &mut a,
                owner,
                endpoint,
                Outgoing {
                    bytes: b"old",
                    capability: None,
                    deadline: Deadline::after(0, 20).unwrap(),
                },
                1,
            )
            .unwrap();
        let before = snapshot(&mailbox);
        let usage = a.metadata_usage();
        let rejected = mailbox
            .into_selected_file(&a, owner, endpoint, destination, receive)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::NotReclaimable);
        assert_eq!(snapshot(&rejected.mailbox), before);
        assert_eq!(a.metadata_usage(), usage);
        mailbox = rejected.mailbox;
        assert_eq!(
            mailbox.receive(&mut a, owner, endpoint, 2).unwrap().ticket,
            ticket
        );
        // Deliberate test-only orphan in otherwise-private escrow. Empty queue
        // alone must not strand an untracked physical authority claim.
        let memory = a
            .create_root(
                owner,
                Kind::Memory,
                Rights::READ | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let orphan = a
            .derive(owner, memory, mailbox.escrow, Rights::READ)
            .unwrap();
        let before = snapshot(&mailbox);
        let usage = a.metadata_usage();
        let rejected = mailbox
            .into_selected_file(&a, owner, endpoint, destination, receive)
            .err()
            .unwrap();
        assert_eq!(
            rejected.error,
            Error::Authority(CapError::DestinationNotEmpty)
        );
        assert_eq!(snapshot(&rejected.mailbox), before);
        assert_eq!(a.metadata_usage(), usage);
        mailbox = rejected.mailbox;
        a.close(mailbox.escrow, orphan).unwrap();
        let mailbox = mailbox
            .into_selected_file(&a, owner, endpoint, destination, receive)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        assert_eq!((mailbox.sequence, mailbox.now), (ticket.0, 2));
        assert_eq!(mailbox.receiver, destination);
        assert_eq!(mailbox.delivery_policy, DeliveryPolicy::SelectedFileSend);
        assert!(mailbox.managed);
    }
    #[test]
    fn selected_managed_receipt_never_reopens_as_an_ordinary_mailbox() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let job = a
            .create_root(owner, Kind::Job, Rights::from_bits(481).unwrap())
            .unwrap();
        let endpoint = a
            .create_managed(owner, job, Kind::Endpoint, Rights::from_bits(504).unwrap())
            .unwrap();
        let mailbox = Mailbox::new_managed(&mut a, owner, endpoint).unwrap();
        let destination = a.create_space().unwrap();
        let receive = a
            .derive(
                owner,
                endpoint,
                destination,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let mut mailbox = mailbox
            .into_selected_file(&a, owner, endpoint, destination, receive)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        // Metadata policy model only; scheduler/hardware death is enforced by
        // the SelectedReadRoute owner wrapper, not inferred from these IDs.
        mailbox.receiver_died(destination).unwrap();
        a.close_space(destination).unwrap();
        a.close(owner, endpoint).unwrap();
        let receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        assert_eq!(receipt.delivery_policy, DeliveryPolicy::SelectedFileSend);
        let endpoint = a
            .create_managed(owner, job, Kind::Endpoint, Rights::from_bits(504).unwrap())
            .unwrap();
        let mut mailbox = Mailbox::new_reusing(&mut a, owner, endpoint, receipt)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        assert_eq!(mailbox.delivery_policy, DeliveryPolicy::SelectedFileSend);
        let destination = a.recycle_space(destination).unwrap();
        let receive = a
            .derive(
                owner,
                endpoint,
                destination,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        assert_eq!(
            mailbox.rebind_empty(&a, owner, endpoint, destination, receive),
            Err(Error::RestrictedBinding)
        );
        let mailbox = mailbox
            .into_selected_file(&a, owner, endpoint, destination, receive)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        assert_eq!(mailbox.delivery_policy, DeliveryPolicy::SelectedFileSend);
    }
    fn retire_rejected(a: &mut Authority, mailbox: Mailbox, expected: Error) -> Mailbox {
        let before = snapshot(&mailbox);
        let authority_before = a.staged_copy();
        let usage = a.metadata_usage();
        let escrow = mailbox.escrow;
        let live = a.is_live_space(escrow);
        let mut staged = a.staged_copy();
        let collection = (
            staged.collect_lineage().unwrap(),
            staged.collect_dead_objects().unwrap(),
        );
        let rejected = mailbox.retire_managed(a).err().unwrap();
        assert_eq!(rejected.error, expected);
        assert_eq!(snapshot(&rejected.mailbox), before);
        crate::capability::tests::unchanged(a, &authority_before);
        assert_eq!(a.metadata_usage(), usage);
        assert_eq!(a.is_live_space(escrow), live);
        let mut staged = a.staged_copy();
        assert_eq!(
            (
                staged.collect_lineage().unwrap(),
                staged.collect_dead_objects().unwrap()
            ),
            collection
        );
        rejected.mailbox
    }
    #[test]
    fn managed_retirement_requires_closed_drained_mailbox_and_no_escaped_endpoint_nodes() {
        let (mut a, owner, endpoint, mailbox) = managed_mailbox();
        let mut mailbox = retire_rejected(&mut a, mailbox, Error::NotReclaimable);
        let foreign = a.create_space().unwrap();
        let escaped = a.derive(owner, endpoint, foreign, Rights::SEND).unwrap();
        let payload = a
            .create_root(owner, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = mailbox
            .send(
                &mut a,
                owner,
                endpoint,
                Outgoing {
                    bytes: b"accepted",
                    capability: Some(payload),
                    deadline: deadline(100),
                },
                7,
            )
            .unwrap();
        mailbox.receiver_died(owner).unwrap();
        let mut mailbox = retire_rejected(&mut a, mailbox, Error::NotReclaimable);
        let reclaimed = mailbox.reclaim(&mut a, owner, ticket, 7).unwrap();
        let Reclaimed::Capability(returned) = reclaimed else {
            panic!("live sender retains accepted escrow")
        };
        a.close(owner, endpoint).unwrap();
        let mailbox = retire_rejected(&mut a, mailbox, Error::Authority(CapError::ObjectBusy));
        assert!(
            a.authorize(foreign, escaped, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(a.revoke(foreign, escaped), Err(CapError::Denied));
        a.close(foreign, escaped).unwrap();
        let old_escrow = mailbox.escrow;
        let receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(receipt.escrow, old_escrow);
        assert_eq!((receipt.sequence, receipt.now), (ticket.0, 7));
        assert!(!a.is_live_space(old_escrow));
        assert!(
            a.authorize(owner, returned, Kind::Memory, Rights::READ)
                .is_ok()
        );
    }
    #[test]
    fn sealed_mailboxes_remain_external_even_after_the_last_endpoint_reference_is_closed() {
        let mut f = restart_fixture();
        f.mailbox.receiver_died(f.receiver).unwrap();
        f.authority.close(f.owner, f.control).unwrap();
        f.authority.close(f.sender, f.send).unwrap();
        f.authority.close(f.receiver, f.receive).unwrap();
        f.authority.collect_lineage().unwrap();
        let endpoint = f.mailbox.endpoint;
        let mut mailbox = retire_rejected(&mut f.authority, f.mailbox, Error::NotManaged);
        // Legacy close-escrow maintenance still works, but grants no authority
        // to destroy a permanent boot/event endpoint descriptor.
        mailbox.retire_empty(&mut f.authority).unwrap();
        assert_eq!(
            f.authority
                .retire_unreferenced_object(endpoint, Kind::Memory),
            Err(CapError::WrongKind)
        );
        assert_eq!(f.authority.collect_dead_objects(), Ok(0));
    }
    #[test]
    fn managed_retirement_rejects_revoked_but_still_installed_foreign_endpoint_handle() {
        let (mut a, owner, endpoint, mut mailbox) = managed_mailbox();
        let foreign = a.create_space().unwrap();
        let escaped = a.derive(owner, endpoint, foreign, Rights::SEND).unwrap();
        mailbox.receiver_died(owner).unwrap();
        a.revoke(owner, endpoint).unwrap();
        a.close(owner, endpoint).unwrap();
        let mailbox = retire_rejected(&mut a, mailbox, Error::Authority(CapError::ObjectBusy));
        assert_eq!(
            a.authorize(foreign, escaped, Kind::Endpoint, Rights::SEND)
                .err(),
            Some(CapError::Revoked)
        );
        a.close(foreign, escaped).unwrap();
        let _receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
    }
    #[test]
    fn failed_receipt_reuse_retains_owner_and_cannot_recycle_a_foreign_or_live_escrow() {
        let (mut a, owner, endpoint, mut mailbox) = managed_mailbox();
        mailbox.receiver_died(owner).unwrap();
        a.close(owner, endpoint).unwrap();
        let receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let job = a
            .create_root(owner, Kind::Job, Rights::from_bits(481).unwrap())
            .unwrap();
        let fresh = a
            .create_managed(owner, job, Kind::Endpoint, Rights::from_bits(504).unwrap())
            .unwrap();
        let usage = a.metadata_usage();
        let rejected = Mailbox::new_reusing(&mut a, owner, job, receipt)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::Authority(CapError::WrongKind));
        assert_eq!(a.metadata_usage(), usage);
        let old = rejected.receipt.escrow;
        let recycled = a.recycle_space(old).unwrap();
        let usage = a.metadata_usage();
        let rejected = Mailbox::new_reusing(&mut a, owner, fresh, rejected.receipt)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::Authority(CapError::InvalidSpace));
        assert_eq!(rejected.receipt.escrow, old);
        assert_eq!(a.metadata_usage(), usage);
        assert!(a.is_live_space(recycled));
    }
    #[test]
    fn managed_replacement_preserves_exhausted_sequence_instead_of_resetting_it() {
        let (mut a, owner, endpoint, mut mailbox) = managed_mailbox();
        mailbox.sequence = u64::MAX;
        mailbox.now = 17;
        mailbox.receiver_died(owner).unwrap();
        a.close(owner, endpoint).unwrap();
        let receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let creator = a
            .create_root(owner, Kind::Job, Rights::from_bits(481).unwrap())
            .unwrap();
        let fresh = a
            .create_managed(
                owner,
                creator,
                Kind::Endpoint,
                Rights::from_bits(504).unwrap(),
            )
            .unwrap();
        let mut mailbox = Mailbox::new_reusing(&mut a, owner, fresh, receipt)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let before = snapshot(&mailbox);
        assert_eq!(
            mailbox.send(
                &mut a,
                owner,
                fresh,
                Outgoing {
                    bytes: b"must not wrap",
                    capability: None,
                    deadline: deadline(100),
                },
                17
            ),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(snapshot(&mailbox), before);
    }
    #[test]
    fn restart_reopen_requires_old_request_and_capability_escrow_to_be_drained() {
        let mut f = restart_fixture();
        let endpoint = f.mailbox.endpoint;
        let escrow = f.mailbox.escrow;
        let payload = f
            .authority
            .create_root(f.sender, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let first = f
            .mailbox
            .send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"old request",
                    capability: Some(payload),
                    deadline: deadline(100),
                },
                0,
            )
            .unwrap();
        assert_eq!(first, Ticket(1));
        assert!(
            f.authority
                .authorize(f.sender, payload, Kind::Memory, Rights::READ)
                .is_err()
        );
        f.mailbox.receiver_died(f.receiver).unwrap();
        assert!(f.mailbox.is_closed());
        f.authority.close_space(f.receiver).unwrap();
        let next = f.authority.recycle_space(f.receiver).unwrap();
        let receive = f
            .authority
            .derive(f.owner, f.control, next, Rights::RECEIVE | Rights::CONTROL)
            .unwrap();
        assert_ne!(f.receiver, next);
        assert_ne!(f.receive, receive);
        let before = snapshot(&f.mailbox);
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.owner, f.control, next, receive),
            Err(Error::NotReclaimable)
        );
        assert_eq!(snapshot(&f.mailbox), before);
        let Reclaimed::Capability(returned) = f
            .mailbox
            .reclaim(&mut f.authority, f.sender, first, 0)
            .unwrap()
        else {
            panic!("accepted capability must return to its live sender");
        };
        assert!(
            f.authority
                .authorize(f.sender, returned, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert_eq!(f.mailbox.pending(), 0);
        f.mailbox
            .reopen_empty(&f.authority, f.owner, f.control, next, receive)
            .unwrap();
        assert!(!f.mailbox.is_closed());
        assert_eq!(
            (f.mailbox.endpoint, f.mailbox.escrow, f.mailbox.sequence),
            (endpoint, escrow, 1)
        );
        assert_eq!(
            f.mailbox
                .receive(&mut f.authority, f.receiver, f.receive, 0),
            Err(Error::WrongOwner)
        );
        assert_eq!(
            f.mailbox.receive(&mut f.authority, next, f.receive, 0),
            Err(Error::Authority(CapError::InvalidHandle))
        );
        let second = f
            .mailbox
            .send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"replacement request",
                    capability: Some(returned),
                    deadline: deadline(100),
                },
                1,
            )
            .unwrap();
        assert_eq!(second, Ticket(2));
        assert_eq!(
            f.mailbox.reclaim(&mut f.authority, f.sender, first, 1),
            Err(Error::InvalidTicket)
        );
        assert_eq!(f.mailbox.pending(), 1);
        let delivery = f
            .mailbox
            .receive(&mut f.authority, next, receive, 1)
            .unwrap();
        assert_eq!(&delivery.bytes[..delivery.length], b"replacement request");
        let delivered = delivery.capability.unwrap();
        assert!(
            f.authority
                .authorize(next, delivered, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert!(
            f.authority
                .authorize(f.sender, returned, Kind::Memory, Rights::READ)
                .is_err()
        );
        assert_eq!(
            f.authority
                .authorize(f.receiver, delivered, Kind::Memory, Rights::READ)
                .err(),
            Some(CapError::InvalidSpace)
        );
        assert_eq!(
            f.mailbox.reclaim(&mut f.authority, f.sender, second, 1),
            Err(Error::InvalidTicket)
        );
        assert_eq!(f.mailbox.pending(), 0);
    }
    #[test]
    fn restart_reopen_rejects_wrong_roles_objects_and_dead_old_owner_atomically() {
        let mut f = restart_fixture();
        let target = f.authority.create_space().unwrap();
        let receive = f
            .authority
            .derive(
                f.owner,
                f.control,
                target,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let weak_owner = f
            .authority
            .derive(f.owner, f.control, f.owner, Rights::RECEIVE)
            .unwrap();
        let receive_only = f
            .authority
            .derive(f.owner, f.control, target, Rights::RECEIVE)
            .unwrap();
        let control_only = f
            .authority
            .derive(f.owner, f.control, target, Rights::CONTROL)
            .unwrap();
        let wrong = f
            .authority
            .create_root(
                f.owner,
                Kind::Endpoint,
                Rights::RECEIVE | Rights::CONTROL | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let wrong_receive = f
            .authority
            .derive(f.owner, wrong, target, Rights::RECEIVE | Rights::CONTROL)
            .unwrap();
        let memory = f
            .authority
            .create_root(f.owner, Kind::Memory, Rights::CONTROL)
            .unwrap();
        let before = snapshot(&f.mailbox);
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.owner, f.control, target, receive),
            Err(Error::NotReclaimable)
        );
        assert_eq!(snapshot(&f.mailbox), before);
        f.mailbox.receiver_died(f.receiver).unwrap();
        for (owner, control, destination, target_cap, expected) in [
            (
                f.owner,
                weak_owner,
                target,
                receive,
                Error::Authority(CapError::Denied),
            ),
            (
                f.sender,
                f.control,
                target,
                receive,
                Error::Authority(CapError::Denied),
            ),
            (f.owner, wrong, target, receive, Error::WrongEndpoint),
            (
                f.owner,
                memory,
                target,
                receive,
                Error::Authority(CapError::WrongKind),
            ),
            (
                f.owner,
                f.control,
                target,
                receive_only,
                Error::Authority(CapError::Denied),
            ),
            (
                f.owner,
                f.control,
                target,
                control_only,
                Error::Authority(CapError::Denied),
            ),
            (
                f.owner,
                f.control,
                target,
                wrong_receive,
                Error::WrongEndpoint,
            ),
            (
                f.owner,
                Handle(u64::MAX),
                target,
                receive,
                Error::Authority(CapError::InvalidHandle),
            ),
            (
                f.owner,
                f.control,
                target,
                Handle(u64::MAX),
                Error::Authority(CapError::InvalidHandle),
            ),
        ] {
            let before = snapshot(&f.mailbox);
            assert_eq!(
                f.mailbox
                    .reopen_empty(&f.authority, owner, control, destination, target_cap),
                Err(expected)
            );
            assert_eq!(snapshot(&f.mailbox), before);
        }
        f.authority.close_space(f.receiver).unwrap();
        let before = snapshot(&f.mailbox);
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.receiver, f.receive, target, receive),
            Err(Error::Authority(CapError::InvalidSpace))
        );
        assert_eq!(snapshot(&f.mailbox), before);
        f.mailbox
            .reopen_empty(&f.authority, f.owner, f.control, target, receive)
            .unwrap();
        assert_eq!(f.mailbox.receiver, target);
        assert!(!f.mailbox.is_closed());
    }
    #[test]
    fn restart_reopen_cannot_reuse_retired_or_recycled_private_escrow() {
        let mut f = restart_fixture();
        let target = f.authority.create_space().unwrap();
        let receive = f
            .authority
            .derive(
                f.owner,
                f.control,
                target,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        f.mailbox.receiver_died(f.receiver).unwrap();
        let escrow = f.mailbox.escrow;
        f.mailbox.retire_empty(&mut f.authority).unwrap();
        let before = snapshot(&f.mailbox);
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.owner, f.control, target, receive),
            Err(Error::Closed)
        );
        assert_eq!(snapshot(&f.mailbox), before);
        let recycled = f.authority.recycle_space(escrow).unwrap();
        assert_ne!(escrow, recycled);
        assert!(f.authority.is_live_space(recycled));
        assert!(!f.authority.is_live_space(escrow));
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.owner, f.control, target, receive),
            Err(Error::Closed)
        );
        assert_eq!(snapshot(&f.mailbox), before);
    }
    #[test]
    fn restart_reopen_requires_the_same_tagged_endpoint_even_after_slot_reuse() {
        let mut f = restart_fixture();
        let target = f.authority.create_space().unwrap();
        let old_identity = f.mailbox.endpoint;
        f.mailbox.receiver_died(f.receiver).unwrap();
        f.authority.destroy(f.owner, f.control).unwrap();
        f.authority.close(f.owner, f.control).unwrap();
        f.authority.close(f.sender, f.send).unwrap();
        f.authority.close(f.receiver, f.receive).unwrap();
        assert_eq!(f.authority.collect_lineage(), Ok(3));
        assert_eq!(f.authority.collect_dead_objects(), Ok(1));
        let replacement = f
            .authority
            .create_root(
                f.owner,
                Kind::Endpoint,
                Rights::RECEIVE | Rights::CONTROL | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let receive = f
            .authority
            .derive(
                f.owner,
                replacement,
                target,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let identity = f
            .authority
            .authorize(f.owner, replacement, Kind::Endpoint, Rights::CONTROL)
            .unwrap()
            .identity();
        assert_eq!(old_identity & 255, identity & 255);
        assert_ne!(old_identity, identity);
        let before = snapshot(&f.mailbox);
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.owner, replacement, target, receive),
            Err(Error::WrongEndpoint)
        );
        assert_eq!(snapshot(&f.mailbox), before);
    }
    #[test]
    fn repeated_restart_reopen_preserves_one_endpoint_sender_escrow_and_ticket_sequence() {
        let mut f = restart_fixture();
        let endpoint = f.mailbox.endpoint;
        let escrow = f.mailbox.escrow;
        let sender = f.sender;
        let mut receiver = f.receiver;
        let mut receive = f.receive;
        let mut payload = f
            .authority
            .create_root(sender, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let mut previous = None;
        for serial in 1u64..=512 {
            let bytes = serial.to_le_bytes();
            let ticket = f
                .mailbox
                .send(
                    &mut f.authority,
                    sender,
                    f.send,
                    Outgoing {
                        bytes: &bytes,
                        capability: Some(payload),
                        deadline: Deadline::after(serial, 10).unwrap(),
                    },
                    serial,
                )
                .unwrap();
            assert_eq!(ticket, Ticket(serial));
            f.mailbox.receiver_died(receiver).unwrap();
            if let Some(old) = previous {
                assert_eq!(
                    f.mailbox.reclaim(&mut f.authority, sender, old, serial),
                    Err(Error::InvalidTicket)
                );
                assert_eq!(f.mailbox.pending(), 1);
            }
            let Reclaimed::Capability(returned) = f
                .mailbox
                .reclaim(&mut f.authority, sender, ticket, serial)
                .unwrap()
            else {
                panic!("restart must return the unique escrow grant");
            };
            assert!(
                f.authority
                    .authorize(sender, payload, Kind::Memory, Rights::READ)
                    .is_err()
            );
            assert!(
                f.authority
                    .authorize(sender, returned, Kind::Memory, Rights::READ)
                    .is_ok()
            );
            payload = returned;
            f.authority.close_space(receiver).unwrap();
            let next = f.authority.recycle_space(receiver).unwrap();
            assert_eq!(f.authority.collect_lineage(), Ok(1));
            let target = f
                .authority
                .derive(f.owner, f.control, next, Rights::RECEIVE | Rights::CONTROL)
                .unwrap();
            assert_ne!(receiver, next);
            assert_ne!(receive, target);
            f.mailbox
                .reopen_empty(&f.authority, f.owner, f.control, next, target)
                .unwrap();
            assert_eq!(
                (f.mailbox.endpoint, f.mailbox.escrow, f.mailbox.sequence),
                (endpoint, escrow, serial)
            );
            assert!(!f.mailbox.is_closed());
            assert_eq!(f.mailbox.pending(), 0);
            assert_eq!(
                f.mailbox
                    .receive(&mut f.authority, receiver, receive, serial),
                Err(Error::WrongOwner)
            );
            assert_eq!(
                f.mailbox.receive(&mut f.authority, next, receive, serial),
                Err(Error::Authority(CapError::InvalidHandle))
            );
            assert_eq!(
                f.mailbox.receive(&mut f.authority, next, target, serial),
                Err(Error::Empty)
            );
            receiver = next;
            receive = target;
            previous = Some(ticket);
        }
        assert_eq!(f.mailbox.sequence, 512);
        assert!(
            f.authority
                .authorize(f.owner, f.control, Kind::Endpoint, Rights::CONTROL)
                .is_ok()
        );
        assert!(
            f.authority
                .authorize(sender, f.send, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert!(f.authority.is_live_space(escrow));
    }
    #[test]
    fn receive_binding_moves_only_when_empty_with_both_exact_control_grants() {
        let (mut a, mut queue, sender, receiver, send, receive) = setup();
        let next = a.create_space().unwrap();
        let weak = a.derive(receiver, receive, next, Rights::RECEIVE).unwrap();
        assert!(
            queue
                .rebind_empty(&a, receiver, receive, next, weak)
                .is_err()
        );
        let target = a
            .derive(receiver, receive, next, Rights::RECEIVE | Rights::CONTROL)
            .unwrap();
        queue
            .send(
                &mut a,
                sender,
                send,
                Outgoing {
                    bytes: b"owned",
                    capability: None,
                    deadline: Deadline::after(0, 10).unwrap(),
                },
                0,
            )
            .unwrap();
        assert_eq!(
            queue.rebind_empty(&a, receiver, receive, next, target),
            Err(Error::NotReclaimable)
        );
        assert_eq!(
            queue.receive(&mut a, receiver, receive, 0).unwrap().length,
            5
        );
        queue
            .rebind_empty(&a, receiver, receive, next, target)
            .unwrap();
        assert_eq!(
            queue.receive(&mut a, receiver, receive, 0),
            Err(Error::WrongOwner)
        );
        queue
            .send(
                &mut a,
                sender,
                send,
                Outgoing {
                    bytes: b"new",
                    capability: None,
                    deadline: Deadline::after(0, 10).unwrap(),
                },
                0,
            )
            .unwrap();
        assert_eq!(queue.receive(&mut a, next, target, 0).unwrap().length, 3);
        queue.receiver_died(next).unwrap();
        assert_eq!(
            queue.rebind_empty(&a, next, target, receiver, receive),
            Err(Error::Closed)
        );
        queue.retire_empty(&mut a).unwrap();
    }
    fn setup() -> (Authority, Mailbox, SpaceId, SpaceId, Handle, Handle) {
        let mut a = Authority::new();
        let s = a.create_space().unwrap();
        let r = a.create_space().unwrap();
        let receive = a
            .create_root(
                r,
                Kind::Endpoint,
                Rights::SEND
                    | Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::TRANSFER,
            )
            .unwrap();
        let send = a.derive(r, receive, s, Rights::SEND).unwrap();
        let m = Mailbox::new(&mut a, r, receive).unwrap();
        (a, m, s, r, send, receive)
    }
    fn deadline(t: u64) -> Deadline {
        Deadline::after(0, t).unwrap()
    }
    #[test]
    fn capfree_send_preflight_reserves_nothing_and_matches_actual_commit() {
        let (mut a, mut queue, sender, receiver, send, receive) = setup();
        let before = snapshot(&queue);
        let authority_before = a.metadata_usage();
        for _ in 0..8 {
            assert_eq!(
                queue.check_send(&a, sender, send, b"request1", deadline(10), 2),
                Ok(())
            );
            assert_eq!(snapshot(&queue), before);
            assert_eq!(a.metadata_usage(), authority_before);
        }
        let ticket = queue
            .send(
                &mut a,
                sender,
                send,
                Outgoing {
                    bytes: b"request1",
                    capability: None,
                    deadline: deadline(10),
                },
                2,
            )
            .unwrap();
        assert_eq!(ticket, Ticket(1));
        let delivery = queue.receive(&mut a, receiver, receive, 3).unwrap();
        assert_eq!(delivery.ticket, ticket);
        assert_eq!(&delivery.bytes[..delivery.length], b"request1");
        assert_eq!(delivery.capability, None);
    }
    #[test]
    fn capfree_send_preflight_rejects_every_late_queue_failure_without_clock_advance() {
        for case in 0..8 {
            let (mut a, mut queue, sender, _, send, _) = setup();
            queue.now = 2;
            let mut payload = b"request1".as_slice();
            let too_large = [0; MAX_BYTES + 1];
            let mut when = 2;
            let mut expires = deadline(10);
            match case {
                0 => queue.closed = true,
                1 => when = 1,
                2 => expires = deadline(2),
                3 => payload = &too_large,
                4 => queue.sequence = u64::MAX,
                5 => {
                    a.close(sender, send).unwrap();
                }
                6 => queue.delivery_policy = DeliveryPolicy::SelectedFileSend,
                7 => {
                    for _ in 0..MAX_MESSAGES {
                        queue
                            .send(
                                &mut a,
                                sender,
                                send,
                                Outgoing {
                                    bytes: b"old",
                                    capability: None,
                                    deadline: expires,
                                },
                                2,
                            )
                            .unwrap();
                    }
                }
                _ => unreachable!(),
            }
            let before = snapshot(&queue);
            let authority_before = a.metadata_usage();
            assert!(
                queue
                    .check_send(&a, sender, send, payload, expires, when)
                    .is_err(),
                "case {case}"
            );
            assert_eq!(snapshot(&queue), before, "case {case}");
            assert_eq!(a.metadata_usage(), authority_before);
        }
    }
    #[test]
    fn scoped_revocation_invalidates_accepted_escrow_and_rejects_later_transfers() {
        use crate::capability::Derivation;
        let (mut a, mut m, s, r, send, receive) = setup();
        let custody = a.create_space().unwrap();
        let branches = a.create_space().unwrap();
        let user = a.create_space().unwrap();
        let root = a
            .create_root(
                custody,
                Kind::Memory,
                Rights::READ | Rights::TRANSFER | Rights::DERIVE | Rights::REVOKE,
            )
            .unwrap();
        let request = Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ | Rights::TRANSFER,
        };
        let batch = a
            .derive_scoped_into_empty(custody, branches, user, &[request; 2])
            .unwrap();
        let before = a.transfer(user, batch.grants.handles()[0], s).unwrap();
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(before),
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        a.collect_lineage().unwrap();
        a.revoke_batch(branches, batch.branches.handles()).unwrap();
        assert_eq!(
            m.receive(&mut a, r, receive, 1),
            Err(Error::Authority(CapError::Revoked))
        );
        assert_eq!(
            a.transfer(user, batch.grants.handles()[1], s),
            Err(CapError::Revoked)
        );
        assert_eq!(m.reclaim(&mut a, s, ticket, 5), Ok(Reclaimed::Invalidated));
        assert_eq!(m.pending(), 0);
        assert!(a.derive(custody, root, s, Rights::READ).is_ok());
    }
    #[test]
    fn recycled_sender_cannot_reclaim_old_escrow_and_collection_keeps_inflight_authority() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"old",
                    capability: Some(cap),
                    deadline: deadline(10),
                },
                0,
            )
            .unwrap();
        a.close_space(s).unwrap();
        let replacement = a.recycle_space(s).unwrap();
        a.collect_lineage().unwrap();
        assert_eq!(
            m.reclaim(&mut a, replacement, ticket, 1),
            Err(Error::WrongOwner)
        );
        assert_eq!(
            m.reclaim(&mut a, s, ticket, 1),
            Err(Error::Authority(CapError::InvalidSpace))
        );
        let delivered = m.receive(&mut a, r, receive, 1).unwrap();
        assert!(
            a.authorize(r, delivered.capability.unwrap(), Kind::Memory, Rights::READ)
                .is_ok()
        );
    }
    #[test]
    fn dead_sender_message_remains_deliverable_but_expired_orphans_are_discarded() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        m.send(
            &mut a,
            s,
            send,
            Outgoing {
                bytes: b"committed",
                capability: Some(cap),
                deadline: deadline(10),
            },
            0,
        )
        .unwrap();
        m.send(
            &mut a,
            s,
            send,
            Outgoing {
                bytes: b"expires",
                capability: None,
                deadline: deadline(2),
            },
            0,
        )
        .unwrap();
        a.close_space(s).unwrap();
        assert_eq!(m.reap_dead_senders(&mut a, 1), Ok(0));
        let delivered = m.receive(&mut a, r, receive, 1).unwrap();
        assert!(
            a.authorize(r, delivered.capability.unwrap(), Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert_eq!(m.reap_dead_senders(&mut a, 2), Ok(1));
        assert_eq!(m.receive(&mut a, r, receive, 2), Err(Error::Empty));
        assert_eq!(m.retire_empty(&mut a), Err(Error::NotReclaimable));
    }
    #[test]
    fn receiver_death_preserves_live_sender_reclaim_then_both_dead_drain_escrow() {
        let (mut a, mut m, s, r, send, _) = setup();
        let mut tickets = [Ticket(0); 2];
        for ticket in &mut tickets {
            let cap = a
                .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
                .unwrap();
            *ticket = m
                .send(
                    &mut a,
                    s,
                    send,
                    Outgoing {
                        bytes: b"held",
                        capability: Some(cap),
                        deadline: deadline(10),
                    },
                    0,
                )
                .unwrap();
        }
        a.close_space(r).unwrap();
        m.receiver_died(r).unwrap();
        assert_eq!(m.reap_dead_senders(&mut a, 1), Ok(0));
        assert_eq!(m.retire_empty(&mut a), Err(Error::NotReclaimable));
        let Reclaimed::Capability(returned) = m.reclaim(&mut a, s, tickets[0], 1).unwrap() else {
            panic!("return expected")
        };
        assert!(a.authorize(s, returned, Kind::Memory, Rights::READ).is_ok());
        a.close_space(s).unwrap();
        assert_eq!(
            m.reclaim(&mut a, s, tickets[1], 1),
            Err(Error::Authority(CapError::InvalidSpace))
        );
        assert_eq!(m.reap_dead_senders(&mut a, 1), Ok(1));
        assert_eq!(m.reap_dead_senders(&mut a, 1), Ok(0));
        assert!(m.messages.iter().all(Option::is_none));
        m.retire_empty(&mut a).unwrap();
        assert!(!a.is_live_space(m.escrow));
        m.retire_empty(&mut a).unwrap();
    }
    #[test]
    fn accepted_capability_is_unique_in_escrow_then_delivered_once() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"hello",
                    capability: Some(cap),
                    deadline: deadline(10),
                },
                0,
            )
            .unwrap();
        assert!(a.authorize(s, cap, Kind::Memory, Rights::READ).is_err());
        let got = m.receive(&mut a, r, receive, 1).unwrap();
        assert_eq!(&got.bytes[..got.length], b"hello");
        assert!(
            a.authorize(r, got.capability.unwrap(), Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert_eq!(m.receive(&mut a, r, receive, 2), Err(Error::Empty));
        assert_eq!(m.reclaim(&mut a, s, ticket, 10), Err(Error::InvalidTicket));
    }
    #[test]
    fn full_oversize_and_expired_sends_leave_source_capability_untouched() {
        let (mut a, mut m, s, _, send, _) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        assert_eq!(
            m.send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: &[0; MAX_BYTES + 1],
                    capability: Some(cap),
                    deadline: deadline(10)
                },
                0
            ),
            Err(Error::TooLarge)
        );
        assert_eq!(
            m.send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(cap),
                    deadline: deadline(0)
                },
                0
            ),
            Err(Error::Expired)
        );
        for _ in 0..MAX_MESSAGES {
            m.send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: None,
                    deadline: deadline(10),
                },
                0,
            )
            .unwrap();
        }
        assert_eq!(
            m.send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(cap),
                    deadline: deadline(10)
                },
                0
            ),
            Err(Error::Full)
        );
        assert!(a.authorize(s, cap, Kind::Memory, Rights::READ).is_ok());
        assert_eq!(m.pending(), MAX_MESSAGES);
    }
    #[test]
    fn receiver_full_table_keeps_escrow_and_fifo_for_retry() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        m.send(
            &mut a,
            s,
            send,
            Outgoing {
                bytes: b"first",
                capability: Some(cap),
                deadline: deadline(10),
            },
            0,
        )
        .unwrap();
        m.send(
            &mut a,
            s,
            send,
            Outgoing {
                bytes: b"second",
                capability: None,
                deadline: deadline(10),
            },
            0,
        )
        .unwrap();
        let mut fill = None;
        for _ in 1..crate::capability::MAX_CAPS {
            fill = Some(a.derive(r, receive, r, Rights::SEND).unwrap());
        }
        assert_eq!(
            m.receive(&mut a, r, receive, 1),
            Err(Error::Authority(CapError::Capacity))
        );
        assert_eq!(m.pending(), 2);
        a.close(r, fill.unwrap()).unwrap();
        let first = m.receive(&mut a, r, receive, 2).unwrap();
        assert_eq!(&first.bytes[..first.length], b"first");
        let second = m.receive(&mut a, r, receive, 2).unwrap();
        assert_eq!(&second.bytes[..second.length], b"second");
    }
    #[test]
    fn expiry_and_receiver_death_return_authority_without_duplicate_handles() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(cap),
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        assert_eq!(m.reclaim(&mut a, s, ticket, 4), Err(Error::NotReclaimable));
        assert_eq!(m.receive(&mut a, r, receive, 5), Err(Error::Expired));
        let Reclaimed::Capability(back) = m.reclaim(&mut a, s, ticket, 5).unwrap() else {
            panic!()
        };
        assert_ne!(back, cap);
        assert!(a.authorize(s, back, Kind::Memory, Rights::READ).is_ok());
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(back),
                    deadline: deadline(10),
                },
                5,
            )
            .unwrap();
        m.receiver_died(r).unwrap();
        assert_eq!(m.receive(&mut a, r, receive, 5), Err(Error::Closed));
        assert!(matches!(
            m.reclaim(&mut a, s, ticket, 5),
            Ok(Reclaimed::Capability(_))
        ));
        assert_eq!(m.reclaim(&mut a, s, ticket, 5), Err(Error::InvalidTicket));
    }
    #[test]
    fn revocation_in_escrow_prevents_delivery_and_reclaim_reports_invalidation() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let root = a
            .create_root(
                s,
                Kind::Memory,
                Rights::READ | Rights::TRANSFER | Rights::DERIVE | Rights::REVOKE,
            )
            .unwrap();
        let child = a
            .derive(s, root, s, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(child),
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        a.revoke(s, root).unwrap();
        assert_eq!(
            m.receive(&mut a, r, receive, 1),
            Err(Error::Authority(CapError::Revoked))
        );
        assert_eq!(m.pending(), 1);
        assert_eq!(m.reclaim(&mut a, s, ticket, 5), Ok(Reclaimed::Invalidated));
        assert_eq!(m.pending(), 0);
    }
    #[test]
    fn caller_and_endpoint_authority_are_required_and_clock_cannot_reverse() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let wrong = a.create_root(s, Kind::Endpoint, Rights::SEND).unwrap();
        assert_eq!(
            m.send(
                &mut a,
                s,
                wrong,
                Outgoing {
                    bytes: b"",
                    capability: None,
                    deadline: deadline(5)
                },
                0
            ),
            Err(Error::WrongEndpoint)
        );
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: None,
                    deadline: deadline(5),
                },
                1,
            )
            .unwrap();
        assert_eq!(m.receive(&mut a, s, send, 1), Err(Error::WrongOwner));
        assert_eq!(m.reclaim(&mut a, r, ticket, 5), Err(Error::WrongOwner));
        assert_eq!(m.receive(&mut a, r, receive, 4), Err(Error::ClockReversed));
        assert_eq!(m.pending(), 1);
    }
    #[test]
    fn sender_full_on_rollback_preserves_escrow_until_space_is_available() {
        let (mut a, mut m, s, r, send, receive) = setup();
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let ticket = m
            .send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(cap),
                    deadline: deadline(5),
                },
                0,
            )
            .unwrap();
        let mut filled = None;
        for _ in 1..crate::capability::MAX_CAPS {
            filled = Some(a.derive(r, receive, s, Rights::SEND).unwrap());
        }
        assert_eq!(
            m.reclaim(&mut a, s, ticket, 5),
            Err(Error::Authority(CapError::Capacity))
        );
        assert_eq!(m.pending(), 1);
        a.close(s, filled.unwrap()).unwrap();
        let Reclaimed::Capability(back) = m.reclaim(&mut a, s, ticket, 5).unwrap() else {
            panic!()
        };
        assert!(a.authorize(s, back, Kind::Memory, Rights::READ).is_ok());
        assert_eq!(m.pending(), 0);
    }
    #[test]
    fn denied_capability_transfer_does_not_accept_message() {
        let (mut a, mut m, s, _, send, _) = setup();
        let cap = a.create_root(s, Kind::Memory, Rights::READ).unwrap();
        assert_eq!(
            m.send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(cap),
                    deadline: deadline(5)
                },
                0
            ),
            Err(Error::Authority(CapError::Denied))
        );
        assert_eq!(m.pending(), 0);
        assert!(a.authorize(s, cap, Kind::Memory, Rights::READ).is_ok());
    }
    #[test]
    fn sequence_exhaustion_leaves_queue_and_source_authority_unchanged() {
        let (mut a, mut m, s, _, send, _) = setup();
        m.sequence = u64::MAX;
        let cap = a
            .create_root(s, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        assert_eq!(
            m.send(
                &mut a,
                s,
                send,
                Outgoing {
                    bytes: b"",
                    capability: Some(cap),
                    deadline: deadline(5)
                },
                0
            ),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(m.pending(), 0);
        assert!(a.authorize(s, cap, Kind::Memory, Rights::READ).is_ok());
    }
    #[test]
    fn selected_policy_sequence_exhaustion_and_rebind_are_atomic_and_immutable() {
        let mut f = restart_fixture();
        f.mailbox.delivery_policy = DeliveryPolicy::SelectedFileSend;
        let source = f
            .authority
            .derive(
                f.owner,
                f.control,
                f.sender,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        f.mailbox.sequence = u64::MAX;
        let before = snapshot(&f.mailbox);
        let usage = f.authority.metadata_usage();
        assert_eq!(
            f.mailbox.send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"selected",
                    capability: Some(source),
                    deadline: Deadline::after(0, 10).unwrap()
                },
                0
            ),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(snapshot(&f.mailbox), before);
        assert_eq!(f.authority.metadata_usage(), usage);
        assert!(
            f.authority
                .authorize(f.sender, source, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(
            f.mailbox
                .rebind_empty(&f.authority, f.receiver, f.receive, f.receiver, f.receive),
            Err(Error::RestrictedBinding)
        );
        assert_eq!(
            f.mailbox
                .reopen_empty(&f.authority, f.owner, f.control, f.receiver, f.receive),
            Err(Error::RestrictedBinding)
        );
        assert_eq!(snapshot(&f.mailbox), before);
    }
    #[test]
    fn selected_queue_bound_and_late_delivery_node_failure_keep_original_escrow() {
        let mut f = restart_fixture();
        f.mailbox.delivery_policy = DeliveryPolicy::SelectedFileSend;
        let mut tickets = [Ticket(0); MAX_MESSAGES];
        for ticket in &mut tickets {
            let source = f
                .authority
                .derive(
                    f.owner,
                    f.control,
                    f.sender,
                    Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
                )
                .unwrap();
            *ticket = f
                .mailbox
                .send(
                    &mut f.authority,
                    f.sender,
                    f.send,
                    Outgoing {
                        bytes: b"selected",
                        capability: Some(source),
                        deadline: Deadline::after(0, 10).unwrap(),
                    },
                    0,
                )
                .unwrap();
        }
        let source = f
            .authority
            .derive(
                f.owner,
                f.control,
                f.sender,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let before = snapshot(&f.mailbox);
        let usage = f.authority.metadata_usage();
        assert_eq!(
            f.mailbox.send(
                &mut f.authority,
                f.sender,
                f.send,
                Outgoing {
                    bytes: b"selected",
                    capability: Some(source),
                    deadline: Deadline::after(0, 10).unwrap()
                },
                0
            ),
            Err(Error::Full)
        );
        assert_eq!(snapshot(&f.mailbox), before);
        assert_eq!(f.authority.metadata_usage(), usage);
        while let Ok(cap) = f
            .authority
            .derive(f.owner, f.control, f.owner, Rights::SEND)
        {
            f.authority.close(f.owner, cap).unwrap();
        }
        let before = snapshot(&f.mailbox);
        let usage = f.authority.metadata_usage();
        assert_eq!(
            f.mailbox
                .receive(&mut f.authority, f.receiver, f.receive, 0),
            Err(Error::Authority(CapError::Capacity))
        );
        assert_eq!(snapshot(&f.mailbox), before);
        assert_eq!(f.authority.metadata_usage(), usage);
        f.authority.collect_lineage().unwrap();
        let leaf = f
            .mailbox
            .receive(&mut f.authority, f.receiver, f.receive, 0)
            .unwrap()
            .capability
            .unwrap();
        assert_eq!(
            f.authority
                .authorize(f.receiver, leaf, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights(),
            Rights::SEND
        );
        f.mailbox.receiver_died(f.receiver).unwrap();
        let refund = match f
            .mailbox
            .reclaim(&mut f.authority, f.sender, tickets[1], 0)
            .unwrap()
        {
            Reclaimed::Capability(h) => h,
            _ => panic!("original rights refund required"),
        };
        assert_eq!(
            f.authority
                .authorize(f.sender, refund, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights()
                .bits(),
            104
        );
    }
}
