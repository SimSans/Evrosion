//! One actual capability-bearing synchronous route, with retained ownership.
//!
//! A single trusted dispatcher retains this owner and the SAME Authority/Rpc/
//! Scheduler. Mailboxes are consumed at binding, never cloned. This module does
//! not block/wake a CPU: the runtime associates the full returned CallId with
//! its actual Scheduler WaitTicket before resuming any user context.
//! The first typed envelope is Internal cap_echo@1 (Memory READ|TRANSFER).
use crate::{
    capability::{self, Authority, Handle, Kind, Rights, SpaceId},
    ipc::{self, Delivery, Mailbox, Outgoing, Reclaimed, Ticket},
    rpc::{self, CallId, CompleteError, Completion, MessageShape, Policy, Rpc, Status},
    scheduler::{Scheduler, State, ThreadId},
    time::Deadline,
};
use ev_userspace_contract::cap_echo;

const ATTACHMENT: Rights =
    Rights::from_bits(Rights::READ.bits() | Rights::TRANSFER.bits()).unwrap();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority(capability::Error),
    Mailbox(ipc::Error),
    Rpc(rpc::Error),
    Wire(cap_echo::DecodeError),
    WrongThread,
    WrongCall,
    WrongObject,
    Binding,
    Busy,
    NotCancelled,
    Integrity,
}
impl From<capability::Error> for Error {
    fn from(error: capability::Error) -> Self {
        Self::Authority(error)
    }
}
impl From<ipc::Error> for Error {
    fn from(error: ipc::Error) -> Self {
        Self::Mailbox(error)
    }
}
impl From<rpc::Error> for Error {
    fn from(error: rpc::Error) -> Self {
        Self::Rpc(error)
    }
}

/// Rejection retains the input local handle; this does not assert that a forged
/// or subsequently revoked raw input was authorized. No new grant is minted.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejected {
    pub error: Error,
    pub retained: Handle,
}
pub struct RejectedBinding {
    pub request: Mailbox,
    pub response: Mailbox,
    pub error: Error,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub call: CallId,
    pub ticket: Ticket,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    pub call: CallId,
    pub bytes: [u8; 8],
    /// Actual newly installed handle in the servicing domain.
    pub capability: Handle,
}
pub enum ReceiveError {
    Rejected(Error),
    /// Private queue invariants failed after a real transfer. Preserve the full
    /// actual delivery instead of losing or inventing capability ownership.
    Integrity(Delivery),
}
#[derive(Debug, PartialEq, Eq)]
pub enum Replied {
    Returned {
        completion: Completion,
        bytes: [u8; 8],
        /// Actual newly installed caller-local handle, never the old input.
        capability: Handle,
    },
    Late {
        completion: Completion,
        /// Acknowledgement releases execution, but does not transfer this cap.
        retained: Handle,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub enum Failed {
    QueuedRecovered {
        call: CallId,
        status: Status,
        capability: Handle,
    },
    QueuedInvalidated {
        call: CallId,
        status: Status,
    },
    QueuedPending {
        call: CallId,
        status: Status,
    },
    /// The callee received the request. There is no original capability refund.
    Delivered {
        call: CallId,
        status: Status,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub enum DeadCaller {
    QueuedDiscarded { call: CallId },
    Delivered { call: CallId },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Delivered,
}
struct Exchange {
    id: CallId,
    ticket: Ticket,
    object: usize,
    phase: Phase,
}

pub struct EchoChannel {
    caller: ThreadId,
    callee: ThreadId,
    caller_space: SpaceId,
    callee_space: SpaceId,
    request_object: usize,
    response_object: usize,
    request: Mailbox,
    response: Mailbox,
    current: Option<Exchange>,
}
impl EchoChannel {
    /// Consume both actual, empty mailbox owners for this registered pair.
    /// The request endpoint is bound to the actual registered servicing thread;
    /// response SEND authority is checked again on every reply. The two peers
    /// use distinct domains, as in the initial service-process transport.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn bind(
        authority: &Authority,
        rpc: &mut Rpc,
        caller: ThreadId,
        callee: ThreadId,
        request_control: Handle,
        response_control: Handle,
        request: Mailbox,
        response: Mailbox,
    ) -> Result<Self, RejectedBinding> {
        let checked = (|| -> Result<_, Error> {
            let caller_space = rpc.thread_domain(caller)?;
            let callee_space = rpc.thread_domain(callee)?;
            if caller == callee || caller_space == callee_space {
                return Err(Error::Binding);
            }
            request.check_binding(authority, callee_space, request_control)?;
            response.check_binding(authority, caller_space, response_control)?;
            let incoming = authority
                .authorize(
                    callee_space,
                    request_control,
                    Kind::Endpoint,
                    Rights::RECEIVE | Rights::CONTROL,
                )?
                .identity();
            let outgoing = authority
                .authorize(
                    caller_space,
                    response_control,
                    Kind::Endpoint,
                    Rights::RECEIVE | Rights::CONTROL,
                )?
                .identity();
            if incoming == outgoing {
                return Err(Error::Binding);
            }
            rpc.bind_endpoint(
                authority,
                callee_space,
                request_control,
                callee,
                Policy::new(8, 1).ok_or(Error::Integrity)?,
            )?;
            Ok((caller_space, callee_space, incoming, outgoing))
        })();
        match checked {
            Ok((caller_space, callee_space, request_object, response_object)) => Ok(Self {
                caller,
                callee,
                caller_space,
                callee_space,
                request_object,
                response_object,
                request,
                response,
                current: None,
            }),
            Err(error) => Err(RejectedBinding {
                request,
                response,
                error,
            }),
        }
    }
    fn attachment(
        authority: &Authority,
        owner: SpaceId,
        cap: Handle,
    ) -> Result<(cap_echo::AttachmentShape, usize), Error> {
        let access = authority.authorize(owner, cap, Kind::Memory, ATTACHMENT)?;
        Ok((
            cap_echo::AttachmentShape {
                kind: 1,
                rights: access.rights().bits(),
            },
            access.identity(),
        ))
    }
    /// The runtime must preflight actual Scheduler::check_block before this
    /// acceptance, under the same serialized owner. No user wait is published
    /// until this returns Accepted. A failed enqueue cancels/acknowledges only
    /// the new undispatched edge; monotonic CallId gaps are intentionally kept.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self,
        authority: &mut Authority,
        rpc: &mut Rpc,
        caller: ThreadId,
        endpoint: Handle,
        bytes: [u8; 8],
        capability: Handle,
        deadline: Deadline,
        now: u64,
    ) -> Result<Accepted, Rejected> {
        let checked = (|| -> Result<_, Error> {
            if caller != self.caller {
                return Err(Error::WrongThread);
            }
            if self.current.is_some() {
                return Err(Error::Busy);
            }
            if rpc.thread_domain(caller)? != self.caller_space
                || rpc.thread_domain(self.callee)? != self.callee_space
            {
                return Err(Error::Binding);
            }
            if authority
                .authorize(self.caller_space, endpoint, Kind::Endpoint, Rights::SEND)?
                .identity()
                != self.request_object
            {
                return Err(Error::Binding);
            }
            let (shape, object) = Self::attachment(authority, self.caller_space, capability)?;
            cap_echo::validate_request(&bytes, &[shape]).map_err(Error::Wire)?;
            let id = rpc.begin(
                authority,
                caller,
                endpoint,
                deadline,
                MessageShape {
                    bytes: 8,
                    capabilities: 1,
                },
                now,
            )?;
            match self.request.send(
                authority,
                self.caller_space,
                endpoint,
                Outgoing {
                    bytes: &bytes,
                    capability: Some(capability),
                    deadline,
                },
                now,
            ) {
                Ok(ticket) => Ok((id, ticket, object)),
                Err(error) => {
                    // No message or wait was accepted. Keep the serial consumed
                    // but release the private undispatched reservation.
                    rpc.cancel(caller, id, now).map_err(|_| Error::Integrity)?;
                    rpc.complete(self.callee, id, now)
                        .map_err(|_| Error::Integrity)?;
                    Err(error.into())
                }
            }
        })();
        match checked {
            Ok((id, ticket, object)) => {
                self.current = Some(Exchange {
                    id,
                    ticket,
                    object,
                    phase: Phase::Queued,
                });
                Ok(Accepted { call: id, ticket })
            }
            Err(error) => Err(Rejected {
                error,
                retained: capability,
            }),
        }
    }
    /// Deliver only the current still-live protected request. Mailbox::receive
    /// performs the real escrow move; full receiver tables leave it queued.
    pub fn receive(
        &mut self,
        authority: &mut Authority,
        rpc: &Rpc,
        callee: ThreadId,
        endpoint: Handle,
        now: u64,
    ) -> Result<Received, ReceiveError> {
        let checked = (|| -> Result<_, Error> {
            if callee != self.callee {
                return Err(Error::WrongThread);
            }
            let current = self.current.as_ref().ok_or(Error::WrongCall)?;
            if current.phase != Phase::Queued || rpc.serving(callee) != Some(current.id) {
                return Err(Error::WrongCall);
            }
            let context = rpc.context(current.id)?;
            if let Some(status) = rpc.cancellation(context.cancellation_token, now)? {
                return Err(Error::Rpc(match status {
                    Status::Cancelled => rpc::Error::Cancelled,
                    Status::DeadlineExceeded => rpc::Error::DeadlineExceeded,
                    Status::PeerDied => rpc::Error::PeerDied,
                    Status::Ok => rpc::Error::StaleCall,
                }));
            }
            Ok(current.id)
        })()
        .map_err(ReceiveError::Rejected)?;
        let delivery = self
            .request
            .receive(authority, self.callee_space, endpoint, now)
            .map_err(|error| ReceiveError::Rejected(error.into()))?;
        // A successful queue receive ends refund rights even if a private
        // invariant is later found corrupt; preserve any actual delivered cap.
        if let Some(current) = self.current.as_mut() {
            current.phase = Phase::Delivered;
        }
        let Some(capability) = delivery.capability else {
            return Err(ReceiveError::Integrity(delivery));
        };
        let Some(bytes) = delivery
            .bytes
            .get(..delivery.length)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        else {
            return Err(ReceiveError::Integrity(delivery));
        };
        Ok(Received {
            call: checked,
            bytes,
            capability,
        })
    }
    /// A reply nonce is the protected serial returned by receive, never inferred
    /// from whichever call happens to be current when a SEND arrives. Exact
    /// object/rights/body validation precedes all ownership changes. The actual
    /// transfer runs inside Rpc's acceptance transaction; refusal changes neither
    /// source handle nor reservation. A late acknowledgement retains the cap.
    #[allow(clippy::too_many_arguments)]
    pub fn reply(
        &mut self,
        authority: &mut Authority,
        rpc: &mut Rpc,
        callee: ThreadId,
        endpoint: Handle,
        serial: u64,
        bytes: [u8; 8],
        capability: Handle,
        now: u64,
    ) -> Result<Replied, Rejected> {
        let checked = (|| -> Result<_, Error> {
            if callee != self.callee {
                return Err(Error::WrongThread);
            }
            let current = self.current.as_ref().ok_or(Error::WrongCall)?;
            if current.id.serial() != serial || current.phase != Phase::Delivered {
                return Err(Error::WrongCall);
            }
            if authority
                .authorize(self.callee_space, endpoint, Kind::Endpoint, Rights::SEND)?
                .identity()
                != self.response_object
            {
                return Err(Error::Binding);
            }
            // Validate the wire before acknowledgement as well as delivery.
            // A late acknowledgement returns the identical raw local input; it
            // need not still be a live grant after independent revocation.
            cap_echo::Response::decode(&bytes).map_err(Error::Wire)?;
            if capability.0 == 0 {
                return Err(capability::Error::InvalidHandle.into());
            }
            let result = rpc.complete_with(callee, current.id, now, |completion| {
                if !completion.deliver_reply {
                    return Ok(None);
                }
                let (shape, object) = Self::attachment(authority, self.callee_space, capability)?;
                cap_echo::validate_response(&bytes, &[shape]).map_err(Error::Wire)?;
                if object != current.object {
                    return Err(Error::WrongObject);
                }
                authority
                    .transfer(self.callee_space, capability, self.caller_space)
                    .map(Some)
                    .map_err(Error::from)
            });
            match result {
                Ok((completion, transferred)) => Ok((completion, transferred)),
                Err(CompleteError::Rpc(error)) => Err(error.into()),
                Err(CompleteError::Transport(error)) => Err(error),
            }
        })();
        match checked {
            Ok((completion, Some(returned))) => {
                self.current = None;
                Ok(Replied::Returned {
                    completion,
                    bytes,
                    capability: returned,
                })
            }
            Ok((completion, None)) => {
                self.current = None;
                Ok(Replied::Late {
                    completion,
                    retained: capability,
                })
            }
            Err(error) => Err(Rejected {
                error,
                retained: capability,
            }),
        }
    }
    /// Observe a protected cancellation/deadline/death, never a caller-supplied
    /// readiness flag. Queued rollback moves only the original Ticket; pressure
    /// retains both escrow ownership and execution reservation for retry. A
    /// delivered timeout reports no refund and keeps execution until ack/death.
    pub fn failure(
        &mut self,
        authority: &mut Authority,
        scheduler: &Scheduler,
        rpc: &mut Rpc,
        caller: ThreadId,
        serial: u64,
        now: u64,
    ) -> Result<Failed, Error> {
        if caller != self.caller {
            return Err(Error::WrongThread);
        }
        let current = self.current.as_ref().ok_or(Error::WrongCall)?;
        if current.id.serial() != serial {
            return Err(Error::WrongCall);
        }
        let (status, retired) = match rpc.context(current.id) {
            Ok(context) => (
                rpc.cancellation(context.cancellation_token, now)?
                    .ok_or(Error::NotCancelled)?,
                false,
            ),
            Err(rpc::Error::StaleCall) if scheduler.state(self.callee) == Ok(State::Exited) => {
                (Status::PeerDied, true)
            }
            Err(error) => return Err(error.into()),
        };
        let id = current.id;
        if current.phase == Phase::Delivered {
            if retired {
                self.current = None;
            }
            return Ok(Failed::Delivered { call: id, status });
        }
        let ticket = current.ticket;
        let reclaimed = if retired {
            self.request
                .withdraw_undelivered(authority, self.caller_space, ticket, now)
                .map_err(CompleteError::Transport)
        } else {
            rpc.complete_with(self.callee, id, now, |_| {
                self.request
                    .withdraw_undelivered(authority, self.caller_space, ticket, now)
            })
            .map(|(_, reclaimed)| reclaimed)
        };
        match reclaimed {
            Ok(Reclaimed::Capability(capability)) => {
                self.current = None;
                Ok(Failed::QueuedRecovered {
                    call: id,
                    status,
                    capability,
                })
            }
            Ok(Reclaimed::Invalidated) => {
                self.current = None;
                Ok(Failed::QueuedInvalidated { call: id, status })
            }
            Ok(Reclaimed::NoCapability) => Err(Error::Integrity),
            Err(CompleteError::Transport(ipc::Error::Authority(capability::Error::Capacity))) => {
                Ok(Failed::QueuedPending { call: id, status })
            }
            Err(CompleteError::Transport(error)) => Err(error.into()),
            Err(CompleteError::Rpc(error)) => Err(error.into()),
        }
    }
    pub fn current(&self) -> Option<CallId> {
        self.current.as_ref().map(|c| c.id)
    }
    /// Trusted dead-domain cleanup. Verify actual caller retirement and closed
    /// Authority domain, then discard only its still-queued escrow. Delivered
    /// authority remains with the callee and execution remains reserved until
    /// its acknowledgement/actual death. Apply Rpc::peer_died first so global
    /// causal cancellation notifications are dispatched by the runtime.
    pub fn discard_dead_caller(
        &mut self,
        authority: &mut Authority,
        scheduler: &Scheduler,
        rpc: &mut Rpc,
        now: u64,
    ) -> Result<DeadCaller, Error> {
        if scheduler.state(self.caller) != Ok(State::Exited)
            || authority.is_live_space(self.caller_space)
        {
            return Err(Error::Binding);
        }
        let current = self.current.as_ref().ok_or(Error::WrongCall)?;
        let id = current.id;
        let retired = match rpc.context(id) {
            Ok(context) => {
                if rpc.cancellation(context.cancellation_token, now)?.is_none() {
                    return Err(Error::NotCancelled);
                }
                false
            }
            Err(rpc::Error::StaleCall) if scheduler.state(self.callee) == Ok(State::Exited) => true,
            Err(error) => return Err(error.into()),
        };
        if current.phase == Phase::Delivered {
            if retired {
                self.current = None;
            }
            return Ok(DeadCaller::Delivered { call: id });
        }
        self.request.receiver_died(self.callee_space)?;
        let result = if retired {
            self.request
                .reap_dead_senders(authority, now)
                .map_err(CompleteError::Transport)
        } else {
            rpc.complete_with(self.callee, id, now, |_| {
                self.request.reap_dead_senders(authority, now)
            })
            .map(|(_, count)| count)
        };
        match result {
            Ok(1) => {
                self.current = None;
                Ok(DeadCaller::QueuedDiscarded { call: id })
            }
            Ok(_) => Err(Error::Integrity),
            Err(CompleteError::Rpc(error)) => Err(error.into()),
            Err(CompleteError::Transport(error)) => Err(error.into()),
        }
    }
    /// Return owners only after no request/execution/rollback remains. Physical
    /// teardown still belongs to the retained runtime and managed lifecycle gate.
    #[allow(clippy::result_large_err)]
    pub fn into_mailboxes(self) -> Result<(Mailbox, Mailbox), Self> {
        if self.current.is_some() {
            return Err(self);
        }
        Ok((self.request, self.response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{JobId, ProcessId, WaitTicket};
    use core::num::NonZeroU64;
    const ENDPOINT: Rights = Rights::from_bits(504).unwrap();
    struct Fixture {
        a: Authority,
        s: Scheduler,
        rpc: Rpc,
        channel: EchoChannel,
        caller: ThreadId,
        callee: ThreadId,
        caller_process: ProcessId,
        callee_process: ProcessId,
        caller_job: JobId,
        caller_space: SpaceId,
        callee_space: SpaceId,
        send: Handle,
        receive: Handle,
        reply: Handle,
    }
    fn fixture() -> Fixture {
        let mut a = Authority::new();
        let caller_space = a.create_space().unwrap();
        let callee_space = a.create_space().unwrap();
        let receive = a
            .create_root(callee_space, Kind::Endpoint, ENDPOINT)
            .unwrap();
        let send = a
            .derive(callee_space, receive, caller_space, Rights::SEND)
            .unwrap();
        let response = a
            .create_root(caller_space, Kind::Endpoint, ENDPOINT)
            .unwrap();
        let reply = a
            .derive(caller_space, response, callee_space, Rights::SEND)
            .unwrap();
        let request_mailbox = Mailbox::new(&mut a, callee_space, receive).unwrap();
        let response_mailbox = Mailbox::new(&mut a, caller_space, response).unwrap();
        let mut s = Scheduler::new();
        let caller_job = s.create_job().unwrap();
        let callee_job = s.create_job().unwrap();
        let caller_process = s.create_process(caller_job).unwrap();
        let callee_process = s.create_process(callee_job).unwrap();
        let caller = s.create_thread(caller_process).unwrap();
        let callee = s.create_thread(callee_process).unwrap();
        let mut rpc = Rpc::new(NonZeroU64::new(77).unwrap());
        rpc.register_thread(&a, &s, caller, caller_job, caller_space, None)
            .unwrap();
        rpc.register_thread(&a, &s, callee, callee_job, callee_space, None)
            .unwrap();
        let channel = EchoChannel::bind(
            &a,
            &mut rpc,
            caller,
            callee,
            receive,
            response,
            request_mailbox,
            response_mailbox,
        )
        .unwrap_or_else(|r| panic!("{:?}", r.error));
        Fixture {
            a,
            s,
            rpc,
            channel,
            caller,
            callee,
            caller_process,
            callee_process,
            caller_job,
            caller_space,
            callee_space,
            send,
            receive,
            reply,
        }
    }
    fn cap(f: &mut Fixture) -> Handle {
        f.a.create_root(f.caller_space, Kind::Memory, ATTACHMENT)
            .unwrap()
    }
    fn request(value: u32) -> [u8; 8] {
        cap_echo::Request { value }.encode()
    }
    fn response(value: u32) -> [u8; 8] {
        cap_echo::Response { value }.encode()
    }
    fn begin(f: &mut Fixture, cap: Handle, value: u32, deadline: u64) -> Accepted {
        f.channel
            .begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                f.send,
                request(value),
                cap,
                Deadline::after(0, deadline).unwrap(),
                0,
            )
            .unwrap()
    }
    fn receive(f: &mut Fixture) -> Received {
        f.channel
            .receive(&mut f.a, &f.rpc, f.callee, f.receive, 0)
            .unwrap_or_else(|error| match error {
                ReceiveError::Rejected(error) => panic!("{error:?}"),
                ReceiveError::Integrity(_) => panic!("private queue corruption"),
            })
    }
    fn fill(a: &mut Authority, space: SpaceId) -> Handle {
        // Fill HANDLE capacity, not the independent bounded object table.
        let base = a
            .create_root(space, Kind::Memory, Rights::READ | Rights::DERIVE)
            .unwrap();
        let mut last = base;
        while let Ok(cap) = a.derive(space, base, space, Rights::READ) {
            last = cap;
        }
        last
    }
    fn block(f: &mut Fixture, deadline: u64) -> WaitTicket {
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, f.caller);
        let deadline = Deadline::after(0, deadline).unwrap();
        f.s.check_block(0, deadline).unwrap();
        f.s.block(0, deadline).unwrap()
    }
    #[test]
    fn generated_attachment_mask_matches_actual_transfer_right_and_rejects_revoke_alias() {
        assert_eq!(
            cap_echo::MEMORY_READ_TRANSFER,
            (Rights::READ | Rights::TRANSFER).bits()
        );
        assert_eq!(cap_echo::MEMORY_READ_TRANSFER, 65);
        assert_eq!((Rights::READ | Rights::REVOKE).bits(), 129);
        let mut f = fixture();
        let revoke_only =
            f.a.create_root(f.caller_space, Kind::Memory, Rights::READ | Rights::REVOKE)
                .unwrap();
        let before = f.a.metadata_usage();
        assert_eq!(
            f.channel.begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                f.send,
                request(1),
                revoke_only,
                Deadline::after(0, 10).unwrap(),
                0
            ),
            Err(Rejected {
                error: Error::Authority(capability::Error::Denied),
                retained: revoke_only,
            })
        );
        assert_eq!(f.a.metadata_usage(), before);
        assert_eq!(f.rpc.outstanding(), 0);
        assert_eq!(f.channel.current(), None);
        assert!(
            f.a.authorize(f.caller_space, revoke_only, Kind::Memory, Rights::REVOKE)
                .is_ok()
        );
    }
    #[test]
    fn actual_round_trip_moves_only_once_and_wakes_only_its_real_wait_ticket() {
        for value in [0, 42, u32::MAX] {
            let mut f = fixture();
            let original = cap(&mut f);
            let identity =
                f.a.authorize(f.caller_space, original, Kind::Memory, ATTACHMENT)
                    .unwrap()
                    .identity();
            let accepted = begin(&mut f, original, value, 10);
            let wait = block(&mut f, 10);
            assert!(
                f.a.authorize(f.caller_space, original, Kind::Memory, ATTACHMENT)
                    .is_err()
            );
            let received = receive(&mut f);
            assert_eq!(received.call, accepted.call);
            assert_eq!(received.bytes, request(value));
            assert_eq!(
                f.a.authorize(
                    f.callee_space,
                    received.capability,
                    Kind::Memory,
                    ATTACHMENT
                )
                .unwrap()
                .identity(),
                identity
            );
            let replied = f
                .channel
                .reply(
                    &mut f.a,
                    &mut f.rpc,
                    f.callee,
                    f.reply,
                    accepted.call.serial(),
                    response(value),
                    received.capability,
                    1,
                )
                .unwrap();
            let Replied::Returned {
                completion,
                bytes,
                capability,
            } = replied
            else {
                panic!("timely reply")
            };
            assert_eq!(bytes, response(value));
            assert!(completion.deliver_reply && completion.wake_caller);
            assert_eq!(completion.call, accepted.call);
            assert_eq!(completion.caller, f.caller);
            assert_eq!(
                f.a.authorize(f.caller_space, capability, Kind::Memory, ATTACHMENT)
                    .unwrap()
                    .identity(),
                identity
            );
            assert!(
                f.a.authorize(
                    f.callee_space,
                    received.capability,
                    Kind::Memory,
                    ATTACHMENT
                )
                .is_err()
            );
            assert!(f.s.wake(wait));
            assert!(!f.s.wake(wait));
            assert_eq!(f.rpc.outstanding(), 0);
            assert_eq!(f.channel.current(), None);
            assert_eq!(f.s.process_job(f.caller_process), Ok(f.caller_job));
        }
    }
    #[test]
    fn malformed_wire_and_actual_wrong_kind_or_rights_reject_before_transfer_or_call_id() {
        let mut f = fixture();
        let source = cap(&mut f);
        for mut bytes in [request(1), response(1), [0; 8]] {
            if bytes == request(1) {
                bytes[2] = 2;
            }
            let before = f.a.metadata_usage();
            let rejected = f
                .channel
                .begin(
                    &mut f.a,
                    &mut f.rpc,
                    f.caller,
                    f.send,
                    bytes,
                    source,
                    Deadline::after(0, 10).unwrap(),
                    0,
                )
                .unwrap_err();
            assert_eq!(rejected.retained, source);
            assert_eq!(f.a.metadata_usage(), before);
            assert!(
                f.a.authorize(f.caller_space, source, Kind::Memory, ATTACHMENT)
                    .is_ok()
            );
            assert_eq!(f.rpc.outstanding(), 0);
        }
        for rights in [Rights::READ, ATTACHMENT | Rights::WRITE] {
            let bad =
                f.a.create_root(f.caller_space, Kind::Memory, rights)
                    .unwrap();
            assert!(
                f.channel
                    .begin(
                        &mut f.a,
                        &mut f.rpc,
                        f.caller,
                        f.send,
                        request(1),
                        bad,
                        Deadline::after(0, 10).unwrap(),
                        0
                    )
                    .is_err()
            );
            assert!(
                f.a.authorize(f.caller_space, bad, Kind::Memory, Rights::READ)
                    .is_ok()
            );
        }
        assert!(
            f.channel
                .begin(
                    &mut f.a,
                    &mut f.rpc,
                    f.caller,
                    f.send,
                    request(1),
                    f.send,
                    Deadline::after(0, 10).unwrap(),
                    0
                )
                .is_err()
        );
        assert_eq!(begin(&mut f, source, 1, 10).call.serial(), 1);
    }
    #[test]
    fn wrong_route_cannot_leave_a_foreign_protected_reservation() {
        let mut f = fixture();
        let source = cap(&mut f);
        let wrong =
            f.a.create_root(f.caller_space, Kind::Endpoint, ENDPOINT)
                .unwrap();
        let before = f.a.metadata_usage();
        assert_eq!(
            f.channel.begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                wrong,
                request(1),
                source,
                Deadline::after(0, 10).unwrap(),
                0
            ),
            Err(Rejected {
                error: Error::Binding,
                retained: source
            })
        );
        assert_eq!(f.a.metadata_usage(), before);
        assert_eq!(f.rpc.outstanding(), 0);
        assert_eq!(begin(&mut f, source, 1, 10).call.serial(), 1);
    }
    #[test]
    fn real_queue_full_rolls_back_only_undispatched_edge_without_consuming_source() {
        let mut f = fixture();
        let source = cap(&mut f);
        for _ in 0..ipc::MAX_MESSAGES {
            f.channel
                .request
                .send(
                    &mut f.a,
                    f.caller_space,
                    f.send,
                    Outgoing {
                        bytes: b"occupied",
                        capability: None,
                        deadline: Deadline::after(0, 10).unwrap(),
                    },
                    0,
                )
                .unwrap();
        }
        let before = f.a.metadata_usage();
        assert_eq!(
            f.channel.begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                f.send,
                request(1),
                source,
                Deadline::after(0, 10).unwrap(),
                0
            ),
            Err(Rejected {
                error: Error::Mailbox(ipc::Error::Full),
                retained: source
            })
        );
        assert_eq!(f.a.metadata_usage(), before);
        assert!(
            f.a.authorize(f.caller_space, source, Kind::Memory, ATTACHMENT)
                .is_ok()
        );
        assert_eq!(f.rpc.outstanding(), 0);
        assert_eq!(f.channel.current(), None);
    }
    #[test]
    fn full_callee_table_keeps_request_in_escrow_until_exact_timeout_recovery() {
        let mut f = fixture();
        let source = cap(&mut f);
        let accepted = begin(&mut f, source, 1, 10);
        fill(&mut f.a, f.callee_space);
        assert!(matches!(
            f.channel.receive(&mut f.a, &f.rpc, f.callee, f.receive, 1),
            Err(ReceiveError::Rejected(Error::Mailbox(
                ipc::Error::Authority(capability::Error::Capacity)
            )))
        ));
        f.rpc.expire(10).unwrap();
        let recovered = f
            .channel
            .failure(
                &mut f.a,
                &f.s,
                &mut f.rpc,
                f.caller,
                accepted.call.serial(),
                10,
            )
            .unwrap();
        let Failed::QueuedRecovered {
            capability,
            status: Status::DeadlineExceeded,
            ..
        } = recovered
        else {
            panic!("queued recovery")
        };
        assert!(
            f.a.authorize(f.caller_space, capability, Kind::Memory, ATTACHMENT)
                .is_ok()
        );
        assert_eq!(f.channel.current(), None);
        assert_eq!(f.rpc.outstanding(), 0);
    }
    #[test]
    fn cancelled_queued_request_reclaims_before_deadline_without_closing_route() {
        let mut f = fixture();
        let source = cap(&mut f);
        let accepted = begin(&mut f, source, 1, 10);
        f.rpc.cancel(f.caller, accepted.call, 1).unwrap();
        let Failed::QueuedRecovered {
            capability,
            status: Status::Cancelled,
            ..
        } = f
            .channel
            .failure(
                &mut f.a,
                &f.s,
                &mut f.rpc,
                f.caller,
                accepted.call.serial(),
                1,
            )
            .unwrap()
        else {
            panic!("cancelled queued recovery")
        };
        assert!(!f.channel.request.is_closed());
        let next = f
            .channel
            .begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                f.send,
                request(2),
                capability,
                Deadline::after(0, 10).unwrap(),
                1,
            )
            .unwrap();
        assert!(next.call.serial() > accepted.call.serial());
        assert_eq!(
            f.channel.failure(
                &mut f.a,
                &f.s,
                &mut f.rpc,
                f.caller,
                accepted.call.serial(),
                1
            ),
            Err(Error::WrongCall)
        );
        assert_eq!(f.channel.current(), Some(next.call));
    }
    #[test]
    fn full_caller_rejects_reply_unchanged_then_late_nonce_cannot_reply_to_a_new_call() {
        let mut f = fixture();
        let source = cap(&mut f);
        let accepted = begin(&mut f, source, 1, 10);
        let received = receive(&mut f);
        let freed = fill(&mut f.a, f.caller_space);
        let before = f.a.metadata_usage();
        assert_eq!(
            f.channel.reply(
                &mut f.a,
                &mut f.rpc,
                f.callee,
                f.reply,
                accepted.call.serial(),
                response(1),
                received.capability,
                1
            ),
            Err(Rejected {
                error: Error::Authority(capability::Error::Capacity),
                retained: received.capability,
            })
        );
        assert_eq!(f.a.metadata_usage(), before);
        assert!(
            f.a.authorize(
                f.callee_space,
                received.capability,
                Kind::Memory,
                ATTACHMENT
            )
            .is_ok()
        );
        assert_eq!(f.rpc.serving(f.callee), Some(accepted.call));
        f.rpc.expire(10).unwrap();
        assert_eq!(
            f.channel.failure(
                &mut f.a,
                &f.s,
                &mut f.rpc,
                f.caller,
                accepted.call.serial(),
                10
            ),
            Ok(Failed::Delivered {
                call: accepted.call,
                status: Status::DeadlineExceeded
            })
        );
        let late = f
            .channel
            .reply(
                &mut f.a,
                &mut f.rpc,
                f.callee,
                f.reply,
                accepted.call.serial(),
                response(1),
                received.capability,
                10,
            )
            .unwrap();
        assert!(
            matches!(late, Replied::Late { retained, completion: Completion { deliver_reply: false, wake_caller: false, .. } } if retained == received.capability)
        );
        assert!(
            f.a.authorize(
                f.callee_space,
                received.capability,
                Kind::Memory,
                ATTACHMENT
            )
            .is_ok()
        );
        f.a.close(f.caller_space, freed).unwrap();
        let next_source = cap(&mut f);
        let next = f
            .channel
            .begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                f.send,
                request(2),
                next_source,
                Deadline::after(0, 20).unwrap(),
                10,
            )
            .unwrap();
        let next_received = f
            .channel
            .receive(&mut f.a, &f.rpc, f.callee, f.receive, 10)
            .unwrap_or_else(|_| panic!("next receive"));
        assert_eq!(
            f.channel.reply(
                &mut f.a,
                &mut f.rpc,
                f.callee,
                f.reply,
                accepted.call.serial(),
                response(1),
                received.capability,
                11
            ),
            Err(Rejected {
                error: Error::WrongCall,
                retained: received.capability
            })
        );
        assert_eq!(f.rpc.serving(f.callee), Some(next.call));
        assert_eq!(
            f.channel.reply(
                &mut f.a,
                &mut f.rpc,
                f.callee,
                f.reply,
                next.call.serial(),
                response(2),
                received.capability,
                11
            ),
            Err(Rejected {
                error: Error::WrongObject,
                retained: received.capability
            })
        );
        assert_eq!(f.rpc.serving(f.callee), Some(next.call));
        assert!(matches!(
            f.channel
                .reply(
                    &mut f.a,
                    &mut f.rpc,
                    f.callee,
                    f.reply,
                    next.call.serial(),
                    response(2),
                    next_received.capability,
                    11
                )
                .unwrap(),
            Replied::Returned { .. }
        ));
    }
    #[test]
    fn reply_wire_identity_rights_and_callee_checks_precede_transfer_and_clock_commit() {
        let mut f = fixture();
        let source = cap(&mut f);
        let accepted = begin(&mut f, source, 1, 10);
        let received = receive(&mut f);
        let foreign =
            f.a.create_root(f.callee_space, Kind::Memory, ATTACHMENT)
                .unwrap();
        let excessive =
            f.a.create_root(f.callee_space, Kind::Memory, ATTACHMENT | Rights::WRITE)
                .unwrap();
        let before = f.a.metadata_usage();
        for (callee, endpoint, bytes, cap, expected) in [
            (
                f.caller,
                f.reply,
                response(1),
                received.capability,
                Error::WrongThread,
            ),
            (
                f.callee,
                f.receive,
                response(1),
                received.capability,
                Error::Binding,
            ),
            (
                f.callee,
                f.reply,
                request(1),
                received.capability,
                Error::Wire(cap_echo::DecodeError::Opcode),
            ),
            (f.callee, f.reply, response(1), foreign, Error::WrongObject),
            (
                f.callee,
                f.reply,
                response(1),
                excessive,
                Error::Wire(cap_echo::DecodeError::CapabilityRights),
            ),
        ] {
            assert_eq!(
                f.channel.reply(
                    &mut f.a,
                    &mut f.rpc,
                    callee,
                    endpoint,
                    accepted.call.serial(),
                    bytes,
                    cap,
                    5
                ),
                Err(Rejected {
                    error: expected,
                    retained: cap
                })
            );
            assert_eq!(f.a.metadata_usage(), before);
            assert_eq!(f.rpc.serving(f.callee), Some(accepted.call));
            assert_eq!(f.channel.current(), Some(accepted.call));
        }
        // Every rejection left Rpc's clock as well as its reservation unchanged.
        assert!(matches!(
            f.channel
                .reply(
                    &mut f.a,
                    &mut f.rpc,
                    f.callee,
                    f.reply,
                    accepted.call.serial(),
                    response(1),
                    received.capability,
                    1
                )
                .unwrap(),
            Replied::Returned { .. }
        ));
    }
    #[test]
    fn late_old_route_cannot_deliver_or_wake_a_newer_wait_on_an_independent_route() {
        let mut f = fixture();
        let original = cap(&mut f);
        let old = begin(&mut f, original, 1, 10);
        let old_wait = block(&mut f, 10);
        let old_received = receive(&mut f);
        f.rpc.expire(10).unwrap();
        f.s.advance(10).unwrap();
        let other_space = f.a.create_space().unwrap();
        let other_job = f.s.create_job().unwrap();
        let other_process = f.s.create_process(other_job).unwrap();
        let other_thread = f.s.create_thread(other_process).unwrap();
        f.rpc
            .register_thread(&f.a, &f.s, other_thread, other_job, other_space, None)
            .unwrap();
        let control =
            f.a.create_root(other_space, Kind::Endpoint, ENDPOINT)
                .unwrap();
        let send =
            f.a.derive(other_space, control, f.caller_space, Rights::SEND)
                .unwrap();
        let response_control =
            f.a.create_root(f.caller_space, Kind::Endpoint, ENDPOINT)
                .unwrap();
        let reply =
            f.a.derive(f.caller_space, response_control, other_space, Rights::SEND)
                .unwrap();
        let request_mailbox = Mailbox::new(&mut f.a, other_space, control).unwrap();
        let response_mailbox = Mailbox::new(&mut f.a, f.caller_space, response_control).unwrap();
        let mut other = EchoChannel::bind(
            &f.a,
            &mut f.rpc,
            f.caller,
            other_thread,
            control,
            response_control,
            request_mailbox,
            response_mailbox,
        )
        .unwrap_or_else(|rejected| panic!("{:?}", rejected.error));
        for _ in 0..crate::scheduler::MAX_THREADS {
            if f.s.dispatch(0).unwrap().unwrap().thread == f.caller {
                break;
            }
            f.s.yield_cpu(0).unwrap();
        }
        let deadline = Deadline::after(0, 20).unwrap();
        f.s.check_block(0, deadline).unwrap();
        let next_source = cap(&mut f);
        let next = other
            .begin(
                &mut f.a,
                &mut f.rpc,
                f.caller,
                send,
                request(2),
                next_source,
                deadline,
                10,
            )
            .unwrap();
        let next_wait = f.s.block(0, deadline).unwrap();
        let next_received = other
            .receive(&mut f.a, &f.rpc, other_thread, control, 10)
            .unwrap_or_else(|_| panic!("independent route receive"));
        let authority = f.a.metadata_usage();
        assert!(matches!(
            f.channel
                .reply(
                    &mut f.a,
                    &mut f.rpc,
                    f.callee,
                    f.reply,
                    old.call.serial(),
                    response(1),
                    old_received.capability,
                    11
                )
                .unwrap(),
            Replied::Late {
                completion: Completion {
                    wake_caller: false,
                    deliver_reply: false,
                    ..
                },
                ..
            }
        ));
        assert_eq!(f.a.metadata_usage(), authority);
        assert!(
            f.a.authorize(
                f.callee_space,
                old_received.capability,
                Kind::Memory,
                ATTACHMENT
            )
            .is_ok()
        );
        assert_eq!(f.rpc.waiting(f.caller), Some(next.call));
        assert_eq!(f.rpc.serving(other_thread), Some(next.call));
        assert!(!f.s.wake(old_wait));
        assert!(f.s.waiting(next_wait));
        let Replied::Returned {
            completion,
            capability,
            ..
        } = other
            .reply(
                &mut f.a,
                &mut f.rpc,
                other_thread,
                reply,
                next.call.serial(),
                response(2),
                next_received.capability,
                11,
            )
            .unwrap()
        else {
            panic!("independent current reply")
        };
        assert_eq!(completion.call, next.call);
        assert!(completion.wake_caller && completion.deliver_reply);
        assert!(
            f.a.authorize(f.caller_space, capability, Kind::Memory, ATTACHMENT)
                .is_ok()
        );
        assert!(f.s.wake(next_wait));
        assert_eq!(f.rpc.outstanding(), 0);
    }
    #[test]
    fn queued_recovery_pressure_preserves_escrow_and_reservation_until_retry() {
        let mut f = fixture();
        let source = cap(&mut f);
        let accepted = begin(&mut f, source, 1, 10);
        let free = fill(&mut f.a, f.caller_space);
        f.rpc.expire(10).unwrap();
        for _ in 0..2 {
            assert_eq!(
                f.channel.failure(
                    &mut f.a,
                    &f.s,
                    &mut f.rpc,
                    f.caller,
                    accepted.call.serial(),
                    10
                ),
                Ok(Failed::QueuedPending {
                    call: accepted.call,
                    status: Status::DeadlineExceeded
                })
            );
            assert_eq!(f.channel.current(), Some(accepted.call));
            assert_eq!(f.rpc.outstanding(), 1);
            assert_eq!(f.channel.request.pending(), 1);
        }
        f.a.close(f.caller_space, free).unwrap();
        assert!(matches!(
            f.channel
                .failure(
                    &mut f.a,
                    &f.s,
                    &mut f.rpc,
                    f.caller,
                    accepted.call.serial(),
                    10
                )
                .unwrap(),
            Failed::QueuedRecovered { .. }
        ));
        assert_eq!(f.channel.request.pending(), 0);
        assert_eq!(f.rpc.outstanding(), 0);
        assert_eq!(
            f.channel.failure(
                &mut f.a,
                &f.s,
                &mut f.rpc,
                f.caller,
                accepted.call.serial(),
                10
            ),
            Err(Error::WrongCall)
        );
    }
    #[test]
    fn queued_revocation_reports_invalidation_without_inventing_a_returned_handle() {
        let mut f = fixture();
        let root =
            f.a.create_root(
                f.caller_space,
                Kind::Memory,
                ATTACHMENT | Rights::DERIVE | Rights::REVOKE,
            )
            .unwrap();
        let source =
            f.a.derive(f.caller_space, root, f.caller_space, ATTACHMENT)
                .unwrap();
        let accepted = begin(&mut f, source, 1, 10);
        f.a.revoke(f.caller_space, root).unwrap();
        f.rpc.cancel(f.caller, accepted.call, 1).unwrap();
        assert_eq!(
            f.channel.failure(
                &mut f.a,
                &f.s,
                &mut f.rpc,
                f.caller,
                accepted.call.serial(),
                1
            ),
            Ok(Failed::QueuedInvalidated {
                call: accepted.call,
                status: Status::Cancelled
            })
        );
        assert_eq!(f.rpc.outstanding(), 0);
    }
    #[test]
    fn late_acknowledgement_can_retain_a_now_revoked_input_without_minting_authority() {
        let mut f = fixture();
        let root =
            f.a.create_root(
                f.caller_space,
                Kind::Memory,
                ATTACHMENT | Rights::DERIVE | Rights::REVOKE,
            )
            .unwrap();
        let source =
            f.a.derive(f.caller_space, root, f.caller_space, ATTACHMENT)
                .unwrap();
        let accepted = begin(&mut f, source, 1, 10);
        let received = receive(&mut f);
        f.a.revoke(f.caller_space, root).unwrap();
        f.rpc.cancel(f.caller, accepted.call, 1).unwrap();
        let before = f.a.metadata_usage();
        assert!(
            matches!(f.channel.reply(&mut f.a, &mut f.rpc, f.callee, f.reply, accepted.call.serial(),
            response(1), received.capability, 1).unwrap(), Replied::Late { retained, .. } if retained == received.capability)
        );
        assert_eq!(f.a.metadata_usage(), before);
        assert_eq!(
            f.a.authorize(
                f.callee_space,
                received.capability,
                Kind::Memory,
                ATTACHMENT
            )
            .err(),
            Some(capability::Error::Revoked)
        );
        assert_eq!(f.rpc.outstanding(), 0);
    }
    #[test]
    fn actual_callee_death_recovers_only_queued_requests_and_never_refunds_delivered_caps() {
        for delivered in [false, true] {
            let mut f = fixture();
            let source = cap(&mut f);
            let accepted = begin(&mut f, source, 1, 10);
            let received = delivered.then(|| receive(&mut f));
            assert_eq!(
                f.rpc.peer_died(&f.s, f.callee, 1).err(),
                Some(rpc::Error::PeerStillLive)
            );
            f.s.terminate_process(f.callee_process).unwrap();
            f.rpc.peer_died(&f.s, f.callee, 1).unwrap();
            let failure = f
                .channel
                .failure(
                    &mut f.a,
                    &f.s,
                    &mut f.rpc,
                    f.caller,
                    accepted.call.serial(),
                    1,
                )
                .unwrap();
            if let Some(received) = received {
                assert_eq!(
                    failure,
                    Failed::Delivered {
                        call: accepted.call,
                        status: Status::PeerDied
                    }
                );
                assert!(
                    f.a.authorize(
                        f.callee_space,
                        received.capability,
                        Kind::Memory,
                        ATTACHMENT
                    )
                    .is_ok()
                );
                assert!(
                    f.a.authorize(f.caller_space, source, Kind::Memory, ATTACHMENT)
                        .is_err()
                );
            } else {
                assert!(matches!(
                    failure,
                    Failed::QueuedRecovered {
                        status: Status::PeerDied,
                        ..
                    }
                ));
            }
            assert_eq!(f.channel.current(), None);
        }
    }
    #[test]
    fn actual_dead_closed_caller_discards_queued_escrow_but_not_callee_owned_delivery() {
        for delivered in [false, true] {
            let mut f = fixture();
            let source = cap(&mut f);
            let accepted = begin(&mut f, source, 1, 10);
            let received = delivered.then(|| receive(&mut f));
            assert_eq!(
                f.channel.discard_dead_caller(&mut f.a, &f.s, &mut f.rpc, 1),
                Err(Error::Binding)
            );
            f.s.terminate_process(f.caller_process).unwrap();
            f.rpc.peer_died(&f.s, f.caller, 1).unwrap();
            f.a.close_space(f.caller_space).unwrap();
            let discarded = f
                .channel
                .discard_dead_caller(&mut f.a, &f.s, &mut f.rpc, 1)
                .unwrap();
            if let Some(received) = received {
                assert_eq!(
                    discarded,
                    DeadCaller::Delivered {
                        call: accepted.call
                    }
                );
                assert!(
                    f.a.authorize(
                        f.callee_space,
                        received.capability,
                        Kind::Memory,
                        ATTACHMENT
                    )
                    .is_ok()
                );
                assert_eq!(f.rpc.outstanding(), 1);
            } else {
                assert_eq!(
                    discarded,
                    DeadCaller::QueuedDiscarded {
                        call: accepted.call
                    }
                );
                assert_eq!(f.channel.request.pending(), 0);
                assert_eq!(f.rpc.outstanding(), 0);
            }
        }
    }
    #[test]
    fn both_actual_peers_dead_can_release_queued_or_delivered_owner_without_refund() {
        for delivered in [false, true] {
            for callee_first in [false, true] {
                let mut f = fixture();
                let source = cap(&mut f);
                let accepted = begin(&mut f, source, 1, 10);
                if delivered {
                    receive(&mut f);
                }
                f.s.terminate_process(f.caller_process).unwrap();
                f.s.terminate_process(f.callee_process).unwrap();
                for peer in if callee_first {
                    [f.callee, f.caller]
                } else {
                    [f.caller, f.callee]
                } {
                    f.rpc.peer_died(&f.s, peer, 1).unwrap();
                }
                f.a.close_space(f.caller_space).unwrap();
                f.a.close_space(f.callee_space).unwrap();
                let result = f
                    .channel
                    .discard_dead_caller(&mut f.a, &f.s, &mut f.rpc, 1)
                    .unwrap();
                assert_eq!(
                    result,
                    if delivered {
                        DeadCaller::Delivered {
                            call: accepted.call,
                        }
                    } else {
                        DeadCaller::QueuedDiscarded {
                            call: accepted.call,
                        }
                    }
                );
                assert_eq!(f.channel.current(), None);
                assert_eq!(f.rpc.outstanding(), 0);
                assert!(f.channel.into_mailboxes().is_ok());
            }
        }
    }
}
