//! Capability-controlled cap-free messages with authenticated send provenance.
//! Process/thread identities are copied diagnostics, never bearer authority or
//! a health verdict. One serialized owner retains this queue and its exact
//! Authority/Scheduler/Rpc; no user-supplied PID/domain/healthy flag is accepted.
use crate::{
    capability::{Authority, Handle, SpaceId},
    ipc::{self, Delivery, MAX_MESSAGES, Mailbox, Outgoing, Ticket},
    rpc::{self, Rpc},
    scheduler::{self, ProcessId, Scheduler, ThreadId},
    time::Deadline,
};

pub struct Caller<'a> {
    pub authority: &'a mut Authority,
    pub scheduler: &'a Scheduler,
    pub rpc: &'a Rpc,
    pub cpu: usize,
}
impl Caller<'_> {
    fn identity(&self) -> Result<(SpaceId, ProcessId, ThreadId), Error> {
        let thread = self.scheduler.running_thread(self.cpu)?;
        let process = self.scheduler.thread_process(thread)?;
        let domain = self.rpc.checked_thread_domain(self.scheduler, thread)?;
        if !self.authority.is_live_space(domain) {
            return Err(Error::Ipc(ipc::Error::Authority(
                crate::capability::Error::InvalidSpace,
            )));
        }
        Ok((domain, process, thread))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Ipc(ipc::Error),
    Scheduler(scheduler::Error),
    Rpc(rpc::Error),
    MissingOrigin,
    OriginCapacity,
}
impl From<ipc::Error> for Error {
    fn from(error: ipc::Error) -> Self {
        Self::Ipc(error)
    }
}
impl From<scheduler::Error> for Error {
    fn from(error: scheduler::Error) -> Self {
        Self::Scheduler(error)
    }
}
impl From<rpc::Error> for Error {
    fn from(error: rpc::Error) -> Self {
        Self::Rpc(error)
    }
}
#[derive(Clone, Copy)]
struct Origin {
    ticket: Ticket,
    process: ProcessId,
    thread: ThreadId,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    pub delivery: Delivery,
    pub process: ProcessId,
    pub thread: ThreadId,
}

pub struct Channel {
    mailbox: Mailbox,
    origins: [Option<Origin>; MAX_MESSAGES],
}
impl Channel {
    /// Wrapping never invents provenance for a previously accepted message.
    #[allow(clippy::result_large_err)] // A refused constructor returns the unique escrow owner.
    pub fn new(mailbox: Mailbox) -> Result<Self, Mailbox> {
        if mailbox.pending() != 0 {
            return Err(mailbox);
        }
        Ok(Self {
            mailbox,
            origins: [None; MAX_MESSAGES],
        })
    }
    pub fn metadata_usage(&self) -> (usize, usize) {
        (
            self.mailbox.pending(),
            self.origins.iter().flatten().count(),
        )
    }
    pub fn rebind_empty(
        &mut self,
        a: &Authority,
        owner: SpaceId,
        control: Handle,
        destination: SpaceId,
        receive: Handle,
    ) -> Result<(), Error> {
        if self.origins.iter().any(Option::is_some) {
            return Err(Error::MissingOrigin);
        }
        Ok(self
            .mailbox
            .rebind_empty(a, owner, control, destination, receive)?)
    }
    pub fn send(
        &mut self,
        caller: Caller<'_>,
        endpoint: Handle,
        bytes: [u8; 8],
        deadline: Deadline,
        now: u64,
    ) -> Result<Ticket, Error> {
        let (domain, process, thread) = caller.identity()?;
        self.mailbox
            .check_sender(caller.authority, domain, endpoint)?;
        // Reserve bounded origin capacity BEFORE accepting any queue message.
        let slot = self
            .origins
            .iter()
            .position(Option::is_none)
            .ok_or(Error::OriginCapacity)?;
        let ticket = self.mailbox.send(
            caller.authority,
            domain,
            endpoint,
            Outgoing {
                bytes: &bytes,
                capability: None,
                deadline,
            },
            now,
        )?;
        // Both are fixed metadata writes under the same owner; no fallible work
        // follows the mailbox commit and no other sender can interleave.
        self.origins[slot] = Some(Origin {
            ticket,
            process,
            thread,
        });
        Ok(ticket)
    }
    pub fn receive(
        &mut self,
        caller: Caller<'_>,
        endpoint: Handle,
        now: u64,
    ) -> Result<Received, Error> {
        let (domain, _, _) = caller.identity()?;
        let ticket = self
            .mailbox
            .peek_ticket(caller.authority, domain, endpoint, now)?;
        let slot = self
            .origins
            .iter()
            .position(|origin| origin.is_some_and(|origin| origin.ticket == ticket))
            .ok_or(Error::MissingOrigin)?;
        let origin = self.origins[slot].unwrap();
        // Missing/stale provenance fails above, BEFORE dequeue or escrow moves.
        // Keep the same serialized owner from peek through the exact commit.
        let delivery = self
            .mailbox
            .receive(caller.authority, domain, endpoint, now)?;
        assert_eq!(
            delivery.ticket, ticket,
            "serialized queue changed its selected message"
        );
        self.origins[slot] = None;
        Ok(Received {
            delivery,
            process: origin.process,
            thread: origin.thread,
        })
    }
    pub fn receiver_died(&mut self, receiver: SpaceId) -> Result<(), Error> {
        Ok(self.mailbox.receiver_died(receiver)?)
    }
    /// Ordinary sender-owned expiry/closed-receiver reclaim. A ticket is only a
    /// receipt: the actual running caller's domain must still own the message.
    pub fn reclaim(
        &mut self,
        caller: Caller<'_>,
        ticket: Ticket,
        now: u64,
    ) -> Result<ipc::Reclaimed, Error> {
        let (domain, _, _) = caller.identity()?;
        let slot = self
            .origins
            .iter()
            .position(|origin| origin.is_some_and(|origin| origin.ticket == ticket))
            .ok_or(Error::MissingOrigin)?;
        let reclaimed = self
            .mailbox
            .reclaim(caller.authority, domain, ticket, now)?;
        assert!(!self.mailbox.contains_ticket(ticket));
        self.origins[slot] = None;
        Ok(reclaimed)
    }
    /// Ordinary closed/dead-sender disposal owns queue removal. Only origins
    /// whose exact tickets are no longer retained may be pruned afterward.
    pub fn discard_dead_senders(&mut self, a: &mut Authority, now: u64) -> Result<usize, Error> {
        let count = self.mailbox.reap_dead_senders(a, now)?;
        for origin in &mut self.origins {
            if origin.is_some_and(|origin| !self.mailbox.contains_ticket(origin.ticket)) {
                *origin = None;
            }
        }
        Ok(count)
    }
    #[allow(clippy::result_large_err)] // Failure retains every unique queue/origin owner.
    pub fn into_empty(self) -> Result<Mailbox, Self> {
        if self.mailbox.pending() != 0 || self.origins.iter().any(Option::is_some) {
            Err(self)
        } else {
            Ok(self.mailbox)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capability::{Kind, Rights},
        scheduler::{Limits, State},
    };
    use core::num::NonZeroU64;
    struct Model {
        a: Authority,
        s: Scheduler,
        rpc: Rpc,
        spaces: [SpaceId; 2],
        processes: [ProcessId; 2],
        threads: [ThreadId; 2],
        receive: Handle,
        send: [Handle; 2],
        channel: Channel,
    }
    impl Model {
        fn new() -> Self {
            let mut a = Authority::new();
            let spaces = [a.create_space().unwrap(), a.create_space().unwrap()];
            let all = Rights::SEND
                | Rights::RECEIVE
                | Rights::CONTROL
                | Rights::DERIVE
                | Rights::TRANSFER;
            let receive = a.create_root(spaces[0], Kind::Endpoint, all).unwrap();
            let send = [
                a.derive(spaces[0], receive, spaces[0], Rights::SEND)
                    .unwrap(),
                a.derive(spaces[0], receive, spaces[1], Rights::SEND)
                    .unwrap(),
            ];
            let mailbox = Mailbox::new(&mut a, spaces[0], receive).unwrap();
            let channel = Channel::new(mailbox).unwrap_or_else(|_| panic!("empty model queue"));
            let mut s = Scheduler::new();
            let jobs = [
                s.create_job_with_limits(Limits::new(128, 1, 1, 1)).unwrap(),
                s.create_job_with_limits(Limits::new(128, 1, 1, 1)).unwrap(),
            ];
            let processes = [
                s.create_process(jobs[0]).unwrap(),
                s.create_held_process(jobs[1]).unwrap(),
            ];
            let threads = [
                s.create_thread(processes[0]).unwrap(),
                s.create_thread(processes[1]).unwrap(),
            ];
            let mut rpc = Rpc::new(NonZeroU64::new(1).unwrap());
            for i in 0..2 {
                rpc.register_thread(&a, &s, threads[i], jobs[i], spaces[i], None)
                    .unwrap();
            }
            Self {
                a,
                s,
                rpc,
                spaces,
                processes,
                threads,
                receive,
                send,
                channel,
            }
        }
        fn dispatch(&mut self, index: usize) {
            for _ in 0..8 {
                let dispatch = self.s.dispatch(0).unwrap().unwrap();
                if dispatch.thread == self.threads[index] {
                    return;
                }
                self.s.yield_cpu(0).unwrap();
            }
            panic!("bounded model dispatch");
        }
        fn send(&mut self, index: usize, now: u64, deadline: u64) -> Ticket {
            self.dispatch(index);
            let ticket = self
                .channel
                .send(
                    Caller {
                        authority: &mut self.a,
                        scheduler: &self.s,
                        rpc: &self.rpc,
                        cpu: 0,
                    },
                    self.send[index],
                    *b"EVRT\x01\x05\0\0",
                    Deadline::after(0, deadline).unwrap(),
                    now,
                )
                .unwrap();
            self.s.yield_cpu(0).unwrap();
            ticket
        }
        fn receive(&mut self, now: u64) -> Result<Received, Error> {
            self.dispatch(0);
            let result = self.channel.receive(
                Caller {
                    authority: &mut self.a,
                    scheduler: &self.s,
                    rpc: &self.rpc,
                    cpu: 0,
                },
                self.receive,
                now,
            );
            self.s.yield_cpu(0).unwrap();
            result
        }
        fn admit_critical_model(&mut self) {
            let job = self.s.process_job(self.processes[1]).unwrap();
            self.s.charge_frames(job, 1).unwrap();
            self.s
                .admit_service(self.processes[1], job, self.threads[1], 1)
                .unwrap();
        }
    }
    #[test]
    fn forged_ready_before_and_after_model_admission_keeps_actual_sender_identity() {
        // Queue/identity model only, not actual hardware health admission.
        let mut m = Model::new();
        let before = m.send(0, 1, 20);
        m.admit_critical_model();
        let actual = m.send(1, 2, 20);
        let after = m.send(0, 3, 20);
        for (ticket, source) in [(before, 0), (actual, 1), (after, 0)] {
            let event = m.receive(4).unwrap();
            assert_eq!(event.delivery.ticket, ticket);
            assert_eq!(
                (event.process, event.thread),
                (m.processes[source], m.threads[source])
            );
            assert_eq!(&event.delivery.bytes[..8], b"EVRT\x01\x05\0\0");
        }
        assert_eq!(m.channel.metadata_usage(), (0, 0));
    }
    #[test]
    fn missing_or_stale_origin_refuses_without_losing_the_accepted_message() {
        let mut m = Model::new();
        let ticket = m.send(0, 1, 20);
        let origin = m.channel.origins[0].take().unwrap();
        let usage = m.a.metadata_usage();
        assert_eq!(m.receive(2), Err(Error::MissingOrigin));
        assert_eq!(m.channel.metadata_usage(), (1, 0));
        assert_eq!(m.a.metadata_usage(), usage);
        m.channel.origins[0] = Some(Origin {
            ticket: Ticket(ticket.0 + 1),
            ..origin
        });
        assert_eq!(m.receive(2), Err(Error::MissingOrigin));
        assert_eq!(m.channel.metadata_usage(), (1, 1));
        m.channel.origins[0] = Some(origin);
        assert_eq!(m.receive(2).unwrap().delivery.ticket, ticket);
        m.admit_critical_model();
        let next = m.send(1, 3, 20);
        assert_ne!(next, ticket);
        let current = m.channel.origins[0].replace(origin).unwrap();
        assert_eq!(m.receive(4), Err(Error::MissingOrigin));
        assert_eq!(m.channel.metadata_usage(), (1, 1));
        m.channel.origins[0] = Some(current);
        let received = m.receive(4).unwrap();
        assert_eq!(received.delivery.ticket, next);
        assert_eq!(
            (received.process, received.thread),
            (m.processes[1], m.threads[1])
        );
    }
    #[test]
    fn expired_front_retains_provenance_until_ordinary_dead_sender_drain() {
        let mut m = Model::new();
        m.send(0, 1, 3);
        assert_eq!(m.receive(3), Err(Error::Ipc(ipc::Error::Expired)));
        assert_eq!(m.channel.metadata_usage(), (1, 1));
        m.channel.receiver_died(m.spaces[0]).unwrap();
        m.a.close_space(m.spaces[0]).unwrap();
        assert_eq!(m.channel.discard_dead_senders(&mut m.a, 3), Ok(1));
        assert_eq!(m.channel.metadata_usage(), (0, 0));
        assert!(m.channel.into_empty().is_ok());
    }
    #[test]
    fn origin_capacity_and_foreign_handle_fail_before_queue_acceptance() {
        let mut m = Model::new();
        m.dispatch(0);
        assert!(matches!(
            m.channel.send(
                Caller {
                    authority: &mut m.a,
                    scheduler: &m.s,
                    rpc: &m.rpc,
                    cpu: 0
                },
                Handle(u64::MAX),
                [0; 8],
                Deadline::after(0, 30).unwrap(),
                1
            ),
            Err(Error::Ipc(ipc::Error::Authority(_)))
        ));
        assert_eq!(m.channel.metadata_usage(), (0, 0));
        m.s.yield_cpu(0).unwrap();
        for i in 0..MAX_MESSAGES {
            m.send(0, i as u64 + 1, 30);
        }
        m.dispatch(0);
        let usage = m.a.metadata_usage();
        assert_eq!(
            m.channel.send(
                Caller {
                    authority: &mut m.a,
                    scheduler: &m.s,
                    rpc: &m.rpc,
                    cpu: 0
                },
                m.send[0],
                [0; 8],
                Deadline::after(0, 30).unwrap(),
                5
            ),
            Err(Error::OriginCapacity)
        );
        assert_eq!(m.channel.metadata_usage(), (MAX_MESSAGES, MAX_MESSAGES));
        assert_eq!(m.a.metadata_usage(), usage);
        assert_eq!(m.s.state(m.threads[0]), Ok(State::Running(0)));
    }
    #[test]
    fn live_sender_expiry_reclaim_prunes_only_its_exact_ticket() {
        let mut m = Model::new();
        m.admit_critical_model();
        let ticket = m.send(1, 1, 3);
        m.dispatch(0);
        assert_eq!(
            m.channel.reclaim(
                Caller {
                    authority: &mut m.a,
                    scheduler: &m.s,
                    rpc: &m.rpc,
                    cpu: 0
                },
                ticket,
                3
            ),
            Err(Error::Ipc(ipc::Error::WrongOwner))
        );
        assert_eq!(m.channel.metadata_usage(), (1, 1));
        m.s.yield_cpu(0).unwrap();
        m.dispatch(1);
        assert_eq!(
            m.channel.reclaim(
                Caller {
                    authority: &mut m.a,
                    scheduler: &m.s,
                    rpc: &m.rpc,
                    cpu: 0
                },
                ticket,
                3
            ),
            Ok(ipc::Reclaimed::NoCapability)
        );
        assert_eq!(m.channel.metadata_usage(), (0, 0));
        assert_eq!(
            m.channel.reclaim(
                Caller {
                    authority: &mut m.a,
                    scheduler: &m.s,
                    rpc: &m.rpc,
                    cpu: 0
                },
                ticket,
                3
            ),
            Err(Error::MissingOrigin)
        );
    }
}
