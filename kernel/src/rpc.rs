//! Bounded Internal synchronous-call discipline; no transport or context switch.
//!
//! One trusted kernel owner serializes this metadata with its actual scheduler,
//! endpoint registry and message/capability acceptance. All identities come from
//! that same Authority/Scheduler instance, never userspace diagnostic integers.
//! Accepted cancellation/timeout ends a wait, not callee execution: retain the
//! non-reentrant reservation until the actual callee acknowledges or retires.
use crate::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    incarnation::Token,
    scheduler::{JobId, MAX_THREADS, Scheduler, State, ThreadId},
    time::Deadline,
};
use core::num::NonZeroU64;

pub const MAX_DEPTH: u8 = 8;
pub const MAX_CALLS: usize = 8;
pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_LOCKS: usize = 8;
pub const MAX_BYTES: usize = 64;
pub const MAX_CAPABILITIES: usize = 1;

/// Opaque, monotonically allocated, instance-local identity. The boot owner must
/// maintain one Rpc allocator for this epoch; never mix independent instances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallId {
    epoch: NonZeroU64,
    serial: u64,
}
impl CallId {
    pub fn epoch(self) -> NonZeroU64 {
        self.epoch
    }
    pub fn serial(self) -> u64 {
        self.serial
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceId(CallId);
impl TraceId {
    pub fn root(self) -> CallId {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancellationToken(CallId);

/// Read-only copy of kernel-generated causal metadata. begin() does not accept a
/// caller-supplied Context, trace, parent, origin, depth or cancellation token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub trace_id: TraceId,
    pub call_id: CallId,
    pub parent_call_id: Option<CallId>,
    pub origin_job: JobId,
    pub depth: u8,
    pub deadline: Deadline,
    pub cancellation_token: CancellationToken,
    pub root_incarnation: Option<Token>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Cancelled,
    DeadlineExceeded,
    PeerDied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    PermissionDenied,
    Identity,
    AlreadyRegistered,
    UnknownThread,
    UnknownEndpoint,
    AlreadyBound,
    IncarnationMismatch,
    WouldBlock,
    Overloaded,
    AlreadyWaiting,
    DangerousLock,
    LockOrder,
    DeadlockDetected,
    DepthExceeded,
    DeadlineExtended,
    DeadlineExceeded,
    Cancelled,
    PeerDied,
    PeerStillLive,
    MalformedMessage,
    ClockReversed,
    SequenceExhausted,
    StaleCall,
    WrongCaller,
    WrongCallee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    max_bytes: usize,
    max_capabilities: usize,
}
impl Policy {
    /// Each endpoint has exactly one accepted in-flight request and no unbounded
    /// pending queue. A busy endpoint returns WouldBlock without accepting work.
    pub const fn new(max_bytes: usize, max_capabilities: usize) -> Option<Self> {
        if max_bytes == 0 || max_bytes > MAX_BYTES || max_capabilities > MAX_CAPABILITIES {
            None
        } else {
            Some(Self {
                max_bytes,
                max_capabilities,
            })
        }
    }
    pub const fn max_messages(self) -> usize {
        1
    }
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
    pub const fn max_capabilities(self) -> usize {
        self.max_capabilities
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageShape {
    pub bytes: usize,
    pub capabilities: usize,
}

/// Trusted lock-class registry declaration. No userspace-provided flag may stand
/// in for this per-thread tracking. Numeric ranks must increase strictly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockClass {
    pub rank: u16,
    pub no_ipc_wait: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub call: CallId,
    pub caller: ThreadId,
    pub status: Status,
    pub wake_caller: bool,
    pub deliver_reply: bool,
}
/// Fixed wake notifications. The runtime owns actual WaitTickets and performs
/// scheduler wakeups after the complete metadata transition, under serialization.
pub struct Notifications {
    entries: [Option<Completion>; MAX_CALLS],
}
impl Notifications {
    fn new() -> Self {
        Self {
            entries: [None; MAX_CALLS],
        }
    }
    fn push(&mut self, event: Completion) {
        // At most one event is appended for each of the fixed call slots.
        let slot = self.entries.iter_mut().find(|e| e.is_none()).unwrap();
        *slot = Some(event);
    }
    pub fn iter(&self) -> impl Iterator<Item = &Completion> {
        self.entries.iter().flatten()
    }
    pub fn len(&self) -> usize {
        self.iter().count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Thread {
    id: ThreadId,
    job: JobId,
    space: SpaceId,
    incarnation: Option<Token>,
    locks: [Option<LockClass>; MAX_LOCKS],
    alive: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Endpoint {
    object: usize,
    receiver: SpaceId,
    callee: ThreadId,
    policy: Policy,
    dead: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Call {
    context: Context,
    caller: ThreadId,
    callee: ThreadId,
    endpoint: usize,
    outcome: Option<Status>,
}

pub(crate) enum CompleteError<E> {
    Rpc(Error),
    Transport(E),
}

pub struct Rpc {
    epoch: NonZeroU64,
    sequence: u64,
    now: u64,
    threads: [Option<Thread>; MAX_THREADS],
    endpoints: [Option<Endpoint>; MAX_ENDPOINTS],
    calls: [Option<Call>; MAX_CALLS],
}
impl Rpc {
    /// Registered threads/routes and live execution reservations, not grants.
    pub fn metadata_usage(&self) -> (usize, usize, usize) {
        (
            self.threads.iter().flatten().count(),
            self.endpoints.iter().flatten().count(),
            self.calls.iter().flatten().count(),
        )
    }
    pub const fn new(epoch: NonZeroU64) -> Self {
        Self {
            epoch,
            sequence: 0,
            now: 0,
            threads: [None; MAX_THREADS],
            endpoints: [None; MAX_ENDPOINTS],
            calls: [None; MAX_CALLS],
        }
    }
    fn time(&self, now: u64) -> Result<(), Error> {
        if now < self.now {
            Err(Error::ClockReversed)
        } else {
            Ok(())
        }
    }
    fn thread_index(&self, thread: ThreadId) -> Result<usize, Error> {
        self.threads
            .iter()
            .position(|t| t.is_some_and(|t| t.id == thread))
            .ok_or(Error::UnknownThread)
    }
    fn thread(&self, thread: ThreadId) -> Result<Thread, Error> {
        let entry = self.threads[self.thread_index(thread)?].unwrap();
        if entry.alive {
            Ok(entry)
        } else {
            Err(Error::PeerDied)
        }
    }
    fn call_index(&self, id: CallId) -> Result<usize, Error> {
        self.calls
            .iter()
            .position(|c| c.is_some_and(|c| c.context.call_id == id))
            .ok_or(Error::StaleCall)
    }
    fn incoming(&self, thread: ThreadId) -> Option<Call> {
        self.calls
            .iter()
            .flatten()
            .find(|c| c.callee == thread)
            .copied()
    }
    fn outgoing(&self, thread: ThreadId) -> Option<Call> {
        self.calls
            .iter()
            .flatten()
            .find(|c| c.caller == thread && c.outcome.is_none())
            .copied()
    }
    pub fn waiting(&self, thread: ThreadId) -> Option<CallId> {
        self.outgoing(thread).map(|c| c.context.call_id)
    }
    pub fn serving(&self, thread: ThreadId) -> Option<CallId> {
        self.incoming(thread).map(|c| c.context.call_id)
    }
    /// Includes cancelled/timed-out execution reservations, not just waits.
    pub fn outstanding(&self) -> usize {
        self.calls.iter().flatten().count()
    }
    /// Registered thread provenance and retained causal origins pin Job identity
    /// even after a caller is forgotten. This is a lifecycle reference query,
    /// not authorization or permission to reclaim scheduler/physical resources.
    pub fn references_job(&self, job: JobId) -> bool {
        self.threads
            .iter()
            .flatten()
            .any(|thread| thread.job == job)
            || self
                .calls
                .iter()
                .flatten()
                .any(|call| call.context.origin_job == job)
    }

    /// Actual registered domain; knowing this identity grants no authority.
    pub(crate) fn thread_domain(&self, thread: ThreadId) -> Result<SpaceId, Error> {
        Ok(self.thread(thread)?.space)
    }
    /// Kernel object dispatch derives the table from the actual scheduler caller.
    pub(crate) fn checked_thread_domain(
        &self,
        scheduler: &Scheduler,
        thread: ThreadId,
    ) -> Result<SpaceId, Error> {
        let entry = self.thread(thread)?;
        let process = scheduler
            .thread_process(thread)
            .map_err(|_| Error::Identity)?;
        if scheduler
            .process_job(process)
            .map_err(|_| Error::Identity)?
            != entry.job
            || scheduler.state(thread).map_err(|_| Error::Identity)? == State::Exited
        {
            return Err(Error::Identity);
        }
        Ok(entry.space)
    }
    /// Requires the actual death transition already processed by peer_died().
    pub(crate) fn verified_dead(
        &self,
        scheduler: &Scheduler,
        thread: ThreadId,
    ) -> Result<(), Error> {
        let entry = self.threads[self.thread_index(thread)?].unwrap();
        if entry.alive
            || entry.locks.iter().any(Option::is_some)
            || scheduler.state(thread).map_err(|_| Error::Identity)? != State::Exited
        {
            return Err(Error::PeerStillLive);
        }
        Ok(())
    }
    /// Trusted runtime registration, never a syscall taking raw identities.
    /// Validate the actual Scheduler thread→process→Job relation. The runtime
    /// supplies the actual process's Authority domain and current owned root
    /// token; those associations must come from its retained process registry.
    /// Retained scheduler IDs cannot be rebound to a new domain/incarnation.
    pub fn register_thread(
        &mut self,
        authority: &Authority,
        scheduler: &Scheduler,
        thread: ThreadId,
        job: JobId,
        space: SpaceId,
        incarnation: Option<Token>,
    ) -> Result<(), Error> {
        let process = scheduler
            .thread_process(thread)
            .map_err(|_| Error::Identity)?;
        if scheduler
            .process_job(process)
            .map_err(|_| Error::Identity)?
            != job
            || scheduler.state(thread).map_err(|_| Error::Identity)? == State::Exited
            || !authority.is_live_space(space)
        {
            return Err(Error::Identity);
        }
        if self.thread_index(thread).is_ok() {
            return Err(Error::AlreadyRegistered);
        }
        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Overloaded)?;
        self.threads[slot] = Some(Thread {
            id: thread,
            job,
            space,
            incarnation,
            locks: [None; MAX_LOCKS],
            alive: true,
        });
        Ok(())
    }
    /// Trusted object-registry binding to the actual servicing thread. RECEIVE
    /// and CONTROL authorize binding; begin separately resolves the sender's
    /// SEND handle against this exact live object identity. The Authority retains
    /// object identities; changing descriptor reuse requires generation binding.
    pub fn bind_endpoint(
        &mut self,
        authority: &Authority,
        receiver: SpaceId,
        endpoint: Handle,
        callee: ThreadId,
        policy: Policy,
    ) -> Result<(), Error> {
        let object = authority
            .authorize(
                receiver,
                endpoint,
                Kind::Endpoint,
                Rights::RECEIVE | Rights::CONTROL,
            )
            .map_err(|_| Error::PermissionDenied)?
            .identity();
        if self.thread(callee)?.space != receiver {
            return Err(Error::Identity);
        }
        let slot = if let Some(slot) = self
            .endpoints
            .iter()
            .position(|e| e.is_some_and(|e| e.object == object))
        {
            let old = self.endpoints[slot].unwrap();
            if !old.dead || self.calls.iter().flatten().any(|c| c.endpoint == object) {
                return Err(Error::AlreadyBound);
            }
            slot
        } else {
            self.endpoints
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Overloaded)?
        };
        self.endpoints[slot] = Some(Endpoint {
            object,
            receiver,
            callee,
            policy,
            dead: false,
        });
        Ok(())
    }
    /// Trusted lock entry/exit hooks, paired with the real lock implementation.
    /// This module neither holds kernel locks nor performs a blocking wait.
    pub fn enter_lock(&mut self, thread: ThreadId, class: LockClass) -> Result<(), Error> {
        let current = self.thread(thread)?;
        if self.outgoing(thread).is_some() {
            return Err(Error::AlreadyWaiting);
        }
        if current
            .locks
            .iter()
            .flatten()
            .any(|held| held.rank >= class.rank)
        {
            return Err(Error::LockOrder);
        }
        let slot = current
            .locks
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Overloaded)?;
        let index = self.thread_index(thread)?;
        self.threads[index].as_mut().unwrap().locks[slot] = Some(class);
        Ok(())
    }
    pub fn leave_lock(&mut self, thread: ThreadId, rank: u16) -> Result<(), Error> {
        let current = self.thread(thread)?;
        let slot = current
            .locks
            .iter()
            .rposition(Option::is_some)
            .ok_or(Error::LockOrder)?;
        if current.locks[slot].unwrap().rank != rank {
            return Err(Error::LockOrder);
        }
        let index = self.thread_index(thread)?;
        self.threads[index].as_mut().unwrap().locks[slot] = None;
        Ok(())
    }
    fn outcome_error(status: Status) -> Error {
        match status {
            Status::Cancelled => Error::Cancelled,
            Status::DeadlineExceeded => Error::DeadlineExceeded,
            Status::PeerDied => Error::PeerDied,
            Status::Ok => Error::StaleCall,
        }
    }
    fn cycle(&self, caller: ThreadId, callee: ThreadId) -> bool {
        let mut next = callee;
        for _ in 0..=MAX_CALLS {
            if next == caller {
                return true;
            }
            let Some(edge) = self.outgoing(next) else {
                return false;
            };
            next = edge.callee;
        }
        true // Corrupt or cyclic bounded graph: never commit another edge.
    }
    fn descends_from(&self, call: Call, ancestor: CallId) -> bool {
        let mut parent = call.context.parent_call_id;
        for _ in 0..MAX_DEPTH {
            let Some(id) = parent else {
                return false;
            };
            if id == ancestor {
                return true;
            }
            let Ok(index) = self.call_index(id) else {
                return false;
            };
            parent = self.calls[index].unwrap().context.parent_call_id;
        }
        false
    }
    /// Accept one metadata edge only after every fallible validation succeeds.
    /// The dispatcher must already have validated typed payload/capabilities and
    /// serialize transport acceptance and scheduler blocking with this commit.
    /// No transfer, allocation, scheduler mutation or user pointer access occurs
    /// here. Rejection changes neither sequence, clock nor reservation tables.
    pub fn begin(
        &mut self,
        authority: &Authority,
        caller: ThreadId,
        endpoint: Handle,
        deadline: Deadline,
        shape: MessageShape,
        now: u64,
    ) -> Result<CallId, Error> {
        self.time(now)?;
        let subject = self.thread(caller)?;
        if subject.locks.iter().flatten().any(|held| held.no_ipc_wait) {
            return Err(Error::DangerousLock);
        }
        let object = authority
            .authorize(subject.space, endpoint, Kind::Endpoint, Rights::SEND)
            .map_err(|_| Error::PermissionDenied)?
            .identity();
        let route = self
            .endpoints
            .iter()
            .flatten()
            .find(|e| e.object == object)
            .copied()
            .ok_or(Error::UnknownEndpoint)?;
        if route.dead {
            return Err(Error::PeerDied);
        }
        let receiver = self.thread(route.callee)?;
        if receiver.space != route.receiver {
            return Err(Error::Identity);
        }
        if subject.incarnation != receiver.incarnation {
            return Err(Error::IncarnationMismatch);
        }
        let parent = self.incoming(caller);
        if let Some(parent) = parent {
            if let Some(outcome) = parent.outcome {
                return Err(Self::outcome_error(outcome));
            }
            if parent.context.root_incarnation != subject.incarnation {
                return Err(Error::IncarnationMismatch);
            }
            if parent.context.deadline.reached(now) {
                return Err(Error::DeadlineExceeded);
            }
            if parent.context.depth >= MAX_DEPTH {
                return Err(Error::DepthExceeded);
            }
            if deadline.tick() > parent.context.deadline.tick() {
                return Err(Error::DeadlineExtended);
            }
        }
        if deadline.reached(now) {
            return Err(Error::DeadlineExceeded);
        }
        if shape.bytes > route.policy.max_bytes
            || shape.capabilities > route.policy.max_capabilities
        {
            return Err(Error::MalformedMessage);
        }
        if self.outgoing(caller).is_some() {
            return Err(Error::AlreadyWaiting);
        }
        if self.cycle(caller, route.callee) {
            return Err(Error::DeadlockDetected);
        }
        if self.incoming(route.callee).is_some()
            || self.outgoing(route.callee).is_some()
            || self.calls.iter().flatten().any(|c| c.endpoint == object)
        {
            return Err(Error::WouldBlock);
        }
        let slot = self
            .calls
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Overloaded)?;
        let serial = self
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        let id = CallId {
            epoch: self.epoch,
            serial,
        };
        let context = Context {
            trace_id: parent.map_or(TraceId(id), |p| p.context.trace_id),
            call_id: id,
            parent_call_id: parent.map(|p| p.context.call_id),
            origin_job: parent.map_or(subject.job, |p| p.context.origin_job),
            depth: parent.map_or(1, |p| p.context.depth + 1),
            deadline,
            cancellation_token: CancellationToken(id),
            root_incarnation: parent.map_or(subject.incarnation, |p| p.context.root_incarnation),
        };
        self.calls[slot] = Some(Call {
            context,
            caller,
            callee: route.callee,
            endpoint: object,
            outcome: None,
        });
        self.sequence = serial;
        self.now = now;
        Ok(id)
    }
    pub fn context(&self, id: CallId) -> Result<Context, Error> {
        Ok(self.calls[self.call_index(id)?].unwrap().context)
    }
    /// Cooperative callee check. A deadline is cancellation even before the
    /// dispatcher runs expire(); that dispatcher still owns actual wakeups.
    pub fn cancellation(
        &self,
        token: CancellationToken,
        now: u64,
    ) -> Result<Option<Status>, Error> {
        self.time(now)?;
        let call = self.calls[self.call_index(token.0)?].unwrap();
        Ok(call.outcome.or_else(|| {
            call.context
                .deadline
                .reached(now)
                .then_some(Status::DeadlineExceeded)
        }))
    }
    /// Only the actual servicing thread may release its reservation. A late
    /// reply after timeout/cancellation releases that reservation but neither
    /// wakes the old caller again nor delivers a reply to any newer call.
    pub fn complete(
        &mut self,
        callee: ThreadId,
        id: CallId,
        now: u64,
    ) -> Result<Completion, Error> {
        match self.complete_with(callee, id, now, |_| Ok::<(), core::convert::Infallible>(())) {
            Ok((completion, ())) => Ok(completion),
            Err(CompleteError::Rpc(error)) => Err(error),
            Err(CompleteError::Transport(never)) => match never {},
        }
    }
    /// Serialized acceptance transaction. Validate the protected reservation and
    /// outcome first, then let the transport commit the actual owned transfer.
    /// A refusal leaves Rpc unchanged. No fallible work follows acceptance; the
    /// closure cannot reenter this Rpc owner while its mutable borrow is held.
    pub(crate) fn complete_with<T, E>(
        &mut self,
        callee: ThreadId,
        id: CallId,
        now: u64,
        accept: impl FnOnce(Completion) -> Result<T, E>,
    ) -> Result<(Completion, T), CompleteError<E>> {
        self.time(now).map_err(CompleteError::Rpc)?;
        let slot = self.call_index(id).map_err(CompleteError::Rpc)?;
        let call = self.calls[slot].unwrap();
        if call.callee != callee {
            return Err(CompleteError::Rpc(Error::WrongCallee));
        }
        if self.outgoing(callee).is_some() {
            return Err(CompleteError::Rpc(Error::AlreadyWaiting));
        }
        let status = call.outcome.unwrap_or_else(|| {
            if call.context.deadline.reached(now) {
                Status::DeadlineExceeded
            } else {
                Status::Ok
            }
        });
        let completion = Completion {
            call: id,
            caller: call.caller,
            status,
            wake_caller: call.outcome.is_none(),
            deliver_reply: status == Status::Ok,
        };
        let accepted = accept(completion).map_err(CompleteError::Transport)?;
        self.calls[slot] = None;
        self.now = now;
        Ok((completion, accepted))
    }
    fn abandon(
        &mut self,
        affected: [bool; MAX_CALLS],
        status: Status,
        now: u64,
        dead: Option<ThreadId>,
    ) -> Notifications {
        let mut notifications = Notifications::new();
        for (index, affected) in affected.into_iter().enumerate() {
            if !affected {
                continue;
            }
            let Some(call) = self.calls[index].as_mut() else {
                continue;
            };
            if call.outcome.is_some() {
                continue;
            }
            let outcome = if call.context.deadline.reached(now) {
                Status::DeadlineExceeded
            } else {
                status
            };
            call.outcome = Some(outcome);
            if Some(call.caller) != dead {
                notifications.push(Completion {
                    call: call.context.call_id,
                    caller: call.caller,
                    status: outcome,
                    wake_caller: true,
                    deliver_reply: false,
                });
            }
        }
        self.now = now;
        notifications
    }
    /// Cancellation propagates through the protected causal descendants. The
    /// original outcome wins; cancellation cannot resurrect an expired wait.
    pub fn cancel(
        &mut self,
        caller: ThreadId,
        id: CallId,
        now: u64,
    ) -> Result<Notifications, Error> {
        self.time(now)?;
        let call = self.calls[self.call_index(id)?].unwrap();
        if call.caller != caller {
            return Err(Error::WrongCaller);
        }
        let affected = self
            .calls
            .map(|c| c.is_some_and(|c| c.context.call_id == id || self.descends_from(c, id)));
        Ok(self.abandon(affected, Status::Cancelled, now, None))
    }
    pub fn expire(&mut self, now: u64) -> Result<Notifications, Error> {
        self.time(now)?;
        let affected = self
            .calls
            .map(|c| c.is_some_and(|c| c.context.deadline.reached(now)));
        Ok(self.abandon(affected, Status::DeadlineExceeded, now, None))
    }
    /// Trusted retirement notification, never an unverified peer-death claim.
    /// Scheduler must already have retired this actual servicing/calling thread.
    /// Descendant waits are cancelled; other callees retain execution reservations.
    pub fn peer_died(
        &mut self,
        scheduler: &Scheduler,
        peer: ThreadId,
        now: u64,
    ) -> Result<Notifications, Error> {
        self.time(now)?;
        let index = self.thread_index(peer)?;
        if scheduler.state(peer).map_err(|_| Error::Identity)? != State::Exited {
            return Err(Error::PeerStillLive);
        }
        let direct = self.calls.map(|c| {
            c.filter(|c| c.caller == peer || c.callee == peer)
                .map(|c| c.context.call_id)
        });
        let affected = self.calls.map(|c| {
            c.is_some_and(|c| {
                direct
                    .iter()
                    .flatten()
                    .any(|&id| c.context.call_id == id || self.descends_from(c, id))
            })
        });
        let notifications = self.abandon(affected, Status::PeerDied, now, Some(peer));
        for call in &mut self.calls {
            if call.is_some_and(|c| c.callee == peer) {
                *call = None;
            }
        }
        for endpoint in self.endpoints.iter_mut().flatten() {
            if endpoint.callee == peer {
                endpoint.dead = true;
            }
        }
        let thread = self.threads[index].as_mut().unwrap();
        thread.alive = false;
        thread.locks = [None; MAX_LOCKS];
        Ok(notifications)
    }
    /// Trusted metadata cleanup after peer_died verified this exact scheduler
    /// identity's retirement. The runtime must forget it before reclaiming the
    /// scheduler descriptor. Cancelled/expired calls still pin every referenced
    /// caller/callee until actual acknowledgement or verified callee death.
    /// Read-only parent CallIds may remain in deeper cancelled diagnostics after
    /// direct references disappear; they are never reused. references_job still
    /// protects any origin Job named by that retained causal execution.
    ///
    /// Removes only this dead thread and its dead, unreferenced endpoint routes.
    /// Epoch, call serial, clock and unrelated causal/endpoint state persist;
    /// registration of a fresh scheduler generation can never reuse a CallId.
    pub fn forget_thread(&mut self, scheduler: &Scheduler, peer: ThreadId) -> Result<(), Error> {
        let index = self.thread_index(peer)?;
        if self.threads[index].unwrap().alive {
            return Err(Error::PeerStillLive);
        }
        if scheduler.state(peer).map_err(|_| Error::Identity)? != State::Exited {
            return Err(Error::PeerStillLive);
        }
        if self
            .calls
            .iter()
            .flatten()
            .any(|c| c.caller == peer || c.callee == peer)
        {
            return Err(Error::WouldBlock);
        }
        for endpoint in self.endpoints.iter().flatten().filter(|e| e.callee == peer) {
            if !endpoint.dead {
                return Err(Error::PeerStillLive);
            }
            if self
                .calls
                .iter()
                .flatten()
                .any(|c| c.endpoint == endpoint.object)
            {
                return Err(Error::WouldBlock);
            }
        }
        // All rejection checks precede mutation. In particular an old identity
        // cannot delete a replacement's route, even when its object is stable.
        for endpoint in &mut self.endpoints {
            if endpoint.is_some_and(|e| e.callee == peer) {
                *endpoint = None;
            }
        }
        self.threads[index] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        authority: Authority,
        scheduler: Scheduler,
        rpc: Rpc,
        threads: [ThreadId; 10],
        endpoints: [Handle; 8],
        job: JobId,
        space: SpaceId,
    }
    fn fixture() -> Fixture {
        fixture_routes(false)
    }
    fn fixture_routes(callback_to_origin: bool) -> Fixture {
        let mut authority = Authority::new();
        let space = authority.create_space().unwrap();
        let denied_space = authority.create_space().unwrap();
        let mut scheduler = Scheduler::new();
        let job = scheduler.create_job().unwrap();
        let process = scheduler.create_process(job).unwrap();
        let threads = core::array::from_fn(|_| scheduler.create_thread(process).unwrap());
        let endpoints = core::array::from_fn(|_| {
            authority
                .create_root(
                    space,
                    Kind::Endpoint,
                    Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
                )
                .unwrap()
        });
        let mut rpc = Rpc::new(NonZeroU64::new(17).unwrap());
        for (i, &thread) in threads.iter().enumerate() {
            rpc.register_thread(
                &authority,
                &scheduler,
                thread,
                job,
                if i == 9 { denied_space } else { space },
                None,
            )
            .unwrap();
        }
        for (i, &endpoint) in endpoints.iter().enumerate() {
            let callee = if callback_to_origin && i == 7 {
                threads[0]
            } else {
                threads[i + 1]
            };
            rpc.bind_endpoint(
                &authority,
                space,
                endpoint,
                callee,
                Policy::new(8, 0).unwrap(),
            )
            .unwrap();
        }
        Fixture {
            authority,
            scheduler,
            rpc,
            threads,
            endpoints,
            job,
            space,
        }
    }
    fn deadline(tick: u64) -> Deadline {
        Deadline::after(0, tick).unwrap()
    }
    fn dispatch_to(scheduler: &mut Scheduler, target: ThreadId) {
        for _ in 0..MAX_THREADS {
            let dispatch = scheduler.dispatch(0).unwrap().unwrap();
            if dispatch.thread == target {
                return;
            }
            scheduler.yield_cpu(0).unwrap();
        }
        panic!("expected ready test thread was not dispatched");
    }
    #[test]
    fn forgetting_requires_verified_death_and_leaves_unrelated_state_unchanged() {
        let mut f = fixture();
        let peer = f.threads[1];
        let before = (
            f.rpc.threads,
            f.rpc.endpoints,
            f.rpc.calls,
            f.rpc.sequence,
            f.rpc.now,
        );
        assert_eq!(
            f.rpc.forget_thread(&f.scheduler, peer),
            Err(Error::PeerStillLive)
        );
        assert_eq!(
            (
                f.rpc.threads,
                f.rpc.endpoints,
                f.rpc.calls,
                f.rpc.sequence,
                f.rpc.now
            ),
            before
        );
        dispatch_to(&mut f.scheduler, peer);
        f.scheduler.exit(0).unwrap();
        // Scheduler retirement alone is not a peer_died acknowledgement.
        assert_eq!(
            f.rpc.forget_thread(&f.scheduler, peer),
            Err(Error::PeerStillLive)
        );
        f.rpc.peer_died(&f.scheduler, peer, 3).unwrap();
        let survivor = f.rpc.thread(f.threads[2]).unwrap();
        let route = f
            .rpc
            .endpoints
            .iter()
            .flatten()
            .find(|e| e.callee == f.threads[2])
            .copied();
        let counters = (f.rpc.epoch, f.rpc.sequence, f.rpc.now);
        f.rpc.forget_thread(&f.scheduler, peer).unwrap();
        assert_eq!(f.rpc.thread(peer), Err(Error::UnknownThread));
        assert_eq!(
            f.rpc.forget_thread(&f.scheduler, peer),
            Err(Error::UnknownThread)
        );
        assert_eq!(f.rpc.thread(f.threads[2]), Ok(survivor));
        assert_eq!(
            f.rpc
                .endpoints
                .iter()
                .flatten()
                .find(|e| e.callee == f.threads[2])
                .copied(),
            route
        );
        assert_eq!((f.rpc.epoch, f.rpc.sequence, f.rpc.now), counters);
    }
    #[test]
    fn cancelled_or_expired_outgoing_execution_pins_a_dead_caller_until_actual_ack() {
        for timed_out in [false, true] {
            let mut f = fixture();
            let ab = begin(&mut f, 0, 0, 30, 1).unwrap();
            let bc = begin(&mut f, 1, 1, if timed_out { 3 } else { 20 }, 2).unwrap();
            let independent = begin(&mut f, 4, 4, 30, 2).unwrap();
            if timed_out {
                f.rpc.expire(3).unwrap();
            } else {
                f.rpc.cancel(f.threads[1], bc, 3).unwrap();
            }
            dispatch_to(&mut f.scheduler, f.threads[1]);
            f.scheduler.exit(0).unwrap();
            f.rpc.peer_died(&f.scheduler, f.threads[1], 4).unwrap();
            assert_eq!(f.rpc.context(ab), Err(Error::StaleCall));
            assert_eq!(f.rpc.context(bc).unwrap().parent_call_id, Some(ab));
            let before = (
                f.rpc.threads,
                f.rpc.endpoints,
                f.rpc.calls,
                f.rpc.sequence,
                f.rpc.now,
            );
            assert_eq!(
                f.rpc.forget_thread(&f.scheduler, f.threads[1]),
                Err(Error::WouldBlock)
            );
            assert_eq!(
                (
                    f.rpc.threads,
                    f.rpc.endpoints,
                    f.rpc.calls,
                    f.rpc.sequence,
                    f.rpc.now
                ),
                before
            );
            assert_eq!(f.rpc.complete(f.threads[3], bc, 4), Err(Error::WrongCallee));
            let completion = f.rpc.complete(f.threads[2], bc, 5).unwrap();
            assert_eq!(
                completion.status,
                if timed_out {
                    Status::DeadlineExceeded
                } else {
                    Status::Cancelled
                }
            );
            assert!(!completion.wake_caller && !completion.deliver_reply);
            let independent_context = f.rpc.context(independent).unwrap();
            let counters = (f.rpc.epoch, f.rpc.sequence, f.rpc.now);
            f.rpc.forget_thread(&f.scheduler, f.threads[1]).unwrap();
            assert_eq!(f.rpc.context(independent), Ok(independent_context));
            assert_eq!((f.rpc.epoch, f.rpc.sequence, f.rpc.now), counters);
            assert!(
                f.rpc
                    .complete(f.threads[5], independent, 6)
                    .unwrap()
                    .deliver_reply
            );
        }
    }
    #[test]
    fn sustained_service_recycle_preserves_live_peers_provenance_clock_and_unique_calls() {
        use crate::scheduler::{Limits, Resource};
        let mut authority = Authority::new();
        let space = authority.create_space().unwrap();
        let service_endpoint = authority
            .create_root(
                space,
                Kind::Endpoint,
                Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let peer_endpoint = authority
            .create_root(
                space,
                Kind::Endpoint,
                Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let mut scheduler = Scheduler::new();
        let root = scheduler.create_job().unwrap();
        let caller_job = scheduler.create_child_job(root, Limits::UNLIMITED).unwrap();
        let caller_process = scheduler.create_process(caller_job).unwrap();
        let caller = scheduler.create_thread(caller_process).unwrap();
        let peer_job = scheduler.create_child_job(root, Limits::UNLIMITED).unwrap();
        let peer_process = scheduler.create_process(peer_job).unwrap();
        let peer_caller = scheduler.create_thread(peer_process).unwrap();
        let peer_callee = scheduler.create_thread(peer_process).unwrap();
        let mut rpc = Rpc::new(NonZeroU64::new(29).unwrap());
        for (thread, job) in [
            (caller, caller_job),
            (peer_caller, peer_job),
            (peer_callee, peer_job),
        ] {
            rpc.register_thread(&authority, &scheduler, thread, job, space, None)
                .unwrap();
        }
        rpc.bind_endpoint(
            &authority,
            space,
            peer_endpoint,
            peer_callee,
            Policy::new(8, 0).unwrap(),
        )
        .unwrap();
        let shape = MessageShape {
            bytes: 8,
            capabilities: 0,
        };
        dispatch_to(&mut scheduler, peer_caller);
        let independent = rpc
            .begin(
                &authority,
                peer_caller,
                peer_endpoint,
                deadline(10_000),
                shape,
                0,
            )
            .unwrap();
        let peer_wait = scheduler.block(0, deadline(10_000)).unwrap();
        let independent_context = rpc.context(independent).unwrap();
        assert_eq!(independent_context.origin_job, peer_job);
        let mut previous = None;
        for cycle in 0..128u64 {
            let now = cycle * 10 + 1;
            scheduler.advance(now).unwrap();
            let job = scheduler
                .create_child_job(root, Limits::new(2, 1, 1, 1))
                .unwrap();
            let process = scheduler.create_process(job).unwrap();
            let service = scheduler.create_thread(process).unwrap();
            assert_eq!(
                rpc.register_thread(&authority, &scheduler, service, caller_job, space, None),
                Err(Error::Identity)
            );
            rpc.register_thread(&authority, &scheduler, service, job, space, None)
                .unwrap();
            rpc.bind_endpoint(
                &authority,
                space,
                service_endpoint,
                service,
                Policy::new(8, 0).unwrap(),
            )
            .unwrap();
            dispatch_to(&mut scheduler, caller);
            let call = rpc
                .begin(
                    &authority,
                    caller,
                    service_endpoint,
                    deadline(now + 8),
                    shape,
                    now,
                )
                .unwrap();
            let wait = scheduler.block(0, deadline(now + 8)).unwrap();
            assert_eq!(rpc.context(call).unwrap().origin_job, caller_job);
            assert_eq!(
                (call.epoch(), call.serial()),
                (NonZeroU64::new(29).unwrap(), cycle + 2)
            );
            if let Some((old_thread, old_call, old_wait)) = previous {
                assert_ne!(service, old_thread);
                assert_eq!(rpc.complete(old_thread, call, now), Err(Error::WrongCallee));
                assert_eq!(rpc.complete(service, old_call, now), Err(Error::StaleCall));
                assert_eq!(
                    rpc.cancel(caller, old_call, now).err(),
                    Some(Error::StaleCall)
                );
                assert_eq!(
                    rpc.forget_thread(&scheduler, old_thread),
                    Err(Error::UnknownThread)
                );
                assert_eq!(
                    rpc.begin(
                        &authority,
                        old_thread,
                        service_endpoint,
                        deadline(now + 8),
                        shape,
                        now
                    ),
                    Err(Error::UnknownThread)
                );
                assert!(!scheduler.wake(old_wait));
                assert!(scheduler.waiting(wait));
                assert_eq!(rpc.waiting(caller), Some(call));
            }
            dispatch_to(&mut scheduler, service);
            scheduler.advance(now + 1).unwrap();
            let completion = rpc.complete(service, call, now + 1).unwrap();
            assert!(completion.wake_caller && completion.deliver_reply);
            assert!(scheduler.wake(wait));
            scheduler.charge_cpu(0, 1).unwrap();
            scheduler.exit(0).unwrap();
            scheduler.terminate_process(process).unwrap();
            assert!(
                rpc.peer_died(&scheduler, service, now + 2)
                    .unwrap()
                    .is_empty()
            );
            let counters = (rpc.epoch, rpc.sequence, rpc.now);
            rpc.forget_thread(&scheduler, service).unwrap();
            assert_eq!((rpc.epoch, rpc.sequence, rpc.now), counters);
            assert!(!rpc.references_job(job));
            assert!(rpc.references_job(caller_job) && rpc.references_job(peer_job));
            assert_eq!(scheduler.reclaim_process(process), Ok(1));
            scheduler.reclaim_job(job).unwrap();
            assert_eq!(rpc.context(independent), Ok(independent_context));
            assert!(scheduler.waiting(peer_wait));
            assert_eq!(rpc.outstanding(), 1);
            assert_eq!(scheduler.usage(root, Resource::CpuTicks), Ok(cycle + 1));
            assert_eq!(rpc.expire(now + 1).err(), Some(Error::ClockReversed));
            previous = Some((service, call, wait));
        }
        assert_eq!(rpc.sequence, 129);
        assert_eq!(rpc.now, 1273);
        assert_eq!(rpc.threads.iter().flatten().count(), 3);
        assert_eq!(rpc.endpoints.iter().flatten().count(), 1);
        assert!(
            rpc.complete(peer_callee, independent, 1274)
                .unwrap()
                .deliver_reply
        );
        assert!(scheduler.wake(peer_wait));
        assert_eq!(rpc.outstanding(), 0);
    }
    #[test]
    fn retained_causal_origin_pins_its_job_after_direct_thread_references_are_gone() {
        let mut authority = Authority::new();
        let space = authority.create_space().unwrap();
        let mut scheduler = Scheduler::new();
        let jobs = core::array::from_fn::<_, 4, _>(|_| scheduler.create_job().unwrap());
        let processes = jobs.map(|job| scheduler.create_process(job).unwrap());
        let threads = processes.map(|process| scheduler.create_thread(process).unwrap());
        let endpoints = core::array::from_fn::<_, 3, _>(|_| {
            authority
                .create_root(
                    space,
                    Kind::Endpoint,
                    Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
                )
                .unwrap()
        });
        let mut rpc = Rpc::new(NonZeroU64::new(31).unwrap());
        for (thread, job) in threads.into_iter().zip(jobs) {
            rpc.register_thread(&authority, &scheduler, thread, job, space, None)
                .unwrap();
        }
        for (endpoint, callee) in endpoints.into_iter().zip(threads[1..].iter().copied()) {
            rpc.bind_endpoint(
                &authority,
                space,
                endpoint,
                callee,
                Policy::new(8, 0).unwrap(),
            )
            .unwrap();
        }
        let shape = MessageShape {
            bytes: 8,
            capabilities: 0,
        };
        let ab = rpc
            .begin(&authority, threads[0], endpoints[0], deadline(30), shape, 1)
            .unwrap();
        let bc = rpc
            .begin(&authority, threads[1], endpoints[1], deadline(30), shape, 2)
            .unwrap();
        let cd = rpc
            .begin(&authority, threads[2], endpoints[2], deadline(30), shape, 3)
            .unwrap();
        dispatch_to(&mut scheduler, threads[0]);
        scheduler.exit(0).unwrap();
        scheduler.terminate_process(processes[0]).unwrap();
        rpc.peer_died(&scheduler, threads[0], 4).unwrap();
        assert_eq!(
            rpc.forget_thread(&scheduler, threads[0]),
            Err(Error::WouldBlock)
        );
        assert!(!rpc.complete(threads[1], ab, 5).unwrap().deliver_reply);
        rpc.forget_thread(&scheduler, threads[0]).unwrap();
        assert_eq!(rpc.thread(threads[0]), Err(Error::UnknownThread));
        assert_eq!(rpc.context(ab), Err(Error::StaleCall));
        assert_eq!(rpc.context(bc).unwrap().parent_call_id, Some(ab));
        assert_eq!(rpc.context(cd).unwrap().origin_job, jobs[0]);
        // Remaining provenance is a copied generation-safe Job identity; no
        // registered thread belongs to it now, but actual descendant work pins it.
        assert!(
            !rpc.threads
                .iter()
                .flatten()
                .any(|thread| thread.job == jobs[0])
        );
        assert!(rpc.references_job(jobs[0]));
        assert!(!rpc.complete(threads[2], bc, 6).unwrap().deliver_reply);
        assert!(rpc.references_job(jobs[0]));
        assert!(!rpc.complete(threads[3], cd, 7).unwrap().deliver_reply);
        assert!(!rpc.references_job(jobs[0]));
        assert!(rpc.references_job(jobs[1]));
        assert_eq!(scheduler.reclaim_process(processes[0]), Ok(1));
        scheduler.reclaim_job(jobs[0]).unwrap();
        let replacement = scheduler.create_job().unwrap();
        assert_ne!(replacement, jobs[0]);
        assert!(!rpc.references_job(replacement));
        assert_eq!((rpc.epoch.get(), rpc.sequence, rpc.now), (31, 3, 7));
    }
    fn begin(
        f: &mut Fixture,
        caller: usize,
        endpoint: usize,
        tick: u64,
        now: u64,
    ) -> Result<CallId, Error> {
        f.rpc.begin(
            &f.authority,
            f.threads[caller],
            f.endpoints[endpoint],
            deadline(tick),
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        )
    }
    #[test]
    fn no_ipc_wait_lock_and_rank_violations_reject_before_acceptance() {
        let mut f = fixture();
        f.rpc
            .enter_lock(
                f.threads[0],
                LockClass {
                    rank: 10,
                    no_ipc_wait: true,
                },
            )
            .unwrap();
        let calls = f.rpc.calls;
        assert_eq!(begin(&mut f, 0, 0, 10, 1), Err(Error::DangerousLock));
        assert_eq!(f.rpc.calls, calls);
        assert_eq!((f.rpc.sequence, f.rpc.now), (0, 0));
        assert_eq!(
            f.rpc.enter_lock(
                f.threads[0],
                LockClass {
                    rank: 10,
                    no_ipc_wait: false
                }
            ),
            Err(Error::LockOrder)
        );
        f.rpc
            .enter_lock(
                f.threads[0],
                LockClass {
                    rank: 20,
                    no_ipc_wait: false,
                },
            )
            .unwrap();
        assert_eq!(f.rpc.leave_lock(f.threads[0], 10), Err(Error::LockOrder));
        f.rpc.leave_lock(f.threads[0], 20).unwrap();
        f.rpc.leave_lock(f.threads[0], 10).unwrap();
        assert!(begin(&mut f, 0, 0, 10, 1).is_ok());
    }
    #[test]
    fn forward_chain_preserves_protected_origin_trace_and_parent() {
        let mut f = fixture();
        let ab = begin(&mut f, 0, 0, 20, 1).unwrap();
        let bc = begin(&mut f, 1, 1, 19, 2).unwrap();
        let a = f.rpc.context(ab).unwrap();
        let b = f.rpc.context(bc).unwrap();
        assert_eq!((a.depth, b.depth), (1, 2));
        assert_eq!(a.parent_call_id, None);
        assert_eq!(b.parent_call_id, Some(ab));
        assert_eq!(a.trace_id, b.trace_id);
        assert_eq!(a.trace_id.root(), ab);
        assert_eq!((a.origin_job, b.origin_job), (f.job, f.job));
        assert_eq!(a.root_incarnation, b.root_incarnation);
        assert_eq!(f.rpc.waiting(f.threads[0]), Some(ab));
        assert_eq!(f.rpc.waiting(f.threads[1]), Some(bc));
        assert_eq!(
            f.rpc.complete(f.threads[1], ab, 3),
            Err(Error::AlreadyWaiting)
        );
        let reply = f.rpc.complete(f.threads[2], bc, 3).unwrap();
        assert!(reply.wake_caller && reply.deliver_reply);
        assert_eq!(reply.status, Status::Ok);
        assert!(f.rpc.complete(f.threads[1], ab, 4).unwrap().deliver_reply);
        assert_eq!(f.rpc.outstanding(), 0);
    }
    #[test]
    fn ancestor_callback_and_second_wait_are_rejected_without_side_effects() {
        let mut f = fixture_routes(true);
        let ab = begin(&mut f, 0, 0, 20, 1).unwrap();
        begin(&mut f, 1, 1, 20, 2).unwrap();
        let before = f.rpc.calls;
        assert_eq!(begin(&mut f, 2, 7, 20, 3), Err(Error::DeadlockDetected));
        assert_eq!(begin(&mut f, 0, 2, 20, 3), Err(Error::AlreadyWaiting));
        assert_eq!(f.rpc.calls, before);
        assert_eq!((f.rpc.sequence, f.rpc.now), (2, 2));
        assert_eq!(f.rpc.context(ab).unwrap().depth, 1);
    }
    #[test]
    fn depth_nine_and_extended_descendant_deadlines_fail_before_commit() {
        let mut f = fixture();
        begin(&mut f, 0, 0, 30, 1).unwrap();
        assert_eq!(begin(&mut f, 1, 1, 31, 2), Err(Error::DeadlineExtended));
        assert_eq!(f.rpc.outstanding(), 1);
        for n in 1..8 {
            begin(&mut f, n, n, 30, 2).unwrap();
        }
        assert_eq!(f.rpc.outstanding(), 8);
        let before = f.rpc.calls;
        assert_eq!(begin(&mut f, 8, 0, 30, 3), Err(Error::DepthExceeded));
        assert_eq!(f.rpc.calls, before);
        assert_eq!(f.rpc.sequence, 8);
    }
    #[test]
    fn endpoint_backpressure_and_shapes_never_grow_accepted_metadata() {
        let mut f = fixture();
        assert_eq!(Policy::new(0, 0), None);
        assert_eq!(Policy::new(MAX_BYTES + 1, 0), None);
        assert_eq!(Policy::new(8, MAX_CAPABILITIES + 1), None);
        assert_eq!(Policy::new(8, 0).unwrap().max_messages(), 1);
        for shape in [
            MessageShape {
                bytes: usize::MAX,
                capabilities: 0,
            },
            MessageShape {
                bytes: 8,
                capabilities: 1,
            },
        ] {
            assert_eq!(
                f.rpc.begin(
                    &f.authority,
                    f.threads[0],
                    f.endpoints[0],
                    deadline(10),
                    shape,
                    0
                ),
                Err(Error::MalformedMessage)
            );
            assert_eq!(f.rpc.sequence, 0);
        }
        begin(&mut f, 0, 0, 10, 0).unwrap();
        for _ in 0..128 {
            assert_eq!(begin(&mut f, 3, 0, 10, 0), Err(Error::WouldBlock));
            assert_eq!(f.rpc.outstanding(), 1);
        }
        assert_eq!(begin(&mut f, 9, 1, 10, 0), Err(Error::PermissionDenied));
        assert_eq!(f.rpc.outstanding(), 1);
    }
    #[test]
    fn timeout_retains_callee_until_late_ack_and_never_aliases_a_retry() {
        let mut f = fixture();
        let old = begin(&mut f, 0, 0, 5, 1).unwrap();
        let token = f.rpc.context(old).unwrap().cancellation_token;
        assert_eq!(
            f.rpc.cancellation(token, 5),
            Ok(Some(Status::DeadlineExceeded))
        );
        let events = f.rpc.expire(5).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events.iter().next().unwrap().status,
            Status::DeadlineExceeded
        );
        assert_eq!(f.rpc.waiting(f.threads[0]), None);
        assert_eq!(f.rpc.serving(f.threads[1]), Some(old));
        assert_eq!(begin(&mut f, 0, 0, 20, 5), Err(Error::WouldBlock));
        assert!(f.rpc.expire(5).unwrap().is_empty());
        let late = f.rpc.complete(f.threads[1], old, 6).unwrap();
        assert_eq!(late.status, Status::DeadlineExceeded);
        assert!(!late.wake_caller && !late.deliver_reply);
        let new = begin(&mut f, 0, 0, 20, 6).unwrap();
        assert_ne!(new, old);
        assert_eq!(f.rpc.complete(f.threads[1], old, 7), Err(Error::StaleCall));
        assert_eq!(f.rpc.serving(f.threads[1]), Some(new));
        assert!(f.rpc.complete(f.threads[1], new, 7).unwrap().deliver_reply);
    }
    #[test]
    fn cancellation_cascades_without_freeing_live_execution_reservations() {
        let mut f = fixture();
        let ab = begin(&mut f, 0, 0, 20, 1).unwrap();
        let bc = begin(&mut f, 1, 1, 19, 2).unwrap();
        assert_eq!(
            f.rpc.cancel(f.threads[2], ab, 3).err(),
            Some(Error::WrongCaller)
        );
        assert_eq!(f.rpc.cancel(f.threads[0], ab, 3).unwrap().len(), 2);
        assert_eq!(f.rpc.waiting(f.threads[0]), None);
        assert_eq!(f.rpc.waiting(f.threads[1]), None);
        assert_eq!(f.rpc.outstanding(), 2);
        assert_eq!(begin(&mut f, 1, 2, 19, 3), Err(Error::Cancelled));
        assert!(f.rpc.cancel(f.threads[0], ab, 3).unwrap().is_empty());
        assert!(!f.rpc.complete(f.threads[2], bc, 4).unwrap().deliver_reply);
        assert!(!f.rpc.complete(f.threads[1], ab, 4).unwrap().deliver_reply);
        assert_eq!(f.rpc.outstanding(), 0);
    }
    #[test]
    fn peer_death_requires_actual_retirement_and_preserves_unrelated_calls() {
        let mut f = fixture();
        let ab = begin(&mut f, 0, 0, 20, 1).unwrap();
        let bc = begin(&mut f, 1, 1, 19, 2).unwrap();
        let independent = begin(&mut f, 4, 4, 20, 2).unwrap();
        assert_eq!(
            f.rpc.peer_died(&f.scheduler, f.threads[1], 3).err(),
            Some(Error::PeerStillLive)
        );
        // Fixture threads share a process, but only the selected thread exits.
        loop {
            let dispatch = f.scheduler.dispatch(0).unwrap().unwrap();
            if dispatch.thread == f.threads[1] {
                f.scheduler.exit(0).unwrap();
                break;
            }
            f.scheduler.yield_cpu(0).unwrap();
        }
        let events = f.rpc.peer_died(&f.scheduler, f.threads[1], 3).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events.iter().next().unwrap().call, ab);
        assert_eq!(events.iter().next().unwrap().status, Status::PeerDied);
        assert_eq!(f.rpc.context(ab), Err(Error::StaleCall));
        assert_eq!(f.rpc.context(bc).unwrap().parent_call_id, Some(ab));
        assert_eq!(
            f.rpc
                .cancellation(f.rpc.context(bc).unwrap().cancellation_token, 3),
            Ok(Some(Status::PeerDied))
        );
        assert_eq!(begin(&mut f, 0, 0, 20, 3), Err(Error::PeerDied));
        assert!(!f.rpc.complete(f.threads[2], bc, 4).unwrap().deliver_reply);
        assert!(
            f.rpc
                .complete(f.threads[5], independent, 4)
                .unwrap()
                .deliver_reply
        );
    }
    #[test]
    fn identities_clocks_and_exhausted_sequences_cannot_mutate_pending_calls() {
        let mut f = fixture();
        let other_job = f.scheduler.create_job().unwrap();
        let other_process = f.scheduler.create_process(other_job).unwrap();
        let extra = f.scheduler.create_thread(other_process).unwrap();
        assert_eq!(
            f.rpc
                .register_thread(&f.authority, &f.scheduler, extra, f.job, f.space, None),
            Err(Error::Identity)
        );
        f.rpc
            .register_thread(&f.authority, &f.scheduler, extra, other_job, f.space, None)
            .unwrap();
        let id = begin(&mut f, 0, 0, 10, 2).unwrap();
        let before = f.rpc.calls;
        assert_eq!(f.rpc.complete(f.threads[2], id, 2), Err(Error::WrongCallee));
        assert_eq!(
            f.rpc.complete(f.threads[1], id, 1),
            Err(Error::ClockReversed)
        );
        assert_eq!(f.rpc.calls, before);
        assert_eq!(
            f.rpc.context(CallId {
                epoch: NonZeroU64::new(18).unwrap(),
                serial: id.serial
            }),
            Err(Error::StaleCall)
        );
        f.rpc.complete(f.threads[1], id, 3).unwrap();
        f.rpc.sequence = u64::MAX;
        assert_eq!(begin(&mut f, 0, 0, 10, 4), Err(Error::SequenceExhausted));
        assert_eq!(f.rpc.outstanding(), 0);
        assert_eq!(f.rpc.now, 3);
        assert_eq!(f.rpc.sequence, u64::MAX);
    }
    fn invariants(rpc: &Rpc) {
        assert!(rpc.outstanding() <= MAX_CALLS);
        for (i, a) in rpc
            .calls
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.map(|c| (i, c)))
        {
            assert!((1..=MAX_DEPTH).contains(&a.context.depth));
            assert_eq!(a.context.call_id.epoch, rpc.epoch);
            assert!(a.context.call_id.serial <= rpc.sequence && a.context.call_id.serial > 0);
            for b in rpc.calls[i + 1..].iter().flatten() {
                assert_ne!(a.context.call_id, b.context.call_id);
                assert_ne!(a.endpoint, b.endpoint);
                assert_ne!(a.callee, b.callee);
                assert!(a.caller != b.caller || a.outcome.is_some() || b.outcome.is_some());
            }
            if let Some(parent) = a.context.parent_call_id {
                if let Ok(index) = rpc.call_index(parent) {
                    let b = rpc.calls[index].unwrap();
                    assert_eq!(a.context.trace_id, b.context.trace_id);
                    assert_eq!(a.context.origin_job, b.context.origin_job);
                    assert_eq!(a.context.root_incarnation, b.context.root_incarnation);
                    assert_eq!(a.context.depth, b.context.depth + 1);
                    assert!(a.context.deadline.tick() <= b.context.deadline.tick());
                } else {
                    assert!(a.outcome.is_some());
                }
            }
        }
    }
    #[test]
    fn bounded_arbitrary_operation_sequences_preserve_graph_and_reservations() {
        let mut seed = 0x91f2_0875_0bb0_a43du64;
        for _ in 0..64 {
            let mut f = fixture();
            let mut tickets = [None; 32];
            let mut now = 0;
            for step in 0..128 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let caller = ((seed >> 8) % 10) as usize;
                let endpoint = ((seed >> 16) % 8) as usize;
                let slot = ((seed >> 24) % 32) as usize;
                now += (seed >> 40) & 1;
                match (seed >> 48) % 5 {
                    0 | 1 => {
                        if let Ok(id) = begin(&mut f, caller, endpoint, now + 1 + (seed & 7), now) {
                            tickets[step % 32] = Some(id);
                        }
                    }
                    2 => {
                        if let Some(id) = tickets[slot] {
                            let _ = f.rpc.complete(f.threads[caller], id, now);
                        }
                    }
                    3 => {
                        if let Some(id) = tickets[slot] {
                            let _ = f.rpc.cancel(f.threads[caller], id, now);
                        }
                    }
                    _ => {
                        f.rpc.expire(now).unwrap();
                    }
                }
                invariants(&f.rpc);
            }
        }
    }
    #[test]
    fn repeated_completed_calls_reuse_slots_without_reusing_identity() {
        let mut f = fixture();
        let mut previous = None;
        for now in 1..513 {
            let id = begin(&mut f, 0, 0, now + 1, now).unwrap();
            if let Some(old) = previous {
                assert_ne!(id, old);
                assert_eq!(
                    f.rpc.complete(f.threads[1], old, now),
                    Err(Error::StaleCall)
                );
            }
            assert!(f.rpc.complete(f.threads[1], id, now).unwrap().deliver_reply);
            previous = Some(id);
        }
        assert_eq!(f.rpc.sequence, 512);
        assert_eq!(f.rpc.outstanding(), 0);
    }
}
