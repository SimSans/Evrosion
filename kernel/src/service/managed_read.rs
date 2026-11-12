//! Native3 actual managed selected-READ handoff. No policy/owner/resource metadata is
//! parsed here. All context fields come from the actual retained Kernel world.
use crate::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    incarnation::Token,
    ipc::{Error as IpcError, Ticket},
    live_grant::{self, SelectedReadRoute},
    scheduler::{Scheduler, State, ThreadId},
    service::{self, ActiveGrantBranch, Metadata, Registry},
    time::Deadline,
};
pub const OPCODE: u64 = ev_userspace_contract::syscall::ENQUEUE_MANAGED_READ;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    SelectionOnly,
    ManagedNative3,
}
/// Trusted actual wire readback; never populated from a userspace packet.
#[derive(Clone, Copy)]
pub struct Wire {
    pub object: usize,
    pub receiver: SpaceId,
    pub bound: Option<ThreadId>,
    pub closed: bool,
}
pub struct Context {
    pub mode: Mode,
    pub caller: Metadata,
    pub root: Metadata,
    pub token: Token,
    pub app: Metadata,
    pub file: Metadata,
    pub read_sources: [Wire; 2],
    pub inbox: Wire,
    pub selection_submitted: bool,
}
/// Direct references to existing common runtime fields, not a second nonce DB.
pub struct Open<'a> {
    pub last_nonce: &'a mut u32,
    pub awaiting: &'a mut Option<Metadata>,
    pub active: &'a mut Option<(Metadata, u32)>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub process: Handle,
    pub source: Handle,
    pub inbox: Handle,
    pub nonce: u32,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Denied,
    Busy,
    Authority(crate::capability::Error),
    Service(service::Error),
    Route(live_grant::Error),
}
#[must_use = "retain the actual private branch until read promotion or stopped cleanup"]
pub struct Queued {
    pub branch: ActiveGrantBranch,
    pub ticket: Ticket,
    pub source_object: usize,
    pub nonce: u32,
}
fn alive(a: &Authority, s: &Scheduler, m: Metadata) -> bool {
    a.is_live_space(m.domain)
        && s.thread_process(m.thread) == Ok(m.process)
        && s.process_job(m.process) == Ok(m.job)
        && !matches!(s.state(m.thread), Ok(State::Exited) | Err(_))
}
/// Context and mutable owners remain exclusively borrowed through acceptance.
/// Refusal precedes authority/ticket/nonce mutation. A successful call creates
/// fresh lineage and consumes only this actual authenticated pending Open.
#[allow(clippy::too_many_arguments)]
pub fn enqueue(
    a: &mut Authority,
    s: &Scheduler,
    r: &Registry<'_>,
    context: &Context,
    open: Open<'_>,
    pending: Option<&ActiveGrantBranch>,
    route: &mut SelectedReadRoute,
    request: Request,
    deadline: Deadline,
    now: u64,
) -> Result<Queued, Error> {
    let c = context;
    let fresh =
        *open.awaiting == Some(c.app) && open.active.is_none() && request.nonce > *open.last_nonce;
    let current_unselected = open.awaiting.is_none()
        && *open.active == Some((c.app, request.nonce))
        && request.nonce == *open.last_nonce;
    if c.mode != Mode::ManagedNative3
        || c.caller != c.root
        || c.token.process() != c.root.process
        || c.token.job() != c.root.job
        || !alive(a, s, c.root)
        || s.state(c.root.thread) != Ok(State::Running(0))
        || c.selection_submitted
        || !(fresh || current_unselected)
        || request.nonce == 0
        || request.nonce == u32::MAX
    {
        return Err(Error::Denied);
    }
    if r.active_metadata(a, s, c.root.domain, request.process)
        .map_err(Error::Service)?
        != c.app
        || s.dispatch_inhibited(c.app.process) != Ok(false)
        || !alive(a, s, c.app)
        || !alive(a, s, c.file)
    {
        return Err(Error::Denied);
    }
    let source = a
        .authorize(
            c.root.domain,
            request.source,
            Kind::Endpoint,
            Rights::SEND | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
        )
        .map_err(Error::Authority)?
        .identity();
    if !c.read_sources.iter().any(|wire| {
        wire.object == source
            && !wire.closed
            && wire.receiver == c.file.domain
            && wire.bound == Some(c.file.thread)
    }) {
        return Err(Error::Denied);
    }
    let inbox = a
        .authorize(c.root.domain, request.inbox, Kind::Endpoint, Rights::SEND)
        .map_err(Error::Authority)?
        .identity();
    if c.inbox.closed
        || c.inbox.object != inbox
        || c.inbox.receiver != c.app.domain
        || c.inbox.bound != Some(c.app.thread)
    {
        return Err(Error::Denied);
    }
    if pending.is_some() || route.pending() != 0 {
        return Err(Error::Busy);
    }
    // Exact current token/target/receive role and actual mailbox policy, sender,
    // deadline/capacity/sequence are checked before private lineage is allocated.
    route
        .check_enqueue(a, s, r, c.token, request.inbox, b"EVREAD01", deadline, now)
        .map_err(|error| {
            if matches!(error, live_grant::Error::Ipc(IpcError::Full)) {
                Error::Busy
            } else {
                Error::Route(error)
            }
        })?;
    let (branch, one_shot) = r
        .prepare_active_send(a, s, c.root.domain, request.process, request.source)
        .map_err(Error::Service)?;
    let ticket = match route.enqueue(
        a,
        s,
        r,
        c.token,
        request.inbox,
        one_shot,
        b"EVREAD01",
        deadline,
        now,
    ) {
        Ok(ticket) => ticket,
        Err(error) => {
            // No acceptance occurred. The ordinary source remains retained.
            // Unexpected cleanup failure is fatal with authority still retained,
            // rather than returning a false clean refusal or losing the parent.
            a.close(c.root.domain, one_shot)
                .expect("unaccepted managed one-shot remains owned");
            branch.retire(a).unwrap_or_else(|rejected| {
                panic!("managed-read refusal retained parent: {:?}", rejected.error)
            });
            return Err(Error::Route(error));
        }
    };
    *open.last_nonce = request.nonce;
    *open.awaiting = None;
    // Consumption invalidates either pending route. No GUI approval/selection
    // is created, and an already accepted request cannot be reminted again.
    *open.active = None;
    Ok(Queued {
        branch,
        ticket,
        source_object: source,
        nonce: request.nonce,
    })
}
#[cfg(test)]
mod tests;

/// Actual retained owner context for the one-way Native3 dispatch gate. Values
/// come from the same captured runtime, never from numeric user identities.
pub struct InhibitContext {
    pub mode: Mode,
    pub caller: Metadata,
    pub root: Metadata,
    pub token: Token,
    pub app: Metadata,
}
/// Inhibit only after every read-only authority/liveness/accepted-callee check.
/// Accepted outbound caller work remains fully live and may wake Ready normally.
#[allow(clippy::too_many_arguments)]
pub fn inhibit<L: crate::loaded_image::LoadedExecutable>(
    a: &Authority,
    s: &mut Scheduler,
    r: &Registry<'_>,
    rpc: &crate::rpc::Rpc,
    context: &InhibitContext,
    process: Handle,
    running: &mut crate::service::Running<L>,
) -> Result<(), Error> {
    let c = context;
    if c.mode != Mode::ManagedNative3
        || c.caller != c.root
        || c.token.process() != c.root.process
        || c.token.job() != c.root.job
        || !alive(a, s, c.root)
        || s.state(c.root.thread) != Ok(State::Running(0))
        || running.metadata() != c.app
        || r.active_metadata(a, s, c.root.domain, process)
            .map_err(Error::Service)?
            != c.app
        || !alive(a, s, c.app)
    {
        return Err(Error::Denied);
    }
    if rpc.serving(c.app.thread).is_some() || matches!(s.state(c.app.thread), Ok(State::Running(_)))
    {
        return Err(Error::Busy);
    }
    running.inhibit(s).map_err(Error::Service)
}
