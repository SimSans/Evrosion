//! Owned M8 managed-SEND retirement. Native credit snapshots must come from
//! its retained accepted Pending rows; no PID, ready flag or client journal
//! selector appears in the scalar request or this owner's correlation key.
use crate::{
    capability::{Authority, Handle, Kind, Rights},
    incarnation::Token,
    live_grant::SelectedReadRoute,
    rpc::AcceptedSnapshot,
    scheduler::{Scheduler, State},
    service::{self, ActiveGrantBranch, Metadata, Registry},
};
#[derive(Clone, Copy)]
pub struct Context {
    pub caller: Metadata,
    pub root: Metadata,
    pub token: Token,
}
impl Context {
    /// Reuse the captured Root/custodian/scheduler proof for other selected
    /// controller-only mechanisms. This grants no authority or new handle.
    pub fn validate(self, authority: &Authority, scheduler: &Scheduler) -> Result<(), Error> {
        root_context(authority, scheduler, self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum StateCode {
    Drained = 0,
    RevokedPending = 1,
    Retained = 2,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Caller,
    Owner,
    Nonce,
    Route,
    Authority(crate::capability::Error),
    Service(service::Error),
}
impl From<crate::capability::Error> for Error {
    fn from(e: crate::capability::Error) -> Self {
        Self::Authority(e)
    }
}
impl From<service::Error> for Error {
    fn from(e: service::Error) -> Self {
        Self::Service(e)
    }
}
/// Journal owns the one private revocation parent, separate from both source
/// master and Workspace RX. A failed retirement keeps the same parent owner.
pub struct Entry {
    root: Context,
    target: Metadata,
    process_object: usize,
    nonce: u32,
    endpoint: usize,
    branch: Option<ActiveGrantBranch>,
    queue_cleared: bool,
    drained: bool,
}
fn root_context(a: &Authority, s: &Scheduler, c: Context) -> Result<(), Error> {
    if c.caller != c.root
        || c.root.process != c.token.process()
        || c.root.job != c.token.job()
        || c.root.domain != c.token.destination()
        || !a.is_live_space(c.root.domain)
        || a.slot_capacity(c.root.domain)? != 96
        || s.thread_process(c.root.thread).map_err(|_| Error::Caller)? != c.root.process
        || s.process_job(c.root.process).map_err(|_| Error::Caller)? != c.root.job
        || s.process_terminated(c.root.process)
        || s.state(c.root.thread) != Ok(State::Running(0))
        || s.running_thread(0) != Ok(c.root.thread)
    {
        return Err(Error::Caller);
    }
    Ok(())
}
impl Entry {
    /// Prepare through the same real Registry/Authority. Commit the returned
    /// owner to the native journal only after actual selected enqueue accepts.
    pub fn prepare(
        a: &mut Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        context: Context,
        process: Handle,
        source: Handle,
        nonce: u32,
    ) -> Result<(Self, Handle), Error> {
        root_context(a, s, context)?;
        if nonce == 0 || nonce == u32::MAX {
            return Err(Error::Nonce);
        }
        let target = r.active_metadata(a, s, context.root.domain, process)?;
        let process_object = a
            .authorize(context.root.domain, process, Kind::Process, Rights::CONTROL)?
            .identity();
        let endpoint = a
            .authorize(
                context.root.domain,
                source,
                Kind::Endpoint,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
            )?
            .identity();
        let (branch, one_shot) =
            r.prepare_active_send(a, s, context.root.domain, process, source)?;
        Ok((
            Self {
                root: context,
                target,
                process_object,
                nonce,
                endpoint,
                branch: Some(branch),
                queue_cleared: false,
                drained: false,
            },
            one_shot,
        ))
    }
    pub fn target(&self) -> Metadata {
        self.target
    }
    pub fn nonce(&self) -> u32 {
        self.nonce
    }
    pub fn endpoint(&self) -> usize {
        self.endpoint
    }
    pub fn is_drained(&self) -> bool {
        self.drained
    }
    pub fn queue_cleared(&self) -> bool {
        self.queue_cleared
    }
    /// Actual FIFO consumption, not a caller's acknowledgement or readiness bit.
    pub fn delivered(&mut self, ticket: crate::ipc::Ticket, actual: crate::ipc::Ticket) {
        assert_eq!(ticket, actual);
        self.queue_cleared = true;
    }
    /// Trusted stop path uses this exact route/ticket withdrawal, never a client
    /// Release acknowledgement, to settle an undelivered capability escrow.
    pub fn withdraw_owned(
        &mut self,
        a: &mut Authority,
        route: &mut SelectedReadRoute,
        ticket: crate::ipc::Ticket,
        now: u64,
    ) -> StateCode {
        if self.revoke_owned(a) == StateCode::Retained {
            return StateCode::Retained;
        }
        match route.cancel(a, ticket, now) {
            Ok(crate::ipc::Reclaimed::Capability(cap)) => {
                if a.close(self.root.root.domain, cap).is_err() {
                    return StateCode::RevokedPending;
                }
                self.queue_cleared = true;
            }
            Ok(crate::ipc::Reclaimed::Invalidated | crate::ipc::Reclaimed::NoCapability) => {
                self.queue_cleared = true
            }
            Err(_) => return StateCode::RevokedPending,
        }
        StateCode::RevokedPending
    }
    pub fn observe_stopped(
        &mut self,
        s: &Scheduler,
        r: &Registry<'_>,
        receipt: &crate::live_grant::StoppedSelectedRoute,
        credits: &[Option<AcceptedSnapshot>],
    ) -> Result<(), Error> {
        if self.branch.is_some() || !self.queue_cleared || receipt.target_metadata() != self.target
        {
            return Err(Error::Owner);
        }
        r.require_stopped_owner(s, self.process_object, self.target)?;
        if credits.iter().flatten().any(|c| {
            c.caller() == self.target.thread
                || c.callee() == self.target.thread
                || c.endpoint() == self.endpoint
        }) {
            return Err(Error::Owner);
        }
        self.drained = true;
        Ok(())
    }
    /// Trusted decreasing-authority teardown; permission is not inferred from
    /// revoked public handles. Physical backing/accepted execution stay fenced.
    pub fn revoke_owned(&mut self, a: &mut Authority) -> StateCode {
        if let Some(branch) = self.branch.take()
            && let Err(rejected) = branch.retire(a)
        {
            self.branch = Some(rejected.branch);
            return StateCode::Retained;
        }
        self.drained = false;
        StateCode::RevokedPending
    }
    /// Retires EXACT Root/process/old44 nonce. Source master/RX and independent
    /// service durable stage/device reconciliation are deliberately untouched.
    #[allow(clippy::too_many_arguments)]
    pub fn retire(
        &mut self,
        a: &mut Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        context: Context,
        process: Handle,
        nonce: u32,
        route: &mut SelectedReadRoute,
        queued: Option<crate::ipc::Ticket>,
        credits: &[Option<AcceptedSnapshot>],
        now: u64,
    ) -> Result<StateCode, Error> {
        root_context(a, s, context)?;
        if context.token != self.root.token || context.root != self.root.root {
            return Err(Error::Caller);
        }
        if nonce != self.nonce {
            return Err(Error::Nonce);
        }
        let actual = r.metadata(a, context.root.domain, process)?;
        if actual != self.target
            || a.authorize(context.root.domain, process, Kind::Process, Rights::CONTROL)?
                .identity()
                != self.process_object
        {
            return Err(Error::Owner);
        }
        if route.target_metadata() != self.target {
            return Err(Error::Route);
        }
        if self.revoke_owned(a) == StateCode::Retained {
            return Ok(StateCode::Retained);
        }
        if !self.queue_cleared
            && let Some(ticket) = queued
        {
            match route.cancel(a, ticket, now) {
                Ok(crate::ipc::Reclaimed::Capability(cap)) => {
                    a.close(context.root.domain, cap)?;
                    self.queue_cleared = true;
                }
                Ok(crate::ipc::Reclaimed::Invalidated | crate::ipc::Reclaimed::NoCapability) => {
                    self.queue_cleared = true
                }
                Err(_) => return Ok(StateCode::RevokedPending),
            }
        }
        let accepted = credits.iter().flatten().any(|credit| {
            credit.caller() == self.target.thread
                || credit.callee() == self.target.thread
                || credit.endpoint() == self.endpoint
        });
        if !self.queue_cleared || route.pending() != 0 || accepted {
            return Ok(StateCode::RevokedPending);
        }
        self.drained = true;
        Ok(StateCode::Drained)
    }
}
#[cfg(test)]
mod tests;
