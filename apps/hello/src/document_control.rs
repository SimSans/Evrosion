//! One bounded control exchange and semantic-frame loan. Actual protected
//! peer/capability ownership is the actor's obligation, not a nonce's property.
use ev_userspace_contract::{
    document::Access,
    document_control::{Granted, Operation, Outcome, Reply, Request},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Exhausted,
    Deadline,
    Uncertain,
    Unsolicited,
    Protocol,
    Mismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Published { late: bool },
    Refused { outcome: Outcome, late: bool },
}
#[derive(Clone, Copy)]
struct Pending {
    request: Request,
    deadline: Option<u64>,
    quarantined: bool,
}
pub struct Client {
    sequence: u32,
    pending: Option<Pending>,
}
impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
impl Client {
    pub const fn new() -> Self {
        Self {
            sequence: 0,
            pending: None,
        }
    }
    pub const fn busy(&self) -> bool {
        self.pending.is_some()
    }
    pub fn frame_available(&self) -> bool {
        self.pending
            .is_none_or(|p| p.request.operation() != Operation::Publish)
    }
    pub fn pending_request(&self) -> Option<Request> {
        self.pending.map(|p| p.request)
    }
    fn start(&mut self, operation: Operation, deadline: Option<u64>) -> Result<Request, Error> {
        if let Some(p) = self.pending {
            return Err(if p.quarantined {
                Error::Uncertain
            } else {
                Error::Busy
            });
        }
        let nonce = self
            .sequence
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Exhausted)?;
        let request = Request::new(operation, nonce).map_err(|_| Error::Exhausted)?;
        self.sequence = nonce;
        self.pending = Some(Pending {
            request,
            deadline,
            quarantined: false,
        });
        Ok(request)
    }
    /// Waiting for a human picker is nonblocking and borrows no shared frame.
    /// UI cancellation/actual incarnation retirement ends the bounded request.
    pub fn open(&mut self, access: Access) -> Result<Request, Error> {
        self.start(
            match access {
                Access::Read => Operation::OpenRead,
                Access::Edit => Operation::OpenEdit,
                _ => return Err(Error::Protocol),
            },
            None,
        )
    }
    pub fn publish(&mut self, now: u64, deadline: u64) -> Result<Request, Error> {
        if deadline == u64::MAX || deadline <= now {
            return Err(Error::Deadline);
        }
        self.start(Operation::Publish, Some(deadline))
    }
    fn quarantine(&mut self, error: Error) -> Error {
        if let Some(p) = &mut self.pending {
            p.quarantined = true;
        }
        error
    }
    pub fn poll(&mut self, now: u64) -> Result<(), Error> {
        if let Some(p) = self.pending {
            if p.quarantined {
                return Err(Error::Uncertain);
            }
            if p.deadline.is_some_and(|cut| now >= cut) {
                return Err(self.quarantine(Error::Deadline));
            }
        }
        Ok(())
    }
    /// Only an actual current Root message on the retained protected control
    /// route may reach here. Even a late exact ACK can prove frame release;
    /// this completion never attests a File write or authorizes fresh-counter retry.
    pub fn reply(&mut self, bytes: &[u8], caps: usize, now: u64) -> Result<Completion, Error> {
        let p = self.pending.ok_or(Error::Unsolicited)?;
        let reply = Reply::decode(bytes, caps).map_err(|_| self.quarantine(Error::Protocol))?;
        if reply.nonce() != p.request.nonce() {
            return Err(self.quarantine(Error::Mismatch));
        }
        let late = p.quarantined || p.deadline.is_some_and(|cut| now >= cut);
        let outcome = reply.outcome();
        if outcome == Outcome::Published && p.request.operation() != Operation::Publish {
            return Err(self.quarantine(Error::Protocol));
        }
        self.pending = None;
        Ok(if outcome == Outcome::Published {
            Completion::Published { late }
        } else {
            Completion::Refused { outcome, late }
        })
    }
    /// This checks correlation only. The actor must independently inspect the
    /// actual delivered endpoint and retain/close it on every branch.
    pub fn grant(&mut self, bytes: &[u8], caps: usize) -> Result<Granted, Error> {
        let p = self.pending.ok_or(Error::Unsolicited)?;
        let grant = Granted::decode(bytes, caps).map_err(|_| self.quarantine(Error::Protocol))?;
        if grant.nonce() != p.request.nonce()
            || p.request.operation() == Operation::Publish
            || grant.access() != p.request.operation().access()
        {
            return Err(self.quarantine(Error::Mismatch));
        }
        self.pending = None;
        Ok(grant)
    }
}

#[cfg(test)]
#[path = "document_control_tests.rs"]
mod tests;
