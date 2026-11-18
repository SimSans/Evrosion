//! Exact ordinary own-reader transport. No packet field supplies source,
//! publication, permission or protected confirmation authority.
use super::{Binding, OrdinaryReceipt};
use crate::Identity;
use ev_native_inspector::self_tree::ordinary::{Reply, Request};
use ev_userspace_contract::root_v5::assistive::Intent;
use ev_workspace_client::semantic::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderPhase {
    Idle,
    Sending,
    AwaitReply,
    Acknowledge,
    Blocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderOutcome {
    Intent(Intent),
    Local,
    Rejected,
}
pub struct ReaderTransfer {
    phase: ReaderPhase,
    binding: Option<Binding>,
    receipt: Option<OrdinaryReceipt>,
    publication: u64,
    control: u16,
    nonce: u32,
    last_nonce: u32,
    next: u8,
    by: u64,
    authorized: bool,
    reply: Option<Reply>,
    last_delivery: Option<[u8; 8]>,
}
impl Default for ReaderTransfer {
    fn default() -> Self {
        Self::new()
    }
}
impl ReaderTransfer {
    pub const fn new() -> Self {
        Self {
            phase: ReaderPhase::Idle,
            binding: None,
            receipt: None,
            publication: 0,
            control: 0,
            nonce: 0,
            last_nonce: 0,
            next: 0,
            by: 0,
            authorized: false,
            reply: None,
            last_delivery: None,
        }
    }
    pub const fn phase(&self) -> ReaderPhase {
        self.phase
    }
    pub const fn binding(&self) -> Option<Binding> {
        self.binding
    }
    pub const fn by(&self) -> u64 {
        self.by
    }
    pub const fn last_delivery(&self) -> Option<[u8; 8]> {
        self.last_delivery
    }
    pub const fn retained_reply(&self) -> Option<Reply> {
        self.reply
    }
    pub const fn pending(&self) -> bool {
        !matches!(self.phase, ReaderPhase::Idle)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self,
        binding: Binding,
        publication: u64,
        control: u16,
        nonce: u32,
        selected: u8,
        count: u8,
        by: u64,
    ) -> Result<(), Error> {
        if self.pending() {
            return Err(Error::State);
        }
        if !binding.context.reader
            || matches!(publication, 0 | u64::MAX)
            || nonce <= self.last_nonce
        {
            return Err(Error::Value);
        }
        Request::Begin { nonce, control }.encode()?;
        let receipt =
            OrdinaryReceipt::new(binding, control, selected, count, by).ok_or(Error::Value)?;
        self.binding = Some(binding);
        self.receipt = Some(receipt);
        self.publication = publication;
        self.control = control;
        self.nonce = nonce;
        self.last_nonce = nonce;
        self.next = 0;
        self.by = by;
        self.authorized = true;
        self.reply = None;
        self.last_delivery = None;
        self.phase = ReaderPhase::Sending;
        Ok(())
    }
    pub fn next(&self) -> Option<[u8; 8]> {
        let request = match (self.phase, self.next) {
            (ReaderPhase::Sending, 0) => Request::Begin {
                nonce: self.nonce,
                control: self.control,
            },
            (ReaderPhase::Sending, 1) => Request::CutLow {
                word: self.by as u32,
            },
            (ReaderPhase::Sending, 2) => Request::CutHigh {
                word: (self.by >> 32) as u32,
            },
            (ReaderPhase::Sending, 3) => Request::Commit { nonce: self.nonce },
            (ReaderPhase::Acknowledge, _) => Request::Acknowledge { nonce: self.nonce },
            _ => return None,
        };
        request.encode().ok()
    }
    /// An actual status0 on the original InspectorControl alone advances a
    /// held word. Busy leaves it exact; unknown delivery must call `failed`.
    pub fn sent(&mut self, bytes: [u8; 8], now: u64) -> Result<(), Error> {
        if self.next() != Some(bytes) {
            self.failed();
            return Err(Error::Order);
        }
        self.last_delivery = Some(bytes);
        if now >= self.by {
            // Actual status0 may already have transferred this exact word.
            // A late acknowledgment cannot erase the retained old owner.
            self.failed();
            return Err(Error::State);
        }
        match self.phase {
            ReaderPhase::Sending => {
                self.next += 1;
                if self.next == 4 {
                    self.phase = ReaderPhase::AwaitReply;
                }
            }
            ReaderPhase::Acknowledge => {
                // Delivery responsibility is now in the original App mailbox.
                // This is no App consumption, stream, Present or RPC credit.
                self.phase = ReaderPhase::Idle;
                self.binding = None;
                self.receipt = None;
                self.reply = None;
            }
            _ => return Err(Error::State),
        }
        Ok(())
    }
    pub fn tick(&mut self, current: Option<Binding>, publication: Option<u64>, now: u64) {
        self.retain_recorded_scope(current == self.binding, publication, now);
    }
    /// Root-owned metadata can only veto an already held authorization while
    /// its immutable transport progresses. It never proves a current frame;
    /// receive still requires the full actual Display/provider binding.
    pub fn retain_recorded_scope(&mut self, unchanged: bool, publication: Option<u64>, now: u64) {
        if !self.pending() || self.phase == ReaderPhase::Blocked {
            return;
        }
        if !unchanged || publication != Some(self.publication) {
            self.authorized = false;
        }
        if now >= self.by || !self.authorized {
            if self.phase == ReaderPhase::Sending && self.next == 0 {
                // No transport accepted any request word: only desire drops.
                self.phase = ReaderPhase::Idle;
                self.binding = None;
                self.receipt = None;
            } else if now >= self.by {
                self.failed();
            }
        }
    }
    /// Validate before any acknowledgment releases the App's held repaint.
    /// Even rejection retains the exact reply until original-cut ack delivery.
    pub fn receive(
        &mut self,
        sender: Identity,
        reply: Reply,
        current: Option<Binding>,
        publication: Option<u64>,
        now: u64,
    ) -> Result<ReaderOutcome, Error> {
        if reply.encode().is_err() {
            self.failed();
            return Err(Error::Field);
        }
        if self.binding.is_none_or(|b| b.owner != sender) {
            return Err(Error::Value);
        }
        if self.phase != ReaderPhase::AwaitReply || reply.nonce != self.nonce {
            self.failed();
            return Err(Error::Nonce);
        }
        // The canonical exact-origin/nonce reply was already consumed. A
        // slow actual Display check may have exhausted the original cut, but
        // expiry must retain this value alongside its old owner and request.
        self.reply = Some(reply);
        self.tick(current, publication, now);
        if self.phase == ReaderPhase::Blocked {
            return Err(Error::State);
        }
        let binding = self.binding.unwrap();
        let outcome = if !self.authorized {
            ReaderOutcome::Rejected
        } else if let Some(kind) = reply.kind {
            let intent = Intent {
                kind,
                index: reply.index,
                view: binding.context.view,
            };
            if self.receipt.as_ref().unwrap().matches(current, intent, now) {
                ReaderOutcome::Intent(intent)
            } else {
                ReaderOutcome::Rejected
            }
        } else if matches!(self.control, 201 | 202) {
            ReaderOutcome::Local
        } else {
            ReaderOutcome::Rejected
        };
        self.authorized = false;
        self.phase = ReaderPhase::Acknowledge;
        Ok(outcome)
    }
    pub fn failed(&mut self) {
        self.authorized = false;
        self.phase = ReaderPhase::Blocked;
    }
}
