//! Session-only use of the canonical Rpc outcomes and owned mailbox tickets.
//! Expiry is not shared-memory quiescence. Keep guarded waits and mappings until
//! queued withdrawal, an actual callee acknowledgement, or verified retirement.
use super::*;
use ev_kernel::rpc::{Error as RpcError, Notifications, ScalarError};

const QUIESCENCE_TICKS: u64 = 1024;

#[derive(Clone, Copy)]
pub(super) struct Terminal {
    pub status: Status,
    by: u64,
}

#[derive(Debug)]
pub(super) enum QuiescenceError {
    Rpc(RpcError),
    Scalar(ScalarError),
    Integrity,
    ClockExhausted,
    ClockRegression {
        previous: u64,
        now: u64,
    },
    Grace {
        call: CallId,
        caller: ThreadId,
        callee: ThreadId,
        by: u64,
    },
}
impl core::fmt::Display for QuiescenceError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rpc(error) => write!(output, "canonical RPC: {error:?}"),
            Self::Scalar(error) => write!(output, "scalar ownership: {error:?}"),
            Self::Integrity => output.write_str("retained call identity mismatch"),
            Self::ClockExhausted => output.write_str("quiescence clock exhausted"),
            Self::ClockRegression { previous, now } => {
                write!(
                    output,
                    "async maintenance clock regressed previous={previous} now={now}"
                )
            }
            Self::Grace {
                call,
                caller,
                callee,
                by,
            } => write!(
                output,
                "quiescence expired call={}:{} caller={} callee={} by={by}",
                call.epoch(),
                call.serial(),
                caller.diagnostic_id(),
                callee.diagnostic_id()
            ),
        }
    }
}

impl Runtime<'_, '_> {
    fn terminal(&mut self, slot: usize, status: Status, now: u64) -> Result<(), QuiescenceError> {
        if status == Status::Ok {
            return Err(QuiescenceError::Integrity);
        }
        let pending = self.pending[slot]
            .as_mut()
            .ok_or(QuiescenceError::Integrity)?;
        if let Some(previous) = pending.terminal {
            if previous.status != status {
                return Err(QuiescenceError::Integrity);
            }
            return Ok(());
        }
        let origin = if status == Status::DeadlineExceeded {
            pending.deadline.tick()
        } else {
            now
        };
        let by = origin
            .checked_add(QUIESCENCE_TICKS)
            .filter(|by| *by != u64::MAX)
            .ok_or(QuiescenceError::ClockExhausted)?;
        pending.terminal = Some(Terminal { status, by });
        let snapshot = *pending;
        self.trace_rpc(snapshot, SessionRpcPhase::Terminal, terminal_status(status));
        Ok(())
    }

    fn terminal_notifications(
        &mut self,
        notifications: Notifications,
        now: u64,
    ) -> Result<(), QuiescenceError> {
        for event in notifications.iter() {
            let slot = self
                .pending
                .iter()
                .position(|pending| pending.is_some_and(|pending| pending.id == event.call))
                .ok_or(QuiescenceError::Integrity)?;
            let pending = self.pending[slot].unwrap();
            if self.metadata(pending.caller).map(|meta| meta.thread) != Some(event.caller)
                || event.deliver_reply
                || !event.wake_caller
            {
                return Err(QuiescenceError::Integrity);
            }
            self.terminal(slot, event.status, now)?;
        }
        Ok(())
    }

    /// Observe outcomes without waking any buffer owner. Also used immediately
    /// before an ACK captured on the tick of its deadline.
    pub(super) fn observe_rpc_outcomes(&mut self, now: u64) -> Result<(), QuiescenceError> {
        let notifications = self.rpc.expire(now).map_err(QuiescenceError::Rpc)?;
        self.terminal_notifications(notifications, now)?;
        for slot in 0..self.pending.len() {
            let Some(pending) = self.pending[slot] else {
                continue;
            };
            for index in [pending.caller, pending.callee] {
                let thread = self
                    .metadata(index)
                    .ok_or(QuiescenceError::Integrity)?
                    .thread;
                if self.s.state(thread) == Ok(State::Exited) {
                    let notifications = self
                        .rpc
                        .peer_died(self.s, thread, now)
                        .map_err(QuiescenceError::Rpc)?;
                    self.terminal_notifications(notifications, now)?;
                }
            }
            match self.rpc.context(pending.id) {
                Ok(context) => {
                    if let Some(status) = self
                        .rpc
                        .cancellation(context.cancellation_token, now)
                        .map_err(QuiescenceError::Rpc)?
                    {
                        self.terminal(slot, status, now)?;
                    }
                }
                Err(RpcError::StaleCall)
                    if self
                        .metadata(pending.callee)
                        .is_some_and(|meta| self.s.state(meta.thread) == Ok(State::Exited)) =>
                {
                    if self.pending[slot].unwrap().terminal.is_none() {
                        self.terminal(slot, Status::PeerDied, now)?;
                    }
                }
                Err(error) => return Err(QuiescenceError::Rpc(error)),
            }
        }
        Ok(())
    }

    /// Caller must have actually withdrawn the queued ticket or established
    /// ACK/death. This never runs merely because a deadline elapsed.
    pub(super) fn finish_cancelled_call(&mut self, slot: usize) {
        let pending = self.pending[slot].unwrap();
        let terminal = pending.terminal.unwrap();
        let caller = self.metadata(pending.caller).unwrap();
        self.trace_rpc(
            pending,
            SessionRpcPhase::Quiescent,
            terminal_status(terminal.status),
        );
        if self.s.state(caller.thread) != Ok(State::Exited) {
            assert!(
                self.s.waiting(pending.wait),
                "cancelled buffer owner remains guarded"
            );
            let status = match terminal.status {
                Status::DeadlineExceeded => 4,
                Status::PeerDied => 5,
                Status::Cancelled => 6,
                Status::Ok => unreachable!(),
            };
            scalar(self.context_mut(pending.caller), status, 0);
            assert!(self.s.wake(pending.wait));
            self.facts.wakes += 1;
        }
        self.pending[slot] = None;
    }

    /// Run before Scheduler.advance/dispatch. A grace failure returns ownership
    /// intact to the outer controller: it may stop the whole session, but must
    /// not resume this caller, detach backing, or claim driver reconstruction.
    pub(super) fn expire_calls(&mut self, now: u64) -> Result<(), QuiescenceError> {
        self.expire_async_messages(now)?;
        self.observe_rpc_outcomes(now)?;
        // Leaf completion may unblock an ancestor's queued withdrawal. A fixed
        // number of passes follows the existing bounded canonical causal graph.
        for _ in 0..ev_kernel::rpc::MAX_CALLS {
            let mut progress = false;
            for slot in 0..self.pending.len() {
                let Some(pending) = self.pending[slot].filter(|pending| pending.terminal.is_some())
                else {
                    continue;
                };
                let callee = self
                    .metadata(pending.callee)
                    .ok_or(QuiescenceError::Integrity)?;
                if self.s.state(callee.thread) == Ok(State::Exited) {
                    // A stopped intermediary may still have an accepted child
                    // that can access shared backing. Keep this owner record
                    // until its children have themselves quiesced. Use the
                    // retained Pending ledger: peer_died may already have
                    // removed an intermediate Rpc record while deeper work
                    // still retains a cancelled execution reservation.
                    if self
                        .pending
                        .iter()
                        .flatten()
                        .any(|child| child.caller == pending.callee)
                    {
                        continue;
                    }
                    let wire = self.wires[pending.wire]
                        .as_mut()
                        .ok_or(QuiescenceError::Integrity)?;
                    // An actual stopped receiver cannot access this queue. Its
                    // ordinary cap-free close drains every accepted sender.
                    wire.close(self.a, now)
                        .map_err(|error| QuiescenceError::Scalar(ScalarError::Ipc(error)))?;
                    self.finish_cancelled_call(slot);
                    #[cfg(feature = "test-m6-network-negative")]
                    self.negative_cancelled(pending);
                    progress = true;
                } else if !pending.delivered {
                    let wire = self.wires[pending.wire]
                        .as_mut()
                        .ok_or(QuiescenceError::Integrity)?;
                    match wire.withdraw_rpc(
                        self.a,
                        self.rpc,
                        callee.thread,
                        pending.id,
                        pending.ticket,
                        now,
                    ) {
                        Ok(()) => {
                            self.finish_cancelled_call(slot);
                            #[cfg(feature = "test-m6-network-negative")]
                            self.negative_cancelled(pending);
                            progress = true;
                        }
                        Err(ScalarError::Rpc(RpcError::AlreadyWaiting)) => {}
                        Err(error) => return Err(QuiescenceError::Scalar(error)),
                    }
                }
            }
            if !progress {
                break;
            }
        }
        for pending in self.pending.iter().flatten() {
            if let Some(terminal) = pending.terminal
                && now >= terminal.by
            {
                return Err(QuiescenceError::Grace {
                    call: pending.id,
                    caller: self
                        .metadata(pending.caller)
                        .ok_or(QuiescenceError::Integrity)?
                        .thread,
                    callee: self
                        .metadata(pending.callee)
                        .ok_or(QuiescenceError::Integrity)?
                        .thread,
                    by: terminal.by,
                });
            }
        }
        Ok(())
    }

    fn expire_async_messages(&mut self, now: u64) -> Result<(), QuiescenceError> {
        // All mutation is serialized by this captured-CPU owner. After a
        // successful sweep, SEND can only introduce deadlines strictly after
        // its actual capture tick (Mailbox::send rejects deadline <= now).
        // Receive/withdraw/close only remove queued debt. Thus another syscall
        // at this exact tick cannot introduce a newly due Async message.
        // A newer tick always reaches the canonical path; failed
        // sweeps never update this memo. This is not ownership/credit state.
        // RECEIVE independently checks its actual captured tick, even when
        // execution crossed a deadline after this executor preflight.
        if let Some(previous) = self.async_swept_at {
            if now < previous {
                return Err(QuiescenceError::ClockRegression { previous, now });
            }
            if now == previous {
                return Ok(());
            }
        }
        for slot in 0..self.wires.len() {
            let Some(wire) = self.wires[slot].as_mut() else {
                continue;
            };
            if !wire.needs_async_expiry() {
                continue;
            }
            let expired = wire
                .expire_async(self.a, now)
                .map_err(|error| QuiescenceError::Scalar(ScalarError::Ipc(error)))?;
            self.observe_async_expiries(slot, expired, now)?;
        }
        self.async_swept_at = Some(now);
        Ok(())
    }
    pub(super) fn observe_async_expiries(
        &mut self,
        slot: usize,
        expired: [Option<transport::AsyncExpiry>; ev_kernel::ipc::MAX_MESSAGES],
        now: u64,
    ) -> Result<(), QuiescenceError> {
        let wire = self.wires[slot]
            .as_ref()
            .ok_or(QuiescenceError::Integrity)?;
        let endpoint = wire.object;
        let receiver_domain = wire.receiver;
        for receipt in expired.into_iter().flatten() {
            // These actual accepted sender IDs may now be retired. They
            // identify the old message, never permission for a replacement.
            let receiver = (0..=self.actors.len())
                .filter_map(|index| self.metadata(index))
                .find(|metadata| metadata.domain == receiver_domain)
                .ok_or(QuiescenceError::Integrity)?;
            self.async_expired = self
                .async_expired
                .checked_add(1)
                .ok_or(QuiescenceError::Integrity)?;
            if self.async_expired <= 32 {
                (self.observations)(Observation::SessionAsyncExpiry(SessionAsyncExpiry {
                    sequence: self.async_expired,
                    endpoint,
                    ticket: receipt.message.ticket.0,
                    sender_process: receipt.process.diagnostic_id(),
                    sender_thread: receipt.thread.diagnostic_id(),
                    receiver_process: receiver.process.diagnostic_id(),
                    receiver_thread: receiver.thread.diagnostic_id(),
                    deadline: receipt.message.deadline.tick(),
                    tick: now,
                    value: u64::from_le_bytes(receipt.message.bytes),
                }));
            }
        }
        Ok(())
    }
}
fn terminal_status(status: Status) -> u64 {
    match status {
        Status::DeadlineExceeded => 4,
        Status::PeerDied => 5,
        Status::Cancelled => 6,
        Status::Ok => 0,
    }
}
