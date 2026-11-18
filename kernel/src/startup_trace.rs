//! Finite diagnostic retention, never startup or health authority. Runtime
//! supplies only facts joined to its actual protected actor/endpoint owners.
pub const CAPACITY: usize = 16;
pub const CPU_CAPACITY: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSample {
    pub job: u64,
    pub charged: u64,
    pub scheduler_tick: u64,
    pub budget: crate::scheduler::CpuBudget,
}
/// Two independent endpoints only. Full route/value facts remain in the
/// unchanged event prefix; these fields bind the CPU point to its exact event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuPoint {
    pub phase: u8,
    pub tick: u64,
    pub process: u64,
    pub thread: u64,
    pub job: u64,
    pub ticket: u64,
    pub call_epoch: u64,
    pub call: u64,
    /// None is unavailable, never a claim of zero sampled consumption.
    pub sample: Option<CpuSample>,
}
/// Read-only sampled CPU facts, not physical elapsed time or dispatch credit.
/// The runtime first binds the current App role; this guard independently joins
/// its actual typed thread/process/job to the scheduler before reading that Job.
pub fn cpu_sample(
    scheduler: &crate::scheduler::Scheduler,
    process: crate::scheduler::ProcessId,
    thread: crate::scheduler::ThreadId,
    job: crate::scheduler::JobId,
) -> Option<CpuSample> {
    if scheduler.thread_process(thread).ok()? != process
        || scheduler.process_job(process).ok()? != job
    {
        return None;
    }
    Some(CpuSample {
        job: job.diagnostic_id(),
        charged: scheduler
            .usage(job, crate::scheduler::Resource::CpuTicks)
            .ok()?,
        scheduler_tick: scheduler.observed_tick(),
        budget: scheduler.cpu_budget(job).ok()??,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// Event accepted1/received2; Present accepted3/delivered4/reply5,
    /// digest begin6/validated finalized digest7, protected completion+wake8,
    /// actual initial Read reply delivered9.
    pub phase: u8,
    pub wire: u8,
    pub tick: u64,
    pub process: u64,
    pub thread: u64,
    pub peer_process: u64,
    pub peer_thread: u64,
    pub endpoint: u64,
    pub ticket: u64,
    pub call_epoch: u64,
    pub call: u64,
    pub value: u64,
}

#[derive(Default)]
pub struct Retained {
    rows: [Row; CAPACITY],
    count: usize,
    observed: u64,
    overflow: u64,
    present: Option<(u64, u64)>,
    note_delivered: bool,
    cpu: [CpuPoint; CPU_CAPACITY],
    cpu_count: usize,
    cpu_observed: u64,
    cpu_duplicates: u64,
    cpu_overflow: u64,
    cpu_seen: u8,
    closed: bool,
}
impl Retained {
    pub fn recording(&self) -> bool {
        !self.closed
    }
    pub fn select_note(&mut self) -> bool {
        if self.closed || self.note_delivered {
            return false;
        }
        self.note_delivered = true;
        true
    }
    /// Independent two-point cap/once guards. Duplicate endpoints never
    /// replace an earlier valid or explicitly unavailable sample.
    pub fn push_cpu(&mut self, point: CpuPoint) {
        if self.closed {
            return;
        }
        let bit = match point.phase {
            9 => 1,
            3 => 2,
            _ => return,
        };
        self.cpu_observed = self.cpu_observed.saturating_add(1);
        if self.cpu_seen & bit != 0 {
            self.cpu_duplicates = self.cpu_duplicates.saturating_add(1);
            return;
        }
        self.cpu_seen |= bit;
        if self.cpu_count == CPU_CAPACITY {
            self.cpu_overflow = self.cpu_overflow.saturating_add(1);
            return;
        }
        self.cpu[self.cpu_count] = point;
        self.cpu_count += 1;
    }
    pub fn cpu_point(&self, index: usize) -> Option<CpuPoint> {
        (index < self.cpu_count).then(|| self.cpu[index])
    }
    pub fn cpu_counts(&self) -> (u64, usize, u64, u64) {
        (
            self.cpu_observed,
            self.cpu_count,
            self.cpu_duplicates,
            self.cpu_overflow,
        )
    }
    /// The first actual protected valid App Present is the sole sampled RPC.
    /// A later call cannot reopen or replace the retained call identity.
    pub fn select_present(&mut self, epoch: u64, call: u64) -> bool {
        if self.closed || epoch == 0 || call == 0 {
            return false;
        }
        if self.present.is_none() {
            self.present = Some((epoch, call));
        }
        self.present == Some((epoch, call))
    }
    pub fn selected_present(&self, epoch: u64, call: u64) -> bool {
        !self.closed && self.present == Some((epoch, call))
    }
    pub fn push(&mut self, row: Row) {
        if self.closed {
            return;
        }
        self.observed = self.observed.saturating_add(1);
        if self.count == CAPACITY {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        self.rows[self.count] = row;
        self.count += 1;
    }
    /// Called only after the ordinary authenticated typed System outcome.
    /// Close before emitting, so repeated reports cannot duplicate/reopen it.
    /// This is a prefix: an absent event may be emitted after closure. Counts
    /// describe retention within the open prefix, never a negative health proof.
    pub fn close(&mut self) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        true
    }
    pub fn row(&self, index: usize) -> Option<Row> {
        (index < self.count).then(|| self.rows[index])
    }
    pub fn counts(&self) -> (u64, usize, u64) {
        (self.observed, self.count, self.overflow)
    }
}

pub fn startup_token(bytes: [u8; 8]) -> bool {
    matches!(&bytes, b"EVGARDY1" | b"EVGADON1" | b"EVAPCRD1")
}
pub fn present_request(value: u64) -> bool {
    let bytes = value.to_le_bytes();
    let frame = u32::from_le_bytes(bytes[4..].try_into().unwrap());
    &bytes[..4] == b"EVP1" && frame != 0 && frame != u32::MAX
}
pub fn initial_note_reply(value: u64) -> bool {
    use ev_userspace_contract::session_note::{Outcome, Response};
    Response::decode(&value.to_le_bytes(), 0)
        .is_ok_and(|reply| reply.nonce() == 1 && reply.outcome() == Outcome::Read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{Limits, Scheduler};
    #[test]
    fn cpu_facts_keep_reservations_lifetime_usage_and_period_renewal_without_changes() {
        let mut scheduler = Scheduler::new();
        let job = scheduler
            .create_job_with_limits(Limits::new(2, 4, 1, 1))
            .unwrap();
        scheduler.configure_cpu_budget(job, 2, 4).unwrap();
        let process = scheduler.create_process(job).unwrap();
        let thread = scheduler.create_thread(process).unwrap();
        let initial = cpu_sample(&scheduler, process, thread, job).unwrap();
        assert_eq!(
            (initial.job, initial.charged, initial.scheduler_tick),
            (job.diagnostic_id(), 0, 0)
        );
        assert_eq!(
            (initial.budget.quota_ticks, initial.budget.period_ticks),
            (2, 4)
        );
        assert_eq!(
            (initial.budget.window_start, initial.budget.window_end),
            (0, 4)
        );
        assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, thread);
        let reserved = cpu_sample(&scheduler, process, thread, job).unwrap();
        assert_eq!(
            (
                reserved.budget.reserved_ticks,
                reserved.budget.remaining_ticks
            ),
            (1, 1)
        );
        assert_eq!(cpu_sample(&scheduler, process, thread, job), Some(reserved));
        assert_eq!(scheduler.cpu_budget(job).unwrap(), Some(reserved.budget));
        scheduler.charge_cpu(0, 2).unwrap();
        scheduler.yield_cpu(0).unwrap();
        let exhausted = cpu_sample(&scheduler, process, thread, job).unwrap();
        assert_eq!(
            (
                exhausted.charged,
                exhausted.budget.consumed_ticks,
                exhausted.budget.remaining_ticks
            ),
            (2, 2, 0)
        );
        assert!(scheduler.dispatch(0).unwrap().is_none());
        scheduler.advance(4).unwrap();
        let renewed = cpu_sample(&scheduler, process, thread, job).unwrap();
        assert_eq!((renewed.charged, renewed.scheduler_tick), (2, 4));
        assert_eq!(
            (
                renewed.budget.window_start,
                renewed.budget.window_end,
                renewed.budget.consumed_ticks,
                renewed.budget.remaining_ticks
            ),
            (4, 8, 0, 2)
        );
        assert_eq!(cpu_sample(&scheduler, process, thread, job), Some(renewed));
    }
    #[test]
    fn foreign_thread_process_job_and_reclaimed_ids_do_not_borrow_another_budget() {
        let mut scheduler = Scheduler::new();
        let a = scheduler
            .create_job_with_limits(Limits::new(2, 4, 1, 1))
            .unwrap();
        let b = scheduler
            .create_job_with_limits(Limits::new(4, 4, 1, 1))
            .unwrap();
        scheduler.configure_cpu_budget(a, 2, 4).unwrap();
        scheduler.configure_cpu_budget(b, 4, 8).unwrap();
        let pa = scheduler.create_process(a).unwrap();
        let ta = scheduler.create_thread(pa).unwrap();
        let pb = scheduler.create_process(b).unwrap();
        let tb = scheduler.create_thread(pb).unwrap();
        assert!(cpu_sample(&scheduler, pa, ta, a).is_some());
        assert!(cpu_sample(&scheduler, pb, tb, b).is_some());
        for (p, t, j) in [(pa, ta, b), (pa, tb, a), (pb, ta, b)] {
            assert_eq!(cpu_sample(&scheduler, p, t, j), None);
        }
        scheduler.terminate_process(pa).unwrap();
        scheduler.reclaim_process(pa).unwrap();
        scheduler.reclaim_job(a).unwrap();
        let replacement = scheduler
            .create_job_with_limits(Limits::new(2, 4, 1, 1))
            .unwrap();
        scheduler.configure_cpu_budget(replacement, 1, 2).unwrap();
        assert_ne!(replacement.diagnostic_id(), a.diagnostic_id());
        assert_eq!(cpu_sample(&scheduler, pa, ta, a), None);
        assert_eq!(cpu_sample(&scheduler, pa, ta, replacement), None);
    }
    #[test]
    fn absent_budget_is_explicit_and_only_first_actual_initial_read_is_selected() {
        use ev_userspace_contract::session_note::{Operation, Outcome, Refusal, Request};
        let mut scheduler = Scheduler::new();
        let job = scheduler.create_job().unwrap();
        let process = scheduler.create_process(job).unwrap();
        let thread = scheduler.create_thread(process).unwrap();
        assert_eq!(cpu_sample(&scheduler, process, thread, job), None);
        let reply = |nonce, outcome| {
            u64::from_le_bytes(
                Request::new(Operation::Read, nonce)
                    .unwrap()
                    .reply(outcome)
                    .encode(),
            )
        };
        assert!(initial_note_reply(reply(1, Outcome::Read)));
        for value in [
            reply(2, Outcome::Read),
            reply(1, Outcome::Written),
            reply(1, Outcome::Refused(Refusal::Busy)),
            0,
            u64::MAX,
        ] {
            assert!(!initial_note_reply(value));
        }
        let mut retained = Retained::default();
        assert!(retained.select_note());
        assert!(!retained.select_note());
        assert!(retained.close());
        assert!(!retained.select_note());
    }
    #[test]
    fn two_cpu_endpoints_are_separate_from_event_cap_once_and_close_without_replacement() {
        let mut retained = Retained::default();
        // Fill the original event prefix; it does not consume CPU slots.
        for tick in 0..CAPACITY as u64 {
            retained.push(Row {
                tick,
                ..Row::default()
            });
        }
        let note = CpuPoint {
            phase: 9,
            tick: 120,
            process: 8,
            thread: 9,
            job: 10,
            ticket: 2,
            ..CpuPoint::default()
        };
        let present = CpuPoint {
            phase: 3,
            tick: 150,
            process: 8,
            thread: 9,
            job: 10,
            ticket: 3,
            call_epoch: 501,
            call: 44,
            sample: Some(CpuSample {
                job: 10,
                charged: 23,
                scheduler_tick: 150,
                budget: crate::scheduler::CpuBudget {
                    quota_ticks: 64,
                    period_ticks: 256,
                    window_start: 0,
                    window_end: 256,
                    consumed_ticks: 23,
                    reserved_ticks: 0,
                    remaining_ticks: 41,
                },
            }),
        };
        retained.push_cpu(note);
        retained.push_cpu(present);
        retained.push_cpu(CpuPoint { tick: 200, ..note });
        retained.push_cpu(CpuPoint {
            phase: 8,
            ..present
        });
        assert_eq!(retained.cpu_counts(), (3, 2, 1, 0));
        assert_eq!(retained.cpu_point(0), Some(note));
        assert_eq!(retained.cpu_point(1), Some(present));
        assert_eq!(core::mem::size_of::<Row>(), 88);
        assert_eq!(retained.cpu_point(2), None);
        assert_eq!(retained.counts(), (CAPACITY as u64, CAPACITY, 0));
        assert!(retained.close());
        retained.push_cpu(note);
        assert_eq!(retained.cpu_counts(), (3, 2, 1, 0));
        assert!(!retained.close());
    }
    #[test]
    fn exact_tokens_and_present_grammar_do_not_classify_neighbors() {
        for token in [*b"EVGARDY1", *b"EVGADON1", *b"EVAPCRD1"] {
            assert!(startup_token(token));
            for index in 0..8 {
                let mut changed = token;
                changed[index] ^= 1;
                assert!(!startup_token(changed));
            }
        }
        assert!(!startup_token(*b"EVSHCRD1"));
        assert!(!startup_token(*b"EVSHRDY1"));
        for frame in [1, 2, u32::MAX - 1] {
            let mut bytes = *b"EVP1\0\0\0\0";
            bytes[4..].copy_from_slice(&frame.to_le_bytes());
            assert!(present_request(u64::from_le_bytes(bytes)));
        }
        for bytes in [
            *b"EVP1\0\0\0\0",
            *b"EVP1\xff\xff\xff\xff",
            *b"EVR1\x01\0\0\0",
        ] {
            assert!(!present_request(u64::from_le_bytes(bytes)));
        }
    }
    #[test]
    fn actual_call_identity_is_fixed_and_rows_preserve_exact_phase_facts() {
        let mut retained = Retained::default();
        assert!(!retained.select_present(0, 1));
        assert!(!retained.select_present(501, 0));
        assert!(retained.select_present(501, 42));
        assert!(!retained.select_present(502, 42));
        assert!(!retained.select_present(501, 43));
        for phase in 3..=8 {
            retained.push(Row {
                phase,
                wire: 0,
                tick: 100 + u64::from(phase),
                process: 8,
                thread: 9,
                peer_process: 3,
                peer_thread: 4,
                endpoint: 31,
                ticket: 11,
                call_epoch: 501,
                call: 42,
                value: u64::from_le_bytes(*b"EVP1\x01\0\0\0"),
            });
        }
        assert_eq!(retained.counts(), (6, 6, 0));
        let row = retained.row(5).unwrap();
        assert_eq!(
            (row.phase, row.tick, row.process, row.thread),
            (8, 108, 8, 9)
        );
        assert_eq!(
            (row.peer_process, row.peer_thread, row.call_epoch, row.call),
            (3, 4, 501, 42)
        );
        assert_eq!((row.endpoint, row.ticket, row.wire), (31, 11, 0));
    }
    #[test]
    fn overflow_is_explicit_finite_and_cannot_replace_retained_prefix() {
        let mut retained = Retained::default();
        for tick in 0..CAPACITY as u64 + 5 {
            retained.push(Row {
                tick,
                ..Row::default()
            });
        }
        assert_eq!(retained.counts(), (CAPACITY as u64 + 5, CAPACITY, 5));
        for index in 0..CAPACITY {
            assert_eq!(retained.row(index).unwrap().tick, index as u64);
        }
        assert_eq!(retained.row(CAPACITY), None);
        retained.observed = u64::MAX;
        retained.overflow = u64::MAX;
        retained.push(Row::default());
        assert_eq!(retained.counts(), (u64::MAX, CAPACITY, u64::MAX));
    }
    #[test]
    fn outcome_flush_is_once_and_closes_all_future_recording() {
        let mut retained = Retained::default();
        assert!(retained.select_present(501, 42));
        retained.push(Row {
            phase: 1,
            tick: 120,
            ..Row::default()
        });
        assert!(retained.close());
        assert!(!retained.close());
        assert!(!retained.recording());
        assert!(!retained.select_present(501, 42));
        assert!(!retained.selected_present(501, 42));
        retained.push(Row {
            phase: 2,
            tick: 180,
            ..Row::default()
        });
        assert_eq!(retained.counts(), (1, 1, 0));
        assert_eq!(retained.row(0).unwrap().tick, 120);
    }
}
