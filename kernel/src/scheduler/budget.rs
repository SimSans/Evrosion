//! Opt-in sampled-CPU windows. Only the serialized trusted scheduler owner may
//! configure them; this module exposes no userspace capability or syscall.
use super::{Error, JobId, MAX_CPUS, MAX_JOBS, Resource, Scheduler};
const _: () = assert!(MAX_CPUS <= u8::BITS as usize);

/// Copied diagnostics, never budget-changing authority. Remaining credit
/// excludes ticks reserved by actual running CPUs. Usage(CpuTicks) separately
/// retains monotonic lifetime consumption, including every descendant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuBudget {
    pub quota_ticks: u64,
    pub period_ticks: u64,
    pub window_start: u64,
    pub window_end: u64,
    pub consumed_ticks: u64,
    pub reserved_ticks: u64,
    pub remaining_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Window {
    quota: u64,
    period: u64,
    end: u64,
    used: u64,
}
impl Window {
    fn at(self, now: u64) -> Result<Self, Error> {
        if now < self.end {
            return Ok(self);
        }
        // Reanchor to the containing period, never issue missed-period credit.
        // Subtraction is safe: end is a checked sum of start + nonzero period.
        let start = self.end - self.period;
        let elapsed = (now - start) / self.period;
        let next_start = start
            .checked_add(elapsed.checked_mul(self.period).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            end: next_start.checked_add(self.period).ok_or(Error::Overflow)?,
            used: 0,
            ..self
        })
    }
}

impl Scheduler {
    /// One-time trusted installation before this Job or any descendant first
    /// dispatches. The existing CPU limit bounds the chosen per-period quota;
    /// other resource limits retain their meaning. Cumulative CPU accounting is
    /// not reset, and no configuration/replenishment operation is user-facing.
    /// First enable requires all CPUs returned to the controller. Later new,
    /// never-dispatched children may be configured while other actors run.
    pub fn configure_cpu_budget(
        &mut self,
        job: JobId,
        quota_ticks: u64,
        period_ticks: u64,
    ) -> Result<(), Error> {
        let index = self.job_index(job)?;
        if quota_ticks == 0
            || period_ticks == 0
            || quota_ticks == u64::MAX
            || period_ticks == u64::MAX
            || quota_ticks > period_ticks
            || quota_ticks > self.jobs[index].unwrap().limits.limit(Resource::CpuTicks)
        {
            return Err(Error::InvalidBudget);
        }
        let end = self.now.checked_add(period_ticks).ok_or(Error::Overflow)?;
        let target = self.jobs[index].unwrap();
        if target.cpu_window.is_some()
            || target.used[0] != 0
            || target.cpu_reserved != 0
            || target.subtree_dispatched
        {
            return Err(Error::Admission);
        }
        if !self.cpu_windows_enabled {
            for (cpu, current) in self.running.iter().enumerate() {
                if current.is_some() {
                    self.current(cpu)?;
                    return Err(Error::ProcessRunning);
                }
            }
        }
        self.jobs[index].as_mut().unwrap().cpu_window = Some(Window {
            quota: quota_ticks,
            period: period_ticks,
            end,
            used: 0,
        });
        self.cpu_windows_enabled = true;
        Ok(())
    }

    pub fn cpu_budget(&self, job: JobId) -> Result<Option<CpuBudget>, Error> {
        let entry = self.jobs[self.job_index(job)?].unwrap();
        entry
            .cpu_window
            .map(|window| {
                let reserved = u64::from(entry.cpu_reserved.count_ones());
                let remaining = window
                    .quota
                    .checked_sub(window.used.checked_add(reserved).ok_or(Error::Overflow)?)
                    .ok_or(Error::InvalidId)?;
                Ok(CpuBudget {
                    quota_ticks: window.quota,
                    period_ticks: window.period,
                    window_start: window.end - window.period,
                    window_end: window.end,
                    consumed_ticks: window.used,
                    reserved_ticks: reserved,
                    remaining_ticks: remaining,
                })
            })
            .transpose()
    }

    /// Earliest trusted window boundary, for an external interruptible idle
    /// owner. This does not advance time, wake a CPU or promise runnable work.
    pub fn next_cpu_renewal(&self) -> Option<u64> {
        self.jobs
            .iter()
            .flatten()
            .filter_map(|j| j.cpu_window.map(|w| w.end))
            .min()
    }

    pub(super) fn cpu_chain(&self, job: JobId) -> Result<([usize; MAX_JOBS], usize), Error> {
        let mut chain = [0; MAX_JOBS];
        let mut count = 0;
        let mut current = Some(job);
        while let Some(job) = current {
            if count == MAX_JOBS {
                return Err(Error::InvalidId);
            }
            let index = self.job_index(job)?;
            chain[count] = index;
            count += 1;
            current = self.jobs[index].unwrap().parent;
        }
        Ok((chain, count))
    }
    fn available(&self, index: usize) -> Result<u64, Error> {
        let entry = self.jobs[index].unwrap();
        let (limit, used) = entry.cpu_window.map_or(
            (entry.limits.limit(Resource::CpuTicks), entry.used[0]),
            |w| (w.quota, w.used),
        );
        limit
            .checked_sub(
                used.checked_add(u64::from(entry.cpu_reserved.count_ones()))
                    .ok_or(Error::Overflow)?,
            )
            .ok_or(Error::InvalidId)
    }

    pub(super) fn check_cpu_dispatch(&self, job: JobId, cpu: usize) -> Result<bool, Error> {
        let bit = 1u8 << cpu;
        if self
            .jobs
            .iter()
            .flatten()
            .any(|j| j.cpu_reserved & bit != 0)
        {
            return Err(Error::InvalidId);
        }
        let (chain, count) = self.cpu_chain(job)?;
        for index in chain.into_iter().take(count) {
            self.jobs[index].unwrap().used[0]
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            if self.available(index)? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn claim_cpu_dispatch(&mut self, job: JobId, cpu: usize) {
        let bit = 1u8 << cpu;
        let mut current = Some(job);
        for _ in 0..MAX_JOBS {
            let Some(job) = current else { break };
            let entry = self.jobs[job.0].as_mut().unwrap();
            entry.cpu_reserved |= bit;
            current = entry.parent;
        }
    }

    /// Acquire a single sampled tick before continuing an already Running
    /// context. Idempotent across ordinary nonblocking syscalls. An IRQ charge
    /// consumes it; yield/block/exit relinquishes any unused reservation.
    /// Legacy all-finite schedulers retain their old unrestricted resume path.
    pub fn reserve_cpu(&mut self, cpu: usize) -> Result<(), Error> {
        let thread = self.current(cpu)?;
        if !self.cpu_windows_enabled {
            return Ok(());
        }
        let job = self.process_job(self.thread_process(thread)?)?;
        if self.check_cpu_stop(cpu)? {
            return Ok(());
        }
        if !self.check_cpu_dispatch(job, cpu)? {
            return Err(Error::Budget);
        }
        self.claim_cpu_dispatch(job, cpu);
        Ok(())
    }

    /// Validate either one complete ancestral reservation or none. No unrelated
    /// Job may hold this CPU's credit. A post-charge Running context has none.
    pub(super) fn check_cpu_stop(&self, cpu: usize) -> Result<bool, Error> {
        let thread = self.current(cpu)?;
        let job = self.process_job(self.thread_process(thread)?)?;
        let (chain, count) = self.cpu_chain(job)?;
        let bit = 1u8 << cpu;
        let held = self.jobs[chain[0]].unwrap().cpu_reserved & bit != 0;
        for (slot, entry) in self.jobs.iter().enumerate() {
            let Some(entry) = entry else { continue };
            let expected = held && chain[..count].contains(&slot);
            if (entry.cpu_reserved & bit != 0) != expected {
                return Err(Error::InvalidId);
            }
        }
        Ok(held)
    }
    pub(super) fn release_cpu_reservation(&mut self, cpu: usize) {
        let bit = !(1u8 << cpu);
        for entry in self.jobs.iter_mut().flatten() {
            entry.cpu_reserved &= bit;
        }
    }

    pub(super) fn charge_windowed_cpu(&mut self, cpu: usize, ticks: u64) -> Result<(), Error> {
        let thread = self.current(cpu)?;
        let job = self.process_job(self.thread_process(thread)?)?;
        let reserved = self.check_cpu_stop(cpu)?;
        if ticks == 0 {
            return Ok(());
        }
        if !reserved {
            return Err(Error::NotHeld);
        }
        let (chain, count) = self.cpu_chain(job)?;
        for index in chain.into_iter().take(count) {
            let entry = self.jobs[index].unwrap();
            entry.used[0].checked_add(ticks).ok_or(Error::Overflow)?;
            // The current CPU already owns one credit; other CPUs' credits
            // remain unavailable even to a trusted batched accounting call.
            if ticks
                > self
                    .available(index)?
                    .checked_add(1)
                    .ok_or(Error::Overflow)?
            {
                return Err(Error::Budget);
            }
        }
        let bit = !(1u8 << cpu);
        for index in chain.into_iter().take(count) {
            let entry = self.jobs[index].as_mut().unwrap();
            entry.used[0] += ticks;
            if let Some(window) = &mut entry.cpu_window {
                window.used += ticks;
            }
            entry.cpu_reserved &= bit;
        }
        Ok(())
    }

    pub(super) fn check_cpu_advance(&self, now: u64) -> Result<(), Error> {
        for (slot, entry) in self.jobs.iter().enumerate() {
            let Some(entry) = entry else { continue };
            self.job_index(JobId(slot, self.job_generations[slot]))?;
            self.available(slot)?;
            if let Some(window) = entry.cpu_window {
                window.at(now)?;
            }
        }
        for cpu in 0..MAX_CPUS {
            if self.running[cpu].is_some() {
                self.check_cpu_stop(cpu)?;
            } else if self
                .jobs
                .iter()
                .flatten()
                .any(|j| j.cpu_reserved & (1 << cpu) != 0)
            {
                return Err(Error::InvalidId);
            }
        }
        Ok(())
    }
    pub(super) fn advance_cpu_windows(&mut self, now: u64) {
        for entry in self.jobs.iter_mut().flatten() {
            if let Some(window) = entry.cpu_window {
                entry.cpu_window = Some(window.at(now).unwrap());
            }
        }
    }
}

#[cfg(test)]
mod tests;
