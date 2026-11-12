//! Internal, allocation-free scheduling state. No context switch or IRQ control.
//!
//! A single mutable owner serializes all transitions (including timeout/wake).
//! Handles are trusted, instance-local slot/generation identities, never
//! userspace capabilities. Explicit post-quiescence metadata reclamation permits
//! reuse without reviving old identities. Hardware retirement stays external.
use crate::time::Deadline;

pub const MAX_JOBS: usize = 16;
pub const MAX_PROCESSES: usize = 16;
pub const MAX_THREADS: usize = 32;
pub const MAX_CPUS: usize = 8;
const MAX_ID_GENERATION: u64 = u64::MAX >> 8;
const _: () = assert!(MAX_JOBS < 256 && MAX_PROCESSES < 256 && MAX_THREADS < 256);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobId(usize, u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessId(usize, u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadId(usize, u64);
impl JobId {
    pub fn diagnostic_id(self) -> u64 {
        ((self.1 - 1) << 8) | (self.0 as u64 + 1)
    }
}
impl ProcessId {
    pub fn diagnostic_id(self) -> u64 {
        ((self.1 - 1) << 8) | (self.0 as u64 + 1)
    }
}
impl ThreadId {
    pub fn diagnostic_id(self) -> u64 {
        ((self.1 - 1) << 8) | (self.0 as u64 + 1)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTicket {
    thread: ThreadId,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeReason {
    Signal,
    Deadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Running(usize),
    Blocked {
        deadline: Deadline,
        ticket: WaitTicket,
    },
    Exited,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Capacity,
    InvalidId,
    InvalidCpu,
    CpuBusy,
    CpuIdle,
    Expired,
    ClockReversed,
    Overflow,
    ProcessRunning,
    Terminated,
    Budget,
    Underflow,
    NotHeld,
    Admission,
    GenerationExhausted,
    NotQuiescent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub thread: ThreadId,
    pub process: ProcessId,
    pub job: JobId,
    pub wake: Option<WakeReason>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    CpuTicks,
    Frames,
    Processes,
    Threads,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits([u64; 4]);
impl Limits {
    pub const UNLIMITED: Self = Self([u64::MAX; 4]);
    pub fn limit(self, resource: Resource) -> u64 {
        self.0[resource as usize]
    }
    pub const fn new(cpu_ticks: u64, frames: u64, processes: u64, threads: u64) -> Self {
        Self([cpu_ticks, frames, processes, threads])
    }
}
#[derive(Clone, Copy)]
struct Job {
    parent: Option<JobId>,
    limits: Limits,
    used: [u64; 4],
    dispatches: u64,
}
#[derive(Clone, Copy)]
struct Thread {
    process: ProcessId,
    state: State,
    wake: Option<WakeReason>,
}

pub struct Scheduler {
    jobs: [Option<Job>; MAX_JOBS],
    processes: [Option<JobId>; MAX_PROCESSES],
    threads: [Option<Thread>; MAX_THREADS],
    job_generations: [u64; MAX_JOBS],
    process_generations: [u64; MAX_PROCESSES],
    thread_generations: [u64; MAX_THREADS],
    terminated: [bool; MAX_PROCESSES],
    admission_held: [bool; MAX_PROCESSES],
    admission_released: [bool; MAX_PROCESSES],
    running: [Option<ThreadId>; MAX_CPUS],
    cursor: usize,
    now: u64,
    generation: u64,
}
impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
impl Scheduler {
    /// Occupied Job/process/thread descriptors, including retained exited rows.
    /// Historical CPU usage is independent and is never reset by reclamation.
    pub fn metadata_usage(&self) -> (usize, usize, usize) {
        (
            self.jobs.iter().flatten().count(),
            self.processes.iter().flatten().count(),
            self.threads.iter().flatten().count(),
        )
    }
    pub const fn new() -> Self {
        Self {
            jobs: [None; MAX_JOBS],
            processes: [None; MAX_PROCESSES],
            threads: [None; MAX_THREADS],
            job_generations: [0; MAX_JOBS],
            process_generations: [0; MAX_PROCESSES],
            thread_generations: [0; MAX_THREADS],
            terminated: [false; MAX_PROCESSES],
            admission_held: [false; MAX_PROCESSES],
            admission_released: [false; MAX_PROCESSES],
            running: [None; MAX_CPUS],
            cursor: 0,
            now: 0,
            generation: 0,
        }
    }
    /// Fixed metadata staging for one serialized multi-table admission commit.
    /// No stacks, hardware context or physical ownership is copied. This copy
    /// must never drive independent dispatch; only a fully validated staged
    /// transaction may replace its original Scheduler under the same owner.
    pub(crate) fn staged_copy(&self) -> Self {
        Self {
            jobs: self.jobs,
            processes: self.processes,
            threads: self.threads,
            job_generations: self.job_generations,
            process_generations: self.process_generations,
            thread_generations: self.thread_generations,
            terminated: self.terminated,
            admission_held: self.admission_held,
            admission_released: self.admission_released,
            running: self.running,
            cursor: self.cursor,
            now: self.now,
            generation: self.generation,
        }
    }
    fn next_generation(generation: u64) -> Result<u64, Error> {
        generation
            .checked_add(1)
            .filter(|g| *g <= MAX_ID_GENERATION)
            .ok_or(Error::GenerationExhausted)
    }
    fn raw_job_index(&self, job: JobId) -> Result<usize, Error> {
        if job.1 == 0
            || self.job_generations.get(job.0) != Some(&job.1)
            || self.jobs.get(job.0).is_none_or(Option::is_none)
        {
            return Err(Error::InvalidId);
        }
        Ok(job.0)
    }
    fn job_index(&self, job: JobId) -> Result<usize, Error> {
        let index = self.raw_job_index(job)?;
        let mut parent = self.jobs[index].unwrap().parent;
        for _ in 0..MAX_JOBS {
            let Some(id) = parent else {
                return Ok(index);
            };
            parent = self.jobs[self.raw_job_index(id)?].unwrap().parent;
        }
        Err(Error::InvalidId)
    }
    fn process_index(&self, process: ProcessId) -> Result<usize, Error> {
        if process.1 == 0 || self.process_generations.get(process.0) != Some(&process.1) {
            return Err(Error::InvalidId);
        }
        let job = self
            .processes
            .get(process.0)
            .and_then(|p| *p)
            .ok_or(Error::InvalidId)?;
        self.job_index(job)?;
        Ok(process.0)
    }
    fn thread_index(&self, thread: ThreadId) -> Result<usize, Error> {
        if thread.1 == 0 || self.thread_generations.get(thread.0) != Some(&thread.1) {
            return Err(Error::InvalidId);
        }
        let process = self
            .threads
            .get(thread.0)
            .and_then(|t| *t)
            .ok_or(Error::InvalidId)?
            .process;
        self.process_index(process)?;
        Ok(thread.0)
    }
    pub fn create_job(&mut self) -> Result<JobId, Error> {
        self.create_bounded_job(None, Limits::UNLIMITED)
    }
    pub fn create_job_with_limits(&mut self, limits: Limits) -> Result<JobId, Error> {
        self.create_bounded_job(None, limits)
    }
    pub fn create_child_job(&mut self, parent: JobId, limits: Limits) -> Result<JobId, Error> {
        self.dispatches(parent)?;
        self.create_bounded_job(Some(parent), limits)
    }
    fn create_bounded_job(
        &mut self,
        parent: Option<JobId>,
        limits: Limits,
    ) -> Result<JobId, Error> {
        let slot = self
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = Self::next_generation(self.job_generations[slot])?;
        self.jobs[slot] = Some(Job {
            parent,
            limits,
            used: [0; 4],
            dispatches: 0,
        });
        self.job_generations[slot] = generation;
        Ok(JobId(slot, generation))
    }
    pub fn usage(&self, job: JobId, resource: Resource) -> Result<u64, Error> {
        Ok(self.jobs[self.job_index(job)?].unwrap().used[resource as usize])
    }
    /// Trusted retained identity lookup, not a capability authorization check.
    pub fn process_job(&self, process: ProcessId) -> Result<JobId, Error> {
        Ok(self.processes[self.process_index(process)?].unwrap())
    }
    /// Trusted retained identity lookup for causal-context attribution.
    pub fn thread_process(&self, thread: ThreadId) -> Result<ProcessId, Error> {
        Ok(self.threads[self.thread_index(thread)?].unwrap().process)
    }
    /// Preflight all resources at every ancestor before changing any count.
    /// Validate each retained parent generation before charging any ancestor.
    fn adjust(&mut self, job: JobId, amounts: [u64; 4], release: bool) -> Result<(), Error> {
        let mut chain = [0usize; MAX_JOBS];
        let mut count = 0;
        let mut current = Some(job);
        while let Some(id) = current {
            if count == MAX_JOBS {
                return Err(Error::Overflow);
            }
            let index = self.job_index(id)?;
            let entry = self.jobs[index].unwrap();
            for (i, amount) in amounts.iter().enumerate() {
                let next = if release {
                    entry.used[i].checked_sub(*amount).ok_or(Error::Underflow)?
                } else {
                    entry.used[i].checked_add(*amount).ok_or(Error::Overflow)?
                };
                if next > entry.limits.0[i] {
                    return Err(Error::Budget);
                }
            }
            chain[count] = index;
            count += 1;
            current = entry.parent;
        }
        for index in chain.into_iter().take(count) {
            let entry = self.jobs[index].as_mut().ok_or(Error::InvalidId)?;
            for (i, amount) in amounts.iter().enumerate() {
                if release {
                    entry.used[i] -= amount;
                } else {
                    entry.used[i] += amount;
                }
            }
        }
        Ok(())
    }
    pub fn charge_frames(&mut self, job: JobId, frames: u64) -> Result<(), Error> {
        self.adjust(job, [0, frames, 0, 0], false)
    }
    pub fn release_frames(&mut self, job: JobId, frames: u64) -> Result<(), Error> {
        self.adjust(job, [0, frames, 0, 0], true)
    }
    /// Sampled user/kernel-worker timer ticks, not elapsed wall time. The owner
    /// decides how to handle budget exhaustion before resuming the current CPU.
    pub fn charge_cpu(&mut self, cpu: usize, ticks: u64) -> Result<(), Error> {
        let thread = self.current(cpu)?;
        let process = self.thread_process(thread)?;
        let job = self.process_job(process)?;
        self.adjust(job, [ticks, 0, 0, 0], false)
    }
    pub fn create_process(&mut self, job: JobId) -> Result<ProcessId, Error> {
        self.create_process_with_hold(job, false)
    }
    /// Bootstrap preparation only. Threads can be constructed but cannot be
    /// dispatched. Only the incarnation activation transaction may release it.
    pub fn create_held_process(&mut self, job: JobId) -> Result<ProcessId, Error> {
        self.create_process_with_hold(job, true)
    }
    /// Validates a live, never-admitted bootstrap process and its actual Job.
    /// Instance-local IDs must refer to this Scheduler, as for every other API.
    pub fn held_process_job(&self, process: ProcessId) -> Result<JobId, Error> {
        let index = self.process_index(process)?;
        let job = self.processes[index].unwrap();
        if self.terminated[process.0] {
            return Err(Error::Terminated);
        }
        if !self.admission_held[process.0] || self.admission_released[process.0] {
            return Err(Error::NotHeld);
        }
        Ok(job)
    }
    pub fn job_limits(&self, job: JobId) -> Result<Limits, Error> {
        Ok(self.jobs[self.job_index(job)?].unwrap().limits)
    }
    /// Internal activation commit. The initial bootstrap Job contains exactly
    /// one process, one ready thread and the charged executable/root/stack frames.
    /// All checks precede the sole mutation; caller also owns the Authority borrow.
    pub(crate) fn admit_bootstrap(
        &mut self,
        process: ProcessId,
        job: JobId,
        thread: ThreadId,
        frames: u64,
    ) -> Result<(), Error> {
        if self.held_process_job(process)? != job {
            return Err(Error::Admission);
        }
        let initial = self.threads[self.thread_index(thread)?].unwrap();
        if initial.process != process
            || initial.state != State::Ready
            || self
                .threads
                .iter()
                .flatten()
                .filter(|t| t.process == process)
                .count()
                != 1
            || self.usage(job, Resource::Processes)? != 1
            || self.usage(job, Resource::Threads)? != 1
            || self.usage(job, Resource::Frames)? != frames
        {
            return Err(Error::Admission);
        }
        self.admission_held[process.0] = false;
        self.admission_released[process.0] = true;
        Ok(())
    }
    /// General measured service admission uses the same initial one-process/
    /// one-thread/dedicated-Job checks, after its own loaded owner and live
    /// delegated authority are validated by the portable service registry.
    pub(crate) fn admit_service(
        &mut self,
        process: ProcessId,
        job: JobId,
        thread: ThreadId,
        frames: u64,
    ) -> Result<(), Error> {
        self.admit_bootstrap(process, job, thread, frames)
    }
    /// Blocks future dispatch first, including new/woken siblings. A currently
    /// running CPU must still return to the controller before teardown.
    pub(crate) fn inhibit_process(&mut self, process: ProcessId) -> Result<(), Error> {
        self.process_index(process)?;
        self.admission_held[process.0] = true;
        Ok(())
    }
    /// Trusted read-only dispatch gate for the actual retained process identity.
    /// A held process may retain accepted work and live mappings; this query is
    /// neither permission to reclaim nor a user-facing diagnostic lookup.
    pub fn dispatch_inhibited(&self, process: ProcessId) -> Result<bool, Error> {
        let index = self.process_index(process)?;
        Ok(self.admission_held[index])
    }
    pub(crate) fn process_terminated(&self, process: ProcessId) -> bool {
        self.process_index(process).is_ok() && self.terminated[process.0]
    }
    fn create_process_with_hold(&mut self, job: JobId, held: bool) -> Result<ProcessId, Error> {
        self.dispatches(job)?;
        let slot = self
            .processes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = Self::next_generation(self.process_generations[slot])?;
        self.adjust(job, [0, 0, 1, 0], false)?;
        self.processes[slot] = Some(job);
        self.process_generations[slot] = generation;
        self.terminated[slot] = false;
        self.admission_held[slot] = held;
        self.admission_released[slot] = !held;
        Ok(ProcessId(slot, generation))
    }
    pub fn create_thread(&mut self, process: ProcessId) -> Result<ThreadId, Error> {
        self.process_index(process)?;
        if self.terminated[process.0] {
            return Err(Error::Terminated);
        }
        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = Self::next_generation(self.thread_generations[slot])?;
        let job = self.process_job(process)?;
        self.adjust(job, [0, 0, 0, 1], false)?;
        self.threads[slot] = Some(Thread {
            process,
            state: State::Ready,
            wake: None,
        });
        self.thread_generations[slot] = generation;
        Ok(ThreadId(slot, generation))
    }
    /// All CPUs must relinquish this process before retirement. Failure leaves
    /// every sibling unchanged; ready/blocked siblings retire together. The
    /// kernel must first switch away from hardware contexts and active mappings.
    pub fn terminate_process(&mut self, process: ProcessId) -> Result<usize, Error> {
        self.process_index(process)?;
        // Validate every examined association and both representations of a
        // running CPU before any counter/thread transition can be committed.
        for (slot, thread) in self.threads.iter().enumerate() {
            let Some(thread) = thread else {
                continue;
            };
            let id = ThreadId(slot, self.thread_generations[slot]);
            self.thread_index(id)?;
            if let State::Running(cpu) = thread.state {
                if self.running.get(cpu) != Some(&Some(id)) {
                    return Err(Error::InvalidId);
                }
                if thread.process == process {
                    return Err(Error::ProcessRunning);
                }
            }
        }
        for (cpu, thread) in self.running.iter().enumerate() {
            if thread.is_some() {
                self.current(cpu)?;
            }
        }
        if self.terminated[process.0] {
            return Ok(0);
        }
        let retired = self
            .threads
            .iter()
            .flatten()
            .filter(|t| t.process == process && t.state != State::Exited)
            .count();
        let job = self.process_job(process)?;
        self.adjust(job, [0, 0, 1, retired as u64], true)?;
        for t in self
            .threads
            .iter_mut()
            .flatten()
            .filter(|t| t.process == process)
        {
            t.state = State::Exited;
            t.wake = None;
        }
        self.terminated[process.0] = true;
        Ok(retired)
    }
    /// Explicit metadata-only reclamation after external hardware/IPC/reference
    /// quiescence. This does not stop a CPU, release a mapping or free a frame.
    /// Conservative bringup rule: the process has a dedicated Job, all its
    /// threads have exited and that Job has no charged frames. Shared-Job
    /// process reclamation requires future per-process frame accounting.
    pub fn reclaim_process(&mut self, process: ProcessId) -> Result<usize, Error> {
        let index = self.process_index(process)?;
        let job = self.processes[index].unwrap();
        let mut threads = 0;
        for (slot, thread) in self.threads.iter().enumerate() {
            let Some(thread) = thread else {
                continue;
            };
            self.thread_index(ThreadId(slot, self.thread_generations[slot]))?;
            if thread.process == process {
                if matches!(thread.state, State::Running(_)) {
                    return Err(Error::ProcessRunning);
                }
                if thread.state != State::Exited {
                    return Err(Error::NotQuiescent);
                }
                threads += 1;
            }
        }
        for (cpu, current) in self.running.iter().enumerate() {
            if current.is_some() {
                let thread = self.current(cpu)?;
                if self.thread_process(thread)? == process {
                    return Err(Error::ProcessRunning);
                }
            }
        }
        for (slot, parent) in self.processes.iter().enumerate() {
            if let Some(parent) = parent {
                self.process_index(ProcessId(slot, self.process_generations[slot]))?;
                if slot != index && *parent == job {
                    return Err(Error::NotQuiescent);
                }
            }
        }
        if !self.terminated[index] || self.usage(job, Resource::Frames)? != 0 {
            return Err(Error::NotQuiescent);
        }
        // No fallible work remains. Counters were released at termination/HAL
        // cleanup; identity counters, clock, cursor and wait sequence persist.
        for thread in &mut self.threads {
            if thread.is_some_and(|t| t.process == process) {
                *thread = None;
            }
        }
        self.processes[index] = None;
        self.terminated[index] = false;
        self.admission_held[index] = false;
        self.admission_released[index] = false;
        Ok(threads)
    }
    /// Reclaim a Job descriptor only after every process and child Job descriptor
    /// is gone and all LIVE resources are zero. Consumed CPU ticks remain charged
    /// to surviving ancestors; removal never refunds historical usage. External
    /// owners must already have retired all hardware/IPC/registry references.
    pub fn reclaim_job(&mut self, job: JobId) -> Result<(), Error> {
        let index = self.job_index(job)?;
        for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
            if self.usage(job, resource)? != 0 {
                return Err(Error::NotQuiescent);
            }
        }
        for (slot, process) in self.processes.iter().enumerate() {
            if let Some(parent) = process {
                self.process_index(ProcessId(slot, self.process_generations[slot]))?;
                if *parent == job {
                    return Err(Error::NotQuiescent);
                }
            }
        }
        for (slot, child) in self.jobs.iter().enumerate() {
            if let Some(child) = child {
                self.job_index(JobId(slot, self.job_generations[slot]))?;
                if child.parent == Some(job) {
                    return Err(Error::NotQuiescent);
                }
            }
        }
        for (slot, thread) in self.threads.iter().enumerate() {
            if thread.is_some() {
                self.thread_index(ThreadId(slot, self.thread_generations[slot]))?;
            }
        }
        self.jobs[index] = None;
        Ok(())
    }
    pub fn state(&self, thread: ThreadId) -> Result<State, Error> {
        Ok(self.threads[self.thread_index(thread)?].unwrap().state)
    }
    pub fn waiting(&self, ticket: WaitTicket) -> bool {
        matches!(self.state(ticket.thread), Ok(State::Blocked { ticket: current, .. }) if current == ticket)
    }
    pub fn dispatches(&self, job: JobId) -> Result<u64, Error> {
        Ok(self.jobs[self.job_index(job)?].unwrap().dispatches)
    }
    /// At most MAX_THREADS inspections. Fair across continuously ready threads
    /// when the caller returns control; no wall-clock fairness is claimed.
    pub fn dispatch(&mut self, cpu: usize) -> Result<Option<Dispatch>, Error> {
        if self.running.get(cpu).ok_or(Error::InvalidCpu)?.is_some() {
            self.current(cpu)?;
            return Err(Error::CpuBusy);
        }
        for offset in 0..MAX_THREADS {
            let slot = (self.cursor + offset) % MAX_THREADS;
            let Some(thread) = self.threads[slot] else {
                continue;
            };
            let id = ThreadId(slot, self.thread_generations[slot]);
            self.thread_index(id)?;
            if thread.state != State::Ready || self.admission_held[thread.process.0] {
                continue;
            }
            let job = self.process_job(thread.process)?;
            let count = self
                .dispatches(job)?
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            // Validate all fallible work before committing the transition.
            self.jobs[job.0]
                .as_mut()
                .ok_or(Error::InvalidId)?
                .dispatches = count;
            self.threads[slot] = Some(Thread {
                state: State::Running(cpu),
                wake: None,
                ..thread
            });
            self.running[cpu] = Some(id);
            self.cursor = (slot + 1) % MAX_THREADS;
            return Ok(Some(Dispatch {
                thread: id,
                process: thread.process,
                job,
                wake: thread.wake,
            }));
        }
        Ok(None)
    }
    /// Actual live running identity, for serialized kernel object dispatch only.
    pub(crate) fn running_thread(&self, cpu: usize) -> Result<ThreadId, Error> {
        self.current(cpu)
    }
    fn current(&self, cpu: usize) -> Result<ThreadId, Error> {
        let id = self
            .running
            .get(cpu)
            .ok_or(Error::InvalidCpu)?
            .ok_or(Error::CpuIdle)?;
        if self.threads[self.thread_index(id)?].unwrap().state != State::Running(cpu) {
            return Err(Error::InvalidId);
        }
        Ok(id)
    }
    fn stop(&mut self, cpu: usize, state: State) -> Result<ThreadId, Error> {
        let id = self.current(cpu)?;
        if state == State::Exited {
            let process = self.thread_process(id)?;
            let job = self.process_job(process)?;
            self.adjust(job, [0, 0, 0, 1], true)?;
        }
        self.threads[id.0].as_mut().unwrap().state = state;
        self.running[cpu] = None;
        Ok(id)
    }
    pub fn yield_cpu(&mut self, cpu: usize) -> Result<ThreadId, Error> {
        self.stop(cpu, State::Ready)
    }
    pub fn exit(&mut self, cpu: usize) -> Result<ThreadId, Error> {
        self.stop(cpu, State::Exited)
    }
    /// Read-only preflight for a serialized cross-table wait commit. This checks
    /// the current thread, absolute deadline and remaining wait sequence before
    /// a dispatcher accepts RPC/enqueues work. It neither issues a ticket nor
    /// changes clock, state or counters; the same owner must retain serialization
    /// through the following block operation.
    pub fn check_block(&self, cpu: usize, deadline: Deadline) -> Result<(), Error> {
        self.current(cpu)?;
        if deadline.reached(self.now) {
            return Err(Error::Expired);
        }
        self.generation.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }
    pub fn block(&mut self, cpu: usize, deadline: Deadline) -> Result<WaitTicket, Error> {
        self.check_block(cpu, deadline)?;
        let thread = self.current(cpu)?;
        let generation = self.generation + 1;
        let ticket = WaitTicket { thread, generation };
        self.stop(cpu, State::Blocked { deadline, ticket })?;
        self.generation = generation;
        Ok(ticket)
    }
    /// Signal succeeds exactly once for the current wait. Old tickets cannot
    /// wake a later wait, including after a timeout. Update time before signals.
    pub fn wake(&mut self, ticket: WaitTicket) -> bool {
        let Ok(index) = self.thread_index(ticket.thread) else {
            return false;
        };
        let thread = self.threads[index].as_mut().unwrap();
        if !matches!(thread.state, State::Blocked { ticket: current, .. } if current == ticket) {
            return false;
        }
        thread.state = State::Ready;
        thread.wake = Some(WakeReason::Signal);
        true
    }
    /// One bounded scan. Time cannot move backward; timeout wins when advance
    /// reaches the deadline before a signal is processed by the caller.
    pub fn advance(&mut self, now: u64) -> Result<usize, Error> {
        if now < self.now {
            return Err(Error::ClockReversed);
        }
        // Preflight all identities before waking even the first thread; an
        // invalid retained association cannot produce a partial clock advance.
        for (slot, thread) in self.threads.iter().enumerate() {
            let Some(thread) = thread else {
                continue;
            };
            let id = ThreadId(slot, self.thread_generations[slot]);
            self.thread_index(id)?;
            if matches!(thread.state, State::Blocked { ticket, .. } if ticket.thread != id) {
                return Err(Error::InvalidId);
            }
        }
        for (cpu, thread) in self.running.iter().enumerate() {
            if thread.is_some() {
                self.current(cpu)?;
            }
        }
        let mut woken = 0;
        for thread in self.threads.iter_mut().flatten() {
            if matches!(thread.state, State::Blocked { deadline, .. } if deadline.reached(now)) {
                thread.state = State::Ready;
                thread.wake = Some(WakeReason::Deadline);
                woken += 1;
            }
        }
        self.now = now;
        Ok(woken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unchanged(s: &Scheduler, before: &Scheduler) {
        assert_eq!(
            s.jobs
                .map(|j| j.map(|j| (j.parent, j.limits, j.used, j.dispatches))),
            before
                .jobs
                .map(|j| j.map(|j| (j.parent, j.limits, j.used, j.dispatches)))
        );
        assert_eq!(s.processes, before.processes);
        assert_eq!(
            s.threads.map(|t| t.map(|t| (t.process, t.state, t.wake))),
            before
                .threads
                .map(|t| t.map(|t| (t.process, t.state, t.wake)))
        );
        assert_eq!(s.job_generations, before.job_generations);
        assert_eq!(s.process_generations, before.process_generations);
        assert_eq!(s.thread_generations, before.thread_generations);
        assert_eq!(s.terminated, before.terminated);
        assert_eq!(s.admission_held, before.admission_held);
        assert_eq!(s.admission_released, before.admission_released);
        assert_eq!(s.running, before.running);
        assert_eq!(
            (s.cursor, s.now, s.generation),
            (before.cursor, before.now, before.generation)
        );
    }
    fn single() -> (Scheduler, JobId, ProcessId, ThreadId) {
        let mut s = Scheduler::new();
        let j = s.create_job().unwrap();
        let p = s.create_process(j).unwrap();
        let t = s.create_thread(p).unwrap();
        (s, j, p, t)
    }
    #[test]
    fn admission_hold_blocks_every_cpu_and_new_siblings_without_blocking_peers() {
        let mut s = Scheduler::new();
        let job = s.create_job().unwrap();
        let held = s.create_held_process(job).unwrap();
        let a = s.create_thread(held).unwrap();
        let peer = s.create_process(job).unwrap();
        let b = s.create_thread(peer).unwrap();
        assert_eq!(s.held_process_job(held), Ok(job));
        assert_eq!(s.held_process_job(peer), Err(Error::NotHeld));
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, b);
        let c = s.create_thread(held).unwrap();
        for cpu in 1..MAX_CPUS {
            assert_eq!(s.dispatch(cpu), Ok(None));
        }
        s.exit(0).unwrap();
        assert_eq!(s.dispatch(0), Ok(None));
        assert_eq!(s.state(a), Ok(State::Ready));
        assert_eq!(s.state(c), Ok(State::Ready));
        assert_eq!(s.terminate_process(held), Ok(2));
        assert_eq!(s.held_process_job(held), Err(Error::Terminated));
        assert_eq!(s.create_thread(held), Err(Error::Terminated));
        assert_eq!(s.usage(job, Resource::Threads), Ok(0));
    }
    #[test]
    fn ancestor_frame_limits_reject_atomically_and_release_never_underflows() {
        let mut s = Scheduler::new();
        let root = s.create_job_with_limits(Limits::new(10, 4, 2, 2)).unwrap();
        let a = s.create_child_job(root, Limits::new(8, 3, 2, 2)).unwrap();
        let b = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        s.charge_frames(a, 3).unwrap();
        assert_eq!(s.charge_frames(b, 2), Err(Error::Budget));
        assert_eq!(s.usage(b, Resource::Frames), Ok(0));
        assert_eq!(s.usage(root, Resource::Frames), Ok(3));
        assert_eq!(s.release_frames(a, 4), Err(Error::Underflow));
        assert_eq!(s.usage(a, Resource::Frames), Ok(3));
        s.release_frames(a, 1).unwrap();
        s.charge_frames(b, 2).unwrap();
        assert_eq!(s.usage(root, Resource::Frames), Ok(4));
        assert_eq!(s.usage(root, Resource::CpuTicks), Ok(0));
    }
    #[test]
    fn process_and_thread_budget_failures_do_not_consume_slots_or_charges() {
        let mut s = Scheduler::new();
        let j = s.create_job_with_limits(Limits::new(10, 0, 1, 1)).unwrap();
        let p = s.create_process(j).unwrap();
        assert_eq!(s.create_process(j), Err(Error::Budget));
        s.create_thread(p).unwrap();
        assert_eq!(s.create_thread(p), Err(Error::Budget));
        assert_eq!(s.usage(j, Resource::Processes), Ok(1));
        assert_eq!(s.usage(j, Resource::Threads), Ok(1));
        s.dispatch(0).unwrap();
        assert_eq!(s.terminate_process(p), Err(Error::ProcessRunning));
        s.exit(0).unwrap();
        s.terminate_process(p).unwrap();
        assert_eq!(s.usage(j, Resource::Threads), Ok(0));
        assert_eq!(s.usage(j, Resource::Processes), Ok(0));
        assert_eq!(s.create_thread(p), Err(Error::Terminated));
        let replacement = s.create_process(j).unwrap();
        assert_ne!(replacement, p);
        assert_eq!(s.usage(j, Resource::Processes), Ok(1));
    }
    #[test]
    fn sampled_cpu_ticks_follow_current_process_and_all_ancestors() {
        let mut s = Scheduler::new();
        let root = s.create_job_with_limits(Limits::new(3, 0, 2, 2)).unwrap();
        let a = s.create_child_job(root, Limits::new(2, 0, 1, 1)).unwrap();
        let b = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        let pa = s.create_process(a).unwrap();
        let pb = s.create_process(b).unwrap();
        s.create_thread(pa).unwrap();
        s.create_thread(pb).unwrap();
        assert_eq!(s.charge_cpu(0, 1), Err(Error::CpuIdle));
        s.dispatch(0).unwrap();
        s.charge_cpu(0, 2).unwrap();
        assert_eq!(s.charge_cpu(0, 1), Err(Error::Budget));
        s.exit(0).unwrap();
        s.terminate_process(pa).unwrap();
        assert_eq!(s.usage(a, Resource::CpuTicks), Ok(2));
        s.dispatch(0).unwrap();
        assert_eq!(s.charge_cpu(0, 2), Err(Error::Budget));
        assert_eq!(s.usage(b, Resource::CpuTicks), Ok(0));
        s.charge_cpu(0, 1).unwrap();
        assert_eq!(s.usage(root, Resource::CpuTicks), Ok(3));
        assert_eq!(s.usage(root, Resource::Processes), Ok(1));
    }
    #[test]
    fn accounting_overflow_never_partially_charges_ancestors() {
        let mut s = Scheduler::new();
        let root = s.create_job().unwrap();
        let child = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        s.charge_frames(root, u64::MAX).unwrap();
        assert_eq!(s.charge_frames(child, 1), Err(Error::Overflow));
        assert_eq!(s.usage(child, Resource::Frames), Ok(0));
        assert_eq!(s.usage(root, Resource::Frames), Ok(u64::MAX));
        assert_eq!(
            s.create_child_job(JobId(usize::MAX, 1), Limits::UNLIMITED),
            Err(Error::InvalidId)
        );
    }
    #[test]
    fn retirement_requires_all_cpu_runners_to_stop_before_any_sibling_changes() {
        let (mut s, _, p, first) = single();
        let blocked = s.create_thread(p).unwrap();
        let ready = s.create_thread(p).unwrap();
        s.dispatch(1).unwrap();
        s.dispatch(0).unwrap();
        let ticket = s.block(0, Deadline::after(0, 10).unwrap()).unwrap();
        assert_eq!(s.terminate_process(p), Err(Error::ProcessRunning));
        assert_eq!(s.state(first), Ok(State::Running(1)));
        assert!(s.waiting(ticket));
        assert_eq!(s.state(ready), Ok(State::Ready));
        s.exit(1).unwrap();
        assert_eq!(s.terminate_process(p), Ok(2));
        assert_eq!(s.state(blocked), Ok(State::Exited));
        assert_eq!(s.state(ready), Ok(State::Exited));
        assert!(!s.wake(ticket));
        assert_eq!(s.advance(10), Ok(0));
        assert_eq!(s.dispatch(0), Ok(None));
        assert_eq!(s.create_thread(p), Err(Error::Terminated));
        assert_eq!(s.terminate_process(p), Ok(0));
    }
    #[test]
    fn retirement_does_not_affect_other_processes_or_recycle_identity() {
        let (mut s, j, p, t) = single();
        let peer = s.create_process(j).unwrap();
        let survivor = s.create_thread(peer).unwrap();
        assert_eq!(
            s.terminate_process(ProcessId(usize::MAX, 1)),
            Err(Error::InvalidId)
        );
        assert_eq!(s.state(t), Ok(State::Ready));
        s.terminate_process(p).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, survivor);
        assert_ne!(s.create_process(j).unwrap(), p);
    }
    #[test]
    fn full_queue_is_fair_and_attribution_follows_process_owner() {
        let mut s = Scheduler::new();
        let jobs = [s.create_job().unwrap(), s.create_job().unwrap()];
        let processes = jobs.map(|j| s.create_process(j).unwrap());
        let threads: [_; MAX_THREADS] =
            core::array::from_fn(|i| s.create_thread(processes[i % 2]).unwrap());
        for round in 0..10 {
            for (i, t) in threads.iter().enumerate() {
                let dispatch = s.dispatch(0).unwrap().unwrap();
                assert_eq!(
                    dispatch,
                    Dispatch {
                        thread: *t,
                        process: processes[i % 2],
                        job: jobs[i % 2],
                        wake: None
                    }
                );
                s.yield_cpu(0).unwrap();
            }
            for j in jobs {
                assert_eq!(s.dispatches(j), Ok((round + 1) * 16));
            }
        }
    }
    #[test]
    fn cpu_slots_cannot_dispatch_the_same_thread_or_overwrite_a_runner() {
        let (mut s, _, p, a) = single();
        let b = s.create_thread(p).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, a);
        assert_eq!(s.dispatch(0), Err(Error::CpuBusy));
        assert_eq!(s.dispatch(1).unwrap().unwrap().thread, b);
        assert_eq!(s.dispatch(2), Ok(None));
        s.exit(0).unwrap();
        s.yield_cpu(1).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, b);
        assert_eq!(s.state(a), Ok(State::Exited));
        assert_eq!(s.state(b), Ok(State::Running(0)));
    }
    #[test]
    fn signal_is_once_only_and_old_ticket_cannot_wake_a_new_wait() {
        let (mut s, _, _, t) = single();
        s.dispatch(0).unwrap();
        let first = s.block(0, Deadline::after(0, 10).unwrap()).unwrap();
        assert_eq!(s.dispatch(0), Ok(None));
        assert!(s.wake(first));
        assert!(!s.wake(first));
        assert_eq!(
            s.dispatch(0).unwrap().unwrap().wake,
            Some(WakeReason::Signal)
        );
        let second = s.block(0, Deadline::after(0, 20).unwrap()).unwrap();
        assert!(!s.wake(first));
        assert!(matches!(s.state(t), Ok(State::Blocked { .. })));
        assert!(s.wake(second));
    }
    #[test]
    fn timeout_at_exact_boundary_wins_and_wake_reason_is_consumed_once() {
        let (mut s, _, _, _) = single();
        s.dispatch(0).unwrap();
        let ticket = s.block(0, Deadline::after(0, 10).unwrap()).unwrap();
        assert_eq!(s.advance(9), Ok(0));
        assert_eq!(s.dispatch(0), Ok(None));
        assert_eq!(s.advance(10), Ok(1));
        assert!(!s.wake(ticket));
        assert_eq!(s.advance(10), Ok(0));
        assert_eq!(
            s.dispatch(0).unwrap().unwrap().wake,
            Some(WakeReason::Deadline)
        );
        s.yield_cpu(0).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().wake, None);
    }
    #[test]
    fn invalid_transition_and_clock_errors_leave_current_runner_intact() {
        let (mut s, j, _, t) = single();
        assert_eq!(s.yield_cpu(0), Err(Error::CpuIdle));
        assert_eq!(s.dispatch(MAX_CPUS), Err(Error::InvalidCpu));
        s.advance(5).unwrap();
        s.dispatch(0).unwrap();
        assert_eq!(
            s.block(0, Deadline::after(0, 5).unwrap()),
            Err(Error::Expired)
        );
        assert_eq!(s.advance(4), Err(Error::ClockReversed));
        assert_eq!(s.state(t), Ok(State::Running(0)));
        assert_eq!(s.dispatches(j), Ok(1));
        s.generation = u64::MAX;
        assert_eq!(
            s.block(0, Deadline::after(5, 1).unwrap()),
            Err(Error::Overflow)
        );
        assert_eq!(s.state(t), Ok(State::Running(0)));
    }
    #[test]
    fn capacity_and_invalid_handles_are_explicit_and_exit_does_not_reuse_ids() {
        let (mut s, j, p, _) = single();
        for _ in 1..MAX_JOBS {
            s.create_job().unwrap();
        }
        assert_eq!(s.create_job(), Err(Error::Capacity));
        for _ in 1..MAX_PROCESSES {
            s.create_process(j).unwrap();
        }
        assert_eq!(s.create_process(j), Err(Error::Capacity));
        for _ in 1..MAX_THREADS {
            s.create_thread(p).unwrap();
        }
        s.dispatch(0).unwrap();
        s.exit(0).unwrap();
        assert_eq!(s.create_thread(p), Err(Error::Capacity));
        assert_eq!(
            s.create_process(JobId(usize::MAX, 1)),
            Err(Error::InvalidId)
        );
        assert_eq!(
            s.create_thread(ProcessId(usize::MAX, 1)),
            Err(Error::InvalidId)
        );
        assert_eq!(s.state(ThreadId(usize::MAX, 1)), Err(Error::InvalidId));
    }
    #[test]
    fn dispatch_counter_cannot_wrap_or_partially_commit() {
        let (mut s, j, _, t) = single();
        s.jobs[j.0].as_mut().unwrap().dispatches = u64::MAX;
        assert_eq!(s.dispatch(0), Err(Error::Overflow));
        assert_eq!(s.state(t), Ok(State::Ready));
        assert_eq!(s.running[0], None);
        assert_eq!(s.cursor, 0);
        assert_eq!(s.dispatches(j), Ok(u64::MAX));
    }
    #[test]
    fn explicit_reuse_exceeds_all_tables_and_rejects_every_old_identity_and_wait() {
        let mut s = Scheduler::new();
        let root = s.create_job().unwrap();
        let peer_job = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        let peer = s.create_process(peer_job).unwrap();
        let peer_thread = s.create_thread(peer).unwrap();
        assert_eq!(
            (
                root.diagnostic_id(),
                peer.diagnostic_id(),
                peer_thread.diagnostic_id()
            ),
            (1, 1, 1)
        );
        assert_eq!(s.dispatch(1).unwrap().unwrap().thread, peer_thread);
        let mut previous: [Option<(JobId, ProcessId, ThreadId, WaitTicket)>; 128] = [None; 128];
        for round in 0..previous.len() {
            s.advance(round as u64 + 1).unwrap();
            let job = s.create_child_job(root, Limits::new(10, 1, 1, 1)).unwrap();
            let process = s.create_process(job).unwrap();
            let thread = s.create_thread(process).unwrap();
            s.charge_frames(job, 1).unwrap();
            assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
            s.charge_cpu(0, 1).unwrap();
            let ticket = s.block(0, Deadline::after(s.now, 10).unwrap()).unwrap();
            for &(old_job, old_process, old_thread, old_ticket) in
                previous[..round].iter().flatten()
            {
                assert_ne!(job, old_job);
                assert_ne!(process, old_process);
                assert_ne!(thread, old_thread);
                assert_ne!(process.diagnostic_id(), old_process.diagnostic_id());
                assert_ne!(thread.diagnostic_id(), old_thread.diagnostic_id());
                assert_eq!(s.usage(old_job, Resource::Frames), Err(Error::InvalidId));
                assert_eq!(s.dispatches(old_job), Err(Error::InvalidId));
                assert_eq!(s.job_limits(old_job), Err(Error::InvalidId));
                assert_eq!(s.create_process(old_job), Err(Error::InvalidId));
                assert_eq!(
                    s.create_child_job(old_job, Limits::UNLIMITED),
                    Err(Error::InvalidId)
                );
                assert_eq!(s.charge_frames(old_job, 1), Err(Error::InvalidId));
                assert_eq!(s.release_frames(old_job, 1), Err(Error::InvalidId));
                assert_eq!(s.reclaim_job(old_job), Err(Error::InvalidId));
                assert_eq!(s.process_job(old_process), Err(Error::InvalidId));
                assert_eq!(s.held_process_job(old_process), Err(Error::InvalidId));
                assert_eq!(s.create_thread(old_process), Err(Error::InvalidId));
                assert_eq!(s.terminate_process(old_process), Err(Error::InvalidId));
                assert_eq!(s.inhibit_process(old_process), Err(Error::InvalidId));
                assert_eq!(s.reclaim_process(old_process), Err(Error::InvalidId));
                assert!(!s.process_terminated(old_process));
                assert_eq!(s.state(old_thread), Err(Error::InvalidId));
                assert_eq!(s.thread_process(old_thread), Err(Error::InvalidId));
                assert!(!s.waiting(old_ticket));
                assert!(!s.wake(old_ticket));
                assert!(!s.wake(WaitTicket {
                    thread: old_thread,
                    generation: ticket.generation
                }));
                assert!(s.waiting(ticket));
            }
            assert!(s.wake(ticket));
            assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
            s.exit(0).unwrap();
            s.terminate_process(process).unwrap();
            s.release_frames(job, 1).unwrap();
            let preserved = (s.cursor, s.now, s.generation);
            assert_eq!(s.reclaim_process(process), Ok(1));
            s.reclaim_job(job).unwrap();
            assert_eq!((s.cursor, s.now, s.generation), preserved);
            assert_eq!(s.usage(root, Resource::CpuTicks), Ok(round as u64 + 1));
            assert_eq!(s.state(peer_thread), Ok(State::Running(1)));
            assert_eq!(s.thread_process(peer_thread), Ok(peer));
            assert_eq!(s.process_job(peer), Ok(peer_job));
            previous[round] = Some((job, process, thread, ticket));
        }
        assert_eq!(s.generation, 128);
        assert_eq!(s.usage(root, Resource::Frames), Ok(0));
        s.exit(1).unwrap();
        s.terminate_process(peer).unwrap();
        s.reclaim_process(peer).unwrap();
        s.reclaim_job(peer_job).unwrap();
        assert_eq!(s.usage(root, Resource::CpuTicks), Ok(128));
    }
    #[test]
    fn reclaimed_process_and_thread_stamps_cannot_admit_a_replacement_context() {
        let mut s = Scheduler::new();
        let job = s.create_job_with_limits(Limits::new(10, 1, 1, 1)).unwrap();
        let old = s.create_held_process(job).unwrap();
        let old_thread = s.create_thread(old).unwrap();
        s.charge_frames(job, 1).unwrap();
        s.admit_service(old, job, old_thread, 1).unwrap();
        s.terminate_process(old).unwrap();
        s.release_frames(job, 1).unwrap();
        s.reclaim_process(old).unwrap();
        let replacement = s.create_held_process(job).unwrap();
        let thread = s.create_thread(replacement).unwrap();
        s.charge_frames(job, 1).unwrap();
        assert_eq!(replacement.0, old.0);
        assert_eq!(thread.0, old_thread.0);
        assert_ne!(replacement, old);
        assert_ne!(thread, old_thread);
        let before = s.staged_copy();
        assert_eq!(s.admit_service(old, job, thread, 1), Err(Error::InvalidId));
        assert_eq!(
            s.admit_service(replacement, job, old_thread, 1),
            Err(Error::InvalidId)
        );
        unchanged(&s, &before);
        assert_eq!(s.dispatch(0), Ok(None));
        s.admit_service(replacement, job, thread, 1).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
    }
    #[test]
    fn reclamation_refuses_ready_running_unretired_charged_and_shared_job_owners() {
        let (mut s, job, process, thread) = single();
        let before = s.staged_copy();
        assert_eq!(s.reclaim_process(process), Err(Error::NotQuiescent));
        assert_eq!(s.reclaim_job(job), Err(Error::NotQuiescent));
        unchanged(&s, &before);
        s.charge_frames(job, 1).unwrap();
        s.dispatch(1).unwrap();
        let before = s.staged_copy();
        assert_eq!(s.reclaim_process(process), Err(Error::ProcessRunning));
        unchanged(&s, &before);
        s.exit(1).unwrap();
        assert_eq!(s.reclaim_process(process), Err(Error::NotQuiescent));
        s.terminate_process(process).unwrap();
        let before = s.staged_copy();
        assert_eq!(s.reclaim_process(process), Err(Error::NotQuiescent));
        unchanged(&s, &before);
        assert_eq!(s.state(thread), Ok(State::Exited));
        s.release_frames(job, 1).unwrap();
        assert_eq!(s.reclaim_job(job), Err(Error::NotQuiescent));
        assert_eq!(s.reclaim_process(process), Ok(1));
        s.reclaim_job(job).unwrap();
        let (mut shared, job, first, _) = single();
        let other = shared.create_process(job).unwrap();
        shared.terminate_process(first).unwrap();
        shared.terminate_process(other).unwrap();
        let before = shared.staged_copy();
        assert_eq!(shared.reclaim_process(first), Err(Error::NotQuiescent));
        unchanged(&shared, &before);
    }
    #[test]
    fn reclaimed_child_job_does_not_refund_cpu_or_allow_parent_reuse_while_owned() {
        let mut s = Scheduler::new();
        let root = s.create_job().unwrap();
        let child = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        assert_eq!(s.reclaim_job(root), Err(Error::NotQuiescent));
        let process = s.create_process(child).unwrap();
        let thread = s.create_thread(process).unwrap();
        s.dispatch(0).unwrap();
        s.charge_cpu(0, 7).unwrap();
        s.exit(0).unwrap();
        s.terminate_process(process).unwrap();
        s.reclaim_process(process).unwrap();
        assert_eq!(s.state(thread), Err(Error::InvalidId));
        assert_eq!(s.usage(child, Resource::CpuTicks), Ok(7));
        s.reclaim_job(child).unwrap();
        assert_eq!(s.usage(root, Resource::CpuTicks), Ok(7));
        let fresh = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        assert_eq!(fresh.0, child.0);
        assert_ne!(fresh, child);
        assert_eq!(s.usage(fresh, Resource::CpuTicks), Ok(0));
        assert_eq!(s.usage(root, Resource::CpuTicks), Ok(7));
    }
    #[test]
    fn stale_internal_parent_and_process_associations_fail_before_any_transition() {
        let mut s = Scheduler::new();
        let root = s.create_job().unwrap();
        let child = s.create_child_job(root, Limits::UNLIMITED).unwrap();
        let process = s.create_process(child).unwrap();
        let thread = s.create_thread(process).unwrap();
        s.job_generations[root.0] += 1;
        let before = s.staged_copy();
        assert_eq!(s.charge_frames(child, 1), Err(Error::InvalidId));
        assert_eq!(s.create_process(child), Err(Error::InvalidId));
        assert_eq!(s.process_job(process), Err(Error::InvalidId));
        assert_eq!(s.state(thread), Err(Error::InvalidId));
        assert_eq!(s.dispatch(0), Err(Error::InvalidId));
        assert_eq!(s.advance(1), Err(Error::InvalidId));
        unchanged(&s, &before);
        let (mut s, _, process, thread) = single();
        s.process_generations[process.0] += 1;
        let before = s.staged_copy();
        assert_eq!(s.thread_process(thread), Err(Error::InvalidId));
        assert_eq!(s.dispatch(0), Err(Error::InvalidId));
        assert_eq!(s.advance(1), Err(Error::InvalidId));
        unchanged(&s, &before);
        let (mut s, _, _, thread) = single();
        s.dispatch(0).unwrap();
        s.thread_generations[thread.0] += 1;
        let before = s.staged_copy();
        assert_eq!(s.charge_cpu(0, 1), Err(Error::InvalidId));
        assert_eq!(s.yield_cpu(0), Err(Error::InvalidId));
        assert_eq!(
            s.block(0, Deadline::after(0, 1).unwrap()),
            Err(Error::InvalidId)
        );
        unchanged(&s, &before);
    }
    #[test]
    fn generation_exhaustion_and_budget_failures_are_atomic_and_never_wrap() {
        for kind in 0..3 {
            let mut s = Scheduler::new();
            let job = if kind != 0 {
                Some(s.create_job().unwrap())
            } else {
                None
            };
            let process = if kind == 2 {
                Some(s.create_process(job.unwrap()).unwrap())
            } else {
                None
            };
            match kind {
                0 => s.job_generations[0] = MAX_ID_GENERATION,
                1 => s.process_generations[0] = MAX_ID_GENERATION,
                _ => s.thread_generations[0] = MAX_ID_GENERATION,
            }
            let before = s.staged_copy();
            let result = match kind {
                0 => s.create_job().map(|_| ()),
                1 => s.create_process(job.unwrap()).map(|_| ()),
                _ => s.create_thread(process.unwrap()).map(|_| ()),
            };
            assert_eq!(result, Err(Error::GenerationExhausted));
            unchanged(&s, &before);
        }
        let mut s = Scheduler::new();
        s.job_generations[0] = MAX_ID_GENERATION - 1;
        let job = s.create_job().unwrap();
        assert_eq!(job.1, MAX_ID_GENERATION);
        assert!(job.diagnostic_id() > 256);
        s.reclaim_job(job).unwrap();
        assert_eq!(s.create_job(), Err(Error::GenerationExhausted));
        let mut s = Scheduler::new();
        let job = s.create_job().unwrap();
        s.process_generations[0] = MAX_ID_GENERATION - 1;
        let process = s.create_process(job).unwrap();
        assert!(process.diagnostic_id() > 256);
        s.terminate_process(process).unwrap();
        s.reclaim_process(process).unwrap();
        assert_eq!(s.create_process(job), Err(Error::GenerationExhausted));
        let mut s = Scheduler::new();
        let job = s.create_job().unwrap();
        let process = s.create_process(job).unwrap();
        s.thread_generations[0] = MAX_ID_GENERATION - 1;
        let thread = s.create_thread(process).unwrap();
        assert!(thread.diagnostic_id() > 256);
        s.terminate_process(process).unwrap();
        s.reclaim_process(process).unwrap();
        let next = s.create_process(job).unwrap();
        assert_eq!(s.create_thread(next), Err(Error::GenerationExhausted));
        let mut s = Scheduler::new();
        let job = s.create_job_with_limits(Limits::new(1, 0, 0, 0)).unwrap();
        let before = s.staged_copy();
        assert_eq!(s.create_process(job), Err(Error::Budget));
        unchanged(&s, &before);
        s.jobs[job.0].as_mut().unwrap().limits = Limits::new(1, 0, 1, 0);
        let process = s.create_process(job).unwrap();
        let before = s.staged_copy();
        assert_eq!(s.create_thread(process), Err(Error::Budget));
        unchanged(&s, &before);
    }
    #[test]
    fn block_preflight_does_not_issue_a_ticket_or_mutate_at_wait_counter_exhaustion() {
        let (mut s, _, _, thread) = single();
        s.advance(5).unwrap();
        s.dispatch(0).unwrap();
        let deadline = Deadline::after(5, 2).unwrap();
        s.generation = u64::MAX - 1;
        let before = s.staged_copy();
        assert_eq!(s.check_block(0, deadline), Ok(()));
        unchanged(&s, &before);
        let ticket = s.block(0, deadline).unwrap();
        assert_eq!(ticket.generation, u64::MAX);
        assert!(s.wake(ticket));
        s.dispatch(0).unwrap();
        let before = s.staged_copy();
        assert_eq!(s.check_block(0, deadline), Err(Error::Overflow));
        assert_eq!(s.block(0, deadline), Err(Error::Overflow));
        unchanged(&s, &before);
        assert_eq!(s.state(thread), Ok(State::Running(0)));
    }

    #[test]
    fn inhibit_admitted_process_also_excludes_new_and_woken_siblings() {
        let mut s = Scheduler::new();
        let job = s.create_job().unwrap();
        let process = s.create_process(job).unwrap();
        let first = s.create_thread(process).unwrap();
        let peer = s.create_process(job).unwrap();
        let other = s.create_thread(peer).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, first);
        let deadline = Deadline::after(0, 100).unwrap();
        let ticket = s.block(0, deadline).unwrap();
        s.inhibit_process(process).unwrap();
        assert_eq!(s.dispatch_inhibited(process), Ok(true));
        let sibling = s.create_thread(process).unwrap();
        assert!(s.wake(ticket));
        for _ in 0..64 {
            assert_eq!(s.dispatch(0).unwrap().unwrap().thread, other);
            s.yield_cpu(0).unwrap();
        }
        assert_eq!(s.state(first), Ok(State::Ready));
        assert_eq!(s.state(sibling), Ok(State::Ready));
        assert_eq!(s.terminate_process(process), Ok(2));
        assert_eq!(s.state(first), Ok(State::Exited));
        assert_eq!(s.state(sibling), Ok(State::Exited));
    }
}
