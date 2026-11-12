//! Bounded FIFO registrations for one kernel-owned event source.
//! A single owner serializes event predicate checks, queue mutation and scheduler
//! transitions. Advance scheduler time before enrolling/signalling. IDs are local
//! to that scheduler; this is not a userspace authority or a concurrent queue.
use crate::{
    scheduler::{Error as SchedulerError, Scheduler, WaitTicket},
    time::Deadline,
};

pub const MAX_WAITERS: usize = 4;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Full,
    Scheduler(SchedulerError),
}
pub struct WaitQueue {
    tickets: [Option<WaitTicket>; MAX_WAITERS],
    count: usize,
}
impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            tickets: [None; MAX_WAITERS],
            count: 0,
        }
    }
    /// Retire deadline-woken or otherwise obsolete registrations. Old tickets
    /// cannot wake a new generation of a thread's wait on any queue.
    pub fn reap(&mut self, scheduler: &Scheduler) {
        let mut live = 0;
        for i in 0..self.count {
            let ticket = self.tickets[i].expect("packed wait queue");
            if scheduler.waiting(ticket) {
                self.tickets[live] = Some(ticket);
                live += 1;
            }
        }
        self.tickets[live..].fill(None);
        self.count = live;
    }
    /// Call only after checking the event predicate under the same serialization
    /// as producers. No fallible queue work follows the scheduler block.
    pub fn block(
        &mut self,
        scheduler: &mut Scheduler,
        cpu: usize,
        deadline: Deadline,
    ) -> Result<WaitTicket, Error> {
        self.reap(scheduler);
        if self.count == MAX_WAITERS {
            return Err(Error::Full);
        }
        let ticket = scheduler.block(cpu, deadline).map_err(Error::Scheduler)?;
        self.tickets[self.count] = Some(ticket);
        self.count += 1;
        Ok(ticket)
    }
    /// Signals readiness, not successful consumption. The resumed caller must
    /// recheck its predicate; timeout wins if time was advanced to the deadline.
    pub fn wake_one(&mut self, scheduler: &mut Scheduler) -> bool {
        self.reap(scheduler);
        if self.count == 0 {
            return false;
        }
        let ticket = self.tickets[0].expect("packed wait queue");
        self.tickets.copy_within(1..self.count, 0);
        self.count -= 1;
        self.tickets[self.count] = None;
        scheduler.wake(ticket)
    }
    pub fn is_empty(&mut self, scheduler: &Scheduler) -> bool {
        self.reap(scheduler);
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{State, WakeReason};
    fn setup(n: usize) -> Scheduler {
        let mut s = Scheduler::new();
        let job = s.create_job().unwrap();
        let p = s.create_process(job).unwrap();
        for _ in 0..n {
            s.create_thread(p).unwrap();
        }
        s
    }
    #[test]
    fn full_queue_does_not_block_the_rejected_runner_and_wakes_fifo() {
        let mut s = setup(MAX_WAITERS + 1);
        let mut q = WaitQueue::new();
        let deadline = Deadline::after(0, 10).unwrap();
        let mut first = None;
        for i in 0..MAX_WAITERS {
            let d = s.dispatch(0).unwrap().unwrap();
            if i == 0 {
                first = Some(d.thread);
            }
            q.block(&mut s, 0, deadline).unwrap();
        }
        let runner = s.dispatch(0).unwrap().unwrap().thread;
        assert_eq!(q.block(&mut s, 0, deadline), Err(Error::Full));
        assert_eq!(s.state(runner), Ok(State::Running(0)));
        assert!(q.wake_one(&mut s));
        assert_eq!(s.state(first.unwrap()), Ok(State::Ready));
        s.exit(0).unwrap();
        let dispatch = s.dispatch(0).unwrap().unwrap();
        assert_eq!(Some(dispatch.thread), first);
        assert_eq!(dispatch.wake, Some(WakeReason::Signal));
    }
    #[test]
    fn timeout_at_boundary_retires_registration_and_cannot_wake_new_wait() {
        let mut s = setup(1);
        let mut old = WaitQueue::new();
        let mut new = WaitQueue::new();
        s.dispatch(0).unwrap();
        let ticket = old
            .block(&mut s, 0, Deadline::after(0, 2).unwrap())
            .unwrap();
        s.advance(2).unwrap();
        assert_eq!(
            s.dispatch(0).unwrap().unwrap().wake,
            Some(WakeReason::Deadline)
        );
        new.block(&mut s, 0, Deadline::after(2, 2).unwrap())
            .unwrap();
        assert!(!s.wake(ticket));
        assert!(!old.wake_one(&mut s));
        assert!(old.is_empty(&s));
        assert!(new.wake_one(&mut s));
        assert!(!new.wake_one(&mut s));
    }
    #[test]
    fn failed_deadline_or_cpu_validation_never_publishes_a_waiter() {
        let mut s = setup(1);
        let mut q = WaitQueue::new();
        s.advance(5).unwrap();
        let t = s.dispatch(0).unwrap().unwrap().thread;
        assert_eq!(
            q.block(&mut s, 0, Deadline::after(0, 5).unwrap()),
            Err(Error::Scheduler(SchedulerError::Expired))
        );
        assert_eq!(
            q.block(&mut s, 1, Deadline::after(5, 1).unwrap()),
            Err(Error::Scheduler(SchedulerError::CpuIdle))
        );
        assert!(q.is_empty(&s));
        assert_eq!(s.state(t), Ok(State::Running(0)));
    }
    #[test]
    fn expired_slots_are_reused_without_extending_deadlines() {
        let mut s = setup(MAX_WAITERS);
        let mut q = WaitQueue::new();
        for _ in 0..MAX_WAITERS {
            s.dispatch(0).unwrap();
            q.block(&mut s, 0, Deadline::after(0, 1).unwrap()).unwrap();
        }
        s.advance(1).unwrap();
        assert!(!q.wake_one(&mut s));
        for _ in 0..MAX_WAITERS {
            assert_eq!(
                s.dispatch(0).unwrap().unwrap().wake,
                Some(WakeReason::Deadline)
            );
            q.block(&mut s, 0, Deadline::after(1, 1).unwrap()).unwrap();
        }
        assert_eq!(s.advance(2), Ok(MAX_WAITERS));
        assert!(q.is_empty(&s));
    }
}
