use super::*;
use crate::scheduler::tests::unchanged;
use crate::{
    scheduler::{Limits, State},
    time::Deadline,
};

fn actor(s: &mut Scheduler, job: JobId) -> (super::super::ProcessId, super::super::ThreadId) {
    let process = s.create_process(job).unwrap();
    let thread = s.create_thread(process).unwrap();
    (process, thread)
}

#[test]
fn repeated_windows_keep_lifetime_usage_and_live_resource_limits() {
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(2, 4, 1, 1)).unwrap();
    s.configure_cpu_budget(job, 2, 4).unwrap();
    let (process, thread) = actor(&mut s, job);
    for window in 0..6 {
        for tick in 0..2 {
            assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
            assert_eq!(s.cpu_budget(job).unwrap().unwrap().reserved_ticks, 1);
            s.charge_cpu(0, 1).unwrap();
            assert_eq!(s.usage(job, Resource::CpuTicks), Ok(window * 2 + tick + 1));
            s.yield_cpu(0).unwrap();
        }
        assert_eq!(s.dispatch(0), Ok(None));
        s.advance(window * 4 + 3).unwrap();
        assert_eq!(s.dispatch(0), Ok(None));
        s.advance(window * 4 + 4).unwrap();
        let budget = s.cpu_budget(job).unwrap().unwrap();
        assert_eq!((budget.consumed_ticks, budget.remaining_ticks), (0, 2));
        assert_eq!(s.usage(job, Resource::CpuTicks), Ok((window + 1) * 2));
    }
    s.charge_frames(job, 4).unwrap();
    let before = s.staged_copy();
    assert_eq!(s.charge_frames(job, 1), Err(Error::Budget));
    assert_eq!(s.create_process(job), Err(Error::Budget));
    assert_eq!(s.create_thread(process), Err(Error::Budget));
    unchanged(&s, &before);
    s.release_frames(job, 4).unwrap();
    s.terminate_process(process).unwrap();
    s.reclaim_process(process).unwrap();
    assert_eq!(s.usage(job, Resource::CpuTicks), Ok(12));
    s.reclaim_job(job).unwrap();
    assert_eq!(s.metadata_usage(), (0, 0, 0));
}

#[test]
fn concurrent_reservations_protect_siblings_and_the_complete_parent_cap() {
    let mut s = Scheduler::new();
    let parent = s.create_job_with_limits(Limits::new(3, 0, 2, 2)).unwrap();
    let a = s.create_child_job(parent, Limits::new(2, 0, 1, 1)).unwrap();
    let b = s.create_child_job(parent, Limits::new(3, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(parent, 3, 10).unwrap();
    s.configure_cpu_budget(a, 2, 10).unwrap();
    s.configure_cpu_budget(b, 3, 10).unwrap();
    let (_, ta) = actor(&mut s, a);
    let (_, tb) = actor(&mut s, b);
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, ta);
    assert_eq!(s.dispatch(1).unwrap().unwrap().thread, tb);
    s.charge_cpu(0, 2).unwrap();
    let before = s.staged_copy();
    assert_eq!(s.charge_cpu(1, 2), Err(Error::Budget));
    unchanged(&s, &before);
    s.charge_cpu(1, 1).unwrap();
    s.yield_cpu(0).unwrap();
    s.yield_cpu(1).unwrap();
    assert_eq!(s.usage(a, Resource::CpuTicks), Ok(2));
    assert_eq!(s.usage(b, Resource::CpuTicks), Ok(1));
    assert_eq!(s.usage(parent, Resource::CpuTicks), Ok(3));
    assert_eq!(s.dispatch(0), Ok(None));
    s.advance(10).unwrap();
    assert!(s.dispatch(0).unwrap().is_some());
}

#[test]
fn exhausted_child_does_not_block_peer_with_parent_headroom() {
    let mut s = Scheduler::new();
    let parent = s.create_job_with_limits(Limits::new(4, 0, 2, 2)).unwrap();
    s.configure_cpu_budget(parent, 4, 8).unwrap();
    let app = s.create_child_job(parent, Limits::new(2, 0, 1, 1)).unwrap();
    let service = s.create_child_job(parent, Limits::new(2, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(app, 2, 8).unwrap();
    s.configure_cpu_budget(service, 2, 8).unwrap();
    let (_, ta) = actor(&mut s, app);
    let (_, ts) = actor(&mut s, service);
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, ta);
    s.charge_cpu(0, 2).unwrap();
    s.yield_cpu(0).unwrap();
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, ts);
    s.charge_cpu(0, 1).unwrap();
    s.yield_cpu(0).unwrap();
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, ts);
}

#[test]
fn reservations_are_idempotent_and_release_on_yield_block_and_exit() {
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(job, 1, 4).unwrap();
    let (_, thread) = actor(&mut s, job);
    s.dispatch(0).unwrap();
    s.reserve_cpu(0).unwrap();
    s.reserve_cpu(0).unwrap();
    assert_eq!(s.cpu_budget(job).unwrap().unwrap().reserved_ticks, 1);
    s.yield_cpu(0).unwrap();
    assert_eq!(s.cpu_budget(job).unwrap().unwrap().remaining_ticks, 1);
    s.dispatch(0).unwrap();
    let wait = s.block(0, Deadline::after(0, 3).unwrap()).unwrap();
    assert_eq!(s.cpu_budget(job).unwrap().unwrap().reserved_ticks, 0);
    assert!(s.wake(wait));
    s.dispatch(0).unwrap();
    s.charge_cpu(0, 1).unwrap();
    let before = s.staged_copy();
    assert_eq!(s.charge_cpu(0, 1), Err(Error::NotHeld));
    assert_eq!(s.reserve_cpu(0), Err(Error::Budget));
    unchanged(&s, &before);
    s.advance(4).unwrap();
    s.reserve_cpu(0).unwrap();
    s.exit(0).unwrap();
    assert_eq!(s.state(thread), Ok(State::Exited));
    assert_eq!(s.cpu_budget(job).unwrap().unwrap().reserved_ticks, 0);
    assert_eq!(s.usage(job, Resource::CpuTicks), Ok(1));
}

#[test]
fn running_reservations_survive_renewal_without_double_credit() {
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(1, 0, 1, 2)).unwrap();
    s.configure_cpu_budget(job, 1, 3).unwrap();
    let (p, _) = actor(&mut s, job);
    s.create_thread(p).unwrap();
    s.dispatch(0).unwrap();
    assert_eq!(s.dispatch(1), Ok(None));
    s.advance(30).unwrap();
    let budget = s.cpu_budget(job).unwrap().unwrap();
    assert_eq!(
        (
            budget.window_start,
            budget.window_end,
            budget.reserved_ticks,
            budget.remaining_ticks
        ),
        (30, 33, 1, 0)
    );
    assert_eq!(s.dispatch(1), Ok(None));
    s.charge_cpu(0, 1).unwrap();
    s.yield_cpu(0).unwrap();
    assert_eq!(s.dispatch(0), Ok(None));
    assert_eq!(s.usage(job, Resource::CpuTicks), Ok(1));
}

#[test]
fn fixed_ancestors_and_fixed_children_are_not_accidentally_renewed() {
    let mut s = Scheduler::new();
    let parent = s.create_job_with_limits(Limits::new(2, 0, 1, 1)).unwrap();
    let child = s.create_child_job(parent, Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(child, 1, 2).unwrap();
    actor(&mut s, child);
    for now in [0, 2] {
        s.advance(now).unwrap();
        s.dispatch(0).unwrap().unwrap();
        s.charge_cpu(0, 1).unwrap();
        s.yield_cpu(0).unwrap();
    }
    s.advance(4).unwrap();
    assert_eq!(s.dispatch(0), Ok(None));
    assert_eq!(s.usage(parent, Resource::CpuTicks), Ok(2));
    assert_eq!(s.cpu_budget(parent), Ok(None));
    let mut s = Scheduler::new();
    let parent = s.create_job_with_limits(Limits::new(2, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(parent, 2, 2).unwrap();
    let child = s.create_child_job(parent, Limits::new(1, 0, 1, 1)).unwrap();
    actor(&mut s, child);
    s.dispatch(0).unwrap();
    s.charge_cpu(0, 1).unwrap();
    s.yield_cpu(0).unwrap();
    s.advance(20).unwrap();
    assert_eq!(s.dispatch(0), Ok(None));
    assert_eq!(s.usage(child, Resource::CpuTicks), Ok(1));
}

#[test]
fn unequal_periods_enforce_both_ancestor_windows_without_catchup_credit() {
    let mut s = Scheduler::new();
    let parent = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    let child = s.create_child_job(parent, Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(parent, 1, 6).unwrap();
    s.configure_cpu_budget(child, 1, 4).unwrap();
    actor(&mut s, child);
    s.dispatch(0).unwrap();
    s.charge_cpu(0, 1).unwrap();
    s.yield_cpu(0).unwrap();
    s.advance(4).unwrap();
    assert_eq!(s.dispatch(0), Ok(None));
    s.advance(6).unwrap();
    s.dispatch(0).unwrap().unwrap();
    s.charge_cpu(0, 1).unwrap();
    s.yield_cpu(0).unwrap();
    s.advance(600).unwrap();
    assert_eq!(s.cpu_budget(parent).unwrap().unwrap().remaining_ticks, 1);
    assert_eq!(s.cpu_budget(child).unwrap().unwrap().remaining_ticks, 1);
    assert_eq!(s.usage(parent, Resource::CpuTicks), Ok(2));
}

#[test]
fn configuration_is_bounded_once_only_and_never_retunes_dispatched_subtrees() {
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(3, 0, 1, 1)).unwrap();
    for (quota, period) in [
        (0, 3),
        (1, 0),
        (4, 8),
        (3, 2),
        (u64::MAX, u64::MAX),
        (1, u64::MAX),
    ] {
        let before = s.staged_copy();
        assert_eq!(
            s.configure_cpu_budget(job, quota, period),
            Err(Error::InvalidBudget)
        );
        unchanged(&s, &before);
    }
    s.configure_cpu_budget(job, 2, 4).unwrap();
    let before = s.staged_copy();
    assert_eq!(s.configure_cpu_budget(job, 2, 4), Err(Error::Admission));
    unchanged(&s, &before);
    actor(&mut s, job);
    s.dispatch(0).unwrap();
    let child = s.create_child_job(job, Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(child, 1, 4).unwrap();
    let mut old = Scheduler::new();
    let p = old.create_job().unwrap();
    let c = old.create_child_job(p, Limits::new(1, 0, 1, 1)).unwrap();
    actor(&mut old, c);
    old.dispatch(0).unwrap();
    old.yield_cpu(0).unwrap();
    let before = old.staged_copy();
    assert_eq!(old.configure_cpu_budget(p, 1, 2), Err(Error::Admission));
    unchanged(&old, &before);
    let unused = old.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    old.dispatch(0).unwrap();
    let before = old.staged_copy();
    assert_eq!(
        old.configure_cpu_budget(unused, 1, 2),
        Err(Error::ProcessRunning)
    );
    unchanged(&old, &before);
}

#[test]
fn reaped_zero_tick_descendants_cannot_erase_ancestor_execution_history() {
    let mut s = Scheduler::new();
    let grandparent = s.create_job().unwrap();
    let parent = s
        .create_child_job(grandparent, Limits::new(2, 0, 1, 1))
        .unwrap();
    let child = s.create_child_job(parent, Limits::new(1, 0, 1, 1)).unwrap();
    let (process, _) = actor(&mut s, child);
    s.dispatch(0).unwrap();
    s.exit(0).unwrap();
    s.terminate_process(process).unwrap();
    s.reclaim_process(process).unwrap();
    s.reclaim_job(child).unwrap();
    assert_eq!(s.usage(parent, Resource::CpuTicks), Ok(0));
    assert_eq!(s.dispatches(parent), Ok(0));
    let before = s.staged_copy();
    assert_eq!(s.configure_cpu_budget(parent, 1, 2), Err(Error::Admission));
    unchanged(&s, &before);
    s.reclaim_job(parent).unwrap();
    let before = s.staged_copy();
    assert_eq!(
        s.configure_cpu_budget(grandparent, 1, 2),
        Err(Error::Admission)
    );
    unchanged(&s, &before);
    let fresh = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(fresh, 1, 2).unwrap();
}

#[test]
fn rollback_window_overflow_and_cumulative_overflow_are_atomic() {
    let mut s = Scheduler::new();
    s.advance(u64::MAX - 4).unwrap();
    let job = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(job, 1, 2).unwrap();
    actor(&mut s, job);
    s.dispatch(0).unwrap();
    let wait = s
        .block(0, Deadline::after(u64::MAX - 4, 4).unwrap())
        .unwrap();
    s.advance(u64::MAX - 2).unwrap();
    let before = s.staged_copy();
    assert_eq!(s.advance(u64::MAX - 3), Err(Error::ClockReversed));
    unchanged(&s, &before);
    assert_eq!(s.advance(u64::MAX), Err(Error::Overflow));
    unchanged(&s, &before);
    assert!(s.waiting(wait));
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(job, 1, 2).unwrap();
    actor(&mut s, job);
    s.dispatch(0).unwrap();
    s.jobs[job.0].as_mut().unwrap().used[0] = u64::MAX;
    let before = s.staged_copy();
    assert_eq!(s.charge_cpu(0, 1), Err(Error::Overflow));
    unchanged(&s, &before);
    s.yield_cpu(0).unwrap();
    let before = s.staged_copy();
    assert_eq!(s.dispatch(0), Err(Error::Overflow));
    unchanged(&s, &before);
}

#[test]
fn child_recreation_cannot_refund_ancestor_credit_or_revive_stale_job_ids() {
    let mut s = Scheduler::new();
    let parent = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(parent, 1, 8).unwrap();
    let old = s.create_child_job(parent, Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(old, 1, 8).unwrap();
    let (p, _) = actor(&mut s, old);
    s.dispatch(0).unwrap();
    s.charge_cpu(0, 1).unwrap();
    s.exit(0).unwrap();
    s.terminate_process(p).unwrap();
    s.reclaim_process(p).unwrap();
    s.reclaim_job(old).unwrap();
    let fresh = s.create_child_job(parent, Limits::new(1, 0, 1, 1)).unwrap();
    assert_ne!(fresh, old);
    s.configure_cpu_budget(fresh, 1, 8).unwrap();
    actor(&mut s, fresh);
    let before = s.staged_copy();
    assert_eq!(s.configure_cpu_budget(old, 1, 8), Err(Error::InvalidId));
    assert_eq!(s.cpu_budget(old), Err(Error::InvalidId));
    unchanged(&s, &before);
    assert_eq!(s.dispatch(0), Ok(None));
    assert_eq!(s.usage(parent, Resource::CpuTicks), Ok(1));
    s.advance(8).unwrap();
    assert!(s.dispatch(0).unwrap().is_some());
}

#[test]
fn guarded_wait_retains_deadline_and_ownership_while_other_jobs_renew() {
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    s.configure_cpu_budget(job, 1, 4).unwrap();
    let (_, thread) = actor(&mut s, job);
    s.dispatch(0).unwrap();
    let deadline = Deadline::after(0, 2).unwrap();
    let ticket = s.block_guarded(0, deadline).unwrap();
    assert_eq!(s.cpu_budget(job).unwrap().unwrap().reserved_ticks, 0);
    assert_eq!(s.advance(40), Ok(0));
    assert_eq!(s.state(thread), Ok(State::Blocked { deadline, ticket }));
    assert!(s.waiting(ticket));
    assert_eq!(s.dispatch(0), Ok(None));
    assert!(s.wake(ticket));
    assert!(!s.wake(ticket));
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
    let later = s.block(0, Deadline::after(40, 2).unwrap()).unwrap();
    assert!(!s.wake(ticket));
    assert_eq!(s.advance(42), Ok(1));
    assert!(!s.waiting(later));
}

#[test]
fn guarded_wait_rejection_and_retirement_never_reuse_a_stale_ticket() {
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(Limits::new(1, 0, 1, 1)).unwrap();
    let (process, thread) = actor(&mut s, job);
    s.advance(5).unwrap();
    s.dispatch(0).unwrap();
    let before = s.staged_copy();
    assert_eq!(
        s.block_guarded(0, Deadline::after(0, 5).unwrap()),
        Err(Error::Expired)
    );
    unchanged(&s, &before);
    let ticket = s.block_guarded(0, Deadline::after(5, 1).unwrap()).unwrap();
    s.terminate_process(process).unwrap();
    assert_eq!(s.state(thread), Ok(State::Exited));
    assert!(!s.wake(ticket));
    s.reclaim_process(process).unwrap();
    let (_, replacement) = actor(&mut s, job);
    assert_ne!(replacement, thread);
    s.dispatch(0).unwrap();
    let current = s.block(0, Deadline::after(5, 3).unwrap()).unwrap();
    assert!(!s.wake(ticket));
    assert_eq!(s.advance(8), Ok(1));
    assert!(!s.waiting(current));
}
