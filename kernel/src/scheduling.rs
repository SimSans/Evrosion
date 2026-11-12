//! BSP bootstrap execution of the portable scheduler policy, not thread stacks.
use ev_kernel::scheduler::{Error, Scheduler, State, WakeReason};
use ev_kernel::time::Deadline;

pub fn prove() -> u64 {
    let mut scheduler = Scheduler::new();
    let a = scheduler.create_job().unwrap();
    let b = scheduler.create_job().unwrap();
    let pa = scheduler.create_process(a).unwrap();
    let pb = scheduler.create_process(b).unwrap();
    let threads = [
        scheduler.create_thread(pa).unwrap(),
        scheduler.create_thread(pb).unwrap(),
    ];
    for _ in 0..16 {
        for t in threads {
            assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, t);
            scheduler.yield_cpu(0).unwrap();
        }
    }
    assert_eq!(scheduler.dispatches(a), Ok(16));
    assert_eq!(scheduler.dispatches(b), Ok(16));
    assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, threads[0]);
    let signaled = scheduler.block(0, Deadline::after(0, 4).unwrap()).unwrap();
    assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, threads[1]);
    let timed = scheduler.block(0, Deadline::after(0, 4).unwrap()).unwrap();
    assert_eq!(scheduler.dispatch(0), Ok(None));
    assert_eq!(scheduler.advance(3), Ok(0));
    assert!(scheduler.wake(signaled));
    assert!(!scheduler.wake(signaled));
    assert_eq!(
        scheduler.dispatch(0).unwrap().unwrap().wake,
        Some(WakeReason::Signal)
    );
    scheduler.exit(0).unwrap();
    assert_eq!(scheduler.advance(4), Ok(1));
    assert!(!scheduler.wake(timed));
    assert_eq!(
        scheduler.dispatch(0).unwrap().unwrap().wake,
        Some(WakeReason::Deadline)
    );
    scheduler.exit(0).unwrap();
    assert_eq!(scheduler.advance(3), Err(Error::ClockReversed));
    assert_eq!(scheduler.dispatch(0), Ok(None));
    for t in threads {
        assert_eq!(scheduler.state(t), Ok(State::Exited));
    }
    assert_eq!(scheduler.dispatches(a), Ok(18));
    assert_eq!(scheduler.dispatches(b), Ok(18));
    scheduler.dispatches(a).unwrap() + scheduler.dispatches(b).unwrap()
}
