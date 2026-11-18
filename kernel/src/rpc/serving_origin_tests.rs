use super::*;
use crate::scheduler::ProcessId;

struct Fixture {
    a: Authority,
    s: Scheduler,
    rpc: Rpc,
    spaces: [SpaceId; 3],
    jobs: [JobId; 3],
    processes: [ProcessId; 3],
    threads: [ThreadId; 3],
    receive: [Handle; 2],
    send: [Handle; 2],
}
fn fixture() -> Fixture {
    let mut a = Authority::new();
    let spaces = core::array::from_fn(|_| a.create_space().unwrap());
    let mut s = Scheduler::new();
    let jobs = core::array::from_fn(|_| s.create_job().unwrap());
    let processes = core::array::from_fn(|i| s.create_process(jobs[i]).unwrap());
    let threads = core::array::from_fn(|i| s.create_thread(processes[i]).unwrap());
    let receive = core::array::from_fn(|i| {
        a.create_root(
            spaces[i + 1],
            Kind::Endpoint,
            Rights::SEND
                | Rights::RECEIVE
                | Rights::CONTROL
                | Rights::DERIVE
                | Rights::TRANSFER
                | Rights::REVOKE,
        )
        .unwrap()
    });
    let send = core::array::from_fn(|i| {
        a.derive(spaces[i + 1], receive[i], spaces[i], Rights::SEND)
            .unwrap()
    });
    let mut rpc = Rpc::new(NonZeroU64::new(91).unwrap());
    for i in 0..3 {
        rpc.register_thread(&a, &s, threads[i], jobs[i], spaces[i], None)
            .unwrap();
    }
    for i in 0..2 {
        rpc.bind_endpoint(
            &a,
            spaces[i + 1],
            receive[i],
            threads[i + 1],
            Policy::new(8, 0).unwrap(),
        )
        .unwrap();
    }
    Fixture {
        a,
        s,
        rpc,
        spaces,
        jobs,
        processes,
        threads,
        receive,
        send,
    }
}
fn deadline(tick: u64) -> Deadline {
    Deadline::after(0, tick).unwrap()
}
fn dispatch_to(s: &mut Scheduler, target: ThreadId) {
    if matches!(s.state(target), Ok(State::Running(_))) {
        return;
    }
    for _ in 0..MAX_THREADS {
        let d = s.dispatch(0).unwrap().unwrap();
        if d.thread == target {
            return;
        }
        s.yield_cpu(0).unwrap();
    }
    panic!("expected Ready receiver");
}
fn begin(f: &mut Fixture, index: usize, end: u64, now: u64) -> CallId {
    f.rpc
        .begin(
            &f.a,
            f.threads[index],
            f.send[index],
            deadline(end),
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        )
        .unwrap()
}
fn receiver(f: &Fixture, index: usize, id: CallId) -> ServingReceiver {
    ServingReceiver {
        thread: f.threads[index + 1],
        space: f.spaces[index + 1],
        endpoint: f.receive[index],
        nonce: id.serial(),
    }
}

#[test]
fn immediate_origin_is_derived_from_real_cross_domain_call_and_full_nonce() {
    let mut f = fixture();
    f.rpc.sequence = (1u64 << 40) + 7;
    let id = begin(&mut f, 0, 100, 1);
    dispatch_to(&mut f.s, f.threads[1]);
    let receive = receiver(&f, 0, id);
    let before = (
        f.rpc.sequence,
        f.rpc.now,
        f.rpc.calls,
        f.rpc.threads,
        f.rpc.endpoints,
    );
    let origin = f.rpc.serving_origin(&f.a, &f.s, receive, 2).unwrap();
    assert_eq!(
        [
            origin.field(0),
            origin.field(1),
            origin.field(2),
            origin.field(3),
            origin.field(4),
            origin.field(5),
            origin.field(6),
            origin.field(7)
        ],
        [
            Some(f.processes[0].diagnostic_id()),
            Some(f.threads[0].diagnostic_id()),
            Some(0),
            Some(91),
            Some(id.serial()),
            Some(
                f.a.authorize(f.spaces[1], f.receive[0], Kind::Endpoint, Rights::RECEIVE)
                    .unwrap()
                    .identity() as u64
            ),
            Some(100),
            Some(0)
        ]
    );
    assert_eq!(origin.field(8), None);
    assert_eq!(origin.field(u64::MAX), None);
    assert_ne!(origin.caller_process, f.processes[1].diagnostic_id());
    assert_eq!(
        before,
        (
            f.rpc.sequence,
            f.rpc.now,
            f.rpc.calls,
            f.rpc.threads,
            f.rpc.endpoints
        )
    );
    assert_eq!(f.rpc.outstanding(), 1);
    let truncated = ServingReceiver {
        nonce: id.serial() as u32 as u64,
        ..receive
    };
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, truncated, 2),
        Err(Error::StaleCall)
    );
    let receive_only =
        f.a.derive(f.spaces[1], f.receive[0], f.spaces[1], Rights::RECEIVE)
            .unwrap();
    assert_eq!(
        f.rpc
            .serving_origin(
                &f.a,
                &f.s,
                ServingReceiver {
                    endpoint: receive_only,
                    ..receive
                },
                2
            )
            .unwrap(),
        origin
    );
}

#[test]
fn receiver_context_rights_endpoint_and_live_scheduler_identity_are_required() {
    let mut f = fixture();
    let id = begin(&mut f, 0, 100, 1);
    let receive = receiver(&f, 0, id);
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, receive, 2),
        Err(Error::Identity)
    );
    dispatch_to(&mut f.s, f.threads[1]);
    assert_eq!(
        f.rpc.serving_origin(
            &f.a,
            &f.s,
            ServingReceiver {
                space: f.spaces[0],
                ..receive
            },
            2
        ),
        Err(Error::Identity)
    );
    for nonce in [0, id.serial() + 1, u64::MAX] {
        assert_eq!(
            f.rpc
                .serving_origin(&f.a, &f.s, ServingReceiver { nonce, ..receive }, 2),
            Err(Error::StaleCall)
        );
    }
    let memory =
        f.a.create_root(f.spaces[1], Kind::Memory, Rights::READ)
            .unwrap();
    assert_eq!(
        f.rpc.serving_origin(
            &f.a,
            &f.s,
            ServingReceiver {
                endpoint: memory,
                ..receive
            },
            2
        ),
        Err(Error::PermissionDenied)
    );
    let other =
        f.a.create_root(f.spaces[1], Kind::Endpoint, Rights::RECEIVE)
            .unwrap();
    assert_eq!(
        f.rpc.serving_origin(
            &f.a,
            &f.s,
            ServingReceiver {
                endpoint: other,
                ..receive
            },
            2
        ),
        Err(Error::PermissionDenied)
    );
    let send_only =
        f.a.derive(f.spaces[1], f.receive[0], f.spaces[1], Rights::SEND)
            .unwrap();
    assert_eq!(
        f.rpc.serving_origin(
            &f.a,
            &f.s,
            ServingReceiver {
                endpoint: send_only,
                ..receive
            },
            2
        ),
        Err(Error::PermissionDenied)
    );
    let index = f.rpc.thread_index(f.threads[1]).unwrap();
    let saved = f.rpc.threads[index];
    f.rpc.threads[index].as_mut().unwrap().job = f.jobs[0];
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, receive, 2),
        Err(Error::Identity)
    );
    f.rpc.threads[index] = saved;
    f.a.revoke(f.spaces[1], f.receive[0]).unwrap();
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, receive, 2),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn cancelled_and_expired_contexts_remain_readonly_until_real_callee_ack() {
    for mode in 0..3 {
        let mut f = fixture();
        let id = begin(&mut f, 0, 10, 1);
        dispatch_to(&mut f.s, f.threads[1]);
        let receive = receiver(&f, 0, id);
        let (now, status) = match mode {
            0 => {
                f.rpc.cancel(f.threads[0], id, 2).unwrap();
                (3, Status::Cancelled)
            }
            1 => (10, Status::DeadlineExceeded),
            _ => {
                f.rpc.expire(10).unwrap();
                (11, Status::DeadlineExceeded)
            }
        };
        let before = (
            f.rpc.sequence,
            f.rpc.now,
            f.rpc.calls,
            f.rpc.threads,
            f.rpc.endpoints,
        );
        let origin = f.rpc.serving_origin(&f.a, &f.s, receive, now).unwrap();
        assert_eq!(origin.status, status);
        assert_eq!(origin.caller_process, f.processes[0].diagnostic_id());
        assert_eq!(
            before,
            (
                f.rpc.sequence,
                f.rpc.now,
                f.rpc.calls,
                f.rpc.threads,
                f.rpc.endpoints
            )
        );
        assert_eq!(f.rpc.outstanding(), 1);
        assert_eq!(f.rpc.serving(f.threads[1]), Some(id));
        let completion = f.rpc.complete(f.threads[1], id, now).unwrap();
        assert!(!completion.deliver_reply);
        assert_eq!(completion.wake_caller, mode == 1);
        assert_eq!(
            f.rpc.serving_origin(&f.a, &f.s, receive, now),
            Err(Error::StaleCall)
        );
    }
}

#[test]
fn peer_dead_origin_is_pinned_and_reused_caller_generations_never_alias() {
    let mut f = fixture();
    let id = begin(&mut f, 0, 100, 1);
    dispatch_to(&mut f.s, f.threads[1]);
    let receive = receiver(&f, 0, id);
    f.s.terminate_process(f.processes[0]).unwrap();
    f.rpc.peer_died(&f.s, f.threads[0], 2).unwrap();
    let origin = f.rpc.serving_origin(&f.a, &f.s, receive, 3).unwrap();
    assert_eq!(origin.status, Status::PeerDied);
    assert_eq!(origin.field(7), Some(3));
    assert_eq!(origin.caller_process, f.processes[0].diagnostic_id());
    assert!(f.rpc.forget_thread(&f.s, f.threads[0]).is_err());
    // Combined lifecycle ownership forbids this premature scheduler reclaim;
    // even a violated integration cannot make this accessor name a new peer.
    f.s.reclaim_process(f.processes[0]).unwrap();
    let new = f.s.create_process(f.jobs[0]).unwrap();
    let new_thread = f.s.create_thread(new).unwrap();
    assert_ne!(new, f.processes[0]);
    assert_ne!(new_thread, f.threads[0]);
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, receive, 3),
        Err(Error::Identity)
    );
}

#[test]
fn nested_call_reports_immediate_caller_and_completed_nonce_never_replays() {
    let mut f = fixture();
    let parent = begin(&mut f, 0, 100, 1);
    let child = begin(&mut f, 1, 80, 2);
    dispatch_to(&mut f.s, f.threads[2]);
    let receive = receiver(&f, 1, child);
    let origin = f.rpc.serving_origin(&f.a, &f.s, receive, 3).unwrap();
    assert_eq!(origin.caller_process, f.processes[1].diagnostic_id());
    assert_eq!(origin.caller_thread, f.threads[1].diagnostic_id());
    assert_eq!(origin.original_deadline, 80);
    assert_eq!(f.rpc.context(child).unwrap().origin_job, f.jobs[0]);
    assert_eq!(f.rpc.context(child).unwrap().parent_call_id, Some(parent));
    f.rpc.complete(f.threads[2], child, 3).unwrap();
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, receive, 3),
        Err(Error::StaleCall)
    );
    let next = begin(&mut f, 1, 70, 4);
    assert_ne!(next, child);
    assert_eq!(
        f.rpc.serving_origin(&f.a, &f.s, receive, 4),
        Err(Error::StaleCall)
    );
    assert_eq!(
        f.rpc
            .serving_origin(&f.a, &f.s, receiver(&f, 1, next), 4)
            .unwrap()
            .call_serial,
        next.serial()
    );
}
