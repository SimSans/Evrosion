//! Explicit userspace restart policy for the separate sustained-restart artifact.
use ev_userspace_contract::{Bootstrap, Event, echo, syscall};
use ev_userspace_runtime as rt;
const CYCLES: u32 = 64;
fn required(number: u64, a: u64, b: u64, c: u64) -> u64 {
    let reply = rt::call(number, a, b, c);
    if reply.status != 0 {
        rt::exit(130 + number);
    }
    reply.value
}
fn ping(endpoint: u64, value: u32) {
    let clock = rt::monotonic();
    if clock.status != 0 {
        rt::exit(170);
    }
    let deadline = clock.value.checked_add(32).unwrap_or_else(|| rt::exit(171));
    let response = echo::client_call(&mut rt::SyncEndpoint { endpoint }, value, deadline)
        .unwrap_or_else(|_| rt::exit(172));
    if response.value != value {
        rt::exit(173);
    }
}
fn start(job: u64, image: u64, requests: u64, responses: u64) -> u64 {
    let process = required(syscall::CREATE_PROCESS, job, image, 0);
    for (endpoint, role) in [(requests, 3), (responses, 4)] {
        required(syscall::DELEGATE, process, endpoint, role);
    }
    required(syscall::BIND_RECEIVER, requests, process, 0);
    required(syscall::START, process, 0, 0);
    process
}
pub fn run(bytes: &[u8], events: u64) {
    let record = Bootstrap::parse(bytes).unwrap_or_else(|_| rt::exit(174));
    let creator = record.find(3).unwrap_or_else(|| rt::exit(175));
    let image = record.find(4).unwrap_or_else(|| rt::exit(176));
    if record.grants().count() != 4
        || creator.kind != 5
        || creator.rights != 256
        || image.kind != 1
        || image.rights != 1
    {
        rt::exit(177);
    }
    let jobs = [
        required(syscall::CREATE_JOB, creator.handle, 0, 0),
        required(syscall::CREATE_JOB, creator.handle, 0, 0),
    ];
    let victim_requests = required(syscall::CREATE_ENDPOINT, creator.handle, 0, 0);
    let victim_responses = required(syscall::CREATE_ENDPOINT, creator.handle, 0, 0);
    let peer_requests = required(syscall::CREATE_ENDPOINT, creator.handle, 0, 0);
    let peer_responses = required(syscall::CREATE_ENDPOINT, creator.handle, 0, 0);
    let mut victim = start(jobs[0], image.handle, victim_requests, victim_responses);
    let peer = start(jobs[1], image.handle, peer_requests, peer_responses);
    for cycle in 0..CYCLES {
        ping(peer_requests, cycle * 2);
        ping(victim_requests, 0xdeadbeef);
        let clock = rt::monotonic();
        if clock.status != 0 {
            rt::exit(178);
        }
        let deadline = clock.value.checked_add(32).unwrap_or_else(|| rt::exit(179));
        loop {
            let state = rt::call(syscall::OBSERVE, victim, 0, 0);
            if state.status != 0 {
                rt::exit(180);
            }
            if state.value == 1 {
                break;
            }
            let now = rt::monotonic();
            if now.status != 0 || now.value >= deadline {
                rt::exit(181);
            }
            if rt::yield_now().status != 0 {
                rt::exit(182);
            }
        }
        required(syscall::REAP, victim, 0, 0);
        let old = victim;
        required(syscall::CLOSE, old, 0, 0);
        victim = start(jobs[0], image.handle, victim_requests, victim_responses);
        if victim == old || rt::call(syscall::OBSERVE, old, 0, 0).status == 0 {
            rt::exit(183);
        }
        ping(peer_requests, cycle * 2 + 1);
    }
    if rt::send(events, Event::ServiceResponded.encode()).status != 0 {
        rt::exit(184);
    }
    // Closing userspace handles does not discard the retained kernel image owner.
    required(syscall::CLOSE, victim, 0, 0);
    required(syscall::CLOSE, peer, 0, 0);
}
