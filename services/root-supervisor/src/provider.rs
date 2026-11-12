//! Actual Ring3 binding choice; Kernel supplies only ordinary owner mechanisms.
use ev_provider_test as policy;
use ev_userspace_runtime as rt;
fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let reply = rt::monotonic();
    require(reply.status == 0 && reply.capability == 0, 300);
    reply.value
}
fn yield_now(stop: u64) {
    require(now() < stop, 301);
    let reply = rt::yield_now();
    require(
        reply.status == 0 && reply.value == 0 && reply.capability == 0,
        302,
    );
}
fn send(endpoint: u64, bytes: [u8; 8], stop: u64) {
    loop {
        require(now() < stop, 303);
        let reply = rt::send(endpoint, bytes);
        require(reply.value == 0 && reply.capability == 0, 304);
        match reply.status {
            0 => return,
            2 => yield_now(stop),
            _ => rt::exit(305),
        }
    }
}
fn bind_self(endpoint: u64) {
    let reply = rt::call(rt::syscall::BIND_RECEIVER, endpoint, 0, 0);
    require(
        reply.status == 0 && reply.value == 0 && reply.capability == 0,
        306,
    );
}
use rt::syscall as s;
#[derive(Clone, Copy)]
struct ObservedIdentity {
    process: u64,
    thread: u64,
}
fn required(number: u64, a: u64, b: u64, c: u64) -> u64 {
    let r = rt::call(number, a, b, c);
    require(r.status == 0 && r.capability == 0, 400 + number);
    r.value
}
fn identity(control: u64) -> ObservedIdentity {
    const CANARY: u64 = 0x93d4_270b_6a51_c8ef;
    let r = rt::call4(s::PROCESS_IDENTITY, control, 0, 0, CANARY);
    require(r.serial == CANARY, 430);
    require(r.status == 0 && r.value != 0 && r.capability != 0, 440);
    // These full scheduler IDs correlate authenticated events only. Lifecycle
    // authority remains the separately retained live ProcessCONTROL handle.
    ObservedIdentity {
        process: r.value,
        thread: r.capability,
    }
}
fn wait_event(inbox: u64, event: policy::Event, expected: ObservedIdentity, stop: u64) {
    loop {
        require(now() < stop, 441);
        let r = rt::call4(s::RECEIVE_EVENT, inbox, 0, 0, 0);
        match r.status {
            0 => {
                if policy::Event::decode(r.value.to_le_bytes()) == Some(event)
                    && r.capability == expected.process
                    && r.serial == expected.thread
                {
                    return;
                }
            }
            2 => require(r.value == 0 && r.capability == 0 && r.serial == 0, 442),
            _ => rt::exit(443),
        }
        // Wrong source/body can never advance the binding transaction.
        yield_now(stop);
    }
}
fn create(job: u64, image: u64, roles: &[(u64, u64)]) -> u64 {
    let process = required(s::CREATE_PROCESS, job, image, 0);
    require(process != 0, 444);
    for &(source, selector) in roles {
        require(required(s::DELEGATE, process, source, selector) == 0, 445)
    }
    process
}
fn start_provider(job: u64, image: u64, request: u64, events: u64) -> u64 {
    let process = create(job, image, &[(request, 1), (events, 2)]);
    require(required(s::BIND_RECEIVER, request, process, 0) == 0, 446);
    require(required(s::START, process, 0, 0) == 0, 447);
    process
}
pub fn run(bytes: &[u8], stop: u64) -> ! {
    let [probe, outer, creator, image_a, image_b, image_consumer] =
        policy::roles(bytes, policy::ROOT_LIMITS, &policy::ROOT_ROLES)
            .unwrap_or_else(|| rt::exit(448));
    let r = rt::inspect(probe, 1);
    require(r.status == 0 && r.capability == 0, 449);
    send(outer, ev_userspace_contract::Event::Ready.encode(), stop);
    let provider_job = required(s::CREATE_JOB, creator, 0, 0);
    let consumer_job = required(s::CREATE_JOB, creator, 0, 0);
    let request = required(s::CREATE_ENDPOINT, creator, 0, 0);
    let events = required(s::CREATE_ENDPOINT, creator, 0, 0);
    let control = required(s::CREATE_ENDPOINT, creator, 0, 0);
    require(
        request != events && request != control && events != control,
        450,
    );
    bind_self(events);
    let provider_a = start_provider(provider_job, image_a, request, events);
    let actual_a = identity(provider_a);
    wait_event(events, policy::Event::ProviderReady, actual_a, stop);
    let consumer = create(
        consumer_job,
        image_consumer,
        &[(request, 1), (events, 2), (control, 3)],
    );
    require(required(s::BIND_RECEIVER, control, consumer, 0) == 0, 451);
    require(required(s::START, consumer, 0, 0) == 0, 452);
    let actual_consumer = identity(consumer);
    wait_event(
        events,
        policy::Event::PhaseComplete { phase: 1 },
        actual_consumer,
        stop,
    );
    // PhaseComplete follows actual replies. Busy must fail before mutation;
    // the source never converts an accepted timeout into permission to reap.
    require(required(s::STOP_PROCESS, provider_a, 0, 0) == 0, 453);
    require(required(s::OBSERVE, provider_a, 0, 0) == 1, 454);
    require(required(s::REAP, provider_a, 0, 0) == 0, 455);
    require(required(s::CLOSE, provider_a, 0, 0) == 0, 456);
    let provider_b = start_provider(provider_job, image_b, request, events);
    let actual_b = identity(provider_b);
    require(
        actual_b.process != actual_a.process && actual_b.thread != actual_a.thread,
        457,
    );
    let unchanged = identity(consumer);
    require(
        unchanged.process == actual_consumer.process && unchanged.thread == actual_consumer.thread,
        458,
    );
    wait_event(events, policy::Event::ProviderReady, actual_b, stop);
    // Same consumer process, client instance, installed SEND and Endpoint object.
    send(control, policy::CONTINUE, stop);
    wait_event(
        events,
        policy::Event::PhaseComplete { phase: 2 },
        actual_consumer,
        stop,
    );
    loop {
        let r = rt::call(s::OBSERVE, consumer, 0, 0);
        require(r.status == 0 && r.capability == 0, 459);
        if r.value == 1 {
            break;
        }
        require(r.value == 0, 460);
        yield_now(stop);
    }
    require(required(s::REAP, consumer, 0, 0) == 0, 461);
    require(required(s::CLOSE, consumer, 0, 0) == 0, 462);
    require(required(s::STOP_PROCESS, provider_b, 0, 0) == 0, 463);
    require(required(s::OBSERVE, provider_b, 0, 0) == 1, 464);
    require(required(s::REAP, provider_b, 0, 0) == 0, 465);
    require(required(s::CLOSE, provider_b, 0, 0) == 0, 466);
    send(outer, policy::Event::SwitchComplete.encode(), stop);
    // The generic fixture drains/returns actual managed channel owners after
    // Root exits, preserving exact physical/provenance receipts. No fakeclose
    // can reset channel sequence or claim mappings are already quiescent.
    for cap in [request, events, control, provider_job, consumer_job] {
        require(required(s::CLOSE, cap, 0, 0) == 0, 467)
    }
    rt::exit(0)
}
