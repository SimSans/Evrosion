//! Measured Ring3 benchmark orchestration. Kernel owns only ordinary lifecycle,
//! opaque transport and observations; no provider switch event is fabricated.
use ev_ipc_bench::{self as policy, Event, Sample, sdk};
use ev_userspace_runtime as rt;
use rt::syscall as s;
fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
fn send(cap: u64, body: [u8; 8], stop: u64) {
    require(sdk::send(cap, body, stop).is_ok(), 720);
}
fn required(number: u64, a: u64, b: u64, c: u64) -> u64 {
    let r = rt::call(number, a, b, c);
    require(r.status == 0 && r.capability == 0, 721);
    r.value
}
#[derive(Clone, Copy)]
struct Identity {
    process: u64,
    thread: u64,
}
fn identity(control: u64) -> Identity {
    const CANARY: u64 = 0x91a6_b73d_26f1_c005;
    let r = rt::call4(s::PROCESS_IDENTITY, control, 0, 0, CANARY);
    require(
        r.status == 0 && r.value != 0 && r.capability != 0 && r.serial == CANARY,
        722,
    );
    Identity {
        process: r.value,
        thread: r.capability,
    }
}
fn create(job: u64, image: u64, roles: &[(u64, u64)]) -> u64 {
    let process = required(s::CREATE_PROCESS, job, image, 0);
    require(process != 0, 723);
    for &(source, selector) in roles {
        require(required(s::DELEGATE, process, source, selector) == 0, 724);
    }
    process
}
struct Inbox {
    cap: u64,
    client: Identity,
    server: Identity,
    server_complete: bool,
}
impl Inbox {
    fn client(&mut self, stop: u64) -> [u8; 8] {
        loop {
            sdk::now(stop).unwrap_or_else(|_| rt::exit(725));
            let r = rt::call4(s::RECEIVE_EVENT, self.cap, 0, 0, 0);
            match r.status {
                0 if (r.capability, r.serial) == (self.client.process, self.client.thread) => {
                    return r.value.to_le_bytes();
                }
                0 if (r.capability, r.serial) == (self.server.process, self.server.thread)
                    && Event::decode(r.value.to_le_bytes()) == Some(Event::ServerComplete)
                    && !self.server_complete =>
                {
                    self.server_complete = true
                }
                2 if r.value == 0 && r.capability == 0 && r.serial == 0 => (),
                _ => rt::exit(726),
            }
            sdk::yield_now(stop).unwrap_or_else(|_| rt::exit(727));
        }
    }
    fn event(&mut self, event: Event, stop: u64) {
        require(Event::decode(self.client(stop)) == Some(event), 728);
    }
}
fn ready(inbox: u64, target: Identity, event: Event, stop: u64) {
    loop {
        sdk::now(stop).unwrap_or_else(|_| rt::exit(729));
        let r = rt::call4(s::RECEIVE_EVENT, inbox, 0, 0, 0);
        match r.status {
            0 => {
                require(
                    (r.capability, r.serial) == (target.process, target.thread)
                        && Event::decode(r.value.to_le_bytes()) == Some(event),
                    730,
                );
                return;
            }
            2 => require(r.value == 0 && r.capability == 0 && r.serial == 0, 731),
            _ => rt::exit(732),
        }
        sdk::yield_now(stop).unwrap_or_else(|_| rt::exit(733));
    }
}
pub fn run(bytes: &[u8], stop: u64) -> ! {
    let [probe, outer, creator, server_image, client_image, _] =
        policy::roles(bytes, policy::ROOT_LIMITS, &policy::ROOT_ROLES)
            .unwrap_or_else(|| rt::exit(734));
    let r = rt::inspect(probe, 1);
    require(r.status == 0 && r.capability == 0, 735);
    send(outer, ev_userspace_contract::Event::Ready.encode(), stop);
    let server_job = required(s::CREATE_JOB, creator, 0, 0);
    let client_job = required(s::CREATE_JOB, creator, 0, 0);
    let request = required(s::CREATE_ENDPOINT, creator, 0, 0);
    let events = required(s::CREATE_ENDPOINT, creator, 0, 0);
    let control = required(s::CREATE_ENDPOINT, creator, 0, 0);
    require(
        request != events && request != control && events != control,
        736,
    );
    require(required(s::BIND_RECEIVER, events, 0, 0) == 0, 737);
    let server = create(server_job, server_image, &[(request, 1), (events, 2)]);
    require(required(s::BIND_RECEIVER, request, server, 0) == 0, 738);
    require(required(s::START, server, 0, 0) == 0, 739);
    let actual_server = identity(server);
    ready(events, actual_server, Event::ServerReady, stop);
    let client = create(
        client_job,
        client_image,
        &[(request, 1), (events, 2), (control, 3)],
    );
    require(required(s::BIND_RECEIVER, control, client, 0) == 0, 740);
    require(required(s::START, client, 0, 0) == 0, 741);
    let actual_client = identity(client);
    ready(events, actual_client, Event::ClientReady, stop);
    let mut inbox = Inbox {
        cap: events,
        client: actual_client,
        server: actual_server,
        server_complete: false,
    };
    send(control, policy::START_WARMUP, stop);
    inbox.event(Event::WarmupComplete, stop);
    // Batched observation BEFORE measured control; UART cost is outside client
    // first..last ticks. No runtime may turn ten provider calls into this batch.
    send(outer, Event::BatchBefore.encode(), stop);
    send(control, policy::START_MEASURED, stop);
    inbox.event(Event::SampleBegin, stop);
    let words = core::array::from_fn(|_| u64::from_le_bytes(inbox.client(stop)));
    inbox.event(Event::SampleEnd, stop);
    let sample = Sample::checked(words, stop).unwrap_or_else(|| rt::exit(742));
    send(outer, Event::BatchAfter.encode(), stop);
    send(outer, Event::SampleBegin.encode(), stop);
    for word in sample.words() {
        send(outer, word.to_le_bytes(), stop);
    }
    send(outer, Event::SampleEnd.encode(), stop);
    // Sample is actual-client provenance, not proof that any process exited.
    loop {
        let r = rt::call(s::OBSERVE, client, 0, 0);
        require(r.status == 0 && r.capability == 0 && r.value <= 1, 743);
        if r.value == 1 {
            break;
        }
        sdk::yield_now(stop).unwrap_or_else(|_| rt::exit(744));
    }
    require(required(s::REAP, client, 0, 0) == 0, 745);
    require(required(s::CLOSE, client, 0, 0) == 0, 746);
    require(required(s::STOP_PROCESS, server, 0, 0) == 0, 747);
    require(required(s::OBSERVE, server, 0, 0) == 1, 748);
    require(required(s::REAP, server, 0, 0) == 0, 749);
    require(required(s::CLOSE, server, 0, 0) == 0, 750);
    for cap in [request, events, control, server_job, client_job] {
        require(required(s::CLOSE, cap, 0, 0) == 0, 751);
    }
    send(outer, Event::Finish.encode(), stop);
    rt::exit(0)
}
