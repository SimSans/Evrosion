//! One installed endpoint and one generated client, with no provider identity.
use super::{bind_self, policy, require, rt, send, yield_now};
use policy::wire::{self, Transport};
pub fn run(bytes: &[u8], stop: u64) -> ! {
    let caps = policy::roles(bytes, policy::CHILD_LIMITS, &policy::CONSUMER_ROLES)
        .unwrap_or_else(|| rt::exit(500));
    bind_self(caps[2]);
    let endpoint = policy::endpoint::Endpoint::new(caps[0]).unwrap_or_else(|| rt::exit(501));
    // Construct once. Neither phase replaces this object or installed handle.
    let mut client = wire::Client::new(endpoint);
    let mut malformed_transport =
        policy::endpoint::Endpoint::new(caps[0]).unwrap_or_else(|| rt::exit(511));
    for phase in 0..2 {
        let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(502));
        for value in [0, 137, wire::MAX_INPUT] {
            let response = client
                .evaluate(value, deadline)
                .unwrap_or_else(|_| rt::exit(503));
            require(response == wire::Response::Returned(value * 2 + 1), 504);
        }
        require(
            matches!(
                client.evaluate(u32::MAX, deadline),
                Ok(wire::Response::Refused(wire::Refusal::Overflow))
            ),
            505,
        );
        // Raw malformed method is a deliberate conformance probe. It still
        // uses the SAME real transport/endpoint and must be refused by the
        // generated server before invoking the provider implementation.
        let (reply, attachments) = malformed_transport
            .call([0; 8], deadline)
            .unwrap_or_else(|_| rt::exit(506));
        require(
            attachments == 0
                && wire::Response::decode(&reply, 0)
                    == Ok(wire::Response::Refused(wire::Refusal::Malformed)),
            507,
        );
        send(
            caps[1],
            policy::Event::PhaseComplete { phase: phase + 1 }.encode(),
            stop,
        );
        if phase == 0 {
            loop {
                let r = rt::receive(caps[2]);
                match r.status {
                    0 => {
                        require(
                            r.capability == 0 && r.value.to_le_bytes() == policy::CONTINUE,
                            508,
                        );
                        break;
                    }
                    2 => require(r.capability == 0 && r.value == 0, 509),
                    _ => rt::exit(510),
                }
                yield_now(stop);
            }
        }
    }
    rt::exit(0)
}
