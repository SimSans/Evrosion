use super::{bind_self, now, policy, require, rt, send, yield_now};
pub fn run(bytes: &[u8], stop: u64) -> ! {
    let caps = policy::roles(bytes, policy::CHILD_LIMITS, &policy::PROVIDER_ROLES)
        .unwrap_or_else(|| rt::exit(600));
    bind_self(caps[0]);
    send(caps[1], policy::Event::ProviderReady.encode(), stop);
    while now() < stop {
        let Some(call) = rt::discipline::receive(caps[0]).unwrap_or_else(|_| rt::exit(601)) else {
            yield_now(stop);
            continue;
        };
        let deadline = rt::rpc_deadline();
        require(
            deadline.status == 0
                && deadline.capability == 0
                && deadline.value > stop
                && deadline.value <= stop.checked_add(1024).unwrap_or_else(|| rt::exit(602)),
            603,
        );
        #[cfg(feature = "provider-a")]
        let reply = policy::wire::server_dispatch(&call.bytes, 0, policy::implementation_a);
        #[cfg(feature = "provider-b")]
        let reply = policy::wire::server_dispatch(&call.bytes, 0, policy::implementation_b);
        rt::discipline::reply(caps[0], reply, call.nonce).unwrap_or_else(|_| rt::exit(604));
    }
    rt::exit(0)
}
