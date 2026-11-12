//! Actual protected ReceiveRpc/ReplyRpc; no filesystem/device/selection policy.
use crate::{sdk::*, *};
use ev_userspace_runtime as rt;
pub fn run(bytes: &[u8], stop: u64) -> Result<(), Error> {
    let caps = roles(bytes, CHILD_LIMITS, &SERVER_ROLES).ok_or(Error::Argument)?;
    bind(caps[0])?;
    send(caps[1], Event::ServerReady.encode(), stop)?;
    for sequence in 0..TOTAL {
        let call = loop {
            now(stop)?;
            if let Some(call) = rt::discipline::receive(caps[0]).map_err(Error::Receive)? {
                break call;
            }
            yield_now(stop)?;
        };
        let deadline = rt::rpc_deadline();
        if deadline.status != 0
            || deadline.capability != 0
            || deadline.value != stop.checked_add(512).ok_or(Error::Argument)?
            || call.bytes != request(sequence)
        {
            return Err(Error::Content);
        }
        rt::discipline::reply(caps[0], response(call.bytes), call.nonce).map_err(Error::Reply)?;
    }
    send(caps[1], Event::ServerComplete.encode(), stop)?;
    // Root owns STOP/reap; server does not fake an ordinary client Exit.
    loop {
        yield_now(stop)?;
    }
}
