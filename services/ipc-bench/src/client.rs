//! Exactly one installed SEND handle, with explicit warmup/measurement barriers.
use crate::{sdk::*, *};
pub fn run(bytes: &[u8], stop: u64) -> Result<(), Error> {
    let caps = roles(bytes, CHILD_LIMITS, &CLIENT_ROLES).ok_or(Error::Argument)?;
    bind(caps[2])?;
    send(caps[1], Event::ClientReady.encode(), stop)?;
    if receive(caps[2], stop)? != START_WARMUP {
        return Err(Error::Content);
    }
    calls(caps[0], stop, 0, WARMUP)?;
    send(caps[1], Event::WarmupComplete.encode(), stop)?;
    if receive(caps[2], stop)? != START_MEASURED {
        return Err(Error::Content);
    }
    let first_tick = now(stop)?;
    calls(caps[0], stop, WARMUP, ROUNDS)?;
    let last_tick = now(stop)?;
    let sample = Sample::checked(
        [u64::from(WARMUP), u64::from(ROUNDS), first_tick, last_tick],
        stop,
    )
    .ok_or(Error::Content)?;
    send(caps[1], Event::SampleBegin.encode(), stop)?;
    for word in sample.words() {
        send(caps[1], word.to_le_bytes(), stop)?;
    }
    send(caps[1], Event::SampleEnd.encode(), stop)
}
