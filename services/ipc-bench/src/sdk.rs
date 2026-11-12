//! Measured full SDK roundtrip includes its deadline/clock checks and ordinary
//! scheduling. Delivered IRQ ticks are not calibrated physical nanoseconds.
use ev_userspace_runtime as rt;
#[derive(Debug)]
pub enum Error {
    Argument,
    Clock,
    Rpc(rt::rpc::Error),
    Receive(rt::discipline::Error),
    Reply(rt::discipline::RejectedReply),
    Content,
    Deadline,
    Transport,
}
pub fn now(stop: u64) -> Result<u64, Error> {
    let r = rt::monotonic();
    if r.status != 0 || r.capability != 0 {
        return Err(Error::Clock);
    }
    if r.value >= stop {
        return Err(Error::Deadline);
    }
    Ok(r.value)
}
pub fn yield_now(stop: u64) -> Result<(), Error> {
    now(stop)?;
    let r = rt::yield_now();
    if r.status != 0 || r.value != 0 || r.capability != 0 {
        return Err(Error::Transport);
    }
    Ok(())
}
pub fn send(cap: u64, value: [u8; 8], stop: u64) -> Result<(), Error> {
    loop {
        now(stop)?;
        let r = rt::send(cap, value);
        if r.value != 0 || r.capability != 0 {
            return Err(Error::Transport);
        }
        match r.status {
            0 => return Ok(()),
            2 => yield_now(stop)?,
            _ => return Err(Error::Transport),
        }
    }
}
pub fn receive(cap: u64, stop: u64) -> Result<[u8; 8], Error> {
    loop {
        now(stop)?;
        let r = rt::receive(cap);
        match r.status {
            0 if r.capability == 0 => return Ok(r.value.to_le_bytes()),
            2 if r.value == 0 && r.capability == 0 => yield_now(stop)?,
            _ => return Err(Error::Transport),
        }
    }
}
pub fn bind(cap: u64) -> Result<(), Error> {
    let r = rt::call(rt::syscall::BIND_RECEIVER, cap, 0, 0);
    if r.status != 0 || r.value != 0 || r.capability != 0 {
        return Err(Error::Transport);
    }
    Ok(())
}
pub fn calls(endpoint: u64, stop: u64, first: u32, count: u32) -> Result<(), Error> {
    if endpoint == 0 || stop == 0 || stop == u64::MAX {
        return Err(Error::Argument);
    }
    let deadline = stop.checked_add(512).ok_or(Error::Argument)?;
    for sequence in first..first.checked_add(count).ok_or(Error::Argument)? {
        let bytes = crate::request(sequence);
        let answer = rt::rpc::call(endpoint, bytes, deadline).map_err(Error::Rpc)?;
        if answer != crate::response(bytes) {
            return Err(Error::Content);
        }
    }
    Ok(())
}
