//! Actual scoped userspace PS/2 backend. Raw frames are freshness metadata;
//! protected sender identity, focus, trusted UI and approval stay separate.
use crate::{grant, require};
use ev_input::{
    BarrierRequest,
    ps2::{Driver, Ports},
    stream::Stream,
};
use ev_userspace_runtime as rt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundaryError {
    Port(rt::CapReply),
    Scalar(rt::Reply),
    Send(rt::Reply),
    WrongPort,
}
fn port_value(reply: rt::CapReply, input: bool) -> Result<u8, BoundaryError> {
    if reply.status != 0
        || reply.capability != 0
        || reply.serial != 0
        || reply.value > if input { u8::MAX as u64 } else { 0 }
    {
        return Err(BoundaryError::Port(reply));
    }
    Ok(reply.value as u8)
}
fn clock() -> Result<u64, BoundaryError> {
    let r = rt::monotonic();
    if r.status != 0 || r.capability != 0 || r.value == u64::MAX {
        return Err(BoundaryError::Scalar(r));
    }
    Ok(r.value)
}
fn yield_checked() -> Result<(), BoundaryError> {
    let r = rt::yield_now();
    if r.status != 0 || r.value != 0 || r.capability != 0 {
        return Err(BoundaryError::Scalar(r));
    }
    Ok(())
}
struct Io {
    cap: u64,
}
impl Ports for Io {
    type Error = BoundaryError;
    fn input(&mut self, port: u16) -> Result<u8, BoundaryError> {
        if !matches!(port, 0x60 | 0x64) {
            return Err(BoundaryError::WrongPort);
        }
        port_value(
            rt::call4(rt::syscall::PORT_INPUT, self.cap, u64::from(port), 1, 0),
            true,
        )
    }
    fn output(&mut self, port: u16, value: u8) -> Result<(), BoundaryError> {
        if !matches!(port, 0x60 | 0x64) {
            return Err(BoundaryError::WrongPort);
        }
        port_value(
            rt::call4(
                rt::syscall::PORT_OUTPUT,
                self.cap,
                u64::from(port),
                1,
                u64::from(value),
            ),
            false,
        )?;
        Ok(())
    }
    fn now(&mut self) -> Result<u64, BoundaryError> {
        clock()
    }
    fn yield_now(&mut self) -> Result<(), BoundaryError> {
        yield_checked()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    Accepted,
    Full,
}
fn send_result(reply: rt::Reply) -> Result<Sent, BoundaryError> {
    if reply.value != 0 || reply.capability != 0 {
        return Err(BoundaryError::Send(reply));
    }
    match reply.status {
        0 => Ok(Sent::Accepted),
        2 => Ok(Sent::Full),
        _ => Err(BoundaryError::Send(reply)),
    }
}
fn before(stop: u64) {
    require(clock().unwrap_or_else(|_| rt::exit(761)) < stop, 762);
}
fn pause(stop: u64) {
    before(stop);
    yield_checked().unwrap_or_else(|_| rt::exit(763));
    before(stop);
}
fn ready(endpoint: u64, stop: u64) {
    loop {
        before(stop);
        match send_result(rt::send(endpoint, *b"EVINRDY1")).unwrap_or_else(|_| rt::exit(764)) {
            Sent::Accepted => return,
            Sent::Full => pause(stop),
        }
    }
}

pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    let _ = record;
    require(b.grants().count() == 4, 760);
    let ports = grant(b, 1, 7, 3);
    let shell_keys = grant(b, 2, 2, 8);
    let root_events = grant(b, 3, 2, 8);
    let control = grant(b, 4, 2, 272);
    let mut driver = Driver::new(Io { cap: ports });
    driver.initialize(stop).unwrap_or_else(|_| rt::exit(765));
    let mut stream = Stream::new();
    // Known raw set1 now: drain stale actual bytes without forwarding. Initial
    // unknown-held Enter may launch UI, but cannot approve without a real break.
    driver
        .drain(&mut stream, stop)
        .unwrap_or_else(|_| rt::exit(766));
    let bound = rt::call(rt::syscall::BIND_RECEIVER, control, 0, 0);
    require(
        bound.status == 0 && bound.value == 0 && bound.capability == 0,
        767,
    );
    ready(root_events, stop);
    loop {
        before(stop);
        // Always service protected control before retrying a pending key. Full
        // leaves exactly one unsent frame; barriers drop it and drain held state.
        if let Some(request) = rt::discipline::receive(control).unwrap_or_else(|_| rt::exit(768)) {
            let reply = if BarrierRequest::decode(request.bytes).is_ok() {
                let deadline = rt::rpc_deadline();
                require(
                    deadline.status == 0 && deadline.capability == 0 && deadline.value != u64::MAX,
                    769,
                );
                let deadline = deadline.value.min(stop);
                stream.begin_barrier();
                driver
                    .drain(&mut stream, deadline)
                    .unwrap_or_else(|_| rt::exit(770));
                stream
                    .barrier_reply()
                    .encode()
                    .unwrap_or_else(|_| rt::exit(771))
            } else {
                *b"KBE1\x01\0\0\0"
            };
            rt::discipline::reply(control, reply, request.nonce).unwrap_or_else(|_| rt::exit(772));
            continue;
        }
        if let Some(key) = stream.pending() {
            let bytes = key.encode().unwrap_or_else(|_| rt::exit(773));
            match send_result(rt::send(shell_keys, bytes)).unwrap_or_else(|_| rt::exit(774)) {
                Sent::Accepted => stream.sent(),
                Sent::Full => {}
            }
            pause(stop);
            continue;
        }
        if let Some((status, data)) = driver.poll(stop).unwrap_or_else(|_| rt::exit(775)) {
            stream.push(status, data).unwrap_or_else(|_| rt::exit(776));
        }
        pause(stop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_port_output_is_strict_and_no_unexpected_word_is_truncated() {
        let reply = rt::CapReply {
            status: 0,
            value: 255,
            capability: 0,
            serial: 0,
        };
        assert_eq!(port_value(reply, true), Ok(255));
        for bad in [
            rt::CapReply { status: 1, ..reply },
            rt::CapReply {
                value: 256,
                ..reply
            },
            rt::CapReply {
                capability: 1,
                ..reply
            },
            rt::CapReply { serial: 1, ..reply },
        ] {
            assert!(port_value(bad, true).is_err());
        }
        assert!(port_value(reply, false).is_err());
        assert_eq!(port_value(rt::CapReply { value: 0, ..reply }, false), Ok(0));
    }
    #[test]
    fn only_canonical_full_is_retryable_and_never_acknowledged_as_accepted() {
        let full = rt::Reply {
            status: 2,
            value: 0,
            capability: 0,
        };
        assert_eq!(send_result(full), Ok(Sent::Full));
        assert!(send_result(rt::Reply { status: 1, ..full }).is_err());
        assert!(send_result(rt::Reply { value: 1, ..full }).is_err());
        assert!(
            send_result(rt::Reply {
                capability: 1,
                ..full
            })
            .is_err()
        );
        assert_eq!(
            send_result(rt::Reply { status: 0, ..full }),
            Ok(Sent::Accepted)
        );
    }
}
