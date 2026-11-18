//! Only this executable boundary accesses the actual admitted shared mapping.
use ev_net_driver::{
    diagnostic::{self, Pending},
    mediated::{Mediated, output_reply},
    protocol::{Notice, Packet, WINDOW_BYTES, Window},
    rpc_service::Service,
    startup,
};
use ev_userspace_runtime as rt;

struct MappedWindow;
impl Window for MappedWindow {
    type Error = ();
    fn read(&mut self, offset: usize) -> Result<u8, ()> {
        if offset >= WINDOW_BYTES {
            return Err(());
        }
        // SAFETY: this separately admitted actor requires the actual live
        // NICWindow mapping at the fixed checked layout. Its sole accepted
        // protected RPC credit pins the window until the captured nonce ACK.
        Ok(
            unsafe {
                core::ptr::read_volatile((startup::NIC_WINDOW_ADDRESS + offset) as *const u8)
            },
        )
    }
    fn write(&mut self, offset: usize, value: u8) -> Result<(), ()> {
        if offset >= WINDOW_BYTES {
            return Err(());
        }
        // SAFETY: same actual window/lifetime contract as read; byte access
        // creates no shared Rust reference across a trap or a remote mutation.
        unsafe {
            core::ptr::write_volatile((startup::NIC_WINDOW_ADDRESS + offset) as *mut u8, value)
        };
        Ok(())
    }
}
fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let reply = rt::call4(rt::syscall::MONOTONIC, 0, 0, 0, 0);
    require(
        reply.status == 0 && reply.capability == 0 && reply.serial == 0 && reply.value != u64::MAX,
        1800,
    );
    reply.value
}
fn deadline(stop: u64, delta: u64) -> u64 {
    let deadline = now()
        .checked_add(delta)
        .filter(|value| *value != u64::MAX)
        .unwrap_or_else(|| rt::exit(1801));
    if stop == 0 {
        deadline
    } else {
        deadline.min(stop)
    }
}
fn yield_now() {
    output_reply(rt::call4(rt::syscall::YIELD, 0, 0, 0, 0)).unwrap_or_else(|_| rt::exit(1802));
}

pub fn run(bytes: &[u8], stop: u64) -> ! {
    require(rt::execution::validate(stop, now(), true).is_ok(), 1803);
    #[cfg(feature = "workspace-profile")]
    let caps = startup::driver_m8(bytes).unwrap_or_else(|_| rt::exit(1804));
    #[cfg(not(feature = "workspace-profile"))]
    let caps = startup::driver(bytes).unwrap_or_else(|_| rt::exit(1804));
    let ports = Mediated::new(caps.ports).unwrap_or_else(|_| rt::exit(1805));
    let mut service = Service::new(ports);
    // No accepted client/window work exists during exclusive cold initialization.
    // Actual Ready is sent only after complete STOP + scrub + independent readback.
    service
        .prepare(deadline(stop, 8192))
        .unwrap_or_else(|_| rt::exit(1806));
    output_reply(rt::call4(
        rt::syscall::BIND_RECEIVER,
        caps.requests,
        0,
        0,
        0,
    ))
    .unwrap_or_else(|_| rt::exit(1807));
    let ready_deadline = deadline(stop, 512);
    loop {
        require(now() < ready_deadline, 1808);
        let reply = rt::call4(
            rt::syscall::SEND,
            caps.events,
            u64::from_le_bytes(startup::DRIVER_READY),
            0,
            0,
        );
        if reply.status == 0 {
            output_reply(reply).unwrap_or_else(|_| rt::exit(1809));
            break;
        }
        require(
            reply.status == 2 && reply.value == 0 && reply.capability == 0 && reply.serial == 0,
            1810,
        );
        yield_now();
    }
    let mut packet = Packet::new();
    let mut window = MappedWindow;
    let mut diagnostic: Option<Pending> = None;
    let mut diagnostic_recorded = false;
    loop {
        require(rt::execution::live(stop, now()), 1811);
        if let Some(pending) = diagnostic.as_mut()
            && let Some(bytes) = pending.bytes(now())
        {
            let r = rt::call4(
                rt::syscall::SEND,
                caps.events,
                u64::from_le_bytes(bytes),
                0,
                0,
            );
            if r.status == 0 && r.value == 0 && r.capability == 0 && r.serial == 0 {
                pending.accepted();
            } else if r.status != 2 || r.value != 0 || r.capability != 0 || r.serial != 0 {
                // Losing a diagnostic never clears the underlying device debt.
                pending.discard();
            }
        }
        let Some(received) =
            rt::discipline::receive(caps.requests).unwrap_or_else(|_| rt::exit(1812))
        else {
            yield_now();
            continue;
        };
        let inherited = rt::call4(rt::syscall::RPC_DEADLINE, 0, 0, 0, 0);
        require(
            inherited.status == 0 && inherited.capability == 0 && inherited.serial == 0,
            1813,
        );
        let response = if !rt::execution::accepts_deadline(stop, now(), inherited.value, 1024) {
            // Canonical late quiescence ACK. No window/device access after the
            // actual operation bound; caller never receives this as success.
            *b"n\x01\x05\0\0\0\0\0"
        } else {
            match Notice::decode(received.bytes) {
                Ok(notice) => service
                    .handle(&mut window, notice, inherited.value, &mut packet)
                    .unwrap_or_else(|_| rt::exit(1814)),
                Err(_) => *b"n\x01\x03\0\0\0\0\0",
            }
        };
        // This exact nonce was captured by the real RECEIVE_RPC. A rejected ACK
        // is terminal; never receive/reuse the accepted window or retry its PIO.
        rt::discipline::reply(caps.requests, response, received.nonce)
            .unwrap_or_else(|_| rt::exit(1815));
        if let Some((operation, failure)) = service.take_failure()
            && !diagnostic_recorded
        {
            diagnostic_recorded = true;
            diagnostic = diagnostic::device(operation as u8, &failure, diagnostic::mediated)
                .and_then(|value| Pending::new(value, now()));
        }
    }
}
