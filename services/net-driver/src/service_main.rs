#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_net_driver::{
    control::{self, Initialization, Notice, Operation, Packet, Status},
    diagnostic::{self, Diagnostic, Pending},
    mediated::output_reply,
    network::Session,
    protocol::{WINDOW_BYTES, Window},
    pump::{Client, ProtectedRpc, Pump},
    startup,
};
use ev_net_stack::stack::Storage;
use ev_userspace_runtime as rt;

// SAFETY: ordinary measured executable entry and memory intrinsics. The actual
// producer must admit this separate image, guarded stack and private BSS pages.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: this linker image has exactly four zero RW/NX stack pages at256..259
// with absent255/260. This is independent of its explicitly charged BSS backing.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x8000104000",
    "and rsp,-16",
    "call ev_network_main",
    "ud2",
);

// No heap or large stack temporary. This private ELF storage is initialized
// once, borrowed once, and never rebound/reused inside this service incarnation.
// Upstream nonzero empty enum/reference values place it in initialized RW data,
// rather than assuming an all-zero BSS image is valid Rust socket storage.
static mut STORAGE: Storage<'static> = Storage::EMPTY;

struct MappedWindow {
    address: usize,
}
impl Window for MappedWindow {
    type Error = ();
    fn read(&mut self, n: usize) -> Result<u8, ()> {
        if n >= WINDOW_BYTES {
            return Err(());
        }
        // SAFETY: actual trusted admission provides the exact distinct mapped
        // MemoryObject page for this route; protected RPC pins accepted bytes.
        Ok(unsafe { core::ptr::read_volatile((self.address + n) as *const u8) })
    }
    fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
        if n >= WINDOW_BYTES {
            return Err(());
        }
        // SAFETY: same actual mapping/credit contract; no aliased shared Rust
        // reference exists across syscalls or independently mutable messages.
        unsafe { core::ptr::write_volatile((self.address + n) as *mut u8, b) };
        Ok(())
    }
}
fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let r = rt::call4(rt::syscall::MONOTONIC, 0, 0, 0, 0);
    require(
        r.status == 0 && r.capability == 0 && r.serial == 0 && r.value != u64::MAX,
        1900,
    );
    r.value
}
fn now_millis() -> u64 {
    ev_net_driver::clock::nominal_millis(now())
}
fn deadline(stop: u64) -> u64 {
    let value = now()
        .checked_add(512)
        .filter(|n| *n != u64::MAX)
        .unwrap_or_else(|| rt::exit(1902));
    if stop == 0 { value } else { value.min(stop) }
}
fn yield_now() {
    output_reply(rt::call4(rt::syscall::YIELD, 0, 0, 0, 0)).unwrap_or_else(|_| rt::exit(1903));
}
fn event(endpoint: u64, bytes: [u8; 8], stop: u64) {
    let bound = deadline(stop);
    loop {
        require(now() < bound, 1904);
        let r = rt::call4(rt::syscall::SEND, endpoint, u64::from_le_bytes(bytes), 0, 0);
        if r.status == 0 {
            output_reply(r).unwrap_or_else(|_| rt::exit(1905));
            return;
        }
        require(
            r.status == 2 && r.value == 0 && r.capability == 0 && r.serial == 0,
            1906,
        );
        yield_now();
    }
}
fn remember(pending: &mut Option<Pending>, recorded: &mut bool, value: Option<Diagnostic>) {
    if !*recorded {
        *recorded = true;
        *pending = value.and_then(|value| Pending::new(value, now()));
    }
}
fn stop_driver(
    pump: &mut Pump<MappedWindow, ProtectedRpc>,
    cut: u64,
    pending: &mut Option<Pending>,
    recorded: &mut bool,
) -> bool {
    match pump.stop(cut) {
        Ok(()) => true,
        Err(error) => {
            remember(
                pending,
                recorded,
                diagnostic::pump(pump.operation(), &error, diagnostic::rpc),
            );
            false
        }
    }
}
fn stop_v2(
    pump: &mut Pump<MappedWindow, ProtectedRpc>,
    aggregate: Option<u64>,
    inherited: u64,
    pending: &mut Option<Pending>,
    recorded: &mut bool,
) -> Result<bool, ()> {
    let now = now();
    let end = aggregate.or_else(|| pump.stop_cut()).ok_or(())?;
    if end == u64::MAX || end <= now || end - now > 8192 || inherited > end {
        return Err(());
    }
    let child = now
        .checked_add(512)
        .filter(|v| *v != u64::MAX)
        .ok_or(())?
        .min(end)
        .min(inherited);
    if child <= now {
        return Err(());
    }
    let result = if aggregate.is_some() {
        pump.stop_begin(end, child).map(|()| false)
    } else {
        pump.stop_step(child)
    };
    result.map_err(|error| {
        remember(
            pending,
            recorded,
            diagnostic::pump(pump.operation(), &error, diagnostic::rpc),
        );
    })
}

/// # Safety
/// Only the actual admitted image enters here; loader supplies the immutable
/// v1 bootstrap and distinct checked private/shared mappings. Root is the sole
/// holder of ClientRPC SEND; Initialize must use its actual qualified provider.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ev_network_main(record: *const u8, size: usize, stop: u64) -> ! {
    require(
        record as usize == startup::STARTUP_ADDRESS && size == ev_userspace_contract::SIZE,
        1907,
    );
    require(rt::execution::validate(stop, now(), true).is_ok(), 1908);
    // SAFETY: exact admitted readonly startup extent checked above.
    let bytes = unsafe { core::slice::from_raw_parts(record, size) };
    #[cfg(feature = "workspace-profile")]
    let caps = startup::network_m8(bytes).unwrap_or_else(|_| rt::exit(1909));
    #[cfg(not(feature = "workspace-profile"))]
    let caps = startup::network(bytes).unwrap_or_else(|_| rt::exit(1909));
    output_reply(rt::call4(rt::syscall::BIND_RECEIVER, caps.clients, 0, 0, 0))
        .unwrap_or_else(|_| rt::exit(1910));
    let client = Client::new(
        MappedWindow {
            address: startup::NIC_WINDOW_ADDRESS,
        },
        ProtectedRpc::new(caps.driver).unwrap_or_else(|| rt::exit(1911)),
    );
    let mut pump = Pump::new(client);
    let mut window = MappedWindow {
        address: startup::CLIENT_WINDOW_ADDRESS,
    };
    let mut packet = Packet::new();
    let mut session: Option<Session<'static>> = None;
    let mut startup_sequence = 0u32;
    let mut storage_borrowed = false;
    let mut failed = false;
    let mut shutdown = false;
    let mut diagnostic: Option<Pending> = None;
    let mut diagnostic_recorded = false;
    event(caps.events, control::WAITING, stop);
    loop {
        require(rt::execution::live(stop, now()), 1912);
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
                pending.discard();
            }
        }
        if let Some(received) =
            rt::discipline::receive(caps.clients).unwrap_or_else(|_| rt::exit(1913))
        {
            let inherited = rt::call4(rt::syscall::RPC_DEADLINE, 0, 0, 0, 0);
            require(
                inherited.status == 0 && inherited.capability == 0 && inherited.serial == 0,
                1914,
            );
            let mut became_ready = false;
            let response = match Notice::decode(received.bytes) {
                Err(_) => *b"s\x01\x03\0\0\0\0\0",
                Ok(notice)
                    if !rt::execution::accepts_deadline(stop, now(), inherited.value, 1024) =>
                {
                    // Actual late quiescence ACK only: touch no accepted window,
                    // socket or device once the protected bound has expired.
                    notice.response(Status::Uncertain)
                }
                Ok(notice) if failed => packet
                    .reply(&mut window, notice, Status::Uncertain, &[])
                    .unwrap_or_else(|_| rt::exit(1915)),
                Ok(notice) if shutdown && notice.operation != Operation::ShutdownStep => packet
                    .reply(&mut window, notice, Status::Refused, &[])
                    .unwrap_or_else(|_| rt::exit(1925)),
                Ok(notice) => {
                    if let Some(session) = session.as_mut() {
                        if matches!(
                            notice.operation,
                            Operation::ShutdownBegin | Operation::ShutdownStep
                        ) {
                            let reply = session
                                .shutdown_v2(&mut window, notice, &mut packet, |aggregate| {
                                    shutdown = true;
                                    stop_v2(
                                        &mut pump,
                                        aggregate,
                                        inherited.value,
                                        &mut diagnostic,
                                        &mut diagnostic_recorded,
                                    )
                                })
                                .unwrap_or_else(|_| rt::exit(1928));
                            if notice.response_status(reply) == Ok(Status::Uncertain) {
                                failed = true;
                            }
                            reply
                        } else if notice.operation == Operation::Shutdown {
                            let reply = session
                                .shutdown(&mut window, notice, &mut packet, || {
                                    stop_driver(
                                        &mut pump,
                                        inherited.value,
                                        &mut diagnostic,
                                        &mut diagnostic_recorded,
                                    )
                                })
                                .unwrap_or_else(|_| rt::exit(1926));
                            shutdown = session.terminal();
                            reply
                        } else {
                            session
                                .handle(&mut window, notice, &mut packet)
                                .unwrap_or_else(|_| rt::exit(1916))
                        }
                    } else if startup_sequence.checked_add(1) != Some(notice.sequence) {
                        packet
                            .reply(&mut window, notice, Status::Stale, &[])
                            .unwrap_or_else(|_| rt::exit(1917))
                    } else if packet.read_request(&mut window, notice).is_err() {
                        packet
                            .reply(&mut window, notice, Status::Malformed, &[])
                            .unwrap_or_else(|_| rt::exit(1918))
                    } else {
                        startup_sequence = notice.sequence;
                        if matches!(
                            notice.operation,
                            Operation::ShutdownBegin | Operation::ShutdownStep
                        ) {
                            let begin = notice.operation == Operation::ShutdownBegin;
                            let status = if (!begin && !shutdown) || (begin && shutdown) {
                                Status::Refused
                            } else {
                                let aggregate = if begin {
                                    Some(u64::from_le_bytes(packet.data().try_into().unwrap()))
                                } else {
                                    None
                                };
                                shutdown = true;
                                match stop_v2(
                                    &mut pump,
                                    aggregate,
                                    inherited.value,
                                    &mut diagnostic,
                                    &mut diagnostic_recorded,
                                ) {
                                    Ok(false) => Status::Pending,
                                    Ok(true) => Status::Complete,
                                    Err(()) => {
                                        failed = true;
                                        Status::Uncertain
                                    }
                                }
                            };
                            packet
                                .reply(&mut window, notice, status, &[])
                                .unwrap_or_else(|_| rt::exit(1929))
                        } else if notice.operation == Operation::Shutdown {
                            // Prepared/unseeded shutdown uses the same actual
                            // driver window and protected nonce as live cleanup.
                            shutdown = true;
                            let status = if stop_driver(
                                &mut pump,
                                inherited.value,
                                &mut diagnostic,
                                &mut diagnostic_recorded,
                            ) {
                                Status::Complete
                            } else {
                                failed = true;
                                Status::Uncertain
                            };
                            packet
                                .reply(&mut window, notice, status, &[])
                                .unwrap_or_else(|_| rt::exit(1927))
                        } else if notice.operation != Operation::Initialize || storage_borrowed {
                            packet
                                .reply(&mut window, notice, Status::Refused, &[])
                                .unwrap_or_else(|_| rt::exit(1919))
                        } else {
                            let init = Initialization::parse(packet.data())
                                .unwrap_or_else(|_| rt::exit(1920));
                            storage_borrowed = true;
                            // SAFETY: only this single admitted thread reaches
                            // this branch, exactly once. Storage is private ELF data,
                            // not caller-mutable; the exclusive borrow remains
                            // alive in session until this process is retired.
                            let buffers =
                                unsafe { (&mut *core::ptr::addr_of_mut!(STORAGE)).buffers() };
                            session = Some(
                                Session::new(
                                    init,
                                    caps.incarnation,
                                    now_millis(),
                                    buffers,
                                    startup_sequence,
                                )
                                .unwrap_or_else(|_| rt::exit(1921)),
                            );
                            if let Err(error) = pump.start(inherited.value) {
                                failed = true;
                                remember(
                                    &mut diagnostic,
                                    &mut diagnostic_recorded,
                                    diagnostic::pump(pump.operation(), &error, diagnostic::rpc),
                                );
                                packet
                                    .reply(&mut window, notice, Status::Uncertain, &[])
                                    .unwrap_or_else(|_| rt::exit(1922))
                            } else {
                                became_ready = true;
                                packet
                                    .reply(&mut window, notice, Status::Complete, &[])
                                    .unwrap_or_else(|_| rt::exit(1923))
                            }
                        }
                    }
                }
            };
            rt::discipline::reply(caps.clients, response, received.nonce)
                .unwrap_or_else(|_| rt::exit(1924));
            if became_ready {
                event(caps.events, control::READY, stop);
            }
        }
        if !failed
            && !shutdown
            && let Some(session) = session.as_mut()
            && let Err(error) = pump.turn(session.stack(), now_millis(), deadline(stop))
        {
            // Retain uncertain local TX/window backing. Continue answering
            // explicit Uncertain, without another driver request or retry.
            failed = true;
            remember(
                &mut diagnostic,
                &mut diagnostic_recorded,
                diagnostic::pump(pump.operation(), &error, diagnostic::rpc),
            );
        }
        if !failed
            && !shutdown
            && let Some(session) = session.as_mut()
        {
            session.observe();
        }
        yield_now();
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1999)
}
