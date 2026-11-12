#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_cap_client::Capabilities;
use ev_userspace_contract::{
    SIZE,
    cap_echo::{self, ClientOutcome, Request, SyncTransport, TransportOutcome},
};
use ev_userspace_runtime::{
    self as runtime,
    cap_echo::{Endpoint, Error, MemoryReadTransfer, RecoveryToken},
};

// SAFETY: unique executable entry uses the measured, retained SysV stack and
// bootstrap record; all freestanding memory intrinsics share the common ABI.
global_asm!(ev_userspace_runtime::start_assembly!());
const DELAY_VALUE: u32 = 0xdead0001;
type Outcome = TransportOutcome<MemoryReadTransfer, RecoveryToken, Error>;
const WORLD: u8 = if cfg!(feature = "test-timeout") {
    1
} else if cfg!(feature = "test-death") {
    2
} else if cfg!(feature = "test-queued-timeout") {
    3
} else if cfg!(feature = "test-queued-death") {
    4
} else {
    0
};

fn require(ok: bool, code: u64) {
    if !ok {
        runtime::exit(code);
    }
}
fn now() -> u64 {
    let clock = runtime::monotonic();
    require(clock.status == 0, 200);
    clock.value
}
fn deadline(ticks: u64) -> u64 {
    now()
        .checked_add(ticks)
        .unwrap_or_else(|| runtime::exit(201))
}
fn readable(cap: &MemoryReadTransfer) {
    require(runtime::inspect(cap.as_raw(), 1).status == 0, 202);
    require(runtime::inspect(cap.as_raw(), 2).status == 1, 203);
    require(runtime::inspect(cap.as_raw(), 32).status != 0, 204);
}
fn gone(raw: u64) {
    require(runtime::inspect(raw, 1).status == 1, 205);
}
fn rejected(outcome: Outcome, reason: u64, old: u64) -> MemoryReadTransfer {
    match outcome {
        TransportOutcome::Rejected {
            error: Error::Remote(observed),
            original,
        } if observed == reason && original.as_raw() == old => original,
        _ => runtime::exit(206),
    }
}
fn returned(
    outcome: ClientOutcome<MemoryReadTransfer, RecoveryToken, Error>,
    value: u32,
    old: u64,
) -> MemoryReadTransfer {
    match outcome {
        ClientOutcome::Returned {
            response,
            capability,
        } if response.value == value => {
            require(capability.as_raw() != old, 207);
            gone(old);
            readable(&capability);
            capability
        }
        _ => runtime::exit(208),
    }
}
fn normal(caps: Capabilities, mut first: MemoryReadTransfer, second: MemoryReadTransfer) {
    let mut endpoint = Endpoint {
        endpoint: caps.requests,
    };
    let old = first.as_raw();
    first = rejected(endpoint.call([0; 8], first, deadline(128)), 3, old);
    readable(&first);
    let forged = MemoryReadTransfer::from_raw(u64::MAX).unwrap();
    let forged = rejected(
        endpoint.call(Request { value: 7 }.encode(), forged, deadline(128)),
        1,
        u64::MAX,
    );
    gone(forged.as_raw());
    readable(&first);
    let old = first.as_raw();
    first = rejected(
        endpoint.call(Request { value: 7 }.encode(), first, now()),
        4,
        old,
    );
    readable(&first);
    for value in [7, 0x01020304, u32::MAX] {
        let old = first.as_raw();
        first = returned(
            cap_echo::client_call(&mut endpoint, value, first, deadline(128)),
            value,
            old,
        );
    }
    readable(&first);
    readable(&second);
}
fn delivered_timeout(
    caps: Capabilities,
    first: MemoryReadTransfer,
    mut second: MemoryReadTransfer,
) {
    let mut endpoint = Endpoint {
        endpoint: caps.requests,
    };
    let old = first.as_raw();
    match cap_echo::client_call(&mut endpoint, DELAY_VALUE, first, deadline(32)) {
        ClientOutcome::DeliveredFailure {
            error: Error::Remote(4),
        } => (),
        _ => runtime::exit(209),
    }
    gone(old);
    readable(&second);
    let retry_deadline = deadline(128);
    let second_old = second.as_raw();
    second = rejected(
        endpoint.call(
            Request { value: 0x01020304 }.encode(),
            second,
            retry_deadline,
        ),
        2,
        second_old,
    );
    readable(&second);
    // One absolute bound for all preaccept busy retries; retries cannot silently
    // extend the deadline or regain ownership of the first delivered attachment.
    loop {
        require(now() < retry_deadline, 210);
        let old = second.as_raw();
        match cap_echo::client_call(&mut endpoint, 0x01020304, second, retry_deadline) {
            ClientOutcome::Rejected {
                error: Error::Remote(2),
                original,
            } => {
                require(original.as_raw() == old, 211);
                second = original;
                readable(&second);
                require(runtime::yield_now().status == 0, 212);
            }
            outcome => {
                second = returned(outcome, 0x01020304, old);
                break;
            }
        }
    }
    gone(old);
    readable(&second);
}
fn delivered_death(caps: Capabilities, first: MemoryReadTransfer, second: MemoryReadTransfer) {
    let mut endpoint = Endpoint {
        endpoint: caps.requests,
    };
    let old = first.as_raw();
    match cap_echo::client_call(&mut endpoint, 7, first, deadline(128)) {
        ClientOutcome::DeliveredFailure {
            error: Error::Remote(5),
        } => (),
        _ => runtime::exit(213),
    }
    gone(old);
    readable(&second);
}
fn queued_failure(
    caps: Capabilities,
    first: MemoryReadTransfer,
    second: MemoryReadTransfer,
    reason: u64,
) {
    let mut endpoint = Endpoint {
        endpoint: caps.requests,
    };
    let old = first.as_raw();
    let ticks = if reason == 4 { 32 } else { 128 };
    let recovered = match cap_echo::client_call(&mut endpoint, 7, first, deadline(ticks)) {
        ClientOutcome::QueuedFailure {
            error: Error::Remote(observed),
            recovered,
        } if observed == reason => recovered,
        _ => runtime::exit(214),
    };
    require(recovered.as_raw() != old, 215);
    gone(old);
    readable(&recovered);
    readable(&second);
}

// SAFETY: unique symbol called only by the shared measured executable entry.
#[unsafe(no_mangle)]
extern "C" fn ev_user_main(record: u64, length: u64) -> ! {
    require(
        length == SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record <= (1 << 47) - 4096,
        216,
    );
    // SAFETY: admission supplies a retained initialized readonly bootstrap page;
    // this exact checked slice remains inside its one-page backing.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    let caps = ev_cap_client::startup(bytes).unwrap_or_else(|_| runtime::exit(217));
    let first = MemoryReadTransfer::from_raw(caps.first).unwrap_or_else(|| runtime::exit(218));
    let second = MemoryReadTransfer::from_raw(caps.second).unwrap_or_else(|| runtime::exit(219));
    readable(&first);
    readable(&second);
    require(runtime::inspect(caps.requests, 1).status == 1, 220);
    require(runtime::inspect(caps.responses, 1).status == 1, 221);
    require(runtime::rpc_deadline().status == 1, 222);
    match WORLD {
        1 => delivered_timeout(caps, first, second),
        2 => delivered_death(caps, first, second),
        3 => queued_failure(caps, first, second, 4),
        4 => queued_failure(caps, first, second, 5),
        _ => normal(caps, first, second),
    }
    // Actual Exit0 is the controller's observation that every userspace ownership
    // assertion above completed. No userspace code fabricates transport evidence.
    runtime::exit(0)
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    runtime::exit(299)
}
