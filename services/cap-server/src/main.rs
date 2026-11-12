#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_cap_server::Capabilities;
use ev_userspace_contract::{
    SIZE,
    cap_echo::{self, AttachmentShape},
};
use ev_userspace_runtime::{
    self as runtime,
    cap_echo::{
        self as transport, Error, MemoryReadTransfer, ReceiveOutcome, Received, ReplyOutcome,
        ReplyToken,
    },
};

// SAFETY: unique measured entry uses the retained SysV stack and readonly
// bootstrap record, sharing the exact common freestanding memory intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
const DELAY_VALUE: u32 = 0xdead0001;
const WORLD: u8 = if cfg!(feature = "test-delay") {
    1
} else if cfg!(feature = "test-fault") {
    2
} else if cfg!(feature = "test-hold") {
    3
} else if cfg!(feature = "test-queued-fault") {
    4
} else {
    0
};
fn require(ok: bool, code: u64) {
    if !ok {
        runtime::exit(code);
    }
}
fn yield_now() {
    require(runtime::yield_now().status == 0, 240);
}
fn now() -> u64 {
    let clock = runtime::monotonic();
    require(clock.status == 0, 241);
    clock.value
}
fn wait_until(deadline: u64) {
    while now() < deadline {
        yield_now();
    }
}
fn readable(cap: &MemoryReadTransfer) {
    require(runtime::inspect(cap.as_raw(), 1).status == 0, 242);
    require(runtime::inspect(cap.as_raw(), 2).status == 1, 243);
    require(runtime::inspect(cap.as_raw(), 32).status != 0, 244);
}
fn incoming(caps: Capabilities) -> Received {
    loop {
        match transport::receive(caps.requests) {
            ReceiveOutcome::Received(delivery) => {
                readable(&delivery.capability);
                return delivery;
            }
            ReceiveOutcome::Rejected {
                error: Error::Remote(7),
            } => yield_now(),
            _ => runtime::exit(245),
        }
    }
}
fn response(delivery: &Received) -> [u8; 8] {
    cap_echo::server_dispatch(
        &delivery.bytes,
        &[AttachmentShape {
            kind: 1,
            rights: cap_echo::MEMORY_READ_TRANSFER,
        }],
        |request| cap_echo::Response {
            value: request.value,
        },
    )
    .unwrap_or_else(|_| runtime::exit(246))
}
fn timely(caps: Capabilities, delivery: Received, bytes: [u8; 8]) {
    let old = delivery.capability.as_raw();
    match transport::reply(caps.responses, bytes, delivery.capability, delivery.reply) {
        ReplyOutcome::Accepted => (),
        _ => runtime::exit(247),
    }
    require(runtime::inspect(old, 1).status == 1, 248);
}
fn fault() -> ! {
    // SAFETY: deliberately measured fault-injection executable. This real CPL3
    // access writes unmapped address0 using assembly rather than Rust pointer UB.
    unsafe {
        core::arch::asm!("mov byte ptr [{address}], 0", address=in(reg)0u64, options(nostack));
        core::arch::asm!("ud2", options(noreturn));
    }
}
fn queued(caps: Capabilities) -> ! {
    // RPC assigns the actual serving reservation before mailbox delivery. Read
    // its protected deadline without RECEIVE so the attachment stays in escrow.
    let deadline = loop {
        let observed = runtime::rpc_deadline();
        match observed.status {
            0 => break observed.value,
            1 => yield_now(),
            _ => runtime::exit(249),
        }
    };
    if WORLD == 4 {
        fault();
    }
    wait_until(
        deadline
            .checked_add(1)
            .unwrap_or_else(|| runtime::exit(250)),
    );
    // The actual client observes a recovered handle and exits; its trusted owner
    // then stops this still-live server before graph retirement. Never RECEIVE.
    let _ = caps;
    loop {
        yield_now();
    }
}
fn delayed(caps: Capabilities, first: Received) {
    let value = cap_echo::Request::decode(&first.bytes)
        .unwrap_or_else(|_| runtime::exit(251))
        .value;
    require(value == DELAY_VALUE, 252);
    let bytes = response(&first);
    let actual_deadline = runtime::rpc_deadline();
    require(actual_deadline.status == 0, 253);
    wait_until(
        actual_deadline
            .value
            .checked_add(32)
            .unwrap_or_else(|| runtime::exit(254)),
    );
    let old_serial = first.reply.as_raw();
    let mut retained = match transport::reply(caps.responses, bytes, first.capability, first.reply)
    {
        ReplyOutcome::Late {
            error: Error::Remote(4),
            retained,
        } => retained,
        _ => runtime::exit(255),
    };
    readable(&retained);
    let mut second = incoming(caps);
    let bytes = response(&second);
    require(
        cap_echo::Request::decode(&second.bytes)
            .unwrap_or_else(|_| runtime::exit(256))
            .value
            == 0x01020304,
        257,
    );
    // Deliberately replay the old raw serial. It is an untrusted diagnostic
    // integer; only the kernel's actual serving CallId can authorize completion.
    let stale = ReplyToken::from_raw(old_serial).unwrap();
    retained = match transport::reply(caps.responses, bytes, retained, stale) {
        ReplyOutcome::Rejected {
            error: Error::Remote(8),
            original,
            ..
        } => original,
        _ => runtime::exit(258),
    };
    readable(&retained);
    // Even the NEW valid serial cannot turn the old first attachment into the
    // current request's reply. Exact generation-tagged object identity matters.
    let token = match transport::reply(caps.responses, bytes, retained, second.reply) {
        ReplyOutcome::Rejected {
            error: Error::Remote(1),
            original,
            reply,
        } => {
            readable(&original);
            reply
        }
        _ => runtime::exit(259),
    };
    second.reply = token;
    timely(caps, second, bytes);
}
fn serve(caps: Capabilities) -> ! {
    if matches!(WORLD, 3 | 4) {
        queued(caps);
    }
    if WORLD == 1 {
        let first = incoming(caps);
        delayed(caps, first);
    }
    loop {
        let delivery = incoming(caps);
        let bytes = response(&delivery);
        if WORLD == 2 {
            fault();
        }
        timely(caps, delivery, bytes);
    }
}

// SAFETY: this unique symbol is called only by the measured executable entry.
#[unsafe(no_mangle)]
extern "C" fn ev_user_main(record: u64, length: u64) -> ! {
    require(
        length == SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record <= (1 << 47) - 4096,
        260,
    );
    // SAFETY: a checked retained initialized readonly startup page contains the
    // entire exact slice. It remains owned until the trusted process retirement.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    let caps = ev_cap_server::startup(bytes).unwrap_or_else(|_| runtime::exit(261));
    require(runtime::inspect(caps.requests, 1).status == 1, 262);
    require(runtime::inspect(caps.responses, 1).status == 1, 263);
    serve(caps)
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    runtime::exit(399)
}
