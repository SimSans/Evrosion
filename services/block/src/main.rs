#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_block_service::{
    CONTROL_PORT, Capabilities, PORT_BASE, RECORD, SEED, SEED_LBA, TEST_LBA,
    ata::{AtaPio, Error, Failure, Ports, Progress},
};
use ev_userspace_contract::{SIZE, syscall};
use ev_userspace_runtime as rt;
#[cfg(feature = "desktop-driver")]
mod desktop_actor;
#[cfg(feature = "test-generation-client")]
mod generation_actor;
mod rpc_actor;
#[cfg(feature = "test-store-client")]
mod store_actor;

// SAFETY: unique measured entry/readonly bootstrap and retained private SysV
// stack, with the common freestanding memory intrinsics and scalar trap ABI.
global_asm!(ev_userspace_runtime::start_assembly!());
#[cfg(feature = "test-store-client")]
// SAFETY: separately measured four-page RW/NX stack is initialized and checked
// by the ordinary ELF loader/controller before dispatch. RDI/RSI/RDX survive the
// entry switch, and the Rust entry never returns to the discarded initial stack.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000104000",
    "and rsp, -16",
    "call ev_store_main",
    "ud2",
);
const MODE: u8 = if cfg!(feature = "desktop-driver") {
    9
} else if cfg!(feature = "test-direct-fault") {
    2
} else if cfg!(feature = "test-block-driver") {
    4
} else if cfg!(feature = "test-block-client-write") {
    5
} else if cfg!(feature = "test-block-client-verify") {
    6
} else if cfg!(feature = "test-generation-client") {
    8
} else if cfg!(feature = "test-store-client") {
    7
} else if cfg!(feature = "test-write") && !cfg!(feature = "test-verify") {
    0
} else if cfg!(feature = "test-verify") && !cfg!(feature = "test-write") {
    1
} else {
    3
};
const ABI_ERROR: u64 = u64::MAX;

struct Mediated {
    cap: u64,
}
impl Ports for Mediated {
    fn input(&mut self, port: u16, width: u8) -> Result<u32, u64> {
        let reply = rt::call4(
            syscall::PORT_INPUT,
            self.cap,
            u64::from(port),
            u64::from(width),
            0,
        );
        if reply.status != 0 {
            return Err(reply.status);
        }
        if reply.capability != 0
            || reply.serial != 0
            || reply.value
                > match width {
                    1 => 255,
                    2 => 65535,
                    _ => u32::MAX as u64,
                }
        {
            return Err(ABI_ERROR);
        }
        u32::try_from(reply.value).map_err(|_| ABI_ERROR)
    }
    fn output(&mut self, port: u16, width: u8, value: u32) -> Result<(), u64> {
        let reply = rt::call4(
            syscall::PORT_OUTPUT,
            self.cap,
            u64::from(port),
            u64::from(width),
            u64::from(value),
        );
        if reply.status != 0 {
            return Err(reply.status);
        }
        if reply.value != 0 || reply.capability != 0 || reply.serial != 0 {
            return Err(ABI_ERROR);
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, u64> {
        let reply = rt::monotonic();
        if reply.status == 0 {
            Ok(reply.value)
        } else {
            Err(reply.status)
        }
    }
    fn yield_now(&mut self) -> Result<(), u64> {
        let reply = rt::yield_now();
        if reply.status == 0 {
            Ok(())
        } else {
            Err(reply.status)
        }
    }
}
fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code);
    }
}
fn fail(stage: u16, failure: Failure) -> ! {
    let (kind, detail) = match failure.error {
        Error::Io(value) => (1, value & u32::MAX as u64),
        Error::Deadline => (2, 0),
        Error::ClockReversed => (3, 0),
        Error::PollBudget => (4, 0),
        Error::NoDevice => (5, 0),
        Error::Device { status, error } => (6, (u64::from(status) << 8) | u64::from(error)),
        Error::Protocol => (7, 0),
        Error::Identity => (8, 0),
        Error::Geometry => (9, 0),
        Error::Unsupported => (10, 0),
        Error::Bounds => (11, 0),
        Error::NotIdentified => (12, 0),
        Error::NeedsReset => (13, 0),
    };
    rt::exit(
        (u64::from(stage) << 48)
            | (u64::from(failure.progress == Progress::MayHaveExecuted) << 40)
            | (kind << 32)
            | detail,
    )
}
fn probes(caps: Capabilities) {
    // Legacy scalar operations preserve R10 even when called through the wider
    // wrapper. Port operations alone consume/clear the added fourth argument.
    const CLOCK_CANARY: u64 = 0x7a31_d4f0_85ce_129b;
    const YIELD_CANARY: u64 = 0xe5ca_6209_3471_b80f;
    let clock = rt::call4(syscall::MONOTONIC, 0, 0, 0, CLOCK_CANARY);
    require(
        clock.status == 0
            && clock.value > 0
            && clock.capability == 0
            && clock.serial == CLOCK_CANARY,
        208,
    );
    let yielded = rt::call4(syscall::YIELD, 0, 0, 0, YIELD_CANARY);
    require(
        yielded.status == 0
            && yielded.value == 0
            && yielded.capability == 0
            && yielded.serial == YIELD_CANARY,
        209,
    );
    // Every negative is rejected before the kernel executes an I/O instruction.
    // The byte writes below are control attempts, not accepted device commands.
    let cases = [
        (
            syscall::PORT_INPUT,
            u64::MAX,
            u64::from(PORT_BASE + 7),
            1,
            0,
            1,
        ),
        (syscall::PORT_INPUT, caps.ports, 0x3f8, 1, 0, 1),
        (
            syscall::PORT_INPUT,
            caps.ports,
            u64::from(PORT_BASE),
            4,
            0,
            1,
        ),
        (
            syscall::PORT_OUTPUT,
            caps.read_only,
            u64::from(CONTROL_PORT),
            1,
            2,
            1,
        ),
        (syscall::PORT_INPUT, caps.ports, 65536, 1, 0, 3),
        (
            syscall::PORT_INPUT,
            caps.ports,
            u64::from(PORT_BASE + 7),
            0,
            0,
            3,
        ),
        (
            syscall::PORT_OUTPUT,
            caps.ports,
            u64::from(CONTROL_PORT),
            1,
            256,
            3,
        ),
        (
            syscall::PORT_INPUT,
            caps.ports,
            u64::from(PORT_BASE + 7),
            1,
            1,
            3,
        ),
    ];
    for (index, (number, cap, port, width, value, status)) in cases.into_iter().enumerate() {
        let reply = rt::call4(number, cap, port, width, value);
        require(
            reply.status == status
                && reply.value == 0
                && reply.capability == 0
                && reply.serial == 0,
            200 + index as u64,
        );
    }
}
fn storage(caps: Capabilities, write: bool) {
    probes(caps);
    let clock = rt::monotonic();
    require(clock.status == 0, 180);
    // One finite absolute bound survives reset/identify and every data command;
    // each poll/data loop independently has a finite counter as well.
    let deadline = clock
        .value
        .checked_add(512)
        .unwrap_or_else(|| rt::exit(181));
    let mut disk = AtaPio::new(Mediated { cap: caps.ports });
    disk.reset(deadline).unwrap_or_else(|f| fail(210, f));
    disk.identify(deadline).unwrap_or_else(|f| fail(211, f));
    let mut bytes = [0u8; 512];
    disk.read_sector(SEED_LBA, &mut bytes, deadline)
        .unwrap_or_else(|f| fail(212, f));
    require(bytes == SEED, 213);
    if write {
        disk.write_sector(TEST_LBA, &RECORD, deadline)
            .unwrap_or_else(|f| fail(214, f));
        disk.flush(deadline).unwrap_or_else(|f| fail(215, f));
    }
    disk.read_sector(TEST_LBA, &mut bytes, deadline)
        .unwrap_or_else(|f| fail(216, f));
    require(bytes == RECORD, 217);
    disk.idle(deadline).unwrap_or_else(|f| fail(218, f));
}
fn direct_fault() -> ! {
    // SAFETY: separately measured negative fixture. A raw CPL3 IN must #GP even
    // while a mediated port capability exists; no mediated operation precedes it.
    unsafe {
        core::arch::asm!("in ax, dx", in("dx")PORT_BASE, out("ax")_, options(nostack));
    }
    rt::exit(240)
}
// SAFETY: unique executable symbol called only by the shared measured entry.
#[cfg_attr(not(feature = "test-store-client"), unsafe(no_mangle))]
#[cfg_attr(feature = "test-store-client", unsafe(export_name = "ev_store_main"))]
extern "C" fn ev_user_main(record: u64, length: u64, controller_stop: u64) -> ! {
    require(
        length == SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record <= (1 << 47) - 4096,
        182,
    );
    // SAFETY: exact bounded slice stays within the retained initialized readonly
    // startup page; ordinary process admission verified address/length/digest.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    #[cfg(feature = "desktop-driver")]
    if MODE == 9 {
        desktop_actor::run(bytes, record, controller_stop);
    }
    #[cfg(feature = "test-generation-client")]
    if MODE == 8 {
        generation_actor::run(bytes, record, controller_stop);
    }
    #[cfg(feature = "test-store-client")]
    if MODE == 7 {
        store_actor::run(bytes, record, controller_stop);
    }
    match MODE {
        4 => rpc_actor::driver(
            ev_block_service::driver_startup(bytes).unwrap_or_else(|_| rt::exit(328)),
            record,
        ),
        5 | 6 => rpc_actor::client(
            ev_block_service::client_startup(bytes).unwrap_or_else(|_| rt::exit(329)),
            record,
            controller_stop,
            MODE == 5,
        ),
        _ => (),
    }
    let caps = ev_block_service::startup(bytes).unwrap_or_else(|_| rt::exit(183));
    match MODE {
        0 => storage(caps, true),
        1 => storage(caps, false),
        2 => direct_fault(),
        _ => rt::exit(184),
    }
    // A real Exit0 means every byte/status/drain check above ran in userspace.
    rt::exit(0)
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(299)
}
