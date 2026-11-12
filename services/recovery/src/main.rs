#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_contract::{Event, SIZE};
use ev_userspace_runtime as runtime;

// SAFETY: unique measured executable entry uses the common fixed SysV startup
// and memory intrinsics; it preserves the kernel-provided RDI/RSI record inputs.
global_asm!(ev_userspace_runtime::start_assembly!());

// SAFETY: unique symbol called only by this executable's shared entry assembly.
#[unsafe(no_mangle)]
extern "C" fn ev_user_main(record: u64, length: u64) -> ! {
    if length != SIZE as u64
        || record == 0
        || !record.is_multiple_of(4096)
        || record > (1 << 47) - 4096
    {
        runtime::exit(140);
    }
    // SAFETY: checked startup ABI bounds one retained initialized read-only
    // page; a missing/corrupt mapping faults this isolated recovery process.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    let caps = ev_recovery_service::startup(bytes).unwrap_or_else(|_| runtime::exit(141));
    if runtime::inspect(caps.probe, 1).status != 0
        || runtime::inspect(caps.probe, 2).status != 1
        || runtime::inspect(u64::MAX, 1).status != 1
    {
        runtime::exit(142);
    }
    // This acknowledgement proves separate execution. The actual failed token,
    // fault record and custody reason remain retained by the trusted controller.
    if runtime::send(caps.events, Event::RecoveryReady.encode()).status != 0 {
        runtime::exit(143);
    }
    loop {
        if runtime::yield_now().status != 0 {
            runtime::exit(144);
        }
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    runtime::exit(149)
}
