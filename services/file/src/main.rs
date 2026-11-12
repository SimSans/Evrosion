#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
#[cfg(not(feature = "server"))]
mod app;
#[cfg(feature = "desktop")]
mod desktop_actor;
#[cfg(all(feature = "server", not(feature = "desktop")))]
mod server;
mod window;
// SAFETY: one measured executable uses the shared entry and memory intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: the ordinary loader validates/charges the measured four-page RW/NX
// private stack and adjacent absent guards before this never-returning entry.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000104000",
    "and rsp, -16",
    "call ev_file_main",
    "ud2"
);
pub(crate) fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
pub(crate) fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 600);
    r.value
}
pub(crate) fn yield_now() {
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 601);
}
// SAFETY: unique symbol receives the truthful fixed startup ABI and finite
// controller stop from the trusted measured process loader, never app authority.
#[unsafe(no_mangle)]
extern "C" fn ev_file_main(record: u64, length: u64, stop: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record < (1 << 47) - 4096,
        602,
    );
    // SAFETY: validated exact readonly startup extent, retained by the loader.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    #[cfg(feature = "desktop")]
    desktop_actor::run(bytes, record, stop);
    #[cfg(all(feature = "server", not(feature = "desktop")))]
    server::run(bytes, record, stop);
    #[cfg(not(feature = "server"))]
    app::run(bytes, record, stop);
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(699)
}
