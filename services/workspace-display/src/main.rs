#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
mod native;
// SAFETY: measured executable uses the common scalar entry and intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: selected M8 image admits charged stack480..487 with absent479/488
// guards. No legacy image/stack layout is selected by this separate executable.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x80001e8000",
    "and rsp, -16",
    "call ev_workspace_display_main",
    "ud2"
);
// SAFETY: fixed measured entry only, with actual readonly startup mapping.
#[unsafe(no_mangle)]
extern "C" fn ev_workspace_display_main(record: u64, length: u64, stop: u64) -> ! {
    native::run(record, length, stop)
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1399)
}
