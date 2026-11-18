#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
mod native;
// SAFETY: this separate measured Root executable owns the scalar entry/runtime.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: selected Root V5 loader admits32KiB RW/NX stack256..263; guards255/264.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x8000108000",
    "and rsp,-16",
    "call ev_workspace_root_main",
    "ud2"
);
// SAFETY: only measured startup enters with the actual immutable Root record.
#[unsafe(no_mangle)]
extern "C" fn ev_workspace_root_main(record: u64, length: u64, stop: u64) -> ! {
    native::run(record, length, stop)
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1699)
}
