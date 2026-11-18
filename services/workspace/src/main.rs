#![no_std]
#![no_main]

use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
mod native;

// SAFETY: measured V5 executable shares the existing scalar entry/intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: the distinct V5 loader must admit the charged private stack480..487
// with absent479/488 guards and NX before entering this measured image.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x80001e8000",
    "and rsp, -16",
    "call ev_workspace_main",
    "ud2"
);

// SAFETY: only the fixed measured userspace entry calls this symbol.
#[unsafe(no_mangle)]
extern "C" fn ev_workspace_main(record: u64, length: u64, stop: u64) -> ! {
    native::run(record, length, stop)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1299)
}
