#![no_std]
#![no_main]
#[cfg(not(any(feature = "client", feature = "server")))]
compile_error!("select one measured IPC actor");
#[cfg(all(feature = "client", feature = "server"))]
compile_error!("client and server are distinct actual images");
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
// SAFETY: one measured source executable owns its entry/intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: exact16KiB RW/NX stack pages256..259, absent guards255/260.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x8000104000",
    "and rsp,-16",
    "call ev_ipc_main",
    "ud2"
);
#[unsafe(no_mangle)]
extern "C" fn ev_ipc_main(record: u64, length: u64, stop: u64) -> ! {
    if length != ev_userspace_contract::SIZE as u64
        || record == 0
        || !record.is_multiple_of(4096)
        || record >= (1 << 47) - 4096
        || stop == 0
        || stop == u64::MAX
    {
        rt::exit(700);
    }
    // SAFETY: actual loader's exact initialized readonly ordinary336 startup.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    #[cfg(feature = "client")]
    let result = ev_ipc_bench::client::run(bytes, stop);
    #[cfg(feature = "server")]
    let result = ev_ipc_bench::server::run(bytes, stop);
    rt::exit(if result.is_ok() { 0 } else { 701 })
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(799)
}
