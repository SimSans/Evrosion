#![no_std]
#![no_main]
#[cfg(not(any(feature = "native-a", feature = "native-b")))]
compile_error!("choose the separately measured native-a or native-b image");
#[cfg(all(feature = "native-a", feature = "native-b"))]
compile_error!("native-a and native-b are separate package images");
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
#[cfg(not(feature = "downloaded-c"))]
mod interactive;
// SAFETY: one native source ELF owns this ordinary entry and memory intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: measured four-page private RW/NX stack pages256..259, guarded255/260.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000104000",
    "and rsp,-16",
    "call ev_native_main",
    "ud2"
);
pub(crate) fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code)
    }
}
pub(crate) fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 700);
    r.value
}
#[cfg(not(feature = "downloaded-c"))]
pub(crate) fn yield_now() {
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 701)
}
#[cfg(not(feature = "downloaded-c"))]
pub(crate) fn event(cap: u64, bytes: [u8; 8], stop: u64) {
    let retry_stop = if stop == 0 {
        rt::execution::deadline(stop, now(), 512).unwrap_or_else(|_| rt::exit(702))
    } else {
        stop
    };
    loop {
        require(now() < retry_stop, 702);
        let r = rt::send(cap, bytes);
        require(r.value == 0 && r.capability == 0, 708);
        match r.status {
            0 => return,
            2 => yield_now(),
            _ => rt::exit(709),
        }
    }
}
#[cfg(not(feature = "downloaded-c"))]
pub(crate) fn grant(
    b: &ev_userspace_contract::Bootstrap<'_>,
    selector: u64,
    kind: u8,
    rights: u16,
) -> u64 {
    let g = b.find(selector).unwrap_or_else(|| rt::exit(703));
    require(g.kind == kind && g.rights == rights, 704);
    g.handle
}
// SAFETY: unique native entry receives the actual readonly336 startup mapping
// and finite controller stop. Syntax/roles are checked, not treated as authority.
#[unsafe(no_mangle)]
extern "C" fn ev_native_main(record: u64, length: u64, stop: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record < (1 << 47) - 4096,
        705,
    );
    // SAFETY: actual admitted loader retains the exact initialized startup extent.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let b = ev_native_hello::startup(bytes).unwrap_or_else(|_| rt::exit(706));
    require(
        rt::execution::validate(stop, now(), cfg!(feature = "native-session")).is_ok(),
        707,
    );
    #[cfg(feature = "downloaded-c")]
    {
        core::hint::black_box(b);
        // SAFETY: explicit downloaded negative fixture executes a real user
        // invalid-opcode fault after startup validation and before Ready.
        unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
    }
    #[cfg(not(feature = "downloaded-c"))]
    {
        #[cfg(feature = "downloaded-b")]
        core::hint::black_box(b"Evrosion DEVELOPMENT downloaded Hello B v1");
        interactive::run(&b, record, stop)
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(799)
}
