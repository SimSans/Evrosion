#![no_std]
#![no_main]
#[cfg(not(any(feature = "consumer", feature = "provider-a", feature = "provider-b")))]
compile_error!("select exactly one source actor feature");
#[cfg(any(
    all(feature = "consumer", feature = "provider-a"),
    all(feature = "consumer", feature = "provider-b"),
    all(feature = "provider-a", feature = "provider-b")
))]
compile_error!("source actors have separate measured images");
use core::{arch::global_asm, panic::PanicInfo};
use ev_provider_test as policy;
use ev_userspace_runtime as rt;
#[cfg(feature = "consumer")]
mod consumer;
#[cfg(any(feature = "provider-a", feature = "provider-b"))]
mod provider;
// SAFETY: one measured source executable owns this ordinary entry/intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: actual ELF declares16KiB RW/NX stack at256..259 with absent255/260.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x8000104000",
    "and rsp,-16",
    "call ev_switch_main",
    "ud2"
);
fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code)
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 300);
    r.value
}
fn yield_now(stop: u64) {
    require(now() < stop, 301);
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 302)
}
fn send(endpoint: u64, bytes: [u8; 8], stop: u64) {
    loop {
        require(now() < stop, 303);
        let r = rt::send(endpoint, bytes);
        require(r.value == 0 && r.capability == 0, 304);
        match r.status {
            0 => return,
            2 => yield_now(stop),
            _ => rt::exit(305),
        }
    }
}
fn bind_self(endpoint: u64) {
    let r = rt::call(rt::syscall::BIND_RECEIVER, endpoint, 0, 0);
    require(r.status == 0 && r.value == 0 && r.capability == 0, 306)
}
fn scalar_abi_probes() {
    // Actual trap boundary: legacy scalar calls preserve R10; RPC receive/reply
    // use it separately for the protected nonce, never as a capability.
    const CANARY: u64 = 0xc39e_6d27_418a_b5f0;
    let clock = rt::call4(rt::syscall::MONOTONIC, 0, 0, 0, CANARY);
    require(
        clock.status == 0 && clock.capability == 0 && clock.serial == CANARY,
        309,
    );
    let yielded = rt::call4(rt::syscall::YIELD, 0, 0, 0, CANARY);
    require(
        yielded.status == 0
            && yielded.value == 0
            && yielded.capability == 0
            && yielded.serial == CANARY,
        310,
    );
}
// SAFETY: actual loader provides the retained ordinary336-byte read-only
// bootstrap mapping and finite controller stop inRDX. Stop is not authority.
#[unsafe(no_mangle)]
extern "C" fn ev_switch_main(record: u64, length: u64, stop: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record < (1 << 47) - 4096,
        307,
    );
    require(stop != u64::MAX && stop > now(), 308);
    scalar_abi_probes();
    // SAFETY: exact retained initialized readonly startup extent checked above.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    #[cfg(feature = "consumer")]
    consumer::run(bytes, stop);
    #[cfg(any(feature = "provider-a", feature = "provider-b"))]
    provider::run(bytes, stop);
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(399)
}
