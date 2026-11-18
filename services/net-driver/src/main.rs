#![no_std]
#![no_main]
#[cfg(not(any(feature = "probe", feature = "driver-service")))]
compile_error!("select one separately measured NIC actor");
#[cfg(all(feature = "probe", feature = "driver-service"))]
compile_error!("probe and driver-service are separate admitted source images");
#[cfg(all(feature = "workspace-profile", feature = "probe"))]
compile_error!("selected workspace-profile is a service actor, not the legacy probe");
use core::{arch::global_asm, panic::PanicInfo};
#[cfg(feature = "probe")]
use ev_net_driver::{REFERENCE_MAC, device::Driver, mediated::Mediated};
use ev_userspace_runtime as rt;
#[cfg(feature = "driver-service")]
mod driver_actor;

// SAFETY: separately measured userspace entry and ordinary freestanding memory
// intrinsics; the actual loader must bind startup and all private mappings.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: the actual admitted ELF must retain this sixteen-KiB RW/NX stack and
// unmapped guard pages; only a qualified producer may dispatch this probe.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x8000104000",
    "and rsp,-16",
    "call ev_net_main",
    "ud2",
);

/// A bounded, explicitly selected initialization/stop probe. The network service
/// RPC loop and actual Root/capability graph remain separate integration work.
///
/// # Safety
/// The actual loader supplies the immutable v1 startup at its reserved page;
/// only the admitted source image may enter through the assembly trampoline.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ev_net_main(record: *const u8, size: usize, stop: u64) -> ! {
    if record as usize != 0x80001fd000 || size != ev_userspace_contract::SIZE {
        rt::exit(1700);
    }
    // SAFETY: the actual image admission provides exactly this readonly mapped
    // startup extent for the lifetime of the process; address/length checked.
    let bytes = unsafe { core::slice::from_raw_parts(record, size) };
    #[cfg(feature = "driver-service")]
    driver_actor::run(bytes, stop);
    #[cfg(feature = "probe")]
    probe(bytes, stop)
}

#[cfg(feature = "probe")]
fn probe(bytes: &[u8], _: u64) -> ! {
    let cap = ev_net_driver::probe_startup(bytes).unwrap_or_else(|_| rt::exit(1701));
    let ports = Mediated::new(cap).unwrap_or_else(|_| rt::exit(1702));
    let mut driver = Driver::new(ports);
    let clock = rt::call4(rt::syscall::MONOTONIC, 0, 0, 0, 0);
    if clock.status != 0 || clock.capability != 0 || clock.serial != 0 {
        rt::exit(1703);
    }
    let deadline = clock
        .value
        .checked_add(8192)
        .filter(|n| *n != u64::MAX)
        .unwrap_or_else(|| rt::exit(1704));
    driver
        .initialize(REFERENCE_MAC, deadline)
        .unwrap_or_else(|_| rt::exit(1705));
    driver.start(deadline).unwrap_or_else(|_| rt::exit(1706));
    driver
        .stop_and_scrub(deadline)
        .unwrap_or_else(|_| rt::exit(1707));
    rt::exit(0)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1799)
}
