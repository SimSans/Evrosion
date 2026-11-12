#![no_std]
#![no_main]

use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_contract::{SIZE, echo};
use ev_userspace_runtime as runtime;

// SAFETY: unique executable entry aligns the private SysV stack and preserves
// kernel-supplied RDI/RSI while calling this binary's ev_user_main. Intrinsics
// obey that ABI and keep a single shared implementation across service images.
global_asm!(ev_userspace_runtime::start_assembly!());

// SAFETY: unique symbol called only by the shared executable entry assembly.
#[unsafe(no_mangle)]
extern "C" fn ev_user_main(record: u64, length: u64) -> ! {
    if length != SIZE as u64
        || record == 0
        || !record.is_multiple_of(4096)
        || record > (1 << 47) - 4096
    {
        runtime::exit(100);
    }
    // SAFETY: the measured startup ABI supplies one retained, initialized,
    // read-only user page. This exact bounded slice stays inside that page;
    // kernel admission validates its address/length/digest before entry.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    let caps = ev_echo_service::startup(bytes).unwrap_or_else(|_| runtime::exit(101));
    if runtime::inspect(u64::MAX, 1).status != 1 {
        runtime::exit(107);
    }
    if runtime::inspect(caps.requests, 1).status != 1 {
        runtime::exit(108);
    }
    if runtime::send(caps.requests, [0; 8]).status != 1 {
        runtime::exit(109);
    }
    if runtime::receive(caps.responses).status != 1 {
        runtime::exit(110);
    }
    #[cfg(feature = "test-delay")]
    let mut delayed = false;
    loop {
        let reply = runtime::receive(caps.requests);
        match reply.status {
            2 => {
                if runtime::yield_now().status != 0 {
                    runtime::exit(102);
                }
                continue;
            }
            0 => (),
            _ => runtime::exit(103),
        }
        if reply.capability != 0 {
            runtime::exit(104);
        }
        let response =
            echo::server_dispatch(&reply.value.to_le_bytes(), 0, |request| echo::Response {
                value: request.value,
            })
            .unwrap_or_else(|_| runtime::exit(105));
        #[cfg(feature = "test-delay")]
        if !core::mem::replace(&mut delayed, true) {
            let clock = runtime::rpc_deadline();
            if clock.status != 0 {
                runtime::exit(111);
            }
            let until = clock
                .value
                .checked_add(1)
                .unwrap_or_else(|| runtime::exit(112));
            loop {
                let clock = runtime::monotonic();
                if clock.status != 0 {
                    runtime::exit(113);
                }
                if clock.value >= until {
                    break;
                }
                if runtime::yield_now().status != 0 {
                    runtime::exit(114);
                }
            }
        }
        loop {
            match runtime::send(caps.responses, response).status {
                0 => break,
                // Retain the response across explicit bounded transport
                // backpressure; the dispatcher still enforces its deadline.
                2 if runtime::yield_now().status == 0 => (),
                _ => runtime::exit(106),
            }
        }
        #[cfg(feature = "test-selective-fault")]
        if echo::client_decode(&response, 0)
            .unwrap_or_else(|_| runtime::exit(115))
            .value
            == 0xdeadbeef
        {
            // SAFETY: separately measured test artifact. The decoded special
            // request has already received its reply; actual CPL3 null-page
            // write faults this victim while other instances remain healthy.
            unsafe {
                core::arch::asm!("mov byte ptr [{address}], 0",address=in(reg)0u64,options(nostack));
                core::arch::asm!("ud2", options(noreturn));
            }
        }
        #[cfg(feature = "test-fault")]
        // SAFETY: separately measured fault-injection artifact; after accepting
        // the first response, actually write the unmapped zero page at CPL3.
        // Assembly keeps this a hardware fault rather than a Rust null-pointer UB.
        unsafe {
            core::arch::asm!("mov byte ptr [{address}], 0",address=in(reg)0u64,options(nostack));
            core::arch::asm!("ud2", options(noreturn));
        }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    runtime::exit(199)
}
