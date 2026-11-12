#![no_std]
#![no_main]
#[cfg(all(
    feature = "provider-switch",
    any(
        feature = "desktop-root",
        feature = "service-launch",
        feature = "service-restart",
        feature = "custody-graph",
        feature = "test-fault",
        feature = "generation-good",
        feature = "generation-bad",
        feature = "generation-silent"
    )
))]
compile_error!("provider-switch is a separate ordinary-startup Root profile");
use core::{
    arch::{asm, global_asm},
    panic::PanicInfo,
};
#[cfg(not(any(
    feature = "desktop-root",
    feature = "provider-switch",
    feature = "ipc-bench-root"
)))]
use ev_userspace_contract::{Event, SIZE};
use ev_userspace_runtime as runtime;
#[cfg(all(feature = "custody-graph", not(feature = "desktop-root")))]
mod custody;
#[cfg(all(feature = "service-restart", not(feature = "desktop-root")))]
mod restart;
// SAFETY: fixed SysV entry preserves kernel-provided RDI/RSI, aligns the private
// stack and calls the no_std Rust entry. Memory intrinsics obey the same ABI.
global_asm!(ev_userspace_runtime::start_assembly!());

#[cfg(feature = "ipc-bench-root")]
mod ipc_bench;
#[cfg(feature = "ipc-bench-root")]
// SAFETY: ordinary336 startup; four16KiB RW/NX stackpages andabsentguards.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x8000104000",
    "and rsp,-16",
    "call ev_ipc_root",
    "ud2"
);
#[cfg(feature = "ipc-bench-root")]
#[unsafe(no_mangle)]
extern "C" fn ev_ipc_root(record: u64, length: u64, stop: u64) -> ! {
    if length != ev_userspace_contract::SIZE as u64
        || record == 0
        || !record.is_multiple_of(4096)
        || record >= (1 << 47) - 4096
        || stop == 0
        || stop == u64::MAX
    {
        runtime::exit(700);
    }
    // SAFETY: exact actual readonly ordinary startup extent validated above.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    ipc_bench::run(bytes, stop)
}
#[cfg(all(
    feature = "ipc-bench-root",
    any(
        feature = "provider-switch",
        feature = "desktop-root",
        feature = "service-launch",
        feature = "service-restart",
        feature = "custody-graph",
        feature = "test-fault",
        feature = "generation-good",
        feature = "generation-bad",
        feature = "generation-silent"
    )
))]
compile_error!("IPC benchmark has a distinct ordinary Root profile");
#[cfg(feature = "provider-switch")]
mod provider;
#[cfg(feature = "provider-switch")]
// SAFETY: this separate ordinary336 profile declares the same16KiB private
// guarded stack segment; it does not select desktop RootV2 or its catalogue ABI.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000104000",
    "and rsp,-16",
    "call ev_provider_root",
    "ud2"
);
#[cfg(feature = "provider-switch")]
#[unsafe(no_mangle)]
extern "C" fn ev_provider_root(record: u64, length: u64, stop: u64) -> ! {
    if length != ev_userspace_contract::SIZE as u64
        || record == 0
        || !record.is_multiple_of(4096)
        || record >= (1 << 47) - 4096
        || stop == u64::MAX
        || stop == 0
    {
        runtime::exit(307);
    }
    // SAFETY: actual loader owns this exact initialized readonly336 bootstrap
    // extent. Provider policy defensively validates all6 roles/finite limits.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    provider::run(bytes, stop)
}

#[cfg(feature = "desktop-root")]
mod desktop;
#[cfg(all(feature = "desktop-root", not(feature = "native-root")))]
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000104000",
    "and rsp,-16",
    "call ev_desktop_root",
    "ud2"
);
#[cfg(feature = "native-root")]
// SAFETY: explicit measured Native profile maps8 private stack pages256..263
// RW/NX, guards255/264; named Native loader owns bootstrap and mappings.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000108000",
    "and rsp,-16",
    "call ev_desktop_root",
    "ud2"
);
#[cfg(feature = "desktop-root")]
#[unsafe(no_mangle)]
extern "C" fn ev_desktop_root(record: u64, length: u64, bound: u64) -> ! {
    // SAFETY: named loaded RootV2 readonly startup/catalogue ownership is
    // retained by the Kernel activation owner; desktop::run checks bounds.
    #[cfg(feature = "native-root")]
    unsafe {
        desktop::run_native(record, length, bound)
    }
    #[cfg(not(feature = "native-root"))]
    // SAFETY: exact named loaded Desktop Root ownership; adapter checks bounds.
    unsafe {
        desktop::run(record, length, bound)
    }
}

fn call(number: u64, a: u64, b: u64, c: u64) -> u64 {
    runtime::call(number, a, b, c).status
}
fn fail(code: u64) -> ! {
    call(1, code, 0, 0);
    // SAFETY: if exit unexpectedly returns, fault this userspace process only.
    unsafe {
        asm!("ud2", options(noreturn));
    }
}
// SAFETY: unique symbol called only by this executable's entry assembly.
#[unsafe(no_mangle)]
#[cfg(not(any(
    feature = "desktop-root",
    feature = "provider-switch",
    feature = "ipc-bench-root"
)))]
extern "C" fn ev_user_main(record: u64, length: u64) -> ! {
    if length != SIZE as u64 || record == 0 || !record.is_multiple_of(4096) {
        fail(90);
    }
    // SAFETY: compiled bootstrap ABI supplies one retained read-only user page
    // and exact bounded size. A corrupt mapping faults this isolated process.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    let caps = ev_root_supervisor::startup(bytes).unwrap_or_else(|_| fail(91));
    if call(4, caps.probe, 1, 0) != 0
        || call(4, caps.probe, 2, 0) != 1
        || call(4, u64::MAX, 1, 0) != 1
    {
        fail(92);
    }
    if call(2, caps.events, u64::from_le_bytes(Event::Ready.encode()), 0) != 0 {
        fail(93);
    }
    #[cfg(all(feature = "service-restart", not(feature = "desktop-root")))]
    restart::run(bytes, caps.events);
    #[cfg(all(feature = "custody-graph", not(feature = "desktop-root")))]
    custody::run(bytes, caps.events);
    #[cfg(all(feature = "service-launch", not(feature = "desktop-root")))]
    launch(bytes, caps.events);
    if cfg!(feature = "generation-good")
        && !cfg!(feature = "generation-bad")
        && !cfg!(feature = "generation-silent")
        && !cfg!(feature = "test-fault")
    {
        // A generic Ready only reports bootstrap. This separate measured
        // profile reports critical initialization after all actual authority
        // checks above. Its caller still verifies sender identity and liveness.
        if call(
            2,
            caps.events,
            u64::from_le_bytes(Event::CriticalReady.encode()),
            0,
        ) != 0
        {
            fail(98);
        }
    }
    #[cfg(any(feature = "test-fault", feature = "generation-bad"))]
    // SAFETY: separately identified fault-injection artifact; never in normal service.
    unsafe {
        asm!("mov byte ptr [{address}], 0",address=in(reg)record,options(nostack));
        asm!("ud2", options(noreturn));
    }
    #[cfg(not(any(feature = "test-fault", feature = "generation-bad")))]
    loop {
        if call(0, 0, 0, 0) != 0 {
            fail(94);
        }
    }
}
#[cfg(all(feature = "service-launch", not(feature = "desktop-root")))]
fn launch(bytes: &[u8], events: u64) {
    use ev_userspace_contract::{Bootstrap, syscall};
    let record = Bootstrap::parse(bytes).unwrap_or_else(|_| fail(70));
    let creator = record.find(3).unwrap_or_else(|| fail(71));
    let image = record.find(4).unwrap_or_else(|| fail(72));
    // Invalid/early/duplicate lifecycle messages must be rejected before queue
    // acceptance; they must never panic the kernel or complete a partial graph.
    for payload in [
        [0; 8],
        Event::Ready.encode(),
        Event::ServiceResponded.encode(),
    ] {
        if runtime::send(events, payload).status != 3 {
            fail(96);
        }
    }
    if record.grants().count() != 4
        || creator.kind != 5
        || creator.rights != 256
        || image.kind != 1
        || image.rights != 1
    {
        fail(73);
    }
    if runtime::call(syscall::CREATE_JOB, u64::MAX, 0, 0).status == 0 {
        fail(74);
    }
    if runtime::call(syscall::CREATE_JOB, creator.handle, 99, 0).status == 0 {
        fail(75);
    }
    let job = runtime::call(syscall::CREATE_JOB, creator.handle, 0, 0);
    if job.status != 0 || job.value == 0 {
        fail(76);
    }
    let process = runtime::call(syscall::CREATE_PROCESS, job.value, image.handle, 0);
    if process.status != 0 || process.value == 0 {
        fail(77);
    }
    if runtime::call(syscall::CLOSE, job.value, 0, 0).status != 0 {
        fail(78);
    }
    if runtime::call(syscall::START, process.value, 0, 0).status == 0 {
        fail(79);
    }
    let requests = runtime::call(syscall::CREATE_ENDPOINT, creator.handle, 0, 0);
    let responses = runtime::call(syscall::CREATE_ENDPOINT, creator.handle, 0, 0);
    if requests.status != 0 || responses.status != 0 || requests.value == responses.value {
        fail(80);
    }
    if runtime::call(syscall::DELEGATE, process.value, requests.value, 99).status == 0 {
        fail(81);
    }
    for (source, selector) in [(requests.value, 3), (responses.value, 4)] {
        if runtime::call(syscall::DELEGATE, process.value, source, selector).status != 0 {
            fail(82);
        }
    }
    if runtime::call(syscall::BIND_RECEIVER, requests.value, process.value, 0).status != 0 {
        fail(83);
    }
    if runtime::call(syscall::START, process.value, 0, 0).status != 0 {
        fail(84);
    }
    #[cfg(all(feature = "service-rpc", not(feature = "desktop-root")))]
    {
        exchange_rpc(requests.value);
        if runtime::send(events, Event::ServiceResponded.encode()).status != 0 {
            fail(95);
        }
        if runtime::call(syscall::CLOSE, process.value, 0, 0).status != 0 {
            fail(69);
        }
    }
    #[cfg(not(feature = "service-rpc"))]
    exchange_async(requests.value, responses.value, process.value, events);
}
#[cfg(all(feature = "service-launch", not(feature = "service-rpc")))]
fn exchange_async(requests: u64, responses: u64, process: u64, events: u64) {
    use ev_userspace_contract::{echo, syscall};
    let mut failed = false;
    'exchange: for value in [0, 42, u32::MAX] {
        if runtime::send(requests, echo::Request { value }.encode()).status != 0 {
            let state = runtime::call(syscall::OBSERVE, process, 0, 0);
            if state.status == 0 && state.value == 1 {
                failed = true;
                break;
            }
            fail(85);
        }
        #[cfg(feature = "service-fault")]
        // Deliberate raw-transport pressure in this separate failure artifact:
        // keep one accepted request queued when the server faults after reply.
        if runtime::send(requests, echo::Request { value: 42 }.encode()).status != 0 {
            fail(68);
        }
        loop {
            let mut reply = runtime::receive(responses);
            if reply.status == 2 {
                let state = runtime::call(syscall::OBSERVE, process, 0, 0);
                if state.status == 0 && state.value == 1 {
                    // A reply may have been accepted between Empty and actual
                    // peer retirement. Sender death cannot retract that reply.
                    reply = runtime::receive(responses);
                    if reply.status == 2 {
                        failed = true;
                        break 'exchange;
                    }
                } else {
                    if runtime::yield_now().status != 0 {
                        fail(86);
                    }
                    continue;
                }
            }
            if reply.status != 0 || reply.capability != 0 {
                fail(87);
            }
            let response =
                echo::client_decode(&reply.value.to_le_bytes(), 0).unwrap_or_else(|_| fail(88));
            if response.value != value {
                fail(89);
            }
            break;
        }
        if cfg!(feature = "service-fault") {
            break;
        }
    }
    if cfg!(feature = "service-fault") {
        loop {
            let state = runtime::call(syscall::OBSERVE, process, 0, 0);
            if state.status != 0 {
                fail(97);
            }
            if state.value == 1 {
                break;
            }
            if runtime::yield_now().status != 0 {
                fail(98);
            }
        }
    }
    let event = if cfg!(feature = "service-fault") || failed {
        Event::ServiceStopped
    } else {
        Event::ServiceResponded
    };
    if runtime::send(events, event.encode()).status != 0 {
        fail(95);
    }
    // Closing an ordinary control handle does not cancel the kernel's retained
    // process/image ownership or make quiescent teardown depend on that handle.
    if runtime::call(syscall::CLOSE, process, 0, 0).status != 0 {
        fail(69);
    }
}
#[cfg(all(feature = "service-rpc", not(feature = "desktop-root")))]
fn exchange_rpc(endpoint: u64) {
    use ev_userspace_contract::echo;
    if runtime::rpc_deadline().status != 1 {
        fail(122);
    }
    let clock = runtime::monotonic();
    if clock.status != 0 {
        fail(110);
    }
    let deadline = clock.value.checked_add(16).unwrap_or_else(|| fail(111));
    let mut denied = runtime::SyncEndpoint { endpoint: u64::MAX };
    if echo::client_call(&mut denied, 9, deadline)
        != Err(echo::ClientError::Transport(runtime::SyncError::Status(1)))
    {
        fail(112);
    }
    let mut transport = runtime::SyncEndpoint { endpoint };
    if echo::client_call(&mut transport, 9, clock.value)
        != Err(echo::ClientError::Transport(runtime::SyncError::Status(4)))
    {
        fail(113);
    }
    if cfg!(feature = "service-rpc-timeout") {
        let clock = runtime::monotonic();
        if clock.status != 0 {
            fail(117);
        }
        // Admission has a finite scheduling margin. The delayed server reads
        // this actual protected deadline and withholds its reply beyond it.
        let deadline = clock.value.checked_add(32).unwrap_or_else(|| fail(118));
        if echo::client_call(&mut transport, 0xdeadbeef, deadline)
            != Err(echo::ClientError::Transport(runtime::SyncError::Status(4)))
        {
            fail(119);
        }
    }
    let mut busy = false;
    // Distinct values first expose stale reply delivery. The final timeout-only
    // operation explicitly retries the identical declared READ_ONLY request.
    let values = [0, 42, u32::MAX, 0xdeadbeef];
    for &value in values
        .iter()
        .take(if cfg!(feature = "service-rpc-timeout") {
            4
        } else {
            3
        })
    {
        loop {
            let clock = runtime::monotonic();
            if clock.status != 0 {
                fail(114);
            }
            let deadline = clock.value.checked_add(16).unwrap_or_else(|| fail(115));
            match echo::client_call(&mut transport, value, deadline) {
                Ok(response) if response.value == value => break,
                Err(echo::ClientError::Transport(runtime::SyncError::Status(2)))
                    if cfg!(feature = "service-rpc-timeout") =>
                {
                    busy = true;
                    if runtime::yield_now().status != 0 {
                        fail(120);
                    }
                }
                _ => fail(116),
            }
        }
    }
    if cfg!(feature = "service-rpc-timeout") && !busy {
        fail(121);
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    fail(99)
}
