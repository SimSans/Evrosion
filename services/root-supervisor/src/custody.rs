//! Separate measured artifact: construct a real graph, then fail the Root itself.
use ev_userspace_contract::{Bootstrap, Event, echo, syscall};
use ev_userspace_runtime as rt;

fn required(number: u64, a: u64, b: u64, c: u64) -> u64 {
    let reply = rt::call(number, a, b, c);
    if reply.status != 0 {
        rt::exit(200 + number);
    }
    reply.value
}
fn start(job: u64, image: u64, requests: u64, replies: u64) -> u64 {
    let process = required(syscall::CREATE_PROCESS, job, image, 0);
    required(syscall::DELEGATE, process, requests, 3);
    required(syscall::DELEGATE, process, replies, 4);
    required(syscall::BIND_RECEIVER, requests, process, 0);
    required(syscall::START, process, 0, 0);
    process
}
pub fn run(bytes: &[u8], events: u64) {
    let record = Bootstrap::parse(bytes).unwrap_or_else(|_| rt::exit(240));
    let creator = record.find(3).unwrap_or_else(|| rt::exit(241));
    let image = record.find(4).unwrap_or_else(|| rt::exit(242));
    if record.grants().count() != 4
        || creator.kind != 5
        || creator.rights != 256
        || image.kind != 1
        || image.rights != 1
    {
        rt::exit(243);
    }
    let jobs = [
        required(syscall::CREATE_JOB, creator.handle, 0, 0),
        required(syscall::CREATE_JOB, creator.handle, 0, 0),
    ];
    let channels = core::array::from_fn::<_, 4, _>(|_| {
        required(syscall::CREATE_ENDPOINT, creator.handle, 0, 0)
    });
    let children = [
        start(jobs[0], image.handle, channels[0], channels[1]),
        start(jobs[1], image.handle, channels[2], channels[3]),
    ];
    for child in 0..2 {
        let now = rt::monotonic();
        if now.status != 0 {
            rt::exit(244);
        }
        let deadline = now.value.checked_add(32).unwrap_or_else(|| rt::exit(245));
        let value = u32::try_from(record.incarnation())
            .ok()
            .and_then(|n| n.checked_mul(16))
            .and_then(|n| n.checked_add(child as u32))
            .unwrap_or_else(|| rt::exit(246));
        let reply = echo::client_call(
            &mut rt::SyncEndpoint {
                endpoint: channels[child * 2],
            },
            value,
            deadline,
        )
        .unwrap_or_else(|_| rt::exit(247));
        if reply.value != value {
            rt::exit(248);
        }
    }
    required(
        syscall::SEND,
        events,
        u64::from_le_bytes(Event::ServiceResponded.encode()),
        0,
    );
    // This newly created Process capability explicitly carries TRANSFER. Move
    // it into a real queue; the kernel retains the independent image owner.
    required(
        syscall::SEND,
        channels[1],
        0x4355_5354_4f44_5901,
        children[0],
    );
    #[cfg(feature = "custody-exit")]
    rt::exit(0x4355_5354_4f44_5902);
    #[cfg(all(feature = "custody-watchdog", not(feature = "custody-exit")))]
    loop {
        // SAFETY: unprivileged finite PAUSE instructions retain ordinary IRQ
        // preemption. This measured fixture deliberately stops reporting progress.
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack, preserves_flags));
        }
    }
    // SAFETY: this separately measured failure artifact deliberately faults its
    // own Root at CPL3 after constructing and exercising the entire child graph.
    #[cfg(not(any(feature = "custody-exit", feature = "custody-watchdog")))]
    unsafe {
        core::arch::asm!("mov byte ptr [{address}], 0", address=in(reg)0u64, options(nostack));
        core::arch::asm!("ud2", options(noreturn));
    }
}
