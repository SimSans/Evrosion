//! Q35 bootstrap PIC/PIT boundary. APIC and SMP routing are later work.
use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use ev_kernel::time::{Deadline, wait_bounded};
static ACTIVE: AtomicBool = AtomicBool::new(false);
static TICKS: AtomicU64 = AtomicU64::new(0);
const DIVISOR: u16 = 1193;

/// # Safety
/// Ring 0, bootstrap owner of PIC/PIT; only documented controller ports allowed.
unsafe fn out(port: u16, value: u8) {
    // SAFETY: caller holds controller ownership and selects a valid I/O register.
    unsafe {
        asm!("out dx, al", in("dx") port,in("al") value,options(nomem,nostack,preserves_flags));
    }
}
/// IRQ0 only. Called with IF cleared by the interrupt gate; never blocks/allocates.
pub fn interrupt() -> bool {
    if !ACTIVE.load(Ordering::Acquire) {
        return false;
    }
    // A wrapped clock would invalidate every absolute deadline; fail before wrap.
    let Some(next) = now().checked_add(1) else {
        crate::finish(false)
    };
    // This IRQ is the sole writer; the interrupt gate prevents nested writers.
    TICKS.store(next, Ordering::Relaxed);
    // SAFETY: installed IRQ0 vector; PIC initialization selected manual EOI.
    unsafe {
        out(0x20, 0x20);
    }
    true
}
pub(crate) fn now() -> u64 {
    TICKS.load(Ordering::Relaxed)
}
pub struct Proof {
    pub ticks: u64,
    pub deadline: u64,
}
/// # Safety
/// Sole Q35 boot CPU after owned IDT installation, IF=0. No other controller
/// driver or AP active. Returns with IF=0 and every PIC input masked.
pub unsafe fn prove() -> Proof {
    let flags: u64;
    // SAFETY: ring-0 stack is valid and interrupts are still disabled.
    unsafe {
        asm!("pushfq","pop {}",out(reg) flags,options(preserves_flags));
    }
    assert_eq!(flags & (1 << 9), 0);
    assert_eq!(now(), 0);
    assert!(!ACTIVE.load(Ordering::Acquire));
    // SAFETY: exclusive PIC/PIT bootstrap ownership; fixed Intel ICW sequence,
    // remap IRQ0..15 to vectors32..47 and mask every source before programming PIT.
    unsafe {
        out(0x21, 0xff);
        out(0xa1, 0xff);
        out(0x20, 0x11);
        out(0xa0, 0x11);
        out(0x21, 32);
        out(0xa1, 40);
        out(0x21, 4);
        out(0xa1, 2);
        out(0x21, 1);
        out(0xa1, 1);
        out(0x21, 0xff);
        out(0xa1, 0xff);
        out(0x43, 0x34); // Channel 0, LSB+MSB, mode2, binary counter.
        out(0x40, DIVISOR as u8);
        out(0x40, (DIVISOR >> 8) as u8);
    }
    let deadline = Deadline::after(now(), 8).expect("timer deadline");
    ACTIVE.store(true, Ordering::Release);
    // SAFETY: the owned IRQ handler is ready, but both controllers are masked.
    // Enable IF to exercise the masks; a stopped clock must exhaust its budget.
    // STI/CLI keep compiler memory barriers around asynchronous state changes.
    let stalled = unsafe {
        asm!("sti", options(nostack));
        let stalled = wait_bounded(deadline, 256, now);
        asm!("cli", options(nostack));
        stalled
    };
    assert!(stalled.is_err());
    assert_eq!(now(), 0);
    // SAFETY: owned IDT vector32 and nonallocating handler are ready; only IRQ0
    // is unmasked. Finite polling tolerates a broken timer without unbounded HLT.
    let result = unsafe {
        out(0x21, 0xfe);
        asm!("sti", options(nostack));
        let result = wait_bounded(deadline, 20_000_000, now);
        asm!("cli", options(nostack));
        out(0x21, 0xff);
        result
    };
    ACTIVE.store(false, Ordering::Release);
    let observed = result.expect("timer failed to advance within polling budget");
    assert!(observed >= deadline.tick());
    let after: u64;
    // SAFETY: interrupts disabled and controller masked; flags readback only.
    unsafe {
        asm!("pushfq","pop {}",out(reg) after,options(preserves_flags));
    }
    assert_eq!(after & (1 << 9), 0);
    Proof {
        ticks: now(),
        deadline: deadline.tick(),
    }
}

/// # Safety
/// BSP with IF=0, PIC/PIT already initialized by prove(), AP parked, owned IRQ0
/// handler installed. Caller must stop the clock before relinquishing ownership.
pub(crate) unsafe fn start_runtime() {
    assert!(!ACTIVE.swap(true, Ordering::AcqRel));
    assert!(now() >= 8);
    // SAFETY: exclusive controller owner, only initialized IRQ0 may be unmasked;
    // the negative fixture intentionally keeps every source masked.
    unsafe {
        out(
            0x21,
            if cfg!(feature = "test-preempt-stall") {
                0xff
            } else {
                0xfe
            },
        );
    }
}
/// # Safety
/// Same runtime owner, IF=0, no outstanding interrupt entry on this CPU.
pub(crate) unsafe fn stop_runtime() {
    // SAFETY: initialized PIC, exclusive owner; mask before disarming handler.
    unsafe {
        out(0x21, 0xff);
    }
    assert!(ACTIVE.swap(false, Ordering::AcqRel));
}
