//! Timer-driven BSP context proof. No user or AP enters this scheduler.
use crate::threads::Stacks;
use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use ev_kernel::{
    memory::BootstrapFrames,
    scheduler::{Scheduler, State},
};
unsafe extern "C" {
    fn ev_context_switch(old: *mut u64, new: *const u64);
}
static ACTIVE: AtomicBool = AtomicBool::new(false);
static USED: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static REQUEST: AtomicUsize = AtomicUsize::new(0);
static QUANTA: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static PROGRESS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static mut CONTEXTS: [u64; 3] = [0; 3];
const TARGET: u64 = 4;
fn flags() -> u64 {
    let result;
    // SAFETY: initialized kernel stack, read flags only.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) result, options(preserves_flags));
    }
    result
}
fn suspend(request: usize) {
    assert_eq!(flags() & (1 << 9), 0);
    let index = CURRENT.load(Ordering::Relaxed);
    assert!(index < 2);
    REQUEST.store(request, Ordering::Relaxed);
    // SAFETY: BSP with IF=0; controller context was saved before worker entry.
    // No context reference remains live. Each nested trap has a distinct stack.
    unsafe {
        ev_context_switch(
            ptr::addr_of_mut!(CONTEXTS).cast::<u64>().add(index + 1),
            ptr::addr_of!(CONTEXTS).cast::<u64>(),
        );
    }
    assert_eq!(CURRENT.load(Ordering::Relaxed), index);
}
/// Called only after IRQ0 acknowledgement and release of the exception-entry
/// recursion guard. The controller runs with IF=0 and never takes this path.
pub(crate) fn on_tick() {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let index = CURRENT.load(Ordering::Relaxed);
    assert!(index < 2);
    let n = QUANTA[index]
        .load(Ordering::Relaxed)
        .checked_add(1)
        .expect("quantum counter overflow");
    QUANTA[index].store(n, Ordering::Relaxed);
    suspend(0);
}
fn worker(index: usize) -> ! {
    assert_eq!(CURRENT.load(Ordering::Relaxed), index);
    let mut local = [index as u64 + 0x1234; 32];
    let deadline = QUANTA[index].load(Ordering::Relaxed) + TARGET;
    // SAFETY: private guarded stack and owned IRQ0 are ready; no mutable shared
    // references live. Only IRQ0 is unmasked, and AP remains parked with IF=0.
    unsafe {
        asm!("sti", options(nostack));
    }
    let mut finished = false;
    let polls = if cfg!(feature = "test-preempt-stall") {
        4096
    } else {
        20_000_000
    };
    for count in 1..=polls {
        // Work never yields. IRQs must return to this interrupted continuation.
        for (i, word) in local.iter_mut().enumerate() {
            *word = (index as u64 + 1) * 0x10000 + count + i as u64;
        }
        core::hint::black_box(&local);
        PROGRESS[index].store(count, Ordering::Relaxed);
        if QUANTA[index].load(Ordering::Relaxed) >= deadline {
            finished = true;
            break;
        }
    }
    // SAFETY: same BSP runtime owner; finish with IF=0 before scheduler mutation.
    unsafe {
        asm!("cli", options(nostack));
    }
    if cfg!(feature = "test-preempt-stall") && !finished {
        panic!("M1 deliberate masked preemption clock: finite work bound reached");
    }
    assert!(finished, "preempting clock failed within finite work bound");
    let count = PROGRESS[index].load(Ordering::Relaxed);
    assert!(count > 0);
    for (i, word) in local.iter().enumerate() {
        assert_eq!(*word, (index as u64 + 1) * 0x10000 + count + i as u64);
    }
    suspend(1);
    panic!("exited preempted thread resumed")
}
extern "C" fn worker_a() -> ! {
    worker(0)
}
extern "C" fn worker_b() -> ! {
    worker(1)
}
extern "C" fn returned() -> ! {
    panic!("preempted worker returned")
}
pub struct Proof {
    pub quanta: u64,
    pub dispatches: u64,
}
/// # Safety
/// Once on BSP with IF=0 after cooperative contexts exited. IRQ0 initialized,
/// AP parked, retained direct map and sole allocator owner. Soft-float kernel.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    assert!(!USED.swap(true, Ordering::Relaxed));
    assert_eq!(flags() & (1 << 9), 0);
    let original;
    // SAFETY: ring-0 BSP CR3 readback.
    unsafe {
        asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: caller guarantees private allocations and retained loader maps.
    let stacks = unsafe { Stacks::new(offset, original, frames) };
    // SAFETY: copied root preserves controller/kernel and exception mappings;
    // initialize only retained private RW/NX stack pages, with ABI-aligned entry.
    unsafe {
        asm!("mov cr3, {}", in(reg) stacks.tables[0].start(), options(nostack, preserves_flags));
        for (i, (_, top)) in stacks.bounds.into_iter().enumerate() {
            let saved = (top - 64) as *mut u64;
            ptr::write_bytes(saved, 0, 8);
            saved.add(6).write(if i == 0 {
                worker_a as *const () as u64
            } else {
                worker_b as *const () as u64
            });
            saved.add(7).write(returned as *const () as u64);
            ptr::addr_of_mut!(CONTEXTS)
                .cast::<u64>()
                .add(i + 1)
                .write(saved as u64);
        }
    }
    let mut scheduler = Scheduler::new();
    let jobs = [
        scheduler.create_job().unwrap(),
        scheduler.create_job().unwrap(),
    ];
    let processes = jobs.map(|j| scheduler.create_process(j).unwrap());
    let threads = processes.map(|p| scheduler.create_thread(p).unwrap());
    let before = crate::timer::now();
    ACTIVE.store(true, Ordering::Relaxed);
    // SAFETY: initialized owned IRQ0, IF=0; workers alone enable IF.
    unsafe {
        crate::timer::start_runtime();
    }
    let mut dispatches = 0;
    for _ in 0..128 {
        let Some(dispatch) = scheduler.dispatch(0).unwrap() else {
            break;
        };
        let index = threads.iter().position(|&t| t == dispatch.thread).unwrap();
        assert_eq!(dispatch.job, jobs[index]);
        CURRENT.store(index, Ordering::Relaxed);
        REQUEST.store(usize::MAX, Ordering::Relaxed);
        // SAFETY: no scheduler/global reference survives this boundary. IF=0
        // until the selected worker enables it or IRET restores its saved IF.
        unsafe {
            ev_context_switch(
                ptr::addr_of_mut!(CONTEXTS).cast::<u64>(),
                ptr::addr_of!(CONTEXTS).cast::<u64>().add(index + 1),
            );
        }
        assert_eq!(flags() & (1 << 9), 0);
        dispatches += 1;
        match REQUEST.load(Ordering::Relaxed) {
            0 => {
                scheduler.yield_cpu(0).unwrap();
            }
            1 => {
                scheduler.exit(0).unwrap();
            }
            _ => panic!("invalid preemption request"),
        }
    }
    // SAFETY: controller owns CPU with IF=0; no interrupt handler runs now.
    unsafe {
        crate::timer::stop_runtime();
    }
    ACTIVE.store(false, Ordering::Relaxed);
    let mut quanta = 0;
    for (i, t) in threads.into_iter().enumerate() {
        assert_eq!(scheduler.state(t), Ok(State::Exited));
        let ticks = QUANTA[i].load(Ordering::Relaxed);
        assert!((TARGET..=32).contains(&ticks));
        assert_eq!(scheduler.dispatches(jobs[i]), Ok(ticks + 1));
        assert!(PROGRESS[i].load(Ordering::Relaxed) > 0);
        quanta += ticks;
    }
    assert_eq!(crate::timer::now() - before, quanta);
    assert_eq!(dispatches, quanta + 2);
    // SAFETY: both workers exited; controller stack and original root retained.
    unsafe {
        asm!("mov cr3, {}", in(reg) original, options(nostack, preserves_flags));
    }
    Proof { quanta, dispatches }
}
