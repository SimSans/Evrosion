//! BSP-only cooperative kernel contexts on retained, guarded stacks.
use core::{
    arch::{asm, global_asm},
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use ev_kernel::{
    mapping::{ADDRESS_MASK, ENTRIES, NO_EXECUTE, PRESENT, WRITABLE, direct_address},
    memory::{BootstrapFrames, FRAME_SIZE, PhysicalFrame},
    scheduler::{Scheduler, State, WakeReason},
    time::Deadline,
};
// SAFETY: fixed System V callee-saved switch, IF=0 and shared privileged root.
global_asm!(include_str!("context.S"));
unsafe extern "C" {
    fn ev_context_switch(old: *mut u64, new: *const u64);
    fn ev_context_register_probe(seed: u64) -> u64;
}
static USED: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static REQUEST: AtomicUsize = AtomicUsize::new(0);
static WAKE: AtomicUsize = AtomicUsize::new(0);
// BSP with IF=0 only; no reference survives a switch. AP never accesses these.
static mut CONTEXTS: [u64; 3] = [0; 3];
static mut BOUNDS: [(u64, u64); 2] = [(0, 0); 2];
fn flags() -> u64 {
    let result;
    // SAFETY: initialized active kernel stack, readback only.
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
    // SAFETY: BSP only, no shared references alive. Controller RSP was saved
    // before worker entry; both stacks/root remain mapped and retained.
    unsafe {
        ev_context_switch(
            ptr::addr_of_mut!(CONTEXTS).cast::<u64>().add(index + 1),
            ptr::addr_of!(CONTEXTS).cast::<u64>(),
        );
    }
    assert_eq!(CURRENT.load(Ordering::Relaxed), index);
}
#[unsafe(no_mangle)]
extern "C" fn ev_thread_yield() {
    suspend(0);
}
fn worker(index: usize) -> ! {
    assert_eq!(CURRENT.load(Ordering::Relaxed), index);
    let rsp: u64;
    // SAFETY: active stack readback; bounds initialized before first entry, IF=0.
    let (bottom, top) = unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
        ptr::addr_of!(BOUNDS).cast::<(u64, u64)>().add(index).read()
    };
    assert!((bottom..top).contains(&rsp));
    let mut local = [0u64; 32];
    let seed = 0x1000_0000 * (index as u64 + 1);
    for round in 0..16 {
        for (i, word) in local.iter_mut().enumerate() {
            *word = seed + round * 32 + i as u64;
        }
        // SAFETY: assembly preserves caller registers, seeds all six callee-saved
        // registers, then yields through the validated current context.
        let preserved = unsafe { ev_context_register_probe(seed + round * 16) };
        if cfg!(feature = "test-context-corruption") && preserved != 1 {
            panic!("M1 deliberate context corruption detected");
        }
        assert_eq!(preserved, 1);
        for (i, word) in local.iter().enumerate() {
            assert_eq!(
                // SAFETY: local stack words remain mapped and exclusively owned.
                unsafe { ptr::read_volatile(word) },
                seed + round * 32 + i as u64
            );
        }
    }
    suspend(1);
    assert_eq!(WAKE.load(Ordering::Relaxed), index + 1);
    assert_eq!(local[0], seed + 15 * 32);
    suspend(2);
    panic!("exited thread resumed")
}
extern "C" fn worker_a() -> ! {
    worker(0)
}
extern "C" fn worker_b() -> ! {
    worker(1)
}
extern "C" fn returned() -> ! {
    panic!("thread returned through sentinel")
}
pub(crate) struct Stacks {
    pub(crate) tables: [PhysicalFrame; 4],
    _pages: [PhysicalFrame; 8],
    pub(crate) bounds: [(u64, u64); 2],
}
impl Stacks {
    /// # Safety
    /// Original root/direct map retained, exclusive allocator, BSP with IF=0.
    pub(crate) unsafe fn new(offset: u64, original: u64, frames: &mut BootstrapFrames) -> Self {
        let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 0xff) as u8;
        let pointer =
            |frame| direct_address(offset, frame, bits).expect("stack RAM alias") as *mut u64;
        let tables: [PhysicalFrame; 4] =
            core::array::from_fn(|_| frames.allocate().expect("stack table"));
        let pages: [PhysicalFrame; 8] =
            core::array::from_fn(|_| frames.allocate().expect("stack data"));
        let pointers = tables.each_ref().map(|f| pointer(f.start()));
        let old = pointer(original & ADDRESS_MASK);
        // SAFETY: fresh retained frames and trusted retained loader root. Copy
        // inherited branches read-only; attach only an unused upper-half slot.
        let slot = unsafe {
            let slot = (256..511)
                .find(|&i| old.add(i).read_volatile() == 0)
                .expect("stack slot");
            for p in pointers {
                ptr::write_bytes(p, 0, ENTRIES);
            }
            for i in 0..ENTRIES {
                pointers[0]
                    .add(i)
                    .write_volatile(old.add(i).read_volatile());
            }
            for i in 0..3 {
                pointers[i]
                    .add(if i == 0 { slot } else { 0 })
                    .write_volatile(tables[i + 1].start() | PRESENT | WRITABLE | NO_EXECUTE);
            }
            for (i, frame) in pages.iter().enumerate() {
                ptr::write_bytes(pointer(frame.start()), 0, ENTRIES);
                let leaf = 1 + (i / 4) * 6 + i % 4;
                pointers[3]
                    .add(leaf)
                    .write_volatile(frame.start() | PRESENT | WRITABLE | NO_EXECUTE);
            }
            slot
        };
        let base = 0xffff_0000_0000_0000 | ((slot as u64) << 39);
        Self {
            tables,
            _pages: pages,
            bounds: [
                (base + FRAME_SIZE, base + 5 * FRAME_SIZE),
                (base + 7 * FRAME_SIZE, base + 11 * FRAME_SIZE),
            ],
        }
    }
}
pub struct Proof {
    pub dispatches: u64,
    pub switches: u64,
    pub guards: u64,
}
/// # Safety
/// Once on BSP after prior proofs; AP parked, IF=0, retained loader maps,
/// owned exception tables, NX/WP enabled and PCID off. Stacks stay retained.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    assert!(!USED.swap(true, Ordering::Relaxed));
    assert_eq!(flags() & (1 << 9), 0);
    let original: u64;
    // SAFETY: ring-0 BSP control register read.
    unsafe {
        asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: caller guarantees exclusive allocator and retained direct map.
    let stacks = unsafe { Stacks::new(offset, original, frames) };
    let before = crate::traps::count();
    // SAFETY: new root preserves kernel/controller/descriptor maps and adds only
    // private NX stacks. Guard probes use exact-match exception recovery.
    unsafe {
        asm!("mov cr3, {}", in(reg) stacks.tables[0].start(), options(nostack, preserves_flags));
        for (i, (bottom, top)) in stacks.bounds.into_iter().enumerate() {
            crate::traps::expect_page_fault(bottom - 8, crate::traps::Access::Read, 0);
            crate::traps::expect_page_fault(top, crate::traps::Access::Read, 0);
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
            ptr::addr_of_mut!(BOUNDS)
                .cast::<(u64, u64)>()
                .add(i)
                .write((bottom, top));
        }
    }
    let mut scheduler = Scheduler::new();
    let jobs = [
        scheduler.create_job().unwrap(),
        scheduler.create_job().unwrap(),
    ];
    let processes = jobs.map(|j| scheduler.create_process(j).unwrap());
    let threads = processes.map(|p| scheduler.create_thread(p).unwrap());
    let mut tickets = [None; 2];
    let mut count = 0;
    let mut woke = false;
    for _ in 0..40 {
        if let Some(dispatch) = scheduler.dispatch(0).unwrap() {
            let index = threads.iter().position(|&t| t == dispatch.thread).unwrap();
            assert_eq!(dispatch.job, jobs[index]);
            CURRENT.store(index, Ordering::Relaxed);
            WAKE.store(
                match dispatch.wake {
                    None => 0,
                    Some(WakeReason::Signal) => 1,
                    Some(WakeReason::Deadline) => 2,
                },
                Ordering::Relaxed,
            );
            REQUEST.store(usize::MAX, Ordering::Relaxed);
            // SAFETY: controller frame remains live. No scheduler/global reference
            // crosses this call; workers use raw context pointers and atomic
            // requests. Both contexts retain the same root and IF=0.
            unsafe {
                ev_context_switch(
                    ptr::addr_of_mut!(CONTEXTS).cast::<u64>(),
                    ptr::addr_of!(CONTEXTS).cast::<u64>().add(index + 1),
                );
            }
            // Inject after first yield, while the worker's callee-saved state is
            // suspended on its private stack. Resuming must detect the damage.
            if cfg!(feature = "test-context-corruption") && count == 0 {
                // SAFETY: worker is suspended and this saved frame belongs to
                // its retained stack; no references exist to the register words.
                unsafe {
                    let saved =
                        ptr::addr_of!(CONTEXTS).cast::<u64>().add(index + 1).read() as *mut u64;
                    saved.add(3).write_volatile(0); // Saved r12.
                }
            }
            count += 1;
            match REQUEST.load(Ordering::Relaxed) {
                0 => {
                    scheduler.yield_cpu(0).unwrap();
                }
                1 => {
                    tickets[index] =
                        Some(scheduler.block(0, Deadline::after(0, 2).unwrap()).unwrap());
                }
                2 => {
                    scheduler.exit(0).unwrap();
                }
                _ => panic!("invalid thread request"),
            }
        } else if !woke {
            assert!(tickets.iter().all(Option::is_some));
            scheduler.advance(1).unwrap();
            assert!(scheduler.wake(tickets[0].unwrap()));
            assert_eq!(scheduler.advance(2), Ok(1));
            assert!(!scheduler.wake(tickets[1].unwrap()));
            woke = true;
        } else {
            break;
        }
    }
    assert!(woke);
    assert_eq!(count, 36);
    for (i, t) in threads.into_iter().enumerate() {
        assert_eq!(scheduler.state(t), Ok(State::Exited));
        assert_eq!(scheduler.dispatches(jobs[i]), Ok(18));
    }
    let guards = crate::traps::count() - before;
    assert_eq!(guards, 4);
    assert_eq!(flags() & (1 << 9), 0);
    // SAFETY: workers exited; controller uses unchanged loader stack and original
    // root remained retained/unmodified. No frame is freed or reused.
    unsafe {
        asm!("mov cr3, {}", in(reg) original, options(nostack, preserves_flags));
    }
    Proof {
        dispatches: count,
        switches: count * 2,
        guards,
    }
}
