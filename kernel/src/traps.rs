//! Single-bootstrap-CPU exception boundary. Assembly frame layout is explicit.
use core::{
    arch::{asm, global_asm},
    fmt::Write,
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use ev_kernel::exception::{Gate, Recovery, tss_descriptor};
use ev_kernel::user::UserTrap;

// SAFETY: x86-64 assembly saves all GP registers and the CPU interrupt frame,
// normalizes error/vector words and calls the no-red-zone soft-float Rust ABI.
global_asm!(include_str!("traps.S"));
// SAFETY: fixed single-CPU user entry/return boundary with saved kernel stack.
global_asm!(include_str!("user.S"));

use ev_kernel::user_context::UserContext as TrapFrame;

#[repr(C, packed)]
struct TablePointer {
    limit: u16,
    base: u64,
}
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}
const _: () = assert!(core::mem::size_of::<Tss>() == 104);
#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut ENTRY_STACK: Stack = Stack([0; 16384]);
static mut DOUBLE_STACK: Stack = Stack([0; 16384]);
static mut NMI_STACK: Stack = Stack([0; 16384]);
static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap_base: 104,
};
static mut GDT: [u64; 7] = [0; 7];
static mut IDT: [Gate; 256] = [Gate::MISSING; 256];
static INSTALLED: AtomicBool = AtomicBool::new(false);
static IN_HANDLER: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);
static IP: AtomicU64 = AtomicU64::new(0);
static ADDRESS: AtomicU64 = AtomicU64::new(0);
static ERROR: AtomicU64 = AtomicU64::new(0);
static COUNT: AtomicU64 = AtomicU64::new(0);
static USER_ARMED: AtomicBool = AtomicBool::new(false);
static USER_COUNT: AtomicU64 = AtomicU64::new(0);
static mut USER_EXPECTED: UserTrap = UserTrap {
    vector: 0,
    error: 0,
    ip: 0,
    address: 0,
    stack_top: 0,
};

unsafe extern "C" {
    static ev_exception_stubs: [u64; 35];
    static ev_probe_read_site: u8;
    static ev_probe_write_site: u8;
    static ev_probe_recovered: u8;
    fn ev_reload_segments();
    fn ev_probe_read(address: u64) -> u64;
    fn ev_probe_write(address: u64) -> u64;
    fn ev_probe_execute(address: u64) -> u64;
    fn ev_enter_user(entry: u64, stack: u64, target: u64, value: u64);
}

/// # Safety
/// One ring-0 boot CPU, interrupts disabled, kernel image/stacks permanently
/// mapped and no previous users of this module. APs require separate tables.
pub unsafe fn install() {
    assert!(
        !INSTALLED.swap(true, Ordering::SeqCst),
        "exception tables installed once"
    );
    let flags: u64;
    // SAFETY: ring-0 boot entry with a valid stack, preserving flags.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    assert_eq!(flags & (1 << 9), 0);
    let tss = Tss {
        reserved0: 0,
        rsp: [ptr::addr_of_mut!(ENTRY_STACK) as u64 + 16384, 0, 0],
        reserved1: 0,
        ist: [
            ptr::addr_of_mut!(DOUBLE_STACK) as u64 + 16384,
            ptr::addr_of_mut!(NMI_STACK) as u64 + 16384,
            0,
            0,
            0,
            0,
            0,
        ],
        reserved2: 0,
        reserved3: 0,
        iomap_base: 104,
    };
    let descriptor = tss_descriptor(ptr::addr_of!(TSS) as u64);
    let gdt = [
        0,
        0x00af9a000000ffff,
        0x00cf92000000ffff,
        0x00cff2000000ffff,
        0x00affa000000ffff,
        descriptor[0],
        descriptor[1],
    ];
    let gdtr = TablePointer {
        limit: 55,
        base: ptr::addr_of!(GDT) as u64,
    };
    let idtr = TablePointer {
        limit: 4095,
        base: ptr::addr_of!(IDT) as u64,
    };
    // SAFETY: sole initializer with interrupts off; static backing never moves.
    // Descriptor encoding is host tested. Assembly reloads CS/SS before LTR/LIDT.
    unsafe {
        ptr::addr_of_mut!(TSS).write(tss);
        ptr::addr_of_mut!(GDT).write(gdt);
        let stubs = ptr::addr_of!(ev_exception_stubs).cast::<u64>();
        for vector in 0..256 {
            let address = stubs
                .add(if vector < 33 {
                    vector
                } else if vector == 128 {
                    33
                } else {
                    34
                })
                .read();
            let ist = match vector {
                8 => 1,
                2 => 2,
                _ => 0,
            };
            ptr::addr_of_mut!(IDT)
                .cast::<Gate>()
                .add(vector)
                .write(if vector == 128 {
                    Gate::user_call(address, 8).expect("syscall gate")
                } else {
                    Gate::interrupt(address, 8, ist).expect("valid kernel interrupt gate")
                });
        }
        asm!("lgdt [{}]", in(reg) &gdtr, options(nostack, preserves_flags));
        ev_reload_segments();
        asm!("ltr ax", in("ax") 40u16, options(nostack, preserves_flags));
        asm!("lidt [{}]", in(reg) &idtr, options(nostack, preserves_flags));
    }
}

#[unsafe(no_mangle)]
extern "C" fn ev_exception_dispatch(raw: *mut TrapFrame) -> u64 {
    if IN_HANDLER.swap(true, Ordering::SeqCst) {
        crate::finish(false);
    }
    // SAFETY: assembly passes its exclusively owned, GP+CPU stack frame; the
    // compile-time layout assertions match push order and interrupt-frame size.
    let frame = unsafe { &mut *raw };
    if frame.cs & 3 == 3 && crate::user_runtime::active() {
        let address: u64;
        // SAFETY: ring-0 fault register read; only PF records interpret CR2.
        unsafe {
            asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags));
        }
        let bottom = ptr::addr_of!(ENTRY_STACK) as u64;
        if (raw as u64) >= bottom && (raw as u64) + 176 <= bottom + 16384 {
            if frame.vector == 32 && !crate::timer::interrupt() {
                crate::finish(false);
            }
            if crate::user_runtime::capture(frame, address) {
                IN_HANDLER.store(false, Ordering::Release);
                return 1;
            }
        }
    }
    if frame.vector == 32 && frame.cs & 3 == 0 && crate::timer::interrupt() {
        IN_HANDLER.store(false, Ordering::Release);
        // IRQ acknowledged; each suspended trap frame belongs to its worker's
        // private stack. The next worker may take a distinct timer interrupt.
        crate::preempt::on_tick();
        return 0;
    }
    let address: u64;
    // SAFETY: CR2 is readable in this ring-0 handler; used only for page faults.
    unsafe {
        asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags));
    }
    if USER_ARMED.load(Ordering::Acquire) {
        // SAFETY: only the bootstrap CPU arms this record before user entry;
        // nested handlers halt above, interrupts and APs remain disabled.
        let expected = unsafe { ptr::addr_of!(USER_EXPECTED).read() };
        let actual = UserTrap {
            vector: frame.vector,
            error: frame.error,
            ip: frame.rip,
            address,
            stack_top: frame.rsp,
        };
        let frame_address = raw as u64;
        let entry_bottom = ptr::addr_of!(ENTRY_STACK) as u64;
        if frame_address >= entry_bottom
            && frame_address + 176 <= entry_bottom + 16384
            && expected.matches(&actual, frame.cs, frame.ss, frame.flags)
        {
            USER_ARMED.store(false, Ordering::Release);
            USER_COUNT.fetch_add(1, Ordering::Relaxed);
            IN_HANDLER.store(false, Ordering::Release);
            return 1;
        }
    }
    let armed = ARMED.load(Ordering::Acquire);
    let recovery = Recovery {
        instruction: IP.load(Ordering::Relaxed),
        resume: ptr::addr_of!(ev_probe_recovered) as u64,
        address: ADDRESS.load(Ordering::Relaxed),
        error: ERROR.load(Ordering::Relaxed),
    };
    if armed && recovery.matches(frame.vector, frame.error, frame.rip, frame.cs, address) {
        frame.rip = recovery.resume;
        COUNT.fetch_add(1, Ordering::Relaxed);
        ARMED.store(false, Ordering::Release);
        IN_HANDLER.store(false, Ordering::Release);
        return 0;
    }
    let mut serial = crate::serial::Serial::initialize(1024);
    let _ = writeln!(
        serial,
        "EVROSION_EXCEPTION vector={} error={:#x} rip={:#x} address={:#x}",
        frame.vector, frame.error, frame.rip, address
    );
    let _ = writeln!(serial, "{}", ev_test_protocol::FAIL);
    crate::finish(false)
}

pub fn user_count() -> u64 {
    USER_COUNT.load(Ordering::Relaxed)
}

/// # Safety
/// Sole boot CPU, interrupts off; active root maps the finite trusted user
/// fixture and its stack, plus supervisor-only kernel/entry stacks and tables.
/// No live user memory references; no scheduler, AP or nested fixture may enter.
pub unsafe fn run_user(entry: u64, target: u64, value: u64, expected: UserTrap) {
    assert!(INSTALLED.load(Ordering::Acquire));
    assert!(!ARMED.load(Ordering::Acquire));
    assert!(!USER_ARMED.load(Ordering::Acquire));
    let before = user_count();
    // SAFETY: sole writer, no handler has an outstanding borrow of this record.
    unsafe {
        ptr::addr_of_mut!(USER_EXPECTED).write(expected);
    }
    USER_ARMED.store(true, Ordering::Release);
    // SAFETY: caller provides mapped fixture/stack; IRET clears privilege flags,
    // the exact trap returns via the private saved-stack assembly continuation.
    unsafe {
        ev_enter_user(entry, expected.stack_top, target, value);
    }
    assert!(!USER_ARMED.load(Ordering::Acquire));
    assert_eq!(user_count(), before + 1);
}

pub enum Access {
    Read,
    Write,
    Execute,
}

pub fn count() -> u64 {
    COUNT.load(Ordering::Relaxed)
}

/// # Safety
/// Exact test fixture address: valid writable memory for Write if unexpectedly
/// allowed, or a single RET instruction for Execute. No interrupts/APs may use
/// the global probe. A missing/wrong fault is fatal; it is not general recovery.
pub unsafe fn expect_page_fault(address: u64, access: Access, error: u64) {
    assert!(INSTALLED.load(Ordering::Acquire));
    assert!(!ARMED.load(Ordering::Acquire));
    let instruction = match access {
        Access::Read => ptr::addr_of!(ev_probe_read_site) as u64,
        Access::Write => ptr::addr_of!(ev_probe_write_site) as u64,
        Access::Execute => address,
    };
    IP.store(instruction, Ordering::Relaxed);
    ADDRESS.store(address, Ordering::Relaxed);
    ERROR.store(error, Ordering::Relaxed);
    let before = COUNT.load(Ordering::Relaxed);
    ARMED.store(true, Ordering::Release);
    // SAFETY: caller establishes the test mapping/code bytes; assembly has a
    // fixed recovery label and the handler validates all fault fields before IRET.
    let recovered = unsafe {
        match access {
            Access::Read => ev_probe_read(address),
            Access::Write => ev_probe_write(address),
            Access::Execute => ev_probe_execute(address),
        }
    };
    assert_eq!(recovered, 1, "protection probe unexpectedly succeeded");
    assert!(!ARMED.load(Ordering::Acquire));
    assert_eq!(COUNT.load(Ordering::Relaxed), before + 1);
}
