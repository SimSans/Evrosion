//! Bounded xAPIC two-CPU bootstrap proof. APs never use BSP exception globals.
use core::{
    arch::{asm, global_asm},
    ptr,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use ev_kernel::{
    acpi::Topology,
    exception::Gate,
    mapping::{ADDRESS_MASK, ENTRIES, NO_EXECUTE, PRESENT, WRITABLE, direct_address},
    memory::{BootstrapFrames, PhysicalFrame},
};
// SAFETY: fixed real/protected/long-mode trampoline and stack-free fatal entry;
// patched offsets stay within the allocated retained trampoline page.
global_asm!(include_str!("ap.S"));
#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut AP_STACK: Stack = Stack([0; 16384]);
static mut AP_IDT: [Gate; 256] = [Gate::MISSING; 256];
#[unsafe(no_mangle)]
static ev_ap_failure: AtomicU32 = AtomicU32::new(0);
static STATE: AtomicU32 = AtomicU32::new(0);
static COMMAND: AtomicU32 = AtomicU32::new(0);
static COUNT: AtomicU32 = AtomicU32::new(0);
static EXPECTED_ID: AtomicU32 = AtomicU32::new(0);
static EXPECTED_ROOT: AtomicU64 = AtomicU64::new(0);
static OBSERVED_ID: AtomicU32 = AtomicU32::new(0);
const WORK: u32 = 10000;
const POLLS: u32 = 20_000_000;
unsafe extern "C" {
    static ev_ap_blob: u8;
    static ev_ap_blob_end: u8;
    static ev_ap_gdt: u8;
    static ev_ap_gdtr_base: u8;
    static ev_ap_pm_target: u8;
    static ev_ap_lm_target: u8;
    static ev_ap_pm: u8;
    static ev_ap_lm: u8;
    static ev_ap_cr3: u8;
    static ev_ap_stack: u8;
    static ev_ap_entry_address: u8;
    static ev_ap_idtr_base: u8;
    fn ev_ap_fault();
}
fn park() -> ! {
    loop {
        // SAFETY: AP bootstrap owns this CPU; no interrupts or user work enabled.
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
fn fail() -> ! {
    ev_ap_failure.store(1, Ordering::Release);
    park()
}
#[unsafe(no_mangle)]
extern "C" fn ev_ap_entry() -> ! {
    let id = core::arch::x86_64::__cpuid(1).ebx >> 24;
    let (root, stack, flags): (u64, u64, u64);
    // SAFETY: entered by our long-mode trampoline on its private stack/root.
    unsafe {
        asm!("mov {}, cr3",out(reg) root,options(nomem,nostack,preserves_flags));
        asm!("mov {}, rsp",out(reg) stack,options(nomem,nostack,preserves_flags));
        asm!("pushfq","pop {}",out(reg) flags,options(preserves_flags));
    }
    let bottom = ptr::addr_of!(AP_STACK) as u64;
    if id != EXPECTED_ID.load(Ordering::Acquire)
        || root != EXPECTED_ROOT.load(Ordering::Acquire)
        || !(bottom..bottom + 16384).contains(&stack)
        || flags & (1 << 9) != 0
    {
        fail()
    }
    OBSERVED_ID.store(id, Ordering::Relaxed);
    STATE.store(1, Ordering::Release);
    let mut received = false;
    for _ in 0..POLLS {
        if COMMAND.load(Ordering::Acquire) == 1 {
            received = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !received {
        fail()
    }
    for _ in 0..WORK {
        COUNT.fetch_add(1, Ordering::Relaxed);
    }
    STATE.store(2, Ordering::Release);
    park()
}
struct Access {
    offset: u64,
    bits: u8,
}
impl Access {
    fn pointer(&self, physical: u64) -> *mut u64 {
        direct_address(self.offset, physical, self.bits).expect("bootstrap RAM alias") as *mut u64
    }
}
struct Tables {
    frames: [PhysicalFrame; 4],
}
impl Tables {
    /// # Safety
    /// Exclusive retained bootstrap RAM, trusted direct map, no concurrent use.
    unsafe fn new(access: &Access, frames: &mut BootstrapFrames) -> Self {
        let result = Self {
            frames: core::array::from_fn(|_| frames.allocate().expect("AP table")),
        };
        // SAFETY: fresh unique RAM claims, no other CPU/table references yet.
        unsafe {
            for frame in &result.frames {
                ptr::write_bytes(access.pointer(frame.start()), 0, ENTRIES);
            }
        }
        result
    }
    fn root(&self) -> u64 {
        self.frames[0].start()
    }
    /// # Safety
    /// Inactive root, owned zero tables; entry index <512; target MMIO/RAM is
    /// validated by caller. No inherited branch at slot may be overwritten.
    unsafe fn branch(&self, access: &Access, slot: usize, index: usize, physical: u64, flags: u64) {
        assert!(slot < 512 && index < 512);
        let p = self.frames.each_ref().map(|f| access.pointer(f.start()));
        // SAFETY: checked table indices, exclusively owned inactive tables.
        unsafe {
            assert_eq!(p[0].add(slot).read_volatile(), 0);
            p[0].add(slot)
                .write_volatile(self.frames[1].start() | PRESENT | WRITABLE);
            p[1].write_volatile(self.frames[2].start() | PRESENT | WRITABLE);
            p[2].write_volatile(self.frames[3].start() | PRESENT | WRITABLE);
            p[3].add(index).write_volatile(physical | flags);
        }
    }
}
/// # Safety
/// Ring-0 Q35 boot owner of PIT channel2 and speaker gate; no other driver uses it.
unsafe fn delay(count: u16) {
    let saved: u8;
    // SAFETY: standard Q35 PIT2/port61 gate control. Speaker disabled during
    // bounded one-shot delay; restore original gate/control bits afterwards.
    unsafe {
        asm!("in al, dx",in("dx") 0x61u16,out("al") saved,options(nomem,nostack,preserves_flags));
        for (port, value) in [
            (0x61u16, saved & !3),
            (0x43, 0xb0),
            (0x42, count as u8),
            (0x42, (count >> 8) as u8),
            (0x61, (saved & !3) | 1),
        ] {
            asm!("out dx, al",in("dx") port,in("al") value,options(nomem,nostack,preserves_flags));
        }
    }
    let mut elapsed = false;
    for _ in 0..POLLS {
        let status: u8;
        // SAFETY: read-only PIT2 OUT status at the reserved Q35 port61 register.
        unsafe {
            asm!("in al, dx",in("dx") 0x61u16,out("al") status,options(nomem,nostack,preserves_flags));
        }
        if status & 32 != 0 {
            elapsed = true;
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: restore the exclusively held channel gate/speaker controls.
    unsafe {
        asm!("out dx, al",in("dx") 0x61u16,in("al") saved,options(nomem,nostack,preserves_flags));
    }
    assert!(elapsed, "PIT2 startup delay stalled");
}
struct Lapic(*mut u32);
impl Lapic {
    fn read(&self, offset: usize) -> u32 {
        assert!(offset < 4096 && offset.is_multiple_of(16));
        // SAFETY: private UC-mapped LAPIC page; validated aligned register offset.
        unsafe { self.0.add(offset / 4).read_volatile() }
    }
    fn write(&self, offset: usize, value: u32) {
        assert!(offset < 4096 && offset.is_multiple_of(16));
        // SAFETY: sole BSP driver of its verified local APIC, aligned UC register.
        unsafe {
            self.0.add(offset / 4).write_volatile(value);
        }
        let _ = self.read(0x20); // Flush posted write before subsequent controller use.
    }
    fn send(&self, id: u32, value: u32) {
        assert!(id < 255);
        self.wait_delivery();
        self.write(0x310, id << 24);
        self.write(0x300, value);
        self.wait_delivery();
    }
    fn wait_delivery(&self) {
        for _ in 0..POLLS {
            if self.read(0x300) & (1 << 12) == 0 {
                return;
            }
            core::hint::spin_loop();
        }
        panic!("APIC IPI delivery timed out");
    }
}
fn wait_state(expected: u32) {
    for _ in 0..POLLS {
        assert_eq!(
            ev_ap_failure.load(Ordering::Acquire),
            0,
            "AP failed startup/handshake"
        );
        if STATE.load(Ordering::Acquire) == expected {
            return;
        }
        core::hint::spin_loop();
    }
    panic!("AP startup handshake timed out");
}
fn offset(label: *const u8) -> usize {
    (label as usize)
        .checked_sub(ptr::addr_of!(ev_ap_blob) as usize)
        .expect("trampoline label")
}
/// # Safety
/// Private writable direct alias of the retained trampoline page; not started.
unsafe fn patch<T: Copy>(page: *mut u8, label: *const u8, value: T) {
    let at = offset(label);
    assert!(at + core::mem::size_of::<T>() <= 4096);
    // SAFETY: checked within our private 4KiB page, unaligned patch is intentional.
    unsafe {
        page.add(at).cast::<T>().write_unaligned(value);
    }
}
pub struct Proof {
    pub ap: u32,
    pub root: u64,
    pub count: u32,
}
/// # Safety
/// BSP only, IF=0 after topology/timer proofs. All bootstrap RAM retained. No AP
/// has yet been started by this kernel. xAPIC and PIT2 are exclusively owned.
pub unsafe fn prove(
    offset_map: u64,
    topology: &Topology,
    bsp: u32,
    frames: &mut BootstrapFrames,
) -> Option<Proof> {
    let ap = topology.cpus().iter().find(|cpu| cpu.apic_id != bsp)?;
    assert!(ap.apic_id < 255, "initial xAPIC proof needs an 8-bit AP ID");
    let (original, flags, msr_low, msr_high): (u64, u64, u32, u32);
    assert_ne!(core::arch::x86_64::__cpuid(1).edx & (1 << 9), 0);
    // SAFETY: BSP ring-0 reads; APIC feature checked before accessing its MSR.
    unsafe {
        asm!("mov {}, cr3",out(reg) original,options(nomem,nostack,preserves_flags));
        asm!("pushfq","pop {}",out(reg) flags,options(preserves_flags));
        asm!("rdmsr",in("ecx") 0x1bu32,out("eax") msr_low,out("edx") msr_high,options(nomem,nostack,preserves_flags));
    }
    assert_eq!(flags & (1 << 9), 0);
    let apic_base = (u64::from(msr_high) << 32) | u64::from(msr_low);
    assert_eq!(
        apic_base & (1 << 10),
        0,
        "x2APIC startup is not implemented"
    );
    assert_ne!(apic_base & (1 << 11), 0, "local APIC hardware disabled");
    assert_eq!(apic_base & ADDRESS_MASK, topology.lapic);
    assert_ne!(
        core::arch::x86_64::__cpuid(1).edx & (1 << 16),
        0,
        "PAT required for explicit UC mapping"
    );
    let (pat_low, pat_high): (u32, u32);
    // SAFETY: PAT feature checked; read the selected UC encoding before MMIO.
    unsafe {
        asm!("rdmsr",in("ecx") 0x277u32,out("eax") pat_low,out("edx") pat_high,options(nomem,nostack,preserves_flags));
    }
    let _ = pat_high;
    assert_eq!(
        (pat_low >> 24) & 0xff,
        0,
        "PWT/PCD mapping must select UC PAT entry"
    );
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 0xff) as u8;
    let access = Access {
        offset: offset_map,
        bits,
    };
    let old = access.pointer(original & ADDRESS_MASK);
    let trampoline = frames.allocate().expect("SIPI frame");
    assert!(
        (0x1000..0x100000).contains(&trampoline.start()),
        "SIPI requires retained low RAM"
    );
    // SAFETY: exclusive retained frame allocation and direct map established above.
    let (bsp_tables, ap_tables) =
        unsafe { (Tables::new(&access, frames), Tables::new(&access, frames)) };
    assert!(ap_tables.root() < 1 << 32, "32-bit AP transition CR3");
    // SAFETY: read only the loader root; select empty supervisor branch for MMIO.
    let slot = (256..511)
        .find(|&i| unsafe { old.add(i).read_volatile() == 0 })
        .expect("APIC window");
    let mmio = 0xffff000000000000 | ((slot as u64) << 39);
    // SAFETY: exclusively owned inactive roots. BSP preserves all mappings;
    // AP inherits only privileged high mappings, adding the single RX trampoline.
    unsafe {
        for i in 0..ENTRIES {
            access
                .pointer(bsp_tables.root())
                .add(i)
                .write_volatile(old.add(i).read_volatile());
        }
        for i in 256..ENTRIES {
            access
                .pointer(ap_tables.root())
                .add(i)
                .write_volatile(old.add(i).read_volatile() & !4);
        }
        bsp_tables.branch(
            &access,
            slot,
            0,
            topology.lapic,
            PRESENT | WRITABLE | NO_EXECUTE | 8 | 16,
        );
        ap_tables.branch(
            &access,
            0,
            (trampoline.start() / 4096) as usize,
            trampoline.start(),
            PRESENT,
        );
        let page = access.pointer(trampoline.start()).cast::<u8>();
        ptr::write_bytes(page, 0, 4096);
        let length = offset(ptr::addr_of!(ev_ap_blob_end));
        assert!(length > 0 && length <= 4096);
        ptr::copy_nonoverlapping(ptr::addr_of!(ev_ap_blob), page, length);
        patch(
            page,
            ptr::addr_of!(ev_ap_gdtr_base),
            (trampoline.start() + offset(ptr::addr_of!(ev_ap_gdt)) as u64) as u32,
        );
        patch(
            page,
            ptr::addr_of!(ev_ap_pm_target),
            (trampoline.start() + offset(ptr::addr_of!(ev_ap_pm)) as u64) as u32,
        );
        patch(
            page,
            ptr::addr_of!(ev_ap_lm_target),
            (trampoline.start() + offset(ptr::addr_of!(ev_ap_lm)) as u64) as u32,
        );
        patch(page, ptr::addr_of!(ev_ap_cr3), ap_tables.root());
        patch(
            page,
            ptr::addr_of!(ev_ap_stack),
            ptr::addr_of!(AP_STACK) as u64 + 16384,
        );
        patch(
            page,
            ptr::addr_of!(ev_ap_entry_address),
            ev_ap_entry as *const () as u64,
        );
        patch(
            page,
            ptr::addr_of!(ev_ap_idtr_base),
            ptr::addr_of!(AP_IDT) as u64,
        );
        for i in 0..256 {
            ptr::addr_of_mut!(AP_IDT).cast::<Gate>().add(i).write(
                Gate::interrupt(ev_ap_fault as *const () as u64, 24, 0).expect("AP fatal gate"),
            );
        }
        asm!("mov cr3, {}",in(reg) bsp_tables.root(),options(nostack,preserves_flags));
    }
    EXPECTED_ID.store(ap.apic_id, Ordering::Release);
    EXPECTED_ROOT.store(ap_tables.root(), Ordering::Release);
    let lapic = Lapic(mmio as *mut u32);
    assert_eq!(lapic.read(0x20) >> 24, bsp);
    let svr = lapic.read(0xf0);
    lapic.write(0xf0, (svr & !0xff) | 0x1ff);
    lapic.send(ap.apic_id, 0xc500);
    // SAFETY: sole PIT2 owner, 11932 clocks >=10ms at its fixed platform rate.
    unsafe {
        delay(11932);
    }
    lapic.send(ap.apic_id, 0x8500);
    let vector = (trampoline.start() / 4096) as u32;
    lapic.send(ap.apic_id, 0x4600 | vector);
    // SAFETY: >=200us between startup IPIs, with bounded hardware polling.
    unsafe {
        delay(239);
    }
    lapic.send(ap.apic_id, 0x4600 | vector);
    wait_state(1);
    if cfg!(feature = "test-ap-timeout") {
        // Deliberately withhold COMMAND after confirmed AP readiness. The AP
        // must report its own finite wait failure; a BSP-only timeout is not proof.
        for _ in 0..POLLS * 4 {
            if ev_ap_failure.load(Ordering::Acquire) != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        assert_ne!(
            ev_ap_failure.load(Ordering::Acquire),
            0,
            "withheld-command AP failure record missing"
        );
        panic!("M1 deliberate withheld AP command: bounded AP failure observed");
    }
    COMMAND.store(1, Ordering::Release);
    for _ in 0..WORK {
        COUNT.fetch_add(1, Ordering::Relaxed);
    }
    wait_state(2);
    assert_eq!(COUNT.load(Ordering::Acquire), 2 * WORK);
    lapic.write(0xf0, svr);
    // SAFETY: original BSP root and AP-owned roots/stack/trampoline all retained;
    // restoring BSP CR3 cannot remove any AP mapping. AP is parked with IF=0.
    unsafe {
        asm!("mov cr3, {}",in(reg) original,options(nostack,preserves_flags));
    }
    let restored: u64;
    // SAFETY: BSP ring-0 readback; original root remains live and unchanged.
    unsafe {
        asm!("mov {}, cr3",out(reg) restored,options(nomem,nostack,preserves_flags));
        assert_eq!(old.add(slot).read_volatile(), 0);
    }
    assert_eq!(restored, original);
    Some(Proof {
        ap: OBSERVED_ID.load(Ordering::Acquire),
        root: ap_tables.root(),
        count: COUNT.load(Ordering::Acquire),
    })
}
