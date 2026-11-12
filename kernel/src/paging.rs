//! x86-64 bootstrap-only hardware boundary. No interrupts, APs or reclamation.
use core::{arch::asm, ptr};
use ev_kernel::{
    mapping::{
        ADDRESS_MASK, ENTRIES, LeafMappings, NO_EXECUTE, PRESENT, Permission, WRITABLE,
        direct_address,
    },
    memory::{BootstrapFrames, PhysicalFrame},
};

struct PhysicalAccess {
    offset: u64,
    bits: u8,
}

impl PhysicalAccess {
    fn pointer(&self, physical: u64) -> *mut u64 {
        direct_address(self.offset, physical, self.bits)
            .expect("physical mapping address must be representable") as *mut u64
    }
}

struct OwnedWindow {
    tables: [PhysicalFrame; 4],
    leaf: *mut u64,
    mappings: LeafMappings,
}

impl OwnedWindow {
    /// # Safety
    /// The loader's direct map covers allocated RAM and the original root. All
    /// supplied frames are unique, and no other CPU or interrupt mutates tables.
    unsafe fn new(
        access: &PhysicalAccess,
        frames: &mut BootstrapFrames,
        original_root: u64,
        slot: usize,
    ) -> Self {
        let tables = [
            frames.allocate().expect("root frame"),
            frames.allocate().expect("PDPT frame"),
            frames.allocate().expect("PD frame"),
            frames.allocate().expect("PT frame"),
        ];
        let pointers = tables.each_ref().map(|frame| access.pointer(frame.start()));
        let old = access.pointer(original_root);
        // SAFETY: each pointer covers a distinct, exclusively claimed RAM frame;
        // old names the trusted loader's active root. Raw accesses avoid references
        // aliasing hardware page-table walks. No inherited child table is written.
        unsafe {
            for pointer in pointers {
                ptr::write_bytes(pointer, 0, ENTRIES);
            }
            for i in 0..ENTRIES {
                pointers[0]
                    .add(i)
                    .write_volatile(old.add(i).read_volatile());
            }
            assert_eq!(pointers[0].add(slot).read_volatile(), 0);
            pointers[0]
                .add(slot)
                .write_volatile(tables[1].start() | PRESENT | WRITABLE | NO_EXECUTE);
            pointers[1].write_volatile(tables[2].start() | PRESENT | WRITABLE | NO_EXECUTE);
            pointers[2].write_volatile(tables[3].start() | PRESENT | WRITABLE | NO_EXECUTE);
        }
        Self {
            leaf: pointers[3],
            tables,
            mappings: LeafMappings::new(slot).expect("scratch slot"),
        }
    }

    fn root(&self) -> u64 {
        self.tables[0].start()
    }
    fn address(&self) -> u64 {
        self.mappings.base()
    }

    // SAFETY contracts of new/prove establish exclusive access for these private
    // operations. All indices are checked by the portable ownership model.
    fn sync(&self, address: u64) {
        let index = self.mappings.index(address).expect("owned window address");
        let entry = self.mappings.entry(address).expect("owned leaf");
        // SAFETY: leaf points to our live 512-entry RAM table, index is in bounds.
        // The only CPU invalidates before it can use/reissue this mapping.
        unsafe {
            self.leaf.add(index).write_volatile(entry);
            asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
        }
    }

    fn map(&mut self, frame: PhysicalFrame) {
        self.mappings
            .map(self.address(), frame, Permission::ReadWrite)
            .expect("map empty scratch page");
        self.sync(self.address());
    }

    fn protect(&mut self, permission: Permission) {
        self.mappings
            .protect(self.address(), permission)
            .expect("protect mapped scratch page");
        self.sync(self.address());
    }

    fn unmap(&mut self) -> PhysicalFrame {
        let frame = self
            .mappings
            .unmap(self.address())
            .expect("unmap owned frame");
        self.sync(self.address());
        frame
    }

    fn hardware_entry(&self) -> u64 {
        // SAFETY: leaf is our claimed live RAM table, entry zero is in bounds.
        unsafe { self.leaf.read_volatile() }
    }

    fn activate(&self) {
        // SAFETY: constructor copied all boot mappings and attached only our
        // private branch. Kernel, stack, direct map and descriptor mappings remain.
        // PCID is disabled; this flushes non-global scratch translations.
        unsafe {
            asm!("mov cr3, {}", in(reg) self.root(), options(nostack, preserves_flags));
        }
    }
}

pub struct Proof {
    pub root_a: u64,
    pub root_b: u64,
    pub virtual_address: u64,
    pub faults: u64,
}

/// Exercise bootstrap page tables, restoring original CR3 on successful return.
///
/// # Safety
/// Called once in ring 0 on the bootstrap CPU before APs/interrupts. `offset`
/// must describe the loader's writable direct map, with all loader regions still
/// reserved and all allocated frames exclusively owned by this boot allocator.
/// A panic aborts/halt; it must not unwind past active page-table ownership.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    let faults_before = crate::traps::count();
    let (original, cr4, mut cr0, flags, efer_low, efer_high): (u64, u64, u64, u64, u32, u32);
    // SAFETY: ring 0 bootstrap entry, documented control registers and EFER MSR.
    unsafe {
        asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        asm!("rdmsr", in("ecx") 0xc0000080u32, out("eax") efer_low,
            out("edx") efer_high, options(nomem, nostack, preserves_flags));
    }
    let _ = efer_high;
    assert_eq!(flags & (1 << 9), 0, "interrupts must remain disabled");
    assert_eq!(
        cr4 & ((1 << 12) | (1 << 17)),
        0,
        "LA57/PCID require a later design"
    );
    assert_ne!(efer_low & (1 << 11), 0, "NX must be enabled");
    let max = core::arch::x86_64::__cpuid(0x80000000).eax;
    assert!(max >= 0x80000008, "physical address width is required");
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 0xff) as u8;
    let access = PhysicalAccess { offset, bits };
    let original_root = original & ADDRESS_MASK;
    assert!(
        frames.is_reserved_frame(original_root),
        "loader root must remain reserved"
    );
    let root_pointer = access.pointer(original_root);
    // SAFETY: current CR3 names the loader's root, covered by the checked direct
    // map. Read only the 512-entry page. Choose an unused upper-half entry.
    let slot = (256..511)
        .find(|&i| unsafe { root_pointer.add(i).read_volatile() == 0 })
        .expect("unused upper-half slot for bounded scratch mapping");
    cr0 |= 1 << 16;
    // SAFETY: preserve every CR0 bit and enable supervisor write protection.
    unsafe {
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
    }
    // SAFETY: caller and checks above establish all constructor conditions.
    let (mut a, mut b) = unsafe {
        (
            OwnedWindow::new(&access, frames, original_root, slot),
            OwnedWindow::new(&access, frames, original_root, slot),
        )
    };
    let first = frames.allocate().expect("first data frame");
    let second = frames.allocate().expect("second data frame");
    let first_pointer = access.pointer(first.start());
    let second_pointer = access.pointer(second.start());
    let address = a.address();
    let scratch = address as *mut u64;
    const A: u64 = 0x4556_524f_5349_4f4e;
    const B: u64 = 0x4d31_5041_4749_4e47;
    // SAFETY: two exclusively owned usable frames covered by the direct map.
    // Zero every byte before exposing either through the scratch window.
    unsafe {
        // Deliberately dirty every byte first: zeroing must be observed, not
        // accidentally pass because the emulator supplied already-zero RAM.
        for i in 0..ENTRIES {
            first_pointer.add(i).write_volatile(0xa5a5_a5a5_a5a5_a5a5);
            second_pointer.add(i).write_volatile(0x5a5a_5a5a_5a5a_5a5a);
        }
        ptr::write_bytes(first_pointer, 0, ENTRIES);
        ptr::write_bytes(second_pointer, 0, ENTRIES);
    }
    a.map(first);
    b.map(second);
    a.activate();
    // SAFETY: A's scratch page now maps its owned writable frame. No references
    // coexist with these raw accesses or the direct alias.
    unsafe {
        for i in 0..ENTRIES {
            assert_eq!(scratch.add(i).read_volatile(), 0);
        }
        scratch.write_volatile(A);
        assert_eq!(first_pointer.read_volatile(), A);
    }
    a.protect(Permission::ReadOnly);
    assert_eq!(
        a.hardware_entry() & (PRESENT | WRITABLE | NO_EXECUTE | 4 | 256),
        PRESENT | NO_EXECUTE
    );
    // SAFETY: still present and readable; do not inject a fault without an IDT.
    unsafe {
        assert_eq!(scratch.read_volatile(), A);
        // Exact supervisor write protection fault: present + write, CPL 0.
        crate::traps::expect_page_fault(address, crate::traps::Access::Write, 3);
        assert_eq!(scratch.read_volatile(), A);
        // Seed a harmless RET through the owned physical alias. If NX fails,
        // execution returns normally and the probe fails rather than running data.
        first_pointer.cast::<u8>().write_volatile(0xc3);
        crate::traps::expect_page_fault(address, crate::traps::Access::Execute, 17);
        first_pointer.write_volatile(A);
    }
    a.protect(Permission::ReadWrite);
    b.activate();
    // SAFETY: B's private branch maps its distinct writable frame at the same VA.
    unsafe {
        for i in 0..ENTRIES {
            assert_eq!(scratch.add(i).read_volatile(), 0);
        }
        scratch.write_volatile(B);
        assert_eq!(second_pointer.read_volatile(), B);
    }
    a.activate();
    // SAFETY: the same VA under A must still refer to A's original frame.
    unsafe {
        assert_eq!(scratch.read_volatile(), A);
    }
    let first = a.unmap();
    assert_eq!(a.hardware_entry(), 0);
    // SAFETY: this exact scratch address has just been unmapped; the installed
    // handler accepts only its read probe with a non-present supervisor error.
    unsafe {
        crate::traps::expect_page_fault(address, crate::traps::Access::Read, 0);
    }
    b.activate();
    let second = b.unmap();
    assert_eq!(b.hardware_entry(), 0);
    a.map(second);
    b.map(first);
    a.activate();
    // SAFETY: newly remapped, non-global leaf; CR3 and INVLPG discard stale A data.
    unsafe {
        assert_eq!(scratch.read_volatile(), B);
    }
    b.activate();
    // SAFETY: B now owns the frame originally mapped by A.
    unsafe {
        assert_eq!(scratch.read_volatile(), A);
    }
    // Exercise invalidation without any CR3 switch masking a missing INVLPG.
    let spare = frames.allocate().expect("active remap data frame");
    let spare_pointer = access.pointer(spare.start());
    const C: u64 = 0x544c_425f_5245_4d41;
    // SAFETY: spare is fresh claimed RAM; zero before mapping and seed its value.
    unsafe {
        ptr::write_bytes(spare_pointer, 0, ENTRIES);
        spare_pointer.write_volatile(C);
    }
    let original_b = b.unmap();
    b.map(spare);
    // SAFETY: still on root B, whose active leaf was replaced and invalidated.
    unsafe {
        assert_eq!(scratch.read_volatile(), C);
    }
    let _spare = b.unmap();
    b.map(original_b);
    // SAFETY: still on B after a second invalidation, back to its previous page.
    unsafe {
        assert_eq!(scratch.read_volatile(), A);
    }
    let report = Proof {
        root_a: a.root(),
        root_b: b.root(),
        virtual_address: address,
        faults: crate::traps::count() - faults_before,
    };
    assert_eq!(report.faults, 3);
    // SAFETY: original root and every inherited frame remain intact/reserved.
    unsafe {
        asm!("mov cr3, {}", in(reg) original, options(nostack, preserves_flags));
    }
    let restored: u64;
    // SAFETY: ring 0 readback; dropping tokens does not free physical frames.
    unsafe {
        asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
    }
    assert_eq!(restored, original);
    // The original root's scratch slot was never edited.
    // SAFETY: original root is still covered by the retained direct mapping.
    unsafe {
        assert_eq!(root_pointer.add(slot).read_volatile(), 0);
    }
    report
}
