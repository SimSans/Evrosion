//! Actual RAM and inactive page-table inspection for the graphics fixture.
//! No framebuffer bytes are accessed here: only userspace Display paints them.
use super::*;
use ev_kernel::memory::PhysicalFrame;

pub(super) struct Hardware {
    pub offset: u64,
    pub bits: u8,
    pub original: u64,
}
impl Hardware {
    pub unsafe fn capture(offset: u64) -> Self {
        let original: u64;
        // SAFETY: privileged serialized BSP before any user root is active.
        unsafe { asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags)) };
        Self {
            offset,
            bits: (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8,
            original,
        }
    }
    fn byte(&self, frame: &PhysicalFrame, byte: usize) -> Result<*mut u8, &'static str> {
        if byte >= FRAME_SIZE as usize {
            return Err("RAM byte outside frame");
        }
        direct_address(self.offset, frame.start(), self.bits)
            .map_err(|_| "RAM direct map")?
            .checked_add(byte as u64)
            .map(|address| address as *mut u8)
            .ok_or("RAM byte overflow")
    }
    /// Actual owned page-table RAM; all addresses come from this retained
    /// immutable root's walk, never a userspace pointer or diagnostic ID.
    fn entry(&self, table: u64, index: usize) -> u64 {
        assert!(table != 0 && table.is_multiple_of(FRAME_SIZE) && index < 512);
        let address = direct_address(self.offset, table, self.bits).unwrap();
        // SAFETY: real retained root/owned RAM tables, IF0 and inactive root;
        // userspace cannot mutate page tables and no claim is released here.
        unsafe { (address as *const u64).add(index).read_volatile() }
    }
    fn directory(&self, root: u64, base: u64) -> u64 {
        let pml4 = self.entry(root, ((base >> 39) & 511) as usize);
        assert_eq!(pml4 & (PRESENT | USER), PRESENT | USER);
        let pdpt = self.entry(pml4 & ADDRESS_MASK, ((base >> 30) & 511) as usize);
        assert_eq!(pdpt & (PRESENT | USER | (1 << 7)), PRESENT | USER);
        pdpt & ADDRESS_MASK
    }
    pub fn verify_surface(&self, image: &GraphicsImage, a: &Authority, extent: &MemoryExtent) {
        let lease = image.surface().expect("retained actual surface lease");
        extent.validate(a, lease).unwrap();
        let root = image.root();
        let directory = self.directory(root.root(), root.base());
        let pde = self.entry(directory, 0);
        assert_eq!(pde & (PRESENT | USER | (1 << 7)), PRESENT | USER);
        let leaf = pde & ADDRESS_MASK;
        assert_eq!(self.entry(leaf, 383), 0);
        assert_eq!(self.entry(leaf, 447), 0);
        let mut pages = 0;
        for (index, physical) in extent.physical_pages(lease).unwrap().enumerate() {
            let expected = physical
                | PRESENT
                | USER
                | NO_EXECUTE
                | if lease.writable() { WRITABLE } else { 0 };
            assert_eq!(self.entry(leaf, 384 + index) & !AD, expected);
            pages += 1;
        }
        assert_eq!(pages, SURFACE_PAGES);
        assert_eq!(self.entry(directory, 1), 0);
        assert_eq!(self.entry(directory, 4), 0);
        if let Some(display) = image.display() {
            assert_eq!(display.mapped_root(), Some(root.root()));
            assert!(display.mapped_geometry().is_some());
            assert_eq!(display.table_frames(), 2);
            for index in [2, 3] {
                let pde = self.entry(directory, index);
                assert_eq!(
                    pde & !ADDRESS_MASK & !AD,
                    PRESENT | USER | WRITABLE | NO_EXECUTE
                );
                assert_ne!(pde & ADDRESS_MASK, 0);
            }
        } else {
            // The ordinary App has no Display aperture or descendant PTs.
            assert_eq!(self.entry(directory, 2), 0);
            assert_eq!(self.entry(directory, 3), 0);
        }
    }
    pub fn surface_digest(&self, extent: &MemoryExtent, lease: &ExtentLease) -> [u8; 32] {
        let mut digest = Sha256::new();
        let mut absolute = 0;
        let mut header = [0u8; 64];
        let mut buffer = [0u8; 512];
        for physical in extent.physical_pages(lease).unwrap() {
            let address = direct_address(self.offset, physical, self.bits).unwrap();
            for offset in (0..FRAME_SIZE as usize).step_by(buffer.len()) {
                for (index, byte) in buffer.iter_mut().enumerate() {
                    // SAFETY: actual initialized, retained allocator RAM. User
                    // CPUs are captured; no Rust alias crosses this readback.
                    *byte = unsafe { (address as *const u8).add(offset + index).read_volatile() };
                    if absolute < header.len() {
                        header[absolute] = *byte;
                    }
                    if absolute >= SURFACE_BYTES {
                        assert_eq!(*byte, 0, "surface tail");
                    }
                    absolute += 1;
                }
                digest.update(buffer);
            }
        }
        assert_eq!(absolute, SURFACE_PAGES * FRAME_SIZE as usize);
        assert_eq!(&header[..8], b"EVSURF01");
        assert_eq!(u64::from_le_bytes(header[24..32].try_into().unwrap()), 1);
        digest.finalize().into()
    }
}
// SAFETY: Hardware's checked byte method addresses the exact passed real RAM
// claim, never MMIO or another frame. Each operation is volatile and returns
// real readback; no pointer/reference survives an operation. The controller
// retains the allocator, direct map and exclusive quiescent RAM ownership.
unsafe impl RamAccess for Hardware {
    type Error = &'static str;
    fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), Self::Error> {
        let pointer = self.byte(frame, byte)?;
        // SAFETY: exact initialized/quiescent RAM claim and checked byte above.
        unsafe { pointer.write_volatile(value) };
        Ok(())
    }
    fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, Self::Error> {
        let pointer = self.byte(frame, byte)?;
        // SAFETY: same exact retained RAM claim; truthful volatile readback.
        Ok(unsafe { pointer.read_volatile() })
    }
}
