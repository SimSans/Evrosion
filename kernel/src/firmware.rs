//! Trusted boot-platform ACPI reads, bounded before creating any byte slice.
use ev_boot_contract::{AddressRange, validate_virtual_range};
use ev_kernel::{
    acpi::{self, Error, Topology},
    memory::BootstrapFrames,
};
struct Firmware<'a> {
    offset: u64,
    frames: &'a BootstrapFrames,
}
impl Firmware<'_> {
    /// # Safety
    /// The retained loader direct map covers immutable firmware table RAM;
    /// reserved ranges are never reclaimed and firmware pointers are trusted
    /// platform input. Range checks alone do not validate hostile MMIO pointers.
    unsafe fn bytes(&self, physical: u64, length: usize) -> Result<&[u8], Error> {
        if length == 0
            || length > acpi::MAX_TABLE
            || !self.frames.contains_reserved(physical, length as u64)
        {
            return Err(Error::Address);
        }
        let start = self.offset.checked_add(physical).ok_or(Error::Address)?;
        let end = start.checked_add(length as u64).ok_or(Error::Address)?;
        validate_virtual_range(AddressRange { start, end }).map_err(|_| Error::Address)?;
        // SAFETY: caller guarantees immutable mapped firmware RAM. Bounds and
        // canonical range were checked above; returned borrow cannot outlive self.
        Ok(unsafe { core::slice::from_raw_parts(start as *const u8, length) })
    }
    /// # Safety
    /// Same trusted firmware and retained direct-map requirements as bytes.
    unsafe fn table(&self, physical: u64) -> Result<&[u8], Error> {
        // SAFETY: first read only the checked standard header; validate length
        // before constructing the full reserved-range-bounded slice.
        unsafe {
            let length = acpi::table_length(self.bytes(physical, 36)?)?;
            self.bytes(physical, length)
        }
    }
}
pub struct Proof {
    pub topology: Topology,
    pub bsp: u32,
}
/// # Safety
/// Sole bootstrap CPU, valid retained direct map and firmware's RSDP physical
/// address. No allocation/reclamation/firmware runtime mutates these tables.
pub unsafe fn discover(offset: u64, rsdp: u64, frames: &BootstrapFrames) -> Result<Proof, Error> {
    let firmware = Firmware { offset, frames };
    // SAFETY: caller supplies trusted immutable firmware through a retained map.
    // Every pointer is range checked and reads are length bounded independently.
    let topology = unsafe {
        let header = firmware.bytes(rsdp, 36)?;
        let length = if header[15] >= 2 {
            u32::from_le_bytes(header[20..24].try_into().map_err(|_| Error::Length)?) as usize
        } else {
            20
        };
        if length > 4096 {
            return Err(Error::Length);
        }
        let root = acpi::rsdp(firmware.bytes(rsdp, length)?)?;
        let entries = acpi::root_entries(firmware.table(root.address)?, root.extended)?;
        let mut topology = None;
        for &address in entries.addresses() {
            if firmware.bytes(address, 4)? == b"APIC" {
                if topology.is_some() {
                    return Err(Error::Duplicate);
                }
                topology = Some(acpi::madt(firmware.table(address)?)?);
            }
        }
        topology.ok_or(Error::Missing)?
    };
    // CPUID leaf 0xB reports a full x2APIC ID when present; leaf1 is the
    // bounded legacy fallback. No assumptions about contiguous APIC IDs.
    let max = core::arch::x86_64::__cpuid(0).eax;
    let extended = if max >= 0xb {
        Some(core::arch::x86_64::__cpuid_count(0xb, 0))
    } else {
        None
    };
    let bsp = match extended {
        Some(leaf) if leaf.ebx != 0 => leaf.edx,
        _ => core::arch::x86_64::__cpuid(1).ebx >> 24,
    };
    if !topology.cpus().iter().any(|cpu| cpu.apic_id == bsp) {
        return Err(Error::Missing);
    }
    Ok(Proof { topology, bsp })
}
