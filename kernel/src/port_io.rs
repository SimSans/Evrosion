//! Binary-only privileged instruction boundary. No ATA/device/filesystem policy.
use core::arch::asm;
use ev_kernel::io_ports::{ReadPermit, Width, WritePermit};
/// # Safety
/// CPL0, serialized device owner at IF=0; actual assigned hardware matches the
/// trusted registry binding. Keep the borrowed permit through this instruction.
pub(crate) unsafe fn input(permit: ReadPermit<'_>) -> u32 {
    let value = match permit.width() {
        Width::Byte => {
            let value: u8;
            // SAFETY: caller's actual live typed permit authorizes this exact port/width.
            unsafe {
                asm!("in al, dx",in("dx")permit.port(),out("al")value,options(nostack,preserves_flags));
            }
            u32::from(value)
        }
        Width::Word => {
            let value: u16;
            // SAFETY: same live permit; no address/range comes from unchecked user data.
            unsafe {
                asm!("in ax, dx",in("dx")permit.port(),out("ax")value,options(nostack,preserves_flags));
            }
            u32::from(value)
        }
        Width::Dword => {
            let value: u32;
            // SAFETY: same live permit for an explicitly permitted dword transaction.
            unsafe {
                asm!("in eax, dx",in("dx")permit.port(),out("eax")value,options(nostack,preserves_flags));
            }
            value
        }
    };
    let _object = permit.object();
    value
}
/// # Safety
/// Same CPL0/serialized actual-resource conditions as input(). Data width was
/// validated before constructing this non-forgeable borrowed write permit.
pub(crate) unsafe fn output(permit: WritePermit<'_>) {
    match permit.width() {
        Width::Byte => {
            // SAFETY: exact validated port/width and value fits in the byte register.
            unsafe {
                asm!("out dx, al",in("dx")permit.port(),in("al")permit.value() as u8,options(nostack,preserves_flags));
            }
        }
        Width::Word => {
            // SAFETY: exact validated port/width and value fits in the word register.
            unsafe {
                asm!("out dx, ax",in("dx")permit.port(),in("ax")permit.value() as u16,options(nostack,preserves_flags));
            }
        }
        Width::Dword => {
            // SAFETY: exact validated port/width; the value is already a bounded u32.
            unsafe {
                asm!("out dx, eax",in("dx")permit.port(),in("eax")permit.value(),options(nostack,preserves_flags));
            }
        }
    }
    let _object = permit.object();
}
