//! Binary-only privileged instruction boundary. No ATA/device/filesystem policy.
use core::arch::asm;
#[cfg(feature = "test-m4-desktop")]
use ev_kernel::io_ports::{
    ReadBytes4Permit, ReadWords4Permit, WriteBytes4Permit, WriteWords4Permit,
};
use ev_kernel::io_ports::{ReadPermit, Width, WritePermit};
#[cfg(feature = "test-m8-workspace")]
use ev_kernel::io_ports::{ReadWords256Permit, WriteWords256Permit};
/// Serialized raw TSC interval for the actual IF0 fixed port loop only. This
/// is not nanoseconds, an IRQ charge, or proof of elapsed wall-clock progress.
#[cfg(feature = "test-m8-workspace")]
pub(crate) fn cycles() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: x86-64 baseline LFENCE/RDTSC, no memory operand or user pointer.
    unsafe {
        asm!("lfence", "rdtsc", "lfence", out("eax") low, out("edx") high, options(nostack, preserves_flags));
    }
    u64::from(low) | (u64::from(high) << 32)
}
/// # Safety
/// CPL0/IF0, serialized actual selected device; live permit and Kernel scratch
/// retained for all256 operations. Copy into user RAM occurs only afterwards.
#[cfg(feature = "test-m8-workspace")]
#[inline(never)]
pub(crate) unsafe fn input_words256(permit: ReadWords256Permit<'_>, bytes: &mut [u8; 512]) -> u64 {
    let began = cycles();
    permit.transfer(bytes, |port| {
        let value: u16;
        // SAFETY: actual same-port live borrowed Word authority, fixed count.
        unsafe {
            asm!("in ax, dx", in("dx") port, out("ax") value, options(nostack, preserves_flags));
        }
        value
    });
    cycles()
        .checked_sub(began)
        .expect("PIO TSC reversed; retain owners")
}
/// # Safety
/// Same live actual port/IF0 ownership; complete Kernel snapshot precedes OUT.
#[cfg(feature = "test-m8-workspace")]
#[inline(never)]
pub(crate) unsafe fn output_words256(permit: WriteWords256Permit<'_>, bytes: &[u8; 512]) -> u64 {
    let began = cycles();
    permit.transfer(bytes, |port, value| {
        // SAFETY: fixed same-port256 Word writes under retained live authority.
        unsafe {
            asm!("out dx, ax", in("dx") port, in("ax") value, options(nostack, preserves_flags));
        }
    });
    cycles()
        .checked_sub(began)
        .expect("PIO TSC reversed; retain owners")
}
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
/// # Safety
/// CPL0/IF0, serialized assigned device and the actual live borrowed Word4
/// permit remain retained through all four fixed operations. No user pointer.
#[cfg(feature = "test-m4-desktop")]
pub(crate) unsafe fn input_words4(permit: ReadWords4Permit<'_>) -> u64 {
    let mut packed = 0;
    for word in 0..4 {
        let value: u16;
        // SAFETY: typed permit validated exact same Word port and finite cut;
        // no user execution, revocation or authority mutation occurs at IF0.
        unsafe {
            asm!("in ax, dx",in("dx")permit.port(),out("ax")value,options(nostack,preserves_flags));
        }
        packed |= u64::from(value) << (word * 16);
    }
    let _object = permit.object();
    packed
}
/// # Safety
/// Same fixed-count, actual live authority and IF0 conditions as input_words4.
#[cfg(feature = "test-m4-desktop")]
pub(crate) unsafe fn output_words4(permit: WriteWords4Permit<'_>) {
    for word in 0..4 {
        let value = (permit.value() >> (word * 16)) as u16;
        // SAFETY: all four Word writes were admitted before the first OUT;
        // each source value is exactly16bits and the borrowed port stays live.
        unsafe {
            asm!("out dx, ax",in("dx")permit.port(),in("ax")value,options(nostack,preserves_flags));
        }
    }
    let _object = permit.object();
}

/// # Safety
/// CPL0/IF0 and the actual live same-port Byte4 permit are retained across four
/// fixed byte instructions. No user execution or authority mutation intervenes.
#[cfg(feature = "test-m4-desktop")]
#[inline(never)]
pub(crate) unsafe fn input_bytes4(permit: ReadBytes4Permit<'_>) -> u32 {
    let mut packed = 0;
    for byte in 0..4 {
        let value: u8;
        // SAFETY: the borrowed permit validated this same Byte port and cut
        // before the first IN. The fixed group has no user pointer or loop bound.
        unsafe {
            asm!("in al, dx",in("dx")permit.port(),out("al")value,options(nostack,preserves_flags));
        }
        packed |= u32::from(value) << (byte * 8);
    }
    let _object = permit.object();
    packed
}
/// # Safety
/// Same actual live authority and IF0 conditions as input_bytes4.
#[cfg(feature = "test-m4-desktop")]
#[inline(never)]
pub(crate) unsafe fn output_bytes4(permit: WriteBytes4Permit<'_>) {
    for byte in 0..4 {
        let value = (permit.value() >> (byte * 8)) as u8;
        // SAFETY: the complete same-port group was authorized before any OUT;
        // each value is exactly one byte and the permit stays borrowed at IF0.
        unsafe {
            asm!("out dx, al",in("dx")permit.port(),in("al")value,options(nostack,preserves_flags));
        }
    }
    let _object = permit.object();
}
