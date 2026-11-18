//! Actual scalar52 boundary and fixed retained Root data aliases. No mapped
//! byte from staging is ever borrowed as a Package or immutable Rust slice.
use super::*;
use ev_root_supervisor::native_image::{Images, Io, IoError};
use ev_userspace_contract::root_v4::dynamic::{self as image, Operation};

pub(super) struct Kernel {
    creator: u64,
    base: u64,
    initialized: bool,
    failed: bool,
    pending_bytes: Option<usize>,
    staging: Option<usize>,
    readonly: [Option<usize>; 2],
}
/// # Safety
/// Exact admitted V4 Root startup page509 and CreatorJob bootstrap handle;
/// called once in its resident Controller before any image operation.
pub(super) unsafe fn owner(record: u64, creator: u64) -> Images<Kernel> {
    let base = record
        .checked_sub(ev_userspace_contract::root_v4::ROOT_STARTUP_PAGE * 4096)
        .unwrap_or_else(|| fail(1040));
    Images::new(
        Kernel {
            creator,
            base,
            initialized: false,
            failed: false,
            pending_bytes: None,
            staging: None,
            readonly: [None; 2],
        },
        base,
    )
    .unwrap_or_else(|_| fail(1041))
}
impl Kernel {
    fn address(&self, index: usize) -> usize {
        (self.base + image::REGION + index as u64 * 4096) as usize
    }
}
impl Io for Kernel {
    fn control(&mut self, op: Operation, operand: u64, extra: u64) -> rt::CapReply {
        if self.failed {
            return rt::CapReply {
                status: 1,
                value: 3,
                capability: 0,
                serial: 0,
            };
        }
        let r = rt::call4(
            syscall::IMAGE_CONTROL,
            self.creator,
            op as u64,
            operand,
            extra,
        );
        if r.status != 0 || r.serial != 0 {
            self.failed = true;
            return r;
        }
        match op {
            Operation::Initialize if r.value == image::VERSION && r.capability == 0 => {
                self.initialized = true
            }
            Operation::Begin if matches!(r.value, 1 | 2) && r.capability != 0 => {
                self.staging = Some(r.value as usize - 1)
            }
            Operation::Seal => self.staging = None,
            Operation::Abort => {
                self.staging = None;
                self.pending_bytes = None;
            }
            Operation::Verify if r.value == 0 && r.capability != 0 && matches!(operand, 1 | 2) => {
                self.readonly[operand as usize - 1] = self.pending_bytes;
                self.pending_bytes = None;
            }
            _ => {}
        }
        r
    }
    fn write_header(&mut self, header: &[u8; image::HEADER_BYTES]) -> Result<(), IoError> {
        if !self.initialized || self.failed || self.staging.is_some() {
            return Err(IoError);
        }
        let h = image::Header::decode(header).ok_or(IoError)?;
        let p = self.address(image::CONTROL) as *mut u8;
        for (i, b) in header.iter().enumerate() {
            // SAFETY: successful actual52 Initialize installed exactly this
            // fixed private control page; Root owns its sole writer, no borrow.
            unsafe { p.add(i).write_volatile(*b) };
        }
        self.pending_bytes = Some(h.bytes as usize);
        Ok(())
    }
    fn write_staging(&mut self, offset: usize, bytes: &[u8]) -> Result<(), IoError> {
        if self.failed
            || self.staging.is_none()
            || bytes.is_empty()
            || bytes.len() > 4096
            || offset
                .checked_add(bytes.len())
                .is_none_or(|n| self.pending_bytes.is_none_or(|end| n > end))
        {
            return Err(IoError);
        }
        let p = (self.address(image::STAGING_FIRST) + offset) as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            // SAFETY: actual successful Begin mapped the exact charged RW
            // extent here; checked256KiB bounds, no mutable Rust reference.
            unsafe { p.add(i).write_volatile(*b) };
        }
        Ok(())
    }
    fn readonly(&self, slot: usize, bytes: usize) -> Result<&[u8], IoError> {
        // A later unrelated operation fences creation/mutation, but cannot
        // revoke a previously verified permanent RO mapping. Images exposes
        // these bytes under that fence only for an already Registered slot.
        if !self.initialized || self.readonly.get(slot) != Some(&Some(bytes)) {
            return Err(IoError);
        }
        let p = self.address(image::READONLY_FIRST[slot]) as *const u8;
        // SAFETY: only actual successful finalVerify installs this immutable
        // range after writer removal/readback/CR3 boundary. Its affine Kernel
        // lease is permanent through Root termination; bytes borrow this owner
        // and never static/user-selected memory. No path can remap these slots.
        Ok(unsafe { core::slice::from_raw_parts(p, bytes) })
    }
}
