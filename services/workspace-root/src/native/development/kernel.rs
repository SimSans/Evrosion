//! Actual M8 dynamic2 boundary for the separately protected installer.
//! No caller-supplied VA or package claim can construct this native owner.
//! Staging is volatile bytes; immutable Package borrows begin after final Verify.
use super::*;
use ev_userspace_contract::root_v5::dynamic::{self as image, Operation};
use ev_workspace_root::install_plan::{Io, IoError};

pub(super) struct Kernel {
    creator: u64,
    cut: model::Cut,
    base: u64,
    initialized: bool,
    failed: bool,
    pending_bytes: Option<usize>,
    staging: Option<usize>,
    readonly: [Option<usize>; 2],
    last: Option<(Operation, u64, u64, rt::CapReply)>,
}
impl Kernel {
    /// Actual admitted Root supplies its retained CreatorJob only. No App
    /// message or external address may construct this adapter.
    pub(super) fn new(creator: u64, original_cut: u64) -> Result<Self, IoError> {
        if matches!(creator, 0 | u64::MAX) {
            return Err(IoError);
        }
        Ok(Self {
            creator,
            cut: model::Cut::new(now(), original_cut).map_err(|_| IoError)?,
            base: BASE as u64,
            initialized: false,
            failed: false,
            pending_bytes: None,
            staging: None,
            readonly: [None; 2],
            last: None,
        })
    }
    fn address(&self, index: usize) -> usize {
        (self.base + image::REGION + index as u64 * 4096) as usize
    }
    fn live(&mut self) -> Result<(), IoError> {
        if self.failed || self.cut.admit(now()).is_err() {
            self.failed = true;
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn finished(&mut self) -> Result<(), IoError> {
        if self.cut.complete(now()).is_err() {
            self.failed = true;
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn refused() -> rt::CapReply {
        // Local admission refusal, never recorded as an actual Kernel reply.
        rt::CapReply {
            status: 1,
            value: 3,
            capability: 0,
            serial: 0,
        }
    }
}
impl Io for Kernel {
    fn control(&mut self, op: Operation, operand: u64, extra: u64) -> rt::CapReply {
        if self.failed {
            return Self::refused();
        }
        let creator = self.creator;
        let r = match self.cut.invoke(now, || {
            rt::call4(s::IMAGE_CONTROL, creator, op as u64, operand, extra)
        }) {
            Ok(r) => r,
            Err(failure) => {
                if let Some(r) = failure.actual {
                    self.last = Some((op, operand, extra, r));
                }
                self.failed = true;
                return Self::refused();
            }
        };
        self.last = Some((op, operand, extra, r));
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
        self.live()?;
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
        self.finished()
    }
    fn write_staging(&mut self, offset: usize, bytes: &[u8]) -> Result<(), IoError> {
        self.live()?;
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
        self.finished()
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
