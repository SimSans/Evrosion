//! Narrow failure witness for actual owned-VM diagnosis. This journal never
//! changes a cut, result, retry, frame, poison state or retirement decision.
use super::{now, window::Window};
use core::sync::atomic::{AtomicU64, Ordering};
use ev_block_service::{
    store_io::{DesktopEndpoint, DesktopTransportError, Error},
    workspace::Region,
};
use ev_userspace_runtime as rt;
use ev_workspace_store::{Sector, SectorIo};
type IoError = Error<DesktopTransportError>;
static OP: AtomicU64 = AtomicU64::new(0);
static LBA: AtomicU64 = AtomicU64::new(0);
static CUT: AtomicU64 = AtomicU64::new(0);
static BEGAN: AtomicU64 = AtomicU64::new(0);
static ENDED: AtomicU64 = AtomicU64::new(0);
static ERROR: AtomicU64 = AtomicU64::new(0);
static DETAIL: AtomicU64 = AtomicU64::new(0);
static READS: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);
static FLUSHES: AtomicU64 = AtomicU64::new(0);
pub struct Device {
    inner: Region<DesktopEndpoint, Window>,
}
impl Device {
    pub fn new(inner: Region<DesktopEndpoint, Window>) -> Self {
        Self { inner }
    }
    fn begin(op: u64, lba: u64, cut: u64) {
        OP.store(op, Ordering::Relaxed);
        LBA.store(lba, Ordering::Relaxed);
        CUT.store(cut, Ordering::Relaxed);
        BEGAN.store(now(), Ordering::Relaxed);
        ENDED.store(0, Ordering::Relaxed);
        ERROR.store(0, Ordering::Relaxed);
        DETAIL.store(0, Ordering::Relaxed);
    }
    fn end(result: &Result<(), IoError>) {
        ENDED.store(now(), Ordering::Relaxed);
        if let Err(error) = result {
            let (code, detail) = match error {
                Error::Bounds => (1, 0),
                Error::Deadline => (2, 0),
                Error::NeedsRecovery => (3, 0),
                Error::Transport(DesktopTransportError::Clock) => (4, 0),
                Error::Transport(DesktopTransportError::Deadline) => (5, 0),
                Error::Transport(DesktopTransportError::BusyBudget) => (6, 0),
                Error::Transport(DesktopTransportError::Abi) => (7, 0),
                Error::Transport(DesktopTransportError::Sync(rt::SyncError::Status(s))) => (8, *s),
                Error::Transport(DesktopTransportError::Sync(
                    rt::SyncError::UnexpectedCapability(c),
                )) => (9, *c),
                Error::Decode(d) => (10, *d as u64),
                Error::UnexpectedReply(r) => (11, u64::from_le_bytes(r.encode())),
                Error::Counter => (12, 0),
                Error::Busy => (13, 0),
            };
            ERROR.store(code, Ordering::Relaxed);
            DETAIL.store(detail, Ordering::Relaxed);
        }
    }
}
impl SectorIo for Device {
    type Error = IoError;
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }
    fn read(&mut self, lba: u64, out: &mut Sector, cut: u64) -> Result<(), IoError> {
        READS.fetch_add(1, Ordering::Relaxed);
        Self::begin(1, lba, cut);
        let r = self.inner.read(lba, out, cut);
        Self::end(&r);
        r
    }
    fn write(&mut self, lba: u64, bytes: &Sector, cut: u64) -> Result<(), IoError> {
        WRITES.fetch_add(1, Ordering::Relaxed);
        Self::begin(2, lba, cut);
        let r = self.inner.write(lba, bytes, cut);
        Self::end(&r);
        r
    }
    fn flush(&mut self, cut: u64) -> Result<(), IoError> {
        FLUSHES.fetch_add(1, Ordering::Relaxed);
        Self::begin(3, 0, cut);
        let r = self.inner.flush(cut);
        Self::end(&r);
        r
    }
}
/// WF words are observational. Kernel39 supplies the actual sender outside
/// these bytes. Each finite one-shot send may fail; missing fields remain
/// visibly incomplete rather than blocking/retrying uncertain work.
pub fn emit(events: u64, request: u64, opcode: u8, original_cut: u64, failure: u32) {
    let values = [
        u64::from(opcode) | (u64::from(failure) << 8),
        ERROR.load(Ordering::Relaxed),
        DETAIL.load(Ordering::Relaxed),
        request,
        original_cut,
        OP.load(Ordering::Relaxed),
        LBA.load(Ordering::Relaxed),
        CUT.load(Ordering::Relaxed),
        BEGAN.load(Ordering::Relaxed),
        ENDED.load(Ordering::Relaxed),
        READS.load(Ordering::Relaxed),
        WRITES.load(Ordering::Relaxed),
        FLUSHES.load(Ordering::Relaxed),
    ];
    for (field, value) in values.iter().enumerate() {
        for high in 0..2 {
            let word = if high == 0 {
                *value as u32
            } else {
                (*value >> 32) as u32
            };
            let mut bytes = [b'W', b'F', (field * 2 + high) as u8, 0, 0, 0, 0, 0];
            bytes[4..].copy_from_slice(&word.to_le_bytes());
            let _ = rt::send(events, bytes);
            let _ = rt::yield_now();
        }
    }
}
