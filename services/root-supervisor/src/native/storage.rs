//! One actual RootSystem window/endpoint owner. Region devices reborrow it
//! exclusively; App receives neither this window nor generic sector authority.
use core::marker::PhantomData;
use ev_block_service::store_io::{DesktopEndpoint, Window};
use ev_store::Sector;

pub struct RootWindow<'a> {
    address: u64,
    _unique: PhantomData<&'a mut Sector>,
}
/// Retained versioned Root506 claim: the V3 prototype aliases AppFile; V4 uses
/// its independently admitted NoteWindow. No shared Rust slice escapes; every
/// proposal/reply is copied through volatile IO under the retained owner.
#[cfg(feature = "native-session")]
pub struct NoteWindow {
    address: usize,
}
#[cfg(feature = "native-session")]
impl NoteWindow {
    /// # Safety
    /// Actual measured session mapping at506 is initialized, RW/NX and retained
    /// for this Root lifetime. The serialized Root handler never reenters App
    /// reap/create/scrub while this window operation or its child RPC is active.
    pub unsafe fn new(record: u64) -> Self {
        Self {
            address: (record - 3 * 4096) as usize,
        }
    }
    pub fn snapshot(&self) -> [u8; 256] {
        core::array::from_fn(|i| {
            // SAFETY: retained actual256-byte mapping, copied before parsing.
            unsafe { (self.address as *const u8).add(i).read_volatile() }
        })
    }
    pub fn publish(&mut self, bytes: &[u8; 256]) {
        for (i, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: same retained mapping; accepted client holds its page
            // until a matching Root ACK, independent of logical wait expiry.
            unsafe { (self.address as *mut u8).add(i).write_volatile(byte) };
        }
    }
}
impl RootWindow<'_> {
    /// # Safety
    /// Named admitted Root ABI supplies the actual retained RW System page508,
    /// no App alias; this is its sole Rust-side owner and all requests block the
    /// sole client until real driver completion. Mapping outlives this owner.
    pub unsafe fn new(record: u64) -> Self {
        Self {
            address: record - 4096,
            _unique: PhantomData,
        }
    }
}
impl Window for RootWindow<'_> {
    fn load(&self, out: &mut Sector) {
        for (i, byte) in out.iter_mut().enumerate() {
            // SAFETY: retained exact fixed512-byte window and completed read reply.
            *byte = unsafe { ((self.address as *const u8).add(i)).read_volatile() };
        }
    }
    fn store(&self, bytes: &Sector) {
        for (i, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: unique Root window owner, preflighted write before blocked call.
            unsafe { ((self.address as *mut u8).add(i)).write_volatile(byte) };
        }
    }
}
pub type Backend<'a> =
    ev_root_supervisor::native_plan::storage::Backend<DesktopEndpoint, RootWindow<'a>>;
pub fn backend<'a>(endpoint: u64, window: RootWindow<'a>, stop: u64) -> Option<Backend<'a>> {
    let wire = if stop == 0 {
        DesktopEndpoint::for_session_transactions(endpoint)?
    } else {
        DesktopEndpoint::new(endpoint, stop)?
    };
    Backend::new(wire, window, stop)
}
