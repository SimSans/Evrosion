//! One actual RootSystem window/endpoint owner. Region devices reborrow it
//! exclusively; App receives neither this window nor generic sector authority.
use core::marker::PhantomData;
use ev_block_service::store_io::{DesktopEndpoint, Window};
use ev_store::Sector;

pub struct RootWindow<'a> {
    address: u64,
    _unique: PhantomData<&'a mut Sector>,
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
    Backend::new(DesktopEndpoint::new(endpoint, stop)?, window, stop)
}
