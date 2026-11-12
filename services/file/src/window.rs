//! Volatile access to exact prebound fixture mappings; no shared Rust reference
//! survives a syscall. Runtime admission owns mappings/leases and exclusion.
use crate::require;
#[cfg(feature = "server")]
use ev_userspace_contract::file_test::READY;
pub struct Window {
    address: usize,
}
impl Window {
    pub fn at(record: u64, pages: u64) -> Self {
        Self {
            address: usize::try_from(
                record
                    .checked_sub(pages * 4096)
                    .unwrap_or_else(|| ev_userspace_runtime::exit(603)),
            )
            .unwrap_or_else(|_| ev_userspace_runtime::exit(604)),
        }
    }
    pub fn load(&self) -> [u8; 256] {
        core::array::from_fn(|index| {
            // SAFETY: the exact retained prebound page is mapped/initialized;
            // one blocked client and actual replies exclude concurrent reuse.
            unsafe { (self.address as *const u8).add(index).read_volatile() }
        })
    }
    pub fn publish(&self, bytes: &[u8; 256]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: same initialized owned mapping; only256 exact bytes.
            unsafe { (self.address as *mut u8).add(index).write_volatile(byte) };
        }
    }
    #[cfg(feature = "server")]
    pub fn ready(&self) {
        self.marker(READY);
    }
    pub fn marker(&self, marker: [u8; 8]) {
        // Publish the header LAST so a polling client cannot race later tail
        // initialization against its first request. This is not a health grant.
        for index in 8..256 {
            // SAFETY: retained private fixture window, client still polling.
            unsafe { (self.address as *mut u8).add(index).write_volatile(0) };
        }
        for (index, byte) in marker.into_iter().enumerate() {
            // SAFETY: same eight initialized handshake bytes, tail is finished.
            unsafe { (self.address as *mut u8).add(index).write_volatile(byte) };
        }
    }
    pub fn guards(&self, first: usize) {
        for index in first..4096 {
            // SAFETY: never crosses the retained initialized4096-byte mapping.
            require(
                unsafe { (self.address as *const u8).add(index).read_volatile() } == 0,
                605,
            );
        }
    }
}
#[cfg(feature = "server")]
impl ev_block_service::store_io::Window for Window {
    fn load(&self, out: &mut ev_store::Sector) {
        for (index, byte) in out.iter_mut().enumerate() {
            // SAFETY: exact512-byte IO window; the real blocked request/response
            // lifecycle excludes concurrent use and no Rust alias is retained.
            *byte = unsafe { (self.address as *const u8).add(index).read_volatile() };
        }
    }
    fn store(&self, bytes: &ev_store::Sector) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: same retained exact512-byte IO mapping and exclusion.
            unsafe { (self.address as *mut u8).add(index).write_volatile(byte) };
        }
    }
}
