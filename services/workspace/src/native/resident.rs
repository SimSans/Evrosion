//! Process-private fixed residents, claimed once. No reset or alias API.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
pub struct Data {
    pub store: ev_workspace_store::Scratch,
    pub gateway: ev_workspace_service::Scratch,
    pub legacy: ev_workspace_service::legacy::Scratch,
    pub control: [u8; 256],
    pub bulk: [u8; 4096],
}
struct Resident {
    claimed: AtomicBool,
    data: UnsafeCell<Data>,
}
// SAFETY: the atomic gate grants one permanent mutable claim to the one entry
// thread. No shared Data reference, reset, Drop or second borrow is exposed.
unsafe impl Sync for Resident {}
static RESIDENT: Resident = Resident {
    claimed: AtomicBool::new(false),
    data: UnsafeCell::new(Data {
        store: ev_workspace_store::Scratch::empty(),
        gateway: ev_workspace_service::Scratch::empty(),
        legacy: ev_workspace_service::legacy::Scratch::new(),
        control: [0; 256],
        bulk: [0; 4096],
    }),
};
pub fn claim() -> &'static mut Data {
    super::require(
        RESIDENT
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        1230,
    );
    // SAFETY: the successful one-way gate establishes sole initialized private
    // Data ownership; no other reference is produced for this process lifetime.
    unsafe { &mut *RESIDENT.data.get() }
}
