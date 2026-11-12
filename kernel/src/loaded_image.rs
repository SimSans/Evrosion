//! Narrow hardware ownership contract used by the portable activation gate.
use crate::scheduler::ProcessId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Startup {
    pub address: u64,
    pub bytes: usize,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy)]
pub struct Information {
    pub process: ProcessId,
    pub manifest: [u8; 32],
    pub entry: u64,
    pub stack: u64,
    pub root: u64,
    pub frames: u64,
    pub startup: Option<Startup>,
}

/// An owned, initialized hardware executable image, never a readiness boolean.
///
/// # Safety
/// Implementers must uniquely own and retain the actual page tables and frames
/// reported by information(). Before admission these must contain the exact
/// measured image, final W^X permissions, zero fill, guarded NX stack and any
/// read-only bootstrap page (including its truthful digest) described
/// by that manifest's load plan. information() must remain stable and truthful.
/// No writable alias may modify initialization between validation and admission.
/// After admission only the process's ordinary permitted writes may change it.
/// Dropping this value MUST retain physical backing/mappings: reclamation needs
/// a separate explicit operation proving all CPU/mapping/reference quiescence.
/// These obligations permit safe portable activation to release a held process
/// without exposing it to uninitialized/reclaimed memory or unrelated mappings.
#[allow(unsafe_code)] // Contract declaration only; this module performs no unsafe operations.
pub unsafe trait LoadedExecutable {
    fn information(&self) -> Information;
    /// The default preserves every legacy implementation. A graphics override
    /// asserts ownership of that measured layout's ACTUAL extra RAM tables and
    /// final device PTEs/guards, in addition to all obligations above. It is not
    /// a ready boolean: Registry compares the exact descriptor reservation.
    fn layout(&self) -> crate::executable::LayoutReservation {
        crate::executable::LayoutReservation::Legacy
    }
}
