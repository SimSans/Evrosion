//! Private process-local owner identity. Never persisted, a nonce or authority.
use core::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
fn allocate(next: &AtomicU64) -> Option<u64> {
    next.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .ok()
        .filter(|n| *n != 0)
}
pub(super) fn next() -> Option<u64> {
    allocate(&NEXT)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_identity_exhaustion_never_wraps_or_reuses() {
        let next = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate(&next), Some(u64::MAX - 1));
        assert_eq!(allocate(&next), None);
        assert_eq!(allocate(&next), None);
        assert_eq!(next.load(Ordering::Relaxed), u64::MAX);
        let next = AtomicU64::new(1);
        assert_eq!(allocate(&next), Some(1));
        assert_eq!(allocate(&next), Some(2));
    }
}
