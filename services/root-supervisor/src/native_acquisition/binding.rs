//! Read-only current Store identity, never a publication or clock capability.
use super::*;
use ev_content_store::Backend;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationBinding {
    head: [u8; 32],
    checkpoint: Object,
    revision: u64,
    floor: u64,
}
impl AuthorizationBinding {
    pub const fn utc_floor(self) -> u64 {
        self.floor
    }
}
impl<B: Backend> Store<B> {
    /// Capture only this actual authenticated state and published head. This
    /// read-only identity does not prove backend quiescence or qualify a clock;
    /// the private runtime adapter separately requires both on every callback.
    /// A detached LOCAL identity Snapshot cannot manufacture this binding.
    pub fn authorization_binding(&self) -> Option<AuthorizationBinding> {
        if self.poisoned() {
            return None;
        }
        let snapshot = self.state.as_ref()?;
        Some(AuthorizationBinding {
            head: self.arena.head_digest(),
            checkpoint: self.arena.published_metadata()?,
            revision: snapshot.revision(),
            floor: snapshot.replay().utc_floor(),
        })
    }
}
