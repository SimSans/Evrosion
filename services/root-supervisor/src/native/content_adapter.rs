//! Root-only content backend view. It reborrows the existing single Backend;
//! no window, transport, port or persistent authority is created here.
#![forbid(unsafe_code)]
use super::{Backend, NetworkDevice};
use ev_block_service::store_io::{Window, Wire};
use ev_content_store::{Area, Backend as ContentBackend};
use ev_store::{GenerationId, GenerationManifest, network};
use sha2::{Digest, Sha256};
/// One scoped view; its GAT devices borrow the same actual Backend/window.
/// Availability/consent is trusted Root policy and never read from packets.
pub struct BackendRef<'a, T, W> {
    backend: &'a mut Backend<T, W>,
    writes: bool,
}
/// Affine continuation owner, constructible only by the actual State slot.
/// It retains the same window, RPC fence, counters and private backend identity.
pub struct OwnedBackend<T, W> {
    pub(super) backend: Backend<T, W>,
    pub(super) writes: bool,
    pub(super) loan: u64,
}
impl<T, W> OwnedBackend<T, W> {
    pub(crate) fn selection_owner(&self) -> Option<(u64, u64)> {
        self.writes.then_some((self.backend.identity, self.loan))
    }
}
impl<T: Wire, W: Window> ContentBackend for OwnedBackend<T, W> {
    type Error = super::Error<T::Error>;
    type Device<'a>
        = NetworkDevice<'a, T, W>
    where
        Self: 'a;
    fn device(&mut self, area: Area) -> Self::Device<'_> {
        let area = match area {
            Area::Checkpoint => network::Area::Checkpoint,
            Area::Objects => network::Area::Objects,
        };
        self.backend.network_device(area, self.writes)
    }
    fn has_unresolved_io(&self) -> bool {
        self.backend.has_unresolved_io()
    }
}
impl<'a, T: Wire, W: Window> BackendRef<'a, T, W> {
    pub(crate) fn new(backend: &'a mut Backend<T, W>, writes: bool) -> Self {
        Self { backend, writes }
    }
}
impl<T: Wire, W: Window> ContentBackend for BackendRef<'_, T, W> {
    type Error = super::Error<T::Error>;
    type Device<'a>
        = NetworkDevice<'a, T, W>
    where
        Self: 'a;
    fn device(&mut self, area: Area) -> Self::Device<'_> {
        let area = match area {
            Area::Checkpoint => network::Area::Checkpoint,
            Area::Objects => network::Area::Objects,
        };
        self.backend.network_device(area, self.writes)
    }
    fn has_unresolved_io(&self) -> bool {
        self.backend.has_unresolved_io()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationError {
    Namespace,
    Volume,
}
/// Stable caller-provisioned owner namespace and volume identity. Keep these
/// actual inputs across Root updates/cold recovery; never substitute current
/// startup ABI, current executable SHA, downloaded root keys or cache labels.
/// This is a creation record, not health/KnownGood/admitted execution evidence.
pub fn creation_manifest(
    owner_namespace: [u8; 32],
    volume: [u8; 32],
) -> Result<GenerationManifest, CreationError> {
    if owner_namespace == [0; 32] {
        return Err(CreationError::Namespace);
    }
    if volume == [0; 32] {
        return Err(CreationError::Volume);
    }
    fn hash(domain: &[u8], owner: &[u8; 32], volume: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(ev_content_store::FORMAT_ABI);
        h.update(owner);
        h.update(volume);
        h.finalize().into()
    }
    Ok(GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: hash(
            b"evrosion.root.content.namespace.v1\0",
            &owner_namespace,
            &volume,
        ),
        // Store's structural creation field. This digest names metadata only;
        // it deliberately does not pretend to be an actual Root executable.
        supervisor_image: hash(
            b"evrosion.root.content.creation-only.not-executable.v1\0",
            &owner_namespace,
            &volume,
        ),
        abi: ev_content_store::FORMAT_ABI,
        health_contract: hash(
            b"evrosion.root.content.creation-only.no-health.v1\0",
            &owner_namespace,
            &volume,
        ),
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    })
}
#[cfg(test)]
#[path = "content_adapter_tests.rs"]
mod tests;
