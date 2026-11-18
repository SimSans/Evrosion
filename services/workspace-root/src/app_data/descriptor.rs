//! Independently fixed allocation identity for the one supported external-App
//! registry/data pair. These descriptors are never inferred from mutable media
//! or recomputed from whichever package happens to be selected after an update.
//! They establish namespace interpretation, not enrollment or format authority.
use super::private_data::Allocation;
use ev_store::{GenerationId, GenerationManifest};
use ev_zion::AppId;
use sha2::{Digest, Sha256};
pub const ALLOCATION_ID: [u8; 16] = *b"EVM8-EXTAPP-0001";
const DOMAIN: &[u8] = b"evrosion.m8.external-allocation.v1\0";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    app: AppId,
    schema_epoch: u32,
}
impl Descriptor {
    /// Trusted controller supplies the independently enrolled AppId/schema.
    /// A claimed package ID alone must never authorize this choice, creation,
    /// reopening another app's data, or replacing the enrollment record.
    pub fn for_enrolled_app(app: AppId, schema_epoch: u32) -> Option<Self> {
        (schema_epoch == 1).then_some(Self { app, schema_epoch })
    }
    pub const fn app(self) -> AppId {
        self.app
    }
    pub const fn schema_epoch(self) -> u32 {
        self.schema_epoch
    }
    pub fn data(self) -> Allocation {
        Allocation::new(data_creation(), self.app, self.schema_epoch)
            .expect("fixed supported allocation")
    }
}
fn manifest(purpose: &[u8]) -> GenerationManifest {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(ALLOCATION_ID);
    hash.update(purpose);
    let cohort = hash.finalize().into();
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort,
        // This is a fixed namespace-creation descriptor, not an assertion that
        // a running supervisor/image or package received healthy/KnownGood.
        supervisor_image: Sha256::digest(b"Evrosion M8 external namespace creation descriptor v1")
            .into(),
        abi: ev_userspace_contract::ABI,
        health_contract: Sha256::digest(
            b"Evrosion mutable-only external namespace v1; no boot health",
        )
        .into(),
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    }
}
pub fn registry_creation() -> GenerationManifest {
    manifest(b"registry")
}
pub fn data_creation() -> GenerationManifest {
    manifest(b"private-data")
}
