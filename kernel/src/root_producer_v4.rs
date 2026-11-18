//! Canonical v4 bytes from generation-tagged source descriptions. This encodes
//! no authority: the existing live binding/Custodian gates must independently
//! realize/resolve the exact source identities under actual Authority custody.
pub use crate::root_producer_v2::{Error, Identity, SourceIdentity};
use crate::{root_manifest_v2, root_manifest_v4};
use ev_userspace_contract::{root_v2::ManifestInputs, root_v4};
use sha2::{Digest, Sha256};

pub struct Description {
    entries: [SourceIdentity; root_v4::CURRENT_GRANTS],
    limits: [u64; 4],
    attempts: u8,
    window: u64,
    catalogue: Option<[u8; 32]>,
}
impl Description {
    pub fn full_graph(
        limits: [u64; 4],
        attempts: u8,
        window: u64,
        identities: [Identity; root_v4::CURRENT_GRANTS],
    ) -> Result<Self, Error> {
        if limits != root_v4::ROOT_LIMITS
            || limits.into_iter().any(|v| matches!(v, 0 | u64::MAX))
            || limits[2] > crate::scheduler::MAX_PROCESSES as u64
            || limits[3] > crate::scheduler::MAX_THREADS as u64
        {
            return Err(Error::Limits);
        }
        crate::restart::Policy::new(attempts, window).map_err(|_| Error::Restart)?;
        let mut entries = [None; root_v4::CURRENT_GRANTS];
        for (i, role) in root_v4::ROLES.into_iter().enumerate() {
            if identities[..i]
                .iter()
                .any(|old| old.object == identities[i].object)
            {
                return Err(Error::Alias);
            }
            entries[i] = Some(SourceIdentity {
                selector: role.role.selector(),
                kind: root_manifest_v2::kind(role.kind).ok_or(Error::Kind)?,
                rights: crate::capability::Rights::from_bits(role.rights).ok_or(Error::Rights)?,
                object: identities[i].object,
                lineage: identities[i].lineage,
            });
        }
        Ok(Self {
            entries: entries.map(Option::unwrap),
            limits,
            attempts,
            window,
            catalogue: None,
        })
    }
    pub fn bind_catalogue(mut self, digest: [u8; 32]) -> Self {
        self.catalogue = Some(digest);
        self
    }
    pub fn authority_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(root_manifest_v4::AUTHORITY_DOMAIN);
        hash.update(root_v4::ABI);
        hash.update((root_v4::SIZE as u64).to_le_bytes());
        hash.update(root_v4::PROFILE.to_le_bytes());
        hash.update((self.entries.len() as u64).to_le_bytes());
        for e in self.entries {
            hash.update(e.selector.to_le_bytes());
            hash.update([root_manifest_v2::kind_tag(e.kind)]);
            hash.update(e.object.to_le_bytes());
            hash.update(e.lineage.to_le_bytes());
            hash.update(e.rights.bits().to_le_bytes());
            hash.update([0]);
            hash.update(0u64.to_le_bytes());
            hash.update(0u64.to_le_bytes());
        }
        hash.finalize().into()
    }
}
pub struct Encoded {
    bytes: [u8; root_v4::MANIFEST_CURRENT_BYTES],
}
impl Encoded {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.bytes()).into()
    }
}
pub fn encode_current(image: &[u8], description: &Description) -> Result<Encoded, Error> {
    if image.is_empty() || image.len() > crate::bootstrap_manifest::MAX_IMAGE_BYTES {
        return Err(Error::Image);
    }
    let bytes = root_v4::manifest_profile(ManifestInputs {
        root_image: Sha256::digest(image).into(),
        catalogue: description.catalogue.ok_or(Error::Catalogue)?,
        authority: description.authority_digest(),
        limits: description.limits,
        restart_attempts: description.attempts,
        restart_window: description.window,
    })
    .map_err(|_| Error::Profile)?;
    let encoded = Encoded { bytes };
    root_manifest_v4::verify(encoded.bytes(), encoded.digest(), image)
        .map_err(|_| Error::Profile)?;
    Ok(encoded)
}
