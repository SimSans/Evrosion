//! Canonical V5 producer inputs name full generation identities. Encoding is
//! descriptive; actual retained source roots and custody are resolved at bind.
pub use crate::root_producer_v2::{Error, Identity, SourceIdentity};
use crate::{root_manifest_v2, root_manifest_v5};
use ev_userspace_contract::root_v5;
use sha2::{Digest, Sha256};
/// Closed actual factory rights. Logical role IDs confer no backing authority.
pub fn source_rights(role: root_v5::Role) -> crate::capability::Rights {
    let spec = root_v5::ROLES[role.selector() as usize - 1];
    let bits = match spec.kind {
        1 if root_v5::graph::IMAGES.into_iter().any(|s| s.role() == role) => 481,
        1 | 8 => 487,
        7 => 483,
        _ => spec.rights | 480,
    };
    crate::capability::Rights::from_bits(bits).unwrap()
}
/// Metadata dry-run through a fresh actual selected Authority, not invented
/// ordinals or physical source provenance. Boot independently realizes and
/// resolves every full source identity before admitting any Root instruction.
pub fn planned_identities() -> Result<[Identity; root_v5::CURRENT_GRANTS], Error> {
    use crate::capability::{Authority, Rights};
    let mut a = Authority::for_workspace_profile();
    let custody = a
        .create_workspace_control_space()
        .map_err(|_| Error::Profile)?;
    a.create_workspace_control_space()
        .map_err(|_| Error::Profile)?;
    a.create_workspace_control_space()
        .map_err(|_| Error::Profile)?;
    let mut identities = [Identity {
        object: 0,
        lineage: 0,
    }; root_v5::CURRENT_GRANTS];
    for (i, spec) in root_v5::ROLES.into_iter().enumerate() {
        let kind = root_manifest_v2::kind(spec.kind).ok_or(Error::Kind)?;
        let cap = a
            .create_root(custody, kind, source_rights(spec.role))
            .map_err(|_| Error::Profile)?;
        let actual = a
            .authorize(custody, cap, kind, Rights::DERIVE)
            .map_err(|_| Error::Profile)?;
        identities[i] = Identity {
            object: actual.identity() as u64,
            lineage: actual.lineage_root() as u64,
        };
    }
    Ok(identities)
}
/// Source-independent shared image shape; the two Editors share this digest.
pub fn role_shape_digest(slot: root_v5::graph::ImageSlot) -> [u8; 32] {
    let child = slot.representative();
    let mut h = Sha256::new();
    h.update(b"evrosion.workspace.roles.v5\0");
    h.update(root_v5::ABI);
    h.update(root_v5::child::abi(child));
    h.update((slot.index() as u64).to_le_bytes());
    h.update((root_v5::graph::grants(child).len() as u64).to_le_bytes());
    for (i, g) in root_v5::graph::grants(child).enumerate() {
        h.update((i as u64 + 1).to_le_bytes());
        h.update([g.kind]);
        h.update(g.rights.to_le_bytes());
    }
    h.finalize().into()
}
/// Logical per-instance sources are measured here; actual full object identities
/// are separately joined by the runtime's captured authority/delegation gate.
pub fn instance_binding_digest(child: root_v5::graph::Child) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"evrosion.workspace.instance.v5\0");
    h.update(root_v5::ABI);
    h.update(root_v5::child::abi(child));
    for v in [
        child.index() as u64,
        child.image_slot().index() as u64,
        u64::from(child.instance()),
        root_v5::graph::grants(child).len() as u64,
    ] {
        h.update(v.to_le_bytes());
    }
    for (i, g) in root_v5::graph::grants(child).enumerate() {
        h.update((i as u64 + 1).to_le_bytes());
        h.update([g.kind]);
        h.update(g.rights.to_le_bytes());
        match g.source {
            root_v5::graph::Source::Root(role) => {
                h.update([1]);
                h.update(role.selector().to_le_bytes());
            }
            root_v5::graph::Source::Endpoint(channel) => {
                h.update([2]);
                h.update((channel.index() as u64).to_le_bytes());
            }
        }
    }
    h.finalize().into()
}
pub struct Description {
    entries: [SourceIdentity; root_v5::CURRENT_GRANTS],
    attempts: u8,
    window: u64,
    catalogue: Option<[u8; 32]>,
}
impl Description {
    pub fn full_graph(
        limits: [u64; 4],
        attempts: u8,
        window: u64,
        identities: [Identity; root_v5::CURRENT_GRANTS],
    ) -> Result<Self, Error> {
        if limits != root_v5::ROOT_LIMITS
            || limits[2] > crate::scheduler::MAX_PROCESSES as u64
            || limits[3] > crate::scheduler::MAX_THREADS as u64
        {
            return Err(Error::Limits);
        }
        crate::restart::Policy::new(attempts, window).map_err(|_| Error::Restart)?;
        let mut entries = [None; root_v5::CURRENT_GRANTS];
        for (i, role) in root_v5::ROLES.into_iter().enumerate() {
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
        hash.update(root_manifest_v5::AUTHORITY_DOMAIN);
        hash.update(root_v5::ABI);
        hash.update((root_v5::SIZE as u64).to_le_bytes());
        hash.update(root_v5::PROFILE.to_le_bytes());
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
    bytes: [u8; root_v5::MANIFEST_CURRENT_BYTES],
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
    let bytes = root_v5::manifest_profile(root_v5::ManifestInputs {
        root_image: Sha256::digest(image).into(),
        catalogue: description.catalogue.ok_or(Error::Catalogue)?,
        authority: description.authority_digest(),
        restart_attempts: description.attempts,
        restart_window: description.window,
    })
    .map_err(|_| Error::Profile)?;
    let encoded = Encoded { bytes };
    root_manifest_v5::verify(encoded.bytes(), encoded.digest(), image)
        .map_err(|_| Error::Profile)?;
    Ok(encoded)
}
/// Actual complete optional ingress bytes must match the measured canonical
/// record. This grants no execution, installation or package trust authority.
pub fn verify_external_ingress(
    catalogue: &root_v5::catalogue::Catalogue<'_>,
    bytes: Option<&[u8]>,
) -> Result<(), Error> {
    ingress_bytes(
        catalogue.external_ingress(),
        root_v5::catalogue::PACKAGES.map(|kind| catalogue.package(kind)),
        bytes,
    )
}
fn ingress_bytes(
    expected: Option<root_v5::catalogue::ExternalIngress>,
    packages: [root_v5::catalogue::Package; 4],
    bytes: Option<&[u8]>,
) -> Result<(), Error> {
    match (expected, bytes) {
        (None, None) => Ok(()),
        (Some(ingress), Some(bytes)) => {
            ingress.validate(packages).map_err(|_| Error::Catalogue)?;
            if bytes.len() as u64 != ingress.package.bytes
                || <[u8; 32]>::from(Sha256::digest(bytes)) != ingress.package.digest
            {
                return Err(Error::Catalogue);
            }
            let role = root_v5::ROLES
                .iter()
                .find(|spec| spec.role == root_v5::Role::PackageCandidate)
                .ok_or(Error::Rights)?;
            if role.kind != 1 || role.rights != 5 {
                return Err(Error::Rights);
            }
            Ok(())
        }
        _ => Err(Error::Catalogue),
    }
}
#[cfg(test)]
mod ingress_tests {
    use super::*;
    use root_v5::catalogue::{ExternalIngress, IngressProvenance, Package, PackageBank};
    fn fixture() -> ([Package; 4], ExternalIngress, [u8; 32]) {
        let bytes = [71; 32];
        let packages = core::array::from_fn(|index| Package {
            app_id: [index as u8 + 1; 16],
            digest: [index as u8 + 11; 32],
            build: [21; 32],
            image: [31; 32],
            bytes: 16,
            bank: if index == 3 {
                PackageBank::Candidate
            } else {
                PackageBank::Current
            },
            offset: if index == 3 { 0 } else { index as u32 * 16 },
        });
        let expected = ExternalIngress {
            package: Package {
                app_id: [99; 16],
                digest: Sha256::digest(bytes).into(),
                build: [51; 32],
                image: [61; 32],
                bytes: 32,
                bank: PackageBank::Candidate,
                offset: 16,
            },
            provenance: IngressProvenance::LocalOwnerDevelopment,
        };
        (packages, expected, bytes)
    }
    #[test]
    fn absent_and_present_bytes_join_without_executing_or_widening_candidate_rights() {
        let (packages, expected, bytes) = fixture();
        assert_eq!(ingress_bytes(None, packages, None), Ok(()));
        assert_eq!(
            ingress_bytes(Some(expected), packages, Some(&bytes)),
            Ok(())
        );
        assert_eq!(root_v5::CURRENT_GRANTS, 37);
    }
    #[test]
    fn missing_unexpected_truncated_and_tampered_blob_refuse() {
        let (packages, expected, bytes) = fixture();
        assert_eq!(
            ingress_bytes(Some(expected), packages, None),
            Err(Error::Catalogue)
        );
        assert_eq!(
            ingress_bytes(None, packages, Some(&bytes)),
            Err(Error::Catalogue)
        );
        assert_eq!(
            ingress_bytes(Some(expected), packages, Some(&bytes[..31])),
            Err(Error::Catalogue)
        );
        let mut bad = bytes;
        bad[31] ^= 1;
        assert_eq!(
            ingress_bytes(Some(expected), packages, Some(&bad)),
            Err(Error::Catalogue)
        );
    }
    #[test]
    fn mismatched_record_alias_overlap_and_bank_crossing_refuse_before_backing() {
        let (packages, expected, bytes) = fixture();
        for mutation in 0..5 {
            let mut bad = expected;
            match mutation {
                0 => bad.package.digest = [1; 32],
                1 => bad.package.app_id = packages[3].app_id,
                2 => bad.package.offset = 0,
                3 => bad.package.bank = PackageBank::Current,
                4 => bad.package.bytes = PackageBank::Candidate.capacity_bytes(),
                _ => unreachable!(),
            }
            assert_eq!(
                ingress_bytes(Some(bad), packages, Some(&bytes)),
                Err(Error::Catalogue)
            );
        }
    }
}
