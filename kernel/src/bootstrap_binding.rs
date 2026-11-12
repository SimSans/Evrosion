//! Resolve a measured manifest against kernel-held live roots and atomically
//! derive the exact authority set. Not a sealed BAC or supervisor activation.
use crate::{
    bootstrap_manifest::{Constraint, MAX_GRANTS, Manifest},
    capability::{
        self, Authority, Derivation, GrantBatch, Handle, Kind, Rights, ScopedGrants, SpaceId,
    },
};
use sha2::{Digest, Sha256};

/// Trusted boot catalog entry. The selector is descriptive; the source handle
/// must independently authorize lookup in the supplied kernel custody space.
#[derive(Clone, Copy)]
pub struct CatalogEntry {
    pub selector: u64,
    pub root: Handle,
    pub kind: Kind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    RootV2(crate::root_binding_v2::Error),
    Catalog,
    Alias,
    NotRoot,
    MissingSelector,
    UnsupportedConstraint,
    AuthorityDigest,
    Authority(capability::Error),
}
impl From<capability::Error> for Error {
    fn from(value: capability::Error) -> Self {
        Self::Authority(value)
    }
}
pub struct Installed {
    pub digest: [u8; 32],
    pub grants: GrantBatch,
}

/// The exclusive Authority borrow spans resolution, digest comparison and batch
/// installation, preventing revocation or catalog-object changes between checks.
/// Caller must separately validate executable selection and never schedule an
/// incomplete incarnation. Catalog data itself confers no rights.
pub fn install(
    authority: &mut Authority,
    custody: SpaceId,
    destination: SpaceId,
    catalog: &[CatalogEntry],
    manifest: &Manifest<'_>,
) -> Result<Installed, Error> {
    let (digest, requests, count) = resolve(authority, custody, catalog, manifest)?;
    let grants = authority.derive_into_empty(custody, destination, &requests[..count])?;
    Ok(Installed { digest, grants })
}
/// Measured installation with kernel-held per-object revocation branches. The
/// branch domain must never be exposed to userspace. This is a precursor to BAC;
/// executable/process/job binding and quiescence remain the lifecycle's duty.
pub fn install_scoped(
    authority: &mut Authority,
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
    catalog: &[CatalogEntry],
    manifest: &Manifest<'_>,
) -> Result<ScopedInstalled, Error> {
    let (digest, requests, count) = resolve(authority, custody, catalog, manifest)?;
    let grants =
        authority.derive_scoped_into_empty(custody, branches, destination, &requests[..count])?;
    Ok(ScopedInstalled { digest, grants })
}
pub struct ScopedInstalled {
    pub digest: [u8; 32],
    pub grants: ScopedGrants,
}
/// Revalidate the complete measured set and both exact branch relations under
/// one immutable Authority borrow before scheduler admission can be committed.
pub(crate) struct InstalledView<'a> {
    pub branches: SpaceId,
    pub destination: SpaceId,
    pub private: &'a [Handle],
    pub grants: &'a [Handle],
}
pub(crate) fn revalidate(
    authority: &Authority,
    custody: SpaceId,
    catalog: &[CatalogEntry],
    manifest: &Manifest<'_>,
    set: InstalledView<'_>,
) -> Result<(), Error> {
    let InstalledView {
        branches,
        destination,
        private,
        grants,
    } = set;
    let (_, requests, count) = resolve(authority, custody, catalog, manifest)?;
    if private.len() != count || grants.len() != count {
        return Err(Error::AuthorityDigest);
    }
    authority.require_exact_handles(branches, private)?;
    authority.require_exact_handles(destination, grants)?;
    for (i, request) in requests[..count].iter().enumerate() {
        authority.require_child(
            branches,
            private[i],
            custody,
            request.source,
            request.kind,
            request.rights | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
        )?;
        authority.require_child(
            destination,
            grants[i],
            branches,
            private[i],
            request.kind,
            request.rights,
        )?;
    }
    Ok(())
}
fn resolve(
    authority: &Authority,
    custody: SpaceId,
    catalog: &[CatalogEntry],
    manifest: &Manifest<'_>,
) -> Result<([u8; 32], [Derivation; MAX_GRANTS], usize), Error> {
    if catalog.is_empty() || catalog.len() > MAX_GRANTS {
        return Err(Error::Catalog);
    }
    let mut identities = [0; MAX_GRANTS];
    let mut previous = 0;
    for (i, entry) in catalog.iter().enumerate() {
        if entry.selector <= previous {
            return Err(Error::Catalog);
        }
        previous = entry.selector;
        let access = authority.authorize(
            custody,
            entry.root,
            entry.kind,
            Rights::DERIVE | Rights::TRANSFER,
        )?;
        if !access.is_root() {
            return Err(Error::NotRoot);
        }
        if identities[..i].contains(&access.identity()) {
            return Err(Error::Alias);
        }
        identities[i] = access.identity();
    }
    let mut requests = [Derivation {
        source: Handle(0),
        kind: Kind::Job,
        rights: Rights::READ,
    }; MAX_GRANTS];
    let count = manifest.grants().count();
    let mut hash = Sha256::new();
    hash.update(b"evrosion.bootstrap.authority.v1\0");
    hash.update((count as u64).to_le_bytes());
    for (i, grant) in manifest.grants().enumerate() {
        // The current capability/mapping mechanisms do not enforce subranges.
        // Reject before any mutation rather than dropping the measured constraint.
        if grant.constraint != Constraint::WholeObject {
            return Err(Error::UnsupportedConstraint);
        }
        let source = catalog
            .iter()
            .find(|e| e.selector == grant.selector.value())
            .ok_or(Error::MissingSelector)?;
        let access = authority.authorize(
            custody,
            source.root,
            grant.kind,
            Rights::DERIVE | Rights::TRANSFER | grant.rights,
        )?;
        let kind = match access.kind() {
            Kind::Memory => 1u8,
            Kind::Endpoint => 2,
            Kind::Process => 3,
            Kind::Thread => 4,
            Kind::Job => 5,
            Kind::Mutex => 6,
            Kind::IoPorts => 7,
            Kind::Display => 8,
        };
        hash.update(grant.selector.value().to_le_bytes());
        hash.update([kind]);
        hash.update((access.identity() as u64).to_le_bytes());
        hash.update((access.lineage_root() as u64).to_le_bytes());
        hash.update(grant.rights.bits().to_le_bytes());
        hash.update([0]); // WholeObject constraint tag
        hash.update(0u64.to_le_bytes()); // start
        hash.update(0u64.to_le_bytes()); // length
        requests[i] = Derivation {
            source: source.root,
            kind: grant.kind,
            rights: grant.rights,
        };
    }
    let digest: [u8; 32] = hash.finalize().into();
    if digest != manifest.expected_authority_digest() {
        return Err(Error::AuthorityDigest);
    }
    Ok((digest, requests, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_manifest;
    const BYTES: &[u8; 232] = include_bytes!("../fixtures/bootstrap-whole-object-v1.bin");
    fn manifest(b: &[u8]) -> Manifest<'_> {
        bootstrap_manifest::verify(b, Sha256::digest(b).into(), b"abc", [42; 32]).unwrap()
    }
    fn setup() -> (Authority, SpaceId, SpaceId, [CatalogEntry; 2]) {
        let mut a = Authority::new();
        let s = a.create_space().unwrap();
        let d = a.create_space().unwrap();
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL;
        let memory = a
            .create_root(s, Kind::Memory, common | Rights::READ | Rights::WRITE)
            .unwrap();
        let endpoint = a
            .create_root(s, Kind::Endpoint, common | Rights::SEND)
            .unwrap();
        (
            a,
            s,
            d,
            [
                CatalogEntry {
                    selector: 1,
                    root: memory,
                    kind: Kind::Memory,
                },
                CatalogEntry {
                    selector: 2,
                    root: endpoint,
                    kind: Kind::Endpoint,
                },
            ],
        )
    }
    #[test]
    fn revalidation_rejects_equal_objects_with_wrong_lineage_or_amplified_rights() {
        for amplified in [false, true] {
            let (mut a, s, d, c) = setup();
            let branches = a.create_space().unwrap();
            let m = manifest(BYTES);
            let requests = [
                Derivation {
                    source: c[0].root,
                    kind: Kind::Memory,
                    rights: if amplified {
                        Rights::READ | Rights::WRITE
                    } else {
                        Rights::READ
                    },
                },
                Derivation {
                    source: c[1].root,
                    kind: Kind::Endpoint,
                    rights: Rights::SEND,
                },
            ];
            let scoped = a
                .derive_scoped_into_empty(s, branches, d, &requests)
                .unwrap();
            if amplified {
                assert_eq!(
                    revalidate(
                        &a,
                        s,
                        &c,
                        &m,
                        InstalledView {
                            branches,
                            destination: d,
                            private: scoped.branches.handles(),
                            grants: scoped.grants.handles()
                        }
                    )
                    .err(),
                    Some(Error::Authority(capability::Error::Denied))
                );
            } else {
                let foreign = a.create_space().unwrap();
                let direct = a.derive_into_empty(s, foreign, &requests).unwrap();
                assert_eq!(
                    revalidate(
                        &a,
                        s,
                        &c,
                        &m,
                        InstalledView {
                            branches,
                            destination: foreign,
                            private: scoped.branches.handles(),
                            grants: direct.handles()
                        }
                    )
                    .err(),
                    Some(Error::Authority(capability::Error::Denied))
                );
                assert!(
                    revalidate(
                        &a,
                        s,
                        &c,
                        &m,
                        InstalledView {
                            branches,
                            destination: d,
                            private: scoped.branches.handles(),
                            grants: scoped.grants.handles()
                        }
                    )
                    .is_ok()
                );
            }
        }
    }
    #[test]
    fn scoped_binding_preserves_measured_digest_and_original_custody_roots() {
        let (mut a, s, d, c) = setup();
        let branches = a.create_space().unwrap();
        let manifest = manifest(BYTES);
        let installed = install_scoped(&mut a, s, branches, d, &c, &manifest).unwrap();
        assert_eq!(installed.digest, manifest.expected_authority_digest());
        a.revoke_batch(branches, installed.grants.branches.handles())
            .unwrap();
        for (i, grant) in manifest.grants().enumerate() {
            assert_eq!(
                a.authorize(
                    d,
                    installed.grants.grants.handles()[i],
                    grant.kind,
                    grant.rights
                )
                .err(),
                Some(capability::Error::Revoked)
            );
            assert!(a.authorize(s, c[i].root, grant.kind, grant.rights).is_ok());
        }
        a.close_space(d).unwrap();
        a.close_space(branches).unwrap();
        assert_eq!(a.collect_lineage(), Ok(4));
        let d = a.recycle_space(d).unwrap();
        let branches = a.recycle_space(branches).unwrap();
        assert_eq!(
            install_scoped(&mut a, s, branches, d, &c, &manifest)
                .unwrap()
                .digest,
            installed.digest
        );
    }
    #[test]
    fn scoped_digest_mismatch_leaves_both_domains_empty_for_valid_retry() {
        let (mut a, s, d, c) = setup();
        let branches = a.create_space().unwrap();
        let mut wrong = *BYTES;
        wrong[128] ^= 1;
        assert_eq!(
            install_scoped(&mut a, s, branches, d, &c, &manifest(&wrong)).err(),
            Some(Error::AuthorityDigest)
        );
        assert!(install_scoped(&mut a, s, branches, d, &c, &manifest(BYTES)).is_ok());
    }
    #[test]
    fn actual_object_digest_matches_independent_fixture_and_grants_only_requested_rights() {
        let (mut a, s, d, c) = setup();
        let manifest = manifest(BYTES);
        let installed = install(&mut a, s, d, &c, &manifest).unwrap();
        assert_eq!(installed.digest, manifest.expected_authority_digest());
        let h = installed.grants.handles();
        assert_eq!(h.len(), 2);
        assert!(a.authorize(d, h[0], Kind::Memory, Rights::READ).is_ok());
        assert_eq!(
            a.authorize(d, h[0], Kind::Memory, Rights::WRITE).err(),
            Some(capability::Error::Denied)
        );
        assert_eq!(
            a.derive(d, h[0], s, Rights::READ),
            Err(capability::Error::Denied)
        );
        a.revoke(s, c[0].root).unwrap();
        assert_eq!(
            a.authorize(d, h[0], Kind::Memory, Rights::READ).err(),
            Some(capability::Error::Revoked)
        );
        assert!(a.authorize(d, h[1], Kind::Endpoint, Rights::SEND).is_ok());
    }
    #[test]
    fn authority_digest_mismatch_installs_nothing_and_valid_retry_succeeds() {
        let (mut a, s, d, c) = setup();
        let mut b = *BYTES;
        b[128] ^= 1;
        assert_eq!(
            install(&mut a, s, d, &c, &manifest(&b)).err(),
            Some(Error::AuthorityDigest)
        );
        assert!(install(&mut a, s, d, &c, &manifest(BYTES)).is_ok());
    }
    #[test]
    fn live_object_substitution_is_detected_even_with_matching_kind_and_rights() {
        let (mut a, s, d, mut c) = setup();
        c[0].root = a
            .create_root(
                s,
                Kind::Memory,
                Rights::READ | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        assert_eq!(
            install(&mut a, s, d, &c, &manifest(BYTES)).err(),
            Some(Error::AuthorityDigest)
        );
    }
    #[test]
    fn unsupported_range_missing_selector_and_late_rights_failure_never_partially_install() {
        let (mut a, s, d, c) = setup();
        let mut b = *BYTES;
        b[192..200].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(
            install(&mut a, s, d, &c, &manifest(&b)).err(),
            Some(Error::UnsupportedConstraint)
        );
        assert_eq!(
            install(&mut a, s, d, &c[..1], &manifest(BYTES)).err(),
            Some(Error::MissingSelector)
        );
        b = *BYTES;
        b[210] = 16; // valid Endpoint RECEIVE, absent from custody root
        assert_eq!(
            install(&mut a, s, d, &c, &manifest(&b)).err(),
            Some(Error::Authority(capability::Error::Denied))
        );
        assert!(install(&mut a, s, d, &c, &manifest(BYTES)).is_ok());
    }
    #[test]
    fn catalog_rejects_aliases_unsorted_duplicates_and_non_root_sources() {
        let (mut a, s, d, c) = setup();
        for entries in [[c[1], c[0]], [c[0], c[0]]] {
            assert_eq!(
                install(&mut a, s, d, &entries, &manifest(BYTES)).err(),
                Some(Error::Catalog)
            );
        }
        let mut alias = c;
        alias[1].root = c[0].root;
        alias[1].kind = Kind::Memory;
        assert_eq!(
            install(&mut a, s, d, &alias, &manifest(BYTES)).err(),
            Some(Error::Alias)
        );
        let mut branch = c;
        branch[0].root = a
            .derive(
                s,
                c[0].root,
                s,
                Rights::READ | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        assert_eq!(
            install(&mut a, s, d, &branch, &manifest(BYTES)).err(),
            Some(Error::NotRoot)
        );
        assert!(install(&mut a, s, d, &c, &manifest(BYTES)).is_ok());
    }
    #[test]
    fn revoked_closed_and_wrong_kind_catalog_entries_are_rejected() {
        let (mut a, s, d, c) = setup();
        let mut wrong = c;
        wrong[1].kind = Kind::Memory;
        assert_eq!(
            install(&mut a, s, d, &wrong, &manifest(BYTES)).err(),
            Some(Error::Authority(capability::Error::WrongKind))
        );
        a.revoke(s, c[1].root).unwrap();
        assert_eq!(
            install(&mut a, s, d, &c, &manifest(BYTES)).err(),
            Some(Error::Authority(capability::Error::Revoked))
        );
        a.close_space(s).unwrap();
        assert_eq!(
            install(&mut a, s, d, &c, &manifest(BYTES)).err(),
            Some(Error::Authority(capability::Error::InvalidSpace))
        );
    }
}

#[cfg(test)]
mod mutex_canonical_tests {
    use super::*;
    #[test]
    fn mutex_wire_tag_is_hashed_and_granted_as_its_exact_distinct_kind() {
        let mut a = Authority::new();
        let custody = a.create_space().unwrap();
        let root = a
            .create_root(
                custody,
                Kind::Mutex,
                Rights::CONTROL | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
            )
            .unwrap();
        let mut bytes = [0u8; 200];
        bytes.copy_from_slice(&include_bytes!("../fixtures/bootstrap-static-v1.bin")[..200]);
        bytes[160] = 1;
        bytes[176] = 6;
        bytes[178..180].copy_from_slice(&Rights::CONTROL.bits().to_le_bytes());
        let mut digest = Sha256::new();
        digest.update(b"evrosion.bootstrap.authority.v1\0");
        digest.update(1u64.to_le_bytes());
        digest.update(1u64.to_le_bytes());
        digest.update([6]);
        digest.update(0u64.to_le_bytes());
        digest.update(0u64.to_le_bytes());
        digest.update(Rights::CONTROL.bits().to_le_bytes());
        digest.update([0]);
        digest.update(0u64.to_le_bytes());
        digest.update(0u64.to_le_bytes());
        let expected: [u8; 32] = digest.finalize().into();
        bytes[128..160].copy_from_slice(&expected);
        let image = include_bytes!("../fixtures/bootstrap-static-v1.elf");
        let manifest = crate::bootstrap_manifest::verify(
            &bytes,
            Sha256::digest(bytes).into(),
            image,
            [42; 32],
        )
        .unwrap();
        let branches = a.create_space().unwrap();
        let destination = a.create_space().unwrap();
        let installed = install_scoped(
            &mut a,
            custody,
            branches,
            destination,
            &[CatalogEntry {
                selector: 1,
                root,
                kind: Kind::Mutex,
            }],
            &manifest,
        )
        .unwrap();
        assert_eq!(installed.digest, expected);
        let grant = installed.grants.grants.handles()[0];
        assert!(
            a.authorize(destination, grant, Kind::Mutex, Rights::CONTROL)
                .is_ok()
        );
        assert_eq!(
            a.authorize(destination, grant, Kind::Memory, Rights::READ)
                .err(),
            Some(capability::Error::WrongKind)
        );
    }
}
