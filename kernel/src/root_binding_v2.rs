//! Live source validation and atomic branch derivation, never catalogue minting.
use crate::{
    capability::{self, Authority, Derivation, Handle, Kind, Rights, ScopedGrants, SpaceId},
    root_manifest_v2::{CurrentRoot, Manifest, NativeRoot, kind_tag},
};
use ev_userspace_contract::root_v2;
use sha2::{Digest, Sha256};
#[derive(Clone, Copy)]
pub(crate) struct Source {
    pub selector: u64,
    pub handle: Handle,
    pub kind: Kind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Sources,
    Alias,
    NotRoot,
    Measurement,
    Capacity,
    Record,
    Authority(capability::Error),
}
impl From<capability::Error> for Error {
    fn from(e: capability::Error) -> Self {
        Self::Authority(e)
    }
}
struct Resolved<const N: usize> {
    requests: [Derivation; N],
    count: usize,
    digest: [u8; 32],
}
pub(crate) struct Installed {
    pub digest: [u8; 32],
    pub grants: ScopedGrants,
}
/// Full generation identities, rooted lineage and exact measured roles are
/// hashed while actual Authority is borrowed. Catalog integers cannot authorize.
fn resolve<const N: usize>(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source],
    manifest: &Manifest<'_>,
) -> Result<Resolved<N>, Error> {
    let count = manifest.grants().count();
    if sources.len() != count || count > N {
        return Err(Error::Sources);
    }
    let mut previous = 0;
    let mut identities = [0; N];
    for (i, s) in sources.iter().enumerate() {
        if s.selector <= previous {
            return Err(Error::Sources);
        }
        previous = s.selector;
        let access = a.authorize(custody, s.handle, s.kind, Rights::DERIVE | Rights::TRANSFER)?;
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
        kind: Kind::Memory,
        rights: Rights::READ,
    }; N];
    let mut hash = Sha256::new();
    hash.update(manifest.authority_domain());
    hash.update(manifest.abi_fingerprint());
    hash.update((manifest.startup_bytes() as u64).to_le_bytes());
    hash.update(manifest.profile().to_le_bytes());
    hash.update((count as u64).to_le_bytes());
    for (i, (grant, source)) in manifest.grants().zip(sources).enumerate() {
        if source.selector != grant.selector || source.kind != grant.kind {
            return Err(Error::Sources);
        }
        let access = a.authorize(
            custody,
            source.handle,
            grant.kind,
            Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | grant.rights,
        )?;
        hash.update(grant.selector.to_le_bytes());
        hash.update([kind_tag(access.kind())]);
        hash.update((access.identity() as u64).to_le_bytes());
        hash.update((access.lineage_root() as u64).to_le_bytes());
        hash.update(grant.rights.bits().to_le_bytes());
        hash.update([0]);
        hash.update(0u64.to_le_bytes());
        hash.update(0u64.to_le_bytes());
        requests[i] = Derivation {
            source: source.handle,
            kind: grant.kind,
            rights: grant.rights,
        };
    }
    let digest = hash.finalize().into();
    if digest != manifest.expected_authority_digest() {
        return Err(Error::Measurement);
    }
    Ok(Resolved {
        requests,
        count,
        digest,
    })
}
/// All sources are trusted retained factories' handles in custody. Target must
/// be the actual held Root token's private branches/user domains. This operation
/// installs grants ONLY; it never releases Scheduler admission or creates a BAC.
/// Existing16-cap Authority honestly refuses18 before mutation. No fake success.
pub(crate) fn install(
    a: &mut Authority,
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
    sources: &[Source],
    manifest: &CurrentRoot<'_>,
) -> Result<Installed, Error> {
    install_manifest::<{ root_v2::MAX_GRANTS }>(
        a,
        custody,
        branches,
        destination,
        sources,
        manifest.manifest(),
    )
}
pub(crate) fn install_native(
    a: &mut Authority,
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
    sources: &[Source],
    manifest: &NativeRoot<'_>,
) -> Result<Installed, Error> {
    install_manifest::<{ root_v2::MAX_GRANTS }>(
        a,
        custody,
        branches,
        destination,
        sources,
        manifest.manifest(),
    )
}
pub(crate) fn install_v4(
    a: &mut Authority,
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
    sources: &[Source],
    manifest: &crate::root_manifest_v4::CurrentRoot<'_>,
) -> Result<Installed, Error> {
    install_manifest::<{ ev_userspace_contract::root_v4::MAX_GRANTS }>(
        a,
        custody,
        branches,
        destination,
        sources,
        manifest.manifest(),
    )
}
fn install_manifest<const N: usize>(
    a: &mut Authority,
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
    sources: &[Source],
    manifest: &Manifest<'_>,
) -> Result<Installed, Error> {
    let count = manifest.grants().count();
    if count > a.slot_capacity(branches)? || count > a.slot_capacity(destination)? {
        return Err(Error::Capacity);
    }
    let p = resolve::<N>(a, custody, sources, manifest)?;
    let grants =
        a.derive_scoped_into_empty(custody, branches, destination, &p.requests[..p.count])?;
    Ok(Installed {
        digest: p.digest,
        grants,
    })
}
/// The selected typed graph requires real96-slot custody/branch/Root banks.
/// Compiled array headroom or a legacy64-slot control bank cannot enable it.
#[cfg(feature = "workspace-authority")]
fn workspace_banks(a: &Authority, spaces: &[SpaceId]) -> Result<(), Error> {
    for &space in spaces {
        if a.slot_capacity(space)? != ev_userspace_contract::root_v5::resources::ROOT_HANDLES {
            return Err(Error::Capacity);
        }
    }
    Ok(())
}
#[cfg(feature = "workspace-authority")]
pub(crate) fn install_v5(
    a: &mut Authority,
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
    sources: &[Source],
    manifest: &crate::root_manifest_v5::CurrentRoot<'_>,
) -> Result<Installed, Error> {
    workspace_banks(a, &[custody, branches, destination])?;
    install_manifest::<{ ev_userspace_contract::root_v5::MAX_GRANTS }>(
        a,
        custody,
        branches,
        destination,
        sources,
        manifest.manifest(),
    )
}
#[cfg(feature = "workspace-authority")]
pub(crate) fn revalidate_v5(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source],
    manifest: &crate::root_manifest_v5::CurrentRoot<'_>,
    view: crate::bootstrap_binding::InstalledView<'_>,
) -> Result<(), Error> {
    workspace_banks(a, &[custody, view.branches, view.destination])?;
    revalidate_manifest::<{ ev_userspace_contract::root_v5::MAX_GRANTS }>(
        a,
        custody,
        sources,
        manifest.manifest(),
        view,
    )
}
/// Check both actual branch relations immediately before the SAME lifecycle
/// admission gate. Revocation/stale handles/extra table grants all fail closed.
pub(crate) fn revalidate(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source],
    manifest: &CurrentRoot<'_>,
    view: crate::bootstrap_binding::InstalledView<'_>,
) -> Result<(), Error> {
    revalidate_manifest::<{ root_v2::MAX_GRANTS }>(a, custody, sources, manifest.manifest(), view)
}
pub(crate) fn revalidate_native(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source],
    manifest: &NativeRoot<'_>,
    view: crate::bootstrap_binding::InstalledView<'_>,
) -> Result<(), Error> {
    revalidate_manifest::<{ root_v2::MAX_GRANTS }>(a, custody, sources, manifest.manifest(), view)
}
pub(crate) fn revalidate_v4(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source],
    manifest: &crate::root_manifest_v4::CurrentRoot<'_>,
    view: crate::bootstrap_binding::InstalledView<'_>,
) -> Result<(), Error> {
    revalidate_manifest::<{ ev_userspace_contract::root_v4::MAX_GRANTS }>(
        a,
        custody,
        sources,
        manifest.manifest(),
        view,
    )
}
fn revalidate_manifest<const N: usize>(
    a: &Authority,
    custody: SpaceId,
    sources: &[Source],
    manifest: &Manifest<'_>,
    view: crate::bootstrap_binding::InstalledView<'_>,
) -> Result<(), Error> {
    let plan = resolve::<N>(a, custody, sources, manifest)?;
    if view.private.len() != plan.count || view.grants.len() != plan.count {
        return Err(Error::Record);
    }
    a.require_exact_handles(view.branches, view.private)?;
    a.require_exact_handles(view.destination, view.grants)?;
    for (i, request) in plan.requests[..plan.count].iter().enumerate() {
        a.require_child(
            view.branches,
            view.private[i],
            custody,
            request.source,
            request.kind,
            request.rights | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
        )?;
        a.require_child(
            view.destination,
            view.grants[i],
            view.branches,
            view.private[i],
            request.kind,
            request.rights,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_producer_v2::{Description, Identity, SourceIdentity, encode};
    fn source(a: &mut Authority, c: SpaceId, selector: u64, kind: Kind, rights: Rights) -> Source {
        Source {
            selector,
            kind,
            handle: a
                .create_root(
                    c,
                    kind,
                    rights | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
                )
                .unwrap(),
        }
    }
    fn description(a: &Authority, c: SpaceId, s: &[Source]) -> Description {
        let mut entries = [None; root_v2::MAX_GRANTS];
        for (i, x) in s.iter().enumerate() {
            let access = a.authorize(c, x.handle, x.kind, Rights::DERIVE).unwrap();
            entries[i] = Some(SourceIdentity {
                selector: x.selector,
                kind: x.kind,
                rights: if x.kind == Kind::Memory {
                    Rights::READ
                } else {
                    Rights::SEND
                },
                object: access.identity() as u64,
                lineage: access.lineage_root() as u64,
            });
        }
        Description::new(&entries[..s.len()], [4096, 256, 7, 7], 3, 60)
            .unwrap()
            .bind_catalogue([7; 32])
    }
    #[test]
    fn root_v2_real_source_resolution_rejects_forgery_revoke_alias_and_mismatch() {
        let mut a = Authority::new();
        let c = a.create_space().unwrap();
        let branch = a.create_space().unwrap();
        let d = a.create_space().unwrap();
        let sources = [
            source(&mut a, c, 1, Kind::Memory, Rights::READ),
            source(&mut a, c, 2, Kind::Endpoint, Rights::SEND),
        ];
        let desc = description(&a, c, &sources);
        let encoded = encode(b"image", &desc).unwrap();
        let m =
            crate::root_manifest_v2::verify(encoded.bytes(), encoded.digest(), b"image").unwrap();
        let before = a.metadata_usage();
        let p = resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &sources, &m).unwrap();
        assert_eq!(a.metadata_usage(), before);
        let installed = a
            .derive_scoped_into_empty(c, branch, d, &p.requests[..p.count])
            .unwrap();
        assert_eq!(installed.grants.handles().len(), 2);
        let before = a.metadata_usage();
        let mut forged = sources;
        forged[0].handle = Handle(u64::MAX);
        assert!(resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &forged, &m).is_err());
        assert_eq!(a.metadata_usage(), before);
        let mut alias = sources;
        alias[1].handle = sources[0].handle;
        alias[1].kind = Kind::Memory;
        assert!(matches!(
            resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &alias, &m),
            Err(Error::Alias)
        ));
        let mut wrong = sources;
        wrong.swap(0, 1);
        assert!(resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &wrong, &m).is_err());
        a.revoke(c, sources[0].handle).unwrap();
        assert!(resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &sources, &m).is_err());
    }
    #[test]
    fn root_v2_source_without_revoke_or_nonroot_is_not_sealed_custody() {
        let mut a = Authority::new();
        let c = a.create_space().unwrap();
        let other = a.create_space().unwrap();
        let root = a
            .create_root(
                c,
                Kind::Memory,
                Rights::READ | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let s = [Source {
            selector: 1,
            kind: Kind::Memory,
            handle: root,
        }];
        let desc = description(&a, c, &s);
        let e = encode(b"image", &desc).unwrap();
        let m = crate::root_manifest_v2::verify(e.bytes(), e.digest(), b"image").unwrap();
        assert!(resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &s, &m).is_err());
        let child = a
            .derive(
                c,
                root,
                other,
                Rights::READ | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let s = [Source {
            selector: 1,
            kind: Kind::Memory,
            handle: child,
        }];
        assert!(matches!(
            resolve::<{ root_v2::MAX_GRANTS }>(&a, other, &s, &m),
            Err(Error::NotRoot)
        ));
    }
    #[test]
    fn root_v2_recycled_same_kind_source_cannot_satisfy_old_generation_digest() {
        let mut a = Authority::new();
        let c = a.create_space().unwrap();
        let old = [source(
            &mut a,
            c,
            1,
            Kind::Memory,
            Rights::READ | Rights::CONTROL,
        )];
        let d = description(&a, c, &old);
        let e = encode(b"image", &d).unwrap();
        let m = crate::root_manifest_v2::verify(e.bytes(), e.digest(), b"image").unwrap();
        let old_id = a
            .authorize(c, old[0].handle, Kind::Memory, Rights::READ)
            .unwrap()
            .identity();
        a.destroy(c, old[0].handle).unwrap();
        a.close(c, old[0].handle).unwrap();
        a.collect_lineage().unwrap();
        a.collect_dead_objects().unwrap();
        let new = [source(&mut a, c, 1, Kind::Memory, Rights::READ)];
        let id = a
            .authorize(c, new[0].handle, Kind::Memory, Rights::READ)
            .unwrap()
            .identity();
        assert_ne!(old_id, id);
        assert_eq!(old_id & 255, id & 255);
        let before = a.metadata_usage();
        assert!(matches!(
            resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &new, &m),
            Err(Error::Measurement)
        ));
        assert_eq!(a.metadata_usage(), before);
        let d = description(&a, c, &new);
        let e = encode(b"image", &d).unwrap();
        let m = crate::root_manifest_v2::verify(e.bytes(), e.digest(), b"image").unwrap();
        assert!(resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &new, &m).is_ok());
    }
    #[test]
    fn root_v2_control_domains_install18_through_same_custodian_and_check_loaded_record() {
        use crate::{
            bootstrap_binding::CatalogEntry,
            custodian::Custodian,
            incarnation,
            loaded_image::{Information, LoadedExecutable, Startup},
            root_factory_v2::RootDomains,
            scheduler::Scheduler,
            service::Registry,
        };
        use core::num::NonZeroU64;
        struct Model(Information, bool);
        // SAFETY: host-only policy model. No real CR3/frame/page permission or
        // hardware Root execution is claimed; this implements only model facts.
        #[allow(unsafe_code)]
        unsafe impl LoadedExecutable for Model {
            fn information(&self) -> Information {
                self.0
            }
            fn layout(&self) -> crate::executable::LayoutReservation {
                if self.1 {
                    crate::executable::LayoutReservation::DisplayApertureV1
                } else {
                    crate::executable::LayoutReservation::Legacy
                }
            }
        }
        for corrupt in 0..6 {
            let mut a = Authority::new();
            let domains = RootDomains::allocate(&mut a).unwrap();
            let c = domains.custody();
            // Extra sealed custody objects do not enter Root's measured set.
            // Force CreatorJob's full object ID above the Registry row count.
            if corrupt == 0 {
                for _ in 0..20 {
                    a.create_root(c, Kind::Memory, Rights::READ).unwrap();
                }
            }
            let sources = core::array::from_fn::<_, { root_v2::CURRENT_GRANTS }, _>(|i| {
                let spec = root_v2::ROLES[i];
                let kind = match spec.kind {
                    1 => Kind::Memory,
                    2 => Kind::Endpoint,
                    5 => Kind::Job,
                    7 => Kind::IoPorts,
                    8 => Kind::Display,
                    _ => unreachable!(),
                };
                source(
                    &mut a,
                    c,
                    spec.role.selector(),
                    kind,
                    Rights::from_bits(spec.rights).unwrap(),
                )
            });
            let identities = core::array::from_fn(|i| {
                let access = a
                    .authorize(c, sources[i].handle, sources[i].kind, Rights::DERIVE)
                    .unwrap();
                Identity {
                    object: access.identity() as u64,
                    lineage: access.lineage_root() as u64,
                }
            });
            let desc = Description::full_graph([4096, 256, 7, 7], 3, 60, identities)
                .unwrap()
                .bind_catalogue([7; 32]);
            let e = crate::root_producer_v2::encode_current(
                include_bytes!("../fixtures/bootstrap-static-v1.elf"),
                &desc,
            )
            .unwrap();
            let m = crate::root_manifest_v2::verify(
                e.bytes(),
                e.digest(),
                include_bytes!("../fixtures/bootstrap-static-v1.elf"),
            )
            .unwrap()
            .current_profile()
            .unwrap();
            let mut scheduler = Scheduler::new();
            let job = scheduler
                .create_job_with_limits(m.manifest().limits())
                .unwrap();
            let process = scheduler.create_held_process(job).unwrap();
            let thread = scheduler.create_thread(process).unwrap();
            let (custody, target) = domains.into_target(process, job);
            let mut registry = Registry::new();
            registry
                .register_job(&a, custody, sources[6].handle, job)
                .unwrap();
            let catalog = sources.map(|s| CatalogEntry {
                selector: s.selector,
                root: s.handle,
                kind: s.kind,
            });
            let mut custodian =
                Custodian::new_root_v2(NonZeroU64::new(44).unwrap(), &m, custody, &catalog);
            let attempt = custodian.begin(0).unwrap();
            let (mut binding, token) = custodian
                .prepare(attempt, &mut a, &scheduler, target)
                .unwrap();
            let bytes = binding.bootstrap_record_v2(token).unwrap();
            let record = root_v2::FullGraph::parse(&bytes).unwrap();
            assert_eq!(record.context().process, process.diagnostic_id());
            assert_eq!(record.context().incarnation, 1);
            assert_eq!(binding.bootstrap_record(token).unwrap(), None);
            let plan = binding.executable(token).unwrap();
            scheduler
                .charge_frames(job, plan.required_frames())
                .unwrap();
            let mut information = Information {
                process,
                manifest: m.manifest().digest(),
                entry: plan.entry(),
                stack: plan.stack_top(),
                root: 4096,
                frames: plan.required_frames(),
                startup: Some(Startup {
                    address: plan.bootstrap_page().unwrap(),
                    bytes: root_v2::SIZE,
                    digest: Sha256::digest(bytes).into(),
                }),
            };
            match corrupt {
                1 => information.startup.as_mut().unwrap().bytes = 336,
                2 => information.startup.as_mut().unwrap().digest[0] ^= 1,
                3 => information.startup = None,
                4 => information.startup.as_mut().unwrap().address += 4096,
                _ => (),
            }
            let active = binding.activate(
                &a,
                &mut scheduler,
                token,
                thread,
                Model(information, corrupt == 5),
            );
            if corrupt == 0 {
                let active = active
                    .unwrap_or_else(|r| panic!("model RootV2 admission refused: {:?}", r.error));
                custodian.confirm_active(&active).unwrap();
                assert_eq!(scheduler.dispatch(0).unwrap().unwrap().process, process);
                assert!(custodian.begin(1).is_err());
            } else {
                let rejected = match active {
                    Err(r) => r,
                    Ok(_) => panic!("corrupt RootV2 record admitted"),
                };
                assert_eq!(rejected.error, incarnation::Error::ImageMismatch);
                custodian.report_failure(&rejected.binding).unwrap();
                assert!(custodian.begin(1).is_err());
                assert_eq!(scheduler.dispatch(0), Ok(None));
            }
        }
    }
    #[test]
    fn root_v2_control_batch24_is_real_but_not_current_full_graph_profile() {
        let mut a = Authority::new();
        let c = a.create_control_space().unwrap();
        let b = a.create_control_space().unwrap();
        let d = a.create_control_space().unwrap();
        let sources = core::array::from_fn::<_, { root_v2::MAX_GRANTS }, _>(|i| {
            source(&mut a, c, i as u64 + 1, Kind::Memory, Rights::READ)
        });
        let desc = description(&a, c, &sources);
        let e = encode(b"image", &desc).unwrap();
        let m = crate::root_manifest_v2::verify(e.bytes(), e.digest(), b"image").unwrap();
        let p = resolve::<{ root_v2::MAX_GRANTS }>(&a, c, &sources, &m).unwrap();
        let grants = a
            .derive_scoped_into_empty(c, b, d, &p.requests[..p.count])
            .unwrap();
        assert_eq!(grants.grants.handles().len(), 24);
        assert_eq!(a.slot_capacity(d), Ok(64));
        assert!(m.current_profile().is_err());
    }
    #[test]
    fn root_v2_complete18_is_truthfully_capacity_rejected_without_mutation() {
        let desc = Description::full_graph(
            [4096, 256, 7, 7],
            3,
            60,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        let e = encode(b"image", &desc).unwrap();
        let m = crate::root_manifest_v2::verify(e.bytes(), e.digest(), b"image")
            .unwrap()
            .current_profile()
            .unwrap();
        let mut a = Authority::new();
        let c = a.create_space().unwrap();
        let b = a.create_space().unwrap();
        let d = a.create_space().unwrap();
        let before = a.metadata_usage();
        assert!(matches!(
            install(&mut a, c, b, d, &[], &m),
            Err(Error::Capacity)
        ));
        assert_eq!(a.metadata_usage(), before);
        assert_eq!(capability::MAX_CAPS, 16);
    }
}
