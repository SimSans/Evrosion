//! Real kernel execution of measured-manifest binding in an isolated fixture.
//! The image bytes are a digest fixture, not an executable or Root Supervisor.
use ev_kernel::{
    bootstrap_binding::{self, CatalogEntry},
    bootstrap_manifest,
    capability::{Authority, Error, Kind, Rights},
};
const MANIFEST: &[u8; 232] = include_bytes!("../fixtures/bootstrap-whole-object-v1.bin");
const EXPECTED: [u8; 32] = [
    0x43, 0xbc, 0x79, 0x54, 0xf2, 0x7d, 0x9b, 0x27, 0x59, 0xdc, 0x89, 0x74, 0x5f, 0xd9, 0x83, 0xaa,
    0xf5, 0xc7, 0x1d, 0xb4, 0x1f, 0xfd, 0xc0, 0xc7, 0xa1, 0x77, 0xd2, 0x4e, 0x78, 0xfe, 0xde, 0x5f,
];
pub fn prove() {
    let manifest = bootstrap_manifest::verify(MANIFEST, EXPECTED, b"abc", [42; 32]).unwrap();
    let mut authority = Authority::new();
    let custody = authority.create_space().unwrap();
    let mut destination = authority.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL;
    let memory = authority
        .create_root(custody, Kind::Memory, common | Rights::READ | Rights::WRITE)
        .unwrap();
    let endpoint = authority
        .create_root(custody, Kind::Endpoint, common | Rights::SEND)
        .unwrap();
    let catalog = [
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
    ];
    let mut corrupt = *MANIFEST;
    corrupt[128] ^= 1;
    assert_eq!(
        bootstrap_manifest::verify(&corrupt, EXPECTED, b"abc", [42; 32]).err(),
        Some(bootstrap_manifest::Error::ManifestDigest)
    );
    // Independently valid manifest, but a live catalog bound to a different object.
    let replacement = authority
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let mut substituted = catalog;
    substituted[0].root = replacement;
    assert_eq!(
        bootstrap_binding::install(
            &mut authority,
            custody,
            destination,
            &substituted,
            &manifest
        )
        .err(),
        Some(bootstrap_binding::Error::AuthorityDigest)
    );
    let mut stale = None;
    for _ in 0..64 {
        let batch =
            bootstrap_binding::install(&mut authority, custody, destination, &catalog, &manifest)
                .unwrap();
        let current = batch.grants.handles()[0];
        assert_eq!(batch.digest, manifest.expected_authority_digest());
        assert!(
            authority
                .authorize(destination, current, Kind::Memory, Rights::READ)
                .is_ok()
        );
        if let Some((old_space, old_handle)) = stale {
            assert_eq!(
                authority
                    .authorize(old_space, current, Kind::Memory, Rights::READ)
                    .err(),
                Some(Error::InvalidSpace)
            );
            assert_eq!(
                authority
                    .authorize(destination, old_handle, Kind::Memory, Rights::READ)
                    .err(),
                Some(Error::InvalidHandle)
            );
        }
        stale = Some((destination, current));
        authority.close_space(destination).unwrap();
        assert_eq!(authority.collect_lineage(), Ok(2));
        destination = authority.recycle_space(destination).unwrap();
    }
    let installed =
        bootstrap_binding::install(&mut authority, custody, destination, &catalog, &manifest)
            .unwrap();
    assert_eq!(installed.digest, manifest.expected_authority_digest());
    let handles = installed.grants.handles();
    assert_eq!(handles.len(), 2);
    assert!(
        authority
            .authorize(destination, handles[0], Kind::Memory, Rights::READ)
            .is_ok()
    );
    assert_eq!(
        authority
            .authorize(destination, handles[0], Kind::Memory, Rights::WRITE)
            .err(),
        Some(Error::Denied)
    );
    authority.revoke(custody, memory).unwrap();
    assert_eq!(
        authority
            .authorize(destination, handles[0], Kind::Memory, Rights::READ)
            .err(),
        Some(Error::Revoked)
    );
    assert!(
        authority
            .authorize(destination, handles[1], Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
}

/// Authority-only scope replacement: no scheduler, executable or quiescence claim.
pub fn prove_scopes() {
    let manifest = bootstrap_manifest::verify(MANIFEST, EXPECTED, b"abc", [42; 32]).unwrap();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let mut branches = a.create_space().unwrap();
    let mut user = a.create_space().unwrap();
    let peer = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let memory = a
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let endpoint = a
        .create_root(custody, Kind::Endpoint, common | Rights::SEND)
        .unwrap();
    let independent = a.derive(custody, memory, peer, Rights::READ).unwrap();
    let catalog = [
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
    ];
    let mut stale = None;
    for _ in 0..64 {
        let batch =
            bootstrap_binding::install_scoped(&mut a, custody, branches, user, &catalog, &manifest)
                .unwrap();
        assert_eq!(batch.digest, manifest.expected_authority_digest());
        if let Some((old_space, old_handle)) = stale {
            assert_eq!(
                a.revoke_batch(old_space, batch.grants.branches.handles()),
                Err(Error::InvalidSpace)
            );
            assert_eq!(
                a.revoke_batch(branches, &[old_handle]),
                Err(Error::InvalidHandle)
            );
        }
        for (i, g) in manifest.grants().enumerate() {
            assert!(
                a.authorize(user, batch.grants.grants.handles()[i], g.kind, g.rights)
                    .is_ok()
            );
        }
        assert_eq!(a.collect_lineage(), Ok(0));
        a.revoke_batch(branches, batch.grants.branches.handles())
            .unwrap();
        a.revoke_batch(branches, batch.grants.branches.handles())
            .unwrap();
        for (i, g) in manifest.grants().enumerate() {
            assert_eq!(
                a.authorize(user, batch.grants.grants.handles()[i], g.kind, g.rights)
                    .err(),
                Some(Error::Revoked)
            );
            assert!(
                a.authorize(custody, catalog[i].root, g.kind, g.rights)
                    .is_ok()
            );
        }
        assert!(
            a.authorize(peer, independent, Kind::Memory, Rights::READ)
                .is_ok()
        );
        stale = Some((branches, batch.grants.branches.handles()[0]));
        a.close_space(user).unwrap();
        assert_eq!(a.collect_lineage(), Ok(2));
        a.close_space(branches).unwrap();
        assert_eq!(a.collect_lineage(), Ok(2));
        user = a.recycle_space(user).unwrap();
        branches = a.recycle_space(branches).unwrap();
    }
}

/// Two isolated simulated boot epochs, not two simultaneous incarnations.
pub fn prove_incarnation() {
    let old = prepared_epoch(1, None);
    let new = prepared_epoch(2, Some(old));
    assert_ne!(old, new);
}
pub(crate) fn prepared_epoch(
    epoch: u64,
    stale: Option<ev_kernel::incarnation::Token>,
) -> ev_kernel::incarnation::Token {
    use core::num::NonZeroU64;
    use ev_kernel::{
        incarnation::{Bindings, Error as BindError, Phase, Target},
        scheduler::Scheduler,
    };
    let manifest = bootstrap_manifest::verify(MANIFEST, EXPECTED, b"abc", [42; 32]).unwrap();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let branches = a.create_space().unwrap();
    let destination = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let memory = a
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let endpoint = a
        .create_root(custody, Kind::Endpoint, common | Rights::SEND)
        .unwrap();
    let catalog = [
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
    ];
    let mut scheduler = Scheduler::new();
    let job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    scheduler.create_thread(process).unwrap();
    let target = Target {
        process,
        job,
        destination,
        branches,
    };
    let wrong_job = scheduler.create_job().unwrap();
    let wrong_process = scheduler.create_held_process(wrong_job).unwrap();
    let mut binding = Bindings::new(
        NonZeroU64::new(epoch).unwrap(),
        &manifest,
        custody,
        &catalog,
    );
    assert_eq!(
        binding.prepare(
            &mut a,
            &scheduler,
            Target {
                process: wrong_process,
                job: wrong_job,
                ..target
            }
        ),
        Err(BindError::JobLimits)
    );
    let token = binding.prepare(&mut a, &scheduler, target).unwrap();
    assert_eq!(token.process(), process);
    assert_eq!(token.job(), job);
    assert_eq!(token.number(), 1);
    assert_eq!(
        binding.prepare(&mut a, &scheduler, target),
        Err(BindError::Busy)
    );
    if let Some(stale) = stale {
        assert_eq!(binding.revoke(&mut a, stale), Err(BindError::StaleToken));
        assert_eq!(binding.grants(stale), Err(BindError::StaleToken));
    }
    let handles = [
        binding.grants(token).unwrap()[0],
        binding.grants(token).unwrap()[1],
    ];
    for (i, g) in manifest.grants().enumerate() {
        assert!(
            a.authorize(destination, handles[i], g.kind, g.rights)
                .is_ok()
        );
    }
    scheduler.create_thread(process).unwrap();
    let peer = scheduler.create_process(job).unwrap();
    let peer_thread = scheduler.create_thread(peer).unwrap();
    assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, peer_thread);
    scheduler.exit(0).unwrap();
    for cpu in 0..ev_kernel::scheduler::MAX_CPUS {
        assert_eq!(scheduler.dispatch(cpu), Ok(None));
    }
    binding.revoke(&mut a, token).unwrap();
    binding.revoke(&mut a, token).unwrap();
    assert_eq!(binding.phase(), Phase::Revoked);
    assert_eq!(
        binding.prepare(&mut a, &scheduler, target),
        Err(BindError::Busy)
    );
    for (i, g) in manifest.grants().enumerate() {
        assert_eq!(
            a.authorize(destination, handles[i], g.kind, g.rights).err(),
            Some(Error::Revoked)
        );
        assert!(
            a.authorize(custody, catalog[i].root, g.kind, g.rights)
                .is_ok()
        );
    }
    token
}
