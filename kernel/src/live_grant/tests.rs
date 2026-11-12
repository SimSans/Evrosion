extern crate std;
use super::*;
use crate::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    incarnation::{Bindings, Target},
    scheduler::Limits,
    service::{Role, SERVICE_LIMITS, ServiceImage},
};
use core::num::NonZeroU64;
use picker::{
    AppId, AppRef, BootEpoch, ContentDigest, Incarnation, ObjectId, ObjectView, Origin,
    Persistence, Picker, PickerEpoch, Requester, Revision, SessionId, UserId, VolumeId,
};
use sha2::{Digest, Sha256};

const ELF: &[u8] = include_bytes!("../../fixtures/bootstrap-static-v1.elf");
const MANIFEST: &[u8] = include_bytes!("../../fixtures/bootstrap-whole-object-v1.bin");
fn common() -> Rights {
    Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE
}
fn requester() -> Requester {
    Requester {
        user: UserId::new([1; 16]).unwrap(),
        session: SessionId::new([2; 16]).unwrap(),
        app: AppRef {
            app: AppId::new([3; 16]).unwrap(),
            package: ContentDigest::new([4; 32]).unwrap(),
        },
        incarnation: Incarnation::new(BootEpoch::new([5; 16]).unwrap(), 1).unwrap(),
        policy_revision: 1,
        alive: true,
    }
}
fn object() -> ObjectView {
    ObjectView {
        object: ObjectId::new(VolumeId::new([6; 16]).unwrap(), 1).unwrap(),
        revision: Revision::new(1, ContentDigest::new([7; 32]).unwrap()).unwrap(),
        permission_revision: 1,
        readable: true,
    }
}
struct Fixture {
    a: Authority,
    s: Scheduler,
    r: Registry<'static>,
    owner: SpaceId,
    root: Token,
    process: Handle,
    child: Handle,
    image: Handle,
    target: Metadata,
    endpoint: Handle,
    send: Handle,
    file: Handle,
    source: Handle,
    route: SelectedReadRoute,
    catalog: [CatalogEntry; 2],
}
fn root_token(
    a: &mut Authority,
    s: &mut Scheduler,
    owner: SpaceId,
    catalog: &[CatalogEntry; 2],
    epoch: u64,
) -> Token {
    let manifest =
        bootstrap_manifest::verify(MANIFEST, Sha256::digest(MANIFEST).into(), b"abc", [42; 32])
            .unwrap();
    let job = s.create_job_with_limits(manifest.limits()).unwrap();
    let target = Target {
        process: s.create_held_process(job).unwrap(),
        job,
        destination: a.create_space().unwrap(),
        branches: a.create_space().unwrap(),
    };
    let mut binding = Bindings::new(NonZeroU64::new(epoch).unwrap(), &manifest, owner, catalog);
    binding.prepare(a, s, target).unwrap()
}
fn fixture() -> Fixture {
    let mut a = Authority::new();
    let owner = a.create_space().unwrap();
    let memory = a
        .create_root(owner, Kind::Memory, Rights::READ | common())
        .unwrap();
    let root_endpoint = a
        .create_root(owner, Kind::Endpoint, Rights::SEND | common())
        .unwrap();
    let catalog = [
        CatalogEntry {
            selector: 1,
            root: memory,
            kind: Kind::Memory,
        },
        CatalogEntry {
            selector: 2,
            root: root_endpoint,
            kind: Kind::Endpoint,
        },
    ];
    let mut s = Scheduler::new();
    let root = root_token(&mut a, &mut s, owner, &catalog, 11);
    let creator = a
        .create_root(owner, Kind::Job, Rights::READ | Rights::CONTROL | common())
        .unwrap();
    let image = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
    let job = s
        .create_job_with_limits(Limits::new(1000, 64, 4, 8))
        .unwrap();
    let mut r = Registry::new();
    r.register_job(&a, owner, creator, job).unwrap();
    r.register_image(
        &a,
        owner,
        image,
        ServiceImage::verify(
            ELF,
            Sha256::digest(ELF).into(),
            SERVICE_LIMITS,
            &[Role {
                selector: 1,
                kind: Kind::Endpoint,
                rights: Rights::RECEIVE | Rights::CONTROL,
            }],
        )
        .unwrap(),
    )
    .unwrap();
    let child = r.create_job(&mut a, &mut s, owner, creator, 0).unwrap();
    let (endpoint, mailbox) = r.create_channel(&mut a, owner, child).unwrap();
    let send = a.derive(owner, endpoint, owner, Rights::SEND).unwrap();
    let process = r
        .create_process(&mut a, &mut s, owner, child, image)
        .unwrap();
    r.delegate(&mut a, owner, process, endpoint, 1).unwrap();
    let target = r
        .model_admit_for_grant_test(&a, &mut s, owner, process)
        .unwrap();
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, target.thread);
    let file = a
        .create_root(
            owner,
            Kind::Endpoint,
            Rights::SEND | common() | Rights::CONTROL,
        )
        .unwrap();
    let source = a
        .derive(owner, file, owner, Rights::SEND | common())
        .unwrap();
    let route =
        SelectedReadRoute::from_managed(&a, &s, &r, root, owner, process, 1, endpoint, mailbox)
            .unwrap_or_else(|rejected| panic!("{:?}", rejected.error));
    Fixture {
        a,
        s,
        r,
        owner,
        root,
        process,
        child,
        image,
        target,
        endpoint,
        send,
        file,
        source,
        route,
        catalog,
    }
}
fn enqueue(f: &mut Fixture, deadline: u64) -> Ticket {
    f.route
        .enqueue(
            &mut f.a,
            &f.s,
            &f.r,
            f.root,
            f.send,
            f.source,
            b"chosen",
            Deadline::after(0, deadline).unwrap(),
            0,
        )
        .unwrap()
}

#[test]
fn running_app_receives_exact_send8_once_and_root_ancestor_revokes_after_source_close() {
    let mut f = fixture();
    let object =
        f.a.authorize(f.owner, f.source, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity();
    let ticket = enqueue(&mut f, 10);
    assert_eq!(
        f.a.authorize(f.owner, f.source, Kind::Endpoint, Rights::SEND)
            .err(),
        Some(CapError::InvalidHandle)
    );
    let received = f
        .route
        .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 1)
        .unwrap();
    assert_eq!(received.ticket, ticket);
    let leaf = received.capability.unwrap();
    let access =
        f.a.authorize(f.target.domain, leaf, Kind::Endpoint, Rights::SEND)
            .unwrap();
    assert_eq!(access.identity(), object);
    assert_eq!(access.rights(), Rights::SEND);
    assert_eq!(
        f.a.transfer(f.target.domain, leaf, f.owner),
        Err(CapError::Denied)
    );
    assert_eq!(
        f.a.derive(f.target.domain, leaf, f.target.domain, Rights::SEND),
        Err(CapError::Denied)
    );
    assert_eq!(
        f.a.authorize(f.target.domain, leaf, Kind::Memory, Rights::READ)
            .err(),
        Some(CapError::WrongKind)
    );
    assert_eq!(
        f.a.authorize(f.target.domain, leaf, Kind::Endpoint, Rights::RECEIVE)
            .err(),
        Some(CapError::Denied)
    );
    f.a.collect_lineage().unwrap();
    f.a.revoke(f.owner, f.file).unwrap();
    assert_eq!(
        f.a.authorize(f.target.domain, leaf, Kind::Endpoint, Rights::SEND)
            .err(),
        Some(CapError::Revoked)
    );
    assert_eq!(f.route.pending(), 0);
    assert!(f.route.reclaim(&mut f.a, ticket, 10).is_err());
}
#[test]
fn queued_timeout_and_real_scheduler_death_refund_the_original_rights() {
    for death in [false, true] {
        let mut f = fixture();
        let rights =
            f.a.authorize(f.owner, f.source, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights();
        let ticket = enqueue(&mut f, 5);
        if death {
            f.s.exit(0).unwrap();
            f.s.terminate_process(f.target.process).unwrap();
            f.route.receiver_died(&f.s).unwrap();
        }
        let returned = match f
            .route
            .reclaim(&mut f.a, ticket, if death { 1 } else { 5 })
            .unwrap()
        {
            Reclaimed::Capability(h) => h,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            f.a.authorize(f.owner, returned, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights(),
            rights
        );
        assert!(rights.contains(Rights::DERIVE | Rights::TRANSFER));
        assert_eq!(f.route.pending(), 0);
    }
}
#[test]
fn target_control_revocation_dead_domain_wrong_thread_and_old_incarnation_never_deliver() {
    for mode in 0..4 {
        let mut f = fixture();
        let ticket = enqueue(&mut f, 10);
        let usage = f.a.metadata_usage();
        match mode {
            0 => f.a.revoke(f.owner, f.process).unwrap(),
            1 => {
                f.a.close_space(f.target.domain).unwrap();
                let replacement = f.a.recycle_space(f.target.domain).unwrap();
                assert_ne!(replacement, f.target.domain);
                f.a.derive(
                    f.owner,
                    f.endpoint,
                    replacement,
                    Rights::RECEIVE | Rights::CONTROL,
                )
                .unwrap();
            }
            2 => {
                f.s.exit(0).unwrap();
                f.s.terminate_process(f.target.process).unwrap();
            }
            _ => {}
        }
        let thread = if mode == 3 {
            let job = f.s.create_job().unwrap();
            let process = f.s.create_process(job).unwrap();
            f.s.create_thread(process).unwrap()
        } else {
            f.target.thread
        };
        let after_change = f.a.metadata_usage();
        assert!(
            f.route
                .receive(&mut f.a, &f.s, &f.r, f.root, thread, 1)
                .is_err()
        );
        assert_eq!(f.a.metadata_usage(), after_change);
        assert_eq!(f.route.pending(), 1);
        assert!(usage.2 <= after_change.2);
        // No delivered leaf is invented; original sender can refund only at
        // actual queue deadline (or after a real death notification).
        assert!(matches!(
            f.route.reclaim(&mut f.a, ticket, 10).unwrap(),
            Reclaimed::Capability(_)
        ));
    }
    let mut f = fixture();
    enqueue(&mut f, 10);
    let alternate = root_token(&mut f.a, &mut f.s, f.owner, &f.catalog, 12);
    let before = f.a.metadata_usage();
    assert_eq!(
        f.route
            .receive(&mut f.a, &f.s, &f.r, alternate, f.target.thread, 1)
            .err(),
        Some(Error::StaleRoot)
    );
    assert_eq!(f.a.metadata_usage(), before);
    assert_eq!(f.route.pending(), 1);
}
#[test]
fn source_close_or_revoke_wrong_kind_and_receiver_capacity_are_atomic() {
    for mode in 0..3 {
        let mut f = fixture();
        let source = match mode {
            0 => {
                f.a.close(f.owner, f.source).unwrap();
                f.source
            }
            1 => {
                f.a.revoke(f.owner, f.file).unwrap();
                f.source
            }
            _ => {
                f.a.create_root(f.owner, Kind::Memory, Rights::READ | common())
                    .unwrap()
            }
        };
        let usage = f.a.metadata_usage();
        assert!(
            f.route
                .enqueue(
                    &mut f.a,
                    &f.s,
                    &f.r,
                    f.root,
                    f.send,
                    source,
                    b"chosen",
                    Deadline::after(0, 10).unwrap(),
                    0
                )
                .is_err()
        );
        assert_eq!(f.a.metadata_usage(), usage);
        assert_eq!(f.route.pending(), 0);
    }
    let mut f = fixture();
    enqueue(&mut f, 10);
    let receive = f.r.grant(&f.a, f.owner, f.process, 1).unwrap();
    let mut last = None;
    while let Ok(h) =
        f.a.derive(f.owner, f.endpoint, f.target.domain, Rights::SEND)
    {
        last = Some(h);
    }
    let usage = f.a.metadata_usage();
    assert_eq!(
        f.route
            .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 1)
            .err(),
        Some(Error::Ipc(ipc::Error::Authority(CapError::Capacity)))
    );
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!(f.route.pending(), 1);
    f.a.close(f.target.domain, last.unwrap()).unwrap();
    let got = f
        .route
        .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 1)
        .unwrap()
        .capability
        .unwrap();
    assert_ne!(got, receive);
    assert_eq!(
        f.a.authorize(f.target.domain, got, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .rights()
            .bits(),
        8
    );
}
#[test]
fn picker_nonce_current_object_and_policy_revalidation_precede_the_real_escrow_move() {
    for mode in 0..5 {
        let mut f = fixture();
        let mut picker = Picker::new(PickerEpoch::new([8; 16]).unwrap(), 20).unwrap();
        let requester = requester();
        let object = object();
        let approval = picker
            .prepare(requester, object, Persistence::ThisIncarnation, 0, 10)
            .unwrap();
        let selection = approval.selection();
        let row = SelectedObject::bind(&f.a, f.owner, f.source, object).unwrap();
        let mut current = object;
        let mut who = requester;
        match mode {
            1 => current.revision = Revision::new(2, ContentDigest::new([9; 32]).unwrap()).unwrap(),
            2 => current.permission_revision += 1,
            3 => who.incarnation = Incarnation::new(BootEpoch::new([5; 16]).unwrap(), 2).unwrap(),
            4 => {
                picker.requester_died(requester.incarnation);
            }
            _ => {}
        }
        let usage = f.a.metadata_usage();
        let mut handoff = PickerHandoff {
            authority: &mut f.a,
            scheduler: &f.s,
            registry: &f.r,
            route: &mut f.route,
            root: f.root,
            send: f.send,
            object: &row,
            requester: who,
            now: 1,
        };
        let result = picker.commit(
            approval,
            picker::Consent {
                displayed_action: selection.action_digest(),
                approver: requester.user,
                origin: Origin::TrustedPicker,
            },
            who,
            current,
            1,
            &mut handoff,
        );
        if mode == 0 {
            assert!(matches!(
                result,
                Ok(picker::Delivery::Delivered(AcceptedGrant::Queued(_)))
            ));
            assert_eq!(f.route.pending(), 1);
            let leaf = f
                .route
                .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 2)
                .unwrap()
                .capability
                .unwrap();
            assert_eq!(
                f.a.authorize(f.target.domain, leaf, Kind::Endpoint, Rights::SEND)
                    .unwrap()
                    .rights()
                    .bits(),
                8
            );
        } else {
            assert!(result.is_err());
            assert_eq!(f.a.metadata_usage(), usage);
            assert_eq!(f.route.pending(), 0);
            assert!(
                f.a.authorize(f.owner, f.source, Kind::Endpoint, Rights::SEND)
                    .is_ok()
            );
        }
    }
}
#[test]
fn handoff_rechecks_current_object_even_after_picker_preflight() {
    let mut f = fixture();
    let mut picker = Picker::new(PickerEpoch::new([8; 16]).unwrap(), 20).unwrap();
    let requester = requester();
    let object = object();
    let approval = picker
        .prepare(requester, object, Persistence::ThisIncarnation, 0, 10)
        .unwrap();
    let selection = approval.selection();
    let mut row = SelectedObject::bind(&f.a, f.owner, f.source, object).unwrap();
    row.view.revision = Revision::new(2, ContentDigest::new([9; 32]).unwrap()).unwrap();
    let usage = f.a.metadata_usage();
    let mut handoff = PickerHandoff {
        authority: &mut f.a,
        scheduler: &f.s,
        registry: &f.r,
        route: &mut f.route,
        root: f.root,
        send: f.send,
        object: &row,
        requester,
        now: 1,
    };
    assert_eq!(
        picker.commit(
            approval,
            picker::Consent {
                displayed_action: selection.action_digest(),
                approver: requester.user,
                origin: Origin::TrustedPicker
            },
            requester,
            object,
            1,
            &mut handoff
        ),
        Ok(picker::Delivery::Refused(Error::ChangedSelection))
    );
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!(f.route.pending(), 0);
}

#[test]
fn construction_requires_live_process_control_and_an_actual_declared_receive_role() {
    let mut f = fixture();
    let weak =
        f.a.derive(f.owner, f.process, f.owner, Rights::READ)
            .unwrap();
    for (control, role) in [(weak, 1), (f.file, 1), (f.process, 99)] {
        let usage = f.a.metadata_usage();
        assert!(
            SelectedReadRoute::new(&mut f.a, &f.s, &f.r, f.root, f.owner, control, role).is_err()
        );
        assert_eq!(f.a.metadata_usage(), usage);
    }
}

#[test]
fn revoked_queued_authority_is_invalidated_without_a_fabricated_refund() {
    let mut f = fixture();
    let ticket = enqueue(&mut f, 5);
    f.a.revoke(f.owner, f.file).unwrap();
    let usage = f.a.metadata_usage();
    assert_eq!(
        f.route
            .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 1)
            .err(),
        Some(Error::Ipc(ipc::Error::Authority(CapError::Revoked)))
    );
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!(f.route.pending(), 1);
    assert_eq!(
        f.route.reclaim(&mut f.a, ticket, 5),
        Ok(Reclaimed::Invalidated)
    );
    assert_eq!(f.route.pending(), 0);
}

#[test]
fn matching_object_metadata_cannot_substitute_a_different_installed_endpoint() {
    let mut f = fixture();
    let mut picker = Picker::new(PickerEpoch::new([8; 16]).unwrap(), 20).unwrap();
    let requester = requester();
    let object = object();
    let approval = picker
        .prepare(requester, object, Persistence::ThisIncarnation, 0, 10)
        .unwrap();
    let selection = approval.selection();
    let mut row = SelectedObject::bind(&f.a, f.owner, f.source, object).unwrap();
    row.source = f.endpoint;
    let usage = f.a.metadata_usage();
    let mut handoff = PickerHandoff {
        authority: &mut f.a,
        scheduler: &f.s,
        registry: &f.r,
        route: &mut f.route,
        root: f.root,
        send: f.send,
        object: &row,
        requester,
        now: 1,
    };
    assert_eq!(
        picker.commit(
            approval,
            picker::Consent {
                displayed_action: selection.action_digest(),
                approver: requester.user,
                origin: Origin::TrustedPicker
            },
            requester,
            object,
            1,
            &mut handoff
        ),
        Ok(picker::Delivery::Refused(Error::WrongObject))
    );
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!(f.route.pending(), 0);
    assert!(
        f.a.authorize(f.owner, f.source, Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
}

#[test]
fn repeated_live_grants_reuse_bounded_tables_without_reviving_old_caps_or_tickets() {
    let mut f = fixture();
    let mut source = f.source;
    let mut old = None;
    for serial in 1..=128 {
        let ticket = f
            .route
            .enqueue(
                &mut f.a,
                &f.s,
                &f.r,
                f.root,
                f.send,
                source,
                b"selected",
                Deadline::after(0, 200).unwrap(),
                0,
            )
            .unwrap();
        assert_eq!(ticket.0, serial);
        let leaf = f
            .route
            .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 0)
            .unwrap()
            .capability
            .unwrap();
        if let Some(previous) = old {
            assert_ne!(leaf, previous);
            assert_eq!(
                f.a.authorize(f.target.domain, previous, Kind::Endpoint, Rights::SEND)
                    .err(),
                Some(CapError::InvalidHandle)
            );
        }
        assert_eq!(
            f.a.authorize(f.target.domain, leaf, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights()
                .bits(),
            8
        );
        f.a.close(f.target.domain, leaf).unwrap();
        f.a.collect_lineage().unwrap();
        old = Some(leaf);
        source =
            f.a.derive(f.owner, f.file, f.owner, Rights::SEND | common())
                .unwrap();
        assert_eq!(f.route.pending(), 0);
        assert!(f.a.metadata_usage().2 < 40);
    }
}

#[test]
fn pending_cancel_returns_original_rights_and_cannot_refund_a_delivered_or_new_message() {
    let mut f = fixture();
    let first = enqueue(&mut f, 20);
    let source = match f.route.cancel(&mut f.a, first, 1).unwrap() {
        Reclaimed::Capability(h) => h,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        f.a.authorize(f.owner, source, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .rights()
            .bits(),
        232
    );
    let second = f
        .route
        .enqueue(
            &mut f.a,
            &f.s,
            &f.r,
            f.root,
            f.send,
            source,
            b"selected",
            Deadline::after(0, 20).unwrap(),
            1,
        )
        .unwrap();
    assert_ne!(first, second);
    let usage = f.a.metadata_usage();
    assert!(f.route.cancel(&mut f.a, first, 1).is_err());
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!(f.route.pending(), 1);
    f.route
        .receive(&mut f.a, &f.s, &f.r, f.root, f.target.thread, 2)
        .unwrap();
    assert!(f.route.cancel(&mut f.a, second, 2).is_err());
    assert_eq!(f.route.pending(), 0);
}

#[test]
fn managed_route_retirement_keeps_live_or_queued_owner_and_survives_revoked_closed_control() {
    let mut f = fixture();
    let usage = f.a.metadata_usage();
    let rejected = f
        .route
        .into_stopped_mailbox(&f.a, &f.s, &f.r)
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::Service(service::Error::Phase));
    assert_eq!(f.a.metadata_usage(), usage);
    f.route = rejected.route;
    let ticket = enqueue(&mut f, 10);
    f.s.exit(0).unwrap();
    f.s.terminate_process(f.target.process).unwrap();
    let usage = f.a.metadata_usage();
    let rejected = f
        .route
        .into_stopped_mailbox(&f.a, &f.s, &f.r)
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::Ipc(ipc::Error::NotReclaimable));
    assert_eq!(rejected.route.pending(), 1);
    assert_eq!(f.a.metadata_usage(), usage);
    f.route = rejected.route;
    f.route.receiver_died(&f.s).unwrap();
    f.a.revoke(f.owner, f.file).unwrap();
    assert_eq!(
        f.route.reclaim(&mut f.a, ticket, 1).unwrap(),
        Reclaimed::Invalidated
    );
    // Revoking/closing the public control and all target RX grants cannot
    // strand the non-Clone mailbox owner's decreasing-authority cleanup.
    f.a.revoke(f.owner, f.process).unwrap();
    f.a.close(f.owner, f.process).unwrap();
    f.r.retire_stopped(&mut f.a, &f.s, f.target.process)
        .unwrap();
    let mailbox = f
        .route
        .into_stopped_mailbox(&f.a, &f.s, &f.r)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    f.a.close(f.owner, f.endpoint).unwrap();
    f.a.close(f.owner, f.send).unwrap();
    let _receipt = mailbox
        .retire_managed(&mut f.a)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
}
#[test]
fn missing_or_recycled_registry_identity_never_declassifies_an_old_route_owner() {
    let mut f = fixture();
    f.s.exit(0).unwrap();
    f.s.terminate_process(f.target.process).unwrap();
    f.r.retire_stopped(&mut f.a, &f.s, f.target.process)
        .unwrap();
    f.s.release_frames(f.target.job, f.target.frames).unwrap();
    f.a.close(f.owner, f.process).unwrap();
    // Deliberately wrong order: the typed route must have retired BEFORE this.
    f.r.forget_retired(&mut f.a, &f.s, f.target.process)
        .unwrap();
    f.s.reclaim_process(f.target.process).unwrap();
    let fresh =
        f.r.create_process(&mut f.a, &mut f.s, f.owner, f.child, f.image)
            .unwrap();
    f.r.delegate(&mut f.a, f.owner, fresh, f.endpoint, 1)
        .unwrap();
    let fresh_meta =
        f.r.model_admit_for_grant_test(&f.a, &mut f.s, f.owner, fresh)
            .unwrap();
    assert_ne!(fresh_meta.process, f.target.process);
    assert_ne!(fresh_meta.thread, f.target.thread);
    let before = f.a.metadata_usage();
    let rejected = f
        .route
        .into_stopped_mailbox(&f.a, &f.s, &f.r)
        .err()
        .unwrap();
    assert_eq!(
        rejected.error,
        Error::Service(service::Error::UnknownObject)
    );
    assert_eq!(f.a.metadata_usage(), before);
    assert_eq!(rejected.route.pending(), 0);
    // Explicit retained failed owner, never a claim that the bad-order graph
    // has been fully cleaned or that a recycled process is actually stopped.
    let _retained = rejected.route;
}
#[test]
fn managed_selected_route_recycles_64_times_without_domain_or_ticket_reset() {
    // Actual portable core lifecycle only. model_admit_for_grant_test is absent
    // from production; no physical image/RAM/CPU/input execution is certified.
    let mut a = Authority::new();
    let owner = a.create_control_space().unwrap();
    let memory = a
        .create_root(owner, Kind::Memory, Rights::READ | common())
        .unwrap();
    let events = a
        .create_root(owner, Kind::Endpoint, Rights::SEND | common())
        .unwrap();
    let catalog = [
        CatalogEntry {
            selector: 1,
            root: memory,
            kind: Kind::Memory,
        },
        CatalogEntry {
            selector: 2,
            root: events,
            kind: Kind::Endpoint,
        },
    ];
    let mut s = Scheduler::new();
    let root = root_token(&mut a, &mut s, owner, &catalog, 71);
    let creator = a
        .create_root(owner, Kind::Job, Rights::READ | Rights::CONTROL | common())
        .unwrap();
    let image = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
    let parent = s
        .create_job_with_limits(Limits::new(1000, 64, 4, 8))
        .unwrap();
    let mut r = Registry::new();
    r.register_job(&a, owner, creator, parent).unwrap();
    r.register_image(
        &a,
        owner,
        image,
        ServiceImage::verify(
            ELF,
            Sha256::digest(ELF).into(),
            SERVICE_LIMITS,
            &[Role {
                selector: 1,
                kind: Kind::Endpoint,
                rights: Rights::RECEIVE | Rights::CONTROL,
            }],
        )
        .unwrap(),
    )
    .unwrap();
    let child = r.create_job(&mut a, &mut s, owner, creator, 0).unwrap();
    let file = a
        .create_root(
            owner,
            Kind::Endpoint,
            Rights::SEND | Rights::CONTROL | common(),
        )
        .unwrap();
    let baseline = a.metadata_usage();
    let mut receipt = None;
    let mut previous: Option<(Handle, Metadata, Handle, Ticket)> = None;
    for cycle in 0..64u64 {
        let (endpoint, mailbox) = match receipt.take() {
            None => r.create_channel(&mut a, owner, child).unwrap(),
            Some(receipt) => r
                .create_channel_reusing(&mut a, owner, child, receipt)
                .unwrap(),
        };
        let process = r
            .create_process(&mut a, &mut s, owner, child, image)
            .unwrap();
        r.delegate(&mut a, owner, process, endpoint, 1).unwrap();
        let target = r
            .model_admit_for_grant_test(&a, &mut s, owner, process)
            .unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, target.thread);
        s.charge_cpu(0, 1).unwrap();
        let parent_grant = a
            .derive(owner, file, owner, Rights::SEND | common())
            .unwrap();
        let source = a
            .derive(
                owner,
                parent_grant,
                owner,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let mut route =
            SelectedReadRoute::from_managed(&a, &s, &r, root, owner, process, 1, endpoint, mailbox)
                .unwrap_or_else(|e| panic!("{:?}", e.error));
        let ticket = route
            .enqueue(
                &mut a,
                &s,
                &r,
                root,
                endpoint,
                source,
                b"selected",
                Deadline::after(cycle, 1000).unwrap(),
                cycle,
            )
            .unwrap();
        assert_eq!(ticket.0, cycle + 1);
        if let Some((old_control, old_meta, old_endpoint, old_ticket)) = previous {
            assert_ne!(old_control, process);
            assert_ne!(old_meta.process, target.process);
            assert_ne!(old_meta.domain, target.domain);
            assert_ne!(old_meta.thread, target.thread);
            assert_ne!(old_endpoint, endpoint);
            assert_ne!(old_ticket, ticket);
            let usage = a.metadata_usage();
            assert_eq!(
                route
                    .receive(&mut a, &s, &r, root, old_meta.thread, cycle)
                    .err(),
                Some(Error::WrongThread)
            );
            assert_eq!(route.pending(), 1);
            assert_eq!(a.metadata_usage(), usage);
            assert_eq!(
                r.metadata(&a, owner, old_control).err(),
                Some(service::Error::Authority(CapError::InvalidHandle))
            );
        }
        let delivery = route
            .receive(&mut a, &s, &r, root, target.thread, cycle)
            .unwrap();
        assert_eq!(delivery.ticket, ticket);
        let grant = delivery.capability.unwrap();
        assert_eq!(
            a.authorize(target.domain, grant, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights(),
            Rights::SEND
        );
        a.revoke(owner, parent_grant).unwrap();
        a.collect_lineage().unwrap();
        assert_eq!(
            a.authorize(target.domain, grant, Kind::Endpoint, Rights::SEND)
                .err(),
            Some(CapError::Revoked)
        );
        assert!(
            a.authorize(owner, file, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        a.revoke(owner, process).unwrap();
        a.close(owner, process).unwrap();
        s.exit(0).unwrap();
        s.terminate_process(target.process).unwrap();
        r.retire_stopped(&mut a, &s, target.process).unwrap();
        let mailbox = route
            .into_stopped_mailbox(&a, &s, &r)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        a.close(owner, endpoint).unwrap();
        a.close(owner, parent_grant).unwrap();
        receipt = Some(
            mailbox
                .retire_managed(&mut a)
                .unwrap_or_else(|e| panic!("{:?}", e.error)),
        );
        s.release_frames(target.job, target.frames).unwrap();
        r.forget_retired(&mut a, &s, target.process).unwrap();
        s.reclaim_process(target.process).unwrap();
        a.collect_lineage().unwrap();
        a.collect_dead_objects().unwrap();
        assert_eq!(a.metadata_usage(), baseline);
        assert_eq!(r.metadata_usage(), (2, 1, 0, 2));
        assert_eq!(
            s.usage(parent, crate::scheduler::Resource::CpuTicks),
            Ok(cycle + 1)
        );
        previous = Some((process, target, endpoint, ticket));
    }
}

#[test]
fn production_route_constructor_returns_same_managed_owner_on_control_or_binding_denial() {
    for revoke in [false, true] {
        let mut f = fixture();
        let (endpoint, mailbox) = f.r.create_channel(&mut f.a, f.owner, f.child).unwrap();
        if revoke {
            f.a.revoke(f.owner, f.process).unwrap();
        }
        let usage = f.a.metadata_usage();
        let rejected = SelectedReadRoute::from_managed(
            &f.a, &f.s, &f.r, f.root, f.owner, f.process, 1, endpoint, mailbox,
        )
        .err()
        .unwrap();
        assert_eq!(f.a.metadata_usage(), usage);
        assert_eq!(rejected.mailbox.pending(), 0);
        assert_eq!(
            rejected.error,
            if revoke {
                Error::Service(service::Error::Authority(CapError::Revoked))
            } else {
                Error::Ipc(ipc::Error::WrongEndpoint)
            }
        );
        let mut mailbox = rejected.mailbox;
        mailbox.receiver_died(f.owner).unwrap();
        f.a.close(f.owner, endpoint).unwrap();
        let _receipt = mailbox
            .retire_managed(&mut f.a)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
    }
}

#[test]
fn active_send_parent_is_private_bounded_and_never_revokes_file_receiver_source() {
    let mut f = fixture();
    let source_id =
        f.a.authorize(f.owner, f.file, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity();
    let (branch, child) =
        f.r.prepare_active_send(&mut f.a, &f.s, f.owner, f.process, f.file)
            .unwrap();
    assert_eq!(branch.metadata(), f.target);
    assert_eq!(
        f.a.authorize(
            f.owner,
            child,
            Kind::Endpoint,
            Rights::SEND | Rights::DERIVE | Rights::TRANSFER
        )
        .unwrap()
        .identity(),
        source_id
    );
    branch
        .retire(&mut f.a)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    assert!(
        f.a.authorize(f.owner, child, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    assert!(
        f.a.authorize(f.owner, f.file, Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
    f.a.close(f.owner, child).unwrap();
}
#[test]
fn active_send_late_controller_capacity_failure_commits_no_private_parent() {
    let mut f = fixture();
    while f
        .a
        .create_root(f.owner, Kind::Thread, Rights::CONTROL)
        .is_ok()
    {}
    let before = f.a.metadata_usage();
    assert!(
        f.r.prepare_active_send(&mut f.a, &f.s, f.owner, f.process, f.file)
            .is_err()
    );
    assert_eq!(f.a.metadata_usage(), before);
    assert!(
        f.a.authorize(f.owner, f.file, Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
}

#[test]
fn active_send_owned_cleanup_survives_closed_control_and_revoked_source() {
    let mut f = fixture();
    let (branch, child) =
        f.r.prepare_active_send(&mut f.a, &f.s, f.owner, f.process, f.file)
            .unwrap();
    let receive = f.r.grant(&f.a, f.owner, f.process, 1).unwrap();
    f.a.close(f.owner, f.process).unwrap();
    f.a.revoke(f.owner, f.file).unwrap();
    branch
        .retire(&mut f.a)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    assert!(
        f.a.authorize(f.owner, child, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    f.a.close(f.owner, child).unwrap();
    assert!(
        f.a.authorize(f.target.domain, receive, Kind::Endpoint, Rights::RECEIVE)
            .is_ok()
    );
}
