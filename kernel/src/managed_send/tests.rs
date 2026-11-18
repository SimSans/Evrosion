//! Real portable Authority/Registry/Rpc/selected-escrow lifecycle. Admission is
//! host metadata only: no physical loading, guest progress or device claim.
extern crate std;
use super::*;
use crate::{
    bootstrap_binding::CatalogEntry,
    custodian::Custodian,
    ipc::Ticket,
    root_manifest_v5,
    rpc::{MessageShape, Policy, Rpc},
    scheduler::{Limits, ThreadId},
    service::{Role, SERVICE_LIMITS, ServiceImage},
    time::Deadline,
};
use core::num::NonZeroU64;
use sha2::{Digest, Sha256};
const BRANCH: Rights = Rights::from_bits(224).unwrap();
const ELF: &[u8] = include_bytes!("../../fixtures/bootstrap-static-v1.elf");
struct Fixture {
    a: Authority,
    s: Scheduler,
    r: Registry<'static>,
    context: Context,
    process: Handle,
    child: Handle,
    image: Handle,
    target: Metadata,
    inbox: Handle,
    source: Handle,
    route: SelectedReadRoute,
    rpc: Rpc,
    receiver: Metadata,
    receive: Handle,
}
fn fixture() -> Fixture {
    let image = crate::root_v5_tests::elf();
    let (mut a, domains, sources) = crate::root_v5_tests::setup(&image);
    let custody = domains.custody();
    let encoded = crate::root_v5_tests::encoded(&image, &a, custody, &sources);
    let manifest = root_manifest_v5::verify(encoded.bytes(), encoded.digest(), &image).unwrap();
    let mut s = Scheduler::new();
    let job = s
        .create_job_with_limits(manifest.manifest().limits())
        .unwrap();
    let process = s.create_held_process(job).unwrap();
    let thread = s.create_thread(process).unwrap();
    let (custody, target) = domains.into_target(process, job);
    let catalogue = sources.map(|x| CatalogEntry {
        selector: x.selector,
        root: x.handle,
        kind: x.kind,
    });
    let mut custodian = Custodian::new_root_v5(
        NonZeroU64::new(805).unwrap(),
        &manifest,
        custody,
        &catalogue,
    );
    let attempt = custodian.begin(0).unwrap();
    let (mut binding, token) = custodian.prepare(attempt, &mut a, &s, target).unwrap();
    // Only host metadata admission; the native path requires an owned physical
    // LoadedExecutable and all exact page/extent bindings before activation.
    let frames = binding.executable(token).unwrap().required_frames();
    s.charge_frames(job, frames).unwrap();
    s.admit_bootstrap(process, job, thread, frames).unwrap();
    let root = Metadata {
        process,
        thread,
        job,
        domain: target.destination,
        frames,
    };
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
    let owner = root.domain;
    let creator = binding.grants(token).unwrap()[6];
    let mut r = Registry::new();
    r.register_job(&a, owner, creator, job).unwrap();
    let image = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
    // A one-role immutable host fixture suffices for the grant/credit proof;
    // production V5 uses verify_m8 and the exact six-role Editor descriptor.
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
    let (inbox, mailbox) = r.create_channel(&mut a, owner, child).unwrap();
    let process = r
        .create_process(&mut a, &mut s, owner, child, image)
        .unwrap();
    r.delegate(&mut a, owner, process, inbox, 1).unwrap();
    let target = r
        .model_admit_for_grant_test(&a, &mut s, owner, process)
        .unwrap();
    let source = a
        .create_root(
            owner,
            Kind::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::CONTROL | BRANCH,
        )
        .unwrap();
    let receiver_domain = a.create_space().unwrap();
    let receiver_job = s
        .create_job_with_limits(Limits::new(16384, 64, 1, 1))
        .unwrap();
    let receiver_process = s.create_process(receiver_job).unwrap();
    let receiver_thread = s.create_thread(receiver_process).unwrap();
    let receiver = Metadata {
        process: receiver_process,
        thread: receiver_thread,
        job: receiver_job,
        domain: receiver_domain,
        frames: 0,
    };
    let receive = a
        .derive(
            owner,
            source,
            receiver_domain,
            Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap();
    let route =
        SelectedReadRoute::from_managed(&a, &s, &r, token, owner, process, 1, inbox, mailbox)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
    let mut rpc = Rpc::new(NonZeroU64::new(805).unwrap());
    for meta in [root, target, receiver] {
        rpc.register_thread(&a, &s, meta.thread, meta.job, meta.domain, Some(token))
            .unwrap();
    }
    rpc.bind_endpoint(
        &a,
        receiver.domain,
        receive,
        receiver.thread,
        Policy::new(8, 0).unwrap(),
    )
    .unwrap();
    Fixture {
        a,
        s,
        r,
        context: Context {
            caller: root,
            root,
            token,
        },
        process,
        child,
        image,
        target,
        inbox,
        source,
        route,
        rpc,
        receiver,
        receive,
    }
}
fn enqueue(f: &mut Fixture, nonce: u32) -> (Entry, Ticket, Handle) {
    let (entry, send) =
        Entry::prepare(&mut f.a, &f.s, &f.r, f.context, f.process, f.source, nonce).unwrap();
    let escaped =
        f.a.derive(f.context.root.domain, send, f.receiver.domain, Rights::SEND)
            .unwrap();
    let ticket = f
        .route
        .enqueue(
            &mut f.a,
            &f.s,
            &f.r,
            f.context.token,
            f.inbox,
            send,
            &u64::from(nonce).to_le_bytes(),
            Deadline::after(0, 100).unwrap(),
            0,
        )
        .unwrap();
    assert!(!entry.queue_cleared());
    (entry, ticket, escaped)
}
fn dispatch(f: &mut Fixture, wanted: ThreadId) {
    if f.s.state(wanted) == Ok(State::Running(0)) {
        return;
    }
    if f.s.running_thread(0).is_ok() {
        f.s.yield_cpu(0).unwrap();
    }
    for _ in 0..16 {
        let thread = f.s.dispatch(0).unwrap().unwrap().thread;
        if thread == wanted {
            return;
        }
        f.s.yield_cpu(0).unwrap();
    }
    panic!("ready fixture owner");
}
fn retire(
    f: &mut Fixture,
    entry: &mut Entry,
    ticket: Option<Ticket>,
    credits: &[Option<AcceptedSnapshot>],
) -> StateCode {
    let root = f.context.root.thread;
    dispatch(f, root);
    entry
        .retire(
            &mut f.a,
            &f.s,
            &f.r,
            f.context,
            f.process,
            entry.nonce(),
            &mut f.route,
            ticket,
            credits,
            2,
        )
        .unwrap()
}
fn source_live(f: &Fixture) {
    assert!(
        f.a.authorize(
            f.context.root.domain,
            f.source,
            Kind::Endpoint,
            Rights::SEND
        )
        .is_ok()
    );
    assert!(
        f.a.authorize(
            f.receiver.domain,
            f.receive,
            Kind::Endpoint,
            Rights::RECEIVE | Rights::CONTROL
        )
        .is_ok()
    );
}
#[test]
fn queued_grant_revokes_escaped_send_and_withdraws_real_escrow_without_aliasing_regrant() {
    let mut f = fixture();
    let (mut entry, ticket, escaped) = enqueue(&mut f, 7);
    assert_eq!(f.route.pending(), 1);
    assert_eq!(
        retire(&mut f, &mut entry, Some(ticket), &[]),
        StateCode::Drained
    );
    assert_eq!(f.route.pending(), 0);
    assert!(entry.is_drained());
    assert!(
        f.a.authorize(f.receiver.domain, escaped, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    source_live(&f);
    let (next, send) =
        Entry::prepare(&mut f.a, &f.s, &f.r, f.context, f.process, f.source, 8).unwrap();
    assert!(
        f.a.authorize(f.context.root.domain, send, Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
    assert!(
        f.a.authorize(f.receiver.domain, escaped, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    assert_eq!(next.endpoint(), entry.endpoint());
    assert_ne!(next.nonce(), entry.nonce());
    let mut next = next;
    assert_eq!(next.revoke_owned(&mut f.a), StateCode::RevokedPending);
    f.a.close(f.context.root.domain, send).unwrap();
}
#[test]
fn authenticated_owner_full_process_control_and_exact_nonce_precede_any_revocation() {
    let mut f = fixture();
    let (mut entry, ticket, escaped) = enqueue(&mut f, 9);
    let wrong = Context {
        caller: f.target,
        ..f.context
    };
    assert_eq!(
        entry.retire(
            &mut f.a,
            &f.s,
            &f.r,
            wrong,
            f.process,
            9,
            &mut f.route,
            Some(ticket),
            &[],
            1
        ),
        Err(Error::Caller)
    );
    assert_eq!(
        entry.retire(
            &mut f.a,
            &f.s,
            &f.r,
            f.context,
            f.process,
            10,
            &mut f.route,
            Some(ticket),
            &[],
            1
        ),
        Err(Error::Nonce)
    );
    let fake =
        f.a.create_root(f.context.root.domain, Kind::Process, Rights::CONTROL)
            .unwrap();
    assert!(
        entry
            .retire(
                &mut f.a,
                &f.s,
                &f.r,
                f.context,
                fake,
                9,
                &mut f.route,
                Some(ticket),
                &[],
                1
            )
            .is_err()
    );
    f.a.close(f.context.root.domain, fake).unwrap();
    assert_eq!(f.route.pending(), 1);
    assert!(!entry.queue_cleared());
    assert!(
        f.a.authorize(f.receiver.domain, escaped, Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
    // Closing the forged object retains historical Authority rows; it cannot
    // mutate or revoke the real journal's owned branch or selected escrow.
    assert_eq!(
        retire(&mut f, &mut entry, Some(ticket), &[]),
        StateCode::Drained
    );
}
#[test]
fn delivered_rpc_deadline_and_retained_snapshot_fence_reuse_until_actual_completion() {
    let mut f = fixture();
    let (mut entry, ticket, escaped) = enqueue(&mut f, 11);
    let target = f.target.thread;
    dispatch(&mut f, target);
    let delivery = f
        .route
        .receive(&mut f.a, &f.s, &f.r, f.context.token, target, 1)
        .unwrap();
    entry.delivered(ticket, delivery.ticket);
    let send = delivery.capability.unwrap();
    let id = f
        .rpc
        .begin(
            &f.a,
            target,
            send,
            Deadline::after(0, 50).unwrap(),
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            1,
        )
        .unwrap();
    let credit = f.rpc.accepted_snapshot(id).unwrap();
    assert_eq!(credit.caller(), target);
    assert_eq!(credit.callee(), f.receiver.thread);
    assert_eq!(credit.endpoint(), entry.endpoint());
    assert_eq!(
        retire(&mut f, &mut entry, None, &[Some(credit)]),
        StateCode::RevokedPending
    );
    assert!(!entry.is_drained());
    assert!(
        f.a.authorize(f.target.domain, send, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    assert!(
        f.a.authorize(f.receiver.domain, escaped, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    source_live(&f);
    f.rpc.expire(50).unwrap();
    assert_eq!(f.rpc.outstanding(), 1);
    assert_eq!(
        retire(&mut f, &mut entry, None, &[Some(credit)]),
        StateCode::RevokedPending
    );
    f.rpc
        .complete_scalar(f.receiver.thread, id, 50, None)
        .unwrap();
    assert_eq!(f.rpc.outstanding(), 0);
    // Even removing Rpc's record is insufficient while native transport still
    // owns a window/accepted row. Only its actual release removes the snapshot.
    assert_eq!(
        retire(&mut f, &mut entry, None, &[Some(credit)]),
        StateCode::RevokedPending
    );
    assert_eq!(retire(&mut f, &mut entry, None, &[]), StateCode::Drained);
}
#[test]
fn actual_stopped_receipt_preserves_selected_policy_and_sequence_for_new_generation() {
    let mut f = fixture();
    let (mut entry, ticket, _) = enqueue(&mut f, 12);
    assert_eq!(
        retire(&mut f, &mut entry, Some(ticket), &[]),
        StateCode::Drained
    );
    f.s.terminate_process(f.target.process).unwrap();
    let stopped = f
        .route
        .into_stopped_route(&f.a, &f.s, &f.r)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(stopped.target_metadata(), f.target);
    entry.observe_stopped(&f.s, &f.r, &stopped, &[]).unwrap();
    f.r.retire_stopped(&mut f.a, &f.s, f.target.process)
        .unwrap();
    // Model executable owns no physical RAM; discharge its host-only metadata
    // charge after actual stopped authority, as native Reap does after detach.
    f.s.release_frames(f.target.job, f.target.frames).unwrap();
    let next =
        f.r.create_process(&mut f.a, &mut f.s, f.context.root.domain, f.child, f.image)
            .unwrap();
    f.r.delegate(&mut f.a, f.context.root.domain, next, f.inbox, 1)
        .unwrap();
    let target =
        f.r.model_admit_for_grant_test(&f.a, &mut f.s, f.context.root.domain, next)
            .unwrap();
    assert_ne!(target, f.target);
    let stopped = stopped
        .rebind(&f.a, &f.s, &f.r, f.context.token, f.process, 1, f.inbox)
        .err()
        .expect("old process cannot rebind")
        .owner;
    f.route = stopped
        .rebind(&f.a, &f.s, &f.r, f.context.token, next, 1, f.inbox)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    let (mut next_entry, send) =
        Entry::prepare(&mut f.a, &f.s, &f.r, f.context, next, f.source, 13).unwrap();
    let fresh = f
        .route
        .enqueue(
            &mut f.a,
            &f.s,
            &f.r,
            f.context.token,
            f.inbox,
            send,
            &13u64.to_le_bytes(),
            Deadline::after(2, 100).unwrap(),
            2,
        )
        .unwrap();
    assert!(fresh.0 > ticket.0);
    assert_eq!(f.route.target_metadata(), target);
    assert_eq!(
        next_entry.withdraw_owned(&mut f.a, &mut f.route, fresh, 3),
        StateCode::RevokedPending
    );
    source_live(&f);
}
