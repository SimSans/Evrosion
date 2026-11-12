//! Actual Authority/Scheduler/Registry/SelectedReadRoute component model only.
//! Test-only admission releases no real hardware image and proves no consent,
//! durable policy, boot epoch or physical protected execution.
extern crate std;
use super::*;
use crate::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    incarnation::{Bindings, Target},
    ipc::Reclaimed,
    scheduler::Limits,
    service::{Role, SERVICE_LIMITS, ServiceImage},
    user_context::{Call, UserContext, decode},
};
use core::num::NonZeroU64;
use sha2::{Digest, Sha256};
fn common() -> Rights {
    Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE
}
struct TestImage(crate::loaded_image::Information);
// SAFETY: explicit host-only model of exact retained startup/layout metadata.
// This model never dereferences RAM, executes Ring3, or claims hardware PTEs.
#[allow(unsafe_code)]
unsafe impl crate::loaded_image::LoadedExecutable for TestImage {
    fn information(&self) -> crate::loaded_image::Information {
        self.0
    }
}
struct Fixture {
    a: Authority,
    s: Scheduler,
    r: Registry<'static>,
    context: Context,
    route: SelectedReadRoute,
    request: Request,
    last: u32,
    awaiting: Option<Metadata>,
    active: Option<(Metadata, u32)>,
    running: crate::service::Running<TestImage>,
}
fn fixture() -> Fixture {
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let memory = a
        .create_root(custody, Kind::Memory, Rights::READ | common())
        .unwrap();
    let endpoint = a
        .create_root(custody, Kind::Endpoint, Rights::SEND | common())
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
    let bytes = include_bytes!("../../../fixtures/bootstrap-whole-object-v1.bin");
    let manifest =
        bootstrap_manifest::verify(bytes, Sha256::digest(bytes).into(), b"abc", [42; 32]).unwrap();
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(manifest.limits()).unwrap();
    let process = s.create_held_process(job).unwrap();
    let thread = s.create_thread(process).unwrap();
    let owner = a.create_space().unwrap();
    let branches = a.create_space().unwrap();
    let mut binding = Bindings::new(NonZeroU64::new(601).unwrap(), &manifest, custody, &catalog);
    let token = binding
        .prepare(
            &mut a,
            &s,
            Target {
                process,
                job,
                destination: owner,
                branches,
            },
        )
        .unwrap();
    // Model admission only, deliberately no LoadedExecutable/hardware claim.
    s.admit_bootstrap(process, job, thread, 0).unwrap();
    let root = Metadata {
        process,
        thread,
        job,
        domain: owner,
        frames: 0,
    };
    let creator = a
        .create_root(owner, Kind::Job, Rights::CONTROL | common())
        .unwrap();
    let image = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
    let parent = s
        .create_job_with_limits(Limits::new(1000, 64, 4, 8))
        .unwrap();
    let mut r = Registry::new();
    r.register_job(&a, owner, creator, parent).unwrap();
    let elf = include_bytes!("../../../fixtures/bootstrap-static-v1.elf");
    r.register_image(
        &a,
        owner,
        image,
        ServiceImage::verify(
            elf,
            Sha256::digest(elf).into(),
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
    let app_job = r.create_job(&mut a, &mut s, owner, creator, 0).unwrap();
    let (inbox, mailbox) = r.create_channel(&mut a, owner, app_job).unwrap();
    let inbox_send = a.derive(owner, inbox, owner, Rights::SEND).unwrap();
    let app_cap = r
        .create_process(&mut a, &mut s, owner, app_job, image)
        .unwrap();
    r.delegate(&mut a, owner, app_cap, inbox, 1).unwrap();
    let app = r.metadata(&a, owner, app_cap).unwrap();
    let plan = r.plan(&a, owner, app_cap).unwrap();
    let startup = r
        .startup(&a, owner, app_cap, NonZeroU64::new(601).unwrap())
        .unwrap();
    let loaded = TestImage(crate::loaded_image::Information {
        process: app.process,
        manifest: plan.manifest_digest(),
        entry: plan.entry(),
        stack: plan.stack_top(),
        root: 4096,
        frames: plan.required_frames(),
        startup: Some(crate::loaded_image::Startup {
            address: plan.bootstrap_page().unwrap(),
            bytes: startup.len(),
            digest: Sha256::digest(startup).into(),
        }),
    });
    let running = r
        .start(
            &a,
            &mut s,
            owner,
            app_cap,
            NonZeroU64::new(601).unwrap(),
            loaded,
        )
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    let file_job = s.create_job().unwrap();
    let file_process = s.create_process(file_job).unwrap();
    let file_thread = s.create_thread(file_process).unwrap();
    let file = Metadata {
        process: file_process,
        thread: file_thread,
        job: file_job,
        domain: a.create_space().unwrap(),
        frames: 0,
    };
    let notes = a
        .create_root(
            owner,
            Kind::Endpoint,
            Rights::SEND | Rights::CONTROL | common(),
        )
        .unwrap();
    let private = a
        .create_root(
            owner,
            Kind::Endpoint,
            Rights::SEND | Rights::CONTROL | common(),
        )
        .unwrap();
    let read_sources = [notes, private].map(|source| Wire {
        object: a
            .authorize(owner, source, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity(),
        receiver: file.domain,
        bound: Some(file.thread),
        closed: false,
    });
    let inbox_wire = Wire {
        object: a
            .authorize(owner, inbox, Kind::Endpoint, Rights::CONTROL)
            .unwrap()
            .identity(),
        receiver: app.domain,
        bound: Some(app.thread),
        closed: false,
    };
    let route =
        SelectedReadRoute::from_managed(&a, &s, &r, token, owner, app_cap, 1, inbox, mailbox)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
    assert_eq!(s.dispatch(0).unwrap().unwrap().thread, root.thread);
    Fixture {
        a,
        s,
        r,
        context: Context {
            mode: Mode::ManagedNative3,
            caller: root,
            root,
            token,
            app,
            file,
            read_sources,
            inbox: inbox_wire,
            selection_submitted: false,
        },
        route,
        request: Request {
            process: app_cap,
            source: notes,
            inbox: inbox_send,
            nonce: 1,
        },
        last: 0,
        awaiting: Some(app),
        active: None,
        running,
    }
}
fn handoff(f: &mut Fixture) -> Result<Queued, Error> {
    handoff_at(f, 0)
}
fn handoff_at(f: &mut Fixture, now: u64) -> Result<Queued, Error> {
    enqueue(
        &mut f.a,
        &f.s,
        &f.r,
        &f.context,
        Open {
            last_nonce: &mut f.last,
            awaiting: &mut f.awaiting,
            active: &mut f.active,
        },
        None,
        &mut f.route,
        f.request,
        Deadline::after(0, 100).unwrap(),
        now,
    )
}
fn refused_unchanged(f: &mut Fixture) {
    let usage = f.a.metadata_usage();
    let state = (f.last, f.awaiting, f.active);
    assert!(handoff(f).is_err());
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!((f.last, f.awaiting, f.active), state);
    assert_eq!(f.route.pending(), 0);
}
#[test]
fn op44_decodes_four_scalars_and_never_aliases_legacy_selection41() {
    let mut frame = UserContext::ZERO;
    frame.registers[14] = OPCODE;
    frame.registers[8] = 101;
    frame.registers[9] = 202;
    frame.registers[11] = 303;
    frame.registers[5] = 7;
    assert_eq!(
        decode(&frame),
        Ok(Call::EnqueueManagedRead {
            process: Handle(101),
            source: Handle(202),
            inbox: Handle(303),
            nonce: 7
        })
    );
    for nonce in [0, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        frame.registers[5] = nonce;
        assert!(decode(&frame).is_err());
    }
    frame.registers[14] = 41;
    frame.registers[5] = 7;
    assert!(decode(&frame).is_err());
}
#[test]
fn fresh_managed_lineage_delivers_only_send8_after_real_receive_without_gui_selection() {
    let mut f = fixture();
    let source = f.request.source;
    let queued = handoff(&mut f).unwrap();
    assert_eq!(f.last, 1);
    assert!(f.awaiting.is_none());
    assert_eq!(f.active, None);
    assert!(!f.context.selection_submitted);
    assert_eq!(f.route.pending(), 1);
    assert_eq!(
        f.a.authorize(f.context.root.domain, source, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity(),
        queued.source_object
    );
    f.s.yield_cpu(0).unwrap();
    assert_eq!(
        f.s.dispatch(0).unwrap().unwrap().thread,
        f.context.app.thread
    );
    let delivery = f
        .route
        .receive(
            &mut f.a,
            &f.s,
            &f.r,
            f.context.token,
            f.context.app.thread,
            1,
        )
        .unwrap();
    assert_eq!(delivery.ticket, queued.ticket);
    assert_eq!(&delivery.bytes[..delivery.length], b"EVREAD01");
    let leaf = delivery.capability.unwrap();
    let access =
        f.a.authorize(f.context.app.domain, leaf, Kind::Endpoint, Rights::SEND)
            .unwrap();
    assert_eq!(access.identity(), queued.source_object);
    assert_eq!(access.rights(), Rights::SEND);
    assert!(
        f.a.transfer(f.context.app.domain, leaf, f.context.root.domain)
            .is_err()
    );
    assert!(
        f.a.derive(
            f.context.app.domain,
            leaf,
            f.context.app.domain,
            Rights::SEND
        )
        .is_err()
    );
    queued
        .branch
        .retire(&mut f.a)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    assert!(
        f.a.authorize(f.context.app.domain, leaf, Kind::Endpoint, Rights::SEND)
            .is_err()
    );
    assert!(
        f.a.authorize(f.context.root.domain, source, Kind::Endpoint, Rights::SEND)
            .is_ok()
    );
}
#[test]
fn native2_nonroot_stale_nonce_and_submitted_selection_refuse_before_lineage_or_queue_changes() {
    for mode in 0..7 {
        let mut f = fixture();
        match mode {
            0 => f.context.mode = Mode::SelectionOnly,
            1 => f.context.caller = f.context.app,
            2 => f.awaiting = None,
            3 => f.last = 1,
            4 => f.context.selection_submitted = true,
            5 => f.active = Some((f.context.app, 1)),
            _ => f.awaiting = Some(f.context.file),
        };
        refused_unchanged(&mut f);
    }
}
#[test]
fn wrong_or_revoked_process_source_inbox_and_file_receiver_are_denied_without_mutation() {
    for mode in 0..9 {
        let mut f = fixture();
        match mode {
            0 => f.request.process = Handle(u64::MAX),
            1 => f.request.source = Handle(u64::MAX),
            2 => f.request.inbox = Handle(u64::MAX),
            3 => f.context.read_sources[0].closed = true,
            4 => f.context.read_sources[0].receiver = f.context.app.domain,
            5 => f.context.read_sources[0].bound = Some(f.context.app.thread),
            6 => {
                let wrong =
                    f.a.create_root(
                        f.context.root.domain,
                        Kind::Endpoint,
                        Rights::SEND | common(),
                    )
                    .unwrap();
                f.request.source = wrong;
            }
            7 => {
                let attenuated =
                    f.a.derive(
                        f.context.root.domain,
                        f.request.source,
                        f.context.root.domain,
                        Rights::SEND,
                    )
                    .unwrap();
                f.request.source = attenuated;
            }
            _ => {
                f.a.revoke(f.context.root.domain, f.request.process)
                    .unwrap();
            }
        };
        refused_unchanged(&mut f);
    }
}
#[test]
fn dead_app_and_old_inbox_receipts_cannot_remint_to_another_recipient() {
    let mut f = fixture();
    f.s.terminate_process(f.context.app.process).unwrap();
    refused_unchanged(&mut f);
    let mut f = fixture();
    f.context.inbox.receiver = f.context.file.domain;
    refused_unchanged(&mut f);
    let mut f = fixture();
    f.context.inbox.bound = Some(f.context.file.thread);
    refused_unchanged(&mut f);
    let mut f = fixture();
    f.context.inbox.closed = true;
    refused_unchanged(&mut f);
}
#[test]
fn busy_pending_branch_and_accepted_queue_preserve_nonce_and_source_for_exact_retry() {
    let mut f = fixture();
    let (branch, held_one_shot) =
        f.r.prepare_active_send(
            &mut f.a,
            &f.s,
            f.context.root.domain,
            f.request.process,
            f.request.source,
        )
        .unwrap();
    let usage = f.a.metadata_usage();
    let state = (f.last, f.awaiting, f.active);
    assert!(matches!(
        enqueue(
            &mut f.a,
            &f.s,
            &f.r,
            &f.context,
            Open {
                last_nonce: &mut f.last,
                awaiting: &mut f.awaiting,
                active: &mut f.active
            },
            Some(&branch),
            &mut f.route,
            f.request,
            Deadline::after(0, 100).unwrap(),
            0
        ),
        Err(Error::Busy)
    ));
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!((f.last, f.awaiting, f.active), state);
    f.a.close(f.context.root.domain, held_one_shot).unwrap();
    branch
        .retire(&mut f.a)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    let mut f = fixture();
    let (branch, one_shot) =
        f.r.prepare_active_send(
            &mut f.a,
            &f.s,
            f.context.root.domain,
            f.request.process,
            f.request.source,
        )
        .unwrap();
    let ticket = f
        .route
        .enqueue(
            &mut f.a,
            &f.s,
            &f.r,
            f.context.token,
            f.request.inbox,
            one_shot,
            b"EVREAD01",
            Deadline::after(0, 100).unwrap(),
            0,
        )
        .unwrap();
    let usage = f.a.metadata_usage();
    assert!(matches!(handoff(&mut f), Err(Error::Busy)));
    assert_eq!(f.last, 0);
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!(f.route.pending(), 1);
    let Reclaimed::Capability(cap) = f.route.cancel(&mut f.a, ticket, 1).unwrap() else {
        panic!("original source cap");
    };
    f.a.close(f.context.root.domain, cap).unwrap();
    branch
        .retire(&mut f.a)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    let queued = handoff_at(&mut f, 2).unwrap();
    assert_eq!(f.last, 1);
    assert_ne!(queued.ticket, ticket);
}
#[test]
fn stopped_receiver_returns_queued_one_shot_before_private_branch_and_mailbox_retirement() {
    let mut f = fixture();
    let queued = handoff(&mut f).unwrap();
    f.s.terminate_process(f.context.app.process).unwrap();
    f.route.receiver_died(&f.s).unwrap();
    let Reclaimed::Capability(cap) = f.route.reclaim(&mut f.a, queued.ticket, 1).unwrap() else {
        panic!("exact queued one-shot");
    };
    f.a.close(f.context.root.domain, cap).unwrap();
    queued
        .branch
        .retire(&mut f.a)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
    assert_eq!(f.route.pending(), 0);
    let _mailbox = f
        .route
        .into_stopped_mailbox(&f.a, &f.s, &f.r)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
}
#[test]
fn expired_route_preflight_preserves_fresh_nonce_and_all_authority_before_branch_creation() {
    let mut f = fixture();
    let usage = f.a.metadata_usage();
    let state = (f.last, f.awaiting, f.active);
    assert!(matches!(
        handoff_at(&mut f, 100),
        Err(Error::Route(live_grant::Error::Ipc(IpcError::Expired)))
    ));
    assert_eq!(f.a.metadata_usage(), usage);
    assert_eq!((f.last, f.awaiting, f.active), state);
    assert_eq!(f.route.pending(), 0);
}

#[test]
fn actual_dispatch_inhibition_refuses_remint_without_consuming_pending_open_or_lineage() {
    let mut f = fixture();
    f.s.inhibit_process(f.context.app.process).unwrap();
    assert_eq!(f.s.dispatch_inhibited(f.context.app.process), Ok(true));
    refused_unchanged(&mut f);
}

fn inhibit_context(f: &Fixture) -> InhibitContext {
    InhibitContext {
        mode: f.context.mode,
        caller: f.context.caller,
        root: f.context.root,
        token: f.context.token,
        app: f.context.app,
    }
}
#[test]
fn inhibit_requires_actual_root_current_control_and_refuses_modes_without_mutation() {
    for case in 0..4 {
        let mut f = fixture();
        let mut c = inhibit_context(&f);
        let mut cap = f.request.process;
        match case {
            0 => c.mode = Mode::SelectionOnly,
            1 => c.caller = f.context.file,
            2 => cap = f.request.source,
            _ => {
                f.s.yield_cpu(0).unwrap();
            }
        }
        let usage = f.a.metadata_usage();
        let rpc = crate::rpc::Rpc::new(NonZeroU64::new(601).unwrap());
        assert!(inhibit(&f.a, &mut f.s, &f.r, &rpc, &c, cap, &mut f.running).is_err());
        assert_eq!(f.s.dispatch_inhibited(c.app.process), Ok(false));
        assert_eq!(f.a.metadata_usage(), usage);
    }
}
#[test]
fn accepted_app_callee_is_busy_before_inhibition_then_real_completion_allows_gate() {
    use crate::rpc::{MessageShape, Policy, Rpc, Status};
    let mut f = fixture();
    let c = inhibit_context(&f);
    let mut rpc = Rpc::new(NonZeroU64::new(601).unwrap());
    for m in [c.app, f.context.file] {
        rpc.register_thread(&f.a, &f.s, m.thread, m.job, m.domain, None)
            .unwrap();
    }
    let endpoint =
        f.a.create_root(
            f.context.file.domain,
            Kind::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::CONTROL | common(),
        )
        .unwrap();
    let receive =
        f.a.derive(
            f.context.file.domain,
            endpoint,
            c.app.domain,
            Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap();
    rpc.bind_endpoint(
        &f.a,
        c.app.domain,
        receive,
        c.app.thread,
        Policy::new(8, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(f.s.dispatch(1).unwrap().unwrap().thread, c.app.thread);
    f.s.yield_cpu(1).unwrap();
    assert_eq!(
        f.s.dispatch(1).unwrap().unwrap().thread,
        f.context.file.thread
    );
    let deadline = Deadline::after(0, 100).unwrap();
    let call = rpc
        .begin(
            &f.a,
            f.context.file.thread,
            endpoint,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            0,
        )
        .unwrap();
    let wait = f.s.block(1, deadline).unwrap();
    let before = f.a.metadata_usage();
    assert_eq!(
        inhibit(
            &f.a,
            &mut f.s,
            &f.r,
            &rpc,
            &c,
            f.request.process,
            &mut f.running
        ),
        Err(Error::Busy)
    );
    assert_eq!(f.s.dispatch_inhibited(c.app.process), Ok(false));
    assert_eq!(rpc.outstanding(), 1);
    assert_eq!(f.a.metadata_usage(), before);
    assert!(f.s.waiting(wait));
    assert_eq!(f.s.dispatch(1).unwrap().unwrap().thread, c.app.thread);
    let completion = rpc.complete(c.app.thread, call, 1).unwrap();
    assert_eq!(completion.status, Status::Ok);
    assert!(f.s.wake(wait));
    f.s.yield_cpu(1).unwrap();
    inhibit(
        &f.a,
        &mut f.s,
        &f.r,
        &rpc,
        &c,
        f.request.process,
        &mut f.running,
    )
    .unwrap();
    assert_eq!(f.s.dispatch_inhibited(c.app.process), Ok(true));
    assert_eq!(rpc.outstanding(), 0);
}
#[test]
fn inhibit45_decoder_rejects_reserved_operands_and_keeps_legacy_r10_uninterpreted() {
    let mut f = UserContext::ZERO;
    f.registers[14] = ev_userspace_contract::syscall::INHIBIT_MANAGED_PROCESS;
    f.registers[8] = 83;
    f.registers[5] = 0x397e_7842_eda1_67bf;
    assert_eq!(decode(&f), Ok(Call::InhibitManagedProcess(Handle(83))));
    for index in [9, 11] {
        let mut bad = f;
        bad.registers[index] = 1;
        assert!(decode(&bad).is_err());
    }
}

#[test]
fn current_authenticated_unselected_gui_open_can_be_consumed_by_owner_handoff_once() {
    let mut f = fixture();
    f.last = f.request.nonce;
    f.awaiting = None;
    f.active = Some((f.context.app, f.request.nonce));
    let queued = handoff(&mut f).unwrap();
    assert_eq!(queued.nonce, 1);
    assert_eq!((f.awaiting, f.active), (None, None));
    assert_eq!(f.last, 1);
    // The actual managed request owns the queue/lineage. Even after delivery,
    // the consumed Open cannot be replayed with the same or a larger nonce.
    let delivered = f
        .route
        .receive(
            &mut f.a,
            &f.s,
            &f.r,
            f.context.token,
            f.context.app.thread,
            1,
        )
        .unwrap();
    assert_eq!(delivered.ticket, queued.ticket);
    assert!(handoff(&mut f).is_err());
    f.request.nonce = 2;
    assert!(handoff(&mut f).is_err());
}
#[test]
fn existing_open_wrong_app_nonce_or_submitted_selection_refuses_without_consumption() {
    for case in 0..4 {
        let mut f = fixture();
        f.last = 1;
        f.awaiting = None;
        f.active = Some((f.context.app, 1));
        match case {
            0 => f.active = Some((f.context.file, 1)),
            1 => f.request.nonce = 2,
            2 => f.context.selection_submitted = true,
            _ => f.active = None,
        }
        let state = (f.last, f.awaiting, f.active);
        let usage = f.a.metadata_usage();
        assert!(handoff(&mut f).is_err());
        assert_eq!((f.last, f.awaiting, f.active), state);
        assert_eq!(f.a.metadata_usage(), usage);
    }
}
