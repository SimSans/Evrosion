use super::*;
use crate::{
    Actor, Identity,
    app_data::session::{self as model, Admission, Enrollment, SendResult, Session, Target},
};
use ev_userspace_contract::{
    app_data as nd,
    root_v5::{
        child,
        graph::{Child, ImageSlot},
    },
};
use ev_zion::{
    Capability, CapabilityRequest, Contract, DataSchema, Package, Platform, Version,
    producer::{self, Spec},
};

fn package(app: u8, cap: bool, contract: bool) -> Vec<u8> {
    let contracts = [Contract {
        name: nd::INTERFACE,
        major: 1,
        minimum_minor: 0,
        features: 0,
    }];
    let capabilities = [CapabilityRequest {
        capability: Capability::AppPrivateData,
        required: true,
    }];
    producer::build(
        &Spec {
            app: AppId::new([app; 16]).unwrap(),
            name: "ND model fixture",
            source: "Not native execution",
            publisher: None,
            version: Version {
                major: 0,
                minor: 1,
                patch: 0,
            },
            build_id: [app; 32],
            platform: Platform {
                minimum: 1,
                target: 1,
            },
            abi: child::abi(ImageSlot::Editor.representative()),
            data_schema: DataSchema {
                current: 1,
                oldest_readable: 1,
            },
            entrypoint: "bin/main.elf",
            contracts: if contract { &contracts } else { &[] },
            capabilities: if cap { &capabilities } else { &[] },
        },
        include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf"),
        &[],
    )
    .unwrap()
}
fn actor(id: u64) -> Actor {
    Actor {
        control: id,
        identity: Identity {
            process: id + 1,
            thread: id + 2,
            registered: id + 3,
        },
        ready: false,
        mapping_epoch: 1,
        failed: false,
    }
}
fn enrollment(id: u64) -> Enrollment {
    let bytes = package(9, true, true);
    let package = Package::parse(&bytes).unwrap();
    Enrollment::captured(
        Child::EditorTwo,
        actor(id),
        Descriptor::for_enrolled_app(package.app().claimed_app, 1).unwrap(),
        &package,
        7,
    )
    .unwrap()
}
fn initial() -> AppDataEnvelope {
    AppDataEnvelope::initial(AppId::new([9; 16]).unwrap(), 1, 0).unwrap()
}
fn session() -> (Session, Enrollment) {
    let mut session = Session::new();
    let enrolled = enrollment(10);
    session.enroll(enrolled, initial(), 100, 8000).unwrap();
    (session, enrolled)
}
fn take_work(session: &mut Session, target: Target, request: nd::Request, now: u64) -> model::Work {
    let Admission::Work(work) = session.accept(target, request.encode(), now).unwrap() else {
        panic!("expected reserved executable work")
    };
    work
}
fn accept_reply(session: &mut Session, now: u64) {
    let reply = session.reply(now).unwrap().unwrap();
    session.sent(reply, SendResult::Accepted, now).unwrap();
}
fn read_completed(session: &mut Session, enrolled: Enrollment) {
    let work = take_work(session, enrolled.target, nd::Request::Read, 101);
    session.completed(work, initial(), 102).unwrap();
    accept_reply(session, 103);
}

#[test]
fn enrollment_checks_exact_owner_manifest_held_facts_and_contextual_provider() {
    let bytes = package(9, true, true);
    let parsed = Package::parse(&bytes).unwrap();
    let descriptor = Descriptor::for_enrolled_app(parsed.app().claimed_app, 1).unwrap();
    let loaded = crate::requirements::LoadedContracts {
        semantic_tree: true,
        file: None,
    };
    assert!(crate::requirements::file_app(&bytes, &loaded).is_err());
    for available in [false, true] {
        let support = crate::requirements::PrivateDataContracts::new(&loaded, available);
        assert_eq!(
            crate::requirements::private_file_app(&bytes, &support).is_ok(),
            available
        );
    }
    assert!(Enrollment::captured(Child::EditorTwo, actor(10), descriptor, &parsed, 7).is_some());
    for held in [
        Actor {
            ready: true,
            ..actor(10)
        },
        Actor {
            failed: true,
            ..actor(10)
        },
        Actor {
            control: 0,
            ..actor(10)
        },
    ] {
        assert!(Enrollment::captured(Child::EditorTwo, held, descriptor, &parsed, 7).is_none());
    }
    assert!(Enrollment::captured(Child::Files, actor(10), descriptor, &parsed, 7).is_none());
    assert!(
        Enrollment::captured(
            Child::EditorTwo,
            actor(10),
            Descriptor::for_enrolled_app(AppId::new([8; 16]).unwrap(), 1).unwrap(),
            &parsed,
            7
        )
        .is_none()
    );
    for (cap, contract) in [(false, true), (true, false)] {
        let bytes = package(9, cap, contract);
        let package = Package::parse(&bytes).unwrap();
        assert!(
            Enrollment::captured(Child::EditorTwo, actor(10), descriptor, &package, 7).is_none()
        );
    }
}
#[test]
fn foreign_sender_and_replayed_read_never_return_executable_work() {
    let (mut session, enrolled) = session();
    let foreign = Target::captured(Child::EditorOne, actor(30)).unwrap();
    assert_eq!(
        session.accept(foreign, nd::Request::SetValue(77).encode(), 101),
        Ok(Admission::ReplyReserved)
    );
    assert_eq!(
        nd::Response::decode(&session.reply(102).unwrap().unwrap().bytes, 0),
        Ok(nd::Response::Refused(nd::Refusal::Denied))
    );
    assert!(session.work().is_none());
    accept_reply(&mut session, 103);
    let work = take_work(&mut session, enrolled.target, nd::Request::Read, 104);
    session.completed(work, initial(), 105).unwrap();
    accept_reply(&mut session, 106);
    assert_eq!(
        session.accept(enrolled.target, nd::Request::Read.encode(), 107),
        Ok(Admission::ReplyReserved)
    );
    assert!(session.work().is_none());
    assert_eq!(
        nd::Response::decode(&session.reply(108).unwrap().unwrap().bytes, 0),
        Ok(nd::Response::Refused(nd::Refusal::Denied))
    );
}
#[test]
fn reservation_precedes_io_and_cannot_be_coalesced_or_overwritten() {
    let media = Rc::new(RefCell::new(Media::new()));
    let mut owner = owner(&media);
    prepare(&mut owner, initial().app());
    let (mut session, enrolled) = session();
    let work = take_work(&mut session, enrolled.target, nd::Request::Read, 101);
    let reserved = session.reply(102).unwrap().unwrap();
    let before = media.borrow().calls.len();
    assert_eq!(
        session.accept(enrolled.target, nd::Request::SetValue(7).encode(), 103),
        Err(model::Error::Retained)
    );
    assert_eq!(session.work(), Some(work));
    assert_eq!(session.reply(104).unwrap(), Some(reserved));
    assert_eq!(media.borrow().calls.len(), before);
    let value = model::execute(&mut owner, work).unwrap();
    session.completed(work, value, 105).unwrap();
    let reply = session.reply(106).unwrap().unwrap();
    let calls = media.borrow().calls.len();
    assert_eq!(
        nd::Response::decode(&reply.bytes, 0),
        Ok(nd::Response::Value(0))
    );
    session.sent(reply, SendResult::WouldBlock, 107).unwrap();
    assert_eq!(session.reply(108).unwrap(), Some(reply));
    assert_eq!(media.borrow().calls.len(), calls);
    session.sent(reply, SendResult::Accepted, 109).unwrap();
    let work = take_work(
        &mut session,
        enrolled.target,
        nd::Request::SetValue(77),
        110,
    );
    let value = model::execute(&mut owner, work).unwrap();
    assert_eq!((value.counter(), value.value()), (1, 77));
    session.completed(work, value, 111).unwrap();
    accept_reply(&mut session, 112);
    assert_eq!(
        session.accept(enrolled.target, nd::Request::SetValue(88).encode(), 113),
        Ok(Admission::ReplyReserved)
    );
    assert!(session.work().is_none());
}
#[test]
fn uncertain_reply_preserves_exact_bytes_and_is_never_sent_again() {
    let (mut session, enrolled) = session();
    let work = take_work(&mut session, enrolled.target, nd::Request::Read, 101);
    session.completed(work, initial(), 102).unwrap();
    let reply = session.reply(103).unwrap().unwrap();
    assert_eq!(
        session.sent(reply, SendResult::Unknown, 104),
        Err(model::Error::Retained)
    );
    assert_eq!(session.reply(105), Err(model::Error::Retained));
    assert!(session.has_reply());
    assert!(!session.receive_ready());
    assert!(!session.can_stop());
    assert_eq!(session.seal(106, 8001), Err(model::Error::Retained));
}
#[test]
fn accepted_storage_failure_keeps_operation_proposal_cut_and_window_owner_fenced() {
    let media = Rc::new(RefCell::new(Media::new()));
    let mut owner = owner(&media);
    prepare(&mut owner, initial().app());
    let (mut session, enrolled) = session();
    read_completed(&mut session, enrolled);
    let work = take_work(
        &mut session,
        enrolled.target,
        nd::Request::SetValue(77),
        104,
    );
    {
        let mut m = media.borrow_mut();
        m.fail_write = Some(m.writes + 2);
    }
    let failure = model::execute(&mut owner, work).unwrap_err();
    let pending = failure.pending.expect("exact accepted Store publication");
    assert_eq!(pending.proposal.value(), 77);
    assert_eq!(pending.proposal.counter(), 1);
    session.storage_failed(Some(pending));
    let calls = media.borrow().calls.len();
    assert_eq!(session.pending(), Some(pending));
    assert_eq!(session.work(), Some(work));
    assert_eq!(session.work().unwrap().original_cut, 8000);
    assert!(matches!(owner.status().phase, Phase::Retained(_)));
    assert!(!session.can_stop());
    assert_eq!(session.seal(105, 8001), Err(model::Error::Retained));
    assert_eq!(
        session.accept(enrolled.target, nd::Request::SetValue(88).encode(), 106),
        Err(model::Error::Retained)
    );
    assert_eq!(media.borrow().calls.len(), calls);
}
#[test]
fn completion_and_reply_use_original_cut_without_clock_or_deadline_renewal() {
    for late in [99, 8000, u64::MAX] {
        let (mut session, enrolled) = session();
        let work = take_work(&mut session, enrolled.target, nd::Request::Read, 101);
        assert_eq!(
            session.completed(work, initial(), late),
            Err(model::Error::Deadline)
        );
        assert_eq!(session.work(), Some(work));
        assert!(session.retained());
        assert!(!session.can_stop());
        assert_eq!(work.original_cut, 8000);
    }
}
#[test]
fn changed_actual_data_cannot_be_overwritten_using_only_an_old_counter() {
    let media = Rc::new(RefCell::new(Media::new()));
    let mut owner = owner(&media);
    prepare(&mut owner, initial().app());
    let (mut session, enrolled) = session();
    read_completed(&mut session, enrolled);
    let work = take_work(
        &mut session,
        enrolled.target,
        nd::Request::SetValue(77),
        104,
    );
    {
        let mut store = owner
            .open_mutable_namespace(
                Region::ExternalAppData,
                Access::ReadWrite,
                &data_creation(),
                8000,
            )
            .unwrap_or_else(|_| panic!("fixture"));
        let rewritten = AppDataEnvelope::initial(initial().app(), 1, 99)
            .unwrap()
            .encode();
        store
            .execute(
                store.next_operation().unwrap(),
                StoreRequest::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &rewritten,
                },
                8000,
            )
            .unwrap();
    }
    let before = media.borrow().physical.clone();
    let calls = media.borrow().calls.len();
    let failure = model::execute(&mut owner, work).unwrap_err();
    assert_eq!(failure.error, private_data::Error::Readback);
    assert!(failure.pending.is_none());
    assert_eq!(media.borrow().physical, before);
    assert!(
        media.borrow().calls[calls..]
            .iter()
            .all(|r| matches!(r, Request::Read { .. }))
    );
}
#[test]
fn foreign_pending_payload_refuses_before_any_recovery_write_in_nd_executor() {
    let media = Rc::new(RefCell::new(Media::new()));
    let mut owner = owner(&media);
    prepare(&mut owner, initial().app());
    {
        let mut store = owner
            .open_mutable_namespace(
                Region::ExternalAppData,
                Access::ReadWrite,
                &data_creation(),
                8000,
            )
            .unwrap_or_else(|_| panic!("fixture"));
        let foreign = AppDataEnvelope::initial(AppId::new([7; 16]).unwrap(), 1, 88)
            .unwrap()
            .encode();
        {
            let mut m = media.borrow_mut();
            m.fail_write = Some(m.writes + 2);
        }
        assert!(
            store
                .execute(
                    store.next_operation().unwrap(),
                    StoreRequest::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: &foreign
                    },
                    8000
                )
                .is_err()
        );
    }
    drop(owner);
    let before = media.borrow().physical.clone();
    let calls = media.borrow().calls.len();
    let mut cold = super::owner(&media);
    let (mut session, enrolled) = session();
    let work = take_work(&mut session, enrolled.target, nd::Request::Read, 101);
    assert!(model::execute(&mut cold, work).is_err());
    assert_eq!(media.borrow().physical, before);
    assert!(
        media.borrow().calls[calls..]
            .iter()
            .all(|r| matches!(r, Request::Read { .. }))
    );
}
#[test]
fn replacement_requires_actual_stop_then_empty_barrier_and_preserves_allocation() {
    let (mut session, enrolled) = session();
    read_completed(&mut session, enrolled);
    let replacement = enrollment(40);
    assert_eq!(
        session.can_enroll(replacement, 9000, 16000),
        Err(model::Error::State)
    );
    session.seal(9000, 16000).unwrap();
    session.events_empty(9001).unwrap();
    assert!(session.enrollment().is_some());
    assert_eq!(session.seal(9002, 16001), Err(model::Error::Identity));
    assert_eq!(
        session.accept(enrolled.target, nd::Request::Read.encode(), 9003),
        Ok(Admission::ReplyReserved)
    );
    accept_reply(&mut session, 9004);
    assert_eq!(
        session.stopped(replacement.target, 9005),
        Err(model::Error::Identity)
    );
    session.stopped(enrolled.target, 9006).unwrap();
    assert_eq!(
        session.accept(enrolled.target, nd::Request::SetValue(77).encode(), 9007),
        Ok(Admission::RetiredFrameDrained)
    );
    assert!(session.enrollment().is_some());
    session.events_empty(9008).unwrap();
    assert!(session.quiescent());
    assert_eq!(
        session.can_enroll(enrolled, 9010, 16000),
        Err(model::Error::Identity)
    );
    let mut foreign = replacement;
    foreign.descriptor = Descriptor::for_enrolled_app(AppId::new([8; 16]).unwrap(), 1).unwrap();
    assert_eq!(
        session.can_enroll(foreign, 9010, 16000),
        Err(model::Error::Identity)
    );
    session.enroll(replacement, initial(), 9011, 16000).unwrap();
    assert_eq!(session.enrollment(), Some(replacement));
}
#[test]
fn replacing_unenrolled_builtin_does_not_invent_an_nd_retirement_owner() {
    let mut session = Session::new();
    session.seal(100, 8000).unwrap();
    session.events_empty(101).unwrap();
    assert!(session.quiescent());
    let new = enrollment(40);
    session.enroll(new, initial(), 102, 8000).unwrap();
    assert_eq!(session.enrollment(), Some(new));
    assert!(!session.quiescent());
}
