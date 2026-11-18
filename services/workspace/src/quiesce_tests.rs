use super::*;
use crate::control::{self, Command, Status};
use ev_userspace_contract::workspace as ns;

fn shutdown(token: u64, cut: u64) -> control::Request {
    control::Request {
        request_id: 91,
        deadline: Deadline::new(cut).unwrap(),
        command: Command::Quiesce { token },
    }
}
#[test]
fn terminal_control_codec_is_exact_token_cut_and_no_ordinary_frame_or_packet_authority() {
    let request = shutdown(55, 1000);
    let frame = request.encode().unwrap();
    assert_eq!(frame[8], 7);
    assert_eq!(control::Request::decode(&frame), Ok(request));
    assert_eq!(request.lease_epoch(), 55);
    let response = control::Response {
        request_id: 91,
        lease_epoch: 55,
        status: Status::Applied,
    };
    assert_eq!(
        control::Response::decode(&response.encode().unwrap())
            .unwrap()
            .matches(request),
        Ok(response)
    );
    assert!(
        control::Response {
            lease_epoch: 56,
            ..response
        }
        .matches(request)
        .is_err()
    );
    assert!(wire::Request::decode(&frame).is_err());
    assert!(ns::Request::decode(&frame).is_err());
    for i in [9, 10, 11, 15, 40, 48, 56, 64, 88, 96, 255] {
        let mut corrupt = frame;
        corrupt[i] = 1;
        assert!(control::Request::decode(&corrupt).is_err());
    }
    for token in [0, u64::MAX] {
        assert!(shutdown(token, 1000).encode().is_err());
    }
    let deadline = control::Response {
        status: Status::Deadline,
        ..response
    };
    assert_eq!(
        control::Response::decode(&deadline.encode().unwrap()),
        Ok(deadline)
    );
}

#[test]
fn actual_flush_precedes_applied_and_admission_stays_sealed_without_more_io() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let key = gateway.bind(route).unwrap();
    let files = NamespaceBinding {
        endpoint: EndpointId::new(50, 1).unwrap(),
        caller: Caller::new(80, 0).unwrap(),
        lease_epoch: 1,
        directory: ObjectId::ROOT,
        rights: NamespaceRights::Manage,
    };
    let namespace_key = gateway.bind_namespace(files).unwrap();
    let original = shutdown(55, 1000);
    let before = memory.counts();
    assert_eq!(gateway.quiesce(original, 100, false), Status::Applied);
    assert!(gateway.is_sealed());
    assert_eq!(memory.counts(), (before.0, before.1, before.2 + 1));
    let before = memory.counts();
    assert_eq!(
        gateway.quiesce(original, 2000, false),
        Status::Applied,
        "historical identical result, not renewed freshness"
    );
    for changed in [
        control::Request {
            request_id: 92,
            ..original
        },
        shutdown(56, 1000),
        shutdown(55, 2000),
    ] {
        assert_eq!(gateway.quiesce(changed, 100, false), Status::Stale);
    }
    let read = request(
        1,
        revision,
        wire::Method::Read {
            offset: 0,
            length: 1,
        },
    );
    let mut output = [0xa5];
    assert_eq!(
        reply(
            read,
            handle(&mut gateway, route, read, Loan::Read(&mut output))
        )
        .outcome,
        Outcome::Cancelled
    );
    assert_eq!(output, [0xa5]);
    assert_eq!(
        gateway.bind(binding(object, 8, Rights::ReadOnly)),
        Err(BindError::StorageFenced)
    );
    assert_eq!(gateway.revoke(key), Err(BindError::StorageFenced));
    assert_eq!(
        gateway.retire_quiescent(key, DEADLINE),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(
        gateway.revoke_namespace(namespace_key),
        Err(BindError::StorageFenced)
    );
    assert_eq!(
        gateway.check_namespace_quiescent(),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(
        gateway.retire_namespace_quiescent(namespace_key),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(gateway.bind_namespace(files), Err(BindError::StorageFenced));
    let create = ns::Request {
        request_id: 101,
        operation_id: 1,
        deadline: Deadline::new(1000).unwrap(),
        operation: ns::Operation::Create {
            directory: ns::ObjectId {
                slot: 0,
                generation: 1,
            },
            kind: ns::Kind::File,
            name: ns::Name::new(b"late.txt").unwrap(),
            expected_namespace_revision: gateway.namespace_revision(),
        },
    };
    let captured = Captured {
        endpoint: files.endpoint,
        caller: files.caller,
        lease_epoch: files.lease_epoch,
        now: 100,
    };
    let NamespaceDispatch::Complete { frame } = gateway
        .handle_namespace(captured, &create.encode().unwrap(), 0)
        .unwrap()
    else {
        panic!("terminal refusal");
    };
    assert_eq!(
        ns::client_decode(create, &frame, 0).unwrap().outcome,
        Outcome::Cancelled
    );
    assert_eq!(memory.counts(), before);
    assert!(gateway.into_storage().is_err());
}

#[test]
fn first_expired_or_fenced_attempt_is_a_permanent_zero_io_seal() {
    for (now, legacy_fenced, expected) in [
        (1000, false, Status::Deadline),
        (100, true, Status::Storage),
    ] {
        let memory = Memory::new();
        let mut ss = Box::new(StoreScratch::empty());
        let mut gs = Box::new(Scratch::empty());
        let (store, object, _) = dataset(memory.clone(), &mut ss);
        let mut gateway = Gateway::new(store, &mut gs);
        let before = memory.counts();
        assert_eq!(
            gateway.quiesce(shutdown(55, 1000), now, legacy_fenced),
            expected
        );
        assert!(gateway.is_sealed());
        assert_eq!(
            gateway.quiesce(shutdown(55, 2000), 100, false),
            Status::Stale
        );
        assert_eq!(
            gateway.bind(binding(object, 7, Rights::ReadOnly)),
            Err(BindError::StorageFenced)
        );
        assert_eq!(memory.counts(), before);
    }
}

#[test]
fn stage_or_accepted_commit_is_never_aborted_completed_or_flushed_by_quiesce() {
    for accepted in [false, true] {
        let memory = Memory::new();
        let mut ss = Box::new(StoreScratch::empty());
        let mut gs = Box::new(Scratch::empty());
        let (store, object, revision) = dataset(memory.clone(), &mut ss);
        let mut gateway = Gateway::new(store, &mut gs);
        let route = binding(object, 7, Rights::ReadWrite);
        gateway.bind(route).unwrap();
        let begin = request(
            1,
            revision,
            wire::Method::BeginWrite {
                length: 0,
                digest: hash(&[]),
            },
        );
        let transfer = reply(begin, handle(&mut gateway, route, begin, Loan::None)).transfer_id;
        let commit = request(
            2,
            revision,
            wire::Method::Commit {
                transfer_id: transfer,
                length: 0,
                digest: hash(&[]),
            },
        );
        if accepted {
            assert!(matches!(
                handle(&mut gateway, route, commit, Loan::None),
                Dispatch::Accepted { .. }
            ));
        }
        let pending = gateway.pending();
        let stage = gateway.store.pending_stage().unwrap();
        let before = memory.counts();
        assert_eq!(
            gateway.quiesce(shutdown(55, 1000), 100, false),
            Status::Busy
        );
        assert_eq!(gateway.pending(), pending);
        assert_eq!(gateway.store.pending_stage().unwrap(), stage);
        assert_eq!(gateway.owner_metadata(object).unwrap().revision, revision);
        assert_eq!(memory.counts(), before);
        if accepted {
            assert!(matches!(
                gateway.poll_commit(100).unwrap(),
                Dispatch::Retained { .. }
            ));
            assert_eq!(gateway.pending().unwrap().request, pending.unwrap().request);
            assert!(gateway.pending().unwrap().uncertain);
            assert_eq!(memory.counts(), before);
        }
    }
}

#[test]
fn uncertain_actual_flush_stays_retained_and_never_runs_again() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, _) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    memory.fail_next_flush_after_persist();
    let before = memory.counts();
    let original = shutdown(55, 1000);
    assert_eq!(gateway.quiesce(original, 100, false), Status::Uncertain);
    assert_eq!(memory.counts(), (before.0, before.1, before.2 + 1));
    let before = memory.counts();
    assert_eq!(gateway.quiesce(original, 101, false), Status::Uncertain);
    assert_eq!(
        gateway.quiesce(shutdown(55, 2000), 101, false),
        Status::Stale
    );
    assert_eq!(
        gateway.bind(binding(object, 7, Rights::ReadOnly)),
        Err(BindError::StorageFenced)
    );
    assert_eq!(memory.counts(), before);
    assert!(gateway.into_storage().is_err());
}

#[test]
fn preexisting_storage_uncertainty_is_preserved_and_no_flush_is_attempted() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 0,
            digest: hash(&[]),
        },
    );
    memory.fail_next_flush_after_persist();
    assert!(matches!(
        handle(&mut gateway, route, begin, Loan::None),
        Dispatch::Retained { .. }
    ));
    let pending = gateway.pending().unwrap();
    let before = memory.counts();
    assert_eq!(
        gateway.quiesce(shutdown(55, 1000), 100, false),
        Status::Storage
    );
    assert_eq!(gateway.pending().unwrap(), pending);
    assert_eq!(memory.counts(), before);
    assert!(matches!(
        handle(&mut gateway, route, begin, Loan::None),
        Dispatch::Retained { .. }
    ));
    assert_eq!(memory.counts(), before);
}

#[derive(Clone)]
struct CutDevice {
    memory: Memory,
    cuts: Rc<RefCell<std::vec::Vec<u64>>>,
}
impl SectorIo for CutDevice {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        self.memory.sectors()
    }
    fn read(&mut self, lba: u64, out: &mut Sector, cut: u64) -> Result<(), Fault> {
        self.memory.read(lba, out, cut)
    }
    fn write(&mut self, lba: u64, bytes: &Sector, cut: u64) -> Result<(), Fault> {
        self.memory.write(lba, bytes, cut)
    }
    fn flush(&mut self, cut: u64) -> Result<(), Fault> {
        self.cuts.borrow_mut().push(cut);
        self.memory.flush(cut)
    }
}
#[test]
fn terminal_flush_uses_the_one_original_absolute_cut_and_never_a_refreshed_cut() {
    let memory = Memory::new();
    let cuts = Rc::new(RefCell::new(std::vec::Vec::new()));
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, _, _) = dataset(memory.clone(), &mut ss);
    drop(store);
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let store = Dataset::open(
        CutDevice {
            memory,
            cuts: cuts.clone(),
        },
        &mut cold_scratch,
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("open"));
    let mut gateway = Gateway::new(store, &mut gs);
    assert!(cuts.borrow().is_empty());
    let original = shutdown(55, 344);
    assert_eq!(gateway.quiesce(original, 100, false), Status::Applied);
    assert_eq!(&*cuts.borrow(), &[344]);
    assert_eq!(
        gateway.quiesce(shutdown(55, 900), 101, false),
        Status::Stale
    );
    assert_eq!(&*cuts.borrow(), &[344]);
}
