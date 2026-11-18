//! Same actual authority/Scheduler/Rpc gate as scalar/Word4, no physical I/O.
use super::*;
fn byte_request(f: &Fixture) -> Request {
    Request {
        capability: f.caps[0],
        port: 0x3ee,
        width: 1,
    }
}
#[test]
fn four_bytes_use_one_existing_byte_port_and_reject_word_scope_and_bad_shapes() {
    let mut f = fixture();
    f.run(0);
    let req = byte_request(&f);
    assert_eq!(
        f.registry
            .input_bytes4(f.caller(), req, 1025, 1)
            .unwrap()
            .port(),
        0x3ee
    );
    let p = f
        .registry
        .output_bytes4(f.caller(), req, u32::MAX as u64, 1025, 1)
        .unwrap();
    assert_eq!((p.port(), p.value()), (0x3ee, u32::MAX));
    // The scope contains only this one byte port, not four consecutive ports.
    for width in [0, 2, 4, 8, u64::MAX] {
        assert_eq!(
            f.registry
                .input_bytes4(f.caller(), Request { width, ..req }, 5, 1)
                .err(),
            Some(Error::Width)
        );
    }
    for deadline in [0, 1, 1026, u64::MAX] {
        assert_eq!(
            f.registry.input_bytes4(f.caller(), req, deadline, 1).err(),
            Some(Error::Deadline)
        );
    }
    for port in [0x1e8, 0x300, 0x3ef, 65535, 65536, u64::MAX] {
        assert!(
            f.registry
                .input_bytes4(f.caller(), Request { port, ..req }, 5, 1)
                .is_err()
        );
    }
    assert_eq!(
        f.registry
            .output_bytes4(f.caller(), req, 1 << 32, 5, 1)
            .err(),
        Some(Error::Value)
    );
    assert_eq!(
        f.registry
            .output_bytes4(f.caller(), req, u64::MAX, 5, 1)
            .err(),
        Some(Error::Value)
    );
    assert_eq!(
        f.registry
            .input_words4(f.caller(), Request { width: 2, ..req }, 5, 1)
            .err(),
        Some(Error::Range)
    );
}
#[test]
fn byte_batch_preserves_current_domain_direction_kind_revocation_and_stop_gates() {
    let mut f = fixture();
    f.run(0);
    let cap =
        f.a.create_root(
            f.domains[0],
            Kind::IoPorts,
            Rights::CONTROL
                | Rights::READ
                | Rights::WRITE
                | Rights::DERIVE
                | Rights::TRANSFER
                | Rights::REVOKE,
        )
        .unwrap();
    f.registry
        .register(
            &f.a,
            f.domains[0],
            cap,
            &[Range {
                first: 0x310,
                last: 0x310,
                widths: Widths::BYTE,
                direction: Direction::Input,
            }],
        )
        .unwrap();
    let req = Request {
        capability: cap,
        port: 0x310,
        width: 1,
    };
    assert!(f.registry.input_bytes4(f.caller(), req, 5, 1).is_ok());
    assert_eq!(
        f.registry.output_bytes4(f.caller(), req, 0, 5, 1).err(),
        Some(Error::Direction)
    );
    let wrong =
        f.a.create_root(f.domains[0], Kind::Memory, Rights::READ)
            .unwrap();
    assert_eq!(
        f.registry
            .input_bytes4(
                f.caller(),
                Request {
                    capability: wrong,
                    ..req
                },
                5,
                1
            )
            .err(),
        Some(Error::Authority(capability::Error::WrongKind))
    );
    f.run(1);
    assert!(f.registry.input_bytes4(f.caller(), req, 5, 1).is_err());
    f.run(0);
    let read =
        f.a.derive(f.domains[0], cap, f.domains[1], Rights::READ)
            .unwrap();
    f.run(1);
    let req = Request {
        capability: read,
        ..req
    };
    assert!(f.registry.input_bytes4(f.caller(), req, 5, 1).is_ok());
    assert_eq!(
        f.registry.output_bytes4(f.caller(), req, 0, 5, 1).err(),
        Some(Error::Authority(capability::Error::Denied))
    );
    f.a.revoke(f.domains[0], cap).unwrap();
    assert_eq!(
        f.registry.input_bytes4(f.caller(), req, 5, 1).err(),
        Some(Error::Authority(capability::Error::Revoked))
    );
    f.s.exit(0).unwrap();
    assert_eq!(
        f.registry.input_bytes4(f.caller(), req, 5, 1).err(),
        Some(Error::Scheduler(scheduler::Error::CpuIdle))
    );
}
#[test]
fn exhausted_job_cannot_gain_a_current_caller_or_renew_an_expired_batch_cut() {
    let mut f = fixture();
    for thread in f.threads {
        let job =
            f.s.process_job(f.s.thread_process(thread).unwrap())
                .unwrap();
        f.s.configure_cpu_budget(job, 1, 4).unwrap();
    }
    f.run(0);
    let req = byte_request(&f);
    assert!(f.registry.input_bytes4(f.caller(), req, 3, 0).is_ok());
    f.s.charge_cpu(0, 1).unwrap();
    f.s.yield_cpu(0).unwrap();
    f.current = false;
    assert_eq!(
        f.registry.input_bytes4(f.caller(), req, 3, 1).err(),
        Some(Error::Scheduler(scheduler::Error::CpuIdle))
    );
    let peer = f.s.dispatch(0).unwrap().unwrap();
    assert_eq!(peer.thread, f.threads[1]);
    f.s.charge_cpu(0, 1).unwrap();
    f.s.yield_cpu(0).unwrap();
    assert!(f.s.dispatch(0).unwrap().is_none());
    f.s.advance(4).unwrap();
    f.run(0);
    assert_eq!(
        f.registry.input_bytes4(f.caller(), req, 3, 4).err(),
        Some(Error::Deadline)
    );
    assert!(f.registry.input_bytes4(f.caller(), req, 5, 4).is_ok()); // Separate later owner command, not a renewed old receipt.
}
