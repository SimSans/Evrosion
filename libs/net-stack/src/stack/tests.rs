use super::*;
extern crate std;

#[test]
fn finite_storage_is_reported_separately_from_stack_owner_metadata() {
    std::eprintln!(
        "BORROWED_STORAGE_BYTES={BORROWED_STORAGE_BYTES} STACK_METADATA_BYTES={}",
        core::mem::size_of::<Stack<'static>>()
    );
}

fn with_stack(f: impl FnOnce(&mut Stack<'_>)) {
    let mut storage = Storage::EMPTY;
    let mut stack = Stack::new(
        7,
        [2, 0x45, 0x56, 0x52, 0, 1],
        0x12345678,
        0,
        storage.buffers(),
    )
    .unwrap();
    f(&mut stack);
}

#[test]
fn bounded_turn_emits_real_dhcp_from_the_actual_selected_stack() {
    with_stack(|stack| {
        stack.turn(0).unwrap();
        assert_eq!(stack.device.pending_tx(), 1);
        let frame = stack.device.begin_tx().unwrap().unwrap();
        assert_eq!(&frame[..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &[2, 0x45, 0x56, 0x52, 0, 1]);
        assert_eq!(&frame[12..14], &[8, 0]);
        assert_eq!(frame[23], 17); // IPv4 UDP
        assert_eq!(&frame[34..38], &[0, 68, 0, 67]); // DHCP client->server
        assert_eq!(&frame[278..282], &[0x63, 0x82, 0x53, 0x63]);
        assert!(frame.len() <= 1514);
        stack.device.complete_tx().unwrap();
        assert_eq!(stack.lease(), None); // A sent discover is not a lease.
    });
}

#[test]
fn one_turn_never_drains_an_unbounded_ingress_queue() {
    with_stack(|stack| {
        for _ in 0..4 {
            stack.device.enqueue_rx(&[0; 60]).unwrap();
        }
        stack.turn(0).unwrap();
        assert_eq!(stack.device.pending_rx(), 3);
        stack.turn(1).unwrap();
        assert_eq!(stack.device.pending_rx(), 2);
        stack.turn(2).unwrap();
        assert_eq!(stack.device.pending_rx(), 1);
    });
}

#[test]
fn time_regression_and_overflow_latch_without_new_output() {
    with_stack(|stack| {
        stack.turn(2).unwrap();
        let queued = stack.device.pending_tx();
        assert_eq!(stack.turn(1), Err(Error::Time));
        assert_eq!(stack.turn(3), Err(Error::Quarantined));
        assert_eq!(stack.device.pending_tx(), queued);
        assert_eq!(stack.query("example.test"), Err(Error::Quarantined));
    });
    with_stack(|stack| {
        assert_eq!(stack.turn(u64::MAX), Err(Error::Time));
        assert_eq!(stack.turn(0), Err(Error::Quarantined));
    });
}

#[test]
fn dns_query_tickets_prevent_upstream_free_slot_panics_and_replay() {
    with_stack(|stack| {
        stack
            .sockets
            .get_mut::<dns::Socket>(stack.dns)
            .update_servers(&[IpAddress::Ipv4(Ipv4Address::new(10, 0, 2, 3))]);
        let first = stack.query("one.test").unwrap();
        let second = stack.query("two.test").unwrap();
        assert_eq!(stack.query("third.test"), Err(Error::Capacity));
        assert_eq!(stack.query_result(first), Err(Error::QueryPending));
        stack.cancel_query(first).unwrap();
        assert_eq!(stack.query_result(first), Err(Error::StaleQuery));
        assert_eq!(stack.cancel_query(first), Err(Error::StaleQuery));
        let replacement = stack.query("new.test").unwrap();
        assert_ne!(replacement, first);
        assert_eq!(stack.cancel_query(first), Err(Error::StaleQuery));
        stack.cancel_query(replacement).unwrap();
        stack.cancel_query(second).unwrap();
        let foreign = Query {
            incarnation: 8,
            sequence: replacement.sequence,
        };
        assert_eq!(stack.query_result(foreign), Err(Error::StaleQuery));
    });
}

#[test]
fn exhausted_query_counter_refuses_before_socket_mutation() {
    with_stack(|stack| {
        stack.query_sequence = u64::MAX;
        assert_eq!(stack.query("example.test"), Err(Error::Counter));
        assert!(stack.pending.iter().all(Option::is_none));
    });
}
