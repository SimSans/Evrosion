use crate::{ne2000 as nic, packet};

#[test]
fn packet_saturation_is_atomic_and_releasing_one_preserves_others() {
    let mut pool = packet::Pool::new(7).unwrap();
    let mut tickets = [None; packet::PACKET_SLOTS];
    for (index, ticket) in tickets.iter_mut().enumerate() {
        *ticket = Some(pool.insert(&[index as u8; 60]).unwrap());
    }
    assert_eq!(pool.pending(), 4);
    assert_eq!(pool.insert(&[9; 60]), Err(packet::Error::Full));
    assert_eq!(pool.insert(&[9; 1515]), Err(packet::Error::FrameLength));
    for (index, ticket) in tickets.iter().enumerate() {
        assert_eq!(pool.get(ticket.unwrap()).unwrap(), &[index as u8; 60]);
    }
    pool.release(tickets[1].unwrap()).unwrap();
    let replacement = pool.insert(&[5; 60]).unwrap();
    assert_eq!(pool.pending(), 4);
    assert_eq!(pool.get(replacement).unwrap(), &[5; 60]);
    assert_eq!(pool.get(tickets[1].unwrap()), Err(packet::Error::Stale));
    assert_eq!(pool.release(tickets[1].unwrap()), Err(packet::Error::Stale));
    assert_eq!(pool.get(replacement).unwrap(), &[5; 60]);
}

#[test]
fn packet_handles_cannot_cross_replacement_incarnations() {
    let mut old = packet::Pool::new(10).unwrap();
    let old_ticket = old.insert(&[1; 60]).unwrap();
    let mut new = packet::Pool::new(11).unwrap();
    let new_ticket = new.insert(&[2; 60]).unwrap();
    assert_eq!(new.get(old_ticket), Err(packet::Error::Stale));
    assert_eq!(new.release(old_ticket), Err(packet::Error::Stale));
    assert_eq!(old.get(new_ticket), Err(packet::Error::Stale));
    assert_eq!(new.get(new_ticket).unwrap(), &[2; 60]);
}

#[test]
fn release_and_retirement_clear_owned_storage_and_are_terminal() {
    let mut pool = packet::Pool::new(1).unwrap();
    let first = pool.insert(&[0xa5; 1514]).unwrap();
    assert!(!pool.all_scrubbed());
    pool.release(first).unwrap();
    assert!(pool.all_scrubbed());
    let second = pool.insert(&[0x6b; 60]).unwrap();
    pool.retire();
    assert_eq!(pool.pending(), 0);
    assert!(pool.all_scrubbed());
    assert_eq!(pool.get(second), Err(packet::Error::Retired));
    assert_eq!(pool.release(second), Err(packet::Error::Retired));
    assert_eq!(pool.insert(&[1; 60]), Err(packet::Error::Retired));
}

#[test]
fn invalid_frames_and_exhaustion_never_discard_existing_packets() {
    assert!(matches!(
        packet::Pool::new(0),
        Err(packet::Error::InvalidIncarnation)
    ));
    let mut pool = packet::Pool::new(1).unwrap();
    let ticket = pool.insert(&[7; 60]).unwrap();
    for len in [0, 1, 14, 59, 1515, 4096] {
        assert_eq!(
            pool.insert(&[1; 4096][..len]),
            Err(packet::Error::FrameLength)
        );
    }
    pool.set_generation_for_test(u64::MAX);
    assert_eq!(pool.insert(&[2; 60]), Err(packet::Error::Exhausted));
    assert_eq!(pool.pending(), 1);
    assert_eq!(pool.get(ticket).unwrap(), &[7; 60]);
    // Four1514-byte slots plus bounded metadata, with no heap allocation.
    assert!(core::mem::size_of::<packet::Pool>() <= 7 * 1024);
}

#[test]
fn receive_wraps_only_within_the_declared_device_ring() {
    // Last page, a full-size frame, six pages to next producer page0x4b.
    let rx = nic::receive(0x7f, 0x4b, [1, 0x4b, 0xee, 0x05]).unwrap();
    assert_eq!(rx.frame_bytes, 1514);
    assert_eq!(
        rx.first,
        nic::Span {
            address: 0x7f04,
            bytes: 252
        }
    );
    assert_eq!(
        rx.second,
        Some(nic::Span {
            address: 0x4600,
            bytes: 1262
        })
    );
    assert_eq!(rx.boundary, 0x4a);
    assert_eq!(rx.next_page, 0x4b);
    let single = nic::receive(0x7f, 0x46, [0x21, 0x46, 64, 0]).unwrap();
    assert_eq!(single.frame_bytes, 60);
    assert_eq!(single.first.bytes, 60);
    assert_eq!(single.second, None);
    assert_eq!(single.boundary, 0x7f);
}

#[test]
fn receive_refuses_corrupt_metadata_before_deriving_any_copy_or_ack() {
    for page in [0, 0x40, 0x45, 0x80, 0xff] {
        assert_eq!(
            nic::receive(page, 0x47, [1, 0x47, 64, 0]),
            Err(nic::Error::Page)
        );
        assert_eq!(
            nic::receive(0x46, page, [1, 0x47, 64, 0]),
            Err(nic::Error::Page)
        );
    }
    for status in [0, 2, 3, 0x40, 0x81, 0xff] {
        assert_eq!(
            nic::receive(0x46, 0x47, [status, 0x47, 64, 0]),
            Err(nic::Error::Status)
        );
    }
    for count in [0_u16, 3, 4, 17, 1519, u16::MAX] {
        let [lo, hi] = count.to_le_bytes();
        assert_eq!(
            nic::receive(0x46, 0x47, [1, 0x47, lo, hi]),
            Err(nic::Error::Count)
        );
    }
    assert_eq!(
        nic::receive(0x46, 0x47, [1, 0x46, 64, 0]),
        Err(nic::Error::NextPage)
    );
    assert_eq!(
        nic::receive(0x46, 0x46, [1, 0x47, 64, 0]),
        Err(nic::Error::NextPage)
    );
    // Honest next pointer alone cannot permit reading past the producer.
    assert_eq!(
        nic::receive(0x46, 0x47, [1, 0x4c, 0xee, 0x05]),
        Err(nic::Error::NextPage)
    );
}

#[test]
fn all_accepted_receive_spans_and_transmits_stay_in_device_packet_ram() {
    for page in nic::RX_START..nic::RX_STOP {
        for len in packet::MIN_RECEIVE_FRAME_BYTES..=packet::MAX_FRAME_BYTES {
            let count = len as u16 + 4;
            let pages = (count + 4).div_ceil(256);
            let next = 0x46 + ((u16::from(page - 0x46) + pages) % 58) as u8;
            let [lo, hi] = count.to_le_bytes();
            let rx = nic::receive(page, next, [1, next, lo, hi]).unwrap();
            let mut total = 0;
            for span in [Some(rx.first), rx.second].into_iter().flatten() {
                assert!(span.address >= 0x4600);
                assert!(u32::from(span.address) + u32::from(span.bytes) <= 0x8000);
                assert!(span.bytes != 0);
                total += usize::from(span.bytes);
            }
            assert_eq!(total, len);
            if len < packet::MIN_FRAME_BYTES {
                assert_eq!(nic::transmit(len), Err(nic::Error::FrameLength));
            } else {
                let tx = nic::transmit(len).unwrap();
                assert!(usize::from(tx.address) + len <= 0x4600);
            }
        }
    }
}

#[test]
fn stopped_status_requires_actual_stop_not_reset_complete_or_start() {
    assert_eq!(nic::verify_stopped(nic::STOP_COMMAND), Ok(()));
    for value in [0, 0x01, 0x22, 0x25, 0x61, nic::RESET_COMPLETED, 0xff] {
        assert_eq!(nic::verify_stopped(value), Err(nic::Error::NotStopped));
    }
    assert_eq!(nic::STOP_WRITES[0], (0, nic::STOP_COMMAND));
    assert!(nic::STOP_WRITES.iter().all(|(offset, _)| *offset < 0x10));
}

#[test]
fn fixed_poll_limits_survive_a_stalled_clock_and_busy_retries() {
    let mut poll = nic::PollBudget::new(5, 10, 3).unwrap();
    for _ in 0..3 {
        assert_eq!(poll.before_poll(5), Ok(()));
    }
    assert_eq!(poll.before_poll(5), Err(nic::Error::TimedOut));
    assert_eq!(poll.before_poll(6), Err(nic::Error::TimedOut));
    let mut deadline = nic::PollBudget::new(5, 10, 100).unwrap();
    assert_eq!(deadline.before_poll(14), Ok(()));
    assert_eq!(deadline.before_poll(15), Err(nic::Error::TimedOut));
    assert_eq!(deadline.before_poll(14), Err(nic::Error::TimedOut));
}

#[test]
fn bad_or_regressed_clocks_refuse_instead_of_extending_operation_time() {
    assert!(matches!(
        nic::PollBudget::new(1, 0, 1),
        Err(nic::Error::InvalidBudget)
    ));
    assert!(matches!(
        nic::PollBudget::new(1, 1, 0),
        Err(nic::Error::InvalidBudget)
    ));
    assert!(matches!(
        nic::PollBudget::new(u64::MAX, 1, 1),
        Err(nic::Error::InvalidBudget)
    ));
    let mut poll = nic::PollBudget::new(5, 10, 3).unwrap();
    assert_eq!(poll.before_poll(7), Ok(()));
    assert_eq!(poll.before_poll(6), Err(nic::Error::ClockRegression));
    assert_eq!(poll.before_poll(8), Err(nic::Error::ClockRegression));
}

#[test]
fn transmit_is_single_pending_and_rejects_duplicate_or_old_completion() {
    let mut tx = nic::Transmitter::new(2).unwrap();
    let first = tx.begin(60).unwrap();
    assert_eq!(tx.begin(60), Err(nic::Error::Busy));
    tx.complete(first, 2, 1).unwrap();
    assert_eq!(tx.complete(first, 2, 1), Err(nic::Error::Stale));
    let second = tx.begin(1514).unwrap();
    assert_eq!(tx.complete(first, 2, 1), Err(nic::Error::Stale));
    tx.complete(second, 2, 1).unwrap();
    let mut next = nic::Transmitter::new(3).unwrap();
    let third = next.begin(60).unwrap();
    assert_eq!(next.complete(second, 2, 1), Err(nic::Error::Stale));
    next.complete(third, 2, 1).unwrap();
}

#[test]
fn timeout_uncertainty_and_error_status_never_retry_an_accepted_transmit() {
    for status in [0, 2, 0x09, 0x11, 0x21, 0x41, 0x81] {
        let mut tx = nic::Transmitter::new(1).unwrap();
        let ticket = tx.begin(60).unwrap();
        assert_eq!(tx.complete(ticket, 2, status), Err(nic::Error::Status));
        assert_eq!(tx.begin(60), Err(nic::Error::Quarantined));
        assert_eq!(tx.complete(ticket, 2, 1), Err(nic::Error::Quarantined));
    }
    for isr in [0, 8, 10] {
        let mut tx = nic::Transmitter::new(1).unwrap();
        let ticket = tx.begin(60).unwrap();
        assert_eq!(tx.complete(ticket, isr, 1), Err(nic::Error::Status));
        assert_eq!(tx.begin(60), Err(nic::Error::Quarantined));
    }
    let mut tx = nic::Transmitter::new(1).unwrap();
    let ticket = tx.begin(60).unwrap();
    tx.quarantine();
    assert_eq!(tx.begin(60), Err(nic::Error::Quarantined));
    assert_eq!(tx.complete(ticket, 2, 1), Err(nic::Error::Quarantined));
}
