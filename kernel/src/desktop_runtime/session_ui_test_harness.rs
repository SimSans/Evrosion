//! Host the exact diagnostic recognizers and independently encode actual public
//! service frames. This does not simulate protected routing or a live device.
#[path = "session_ui.rs"]
mod ui;

#[test]
fn barriers_match_actual_v2_input_codec_and_reject_legacy_or_malformed_frames() {
    use ev_input::{EnterState, PointerState, SessionBarrierReply, SessionBarrierRequest};
    for flags in 0..16u8 {
        for buttons in 0..64u8 {
            for (frame, sequence) in [(0, 0), (17, 29), (u32::MAX - 1, u32::MAX - 1)] {
                let request = SessionBarrierRequest::new(frame).unwrap().encode();
                let reply = SessionBarrierReply {
                    sequence,
                    enter: EnterState {
                        main_released: flags & 1 != 0,
                        keypad_released: flags & 2 != 0,
                        main_held: flags & 4 != 0,
                        keypad_held: flags & 8 != 0,
                    },
                    pointer: PointerState {
                        held: buttons & 7,
                        released: buttons >> 3,
                    },
                }
                .encode()
                .unwrap();
                let observed =
                    ui::barrier(u64::from_le_bytes(request), u64::from_le_bytes(reply)).unwrap();
                assert_eq!(
                    (
                        observed.frame,
                        observed.sequence,
                        observed.flags,
                        observed.buttons
                    ),
                    (frame, sequence, flags, buttons)
                );
                for (index, bit) in [(0, 1), (1, 1), (2, 16), (3, 64)] {
                    let mut bad = reply;
                    bad[index] ^= bit;
                    assert!(
                        ui::barrier(u64::from_le_bytes(request), u64::from_le_bytes(bad)).is_none()
                    );
                }
            }
        }
    }
    let request = SessionBarrierRequest::new(7).unwrap().encode();
    let mut reply = *b"B\x02\0\0\0\0\0\0";
    let mut legacy = request;
    legacy[3] = b'1';
    assert!(ui::barrier(u64::from_le_bytes(legacy), u64::from_le_bytes(reply)).is_none());
    reply[4..].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(ui::barrier(u64::from_le_bytes(request), u64::from_le_bytes(reply)).is_none());
}

#[test]
fn cursors_require_actual_codec_reply_matching_position_sequence_and_closed_geometry() {
    use ev_desktop::protocol::CursorControl;
    for x in [0, 255, 256, 319] {
        for y in [0, 199] {
            for sequence in [1, 73, u32::MAX - 1] {
                let cursor = CursorControl { x, y, sequence };
                let request = cursor.request().unwrap();
                let reply = cursor.reply().unwrap();
                let observed =
                    ui::cursor(u64::from_le_bytes(request), u64::from_le_bytes(reply)).unwrap();
                assert_eq!(
                    (observed.x, observed.y, observed.sequence),
                    (x, y, sequence)
                );
                assert!(
                    ui::cursor(u64::from_le_bytes(reply), u64::from_le_bytes(request)).is_none()
                );
                for index in 2..8 {
                    let mut other = reply;
                    other[index] ^= 1;
                    assert!(
                        ui::cursor(u64::from_le_bytes(request), u64::from_le_bytes(other))
                            .is_none()
                    );
                }
            }
        }
    }
    for (x, y, sequence) in [
        (320u16, 0u8, 1u32),
        (0, 200, 1),
        (0, 0, 0),
        (0, 0, u32::MAX),
    ] {
        let mut request = [b'C', 1 | ((x >> 8) as u8) << 2, x as u8, y, 0, 0, 0, 0];
        request[4..].copy_from_slice(&sequence.to_le_bytes());
        let mut reply = request;
        reply[1] = (request[1] & 4) | 2;
        assert!(CursorControl::parse_request(request).is_err());
        assert!(ui::cursor(u64::from_le_bytes(request), u64::from_le_bytes(reply)).is_none());
    }
}

#[test]
fn bounded_samples_keep_exact_cumulative_count_after_thirty_two_without_resetting() {
    let mut count = 0;
    for observed in 1..=80 {
        assert_eq!(ui::sample(&mut count), (observed <= 32).then_some(observed));
        assert_eq!(count, observed);
    }
}

#[test]
fn actual_v2_present_join_rejects_wrong_incarnation_frame_and_reserved_bits() {
    use ev_input::{EnterState, PointerState, SessionBarrierReply, SessionBarrierRequest};
    let request = u64::from_le_bytes(SessionBarrierRequest::new(3).unwrap().encode());
    let reply = u64::from_le_bytes(
        SessionBarrierReply {
            sequence: 22,
            enter: EnterState {
                main_held: true,
                ..EnterState::default()
            },
            pointer: PointerState {
                held: 0,
                released: 7,
            },
        }
        .encode()
        .unwrap(),
    );
    let mut count = 0;
    for (caller, presented, frame) in [(0, 0, 3), (6, 7, 3), (7, 6, 3), (6, 6, 2), (6, 6, 4)] {
        assert!(
            ui::barrier_at_present(request, reply, caller, presented, frame, &mut count).is_none()
        );
        assert_eq!(count, 0);
    }
    let joined = ui::barrier_at_present(request, reply, 6, 6, 3, &mut count).unwrap();
    assert_eq!(
        (
            joined.fields.frame,
            joined.fields.flags,
            joined.fields.buttons,
            joined.sample
        ),
        (3, 4, 56, Some(1))
    );
    let malformed = reply | (1 << 23);
    assert!(ui::barrier_at_present(request, malformed, 6, 6, 3, &mut count).is_none());
    assert_eq!(count, 1);
}

#[test]
fn thirty_third_actual_barrier_still_returns_fresh_operational_fields_without_serial_sample() {
    use ev_input::{EnterState, PointerState, SessionBarrierReply, SessionBarrierRequest};
    let mut count = 0;
    for frame in 1..=40 {
        let request = u64::from_le_bytes(SessionBarrierRequest::new(frame).unwrap().encode());
        let reply = u64::from_le_bytes(
            SessionBarrierReply {
                sequence: frame + 10,
                enter: EnterState {
                    main_held: frame % 2 == 0,
                    ..EnterState::default()
                },
                pointer: PointerState {
                    held: 0,
                    released: 7,
                },
            }
            .encode()
            .unwrap(),
        );
        let update =
            ui::barrier_at_present(request, reply, 6, 6, u64::from(frame), &mut count).unwrap();
        assert_eq!(update.fields.frame, frame);
        assert_eq!(update.fields.sequence, frame + 10);
        assert_eq!(update.fields.flags, if frame % 2 == 0 { 4 } else { 0 });
        assert_eq!(update.sample, (frame <= 32).then_some(u64::from(frame)));
    }
    assert_eq!(count, 40);
}

#[test]
fn counter_exhaustion_never_wraps_or_restarts_diagnostic_sampling() {
    let mut count = u64::MAX;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ui::sample(&mut count))).is_err()
    );
    assert_eq!(count, u64::MAX);
}
