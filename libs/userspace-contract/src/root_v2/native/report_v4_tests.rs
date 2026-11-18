use super::*;

fn snapshot() -> Snapshot {
    Snapshot {
        operation: Operation::Stage,
        result: ResultCode::Ok,
        installed: true,
        active: Slot::A,
        staged: Slot::B,
        previous: Slot::None,
        process: u64::MAX - 1,
        thread: 1 << 40,
        revision: 3,
        data_epoch: 1,
        data_counter: 0,
        value: 1001,
        mutations: 17,
        recovery: false,
    }
}
#[test]
fn v1_exact_golden_bytes_remain_unchanged_and_never_accept_downloaded_slots() {
    let s = snapshot();
    let mut frames = Frames::new(0x01020304, s).unwrap();
    let mut decoder = Decoder::new();
    // Independent fixed v1 transcript: serial,13 payload words,serial.
    let words: [u32; 15] = [
        0x01020304,
        0x4c04,
        0xffff_fffe,
        0xffff_ffff,
        0,
        0x100,
        3,
        0,
        1,
        0,
        0,
        1001,
        17,
        0,
        0x01020304,
    ];
    for (i, word) in words.into_iter().enumerate() {
        let expected = [
            b'N',
            b'R',
            1,
            if i == 14 { 255 } else { i as u8 },
            word as u8,
            (word >> 8) as u8,
            (word >> 16) as u8,
            (word >> 24) as u8,
        ];
        assert_eq!(frames.next_frame(), Some(expected));
        assert_eq!(decoder.accept(expected), Ok((i == 14).then_some(s)));
    }
    assert!(frames.complete());
    assert!(frames.next_frame().is_none());
    for downloaded in [Slot::DownloadedB, Slot::DownloadedC] {
        for field in 0..3 {
            let mut s = s;
            match field {
                0 => s.active = downloaded,
                1 => s.staged = downloaded,
                _ => s.previous = downloaded,
            }
            assert!(matches!(Frames::new(1, s), Err(Error::Shape)));
        }
    }
    assert_eq!(core::mem::size_of::<Frames>(), 60);
    assert_eq!(core::mem::size_of::<Decoder>(), 64);
}
#[test]
fn v4_three_bit_slots_roundtrip_every_closed_identity_without_legacy_alias() {
    let slots = [
        Slot::None,
        Slot::A,
        Slot::B,
        Slot::DownloadedB,
        Slot::DownloadedC,
    ];
    let mut decoder = Decoder::new_v4();
    let mut serial = 1;
    for active in slots {
        for staged in slots {
            for previous in slots {
                let s = Snapshot {
                    active,
                    staged,
                    previous,
                    recovery: true,
                    ..snapshot()
                };
                let mut frames = Frames::new_v4(serial, s).unwrap();
                let mut final_value = None;
                while let Some(frame) = frames.next_frame() {
                    assert_eq!(frame[2], 2);
                    final_value = decoder.accept(frame).unwrap();
                }
                assert_eq!(final_value, Some(s));
                assert!(!decoder.pending());
                serial += 1;
            }
        }
    }
    assert_eq!(Slot::DownloadedB.name(), "downloaded-b");
    assert_eq!(Slot::DownloadedC.name(), "downloaded-c");
    let s = Snapshot {
        active: Slot::DownloadedB,
        staged: Slot::DownloadedC,
        previous: Slot::B,
        recovery: true,
        ..snapshot()
    };
    let w = s.words_for(true).unwrap();
    assert_eq!(
        w[0],
        4 | (1 << 10) | (3 << 11) | (4 << 14) | (2 << 17) | (1 << 20)
    );
    assert_eq!(Snapshot::decode_for(w, true), Ok(s));
}
#[test]
fn explicit_profile_header_is_strict_in_both_directions() {
    let s = snapshot();
    let v1 = Frames::new(1, s).unwrap().next_frame().unwrap();
    let v2 = Frames::new_v4(1, s).unwrap().next_frame().unwrap();
    assert_eq!(Decoder::new().accept(v2), Err(Error::Header));
    assert_eq!(Decoder::new_v4().accept(v1), Err(Error::Header));
    for version in [0, 3, 255] {
        let mut unknown = v1;
        unknown[2] = version;
        assert_eq!(Decoder::new().accept(unknown), Err(Error::Header));
        assert_eq!(Decoder::new_v4().accept(unknown), Err(Error::Header));
    }
}
#[test]
fn v4_unknown_slots_reserved_bits_shapes_and_replays_refuse() {
    let s = snapshot();
    for shift in [11, 14, 17] {
        for invalid in 5..8 {
            let mut w = s.words_for(true).unwrap();
            w[0] = (w[0] & !(7 << shift)) | (invalid << shift);
            assert_eq!(Snapshot::decode_for(w, true), Err(Error::Shape));
        }
    }
    for bit in 21..32 {
        let mut w = s.words_for(true).unwrap();
        w[0] |= 1 << bit;
        assert_eq!(Snapshot::decode_for(w, true), Err(Error::Shape));
    }
    for op in 27..=255 {
        let mut w = s.words_for(true).unwrap();
        w[0] = (w[0] & !255) | op;
        assert_eq!(Snapshot::decode_for(w, true), Err(Error::Shape));
    }
    for invalid in [
        Snapshot { thread: 0, ..s },
        Snapshot {
            installed: false,
            ..s
        },
    ] {
        assert!(matches!(Frames::new_v4(1, invalid), Err(Error::Shape)));
    }
    assert!(matches!(Frames::new_v4(0, s), Err(Error::Serial)));
    let mut decoder = Decoder::new_v4();
    let mut f = Frames::new_v4(2, s).unwrap();
    let begin = f.next_frame().unwrap();
    assert_eq!(decoder.accept(begin), Ok(None));
    assert_eq!(decoder.accept(begin), Err(Error::Order));
    let field = f.next_frame().unwrap();
    assert_eq!(decoder.accept(field), Ok(None));
    assert_eq!(decoder.accept(field), Err(Error::Order));
    while let Some(frame) = f.next_frame() {
        decoder.accept(frame).unwrap();
    }
    assert_eq!(decoder.accept(begin), Err(Error::Serial));
}

#[test]
fn remote_fetch_operation_is_v4_only_even_without_downloaded_slot_fields() {
    let s = Snapshot {
        operation: Operation::UpdateFetch,
        active: Slot::A,
        staged: Slot::None,
        previous: Slot::B,
        ..snapshot()
    };
    assert_eq!(s.operation.name(), "update-fetch");
    assert!(matches!(Frames::new(1, s), Err(Error::Shape)));
    assert_eq!(s.words(), Err(Error::Shape));
    let mut decoder = Decoder::new_v4();
    let mut frames = Frames::new_v4(1, s).unwrap();
    let mut completed = None;
    while let Some(frame) = frames.next_frame() {
        completed = decoder.accept(frame).unwrap();
    }
    assert_eq!(completed, Some(s));
    assert_eq!(
        Snapshot::decode_for(s.words_for(true).unwrap(), true),
        Ok(s)
    );
    let mut legacy = snapshot().words_for(false).unwrap();
    for operation in (25..=255).filter(|op| *op != 26) {
        legacy[0] = (legacy[0] & !255) | operation;
        assert_eq!(Snapshot::decode_for(legacy, false), Err(Error::Shape));
    }
}
