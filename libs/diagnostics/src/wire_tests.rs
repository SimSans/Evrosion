extern crate std;
use super::{framing::*, system::*};
use std::vec::Vec;
fn complete(decoder: &mut Decoder, kind: Kind, serial: u32, bytes: &[u8]) -> Completed {
    let mut tx = Tx::new(kind, serial).unwrap();
    loop {
        let frame = tx.current(bytes).unwrap().unwrap();
        let result = decoder.accept(frame).unwrap();
        let done = tx.accepted().unwrap();
        if let Some(result) = result {
            assert!(done);
            return result;
        }
        assert!(!done);
    }
}
#[test]
fn all_kinds_share_one_ordered_serial_space_and_exact_payload() {
    let mut decoder = Decoder::new();
    for (i, kind) in [Kind::Crash, Kind::Job, Kind::System, Kind::OwnerPrompt]
        .into_iter()
        .enumerate()
    {
        let bytes: Vec<_> = (0..kind.bytes()).map(|v| v as u8).collect();
        let completed = complete(&mut decoder, kind, i as u32 + 1, &bytes);
        assert_eq!(&completed.bytes[..kind.bytes()], &bytes);
        assert!(!decoder.pending());
    }
    let stale = Tx::new(Kind::Crash, 2)
        .unwrap()
        .current(&[0; CRASH_BYTES])
        .unwrap()
        .unwrap();
    assert_eq!(
        decoder.accept(stale).err(),
        Some(super::framing::Error::Serial)
    );
    assert!(decoder.failed());
}
#[test]
fn system_v2_reports_current_bad_after_next_good_selected_and_v1_never_invents_admission() {
    let mut value = metadata();
    value.current = Some(Admission {
        manifest: [0x31; 32],
        generation: 3,
        boot_serial: 7,
        process_stamp: [0x32; 32],
        phase: Phase::Failed,
    });
    let bytes = value.encode().unwrap();
    assert_eq!(Snapshot::decode(&bytes), Ok(value));
    assert_eq!(value.selected.unwrap().generation, 2);
    assert_eq!(value.current.unwrap().generation, 3);
    let mut legacy = metadata().encode().unwrap();
    legacy[8..10].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(Snapshot::decode(&legacy).unwrap().current, None);
    let mut invalid = bytes;
    invalid[368..376].copy_from_slice(&4u64.to_le_bytes());
    assert!(Snapshot::decode(&invalid).is_err());
    let mut invalid = bytes;
    invalid[376] = 1;
    assert!(Snapshot::decode(&invalid).is_err());
    let mut invalid = legacy;
    invalid[288] = 1;
    assert!(Snapshot::decode(&invalid).is_err());
}
#[test]
fn full_retains_exact_frame_and_no_partial_or_different_family_can_complete() {
    let mut outbox = Outbox::new();
    outbox.start(Kind::System, 1, &[19; SYSTEM_BYTES]).unwrap();
    let first = outbox.current().unwrap().unwrap();
    assert_eq!(outbox.current().unwrap(), Some(first));
    assert_eq!(
        outbox.start(Kind::Crash, 5, &[0; CRASH_BYTES]),
        Err(super::framing::Error::Busy)
    );
    let mut decoder = Decoder::new();
    decoder.accept(first).unwrap();
    assert!(decoder.pending());
    let mut wrong = first;
    wrong[1] = b'J';
    wrong[3] = 1;
    assert_eq!(
        decoder.accept(wrong).err(),
        Some(super::framing::Error::Order)
    );
    assert!(decoder.failed());
}
fn metadata() -> Snapshot {
    Snapshot {
        state: State::Committed,
        first_tick: 10,
        last_tick: 12,
        selected: Some(Manifest {
            generation: 2,
            cohort: [2; 32],
            supervisor_image: [3; 32],
            abi: [4; 32],
            health_contract: [5; 32],
            health_version: 1,
            required_checks: 3,
        }),
        known_good: Some(1),
        last_failure: Some(Failure {
            generation: 3,
            boot_serial: 7,
            attempts: 1,
            reason: 1,
            supervisor_image: [6; 32],
            process_stamp: Some([7; 32]),
            operation: 19,
            sequence: 20,
        }),
        current: None,
    }
}
#[test]
fn system_metadata_roundtrip_has_no_current_admission_or_health_claim() {
    for state in [
        State::NotCollected,
        State::Unformatted,
        State::NeedsRecovery,
        State::Unavailable,
    ] {
        let value = Snapshot::new(state, 10, 12);
        assert_eq!(Snapshot::decode(&value.encode().unwrap()), Ok(value));
    }
    let value = metadata();
    let bytes = value.encode().unwrap();
    assert_eq!(bytes.len(), 384);
    assert_eq!(Snapshot::decode(&bytes), Ok(value));
    assert_eq!(&bytes[288..], &[0; 96]);
}
#[test]
fn system_parser_refuses_partial_reserved_noncanonical_and_mixed_metadata() {
    let value = metadata();
    let bytes = value.encode().unwrap();
    for offset in [14, 154, 186, 288, 383] {
        let mut changed = bytes;
        changed[offset] = 1;
        assert!(Snapshot::decode(&changed).is_err());
    }
    for offset in [12, 13, 152, 156, 184, 185] {
        let mut changed = bytes;
        changed[offset] = 255;
        assert!(Snapshot::decode(&changed).is_err());
    }
    assert!(Snapshot::decode(&bytes[..383]).is_err());
    let mut changed = bytes;
    changed[12] = 1;
    assert!(Snapshot::decode(&changed).is_err());
    let mut changed = bytes;
    changed[13] &= !4;
    assert!(Snapshot::decode(&changed).is_err());
    let mut backwards = value;
    backwards.last_tick = 9;
    assert_eq!(backwards.encode(), Err(super::system::Error::Clock));
}
