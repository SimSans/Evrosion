extern crate std;
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use ev_release_trust::signature::PublicKey;
use ev_time_contract::{Domain, Error as ClockError};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, vec, vec::Vec};
const FIXTURE_NONCE: &[u8; 32] = include_bytes!("../tests/fixtures/nonce.bin");
const FIXTURE_REPLY: &[u8] = include_bytes!("../tests/fixtures/response.bin");
const FIXTURE_REQUEST: &[u8; 1024] = include_bytes!("../tests/fixtures/request.bin");
const MID: u64 = 1794502815;
const MERKLE_ROOTS: [[u8; 32]; 4] = [
    [
        66, 188, 52, 128, 132, 52, 219, 46, 6, 144, 197, 61, 38, 231, 155, 150, 113, 241, 85, 44,
        196, 2, 55, 113, 194, 106, 231, 132, 198, 211, 158, 45,
    ],
    [
        225, 186, 145, 191, 41, 61, 183, 198, 78, 187, 100, 225, 243, 101, 121, 53, 27, 203, 67,
        110, 239, 72, 158, 239, 60, 191, 247, 142, 111, 178, 152, 6,
    ],
    [
        169, 77, 85, 33, 29, 173, 50, 94, 6, 89, 122, 147, 170, 143, 164, 232, 7, 113, 232, 212,
        186, 206, 223, 250, 27, 134, 254, 6, 38, 25, 119, 239,
    ],
    [
        251, 13, 152, 86, 51, 169, 139, 62, 28, 40, 31, 176, 75, 54, 169, 125, 26, 249, 42, 76, 23,
        50, 110, 154, 183, 118, 13, 153, 118, 169, 4, 213,
    ],
];
fn instant(t: u64) -> Instant {
    Domain::new(77).unwrap().at(t)
}
fn policy() -> Policy {
    Policy::new(ClockModel::one_second_floor(1, 1).unwrap(), 8, 30, 4, 2).unwrap()
}
struct Source {
    values: VecDeque<[u8; 32]>,
    calls: usize,
}
impl NonceSource for Source {
    type Error = ();
    fn fresh_nonce(&mut self, out: &mut [u8; 32]) -> Result<(), ()> {
        self.calls += 1;
        *out = self.values.pop_front().ok_or(())?;
        Ok(())
    }
}
fn client() -> Client<Source> {
    client_with_policy(policy())
}
fn client_with_policy(policy: Policy) -> Client<Source> {
    Client::new(
        Source {
            values: VecDeque::from([*FIXTURE_NONCE, [0x24; 32]]),
            calls: 0,
        },
        instant(100),
        policy,
    )
    .unwrap()
}
fn anchor() -> Anchor {
    let mut c = client();
    let request = c.begin(instant(100)).unwrap();
    c.finish(request, instant(100), FIXTURE_REPLY).unwrap()
}
#[test]
fn source_preparation_keeps_challenge_history_and_cannot_touch_pending_work() {
    let mut c = client();
    let request = c
        .begin_after(instant(100), |source| {
            assert_eq!(source.calls, 0);
            Ok(())
        })
        .unwrap();
    assert_eq!(request.sequence(), 1);
    assert_eq!(
        err(c.begin_after(instant(101), |_| panic!("pending source preparation"))),
        Error::State
    );
    c.finish(request, instant(101), FIXTURE_REPLY).unwrap();
    let second = c
        .begin_after(instant(102), |source| {
            assert_eq!(source.calls, 1);
            source.values.clear();
            source.values.push_back([0x31; 32]);
            Ok(())
        })
        .unwrap();
    assert_eq!(second.sequence(), 2);
    assert_eq!(second.nonce(), &[0x31; 32]);
    assert!(c.finish(second, instant(102), FIXTURE_REPLY).is_err());
    assert!(!c.has_pending());
    let third = c
        .begin_after(instant(103), |source| {
            source.values.push_back([0x32; 32]);
            Ok(())
        })
        .unwrap();
    assert_eq!(third.sequence(), 3);
    assert!(c.finish(third, instant(103), b"malformed").is_err());
    assert_eq!(
        err(c.begin_after(instant(104), |source| {
            source.values.push_back([0x32; 32]);
            Ok(())
        })),
        Error::Entropy
    );
    assert_eq!(
        err(c.begin_after(instant(105), |_| panic!("failed source preparation"))),
        Error::State
    );
}
#[test]
fn failed_preparation_clock_and_sequence_bounds_never_run_a_new_source_after_fence() {
    let mut c = client();
    assert_eq!(
        err(c.begin_after(instant(100), |_| Err(()))),
        Error::Entropy
    );
    assert!(!c.has_pending());
    assert_eq!(
        err(c.begin_after(instant(101), |_| panic!("failed owner"))),
        Error::State
    );
    let mut c = client();
    assert_eq!(
        err(c.begin_after(instant(99), |_| panic!("regressed origin"))),
        Error::Clock(ClockError::ClockRegression)
    );
    let mut c = client();
    c.sequence = u64::MAX - 1;
    assert_eq!(
        err(c.begin_after(instant(100), |_| panic!("exhausted sequence"))),
        Error::Overflow
    );
    assert!(!c.has_pending());
}
fn err<T>(r: Result<T, Error>) -> Error {
    match r {
        Ok(_) => panic!("unexpected acceptance"),
        Err(e) => e,
    }
}
#[test]
fn actual_public_packet_and_exact_request_encode_bind_private_pending_owner() {
    let mut c = client();
    let request = c.begin(instant(100)).unwrap();
    let mut bytes = [0; 1024];
    request.encode(&mut bytes);
    assert_eq!(&bytes, FIXTURE_REQUEST);
    assert!(c.has_pending());
    let mut a = c.finish(request, instant(100), FIXTURE_REPLY).unwrap();
    assert!(!c.has_pending());
    let p = a.window(instant(100), instant(100), MID - 1).unwrap();
    assert_eq!(p.utc().earliest(), MID - 1);
    assert_eq!(p.utc().latest(), MID + 2);
    assert_eq!(p.next_floor(), MID - 1);
    assert_eq!(p.observed(), instant(100));
    assert_eq!(p.through(), instant(100));
    let expected = [
        75, 0, 82, 139, 25, 236, 5, 220, 154, 160, 198, 173, 242, 245, 136, 119, 159, 152, 144, 71,
        34, 121, 238, 164, 191, 77, 155, 107, 156, 64, 139, 111,
    ];
    assert_eq!(<[u8; 32]>::from(Sha256::digest(FIXTURE_REPLY)), expected);
}
#[test]
fn consumed_or_foreign_tokens_cannot_reauthorize_a_recorded_response() {
    let mut c = client();
    let request = c.begin(instant(100)).unwrap();
    let nonce = *request.nonce();
    let seq = request.sequence();
    c.finish(request, instant(100), FIXTURE_REPLY).unwrap();
    assert_eq!(
        err(c.finish(
            Request {
                nonce,
                sequence: seq
            },
            instant(100),
            FIXTURE_REPLY
        )),
        Error::State
    );
    let current = c.begin(instant(101)).unwrap();
    let current_nonce = *current.nonce();
    let current_seq = current.sequence();
    assert_eq!(
        err(c.finish(
            Request {
                nonce,
                sequence: seq
            },
            instant(101),
            FIXTURE_REPLY
        )),
        Error::Challenge
    );
    assert!(!c.has_pending());
    assert_eq!(
        err(c.finish(
            Request {
                nonce: current_nonce,
                sequence: current_seq
            },
            instant(101),
            FIXTURE_REPLY
        )),
        Error::State
    );
}
#[test]
fn busy_begin_never_redraws_nonce_or_slides_original_exchange_origin() {
    let tight = Policy::new(ClockModel::one_second_floor(1, 1).unwrap(), 2, 30, 1, 2).unwrap();
    let mut c = client_with_policy(tight);
    let request = c.begin(instant(100)).unwrap();
    assert_eq!(err(c.begin(instant(101))), Error::State);
    assert_eq!(c.source.calls, 1);
    assert_eq!(
        err(c.finish(request, instant(102), FIXTURE_REPLY)),
        Error::Age
    );
    assert!(!c.has_pending());
}
#[test]
fn failed_crypto_or_clock_attempt_consumes_pending_and_never_returns_an_anchor() {
    for clock_failure in [false, true] {
        let mut c = client();
        let request = c.begin(instant(100)).unwrap();
        let mut bad = FIXTURE_REPLY.to_vec();
        bad[60] ^= 1;
        let result = c.finish(
            request,
            if clock_failure {
                instant(99)
            } else {
                instant(100)
            },
            if clock_failure { FIXTURE_REPLY } else { &bad },
        );
        assert!(result.is_err());
        assert!(!c.has_pending());
        if clock_failure {
            assert_eq!(err(c.begin(instant(100))), Error::State);
        }
    }
}
#[test]
fn absent_zero_or_repeated_source_output_fails_closed_without_a_freshness_label() {
    for values in [vec![], vec![[0; 32]]] {
        let mut c = Client::new(
            Source {
                values: values.into(),
                calls: 0,
            },
            instant(100),
            policy(),
        )
        .unwrap();
        assert_eq!(err(c.begin(instant(100))), Error::Entropy);
        assert_eq!(err(c.begin(instant(101))), Error::State);
    }
    let mut c = Client::new(
        Source {
            values: VecDeque::from([*FIXTURE_NONCE, *FIXTURE_NONCE]),
            calls: 0,
        },
        instant(100),
        policy(),
    )
    .unwrap();
    let r = c.begin(instant(100)).unwrap();
    c.finish(r, instant(100), FIXTURE_REPLY).unwrap();
    assert_eq!(err(c.begin(instant(101))), Error::Entropy);
    assert!(!c.has_pending());
}
#[test]
fn actual_wrong_nonce_key_signed_mutation_and_unsigned_residual_index_refuse() {
    let key = PublicKey::parse(PUBLIC_KEY).unwrap();
    let mut nonce = *FIXTURE_NONCE;
    nonce[0] ^= 1;
    assert_eq!(
        packet::verify(key, &nonce, FIXTURE_REPLY, 2).err(),
        Some(PacketError::Nonce)
    );
    let wrong =
        PublicKey::parse(SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes()).unwrap();
    assert_eq!(
        packet::verify(wrong, FIXTURE_NONCE, FIXTURE_REPLY, 2).err(),
        Some(PacketError::Signature)
    );
    let mut signed = FIXTURE_REPLY.to_vec();
    signed[195] ^= 1;
    assert_eq!(
        packet::verify(key, FIXTURE_NONCE, &signed, 2).err(),
        Some(PacketError::Signature)
    );
    let mut unsigned = FIXTURE_REPLY.to_vec();
    unsigned[351] ^= 1;
    assert_eq!(
        packet::verify(key, FIXTURE_NONCE, &unsigned, 2).err(),
        Some(PacketError::Path)
    );
}
#[test]
fn truncation_count_offsets_order_unknown_tags_and_trailing_extents_are_closed() {
    let key = PublicKey::parse(PUBLIC_KEY).unwrap();
    for n in 0..FIXTURE_REPLY.len() {
        assert!(packet::verify(key, FIXTURE_NONCE, &FIXTURE_REPLY[..n], 2).is_err());
    }
    for (at, value) in [
        (8, 0u32),
        (12, 0),
        (12, u32::MAX),
        (16, u32::MAX),
        (16, 1),
        (20, 60),
        (36, 0),
        (40, 0x00524557),
    ] {
        let mut bad = FIXTURE_REPLY.to_vec();
        bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            packet::verify(key, FIXTURE_NONCE, &bad, 2).is_err(),
            "offset{at} value{value}"
        );
    }
    let mut trailing = FIXTURE_REPLY.to_vec();
    trailing.extend([0; 4]);
    assert!(packet::verify(key, FIXTURE_NONCE, &trailing, 2).is_err());
    trailing[8..12].copy_from_slice(&344u32.to_le_bytes());
    assert!(packet::verify(key, FIXTURE_NONCE, &trailing, 2).is_err());
    let mut version = FIXTURE_REPLY.to_vec();
    version[124..128].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        packet::verify(key, FIXTURE_NONCE, &version, 2).err(),
        Some(PacketError::Version)
    );
}
fn tag(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}
fn message(mut fields: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    fields.sort_by_key(|v| v.0);
    let count = fields.len();
    let mut bytes = vec![0; count * 8];
    bytes[..4].copy_from_slice(&(count as u32).to_le_bytes());
    let mut offset = 0;
    for (i, (tag, data)) in fields.into_iter().enumerate() {
        assert_eq!(data.len() % 4, 0);
        if i > 0 {
            bytes[4 * i..4 * i + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        }
        bytes[count * 4 + i * 4..count * 4 + i * 4 + 4].copy_from_slice(&tag.to_le_bytes());
        offset += data.len();
        bytes.extend_from_slice(&data);
    }
    bytes
}
fn sign(key: &SigningKey, domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(body);
    key.sign(&bytes).to_bytes().to_vec()
}
fn synthetic(
    mid: u64,
    radius: u32,
    min: u64,
    max: u64,
    root: [u8; 32],
    path: Vec<u8>,
    index: u32,
) -> (Vec<u8>, PublicKey) {
    let key = SigningKey::from_bytes(&[11; 32]);
    let online = SigningKey::from_bytes(&[12; 32]);
    let delegation = message(vec![
        (tag(b"PUBK"), online.verifying_key().to_bytes().to_vec()),
        (tag(b"MINT"), min.to_le_bytes().to_vec()),
        (tag(b"MAXT"), max.to_le_bytes().to_vec()),
    ]);
    let cert = message(vec![
        (tag(b"DELE"), delegation.clone()),
        (
            tag(b"SIG\0"),
            sign(&key, b"RoughTime v1 delegation signature--\0", &delegation),
        ),
    ]);
    let signed = message(vec![
        (tag(b"MIDP"), mid.to_le_bytes().to_vec()),
        (tag(b"RADI"), radius.to_le_bytes().to_vec()),
        (tag(b"ROOT"), root.to_vec()),
    ]);
    let body = message(vec![
        (
            tag(b"SIG\0"),
            sign(&online, b"RoughTime v1 response signature\0", &signed),
        ),
        (tag(b"SREP"), signed),
        (tag(b"CERT"), cert),
        (tag(b"VER\0"), PROTOCOL.to_le_bytes().to_vec()),
        (tag(b"PATH"), path),
        (tag(b"INDX"), index.to_le_bytes().to_vec()),
    ]);
    let mut bytes = b"ROUGHTIM".to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend(body);
    (
        bytes,
        PublicKey::parse(key.verifying_key().to_bytes()).unwrap(),
    )
}
#[test]
fn real_signed_two_level_merkle_branches_match_independent_python_sha512_vectors() {
    for (index, root) in MERKLE_ROOTS.iter().copied().enumerate() {
        let mut path = vec![0x55; 32];
        path.extend([0x66; 32]);
        let (bytes, key) = synthetic(100, 1, 50, 200, root, path, index as u32);
        let time = packet::verify(key, &[0x42; 32], &bytes, 2).unwrap();
        assert_eq!((time.earliest, time.latest), (99, 101));
    }
    let mut path = vec![0x55; 32];
    path.extend([0x66; 32]);
    let (bytes, key) = synthetic(100, 1, 50, 200, MERKLE_ROOTS[0], path, 4);
    assert_eq!(
        packet::verify(key, &[0x42; 32], &bytes, 2).err(),
        Some(PacketError::Path)
    );
}
#[test]
fn actual_signatures_do_not_override_delegation_radius_path_or_arithmetic_bounds() {
    for (mid, rad, min, max, expected) in [
        (100, 1, 101, 200, PacketError::Delegation),
        (100, 1, 0, 99, PacketError::Delegation),
        (100, 1, 200, 100, PacketError::Delegation),
        (100, 0, 0, 200, PacketError::Radius),
        (100, 3, 0, 200, PacketError::Radius),
        (0, 1, 0, 200, PacketError::Overflow),
        (u64::MAX, 1, 0, u64::MAX, PacketError::Overflow),
    ] {
        let mut path = vec![0x55; 32];
        path.extend([0x66; 32]);
        let (bytes, key) = synthetic(mid, rad, min, max, MERKLE_ROOTS[0], path, 0);
        assert_eq!(
            packet::verify(key, &[0x42; 32], &bytes, 2).err(),
            Some(expected)
        );
    }
    for path in [vec![0; 4], vec![0; 32 * 17]] {
        let (bytes, key) = synthetic(100, 1, 50, 200, MERKLE_ROOTS[0], path, 0);
        assert!(packet::verify(key, &[0x42; 32], &bytes, 2).is_err());
    }
}
#[test]
fn whole_window_quantization_pause_age_and_nonunit_rate_are_conservative() {
    let mut a = anchor();
    let p = a.window(instant(101), instant(103), MID - 1).unwrap();
    assert_eq!((p.utc().earliest(), p.utc().latest()), (MID - 1, MID + 5));
    let policy = Policy::new(
        ClockModel::one_second_floor(999, 1000).unwrap(),
        8,
        30,
        4,
        2,
    )
    .unwrap();
    let mut c = client_with_policy(policy);
    let r = c.begin(instant(100)).unwrap();
    let mut a = c.finish(r, instant(100), FIXTURE_REPLY).unwrap();
    let p = a.window(instant(100), instant(100), MID - 1).unwrap();
    assert_eq!(p.utc().latest(), MID + 3);
    let mut a = anchor();
    assert_eq!(err(a.window(instant(3700), instant(3700), 0)), Error::Age);
    assert_eq!(err(a.window(instant(100), instant(100), 0)), Error::State);
}
#[test]
fn post_crypto_first_window_checks_whole_exchange_and_original_age_never_slides() {
    let mut a = anchor();
    assert_eq!(err(a.window(instant(108), instant(108), 0)), Error::Age);
    let mut a = anchor();
    a.window(instant(101), instant(101), 0).unwrap();
    a.window(instant(110), instant(110), 0).unwrap();
    assert_eq!(err(a.window(instant(130), instant(130), 0)), Error::Age);
    let mut a = anchor();
    assert_eq!(err(a.window(instant(101), instant(106), 0)), Error::Age);
}
#[test]
fn regression_wrong_domain_future_overflow_and_cold_floor_close_anchor() {
    for (observed, through, floor, expected) in [
        (
            instant(99),
            instant(99),
            0,
            Error::Clock(ClockError::ClockRegression),
        ),
        (
            Domain::new(78).unwrap().at(100),
            Domain::new(78).unwrap().at(100),
            0,
            Error::Clock(ClockError::DifferentBoot),
        ),
        (
            instant(100),
            instant(99),
            0,
            Error::Clock(ClockError::ClockRegression),
        ),
        (instant(100), instant(100), MID, Error::Rollback),
    ] {
        let mut a = anchor();
        assert_eq!(err(a.window(observed, through, floor)), expected);
        assert_eq!(err(a.window(instant(101), instant(101), 0)), Error::State);
    }
    let mut a = anchor();
    a.window(instant(101), instant(101), 0).unwrap();
    assert_eq!(
        err(a.window(instant(100), instant(100), 0)),
        Error::Clock(ClockError::ClockRegression)
    );
    assert_eq!(ClockModel::one_second_floor(0, 1), Err(Error::Policy));
    assert!(ClockModel::one_second_floor(1, 0).is_err());
    assert!(ClockModel::one_second_floor(2, 1).is_err());
    assert!(ClockModel::one_second_floor(1, 1_000_001).is_err());
}
#[test]
fn invalid_policy_and_no_hidden_ready_or_large_copies() {
    let clock = ClockModel::one_second_floor(1, 1).unwrap();
    for args in [
        (0, 30, 1, 2),
        (3601, 3601, 1, 2),
        (8, 7, 1, 2),
        (8, 86401, 1, 2),
        (8, 30, 31, 2),
        (8, 30, 1, 0),
        (8, 30, 1, 3601),
    ] {
        assert!(Policy::new(clock, args.0, args.1, args.2, args.3).is_err());
    }
    assert!(core::mem::size_of::<Client<Source>>() <= 320);
    assert!(core::mem::size_of::<Anchor>() <= 192);
    assert!(core::mem::size_of::<IntervalProposal>() <= 80);
}

const DEPTH16_ROOT: [u8; 32] = [
    83, 226, 33, 88, 130, 66, 165, 135, 7, 94, 116, 185, 56, 103, 36, 248, 17, 152, 197, 144, 183,
    190, 254, 158, 221, 174, 172, 7, 14, 184, 186, 24,
];

#[test]
fn exact_maximum_path_accepts_and_any_residual_high_index_refuses() {
    let path: Vec<u8> = (0..16).flat_map(|i| [0x55 + i; 32]).collect();
    let (bytes, key) = synthetic(100, 1, 50, 200, DEPTH16_ROOT, path.clone(), 0);
    assert_eq!(bytes.len(), MAX_REPLY_BYTES);
    assert!(packet::verify(key, &[0x42; 32], &bytes, 2).is_ok());
    let (bytes, key) = synthetic(100, 1, 50, 200, DEPTH16_ROOT, path, 1 << 16);
    assert_eq!(
        packet::verify(key, &[0x42; 32], &bytes, 2).err(),
        Some(PacketError::Path)
    );
}
#[test]
fn valid_root_signature_cannot_authorize_a_weak_delegated_key_in_this_profile() {
    let root = SigningKey::from_bytes(&[11; 32]);
    let online = SigningKey::from_bytes(&[12; 32]);
    for key in [
        [0; 32],
        {
            let mut k = [0; 32];
            k[0] = 1;
            k
        },
        [0xff; 32],
    ] {
        let delegation = message(vec![
            (tag(b"PUBK"), key.to_vec()),
            (tag(b"MINT"), 50u64.to_le_bytes().to_vec()),
            (tag(b"MAXT"), 200u64.to_le_bytes().to_vec()),
        ]);
        let certificate = message(vec![
            (tag(b"DELE"), delegation.clone()),
            (
                tag(b"SIG\0"),
                sign(&root, b"RoughTime v1 delegation signature--\0", &delegation),
            ),
        ]);
        let signed = message(vec![
            (tag(b"MIDP"), 100u64.to_le_bytes().to_vec()),
            (tag(b"RADI"), 1u32.to_le_bytes().to_vec()),
            (tag(b"ROOT"), MERKLE_ROOTS[0].to_vec()),
        ]);
        let body = message(vec![
            (
                tag(b"SIG\0"),
                sign(&online, b"RoughTime v1 response signature\0", &signed),
            ),
            (tag(b"SREP"), signed),
            (tag(b"CERT"), certificate),
            (tag(b"VER\0"), PROTOCOL.to_le_bytes().to_vec()),
            (tag(b"PATH"), vec![0; 64]),
            (tag(b"INDX"), vec![0; 4]),
        ]);
        let mut bytes = b"ROUGHTIM".to_vec();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend(body);
        let root = PublicKey::parse(root.verifying_key().to_bytes()).unwrap();
        assert_eq!(
            packet::verify(root, &[0x42; 32], &bytes, 2).err(),
            Some(PacketError::Key)
        );
    }
}
#[test]
fn utc_projection_and_quantized_counter_overflow_fail_without_rearming() {
    let mut path = vec![0x55; 32];
    path.extend([0x66; 32]);
    let (bytes, key) = synthetic(u64::MAX - 1, 1, 0, u64::MAX, MERKLE_ROOTS[0], path, 0);
    let signed = packet::verify(key, &[0x42; 32], &bytes, 2).unwrap();
    let mut a = Anchor::new(signed, instant(100), instant(100), policy());
    assert_eq!(
        err(a.window(instant(100), instant(100), 0)),
        Error::Overflow
    );
    assert_eq!(err(a.window(instant(100), instant(100), 0)), Error::State);
    let mut c = Client::new(
        Source {
            values: VecDeque::from([*FIXTURE_NONCE]),
            calls: 0,
        },
        instant(0),
        policy(),
    )
    .unwrap();
    let request = c.begin(instant(0)).unwrap();
    let mut a = c.finish(request, instant(0), FIXTURE_REPLY).unwrap();
    assert_eq!(
        err(a.window(instant(u64::MAX), instant(u64::MAX), 0)),
        Error::Overflow
    );
}

#[test]
fn fresh_post_crypto_observation_checks_original_exchange_and_fences_every_failure() {
    for (sample, expected) in [
        (instant(108), Error::Age),
        (instant(99), Error::Clock(ClockError::ClockRegression)),
        (
            Domain::new(78).unwrap().at(100),
            Error::Clock(ClockError::DifferentBoot),
        ),
    ] {
        let mut a = anchor();
        assert_eq!(a.observe_post_crypto(sample), Err(expected));
        assert_eq!(a.observe_post_crypto(instant(100)), Err(Error::State));
        assert_eq!(err(a.window(instant(100), instant(100), 0)), Error::State);
    }
    let mut a = anchor();
    a.observe_post_crypto(instant(107)).unwrap();
    assert_eq!(
        a.observe_post_crypto(instant(106)),
        Err(Error::Clock(ClockError::ClockRegression))
    );
    assert_eq!(a.observe_post_crypto(instant(107)), Err(Error::State));
}
#[test]
fn checked_post_crypto_read_does_not_reset_age_or_bypass_later_actual_floor_and_window() {
    let mut a = anchor();
    a.observe_post_crypto(instant(101)).unwrap();
    let proposal = a.window(instant(109), instant(110), MID - 1).unwrap();
    assert_eq!(proposal.utc().earliest(), MID - 1);
    assert_eq!(proposal.utc().latest(), MID + 12);
    assert_eq!(
        err(a.window(instant(130), instant(130), MID - 1)),
        Error::Age
    );
    let mut a = anchor();
    a.observe_post_crypto(instant(101)).unwrap();
    assert_eq!(
        err(a.window(instant(102), instant(102), MID)),
        Error::Rollback
    );
    assert_eq!(a.observe_post_crypto(instant(102)), Err(Error::State));
    let mut a = anchor();
    a.observe_post_crypto(instant(101)).unwrap();
    assert_eq!(
        err(a.window(instant(102), instant(107), MID - 1)),
        Error::Age
    );
}
