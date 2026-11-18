extern crate std;
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::vec::Vec;

fn signer(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
fn public(key: &SigningKey) -> PublicKey {
    PublicKey::parse(key.verifying_key().to_bytes()).unwrap()
}
#[test]
fn strict_primitive_matches_rfc8032_test_one() {
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }
    // RFC8032 §7.1 TEST1; public reference material, not a deployed key.
    let public = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    PublicKey::parse(public).unwrap();
    let key = VerifyingKey::from_bytes(&public).unwrap();
    assert!(
        key.verify_strict(b"", &Signature::from_bytes(&signature))
            .is_ok()
    );
    assert!(
        key.verify_strict(b"different", &Signature::from_bytes(&signature))
            .is_err()
    );
}
fn envelope(role: Role, payload: &[u8], signers: &[&SigningKey]) -> Vec<u8> {
    let mut out = header(role, payload.len(), signers.len()).unwrap().to_vec();
    out.extend_from_slice(payload);
    let mut signed: Vec<_> = signers
        .iter()
        .map(|key| (public(key).id(), key.sign(&out).to_bytes()))
        .collect();
    signed.sort_by_key(|s| s.0);
    for (key, signature) in signed {
        out.extend_from_slice(&key);
        out.extend_from_slice(&signature);
    }
    out
}

#[test]
fn genuine_independent_quorum_verifies_exact_immutable_payload() {
    let a = signer(1);
    let b = signer(2);
    let c = signer(3);
    let keys = [public(&a), public(&b), public(&c)];
    let policy = KeySet::checked_configuration(Role::Targets, &keys, 2).unwrap();
    let bytes = envelope(
        Role::Targets,
        b"bounded development target metadata",
        &[&a, &b],
    );
    let parsed = Envelope::parse(&bytes).unwrap();
    assert_eq!(parsed.payload(), b"bounded development target metadata");
    assert_eq!(parsed.signature_count(), 2);
    assert_eq!(parsed.bytes(), bytes);
    assert_eq!(policy.verify(&parsed), Ok(()));
    let mut tampered = bytes.clone();
    tampered[HEADER_BYTES] ^= 1;
    assert_eq!(
        policy.verify(&Envelope::parse(&tampered).unwrap()),
        Err(Error::Threshold)
    );
    let other_keys = [public(&c)];
    assert_eq!(
        KeySet::checked_configuration(Role::Targets, &other_keys, 1)
            .unwrap()
            .verify(&parsed),
        Err(Error::Threshold)
    );
}

#[test]
fn metadata_roles_are_signed_domains_not_caller_labels() {
    let a = signer(1);
    let keys = [public(&a)];
    let roots = KeySet::checked_configuration(Role::Root, &keys, 1).unwrap();
    let targets = KeySet::checked_configuration(Role::Targets, &keys, 1).unwrap();
    let bytes = envelope(Role::Root, b"same bytes different role", &[&a]);
    assert_eq!(roots.verify(&Envelope::parse(&bytes).unwrap()), Ok(()));
    assert_eq!(
        targets.verify(&Envelope::parse(&bytes).unwrap()),
        Err(Error::Role)
    );
    let mut relabelled = bytes;
    relabelled[10] = Role::Targets as u8;
    assert_eq!(
        targets.verify(&Envelope::parse(&relabelled).unwrap()),
        Err(Error::Threshold)
    );
}

#[test]
fn duplicates_unknown_algorithms_reserved_data_and_extent_tricks_refuse() {
    let a = signer(1);
    let b = signer(2);
    let bytes = envelope(Role::Snapshot, b"snapshot", &[&a, &b]);
    for bad in [
        {
            let mut b = bytes.clone();
            b[11] = 2;
            b
        },
        {
            let mut b = bytes.clone();
            b[10] = 0;
            b
        },
        {
            let mut b = bytes.clone();
            b[17] = 1;
            b
        },
        {
            let mut b = bytes.clone();
            b[16] = 0;
            b
        },
        {
            let mut b = bytes.clone();
            b[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
            b
        },
        {
            let mut b = bytes.clone();
            b.push(0);
            b
        },
        bytes[..bytes.len() - 1].to_vec(),
    ] {
        assert!(Envelope::parse(&bad).is_err());
    }
    let first = HEADER_BYTES + b"snapshot".len();
    let mut duplicate = bytes.clone();
    let record = duplicate[first..first + SIGNATURE_BYTES].to_vec();
    duplicate[first + SIGNATURE_BYTES..].copy_from_slice(&record);
    assert!(matches!(
        Envelope::parse(&duplicate),
        Err(Error::SignerOrder)
    ));
    let mut reversed = bytes.clone();
    reversed[first..first + SIGNATURE_BYTES].copy_from_slice(&bytes[first + SIGNATURE_BYTES..]);
    reversed[first + SIGNATURE_BYTES..].copy_from_slice(&bytes[first..first + SIGNATURE_BYTES]);
    assert!(matches!(
        Envelope::parse(&reversed),
        Err(Error::SignerOrder)
    ));
}

#[test]
fn wrong_signatures_do_not_count_and_one_bad_extra_does_not_destroy_a_quorum() {
    let a = signer(1);
    let b = signer(2);
    let c = signer(3);
    let foreign = signer(4);
    let keys = [public(&a), public(&b), public(&c)];
    let policy = KeySet::checked_configuration(Role::Timestamp, &keys, 2).unwrap();
    let bytes = envelope(Role::Timestamp, b"timestamp", &[&a, &b, &foreign]);
    assert_eq!(policy.verify(&Envelope::parse(&bytes).unwrap()), Ok(()));
    let mut bad = envelope(Role::Timestamp, b"timestamp", &[&a, &b, &c]);
    // Corrupt exactly one signed record; other independent valid signatures
    // retain the declared2-of3 authorization. No invalid signer is counted.
    let at = HEADER_BYTES + b"timestamp".len() + 32;
    bad[at] ^= 1;
    assert_eq!(policy.verify(&Envelope::parse(&bad).unwrap()), Ok(()));
    let all = KeySet::checked_configuration(Role::Timestamp, &keys, 3).unwrap();
    assert_eq!(
        all.verify(&Envelope::parse(&bad).unwrap()),
        Err(Error::Threshold)
    );
}

#[test]
fn key_configuration_is_canonical_bounded_and_distinct_without_becoming_trust() {
    let a = signer(1);
    let key = public(&a);
    assert_eq!(PublicKey::parse([0; 32]), Err(Error::Key));
    let mut identity = [0; 32];
    identity[0] = 1;
    assert_eq!(PublicKey::parse(identity), Err(Error::Key));
    assert_eq!(PublicKey::parse([0xff; 32]), Err(Error::Key));
    let mixed = (a.verifying_key().to_edwards() + curve25519_dalek::constants::EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    assert!(!VerifyingKey::from_bytes(&mixed).unwrap().is_weak());
    assert_eq!(PublicKey::parse(mixed), Err(Error::Key));
    assert!(matches!(
        KeySet::checked_configuration(Role::Root, &[], 1),
        Err(Error::KeyCount)
    ));
    assert!(matches!(
        KeySet::checked_configuration(Role::Root, &[key, key], 1),
        Err(Error::DuplicateKey)
    ));
    assert!(matches!(
        KeySet::checked_configuration(Role::Root, &[key], 0),
        Err(Error::Threshold)
    ));
    assert!(matches!(
        KeySet::checked_configuration(Role::Root, &[key], 2),
        Err(Error::Threshold)
    ));
    assert!(header(Role::Root, 0, 1).is_err());
    assert!(header(Role::Root, MAX_PAYLOAD_BYTES + 1, 1).is_err());
    assert!(header(Role::Root, 1, MAX_SIGNATURES + 1).is_err());
}

#[test]
fn root_succession_can_require_both_old_and_new_independent_thresholds() {
    let old = signer(1);
    let new = signer(2);
    let neither = signer(3);
    let old_keys = [public(&old)];
    let new_keys = [public(&new)];
    let previous = KeySet::checked_configuration(Role::Root, &old_keys, 1).unwrap();
    let successor = KeySet::checked_configuration(Role::Root, &new_keys, 1).unwrap();
    let bytes = envelope(
        Role::Root,
        b"new root payload; version policy is separate",
        &[&old, &new],
    );
    let parsed = Envelope::parse(&bytes).unwrap();
    assert_eq!(previous.verify(&parsed), Ok(()));
    assert_eq!(successor.verify(&parsed), Ok(()));
    let bytes = envelope(
        Role::Root,
        b"new root payload; version policy is separate",
        &[&old, &neither],
    );
    let parsed = Envelope::parse(&bytes).unwrap();
    assert_eq!(previous.verify(&parsed), Ok(()));
    assert_eq!(successor.verify(&parsed), Err(Error::Threshold));
}

#[test]
fn noncanonical_scalar_and_small_order_signature_r_never_count_as_a_quorum() {
    let signer = signer(9);
    let keys = [public(&signer)];
    let policy = KeySet::checked_configuration(Role::Targets, &keys, 1).unwrap();
    let bytes = envelope(Role::Targets, b"real signature mutation", &[&signer]);
    let start = HEADER_BYTES + b"real signature mutation".len() + 32;
    for altered in [
        {
            let mut b = bytes.clone();
            b[start + 32..start + 64].fill(0xff);
            b
        },
        {
            let mut b = bytes.clone();
            b[start..start + 32].fill(0);
            b
        },
        {
            let mut b = bytes.clone();
            b[start..start + 32].fill(0);
            b[start] = 1;
            b
        },
    ] {
        assert_eq!(
            policy.verify(&Envelope::parse(&altered).unwrap()),
            Err(Error::Threshold)
        );
    }
}
