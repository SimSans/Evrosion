extern crate std;
use crate::{
    metadata::{self as md, Binding, Common, Identity, RolePolicy, TargetSpec},
    signature::{self, Envelope, PublicKey, Role},
    verifier::{self as v, Error, Policy, ReplayState, TrustedRoot},
};
use ed25519_dalek::{Signer, SigningKey};
use ev_time_contract::{
    Domain,
    freshness::{self, QualifiedWindow, Time, UtcInterval},
};
use sha2::{Digest, Sha256};
use std::{vec, vec::Vec};
fn binding() -> Binding {
    Binding {
        namespace: [1; 32],
        channel: [2; 32],
        platform: [3; 32],
    }
}
fn common(root: u64, version: u64) -> Common {
    Common {
        binding: binding(),
        version,
        root_version: root,
        not_before: 90,
        expires: 150,
    }
}
fn policy() -> Policy {
    Policy::new(8, 4096).unwrap()
}
fn now() -> ev_time_contract::Instant {
    Domain::new(77).unwrap().at(15)
}
fn time() -> Time {
    time_interval(100, 101)
}
fn time_interval(a: u64, b: u64) -> Time {
    let d = Domain::new(77).unwrap();
    Time::Qualified(
        QualifiedWindow::new(d.at(10), d.at(20), UtcInterval::new(a, b).unwrap()).unwrap(),
    )
}
fn public(key: &SigningKey) -> PublicKey {
    PublicKey::parse(key.verifying_key().to_bytes()).unwrap()
}
fn signed(role: Role, payload: &[u8], keys: &[&SigningKey]) -> Vec<u8> {
    let mut bytes = signature::header(role, payload.len(), keys.len())
        .unwrap()
        .to_vec();
    bytes.extend_from_slice(payload);
    let mut signatures: Vec<_> = keys
        .iter()
        .map(|key| (public(key).id(), key.sign(&bytes).to_bytes()))
        .collect();
    signatures.sort_by_key(|v| v.0);
    for (id, sig) in signatures {
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&sig);
    }
    bytes
}
struct Keys {
    keys: Vec<SigningKey>,
    root_count: usize,
}
impl Keys {
    fn new(first: u8, count: usize) -> Self {
        Self {
            keys: (0..count + 3)
                .map(|i| SigningKey::from_bytes(&[first + i as u8; 32]))
                .collect(),
            root_count: count,
        }
    }
    fn role(&self, role: Role) -> Vec<&SigningKey> {
        if role == Role::Root {
            self.keys[..self.root_count].iter().collect()
        } else {
            vec![&self.keys[self.root_count + role as usize - 2]]
        }
    }
    fn public_and_policies(&self) -> (Vec<PublicKey>, [RolePolicy; 4]) {
        let mut keys: Vec<_> = self.keys.iter().map(public).collect();
        keys.sort_by_key(|k| k.id());
        let roles = [Role::Root, Role::Targets, Role::Snapshot, Role::Timestamp];
        let max = [1000, 500, 300, 100];
        let policies = core::array::from_fn(|i| {
            let role = self.role(roles[i]);
            let mut mask = 0;
            for key in &role {
                mask |= 1 << keys.iter().position(|p| *p == public(key)).unwrap();
            }
            RolePolicy {
                mask,
                threshold: role.len() as u8,
                max_validity_secs: max[i],
            }
        });
        (keys, policies)
    }
    fn root_payload(&self, c: Common) -> Vec<u8> {
        let (keys, p) = self.public_and_policies();
        let mut bytes = vec![0; md::ROOT_BYTES];
        md::encode_root(&mut bytes, c, &keys, p).unwrap();
        bytes
    }
    fn root(&self, version: u64, signers: &[&SigningKey]) -> Vec<u8> {
        let c = Common {
            not_before: 0,
            expires: 500,
            ..common(version, version)
        };
        signed(Role::Root, &self.root_payload(c), signers)
    }
}
fn spec(name: u8, version: u64, data: &[u8]) -> TargetSpec {
    TargetSpec {
        name: [name; 32],
        version,
        length: data.len() as u64,
        sha256: Sha256::digest(data).into(),
        generation: [4; 32],
        release: [5; 32],
        source_revision: [6; 32],
        build: [7; 32],
        provenance: [8; 32],
        contract: [9; 32],
    }
}
struct Bundle {
    targets: Vec<u8>,
    snapshot: Vec<u8>,
    timestamp: Vec<u8>,
}
fn targets(keys: &Keys, c: Common, specs: &[TargetSpec]) -> Vec<u8> {
    let mut p = vec![0; md::HEADER_BYTES + md::TARGET_BYTES * specs.len()];
    md::encode_targets(&mut p, c, specs).unwrap();
    signed(Role::Targets, &p, &keys.role(Role::Targets))
}
fn linked(keys: &Keys, role: Role, c: Common, link: Identity) -> Vec<u8> {
    let mut p = vec![0; md::HEADER_BYTES + md::LINK_BYTES];
    md::encode_link(&mut p, role, c, link).unwrap();
    signed(role, &p, &keys.role(role))
}
fn identity(bytes: &[u8], version: u64) -> Identity {
    Identity::of(&Envelope::parse(bytes).unwrap(), version)
}
fn bundle(keys: &Keys, root: u64, versions: [u64; 3], specs: &[TargetSpec]) -> Bundle {
    let targets = targets(keys, common(root, versions[0]), specs);
    let snapshot = linked(
        keys,
        Role::Snapshot,
        common(root, versions[1]),
        identity(&targets, versions[0]),
    );
    let timestamp = linked(
        keys,
        Role::Timestamp,
        common(root, versions[2]),
        identity(&snapshot, versions[1]),
    );
    Bundle {
        targets,
        snapshot,
        timestamp,
    }
}
fn verify<'a>(
    root: &TrustedRoot<'_>,
    state: &ReplayState,
    b: &'a Bundle,
) -> Result<v::Verified<'a>, Error> {
    v::verify_bundle(
        root,
        state,
        v::Bundle {
            timestamp: &b.timestamp,
            snapshot: &b.snapshot,
            targets: &b.targets,
        },
        time(),
        now(),
        policy(),
    )
}
fn error<T>(r: Result<T, Error>) -> Error {
    match r {
        Ok(_) => panic!("unexpected acceptance"),
        Err(e) => e,
    }
}
#[test]
fn actual_signatures_bind_complete_chain_and_exact_artifact_bytes() {
    let keys = Keys::new(1, 2);
    let bytes = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&bytes, binding()).unwrap();
    let initial = ReplayState::initial(&root);
    let before = initial;
    let b = bundle(
        &keys,
        1,
        [1; 3],
        &[spec(10, 1, b"downloaded executable bytes")],
    );
    let verified = verify(&root, &initial, &b).unwrap();
    assert_eq!(initial, before);
    assert_eq!(verified.targets().len(), 1);
    assert!(
        verified
            .verify_artifact([10; 32], b"downloaded executable bytes")
            .is_ok()
    );
    assert!(
        verified
            .verify_artifact([10; 32], b"downloaded executable byteS")
            .is_err()
    );
    assert!(
        verified
            .verify_artifact([11; 32], b"downloaded executable bytes")
            .is_err()
    );
    let next = *verified.proposed();
    assert_eq!(next.utc_floor(), 100);
    assert_eq!(next.root(), root.identity());
    assert_eq!(verify(&root, &next, &b).unwrap().proposed(), &next);
    let restored =
        ReplayState::restored(&root, *next.roles(), *next.targets(), next.utc_floor()).unwrap();
    assert_eq!(restored, next);
}
#[test]
fn namespace_channel_and_platform_are_not_transport_claims() {
    let keys = Keys::new(1, 1);
    let bytes = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&bytes, binding()).unwrap();
    let state = ReplayState::initial(&root);
    for which in 0..3 {
        let mut c = common(1, 1);
        match which {
            0 => c.binding.namespace[0] ^= 1,
            1 => c.binding.channel[0] ^= 1,
            _ => c.binding.platform[0] ^= 1,
        }
        let t = targets(&keys, c, &[spec(1, 1, b"a")]);
        let sn = linked(&keys, Role::Snapshot, common(1, 1), identity(&t, 1));
        let ts = linked(&keys, Role::Timestamp, common(1, 1), identity(&sn, 1));
        let b = Bundle {
            targets: t,
            snapshot: sn,
            timestamp: ts,
        };
        assert_eq!(error(verify(&root, &state, &b)), Error::Binding);
        assert_eq!(
            error(TrustedRoot::provisioned(&bytes, c.binding)),
            Error::Binding
        );
    }
}
#[test]
fn separate_role_keys_and_signature_domain_refuse_relabelled_or_forged_metadata() {
    let keys = Keys::new(1, 1);
    let bytes = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&bytes, binding()).unwrap();
    let state = ReplayState::initial(&root);
    let mut b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"a")]);
    let payload = Envelope::parse(&b.targets).unwrap().payload().to_vec();
    b.targets = signed(Role::Targets, &payload, &keys.role(Role::Timestamp));
    b.snapshot = linked(&keys, Role::Snapshot, common(1, 1), identity(&b.targets, 1));
    b.timestamp = linked(
        &keys,
        Role::Timestamp,
        common(1, 1),
        identity(&b.snapshot, 1),
    );
    assert_eq!(
        error(verify(&root, &state, &b)),
        Error::Metadata(md::Error::Signature(signature::Error::Threshold))
    );
    let mut b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"a")]);
    let last = b.targets.len() - 1;
    b.targets[last] ^= 1;
    b.snapshot = linked(&keys, Role::Snapshot, common(1, 1), identity(&b.targets, 1));
    b.timestamp = linked(
        &keys,
        Role::Timestamp,
        common(1, 1),
        identity(&b.snapshot, 1),
    );
    assert!(verify(&root, &state, &b).is_err());
    let b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"a")]);
    assert!(
        v::verify_bundle(
            &root,
            &state,
            v::Bundle {
                timestamp: &b.snapshot,
                snapshot: &b.timestamp,
                targets: &b.targets
            },
            time(),
            now(),
            policy()
        )
        .is_err()
    );
}
#[test]
fn exact_hash_length_and_version_links_refuse_validly_signed_mix_and_match() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let state = ReplayState::initial(&root);
    let original = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"a")]);
    for which in 0..3 {
        let mut id = identity(&original.targets, 1);
        match which {
            0 => id.sha256[0] ^= 1,
            1 => id.length += 1,
            _ => id.version += 1,
        };
        let sn = linked(&keys, Role::Snapshot, common(1, 1), id);
        let ts = linked(&keys, Role::Timestamp, common(1, 1), identity(&sn, 1));
        let b = Bundle {
            targets: original.targets.clone(),
            snapshot: sn,
            timestamp: ts,
        };
        assert_eq!(error(verify(&root, &state, &b)), Error::Link);
    }
    let other = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"b")]);
    let b = Bundle {
        targets: other.targets,
        snapshot: original.snapshot,
        timestamp: original.timestamp,
    };
    assert_eq!(error(verify(&root, &state, &b)), Error::Link);
}
#[test]
fn qualified_time_is_required_again_even_for_exact_idempotent_revalidation() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"a")]);
    let state = *verify(&root, &ReplayState::initial(&root), &b)
        .unwrap()
        .proposed();
    let before = state;
    for (sample, instant, expected) in [
        (Time::Unknown, now(), freshness::Error::UnknownTime),
        (
            Time::Tentative(UtcInterval::new(100, 101).unwrap()),
            now(),
            freshness::Error::UnqualifiedTime,
        ),
        (time_interval(99, 100), now(), freshness::Error::Rollback),
        (
            time(),
            Domain::new(77).unwrap().at(21),
            freshness::Error::StaleSample,
        ),
        (time_interval(149, 150), now(), freshness::Error::Uncertain),
        (time_interval(150, 151), now(), freshness::Error::Expired),
    ] {
        assert_eq!(
            error(v::verify_bundle(
                &root,
                &state,
                v::Bundle {
                    timestamp: &b.timestamp,
                    snapshot: &b.snapshot,
                    targets: &b.targets
                },
                sample,
                instant,
                policy()
            )),
            Error::Time(expected)
        );
        assert_eq!(state, before);
    }
    assert!(
        v::verify_bundle(
            &root,
            &state,
            v::Bundle {
                timestamp: &b.timestamp,
                snapshot: &b.snapshot,
                targets: &b.targets
            },
            time(),
            Domain::new(78).unwrap().at(15),
            policy()
        )
        .is_err()
    );
}
#[test]
fn signed_overlong_freshness_interval_is_refused_by_trusted_role_policy() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let mut b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"a")]);
    b.timestamp = linked(
        &keys,
        Role::Timestamp,
        Common {
            not_before: 0,
            expires: 400,
            ..common(1, 1)
        },
        identity(&b.snapshot, 1),
    );
    assert_eq!(
        error(verify(&root, &ReplayState::initial(&root), &b)),
        Error::Metadata(md::Error::Validity)
    );
}
#[test]
fn successive_root_rotation_requires_old_and_new_real_thresholds() {
    let old = Keys::new(1, 2);
    let new = Keys::new(21, 2);
    let rb = old.root(1, &old.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let state = ReplayState::initial(&root);
    let before = state;
    let mut both = old.role(Role::Root);
    both.extend(new.role(Role::Root));
    let next = new.root(2, &both);
    let advance = v::advance_root(&root, &state, &next).unwrap();
    assert!(advance.changed);
    assert_eq!(state, before);
    assert_eq!(advance.proposed.targets(), state.targets());
    assert_eq!(advance.proposed.roles(), state.roles());
    assert_eq!(advance.proposed.utc_floor(), state.utc_floor());
    for bad in [
        new.root(2, &old.role(Role::Root)),
        new.root(2, &new.role(Role::Root)),
        new.root(3, &both),
    ] {
        assert!(v::advance_root(&root, &state, &bad).is_err());
        assert_eq!(state, before);
    }
    let same = v::advance_root(&root, &state, &rb).unwrap();
    assert!(!same.changed);
    assert_eq!(same.proposed, state);
    let mut c = common(1, 1);
    c.not_before = 0;
    c.expires = 400;
    let different = signed(Role::Root, &old.root_payload(c), &old.role(Role::Root));
    assert_eq!(
        error(v::advance_root(&root, &state, &different)),
        Error::SameVersionConflict
    );
    let b = bundle(&new, 2, [1; 3], &[spec(1, 1, b"new")]);
    assert!(verify(&advance.root, &advance.proposed, &b).is_ok());
    assert_eq!(
        error(verify(&advance.root, &state, &b)),
        Error::RootCheckpoint
    );
}
#[test]
fn expired_intermediate_roots_can_rotate_but_final_expired_root_cannot_accept_targets() {
    let old = Keys::new(1, 1);
    let middle = Keys::new(11, 1);
    let new = Keys::new(21, 1);
    let rb = signed(
        Role::Root,
        &old.root_payload(Common {
            not_before: 0,
            expires: 50,
            ..common(1, 1)
        }),
        &old.role(Role::Root),
    );
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let s = ReplayState::initial(&root);
    let mut sign = old.role(Role::Root);
    sign.extend(middle.role(Role::Root));
    let mid = signed(
        Role::Root,
        &middle.root_payload(Common {
            not_before: 0,
            expires: 80,
            ..common(2, 2)
        }),
        &sign,
    );
    let middle_root = v::advance_root(&root, &s, &mid).unwrap();
    let b = bundle(&middle, 2, [1; 3], &[spec(1, 1, b"a")]);
    assert_eq!(
        error(verify(&middle_root.root, &middle_root.proposed, &b)),
        Error::Time(freshness::Error::Expired)
    );
    let mut sign = middle.role(Role::Root);
    sign.extend(new.role(Role::Root));
    let nb = new.root(3, &sign);
    let final_root = v::advance_root(&middle_root.root, &middle_root.proposed, &nb).unwrap();
    let b = bundle(&new, 3, [1; 3], &[spec(1, 1, b"b")]);
    assert!(verify(&final_root.root, &final_root.proposed, &b).is_ok());
}
#[test]
fn target_floors_survive_root_rotation_and_removed_targets() {
    let old = Keys::new(1, 1);
    let new = Keys::new(21, 1);
    let rb = old.root(1, &old.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let b = bundle(&old, 1, [2; 3], &[spec(1, 2, b"v2")]);
    let s = *verify(&root, &ReplayState::initial(&root), &b)
        .unwrap()
        .proposed();
    let withdrawn = bundle(&old, 1, [3; 3], &[]);
    let withdrawn = *verify(&root, &s, &withdrawn).unwrap().proposed();
    assert_eq!(withdrawn.targets(), s.targets());
    let mut sign = old.role(Role::Root);
    sign.extend(new.role(Role::Root));
    let nb = new.root(2, &sign);
    let rotated = v::advance_root(&root, &withdrawn, &nb).unwrap();
    assert_eq!(rotated.proposed.targets(), s.targets());
    assert_eq!(rotated.proposed.roles(), withdrawn.roles());
    let rollback = bundle(&new, 2, [4; 3], &[spec(1, 1, b"old")]);
    assert_eq!(
        error(verify(&rotated.root, &rotated.proposed, &rollback)),
        Error::Rollback
    );
    let role_reset = bundle(&new, 2, [1; 3], &[spec(1, 3, b"new")]);
    assert_eq!(
        error(verify(&rotated.root, &rotated.proposed, &role_reset)),
        Error::Rollback
    );
    let good = bundle(&new, 2, [4; 3], &[spec(1, 3, b"new")]);
    assert!(verify(&rotated.root, &rotated.proposed, &good).is_ok());
}
#[test]
fn same_version_conflicts_and_bounded_fast_forward_refuse_without_state_change() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"one")]);
    let s = *verify(&root, &ReplayState::initial(&root), &b)
        .unwrap()
        .proposed();
    let before = s;
    for (candidate, expected) in [
        (
            bundle(&keys, 1, [1; 3], &[spec(1, 2, b"two")]),
            Error::SameVersionConflict,
        ),
        (
            bundle(&keys, 1, [2; 3], &[spec(1, 1, b"conflict")]),
            Error::SameVersionConflict,
        ),
        (
            bundle(&keys, 1, [10; 3], &[spec(1, 2, b"two")]),
            Error::FastForward,
        ),
        (
            bundle(&keys, 1, [2; 3], &[spec(1, 10, b"two")]),
            Error::FastForward,
        ),
    ] {
        assert_eq!(error(verify(&root, &s, &candidate)), expected);
        assert_eq!(s, before);
    }
}
#[test]
fn fixed_floor_capacity_never_evicts_a_withdrawn_identity() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let specs: Vec<_> = (1..=8).map(|n| spec(n, 1, b"a")).collect();
    let b = bundle(&keys, 1, [1; 3], &specs);
    let s = *verify(&root, &ReplayState::initial(&root), &b)
        .unwrap()
        .proposed();
    let empty = bundle(&keys, 1, [2; 3], &[]);
    let s = *verify(&root, &s, &empty).unwrap().proposed();
    let replacement = bundle(&keys, 1, [3; 3], &[spec(9, 1, b"b")]);
    assert_eq!(error(verify(&root, &s, &replacement)), Error::Capacity);
    assert_eq!(s.targets().iter().flatten().count(), 8);
}
#[test]
fn canonical_counts_key_policies_order_reserved_and_cohort_fail_closed() {
    let keys = Keys::new(1, 1);
    let root = keys.root(1, &keys.role(Role::Root));
    for n in 0..root.len() {
        assert!(Envelope::parse(&root[..n]).is_err());
    }
    let original = keys.root_payload(Common {
        not_before: 0,
        expires: 500,
        ..common(1, 1)
    });
    for at in [
        11,
        15,
        146,
        159,
        md::HEADER_BYTES + 4 * 32,
        md::HEADER_BYTES + signature::MAX_KEYS * 32 + 3,
    ] {
        let mut p = original.clone();
        p[at] = 1;
        let bytes = signed(Role::Root, &p, &keys.role(Role::Root));
        assert!(TrustedRoot::provisioned(&bytes, binding()).is_err());
    }
    let (mut public, policies) = keys.public_and_policies();
    public.swap(0, 1);
    let mut p = vec![0; md::ROOT_BYTES];
    md::encode_root(
        &mut p,
        Common {
            not_before: 0,
            expires: 500,
            ..common(1, 1)
        },
        &public,
        policies,
    )
    .unwrap();
    assert!(
        TrustedRoot::provisioned(&signed(Role::Root, &p, &keys.role(Role::Root)), binding())
            .is_err()
    );
    for which in 0..3 {
        let (public, mut policies) = keys.public_and_policies();
        match which {
            0 => policies[0].threshold = 0,
            1 => policies[1].mask = policies[0].mask,
            _ => policies[2].max_validity_secs = 0,
        };
        md::encode_root(
            &mut p,
            Common {
                not_before: 0,
                expires: 500,
                ..common(1, 1)
            },
            &public,
            policies,
        )
        .unwrap();
        assert!(
            TrustedRoot::provisioned(&signed(Role::Root, &p, &keys.role(Role::Root)), binding())
                .is_err()
        );
    }
    let too_large = Keys::new(31, 5);
    let rb = too_large.root(1, &too_large.role(Role::Root));
    assert_eq!(
        error(TrustedRoot::provisioned(&rb, binding())),
        Error::Metadata(md::Error::Policy)
    );
    for specs in [
        vec![spec(2, 1, b"a"), spec(1, 1, b"b")],
        vec![spec(1, 1, b"a"), spec(1, 1, b"b")],
        vec![
            spec(1, 1, b"a"),
            TargetSpec {
                generation: [99; 32],
                ..spec(2, 1, b"b")
            },
        ],
    ] {
        let bytes = targets(&keys, common(1, 1), &specs);
        let env = Envelope::parse(&bytes).unwrap();
        assert!(md::Targets::parse(&env).is_err());
    }
}
#[test]
fn artifact_staging_bound_and_restored_checkpoint_structure_are_explicit() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let b = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"too long")]);
    let s = ReplayState::initial(&root);
    assert_eq!(
        error(v::verify_bundle(
            &root,
            &s,
            v::Bundle {
                timestamp: &b.timestamp,
                snapshot: &b.snapshot,
                targets: &b.targets
            },
            time(),
            now(),
            Policy::new(8, 2).unwrap()
        )),
        Error::Bounds
    );
    assert!(Policy::new(0, 4096).is_err());
    assert!(Policy::new(1_000_001, 4096).is_err());
    assert!(Policy::new(1, 0).is_err());
    assert!(
        ReplayState::restored(
            &root,
            [Some(root.identity()), None, None],
            [None; md::MAX_TARGETS],
            0
        )
        .is_err()
    );
    assert!(core::mem::size_of::<md::Root<'_>>() <= 768);
    assert!(core::mem::size_of::<ReplayState>() <= 1280);
    assert!(core::mem::size_of::<v::Verified<'_>>() <= 1536);
}

#[test]
fn two_of_three_roots_rotate_with_independent_partial_old_and_new_quorums() {
    let old = Keys::new(1, 3);
    let new = Keys::new(21, 3);
    let make = |keys: &Keys, version, signers: &[&SigningKey]| {
        let (public, mut policies) = keys.public_and_policies();
        policies[0].threshold = 2;
        let mut payload = vec![0; md::ROOT_BYTES];
        md::encode_root(
            &mut payload,
            Common {
                not_before: 0,
                expires: 500,
                ..common(version, version)
            },
            &public,
            policies,
        )
        .unwrap();
        signed(Role::Root, &payload, signers)
    };
    let rb = make(&old, 1, &old.role(Role::Root)[..2]);
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let state = ReplayState::initial(&root);
    let mut both = old.role(Role::Root)[..2].to_vec();
    both.extend_from_slice(&new.role(Role::Root)[1..]);
    let candidate = make(&new, 2, &both);
    assert!(v::advance_root(&root, &state, &candidate).is_ok());
    for missing_old in [true, false] {
        let mut signers = old.role(Role::Root)[..if missing_old { 1 } else { 2 }].to_vec();
        signers.extend_from_slice(&new.role(Role::Root)[..if missing_old { 2 } else { 1 }]);
        let candidate = make(&new, 2, &signers);
        assert!(v::advance_root(&root, &state, &candidate).is_err());
    }
}
#[test]
fn maximum_supported_disjoint_root_rotation_fits_exact_eight_signature_bound() {
    let old = Keys::new(1, 4);
    let new = Keys::new(21, 4);
    let rb = old.root(1, &old.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let state = ReplayState::initial(&root);
    let mut both = old.role(Role::Root);
    both.extend(new.role(Role::Root));
    let candidate = new.root(2, &both);
    assert_eq!(
        Envelope::parse(&candidate).unwrap().signature_count(),
        signature::MAX_SIGNATURES
    );
    assert!(v::advance_root(&root, &state, &candidate).is_ok());
}
#[test]
fn malformed_trusted_checkpoint_cannot_alias_two_target_floor_names() {
    let keys = Keys::new(1, 1);
    let rb = keys.root(1, &keys.role(Role::Root));
    let root = TrustedRoot::provisioned(&rb, binding()).unwrap();
    let bundle = bundle(&keys, 1, [1; 3], &[spec(1, 1, b"one")]);
    let verified = verify(&root, &ReplayState::initial(&root), &bundle).unwrap();
    let state = verified.proposed();
    let mut targets = *state.targets();
    targets[1] = targets[0];
    assert_eq!(
        error(ReplayState::restored(
            &root,
            *state.roles(),
            targets,
            state.utc_floor()
        )),
        Error::State
    );
    targets[1] = None;
    targets[0].as_mut().unwrap().version = 0;
    assert_eq!(
        error(ReplayState::restored(
            &root,
            *state.roles(),
            targets,
            state.utc_floor()
        )),
        Error::State
    );
}
