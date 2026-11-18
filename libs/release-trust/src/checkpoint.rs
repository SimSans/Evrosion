//! Canonical durable-state payload. Hash-bound immutable storage and atomic
//! publication are external requirements; parsing creates no new root authority.
use crate::{
    metadata::{Binding, Identity, MAX_TARGETS},
    verifier::{ReplayState, TargetFloor, TrustedRoot},
};
pub const BYTES: usize = 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    Reserved,
    Binding,
    Root,
    State(crate::verifier::Error),
}
fn put(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
fn get(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn identity(out: &mut [u8], at: usize, v: Identity) {
    put(out, at, v.version);
    put(out, at + 8, v.length);
    out[at + 16..at + 48].copy_from_slice(&v.sha256);
}
fn read(b: &[u8], at: usize) -> Identity {
    Identity {
        version: get(b, at),
        length: get(b, at + 8),
        sha256: b[at + 16..at + 48].try_into().unwrap(),
    }
}
/// Preserve every retained floor, including withdrawn targets. This has no
/// initial-state fallback and advances neither authority nor durable state.
pub fn encode(state: &ReplayState, out: &mut [u8; BYTES]) {
    out.fill(0);
    out[..8].copy_from_slice(b"EVRCP001");
    out[8] = 1;
    let binding = state.binding();
    out[16..48].copy_from_slice(&binding.namespace);
    out[48..80].copy_from_slice(&binding.channel);
    out[80..112].copy_from_slice(&binding.platform);
    identity(out, 112, state.root());
    for (i, value) in state.roles().iter().enumerate() {
        if let Some(v) = value {
            out[10] |= 1 << i;
            identity(out, 160 + i * 48, *v);
        }
    }
    for (i, value) in state.targets().iter().enumerate() {
        if let Some(v) = value {
            out[11] |= 1 << i;
            let p = 304 + i * 72;
            out[p..p + 32].copy_from_slice(&v.name);
            put(out, p + 32, v.version);
            out[p + 40..p + 72].copy_from_slice(&v.identity);
        }
    }
    put(out, 880, state.utc_floor());
}
/// Caller must supply the exact independently trusted/continuity-verified root
/// retained with this same atomic checkpoint. This is syntax/association only,
/// not trust bootstrap, medium authentication or whole-disk rollback resistance.
pub fn decode(root: &TrustedRoot<'_>, bytes: &[u8; BYTES]) -> Result<ReplayState, Error> {
    if &bytes[..8] != b"EVRCP001" || bytes[8] != 1 {
        return Err(Error::Version);
    }
    if bytes[9] != 0
        || bytes[10] & !7 != 0
        || bytes[12..16]
            .iter()
            .chain(bytes[888..].iter())
            .any(|v| *v != 0)
    {
        return Err(Error::Reserved);
    }
    let binding = Binding {
        namespace: bytes[16..48].try_into().unwrap(),
        channel: bytes[48..80].try_into().unwrap(),
        platform: bytes[80..112].try_into().unwrap(),
    };
    if binding != root.common().binding {
        return Err(Error::Binding);
    }
    if read(bytes, 112) != root.identity() {
        return Err(Error::Root);
    }
    let mut roles = [None; 3];
    for (i, value) in roles.iter_mut().enumerate() {
        let p = 160 + i * 48;
        if bytes[10] & (1 << i) != 0 {
            *value = Some(read(bytes, p));
        } else if bytes[p..p + 48].iter().any(|v| *v != 0) {
            return Err(Error::Reserved);
        }
    }
    let mut targets = [None; MAX_TARGETS];
    for (i, value) in targets.iter_mut().enumerate() {
        let p = 304 + i * 72;
        if bytes[11] & (1 << i) != 0 {
            *value = Some(TargetFloor {
                name: bytes[p..p + 32].try_into().unwrap(),
                version: get(bytes, p + 32),
                identity: bytes[p + 40..p + 72].try_into().unwrap(),
            });
        } else if bytes[p..p + 72].iter().any(|v| *v != 0) {
            return Err(Error::Reserved);
        }
    }
    ReplayState::restored(root, roles, targets, get(bytes, 880)).map_err(Error::State)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{self, Common, RolePolicy},
        signature::{self, Envelope, PublicKey, Role},
    };
    use ed25519_dalek::{Signer, SigningKey};
    extern crate std;
    use std::{vec, vec::Vec};
    fn root_bytes() -> Vec<u8> {
        let binding = Binding {
            namespace: [1; 32],
            channel: [2; 32],
            platform: [3; 32],
        };
        let c = Common {
            binding,
            version: 1,
            root_version: 1,
            not_before: 1,
            expires: 1000,
        };
        let keys: [SigningKey; 4] =
            core::array::from_fn(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]));
        let mut public: Vec<_> = keys
            .iter()
            .map(|k| PublicKey::parse(k.verifying_key().to_bytes()).unwrap())
            .collect();
        public.sort_by_key(|k| k.id());
        let policies = core::array::from_fn(|i| RolePolicy {
            mask: 1
                << public
                    .iter()
                    .position(|p| p.bytes() == keys[i].verifying_key().to_bytes())
                    .unwrap(),
            threshold: 1,
            max_validity_secs: 1000,
        });
        let mut payload = vec![0; metadata::ROOT_BYTES];
        metadata::encode_root(&mut payload, c, &public, policies).unwrap();
        let mut b = signature::header(Role::Root, payload.len(), 1)
            .unwrap()
            .to_vec();
        b.extend(payload);
        let sig = keys[0].sign(&b).to_bytes();
        let k = PublicKey::parse(keys[0].verifying_key().to_bytes()).unwrap();
        b.extend(k.id());
        b.extend(sig);
        assert!(Envelope::parse(&b).is_ok());
        b
    }
    #[test]
    fn canonical_checkpoint_roundtrip_preserves_withdrawn_targets_and_all_floors() {
        let bytes = root_bytes();
        let root = TrustedRoot::provisioned(
            &bytes,
            Binding {
                namespace: [1; 32],
                channel: [2; 32],
                platform: [3; 32],
            },
        )
        .unwrap();
        let mut b = [0; BYTES];
        let initial = ReplayState::initial(&root);
        encode(&initial, &mut b);
        assert_eq!(decode(&root, &b), Ok(initial));
        let id = root.identity();
        let floors = core::array::from_fn(|i| {
            Some(TargetFloor {
                name: [i as u8 + 1; 32],
                version: i as u64 + 3,
                identity: [i as u8 + 5; 32],
            })
        });
        let state = ReplayState::restored(&root, [Some(id); 3], floors, 555).unwrap();
        encode(&state, &mut b);
        assert_eq!(decode(&root, &b), Ok(state));
        let mut again = [0; BYTES];
        encode(&decode(&root, &b).unwrap(), &mut again);
        assert_eq!(b, again);
    }
    #[test]
    fn malformed_or_unbound_checkpoint_never_resets_or_initializes_floors() {
        let bytes = root_bytes();
        let root = TrustedRoot::provisioned(
            &bytes,
            Binding {
                namespace: [1; 32],
                channel: [2; 32],
                platform: [3; 32],
            },
        )
        .unwrap();
        let state =
            ReplayState::restored(&root, [Some(root.identity()); 3], [None; 8], 555).unwrap();
        let mut good = [0; BYTES];
        encode(&state, &mut good);
        for offset in [0, 8, 9, 12, 15, 888, 1023, 16, 48, 80, 112, 128] {
            let mut b = good;
            b[offset] ^= 1;
            assert!(decode(&root, &b).is_err(), "offset {offset}");
        }
        let mut b = good;
        b[10] = 1;
        assert!(decode(&root, &b).is_err());
        let mut b = good;
        b[11] = 1;
        assert!(decode(&root, &b).is_err());
        let mut b = good;
        b[304] = 1;
        assert_eq!(decode(&root, &b), Err(Error::Reserved));
        let mut b = good;
        b[10] = 8;
        assert_eq!(decode(&root, &b), Err(Error::Reserved));
    }
}
