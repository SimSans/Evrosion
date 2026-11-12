//! Internal test-provider actors. Lifecycle/identity data are not capabilities.
#![no_std]
#![forbid(unsafe_code)]
pub mod endpoint;
pub use ev_userspace_contract::provider as wire;
pub const CHILD_LIMITS: [u64; 4] = [16_384, 32, 1, 1];
pub const ROOT_LIMITS: [u64; 4] = [16_384, 64, 4, 8];
/// Ordered startup declarations consumed by source actors and bundle admission.
/// Kind/rights numbers are ABI data, never an authority-producing selector.
pub const ROOT_ROLES: [(u8, u16); 6] = [(1, 1), (2, 8), (5, 256), (1, 1), (1, 1), (1, 1)];
pub const CONSUMER_ROLES: [(u8, u16); 3] = [(2, 8), (2, 8), (2, 272)];
pub const PROVIDER_ROLES: [(u8, u16); 2] = [(2, 272), (2, 8)];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    ProviderReady,
    PhaseComplete { phase: u32 },
    SwitchComplete,
}
impl Event {
    pub fn encode(self) -> [u8; 8] {
        let (opcode, value) = match self {
            Self::ProviderReady => (1, 0),
            Self::PhaseComplete { phase } => (2, phase),
            Self::SwitchComplete => (3, 0),
        };
        let mut bytes = [b'P', b'R', 1, opcode, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&value.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: [u8; 8]) -> Option<Self> {
        if bytes[..3] != [b'P', b'R', 1] {
            return None;
        }
        let value = u32::from_le_bytes(bytes[4..].try_into().ok()?);
        match (bytes[3], value) {
            (1, 0) => Some(Self::ProviderReady),
            (2, 1..=2) => Some(Self::PhaseComplete { phase: value }),
            (3, 0) => Some(Self::SwitchComplete),
            _ => None,
        }
    }
}
pub const CONTINUE: [u8; 8] = [b'P', b'C', 1, 1, 0, 0, 0, 0];
pub fn roles(bytes: &[u8], limits: [u64; 4], expected: &[(u8, u16)]) -> Option<[u64; 6]> {
    let bootstrap = ev_userspace_contract::Bootstrap::parse(bytes).ok()?;
    if expected.len() > 6 || bootstrap.grants().count() != expected.len() {
        return None;
    }
    for (index, value) in limits.into_iter().enumerate() {
        if bytes[40 + index * 8..48 + index * 8] != value.to_le_bytes() {
            return None;
        }
    }
    let mut handles = [0; 6];
    for (index, &(kind, rights)) in expected.iter().enumerate() {
        let grant = bootstrap.find((index + 1) as u64)?;
        if grant.kind != kind || grant.rights != rights || handles[..index].contains(&grant.handle)
        {
            return None;
        }
        handles[index] = grant.handle;
    }
    Some(handles)
}
#[inline(never)]
pub fn implementation_a(value: u32) -> Result<u32, wire::Refusal> {
    value
        .checked_mul(2)
        .and_then(|x| x.checked_add(1))
        .ok_or(wire::Refusal::Overflow)
}
#[inline(never)]
pub fn implementation_b(value: u32) -> Result<u32, wire::Refusal> {
    if value > wire::MAX_INPUT {
        return Err(wire::Refusal::Overflow);
    }
    let mut input = core::hint::black_box(value);
    let mut place = 2u32;
    let mut result = 1u32;
    for _ in 0..31 {
        if input & 1 != 0 {
            result |= place;
        }
        input = core::hint::black_box(input >> 1);
        place = place.wrapping_shl(1);
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};
    #[test]
    fn role_profiles_reject_aliases_wrong_rights_and_limits_before_lifecycle() {
        for expected in [&PROVIDER_ROLES[..], &CONSUMER_ROLES[..], &ROOT_ROLES[..]] {
            let limits = if expected.len() == 6 {
                ROOT_LIMITS
            } else {
                CHILD_LIMITS
            };
            let context = Context {
                epoch: 1,
                incarnation: 1,
                process: 7,
                limits,
                manifest: [1; 32],
                authority: [2; 32],
            };
            let mut grants = [Grant {
                selector: 1,
                handle: 512,
                kind: 1,
                rights: 1,
            }; 6];
            for (index, &(kind, rights)) in expected.iter().enumerate() {
                grants[index] = Grant {
                    selector: (index + 1) as u64,
                    handle: 512 + index as u64,
                    kind,
                    rights,
                };
            }
            let bytes = encode(context, &grants[..expected.len()]).unwrap();
            assert!(roles(&bytes, limits, expected).is_some());
            let mut wrong = context;
            wrong.limits[0] = 2048;
            assert!(
                roles(
                    &encode(wrong, &grants[..expected.len()]).unwrap(),
                    limits,
                    expected
                )
                .is_none()
            );
            for index in 0..expected.len() {
                let mut wrong = grants;
                wrong[index].rights ^= 256;
                if let Ok(bytes) = encode(context, &wrong[..expected.len()]) {
                    assert!(roles(&bytes, limits, expected).is_none());
                }
            }
            grants[1].handle = grants[0].handle;
            assert!(
                roles(
                    &encode(context, &grants[..expected.len()]).unwrap(),
                    limits,
                    expected
                )
                .is_none()
            );
        }
    }
    #[test]
    fn lifecycle_frames_are_total_canonical_and_do_not_accept_control_as_event() {
        for event in [
            Event::ProviderReady,
            Event::PhaseComplete { phase: 1 },
            Event::PhaseComplete { phase: 2 },
            Event::SwitchComplete,
        ] {
            let bytes = event.encode();
            assert_eq!(Event::decode(bytes), Some(event));
            for index in [0, 1, 2, 5, 6, 7] {
                let mut bad = bytes;
                bad[index] ^= 1;
                assert!(Event::decode(bad).is_none());
            }
        }
        assert!(Event::decode(CONTINUE).is_none());
        for phase in [0u32, 3, u32::MAX] {
            assert!(Event::decode(Event::PhaseComplete { phase }.encode()).is_none());
        }
        assert_ne!(
            Event::PhaseComplete { phase: 1 }.encode(),
            Event::PhaseComplete { phase: 2 }.encode()
        );
        for opcode in 0..=255 {
            let mut b = Event::ProviderReady.encode();
            b[3] = opcode;
            assert_eq!(Event::decode(b).is_some(), [1, 3].contains(&opcode));
        }
    }
    #[test]
    fn actual_alternate_algorithms_agree_for_domain_and_overflow() {
        let mut value = 17u32;
        for _ in 0..100_000 {
            value = value.wrapping_mul(1664525).wrapping_add(1013904223);
            assert_eq!(implementation_a(value), implementation_b(value));
        }
        for value in [0, 137, wire::MAX_INPUT, wire::MAX_INPUT + 1, u32::MAX] {
            assert_eq!(implementation_a(value), implementation_b(value));
        }
    }
}
