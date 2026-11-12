//! Explicit cap-free SDK RPC regression fixture. No authority or performance
//! result follows from parsing these framing/role declarations.
#![no_std]
#![forbid(unsafe_code)]
pub mod client;
pub mod sdk;
pub mod server;
pub const WARMUP: u32 = 64;
pub const ROUNDS: u32 = 4096;
pub const TOTAL: u32 = WARMUP + ROUNDS;
pub const ROOT_LIMITS: [u64; 4] = [16384, 64, 4, 8];
pub const CHILD_LIMITS: [u64; 4] = [16384, 32, 1, 1];
pub const ROOT_ROLES: [(u8, u16); 5] = [(1, 1), (2, 8), (5, 256), (1, 1), (1, 1)];
pub const CLIENT_ROLES: [(u8, u16); 3] = [(2, 8), (2, 8), (2, 272)];
pub const SERVER_ROLES: [(u8, u16); 2] = [(2, 272), (2, 8)];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    ServerReady,
    ClientReady,
    WarmupComplete,
    ServerComplete,
    SampleBegin,
    SampleEnd,
    BatchBefore,
    BatchAfter,
    Finish,
}
impl Event {
    pub const fn encode(self) -> [u8; 8] {
        let code = match self {
            Self::ServerReady => 1,
            Self::ClientReady => 2,
            Self::WarmupComplete => 3,
            Self::ServerComplete => 4,
            Self::SampleBegin => 5,
            Self::SampleEnd => 6,
            Self::BatchBefore => 7,
            Self::BatchAfter => 8,
            Self::Finish => 9,
        };
        [b'I', b'B', 1, code, 0, 0, 0, 0]
    }
    pub fn decode(b: [u8; 8]) -> Option<Self> {
        if b[..3] != [b'I', b'B', 1] || b[4..] != [0; 4] {
            return None;
        }
        Some(match b[3] {
            1 => Self::ServerReady,
            2 => Self::ClientReady,
            3 => Self::WarmupComplete,
            4 => Self::ServerComplete,
            5 => Self::SampleBegin,
            6 => Self::SampleEnd,
            7 => Self::BatchBefore,
            8 => Self::BatchAfter,
            9 => Self::Finish,
            _ => return None,
        })
    }
}
pub const START_WARMUP: [u8; 8] = [b'I', b'C', 1, 1, 0, 0, 0, 0];
pub const START_MEASURED: [u8; 8] = [b'I', b'C', 1, 2, 0, 0, 0, 0];
const REQUEST_TAG: u32 = 0x3142_5049;
const RESPONSE_MASK: u64 = 0x9b1e_27a5_63d8_40fc;
pub fn request(sequence: u32) -> [u8; 8] {
    ((u64::from(REQUEST_TAG) << 32) | u64::from(sequence)).to_le_bytes()
}
pub fn response(bytes: [u8; 8]) -> [u8; 8] {
    (u64::from_le_bytes(bytes).rotate_left(17) ^ RESPONSE_MASK).to_le_bytes()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub warmups: u64,
    pub rounds: u64,
    pub first_tick: u64,
    pub last_tick: u64,
}
impl Sample {
    pub fn words(self) -> [u64; 4] {
        [self.warmups, self.rounds, self.first_tick, self.last_tick]
    }
    pub fn checked(words: [u64; 4], stop: u64) -> Option<Self> {
        let [warmups, rounds, first_tick, last_tick] = words;
        if warmups != u64::from(WARMUP)
            || rounds != u64::from(ROUNDS)
            || first_tick > last_tick
            || last_tick >= stop
        {
            return None;
        }
        Some(Self {
            warmups,
            rounds,
            first_tick,
            last_tick,
        })
    }
}
pub fn roles(bytes: &[u8], limits: [u64; 4], expected: &[(u8, u16)]) -> Option<[u64; 6]> {
    let parsed = ev_userspace_contract::Bootstrap::parse(bytes).ok()?;
    if expected.len() > 6 || parsed.grants().count() != expected.len() {
        return None;
    }
    for (i, n) in limits.into_iter().enumerate() {
        if bytes[40 + i * 8..48 + i * 8] != n.to_le_bytes() {
            return None;
        }
    }
    let mut handles = [0; 6];
    for (i, &(kind, rights)) in expected.iter().enumerate() {
        let g = parsed.find(i as u64 + 1)?;
        if g.kind != kind || g.rights != rights || handles[..i].contains(&g.handle) {
            return None;
        }
        handles[i] = g.handle;
    }
    Some(handles)
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_frames_and_samples_cannot_accept_provider_or_control_packets() {
        for e in [
            Event::ServerReady,
            Event::ClientReady,
            Event::WarmupComplete,
            Event::ServerComplete,
            Event::SampleBegin,
            Event::SampleEnd,
            Event::BatchBefore,
            Event::BatchAfter,
            Event::Finish,
        ] {
            assert_eq!(Event::decode(e.encode()), Some(e));
            let mut bad = e.encode();
            bad[7] = 1;
            assert_eq!(Event::decode(bad), None);
        }
        assert_eq!(Event::decode(START_WARMUP), None);
        assert_eq!(Event::decode([b'P', b'R', 1, 3, 0, 0, 0, 0]), None);
        assert!(Sample::checked([64, 4096, 10, 10], 11).is_some());
        for bad in [
            [63, 4096, 10, 11],
            [64, 4095, 10, 11],
            [64, 4096, 12, 11],
            [64, 4096, 10, 20],
        ] {
            assert!(Sample::checked(bad, 20).is_none());
        }
    }
    #[test]
    fn ordinary_role_metadata_rejects_extra_authority_or_capability_aliases() {
        use ev_userspace_contract::{Context, Grant, encode};
        for shape in [&ROOT_ROLES[..], &CLIENT_ROLES[..], &SERVER_ROLES[..]] {
            let limits = if shape.len() == 5 {
                ROOT_LIMITS
            } else {
                CHILD_LIMITS
            };
            let context = Context {
                epoch: 1,
                incarnation: 1,
                process: 1,
                limits,
                manifest: [1; 32],
                authority: [2; 32],
            };
            let grants: std::vec::Vec<_> = shape
                .iter()
                .enumerate()
                .map(|(i, &(kind, rights))| Grant {
                    selector: i as u64 + 1,
                    handle: 512 + i as u64,
                    kind,
                    rights,
                })
                .collect();
            assert!(roles(&encode(context, &grants).unwrap(), limits, shape).is_some());
            let mut aliased = grants.clone();
            aliased[1].handle = aliased[0].handle;
            if let Ok(bytes) = encode(context, &aliased) {
                assert!(roles(&bytes, limits, shape).is_none());
            }
            let mut widened = grants.clone();
            widened[0].rights ^= 256;
            if let Ok(bytes) = encode(context, &widened) {
                assert!(roles(&bytes, limits, shape).is_none());
            }
        }
    }
    #[test]
    fn every_request_and_reply_is_sequence_sensitive() {
        let mut last = None;
        for n in 0..TOTAL {
            let r = response(request(n));
            assert_ne!(Some(r), last);
            last = Some(r);
        }
        assert_ne!(request(0), request(TOTAL));
    }
}
