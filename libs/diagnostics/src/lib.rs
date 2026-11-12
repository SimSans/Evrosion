//! Bounded local crash data, never authority. Actual capture and persistence
//! belong to separately authorized collectors and storage owners.
//! Decoding establishes syntax/integrity only, not trusted capture or provenance.
#![no_std]
#![forbid(unsafe_code)]
use ev_app_identity::AppId;
use sha2::{Digest, Sha256};

pub mod framing;
/// Bounded local RAM/host artifact. The current Store Object1 payload is only
/// 256 bytes; persisting this416-byte artifact needs a separate design.
pub mod inspector;
pub mod live;
pub mod owner;
pub mod presentation;
pub mod system;
#[cfg(test)]
mod wire_tests;
pub const BYTES: usize = 416;
/// Fixed register order from the current x86-64 traps.S push sequence.
pub const REGISTERS: [&str; 15] = [
    "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rdi", "rsi", "rbp", "rdx", "rcx", "rbx",
    "rax",
];
const PAYLOAD: usize = 384;
const MAGIC: &[u8; 8] = b"EVCRASH1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Application(AppId),
    /// Closed source-defined service role, not a handle or global lookup key.
    Service(u16),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub component: Component,
    pub image: [u8; 32],
    /// None for a service outside a native package.
    pub package: Option<[u8; 32]>,
    pub component_build: [u8; 32],
    /// Only Some when actually selected from the durable generation protocol.
    pub generation: Option<[u8; 32]>,
    pub epoch: u64,
    pub incarnation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capture {
    pub job: u64,
    pub process: u64,
    pub thread: u64,
    pub vector: u64,
    pub error: u64,
    pub address: u64,
    pub instruction: u64,
    pub stack: u64,
    pub flags: u64,
    /// Exact kernel UserContext order; no pointers are dereferenced.
    pub registers: [u64; 15],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Reserved,
    Integrity,
    Identity,
    Fault,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crash {
    provenance: Provenance,
    capture: Capture,
}
fn put(b: &mut [u8], offset: usize, value: u64) {
    b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn word(b: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap())
}
fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
impl Crash {
    /// Trusted collector supplies actual capture and measured provenance.
    /// This constructor cannot prove their origin and grants no permissions.
    pub fn new(provenance: Provenance, capture: Capture) -> Result<Self, Error> {
        if provenance.epoch == 0
            || provenance.incarnation == 0
            || capture.job == 0
            || capture.process == 0
            || capture.thread == 0
            || matches!(provenance.component, Component::Service(0))
        {
            return Err(Error::Identity);
        }
        if !matches!(
            capture.vector,
            0 | 1 | 3 | 4 | 5 | 6 | 7 | 10 | 11 | 12 | 13 | 14 | 16 | 17 | 19
        ) {
            return Err(Error::Fault);
        }
        if matches!(provenance.component, Component::Application(_)) && provenance.package.is_none()
        {
            return Err(Error::Identity);
        }
        Ok(Self {
            provenance,
            capture,
        })
    }
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }
    pub const fn capture(&self) -> Capture {
        self.capture
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut b = [0; BYTES];
        b[..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(&(BYTES as u16).to_le_bytes());
        let p = self.provenance;
        if let Component::Application(app) = p.component {
            b[12] |= 1;
            b[16..32].copy_from_slice(&app.bytes());
        } else if let Component::Service(role) = p.component {
            b[14..16].copy_from_slice(&role.to_le_bytes());
        }
        b[32..64].copy_from_slice(&p.image);
        if let Some(package) = p.package {
            b[12] |= 2;
            b[64..96].copy_from_slice(&package);
        }
        b[96..128].copy_from_slice(&p.component_build);
        if let Some(generation) = p.generation {
            b[12] |= 4;
            b[128..160].copy_from_slice(&generation);
        }
        let c = self.capture;
        for (index, v) in [
            p.epoch,
            p.incarnation,
            c.job,
            c.process,
            c.thread,
            c.vector,
            c.error,
            c.address,
            c.instruction,
            c.stack,
            c.flags,
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut b, 160 + index * 8, v);
        }
        for (index, v) in c.registers.into_iter().enumerate() {
            put(&mut b, 248 + index * 8, v);
        }
        // Sixteen reserved zero bytes leave room for an additive internal field.
        let checksum = digest(&b[..PAYLOAD]);
        b[PAYLOAD..].copy_from_slice(&checksum);
        b
    }
}
impl Crash {
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BYTES {
            return Err(Error::Length);
        }
        if &b[..8] != MAGIC
            || b[8..10] != 1u16.to_le_bytes()
            || b[10..12] != (BYTES as u16).to_le_bytes()
        {
            return Err(Error::Version);
        }
        if digest(&b[..PAYLOAD]) != b[PAYLOAD..] {
            return Err(Error::Integrity);
        }
        if b[12] & !7 != 0 || b[13] != 0 || b[368..384].iter().any(|x| *x != 0) {
            return Err(Error::Reserved);
        }
        let app_bytes: [u8; 16] = b[16..32].try_into().unwrap();
        let role = u16::from_le_bytes(b[14..16].try_into().unwrap());
        let component = if b[12] & 1 != 0 {
            if role != 0 {
                return Err(Error::Reserved);
            }
            Component::Application(AppId::new(app_bytes).ok_or(Error::Identity)?)
        } else {
            if app_bytes != [0; 16] {
                return Err(Error::Reserved);
            }
            Component::Service(role)
        };
        let package = if b[12] & 2 != 0 {
            Some(b[64..96].try_into().unwrap())
        } else {
            if b[64..96].iter().any(|x| *x != 0) {
                return Err(Error::Reserved);
            }
            None
        };
        let generation = if b[12] & 4 != 0 {
            Some(b[128..160].try_into().unwrap())
        } else {
            if b[128..160].iter().any(|x| *x != 0) {
                return Err(Error::Reserved);
            }
            None
        };
        let provenance = Provenance {
            component,
            image: b[32..64].try_into().unwrap(),
            package,
            component_build: b[96..128].try_into().unwrap(),
            generation,
            epoch: word(b, 160),
            incarnation: word(b, 168),
        };
        let capture = Capture {
            job: word(b, 176),
            process: word(b, 184),
            thread: word(b, 192),
            vector: word(b, 200),
            error: word(b, 208),
            address: word(b, 216),
            instruction: word(b, 224),
            stack: word(b, 232),
            flags: word(b, 240),
            registers: core::array::from_fn(|i| word(b, 248 + i * 8)),
        };
        Self::new(provenance, capture)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn captured() -> Crash {
        Crash::new(
            Provenance {
                component: Component::Application(AppId::new([7; 16]).unwrap()),
                image: [2; 32],
                package: Some([3; 32]),
                component_build: [4; 32],
                generation: Some([5; 32]),
                epoch: 501,
                incarnation: 2,
            },
            Capture {
                job: 17,
                process: 0x20002,
                thread: 0x30005,
                vector: 14,
                error: 4,
                address: 0x1a000000,
                instruction: 0x10000190,
                stack: 0x10102f10,
                flags: 0x202,
                registers: core::array::from_fn(|i| 0x1234_5600 + i as u64),
            },
        )
        .unwrap()
    }
    fn checksum(b: &mut [u8; BYTES]) {
        let h = digest(&b[..PAYLOAD]);
        b[PAYLOAD..].copy_from_slice(&h);
    }
    #[test]
    fn exact_capture_and_provenance_survive_bounded_local_artifact() {
        let crash = captured();
        let b = crash.encode();
        assert_eq!(Crash::decode(&b), Ok(crash));
        assert_eq!(
            Crash::decode(&b).unwrap().capture().registers[14],
            0x1234_560e
        );
        for n in 0..BYTES {
            assert_eq!(Crash::decode(&b[..n]), Err(Error::Length));
        }
        for i in 0..BYTES {
            let mut damaged = b;
            damaged[i] ^= 1;
            assert!(Crash::decode(&damaged).is_err(), "byte{i}");
        }
    }
    #[test]
    fn rechecks_reserved_and_semantics_even_with_a_fresh_checksum() {
        let b = captured().encode();
        for i in [13, 14, 15, 368, 383] {
            let mut changed = b;
            changed[i] = 1;
            checksum(&mut changed);
            assert_eq!(Crash::decode(&changed), Err(Error::Reserved));
        }
        for offset in [160, 168, 176, 184, 192] {
            let mut changed = b;
            put(&mut changed, offset, 0);
            checksum(&mut changed);
            assert_eq!(Crash::decode(&changed), Err(Error::Identity));
        }
        let mut changed = b;
        put(&mut changed, 200, 8);
        checksum(&mut changed);
        assert_eq!(Crash::decode(&changed), Err(Error::Fault));
        let mut changed = b;
        changed[16..32].fill(0);
        checksum(&mut changed);
        assert_eq!(Crash::decode(&changed), Err(Error::Identity));
    }
    #[test]
    fn absent_generation_is_explicit_and_nonpackaged_service_does_not_claim_an_app() {
        let crash = captured();
        let mut p = crash.provenance();
        p.generation = None;
        let without = Crash::new(p, crash.capture()).unwrap();
        assert_eq!(
            Crash::decode(&without.encode())
                .unwrap()
                .provenance()
                .generation,
            None
        );
        let mut forged = without.encode();
        forged[128] = 1;
        checksum(&mut forged);
        assert_eq!(Crash::decode(&forged), Err(Error::Reserved));
        p.package = None;
        assert_eq!(Crash::new(p, crash.capture()), Err(Error::Identity));
        p.component = Component::Service(3);
        let service = Crash::new(p, crash.capture()).unwrap();
        assert_eq!(Crash::decode(&service.encode()), Ok(service));
        let mut forged = service.encode();
        forged[16] = 7;
        checksum(&mut forged);
        assert_eq!(Crash::decode(&forged), Err(Error::Reserved));
    }
}
