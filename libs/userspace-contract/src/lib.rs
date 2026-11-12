//! Internal startup contract shared by the kernel, bundle producer and userspace.
#![no_std]
#![forbid(unsafe_code)]

pub mod app_data;
pub mod block;
pub mod cap_echo;
pub mod echo;
pub mod file;
pub mod file_test;
pub mod generation;
pub mod provider;
pub mod store_test;
pub mod syscall;

pub const SIZE: usize = 336;
pub const MAX_GRANTS: usize = 8;
pub const HEADER: usize = 144;
pub const GRANT_BYTES: usize = 24;
pub const ABI_DESCRIPTION: &[u8] = b"Evrosion Internal userspace bootstrap v1; x86_64; readonly336; rdi=record;rsi=size; int80 scalar v1; EVRT events v1";
// SHA-256 of ABI_DESCRIPTION, pinned independently by the producer test.
pub const ABI: [u8; 32] = [
    0x72, 0xcd, 0xbf, 0xdb, 0x85, 0xd6, 0xf8, 0xe1, 0x3e, 0xa3, 0xde, 0xac, 0xd9, 0x40, 0xa4, 0x1a,
    0xa9, 0x19, 0x4, 0x8c, 0x83, 0x7e, 0xe0, 0xda, 0x3e, 0xf6, 0x39, 0x48, 0xa0, 0xbc, 0x71, 0x78,
];
pub const SELECTOR_PROBE: u64 = 1;
pub const SELECTOR_EVENTS: u64 = 2;
pub const READ: u16 = 1;
pub const TRANSFER: u16 = 64;
pub const SEND: u16 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Reserved,
    Identity,
    Limits,
    GrantCount,
    Grant,
    Order,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub selector: u64,
    pub handle: u64,
    pub kind: u8,
    pub rights: u16,
}
#[derive(Clone, Copy)]
pub struct Context {
    pub epoch: u64,
    pub incarnation: u64,
    pub process: u64,
    pub limits: [u64; 4],
    pub manifest: [u8; 32],
    pub authority: [u8; 32],
}
pub struct Bootstrap<'a> {
    bytes: &'a [u8],
    count: usize,
}
fn wide(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn put(b: &mut [u8], i: usize, n: u64) {
    b[i..i + 8].copy_from_slice(&n.to_le_bytes());
}
fn valid_grant(g: Grant) -> bool {
    let specific = match g.kind {
        1 => 7,
        2 => 24,
        3..=5 => 1,
        6 => 0,
        7 => 3,
        8 => 7, // Display: distinct device kind, hardware RW mappings also read.
        _ => return false,
    };
    g.selector != 0 && g.handle != 0 && g.rights != 0 && g.rights & !(480 | specific) == 0
}
impl<'a> Bootstrap<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVSUPV01"
            || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != 1
            || usize::from(u16::from_le_bytes(bytes[10..12].try_into().unwrap())) != SIZE
        {
            return Err(Error::Version);
        }
        if bytes[12..16]
            .iter()
            .chain(&bytes[137..144])
            .any(|&b| b != 0)
        {
            return Err(Error::Reserved);
        }
        if [16, 24, 32].into_iter().any(|i| wide(bytes, i) == 0) {
            return Err(Error::Identity);
        }
        if [40, 48, 56, 64]
            .into_iter()
            .any(|i| matches!(wide(bytes, i), 0 | u64::MAX))
        {
            return Err(Error::Limits);
        }
        let count = usize::from(bytes[136]);
        if !(1..=MAX_GRANTS).contains(&count) {
            return Err(Error::GrantCount);
        }
        let result = Self { bytes, count };
        let mut previous = 0;
        for (i, g) in result.grants().enumerate() {
            let slot = &bytes[HEADER + i * GRANT_BYTES..HEADER + (i + 1) * GRANT_BYTES];
            if slot[17] != 0 || slot[20..].iter().any(|&b| b != 0) {
                return Err(Error::Reserved);
            }
            if !valid_grant(g) {
                return Err(Error::Grant);
            }
            if g.selector <= previous {
                return Err(Error::Order);
            }
            previous = g.selector;
        }
        if bytes[HEADER + count * GRANT_BYTES..]
            .iter()
            .any(|&b| b != 0)
        {
            return Err(Error::Reserved);
        }
        Ok(result)
    }
    pub fn epoch(&self) -> u64 {
        wide(self.bytes, 16)
    }
    pub fn incarnation(&self) -> u64 {
        wide(self.bytes, 24)
    }
    pub fn process(&self) -> u64 {
        wide(self.bytes, 32)
    }
    pub fn grants(&self) -> impl Iterator<Item = Grant> + '_ {
        (0..self.count).map(|i| {
            let b = &self.bytes[HEADER + i * GRANT_BYTES..];
            Grant {
                selector: wide(b, 0),
                handle: wide(b, 8),
                kind: b[16],
                rights: u16::from_le_bytes(b[18..20].try_into().unwrap()),
            }
        })
    }
    pub fn find(&self, selector: u64) -> Option<Grant> {
        self.grants().find(|g| g.selector == selector)
    }
}
pub fn encode(context: Context, grants: &[Grant]) -> Result<[u8; SIZE], Error> {
    if !(1..=MAX_GRANTS).contains(&grants.len()) {
        return Err(Error::GrantCount);
    }
    let mut bytes = [0; SIZE];
    bytes[..8].copy_from_slice(b"EVSUPV01");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
    for (i, n) in [context.epoch, context.incarnation, context.process]
        .into_iter()
        .enumerate()
    {
        put(&mut bytes, 16 + i * 8, n);
    }
    for (i, n) in context.limits.into_iter().enumerate() {
        put(&mut bytes, 40 + i * 8, n);
    }
    bytes[72..104].copy_from_slice(&context.manifest);
    bytes[104..136].copy_from_slice(&context.authority);
    bytes[136] = grants.len() as u8;
    for (i, g) in grants.iter().enumerate() {
        let b = &mut bytes[HEADER + i * GRANT_BYTES..HEADER + (i + 1) * GRANT_BYTES];
        put(b, 0, g.selector);
        put(b, 8, g.handle);
        b[16] = g.kind;
        b[18..20].copy_from_slice(&g.rights.to_le_bytes());
    }
    Bootstrap::parse(&bytes)?;
    Ok(bytes)
}

/// Small versioned bootstrap event sent over an explicitly granted endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Ready,
    ServiceResponded,
    ServiceStopped,
    RecoveryReady,
    CriticalReady,
}
impl Event {
    pub fn encode(self) -> [u8; 8] {
        match self {
            Self::Ready => *b"EVRT\x01\x01\0\0",
            Self::ServiceResponded => *b"EVRT\x01\x02\0\0",
            Self::ServiceStopped => *b"EVRT\x01\x03\0\0",
            Self::RecoveryReady => *b"EVRT\x01\x04\0\0",
            Self::CriticalReady => *b"EVRT\x01\x05\0\0",
        }
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"EVRT\x01\x01\0\0" => Some(Self::Ready),
            b"EVRT\x01\x02\0\0" => Some(Self::ServiceResponded),
            b"EVRT\x01\x03\0\0" => Some(Self::ServiceStopped),
            b"EVRT\x01\x04\0\0" => Some(Self::RecoveryReady),
            b"EVRT\x01\x05\0\0" => Some(Self::CriticalReady),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context {
        Context {
            epoch: 9,
            incarnation: 2,
            process: 3,
            limits: [100, 64, 4, 8],
            manifest: [7; 32],
            authority: [8; 32],
        }
    }
    fn grants() -> [Grant; 2] {
        [
            Grant {
                selector: 1,
                handle: 256,
                kind: 1,
                rights: READ,
            },
            Grant {
                selector: 2,
                handle: 257,
                kind: 2,
                rights: SEND,
            },
        ]
    }
    #[test]
    fn bootstrap_roundtrip_preserves_identity_measurements_and_exact_grants() {
        let bytes = encode(context(), &grants()).unwrap();
        let b = Bootstrap::parse(&bytes).unwrap();
        assert_eq!((b.epoch(), b.incarnation(), b.process()), (9, 2, 3));
        assert_eq!(b.grants().count(), 2);
        assert_eq!(b.find(1), Some(grants()[0]));
        assert_eq!(b.find(2), Some(grants()[1]));
        assert_eq!(b.find(3), None);
        assert_eq!(&bytes[72..104], &[7; 32]);
        assert_eq!(&bytes[104..136], &[8; 32]);
    }
    #[test]
    fn every_reserved_byte_and_unused_slot_is_rejected() {
        let bytes = encode(context(), &grants()).unwrap();
        for i in (12..16)
            .chain(137..144)
            .chain([161, 185])
            .chain(164..168)
            .chain(188..SIZE)
        {
            let mut bad = bytes;
            bad[i] = 1;
            assert_eq!(
                Bootstrap::parse(&bad).err(),
                Some(Error::Reserved),
                "byte {i}"
            );
        }
    }
    #[test]
    fn truncated_versions_unbounded_limits_and_zero_identities_are_rejected() {
        let bytes = encode(context(), &grants()).unwrap();
        for length in 0..SIZE {
            assert_eq!(
                Bootstrap::parse(&bytes[..length]).err(),
                Some(Error::Length)
            );
        }
        for i in [0, 8, 10] {
            let mut bad = bytes;
            bad[i] ^= 1;
            assert_eq!(Bootstrap::parse(&bad).err(), Some(Error::Version));
        }
        for i in [16, 24, 32] {
            let mut bad = bytes;
            put(&mut bad, i, 0);
            assert_eq!(Bootstrap::parse(&bad).err(), Some(Error::Identity));
        }
        for i in [40, 48, 56, 64] {
            for n in [0, u64::MAX] {
                let mut bad = bytes;
                put(&mut bad, i, n);
                assert_eq!(Bootstrap::parse(&bad).err(), Some(Error::Limits));
            }
        }
        for count in [0, 9, 255] {
            let mut bad = bytes;
            bad[136] = count;
            assert_eq!(Bootstrap::parse(&bad).err(), Some(Error::GrantCount));
        }
    }
    #[test]
    fn wrong_kind_rights_zero_handles_and_noncanonical_order_are_rejected() {
        for field in 0..5 {
            let mut g = grants();
            match field {
                0 => g[0].handle = 0,
                1 => g[0].selector = 0,
                2 => g[0].kind = 0,
                3 => g[0].rights = SEND,
                _ => g[1].rights = READ,
            }
            assert_eq!(encode(context(), &g), Err(Error::Grant));
        }
        let mut g = grants();
        g[1].selector = g[0].selector;
        assert_eq!(encode(context(), &g), Err(Error::Order));
        g.swap(0, 1);
        assert_eq!(encode(context(), &g), Err(Error::Order));
        assert_eq!(encode(context(), &[]), Err(Error::GrantCount));
        let mut g = grants();
        g[0].rights |= 512;
        assert_eq!(encode(context(), &g), Err(Error::Grant));
    }
    #[test]
    fn event_decoder_rejects_unknown_versions_types_reserved_bits_and_length() {
        assert_eq!(Event::RecoveryReady.encode(), *b"EVRT\x01\x04\0\0");
        assert_eq!(
            Event::decode(b"EVRT\x01\x04\0\0"),
            Some(Event::RecoveryReady)
        );
        let bytes = Event::Ready.encode();
        assert_eq!(Event::decode(&bytes), Some(Event::Ready));
        for i in 0..8 {
            for bit in 0..8 {
                let mut bad = bytes;
                bad[i] ^= 1 << bit;
                let expected = if bad == Event::ServiceStopped.encode() {
                    Some(Event::ServiceStopped)
                } else if bad == Event::CriticalReady.encode() {
                    Some(Event::CriticalReady)
                } else {
                    None
                };
                assert_eq!(Event::decode(&bad), expected);
            }
            assert_eq!(Event::decode(&bytes[..i]), None);
        }
        assert_eq!(Event::decode(&[0; 9]), None);
    }
}

#[cfg(test)]
mod mutex_wire_tests {
    use super::*;
    #[test]
    fn mutex_tag_and_control_round_trip_without_memory_rights() {
        let context = Context {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: [1, 1, 1, 1],
            manifest: [1; 32],
            authority: [2; 32],
        };
        let grant = Grant {
            selector: 6,
            handle: 257,
            kind: 6,
            rights: 256,
        };
        let encoded = encode(context, &[grant]).unwrap();
        assert_eq!(Bootstrap::parse(&encoded).unwrap().find(6), Some(grant));
        for rights in [1, 2, 4, 8, 16] {
            assert_eq!(
                encode(context, &[Grant { rights, ..grant }]),
                Err(Error::Grant)
            );
        }
    }
}

#[cfg(test)]
mod io_ports_wire_tests {
    use super::*;
    #[test]
    fn io_ports_tag_seven_round_trips_only_declared_port_instruction_rights() {
        let context = Context {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: [1, 1, 1, 1],
            manifest: [1; 32],
            authority: [2; 32],
        };
        let grant = Grant {
            selector: 7,
            handle: 257,
            kind: 7,
            rights: 3,
        };
        let bytes = encode(context, &[grant]).unwrap();
        assert_eq!(Bootstrap::parse(&bytes).unwrap().find(7), Some(grant));
        for rights in [4, 8, 16] {
            assert_eq!(
                encode(context, &[Grant { rights, ..grant }]),
                Err(Error::Grant)
            );
        }
    }
}

/// Additive Root-only contract; ordinary v1 constants stay unchanged.
pub mod root_v2;
