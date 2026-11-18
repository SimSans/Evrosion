//! Internal Root-only network-control frame. The actual SEND capability is the
//! authority boundary. A seed value does not prove entropy, and DNS/IP bytes do
//! not grant destination authority. One scope is fixed for the service lifetime.
use crate::protocol::{Failure, Window};

pub const MAX_DATA: usize = 1024;
pub const MAX_NAME: usize = 253;
pub const WAITING: [u8; 8] = *b"EVNSWAIT";
pub const READY: [u8; 8] = *b"EVNSRDY1";
const HEADER: usize = 64;
const MAGIC: [u8; 8] = *b"EVNET001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Initialize = 1,
    Status = 2,
    Resolve = 3,
    QueryResult = 4,
    Connect = 5,
    Write = 6,
    Read = 7,
    Close = 8,
    /// Terminal service/device shutdown, distinct from closing a TCP socket.
    Shutdown = 9,
    ShutdownBegin = 10,
    ShutdownStep = 11,
}
impl Operation {
    fn version(self) -> u8 {
        if matches!(self, Self::ShutdownBegin | Self::ShutdownStep) {
            2
        } else {
            1
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Complete = 0,
    Pending = 1,
    Refused = 2,
    Malformed = 3,
    Stale = 4,
    Uncertain = 5,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Sequence,
    Operation,
    Length,
    Reserved,
    Scope,
    Join,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ControlFailure<E> {
    Window(E),
    Frame(Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice {
    pub operation: Operation,
    pub sequence: u32,
}
impl Notice {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if matches!(self.sequence, 0 | u32::MAX) {
            return Err(Error::Sequence);
        }
        let mut bytes = [
            b'S',
            self.operation.version(),
            self.operation as u8,
            0,
            0,
            0,
            0,
            0,
        ];
        bytes[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if bytes[0] != b'S' || bytes[3] != 0 {
            return Err(Error::Header);
        }
        let operation = match bytes[2] {
            1 => Operation::Initialize,
            2 => Operation::Status,
            3 => Operation::Resolve,
            4 => Operation::QueryResult,
            5 => Operation::Connect,
            6 => Operation::Write,
            7 => Operation::Read,
            8 => Operation::Close,
            9 => Operation::Shutdown,
            10 => Operation::ShutdownBegin,
            11 => Operation::ShutdownStep,
            _ => return Err(Error::Operation),
        };
        let notice = Self {
            operation,
            sequence: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        notice.encode()?;
        if bytes[1] != operation.version() {
            return Err(Error::Header);
        }
        Ok(notice)
    }
    pub fn response(self, status: Status) -> [u8; 8] {
        let mut bytes = [
            b's',
            self.operation.version(),
            status as u8,
            self.operation as u8,
            0,
            0,
            0,
            0,
        ];
        bytes[4..].copy_from_slice(&self.sequence.to_le_bytes());
        bytes
    }
    pub fn response_status(self, bytes: [u8; 8]) -> Result<Status, Error> {
        self.encode()?;
        if bytes[..2] != [b's', self.operation.version()]
            || bytes[3] != self.operation as u8
            || bytes[4..] != self.sequence.to_le_bytes()
        {
            return Err(Error::Join);
        }
        match bytes[2] {
            0 => Ok(Status::Complete),
            1 => Ok(Status::Pending),
            2 => Ok(Status::Refused),
            3 => Ok(Status::Malformed),
            4 => Ok(Status::Stale),
            5 => Ok(Status::Uncertain),
            _ => Err(Error::Header),
        }
    }
}

/// Seed + exact single destination/name scope supplied by the sole trusted
/// Root control route. Future app routes must not receive Initialize authority.
pub struct Initialization {
    pub seed: u64,
    pub scope: Scope,
}
pub struct Scope {
    address: [u8; 4],
    remote_port: u16,
    local_port: u16,
    name: [u8; MAX_NAME],
    name_len: usize,
}
impl Scope {
    pub fn address(&self) -> [u8; 4] {
        self.address
    }
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }
    pub fn local_port(&self) -> u16 {
        // V4 local-port allocation v2: inclusive first ephemeral port. The
        // service consumes successive values without reusing a closed tuple.
        self.local_port
    }
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap()
    }
    pub fn allows_name(&self, name: &[u8]) -> bool {
        name == &self.name[..self.name_len]
    }
    pub fn allows_destination(&self, bytes: &[u8]) -> bool {
        bytes.len() == 6
            && bytes[..4] == self.address
            && bytes[4..] == self.remote_port.to_le_bytes()
    }
}
fn valid_name(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_NAME {
        return false;
    }
    bytes.split(|b| *b == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label[0].is_ascii_alphanumeric()
            && label[label.len() - 1].is_ascii_alphanumeric()
            && label
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    })
}
impl Initialization {
    /// Exact body: seed8/IP4/remotePort2/localPort2/nameLen1/reserved7/name.
    /// This parsing is not an approved entropy-source or owner-consent witness.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 25
            || bytes.len() > 24 + MAX_NAME
            || bytes[17..24].iter().any(|b| *b != 0)
            || usize::from(bytes[16]) != bytes.len() - 24
        {
            return Err(Error::Scope);
        }
        let address: [u8; 4] = bytes[8..12].try_into().unwrap();
        let remote_port = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
        let local_port = u16::from_le_bytes(bytes[14..16].try_into().unwrap());
        if matches!(address[0], 0 | 127 | 224..=255)
            || address == [255; 4]
            || remote_port == 0
            || local_port < 49152
            || !valid_name(&bytes[24..])
        {
            return Err(Error::Scope);
        }
        let mut name = [0; MAX_NAME];
        name[..bytes.len() - 24].copy_from_slice(&bytes[24..]);
        Ok(Self {
            seed: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            scope: Scope {
                address,
                remote_port,
                local_port,
                name,
                name_len: bytes.len() - 24,
            },
        })
    }
}

/// Private snapshot/output. The whole shared page is canonical and is retained
/// by the real RPC credit until the executable sends its captured nonce ACK.
pub struct Packet {
    pub(crate) data: [u8; MAX_DATA],
    pub(crate) length: usize,
}
impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}
impl Packet {
    pub const fn new() -> Self {
        Self {
            data: [0; MAX_DATA],
            length: 0,
        }
    }
    pub fn data(&self) -> &[u8] {
        &self.data[..self.length]
    }
    fn valid_request(operation: Operation, data: &[u8]) -> bool {
        match operation {
            Operation::Initialize => Initialization::parse(data).is_ok(),
            Operation::Status
            | Operation::QueryResult
            | Operation::Close
            | Operation::Shutdown
            | Operation::ShutdownStep => data.is_empty(),
            Operation::Resolve => valid_name(data),
            Operation::Connect => data.len() == 6,
            Operation::ShutdownBegin => {
                data.len() == 8
                    && !matches!(u64::from_le_bytes(data.try_into().unwrap()), 0 | u64::MAX)
            }
            Operation::Write => !data.is_empty() && data.len() <= MAX_DATA,
            Operation::Read => {
                data.len() == 2
                    && (1..=MAX_DATA as u16).contains(&u16::from_le_bytes(data.try_into().unwrap()))
            }
        }
    }
    fn valid_response(operation: Operation, status: Status, data: &[u8]) -> bool {
        if status != Status::Complete {
            return data.is_empty();
        }
        match operation {
            Operation::Initialize
            | Operation::Resolve
            | Operation::Connect
            | Operation::Close
            | Operation::Shutdown => data.is_empty(),
            Operation::ShutdownBegin | Operation::ShutdownStep => data.is_empty(),
            Operation::Status => {
                data.len() == 32
                    && data[0] == 1
                    && data[1] <= 1
                    && data[2] <= 10
                    && data[3] <= 1
                    && data[4] <= 1
                    && data[5] <= 32
                    && data[6..8] == [0; 2]
                    && data[28..] == [0; 4]
            }
            Operation::QueryResult => data.len() == 4,
            Operation::Write => {
                data.len() == 2
                    && (1..=MAX_DATA as u16).contains(&u16::from_le_bytes(data.try_into().unwrap()))
            }
            Operation::Read => data.len() <= MAX_DATA,
        }
    }
    fn publish<W: Window>(
        &self,
        window: &mut W,
        notice: Notice,
        response: Option<Status>,
    ) -> Result<(), ControlFailure<W::Error>> {
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(&MAGIC);
        header[8..10].copy_from_slice(&u16::from(notice.operation.version()).to_le_bytes());
        header[10] = u8::from(response.is_some());
        header[11] = notice.operation as u8;
        header[12] = response.unwrap_or(Status::Complete) as u8;
        header[14..16].copy_from_slice(&(self.length as u16).to_le_bytes());
        header[16..20].copy_from_slice(&notice.sequence.to_le_bytes());
        for (n, byte) in header.into_iter().enumerate() {
            window.write(n, byte).map_err(ControlFailure::Window)?;
        }
        for n in 0..4096 - HEADER {
            window
                .write(HEADER + n, if n < self.length { self.data[n] } else { 0 })
                .map_err(ControlFailure::Window)?;
        }
        Ok(())
    }
    pub fn write_request<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        data: &[u8],
    ) -> Result<(), ControlFailure<W::Error>> {
        notice.encode().map_err(ControlFailure::Frame)?;
        if !Self::valid_request(notice.operation, data) {
            return Err(ControlFailure::Frame(Error::Length));
        }
        self.data.fill(0);
        self.data[..data.len()].copy_from_slice(data);
        self.length = data.len();
        self.publish(window, notice, None)
    }
    pub fn read_request<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
    ) -> Result<(), ControlFailure<W::Error>> {
        self.read(window, notice, None)?;
        if !Self::valid_request(notice.operation, self.data()) {
            self.length = 0;
            return Err(ControlFailure::Frame(Error::Length));
        }
        Ok(())
    }
    pub fn read_response<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        status: Status,
    ) -> Result<(), ControlFailure<W::Error>> {
        self.read(window, notice, Some(status))?;
        if !Self::valid_response(notice.operation, status, self.data()) {
            self.length = 0;
            return Err(ControlFailure::Frame(Error::Length));
        }
        Ok(())
    }
    fn read<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        response: Option<Status>,
    ) -> Result<(), ControlFailure<W::Error>> {
        notice.encode().map_err(ControlFailure::Frame)?;
        self.length = 0;
        self.data.fill(0);
        let mut header = [0; HEADER];
        for (n, b) in header.iter_mut().enumerate() {
            *b = window.read(n).map_err(ControlFailure::Window)?;
        }
        if header[..8] != MAGIC
            || header[8..10] != u16::from(notice.operation.version()).to_le_bytes()
            || header[10] != u8::from(response.is_some())
        {
            return Err(ControlFailure::Frame(Error::Header));
        }
        if header[11] != notice.operation as u8
            || header[16..20] != notice.sequence.to_le_bytes()
            || header[12..14] != [response.unwrap_or(Status::Complete) as u8, 0]
        {
            return Err(ControlFailure::Frame(Error::Join));
        }
        if header[20..].iter().any(|b| *b != 0) {
            return Err(ControlFailure::Frame(Error::Reserved));
        }
        let length = usize::from(u16::from_le_bytes(header[14..16].try_into().unwrap()));
        if length > MAX_DATA {
            return Err(ControlFailure::Frame(Error::Length));
        }
        for (n, b) in self.data[..length].iter_mut().enumerate() {
            *b = window.read(HEADER + n).map_err(ControlFailure::Window)?;
        }
        for n in HEADER + length..4096 {
            if window.read(n).map_err(ControlFailure::Window)? != 0 {
                return Err(ControlFailure::Frame(Error::Reserved));
            }
        }
        self.length = length;
        Ok(())
    }
    pub(crate) fn response<W: Window>(
        &self,
        window: &mut W,
        notice: Notice,
        status: Status,
    ) -> Result<[u8; 8], ControlFailure<W::Error>> {
        self.publish(window, notice, Some(status))?;
        Ok(notice.response(status))
    }
    pub fn reply<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        status: Status,
        data: &[u8],
    ) -> Result<[u8; 8], ControlFailure<W::Error>> {
        notice.encode().map_err(ControlFailure::Frame)?;
        if !Self::valid_response(notice.operation, status, data) {
            return Err(ControlFailure::Frame(Error::Length));
        }
        self.data.fill(0);
        self.data[..data.len()].copy_from_slice(data);
        self.length = data.len();
        self.response(window, notice, status)
    }
}

// Keep the two protocol error domains explicit; no device error is promoted to
// a transport ACK merely because its byte representation fits a shared window.
impl<E> From<Failure<E>> for ControlFailure<E> {
    fn from(value: Failure<E>) -> Self {
        match value {
            Failure::Window(error) => Self::Window(error),
            Failure::Frame(_) => Self::Frame(Error::Header),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    struct Memory([u8; 4096]);
    impl Window for Memory {
        type Error = ();
        fn read(&mut self, n: usize) -> Result<u8, ()> {
            self.0.get(n).copied().ok_or(())
        }
        fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
            *self.0.get_mut(n).ok_or(())? = b;
            Ok(())
        }
    }
    pub(crate) fn initialization() -> [u8; 40] {
        let mut body = [0; 40];
        body[..8].copy_from_slice(&123u64.to_le_bytes());
        body[8..12].copy_from_slice(&[10, 0, 2, 2]);
        body[12..14].copy_from_slice(&8080u16.to_le_bytes());
        body[14..16].copy_from_slice(&49152u16.to_le_bytes());
        body[16] = 16;
        body[24..].copy_from_slice(b"net.evrosion.dev");
        body
    }
    #[test]
    fn fixed_scope_is_exact_and_invalid_names_ports_and_reserved_bytes_refuse() {
        let body = initialization();
        let init = Initialization::parse(&body).unwrap();
        assert!(init.scope.allows_name(b"net.evrosion.dev"));
        assert!(!init.scope.allows_name(b"x.net.evrosion.dev"));
        assert!(init.scope.allows_destination(&[10, 0, 2, 2, 0x90, 0x1f]));
        assert!(!init.scope.allows_destination(&[10, 0, 2, 3, 0x90, 0x1f]));
        for offset in [16, 17, 23] {
            let mut bad = body;
            bad[offset] ^= 1;
            assert!(Initialization::parse(&bad).is_err());
        }
        for address in [[0, 1, 2, 3], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
            let mut bad = body;
            bad[8..12].copy_from_slice(&address);
            assert!(Initialization::parse(&bad).is_err());
        }
        for name in [
            &b"a..b"[..],
            b"-host.test",
            b"host-.test",
            b"UPPER.test",
            b"a.test.",
            b"a\0test",
        ] {
            assert!(!valid_name(name));
        }
    }
    #[test]
    fn canonical_control_snapshot_joins_notice_and_refuses_partial_or_foreign_frames() {
        let notice = Notice {
            operation: Operation::Initialize,
            sequence: 1,
        };
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        packet
            .write_request(&mut memory, notice, &initialization())
            .unwrap();
        packet.read_request(&mut memory, notice).unwrap();
        for offset in [0, 8, 10, 11, 12, 15, 16, 20, 63, 4095] {
            let original = memory.0[offset];
            memory.0[offset] ^= 0x80;
            assert!(packet.read_request(&mut memory, notice).is_err());
            assert!(packet.data().is_empty());
            memory.0[offset] = original;
        }
        assert!(
            packet
                .read_request(
                    &mut memory,
                    Notice {
                        sequence: 2,
                        ..notice
                    }
                )
                .is_err()
        );
        assert!(
            Notice {
                sequence: u32::MAX,
                ..notice
            }
            .encode()
            .is_err()
        );
    }
    #[test]
    fn v2_shutdown_is_explicit_and_does_not_relabel_any_old_s1_frame() {
        for operation in [
            Operation::Initialize,
            Operation::Status,
            Operation::Resolve,
            Operation::QueryResult,
            Operation::Connect,
            Operation::Write,
            Operation::Read,
            Operation::Close,
            Operation::Shutdown,
        ] {
            let n = Notice {
                operation,
                sequence: 7,
            };
            assert_eq!(
                n.encode().unwrap(),
                [b'S', 1, operation as u8, 0, 7, 0, 0, 0]
            );
            assert_eq!(
                n.response(Status::Complete),
                [b's', 1, 0, operation as u8, 7, 0, 0, 0]
            );
            let mut wrong = n.encode().unwrap();
            wrong[1] = 2;
            assert!(Notice::decode(wrong).is_err());
        }
        let n = Notice {
            operation: Operation::ShutdownBegin,
            sequence: 7,
        };
        assert_eq!(n.encode().unwrap(), [b'S', 2, 10, 0, 7, 0, 0, 0]);
        let mut old = n.encode().unwrap();
        old[1] = 1;
        assert!(Notice::decode(old).is_err());
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        for bad in [0, u64::MAX] {
            assert!(
                packet
                    .write_request(&mut memory, n, &bad.to_le_bytes())
                    .is_err()
            );
        }
        packet
            .write_request(&mut memory, n, &8192u64.to_le_bytes())
            .unwrap();
        packet.read_request(&mut memory, n).unwrap();
        assert_eq!(packet.data(), &8192u64.to_le_bytes());
        memory.0[8] = 1;
        assert!(packet.read_request(&mut memory, n).is_err());
        let step = Notice {
            operation: Operation::ShutdownStep,
            sequence: 8,
        };
        assert!(
            packet
                .write_request(&mut memory, step, &8192u64.to_le_bytes())
                .is_err()
        );
        packet.write_request(&mut memory, step, &[]).unwrap();
        packet.read_request(&mut memory, step).unwrap();
    }
}
