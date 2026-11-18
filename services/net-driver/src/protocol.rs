//! One actual protected RPC credit protects this whole window. These bytes do
//! not prove that credit, sender identity, mapping lifetime or device authority.
use ev_net_device::packet::{MAX_FRAME_BYTES, MIN_FRAME_BYTES, MIN_RECEIVE_FRAME_BYTES};

pub const WINDOW_BYTES: usize = 4096;
pub const HEADER_BYTES: usize = 64;
const MAGIC: [u8; 8] = *b"EVNIO001";

pub trait Window {
    type Error;
    fn read(&mut self, offset: usize) -> Result<u8, Self::Error>;
    fn write(&mut self, offset: usize, value: u8) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Initialize = 1,
    Start = 2,
    Transmit = 3,
    Poll = 4,
    Stop = 5,
    StopBegin = 6,
    StopStep = 7,
}
impl Operation {
    fn version(self) -> u8 {
        if matches!(self, Self::StopBegin | Self::StopStep) {
            2
        } else {
            1
        }
    }
    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Initialize),
            2 => Ok(Self::Start),
            3 => Ok(Self::Transmit),
            4 => Ok(Self::Poll),
            5 => Ok(Self::Stop),
            6 => Ok(Self::StopBegin),
            7 => Ok(Self::StopStep),
            _ => Err(Error::Operation),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Status {
    Complete = 0,
    Empty = 1,
    Refused = 2,
    Malformed = 3,
    Stale = 4,
    Quarantined = 5,
    Uncertain = 6,
    Progress = 7,
}
impl Status {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Complete),
            1 => Ok(Self::Empty),
            2 => Ok(Self::Refused),
            3 => Ok(Self::Malformed),
            4 => Ok(Self::Stale),
            5 => Ok(Self::Quarantined),
            6 => Ok(Self::Uncertain),
            7 => Ok(Self::Progress),
            _ => Err(Error::Status),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Operation,
    Status,
    Sequence,
    Length,
    Reserved,
    Join,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Failure<E> {
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
        if self.sequence == 0 || self.sequence == u32::MAX {
            return Err(Error::Sequence);
        }
        let mut bytes = [
            b'N',
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
        if bytes[0] != b'N' || bytes[3] != 0 {
            return Err(Error::Header);
        }
        let result = Self {
            operation: Operation::decode(bytes[2])?,
            sequence: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        result.encode()?;
        if bytes[1] != result.operation.version() {
            return Err(Error::Header);
        }
        Ok(result)
    }
    pub fn response(self, status: Status) -> [u8; 8] {
        let mut bytes = [
            b'n',
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
        if bytes[0] != b'n'
            || bytes[1] != self.operation.version()
            || bytes[3] != self.operation as u8
            || bytes[4..] != self.sequence.to_le_bytes()
        {
            return Err(Error::Join);
        }
        Status::decode(u16::from(bytes[2]))
    }
}

/// One private owned packet. No shared-memory Rust reference crosses a syscall.
pub struct Packet {
    pub(crate) payload: [u8; MAX_FRAME_BYTES],
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
            payload: [0; MAX_FRAME_BYTES],
            length: 0,
        }
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.length]
    }

    fn header(notice: Notice, response: bool, status: Status, length: usize) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(&MAGIC);
        header[8..10].copy_from_slice(&u16::from(notice.operation.version()).to_le_bytes());
        header[10] = u8::from(response);
        header[11] = notice.operation as u8;
        header[12..14].copy_from_slice(&(status as u16).to_le_bytes());
        header[14..16].copy_from_slice(&(length as u16).to_le_bytes());
        header[16..20].copy_from_slice(&notice.sequence.to_le_bytes());
        header
    }
    fn write_frame<W: Window>(
        &self,
        window: &mut W,
        notice: Notice,
        response: bool,
        status: Status,
    ) -> Result<(), Failure<W::Error>> {
        let header = Self::header(notice, response, status, self.length);
        for (index, byte) in header.into_iter().enumerate() {
            window.write(index, byte).map_err(Failure::Window)?;
        }
        for (index, byte) in self.payload().iter().copied().enumerate() {
            window
                .write(HEADER_BYTES + index, byte)
                .map_err(Failure::Window)?;
        }
        for index in HEADER_BYTES + self.length..WINDOW_BYTES {
            window.write(index, 0).map_err(Failure::Window)?;
        }
        Ok(())
    }
    pub fn write_request<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        payload: &[u8],
    ) -> Result<(), Failure<W::Error>> {
        notice.encode().map_err(Failure::Frame)?;
        let valid = match notice.operation {
            Operation::Transmit => (MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&payload.len()),
            Operation::StopBegin => {
                payload.len() == 8
                    && !matches!(
                        u64::from_le_bytes(payload.try_into().unwrap()),
                        0 | u64::MAX
                    )
            }
            _ => payload.is_empty(),
        };
        if !valid {
            return Err(Failure::Frame(Error::Length));
        }
        self.payload.fill(0);
        self.payload[..payload.len()].copy_from_slice(payload);
        self.length = payload.len();
        self.write_frame(window, notice, false, Status::Complete)
    }
    pub fn read_request<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
    ) -> Result<(), Failure<W::Error>> {
        self.read_frame(window, notice, None).map(|_| ())
    }
    pub fn read_response<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        status: Status,
    ) -> Result<(), Failure<W::Error>> {
        self.read_frame(window, notice, Some(status)).map(|_| ())
    }
    fn read_frame<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        response: Option<Status>,
    ) -> Result<Status, Failure<W::Error>> {
        notice.encode().map_err(Failure::Frame)?;
        self.length = 0;
        self.payload.fill(0);
        let mut header = [0; HEADER_BYTES];
        for (index, byte) in header.iter_mut().enumerate() {
            *byte = window.read(index).map_err(Failure::Window)?;
        }
        if header[..8] != MAGIC
            || header[8..10] != u16::from(notice.operation.version()).to_le_bytes()
            || header[10] != u8::from(response.is_some())
        {
            return Err(Failure::Frame(Error::Header));
        }
        if header[11] != notice.operation as u8 || header[16..20] != notice.sequence.to_le_bytes() {
            return Err(Failure::Frame(Error::Join));
        }
        if header[20..].iter().any(|byte| *byte != 0) {
            return Err(Failure::Frame(Error::Reserved));
        }
        let status = Status::decode(u16::from_le_bytes(header[12..14].try_into().unwrap()))
            .map_err(Failure::Frame)?;
        if status != response.unwrap_or(Status::Complete) {
            return Err(Failure::Frame(Error::Join));
        }
        if response.is_some()
            && ((status == Status::Empty && notice.operation != Operation::Poll)
                || (status == Status::Uncertain
                    && !matches!(
                        notice.operation,
                        Operation::Transmit | Operation::StopBegin | Operation::StopStep
                    ))
                || (status == Status::Progress
                    && !matches!(notice.operation, Operation::StopBegin | Operation::StopStep)))
        {
            return Err(Failure::Frame(Error::Status));
        }
        let length = usize::from(u16::from_le_bytes(header[14..16].try_into().unwrap()));
        let valid = match (response, notice.operation, status) {
            (None, Operation::Transmit, _) => (MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length),
            (None, Operation::StopBegin, _) => length == 8,
            (
                Some(_),
                Operation::StopBegin | Operation::StopStep,
                Status::Progress | Status::Complete,
            ) => length == 8,
            (Some(_), Operation::Poll, Status::Complete) => {
                (MIN_RECEIVE_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length)
            }
            (Some(_), Operation::Transmit, Status::Complete) => length == 16,
            _ => length == 0,
        };
        if !valid {
            return Err(Failure::Frame(Error::Length));
        }
        for (index, byte) in self.payload[..length].iter_mut().enumerate() {
            *byte = window.read(HEADER_BYTES + index).map_err(Failure::Window)?;
        }
        for index in HEADER_BYTES + length..WINDOW_BYTES {
            if window.read(index).map_err(Failure::Window)? != 0 {
                return Err(Failure::Frame(Error::Reserved));
            }
        }
        if notice.operation == Operation::StopBegin
            && response.is_none()
            && matches!(
                u64::from_le_bytes(self.payload[..8].try_into().unwrap()),
                0 | u64::MAX
            )
        {
            return Err(Failure::Frame(Error::Length));
        }
        if response.is_some()
            && matches!(notice.operation, Operation::StopBegin | Operation::StopStep)
            && matches!(status, Status::Progress | Status::Complete)
        {
            let p = crate::device::StopProgress::decode(&self.payload[..length])
                .ok_or(Failure::Frame(Error::Length))?;
            if (status == Status::Complete) != p.complete()
                || (notice.operation == Operation::StopBegin
                    && (p.done != 0 || status != Status::Progress))
                || (notice.operation == Operation::StopStep && p.done == 0)
            {
                return Err(Failure::Frame(Error::Length));
            }
        }
        if response.is_some()
            && notice.operation == Operation::Transmit
            && status == Status::Complete
            && (self.payload[..8] == [0; 8]
                || self.payload[10..16].iter().any(|byte| *byte != 0)
                || !(MIN_FRAME_BYTES as u16..=MAX_FRAME_BYTES as u16)
                    .contains(&u16::from_le_bytes([self.payload[8], self.payload[9]])))
        {
            return Err(Failure::Frame(Error::Length));
        }
        self.length = length;
        Ok(status)
    }
    pub(crate) fn publish<W: Window>(
        &self,
        window: &mut W,
        notice: Notice,
        status: Status,
    ) -> Result<(), Failure<W::Error>> {
        self.write_frame(window, notice, true, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Memory {
        bytes: [u8; WINDOW_BYTES],
        writes: usize,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                bytes: [0; WINDOW_BYTES],
                writes: 0,
            }
        }
    }
    impl Window for Memory {
        type Error = ();
        fn read(&mut self, offset: usize) -> Result<u8, ()> {
            self.bytes.get(offset).copied().ok_or(())
        }
        fn write(&mut self, offset: usize, value: u8) -> Result<(), ()> {
            *self.bytes.get_mut(offset).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }
    #[test]
    fn canonical_private_snapshot_and_scalar_join_reject_mixed_requests() {
        let notice = Notice {
            operation: Operation::Transmit,
            sequence: 7,
        };
        let mut memory = Memory::new();
        let mut packet = Packet::new();
        packet
            .write_request(&mut memory, notice, &[0x6b; 60])
            .unwrap();
        packet.read_request(&mut memory, notice).unwrap();
        assert_eq!(packet.payload(), &[0x6b; 60]);
        assert!(
            packet
                .read_request(
                    &mut memory,
                    Notice {
                        sequence: 8,
                        ..notice
                    }
                )
                .is_err()
        );
        assert_eq!(
            notice.response_status(notice.response(Status::Complete)),
            Ok(Status::Complete)
        );
        assert!(
            Notice {
                sequence: 8,
                ..notice
            }
            .response_status(notice.response(Status::Complete))
            .is_err()
        );
    }
    #[test]
    fn malformed_headers_lengths_and_nonzero_tail_do_not_escape_the_window() {
        let notice = Notice {
            operation: Operation::Transmit,
            sequence: 1,
        };
        // Flipping the low length byte 60 -> 188 would remain a valid padded
        // frame; corrupt the high byte to exercise actual bounds rejection.
        for offset in [0, 8, 10, 11, 12, 15, 16, 20, 63, 4095] {
            let mut memory = Memory::new();
            let mut packet = Packet::new();
            packet.write_request(&mut memory, notice, &[1; 60]).unwrap();
            memory.bytes[offset] ^= 0x80;
            assert!(packet.read_request(&mut memory, notice).is_err());
            assert!(packet.payload().is_empty());
        }
        let mut memory = Memory::new();
        let mut packet = Packet::new();
        assert!(packet.write_request(&mut memory, notice, &[0; 59]).is_err());
        assert_eq!(memory.writes, 0);
        assert!(
            packet
                .write_request(
                    &mut memory,
                    Notice {
                        operation: Operation::Start,
                        ..notice
                    },
                    &[1]
                )
                .is_err()
        );
        assert_eq!(memory.writes, 0);
        for sequence in [0, u32::MAX] {
            assert!(Notice { sequence, ..notice }.encode().is_err());
        }
    }
    #[test]
    fn additive_stop_frames_reject_wrong_version_and_noncanonical_progress_without_changing_v1() {
        for operation in [
            Operation::Initialize,
            Operation::Start,
            Operation::Transmit,
            Operation::Poll,
            Operation::Stop,
        ] {
            let n = Notice {
                operation,
                sequence: 7,
            };
            assert_eq!(
                n.encode().unwrap(),
                [b'N', 1, operation as u8, 0, 7, 0, 0, 0]
            );
            assert_eq!(
                n.response(Status::Complete),
                [b'n', 1, 0, operation as u8, 7, 0, 0, 0]
            );
            let mut wrong = n.encode().unwrap();
            wrong[1] = 2;
            assert!(Notice::decode(wrong).is_err());
        }
        let n = Notice {
            operation: Operation::StopBegin,
            sequence: 7,
        };
        assert_eq!(n.encode().unwrap(), [b'N', 2, 6, 0, 7, 0, 0, 0]);
        let mut old = n.encode().unwrap();
        old[1] = 1;
        assert!(Notice::decode(old).is_err());
        let mut memory = Memory::new();
        let mut packet = Packet::new();
        packet
            .write_request(&mut memory, n, &8192u64.to_le_bytes())
            .unwrap();
        assert_eq!(&memory.bytes[8..10], &[2, 0]);
        packet.read_request(&mut memory, n).unwrap();
        memory.bytes[8] = 1;
        assert!(packet.read_request(&mut memory, n).is_err());
        let step = Notice {
            operation: Operation::StopStep,
            sequence: 8,
        };
        for (done, status, valid) in [
            (0, Status::Progress, false),
            (128, Status::Progress, true),
            (128, Status::Complete, false),
            (16384, Status::Complete, true),
            (16384, Status::Progress, false),
        ] {
            packet.payload[..8].copy_from_slice(&crate::device::StopProgress { done }.encode());
            packet.length = 8;
            packet.publish(&mut memory, step, status).unwrap();
            assert_eq!(
                packet.read_response(&mut memory, step, status).is_ok(),
                valid
            );
        }
        packet.payload[..8].copy_from_slice(&crate::device::StopProgress { done: 128 }.encode());
        packet.length = 8;
        for offset in [HEADER_BYTES + 2, HEADER_BYTES + 4, HEADER_BYTES + 6, 4095] {
            packet.publish(&mut memory, step, Status::Progress).unwrap();
            memory.bytes[offset] ^= 1;
            assert!(
                packet
                    .read_response(&mut memory, step, Status::Progress)
                    .is_err()
            );
            packet.payload[..8]
                .copy_from_slice(&crate::device::StopProgress { done: 128 }.encode());
            packet.length = 8;
        }
    }
}
