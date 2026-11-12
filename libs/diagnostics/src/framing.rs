//! Bounded authenticated-origin diagnostic transport. Origin checks belong to the receiver. Rejected Full2 keeps the identical current
//! frame. Advance only after actual ordinary SEND acceptance; no queue ACK invented.
pub const CRASH_BYTES: usize = crate::BYTES;
pub const JOB_BYTES: usize = 192;
pub const SYSTEM_BYTES: usize = 384;
pub const OWNER_BYTES: usize = 416;
pub const MAX_BYTES: usize = CRASH_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Crash,
    Job,
    System,
    OwnerPrompt,
}
impl Kind {
    fn tag(self) -> u8 {
        match self {
            Self::Crash => b'C',
            Self::Job => b'J',
            Self::System => b'S',
            Self::OwnerPrompt => b'O',
        }
    }
    pub const fn bytes(self) -> usize {
        match self {
            Self::Crash => CRASH_BYTES,
            Self::Job => JOB_BYTES,
            Self::System => SYSTEM_BYTES,
            Self::OwnerPrompt => OWNER_BYTES,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Serial,
    Order,
    Version,
    Busy,
    NoReport,
}
pub struct Tx {
    kind: Kind,
    serial: u32,
    next: u8,
    complete: bool,
}
impl Tx {
    pub fn new(kind: Kind, serial: u32) -> Result<Self, Error> {
        if serial == 0 {
            return Err(Error::Serial);
        }
        Ok(Self {
            kind,
            serial,
            next: 0,
            complete: false,
        })
    }
    pub fn current(&self, payload: &[u8]) -> Result<Option<[u8; 8]>, Error> {
        if payload.len() != self.kind.bytes() {
            return Err(Error::Length);
        }
        if self.complete {
            return Ok(None);
        }
        let mut frame = [b'N', self.kind.tag(), 1, self.next, 0, 0, 0, 0];
        let data = if self.next == 0 || self.next == 255 {
            self.serial.to_le_bytes()
        } else {
            let offset = (self.next as usize - 1) * 4;
            payload[offset..offset + 4].try_into().unwrap()
        };
        frame[4..].copy_from_slice(&data);
        Ok(Some(frame))
    }
    pub fn accepted(&mut self) -> Result<bool, Error> {
        if self.complete {
            return Err(Error::NoReport);
        }
        if self.next == 255 {
            self.complete = true;
        } else if self.next as usize == self.kind.bytes() / 4 {
            self.next = 255;
        } else {
            self.next += 1;
        }
        Ok(self.complete)
    }
}
pub struct Completed {
    pub kind: Kind,
    pub serial: u32,
    pub bytes: [u8; MAX_BYTES],
}
pub struct Decoder {
    failed: bool,
    active: Option<(Kind, u32, u8)>,
    last: u32,
    bytes: [u8; MAX_BYTES],
}
impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
impl Decoder {
    pub const fn new() -> Self {
        Self {
            failed: false,
            active: None,
            last: 0,
            bytes: [0; MAX_BYTES],
        }
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn pending(&self) -> bool {
        self.active.is_some()
    }
    /// Caller must separately authenticate actual Root sender at Begin and hold
    /// that immutable origin through End. Parser integrity never authenticates it.
    pub fn accept(&mut self, frame: [u8; 8]) -> Result<Option<Completed>, Error> {
        if self.failed {
            return Err(Error::Order);
        }
        let result = self.accept_inner(frame);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn accept_inner(&mut self, frame: [u8; 8]) -> Result<Option<Completed>, Error> {
        if frame[0] != b'N' || frame[2] != 1 {
            return Err(Error::Version);
        }
        let kind = match frame[1] {
            b'C' => Kind::Crash,
            b'J' => Kind::Job,
            b'S' => Kind::System,
            b'O' => Kind::OwnerPrompt,
            _ => return Err(Error::Version),
        };
        let word = u32::from_le_bytes(frame[4..].try_into().unwrap());
        if frame[3] == 0 {
            if self.active.is_some() {
                return Err(Error::Busy);
            }
            if Some(word) != self.last.checked_add(1) {
                return Err(Error::Serial);
            }
            self.bytes.fill(0);
            self.active = Some((kind, word, 1));
            return Ok(None);
        }
        let (current, serial, next) = self.active.ok_or(Error::NoReport)?;
        if current != kind || frame[3] != next {
            return Err(Error::Order);
        }
        if next == 255 {
            if word != serial {
                return Err(Error::Serial);
            }
            self.active = None;
            self.last = serial;
            return Ok(Some(Completed {
                kind,
                serial,
                bytes: self.bytes,
            }));
        }
        let offset = (next as usize - 1) * 4;
        self.bytes[offset..offset + 4].copy_from_slice(&frame[4..]);
        self.active = Some((
            kind,
            serial,
            if next as usize == kind.bytes() / 4 {
                255
            } else {
                next + 1
            },
        ));
        Ok(None)
    }
}

/// Sole mutable output buffer. A live report cannot be replaced or cleared by
/// later collection; Full2 retains current payload/cursor for identical retry.
pub struct Outbox {
    payload: [u8; MAX_BYTES],
    tx: Option<Tx>,
    length: usize,
}
impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}
impl Outbox {
    pub const fn new() -> Self {
        Self {
            payload: [0; MAX_BYTES],
            tx: None,
            length: 0,
        }
    }
    pub fn pending(&self) -> bool {
        self.tx.is_some()
    }
    pub fn start(&mut self, kind: Kind, serial: u32, payload: &[u8]) -> Result<(), Error> {
        if self.pending() {
            return Err(Error::Busy);
        }
        if payload.len() != kind.bytes() {
            return Err(Error::Length);
        }
        let tx = Tx::new(kind, serial)?;
        self.payload.fill(0);
        self.payload[..payload.len()].copy_from_slice(payload);
        self.length = payload.len();
        self.tx = Some(tx);
        Ok(())
    }
    pub fn current(&self) -> Result<Option<[u8; 8]>, Error> {
        match &self.tx {
            Some(tx) => tx.current(&self.payload[..self.length]),
            None => Ok(None),
        }
    }
    pub fn accepted(&mut self) -> Result<bool, Error> {
        let complete = self.tx.as_mut().ok_or(Error::NoReport)?.accepted()?;
        if complete {
            self.tx = None;
        }
        Ok(complete)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ArchiveError {
    Full,
    Duplicate,
    Missing,
}
/// Two full local crash capsules for the bounded App+Shell scenario. Overflow
/// is explicit; old evidence is never silently overwritten. Eviction is an
/// explicit caller decision after durable host export, not implicit Drop policy.
pub struct CrashArchive {
    reports: [Option<[u8; CRASH_BYTES]>; 2],
}
impl Default for CrashArchive {
    fn default() -> Self {
        Self::new()
    }
}
impl CrashArchive {
    pub const fn new() -> Self {
        Self {
            reports: [None, None],
        }
    }
    pub fn push(&mut self, crash: crate::Crash) -> Result<usize, ArchiveError> {
        let capture = crash.capture();
        for old in self.reports.iter().flatten() {
            let old = crate::Crash::decode(old)
                .expect("retained valid crash encoding")
                .capture();
            if (old.process, old.thread) == (capture.process, capture.thread) {
                return Err(ArchiveError::Duplicate);
            }
        }
        let slot = self
            .reports
            .iter()
            .position(Option::is_none)
            .ok_or(ArchiveError::Full)?;
        self.reports[slot] = Some(crash.encode());
        Ok(slot)
    }
    pub fn payload(&self, index: usize) -> Result<&[u8; CRASH_BYTES], ArchiveError> {
        self.reports
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(ArchiveError::Missing)
    }
    pub fn remove(&mut self, index: usize) -> Result<[u8; CRASH_BYTES], ArchiveError> {
        self.reports
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(ArchiveError::Missing)
    }
}
