//! Bounded Native diagnostic framing over the existing authenticated Events
//! endpoint. These claims are never grants/health/admission facts. The receiver
//! binds actual sender identity, compares mechanism facts and prints only one
//! complete ordered snapshot. UART input remains ordinary mediated device IO.
#![forbid(unsafe_code)]
const WORDS: usize = 13;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Open = 1,
    Boot = 2,
    Install = 3,
    Stage = 4,
    Activate = 5,
    Rollback = 6,
    Remove = 7,
    Reinstall = 8,
    Inspect = 9,
    Cancel = 10,
    Finish = 11,
    CrashShell = 12,
    Invalid = 13,
    InitializeGrants = 14,
    Remember = 15,
    Revoke = 16,
    SystemInitialize = 17,
    SystemStage = 18,
    SystemActivate = 19,
    RecoverGood = 20,
}
impl Operation {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Boot => "boot",
            Self::Install => "install",
            Self::Stage => "stage",
            Self::Activate => "activate",
            Self::Rollback => "rollback",
            Self::Remove => "remove",
            Self::Reinstall => "reinstall",
            Self::Inspect => "inspect",
            Self::Cancel => "cancel",
            Self::Finish => "finish",
            Self::CrashShell => "crash-shell",
            Self::Invalid => "invalid",
            Self::InitializeGrants => "initialize-grants",
            Self::Remember => "remember",
            Self::Revoke => "revoke",
            Self::SystemInitialize => "system-init",
            Self::SystemStage => "system-stage",
            Self::SystemActivate => "system-activate",
            Self::RecoverGood => "recover-good",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResultCode {
    Ok = 0,
    Busy = 1,
    Refused = 2,
    Recovery = 3,
}
impl ResultCode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Busy => "busy",
            Self::Refused => "refused",
            Self::Recovery => "recovery",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Slot {
    None = 0,
    A = 1,
    B = 2,
}
impl Slot {
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::A => "a",
            Self::B => "b",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub operation: Operation,
    pub result: ResultCode,
    pub installed: bool,
    pub active: Slot,
    pub staged: Slot,
    pub previous: Slot,
    pub process: u64,
    pub thread: u64,
    pub revision: u64,
    pub data_epoch: u32,
    pub data_counter: u64,
    pub value: u32,
    pub mutations: u64,
    pub recovery: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Order,
    Serial,
    Shape,
}
impl Snapshot {
    fn words(self) -> Result<[u32; WORDS], Error> {
        if (self.process == 0) != (self.thread == 0)
            || (!self.installed && (self.active != Slot::None || self.staged != Slot::None))
        {
            return Err(Error::Shape);
        }
        Ok([
            self.operation as u32
                | ((self.result as u32) << 8)
                | ((self.installed as u32) << 10)
                | ((self.active as u32) << 11)
                | ((self.staged as u32) << 13)
                | ((self.previous as u32) << 15)
                | ((self.recovery as u32) << 17),
            self.process as u32,
            (self.process >> 32) as u32,
            self.thread as u32,
            (self.thread >> 32) as u32,
            self.revision as u32,
            (self.revision >> 32) as u32,
            self.data_epoch,
            self.data_counter as u32,
            (self.data_counter >> 32) as u32,
            self.value,
            self.mutations as u32,
            (self.mutations >> 32) as u32,
        ])
    }
    fn decode(w: [u32; WORDS]) -> Result<Self, Error> {
        if w[0] >> 18 != 0 {
            return Err(Error::Shape);
        }
        let operation = match w[0] & 255 {
            1 => Operation::Open,
            2 => Operation::Boot,
            3 => Operation::Install,
            4 => Operation::Stage,
            5 => Operation::Activate,
            6 => Operation::Rollback,
            7 => Operation::Remove,
            8 => Operation::Reinstall,
            9 => Operation::Inspect,
            10 => Operation::Cancel,
            11 => Operation::Finish,
            12 => Operation::CrashShell,
            13 => Operation::Invalid,
            14 => Operation::InitializeGrants,
            15 => Operation::Remember,
            16 => Operation::Revoke,
            17 => Operation::SystemInitialize,
            18 => Operation::SystemStage,
            19 => Operation::SystemActivate,
            20 => Operation::RecoverGood,
            _ => return Err(Error::Shape),
        };
        let slot = |n| match n {
            0 => Ok(Slot::None),
            1 => Ok(Slot::A),
            2 => Ok(Slot::B),
            _ => Err(Error::Shape),
        };
        let result = match (w[0] >> 8) & 3 {
            0 => ResultCode::Ok,
            1 => ResultCode::Busy,
            2 => ResultCode::Refused,
            _ => ResultCode::Recovery,
        };
        let value = Self {
            operation,
            result,
            installed: w[0] & (1 << 10) != 0,
            active: slot((w[0] >> 11) & 3)?,
            staged: slot((w[0] >> 13) & 3)?,
            previous: slot((w[0] >> 15) & 3)?,
            recovery: w[0] & (1 << 17) != 0,
            process: u64::from(w[1]) | (u64::from(w[2]) << 32),
            thread: u64::from(w[3]) | (u64::from(w[4]) << 32),
            revision: u64::from(w[5]) | (u64::from(w[6]) << 32),
            data_epoch: w[7],
            data_counter: u64::from(w[8]) | (u64::from(w[9]) << 32),
            value: w[10],
            mutations: u64::from(w[11]) | (u64::from(w[12]) << 32),
        };
        value.words()?;
        Ok(value)
    }
}
pub struct Frames {
    serial: u32,
    words: [u32; WORDS],
    cursor: u8,
}
impl Frames {
    pub fn new(serial: u32, snapshot: Snapshot) -> Result<Self, Error> {
        if serial == 0 {
            return Err(Error::Serial);
        }
        Ok(Self {
            serial,
            words: snapshot.words()?,
            cursor: 0,
        })
    }
    pub fn next_frame(&mut self) -> Option<[u8; 8]> {
        let (field, value) = match self.cursor {
            0 => (0, self.serial),
            1..=13 => (self.cursor, self.words[usize::from(self.cursor) - 1]),
            14 => (255, self.serial),
            _ => return None,
        };
        self.cursor += 1;
        let mut b = [b'N', b'R', 1, field, 0, 0, 0, 0];
        b[4..].copy_from_slice(&value.to_le_bytes());
        Some(b)
    }
    pub fn complete(&self) -> bool {
        self.cursor == 15
    }
}
pub struct Decoder {
    last: u32,
    serial: u32,
    next: u8,
    words: [u32; WORDS],
}
impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
impl Decoder {
    pub const fn new() -> Self {
        Self {
            last: 0,
            serial: 0,
            next: 0,
            words: [0; WORDS],
        }
    }
    pub const fn pending(&self) -> bool {
        self.next != 0
    }
    pub fn accept(&mut self, b: [u8; 8]) -> Result<Option<Snapshot>, Error> {
        if b[..3] != [b'N', b'R', 1] {
            return Err(Error::Header);
        }
        let value = u32::from_le_bytes(b[4..].try_into().unwrap());
        if b[3] == 0 {
            if self.pending() {
                return Err(Error::Order);
            }
            if value == 0 || value <= self.last {
                return Err(Error::Serial);
            }
            self.serial = value;
            self.next = 1;
            return Ok(None);
        }
        if !self.pending() {
            return Err(Error::Order);
        }
        if b[3] == 255 {
            if self.next != 14 {
                return Err(Error::Order);
            }
            if value != self.serial {
                return Err(Error::Serial);
            }
            let snapshot = Snapshot::decode(self.words)?;
            self.last = self.serial;
            self.serial = 0;
            self.next = 0;
            return Ok(Some(snapshot));
        }
        if b[3] != self.next || b[3] > 13 {
            return Err(Error::Order);
        }
        self.words[usize::from(self.next) - 1] = value;
        self.next += 1;
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> Snapshot {
        Snapshot {
            operation: Operation::Stage,
            result: ResultCode::Ok,
            installed: true,
            active: Slot::A,
            staged: Slot::B,
            previous: Slot::None,
            process: u64::MAX - 1,
            thread: 1 << 40,
            revision: 3,
            data_epoch: 1,
            data_counter: 0,
            value: 1001,
            mutations: 17,
            recovery: false,
        }
    }
    #[test]
    fn exact_order_full_width_and_replay() {
        let s = snapshot();
        let mut frames = Frames::new(1, s).unwrap();
        let mut d = Decoder::new();
        for _ in 0..14 {
            assert_eq!(d.accept(frames.next_frame().unwrap()), Ok(None));
        }
        assert!(d.pending());
        assert_eq!(d.accept(frames.next_frame().unwrap()), Ok(Some(s)));
        assert!(!d.pending());
        assert!(frames.complete());
        assert_eq!(
            d.accept(Frames::new(1, s).unwrap().next_frame().unwrap()),
            Err(Error::Serial)
        );
    }
    #[test]
    fn partial_duplicate_unknown_reserved_and_shape_refuse() {
        let s = snapshot();
        let mut f = Frames::new(2, s).unwrap();
        let begin = f.next_frame().unwrap();
        let first = f.next_frame().unwrap();
        let mut d = Decoder::new();
        assert_eq!(d.accept(first), Err(Error::Order));
        d.accept(begin).unwrap();
        assert_eq!(d.accept(begin), Err(Error::Order));
        d.accept(first).unwrap();
        assert_eq!(d.accept(first), Err(Error::Order));
        assert!(d.pending());
        let mut invalid = s;
        invalid.thread = 0;
        assert!(Frames::new(1, invalid).is_err());
        let mut w = s.words().unwrap();
        w[0] |= 1 << 31;
        assert!(Snapshot::decode(w).is_err());
        for op in 21..=255 {
            let mut w = s.words().unwrap();
            w[0] = (w[0] & !255) | op;
            assert!(Snapshot::decode(w).is_err());
        }
    }
}

#[cfg(test)]
mod native3_ack_tests {
    use super::*;
    #[test]
    fn operation_wire_ids_remain_stable_and_new_acks_append_without_payload_changes() {
        let ops = [
            Operation::Open,
            Operation::Boot,
            Operation::Install,
            Operation::Stage,
            Operation::Activate,
            Operation::Rollback,
            Operation::Remove,
            Operation::Reinstall,
            Operation::Inspect,
            Operation::Cancel,
            Operation::Finish,
            Operation::CrashShell,
            Operation::Invalid,
            Operation::InitializeGrants,
            Operation::Remember,
            Operation::Revoke,
            Operation::SystemInitialize,
            Operation::SystemStage,
            Operation::SystemActivate,
            Operation::RecoverGood,
        ];
        for (index, op) in ops.into_iter().enumerate() {
            assert_eq!(op as usize, index + 1);
            let snapshot = Snapshot {
                operation: op,
                result: ResultCode::Ok,
                installed: false,
                active: Slot::None,
                staged: Slot::None,
                previous: Slot::None,
                process: 0,
                thread: 0,
                revision: 0,
                data_epoch: 0,
                data_counter: 0,
                value: 0,
                mutations: 0,
                recovery: false,
            };
            assert_eq!(Snapshot::decode(snapshot.words().unwrap()), Ok(snapshot));
        }
    }
}
