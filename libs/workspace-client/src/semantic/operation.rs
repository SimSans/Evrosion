//! Ordered A1 actions/ranges. Sender identity, provider lease, rights, focus and
//! protected input witnesses stay in Root's custody; this wire cannot grant them.
use super::{Error, Frame, nonce};
pub const MAX_RANGE: usize = 256;
pub const COMMIT: u16 = 0x81ff;
pub const ABORT: u16 = 0x81fe;
pub const RESPONSE_COMMIT: u16 = 0x90ff;
pub const ABORT_ACK: u16 = 0x91fe;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub snapshot_nonce: u32,
    pub model: u64,
    pub view: u64,
    pub frame: u64,
    pub mapping_epoch: u64,
    pub text_revision: u64,
}
impl Binding {
    /// Correlation only. Root separately checks actual identity, provider lease,
    /// accepted Display geometry and consumer authority before using it.
    pub const fn matches(self, header: super::Header) -> bool {
        self.snapshot_nonce == header.nonce
            && self.model == header.model
            && self.view == header.view
            && self.frame == header.frame
            && self.mapping_epoch == header.mapping_epoch
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Activate = 0,
    Focus = 1,
    Select = 2,
    Scroll = 3,
    Expand = 4,
    SetValue = 5,
}
impl Action {
    fn read(v: u8) -> Result<Self, Error> {
        Ok(match v {
            0 => Self::Activate,
            1 => Self::Focus,
            2 => Self::Select,
            3 => Self::Scroll,
            4 => Self::Expand,
            5 => Self::SetValue,
            _ => return Err(Error::Field),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RangeKind {
    AccessibleLabel = 0,
    Document = 1,
}
impl RangeKind {
    fn read(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::AccessibleLabel),
            1 => Ok(Self::Document),
            _ => Err(Error::Field),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Action {
        action: Action,
        argument: u64,
    },
    Range {
        kind: RangeKind,
        offset: u64,
        length: u16,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub nonce: u32,
    pub node: u16,
    pub binding: Binding,
    pub kind: Kind,
}
impl Request {
    pub fn validate(self) -> Result<(), Error> {
        if !nonce(self.nonce) || !nonce(self.binding.snapshot_nonce) || self.node == 0 {
            return Err(Error::Nonce);
        }
        if [
            self.binding.model,
            self.binding.view,
            self.binding.frame,
            self.binding.mapping_epoch,
        ]
        .iter()
        .any(|n| matches!(*n, 0 | u64::MAX))
        {
            return Err(Error::Value);
        }
        match self.kind {
            Kind::Action {
                action: Action::Select,
                argument,
            } => {
                if self.binding.text_revision == 0
                    || self.binding.text_revision == u64::MAX
                    || argument as u32 > super::MAX_TEXT as u32
                    || (argument >> 32) > super::MAX_TEXT
                {
                    return Err(Error::Bounds);
                }
            }
            Kind::Action {
                action: Action::Scroll,
                argument,
            } => {
                if self.binding.text_revision != 0 || i16::try_from(argument as i64).is_err() {
                    return Err(Error::Bounds);
                }
            }
            Kind::Action {
                action: Action::SetValue,
                ..
            } => return Err(Error::Field),
            Kind::Action { argument, .. } => {
                if argument != 0 || self.binding.text_revision != 0 {
                    return Err(Error::Field);
                }
            }
            Kind::Range { offset, length, .. } => {
                if self.binding.text_revision == 0
                    || self.binding.text_revision == u64::MAX
                    || length == 0
                    || usize::from(length) > MAX_RANGE
                    || offset > super::MAX_TEXT
                    || offset.checked_add(u64::from(length)).is_none()
                {
                    return Err(Error::Bounds);
                }
            }
        }
        Ok(())
    }
    pub fn frame(self, ordinal: u16) -> Result<Option<Frame>, Error> {
        self.validate()?;
        let word = match ordinal {
            0 => self.nonce,
            1 => {
                let (k, a) = match self.kind {
                    Kind::Action { action, .. } => (1, action as u8),
                    Kind::Range { kind, .. } => (2, kind as u8),
                };
                k | (u32::from(a) << 8) | (u32::from(self.node) << 16)
            }
            2..=11 => {
                let n = match ordinal {
                    2 | 3 => self.binding.model,
                    4 | 5 => self.binding.view,
                    6 | 7 => self.binding.frame,
                    8 | 9 => self.binding.mapping_epoch,
                    _ => self.binding.text_revision,
                };
                if ordinal.is_multiple_of(2) {
                    n as u32
                } else {
                    (n >> 32) as u32
                }
            }
            12 | 13 => {
                let n = match self.kind {
                    Kind::Range { offset, .. } => offset,
                    _ => 0,
                };
                if ordinal == 12 {
                    n as u32
                } else {
                    (n >> 32) as u32
                }
            }
            14 | 15 => {
                let n = match self.kind {
                    Kind::Action { argument, .. } => argument,
                    Kind::Range { length, .. } => u64::from(length),
                };
                if ordinal == 14 {
                    n as u32
                } else {
                    (n >> 32) as u32
                }
            }
            16 => self.binding.snapshot_nonce,
            17 => self.nonce,
            _ => return Ok(None),
        };
        Ok(Some(Frame {
            field: if ordinal == 17 {
                COMMIT
            } else {
                0x8100 + ordinal
            },
            word,
        }))
    }
    fn read(words: &[u32; 17]) -> Result<Self, Error> {
        let pair = |i: usize| u64::from(words[i]) | (u64::from(words[i + 1]) << 32);
        let offset = pair(12);
        let argument = pair(14);
        let kind = match words[1] as u8 {
            1 if offset == 0 => Kind::Action {
                action: Action::read((words[1] >> 8) as u8)?,
                argument,
            },
            2 => Kind::Range {
                kind: RangeKind::read((words[1] >> 8) as u8)?,
                offset,
                length: u16::try_from(argument).map_err(|_| Error::Bounds)?,
            },
            _ => return Err(Error::Field),
        };
        let out = Self {
            nonce: words[0],
            node: (words[1] >> 16) as u16,
            kind,
            binding: Binding {
                snapshot_nonce: words[16],
                model: pair(2),
                view: pair(4),
                frame: pair(6),
                mapping_epoch: pair(8),
                text_revision: pair(10),
            },
        };
        out.validate()?;
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Receiving,
    Complete(Request),
    Aborted(u32),
}
/// A malformed/expired partial request stays fenced until explicit matching
/// Abort. Advancing nonce alone cannot discard its queued control words.
pub struct Receiver {
    words: [u32; 17],
    next: u16,
    last: u32,
    active: bool,
    fenced: bool,
}
impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}
impl Receiver {
    pub const fn new() -> Self {
        Self {
            words: [0; 17],
            next: 0,
            last: 0,
            active: false,
            fenced: false,
        }
    }
    pub fn expire(&mut self) {
        self.fenced = true;
    }
    pub fn push(&mut self, f: Frame) -> Result<Progress, Error> {
        if f.field == ABORT && f.word == self.last && nonce(f.word) {
            self.active = false;
            self.fenced = false;
            self.next = 0;
            return Ok(Progress::Aborted(f.word));
        }
        if self.fenced {
            return Err(Error::Quarantined);
        }
        let result = self.accept(f);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    fn accept(&mut self, f: Frame) -> Result<Progress, Error> {
        if f.field == 0x8100 {
            if self.active || !nonce(f.word) || f.word <= self.last {
                return Err(Error::Nonce);
            }
            self.words.fill(0);
            self.last = f.word;
            self.words[0] = f.word;
            self.next = 1;
            self.active = true;
            return Ok(Progress::Receiving);
        }
        if !self.active {
            return Err(Error::State);
        }
        if f.field == COMMIT {
            if self.next != 17 || f.word != self.last {
                return Err(Error::Incomplete);
            }
            let request = Request::read(&self.words)?;
            self.active = false;
            self.next = 0;
            return Ok(Progress::Complete(request));
        }
        if f.field != 0x8100 + self.next || self.next >= 17 {
            return Err(Error::Order);
        }
        self.words[usize::from(self.next)] = f.word;
        self.next += 1;
        Ok(Progress::Receiving)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Unsupported = 1,
    Busy = 2,
    Stale = 3,
    Denied = 4,
}
pub const fn terminal(nonce: u32, result: Result<(), Refusal>) -> Frame {
    Frame {
        field: match result {
            Ok(()) => 0x9f00,
            Err(r) => 0x9f00 | r as u16,
        },
        word: nonce,
    }
}
/// Immutable UTF-8 result, emitted in fixed order with canonical zero tail.
/// Root authenticates the real provider and rechecks its current binding before
/// releasing staged text. Range bytes do not carry authority.
pub struct RangeReply {
    nonce: u32,
    node: u16,
    kind: RangeKind,
    length: u16,
    bytes: [u8; MAX_RANGE],
}
impl RangeReply {
    pub fn new(n: u32, node: u16, kind: RangeKind, text: &str) -> Result<Self, Error> {
        if !nonce(n) || node == 0 || text.len() > MAX_RANGE {
            return Err(Error::Bounds);
        }
        let mut out = Self {
            nonce: n,
            node,
            kind,
            length: text.len() as u16,
            bytes: [0; MAX_RANGE],
        };
        out.bytes[..text.len()].copy_from_slice(text.as_bytes());
        Ok(out)
    }
    pub fn frame(&self, ordinal: u16) -> Option<Frame> {
        let (field, word) = match ordinal {
            0 => (0x9000, self.nonce),
            1 => (0x9001, u32::from(self.length)),
            2 => (0x9002, u32::from(self.node) | ((self.kind as u32) << 16)),
            3..=66 => {
                let at = usize::from(ordinal - 3) * 4;
                (
                    0x9010 + ordinal - 3,
                    u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap()),
                )
            }
            67 => (RESPONSE_COMMIT, self.nonce),
            _ => return None,
        };
        Some(Frame { field, word })
    }
}
pub struct RangeReceiver {
    request: Request,
    next: u16,
    bytes: [u8; MAX_RANGE],
    length: usize,
    complete: bool,
    fenced: bool,
}
impl RangeReceiver {
    pub fn new(request: Request) -> Result<Self, Error> {
        request.validate()?;
        if !matches!(request.kind, Kind::Range { .. }) {
            return Err(Error::Field);
        }
        Ok(Self {
            request,
            next: 0,
            bytes: [0; MAX_RANGE],
            length: 0,
            complete: false,
            fenced: false,
        })
    }
    pub fn expire(&mut self) {
        self.fenced = true;
    }
    pub fn push(&mut self, f: Frame) -> Result<bool, Error> {
        if self.fenced {
            return Err(Error::Quarantined);
        }
        let r = self.accept(f);
        if r.is_err() {
            self.fenced = true;
        }
        r
    }
    fn accept(&mut self, f: Frame) -> Result<bool, Error> {
        if self.complete {
            return Err(Error::State);
        }
        let Kind::Range { kind, length, .. } = self.request.kind else {
            return Err(Error::State);
        };
        let expected = match self.next {
            0 => 0x9000,
            1 => 0x9001,
            2 => 0x9002,
            3..=66 => 0x9010 + self.next - 3,
            67 => RESPONSE_COMMIT,
            _ => return Err(Error::State),
        };
        if f.field != expected {
            return Err(Error::Order);
        }
        match self.next {
            0 | 67 => {
                if f.word != self.request.nonce {
                    return Err(Error::Nonce);
                }
            }
            1 => {
                if f.word > u32::from(length) {
                    return Err(Error::Bounds);
                }
                self.length = f.word as usize;
            }
            2 => {
                if f.word != u32::from(self.request.node) | ((kind as u32) << 16) {
                    return Err(Error::Field);
                }
            }
            3..=66 => {
                let at = usize::from(self.next - 3) * 4;
                self.bytes[at..at + 4].copy_from_slice(&f.word.to_le_bytes());
            }
            _ => return Err(Error::State),
        }
        if self.next == 67 {
            if self.bytes[self.length..].iter().any(|b| *b != 0)
                || core::str::from_utf8(&self.bytes[..self.length]).is_err()
            {
                return Err(Error::Label);
            }
            self.complete = true;
        }
        self.next += 1;
        Ok(self.complete)
    }
    /// Staged only: actual provider/current lease/full Display binding need a
    /// separate Root check. This method does not publish data to a consumer.
    pub fn staged_text(&self) -> Result<&str, Error> {
        if !self.complete || self.fenced {
            return Err(Error::State);
        }
        core::str::from_utf8(&self.bytes[..self.length]).map_err(|_| Error::Label)
    }
}
/// Largest UTF-8 prefix within the requested byte budget. Starting in a scalar
/// or past EOF is refused; a short final scalar may legitimately return zero.
pub fn text_range(text: &str, offset: u64, length: u16) -> Result<&str, Error> {
    let at = usize::try_from(offset).map_err(|_| Error::Bounds)?;
    if length == 0
        || usize::from(length) > MAX_RANGE
        || at > text.len()
        || !text.is_char_boundary(at)
    {
        return Err(Error::Bounds);
    }
    let mut end = at.saturating_add(usize::from(length)).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(&text[at..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn range() -> Request {
        Request {
            nonce: 17,
            node: 3,
            binding: Binding {
                snapshot_nonce: 11,
                model: 0x1_0000_0001,
                view: 0x2_0000_0002,
                frame: 0x3_0000_0003,
                mapping_epoch: 0x4_0000_0004,
                text_revision: 0x2_0000_0002,
            },
            kind: Kind::Range {
                kind: RangeKind::Document,
                offset: 2,
                length: 256,
            },
        }
    }
    #[test]
    fn binding_matches_all_snapshot_fields_including_full_width_and_nonce() {
        let q = range();
        let b = q.binding;
        let h = super::super::Header {
            nonce: b.snapshot_nonce,
            page: 0,
            pages: 1,
            model: b.model,
            view: b.view,
            frame: b.frame,
            mapping_epoch: b.mapping_epoch,
            width: 320,
            height: 180,
            keyboard: 3,
            modal: 0,
        };
        assert!(b.matches(h));
        for changed in [
            super::super::Header {
                nonce: h.nonce + 1,
                ..h
            },
            super::super::Header {
                model: h.model as u32 as u64,
                ..h
            },
            super::super::Header {
                view: h.view as u32 as u64,
                ..h
            },
            super::super::Header {
                frame: h.frame as u32 as u64,
                ..h
            },
            super::super::Header {
                mapping_epoch: h.mapping_epoch as u32 as u64,
                ..h
            },
        ] {
            assert!(!b.matches(changed));
        }
    }
    #[test]
    fn operation_roundtrip_retains_full_binding_and_every_missing_word_fences() {
        let q = range();
        let mut receiver = Receiver::new();
        for i in 0..18 {
            let p = receiver.push(q.frame(i).unwrap().unwrap()).unwrap();
            if i == 17 {
                assert_eq!(p, Progress::Complete(q));
            }
        }
        assert_eq!(
            receiver.push(q.frame(0).unwrap().unwrap()),
            Err(Error::Nonce)
        );
        for missing in 1..18 {
            let mut receiver = Receiver::new();
            let mut failed = false;
            for i in 0..18 {
                if i == missing {
                    continue;
                }
                if receiver.push(q.frame(i).unwrap().unwrap()).is_err() {
                    failed = true;
                }
            }
            if missing != 17 {
                assert!(failed);
            }
            receiver.expire();
            assert_eq!(
                receiver.push(Request { nonce: 18, ..q }.frame(0).unwrap().unwrap()),
                Err(Error::Quarantined)
            );
            assert_eq!(
                receiver.push(Frame {
                    field: ABORT,
                    word: 17
                }),
                Ok(Progress::Aborted(17))
            );
            assert_eq!(
                receiver.push(q.frame(0).unwrap().unwrap()),
                Err(Error::Nonce)
            );
        }
    }
    #[test]
    fn ranges_are_immutable_exact_utf8_and_zero_tail_is_required() {
        let q = range();
        let reply = RangeReply::new(q.nonce, 3, RangeKind::Document, "αβ 😀").unwrap();
        let mut recv = RangeReceiver::new(q).unwrap();
        for i in 0..68 {
            assert_eq!(recv.push(reply.frame(i).unwrap()).unwrap(), i == 67);
            if i != 67 {
                assert!(recv.staged_text().is_err());
            }
        }
        assert_eq!(recv.staged_text().unwrap(), "αβ 😀");
        let mut corrupt = RangeReceiver::new(q).unwrap();
        for i in 0..68 {
            let mut f = reply.frame(i).unwrap();
            if i == 66 {
                f.word = 1;
            }
            let result = corrupt.push(f);
            if i == 67 {
                assert_eq!(result, Err(Error::Label));
            } else {
                assert!(result.is_ok());
            }
        }
        assert!(corrupt.staged_text().is_err());
        for missing in [0, 1, 2, 30, 66] {
            let mut r = RangeReceiver::new(q).unwrap();
            for i in 0..68 {
                if i != missing {
                    let _ = r.push(reply.frame(i).unwrap());
                }
            }
            assert!(r.staged_text().is_err());
        }
        assert_eq!(text_range("αβ😀", 0, 1), Ok(""));
        assert_eq!(text_range("αβ😀", 0, 3), Ok("α"));
        assert_eq!(text_range("αβ😀", 2, 6), Ok("β😀"));
        assert_eq!(text_range("αβ😀", 8, 6), Ok(""));
        assert_eq!(text_range("αβ😀", 1, 6), Err(Error::Bounds));
        assert_eq!(text_range("αβ😀", 9, 6), Err(Error::Bounds));
    }
    #[test]
    fn illegal_action_arguments_widths_and_unknown_meta_do_not_create_requests() {
        let q = range();
        let mut r = Receiver::new();
        for i in 0..18 {
            let mut f = q.frame(i).unwrap().unwrap();
            if i == 1 {
                f.word |= 0x8000;
            }
            let result = r.push(f);
            if i == 17 {
                assert_eq!(result, Err(Error::Field));
            } else {
                assert!(result.is_ok());
            }
        }
        let action = |a, arg, rev| Request {
            kind: Kind::Action {
                action: a,
                argument: arg,
            },
            binding: Binding {
                text_revision: rev,
                ..q.binding
            },
            ..q
        };
        assert!(action(Action::Activate, 0, 0).validate().is_ok());
        assert!(action(Action::Activate, 1, 0).validate().is_err());
        assert!(
            action(Action::Scroll, (-25i64) as u64, 0)
                .validate()
                .is_ok()
        );
        assert!(action(Action::Scroll, 32768, 0).validate().is_err());
        assert!(
            action(Action::Select, (1_048_576u64 << 32) | 1_048_576, 1)
                .validate()
                .is_ok()
        );
        assert!(
            action(Action::Select, (1_048_577u64 << 32) | 1_048_576, 1)
                .validate()
                .is_err()
        );
        assert!(action(Action::SetValue, 0, 0).validate().is_err());
        let mut recv = RangeReceiver::new(q).unwrap();
        recv.expire();
        assert_eq!(
            recv.push(Frame {
                field: 0x9000,
                word: 17
            }),
            Err(Error::Quarantined)
        );
    }
}
