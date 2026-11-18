//! Internal A1 paged semantic snapshots. Data/IDs confer no authority. Native
//! adapters authenticate the actual sender, bind source view/frame/epoch to a
//! coherent accepted Display tuple, and independently enforce provider scope.
#![forbid(unsafe_code)]
pub mod operation;

/// Internal logical contract for the complete A1 snapshot/action/range wire.
pub const INTERFACE: &str = "ev.internal.semantic-tree";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const FEATURES: u64 = 0;

pub const MAX_NODES: usize = 16;
pub const MAX_PAGES: u8 = 8;
pub const MAX_TEXT: u64 = 1_048_576;
pub const COMMIT: u16 = 0x7fff;
pub const ABORT_ACK: u16 = 0x7ffe;
const WORDS: usize = 16 + MAX_NODES * 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Wire,
    Field,
    Nonce,
    State,
    Order,
    Incomplete,
    Bounds,
    Role,
    Flags,
    Label,
    Value,
    Tree,
    Quarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub field: u16,
    pub word: u32,
}
impl Frame {
    pub const fn encode(self) -> [u8; 8] {
        let f = self.field.to_le_bytes();
        let w = self.word.to_le_bytes();
        [0x41, 1, f[0], f[1], w[0], w[1], w[2], w[3]]
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 8 || bytes[..2] != [0x41, 1] {
            return Err(Error::Wire);
        }
        Ok(Self {
            field: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            word: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        })
    }
}
fn nonce(value: u32) -> bool {
    !matches!(value, 0 | u32::MAX)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Snapshot { page: u8, nonce: u32 },
    Abort { nonce: u32 },
}
impl Request {
    pub fn frame(self) -> Result<Frame, Error> {
        match self {
            Self::Snapshot { page, nonce: n } if page < MAX_PAGES && nonce(n) => Ok(Frame {
                field: 0x8000 | u16::from(page),
                word: n,
            }),
            Self::Abort { nonce: n } if nonce(n) => Ok(Frame {
                field: 0x8008,
                word: n,
            }),
            _ => Err(Error::Field),
        }
    }
    pub fn decode(frame: Frame) -> Result<Self, Error> {
        match frame.field {
            0x8000..=0x8007 if nonce(frame.word) => Ok(Self::Snapshot {
                page: (frame.field & 7) as u8,
                nonce: frame.word,
            }),
            0x8008 if nonce(frame.word) => Ok(Self::Abort { nonce: frame.word }),
            _ => Err(Error::Field),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Window = 1,
    Dialog = 2,
    Button = 3,
    TextBox = 4,
    Label = 5,
    List = 6,
    ListItem = 7,
    Document = 8,
    Menu = 9,
    Slider = 10,
}
impl Role {
    fn read(value: u8) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::Window,
            2 => Self::Dialog,
            3 => Self::Button,
            4 => Self::TextBox,
            5 => Self::Label,
            6 => Self::List,
            7 => Self::ListItem,
            8 => Self::Document,
            9 => Self::Menu,
            10 => Self::Slider,
            _ => return Err(Error::Role),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    bytes: [u8; 64],
    length: u8,
}
impl Label {
    pub const EMPTY: Self = Self {
        bytes: [0; 64],
        length: 0,
    };
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.len() > 64 || text.chars().any(char::is_control) {
            return Err(Error::Label);
        }
        let mut out = Self::EMPTY;
        out.bytes[..text.len()].copy_from_slice(text.as_bytes());
        out.length = text.len() as u8;
        Ok(out)
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.length as usize]).expect("validated label")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}
impl Rect {
    fn valid(self) -> bool {
        self.width > 0 && self.height > 0
    }
    fn contains(self, child: Self) -> bool {
        self.valid()
            && child.valid()
            && child.x >= self.x
            && child.y >= self.y
            && u32::from(child.x) + u32::from(child.width)
                <= u32::from(self.x) + u32::from(self.width)
            && u32::from(child.y) + u32::from(child.height)
                <= u32::from(self.y) + u32::from(self.height)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    None,
    Number(i64),
    TextRange {
        revision: u64,
        offset: u64,
        length: u32,
        total: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub local: u16,
    pub parent: u16,
    pub role: Role,
    pub flags: u8,
    pub actions: u8,
    pub label: Label,
    pub bounds: Rect,
    pub value: Value,
}
impl Node {
    pub const EMPTY: Self = Self {
        local: 0,
        parent: 0,
        role: Role::Label,
        flags: 0,
        actions: 0,
        label: Label::EMPTY,
        bounds: Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        },
        value: Value::None,
    };
    fn word(self, index: usize) -> u32 {
        match index {
            0 => u32::from(self.local) | (u32::from(self.parent) << 16),
            1 => {
                (self.role as u32)
                    | (u32::from(self.flags) << 8)
                    | (u32::from(self.actions) << 16)
                    | (u32::from(self.label.length) << 24)
            }
            2 => u32::from(self.bounds.x) | (u32::from(self.bounds.y) << 16),
            3 => u32::from(self.bounds.width) | (u32::from(self.bounds.height) << 16),
            4 => match self.value {
                Value::None => 0,
                Value::Number(_) => 1,
                Value::TextRange { .. } => 2,
            },
            5 | 6 => {
                let n = match self.value {
                    Value::Number(n) => n as u64,
                    Value::TextRange { revision, .. } => revision,
                    _ => 0,
                };
                if index == 5 {
                    n as u32
                } else {
                    (n >> 32) as u32
                }
            }
            7 | 8 => {
                let n = match self.value {
                    Value::TextRange { offset, .. } => offset,
                    _ => 0,
                };
                if index == 7 {
                    n as u32
                } else {
                    (n >> 32) as u32
                }
            }
            9 => match self.value {
                Value::TextRange { length, .. } => length,
                _ => 0,
            },
            10 | 11 => {
                let n = match self.value {
                    Value::TextRange { total, .. } => total,
                    _ => 0,
                };
                if index == 10 {
                    n as u32
                } else {
                    (n >> 32) as u32
                }
            }
            12..=27 => {
                let at = (index - 12) * 4;
                u32::from_le_bytes(self.label.bytes[at..at + 4].try_into().unwrap())
            }
            _ => 0,
        }
    }
    fn decode(words: &[u32]) -> Result<Self, Error> {
        if words.len() != 32 || words[28..].iter().any(|n| *n != 0) {
            return Err(Error::Field);
        }
        let flags = (words[1] >> 8) as u8;
        let actions = (words[1] >> 16) as u8;
        let len = (words[1] >> 24) as usize;
        if flags & !3 != 0 || actions & !63 != 0 {
            return Err(Error::Flags);
        }
        if len > 64 {
            return Err(Error::Label);
        }
        let mut bytes = [0; 64];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(&words[12..28]) {
            chunk.copy_from_slice(&word.to_le_bytes())
        }
        if bytes[len..].iter().any(|b| *b != 0) {
            return Err(Error::Label);
        }
        let label = Label::new(core::str::from_utf8(&bytes[..len]).map_err(|_| Error::Label)?)?;
        let pair = |at: usize| u64::from(words[at]) | (u64::from(words[at + 1]) << 32);
        let value = match words[4] {
            0 if words[5..12].iter().all(|n| *n == 0) => Value::None,
            1 if words[7..12].iter().all(|n| *n == 0) => Value::Number(pair(5) as i64),
            2 => {
                let (revision, offset, length, total) = (pair(5), pair(7), words[9], pair(10));
                if revision == u64::MAX
                    || total > MAX_TEXT
                    || offset
                        .checked_add(u64::from(length))
                        .is_none_or(|end| end > total)
                {
                    return Err(Error::Value);
                }
                Value::TextRange {
                    revision,
                    offset,
                    length,
                    total,
                }
            }
            _ => return Err(Error::Value),
        };
        let out = Self {
            local: words[0] as u16,
            parent: (words[0] >> 16) as u16,
            role: Role::read(words[1] as u8)?,
            flags,
            actions,
            label,
            bounds: Rect {
                x: words[2] as u16,
                y: (words[2] >> 16) as u16,
                width: words[3] as u16,
                height: (words[3] >> 16) as u16,
            },
            value,
        };
        if out.local == 0 || !out.bounds.valid() {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub nonce: u32,
    pub page: u8,
    pub pages: u8,
    pub model: u64,
    pub view: u64,
    pub frame: u64,
    pub mapping_epoch: u64,
    pub width: u16,
    pub height: u16,
    pub keyboard: u16,
    pub modal: u16,
}
impl Header {
    const EMPTY: Self = Self {
        nonce: 0,
        page: 0,
        pages: 0,
        model: 0,
        view: 0,
        frame: 0,
        mapping_epoch: 0,
        width: 0,
        height: 0,
        keyboard: 0,
        modal: 0,
    };
    fn valid(self) -> Result<(), Error> {
        if !nonce(self.nonce)
            || self.pages == 0
            || self.pages > MAX_PAGES
            || self.page >= self.pages
        {
            return Err(Error::Nonce);
        }
        if [self.model, self.view, self.frame, self.mapping_epoch]
            .iter()
            .any(|n| matches!(*n, 0 | u64::MAX))
        {
            return Err(Error::Value);
        }
        if self.width == 0 || self.height == 0 {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}
/// Caller-owned resident immutable snapshot. Only staged complete validated
/// data is written here; native acceptance/publication is a separate operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    header: Header,
    nodes: [Node; MAX_NODES],
    count: u8,
}
impl Snapshot {
    pub const EMPTY: Self = Self {
        header: Header::EMPTY,
        nodes: [Node::EMPTY; MAX_NODES],
        count: 0,
    };
    pub const fn header(&self) -> Header {
        self.header
    }
    pub fn nodes(&self) -> &[Node] {
        &self.nodes[..self.count as usize]
    }
    pub fn replace(&mut self, header: Header, nodes: &[Node]) -> Result<(), Error> {
        validate(header, nodes)?;
        self.header = header;
        self.count = nodes.len() as u8;
        self.nodes.fill(Node::EMPTY);
        self.nodes[..nodes.len()].copy_from_slice(nodes);
        Ok(())
    }
    pub fn frames(&self) -> u16 {
        13 + u16::from(self.count) * 32
    }
    pub fn frame(&self, ordinal: u16) -> Option<Frame> {
        if ordinal >= self.frames() || self.count == 0 {
            return None;
        }
        let (field, word) = match ordinal {
            0 => (0, self.header.nonce),
            1 => (
                1,
                u32::from(self.count)
                    | (u32::from(self.header.page) << 8)
                    | (u32::from(self.header.pages) << 16),
            ),
            2..=9 => {
                let n = match ordinal {
                    2 | 3 => self.header.model,
                    4 | 5 => self.header.view,
                    6 | 7 => self.header.frame,
                    _ => self.header.mapping_epoch,
                };
                (
                    ordinal,
                    if ordinal.is_multiple_of(2) {
                        n as u32
                    } else {
                        (n >> 32) as u32
                    },
                )
            }
            10 => (
                10,
                u32::from(self.header.width) | (u32::from(self.header.height) << 16),
            ),
            11 => (
                11,
                u32::from(self.header.keyboard) | (u32::from(self.header.modal) << 16),
            ),
            _ if ordinal == self.frames() - 1 => (COMMIT, self.header.nonce),
            _ => {
                let offset = usize::from(ordinal - 12);
                (
                    16 + offset as u16,
                    self.nodes[offset / 32].word(offset % 32),
                )
            }
        };
        Some(Frame { field, word })
    }
}
fn validate(header: Header, nodes: &[Node]) -> Result<(), Error> {
    header.valid()?;
    if nodes.is_empty() || nodes.len() > MAX_NODES {
        return Err(Error::Bounds);
    }
    let root = Rect {
        x: 0,
        y: 0,
        width: header.width,
        height: header.height,
    };
    if nodes[0].local != 1
        || nodes[0].parent != 0
        || nodes[0].role != Role::Window
        || nodes[0].bounds != root
    {
        return Err(Error::Tree);
    }
    for (i, node) in nodes.iter().enumerate() {
        // Round-trip validates every private canonical field without relying on
        // the caller to have obtained Node through this module's decoder.
        let words = core::array::from_fn::<_, 32, _>(|at| node.word(at));
        Node::decode(&words)?;
        if !root.contains(node.bounds) || nodes[..i].iter().any(|old| old.local == node.local) {
            return Err(Error::Tree);
        }
        let mut at = i;
        let mut done = false;
        for _ in 0..MAX_NODES {
            let parent = nodes[at].parent;
            if parent == 0 {
                done = at == 0;
                break;
            }
            let next = nodes
                .iter()
                .position(|n| n.local == parent)
                .ok_or(Error::Tree)?;
            if !nodes[next].bounds.contains(nodes[at].bounds) {
                return Err(Error::Tree);
            }
            at = next;
        }
        if !done {
            return Err(Error::Tree);
        }
    }
    for id in [header.keyboard, header.modal] {
        if id != 0 && !nodes.iter().any(|n| n.local == id) {
            return Err(Error::Tree);
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Idle,
    Begin,
    Receiving,
    Complete,
    Refused,
    Aborting,
    Quarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Receiving,
    Complete,
    Aborted,
    Refused(u8),
}
pub struct Receiver {
    words: [u32; WORDS],
    nonce: u32,
    page: u8,
    expected: u16,
    stage: Stage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sending {
    Idle,
    Snapshot,
    Terminal,
}
/// Process-private bounded outbox. The native adapter advances only after an
/// actual successful SEND; accepted stream words are immutable until Commit or
/// an explicit matching AbortAck. It never borrows/reuses a File2 window.
pub struct Publisher {
    snapshot: Snapshot,
    ordinal: u16,
    mode: Sending,
    terminal: Option<Frame>,
    last_nonce: u32,
    last_abort: u32,
}
impl Default for Publisher {
    fn default() -> Self {
        Self::new()
    }
}
impl Publisher {
    pub const fn new() -> Self {
        Self {
            snapshot: Snapshot::EMPTY,
            ordinal: 0,
            mode: Sending::Idle,
            terminal: None,
            last_nonce: 0,
            last_abort: 0,
        }
    }
    pub fn busy(&self) -> bool {
        self.mode != Sending::Idle
    }
    pub fn begin(&mut self, header: Header, nodes: &[Node]) -> Result<(), Error> {
        if self.busy() {
            return Err(Error::State);
        }
        if header.nonce <= self.last_nonce {
            return Err(Error::Nonce);
        }
        self.snapshot.replace(header, nodes)?;
        self.last_nonce = header.nonce;
        self.ordinal = 0;
        self.mode = Sending::Snapshot;
        Ok(())
    }
    pub fn refuse(&mut self, n: u32, code: u8) -> Result<(), Error> {
        if self.busy() {
            return Err(Error::State);
        }
        if !nonce(n) || n <= self.last_nonce || !(1..=4).contains(&code) {
            return Err(Error::Nonce);
        }
        self.last_nonce = n;
        self.mode = Sending::Terminal;
        self.terminal = Some(Frame {
            field: 0x7f00 | u16::from(code),
            word: n,
        });
        Ok(())
    }
    pub fn abort(&mut self, n: u32) -> Result<(), Error> {
        if !nonce(n) || n != self.last_nonce {
            return Err(Error::Nonce);
        }
        if self.last_abort == n {
            return Ok(());
        }
        self.mode = Sending::Terminal;
        self.terminal = Some(Frame {
            field: ABORT_ACK,
            word: n,
        });
        Ok(())
    }
    pub fn next(&self) -> Option<Frame> {
        match self.mode {
            Sending::Idle => None,
            Sending::Snapshot => self.snapshot.frame(self.ordinal),
            Sending::Terminal => self.terminal,
        }
    }
    /// The frame is correlation, not a fabricated transport receipt. Caller
    /// must have obtained actual status0 from its held RootEvents SEND.
    pub fn sent(&mut self, frame: Frame) -> Result<(), Error> {
        if self.next() != Some(frame) {
            return Err(Error::Order);
        }
        match self.mode {
            Sending::Snapshot => {
                self.ordinal += 1;
                if self.ordinal == self.snapshot.frames() {
                    self.mode = Sending::Idle;
                }
            }
            Sending::Terminal => {
                if frame.field == ABORT_ACK {
                    self.last_abort = frame.word;
                }
                self.terminal = None;
                self.mode = Sending::Idle;
            }
            Sending::Idle => return Err(Error::State),
        }
        Ok(())
    }
}
impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}
impl Receiver {
    pub const fn new() -> Self {
        Self {
            words: [0; WORDS],
            nonce: 0,
            page: 0,
            expected: 0,
            stage: Stage::Idle,
        }
    }
    /// Authenticate the real expected sender outside this model. Starting a new
    /// instance never repairs unknown FIFO state on the same live native stream.
    pub fn request(&mut self, page: u8, n: u32) -> Result<Frame, Error> {
        if !matches!(self.stage, Stage::Idle | Stage::Complete | Stage::Refused) {
            return Err(Error::State);
        }
        if n <= self.nonce {
            return Err(Error::Nonce);
        }
        let frame = Request::Snapshot { page, nonce: n }.frame()?;
        self.words.fill(0);
        self.nonce = n;
        self.page = page;
        self.expected = 0;
        self.stage = Stage::Begin;
        Ok(frame)
    }
    pub fn abort(&mut self) -> Result<Frame, Error> {
        if self.nonce == 0 || self.stage == Stage::Idle {
            return Err(Error::State);
        }
        self.stage = Stage::Aborting;
        Request::Abort { nonce: self.nonce }.frame()
    }
    pub fn expire(&mut self) {
        self.stage = Stage::Quarantined
    }
    fn end(&self) -> usize {
        16 + ((self.words[1] & 255) as usize) * 32
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = Stage::Quarantined;
        Err(error)
    }
    pub fn push(&mut self, frame: Frame) -> Result<Progress, Error> {
        if frame.field == ABORT_ACK && frame.word == self.nonce && self.stage == Stage::Aborting {
            self.stage = Stage::Idle;
            return Ok(Progress::Aborted);
        }
        if self.stage == Stage::Aborting {
            return Ok(Progress::Receiving);
        }
        if self.stage == Stage::Quarantined {
            return Err(Error::Quarantined);
        }
        if !matches!(self.stage, Stage::Begin | Stage::Receiving) {
            return self.fail(Error::State);
        }
        if (0x7f01..=0x7f04).contains(&frame.field) && frame.word == self.nonce {
            self.stage = Stage::Refused;
            return Ok(Progress::Refused(frame.field as u8));
        }
        if frame.field == COMMIT {
            if frame.word != self.nonce {
                return self.fail(Error::Nonce);
            }
            if self.stage != Stage::Receiving || usize::from(self.expected) != self.end() {
                return self.fail(Error::Incomplete);
            }
            if let Err(error) = self.check_wire() {
                return self.fail(error);
            }
            self.stage = Stage::Complete;
            return Ok(Progress::Complete);
        }
        if frame.field != self.expected {
            return self.fail(Error::Order);
        }
        if frame.field == 0 {
            if self.stage != Stage::Begin || frame.word != self.nonce {
                return self.fail(Error::Nonce);
            }
            self.stage = Stage::Receiving;
        } else if frame.field == 1 {
            let count = (frame.word & 255) as usize;
            let page = (frame.word >> 8) as u8;
            let pages = (frame.word >> 16) as u8;
            if frame.word >> 24 != 0
                || count == 0
                || count > MAX_NODES
                || page != self.page
                || pages == 0
                || pages > MAX_PAGES
                || page >= pages
            {
                return self.fail(Error::Bounds);
            }
        }
        if frame.field >= 12 && (frame.field < 16 || usize::from(frame.field) >= self.end()) {
            return self.fail(Error::Field);
        }
        let Some(word) = self.words.get_mut(frame.field as usize) else {
            return self.fail(Error::Field);
        };
        *word = frame.word;
        self.expected = if frame.field == 11 {
            16
        } else {
            frame.field + 1
        };
        Ok(Progress::Receiving)
    }
    fn header(&self) -> Header {
        let pair = |at: usize| u64::from(self.words[at]) | (u64::from(self.words[at + 1]) << 32);
        Header {
            nonce: self.nonce,
            page: (self.words[1] >> 8) as u8,
            pages: (self.words[1] >> 16) as u8,
            model: pair(2),
            view: pair(4),
            frame: pair(6),
            mapping_epoch: pair(8),
            width: self.words[10] as u16,
            height: (self.words[10] >> 16) as u16,
            keyboard: self.words[11] as u16,
            modal: (self.words[11] >> 16) as u16,
        }
    }
    fn check_wire(&self) -> Result<(), Error> {
        let count = (self.words[1] & 255) as usize;
        let mut nodes = [Node::EMPTY; MAX_NODES];
        for (i, node) in nodes[..count].iter_mut().enumerate() {
            *node = Node::decode(&self.words[16 + i * 32..16 + (i + 1) * 32])?
        }
        validate(self.header(), &nodes[..count])
    }
    /// Decode into a STAGED candidate only. Caller still needs actual coherent
    /// Display acceptance and current sender/lease/geometry before publication.
    pub fn candidate(&self, out: &mut Snapshot) -> Result<(), Error> {
        if self.stage != Stage::Complete || usize::from(self.expected) != self.end() {
            return Err(Error::State);
        }
        self.check_wire()?;
        let count = (self.words[1] & 255) as usize;
        out.header = self.header();
        out.count = count as u8;
        out.nodes.fill(Node::EMPTY);
        for (i, node) in out.nodes[..count].iter_mut().enumerate() {
            *node = Node::decode(&self.words[16 + i * 32..16 + (i + 1) * 32])?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header() -> Header {
        Header {
            nonce: 17,
            page: 1,
            pages: 3,
            model: 0x1_0000_0001,
            view: 0x2_0000_0002,
            frame: 0x3_0000_0003,
            mapping_epoch: 0x4_0000_0004,
            width: 320,
            height: 180,
            keyboard: 16,
            modal: 0,
        }
    }
    fn snapshot() -> Snapshot {
        let nodes = [
            Node {
                local: 1,
                parent: 0,
                role: Role::Window,
                label: Label::new("Editor α").unwrap(),
                bounds: Rect {
                    x: 0,
                    y: 0,
                    width: 320,
                    height: 180,
                },
                ..Node::EMPTY
            },
            Node {
                local: 16,
                parent: 1,
                role: Role::Button,
                actions: 3,
                label: Label::new("Save").unwrap(),
                bounds: Rect {
                    x: 4,
                    y: 4,
                    width: 80,
                    height: 20,
                },
                value: Value::Number(-7),
                ..Node::EMPTY
            },
            Node {
                local: 32,
                parent: 1,
                role: Role::Document,
                actions: 2,
                label: Label::new("Document 😀").unwrap(),
                bounds: Rect {
                    x: 4,
                    y: 30,
                    width: 312,
                    height: 140,
                },
                value: Value::TextRange {
                    revision: 9,
                    offset: 0,
                    length: 4096,
                    total: MAX_TEXT,
                },
                ..Node::EMPTY
            },
        ];
        let mut s = Snapshot::EMPTY;
        s.replace(header(), &nodes).unwrap();
        s
    }
    fn receiver(s: &Snapshot) -> Receiver {
        let mut r = Receiver::new();
        r.request(s.header().page, s.header().nonce).unwrap();
        r
    }
    #[test]
    fn exact_wire_paged_snapshot_preserves_all64bit_bindings_unicode_and_bounded_ranges() {
        let s = snapshot();
        let mut r = receiver(&s);
        let mut out = Snapshot::EMPTY;
        for i in 0..s.frames() {
            let frame = s.frame(i).unwrap();
            assert_eq!(Frame::decode(&frame.encode()), Ok(frame));
            let p = r.push(frame).unwrap();
            assert_eq!(
                p,
                if i == s.frames() - 1 {
                    Progress::Complete
                } else {
                    Progress::Receiving
                }
            );
            if p != Progress::Complete {
                assert!(r.candidate(&mut out).is_err());
                assert_eq!(out, Snapshot::EMPTY);
            }
        }
        r.candidate(&mut out).unwrap();
        assert_eq!(out, s);
        assert_eq!(out.nodes()[2].label.as_str(), "Document 😀");
        assert_eq!(out.header().model, 0x1_0000_0001);
        assert_eq!(s.frame(s.frames()), None);
    }
    #[test]
    fn each_missing_duplicate_or_reordered_field_prevents_atomic_candidate_publication() {
        let s = snapshot();
        for missing in 0..s.frames() {
            let mut r = receiver(&s);
            let mut out = s.clone();
            for i in 0..s.frames() {
                if i == missing {
                    continue;
                }
                if r.push(s.frame(i).unwrap()).is_err() {
                    break;
                }
            }
            assert!(r.candidate(&mut out).is_err());
            assert_eq!(out, s);
        }
        for duplicate in 0..s.frames() - 1 {
            let mut r = receiver(&s);
            for i in 0..=duplicate {
                r.push(s.frame(i).unwrap()).unwrap();
            }
            assert!(r.push(s.frame(duplicate).unwrap()).is_err());
            assert!(r.request(1, 18).is_err());
        }
    }
    #[test]
    fn refusal_after_all_data_does_not_supply_commit_or_release_an_ambiguous_stream() {
        let s = snapshot();
        let mut r = receiver(&s);
        for i in 0..s.frames() - 1 {
            r.push(s.frame(i).unwrap()).unwrap();
        }
        assert_eq!(
            r.push(Frame {
                field: 0x7f03,
                word: 17
            }),
            Ok(Progress::Refused(3))
        );
        let mut out = Snapshot::EMPTY;
        assert!(r.candidate(&mut out).is_err());
        assert_eq!(out, Snapshot::EMPTY);
        assert!(r.request(1, 18).is_ok());
        assert_eq!(r.push(Frame { field: 0, word: 17 }), Err(Error::Nonce));
        r.expire();
        assert!(r.request(1, 19).is_err());
        assert_eq!(
            r.abort().unwrap(),
            Request::Abort { nonce: 18 }.frame().unwrap()
        );
        assert_eq!(
            r.push(Frame {
                field: ABORT_ACK,
                word: 17
            }),
            Ok(Progress::Receiving)
        );
        assert!(r.request(1, 19).is_err());
        assert_eq!(
            r.push(Frame {
                field: ABORT_ACK,
                word: 18
            }),
            Ok(Progress::Aborted)
        );
        assert!(r.request(1, 19).is_ok());
    }
    #[test]
    fn reserved_roles_flags_utf8_tail_values_and_stale_commit_are_rejected() {
        let s = snapshot();
        for (field, word) in [
            (1, 0xff00_0303),
            (16 + 32 + 1, 0),
            (16 + 32 + 1, 0x0401_0403),
            (16 + 32 + 4, 9),
            (16 + 32 + 28, 1),
            (16 + 32 + 12, 0xff),
            (16 + 32 + 27, 1),
            (16 + 64 + 10, MAX_TEXT as u32 + 1),
            (COMMIT, 18),
        ] {
            let mut r = receiver(&s);
            let mut matched = false;
            for i in 0..s.frames() {
                let mut f = s.frame(i).unwrap();
                if f.field == field {
                    f.word = word;
                    matched = true
                }
                if r.push(f).is_err() {
                    break;
                }
            }
            assert!(matched);
            let mut old = s.clone();
            assert!(r.candidate(&mut old).is_err(), "field{field}");
            assert_eq!(old, s);
        }
        for n in [0, u32::MAX] {
            assert!(Request::Snapshot { page: 0, nonce: n }.frame().is_err());
        }
        assert!(Request::Snapshot { page: 8, nonce: 17 }.frame().is_err());
        for len in 0..8 {
            assert_eq!(Frame::decode(&[0; 8][..len]), Err(Error::Wire));
        }
    }
    #[test]
    fn repeated_page_root_is_valid_but_cycles_outside_bounds_and_missing_focus_are_not() {
        let s = snapshot();
        let mut out = s.clone();
        let mut nodes = s.nodes().to_vec();
        nodes[1].parent = 32;
        nodes[2].parent = 16;
        assert_eq!(out.replace(s.header(), &nodes), Err(Error::Tree));
        assert_eq!(out, s);
        let mut nodes = s.nodes().to_vec();
        nodes[1].bounds.x = 310;
        assert_eq!(out.replace(s.header(), &nodes), Err(Error::Tree));
        assert_eq!(out, s);
        assert_eq!(
            out.replace(
                Header {
                    keyboard: 99,
                    ..s.header()
                },
                s.nodes()
            ),
            Err(Error::Tree)
        );
        assert!(Label::new("line\nbreak").is_err());
        assert!(Label::new(&"α".repeat(33)).is_err());
        assert!(Label::new(&"α".repeat(32)).is_ok());
    }
    #[test]
    fn publisher_backpressure_preserves_exact_stream_and_abort_ack_drains_before_new_begin() {
        let s = snapshot();
        let mut publisher = Publisher::new();
        publisher.begin(s.header(), s.nodes()).unwrap();
        let begin = publisher.next().unwrap();
        for _ in 0..20 {
            assert_eq!(publisher.next(), Some(begin));
        }
        assert_eq!(
            publisher.sent(Frame { field: 1, word: 0 }),
            Err(Error::Order)
        );
        publisher.sent(begin).unwrap();
        let second = publisher.next().unwrap();
        assert!(
            publisher
                .begin(
                    Header {
                        nonce: 18,
                        ..s.header()
                    },
                    s.nodes()
                )
                .is_err()
        );
        assert_eq!(publisher.next(), Some(second));
        publisher.abort(17).unwrap();
        let ack = Frame {
            field: ABORT_ACK,
            word: 17,
        };
        assert_eq!(publisher.next(), Some(ack));
        assert!(publisher.refuse(18, 2).is_err());
        publisher.sent(ack).unwrap();
        publisher.abort(17).unwrap();
        assert_eq!(publisher.next(), None); // accepted Ack is never duplicated
        assert!(publisher.begin(s.header(), s.nodes()).is_err());
        publisher
            .begin(
                Header {
                    nonce: 18,
                    ..s.header()
                },
                s.nodes(),
            )
            .unwrap();
        while let Some(frame) = publisher.next() {
            publisher.sent(frame).unwrap();
        }
        publisher.refuse(19, 1).unwrap();
        assert_eq!(
            publisher.next(),
            Some(Frame {
                field: 0x7f01,
                word: 19
            })
        );
    }
}
