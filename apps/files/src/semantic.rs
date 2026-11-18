//! Paged semantic projection of the actual browser state. Descriptive rows and
//! names never authorize File contents or namespace operations.
use crate::{Browser, Mode, ROOT, Status};
use ev_userspace_contract::workspace::{EntryState, Kind};
use ev_workspace_client::semantic as a1;
pub const LABELS: [&str; 13] = [
    "Up",
    "New folder",
    "New text file",
    "Rename",
    "Move",
    "Trash",
    "Restore",
    "Open",
    "Previous page",
    "Next page",
    "Apply",
    "Cancel",
    "Refresh",
];
pub fn button(browser: &Browser, local: u16) -> Option<u16> {
    let i = local.checked_sub(16)?;
    if usize::from(i) >= LABELS.len() {
        return None;
    }
    if browser.loading() || browser.status() == Status::Uncertain {
        return None;
    }
    let selected = browser.selected();
    let input = browser.editing_name();
    let moving = matches!(browser.mode(), Mode::Move { .. });
    let enabled = match i + 1 {
        1 => !input && browser.directory() != ROOT,
        2 | 3 => !input && !moving,
        4 | 5 => !input && selected.is_some(),
        6 => !input && selected.is_some_and(|e| e.state == EntryState::Live),
        7 => !input && selected.is_some_and(|e| e.state == EntryState::Trashed),
        8 => !input && selected.is_some_and(|e| e.state == EntryState::Live),
        9 => !input && browser.has_previous_page(),
        10 => !input && browser.has_next_page(),
        11 => input || moving,
        12 => input || moving,
        13 => !input,
        _ => false,
    };
    enabled.then_some(i + 1)
}
pub fn row_actions(browser: &Browser, index: usize, visible: usize) -> u8 {
    if index >= visible
        || browser.loading()
        || browser.status() == Status::Uncertain
        || browser.editing_name()
    {
        return 0;
    }
    match browser.entries().nth(index) {
        Some(e) => 4 | u8::from(e.state == EntryState::Live),
        None => 0,
    }
}
pub fn visible_rows(height: u16) -> usize {
    usize::from(height.saturating_sub(80) / 10).min(crate::ROWS)
}
fn status(browser: &Browser) -> &'static str {
    match browser.status() {
        Status::Loading => "Loading",
        Status::Ready => "Ready",
        Status::Editing => "Name: Enter applies",
        Status::Moving => "Choose destination folder",
        Status::Changed => "Changed elsewhere: Refresh",
        Status::Refused => "Operation refused",
        Status::Full => "Workspace limit reached",
        Status::Name => "Use a valid name up to96 bytes",
        Status::Uncertain => "Recovery required",
    }
}
pub fn publish(
    out: &mut a1::Publisher,
    mut h: a1::Header,
    browser: &Browser,
    focused: bool,
) -> Result<(), a1::Error> {
    let (w, height) = (h.width, h.height);
    if w < 128 || height < 80 || h.page > 2 || h.pages != 3 {
        return Err(a1::Error::Bounds);
    }
    let rect = |x, y, width, height| a1::Rect {
        x,
        y,
        width,
        height,
    };
    let node = |local, parent, role, label, bounds, value, flags, actions| {
        Ok(a1::Node {
            local,
            parent,
            role,
            label: a1::Label::new(label)?,
            bounds,
            value,
            flags,
            actions,
        })
    };
    let mut nodes = [a1::Node::EMPTY; 16];
    let mut count = 1;
    nodes[0] = node(
        1,
        0,
        a1::Role::Window,
        "Files",
        rect(0, 0, w, height),
        a1::Value::None,
        0,
        0,
    )?;
    let toolbar = rect(0, 0, w, 40);
    let body = rect(0, 68, w, height - 78);
    let name = rect(0, 40, w, 20);
    let input = browser.editing_name();
    let moving = matches!(browser.mode(), Mode::Move { .. });
    let visible = visible_rows(height);
    if h.page == 0 || h.page == 1 {
        nodes[count] = node(
            2,
            1,
            a1::Role::Menu,
            "File actions",
            toolbar,
            if h.page == 0 {
                a1::Value::Number(1)
            } else {
                a1::Value::None
            },
            0,
            if h.page == 0 { 16 } else { 0 },
        )?;
        count += 1;
    }
    if h.page == 0 || h.page == 2 {
        nodes[count] = node(
            3,
            1,
            a1::Role::List,
            "Folder entries",
            body,
            if h.page == 0 {
                a1::Value::Number(2)
            } else {
                a1::Value::None
            },
            0,
            if h.page == 0 {
                16
            } else if !browser.loading()
                && !browser.editing_name()
                && browser.status() != Status::Uncertain
            {
                8
            } else {
                0
            },
        )?;
        count += 1;
    }
    if h.page == 1 {
        for (i, label) in LABELS.into_iter().enumerate() {
            if matches!(i, 10 | 11) && !input && !moving {
                continue;
            }
            let bounds = match i {
                0..=9 => rect(i as u16 % 5 * (w / 5), i as u16 / 5 * 20, w / 5 - 1, 19),
                10 => rect(w - 120, 40, 59, 19),
                11 => rect(w - 60, 40, 59, 19),
                _ => rect(w - 60, height - 10, 60, 10),
            };
            // Name/Apply/Cancel and Refresh live outside the toolbar's rectangle.
            let parent = if i < 10 { 2 } else { 1 };
            let enabled = button(browser, 16 + i as u16).is_some();
            nodes[count] = node(
                16 + i as u16,
                parent,
                a1::Role::Button,
                label,
                bounds,
                a1::Value::None,
                u8::from(!enabled),
                u8::from(enabled),
            )?;
            count += 1;
        }
    }
    if h.page == 2 {
        for (i, e) in browser.entries().take(visible).enumerate() {
            let selected = i == browser.selected_index();
            let label = match (
                selected,
                e.state == EntryState::Trashed,
                e.kind == Kind::Directory,
            ) {
                (true, true, _) => "Selected trashed entry",
                (true, false, true) => "Selected folder",
                (true, false, false) => "Selected file",
                (false, true, _) => "Trashed entry",
                (false, false, true) => "Folder",
                _ => "File",
            };
            nodes[count] = node(
                32 + i as u16,
                3,
                a1::Role::ListItem,
                label,
                rect(0, 68 + i as u16 * 10, w, 9),
                a1::Value::TextRange {
                    revision: h.view,
                    offset: 0,
                    length: e.name.as_str().len() as u32,
                    total: e.name.as_str().len() as u64,
                },
                0,
                row_actions(browser, i, visible),
            )?;
            count += 1;
        }
    }
    if h.page != 1 {
        nodes[count] = node(
            4,
            1,
            a1::Role::Label,
            status(browser),
            rect(0, height - 10, w - 60, 10),
            a1::Value::None,
            0,
            0,
        )?;
        count += 1;
    }
    if h.page != 1 || input {
        let label = if input {
            "Name"
        } else if moving {
            "Choose destination folder"
        } else if browser.directory() == ROOT {
            "Workspace"
        } else {
            "Folder"
        };
        let bounds = if input {
            rect(0, 40, w - 120, 20)
        } else {
            name
        };
        nodes[count] = node(
            5,
            1,
            if input {
                a1::Role::TextBox
            } else {
                a1::Role::Label
            },
            label,
            bounds,
            if input {
                a1::Value::TextRange {
                    revision: h.view,
                    offset: 0,
                    length: browser.name().len() as u32,
                    total: browser.name().len() as u64,
                }
            } else {
                a1::Value::None
            },
            0,
            if input { 2 } else { 0 },
        )?;
        count += 1;
    }
    h.modal = 0;
    h.keyboard = if focused && input {
        5
    } else if focused
        && h.page == 2
        && browser.selected_index() < browser.entries().take(visible).count()
    {
        32 + browser.selected_index() as u16
    } else {
        0
    };
    out.begin(h, &nodes[..count])
}

use a1::operation as op;
// One bounded process-private256-byte response; no allocator or shared file loan.
#[allow(clippy::large_enum_variant)]
enum Reply {
    Word(a1::Frame),
    Range {
        reply: op::RangeReply,
        ordinal: u16,
        nonce: u32,
    },
    AfterPresent {
        nonce: u32,
        frame: u64,
    },
}
/// Native adapters keep one instance for the whole live Root control stream.
/// This is protocol custody only; the actual selected channel authenticates Root.
pub struct Session {
    publisher: a1::Publisher,
    input: op::Receiver,
    pending: Option<a1::Header>,
    committed: Option<a1::Header>,
    reply: Option<Reply>,
}
impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
impl Session {
    pub const fn new() -> Self {
        Self {
            publisher: a1::Publisher::new(),
            input: op::Receiver::new(),
            pending: None,
            committed: None,
            reply: None,
        }
    }
    pub fn request(
        &mut self,
        request: a1::Request,
        mut header: a1::Header,
        available: bool,
        browser: &Browser,
        focused: bool,
    ) {
        match request {
            a1::Request::Abort { nonce } => {
                let _ = self.publisher.abort(nonce);
            }
            a1::Request::Snapshot { page, nonce } => {
                if self.publisher.busy() {
                    return;
                }
                if self.reply.is_some() {
                    let _ = self.publisher.refuse(nonce, 2);
                    return;
                }
                if !available {
                    let _ = self.publisher.refuse(nonce, 3);
                    return;
                }
                header.nonce = nonce;
                header.page = page;
                header.pages = 3;
                if publish(&mut self.publisher, header, browser, focused).is_ok() {
                    self.pending = Some(header);
                } else {
                    let _ = self.publisher.refuse(nonce, 1);
                }
            }
        }
    }
    pub fn snapshot_next(&self) -> Option<a1::Frame> {
        self.publisher.next()
    }
    /// Called only after actual successful SEND of this exact offered frame.
    pub fn snapshot_sent(&mut self, frame: a1::Frame) -> Result<(), a1::Error> {
        self.publisher.sent(frame)?;
        if frame.field == a1::COMMIT && self.pending.is_some_and(|h| h.nonce == frame.word) {
            self.committed = self.pending.take();
        } else if frame.field == a1::ABORT_ACK {
            self.pending = None;
            if self.committed.is_some_and(|h| h.nonce == frame.word) {
                self.committed = None;
            }
        }
        Ok(())
    }
    pub fn bound_page(&self, binding: op::Binding) -> Option<u8> {
        self.committed
            .filter(|h| binding.matches(*h))
            .map(|h| h.page)
    }
    pub fn operation(&mut self, frame: a1::Frame) -> Option<op::Request> {
        if frame.field == 0x8100 && self.reply.is_some() {
            return None;
        }
        match self.input.push(frame) {
            Ok(op::Progress::Complete(q)) => Some(q),
            Ok(op::Progress::Aborted(n)) => {
                let own = match self.reply.as_ref() {
                    Some(Reply::Word(f)) => f.word == n,
                    Some(Reply::Range { nonce, .. } | Reply::AfterPresent { nonce, .. }) => {
                        *nonce == n
                    }
                    None => true,
                };
                if own {
                    self.reply = Some(Reply::Word(a1::Frame {
                        field: op::ABORT_ACK,
                        word: n,
                    }));
                }
                None
            }
            _ => None,
        }
    }
    pub fn terminal(&mut self, n: u32, result: Result<(), op::Refusal>) {
        self.reply = Some(Reply::Word(op::terminal(n, result)));
    }
    pub fn after_present(&mut self, n: u32, frame: u64) {
        self.reply = Some(Reply::AfterPresent { nonce: n, frame });
    }
    pub fn range(
        &mut self,
        n: u32,
        node: u16,
        kind: op::RangeKind,
        text: &str,
    ) -> Result<(), a1::Error> {
        self.reply = Some(Reply::Range {
            reply: op::RangeReply::new(n, node, kind, text)?,
            ordinal: 0,
            nonce: n,
        });
        Ok(())
    }
    pub fn operation_next(
        &mut self,
        accepted: bool,
        paint: bool,
        current_frame: u64,
    ) -> Option<a1::Frame> {
        if let Some(Reply::AfterPresent { nonce, frame }) = self.reply
            && accepted
            && !paint
            && current_frame > frame
        {
            self.terminal(nonce, Ok(()));
        }
        match self.reply.as_ref() {
            Some(Reply::Word(f)) => Some(*f),
            Some(Reply::Range { reply, ordinal, .. }) => reply.frame(*ordinal),
            _ => None,
        }
    }
    /// Actual successful SEND only; backpressure retains the identical next word.
    pub fn operation_sent(&mut self, offered: a1::Frame) -> Result<(), a1::Error> {
        match self.reply.as_mut() {
            Some(Reply::Word(f)) if *f == offered => self.reply = None,
            Some(Reply::Range { reply, ordinal, .. }) if reply.frame(*ordinal) == Some(offered) => {
                *ordinal += 1;
                if *ordinal == 68 {
                    self.reply = None;
                }
            }
            _ => return Err(a1::Error::Order),
        }
        Ok(())
    }
}
