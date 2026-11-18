//! First-party semantic consumer staging. Root authenticates and authorizes
//! sources; this client never reads another process mapping or File2 window.
use ev_graphics::{ACCENT, BACKGROUND, Canvas, Error, INK, MUTED, PANEL, Pixels};
use ev_userspace_contract::root_v5::assistive::{
    self as control, Context, Intent, IntentKind, Mode,
};
use ev_workspace_client::semantic::{self, Frame, Progress, Receiver, Snapshot, operation as op};
pub struct Consumer {
    context: Context,
    staged: Option<Context>,
    view: u32,
    painted_view: u32,
    range_present: Option<u32>,
    receiver: Receiver,
    snapshot: Snapshot,
    selected: u8,
    active: bool,
    abort_view: Option<u32>,
    snapshot_pending: bool,
    operation: op::Receiver,
    operation_pending: bool,
    range: Option<op::RangeReceiver>,
    range_nonce: u32,
    text: [u8; 1024],
    text_len: usize,
    text_at: usize,
    width: u16,
    height: u16,
}
impl Default for Consumer {
    fn default() -> Self {
        Self::new()
    }
}
impl Consumer {
    pub const fn new() -> Self {
        Self {
            context: Context {
                mode: Mode::Stats,
                source: ev_userspace_contract::root_v5::display_control::Slot::EditorOne,
                scopes: 0,
            },
            staged: None,
            view: 0,
            painted_view: 0,
            range_present: None,
            receiver: Receiver::new(),
            snapshot: Snapshot::EMPTY,
            selected: 0,
            active: false,
            abort_view: None,
            snapshot_pending: false,
            operation: op::Receiver::new(),
            operation_pending: false,
            range: None,
            range_nonce: 0,
            text: [0; 1024],
            text_len: 0,
            text_at: 0,
            width: 320,
            height: 180,
        }
    }
    pub fn geometry(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
    }
    /// The actual sole-Root route may drive the authorized Root reader while
    /// protected attention owns keyboard focus. This is navigation/data only;
    /// ordinary Activate still goes through Root's protected-node refusal.
    pub fn modal_reader_control(&self, node: u16) -> bool {
        self.context.mode == Mode::Semantic
            && self.context.source
                == ev_userspace_contract::root_v5::display_control::Slot::ProtectedRoot
            && self.context.scopes & 1 != 0
            && self.snapshot.header().modal != 0
            && matches!(node,201..=204|206..=207|209|212..=214|218|300..=315)
    }
    pub fn protected_confirm(&self, node: u16) -> bool {
        node == 213
            && self.context.mode == Mode::Semantic
            && self.context.source
                == ev_userspace_contract::root_v5::display_control::Slot::ProtectedRoot
            && self.context.scopes & 10 == 10
            && self.snapshot.header().modal != 0
    }
    pub fn paintable(&self) -> bool {
        self.context.mode != Mode::Receiving
    }
    pub const fn active(&self) -> bool {
        self.active
    }
    pub const fn presentation_view(&self) -> u32 {
        self.painted_view
    }
    pub fn marker_sent(&mut self) {
        self.range_present = None;
    }
    pub const fn aborting(&self) -> bool {
        self.abort_view.is_some()
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        (self.context.mode == Mode::Semantic).then_some(&self.snapshot)
    }
    /// Called only for bytes consumed from the actual sole-Root control route.
    /// Returns true only when complete state changes the local presentation.
    pub fn receive(&mut self, bytes: [u8; 8]) -> Result<bool, semantic::Error> {
        if let Ok(context) = Context::decode(bytes) {
            self.staged = Some(context);
            return Ok(false);
        }
        if let Ok(view) = control::decode_commit(bytes) {
            if view <= self.view.max(self.painted_view) {
                return Err(semantic::Error::Nonce);
            }
            if self.snapshot_pending
                || self.abort_view.is_some()
                || self.operation_pending
                || self.range.is_some()
            {
                return Err(semantic::Error::State);
            }
            let context = self.staged.take().ok_or(semantic::Error::State)?;
            if context.mode == Mode::Semantic {
                return Err(semantic::Error::State);
            }
            self.context = context;
            self.view = view;
            self.painted_view = view;
            self.range_present = None;
            self.active = context.mode != Mode::Stats;
            self.selected = 0;
            if context.mode != Mode::Semantic {
                self.snapshot = Snapshot::EMPTY;
            }
            // A Receiving placeholder must never acknowledge this nonce as a
            // delivered semantic page. Keep prior pixels until full commit.
            return Ok(!matches!(context.mode, Mode::Receiving | Mode::Stats));
        }
        if let Ok(view) = control::decode_abort(bytes) {
            if view != self.view {
                return Err(semantic::Error::Nonce);
            }
            let _ = self.receiver.abort()?;
            self.abort_view = Some(view);
            self.context.mode = Mode::Revoking;
            self.snapshot = Snapshot::EMPTY;
            self.text_len = 0;
            self.text_at = 0;
            return Ok(true);
        }
        let frame = Frame::decode(&bytes)?;
        if (0x8100..=0x81ff).contains(&frame.field) {
            if self.context.mode != Mode::Semantic {
                return Err(semantic::Error::State);
            }
            if frame.field == 0x8100 {
                self.operation_pending = true;
            }
            match self.operation.push(frame)? {
                op::Progress::Complete(request) => {
                    self.operation_pending = false;
                    if !request.binding.matches(self.snapshot.header())
                        || !self
                            .snapshot
                            .nodes()
                            .iter()
                            .any(|n| n.local == request.node)
                    {
                        return Err(semantic::Error::Value);
                    }
                    let op::Kind::Range { kind, .. } = request.kind else {
                        return Err(semantic::Error::Field);
                    };
                    if kind == op::RangeKind::Document && self.context.scopes & 4 == 0 {
                        return Err(semantic::Error::Value);
                    }
                    self.range = Some(op::RangeReceiver::new(request)?);
                    self.range_nonce = request.nonce;
                    self.text_len = 0;
                    self.text_at = 0;
                }
                op::Progress::Aborted(_) => {
                    self.operation_pending = false;
                    self.range = None;
                    self.text_len = 0;
                    self.text_at = 0;
                }
                op::Progress::Receiving => (),
            }
            return Ok(false);
        }
        if (0x9000..=0x90ff).contains(&frame.field) {
            let range = self.range.as_mut().ok_or(semantic::Error::State)?;
            if range.push(frame)? {
                let digits = b"0123456789abcdef";
                for byte in range.staged_text()?.bytes() {
                    if byte.is_ascii_graphic() && byte != b'\\' || byte == b' ' {
                        self.text[self.text_len] = byte;
                        self.text_len += 1;
                    } else {
                        self.text[self.text_len..self.text_len + 2].copy_from_slice(b"\\x");
                        self.text[self.text_len + 2] = digits[(byte >> 4) as usize];
                        self.text[self.text_len + 3] = digits[(byte & 15) as usize];
                        self.text_len += 4;
                    }
                }
                if self.text_len == 0 {
                    self.text[..14].copy_from_slice(b"[End of range]");
                    self.text_len = 14;
                }
                self.painted_view = self.range_nonce;
                self.range_present = Some(self.range_nonce);
                self.range = None;
                return Ok(true);
            }
            return Ok(false);
        }
        if (0x9f01..=0x9f04).contains(&frame.field) && frame.word == self.range_nonce {
            self.range = None;
            self.text_len = 0;
            self.painted_view = self.range_nonce;
            self.range_present = Some(self.range_nonce);
            return Ok(true);
        }

        if let Ok(semantic::Request::Snapshot { page, nonce }) = semantic::Request::decode(frame) {
            if self.context.mode != Mode::Receiving || nonce != self.view {
                return Err(semantic::Error::State);
            }
            self.receiver.request(page, nonce)?;
            self.snapshot_pending = true;
            return Ok(false);
        }
        match self.receiver.push(frame)? {
            Progress::Complete => {
                self.receiver.candidate(&mut self.snapshot)?;
                if self.snapshot.header().nonce != self.view {
                    return Err(semantic::Error::Nonce);
                }
                self.snapshot_pending = false;
                self.context.mode = Mode::Semantic;
                self.selected = 0;
                Ok(true)
            }
            Progress::Aborted => {
                self.snapshot = Snapshot::EMPTY;
                self.context.mode = Mode::Revoked;
                self.abort_view = None;
                self.snapshot_pending = false;
                Ok(true)
            }
            Progress::Refused(_) => {
                self.snapshot_pending = false;
                self.context.mode = Mode::Unsupported;
                Ok(true)
            }
            Progress::Receiving => Ok(false),
        }
    }
    pub(crate) fn tool_allowed(&self, action: u16) -> bool {
        match action {
            204 | 205 | 215 | 216 | 217 => {
                self.context.mode == Mode::Semantic && self.context.scopes & 2 != 0
            }
            208 => self.context.mode == Mode::Semantic && self.context.scopes & 4 != 0,
            213 => self.protected_confirm(action),
            _ => true,
        }
    }
    /// Projection of this consumer's own controls, never the nested provider's
    /// names or document bytes. A partial stream cannot describe accepted pixels.
    pub(crate) fn self_view_ready(&self) -> bool {
        self.context.mode != Mode::Receiving
            && !self.snapshot_pending
            && !self.operation_pending
            && self.range.is_none()
            && self.abort_view.is_none()
    }
    pub(crate) const fn context(&self) -> Context {
        self.context
    }
    pub(crate) const fn text_viewport(&self) -> (usize, usize) {
        (self.text_at, self.text_len)
    }
    pub fn control_enabled(&self, action: u16) -> bool {
        self.active
            && self.view != 0
            && self.self_view_ready()
            && (matches!(action, 212 | 214) || self.context.mode == Mode::Semantic)
            && self.tool_allowed(action)
            && ((201..=218).contains(&action)
                || ((300..316).contains(&action)
                    && self.context.mode == Mode::Semantic
                    && usize::from(action - 300) < self.snapshot.nodes().len()))
    }
    pub fn activate(&mut self, action: u16) -> Option<Intent> {
        if !self.active
            || self.view == 0
            || self.snapshot_pending
            || self.abort_view.is_some()
            || !self.tool_allowed(action)
        {
            return None;
        }
        if (300..316).contains(&action) && self.context.mode == Mode::Semantic {
            let index = (action - 300) as u8;
            if usize::from(index) >= self.snapshot.nodes().len() {
                return None;
            }
            self.selected = index;
            self.text_len = 0;
            self.text_at = 0;
            return Some(Intent {
                kind: IntentKind::AssistiveFocus,
                index,
                view: self.painted_view,
            });
        }
        let kind = match action {
            201 => IntentKind::PreviousNode,
            202 => IntentKind::NextNode,
            203 => IntentKind::AssistiveFocus,
            204 => IntentKind::Activate,
            205 => IntentKind::KeyboardFocus,
            206 => IntentKind::Expand,
            207 => IntentKind::ReadLabel,
            208 => IntentKind::ReadDocument,
            209 => IntentKind::Refresh,
            210 => IntentKind::PreviousSource,
            211 => IntentKind::NextSource,
            212 => IntentKind::Disable,
            213 => IntentKind::ConfirmProtected,
            214 => IntentKind::Cancel,
            215 => IntentKind::Select,
            216 => IntentKind::ScrollUp,
            217 => IntentKind::ScrollDown,
            218 => IntentKind::MoreText,
            _ => return None,
        };
        if matches!(kind, IntentKind::ReadLabel | IntentKind::ReadDocument) {
            self.text_len = 0;
            self.text_at = 0;
        }
        if self.text_len > 0 && matches!(kind, IntentKind::PreviousNode | IntentKind::NextNode) {
            let count = (usize::from(self.width) / 6).max(1)
                * (usize::from(self.height).saturating_sub(68) / 8).max(1);
            if kind == IntentKind::NextNode {
                self.text_at = (self.text_at + count).min((self.text_len - 1) / count * count);
            } else {
                self.text_at = self.text_at.saturating_sub(count);
            }
            return None;
        }
        if self.context.mode == Mode::Semantic {
            let count = self.snapshot.nodes().len() as u8;
            if kind == IntentKind::NextNode && count > 0 {
                self.selected = (self.selected + 1) % count;
            }
            if kind == IntentKind::PreviousNode && count > 0 {
                self.selected = (self.selected + count - 1) % count;
            }
        }
        Some(Intent {
            kind,
            index: self.selected,
            view: self.painted_view,
        })
    }
    pub const fn selected(&self) -> u8 {
        self.selected
    }
    pub fn presented(&self) -> Option<[u8; 8]> {
        if !self.active || self.painted_view == 0 || self.context.mode == Mode::Receiving {
            return None;
        }
        Some(if self.range_present.is_some() {
            control::range_presented(self.painted_view).unwrap()
        } else {
            control::presented(self.painted_view).unwrap()
        })
    }
}
fn label<P: Pixels>(
    p: &mut P,
    x: usize,
    y: usize,
    bytes: &[u8],
    color: ev_graphics::Color,
) -> Result<(), Error> {
    let (w, h) = p.dimensions();
    if x >= w || y + 7 > h {
        return Ok(());
    }
    let count = bytes.len().min((w - x) / 6);
    Canvas::new(p).text_exact(x, y, &bytes[..count], color)
}
fn escaped<P: Pixels>(
    p: &mut P,
    x: usize,
    y: usize,
    value: &str,
    color: ev_graphics::Color,
) -> Result<(), Error> {
    let mut bytes = [0u8; 256];
    let mut count = 0;
    let digits = b"0123456789abcdef";
    for byte in value.bytes() {
        if byte.is_ascii_graphic() && byte != b'\\' || byte == b' ' {
            bytes[count] = byte;
            count += 1;
        } else {
            bytes[count..count + 2].copy_from_slice(b"\\x");
            bytes[count + 2] = digits[(byte >> 4) as usize];
            bytes[count + 3] = digits[(byte & 15) as usize];
            count += 4;
        }
    }
    label(p, x, y, &bytes[..count], color)
}
pub fn render<P: Pixels>(p: &mut P, consumer: &Consumer) -> Result<(), Error> {
    let (w, h) = p.dimensions();
    if w == 0 || h == 0 || w > 320 || h > 200 {
        return Err(Error::Geometry);
    }
    Canvas::new(p).fill(PANEL)?;
    let names: [&[u8]; 18] = [
        b"Prev",
        b"Next",
        b"AT focus",
        b"Activate",
        b"Key focus",
        b"Expand",
        b"Name",
        b"Text",
        b"Refresh",
        b"Prev app",
        b"Next app",
        b"Revoke",
        b"Confirm",
        b"Cancel",
        b"Select",
        b"Scroll up",
        b"Scroll down",
        b"More text",
    ];
    let cell = (w / 7).max(1);
    for (i, name) in names.into_iter().enumerate() {
        let x = i % 7 * cell;
        let y = i / 7 * 20;
        if x < w && y < h {
            Canvas::new(p).rect(
                x,
                y,
                (w - x).min(cell.saturating_sub(1)),
                (h - y).min(19),
                BACKGROUND,
            )?;
            label(
                p,
                x + 1,
                y + 6,
                name,
                if consumer.tool_allowed(201 + i as u16) {
                    INK
                } else {
                    MUTED
                },
            )?;
        }
    }
    let Some(snapshot) = consumer.snapshot() else {
        label(
            p,
            2,
            64,
            match consumer.context.mode {
                Mode::AttentionRequested => b"Press Root Controls/Esc to review access",
                Mode::Receiving => b"Receiving complete semantic page",
                Mode::Revoking => b"Revoking; old work is retained",
                Mode::Revoked => b"Semantic access revoked",
                Mode::Unsupported => b"Current source unavailable",
                _ => b"No authorized semantic page",
            },
            MUTED,
        )?;
        return Ok(());
    };
    if consumer.text_len > 0 {
        let cols = (w / 6).max(1);
        let rows = (h.saturating_sub(68) / 8).max(1);
        for (row, line) in consumer.text[consumer.text_at..consumer.text_len]
            .chunks(cols)
            .take(rows)
            .enumerate()
        {
            label(p, 1, 62 + row * 8, line, INK)?;
        }
        return Ok(());
    }
    let rows = (h.saturating_sub(72) / 18 + 1).clamp(1, 6);
    let start = usize::from(consumer.selected) / rows * rows;
    for (i, node) in snapshot.nodes().iter().enumerate().skip(start).take(6) {
        let y = 64 + (i - start) * 18;
        if y + 8 > h.saturating_sub(8) {
            break;
        }
        if i == usize::from(consumer.selected) {
            Canvas::new(p).rect(0, y, w, (h - y).min(16), ACCENT)?;
        }
        escaped(
            p,
            2,
            y + 1,
            node.label.as_str(),
            if i == usize::from(consumer.selected) {
                BACKGROUND
            } else {
                INK
            },
        )?;
        if y + 16 <= h.saturating_sub(8) {
            label(
                p,
                2,
                y + 9,
                if node.flags & 2 != 0 {
                    b"Protected: ordinary Activate denied"
                } else if node.flags & 1 != 0 {
                    b"Disabled"
                } else if node.local == snapshot.header().keyboard {
                    b"Keyboard focus in Root-selected window"
                } else {
                    b"Semantic node; assistive selection is separate"
                },
                MUTED,
            )?;
        }
    }
    label(
        p,
        2,
        h.saturating_sub(8),
        b"Assistive focus is separate from keyboard focus",
        MUTED,
    )
}

/// Logical areas are descriptive; the broker validates its accepted Inspector
/// frame and authorized snapshot before forwarding any resulting action.
pub fn hit_test(width: usize, height: usize, x: usize, y: usize, selected: u8) -> Option<u16> {
    if width == 0 || height == 0 || width > 320 || height > 200 || x >= width || y >= height {
        return None;
    }
    if y < 60 {
        let cell = (width / 7).max(1);
        let column = x / cell;
        return (column < 7 && y / 20 * 7 + column < 18)
            .then_some(201 + (y / 20 * 7 + column) as u16);
    }
    let rows = (height.saturating_sub(72) / 18 + 1).clamp(1, 6);
    let start = usize::from(selected) / rows * rows;
    if y >= 64 {
        let row = (y - 64) / 18;
        if row < rows && start + row < 16 && 64 + row * 18 + 8 <= height.saturating_sub(8) {
            return Some(300 + (start + row) as u16);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(nonce: u32) -> Snapshot {
        let h = semantic::Header {
            nonce,
            page: 0,
            pages: 1,
            model: 0x1_0000_0001,
            view: 0x2_0000_0002,
            frame: 0x3_0000_0003,
            mapping_epoch: 0x4_0000_0004,
            width: 320,
            height: 180,
            keyboard: 0,
            modal: 0,
        };
        let root = semantic::Node {
            local: 1,
            parent: 0,
            role: semantic::Role::Window,
            flags: 0,
            actions: 0,
            label: semantic::Label::new("Actual Editor").unwrap(),
            bounds: semantic::Rect {
                x: 0,
                y: 0,
                width: 320,
                height: 180,
            },
            value: semantic::Value::None,
        };
        let button = semantic::Node {
            local: 16,
            parent: 1,
            role: semantic::Role::Button,
            flags: 0,
            actions: 1,
            label: semantic::Label::new("Open").unwrap(),
            bounds: semantic::Rect {
                x: 0,
                y: 0,
                width: 50,
                height: 20,
            },
            value: semantic::Value::None,
        };
        let mut snapshot = Snapshot::EMPTY;
        snapshot.replace(h, &[root, button]).unwrap();
        snapshot
    }
    fn begin(c: &mut Consumer, n: u32) {
        let context = Context {
            mode: Mode::Receiving,
            source: ev_userspace_contract::root_v5::display_control::Slot::EditorOne,
            scopes: 1,
        };
        assert!(!c.receive(context.encode().unwrap()).unwrap());
        assert!(!c.receive(control::commit(n).unwrap()).unwrap());
        assert!(c.presented().is_none());
        assert!(
            !c.receive(
                semantic::Request::Snapshot { page: 0, nonce: n }
                    .frame()
                    .unwrap()
                    .encode()
            )
            .unwrap()
        );
    }
    #[test]
    fn only_complete_actual_snapshot_is_exposed_and_partial_replacement_waits_for_abort() {
        let mut c = Consumer::new();
        begin(&mut c, 7);
        let snapshot = source(7);
        for i in 0..snapshot.frames() - 1 {
            assert!(!c.receive(snapshot.frame(i).unwrap().encode()).unwrap());
            assert!(c.snapshot().is_none());
            assert!(c.presented().is_none());
        }
        assert!(
            c.receive(snapshot.frame(snapshot.frames() - 1).unwrap().encode())
                .unwrap()
        );
        assert_eq!(c.snapshot().unwrap().header(), snapshot.header());
        assert_eq!(control::decode_presented(c.presented().unwrap()), Ok(7));
        assert_eq!(c.activate(302), None);
        assert_eq!(c.activate(301).unwrap().index, 1);
        assert!(c.receive(control::abort_relay(7).unwrap()).unwrap());
        assert!(c.snapshot().is_none());
        assert!(c.activate(204).is_none());
        let replacement = Context {
            mode: Mode::Receiving,
            source: ev_userspace_contract::root_v5::display_control::Slot::EditorTwo,
            scopes: 1,
        };
        c.receive(replacement.encode().unwrap()).unwrap();
        assert!(c.receive(control::commit(8).unwrap()).is_err());
        assert!(
            c.receive(
                Frame {
                    field: semantic::ABORT_ACK,
                    word: 7
                }
                .encode()
            )
            .unwrap()
        );
        assert!(!c.aborting());
        c.receive(replacement.encode().unwrap()).unwrap();
        assert!(!c.receive(control::commit(8).unwrap()).unwrap());
    }
    #[test]
    fn context_cannot_fabricate_a_semantic_page_or_reuse_a_published_nonce() {
        let mut c = Consumer::new();
        let context = Context {
            mode: Mode::Semantic,
            source: ev_userspace_contract::root_v5::display_control::Slot::EditorOne,
            scopes: 1,
        };
        c.receive(context.encode().unwrap()).unwrap();
        assert!(c.receive(control::commit(7).unwrap()).is_err());
        assert!(c.snapshot().is_none());
        begin(&mut c, 8);
        assert!(c.receive(control::commit(8).unwrap()).is_err());
        assert!(
            c.receive(
                Frame {
                    field: semantic::COMMIT,
                    word: 8
                }
                .encode()
            )
            .is_err()
        );
        assert!(c.presented().is_none());
    }
    fn complete(c: &mut Consumer, n: u32) {
        begin(c, n);
        let snapshot = source(n);
        for i in 0..snapshot.frames() {
            c.receive(snapshot.frame(i).unwrap().encode()).unwrap();
        }
    }
    fn range_request(c: &Consumer, nonce: u32, kind: op::RangeKind) -> op::Request {
        let h = c.snapshot().unwrap().header();
        op::Request {
            nonce,
            node: 16,
            binding: op::Binding {
                snapshot_nonce: h.nonce,
                model: h.model,
                view: h.view,
                frame: h.frame,
                mapping_epoch: h.mapping_epoch,
                text_revision: h.view,
            },
            kind: op::Kind::Range {
                kind,
                offset: 0,
                length: 128,
            },
        }
    }
    #[test]
    fn range_requires_exact_view_and_text_scope_and_hides_partial_utf8_results() {
        let mut c = Consumer::new();
        complete(&mut c, 7);
        let request = range_request(&c, 10, op::RangeKind::AccessibleLabel);
        for i in 0..18 {
            assert!(
                !c.receive(request.frame(i).unwrap().unwrap().encode())
                    .unwrap()
            );
        }
        let reply = op::RangeReply::new(10, 16, op::RangeKind::AccessibleLabel, "é name").unwrap();
        for i in 0..67 {
            assert!(!c.receive(reply.frame(i).unwrap().encode()).unwrap());
            assert_eq!(c.text_len, 0);
        }
        assert!(c.receive(reply.frame(67).unwrap().encode()).unwrap());
        assert_eq!(&c.text[..c.text_len], b"\\xc3\\xa9 name");
        assert_eq!(c.snapshot().unwrap().header().nonce, 7);
        assert_eq!(c.presentation_view(), 10);
        assert_eq!(
            control::decode_range_presented(c.presented().unwrap()),
            Ok(10)
        );
        let old = Context {
            mode: Mode::Receiving,
            source: ev_userspace_contract::root_v5::display_control::Slot::EditorOne,
            scopes: 1,
        };
        c.receive(old.encode().unwrap()).unwrap();
        assert!(c.receive(control::commit(8).unwrap()).is_err());

        let mut no_text = Consumer::new();
        complete(&mut no_text, 8);
        let denied = range_request(&no_text, 11, op::RangeKind::Document);
        for i in 0..17 {
            assert!(
                !no_text
                    .receive(denied.frame(i).unwrap().unwrap().encode())
                    .unwrap()
            );
        }
        assert!(
            no_text
                .receive(denied.frame(17).unwrap().unwrap().encode())
                .is_err()
        );
        assert!(no_text.range.is_none());
        assert_eq!(no_text.text_len, 0);
    }
    #[test]
    fn partial_operation_is_not_erased_by_a_new_source_context() {
        let mut c = Consumer::new();
        complete(&mut c, 7);
        let request = range_request(&c, 10, op::RangeKind::AccessibleLabel);
        c.receive(request.frame(0).unwrap().unwrap().encode())
            .unwrap();
        let replacement = Context {
            mode: Mode::Receiving,
            source: ev_userspace_contract::root_v5::display_control::Slot::EditorTwo,
            scopes: 1,
        };
        c.receive(replacement.encode().unwrap()).unwrap();
        assert!(c.receive(control::commit(8).unwrap()).is_err());
        c.receive(
            Frame {
                field: op::ABORT,
                word: 10,
            }
            .encode(),
        )
        .unwrap();
        assert!(!c.operation_pending);
        assert_eq!(c.view, 7);
        c.receive(control::abort_relay(7).unwrap()).unwrap();
        c.receive(
            Frame {
                field: semantic::ABORT_ACK,
                word: 7,
            }
            .encode(),
        )
        .unwrap();
        c.receive(replacement.encode().unwrap()).unwrap();
        assert!(!c.receive(control::commit(8).unwrap()).unwrap());
    }
    #[test]
    fn modal_root_reader_navigation_does_not_create_confirm_or_action_permission() {
        let mut c = Consumer::new();
        complete(&mut c, 7);
        let mut header = c.snapshot.header();
        header.modal = 1;
        let node = c.snapshot.nodes()[0];
        c.snapshot.replace(header, &[node]).unwrap();
        c.context.source = ev_userspace_contract::root_v5::display_control::Slot::ProtectedRoot;
        c.context.scopes = 1;
        for tool in [201, 202, 203, 206, 207, 209, 300] {
            assert!(c.modal_reader_control(tool));
        }
        assert!(c.activate(204).is_none());
        assert!(!c.protected_confirm(213));
        assert!(!c.modal_reader_control(205));
        assert!(!c.modal_reader_control(208));
        assert!(!c.modal_reader_control(215));
        c.context.scopes = 3;
        assert!(c.activate(204).is_some());
        assert!(!c.protected_confirm(213));
        c.context.scopes = 11;
        assert!(c.protected_confirm(213));
        c.context.source = ev_userspace_contract::root_v5::display_control::Slot::EditorOne;
        assert!(!c.modal_reader_control(201));
        assert!(!c.protected_confirm(213));
    }
}
