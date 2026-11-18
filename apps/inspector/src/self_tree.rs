//! Inspector's bounded self-description. This is a distinct stream from the
//! selected external provider, so describing controls never replaces its page.
//! Nested provider names and text remain redacted; their original READ/TEXT
//! grants cannot be laundered through a second grant on Inspector's own tree.
use crate::{Model, consumer::Consumer};
use ev_graphics::{ACCENT, Canvas, Error as GraphicsError, INK, PANEL, Pixels};
use ev_workspace_client::semantic::{self as a1, Frame, Header, Label, Node, Rect, Role, Value};
pub mod ordinary;
pub const NAV_ENTER: u16 = 9000;
pub const NAV_LEAVE: u16 = 9001;

pub const STATS_NAMES: [&str; 14] = [
    "Refresh",
    "Next page",
    "Previous page",
    "Focus selected process",
    "Request stop",
    "Request restart",
    "Request file revoke",
    "Layer",
    "Contrast",
    "Focus outline",
    "Scale",
    "Request shutdown",
    "Request restart all",
    "Request assistive access",
];
pub const READER_NAMES: [&str; 18] = [
    "Previous node or text page",
    "Next node or text page",
    "Assistive focus",
    "Activate source node",
    "Keyboard focus",
    "Expand",
    "Read source name",
    "Read document text",
    "Refresh",
    "Previous source",
    "Next source",
    "Revoke semantic access",
    "Dedicated protected confirmation",
    "Cancel",
    "Select",
    "Scroll up",
    "Scroll down",
    "More text",
];

/// Installed sole-Root delivery authenticates these bytes. The disjoint magic
/// prevents a self request from becoming an external-provider snapshot or intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Snapshot { page: u8, nonce: u32 },
    Abort { nonce: u32 },
}
impl Request {
    pub fn encode(self) -> Result<[u8; 8], a1::Error> {
        let (op, page, nonce) = match self {
            Self::Snapshot { page, nonce } if page < 5 => (1, page, nonce),
            Self::Abort { nonce } => (2, 0, nonce),
            _ => return Err(a1::Error::Field),
        };
        if matches!(nonce, 0 | u32::MAX) {
            return Err(a1::Error::Nonce);
        }
        let n = nonce.to_le_bytes();
        Ok([b'I', b'S', op, page, n[0], n[1], n[2], n[3]])
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, a1::Error> {
        if bytes[..2] != *b"IS" {
            return Err(a1::Error::Wire);
        }
        let nonce = u32::from_le_bytes(bytes[4..].try_into().unwrap());
        let request = match (bytes[2], bytes[3]) {
            (1, page @ 0..=4) => Self::Snapshot { page, nonce },
            (2, 0) => Self::Abort { nonce },
            _ => return Err(a1::Error::Field),
        };
        request.encode()?;
        Ok(request)
    }
}
/// Self replies keep all canonical A1 fields and ordering, with a distinct
/// envelope. A Root adapter must unwrap only its actual Inspector event sender.
pub const fn reply(frame: Frame) -> [u8; 8] {
    let f = frame.field.to_le_bytes();
    let w = frame.word.to_le_bytes();
    [b'I', b'T', f[0], f[1], w[0], w[1], w[2], w[3]]
}
pub fn decode_reply(bytes: [u8; 8]) -> Result<Frame, a1::Error> {
    if bytes[..2] != *b"IT" {
        return Err(a1::Error::Wire);
    }
    Ok(Frame {
        field: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        word: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
    })
}
pub struct Session {
    publisher: a1::Publisher,
    offered: Option<(Header, Option<u16>)>,
    completed: Option<(Header, Option<u16>)>,
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
            offered: None,
            completed: None,
        }
    }
    /// `accepted` is supplied only by the native adapter after exact own
    /// successful Present, with no pending repaint/scene/stream transition.
    pub fn request(
        &mut self,
        request: Request,
        mut header: Header,
        model: &Model,
        consumer: &Consumer,
        focus: Option<u16>,
        accepted: bool,
    ) -> Result<(), a1::Error> {
        match request {
            Request::Abort { nonce } => {
                self.offered = None;
                self.completed = None;
                self.publisher.abort(nonce)
            }
            Request::Snapshot { page, nonce } => {
                if self.publisher.busy() {
                    return Err(a1::Error::State);
                }
                self.completed = None;
                self.offered = None;
                if !accepted || (consumer.active() && !consumer.self_view_ready()) {
                    return self.publisher.refuse(nonce, 1);
                }
                header.nonce = nonce;
                header.page = page;
                publish(&mut self.publisher, header, model, consumer, focus)?;
                self.offered = Some((header, focus));
                Ok(())
            }
        }
    }
    pub fn next(&self) -> Option<[u8; 8]> {
        self.publisher.next().map(reply)
    }
    /// Call only after actual status0 on the original held RootEvents SEND.
    pub fn sent(&mut self, bytes: [u8; 8]) -> Result<(), a1::Error> {
        let frame = decode_reply(bytes)?;
        self.publisher.sent(frame)?;
        if frame.field == a1::COMMIT {
            self.completed = self.offered.take();
        }
        Ok(())
    }
    /// Only a fully sent own snapshot and the actual unchanged accepted
    /// surface/current ordinary keyboard control can arm a reader action.
    pub fn ordinary_scope(
        &self,
        current: Header,
        consumer: &Consumer,
        focus: Option<u16>,
        accepted: bool,
    ) -> Option<ordinary::Scope> {
        let (mut old, keyboard) = self.completed?;
        if !accepted
            || self.publisher.busy()
            || !consumer.active()
            || !consumer.self_view_ready()
            || old.view != u64::from(consumer.presentation_view())
            || focus != keyboard
            || old.model != current.model
            || old.view != current.view
            || old.frame != current.frame
            || old.mapping_epoch != current.mapping_epoch
            || old.width != current.width
            || old.height != current.height
        {
            return None;
        }
        let control = focus?;
        if control == 213
            || !consumer.control_enabled(control)
            || control >= 300 && consumer.text_viewport().1 != 0
        {
            return None;
        }
        old.keyboard = control;
        Some(ordinary::Scope {
            header: old,
            control,
        })
    }
}
fn rect(x: u16, y: u16, width: u16, height: u16) -> Rect {
    Rect {
        x,
        y,
        width,
        height,
    }
}
fn node(id: u16, role: Role, name: &str, bounds: Rect) -> Result<Node, a1::Error> {
    Ok(Node {
        local: id,
        parent: 1,
        role,
        flags: 0,
        actions: 0,
        label: Label::new(name)?,
        bounds,
        value: Value::None,
    })
}
fn number_label(name: &str, value: u64) -> Result<Label, a1::Error> {
    let mut out = [0; 64];
    let bytes = name.as_bytes();
    if bytes.len() > 42 {
        return Err(a1::Error::Label);
    }
    out[..bytes.len()].copy_from_slice(bytes);
    out[bytes.len()] = b':';
    out[bytes.len() + 1] = b' ';
    let mut digits = [0; 20];
    let mut at = 20;
    let mut n = value;
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let end = bytes.len() + 2 + 20 - at;
    out[bytes.len() + 2..end].copy_from_slice(&digits[at..]);
    Label::new(core::str::from_utf8(&out[..end]).map_err(|_| a1::Error::Label)?)
}
fn stats_enabled(model: &Model, action: u16) -> bool {
    if action == 14 {
        model.snapshot().is_some()
    } else {
        u8::try_from(action)
            .ok()
            .and_then(|a| model.action(a))
            .is_some()
    }
}
/// Shared with local self navigation. This returns an ordinary control intent;
/// Confirm is deliberately absent. It cannot mint Root's physical ticket.
pub fn ordinary_control(model: &Model, consumer: &Consumer, id: u16) -> Option<u16> {
    if consumer.active() {
        (id != 213
            && consumer.control_enabled(id)
            && !(id >= 300 && consumer.text_viewport().1 != 0))
            .then_some(id)
    } else if (16..30).contains(&id) {
        let action = id - 15;
        stats_enabled(model, action).then_some(action)
    } else if (100..106).contains(&id)
        && model
            .snapshot()
            .and_then(|s| s.row((id - 100) as u8))
            .is_some_and(|r| r[0] & 255 != 0)
    {
        Some(id)
    } else {
        None
    }
}
fn bounds(id: u16, reader: bool, width: u16, height: u16, selected: u8) -> Option<Rect> {
    if reader && (201..=218).contains(&id) {
        let i = id - 201;
        let cell = (width / 7).max(1);
        return Some(rect(i % 7 * cell, i / 7 * 20, cell.saturating_sub(1), 19));
    }
    if !reader && (16..30).contains(&id) {
        let i = id - 16;
        let (x, y, cell) = if i < 10 {
            (i % 5 * (width / 5), i / 5 * 20, width / 5)
        } else {
            ((i - 10) * (width / 4), 40, width / 4)
        };
        return Some(rect(x, y, cell.saturating_sub(1), 19));
    }
    if !reader && (100..106).contains(&id) {
        let y = 64 + (id - 100) * 10;
        return (y + 9 <= height.saturating_sub(40)).then_some(rect(0, y, width, 9));
    }
    if reader && (300..316).contains(&id) {
        let rows = (usize::from(height.saturating_sub(72)) / 18 + 1).clamp(1, 6);
        let start = usize::from(selected) / rows * rows;
        let index = usize::from(id - 300);
        if index < start || index >= start + rows {
            return None;
        }
        let y = 64 + (index - start) as u16 * 18;
        return (y + 8 <= height.saturating_sub(8)).then_some(rect(
            0,
            y,
            width,
            (height - y).min(16),
        ));
    }
    None
}
pub fn publish(
    out: &mut a1::Publisher,
    mut h: Header,
    model: &Model,
    consumer: &Consumer,
    focus: Option<u16>,
) -> Result<(), a1::Error> {
    if h.width < 120 || h.width > 320 || h.height < 80 || h.height > 200 {
        return Err(a1::Error::Bounds);
    }
    let reader = consumer.active();
    h.pages = if reader { 5 } else { 4 };
    h.keyboard = 0;
    h.modal = 0;
    if h.page >= h.pages {
        return out.refuse(h.nonce, 2);
    }
    let (w, height) = (h.width, h.height);
    let mut nodes = [Node::EMPTY; 16];
    let mut count = 1;
    nodes[0] = node(1, Role::Window, "Inspector", rect(0, 0, w, height))?;
    nodes[0].parent = 0;
    let mut add = |n: Node| -> Result<(), a1::Error> {
        if count == nodes.len() {
            return Err(a1::Error::Bounds);
        }
        nodes[count] = n;
        count += 1;
        Ok(())
    };
    if h.page == 0 {
        for (id, name, page, y) in [
            (2, "Inspector controls", 1, 0),
            (3, "More controls", 2, 20),
            (
                4,
                "Current rows and selection",
                if reader { 3 } else { 2 },
                64,
            ),
            (
                5,
                if reader {
                    "Private source viewport"
                } else {
                    "Settings and permissions"
                },
                if reader { 4 } else { 3 },
                height - 10,
            ),
        ] {
            let mut n = node(
                id,
                Role::Menu,
                name,
                rect(0, y, w, if y == height - 10 { 10 } else { 16 }),
            )?;
            n.actions = 16;
            n.value = Value::Number(page);
            add(n)?;
        }
        let mut n = node(6, Role::Label, "Inspector mode", rect(0, 40, w, 16))?;
        n.value = Value::Number(if reader { 1 } else { 0 });
        add(n)?;
    } else if (!reader && h.page == 1) || (reader && matches!(h.page, 1 | 2)) {
        let (start, end) = if !reader {
            (0, 14)
        } else if h.page == 1 {
            (0, 9)
        } else {
            (9, 18)
        };
        for index in start..end {
            let id = if reader {
                201 + index as u16
            } else {
                16 + index as u16
            };
            let name = if reader {
                READER_NAMES[index]
            } else {
                STATS_NAMES[index]
            };
            let Some(area) = bounds(id, reader, w, height, consumer.selected()) else {
                continue;
            };
            if area.width == 0 || area.y + area.height > height {
                continue;
            }
            let enabled = if reader {
                consumer.control_enabled(id)
            } else {
                stats_enabled(model, id - 15)
            };
            let protected = reader && id == 213;
            let mut n = node(id, Role::Button, name, area)?;
            n.flags = u8::from(!enabled) | if protected { 2 } else { 0 };
            n.actions = u8::from(enabled && !protected);
            add(n)?;
        }
    } else if !reader && h.page == 2 {
        if let Some(s) = model.snapshot() {
            for row in 0..6 {
                let id = 100 + row;
                let Some(area) = bounds(id, false, w, height, 0) else {
                    continue;
                };
                let words = s.row(row as u8).unwrap();
                let state = words[0] & 255;
                let name = if state == 0 {
                    "Absent resource row"
                } else if state == 3 {
                    "Unobserved resource row"
                } else {
                    core::str::from_utf8(crate::role(words[0] >> 8)).unwrap_or("Resource row")
                };
                let mut n = node(id, Role::ListItem, name, area)?;
                n.flags = u8::from(state == 0);
                n.actions = u8::from(state != 0) * 4;
                n.value = Value::Number(i64::from(row as u8 == model.selected()));
                add(n)?;
            }
            if let Some(words) = s.row(model.selected()) {
                for (i, (name, value)) in [
                    ("CPU used", words[4]),
                    ("CPU limit", words[5]),
                    ("Frames used", words[6]),
                    ("Frames limit", words[7]),
                ]
                .into_iter()
                .enumerate()
                {
                    let y = 128 + (i as u16 / 2) * 10;
                    if y + 8 > height {
                        continue;
                    }
                    let mut n = node(120 + i as u16, Role::Label, name, rect(0, y, w, 8))?;
                    n.label = if matches!(words[0] & 255, 1 | 2) {
                        number_label(name, value)?
                    } else {
                        Label::new("Counters unobserved")?
                    };
                    add(n)?;
                }
            }
        } else {
            add(node(
                7,
                Role::Label,
                "Resource data unavailable",
                rect(0, 64, w, 16),
            )?)?;
        }
    } else if !reader && h.page == 3 {
        if let Some(s) = model.snapshot() {
            for (i, (name, field, x, y)) in [
                ("Layer", 120, 2, 150),
                ("Scale code", 121, 62, 150),
                ("High contrast", 122, 122, 150),
                ("Thick outline", 123, 238, 150),
                ("File lease bits", 124, 2, 160),
                ("Phase", 125, 238, 160),
            ]
            .into_iter()
            .enumerate()
            {
                if y + 8 > height || x >= w {
                    continue;
                }
                let mut n = node(
                    140 + i as u16,
                    Role::Label,
                    name,
                    rect(x, y, (w - x).min(96), 8),
                )?;
                n.label = number_label(name, s.word(field).unwrap())?;
                add(n)?;
            }
        }
    } else if reader && h.page == 3 {
        // The consumer owns these controls, but their rendered provider labels
        // keep their provenance. Publish IDs/state only, never proxy their bytes.
        if let Some(s) = consumer.snapshot()
            && consumer.text_viewport().1 == 0
        {
            for (index, source) in s.nodes().iter().enumerate() {
                let id = 300 + index as u16;
                let Some(area) = bounds(id, true, w, height, consumer.selected()) else {
                    continue;
                };
                let mut n = node(
                    id,
                    Role::ListItem,
                    "Source label requires original scope",
                    area,
                )?;
                n.flags = u8::from(!consumer.control_enabled(id));
                n.actions = if n.flags == 0 { 4 } else { 0 };
                n.value = Value::Number(i64::from(source.local));
                add(n)?;
            }
        }
    } else if reader && h.page == 4 {
        let context = consumer.context();
        for (i, (name, value)) in [
            ("Source slot", context.source as u64),
            ("Authorized scope bits", u64::from(context.scopes)),
            ("Selected node index", u64::from(consumer.selected())),
            (
                "Private range viewport active",
                u64::from(consumer.text_viewport().1 != 0),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let y = 64 + i as u16 * 10;
            if y + 8 > height.saturating_sub(20) {
                continue;
            }
            let mut n = node(160 + i as u16, Role::Label, name, rect(0, y, w, 8))?;
            n.label = number_label(name, value)?;
            add(n)?;
        }
        add(node(
            166,
            Role::Label,
            "Nested names and text retain original scope",
            rect(0, height - 20, w, 8),
        )?)?;
        add(node(
            167,
            Role::Label,
            "Assistive focus differs from keyboard focus",
            rect(0, height - 10, w, 8),
        )?)?;
    }
    if let Some(focus) = focus.filter(|f| nodes[..count].iter().any(|n| n.local == *f)) {
        h.keyboard = focus;
    }
    out.begin(h, &nodes[..count])
}

/// Local focus over Inspector's visible enabled controls. It never traverses
/// protected Confirm, and never turns a self node into source authority.
pub fn next_control(
    model: &Model,
    consumer: &Consumer,
    current: Option<u16>,
    forward: bool,
    width: u16,
    height: u16,
) -> Option<u16> {
    if !(120..=320).contains(&width) || !(80..=200).contains(&height) {
        return None;
    }
    let mut controls = [0u16; 36];
    let mut count = 0;
    let reader = consumer.active();
    let ranges = if reader {
        [(201, 219), (300, 316)]
    } else {
        [(16, 30), (100, 106)]
    };
    for (start, end) in ranges {
        for id in start..end {
            if visible_control(model, consumer, id, width, height).is_some() {
                controls[count] = id;
                count += 1;
            }
        }
    }
    if count == 0 {
        return None;
    }
    let position = current.and_then(|id| controls[..count].iter().position(|v| *v == id));
    Some(
        controls[match (position, forward) {
            (Some(i), true) => (i + 1) % count,
            (Some(i), false) => (i + count - 1) % count,
            (None, true) => 0,
            (None, false) => count - 1,
        }],
    )
}
/// Current logical geometry is part of local input eligibility. In particular,
/// a row hidden by shrink or replaced by a text viewport cannot retain Enter.
pub fn visible_control(
    model: &Model,
    consumer: &Consumer,
    id: u16,
    width: u16,
    height: u16,
) -> Option<u16> {
    if !(120..=320).contains(&width) || !(80..=200).contains(&height) {
        return None;
    }
    let action = ordinary_control(model, consumer, id)?;
    bounds(id, consumer.active(), width, height, consumer.selected())
        .is_some_and(|r| r.width > 0 && r.y + r.height <= height)
        .then_some(action)
}
/// This cue changes the actual own surface, requiring another normal Present.
pub fn render_focus<P: Pixels>(
    p: &mut P,
    consumer: &Consumer,
    id: u16,
) -> Result<(), GraphicsError> {
    let (w, h) = p.dimensions();
    if w == 0 || h == 0 || w > 320 || h > 200 {
        return Err(GraphicsError::Geometry);
    }
    if let Some(area) = bounds(
        id,
        consumer.active(),
        w as u16,
        h as u16,
        consumer.selected(),
    ) {
        let (x, y, width, height) = (
            usize::from(area.x),
            usize::from(area.y),
            usize::from(area.width),
            usize::from(area.height),
        );
        if width > 0 && height > 0 && x + width <= w && y + height <= h {
            let mut c = Canvas::new(p);
            c.rect(x, y, width, 1, ACCENT)?;
            c.rect(x, y + height - 1, width, 1, ACCENT)?;
            c.rect(x, y, 1, height, ACCENT)?;
            c.rect(x + width - 1, y, 1, height, ACCENT)?;
        }
    }
    if h >= 8 && w >= 6 {
        let name = if consumer.active() {
            (201..219)
                .contains(&id)
                .then(|| READER_NAMES[usize::from(id - 201)])
        } else {
            (16..30)
                .contains(&id)
                .then(|| STATS_NAMES[usize::from(id - 16)])
        };
        let text = name.unwrap_or("Resource or source row").as_bytes();
        let mut c = Canvas::new(p);
        c.rect(0, h - 8, w, 8, PANEL)?;
        c.text_exact(0, h - 8, &text[..text.len().min(w / 6)], INK)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
