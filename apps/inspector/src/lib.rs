//! Root-fed Inspector data and ordinary action intents. Metrics and row IDs
//! never grant ProcessCONTROL, lookup authority, permission or owner approval.
#![no_std]
#![forbid(unsafe_code)]
pub mod consumer;
pub mod presentation;
pub mod self_tree;
use ev_graphics::{
    ACCENT, BACKGROUND, Canvas, Color, Error as GraphicsError, INK, MUTED, PANEL, Pixels,
};
use ev_workspace_client::ui::{Event, inspector as field};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Field,
    Order,
    Duplicate,
    Value,
    Incomplete,
    Profile,
}
pub struct Profile {
    pub process: u64,
    pub incarnation: u64,
    pub handles: [u64; 6],
}
impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let b = ev_userspace_contract::Bootstrap::parse(bytes).map_err(|_| Error::Profile)?;
        let limits: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(bytes[40 + i * 8..48 + i * 8].try_into().unwrap())
        });
        if limits != ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[2]
            || b.grants().count() != 6
        {
            return Err(Error::Profile);
        }
        let specs = [(1, 7), (2, 8), (2, 8), (2, 272), (1, 7), (2, 272)];
        let mut handles = [0; 6];
        for (i, g) in b.grants().enumerate() {
            if g.selector != i as u64 + 1
                || (g.kind, g.rights) != specs[i]
                || handles[..i].contains(&g.handle)
            {
                return Err(Error::Profile);
            }
            handles[i] = g.handle;
        }
        Ok(Self {
            process: b.process(),
            incarnation: b.incarnation(),
            handles,
        })
    }
}
pub struct Snapshot {
    words: [u64; 128],
}
impl Snapshot {
    pub fn view(&self) -> u32 {
        self.words[0] as u32
    }
    pub fn word(&self, field: u8) -> Option<u64> {
        if field::required(field) {
            Some(self.words[usize::from(field)])
        } else {
            None
        }
    }
    pub fn row(&self, row: u8) -> Option<[u64; 12]> {
        if row >= 6 {
            None
        } else {
            Some(core::array::from_fn(|m| {
                self.words[1 + row as usize * 12 + m]
            }))
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if self.words[0] == 0
            || self.words[0] >= u64::from(u32::MAX)
            || self.words[73] > 1
            || self.words[74] != 12
            || self.words[75] > self.words[76]
            || !(1..=3).contains(&self.words[120])
            || !(1..=4).contains(&self.words[121])
            || self.words[122] > 1
            || self.words[123] > 1
            || self.words[124] > 255
            || self.words[125] > 3
        {
            return Err(Error::Value);
        }
        for i in 0..4 {
            if (self.words[124] >> (i * 2)) & 3 == 2 {
                return Err(Error::Value);
            }
        }
        let mut roles = 0u16;
        for r in 0..6 {
            let row = self.row(r).unwrap();
            let state = row[0] & 255;
            let role = (row[0] >> 8) & 255;
            if row[0] >> 16 != 0 || state > 3 || role > 11 {
                return Err(Error::Value);
            }
            if state == 0 {
                if row.iter().any(|v| *v != 0) {
                    return Err(Error::Value);
                }
                continue;
            }
            if roles & (1 << role) != 0 {
                return Err(Error::Value);
            }
            roles |= 1 << role;
            if matches!(state, 1 | 2)
                && ([row[1], row[2]].iter().any(|v| matches!(*v, 0 | u64::MAX))
                    || row[3] == u64::MAX)
            {
                return Err(Error::Value);
            }
        }
        Ok(())
    }
}
pub struct Model {
    published: Option<Snapshot>,
    staged: [u64; 128],
    seen: [u8; 128],
    collecting: bool,
    rejected: bool,
    selected: u8,
}
impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}
impl Model {
    pub const fn new() -> Self {
        Self {
            published: None,
            staged: [0; 128],
            seen: [0; 128],
            collecting: false,
            rejected: false,
            selected: 0,
        }
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.published.as_ref()
    }
    /// A throttled repaint must use a complete quiet sample. Drawing while a
    /// newer stream is staged can otherwise freeze its temporary progress
    /// footer until the next throttled frame despite valid committed metrics.
    pub fn paintable(&self, expected_view: u64) -> bool {
        !self.collecting
            && self
                .snapshot()
                .is_some_and(|s| u64::from(s.view()) == expected_view)
    }
    pub const fn collecting(&self) -> bool {
        self.collecting
    }
    pub const fn rejected(&self) -> bool {
        self.rejected
    }
    fn reject(&mut self, error: Error) -> Result<bool, Error> {
        self.collecting = false;
        self.rejected = true;
        Err(error)
    }
    /// Stages all full64 words privately. Only exact complete commit replaces
    /// the displayed snapshot; defaults and partially received data stay hidden.
    pub fn put(&mut self, field: u8, high: bool, word: u32) -> Result<bool, Error> {
        if field > 127 || (!field::required(field) && field != field::COMMIT) {
            return self.reject(Error::Field);
        }
        if field == 0 && !high {
            if matches!(word, 0 | u32::MAX)
                || self.published.as_ref().is_some_and(|p| word <= p.view())
            {
                return self.reject(Error::Order);
            }
            self.staged = [0; 128];
            self.seen = [0; 128];
            self.collecting = true;
            self.rejected = false;
        }
        if !self.collecting {
            return self.reject(Error::Order);
        }
        let index = usize::from(field);
        let mask = if high { 2 } else { 1 };
        if self.seen[index] & mask != 0 {
            return self.reject(Error::Duplicate);
        }
        if field != 0 && self.seen[0] != 3 {
            return self.reject(Error::Order);
        }
        self.staged[index] |= u64::from(word) << (if high { 32 } else { 0 });
        self.seen[index] |= mask;
        if field == 0 && high && word != 0 {
            return self.reject(Error::Value);
        }
        if field == field::COMMIT && self.seen[index] == 3 {
            if (0..128).any(|i| field::required(i as u8) && self.seen[i] != 3) {
                return self.reject(Error::Incomplete);
            }
            if self.staged[index] != self.staged[0] {
                return self.reject(Error::Order);
            }
            let next = Snapshot { words: self.staged };
            if let Err(e) = next.validate() {
                return self.reject(e);
            }
            self.published = Some(next);
            self.collecting = false;
            self.rejected = false;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn select(&mut self, row: u8) {
        if row < 6 {
            self.selected = row;
        }
    }
    pub const fn selected(&self) -> u8 {
        self.selected
    }
    pub fn action(&self, action: u8) -> Option<Event> {
        let snapshot = self.published.as_ref()?;
        if !(1..=13).contains(&action) {
            return None;
        }
        let row = if field::row_action(action) {
            let row = snapshot.row(self.selected)?;
            if row[0] & 255 == 0 {
                return None;
            }
            self.selected
        } else {
            0
        };
        Some(Event::InspectAction {
            action,
            row,
            view: snapshot.view(),
        })
    }
}
fn label<P: Pixels>(
    p: &mut P,
    x: usize,
    y: usize,
    text: &[u8],
    color: Color,
) -> Result<(), GraphicsError> {
    let (w, h) = p.dimensions();
    if x < w && y + 7 <= h {
        let n = text.len().min((w - x) / 6);
        Canvas::new(p).text_exact(x, y, &text[..n], color)?;
    }
    Ok(())
}
fn decimal(value: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut n = value;
    let mut at = 20;
    loop {
        at -= 1;
        out[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &out[at..]
}
fn metric<P: Pixels>(
    p: &mut P,
    y: usize,
    name: &[u8],
    used: u64,
    limit: u64,
) -> Result<(), GraphicsError> {
    let mut a = [0; 20];
    let mut b = [0; 20];
    label(p, 2, y, name, MUTED)?;
    let value = decimal(used, &mut a);
    label(p, 38, y, value, INK)?;
    let x = 38 + value.len() * 6;
    label(p, x, y, b"/", MUTED)?;
    label(p, x + 6, y, decimal(limit, &mut b), INK)
}
fn role(role: u64) -> &'static [u8] {
    use ev_userspace_contract::root_v5::graph::{CHILDREN, Child};
    if role == 0 {
        return b"Root";
    }
    let Some(child) = CHILDREN.get(role.saturating_sub(1) as usize) else {
        return b"Unknown";
    };
    match child {
        Child::Block => b"Block",
        Child::Workspace => b"Workspace",
        Child::Input => b"Input",
        Child::Display => b"Display",
        Child::Shell => b"Shell",
        Child::NetDriver => b"NetDriver",
        Child::NetService => b"NetService",
        Child::Files => b"Files",
        Child::EditorOne => b"Editor1",
        Child::EditorTwo => b"Editor2",
        Child::Inspector => b"Inspector",
    }
}
pub fn render<P: Pixels>(p: &mut P, model: &Model, focused: bool) -> Result<(), GraphicsError> {
    let (w, h) = p.dimensions();
    if w == 0 || h == 0 || w > 320 || h > 200 {
        return Err(GraphicsError::Geometry);
    }
    Canvas::new(p).fill(PANEL)?;
    let labels = [
        b"Refresh".as_slice(),
        b"Next",
        b"Prev",
        b"Focus",
        b"Stop",
        b"Restart",
        b"Revoke",
        b"Layer",
        b"Contrast",
        b"Outline",
    ];
    let cell = w / 5;
    for (i, text) in labels.into_iter().enumerate() {
        let x = i % 5 * cell;
        let y = i / 5 * 20;
        if cell > 1 && y < h {
            Canvas::new(p).rect(x, y, cell - 1, (h - y).min(19), BACKGROUND)?;
            label(p, x + 2, y + 6, text, INK)?;
        }
    }
    let cell = w / 4;
    for (i, text) in [
        b"Scale".as_slice(),
        b"Shutdown",
        b"Restart all",
        b"Assistive",
    ]
    .into_iter()
    .enumerate()
    {
        let x = i * cell;
        if cell > 1 && h > 40 {
            Canvas::new(p).rect(x, 40, cell - 1, (h - 40).min(19), BACKGROUND)?;
            label(p, x + 2, 46, text, INK)?;
        }
    }
    let Some(snapshot) = model.snapshot() else {
        label(p, 4, 72, b"Loading resource data", MUTED)?;
        return Ok(());
    };
    for row in 0..6 {
        let words = snapshot.row(row).unwrap();
        let y = 64 + row as usize * 10;
        if y + 9 > h.saturating_sub(40) {
            break;
        }
        if row == model.selected && focused {
            Canvas::new(p).rect(0, y, w, 9, ACCENT)?;
        }
        let state = words[0] & 255;
        label(
            p,
            2,
            y + 1,
            if state == 0 {
                b"Absent"
            } else {
                role(words[0] >> 8)
            },
            if row == model.selected && focused {
                BACKGROUND
            } else {
                INK
            },
        )?;
        label(
            p,
            98,
            y + 1,
            match state {
                0 => b"-",
                1 => b"Live",
                2 => b"Stopped",
                _ => b"Unobserved",
            },
            MUTED,
        )?;
    }
    if let Some(row) = snapshot.row(model.selected) {
        if matches!(row[0] & 255, 1 | 2) {
            metric(p, 128, b"CPU", row[4], row[5])?;
            metric(p, 138, b"Frame", row[6], row[7])?;
        } else {
            label(p, 2, 128, b"No observed counters", MUTED)?;
        }
    }
    let mut number = [0; 20];
    label(p, 2, 150, b"Layer", MUTED)?;
    label(p, 38, 150, decimal(snapshot.words[120], &mut number), INK)?;
    label(p, 62, 150, b"Scale", MUTED)?;
    label(p, 98, 150, decimal(snapshot.words[121], &mut number), INK)?;
    label(
        p,
        122,
        150,
        if snapshot.words[122] == 1 {
            b"Contrast on"
        } else {
            b"Contrast off"
        },
        MUTED,
    )?;
    if h >= 10 {
        for (index, (x, name)) in [
            (2, b"F:".as_slice()),
            (50, b"E1:"),
            (110, b"E2:"),
            (170, b"I:"),
        ]
        .into_iter()
        .enumerate()
        {
            label(p, x, 160, name, MUTED)?;
            label(
                p,
                x + name.len() * 6,
                160,
                match (snapshot.words[124] >> (index * 2)) & 3 {
                    0 => b"-",
                    1 => b"R",
                    _ => b"RW",
                },
                INK,
            )?;
        }
        label(
            p,
            238,
            150,
            if snapshot.words[123] == 1 {
                b"Thick"
            } else {
                b"Thin"
            },
            MUTED,
        )?;
        label(
            p,
            238,
            160,
            match snapshot.words[125] {
                0 => b"Boot",
                1 => b"Desktop",
                2 => b"Drain",
                _ => b"Offline",
            },
            MUTED,
        )?;
        label(
            p,
            2,
            h - 8,
            if model.rejected {
                b"Resource data unavailable - refresh"
            } else if model.collecting {
                b"Refreshing..."
            } else {
                b"Sampled resource data"
            },
            MUTED,
        )?;
    }
    Ok(())
}
pub fn hit_test(width: usize, height: usize, x: usize, y: usize) -> Option<u16> {
    if width == 0 || height == 0 || width > 320 || height > 200 || x >= width || y >= height {
        return None;
    }
    if y < 40 {
        let cell = width / 5;
        if cell > 0 && x / cell < 5 {
            return Some((y / 20 * 5 + x / cell + 1) as u16);
        }
    } else if y < 60 {
        let cell = width / 4;
        if cell > 0 && x / cell < 4 {
            return Some((11 + x / cell) as u16);
        }
    } else if (64..124.min(height.saturating_sub(40))).contains(&y) {
        return Some(100 + ((y - 64) / 10) as u16);
    }
    None
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
