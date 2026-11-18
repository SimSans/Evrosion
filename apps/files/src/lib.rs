//! Bounded native Files browser over dynamic generated namespace metadata.
//! A selected object ID is descriptive; opening contents asks Root's picker.
#![no_std]
#![forbid(unsafe_code)]
pub mod semantic;

use ev_graphics::{
    ACCENT, BACKGROUND, Canvas, Color, DANGER, Error as GraphicsError, INK, MUTED, PANEL, Pixels,
};
use ev_userspace_contract::workspace::{
    Deadline, Entry, EntryState, Kind, Name, ObjectId, Operation, Outcome,
};
use ev_workspace_client::{
    namespace::{Client, Link, State as ClientState},
    ui::{Command, Event, Navigation, State as AppState},
};

pub const ROWS: usize = 8;
pub const ROOT: ObjectId = ObjectId {
    slot: 0,
    generation: 1,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    Bootstrap,
    Limits,
    Roles,
}
/// Syntax/shape only; actual grants and fixed mappings require Kernel V5
/// admission. Parsed process/handle scalars cannot create that authority.
pub struct Profile {
    pub process: u64,
    pub registered_incarnation: u64,
    pub handles: [u64; 7],
}
impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let bootstrap =
            ev_userspace_contract::Bootstrap::parse(bytes).map_err(|_| ProfileError::Bootstrap)?;
        let limits: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(bytes[40 + i * 8..48 + i * 8].try_into().unwrap())
        });
        if limits != ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[2] {
            return Err(ProfileError::Limits);
        }
        if bootstrap.grants().count() != 7 {
            return Err(ProfileError::Roles);
        }
        let specs = [(1, 7), (2, 8), (2, 8), (2, 272), (1, 7), (2, 272), (2, 8)];
        let mut handles = [0; 7];
        for (i, g) in bootstrap.grants().enumerate() {
            if g.selector != i as u64 + 1
                || (g.kind, g.rights) != specs[i]
                || handles[..i].contains(&g.handle)
            {
                return Err(ProfileError::Roles);
            }
            handles[i] = g.handle;
        }
        Ok(Self {
            process: bootstrap.process(),
            registered_incarnation: bootstrap.incarnation(),
            handles,
        })
    }
}
pub mod action {
    pub const UP: u16 = 1;
    pub const FOLDER: u16 = 2;
    pub const TEXT: u16 = 3;
    pub const RENAME: u16 = 4;
    pub const MOVE: u16 = 5;
    pub const TRASH: u16 = 6;
    pub const RESTORE: u16 = 7;
    pub const OPEN: u16 = 8;
    pub const PREV: u16 = 9;
    pub const NEXT: u16 = 10;
    pub const APPLY: u16 = 11;
    pub const CANCEL: u16 = 12;
    pub const REFRESH: u16 = 13;
    pub const SELECT: u16 = 100;
    pub const ENTER: u16 = 200;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Browse,
    NewFile,
    NewFolder,
    Rename(ObjectId),
    Move {
        object: ObjectId,
        name: Name,
        restore: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Loading,
    Ready,
    Editing,
    Moving,
    Changed,
    Refused,
    Full,
    Name,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    Ready,
    ConfirmDiscard,
    RecoveryRequired,
}
#[derive(Clone, Copy)]
enum Load {
    Inspect,
    List(u16),
}
pub struct Browser {
    directory: ObjectId,
    parent: ObjectId,
    namespace_revision: u64,
    rows: [Option<Entry>; ROWS],
    count: usize,
    selected: usize,
    starts: [u16; 32],
    page: usize,
    next: Option<u16>,
    load: Option<Load>,
    mode: Mode,
    name: [u8; 96],
    name_len: usize,
    select_all: bool,
    status: Status,
}
impl Default for Browser {
    fn default() -> Self {
        Self::new()
    }
}
impl Browser {
    pub const fn new() -> Self {
        Self {
            directory: ROOT,
            parent: ROOT,
            namespace_revision: 0,
            rows: [None; ROWS],
            count: 0,
            selected: 0,
            starts: [0; 32],
            page: 0,
            next: None,
            load: Some(Load::Inspect),
            mode: Mode::Browse,
            name: [0; 96],
            name_len: 0,
            select_all: false,
            status: Status::Loading,
        }
    }
    pub const fn directory(&self) -> ObjectId {
        self.directory
    }
    pub const fn status(&self) -> Status {
        self.status
    }
    pub const fn mode(&self) -> Mode {
        self.mode
    }
    /// A partially entered name or unsubmitted move is user work even before
    /// any namespace mutation. Refuse ordinary close without clearing it.
    pub fn close(&self, discard: bool) -> Close {
        if self.status == Status::Uncertain {
            Close::RecoveryRequired
        } else if !matches!(self.mode, Mode::Browse) && !discard {
            Close::ConfirmDiscard
        } else {
            Close::Ready
        }
    }
    pub fn app_state(&self) -> AppState {
        match self.status {
            Status::Uncertain => AppState::Uncertain,
            _ if !matches!(self.mode, Mode::Browse) => AppState::Dirty,
            Status::Loading => AppState::Loading,
            Status::Changed => AppState::Conflict,
            _ => AppState::Saved,
        }
    }
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        self.rows[..self.count].iter().flatten().copied()
    }
    pub fn selected(&self) -> Option<Entry> {
        self.rows.get(self.selected).copied().flatten()
    }
    pub const fn selected_index(&self) -> usize {
        self.selected
    }
    pub const fn has_previous_page(&self) -> bool {
        self.page > 0
    }
    pub fn has_next_page(&self) -> bool {
        self.next.is_some() && self.page + 1 < self.starts.len()
    }
    pub fn editing_name(&self) -> bool {
        self.input_mode()
    }
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).expect("inserted scalar UTF8")
    }
    pub fn loading(&self) -> bool {
        self.load.is_some()
    }
    pub fn refresh(&mut self) {
        if self.status != Status::Uncertain {
            self.load = Some(Load::Inspect);
            self.status = Status::Loading;
        }
    }
    fn switch(&mut self, directory: ObjectId) {
        self.directory = directory;
        self.page = 0;
        self.starts = [0; 32];
        self.refresh();
    }
    fn failed(&mut self, outcome: Outcome) {
        self.load = None;
        self.status = match outcome {
            Outcome::Conflict | Outcome::Stale => Status::Changed,
            Outcome::NoSpace => Status::Full,
            Outcome::Accepted | Outcome::Uncertain | Outcome::Corrupt => Status::Uncertain,
            _ => Status::Refused,
        };
    }
    fn input_mode(&self) -> bool {
        matches!(self.mode, Mode::NewFile | Mode::NewFolder | Mode::Rename(_))
    }
    fn clear_input(&mut self) {
        self.name.fill(0);
        self.name_len = 0;
        self.select_all = false;
    }
    fn input(&mut self, c: char) {
        if !self.input_mode() || c.is_control() || matches!(c, '/' | '\\') {
            return;
        }
        let mut bytes = [0; 4];
        let text = c.encode_utf8(&mut bytes);
        if self.select_all {
            self.clear_input();
        }
        if self.name_len + text.len() > 96 {
            self.status = Status::Name;
            return;
        }
        self.name[self.name_len..self.name_len + text.len()].copy_from_slice(text.as_bytes());
        self.name_len += text.len();
        self.status = Status::Editing;
    }
    fn backspace(&mut self) {
        if self.select_all {
            self.clear_input();
            return;
        }
        if let Some((at, _)) = self.name().char_indices().next_back() {
            self.name[at..self.name_len].fill(0);
            self.name_len = at;
        }
    }
    fn rename(&mut self) {
        if let Some(entry) = self.selected() {
            self.mode = Mode::Rename(entry.object);
            self.clear_input();
            self.name[..entry.name.as_bytes().len()].copy_from_slice(entry.name.as_bytes());
            self.name_len = entry.name.as_bytes().len();
            self.select_all = true;
            self.status = Status::Editing;
        }
    }
    /// One real metadata request per step, so queues, frames and visible entries
    /// remain bounded. A namespace revision change never mixes list snapshots.
    pub fn step<L: Link>(&mut self, client: &mut Client<L>, deadline: Deadline) {
        let Some(load) = self.load else {
            return;
        };
        let op = match load {
            Load::Inspect => Operation::Inspect {
                object: self.directory,
            },
            Load::List(cursor) => Operation::List {
                directory: self.directory,
                cursor,
                expected_namespace_revision: self.namespace_revision,
            },
        };
        let response = match client.issue(op, deadline) {
            Ok(r) => r,
            Err(_) => {
                self.load = None;
                self.status = if client.state() == ClientState::Uncertain {
                    Status::Uncertain
                } else {
                    Status::Refused
                };
                return;
            }
        };
        if client.state() == ClientState::Uncertain {
            self.load = None;
            self.status = Status::Uncertain;
            return;
        }
        match (load, response.outcome) {
            (Load::Inspect, Outcome::Completed) => {
                let Some(entry) = response
                    .entry
                    .filter(|e| e.object == self.directory && e.kind == Kind::Directory)
                else {
                    self.failed(Outcome::Corrupt);
                    return;
                };
                self.parent = entry.parent;
                self.namespace_revision = response.namespace_revision;
                self.rows = [None; ROWS];
                self.count = 0;
                self.selected = 0;
                self.next = None;
                self.load = Some(Load::List(self.starts[self.page]));
            }
            (Load::List(cursor), Outcome::Completed) => {
                let Some(entry) = response
                    .entry
                    .filter(|e| e.parent == self.directory && e.object.slot > cursor)
                else {
                    self.failed(Outcome::Corrupt);
                    return;
                };
                if self.count >= ROWS || response.next_cursor != Some(entry.object.slot) {
                    self.failed(Outcome::Corrupt);
                    return;
                }
                self.rows[self.count] = Some(entry);
                self.count += 1;
                self.next = response.next_cursor;
                if self.count == ROWS {
                    self.load = None;
                    self.status = if matches!(self.mode, Mode::Move { .. }) {
                        Status::Moving
                    } else {
                        Status::Ready
                    };
                } else {
                    self.load = Some(Load::List(entry.object.slot));
                }
            }
            (Load::List(_), Outcome::End) => {
                self.load = None;
                self.next = None;
                self.status = if matches!(self.mode, Mode::Move { .. }) {
                    Status::Moving
                } else {
                    Status::Ready
                };
            }
            (_, outcome) => self.failed(outcome),
        }
    }
    fn mutate<L: Link>(
        &mut self,
        client: &mut Client<L>,
        operation: Operation,
        deadline: Deadline,
    ) {
        match client.issue(operation, deadline) {
            Ok(r) if client.state() == ClientState::Ready && r.outcome == Outcome::Completed => {
                self.mode = Mode::Browse;
                self.clear_input();
                self.refresh();
            }
            Ok(r) => {
                if client.state() == ClientState::Uncertain {
                    self.status = Status::Uncertain;
                } else {
                    self.failed(r.outcome);
                }
            }
            Err(_) => {
                self.status = if client.state() == ClientState::Uncertain {
                    Status::Uncertain
                } else {
                    Status::Refused
                }
            }
        }
    }
    fn apply<L: Link>(&mut self, client: &mut Client<L>, deadline: Deadline) {
        let expected_namespace_revision = self.namespace_revision;
        let operation = match self.mode {
            Mode::NewFile | Mode::NewFolder | Mode::Rename(_) => {
                let Ok(name) = Name::new(self.name().as_bytes()) else {
                    self.status = Status::Name;
                    return;
                };
                match self.mode {
                    Mode::NewFile | Mode::NewFolder => Operation::Create {
                        directory: self.directory,
                        kind: if self.mode == Mode::NewFile {
                            Kind::File
                        } else {
                            Kind::Directory
                        },
                        name,
                        expected_namespace_revision,
                    },
                    Mode::Rename(object) => Operation::Rename {
                        object,
                        name,
                        expected_namespace_revision,
                    },
                    _ => unreachable!(),
                }
            }
            Mode::Move {
                object,
                name,
                restore,
            } => {
                if restore {
                    Operation::Restore {
                        object,
                        destination: self.directory,
                        name,
                        expected_namespace_revision,
                    }
                } else {
                    Operation::Move {
                        object,
                        destination: self.directory,
                        expected_namespace_revision,
                    }
                }
            }
            Mode::Browse => return,
        };
        self.mutate(client, operation, deadline);
    }
    fn enter(&mut self) -> Option<Event> {
        let entry = self.selected()?;
        if entry.kind == Kind::Directory {
            self.switch(entry.object);
            None
        } else {
            Some(Event::Open)
        }
    }
    pub fn command<L: Link>(
        &mut self,
        client: &mut Client<L>,
        command: Command,
        deadline: Deadline,
    ) -> Option<Event> {
        if self.status == Status::Uncertain || client.state() == ClientState::Uncertain {
            return None;
        }
        if let Command::Focus(_)
        | Command::Resize { .. }
        | Command::ScenePart { .. }
        | Command::Configure { .. } = command
        {
            return None;
        }
        if self.loading() {
            return None;
        }
        // Name editing cannot navigate to another directory or change the row
        // while retaining a rename's original object identity.
        if self.input_mode()
            && (matches!(
                command,
                Command::Navigate {
                    key: Navigation::Left
                        | Navigation::Right
                        | Navigation::Up
                        | Navigation::Down
                        | Navigation::Home
                        | Navigation::End,
                    ..
                } | Command::Scroll(_)
            ) || matches!(command, Command::Activate(node) if
                (action::SELECT..action::SELECT+ROWS as u16).contains(&node)
                || (action::ENTER..action::ENTER+ROWS as u16).contains(&node)
                || matches!(node,action::UP|action::OPEN|action::PREV|action::NEXT|action::MOVE|action::TRASH|action::RESTORE|action::RENAME)))
        {
            return None;
        }
        if let Command::Insert(c) = command {
            if matches!(c, '\n' | '\r') {
                if self.input_mode() || matches!(self.mode, Mode::Move { .. }) {
                    self.apply(client, deadline);
                    return None;
                }
                return self.enter();
            }
            self.input(c);
            return None;
        }
        match command {
            Command::SelectAll if self.input_mode() => self.select_all = true,
            Command::Navigate {
                key: Navigation::Backspace,
                ..
            } if self.input_mode() => self.backspace(),
            Command::Navigate {
                key: Navigation::Up,
                ..
            } => self.selected = self.selected.saturating_sub(1),
            Command::Navigate {
                key: Navigation::Down,
                ..
            } => self.selected = (self.selected + 1).min(self.count.saturating_sub(1)),
            Command::Scroll(lines) => {
                if lines < 0 {
                    self.selected = self.selected.saturating_sub(lines.unsigned_abs() as usize);
                } else {
                    self.selected = self
                        .selected
                        .saturating_add(lines as usize)
                        .min(self.count.saturating_sub(1));
                }
            }
            Command::Navigate {
                key: Navigation::Home,
                ..
            } => self.selected = 0,
            Command::Navigate {
                key: Navigation::End,
                ..
            } => self.selected = self.count.saturating_sub(1),
            Command::Navigate {
                key: Navigation::Left | Navigation::Backspace,
                ..
            }
            | Command::Activate(action::UP) => {
                if self.directory != ROOT {
                    self.switch(self.parent);
                }
            }
            Command::Navigate {
                key: Navigation::Right,
                ..
            } => return self.enter(),
            Command::Save | Command::Activate(action::APPLY) => self.apply(client, deadline),
            Command::Activate(action::FOLDER) | Command::Activate(action::TEXT) => {
                self.mode = if command == Command::Activate(action::FOLDER) {
                    Mode::NewFolder
                } else {
                    Mode::NewFile
                };
                self.clear_input();
                self.status = Status::Editing;
            }
            Command::Activate(action::RENAME) => self.rename(),
            Command::Activate(action::MOVE) => {
                if matches!(self.mode, Mode::Move { .. }) {
                    self.apply(client, deadline);
                } else if let Some(e) = self.selected() {
                    self.mode = Mode::Move {
                        object: e.object,
                        name: e.name,
                        restore: e.state == EntryState::Trashed,
                    };
                    self.status = Status::Moving;
                }
            }
            Command::Activate(action::TRASH) => {
                if let Some(e) = self.selected() {
                    self.mutate(
                        client,
                        Operation::Trash {
                            object: e.object,
                            expected_namespace_revision: self.namespace_revision,
                        },
                        deadline,
                    );
                }
            }
            Command::Activate(action::RESTORE) => {
                if let Some(e) = self.selected() {
                    self.mutate(
                        client,
                        Operation::Restore {
                            object: e.object,
                            destination: self.directory,
                            name: e.name,
                            expected_namespace_revision: self.namespace_revision,
                        },
                        deadline,
                    );
                }
            }
            Command::Activate(action::OPEN) => return self.enter(),
            Command::Activate(action::PREV) if self.page > 0 => {
                self.page -= 1;
                self.refresh();
            }
            Command::Activate(action::NEXT) if self.page + 1 < self.starts.len() => {
                if let Some(cursor) = self.next {
                    self.page += 1;
                    self.starts[self.page] = cursor;
                    self.refresh();
                }
            }
            Command::Activate(action::CANCEL) => {
                self.mode = Mode::Browse;
                self.clear_input();
                self.status = Status::Ready;
            }
            Command::Activate(action::REFRESH) => self.refresh(),
            Command::Activate(node)
                if (action::SELECT..action::SELECT + ROWS as u16).contains(&node) =>
            {
                let row = usize::from(node - action::SELECT);
                if row < self.count {
                    self.selected = row;
                }
            }
            Command::Activate(node)
                if (action::ENTER..action::ENTER + ROWS as u16).contains(&node) =>
            {
                let row = usize::from(node - action::ENTER);
                if row < self.count {
                    self.selected = row;
                    return self.enter();
                }
            }
            _ => (),
        }
        None
    }
}
fn label<P: Pixels>(
    p: &mut P,
    x: usize,
    y: usize,
    text: &str,
    color: Color,
) -> Result<(), GraphicsError> {
    let (w, h) = p.dimensions();
    if x >= w || y + 7 > h {
        return Ok(());
    }
    for (i, c) in text.chars().take((w - x) / 6).enumerate() {
        let byte = if c.is_ascii_graphic() || c == ' ' {
            c as u8
        } else {
            b'?'
        };
        Canvas::new(p).text_exact(x + i * 6, y, &[byte], color)?;
    }
    Ok(())
}
pub fn render<P: Pixels>(
    pixels: &mut P,
    browser: &Browser,
    focused: bool,
) -> Result<(), GraphicsError> {
    let (w, h) = pixels.dimensions();
    if w == 0 || h == 0 || w > 320 || h > 200 {
        return Err(GraphicsError::Geometry);
    }
    Canvas::new(pixels).fill(PANEL)?;
    let labels = [
        "Up", "Folder", "Text", "Rename", "Move", "Trash", "Restore", "Open", "Prev", "Next",
    ];
    let cell = w / 5;
    for (i, text) in labels.into_iter().enumerate() {
        let x = i % 5 * cell;
        let y = i / 5 * 20;
        if cell > 1 && y < h {
            Canvas::new(pixels).rect(x, y, cell - 1, (h - y).min(19), BACKGROUND)?;
            label(pixels, x + 2, y + 6, text, INK)?;
        }
    }
    if browser.input_mode() {
        let mut shown = [0u8; 96];
        let mut length = 0;
        for c in browser.name().chars().take(w.saturating_sub(124) / 6) {
            shown[length] = if c.is_ascii_graphic() || c == ' ' {
                c as u8
            } else {
                b'?'
            };
            length += 1;
        }
        label(
            pixels,
            2,
            46,
            core::str::from_utf8(&shown[..length]).unwrap(),
            if focused { ACCENT } else { MUTED },
        )?;
    } else if matches!(browser.mode, Mode::Move { .. }) {
        label(pixels, 2, 46, "Choose folder, Move applies here", ACCENT)?;
    } else {
        label(
            pixels,
            2,
            46,
            if browser.directory == ROOT {
                "Workspace"
            } else {
                "Folder"
            },
            MUTED,
        )?;
    }
    if browser.input_mode() || matches!(browser.mode, Mode::Move { .. }) {
        for (offset, text) in [(120, "Apply"), (60, "Cancel")] {
            if w >= offset && h >= 60 {
                Canvas::new(pixels).rect(w - offset, 40, 59, 19, BACKGROUND)?;
                label(pixels, w - offset + 2, 46, text, INK)?;
            }
        }
    }
    let visible = h.saturating_sub(80) / 10;
    for (index, entry) in browser.entries().take(visible.min(ROWS)).enumerate() {
        let y = 68 + index * 10;
        if index == browser.selected && w > 0 && y < h {
            Canvas::new(pixels).rect(
                0,
                y,
                w,
                (h - y).min(9),
                if focused { ACCENT } else { BACKGROUND },
            )?;
        }
        label(
            pixels,
            2,
            y + 1,
            match (
                index == browser.selected,
                entry.state == EntryState::Trashed,
                entry.kind == Kind::Directory,
            ) {
                (true, true, _) => ">T",
                (true, false, true) => ">D",
                (true, false, false) => "> ",
                (false, true, _) => " T",
                (false, false, true) => " D",
                _ => "  ",
            },
            MUTED,
        )?;
        label(
            pixels,
            14,
            y + 1,
            entry.name.as_str(),
            if index == browser.selected && focused {
                BACKGROUND
            } else {
                INK
            },
        )?;
    }
    if h >= 10 {
        Canvas::new(pixels).rect(0, h - 10, w, 10, BACKGROUND)?;
        label(
            pixels,
            2,
            h - 8,
            match browser.status {
                Status::Loading => "Loading...",
                Status::Ready => "Ready",
                Status::Editing => "Name: Enter applies",
                Status::Moving => "Choose destination folder",
                Status::Changed => "Changed elsewhere - Refresh",
                Status::Refused => "Operation refused",
                Status::Full => "Workspace limit reached",
                Status::Name => "Use a valid name (up to96 bytes)",
                Status::Uncertain => "Recovery required",
            },
            if browser.status == Status::Uncertain {
                DANGER
            } else {
                MUTED
            },
        )?;
    }
    if w >= 120 && h >= 10 {
        Canvas::new(pixels).rect(w - 60, h - 10, 60, 10, BACKGROUND)?;
        label(pixels, w - 58, h - 8, "Refresh", INK)?;
    }
    Ok(())
}
/// Logical action map for Root's focus/hit routing; no packet claims focus.
pub fn hit_test(width: usize, height: usize, x: usize, y: usize) -> Option<u16> {
    if width >= 120
        && height >= 10
        && x < width
        && y < height
        && x >= width - 60
        && y >= height - 10
    {
        return Some(action::REFRESH);
    }

    if width == 0 || height == 0 || width > 320 || height > 200 || x >= width || y >= height {
        return None;
    }
    if y < 40 {
        let cell = width / 5;
        if cell == 0 {
            return None;
        }
        let column = x / cell;
        if column >= 5 {
            return None;
        }
        return Some((y / 20 * 5 + column + 1) as u16);
    }
    if (40..60).contains(&y) && width >= 120 {
        if x >= width - 60 {
            return Some(action::CANCEL);
        }
        if x >= width - 120 {
            return Some(action::APPLY);
        }
    }
    if (68..148.min(height.saturating_sub(10))).contains(&y) {
        return Some(action::SELECT + ((y - 68) / 10) as u16);
    }
    None
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
