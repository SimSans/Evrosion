//! Fresh owner requests only. A displayed state is not publisher/file authority;
//! Root must authenticate Shell and match its retained actual presentation scope.
use ev_graphics::connection::{self, Action, Connection, Status, Update, View};
pub mod root;
use ev_input::{
    Key, KeyEvent, SessionBarrierReply,
    pointer::{FreshGate as PointerGate, LEFT, PointerEvent},
    protocol::FreshGate,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    Stale,
    Counter,
    State,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Open,
    Fetch,
    SelectNext,
    Restart,
    Confirm,
    Cancel,
    Back,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub operation: Operation,
    pub revision: u32,
}
impl Request {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.revision == u32::MAX || (self.revision == 0 && self.operation != Operation::Open) {
            return Err(Error::Counter);
        }
        let mut b = [
            b'O',
            1,
            match self.operation {
                Operation::Open => 1,
                Operation::Fetch => 2,
                Operation::SelectNext => 3,
                Operation::Confirm => 4,
                Operation::Cancel => 5,
                Operation::Back => 6,
                Operation::Restart => 7,
            },
            0,
            0,
            0,
            0,
            0,
        ];
        b[4..].copy_from_slice(&self.revision.to_le_bytes());
        Ok(b)
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[..2] != [b'O', 1] || b[3] != 0 {
            return Err(Error::Format);
        }
        let operation = match b[2] {
            1 => Operation::Open,
            2 => Operation::Fetch,
            3 => Operation::SelectNext,
            4 => Operation::Confirm,
            5 => Operation::Cancel,
            6 => Operation::Back,
            7 => Operation::Restart,
            _ => return Err(Error::Format),
        };
        let r = Self {
            operation,
            revision: u32::from_le_bytes(b[4..].try_into().unwrap()),
        };
        r.encode()?;
        Ok(r)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub revision: u32,
    pub status: Status,
}
impl Presentation {
    /// Packed into an additive RootControl word; old messages/goldens unchanged.
    pub fn word(self) -> Result<u32, Error> {
        if self.revision == 0 || self.revision >= 0x007f_ffff {
            return Err(Error::Counter);
        }
        if self.status.confirm && (!matches!(self.status.update, Update::Selected)) {
            return Err(Error::State);
        }
        let c = match self.status.connection {
            Connection::Connecting => 0,
            Connection::Online => 1,
            Connection::Offline => 2,
        };
        let u = match self.status.update {
            Update::Idle => 0,
            Update::Preparing => 1,
            Update::Downloading => 2,
            Update::Checking => 3,
            Update::Ready => 4,
            Update::Failed => 5,
            Update::Selecting => 6,
            Update::Unavailable => 7,
            Update::Selected => 8,
            Update::SetupRequired => 9,
        };
        Ok(self.revision << 9
            | c
            | u << 2
            | u32::from(self.status.app_running) << 6
            | u32::from(self.status.confirm) << 7
            | u32::from(self.status.candidate_available) << 8)
    }
    pub fn decode(word: u32) -> Result<Self, Error> {
        let p = Self {
            revision: word >> 9,
            status: Status {
                connection: match word & 3 {
                    0 => Connection::Connecting,
                    1 => Connection::Online,
                    2 => Connection::Offline,
                    _ => return Err(Error::Format),
                },
                update: match (word >> 2) & 15 {
                    0 => Update::Idle,
                    1 => Update::Preparing,
                    2 => Update::Downloading,
                    3 => Update::Checking,
                    4 => Update::Ready,
                    5 => Update::Failed,
                    6 => Update::Selecting,
                    7 => Update::Unavailable,
                    8 => Update::Selected,
                    9 => Update::SetupRequired,
                    _ => return Err(Error::Format),
                },
                app_running: word & 64 != 0,
                confirm: word & 128 != 0,
                candidate_available: word & 256 != 0,
            },
        };
        p.word()?;
        Ok(p)
    }
}
pub struct Policy {
    presentation: Presentation,
    focus: Action,
    frame: u32,
    awaiting_display: bool,
    awaiting_barrier: bool,
    keyboard: Option<FreshGate>,
    pointer: Option<PointerGate>,
    last_sequence: u32,
    submitted: bool,
}
impl Policy {
    pub fn new(presentation: Presentation, frame: u32) -> Result<Self, Error> {
        presentation.word()?;
        if frame == 0 || frame == u32::MAX {
            return Err(Error::Counter);
        }
        Ok(Self {
            presentation,
            focus: if presentation.status.confirm {
                Action::Cancel
            } else {
                Action::Back
            },
            frame,
            awaiting_display: true,
            awaiting_barrier: false,
            keyboard: None,
            pointer: None,
            last_sequence: 0,
            submitted: false,
        })
    }
    pub fn view(&self) -> View {
        View {
            status: self.presentation.status,
            focus: self.focus,
        }
    }
    pub fn redraw(&mut self, frame: u32) -> Result<(), Error> {
        if frame <= self.frame || frame == u32::MAX || self.submitted {
            return Err(Error::Stale);
        }
        self.frame = frame;
        self.awaiting_display = true;
        self.awaiting_barrier = false;
        self.keyboard = None;
        self.pointer = None;
        Ok(())
    }
    pub fn displayed(&mut self, frame: u32) -> Result<(), Error> {
        if !self.awaiting_display || frame != self.frame {
            return Err(Error::Stale);
        }
        self.awaiting_display = false;
        self.awaiting_barrier = true;
        Ok(())
    }
    pub fn barrier(&mut self, frame: u32, mut snapshot: SessionBarrierReply) -> Result<(), Error> {
        if !self.awaiting_barrier || self.awaiting_display || frame != self.frame || self.submitted
        {
            return Err(Error::Stale);
        }
        snapshot.encode().map_err(|_| Error::Format)?;
        self.awaiting_barrier = false;
        snapshot.sequence = snapshot.sequence.max(self.last_sequence);
        self.keyboard =
            Some(FreshGate::after_barrier(snapshot.keyboard()).map_err(|_| Error::Format)?);
        self.pointer = Some(PointerGate::after_barrier(snapshot).map_err(|_| Error::Format)?);
        self.last_sequence = snapshot.sequence;
        Ok(())
    }
    fn action(&mut self, action: Action) -> Result<Option<Request>, Error> {
        if self.submitted || !connection::enabled(self.presentation.status, action) {
            return Ok(None);
        }
        self.submitted = true;
        self.keyboard = None;
        self.pointer = None;
        Ok(Some(Request {
            revision: self.presentation.revision,
            operation: match action {
                Action::Back => Operation::Back,
                Action::Fetch => Operation::Fetch,
                Action::SelectNext => Operation::SelectNext,
                Action::Restart => Operation::Restart,
                Action::Cancel => Operation::Cancel,
                Action::Confirm => Operation::Confirm,
            },
        }))
    }
    pub fn key(&mut self, event: KeyEvent) -> Result<Option<Request>, Error> {
        event.encode().map_err(|_| Error::Format)?;
        if event.sequence <= self.last_sequence {
            return Err(Error::Stale);
        }
        self.last_sequence = event.sequence;
        if self.submitted {
            return Ok(None);
        }
        let fresh = self
            .keyboard
            .as_mut()
            .map(|g| g.observe(event))
            .transpose()
            .map_err(|_| Error::Format)?
            .flatten();
        if event.key == Key::Escape {
            return self.action(if self.presentation.status.confirm {
                Action::Cancel
            } else {
                Action::Back
            });
        }
        if event.key == Key::Enter && fresh == Some(Key::Enter) {
            return self.action(self.focus);
        }
        if matches!(event.key, Key::Tab | Key::Down | Key::Up) {
            let order = if self.presentation.status.confirm {
                [Action::Cancel, Action::Confirm, Action::Cancel]
            } else {
                [
                    Action::Back,
                    Action::Fetch,
                    connection::primary(self.presentation.status),
                ]
            };
            let index = order.iter().position(|a| *a == self.focus).unwrap_or(0);
            for offset in 1..=3 {
                let next = order[(index + offset) % 3];
                if connection::enabled(self.presentation.status, next) {
                    self.focus = next;
                    break;
                }
            }
        }
        Ok(None)
    }
    pub fn pointer(
        &mut self,
        event: PointerEvent,
        x: u16,
        y: u8,
    ) -> Result<Option<Request>, Error> {
        event.encode().map_err(|_| Error::Format)?;
        if event.sequence <= self.last_sequence {
            return Err(Error::Stale);
        }
        self.last_sequence = event.sequence;
        let fresh = self
            .pointer
            .as_mut()
            .map(|g| g.observe(event))
            .transpose()
            .map_err(|_| Error::Format)?
            .unwrap_or(0)
            & LEFT
            != 0;
        if !fresh {
            return Ok(None);
        }
        if let Some(action) = connection::hit(self.view(), usize::from(x), usize::from(y)) {
            self.focus = action;
            return self.action(action);
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests;
