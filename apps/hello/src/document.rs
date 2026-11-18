//! Native selected-document state. This model owns no endpoint or storage and
//! cannot authorize a save. The actor must validate the actual File transport,
//! retain its loan until completion/quiescence and supply exact observed bytes.
use ev_userspace_contract::{
    document::{Access, Choice, Feedback, Focus, Snapshot, State, TEXT_BYTES, Text},
    file::{ErrorCode, Payload, Request, Response},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    ReadOnly,
    Full,
    Text,
    Position,
    Reply,
    Busy,
    Uncertain,
    Exhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Navigation {
    Open,
    OpenRead,
    Close,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Navigate {
    Ready(Navigation),
    ConfirmDiscard,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub counter: u64,
    pub text: Text,
}
impl Proposal {
    pub fn request(self) -> Request {
        Request::Replace {
            counter: self.counter,
            payload: Payload::new(self.text.as_bytes()).expect("same bounded File payload"),
        }
    }
}

pub struct Editor {
    current: Text,
    confirmed: Text,
    proposal: Option<Proposal>,
    state: State,
    focus: Focus,
    choice: Choice,
    access: Access,
    revision: u64,
    cursor: u16,
    anchor: u16,
    feedback: Feedback,
    navigation: Option<Navigation>,
}
impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}
impl Editor {
    pub const fn new() -> Self {
        Self {
            current: Text::empty(),
            confirmed: Text::empty(),
            proposal: None,
            state: State::Closed,
            focus: Focus::Open,
            choice: Choice::None,
            access: Access::None,
            revision: 0,
            cursor: 0,
            anchor: 0,
            feedback: Feedback::None,
            navigation: None,
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state,
            focus: self.focus,
            choice: self.choice,
            access: self.access,
            text: self.current,
            cursor: self.cursor,
            anchor: self.anchor,
            revision: self.revision,
            feedback: self.feedback,
            dirty: self.current != self.confirmed,
        }
    }
    pub const fn pending(&self) -> Option<Proposal> {
        self.proposal
    }
    pub fn open(
        &mut self,
        choice: Choice,
        access: Access,
        counter: u64,
        payload: &Payload,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Closed | State::Saved | State::Selecting)
            || self.current != self.confirmed
            || self.proposal.is_some()
        {
            return Err(Error::State);
        }
        if choice == Choice::None || access == Access::None || counter == u64::MAX {
            return Err(Error::Reply);
        }
        // Validate before replacing the previous clean document. Unsupported
        // bytes never become an empty/lossily decoded replacement.
        let text = Text::new(payload.as_slice()).map_err(|_| Error::Text)?;
        self.current = text;
        self.confirmed = text;
        self.revision = counter;
        self.choice = choice;
        self.access = access;
        self.state = State::Saved;
        self.cursor = text.len() as u16;
        self.anchor = self.cursor;
        self.focus = Focus::Text;
        self.feedback = Feedback::None;
        self.navigation = None;
        Ok(())
    }
    pub fn selecting(&mut self) -> Result<(), Error> {
        if self.state == State::Closed {
            self.state = State::Selecting;
            Ok(())
        } else if self.state == State::Saved {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
    pub fn cancel_selection(&mut self) {
        if self.state == State::Selecting {
            self.state = State::Closed;
        }
    }
    pub fn selection_refused(&mut self, reason: Feedback) {
        self.cancel_selection();
        self.feedback = reason;
    }
    pub fn focus(&mut self, focus: Focus) -> Result<(), Error> {
        if self.state == State::ConfirmDiscard {
            if !matches!(focus, Focus::Discard | Focus::KeepEditing) {
                return Err(Error::State);
            }
        } else if matches!(focus, Focus::Discard | Focus::KeepEditing)
            || (matches!(self.state, State::Closed | State::Selecting)
                && !matches!(focus, Focus::Open | Focus::OpenRead))
        {
            return Err(Error::State);
        }
        self.focus = focus;
        Ok(())
    }
    pub fn move_cursor(&mut self, offset: usize, extend: bool) -> Result<(), Error> {
        if !self.current.boundary(offset) {
            return Err(Error::Position);
        }
        if matches!(
            self.state,
            State::Closed | State::Selecting | State::ConfirmDiscard
        ) {
            return Err(Error::State);
        }
        self.cursor = offset as u16;
        if !extend {
            self.anchor = self.cursor;
        }
        Ok(())
    }
    pub fn select_all(&mut self) -> Result<(), Error> {
        self.move_cursor(0, false)?;
        self.move_cursor(self.current.len(), true)?;
        self.focus = Focus::Text;
        Ok(())
    }
    pub fn horizontal(&mut self, right: bool) -> Result<(), Error> {
        let cursor = usize::from(self.cursor);
        let next = if self.cursor != self.anchor {
            if right {
                self.cursor.max(self.anchor) as usize
            } else {
                self.cursor.min(self.anchor) as usize
            }
        } else if right {
            self.current.as_str()[cursor..]
                .chars()
                .next()
                .map(|c| cursor + c.len_utf8())
                .unwrap_or(cursor)
        } else {
            self.current.as_str()[..cursor]
                .char_indices()
                .last()
                .map(|(at, _)| at)
                .unwrap_or(0)
        };
        self.move_cursor(next, false)
    }
    fn editable(&self) -> Result<(), Error> {
        if self.access != Access::Edit {
            return Err(Error::ReadOnly);
        }
        match self.state {
            State::Saved | State::Dirty | State::Saving | State::Readback => Ok(()),
            State::Unavailable => Err(Error::Uncertain),
            _ => Err(Error::State),
        }
    }
    fn changed(&mut self) {
        if !matches!(self.state, State::Saving | State::Readback) {
            self.state = if self.current == self.confirmed {
                State::Saved
            } else {
                State::Dirty
            };
        }
    }
    pub fn insert(&mut self, text: &str) -> Result<(), Error> {
        self.editable()?;
        let start = usize::from(self.cursor.min(self.anchor));
        let end = usize::from(self.cursor.max(self.anchor));
        let length = self.current.len() - (end - start) + text.len();
        if length > TEXT_BYTES {
            self.feedback = Feedback::Full;
            return Err(Error::Full);
        }
        Text::new(text.as_bytes()).map_err(|_| Error::Text)?;
        let mut bytes = [0; TEXT_BYTES];
        bytes[..start].copy_from_slice(&self.current.as_bytes()[..start]);
        bytes[start..start + text.len()].copy_from_slice(text.as_bytes());
        bytes[start + text.len()..length].copy_from_slice(&self.current.as_bytes()[end..]);
        self.current = Text::new(&bytes[..length]).map_err(|_| Error::Text)?;
        self.cursor = (start + text.len()) as u16;
        self.anchor = self.cursor;
        self.feedback = Feedback::None;
        self.changed();
        Ok(())
    }
    pub fn backspace(&mut self) -> Result<(), Error> {
        self.editable()?;
        if self.cursor == self.anchor && self.cursor != 0 {
            self.anchor = self.current.as_str()[..usize::from(self.cursor)]
                .char_indices()
                .last()
                .map(|(i, _)| i as u16)
                .unwrap_or(0);
        }
        self.insert("")
    }
    pub fn prepare_save(&mut self) -> Result<Proposal, Error> {
        if self.proposal.is_some() {
            return Err(if self.state == State::Unavailable {
                Error::Uncertain
            } else {
                Error::Busy
            });
        }
        if self.access != Access::Edit {
            return Err(Error::ReadOnly);
        }
        if self.state != State::Dirty || self.current == self.confirmed {
            return Err(Error::State);
        }
        let Some(counter) = self.revision.checked_add(1).filter(|n| *n != u64::MAX) else {
            self.feedback = Feedback::Exhausted;
            return Err(Error::Exhausted);
        };
        let proposal = Proposal {
            counter,
            text: self.current,
        };
        self.proposal = Some(proposal);
        self.state = State::Saving;
        self.feedback = Feedback::None;
        Ok(proposal)
    }
    pub fn acknowledge(&mut self, response: Response) -> Result<(), Error> {
        if self.state != State::Saving || self.proposal.is_none() {
            return Err(Error::State);
        }
        match response {
            Response::Replaced { counter, .. } if counter == self.proposal.unwrap().counter => {
                self.state = State::Readback;
                Ok(())
            }
            Response::Error { code } => {
                self.failed(match code {
                    ErrorCode::Denied => Feedback::Denied,
                    ErrorCode::Conflict
                    | ErrorCode::InvalidCounter
                    | ErrorCode::Stale
                    | ErrorCode::Skipped => Feedback::Conflict,
                    ErrorCode::Exhausted => Feedback::Exhausted,
                    _ => Feedback::Storage,
                });
                Err(Error::Reply)
            }
            _ => {
                self.failed(Feedback::Uncertain);
                Err(Error::Reply)
            }
        }
    }
    pub fn readback(&mut self, counter: u64, payload: &Payload) -> Result<(), Error> {
        if self.state != State::Readback {
            return Err(Error::State);
        }
        let Some(proposal) = self.proposal else {
            return Err(Error::State);
        };
        if counter != proposal.counter || payload.as_slice() != proposal.text.as_bytes() {
            self.failed(Feedback::Conflict);
            return Err(Error::Reply);
        }
        self.confirmed = proposal.text;
        self.revision = counter;
        self.proposal = None;
        self.feedback = Feedback::None;
        self.state = State::Saved;
        self.changed();
        Ok(())
    }
    /// A failed accepted call/readback never authorizes another attempt or
    /// frame reuse. Only actual transport quiescence and a fresh open may reset
    /// the actor/model. Keep the proposal for diagnosis/recovery, not auto-retry.
    pub fn failed(&mut self, reason: Feedback) {
        self.state = if self.choice == Choice::None {
            State::Closed
        } else {
            State::Unavailable
        };
        self.feedback = if reason == Feedback::None {
            Feedback::Uncertain
        } else {
            reason
        };
    }
    pub fn navigate(&mut self, navigation: Navigation) -> Result<Navigate, Error> {
        if self.proposal.is_some() || matches!(self.state, State::Saving | State::Readback) {
            return Err(Error::Busy);
        }
        if self.state == State::Unavailable {
            return Err(Error::Uncertain);
        }
        if self.state == State::ConfirmDiscard {
            return Err(Error::State);
        }
        if self.current != self.confirmed {
            self.navigation = Some(navigation);
            self.state = State::ConfirmDiscard;
            self.focus = Focus::KeepEditing;
            return Ok(Navigate::ConfirmDiscard);
        }
        Ok(Navigate::Ready(navigation))
    }
    pub fn keep_editing(&mut self) -> Result<(), Error> {
        if self.state != State::ConfirmDiscard {
            return Err(Error::State);
        }
        self.navigation = None;
        self.state = State::Dirty;
        self.focus = Focus::Text;
        Ok(())
    }
    pub fn discard(&mut self) -> Result<Navigation, Error> {
        if self.state != State::ConfirmDiscard {
            return Err(Error::State);
        }
        let navigation = self.navigation.take().ok_or(Error::State)?;
        self.current = self.confirmed;
        self.cursor = self.current.len() as u16;
        self.anchor = self.cursor;
        self.state = State::Saved;
        self.focus = Focus::Text;
        self.feedback = Feedback::None;
        Ok(navigation)
    }
    /// The caller closes the actual selected endpoint before clearing its view.
    pub fn closed(&mut self) -> Result<(), Error> {
        if self.proposal.is_some()
            || self.current != self.confirmed
            || self.state == State::Unavailable
        {
            return Err(Error::State);
        }
        *self = Self::new();
        Ok(())
    }
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
