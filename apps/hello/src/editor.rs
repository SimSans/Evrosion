// SPDX-License-Identifier: GPL-3.0-only
//! Local note editing. Only the actual nonce-matched durable readback may mark
//! a save complete; edits made while saving remain unsaved afterward.
use ev_app_registry::note_data::{MAX_NOTE_BYTES, NoteDataEnvelope};
use ev_input::text::Text;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Loading,
    Saved,
    Unsaved,
    Saving,
    Unavailable,
    Busy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Busy,
    Full,
    Character,
    Reply,
}
pub struct Editor {
    confirmed: Option<NoteDataEnvelope>,
    proposed: Option<NoteDataEnvelope>,
    bytes: [u8; MAX_NOTE_BYTES],
    length: usize,
    state: State,
}
impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}
impl Editor {
    pub const fn new() -> Self {
        Self {
            confirmed: None,
            proposed: None,
            bytes: [0; MAX_NOTE_BYTES],
            length: 0,
            state: State::Loading,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub const fn state(&self) -> State {
        self.state
    }
    pub fn loaded(&mut self, note: NoteDataEnvelope) -> Result<(), Error> {
        if self.state != State::Loading || self.confirmed.is_some() {
            return Err(Error::Reply);
        }
        let text = note.note().as_bytes();
        self.bytes[..text.len()].copy_from_slice(text);
        self.length = text.len();
        self.confirmed = Some(note);
        self.state = State::Saved;
        Ok(())
    }
    pub fn edit(&mut self, text: Text) -> Result<(), Error> {
        if self.confirmed.is_none() {
            return Err(Error::Unavailable);
        }
        match text {
            Text::Ascii(byte @ 0x20..=0x7e) => {
                if self.length == MAX_NOTE_BYTES {
                    return Err(Error::Full);
                }
                self.bytes[self.length] = byte;
                self.length += 1;
            }
            Text::Ascii(_) => return Err(Error::Character),
            Text::Backspace if self.length > 0 => {
                self.length -= 1;
                self.bytes[self.length] = 0;
            }
            Text::Backspace => {}
        }
        if self.state != State::Saving && self.state != State::Unavailable {
            self.state = if self.confirmed.as_ref().unwrap().note().as_bytes() == self.bytes() {
                State::Saved
            } else {
                State::Unsaved
            };
        }
        Ok(())
    }
    pub fn prepare_save(&mut self) -> Result<NoteDataEnvelope, Error> {
        if self.state == State::Saving {
            return Err(Error::Busy);
        }
        if !matches!(self.state, State::Unsaved | State::Busy) {
            return Err(Error::Unavailable);
        }
        let old = self.confirmed.as_ref().ok_or(Error::Unavailable)?;
        let text = core::str::from_utf8(self.bytes()).map_err(|_| Error::Character)?;
        let proposed = old
            .checked_replace(old.app(), old.counter(), text)
            .map_err(|_| Error::Reply)?;
        self.proposed = Some(proposed);
        self.state = State::Saving;
        Ok(proposed)
    }
    /// Call only after Client validates the actual protected Root sender, nonce
    /// and complete readback bytes. A different valid envelope is insufficient.
    pub fn saved(&mut self, actual: NoteDataEnvelope) -> Result<(), Error> {
        if self.state != State::Saving || self.proposed != Some(actual) {
            self.failed();
            return Err(Error::Reply);
        }
        self.proposed = None;
        self.confirmed = Some(actual);
        self.state = if actual.note().as_bytes() == self.bytes() {
            State::Saved
        } else {
            State::Unsaved
        };
        Ok(())
    }
    pub fn proposed(&self) -> Option<NoteDataEnvelope> {
        self.proposed
    }
    /// Only after the actual Client completes a matching Busy response. No IO
    /// was started by Root; timeout/unknown/recovery never use this transition.
    pub fn busy(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Loading | State::Saving) {
            return Err(Error::Reply);
        }
        self.proposed = None;
        self.state = State::Busy;
        Ok(())
    }
    pub fn retry_read(&mut self) -> bool {
        if self.state != State::Busy || self.confirmed.is_some() {
            return false;
        }
        self.state = State::Loading;
        true
    }
    pub fn failed(&mut self) {
        self.state = State::Unavailable;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn empty() -> NoteDataEnvelope {
        NoteDataEnvelope::initial(ev_zion::AppId::new([7; 16]).unwrap(), "").unwrap()
    }
    #[test]
    fn edits_during_a_save_are_preserved_and_only_exact_readback_completes_it() {
        let mut e = Editor::new();
        e.loaded(empty()).unwrap();
        e.edit(Text::Ascii(b'A')).unwrap();
        let first = e.prepare_save().unwrap();
        e.edit(Text::Ascii(b'b')).unwrap();
        assert_eq!(e.prepare_save(), Err(Error::Busy));
        e.saved(first).unwrap();
        assert_eq!(e.bytes(), b"Ab");
        assert_eq!(e.state(), State::Unsaved);
        let second = e.prepare_save().unwrap();
        e.saved(second).unwrap();
        assert_eq!(e.state(), State::Saved);
        assert_eq!(second.counter(), 2);
        assert_eq!(e.saved(first), Err(Error::Reply));
        assert_eq!(e.bytes(), b"Ab");
    }
    #[test]
    fn full_note_refuses_overflow_and_failed_save_never_discards_edits() {
        let mut e = Editor::new();
        assert!(e.edit(Text::Ascii(b'a')).is_err());
        e.loaded(empty()).unwrap();
        for _ in 0..MAX_NOTE_BYTES {
            e.edit(Text::Ascii(b'x')).unwrap();
        }
        assert_eq!(e.edit(Text::Ascii(b'y')), Err(Error::Full));
        e.prepare_save().unwrap();
        e.failed();
        e.edit(Text::Backspace).unwrap();
        assert_eq!(e.state(), State::Unavailable);
        assert_eq!(e.bytes().len(), MAX_NOTE_BYTES - 1);
        assert!(e.prepare_save().is_err());
    }
    #[test]
    fn authenticated_busy_write_preserves_text_counter_and_requires_new_explicit_nonce() {
        use ev_userspace_contract::session_note::{
            Client, Completion, Operation, Outcome, Refusal,
        };
        let mut e = Editor::new();
        e.loaded(empty()).unwrap();
        e.edit(Text::Ascii(b'A')).unwrap();
        let proposed = e.prepare_save().unwrap();
        let mut client = Client::new();
        let request = client.prepare(Operation::Write, 1, 100).unwrap();
        client.accepted(request, 2).unwrap();
        let completion = client
            .accept(
                &request.reply(Outcome::Refused(Refusal::Busy)).encode(),
                0,
                3,
                |_| -> Result<NoteDataEnvelope, ()> { panic!("Busy cannot authorize bulk access") },
            )
            .unwrap();
        assert_eq!(completion, Completion::Refused(Refusal::Busy));
        assert!(client.page_available());
        e.busy().unwrap();
        assert_eq!(e.state(), State::Busy);
        assert_eq!(e.bytes(), b"A");
        assert!(e.proposed().is_none());
        let replacement = e.prepare_save().unwrap();
        assert_eq!(replacement, proposed);
        let next = client.prepare(Operation::Write, 4, 100).unwrap();
        assert_eq!(next.nonce(), request.nonce() + 1);
        assert!(client.accepted(request, 5).is_err()); // No replay of the completed request.
    }
    #[test]
    fn busy_initial_read_cannot_save_over_unloaded_data_or_reopen_a_failed_editor() {
        let mut e = Editor::new();
        e.busy().unwrap();
        assert!(e.prepare_save().is_err());
        assert!(e.edit(Text::Ascii(b'x')).is_err());
        assert!(e.retry_read());
        assert_eq!(e.state(), State::Loading);
        e.loaded(empty()).unwrap();
        assert_eq!(e.state(), State::Saved);
        e.edit(Text::Ascii(b'x')).unwrap();
        e.prepare_save().unwrap();
        e.failed();
        assert!(e.busy().is_err());
        assert_eq!(e.state(), State::Unavailable);
        assert!(!e.retry_read());
        assert_eq!(e.bytes(), b"x");
    }
    #[test]
    fn validated_note_client_can_render_saved_first_surface_without_loading_present() {
        use ev_userspace_contract::session_note::{Client, Completion, Operation, Outcome};
        let mut editor = Editor::new();
        assert_eq!(editor.state(), State::Loading);
        let mut client = Client::new();
        let req = client.prepare(Operation::Read, 10, 50).unwrap();
        client.accepted(req, 10).unwrap();
        let saved =
            NoteDataEnvelope::initial(ev_zion::AppId::new(crate::APP_ID).unwrap(), "M6 keep42")
                .unwrap();
        let completion = client
            .accept(&req.reply(Outcome::Read).encode(), 0, 11, |outcome| {
                if outcome != Outcome::Read {
                    return Err(());
                }
                let note = NoteDataEnvelope::decode(&saved.encode()).map_err(|_| ())?;
                if note.app().bytes() != crate::APP_ID {
                    return Err(());
                }
                Ok(note)
            })
            .unwrap();
        let Completion::Read(note) = completion else {
            panic!("validated Read required");
        };
        editor.loaded(note).unwrap();
        assert_eq!(editor.state(), State::Saved);
        assert_eq!(editor.bytes(), b"M6 keep42");
        struct Canvas {
            writes: usize,
            nonzero: usize,
        }
        impl ev_graphics::Pixels for Canvas {
            fn dimensions(&self) -> (usize, usize) {
                (ev_graphics::WIDTH, ev_graphics::HEIGHT)
            }
            fn write(
                &mut self,
                x: usize,
                y: usize,
                pixel: ev_graphics::Color,
            ) -> Result<(), ev_graphics::Error> {
                if x >= ev_graphics::WIDTH || y >= ev_graphics::HEIGHT {
                    return Err(ev_graphics::Error::Bounds);
                }
                self.writes += 1;
                self.nonzero += usize::from(pixel.0 != 0);
                Ok(())
            }
        }
        let mut canvas = Canvas {
            writes: 0,
            nonzero: 0,
        };
        ev_graphics::session::render(
            &mut canvas,
            ev_graphics::session::View {
                build: ev_graphics::native::Build::B,
                focus: ev_graphics::session::Focus::Note,
                note: editor.bytes(),
                state: ev_graphics::session::SaveState::Saved,
                file: None,
            },
        )
        .unwrap();
        assert!(canvas.writes >= ev_graphics::WIDTH * ev_graphics::HEIGHT);
        assert!(canvas.nonzero > 0);
        let header = ev_graphics::SurfaceHeader::parse(
            &ev_graphics::SurfaceHeader { sequence: 1 }.encode().unwrap(),
        )
        .unwrap();
        let mut display = ev_desktop::compositor_policy::State::new();
        display
            .reset(ev_desktop::compositor_policy::SessionReset {
                producer: ev_desktop::compositor_policy::Producer::App,
                epoch: 1,
            })
            .unwrap();
        display
            .present(
                ev_desktop::compositor_policy::Producer::App,
                1,
                header.sequence,
            )
            .unwrap();
        assert!(
            !display.visible(),
            "model Present acceptance is not visible composition proof"
        );
        assert!(client.page_available());
    }
    #[test]
    fn invalid_or_refused_first_note_never_marks_saved_or_read_ready() {
        use ev_userspace_contract::session_note::{
            Client, Completion, Operation, Outcome, Refusal, Request,
        };
        for case in 0..6 {
            let mut editor = Editor::new();
            let mut client = Client::new();
            let request = client.prepare(Operation::Read, 10, 50).unwrap();
            client.accepted(request, 10).unwrap();
            let app = if case == 3 { [7; 16] } else { crate::APP_ID };
            let mut body =
                NoteDataEnvelope::initial(ev_zion::AppId::new(app).unwrap(), "M6 keep42")
                    .unwrap()
                    .encode();
            if case == 4 {
                body[255] ^= 1;
            }
            let mut reply = match case {
                0 => Request::new(Operation::Read, 2)
                    .unwrap()
                    .reply(Outcome::Read)
                    .encode(),
                2 => request.reply(Outcome::Refused(Refusal::Stale)).encode(),
                _ => request.reply(Outcome::Read).encode(),
            };
            if case == 1 {
                reply[0] ^= 1;
            }
            let mut bulk_called = false;
            let result = client.accept(&reply, 0, if case == 5 { 50 } else { 11 }, |outcome| {
                bulk_called = true;
                if outcome != Outcome::Read {
                    return Err(());
                }
                let note = NoteDataEnvelope::decode(&body).map_err(|_| ())?;
                if note.app().bytes() != crate::APP_ID {
                    return Err(());
                }
                Ok(note)
            });
            let initial_ready = match result {
                Ok(Completion::Read(note)) => editor.loaded(note).is_ok(),
                _ => false,
            };
            assert!(
                !initial_ready,
                "only real validated Read can precede startup Critical"
            );
            editor.failed();
            assert_eq!(editor.state(), State::Unavailable);
            assert!(editor.bytes().is_empty());
            assert_eq!(bulk_called, matches!(case, 3 | 4));
        }
    }
}
