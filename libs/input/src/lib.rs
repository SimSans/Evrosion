//! First reference-machine keyboard decoder. This consumes actual controller
//! bytes; it neither grants input authority nor selects a focused recipient.
#![no_std]
#![deny(unsafe_code)]
pub mod pointer;
pub mod protocol;
pub mod ps2;
pub mod stream;
pub mod text;
pub use ev_userspace_contract::focused_input::Key;
pub use protocol::{
    BarrierReply, BarrierRequest, EnterState, KeyEvent, PointerState, SessionBarrierReply,
    SessionBarrierRequest,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    Controller,
    UnsupportedSequence,
}
#[derive(Default)]
pub struct Keyboard {
    extended: bool,
    pause_remaining: u8,
    pressed: u8,
    quarantined: bool,
    enter_released: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    pub key: Key,
    pub pressed: bool,
    pub(crate) bit: u8,
}
impl Keyboard {
    /// Accept translated set1 bytes from a separately authorized PS/2 Input
    /// service. Parity/timeout and AUX bytes never become application keys.
    pub fn feed(&mut self, status: u8, data: u8) -> Result<Option<Key>, InputError> {
        Ok(self
            .transition(status, data)?
            .filter(|t| t.pressed)
            .map(|t| t.key))
    }
    /// Physical main/keypad Enter are tracked independently. A real validated
    /// break establishes release knowledge; a barrier never clears held state.
    pub fn transition(&mut self, status: u8, data: u8) -> Result<Option<Transition>, InputError> {
        if self.quarantined {
            return Err(InputError::UnsupportedSequence);
        }
        if status & 0xc0 != 0 {
            self.quarantined = true;
            return Err(InputError::Controller);
        }
        if status & 1 == 0 {
            return Ok(None);
        }
        if status & 0x20 != 0 {
            return Ok(None);
        }
        if self.pause_remaining != 0 {
            let expected = [0x1d, 0x45, 0xe1, 0x9d, 0xc5];
            if data != expected[5 - usize::from(self.pause_remaining)] {
                self.quarantined = true;
                return Err(InputError::UnsupportedSequence);
            }
            self.pause_remaining -= 1;
            return Ok(None);
        }
        match data {
            0xe1 => {
                if self.extended {
                    self.quarantined = true;
                    return Err(InputError::UnsupportedSequence);
                }
                self.extended = false;
                self.pause_remaining = 5;
                return Ok(None);
            }
            0xe0 => {
                if self.extended {
                    self.quarantined = true;
                    return Err(InputError::UnsupportedSequence);
                }
                self.extended = true;
                return Ok(None);
            }
            // Set2 break prefix or controller response: never interpret the
            // following byte as a set1 application action.
            0xf0 | 0xfa | 0xfe => {
                self.quarantined = true;
                return Err(InputError::UnsupportedSequence);
            }
            _ => {}
        }
        if matches!(data, 0 | 0xff) {
            self.quarantined = true;
            return Err(InputError::Controller);
        }
        let extended = core::mem::replace(&mut self.extended, false);
        let release = data & 0x80 != 0;
        let (key, bit) = match (extended, data & 0x7f) {
            (false, 0x0f) => (Key::Tab, 1),
            (false, 0x1c) => (Key::Enter, 2),
            (true, 0x1c) => (Key::Enter, 32),
            (false, 0x01) => (Key::Escape, 4),
            (true, 0x48) => (Key::Up, 8),
            (true, 0x50) => (Key::Down, 16),
            (true, 0x4b) => (Key::Left, 64),
            (true, 0x4d) => (Key::Right, 128),
            _ => return Ok(None),
        };
        if release {
            self.pressed &= !bit;
            if key == Key::Enter {
                self.enter_released |= bit;
            }
            return Ok(Some(Transition {
                key,
                pressed: false,
                bit,
            }));
        }
        if self.pressed & bit != 0 {
            return Ok(None);
        }
        self.pressed |= bit;
        Ok(Some(Transition {
            key,
            pressed: true,
            bit,
        }))
    }
    pub fn enter_state(&self) -> EnterState {
        EnterState {
            main_released: self.enter_released & 2 != 0,
            keypad_released: self.enter_released & 32 != 0,
            main_held: self.pressed & 2 != 0,
            keypad_held: self.pressed & 32 != 0,
        }
    }
    pub fn at_boundary(&self) -> bool {
        !self.extended && self.pause_remaining == 0
    }
    pub(crate) fn held_enters(&self) -> u8 {
        self.pressed & (2 | 32)
    }
    pub(crate) fn release_known(&self, bit: u8) -> bool {
        self.enter_released & bit != 0
    }
    /// Only a new supervised Input lifetime may discard physical key knowledge.
    /// All pending approvals must first be cancelled. Never call for a barrier.
    pub fn reset(&mut self) {
        self.extended = false;
        self.pause_remaining = 0;
        self.pressed = 0;
        self.quarantined = false;
        self.enter_released = 0;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_actual_complete_keyboard_make_routes_once_until_release() {
        let mut k = Keyboard::default();
        assert_eq!(k.feed(0, 0x0f), Ok(None));
        assert_eq!(k.feed(0x21, 0x0f), Ok(None));
        assert_eq!(k.feed(1, 0x0f), Ok(Some(Key::Tab)));
        assert_eq!(k.feed(1, 0x0f), Ok(None));
        assert_eq!(k.feed(1, 0x8f), Ok(None));
        assert_eq!(k.feed(1, 0x0f), Ok(Some(Key::Tab)));
    }
    #[test]
    fn extended_arrows_and_pause_do_not_forge_enter_or_navigation() {
        let mut k = Keyboard::default();
        assert_eq!(k.feed(1, 0x48), Ok(None));
        assert_eq!(k.feed(1, 0xe0), Ok(None));
        assert_eq!(k.feed(1, 0x48), Ok(Some(Key::Up)));
        assert_eq!(k.feed(1, 0xe1), Ok(None));
        for b in [0x1d, 0x45, 0xe1, 0x9d, 0xc5] {
            assert_eq!(k.feed(1, b), Ok(None));
        }
        assert_eq!(k.feed(1, 0x1c), Ok(Some(Key::Enter)));
    }
    #[test]
    fn horizontal_keys_require_extended_make_and_distinct_break() {
        let mut k = Keyboard::default();
        for (scan, key) in [(0x4b, Key::Left), (0x4d, Key::Right)] {
            assert_eq!(k.feed(1, scan), Ok(None));
            assert_eq!(k.feed(1, 0xe0), Ok(None));
            assert_eq!(k.feed(1, scan), Ok(Some(key)));
            k.feed(1, 0xe0).unwrap();
            assert_eq!(k.feed(1, scan), Ok(None));
            k.feed(1, 0xe0).unwrap();
            k.feed(1, scan | 0x80).unwrap();
            k.feed(1, 0xe0).unwrap();
            assert_eq!(k.feed(1, scan), Ok(Some(key)));
        }
        assert_eq!(k.enter_state(), EnterState::default());
    }
    #[test]
    fn corrupt_controller_input_and_unsupported_set2_refuse() {
        let mut k = Keyboard::default();
        assert_eq!(k.feed(0x81, 0x1c), Err(InputError::Controller));
        assert_eq!(k.feed(1, 0xf0), Err(InputError::UnsupportedSequence));
        assert_eq!(k.feed(1, 0x5a), Err(InputError::UnsupportedSequence));
        assert_eq!(k.feed(1, 0x1c), Err(InputError::UnsupportedSequence)); // Set2 A must not become set1 Enter.
        k.reset();
        assert_eq!(k.feed(1, 0x1c), Ok(Some(Key::Enter)));
    }
}
