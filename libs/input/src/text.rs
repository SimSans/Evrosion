//! Bounded set1 US-ASCII text decoding, separate from protected action keys.
//! Actual Input initialization must establish set1 and drain command replies.
//! A text frame conveys data/freshness only, never focus, consent or authority.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Controller,
    Framing,
    Incomplete,
    Header,
    Character,
    Sequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Text {
    Ascii(u8),
    Backspace,
}

impl Text {
    fn byte(self) -> Result<u8, Error> {
        match self {
            Self::Ascii(byte @ 0x20..=0x7e) => Ok(byte),
            Self::Backspace => Ok(8),
            _ => Err(Error::Character),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextEvent {
    pub text: Text,
    pub sequence: u32,
}

impl TextEvent {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.sequence == 0 || self.sequence == u32::MAX {
            return Err(Error::Sequence);
        }
        let mut bytes = [b'T', 1, self.text.byte()?, 0, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if bytes[0] != b'T' || bytes[1] != 1 || bytes[3] != 0 {
            return Err(Error::Header);
        }
        let text = match bytes[2] {
            8 => Text::Backspace,
            byte @ 0x20..=0x7e => Text::Ascii(byte),
            _ => return Err(Error::Character),
        };
        let result = Self {
            text,
            sequence: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        result.encode()?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub shift: bool,
    pub caps_lock: bool,
    pub control: bool,
    pub alt: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Prefix {
    #[default]
    None,
    Extended,
    Pause(u8),
    PrintMakeE0,
    PrintMake37,
}

/// New only for an actual new supervised Input lifetime, after controller drain.
/// There is no reset method that forgets modifiers in a still-running lifetime.
/// Typematic text makes may repeat; lock toggles require a distinct make/break.
#[derive(Default)]
pub struct Decoder {
    prefix: Prefix,
    shift: u8,
    control: u8,
    alt: u8,
    caps: bool,
    caps_down: bool,
    print_tail_allowed: bool,
    failed: Option<Error>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn modifiers(&self) -> Modifiers {
        Modifiers {
            shift: self.shift != 0,
            caps_lock: self.caps,
            control: self.control != 0,
            alt: self.alt != 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.failed.is_none() && self.prefix == Prefix::None
    }

    /// Use at a drain/end boundary. A partial sequence must not cross that cut.
    pub fn finish(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.prefix != Prefix::None {
            self.failed = Some(Error::Incomplete);
            return Err(Error::Incomplete);
        }
        Ok(())
    }

    pub fn feed(&mut self, status: u8, data: u8) -> Result<Option<Text>, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = self.feed_inner(status, data);
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }

    fn feed_inner(&mut self, status: u8, data: u8) -> Result<Option<Text>, Error> {
        if status & 0xc0 != 0 {
            return Err(Error::Controller);
        }
        if status & 1 == 0 || status & 0x20 != 0 {
            return Ok(None);
        }
        // Replies/set2 break prefixes must be consumed by controller command
        // handling, not reinterpreted as set1 character or modifier sequences.
        if matches!(data, 0 | 0xff | 0xf0 | 0xfa | 0xfe | 0xfc | 0xfd | 0xee) {
            return Err(Error::Framing);
        }
        match self.prefix {
            Prefix::Pause(index) => {
                const REST: [u8; 5] = [0x1d, 0x45, 0xe1, 0x9d, 0xc5];
                if data != REST[usize::from(index)] {
                    return Err(Error::Framing);
                }
                self.prefix = if index == 4 {
                    Prefix::None
                } else {
                    Prefix::Pause(index + 1)
                };
                return Ok(None);
            }
            Prefix::PrintMakeE0 => {
                if data != 0xe0 {
                    return Err(Error::Framing);
                }
                self.prefix = Prefix::PrintMake37;
                return Ok(None);
            }
            Prefix::PrintMake37 => {
                if data != 0x37 {
                    return Err(Error::Framing);
                }
                self.prefix = Prefix::None;
                return Ok(None);
            }
            Prefix::Extended => {
                self.prefix = Prefix::None;
                return self.extended(data);
            }
            Prefix::None => {}
        }
        if data == 0xe0 {
            self.prefix = Prefix::Extended;
            return Ok(None);
        }
        self.print_tail_allowed = false;
        if data == 0xe1 {
            self.prefix = Prefix::Pause(0);
            return Ok(None);
        }
        let release = data & 0x80 != 0;
        let code = data & 0x7f;
        if !(1..=0x58).contains(&code) {
            return Err(Error::Framing);
        }
        match code {
            0x2a => Self::held(&mut self.shift, 1, release),
            0x36 => Self::held(&mut self.shift, 2, release),
            0x1d => Self::held(&mut self.control, 1, release),
            0x38 => Self::held(&mut self.alt, 1, release),
            0x3a => {
                if !release && !self.caps_down {
                    self.caps = !self.caps;
                }
                self.caps_down = !release;
            }
            _ if !release && self.control == 0 && self.alt == 0 => {
                return Ok(self.character(code));
            }
            _ => {}
        }
        Ok(None)
    }

    fn held(value: &mut u8, bit: u8, release: bool) {
        if release {
            *value &= !bit;
        } else {
            *value |= bit;
        }
    }

    fn extended(&mut self, data: u8) -> Result<Option<Text>, Error> {
        let tail = core::mem::take(&mut self.print_tail_allowed);
        match data {
            0x2a => self.prefix = Prefix::PrintMakeE0,
            0x37 => {} // Shift/Ctrl+PrintScreen shortened alias.
            0xb7 => self.print_tail_allowed = true, // Full or shortened break.
            0xaa if tail => {} // Optional full PrintScreen break suffix.
            0x1d | 0x9d => Self::held(&mut self.control, 2, data & 0x80 != 0),
            0x38 | 0xb8 => Self::held(&mut self.alt, 2, data & 0x80 != 0),
            0x35 if self.control == 0 && self.alt == 0 => {
                return Ok(Some(Text::Ascii(b'/'))); // Keypad divide.
            }
            // Known extended non-text keys: Enter, divide break, navigation,
            // Windows/menu, Ctrl+Pause and multimedia keys. No fake Shift.
            _ if matches!(
                data & 0x7f,
                0x10 | 0x19
                    | 0x1c
                    | 0x20
                    | 0x21
                    | 0x22
                    | 0x24
                    | 0x2e
                    | 0x30
                    | 0x32
                    | 0x35
                    | 0x46
                    | 0x47
                    | 0x48
                    | 0x49
                    | 0x4b
                    | 0x4d
                    | 0x4f
                    | 0x50
                    | 0x51
                    | 0x52
                    | 0x53
                    | 0x5b
                    | 0x5c
                    | 0x5d
                    | 0x5e
                    | 0x5f
                    | 0x63
                    | 0x65
                    | 0x66
                    | 0x67
                    | 0x68
                    | 0x69
                    | 0x6a
                    | 0x6b
                    | 0x6c
                    | 0x6d
            ) => {}
            _ => return Err(Error::Framing),
        }
        Ok(None)
    }

    fn character(&self, code: u8) -> Option<Text> {
        let letter = match code {
            0x10..=0x19 => Some(b"qwertyuiop"[usize::from(code - 0x10)]),
            0x1e..=0x26 => Some(b"asdfghjkl"[usize::from(code - 0x1e)]),
            0x2c..=0x32 => Some(b"zxcvbnm"[usize::from(code - 0x2c)]),
            _ => None,
        };
        if let Some(letter) = letter {
            return Some(Text::Ascii(if (self.shift != 0) ^ self.caps {
                letter.to_ascii_uppercase()
            } else {
                letter
            }));
        }
        let shift = self.shift != 0;
        let byte = match code {
            0x02..=0x0b => {
                let row = if shift { b"!@#$%^&*()" } else { b"1234567890" };
                row[usize::from(code - 2)]
            }
            0x0c => {
                if shift {
                    b'_'
                } else {
                    b'-'
                }
            }
            0x0d => {
                if shift {
                    b'+'
                } else {
                    b'='
                }
            }
            0x0e => return Some(Text::Backspace),
            0x1a => {
                if shift {
                    b'{'
                } else {
                    b'['
                }
            }
            0x1b => {
                if shift {
                    b'}'
                } else {
                    b']'
                }
            }
            0x27 => {
                if shift {
                    b':'
                } else {
                    b';'
                }
            }
            0x28 => {
                if shift {
                    b'"'
                } else {
                    b'\''
                }
            }
            0x29 => {
                if shift {
                    b'~'
                } else {
                    b'`'
                }
            }
            0x2b => {
                if shift {
                    b'|'
                } else {
                    b'\\'
                }
            }
            0x33 => {
                if shift {
                    b'<'
                } else {
                    b','
                }
            }
            0x34 => {
                if shift {
                    b'>'
                } else {
                    b'.'
                }
            }
            0x35 => {
                if shift {
                    b'?'
                } else {
                    b'/'
                }
            }
            0x37 => b'*',
            0x39 => b' ',
            0x4a => b'-',
            0x4e => b'+',
            _ => return None,
        };
        Some(Text::Ascii(byte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(decoder: &mut Decoder, bytes: &[u8]) {
        for byte in bytes {
            assert_eq!(decoder.feed(1, *byte), Ok(None));
        }
    }

    #[test]
    fn every_printable_ascii_character_has_a_distinct_make_mapping() {
        let mut seen = [false; 95];
        for shift in [false, true] {
            for code in 1..=0x58 {
                let mut d = Decoder::new();
                if shift {
                    send(&mut d, &[0x2a]);
                }
                if let Some(Text::Ascii(byte)) = d.feed(1, code).unwrap() {
                    assert!((0x20..=0x7e).contains(&byte));
                    seen[usize::from(byte - 0x20)] = true;
                }
            }
        }
        assert!(seen.into_iter().all(|present| present));
    }

    #[test]
    fn both_shift_aliases_and_caps_breaks_preserve_actual_modifier_state() {
        let mut d = Decoder::new();
        send(&mut d, &[0x2a, 0x36, 0xaa]);
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'A'))));
        send(&mut d, &[0xb6]);
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
        send(&mut d, &[0x3a, 0x3a, 0x3a]);
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'A'))));
        assert_eq!(d.feed(1, 0x02), Ok(Some(Text::Ascii(b'1'))));
        send(&mut d, &[0x2a]);
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
        assert_eq!(d.feed(1, 0x02), Ok(Some(Text::Ascii(b'!'))));
        send(&mut d, &[0xaa, 0xba, 0x3a]);
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
    }

    #[test]
    fn left_and_right_ctrl_alt_suppress_text_until_both_aliases_release() {
        for (make, release) in [(0x1d, 0x9d), (0x38, 0xb8)] {
            let mut d = Decoder::new();
            send(&mut d, &[make, 0xe0, make]);
            assert_eq!(d.feed(1, 0x1e), Ok(None));
            assert_eq!(d.feed(1, 0x0e), Ok(None));
            send(&mut d, &[release]);
            assert_eq!(d.feed(1, 0x1e), Ok(None));
            send(&mut d, &[0xe0, release]);
            assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
            assert_eq!(d.feed(1, 0x0e), Ok(Some(Text::Backspace)));
        }
    }

    #[test]
    fn full_and_short_printscreen_pause_and_sysrq_never_forge_shift_or_text() {
        for sequence in [
            &[0xe0, 0x2a, 0xe0, 0x37, 0xe0, 0xb7, 0xe0, 0xaa][..],
            &[0xe0, 0x37, 0xe0, 0xb7][..],
            &[0xe1, 0x1d, 0x45, 0xe1, 0x9d, 0xc5][..],
            &[0xe0, 0x46, 0xe0, 0xc6][..],
            &[0x38, 0xb8, 0x38, 0x54, 0xd4, 0xb8, 0x38, 0xb8][..],
        ] {
            let mut d = Decoder::new();
            send(&mut d, sequence);
            assert!(d.is_complete());
            assert_eq!(d.modifiers(), Modifiers::default());
            assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
        }
        // The shortened break is complete; no mandatory fake-shift suffix.
        let mut d = Decoder::new();
        send(&mut d, &[0xe0, 0xb7]);
        assert_eq!(d.finish(), Ok(()));
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
    }

    #[test]
    fn breaks_never_emit_text_and_typematic_printables_remain_data() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
        assert_eq!(d.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
        send(&mut d, &[0x9e, 0xaa, 0xab]);
        assert_eq!(d.feed(1, 0x0e), Ok(Some(Text::Backspace)));
        send(&mut d, &[0x8e, 0xe0, 0x1c, 0xe0, 0x9c]);
        send(&mut d, &[0x1c, 0x9c, 0x0f, 0x8f, 0x01, 0x81]);
        assert_eq!(d.feed(1, 0xe0), Ok(None));
        assert_eq!(d.feed(1, 0x35), Ok(Some(Text::Ascii(b'/'))));
    }

    #[test]
    fn response_bytes_malformed_aliases_and_controller_errors_latch_failure() {
        for response in [0, 0xff, 0xf0, 0xfa, 0xfe, 0xfc, 0xfd, 0xee] {
            let mut d = Decoder::new();
            assert_eq!(d.feed(1, response), Err(Error::Framing));
            assert_eq!(d.feed(1, 0x1e), Err(Error::Framing));
        }
        for sequence in [
            &[0xe0, 0xe0][..],
            &[0xe0, 0xaa][..],
            &[0xe0, 0x2a, 0xe0, 0x1e][..],
            &[0xe1, 0x1d, 0x44][..],
        ] {
            let mut d = Decoder::new();
            for byte in &sequence[..sequence.len() - 1] {
                assert_eq!(d.feed(1, *byte), Ok(None));
            }
            assert_eq!(d.feed(1, *sequence.last().unwrap()), Err(Error::Framing));
            assert!(!d.is_complete());
            assert_eq!(d.feed(1, 0x1e), Err(Error::Framing));
        }
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x81, 0x1e), Err(Error::Controller));
        assert_eq!(d.finish(), Err(Error::Controller));
    }

    #[test]
    fn partial_sequences_cannot_cross_a_finished_or_restarted_lifetime() {
        for partial in [&[0xe0][..], &[0xe1, 0x1d][..], &[0xe0, 0x2a, 0xe0][..]] {
            let mut d = Decoder::new();
            send(&mut d, partial);
            assert!(!d.is_complete());
            assert_eq!(d.finish(), Err(Error::Incomplete));
            assert_eq!(d.feed(1, 0x1e), Err(Error::Incomplete));
            let mut replacement = Decoder::new();
            assert_eq!(replacement.feed(1, 0x1e), Ok(Some(Text::Ascii(b'a'))));
        }
        let mut d = Decoder::new();
        send(&mut d, &[0xe0]);
        assert_eq!(d.feed(0x21, 0x1e), Ok(None)); // AUX interleaving.
        assert_eq!(d.feed(0, 0x1e), Ok(None));
        assert_eq!(d.feed(1, 0x35), Ok(Some(Text::Ascii(b'/'))));
    }

    #[test]
    fn text_wire_is_canonical_bounded_and_not_an_action_key() {
        for text in (0x20..=0x7e).map(Text::Ascii).chain([Text::Backspace]) {
            for sequence in [1, 0x12345678, u32::MAX - 1] {
                let event = TextEvent { text, sequence };
                let bytes = event.encode().unwrap();
                assert_eq!(TextEvent::decode(bytes), Ok(event));
                assert!(crate::KeyEvent::decode(bytes).is_err());
            }
        }
        for sequence in [0, u32::MAX] {
            assert_eq!(
                TextEvent {
                    text: Text::Backspace,
                    sequence
                }
                .encode(),
                Err(Error::Sequence)
            );
        }
        for byte in [0, 9, 10, 13, 0x1b, 0x7f, 0xff] {
            assert_eq!(
                TextEvent {
                    text: Text::Ascii(byte),
                    sequence: 1
                }
                .encode(),
                Err(Error::Character)
            );
        }
        let valid = TextEvent {
            text: Text::Ascii(b'a'),
            sequence: 1,
        }
        .encode()
        .unwrap();
        for index in [0, 1, 3] {
            let mut bad = valid;
            bad[index] ^= 0x80;
            assert_eq!(TextEvent::decode(bad), Err(Error::Header));
        }
    }
}
