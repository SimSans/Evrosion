//! Independent three-byte PS/2 AUX packet decoder. Relative data only: no focus,
//! click eligibility, approval or capability is established by these values.

pub const LEFT: u8 = 1;
pub const RIGHT: u8 = 2;
pub const MIDDLE: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Controller,
    Framing,
    Overflow,
    Incomplete,
    Header,
    Range,
    Buttons,
    Sequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Motion {
    pub dx: i16,
    /// PS/2 positive Y is upward. The compositor chooses display coordinates.
    pub dy: i16,
    pub buttons: u8,
}

fn header(status: u8) -> Result<(), Error> {
    if status & 0x08 == 0 {
        return Err(Error::Framing);
    }
    if status & 0xc0 != 0 {
        return Err(Error::Overflow);
    }
    Ok(())
}

fn motion(packet: [u8; 3]) -> Result<Motion, Error> {
    header(packet[0])?;
    Ok(Motion {
        dx: i16::from(packet[1]) - if packet[0] & 0x10 != 0 { 256 } else { 0 },
        dy: i16::from(packet[2]) - if packet[0] & 0x20 != 0 { 256 } else { 0 },
        buttons: packet[0] & 7,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerEvent {
    pub dx: i16,
    pub dy: i16,
    pub buttons: u8,
    pub sequence: u32,
}

impl PointerEvent {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.sequence == 0 || self.sequence == u32::MAX {
            return Err(Error::Sequence);
        }
        if self.buttons & !7 != 0 {
            return Err(Error::Buttons);
        }
        if !(-256..=255).contains(&self.dx) || !(-256..=255).contains(&self.dy) {
            return Err(Error::Range);
        }
        let flags = 8 | self.buttons | (u8::from(self.dx < 0) << 4) | (u8::from(self.dy < 0) << 5);
        let mut bytes = [b'P', flags, self.dx as u8, self.dy as u8, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if bytes[0] != b'P' {
            return Err(Error::Header);
        }
        let motion = motion([bytes[1], bytes[2], bytes[3]])?;
        let result = Self {
            dx: motion.dx,
            dy: motion.dy,
            buttons: motion.buttons,
            sequence: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        result.encode()?;
        Ok(result)
    }
}

/// Trusted Shell forwarding data: absolute logical coordinates survive movement
/// while an App was obscured. Freshness is established by Shell's separate
/// authenticated Present/barrier path; this packet alone grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionEvent {
    pub x: u16,
    pub y: u8,
    pub buttons: u8,
    pub fresh_left_press: bool,
    pub sequence: u32,
}
impl PositionEvent {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.x >= 320 || self.y >= 200 {
            return Err(Error::Range);
        }
        if self.buttons & !7 != 0 || self.fresh_left_press && self.buttons & LEFT == 0 {
            return Err(Error::Buttons);
        }
        if self.sequence == 0 || self.sequence == u32::MAX {
            return Err(Error::Sequence);
        }
        let mut bytes = [
            b'M',
            0x20 | self.buttons | ((self.x >> 8) as u8) << 3 | u8::from(self.fresh_left_press) << 4,
            self.x as u8,
            self.y,
            0,
            0,
            0,
            0,
        ];
        bytes[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if bytes[0] != b'M' || bytes[1] & 0xe0 != 0x20 {
            return Err(Error::Header);
        }
        let result = Self {
            x: u16::from(bytes[2]) | u16::from((bytes[1] >> 3) & 1) << 8,
            y: bytes[3],
            buttons: bytes[1] & 7,
            fresh_left_press: bytes[1] & 16 != 0,
            sequence: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        result.encode()?;
        Ok(result)
    }
}

/// Only the actual authenticated Input RPC after actual UI Present may create
/// this gate. Drained/initial held buttons require a real subsequent release;
/// neither quiet, a reset nor a repeated held packet constitutes a fresh click.
pub struct FreshGate {
    floor: u32,
    last: u32,
    held: u8,
    released: u8,
    blocked: u8,
}
impl FreshGate {
    pub fn after_barrier(reply: crate::SessionBarrierReply) -> Result<Self, Error> {
        reply.encode().map_err(|_| Error::Buttons)?;
        Ok(Self {
            floor: reply.sequence,
            last: reply.sequence,
            held: reply.pointer.held,
            released: reply.pointer.released,
            blocked: reply.pointer.held,
        })
    }
    /// Returns the independently fresh button-down edges, not a synthetic key.
    pub fn observe(&mut self, event: PointerEvent) -> Result<u8, Error> {
        event.encode()?;
        if event.sequence <= self.floor {
            return Ok(0);
        }
        if event.sequence <= self.last {
            return Err(Error::Sequence);
        }
        self.last = event.sequence;
        let newly_pressed = event.buttons & !self.held;
        let eligible = newly_pressed & self.released & !self.blocked;
        self.blocked &= event.buttons;
        self.released |= !event.buttons & 7;
        self.held = event.buttons;
        Ok(eligible)
    }
}

/// Caller must initialize and verify the mouse's three-byte protocol first.
/// Interleaved keyboard bytes are ignored without disturbing a partial packet.
/// Bad framing/overflow latch; there is no guessed resynchronization or reset.
#[derive(Default)]
pub struct Decoder {
    packet: [u8; 3],
    count: usize,
    failed: Option<Error>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_complete(&self) -> bool {
        self.failed.is_none() && self.count == 0
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.count != 0 {
            self.failed = Some(Error::Incomplete);
            return Err(Error::Incomplete);
        }
        Ok(())
    }

    pub fn feed(&mut self, status: u8, data: u8) -> Result<Option<Motion>, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = self.feed_inner(status, data);
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }

    fn feed_inner(&mut self, status: u8, data: u8) -> Result<Option<Motion>, Error> {
        if status & 0xc0 != 0 {
            return Err(Error::Controller);
        }
        if status & 1 == 0 || status & 0x20 == 0 {
            return Ok(None);
        }
        if self.count == 0 {
            header(data)?;
        }
        self.packet[self.count] = data;
        self.count += 1;
        if self.count != 3 {
            return Ok(None);
        }
        self.count = 0;
        motion(self.packet).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absolute_positions_carry_explicit_fresh_edge_and_never_decode_as_raw_input_or_keys() {
        for x in [0, 255, 256, 319] {
            for y in [0, 199] {
                for buttons in 0..8 {
                    for fresh_left_press in [false, true] {
                        let p = PositionEvent {
                            x,
                            y,
                            buttons,
                            fresh_left_press,
                            sequence: 17,
                        };
                        if fresh_left_press && buttons & LEFT == 0 {
                            assert_eq!(p.encode(), Err(Error::Buttons));
                            continue;
                        }
                        let bytes = p.encode().unwrap();
                        assert_eq!(PositionEvent::decode(bytes), Ok(p));
                        assert!(PointerEvent::decode(bytes).is_err());
                        assert!(crate::KeyEvent::decode(bytes).is_err());
                        for high in [0, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0] {
                            let mut bad = bytes;
                            bad[1] = (bad[1] & 31) | high;
                            assert!(PositionEvent::decode(bad).is_err());
                        }
                    }
                }
            }
        }
        let p = PositionEvent {
            x: 319,
            y: 199,
            buttons: 1,
            fresh_left_press: true,
            sequence: 1,
        };
        assert!(PositionEvent { x: 320, ..p }.encode().is_err());
        assert!(PositionEvent { y: 200, ..p }.encode().is_err());
        assert!(PositionEvent { sequence: 0, ..p }.encode().is_err());
        assert!(
            PositionEvent {
                sequence: u32::MAX,
                ..p
            }
            .encode()
            .is_err()
        );
    }
    #[test]
    fn held_or_initial_unknown_button_needs_real_release_then_new_post_barrier_make() {
        for pointer in [
            crate::PointerState {
                held: 1,
                released: 7,
            },
            crate::PointerState {
                held: 0,
                released: 0,
            },
        ] {
            let mut gate = FreshGate::after_barrier(crate::SessionBarrierReply {
                sequence: 10,
                enter: crate::EnterState::default(),
                pointer,
            })
            .unwrap();
            let event = |buttons, sequence| PointerEvent {
                dx: 0,
                dy: 0,
                buttons,
                sequence,
            };
            assert_eq!(gate.observe(event(0, 9)), Ok(0)); // stale release is no evidence
            assert_eq!(gate.observe(event(1, 11)), Ok(0));
            assert_eq!(gate.observe(event(1, 12)), Ok(0));
            assert_eq!(gate.observe(event(0, 13)), Ok(0));
            assert_eq!(gate.observe(event(1, 14)), Ok(1));
            assert_eq!(gate.observe(event(1, 15)), Ok(0));
            assert_eq!(gate.observe(event(0, 15)), Err(Error::Sequence));
        }
    }

    #[test]
    fn complete_packets_preserve_signed_nine_bit_deltas_and_all_three_buttons() {
        for buttons in 0..8 {
            for dx in [-256_i16, -255, -129, -128, -1, 0, 1, 127, 128, 255] {
                for dy in [-256_i16, -255, -129, -128, -1, 0, 1, 127, 128, 255] {
                    let event = PointerEvent {
                        dx,
                        dy,
                        buttons,
                        sequence: 7,
                    };
                    let bytes = event.encode().unwrap();
                    assert_eq!(PointerEvent::decode(bytes), Ok(event));
                    let mut decoder = Decoder::new();
                    assert_eq!(decoder.feed(0x21, bytes[1]), Ok(None));
                    assert_eq!(decoder.feed(0x21, bytes[2]), Ok(None));
                    assert_eq!(
                        decoder.feed(0x21, bytes[3]),
                        Ok(Some(Motion { dx, dy, buttons }))
                    );
                    assert!(decoder.is_complete());
                    assert!(crate::KeyEvent::decode(bytes).is_err());
                }
            }
        }
    }

    #[test]
    fn keyboard_and_empty_status_do_not_consume_partial_aux_packets() {
        let mut decoder = Decoder::new();
        assert_eq!(decoder.feed(0x21, 0x29), Ok(None));
        assert_eq!(decoder.feed(1, 0x1e), Ok(None));
        assert_eq!(decoder.feed(0, 0xff), Ok(None));
        assert_eq!(decoder.feed(0x21, 127), Ok(None));
        assert_eq!(decoder.feed(1, 0x9e), Ok(None));
        assert_eq!(
            decoder.feed(0x21, 0xff),
            Ok(Some(Motion {
                dx: 127,
                dy: -1,
                buttons: LEFT
            }))
        );
    }

    #[test]
    fn overflow_and_bad_framing_never_guess_a_new_packet_boundary() {
        for first in [0, 1, 7, 0xfa, 0xaa, 0x48, 0x88, 0xc8] {
            let mut decoder = Decoder::new();
            let expected = if first & 8 == 0 {
                Error::Framing
            } else {
                Error::Overflow
            };
            assert_eq!(decoder.feed(0x21, first), Err(expected));
            for byte in [8, 0, 0] {
                assert_eq!(decoder.feed(0x21, byte), Err(expected));
            }
            assert!(!decoder.is_complete());
        }
    }

    #[test]
    fn command_reply_values_are_legal_only_as_packet_payload_bytes() {
        let mut decoder = Decoder::new();
        assert_eq!(decoder.feed(0x21, 8), Ok(None));
        assert_eq!(decoder.feed(0x21, 0xfa), Ok(None));
        assert_eq!(
            decoder.feed(0x21, 0xaa),
            Ok(Some(Motion {
                dx: 250,
                dy: 170,
                buttons: 0
            }))
        );
        // Header validation, not a data-byte blacklist, distinguishes replies.
        assert_eq!(decoder.feed(0x21, 0xfa), Err(Error::Overflow));
    }

    #[test]
    fn partial_packets_and_controller_errors_require_supervised_replacement() {
        for count in [1, 2] {
            let mut decoder = Decoder::new();
            decoder.feed(0x21, 8).unwrap();
            if count == 2 {
                decoder.feed(0x21, 1).unwrap();
            }
            assert_eq!(decoder.finish(), Err(Error::Incomplete));
            assert_eq!(decoder.feed(0x21, 8), Err(Error::Incomplete));
            let replacement = Decoder::new();
            assert!(replacement.is_complete());
        }
        let mut decoder = Decoder::new();
        decoder.feed(0x21, 8).unwrap();
        assert_eq!(decoder.feed(0xe1, 1), Err(Error::Controller));
        assert_eq!(decoder.finish(), Err(Error::Controller));
    }

    #[test]
    fn pointer_wire_refuses_extra_buttons_ranges_overflow_and_bad_sequence() {
        let base = PointerEvent {
            dx: 1,
            dy: -1,
            buttons: MIDDLE,
            sequence: 1,
        };
        for (dx, dy) in [(256, 0), (-257, 0), (0, 256), (0, -257)] {
            assert_eq!(PointerEvent { dx, dy, ..base }.encode(), Err(Error::Range));
        }
        for buttons in [8, 16, 255] {
            assert_eq!(
                PointerEvent { buttons, ..base }.encode(),
                Err(Error::Buttons)
            );
        }
        for sequence in [0, u32::MAX] {
            assert_eq!(
                PointerEvent { sequence, ..base }.encode(),
                Err(Error::Sequence)
            );
        }
        for status in 0..=255_u8 {
            let mut bytes = base.encode().unwrap();
            bytes[1] = status;
            let decoded = PointerEvent::decode(bytes);
            assert_eq!(decoded.is_ok(), status & 8 != 0 && status & 0xc0 == 0);
        }
        let mut bad = base.encode().unwrap();
        bad[0] = b'K';
        assert_eq!(PointerEvent::decode(bad), Err(Error::Header));
    }
}
