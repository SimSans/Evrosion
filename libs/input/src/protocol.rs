//! Freshness metadata only. Neither a key frame nor a barrier snapshot proves
//! consent, sender identity, display provenance or object authority.
use crate::Key;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Key,
    Flags,
    Sequence,
    Nonce,
    Replay,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub key: Key,
    pub sequence: u32,
    pub release_known: bool,
    pub approval_ready: bool,
}
fn generated_error(error: ev_userspace_contract::focused_input::Error) -> Error {
    use ev_userspace_contract::focused_input::Error as E;
    match error {
        E::Key => Error::Key,
        E::Flags => Error::Flags,
        E::Sequence => Error::Sequence,
        E::Length | E::Header | E::CapabilityCount => Error::Header,
    }
}
impl KeyEvent {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        ev_userspace_contract::focused_input::KeyEvent {
            key: self.key,
            sequence: self.sequence,
            release_known: self.release_known,
            approval_ready: self.approval_ready,
        }
        .encode()
        .map_err(generated_error)
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        let event = ev_userspace_contract::focused_input::KeyEvent::decode(&b, 0)
            .map_err(generated_error)?;
        Ok(Self {
            key: event.key,
            sequence: event.sequence,
            release_known: event.release_known,
            approval_ready: event.approval_ready,
        })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnterState {
    pub main_released: bool,
    pub keypad_released: bool,
    pub main_held: bool,
    pub keypad_held: bool,
}
impl EnterState {
    fn flags(self) -> u8 {
        u8::from(self.main_released)
            | (u8::from(self.keypad_released) << 1)
            | (u8::from(self.main_held) << 2)
            | (u8::from(self.keypad_held) << 3)
    }
    fn from_flags(flags: u8) -> Self {
        Self {
            main_released: flags & 1 != 0,
            keypad_released: flags & 2 != 0,
            main_held: flags & 4 != 0,
            keypad_held: flags & 8 != 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarrierRequest {
    nonce: u32,
}
impl BarrierRequest {
    pub fn new(nonce: u32) -> Result<Self, Error> {
        if nonce == u32::MAX {
            Err(Error::Nonce)
        } else {
            Ok(Self { nonce })
        }
    }
    pub const fn nonce(self) -> u32 {
        self.nonce
    }
    pub fn encode(self) -> [u8; 8] {
        let mut b = *b"KBR1\0\0\0\0";
        b[4..].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if &b[..4] != b"KBR1" {
            return Err(Error::Header);
        }
        Self::new(u32::from_le_bytes(b[4..].try_into().unwrap()))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarrierReply {
    pub sequence: u32,
    pub enter: EnterState,
}
impl BarrierReply {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.sequence == u32::MAX {
            return Err(Error::Sequence);
        }
        let mut b = [b'B', 1, self.enter.flags(), 0, 0, 0, 0, 0];
        b[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(b)
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[0] != b'B' || b[1] != 1 {
            return Err(Error::Header);
        }
        if b[2] & !15 != 0 || b[3] != 0 {
            return Err(Error::Flags);
        }
        let result = Self {
            sequence: u32::from_le_bytes(b[4..].try_into().unwrap()),
            enter: EnterState::from_flags(b[2]),
        };
        result.encode()?;
        Ok(result)
    }
}
/// Explicit session opt-in; legacy KBR1/B1 bytes remain unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBarrierRequest {
    nonce: u32,
}
impl SessionBarrierRequest {
    pub fn new(nonce: u32) -> Result<Self, Error> {
        BarrierRequest::new(nonce)?;
        Ok(Self { nonce })
    }
    pub const fn nonce(self) -> u32 {
        self.nonce
    }
    pub fn encode(self) -> [u8; 8] {
        let mut bytes = *b"KBR2\0\0\0\0";
        bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if &bytes[..4] != b"KBR2" {
            return Err(Error::Header);
        }
        Self::new(u32::from_le_bytes(bytes[4..].try_into().unwrap()))
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointerState {
    pub held: u8,
    /// A complete actual packet has observed this button released. Reset/quiet
    /// alone never supplies this knowledge; held and released may both be set.
    pub released: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBarrierReply {
    pub sequence: u32,
    pub enter: EnterState,
    pub pointer: PointerState,
}
impl SessionBarrierReply {
    pub fn keyboard(self) -> BarrierReply {
        BarrierReply {
            sequence: self.sequence,
            enter: self.enter,
        }
    }
    pub fn encode(self) -> Result<[u8; 8], Error> {
        self.keyboard().encode()?;
        if (self.pointer.held | self.pointer.released) & !7 != 0 {
            return Err(Error::Flags);
        }
        let mut bytes = [
            b'B',
            2,
            self.enter.flags(),
            self.pointer.held | self.pointer.released << 3,
            0,
            0,
            0,
            0,
        ];
        bytes[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if bytes[0] != b'B' || bytes[1] != 2 {
            return Err(Error::Header);
        }
        if bytes[2] & !15 != 0 || bytes[3] & !63 != 0 {
            return Err(Error::Flags);
        }
        let result = Self {
            sequence: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
            enter: EnterState::from_flags(bytes[2]),
            pointer: PointerState {
                held: bytes[3] & 7,
                released: bytes[3] >> 3,
            },
        };
        result.encode()?;
        Ok(result)
    }
}
/// The caller must obtain the snapshot from an actual authenticated Input RPC
/// AFTER trusted UI Present. This reducer is no proof of either precondition.
pub struct FreshGate {
    floor: u32,
    last: u32,
    active: bool,
}
impl FreshGate {
    pub fn after_barrier(reply: BarrierReply) -> Result<Self, Error> {
        reply.encode()?;
        Ok(Self {
            floor: reply.sequence,
            last: reply.sequence,
            active: true,
        })
    }
    pub fn cancel(&mut self) {
        self.active = false;
    }
    pub fn observe(&mut self, event: KeyEvent) -> Result<Option<Key>, Error> {
        if !self.active {
            return Err(Error::Cancelled);
        }
        event.encode()?;
        if event.sequence <= self.floor {
            return Ok(None);
        }
        if event.sequence <= self.last {
            return Err(Error::Replay);
        }
        self.last = event.sequence;
        if event.key == Key::Enter && !event.approval_ready {
            return Ok(None);
        }
        Ok(Some(event.key))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_barrier_binds_real_button_state_without_changing_v1_golden_bytes() {
        let legacy = BarrierReply {
            sequence: 0x04030201,
            enter: EnterState {
                main_released: true,
                keypad_released: false,
                main_held: true,
                keypad_held: false,
            },
        };
        assert_eq!(legacy.encode(), Ok([b'B', 1, 5, 0, 1, 2, 3, 4]));
        assert_eq!(
            BarrierRequest::new(0x04030201).unwrap().encode(),
            [b'K', b'B', b'R', b'1', 1, 2, 3, 4]
        );
        for held in 0..8 {
            for released in 0..8 {
                let reply = SessionBarrierReply {
                    sequence: legacy.sequence,
                    enter: legacy.enter,
                    pointer: PointerState { held, released },
                };
                let bytes = reply.encode().unwrap();
                assert_eq!(SessionBarrierReply::decode(bytes), Ok(reply));
                assert!(BarrierReply::decode(bytes).is_err());
                assert_eq!(reply.keyboard(), legacy);
                for (index, mask) in [(2, 16), (3, 64), (3, 128)] {
                    let mut bad = bytes;
                    bad[index] |= mask;
                    assert!(SessionBarrierReply::decode(bad).is_err());
                }
            }
        }
        assert!(SessionBarrierReply::decode(legacy.encode().unwrap()).is_err());
        let request = SessionBarrierRequest::new(7).unwrap();
        assert_eq!(SessionBarrierRequest::decode(request.encode()), Ok(request));
        assert!(BarrierRequest::decode(request.encode()).is_err());
        assert!(SessionBarrierRequest::new(u32::MAX).is_err());
    }
    #[test]
    fn canonical_key_and_barrier_frames_are_total_and_reject_reserved_combinations() {
        let event = KeyEvent {
            key: Key::Enter,
            sequence: 7,
            release_known: true,
            approval_ready: true,
        };
        let encoded = event.encode().unwrap();
        assert_eq!(KeyEvent::decode(encoded), Ok(event));
        for i in 0..4 {
            let mut bad = encoded;
            bad[i] = 255;
            assert!(KeyEvent::decode(bad).is_err());
        }
        for flags in [2, 4, 255] {
            let mut bad = encoded;
            bad[3] = flags;
            assert!(KeyEvent::decode(bad).is_err());
        }
        for sequence in [0, u32::MAX] {
            assert!(KeyEvent { sequence, ..event }.encode().is_err());
        }
        assert!(
            KeyEvent {
                key: Key::Tab,
                ..event
            }
            .encode()
            .is_err()
        );
        for flags in 0..16 {
            let reply = BarrierReply {
                sequence: 7,
                enter: EnterState::from_flags(flags),
            };
            assert_eq!(BarrierReply::decode(reply.encode().unwrap()), Ok(reply));
        }
        let request = BarrierRequest::new(42).unwrap();
        assert_eq!(BarrierRequest::decode(request.encode()), Ok(request));
        assert!(BarrierRequest::new(u32::MAX).is_err());
        for n in 0..2048u64 {
            let b = n.wrapping_mul(0x9e3779b97f4a7c15).to_le_bytes();
            let _ = KeyEvent::decode(b);
            let _ = BarrierRequest::decode(b);
            let _ = BarrierReply::decode(b);
        }
    }
    #[test]
    fn fresh_gate_discards_old_frames_refuses_unknown_repeat_and_cancels_on_lifetime_change() {
        let mut gate = FreshGate::after_barrier(BarrierReply {
            sequence: 4,
            enter: EnterState::default(),
        })
        .unwrap();
        let mut event = KeyEvent {
            key: Key::Enter,
            sequence: 4,
            release_known: true,
            approval_ready: true,
        };
        assert_eq!(gate.observe(event), Ok(None));
        event.sequence = 5;
        event.release_known = false;
        event.approval_ready = false;
        assert_eq!(gate.observe(event), Ok(None));
        event.sequence = 6;
        event.release_known = true;
        event.approval_ready = true;
        assert_eq!(gate.observe(event), Ok(Some(Key::Enter)));
        assert_eq!(gate.observe(event), Err(Error::Replay));
        gate.cancel();
        event.sequence = 7;
        assert_eq!(gate.observe(event), Err(Error::Cancelled));
    }
}
