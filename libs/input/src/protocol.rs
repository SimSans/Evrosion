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
fn key_code(key: Key) -> u8 {
    match key {
        Key::Tab => 1,
        Key::Enter => 2,
        Key::Escape => 3,
        Key::Up => 4,
        Key::Down => 5,
    }
}
fn key(code: u8) -> Result<Key, Error> {
    match code {
        1 => Ok(Key::Tab),
        2 => Ok(Key::Enter),
        3 => Ok(Key::Escape),
        4 => Ok(Key::Up),
        5 => Ok(Key::Down),
        _ => Err(Error::Key),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub key: Key,
    pub sequence: u32,
    pub release_known: bool,
    pub approval_ready: bool,
}
impl KeyEvent {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.sequence == 0 || self.sequence == u32::MAX {
            return Err(Error::Sequence);
        }
        if self.key != Key::Enter && (self.release_known || self.approval_ready)
            || self.approval_ready && !self.release_known
        {
            return Err(Error::Flags);
        }
        let mut b = [
            b'K',
            1,
            key_code(self.key),
            u8::from(self.release_known) | (u8::from(self.approval_ready) << 1),
            0,
            0,
            0,
            0,
        ];
        b[4..].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(b)
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[0] != b'K' || b[1] != 1 {
            return Err(Error::Header);
        }
        if b[3] & !3 != 0 {
            return Err(Error::Flags);
        }
        let event = Self {
            key: key(b[2])?,
            sequence: u32::from_le_bytes(b[4..].try_into().unwrap()),
            release_known: b[3] & 1 != 0,
            approval_ready: b[3] & 2 != 0,
        };
        event.encode()?;
        Ok(event)
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
