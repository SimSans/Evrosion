//! One pending frame, monotonic nonwrapping sequence and persistent held-state
//! barriers. Pending/sequence values carry no capabilities or consent.
use crate::{BarrierReply, InputError, Key, KeyEvent, Keyboard};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Decoder(InputError),
    CounterExhausted,
    Pending,
}
pub struct Stream {
    keyboard: Keyboard,
    sequence: u32,
    pending: Option<KeyEvent>,
    blocked_enters: u8,
    failed: Option<Error>,
}
impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}
impl Stream {
    pub fn new() -> Self {
        Self {
            keyboard: Keyboard::default(),
            sequence: 0,
            pending: None,
            blocked_enters: 0,
            failed: None,
        }
    }
    pub fn pending(&self) -> Option<KeyEvent> {
        self.pending
    }
    /// Clear only after the actual SEND acknowledged acceptance. Full retains it.
    pub fn sent(&mut self) {
        self.pending = None;
    }
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    pub fn at_boundary(&self) -> bool {
        self.failed.is_none() && self.keyboard.at_boundary()
    }
    pub fn push(&mut self, status: u8, data: u8) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        self.feed(status, data, true)
    }
    /// Ready/barrier drain consumes real bytes and updates held/release/sequence
    /// knowledge, but never forwards those stale makes or resets the decoder.
    pub fn discard(&mut self, status: u8, data: u8) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        self.feed(status, data, false)
    }
    fn feed(&mut self, status: u8, data: u8, forward: bool) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let transition = match self.keyboard.transition(status, data) {
            Ok(t) => t,
            Err(error) => {
                let error = Error::Decoder(error);
                self.failed = Some(error);
                return Err(error);
            }
        };
        let Some(transition) = transition else {
            return Ok(());
        };
        if !transition.pressed {
            self.blocked_enters &= !transition.bit;
            return Ok(());
        }
        let next = match self.sequence.checked_add(1).filter(|n| *n != u32::MAX) {
            Some(n) => n,
            None => {
                self.failed = Some(Error::CounterExhausted);
                return Err(Error::CounterExhausted);
            }
        };
        self.sequence = next;
        let known = transition.key == Key::Enter && self.keyboard.release_known(transition.bit);
        let event = KeyEvent {
            key: transition.key,
            sequence: next,
            release_known: known,
            approval_ready: known && self.blocked_enters == 0,
        };
        if forward {
            self.pending = Some(event);
        }
        Ok(())
    }
    pub fn begin_barrier(&mut self) {
        self.pending = None;
        self.blocked_enters |= self.keyboard.held_enters();
    }
    /// Call only after bounded real controller drain/quiet interval completes.
    pub fn barrier_reply(&mut self) -> BarrierReply {
        // Makes may arrive DURING the drain, after begin_barrier's snapshot.
        // Pin all Enter keys still held at the actual reply linearization cut.
        self.blocked_enters |= self.keyboard.held_enters();
        BarrierReply {
            sequence: self.sequence,
            enter: self.keyboard.enter_state(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_initial_make_can_launch_but_only_real_break_makes_approval_eligible() {
        let mut s = Stream::new();
        s.push(1, 0x1c).unwrap();
        let first = s.pending().unwrap();
        assert!(!first.approval_ready);
        s.sent();
        s.begin_barrier();
        assert!(s.barrier_reply().enter.main_held);
        s.push(1, 0x1c).unwrap();
        assert!(s.pending().is_none());
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x1c).unwrap();
        assert!(s.pending().unwrap().approval_ready);
    }
    #[test]
    fn pending_full_frame_survives_retry_and_barrier_drops_it_without_resetting_held() {
        let mut s = Stream::new();
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x1c).unwrap();
        let frame = s.pending();
        assert_eq!(s.push(1, 0x0f), Err(Error::Pending));
        assert_eq!(s.pending(), frame);
        s.begin_barrier();
        s.discard(1, 0x1c).unwrap();
        assert!(s.pending().is_none());
        assert_eq!(s.sequence(), 1);
        s.push(1, 0x1c).unwrap();
        assert!(s.pending().is_none());
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x1c).unwrap();
        assert_eq!(s.pending().unwrap().sequence, 2);
        assert!(s.pending().unwrap().approval_ready);
    }
    #[test]
    fn main_and_keypad_held_keys_cannot_release_or_approve_for_each_other() {
        let mut s = Stream::new();
        for b in [0x9c, 0xe0, 0x9c, 0x1c] {
            s.discard(1, b).unwrap();
        }
        s.begin_barrier();
        s.push(1, 0xe0).unwrap();
        s.push(1, 0x1c).unwrap();
        assert!(!s.pending().unwrap().approval_ready);
        s.sent();
        s.push(1, 0xe0).unwrap();
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x1c).unwrap();
        assert!(s.pending().is_none());
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x1c).unwrap();
        assert!(s.pending().unwrap().approval_ready);
    }
    #[test]
    fn malformed_pause_parity_and_counter_exhaustion_latch_without_guessing() {
        let mut s = Stream::new();
        s.push(1, 0xe1).unwrap();
        assert!(s.push(1, 0x1c).is_err());
        assert!(s.push(1, 0x1c).is_err());
        assert!(s.pending().is_none());
        let mut s = Stream::new();
        assert_eq!(
            s.push(0x81, 0x1c),
            Err(Error::Decoder(InputError::Controller))
        );
        assert!(s.push(1, 0x1c).is_err());
        let mut s = Stream::new();
        s.sequence = u32::MAX - 1;
        assert_eq!(s.push(1, 0x1c), Err(Error::CounterExhausted));
        assert_eq!(s.sequence(), u32::MAX - 1);
        assert!(s.pending().is_none());
        assert_eq!(s.discard(1, 0x9c), Err(Error::CounterExhausted));
    }
    #[test]
    fn makes_arriving_during_drain_are_held_at_the_final_barrier_cut() {
        let mut s = Stream::new();
        for byte in [0x9c, 0xe0, 0x9c] {
            s.discard(1, byte).unwrap();
        }
        s.begin_barrier();
        s.discard(1, 0x1c).unwrap();
        assert!(s.barrier_reply().enter.main_held);
        s.push(1, 0xe0).unwrap();
        s.push(1, 0x1c).unwrap();
        assert!(!s.pending().unwrap().approval_ready);
        s.sent();
        s.push(1, 0xe0).unwrap();
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x9c).unwrap();
        s.push(1, 0xe0).unwrap();
        s.push(1, 0x1c).unwrap();
        assert!(s.pending().unwrap().approval_ready);
    }
}
