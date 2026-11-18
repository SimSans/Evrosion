//! One pending frame, monotonic nonwrapping sequence and persistent held-state
//! barriers. Pending/sequence values carry no capabilities or consent.
use crate::pointer::{Decoder as PointerDecoder, PointerEvent};
use crate::text::{Decoder as TextDecoder, TextEvent};
use crate::{BarrierReply, InputError, Key, KeyEvent, Keyboard, PointerState, SessionBarrierReply};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Decoder(InputError),
    TextDecoder(crate::text::Error),
    PointerDecoder(crate::pointer::Error),
    CounterExhausted,
    Pending,
}
pub struct Stream {
    keyboard: Keyboard,
    sequence: u32,
    pending: Option<KeyEvent>,
    blocked_enters: u8,
    failed: Option<Error>,
    text: Option<TextDecoder>,
    pending_text: Option<TextEvent>,
    pointer: Option<PointerDecoder>,
    pending_pointer: Option<PointerEvent>,
    pointer_state: PointerState,
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
            text: None,
            pending_text: None,
            pointer: None,
            pending_pointer: None,
            pointer_state: PointerState::default(),
        }
    }
    /// Explicit session opt-in. The legacy stream remains action-key only.
    /// Text shares the action-key sequence and barrier; it carries no approval.
    pub fn with_text() -> Self {
        Self {
            text: Some(TextDecoder::default()),
            ..Self::new()
        }
    }
    /// Full session input only after actual cold three-byte mouse admission.
    /// Keyboard, text and pointer share one sequence and one pending credit.
    pub fn with_pointer() -> Self {
        Self {
            pointer: Some(PointerDecoder::new()),
            ..Self::with_text()
        }
    }
    pub fn pending(&self) -> Option<KeyEvent> {
        self.pending
    }
    pub fn pending_text(&self) -> Option<TextEvent> {
        self.pending_text
    }
    pub fn pending_pointer(&self) -> Option<PointerEvent> {
        self.pending_pointer
    }
    /// Clear only after the actual SEND acknowledged acceptance. Full retains it.
    pub fn sent(&mut self) {
        self.pending = None;
        self.pending_text = None;
        self.pending_pointer = None;
    }
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    pub fn at_boundary(&self) -> bool {
        self.failed.is_none()
            && self.keyboard.at_boundary()
            && self.text.as_ref().is_none_or(TextDecoder::is_complete)
            && self
                .pointer
                .as_ref()
                .is_none_or(PointerDecoder::is_complete)
    }
    pub fn push(&mut self, status: u8, data: u8) -> Result<(), Error> {
        if self.has_pending() {
            return Err(Error::Pending);
        }
        self.feed(status, data, true)
    }
    /// Ready/barrier drain consumes real bytes and updates held/release/sequence
    /// knowledge, but never forwards those stale makes or resets the decoder.
    pub fn discard(&mut self, status: u8, data: u8) -> Result<(), Error> {
        if self.has_pending() {
            return Err(Error::Pending);
        }
        self.feed(status, data, false)
    }
    fn feed(&mut self, status: u8, data: u8, forward: bool) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if let Some(decoder) = self.pointer.as_mut() {
            match decoder.feed(status, data) {
                Err(error) => {
                    let error = Error::PointerDecoder(error);
                    self.failed = Some(error);
                    return Err(error);
                }
                Ok(Some(motion)) => {
                    self.pointer_state.held = motion.buttons;
                    self.pointer_state.released |= !motion.buttons & 7;
                    let sequence = self.next_sequence()?;
                    if forward {
                        self.pending_pointer = Some(PointerEvent {
                            dx: motion.dx,
                            dy: motion.dy,
                            buttons: motion.buttons,
                            sequence,
                        });
                    }
                    return Ok(());
                }
                Ok(None) => (),
            }
        }
        let text = match self.text.as_mut().map(|decoder| decoder.feed(status, data)) {
            Some(Err(error)) => {
                let error = Error::TextDecoder(error);
                self.failed = Some(error);
                return Err(error);
            }
            Some(Ok(text)) => text,
            None => None,
        };
        let transition = match self.keyboard.transition(status, data) {
            Ok(t) => t,
            Err(error) => {
                let error = Error::Decoder(error);
                self.failed = Some(error);
                return Err(error);
            }
        };
        let Some(transition) = transition else {
            if let Some(text) = text {
                let sequence = self.next_sequence()?;
                if forward {
                    self.pending_text = Some(TextEvent { text, sequence });
                }
            }
            return Ok(());
        };
        if !transition.pressed {
            self.blocked_enters &= !transition.bit;
            return Ok(());
        }
        let next = self.next_sequence()?;
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
    fn next_sequence(&mut self) -> Result<u32, Error> {
        let next = match self.sequence.checked_add(1).filter(|n| *n != u32::MAX) {
            Some(n) => n,
            None => {
                self.failed = Some(Error::CounterExhausted);
                return Err(Error::CounterExhausted);
            }
        };
        self.sequence = next;
        Ok(next)
    }
    fn has_pending(&self) -> bool {
        self.pending.is_some() || self.pending_text.is_some() || self.pending_pointer.is_some()
    }
    pub fn begin_barrier(&mut self) {
        self.pending = None;
        self.pending_text = None;
        self.pending_pointer = None;
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
    pub fn session_barrier_reply(&mut self) -> SessionBarrierReply {
        let keyboard = self.barrier_reply();
        SessionBarrierReply {
            sequence: keyboard.sequence,
            enter: keyboard.enter,
            pointer: self.pointer_state,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::Text;
    #[test]
    fn new_boot_requires_a_real_enter_break_before_a_later_make_can_approve() {
        let mut boot = Stream::new();
        boot.begin_barrier();
        let snapshot = boot.session_barrier_reply();
        assert!(!snapshot.enter.main_held && !snapshot.enter.main_released);
        boot.push(1, 0x1c).unwrap();
        assert!(!boot.pending().unwrap().approval_ready);
        boot.sent();
        boot.push(1, 0x9c).unwrap();
        assert!(boot.pending().is_none());
        boot.begin_barrier();
        let snapshot = boot.session_barrier_reply();
        assert!(!snapshot.enter.main_held && snapshot.enter.main_released);
        boot.push(1, 0x1c).unwrap();
        assert!(boot.pending().unwrap().approval_ready);
        // A real reference-device break outside the protected dialog also
        // establishes release without an earlier make in this Input lifetime.
        let mut next = Stream::new();
        next.push(1, 0x9c).unwrap();
        next.begin_barrier();
        assert!(next.session_barrier_reply().enter.main_released);
        next.push(1, 0x1c).unwrap();
        assert!(next.pending().unwrap().approval_ready);
    }
    fn packet(s: &mut Stream, buttons: u8, forward: bool) {
        for b in [8 | buttons, 0, 0] {
            if forward {
                s.push(0x21, b)
            } else {
                s.discard(0x21, b)
            }
            .unwrap();
        }
    }
    #[test]
    fn pointer_text_and_keys_share_exact_credit_and_drain_retains_all_button_knowledge() {
        let mut s = Stream::with_pointer();
        s.push(0x21, 8).unwrap();
        s.push(1, 0x1e).unwrap();
        assert_eq!(s.pending_text().unwrap().sequence, 1);
        assert_eq!(s.push(0x21, 0), Err(Error::Pending));
        s.sent();
        s.push(0x21, 0).unwrap();
        s.push(0x21, 0).unwrap();
        assert_eq!(s.pending_pointer().unwrap().sequence, 2);
        assert_eq!(s.push(1, 0x1c), Err(Error::Pending));
        assert_eq!(s.pending_pointer().unwrap().buttons, 0);
        s.sent();
        s.push(1, 0x1c).unwrap();
        assert_eq!(s.pending().unwrap().sequence, 3);
        s.begin_barrier();
        packet(&mut s, 1, false);
        s.discard(1, 0x2a).unwrap();
        s.discard(1, 0x30).unwrap();
        let reply = s.session_barrier_reply();
        assert_eq!(reply.sequence, 5);
        assert!(reply.enter.main_held);
        assert_eq!(
            reply.pointer,
            PointerState {
                held: 1,
                released: 7
            }
        );
        assert!(s.pending_pointer().is_none() && s.pending_text().is_none());
        assert!(s.at_boundary());
        s.discard(1, 0xb0).unwrap();
        s.discard(1, 0xaa).unwrap();
        s.push(1, 0x2e).unwrap();
        assert_eq!(s.pending_text().unwrap().text, Text::Ascii(b'c'));
        assert_eq!(s.pending_text().unwrap().sequence, 6);
        let mut legacy = Stream::new();
        packet(&mut legacy, 1, true);
        assert_eq!(legacy.sequence(), 0);
        assert!(legacy.pending_pointer().is_none());
    }
    #[test]
    fn pointer_partial_corruption_and_sequence_exhaustion_latch_without_reset() {
        let mut s = Stream::with_pointer();
        s.push(0x21, 8).unwrap();
        assert!(!s.at_boundary());
        s.begin_barrier();
        assert!(!s.at_boundary());
        assert_eq!(
            s.discard(0xe1, 0),
            Err(Error::PointerDecoder(crate::pointer::Error::Controller))
        );
        assert!(s.push(1, 0x1c).is_err());
        let mut s = Stream::with_pointer();
        s.sequence = u32::MAX - 1;
        s.push(0x21, 8).unwrap();
        s.push(0x21, 0).unwrap();
        assert_eq!(s.push(0x21, 0), Err(Error::CounterExhausted));
        assert!(s.pending_pointer().is_none());
        assert!(s.discard(0x21, 8).is_err());
    }
    #[test]
    fn text_and_action_keys_share_credit_sequence_and_real_drain_state() {
        let mut s = Stream::with_text();
        s.push(1, 0x2a).unwrap(); // Shift held across the visual barrier.
        s.push(1, 0x1e).unwrap(); // A
        assert_eq!(
            s.pending_text(),
            Some(TextEvent {
                text: Text::Ascii(b'A'),
                sequence: 1
            })
        );
        assert_eq!(s.push(1, 0x0f), Err(Error::Pending));
        s.begin_barrier();
        s.discard(1, 0x9e).unwrap();
        s.discard(1, 0x30).unwrap(); // B arrived during drain: counted, not forwarded.
        assert!(s.pending_text().is_none());
        assert_eq!(s.barrier_reply().sequence, 2);
        s.discard(1, 0xb0).unwrap();
        s.discard(1, 0xaa).unwrap(); // Real Shift release during drain.
        s.push(1, 0x2e).unwrap();
        assert_eq!(
            s.pending_text(),
            Some(TextEvent {
                text: Text::Ascii(b'c'),
                sequence: 3
            })
        );
        s.sent();
        s.push(1, 0x9c).unwrap();
        s.push(1, 0x1c).unwrap();
        assert_eq!(s.pending().unwrap().sequence, 4);
        assert!(s.pending().unwrap().approval_ready);
        assert!(s.pending_text().is_none());
        let mut legacy = Stream::new();
        legacy.push(1, 0x1e).unwrap();
        assert!(legacy.pending_text().is_none());
        assert_eq!(legacy.sequence(), 0);
    }
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
