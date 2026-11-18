//! Fixed two-surface composition state. These plans grant no memory access.
//! The actual adapter may read a surface only while its one writer is blocked
//! in that surface's protected Present call. Window/session control reads none.
use crate::protocol::{CursorControl, WindowControl};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Producer {
    App,
    Shell,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Stale,
    Counter,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionReset {
    pub producer: Producer,
    pub epoch: u32,
}
impl SessionReset {
    fn encode(self, op: u8) -> Result<[u8; 8], Error> {
        valid(self.epoch)?;
        let mut bytes = [
            b'D',
            op,
            if self.producer == Producer::App { 1 } else { 2 },
            0,
            0,
            0,
            0,
            0,
        ];
        bytes[4..].copy_from_slice(&self.epoch.to_le_bytes());
        Ok(bytes)
    }
    pub fn request(self) -> Result<[u8; 8], Error> {
        self.encode(1)
    }
    pub fn reply(self) -> Result<[u8; 8], Error> {
        self.encode(2)
    }
    fn parse(bytes: [u8; 8], op: u8) -> Result<Self, Error> {
        if bytes[0] != b'D' || bytes[1] != op || bytes[3] != 0 {
            return Err(Error::Stale);
        }
        let producer = match bytes[2] {
            1 => Producer::App,
            2 => Producer::Shell,
            _ => return Err(Error::Stale),
        };
        let reset = Self {
            producer,
            epoch: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        reset.encode(op)?;
        Ok(reset)
    }
    pub fn parse_request(bytes: [u8; 8]) -> Result<Self, Error> {
        Self::parse(bytes, 1)
    }
    pub fn parse_reply(bytes: [u8; 8]) -> Result<Self, Error> {
        Self::parse(bytes, 2)
    }
}

pub struct State {
    epochs: [u32; 2],
    next: [u32; 2],
    window: u32,
    visible: bool,
    cursor_sequence: u32,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            epochs: [0; 2],
            next: [1; 2],
            window: 0,
            visible: false,
            cursor_sequence: 0,
        }
    }
    pub const fn visible(&self) -> bool {
        self.visible
    }
    /// Root has already stopped the old writer, settled its RPC, detached its
    /// mapping and rebound the route before admitting the new writer. The fixed
    /// Root-only endpoint is mandatory; this integer is only replay protection.
    pub fn reset(&mut self, reset: SessionReset) -> Result<(), Error> {
        valid(reset.epoch)?;
        let i = index(reset.producer);
        if reset.epoch <= self.epochs[i] {
            return Err(Error::Stale);
        }
        self.epochs[i] = reset.epoch;
        self.next[i] = 1;
        if reset.producer == Producer::Shell {
            self.window = 0;
            self.visible = false;
            self.cursor_sequence = 0;
        }
        Ok(())
    }
    pub fn window(&mut self, control: WindowControl) -> Result<(), Error> {
        valid(control.sequence)?;
        if self.epochs[1] == 0
            || (control.visible && self.epochs[0] == 0)
            || self.window.checked_add(1) != Some(control.sequence)
        {
            return Err(Error::Stale);
        }
        self.window = control.sequence;
        self.visible = control.visible;
        Ok(())
    }
    pub fn cursor(&mut self, control: CursorControl) -> Result<(), Error> {
        control.request().map_err(|_| Error::Counter)?;
        if self.epochs[1] == 0
            || self.next[1] <= 1
            || self.cursor_sequence.checked_add(1) != Some(control.sequence)
        {
            return Err(Error::Stale);
        }
        self.cursor_sequence = control.sequence;
        Ok(())
    }
    /// Invoke while servicing the matching actual Present, after validating its
    /// fixed surface header. It never implies ownership of the other surface.
    pub fn present(&mut self, producer: Producer, frame: u32, header: u64) -> Result<(), Error> {
        valid(frame)?;
        let i = index(producer);
        if self.epochs[i] == 0
            || self.next[i] != frame
            || header != u64::from(frame)
            || (producer == Producer::Shell && self.window != frame)
        {
            return Err(Error::Stale);
        }
        self.next[i] = frame
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Counter)?;
        Ok(())
    }
}
fn index(p: Producer) -> usize {
    if p == Producer::App { 0 } else { 1 }
}
fn valid(n: u32) -> Result<(), Error> {
    if n == 0 || n == u32::MAX {
        Err(Error::Counter)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reset(state: &mut State, producer: Producer, epoch: u32) {
        state.reset(SessionReset { producer, epoch }).unwrap();
    }
    #[test]
    fn cursor_requires_actual_shell_present_and_its_sequence_never_advances_surface_credit() {
        let mut s = State::new();
        let cursor = |sequence| CursorControl {
            x: 319,
            y: 199,
            sequence,
        };
        assert_eq!(s.cursor(cursor(1)), Err(Error::Stale));
        reset(&mut s, Producer::Shell, 1);
        assert_eq!(s.cursor(cursor(1)), Err(Error::Stale));
        s.window(WindowControl {
            visible: false,
            sequence: 1,
        })
        .unwrap();
        s.present(Producer::Shell, 1, 1).unwrap();
        s.cursor(cursor(1)).unwrap();
        s.cursor(cursor(2)).unwrap();
        assert_eq!(s.cursor(cursor(2)), Err(Error::Stale));
        assert_eq!(s.cursor(cursor(4)), Err(Error::Stale));
        s.window(WindowControl {
            visible: false,
            sequence: 2,
        })
        .unwrap();
        s.present(Producer::Shell, 2, 2).unwrap();
        reset(&mut s, Producer::App, 1);
        s.cursor(cursor(3)).unwrap();
        reset(&mut s, Producer::Shell, 2);
        assert_eq!(s.cursor(cursor(1)), Err(Error::Stale));
        s.window(WindowControl {
            visible: false,
            sequence: 1,
        })
        .unwrap();
        s.present(Producer::Shell, 1, 1).unwrap();
        s.cursor(cursor(1)).unwrap();
    }
    #[test]
    fn control_cannot_supply_a_present_or_read_credit() {
        let mut state = State::new();
        assert!(
            state
                .window(WindowControl {
                    visible: true,
                    sequence: 1
                })
                .is_err()
        );
        reset(&mut state, Producer::Shell, 1);
        assert!(
            state
                .window(WindowControl {
                    visible: true,
                    sequence: 1
                })
                .is_err()
        );
        state
            .window(WindowControl {
                visible: false,
                sequence: 1,
            })
            .unwrap();
        assert!(state.present(Producer::Shell, 1, 2).is_err());
        assert!(state.present(Producer::App, 1, 1).is_err());
        state.present(Producer::Shell, 1, 1).unwrap();
        assert!(state.present(Producer::Shell, 1, 1).is_err());
    }
    #[test]
    fn independent_writer_replacement_preserves_other_frame_clock() {
        let mut state = State::new();
        reset(&mut state, Producer::App, 1);
        reset(&mut state, Producer::Shell, 1);
        state
            .window(WindowControl {
                visible: true,
                sequence: 1,
            })
            .unwrap();
        state.present(Producer::Shell, 1, 1).unwrap();
        state.present(Producer::App, 1, 1).unwrap();
        reset(&mut state, Producer::App, 2);
        state.present(Producer::App, 1, 1).unwrap();
        state
            .window(WindowControl {
                visible: true,
                sequence: 2,
            })
            .unwrap();
        state.present(Producer::Shell, 2, 2).unwrap();
        reset(&mut state, Producer::Shell, 2);
        assert!(!state.visible());
        state.present(Producer::App, 2, 2).unwrap();
        state
            .window(WindowControl {
                visible: true,
                sequence: 1,
            })
            .unwrap();
        state.present(Producer::Shell, 1, 1).unwrap();
        assert!(
            state
                .reset(SessionReset {
                    producer: Producer::App,
                    epoch: 1
                })
                .is_err()
        );
    }
    #[test]
    fn reset_codec_is_separate_and_strict_about_producer_epoch_and_reply() {
        let r = SessionReset {
            producer: Producer::App,
            epoch: 7,
        };
        assert_eq!(SessionReset::parse_request(r.request().unwrap()), Ok(r));
        assert_eq!(SessionReset::parse_reply(r.reply().unwrap()), Ok(r));
        assert!(SessionReset::parse_reply(r.request().unwrap()).is_err());
        for index in [0, 1, 2, 3] {
            let mut bad = r.request().unwrap();
            bad[index] = 255;
            assert!(SessionReset::parse_request(bad).is_err());
        }
        assert!(
            SessionReset {
                epoch: u32::MAX,
                ..r
            }
            .request()
            .is_err()
        );
    }
}
