//! Internal M8 eight-byte App control/events. The installed Root-only control
//! route and actual focus/input policy authenticate delivery; bytes do not.
/// Dedicated Editor cancellation intent over existing Activate. It must never
/// fall back to Close when a delayed Root Saving observation becomes stale.
pub const EDITOR_CANCEL_SAVE_ACTION: u16 = 9002;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Opcode,
    Reserved,
    Value,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Navigation {
    Left = 1,
    Right = 2,
    Up = 3,
    Down = 4,
    Home = 5,
    End = 6,
    Backspace = 7,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReleaseMode {
    KeepDocument = 1,
    CloseSaved = 2,
    Discard = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Configure {
        instance: u8,
        mapping_epoch: u32,
    },
    Insert(char),
    Navigate {
        key: Navigation,
        extend: bool,
    },
    Save,
    SelectAll,
    Close {
        discard: bool,
    },
    Scroll(i16),
    Focus(bool),
    Activate(u16),
    Resize {
        width: u16,
        height: u16,
    },
    ScenePart {
        high: bool,
        word: u32,
    },
    /// Root-fed bounded Inspector snapshot data; metrics/IDs are descriptive.
    InfoWord {
        field: u8,
        high: bool,
        word: u32,
    },
    ReleaseFile {
        nonce: u32,
        mode: ReleaseMode,
    },
}
impl Command {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        let (op, flags, value) = match self {
            Self::Configure {
                instance,
                mapping_epoch,
            } => {
                // Instance0 is Shell only. Every actor must enforce its own
                // actual role (Files1/Editors2,3/Inspector4/Shell0).
                if instance > 4 || matches!(mapping_epoch, 0 | u32::MAX) {
                    return Err(Error::Value);
                }
                (1, instance, mapping_epoch)
            }
            Self::Insert(c) => {
                if c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
                    return Err(Error::Value);
                }
                (2, 0, c as u32)
            }
            Self::Navigate { key, extend } => (3, u8::from(extend), key as u32),
            Self::Save => (4, 0, 0),
            Self::SelectAll => (5, 0, 0),
            Self::Close { discard } => (6, u8::from(discard), 0),
            Self::Scroll(n) => (7, 0, i32::from(n) as u32),
            Self::Focus(value) => (8, u8::from(value), 0),
            Self::Activate(node) => (9, 0, u32::from(node)),
            Self::Resize { width, height } => {
                if width == 0 || width > 320 || height == 0 || height > 200 {
                    return Err(Error::Value);
                }
                (10, 0, u32::from(width) | (u32::from(height) << 16))
            }
            Self::ScenePart { high, word } => (11, u8::from(high), word),
            Self::InfoWord { field, high, word } => {
                if field > 127 {
                    return Err(Error::Value);
                }
                (12, field | (u8::from(high) << 7), word)
            }
            Self::ReleaseFile { nonce, mode } => {
                if matches!(nonce, 0 | u32::MAX) {
                    return Err(Error::Value);
                }
                (13, mode as u8, nonce)
            }
        };
        let mut b = [b'W', 1, op, flags, 0, 0, 0, 0];
        b[4..].copy_from_slice(&value.to_le_bytes());
        Ok(b)
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[..2] != [b'W', 1] {
            return Err(Error::Header);
        }
        let value = u32::from_le_bytes(b[4..].try_into().unwrap());
        let c = match b[2] {
            1 => Self::Configure {
                instance: b[3],
                mapping_epoch: value,
            },
            2 => Self::Insert(char::from_u32(value).ok_or(Error::Value)?),
            3 => Self::Navigate {
                key: match value {
                    1 => Navigation::Left,
                    2 => Navigation::Right,
                    3 => Navigation::Up,
                    4 => Navigation::Down,
                    5 => Navigation::Home,
                    6 => Navigation::End,
                    7 => Navigation::Backspace,
                    _ => return Err(Error::Value),
                },
                extend: b[3] == 1,
            },
            4 => Self::Save,
            5 => Self::SelectAll,
            6 => Self::Close { discard: b[3] == 1 },
            7 => Self::Scroll(i16::try_from(value as i32).map_err(|_| Error::Value)?),
            8 => Self::Focus(b[3] == 1),
            9 => Self::Activate(u16::try_from(value).map_err(|_| Error::Value)?),
            10 => Self::Resize {
                width: value as u16,
                height: (value >> 16) as u16,
            },
            11 => Self::ScenePart {
                high: b[3] == 1,
                word: value,
            },
            12 => Self::InfoWord {
                field: b[3] & 127,
                high: b[3] & 128 != 0,
                word: value,
            },
            13 => Self::ReleaseFile {
                nonce: value,
                mode: match b[3] {
                    1 => ReleaseMode::KeepDocument,
                    2 => ReleaseMode::CloseSaved,
                    3 => ReleaseMode::Discard,
                    _ => return Err(Error::Value),
                },
            },
            _ => return Err(Error::Opcode),
        };
        if c.encode()? != b {
            return Err(Error::Reserved);
        }
        Ok(c)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    NoFile = 1,
    Loading = 2,
    Saved = 3,
    Dirty = 4,
    Saving = 5,
    Uncertain = 6,
    Conflict = 7,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Ready(u8),
    State(State),
    Open,
    SaveAs,
    CloseNeedsDiscard,
    Closed,
    Refused(u8),
    /// Ordinary actual-origin Inspector intent, never approval or a raw PID
    /// lookup. Root joins current snapshot + actual gesture/actor/model first.
    InspectAction {
        action: u8,
        row: u8,
        view: u32,
    },
    /// Ordinary Shell window request. Root owns actual focus/gesture policy.
    Window(u8),
    /// An actual-origin App protocol acknowledgment, never a Kernel drain or
    /// revocation proof. Root must still retire/fence the old SEND derivations
    /// and accepted RPCs before reusing a route or changing its bound object.
    Released {
        nonce: u32,
    },
}
impl Event {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        let (op, value) = match self {
            Self::Ready(n) => {
                if n > 4 {
                    return Err(Error::Value);
                }
                (1, n)
            }
            Self::State(s) => (2, s as u8),
            Self::Open => (3, 0),
            Self::SaveAs => (4, 0),
            Self::CloseNeedsDiscard => (5, 0),
            Self::Closed => (6, 0),
            Self::Refused(n) => (7, n),
            Self::InspectAction { action, row, view } => {
                if !(1..=13).contains(&action)
                    || row >= inspector::ROWS
                    || matches!(view, 0 | u32::MAX)
                    || (!inspector::row_action(action) && row != 0)
                {
                    return Err(Error::Value);
                }
                let mut b = [b'E', 5, 8, (action << 4) | row, 0, 0, 0, 0];
                b[4..].copy_from_slice(&view.to_le_bytes());
                return Ok(b);
            }
            Self::Window(instance) => {
                if !(1..=4).contains(&instance) {
                    return Err(Error::Value);
                }
                (9, instance)
            }
            Self::Released { nonce } => {
                if matches!(nonce, 0 | u32::MAX) {
                    return Err(Error::Value);
                }
                let mut b = [b'E', 5, 10, 0, 0, 0, 0, 0];
                b[4..].copy_from_slice(&nonce.to_le_bytes());
                return Ok(b);
            }
        };
        Ok([b'E', 5, op, value, 0, 0, 0, 0])
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[..2] != [b'E', 5] {
            return Err(Error::Header);
        }
        let e = match b[2] {
            1 => Self::Ready(b[3]),
            2 => Self::State(match b[3] {
                1 => State::NoFile,
                2 => State::Loading,
                3 => State::Saved,
                4 => State::Dirty,
                5 => State::Saving,
                6 => State::Uncertain,
                7 => State::Conflict,
                _ => return Err(Error::Value),
            }),
            3 => Self::Open,
            4 => Self::SaveAs,
            5 => Self::CloseNeedsDiscard,
            6 => Self::Closed,
            7 => Self::Refused(b[3]),
            8 => Self::InspectAction {
                action: b[3] >> 4,
                row: b[3] & 15,
                view: u32::from_le_bytes(b[4..].try_into().unwrap()),
            },
            9 => Self::Window(b[3]),
            10 => Self::Released {
                nonce: u32::from_le_bytes(b[4..].try_into().unwrap()),
            },
            _ => return Err(Error::Opcode),
        };
        if e.encode()? != b {
            return Err(Error::Reserved);
        }
        Ok(e)
    }
}
/// Snapshot fields are exact u64 low/high pairs. Root publishes an interval,
/// not an atomic system census. Missing/partial words never become zero stats.
pub mod inspector {
    pub const ROWS: u8 = 6;
    pub const METRICS: u8 = 12;
    pub const VIEW: u8 = 0;
    pub const PAGE: u8 = 73;
    pub const TOTAL_ROWS: u8 = 74;
    pub const SAMPLE_START: u8 = 75;
    pub const SAMPLE_END: u8 = 76;
    pub const LAYER: u8 = 120;
    pub const SCALE: u8 = 121;
    pub const CONTRAST: u8 = 122;
    pub const FOCUS_STYLE: u8 = 123;
    pub const FILE_PERMISSIONS: u8 = 124;
    pub const PHASE: u8 = 125;
    pub const COMMIT: u8 = 127;
    pub const fn row_field(row: u8, metric: u8) -> Option<u8> {
        if row < ROWS && metric < METRICS {
            Some(1 + row * METRICS + metric)
        } else {
            None
        }
    }
    pub const fn required(field: u8) -> bool {
        field <= 76 || (field >= 120 && field <= 125)
    }
    pub const fn row_action(action: u8) -> bool {
        action >= 4 && action <= 7
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_commands_events_unicode_and_reserved_bits() {
        for c in [
            Command::Configure {
                instance: 3,
                mapping_epoch: 7,
            },
            Command::Insert('é'),
            Command::Insert('\n'),
            Command::Navigate {
                key: Navigation::Up,
                extend: true,
            },
            Command::Save,
            Command::SelectAll,
            Command::Close { discard: true },
            Command::Scroll(-12),
            Command::Focus(false),
            Command::Activate(123),
            Command::ReleaseFile {
                nonce: 123,
                mode: ReleaseMode::KeepDocument,
            },
            Command::Configure {
                instance: 0,
                mapping_epoch: 7,
            },
            Command::InfoWord {
                field: 127,
                high: true,
                word: 0xfeed_beef,
            },
        ] {
            let b = c.encode().unwrap();
            assert_eq!(Command::decode(b), Ok(c));
            let mut bad = b;
            bad[1] = 9;
            assert!(Command::decode(bad).is_err());
        }
        for event in [
            Event::Ready(2),
            Event::State(State::Uncertain),
            Event::Open,
            Event::SaveAs,
            Event::CloseNeedsDiscard,
            Event::Closed,
            Event::Refused(5),
            Event::Released { nonce: 123 },
            Event::Ready(0),
            Event::Window(4),
            Event::InspectAction {
                action: 5,
                row: 5,
                view: 0xfedc_ba98,
            },
        ] {
            assert_eq!(Event::decode(event.encode().unwrap()), Ok(event));
        }
        let mut bad = Command::Save.encode().unwrap();
        bad[4] = 1;
        assert!(Command::decode(bad).is_err());
        assert!(
            Command::InfoWord {
                field: 128,
                high: false,
                word: 0
            }
            .encode()
            .is_err()
        );
        for event in [
            Event::Window(0),
            Event::InspectAction {
                action: 14,
                row: 0,
                view: 1,
            },
            Event::InspectAction {
                action: 1,
                row: 1,
                view: 1,
            },
            Event::InspectAction {
                action: 5,
                row: 6,
                view: 1,
            },
            Event::InspectAction {
                action: 5,
                row: 0,
                view: u32::MAX,
            },
        ] {
            assert!(event.encode().is_err());
        }
        let mut bad = Command::Navigate {
            key: Navigation::Left,
            extend: false,
        }
        .encode()
        .unwrap();
        bad[3] = 2;
        assert!(Command::decode(bad).is_err());
    }
}
