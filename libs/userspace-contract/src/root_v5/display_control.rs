//! Strict Root-only Display control bytes. The separate installed receiver10,
//! actual serving origin and immutable control loan authenticate the sender;
//! no opcode, logical ID, request or claimed Root label supplies authority.
use super::{
    Error, Role, put,
    surface::{Producer, Registration},
    word,
};
pub const SIZE: usize = 256;
pub const OFFSET: usize = 256;
pub const DENIED: u64 = u64::MAX;
const REPLY_MAGIC: u64 = 0x4556_4435_0000_0000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Slot {
    Files = 0,
    EditorOne = 1,
    EditorTwo = 2,
    Inspector = 3,
    Shell = 4,
    ProtectedRoot = 5,
}
pub const SLOTS: [Slot; 6] = [
    Slot::Files,
    Slot::EditorOne,
    Slot::EditorTwo,
    Slot::Inspector,
    Slot::Shell,
    Slot::ProtectedRoot,
];
impl Slot {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn from_index(index: u8) -> Option<Self> {
        if index < 6 {
            Some(SLOTS[index as usize])
        } else {
            None
        }
    }
    pub const fn source(self) -> Role {
        [
            Role::FilesSurface,
            Role::EditorOneSurface,
            Role::EditorTwoSurface,
            Role::InspectorSurface,
            Role::ShellSurface,
            Role::ProtectedSurface,
        ][self.index()]
    }
    pub const fn producer(self) -> Producer {
        match self {
            Self::Shell => Producer::Shell,
            Self::ProtectedRoot => Producer::ProtectedRoot,
            _ => Producer::Application,
        }
    }
    pub const fn instance(self) -> u16 {
        match self {
            Self::Files => 1,
            Self::EditorOne => 2,
            Self::EditorTwo => 3,
            Self::Inspector => 4,
            _ => 0,
        }
    }
    pub const fn pages(self) -> u64 {
        if matches!(self, Self::ProtectedRoot) {
            51
        } else {
            63
        }
    }
    pub const fn first_page(self) -> u64 {
        [64, 128, 192, 256, 320, 384][self.index()]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}
impl Bounds {
    pub fn valid_for(self, slot: Slot) -> bool {
        match slot {
            Slot::Shell => {
                self == Self {
                    x: 0,
                    y: 462,
                    width: 640,
                    height: 18,
                }
            }
            Slot::ProtectedRoot => {
                self == Self {
                    x: 0,
                    y: 0,
                    width: 640,
                    height: 80,
                }
            }
            _ => {
                self.x >= 0
                    && self.y >= 91
                    && self.width != 0
                    && self.height != 0
                    && self.width <= 320
                    && self.height <= 180
                    && i64::from(self.x) + i64::from(self.width) <= 640
                    && i64::from(self.y) + i64::from(self.height) <= 462
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preferences {
    pub scale: u8,
    pub high_contrast: bool,
    pub thick_focus: bool,
}
impl Preferences {
    pub fn valid(self) -> bool {
        (1..=4).contains(&self.scale)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub slot: Slot,
    pub registration: Registration,
    pub bounds: Bounds,
    pub z: u8,
    pub visible: bool,
    /// Root may bind an exact semantic revision once that native provider exists.
    /// Otherwise this is a monotonic floor, not a semantic-completeness claim.
    pub view_revision: u64,
    pub strict_view: bool,
    pub focused: bool,
}
impl Window {
    pub fn valid(self) -> Result<(), Error> {
        self.registration.encode()?;
        if self.registration.source_role != self.slot.source()
            || self.registration.producer != self.slot.producer()
            || self.registration.instance != self.slot.instance()
            || !self.bounds.valid_for(self.slot)
            || (self.slot.index() < 4 && self.z > 3)
            || (self.slot.index() >= 4 && usize::from(self.z) != self.slot.index())
            || self.view_revision == u64::MAX
            || (self.strict_view && self.view_revision == 0)
            || (self.focused && self.slot.index() >= 4)
        {
            return Err(Error::Profile);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Begin {
        transaction: u64,
        model_revision: u64,
        preferences: Preferences,
    },
    Register {
        transaction: u64,
        window: Window,
    },
    Remove {
        transaction: u64,
        slot: Slot,
    },
    Commit {
        transaction: u64,
    },
    Abort {
        transaction: u64,
    },
    /// Fields0mask/1model/2frame/3view/4mapEpoch, exact retained state only.
    Inspect {
        slot: Slot,
        field: u8,
    },
    Cursor {
        x: u16,
        y: u16,
        visible: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub request: u64,
    pub command: Command,
}
fn finite(value: u64) -> bool {
    !matches!(value, 0 | u64::MAX)
}
impl Envelope {
    pub fn encode(self) -> Result<[u8; SIZE], Error> {
        if !finite(self.request) {
            return Err(Error::Identity);
        }
        let mut b = [0; SIZE];
        b[..8].copy_from_slice(b"EVDSPL05");
        b[8..10].copy_from_slice(&5u16.to_le_bytes());
        b[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
        b[13] = 255;
        put(&mut b, 16, self.request);
        let transaction = match self.command {
            Command::Begin {
                transaction,
                model_revision,
                preferences,
            } => {
                if !finite(model_revision) || !preferences.valid() {
                    return Err(Error::Profile);
                }
                b[12] = 1;
                put(&mut b, 32, model_revision);
                b[65] = preferences.scale;
                b[66] = u8::from(preferences.high_contrast);
                b[67] = u8::from(preferences.thick_focus);
                transaction
            }
            Command::Register {
                transaction,
                window,
            } => {
                window.valid()?;
                b[12] = 2;
                b[13] = window.slot as u8;
                b[14] = u8::from(window.visible)
                    | u8::from(window.strict_view) << 1
                    | u8::from(window.focused) << 2;
                put(&mut b, 40, window.view_revision);
                b[48..52].copy_from_slice(&window.bounds.x.to_le_bytes());
                b[52..56].copy_from_slice(&window.bounds.y.to_le_bytes());
                b[56..60].copy_from_slice(&window.bounds.width.to_le_bytes());
                b[60..64].copy_from_slice(&window.bounds.height.to_le_bytes());
                b[64] = window.z;
                b[80..208].copy_from_slice(&window.registration.encode()?);
                transaction
            }
            Command::Remove { transaction, slot } => {
                b[12] = 3;
                b[13] = slot as u8;
                transaction
            }
            Command::Commit { transaction } => {
                b[12] = 4;
                transaction
            }
            Command::Abort { transaction } => {
                b[12] = 5;
                transaction
            }
            Command::Inspect { slot, field } => {
                if field > 6 {
                    return Err(Error::Profile);
                }
                b[12] = 6;
                b[13] = slot as u8;
                b[64] = field;
                0
            }
            Command::Cursor { x, y, visible } => {
                if x >= 640 || y >= 480 {
                    return Err(Error::Profile);
                }
                b[12] = 7;
                b[32..34].copy_from_slice(&x.to_le_bytes());
                b[34..36].copy_from_slice(&y.to_le_bytes());
                b[36] = u8::from(visible);
                0
            }
        };
        if !matches!(
            self.command,
            Command::Inspect { .. } | Command::Cursor { .. }
        ) && !finite(transaction)
        {
            return Err(Error::Identity);
        }
        put(&mut b, 24, transaction);
        Ok(b)
    }
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() != SIZE {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVDSPL05"
            || b[8..10] != 5u16.to_le_bytes()
            || b[10..12] != (SIZE as u16).to_le_bytes()
        {
            return Err(Error::Version);
        }
        let slot = || Slot::from_index(b[13]).ok_or(Error::Profile);
        let transaction = word(b, 24);
        let command = match b[12] {
            1 => Command::Begin {
                transaction,
                model_revision: word(b, 32),
                preferences: Preferences {
                    scale: b[65],
                    high_contrast: b[66] == 1,
                    thick_focus: b[67] == 1,
                },
            },
            2 => Command::Register {
                transaction,
                window: Window {
                    slot: slot()?,
                    registration: Registration::parse(&b[80..208])?,
                    bounds: Bounds {
                        x: i32::from_le_bytes(b[48..52].try_into().unwrap()),
                        y: i32::from_le_bytes(b[52..56].try_into().unwrap()),
                        width: u32::from_le_bytes(b[56..60].try_into().unwrap()),
                        height: u32::from_le_bytes(b[60..64].try_into().unwrap()),
                    },
                    z: b[64],
                    visible: b[14] & 1 != 0,
                    strict_view: b[14] & 2 != 0,
                    focused: b[14] & 4 != 0,
                    view_revision: word(b, 40),
                },
            },
            3 => Command::Remove {
                transaction,
                slot: slot()?,
            },
            4 => Command::Commit { transaction },
            5 => Command::Abort { transaction },
            6 => Command::Inspect {
                slot: slot()?,
                field: b[64],
            },
            7 => Command::Cursor {
                x: u16::from_le_bytes(b[32..34].try_into().unwrap()),
                y: u16::from_le_bytes(b[34..36].try_into().unwrap()),
                visible: b[36] == 1,
            },
            _ => return Err(Error::Profile),
        };
        let envelope = Self {
            request: word(b, 16),
            command,
        };
        if envelope.encode()?.as_slice() != b {
            return Err(Error::Reserved);
        }
        Ok(envelope)
    }
}
pub const fn reply(repaint_mask: u8) -> Option<u64> {
    if repaint_mask & !63 != 0 {
        None
    } else {
        Some(REPLY_MAGIC | repaint_mask as u64)
    }
}
pub const fn decode_reply(value: u64) -> Option<u8> {
    if value & !63 == REPLY_MAGIC {
        Some(value as u8 & 63)
    } else {
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn window() -> Window {
        Window {
            slot: Slot::EditorOne,
            registration: Registration {
                sequence: 1,
                source_role: Role::EditorOneSurface,
                producer: Producer::Application,
                instance: 2,
                process: 10,
                thread: 11,
                incarnation: 12,
                surface_object: 9,
                surface_generation: 10,
                mapping_epoch: 1,
            },
            bounds: Bounds {
                x: 0,
                y: 91,
                width: 320,
                height: 180,
            },
            z: 1,
            visible: true,
            view_revision: 0,
            strict_view: false,
            focused: true,
        }
    }
    #[test]
    fn canonical_commands_and_reserved_bytes() {
        for command in [
            Command::Begin {
                transaction: 7,
                model_revision: 1,
                preferences: Preferences {
                    scale: 1,
                    high_contrast: false,
                    thick_focus: true,
                },
            },
            Command::Register {
                transaction: 7,
                window: window(),
            },
            Command::Remove {
                transaction: 7,
                slot: Slot::EditorTwo,
            },
            Command::Commit { transaction: 7 },
            Command::Abort { transaction: 7 },
            Command::Inspect {
                slot: Slot::EditorOne,
                field: 6,
            },
            Command::Cursor {
                x: 639,
                y: 479,
                visible: true,
            },
        ] {
            let envelope = Envelope {
                request: 5,
                command,
            };
            let b = envelope.encode().unwrap();
            assert_eq!(Envelope::parse(&b), Ok(envelope));
            let mut bad = b;
            bad[255] = 1;
            assert_eq!(Envelope::parse(&bad), Err(Error::Reserved));
        }
        assert_eq!(decode_reply(reply(31).unwrap()), Some(31));
        assert_eq!(decode_reply(DENIED), None);
    }
    #[test]
    fn no_claimed_root_slot_or_bounds_override() {
        let mut w = window();
        w.slot = Slot::ProtectedRoot;
        assert_eq!(w.valid(), Err(Error::Profile));
        let mut w = window();
        w.bounds.y = 80;
        assert_eq!(w.valid(), Err(Error::Profile));
        let mut w = window();
        w.strict_view = true;
        assert_eq!(w.valid(), Err(Error::Profile));
    }
}
