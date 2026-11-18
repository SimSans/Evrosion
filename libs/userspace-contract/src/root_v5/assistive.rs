//! Local Root/Inspector UI control alongside the A1 provider boundary.
//! Neither a mode nor an intent grants provider, action or document authority.
use crate::root_v5::display_control::Slot;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Field,
    Value,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IntentKind {
    Enable = 0,
    Disable = 1,
    Refresh = 2,
    NextSource = 3,
    PreviousSource = 4,
    PreviousNode = 5,
    NextNode = 6,
    AssistiveFocus = 7,
    Activate = 8,
    KeyboardFocus = 9,
    Expand = 10,
    ReadLabel = 11,
    ReadDocument = 12,
    ConfirmProtected = 13,
    Cancel = 14,
    Select = 15,
    ScrollUp = 16,
    ScrollDown = 17,
    MoreText = 18,
}
impl IntentKind {
    fn decode(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::Enable,
            1 => Self::Disable,
            2 => Self::Refresh,
            3 => Self::NextSource,
            4 => Self::PreviousSource,
            5 => Self::PreviousNode,
            6 => Self::NextNode,
            7 => Self::AssistiveFocus,
            8 => Self::Activate,
            9 => Self::KeyboardFocus,
            10 => Self::Expand,
            11 => Self::ReadLabel,
            12 => Self::ReadDocument,
            13 => Self::ConfirmProtected,
            14 => Self::Cancel,
            15 => Self::Select,
            16 => Self::ScrollUp,
            17 => Self::ScrollDown,
            18 => Self::MoreText,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intent {
    pub kind: IntentKind,
    pub index: u8,
    pub view: u32,
}
impl Intent {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.index >= 16 || matches!(self.view, 0 | u32::MAX) {
            return Err(Error::Value);
        }
        let field = 0x8300u16 + (u16::from(self.kind as u8) << 4) + u16::from(self.index);
        Ok(word(field, self.view))
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        let (field, view) = parse(bytes)?;
        if !(0x8300..=0x842f).contains(&field) {
            return Err(Error::Field);
        }
        let out = Self {
            kind: IntentKind::decode(((field - 0x8300) >> 4) as u8).ok_or(Error::Field)?,
            index: (field & 15) as u8,
            view,
        };
        if out.encode()? != bytes {
            return Err(Error::Value);
        }
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Stats = 0,
    AttentionRequested = 1,
    Receiving = 2,
    Semantic = 3,
    Revoking = 4,
    Revoked = 5,
    Unsupported = 6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub mode: Mode,
    pub source: Slot,
    pub scopes: u8,
}
impl Context {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        if self.scopes & !15 != 0 {
            return Err(Error::Value);
        }
        Ok(word(
            0x8220,
            u32::from(self.mode as u8) | (self.source as u32) << 8 | u32::from(self.scopes) << 16,
        ))
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        let (field, value) = parse(bytes)?;
        if field != 0x8220 || value >> 24 != 0 {
            return Err(Error::Field);
        }
        let mode = match value & 255 {
            0 => Mode::Stats,
            1 => Mode::AttentionRequested,
            2 => Mode::Receiving,
            3 => Mode::Semantic,
            4 => Mode::Revoking,
            5 => Mode::Revoked,
            6 => Mode::Unsupported,
            _ => return Err(Error::Value),
        };
        let source = *crate::root_v5::display_control::SLOTS
            .get(((value >> 8) & 255) as usize)
            .ok_or(Error::Value)?;
        let out = Self {
            mode,
            source,
            scopes: ((value >> 16) & 255) as u8,
        };
        if out.encode()? != bytes {
            return Err(Error::Value);
        }
        Ok(out)
    }
}
pub fn commit(view: u32) -> Result<[u8; 8], Error> {
    finite_word(0x8221, view)
}
pub fn abort_relay(view: u32) -> Result<[u8; 8], Error> {
    finite_word(0x8222, view)
}
pub fn presented(view: u32) -> Result<[u8; 8], Error> {
    finite_word(0x8230, view)
}
pub fn range_presented(view: u32) -> Result<[u8; 8], Error> {
    finite_word(0x8231, view)
}
pub fn decode_range_presented(bytes: [u8; 8]) -> Result<u32, Error> {
    decode_finite(0x8231, bytes)
}
pub fn decode_commit(bytes: [u8; 8]) -> Result<u32, Error> {
    decode_finite(0x8221, bytes)
}
pub fn decode_abort(bytes: [u8; 8]) -> Result<u32, Error> {
    decode_finite(0x8222, bytes)
}
pub fn decode_presented(bytes: [u8; 8]) -> Result<u32, Error> {
    decode_finite(0x8230, bytes)
}
fn finite_word(field: u16, value: u32) -> Result<[u8; 8], Error> {
    if matches!(value, 0 | u32::MAX) {
        Err(Error::Value)
    } else {
        Ok(word(field, value))
    }
}
fn decode_finite(expected: u16, bytes: [u8; 8]) -> Result<u32, Error> {
    let (field, value) = parse(bytes)?;
    if field != expected {
        return Err(Error::Field);
    }
    finite_word(field, value)?;
    Ok(value)
}
fn word(field: u16, value: u32) -> [u8; 8] {
    let f = field.to_le_bytes();
    let v = value.to_le_bytes();
    [0x41, 1, f[0], f[1], v[0], v[1], v[2], v[3]]
}
fn parse(b: [u8; 8]) -> Result<(u16, u32), Error> {
    if b[..2] != [0x41, 1] {
        return Err(Error::Header);
    }
    Ok((
        u16::from_le_bytes([b[2], b[3]]),
        u32::from_le_bytes(b[4..].try_into().unwrap()),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_intents_and_context_do_not_accept_other_a1_families() {
        let good = Intent {
            kind: IntentKind::ConfirmProtected,
            index: 15,
            view: 0xffff_fffe,
        };
        assert_eq!(Intent::decode(good.encode().unwrap()), Ok(good));
        assert!(Intent::decode(word(0x8100, 7)).is_err());
        assert!(Intent::decode(word(0x8430, 7)).is_err());
        assert!(Intent { view: 0, ..good }.encode().is_err());
        let c = Context {
            mode: Mode::Semantic,
            source: Slot::EditorTwo,
            scopes: 7,
        };
        assert_eq!(Context::decode(c.encode().unwrap()), Ok(c));
        assert!(Context { scopes: 16, ..c }.encode().is_err());
        assert_eq!(
            Context::decode(Context { scopes: 9, ..c }.encode().unwrap())
                .unwrap()
                .scopes,
            9
        );
        assert_eq!(decode_commit(commit(7).unwrap()), Ok(7));
        assert!(decode_presented(commit(7).unwrap()).is_err());
    }
}
