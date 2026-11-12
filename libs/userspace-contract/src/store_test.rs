//! Closed runner/control and completion records for the physical journal fixture.
//! These records grant no storage or generation authority. PendingA references
//! remain unresolved fixtures: no admission, boot health or KnownGood is asserted.
pub const BYTES: usize = 512;
pub const STORE_BASE: u32 = 16;
pub const STORE_BLOCKS: u32 = 14;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Init = 0,
    Cut = 1,
    Recover = 2,
    Commit = 3,
    Verify = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Magic,
    Version,
    Mode,
    Reserved,
    Cut,
    Layout,
    Completion,
}
fn mode(value: u8) -> Result<Mode, Error> {
    match value {
        0 => Ok(Mode::Init),
        1 => Ok(Mode::Cut),
        2 => Ok(Mode::Recover),
        3 => Ok(Mode::Commit),
        4 => Ok(Mode::Verify),
        _ => Err(Error::Mode),
    }
}
fn header(bytes: &[u8], magic: &[u8; 4]) -> Result<Mode, Error> {
    if bytes.len() != BYTES {
        return Err(Error::Length);
    }
    if &bytes[..4] != magic {
        return Err(Error::Magic);
    }
    if bytes[4] != 1 {
        return Err(Error::Version);
    }
    mode(bytes[5])
}
fn wide(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub mode: Mode,
    pub cut: u64,
}
impl Control {
    pub const fn new(mode: Mode, cut: u64) -> Option<Self> {
        if matches!(mode, Mode::Cut) {
            if cut < 1 || cut > 6 {
                return None;
            }
        } else if cut != 0 {
            return None;
        }
        Some(Self { mode, cut })
    }
    pub const fn mode(self) -> Mode {
        self.mode
    }
    pub const fn cut(self) -> u64 {
        self.cut
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(b"EVST");
        bytes[4] = 1;
        bytes[5] = self.mode as u8;
        bytes[8..16].copy_from_slice(&self.cut.to_le_bytes());
        bytes[16..20].copy_from_slice(&STORE_BASE.to_le_bytes());
        bytes[20..24].copy_from_slice(&STORE_BLOCKS.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mode = header(bytes, b"EVST")?;
        if bytes[6..8].iter().chain(&bytes[24..]).any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if bytes[16..20] != STORE_BASE.to_le_bytes() || bytes[20..24] != STORE_BLOCKS.to_le_bytes()
        {
            return Err(Error::Layout);
        }
        Self::new(mode, wide(bytes, 8)).ok_or(Error::Cut)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub mode: Mode,
    pub flags: u8,
    pub operation: u64,
    pub sequence: u64,
    pub mutations: u64,
}
impl Completion {
    pub const fn new(mode: Mode, mutations: u64) -> Option<Self> {
        if matches!(mode, Mode::Cut) {
            None
        } else {
            let initial = matches!(mode, Mode::Init);
            Some(Self {
                mode,
                flags: if initial { 1 } else { 7 },
                operation: if initial { 0 } else { 1 },
                sequence: if initial { 1 } else { 2 },
                mutations,
            })
        }
    }
    pub const fn mode(self) -> Mode {
        self.mode
    }
    pub const fn mutations(self) -> u64 {
        self.mutations
    }
    pub const fn operation(self) -> u64 {
        self.operation
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn replayed(self) -> bool {
        !matches!(self.mode, Mode::Init)
    }
    fn flags(self) -> u8 {
        self.flags
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(b"EVSR");
        bytes[4] = 1;
        bytes[5] = self.mode as u8;
        bytes[6] = self.flags();
        bytes[8..16].copy_from_slice(&self.operation().to_le_bytes());
        bytes[16..24].copy_from_slice(&self.sequence().to_le_bytes());
        bytes[24..32].copy_from_slice(&self.mutations.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mode = header(bytes, b"EVSR")?;
        if bytes[7] != 0 || bytes[32..].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        let completion = Self::new(mode, wide(bytes, 24)).ok_or(Error::Completion)?;
        if bytes[6] != completion.flags()
            || wide(bytes, 8) != completion.operation()
            || wide(bytes, 16) != completion.sequence()
        {
            return Err(Error::Completion);
        }
        Ok(completion)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_control_modes_cuts_and_volume_layout_are_canonical() {
        for m in [
            Mode::Init,
            Mode::Cut,
            Mode::Recover,
            Mode::Commit,
            Mode::Verify,
        ] {
            for cut in [0, 1, 2, 6, 7, u64::MAX] {
                let valid = if m == Mode::Cut {
                    (1..=6).contains(&cut)
                } else {
                    cut == 0
                };
                assert_eq!(Control::new(m, cut).is_some(), valid);
                if let Some(c) = Control::new(m, cut) {
                    assert_eq!(Control::decode(&c.encode()), Ok(c));
                }
            }
        }
        let good = Control::new(Mode::Cut, 3).unwrap().encode();
        for len in 0..BYTES {
            assert_eq!(Control::decode(&good[..len]), Err(Error::Length));
        }
        for i in [6, 7].into_iter().chain(24..BYTES) {
            let mut bad = good;
            bad[i] = 1;
            assert_eq!(Control::decode(&bad), Err(Error::Reserved));
        }
        for i in 16..24 {
            let mut bad = good;
            bad[i] ^= 1;
            assert_eq!(Control::decode(&bad), Err(Error::Layout));
        }
        for value in 5..=255 {
            let mut bad = good;
            bad[5] = value;
            assert_eq!(Control::decode(&bad), Err(Error::Mode));
        }
    }
    #[test]
    fn completion_is_diagnostic_pending_only_and_cut_requires_actual_fault() {
        assert!(Completion::new(Mode::Cut, 1).is_none());
        for m in [Mode::Init, Mode::Recover, Mode::Commit, Mode::Verify] {
            let c = Completion::new(m, 6).unwrap();
            let good = c.encode();
            assert_eq!(Completion::decode(&good), Ok(c));
            for i in [6, 7, 8, 16].into_iter().chain(32..BYTES) {
                let mut bad = good;
                bad[i] ^= 8;
                assert!(Completion::decode(&bad).is_err());
            }
            for len in 0..BYTES {
                assert!(Completion::decode(&good[..len]).is_err());
            }
            assert_eq!(c.replayed(), m != Mode::Init);
        }
        assert!(Completion::decode(&Control::new(Mode::Init, 0).unwrap().encode()).is_err());
    }
}
