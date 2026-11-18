//! Syntax of an owner-confirmed request to the host-owned VM front door.
//! This is no hardware power authority and no proof of successful retirement.
#![forbid(unsafe_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    Generation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restart {
    generation: u32,
}
impl Restart {
    /// This version names only the bounded compatible SystemManaged boot set.
    /// Wider generation numbers need a new packet, never truncation.
    pub fn new(generation: u64) -> Result<Self, Error> {
        let generation = u32::try_from(generation).map_err(|_| Error::Generation)?;
        if generation == 0 || generation == u32::MAX {
            return Err(Error::Generation);
        }
        Ok(Self { generation })
    }
    pub const fn generation(self) -> u32 {
        self.generation
    }
    pub const fn mode(self) -> u8 {
        1
    }
    pub fn encode(self) -> [u8; 8] {
        let mut bytes = [b'R', b'S', 1, 1, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&self.generation.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, Error> {
        if bytes[..4] != [b'R', b'S', 1, 1] {
            return Err(Error::Format);
        }
        Self::new(u64::from(u32::from_le_bytes(
            bytes[4..].try_into().unwrap(),
        )))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_versioned_generation_and_mode_never_wrap_or_grant_reset() {
        let restart = Restart::new(2).unwrap();
        assert_eq!(restart.encode(), [b'R', b'S', 1, 1, 2, 0, 0, 0]);
        assert_eq!(Restart::decode(restart.encode()), Ok(restart));
        assert_eq!(restart.mode(), 1);
        for g in [0, u64::from(u32::MAX), u64::from(u32::MAX) + 1, u64::MAX] {
            assert!(Restart::new(g).is_err())
        }
        for index in 0..4 {
            let mut bad = restart.encode();
            bad[index] ^= 1;
            assert!(Restart::decode(bad).is_err())
        }
    }
}
