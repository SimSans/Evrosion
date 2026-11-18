//! Additive Root-only network/update storage namespace. Actual endpoint binding
//! selects this profile; untrusted scalar requests cannot opt into it.
//! Native and session profile mappings remain strict and unchanged.
pub const PROFILE: u16 = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Checkpoint,
    Objects,
}
impl Area {
    pub const fn sectors(self) -> u64 {
        match self {
            Self::Checkpoint => 14,
            Self::Objects => 7936,
        }
    }
    pub const fn wire_start(self) -> u32 {
        match self {
            Self::Checkpoint => 80,
            Self::Objects => 128,
        }
    }
    pub const fn physical_start(self) -> u32 {
        match self {
            Self::Checkpoint => 128,
            Self::Objects => 256,
        }
    }
    pub const fn wire_sector(self, local: u64) -> Option<u32> {
        if local < self.sectors() {
            Some(self.wire_start() + local as u32)
        } else {
            None
        }
    }
}
pub const fn physical_sector(logical: u32) -> Option<u32> {
    match logical {
        80..=93 => Some(logical + 48),
        128..=8063 => Some(logical + 128),
        _ => crate::native::session_physical_sector(logical),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_new_spans_and_all_guards_are_closed_without_widening_old_profiles() {
        for area in [Area::Checkpoint, Area::Objects] {
            for local in 0..area.sectors() {
                let wire = area.wire_sector(local).unwrap();
                assert_eq!(
                    physical_sector(wire),
                    Some(area.physical_start() + local as u32)
                );
                assert_eq!(crate::native::physical_sector(wire), None);
                assert_eq!(crate::native::session_physical_sector(wire), None);
                for client in [
                    crate::desktop::Client::System,
                    crate::desktop::Client::Files,
                ] {
                    assert_eq!(client.physical_sector(wire), None);
                }
            }
            for local in [area.sectors(), u32::MAX as u64, u64::MAX] {
                assert_eq!(area.wire_sector(local), None);
            }
        }
        for wire in 0..=8192 {
            let expected = match wire {
                80..=93 => Some(wire + 48),
                128..=8063 => Some(wire + 128),
                _ => crate::native::session_physical_sector(wire),
            };
            assert_eq!(physical_sector(wire), expected);
        }
        assert_eq!(physical_sector(u32::MAX), None);
    }
}
