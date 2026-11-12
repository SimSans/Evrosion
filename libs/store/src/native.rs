//! Additive Native RootSystem disk layout. Numbers alone grant no Block access;
//! a separately measured endpoint binding must enforce this closed profile.
//! Desktop System and File mappings in `desktop` remain unchanged.
use crate::REQUIRED_SECTORS;
pub const PROFILE: u16 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    System,
    AppRegistry,
    AppData,
    GrantPolicy,
}
impl Region {
    pub const fn wire_start(self) -> u32 {
        match self {
            Self::System => 0,
            Self::AppRegistry => 16,
            Self::AppData => 32,
            Self::GrantPolicy => 48,
        }
    }
    pub const fn physical_start(self) -> u32 {
        match self {
            Self::System => 16,
            Self::AppRegistry => 64,
            Self::AppData => 80,
            Self::GrantPolicy => 96,
        }
    }
    pub const fn wire_sector(self, local: u64) -> Option<u32> {
        if local < REQUIRED_SECTORS {
            Some(self.wire_start() + local as u32)
        } else {
            None
        }
    }
}
/// Exact scalar u32 request mapping, only for an explicitly registered Native
/// RootSystem endpoint. No runtime service or authority is exposed by this module.
pub const fn physical_sector(logical: u32) -> Option<u32> {
    match logical {
        0..=13 => Some(16 + logical),
        16..=29 => Some(48 + logical),
        32..=45 => Some(48 + logical),
        48..=61 => Some(48 + logical),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_four_regions_roundtrip_and_do_not_touch_file_or_guards() {
        for region in [
            Region::System,
            Region::AppRegistry,
            Region::AppData,
            Region::GrantPolicy,
        ] {
            for local in 0..REQUIRED_SECTORS {
                let wire = region.wire_sector(local).unwrap();
                let physical = physical_sector(wire).unwrap();
                assert_eq!(physical, region.physical_start() + local as u32);
                assert!(!(32..62).contains(&physical));
            }
            for local in [14, 15, 16, u32::MAX as u64, u64::MAX] {
                assert_eq!(region.wire_sector(local), None);
            }
        }
        for logical in 0..128 {
            let expected = match logical {
                0..=13 => Some(16 + logical),
                16..=29 | 32..=45 | 48..=61 => Some(48 + logical),
                _ => None,
            };
            assert_eq!(physical_sector(logical), expected);
        }
        assert_eq!(physical_sector(u32::MAX), None);
    }
    #[test]
    fn native_metadata_does_not_widen_desktop_system_or_file_namespaces() {
        use crate::desktop::Client;
        for logical in 14..128 {
            assert_eq!(Client::System.physical_sector(logical), None);
        }
        for logical in 0..128 {
            let file = Client::Files.physical_sector(logical);
            if let Some(value) = file {
                assert!((32..46).contains(&value) || (48..62).contains(&value));
                assert!(!(64..110).contains(&value));
            }
        }
        assert_eq!(Client::System.physical_sector(u32::MAX), None);
        assert_eq!(Client::Files.physical_sector(u32::MAX), None);
    }
}
