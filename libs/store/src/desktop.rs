//! Explicit bounded reference desktop disk layout, separate from Store-v2's
//! durable format. Logical sector numbers are backend arguments, not authority.
//! Only trusted userspace Block endpoint binding selects a client slice.
use crate::{Error, REQUIRED_SECTORS, SECTOR_BYTES, SectorIo, valid_deadline};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    System,
    Files,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    System,
    FileA,
    FileB,
}
impl Region {
    pub const fn client(self) -> Client {
        match self {
            Self::System => Client::System,
            Self::FileA | Self::FileB => Client::Files,
        }
    }
    pub const fn physical_start(self) -> u32 {
        match self {
            Self::System => 16,
            Self::FileA => 32,
            Self::FileB => 48,
        }
    }
    pub const fn wire_start(self) -> u32 {
        match self {
            Self::System | Self::FileA => 0,
            Self::FileB => 16,
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
impl Client {
    /// Used by the serialized userspace Block service BEFORE window/device
    /// access. Root's System endpoint can never name either File region.
    pub const fn physical_sector(self, logical: u32) -> Option<u32> {
        match self {
            Self::System if logical < 14 => Some(16 + logical),
            Self::Files if logical < 14 => Some(32 + logical),
            Self::Files if logical >= 16 && logical < 30 => Some(32 + logical),
            _ => None,
        }
    }
}
/// Optional preflight for explicit fresh provisioning of several disjoint
/// volumes. It never writes/flushes and is not format-on-open-error recovery.
pub fn require_blank<D: SectorIo>(device: &mut D, deadline: u64) -> Result<(), Error<D::Error>> {
    valid_deadline(deadline)?;
    if device.sectors() < REQUIRED_SECTORS {
        return Err(Error::Capacity);
    }
    let mut bytes = [0; SECTOR_BYTES];
    for lba in 0..REQUIRED_SECTORS {
        device.read(lba, &mut bytes, deadline).map_err(Error::Io)?;
        if bytes.iter().any(|b| *b != 0) {
            return Err(Error::NotBlank);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_namespaces_are_disjoint_and_all_guard_or_overflow_values_refuse() {
        for region in [Region::System, Region::FileA, Region::FileB] {
            for local in 0..14 {
                let wire = region.wire_sector(local).unwrap();
                assert_eq!(
                    region.client().physical_sector(wire),
                    Some(region.physical_start() + local as u32)
                );
            }
            for invalid in [14, 15, u64::MAX] {
                assert_eq!(region.wire_sector(invalid), None);
            }
        }
        for logical in [14, 15, 30, 31, 32, 48, u32::MAX] {
            assert_eq!(Client::Files.physical_sector(logical), None);
        }
        for logical in [14, 16, 29, 32, 48, u32::MAX] {
            assert_eq!(Client::System.physical_sector(logical), None);
        }
        for logical in 0..30 {
            if let Some(system) = Client::System.physical_sector(logical) {
                assert!(!(32..62).contains(&system));
            }
            if let Some(file) = Client::Files.physical_sector(logical) {
                assert!(!(16..32).contains(&file));
            }
        }
    }
    struct Blank {
        bytes: [[u8; 512]; 14],
        reads: u64,
        sectors: u64,
        fail: bool,
    }
    impl SectorIo for Blank {
        type Error = ();
        fn sectors(&self) -> u64 {
            self.sectors
        }
        fn read(&mut self, lba: u64, out: &mut crate::Sector, _: u64) -> Result<(), ()> {
            self.reads += 1;
            if self.fail {
                return Err(());
            }
            *out = self.bytes[lba as usize];
            Ok(())
        }
        fn write(&mut self, _: u64, _: &crate::Sector, _: u64) -> Result<(), ()> {
            panic!("blank preflight must never write")
        }
        fn flush(&mut self, _: u64) -> Result<(), ()> {
            panic!("blank preflight must never flush")
        }
    }
    #[test]
    fn fresh_preflight_refuses_nonblank_last_sector_short_media_and_invalid_deadline_without_writes()
     {
        let mut disk = Blank {
            bytes: [[0; 512]; 14],
            reads: 0,
            sectors: 14,
            fail: false,
        };
        assert_eq!(require_blank(&mut disk, 10), Ok(()));
        assert_eq!(disk.reads, 14);
        disk.bytes[13][511] = 1;
        assert_eq!(require_blank(&mut disk, 10), Err(Error::NotBlank));
        assert_eq!(disk.reads, 28);
        disk.sectors = 13;
        assert_eq!(require_blank(&mut disk, 10), Err(Error::Capacity));
        assert_eq!(disk.reads, 28);
        disk.sectors = 14;
        assert_eq!(require_blank(&mut disk, 0), Err(Error::InvalidDeadline));
        assert_eq!(disk.reads, 28);
        disk.fail = true;
        assert_eq!(require_blank(&mut disk, 10), Err(Error::Io(())));
        assert_eq!(disk.reads, 29);
    }
}
