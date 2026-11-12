//! FUTURE NativeSystem endpoint mapping only. This is not authority and is not
//! wired to active M4 Block, whose System route remains logical0..13 only.
use ev_store::{REQUIRED_SECTORS, Sector, SectorIo};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    System,
    AppRegistry,
}
impl Region {
    pub const fn wire_sector(self, local: u64) -> Option<u64> {
        if local >= REQUIRED_SECTORS {
            return None;
        }
        Some(match self {
            Self::System => local,
            Self::AppRegistry => 16 + local,
        })
    }
}
pub const fn physical_sector(logical: u64) -> Option<u64> {
    match logical {
        0..=13 => Some(16 + logical),
        16..=29 => Some(48 + logical),
        _ => None,
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Backend(E),
    Bounds,
}
/// A reborrow of ONE serialized backend, so safe Rust cannot use two Regions
/// concurrently. It does not clone the actual endpoint/window or grant a path.
pub struct Slice<'a, D> {
    device: &'a mut D,
    region: Region,
}
impl<'a, D: SectorIo> Slice<'a, D> {
    pub fn new(device: &'a mut D, region: Region) -> Self {
        Self { device, region }
    }
}
impl<D: SectorIo> SectorIo for Slice<'_, D> {
    type Error = Error<D::Error>;
    fn sectors(&self) -> u64 {
        REQUIRED_SECTORS
    }
    fn read(&mut self, local: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        let wire = self.region.wire_sector(local).ok_or(Error::Bounds)?;
        self.device
            .read(wire, out, deadline)
            .map_err(Error::Backend)
    }
    fn write(&mut self, local: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        let wire = self.region.wire_sector(local).ok_or(Error::Bounds)?;
        self.device
            .write(wire, bytes, deadline)
            .map_err(Error::Backend)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        self.device.flush(deadline).map_err(Error::Backend)
    }
}
