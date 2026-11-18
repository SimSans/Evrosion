//! The actual native legacy backend's safe typed Block I/O core. One value
//! exclusively owns one transport/window; there is no region splitting, Clone,
//! reset or extraction API. Numbers do not supply the underlying capability.
use crate::legacy::LEGACY_LOGICAL_SECTORS;
use ev_block_service::store_io::{Window, Wire};
use ev_store::{Sector, SectorIo};
use ev_userspace_contract::block::{DecodeError, Request, Response};

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Bounds,
    Deadline,
    ReadOnly,
    NeedsRecovery,
    Transport(E),
    Decode(DecodeError),
    UnexpectedReply,
}
pub struct Device<T, W> {
    transport: T,
    window: W,
    poisoned: bool,
}
impl<T: Wire, W: Window> Device<T, W> {
    pub fn new(transport: T, window: W) -> Option<Self> {
        transport.supports_session().then_some(Self {
            transport,
            window,
            poisoned: false,
        })
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}
impl<T: Wire, W: Window> SectorIo for Device<T, W> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        LEGACY_LOGICAL_SECTORS
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(Error::NeedsRecovery);
        }
        if !(lba < 14 || (16..30).contains(&lba)) {
            return Err(Error::Bounds);
        }
        let child = self
            .transport
            .capture_session_deadline(deadline)
            .filter(|child| *child != 0 && *child != u64::MAX && *child <= deadline)
            .ok_or(Error::Deadline)?;
        let request = Request::Read { sector: lba as u32 };
        let result = (|| {
            let reply = self
                .transport
                .call(request.encode(), child)
                .map_err(Error::Transport)?;
            if Response::decode(&reply).map_err(Error::Decode)? != request.success() {
                return Err(Error::UnexpectedReply);
            }
            self.window.load(out);
            Ok(())
        })();
        self.poisoned |= result.is_err();
        result
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> Result<(), Self::Error> {
        Err(Error::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> Result<(), Self::Error> {
        Err(Error::ReadOnly)
    }
}

#[cfg(test)]
#[path = "legacy_device_tests.rs"]
mod tests;
