//! The native State remains available for cached UI while its exact backend
//! moves into bounded content work. There is no replacement/fresh-owner path.
use super::content::OwnedBackend;
use super::*;
pub(crate) struct BackendSlot<T, W> {
    backend: Option<Backend<T, W>>,
    identity: u64,
    mutations: u64,
    loan: u64,
}
impl<T: Wire, W: Window> From<Backend<T, W>> for BackendSlot<T, W> {
    fn from(backend: Backend<T, W>) -> Self {
        Self {
            identity: backend.identity,
            mutations: backend.mutations(),
            loan: 0,
            backend: Some(backend),
        }
    }
}
impl<T: Wire, W: Window> BackendSlot<T, W> {
    pub(crate) fn busy(&self) -> bool {
        self.backend.is_none()
    }
    pub(crate) fn mutations(&self) -> u64 {
        self.backend
            .as_ref()
            .map_or(self.mutations, Backend::mutations)
    }
    pub(crate) fn poisoned(&self) -> bool {
        self.backend.as_ref().is_some_and(Backend::poisoned)
    }
    pub(crate) fn available_mut(&mut self) -> Option<&mut Backend<T, W>> {
        self.backend.as_mut()
    }
    pub(crate) fn take(&mut self, writes: bool) -> Option<OwnedBackend<T, W>> {
        if self.poisoned() {
            return None;
        }
        let loan = self.next_loan()?;
        let backend = self.backend.take()?;
        self.loan = loan;
        self.mutations = backend.mutations();
        Some(OwnedBackend {
            backend,
            writes,
            loan,
        })
    }
    pub(crate) fn restore(&mut self, owner: OwnedBackend<T, W>) -> Result<(), OwnedBackend<T, W>> {
        if self.backend.is_some()
            || owner.backend.identity != self.identity
            || owner.loan != self.loan
            || owner.backend.mutations() < self.mutations
        {
            return Err(owner);
        }
        self.mutations = owner.backend.mutations();
        self.backend = Some(owner.backend);
        Ok(())
    }
    pub(crate) fn next_loan(&self) -> Option<u64> {
        self.loan.checked_add(1).filter(|n| *n != u64::MAX)
    }
    pub(crate) fn selection_owner(&self) -> (u64, u64) {
        (self.identity, self.loan)
    }
    pub(crate) fn device(&mut self, region: Region, writes: bool) -> SlotDevice<'_, T, W> {
        SlotDevice(self.backend.as_mut().map(|b| b.device(region, writes)))
    }
}
pub(crate) struct SlotDevice<'a, T, W>(Option<Device<'a, T, W>>);
impl<T: Wire, W: Window> SectorIo for SlotDevice<'_, T, W> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, lba: u64, out: &mut Sector, cut: u64) -> Result<(), Self::Error> {
        self.0.as_mut().ok_or(Error::NoConsent)?.read(lba, out, cut)
    }
    fn write(&mut self, lba: u64, bytes: &Sector, cut: u64) -> Result<(), Self::Error> {
        self.0
            .as_mut()
            .ok_or(Error::NoConsent)?
            .write(lba, bytes, cut)
    }
    fn flush(&mut self, cut: u64) -> Result<(), Self::Error> {
        self.0.as_mut().ok_or(Error::NoConsent)?.flush(cut)
    }
}
