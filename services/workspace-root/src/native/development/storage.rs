//! Thin native wrapper over the same exclusive-owner storage core as tests.
use super::*;
pub(super) use ev_workspace_root::development::storage::Failure;
impl Root<'_> {
    #[inline(never)]
    pub(super) fn development_allocate(&mut self, pending: &mut Pending) -> Result<(), Failure> {
        let loaded = self.development_loaded().map_err(|_| Failure::Refused)?;
        let available = self.app_data_available();
        let support =
            ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
        let bytes = source_bytes(&self.catalogue).map_err(|_| Failure::Refused)?;
        let owner = self
            .private_data
            .development_owner()
            .map_err(|_| Failure::Retained)?;
        owner.development_allocate(
            bytes,
            &support,
            &pending.approval,
            &mut pending.storage_started,
            &mut pending.registry,
        )
    }
    #[inline(never)]
    pub(super) fn development_registry(
        &mut self,
        pending: &mut Pending,
        activate: bool,
    ) -> Result<(), Failure> {
        let loaded = self.development_loaded().map_err(|_| Failure::Refused)?;
        let available = self.app_data_available();
        let support =
            ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
        let bytes = source_bytes(&self.catalogue).map_err(|_| Failure::Refused)?;
        let owner = self
            .private_data
            .development_owner()
            .map_err(|_| Failure::Retained)?;
        owner.development_registry(
            bytes,
            &support,
            &pending.approval,
            activate,
            &mut pending.registry,
        )
    }
}
