//! Local receipt of a genuine Registry open/publication and the next exclusive
//! content loan. This is neither remote authorization nor executable health.
use super::*;
use crate::native_sources::DownloadedSlot;
use sha2::{Digest, Sha256};

/// Move-only, incarnation-local evidence. No public constructor or wire format.
pub struct RegistrySelection {
    owner: u64,
    loan: u64,
    record: [u8; 32],
    package: [u8; 32],
    slot: DownloadedSlot,
}
impl RegistrySelection {
    pub(crate) fn package(&self) -> [u8; 32] {
        self.package
    }
    pub(crate) fn version(&self) -> u64 {
        self.slot.version()
    }
    pub(crate) fn owner(&self) -> (u64, u64) {
        (self.owner, self.loan)
    }
}
impl<T: Wire, W: Window> State<T, W> {
    fn selection_fences_clear(&self) -> bool {
        !self.recovery_required()
            && self.pending.is_none()
            && self.grant_pending.is_none()
            && !self.grant_fenced
            && self.system_pending.is_none()
    }
    /// Call immediately before `take_content_backend(true)`. The cached record
    /// exists only after actual Registry open or an exact publication ACK.
    /// Full current source/compatibility is checked again here; staged content
    /// and a running-process label cannot mint a selected-content receipt.
    pub fn registry_selection(
        &self,
        packages: &impl Sources,
    ) -> Result<Option<RegistrySelection>, Error> {
        self.usable()?;
        if !self.selection_fences_clear() {
            return Err(Error::State);
        }
        let Some(record) = self.record.as_ref() else {
            return Ok(None);
        };
        let Some(active) = record.active() else {
            return Ok(None);
        };
        let source = packages.source(active.digest()).ok_or(Error::Package)?;
        let Source::Downloaded(slot) = source else {
            return Ok(None);
        };
        let package = packages
            .checked_source(source)
            .map_err(|_| Error::Package)?;
        let compatible = package
            .compatible(1, ev_userspace_contract::ABI, &Contracts)
            .map_err(|_| Error::Package)?;
        if !record.installed()
            || record.app() != packages.app()
            || package.app().claimed_app != record.app()
            || !active.matches(&compatible)
            || !package.app().data_schema.reads(record.data_epoch())
            || packages.source_digest(source) != Some(active.digest())
        {
            return Err(Error::Package);
        }
        let (owner, _) = self.backend.selection_owner();
        Ok(Some(RegistrySelection {
            owner,
            loan: self.backend.next_loan().ok_or(Error::State)?,
            record: Sha256::digest(record.encode()).into(),
            package: active.digest(),
            slot,
        }))
    }
    /// While content owns the actual backend, Registry/data publication is
    /// fenced. Require the exact receipt, current record and same current loan.
    pub(crate) fn matches_registry_selection(&self, selected: &RegistrySelection) -> bool {
        self.content_busy()
            && self.selection_fences_clear()
            && self.backend.selection_owner() == selected.owner()
            && self.record.as_ref().is_some_and(|r| {
                <[u8; 32]>::from(Sha256::digest(r.encode())) == selected.record
                    && r.active().is_some_and(|a| a.digest() == selected.package)
            })
    }
}
