//! Native adapter's explicit File backend discriminator. This is retained
//! trusted route state, never an app wire selector or a kernel retirement proof.
use crate::{BindError, Gateway, RetireError, RouteKey, legacy};
use ev_workspace_store::SectorIo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Dataset(RouteKey),
    Legacy {
        object: legacy::Object,
        metadata: legacy::Metadata,
    },
}
impl Key {
    /// Shared preflight for a native cross-backend bind or retirement. It must
    /// precede legacy inspection, so a Dataset fence cannot be escaped merely
    /// by selecting a different backend or another empty installed slot.
    pub fn check_quiescent<D: SectorIo>(
        gateway: &Gateway<'_, '_, D>,
        legacy_fenced: bool,
    ) -> Result<(), RetireError> {
        if legacy_fenced {
            return Err(RetireError::StorageFenced);
        }
        gateway.check_namespace_quiescent()
    }
    /// Logical revoke cannot return an actual old endpoint/window/loan. The
    /// native installed row remains retained until Root's separate reconcile.
    pub fn revoke<D: SectorIo>(self, gateway: &mut Gateway<'_, '_, D>) -> Result<(), BindError> {
        match self {
            Self::Dataset(key) => gateway.revoke(key),
            Self::Legacy { .. } => Ok(()),
        }
    }
    /// Called only AFTER native row revoke, exact old owner/nonce matching and
    /// independently proven Kernel61 retirement. A scalar call proves none of
    /// those obligations. No backend switch may bypass global accepted work.
    pub fn retire_quiescent<D: SectorIo>(
        self,
        gateway: &mut Gateway<'_, '_, D>,
        legacy_fenced: bool,
        deadline: u64,
    ) -> Result<(), RetireError> {
        Self::check_quiescent(gateway, legacy_fenced)?;
        match self {
            Self::Dataset(key) => gateway.retire_quiescent(key, deadline),
            Self::Legacy { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
