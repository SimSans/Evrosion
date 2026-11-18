//! Conditional reviewed-VM clock for new remote decisions only. Actual local
//! cold identity/recovery never depends on this provider or current networking.
use super::{Time, vm_rtc};
use ev_content_store::Backend;
use ev_root_supervisor::native_acquisition::{
    AuthorizationBinding, Commit, Fault, QualifiedClock, Remote, Store,
};
use ev_time_contract::{Instant, freshness::QualifiedWindow};

#[derive(Debug)]
pub(super) enum Error {
    State,
    Store,
    Clock,
    Proof,
}
/// This module is private to the actual V4 Root. Its only source is the retained
/// private nonce/signature client plus the actual read-only RTC owner, under the
/// reviewed trusted Linux/QEMU/BOOTTIME profile and conditional minimum1/2 rate.
/// No author time, downloaded witness or ready label constructs this adapter.
pub(super) struct Clock<'a, B: Backend> {
    time: &'a mut Time,
    source: &'a mut vm_rtc::Source,
    rtc: u64,
    store: &'a Store<B>,
    binding: AuthorizationBinding,
}
impl<'a, B: Backend> Clock<'a, B> {
    pub(super) fn prepare(
        &mut self,
        current_root: &[u8],
        bundle: ev_release_trust::verifier::Bundle<'_>,
    ) -> Result<ev_root_supervisor::native_acquisition::Preparation, Fault> {
        let store = self.store;
        store.prepare_metadata(current_root, bundle, self)
    }
    pub(super) fn new(
        time: &'a mut Time,
        source: &'a mut vm_rtc::Source,
        rtc: u64,
        store: &'a Store<B>,
    ) -> Result<Self, Error> {
        if time.halted
            || time.failed
            || time.active()
            || time.anchor.is_none()
            || time.post_crypto.is_none()
            || source.failed()
        {
            return Err(Error::State);
        }
        if store.has_unresolved_io() {
            return Err(Error::Store);
        }
        let binding = store.authorization_binding().ok_or(Error::Store)?;
        Ok(Self {
            time,
            source,
            rtc,
            store,
            binding,
        })
    }
    /// The Store being authorized is exactly the one borrowed by construction.
    /// The affine decision occupies the existing resident Commit, separately
    /// bound to that head/revision; no large Snapshot return crosses this frame.
    pub(super) fn authorize_into(
        &mut self,
        remote: Remote<'_>,
        workspace: &mut Commit<B>,
    ) -> Result<(), Fault> {
        let store = self.store;
        store.authorize_into(remote, self, workspace)
    }
}
impl<B: Backend> QualifiedClock for Clock<'_, B> {
    type Error = Error;
    fn fresh(&mut self) -> Result<(QualifiedWindow, Instant), Error> {
        if self.store.has_unresolved_io()
            || self.store.authorization_binding() != Some(self.binding)
        {
            return Err(Error::Store);
        }
        if self.time.halted
            || self.time.failed
            || self.time.active()
            || self.time.post_crypto.is_none()
        {
            return Err(Error::State);
        }
        let observed = match self.source.sample(self.rtc) {
            Ok(sample) => sample,
            Err(_) => {
                self.time.source_failed(true);
                return Err(Error::Clock);
            }
        };
        let Some(anchor) = self.time.anchor.as_mut() else {
            return Err(Error::State);
        };
        let proposal = match anchor.window(observed, observed, self.binding.utc_floor()) {
            Ok(proposal) => proposal,
            Err(_) => {
                self.time.failed = true;
                self.time.post_crypto = None;
                return Err(Error::Proof);
            }
        };
        let window = QualifiedWindow::new(proposal.observed(), proposal.through(), proposal.utc())
            .map_err(|_| Error::Clock)?;
        Ok((window, observed))
    }
}
