//! Pre-Start read authority for the one actual downloaded health subject.
//! The exclusive owner validates real Store data before Start. Probation has
//! no storage fallback and cannot format, replay, or write either namespace.
use super::*;
use ev_app_registry::note_data::NoteDataEnvelope;
use sha2::{Digest as _, Sha256};

/// Move-only, private-construction authority, consumed by actual admission.
/// Scalar data remains in State.data; only its exact fingerprint is retained.
pub struct HealthReads {
    owner: (u64, u64),
    epoch: u64,
    head: [u8; 32],
    package: [u8; 32],
    data: [u8; 32],
    // None means Store explicitly reported Unformatted. It grants no empty note.
    note: Option<NoteDataEnvelope>,
}
impl HealthReads {
    pub(super) fn package(&self) -> [u8; 32] {
        self.package
    }
}
impl<T: Wire, W: Window> State<T, W> {
    /// Same original whole cut is supplied by the controller before BeginBoot
    /// and Start. No App nonce/read ledger or health evidence is advanced here.
    #[inline(never)]
    pub fn prepare_health_reads(
        &mut self,
        packages: &impl Sources,
        source: Source,
        deadline: u64,
    ) -> Result<HealthReads, Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if self.session.is_some()
            || !self.health_reads_fences_clear()
            || self.health_reads_epoch == u64::MAX
            || !matches!(source, Source::Downloaded(_))
            || !packages.is_session()
            || self.active_source(packages)? != Some(source)
        {
            return Err(Error::State);
        }
        let package = packages
            .checked_source(source)
            .map_err(|_| Error::Package)?;
        let descriptor = package.app();
        if !descriptor
            .capability_requests()
            .any(|cap| cap.required && cap.capability == ev_zion::Capability::AppPrivateData)
            || !descriptor.contracts().any(|c| {
                c.name == ev_userspace_contract::session_note::INTERFACE
                    && c.major == 1
                    && c.minimum_minor == 0
                    && c.features == 0
            })
        {
            return Err(Error::Package);
        }
        let data = self.load_data_with_writes(packages, deadline, false)?;
        let note = {
            let device = self.backend.device(Region::SessionNote, false);
            match Store::open(device, deadline) {
                Ok(mut store) => note_state::validated_note(&mut store, packages, deadline)
                    .map(Some)
                    .map_err(|_| Error::Storage),
                Err(rejected) if matches!(rejected.error, ev_store::Error::Unformatted) => Ok(None),
                Err(_) => Err(Error::Storage),
            }
        };
        let note = note.map_err(|_| self.fail())?;
        let record = self.record.as_ref().ok_or(Error::State)?;
        if record.app() != packages.app() || record.data_epoch() != data.schema_epoch() {
            return Err(self.fail());
        }
        self.data = Some(data);
        Ok(HealthReads {
            owner: self.backend.selection_owner(),
            epoch: self.health_reads_epoch,
            head: Sha256::digest(record.encode()).into(),
            package: packages.source_digest(source).ok_or(Error::Package)?,
            data: Sha256::digest(data.encode()).into(),
            note,
        })
    }
    fn health_reads_fences_clear(&self) -> bool {
        !self.recovery_required()
            && !self.content_busy()
            && self.pending.is_none()
            && self.grant_pending.is_none()
            && !self.grant_fenced
            && self.system_pending.is_none()
    }
    pub(super) fn matches_health_reads(
        &self,
        reads: &HealthReads,
        packages: &impl Sources,
    ) -> bool {
        self.health_reads_fences_clear()
            && reads.epoch != u64::MAX
            && reads.epoch == self.health_reads_epoch
            && reads.owner == self.backend.selection_owner()
            && self.record.as_ref().is_some_and(|r| {
                r.app() == packages.app()
                    && r.active().is_some_and(|a| a.digest() == reads.package)
                    && <[u8; 32]>::from(Sha256::digest(r.encode())) == reads.head
                    && self.data.is_some_and(|d| {
                        d.app() == packages.app()
                            && r.data_epoch() == d.schema_epoch()
                            && <[u8; 32]>::from(Sha256::digest(d.encode())) == reads.data
                    })
            })
    }
    fn admitted_health_reads(&self, packages: &impl Sources) -> Result<&HealthReads, Error> {
        let session = self.session.as_ref().ok_or(Error::State)?;
        let reads = session.health_reads.as_ref().ok_or(Error::State)?;
        if !session.health_probation
            || session.package != reads.package
            || !self.matches_health_reads(reads, packages)
        {
            return Err(Error::State);
        }
        Ok(reads)
    }
    pub(super) fn retained_health_data(
        &self,
        packages: &impl Sources,
    ) -> Result<AppDataEnvelope, Error> {
        self.admitted_health_reads(packages)?;
        self.data.ok_or(Error::State)
    }
    pub(super) fn retained_health_note(
        &self,
        packages: &impl Sources,
    ) -> Result<Option<NoteDataEnvelope>, Error> {
        Ok(self.admitted_health_reads(packages)?.note)
    }
}

#[cfg(test)]
#[path = "health_reads_tests.rs"]
mod tests;
