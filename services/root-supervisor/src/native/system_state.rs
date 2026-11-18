//! System exclusively borrows State's backend. An accepted intent retains its
//! exact operation/payload before execution; no blind replacement-ID retries.
use super::*;
use ev_store::{
    AdmissionReport, BootPlan, GenerationId, GenerationManifest, HealthReport, LastFailure,
    OperationId,
};
#[derive(Clone, Copy, Debug)]
pub struct SystemView {
    pub selected: Option<GenerationManifest>,
    pub staged: Option<GenerationManifest>,
    pub known_good: Option<u64>,
    pub boot_plan: Option<BootPlan>,
    pub boot_serial: u64,
    pub highest_generation: u64,
    pub next_operation: OperationId,
    pub last_failure: Option<LastFailure>,
    pub recovery_required: bool,
}
impl SystemView {
    pub fn head_digest(self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"evrosion.native.system.owner-head.v1\0");
        for m in [self.selected, self.staged] {
            h.update(m.map_or([0; 32], |m| super::super::system::manifest_digest(&m)));
        }
        for value in [
            self.known_good.unwrap_or(0),
            self.boot_serial,
            self.highest_generation,
            self.next_operation.get(),
        ] {
            h.update(value.to_le_bytes());
        }
        if let Some(f) = self.last_failure {
            for value in [
                f.generation.get(),
                f.boot_serial,
                f.operation.get(),
                f.sequence,
            ] {
                h.update(value.to_le_bytes());
            }
        }
        h.finalize().into()
    }
}
pub enum SystemChange {
    Stage(GenerationManifest),
    Activate(GenerationId),
    BeginBoot(GenerationId),
    Admission(AdmissionReport),
    Health(HealthReport),
    ComponentFault(ev_store::CriticalFaultReport),
    Probe([u8; 256]),
    SelectKnownGood,
}
impl SystemChange {
    fn request(&self) -> Request<'_> {
        match self {
            Self::Stage(m) => Request::Stage(m),
            Self::Activate(g) => Request::Activate(*g),
            Self::BeginBoot(g) => Request::BeginBoot(*g),
            Self::Admission(a) => Request::Admission(*a),
            Self::Health(h) => Request::Health(*h),
            Self::ComponentFault(h) => Request::CriticalFault(*h),
            Self::Probe(bytes) => Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes,
            },
            Self::SelectKnownGood => Request::SelectKnownGood,
        }
    }
}
pub(super) struct SystemIntent {
    operation: OperationId,
    change: SystemChange,
}
fn view<D: ev_store::SectorIo>(
    store: &mut Store<D>,
    deadline: u64,
) -> Result<SystemView, ev_store::Error<D::Error>> {
    let (selected, recovery_required) = match store.selected_manifest(deadline) {
        Ok(m) => (Some(m), false),
        Err(ev_store::Error::RecoveryRequired) => (None, true),
        Err(e) => return Err(e),
    };
    let staged = store.staged_manifest(deadline)?;
    let boot_plan = match store.boot_plan(deadline) {
        Ok(p) => Some(p),
        Err(ev_store::Error::Phase | ev_store::Error::RecoveryRequired) => None,
        Err(e) => return Err(e),
    };
    Ok(SystemView {
        selected,
        staged,
        known_good: store.known_good().map(|g| g.get()),
        boot_plan,
        boot_serial: store.committed_boot_serial()?,
        highest_generation: store.highest_generation()?,
        next_operation: store.next_operation()?,
        last_failure: store.last_failure()?,
        recovery_required,
    })
}
impl<T: Wire, W: Window> State<T, W> {
    /// Protected Recovery reads never replay Store intent or issue writes before
    /// explicit owner confirmation. A dirty journal remains recovery-required.
    pub fn system_readonly_snapshot(&mut self, deadline: u64) -> Result<Option<SystemView>, Error> {
        self.usable()?;
        let result = {
            let device = self.backend.device(Region::System, false);
            match self.system_profile.open(
                crate::native_diagnostics::system::ReadOnly(device),
                deadline,
            ) {
                Ok(mut store) => view(&mut store, deadline).map(Some).map_err(|_| false),
                Err(r) => Err(matches!(r.error, ev_store::Error::Unformatted)),
            }
        };
        match result {
            Ok(value) => Ok(value),
            Err(true) => {
                let mut device = self.backend.device(Region::System, false);
                ev_store::desktop::require_blank(&mut device, deadline)
                    .map_err(|_| Error::Recovery)?;
                Ok(None)
            }
            Err(false) => Err(Error::Recovery),
        }
    }
    pub fn system_snapshot(&mut self, deadline: u64) -> Result<Option<SystemView>, Error> {
        self.usable()?;
        let result = {
            let device = self.backend.device(Region::System, true);
            match self.system_profile.open(device, deadline) {
                Ok(mut store) => view(&mut store, deadline).map(Some).map_err(|_| false),
                Err(r) => Err(matches!(r.error, ev_store::Error::Unformatted)),
            }
        };
        match result {
            Ok(value) => Ok(value),
            Err(true) => {
                let mut device = self.backend.device(Region::System, false);
                ev_store::desktop::require_blank(&mut device, deadline).map_err(|_| self.fail())?;
                Ok(None)
            }
            Err(false) => Err(self.fail()),
        }
    }
    /// Real complete owner init only; never an ordinary-error fallback.
    pub fn system_initialize(
        &mut self,
        packages: &Packages<'_>,
        deadline: u64,
    ) -> Result<SystemView, Error> {
        self.usable()?;
        if self.system_snapshot(deadline)?.is_some() {
            return Err(Error::State);
        }
        let manifest =
            super::super::system::manifest(packages, super::super::system::Slot::Good, 1)
                .map_err(|_| Error::Package)?;
        let result = {
            let device = self.backend.device(Region::System, true);
            self.system_profile
                .format(
                    device,
                    manifest,
                    super::super::system::INITIAL_PAYLOAD,
                    BootPolicy::new(3).unwrap(),
                    deadline,
                )
                .map(|mut store| view(&mut store, deadline))
                .map_err(|_| ())
        };
        match result {
            Ok(Ok(v)) => Ok(v),
            _ => Err(self.fail()),
        }
    }
    pub fn system_apply(
        &mut self,
        change: SystemChange,
        deadline: u64,
    ) -> Result<SystemView, Error> {
        self.usable()?;
        if self.system_pending.is_some() {
            return Err(Error::State);
        }
        let pending = &mut self.system_pending;
        let result = (|| {
            let device = self.backend.device(Region::System, true);
            let mut store = self
                .system_profile
                .open(device, deadline)
                .map_err(|_| true)?;
            let operation = store.next_operation().map_err(|_| true)?;
            *pending = Some(SystemIntent { operation, change });
            let intent = pending.as_ref().unwrap();
            if let Err(error) = store.execute(intent.operation, intent.change.request(), deadline) {
                let uncertain = !matches!(
                    error,
                    ev_store::Error::InvalidRequest
                        | ev_store::Error::Conflict
                        | ev_store::Error::StaleOperation
                        | ev_store::Error::OutOfOrder
                        | ev_store::Error::Phase
                        | ev_store::Error::NoSpace
                        | ev_store::Error::StaleHealth
                );
                if !uncertain {
                    *pending = None;
                }
                return Err(uncertain);
            }
            if let SystemChange::Probe(expected) = &pending.as_ref().unwrap().change {
                let mut actual = [0; 256];
                if store
                    .read_mutable(ObjectId::user_data(), &mut actual, deadline)
                    .map_err(|_| true)?
                    != 256
                    || actual != *expected
                {
                    return Err(true);
                }
            }
            let observed = view(&mut store, deadline).map_err(|_| true)?;
            *pending = None;
            Ok(observed)
        })();
        match result {
            Ok(value) => Ok(value),
            Err(true) => Err(self.fail()),
            Err(false) => Err(Error::State),
        }
    }
    pub fn system_probe_digest(&mut self, deadline: u64) -> Result<[u8; 32], Error> {
        self.usable()?;
        let result = (|| {
            let device = self.backend.device(Region::System, true);
            let mut store = self.system_profile.open(device, deadline).map_err(|_| ())?;
            let mut bytes = [0; 256];
            let len = store
                .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
                .map_err(|_| ())?;
            use sha2::{Digest as _, Sha256};
            Ok::<_, ()>(Sha256::digest(&bytes[..len]).into())
        })();
        result.map_err(|_| self.fail())
    }
}

#[cfg(feature = "native-network")]
impl<T: Wire, W: Window> State<T, W> {
    pub(crate) fn initialize_downloaded_manifest(
        &mut self,
        manifest: GenerationManifest,
        deadline: u64,
    ) -> Result<(), Error> {
        self.usable()?;
        if self.system_snapshot(deadline)?.is_some() {
            return Err(Error::State);
        }
        let result = self.system_profile.format(
            self.backend.device(Region::System, true),
            manifest,
            super::super::system::INITIAL_PAYLOAD,
            BootPolicy::new(3).unwrap(),
            deadline,
        );
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(self.fail()),
        }
    }
    pub(crate) fn apply_component_fault(
        &mut self,
        report: ev_store::CriticalFaultReport,
        deadline: u64,
    ) -> Result<(), Error> {
        self.system_apply(SystemChange::ComponentFault(report), deadline)
            .map(|_| ())
    }
}

#[cfg(feature = "native-network")]
impl<T: Wire, W: Window> State<T, W> {
    fn health_receipt(
        &self,
        cohort: &crate::downloaded_health::Cohort,
        sources: &impl Sources,
    ) -> Result<crate::downloaded_health::HealthReceipt, Error> {
        self.usable()?;
        let selected = self.registry_selection(sources)?.ok_or(Error::Package)?;
        if selected.package() != cohort.content().package
            || selected.version() != cohort.content().version
        {
            return Err(Error::Package);
        }
        Ok(crate::downloaded_health::HealthReceipt {
            selected,
            cohort: cohort.manifest().cohort,
            generation: cohort.manifest().generation.get(),
            mutations: self.mutations(),
        })
    }
    pub(crate) fn commit_downloaded_health_receipt(
        &mut self,
        cohort: &crate::downloaded_health::Cohort,
        report: HealthReport,
        sources: &impl Sources,
        deadline: u64,
    ) -> Result<crate::downloaded_health::HealthReceipt, Error> {
        if report.admitted.cohort != cohort.manifest().cohort
            || report.outcome != ev_store::HealthOutcome::CriticalPassed
        {
            return Err(Error::State);
        }
        let view = self.system_apply(SystemChange::Health(report), deadline)?;
        if view.known_good != Some(cohort.manifest().generation.get())
            || view.selected != Some(cohort.manifest())
        {
            return Err(self.fail());
        }
        self.health_receipt(cohort, sources)
    }
    /// Recover only an actually committed protected System manifest. A current
    /// GUI Ready, detached Snapshot or caller-known generation is insufficient.
    pub fn retained_downloaded_health(
        &mut self,
        cohort: &crate::downloaded_health::Cohort,
        sources: &impl Sources,
        deadline: u64,
    ) -> Result<crate::downloaded_health::HealthReceipt, Error> {
        self.usable()?;
        if self
            .system_snapshot(deadline)?
            .and_then(|v| v.known_good)
            .is_none()
        {
            return Err(Error::State);
        }
        let result = {
            let device = self.backend.device(Region::System, true);
            match self.system_profile.open(device, deadline) {
                Ok(mut store) => store.known_good_manifest(deadline).map_err(|_| ()),
                Err(_) => Err(()),
            }
        };
        match result {
            Ok(Some(manifest)) if cohort.matches(&manifest) => self.health_receipt(cohort, sources),
            Ok(_) => Err(Error::State),
            Err(_) => Err(self.fail()),
        }
    }
    pub(crate) fn matches_downloaded_health(
        &self,
        receipt: &crate::downloaded_health::HealthReceipt,
    ) -> bool {
        self.matches_registry_selection(&receipt.selected) && self.mutations() == receipt.mutations
    }
}

#[cfg(feature = "native-network")]
impl<T: Wire, W: Window> State<T, W> {
    /// Actual controller uses this for the required subject only. Ordinary
    /// writes and Note namespace creation are refused until durable health.
    pub fn admit_health_subject(
        &mut self,
        sources: &impl Sources,
        source: Source,
        identity: Identity,
        reads: HealthReads,
    ) -> Result<(), Error> {
        if !matches!(source, Source::Downloaded(_)) {
            self.invalidate_health_reads();
            return Err(Error::Package);
        }
        if !self.matches_health_reads(&reads, sources)
            || sources.source_digest(source) != Some(reads.package())
        {
            self.invalidate_health_reads();
            return Err(Error::State);
        }
        if let Err(error) = self.admit_source_inner(sources, source, identity) {
            self.invalidate_health_reads();
            return Err(error);
        }
        let session = self.session.as_mut().unwrap();
        session.health_probation = true;
        session.health_reads = Some(reads);
        Ok(())
    }
    pub fn release_health_subject(
        &mut self,
        cohort: &crate::downloaded_health::Cohort,
        sources: &impl Sources,
        deadline: u64,
    ) -> Result<(), Error> {
        let _actual = self.retained_downloaded_health(cohort, sources, deadline)?;
        // A post-promotion child may already have stopped while the durable
        // content join completes. An absent fenced session grants nothing.
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        if session.package != cohort.content().package {
            return Err(Error::Package);
        }
        session.health_probation = false;
        self.invalidate_health_reads();
        Ok(())
    }
}
