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
            match Store::open(
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
            match Store::open(device, deadline) {
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
            Store::format_new(
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
            let mut store = Store::open(device, deadline).map_err(|_| true)?;
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
            let mut store = Store::open(device, deadline).map_err(|_| ())?;
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
