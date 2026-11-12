//! Sole serialized native registry/data owner. Durable publication is separate
//! from executable admission; the executable adapter fences and retires the old
//! incarnation before calling commit, and starts only after exact readback.
#![forbid(unsafe_code)]
use super::{Contracts, Packages, Slot, storage::Backend};
use ev_app_registry::{Change, Policy, Prepared, Registry, app_data::AppDataEnvelope};
use ev_block_service::store_io::{Window, Wire};
use ev_store::{BootPolicy, ObjectId, Request, Store, native::Region};
use ev_userspace_contract::app_data::{Refusal, Request as DataRequest, Response};
use ev_zion::lifecycle::Record;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Storage,
    Package,
    Corrupt,
    Recovery,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub process: u64,
    pub thread: u64,
}
struct Session {
    identity: Identity,
    package: [u8; 32],
    read: bool,
    set: bool,
}
#[path = "grant_state.rs"]
mod grant_state;
pub use grant_state::GrantSnapshot;
#[path = "system_state.rs"]
mod system_state;
pub use system_state::{SystemChange, SystemView};
/// Move-only actual backend/window owner. Plain cached metadata never grants
/// authority and is refreshed from Store before each publication/data operation.
pub struct State<T, W> {
    backend: Backend<T, W>,
    record: Option<Record>,
    data: Option<AppDataEnvelope>,
    blank: bool,
    recovery: bool,
    pending: Option<Prepared>,
    session: Option<Session>,
    grant_pending: Option<ev_grant_policy::Prepared>,
    grant_fenced: bool,
    system_pending: Option<system_state::SystemIntent>,
}
impl<T: Wire, W: Window> State<T, W> {
    pub fn new(backend: Backend<T, W>) -> Self {
        Self {
            backend,
            record: None,
            data: None,
            blank: false,
            recovery: false,
            pending: None,
            session: None,
            grant_pending: None,
            grant_fenced: false,
            system_pending: None,
        }
    }
    pub fn record(&self) -> Option<&Record> {
        self.record.as_ref()
    }
    pub fn data(&self) -> Option<AppDataEnvelope> {
        self.data
    }
    pub fn mutations(&self) -> u64 {
        self.backend.mutations()
    }
    pub fn recovery_required(&self) -> bool {
        self.recovery || self.backend.poisoned()
    }
    pub fn transition_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn fence(&mut self) {
        self.session = None;
    }
    /// Exclusively reborrow the one actual System window. The inspector refuses
    /// every write/flush, including Store.open's possible recovery publication.
    #[inline(never)]
    pub fn inspect_system(&mut self, deadline: u64) -> crate::native_diagnostics::system::State {
        let device = self.backend.device(Region::System, false);
        let (_device, state) = crate::native_diagnostics::system::inspect(device, deadline);
        state
    }
    fn usable(&self) -> Result<(), Error> {
        if self.recovery_required() {
            Err(Error::Recovery)
        } else {
            Ok(())
        }
    }
    fn policy(packages: &Packages<'_>) -> Policy {
        Policy {
            app: packages.app(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        }
    }
    fn fail(&mut self) -> Error {
        self.recovery = true;
        self.session = None;
        Error::Storage
    }
    /// Cold open may replay prior committed Store intent. A missing store is
    /// accepted ONLY if BOTH complete regions actually contain zero bytes.
    /// Partial allocation, corrupt data and IO errors never format anything.
    #[inline(never)]
    pub fn open(&mut self, packages: &Packages<'_>, deadline: u64) -> Result<(), Error> {
        self.usable()?;
        let result = {
            let device = self.backend.device(Region::AppRegistry, true);
            Registry::with_open(
                device,
                Self::policy(packages),
                packages,
                &Contracts,
                deadline,
                |registry| {
                    registry
                        .record()
                        .map(|record| record.map(|r| Record::decode(&r.encode()).unwrap()))
                },
            )
            .map(|(_device, record)| record)
            .map_err(|rejected| {
                matches!(
                    rejected.error,
                    ev_app_registry::Error::Store(ev_store::Error::Unformatted)
                )
            })
        };
        match result {
            Ok(record) => {
                self.record = record;
                let data = self.load_data(packages, deadline)?;
                if self
                    .record
                    .as_ref()
                    .is_none_or(|r| r.data_epoch() != data.schema_epoch())
                {
                    return Err(self.fail());
                }
                self.data = Some(data);
                self.blank = false;
                Ok(())
            }
            Err(true) => {
                if self.require_blank(deadline).is_err() {
                    return Err(self.fail());
                }
                self.blank = true;
                self.record = None;
                self.data = None;
                Ok(())
            }
            Err(false) => Err(self.fail()),
        }
    }
    fn require_blank(&mut self, deadline: u64) -> Result<(), Error> {
        for region in [Region::AppRegistry, Region::AppData] {
            let mut device = self.backend.device(region, false);
            ev_store::desktop::require_blank(&mut device, deadline).map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
    fn load_data(
        &mut self,
        packages: &Packages<'_>,
        deadline: u64,
    ) -> Result<AppDataEnvelope, Error> {
        let result = (|| {
            let device = self.backend.device(Region::AppData, true);
            let mut store = Store::open(device, deadline).map_err(|_| Error::Storage)?;
            let mut bytes = [0; 256];
            if store
                .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
                .map_err(|_| Error::Storage)?
                != 256
            {
                return Err(Error::Corrupt);
            }
            let data = AppDataEnvelope::decode(&bytes).map_err(|_| Error::Corrupt)?;
            if data.app() != packages.app() || data.schema_epoch() != 1 {
                return Err(Error::Corrupt);
            }
            Ok(data)
        })();
        if result.is_err() {
            self.recovery = true;
            self.session = None;
        }
        result
    }
    /// This is called only for an actual complete owner InstallA line. Initial
    /// 1001 is written to a NEW namespace, never used as an error fallback.
    pub fn install(&mut self, packages: &Packages<'_>, deadline: u64) -> Result<(), Error> {
        self.usable()?;
        if !self.blank || self.record.is_some() || self.pending.is_some() {
            return Err(Error::State);
        }
        self.require_blank(deadline).map_err(|_| self.fail())?;
        let initial =
            AppDataEnvelope::initial(packages.app(), 1, 1001).map_err(|_| Error::Corrupt)?;
        let result = (|| {
            {
                let data = self.backend.device(Region::AppData, true);
                let mut store = Store::format_new(
                    data,
                    packages.format_manifest(Region::AppData),
                    &initial.encode(),
                    BootPolicy::new(1).unwrap(),
                    deadline,
                )
                .map_err(|_| Error::Storage)?;
                let mut actual = [0; 256];
                if store
                    .read_mutable(ObjectId::user_data(), &mut actual, deadline)
                    .map_err(|_| Error::Storage)?
                    != 256
                    || actual != initial.encode()
                {
                    return Err(Error::Corrupt);
                }
            }
            let device = self.backend.device(Region::AppRegistry, true);
            let mut registry = Registry::format_new(
                device,
                Self::policy(packages),
                packages.format_manifest(Region::AppRegistry),
                deadline,
            )
            .map_err(|_| Error::Storage)?;
            let intent = registry
                .prepare(
                    registry.expected().map_err(|_| Error::Storage)?,
                    Change::Install {
                        package: packages.digest(Slot::A),
                        data_epoch: 1,
                    },
                    packages,
                    &Contracts,
                )
                .map_err(|_| Error::Package)?;
            if registry
                .publish(intent, packages, &Contracts, deadline)
                .is_err()
            {
                self.pending = registry.into_parts().2;
                return Err(Error::Storage);
            }
            self.record = registry
                .record()
                .map_err(|_| Error::Storage)?
                .map(|r| Record::decode(&r.encode()).unwrap());
            Ok(())
        })();
        if result.is_err() {
            self.recovery = true;
            self.session = None;
        } else {
            self.blank = false;
            self.data = Some(initial);
        }
        result
    }
    /// Metadata-only publication (Stage/Reinstall). No target process or data
    /// grant is created by changing a durable reference.
    pub fn metadata(
        &mut self,
        packages: &Packages<'_>,
        change: Change,
        deadline: u64,
    ) -> Result<(), Error> {
        self.usable()?;
        if self.pending.is_some()
            || !matches!(change, Change::Stage { .. } | Change::Reinstall { .. })
        {
            return Err(Error::State);
        }
        self.prepare(packages, change, deadline)?;
        self.commit(packages, deadline)
    }
    pub fn active(&self, packages: &Packages<'_>) -> Result<Option<Slot>, Error> {
        self.usable()?;
        self.record
            .as_ref()
            .and_then(|r| r.active())
            .map(|v| packages.slot(v.digest()).ok_or(Error::Package))
            .transpose()
    }
    /// Retains the exact move-only operation while the physical adapter stops
    /// the old App and prepares a held replacement. Nothing is published here.
    pub fn prepare(
        &mut self,
        packages: &Packages<'_>,
        change: Change,
        deadline: u64,
    ) -> Result<Option<Slot>, Error> {
        self.usable()?;
        if self.pending.is_some() || self.blank {
            return Err(Error::State);
        }
        let mut entered = false;
        let result = Registry::with_open(
            self.backend.device(Region::AppRegistry, true),
            Self::policy(packages),
            packages,
            &Contracts,
            deadline,
            |registry| {
                entered = true;
                registry.prepare(registry.expected()?, change, packages, &Contracts)
            },
        );
        let intent = match result {
            Ok((_device, intent)) => intent,
            Err(rejected) => {
                let storage = !entered
                    || matches!(
                        rejected.error,
                        ev_app_registry::Error::Store(_) | ev_app_registry::Error::NeedsRecovery
                    );
                if let Some(intent) = rejected.pending {
                    self.pending = Some(intent);
                }
                if storage {
                    self.recovery = true;
                    self.session = None;
                }
                return Err(if storage {
                    Error::Storage
                } else {
                    Error::State
                });
            }
        };
        let target = intent
            .after()
            .active()
            .map(|v| packages.slot(v.digest()).ok_or(Error::Package))
            .transpose()?;
        self.pending = Some(intent);
        Ok(target)
    }
    /// Physical caller must already have stopped/revoked/reaped old App and
    /// prepared (but not dispatched) the target. Only exact durable success
    /// permits it to Start. Failure keeps an unresolved intent and fences data.
    pub fn commit(&mut self, packages: &Packages<'_>, deadline: u64) -> Result<(), Error> {
        self.usable()?;
        if self.pending.is_none() {
            return Err(Error::State);
        }
        // Only consume the held intent after actual open succeeds. A failed
        // publication returns its exact unresolved owner through with_open.
        let pending = &mut self.pending;
        let result = Registry::with_open(
            self.backend.device(Region::AppRegistry, true),
            Self::policy(packages),
            packages,
            &Contracts,
            deadline,
            |registry| {
                let intent = pending.take().expect("retained prepared publication");
                registry.publish(intent, packages, &Contracts, deadline)?;
                registry
                    .record()
                    .map(|record| record.map(|r| Record::decode(&r.encode()).unwrap()))
            },
        );
        match result {
            Ok((_device, record)) => {
                self.record = record;
                Ok(())
            }
            Err(rejected) => {
                if let Some(intent) = rejected.pending {
                    self.pending = Some(intent);
                }
                self.recovery = true;
                self.session = None;
                Err(Error::Storage)
            }
        }
    }
    pub fn admit(
        &mut self,
        packages: &Packages<'_>,
        slot: Slot,
        identity: Identity,
    ) -> Result<(), Error> {
        self.usable()?;
        if self.session.is_some()
            || self.pending.is_some()
            || identity.process == 0
            || identity.thread == 0
            || self.active(packages)? != Some(slot)
        {
            return Err(Error::State);
        }
        packages.checked(slot).map_err(|_| Error::Package)?;
        self.session = Some(Session {
            identity,
            package: packages.digest(slot),
            read: false,
            set: false,
        });
        Ok(())
    }
    /// Authenticated actual current sender only. No IDs/schema/epoch/sector or
    /// global operation number are accepted from the App's wire message.
    pub fn data_request(
        &mut self,
        packages: &Packages<'_>,
        identity: Identity,
        request: DataRequest,
        deadline: u64,
    ) -> Response {
        let denied = Response::Refused(Refusal::Denied);
        if self.recovery_required() {
            return Response::Refused(Refusal::Storage);
        }
        let Some(session) = self.session.as_ref() else {
            return denied;
        };
        if session.identity != identity
            || self.pending.is_some()
            || self
                .record
                .as_ref()
                .and_then(|r| r.active())
                .is_none_or(|v| v.digest() != session.package)
        {
            return denied;
        }
        match request {
            DataRequest::Read if session.read => return denied,
            DataRequest::SetValue(_) if !session.read || session.set => return denied,
            _ => (),
        }
        let Ok(old) = self.load_data(packages, deadline) else {
            return Response::Refused(Refusal::Storage);
        };
        let data = match request {
            DataRequest::Read => old,
            DataRequest::SetValue(value) => {
                if value == old.value() {
                    return denied;
                }
                let Ok(next) = old.checked_replace(packages.app(), 1, old.counter(), value) else {
                    return Response::Refused(Refusal::Storage);
                };
                let result = (|| {
                    let device = self.backend.device(Region::AppData, true);
                    let mut store = Store::open(device, deadline).map_err(|_| Error::Storage)?;
                    let operation = store.next_operation().map_err(|_| Error::Storage)?;
                    store
                        .execute(
                            operation,
                            Request::WriteMutable {
                                object: ObjectId::user_data(),
                                bytes: &next.encode(),
                            },
                            deadline,
                        )
                        .map_err(|_| Error::Storage)?;
                    let mut actual = [0; 256];
                    if store
                        .read_mutable(ObjectId::user_data(), &mut actual, deadline)
                        .map_err(|_| Error::Storage)?
                        != 256
                        || actual != next.encode()
                    {
                        return Err(Error::Corrupt);
                    }
                    Ok(next)
                })();
                match result {
                    Ok(data) => data,
                    Err(_) => {
                        self.recovery = true;
                        self.session = None;
                        return Response::Refused(Refusal::Storage);
                    }
                }
            }
        };
        self.data = Some(data);
        let session = self.session.as_mut().unwrap();
        match request {
            DataRequest::Read => session.read = true,
            DataRequest::SetValue(_) => session.set = true,
        };
        Response::Value(data.value())
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
