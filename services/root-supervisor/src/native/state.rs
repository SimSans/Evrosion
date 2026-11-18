//! Sole serialized native registry/data owner. Durable publication is separate
//! from executable admission; the executable adapter fences and retires the old
//! incarnation before calling commit, and starts only after exact readback.
#![forbid(unsafe_code)]
use super::{Contracts, Packages, Slot, storage::Backend};
use crate::native_sources::{Source, Sources};
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
    note_nonce: u32,
    health_probation: bool,
    #[cfg(feature = "native-network")]
    health_reads: Option<HealthReads>,
}
#[cfg(feature = "native-network")]
#[path = "health_reads.rs"]
mod health_reads;
#[cfg(feature = "native-network")]
pub use health_reads::HealthReads;
#[cfg(feature = "native-network")]
#[path = "startup_setup.rs"]
mod startup_setup;
#[cfg(feature = "native-network")]
pub use startup_setup::{SetupHint, StartupSelection};
#[path = "note_state.rs"]
mod note_state;
pub use note_state::NoteReply;
#[path = "grant_state.rs"]
mod grant_state;
pub use grant_state::GrantSnapshot;
#[path = "system_state.rs"]
mod system_state;
pub use system_state::{SystemChange, SystemView};
#[cfg(feature = "native-network")]
#[path = "registry_selection.rs"]
mod registry_selection;
#[cfg(feature = "native-network")]
pub use registry_selection::RegistrySelection;
/// Read-only policy result for the explicitly named bundled-App launch. It is
/// neither a live process nor authority to bypass prepare/held-image/commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundledLaunch {
    Install,
    ActivateA,
    Start(Slot),
}
/// Fixed trusted-constructor choice for the System namespace only.
#[derive(Clone, Copy)]
enum SystemProfile {
    LegacyV1,
    #[cfg(feature = "native-network")]
    DownloadedV2,
}
impl SystemProfile {
    fn open<D: ev_store::SectorIo>(
        self,
        device: D,
        deadline: u64,
    ) -> Result<Store<D>, ev_store::RejectedDevice<D>> {
        match self {
            Self::LegacyV1 => Store::open(device, deadline),
            #[cfg(feature = "native-network")]
            Self::DownloadedV2 => Store::open_downloaded_v2(device, deadline),
        }
    }
    fn format<D: ev_store::SectorIo>(
        self,
        device: D,
        initial: ev_store::GenerationManifest,
        user: &[u8],
        policy: ev_store::BootPolicy,
        deadline: u64,
    ) -> Result<Store<D>, ev_store::RejectedDevice<D>> {
        match self {
            Self::LegacyV1 => Store::format_new(device, initial, user, policy, deadline),
            #[cfg(feature = "native-network")]
            Self::DownloadedV2 => {
                Store::format_new_downloaded_v2(device, initial, user, policy, deadline)
            }
        }
    }
    fn inspect<D: ev_store::SectorIo>(
        self,
        device: D,
        deadline: u64,
    ) -> (D, crate::native_diagnostics::system::State) {
        match self {
            Self::LegacyV1 => crate::native_diagnostics::system::inspect(device, deadline),
            #[cfg(feature = "native-network")]
            Self::DownloadedV2 => {
                crate::native_diagnostics::system::inspect_downloaded_v2(device, deadline)
            }
        }
    }
}
/// Move-only actual backend/window owner. Plain cached metadata never grants
/// authority and is refreshed from Store before each publication/data operation.
/// Private blank credit has the closed exclusive-writer scope documented at install.
pub struct State<T, W> {
    backend: super::storage::BackendSlot<T, W>,
    record: Option<Record>,
    data: Option<AppDataEnvelope>,
    blank: bool,
    recovery: bool,
    pending: Option<Prepared>,
    session: Option<Session>,
    grant_pending: Option<ev_grant_policy::Prepared>,
    grant_fenced: bool,
    system_pending: Option<system_state::SystemIntent>,
    // Fixed by the trusted constructor; neither media nor an App can switch it.
    system_profile: SystemProfile,
    #[cfg(feature = "native-network")]
    health_reads_epoch: u64,
    #[cfg(feature = "native-network")]
    setup_hint: SetupHint,
}
impl<T: Wire, W: Window> State<T, W> {
    pub fn new(backend: Backend<T, W>) -> Self {
        Self::new_profile(backend, SystemProfile::LegacyV1)
    }
    /// Actual verified V4 construction opts only the System namespace into v2.
    /// App/scalar/Note/grant stores keep their historical default constructors.
    #[cfg(feature = "native-network")]
    pub fn new_downloaded_v2(backend: Backend<T, W>) -> Self {
        Self::new_profile(backend, SystemProfile::DownloadedV2)
    }
    fn new_profile(backend: Backend<T, W>, system_profile: SystemProfile) -> Self {
        Self {
            #[cfg(feature = "native-network")]
            backend: backend.into(),
            #[cfg(not(feature = "native-network"))]
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
            system_profile,
            #[cfg(feature = "native-network")]
            health_reads_epoch: 0,
            #[cfg(feature = "native-network")]
            setup_hint: SetupHint::Unknown,
        }
    }
    pub fn record(&self) -> Option<&Record> {
        self.record.as_ref()
    }
    pub fn data(&self) -> Option<AppDataEnvelope> {
        self.data
    }
    /// Exclusively lend the existing serialized Root backend to content work.
    /// Pending or uncertain registry/grant/System intent must settle first. The
    /// borrow excludes every other State storage/data operation until returned.
    #[cfg(feature = "native-network")]
    pub fn content_backend(
        &mut self,
        writes: bool,
    ) -> Result<super::storage::content::BackendRef<'_, T, W>, Error> {
        self.usable()?;
        if self.pending.is_some()
            || self.grant_pending.is_some()
            || self.grant_fenced
            || self.system_pending.is_some()
        {
            return Err(Error::State);
        }
        self.invalidate_health_reads();
        Ok(super::storage::content::BackendRef::new(
            self.backend.available_mut().ok_or(Error::State)?,
            writes,
        ))
    }
    /// Move the actual serialized backend into a controller-owned continuation.
    /// All storage operations remain fenced until this same owner returns.
    #[cfg(feature = "native-network")]
    pub fn take_content_backend(
        &mut self,
        writes: bool,
    ) -> Result<super::storage::content::OwnedBackend<T, W>, Error> {
        {
            self.content_backend(writes)?;
        }
        self.backend.take(writes).ok_or(Error::State)
    }
    #[cfg(feature = "native-network")]
    #[allow(clippy::result_large_err)] // Return the rejected actual owner intact.
    pub fn restore_content_backend(
        &mut self,
        owner: super::storage::content::OwnedBackend<T, W>,
    ) -> Result<(), super::storage::content::OwnedBackend<T, W>> {
        // Recheck actual State intent fences at the final ownership handoff;
        // cached "healthy" observations never replace these current guards.
        // A Session is an admitted App identity, not an outstanding IO loan.
        if self.recovery
            || self.pending.is_some()
            || self.grant_pending.is_some()
            || self.grant_fenced
            || self.system_pending.is_some()
        {
            return Err(owner);
        }
        self.backend.restore(owner)
    }
    pub fn content_busy(&self) -> bool {
        self.backend.busy()
    }
    pub fn mutations(&self) -> u64 {
        self.backend.mutations()
    }
    pub fn recovery_required(&self) -> bool {
        self.recovery || self.backend.poisoned()
    }
    /// A prerequisite content/authentication failure precedes the FIRST
    /// registry open. It cannot select a bank-only fallback or clear a fence.
    #[cfg(feature = "native-network")]
    pub fn refuse_content_startup(&mut self) {
        self.invalidate_health_reads();
        self.recovery = true;
        self.session = None;
    }
    pub fn transition_pending(&self) -> bool {
        self.pending.is_some() || self.content_busy()
    }
    pub fn fence(&mut self) {
        self.invalidate_health_reads();
        self.session = None;
    }
    /// Exclusively reborrow the one actual System window. The inspector refuses
    /// every write/flush, including Store.open's possible recovery publication.
    #[inline(never)]
    pub fn inspect_system(&mut self, deadline: u64) -> crate::native_diagnostics::system::State {
        if self.content_busy() {
            return crate::native_diagnostics::system::State::NotCollected;
        }
        let device = self.backend.device(Region::System, false);
        let (_device, state) = self.system_profile.inspect(device, deadline);
        state
    }
    fn invalidate_health_reads(&mut self) {
        #[cfg(feature = "native-network")]
        {
            self.setup_hint = SetupHint::Unknown;
            self.health_reads_epoch = self.health_reads_epoch.saturating_add(1);
            if let Some(session) = self.session.as_mut() {
                session.health_reads = None;
            }
        }
    }
    fn usable(&self) -> Result<(), Error> {
        if self.content_busy() {
            Err(Error::State)
        } else if self.recovery_required() {
            Err(Error::Recovery)
        } else {
            Ok(())
        }
    }
    fn policy(packages: &impl Sources) -> Policy {
        Policy {
            app: packages.app(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        }
    }
    fn fail(&mut self) -> Error {
        self.invalidate_health_reads();
        self.recovery = true;
        self.session = None;
        Error::Storage
    }
    /// Cold open may replay prior committed Store intent. A missing store is
    /// accepted ONLY if BOTH complete regions actually contain zero bytes.
    /// Partial allocation, corrupt data and IO errors never format anything.
    #[inline(never)]
    pub fn open(&mut self, packages: &impl Sources, deadline: u64) -> Result<(), Error> {
        self.invalidate_health_reads();
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
        packages: &impl Sources,
        deadline: u64,
    ) -> Result<AppDataEnvelope, Error> {
        let writes = !self.session.as_ref().is_some_and(|s| s.health_probation);
        self.load_data_with_writes(packages, deadline, writes)
    }
    fn load_data_with_writes(
        &mut self,
        packages: &impl Sources,
        deadline: u64,
        writes: bool,
    ) -> Result<AppDataEnvelope, Error> {
        let result = (|| {
            let device = self.backend.device(Region::AppData, writes);
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
    pub fn bundled_launch(&self, packages: &Packages<'_>) -> Result<BundledLaunch, Error> {
        self.usable()?;
        if self.pending.is_some() {
            return Err(Error::State);
        }
        if let Some(slot) = self.active(packages)? {
            return Ok(BundledLaunch::Start(slot));
        }
        if self.blank && self.record.is_none() {
            return Ok(BundledLaunch::Install);
        }
        if self.record.as_ref().is_some_and(|r| {
            r.installed()
                && r.staged()
                    .is_some_and(|v| v.digest() == packages.digest(Slot::A))
        }) {
            return Ok(BundledLaunch::ActivateA);
        }
        // In particular a removal tombstone or another staged package is not
        // permission to format/reinstall or silently activate that package.
        Err(Error::State)
    }
    /// Called for an actual owner InstallA line or explicit bundled-App launch. Initial
    /// 1001 is written to a NEW namespace, never used as an error fallback.
    pub fn install(&mut self, packages: &Packages<'_>, deadline: u64) -> Result<(), Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if !self.blank || self.record.is_some() || self.pending.is_some() {
            return Err(Error::State);
        }
        // `blank` is a private observation made by open() over BOTH complete
        // regions. This serialized Backend is their only writer in the closed
        // RootSystem graph: no record/session/pending publication can write
        // AppData before install, and System/grant/Note use disjoint regions.
        // The owned VM disk also has no concurrent host writer. Reuse that
        // observation here; EACH Store::format_new below still reads and checks
        // its own entire region before writing. Any failed/unknown completion
        // fences this owner through recovery/Backend poison, never retrying a
        // format from cached `blank`. This is not general device freshness or
        // cross-volume atomicity if an outside writer violates that ownership.
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
        packages: &impl Sources,
        change: Change,
        deadline: u64,
    ) -> Result<(), Error> {
        self.usable()?;
        if self.pending.is_some()
            || !matches!(change, Change::Stage { .. } | Change::Reinstall { .. })
        {
            return Err(Error::State);
        }
        self.prepare_source(packages, change, deadline)?;
        self.commit(packages, deadline)
    }
    pub fn active(&self, packages: &Packages<'_>) -> Result<Option<Slot>, Error> {
        self.active_source(packages)?
            .map(|source| source.bank().ok_or(Error::Package))
            .transpose()
    }
    pub fn active_source(&self, packages: &impl Sources) -> Result<Option<Source>, Error> {
        self.usable()?;
        self.record
            .as_ref()
            .and_then(|r| r.active())
            .map(|v| packages.source(v.digest()).ok_or(Error::Package))
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
        self.prepare_source(packages, change, deadline)?
            .map(|source| source.bank().ok_or(Error::Package))
            .transpose()
    }
    pub fn prepare_source(
        &mut self,
        packages: &impl Sources,
        change: Change,
        deadline: u64,
    ) -> Result<Option<Source>, Error> {
        self.invalidate_health_reads();
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
            .map(|v| packages.source(v.digest()).ok_or(Error::Package))
            .transpose()?;
        self.pending = Some(intent);
        Ok(target)
    }
    /// Physical caller must already have stopped/revoked/reaped old App and
    /// prepared (but not dispatched) the target. Only exact durable success
    /// permits it to Start. Failure keeps an unresolved intent and fences data.
    pub fn commit(&mut self, packages: &impl Sources, deadline: u64) -> Result<(), Error> {
        self.invalidate_health_reads();
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
        self.admit_source(packages, Source::Bank(slot), identity)
    }
    pub fn admit_source(
        &mut self,
        packages: &impl Sources,
        source: Source,
        identity: Identity,
    ) -> Result<(), Error> {
        self.invalidate_health_reads();
        self.admit_source_inner(packages, source, identity)
    }
    fn admit_source_inner(
        &mut self,
        packages: &impl Sources,
        source: Source,
        identity: Identity,
    ) -> Result<(), Error> {
        self.usable()?;
        if self.session.is_some()
            || self.pending.is_some()
            || identity.process == 0
            || identity.thread == 0
            || self.active_source(packages)? != Some(source)
        {
            return Err(Error::State);
        }
        packages
            .checked_source(source)
            .map_err(|_| Error::Package)?;
        self.session = Some(Session {
            identity,
            package: packages.source_digest(source).ok_or(Error::Package)?,
            read: false,
            set: false,
            note_nonce: 0,
            health_probation: false,
            #[cfg(feature = "native-network")]
            health_reads: None,
        });
        Ok(())
    }
    /// Authenticated actual current sender only. No IDs/schema/epoch/sector or
    /// global operation number are accepted from the App's wire message.
    pub fn data_request(
        &mut self,
        packages: &impl Sources,
        identity: Identity,
        request: DataRequest,
        deadline: u64,
    ) -> Response {
        if matches!(request, DataRequest::SetValue(_)) {
            self.invalidate_health_reads();
        }
        let response = self.data_request_inner(packages, identity, request, deadline);
        if matches!(response, Response::Refused(_)) {
            self.invalidate_health_reads();
        }
        response
    }
    fn data_request_inner(
        &mut self,
        packages: &impl Sources,
        identity: Identity,
        request: DataRequest,
        deadline: u64,
    ) -> Response {
        let denied = Response::Refused(Refusal::Denied);
        if self.content_busy() {
            return denied;
        }
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
        let Some(source) = packages.source(session.package) else {
            return denied;
        };
        if packages.checked_source(source).is_err() {
            return denied;
        }
        match request {
            DataRequest::Read if session.read => return denied,
            DataRequest::SetValue(_)
                if !session.read || session.set || session.health_probation =>
            {
                return denied;
            }
            _ => (),
        }
        #[cfg(feature = "native-network")]
        let retained = session.health_probation;
        #[cfg(not(feature = "native-network"))]
        let retained = false;
        let old = if retained {
            #[cfg(feature = "native-network")]
            let result = self.retained_health_data(packages);
            #[cfg(not(feature = "native-network"))]
            let result: Result<AppDataEnvelope, Error> = Err(Error::State);
            result
        } else {
            self.load_data(packages, deadline)
        };
        let Ok(old) = old else {
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
                    let writes = !self.session.as_ref().is_some_and(|s| s.health_probation);
                    let device = self.backend.device(Region::AppData, writes);
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
pub(crate) mod tests;
