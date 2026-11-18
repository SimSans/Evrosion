//! Read-only first-use prerequisite inspection. Cached hints describe UI only;
//! every downloaded selection performs fresh reads through the same owner.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupHint {
    Unknown,
    OpenHello,
    Ready,
}

/// Move-only owner selection intent, not readiness or storage authority. Root
/// constructs it only for an explicit protected System action from its actual
/// current head/candidate. State independently validates both claims before IO.
pub struct StartupSelection {
    revision: u64,
    candidate: [u8; 32],
}
impl StartupSelection {
    pub const fn new(revision: u64, candidate: [u8; 32]) -> Self {
        Self {
            revision,
            candidate,
        }
    }
}

enum Head {
    Missing,
    Same,
    Different,
}

impl<T: Wire, W: Window> State<T, W> {
    fn setup_available(&self) -> bool {
        !self.recovery_required()
            && !self.content_busy()
            && self.pending.is_none()
            && self.grant_pending.is_none()
            && !self.grant_fenced
            && self.system_pending.is_none()
            && !self.session.as_ref().is_some_and(|s| s.health_probation)
    }
    /// Explicit protected owner Fetch prerequisite. Only the existing private
    /// whole Registry+Data blank credit may enter unchanged baseline InstallA.
    /// A tombstone, unknown State or health subject never means new allocation.
    pub fn prepare_fetch_setup(
        &mut self,
        packages: &Packages<'_>,
        deadline: u64,
    ) -> Result<(), Error> {
        self.usable()?;
        if !self.setup_available() || !packages.is_session() {
            return Err(Error::State);
        }
        if self.installed_for_fetch() {
            return self
                .record
                .as_ref()
                .filter(|r| r.app() == packages.app())
                .map(|_| ())
                .ok_or(Error::State);
        }
        if !self.blank || self.record.is_some() || self.data.is_some() {
            return Err(Error::State);
        }
        self.install(packages, deadline)
    }
    /// Explicit protected owner System prerequisite. Current Registry revision
    /// and the actual immutable checked Downloaded candidate bind separately:
    /// legitimate B selection may occur while bank A is still the live head.
    /// All reads/blank-only creation/readback/final fresh check use the ONE
    /// caller-supplied storage cut; no accepted child operation is renewed.
    #[inline(never)]
    pub fn prepare_startup_setup(
        &mut self,
        sources: &impl Sources,
        intent: StartupSelection,
        deadline: u64,
    ) -> Result<SetupHint, Error> {
        self.usable()?;
        if !self.setup_available()
            || !sources.is_session()
            || self
                .record
                .as_ref()
                .is_none_or(|r| r.revision() != intent.revision)
        {
            return Err(Error::State);
        }
        let source = sources.source(intent.candidate).ok_or(Error::Package)?;
        if !matches!(source, Source::Downloaded(_))
            || sources.source_digest(source) != Some(intent.candidate)
        {
            return Err(Error::Package);
        }
        require_note_source(sources, source)?;
        match self.check_startup_setup(sources, deadline)? {
            SetupHint::Ready => return Ok(SetupHint::Ready),
            SetupHint::OpenHello if self.installed_for_fetch() => (),
            _ => return Err(Error::State),
        }
        // Creation changes a namespace. Invalidate any pre-Start read receipt
        // minted before this operation, even when no App is currently admitted.
        self.invalidate_health_reads();
        // No event pump or ownership handoff intervenes. The shared creation
        // helper nevertheless scans every sector again, then format_new checks
        // blank again. Existing/dirty/partial bytes cannot be reformatted.
        let created = (|| {
            let device = self.backend.device(Region::SessionNote, true);
            let mut store = note_state::create_blank_note(device, sources, None, deadline)
                .map_err(|_| Error::Storage)?;
            let actual = note_state::validated_note(&mut store, sources, deadline)
                .map_err(|_| Error::Corrupt)?;
            let initial = ev_app_registry::note_data::NoteDataEnvelope::initial(sources.app(), "")
                .map_err(|_| Error::Corrupt)?;
            if actual != initial {
                return Err(Error::Corrupt);
            }
            Ok(())
        })();
        if let Err(error) = created {
            self.fail();
            return Err(error);
        }
        // This genuine fresh readonly check remains mandatory even after exact
        // format/readback. No App nonce/read marker/session/health is synthesized.
        self.check_startup_setup(sources, deadline)
    }
    /// Pure UI projection. The existing private blank credit was obtained by
    /// reading BOTH complete regions and remains valid under this closed sole
    /// writer's disjoint content loans. Mere missing Record never grants it.
    pub fn startup_setup_hint(&self) -> SetupHint {
        if !self.setup_available() {
            SetupHint::Unknown
        } else if self.blank && self.record.is_none() && self.data.is_none() {
            SetupHint::OpenHello
        } else if self.installed_for_fetch() {
            self.setup_hint
        } else {
            SetupHint::Unknown
        }
    }
    /// No IO and no selection authority. State's cached typed record/data came
    /// from its validated open or exact durable publication/readback paths.
    pub fn installed_for_fetch(&self) -> bool {
        self.setup_available()
            && !self.blank
            && self.record.as_ref().is_some_and(|record| {
                record.installed()
                    && self.data.is_some_and(|data| {
                        data.app() == record.app()
                            && data.schema_epoch() == 1
                            && record.data_epoch() == data.schema_epoch()
                    })
            })
    }
    /// Explicit fresh readonly prerequisites before any System publication.
    /// An ordinary live A session is permitted. Probation and unresolved owners
    /// refuse before IO; no format, recovery replay, retry or body synthesis.
    #[inline(never)]
    pub fn check_startup_setup(
        &mut self,
        sources: &impl Sources,
        deadline: u64,
    ) -> Result<SetupHint, Error> {
        self.usable()?;
        if !self.setup_available() || !sources.is_session() {
            return Err(Error::State);
        }
        self.setup_hint = SetupHint::Unknown;
        let result = self.check_setup_readonly(sources, deadline);
        match result {
            Ok(hint) => {
                self.setup_hint = hint;
                Ok(hint)
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    fn check_setup_readonly(
        &mut self,
        sources: &impl Sources,
        deadline: u64,
    ) -> Result<SetupHint, Error> {
        let expected = &self.record;
        let actual = Registry::with_open(
            self.backend.device(Region::AppRegistry, false),
            Self::policy(sources),
            sources,
            &Contracts,
            deadline,
            |registry| {
                Ok(match registry.record()? {
                    None => Head::Missing,
                    Some(record) if Some(record) == expected.as_ref() => Head::Same,
                    Some(_) => Head::Different,
                })
            },
        )
        .map(|(_device, record)| record)
        .map_err(|rejected| {
            matches!(
                rejected.error,
                ev_app_registry::Error::Store(ev_store::Error::Unformatted)
            )
        });
        match actual {
            Ok(Head::Same) => (),
            Ok(Head::Different) => return Err(Error::State),
            Err(true) => {
                // Loss of an already installed namespace is never first use.
                if !self.blank || self.record.is_some() || self.data.is_some() {
                    return Err(Error::Corrupt);
                }
                self.require_blank(deadline)?;
                return Ok(SetupHint::OpenHello);
            }
            _ => return Err(Error::Storage),
        }
        // The fresh Registry parsed and revalidated its real Record under the
        // supplied Sources, then compared every typed field with this cache.
        // No event pump or owner change can intervene in this exclusive borrow.
        let actual = self.record.as_ref().ok_or(Error::State)?;
        if !actual.installed() {
            return Err(Error::State);
        }
        let app = actual.app();
        let data_epoch = actual.data_epoch();
        let version = actual.active().or(actual.staged()).ok_or(Error::State)?;
        let source = sources.source(version.digest()).ok_or(Error::Package)?;
        require_note_source(sources, source)?;
        let data = self.load_data_with_writes(sources, deadline, false)?;
        if app != sources.app() || data_epoch != data.schema_epoch() {
            return Err(Error::Corrupt);
        }
        let note = {
            let device = self.backend.device(Region::SessionNote, false);
            match Store::open(device, deadline) {
                Ok(mut store) => {
                    note_state::validated_note(&mut store, sources, deadline)
                        .map_err(|_| Error::Corrupt)?;
                    SetupHint::Ready
                }
                Err(rejected) if matches!(rejected.error, ev_store::Error::Unformatted) => {
                    let mut device = rejected.device;
                    ev_store::desktop::require_blank(&mut device, deadline)
                        .map_err(|_| Error::Storage)?;
                    SetupHint::OpenHello
                }
                Err(_) => return Err(Error::Storage),
            }
        };
        self.data = Some(data);
        Ok(note)
    }
}

fn require_note_source(sources: &impl Sources, source: Source) -> Result<(), Error> {
    let package = sources.checked_source(source).map_err(|_| Error::Package)?;
    let descriptor = package.app();
    if !descriptor
        .capability_requests()
        .any(|cap| cap.required && cap.capability == ev_zion::Capability::AppPrivateData)
        || !descriptor.contracts().any(|contract| {
            contract.name == ev_userspace_contract::session_note::INTERFACE
                && contract.major == 1
                && contract.minimum_minor == 0
                && contract.features == 0
        })
    {
        return Err(Error::Package);
    }
    Ok(())
}

#[cfg(test)]
#[path = "startup_setup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "startup_prepare_tests.rs"]
mod prepare_tests;
