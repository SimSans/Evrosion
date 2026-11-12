//! Bounded userspace durable operations and generation metadata; no filesystem
//! or device authority exists merely by linking this crate. SectorIo belongs to
//! the authorized storage-service backend, never the application's File API.
//! Checksums establish integrity, not publisher authentication. Health reports
//! require a trusted integration to bind actual admitted measured execution;
//! portable/model success alone certifies no hardware durability or boot health.
#![no_std]
#![forbid(unsafe_code)]
use sha2::{Digest as _, Sha256};
mod codec;
pub mod desktop;
pub mod native;
#[cfg(test)]
mod tests;

pub const SECTOR_BYTES: usize = 512;
/// Internal durable-record format. Version one is refused, never auto-migrated.
pub const FORMAT_VERSION: u16 = 2;
pub const PAYLOAD_BYTES: usize = 256;
pub const MANIFEST_BYTES: usize = 192;
pub const REQUIRED_SECTORS: u64 = 14;
pub const JOURNAL_SLOTS: u64 = 8;
pub const HEALTH_STORAGE: u32 = 1;
pub const HEALTH_SUPERVISOR: u32 = 2;
pub type Sector = [u8; SECTOR_BYTES];
pub type Digest = [u8; 32];
const ZERO: Digest = [0; 32];
const ROOT_KIND: u8 = 1;
const GEN_KIND: u8 = 2;
const USER_KIND: u8 = 3;
const OP_KIND: u8 = 4;
const USER_OBJECT: u64 = 1;
const GEN_BASE: u64 = 10;
const USER_BASE: u64 = 12;

/// Successful flush means the device confirmed preceding writes durable, not
/// merely copied into its cache. Implementations enforce the supplied absolute
/// monotonic deadline and preserve uncertain execution errors; never auto-retry.
/// The trusted integration must give one live Store exclusive ownership of the
/// entire physical region, including journal, roots and referenced data. Owning
/// one backend value or shared-buffer lease does not exclude a second backend
/// alias; old writers must be stopped before another Store opens the region.
pub trait SectorIo {
    type Error;
    fn sectors(&self) -> u64;
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error>;
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error>;
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationId(u64);
impl GenerationId {
    pub const fn new(id: u64) -> Option<Self> {
        if id != 0 && id != u64::MAX {
            Some(Self(id))
        } else {
            None
        }
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId(u64);
impl OperationId {
    pub const fn new(id: u64) -> Option<Self> {
        if id != 0 && id != u64::MAX {
            Some(Self(id))
        } else {
            None
        }
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId(u64);
impl ObjectId {
    pub const fn user_data() -> Self {
        Self(USER_OBJECT)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootPolicy {
    max_attempts: u8,
}
impl BootPolicy {
    pub const fn new(max_attempts: u8) -> Option<Self> {
        if max_attempts > 0 && max_attempts <= 8 {
            Some(Self { max_attempts })
        } else {
            None
        }
    }
}

/// Immutable coherent boot-critical cohort reference. Its resolver must verify
/// the complete trusted matching bundle and execute this exact supervisor/ABI.
/// Unchanged image bytes may be shared; no entire ELF lives in this small record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationManifest {
    pub generation: GenerationId,
    pub cohort: Digest,
    pub supervisor_image: Digest,
    pub abi: Digest,
    pub health_contract: Digest,
    pub health_version: u16,
    pub required_checks: u32,
}
impl GenerationManifest {
    pub fn valid(&self) -> bool {
        self.cohort != ZERO
            && self.supervisor_image != ZERO
            && self.abi != ZERO
            && self.health_contract != ZERO
            && self.health_version == 1
            && self.required_checks == (HEALTH_STORAGE | HEALTH_SUPERVISOR)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootPlan {
    pub manifest: GenerationManifest,
    pub serial: u64,
    pub candidate: bool,
    pub attempt: u8,
}
/// Stamp identifies actual admitted execution in the trusted observer. It is
/// diagnostic provenance, not a serialized capability or authority substitute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionReport {
    pub generation: GenerationId,
    pub boot_serial: u64,
    pub process_stamp: Digest,
    pub cohort: Digest,
    pub supervisor_image: Digest,
    pub abi: Digest,
    pub health_contract: Digest,
    pub health_version: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthOutcome {
    CriticalPassed,
    ProcessFault,
    MissingProgress,
    StorageFailure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthReport {
    pub admitted: AdmissionReport,
    pub outcome: HealthOutcome,
    pub observed_checks: u32,
    pub storage_probe: Digest,
}
/// Failure diagnostics, not proof that a supplied observer report was truthful.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastFailureReason {
    ProcessFault,
    MissingProgress,
    StorageFailure,
    AttemptBudgetExhausted,
}
/// One durable LAST failure, preserved across journal and manifest-slot reuse.
/// IDs/stamps are diagnostic provenance and never persistent capability handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastFailure {
    pub generation: GenerationId,
    pub boot_serial: u64,
    pub attempts: u8,
    pub reason: LastFailureReason,
    pub supervisor_image: Digest,
    pub process_stamp: Option<Digest>,
    pub operation: OperationId,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Stage(&'a GenerationManifest),
    Activate(GenerationId),
    BeginBoot(GenerationId),
    Admission(AdmissionReport),
    Health(HealthReport),
    WriteMutable { object: ObjectId, bytes: &'a [u8] },
    SelectKnownGood,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub operation: OperationId,
    pub sequence: u64,
    pub replayed: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    InvalidDeadline,
    Capacity,
    NotBlank,
    Unformatted,
    Corrupt,
    Unsupported,
    InvalidRequest,
    Conflict,
    StaleOperation,
    OutOfOrder,
    Phase,
    UnknownObject,
    NoSpace,
    Exhausted,
    StaleHealth,
    NeedsRecovery,
    RecoveryRequired,
}
pub struct RejectedDevice<D: SectorIo> {
    pub device: D,
    pub error: Error<D::Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GenerationRef {
    id: u64,
    digest: Digest,
    image: Digest,
    len: u16,
}
impl GenerationRef {
    const EMPTY: Self = Self {
        id: 0,
        digest: ZERO,
        image: ZERO,
        len: 0,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Root {
    sequence: u64,
    last_operation: u64,
    active: u8,
    known_good: u8,
    staged: u8,
    phase: u8,
    attempts: u8,
    max_attempts: u8,
    user_slot: u8,
    highest_generation: u64,
    generations: [GenerationRef; 2],
    user_len: u16,
    user_revision: u64,
    user_digest: Digest,
    admitted_stamp: Digest,
    boot_serial: u64,
    admitted_serial: u64,
    boot_pending: bool,
    last_failure: Option<LastFailure>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Operation {
    kind: u8,
    health: u8,
    generation: u64,
    boot_serial: u64,
    len: u16,
    body: [u8; PAYLOAD_BYTES],
    fingerprint: Digest,
}
impl Operation {
    fn from_request<E>(request: Request<'_>) -> Result<Self, Error<E>> {
        codec::operation(request)
    }
}
pub struct Store<D: SectorIo> {
    device: D,
    root: Root,
    buffer: Sector,
    poisoned: bool,
}
fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}
fn valid_deadline<E>(deadline: u64) -> Result<(), Error<E>> {
    if deadline == 0 || deadline == u64::MAX {
        Err(Error::InvalidDeadline)
    } else {
        Ok(())
    }
}

impl<D: SectorIo> Store<D> {
    pub fn format_new(
        mut device: D,
        initial: GenerationManifest,
        user: &[u8],
        policy: BootPolicy,
        deadline: u64,
    ) -> Result<Self, RejectedDevice<D>> {
        let result = (|| {
            valid_deadline(deadline)?;
            if device.sectors() < REQUIRED_SECTORS {
                return Err(Error::Capacity);
            }
            if !initial.valid() || user.len() > PAYLOAD_BYTES {
                return Err(Error::InvalidRequest);
            }
            let mut buffer = [0; SECTOR_BYTES];
            for lba in 0..REQUIRED_SECTORS {
                device.read(lba, &mut buffer, deadline).map_err(Error::Io)?;
                if buffer.iter().any(|&byte| byte != 0) {
                    return Err(Error::NotBlank);
                }
            }
            let manifest = codec::manifest(&initial);
            buffer = codec::data(GEN_KIND, initial.generation.get(), 0, &manifest);
            device
                .write(GEN_BASE, &buffer, deadline)
                .map_err(Error::Io)?;
            buffer = codec::data(USER_KIND, 1, USER_OBJECT, user);
            device
                .write(USER_BASE, &buffer, deadline)
                .map_err(Error::Io)?;
            device.flush(deadline).map_err(Error::Io)?;
            device
                .read(GEN_BASE, &mut buffer, deadline)
                .map_err(Error::Io)?;
            if codec::decode_data(&buffer, GEN_KIND, initial.generation.get(), 0)
                != Some(&manifest[..])
            {
                return Err(Error::Corrupt);
            }
            device
                .read(USER_BASE, &mut buffer, deadline)
                .map_err(Error::Io)?;
            if codec::decode_data(&buffer, USER_KIND, 1, USER_OBJECT) != Some(user) {
                return Err(Error::Corrupt);
            }
            let root = Root {
                sequence: 1,
                last_operation: 0,
                active: 0,
                known_good: 2,
                staged: 1,
                phase: 2,
                attempts: 0,
                max_attempts: policy.max_attempts,
                user_slot: 0,
                highest_generation: initial.generation.get(),
                generations: [
                    GenerationRef {
                        id: initial.generation.get(),
                        digest: digest(&manifest),
                        image: initial.supervisor_image,
                        len: MANIFEST_BYTES as u16,
                    },
                    GenerationRef::EMPTY,
                ],
                user_len: user.len() as u16,
                user_revision: 1,
                user_digest: digest(user),
                admitted_stamp: ZERO,
                boot_serial: 0,
                admitted_serial: 0,
                boot_pending: false,
                last_failure: None,
            };
            buffer = codec::root(&root);
            device.write(1, &buffer, deadline).map_err(Error::Io)?;
            device.flush(deadline).map_err(Error::Io)?;
            device.read(1, &mut buffer, deadline).map_err(Error::Io)?;
            if codec::decode_root(&buffer) != Some(root) {
                return Err(Error::Corrupt);
            }
            Ok(root)
        })();
        match result {
            Ok(root) => Ok(Self {
                device,
                root,
                buffer: [0; SECTOR_BYTES],
                poisoned: false,
            }),
            Err(error) => Err(RejectedDevice { device, error }),
        }
    }
    pub fn open(mut device: D, deadline: u64) -> Result<Self, RejectedDevice<D>> {
        let result = (|| {
            valid_deadline(deadline)?;
            if device.sectors() < REQUIRED_SECTORS {
                return Err(Error::Capacity);
            }
            let mut selected: Option<Root> = None;
            let mut buffer = [0; SECTOR_BYTES];
            let mut any = false;
            for lba in 0..2 {
                device.read(lba, &mut buffer, deadline).map_err(Error::Io)?;
                if codec::unsupported_format(&buffer) {
                    return Err(Error::Unsupported);
                }
                any |= buffer.iter().any(|&b| b != 0);
                if let Some(root) = codec::decode_root(&buffer) {
                    if let Some(old) = selected {
                        if old.sequence == root.sequence && old != root {
                            return Err(Error::Corrupt);
                        }
                        if root.sequence > old.sequence {
                            selected = Some(root);
                        }
                    } else {
                        selected = Some(root);
                    }
                }
            }
            selected.ok_or(if any {
                Error::Corrupt
            } else {
                Error::Unformatted
            })
        })();
        let root = match result {
            Ok(root) => root,
            Err(error) => return Err(RejectedDevice { device, error }),
        };
        let mut store = Self {
            device,
            root,
            buffer: [0; SECTOR_BYTES],
            poisoned: false,
        };
        let result = store
            .verify_references(deadline)
            .and_then(|()| store.recover(deadline))
            .and_then(|()| store.verify_references(deadline));
        match result {
            Ok(()) => Ok(store),
            Err(error) => Err(RejectedDevice {
                device: store.device,
                error,
            }),
        }
    }
    pub fn into_device(self) -> D {
        self.device
    }
    pub fn next_operation(&self) -> Result<OperationId, Error<D::Error>> {
        if self.poisoned {
            return Err(Error::NeedsRecovery);
        }
        self.root
            .last_operation
            .checked_add(1)
            .and_then(OperationId::new)
            .ok_or(Error::Exhausted)
    }
    pub fn selected_manifest(
        &mut self,
        deadline: u64,
    ) -> Result<GenerationManifest, Error<D::Error>> {
        self.check(deadline)?;
        if self.root.phase == 3 {
            return Err(Error::RecoveryRequired);
        }
        self.load_manifest(self.root.active, deadline)
    }
    pub fn known_good(&self) -> Option<GenerationId> {
        if self.root.known_good < 2 {
            Some(GenerationId(
                self.root.generations[self.root.known_good as usize].id,
            ))
        } else {
            None
        }
    }
    /// Exact staged candidate, if any. Metadata only: no activation or health.
    pub fn staged_manifest(
        &mut self,
        deadline: u64,
    ) -> Result<Option<GenerationManifest>, Error<D::Error>> {
        self.check(deadline)?;
        if self.root.staged == 0 {
            Ok(None)
        } else {
            self.load_manifest(self.root.staged - 1, deadline).map(Some)
        }
    }
    /// Read the LAST failure retained in committed root metadata. It does not
    /// depend on journal history or the failed generation's manifest slot.
    /// Report-based reasons require a matched admitted stamp. Bare exhaustion
    /// explicitly permits no admission; it does not invent an executed process.
    pub fn last_failure(&self) -> Result<Option<LastFailure>, Error<D::Error>> {
        if self.poisoned {
            Err(Error::NeedsRecovery)
        } else {
            Ok(self.root.last_failure)
        }
    }
    /// Current durable boot-attempt serial, including attempts already finished
    /// by health or rollback. This diagnostic counter creates no authority.
    pub fn committed_boot_serial(&self) -> Result<u64, Error<D::Error>> {
        if self.poisoned {
            Err(Error::NeedsRecovery)
        } else {
            Ok(self.root.boot_serial)
        }
    }
    /// Highest generation ID ever staged, even after its manifest slot is reused
    /// or selection rolls back. This diagnostic counter creates no authority.
    pub fn highest_generation(&self) -> Result<u64, Error<D::Error>> {
        if self.poisoned {
            Err(Error::NeedsRecovery)
        } else {
            Ok(self.root.highest_generation)
        }
    }
    pub fn boot_plan(&mut self, deadline: u64) -> Result<BootPlan, Error<D::Error>> {
        self.check(deadline)?;
        if self.root.phase == 3 {
            return Err(Error::RecoveryRequired);
        }
        if !self.root.boot_pending {
            return Err(Error::Phase);
        }
        Ok(BootPlan {
            manifest: self.load_manifest(self.root.active, deadline)?,
            serial: self.root.boot_serial,
            candidate: self.root.phase == 2,
            attempt: self.root.attempts,
        })
    }
    pub fn read_mutable(
        &mut self,
        object: ObjectId,
        out: &mut [u8; PAYLOAD_BYTES],
        deadline: u64,
    ) -> Result<usize, Error<D::Error>> {
        self.check(deadline)?;
        if object.0 != USER_OBJECT {
            return Err(Error::UnknownObject);
        }
        self.device
            .read(
                USER_BASE + u64::from(self.root.user_slot),
                &mut self.buffer,
                deadline,
            )
            .map_err(|error| {
                self.poisoned = true;
                Error::Io(error)
            })?;
        if codec::unsupported_format(&self.buffer) {
            return Err(Error::Unsupported);
        }
        let body = codec::decode_data(
            &self.buffer,
            USER_KIND,
            self.root.user_revision,
            USER_OBJECT,
        )
        .ok_or(Error::Corrupt)?;
        if body.len() != usize::from(self.root.user_len) || digest(body) != self.root.user_digest {
            return Err(Error::Corrupt);
        }
        out.fill(0);
        out[..body.len()].copy_from_slice(body);
        Ok(body.len())
    }
    pub fn execute(
        &mut self,
        id: OperationId,
        request: Request<'_>,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        self.check(deadline)?;
        let operation = Operation::from_request(request)?;
        if let Err(error) = self.verify_references(deadline) {
            self.poisoned = true;
            return Err(error);
        }
        if id.get() <= self.root.last_operation {
            self.device
                .read(2 + id.get() % JOURNAL_SLOTS, &mut self.buffer, deadline)
                .map_err(|error| {
                    self.poisoned = true;
                    Error::Io(error)
                })?;
            if codec::unsupported_format(&self.buffer) {
                self.poisoned = true;
                return Err(Error::Unsupported);
            }
            let Some((found, _, record)) = codec::decode_operation(&self.buffer) else {
                return Err(Error::StaleOperation);
            };
            if found != id.get() {
                return Err(Error::StaleOperation);
            }
            if record.fingerprint != operation.fingerprint {
                return Err(Error::Conflict);
            }
            return Ok(Receipt {
                operation: id,
                sequence: id.get() + 1,
                replayed: true,
            });
        }
        if id != self.next_operation()? {
            return Err(Error::OutOfOrder);
        }
        let next = match self.transition(&operation, deadline) {
            Ok(next) => next,
            Err(error) => {
                if matches!(error, Error::Io(_)) {
                    self.poisoned = true;
                }
                return Err(error);
            }
        };
        let result = (|| {
            self.buffer = codec::journal(id.get(), self.root.sequence, &operation);
            self.device
                .write(2 + id.get() % JOURNAL_SLOTS, &self.buffer, deadline)
                .map_err(Error::Io)?;
            self.device.flush(deadline).map_err(Error::Io)?;
            self.device
                .read(2 + id.get() % JOURNAL_SLOTS, &mut self.buffer, deadline)
                .map_err(Error::Io)?;
            let Some((found, base, recorded)) = codec::decode_operation(&self.buffer) else {
                return Err(Error::Corrupt);
            };
            if found != id.get() || base != self.root.sequence || recorded != operation {
                return Err(Error::Corrupt);
            }
            self.publish(id, &operation, next, deadline)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn check(&self, deadline: u64) -> Result<(), Error<D::Error>> {
        valid_deadline(deadline)?;
        if self.poisoned {
            Err(Error::NeedsRecovery)
        } else {
            Ok(())
        }
    }
    fn load_manifest(
        &mut self,
        slot: u8,
        deadline: u64,
    ) -> Result<GenerationManifest, Error<D::Error>> {
        let reference = self.root.generations[slot as usize];
        self.device
            .read(GEN_BASE + u64::from(slot), &mut self.buffer, deadline)
            .map_err(|error| {
                self.poisoned = true;
                Error::Io(error)
            })?;
        if codec::unsupported_format(&self.buffer) {
            return Err(Error::Unsupported);
        }
        let body =
            codec::decode_data(&self.buffer, GEN_KIND, reference.id, 0).ok_or(Error::Corrupt)?;
        if body.len() != usize::from(reference.len) || digest(body) != reference.digest {
            return Err(Error::Corrupt);
        }
        let manifest = codec::decode_manifest(body).ok_or(Error::Corrupt)?;
        if manifest.generation.get() != reference.id || manifest.supervisor_image != reference.image
        {
            return Err(Error::Corrupt);
        }
        Ok(manifest)
    }
    fn verify_references(&mut self, deadline: u64) -> Result<(), Error<D::Error>> {
        self.load_manifest(self.root.active, deadline)?;
        if self.root.known_good < 2 {
            self.load_manifest(self.root.known_good, deadline)?;
        }
        if self.root.staged != 0 {
            self.load_manifest(self.root.staged - 1, deadline)?;
        }
        self.read_mutable(ObjectId::user_data(), &mut [0; PAYLOAD_BYTES], deadline)?;
        Ok(())
    }
    fn recover(&mut self, deadline: u64) -> Result<(), Error<D::Error>> {
        let Some(next) = self
            .root
            .last_operation
            .checked_add(1)
            .and_then(OperationId::new)
        else {
            return Ok(());
        };
        let mut pending = None;
        for slot in 0..JOURNAL_SLOTS {
            self.device
                .read(2 + slot, &mut self.buffer, deadline)
                .map_err(Error::Io)?;
            if codec::unsupported_format(&self.buffer) {
                return Err(Error::Unsupported);
            }
            if let Some((id, base, operation)) = codec::decode_operation(&self.buffer) {
                if id > next.get() {
                    return Err(Error::Corrupt);
                }
                if id == next.get() {
                    if base != self.root.sequence || pending.is_some() {
                        return Err(Error::Corrupt);
                    }
                    pending = Some(operation);
                }
            }
        }
        if let Some(operation) = pending {
            let state = self.transition(&operation, deadline)?;
            self.publish(next, &operation, state, deadline)?;
        }
        Ok(())
    }
    fn transition(
        &mut self,
        operation: &Operation,
        deadline: u64,
    ) -> Result<Root, Error<D::Error>> {
        let mut root = self.root;
        match operation.kind {
            1 => {
                let manifest =
                    codec::decode_manifest(&operation.body[..usize::from(operation.len)])
                        .ok_or(Error::InvalidRequest)?;
                if root.phase != 0 || root.boot_pending {
                    return Err(Error::NoSpace);
                }
                if manifest.generation.get() <= root.highest_generation {
                    return Err(Error::InvalidRequest);
                }
                let slot = 1 - root.known_good;
                root.generations[slot as usize] = GenerationRef {
                    id: manifest.generation.get(),
                    digest: digest(&operation.body[..usize::from(operation.len)]),
                    image: manifest.supervisor_image,
                    len: operation.len,
                };
                root.staged = slot + 1;
                root.phase = 1;
                root.highest_generation = manifest.generation.get();
                root.attempts = 0;
            }
            2 => {
                if root.phase != 1
                    || root.generations[(root.staged - 1) as usize].id != operation.generation
                {
                    return Err(Error::Phase);
                }
                self.load_manifest(root.staged - 1, deadline)?;
                root.active = root.staged - 1;
                root.phase = 2;
                root.attempts = 0;
                root.admitted_stamp = ZERO;
                root.admitted_serial = 0;
                root.boot_pending = false;
            }
            3 => {
                if !matches!(root.phase, 0 | 2)
                    || root.generations[root.active as usize].id != operation.generation
                {
                    return Err(Error::Phase);
                }
                if root.attempts >= root.max_attempts {
                    // Preserve the exhausted generation BEFORE rollback and
                    // before A may receive a new charged serial/attempt.
                    root.last_failure = Some(Self::failure(
                        &root,
                        root.generations[root.active as usize].id,
                        root.generations[root.active as usize].image,
                        (root.admitted_stamp != ZERO).then_some(root.admitted_stamp),
                        LastFailureReason::AttemptBudgetExhausted,
                    )?);
                    if root.phase == 2 && root.known_good < 2 {
                        Self::rollback(&mut root);
                    } else {
                        Self::rollback(&mut root);
                        root.phase = 3;
                    }
                }
                if root.phase != 3 {
                    root.boot_serial = root.boot_serial.checked_add(1).ok_or(Error::Exhausted)?;
                    root.attempts += 1;
                    root.admitted_stamp = ZERO;
                    root.admitted_serial = 0;
                    root.boot_pending = true;
                }
            }
            4 | 5 => {
                let report = codec::decode_admission(operation).ok_or(Error::InvalidRequest)?;
                let manifest = self.load_manifest(root.active, deadline)?;
                if !matches!(root.phase, 0 | 2)
                    || !root.boot_pending
                    || root.attempts == 0
                    || report.generation != manifest.generation
                    || report.boot_serial != root.boot_serial
                    || report.process_stamp == ZERO
                    || report.cohort != manifest.cohort
                    || report.supervisor_image != manifest.supervisor_image
                    || report.abi != manifest.abi
                    || report.health_contract != manifest.health_contract
                    || report.health_version != manifest.health_version
                {
                    return Err(Error::StaleHealth);
                }
                if operation.kind == 4 {
                    if root.admitted_stamp != ZERO {
                        return Err(Error::Phase);
                    }
                    root.admitted_stamp = report.process_stamp;
                    root.admitted_serial = root.boot_serial;
                } else {
                    if root.admitted_stamp != report.process_stamp
                        || root.admitted_serial != report.boot_serial
                    {
                        return Err(Error::StaleHealth);
                    }
                    if operation.health == 1 {
                        let (checks, probe) =
                            codec::health_details(operation).ok_or(Error::InvalidRequest)?;
                        if checks != manifest.required_checks || probe != root.user_digest {
                            return Err(Error::StaleHealth);
                        }
                        root.known_good = root.active;
                        root.staged = 0;
                        root.phase = 0;
                        root.attempts = 0;
                        root.admitted_stamp = ZERO;
                        root.admitted_serial = 0;
                        root.boot_pending = false;
                    } else {
                        let reason = match operation.health {
                            2 => LastFailureReason::ProcessFault,
                            3 => LastFailureReason::MissingProgress,
                            4 => LastFailureReason::StorageFailure,
                            _ => return Err(Error::InvalidRequest),
                        };
                        root.last_failure = Some(Self::failure(
                            &root,
                            manifest.generation.get(),
                            manifest.supervisor_image,
                            Some(report.process_stamp),
                            reason,
                        )?);
                        let candidate = root.phase == 2
                            && root.known_good < 2
                            && root.active != root.known_good;
                        Self::rollback(&mut root);
                        if !candidate {
                            root.phase = 3;
                        }
                    }
                }
            }
            6 => {
                root.user_slot = 1 - root.user_slot;
                root.user_revision = root.user_revision.checked_add(1).ok_or(Error::Exhausted)?;
                root.user_len = operation.len;
                root.user_digest = digest(&operation.body[..usize::from(operation.len)]);
            }
            7 => {
                if root.known_good >= 2 {
                    return Err(Error::RecoveryRequired);
                }
                Self::rollback(&mut root);
            }
            _ => return Err(Error::InvalidRequest),
        }
        root.sequence = root.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        root.last_operation = root.last_operation.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(root)
    }
    fn failure(
        root: &Root,
        generation: u64,
        supervisor_image: Digest,
        process_stamp: Option<Digest>,
        reason: LastFailureReason,
    ) -> Result<LastFailure, Error<D::Error>> {
        Ok(LastFailure {
            generation: GenerationId::new(generation).ok_or(Error::Corrupt)?,
            boot_serial: root.boot_serial,
            attempts: root.attempts,
            reason,
            supervisor_image,
            process_stamp,
            operation: root
                .last_operation
                .checked_add(1)
                .and_then(OperationId::new)
                .ok_or(Error::Exhausted)?,
            sequence: root.sequence.checked_add(1).ok_or(Error::Exhausted)?,
        })
    }
    fn rollback(root: &mut Root) {
        if root.known_good < 2 {
            root.active = root.known_good;
            root.phase = 0;
        } else {
            root.phase = 3;
        }
        root.staged = 0;
        root.attempts = 0;
        root.admitted_stamp = ZERO;
        root.admitted_serial = 0;
        root.boot_pending = false;
    }
    fn publish(
        &mut self,
        id: OperationId,
        operation: &Operation,
        next: Root,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        match operation.kind {
            1 => {
                let slot = next.staged - 1;
                self.buffer = codec::data(
                    GEN_KIND,
                    operation.generation,
                    0,
                    &operation.body[..usize::from(operation.len)],
                );
                self.device
                    .write(GEN_BASE + u64::from(slot), &self.buffer, deadline)
                    .map_err(Error::Io)?;
                self.device.flush(deadline).map_err(Error::Io)?;
                self.device
                    .read(GEN_BASE + u64::from(slot), &mut self.buffer, deadline)
                    .map_err(Error::Io)?;
                if codec::decode_data(&self.buffer, GEN_KIND, operation.generation, 0)
                    != Some(&operation.body[..usize::from(operation.len)])
                {
                    return Err(Error::Corrupt);
                }
            }
            6 => {
                self.buffer = codec::data(
                    USER_KIND,
                    next.user_revision,
                    USER_OBJECT,
                    &operation.body[..usize::from(operation.len)],
                );
                self.device
                    .write(
                        USER_BASE + u64::from(next.user_slot),
                        &self.buffer,
                        deadline,
                    )
                    .map_err(Error::Io)?;
                self.device.flush(deadline).map_err(Error::Io)?;
                self.device
                    .read(
                        USER_BASE + u64::from(next.user_slot),
                        &mut self.buffer,
                        deadline,
                    )
                    .map_err(Error::Io)?;
                if codec::decode_data(&self.buffer, USER_KIND, next.user_revision, USER_OBJECT)
                    != Some(&operation.body[..usize::from(operation.len)])
                {
                    return Err(Error::Corrupt);
                }
            }
            _ => (),
        }
        self.buffer = codec::root(&next);
        self.device
            .write(next.sequence % 2, &self.buffer, deadline)
            .map_err(Error::Io)?;
        self.device.flush(deadline).map_err(Error::Io)?;
        self.device
            .read(next.sequence % 2, &mut self.buffer, deadline)
            .map_err(Error::Io)?;
        if codec::decode_root(&self.buffer) != Some(next) {
            return Err(Error::Corrupt);
        }
        self.root = next;
        Ok(Receipt {
            operation: id,
            sequence: next.sequence,
            replayed: false,
        })
    }
}
