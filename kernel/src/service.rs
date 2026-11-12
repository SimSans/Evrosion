//! Bounded capability-controlled service creation and owned initial admission.
//! The same trusted controller retains this registry and its Authority/Scheduler.
//! No raw scheduler identity is accepted from userspace; Root BAC custody and
//! replacement are separate. Explicit stopped cleanup permits descriptor/domain
//! reuse; actual hardware quiescence remains the controller's responsibility.
pub mod managed_read;
use crate::{
    capability::{self, Authority, Handle, Kind, MAX_SPACES, Rights, SpaceId},
    executable::{self, Image, LayoutReservation},
    loaded_image::{LoadedExecutable, Startup},
    mapping::ADDRESS_MASK,
    memory::FRAME_SIZE,
    rpc::Rpc,
    scheduler::{self, JobId, Limits, ProcessId, Resource, Scheduler, ThreadId},
    user_context::UserContext,
};
use core::num::NonZeroU64;
use sha2::{Digest, Sha256};

pub const SERVICE_LIMITS: Limits = Limits::new(128, 16, 1, 1);
/// Sustained development workload; still finite and charged across replacements.
// Its entire hardware proof has a 2048-tick global deadline. Use that same finite
// upper bound so QEMU polling/preemption variation cannot select the result.
pub const RESTART_SERVICE_LIMITS: Limits = Limits::new(2048, 16, 1, 1);
/// Typed registry storage is independent of global Authority object slots.
/// These bounds cover the fixed cohort plus retained replacement candidates.
pub const MAX_JOB_RECORDS: usize = 16;
pub const MAX_IMAGE_RECORDS: usize = 16;
pub const MAX_PROCESS_RECORDS: usize = 16;
const MAX_ROLES: usize = ev_userspace_contract::MAX_GRANTS;
const _: () = assert!(MAX_ROLES <= capability::MAX_CAPS);
#[cfg(test)]
use crate::capability::{MAX_CAPS, MAX_OBJECTS};
const BRANCH: Rights = Rights::from_bits(224).unwrap();
const PROCESS_RIGHTS: Rights = Rights::from_bits(481).unwrap();
const ENDPOINT_RIGHTS: Rights = Rights::from_bits(504).unwrap();
const RESOURCES: [Resource; 4] = [
    Resource::CpuTicks,
    Resource::Frames,
    Resource::Processes,
    Resource::Threads,
];

fn valid_limits(limits: Limits) -> bool {
    RESOURCES
        .iter()
        .all(|&r| !matches!(limits.limit(r), 0 | u64::MAX))
        && limits.limit(Resource::Processes) <= scheduler::MAX_PROCESSES as u64
        && limits.limit(Resource::Threads) <= scheduler::MAX_THREADS as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Role {
    pub selector: u64,
    pub kind: Kind,
    pub rights: Rights,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority(capability::Error),
    Scheduler(scheduler::Error),
    Executable(executable::Error),
    Ipc(crate::ipc::Error),
    Bootstrap(ev_userspace_contract::Error),
    Measurement,
    Descriptor,
    UnknownObject,
    Capacity,
    AlreadyRegistered,
    UnsupportedTemplate,
    JobLimits,
    Phase,
    Role,
    ImageMismatch,
    Incarnation,
}
impl From<capability::Error> for Error {
    fn from(e: capability::Error) -> Self {
        Self::Authority(e)
    }
}
impl From<scheduler::Error> for Error {
    fn from(e: scheduler::Error) -> Self {
        Self::Scheduler(e)
    }
}
impl From<executable::Error> for Error {
    fn from(e: executable::Error) -> Self {
        Self::Executable(e)
    }
}
impl From<crate::ipc::Error> for Error {
    fn from(e: crate::ipc::Error) -> Self {
        Self::Ipc(e)
    }
}
fn kind_tag(kind: Kind) -> u8 {
    match kind {
        Kind::Memory => 1,
        Kind::Endpoint => 2,
        Kind::Process => 3,
        Kind::Thread => 4,
        Kind::Job => 5,
        Kind::Mutex => 6,
        Kind::IoPorts => 7,
        Kind::Display => 8,
    }
}

/// Immutable measured service policy. Roles describe requested authority, not
/// runtime handles or a fixed digest of newly created per-instance objects.
pub struct ServiceImage<'a> {
    bytes: &'a [u8],
    digest: [u8; 32],
    limits: Limits,
    roles: [Option<Role>; MAX_ROLES],
    count: usize,
    layout: LayoutReservation,
}
impl<'a> ServiceImage<'a> {
    pub fn verify(
        bytes: &'a [u8],
        expected_image_sha: [u8; 32],
        limits: Limits,
        roles: &[Role],
    ) -> Result<Self, Error> {
        Self::verify_layout(
            bytes,
            expected_image_sha,
            limits,
            roles,
            LayoutReservation::Legacy,
        )
    }
    /// Additive version2 descriptor for an explicitly requested fixed display
    /// reservation. No service-supplied pointer/layout and no out-of-window ELF
    /// segment is accepted. A distinct Display grant remains required at runtime.
    pub fn verify_layout(
        bytes: &'a [u8],
        expected_image_sha: [u8; 32],
        limits: Limits,
        roles: &[Role],
        layout: LayoutReservation,
    ) -> Result<Self, Error> {
        if bytes.len() > crate::bootstrap_manifest::MAX_IMAGE_BYTES
            || Sha256::digest(bytes).as_slice() != expected_image_sha
        {
            return Err(Error::Measurement);
        }
        if roles.is_empty()
            || roles.len() > ev_userspace_contract::MAX_GRANTS
            || !valid_limits(limits)
        {
            return Err(Error::Descriptor);
        }
        if layout == LayoutReservation::DisplayApertureV1 {
            let mut displays = roles.iter().filter(|role| role.kind == Kind::Display);
            if displays
                .next()
                .is_none_or(|role| role.rights != (Rights::READ | Rights::WRITE | Rights::MAP))
                || displays.next().is_some()
            {
                return Err(Error::Role);
            }
        }
        let mut previous = 0;
        let mut saved = [None; MAX_ROLES];
        let mut hash = Sha256::new();
        hash.update(match layout {
            LayoutReservation::Legacy => b"evrosion.service.descriptor.v1\0".as_slice(),
            LayoutReservation::DisplayApertureV1 => b"evrosion.service.descriptor.v2\0".as_slice(),
        });
        hash.update(expected_image_sha);
        hash.update(ev_userspace_contract::ABI);
        for r in RESOURCES {
            hash.update(limits.limit(r).to_le_bytes());
        }
        hash.update((roles.len() as u64).to_le_bytes());
        for (i, role) in roles.iter().copied().enumerate() {
            if role.selector <= previous
                || role.rights.bits() == 0
                || !role.kind.permits(role.rights)
            {
                return Err(Error::Role);
            }
            previous = role.selector;
            saved[i] = Some(role);
            hash.update(role.selector.to_le_bytes());
            hash.update([kind_tag(role.kind)]);
            hash.update(role.rights.bits().to_le_bytes());
        }
        if layout == LayoutReservation::DisplayApertureV1 {
            // Closed normalized reservation transcript, including exact guards,
            // table count and mandatory USER|RW|NX permissions. V1 appends none.
            hash.update([1]);
            for value in [
                executable::DISPLAY_RELATIVE_START,
                executable::DISPLAY_MAXIMUM_BYTES,
                executable::DISPLAY_LOWER_GUARD,
                executable::DISPLAY_UPPER_GUARD,
                executable::DISPLAY_TABLE_FRAMES,
                7,
                1u64 << 63,
            ] {
                hash.update(value.to_le_bytes());
            }
        }
        let result = Self {
            bytes,
            digest: hash.finalize().into(),
            limits,
            roles: saved,
            count: roles.len(),
            layout,
        };
        result.plan()?;
        Ok(result)
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub const fn layout(&self) -> LayoutReservation {
        self.layout
    }
    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        self.roles[..self.count].iter().flatten().copied()
    }
    pub fn plan(&self) -> Result<Image<'a>, Error> {
        Ok(Image::from_descriptor_with_layout(
            self.bytes,
            self.digest,
            ev_userspace_contract::ABI,
            self.limits,
            self.layout,
        )?)
    }
}

/// Trusted kernel-facing diagnostic/ownership coordinates, never syscall IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub process: ProcessId,
    pub thread: ThreadId,
    pub job: JobId,
    pub domain: SpaceId,
    pub frames: u64,
}
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Source {
    owner: SpaceId,
    handle: Handle,
}
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Delegated {
    source: Source,
    private: Handle,
    grant: Handle,
}
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
enum Phase {
    Held,
    Active,
    Retired,
}
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Process {
    object: usize,
    metadata: Metadata,
    branches: SpaceId,
    image: usize,
    image_source: Source,
    grants: [Option<Delegated>; MAX_ROLES],
    phase: Phase,
}
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
enum JobOrigin {
    External,
    Managed,
}
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Job {
    object: usize,
    actual: JobId,
    origin: JobOrigin,
}
/// A failed channel replacement retains the unique retired escrow receipt.
#[derive(Debug)]
pub struct RejectedChannel {
    pub receipt: crate::ipc::RetiredMailbox,
    pub error: Error,
}
/// One private revocation parent for a grant to an already admitted process.
/// It is distinct from the controller's retained service endpoint source. Drop
/// performs no revocation; the lifecycle owner must explicitly retire it before
/// forgetting the recipient's private domain.
#[must_use]
pub struct ActiveGrantBranch {
    owner: SpaceId,
    parent: Handle,
    metadata: Metadata,
}
pub struct RejectedActiveGrantBranch {
    pub branch: ActiveGrantBranch,
    pub error: Error,
}
impl ActiveGrantBranch {
    pub fn metadata(&self) -> Metadata {
        self.metadata
    }
    /// Decrease authority using the retained actual branch receipt. Revoked
    /// controller/recipient public capabilities never block this operation.
    #[allow(clippy::result_large_err)]
    pub fn retire(self, a: &mut Authority) -> Result<(), RejectedActiveGrantBranch> {
        let mut staged = a.staged_copy();
        let result = (|| -> Result<(), Error> {
            staged.revoke_batch(self.owner, &[self.parent])?;
            staged.close(self.owner, self.parent)?;
            staged.collect_lineage()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                *a = staged;
                Ok(())
            }
            Err(error) => Err(RejectedActiveGrantBranch {
                branch: self,
                error,
            }),
        }
    }
}
pub struct Registry<'a> {
    incarnation: NonZeroU64,
    service_limits: Limits,
    jobs: [Option<Job>; MAX_JOB_RECORDS],
    images: [Option<(usize, ServiceImage<'a>)>; MAX_IMAGE_RECORDS],
    processes: [Option<Process>; MAX_PROCESS_RECORDS],
    closed_domains: [Option<SpaceId>; MAX_SPACES],
}
#[cfg(test)]
fn object_slot(identity: usize) -> Result<usize, Error> {
    let slot = identity & 255;
    if slot < MAX_OBJECTS {
        Ok(slot)
    } else {
        Err(Error::UnknownObject)
    }
}
fn take_domain(
    staged: &mut Authority,
    pool: &mut [Option<SpaceId>; MAX_SPACES],
) -> Result<SpaceId, Error> {
    if let Some(slot) = pool.iter().position(Option::is_some) {
        let next = staged.recycle_space(pool[slot].unwrap())?;
        pool[slot] = None;
        Ok(next)
    } else {
        Ok(staged.create_space()?)
    }
}
impl Default for Registry<'_> {
    fn default() -> Self {
        Self::new()
    }
}
impl<'a> Registry<'a> {
    /// Retained Job/image/process rows and explicitly pooled closed domains.
    pub fn metadata_usage(&self) -> (usize, usize, usize, usize) {
        (
            self.jobs.iter().flatten().count(),
            self.images.iter().flatten().count(),
            self.processes.iter().flatten().count(),
            self.closed_domains.iter().flatten().count(),
        )
    }
    pub const fn new() -> Self {
        Self::for_incarnation(NonZeroU64::new(1).unwrap())
    }
    /// Trusted parent incarnation identity; no registry reset authorizes restart.
    pub const fn for_incarnation(incarnation: NonZeroU64) -> Self {
        Self {
            incarnation,
            service_limits: SERVICE_LIMITS,
            jobs: [None; MAX_JOB_RECORDS],
            images: [const { None }; MAX_IMAGE_RECORDS],
            processes: [None; MAX_PROCESS_RECORDS],
            closed_domains: [None; MAX_SPACES],
        }
    }
    /// Trusted immutable profile selection, never supplied by a userspace call.
    /// Template zero uses this finite budget; replacement preserves Job history.
    pub fn with_service_limits(incarnation: NonZeroU64, limits: Limits) -> Result<Self, Error> {
        if !valid_limits(limits) {
            return Err(Error::Descriptor);
        }
        let mut registry = Self::for_incarnation(incarnation);
        registry.service_limits = limits;
        Ok(registry)
    }
    /// Trusted once-only binding of an existing object to its actual scheduler Job.
    pub fn register_job(
        &mut self,
        a: &Authority,
        space: SpaceId,
        cap: Handle,
        job: JobId,
    ) -> Result<(), Error> {
        let id = a
            .authorize(space, cap, Kind::Job, Rights::CONTROL)?
            .identity();
        if self
            .jobs
            .iter()
            .flatten()
            .any(|bound| bound.object == id || bound.actual == job)
        {
            return Err(Error::AlreadyRegistered);
        }
        let slot = self
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.jobs[slot] = Some(Job {
            object: id,
            actual: job,
            origin: JobOrigin::External,
        });
        Ok(())
    }
    /// Trusted once-only binding of a measured descriptor to a readable object.
    pub fn register_image(
        &mut self,
        a: &Authority,
        space: SpaceId,
        cap: Handle,
        image: ServiceImage<'a>,
    ) -> Result<(), Error> {
        let id = a
            .authorize(space, cap, Kind::Memory, Rights::READ)?
            .identity();
        if self.images.iter().flatten().any(|(key, _)| *key == id) {
            return Err(Error::AlreadyRegistered);
        }
        let slot = self
            .images
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.images[slot] = Some((id, image));
        Ok(())
    }
    fn job(&self, a: &Authority, caller: SpaceId, cap: Handle) -> Result<JobId, Error> {
        let id = a
            .authorize(caller, cap, Kind::Job, Rights::CONTROL)?
            .identity();
        self.jobs
            .iter()
            .flatten()
            .find(|job| job.object == id)
            .map(|job| job.actual)
            .ok_or(Error::UnknownObject)
    }
    /// Capture an actual generational Job identity while its exact CONTROL
    /// grant is live. This is trusted lifecycle metadata, never a syscall ID.
    pub fn job_id(&self, a: &Authority, caller: SpaceId, cap: Handle) -> Result<JobId, Error> {
        self.job(a, caller, cap)
    }
    /// Forget only an empty, unreferenced actual Job. Managed objects must have
    /// no escaped authority nodes; external sealed objects remain intact. Both
    /// tables and the row commit together, without refunding ancestor CPU use.
    /// Hardware consumers must already be stopped by the trusted lifecycle owner.
    pub fn forget_job(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        rpc: &Rpc,
        job: JobId,
    ) -> Result<(), Error> {
        let slot = self
            .jobs
            .iter()
            .position(|row| row.is_some_and(|row| row.actual == job))
            .ok_or(Error::UnknownObject)?;
        let row = self.jobs[slot].ok_or(Error::UnknownObject)?;
        if self
            .processes
            .iter()
            .flatten()
            .any(|p| p.metadata.job == job)
            || rpc.references_job(job)
        {
            return Err(Error::Phase);
        }
        let mut authority = a.staged_copy();
        let mut scheduler = s.staged_copy();
        scheduler.reclaim_job(job)?;
        if row.origin == JobOrigin::Managed {
            authority.collect_lineage()?;
            authority.retire_unreferenced_object(row.object, Kind::Job)?;
            authority.collect_dead_objects()?;
        }
        *a = authority;
        *s = scheduler;
        self.jobs[slot] = None;
        Ok(())
    }
    /// Select the next immutable incarnation only after all old Job/process
    /// rows have been forgotten through their lifecycle gates. Images, domain
    /// pool, profile and all external Authority/Scheduler history are retained.
    /// This metadata operation is not a physical quiescence witness.
    pub fn advance_incarnation(&mut self, next: NonZeroU64) -> Result<(), Error> {
        if self.incarnation.get().checked_add(1) != Some(next.get()) {
            return Err(Error::Incarnation);
        }
        if self.jobs.iter().any(Option::is_some) || self.processes.iter().any(Option::is_some) {
            return Err(Error::Phase);
        }
        self.incarnation = next;
        Ok(())
    }
    fn process(
        &self,
        a: &Authority,
        caller: SpaceId,
        cap: Handle,
    ) -> Result<(usize, Process), Error> {
        let id = a
            .authorize(caller, cap, Kind::Process, Rights::CONTROL)?
            .identity();
        let slot = self
            .processes
            .iter()
            .position(|row| row.is_some_and(|p| p.object == id))
            .ok_or(Error::UnknownObject)?;
        let process = self.processes[slot].ok_or(Error::UnknownObject)?;
        Ok((slot, process))
    }
    fn image(&self, id: usize) -> Result<&ServiceImage<'a>, Error> {
        self.images
            .iter()
            .flatten()
            .find(|(key, _)| *key == id)
            .map(|(_, image)| image)
            .ok_or(Error::UnknownObject)
    }
    fn held(&self, process: Process) -> Result<&ServiceImage<'a>, Error> {
        if process.phase != Phase::Held {
            return Err(Error::Phase);
        }
        self.image(process.image)
    }
    pub fn create_job(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        caller: SpaceId,
        creator: Handle,
        template: u64,
    ) -> Result<Handle, Error> {
        let parent = self.job(a, caller, creator)?;
        if template != 0 {
            return Err(Error::UnsupportedTemplate);
        }
        let slot = self
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut authority = a.staged_copy();
        let mut scheduler = s.staged_copy();
        let job = scheduler.create_child_job(parent, self.service_limits)?;
        let cap = authority.create_managed(caller, creator, Kind::Job, PROCESS_RIGHTS)?;
        let id = authority
            .authorize(caller, cap, Kind::Job, Rights::CONTROL)?
            .identity();
        *a = authority;
        *s = scheduler;
        self.jobs[slot] = Some(Job {
            object: id,
            actual: job,
            origin: JobOrigin::Managed,
        });
        Ok(cap)
    }
    pub fn create_endpoint(
        &mut self,
        a: &mut Authority,
        caller: SpaceId,
        job: Handle,
    ) -> Result<Handle, Error> {
        self.job(a, caller, job)?;
        let mut staged = a.staged_copy();
        let cap = staged.create_managed(caller, job, Kind::Endpoint, ENDPOINT_RIGHTS)?;
        *a = staged;
        Ok(cap)
    }
    /// Create the endpoint and its unique bounded escrow mailbox in one commit.
    /// Escrow-space exhaustion must not leave a granted but unbound endpoint.
    pub fn create_channel(
        &mut self,
        a: &mut Authority,
        caller: SpaceId,
        job: Handle,
    ) -> Result<(Handle, crate::ipc::Mailbox), Error> {
        self.job(a, caller, job)?;
        let mut staged = a.staged_copy();
        let cap = staged.create_managed(caller, job, Kind::Endpoint, ENDPOINT_RIGHTS)?;
        let mailbox = crate::ipc::Mailbox::new_managed(&mut staged, caller, cap)?;
        *a = staged;
        Ok((cap, mailbox))
    }
    /// Reuse exactly one consumed managed escrow receipt in an atomic channel
    /// creation. A rejected request returns that same receipt and cannot consume
    /// an endpoint identity, handle generation or escrow-space generation.
    pub fn create_channel_reusing(
        &mut self,
        a: &mut Authority,
        caller: SpaceId,
        job: Handle,
        receipt: crate::ipc::RetiredMailbox,
    ) -> Result<(Handle, crate::ipc::Mailbox), RejectedChannel> {
        if let Err(error) = self.job(a, caller, job) {
            return Err(RejectedChannel { receipt, error });
        }
        let mut staged = a.staged_copy();
        let cap = match staged.create_managed(caller, job, Kind::Endpoint, ENDPOINT_RIGHTS) {
            Ok(cap) => cap,
            Err(error) => {
                return Err(RejectedChannel {
                    receipt,
                    error: error.into(),
                });
            }
        };
        match crate::ipc::Mailbox::new_reusing(&mut staged, caller, cap, receipt) {
            Ok(mailbox) => {
                *a = staged;
                Ok((cap, mailbox))
            }
            Err(rejected) => Err(RejectedChannel {
                receipt: rejected.receipt,
                error: rejected.error.into(),
            }),
        }
    }
    pub fn create_process(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        caller: SpaceId,
        job_cap: Handle,
        image_cap: Handle,
    ) -> Result<Handle, Error> {
        let job = self.job(a, caller, job_cap)?;
        let image_id = a
            .authorize(caller, image_cap, Kind::Memory, Rights::READ)?
            .identity();
        let descriptor = self.image(image_id)?;
        if s.job_limits(job)? != descriptor.limits() {
            return Err(Error::JobLimits);
        }
        for r in [Resource::Frames, Resource::Processes, Resource::Threads] {
            if s.usage(job, r)? != 0 {
                return Err(Error::Phase);
            }
        }
        let frames = descriptor.plan()?.required_frames();
        let slot = self
            .processes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut authority = a.staged_copy();
        let mut scheduler = s.staged_copy();
        let mut pool = self.closed_domains;
        let domain = take_domain(&mut authority, &mut pool)?;
        let branches = take_domain(&mut authority, &mut pool)?;
        scheduler.charge_frames(job, frames)?;
        let process = scheduler.create_held_process(job)?;
        let thread = scheduler.create_thread(process)?;
        let cap = authority.create_managed(caller, job_cap, Kind::Process, PROCESS_RIGHTS)?;
        let id = authority
            .authorize(caller, cap, Kind::Process, Rights::CONTROL)?
            .identity();
        let record = Process {
            object: id,
            metadata: Metadata {
                process,
                thread,
                job,
                domain,
                frames,
            },
            branches,
            image: image_id,
            image_source: Source {
                owner: caller,
                handle: image_cap,
            },
            grants: [None; MAX_ROLES],
            phase: Phase::Held,
        };
        *a = authority;
        *s = scheduler;
        self.processes[slot] = Some(record);
        self.closed_domains = pool;
        Ok(cap)
    }
    pub fn delegate(
        &mut self,
        a: &mut Authority,
        caller: SpaceId,
        process_cap: Handle,
        source: Handle,
        selector: u64,
    ) -> Result<Handle, Error> {
        let (id, mut process) = self.process(a, caller, process_cap)?;
        let image = self.held(process)?;
        let index = image
            .roles()
            .position(|r| r.selector == selector)
            .ok_or(Error::Role)?;
        if process.grants[index].is_some() {
            return Err(Error::Role);
        }
        let role = image.roles[index].unwrap();
        a.authorize(caller, source, role.kind, role.rights | BRANCH)?;
        let mut staged = a.staged_copy();
        let private = staged.derive(caller, source, process.branches, role.rights | BRANCH)?;
        let grant = staged.derive(
            process.branches,
            private,
            process.metadata.domain,
            role.rights,
        )?;
        process.grants[index] = Some(Delegated {
            source: Source {
                owner: caller,
                handle: source,
            },
            private,
            grant,
        });
        *a = staged;
        self.processes[id] = Some(process);
        Ok(grant)
    }
    pub fn metadata(
        &self,
        a: &Authority,
        caller: SpaceId,
        process: Handle,
    ) -> Result<Metadata, Error> {
        Ok(self.process(a, caller, process)?.1.metadata)
    }
    pub fn observe(
        &self,
        a: &Authority,
        s: &Scheduler,
        caller: SpaceId,
        process: Handle,
    ) -> Result<bool, Error> {
        let metadata = self.process(a, caller, process)?.1.metadata;
        if s.process_job(metadata.process)? != metadata.job {
            return Err(Error::JobLimits);
        }
        Ok(s.process_terminated(metadata.process))
    }
    /// Trusted read-only live-grant adapter: exact ProcessCONTROL binding,
    /// actual active registry phase and generational scheduler coordinates.
    pub(crate) fn active_metadata(
        &self,
        a: &Authority,
        s: &Scheduler,
        caller: SpaceId,
        cap: Handle,
    ) -> Result<Metadata, Error> {
        let (_, process) = self.process(a, caller, cap)?;
        if process.phase != Phase::Active
            || s.process_terminated(process.metadata.process)
            || s.thread_process(process.metadata.thread)? != process.metadata.process
            || s.process_job(process.metadata.process)? != process.metadata.job
            || !matches!(
                s.held_process_job(process.metadata.process),
                Err(scheduler::Error::NotHeld)
            )
        {
            return Err(Error::Phase);
        }
        Ok(process.metadata)
    }
    /// Trusted live-grant mechanism. The controller must hold actual active
    /// ProcessCONTROL and a transferable revocable SEND source. The new private
    /// parent lives in that process's existing kernel-only branch domain; the
    /// returned transferable child is controller-local and may enter escrow.
    /// Every capacity/rights/target check commits as one Authority transaction.
    pub fn prepare_active_send(
        &self,
        a: &mut Authority,
        s: &Scheduler,
        caller: SpaceId,
        process: Handle,
        source: Handle,
    ) -> Result<(ActiveGrantBranch, Handle), Error> {
        let metadata = self.active_metadata(a, s, caller, process)?;
        let (_, record) = self.process(a, caller, process)?;
        a.authorize(caller, source, Kind::Endpoint, Rights::SEND | BRANCH)?;
        let mut staged = a.staged_copy();
        let parent = staged.derive(caller, source, record.branches, Rights::SEND | BRANCH)?;
        let child = staged.derive(
            record.branches,
            parent,
            caller,
            Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
        )?;
        *a = staged;
        Ok((
            ActiveGrantBranch {
                owner: record.branches,
                parent,
                metadata,
            },
            child,
        ))
    }
    /// Captured owner cleanup, never a userspace diagnostic lookup. The caller
    /// obtained this full Process object/Metadata through live CONTROL before
    /// retaining its non-Clone owner. Revoked/closed public handles cannot
    /// prevent removal of stopped authority, but missing/recycled rows refuse.
    pub(crate) fn require_stopped_owner(
        &self,
        s: &Scheduler,
        object: usize,
        metadata: Metadata,
    ) -> Result<(), Error> {
        let record = self
            .processes
            .iter()
            .flatten()
            .find(|record| record.object == object)
            .ok_or(Error::UnknownObject)?;
        if record.metadata != metadata
            || !s.process_terminated(metadata.process)
            || s.thread_process(metadata.thread)? != metadata.process
            || s.process_job(metadata.process)? != metadata.job
            || s.state(metadata.thread)? != scheduler::State::Exited
        {
            return Err(Error::Phase);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn model_admit_for_grant_test(
        &mut self,
        a: &Authority,
        s: &mut Scheduler,
        caller: SpaceId,
        cap: Handle,
    ) -> Result<Metadata, Error> {
        // Host policy model only, no loaded image/hardware claim. This helper
        // does not exist in the production API; ordinary start still requires
        // the unchanged LoadedExecutable ownership contract.
        let (slot, mut record) = self.process(a, caller, cap)?;
        if record.phase != Phase::Held {
            return Err(Error::Phase);
        }
        let m = record.metadata;
        s.admit_service(m.process, m.job, m.thread, m.frames)?;
        record.phase = Phase::Active;
        self.processes[slot] = Some(record);
        Ok(m)
    }
    /// Trusted controller cleanup after ending image leases and proving actual
    /// hardware/IPC/reference quiescence. This closes authority domains only;
    /// it does not reclaim physical backing or certify those external facts.
    /// Scheduler/object descriptors remain retained and cannot be reset here.
    pub fn retire(
        &mut self,
        a: &mut Authority,
        s: &Scheduler,
        caller: SpaceId,
        process_cap: Handle,
    ) -> Result<(), Error> {
        let (id, _) = self.process(a, caller, process_cap)?;
        self.retire_record(a, s, id)
    }
    /// Kernel-owned teardown after Running::finish and independently proven
    /// hardware/IPC/reference quiescence, even if userspace closed its control
    /// handle. The identity comes from the retained running owner and the SAME
    /// Scheduler, never by decoding a userspace diagnostic integer. This only
    /// closes authority domains; it does not certify or perform physical cleanup.
    pub fn retire_stopped(
        &mut self,
        a: &mut Authority,
        s: &Scheduler,
        process: ProcessId,
    ) -> Result<(), Error> {
        let id = self
            .processes
            .iter()
            .position(|p| p.is_some_and(|p| p.metadata.process == process))
            .ok_or(Error::UnknownObject)?;
        self.retire_record(a, s, id)
    }
    fn retire_record(&mut self, a: &mut Authority, s: &Scheduler, id: usize) -> Result<(), Error> {
        let process = self.processes[id].ok_or(Error::UnknownObject)?;
        if !s.process_terminated(process.metadata.process) {
            return Err(Error::Phase);
        }
        if s.process_job(process.metadata.process)? != process.metadata.job {
            return Err(Error::JobLimits);
        }
        if process.phase == Phase::Retired {
            return Ok(());
        }
        let mut staged = a.staged_copy();
        let mut pool = self.closed_domains;
        let mut vacancies = pool
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.is_none())
            .map(|(i, _)| i);
        let domain_slot = vacancies
            .next()
            .ok_or(Error::Authority(capability::Error::Capacity))?;
        let branch_slot = vacancies
            .next()
            .ok_or(Error::Authority(capability::Error::Capacity))?;
        let mut private = [Handle(0); MAX_ROLES];
        let mut count = 0;
        for grant in process.grants.iter().flatten() {
            private[count] = grant.private;
            count += 1;
        }
        if count != 0 {
            staged.revoke_batch(process.branches, &private[..count])?;
        }
        staged.close_space(process.metadata.domain)?;
        staged.close_space(process.branches)?;
        pool[domain_slot] = Some(process.metadata.domain);
        pool[branch_slot] = Some(process.branches);
        *a = staged;
        self.closed_domains = pool;
        self.processes[id].as_mut().unwrap().phase = Phase::Retired;
        Ok(())
    }
    /// Forget a fully stopped dedicated process only after physical retirement,
    /// balanced live charges and closing every public/escaped control handle.
    /// The retained scheduler ID comes from the owned controller, never a user
    /// integer. This leaves its Job and logical endpoint objects available for a
    /// fresh process. Scheduler descriptor reclamation is a separate next step.
    pub fn forget_retired(
        &mut self,
        a: &mut Authority,
        s: &Scheduler,
        process: ProcessId,
    ) -> Result<(), Error> {
        let slot = self
            .processes
            .iter()
            .position(|entry| entry.is_some_and(|p| p.metadata.process == process))
            .ok_or(Error::UnknownObject)?;
        let record = self.processes[slot].unwrap();
        if record.phase != Phase::Retired
            || !s.process_terminated(process)
            || s.process_job(process)? != record.metadata.job
            || s.usage(record.metadata.job, Resource::Frames)? != 0
            || a.is_live_space(record.metadata.domain)
            || a.is_live_space(record.branches)
        {
            return Err(Error::Phase);
        }
        let mut staged = a.staged_copy();
        staged.collect_lineage()?;
        staged.retire_unreferenced_object(record.object, Kind::Process)?;
        staged.collect_dead_objects()?;
        *a = staged;
        self.processes[slot] = None;
        Ok(())
    }
    pub fn grant(
        &self,
        a: &Authority,
        caller: SpaceId,
        process: Handle,
        selector: u64,
    ) -> Result<Handle, Error> {
        let (_, process) = self.process(a, caller, process)?;
        let image = self.image(process.image)?;
        let index = image
            .roles()
            .position(|r| r.selector == selector)
            .ok_or(Error::Role)?;
        let grant = process.grants[index].ok_or(Error::Role)?.grant;
        let role = image.roles[index].unwrap();
        a.authorize(process.metadata.domain, grant, role.kind, role.rights)?;
        Ok(grant)
    }
    fn validate_grants(&self, a: &Authority, process: Process) -> Result<[u8; 32], Error> {
        let image = self.held(process)?;
        if a.authorize(
            process.image_source.owner,
            process.image_source.handle,
            Kind::Memory,
            Rights::READ,
        )?
        .identity()
            != process.image
        {
            return Err(Error::UnknownObject);
        }
        let mut private = [Handle(0); MAX_ROLES];
        let mut grants = [Handle(0); MAX_ROLES];
        for (i, role) in image.roles().enumerate() {
            let supplied = process.grants[i].ok_or(Error::Role)?;
            private[i] = supplied.private;
            grants[i] = supplied.grant;
            a.require_child(
                process.branches,
                supplied.private,
                supplied.source.owner,
                supplied.source.handle,
                role.kind,
                role.rights | BRANCH,
            )?;
            a.require_child(
                process.metadata.domain,
                supplied.grant,
                process.branches,
                supplied.private,
                role.kind,
                role.rights,
            )?;
        }
        a.require_exact_handles(process.branches, &private[..image.count])?;
        a.require_exact_handles(process.metadata.domain, &grants[..image.count])?;
        let mut hash = Sha256::new();
        hash.update(b"evrosion.service.authority.v1\0");
        hash.update((image.count as u64).to_le_bytes());
        for (i, role) in image.roles().enumerate() {
            let access = a.authorize(process.metadata.domain, grants[i], role.kind, role.rights)?;
            hash.update(role.selector.to_le_bytes());
            hash.update([kind_tag(role.kind)]);
            hash.update((access.identity() as u64).to_le_bytes());
            hash.update((access.lineage_root() as u64).to_le_bytes());
            hash.update(role.rights.bits().to_le_bytes());
        }
        Ok(hash.finalize().into())
    }
    pub fn startup(
        &self,
        a: &Authority,
        caller: SpaceId,
        process_cap: Handle,
        epoch: NonZeroU64,
    ) -> Result<[u8; ev_userspace_contract::SIZE], Error> {
        let (_, process) = self.process(a, caller, process_cap)?;
        let image = self.held(process)?;
        let authority = self.validate_grants(a, process)?;
        let mut grants = [ev_userspace_contract::Grant {
            selector: 0,
            handle: 0,
            kind: 0,
            rights: 0,
        }; MAX_ROLES];
        for (i, role) in image.roles().enumerate() {
            grants[i] = ev_userspace_contract::Grant {
                selector: role.selector,
                handle: process.grants[i].unwrap().grant.0,
                kind: kind_tag(role.kind),
                rights: role.rights.bits(),
            };
        }
        ev_userspace_contract::encode(
            ev_userspace_contract::Context {
                epoch: epoch.get(),
                incarnation: self.incarnation.get(),
                process: process.metadata.process.diagnostic_id(),
                limits: RESOURCES.map(|r| image.limits.limit(r)),
                manifest: image.digest,
                authority,
            },
            &grants[..image.count],
        )
        .map_err(Error::Bootstrap)
    }
    pub fn plan(
        &self,
        a: &Authority,
        caller: SpaceId,
        process_cap: Handle,
    ) -> Result<Image<'a>, Error> {
        let (_, process) = self.process(a, caller, process_cap)?;
        self.held(process)?.plan()
    }
    /// Consume actual loaded-image ownership only after complete live validation.
    /// Rejection returns the same owner, keeps admission held and changes no table.
    #[allow(clippy::result_large_err)] // No heap; rejected admission retains its sole loaded owner.
    pub fn start<L: LoadedExecutable>(
        &mut self,
        a: &Authority,
        s: &mut Scheduler,
        caller: SpaceId,
        process_cap: Handle,
        epoch: NonZeroU64,
        loaded: L,
    ) -> Result<Running<L>, Rejected<L>> {
        match self.check_start(a, s, caller, process_cap, epoch, &loaded) {
            Err(error) => Err(Rejected {
                image: loaded,
                error,
            }),
            Ok((id, process, context)) => {
                if let Err(e) = s.admit_service(
                    process.metadata.process,
                    process.metadata.job,
                    process.metadata.thread,
                    process.metadata.frames,
                ) {
                    return Err(Rejected {
                        image: loaded,
                        error: Error::Scheduler(e),
                    });
                }
                self.processes[id].as_mut().unwrap().phase = Phase::Active;
                let count = self.image(process.image).unwrap().count;
                let mut private = [Handle(0); MAX_ROLES];
                for (i, cap) in private.iter_mut().take(count).enumerate() {
                    *cap = process.grants[i].unwrap().private;
                }
                Ok(Running {
                    image: loaded,
                    metadata: process.metadata,
                    context,
                    branches: process.branches,
                    private,
                    count,
                    stopping: false,
                })
            }
        }
    }
    fn check_start<L: LoadedExecutable>(
        &self,
        a: &Authority,
        s: &Scheduler,
        caller: SpaceId,
        process_cap: Handle,
        epoch: NonZeroU64,
        loaded: &L,
    ) -> Result<(usize, Process, UserContext), Error> {
        let (id, process) = self.process(a, caller, process_cap)?;
        let image = self.held(process)?;
        if s.held_process_job(process.metadata.process)? != process.metadata.job
            || s.job_limits(process.metadata.job)? != image.limits
        {
            return Err(Error::JobLimits);
        }
        let plan = image.plan()?;
        let record = self.startup(a, caller, process_cap, epoch)?;
        let info = loaded.information();
        let startup = Startup {
            address: plan.bootstrap_page().unwrap(),
            bytes: record.len(),
            digest: Sha256::digest(record).into(),
        };
        if info.process != process.metadata.process
            || loaded.layout() != plan.layout()
            || info.manifest != image.digest
            || info.entry != plan.entry()
            || info.stack != plan.stack_top()
            || info.frames != process.metadata.frames
            || info.frames != plan.required_frames()
            || info.root == 0
            || !info.root.is_multiple_of(FRAME_SIZE)
            || info.root & ADDRESS_MASK != info.root
            || info.startup != Some(startup)
        {
            return Err(Error::ImageMismatch);
        }
        let mut context = UserContext::new(info.entry, info.stack).ok_or(Error::ImageMismatch)?;
        context.registers[8] = startup.address;
        context.registers[9] = startup.bytes as u64;
        Ok((id, process, context))
    }
}

pub struct Rejected<L> {
    pub image: L,
    pub error: Error,
}
#[must_use = "retain the loaded image until its process stops and hardware quiescence is proven"]
pub struct Running<L: LoadedExecutable> {
    image: L,
    metadata: Metadata,
    context: UserContext,
    branches: SpaceId,
    private: [Handle; MAX_ROLES],
    count: usize,
    stopping: bool,
}
impl<L: LoadedExecutable> Running<L> {
    pub fn image(&self) -> &L {
        &self.image
    }
    pub fn metadata(&self) -> Metadata {
        self.metadata
    }
    pub fn initial_context(&self) -> Result<UserContext, Error> {
        if self.stopping {
            Err(Error::Phase)
        } else {
            Ok(self.context)
        }
    }
    /// Irreversibly inhibits future dispatch using the same scheduler owner.
    /// This does NOT revoke authority, cancel accepted RPCs, stop a current CPU,
    /// release mappings/credits, mark stopping, or return the image owner.
    /// The trusted controller must drain accepted work and then use stop/finish.
    pub fn inhibit(&mut self, s: &mut Scheduler) -> Result<(), Error> {
        if self.stopping || s.process_terminated(self.metadata.process) {
            return Err(Error::Phase);
        }
        s.inhibit_process(self.metadata.process)?;
        Ok(())
    }
    /// Trusted controller operation with the SAME tables used for admission.
    /// Inhibit redispatch first, then revoke all service grants and descendants.
    /// Already running CPUs must still return before process retirement.
    pub fn stop(&mut self, a: &mut Authority, s: &mut Scheduler) -> Result<(), Error> {
        s.inhibit_process(self.metadata.process)?;
        a.revoke_batch(self.branches, &self.private[..self.count])?;
        self.stopping = true;
        Ok(())
    }
    /// Returns only metadata ownership after stopped scheduler retirement. The
    /// controller must additionally prove hardware/IPC/reference quiescence
    /// before reclaiming backing, balancing frames or closing branch domains.
    #[allow(clippy::result_large_err)] // Failed teardown must preserve the unique image owner.
    pub fn finish(self, s: &Scheduler) -> Result<L, Self> {
        if !self.stopping || !s.process_terminated(self.metadata.process) {
            Err(self)
        } else {
            Ok(self.image)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::loaded_image::Information;
    const ELF: &[u8] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
    fn roles() -> [Role; 2] {
        [
            Role {
                selector: 3,
                kind: Kind::Endpoint,
                rights: Rights::RECEIVE | Rights::CONTROL,
            },
            Role {
                selector: 4,
                kind: Kind::Endpoint,
                rights: Rights::SEND,
            },
        ]
    }
    fn image(roles: &[Role]) -> ServiceImage<'static> {
        ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, roles).unwrap()
    }
    fn epoch() -> NonZeroU64 {
        NonZeroU64::new(7).unwrap()
    }
    struct Fixture {
        a: Authority,
        s: Scheduler,
        r: Registry<'static>,
        owner: SpaceId,
        parent: Handle,
        image: Handle,
        parent_job: JobId,
    }
    fn fixture(roles: &[Role]) -> Fixture {
        fixture_layout(roles, LayoutReservation::Legacy)
    }
    fn fixture_layout(roles: &[Role], layout: LayoutReservation) -> Fixture {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let parent = a.create_root(owner, Kind::Job, PROCESS_RIGHTS).unwrap();
        let executable = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        let mut s = Scheduler::new();
        let parent_job = s
            .create_job_with_limits(Limits::new(1000, 64, 4, 8))
            .unwrap();
        let mut r = Registry::new();
        r.register_job(&a, owner, parent, parent_job).unwrap();
        r.register_image(
            &a,
            owner,
            executable,
            ServiceImage::verify_layout(
                ELF,
                Sha256::digest(ELF).into(),
                SERVICE_LIMITS,
                roles,
                layout,
            )
            .unwrap(),
        )
        .unwrap();
        Fixture {
            a,
            s,
            r,
            owner,
            parent,
            image: executable,
            parent_job,
        }
    }
    fn failed_job_forget_unchanged(f: &mut Fixture, rpc: &Rpc, job: JobId, expected: Error) {
        let rows = f.r.jobs;
        let processes = f.r.processes;
        let pool = f.r.closed_domains;
        let usage = (f.a.metadata_usage(), f.s.metadata_usage());
        let probe = authority_probe(f);
        let parent_job = f.parent_job;
        let scheduler_probe = |scheduler: &Scheduler| {
            let mut staged = scheduler.staged_copy();
            staged.create_child_job(parent_job, SERVICE_LIMITS).unwrap()
        };
        let next_job = scheduler_probe(&f.s);
        assert_eq!(f.r.forget_job(&mut f.a, &mut f.s, rpc, job), Err(expected));
        assert_eq!(f.r.jobs, rows);
        assert_eq!(f.r.processes, processes);
        assert_eq!(f.r.closed_domains, pool);
        assert_eq!((f.a.metadata_usage(), f.s.metadata_usage()), usage);
        assert_eq!(authority_probe(f), probe);
        assert_eq!(scheduler_probe(&f.s), next_job);
    }
    #[test]
    fn capacity_metadata_census_keeps_roles_eight_and_service_rows_independent() {
        assert_eq!(MAX_ROLES, 8);
        assert_eq!(
            (MAX_JOB_RECORDS, MAX_IMAGE_RECORDS, MAX_PROCESS_RECORDS),
            (16, 16, 16)
        );
        assert!(core::mem::size_of::<Registry<'_>>() < 24 * 1024);
        std::println!(
            "CAPACITY Registry={} ServiceImage={} Process={} Job={} Scheduler={} Rpc={} BootstrapFrames={} IoPorts={} Mutex={}",
            core::mem::size_of::<Registry<'_>>(),
            core::mem::size_of::<ServiceImage<'_>>(),
            core::mem::size_of::<Process>(),
            core::mem::size_of::<Job>(),
            core::mem::size_of::<Scheduler>(),
            core::mem::size_of::<Rpc>(),
            core::mem::size_of::<crate::memory::BootstrapFrames>(),
            core::mem::size_of::<crate::io_ports::Registry>(),
            core::mem::size_of::<crate::mutex::Registry>()
        );
    }
    #[test]
    fn sparse_high_object_services_reuse_rows_by_full_identity_for_128_cycles() {
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        for _ in 0..20 {
            a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        }
        let parent = a.create_root(owner, Kind::Job, PROCESS_RIGHTS).unwrap();
        let executable = a
            .create_root(owner, Kind::Memory, Rights::READ | BRANCH | Rights::CONTROL)
            .unwrap();
        let mut s = Scheduler::new();
        let parent_job = s.create_job_with_limits(SERVICE_LIMITS).unwrap();
        let mut r = Registry::new();
        r.register_job(&a, owner, parent, parent_job).unwrap();
        r.register_image(
            &a,
            owner,
            executable,
            image(&[Role {
                selector: 1,
                kind: Kind::Memory,
                rights: Rights::READ,
            }]),
        )
        .unwrap();
        assert!(
            a.authorize(owner, parent, Kind::Job, Rights::CONTROL)
                .unwrap()
                .identity()
                >= MAX_JOB_RECORDS
        );
        assert!(
            a.authorize(owner, executable, Kind::Memory, Rights::READ)
                .unwrap()
                .identity()
                >= MAX_IMAGE_RECORDS
        );
        let mut f = Fixture {
            a,
            s,
            r,
            owner,
            parent,
            image: executable,
            parent_job,
        };
        let mut previous: Option<(Handle, Metadata, usize)> = None;
        for cycle in 0..128 {
            let control =
                f.r.create_process(&mut f.a, &mut f.s, owner, parent, executable)
                    .unwrap();
            f.r.delegate(&mut f.a, owner, control, executable, 1)
                .unwrap();
            let (row, record) = f.r.process(&f.a, owner, control).unwrap();
            assert_eq!(row, 0);
            assert!(object_slot(record.object).unwrap() >= MAX_PROCESS_RECORDS);
            assert_eq!(f.r.job_id(&f.a, owner, parent), Ok(parent_job));
            if let Some((old_cap, old_meta, old_object)) = previous {
                assert_ne!(old_cap, control);
                assert_ne!(old_meta.process, record.metadata.process);
                assert_ne!(old_object, record.object);
                assert_eq!(object_slot(old_object), object_slot(record.object));
                assert_eq!(
                    f.r.metadata(&f.a, owner, old_cap).err(),
                    Some(Error::Authority(capability::Error::InvalidHandle))
                );
                assert_eq!(
                    f.r.retire_stopped(&mut f.a, &f.s, old_meta.process),
                    Err(Error::UnknownObject)
                );
            }
            let loaded = model(&f, control);
            let running =
                f.r.start(&f.a, &mut f.s, owner, control, epoch(), loaded)
                    .unwrap_or_else(|e| panic!("{:?}", e.error));
            assert_eq!(
                f.s.dispatch(0).unwrap().unwrap().thread,
                record.metadata.thread
            );
            f.s.charge_cpu(0, 1).unwrap();
            let metadata = finish_model(&mut f, running);
            f.s.release_frames(metadata.job, metadata.frames).unwrap();
            f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
                .unwrap();
            f.a.close(owner, control).unwrap();
            f.r.forget_retired(&mut f.a, &f.s, metadata.process)
                .unwrap();
            f.s.reclaim_process(metadata.process).unwrap();
            assert_eq!(f.r.metadata_usage(), (1, 1, 0, 2));
            assert_eq!(f.a.metadata_usage(), (1, 22, 22, 22));
            assert_eq!(f.s.usage(parent_job, Resource::CpuTicks), Ok(cycle + 1));
            previous = Some((control, metadata, record.object));
        }
    }
    #[test]
    fn independent_image_rows_never_alias_a_reused_global_object_slot() {
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        for _ in 0..20 {
            a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        }
        let old = a
            .create_root(owner, Kind::Memory, Rights::READ | Rights::CONTROL)
            .unwrap();
        let old_id = a
            .authorize(owner, old, Kind::Memory, Rights::READ)
            .unwrap()
            .identity();
        let mut r = Registry::new();
        let descriptor = image(&[Role {
            selector: 1,
            kind: Kind::Memory,
            rights: Rights::READ,
        }]);
        let old_digest = descriptor.digest();
        r.register_image(&a, owner, old, descriptor).unwrap();
        a.destroy(owner, old).unwrap();
        a.close(owner, old).unwrap();
        a.collect_lineage().unwrap();
        a.collect_dead_objects().unwrap();
        let fresh = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        let new_id = a
            .authorize(owner, fresh, Kind::Memory, Rights::READ)
            .unwrap()
            .identity();
        assert_ne!(old_id, new_id);
        assert_eq!(object_slot(old_id), object_slot(new_id));
        assert_eq!(r.image(new_id).err(), Some(Error::UnknownObject));
        let descriptor = image(&[Role {
            selector: 2,
            kind: Kind::Memory,
            rights: Rights::READ,
        }]);
        let new_digest = descriptor.digest();
        assert_ne!(new_digest, old_digest);
        r.register_image(&a, owner, fresh, descriptor).unwrap();
        assert_eq!(r.image(old_id).unwrap().digest(), old_digest);
        assert_eq!(r.image(new_id).unwrap().digest(), new_digest);
        assert_eq!(r.metadata_usage(), (0, 2, 0, 0));
    }
    #[test]
    fn registry_row_capacity_preflights_without_committing_objects_domains_or_scheduler() {
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        let mut r = Registry::new();
        for _ in 0..MAX_IMAGE_RECORDS {
            let cap = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
            r.register_image(&a, owner, cap, image(&roles())).unwrap();
        }
        let extra = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        let before = (a.metadata_usage(), r.metadata_usage());
        assert_eq!(
            r.register_image(&a, owner, extra, image(&roles())),
            Err(Error::Capacity)
        );
        assert_eq!((a.metadata_usage(), r.metadata_usage()), before);
        // Fill every independent process row with a real held Scheduler target.
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        let mut r = Registry::new();
        let mut s = Scheduler::new();
        let executable = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        r.register_image(&a, owner, executable, image(&roles()))
            .unwrap();
        let mut jobs = [Handle(0); MAX_PROCESS_RECORDS];
        let mut controls = [Handle(0); MAX_PROCESS_RECORDS];
        for i in 0..MAX_PROCESS_RECORDS {
            jobs[i] = a.create_root(owner, Kind::Job, PROCESS_RIGHTS).unwrap();
            let actual = s.create_job_with_limits(SERVICE_LIMITS).unwrap();
            r.register_job(&a, owner, jobs[i], actual).unwrap();
            controls[i] = r
                .create_process(&mut a, &mut s, owner, jobs[i], executable)
                .unwrap();
        }
        let first = r.metadata(&a, owner, controls[0]).unwrap();
        // Portable model: no image/RAM owner has been created or dispatched.
        s.terminate_process(first.process).unwrap();
        s.release_frames(first.job, first.frames).unwrap();
        r.retire_stopped(&mut a, &s, first.process).unwrap();
        let before = (a.metadata_usage(), s.metadata_usage(), r.metadata_usage());
        let rows = r.processes;
        let pool = r.closed_domains;
        let mut probe = a.staged_copy();
        let expected = probe
            .create_root(owner, Kind::Memory, Rights::READ)
            .unwrap();
        assert_eq!(
            r.create_process(&mut a, &mut s, owner, jobs[0], executable),
            Err(Error::Capacity)
        );
        assert_eq!(
            (a.metadata_usage(), s.metadata_usage(), r.metadata_usage()),
            before
        );
        assert_eq!(r.processes, rows);
        assert_eq!(r.closed_domains, pool);
        let mut probe = a.staged_copy();
        assert_eq!(
            probe
                .create_root(owner, Kind::Memory, Rights::READ)
                .unwrap(),
            expected
        );
        // Closing/forgetting only the exact retired process reopens one row.
        a.close(owner, controls[0]).unwrap();
        r.forget_retired(&mut a, &s, first.process).unwrap();
        s.reclaim_process(first.process).unwrap();
        let fresh = r
            .create_process(&mut a, &mut s, owner, jobs[0], executable)
            .unwrap();
        assert_ne!(fresh, controls[0]);
        assert_ne!(r.metadata(&a, owner, fresh).unwrap().process, first.process);
        assert_eq!(r.metadata_usage().2, MAX_PROCESS_RECORDS);
    }
    #[test]
    fn managed_jobs_and_channels_recycle_128_times_without_refunds_or_ticket_aliasing() {
        use crate::{
            ipc::{Error as IpcError, Outgoing},
            time::Deadline,
        };
        let mut f = fixture(&roles());
        let rpc = Rpc::new(epoch());
        let mut receipt = None;
        let mut previous = None;
        for cycle in 0..128u64 {
            let cap =
                f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                    .unwrap();
            let job = f.r.job_id(&f.a, f.owner, cap).unwrap();
            let (endpoint, mut mailbox) = match receipt.take() {
                Some(retired) => {
                    f.r.create_channel_reusing(&mut f.a, f.owner, cap, retired)
                        .unwrap()
                }
                None => f.r.create_channel(&mut f.a, f.owner, cap).unwrap(),
            };
            let ticket = mailbox
                .send(
                    &mut f.a,
                    f.owner,
                    endpoint,
                    Outgoing {
                        bytes: b"retained sequence",
                        capability: None,
                        deadline: Deadline::after(cycle, 1000).unwrap(),
                    },
                    cycle,
                )
                .unwrap();
            assert_eq!(ticket.0, cycle + 1);
            if let Some((old_job, old_cap, old_endpoint, old_ticket)) = previous {
                assert_ne!(job, old_job);
                assert_ne!(cap, old_cap);
                assert_ne!(endpoint, old_endpoint);
                assert!(f.r.job_id(&f.a, f.owner, old_cap).is_err());
                assert!(
                    f.a.authorize(f.owner, old_endpoint, Kind::Endpoint, Rights::SEND)
                        .is_err()
                );
                assert_eq!(
                    mailbox.reclaim(&mut f.a, f.owner, old_ticket, cycle),
                    Err(IpcError::InvalidTicket)
                );
                failed_job_forget_unchanged(&mut f, &rpc, old_job, Error::UnknownObject);
            }
            assert_eq!(
                mailbox
                    .receive(&mut f.a, f.owner, endpoint, cycle)
                    .unwrap()
                    .length,
                17
            );
            mailbox.receiver_died(f.owner).unwrap();
            assert_eq!(
                mailbox.reclaim(&mut f.a, f.owner, ticket, cycle),
                Err(IpcError::InvalidTicket)
            );
            f.a.close(f.owner, endpoint).unwrap();
            receipt = Some(
                mailbox
                    .retire_managed(&mut f.a)
                    .unwrap_or_else(|r| panic!("{:?}", r.error)),
            );
            let process = f.s.create_process(job).unwrap();
            let thread = f.s.create_thread(process).unwrap();
            assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, thread);
            f.s.charge_cpu(0, 1).unwrap();
            f.s.exit(0).unwrap();
            f.s.terminate_process(process).unwrap();
            f.s.reclaim_process(process).unwrap();
            f.a.close(f.owner, cap).unwrap();
            f.r.forget_job(&mut f.a, &mut f.s, &rpc, job).unwrap();
            assert_eq!(f.s.usage(f.parent_job, Resource::CpuTicks), Ok(cycle + 1));
            assert_eq!(f.r.metadata_usage(), (1, 1, 0, 0));
            assert_eq!(f.s.metadata_usage(), (1, 0, 0));
            assert_eq!(f.a.metadata_usage(), (1, 2, 2, 2));
            previous = Some((job, cap, endpoint, ticket));
        }
        // Sealed external creator/image objects survive the entire lifecycle.
        assert!(
            f.a.authorize(f.owner, f.parent, Kind::Job, Rights::CONTROL)
                .is_ok()
        );
        assert!(
            f.a.authorize(f.owner, f.image, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert_eq!(rpc.outstanding(), 0);
        let _receipt = receipt.unwrap();
    }
    #[test]
    fn job_forgetting_rejects_escaped_descendant_and_actual_scheduler_or_rpc_pins() {
        let mut f = fixture(&roles());
        let mut rpc = Rpc::new(epoch());
        let cap =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let job = f.r.job_id(&f.a, f.owner, cap).unwrap();
        failed_job_forget_unchanged(
            &mut f,
            &rpc,
            job,
            Error::Authority(capability::Error::ObjectBusy),
        );
        let foreign = f.a.create_space().unwrap();
        let escaped = f.a.derive(f.owner, cap, foreign, Rights::READ).unwrap();
        f.a.close(f.owner, cap).unwrap();
        failed_job_forget_unchanged(
            &mut f,
            &rpc,
            job,
            Error::Authority(capability::Error::ObjectBusy),
        );
        assert!(
            f.a.authorize(foreign, escaped, Kind::Job, Rights::READ)
                .is_ok()
        );
        f.a.close(foreign, escaped).unwrap();
        let process = f.s.create_process(job).unwrap();
        let thread = f.s.create_thread(process).unwrap();
        failed_job_forget_unchanged(
            &mut f,
            &rpc,
            job,
            Error::Scheduler(scheduler::Error::NotQuiescent),
        );
        rpc.register_thread(&f.a, &f.s, thread, job, f.owner, None)
            .unwrap();
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, thread);
        f.s.exit(0).unwrap();
        f.s.terminate_process(process).unwrap();
        rpc.peer_died(&f.s, thread, 1).unwrap();
        failed_job_forget_unchanged(&mut f, &rpc, job, Error::Phase);
        rpc.forget_thread(&f.s, thread).unwrap();
        // Even exited process metadata must be reclaimed first.
        failed_job_forget_unchanged(
            &mut f,
            &rpc,
            job,
            Error::Scheduler(scheduler::Error::NotQuiescent),
        );
        f.s.reclaim_process(process).unwrap();
        f.r.forget_job(&mut f.a, &mut f.s, &rpc, job).unwrap();
        assert!(f.s.job_limits(job).is_err());
        assert!(
            f.a.authorize(foreign, escaped, Kind::Job, Rights::READ)
                .is_err()
        );
    }
    #[test]
    fn retained_registry_process_prevents_forgetting_even_if_scheduler_was_reclaimed() {
        let (mut f, process) = prepared();
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        let rpc = Rpc::new(epoch());
        // Model-only metadata teardown: this fixture owns no hardware backing.
        f.s.terminate_process(metadata.process).unwrap();
        f.s.release_frames(metadata.job, metadata.frames).unwrap();
        f.s.reclaim_process(metadata.process).unwrap();
        failed_job_forget_unchanged(&mut f, &rpc, metadata.job, Error::Phase);
    }
    #[test]
    fn incarnation_advance_requires_empty_graph_exact_sequence_and_preserves_sealed_catalog() {
        let mut f = fixture(&roles());
        let rpc = Rpc::new(epoch());
        let next = NonZeroU64::new(2).unwrap();
        assert_eq!(f.r.advance_incarnation(next), Err(Error::Phase));
        for value in [1, 3, u64::MAX] {
            assert_eq!(
                f.r.advance_incarnation(NonZeroU64::new(value).unwrap()),
                Err(Error::Incarnation)
            );
        }
        let before = f.a.metadata_usage();
        f.r.forget_job(&mut f.a, &mut f.s, &rpc, f.parent_job)
            .unwrap();
        assert_eq!(f.a.metadata_usage(), before);
        assert!(
            f.a.authorize(f.owner, f.parent, Kind::Job, Rights::CONTROL)
                .is_ok()
        );
        let domain = f.a.create_space().unwrap();
        f.a.close_space(domain).unwrap();
        f.r.closed_domains[0] = Some(domain);
        let images =
            f.r.images
                .each_ref()
                .map(|i| i.as_ref().map(|(id, image)| (*id, image.digest())));
        f.r.advance_incarnation(next).unwrap();
        assert_eq!(f.r.incarnation, next);
        assert_eq!(f.r.closed_domains[0], Some(domain));
        assert_eq!(
            f.r.images
                .each_ref()
                .map(|i| i.as_ref().map(|(id, image)| (*id, image.digest()))),
            images
        );
        let replacement = f.s.create_job().unwrap();
        f.r.register_job(&f.a, f.owner, f.parent, replacement)
            .unwrap();
        assert_eq!(f.r.job_id(&f.a, f.owner, f.parent), Ok(replacement));
        assert_ne!(replacement, f.parent_job);
        f.r.forget_job(&mut f.a, &mut f.s, &rpc, replacement)
            .unwrap();
        f.r.incarnation = NonZeroU64::new(u64::MAX).unwrap();
        assert_eq!(
            f.r.advance_incarnation(NonZeroU64::new(1).unwrap()),
            Err(Error::Incarnation)
        );
        assert_eq!(f.r.incarnation.get(), u64::MAX);
    }
    #[test]
    fn replacement_channel_returns_receipt_on_failed_auth_or_capacity_and_reuses_closed_escrow() {
        use crate::ipc::{Error as IpcError, Outgoing};
        use crate::time::Deadline;
        let mut f = fixture(&roles());
        let (endpoint, mut mailbox) = f.r.create_channel(&mut f.a, f.owner, f.parent).unwrap();
        let old = mailbox
            .send(
                &mut f.a,
                f.owner,
                endpoint,
                Outgoing {
                    bytes: b"old",
                    capability: None,
                    deadline: Deadline::after(10, 20).unwrap(),
                },
                10,
            )
            .unwrap();
        mailbox.receive(&mut f.a, f.owner, endpoint, 10).unwrap();
        mailbox.receiver_died(f.owner).unwrap();
        f.a.close(f.owner, endpoint).unwrap();
        let receipt = mailbox
            .retire_managed(&mut f.a)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let before = (f.a.metadata_usage(), authority_probe(&f));
        let rejected =
            f.r.create_channel_reusing(&mut f.a, f.owner, f.image, receipt)
                .err()
                .unwrap();
        assert_eq!(
            rejected.error,
            Error::Authority(capability::Error::WrongKind)
        );
        assert_eq!((f.a.metadata_usage(), authority_probe(&f)), before);
        let mut handles = [None; MAX_CAPS];
        for handle in &mut handles {
            *handle = f.a.derive(f.owner, f.parent, f.owner, Rights::READ).ok();
            if handle.is_none() {
                break;
            }
        }
        let full = f.a.metadata_usage();
        let rejected =
            f.r.create_channel_reusing(&mut f.a, f.owner, f.parent, rejected.receipt)
                .err()
                .unwrap();
        assert_eq!(
            rejected.error,
            Error::Authority(capability::Error::Capacity)
        );
        assert_eq!(f.a.metadata_usage(), full);
        for handle in handles.into_iter().flatten() {
            f.a.close(f.owner, handle).unwrap();
        }
        // All other spaces may be occupied: replacement must recycle the exact
        // consumed escrow rather than allocating an additional bounded space.
        while f.a.create_space().is_ok() {}
        let (fresh, mut mailbox) =
            f.r.create_channel_reusing(&mut f.a, f.owner, f.parent, rejected.receipt)
                .unwrap();
        assert_ne!(endpoint, fresh);
        assert_eq!(
            mailbox.send(
                &mut f.a,
                f.owner,
                fresh,
                Outgoing {
                    bytes: b"too early",
                    capability: None,
                    deadline: Deadline::after(0, 100).unwrap(),
                },
                9
            ),
            Err(IpcError::ClockReversed)
        );
        let ticket = mailbox
            .send(
                &mut f.a,
                f.owner,
                fresh,
                Outgoing {
                    bytes: b"new",
                    capability: None,
                    deadline: Deadline::after(10, 20).unwrap(),
                },
                10,
            )
            .unwrap();
        assert_eq!(ticket.0, old.0 + 1);
        assert_eq!(
            mailbox.reclaim(&mut f.a, f.owner, old, 10),
            Err(IpcError::InvalidTicket)
        );
        assert_eq!(
            &mailbox.receive(&mut f.a, f.owner, fresh, 10).unwrap().bytes[..3],
            b"new"
        );
    }
    #[test]
    fn trusted_finite_profile_cannot_be_selected_or_mismatched_by_userspace() {
        let epoch = NonZeroU64::new(1).unwrap();
        for limits in [
            Limits::UNLIMITED,
            Limits::new(0, 16, 1, 1),
            Limits::new(256, 16, 17, 1),
        ] {
            assert_eq!(
                Registry::with_service_limits(epoch, limits).err(),
                Some(Error::Descriptor)
            );
        }
        let mut f = fixture(&roles());
        f.r = Registry::with_service_limits(epoch, RESTART_SERVICE_LIMITS).unwrap();
        f.r.register_job(&f.a, f.owner, f.parent, f.parent_job)
            .unwrap();
        f.r.register_image(&f.a, f.owner, f.image, image(&roles()))
            .unwrap();
        let before = (f.a.metadata_usage(), f.s.metadata_usage());
        assert_eq!(
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 1),
            Err(Error::UnsupportedTemplate)
        );
        assert_eq!((f.a.metadata_usage(), f.s.metadata_usage()), before);
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let id = f.r.job(&f.a, f.owner, job).unwrap();
        assert_eq!(f.s.job_limits(id), Ok(RESTART_SERVICE_LIMITS));
        let before = (f.a.metadata_usage(), f.s.metadata_usage());
        assert_eq!(
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image),
            Err(Error::JobLimits)
        );
        assert_eq!((f.a.metadata_usage(), f.s.metadata_usage()), before);
        let ordinary = image(&roles());
        let sustained = ServiceImage::verify(
            ELF,
            Sha256::digest(ELF).into(),
            RESTART_SERVICE_LIMITS,
            &roles(),
        )
        .unwrap();
        assert_ne!(ordinary.digest(), sustained.digest());
    }
    fn prepared() -> (Fixture, Handle) {
        let mut f = fixture(&roles());
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let process =
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                .unwrap();
        (f, process)
    }
    fn granted(roles: &[Role]) -> (Fixture, Handle, [Handle; 2]) {
        let mut f = fixture(roles);
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let process =
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                .unwrap();
        let receive = f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap();
        let send = f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap();
        f.r.delegate(&mut f.a, f.owner, process, receive, 3)
            .unwrap();
        f.r.delegate(&mut f.a, f.owner, process, send, 4).unwrap();
        (f, process, [receive, send])
    }
    struct Model(Information);
    struct GraphicsModel(Information);
    // SAFETY: host-only model of exact initialized backing. No table address is
    // dereferenced and this test does not claim a hardware graphics receipt.
    #[allow(unsafe_code)]
    unsafe impl LoadedExecutable for GraphicsModel {
        fn information(&self) -> Information {
            self.0
        }
        fn layout(&self) -> LayoutReservation {
            LayoutReservation::DisplayApertureV1
        }
    }
    // SAFETY: test-only model metadata stands in for unique initialized backing;
    // host tests neither dereference this root nor execute its user context.
    #[allow(unsafe_code)]
    unsafe impl LoadedExecutable for Model {
        fn information(&self) -> Information {
            self.0
        }
    }
    #[test]
    fn legacy_descriptor_bytes_and_private_frame_count_are_unchanged() {
        let expected = [
            8, 116, 142, 151, 67, 230, 120, 11, 87, 27, 2, 217, 148, 134, 83, 17, 53, 150, 139,
            112, 155, 192, 76, 138, 61, 203, 253, 98, 203, 106, 28, 255,
        ];
        let ordinary = image(&roles());
        assert_eq!(ordinary.digest(), expected);
        assert_eq!(ordinary.plan().unwrap().layout(), LayoutReservation::Legacy);
        assert_eq!(ordinary.plan().unwrap().required_frames(), 10);
        let explicit = ServiceImage::verify_layout(
            ELF,
            Sha256::digest(ELF).into(),
            SERVICE_LIMITS,
            &roles(),
            LayoutReservation::Legacy,
        )
        .unwrap();
        assert_eq!(ordinary.digest(), explicit.digest());
    }
    #[test]
    fn display_descriptor_requires_exact_distinct_role_and_declared_two_table_frames() {
        let roles = [Role {
            selector: 3,
            kind: Kind::Display,
            rights: Rights::READ | Rights::WRITE | Rights::MAP,
        }];
        let legacy =
            ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, &roles).unwrap();
        let display = ServiceImage::verify_layout(
            ELF,
            Sha256::digest(ELF).into(),
            SERVICE_LIMITS,
            &roles,
            LayoutReservation::DisplayApertureV1,
        )
        .unwrap();
        assert_ne!(legacy.digest(), display.digest());
        let plan = display.plan().unwrap();
        assert_eq!(plan.required_frames(), 12);
        assert_eq!(plan.private_required_frames(), 10);
        assert_eq!(plan.pages().count(), 4);
        assert_eq!(
            ServiceImage::verify_layout(
                ELF,
                Sha256::digest(ELF).into(),
                Limits::new(128, 10, 1, 1),
                &roles,
                LayoutReservation::DisplayApertureV1
            )
            .err(),
            Some(Error::Executable(executable::Error::FrameBudget))
        );
        let mut wrong = roles;
        wrong[0].rights = Rights::WRITE | Rights::MAP;
        assert_eq!(
            ServiceImage::verify_layout(
                ELF,
                Sha256::digest(ELF).into(),
                SERVICE_LIMITS,
                &wrong,
                LayoutReservation::DisplayApertureV1
            )
            .err(),
            Some(Error::Role)
        );
        assert_eq!(
            ServiceImage::verify_layout(
                ELF,
                Sha256::digest(ELF).into(),
                SERVICE_LIMITS,
                &self::roles(),
                LayoutReservation::DisplayApertureV1
            )
            .err(),
            Some(Error::Role)
        );
        let mut outside = ELF.to_vec();
        let base = 1u64 << 39;
        outside[64 + 16..64 + 24].copy_from_slice(&(base + 4 * 1024 * 1024).to_le_bytes());
        assert!(
            ServiceImage::verify_layout(
                &outside,
                Sha256::digest(&outside).into(),
                SERVICE_LIMITS,
                &roles,
                LayoutReservation::DisplayApertureV1
            )
            .is_err()
        );
    }
    #[test]
    fn registry_charges_display_tables_before_any_hardware_and_requires_exact_loaded_layout() {
        let roles = [Role {
            selector: 3,
            kind: Kind::Display,
            rights: Rights::READ | Rights::WRITE | Rights::MAP,
        }];
        let mut f = fixture_layout(&roles, LayoutReservation::DisplayApertureV1);
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let process =
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                .unwrap();
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        assert_eq!(metadata.frames, 12);
        assert_eq!(f.s.usage(metadata.job, Resource::Frames), Ok(12));
        let wrong =
            f.a.create_root(
                f.owner,
                Kind::Memory,
                Rights::READ | Rights::WRITE | Rights::MAP | BRANCH,
            )
            .unwrap();
        assert_eq!(
            f.r.delegate(&mut f.a, f.owner, process, wrong, 3),
            Err(Error::Authority(capability::Error::WrongKind))
        );
        let source =
            f.a.create_root(
                f.owner,
                Kind::Display,
                Rights::READ | Rights::WRITE | Rights::MAP | BRANCH | Rights::CONTROL,
            )
            .unwrap();
        f.r.delegate(&mut f.a, f.owner, process, source, 3).unwrap();
        let record = f.r.startup(&f.a, f.owner, process, epoch()).unwrap();
        let startup = ev_userspace_contract::Bootstrap::parse(&record).unwrap();
        assert_eq!(startup.find(3).unwrap().kind, 8);
        let loaded = model(&f, process);
        let rejected =
            f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded)
                .err()
                .unwrap();
        assert_eq!(rejected.error, Error::ImageMismatch);
        let mut info = rejected.image.0;
        info.frames = 10;
        let rejected =
            f.r.start(
                &f.a,
                &mut f.s,
                f.owner,
                process,
                epoch(),
                GraphicsModel(info),
            )
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::ImageMismatch);
        assert_eq!(f.s.dispatch(0), Ok(None));
        let mut info = rejected.image.0;
        info.frames = 12;
        let running =
            f.r.start(
                &f.a,
                &mut f.s,
                f.owner,
                process,
                epoch(),
                GraphicsModel(info),
            )
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(running.metadata().frames, 12);
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, metadata.thread);
    }
    fn model(f: &Fixture, process: Handle) -> Model {
        let plan = f.r.plan(&f.a, f.owner, process).unwrap();
        let record = f.r.startup(&f.a, f.owner, process, epoch()).unwrap();
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        Model(Information {
            process: metadata.process,
            manifest: plan.manifest_digest(),
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames: plan.required_frames(),
            startup: Some(Startup {
                address: plan.bootstrap_page().unwrap(),
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            }),
        })
    }
    fn create_granted(f: &mut Fixture, job: Handle, sources: [Handle; 2]) -> Handle {
        let process =
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                .unwrap();
        for (source, selector) in sources.into_iter().zip([3, 4]) {
            f.r.delegate(&mut f.a, f.owner, process, source, selector)
                .unwrap();
        }
        process
    }
    /// This host model owns no physical backing or CPU/IPC references. It tests
    /// the portable ownership gates only; the real runtime must independently
    /// prove hardware quiescence before retirement or balancing frame charges.
    fn finish_model(f: &mut Fixture, mut running: Running<Model>) -> Metadata {
        let metadata = running.metadata();
        running.stop(&mut f.a, &mut f.s).unwrap();
        if let scheduler::State::Running(cpu) = f.s.state(metadata.thread).unwrap() {
            assert_eq!(f.s.exit(cpu), Ok(metadata.thread));
        }
        f.s.terminate_process(metadata.process).unwrap();
        let _model = running
            .finish(&f.s)
            .unwrap_or_else(|_| panic!("model owner retained"));
        metadata
    }
    fn probe_authority(
        a: &Authority,
        owner: SpaceId,
        parent: Handle,
    ) -> (usize, usize, Handle, usize) {
        let mut staged = a.staged_copy();
        let lineage = staged.collect_lineage().unwrap();
        let objects = staged.collect_dead_objects().unwrap();
        let next = staged
            .create_managed(owner, parent, Kind::Process, PROCESS_RIGHTS)
            .unwrap();
        let identity = staged
            .authorize(owner, next, Kind::Process, Rights::CONTROL)
            .unwrap()
            .identity();
        (lineage, objects, next, identity)
    }
    fn authority_probe(f: &Fixture) -> (usize, usize, Handle, usize) {
        probe_authority(&f.a, f.owner, f.parent)
    }
    fn failed_forget_unchanged(f: &mut Fixture, process: ProcessId, expected: Error) {
        let jobs = f.r.jobs;
        let processes = f.r.processes;
        let pool = f.r.closed_domains;
        let images =
            f.r.images
                .each_ref()
                .map(|i| i.as_ref().map(|(id, image)| (*id, image.digest())));
        let domains = processes.map(|p| {
            p.map(|p| {
                (
                    f.a.is_live_space(p.metadata.domain),
                    f.a.is_live_space(p.branches),
                )
            })
        });
        let authority = authority_probe(f);
        assert_eq!(f.r.forget_retired(&mut f.a, &f.s, process), Err(expected));
        assert_eq!(f.r.jobs, jobs);
        assert_eq!(f.r.processes, processes);
        assert_eq!(f.r.closed_domains, pool);
        assert_eq!(
            f.r.images
                .each_ref()
                .map(|i| i.as_ref().map(|(id, image)| (*id, image.digest()))),
            images
        );
        assert_eq!(
            f.r.processes.map(|p| p.map(|p| (
                f.a.is_live_space(p.metadata.domain),
                f.a.is_live_space(p.branches)
            ))),
            domains
        );
        assert_eq!(authority_probe(f), authority);
    }
    #[test]
    fn measured_service_policy_binds_exact_image_abi_limits_and_ordered_roles() {
        let original = image(&roles());
        assert_eq!(original.plan().unwrap().required_frames(), 10);
        assert!(original.plan().unwrap().bootstrap_page().is_some());
        let mut changed = roles();
        changed[1].rights = Rights::SEND | Rights::TRANSFER;
        assert_ne!(original.digest(), image(&changed).digest());
        assert_ne!(
            original.digest(),
            ServiceImage::verify(
                ELF,
                Sha256::digest(ELF).into(),
                Limits::new(127, 16, 1, 1),
                &roles()
            )
            .unwrap()
            .digest()
        );
        assert_eq!(
            ServiceImage::verify(ELF, [0; 32], SERVICE_LIMITS, &roles()).err(),
            Some(Error::Measurement)
        );
        assert_eq!(
            ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, &[]).err(),
            Some(Error::Descriptor)
        );
        let duplicate = [roles()[0]; 2];
        assert_eq!(
            ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, &duplicate).err(),
            Some(Error::Role)
        );
        let mut bad = roles();
        bad[0].rights = Rights::READ;
        assert_eq!(
            ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, &bad).err(),
            Some(Error::Role)
        );
        let hash = Sha256::digest(ELF).into();
        assert_eq!(
            ServiceImage::verify(ELF, hash, Limits::new(128, 9, 1, 1), &roles()).err(),
            Some(Error::Executable(executable::Error::FrameBudget))
        );
        assert_eq!(
            ServiceImage::verify(ELF, hash, Limits::UNLIMITED, &roles()).err(),
            Some(Error::Descriptor)
        );
    }
    #[test]
    fn creation_requires_registered_typed_authority_and_supported_template() {
        let mut f = fixture(&roles());
        assert_eq!(
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 1),
            Err(Error::UnsupportedTemplate)
        );
        assert_eq!(
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.image, 0),
            Err(Error::Authority(capability::Error::WrongKind))
        );
        let unknown = f.a.create_root(f.owner, Kind::Job, PROCESS_RIGHTS).unwrap();
        assert_eq!(
            f.r.create_job(&mut f.a, &mut f.s, f.owner, unknown, 0),
            Err(Error::UnknownObject)
        );
        let foreign = f.a.create_space().unwrap();
        assert_eq!(
            f.r.create_job(&mut f.a, &mut f.s, foreign, f.parent, 0),
            Err(Error::Authority(capability::Error::InvalidHandle))
        );
        assert_eq!(
            f.r.register_job(&f.a, f.owner, f.parent, f.parent_job),
            Err(Error::AlreadyRegistered)
        );
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        assert_eq!(
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.parent),
            Err(Error::Authority(capability::Error::WrongKind))
        );
        let unread =
            f.a.create_root(f.owner, Kind::Memory, Rights::READ)
                .unwrap();
        assert_eq!(
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, unread),
            Err(Error::UnknownObject)
        );
        assert_eq!(f.s.dispatch(0), Ok(None));
    }
    #[test]
    fn late_job_and_process_capacity_failure_leaves_all_tables_uncommitted() {
        for process_case in [false, true] {
            let mut f = fixture(&roles());
            let mut fills = [Handle(0); MAX_CAPS];
            let mut count = 0;
            let job = if process_case {
                f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                    .unwrap()
            } else {
                f.parent
            };
            for _ in if process_case { 3 } else { 2 }..MAX_CAPS {
                fills[count] =
                    f.a.derive(f.owner, f.parent, f.owner, Rights::READ)
                        .unwrap();
                count += 1;
            }
            let mut prior_s = f.s.staged_copy();
            let expected_job = if process_case {
                f.r.job(&f.a, f.owner, job).unwrap()
            } else {
                prior_s
                    .create_child_job(f.parent_job, SERVICE_LIMITS)
                    .unwrap()
            };
            let mut prior_a = f.a.staged_copy();
            let expected_domain = prior_a.create_space().unwrap();
            let failed = if process_case {
                f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
            } else {
                f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
            };
            assert_eq!(failed, Err(Error::Authority(capability::Error::Capacity)));
            assert_eq!(f.s.dispatch(0), Ok(None));
            for r in [Resource::Frames, Resource::Processes, Resource::Threads] {
                assert_eq!(f.s.usage(f.parent_job, r), Ok(0));
            }
            f.a.close(f.owner, fills[count - 1]).unwrap();
            if process_case {
                let process =
                    f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                        .unwrap();
                let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
                assert_eq!(metadata.domain, expected_domain);
                assert_eq!(metadata.process.diagnostic_id(), 1);
                assert_eq!(metadata.thread.diagnostic_id(), 1);
                assert_eq!(metadata.job, expected_job);
                assert_eq!(f.s.usage(metadata.job, Resource::Frames), Ok(10));
            } else {
                let created =
                    f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                        .unwrap();
                assert_eq!(f.r.job(&f.a, f.owner, created), Ok(expected_job));
                assert_eq!(f.a.create_space(), Ok(expected_domain));
            }
        }
    }
    #[test]
    fn channel_escrow_failure_does_not_leak_endpoint_object_or_handle() {
        let mut f = fixture(&roles());
        while f.a.create_space().is_ok() {}
        let mut prior = f.a.staged_copy();
        let expected = prior
            .create_managed(f.owner, f.parent, Kind::Endpoint, ENDPOINT_RIGHTS)
            .unwrap();
        let expected_identity = prior
            .authorize(f.owner, expected, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity();
        assert_eq!(
            f.r.create_channel(&mut f.a, f.owner, f.parent).err(),
            Some(Error::Ipc(crate::ipc::Error::Authority(
                capability::Error::Capacity
            )))
        );
        let actual = f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            f.a.authorize(f.owner, actual, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .identity(),
            expected_identity
        );
    }
    #[test]
    fn missing_duplicate_excess_or_weak_delegation_cannot_produce_startup() {
        let (mut f, process) = prepared();
        assert_eq!(
            f.r.startup(&f.a, f.owner, process, epoch()),
            Err(Error::Role)
        );
        let endpoint = f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap();
        assert_eq!(
            f.r.delegate(&mut f.a, f.owner, process, f.image, 3),
            Err(Error::Authority(capability::Error::WrongKind))
        );
        assert_eq!(
            f.r.delegate(&mut f.a, f.owner, process, endpoint, 5),
            Err(Error::Role)
        );
        let weak =
            f.a.derive(f.owner, endpoint, f.owner, Rights::SEND)
                .unwrap();
        assert_eq!(
            f.r.delegate(&mut f.a, f.owner, process, weak, 4),
            Err(Error::Authority(capability::Error::Denied))
        );
        f.a.close(f.owner, weak).unwrap();
        f.r.delegate(&mut f.a, f.owner, process, endpoint, 3)
            .unwrap();
        assert_eq!(
            f.r.delegate(&mut f.a, f.owner, process, endpoint, 3),
            Err(Error::Role)
        );
        assert_eq!(
            f.r.startup(&f.a, f.owner, process, epoch()),
            Err(Error::Role)
        );
        f.r.delegate(&mut f.a, f.owner, process, endpoint, 4)
            .unwrap();
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        let extra =
            f.a.derive(f.owner, endpoint, metadata.domain, Rights::SEND)
                .unwrap();
        assert_eq!(
            f.r.startup(&f.a, f.owner, process, epoch()),
            Err(Error::Authority(capability::Error::Denied))
        );
        f.a.close(metadata.domain, extra).unwrap();
        let record = f.r.startup(&f.a, f.owner, process, epoch()).unwrap();
        let decoded = ev_userspace_contract::Bootstrap::parse(&record).unwrap();
        assert_eq!(decoded.epoch(), 7);
        assert_eq!(decoded.process(), metadata.process.diagnostic_id());
        assert_eq!(decoded.grants().count(), 2);
        assert_eq!(f.s.dispatch(0), Ok(None));
    }
    #[test]
    fn forged_loaded_identity_or_startup_cannot_release_service_admission() {
        for damage in 0..9 {
            let (mut f, process, _) = granted(&roles());
            let mut loaded = model(&f, process);
            match damage {
                0 => loaded.0.manifest[0] ^= 1,
                1 => loaded.0.entry += 1,
                2 => loaded.0.stack -= 16,
                3 => loaded.0.root = 0,
                4 => loaded.0.frames += 1,
                5 => loaded.0.startup.as_mut().unwrap().address += 4096,
                6 => loaded.0.startup.as_mut().unwrap().digest[0] ^= 1,
                7 => loaded.0.startup.as_mut().unwrap().bytes -= 1,
                _ => loaded.0.startup = None,
            }
            let rejected = match f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded) {
                Err(r) => r,
                Ok(_) => panic!("forged service image admitted"),
            };
            assert_eq!(rejected.error, Error::ImageMismatch);
            assert_eq!(f.s.dispatch(0), Ok(None));
            assert!(f.r.startup(&f.a, f.owner, process, epoch()).is_ok());
        }
    }
    #[test]
    fn late_scheduler_charge_failure_preserves_owner_and_held_retry() {
        let (mut f, process, _) = granted(&roles());
        let loaded = model(&f, process);
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        f.s.charge_frames(metadata.job, 1).unwrap();
        let rejected = match f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded) {
            Err(r) => r,
            Ok(_) => panic!("shared frame charge admitted"),
        };
        assert_eq!(
            rejected.error,
            Error::Scheduler(scheduler::Error::Admission)
        );
        assert_eq!(f.s.dispatch(0), Ok(None));
        f.s.release_frames(metadata.job, 1).unwrap();
        let running =
            f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), rejected.image)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        let context = running.initial_context().unwrap();
        assert_eq!(context.registers[9], ev_userspace_contract::SIZE as u64);
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, metadata.thread);
        assert_eq!(
            f.r.startup(&f.a, f.owner, process, epoch()),
            Err(Error::Phase)
        );
    }
    #[test]
    fn stopped_service_revokes_escaped_grants_and_preserves_peer_and_owner_until_retirement() {
        let mut policy = roles();
        policy[1].rights = Rights::SEND | Rights::TRANSFER;
        let (mut f, process, sources) = granted(&policy);
        let loaded = model(&f, process);
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        let escaped_owner = f.a.create_space().unwrap();
        let grant = f.r.grant(&f.a, f.owner, process, 4).unwrap();
        let mut running =
            f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        let moved = f.a.transfer(metadata.domain, grant, escaped_owner).unwrap();
        let peer_job = f.s.create_job().unwrap();
        let peer = f.s.create_process(peer_job).unwrap();
        let peer_thread = f.s.create_thread(peer).unwrap();
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, metadata.thread);
        running = match running.finish(&f.s) {
            Err(owner) => owner,
            Ok(_) => panic!("active image released"),
        };
        running.stop(&mut f.a, &mut f.s).unwrap();
        assert_eq!(
            f.a.authorize(escaped_owner, moved, Kind::Endpoint, Rights::SEND)
                .err(),
            Some(capability::Error::Revoked)
        );
        assert!(
            f.a.authorize(f.owner, sources[1], Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        running = match running.finish(&f.s) {
            Err(owner) => owner,
            Ok(_) => panic!("running CPU image released"),
        };
        assert_eq!(f.s.exit(0), Ok(metadata.thread));
        f.s.terminate_process(metadata.process).unwrap();
        assert_eq!(f.r.observe(&f.a, &f.s, f.owner, process), Ok(true));
        let _image = running
            .finish(&f.s)
            .unwrap_or_else(|_| panic!("retired owner withheld"));
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, peer_thread);
        f.s.exit(0).unwrap();
        f.s.terminate_process(peer).unwrap();
        f.r.retire(&mut f.a, &f.s, f.owner, process).unwrap();
        f.r.retire(&mut f.a, &f.s, f.owner, process).unwrap();
        assert!(!f.a.is_live_space(metadata.domain));
        f.s.release_frames(metadata.job, metadata.frames).unwrap();
        for r in [Resource::Frames, Resource::Processes, Resource::Threads] {
            assert_eq!(f.s.usage(metadata.job, r), Ok(0));
        }
    }
    #[test]
    fn revoked_creator_cancels_created_service_authority_before_any_dispatch() {
        let (mut f, process, _) = granted(&roles());
        let loaded = model(&f, process);
        f.a.revoke(f.owner, f.parent).unwrap();
        assert_eq!(
            f.r.metadata(&f.a, f.owner, process).err(),
            Some(Error::Authority(capability::Error::Revoked))
        );
        let rejected = match f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded) {
            Err(r) => r,
            Ok(_) => panic!("revoked creator admitted"),
        };
        assert_eq!(rejected.error, Error::Authority(capability::Error::Revoked));
        assert_eq!(f.s.dispatch(0), Ok(None));
    }
    #[test]
    fn closing_control_handle_cannot_block_owned_stopped_cleanup_or_fake_quiescence() {
        let (mut f, process, _) = granted(&roles());
        let loaded = model(&f, process);
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        let object =
            f.a.authorize(f.owner, process, Kind::Process, Rights::CONTROL)
                .unwrap()
                .identity();
        let branches = f.r.process(&f.a, f.owner, process).unwrap().1.branches;
        assert_eq!(
            f.r.process(&f.a, f.owner, process).unwrap().1.object,
            object
        );
        let mut running =
            f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        f.a.close(f.owner, process).unwrap();
        assert_eq!(
            f.r.retire(&mut f.a, &f.s, f.owner, process),
            Err(Error::Authority(capability::Error::InvalidHandle))
        );
        assert_eq!(
            f.r.retire_stopped(&mut f.a, &f.s, metadata.process),
            Err(Error::Phase)
        );
        assert!(f.a.is_live_space(metadata.domain) && f.a.is_live_space(branches));
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, metadata.thread);
        running.stop(&mut f.a, &mut f.s).unwrap();
        assert_eq!(
            f.r.retire_stopped(&mut f.a, &f.s, metadata.process),
            Err(Error::Phase)
        );
        running = match running.finish(&f.s) {
            Err(owner) => owner,
            Ok(_) => panic!("running image released"),
        };
        assert_eq!(f.s.exit(0), Ok(metadata.thread));
        f.s.terminate_process(metadata.process).unwrap();
        let _image = running
            .finish(&f.s)
            .unwrap_or_else(|_| panic!("stopped owner retained"));
        // Host model has no physical backing/IPC references. The trusted runtime
        // must complete real hardware cleanup before invoking this operation.
        f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
            .unwrap();
        f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
            .unwrap();
        assert!(!f.a.is_live_space(metadata.domain) && !f.a.is_live_space(branches));
        assert_eq!(
            f.s.usage(metadata.job, Resource::Frames),
            Ok(metadata.frames)
        );
    }
    #[test]
    fn repeated_service_incarnations_reuse_metadata_and_domains_without_aliasing_peer_or_history() {
        // Portable host model only: no physical frames or user instructions are
        // executed. The same registry/Authority/Scheduler remain throughout;
        // each model owner passes the real admission and stopped-cleanup gates.
        #[derive(Clone, Copy)]
        struct Past {
            control: Handle,
            metadata: Metadata,
            grants: [Handle; 2],
            object: usize,
        }
        let mut f = fixture(&roles());
        let peer_job =
            f.s.create_child_job(f.parent_job, Limits::UNLIMITED)
                .unwrap();
        let peer = f.s.create_process(peer_job).unwrap();
        let peer_thread = f.s.create_thread(peer).unwrap();
        assert_eq!(f.s.dispatch(1).unwrap().unwrap().thread, peer_thread);
        f.s.charge_cpu(1, 3).unwrap();
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let sources = [
            f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap(),
            f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap(),
        ];
        let mut past: [Option<Past>; 128] = [None; 128];
        let mut stale_row: Option<Process> = None;
        let mut stale_image: Option<Information> = None;
        for cycle in 0..past.len() {
            let process = create_granted(&mut f, job, sources);
            let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
            let object =
                f.a.authorize(f.owner, process, Kind::Process, Rights::CONTROL)
                    .unwrap()
                    .identity();
            let slot = f.r.process(&f.a, f.owner, process).unwrap().0;
            let grants = [
                f.r.grant(&f.a, f.owner, process, 3).unwrap(),
                f.r.grant(&f.a, f.owner, process, 4).unwrap(),
            ];
            assert_eq!(f.r.processes[slot].unwrap().object, object);
            assert_eq!(f.s.dispatch(0), Ok(None));
            for previous in past[..cycle].iter().flatten() {
                assert_ne!(previous.metadata.process, metadata.process);
                assert_ne!(previous.metadata.thread, metadata.thread);
                assert_ne!(previous.metadata.domain, metadata.domain);
                assert_ne!(previous.control, process);
                assert_ne!(previous.object, object);
                assert_eq!(
                    object_slot(previous.object).unwrap(),
                    object_slot(object).unwrap()
                );
                assert_eq!(
                    f.r.metadata(&f.a, f.owner, previous.control).err(),
                    Some(Error::Authority(capability::Error::InvalidHandle))
                );
                assert_eq!(
                    f.r.retire_stopped(&mut f.a, &f.s, previous.metadata.process),
                    Err(Error::UnknownObject)
                );
                assert_eq!(
                    f.r.forget_retired(&mut f.a, &f.s, previous.metadata.process),
                    Err(Error::UnknownObject)
                );
                assert_eq!(
                    f.s.process_job(previous.metadata.process),
                    Err(scheduler::Error::InvalidId)
                );
                assert_eq!(
                    f.s.state(previous.metadata.thread),
                    Err(scheduler::Error::InvalidId)
                );
                for (i, right) in [Rights::RECEIVE, Rights::SEND].into_iter().enumerate() {
                    assert_eq!(
                        f.a.authorize(previous.metadata.domain, grants[i], Kind::Endpoint, right)
                            .err(),
                        Some(capability::Error::InvalidSpace)
                    );
                    assert_eq!(
                        f.a.authorize(metadata.domain, previous.grants[i], Kind::Endpoint, right)
                            .err(),
                        Some(capability::Error::InvalidHandle)
                    );
                }
                assert_eq!(
                    f.a.retire_unreferenced_object(previous.object, Kind::Process),
                    Err(capability::Error::DeadObject)
                );
            }
            if let Some(previous) = stale_row {
                let current = f.r.processes[slot];
                f.r.processes[slot] = Some(previous);
                assert_eq!(
                    f.r.metadata(&f.a, f.owner, process).err(),
                    Some(Error::UnknownObject)
                );
                f.r.processes[slot] = current;
            }
            if let Some(previous) = stale_image {
                let rejected =
                    match f
                        .r
                        .start(&f.a, &mut f.s, f.owner, process, epoch(), Model(previous))
                    {
                        Err(r) => r,
                        Ok(_) => panic!("prior incarnation image admitted"),
                    };
                assert_eq!(rejected.error, Error::ImageMismatch);
                assert_eq!(rejected.image.0.process, previous.process);
                assert_eq!(f.s.dispatch(0), Ok(None));
            }
            let loaded = model(&f, process);
            stale_image = Some(loaded.0);
            let running =
                f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded)
                    .unwrap_or_else(|r| panic!("{:?}", r.error));
            assert_eq!(running.metadata(), metadata);
            assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, metadata.thread);
            f.s.charge_cpu(0, 1).unwrap();
            assert_eq!(finish_model(&mut f, running), metadata);
            f.s.release_frames(metadata.job, metadata.frames).unwrap();
            f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
                .unwrap();
            let pool = f.r.closed_domains;
            f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
                .unwrap();
            assert_eq!(f.r.closed_domains, pool);
            assert_eq!(pool.iter().flatten().count(), 2);
            f.a.close(f.owner, process).unwrap();
            stale_row = f.r.processes[slot];
            f.r.forget_retired(&mut f.a, &f.s, metadata.process)
                .unwrap();
            assert!(f.r.processes[slot].is_none());
            assert_eq!(f.s.reclaim_process(metadata.process), Ok(1));
            assert_eq!(f.a.collect_lineage(), Ok(0));
            assert_eq!(f.a.collect_dead_objects(), Ok(0));
            for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
                assert_eq!(f.s.usage(metadata.job, resource), Ok(0));
            }
            assert_eq!(
                f.s.usage(metadata.job, Resource::CpuTicks),
                Ok(cycle as u64 + 1)
            );
            assert_eq!(
                f.s.usage(f.parent_job, Resource::CpuTicks),
                Ok(cycle as u64 + 4)
            );
            assert_eq!(f.s.usage(peer_job, Resource::CpuTicks), Ok(3));
            assert_eq!(f.s.state(peer_thread), Ok(scheduler::State::Running(1)));
            f.s.yield_cpu(1).unwrap();
            assert_eq!(f.s.dispatch(1).unwrap().unwrap().thread, peer_thread);
            assert_eq!(f.s.process_job(peer), Ok(peer_job));
            past[cycle] = Some(Past {
                control: process,
                metadata,
                grants,
                object,
            });
        }
        assert_eq!(f.r.processes.iter().flatten().count(), 0);
        assert_eq!(f.r.closed_domains.iter().flatten().count(), 2);
        assert_eq!(f.r.jobs.iter().flatten().count(), 2);
        assert_eq!(f.r.images.iter().flatten().count(), 1);
    }
    #[test]
    fn premature_forget_preserves_frames_and_live_or_escaped_control_pins_atomically() {
        let (mut f, process, _) = granted(&roles());
        let loaded = model(&f, process);
        let metadata = f.r.metadata(&f.a, f.owner, process).unwrap();
        failed_forget_unchanged(&mut f, metadata.process, Error::Phase);
        let running =
            f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        failed_forget_unchanged(&mut f, metadata.process, Error::Phase);
        finish_model(&mut f, running);
        f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
            .unwrap();
        failed_forget_unchanged(&mut f, metadata.process, Error::Phase);
        assert_eq!(
            f.s.usage(metadata.job, Resource::Frames),
            Ok(metadata.frames)
        );
        f.s.release_frames(metadata.job, metadata.frames).unwrap();
        failed_forget_unchanged(
            &mut f,
            metadata.process,
            Error::Authority(capability::Error::ObjectBusy),
        );
        let escaped_space = f.a.create_space().unwrap();
        let escaped =
            f.a.derive(f.owner, process, escaped_space, Rights::CONTROL)
                .unwrap();
        f.a.close(f.owner, process).unwrap();
        failed_forget_unchanged(
            &mut f,
            metadata.process,
            Error::Authority(capability::Error::ObjectBusy),
        );
        assert!(
            f.a.authorize(escaped_space, escaped, Kind::Process, Rights::CONTROL)
                .is_ok()
        );
        f.a.close(escaped_space, escaped).unwrap();
        f.r.forget_retired(&mut f.a, &f.s, metadata.process)
            .unwrap();
        assert_eq!(f.s.reclaim_process(metadata.process), Ok(1));
    }
    #[test]
    fn late_creation_failure_does_not_consume_recycled_domains_or_generations() {
        let mut f = fixture(&roles());
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let sources = [
            f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap(),
            f.r.create_endpoint(&mut f.a, f.owner, f.parent).unwrap(),
        ];
        let process = create_granted(&mut f, job, sources);
        let loaded = model(&f, process);
        let running =
            f.r.start(&f.a, &mut f.s, f.owner, process, epoch(), loaded)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        let metadata = finish_model(&mut f, running);
        f.s.release_frames(metadata.job, metadata.frames).unwrap();
        f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
            .unwrap();
        f.a.close(f.owner, process).unwrap();
        f.r.forget_retired(&mut f.a, &f.s, metadata.process)
            .unwrap();
        f.s.reclaim_process(metadata.process).unwrap();
        let pool = f.r.closed_domains;
        let mut staged = f.a.staged_copy();
        let mut copy_pool = pool;
        let expected_domain = take_domain(&mut staged, &mut copy_pool).unwrap();
        let mut fillers = [Handle(0); MAX_CAPS];
        let mut count = 0;
        for _ in 5..MAX_CAPS {
            fillers[count] =
                f.a.derive(f.owner, f.parent, f.owner, Rights::READ)
                    .unwrap();
            count += 1;
        }
        let mut prior = f.a.staged_copy();
        assert_eq!(
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image),
            Err(Error::Authority(capability::Error::Capacity))
        );
        assert_eq!(f.r.closed_domains, pool);
        assert_eq!(f.s.usage(metadata.job, Resource::Frames), Ok(0));
        assert_eq!(f.s.usage(metadata.job, Resource::Processes), Ok(0));
        for domain in pool.iter().flatten() {
            assert!(!f.a.is_live_space(*domain));
        }
        // A full cap table intentionally prevents the ordinary creation probe;
        // compare after opening the same one vacancy in each staged history.
        f.a.close(f.owner, fillers[count - 1]).unwrap();
        prior.close(f.owner, fillers[count - 1]).unwrap();
        assert_eq!(
            authority_probe(&f),
            probe_authority(&prior, f.owner, f.parent)
        );
        let next =
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                .unwrap();
        let next_metadata = f.r.metadata(&f.a, f.owner, next).unwrap();
        assert_eq!(next_metadata.domain, expected_domain);
        assert_eq!(next_metadata.process.diagnostic_id(), 257);
        assert_eq!(next_metadata.thread.diagnostic_id(), 257);
    }
    #[test]
    fn service_roles_remain_bounded_by_bootstrap_contract_when_cap_tables_are_larger() {
        let valid: [Role; ev_userspace_contract::MAX_GRANTS] = core::array::from_fn(|i| Role {
            selector: i as u64 + 1,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        });
        assert!(image(&valid).plan().is_ok());
        let excessive: [Role; ev_userspace_contract::MAX_GRANTS + 1] =
            core::array::from_fn(|i| Role {
                selector: i as u64 + 1,
                kind: Kind::Endpoint,
                rights: Rights::SEND,
            });
        assert_eq!(
            ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, &excessive).err(),
            Some(Error::Descriptor)
        );
        let all_slots: [Role; MAX_CAPS] = core::array::from_fn(|i| Role {
            selector: i as u64 + 1,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        });
        assert_eq!(
            ServiceImage::verify(ELF, Sha256::digest(ELF).into(), SERVICE_LIMITS, &all_slots).err(),
            Some(Error::Descriptor)
        );
    }

    #[test]
    fn measured_mutex_role_uses_kind_six_in_actual_service_startup() {
        let mut f = fixture(&[Role {
            selector: 6,
            kind: Kind::Mutex,
            rights: Rights::CONTROL,
        }]);
        let job =
            f.r.create_job(&mut f.a, &mut f.s, f.owner, f.parent, 0)
                .unwrap();
        let process =
            f.r.create_process(&mut f.a, &mut f.s, f.owner, job, f.image)
                .unwrap();
        let source =
            f.a.create_root(
                f.owner,
                Kind::Mutex,
                Rights::CONTROL | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
            )
            .unwrap();
        f.r.delegate(&mut f.a, f.owner, process, source, 6).unwrap();
        let record =
            f.r.startup(&f.a, f.owner, process, NonZeroU64::new(7).unwrap())
                .unwrap();
        let grant = ev_userspace_contract::Bootstrap::parse(&record)
            .unwrap()
            .find(6)
            .unwrap();
        assert_eq!((grant.kind, grant.rights), (6, Rights::CONTROL.bits()));
        let meta = f.r.metadata(&f.a, f.owner, process).unwrap();
        assert!(
            f.a.authorize(
                meta.domain,
                Handle(grant.handle),
                Kind::Mutex,
                Rights::CONTROL
            )
            .is_ok()
        );
        assert!(
            f.a.authorize(
                meta.domain,
                Handle(grant.handle),
                Kind::Memory,
                Rights::READ
            )
            .is_err()
        );
    }

    struct InhibitTestRam(std::boxed::Box<[u8; 4096]>);
    // SAFETY: explicit host-only byte backing for this test's sole retained
    // physical-frame identity. This is not actual hardware RAM or a PTE proof.
    #[allow(unsafe_code)]
    unsafe impl crate::memory_extent::RamAccess for InhibitTestRam {
        type Error = ();
        fn write(
            &mut self,
            frame: &crate::memory::PhysicalFrame,
            byte: usize,
            value: u8,
        ) -> Result<(), ()> {
            assert_eq!(frame.start(), 4096);
            self.0[byte] = value;
            Ok(())
        }
        fn read(&mut self, frame: &crate::memory::PhysicalFrame, byte: usize) -> Result<u8, ()> {
            assert_eq!(frame.start(), 4096);
            Ok(self.0[byte])
        }
    }
    #[test]
    fn inhibit_pending_read_preserves_real_rpc_then_blocks_reply_wake_redispatch() {
        use crate::{
            ipc::{Mailbox, Outgoing},
            rpc::{MessageShape, Policy, Status},
            time::Deadline,
        };
        let (mut f, control, sources) = granted(&roles());
        let loaded = model(&f, control);
        let metadata = f.r.metadata(&f.a, f.owner, control).unwrap();
        let send = f.r.grant(&f.a, f.owner, control, 4).unwrap();
        let mut running =
            f.r.start(&f.a, &mut f.s, f.owner, control, epoch(), loaded)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        let server_job = f.s.create_child_job(f.parent_job, SERVICE_LIMITS).unwrap();
        let server_process = f.s.create_process(server_job).unwrap();
        let server = f.s.create_thread(server_process).unwrap();
        // One actual owned frame and two move-only live mapping claims.
        let mut frames = crate::memory::BootstrapFrames::new(
            ev_boot_contract::MemoryMap::validate([ev_boot_contract::MemoryRegion {
                start: 4096,
                end: 12288,
                kind: ev_boot_contract::MemoryKind::Usable,
            }])
            .unwrap(),
        );
        let mut ram = InhibitTestRam(std::boxed::Box::new([0xa5; 4096]));
        let owned = crate::memory_extent::UninitializedRam::allocate(
            &mut frames,
            &mut f.s,
            f.parent_job,
            1,
        )
        .unwrap_or_else(|r| panic!("{:?}", r.error))
        .initialize(&mut ram)
        .unwrap_or_else(|r| panic!("{:?}", r.error));
        let (mut shared, shared_control) =
            crate::memory_extent::MemoryExtent::publish(&mut f.a, f.owner, owned, &frames, &f.s)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        let app_memory =
            f.a.derive(
                f.owner,
                shared_control,
                metadata.domain,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )
            .unwrap();
        let app_lease = shared.map(&f.a, metadata.domain, app_memory, true).unwrap();
        let file_lease = shared.map(&f.a, f.owner, shared_control, true).unwrap();
        let mut rpc = Rpc::new(epoch());
        rpc.register_thread(
            &f.a,
            &f.s,
            metadata.thread,
            metadata.job,
            metadata.domain,
            None,
        )
        .unwrap();
        rpc.register_thread(&f.a, &f.s, server, server_job, f.owner, None)
            .unwrap();
        rpc.bind_endpoint(
            &f.a,
            f.owner,
            sources[1],
            server,
            Policy::new(8, 0).unwrap(),
        )
        .unwrap();
        let mut mailbox = Mailbox::new(&mut f.a, f.owner, sources[1]).unwrap();
        let deadline = Deadline::after(0, 100).unwrap();
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, metadata.thread);
        let call = rpc
            .begin(
                &f.a,
                metadata.thread,
                send,
                deadline,
                MessageShape {
                    bytes: 8,
                    capabilities: 0,
                },
                0,
            )
            .unwrap();
        let payload = *b"READ0001";
        mailbox
            .send(
                &mut f.a,
                metadata.domain,
                send,
                Outgoing {
                    bytes: &payload,
                    capability: None,
                    deadline,
                },
                0,
            )
            .unwrap();
        let wait = f.s.block(0, deadline).unwrap();
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, server);
        let delivered = mailbox.receive(&mut f.a, f.owner, sources[1], 0).unwrap();
        assert_eq!(&delivered.bytes[..8], &payload);
        assert_eq!(delivered.capability, None);
        let usage_before = f.s.usage(metadata.job, Resource::Frames).unwrap();
        let authority_before = f.a.metadata_usage();
        running.inhibit(&mut f.s).unwrap();
        running.inhibit(&mut f.s).unwrap(); // accepted idempotent inhibition
        assert!(f.s.waiting(wait));
        assert_eq!(shared.live_leases(), 2);
        assert_eq!(
            shared.destroy(&mut f.a, f.owner, shared_control).err(),
            Some(crate::memory_extent::Error::Busy)
        );
        assert_eq!(frames.remaining_frames(), 1);
        assert_eq!(rpc.outstanding(), 1);
        assert_eq!(rpc.serving(server), Some(call));
        assert_eq!(f.a.metadata_usage(), authority_before);
        assert!(
            f.a.authorize(metadata.domain, send, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(f.s.usage(metadata.job, Resource::Frames), Ok(usage_before));
        running = match running.finish(&f.s) {
            Err(owner) => owner,
            Ok(_) => panic!("inhibition returned live image"),
        };
        assert_eq!(
            f.r.retire_stopped(&mut f.a, &f.s, metadata.process),
            Err(Error::Phase)
        );
        assert_eq!(
            f.s.reclaim_process(metadata.process),
            Err(scheduler::Error::NotQuiescent)
        );
        // Exact callee still runs, owns its accepted request and completes it.
        // No revoke/timeout/forged reply makes the shared-work credit disappear.
        assert_eq!(f.s.state(server), Ok(scheduler::State::Running(0)));
        let reply = rpc.complete(server, call, 1).unwrap();
        assert_eq!(reply.status, Status::Ok);
        assert!(reply.wake_caller && reply.deliver_reply);
        assert!(f.s.wake(wait));
        assert_eq!(rpc.outstanding(), 0);
        assert_eq!(f.s.state(metadata.thread), Ok(scheduler::State::Ready));
        assert_eq!(shared.live_leases(), 2);
        assert_eq!(
            shared.destroy(&mut f.a, f.owner, shared_control).err(),
            Some(crate::memory_extent::Error::Busy)
        );
        assert_eq!(frames.remaining_frames(), 1);
        f.s.yield_cpu(0).unwrap();
        // Reply wakes Ready normally, but ALL CPUs still skip this process.
        for cpu in 0..scheduler::MAX_CPUS {
            if let Some(dispatch) = f.s.dispatch(cpu).unwrap() {
                assert_eq!(dispatch.thread, server);
                f.s.yield_cpu(cpu).unwrap();
            }
        }
        assert_eq!(
            f.s.held_process_job(metadata.process),
            Err(scheduler::Error::NotHeld)
        );
        assert_eq!(
            f.s.admit_service(
                metadata.process,
                metadata.job,
                metadata.thread,
                metadata.frames
            ),
            Err(scheduler::Error::NotHeld)
        );
        // Only after actual completion does ordinary stop revoke descendants.
        running.stop(&mut f.a, &mut f.s).unwrap();
        assert_eq!(
            f.a.authorize(metadata.domain, send, Kind::Endpoint, Rights::SEND)
                .err(),
            Some(capability::Error::Revoked)
        );
        f.s.terminate_process(metadata.process).unwrap();
        assert!(rpc.peer_died(&f.s, metadata.thread, 1).unwrap().is_empty());
        let _returned = running
            .finish(&f.s)
            .unwrap_or_else(|_| panic!("stopped image retained"));
        // This host model has no real mappings/physical memory. The actual
        // runtime must detach/unmap/retire those before balancing these frames.
        f.s.release_frames(metadata.job, metadata.frames).unwrap();
        f.r.retire_stopped(&mut f.a, &f.s, metadata.process)
            .unwrap();
        rpc.forget_thread(&f.s, metadata.thread).unwrap();
        f.s.reclaim_process(metadata.process).unwrap();
        assert_eq!(f.s.usage(metadata.job, Resource::Frames), Ok(0));
        // In this portable model no hardware alias exists. Actual runtime must
        // detach the exact mapping before returning each move-only lease.
        shared.unmap(app_lease).unwrap();
        assert_eq!(
            shared.destroy(&mut f.a, f.owner, shared_control).err(),
            Some(crate::memory_extent::Error::Busy)
        );
        f.s.terminate_process(server_process).unwrap();
        shared.unmap(file_lease).unwrap();
        let retired = shared.destroy(&mut f.a, f.owner, shared_control).unwrap();
        retired
            .release(&mut frames, &mut f.s, &mut ram)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(frames.remaining_frames(), 2);
        assert!(ram.0.iter().all(|byte| *byte == 0));
    }
    #[test]
    fn inhibit_after_stopping_refuses_without_changing_authority_or_frames() {
        let (mut f, control, _) = granted(&roles());
        let loaded = model(&f, control);
        let mut running =
            f.r.start(&f.a, &mut f.s, f.owner, control, epoch(), loaded)
                .unwrap_or_else(|r| panic!("{:?}", r.error));
        running.stop(&mut f.a, &mut f.s).unwrap();
        let before = (
            f.a.metadata_usage(),
            f.s.metadata_usage(),
            f.s.usage(running.metadata().job, Resource::Frames),
        );
        assert_eq!(running.inhibit(&mut f.s), Err(Error::Phase));
        assert_eq!(
            (
                f.a.metadata_usage(),
                f.s.metadata_usage(),
                f.s.usage(running.metadata().job, Resource::Frames)
            ),
            before
        );
    }
}
