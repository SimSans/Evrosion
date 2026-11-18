//! Internal incarnation admission and owned executable lifetime; full BAC recovery remains pending.
//! One trusted owner retains this record and the SAME Authority/Scheduler for a
//! boot epoch. Epoch uniqueness comes from trusted boot selection, not this API.
//! Bound processes remain held until typed image ownership and live authority
//! pass admission. Replacement/reset still require actual external quiescence.
use core::num::NonZeroU64;
use sha2::{Digest, Sha256};

use crate::{
    bootstrap_binding::{self, CatalogEntry},
    bootstrap_manifest::Manifest,
    capability::{self, Authority, GrantBatch, Handle, SpaceId},
    loaded_image::LoadedExecutable,
    scheduler::{self, JobId, ProcessId, Scheduler, ThreadId},
};

/// Kernel event identity, never a capability or userspace-transferable token.
/// Copying this identifier does not copy the single current binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    epoch: NonZeroU64,
    number: u64,
    process: ProcessId,
    job: JobId,
    manifest: [u8; 32],
    authority: [u8; 32],
    destination: SpaceId,
    branches: SpaceId,
}

impl Token {
    pub fn number(self) -> u64 {
        self.number
    }
    pub fn process(self) -> ProcessId {
        self.process
    }
    pub fn job(self) -> JobId {
        self.job
    }
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn destination(self) -> SpaceId {
        self.destination
    }
}

/// Trusted kernel target description; never accepted from a userspace request.
#[derive(Clone, Copy)]
pub struct Target {
    pub process: ProcessId,
    pub job: JobId,
    pub destination: SpaceId,
    pub branches: SpaceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Empty,
    Bound,
    Active,
    Revoking,
    Revoked,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    StaleToken,
    WrongJob,
    JobLimits,
    ImageMismatch,
    Bootstrap(ev_userspace_contract::Error),
    SequenceExhausted,
    RecoveryRequired,
    #[cfg(feature = "workspace-authority")]
    SharedBacking,
    Scheduler(scheduler::Error),
    Binding(bootstrap_binding::Error),
    Authority(capability::Error),
    Executable(crate::executable::Error),
}

struct Current {
    token: Token,
    branches: GrantBatch,
    grants: GrantBatch,
}

/// Non-Clone boot-lifetime record. No current token is published until the live
/// digest, both authority tables and scheduler identity all agree. This record
/// stores borrowed measured bytes and catalog for its entire lifetime.
pub struct Bindings<'a> {
    epoch: NonZeroU64,
    sequence: u64,
    manifest: crate::root_selection::Selection<'a>,
    custody: SpaceId,
    catalog: &'a [CatalogEntry],
    phase: Phase,
    current: Option<Current>,
    failure: Option<Error>,
}
impl<'a> Bindings<'a> {
    /// Trusted once-per-boot construction. Do not recreate to bypass retirement.
    pub fn new(
        epoch: NonZeroU64,
        manifest: &'a Manifest<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self::new_selected(
            epoch,
            crate::root_selection::Selection::V1(manifest),
            custody,
            catalog,
        )
    }
    pub(crate) fn new_selected(
        epoch: NonZeroU64,
        manifest: crate::root_selection::Selection<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self {
            epoch,
            sequence: 0,
            manifest,
            custody,
            catalog,
            phase: Phase::Empty,
            current: None,
            failure: None,
        }
    }
    /// Sealed custodian construction after a uniquely admitted attempt. The
    /// custodian owns the monotonic sequence; ordinary callers cannot reset it.
    pub(crate) fn new_after_sequence(
        epoch: NonZeroU64,
        previous: u64,
        manifest: crate::root_selection::Selection<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        let mut binding = Self::new_selected(epoch, manifest, custody, catalog);
        binding.sequence = previous;
        binding
    }
    pub(crate) fn current_token(&self) -> Option<Token> {
        self.current.as_ref().map(|current| current.token)
    }
    pub(crate) fn sealed_context_matches(
        &self,
        epoch: NonZeroU64,
        manifest: crate::root_selection::Selection<'a>,
        custody: SpaceId,
        catalog: &[CatalogEntry],
    ) -> bool {
        self.epoch == epoch
            && self.custody == custody
            && self.manifest.same(manifest)
            && core::ptr::eq(self.catalog, catalog)
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    fn fail(&mut self, error: Error) -> Error {
        self.phase = Phase::RecoveryRequired;
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The scheduler remains borrowed through installation, so preparation
    /// cannot race dispatch. Its admission hold remains set after this returns.
    /// Invalid target descriptions create nothing; a failed installation latches
    /// recovery and never publishes a partially bound token or refunds its number.
    pub fn prepare(
        &mut self,
        authority: &mut Authority,
        scheduler: &Scheduler,
        target: Target,
    ) -> Result<Token, Error> {
        match self.phase {
            Phase::Empty => (),
            Phase::RecoveryRequired => return Err(Error::RecoveryRequired),
            _ => return Err(Error::Busy),
        }
        let actual_job = scheduler
            .held_process_job(target.process)
            .map_err(Error::Scheduler)?;
        if actual_job != target.job {
            return Err(Error::WrongJob);
        }
        if scheduler.job_limits(actual_job).map_err(Error::Scheduler)? != self.manifest.limits() {
            return Err(Error::JobLimits);
        }
        let Some(number) = self.sequence.checked_add(1) else {
            return Err(self.fail(Error::SequenceExhausted));
        };
        self.sequence = number;
        let installed = match self.manifest.install(
            authority,
            self.custody,
            target.branches,
            target.destination,
            self.catalog,
        ) {
            Ok(installed) => installed,
            Err(error) => {
                return Err(self.fail(Error::Binding(error)));
            }
        };
        let token = Token {
            epoch: self.epoch,
            number,
            process: target.process,
            job: actual_job,
            manifest: self.manifest.digest(),
            authority: installed.digest,
            destination: target.destination,
            branches: target.branches,
        };
        self.current = Some(Current {
            token,
            branches: installed.grants.branches,
            grants: installed.grants.grants,
        });
        self.phase = Phase::Bound;
        Ok(token)
    }

    /// Kernel-issued runtime handles and identity, for the current ABI only.
    /// This record is volatile startup data, never serialized durable policy.
    pub fn bootstrap_record(
        &self,
        token: Token,
    ) -> Result<Option<[u8; ev_userspace_contract::SIZE]>, Error> {
        let current = self.matching(token)?;
        if self.phase != Phase::Bound {
            return Err(Error::Busy);
        }
        if self.manifest.abi_fingerprint() != ev_userspace_contract::ABI {
            return Ok(None);
        }
        let mut grants = [ev_userspace_contract::Grant {
            selector: 0,
            handle: 0,
            kind: 0,
            rights: 0,
        }; 8];
        let mut count = 0;
        for (i, grant) in self.manifest.grants().enumerate() {
            grants[i] = ev_userspace_contract::Grant {
                selector: grant.selector,
                handle: current.grants.handles()[i].0,
                kind: match grant.kind {
                    capability::Kind::Memory => 1,
                    capability::Kind::Endpoint => 2,
                    capability::Kind::Process => 3,
                    capability::Kind::Thread => 4,
                    capability::Kind::Job => 5,
                    capability::Kind::Mutex => 6,
                    capability::Kind::IoPorts => 7,
                    capability::Kind::Display => 8,
                },
                rights: grant.rights.bits(),
            };
            count += 1;
        }
        let limits = self.manifest.limits();
        ev_userspace_contract::encode(
            ev_userspace_contract::Context {
                epoch: token.epoch.get(),
                incarnation: token.number,
                process: token.process.diagnostic_id(),
                limits: [
                    scheduler::Resource::CpuTicks,
                    scheduler::Resource::Frames,
                    scheduler::Resource::Processes,
                    scheduler::Resource::Threads,
                ]
                .map(|r| limits.limit(r)),
                manifest: token.manifest,
                authority: token.authority,
            },
            &grants[..count],
        )
        .map(Some)
        .map_err(Error::Bootstrap)
    }

    /// Named Root-only record, from the same actual binding/token/owned grants.
    pub fn bootstrap_record_v2(
        &self,
        token: Token,
    ) -> Result<[u8; ev_userspace_contract::root_v2::SIZE], Error> {
        let current = self.matching(token)?;
        if self.phase != Phase::Bound || !self.manifest.is_root_v2() {
            return Err(Error::Busy);
        }
        let mut handles = [0; ev_userspace_contract::root_v2::CURRENT_GRANTS];
        if current.grants.handles().len() != handles.len() {
            return Err(Error::ImageMismatch);
        }
        for (i, h) in current.grants.handles().iter().enumerate() {
            handles[i] = h.0;
        }
        let limits = self.manifest.limits();
        ev_userspace_contract::root_v2::encode_full_graph(
            ev_userspace_contract::Context {
                epoch: token.epoch.get(),
                incarnation: token.number,
                process: token.process.diagnostic_id(),
                limits: [
                    scheduler::Resource::CpuTicks,
                    scheduler::Resource::Frames,
                    scheduler::Resource::Processes,
                    scheduler::Resource::Threads,
                ]
                .map(|r| limits.limit(r)),
                manifest: token.manifest,
                authority: token.authority,
            },
            handles,
        )
        .map_err(|_| Error::ImageMismatch)
    }
    /// Native-only profile2 record from this exact bound token and its21 live
    /// grants. Desktop profile1 and ordinary v1 callers cannot select it.
    pub fn bootstrap_record_native(
        &self,
        token: Token,
    ) -> Result<[u8; ev_userspace_contract::root_v2::native::SIZE], Error> {
        let current = self.matching(token)?;
        if self.phase != Phase::Bound || !self.manifest.is_native_root() {
            return Err(Error::Busy);
        }
        let mut handles = [0; ev_userspace_contract::root_v2::native::CURRENT_GRANTS];
        if current.grants.handles().len() != handles.len() {
            return Err(Error::ImageMismatch);
        }
        for (i, h) in current.grants.handles().iter().enumerate() {
            handles[i] = h.0;
        }
        let limits = self.manifest.limits();
        ev_userspace_contract::root_v2::native::encode_full_graph(
            ev_userspace_contract::Context {
                epoch: token.epoch.get(),
                incarnation: token.number,
                process: token.process.diagnostic_id(),
                limits: [
                    scheduler::Resource::CpuTicks,
                    scheduler::Resource::Frames,
                    scheduler::Resource::Processes,
                    scheduler::Resource::Threads,
                ]
                .map(|r| limits.limit(r)),
                manifest: token.manifest,
                authority: token.authority,
            },
            handles,
        )
        .map_err(|_| Error::ImageMismatch)
    }
    /// V4 record from this same actual bound token/27 grants. Other typed
    /// selections cannot use it, and it never changes the immutable selection.
    pub fn bootstrap_record_v4(
        &self,
        token: Token,
    ) -> Result<[u8; ev_userspace_contract::root_v4::SIZE], Error> {
        let current = self.matching(token)?;
        if self.phase != Phase::Bound || !self.manifest.is_root_v4() {
            return Err(Error::Busy);
        }
        let mut handles = [0; ev_userspace_contract::root_v4::CURRENT_GRANTS];
        if current.grants.handles().len() != handles.len() {
            return Err(Error::ImageMismatch);
        }
        for (i, h) in current.grants.handles().iter().enumerate() {
            handles[i] = h.0;
        }
        let limits = self.manifest.limits();
        ev_userspace_contract::root_v4::encode_full_graph(
            ev_userspace_contract::Context {
                epoch: token.epoch.get(),
                incarnation: token.number,
                process: token.process.diagnostic_id(),
                limits: [
                    scheduler::Resource::CpuTicks,
                    scheduler::Resource::Frames,
                    scheduler::Resource::Processes,
                    scheduler::Resource::Threads,
                ]
                .map(|r| limits.limit(r)),
                manifest: token.manifest,
                authority: token.authority,
            },
            handles,
        )
        .map_err(|_| Error::ImageMismatch)
    }
    fn expected_startup(
        &self,
        token: Token,
        image: &crate::executable::Image<'_>,
    ) -> Result<Option<crate::loaded_image::Startup>, Error> {
        #[cfg(feature = "workspace-authority")]
        if self.manifest.is_root_v5() {
            return self.expected_startup_v5(token, image);
        }
        if self.manifest.is_root_v4() {
            let record = self.bootstrap_record_v4(token)?;
            return Ok(Some(crate::loaded_image::Startup {
                address: image.bootstrap_page().ok_or(Error::ImageMismatch)?,
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            }));
        }
        if self.manifest.has_root_record() {
            let record = if self.manifest.is_native_root() {
                self.bootstrap_record_native(token)?
            } else {
                self.bootstrap_record_v2(token)?
            };
            Ok(Some(crate::loaded_image::Startup {
                address: image.bootstrap_page().ok_or(Error::ImageMismatch)?,
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            }))
        } else {
            Ok(self
                .bootstrap_record(token)?
                .map(|record| crate::loaded_image::Startup {
                    address: image.bootstrap_page().unwrap(),
                    bytes: record.len(),
                    digest: Sha256::digest(record).into(),
                }))
        }
    }
    /// Exact kernel-captured Root identity and installed37 destination grants.
    #[cfg(feature = "workspace-authority")]
    pub fn bootstrap_record_v5(
        &self,
        token: Token,
    ) -> Result<[u8; ev_userspace_contract::root_v5::SIZE], Error> {
        let current = self.matching(token)?;
        if self.phase != Phase::Bound || !self.manifest.is_root_v5() {
            return Err(Error::Busy);
        }
        let mut handles = [0; ev_userspace_contract::root_v5::CURRENT_GRANTS];
        if current.grants.handles().len() != handles.len() {
            return Err(Error::ImageMismatch);
        }
        for (i, h) in current.grants.handles().iter().enumerate() {
            handles[i] = h.0;
        }
        let limits = self.manifest.limits();
        ev_userspace_contract::root_v5::encode_full_graph(
            ev_userspace_contract::Context {
                epoch: token.epoch.get(),
                incarnation: token.number,
                process: token.process.diagnostic_id(),
                limits: [
                    scheduler::Resource::CpuTicks,
                    scheduler::Resource::Frames,
                    scheduler::Resource::Processes,
                    scheduler::Resource::Threads,
                ]
                .map(|r| limits.limit(r)),
                manifest: token.manifest,
                authority: token.authority,
            },
            handles,
        )
        .map_err(|_| Error::ImageMismatch)
    }
    #[cfg(feature = "workspace-authority")]
    #[inline(never)]
    fn expected_startup_v5(
        &self,
        token: Token,
        image: &crate::executable::Image<'_>,
    ) -> Result<Option<crate::loaded_image::Startup>, Error> {
        let record = self.bootstrap_record_v5(token)?;
        Ok(Some(crate::loaded_image::Startup {
            address: image.bootstrap_page().ok_or(Error::ImageMismatch)?,
            bytes: record.len(),
            digest: Sha256::digest(record).into(),
        }))
    }

    /// Transfer loaded-image ownership into the active record only after every
    /// measured identity, capability relation and scheduler precondition passes.
    /// A rejected attempt returns both owners and keeps admission held.
    #[allow(clippy::result_large_err)] // Allocation-free rejection must return both bounded owners.
    pub fn activate<L: LoadedExecutable>(
        mut self,
        authority: &Authority,
        scheduler: &mut Scheduler,
        token: Token,
        thread: ThreadId,
        image: L,
    ) -> Result<Active<'a, L>, Rejected<'a, L>> {
        let checked = self.check_activation(authority, scheduler, token, &image);
        let frames = match checked {
            Ok(frames) => frames,
            Err(error) => {
                return Err(Rejected {
                    binding: self,
                    image,
                    error,
                });
            }
        };
        if let Err(error) = scheduler.admit_bootstrap(token.process, token.job, thread, frames) {
            return Err(Rejected {
                binding: self,
                image,
                error: Error::Scheduler(error),
            });
        }
        // All fallible work is complete. Exclusive scheduler access prevents a
        // dispatch between hold release and publication of the owning Active.
        self.phase = Phase::Active;
        Ok(Active {
            binding: self,
            image,
        })
    }
    /// Additive selected V5 admission: actual shared source RAM was already
    /// charged to this Root subtree before its first instruction. Borrow each
    /// initialized owner, exact source identity and allocator through commit;
    /// a user quota, sampled usage or unrelated backing cannot release hold.
    #[cfg(feature = "workspace-authority")]
    #[allow(clippy::result_large_err, clippy::too_many_arguments)]
    pub fn activate_root_v5<L: LoadedExecutable, const N: usize>(
        mut self,
        authority: &Authority,
        scheduler: &mut Scheduler,
        token: Token,
        thread: ThreadId,
        image: L,
        allocator: &crate::memory::BootstrapFrames,
        extents: &[Option<crate::memory_extent::BoundedMemoryExtent<N>>;
             ev_userspace_contract::root_v5::CURRENT_GRANTS],
    ) -> Result<Active<'a, L>, Rejected<'a, L>> {
        let checked = (|| {
            if !self.manifest.is_root_v5() || self.catalog.len() != extents.len() {
                return Err(Error::SharedBacking);
            }
            let private = self.check_activation(authority, scheduler, token, &image)?;
            let mut shared = 0u64;
            for (index, extent) in extents.iter().enumerate() {
                if let Some(extent) = extent {
                    let charge = extent
                        .root_shared_charge(
                            authority,
                            allocator,
                            scheduler,
                            token.job,
                            self.custody,
                            self.catalog[index].root,
                        )
                        .map_err(|_| Error::SharedBacking)?;
                    shared = shared.checked_add(charge).ok_or(Error::SharedBacking)?;
                }
            }
            scheduler
                .admit_workspace_root(token.process, token.job, thread, private, shared)
                .map_err(Error::Scheduler)
        })();
        if let Err(error) = checked {
            return Err(Rejected {
                binding: self,
                image,
                error,
            });
        }
        self.phase = Phase::Active;
        Ok(Active {
            binding: self,
            image,
        })
    }
    fn check_activation<L: LoadedExecutable>(
        &mut self,
        authority: &Authority,
        scheduler: &Scheduler,
        token: Token,
        image: &L,
    ) -> Result<u64, Error> {
        self.matching(token)?;
        if self.phase != Phase::Bound {
            return Err(Error::Busy);
        }
        if scheduler
            .held_process_job(token.process)
            .map_err(Error::Scheduler)?
            != token.job
        {
            return Err(Error::WrongJob);
        }
        if scheduler.job_limits(token.job).map_err(Error::Scheduler)? != self.manifest.limits() {
            return Err(Error::JobLimits);
        }
        let expected = self
            .manifest
            .executable_plan()
            .map_err(|e| self.fail(Error::Executable(e)))?;
        let startup = self.expected_startup(token, &expected)?;
        let info = image.information();
        if (self.manifest.has_root_record() && image.layout() != expected.layout())
            || info.startup != startup
            || info.process != token.process
            || info.manifest != token.manifest
            || info.entry != expected.entry()
            || info.stack != expected.stack_top()
            || info.frames != expected.required_frames()
            || info.root == 0
            || !info.root.is_multiple_of(crate::memory::FRAME_SIZE)
            || info.root & crate::mapping::ADDRESS_MASK != info.root
        {
            return Err(self.fail(Error::ImageMismatch));
        }
        let current = self.matching(token)?;
        self.manifest
            .revalidate(
                authority,
                self.custody,
                self.catalog,
                bootstrap_binding::InstalledView {
                    branches: token.branches,
                    destination: token.destination,
                    private: current.branches.handles(),
                    grants: current.grants.handles(),
                },
            )
            .map_err(|e| self.fail(Error::Binding(e)))?;
        Ok(info.frames)
    }

    /// Validate the exact measured image for the current held attempt. An image
    /// plan is not a loaded address space or permission to release admission.
    pub fn executable(&mut self, token: Token) -> Result<crate::executable::Image<'a>, Error> {
        self.matching(token)?;
        if self.phase != Phase::Bound {
            return Err(Error::Busy);
        }
        self.manifest
            .executable_plan()
            .map_err(|e| self.fail(Error::Executable(e)))
    }

    pub(crate) fn check_dynamic_root(
        &self,
        authority: &Authority,
        scheduler: &Scheduler,
        caller: SpaceId,
        creator: Handle,
    ) -> Result<crate::dynamic_image::RootIdentity, Error> {
        self.check_dynamic_root_profile(authority, scheduler, caller, creator, false)
    }

    #[cfg(feature = "workspace-authority")]
    pub(crate) fn check_workspace_dynamic_root(
        &self,
        authority: &Authority,
        scheduler: &Scheduler,
        caller: SpaceId,
        creator: Handle,
        thread: ThreadId,
    ) -> Result<crate::dynamic_image::RootIdentity, Error> {
        let root = self.check_dynamic_root_profile(authority, scheduler, caller, creator, true)?;
        if scheduler.thread_process(thread).map_err(Error::Scheduler)? != root.token.process
            || !matches!(
                scheduler.state(thread),
                Ok(crate::scheduler::State::Running(_))
            )
        {
            return Err(Error::WrongJob);
        }
        let current = self.current.as_ref().ok_or(Error::StaleToken)?;
        if self.catalog.len() != ev_userspace_contract::root_v5::CURRENT_GRANTS {
            return Err(Error::StaleToken);
        }
        // New service/endpoint handles legitimately extend the destination
        // table. Revalidate every original V5 source/branch/grant identity
        // without treating that table as an admission-time exact handle set.
        for (index, grant) in self.manifest.grants().enumerate() {
            let source = self
                .catalog
                .iter()
                .find(|source| source.selector == grant.selector && source.kind == grant.kind)
                .ok_or(Error::StaleToken)?;
            let branch = *current
                .branches
                .handles()
                .get(index)
                .ok_or(Error::StaleToken)?;
            let installed = *current
                .grants
                .handles()
                .get(index)
                .ok_or(Error::StaleToken)?;
            authority
                .require_child(
                    root.token.branches,
                    branch,
                    self.custody,
                    source.root,
                    grant.kind,
                    grant.rights
                        | capability::Rights::DERIVE
                        | capability::Rights::TRANSFER
                        | capability::Rights::REVOKE,
                )
                .map_err(Error::Authority)?;
            authority
                .require_child(
                    caller,
                    installed,
                    root.token.branches,
                    branch,
                    grant.kind,
                    grant.rights,
                )
                .map_err(Error::Authority)?;
        }
        Ok(root)
    }

    fn check_dynamic_root_profile(
        &self,
        authority: &Authority,
        scheduler: &Scheduler,
        caller: SpaceId,
        creator: Handle,
        workspace: bool,
    ) -> Result<crate::dynamic_image::RootIdentity, Error> {
        #[cfg(feature = "workspace-authority")]
        let profile_matches = if workspace {
            self.manifest.is_root_v5()
        } else {
            self.manifest.is_root_v4()
        };
        #[cfg(not(feature = "workspace-authority"))]
        let profile_matches = !workspace && self.manifest.is_root_v4();
        if self.phase != Phase::Active || self.failure.is_some() || !profile_matches {
            return Err(Error::Busy);
        }
        let current = self.current.as_ref().ok_or(Error::StaleToken)?;
        let token = current.token;
        if token.destination != caller || !authority.is_live_space(caller) {
            return Err(Error::StaleToken);
        }
        if scheduler.process_terminated(token.process)
            || scheduler
                .dispatch_inhibited(token.process)
                .map_err(Error::Scheduler)?
            || scheduler
                .process_job(token.process)
                .map_err(Error::Scheduler)?
                != token.job
            || scheduler.job_limits(token.job).map_err(Error::Scheduler)? != self.manifest.limits()
        {
            return Err(Error::WrongJob);
        }
        #[cfg(feature = "workspace-authority")]
        let (selector, rights_bits) = if workspace {
            let role = ev_userspace_contract::root_v5::ROLES
                [ev_userspace_contract::root_v5::Role::CreatorJob.selector() as usize - 1];
            (role.role.selector(), role.rights)
        } else {
            let role = ev_userspace_contract::root_v4::ROLES
                [ev_userspace_contract::root_v4::Role::CreatorJob.selector() as usize - 1];
            (role.role.selector(), role.rights)
        };
        #[cfg(not(feature = "workspace-authority"))]
        let (selector, rights_bits) = {
            let role = ev_userspace_contract::root_v4::ROLES
                [ev_userspace_contract::root_v4::Role::CreatorJob.selector() as usize - 1];
            (role.role.selector(), role.rights)
        };
        let index = selector as usize - 1;
        if current.grants.handles().get(index) != Some(&creator) {
            return Err(Error::StaleToken);
        }
        authority
            .authorize(
                caller,
                creator,
                capability::Kind::Job,
                capability::Rights::CONTROL,
            )
            .map_err(Error::Authority)?;
        // Active Root has legitimately created service/endpoint handles. The
        // admission-only exact destination-table check is deliberately NOT
        // reused here. Recheck this installed CreatorJob's exact two-hop
        // lineage in the immutable bootstrap branch and original custody.
        let rights = capability::Rights::from_bits(rights_bits).ok_or(Error::StaleToken)?;
        let source = self
            .catalog
            .iter()
            .find(|entry| entry.selector == selector && entry.kind == capability::Kind::Job)
            .ok_or(Error::StaleToken)?;
        let branch = *current
            .branches
            .handles()
            .get(index)
            .ok_or(Error::StaleToken)?;
        authority
            .require_exact_handles(token.branches, current.branches.handles())
            .map_err(Error::Authority)?;
        authority
            .require_child(
                token.branches,
                branch,
                self.custody,
                source.root,
                capability::Kind::Job,
                rights
                    | capability::Rights::DERIVE
                    | capability::Rights::TRANSFER
                    | capability::Rights::REVOKE,
            )
            .map_err(Error::Authority)?;
        authority
            .require_child(
                caller,
                creator,
                token.branches,
                branch,
                capability::Kind::Job,
                rights,
            )
            .map_err(Error::Authority)?;
        Ok(crate::dynamic_image::RootIdentity {
            token,
            domain: caller,
            job: token.job,
        })
    }
    fn matching(&self, token: Token) -> Result<&Current, Error> {
        self.current
            .as_ref()
            .filter(|c| c.token == token)
            .ok_or(Error::StaleToken)
    }

    /// Exact destination-local grants, available only for the current bound
    /// token. Private branch handles never leave this manager through this API.
    pub fn grants(&self, token: Token) -> Result<&[Handle], Error> {
        let current = self.matching(token)?;
        if self.phase != Phase::Bound {
            return Err(Error::Busy);
        }
        Ok(current.grants.handles())
    }

    /// Validates the complete event identity BEFORE touching any authority.
    /// The exclusive borrow spans group revocation and phase transition. Repeated
    /// matching teardown is harmless. Keep branch handles pinned afterwards;
    /// revoked does not mean quiescent and does not authorize replacement.
    pub fn revoke(&mut self, authority: &mut Authority, token: Token) -> Result<(), Error> {
        let current = self.matching(token)?;
        if matches!(self.phase, Phase::Active | Phase::Revoking) {
            return Err(Error::Busy);
        }
        authority
            .revoke_batch(current.token.branches, current.branches.handles())
            .map_err(|e| self.fail(Error::Authority(e)))?;
        if self.phase != Phase::RecoveryRequired {
            self.phase = Phase::Revoked;
        }
        Ok(())
    }
}

/// A failed admission returns the same owners; no loaded backing is discarded.
pub struct Rejected<'a, L> {
    pub binding: Bindings<'a>,
    pub image: L,
    pub error: Error,
}
/// Owns both the unique current binding and actual executable backing. There is
/// no constructor or cloning API outside the checked activation transaction.
#[must_use = "retain active image ownership until revocation and process retirement"]
pub struct Active<'a, L: LoadedExecutable> {
    binding: Bindings<'a>,
    image: L,
}
impl<'a, L: LoadedExecutable> Active<'a, L> {
    pub(crate) fn sealed_context_matches(
        &self,
        epoch: NonZeroU64,
        manifest: crate::root_selection::Selection<'a>,
        custody: SpaceId,
        catalog: &[CatalogEntry],
    ) -> bool {
        self.binding
            .sealed_context_matches(epoch, manifest, custody, catalog)
    }
    /// Borrow the actual active V4 binding, not a caller-nominated PID/Job.
    /// The permit revalidates this same live binding and CreatorJob lineage on
    /// every operation; revocation cannot proceed through its shared borrow.
    pub fn dynamic_image_permit<'s>(
        &'s self,
        authority: &Authority,
        scheduler: &Scheduler,
        caller: SpaceId,
        creator: Handle,
    ) -> Result<crate::dynamic_image::RootPermit<'s, 'a>, Error> {
        self.binding
            .check_dynamic_root(authority, scheduler, caller, creator)?;
        Ok(crate::dynamic_image::RootPermit::new(
            &self.binding,
            caller,
            creator,
        ))
    }
    /// Selected V5 factory permit. The exact current V5 bootstrap binding and
    /// its independently held CreatorJob lineage are checked on every use.
    /// This does not validate a publisher, package signature or app identity.
    #[cfg(feature = "workspace-authority")]
    pub fn workspace_dynamic_image_permit<'s>(
        &'s self,
        authority: &Authority,
        scheduler: &Scheduler,
        caller: SpaceId,
        creator: Handle,
        thread: ThreadId,
    ) -> Result<crate::dynamic_image::RootPermit<'s, 'a>, Error> {
        self.binding
            .check_workspace_dynamic_root(authority, scheduler, caller, creator, thread)?;
        Ok(crate::dynamic_image::RootPermit::workspace(
            &self.binding,
            caller,
            creator,
            thread,
        ))
    }
    pub fn token(&self) -> Token {
        self.binding.current.as_ref().unwrap().token
    }
    pub fn phase(&self) -> Phase {
        self.binding.phase
    }
    pub fn image(&self) -> &L {
        &self.image
    }
    pub fn initial_context(&self) -> Result<crate::user_context::UserContext, Error> {
        if self.binding.phase != Phase::Active {
            return Err(Error::Busy);
        }
        let info = self.image.information();
        let mut context = crate::user_context::UserContext::new(info.entry, info.stack).unwrap();
        if let Some(startup) = info.startup {
            context.registers[8] = startup.address;
            context.registers[9] = startup.bytes as u64;
        }
        Ok(context)
    }
    /// Serializes dispatch inhibition with complete branch revocation. A CPU
    /// already running must still return; the image stays owned while it does.
    pub fn revoke(
        &mut self,
        authority: &mut Authority,
        scheduler: &mut Scheduler,
        token: Token,
    ) -> Result<(), Error> {
        self.binding.matching(token)?;
        scheduler
            .inhibit_process(token.process)
            .map_err(|e| self.binding.fail(Error::Scheduler(e)))?;
        // Reborrow after the scheduler transition; no branch handle is exported.
        let current = self.binding.matching(token)?;
        authority
            .revoke_batch(token.branches, current.branches.handles())
            .map_err(|e| self.binding.fail(Error::Authority(e)))?;
        if self.binding.phase != Phase::RecoveryRequired {
            self.binding.phase = Phase::Revoking;
        }
        Ok(())
    }
    /// Return root ownership only after matching revocation and scheduler process
    /// retirement. This certifies metadata only: physical reclamation still needs
    /// the hardware boundary's CR3/CPU/reference quiescence proof. No replacement.
    #[allow(clippy::result_large_err)] // Pending teardown must return the sole active owner, never drop it.
    pub fn finish(
        mut self,
        scheduler: &Scheduler,
        token: Token,
    ) -> Result<(Bindings<'a>, L), Self> {
        if self.binding.matching(token).is_err()
            || self.binding.phase != Phase::Revoking
            || !scheduler.process_terminated(token.process)
        {
            return Err(self);
        }
        self.binding.phase = Phase::Revoked;
        Ok((self.binding, self.image))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap_manifest,
        capability::{Kind, Rights},
        scheduler::Limits,
    };
    use sha2::{Digest, Sha256};
    const BYTES: &[u8; 232] = include_bytes!("../fixtures/bootstrap-whole-object-v1.bin");
    fn manifest(bytes: &[u8]) -> Manifest<'_> {
        bootstrap_manifest::verify(bytes, Sha256::digest(bytes).into(), b"abc", [42; 32]).unwrap()
    }
    struct Fixture {
        a: Authority,
        s: Scheduler,
        custody: SpaceId,
        catalog: [CatalogEntry; 2],
        target: Target,
    }
    fn fixture(limits: Limits) -> Fixture {
        let mut a = Authority::new();
        let custody = a.create_space().unwrap();
        let branches = a.create_space().unwrap();
        let destination = a.create_space().unwrap();
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
        let memory = a
            .create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap();
        let endpoint = a
            .create_root(custody, Kind::Endpoint, common | Rights::SEND)
            .unwrap();
        let mut s = Scheduler::new();
        let job = s.create_job_with_limits(limits).unwrap();
        let process = s.create_held_process(job).unwrap();
        Fixture {
            a,
            s,
            custody,
            catalog: [
                CatalogEntry {
                    selector: 1,
                    root: memory,
                    kind: Kind::Memory,
                },
                CatalogEntry {
                    selector: 2,
                    root: endpoint,
                    kind: Kind::Endpoint,
                },
            ],
            target: Target {
                process,
                job,
                destination,
                branches,
            },
        }
    }
    struct ModelImage(crate::loaded_image::Information);
    // SAFETY: host-only model: metadata and unique ownership stand in for hardware;
    // no dispatch here executes machine instructions or dereferences a model root.
    #[allow(unsafe_code)]
    unsafe impl LoadedExecutable for ModelImage {
        fn information(&self) -> crate::loaded_image::Information {
            self.0
        }
    }
    fn static_manifest() -> Manifest<'static> {
        let bytes = include_bytes!("../fixtures/bootstrap-static-v1.bin");
        bootstrap_manifest::verify(
            bytes,
            Sha256::digest(bytes).into(),
            include_bytes!("../fixtures/bootstrap-static-v1.elf"),
            [42; 32],
        )
        .unwrap()
    }
    fn model(m: &Manifest<'_>, f: &mut Fixture) -> (ModelImage, ThreadId) {
        let image = crate::executable::Image::from_manifest(m).unwrap();
        let thread = f.s.create_thread(f.target.process).unwrap();
        f.s.charge_frames(f.target.job, image.required_frames())
            .unwrap();
        (
            ModelImage(crate::loaded_image::Information {
                process: f.target.process,
                manifest: m.digest(),
                entry: image.entry(),
                stack: image.stack_top(),
                root: 4096,
                frames: image.required_frames(),
                startup: None,
            }),
            thread,
        )
    }
    #[test]
    fn activation_owns_image_and_releases_only_the_matching_initial_process() {
        let m = static_manifest();
        let mut f = fixture(m.limits());
        let (image, thread) = model(&m, &mut f);
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        assert_eq!(f.s.dispatch(0), Ok(None));
        let active = b
            .activate(&f.a, &mut f.s, token, thread, image)
            .unwrap_or_else(|r| panic!("admission failed: {:?}", r.error));
        assert_eq!(active.phase(), Phase::Active);
        assert_eq!(active.token(), token);
        // A successfully admitted legacy Root is still not the V4-only
        // dynamic loader profile, regardless of its live source handles.
        assert!(matches!(
            active.dynamic_image_permit(&f.a, &f.s, f.target.destination, f.catalog[0].root,),
            Err(Error::Busy)
        ));
        assert_eq!(
            active.initial_context().unwrap().rip,
            active.image().0.entry
        );
        assert_eq!(
            active.initial_context().unwrap().rsp,
            active.image().0.stack
        );
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, thread);
        assert_eq!(f.s.dispatch(1), Ok(None));
    }
    #[test]
    fn bootstrap_bytes_bind_live_grants_identity_and_loaded_readonly_metadata() {
        for damage in 0..5 {
            let mut bytes = *include_bytes!("../fixtures/bootstrap-static-v1.bin");
            bytes[48..80].copy_from_slice(&ev_userspace_contract::ABI);
            let m = bootstrap_manifest::verify(
                &bytes,
                Sha256::digest(bytes).into(),
                include_bytes!("../fixtures/bootstrap-static-v1.elf"),
                ev_userspace_contract::ABI,
            )
            .unwrap();
            let mut f = fixture(m.limits());
            let (mut image, thread) = model(&m, &mut f);
            let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
            let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
            let mut stale = token;
            stale.number += 1;
            assert_eq!(b.bootstrap_record(stale), Err(Error::StaleToken));
            let record = b.bootstrap_record(token).unwrap().unwrap();
            let decoded = ev_userspace_contract::Bootstrap::parse(&record).unwrap();
            assert_eq!(
                (decoded.epoch(), decoded.incarnation(), decoded.process()),
                (7, 1, token.process().diagnostic_id())
            );
            for (i, g) in decoded.grants().enumerate() {
                assert_eq!(g.handle, b.grants(token).unwrap()[i].0);
                assert_eq!(g.rights, m.grants().nth(i).unwrap().rights.bits());
            }
            let mut startup = crate::loaded_image::Startup {
                address: b.executable(token).unwrap().bootstrap_page().unwrap(),
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            };
            match damage {
                0 => startup.address += 4096,
                1 => startup.bytes -= 1,
                2 => startup.digest[0] ^= 1,
                _ => (),
            }
            image.0.startup = (damage != 3).then_some(startup);
            let result = b.activate(&f.a, &mut f.s, token, thread, image);
            if damage == 4 {
                let active = result.unwrap_or_else(|r| panic!("{:?}", r.error));
                let context = active.initial_context().unwrap();
                assert_eq!(
                    (context.registers[8], context.registers[9]),
                    (startup.address, record.len() as u64)
                );
                assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, thread);
            } else {
                let rejected = match result {
                    Err(r) => r,
                    Ok(_) => panic!("corrupt bootstrap admitted"),
                };
                assert_eq!(rejected.error, Error::ImageMismatch);
                assert_eq!(f.s.dispatch(0), Ok(None));
            }
        }
    }
    #[test]
    fn stale_admission_returns_both_owners_and_can_retry_without_recreating_binding() {
        let m = static_manifest();
        let mut f = fixture(m.limits());
        let (image, thread) = model(&m, &mut f);
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let mut stale = token;
        stale.number += 1;
        let rejected = match b.activate(&f.a, &mut f.s, stale, thread, image) {
            Err(r) => r,
            Ok(_) => panic!("stale admission"),
        };
        assert_eq!(rejected.error, Error::StaleToken);
        assert_eq!(rejected.binding.phase(), Phase::Bound);
        assert_eq!(f.s.dispatch(0), Ok(None));
        assert!(
            rejected
                .binding
                .activate(&f.a, &mut f.s, token, thread, rejected.image)
                .is_ok()
        );
    }
    #[test]
    fn every_loaded_identity_field_is_checked_before_admission() {
        for field in 0..8 {
            let m = static_manifest();
            let mut f = fixture(m.limits());
            let (mut image, thread) = model(&m, &mut f);
            let peer_job = f.s.create_job().unwrap();
            let peer = f.s.create_held_process(peer_job).unwrap();
            match field {
                0 => image.0.process = peer,
                1 => image.0.manifest[0] ^= 1,
                2 => image.0.entry += 1,
                3 => image.0.stack -= 16,
                4 => image.0.root = 0,
                5 => image.0.root = 4097,
                6 => image.0.frames += 1,
                _ => image.0.root = 1 << 63,
            }
            let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
            let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
            let rejected = match b.activate(&f.a, &mut f.s, token, thread, image) {
                Err(r) => r,
                Ok(_) => panic!("bad image {field}"),
            };
            assert_eq!(rejected.error, Error::ImageMismatch);
            assert_eq!(rejected.binding.phase(), Phase::RecoveryRequired);
            assert_eq!(f.s.dispatch(0), Ok(None));
        }
    }
    #[test]
    fn authority_changes_after_loading_cannot_release_the_hold() {
        for change in 0..6 {
            let m = static_manifest();
            let mut f = fixture(m.limits());
            let (image, thread) = model(&m, &mut f);
            let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
            let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
            let grant = b.grants(token).unwrap()[0];
            match change {
                0 => f.a.revoke(f.custody, f.catalog[0].root).unwrap(),
                1 => f.a.close(f.target.destination, grant).unwrap(),
                2 => {
                    f.a.derive(
                        f.custody,
                        f.catalog[0].root,
                        f.target.destination,
                        Rights::READ,
                    )
                    .unwrap();
                }
                3 => {
                    f.a.close(f.target.destination, grant).unwrap();
                    f.a.derive(
                        f.custody,
                        f.catalog[0].root,
                        f.target.destination,
                        Rights::READ,
                    )
                    .unwrap();
                }
                4 => {
                    f.a.derive(
                        f.custody,
                        f.catalog[0].root,
                        f.target.branches,
                        Rights::READ,
                    )
                    .unwrap();
                }
                _ => {
                    f.a.close_space(f.target.branches).unwrap();
                }
            }
            let rejected = match b.activate(&f.a, &mut f.s, token, thread, image) {
                Err(r) => r,
                Ok(_) => panic!("changed authority {change}"),
            };
            assert!(matches!(rejected.error, Error::Binding(_)));
            assert_eq!(rejected.binding.phase(), Phase::RecoveryRequired);
            assert_eq!(f.s.dispatch(0), Ok(None));
        }
    }
    #[test]
    fn admission_requires_exact_frame_charge_and_one_matching_ready_thread() {
        for change in 0..5 {
            let m = static_manifest();
            let mut f = fixture(m.limits());
            let (image, mut thread) = model(&m, &mut f);
            let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
            let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
            match change {
                0 => f.s.release_frames(f.target.job, 1).unwrap(),
                1 => f.s.charge_frames(f.target.job, 1).unwrap(),
                2 => {
                    f.s.create_thread(f.target.process).unwrap();
                }
                3 => {
                    f.s.create_held_process(f.target.job).unwrap();
                }
                _ => {
                    let job = f.s.create_job().unwrap();
                    let process = f.s.create_held_process(job).unwrap();
                    thread = f.s.create_thread(process).unwrap();
                }
            }
            let rejected = match b.activate(&f.a, &mut f.s, token, thread, image) {
                Err(r) => r,
                Ok(_) => panic!("bad admission {change}"),
            };
            assert_eq!(
                rejected.error,
                Error::Scheduler(scheduler::Error::Admission)
            );
            assert_eq!(rejected.binding.phase(), Phase::Bound);
            assert_eq!(f.s.dispatch(0), Ok(None));
        }
    }
    #[test]
    fn revocation_blocks_future_dispatch_and_retains_image_until_process_termination() {
        let m = static_manifest();
        let mut f = fixture(m.limits());
        let (image, thread) = model(&m, &mut f);
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let h = b.grants(token).unwrap()[0];
        let mut active = b
            .activate(&f.a, &mut f.s, token, thread, image)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        f.s.dispatch(0).unwrap().unwrap();
        let mut stale = token;
        stale.number += 1;
        assert_eq!(
            active.revoke(&mut f.a, &mut f.s, stale),
            Err(Error::StaleToken)
        );
        assert_eq!(active.phase(), Phase::Active);
        assert!(
            f.a.authorize(f.target.destination, h, Kind::Memory, Rights::READ)
                .is_ok()
        );
        active = match active.finish(&f.s, token) {
            Err(owner) => owner,
            Ok(_) => panic!("active root released"),
        };
        active.revoke(&mut f.a, &mut f.s, token).unwrap();
        assert_eq!(active.phase(), Phase::Revoking);
        assert_eq!(active.initial_context().err(), Some(Error::Busy));
        assert_eq!(
            f.a.authorize(f.target.destination, h, Kind::Memory, Rights::READ)
                .err(),
            Some(capability::Error::Revoked)
        );
        assert!(
            f.a.authorize(f.custody, f.catalog[0].root, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert_eq!(
            f.s.terminate_process(f.target.process),
            Err(scheduler::Error::ProcessRunning)
        );
        active = match active.finish(&f.s, token) {
            Err(owner) => owner,
            Ok(_) => panic!("running root released"),
        };
        f.s.yield_cpu(0).unwrap();
        for cpu in 0..scheduler::MAX_CPUS {
            assert_eq!(f.s.dispatch(cpu), Ok(None));
        }
        assert_eq!(
            f.s.held_process_job(f.target.process),
            Err(scheduler::Error::NotHeld)
        );
        active = match active.finish(&f.s, token) {
            Err(owner) => owner,
            Ok(_) => panic!("unretired root released"),
        };
        active.revoke(&mut f.a, &mut f.s, token).unwrap();
        f.s.terminate_process(f.target.process).unwrap();
        let (mut b, image) = match active.finish(&f.s, token) {
            Ok(parts) => parts,
            Err(_) => panic!("retired image retained"),
        };
        assert_eq!(image.0.manifest, m.digest());
        assert_eq!(b.phase(), Phase::Revoked);
        assert_eq!(b.prepare(&mut f.a, &f.s, f.target), Err(Error::Busy));
    }
    #[test]
    fn damaged_active_branch_custody_inhibits_dispatch_and_latches_recovery() {
        let m = static_manifest();
        let mut f = fixture(m.limits());
        let (image, thread) = model(&m, &mut f);
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let mut active = b
            .activate(&f.a, &mut f.s, token, thread, image)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        f.a.close_space(f.target.branches).unwrap();
        assert_eq!(
            active.revoke(&mut f.a, &mut f.s, token),
            Err(Error::Authority(capability::Error::InvalidSpace))
        );
        assert_eq!(active.phase(), Phase::RecoveryRequired);
        assert_eq!(f.s.dispatch(0), Ok(None));
        f.s.terminate_process(f.target.process).unwrap();
        assert!(active.finish(&f.s, token).is_err());
    }
    #[test]
    fn measured_executable_plan_is_available_only_for_the_current_held_binding() {
        let bytes = include_bytes!("../fixtures/bootstrap-static-v1.bin");
        let image = include_bytes!("../fixtures/bootstrap-static-v1.elf");
        let m = bootstrap_manifest::verify(bytes, Sha256::digest(bytes).into(), image, [42; 32])
            .unwrap();
        let mut f = fixture(m.limits());
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let mut stale = token;
        stale.number += 1;
        assert_eq!(b.executable(stale).err(), Some(Error::StaleToken));
        let plan = b.executable(token).unwrap();
        assert_eq!(plan.manifest_digest(), m.digest());
        assert_eq!(plan.required_frames(), 9);
        assert_eq!(f.s.dispatch(0), Ok(None));
        assert_eq!(b.phase(), Phase::Bound);
        b.revoke(&mut f.a, token).unwrap();
        assert_eq!(b.executable(token).err(), Some(Error::Busy));
    }
    #[test]
    fn non_executable_measured_bytes_latch_recovery_and_keep_dispatch_held() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        f.s.create_thread(f.target.process).unwrap();
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let error = Error::Executable(crate::executable::Error::Header);
        assert_eq!(b.executable(token).err(), Some(error));
        assert_eq!(b.failure(), Some(error));
        assert_eq!(b.phase(), Phase::RecoveryRequired);
        assert_eq!(f.s.dispatch(0), Ok(None));
        b.revoke(&mut f.a, token).unwrap();
        assert_eq!(b.phase(), Phase::RecoveryRequired);
        assert_eq!(b.failure(), Some(error));
    }
    #[test]
    fn prepared_identity_matches_measured_objects_and_never_admits_execution() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        let thread = f.s.create_thread(f.target.process).unwrap();
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        assert_eq!(token.process(), f.target.process);
        assert_eq!(token.job(), f.target.job);
        assert_eq!(token.number(), 1);
        assert_eq!(token.manifest, m.digest());
        assert_eq!(token.authority, m.expected_authority_digest());
        assert_eq!(b.phase(), Phase::Bound);
        assert_eq!(b.prepare(&mut f.a, &f.s, f.target), Err(Error::Busy));
        for (i, g) in m.grants().enumerate() {
            assert!(
                f.a.authorize(
                    f.target.destination,
                    b.grants(token).unwrap()[i],
                    g.kind,
                    g.rights
                )
                .is_ok()
            );
        }
        for cpu in 0..scheduler::MAX_CPUS {
            assert_eq!(f.s.dispatch(cpu), Ok(None));
        }
        assert_eq!(f.s.state(thread), Ok(scheduler::State::Ready));
        b.revoke(&mut f.a, token).unwrap();
        b.revoke(&mut f.a, token).unwrap();
        assert_eq!(b.phase(), Phase::Revoked);
        assert_eq!(b.grants(token), Err(Error::Busy));
        // Revoked authority is not a quiescence certificate or replacement permit.
        assert_eq!(b.prepare(&mut f.a, &f.s, f.target), Err(Error::Busy));
    }
    #[test]
    fn every_token_component_is_checked_before_revocation() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        let other_job = f.s.create_job_with_limits(m.limits()).unwrap();
        let other_process = f.s.create_held_process(other_job).unwrap();
        let other_space = f.a.create_space().unwrap();
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let mut bad = [token; 8];
        bad[0].epoch = NonZeroU64::new(8).unwrap();
        bad[1].number += 1;
        bad[2].process = other_process;
        bad[3].job = other_job;
        bad[4].manifest[0] ^= 1;
        bad[5].authority[0] ^= 1;
        bad[6].destination = other_space;
        bad[7].branches = other_space;
        for stale in bad {
            assert_eq!(b.revoke(&mut f.a, stale), Err(Error::StaleToken));
            assert_eq!(b.grants(stale), Err(Error::StaleToken));
            assert_eq!(b.phase(), Phase::Bound);
            let h = b.grants(token).unwrap()[0];
            assert!(
                f.a.authorize(f.target.destination, h, Kind::Memory, Rights::READ)
                    .is_ok()
            );
        }
    }
    #[test]
    fn wrong_job_limits_unheld_and_terminated_targets_mint_nothing() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        let wrong_job = f.s.create_job().unwrap();
        let weak_process = f.s.create_held_process(wrong_job).unwrap();
        let unheld = f.s.create_process(f.target.job).unwrap();
        let dead = f.s.create_held_process(f.target.job).unwrap();
        f.s.terminate_process(dead).unwrap();
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        for (target, error) in [
            (
                Target {
                    job: wrong_job,
                    ..f.target
                },
                Error::WrongJob,
            ),
            (
                Target {
                    job: wrong_job,
                    process: weak_process,
                    ..f.target
                },
                Error::JobLimits,
            ),
            (
                Target {
                    process: unheld,
                    ..f.target
                },
                Error::Scheduler(scheduler::Error::NotHeld),
            ),
            (
                Target {
                    process: dead,
                    ..f.target
                },
                Error::Scheduler(scheduler::Error::Terminated),
            ),
        ] {
            assert_eq!(b.prepare(&mut f.a, &f.s, target), Err(error));
            assert_eq!(b.phase(), Phase::Empty);
            assert_eq!(b.sequence, 0);
        }
        assert!(b.prepare(&mut f.a, &f.s, f.target).is_ok());
    }
    #[test]
    fn bad_digest_latches_recovery_with_no_token_or_partial_grants() {
        let mut bytes = *BYTES;
        bytes[128] ^= 1;
        let m = manifest(&bytes);
        let mut f = fixture(m.limits());
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let error = Error::Binding(bootstrap_binding::Error::AuthorityDigest);
        assert_eq!(b.prepare(&mut f.a, &f.s, f.target), Err(error));
        assert_eq!(b.failure(), Some(error));
        assert!(b.current.is_none());
        assert_eq!(b.sequence, 1);
        assert_eq!(
            b.prepare(&mut f.a, &f.s, f.target),
            Err(Error::RecoveryRequired)
        );
        // Direct validator confirms the failed transaction left both tables empty.
        assert!(
            bootstrap_binding::install_scoped(
                &mut f.a,
                f.custody,
                f.target.branches,
                f.target.destination,
                &f.catalog,
                &manifest(BYTES)
            )
            .is_ok()
        );
        assert_eq!(b.phase(), Phase::RecoveryRequired);
    }
    #[test]
    fn incarnation_counter_exhaustion_is_latched_without_wrap_or_mint() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        b.sequence = u64::MAX;
        assert_eq!(
            b.prepare(&mut f.a, &f.s, f.target),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(b.sequence, u64::MAX);
        assert_eq!(b.failure(), Some(Error::SequenceExhausted));
        assert!(b.current.is_none());
        assert_eq!(
            b.prepare(&mut f.a, &f.s, f.target),
            Err(Error::RecoveryRequired)
        );
    }
    #[test]
    fn revocation_invalidates_user_grants_preserves_roots_and_keeps_branches_pinned() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        let handles = [b.grants(token).unwrap()[0], b.grants(token).unwrap()[1]];
        b.revoke(&mut f.a, token).unwrap();
        for (i, g) in m.grants().enumerate() {
            assert_eq!(
                f.a.authorize(f.target.destination, handles[i], g.kind, g.rights)
                    .err(),
                Some(capability::Error::Revoked)
            );
            assert!(
                f.a.authorize(f.custody, f.catalog[i].root, g.kind, g.rights)
                    .is_ok()
            );
        }
        f.a.close_space(f.target.destination).unwrap();
        assert_eq!(f.a.collect_lineage(), Ok(2));
        assert_eq!(f.a.collect_lineage(), Ok(0));
        assert_eq!(b.revoke(&mut f.a, token), Ok(()));
    }
    #[test]
    fn damaged_private_custody_latches_recovery_and_retains_original_failure() {
        let m = manifest(BYTES);
        let mut f = fixture(m.limits());
        let mut b = Bindings::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let token = b.prepare(&mut f.a, &f.s, f.target).unwrap();
        f.a.close_space(f.target.branches).unwrap();
        let error = Error::Authority(capability::Error::InvalidSpace);
        assert_eq!(b.revoke(&mut f.a, token), Err(error));
        assert_eq!(b.phase(), Phase::RecoveryRequired);
        assert_eq!(b.failure(), Some(error));
        assert_eq!(b.revoke(&mut f.a, token), Err(error));
        assert_eq!(
            b.prepare(&mut f.a, &f.s, f.target),
            Err(Error::RecoveryRequired)
        );
        assert_eq!(b.grants(token), Err(Error::Busy));
    }
}
