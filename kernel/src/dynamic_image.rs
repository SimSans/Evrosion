//! Bounded affine executable staging. Publisher/package policy remains in Root;
//! this mechanism retains actual charged RAM and removes mutable aliases before
//! any immutable byte view/descriptor can be used by the service registry.
#![allow(clippy::result_large_err)] // No allocator; failed transitions retain RAM/leases.
use crate::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    incarnation::{Bindings, Token},
    memory::{BootstrapFrames, FRAME_SIZE},
    memory_extent::{
        ExtentLease, InitializedRam, MemoryExtent, RamAccess, RetiredRam, UninitializedRam,
    },
    scheduler::{JobId, Scheduler},
};
use sha2::{Digest, Sha256};
pub const MAX_BYTES: usize = 64 * 4096;
pub const CHUNK_BYTES: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootIdentity {
    pub token: Token,
    pub domain: SpaceId,
    pub job: JobId,
}
pub struct RootPermit<'a, 'm> {
    binding: &'a Bindings<'m>,
    caller: SpaceId,
    creator: Handle,
    workspace: bool,
    #[cfg(feature = "workspace-authority")]
    thread: Option<crate::scheduler::ThreadId>,
}
impl<'a, 'm> RootPermit<'a, 'm> {
    pub(crate) fn new(binding: &'a Bindings<'m>, caller: SpaceId, creator: Handle) -> Self {
        Self {
            binding,
            caller,
            creator,
            workspace: false,
            #[cfg(feature = "workspace-authority")]
            thread: None,
        }
    }
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn workspace(
        binding: &'a Bindings<'m>,
        caller: SpaceId,
        creator: Handle,
        thread: crate::scheduler::ThreadId,
    ) -> Self {
        Self {
            binding,
            caller,
            creator,
            workspace: true,
            thread: Some(thread),
        }
    }
    pub(crate) fn is_workspace(&self) -> bool {
        self.workspace
    }
    pub(crate) fn check(&self, a: &Authority, s: &Scheduler) -> Result<RootIdentity, Error> {
        #[cfg(feature = "workspace-authority")]
        if self.workspace {
            return self
                .binding
                .check_workspace_dynamic_root(
                    a,
                    s,
                    self.caller,
                    self.creator,
                    self.thread.ok_or(Error::Phase)?,
                )
                .map_err(Error::Root);
        }
        self.binding
            .check_dynamic_root(a, s, self.caller, self.creator)
            .map_err(Error::Root)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Specification {
    pub bytes: usize,
    pub sha256: [u8; 32],
    pub elf_offset: usize,
    pub elf_bytes: usize,
    pub elf_sha256: [u8; 32],
    pub package: [u8; 32],
    pub abi: [u8; 32],
    pub descriptor: [u8; 32],
}
impl Specification {
    fn valid(self) -> bool {
        self.bytes > 0
            && self.bytes <= MAX_BYTES
            && self.elf_bytes > 0
            && self
                .elf_offset
                .checked_add(self.elf_bytes)
                .is_some_and(|end| end <= self.bytes)
            && [self.sha256, self.elf_sha256, self.package, self.descriptor]
                .iter()
                .all(|v| *v != [0; 32])
            && self.abi == ev_userspace_contract::ABI
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Root(crate::incarnation::Error),
    Authority(crate::capability::Error),
    Extent(crate::memory_extent::Error),
    Specification,
    Phase,
    Bounds,
    Deadline,
    Clock,
    Mapping,
    Access,
    Hash,
    Busy,
    Service(crate::service::Error),
}
impl From<crate::memory_extent::Error> for Error {
    fn from(e: crate::memory_extent::Error) -> Self {
        Self::Extent(e)
    }
}
impl From<crate::capability::Error> for Error {
    fn from(e: crate::capability::Error) -> Self {
        Self::Authority(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    object: usize,
    backing: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mapping {
    Unattached,
    Attaching,
    Attached,
    Detaching,
    Detached,
}
/// Actual HAL page-table operations. The implementation must validate captured
/// Root/CR3/IF0/AP ownership, exact physical pages/guards and readback. Failure
/// may have changed PTEs and MUST retain that actual hardware debt. No caller
/// boolean or revocation flag can substitute for removing every writable alias.
///
/// # Safety
/// install must map exactly the retained writer lease RW/NX in the selected V4
/// Root window. remove_writers must remove ALL writable aliases to these frames,
/// read back every PTE/guard and invalidate all relevant TLBs before Ok. It must
/// work for partial installation; no process may resume through unknown state.
#[allow(unsafe_code)]
pub unsafe trait Mappings {
    type Error;
    fn install(&mut self, extent: &MemoryExtent, lease: &ExtentLease) -> Result<(), Self::Error>;
    fn remove_writers(
        &mut self,
        extent: &MemoryExtent,
        lease: &ExtentLease,
    ) -> Result<(), Self::Error>;
}
/// Trusted immutable contiguous RAM view, not a cast of a user virtual pointer.
///
/// # Safety
/// bytes must return the exact retained allocator-owned contiguous frames at
/// the supplied physical address, with no fabricated/static lifetime, MMIO,
/// writable user alias or retained mutation path. The lifetime is bounded by
/// both the actual sealed owner and the captured hardware view.
#[allow(unsafe_code)]
pub unsafe trait ReadOnlyRam {
    type Error;
    fn bytes(&self, physical: u64, length: usize) -> Result<&[u8], Self::Error>;
}
#[must_use = "retain the actual writer/lease owner until sealed or explicitly aborted"]
pub struct Staging {
    extent: MemoryExtent,
    cap: Handle,
    custody: SpaceId,
    root: RootIdentity,
    writer: Option<Handle>,
    lease: Option<ExtentLease>,
    mapping: Mapping,
    spec: Specification,
    physical: u64,
    written: usize,
    cut: u64,
    last: u64,
    failed: bool,
}
// Allocation-free failure must retain every affine physical owner; boxing would
// require a heap and dropping the smaller variants would lose live resources.
#[allow(clippy::large_enum_variant)]
pub enum Retained {
    Uninitialized(UninitializedRam),
    Initialized(InitializedRam),
    Staging(Staging),
    Sealing(Sealing),
    Sealed(SealedImage),
    Retired(RetiredRam),
}
pub struct Rejected {
    pub error: Error,
    pub owner: Option<Retained>,
}
impl Staging {
    #[allow(clippy::too_many_arguments)] // Actual allocator/quota/authority/HAL owners are explicit.
    pub fn allocate<R: RamAccess>(
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
        ram: &mut R,
        permit: &RootPermit<'_, '_>,
        custody: SpaceId,
        spec: Specification,
        now: u64,
        cut: u64,
    ) -> Result<Self, Rejected> {
        let early = |error| Rejected { error, owner: None };
        let root = permit.check(a, s).map_err(early)?;
        if !spec.valid() {
            return Err(early(Error::Specification));
        }
        if now >= cut || cut == u64::MAX {
            return Err(early(Error::Deadline));
        }
        let ram = UninitializedRam::allocate(frames, s, root.job, spec.bytes.div_ceil(4096))
            .map_err(|r| Rejected {
                error: Error::Extent(r.error),
                owner: r.owner.map(Retained::Uninitialized),
            })?
            .initialize(ram)
            .map_err(|r| Rejected {
                error: Error::Access,
                owner: Some(Retained::Uninitialized(r.owner)),
            })?;
        let (extent, cap) =
            MemoryExtent::publish(a, custody, ram, frames, s).map_err(|r| Rejected {
                error: Error::Extent(r.error),
                owner: Some(Retained::Initialized(r.owner)),
            })?;
        let mut owner = Self {
            extent,
            cap,
            custody,
            root,
            writer: None,
            lease: None,
            mapping: Mapping::Unattached,
            spec,
            physical: 0,
            written: 0,
            cut,
            last: now,
            failed: false,
        };
        let result = (|| {
            owner.physical = owner.extent.contiguous()?;
            let writer = a.derive(
                custody,
                cap,
                root.domain,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )?;
            owner.writer = Some(writer);
            owner.lease = Some(owner.extent.map(a, root.domain, writer, true)?);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(owner),
            Err(error) => Err(Rejected {
                error,
                owner: Some(Retained::Staging(owner)),
            }),
        }
    }
    fn check(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Phase);
        }
        if permit.check(a, s)? != self.root {
            return Err(Error::Phase);
        }
        if now < self.last {
            self.failed = true;
            return Err(Error::Clock);
        }
        self.last = now;
        if now >= self.cut {
            self.failed = true;
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub fn writer(&self) -> Option<Handle> {
        self.writer
    }
    pub fn pages(&self) -> usize {
        self.extent.pages()
    }
    pub fn specification(&self) -> Specification {
        self.spec
    }
    pub fn attach<M: Mappings>(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
        maps: &mut M,
    ) -> Result<(), Error> {
        self.check(a, s, permit, now)?;
        if self.mapping != Mapping::Unattached {
            return Err(Error::Phase);
        }
        self.mapping = Mapping::Attaching;
        if maps
            .install(&self.extent, self.lease.as_ref().ok_or(Error::Phase)?)
            .is_err()
        {
            self.failed = true;
            return Err(Error::Mapping);
        }
        self.mapping = Mapping::Attached;
        Ok(())
    }
    /// Sequential progress only; it is never proof of bytes, hash or immutability.
    /// Full physical readback occurs only after all mutable aliases are detached.
    pub fn chunk_written(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
        offset: usize,
        length: usize,
    ) -> Result<(), Error> {
        self.check(a, s, permit, now)?;
        if self.mapping != Mapping::Attached {
            return Err(Error::Phase);
        }
        self.extent
            .validate(a, self.lease.as_ref().ok_or(Error::Phase)?)?;
        if offset != self.written
            || length == 0
            || length > CHUNK_BYTES
            || offset
                .checked_add(length)
                .is_none_or(|end| end > self.spec.bytes)
        {
            return Err(Error::Bounds);
        }
        self.written += length;
        Ok(())
    }
    pub fn seal<M: Mappings>(
        mut self,
        a: &mut Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
        maps: &mut M,
    ) -> Result<Sealing, Rejected> {
        let result = (|| {
            self.check(a, s, permit, now)?;
            if self.mapping != Mapping::Attached || self.written != self.spec.bytes {
                return Err(Error::Phase);
            }
            let writer = self.writer.ok_or(Error::Phase)?;
            a.authorize(
                self.root.domain,
                writer,
                Kind::Memory,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )?;
            // Preflight the SAME-slot handle replacement before changing hardware.
            let mut staged = a.staged_copy();
            staged.close(self.root.domain, writer)?;
            let readonly = staged.derive(
                self.custody,
                self.cap,
                self.root.domain,
                Rights::READ | Rights::MAP,
            )?;
            self.mapping = Mapping::Detaching;
            if maps
                .remove_writers(&self.extent, self.lease.as_ref().ok_or(Error::Phase)?)
                .is_err()
            {
                self.failed = true;
                return Err(Error::Mapping);
            }
            let lease = self.lease.take().ok_or(Error::Phase)?;
            if let Err((e, lease)) = self.extent.unmap(lease) {
                self.lease = Some(lease);
                self.failed = true;
                return Err(e.into());
            }
            self.mapping = Mapping::Detached;
            self.writer = Some(readonly);
            *a = staged;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Sealing {
                owner: self,
                read: 0,
                hash: Sha256::new(),
                elf_hash: Sha256::new(),
            }),
            Err(error) => Err(Rejected {
                error,
                owner: Some(Retained::Staging(self)),
            }),
        }
    }
    /// No automatic Drop. Even failed/partially attached owners need actual HAL
    /// removal, lease return, authority invalidation and scrub before frame reuse.
    pub fn abort<M: Mappings>(
        mut self,
        a: &mut Authority,
        maps: &mut M,
    ) -> Result<RetiredRam, Rejected> {
        let result = (|| {
            if let Some(lease) = self.lease.as_ref() {
                self.mapping = Mapping::Detaching;
                if maps.remove_writers(&self.extent, lease).is_err() {
                    return Err(Error::Mapping);
                }
            }
            if let Some(lease) = self.lease.take()
                && let Err((e, lease)) = self.extent.unmap(lease)
            {
                self.lease = Some(lease);
                return Err(e.into());
            }
            if let Some(handle) = self.writer {
                if a.is_live_space(self.root.domain) {
                    match a.close(self.root.domain, handle) {
                        Ok(()) | Err(crate::capability::Error::InvalidHandle) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                self.writer = None;
            }
            self.extent
                .destroy(a, self.custody, self.cap)
                .map_err(Error::Extent)
        })();
        match result {
            Ok(ram) => match a.close(self.custody, self.cap) {
                Ok(()) => Ok(ram),
                Err(error) => Err(Rejected {
                    error: Error::Authority(error),
                    owner: Some(Retained::Retired(ram)),
                }),
            },
            Err(error) => Err(Rejected {
                error,
                owner: Some(Retained::Staging(self)),
            }),
        }
    }
}
#[must_use = "retain the immutable RAM owner through readback or explicit cleanup"]
pub struct Sealing {
    owner: Staging,
    read: usize,
    hash: Sha256,
    elf_hash: Sha256,
}
impl Sealing {
    pub fn specification(&self) -> Specification {
        self.owner.spec
    }
    pub fn pages(&self) -> usize {
        self.owner.extent.pages()
    }
    /// Retained converted capability, for Kernel lifetime/close fencing only.
    pub fn root_handle(&self) -> Option<Handle> {
        self.owner.writer
    }
    pub fn remaining(&self) -> usize {
        self.owner.extent.pages() * 4096 - self.read
    }
    pub fn step<R: RamAccess>(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
        ram: &mut R,
    ) -> Result<(), Error> {
        self.owner.check(a, s, permit, now)?;
        if self.owner.mapping != Mapping::Detached {
            return Err(Error::Phase);
        }
        let n = self.remaining().min(CHUNK_BYTES);
        if n == 0 {
            return Ok(());
        }
        let mut bytes = [0; CHUNK_BYTES];
        self.owner.failed = true;
        self.owner
            .extent
            .read_owned(ram, self.read, &mut bytes[..n])
            .map_err(|_| Error::Access)?;
        let spec = self.owner.spec;
        let payload = n.min(spec.bytes.saturating_sub(self.read));
        if bytes[payload..n].iter().any(|byte| *byte != 0) {
            return Err(Error::Hash);
        }
        self.hash.update(&bytes[..payload]);
        let elf_start = self.read.max(spec.elf_offset);
        let elf_end = (self.read + n).min(spec.elf_offset + spec.elf_bytes);
        if elf_start < elf_end {
            self.elf_hash
                .update(&bytes[elf_start - self.read..elf_end - self.read]);
        }
        self.read += n;
        self.owner.failed = false;
        Ok(())
    }
    pub fn finish(
        mut self,
        a: &Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
    ) -> Result<SealedImage, Rejected> {
        if let Err(error) = self.owner.check(a, s, permit, now) {
            return Err(Rejected {
                error,
                owner: Some(Retained::Sealing(self)),
            });
        }
        let result = if self.owner.failed || self.remaining() != 0 {
            Err(Error::Phase)
        } else if <[u8; 32]>::from(self.hash.clone().finalize()) != self.owner.spec.sha256
            || <[u8; 32]>::from(self.elf_hash.clone().finalize()) != self.owner.spec.elf_sha256
        {
            self.owner.failed = true;
            Err(Error::Hash)
        } else {
            Ok(())
        };
        match result {
            Ok(()) => Ok(SealedImage {
                owner: self.owner,
                registered: false,
            }),
            Err(error) => Err(Rejected {
                error,
                owner: Some(Retained::Sealing(self)),
            }),
        }
    }
    pub fn abort<M: Mappings>(
        self,
        a: &mut Authority,
        maps: &mut M,
    ) -> Result<RetiredRam, Rejected> {
        self.owner.abort(a, maps)
    }
}
/// Affine immutable byte owner. There is no mutable extent accessor, unseal or
/// reinitialization API. Registration/lifecycle holds this exact stamp until
/// all held/running references and actual readonly mappings are retired.
#[must_use = "retain immutable code and Root readers through canonical retirement"]
pub struct SealedImage {
    owner: Staging,
    registered: bool,
}
impl SealedImage {
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn workspace_registration_fenced(&self) -> bool {
        self.owner.failed
    }
    /// New registration retains the upload's original cut and clock fence.
    /// Expiry never removes immutable bytes, readers, or a prior registration.
    /// The native caller supplies actual Kernel admission time, not a packet.
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn admit_workspace_registration(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
    ) -> Result<(), Error> {
        if self.registered {
            return Err(Error::Busy);
        }
        self.owner.check(a, s, permit, now)
    }
    /// Actual Registry pin state; diagnostics never change it.
    pub fn is_registered(&self) -> bool {
        self.registered
    }
    pub(crate) fn root(&self) -> RootIdentity {
        self.owner.root
    }
    pub(crate) fn registered(&self) -> bool {
        self.registered
    }
    pub(crate) fn pin(&mut self) {
        self.registered = true;
    }
    pub(crate) fn unpin(&mut self) {
        self.registered = false;
    }
    pub fn retire<M: Mappings>(
        self,
        a: &mut Authority,
        maps: &mut M,
    ) -> Result<RetiredRam, Rejected> {
        if self.registered || self.owner.extent.live_leases() != 0 {
            return Err(Rejected {
                error: Error::Busy,
                owner: Some(Retained::Sealed(self)),
            });
        }
        self.owner.abort(a, maps)
    }
    pub fn identity(&self) -> Identity {
        let (object, backing) = self
            .owner
            .extent
            .stamp()
            .expect("retained live sealed extent");
        Identity { object, backing }
    }
    pub fn root_handle(&self) -> Handle {
        self.owner.writer.expect("sealed readonly handle")
    }
    pub fn physical(&self) -> u64 {
        self.owner.physical
    }
    pub fn pages(&self) -> usize {
        self.owner.extent.pages()
    }
    pub fn specification(&self) -> Specification {
        self.owner.spec
    }
    /// Actual immutable package bytes, excluding physical tail padding. Root
    /// may borrow its Zion index/resources from this same retained owner; the
    /// borrow cannot outlive either the sealed RAM or the captured HAL view.
    pub fn bytes<'s, R: ReadOnlyRam>(&'s self, ram: &'s R) -> Result<&'s [u8], Error> {
        let bytes = ram
            .bytes(
                self.owner.physical,
                self.owner.extent.pages() * FRAME_SIZE as usize,
            )
            .map_err(|_| Error::Access)?;
        if bytes.len() != self.owner.extent.pages() * 4096 {
            return Err(Error::Access);
        }
        Ok(&bytes[..self.owner.spec.bytes])
    }
    pub fn elf<'s, R: ReadOnlyRam>(&'s self, ram: &'s R) -> Result<&'s [u8], Error> {
        let bytes = self.bytes(ram)?;
        Ok(&bytes
            [self.owner.spec.elf_offset..self.owner.spec.elf_offset + self.owner.spec.elf_bytes])
    }
    pub fn map_readonly(&mut self, a: &Authority) -> Result<ExtentLease, Error> {
        self.owner
            .extent
            .map(a, self.owner.root.domain, self.root_handle(), false)
            .map_err(Error::Extent)
    }
    pub fn return_readonly(&mut self, lease: ExtentLease) -> Result<(), (Error, ExtentLease)> {
        self.owner
            .extent
            .unmap(lease)
            .map_err(|(e, l)| (Error::Extent(e), l))
    }
    pub fn extent(&self) -> &MemoryExtent {
        &self.owner.extent
    }
}

#[cfg(test)]
mod tests;
