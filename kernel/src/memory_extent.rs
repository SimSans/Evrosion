//! Bounded owned RAM extents under one capability and move-only mapping claims.
//! One serialized Authority/Scheduler/allocator owner must survive all leases.
//! HAL implements RamAccess for real allocator-owned RAM; MMIO is a different
//! resource type and must never be cast into PhysicalFrame or this factory.
#![deny(unsafe_code)]
// Errors retain the bounded non-Clone RAM owner and its quota without requiring
// an allocator/Box before construction or cleanup has succeeded.
#![allow(clippy::result_large_err)]
use crate::{
    capability::{Authority, Error as CapError, Handle, Kind, Rights, SpaceId},
    memory::{BootstrapFrames, FRAME_SIZE, MAX_RECYCLED, PhysicalFrame},
    scheduler::{Error as SchedulerError, JobId, Resource, Scheduler},
};
use core::sync::atomic::{AtomicU64, Ordering};
pub const MAX_PAGES: usize = 64;
pub const MAX_LEASES: usize = 8;
static NEXT_BACKING: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Count,
    Capacity,
    Exhausted,
    WrongAllocator,
    MissingCharge,
    WrongObject,
    InvalidLease,
    Overflow,
    Busy,
    Destroyed,
    Authority(CapError),
    Scheduler(SchedulerError),
}
impl From<CapError> for Error {
    fn from(e: CapError) -> Self {
        Self::Authority(e)
    }
}
impl From<SchedulerError> for Error {
    fn from(e: SchedulerError) -> Self {
        Self::Scheduler(e)
    }
}
/// Trusted hardware boundary. Each operation must address this exact retained
/// RAM frame+byte, using the actual direct-map checks/volatile access in HAL.
/// No initialization assertion or user-controlled flag is accepted by the core.
/// Implementations must retain no hardware alias after returning.
///
/// # Safety
/// Access must target the exact allocator-owned RAM frame and checked byte,
/// preserving real readback/volatile semantics. Returning fabricated zeroes or
/// addressing unrelated RAM/MMIO would invalidate initialization/publication.
#[allow(unsafe_code)] // Contract declaration only; core performs no unsafe ops.
pub unsafe trait RamAccess {
    type Error;
    fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), Self::Error>;
    fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum InitError<E> {
    Access(E),
    Readback,
    Incomplete,
}
struct OwnedRam {
    frames: [Option<PhysicalFrame>; MAX_PAGES],
    pages: usize,
    job: JobId,
    charge: u64,
    backing: u64,
}
impl OwnedRam {
    fn count(&self) -> usize {
        self.frames.iter().flatten().count()
    }
    fn check(&self, a: &BootstrapFrames, s: &Scheduler) -> Result<(), Error> {
        if self.frames.iter().flatten().any(|frame| !a.owns(frame)) {
            return Err(Error::WrongAllocator);
        }
        if s.usage(self.job, Resource::Frames)? < self.charge {
            return Err(Error::MissingCharge);
        }
        Ok(())
    }
    fn initialize<R: RamAccess>(&self, access: &mut R) -> Result<(), InitError<R::Error>> {
        for frame in self.frames.iter().flatten() {
            for i in 0..FRAME_SIZE as usize {
                access.write(frame, i, 0).map_err(InitError::Access)?;
            }
            for i in 0..FRAME_SIZE as usize {
                if access.read(frame, i).map_err(InitError::Access)? != 0 {
                    return Err(InitError::Readback);
                }
            }
        }
        Ok(())
    }
}
#[must_use = "retain or explicitly release the RAM claims and quota"]
pub struct UninitializedRam(OwnedRam);
#[must_use = "publish, retain, or explicitly release the RAM claims and quota"]
pub struct InitializedRam(OwnedRam);
#[must_use = "reinitialize or explicitly release the retired RAM claims and quota"]
pub struct RetiredRam(OwnedRam);
pub struct AllocationRejected {
    pub error: Error,
    pub owner: Option<UninitializedRam>,
}
pub struct InitializationRejected<T, E> {
    pub error: InitError<E>,
    pub owner: T,
}
pub struct PublicationRejected {
    pub error: Error,
    pub owner: InitializedRam,
}
pub struct ReleaseRejected<T, E> {
    pub error: ReleaseError<E>,
    pub owner: T,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseError<E> {
    State(Error),
    Scrub(InitError<E>),
}
impl UninitializedRam {
    /// Reserves an explicit non-process owner Job quota. A process mapper is not
    /// silently charged again. Late refusal returns every frame and charge.
    pub fn allocate(
        a: &mut BootstrapFrames,
        s: &mut Scheduler,
        job: JobId,
        pages: usize,
    ) -> Result<Self, AllocationRejected> {
        let early = |error| AllocationRejected { error, owner: None };
        if !(1..=MAX_PAGES).contains(&pages) {
            return Err(early(Error::Count));
        }
        let reused = pages.min(MAX_RECYCLED - a.recycle_capacity()) as u64;
        if a.remaining_frames() < pages as u64 || a.reused_frames().checked_add(reused).is_none() {
            return Err(early(Error::Exhausted));
        }
        let backing = NEXT_BACKING
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| early(Error::Overflow))?;
        s.charge_frames(job, pages as u64)
            .map_err(|e| early(Error::Scheduler(e)))?;
        let mut owner = OwnedRam {
            frames: [const { None }; MAX_PAGES],
            pages,
            job,
            charge: pages as u64,
            backing,
        };
        for index in 0..pages {
            match a.allocate() {
                Ok(frame) => owner.frames[index] = Some(frame),
                Err(_) => {
                    return Err(AllocationRejected {
                        error: Error::Exhausted,
                        owner: Some(Self(owner)),
                    });
                }
            }
        }
        Ok(Self(owner))
    }
    pub fn pages(&self) -> usize {
        self.0.pages
    }
    pub fn initialize<R: RamAccess>(
        self,
        access: &mut R,
    ) -> Result<InitializedRam, InitializationRejected<Self, R::Error>> {
        if self.0.count() != self.0.pages {
            return Err(InitializationRejected {
                error: InitError::Incomplete,
                owner: self,
            });
        }
        match self.0.initialize(access) {
            Ok(()) => Ok(InitializedRam(self.0)),
            Err(error) => Err(InitializationRejected { error, owner: self }),
        }
    }
}
impl RetiredRam {
    /// A destroyed writable extent is not still zero-initialized. Re-publication
    /// requires actual byte initialization/readback again, or explicit release.
    pub fn initialize<R: RamAccess>(
        self,
        access: &mut R,
    ) -> Result<InitializedRam, InitializationRejected<Self, R::Error>> {
        match self.0.initialize(access) {
            Ok(()) => Ok(InitializedRam(self.0)),
            Err(error) => Err(InitializationRejected { error, owner: self }),
        }
    }
}
// This helper refuses before any reclaim if the real bootstrap return queue
// cannot accept the full owner. The return-queue bound remains unchanged.
fn release<R: RamAccess>(
    mut owner: OwnedRam,
    a: &mut BootstrapFrames,
    s: &mut Scheduler,
    access: &mut R,
) -> Result<(), (ReleaseError<R::Error>, OwnedRam)> {
    if let Err(error) = owner.check(a, s) {
        return Err((ReleaseError::State(error), owner));
    }
    if a.recycle_capacity() < owner.count() {
        return Err((ReleaseError::State(Error::Capacity), owner));
    }
    if let Err(error) = owner.initialize(access) {
        return Err((ReleaseError::Scrub(error), owner));
    }
    for slot in &mut owner.frames {
        if let Some(frame) = slot.take()
            && let Err((_error, frame)) = a.reclaim(frame)
        {
            *slot = Some(frame);
            return Err((ReleaseError::State(Error::Capacity), owner));
        }
    }
    if let Err(error) = s.release_frames(owner.job, owner.charge) {
        return Err((ReleaseError::State(Error::Scheduler(error)), owner));
    }
    Ok(())
}
macro_rules! release_owner {
    ($owner:ty) => {
        impl $owner {
            /// Hardware users/aliases must already be quiescent. Extent destruction
            /// provides the no-live-lease metadata gate, never a CPU/DMA fence.
            pub fn release<R: RamAccess>(
                self,
                a: &mut BootstrapFrames,
                s: &mut Scheduler,
                access: &mut R,
            ) -> Result<(), ReleaseRejected<Self, R::Error>> {
                release(self.0, a, s, access).map_err(|(error, owner)| ReleaseRejected {
                    error,
                    owner: Self(owner),
                })
            }
        }
    };
}
release_owner!(UninitializedRam);
release_owner!(InitializedRam);
release_owner!(RetiredRam);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeaseRecord {
    token: u64,
    backing: u64,
    pages: u8,
    writable: bool,
    owner: SpaceId,
    cap: Handle,
}
/// A single non-Clone/non-Copy claim for a full immutable frame set, not 64
/// independent mapping tokens. Physical addresses come only from the owner.
#[must_use = "the mapping claim must return only after hardware quiescence"]
#[derive(Debug)]
pub struct ExtentLease {
    object: usize,
    record: LeaseRecord,
}
impl ExtentLease {
    pub fn owner(&self) -> SpaceId {
        self.record.owner
    }
    pub fn pages(&self) -> usize {
        usize::from(self.record.pages)
    }
    pub fn writable(&self) -> bool {
        self.record.writable
    }
}
pub struct MemoryExtent {
    object: usize,
    owner: Option<OwnedRam>,
    leases: [Option<LeaseRecord>; MAX_LEASES],
    sequence: u64,
}
impl MemoryExtent {
    pub fn publish(
        a: &mut Authority,
        domain: SpaceId,
        ram: InitializedRam,
        allocator: &BootstrapFrames,
        scheduler: &Scheduler,
    ) -> Result<(Self, Handle), PublicationRejected> {
        let reject = |error, owner| PublicationRejected { error, owner };
        if let Err(error) = ram.0.check(allocator, scheduler) {
            return Err(reject(error, ram));
        }
        if !(1..=MAX_PAGES).contains(&ram.0.pages)
            || ram.0.count() != ram.0.pages
            || ram.0.charge != ram.0.pages as u64
        {
            return Err(reject(Error::Count, ram));
        }
        let rights = Rights::from_bits(487).unwrap();
        let cap = match a.create_root(domain, Kind::Memory, rights) {
            Ok(cap) => cap,
            Err(error) => return Err(reject(Error::Authority(error), ram)),
        };
        let object = a
            .authorize(domain, cap, Kind::Memory, Rights::CONTROL)
            .expect("fresh typed object")
            .identity();
        Ok((
            Self {
                object,
                owner: Some(ram.0),
                leases: [None; MAX_LEASES],
                sequence: 0,
            },
            cap,
        ))
    }
    fn authorize(
        &self,
        a: &Authority,
        domain: SpaceId,
        cap: Handle,
        rights: Rights,
    ) -> Result<(), Error> {
        if self.owner.is_none() {
            return Err(Error::Destroyed);
        }
        if a.authorize(domain, cap, Kind::Memory, rights)?.identity() != self.object {
            return Err(Error::WrongObject);
        }
        Ok(())
    }
    pub fn pages(&self) -> usize {
        self.owner.as_ref().map_or(0, |owner| owner.pages)
    }
    pub fn charged_job(&self) -> Result<JobId, Error> {
        Ok(self.owner.as_ref().ok_or(Error::Destroyed)?.job)
    }
    pub fn live_leases(&self) -> usize {
        self.leases.iter().flatten().count()
    }
    pub fn map(
        &mut self,
        a: &Authority,
        domain: SpaceId,
        cap: Handle,
        writable: bool,
    ) -> Result<ExtentLease, Error> {
        let mut rights = Rights::READ | Rights::MAP;
        if writable {
            rights = rights | Rights::WRITE;
        }
        self.authorize(a, domain, cap, rights)?;
        let slot = self
            .leases
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let token = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let owner = self.owner.as_ref().ok_or(Error::Destroyed)?;
        let record = LeaseRecord {
            token,
            backing: owner.backing,
            pages: owner.pages as u8,
            writable,
            owner: domain,
            cap,
        };
        self.leases[slot] = Some(record);
        self.sequence = token;
        Ok(ExtentLease {
            object: self.object,
            record,
        })
    }
    fn retained(&self, lease: &ExtentLease) -> Result<&OwnedRam, Error> {
        let owner = self.owner.as_ref().ok_or(Error::Destroyed)?;
        if lease.object != self.object
            || lease.record.backing != owner.backing
            || lease.pages() != owner.pages
        {
            return Err(Error::WrongObject);
        }
        if !self.leases.contains(&Some(lease.record)) {
            return Err(Error::InvalidLease);
        }
        Ok(owner)
    }
    pub fn validate(&self, a: &Authority, lease: &ExtentLease) -> Result<(), Error> {
        self.retained(lease)?;
        let mut rights = Rights::READ | Rights::MAP;
        if lease.writable() {
            rights = rights | Rights::WRITE;
        }
        self.authorize(a, lease.record.owner, lease.record.cap, rights)
    }
    /// Actual immutable frame identity for one retained whole-extent claim.
    /// This does not authorize installation: validate(authority, lease) again
    /// under the serialized hardware owner before publishing any new PTE.
    /// HAL must preflight every target PTE before writing any and retain the
    /// original lease with any partially attached owner until stopped cleanup.
    pub fn physical_pages<'a>(
        &'a self,
        lease: &ExtentLease,
    ) -> Result<impl Iterator<Item = u64> + 'a, Error> {
        let owner = self.retained(lease)?;
        Ok(owner.frames.iter().flatten().map(PhysicalFrame::start))
    }
    /// Cleanup uses the exact retained claim, even after authority revocation.
    /// The external hardware owner must first remove all PTEs and prove stop.
    pub fn unmap(&mut self, lease: ExtentLease) -> Result<(), (Error, ExtentLease)> {
        if let Err(error) = self.retained(&lease) {
            return Err((error, lease));
        }
        let slot = self
            .leases
            .iter()
            .position(|record| *record == Some(lease.record))
            .expect("retained record");
        self.leases[slot] = None;
        Ok(())
    }
    pub fn destroy(
        &mut self,
        a: &mut Authority,
        domain: SpaceId,
        cap: Handle,
    ) -> Result<RetiredRam, Error> {
        self.authorize(a, domain, cap, Rights::CONTROL)?;
        if self.leases.iter().any(Option::is_some) {
            return Err(Error::Busy);
        }
        a.destroy(domain, cap)?;
        Ok(RetiredRam(self.owner.take().ok_or(Error::Destroyed)?))
    }
}

#[cfg(test)]
mod tests;
