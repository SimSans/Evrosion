//! Retained immutable package RAM. These are ordinary allocated RAM extents,
//! independently charged to their parent Job, never executable/device mappings.
use ev_kernel::{
    capability::{Authority, Handle, SpaceId},
    mapping::direct_address,
    memory::{BootstrapFrames, FRAME_SIZE, PhysicalFrame},
    memory_extent::{
        ExtentLease, InitializedRam, MemoryExtent, RamAccess, RetiredRam, UninitializedRam,
    },
    scheduler::{JobId, Scheduler},
};
use ev_userspace_contract::root_v2::native;
use sha2::{Digest, Sha256};

pub(crate) struct Ram {
    pub offset: u64,
    pub bits: u8,
}
impl Ram {
    fn pointer(&self, frame: &PhysicalFrame, byte: usize) -> Result<*mut u8, &'static str> {
        if byte >= FRAME_SIZE as usize {
            return Err("native package RAM byte bounds");
        }
        direct_address(self.offset, frame.start(), self.bits)
            .map_err(|_| "native package RAM direct map")?
            .checked_add(byte as u64)
            .map(|address| address as *mut u8)
            .ok_or("native package RAM address overflow")
    }
}
// SAFETY: access targets the checked byte of the exact retained allocator RAM
// claim, with volatile readback. No address/claim conversion exists for MMIO.
unsafe impl RamAccess for Ram {
    type Error = &'static str;
    fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), Self::Error> {
        // SAFETY: exact owned frame + bounded byte checked above.
        unsafe { self.pointer(frame, byte)?.write_volatile(value) };
        Ok(())
    }
    fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, Self::Error> {
        // SAFETY: exact owned frame + bounded byte checked above.
        Ok(unsafe { self.pointer(frame, byte)?.read_volatile() })
    }
}

pub(crate) enum Error {
    Description,
    Access(&'static str),
    Readback,
    Extent(ev_kernel::memory_extent::Error),
    Initialize,
    Release,
}
/// A failed stage returns every actual claim. Dropping it performs no cleanup;
/// the trusted controller must retain it or explicitly finish stopped teardown.
// No heap is available at this boundary. Failure variants retain bounded,
// move-only physical claims; indirection must not silently discard an owner.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Retained {
    Uninitialized(UninitializedRam),
    Initialized(InitializedRam),
    Published(PackageBank),
    Retired(RetiredRam),
}
pub(crate) struct Rejected {
    pub error: Error,
    pub owner: Option<Retained>,
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Access(error) => f.debug_tuple("Access").field(error).finish(),
            Self::Extent(error) => f.debug_tuple("Extent").field(error).finish(),
            Self::Description => f.write_str("Description"),
            Self::Readback => f.write_str("Readback"),
            Self::Initialize => f.write_str("Initialize"),
            Self::Release => f.write_str("Release"),
        }
    }
}
impl core::fmt::Debug for Retained {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uninitialized(owner) => f
                .debug_struct("Uninitialized")
                .field("pages", &owner.pages())
                .finish(),
            Self::Initialized(owner) => f
                .debug_struct("Initialized")
                .field("retained_claim_bytes", &core::mem::size_of_val(owner))
                .finish(),
            Self::Published(owner) => f
                .debug_struct("Published")
                .field("pages", &owner.pages())
                .field("bytes", &owner.bytes())
                .field("live_leases", &owner.extent().live_leases())
                .finish(),
            Self::Retired(owner) => f
                .debug_struct("Retired")
                .field("retained_claim_bytes", &core::mem::size_of_val(owner))
                .finish(),
        }
    }
}
impl core::fmt::Debug for Rejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rejected")
            .field("error", &self.error)
            .field("retained_owner", &self.owner)
            .finish()
    }
}

pub(crate) struct PackageBank {
    extent: MemoryExtent,
    cap: Handle,
    custody: SpaceId,
    bytes: usize,
    digest: [u8; 32],
    initializing: Option<ExtentLease>,
    sealed: bool,
}
impl PackageBank {
    /// # Safety
    /// Sole captured BSP/direct-map/allocator owner, IF0 and parked APs; no
    /// package user exists. Source bytes are the retained immutable build input.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub unsafe fn new(
        a: &mut Authority,
        s: &mut Scheduler,
        parent: JobId,
        custody: SpaceId,
        frames: &mut BootstrapFrames,
        ram: &mut Ram,
        bytes: &[u8],
        expected: [u8; 32],
    ) -> Result<Self, Rejected> {
        let Some(pages) = native::catalogue::package_pages(bytes.len() as u64) else {
            return Err(Rejected {
                error: Error::Description,
                owner: None,
            });
        };
        if <[u8; 32]>::from(Sha256::digest(bytes)) != expected {
            return Err(Rejected {
                error: Error::Description,
                owner: None,
            });
        }
        let owner = UninitializedRam::allocate(frames, s, parent, pages as usize).map_err(|r| {
            Rejected {
                error: Error::Extent(r.error),
                owner: r.owner.map(Retained::Uninitialized),
            }
        })?;
        let owner = owner.initialize(ram).map_err(|r| Rejected {
            error: Error::Initialize,
            owner: Some(Retained::Uninitialized(r.owner)),
        })?;
        let (extent, cap) =
            MemoryExtent::publish(a, custody, owner, frames, s).map_err(|r| Rejected {
                error: Error::Extent(r.error),
                owner: Some(Retained::Initialized(r.owner)),
            })?;
        let mut bank = Self {
            extent,
            cap,
            custody,
            bytes: bytes.len(),
            digest: expected,
            initializing: None,
            sealed: false,
        };
        // This sole temporary WRITE claim is never delegated to Root. The
        // measured Root grants contain READ|MAP|BRANCH only, and mapping below
        // refuses an unsealed bank even if the trusted source object exists.
        let writer = match bank.extent.map(a, custody, cap, true) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(Rejected {
                    error: Error::Extent(error),
                    owner: Some(Retained::Published(bank)),
                });
            }
        };
        bank.initializing = Some(writer);
        // SAFETY: source/custody owner is retained, no user mapping exists.
        if let Err(error) = unsafe { bank.copy_and_measure(a, ram, bytes) } {
            return Err(Rejected {
                error,
                owner: Some(Retained::Published(bank)),
            });
        }
        let lease = bank.initializing.take().unwrap();
        if let Err((error, lease)) = bank.extent.unmap(lease) {
            bank.initializing = Some(lease);
            return Err(Rejected {
                error: Error::Extent(error),
                owner: Some(Retained::Published(bank)),
            });
        }
        bank.sealed = true;
        Ok(bank)
    }
    /// # Safety
    /// Exact unique initialization WRITE lease; no user/alias can access bytes.
    unsafe fn copy_and_measure(
        &mut self,
        a: &Authority,
        ram: &Ram,
        source: &[u8],
    ) -> Result<(), Error> {
        let lease = self.initializing.as_ref().ok_or(Error::Description)?;
        self.extent.validate(a, lease).map_err(Error::Extent)?;
        let mut hash = Sha256::new();
        let mut index = 0usize;
        for physical in self.extent.physical_pages(lease).map_err(Error::Extent)? {
            let address = direct_address(ram.offset, physical, ram.bits)
                .map_err(|_| Error::Access("native package copy alias"))?;
            for byte in 0..FRAME_SIZE as usize {
                let value = source.get(index + byte).copied().unwrap_or(0);
                // SAFETY: exact retained writable package frame and bounded byte.
                unsafe { (address as *mut u8).add(byte).write_volatile(value) };
            }
            for byte in 0..FRAME_SIZE as usize {
                // SAFETY: same initialized RAM; truthful direct-map readback.
                let actual = unsafe { (address as *const u8).add(byte).read_volatile() };
                let expected = source.get(index + byte).copied().unwrap_or(0);
                if actual != expected {
                    return Err(Error::Readback);
                }
                if index + byte < source.len() {
                    hash.update([actual]);
                }
            }
            index += FRAME_SIZE as usize;
        }
        if index < source.len() || <[u8; 32]>::from(hash.finalize()) != self.digest {
            return Err(Error::Readback);
        }
        Ok(())
    }
    pub fn cap(&self) -> Handle {
        self.cap
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn pages(&self) -> usize {
        self.extent.pages()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn extent(&self) -> &MemoryExtent {
        &self.extent
    }
    pub fn map_readonly(
        &mut self,
        a: &Authority,
        domain: SpaceId,
        grant: Handle,
    ) -> Result<ExtentLease, Error> {
        if !self.sealed || self.initializing.is_some() {
            return Err(Error::Description);
        }
        self.extent
            .map(a, domain, grant, false)
            .map_err(Error::Extent)
    }
    pub fn return_lease(
        &mut self,
        lease: ExtentLease,
    ) -> Result<(), (ev_kernel::memory_extent::Error, ExtentLease)> {
        self.extent.unmap(lease)
    }
    /// # Safety
    /// Actual Root stopped, CR3 restored, every bank PTE removed and its exact
    /// lease returned; no CPU/AP/reference can read the bank during scrub/free.
    #[allow(clippy::result_large_err)]
    pub unsafe fn retire(
        mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
        ram: &mut Ram,
    ) -> Result<(), Rejected> {
        if let Some(lease) = self.initializing.take()
            && let Err((error, lease)) = self.extent.unmap(lease)
        {
            self.initializing = Some(lease);
            return Err(Rejected {
                error: Error::Extent(error),
                owner: Some(Retained::Published(self)),
            });
        }
        let owner = match self.extent.destroy(a, self.custody, self.cap) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(Rejected {
                    error: Error::Extent(error),
                    owner: Some(Retained::Published(self)),
                });
            }
        };
        if let Err(rejected) = owner.release(frames, s, ram) {
            return Err(Rejected {
                error: Error::Release,
                owner: Some(Retained::Retired(rejected.owner)),
            });
        }
        // The exact source is no longer usable and pins no physical backing.
        a.close(self.custody, self.cap).map_err(|error| Rejected {
            error: Error::Extent(error.into()),
            owner: None,
        })?;
        Ok(())
    }
}

/// Exactly the three additional retained source roots after the common18.
/// Partial construction still owns every successfully published bank/frame.
pub(crate) struct NativeBacking {
    pub app_b: Handle,
    pub bad_shell: Option<Handle>,
    banks: [Option<PackageBank>; 2],
    custody: SpaceId,
    parent: JobId,
    pub ram: Ram,
}
pub(crate) struct RejectedBacking {
    pub error: &'static str,
    pub owner: Option<NativeBacking>,
    pub partial: Option<Rejected>,
}
impl core::fmt::Debug for RejectedBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let banks = self.owner.as_ref().map(|owner| {
            owner
                .banks
                .iter()
                .filter_map(Option::as_ref)
                .map(PackageBank::pages)
                .sum::<usize>()
        });
        f.debug_struct("RejectedBacking")
            .field("error", &self.error)
            .field("retained_bank_pages", &banks)
            .field("partial", &self.partial)
            .finish()
    }
}

impl NativeBacking {
    /// # Safety
    /// Same sole boot factory as common18; no user entered. The catalogue and
    /// immutable package/image bytes remain retained through all root users.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub unsafe fn append(
        a: &mut Authority,
        s: &mut Scheduler,
        parent: JobId,
        custody: SpaceId,
        frames: &mut BootstrapFrames,
        offset: u64,
        bits: u8,
        catalogue: &native::catalogue::Catalogue<'_>,
        app_b: &[u8],
        app_b_sha: [u8; 32],
        bad_shell: &[u8],
        bad_shell_sha: [u8; 32],
        packages: [&[u8]; 2],
    ) -> Result<Self, RejectedBacking> {
        let early = |error| RejectedBacking {
            error,
            owner: None,
            partial: None,
        };
        if a.metadata_usage().3 != 18
            || a.slot_capacity(custody) != Ok(64)
            || catalogue.app_b().image != app_b_sha
            || <[u8; 32]>::from(Sha256::digest(app_b)) != app_b_sha
            || catalogue.bad_shell().image != bad_shell_sha
            || <[u8; 32]>::from(Sha256::digest(bad_shell)) != bad_shell_sha
            || packages[0].len() as u64 != catalogue.package_a_bytes()
            || packages[1].len() as u64 != catalogue.package_b_bytes()
            || <[u8; 32]>::from(Sha256::digest(packages[0])) != catalogue.package_a()
            || <[u8; 32]>::from(Sha256::digest(packages[1])) != catalogue.package_b()
        {
            return Err(early("native extra source description"));
        }
        let pages = native::catalogue::package_pages(catalogue.package_a_bytes()).unwrap()
            + native::catalogue::package_pages(catalogue.package_b_bytes()).unwrap();
        let used = s
            .usage(parent, ev_kernel::scheduler::Resource::Frames)
            .map_err(|_| early("native parent Job"))?;
        let limit = s
            .job_limits(parent)
            .map_err(|_| early("native parent limits"))?
            .limit(ev_kernel::scheduler::Resource::Frames);
        if frames.remaining_frames() < pages
            || used.checked_add(pages).is_none_or(|total| total > limit)
        {
            return Err(early("native bank quota/frames"));
        }
        let app_b = a
            .create_root(
                custody,
                ev_kernel::capability::Kind::Memory,
                ev_kernel::capability::Rights::from_bits(481).unwrap(),
            )
            .map_err(|_| early("native AppB source capacity"))?;
        let mut owner = Self {
            app_b,
            bad_shell: None,
            banks: [None, None],
            custody,
            parent,
            ram: Ram { offset, bits },
        };
        for (index, expected) in [catalogue.package_a(), catalogue.package_b()]
            .into_iter()
            .enumerate()
        {
            // SAFETY: actual immutable source data and sole trusted parent/RAM owner.
            match unsafe {
                PackageBank::new(
                    a,
                    s,
                    parent,
                    custody,
                    frames,
                    &mut owner.ram,
                    packages[index],
                    expected,
                )
            } {
                Ok(bank) => owner.banks[index] = Some(bank),
                Err(partial) => {
                    return Err(RejectedBacking {
                        error: "native bank construction",
                        owner: Some(owner),
                        partial: Some(partial),
                    });
                }
            }
        }
        owner.bad_shell = match a.create_root(
            custody,
            ev_kernel::capability::Kind::Memory,
            ev_kernel::capability::Rights::from_bits(481).unwrap(),
        ) {
            Ok(cap) => Some(cap),
            Err(_) => {
                return Err(RejectedBacking {
                    error: "native BadShell source capacity",
                    owner: Some(owner),
                    partial: None,
                });
            }
        };
        for (index, expected) in [catalogue.package_a(), catalogue.package_b()]
            .into_iter()
            .enumerate()
        {
            assert_eq!(owner.bank(index).digest(), expected);
            assert_eq!(owner.bank(index).bytes(), packages[index].len());
        }
        assert_eq!(
            s.usage(parent, ev_kernel::scheduler::Resource::Frames)
                .unwrap()
                - used,
            pages
        );
        Ok(owner)
    }
    pub fn sources(&self) -> [Handle; 4] {
        [
            self.app_b,
            self.bank(0).cap(),
            self.bank(1).cap(),
            self.bad_shell.expect("complete Native3 BadShell source"),
        ]
    }
    pub fn bank(&self, index: usize) -> &PackageBank {
        self.banks[index].as_ref().expect("complete native bank")
    }
    pub fn bank_mut(&mut self, index: usize) -> &mut PackageBank {
        self.banks[index].as_mut().expect("complete native bank")
    }
    pub fn pages(&self) -> [u64; 2] {
        [self.bank(0).pages() as u64, self.bank(1).pages() as u64]
    }
    /// # Safety
    /// Every Root stopped/detached and every bank lease returned. Captured
    /// controller owns the same allocator, authority, parent quota and direct map.
    #[allow(clippy::result_large_err)]
    pub unsafe fn retire(
        mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
    ) -> Result<(), RejectedBacking> {
        let before = s
            .usage(self.parent, ev_kernel::scheduler::Resource::Frames)
            .unwrap();
        let mut returned = 0;
        for index in 0..2 {
            let Some(bank) = self.banks[index].take() else {
                continue;
            };
            let pages = bank.pages() as u64;
            // SAFETY: explicit actual stopped/PTE/lease fence required by caller.
            if let Err(partial) = unsafe { bank.retire(a, s, frames, &mut self.ram) } {
                return Err(RejectedBacking {
                    error: "native bank retirement",
                    owner: Some(self),
                    partial: Some(partial),
                });
            }
            returned += pages;
        }
        assert_eq!(
            before
                - s.usage(self.parent, ev_kernel::scheduler::Resource::Frames)
                    .unwrap(),
            returned
        );
        if let Some(bad_shell) = self.bad_shell {
            if a.destroy(self.custody, bad_shell).is_err()
                || a.close(self.custody, bad_shell).is_err()
            {
                return Err(RejectedBacking {
                    error: "native BadShell source retirement",
                    owner: Some(self),
                    partial: None,
                });
            }
            self.bad_shell = None;
        }
        if a.destroy(self.custody, self.app_b).is_err()
            || a.close(self.custody, self.app_b).is_err()
        {
            return Err(RejectedBacking {
                error: "native AppB source retirement",
                owner: Some(self),
                partial: None,
            });
        }
        Ok(())
    }
}
