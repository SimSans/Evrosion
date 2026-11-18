//! Physical loading and finite CPL3 proof for the measured ELF fixture.
//! This standalone loader proof does not release a supervisor's admission hold.
use crate::user_space::PrivateUserRoot;
use core::{arch::asm, num::NonZeroU64, ops::Deref};
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
use ev_kernel::memory_object::{MappingLease, MemoryObject};
use ev_kernel::user::MAX_PRIVATE_PAGES;
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    capability::{Authority, Kind, Rights},
    executable::Image,
    incarnation::{Bindings, Error as IncarnationError, Phase, Target, Token},
    loaded_image::{Information, LoadedExecutable},
    mapping::ADDRESS_MASK,
    memory::{BootstrapFrames, FRAME_SIZE},
    scheduler::{ProcessId, Resource, Scheduler},
    user::UserTrap,
};
use sha2::{Digest, Sha256};

const ELF: &[u8; 8200] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
const MANIFEST: &[u8; 232] = include_bytes!("../fixtures/bootstrap-static-v1.bin");
const MEASURED: [u8; 32] = [
    0xcd, 0x6c, 0xca, 0xc5, 0x4e, 0xef, 0x77, 0x02, 0x63, 0x57, 0x03, 0xc2, 0xc4, 0x1f, 0xa4, 0x4d,
    0xe5, 0xcd, 0x4e, 0xd5, 0xb2, 0xb1, 0xfd, 0xbe, 0x0e, 0x46, 0xa7, 0x1a, 0x03, 0x03, 0x73, 0x34,
];

/// Opaque runtime ownership; future activation must consume/retain this root,
/// rather than accepting a caller assertion that some other memory was loaded.
pub(crate) type LoadedImage = PrivateLoadedImage<MAX_PRIVATE_PAGES>;
pub(crate) type LoadedRoot = PrivateLoadedRoot<MAX_PRIVATE_PAGES>;
#[cfg(all(feature = "test-m5-native", not(feature = "test-m6-network")))]
pub(crate) type NativeLoadedImage =
    PrivateLoadedImage<{ ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_PAGES }>;
#[cfg(all(feature = "test-m5-native", not(feature = "test-m6-network")))]
pub(crate) type NativeLoadedRoot =
    PrivateLoadedRoot<{ ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_PAGES }>;
#[cfg(feature = "test-m6-network")]
pub(crate) type NetworkLoadedImage =
    PrivateLoadedImage<{ ev_kernel::executable::ROOT_V4_MAX_PRIVATE_PAGES }>;
#[cfg(feature = "test-m6-network")]
pub(crate) type NetworkLoadedRoot =
    PrivateLoadedRoot<{ ev_kernel::executable::ROOT_V4_MAX_PRIVATE_PAGES }>;
pub(crate) struct PrivateLoadedImage<const N: usize> {
    pub(crate) root: PrivateLoadedRoot<N>,
    entry: u64,
    stack: u64,
    manifest: [u8; 32],
    startup: Option<ev_kernel::loaded_image::Startup>,
}
const _: () = {
    // V4 retains one additional move-only mapping ledger entry for Root505.
    // This metadata allowance is not a stack/quota increase: actual linked
    // Kernel call-chain admission still enforces the unchanged256KiB stack.
    let allowance = if cfg!(feature = "test-m6-network") {
        core::mem::size_of::<Option<(u64, ev_kernel::memory_object::MappingLease)>>()
    } else {
        0
    };
    assert!(core::mem::size_of::<LoadedImage>() <= 2048 + allowance);
    assert!(core::mem::size_of::<LoadedRoot>() <= 2048 + allowance);
};

/// Reusable controller slot. Empty is a tombstone with no backing, never an
/// executable root. Drop does not reclaim frames or invalidate mappings.
pub(crate) struct PrivateLoadedRoot<const N: usize> {
    backing: Option<PrivateUserRoot<N>>,
}

/// One explicit prebound NX buffer page; code, bootstrap and both guard pages
/// can never be selected through this narrow mapping API.
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
pub(crate) const PREBOUND_SHARED_PAGE: u64 = 508 * FRAME_SIZE;
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
pub(crate) const PREBOUND_CATALOGUE_PAGE: u64 = 507 * FRAME_SIZE;
#[cfg(any(feature = "test-m3-file", feature = "test-m4-desktop"))]
pub(crate) const PREBOUND_APPLICATION_PAGE: u64 = 507 * FRAME_SIZE;
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
pub(crate) enum SharedMapError {
    Empty,
    Active,
    Missing,
    Unavailable,
    Authority(ev_kernel::memory_object::Error),
}
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
impl core::fmt::Debug for SharedMapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Active => f.write_str("Active"),
            Self::Missing => f.write_str("Missing"),
            Self::Unavailable => f.write_str("Unavailable"),
            Self::Authority(error) => f.debug_tuple("Authority").field(error).finish(),
        }
    }
}
/// Rejection preserves the unique mapping claim. The caller must return it to
/// its Memory Object or retain it; dropping it cannot reclaim physical backing.
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
pub(crate) struct RejectedSharedMap {
    pub(crate) error: SharedMapError,
    pub(crate) lease: MappingLease,
}
impl<const N: usize> Deref for PrivateLoadedRoot<N> {
    type Target = PrivateUserRoot<N>;
    fn deref(&self) -> &PrivateUserRoot<N> {
        self.backing
            .as_ref()
            .expect("empty loaded root cannot execute")
    }
}
impl<const N: usize> PrivateLoadedRoot<N> {
    /// # Safety
    /// Exact stopped/held selected V5 owner and retained extent claims. No
    /// admitted ProcessLease permits an exclusive borrow of this root.
    #[cfg(feature = "test-m8-workspace")]
    pub(crate) unsafe fn workspace_leaf_inactive(
        &mut self,
        first: usize,
        pages: usize,
    ) -> Result<crate::user_space::WorkspaceLeaf<'_, N>, &'static str> {
        let root = self.backing.as_mut().ok_or("empty workspace root")?;
        // SAFETY: caller and narrow underlying guard share actual exclusion.
        unsafe { root.workspace_leaf_inactive(first, pages) }
    }
    /// # Safety
    /// Exact captured Root/controller/AP exclusion and retained dynamic PT owner.
    #[cfg(feature = "test-m6-network")]
    pub(crate) unsafe fn dynamic_leaf_captured(
        &self,
        table: &ev_kernel::memory::PhysicalFrame,
        controller: u64,
    ) -> Result<crate::user_space::DynamicLeaf<'_, N>, &'static str> {
        let root = self.backing.as_ref().ok_or("empty dynamic Root")?;
        // SAFETY: forwards actual captured/owned frame contract above.
        unsafe { root.dynamic_leaf_captured(table, controller) }
    }
    /// # Safety
    /// Same held/stopped/inactive root contract as the narrow UserRoot API.
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn surface_leaf_inactive(
        &mut self,
    ) -> Result<crate::user_space::SurfaceLeaf<'_, N>, &'static str> {
        let root = self.backing.as_mut().ok_or("empty loaded surface root")?;
        // SAFETY: forwarded actual CPU/root/quiescence ownership.
        unsafe { root.surface_leaf_inactive() }
    }
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) fn display_root_identity(&self) -> Option<(u64, u64)> {
        self.backing.as_ref().map(|root| (root.root(), root.base()))
    }
    /// # Safety
    /// Exact held/stopped/inactive actual root, fixed auxiliary surface only.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) unsafe fn surface_auxiliary_leaf_inactive(
        &mut self,
    ) -> Result<crate::user_space::SurfaceLeaf<'_, N>, &'static str> {
        let root = self
            .backing
            .as_mut()
            .ok_or("empty loaded auxiliary surface root")?;
        // SAFETY: same actual exclusive CPU/root ownership as the caller.
        unsafe { root.surface_auxiliary_leaf_inactive() }
    }
    /// # Safety
    /// Same actual held/stopped/inactive hardware contract as UserRoot's narrow
    /// display access. No generic mutable backing accessor is exposed.
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn display_directory_inactive(
        &mut self,
    ) -> Result<crate::user_space::DisplayDirectory<'_, N>, &'static str> {
        let root = self.backing.as_mut().ok_or("empty loaded display root")?;
        // SAFETY: forwarded exact physical/CPU exclusion from caller.
        unsafe { root.display_directory_inactive() }
    }
    /// # Safety
    /// Serialized BSP/IF0, AP parked, PCID off and controller root restored.
    /// This root is held before admission or was returned by Running::finish.
    /// The caller binds this exact initialized lease to the intended process's
    /// actual Registry domain/capability. Retain its Memory Object/backing until
    /// both processes stop and every lease is explicitly unmapped.
    ///
    /// No DerefMut or general page-table access is exposed. Running retains an
    /// exclusive LoadedImage borrow, so its shared image() accessor cannot call
    /// this method while the process is admitted.
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) unsafe fn map_shared_inactive(
        &mut self,
        authority: &Authority,
        object: &MemoryObject,
        lease: MappingLease,
    ) -> Result<(), RejectedSharedMap> {
        // SAFETY: forwards the same stopped/held root and retained object owner.
        unsafe { self.map_prebound_inactive(authority, object, lease, PREBOUND_SHARED_PAGE) }
    }
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    unsafe fn map_prebound_inactive(
        &mut self,
        authority: &Authority,
        object: &MemoryObject,
        lease: MappingLease,
        relative: u64,
    ) -> Result<(), RejectedSharedMap> {
        let Some(root) = self.backing.as_mut() else {
            return Err(RejectedSharedMap {
                error: SharedMapError::Empty,
                lease,
            });
        };
        let current: u64;
        // SAFETY: caller owns the privileged controller boundary at IF0.
        unsafe { asm!("mov {}, cr3", out(reg) current, options(nomem, nostack, preserves_flags)) };
        if current & ADDRESS_MASK == root.root() {
            return Err(RejectedSharedMap {
                error: SharedMapError::Active,
                lease,
            });
        }
        if let Err(error) = object.validate_mapping(authority, &lease) {
            return Err(RejectedSharedMap {
                error: SharedMapError::Authority(error),
                lease,
            });
        }
        // SAFETY: actual inactive root, live initialized object and exact fixed
        // page; UserRoot preflights occupancy/capacity before changing hardware.
        unsafe { root.map_shared(lease, relative) }.map_err(|lease| RejectedSharedMap {
            error: SharedMapError::Unavailable,
            lease,
        })
    }
    /// # Safety
    /// Same inactive ownership as map_shared_inactive; the separate initialized
    /// catalogue object stays retained through the client's actual stop/finish.
    /// No writable alias may mutate its published bytes during execution.
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) unsafe fn map_catalogue_inactive(
        &mut self,
        authority: &Authority,
        object: &MemoryObject,
        lease: MappingLease,
    ) -> Result<(), RejectedSharedMap> {
        if lease.writable()
            || self
                .backing
                .as_ref()
                .and_then(|root| root.shared_mapping(PREBOUND_SHARED_PAGE))
                .is_some_and(|old| object.owns_mapping(old))
        {
            return Err(RejectedSharedMap {
                error: SharedMapError::Unavailable,
                lease,
            });
        }
        // SAFETY: only fixed507, explicit readonly lease, distinct retained
        // object and identical physical inactive-root preflight below.
        unsafe { self.map_prebound_inactive(authority, object, lease, PREBOUND_CATALOGUE_PAGE) }
    }

    /// Bind the separate application buffer at507, leaving backend IO at508.
    /// This is a writable buffer lease, never authority to mutate the read-only
    /// generation catalogue or an admitted executable's backing.
    ///
    /// # Safety
    /// Same serialized held/stopped root as map_shared_inactive. Both actual
    /// Memory Object owners and every lease remain retained until all users of
    /// each page have stopped and their exact claims are explicitly returned.
    #[cfg(any(feature = "test-m3-file", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn map_application_inactive(
        &mut self,
        authority: &Authority,
        object: &MemoryObject,
        lease: MappingLease,
    ) -> Result<(), RejectedSharedMap> {
        if !lease.writable()
            || self
                .backing
                .as_ref()
                .and_then(|root| root.shared_mapping(PREBOUND_SHARED_PAGE))
                .is_some_and(|old| object.owns_mapping(old))
        {
            return Err(RejectedSharedMap {
                error: SharedMapError::Unavailable,
                lease,
            });
        }
        // SAFETY: separate retained initialized object, fixed507 only, actual
        // inactive-root/authority/occupancy checks preserve a refused lease.
        unsafe { self.map_prebound_inactive(authority, object, lease, PREBOUND_APPLICATION_PAGE) }
    }
    /// # Safety
    /// Actual held/stopped M6 Root, restored CR3, retained initialized AppFile
    /// object and lease. This is the existing Root-owned AppFile capability;
    /// its separate506 mapping never aliases System IO508 or catalogue507.
    #[cfg(feature = "test-m6-session")]
    pub(crate) unsafe fn map_session_note_inactive(
        &mut self,
        authority: &Authority,
        object: &MemoryObject,
        lease: MappingLease,
    ) -> Result<(), RejectedSharedMap> {
        if !lease.writable() {
            return Err(RejectedSharedMap {
                error: SharedMapError::Unavailable,
                lease,
            });
        }
        // SAFETY: caller supplies the existing inactive-root ownership guard.
        unsafe {
            self.map_prebound_inactive(
                authority,
                object,
                lease,
                ev_userspace_contract::root_v2::native::SESSION_NOTE_PAGE * FRAME_SIZE,
            )
        }
    }
    /// # Safety
    /// Held/stopped V4 Root; exact retained client-window claim, no active RPC.
    #[cfg(feature = "test-m6-network")]
    pub(crate) unsafe fn map_network_client_inactive(
        &mut self,
        a: &Authority,
        object: &MemoryObject,
        lease: MappingLease,
    ) -> Result<(), RejectedSharedMap> {
        if !lease.writable() {
            return Err(RejectedSharedMap {
                error: SharedMapError::Unavailable,
                lease,
            });
        }
        // SAFETY: same exact inactive-root lease discipline, fixed V4 page505.
        unsafe {
            self.map_prebound_inactive(
                a,
                object,
                lease,
                ev_userspace_contract::root_v4::ROOT_NET_CLIENT_PAGE * FRAME_SIZE,
            )
        }
    }
    #[cfg(feature = "test-m6-network")]
    pub(crate) fn validate_network_client(
        &self,
        a: &Authority,
        object: &MemoryObject,
    ) -> Result<(), SharedMapError> {
        let root = self.backing.as_ref().ok_or(SharedMapError::Empty)?;
        let lease = root
            .shared_mapping(ev_userspace_contract::root_v4::ROOT_NET_CLIENT_PAGE * FRAME_SIZE)
            .ok_or(SharedMapError::Missing)?;
        if !lease.writable() {
            return Err(SharedMapError::Unavailable);
        }
        object
            .validate_mapping(a, lease)
            .map_err(SharedMapError::Authority)
    }
    /// # Safety
    /// Actual stopped Root and quiesced client RPC; exact retained object.
    #[cfg(feature = "test-m6-network")]
    pub(crate) unsafe fn unmap_network_client_inactive(
        &mut self,
        object: &mut MemoryObject,
    ) -> Result<(), SharedMapError> {
        // SAFETY: the exact fixed505 mapping is no longer accessible by any CPU.
        unsafe {
            self.unmap_prebound_inactive(
                object,
                ev_userspace_contract::root_v4::ROOT_NET_CLIENT_PAGE * FRAME_SIZE,
            )
        }
    }
    #[cfg(feature = "test-m6-session")]
    pub(crate) fn validate_session_note(
        &self,
        authority: &Authority,
        object: &MemoryObject,
    ) -> Result<(), SharedMapError> {
        let root = self.backing.as_ref().ok_or(SharedMapError::Empty)?;
        let lease = root
            .shared_mapping(ev_userspace_contract::root_v2::native::SESSION_NOTE_PAGE * FRAME_SIZE)
            .ok_or(SharedMapError::Missing)?;
        if !lease.writable() {
            return Err(SharedMapError::Unavailable);
        }
        object
            .validate_mapping(authority, lease)
            .map_err(SharedMapError::Authority)
    }
    /// # Safety
    /// Exact stopped Root and quiesced App/File users; preserve the actual lease
    /// until this unmap returns it to the retained AppFile object owner.
    #[cfg(feature = "test-m6-session")]
    pub(crate) unsafe fn unmap_session_note_inactive(
        &mut self,
        object: &mut MemoryObject,
    ) -> Result<(), SharedMapError> {
        // SAFETY: the caller has retired every user of the exact fixed506 lease.
        unsafe {
            self.unmap_prebound_inactive(
                object,
                ev_userspace_contract::root_v2::native::SESSION_NOTE_PAGE * FRAME_SIZE,
            )
        }
    }

    #[cfg(any(feature = "test-m3-file", feature = "test-m4-desktop"))]
    pub(crate) fn validate_application(
        &self,
        authority: &Authority,
        object: &MemoryObject,
    ) -> Result<(), SharedMapError> {
        let root = self.backing.as_ref().ok_or(SharedMapError::Empty)?;
        let lease = root
            .shared_mapping(PREBOUND_APPLICATION_PAGE)
            .ok_or(SharedMapError::Missing)?;
        if !lease.writable() {
            return Err(SharedMapError::Unavailable);
        }
        object
            .validate_mapping(authority, lease)
            .map_err(SharedMapError::Authority)
    }

    /// # Safety
    /// Same actual stopped/held root and hardware quiescence as shared unmap;
    /// capability closure or revocation does not prevent returning this lease.
    #[cfg(any(feature = "test-m3-file", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn unmap_application_inactive(
        &mut self,
        object: &mut MemoryObject,
    ) -> Result<(), SharedMapError> {
        // SAFETY: fixed507 and exact retained application object owner.
        unsafe { self.unmap_prebound_inactive(object, PREBOUND_APPLICATION_PAGE) }
    }

    /// Read-only pre-admission/dispatch check. Failure requires stop/finish before
    /// unmapping; it is never permission to mutate admitted executable backing.
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) fn validate_shared(
        &self,
        authority: &Authority,
        object: &MemoryObject,
    ) -> Result<(), SharedMapError> {
        let root = self.backing.as_ref().ok_or(SharedMapError::Empty)?;
        let lease = root
            .shared_mapping(PREBOUND_SHARED_PAGE)
            .ok_or(SharedMapError::Missing)?;
        object
            .validate_mapping(authority, lease)
            .map_err(SharedMapError::Authority)
    }

    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) fn validate_catalogue(
        &self,
        authority: &Authority,
        object: &MemoryObject,
    ) -> Result<(), SharedMapError> {
        let root = self.backing.as_ref().ok_or(SharedMapError::Empty)?;
        let lease = root
            .shared_mapping(PREBOUND_CATALOGUE_PAGE)
            .ok_or(SharedMapError::Missing)?;
        if lease.writable() {
            return Err(SharedMapError::Unavailable);
        }
        object
            .validate_mapping(authority, lease)
            .map_err(SharedMapError::Authority)
    }

    /// # Safety
    /// Same stopped/inactive hardware boundary as map_shared_inactive.
    /// This root was never admitted, or every thread using it is terminated and
    /// Running::finish returned its exclusive lease. Revoked or closed
    /// capabilities do not prevent cleanup.
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) unsafe fn unmap_shared_inactive(
        &mut self,
        object: &mut MemoryObject,
    ) -> Result<(), SharedMapError> {
        // SAFETY: identical stopped/held mapping-lease return contract.
        unsafe { self.unmap_prebound_inactive(object, PREBOUND_SHARED_PAGE) }
    }
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    unsafe fn unmap_prebound_inactive(
        &mut self,
        object: &mut MemoryObject,
        relative: u64,
    ) -> Result<(), SharedMapError> {
        let root = self.backing.as_mut().ok_or(SharedMapError::Empty)?;
        let Some(lease) = root.shared_mapping(relative) else {
            return Err(SharedMapError::Missing);
        };
        if !object.owns_mapping(lease) {
            return Err(SharedMapError::Authority(
                ev_kernel::memory_object::Error::WrongObject,
            ));
        }
        let current: u64;
        // SAFETY: privileged readback before any PTE/lease transition.
        unsafe { asm!("mov {}, cr3", out(reg) current, options(nomem, nostack, preserves_flags)) };
        if current & ADDRESS_MASK == root.root() {
            return Err(SharedMapError::Active);
        }
        // SAFETY: all roots/CPUs are stopped, local nonglobal translations were
        // invalidated by CR3 restoration and the exact object's lease is owned.
        unsafe { root.unmap_shared(object) };
        Ok(())
    }
    /// # Safety
    /// Same actual stopped/held root and hardware quiescence as shared unmap.
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) unsafe fn unmap_catalogue_inactive(
        &mut self,
        object: &mut MemoryObject,
    ) -> Result<(), SharedMapError> {
        // SAFETY: fixed readonly507 and retained separate catalogue owner.
        unsafe { self.unmap_prebound_inactive(object, PREBOUND_CATALOGUE_PAGE) }
    }

    /// Tombstone metadata fails the ordinary activation gate's nonzero-root
    /// check. Operations needing actual backing still fail closed via Deref.
    pub(crate) fn root(&self) -> u64 {
        self.backing.as_ref().map_or(0, PrivateUserRoot::root)
    }
    /// # Safety
    /// Same hardware/process/reference quiescence as PrivateUserRoot::retire. No active
    /// ProcessImage lease may still retain this slot. Empty retirement is a no-op.
    pub(crate) unsafe fn retire_in_place(&mut self, frames: &mut BootstrapFrames) -> usize {
        let Some(root) = self.backing.take() else {
            return 0;
        };
        // SAFETY: caller independently proves all stopped-root preconditions.
        unsafe { root.retire(frames) }
    }
    /// # Safety
    /// Same retained hardware ownership and quiescence as retire_in_place.
    pub(crate) unsafe fn retire(mut self, frames: &mut BootstrapFrames) -> usize {
        // SAFETY: consuming compatibility API forwards the same preconditions.
        unsafe { self.retire_in_place(frames) }
    }
}
impl<const N: usize> PrivateLoadedImage<N> {
    /// # Safety
    /// Exact measured selected plan and typed record, actual held process,
    /// exclusive allocator/IF0/controller root/AP exclusion. External extent
    /// and Display owners must be installed/retained before admission.
    #[cfg(feature = "test-m8-workspace")]
    pub(crate) unsafe fn load_workspace(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        startup: ev_kernel::startup_record::Record<'_>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        use ev_kernel::executable::StartupLayout;
        if !matches!(
            image.startup_layout(),
            StartupLayout::ServiceV1 | StartupLayout::ServiceV5 | StartupLayout::RootV5
        ) {
            return Err("not selected startup layout");
        }
        startup
            .check_layout(image.startup_layout())
            .map_err(|_| "selected typed startup mismatch")?;
        // SAFETY: same initialized physical loader, exact parsed record/plan.
        let root = unsafe {
            PrivateUserRoot::load_private_record(
                offset,
                bits,
                original,
                image,
                Some(startup),
                frames,
            )?
        };
        Ok(Self {
            root: PrivateLoadedRoot {
                backing: Some(root),
            },
            entry: image.entry(),
            stack: image.stack_top(),
            manifest: image.manifest_digest(),
            startup: Some(ev_kernel::loaded_image::Startup {
                address: image.bootstrap_page().ok_or("selected startup page")?,
                bytes: startup.bytes().len(),
                digest: Sha256::digest(startup.bytes()).into(),
            }),
        })
    }
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) fn borrowed_information(&self, process: ProcessId, frames: u64) -> Information {
        Information {
            process,
            manifest: self.manifest,
            entry: self.entry,
            stack: self.stack,
            root: self
                .root
                .display_root_identity()
                .map_or(0, |(root, _)| root),
            frames,
            startup: self.startup,
        }
    }
    pub(crate) const fn empty() -> Self {
        Self {
            root: PrivateLoadedRoot { backing: None },
            entry: 0,
            stack: 0,
            manifest: [0; 32],
            startup: None,
        }
    }
    /// # Safety
    /// Serialized BSP, IF=0, retained direct map, original root live, AP parked.
    unsafe fn load(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        // SAFETY: forwards the same hardware ownership preconditions.
        unsafe { Self::load_startup(offset, bits, original, image, None, frames) }
    }
    /// # Safety
    /// Same hardware conditions as load; startup bytes belong to this held token.
    pub(crate) unsafe fn load_startup(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        startup: Option<&[u8; ev_userspace_contract::SIZE]>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        // SAFETY: caller preserves allocator, mappings and CPU exclusion through loading.
        let root =
            unsafe { PrivateUserRoot::load_image(offset, bits, original, image, startup, frames)? };
        Ok(Self {
            root: PrivateLoadedRoot {
                backing: Some(root),
            },
            entry: image.entry(),
            stack: image.stack_top(),
            manifest: image.manifest_digest(),
            startup: startup.map(|record| ev_kernel::loaded_image::Startup {
                address: image.bootstrap_page().unwrap(),
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            }),
        })
    }
    /// # Safety
    /// Same actual held image/allocator/CPU exclusion as load_startup. Only the
    /// matching sealed Root token may provide this validated RootV2 record.
    #[cfg(all(feature = "test-m4-desktop", not(feature = "test-m5-native")))]
    pub(crate) unsafe fn load_root_v2(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        startup: &[u8; ev_userspace_contract::root_v2::SIZE],
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        let startup_address = image.bootstrap_page().ok_or("missing RootV2 page")?;
        // SAFETY: named Root-only loader checks plan+version before allocating.
        let root = unsafe {
            PrivateUserRoot::load_root_v2(offset, bits, original, image, startup, frames)?
        };
        Ok(Self {
            root: PrivateLoadedRoot {
                backing: Some(root),
            },
            entry: image.entry(),
            stack: image.stack_top(),
            manifest: image.manifest_digest(),
            startup: Some(ev_kernel::loaded_image::Startup {
                address: startup_address,
                bytes: startup.len(),
                digest: Sha256::digest(startup).into(),
            }),
        })
    }
    /// # Safety
    /// Same actual held allocator/CPU ownership as load_root_v2, with the exact
    /// profile3 record. Bank claims must be installed by the outer native owner
    /// before it can produce an admitted LoadedExecutable lease.
    #[cfg(all(feature = "test-m5-native", not(feature = "test-m6-network")))]
    pub(crate) unsafe fn load_native_root(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        startup: &[u8; ev_userspace_contract::root_v2::native::SIZE],
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        let startup_address = image.bootstrap_page().ok_or("missing native Root page")?;
        // SAFETY: named native parser and same private backing loader.
        let root = unsafe {
            PrivateUserRoot::load_native_root(offset, bits, original, image, startup, frames)?
        };
        Ok(Self {
            root: PrivateLoadedRoot {
                backing: Some(root),
            },
            entry: image.entry(),
            stack: image.stack_top(),
            manifest: image.manifest_digest(),
            startup: Some(ev_kernel::loaded_image::Startup {
                address: startup_address,
                bytes: startup.len(),
                digest: Sha256::digest(startup).into(),
            }),
        })
    }
    /// # Safety
    /// Exact held V4 plan and startup, sole allocator and restored controller.
    #[cfg(feature = "test-m6-network")]
    pub(crate) unsafe fn load_root_v4(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        startup: &[u8; ev_userspace_contract::root_v4::SIZE],
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        let address = image.bootstrap_page().ok_or("missing RootV4 page")?;
        // SAFETY: named V4 parser retains exact initialized physical ownership.
        let root = unsafe {
            PrivateUserRoot::load_root_v4(offset, bits, original, image, startup, frames)?
        };
        Ok(Self {
            root: PrivateLoadedRoot {
                backing: Some(root),
            },
            entry: image.entry(),
            stack: image.stack_top(),
            manifest: image.manifest_digest(),
            startup: Some(ev_kernel::loaded_image::Startup {
                address,
                bytes: startup.len(),
                digest: Sha256::digest(startup).into(),
            }),
        })
    }
    /// # Safety
    /// Same initialized private backing as load_startup. This partial owner is
    /// NOT a loaded graphics executable: its wrapper must install and retain
    /// both declared PT frames/device lease before reporting Display layout.
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn load_graphics_private(
        offset: u64,
        bits: u8,
        original: u64,
        image: &Image<'_>,
        startup: Option<&[u8; ev_userspace_contract::SIZE]>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        if image.layout() != ev_kernel::executable::LayoutReservation::DisplayApertureV1 {
            return Err("not display layout");
        }
        // SAFETY: caller retains exact private root/frame initialization owner.
        let root = unsafe {
            PrivateUserRoot::load_private_backing(offset, bits, original, image, startup, frames)?
        };
        Ok(Self {
            root: PrivateLoadedRoot {
                backing: Some(root),
            },
            entry: image.entry(),
            stack: image.stack_top(),
            manifest: image.manifest_digest(),
            startup: startup.map(|record| ev_kernel::loaded_image::Startup {
                address: image.bootstrap_page().unwrap(),
                bytes: record.len(),
                digest: Sha256::digest(record).into(),
            }),
        })
    }
}

/// An exclusive lifetime lease retains the actual root in its controller slot
/// while portable activation owns the process-specific image binding. Moving a
/// lease never copies page tables or puts a large root into an error payload.
pub(crate) struct ProcessImage<'a> {
    pub(crate) loaded: &'a mut LoadedImage,
    pub(crate) process: ProcessId,
    pub(crate) frames: u64,
}
// SAFETY: LoadedImage::load_startup is the only constructor of nonempty backing: it owns all
// tables/frames, verifies exact initialized bytes and final permissions, and
// records immutable measured entry/stack/digest. This exclusive borrow prevents
// backing mutation or retirement throughout admission/execution. An empty
// controller tombstone reports root zero and cannot pass activation. Neither root
// nor lease Drop unmaps/recycles anything; explicit retirement below requires
// stopped scheduler threads, restored CR3, parked APs and no remaining leases.
unsafe impl LoadedExecutable for ProcessImage<'_> {
    fn information(&self) -> Information {
        Information {
            process: self.process,
            manifest: self.loaded.manifest,
            entry: self.loaded.entry,
            stack: self.loaded.stack,
            root: self.loaded.root.root(),
            frames: self.frames,
            startup: self.loaded.startup,
        }
    }
}

// A compiler-only negative against the REAL admission and backing types. The
// custom cfg is never a Cargo feature, so ordinary/all-features builds exclude
// this intentionally invalid function. The scoped check must fail with E0596 at
// the mapping call, proving shared access through Running cannot mutate backing.
#[cfg(all(
    ev_shared_active_mutation_probe,
    any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    )
))]
fn ev_shared_active_mutation_rejected(
    running: &mut ev_kernel::service::Running<ProcessImage<'_>>,
    authority: &Authority,
    object: &MemoryObject,
    lease: MappingLease,
) {
    // SAFETY: this function must never compile or execute; hardware refusal is
    // separately tested by the actual inactive-map boundary during boot.
    let _ = unsafe {
        running
            .image()
            .loaded
            .root
            .map_shared_inactive(authority, object, lease)
    };
}

/// # Safety
/// Same BSP/direct-map/user-boundary conditions as prove(). All controller-owned
/// roots stay retained until execution stops and the original root is restored.
pub unsafe fn prove_activation(offset: u64, frames: &mut BootstrapFrames) {
    let mut tombstone = LoadedImage::empty();
    assert_eq!(tombstone.root.root(), 0);
    let before = frames.remaining_frames();
    // SAFETY: empty metadata owns no backing; BSP/root quiescence also holds.
    unsafe { assert_eq!(tombstone.root.retire_in_place(frames), 0) };
    assert_eq!(frames.remaining_frames(), before);
    let stale = crate::bootstrap_proof::prepared_epoch(99, None);
    // SAFETY: sequential isolated fixtures retain exclusive ownership and IF=0.
    unsafe {
        activation_case(offset, frames, stale, false);
    }
    // SAFETY: the first case fully reclaimed its private frames before this one.
    unsafe {
        activation_case(offset, frames, stale, true);
    }
}

/// # Safety
/// Same as prove_activation; one isolated Authority/Scheduler and allocator owner.
unsafe fn activation_case(offset: u64, frames: &mut BootstrapFrames, stale: Token, deny: bool) {
    let manifest = bootstrap_manifest::verify(MANIFEST, MEASURED, ELF, [42; 32]).unwrap();
    let mut authority = Authority::new();
    let custody = authority.create_space().unwrap();
    let branches = authority.create_space().unwrap();
    let destination = authority.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let memory = authority
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let endpoint = authority
        .create_root(custody, Kind::Endpoint, common | Rights::SEND)
        .unwrap();
    let catalog = [
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
    ];
    let mut scheduler = Scheduler::new();
    let job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    let thread = scheduler.create_thread(process).unwrap();
    let target = Target {
        process,
        job,
        branches,
        destination,
    };
    let mut binding = Bindings::new(NonZeroU64::new(100).unwrap(), &manifest, custody, &catalog);
    let token = binding.prepare(&mut authority, &scheduler, target).unwrap();
    let user_grants = [
        binding.grants(token).unwrap()[0],
        binding.grants(token).unwrap()[1],
    ];
    let image = binding.executable(token).unwrap();
    scheduler
        .charge_frames(job, image.required_frames())
        .unwrap();
    let original: u64;
    // SAFETY: retained controller root read, no user/IRQ execution active.
    unsafe {
        asm!("mov {}, cr3",out(reg) original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    // SAFETY: immutable plan, exclusive allocator, inactive distinct root slot.
    let mut loaded =
        unsafe { LoadedImage::load(offset, bits, original & ADDRESS_MASK, &image, frames) }
            .unwrap();
    let lease = ProcessImage {
        loaded: &mut loaded,
        process,
        frames: image.required_frames(),
    };
    assert_eq!(scheduler.dispatch(0), Ok(None));
    let rejected = match binding.activate(&authority, &mut scheduler, stale, thread, lease) {
        Err(r) => r,
        Ok(_) => panic!("stale activation admitted"),
    };
    assert_eq!(rejected.error, IncarnationError::StaleToken);
    let binding = rejected.binding;
    let lease = rejected.image;
    assert_eq!(scheduler.dispatch(0), Ok(None));
    if deny {
        // This models authority disappearing after physical load but before the
        // admission commit. Revalidation must leave the actual thread held.
        authority.revoke(custody, memory).unwrap();
        let rejected = match binding.activate(&authority, &mut scheduler, token, thread, lease) {
            Err(r) => r,
            Ok(_) => panic!("revoked authority admitted"),
        };
        assert!(matches!(rejected.error, IncarnationError::Binding(_)));
        let mut binding = rejected.binding;
        assert_eq!(binding.phase(), Phase::RecoveryRequired);
        assert_eq!(scheduler.dispatch(0), Ok(None));
        binding.revoke(&mut authority, token).unwrap();
        scheduler.terminate_process(process).unwrap();
        // End the exclusive image lease only after its held process retires.
        let _lease = rejected.image;
    } else {
        let mut active = binding
            .activate(&authority, &mut scheduler, token, thread, lease)
            .unwrap_or_else(|r| panic!("activation failed: {:?}", r.error));
        assert_eq!(active.phase(), Phase::Active);
        assert_eq!(active.token(), token);
        let peer_job = scheduler.create_job().unwrap();
        let peer = scheduler.create_process(peer_job).unwrap();
        let peer_thread = scheduler.create_thread(peer).unwrap();
        let dispatch = scheduler.dispatch(0).unwrap().unwrap();
        assert_eq!(dispatch.process, token.process());
        assert_eq!(dispatch.thread, thread);
        let context = active.initial_context().unwrap();
        assert!(context.resumable());
        let traps = crate::traps::user_count();
        active.image().loaded.root.activate();
        let expected = UserTrap {
            vector: 6,
            error: 0,
            ip: context.rip + 40,
            address: 0,
            stack_top: context.rsp,
        };
        // SAFETY: the admitted immutable fixture, owned root and exact terminal
        // UD2 return to this controller; no nested entry or live user references.
        unsafe {
            crate::traps::run_user(context.rip, 0, 0, expected);
        }
        assert_eq!(crate::traps::user_count() - traps, 1);
        // SAFETY: finite CPL3 entry returned; switch to the retained controller
        // before any root retirement. Scheduler still records this running slot.
        unsafe {
            asm!("mov cr3, {}",in(reg) original,options(nostack,preserves_flags));
        }
        assert_eq!(
            active.revoke(&mut authority, &mut scheduler, stale),
            Err(IncarnationError::StaleToken)
        );
        active
            .revoke(&mut authority, &mut scheduler, token)
            .unwrap();
        assert_eq!(active.phase(), Phase::Revoking);
        scheduler.yield_cpu(0).unwrap();
        assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, peer_thread);
        scheduler.exit(0).unwrap();
        for cpu in 0..ev_kernel::scheduler::MAX_CPUS {
            assert_eq!(scheduler.dispatch(cpu), Ok(None));
        }
        for (i, g) in manifest.grants().enumerate() {
            assert_eq!(
                authority
                    .authorize(destination, user_grants[i], g.kind, g.rights)
                    .err(),
                Some(ev_kernel::capability::Error::Revoked)
            );
            assert!(
                authority
                    .authorize(custody, catalog[i].root, g.kind, g.rights)
                    .is_ok()
            );
        }
        scheduler.terminate_process(process).unwrap();
        let (mut binding, _lease) = match active.finish(&scheduler, token) {
            Ok(parts) => parts,
            Err(_) => panic!("retired activation kept running"),
        };
        assert_eq!(binding.phase(), Phase::Revoked);
        assert_eq!(
            binding.prepare(&mut authority, &scheduler, target),
            Err(IncarnationError::Busy)
        );
        scheduler.terminate_process(peer).unwrap();
    }
    // SAFETY: all image leases ended with their controller block; threads are
    // retired, original CR3 is current, AP parked, no mapping/backing aliases remain.
    unsafe {
        assert_eq!(
            loaded.root.retire_in_place(frames) as u64,
            image.required_frames()
        );
    }
    assert_eq!(loaded.root.root(), 0);
    // SAFETY: physical retirement completed; this controller slot is empty.
    unsafe { assert_eq!(loaded.root.retire_in_place(frames), 0) };
    scheduler
        .release_frames(job, image.required_frames())
        .unwrap();
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(scheduler.usage(job, resource), Ok(0));
    }
    assert_eq!(frames.remaining_frames(), before);
}

/// # Safety
/// BSP IF=0, AP parked, valid retained direct map; installed user trap boundary,
/// NX/WP enabled and PCID disabled. No process or competing allocator can run.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) {
    let manifest = bootstrap_manifest::verify(MANIFEST, MEASURED, ELF, [42; 32]).unwrap();
    let image = Image::from_manifest(&manifest).unwrap();
    let original: u64;
    // SAFETY: privileged read of the retained controller root.
    unsafe {
        asm!("mov {}, cr3",out(reg) original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let mut scheduler = Scheduler::new();
    let job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
    scheduler
        .charge_frames(job, image.required_frames())
        .unwrap();
    let before = frames.remaining_frames();
    let traps = crate::traps::user_count();
    // SAFETY: single owner satisfies load's hardware conditions.
    let loaded =
        unsafe { LoadedImage::load(offset, bits, original & ADDRESS_MASK, &image, frames) }
            .unwrap();
    assert_eq!(loaded.manifest, manifest.digest());
    assert_eq!(before - frames.remaining_frames(), image.required_frames());
    let after_load = frames.remaining_frames();
    // SAFETY: the newly loaded inactive root is retained and readable. Its user
    // slot is occupied, so conflict preflight must reject without allocating.
    let conflict = unsafe { LoadedImage::load(offset, bits, loaded.root.root(), &image, frames) };
    assert!(conflict.is_err());
    assert_eq!(frames.remaining_frames(), after_load);
    // The entry checks initial data, zero BSS, a BSS write/read and the NX stack.
    // Additional measured RX entry points test actual CPL3 hardware permissions.
    let cases = [
        (loaded.entry, 0, 6, 0, loaded.entry + 40),
        (loaded.entry + 128, loaded.entry, 14, 7, loaded.entry + 128),
        (
            loaded.entry + 144,
            image.base() + 3 * FRAME_SIZE,
            14,
            21,
            image.base() + 3 * FRAME_SIZE,
        ),
        (
            loaded.entry + 160,
            image.stack_page() - FRAME_SIZE,
            14,
            4,
            loaded.entry + 160,
        ),
        (
            loaded.entry + 144,
            image.stack_page(),
            14,
            21,
            image.stack_page(),
        ),
    ];
    for (entry, target, vector, error, ip) in cases {
        loaded.root.activate();
        let expected = UserTrap {
            vector,
            error,
            ip,
            address: target,
            stack_top: loaded.stack,
        };
        // SAFETY: exact finite measured fixture functions and terminal/fault IPs;
        // private mapped stack, IF=0, no nested entry and no live user references.
        unsafe {
            crate::traps::run_user(entry, target, 0x1234, expected);
        }
    }
    // SAFETY: all finite entries returned; switch away before reclaiming owned
    // frames. AP never used these tables, and CR3 invalidates local translations.
    unsafe {
        asm!("mov cr3, {}",in(reg) original,options(nostack,preserves_flags));
        assert_eq!(loaded.root.retire(frames) as u64, image.required_frames());
    }
    assert_eq!(crate::traps::user_count() - traps, 5);
    assert_eq!(frames.remaining_frames(), before);
    scheduler
        .release_frames(job, image.required_frames())
        .unwrap();
    assert_eq!(scheduler.usage(job, Resource::Frames), Ok(0));
}
