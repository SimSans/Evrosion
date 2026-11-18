//! Actual Root-only SystemIo claim; construction hook is separately integrated.
//! Parsing, IDs and checksums do not establish
//! the unsafe admission/sole-window preconditions. There is no app constructor.
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};
use ev_block_service::store_io::{DesktopEndpoint, Window};
use ev_store::{GenerationManifest, Sector};
use ev_userspace_contract::root_v5::{FullGraph, Role, resources};
use ev_workspace_root::app_data::{Access, Device, NamespaceResult, Owner, Region, Status};
mod session;
pub(super) use session::State;

const BASE: usize = 1usize << 39;
pub const WINDOW_PAGE: u64 = resources::ROOT_SYSTEM_IO_PAGE;
pub const WINDOW_BYTES: usize = 4096;
pub const SECTOR_WINDOW_BYTES: usize = 512;
const WINDOW_ADDRESS: usize = BASE + WINDOW_PAGE as usize * WINDOW_BYTES;
const STARTUP_ADDRESS: usize = BASE + resources::STARTUP_PAGE as usize * WINDOW_BYTES;
const _: () = assert!(WINDOW_PAGE == 508 && SECTOR_WINDOW_BYTES <= WINDOW_BYTES);
static CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    Record,
    Endpoint,
    AlreadyClaimed,
    Transport,
}

/// Descriptive source receipt only. Copying it grants no transport or window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub process: u64,
    pub incarnation: u64,
    pub boot_epoch: u64,
    pub system_io_handle: u64,
    pub system_block_handle: u64,
}

/// Private constructor and no Clone/Send/Sync. Its only bytes are the fixed
/// first512 of the already admitted one-page Root SystemIo508 mapping.
pub struct NativeWindow {
    _root_thread_only: PhantomData<*mut ()>,
}
impl Window for NativeWindow {
    fn load(&self, out: &mut Sector) {
        for (index, byte) in out.iter_mut().enumerate() {
            // SAFETY: the sole admitted Root claim retains the exact mapped
            // SystemIo page. Only a canonical completed actual Read calls load;
            // no shared reference escapes and index is bounded to512 bytes.
            *byte = unsafe { ((WINDOW_ADDRESS + index) as *const u8).read_volatile() };
        }
    }
    fn store(&self, bytes: &Sector) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: same retained exclusive Root508 owner, preflighted child
            // cut before publication and no Root event/reap pump while borrowed.
            unsafe { ((WINDOW_ADDRESS + index) as *mut u8).write_volatile(byte) };
        }
    }
}

/// Contains the only native window owner. It cannot be reset, reconstructed,
/// split, cloned or converted into a raw transport. Even Drop never clears the
/// process-once claim; uncertain kernel/device owners require real retirement.
pub struct NativeOwner {
    owner: Owner<DesktopEndpoint, NativeWindow>,
    source: Source,
}
impl NativeOwner {
    /// Claim the already mapped actual admitted Root source, without any Block
    /// I/O, formatting, namespace open, media probe or data permission claim.
    ///
    /// # Safety
    /// `bootstrap` must be the actual Kernel-admitted immutable V5 Root startup
    /// at509 in the current captured Root process, not a copied/parsed app record.
    /// `created_system_block` must be the held actual CREATE_ENDPOINT result for
    /// graph::Channel::SystemBlock, independently routed to profile5 Block's
    /// System receiver. The caller must retain that endpoint and the exclusive
    /// RW/NX SystemIo508 mapping for this owner's entire lifetime, with no old
    /// writer, raw alias, second wrapper, lifecycle/event pump or concurrent
    /// backing access. IDs and this parser do not prove any of these conditions.
    pub unsafe fn claim_from_admitted_root(
        bootstrap: &FullGraph<'_>,
        created_system_block: u64,
    ) -> Result<Self, ClaimError> {
        if bootstrap.bytes().as_ptr() as usize != STARTUP_ADDRESS {
            return Err(ClaimError::Record);
        }
        if matches!(created_system_block, 0 | u64::MAX)
            || bootstrap.grants().any(|g| g.handle == created_system_block)
        {
            return Err(ClaimError::Endpoint);
        }
        let wire = DesktopEndpoint::for_session_transactions(created_system_block)
            .ok_or(ClaimError::Endpoint)?;
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ClaimError::AlreadyClaimed)?;
        let context = bootstrap.context();
        let owner = Owner::new(
            wire,
            NativeWindow {
                _root_thread_only: PhantomData,
            },
        )
        .ok_or(ClaimError::Transport)?;
        Ok(Self {
            owner,
            source: Source {
                process: context.process,
                incarnation: context.incarnation,
                boot_epoch: context.epoch,
                system_io_handle: bootstrap.handle(Role::SystemIo),
                system_block_handle: created_system_block,
            },
        })
    }

    pub const fn source(&self) -> Source {
        self.source
    }
    pub const fn status(&self) -> Status {
        self.owner.status()
    }
    pub(super) fn development_allocate(
        &mut self,
        bytes: &[u8],
        contracts: &ev_workspace_root::requirements::PrivateDataContracts<'_>,
        approval: &ev_workspace_root::development::Approval,
        started: &mut bool,
        pending: &mut Option<ev_app_registry::Prepared>,
    ) -> Result<(), ev_workspace_root::development::storage::Failure> {
        ev_workspace_root::development::storage::allocate(
            &mut self.owner,
            bytes,
            contracts,
            approval,
            started,
            pending,
        )
    }
    pub(super) fn development_registry(
        &mut self,
        bytes: &[u8],
        contracts: &ev_workspace_root::requirements::PrivateDataContracts<'_>,
        approval: &ev_workspace_root::development::Approval,
        activate: bool,
        pending: &mut Option<ev_app_registry::Prepared>,
    ) -> Result<(), ev_workspace_root::development::storage::Failure> {
        ev_workspace_root::development::storage::registry(
            &mut self.owner,
            bytes,
            contracts,
            approval,
            activate,
            pending,
        )
    }
    #[allow(dead_code)] // Protected installer's independent blank preflight is pending.
    pub fn read_only(&mut self, region: Region) -> Device<'_, DesktopEndpoint, NativeWindow> {
        self.owner.read_only(region)
    }
    #[allow(dead_code)] // Explicit protected installer allocation is a separate consumer.
    pub fn read_write(&mut self, region: Region) -> Device<'_, DesktopEndpoint, NativeWindow> {
        self.owner.read_write(region)
    }
    pub fn open_app_data_checked(
        &mut self,
        allocation: ev_workspace_root::app_data::private_data::Allocation,
        access: Access,
        deadline: u64,
    ) -> ev_workspace_root::app_data::private_data::OpenResult<'_, DesktopEndpoint, NativeWindow>
    {
        self.owner
            .open_app_data_checked(allocation, access, deadline)
    }
    #[allow(dead_code)] // Explicit original-context installer maintenance only.
    pub fn open_mutable_namespace(
        &mut self,
        region: Region,
        access: Access,
        original_creation: &GenerationManifest,
        deadline: u64,
    ) -> NamespaceResult<'_, DesktopEndpoint, NativeWindow> {
        self.owner
            .open_mutable_namespace(region, access, original_creation, deadline)
    }
}
