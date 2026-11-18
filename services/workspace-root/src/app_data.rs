//! One affine Root SystemIo owner, adapted from the established small native
//! storage core. This is transport ownership, not app enrollment or permission.
//!
//! The separate executable adapter claims the actual admitted Root only after
//! Block startup. No constructor performs I/O, allocation, open or recovery.

use ev_block_service::store_io::{Window, Wire};
use ev_store::{GenerationManifest, RejectedDevice, Sector, SectorIo, Store};
use ev_userspace_contract::block::{Request, Response};

pub mod descriptor;
pub mod private_data;
pub mod session;

/// Closed Root-owned namespaces. A packet cannot select a raw wire sector or
/// opt into SessionNote, legacy File, network storage or the workspace extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    System,
    Registry,
    AppData,
    GrantPolicy,
    ExternalRegistry,
    ExternalAppData,
}
impl Region {
    pub const fn wire_sector(self, local: u64) -> Option<u32> {
        match self {
            Self::System => ev_store::native::Region::System.wire_sector(local),
            Self::Registry => ev_store::native::Region::AppRegistry.wire_sector(local),
            Self::AppData => ev_store::native::Region::AppData.wire_sector(local),
            Self::GrantPolicy => ev_store::native::Region::GrantPolicy.wire_sector(local),
            Self::ExternalRegistry => {
                ev_block_service::workspace::ExternalRegion::Registry.wire_sector(local)
            }
            Self::ExternalAppData => {
                ev_block_service::workspace::ExternalRegion::PrivateData.wire_sector(local)
            }
        }
    }
    pub const fn physical_start(self) -> u32 {
        match self {
            Self::System => ev_store::native::Region::System.physical_start(),
            Self::Registry => ev_store::native::Region::AppRegistry.physical_start(),
            Self::AppData => ev_store::native::Region::AppData.physical_start(),
            Self::GrantPolicy => ev_store::native::Region::GrantPolicy.physical_start(),
            Self::ExternalRegistry => ev_block_service::workspace::EXTERNAL_REGISTRY_START,
            Self::ExternalAppData => ev_block_service::workspace::EXTERNAL_DATA_START,
        }
    }
}

/// Local trusted-owner policy only. Neither variant is an app capability or
/// consent/enrollment proof. Opening a new mutable region requires separate
/// original-creation and allocation checks in the actual Root controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedReason {
    Transport,
    Decode,
    Reply,
    Counter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready,
    /// The sole window/transport is being used; no event pump may reenter it.
    InFlight,
    /// The last call may have executed. Retain ownership across ALL regions.
    Retained(RetainedReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub sequence: u64,
    pub request: Request,
    pub original_deadline: u64,
    pub child_deadline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub attempts: u64,
    pub completed_mutations: u64,
    pub last: Option<Attempt>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Bounds,
    Deadline,
    ReadOnly,
    Retained,
    Counter,
    Transport(E),
    Decode,
    Reply,
}

/// A trusted constructor consumes exactly one transport and window. It does
/// not publish bytes, call Block, format, open or recover any namespace. Native
/// code can construct its non-cloneable private window only through the once
/// admitted Root claim. There is no reset, raw backend, `into_parts` or escape.
///
/// A live region or Store prevents every other region borrow:
///
/// ```compile_fail
/// use ev_workspace_root::app_data::{Owner, Region};
/// use ev_block_service::store_io::{Window, Wire};
/// use ev_store::SectorIo;
/// fn overlapping<T: Wire, W: Window>(owner: &mut Owner<T, W>) {
///     let mut first = owner.read_only(Region::AppData);
///     let _second = owner.read_only(Region::Registry);
///     let _ = first.read(0, &mut [0; 512], 100);
/// }
/// ```
///
/// Ownership is not duplicated by cloning:
///
/// ```compile_fail
/// use ev_workspace_root::app_data::Owner;
/// fn duplicate<T, W>(owner: &Owner<T, W>) -> Owner<T, W> { owner.clone() }
/// ```
pub struct Owner<T, W> {
    wire: T,
    window: W,
    status: Status,
}
/// An open namespace keeps the same exclusive region borrow on either result.
pub type NamespaceResult<'a, T, W> =
    Result<Store<Device<'a, T, W>>, RejectedDevice<Device<'a, T, W>>>;
impl<T: Wire, W: Window> Owner<T, W> {
    /// The transport must implement fresh bounded session cuts. The native
    /// concrete DesktopEndpoint independently clamps each actual RPC to1024
    /// ticks under the caller's unchanged original aggregate cut (max8192).
    pub fn new(wire: T, window: W) -> Option<Self> {
        wire.supports_session().then_some(Self {
            wire,
            window,
            status: Status {
                phase: Phase::Ready,
                attempts: 0,
                completed_mutations: 0,
                last: None,
            },
        })
    }

    pub const fn status(&self) -> Status {
        self.status
    }

    pub fn read_only(&mut self, region: Region) -> Device<'_, T, W> {
        self.device(region, Access::ReadOnly)
    }

    pub fn read_write(&mut self, region: Region) -> Device<'_, T, W> {
        self.device(region, Access::ReadWrite)
    }

    fn device(&mut self, region: Region, access: Access) -> Device<'_, T, W> {
        Device {
            owner: self,
            region,
            access,
        }
    }

    /// The original namespace descriptor is supplied by independently retained
    /// trusted policy, not read from the media or recomputed from a new app.
    /// This check precedes generic Store recovery writes. It does NOT validate
    /// a matching-creation pending AppDataEnvelope's AppId before generic replay;
    /// callers for private data must instead use open_app_data_checked.
    pub fn open_mutable_namespace(
        &mut self,
        region: Region,
        access: Access,
        original_creation: &GenerationManifest,
        deadline: u64,
    ) -> NamespaceResult<'_, T, W> {
        Store::open_mutable_namespace(self.device(region, access), original_creation, deadline)
    }

    /// Trusted single-allocation reference path. Neither the descriptor nor
    /// AppId authorizes a caller; actual enrollment/capability policy precedes
    /// this exclusive Root borrow. No raw region escapes through the wrapper.
    pub fn open_app_data_checked(
        &mut self,
        allocation: private_data::Allocation,
        access: Access,
        deadline: u64,
    ) -> private_data::OpenResult<'_, T, W> {
        private_data::open(
            self.device(Region::ExternalAppData, access),
            allocation,
            deadline,
        )
    }

    fn ready(&self) -> Result<(), Error<T::Error>> {
        if self.status.phase != Phase::Ready {
            Err(Error::Retained)
        } else {
            Ok(())
        }
    }

    fn preflight(&self, original: u64) -> Result<u64, Error<T::Error>> {
        self.ready()?;
        if matches!(original, 0 | u64::MAX) {
            return Err(Error::Deadline);
        }
        let child = self
            .wire
            .capture_session_deadline(original)
            .filter(|child| !matches!(*child, 0 | u64::MAX) && *child <= original)
            .ok_or(Error::Deadline)?;
        Ok(child)
    }

    fn prepare(
        &mut self,
        request: Request,
        original: u64,
        child: u64,
    ) -> Result<(), Error<T::Error>> {
        let sequence = self
            .status
            .attempts
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Counter)?;
        self.status.attempts = sequence;
        self.status.last = Some(Attempt {
            sequence,
            request,
            original_deadline: original,
            child_deadline: child,
        });
        self.status.phase = Phase::InFlight;
        Ok(())
    }

    fn request(&mut self, request: Request, child: u64) -> Result<(), Error<T::Error>> {
        // No event/lifecycle pump runs while this exclusive synchronous borrow
        // owns the shared window. Every unknown/error is globally retained;
        // even a transport preaccept error is conservatively not reconstructed.
        let reply = self.wire.call(request.encode(), child).map_err(|error| {
            self.status.phase = Phase::Retained(RetainedReason::Transport);
            Error::Transport(error)
        })?;
        let response = Response::decode(&reply).map_err(|_| {
            self.status.phase = Phase::Retained(RetainedReason::Decode);
            Error::Decode
        })?;
        if response != request.success() {
            self.status.phase = Phase::Retained(RetainedReason::Reply);
            return Err(Error::Reply);
        }
        if matches!(request, Request::Write { .. } | Request::Flush) {
            self.status.completed_mutations = self
                .status
                .completed_mutations
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
                .ok_or_else(|| {
                    self.status.phase = Phase::Retained(RetainedReason::Counter);
                    Error::Counter
                })?;
        }
        self.status.phase = Phase::Ready;
        Ok(())
    }
}

/// The only SectorIo implementation is a bounded exclusive region borrow.
/// Device drop does not clear global retained state or prove hardware drain.
pub struct Device<'a, T, W> {
    owner: &'a mut Owner<T, W>,
    region: Region,
    access: Access,
}
impl<T: Wire, W: Window> Device<'_, T, W> {
    fn sector(&self, local: u64) -> Result<u32, Error<T::Error>> {
        self.region.wire_sector(local).ok_or(Error::Bounds)
    }
    fn writable(&self) -> Result<(), Error<T::Error>> {
        self.owner.ready()?;
        if self.access == Access::ReadWrite {
            Ok(())
        } else {
            Err(Error::ReadOnly)
        }
    }
}
impl<T: Wire, W: Window> SectorIo for Device<'_, T, W> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, local: u64, out: &mut Sector, original: u64) -> Result<(), Self::Error> {
        self.owner.ready()?;
        let sector = self.sector(local)?;
        let child = self.owner.preflight(original)?;
        let request = Request::Read { sector };
        self.owner.prepare(request, original, child)?;
        self.owner.request(request, child)?;
        self.owner.window.load(out);
        Ok(())
    }
    fn write(&mut self, local: u64, bytes: &Sector, original: u64) -> Result<(), Self::Error> {
        self.writable()?;
        let sector = self.sector(local)?;
        let child = self.owner.preflight(original)?;
        let request = Request::Write { sector };
        self.owner.prepare(request, original, child)?;
        self.owner.window.store(bytes);
        self.owner.request(request, child)
    }
    fn flush(&mut self, original: u64) -> Result<(), Self::Error> {
        self.writable()?;
        let child = self.owner.preflight(original)?;
        self.owner.prepare(Request::Flush, original, child)?;
        self.owner.request(Request::Flush, child)
    }
}

#[cfg(test)]
mod tests;
