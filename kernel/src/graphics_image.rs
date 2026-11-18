//! Retained RAM surface and optional non-RAM GOP backing for measured services.
//! Private fields prevent retiring an inner LoadedImage while a surface/device
//! receipt remains. No Drop performs unmapping or returns any physical frame.
use crate::{
    display_runtime::{DisplayAperture, OwnedDisplayTables, RetiredDisplayTables},
    executable_runtime::{LoadedImage, LoadedRoot},
};
use ev_kernel::{
    capability::Authority,
    display::DisplayObject,
    executable::{Image, LayoutReservation},
    loaded_image::{Information, LoadedExecutable},
    mapping::{ADDRESS_MASK, NO_EXECUTE, PRESENT, WRITABLE},
    memory::BootstrapFrames,
    memory_extent::{Error as ExtentError, ExtentLease, MemoryExtent},
    scheduler::{Resource, Scheduler, State},
    service::Metadata,
    surface_layout::{PAGES, Window},
    user::USER,
};
const AD: u64 = (1 << 5) | (1 << 6);

pub(crate) enum Error {
    Phase,
    Layout,
    Binding,
    Guard,
    Occupied,
    Readback,
    LiveClaims,
    Missing,
    #[cfg(feature = "test-m4-desktop")]
    Scalar(crate::executable_runtime::SharedMapError),
    Root(&'static str),
    Extent(ExtentError),
    Display(crate::display_runtime::Error),
}
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "test-m4-desktop")]
            Self::Scalar(error) => f.debug_tuple("Scalar").field(error).finish(),
            Self::Root(error) => f.debug_tuple("Root").field(error).finish(),
            Self::Extent(error) => f.debug_tuple("Extent").field(error).finish(),
            Self::Display(error) => f.debug_tuple("Display").field(error).finish(),
            Self::Phase => f.write_str("Phase"),
            Self::Layout => f.write_str("Layout"),
            Self::Binding => f.write_str("Binding"),
            Self::Guard => f.write_str("Guard"),
            Self::Occupied => f.write_str("Occupied"),
            Self::Readback => f.write_str("Readback"),
            Self::LiveClaims => f.write_str("LiveClaims"),
            Self::Missing => f.write_str("Missing"),
        }
    }
}
impl From<ExtentError> for Error {
    fn from(error: ExtentError) -> Self {
        Self::Extent(error)
    }
}
#[derive(Clone, Copy)]
struct Binding {
    root: u64,
    base: u64,
    table: u64,
    installed: bool,
}
struct SurfaceMapping {
    lease: ExtentLease,
    window: Window,
    binding: Option<Binding>,
}
impl SurfaceMapping {
    fn new(lease: ExtentLease, window: Window) -> Self {
        Self {
            lease,
            window,
            binding: None,
        }
    }
    /// # Safety
    /// Actual held process/private root, controller CR3/IF0/AP exclusion; owner
    /// and initialized extent are retained through later stopped detachment.
    unsafe fn install(
        &mut self,
        root: &mut LoadedRoot,
        a: &Authority,
        extent: &MemoryExtent,
        metadata: Metadata,
    ) -> Result<(), Error> {
        if self.binding.is_some() {
            return Err(Error::Phase);
        }
        if self.lease.pages() != PAGES || self.lease.owner() != metadata.domain {
            return Err(Error::Binding);
        }
        extent.validate(a, &self.lease)?;
        // SAFETY: narrow guard checks actual CR3/IF/PCID/LA57 and retains the
        // unique root borrow; it exposes only the fixed 63 PTEs plus two guards.
        let mut leaf = unsafe { surface_leaf(root, self.window) }.map_err(Error::Root)?;
        for index in self.window.lower_guard()..=self.window.upper_guard() {
            if leaf.entry(index).map_err(Error::Root)? != 0 {
                return Err(Error::Occupied);
            }
        }
        let mut count = 0;
        for physical in extent.physical_pages(&self.lease)? {
            if physical == 0 || physical & !ADDRESS_MASK != 0 {
                return Err(Error::Binding);
            }
            count += 1;
        }
        if count != PAGES {
            return Err(Error::Binding);
        }
        // Record ownership BEFORE the first write. An unexpected hardware
        // readback failure retains an attaching owner which cannot be admitted.
        self.binding = Some(Binding {
            root: leaf.root(),
            base: leaf.base(),
            table: leaf.physical(),
            installed: false,
        });
        for (index, physical) in extent.physical_pages(&self.lease)?.enumerate() {
            let entry = expected(physical, self.lease.writable());
            // SAFETY: all entries/guards and exact immutable frame identities
            // preflighted before publication; fixed indices384..446 only.
            unsafe { leaf.write(self.window.first() + index, entry) }.map_err(Error::Root)?;
        }
        for (index, physical) in extent.physical_pages(&self.lease)?.enumerate() {
            if leaf
                .entry(self.window.first() + index)
                .map_err(Error::Root)?
                != expected(physical, self.lease.writable())
            {
                return Err(Error::Readback);
            }
        }
        if leaf.entry(self.window.lower_guard()).map_err(Error::Root)? != 0
            || leaf.entry(self.window.upper_guard()).map_err(Error::Root)? != 0
        {
            return Err(Error::Guard);
        }
        self.binding.as_mut().unwrap().installed = true;
        Ok(())
    }
    /// # Safety
    /// Running.finish returned this exclusive image. All actual process threads
    /// terminated, original CR3 restored, APs quiescent and no global user PTEs.
    unsafe fn detach(
        &mut self,
        root: &mut LoadedRoot,
        s: &Scheduler,
        metadata: Metadata,
        extent: &MemoryExtent,
    ) -> Result<(), Error> {
        let Some(binding) = self.binding else {
            return Ok(());
        };
        if !stopped(s, metadata) {
            return Err(Error::Binding);
        }
        // Retained identity/token is checked without reauthorizing revoked
        // public grants. Correct cleanup must remain possible after stop.
        let _ = extent.physical_pages(&self.lease)?;
        // SAFETY: actual stopped owner and controller-root exclusion above.
        let mut leaf = unsafe { surface_leaf(root, self.window) }.map_err(Error::Root)?;
        if (leaf.root(), leaf.base(), leaf.physical())
            != (binding.root, binding.base, binding.table)
        {
            return Err(Error::Binding);
        }
        if leaf.entry(self.window.lower_guard()).map_err(Error::Root)? != 0
            || leaf.entry(self.window.upper_guard()).map_err(Error::Root)? != 0
        {
            return Err(Error::Guard);
        }
        for (index, physical) in extent.physical_pages(&self.lease)?.enumerate() {
            let actual = leaf
                .entry(self.window.first() + index)
                .map_err(Error::Root)?
                & !AD;
            if actual != expected(physical, self.lease.writable())
                && (binding.installed || actual != 0)
            {
                return Err(Error::Readback);
            }
        }
        for index in self.window.first()..self.window.first() + PAGES {
            // SAFETY: exact retained63-page receipt and fully stopped/inactive
            // actual root; local translations were removed by CR3 restoration.
            unsafe { leaf.write(index, 0) }.map_err(Error::Root)?;
        }
        for index in self.window.lower_guard()..=self.window.upper_guard() {
            if leaf.entry(index).map_err(Error::Root)? != 0 {
                return Err(Error::Readback);
            }
        }
        self.binding = None;
        Ok(())
    }
    fn installed_on(&self, root: u64) -> bool {
        self.binding.is_some_and(|b| b.installed && b.root == root)
    }
}
/// # Safety
/// Same actual held/stopped/inactive root ownership as each named HAL method.
unsafe fn surface_leaf(
    root: &mut LoadedRoot,
    window: Window,
) -> Result<crate::user_space::SurfaceLeaf<'_>, &'static str> {
    match window {
        // SAFETY: forwards the same actual exclusive inactive-root contract.
        Window::Primary => unsafe { root.surface_leaf_inactive() },
        Window::Auxiliary => {
            #[cfg(feature = "test-m4-desktop")]
            {
                // SAFETY: fixed auxiliary window, same exact exclusion contract.
                unsafe { root.surface_auxiliary_leaf_inactive() }
            }
            #[cfg(not(feature = "test-m4-desktop"))]
            {
                Err("auxiliary surface unavailable in this profile")
            }
        }
    }
}
fn expected(physical: u64, writable: bool) -> u64 {
    physical | PRESENT | USER | NO_EXECUTE | if writable { WRITABLE } else { 0 }
}
fn stopped(s: &Scheduler, m: Metadata) -> bool {
    s.thread_process(m.thread) == Ok(m.process)
        && s.process_job(m.process) == Ok(m.job)
        && s.state(m.thread) == Ok(State::Exited)
        && s.usage(m.job, Resource::Processes) == Ok(0)
        && s.usage(m.job, Resource::Threads) == Ok(0)
}

/// Closed hardware mapping shapes selected by trusted measured-service dispatch,
/// never by a caller boolean, role number or userspace readiness claim.
#[cfg(feature = "test-m4-desktop")]
#[derive(Clone, Copy)]
pub(crate) enum DesktopMappings {
    PrivateOnly,
    DualBuffers,
    #[cfg(not(feature = "test-m6-network"))]
    SurfaceBuffer,
    #[cfg(feature = "test-m6-network")]
    SurfaceDualBuffers,
    #[cfg(feature = "test-m6-network")]
    ScalarOnly,
    SurfaceOnly,
    Compositor,
}

pub(crate) struct GraphicsImage {
    private: LoadedImage,
    metadata: Option<Metadata>,
    private_frames: u64,
    layout: LayoutReservation,
    surface: Option<SurfaceMapping>,
    auxiliary: Option<SurfaceMapping>,
    display: Option<OwnedDisplayTables>,
    #[cfg(feature = "test-m4-desktop")]
    scalar_claims: u8,
}
impl GraphicsImage {
    pub(crate) const fn empty() -> Self {
        Self {
            private: LoadedImage::empty(),
            metadata: None,
            private_frames: 0,
            layout: LayoutReservation::Legacy,
            surface: None,
            auxiliary: None,
            display: None,
            #[cfg(feature = "test-m4-desktop")]
            scalar_claims: 0,
        }
    }
    /// # Safety
    /// Same serialized real-RAM/private executable loading contract as
    /// LoadedImage::load_startup. Metadata/plan come from one actual held record.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn load_private(
        &mut self,
        plan: &Image<'_>,
        metadata: Metadata,
        startup: &[u8; ev_userspace_contract::SIZE],
        offset: u64,
        bits: u8,
        original: u64,
        frames: &mut BootstrapFrames,
    ) -> Result<(), Error> {
        if self.metadata.is_some()
            || self.private.root.root() != 0
            || self.surface.is_some()
            || self.auxiliary.is_some()
            || self.display.is_some()
        {
            return Err(Error::Phase);
        }
        if metadata.frames != plan.required_frames() {
            return Err(Error::Layout);
        }
        Window::Primary
            .verify_private(plan)
            .map_err(|_| Error::Layout)?;
        // SAFETY: exact held plan and unique inactive image slot; Display V2
        // keeps its real two-PT reservation separate until its owner is installed.
        self.private = unsafe {
            match plan.layout() {
                LayoutReservation::Legacy => {
                    LoadedImage::load_startup(offset, bits, original, plan, Some(startup), frames)
                }
                LayoutReservation::DisplayApertureV1 => LoadedImage::load_graphics_private(
                    offset,
                    bits,
                    original,
                    plan,
                    Some(startup),
                    frames,
                ),
            }
        }
        .map_err(Error::Root)?;
        self.metadata = Some(metadata);
        self.private_frames = plan.private_required_frames();
        self.layout = plan.layout();
        Ok(())
    }
    /// On refusal the caller still owns this exact lease. No hardware changes.
    pub(crate) fn retain_surface(&mut self, lease: ExtentLease) -> Result<(), ExtentLease> {
        if self.metadata.is_none() || self.surface.is_some() {
            Err(lease)
        } else {
            self.surface = Some(SurfaceMapping::new(lease, Window::Primary));
            Ok(())
        }
    }
    /// Every error retains the lease inside this same image; cleanup can never
    /// accidentally discard an attaching mapping owner.
    /// # Safety
    /// Held inactive actual target, exact live extent and serialized BSP owner.
    pub(crate) unsafe fn install_surface(
        &mut self,
        a: &Authority,
        extent: &MemoryExtent,
    ) -> Result<(), Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        let surface = self.surface.as_mut().ok_or(Error::Missing)?;
        // SAFETY: forwards the same actual target/root/capability exclusion.
        unsafe { surface.install(&mut self.private.root, a, extent, metadata) }
    }
    /// # Safety
    /// Actual stopped target and CPU/reference quiescence after Running.finish.
    pub(crate) unsafe fn detach_surface(
        &mut self,
        s: &Scheduler,
        extent: &MemoryExtent,
    ) -> Result<ExtentLease, Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        // SAFETY: same actual returned root and stopped scheduler metadata.
        unsafe {
            self.surface.as_mut().ok_or(Error::Missing)?.detach(
                &mut self.private.root,
                s,
                metadata,
                extent,
            )
        }?;
        Ok(self.surface.take().unwrap().lease)
    }
    /// A second readonly full-extent claim belongs only to a measured Display
    /// owner. Refusal returns the exact lease; no PTE/claim is lost.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) fn retain_auxiliary_surface(
        &mut self,
        lease: ExtentLease,
    ) -> Result<(), ExtentLease> {
        if self.metadata.is_none()
            || self.layout != LayoutReservation::DisplayApertureV1
            || self.auxiliary.is_some()
            || lease.writable()
        {
            Err(lease)
        } else {
            self.auxiliary = Some(SurfaceMapping::new(lease, Window::Auxiliary));
            Ok(())
        }
    }
    /// # Safety
    /// Exact held inactive process/extent and serialized hardware ownership.
    /// The actual measured plan must match the loaded image before preflighting
    /// all auxiliary LOAD pages/guards and then every real target PTE.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) unsafe fn install_auxiliary_surface(
        &mut self,
        a: &Authority,
        extent: &MemoryExtent,
        plan: &Image<'_>,
    ) -> Result<(), Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        if plan.layout() != self.layout
            || plan.base() != self.private.root.base()
            || plan.required_frames() != metadata.frames
            || plan.private_required_frames() != self.private_frames
            || plan.manifest_digest()
                != self
                    .private
                    .borrowed_information(metadata.process, self.private_frames)
                    .manifest
        {
            return Err(Error::Layout);
        }
        Window::Auxiliary
            .verify_private(plan)
            .map_err(|_| Error::Layout)?;
        let mapping = self.auxiliary.as_mut().ok_or(Error::Missing)?;
        // SAFETY: exact matching measured held target and retained readonly RAM.
        unsafe { mapping.install(&mut self.private.root, a, extent, metadata) }
    }
    /// # Safety
    /// Actual fully stopped target/CPU quiescence after Running.finish. This
    /// detaches only the auxiliary claim, never the independent primary mapping.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) unsafe fn detach_auxiliary_surface(
        &mut self,
        s: &Scheduler,
        extent: &MemoryExtent,
    ) -> Result<ExtentLease, Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        // SAFETY: same exclusive returned image and actual stopped identities.
        unsafe {
            self.auxiliary.as_mut().ok_or(Error::Missing)?.detach(
                &mut self.private.root,
                s,
                metadata,
                extent,
            )
        }?;
        Ok(self.auxiliary.take().unwrap().lease)
    }
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) fn auxiliary_surface(&self) -> Option<&ExtentLease> {
        self.auxiliary.as_ref().map(|surface| &surface.lease)
    }
    #[allow(clippy::result_large_err)] // Refusal preserves the unique device/PT owner.
    pub(crate) fn retain_display(
        &mut self,
        owner: OwnedDisplayTables,
    ) -> Result<(), OwnedDisplayTables> {
        if self.metadata.is_none()
            || self.layout != LayoutReservation::DisplayApertureV1
            || self.display.is_some()
            || owner.table_frames() != 0
            || owner.mapped_root().is_some()
        {
            Err(owner)
        } else {
            self.display = Some(owner);
            Ok(())
        }
    }
    /// # Safety
    /// Same actual held private image, measured v2plan, real device capability,
    /// quota, direct-map and serialized controller as OwnedDisplayTables.install.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn install_display(
        &mut self,
        device: &DisplayObject<DisplayAperture>,
        a: &Authority,
        plan: &Image<'_>,
        s: &Scheduler,
        frames: &mut BootstrapFrames,
        offset: u64,
    ) -> Result<(), Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        if plan.layout() != self.layout
            || plan.private_required_frames() != self.private_frames
            || plan.manifest_digest()
                != self
                    .private
                    .borrowed_information(metadata.process, self.private_frames)
                    .manifest
        {
            return Err(Error::Layout);
        }
        let owner = self.display.take().ok_or(Error::Missing)?;
        // SAFETY: exact retained actual owner; refusal returns even partial PTs.
        match unsafe {
            owner.install(
                &mut self.private.root,
                device,
                a,
                plan,
                metadata,
                s,
                frames,
                offset,
            )
        } {
            Ok(owner) => {
                self.display = Some(owner);
                Ok(())
            }
            Err(rejected) => {
                self.display = Some(rejected.owner);
                Err(Error::Display(rejected.error))
            }
        }
    }
    /// # Safety
    /// Running.finish returned this image; actual all-thread/hardware exclusion.
    pub(crate) unsafe fn detach_display(&mut self, s: &Scheduler) -> Result<(), Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        let owner = self.display.take().ok_or(Error::Missing)?;
        // SAFETY: same exact stopped process/root and retained owner as above.
        match unsafe { owner.detach(&mut self.private.root, s, metadata) } {
            Ok(owner) => {
                self.display = Some(owner);
                Ok(())
            }
            Err(rejected) => {
                self.display = Some(rejected.owner);
                Err(Error::Display(rejected.error))
            }
        }
    }
    /// # Safety
    /// Device tables detached or never attached; direct map/allocator retained.
    pub(crate) unsafe fn retire_display_tables(
        &mut self,
        frames: &mut BootstrapFrames,
    ) -> Result<RetiredDisplayTables, Error> {
        let owner = self.display.take().ok_or(Error::Missing)?;
        // SAFETY: same exclusively retained unattached real RAM claims.
        match unsafe { owner.retire_unattached(frames) } {
            Ok(retired) => Ok(retired),
            Err(rejected) => {
                self.display = Some(rejected.owner);
                Err(Error::Display(rejected.error))
            }
        }
    }
    /// Install an exact initialized scalar Memory Object only at fixed507/508.
    /// The inner UserRoot retains the move-only lease on success. Rejection
    /// returns that same lease to its caller before any admission can occur.
    /// # Safety
    /// Held/inactive unique image, controller IF0/CR3, APs parked; object owner
    /// survives until actual termination and explicit matching unmap.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) unsafe fn install_scalar(
        &mut self,
        a: &Authority,
        object: &ev_kernel::memory_object::MemoryObject,
        lease: ev_kernel::memory_object::MappingLease,
        auxiliary: bool,
    ) -> Result<(), crate::executable_runtime::RejectedSharedMap> {
        let bit = if auxiliary { 2 } else { 1 };
        // SAFETY: named fixed-page helper performs actual root, authority,
        // occupancy and lease checks; it retains every rejected claim.
        let result = if auxiliary {
            // SAFETY: exact held root, fixed507 and original retained lease.
            unsafe {
                if lease.writable() {
                    self.private.root.map_application_inactive(a, object, lease)
                } else {
                    self.private.root.map_catalogue_inactive(a, object, lease)
                }
            }
        } else {
            // SAFETY: exact held root, fixed508 and original retained lease.
            unsafe { self.private.root.map_shared_inactive(a, object, lease) }
        };
        if result.is_ok() {
            self.scalar_claims |= bit;
        }
        result
    }
    /// Return a fixed scalar mapping claim only after actual stop/finish.
    /// # Safety
    /// Exact stopped hardware image, no callee/CPU still accesses the buffer.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) unsafe fn detach_scalar(
        &mut self,
        s: &Scheduler,
        object: &mut ev_kernel::memory_object::MemoryObject,
        auxiliary: bool,
    ) -> Result<(), Error> {
        let meta = self.metadata.ok_or(Error::Missing)?;
        if !stopped(s, meta) {
            return Err(Error::Binding);
        }
        let bit = if auxiliary { 2 } else { 1 };
        if self.scalar_claims & bit == 0 {
            return Err(Error::Missing);
        }
        // SAFETY: fixed page and exact retained object; authority revocation
        // never prevents returning an actual stopped mapping lease.
        // SAFETY: returned exclusive stopped image; both named methods verify
        // the exact retained object/lease before removing a fixed PTE.
        unsafe {
            if auxiliary {
                self.private.root.unmap_application_inactive(object)
            } else {
                self.private.root.unmap_shared_inactive(object)
            }
        }
        .map_err(Error::Scalar)?;
        self.scalar_claims &= !bit;
        Ok(())
    }
    pub(crate) fn root(&self) -> &LoadedRoot {
        &self.private.root
    }
    pub(crate) fn surface(&self) -> Option<&ExtentLease> {
        self.surface.as_ref().map(|surface| &surface.lease)
    }
    pub(crate) fn display(&self) -> Option<&OwnedDisplayTables> {
        self.display.as_ref()
    }
    #[cfg(feature = "test-m4-display")]
    pub(crate) fn lease(&mut self) -> Result<GraphicsProcessImage<'_>, Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        let root = self.private.root.root();
        if !self
            .surface
            .as_ref()
            .is_some_and(|surface| surface.installed_on(root))
        {
            return Err(Error::Phase);
        }
        if self
            .auxiliary
            .as_ref()
            .is_some_and(|surface| !surface.installed_on(root))
        {
            return Err(Error::Phase);
        }
        let tables = self
            .display
            .as_ref()
            .map_or(0, OwnedDisplayTables::table_frames) as u64;
        match self.layout {
            LayoutReservation::Legacy => {
                if self.display.is_some() {
                    return Err(Error::Layout);
                }
            }
            LayoutReservation::DisplayApertureV1 => {
                if !self.display.as_ref().is_some_and(|display| {
                    display.table_frames() == 2
                        && display.mapped_root() == Some(root)
                        && display.mapped_geometry().is_some()
                }) {
                    return Err(Error::Phase);
                }
            }
        }
        if self.private_frames + tables != metadata.frames {
            return Err(Error::Layout);
        }
        Ok(GraphicsProcessImage {
            image: self,
            metadata,
        })
    }
    /// Lease an exact closed desktop mapping shape. This is separate from
    /// lease(), whose primary-surface guarantee remains mandatory. Each ledger
    /// bit/receipt is private and installed only by the actual inactive-root
    /// mapping owner. Registry still checks the complete measured executable;
    /// the controller reads back every PTE/guard before first user dispatch.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) fn lease_desktop(
        &mut self,
        profile: DesktopMappings,
    ) -> Result<GraphicsProcessImage<'_>, Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        let root = self.private.root.root();
        if root == 0 {
            return Err(Error::Phase);
        }
        #[cfg(not(feature = "test-m6-network"))]
        let primary = matches!(
            profile,
            DesktopMappings::SurfaceBuffer
                | DesktopMappings::SurfaceOnly
                | DesktopMappings::Compositor
        );
        #[cfg(feature = "test-m6-network")]
        let primary = matches!(
            profile,
            DesktopMappings::SurfaceOnly | DesktopMappings::Compositor
        );
        #[cfg(feature = "test-m6-network")]
        let primary = primary || matches!(profile, DesktopMappings::SurfaceDualBuffers);
        let device = matches!(profile, DesktopMappings::Compositor);
        let scalars = match profile {
            DesktopMappings::DualBuffers => 3,
            #[cfg(not(feature = "test-m6-network"))]
            DesktopMappings::SurfaceBuffer => 1,
            #[cfg(feature = "test-m6-network")]
            DesktopMappings::SurfaceDualBuffers => 3,
            #[cfg(feature = "test-m6-network")]
            DesktopMappings::ScalarOnly => 1,
            _ => 0,
        };
        if self.scalar_claims != scalars {
            return Err(Error::Phase);
        }
        match (primary, self.surface.as_ref()) {
            (true, Some(surface)) if surface.installed_on(root) => (),
            (false, None) => (),
            _ => return Err(Error::Phase),
        }
        match (device, self.auxiliary.as_ref()) {
            (true, Some(surface)) if surface.installed_on(root) => (),
            (false, None) => (),
            _ => return Err(Error::Phase),
        }
        let tables = if device {
            if self.layout != LayoutReservation::DisplayApertureV1
                || !self.display.as_ref().is_some_and(|display| {
                    display.table_frames() == 2
                        && display.mapped_root() == Some(root)
                        && display.mapped_geometry().is_some()
                })
            {
                return Err(Error::Phase);
            }
            2
        } else {
            if self.layout != LayoutReservation::Legacy || self.display.is_some() {
                return Err(Error::Layout);
            }
            0
        };
        if self.private_frames + tables != metadata.frames {
            return Err(Error::Layout);
        }
        Ok(GraphicsProcessImage {
            image: self,
            metadata,
        })
    }
    /// # Safety
    /// Actual process terminated and all CPU/reference quiescence proven. Both
    /// mapping receipts must have been consumed explicitly before private free.
    pub(crate) unsafe fn retire_private(
        &mut self,
        s: &Scheduler,
        frames: &mut BootstrapFrames,
    ) -> Result<u64, Error> {
        #[cfg(feature = "test-m4-desktop")]
        if self.scalar_claims != 0 {
            return Err(Error::LiveClaims);
        }
        if self.surface.is_some() || self.auxiliary.is_some() || self.display.is_some() {
            return Err(Error::LiveClaims);
        }
        let metadata = self.metadata.ok_or(Error::Missing)?;
        if !stopped(s, metadata) {
            return Err(Error::Binding);
        }
        // SAFETY: actual stopped owner with no external PTE/lease receipts left.
        let retired = unsafe { self.private.root.retire_in_place(frames) } as u64;
        if retired != self.private_frames {
            return Err(Error::Readback);
        }
        self.private = LoadedImage::empty();
        self.metadata = None;
        self.private_frames = 0;
        self.layout = LayoutReservation::Legacy;
        Ok(retired)
    }
}
pub(crate) struct GraphicsProcessImage<'a> {
    image: &'a mut GraphicsImage,
    metadata: Metadata,
}
impl<'a> GraphicsProcessImage<'a> {
    pub(crate) fn image(&self) -> &GraphicsImage {
        self.image
    }
    pub(crate) fn into_image(self) -> &'a mut GraphicsImage {
        self.image
    }
}
// SAFETY: private constructors lease()/lease_desktop() retain the actual measured
// private image and enforce their distinct complete mapping shapes. lease()
// always requires its installed primary63-page surface. lease_desktop() checks
// the exact private/scalar/surface/aux/device profile; a compositor requires two
// installed surfaces and the actual measured2PT aperture, ordinary services can
// own no display backing. All claims originate in real inactive-root helpers;
// the serialized controller verifies PTE/guard readback before first dispatch.
// Running's exclusive borrow prevents initialization/mapping mutation until
// finish returns this sole owner. Drop never reclaims RAM or device backing.
unsafe impl LoadedExecutable for GraphicsProcessImage<'_> {
    fn information(&self) -> Information {
        self.image.private.borrowed_information(
            self.metadata.process,
            self.image.private_frames
                + self
                    .image
                    .display
                    .as_ref()
                    .map_or(0, OwnedDisplayTables::table_frames) as u64,
        )
    }
    fn layout(&self) -> LayoutReservation {
        self.image.layout
    }
}
