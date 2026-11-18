//! Affine physical V5 image and external mapping owners. There is no readiness
//! boolean and no admitted shared accessor can mutate an owned page table.
use super::*;
use crate::{
    display_runtime::{DisplayAperture, OwnedDisplayTables},
    executable_runtime::PrivateLoadedImage,
};
use ev_kernel::{
    display::DisplayObject,
    loaded_image::{Information, LoadedExecutable},
    memory_extent::{ExtentLease, M8SharedExtent as MemoryExtent},
};
const AD: u64 = (1 << 5) | (1 << 6);
struct Mapping {
    spec: mapping::Spec,
    lease: ExtentLease,
}
pub(super) struct Owner<const N: usize> {
    loaded: PrivateLoadedImage<N>,
    maps: [Option<Mapping>; 10],
    display: Option<OwnedDisplayTables>,
}
// Fixed resident slots retain closed owners without heap indirection. Linked
// stack admission separately measures the one moved owner temporary.
#[allow(clippy::large_enum_variant)]
pub(super) enum PhysicalImage {
    Core(Owner<68>),
    Ui(Owner<100>),
    Workspace(Owner<100>),
    Display(Owner<84>),
    Editor(Owner<388>),
    Root(Owner<244>),
}
impl<const N: usize> Owner<N> {
    fn exact_mappings(&self, required: impl Iterator<Item = mapping::Spec>) -> bool {
        let mut count = 0;
        for spec in required {
            count += 1;
            if !self.maps.iter().flatten().any(|map| map.spec == spec) {
                return false;
            }
        }
        count == self.maps.iter().flatten().count()
    }
    unsafe fn load(
        hw: Hardware,
        plan: &ev_kernel::executable::Image<'_>,
        record: ev_kernel::startup_record::Record<'_>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        // SAFETY: exact held plan/record and exclusive physical controller.
        let loaded = unsafe {
            PrivateLoadedImage::load_workspace(
                hw.offset,
                hw.bits,
                hw.original,
                plan,
                record,
                frames,
            )?
        };
        Ok(Self {
            loaded,
            maps: [const { None }; 10],
            display: None,
        })
    }
    fn preflight(&self, spec: mapping::Spec) -> Result<(), &'static str> {
        if spec.pages == 0
            || spec.pages > ev_kernel::memory_extent::M8_SHARED_MAX_PAGES
            || spec.first == 0
            || spec.first + spec.pages > 509
        {
            return Err("V5 external bounds");
        }
        for p in spec.first..spec.first + spec.pages {
            if self.loaded.root.workspace_entry(p)? != 0 {
                return Err("V5 external slot occupied");
            }
        }
        if spec.guards
            && (self.loaded.root.workspace_entry(spec.first - 1)? != 0
                || self.loaded.root.workspace_entry(spec.first + spec.pages)? != 0)
        {
            return Err("V5 external guards occupied");
        }
        Ok(())
    }
    unsafe fn install(
        &mut self,
        a: &Authority,
        extent: &mut MemoryExtent,
        domain: SpaceId,
        cap: Handle,
        spec: mapping::Spec,
    ) -> Result<(), &'static str> {
        self.preflight(spec)?;
        if extent.pages() != spec.pages {
            return Err("V5 actual extent length");
        }
        let slot = self
            .maps
            .iter()
            .position(Option::is_none)
            .ok_or("V5 mapping ledger full")?;
        let lease = extent
            .map(a, domain, cap, spec.writable)
            .map_err(|_| "V5 actual extent authority")?;
        self.maps[slot] = Some(Mapping { spec, lease });
        let map = self.maps[slot].as_ref().unwrap();
        extent
            .validate(a, &map.lease)
            .map_err(|_| "V5 mapping changed before attach")?;
        // SAFETY: all target PTEs/guards preflighted, real lease retained above,
        // physical identities come only from that exact immutable frame owner.
        let mut leaf = unsafe {
            self.loaded
                .root
                .workspace_leaf_inactive(spec.first, spec.pages)?
        };
        for (i, physical) in extent
            .physical_pages(&map.lease)
            .map_err(|_| "V5 extent frame claims")?
            .enumerate()
        {
            let entry = physical | 5 | (1 << 63) | if spec.writable { 2 } else { 0 };
            // SAFETY: retained lease authorizes exact physical page and flags.
            unsafe {
                leaf.write(spec.first + i, entry)?;
            }
        }
        Ok(())
    }
    fn check(
        &self,
        a: &Authority,
        extents: &[Option<MemoryExtent>; 37],
    ) -> Result<(), &'static str> {
        for map in self.maps.iter().flatten() {
            let extent = extents[map.spec.role.selector() as usize - 1]
                .as_ref()
                .ok_or("V5 missing retained extent")?;
            extent
                .validate(a, &map.lease)
                .map_err(|_| "V5 live extent lease revoked")?;
            for (i, physical) in extent
                .physical_pages(&map.lease)
                .map_err(|_| "V5 extent identity")?
                .enumerate()
            {
                let expected = physical | 5 | (1 << 63) | if map.spec.writable { 2 } else { 0 };
                if self.loaded.root.workspace_entry(map.spec.first + i)? & !AD != expected {
                    return Err("V5 actual shared PTE mismatch");
                }
            }
            if map.spec.guards
                && (self.loaded.root.workspace_entry(map.spec.first - 1)? != 0
                    || self
                        .loaded
                        .root
                        .workspace_entry(map.spec.first + map.spec.pages)?
                        != 0)
            {
                return Err("V5 actual shared guards");
            }
        }
        Ok(())
    }
    unsafe fn retire(
        &mut self,
        extents: &mut [Option<MemoryExtent>; 37],
        device: &mut DisplayObject<DisplayAperture>,
        scheduler: &Scheduler,
        meta: Metadata,
        frames: &mut BootstrapFrames,
    ) -> Result<usize, &'static str> {
        if scheduler.state(meta.thread) != Ok(State::Exited)
            || scheduler.usage(meta.job, Resource::Processes) != Ok(0)
            || scheduler.usage(meta.job, Resource::Threads) != Ok(0)
        {
            return Err("V5 physical retirement before stop");
        }
        let mut device_frames = 0;
        if let Some(display) = self.display.take() {
            // SAFETY: actual terminated owner and captured distinct controller.
            match unsafe { display.detach(&mut self.loaded.root, scheduler, meta) } {
                Ok(display) => {
                    // SAFETY: detached actual tables and no process reference.
                    let retired =
                        unsafe { display.retire_unattached(frames) }.map_err(|rejected| {
                            self.display = Some(rejected.owner);
                            "V5 Display table retirement"
                        })?;
                    device_frames = usize::from(retired.returned);
                    device
                        .unmap(retired.lease)
                        .map_err(|_| "V5 Display lease return")?;
                }
                Err(rejected) => {
                    self.display = Some(rejected.owner);
                    return Err("V5 actual Display detach");
                }
            }
        }
        for slot in &mut self.maps {
            let Some(map) = slot.as_ref() else { continue };
            let spec = map.spec;
            let extent = extents[spec.role.selector() as usize - 1]
                .as_mut()
                .ok_or("V5 retirement extent")?;
            // Revoked authority cannot prevent exact claim-based detachment.
            for (i, physical) in extent
                .physical_pages(&map.lease)
                .map_err(|_| "V5 retained retirement frames")?
                .enumerate()
            {
                let expected = physical | 5 | (1 << 63) | if spec.writable { 2 } else { 0 };
                if self.loaded.root.workspace_entry(spec.first + i)? & !AD != expected {
                    return Err("V5 retirement PTE mismatch");
                }
            }
            // SAFETY: same stopped physical root and real retained lease.
            let mut leaf = unsafe {
                self.loaded
                    .root
                    .workspace_leaf_inactive(spec.first, spec.pages)?
            };
            for p in spec.first..spec.first + spec.pages {
                // SAFETY: stopped actual root, exact retained extent/PTE range.
                unsafe {
                    leaf.write(p, 0)?;
                }
            }
            let map = slot.take().unwrap();
            if let Err((_error, lease)) = extent.unmap(map.lease) {
                *slot = Some(Mapping { spec, lease });
                return Err("V5 extent claim return");
            }
        }
        for p in 0..512 {
            if self.loaded.root.workspace_entry(p)? & !AD
                != self.loaded.root.workspace_private_entry(p)?
            {
                return Err("V5 foreign external PTE before private retirement");
            }
        }
        // SAFETY: all external claims/tables detached, actual process stopped,
        // APs parked and controller reload has invalidated local user TLBs.
        Ok(unsafe { self.loaded.root.retire_in_place(frames) } + device_frames)
    }
}
impl PhysicalImage {
    /// # Safety
    /// Exact actual Running Block image was captured into controller CR3/IF0;
    /// APs parked and its affine private ownership remains admitted and pinned.
    pub(super) unsafe fn block_io_buffer(
        &self,
        address: u64,
        controller: u64,
    ) -> Result<crate::user_space::CapturedIoBuffer<'_>, &'static str> {
        let Self::Core(owner) = self else {
            return Err("PIO requires Core owner");
        };
        // SAFETY: forwarded exact captured-owner/exclusive-controller boundary.
        unsafe { owner.loaded.root.io_buffer_captured(address, controller) }
    }
    pub(super) fn dynamic_root(
        &self,
    ) -> Result<&crate::executable_runtime::PrivateLoadedRoot<244>, &'static str> {
        match self {
            Self::Root(owner) => Ok(&owner.loaded.root),
            _ => Err("dynamic mutation requires actual V5 Root owner"),
        }
    }
    fn ready_for(&self, child: Option<Child>) -> bool {
        let class = match (child, self) {
            (None, Self::Root(_)) => true,
            (
                Some(Child::Input | Child::Block | Child::NetDriver | Child::NetService),
                Self::Core(_),
            ) => true,
            (Some(Child::Shell | Child::Files | Child::Inspector), Self::Ui(_)) => true,
            (Some(Child::EditorOne | Child::EditorTwo), Self::Editor(_)) => true,
            (Some(Child::Workspace), Self::Workspace(_)) => true,
            (Some(Child::Display), Self::Display(o)) => o.display.as_ref().is_some_and(|d| {
                d.table_frames() == 2 && d.mapped_root() == Some(o.loaded.root.root())
            }),
            _ => false,
        };
        if !class {
            return false;
        }
        macro_rules! matches {
            ($o:expr) => {
                if let Some(child) = child {
                    $o.exact_mappings(mapping::for_child(child))
                } else {
                    $o.exact_mappings(mapping::ROOT.into_iter())
                }
            };
        }
        match self {
            Self::Core(o) => matches!(o),
            Self::Ui(o) | Self::Workspace(o) => matches!(o),
            Self::Display(o) => matches!(o),
            Self::Editor(o) => matches!(o),
            Self::Root(o) => matches!(o),
        }
    }
    pub unsafe fn load(
        hw: Hardware,
        slot: Option<ImageSlot>,
        plan: &ev_kernel::executable::Image<'_>,
        record: ev_kernel::startup_record::Record<'_>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        // SAFETY: each branch is the SDK's closed private owner; legacy alias68
        // and ordinary loader constructors retain their original capacities.
        unsafe {
            Ok(match slot {
                None => Self::Root(Owner::load(hw, plan, record, frames)?),
                Some(ImageSlot::Display) => Self::Display(Owner::load(hw, plan, record, frames)?),
                Some(ImageSlot::Workspace) => {
                    Self::Workspace(Owner::load(hw, plan, record, frames)?)
                }
                Some(ImageSlot::Editor) => Self::Editor(Owner::load(hw, plan, record, frames)?),
                Some(slot)
                    if v5::resources::image_layout(slot)
                        == v5::resources::ImageLayout::LegacyCore =>
                {
                    Self::Core(Owner::load(hw, plan, record, frames)?)
                }
                Some(_) => Self::Ui(Owner::load(hw, plan, record, frames)?),
            })
        }
    }
    pub unsafe fn install(
        &mut self,
        a: &Authority,
        extent: &mut MemoryExtent,
        domain: SpaceId,
        cap: Handle,
        spec: mapping::Spec,
    ) -> Result<(), &'static str> {
        // SAFETY: same exact inactive owner/extent authority contract per arm.
        unsafe {
            match self {
                Self::Core(o) => o.install(a, extent, domain, cap, spec),
                Self::Ui(o) | Self::Workspace(o) => o.install(a, extent, domain, cap, spec),
                Self::Display(o) => o.install(a, extent, domain, cap, spec),
                Self::Editor(o) => o.install(a, extent, domain, cap, spec),
                Self::Root(o) => o.install(a, extent, domain, cap, spec),
            }
        }
    }
    pub fn check(
        &self,
        a: &Authority,
        extents: &[Option<MemoryExtent>; 37],
    ) -> Result<(), &'static str> {
        match self {
            Self::Core(o) => o.check(a, extents),
            Self::Ui(o) | Self::Workspace(o) => o.check(a, extents),
            Self::Display(o) => o.check(a, extents),
            Self::Editor(o) => o.check(a, extents),
            Self::Root(o) => o.check(a, extents),
        }
    }
    pub fn activate(&self) {
        match self {
            Self::Core(o) => o.loaded.root.activate(),
            Self::Ui(o) | Self::Workspace(o) => o.loaded.root.activate(),
            Self::Display(o) => o.loaded.root.activate(),
            Self::Editor(o) => o.loaded.root.activate(),
            Self::Root(o) => o.loaded.root.activate(),
        }
    }
    pub fn information(&self, meta: Metadata) -> Information {
        match self {
            Self::Core(o) => o.loaded.borrowed_information(meta.process, meta.frames),
            Self::Ui(o) | Self::Workspace(o) => {
                o.loaded.borrowed_information(meta.process, meta.frames)
            }
            Self::Display(o) => {
                assert_eq!(
                    o.display.as_ref().map(OwnedDisplayTables::table_frames),
                    Some(2)
                );
                o.loaded.borrowed_information(meta.process, meta.frames)
            }
            Self::Editor(o) => o.loaded.borrowed_information(meta.process, meta.frames),
            Self::Root(o) => o.loaded.borrowed_information(meta.process, meta.frames),
        }
    }
    pub fn layout(&self) -> ev_kernel::executable::LayoutReservation {
        if matches!(self, Self::Display(_)) {
            ev_kernel::executable::LayoutReservation::DisplayApertureV1
        } else {
            ev_kernel::executable::LayoutReservation::Legacy
        }
    }
    #[allow(clippy::too_many_arguments)] // Explicit actual hardware/allocator owners.
    pub unsafe fn install_display(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        device: &mut DisplayObject<DisplayAperture>,
        cap: Handle,
        plan: &ev_kernel::executable::Image<'_>,
        meta: Metadata,
        frames: &mut BootstrapFrames,
        hw: Hardware,
    ) -> Result<(), &'static str> {
        let Self::Display(owner) = self else {
            return Err("V5 Display owner class");
        };
        let lease = device
            .map(a, meta.domain, cap)
            .map_err(|_| "V5 Display actual grant")?;
        owner.display = Some(OwnedDisplayTables::uninstalled(lease));
        let tables = owner.display.take().unwrap();
        // SAFETY: exact held Registry descriptor/owner and actual GOP claim.
        match unsafe {
            tables.install(
                &mut owner.loaded.root,
                device,
                a,
                plan,
                meta,
                s,
                frames,
                hw.offset,
            )
        } {
            Ok(tables) => {
                owner.display = Some(tables);
                Ok(())
            }
            Err(rejected) => {
                owner.display = Some(rejected.owner);
                Err("V5 Display physical install")
            }
        }
    }
    pub unsafe fn retire(
        &mut self,
        extents: &mut [Option<MemoryExtent>; 37],
        device: &mut DisplayObject<DisplayAperture>,
        s: &Scheduler,
        meta: Metadata,
        frames: &mut BootstrapFrames,
    ) -> Result<usize, &'static str> {
        // SAFETY: exact stopped owner, no accepted operation or device access.
        unsafe {
            match self {
                Self::Core(o) => o.retire(extents, device, s, meta, frames),
                Self::Ui(o) | Self::Workspace(o) => o.retire(extents, device, s, meta, frames),
                Self::Display(o) => o.retire(extents, device, s, meta, frames),
                Self::Editor(o) => o.retire(extents, device, s, meta, frames),
                Self::Root(o) => o.retire(extents, device, s, meta, frames),
            }
        }
    }
}
pub(super) struct ImageLease<'a> {
    pub owner: &'a mut PhysicalImage,
    pub metadata: Metadata,
}
impl<'a> ImageLease<'a> {
    pub fn new(owner: &'a mut PhysicalImage, metadata: Metadata, child: Option<Child>) -> Self {
        assert!(
            owner.ready_for(child),
            "actual exact V5 image class/mapping/display owner before admission"
        );
        Self { owner, metadata }
    }
}
// SAFETY: the lease exclusively borrows the actual initialized private/extent/
// Display owners. Its only production constructor follows exact measured load
// and mapping readback, retains all backing through Running/Active and allows
// no mutable alias during admission. Drop never unmaps or reclaims resources.
unsafe impl LoadedExecutable for ImageLease<'_> {
    fn information(&self) -> Information {
        self.owner.information(self.metadata)
    }
    fn layout(&self) -> ev_kernel::executable::LayoutReservation {
        self.owner.layout()
    }
}
