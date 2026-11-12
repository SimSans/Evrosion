//! Owned privileged Display mapping. Scratch integration draft: kernel only
//! discovers/maps the aperture; all pixel copying/painting stays in userspace.
use crate::executable_runtime::LoadedRoot;
use core::{arch::asm, ptr};
use ev_boot_contract::Framebuffer;
use ev_kernel::{
    capability::Authority,
    display::{DisplayBacking, DisplayLease, DisplayObject, Information},
    display_plan::{self, Geometry, Plan},
    display_walk::{self, NX, PRESENT, Snapshot, Tables, USER, WRITABLE},
    executable::{Image, LayoutReservation},
    mapping::direct_address,
    memory::{BootstrapFrames, PhysicalFrame},
    scheduler::{Resource, Scheduler, State},
    service::Metadata,
};

pub(crate) enum Error {
    Plan(display_plan::Error),
    Walk(display_walk::Error),
    Authority(ev_kernel::display::Error),
    Scheduler(ev_kernel::scheduler::Error),
    Layout,
    Binding,
    Root,
    Source,
    Capacity,
    Allocator,
    Directory(&'static str),
    Readback,
}
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plan(error) => f.debug_tuple("Plan").field(error).finish(),
            Self::Walk(error) => f.debug_tuple("Walk").field(error).finish(),
            Self::Authority(error) => f.debug_tuple("Authority").field(error).finish(),
            Self::Scheduler(error) => f.debug_tuple("Scheduler").field(error).finish(),
            Self::Directory(error) => f.debug_tuple("Directory").field(error).finish(),
            Self::Layout => f.write_str("Layout"),
            Self::Binding => f.write_str("Binding"),
            Self::Root => f.write_str("Root"),
            Self::Source => f.write_str("Source"),
            Self::Capacity => f.write_str("Capacity"),
            Self::Allocator => f.write_str("Allocator"),
            Self::Readback => f.write_str("Readback"),
        }
    }
}
impl From<display_plan::Error> for Error {
    fn from(error: display_plan::Error) -> Self {
        Self::Plan(error)
    }
}
impl From<display_walk::Error> for Error {
    fn from(error: display_walk::Error) -> Self {
        Self::Walk(error)
    }
}
impl From<ev_kernel::display::Error> for Error {
    fn from(error: ev_kernel::display::Error) -> Self {
        Self::Authority(error)
    }
}
impl From<ev_kernel::scheduler::Error> for Error {
    fn from(error: ev_kernel::scheduler::Error) -> Self {
        Self::Scheduler(error)
    }
}

struct RetainedTables<'a> {
    offset: u64,
    snapshot: Snapshot,
    frames: &'a BootstrapFrames,
}
impl Tables for RetainedTables<'_> {
    fn entry(&self, table: u64, index: usize) -> Result<u64, display_walk::Error> {
        if index >= 512 || !self.frames.is_reserved_frame(table) {
            return Err(display_walk::Error::Read);
        }
        let address = direct_address(self.offset, table, self.snapshot.physical_bits())
            .map_err(|_| display_walk::Error::Address)?;
        // SAFETY: actual immutable reserved loader table, retained direct map,
        // checked full-frame range and index; never a framebuffer dereference.
        Ok(unsafe { (address as *const u64).add(index).read_volatile() })
    }
}
fn snapshot() -> Result<Snapshot, Error> {
    if core::arch::x86_64::__cpuid(1).edx & (1 << 16) == 0
        || core::arch::x86_64::__cpuid(0x80000000).eax < 0x80000008
    {
        return Err(Error::Source);
    }
    let (cr3, cr4, cr0, flags, efer_lo, efer_hi, pat_lo, pat_hi): (
        u64,
        u64,
        u64,
        u64,
        u32,
        u32,
        u32,
        u32,
    );
    // SAFETY: only the private Ring0 hardware entry calls this function.
    unsafe {
        asm!("mov {}, cr3",out(reg)cr3,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr4",out(reg)cr4,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr0",out(reg)cr0,options(nomem,nostack,preserves_flags));
        asm!("pushfq","pop {}",out(reg)flags,options(preserves_flags));
        asm!("rdmsr",in("ecx")0xc0000080u32,out("eax")efer_lo,out("edx")efer_hi,options(nomem,nostack,preserves_flags));
        asm!("rdmsr",in("ecx")0x277u32,out("eax")pat_lo,out("edx")pat_hi,options(nomem,nostack,preserves_flags));
    }
    if flags & (1 << 9) != 0 || cr0 & ((1 << 29) | (1 << 30)) != 0 {
        return Err(Error::Source);
    }
    Ok(Snapshot::checked(
        cr3,
        cr4,
        u64::from(efer_lo) | (u64::from(efer_hi) << 32),
        (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8,
        u64::from(pat_lo) | (u64::from(pat_hi) << 32),
        core::arch::x86_64::__cpuid(0x80000001).edx & (1 << 26) != 0,
    )?)
}

/// The only actual source constructor is discover below. No PhysicalFrame or
/// device-free API exists; ownership is move-only and retained by DisplayObject.
pub(crate) struct DisplayAperture {
    plan: Plan,
}
impl DisplayAperture {
    /// # Safety
    /// Actual trusted boot GOP descriptor, serialized BSP/IF0/APs parked,
    /// retained original controller CR3/direct map. Source tables/PAT/MTRRs and
    /// original map remain immutable/retained until all Display users quiesce.
    /// Called once by the trusted boot device factory, not from a syscall.
    pub(crate) unsafe fn discover(
        offset: u64,
        framebuffer: Framebuffer,
        frames: &BootstrapFrames,
    ) -> Result<Self, Error> {
        let state = snapshot()?;
        let reader = RetainedTables {
            offset,
            snapshot: state,
            frames,
        };
        let plan = Plan::checked(
            &reader,
            frames.memory_map(),
            Geometry::checked(framebuffer)?,
            state,
        )?;
        Ok(Self { plan })
    }
    pub(crate) fn plan(&self) -> &Plan {
        &self.plan
    }
}
// SAFETY: the unique private constructor checks actual retained translation,
// every scanout page/cache/PAT setting and no Usable RAM overlap. No constructor
// from a model plan/boolean or source numeric address is exposed to services.
// Physical backing and original loader tables remain retained; Drop frees none.
unsafe impl DisplayBacking for DisplayAperture {
    fn information(&self) -> Information {
        let g = self.plan.geometry();
        Information {
            fingerprint: self.plan.fingerprint(),
            width: g.width(),
            height: g.height(),
            stride: g.stride(),
            byte_length: g.byte_length(),
            page_count: g.pages() as u16,
            byte_offset: g.byte_offset(),
            format: if g.bgr() { 2 } else { 1 },
        }
    }
}

#[derive(Clone, Copy)]
enum Attachment {
    Unattached,
    Attaching { metadata: Metadata, root: u64 },
    Installed { metadata: Metadata, root: u64 },
}
pub(crate) struct OwnedDisplayTables {
    frames: [Option<PhysicalFrame>; 2],
    lease: DisplayLease,
    attachment: Attachment,
    geometry: Option<Geometry>,
    offset: u64,
    bits: u8,
    returned: u8,
}
pub(crate) struct RejectedDisplayTables {
    pub(crate) error: Error,
    pub(crate) owner: OwnedDisplayTables,
}
pub(crate) struct RetiredDisplayTables {
    pub(crate) lease: DisplayLease,
    pub(crate) returned: u8,
}
impl OwnedDisplayTables {
    pub(crate) fn uninstalled(lease: DisplayLease) -> Self {
        Self {
            frames: [None, None],
            lease,
            attachment: Attachment::Unattached,
            geometry: None,
            offset: 0,
            bits: 0,
            returned: 0,
        }
    }
    pub(crate) fn table_frames(&self) -> usize {
        self.frames.iter().flatten().count()
    }
    pub(crate) fn mapped_root(&self) -> Option<u64> {
        match self.attachment {
            Attachment::Unattached | Attachment::Attaching { .. } => None,
            Attachment::Installed { root, .. } => Some(root),
        }
    }
    pub(crate) fn mapped_geometry(&self) -> Option<Geometry> {
        self.mapped_root().and(self.geometry)
    }
    fn rejected(self, error: Error) -> RejectedDisplayTables {
        RejectedDisplayTables { error, owner: self }
    }
    fn addresses(&self) -> Result<[u64; 2], Error> {
        match &self.frames {
            [Some(a), Some(b)] if a.start() != b.start() => Ok([a.start(), b.start()]),
            _ => Err(Error::Allocator),
        }
    }
    fn pointers(&self) -> Result<[*mut u64; 2], Error> {
        let addresses = self.addresses()?;
        Ok([
            direct_address(self.offset, addresses[0], self.bits).map_err(|_| Error::Allocator)?
                as *mut u64,
            direct_address(self.offset, addresses[1], self.bits).map_err(|_| Error::Allocator)?
                as *mut u64,
        ])
    }
    /// # Safety
    /// Actual same Registry held process/plan/private root and charged Job;
    /// serialized BSP/IF0, APs parked, original controller root restored, no
    /// concurrent allocator/table/capability mutation. Metadata is obtained from
    /// that Registry, never decoded from userspace. The graphics wrapper retains
    /// this owner and private root until actual process/reference quiescence.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub(crate) unsafe fn install(
        mut self,
        root: &mut LoadedRoot,
        device: &DisplayObject<DisplayAperture>,
        authority: &Authority,
        plan: &Image<'_>,
        metadata: Metadata,
        scheduler: &Scheduler,
        frames: &mut BootstrapFrames,
        offset: u64,
    ) -> Result<Self, RejectedDisplayTables> {
        let operation = (|| -> Result<(), Error> {
            if !matches!(self.attachment, Attachment::Unattached)
                || self.table_frames() != 0
                || self.returned != 0
            {
                return Err(Error::Binding);
            }
            if plan.layout() != LayoutReservation::DisplayApertureV1
                || metadata.frames != plan.required_frames()
            {
                return Err(Error::Layout);
            }
            if self.lease.owner() != metadata.domain
                || scheduler.held_process_job(metadata.process)? != metadata.job
                || scheduler.thread_process(metadata.thread)? != metadata.process
                || scheduler.usage(metadata.job, Resource::Frames)? != metadata.frames
            {
                return Err(Error::Binding);
            }
            let (root_id, base) = root.display_root_identity().ok_or(Error::Root)?;
            if base != plan.base() {
                return Err(Error::Root);
            }
            let source = device.backing_for(authority, &self.lease)?;
            let state = snapshot()?;
            if state != source.plan.snapshot() || state.root() == root_id {
                return Err(Error::Source);
            }
            self.offset = offset;
            self.bits = state.physical_bits();
            self.geometry = Some(source.plan.geometry());
            // SAFETY: actual held process/root and current privileged exclusion
            // are checked before obtaining any writable PD access.
            let mut directory =
                unsafe { root.display_directory_inactive() }.map_err(Error::Directory)?;
            directory.preflight_empty().map_err(Error::Directory)?;
            if directory.root() != root_id || directory.base() != base {
                return Err(Error::Root);
            }
            source.plan.verify_unchanged(&RetainedTables {
                offset,
                snapshot: state,
                frames,
            })?;
            if frames.remaining_frames() < 2 {
                return Err(Error::Capacity);
            }
            // Full scheduler quota was already charged by Registry::create_process
            // from the V2plan. No second charge or unrelated Job is introduced.
            for frame in &mut self.frames {
                *frame = Some(frames.allocate().map_err(|_| Error::Allocator)?);
            }
            if self
                .frames
                .iter()
                .flatten()
                .any(|frame| !frames.owns(frame))
            {
                return Err(Error::Allocator);
            }
            let pointers = self.pointers()?;
            for pointer in pointers {
                // SAFETY: actual unique allocator RAM frames, unpublished PTs.
                unsafe {
                    ptr::write_bytes(pointer, 0, 512);
                }
            }
            let reader = RetainedTables {
                offset,
                snapshot: state,
                frames,
            };
            source.plan.entries(&reader, |index, entry| {
                // SAFETY: at most1024checked pages, index selects one owned
                // private512-entry table; no PD entry exposes it yet.
                unsafe {
                    pointers[index / 512].add(index % 512).write_volatile(entry);
                }
                Ok(())
            })?;
            // Verify every actual device PTE and every unused tail entry before
            // publication; source fingerprint is rechecked on this third walk.
            source.plan.entries(&reader, |index, expected| {
                // SAFETY: same retained privately filled PT range.
                if unsafe { pointers[index / 512].add(index % 512).read_volatile() } != expected {
                    return Err(display_plan::Error::Changed);
                }
                Ok(())
            })?;
            for index in source.plan.geometry().pages()..1024 {
                // SAFETY: checked bounded unused entry in our owned PTs.
                if unsafe { pointers[index / 512].add(index % 512).read_volatile() } != 0 {
                    return Err(Error::Readback);
                }
            }
            directory.preflight_empty().map_err(Error::Directory)?;
            let addresses = self.addresses()?;
            // SAFETY: both actual unique PTs are fully initialized/verified,
            // root is held/inactive and all directory/source preflights passed.
            unsafe { directory.attach(addresses) }.map_err(Error::Directory)?;
            // Record attachment before any fallible post-publication check so
            // an integrity failure cannot lose an attached backing owner.
            self.attachment = Attachment::Attaching {
                metadata,
                root: root_id,
            };
            for (index, physical) in addresses.into_iter().enumerate() {
                if directory.entry(index + 2).map_err(Error::Directory)?
                    != (physical | PRESENT | WRITABLE | USER | NX)
                {
                    return Err(Error::Readback);
                }
            }
            if directory.entry(1).map_err(Error::Directory)? != 0
                || directory.entry(4).map_err(Error::Directory)? != 0
            {
                return Err(Error::Readback);
            }
            self.attachment = Attachment::Installed {
                metadata,
                root: root_id,
            };
            Ok(())
        })();
        match operation {
            Ok(()) => Ok(self),
            Err(error) => Err(self.rejected(error)),
        }
    }
    /// # Safety
    /// Running::finish returned actual backing; process/all threads terminated,
    /// controller CR3 restored, IF0/APs quiescent, PCID off/no global user leaves.
    /// Source/lease revocation does not excuse or prevent exact physical cleanup.
    #[allow(clippy::result_large_err)]
    pub(crate) unsafe fn detach(
        mut self,
        root: &mut LoadedRoot,
        scheduler: &Scheduler,
        metadata: Metadata,
    ) -> Result<Self, RejectedDisplayTables> {
        let operation = (|| -> Result<(), Error> {
            let (expected, root_id) = match self.attachment {
                Attachment::Attaching { metadata, root }
                | Attachment::Installed { metadata, root } => (metadata, root),
                Attachment::Unattached => return Err(Error::Binding),
            };
            if metadata != expected
                || scheduler.state(metadata.thread)? != State::Exited
                || scheduler.process_job(metadata.process)? != metadata.job
                || scheduler.usage(metadata.job, Resource::Processes)? != 0
                || scheduler.usage(metadata.job, Resource::Threads)? != 0
                || root
                    .display_root_identity()
                    .is_none_or(|(actual, _)| actual != root_id)
            {
                return Err(Error::Binding);
            }
            let addresses = self.addresses()?;
            // SAFETY: exact stopped process/root and CPU exclusion as above.
            let mut directory =
                unsafe { root.display_directory_inactive() }.map_err(Error::Directory)?;
            // SAFETY: exact attached owner/frames; restored CR3/AP quiescence
            // excludes stale users. This clears only its two expected PDEs.
            unsafe { directory.detach(addresses) }.map_err(Error::Directory)?;
            directory.preflight_empty().map_err(Error::Directory)?;
            self.attachment = Attachment::Unattached;
            Ok(())
        })();
        match operation {
            Ok(()) => Ok(self),
            Err(error) => Err(self.rejected(error)),
        }
    }
    /// # Safety
    /// This value was never attached or actual detach above completed. The
    /// retained direct mapping is live and no CPU/reference can use these PTs.
    /// Only allocator RAM claims are scrubbed/returned; never framebuffer pages.
    #[allow(clippy::result_large_err)]
    pub(crate) unsafe fn retire_unattached(
        mut self,
        frames: &mut BootstrapFrames,
    ) -> Result<RetiredDisplayTables, RejectedDisplayTables> {
        let operation = (|| -> Result<(), Error> {
            if !matches!(self.attachment, Attachment::Unattached) {
                return Err(Error::Binding);
            }
            if self
                .frames
                .iter()
                .flatten()
                .any(|frame| !frames.owns(frame))
                || frames.recycle_capacity() < self.table_frames()
            {
                return Err(Error::Allocator);
            }
            // Validate all aliases before scrubbing/reclaiming any backing.
            let mut pointers = [ptr::null_mut(); 2];
            for (index, frame) in self.frames.iter().enumerate() {
                if let Some(frame) = frame {
                    pointers[index] = direct_address(self.offset, frame.start(), self.bits)
                        .map_err(|_| Error::Allocator)?
                        as *mut u64;
                }
            }
            for pointer in pointers.into_iter().filter(|pointer| !pointer.is_null()) {
                for index in 0..512 {
                    // SAFETY: unique actual detached allocator RAM, never VRAM.
                    unsafe {
                        pointer.add(index).write_volatile(0);
                        if pointer.add(index).read_volatile() != 0 {
                            return Err(Error::Readback);
                        }
                    }
                }
            }
            for index in 0..2 {
                if let Some(frame) = self.frames[index].take() {
                    if let Err((_, frame)) = frames.reclaim(frame) {
                        self.frames[index] = Some(frame);
                        return Err(Error::Allocator);
                    }
                    self.returned += 1;
                }
            }
            Ok(())
        })();
        match operation {
            Ok(()) => Ok(RetiredDisplayTables {
                lease: self.lease,
                returned: self.returned,
            }),
            Err(error) => Err(self.rejected(error)),
        }
    }
}
