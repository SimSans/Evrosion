//! Single-CPU user isolation proof; no public process or capability API yet.
use core::{arch::asm, ptr};
use ev_kernel::{
    mapping::{ADDRESS_MASK, ENTRIES, PRESENT, WRITABLE, direct_address},
    memory::{BootstrapFrames, FRAME_SIZE, PhysicalFrame},
    memory_object::{MappingLease, MemoryObject},
    user::{MAX_PRIVATE_PAGES, PrivateUserMappings, USER, UserPermission, UserTrap},
};

unsafe extern "C" {
    static ev_user_blob: u8;
    static ev_user_blob_end: u8;
    static ev_user_read: u8;
    static ev_user_read_ok: u8;
    static ev_user_write: u8;
    static ev_user_write_ok: u8;
    static ev_user_execute: u8;
    static ev_user_stack: u8;
    static ev_user_stack_ok: u8;
    static ev_user_io: u8;
}
const CODE: u64 = FRAME_SIZE;
const DATA: u64 = 3 * FRAME_SIZE;
const STACK: u64 = 5 * FRAME_SIZE;
const PRIVATE: u64 = 7 * FRAME_SIZE;
pub(crate) type UserRoot = PrivateUserRoot<MAX_PRIVATE_PAGES>;
const SHARED_SLOTS: usize = if cfg!(feature = "test-m6-network") {
    4
} else if cfg!(feature = "test-m6-session") {
    3
} else {
    2
};
pub(crate) struct PrivateUserRoot<const N: usize> {
    tables: [PhysicalFrame; 4],
    mappings: PrivateUserMappings<N>,
    leaf: *mut u64,
    offset: u64,
    bits: u8,
    shared: [Option<(u64, MappingLease)>; SHARED_SLOTS],
}
#[cfg(feature = "test-m8-workspace")]
pub(crate) struct CapturedIoBuffer<'a> {
    span: ev_kernel::user::PrivateIoBuffer<'a>,
    offset: u64,
    bits: u8,
}
#[cfg(feature = "test-m8-workspace")]
impl CapturedIoBuffer<'_> {
    pub fn snapshot(&self, bytes: &mut [u8; 512]) -> Result<(), &'static str> {
        self.span.read(&mut IoRam(self.offset, self.bits), bytes)
    }
    pub fn publish(&self, bytes: &[u8; 512]) -> Result<(), &'static str> {
        self.span.write(&mut IoRam(self.offset, self.bits), bytes)
    }
}
#[cfg(feature = "test-m8-workspace")]
struct IoRam(u64, u8);
#[cfg(feature = "test-m8-workspace")]
// SAFETY: exact affine RAM frame and checked byte through retained direct map;
// volatile byte access creates no persistent alias and never targets MMIO.
unsafe impl ev_kernel::memory_extent::RamAccess for IoRam {
    type Error = &'static str;
    fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, Self::Error> {
        if byte >= FRAME_SIZE as usize {
            return Err("PIO RAM byte");
        }
        let p = direct_address(self.0, frame.start(), self.1).map_err(|_| "PIO direct map")?;
        // SAFETY: exact retained frame and bounded byte, checked direct mapping.
        Ok(unsafe { (p as *const u8).add(byte).read_volatile() })
    }
    fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), Self::Error> {
        if byte >= FRAME_SIZE as usize {
            return Err("PIO RAM byte");
        }
        let p = direct_address(self.0, frame.start(), self.1).map_err(|_| "PIO direct map")?;
        // SAFETY: actual exclusive private RAM while its user owner is captured.
        unsafe { (p as *mut u8).add(byte).write_volatile(value) };
        Ok(())
    }
}

/// Captured V4 Root only. This borrows immutable root identity, while the
/// separate affine dynamic-table owner exclusively authorizes actual writes.
#[cfg(feature = "test-m6-network")]
pub(crate) struct DynamicLeaf<'a, const N: usize> {
    root: &'a PrivateUserRoot<N>,
    table: u64,
}
#[cfg(feature = "test-m6-network")]
impl<const N: usize> DynamicLeaf<'_, N> {
    pub fn root(&self) -> u64 {
        self.root.root()
    }
    pub fn table(&self) -> u64 {
        self.table
    }
    pub fn private_entry(&self, index: usize) -> Result<u64, &'static str> {
        if index >= 512 {
            return Err("dynamic private index");
        }
        // SAFETY: exact retained Root PT0, checked index under captured guard.
        Ok(unsafe { self.root.leaf.add(index).read_volatile() })
    }
    pub fn exclusive_user_branch(&self) -> Result<(), &'static str> {
        let slot = (self.root.base() >> 39) as usize;
        for i in 0..512 {
            // SAFETY: actual retained Root tables, captured IF0/AP exclusion.
            let pml4 = unsafe {
                self.root
                    .pointer(self.root.tables[0].start())
                    .add(i)
                    .read_volatile()
            };
            if i != slot && pml4 & USER != 0 {
                return Err("foreign user root branch");
            }
            if i == slot
                && pml4 & !((1 << 5) | (1 << 6))
                    != self.root.tables[1].start() | PRESENT | WRITABLE | USER
            {
                return Err("foreign current user branch");
            }
            // SAFETY: actual retained private PDPT, checked loop index.
            let pdpt = unsafe {
                self.root
                    .pointer(self.root.tables[1].start())
                    .add(i)
                    .read_volatile()
            };
            if i > 0 && pdpt != 0 {
                return Err("foreign user PDPT branch");
            }
            // SAFETY: actual retained private PD, checked loop index.
            let directory = unsafe { self.directory().add(i).read_volatile() };
            if i > 1 && directory != 0 {
                return Err("foreign Root data directory");
            }
        }
        Ok(())
    }
    fn directory(&self) -> *mut u64 {
        self.root.pointer(self.root.tables[2].start())
    }
    pub fn entry(&self, index: usize) -> Result<u64, &'static str> {
        if index >= 512 {
            return Err("dynamic leaf index");
        }
        // SAFETY: exact retained PT frame, checked index and captured IF0 owner.
        Ok(unsafe { self.root.pointer(self.table).add(index).read_volatile() })
    }
    pub fn attached(&self) -> Result<bool, &'static str> {
        // SAFETY: fixed PD1 of this exact retained private Root.
        let entry = unsafe { self.directory().add(1).read_volatile() } & !((1 << 5) | (1 << 6));
        if entry == 0 {
            return Ok(false);
        }
        if entry != self.table | PRESENT | WRITABLE | USER | (1 << 63) {
            return Err("foreign dynamic directory");
        }
        Ok(true)
    }
    /// # Safety
    /// Caller owns the actual initialized PT/control/extent and all partial
    /// receipts; the captured Root cannot resume until complete readback.
    pub unsafe fn write(&mut self, index: usize, entry: u64) -> Result<(), &'static str> {
        use ev_userspace_contract::root_v4::dynamic as d;
        if index >= 512 {
            return Err("dynamic leaf index");
        }
        if entry != 0 {
            let allowed = index == d::CONTROL
                || (d::STAGING_FIRST..d::STAGING_FIRST + d::WINDOW_PAGES).contains(&index)
                || d::READONLY_FIRST
                    .iter()
                    .any(|n| (*n..*n + d::WINDOW_PAGES).contains(&index));
            let flags = entry & !ADDRESS_MASK;
            if !allowed
                || entry & ADDRESS_MASK == 0
                || flags != PRESENT | USER | (1 << 63)
                    && flags != PRESENT | USER | WRITABLE | (1 << 63)
            {
                return Err("dynamic leaf permission");
            }
            if d::READONLY_FIRST
                .iter()
                .any(|n| (*n..*n + d::WINDOW_PAGES).contains(&index))
                && flags & WRITABLE != 0
            {
                return Err("writable dynamic reader");
            }
            if (index == d::CONTROL
                || (d::STAGING_FIRST..d::STAGING_FIRST + d::WINDOW_PAGES).contains(&index))
                && flags & WRITABLE == 0
            {
                return Err("readonly dynamic writer");
            }
        }
        // SAFETY: fixed checked data-only entry in the captured owned table.
        unsafe {
            self.root
                .pointer(self.table)
                .add(index)
                .write_volatile(entry)
        };
        if self.entry(index)? != entry {
            return Err("dynamic leaf readback");
        }
        Ok(())
    }
    /// # Safety
    /// All512 PT entries initialized/read back and retained; no other writer.
    pub unsafe fn attach(&mut self) -> Result<(), &'static str> {
        if self.attached()? {
            return Err("dynamic directory occupied");
        }
        // SAFETY: exclusive captured PD1, preflighted empty slot and real PT.
        unsafe {
            self.directory()
                .add(1)
                .write_volatile(self.table | PRESENT | USER | WRITABLE | (1 << 63))
        };
        if !self.attached()? {
            return Err("dynamic directory readback");
        }
        self.flush();
        Ok(())
    }
    pub fn flush(&self) {
        let current: u64;
        // SAFETY: constructor verified actual distinct controller CR3, IF0,
        // PCID off and parked APs. Reload flushes nonglobal user translations;
        // every future Root resume unconditionally reloads its own CR3.
        unsafe {
            asm!("mov {}, cr3",out(reg)current,options(nomem,nostack,preserves_flags));
            asm!("mov cr3, {}",in(reg)current,options(nostack,preserves_flags));
        }
    }
    /// # Safety
    /// Every user PTE detached/read back first, actual Root remains captured or
    /// terminated; owner retains this frame until flush and later scrub.
    pub unsafe fn detach(&mut self) -> Result<(), &'static str> {
        let attached = self.attached()?;
        for i in 0..512 {
            if self.entry(i)? != 0 {
                return Err("dynamic table still mapped");
            }
        }
        if !attached {
            return Ok(());
        }
        // SAFETY: actual owned empty PT under exclusive captured controller.
        unsafe { self.directory().add(1).write_volatile(0) };
        if self.attached()? {
            return Err("dynamic directory detach");
        }
        self.flush();
        Ok(())
    }
}

/// Narrow borrowed access to this root's owned PD. No raw pointer/general
/// mutation API escapes; only the fixed Display2/3 children may be installed.
#[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
pub(crate) struct DisplayDirectory<'a, const N: usize = MAX_PRIVATE_PAGES> {
    root: &'a mut PrivateUserRoot<N>,
}
#[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
pub(crate) struct SurfaceLeaf<'a, const N: usize = MAX_PRIVATE_PAGES> {
    root: &'a mut PrivateUserRoot<N>,
    window: ev_kernel::surface_layout::Window,
}
/// Selected V5's checked closed-window mapper owns all extent claims outside
/// private-page metadata. This guard never derives backing or authority.
#[cfg(feature = "test-m8-workspace")]
pub(crate) struct WorkspaceLeaf<'a, const N: usize> {
    root: &'a mut PrivateUserRoot<N>,
    first: usize,
    pages: usize,
}
#[cfg(feature = "test-m8-workspace")]
impl<const N: usize> WorkspaceLeaf<'_, N> {
    pub(crate) fn entry(&self, index: usize) -> Result<u64, &'static str> {
        if index < self.first || index >= self.first + self.pages {
            return Err("workspace leaf range");
        }
        // SAFETY: constructor checked the exact private leaf and finite range.
        Ok(unsafe { self.root.leaf.add(index).read_volatile() })
    }
    /// # Safety
    /// Retained actual extent lease authorizes this exact frame and permission;
    /// every target slot was preflighted before the first write. CPU is stopped.
    pub(crate) unsafe fn write(&mut self, index: usize, entry: u64) -> Result<(), &'static str> {
        self.entry(index)?;
        if entry != 0 {
            let flags = entry & !ADDRESS_MASK;
            if entry & ADDRESS_MASK == 0
                || !matches!(flags, 0x8000_0000_0000_0005 | 0x8000_0000_0000_0007)
            {
                return Err("workspace NX RAM flags");
            }
        }
        // SAFETY: actual inactive private leaf; borrowed finite checked range.
        unsafe { self.root.leaf.add(index).write_volatile(entry) };
        if self.entry(index)? != entry {
            return Err("workspace leaf readback");
        }
        Ok(())
    }
}
#[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
impl<const N: usize> SurfaceLeaf<'_, N> {
    pub(crate) fn root(&self) -> u64 {
        self.root.root()
    }
    pub(crate) fn base(&self) -> u64 {
        self.root.base()
    }
    pub(crate) fn physical(&self) -> u64 {
        self.root.tables[3].start()
    }
    pub(crate) fn entry(&self, index: usize) -> Result<u64, &'static str> {
        if !self.window.readable_entry(index) {
            return Err("surface leaf index");
        }
        // SAFETY: actual retained owned PT, checked index, exclusive borrow.
        Ok(unsafe { self.root.leaf.add(index).read_volatile() })
    }
    /// # Safety
    /// The caller owns the matching initialized RAM extent lease and checks
    /// every entry/guard before publication. Root remains inactive/quiescent.
    pub(crate) unsafe fn write(&mut self, index: usize, entry: u64) -> Result<(), &'static str> {
        if !self.window.writable_entry(index) {
            return Err("surface leaf index");
        }
        // SAFETY: exact checked fixed surface slot, actual owned inactive PT.
        unsafe {
            self.root.leaf.add(index).write_volatile(entry);
        }
        Ok(())
    }
}
#[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
impl<const N: usize> DisplayDirectory<'_, N> {
    pub(crate) fn root(&self) -> u64 {
        self.root.root()
    }
    pub(crate) fn base(&self) -> u64 {
        self.root.base()
    }
    pub(crate) fn entry(&self, index: usize) -> Result<u64, &'static str> {
        if !(1..=4).contains(&index) {
            return Err("display directory index");
        }
        // SAFETY: constructor owns inactive root/PD and checked exact index.
        Ok(unsafe {
            self.root
                .pointer(self.root.tables[2].start())
                .add(index)
                .read_volatile()
        })
    }
    pub(crate) fn preflight_empty(&self) -> Result<(), &'static str> {
        for index in 1..=4 {
            if self.entry(index)? != 0 {
                return Err("display aperture/guards occupied");
            }
        }
        Ok(())
    }
    /// Caller owns both unique PT frames, filled privately and checked against
    /// the actual Display lease/source. No failure after this method begins its
    /// final two writes is attributable to untrusted input.
    pub(crate) unsafe fn attach(&mut self, tables: [u64; 2]) -> Result<(), &'static str> {
        self.preflight_empty()?;
        if tables[0] == tables[1]
            || tables.iter().any(|physical| {
                *physical == 0
                    || !physical.is_multiple_of(FRAME_SIZE)
                    || *physical & ADDRESS_MASK != *physical
                    || self
                        .root
                        .tables
                        .iter()
                        .any(|frame| frame.start() == *physical)
            })
        {
            return Err("display table backing");
        }
        let pointer = self.root.pointer(self.root.tables[2].start());
        // SAFETY: unique actual owned inactive PD; both indexes/claims passed
        // all preflights and no user/AP may observe partial publication.
        unsafe {
            pointer
                .add(2)
                .write_volatile(tables[0] | PRESENT | WRITABLE | USER | (1 << 63));
            pointer
                .add(3)
                .write_volatile(tables[1] | PRESENT | WRITABLE | USER | (1 << 63));
        }
        Ok(())
    }
    pub(crate) unsafe fn detach(&mut self, tables: [u64; 2]) -> Result<(), &'static str> {
        for (i, physical) in tables.into_iter().enumerate() {
            let actual = self.entry(i + 2)? & !((1 << 5) | (1 << 6));
            if actual != (physical | PRESENT | WRITABLE | USER | (1 << 63)) {
                return Err("foreign display directory");
            }
        }
        if self.entry(1)? != 0 || self.entry(4)? != 0 {
            return Err("display guard changed");
        }
        let pointer = self.root.pointer(self.root.tables[2].start());
        // SAFETY: same stopped/inactive ownership. PCID is off, no global leaves
        // exist and restoration to the controller CR3 already invalidated local
        // user translations. Other CPUs never used this root or are quiescent.
        unsafe {
            pointer.add(2).write_volatile(0);
            pointer.add(3).write_volatile(0);
        }
        Ok(())
    }
}
// Current owned metadata stays below half a hardware page, without changing the
// 512-entry PTE leaf, frame counts, bootstrap stack or shared-lease ownership.
const _: () = assert!(core::mem::size_of::<UserRoot>() <= 2048);
impl<const N: usize> PrivateUserRoot<N> {
    /// # Safety
    /// Actual admitted owner was captured on the sole BSP, controller CR3
    /// restored, IF0/AP exclusion and all private claims retained throughout.
    #[cfg(feature = "test-m8-workspace")]
    pub(crate) unsafe fn io_buffer_captured(
        &self,
        address: u64,
        controller: u64,
    ) -> Result<CapturedIoBuffer<'_>, &'static str> {
        let (current, cr4, flags): (u64, u64, u64);
        // SAFETY: privileged readback of actual captured CPU state only.
        unsafe {
            asm!("mov {}, cr3", out(reg) current, options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if current & ADDRESS_MASK == self.root()
            || current & ADDRESS_MASK != controller & ADDRESS_MASK
            || cr4 & ((1 << 12) | (1 << 17)) != 0
            || flags & (1 << 9) != 0
        {
            return Err("PIO owner not captured");
        }
        let slot = (self.base() >> 39) as usize;
        // SAFETY: actual retained table frames, fixed own PML4 slot/PDPT0/PD0,
        // serialized IF0 capture. No user pointer selects a page-table frame.
        let path = unsafe {
            [
                self.pointer(self.tables[0].start())
                    .add(slot)
                    .read_volatile(),
                self.pointer(self.tables[1].start()).read_volatile(),
                self.pointer(self.tables[2].start()).read_volatile(),
            ]
        };
        ev_kernel::user::private_io_walk(&self.tables, path)
            .map_err(|_| "PIO private path mismatch")?;
        let span = self
            .mappings
            .io_buffer(address, |index| {
                // SAFETY: bounded PT index from the exact retained private ledger.
                Ok(unsafe { self.leaf.add(index).read_volatile() })
            })
            .map_err(|_| "PIO requires exact private RW/NX span")?;
        // Every physical address is checked before the first copy or IN/OUT.
        for frame in span.frames() {
            direct_address(self.offset, frame.start(), self.bits).map_err(|_| "PIO direct map")?;
        }
        Ok(CapturedIoBuffer {
            span,
            offset: self.offset,
            bits: self.bits,
        })
    }
    /// # Safety
    /// Actual admitted Root was captured on BSP with controller CR3 restored,
    /// IF0, APs parked; caller owns this exact PT frame and no aliasing writer.
    /// This grants only PD1/fixed data entries, never general image mutation.
    #[cfg(feature = "test-m6-network")]
    pub(crate) unsafe fn dynamic_leaf_captured(
        &self,
        table: &PhysicalFrame,
        controller: u64,
    ) -> Result<DynamicLeaf<'_, N>, &'static str> {
        let (current, cr4, flags): (u64, u64, u64);
        // SAFETY: privileged actual capture readback, no user data operands.
        unsafe {
            asm!("mov {}, cr3",out(reg)current,options(nomem,nostack,preserves_flags));
            asm!("mov {}, cr4",out(reg)cr4,options(nomem,nostack,preserves_flags));
            asm!("pushfq","pop {}",out(reg)flags,options(preserves_flags));
        }
        if current & ADDRESS_MASK == self.root()
            || current & ADDRESS_MASK != controller & ADDRESS_MASK
            || cr4 & ((1 << 12) | (1 << 17)) != 0
            || flags & (1 << 9) != 0
            || self
                .tables
                .iter()
                .chain(self.mappings.frames())
                .any(|f| f.start() == table.start())
        {
            return Err("invalid captured dynamic root");
        }
        let leaf = DynamicLeaf {
            root: self,
            table: table.start(),
        };
        leaf.attached()?;
        Ok(leaf)
    }
    /// # Safety
    /// Same physical-memory/CPU conditions as new. The measured image's selected
    /// root slot must be absent from the original root. This root remains inactive
    /// until all initialized bytes and permissions have been checked below.
    pub(crate) unsafe fn load_image(
        offset: u64,
        bits: u8,
        original: u64,
        image: &ev_kernel::executable::Image<'_>,
        startup: Option<&[u8; ev_userspace_contract::SIZE]>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        if image.layout() != ev_kernel::executable::LayoutReservation::Legacy {
            return Err("graphics layout needs owned graphics executable loader");
        }
        // SAFETY: same private image/root ownership; legacy adds no tables.
        unsafe { Self::load_private_backing(offset, bits, original, image, startup, frames) }
    }
    /// # Safety
    /// Same initialization/exclusion as load_image. This returns only private
    /// backing. For a display reservation the caller must retain both extra PT
    /// frames and the exact device lease before implementing LoadedExecutable
    /// with that layout; this partial owner alone cannot pass admission.
    pub(crate) unsafe fn load_private_backing(
        offset: u64,
        bits: u8,
        original: u64,
        image: &ev_kernel::executable::Image<'_>,
        startup: Option<&[u8; ev_userspace_contract::SIZE]>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        let record = startup
            .map(ev_kernel::startup_record::Record::service_v1)
            .transpose()
            .map_err(|_| "invalid v1 startup")?;
        // SAFETY: identical owner/exclusion preconditions; typed service record only.
        unsafe { Self::load_private_record(offset, bits, original, image, record, frames) }
    }
    /// # Safety
    /// Actual held RootV2 plan/bytes/allocator, restored controller CR3/IF0/AP
    /// exclusion; identical physical backing ownership as load_image.
    #[cfg(all(feature = "test-m4-desktop", not(feature = "test-m5-native")))]
    pub(crate) unsafe fn load_root_v2(
        offset: u64,
        bits: u8,
        original: u64,
        image: &ev_kernel::executable::Image<'_>,
        startup: &[u8; ev_userspace_contract::root_v2::SIZE],
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        if image.startup_layout() != ev_kernel::executable::StartupLayout::RootV2
            || image.layout() != ev_kernel::executable::LayoutReservation::Legacy
        {
            return Err("not RootV2 private layout");
        }
        let record = ev_kernel::startup_record::Record::root_v2(startup)
            .map_err(|_| "invalid RootV2 startup")?;
        // SAFETY: forwards actual held/inactive Root-only physical ownership.
        unsafe { Self::load_private_record(offset, bits, original, image, Some(record), frames) }
    }
    /// # Safety
    /// Actual held native Root plan/bytes/allocator and restored CR3/IF0/AP
    /// exclusion. Package mappings belong to the separate outer native owner.
    #[cfg(all(feature = "test-m5-native", not(feature = "test-m6-network")))]
    pub(crate) unsafe fn load_native_root(
        offset: u64,
        bits: u8,
        original: u64,
        image: &ev_kernel::executable::Image<'_>,
        startup: &[u8; ev_userspace_contract::root_v2::native::SIZE],
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        if image.startup_layout() != ev_kernel::executable::StartupLayout::RootV2
            || image.layout() != ev_kernel::executable::LayoutReservation::Legacy
        {
            return Err("not native Root private layout");
        }
        let record = ev_kernel::startup_record::Record::native_root(startup)
            .map_err(|_| "invalid native Root startup")?;
        // SAFETY: same checked physical loader; typed record remains profile3.
        unsafe { Self::load_private_record(offset, bits, original, image, Some(record), frames) }
    }
    /// # Safety
    /// Exact held V4 plan, restored controller CR3/IF0 and exclusive allocator.
    /// A V3 record cannot pass this named parser or the plan-layout check.
    #[cfg(feature = "test-m6-network")]
    pub(crate) unsafe fn load_root_v4(
        offset: u64,
        bits: u8,
        original: u64,
        image: &ev_kernel::executable::Image<'_>,
        startup: &[u8; ev_userspace_contract::root_v4::SIZE],
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        if image.startup_layout() != ev_kernel::executable::StartupLayout::RootV4
            || image.layout() != ev_kernel::executable::LayoutReservation::Legacy
        {
            return Err("not RootV4 private layout");
        }
        let record = ev_kernel::startup_record::Record::root_v4(startup)
            .map_err(|_| "invalid RootV4 startup")?;
        // SAFETY: same owned inactive loader; exact typed V4 record above.
        unsafe { Self::load_private_record(offset, bits, original, image, Some(record), frames) }
    }
    /// # Safety
    /// Same actual initialized private-frame/root ownership as the named wrappers.
    /// The private typed record has already parsed its exact version/length.
    pub(crate) unsafe fn load_private_record(
        offset: u64,
        bits: u8,
        original: u64,
        image: &ev_kernel::executable::Image<'_>,
        startup: Option<ev_kernel::startup_record::Record<'_>>,
        frames: &mut BootstrapFrames,
    ) -> Result<Self, &'static str> {
        if image.bootstrap_page().is_some() != startup.is_some() {
            return Err("bootstrap layout mismatch");
        }
        if image.pages().count() + 1 + usize::from(startup.is_some()) > N {
            return Err("insufficient private mapping metadata");
        }
        if let Some(record) = startup {
            record
                .check_layout(image.startup_layout())
                .map_err(|_| "startup version/plan mismatch")?;
        }
        let old = direct_address(offset, original, bits).map_err(|_| "invalid retained root")?
            as *const u64;
        // SAFETY: retained original hierarchy is readable; parser bounds the slot.
        if unsafe { old.add(image.slot()).read_volatile() } != 0 {
            return Err("executable window conflicts with retained root");
        }
        if frames.remaining_frames() < image.private_required_frames() {
            return Err("insufficient executable frames");
        }
        // SAFETY: preflight covers all four tables, image and stack frames; no
        // concurrent allocator or mapping owner can consume them during this call.
        let mut root = unsafe { Self::new(offset, bits, original, image.slot(), frames) };
        let mut expected = [0u8; FRAME_SIZE as usize];
        for page in image.pages() {
            page.copy_into(&mut expected);
            // SAFETY: bounded, distinct image pages in a fresh inactive root;
            // page allocates/zeroes exclusive RAM before installing the leaf.
            unsafe {
                let pointer = root
                    .page(frames, page.address - image.base(), page.permission)
                    .cast::<u8>();
                ptr::copy_nonoverlapping(expected.as_ptr(), pointer, expected.len());
                for (i, byte) in expected.iter().enumerate() {
                    assert_eq!(pointer.add(i).read_volatile(), *byte);
                }
                let entry = root
                    .leaf
                    .add(root.mappings.index(page.address).unwrap())
                    .read_volatile();
                assert_eq!(entry, root.mappings.entry(page.address).unwrap());
            }
        }
        if let Some(record) = startup {
            // SAFETY: reserved page is distinct from every image/stack/guard page;
            // it is fully zeroed, filled and read back before any user admission.
            unsafe {
                let pointer = root
                    .page(
                        frames,
                        ev_kernel::executable::BOOTSTRAP_PAGE,
                        UserPermission::ReadOnly,
                    )
                    .cast::<u8>();
                ptr::copy_nonoverlapping(record.bytes().as_ptr(), pointer, record.bytes().len());
                for i in 0..FRAME_SIZE as usize {
                    assert_eq!(
                        pointer.add(i).read_volatile(),
                        record.bytes().get(i).copied().unwrap_or(0)
                    );
                }
            }
        }
        // SAFETY: separate NX stack at the bounded final page; both the lowest
        // window page and the page immediately below this stack remain unmapped.
        unsafe {
            root.page(
                frames,
                ev_kernel::executable::STACK_PAGE,
                UserPermission::ReadWrite,
            );
        }
        assert_eq!(root.mappings.entry(image.base()), Ok(0));
        assert_eq!(root.mappings.entry(image.stack_page() - FRAME_SIZE), Ok(0));
        Ok(root)
    }
    fn pointer(&self, frame: u64) -> *mut u64 {
        direct_address(self.offset, frame, self.bits).expect("direct RAM address") as *mut u64
    }
    /// # Safety
    /// Valid retained direct map and original root; exclusive bootstrap frames,
    /// one CPU, interrupts off. The chosen root slot must be unused.
    pub(crate) unsafe fn new(
        offset: u64,
        bits: u8,
        original: u64,
        slot: usize,
        frames: &mut BootstrapFrames,
    ) -> Self {
        let tables = core::array::from_fn(|_| frames.allocate().expect("user table frame"));
        let mut result = Self {
            tables,
            mappings: PrivateUserMappings::new(slot).expect("user slot"),
            leaf: ptr::null_mut(),
            offset,
            bits,
            shared: [const { None }; SHARED_SLOTS],
        };
        let pointers = result
            .tables
            .each_ref()
            .map(|frame| result.pointer(frame.start()));
        result.leaf = pointers[3];
        let old = result.pointer(original);
        // SAFETY: all frames are unique RAM claims. Only our own tables change;
        // inherited branches are retained and forced supervisor-only at the root.
        unsafe {
            for pointer in pointers {
                ptr::write_bytes(pointer, 0, ENTRIES);
            }
            assert_eq!(old.add(slot).read_volatile(), 0);
            for i in 0..ENTRIES {
                pointers[0]
                    .add(i)
                    .write_volatile(old.add(i).read_volatile() & !USER);
            }
            pointers[0]
                .add(slot)
                .write_volatile(result.tables[1].start() | PRESENT | WRITABLE | USER);
            pointers[1].write_volatile(result.tables[2].start() | PRESENT | WRITABLE | USER);
            pointers[2].write_volatile(result.tables[3].start() | PRESENT | WRITABLE | USER);
        }
        result
    }
    pub(crate) fn base(&self) -> u64 {
        self.mappings.base()
    }
    pub(crate) fn root(&self) -> u64 {
        self.tables[0].start()
    }
    /// Read-only evidence from this image's retained private RAM ownership,
    /// excluding separately leased shared/catalogue/package mappings.
    #[cfg(feature = "test-m5-native")]
    pub(crate) fn private_entry(&self, relative: u64) -> Option<u64> {
        let address = self.base().checked_add(relative)?;
        self.mappings
            .entry(address)
            .ok()
            .filter(|entry| *entry != 0)
    }
    /// # Safety
    /// Serialized controller, APs parked, actual process held or all its threads
    /// exited, no pending dispatch/reference. This is its actual owned root;
    /// controller CR3 has been restored and user global mappings never existed.
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn display_directory_inactive(
        &mut self,
    ) -> Result<DisplayDirectory<'_, N>, &'static str> {
        let (current, cr4, flags): (u64, u64, u64);
        // SAFETY: privileged control-register readback of actual CPU state.
        unsafe {
            asm!("mov {}, cr3",out(reg)current,options(nomem,nostack,preserves_flags));
            asm!("mov {}, cr4",out(reg)cr4,options(nomem,nostack,preserves_flags));
            asm!("pushfq","pop {}",out(reg)flags,options(preserves_flags));
        }
        if current & ADDRESS_MASK == self.root()
            || cr4 & ((1 << 12) | (1 << 17)) != 0
            || flags & (1 << 9) != 0
        {
            return Err("display root is active or unsupported CPU state");
        }
        Ok(DisplayDirectory { root: self })
    }
    /// # Safety
    /// Same held/stopped/controller-CR3 exclusion as display_directory_inactive.
    #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
    pub(crate) unsafe fn surface_leaf_inactive(
        &mut self,
    ) -> Result<SurfaceLeaf<'_, N>, &'static str> {
        // SAFETY: forwarded exact CPU/root exclusion; drop narrow PD borrow
        // before returning the separate fixed-surface PT borrow.
        unsafe {
            self.display_directory_inactive()?;
        }
        Ok(SurfaceLeaf {
            root: self,
            window: ev_kernel::surface_layout::Window::Primary,
        })
    }
    /// # Safety
    /// Same held/stopped/inactive root exclusion, only fixed304..366 plus guards.
    #[cfg(feature = "test-m4-desktop")]
    pub(crate) unsafe fn surface_auxiliary_leaf_inactive(
        &mut self,
    ) -> Result<SurfaceLeaf<'_, N>, &'static str> {
        // SAFETY: same actual root/CR3/IF0/PCID checks as the primary guard.
        unsafe {
            self.display_directory_inactive()?;
        }
        Ok(SurfaceLeaf {
            root: self,
            window: ev_kernel::surface_layout::Window::Auxiliary,
        })
    }
    /// # Safety
    /// Selected typed load plan, actual held/stopped root and controller CR3 at
    /// IF0/PCID0/AP exclusion. The trusted V5 mapper fixes the closed range and
    /// retains every real extent lease until all PTEs are detached/read back.
    #[cfg(feature = "test-m8-workspace")]
    pub(crate) unsafe fn workspace_leaf_inactive(
        &mut self,
        first: usize,
        pages: usize,
    ) -> Result<WorkspaceLeaf<'_, N>, &'static str> {
        if pages == 0 || first == 0 || first.checked_add(pages).is_none_or(|end| end > 509) {
            return Err("workspace leaf bounds");
        }
        // SAFETY: same captured actual root/IF/PCID exclusion as Display guard.
        unsafe {
            self.display_directory_inactive()?;
        }
        Ok(WorkspaceLeaf {
            root: self,
            first,
            pages,
        })
    }
    #[cfg(feature = "test-m8-workspace")]
    pub(crate) fn workspace_entry(&self, index: usize) -> Result<u64, &'static str> {
        if index >= 512 {
            return Err("workspace entry index");
        }
        // SAFETY: retained actual immutable PT; serialized controller read only.
        Ok(unsafe { self.leaf.add(index).read_volatile() })
    }
    #[cfg(feature = "test-m8-workspace")]
    pub(crate) fn workspace_private_entry(&self, index: usize) -> Result<u64, &'static str> {
        if index >= 512 {
            return Err("workspace private index");
        }
        self.mappings
            .entry(self.base() + index as u64 * FRAME_SIZE)
            .map_err(|_| "workspace private metadata")
    }
    fn code_label(&self, label: *const u8) -> u64 {
        let delta = (label as u64)
            .checked_sub(ptr::addr_of!(ev_user_blob) as u64)
            .expect("user label");
        assert!(delta < FRAME_SIZE);
        self.base() + CODE + delta
    }
    /// # Safety
    /// Our retained direct map covers this exclusively allocated frame. This
    /// root is not active or has never mapped this address; all slots are unique.
    pub(crate) unsafe fn page(
        &mut self,
        frames: &mut BootstrapFrames,
        relative: u64,
        permission: UserPermission,
    ) -> *mut u64 {
        let address = self
            .base()
            .checked_add(relative)
            .expect("private user address");
        self.mappings
            .index(address)
            .expect("private user leaf index");
        assert_eq!(
            self.mappings.entry(address),
            Ok(0),
            "private user mapping occupied"
        );
        assert!(
            !self
                .shared
                .iter()
                .flatten()
                .any(|(shared, _)| *shared == address),
            "private mapping overlaps shared lease"
        );
        assert!(
            self.mappings.frames().count() < N,
            "private user mapping capacity"
        );
        let frame = frames.allocate().expect("user data frame");
        let pointer = self.pointer(frame.start());
        // SAFETY: fresh exclusively claimed RAM; force dirty bytes before zeroing
        // and observe every word before exposing it at user privilege.
        unsafe {
            for i in 0..ENTRIES {
                pointer.add(i).write_volatile(u64::MAX);
            }
            ptr::write_bytes(pointer, 0, ENTRIES);
            for i in 0..ENTRIES {
                assert_eq!(pointer.add(i).read_volatile(), 0);
            }
        }
        self.mappings
            .map(address, frame, permission)
            .expect("private user mapping");
        let index = self.mappings.index(address).expect("user leaf index");
        // SAFETY: checked leaf in our live table, no concurrent users or APs.
        unsafe {
            self.leaf
                .add(index)
                .write_volatile(self.mappings.entry(address).expect("user entry"));
        }
        pointer
    }
    /// # Safety
    /// Serialized BSP owner, AP never uses this root, PCID off. The backing
    /// object is initialized and retained for the returned mapping's lifetime.
    pub(crate) unsafe fn map_shared(
        &mut self,
        lease: MappingLease,
        relative: u64,
    ) -> Result<(), MappingLease> {
        let Some(address) = self.base().checked_add(relative) else {
            return Err(lease);
        };
        let Ok(index) = self.mappings.index(address) else {
            return Err(lease);
        };
        if self.shared.iter().flatten().any(|(a, _)| *a == address)
            || self.mappings.entry(address) != Ok(0)
        {
            return Err(lease);
        }
        let Some(slot) = self.shared.iter().position(Option::is_none) else {
            return Err(lease);
        };
        let entry = lease.physical()
            | PRESENT
            | USER
            | ev_kernel::mapping::NO_EXECUTE
            | if lease.writable() { WRITABLE } else { 0 };
        // SAFETY: validated unused leaf and retained backing. Invalidate any
        // cached nonpresent translation if this is the current process root.
        unsafe {
            self.leaf.add(index).write_volatile(entry);
            asm!("invlpg [{}]", in(reg) address, options(nostack,preserves_flags));
        }
        self.shared[slot] = Some((address, lease));
        Ok(())
    }
    /// An immutable view of an existing lease; no physical ownership or mutable
    /// page-table access escapes this root. Used by prebound-image validation.
    #[cfg(any(
        feature = "test-m3-pio-write",
        feature = "test-m3-pio-verify",
        feature = "test-m4-desktop"
    ))]
    pub(crate) fn shared_mapping(&self, relative: u64) -> Option<&MappingLease> {
        let address = self.base().checked_add(relative)?;
        self.shared
            .iter()
            .flatten()
            .find_map(|(mapped, lease)| (*mapped == address).then_some(lease))
    }
    /// # Safety
    /// Same quiescence/root conditions as unmap_shared; no process can run
    /// between authority mutation, this invalidation scan and its next dispatch.
    pub(crate) unsafe fn discard_invalid_shared(
        &mut self,
        authority: &ev_kernel::capability::Authority,
        object: &mut MemoryObject,
    ) -> Option<(u64, ev_kernel::memory_object::Error)> {
        let (address, lease) = self
            .shared
            .iter()
            .flatten()
            .find(|(_, lease)| object.owns_mapping(lease))?;
        let error = object.validate_mapping(authority, lease).err()?;
        let address = *address;
        // SAFETY: caller keeps the root inactive and all CPUs quiescent.
        unsafe {
            self.unmap_shared(object);
        }
        Some((address, error))
    }
    /// # Safety
    /// Process quiescent, IF=0, AP never used this root, PCID off and nonglobal
    /// mappings. Controller has switched away; no outstanding backing aliases.
    pub(crate) unsafe fn unmap_shared(&mut self, object: &mut MemoryObject) {
        let current: u64;
        // SAFETY: privileged readback before any leaf/lease mutation.
        unsafe {
            asm!("mov {}, cr3", out(reg) current, options(nomem,nostack,preserves_flags));
        }
        assert_ne!(
            current & ADDRESS_MASK,
            self.root(),
            "cannot unmap active shared root"
        );
        for slot in &mut self.shared {
            if !slot
                .as_ref()
                .is_some_and(|(_, lease)| object.owns_mapping(lease))
            {
                continue;
            }
            let (address, lease) = slot.take().unwrap();
            let index = self.mappings.index(address).unwrap();
            // SAFETY: inactive exclusive leaf; CR3 switch already invalidated
            // local translations and no AP has used this private root.
            unsafe {
                self.leaf.add(index).write_volatile(0);
            }
            object.unmap(lease).expect("matching shared mapping lease");
        }
    }
    pub(crate) fn activate(&self) {
        // SAFETY: constructor preserves privileged boot/stack/descriptor maps;
        // all tables remain live. PCID off; private leaves are never global.
        unsafe {
            asm!("mov cr3, {}", in(reg) self.root(), options(nostack, preserves_flags));
        }
    }
    /// # Safety
    /// All process threads stopped, APs never used this root (or acknowledged
    /// shootdown), IF=0, PCID off, no global user leaves or outstanding memory
    /// aliases. The caller has switched to a distinct retained root. Consumes
    /// ownership; no former pointer may be accessed after returning its frame.
    pub(crate) unsafe fn retire(self, frames: &mut BootstrapFrames) -> usize {
        let current: u64;
        // SAFETY: privileged readback before touching any mapping or claim.
        unsafe {
            asm!("mov {}, cr3", out(reg) current, options(nomem,nostack,preserves_flags));
        }
        assert_ne!(
            current & ADDRESS_MASK,
            self.root(),
            "cannot reclaim active user root"
        );
        assert!(
            self.shared.iter().all(Option::is_none),
            "shared leases must retire before private root"
        );
        // No graphics wrapper may retire the private root while a device child
        // table is still attached, even if its external receipt was misplaced.
        #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
        for index in 1..=4 {
            // SAFETY: actual inactive owned PD retained until all checks pass.
            let entry = unsafe {
                self.pointer(self.tables[2].start())
                    .add(index)
                    .read_volatile()
            };
            assert_eq!(
                entry, 0,
                "external graphics mapping must detach before private retirement"
            );
        }
        #[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
        for index in (384..=446).chain(304..=366) {
            let address = self.base() + index as u64 * FRAME_SIZE;
            // SAFETY: actual inactive owned PT; CPU accessed/dirty bits do not
            // alter ownership. Legacy private pages in this area remain legal.
            let actual = unsafe { self.leaf.add(index).read_volatile() } & !((1 << 5) | (1 << 6));
            assert_eq!(
                actual,
                self.mappings.entry(address).unwrap(),
                "external surface must detach before private retirement"
            );
        }
        assert!(
            self.mappings
                .frames()
                .chain(self.tables.iter())
                .all(|frame| frames.owns(frame)),
            "wrong root allocator"
        );
        assert!(
            frames.recycle_capacity() >= self.mappings.frames().count() + self.tables.len(),
            "root recycle capacity"
        );
        // SAFETY: exclusive inactive leaf table, no other CPU uses this root.
        unsafe {
            ptr::write_bytes(self.leaf, 0, ENTRIES);
        }
        let offset = self.offset;
        let bits = self.bits;
        let mut count = 0;
        for frame in self
            .mappings
            .into_frames()
            .into_iter()
            .flatten()
            .chain(self.tables)
        {
            let pointer = direct_address(offset, frame.start(), bits).expect("retired frame alias")
                as *mut u64;
            // SAFETY: quiescent exclusively owned RAM. Volatile scrubbing cannot
            // be elided at retirement; read back every word before returning it.
            unsafe {
                for i in 0..ENTRIES {
                    pointer.add(i).write_volatile(0);
                }
                for i in 0..ENTRIES {
                    assert_eq!(pointer.add(i).read_volatile(), 0);
                }
            }
            frames
                .reclaim(frame)
                .expect("retired frame recycle capacity/provenance");
            count += 1;
        }
        count
    }
    /// # Safety
    /// Root contains the copied finite fixture and stack; initialized descriptor
    /// entry is installed, one CPU and interrupts disabled, no nested user run.
    unsafe fn probe(
        &self,
        entry: *const u8,
        target: u64,
        value: u64,
        vector: u64,
        error: u64,
        fault_ip: u64,
    ) {
        self.activate();
        let expected = UserTrap {
            vector,
            error,
            ip: fault_ip,
            address: target,
            stack_top: self.base() + STACK + FRAME_SIZE,
        };
        // SAFETY: caller's finite fixture and root ownership satisfy run_user.
        unsafe {
            crate::traps::run_user(self.code_label(entry), target, value, expected);
        }
    }
}

pub struct Proof {
    pub roots: [u64; 2],
    pub traps: u64,
}
/// # Safety
/// Called after paging::prove and traps::install on the same sole bootstrap CPU.
/// Same retained direct mapping, no reclaimed frames, IF=0, NX/WP enabled, PCID off.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    let before = crate::traps::user_count();
    let original: u64;
    // SAFETY: ring-0 control register read, preserving flags and memory.
    unsafe {
        asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags));
    }
    let root = original & ADDRESS_MASK;
    assert!(frames.is_reserved_frame(root));
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 0xff) as u8;
    let old = direct_address(offset, root, bits).expect("original root alias") as *const u64;
    // SAFETY: original retained loader root is readable through the direct map.
    let slot = (1..256)
        .find(|&i| unsafe { old.add(i).read_volatile() == 0 })
        .expect("free lower-half root slot");
    // SAFETY: checked unused slot and exclusive allocator; retained direct map.
    let (mut a, mut b) = unsafe {
        (
            UserRoot::new(offset, bits, root, slot, frames),
            UserRoot::new(offset, bits, root, slot, frames),
        )
    };
    let blob = ptr::addr_of!(ev_user_blob);
    let length = (ptr::addr_of!(ev_user_blob_end) as usize)
        .checked_sub(blob as usize)
        .expect("fixture blob length");
    assert!(length > 0 && length < FRAME_SIZE as usize);
    const A: u64 = 0x41414141414141c3;
    const B: u64 = 0x42424242424242c3;
    const C: u64 = 0x43434343434343c3;
    let mut aliases = [ptr::null_mut(); 2];
    // SAFETY: inactive private roots; each code/data/stack frame is unique and
    // zeroed before user entry. Copy only the bounded assembly fixture blob.
    unsafe {
        for (index, space) in [&mut a, &mut b].into_iter().enumerate() {
            let code = space.page(frames, CODE, UserPermission::ReadExecute);
            ptr::copy_nonoverlapping(blob, code.cast::<u8>(), length);
            let data = space.page(frames, DATA, UserPermission::ReadWrite);
            data.write_volatile(if index == 0 { A } else { B });
            aliases[index] = data;
            space.page(frames, STACK, UserPermission::ReadWrite);
        }
        a.page(frames, PRIVATE, UserPermission::ReadOnly)
            .write_volatile(A);
    }
    let read = ptr::addr_of!(ev_user_read);
    let write = ptr::addr_of!(ev_user_write);
    let read_ok = a.code_label(ptr::addr_of!(ev_user_read_ok));
    let write_ok = a.code_label(ptr::addr_of!(ev_user_write_ok));
    let base = a.base();
    // SAFETY: all code sites are in the copied RX fixture. Exact expected traps
    // end each finite CPL3 run, returning to our saved supervisor stack. Inputs
    // name owned mappings or deliberately denied addresses; Rust never accesses
    // the user pointers. A denied NX probe is seeded with RET for bounded failure.
    unsafe {
        a.probe(read, base + DATA, A, 6, 0, read_ok);
        b.probe(read, base + DATA, B, 6, 0, read_ok);
        a.probe(read, base + DATA, A, 6, 0, read_ok);
        a.probe(write, base + DATA, C, 6, 0, write_ok);
        a.probe(read, base + DATA, C, 6, 0, read_ok);
        a.probe(write, base + CODE, 0x1234, 14, 7, a.code_label(write));
        a.probe(
            ptr::addr_of!(ev_user_execute),
            base + DATA,
            0,
            14,
            21,
            base + DATA,
        );
        a.probe(read, base + 4 * FRAME_SIZE, 0, 14, 4, a.code_label(read));
        a.probe(
            read,
            ptr::addr_of!(ev_user_blob) as u64,
            0,
            14,
            5,
            a.code_label(read),
        );
        a.probe(read, aliases[1] as u64, 0, 14, 5, a.code_label(read));
        a.probe(read, base + PRIVATE, A, 6, 0, read_ok);
        b.probe(read, base + PRIVATE, 0, 14, 4, b.code_label(read));
        a.probe(
            ptr::addr_of!(ev_user_stack),
            0,
            A,
            6,
            0,
            a.code_label(ptr::addr_of!(ev_user_stack_ok)),
        );
        a.probe(
            ptr::addr_of!(ev_user_io),
            0,
            0,
            13,
            0,
            a.code_label(ptr::addr_of!(ev_user_io)),
        );
        b.probe(read, base + DATA, B, 6, 0, read_ok);
        assert_eq!(aliases[0].read_volatile(), C);
        assert_eq!(aliases[1].read_volatile(), B);
        asm!("mov cr3, {}", in(reg) original, options(nostack, preserves_flags));
    }
    let restored: u64;
    // SAFETY: current ring-0 root remains live; readback and original branch are
    // checked without modifying the loader's retained hierarchy.
    unsafe {
        asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
        assert_eq!(restored, original);
        assert_eq!(old.add(slot).read_volatile(), 0);
        for space in [&a, &b] {
            let root = space.pointer(space.root());
            for i in 0..ENTRIES {
                if i != slot {
                    assert_eq!(root.add(i).read_volatile() & USER, 0);
                }
            }
        }
    }
    let traps = crate::traps::user_count() - before;
    assert_eq!(traps, 15);
    Proof {
        roots: [a.root(), b.root()],
        traps,
    }
}
