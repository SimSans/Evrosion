//! V4-only captured Root dynamic-code owners. No Drop releases hardware debt.
use crate::{
    desktop_runtime::Hardware, executable_runtime::NetworkLoadedRoot, user_space::DynamicLeaf,
};
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use ev_kernel::{
    capability::{Authority, Handle, Kind, Rights},
    dynamic_image::{
        self as core_image, Mappings, ReadOnlyRam, Retained, RootPermit, SealedImage, Staging,
    },
    mapping::{ADDRESS_MASK, NO_EXECUTE, PRESENT, WRITABLE, direct_address},
    memory::{BootstrapFrames, PhysicalFrame},
    memory_extent::{ExtentLease, MemoryExtent, RamAccess},
    scheduler::Scheduler,
    service::{Metadata, Registry},
    user::USER,
};
use ev_userspace_contract::root_v4::dynamic as abi;
const AD: u64 = (1 << 5) | (1 << 6);
mod policy;
type Leaf<'a> = DynamicLeaf<'a, { ev_kernel::executable::ROOT_V4_MAX_PRIVATE_PAGES }>;
#[derive(Clone, Copy)]
struct Binding {
    root: u64,
    table: u64,
    physical: u64,
    pages: usize,
    installed: bool,
}
struct Reader {
    lease: ExtentLease,
    binding: Binding,
}
struct Slot {
    owner: Option<Retained>,
    writer: Option<Binding>,
    reader: Option<Reader>,
    written: usize,
    failed: bool,
    actions: [u64; 3],
    object: Option<usize>,
    cut: u64,
}
impl Slot {
    const fn empty() -> Self {
        Self {
            owner: None,
            writer: None,
            reader: None,
            written: 0,
            failed: false,
            actions: [0; 3],
            object: None,
            cut: 0,
        }
    }
}
pub(crate) struct Scope(());
pub(crate) fn scope() -> Scope {
    Scope(())
}
pub(crate) struct State {
    table: Option<PhysicalFrame>,
    control: Option<PhysicalFrame>,
    origin: Option<Metadata>,
    attached: bool,
    poisoned: bool,
    slots: [Slot; 2],
    last_slot: Option<usize>,
}
struct Resident {
    claimed: AtomicBool,
    value: UnsafeCell<MaybeUninit<State>>,
}
// SAFETY: one permanent atomic claim; only its unique scoped mutable borrow
// accesses initialized owners. No reset, shared access or automatic Drop exists.
unsafe impl Sync for Resident {}
static RESIDENT: Resident = Resident {
    claimed: AtomicBool::new(false),
    value: UnsafeCell::new(MaybeUninit::uninit()),
};
impl State {
    pub fn begin_capture(&mut self) {
        self.last_slot = None;
    }
    pub fn snapshot(
        &self,
        op: u8,
        meta: Metadata,
        root_cr3: u64,
        tick: u64,
        result: Result<(u64, u64), u64>,
    ) -> crate::desktop_runtime::SessionDynamicImage {
        use crate::desktop_runtime::SessionDynamicImage;
        let (status, reason, cap) = match result {
            Ok((_, cap)) => (0, 0, cap),
            Err(reason) => (1, reason, 0),
        };
        let mut row = SessionDynamicImage {
            op,
            slot: 0,
            phase: 0,
            status,
            reason,
            process: meta.process.diagnostic_id(),
            thread: meta.thread.diagnostic_id(),
            job: meta.job.diagnostic_id(),
            tick,
            original_cut: 0,
            external_frames: self.external_frames(),
            root_cr3,
            table: self.table.as_ref().map_or(0, PhysicalFrame::start),
            control: self.control.as_ref().map_or(0, PhysicalFrame::start),
            declared_bytes: 0,
            pages: 0,
            verified_bytes: 0,
            elf_sha256: [0; 32],
            content_sha256: [0; 32],
            declared_package_id: [0; 32],
            returned_memory_capability: cap,
        };
        if let Some(index) = self.last_slot {
            let slot = &self.slots[index];
            row.slot = index as u8 + 1;
            row.phase = Self::phase(slot) as u8;
            row.original_cut = slot.cut;
            let spec = match &slot.owner {
                Some(Retained::Staging(o)) => {
                    row.pages = o.pages() as u64;
                    Some(o.specification())
                }
                Some(Retained::Sealing(o)) => {
                    row.pages = o.pages() as u64;
                    Some(o.specification())
                }
                Some(Retained::Sealed(o)) => {
                    row.pages = o.pages() as u64;
                    row.verified_bytes = o.specification().bytes as u64;
                    row.elf_sha256 = o.specification().elf_sha256;
                    row.content_sha256 = o.specification().sha256;
                    Some(o.specification())
                }
                _ => None,
            };
            if let Some(spec) = spec {
                row.declared_bytes = spec.bytes as u64;
                row.declared_package_id = spec.package;
            }
        }
        if self.poisoned || op == 0 && status != 0 {
            row.phase = 5;
        }
        row
    }
    pub fn external_frames(&self) -> u64 {
        u64::from(self.table.is_some()) + u64::from(self.control.is_some())
    }
    pub fn initialized(&self) -> bool {
        self.origin.is_some()
    }
    /// # Safety
    /// Actual captured Root, same controller CR3/IF0/AP conditions as mutation.
    pub unsafe fn check(
        &self,
        root: &NetworkLoadedRoot,
        a: &Authority,
        hw: Hardware,
    ) -> Result<(), u64> {
        if self.poisoned {
            return Err(7);
        }
        let Some(table) = self.table.as_ref() else {
            return Ok(());
        };
        // SAFETY: exact retained table and captured actual Root.
        let leaf = unsafe { root.dynamic_leaf_captured(table, hw.original) }.map_err(|_| 7u64)?;
        leaf.exclusive_user_branch().map_err(|_| 7u64)?;
        if !leaf.attached().map_err(|_| 7u64)? || !self.attached {
            return Err(7);
        }
        // The retained lease is checked once before walking actual PTEs. The
        // captured Kernel scope prevents authority changes during this walk.
        for slot in &self.slots {
            if let Some(reader) = &slot.reader {
                if !reader.binding.installed {
                    return Err(7);
                }
                let Some(Retained::Sealed(owner)) = &slot.owner else {
                    return Err(7);
                };
                owner
                    .extent()
                    .validate(a, &reader.lease)
                    .map_err(|_| 7u64)?;
            }
        }
        for index in 0..512 {
            let mut expected = if index == abi::CONTROL {
                self.control.as_ref().ok_or(7u64)?.start() | PRESENT | USER | WRITABLE | NO_EXECUTE
            } else {
                0
            };
            for (n, slot) in self.slots.iter().enumerate() {
                if let Some(binding) = slot.writer {
                    if !binding.installed {
                        return Err(7);
                    }
                    if (abi::STAGING_FIRST..abi::STAGING_FIRST + binding.pages).contains(&index) {
                        expected = (binding.physical + (index - abi::STAGING_FIRST) as u64 * 4096)
                            | PRESENT
                            | USER
                            | WRITABLE
                            | NO_EXECUTE;
                    }
                }
                if let Some(reader) = &slot.reader {
                    let first = abi::READONLY_FIRST[n];
                    if (first..first + reader.binding.pages).contains(&index) {
                        expected = (reader.binding.physical + (index - first) as u64 * 4096)
                            | PRESENT
                            | USER
                            | NO_EXECUTE;
                    }
                }
            }
            let raw = leaf.entry(index).map_err(|_| 7u64)?;
            if (if expected == 0 { raw } else { raw & !AD }) != expected {
                return Err(7);
            }
        }
        Ok(())
    }
    /// # Safety
    /// Exact held App/private slot and same captured allocator/Root ownership.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn load_app(
        &self,
        index: usize,
        registry: &Registry<'static>,
        a: &Authority,
        s: &Scheduler,
        caller: ev_kernel::capability::SpaceId,
        process: Handle,
        slot: &mut crate::graphics_image::GraphicsImage,
        meta: Metadata,
        record: &[u8; ev_userspace_contract::SIZE],
        hw: Hardware,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let Some(Retained::Sealed(owner)) = &self.slots.get(index).ok_or(1u64)?.owner else {
            return Err(3);
        };
        let view = View::new(hw, a, s, self.origin.ok_or(3u64)?, owner);
        let plan = registry
            .plan_sealed(a, caller, process, owner, &view)
            .map_err(|_| 3u64)?;
        // SAFETY: actual held App +exact short immutable plan, no source byte
        // reference escapes; existing loader retains every private image owner.
        unsafe {
            slot.load_private(
                &plan,
                meta,
                record,
                hw.offset,
                hw.bits,
                hw.original & ADDRESS_MASK,
                frames,
            )
        }
        .map_err(|_| 6)
    }
    /// # Safety
    /// Root terminated, domain closed, all children/loans stopped/forgotten,
    /// Active::finish returned this exact root. IF0/original CR3/APs retained.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn shutdown(
        &mut self,
        root: &NetworkLoadedRoot,
        a: &mut Authority,
        s: &mut Scheduler,
        registry: &mut Registry<'static>,
        frames: &mut BootstrapFrames,
        hw: Hardware,
    ) -> Result<(), u64> {
        self.last_slot = None;
        let Some(meta) = self.origin else {
            return Ok(());
        };
        if s.process_job(meta.process).map_err(|_| 2u64)? != meta.job
            || s.thread_process(meta.thread).map_err(|_| 2u64)? != meta.process
            || s.state(meta.thread).map_err(|_| 2u64)? != ev_kernel::scheduler::State::Exited
            || s.usage(meta.job, ev_kernel::scheduler::Resource::Processes)
                .map_err(|_| 2u64)?
                != 0
            || a.is_live_space(meta.domain)
        {
            return Err(2);
        }
        let table = self.table.as_ref().ok_or(7u64)?;
        // SAFETY: exact stopped Root+retained PT, actual controller exclusion.
        let mut leaf =
            unsafe { root.dynamic_leaf_captured(table, hw.original) }.map_err(|_| 7u64)?;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if let Some(Retained::Sealed(o)) = &mut slot.owner {
                if o.is_registered() {
                    registry
                        .unregister_sealed_stopped(a, s, o)
                        .map_err(|_| 4u64)?;
                }
                if let Some(r) = slot.reader.as_mut() {
                    detach_reader(&mut leaf, index, r, o)?;
                }
                if let Some(reader) = slot.reader.take()
                    && let Err((_e, lease)) = o.return_readonly(reader.lease)
                {
                    slot.reader = Some(Reader {
                        lease,
                        binding: reader.binding,
                    });
                    return Err(7);
                }
            }
            let Some(owner) = slot.owner.take() else {
                continue;
            };
            let mut maps = WriterMap {
                leaf: &mut leaf,
                record: &mut slot.writer,
                a: None,
            };
            let retired = match owner {
                Retained::Staging(o) => o.abort(a, &mut maps),
                Retained::Sealing(o) => o.abort(a, &mut maps),
                Retained::Sealed(o) => o.retire(a, &mut maps),
                Retained::Retired(o) => Ok(o),
                Retained::Uninitialized(o) => match o.release(frames, s, &mut Ram { hw }) {
                    Ok(()) => {
                        slot.object = None;
                        slot.failed = false;
                        continue;
                    }
                    Err(r) => {
                        slot.owner = Some(Retained::Uninitialized(r.owner));
                        return Err(7);
                    }
                },
                Retained::Initialized(o) => match o.release(frames, s, &mut Ram { hw }) {
                    Ok(()) => {
                        slot.object = None;
                        slot.failed = false;
                        continue;
                    }
                    Err(r) => {
                        slot.owner = Some(Retained::Initialized(r.owner));
                        return Err(7);
                    }
                },
            };
            match retired {
                Ok(o) => {
                    if let Err(r) = o.release(frames, s, &mut Ram { hw }) {
                        slot.owner = Some(Retained::Retired(r.owner));
                        return Err(7);
                    }
                }
                Err(r) => {
                    slot.owner = r.owner;
                    return Err(Self::error(r.error));
                }
            }
            slot.object = None;
            slot.failed = false;
        }
        let physical = self.control.as_ref().ok_or(7u64)?.start();
        let actual = leaf.entry(abi::CONTROL).map_err(|_| 7u64)? & !AD;
        if actual != physical | PRESENT | USER | WRITABLE | NO_EXECUTE && actual != 0 {
            return Err(7);
        }
        // SAFETY: exact retained private control, Root stopped and no observers.
        unsafe {
            leaf.write(abi::CONTROL, 0).map_err(|_| 7u64)?;
            leaf.detach().map_err(|_| 7u64)?;
        }
        self.attached = false;
        if frames.recycle_capacity() < 2 {
            return Err(9);
        }
        Self::zero(hw, self.control.as_ref().unwrap())?;
        Self::zero(hw, self.table.as_ref().unwrap())?;
        for cell in [&mut self.control, &mut self.table] {
            if let Some(frame) = cell.take()
                && let Err((_e, frame)) = frames.reclaim(frame)
            {
                *cell = Some(frame);
                return Err(9);
            }
        }
        s.release_frames(meta.job, abi::EXTERNAL_FRAMES)
            .map_err(|_| 7u64)?;
        self.origin = None;
        self.poisoned = false;
        Ok(())
    }
    /// The returned lifetime is that of the caller's execution scope; State
    /// owns no static package/process references. A second claim always refuses.
    pub fn claim(_scope: &mut Scope) -> Result<&mut Self, &'static str> {
        RESIDENT
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "dynamic owner already claimed")?;
        let p = RESIDENT.value.get().cast::<Self>();
        // SAFETY: exact aligned storage, sole permanent claim. Write fields in
        // place, including each large None slot separately, before reference.
        unsafe {
            let _: fn(State) = |State {
                                    table: _,
                                    control: _,
                                    origin: _,
                                    attached: _,
                                    poisoned: _,
                                    slots: _,
                                    last_slot: _,
                                }| {};
            core::ptr::addr_of_mut!((*p).table).write(None);
            core::ptr::addr_of_mut!((*p).control).write(None);
            core::ptr::addr_of_mut!((*p).origin).write(None);
            core::ptr::addr_of_mut!((*p).attached).write(false);
            core::ptr::addr_of_mut!((*p).poisoned).write(false);
            core::ptr::addr_of_mut!((*p).last_slot).write(None);
            for i in 0..2 {
                core::ptr::addr_of_mut!((*p).slots)
                    .cast::<Slot>()
                    .add(i)
                    .write(Slot::empty());
            }
            Ok(&mut *p)
        }
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    fn ptr(hw: Hardware, physical: u64) -> Result<*mut u8, u64> {
        direct_address(hw.offset, physical, hw.bits)
            .map(|a| a as *mut u8)
            .map_err(|_| 6)
    }
    fn zero(hw: Hardware, f: &PhysicalFrame) -> Result<(), u64> {
        let p = Self::ptr(hw, f.start())?;
        for i in 0..4096 {
            // SAFETY: actual uniquely retained allocator RAM, not MMIO.
            unsafe { p.add(i).write_volatile(0) };
        }
        for i in 0..4096 {
            // SAFETY: same initialized exclusively retained RAM, truthful readback.
            if unsafe { p.add(i).read_volatile() } != 0 {
                return Err(6);
            }
        }
        Ok(())
    }
    /// # Safety
    /// Caller has the actual Root capture/IF0/controller CR3/AP ownership.
    unsafe fn ensure(
        &mut self,
        root: &NetworkLoadedRoot,
        meta: Metadata,
        hw: Hardware,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        if self.poisoned {
            return Err(7);
        }
        if let Some(old) = self.origin {
            if old != meta {
                return Err(2);
            }
            return if self.attached { Ok(()) } else { Err(7) };
        }
        if frames.remaining_frames() < 2 {
            return Err(9);
        }
        s.charge_frames(meta.job, abi::EXTERNAL_FRAMES)
            .map_err(|_| 9u64)?;
        self.origin = Some(meta);
        self.table = Some(frames.allocate().map_err(|_| 7u64)?);
        self.control = Some(frames.allocate().map_err(|_| 7u64)?);
        Self::zero(hw, self.table.as_ref().unwrap())?;
        Self::zero(hw, self.control.as_ref().unwrap())?;
        // SAFETY: actual Root capture; both frame owners initialized above.
        let mut leaf =
            unsafe { root.dynamic_leaf_captured(self.table.as_ref().unwrap(), hw.original) }
                .map_err(|_| 7u64)?;
        leaf.exclusive_user_branch().map_err(|_| 7u64)?;
        for i in 0..512 {
            if leaf.entry(i).map_err(|_| 7u64)? != 0 {
                return Err(7);
            }
        }
        self.poisoned = true; // publication may have changed hardware until readback
        // SAFETY: exact private initialized control/PT owners and fixed slot.
        unsafe {
            leaf.write(
                abi::CONTROL,
                self.control.as_ref().unwrap().start() | PRESENT | USER | WRITABLE | NO_EXECUTE,
            )
            .map_err(|_| 7u64)?;
            leaf.attach().map_err(|_| 7u64)?;
        }
        self.attached = true;
        self.poisoned = false;
        Ok(())
    }
    pub fn handle_busy(&self, cap: Handle) -> bool {
        self.slots.iter().any(|slot| match &slot.owner {
            Some(Retained::Staging(o)) => o.writer() == Some(cap),
            Some(Retained::Sealing(o)) => o.root_handle() == Some(cap),
            Some(Retained::Sealed(o)) => o.root_handle() == cap,
            _ => false,
        })
    }
    pub fn object_slot(
        &self,
        a: &Authority,
        domain: ev_kernel::capability::SpaceId,
        cap: Handle,
    ) -> Option<usize> {
        let id = a
            .authorize(domain, cap, Kind::Memory, Rights::READ)
            .ok()?
            .identity();
        self.object_index(id).filter(
            |i| matches!(&self.slots[*i].owner,Some(Retained::Sealed(o)) if o.is_registered()),
        )
    }
    pub fn object_index(&self, object: usize) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.object == Some(object) && matches!(s.owner, Some(Retained::Sealed(_))))
    }
    pub fn image_sha(&self, slot: usize) -> Option<[u8; 32]> {
        match &self.slots.get(slot)?.owner {
            Some(Retained::Sealed(o)) => Some(o.specification().elf_sha256),
            _ => None,
        }
    }
    pub fn action(&mut self, slot: usize, kind: usize) -> Option<[u8; 32]> {
        let sha = self.image_sha(slot)?;
        let n = self.slots[slot].actions.get_mut(kind)?;
        *n = n.checked_add(1)?;
        Some(sha)
    }
    pub fn content_identity(&self, slot: usize) -> Option<([u8; 32], [u8; 32])> {
        match &self.slots.get(slot)?.owner {
            Some(Retained::Sealed(owner)) => {
                let spec = owner.specification();
                Some((spec.sha256, spec.package))
            }
            _ => None,
        }
    }
    fn phase(slot: &Slot) -> u64 {
        if slot.failed {
            return 5;
        }
        match &slot.owner {
            None => 0,
            Some(Retained::Staging(_)) => 1,
            Some(Retained::Sealing(_)) => 2,
            Some(Retained::Sealed(o)) => {
                if o.is_registered() {
                    4
                } else {
                    3
                }
            }
            _ => 5,
        }
    }
    fn error(e: core_image::Error) -> u64 {
        match e {
            core_image::Error::Mapping => 7,
            core_image::Error::Hash => 8,
            core_image::Error::Deadline | core_image::Error::Clock => 5,
            core_image::Error::Busy => 4,
            _ => 3,
        }
    }
    // All helpers below are called only after control's actual captured
    // Root/Creator/leaf checks. Separate branch frames keep unrelated large
    // affine construction/return slots out of the Seal preflight call chain.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn begin_operation(
        &mut self,
        leaf: &mut Leaf<'_>,
        hw: Hardware,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
        custody: ev_kernel::capability::SpaceId,
        permit: &RootPermit<'_, '_>,
        operand: u64,
        now: u64,
    ) -> Result<(u64, u64), u64> {
        if self.slots.iter().any(|s| {
            matches!(s.owner, Some(Retained::Staging(_) | Retained::Sealing(_))) || s.failed
        }) {
            return Err(4);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.owner.is_none())
            .ok_or(9u64)?;
        let mut header = [0; abi::HEADER_BYTES];
        let p = Self::ptr(hw, self.control.as_ref().unwrap().start())?;
        for (i, b) in header.iter_mut().enumerate() {
            // SAFETY: exact retained private control frame, fixed256 bytes.
            *b = unsafe { p.add(i).read_volatile() };
        }
        let h = abi::Header::decode(&header).ok_or(1u64)?;
        self.last_slot = Some(index);
        self.slots[index].cut = operand;
        let spec = core_image::Specification {
            bytes: h.bytes as usize,
            elf_offset: h.elf_offset as usize,
            elf_bytes: h.elf_bytes as usize,
            sha256: h.sha256,
            elf_sha256: h.elf_sha256,
            package: h.package,
            abi: h.abi,
            descriptor: h.descriptor,
        };
        let mut ram = Ram { hw };
        let slot = &mut self.slots[index];
        let mut owner =
            match Staging::allocate(a, s, frames, &mut ram, permit, custody, spec, now, operand) {
                Ok(o) => o,
                Err(r) => {
                    slot.owner = r.owner;
                    slot.failed = slot.owner.is_some();
                    return Err(Self::error(r.error));
                }
            };
        let mut maps = WriterMap {
            leaf,
            record: &mut slot.writer,
            a: Some(a),
        };
        if let Err(e) = owner.attach(a, s, permit, now, &mut maps) {
            slot.failed = true;
            self.poisoned = matches!(e, core_image::Error::Mapping);
            slot.owner = Some(Retained::Staging(owner));
            return Err(Self::error(e));
        }
        let cap = owner.writer().unwrap().0;
        slot.owner = Some(Retained::Staging(owner));
        Ok((index as u64 + 1, cap))
    }
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn verify_operation(
        slot: &mut Slot,
        poisoned: &mut bool,
        leaf: &mut Leaf<'_>,
        hw: Hardware,
        a: &mut Authority,
        s: &Scheduler,
        permit: &RootPermit<'_, '_>,
        now: u64,
        index: usize,
    ) -> Result<(u64, u64), u64> {
        let mut o = match slot.owner.take().ok_or(3u64)? {
            Retained::Sealing(o) => o,
            other => {
                slot.owner = Some(other);
                return Err(3);
            }
        };
        if let Err(e) = o.step(a, s, permit, now, &mut Ram { hw }) {
            slot.failed = true;
            slot.owner = Some(Retained::Sealing(o));
            return Err(Self::error(e));
        }
        let n = o.remaining();
        if n != 0 {
            slot.owner = Some(Retained::Sealing(o));
            return Ok((n as u64, 0));
        }
        let mut image = match o.finish(a, s, permit, now) {
            Ok(o) => o,
            Err(r) => {
                slot.failed = true;
                slot.owner = r.owner;
                return Err(Self::error(r.error));
            }
        };
        let lease = match image.map_readonly(a) {
            Ok(l) => l,
            Err(_) => {
                slot.owner = Some(Retained::Sealed(image));
                slot.failed = true;
                return Err(7);
            }
        };
        slot.reader = Some(Reader {
            binding: Binding {
                root: leaf.root(),
                table: leaf.table(),
                physical: image.physical(),
                pages: image.pages(),
                installed: false,
            },
            lease,
        });
        slot.owner = Some(Retained::Sealed(image));
        *poisoned = true;
        install_reader(leaf, index, slot, a)?;
        *poisoned = false;
        let Some(Retained::Sealed(image)) = &slot.owner else {
            unreachable!()
        };
        Ok((0, image.root_handle().0))
    }
    #[inline(never)]
    fn register_operation(
        slot: &mut Slot,
        hw: Hardware,
        meta: Metadata,
        a: &Authority,
        s: &Scheduler,
        registry: &mut Registry<'static>,
        permit: &RootPermit<'_, '_>,
    ) -> Result<(u64, u64), u64> {
        let Some(Retained::Sealed(o)) = &mut slot.owner else {
            return Err(3);
        };
        let view = View::new(hw, a, s, meta, o);
        registry
            .register_sealed(a, s, permit, o, &view)
            .map_err(|_| 3u64)?;
        slot.object = Some(
            a.authorize(meta.domain, o.root_handle(), Kind::Memory, Rights::READ)
                .map_err(|_| 2u64)?
                .identity(),
        );
        Ok((0, 0))
    }
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn abort_operation(
        slot: &mut Slot,
        poisoned: &mut bool,
        leaf: &mut Leaf<'_>,
        hw: Hardware,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
    ) -> Result<(u64, u64), u64> {
        if slot.reader.is_some() {
            return Err(4);
        };
        let owner = slot.owner.take().ok_or(3u64)?;
        let mut maps = WriterMap {
            leaf,
            record: &mut slot.writer,
            a: None,
        };
        let result = match owner {
            Retained::Staging(o) => o.abort(a, &mut maps),
            Retained::Sealing(o) => o.abort(a, &mut maps),
            Retained::Sealed(o) => o.retire(a, &mut maps),
            Retained::Retired(o) => Ok(o),
            Retained::Uninitialized(o) => {
                return match o.release(frames, s, &mut Ram { hw }) {
                    Ok(()) => {
                        slot.failed = false;
                        slot.written = 0;
                        Ok((0, 0))
                    }
                    Err(r) => {
                        slot.owner = Some(Retained::Uninitialized(r.owner));
                        Err(7)
                    }
                };
            }
            Retained::Initialized(o) => {
                return match o.release(frames, s, &mut Ram { hw }) {
                    Ok(()) => {
                        slot.failed = false;
                        slot.written = 0;
                        Ok((0, 0))
                    }
                    Err(r) => {
                        slot.owner = Some(Retained::Initialized(r.owner));
                        Err(7)
                    }
                };
            }
        };
        match result {
            Ok(o) => match o.release(frames, s, &mut Ram { hw }) {
                Ok(()) => {
                    slot.failed = false;
                    slot.written = 0;
                    Ok((0, 0))
                }
                Err(r) => {
                    slot.owner = Some(Retained::Retired(r.owner));
                    slot.failed = true;
                    Err(7)
                }
            },
            Err(r) => {
                *poisoned = matches!(r.error, core_image::Error::Mapping);
                slot.owner = r.owner;
                slot.failed = true;
                Err(Self::error(r.error))
            }
        }
    }
    /// # Safety
    /// Actual current Root+Creator permit and captured hardware proof. Returns
    /// scalar value and ONLY an actual newly installed/converted Memory cap.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn control(
        &mut self,
        root: &NetworkLoadedRoot,
        meta: Metadata,
        hw: Hardware,
        a: &mut Authority,
        s: &mut Scheduler,
        registry: &mut Registry<'static>,
        frames: &mut BootstrapFrames,
        custody: ev_kernel::capability::SpaceId,
        permit: &RootPermit<'_, '_>,
        op: abi::Operation,
        operand: u64,
        extra: u64,
        now: u64,
    ) -> Result<(u64, u64), u64> {
        self.last_slot = None;
        if op == abi::Operation::Initialize {
            // SAFETY: actual capture, not a user readiness assertion. Only
            // Initialize may allocate/publish the two external private frames.
            if let Err(reason) = unsafe { self.ensure(root, meta, hw, s, frames) } {
                if reason == 6 || reason == 7 {
                    self.poisoned = true;
                }
                return Err(reason);
            }
        } else if self.origin != Some(meta) || !self.attached || self.poisoned {
            return Err(3);
        }
        let table = self.table.as_ref().unwrap();
        // SAFETY: exact captured Root and retained initialized PT.
        let mut leaf =
            unsafe { root.dynamic_leaf_captured(table, hw.original) }.map_err(|_| 7u64)?;
        leaf.exclusive_user_branch().map_err(|_| 7u64)?;
        if op == abi::Operation::Initialize {
            return Ok((abi::VERSION, 0));
        }
        if op == abi::Operation::Inspect && operand == 0 {
            return Ok((
                match extra {
                    0 => root.base() + abi::REGION + abi::CONTROL as u64 * 4096,
                    1 => abi::VERSION,
                    2 => self.external_frames(),
                    _ => return Err(1),
                },
                0,
            ));
        }
        if op == abi::Operation::Begin {
            return self
                .begin_operation(&mut leaf, hw, a, s, frames, custody, permit, operand, now);
        }
        let index = usize::try_from(operand)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n < 2)
            .ok_or(1u64)?;
        let slot = &mut self.slots[index];
        self.last_slot = Some(index);
        if op == abi::Operation::Inspect {
            return Ok((
                match extra {
                    0 => Self::phase(slot),
                    1 => match &slot.owner {
                        Some(Retained::Staging(o)) => o.specification().bytes as u64,
                        Some(Retained::Sealing(o)) => o.specification().bytes as u64,
                        Some(Retained::Sealed(o)) => o.specification().bytes as u64,
                        _ => 0,
                    },
                    2 => slot.written as u64,
                    3 => match &slot.owner {
                        Some(Retained::Sealed(o)) => o.root_handle().0,
                        _ => 0,
                    },
                    4 => root.base() + abi::REGION + abi::READONLY_FIRST[index] as u64 * 4096,
                    5 => slot.actions[0],
                    6 => slot.actions[1],
                    7 => slot.actions[2],
                    8 => u64::from(slot.reader.is_some()),
                    _ => return Err(1),
                },
                0,
            ));
        }
        match op {
            abi::Operation::Written => {
                let Some(Retained::Staging(o)) = &mut slot.owner else {
                    return Err(3);
                };
                let n = (extra >> 32) as usize;
                o.chunk_written(a, s, permit, now, extra as u32 as usize, n)
                    .map_err(Self::error)?;
                slot.written += n;
                Ok((slot.written as u64, 0))
            }
            abi::Operation::Seal => {
                let o = match slot.owner.take().ok_or(3u64)? {
                    Retained::Staging(o) => o,
                    other => {
                        slot.owner = Some(other);
                        return Err(3);
                    }
                };
                let mut maps = WriterMap {
                    leaf: &mut leaf,
                    record: &mut slot.writer,
                    a: None,
                };
                match o.seal(a, s, permit, now, &mut maps) {
                    Ok(o) => {
                        let n = o.remaining();
                        slot.owner = Some(Retained::Sealing(o));
                        Ok((n as u64, 0))
                    }
                    Err(r) => {
                        self.poisoned = matches!(r.error, core_image::Error::Mapping);
                        slot.failed = true;
                        slot.owner = r.owner;
                        Err(Self::error(r.error))
                    }
                }
            }
            abi::Operation::Verify => Self::verify_operation(
                slot,
                &mut self.poisoned,
                &mut leaf,
                hw,
                a,
                s,
                permit,
                now,
                index,
            ),
            abi::Operation::Register => {
                Self::register_operation(slot, hw, meta, a, s, registry, permit)
            }
            abi::Operation::Unregister => {
                let Some(Retained::Sealed(o)) = &mut slot.owner else {
                    return Err(3);
                };
                registry
                    .unregister_sealed(a, s, permit, o)
                    .map_err(|_| 3u64)?;
                Ok((0, 0))
            }
            abi::Operation::Abort => {
                Self::abort_operation(slot, &mut self.poisoned, &mut leaf, hw, a, s, frames)
            }
            _ => Err(1),
        }
    }
}
struct Ram {
    hw: Hardware,
}
// SAFETY: trusted captured RAM owner only, checked exact allocator frame+byte;
// no mutable Rust reference/pointer survives an individual volatile operation.
unsafe impl RamAccess for Ram {
    type Error = u64;
    fn write(&mut self, f: &PhysicalFrame, n: usize, b: u8) -> Result<(), u64> {
        if n >= 4096 {
            return Err(6);
        }
        let p = State::ptr(self.hw, f.start())?;
        // SAFETY: exact retained frame and checked byte under captured owner.
        unsafe { p.add(n).write_volatile(b) };
        Ok(())
    }
    fn read(&mut self, f: &PhysicalFrame, n: usize) -> Result<u8, u64> {
        if n >= 4096 {
            return Err(6);
        }
        let p = State::ptr(self.hw, f.start())?;
        // SAFETY: exact retained frame+byte, no fabricated readback.
        Ok(unsafe { p.add(n).read_volatile() })
    }
}
struct WriterMap<'a, 'r> {
    leaf: &'a mut Leaf<'r>,
    record: &'a mut Option<Binding>,
    a: Option<&'a Authority>,
}
// SAFETY: private adapter constructed only with captured Root leaf and retained
// affine writer receipt. Unknown outcomes keep receipt and inhibit Root.
unsafe impl Mappings for WriterMap<'_, '_> {
    type Error = u64;
    fn install(&mut self, extent: &MemoryExtent, lease: &ExtentLease) -> Result<(), u64> {
        extent
            .validate(self.a.ok_or(7u64)?, lease)
            .map_err(|_| 7u64)?;
        if self.record.is_some() {
            return Err(7);
        };
        policy::empty(
            |i| self.leaf.entry(i).map_err(|_| policy::Error::Read),
            policy::Window::Writer,
        )
        .map_err(|_| 7u64)?;
        let physical = extent
            .physical_pages(lease)
            .map_err(|_| 7u64)?
            .next()
            .ok_or(7u64)?;
        for (i, p) in extent.physical_pages(lease).map_err(|_| 7u64)?.enumerate() {
            if p != physical + i as u64 * 4096 {
                return Err(7);
            }
            for j in 0..512 {
                let old = self.leaf.private_entry(j).map_err(|_| 7u64)?;
                if old & ADDRESS_MASK == p
                    && old & (PRESENT | USER | WRITABLE) == PRESENT | USER | WRITABLE
                {
                    return Err(7);
                }
            }
        }
        *self.record = Some(Binding {
            root: self.leaf.root(),
            table: self.leaf.table(),
            physical,
            pages: lease.pages(),
            installed: false,
        });
        for (i, p) in extent.physical_pages(lease).map_err(|_| 7u64)?.enumerate() {
            // SAFETY: whole fixed window and every actual source preflighted
            // before first write; attaching receipt already retained.
            unsafe {
                self.leaf
                    .write(
                        abi::STAGING_FIRST + i,
                        p | PRESENT | USER | WRITABLE | NO_EXECUTE,
                    )
                    .map_err(|_| 7u64)?
            };
        }
        self.leaf.flush();
        self.record.as_mut().unwrap().installed = true;
        Ok(())
    }
    fn remove_writers(&mut self, extent: &MemoryExtent, lease: &ExtentLease) -> Result<(), u64> {
        let Some(record) = *self.record else {
            return Ok(());
        };
        if record.root != self.leaf.root()
            || record.table != self.leaf.table()
            || record.pages != lease.pages()
        {
            return Err(7);
        }
        for (i, p) in extent.physical_pages(lease).map_err(|_| 7u64)?.enumerate() {
            if p != record.physical + i as u64 * 4096 {
                return Err(7);
            }
        }
        policy::retained(
            |i| self.leaf.entry(i).map_err(|_| policy::Error::Read),
            policy::Window::Writer,
            record.physical,
            record.pages,
            record.installed,
        )
        .map_err(|_| 7u64)?;
        self.record.as_mut().unwrap().installed = false;
        for i in abi::STAGING_FIRST..abi::STAGING_FIRST + 64 {
            // SAFETY: exact retained partial/full fixed mapping, controller capture.
            unsafe { self.leaf.write(i, 0).map_err(|_| 7u64)? };
        }
        self.leaf.flush();
        for p in extent.physical_pages(lease).map_err(|_| 7u64)? {
            for i in 0..512 {
                let low = self.leaf.private_entry(i).map_err(|_| 7u64)?;
                let high = self.leaf.entry(i).map_err(|_| 7u64)?;
                if [low, high].iter().any(|v| {
                    *v & ADDRESS_MASK == p
                        && *v & (PRESENT | USER | WRITABLE) == PRESENT | USER | WRITABLE
                }) {
                    return Err(7);
                }
            }
        }
        *self.record = None;
        Ok(())
    }
}
fn install_reader(
    leaf: &mut Leaf<'_>,
    index: usize,
    slot: &mut Slot,
    a: &Authority,
) -> Result<(), u64> {
    let Some(Retained::Sealed(o)) = &slot.owner else {
        return Err(7);
    };
    let r = slot.reader.as_mut().ok_or(7u64)?;
    o.extent().validate(a, &r.lease).map_err(|_| 7u64)?;
    let first = abi::READONLY_FIRST[index];
    policy::empty(
        |i| leaf.entry(i).map_err(|_| policy::Error::Read),
        policy::Window::Reader(index),
    )
    .map_err(|_| 7u64)?;
    policy::empty(
        |i| leaf.entry(i).map_err(|_| policy::Error::Read),
        policy::Window::Writer,
    )
    .map_err(|_| 7u64)?;
    for (i, p) in o
        .extent()
        .physical_pages(&r.lease)
        .map_err(|_| 7u64)?
        .enumerate()
    {
        // SAFETY: exact sealed readonly actual lease, fixed empty destination.
        unsafe {
            leaf.write(first + i, p | PRESENT | USER | NO_EXECUTE)
                .map_err(|_| 7u64)?
        };
    }
    leaf.flush();
    r.binding.installed = true;
    Ok(())
}
fn detach_reader(
    leaf: &mut Leaf<'_>,
    index: usize,
    reader: &mut Reader,
    owner: &SealedImage,
) -> Result<(), u64> {
    let b = reader.binding;
    if b.root != leaf.root()
        || b.table != leaf.table()
        || b.physical != owner.physical()
        || b.pages != owner.pages()
    {
        return Err(7);
    }
    let first = abi::READONLY_FIRST[index];
    policy::retained(
        |i| leaf.entry(i).map_err(|_| policy::Error::Read),
        policy::Window::Reader(index),
        b.physical,
        b.pages,
        b.installed,
    )
    .map_err(|_| 7u64)?;
    reader.binding.installed = false;
    for i in first..first + 64 {
        // SAFETY: exact retained partial/full reader, actual Root stopped;
        // all process source references already forgot, no CPU/AP can read it.
        unsafe { leaf.write(i, 0).map_err(|_| 7u64)? };
    }
    leaf.flush();
    reader.binding.installed = false;
    Ok(())
}
struct View<'a> {
    hw: Hardware,
    _a: &'a Authority,
    _s: &'a Scheduler,
    meta: Metadata,
    cap: Handle,
    physical: u64,
    length: usize,
}
impl<'a> View<'a> {
    fn new(
        hw: Hardware,
        a: &'a Authority,
        s: &'a Scheduler,
        meta: Metadata,
        o: &SealedImage,
    ) -> Self {
        Self {
            hw,
            _a: a,
            _s: s,
            meta,
            cap: o.root_handle(),
            physical: o.physical(),
            length: o.pages() * 4096,
        }
    }
}
// SAFETY: constructed privately only from a sealed actual owner. Shared
// Authority/Scheduler borrows prohibit destruction/frame release while the view
// exists, yet allow allocation of different App frames. Captured Root/APs
// cannot mutate sealed user bytes; no mutable reference or static slice exists.
unsafe impl ReadOnlyRam for View<'_> {
    type Error = u64;
    fn bytes(&self, p: u64, n: usize) -> Result<&[u8], u64> {
        if p != self.physical || n != self.length {
            return Err(6);
        }
        self._a
            .authorize(self.meta.domain, self.cap, Kind::Memory, Rights::READ)
            .map_err(|_| 2u64)?;
        let pointer = State::ptr(self.hw, p)?;
        let last = p
            .checked_add(n as u64)
            .and_then(|end| end.checked_sub(4096))
            .ok_or(6u64)?;
        let _ = State::ptr(self.hw, last)?;
        // SAFETY: exact sealed contiguous retained range, owner+HAL bounded borrow;
        // privileged direct map stays supervisor-only and has no retained writer.
        Ok(unsafe { core::slice::from_raw_parts(pointer.cast_const(), n) })
    }
}
