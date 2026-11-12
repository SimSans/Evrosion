//! Outer native Root owner. Actual package mapping claims stay outside the
//! bounded UserRoot/LoadedImage metadata and cannot be retired while leased.
use super::backing::PackageBank;
use crate::executable_runtime::{NativeLoadedImage as LoadedImage, NativeLoadedRoot as LoadedRoot};
use ev_kernel::{
    capability::Authority,
    executable::{Image, LayoutReservation},
    loaded_image::{Information, LoadedExecutable},
    mapping::{ADDRESS_MASK, NO_EXECUTE, PRESENT},
    memory::BootstrapFrames,
    memory_extent::ExtentLease,
    scheduler::{Resource, Scheduler, State},
    service::Metadata,
    surface_layout::{PAGES, Window},
    user::USER,
};
const NATIVE_PRIVATE_PAGES: usize = ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_PAGES;
const AD: u64 = (1 << 5) | (1 << 6);

pub(crate) enum Error {
    Phase,
    Layout,
    Binding,
    Occupied,
    Readback,
    LiveClaims,
    Missing,
    Root(&'static str),
    Extent(ev_kernel::memory_extent::Error),
}
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Root(error) => f.debug_tuple("Root").field(error).finish(),
            Self::Extent(error) => f.debug_tuple("Extent").field(error).finish(),
            Self::Phase => f.write_str("Phase"),
            Self::Layout => f.write_str("Layout"),
            Self::Binding => f.write_str("Binding"),
            Self::Occupied => f.write_str("Occupied"),
            Self::Readback => f.write_str("Readback"),
            Self::LiveClaims => f.write_str("LiveClaims"),
            Self::Missing => f.write_str("Missing"),
        }
    }
}
#[derive(Clone, Copy)]
struct Attachment {
    root: u64,
    table: u64,
    base: u64,
    installed: bool,
}
struct BankMapping {
    lease: ExtentLease,
    window: Window,
    attachment: Option<Attachment>,
}
pub(crate) struct NativeRootImage {
    loaded: LoadedImage,
    metadata: Option<Metadata>,
    private_frames: u64,
    banks: [Option<BankMapping>; 2],
}
impl NativeRootImage {
    pub const fn empty() -> Self {
        Self {
            loaded: LoadedImage::empty(),
            metadata: None,
            private_frames: 0,
            banks: [None, None],
        }
    }
    /// # Safety
    /// Actual held metadata, exclusive private allocator/root slot/CPU owner.
    /// Neither package bank may overlap any measured private page or guard.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn load_private(
        &mut self,
        plan: &Image<'_>,
        metadata: Metadata,
        startup: &[u8; ev_userspace_contract::root_v2::native::SIZE],
        offset: u64,
        bits: u8,
        original: u64,
        frames: &mut BootstrapFrames,
    ) -> Result<(), Error> {
        if self.metadata.is_some() || self.banks.iter().any(Option::is_some) {
            return Err(Error::Phase);
        }
        if plan.layout() != LayoutReservation::Legacy || plan.required_frames() != metadata.frames {
            return Err(Error::Layout);
        }
        verify_native_stack(plan)?;
        for window in [Window::Primary, Window::Auxiliary] {
            window.verify_private(plan).map_err(|_| Error::Layout)?;
        }
        // SAFETY: exact named profile3 parser; all overlap checks precede RAM allocation.
        self.loaded =
            unsafe { LoadedImage::load_native_root(offset, bits, original, plan, startup, frames) }
                .map_err(Error::Root)?;
        self.metadata = Some(metadata);
        self.private_frames = plan.required_frames();
        Ok(())
    }
    pub fn retain_bank(
        &mut self,
        index: usize,
        lease: ExtentLease,
    ) -> Result<(), (Error, ExtentLease)> {
        if index >= 2 || self.banks[index].is_some() || self.metadata.is_none() {
            return Err((Error::Phase, lease));
        }
        if lease.writable() || !(1..=PAGES).contains(&lease.pages()) {
            return Err((Error::Binding, lease));
        }
        self.banks[index] = Some(BankMapping {
            lease,
            window: if index == 0 {
                Window::Primary
            } else {
                Window::Auxiliary
            },
            attachment: None,
        });
        Ok(())
    }
    /// # Safety
    /// Held root only; actual RAM/authority retained, original CR3/IF0/AP fence.
    pub unsafe fn install_bank(
        &mut self,
        index: usize,
        a: &Authority,
        s: &Scheduler,
        bank: &PackageBank,
    ) -> Result<(), Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        if s.held_process_job(metadata.process) != Ok(metadata.job) {
            return Err(Error::Phase);
        }
        let mapping = self
            .banks
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Error::Missing)?;
        if mapping.attachment.is_some()
            || mapping.lease.owner() != metadata.domain
            || mapping.lease.pages() != bank.pages()
            || mapping.lease.writable()
        {
            return Err(Error::Binding);
        }
        bank.extent()
            .validate(a, &mapping.lease)
            .map_err(Error::Extent)?;
        // SAFETY: fixed bank window, exact held inactive root.
        let mut leaf =
            unsafe { leaf(&mut self.loaded.root, mapping.window) }.map_err(Error::Root)?;
        for page in mapping.window.lower_guard()..=mapping.window.upper_guard() {
            if leaf.entry(page).map_err(Error::Root)? != 0 {
                return Err(Error::Occupied);
            }
        }
        let mut count = 0;
        for physical in bank
            .extent()
            .physical_pages(&mapping.lease)
            .map_err(Error::Extent)?
        {
            if physical == 0 || physical & !ADDRESS_MASK != 0 {
                return Err(Error::Binding);
            }
            count += 1;
        }
        if count != bank.pages() {
            return Err(Error::Binding);
        }
        // Retain attaching state before the first PTE; no failed install may
        // report readiness or lose the mapping/frame claim.
        mapping.attachment = Some(Attachment {
            root: leaf.root(),
            table: leaf.physical(),
            base: leaf.base(),
            installed: false,
        });
        for (offset, physical) in bank
            .extent()
            .physical_pages(&mapping.lease)
            .map_err(Error::Extent)?
            .enumerate()
        {
            // SAFETY: all fixed entries preflighted; writable bit is NEVER set.
            unsafe {
                leaf.write(
                    mapping.window.first() + offset,
                    physical | PRESENT | USER | NO_EXECUTE,
                )
            }
            .map_err(Error::Root)?;
        }
        for (offset, physical) in bank
            .extent()
            .physical_pages(&mapping.lease)
            .map_err(Error::Extent)?
            .enumerate()
        {
            if leaf
                .entry(mapping.window.first() + offset)
                .map_err(Error::Root)?
                != physical | PRESENT | USER | NO_EXECUTE
            {
                return Err(Error::Readback);
            }
        }
        for page in mapping.window.first() + bank.pages()..=mapping.window.upper_guard() {
            if leaf.entry(page).map_err(Error::Root)? != 0 {
                return Err(Error::Readback);
            }
        }
        if leaf
            .entry(mapping.window.lower_guard())
            .map_err(Error::Root)?
            != 0
        {
            return Err(Error::Readback);
        }
        mapping.attachment.as_mut().unwrap().installed = true;
        Ok(())
    }
    pub fn loaded(&self) -> &LoadedImage {
        &self.loaded
    }
    /// Mutable access is confined to held/stopped physical preparation, never
    /// reachable through Active::image's shared executable lease.
    pub fn loaded_inactive(&mut self, s: &Scheduler) -> Result<&mut LoadedImage, Error> {
        let m = self.metadata.ok_or(Error::Missing)?;
        if s.held_process_job(m.process) != Ok(m.job) && !stopped(s, m) {
            return Err(Error::Phase);
        }
        Ok(&mut self.loaded)
    }
    pub fn bank(&self, index: usize) -> Option<&ExtentLease> {
        self.banks.get(index)?.as_ref().map(|b| &b.lease)
    }
    pub fn lease(&mut self) -> Result<NativeProcessImage<'_>, Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        let root = self.loaded.root.root();
        if self.banks.iter().any(|bank| {
            bank.as_ref()
                .is_none_or(|b| !b.attachment.is_some_and(|a| a.installed && a.root == root))
        }) {
            return Err(Error::Missing);
        }
        Ok(NativeProcessImage {
            image: self,
            metadata,
        })
    }
    /// # Safety
    /// Actual Root stopped and Active::finish returned this exact image owner;
    /// original CR3 restored, no CPU/AP/ref may access these package mappings.
    pub unsafe fn detach_bank(
        &mut self,
        index: usize,
        s: &Scheduler,
        bank: &PackageBank,
    ) -> Result<ExtentLease, Error> {
        let metadata = self.metadata.ok_or(Error::Missing)?;
        if !stopped(s, metadata) {
            return Err(Error::Phase);
        }
        let mapping = self
            .banks
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Error::Missing)?;
        if let Some(attachment) = mapping.attachment {
            // Cleanup deliberately uses retained exact lease identity after
            // public Root grants have been revoked/closed.
            let _ = bank
                .extent()
                .physical_pages(&mapping.lease)
                .map_err(Error::Extent)?;
            // SAFETY: exact stopped inactive root, fixed recorded bank window.
            let mut leaf =
                unsafe { leaf(&mut self.loaded.root, mapping.window) }.map_err(Error::Root)?;
            if (leaf.root(), leaf.physical(), leaf.base())
                != (attachment.root, attachment.table, attachment.base)
            {
                return Err(Error::Binding);
            }
            for (offset, physical) in bank
                .extent()
                .physical_pages(&mapping.lease)
                .map_err(Error::Extent)?
                .enumerate()
            {
                let actual = leaf
                    .entry(mapping.window.first() + offset)
                    .map_err(Error::Root)?
                    & !AD;
                if actual != physical | PRESENT | USER | NO_EXECUTE
                    && (attachment.installed || actual != 0)
                {
                    return Err(Error::Readback);
                }
            }
            for page in [mapping.window.lower_guard(), mapping.window.upper_guard()] {
                if leaf.entry(page).map_err(Error::Root)? != 0 {
                    return Err(Error::Readback);
                }
            }
            for page in
                mapping.window.first() + mapping.lease.pages()..mapping.window.first() + PAGES
            {
                if leaf.entry(page).map_err(Error::Root)? != 0 {
                    return Err(Error::Readback);
                }
            }
            for page in mapping.window.first()..mapping.window.first() + PAGES {
                // SAFETY: all actual mappings quiescent; only fixed bank entries.
                unsafe { leaf.write(page, 0) }.map_err(Error::Root)?;
            }
            for page in mapping.window.lower_guard()..=mapping.window.upper_guard() {
                if leaf.entry(page).map_err(Error::Root)? != 0 {
                    return Err(Error::Readback);
                }
            }
        }
        Ok(self.banks[index].take().unwrap().lease)
    }
    /// # Safety
    /// All actual Root CPUs/context references stopped; every package/scalar
    /// mapping claim returned and controller CR3 active through scrub/free.
    pub unsafe fn retire_private(
        &mut self,
        s: &Scheduler,
        frames: &mut BootstrapFrames,
    ) -> Result<usize, Error> {
        let m = self.metadata.ok_or(Error::Missing)?;
        if !stopped(s, m) {
            return Err(Error::Phase);
        }
        if self.banks.iter().any(Option::is_some) {
            return Err(Error::LiveClaims);
        }
        // SAFETY: stopped owner, exact package mappings detached above; scalar
        // claims are independently checked by the unchanged inner retirement.
        let count = unsafe { self.loaded.root.retire_in_place(frames) };
        if count as u64 != self.private_frames {
            return Err(Error::Binding);
        }
        self.loaded = LoadedImage::empty();
        self.metadata = None;
        self.private_frames = 0;
        Ok(count)
    }
}
/// Sole mutable lifetime lease; Active retains it through actual stopped finish.
pub(crate) struct NativeProcessImage<'a> {
    image: &'a mut NativeRootImage,
    metadata: Metadata,
}
impl<'a> NativeProcessImage<'a> {
    pub fn image(&self) -> &NativeRootImage {
        self.image
    }
    pub fn into_image(self) -> &'a mut NativeRootImage {
        self.image
    }
}
// SAFETY: only the checked outer lease constructor exists, after both RO bank
// receipts and initialized private backing report Installed on the same root.
// Exclusive borrow prevents mutation/retirement throughout admission/execution.
unsafe impl LoadedExecutable for NativeProcessImage<'_> {
    fn information(&self) -> Information {
        self.image
            .loaded
            .borrowed_information(self.metadata.process, self.image.private_frames)
    }
}
/// Enforce the independently measured Native Root stack layout before any RAM
/// allocation. Keep its temporary readback buffer outside the loader call frame.
#[inline(never)]
fn verify_native_stack(plan: &Image<'_>) -> Result<(), Error> {
    use ev_userspace_contract::root_v2::native;
    let first = native::ROOT_STACK_FIRST_PAGE;
    let end = first + native::ROOT_STACK_PAGES;
    let mut bytes = [0u8; 4096];
    for page in first - 1..=end {
        let actual = plan
            .pages()
            .find(|mapped| mapped.address == plan.base() + page * 4096);
        if page == first - 1 || page == end {
            if actual.is_some() {
                return Err(Error::Layout);
            }
        } else {
            let actual = actual.ok_or(Error::Layout)?;
            if actual.permission != ev_kernel::user::UserPermission::ReadWrite {
                return Err(Error::Layout);
            }
            actual.copy_into(&mut bytes);
            if bytes.iter().any(|byte| *byte != 0) {
                return Err(Error::Layout);
            }
        }
    }
    Ok(())
}
fn stopped(s: &Scheduler, m: Metadata) -> bool {
    s.thread_process(m.thread) == Ok(m.process)
        && s.process_job(m.process) == Ok(m.job)
        && s.state(m.thread) == Ok(State::Exited)
        && s.usage(m.job, Resource::Processes) == Ok(0)
        && s.usage(m.job, Resource::Threads) == Ok(0)
}
/// # Safety
/// Exact held/stopped inactive root and fixed named bank window only.
unsafe fn leaf(
    root: &mut LoadedRoot,
    window: Window,
) -> Result<crate::user_space::SurfaceLeaf<'_, NATIVE_PRIVATE_PAGES>, &'static str> {
    match window {
        // SAFETY: forwards the same captured/held root ownership guard.
        Window::Primary => unsafe { root.surface_leaf_inactive() },
        // SAFETY: same guard; no arbitrary PTE index or user pointer accepted.
        Window::Auxiliary => unsafe { root.surface_auxiliary_leaf_inactive() },
    }
}
