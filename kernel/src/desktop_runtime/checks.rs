//! Readback of retained actual RAM mappings. No scanout bytes are read or painted.
use super::*;
use ev_kernel::{
    mapping::{NO_EXECUTE, PRESENT, WRITABLE},
    memory_extent::{ExtentLease, MemoryExtent},
    surface_layout::Window,
    user::USER,
};
const AD: u64 = (1 << 5) | (1 << 6);
impl Hardware {
    fn entry(&self, table: u64, index: usize) -> u64 {
        assert!(table != 0 && table.is_multiple_of(FRAME_SIZE) && index < 512);
        let pointer = direct_address(self.offset, table, self.bits).unwrap() as *const u64;
        // SAFETY: actual retained RAM page tables, IF0/APs parked; no user has
        // writable access to page-table frames and ownership is not released.
        unsafe { pointer.add(index).read_volatile() }
    }
    fn tables(&self, root: u64, base: u64) -> (u64, u64) {
        let pml4 = self.entry(root, ((base >> 39) & 511) as usize);
        assert_eq!(pml4 & (PRESENT | USER), PRESENT | USER);
        let pdpt = self.entry(pml4 & ADDRESS_MASK, ((base >> 30) & 511) as usize);
        assert_eq!(pdpt & (PRESENT | USER | (1 << 7)), PRESENT | USER);
        let directory = pdpt & ADDRESS_MASK;
        let leaf = self.entry(directory, 0);
        assert_eq!(leaf & (PRESENT | USER | (1 << 7)), PRESENT | USER);
        (directory, leaf & ADDRESS_MASK)
    }
    fn surface(
        &self,
        leaf: u64,
        a: &Authority,
        extent: &MemoryExtent,
        lease: &ExtentLease,
        window: Window,
    ) {
        extent.validate(a, lease).unwrap();
        assert_eq!(self.entry(leaf, window.lower_guard()), 0);
        assert_eq!(self.entry(leaf, window.upper_guard()), 0);
        let mut count = 0;
        for (index, frame) in extent.physical_pages(lease).unwrap().enumerate() {
            let flags = PRESENT | USER | NO_EXECUTE | if lease.writable() { WRITABLE } else { 0 };
            assert_eq!(
                self.entry(leaf, window.first() + index) & !AD,
                frame | flags
            );
            count += 1;
        }
        assert_eq!(count, 63);
    }
    fn scalar<const N: usize>(
        &self,
        root: &crate::executable_runtime::PrivateLoadedRoot<N>,
        leaf: u64,
        a: &Authority,
        backing: &Backing,
        which: Scalar,
        aux: bool,
    ) {
        let object = backing.scalar(which);
        let page = if aux { 507 } else { 508 };
        let lease = root.shared_mapping(page * FRAME_SIZE).unwrap();
        object.validate_mapping(a, lease).unwrap();
        assert_eq!(
            direct_address(self.offset, lease.physical(), self.bits).unwrap(),
            backing.alias(which)
        );
        assert_eq!(
            self.entry(leaf, page as usize) & !AD,
            lease.physical()
                | PRESENT
                | USER
                | NO_EXECUTE
                | if lease.writable() { WRITABLE } else { 0 }
        );
        if aux {
            if lease.writable() {
                root.validate_application(a, object).unwrap();
            } else {
                root.validate_catalogue(a, object).unwrap();
            }
        } else {
            root.validate_shared(a, object).unwrap();
        }
    }
}
impl Runtime<'_, '_> {
    pub(super) fn check_mappings(&self, index: usize) {
        if index == 0 {
            self.check_root_mappings(
                &self.root.active.as_ref().unwrap().image().loaded().root,
                index,
            );
        } else {
            self.check_root_mappings(
                self.actors[index - 1]
                    .as_ref()
                    .unwrap()
                    .image()
                    .unwrap()
                    .root(),
                index,
            );
        }
    }
    fn check_root_mappings<const N: usize>(
        &self,
        root: &crate::executable_runtime::PrivateLoadedRoot<N>,
        index: usize,
    ) {
        let (directory, leaf) = self.hw.tables(root.root(), root.base());
        #[cfg(feature = "test-m5-native")]
        let stack_upper = if index == 0 {
            (root_v2::native::ROOT_STACK_FIRST_PAGE + root_v2::native::ROOT_STACK_PAGES) as usize
        } else {
            260
        };
        #[cfg(not(feature = "test-m5-native"))]
        let stack_upper = 260;
        for guard in [255, stack_upper, 303, 367, 383, 447, 510] {
            assert_eq!(self.hw.entry(leaf, guard), 0);
        }
        #[cfg(feature = "test-m5-native")]
        if index == 0 {
            for page in root_v2::native::ROOT_STACK_FIRST_PAGE
                ..root_v2::native::ROOT_STACK_FIRST_PAGE + root_v2::native::ROOT_STACK_PAGES
            {
                let expected = root
                    .private_entry(page * FRAME_SIZE)
                    .expect("Native Root stack page retains actual private RAM ownership");
                assert_eq!(
                    expected & !ADDRESS_MASK,
                    PRESENT | USER | WRITABLE | NO_EXECUTE
                );
                assert_eq!(self.hw.entry(leaf, page as usize) & !AD, expected);
            }
        }
        #[cfg(feature = "test-m6-network")]
        if index == 0 && self.dynamic.initialized() {
            // SAFETY: sole actual restored-CR3/IF0/BSP owner before Root resume.
            unsafe {
                self.dynamic.check(
                    &self.root.active.as_ref().unwrap().image().loaded().root,
                    self.a,
                    self.hw,
                )
            }
            .expect("actual dynamic Root mappings");
        } else {
            assert_eq!(self.hw.entry(directory, 1), 0);
        }
        #[cfg(not(feature = "test-m6-network"))]
        assert_eq!(self.hw.entry(directory, 1), 0);
        assert_eq!(self.hw.entry(directory, 4), 0);
        if index == 0 {
            self.hw
                .scalar(root, leaf, self.a, self.backing, Scalar::System, false);
            self.hw
                .scalar(root, leaf, self.a, self.backing, Scalar::Catalogue, true);
            #[cfg(feature = "test-m6-session")]
            {
                #[cfg(not(feature = "test-m6-network"))]
                let which = Scalar::Application;
                #[cfg(feature = "test-m6-network")]
                let which = Scalar::Note;
                let object = self.backing.scalar(which);
                root.validate_session_note(self.a, object).unwrap();
                let page = root_v2::native::SESSION_NOTE_PAGE;
                let lease = root.shared_mapping(page * FRAME_SIZE).unwrap();
                assert_eq!(
                    direct_address(self.hw.offset, lease.physical(), self.hw.bits).unwrap(),
                    self.backing.alias(which)
                );
                assert_eq!(
                    self.hw.entry(leaf, page as usize) & !AD,
                    lease.physical() | PRESENT | USER | WRITABLE | NO_EXECUTE
                );
            }
            #[cfg(feature = "test-m6-network")]
            {
                let object = self.backing.scalar(Scalar::NetClient);
                root.validate_network_client(self.a, object).unwrap();
                let page = root_abi::ROOT_NET_CLIENT_PAGE;
                let lease = root.shared_mapping(page * FRAME_SIZE).unwrap();
                assert_eq!(
                    direct_address(self.hw.offset, lease.physical(), self.hw.bits).unwrap(),
                    self.backing.alias(Scalar::NetClient)
                );
                assert_eq!(
                    self.hw.entry(leaf, page as usize) & !AD,
                    lease.physical() | PRESENT | USER | WRITABLE | NO_EXECUTE
                );
                assert_ne!(
                    self.backing.alias(Scalar::Note),
                    self.backing.alias(Scalar::Application)
                );
            }
            #[cfg(feature = "test-m5-native")]
            if let (RootImage::Native(owner), Some(native)) =
                (self.root.active.as_ref().unwrap().image(), &self.native)
            {
                for (index, window) in [(0, Window::Primary), (1, Window::Auxiliary)] {
                    let bank = native.backing.bank(index);
                    let lease = owner.image().bank(index).unwrap();
                    assert!(!lease.writable());
                    assert_eq!(lease.pages(), bank.pages());
                    bank.extent().validate(self.a, lease).unwrap();
                    for (offset, physical) in
                        bank.extent().physical_pages(lease).unwrap().enumerate()
                    {
                        assert_eq!(
                            self.hw.entry(leaf, window.first() + offset) & !AD,
                            physical | PRESENT | USER | NO_EXECUTE
                        );
                    }
                    for page in window.first() + bank.pages()..=window.upper_guard() {
                        assert_eq!(self.hw.entry(leaf, page), 0);
                    }
                }
            }
            return;
        }
        let actor = self.actors[index - 1].as_ref().unwrap();
        let image = actor.image().unwrap();
        if let Some(lease) = image.surface() {
            self.hw.surface(
                leaf,
                self.a,
                if actor.child == Child::Shell {
                    &self.backing.shell
                } else {
                    &self.backing.app
                },
                lease,
                Window::Primary,
            );
        }
        if let Some(lease) = image.auxiliary_surface() {
            assert_eq!(actor.child, Child::Display);
            self.hw
                .surface(leaf, self.a, &self.backing.shell, lease, Window::Auxiliary);
        }
        if let Some(display) = image.display() {
            assert_eq!(display.mapped_root(), Some(root.root()));
            assert_eq!(display.table_frames(), 2);
            assert!(display.mapped_geometry().is_some());
            for page in [2, 3] {
                assert_eq!(
                    self.hw.entry(directory, page) & !(ADDRESS_MASK | AD),
                    PRESENT | WRITABLE | USER | NO_EXECUTE
                );
            }
        } else {
            assert_eq!(self.hw.entry(directory, 2), 0);
            assert_eq!(self.hw.entry(directory, 3), 0);
        }
        let scalars: &[(Scalar, bool)] = match actor.child {
            Child::Block => &[(Scalar::System, false), (Scalar::File, true)],
            Child::File => &[(Scalar::File, false), (Scalar::Application, true)],
            #[cfg(not(feature = "test-m6-network"))]
            Child::App => &[(Scalar::Application, false)],
            #[cfg(feature = "test-m6-network")]
            Child::App => &[(Scalar::Application, false), (Scalar::Note, true)],
            #[cfg(feature = "test-m6-network")]
            Child::NetDriver => &[(Scalar::Nic, false)],
            #[cfg(feature = "test-m6-network")]
            Child::NetService => &[(Scalar::Nic, false), (Scalar::NetClient, true)],
            _ => &[],
        };
        for &(which, aux) in scalars {
            self.hw.scalar(root, leaf, self.a, self.backing, which, aux);
        }
    }
    pub(super) fn check_scalar_guards(&mut self) {
        for which in [Scalar::System, Scalar::File, Scalar::Application] {
            // The App legitimately maps all4096 bytes RW. Its unused protocol
            // tail cannot be a Kernel invariant: malformed padding is refused
            // by the File service, not promoted into a critical Kernel fault.
            #[cfg(feature = "test-m6-session")]
            if matches!(which, Scalar::Application) {
                continue;
            }
            let pointer = self.backing.alias(which) as *const u8;
            for byte in 512..FRAME_SIZE as usize {
                // SAFETY: exact initialized parent-owned scalar page, all user
                // CPUs stopped/captured. In M6 only trusted Root/Block/File
                // protocol buffers retain this internal zero-padding check.
                assert_eq!(unsafe { pointer.add(byte).read_volatile() }, 0);
            }
        }
        #[cfg(feature = "test-m6-session")]
        {
            let pointer = self.backing.alias(Scalar::Application) as *const u8;
            let mut nonzero = 0;
            let mut first = FRAME_SIZE;
            for byte in 256..FRAME_SIZE as usize {
                // SAFETY: initialized parent-owned page retained after all App
                // execution stopped; reads do not clear or repair client bytes.
                if unsafe { pointer.add(byte).read_volatile() } != 0 {
                    nonzero += 1;
                    if first == FRAME_SIZE {
                        first = byte as u64;
                    }
                }
            }
            (self.observations)(Observation::SessionWindowPadding(SessionWindowPadding {
                nonzero,
                first,
            }));
        }
    }
}
