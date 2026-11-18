//! Actual retained boot backing for the eighteen measured Root sources. This
//! module initializes owned RAM and binds real device ranges; it never paints
//! scanout or makes a userspace marker stand in for resource ownership.
use super::Scalar;
use crate::display_runtime::DisplayAperture;
#[cfg(not(feature = "test-m5-native"))]
use crate::supervisor_runtime::bundle;
use ev_boot_contract::Framebuffer;
use ev_kernel::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    display::DisplayObject,
    io_ports::{Direction, Range, Registry as Ports, Widths},
    mapping::direct_address,
    memory::{BootstrapFrames, FRAME_SIZE, PhysicalFrame},
    memory_extent::{MemoryExtent, RamAccess, UninitializedRam},
    memory_object::MemoryObject,
    scheduler::{JobId, Resource, Scheduler},
};
use ev_userspace_contract::root_v2::Role;
#[cfg(not(feature = "test-m6-network"))]
use ev_userspace_contract::root_v2::catalogue::Catalogue;
use sha2::{Digest, Sha256};

const SURFACE_PAGES: usize = 63;
pub(super) const SHARED_FRAMES: u64 = 130;
const ATA: [Range; 3] = [
    Range {
        first: 0x1e8,
        last: 0x1e9,
        widths: Widths::WORD,
        direction: Direction::Both,
    },
    Range {
        first: 0x1e9,
        last: 0x1ef,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
    Range {
        first: 0x3ee,
        last: 0x3ee,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
];
const INPUT: [Range; 2] = [
    Range {
        first: 0x60,
        last: 0x60,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
    Range {
        first: 0x64,
        last: 0x64,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
];
const UART: [Range; 2] = [
    Range {
        first: 0x3f8,
        last: 0x3f8,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
    Range {
        first: 0x3fd,
        last: 0x3fd,
        widths: Widths::BYTE,
        direction: Direction::Input,
    },
];

/// Source29 is Root-only and cannot write RTC data/clock state. No physical
/// machine/UTC qualification follows from this explicit developer-VM range.
#[cfg(feature = "test-m6-network")]
const RTC: [Range; 2] = [
    Range {
        first: ev_userspace_contract::root_v4::RTC_INDEX_PORT,
        last: ev_userspace_contract::root_v4::RTC_INDEX_PORT,
        widths: Widths::BYTE,
        direction: Direction::Output,
    },
    Range {
        first: ev_userspace_contract::root_v4::RTC_DATA_PORT,
        last: ev_userspace_contract::root_v4::RTC_DATA_PORT,
        widths: Widths::BYTE,
        direction: Direction::Input,
    },
];

struct Ram {
    offset: u64,
    bits: u8,
}
impl Ram {
    fn pointer(&self, frame: &PhysicalFrame, byte: usize) -> Result<*mut u8, &'static str> {
        if byte >= FRAME_SIZE as usize {
            return Err("desktop RAM byte bounds");
        }
        direct_address(self.offset, frame.start(), self.bits)
            .map_err(|_| "desktop RAM direct map")?
            .checked_add(byte as u64)
            .map(|address| address as *mut u8)
            .ok_or("desktop RAM address overflow")
    }
    fn zero(&mut self, frame: &PhysicalFrame) {
        for i in 0..FRAME_SIZE as usize {
            self.write(frame, i, 0).unwrap();
        }
        for i in 0..FRAME_SIZE as usize {
            assert_eq!(self.read(frame, i).unwrap(), 0);
        }
    }
}
// SAFETY: every access is to a checked byte of the exact allocator-owned RAM
// claim passed by the extent owner. Actual volatile readback is returned; no
// Rust memory alias is retained and no MMIO address can become a PhysicalFrame.
unsafe impl RamAccess for Ram {
    type Error = &'static str;
    fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), Self::Error> {
        let pointer = self.pointer(frame, byte)?;
        // SAFETY: exact retained quiescent RAM claim and checked byte above.
        unsafe { pointer.write_volatile(value) };
        Ok(())
    }
    fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, Self::Error> {
        let pointer = self.pointer(frame, byte)?;
        // SAFETY: exact retained RAM claim; truthful volatile readback.
        Ok(unsafe { pointer.read_volatile() })
    }
}

/// Immutable build inputs. Selecting this enum does not bypass independent
/// manifest/profile/catalogue/content validation before any source is published.
#[derive(Clone, Copy)]
pub(crate) enum Profile {
    #[cfg(not(feature = "test-m5-native"))]
    Desktop,
    #[cfg(all(feature = "test-m5-native", not(feature = "test-m6-network")))]
    Native,
    #[cfg(feature = "test-m6-network")]
    Network {
        images: [(&'static [u8], [u8; 32]); 2],
    },
}
pub(crate) struct Assets<'a> {
    pub profile: Profile,
    pub root_image: &'a [u8],
    pub root_manifest: &'a [u8],
    pub root_measurement: [u8; 32],
    pub catalogue: &'a [u8],
    pub catalogue_sha: [u8; 32],
    pub images: [(&'a [u8], [u8; 32]); 6],
    pub app_package: &'a [u8],
}
impl Assets<'static> {
    #[cfg(not(feature = "test-m5-native"))]
    pub(crate) fn desktop() -> Self {
        Self {
            profile: Profile::Desktop,
            root_image: bundle::M4_DESKTOP_ROOT_IMAGE,
            root_manifest: bundle::M4_DESKTOP_ROOT_MANIFEST,
            root_measurement: bundle::M4_DESKTOP_ROOT_MEASUREMENT,
            catalogue: bundle::M4_DESKTOP_CATALOGUE,
            catalogue_sha: bundle::M4_DESKTOP_CATALOGUE_SHA,
            images: [
                (bundle::M4_DESKTOP_SHELL_IMAGE, bundle::M4_DESKTOP_SHELL_SHA),
                (bundle::M4_DESKTOP_INPUT_IMAGE, bundle::M4_DESKTOP_INPUT_SHA),
                (bundle::M4_DESKTOP_FILE_IMAGE, bundle::M4_DESKTOP_FILE_SHA),
                (bundle::M4_DESKTOP_BLOCK_IMAGE, bundle::M4_DESKTOP_BLOCK_SHA),
                (bundle::M4_DESKTOP_APP_IMAGE, bundle::M4_DESKTOP_APP_SHA),
                (
                    bundle::M4_DESKTOP_DISPLAY_IMAGE,
                    bundle::M4_DESKTOP_DISPLAY_SHA,
                ),
            ],
            app_package: bundle::M4_DESKTOP_APP_PACKAGE,
        }
    }
}
struct VerifiedCatalogue<'a> {
    bytes: &'a [u8],
}

#[cfg(feature = "test-m6-network")]
pub(super) struct NetworkBacking {
    pub sources: [Handle; 7],
    nic: MemoryObject,
    client: MemoryObject,
    note: MemoryObject,
    aliases: [u64; 3],
}
pub(super) struct Backing {
    #[cfg(feature = "test-m6-network")]
    pub network: Option<NetworkBacking>,
    pub custody: SpaceId,
    pub sources: [Handle; 18],
    pub app: MemoryExtent,
    pub shell: MemoryExtent,
    pub device: DisplayObject<DisplayAperture>,
    pub ports: Ports,
    system: MemoryObject,
    file: MemoryObject,
    app_file: MemoryObject,
    catalogue: MemoryObject,
    aliases: [u64; 4],
    ram_parent: JobId,
    offset: u64,
    bits: u8,
}
impl Backing {
    /// # Safety
    /// Fresh trusted RootDomains custody; exclusive actual bootstrap allocator,
    /// direct map, GOP/cache/source tables, IF0/BSP/AP exclusion. No user process
    /// is executing. This is a boot-only factory, never a scalar user operation.
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(feature = "test-m5-native"))]
    pub unsafe fn new_in(
        custody: SpaceId,
        a: &mut Authority,
        s: &mut Scheduler,
        ram_parent: JobId,
        root_job: JobId,
        offset: u64,
        bits: u8,
        frames: &mut BootstrapFrames,
        framebuffer: Framebuffer,
    ) -> Self {
        // SAFETY: same exclusive boot owner and exact original Desktop inputs.
        unsafe {
            Self::new_with_assets(
                custody,
                a,
                s,
                ram_parent,
                root_job,
                offset,
                bits,
                frames,
                framebuffer,
                &Assets::desktop(),
            )
        }
    }
    /// # Safety
    /// Same boot-only exclusion and exclusive physical ownership as new_in.
    /// Every input is independently checked before any capability is published.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn new_with_assets(
        custody: SpaceId,
        a: &mut Authority,
        s: &mut Scheduler,
        ram_parent: JobId,
        root_job: JobId,
        offset: u64,
        bits: u8,
        frames: &mut BootstrapFrames,
        framebuffer: Framebuffer,
        assets: &Assets<'_>,
    ) -> Self {
        assert_eq!(a.slot_capacity(custody).unwrap(), 64);
        let (_, handles, nodes, objects) = a.metadata_usage();
        assert_eq!(
            (handles, nodes, objects),
            (0, 0, 0),
            "desktop source catalogue must be first"
        );
        assert_ne!(ram_parent, root_job);
        let parent_before = s.usage(ram_parent, Resource::Frames).unwrap();
        let root_before = s.usage(root_job, Resource::Frames).unwrap();
        let compiled = verify_catalogue(assets);
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL;
        let mut sources = [Handle(0); 18];
        // Keep creation order EXACTLY the measured Root-v2 role order. Backing
        // allocations do not create hidden authority objects or mailbox escrows.
        for source in &mut sources[..6] {
            *source = a
                .create_root(custody, Kind::Memory, common | Rights::READ)
                .unwrap();
        }
        sources[6] = a
            .create_root(custody, Kind::Job, common | Rights::READ)
            .unwrap();
        sources[7] = a
            .create_root(
                custody,
                Kind::Endpoint,
                common | Rights::SEND | Rights::RECEIVE,
            )
            .unwrap();
        let mut ram = Ram { offset, bits };
        let (app, cap) = extent(a, s, ram_parent, custody, frames, &mut ram);
        sources[8] = cap;
        let (system, cap, system_alias) = scalar(a, s, ram_parent, custody, frames, &mut ram, &[]);
        sources[9] = cap;
        let (file, cap, file_alias) = scalar(a, s, ram_parent, custody, frames, &mut ram, &[]);
        sources[10] = cap;
        let (app_file, cap, app_alias) = scalar(a, s, ram_parent, custody, frames, &mut ram, &[]);
        sources[11] = cap;
        let (catalogue, cap, catalogue_alias) =
            scalar(a, s, ram_parent, custody, frames, &mut ram, compiled.bytes);
        sources[12] = cap;
        let (shell, cap) = extent(a, s, ram_parent, custody, frames, &mut ram);
        sources[13] = cap;
        let mut ports = Ports::new();
        sources[14] = port_object(a, custody, &mut ports, &ATA);
        sources[15] = port_object(a, custody, &mut ports, &INPUT);
        // SAFETY: actual retained GOP descriptor/cache tables; the discovery
        // walker rejects Usable RAM aliases. Device storage is never allocated,
        // initialized or scrubbed by this factory.
        let aperture = unsafe { DisplayAperture::discover(offset, framebuffer, frames) }.unwrap();
        let (device, cap) = DisplayObject::new(a, custody, aperture)
            .unwrap_or_else(|(error, _owner)| panic!("desktop Display publication: {error:?}"));
        sources[16] = cap;
        sources[17] = port_object(a, custody, &mut ports, &UART);
        for (source, spec) in sources.iter().zip(ev_userspace_contract::root_v2::ROLES) {
            let kind = match spec.kind {
                1 => Kind::Memory,
                2 => Kind::Endpoint,
                5 => Kind::Job,
                7 => Kind::IoPorts,
                8 => Kind::Display,
                _ => panic!("desktop source kind"),
            };
            let access = a
                .authorize(
                    custody,
                    *source,
                    kind,
                    Rights::from_bits(spec.rights).unwrap(),
                )
                .unwrap();
            assert!(access.is_root());
        }
        assert_eq!(
            s.usage(ram_parent, Resource::Frames).unwrap() - parent_before,
            SHARED_FRAMES
        );
        assert_eq!(
            s.usage(root_job, Resource::Frames).unwrap(),
            root_before,
            "shared RAM cannot consume Root private quota"
        );
        Self {
            #[cfg(feature = "test-m6-network")]
            network: None,
            custody,
            sources,
            app,
            shell,
            device,
            ports,
            system,
            file,
            app_file,
            catalogue,
            aliases: [system_alias, file_alias, app_alias, catalogue_alias],
            ram_parent,
            offset,
            bits,
        }
    }
    /// # Safety
    /// Sole boot owner after exactly22 original Native sources, before any actor
    /// starts. The three transfer objects are distinct actual allocated frames.
    #[cfg(feature = "test-m6-network")]
    pub unsafe fn append_network(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
    ) {
        assert!(self.network.is_none());
        assert_eq!(a.metadata_usage().3, 22);
        let c = self.custody;
        let image_rights = Rights::from_bits(481).unwrap();
        let driver = a.create_root(c, Kind::Memory, image_rights).unwrap();
        let service = a.create_root(c, Kind::Memory, image_rights).unwrap();
        let ports = port_object(
            a,
            c,
            &mut self.ports,
            &[Range {
                first: 0x300,
                last: 0x31f,
                widths: Widths::BYTE,
                direction: Direction::Both,
            }],
        );
        let mut ram = Ram {
            offset: self.offset,
            bits: self.bits,
        };
        let (nic, nic_cap, nic_alias) = scalar(a, s, self.ram_parent, c, frames, &mut ram, &[]);
        let (client, client_cap, client_alias) =
            scalar(a, s, self.ram_parent, c, frames, &mut ram, &[]);
        let (note, note_cap, note_alias) = scalar(a, s, self.ram_parent, c, frames, &mut ram, &[]);
        for (i, x) in [nic_alias, client_alias, note_alias].iter().enumerate() {
            assert!(!self.aliases.contains(x));
            assert!(![nic_alias, client_alias, note_alias][..i].contains(x));
        }
        let rtc = port_object(a, c, &mut self.ports, &RTC);
        self.network = Some(NetworkBacking {
            sources: [driver, service, ports, nic_cap, client_cap, note_cap, rtc],
            nic,
            client,
            note,
            aliases: [nic_alias, client_alias, note_alias],
        });
    }
    pub fn scalar(&self, which: Scalar) -> &MemoryObject {
        match which {
            Scalar::System => &self.system,
            Scalar::File => &self.file,
            Scalar::Application => &self.app_file,
            Scalar::Catalogue => &self.catalogue,
            #[cfg(feature = "test-m6-network")]
            Scalar::Nic => &self.network.as_ref().unwrap().nic,
            #[cfg(feature = "test-m6-network")]
            Scalar::NetClient => &self.network.as_ref().unwrap().client,
            #[cfg(feature = "test-m6-network")]
            Scalar::Note => &self.network.as_ref().unwrap().note,
        }
    }
    pub fn scalar_mut(&mut self, which: Scalar) -> &mut MemoryObject {
        match which {
            Scalar::System => &mut self.system,
            Scalar::File => &mut self.file,
            Scalar::Application => &mut self.app_file,
            Scalar::Catalogue => &mut self.catalogue,
            #[cfg(feature = "test-m6-network")]
            Scalar::Nic => &mut self.network.as_mut().unwrap().nic,
            #[cfg(feature = "test-m6-network")]
            Scalar::NetClient => &mut self.network.as_mut().unwrap().client,
            #[cfg(feature = "test-m6-network")]
            Scalar::Note => &mut self.network.as_mut().unwrap().note,
        }
    }
    /// Actual direct-map alias of this retained scalar owner, not a user
    /// address. Caller must respect the current blocked-window protocol.
    pub fn alias(&self, which: Scalar) -> u64 {
        self.aliases[match which {
            Scalar::System => 0,
            Scalar::File => 1,
            Scalar::Application => 2,
            Scalar::Catalogue => 3,
            #[cfg(feature = "test-m6-network")]
            Scalar::Nic => return self.network.as_ref().unwrap().aliases[0],
            #[cfg(feature = "test-m6-network")]
            Scalar::NetClient => return self.network.as_ref().unwrap().aliases[1],
            #[cfg(feature = "test-m6-network")]
            Scalar::Note => return self.network.as_ref().unwrap().aliases[2],
        }]
    }
    pub fn source(&self, role: Role) -> Handle {
        self.sources[role.selector() as usize - 1]
    }
    /// # Safety
    /// The old App is actually stopped/detached, the new App is not admitted,
    /// and no App Present/File request retains shared-buffer credit. Display's
    /// READ lease may remain: it reads this RAM only during those actual calls.
    /// BSP captured/IF0/APs parked; File cannot concurrently access its window.
    pub unsafe fn scrub_app(&mut self, a: &Authority) {
        // SAFETY: forwards the actual stopped-writer/captured-controller guard.
        unsafe {
            clear_extent(
                &mut self.app,
                a,
                self.custody,
                self.sources[8],
                self.offset,
                self.bits,
            )
        };
        // This is transfer RAM, not durable app data. A restarted incarnation
        // must not inherit the previous selected File response through it.
        // SAFETY: exact retained transfer page, with all previous users quiescent.
        unsafe { clear_alias(self.aliases[2], FRAME_SIZE as usize) };
        #[cfg(feature = "test-m6-network")]
        // SAFETY: same actual stopped App and quiesced Root Note transaction;
        // the dedicated transfer page is distinct from every File/NIC page.
        unsafe {
            clear_alias(
                self.network.as_ref().unwrap().aliases[2],
                FRAME_SIZE as usize,
            )
        };
    }
    /// # Safety
    /// Old Shell stopped/detached and no Shell Present pending; new Shell not
    /// admitted. Display retains only its inactive READ claim to this surface.
    pub unsafe fn scrub_shell(&mut self, a: &Authority) {
        // SAFETY: forwards the actual stopped-writer/captured-controller guard.
        unsafe {
            clear_extent(
                &mut self.shell,
                a,
                self.custody,
                self.sources[13],
                self.offset,
                self.bits,
            )
        };
    }
    /// # Safety
    /// Root and every child are actually stopped, all hardware mappings/leases
    /// returned and all queued/protected operations settled. Device/PIO is idle;
    /// no DMA was enabled. The caller retains the original BSP/direct-map guard.
    pub unsafe fn teardown(
        mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
    ) {
        let mut ram = Ram {
            offset: self.offset,
            bits: self.bits,
        };
        let before = s.usage(self.ram_parent, Resource::Frames).unwrap();
        for (object, cap) in [
            (&mut self.app, self.sources[8]),
            (&mut self.shell, self.sources[13]),
        ] {
            let retired = object.destroy(a, self.custody, cap).unwrap();
            retired
                .release(frames, s, &mut ram)
                .unwrap_or_else(|rejected| {
                    panic!("desktop surface retirement: {:?}", rejected.error)
                });
        }
        for (object, cap) in [
            (&mut self.system, self.sources[9]),
            (&mut self.file, self.sources[10]),
            (&mut self.app_file, self.sources[11]),
            (&mut self.catalogue, self.sources[12]),
        ] {
            let frame = object.destroy(a, self.custody, cap).unwrap();
            ram.zero(&frame);
            frames
                .reclaim(frame)
                .unwrap_or_else(|(error, _frame)| panic!("desktop scalar retirement: {error:?}"));
            s.release_frames(self.ram_parent, 1).unwrap();
        }
        #[cfg(feature = "test-m6-network")]
        let extra_frames = if let Some(mut network) = self.network.take() {
            for (object, cap) in [
                (&mut network.nic, network.sources[3]),
                (&mut network.client, network.sources[4]),
                (&mut network.note, network.sources[5]),
            ] {
                let frame = object.destroy(a, self.custody, cap).unwrap();
                ram.zero(&frame);
                frames
                    .reclaim(frame)
                    .unwrap_or_else(|(e, _)| panic!("network RAM retirement: {e:?}"));
                s.release_frames(self.ram_parent, 1).unwrap();
            }
            self.ports
                .retire(a, self.custody, network.sources[2])
                .unwrap();
            self.ports
                .retire(a, self.custody, network.sources[6])
                .unwrap();
            for cap in &network.sources[..2] {
                a.destroy(self.custody, *cap).unwrap();
            }
            3
        } else {
            0
        };
        #[cfg(not(feature = "test-m6-network"))]
        let extra_frames = 0;
        for index in [14, 15, 17] {
            self.ports
                .retire(a, self.custody, self.sources[index])
                .unwrap();
        }
        assert_eq!(self.ports.registered(), 0);
        // Device ownership has no RAM frame to reclaim. All Display PT receipts
        // and its unique lease were already physically detached by the executor.
        a.destroy(self.custody, self.sources[16]).unwrap();
        for cap in &self.sources[..8] {
            a.destroy(self.custody, *cap).unwrap();
        }
        a.collect_lineage().unwrap();
        a.collect_dead_objects().unwrap();
        assert_eq!(
            before - s.usage(self.ram_parent, Resource::Frames).unwrap(),
            SHARED_FRAMES + extra_frames
        );
    }
}

fn extent(
    a: &mut Authority,
    s: &mut Scheduler,
    parent: JobId,
    custody: SpaceId,
    frames: &mut BootstrapFrames,
    ram: &mut Ram,
) -> (MemoryExtent, Handle) {
    let initialized = UninitializedRam::allocate(frames, s, parent, SURFACE_PAGES)
        .unwrap_or_else(|rejected| panic!("desktop surface allocation: {:?}", rejected.error))
        .initialize(ram)
        .unwrap_or_else(|rejected| panic!("desktop surface initialization: {:?}", rejected.error));
    MemoryExtent::publish(a, custody, initialized, frames, s)
        .unwrap_or_else(|rejected| panic!("desktop surface publication: {:?}", rejected.error))
}
fn scalar(
    a: &mut Authority,
    s: &mut Scheduler,
    parent: JobId,
    custody: SpaceId,
    frames: &mut BootstrapFrames,
    ram: &mut Ram,
    content: &[u8],
) -> (MemoryObject, Handle, u64) {
    assert!(content.len() <= FRAME_SIZE as usize);
    s.charge_frames(parent, 1).unwrap();
    let frame = frames.allocate().expect("desktop scalar RAM allocation");
    ram.zero(&frame);
    for (i, byte) in content.iter().copied().enumerate() {
        ram.write(&frame, i, byte).unwrap();
    }
    for i in 0..FRAME_SIZE as usize {
        assert_eq!(
            ram.read(&frame, i).unwrap(),
            content.get(i).copied().unwrap_or(0)
        );
    }
    let alias = direct_address(ram.offset, frame.start(), ram.bits).unwrap();
    let (object, cap) = MemoryObject::new(a, custody, frame)
        .unwrap_or_else(|(error, _frame)| panic!("desktop scalar publication: {error:?}"));
    (object, cap, alias)
}
fn port_object(a: &mut Authority, custody: SpaceId, ports: &mut Ports, ranges: &[Range]) -> Handle {
    let rights = Rights::READ
        | Rights::WRITE
        | Rights::DERIVE
        | Rights::TRANSFER
        | Rights::REVOKE
        | Rights::CONTROL;
    let cap = a.create_root(custody, Kind::IoPorts, rights).unwrap();
    ports.register(a, custody, cap, ranges).unwrap();
    cap
}
/// # Safety
/// Captured controller, no current writer/reader call; exact extent retained.
unsafe fn clear_extent(
    extent: &mut MemoryExtent,
    a: &Authority,
    custody: SpaceId,
    cap: Handle,
    offset: u64,
    bits: u8,
) {
    // A temporary real authorized WRITE lease retains the exact immutable page
    // identities. No user PTE or device aperture is created for this operation.
    let lease = extent.map(a, custody, cap, true).unwrap();
    extent.validate(a, &lease).unwrap();
    for physical in extent.physical_pages(&lease).unwrap() {
        let address = direct_address(offset, physical, bits).unwrap();
        // SAFETY: checked actual page of the retained WRITE lease, under the
        // caller's actual shared-surface quiescence/exclusive BSP guard.
        unsafe { clear_alias(address, FRAME_SIZE as usize) };
    }
    extent.unmap(lease).unwrap();
}
/// # Safety
/// Exact retained initialized RAM frame alias, all previous users quiescent.
unsafe fn clear_alias(address: u64, bytes: usize) {
    assert!(address != 0 && address.is_multiple_of(FRAME_SIZE) && bytes == FRAME_SIZE as usize);
    for i in 0..bytes {
        // SAFETY: called only with an exact retained RAM frame alias by the
        // exclusive captured controller; all shared-window users are quiescent.
        unsafe { (address as *mut u8).add(i).write_volatile(0) };
    }
    for i in 0..bytes {
        // SAFETY: same bounded retained frame; actual readback, no Rust alias.
        assert_eq!(unsafe { (address as *const u8).add(i).read_volatile() }, 0);
    }
}
#[cfg(not(feature = "test-m6-network"))]
fn verify_catalogue<'a>(assets: &Assets<'a>) -> VerifiedCatalogue<'a> {
    use ev_userspace_contract::root_v2;
    #[cfg(feature = "test-m5-native")]
    use ev_userspace_contract::root_v2::native;
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(assets.catalogue)),
        assets.catalogue_sha
    );
    let manifest = ev_kernel::root_manifest_v2::verify(
        assets.root_manifest,
        assets.root_measurement,
        assets.root_image,
    )
    .expect("actual Root manifest");
    assert_eq!(manifest.expected_catalogue_digest(), assets.catalogue_sha);
    let base = match assets.profile {
        #[cfg(not(feature = "test-m5-native"))]
        Profile::Desktop => {
            manifest
                .current_profile()
                .expect("explicit Desktop Root profile");
            Catalogue::decode(assets.catalogue).expect("actual Desktop catalogue")
        }
        #[cfg(feature = "test-m5-native")]
        Profile::Native => {
            manifest
                .native_profile()
                .expect("explicit Native Root profile");
            let c = native::catalogue::Catalogue::decode(assets.catalogue)
                .expect("actual complete Native catalogue");
            let (first, last) = c.measurement_parts();
            let mut hash = Sha256::new();
            hash.update(native::catalogue::MEASUREMENT_DOMAIN);
            hash.update(first);
            hash.update([0; 32]);
            hash.update(last);
            hash.update(native::layout_description());
            hash.update(root_v2::graph::description());
            #[cfg(feature = "test-m6-session")]
            hash.update(native::SESSION_LAYOUT);
            assert_eq!(<[u8; 32]>::from(hash.finalize()), c.layout_measurement());
            assert_eq!(assets.app_package.len() as u64, c.package_a_bytes());
            Catalogue::decode(&assets.catalogue[..native::catalogue::BASE_SIZE]).unwrap()
        }
    };
    assert_eq!(
        base.root_image(),
        <[u8; 32]>::from(Sha256::digest(assets.root_image))
    );
    #[cfg(feature = "test-m5-native")]
    assert_eq!(base.kernel_input(), build_id(crate::SOURCE_SHA256));
    #[cfg(not(feature = "test-m5-native"))]
    assert_eq!(base.kernel_input(), build_id(crate::BUILD_ID));
    if base.provenance() == root_v2::catalogue::Provenance::Zion {
        assert_eq!(
            base.package(),
            <[u8; 32]>::from(Sha256::digest(assets.app_package))
        );
    }
    for (metadata, (bytes, expected)) in base.images().zip(assets.images) {
        assert_eq!(metadata.image, expected);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), expected);
    }
    VerifiedCatalogue {
        bytes: assets.catalogue,
    }
}
fn build_id(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("desktop build ID hex"),
        };
        *out = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    result
}

#[cfg(feature = "test-m6-network")]
fn verify_catalogue<'a>(assets: &Assets<'a>) -> VerifiedCatalogue<'a> {
    use ev_userspace_contract::root_v4;
    let Profile::Network { images } = assets.profile;
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(assets.catalogue)),
        assets.catalogue_sha
    );
    let root = ev_kernel::root_manifest_v4::verify(
        assets.root_manifest,
        assets.root_measurement,
        assets.root_image,
    )
    .expect("actual V4 Root manifest");
    assert_eq!(
        root.manifest().expected_catalogue_digest(),
        assets.catalogue_sha
    );
    let c = root_v4::catalogue::Catalogue::decode(assets.catalogue)
        .expect("actual complete V4 catalogue");
    let (first, last) = c.measurement_parts();
    let mut h = Sha256::new();
    h.update(root_v4::catalogue::MEASUREMENT_DOMAIN);
    h.update(first);
    h.update([0; 32]);
    h.update(last);
    h.update(root_v4::layout_description());
    h.update(root_v4::graph::description());
    assert_eq!(<[u8; 32]>::from(h.finalize()), c.layout_measurement());
    let base = c.base();
    assert_eq!(
        base.root_image(),
        <[u8; 32]>::from(Sha256::digest(assets.root_image))
    );
    assert_eq!(base.kernel_input(), build_id(crate::SOURCE_SHA256));
    assert_eq!(assets.app_package.len() as u64, c.package_a_bytes());
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(assets.app_package)),
        c.package_a()
    );
    for (declared, (bytes, sha)) in base.images().zip(assets.images) {
        assert_eq!(declared.image, sha);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), sha);
    }
    for (declared, (bytes, sha)) in [c.net_driver(), c.net_service()].into_iter().zip(images) {
        assert_eq!(declared.image, sha);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), sha);
    }
    VerifiedCatalogue {
        bytes: assets.catalogue,
    }
}
