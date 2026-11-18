//! Retained actual source factories, exact37-role creation order and real RAM/
//! device claims. Publication never creates a second hidden source identity.
use super::*;
use crate::display_runtime::DisplayAperture;
use ev_kernel::{
    display::DisplayObject,
    io_ports::{Direction, Range, Registry as Ports, Widths},
    mapping::direct_address,
    memory::PhysicalFrame,
    memory_extent::{
        M8SharedExtent as MemoryExtent, M8SharedUninitializedRam as UninitializedRam, RamAccess,
    },
};
pub(super) struct Backing {
    pub custody: SpaceId,
    pub sources: [Handle; 37],
    pub extents: [Option<MemoryExtent>; 37],
    pub ports: Ports,
    pub device: Option<DisplayObject<DisplayAperture>>,
    pub ram_parent: JobId,
    pub hw: Hardware,
}
struct Ram(Hardware);
// SAFETY: exact checked actual allocator frame/byte and retained direct map,
// truthful volatile write/readback; no reference or hardware alias is retained.
unsafe impl RamAccess for Ram {
    type Error = &'static str;
    fn write(&mut self, frame: &PhysicalFrame, byte: usize, value: u8) -> Result<(), Self::Error> {
        if byte >= 4096 {
            return Err("V5 RAM byte bounds");
        }
        let p = direct_address(self.0.offset, frame.start(), self.0.bits)
            .map_err(|_| "V5 RAM direct map")?;
        // SAFETY: checked byte of the exact passed allocator-owned RAM frame.
        unsafe { (p as *mut u8).add(byte).write_volatile(value) };
        Ok(())
    }
    fn read(&mut self, frame: &PhysicalFrame, byte: usize) -> Result<u8, Self::Error> {
        if byte >= 4096 {
            return Err("V5 RAM byte bounds");
        }
        let p = direct_address(self.0.offset, frame.start(), self.0.bits)
            .map_err(|_| "V5 RAM direct map")?;
        // SAFETY: retained frame and checked byte; truthful volatile readback.
        Ok(unsafe { (p as *const u8).add(byte).read_volatile() })
    }
}
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
const RTC: [Range; 2] = [
    Range {
        first: 0x70,
        last: 0x70,
        widths: Widths::BYTE,
        direction: Direction::Output,
    },
    Range {
        first: 0x71,
        last: 0x71,
        widths: Widths::BYTE,
        direction: Direction::Input,
    },
];
const NIC: [Range; 1] = [Range {
    first: 0x300,
    last: 0x31f,
    widths: Widths::BYTE,
    direction: Direction::Both,
}];
fn pages(role: Role) -> usize {
    match role {
        Role::EditorOneSurface
        | Role::EditorTwoSurface
        | Role::FilesSurface
        | Role::InspectorSurface
        | Role::ShellSurface
        | Role::PackageCandidate => 63,
        Role::PackageCurrent => v5::resources::PACKAGE_CURRENT_PAGES as usize,
        Role::ProtectedSurface => 51,
        Role::Catalogue => 3,
        Role::EditorOneFrame
        | Role::EditorTwoFrame
        | Role::FilesFrame
        | Role::InspectorFrame
        | Role::RootWorkspaceFrame => 2,
        _ => 1,
    }
}
impl Backing {
    pub const fn empty(custody: SpaceId, parent: JobId, hw: Hardware) -> Self {
        Self {
            custody,
            sources: [Handle(0); 37],
            extents: [const { None }; 37],
            ports: Ports::new(),
            device: None,
            ram_parent: parent,
            hw,
        }
    }
    /// # Safety
    /// Field-resident fresh selected backing, verified actual V5 assets, actual
    /// sole allocator/device/controller owner and no admitted process/lease.
    pub unsafe fn populate(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        frames: &mut BootstrapFrames,
        fb: ev_boot_contract::Framebuffer,
        assets: &Assets,
    ) {
        assert_eq!(a.slot_capacity(self.custody), Ok(96));
        assert_eq!(
            a.metadata_usage().1,
            0,
            "V5 sources are first actual objects"
        );
        for spec in v5::ROLES {
            let role = spec.role;
            let index = role.selector() as usize - 1;
            let kind = kind(spec.kind);
            let cap = match kind {
                Kind::Display => {
                    // SAFETY: trusted actual GOP descriptor/retained tables.
                    let aperture = unsafe { DisplayAperture::discover(self.hw.offset, fb, frames) }
                        .expect("actual V5 GOP source");
                    let (device, cap) = DisplayObject::new(a, self.custody, aperture)
                        .unwrap_or_else(|(e, _)| panic!("V5 Display source:{e:?}"));
                    self.device = Some(device);
                    cap
                }
                Kind::IoPorts => {
                    let cap = a
                        .create_root(
                            self.custody,
                            kind,
                            ev_kernel::root_producer_v5::source_rights(role),
                        )
                        .unwrap();
                    let ranges: &[Range] = match role {
                        Role::AtaPorts => &ATA,
                        Role::InputPorts => &INPUT,
                        Role::OwnerUart => &UART,
                        Role::RtcPorts => &RTC,
                        Role::NicPorts => &NIC,
                        _ => panic!("V5 ports role"),
                    };
                    self.ports
                        .register(a, self.custody, cap, ranges)
                        .expect("actual V5 port registry");
                    cap
                }
                Kind::Memory if graph::IMAGES.into_iter().any(|slot| slot.role() == role) => a
                    .create_root(
                        self.custody,
                        kind,
                        ev_kernel::root_producer_v5::source_rights(role),
                    )
                    .unwrap(),
                Kind::Memory => {
                    let raw = UninitializedRam::allocate(frames, s, self.ram_parent, pages(role))
                        .unwrap_or_else(|r| panic!("V5 extent allocation:{:?}", r.error));
                    let initialized = raw
                        .initialize(&mut Ram(self.hw))
                        .unwrap_or_else(|r| panic!("V5 extent initialize:{:?}", r.error));
                    let (extent, cap) =
                        MemoryExtent::publish(a, self.custody, initialized, frames, s)
                            .unwrap_or_else(|r| panic!("V5 extent publish:{:?}", r.error));
                    self.extents[index] = Some(extent);
                    cap
                }
                Kind::Job | Kind::Endpoint => a
                    .create_root(
                        self.custody,
                        kind,
                        ev_kernel::root_producer_v5::source_rights(role),
                    )
                    .unwrap(),
                _ => panic!("V5 source kind"),
            };
            self.sources[index] = cap;
        }
        // Actual initialized byte copies/readback into retained independent
        // extents; no document/catalogue-sized stack value is constructed.
        // SAFETY: fresh quiescent owned catalogue extent, verified actual bytes.
        unsafe { self.fill(a, Role::Catalogue, 0, assets.catalogue.bytes) };
        for (index, placement) in assets.placements.iter().enumerate() {
            let role = if placement.bank == 0 {
                Role::PackageCurrent
            } else {
                Role::PackageCandidate
            };
            // SAFETY: actual checked nonoverlapping package bank placement;
            // no process or foreign extent mapping has been admitted.
            unsafe {
                self.fill(
                    a,
                    role,
                    placement.offset as usize,
                    assets.packages[index].bytes,
                )
            };
        }
        if let Some(artifact) = assets.external_ingress {
            let catalogue = v5::catalogue::Catalogue::decode(assets.catalogue.bytes).unwrap();
            let ingress = catalogue
                .external_ingress()
                .expect("verified ingress descriptor");
            // SAFETY: independently verified full bytes in the canonical unused
            // Candidate tail; the actual Root mapping remains READ/MAP only.
            unsafe {
                self.fill(
                    a,
                    Role::PackageCandidate,
                    ingress.package.offset as usize,
                    artifact.bytes,
                )
            };
        }
    }
    unsafe fn fill(&mut self, a: &Authority, role: Role, offset: usize, content: &[u8]) {
        let extent = self.extents[role.selector() as usize - 1].as_mut().unwrap();
        let cap = self.sources[role.selector() as usize - 1];
        assert!(
            offset
                .checked_add(content.len())
                .is_some_and(|end| end <= extent.pages() * 4096)
        );
        let lease = extent.map(a, self.custody, cap, true).unwrap();
        extent.validate(a, &lease).unwrap();
        for (page, physical) in extent.physical_pages(&lease).unwrap().enumerate() {
            let address = direct_address(self.hw.offset, physical, self.hw.bits).unwrap();
            for byte in 0..4096 {
                let at = page * 4096 + byte;
                if let Some(source) = at.checked_sub(offset).and_then(|i| content.get(i)) {
                    // SAFETY: exact bounded page of the retained WRITE lease,
                    // no user writer; compare the actual physical byte.
                    unsafe {
                        (address as *mut u8).add(byte).write_volatile(*source);
                        assert_eq!((address as *const u8).add(byte).read_volatile(), *source);
                    }
                }
            }
        }
        extent.unmap(lease).unwrap();
    }
    pub fn source(&self, role: Role) -> Handle {
        self.sources[role.selector() as usize - 1]
    }
    pub fn identity(&self, a: &Authority, role: Role) -> usize {
        let spec = v5::ROLES[role.selector() as usize - 1];
        a.authorize(
            self.custody,
            self.source(role),
            kind(spec.kind),
            Rights::from_bits(spec.rights).unwrap(),
        )
        .unwrap()
        .identity()
    }
    /// # Safety
    /// Sole IF0/controller CR3 with APs parked. The exact old app has stopped,
    /// every accepted RPC/loan and selected delivery has settled, its physical
    /// mappings have detached, and no replacement has been admitted. Display
    /// may retain its readonly mapping; it cannot execute during this scrub.
    /// Root must also remove the old surface from the visible owner model.
    pub unsafe fn scrub_retired_app(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        meta: Metadata,
        child: Child,
    ) -> Result<usize, &'static str> {
        if s.state(meta.thread) != Ok(State::Exited)
            || s.usage(meta.job, Resource::Processes) != Ok(0)
            || s.usage(meta.job, Resource::Threads) != Ok(0)
        {
            return Err("V5 app scrub before actual stop");
        }
        let roles: &[Role] = match child {
            Child::EditorOne => &[Role::EditorOneSurface, Role::EditorOneFrame],
            Child::EditorTwo => &[Role::EditorTwoSurface, Role::EditorTwoFrame],
            Child::Files => &[Role::FilesSurface, Role::FilesFrame],
            Child::Inspector => &[Role::InspectorSurface, Role::InspectorFrame],
            Child::Shell => &[Role::ShellSurface],
            _ => return Ok(0),
        };
        let mut cleared = 0;
        for role in roles {
            let index = role.selector() as usize - 1;
            let extent = self.extents[index]
                .as_mut()
                .ok_or("V5 scrub missing extent")?;
            if extent.pages() != pages(*role) {
                return Err("V5 scrub extent length");
            }
            let lease = extent
                .map(a, self.custody, self.sources[index], true)
                .map_err(|_| "V5 scrub exact source authority")?;
            extent
                .validate(a, &lease)
                .map_err(|_| "V5 scrub changed lease")?;
            // SAFETY: exact old app CPU/mappings/accepted calls have retired;
            // this sole IF0 controller excludes remaining readonly readers.
            // The real Ram adapter uses exact retained allocator frame IDs.
            unsafe { extent.scrub_captured(a, &lease, &mut Ram(self.hw)) }
                .map_err(|_| "V5 scrub actual RAM access/readback; lease retained")?;
            cleared += extent.pages();
            extent.unmap(lease).map_err(|_| "V5 scrub lease return")?;
        }
        Ok(cleared)
    }
}
