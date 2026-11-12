//! Bounded I/O-port authority; no device protocol, filesystem or in/out code.
//! One serialized owner retains this registry with its Authority/Scheduler/Rpc.
use crate::{
    capability::{self, Access, Authority, Handle, Kind, MAX_OBJECTS, Rights, SpaceId},
    rpc::{self, Rpc},
    scheduler::{self, Scheduler},
};
pub const MAX_RANGES: usize = 4;
/// Kernel-owned dispatch context. The syscall supplies none of these identities.
#[derive(Clone, Copy)]
pub struct Caller<'a> {
    pub authority: &'a Authority,
    pub scheduler: &'a Scheduler,
    pub rpc: &'a Rpc,
    pub cpu: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub capability: Handle,
    pub port: u64,
    pub width: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Byte,
    Word,
    Dword,
}
impl Width {
    pub fn from_bytes(bytes: u64) -> Result<Self, Error> {
        match bytes {
            1 => Ok(Self::Byte),
            2 => Ok(Self::Word),
            4 => Ok(Self::Dword),
            _ => Err(Error::Width),
        }
    }
    pub const fn bytes(self) -> u16 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
        }
    }
    fn mask(self) -> u8 {
        self.bytes() as u8
    }
    fn max(self) -> u64 {
        match self {
            Self::Byte => u8::MAX as u64,
            Self::Word => u16::MAX as u64,
            Self::Dword => u32::MAX as u64,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Widths(u8);
impl Widths {
    pub const BYTE: Self = Self(1);
    pub const WORD: Self = Self(2);
    pub const DWORD: Self = Self(4);
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits != 0 && bits & !7 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Input,
    Output,
    Both,
}
impl Direction {
    fn permits(self, output: bool) -> bool {
        matches!(
            (self, output),
            (Self::Both, _) | (Self::Input, false) | (Self::Output, true)
        )
    }
}
/// Immutable byte-port extent plus allowed transaction widths. Every requested
/// transaction must fit in one declared extent without wrapping 16-bit I/O space.
/// Data Word@[1e8,1e9] and Byte@[1e9,1ef] may coexist in one controller object;
/// the disjoint width masks allow only their declared starting-register accesses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub first: u16,
    pub last: u16,
    pub widths: Widths,
    pub direction: Direction,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority(capability::Error),
    Scheduler(scheduler::Error),
    Rpc(rpc::Error),
    UnknownObject,
    AlreadyRegistered,
    Range,
    Overlap,
    Width,
    Port,
    Direction,
    Value,
}
impl From<capability::Error> for Error {
    fn from(e: capability::Error) -> Self {
        Self::Authority(e)
    }
}
impl From<scheduler::Error> for Error {
    fn from(e: scheduler::Error) -> Self {
        Self::Scheduler(e)
    }
}
impl From<rpc::Error> for Error {
    fn from(e: rpc::Error) -> Self {
        Self::Rpc(e)
    }
}
#[derive(Clone, Copy)]
struct Binding {
    object: usize,
    ranges: [Option<Range>; MAX_RANGES],
    count: usize,
}
pub struct Registry {
    bindings: [Option<Binding>; MAX_OBJECTS],
}
impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
impl Registry {
    pub const fn new() -> Self {
        Self {
            bindings: [None; MAX_OBJECTS],
        }
    }
    pub fn registered(&self) -> usize {
        self.bindings.iter().flatten().count()
    }
    fn slot(object: usize) -> Result<usize, Error> {
        let slot = object & 255;
        if slot >= MAX_OBJECTS {
            Err(Error::UnknownObject)
        } else {
            Ok(slot)
        }
    }
    /// Trusted actual-resource binding, never a syscall accepting caller ranges.
    /// Distinct objects cannot overlap any assigned byte ports. Within one
    /// controller, overlapping extents require disjoint transaction widths.
    pub fn register(
        &mut self,
        a: &Authority,
        owner: SpaceId,
        cap: Handle,
        ranges: &[Range],
    ) -> Result<(), Error> {
        let object = a
            .authorize(owner, cap, Kind::IoPorts, Rights::CONTROL)?
            .identity();
        let slot = Self::slot(object)?;
        if self.bindings[slot].is_some() {
            return Err(Error::AlreadyRegistered);
        }
        if ranges.is_empty() || ranges.len() > MAX_RANGES {
            return Err(Error::Range);
        }
        for (i, range) in ranges.iter().enumerate() {
            if range.first > range.last || Widths::from_bits(range.widths.0).is_none() {
                return Err(Error::Range);
            }
            let extent = u32::from(range.last) - u32::from(range.first) + 1;
            if ![Width::Byte, Width::Word, Width::Dword]
                .iter()
                .any(|width| {
                    range.widths.0 & width.mask() != 0 && u32::from(width.bytes()) <= extent
                })
            {
                return Err(Error::Range);
            }
            for other in &ranges[..i] {
                if overlap(*range, *other) && range.widths.0 & other.widths.0 != 0 {
                    return Err(Error::Overlap);
                }
            }
            if self.bindings.iter().flatten().any(|binding| {
                binding.ranges[..binding.count]
                    .iter()
                    .flatten()
                    .any(|other| overlap(*range, *other))
            }) {
                return Err(Error::Overlap);
            }
        }
        let mut stored = [None; MAX_RANGES];
        for (slot, range) in stored.iter_mut().zip(ranges) {
            *slot = Some(*range);
        }
        self.bindings[slot] = Some(Binding {
            object,
            ranges: stored,
            count: ranges.len(),
        });
        Ok(())
    }
    fn check<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
        output: bool,
    ) -> Result<Permit<'a>, Error> {
        let Caller {
            authority: a,
            scheduler: s,
            rpc,
            cpu,
        } = caller;
        let Request {
            capability: cap,
            port,
            width,
        } = request;
        let thread = s.running_thread(cpu)?;
        let domain = rpc.checked_thread_domain(s, thread)?;
        let access = a.authorize(
            domain,
            cap,
            Kind::IoPorts,
            if output { Rights::WRITE } else { Rights::READ },
        )?;
        let object = access.identity();
        let binding = self.bindings[Self::slot(object)?]
            .as_ref()
            .filter(|binding| binding.object == object)
            .ok_or(Error::UnknownObject)?;
        let port = u16::try_from(port).map_err(|_| Error::Port)?;
        let width = Width::from_bytes(width)?;
        let end = port.checked_add(width.bytes() - 1).ok_or(Error::Port)?;
        let range = binding.ranges[..binding.count]
            .iter()
            .flatten()
            .find(|range| {
                port >= range.first && end <= range.last && range.widths.0 & width.mask() != 0
            })
            .ok_or(Error::Range)?;
        if !range.direction.permits(output) {
            return Err(Error::Direction);
        }
        Ok(Permit {
            access,
            _binding: binding,
            port,
            width,
        })
    }
    /// This permit borrows the live authority and immutable binding across the
    /// actual single binary instruction; it cannot be cloned or forged by a user.
    pub fn input<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
    ) -> Result<ReadPermit<'a>, Error> {
        Ok(ReadPermit(self.check(caller, request, false)?))
    }
    pub fn output<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
        value: u64,
    ) -> Result<WritePermit<'a>, Error> {
        let permit = self.check(caller, request, true)?;
        if value > permit.width.max() {
            return Err(Error::Value);
        }
        Ok(WritePermit {
            permit,
            value: value as u32,
        })
    }
    /// Trusted metadata retirement after independent device/IRQ/operation
    /// quiescence. This does not certify a completed or durable disk write.
    pub fn retire(&mut self, a: &mut Authority, owner: SpaceId, cap: Handle) -> Result<(), Error> {
        let object = a
            .authorize(owner, cap, Kind::IoPorts, Rights::CONTROL)?
            .identity();
        let slot = Self::slot(object)?;
        if !self.bindings[slot].is_some_and(|binding| binding.object == object) {
            return Err(Error::UnknownObject);
        }
        let mut staged = a.staged_copy();
        staged.close(owner, cap)?;
        staged.collect_lineage()?;
        staged.retire_unreferenced_object(object, Kind::IoPorts)?;
        staged.collect_dead_objects()?;
        *a = staged;
        self.bindings[slot] = None;
        Ok(())
    }
}
fn overlap(a: Range, b: Range) -> bool {
    a.first <= b.last && b.first <= a.last
}
struct Permit<'a> {
    access: Access<'a>,
    _binding: &'a Binding,
    port: u16,
    width: Width,
}
pub struct ReadPermit<'a>(Permit<'a>);
impl ReadPermit<'_> {
    pub fn port(&self) -> u16 {
        self.0.port
    }
    pub fn width(&self) -> Width {
        self.0.width
    }
    pub fn object(&self) -> usize {
        self.0.access.identity()
    }
}
pub struct WritePermit<'a> {
    permit: Permit<'a>,
    value: u32,
}
impl WritePermit<'_> {
    pub fn port(&self) -> u16 {
        self.permit.port
    }
    pub fn width(&self) -> Width {
        self.permit.width
    }
    pub fn value(&self) -> u32 {
        self.value
    }
    pub fn object(&self) -> usize {
        self.permit.access.identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
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
    struct Fixture {
        a: Authority,
        s: Scheduler,
        rpc: Rpc,
        registry: Registry,
        domains: [SpaceId; 2],
        threads: [crate::scheduler::ThreadId; 2],
        caps: [Handle; 2],
        current: bool,
    }
    fn fixture() -> Fixture {
        let mut a = Authority::new();
        let domains = [a.create_space().unwrap(), a.create_space().unwrap()];
        let cap = a
            .create_root(
                domains[0],
                Kind::IoPorts,
                Rights::READ
                    | Rights::WRITE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::TRANSFER
                    | Rights::REVOKE,
            )
            .unwrap();
        let read = a.derive(domains[0], cap, domains[1], Rights::READ).unwrap();
        let mut s = Scheduler::new();
        let jobs = [s.create_job().unwrap(), s.create_job().unwrap()];
        let processes = jobs.map(|job| s.create_process(job).unwrap());
        let threads = processes.map(|p| s.create_thread(p).unwrap());
        let mut rpc = Rpc::new(NonZeroU64::new(90).unwrap());
        for i in 0..2 {
            rpc.register_thread(&a, &s, threads[i], jobs[i], domains[i], None)
                .unwrap();
        }
        let mut registry = Registry::new();
        registry.register(&a, domains[0], cap, &ATA).unwrap();
        Fixture {
            a,
            s,
            rpc,
            registry,
            domains,
            threads,
            caps: [cap, read],
            current: false,
        }
    }
    impl Fixture {
        fn run(&mut self, index: usize) {
            if self.current {
                self.s.yield_cpu(0).unwrap();
            }
            for _ in 0..scheduler::MAX_THREADS {
                let thread = self.s.dispatch(0).unwrap().unwrap().thread;
                if thread == self.threads[index] {
                    self.current = true;
                    return;
                }
                self.s.yield_cpu(0).unwrap();
            }
            panic!("model actor not runnable");
        }
        fn caller(&self) -> Caller<'_> {
            Caller {
                authority: &self.a,
                scheduler: &self.s,
                rpc: &self.rpc,
                cpu: 0,
            }
        }
        fn read(&self, index: usize, port: u64, width: u64) -> Result<ReadPermit<'_>, Error> {
            self.registry.input(
                self.caller(),
                Request {
                    capability: self.caps[index],
                    port,
                    width,
                },
            )
        }
        fn write(
            &self,
            index: usize,
            port: u64,
            width: u64,
            value: u64,
        ) -> Result<WritePermit<'_>, Error> {
            self.registry.output(
                self.caller(),
                Request {
                    capability: self.caps[index],
                    port,
                    width,
                },
                value,
            )
        }
    }
    #[test]
    fn exact_data_word_and_byte_registers_produce_only_typed_permits() {
        let mut f = fixture();
        f.run(0);
        let data = f.read(0, 0x1e8, 2).unwrap();
        assert_eq!((data.port(), data.width()), (0x1e8, Width::Word));
        let command = f.write(0, 0x1ef, 1, 0xec).unwrap();
        assert_eq!(
            (command.port(), command.width(), command.value()),
            (0x1ef, Width::Byte, 0xec)
        );
        assert!(f.read(0, 0x3ee, 1).is_ok());
        assert_eq!(f.read(0, 0x1e8, 1).err(), Some(Error::Range));
        assert_eq!(f.read(0, 0x1e9, 2).err(), Some(Error::Range));
        assert_eq!(f.read(0, 0x1e8, 4).err(), Some(Error::Range));
        assert_eq!(f.read(0, 0x1ef, 2).err(), Some(Error::Range));
        assert_eq!(f.read(0, 0x3ef, 1).err(), Some(Error::Range));
    }
    #[test]
    fn no_cap_means_no_pic_pit_serial_pci_or_exit_authority() {
        let mut f = fixture();
        f.run(0);
        for port in [
            0x20, 0x21, 0x40, 0x43, 0xa0, 0xf4, 0x1f0, 0x3f8, 0xcf8, 0xcfc,
        ] {
            assert_eq!(f.read(0, port, 1).err(), Some(Error::Range));
            assert_eq!(f.write(0, port, 1, 0).err(), Some(Error::Range));
        }
        assert_eq!(
            f.registry
                .input(
                    f.caller(),
                    Request {
                        capability: Handle(u64::MAX),
                        port: 0x1ef,
                        width: 1
                    }
                )
                .err(),
            Some(Error::Authority(capability::Error::InvalidHandle))
        );
        let memory =
            f.a.create_root(
                f.domains[0],
                Kind::Memory,
                Rights::READ | Rights::WRITE | Rights::CONTROL,
            )
            .unwrap();
        assert_eq!(
            f.registry
                .input(
                    f.caller(),
                    Request {
                        capability: memory,
                        port: 0x1ef,
                        width: 1
                    }
                )
                .err(),
            Some(Error::Authority(capability::Error::WrongKind))
        );
        assert_eq!(f.registry.registered(), 1);
    }
    #[test]
    fn actual_registered_caller_domain_attenuation_and_revocation_are_enforced() {
        let mut f = fixture();
        assert_eq!(
            f.read(0, 0x1ef, 1).err(),
            Some(Error::Scheduler(scheduler::Error::CpuIdle))
        );
        f.run(1);
        assert!(f.read(1, 0x1ef, 1).is_ok());
        assert_eq!(
            f.write(1, 0x1ef, 1, 0xec).err(),
            Some(Error::Authority(capability::Error::Denied))
        );
        f.a.revoke(f.domains[0], f.caps[0]).unwrap();
        assert_eq!(
            f.read(1, 0x1ef, 1).err(),
            Some(Error::Authority(capability::Error::Revoked))
        );
    }
    #[test]
    fn invalid_ports_widths_and_nonfitting_output_values_never_get_permits() {
        let mut f = fixture();
        f.run(0);
        for port in [65536, u64::MAX] {
            assert_eq!(f.read(0, port, 1).err(), Some(Error::Port));
        }
        for width in [0, 3, 8, u64::MAX] {
            assert_eq!(f.read(0, 0x1ef, width).err(), Some(Error::Width));
        }
        assert_eq!(f.write(0, 0x1ef, 1, 256).err(), Some(Error::Value));
        assert_eq!(f.write(0, 0x1e8, 2, 65536).err(), Some(Error::Value));
        assert!(f.write(0, 0x1e8, 2, 65535).is_ok());
        assert_eq!(f.registry.registered(), 1);
    }
    #[test]
    fn range_validation_overlap_and_rebinding_fail_before_commit() {
        let mut f = fixture();
        let cap =
            f.a.create_root(
                f.domains[0],
                Kind::IoPorts,
                Rights::CONTROL | Rights::READ | Rights::WRITE,
            )
            .unwrap();
        assert_eq!(
            f.registry.register(&f.a, f.domains[0], cap, &[]),
            Err(Error::Range)
        );
        assert_eq!(
            f.registry.register(
                &f.a,
                f.domains[0],
                cap,
                &[Range {
                    first: 5,
                    last: 4,
                    ..ATA[1]
                }]
            ),
            Err(Error::Range)
        );
        assert_eq!(
            f.registry.register(
                &f.a,
                f.domains[0],
                cap,
                &[Range {
                    first: 0xffff,
                    last: 0xffff,
                    widths: Widths::WORD,
                    ..ATA[1]
                }]
            ),
            Err(Error::Range)
        );
        assert_eq!(
            f.registry.register(&f.a, f.domains[0], cap, &[ATA[1]]),
            Err(Error::Overlap)
        );
        assert_eq!(
            f.registry.register(
                &f.a,
                f.domains[0],
                f.caps[0],
                &[Range {
                    first: 0,
                    last: 255,
                    ..ATA[1]
                }]
            ),
            Err(Error::AlreadyRegistered)
        );
        assert_eq!(f.registry.registered(), 1);
        f.run(0);
        assert_eq!(f.read(0, 0x20, 1).err(), Some(Error::Range));
    }
    #[test]
    fn immutable_direction_is_additional_to_capability_rights() {
        let mut f = fixture();
        let cap =
            f.a.create_root(
                f.domains[0],
                Kind::IoPorts,
                Rights::CONTROL | Rights::READ | Rights::WRITE,
            )
            .unwrap();
        let range = Range {
            first: 0x600,
            last: 0x603,
            widths: Widths::DWORD,
            direction: Direction::Input,
        };
        f.registry
            .register(&f.a, f.domains[0], cap, &[range])
            .unwrap();
        f.run(0);
        assert!(
            f.registry
                .input(
                    f.caller(),
                    Request {
                        capability: cap,
                        port: 0x600,
                        width: 4
                    }
                )
                .is_ok()
        );
        assert_eq!(
            f.registry
                .output(
                    f.caller(),
                    Request {
                        capability: cap,
                        port: 0x600,
                        width: 4
                    },
                    0
                )
                .err(),
            Some(Error::Direction)
        );
    }
    #[test]
    fn pinned_retirement_and_full_generation_reuse_do_not_alias_old_authority() {
        let mut f = fixture();
        f.run(0);
        let old = f.read(0, 0x1ef, 1).unwrap().object();
        assert_eq!(
            f.registry.retire(&mut f.a, f.domains[0], f.caps[0]),
            Err(Error::Authority(capability::Error::ObjectBusy))
        );
        assert!(f.read(0, 0x1ef, 1).is_ok());
        f.a.close(f.domains[1], f.caps[1]).unwrap();
        f.registry
            .retire(&mut f.a, f.domains[0], f.caps[0])
            .unwrap();
        let next =
            f.a.create_root(
                f.domains[0],
                Kind::IoPorts,
                Rights::CONTROL | Rights::READ | Rights::WRITE,
            )
            .unwrap();
        f.registry.register(&f.a, f.domains[0], next, &ATA).unwrap();
        assert_eq!(
            f.read(0, 0x1ef, 1).err(),
            Some(Error::Authority(capability::Error::InvalidHandle))
        );
        let permit = f
            .registry
            .input(
                f.caller(),
                Request {
                    capability: next,
                    port: 0x1ef,
                    width: 1,
                },
            )
            .unwrap();
        assert_ne!(permit.object(), old);
    }
}
