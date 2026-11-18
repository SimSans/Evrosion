//! Bounded I/O-port authority; no device protocol, filesystem or in/out code.
//! One serialized owner retains this registry with its Authority/Scheduler/Rpc.
use crate::{
    capability::{
        self, Access, Authority, Handle, Kind, OBJECT_STORAGE_CAPACITY as MAX_OBJECTS, Rights,
        SpaceId,
    },
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
    Deadline,
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
    /// Fixed four Word transactions at one port, under one live borrowed
    /// authority. A caller's fresh cleanup cut does not revoke or mint ports;
    /// actual stop/revocation still denies the device owner as for scalar I/O.
    pub fn input_words4<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
        deadline: u64,
        now: u64,
    ) -> Result<ReadWords4Permit<'a>, Error> {
        batch_shape(request, deadline, now)?;
        Ok(ReadWords4Permit(self.check(caller, request, false)?))
    }
    /// Fixed sector permission. Buffer ownership is checked independently by
    /// the selected physical executor before invoking this retained permit.
    #[cfg(feature = "workspace-authority")]
    pub fn words256_call<'a>(
        &'a self,
        caller: Caller<'a>,
        call: crate::user_context::Call,
        now: u64,
    ) -> Result<Words256Permit<'a>, Error> {
        use crate::user_context::Call;
        let (capability, port, deadline, output) = match call {
            Call::PortInputWords256 {
                capability,
                port,
                deadline,
                ..
            } => (capability, port, deadline, false),
            Call::PortOutputWords256 {
                capability,
                port,
                deadline,
                ..
            } => (capability, port, deadline, true),
            _ => return Err(Error::Width),
        };
        let request = Request {
            capability,
            port,
            width: 2,
        };
        batch_shape(request, deadline, now)?;
        let permit = self.check(caller, request, output)?;
        Ok(if output {
            Words256Permit::Output(WriteWords256Permit(permit))
        } else {
            Words256Permit::Input(ReadWords256Permit(permit))
        })
    }
    pub fn output_words4<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
        value: u64,
        deadline: u64,
        now: u64,
    ) -> Result<WriteWords4Permit<'a>, Error> {
        batch_shape(request, deadline, now)?;
        Ok(WriteWords4Permit {
            permit: self.check(caller, request, true)?,
            value,
        })
    }
    /// Selected scalar decoding to the actual borrowed output permit. Keep
    /// payload and deadline named across this boundary: both are u64, but the
    /// packed data must never become the finite preflight deadline.
    #[cfg(feature = "workspace-authority")]
    pub fn output_batch_call<'a>(
        &'a self,
        caller: Caller<'a>,
        call: crate::user_context::Call,
        now: u64,
    ) -> Result<OutputBatchPermit<'a>, Error> {
        use crate::user_context::Call;
        match call {
            Call::PortOutputWords4 {
                capability,
                port,
                deadline,
                value,
            } => self
                .output_words4(
                    caller,
                    Request {
                        capability,
                        port,
                        width: 2,
                    },
                    value,
                    deadline,
                    now,
                )
                .map(OutputBatchPermit::Words),
            Call::PortOutputBytes4 {
                capability,
                port,
                deadline,
                value,
            } => self
                .output_bytes4(
                    caller,
                    Request {
                        capability,
                        port,
                        width: 1,
                    },
                    value,
                    deadline,
                    now,
                )
                .map(OutputBatchPermit::Bytes),
            _ => Err(Error::Width),
        }
    }
    /// Four byte transactions at exactly one scoped port. The full current
    /// caller/capability/range/direction check precedes any physical operation.
    pub fn input_bytes4<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
        deadline: u64,
        now: u64,
    ) -> Result<ReadBytes4Permit<'a>, Error> {
        byte_batch_shape(request, deadline, now)?;
        Ok(ReadBytes4Permit(self.check(caller, request, false)?))
    }
    pub fn output_bytes4<'a>(
        &'a self,
        caller: Caller<'a>,
        request: Request,
        value: u64,
        deadline: u64,
        now: u64,
    ) -> Result<WriteBytes4Permit<'a>, Error> {
        byte_batch_shape(request, deadline, now)?;
        if value > u32::MAX as u64 {
            return Err(Error::Value);
        }
        Ok(WriteBytes4Permit {
            permit: self.check(caller, request, true)?,
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
fn byte_batch_shape(request: Request, deadline: u64, now: u64) -> Result<(), Error> {
    if request.width != 1 {
        return Err(Error::Width);
    }
    if deadline == 0
        || deadline == u64::MAX
        || deadline <= now
        || deadline - now > ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS
    {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn batch_shape(request: Request, deadline: u64, now: u64) -> Result<(), Error> {
    if request.width != 2 {
        return Err(Error::Width);
    }
    if deadline == 0
        || deadline == u64::MAX
        || deadline <= now
        || deadline - now > ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS
    {
        return Err(Error::Deadline);
    }
    Ok(())
}
struct Permit<'a> {
    access: Access<'a>,
    _binding: &'a Binding,
    port: u16,
    width: Width,
}
#[cfg(feature = "workspace-authority")]
pub enum Words256Permit<'a> {
    Input(ReadWords256Permit<'a>),
    Output(WriteWords256Permit<'a>),
}
#[cfg(feature = "workspace-authority")]
pub struct ReadWords256Permit<'a>(Permit<'a>);
#[cfg(feature = "workspace-authority")]
pub struct WriteWords256Permit<'a>(Permit<'a>);
#[cfg(feature = "workspace-authority")]
impl ReadWords256Permit<'_> {
    /// Exactly256 same-port Word reads into Kernel scratch. No caller loop
    /// bound or pointer reaches the device boundary; permit lives to the end.
    pub fn transfer(self, bytes: &mut [u8; 512], mut read: impl FnMut(u16) -> u16) {
        for pair in bytes.as_chunks_mut::<2>().0 {
            pair.copy_from_slice(&read(self.0.port).to_le_bytes());
        }
    }
}
#[cfg(feature = "workspace-authority")]
impl WriteWords256Permit<'_> {
    pub fn transfer(self, bytes: &[u8; 512], mut write: impl FnMut(u16, u16)) {
        for pair in bytes.as_chunks::<2>().0 {
            write(self.0.port, u16::from_le_bytes(*pair));
        }
    }
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
/// Non-cloneable live permission for four Byte operations, never four ports.
pub struct ReadBytes4Permit<'a>(Permit<'a>);
impl ReadBytes4Permit<'_> {
    pub fn port(&self) -> u16 {
        self.0.port
    }
    pub fn object(&self) -> usize {
        self.0.access.identity()
    }
}
pub struct WriteBytes4Permit<'a> {
    permit: Permit<'a>,
    value: u32,
}
impl WriteBytes4Permit<'_> {
    pub fn port(&self) -> u16 {
        self.permit.port
    }
    pub fn object(&self) -> usize {
        self.permit.access.identity()
    }
    pub fn value(&self) -> u32 {
        self.value
    }
}
pub struct WritePermit<'a> {
    permit: Permit<'a>,
    value: u32,
}
/// Non-cloneable, non-forgeable borrowed permission for exactly four Word ops.
pub struct ReadWords4Permit<'a>(Permit<'a>);
impl ReadWords4Permit<'_> {
    pub fn port(&self) -> u16 {
        self.0.port
    }
    pub fn object(&self) -> usize {
        self.0.access.identity()
    }
}
pub struct WriteWords4Permit<'a> {
    permit: Permit<'a>,
    value: u64,
}
#[cfg(feature = "workspace-authority")]
pub enum OutputBatchPermit<'a> {
    Words(WriteWords4Permit<'a>),
    Bytes(WriteBytes4Permit<'a>),
}
impl WriteWords4Permit<'_> {
    pub fn port(&self) -> u16 {
        self.permit.port
    }
    pub fn object(&self) -> usize {
        self.permit.access.identity()
    }
    pub fn value(&self) -> u64 {
        self.value
    }
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
    #[path = "byte_batch.rs"]
    mod byte_batch;
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
    #[cfg(feature = "workspace-authority")]
    #[test]
    fn decoded_output_batches_keep_catalogue_payload_separate_from_the_actual_deadline() {
        use crate::user_context::{UserContext, decode};
        use ev_userspace_contract::syscall;
        let mut f = fixture();
        f.run(0);
        let now = 100;
        let cut = now + syscall::PORT_BATCH_MAX_TICKS.min(8);
        for (number, port, data) in [
            (
                syscall::PORT_OUTPUT_WORDS4,
                0x1e8,
                u64::from_le_bytes(*b"EVWENT01"),
            ),
            (syscall::PORT_OUTPUT_WORDS4, 0x1e8, 0),
            (syscall::PORT_OUTPUT_BYTES4, 0x1e9, 0x89ab_cdef),
            (syscall::PORT_OUTPUT_BYTES4, 0x1e9, 0),
        ] {
            let mut frame = UserContext::ZERO;
            frame.registers[14] = number;
            frame.registers[8] = f.caps[0].0;
            frame.registers[9] = port;
            frame.registers[11] = cut;
            frame.registers[5] = data;
            match f
                .registry
                .output_batch_call(f.caller(), decode(&frame).unwrap(), now)
                .unwrap()
            {
                OutputBatchPermit::Words(permit) => {
                    assert_eq!(number, syscall::PORT_OUTPUT_WORDS4);
                    assert_eq!(permit.value(), data);
                    assert_eq!(u64::from(permit.port()), port);
                }
                OutputBatchPermit::Bytes(permit) => {
                    assert_eq!(number, syscall::PORT_OUTPUT_BYTES4);
                    assert_eq!(u64::from(permit.value()), data);
                    assert_eq!(u64::from(permit.port()), port);
                }
            }
            frame.registers[11] = now;
            assert!(matches!(
                f.registry
                    .output_batch_call(f.caller(), decode(&frame).unwrap(), now),
                Err(Error::Deadline)
            ));
        }
        f.run(1);
        let call = crate::user_context::Call::PortOutputWords4 {
            capability: f.caps[1],
            port: 0x1e8,
            deadline: cut,
            value: 0,
        };
        assert!(f.registry.output_batch_call(f.caller(), call, now).is_err());
    }
    #[cfg(feature = "workspace-authority")]
    #[test]
    fn fixed_sector_decode_permits_exact_256_words_at_one_port_with_little_endian_scratch() {
        use crate::user_context::{UserContext, decode};
        use ev_userspace_contract::syscall;
        let mut f = fixture();
        f.run(0);
        let mut frame = UserContext::ZERO;
        frame.registers[14] = syscall::PORT_INPUT_WORDS256;
        frame.registers[8] = f.caps[0].0;
        frame.registers[9] = 0x1e8;
        frame.registers[11] = 110;
        frame.registers[5] = 0x8000003001; // Byte alignment is intentionally valid.
        let input = f
            .registry
            .words256_call(f.caller(), decode(&frame).unwrap(), 100)
            .unwrap();
        let Words256Permit::Input(input) = input else {
            panic!("direction");
        };
        let mut bytes = [0; 512];
        let mut words = 0u16;
        input.transfer(&mut bytes, |port| {
            assert_eq!(port, 0x1e8);
            let v = words ^ 0xa55a;
            words += 1;
            v
        });
        assert_eq!(words, 256);
        for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            assert_eq!(u16::from_le_bytes(*pair), i as u16 ^ 0xa55a);
        }
        frame.registers[14] = syscall::PORT_OUTPUT_WORDS256;
        let output = f
            .registry
            .words256_call(f.caller(), decode(&frame).unwrap(), 100)
            .unwrap();
        let Words256Permit::Output(output) = output else {
            panic!("direction");
        };
        let mut words = 0u16;
        output.transfer(&bytes, |port, v| {
            assert_eq!(port, 0x1e8);
            assert_eq!(v, words ^ 0xa55a);
            words += 1;
        });
        assert_eq!(words, 256);
    }
    #[cfg(feature = "workspace-authority")]
    #[test]
    fn sector_authority_requires_actual_running_domain_range_direction_and_original_finite_cut() {
        use crate::user_context::Call;
        let mut f = fixture();
        f.run(0);
        let call = |capability, port, deadline| Call::PortInputWords256 {
            capability,
            port,
            deadline,
            buffer: 0,
        };
        for cut in [0, 100, 99, 1125, u64::MAX] {
            assert!(matches!(
                f.registry
                    .words256_call(f.caller(), call(f.caps[0], 0x1e8, cut), 100),
                Err(Error::Deadline)
            ));
        }
        assert!(
            f.registry
                .words256_call(f.caller(), call(f.caps[0], 0x1e8, 1124), 100)
                .is_ok()
        );
        for port in [0x1e9, 0x1ef, 0x3ee, 0x10000, u64::MAX] {
            assert!(
                f.registry
                    .words256_call(f.caller(), call(f.caps[0], port, 110), 100)
                    .is_err()
            );
        }
        f.run(1);
        let output = Call::PortOutputWords256 {
            capability: f.caps[1],
            port: 0x1e8,
            deadline: 110,
            buffer: 0,
        };
        assert!(f.registry.words256_call(f.caller(), output, 100).is_err());
        assert!(
            f.registry
                .words256_call(f.caller(), call(f.caps[1], 0x1e8, 110), 100)
                .is_ok()
        );
        // Handle values are local coordinates. The root owner's same numeric
        // handle resolves only this caller's read derivation, never root WRITE.
        assert_eq!(f.caps[0], f.caps[1]);
        assert!(
            f.registry
                .words256_call(
                    f.caller(),
                    Call::PortOutputWords256 {
                        capability: f.caps[0],
                        port: 0x1e8,
                        deadline: 110,
                        buffer: 0,
                    },
                    100
                )
                .is_err()
        );
        f.a.revoke(f.domains[0], f.caps[0]).unwrap();
        assert!(matches!(
            f.registry
                .words256_call(f.caller(), call(f.caps[1], 0x1e8, 110), 100),
            Err(Error::Authority(capability::Error::Revoked))
        ));
        f.s.exit(0).unwrap();
        assert!(matches!(
            f.registry
                .words256_call(f.caller(), call(f.caps[1], 0x1e8, 110), 100),
            Err(Error::Scheduler(scheduler::Error::CpuIdle))
        ));
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
    fn fixed_word_batch_preflight_denies_all_malformed_or_expired_permits() {
        let mut f = fixture();
        f.run(0);
        let request = Request {
            capability: f.caps[0],
            port: 0x1e8,
            width: 2,
        };
        let p = f
            .registry
            .input_words4(f.caller(), request, 1025, 1)
            .unwrap();
        assert_eq!(p.port(), 0x1e8);
        let p = f
            .registry
            .output_words4(f.caller(), request, u64::MAX, 1025, 1)
            .unwrap();
        assert_eq!((p.port(), p.value()), (0x1e8, u64::MAX));
        for cut in [0, 1, 1026, u64::MAX] {
            assert_eq!(
                f.registry.input_words4(f.caller(), request, cut, 1).err(),
                Some(Error::Deadline)
            );
        }
        for width in [0, 1, 4, 8, u64::MAX] {
            assert_eq!(
                f.registry
                    .input_words4(f.caller(), Request { width, ..request }, 5, 1)
                    .err(),
                Some(Error::Width)
            );
        }
        for port in [0x1e9, 0x3ee, 0x20, 65535, 65536, u64::MAX] {
            assert!(
                f.registry
                    .input_words4(f.caller(), Request { port, ..request }, 5, 1)
                    .is_err()
            );
        }
        let memory =
            f.a.create_root(f.domains[0], Kind::Memory, Rights::READ)
                .unwrap();
        assert_eq!(
            f.registry
                .input_words4(
                    f.caller(),
                    Request {
                        capability: memory,
                        ..request
                    },
                    5,
                    1
                )
                .err(),
            Some(Error::Authority(capability::Error::WrongKind))
        );
        f.run(1);
        let read = Request {
            capability: f.caps[1],
            ..request
        };
        assert!(f.registry.input_words4(f.caller(), read, 5, 1).is_ok());
        assert_eq!(
            f.registry.output_words4(f.caller(), read, 0, 5, 1).err(),
            Some(Error::Authority(capability::Error::Denied))
        );
        f.a.revoke(f.domains[0], f.caps[0]).unwrap();
        assert_eq!(
            f.registry.input_words4(f.caller(), read, 5, 1).err(),
            Some(Error::Authority(capability::Error::Revoked))
        );
    }
    #[test]
    fn cancelled_rpc_does_not_mint_ports_or_prevent_bounded_owner_cleanup() {
        let mut f = fixture();
        f.run(0);
        let endpoint =
            f.a.create_root(
                f.domains[0],
                Kind::Endpoint,
                Rights::SEND
                    | Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::TRANSFER,
            )
            .unwrap();
        let send =
            f.a.derive(f.domains[0], endpoint, f.domains[1], Rights::SEND)
                .unwrap();
        f.rpc
            .bind_endpoint(
                &f.a,
                f.domains[0],
                endpoint,
                f.threads[0],
                rpc::Policy::new(8, 0).unwrap(),
            )
            .unwrap();
        let id = f
            .rpc
            .begin(
                &f.a,
                f.threads[1],
                send,
                crate::time::Deadline::after(0, 5).unwrap(),
                rpc::MessageShape {
                    bytes: 8,
                    capabilities: 0,
                },
                1,
            )
            .unwrap();
        f.rpc.cancel(f.threads[1], id, 6).unwrap();
        let request = Request {
            capability: f.caps[0],
            port: 0x1e8,
            width: 2,
        };
        assert_eq!(
            f.registry.input_words4(f.caller(), request, 5, 6).err(),
            Some(Error::Deadline)
        );
        assert!(
            f.registry
                .input_words4(f.caller(), request, 1030, 6)
                .is_ok()
        );
        f.s.exit(0).unwrap();
        assert_eq!(
            f.registry.input_words4(f.caller(), request, 1030, 6).err(),
            Some(Error::Scheduler(scheduler::Error::CpuIdle))
        );
    }
    #[test]
    fn fixed_batch_preserves_immutable_word_range_direction() {
        let mut f = fixture();
        f.run(0);
        let cap =
            f.a.create_root(
                f.domains[0],
                Kind::IoPorts,
                Rights::CONTROL | Rights::READ | Rights::WRITE,
            )
            .unwrap();
        f.registry
            .register(
                &f.a,
                f.domains[0],
                cap,
                &[Range {
                    first: 0x600,
                    last: 0x601,
                    widths: Widths::WORD,
                    direction: Direction::Input,
                }],
            )
            .unwrap();
        let request = Request {
            capability: cap,
            port: 0x600,
            width: 2,
        };
        assert!(f.registry.input_words4(f.caller(), request, 5, 1).is_ok());
        assert_eq!(
            f.registry
                .output_words4(f.caller(), request, u64::MAX, 5, 1)
                .err(),
            Some(Error::Direction)
        );
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
    fn v4_calendar_data_is_readonly_even_with_root_readwrite_rights() {
        use ev_userspace_contract::root_v4 as v4;
        let mut f = fixture();
        let c = f.domains[0];
        let cap =
            f.a.create_root(
                c,
                Kind::IoPorts,
                Rights::CONTROL | Rights::READ | Rights::WRITE,
            )
            .unwrap();
        f.registry
            .register(
                &f.a,
                c,
                cap,
                &[
                    Range {
                        first: v4::RTC_INDEX_PORT,
                        last: v4::RTC_INDEX_PORT,
                        widths: Widths::BYTE,
                        direction: Direction::Output,
                    },
                    Range {
                        first: v4::RTC_DATA_PORT,
                        last: v4::RTC_DATA_PORT,
                        widths: Widths::BYTE,
                        direction: Direction::Input,
                    },
                ],
            )
            .unwrap();
        f.run(0);
        let index = Request {
            capability: cap,
            port: u64::from(v4::RTC_INDEX_PORT),
            width: 1,
        };
        let data = Request {
            port: u64::from(v4::RTC_DATA_PORT),
            ..index
        };
        assert!(
            f.registry
                .output(f.caller(), index, u64::from(v4::RTC_CENTURY))
                .is_ok()
        );
        assert!(f.registry.input(f.caller(), data).is_ok());
        assert_eq!(
            f.registry.input(f.caller(), index).err(),
            Some(Error::Direction)
        );
        assert_eq!(
            f.registry.output(f.caller(), data, 0).err(),
            Some(Error::Direction)
        );
        for port in [0x6f, 0x72, 0x300] {
            assert_eq!(
                f.registry.input(f.caller(), Request { port, ..data }).err(),
                Some(Error::Range)
            );
        }
        for width in [2, 4] {
            assert_eq!(
                f.registry
                    .input(f.caller(), Request { width, ..data })
                    .err(),
                Some(Error::Range)
            );
        }
        f.run(1);
        // Actual other scheduler/domain cannot use a numeric Root-local handle.
        assert!(f.registry.input(f.caller(), data).is_err());
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
        assert_eq!(
            f.registry
                .input_words4(
                    f.caller(),
                    Request {
                        capability: f.caps[0],
                        port: 0x1e8,
                        width: 2
                    },
                    5,
                    1
                )
                .err(),
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
