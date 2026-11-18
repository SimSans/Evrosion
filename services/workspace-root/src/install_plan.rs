//! M8 dynamic2 image transfer only. This is neither an installer nor a
//! publisher/owner policy receipt. Actual Root must authorize exact source,
//! package identity and capability effects before calling Register; only the
//! Kernel admits FileApp6 and actual native mappings. No old V4 code is changed.
#![forbid(unsafe_code)]
use ev_userspace_contract::root_v5::dynamic::{self as abi, Header, Operation};
use ev_userspace_runtime::CapReply;

/// Implemented by the private actual syscall/window adapter. Host models of
/// this trait are not evidence of mappings, authority, sealing or execution.
pub trait Io {
    fn control(&mut self, op: Operation, operand: u64, extra: u64) -> CapReply;
    fn write_header(&mut self, header: &[u8; abi::HEADER_BYTES]) -> Result<(), IoError>;
    fn write_staging(&mut self, offset: usize, bytes: &[u8]) -> Result<(), IoError>;
    /// Validate this exact permanent Verify-installed slot/length receipt.
    /// An unrelated new-operation failure does not revoke an immutable reader;
    /// missing or uncertain mapping ownership must still refuse this view.
    fn readonly(&self, slot: usize, bytes: usize) -> Result<&[u8], IoError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Shape,
    Deadline,
    Clock,
    Io,
    Reply,
    Package,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Empty,
    Writing,
    Hashing,
    Sealed,
    Registered,
}
struct Slot {
    phase: Phase,
    header: Option<Header>,
    cap: u64,
    cut: u64,
    written: usize,
    remaining: u64,
}
impl Slot {
    const fn empty() -> Self {
        Self {
            phase: Phase::Empty,
            header: None,
            cap: 0,
            cut: 0,
            written: 0,
            remaining: 0,
        }
    }
}
/// Non-Clone local continuation. Uncertain outcomes fence new operations;
/// already registered immutable readers retain their exact permanent lease.
/// Actual Kernel owners persist until stopped-Root physical cleanup.
///
/// ```compile_fail,E0502
/// use ev_workspace_root::install_plan::{Images, Io};
/// use ev_userspace_contract::root_v5::dynamic::Header;
/// fn cannot_mutate_a_borrowed_owner<T: Io>(images: &mut Images<T>, header: Header) {
///     let bytes = images.bytes(0).unwrap();
///     images.begin(header, 2, 100).unwrap();
///     core::hint::black_box(bytes);
/// }
/// ```
pub struct Images<T> {
    io: T,
    base: u64,
    initialized: bool,
    failed: bool,
    last: u64,
    slots: [Slot; 2],
}
impl<T: Io> Images<T> {
    pub fn new(io: T, root_base: u64) -> Result<Self, Error> {
        if root_base == 0
            || !root_base.is_multiple_of(2 * 1024 * 1024)
            || root_base >= (1u64 << 47) - 4 * 1024 * 1024
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            io,
            base: root_base,
            initialized: false,
            failed: false,
            last: 0,
            slots: [Slot::empty(), Slot::empty()],
        })
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    /// Previously retained capability from the actual registered transition.
    /// A later operation failure neither mints nor revokes this handle; actual
    /// Kernel authority is checked when used. Unregistered slots never qualify.
    pub fn registered_capability(&self, slot: usize) -> Option<u64> {
        self.slots
            .get(slot)
            .filter(|s| s.phase == Phase::Registered)
            .map(|s| s.cap)
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        if now < self.last || now == u64::MAX {
            self.failed = true;
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(())
    }
    fn reply(&mut self, op: Operation, operand: u64, extra: u64) -> Result<CapReply, Error> {
        let r = self.io.control(op, operand, extra);
        if r.status != 0 || r.serial != 0 {
            self.failed = true;
            return Err(Error::Reply);
        }
        Ok(r)
    }
    fn scalar(&mut self, op: Operation, operand: u64, extra: u64, value: u64) -> Result<(), Error> {
        let r = self.reply(op, operand, extra)?;
        if r.value != value || r.capability != 0 {
            self.failed = true;
            return Err(Error::Reply);
        }
        Ok(())
    }
    pub fn initialize(&mut self, now: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self.initialized {
            return Err(Error::State);
        }
        self.scalar(Operation::Initialize, 0, 0, abi::VERSION)?;
        self.scalar(
            Operation::Inspect,
            0,
            0,
            self.base + abi::REGION + abi::CONTROL as u64 * 4096,
        )?;
        self.scalar(Operation::Inspect, 0, 1, abi::VERSION)?;
        self.scalar(Operation::Inspect, 0, 2, abi::EXTERNAL_FRAMES)?;
        self.initialized = true;
        Ok(())
    }
    fn active(&mut self, slot: usize, now: u64, phase: Phase) -> Result<(), Error> {
        self.observe(now)?;
        let s = self.slots.get(slot).ok_or(Error::Shape)?;
        if !self.initialized || s.phase != phase {
            return Err(Error::State);
        }
        if now >= s.cut {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    /// Header is an immutable request, not verified package or release policy.
    /// The exact cut is captured once and never renewed by later steps.
    pub fn begin(&mut self, header: Header, now: u64, original_cut: u64) -> Result<usize, Error> {
        self.observe(now)?;
        if header.bytes > ev_userspace_contract::root_v5::resources::PACKAGE_MAX_BYTES {
            return Err(Error::Shape);
        }
        if !self.initialized
            || self
                .slots
                .iter()
                .any(|s| matches!(s.phase, Phase::Writing | Phase::Hashing))
        {
            return Err(Error::State);
        }
        if original_cut <= now || original_cut == u64::MAX {
            return Err(Error::Deadline);
        }
        let bytes = header.encode().ok_or(Error::Shape)?;
        if self.slots.iter().all(|s| s.phase != Phase::Empty) {
            return Err(Error::State);
        }
        if self.io.write_header(&bytes).is_err() {
            self.failed = true;
            return Err(Error::Io);
        }
        let r = self.reply(Operation::Begin, original_cut, 0)?;
        let index = r
            .value
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|i| *i < 2);
        let Some(index) = index else {
            self.failed = true;
            return Err(Error::Reply);
        };
        if self.slots[index].phase != Phase::Empty || matches!(r.capability, 0 | u64::MAX) {
            self.failed = true;
            return Err(Error::Reply);
        }
        self.slots[index] = Slot {
            phase: Phase::Writing,
            header: Some(header),
            cap: r.capability,
            cut: original_cut,
            written: 0,
            remaining: 0,
        };
        Ok(index)
    }
    /// Sequential <=4KiB writes; the actual Kernel independently checks the
    /// same extent/cut. A failed ACK is never retried or treated as unaccepted.
    pub fn write_chunk(&mut self, slot: usize, now: u64, bytes: &[u8]) -> Result<(), Error> {
        self.active(slot, now, Phase::Writing)?;
        let offset = self.slots[slot].written;
        let end = offset.checked_add(bytes.len()).ok_or(Error::Shape)?;
        if bytes.is_empty()
            || bytes.len() > 4096
            || end > self.slots[slot].header.unwrap().bytes as usize
        {
            return Err(Error::Shape);
        }
        if self.io.write_staging(offset, bytes).is_err() {
            self.failed = true;
            return Err(Error::Io);
        }
        self.scalar(
            Operation::Written,
            slot as u64 + 1,
            offset as u64 | ((bytes.len() as u64) << 32),
            end as u64,
        )?;
        self.slots[slot].written = end;
        Ok(())
    }
    pub fn seal(&mut self, slot: usize, now: u64) -> Result<(), Error> {
        self.active(slot, now, Phase::Writing)?;
        let bytes = self.slots[slot].header.unwrap().bytes;
        if self.slots[slot].written as u64 != bytes {
            return Err(Error::State);
        }
        let remaining = bytes.div_ceil(4096) * 4096;
        self.scalar(Operation::Seal, slot as u64 + 1, 0, remaining)?;
        self.slots[slot].remaining = remaining;
        self.slots[slot].phase = Phase::Hashing;
        Ok(())
    }
    pub fn verify_step(&mut self, slot: usize, now: u64) -> Result<bool, Error> {
        self.active(slot, now, Phase::Hashing)?;
        let remaining = self.slots[slot].remaining;
        let expected = remaining.saturating_sub(4096);
        let r = self.reply(Operation::Verify, slot as u64 + 1, 0)?;
        if remaining == 0
            || r.value != expected
            || (expected != 0 && r.capability != 0)
            || (expected == 0
                && (matches!(r.capability, 0 | u64::MAX) || r.capability == self.slots[slot].cap))
        {
            self.failed = true;
            return Err(Error::Reply);
        }
        self.slots[slot].remaining = expected;
        if expected == 0 {
            self.slots[slot].cap = r.capability;
            self.slots[slot].phase = Phase::Sealed;
        }
        Ok(expected == 0)
    }
    /// Explicit cancellation may retire a known unsealed owner after its
    /// transfer cut. Unknown results remain fenced until stopped-Root cleanup.
    /// Permanent readonly slots are never recycled during this Root execution.
    pub fn abort(&mut self, slot: usize, now: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self
            .slots
            .get(slot)
            .is_none_or(|s| !matches!(s.phase, Phase::Writing | Phase::Hashing))
        {
            return Err(Error::State);
        }
        self.scalar(Operation::Abort, slot as u64 + 1, 0, 0)?;
        self.slots[slot] = Slot::empty();
        Ok(())
    }
    /// Short immutable view backed by the permanent actual Kernel RO lease.
    /// No user supplied address, static lifetime or writable alias escapes.
    /// After a failure only previously Registered slots remain eligible. The
    /// actual IO adapter must still validate the permanent slot/length receipt.
    pub fn bytes(&self, slot: usize) -> Result<&[u8], Error> {
        let s = self.slots.get(slot).ok_or(Error::Shape)?;
        if !matches!(s.phase, Phase::Sealed | Phase::Registered)
            || (self.failed && s.phase != Phase::Registered)
        {
            return Err(Error::State);
        }
        let bytes = self
            .io
            .readonly(slot, s.header.unwrap().bytes as usize)
            .map_err(|_| Error::Io)?;
        if bytes.len() != s.header.unwrap().bytes as usize {
            return Err(Error::Shape);
        }
        Ok(bytes)
    }
    pub fn package(&self, slot: usize) -> Result<ev_zion::Package<'_>, Error> {
        use sha2::{Digest, Sha256};
        let h = self
            .slots
            .get(slot)
            .and_then(|s| s.header)
            .ok_or(Error::State)?;
        let bytes = self.bytes(slot)?;
        let mut descriptor = Sha256::new();
        abi::app_descriptor_transcript(&h.elf_sha256, |bytes| descriptor.update(bytes));
        let descriptor: [u8; 32] = descriptor.finalize().into();
        // Do not let a later parse refusal hide a known binding failure.
        if h.package != h.sha256 || descriptor != h.descriptor {
            return Err(Error::Shape);
        }
        let p = ev_zion::Package::parse(bytes).map_err(|_| Error::Package)?;
        if p.id().bytes() != h.package
            || p.executable().digest != h.elf_sha256
            || p.executable().bytes.len() as u64 != h.elf_bytes
            || p.executable().bytes.as_ptr() as usize
                != p.bytes().as_ptr() as usize + h.elf_offset as usize
        {
            return Err(Error::Shape);
        }
        Ok(p)
    }
    /// Caller must first authorize the exact source/App/build/schema and
    /// capability policy: protected owner-development admission or separately
    /// authenticated release provenance. This only binds the sealed container.
    pub fn register(
        &mut self,
        slot: usize,
        now: u64,
        loaded: &crate::requirements::LoadedContracts,
    ) -> Result<u64, Error> {
        self.active(slot, now, Phase::Sealed)?;
        let _checked =
            crate::requirements::file_app(self.bytes(slot)?, loaded).map_err(|_| Error::Package)?;
        self.package(slot)?;
        self.scalar(Operation::Register, slot as u64 + 1, 0, 0)?;
        self.slots[slot].phase = Phase::Registered;
        Ok(self.slots[slot].cap)
    }
    /// Same exact sealed owner, with private-data compatibility supplied only
    /// by the actual loaded Root handler/window context. This does not grant
    /// enrollment, allocate data, or infer publisher/update permission.
    pub fn register_private(
        &mut self,
        slot: usize,
        now: u64,
        loaded: &crate::requirements::PrivateDataContracts<'_>,
    ) -> Result<u64, Error> {
        self.active(slot, now, Phase::Sealed)?;
        crate::requirements::private_file_app(self.bytes(slot)?, loaded)
            .map_err(|_| Error::Package)?;
        self.package(slot)?;
        self.scalar(Operation::Register, slot as u64 + 1, 0, 0)?;
        self.slots[slot].phase = Phase::Registered;
        Ok(self.slots[slot].cap)
    }
}

/// Build a transfer request from the exact immutable requirements-checked
/// package. This authenticates no publisher and performs no ELF admission.
pub fn header(checked: &crate::requirements::Checked<'_>) -> Result<Header, Error> {
    use sha2::{Digest, Sha256};
    let package = checked.package();
    let bytes = package.bytes();
    if bytes.len() as u64 > ev_userspace_contract::root_v5::resources::PACKAGE_MAX_BYTES {
        return Err(Error::Shape);
    }
    let mut descriptor = Sha256::new();
    abi::app_descriptor_transcript(&package.executable().digest, |b| descriptor.update(b));
    let value = Header {
        bytes: bytes.len() as u64,
        elf_offset: (package.executable().bytes.as_ptr() as usize)
            .checked_sub(bytes.as_ptr() as usize)
            .ok_or(Error::Shape)? as u64,
        elf_bytes: package.executable().bytes.len() as u64,
        sha256: package.id().bytes(),
        elf_sha256: package.executable().digest,
        package: package.id().bytes(),
        abi: ev_userspace_contract::ABI,
        descriptor: descriptor.finalize().into(),
    };
    value.encode().ok_or(Error::Shape)?;
    Ok(value)
}

#[cfg(test)]
mod tests;
