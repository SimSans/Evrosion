//! Authorized storage-service backend adapter, never an application
//! File/Object API. No timeout/cancellation-safe shared-memory claim is made.
#![forbid(unsafe_code)]
use ev_store::{Sector, SectorIo};
use ev_userspace_contract::block::{DecodeError, Request, Response};
use ev_userspace_runtime::{SyncEndpoint, SyncError};

pub const STORE_START: u32 = ev_userspace_contract::store_test::STORE_BASE;
pub const STORE_SECTORS: u32 = ev_userspace_contract::store_test::STORE_BLOCKS;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Legacy,
    Desktop(ev_store::desktop::Region),
    Native(ev_store::native::Region),
}
impl Profile {
    fn sector(self, local: u64) -> Option<u32> {
        if local >= u64::from(STORE_SECTORS) {
            return None;
        }
        match self {
            Self::Legacy => Some(STORE_START + local as u32),
            Self::Desktop(region) => region.wire_sector(local),
            Self::Native(region) => region.wire_sector(local),
        }
    }
}
/// A raw eight-byte transport. Implementations do not infer buffer ownership
/// from CallId metadata. The concrete kernel fixture prevents admitted timeout
/// before its finite controller stop and blocks the sole client until reply.
pub trait Wire {
    type Error;
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error>;
    /// Opt-in metadata for a transport that independently enforces a fresh,
    /// finite operation deadline. This is not capability or timeout ownership.
    fn supports_session(&self) -> bool {
        false
    }
    /// Check the captured horizon before publishing a shared-window request.
    fn session_deadline_valid(&self, _deadline: u64) -> bool {
        false
    }
    /// Capture the child request cut before a shared window is published. The
    /// default preserves the tight adapter's existing exact-deadline contract.
    fn capture_session_deadline(&self, deadline: u64) -> Option<u64> {
        self.session_deadline_valid(deadline).then_some(deadline)
    }
}
#[cfg(all(test, feature = "test-store-client"))]
#[path = "store_io/session_tests.rs"]
mod session_tests;
/// This uses the existing scalar endpoint, without importing Echo's wire codec
/// or presenting Echo's generated trait as this interface's type contract.
pub struct Endpoint(pub SyncEndpoint);
impl Wire for Endpoint {
    type Error = SyncError;
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error> {
        let reply = ev_userspace_runtime::call(
            ev_userspace_runtime::syscall::RPC_CALL,
            self.0.endpoint,
            u64::from_le_bytes(bytes),
            deadline,
        );
        if reply.status != 0 {
            return Err(SyncError::Status(reply.status));
        }
        if reply.capability != 0 {
            return Err(SyncError::UnexpectedCapability(reply.capability));
        }
        Ok(reply.value.to_le_bytes())
    }
}
/// Desktop-only retry of a canonical PRE-ACCEPT Busy response. It never retries
/// timeout/death/ambiguous errors. The runtime must reject Busy before escrow,
/// buffer access or CallId acceptance, and retain both real window owners.
pub struct DesktopEndpoint {
    endpoint: SyncEndpoint,
    stop: u64,
    last: core::cell::Cell<u64>,
    aggregate_span: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum DesktopTransportError {
    Sync(SyncError),
    Clock,
    Deadline,
    BusyBudget,
    Abi,
}
impl DesktopEndpoint {
    pub fn new(endpoint: u64, stop: u64) -> Option<Self> {
        stop.checked_add(1024)
            .filter(|_| stop != 0 && endpoint != 0)?;
        Some(Self {
            endpoint: SyncEndpoint { endpoint },
            stop,
            last: core::cell::Cell::new(0),
            aggregate_span: 1024,
        })
    }
    /// The sustained profile still checks each absolute operation deadline
    /// before its first IPC acceptance and never extends it during retries.
    pub fn for_session(endpoint: u64) -> Option<Self> {
        (endpoint != 0).then_some(Self {
            endpoint: SyncEndpoint { endpoint },
            stop: 0,
            last: core::cell::Cell::new(0),
            aggregate_span: 1024,
        })
    }
    /// Explicit bounded multi-sector transaction profile. The aggregate cut is
    /// never renewed; each independently issued child captures at most1024 ticks.
    pub fn for_session_transactions(endpoint: u64) -> Option<Self> {
        let mut endpoint = Self::for_session(endpoint)?;
        endpoint.aggregate_span = 8192;
        Some(endpoint)
    }
}
trait DesktopRuntime {
    fn clock(&mut self) -> ev_userspace_runtime::Reply;
    fn call(&mut self, endpoint: u64, bytes: [u8; 8], deadline: u64)
    -> ev_userspace_runtime::Reply;
    fn yield_now(&mut self) -> ev_userspace_runtime::Reply;
}
fn capture_desktop_deadline(
    runtime: &mut impl DesktopRuntime,
    deadline: u64,
    aggregate_span: u64,
    last: &mut u64,
) -> Option<u64> {
    let clock = runtime.clock();
    if clock.status != 0 || clock.capability != 0 || clock.value < *last {
        return None;
    }
    *last = clock.value;
    if !ev_userspace_runtime::execution::accepts_deadline(0, clock.value, deadline, aggregate_span)
    {
        return None;
    }
    Some(
        deadline.min(
            clock
                .value
                .checked_add(1024)
                .filter(|cut| *cut != u64::MAX)?,
        ),
    )
}
struct ActualRuntime;
impl DesktopRuntime for ActualRuntime {
    fn clock(&mut self) -> ev_userspace_runtime::Reply {
        ev_userspace_runtime::monotonic()
    }
    fn call(
        &mut self,
        endpoint: u64,
        bytes: [u8; 8],
        deadline: u64,
    ) -> ev_userspace_runtime::Reply {
        ev_userspace_runtime::call(
            ev_userspace_runtime::syscall::RPC_CALL,
            endpoint,
            u64::from_le_bytes(bytes),
            deadline,
        )
    }
    fn yield_now(&mut self) -> ev_userspace_runtime::Reply {
        ev_userspace_runtime::yield_now()
    }
}
fn desktop_exchange<R: DesktopRuntime>(
    runtime: &mut R,
    endpoint: u64,
    bytes: [u8; 8],
    deadline: u64,
    stop: u64,
    last: &mut u64,
) -> Result<[u8; 8], DesktopTransportError> {
    if stop != 0 && (deadline <= stop || deadline > stop + 1024) {
        return Err(DesktopTransportError::Deadline);
    }
    for _ in 0..4096 {
        let clock = runtime.clock();
        if clock.status != 0 || clock.capability != 0 || clock.value < *last {
            return Err(DesktopTransportError::Clock);
        }
        *last = clock.value;
        if !ev_userspace_runtime::execution::accepts_deadline(stop, *last, deadline, 1024) {
            return Err(DesktopTransportError::Deadline);
        }
        let reply = runtime.call(endpoint, bytes, deadline);
        if reply.status == 2 {
            if reply.value != 0 || reply.capability != 0 {
                return Err(DesktopTransportError::Abi);
            }
            let yielded = runtime.yield_now();
            if yielded.status != 0 || yielded.value != 0 || yielded.capability != 0 {
                return Err(DesktopTransportError::Abi);
            }
            continue;
        }
        if reply.status != 0 {
            return Err(DesktopTransportError::Sync(SyncError::Status(reply.status)));
        }
        if reply.capability != 0 {
            return Err(DesktopTransportError::Sync(
                SyncError::UnexpectedCapability(reply.capability),
            ));
        }
        return Ok(reply.value.to_le_bytes());
    }
    Err(DesktopTransportError::BusyBudget)
}
impl Wire for DesktopEndpoint {
    type Error = DesktopTransportError;
    fn supports_session(&self) -> bool {
        self.stop == 0
    }
    fn session_deadline_valid(&self, deadline: u64) -> bool {
        self.capture_session_deadline(deadline).is_some()
    }
    fn capture_session_deadline(&self, deadline: u64) -> Option<u64> {
        let mut last = self.last.get();
        let captured =
            capture_desktop_deadline(&mut ActualRuntime, deadline, self.aggregate_span, &mut last);
        self.last.set(last);
        captured
    }
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error> {
        let mut last = self.last.get();
        let result = desktop_exchange(
            &mut ActualRuntime,
            self.endpoint.endpoint,
            bytes,
            deadline,
            self.stop,
            &mut last,
        );
        self.last.set(last);
        result
    }
}

pub trait Window {
    fn load(&self, out: &mut Sector);
    fn store(&self, bytes: &Sector);
}
/// Userspace policy guard, not authority or hardware-quiescence evidence.
/// Closed inspection refuses writes/flushes BEFORE buffer publication or IPC,
/// including journal replay attempted by Store::open before owner consent.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsentError<E> {
    NoConsent,
    Backend(E),
}
pub struct WriteGate<D> {
    device: D,
    allowed: bool,
}
impl<D> WriteGate<D> {
    pub fn closed(device: D) -> Self {
        Self {
            device,
            allowed: false,
        }
    }
    pub fn allow_writes(&mut self) {
        self.allowed = true;
    }
    pub fn into_inner(self) -> D {
        self.device
    }
}
impl<D: SectorIo> SectorIo for WriteGate<D> {
    type Error = ConsentError<D::Error>;
    fn sectors(&self) -> u64 {
        self.device.sectors()
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        self.device
            .read(lba, out, deadline)
            .map_err(ConsentError::Backend)
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        if !self.allowed {
            return Err(ConsentError::NoConsent);
        }
        self.device
            .write(lba, bytes, deadline)
            .map_err(ConsentError::Backend)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        if !self.allowed {
            return Err(ConsentError::NoConsent);
        }
        self.device.flush(deadline).map_err(ConsentError::Backend)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Bounds,
    Deadline,
    NeedsRecovery,
    Transport(E),
    Decode(DecodeError),
    UnexpectedReply(Response),
    Counter,
    Busy,
}
/// Test observer runs only after the typed response confirms one completed
/// backend write/flush. It creates no authority, durability or readiness claim.
pub trait Mutations {
    fn completed(&mut self, count: u64);
}
pub struct NoCut;
impl Mutations for NoCut {
    fn completed(&mut self, _: u64) {}
}
pub struct StoreRegion<T, W, C = NoCut> {
    transport: T,
    window: W,
    stop: u64,
    poisoned: bool,
    mutations: u64,
    observer: C,
    profile: Profile,
}
impl<T: Wire, W: Window> StoreRegion<T, W, NoCut> {
    /// The stop value constrains requests; it does not authenticate the kernel's
    /// enforcement or create window authority. Only the fixed fixture is ready.
    pub fn new(transport: T, window: W, stop: u64) -> Option<Self> {
        stop.checked_add(1024)
            .filter(|_| stop != 0 || transport.supports_session())?;
        Some(Self {
            transport,
            window,
            stop,
            poisoned: false,
            mutations: 0,
            observer: NoCut,
            profile: Profile::Legacy,
        })
    }
    pub fn for_profile(transport: T, window: W, stop: u64, profile: Profile) -> Option<Self> {
        let mut result = Self::new(transport, window, stop)?;
        result.profile = profile;
        Some(result)
    }
}
impl<T: Wire, W: Window, C: Mutations> StoreRegion<T, W, C> {
    pub fn with_observer(transport: T, window: W, stop: u64, observer: C) -> Option<Self> {
        stop.checked_add(1024)
            .filter(|_| stop != 0 || transport.supports_session())?;
        Some(Self {
            transport,
            window,
            stop,
            poisoned: false,
            mutations: 0,
            observer,
            profile: Profile::Legacy,
        })
    }
    pub fn mutations(&self) -> u64 {
        self.mutations
    }
    pub fn into_parts(self) -> (T, W) {
        (self.transport, self.window)
    }
    fn preflight(&self, lba: u64, deadline: u64) -> Result<(u32, u64), Error<T::Error>> {
        self.preflight_profile(self.profile, lba, deadline)
    }
    fn preflight_profile(
        &self,
        profile: Profile,
        lba: u64,
        deadline: u64,
    ) -> Result<(u32, u64), Error<T::Error>> {
        if self.poisoned {
            return Err(Error::NeedsRecovery);
        }
        let child = if self.stop == 0 {
            self.transport
                .capture_session_deadline(deadline)
                .ok_or(Error::Deadline)?
        } else {
            deadline
        };
        if (self.stop != 0 && (deadline <= self.stop || deadline > self.stop + 1024))
            || deadline == 0
            || deadline == u64::MAX
            || child == 0
            || child == u64::MAX
            || child > deadline
        {
            return Err(Error::Deadline);
        }
        Ok((profile.sector(lba).ok_or(Error::Bounds)?, child))
    }
    fn request(&mut self, request: Request, deadline: u64) -> Result<(), Error<T::Error>> {
        let bytes = self
            .transport
            .call(request.encode(), deadline)
            .map_err(|error| {
                self.poisoned = true;
                Error::Transport(error)
            })?;
        let response = Response::decode(&bytes).map_err(|error| {
            self.poisoned = true;
            Error::Decode(error)
        })?;
        if response != request.success() {
            self.poisoned = true;
            return Err(Error::UnexpectedReply(response));
        }
        if matches!(request, Request::Write { .. } | Request::Flush) {
            self.mutations = self.mutations.checked_add(1).ok_or_else(|| {
                self.poisoned = true;
                Error::Counter
            })?;
            self.observer.completed(self.mutations);
        }
        Ok(())
    }
    fn read_profile(
        &mut self,
        profile: Profile,
        lba: u64,
        out: &mut Sector,
        deadline: u64,
    ) -> Result<(), Error<T::Error>> {
        let (sector, child) = self.preflight_profile(profile, lba, deadline)?;
        self.request(Request::Read { sector }, child)?;
        self.window.load(out);
        Ok(())
    }
    fn write_profile(
        &mut self,
        profile: Profile,
        lba: u64,
        bytes: &Sector,
        deadline: u64,
    ) -> Result<(), Error<T::Error>> {
        let (sector, child) = self.preflight_profile(profile, lba, deadline)?;
        self.window.store(bytes);
        self.request(Request::Write { sector }, child)
    }
}
impl<T: Wire, W: Window, C: Mutations> SectorIo for StoreRegion<T, W, C> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        u64::from(STORE_SECTORS)
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        self.read_profile(self.profile, lba, out, deadline)
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        self.write_profile(self.profile, lba, bytes, deadline)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        let (_, child) = self.preflight(0, deadline)?;
        self.request(Request::Flush, child)
    }
}

/// One actual File RPC/window owner, borrowed by exactly two disjoint, non-Clone
/// region tokens. &mut self keeps another split/owner mutation unavailable while
/// either Store exists. RefCell detects reentrancy instead of aliasing a buffer.
pub struct DesktopFiles<T, W> {
    inner: core::cell::RefCell<StoreRegion<T, W>>,
}
pub struct FileRegion<'a, T, W> {
    inner: &'a core::cell::RefCell<StoreRegion<T, W>>,
    region: ev_store::desktop::Region,
}
impl<T: Wire, W: Window> DesktopFiles<T, W> {
    pub fn new(transport: T, window: W, stop: u64) -> Option<Self> {
        Some(Self {
            inner: core::cell::RefCell::new(StoreRegion::for_profile(
                transport,
                window,
                stop,
                Profile::Desktop(ev_store::desktop::Region::FileA),
            )?),
        })
    }
    pub fn regions(&mut self) -> (FileRegion<'_, T, W>, FileRegion<'_, T, W>) {
        (
            FileRegion {
                inner: &self.inner,
                region: ev_store::desktop::Region::FileA,
            },
            FileRegion {
                inner: &self.inner,
                region: ev_store::desktop::Region::FileB,
            },
        )
    }
    pub fn into_parts(self) -> (T, W) {
        self.inner.into_inner().into_parts()
    }
}
impl<T: Wire, W: Window> SectorIo for FileRegion<'_, T, W> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        u64::from(STORE_SECTORS)
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?
            .read_profile(Profile::Desktop(self.region), lba, out, deadline)
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?
            .write_profile(Profile::Desktop(self.region), lba, bytes, deadline)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        let mut owner = self.inner.try_borrow_mut().map_err(|_| Error::Busy)?;
        let (_, child) = owner.preflight_profile(Profile::Desktop(self.region), 0, deadline)?;
        owner.request(Request::Flush, child)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, rc::Rc, vec, vec::Vec};
    struct State {
        window: Sector,
        disk: Vec<Sector>,
        calls: Vec<(Request, u64)>,
        fail: bool,
        wrong: bool,
        flushes: u64,
    }
    #[derive(Clone)]
    struct Model(Rc<RefCell<State>>);
    impl Window for Model {
        fn load(&self, out: &mut Sector) {
            out.copy_from_slice(&self.0.borrow().window);
        }
        fn store(&self, bytes: &Sector) {
            self.0.borrow_mut().window.copy_from_slice(bytes);
        }
    }
    impl Wire for Model {
        type Error = u64;
        fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], u64> {
            let request = Request::decode(&bytes).unwrap();
            let mut s = self.0.borrow_mut();
            s.calls.push((request, deadline));
            if s.fail {
                return Err(4);
            }
            match request {
                Request::Read { sector } => s.window = s.disk[sector as usize],
                Request::Write { sector } => {
                    let window = s.window;
                    s.disk[sector as usize] = window;
                }
                Request::Flush => s.flushes += 1,
            }
            Ok(if s.wrong {
                Response::Read { sector: 99 }.encode()
            } else {
                request.success().encode()
            })
        }
    }
    fn setup() -> (StoreRegion<Model, Model>, Model) {
        let model = Model(Rc::new(RefCell::new(State {
            window: [0; 512],
            disk: vec![[0; 512]; 30],
            calls: Vec::new(),
            fail: false,
            wrong: false,
            flushes: 0,
        })));
        (
            StoreRegion::new(model.clone(), model.clone(), 100).unwrap(),
            model,
        )
    }
    #[test]
    fn scoped_offset_immediate_readback_and_flush_use_typed_calls() {
        let (mut io, m) = setup();
        let bytes = [0x59; 512];
        let mut out = [0; 512];
        io.write(13, &bytes, 612).unwrap();
        io.flush(612).unwrap();
        io.read(13, &mut out, 612).unwrap();
        assert_eq!(out, bytes);
        let s = m.0.borrow();
        assert_eq!(s.disk[29], bytes);
        assert_eq!(s.flushes, 1);
        assert!(s.disk[..16].iter().all(|b| *b == [0; 512]));
        assert_eq!(
            s.calls,
            vec![
                (Request::Write { sector: 29 }, 612),
                (Request::Flush, 612),
                (Request::Read { sector: 29 }, 612)
            ]
        );
    }
    #[test]
    fn invalid_extent_or_deadline_changes_neither_buffer_nor_transport() {
        let (mut io, m) = setup();
        assert_eq!(io.write(14, &[1; 512], 612), Err(Error::Bounds));
        assert_eq!(io.write(0, &[1; 512], 100), Err(Error::Deadline));
        assert_eq!(io.flush(1125), Err(Error::Deadline));
        assert!(m.0.borrow().calls.is_empty());
        assert_eq!(m.0.borrow().window, [0; 512]);
    }
    #[test]
    fn transport_failure_latches_and_never_replays_or_claims_refund() {
        let (mut io, m) = setup();
        m.0.borrow_mut().fail = true;
        assert_eq!(io.write(0, &[1; 512], 612), Err(Error::Transport(4)));
        m.0.borrow_mut().fail = false;
        assert_eq!(io.flush(612), Err(Error::NeedsRecovery));
        assert_eq!(io.read(0, &mut [0; 512], 612), Err(Error::NeedsRecovery));
        assert_eq!(m.0.borrow().calls.len(), 1);
    }
    #[test]
    fn wrong_generation_or_sector_reply_never_releases_data() {
        let (mut io, m) = setup();
        m.0.borrow_mut().wrong = true;
        let mut out = [7; 512];
        assert_eq!(
            io.read(0, &mut out, 612),
            Err(Error::UnexpectedReply(Response::Read { sector: 99 }))
        );
        assert_eq!(out, [7; 512]);
        assert_eq!(io.flush(612), Err(Error::NeedsRecovery));
    }
    #[test]
    fn observer_follows_only_successful_typed_mutations() {
        struct Spy(Model, Rc<RefCell<Vec<(u64, u64)>>>);
        impl Mutations for Spy {
            fn completed(&mut self, count: u64) {
                self.1.borrow_mut().push((count, self.0.0.borrow().flushes));
            }
        }
        let (_, model) = setup();
        let seen = Rc::new(RefCell::new(Vec::new()));
        let mut io = StoreRegion::with_observer(
            model.clone(),
            model.clone(),
            100,
            Spy(model.clone(), seen.clone()),
        )
        .unwrap();
        io.write(0, &[3; 512], 612).unwrap();
        io.read(0, &mut [0; 512], 612).unwrap();
        io.flush(612).unwrap();
        assert_eq!(*seen.borrow(), vec![(1, 0), (2, 1)]);
        assert_eq!(io.mutations(), 2);
        model.0.borrow_mut().wrong = true;
        assert!(io.write(1, &[4; 512], 612).is_err());
        assert_eq!(*seen.borrow(), vec![(1, 0), (2, 1)]);
        assert_eq!(io.mutations(), 2);
    }
    #[test]
    fn closed_consent_gate_rejects_store_writes_before_buffer_or_rpc_side_effects() {
        let (io, model) = setup();
        let mut gate = WriteGate::closed(io);
        assert_eq!(gate.write(0, &[8; 512], 612), Err(ConsentError::NoConsent));
        assert_eq!(gate.flush(612), Err(ConsentError::NoConsent));
        assert!(model.0.borrow().calls.is_empty());
        assert_eq!(model.0.borrow().window, [0; 512]);
        let initial = ev_store::GenerationManifest {
            generation: ev_store::GenerationId::new(1).unwrap(),
            cohort: [1; 32],
            supervisor_image: [2; 32],
            abi: [3; 32],
            health_contract: [4; 32],
            health_version: 1,
            required_checks: 3,
        };
        let rejected = ev_store::Store::format_new(
            gate,
            initial,
            b"owner",
            ev_store::BootPolicy::new(3).unwrap(),
            612,
        )
        .err()
        .unwrap();
        assert_eq!(rejected.error, ev_store::Error::Io(ConsentError::NoConsent));
        assert!(
            model
                .0
                .borrow()
                .calls
                .iter()
                .all(|(request, _)| matches!(request, Request::Read { .. }))
        );
        assert!(
            model
                .0
                .borrow()
                .disk
                .iter()
                .all(|sector| *sector == [0; 512])
        );
        let mut gate = rejected.device;
        gate.allow_writes();
        gate.write(0, &[8; 512], 612).unwrap();
        assert_eq!(model.0.borrow().disk[16], [8; 512]);
    }
    #[test]
    fn desktop_file_regions_share_one_window_but_cannot_cross_their_fixed_bounds() {
        let (_, model) = setup();
        model.0.borrow_mut().disk.resize(64, [0; 512]);
        let mut owner = DesktopFiles::new(model.clone(), model.clone(), 100).unwrap();
        let (mut a, mut b) = owner.regions();
        a.write(0, &[0xa1; 512], 612).unwrap();
        b.write(13, &[0xb2; 512], 612).unwrap();
        let mut bytes = [0; 512];
        a.read(0, &mut bytes, 612).unwrap();
        assert_eq!(bytes, [0xa1; 512]);
        b.read(13, &mut bytes, 612).unwrap();
        assert_eq!(bytes, [0xb2; 512]);
        // This model's wire records logical sectors. The actual Block Routes
        // tests separately verify their physical32..45/48..61 translation.
        let state = model.0.borrow();
        assert_eq!(state.disk[0], [0xa1; 512]);
        assert_eq!(state.disk[29], [0xb2; 512]);
        drop(state);
        let calls = model.0.borrow().calls.len();
        let window = model.0.borrow().window;
        for local in [14, u64::MAX] {
            assert_eq!(a.write(local, &[9; 512], 612), Err(Error::Bounds));
            assert_eq!(b.read(local, &mut bytes, 612), Err(Error::Bounds));
        }
        assert_eq!(model.0.borrow().calls.len(), calls);
        assert_eq!(model.0.borrow().window, window);
        let cell = a.inner;
        let held = cell.borrow_mut();
        assert_eq!(b.write(0, &[8; 512], 612), Err(Error::Busy));
        assert_eq!(model.0.borrow().calls.len(), calls);
        drop(held);
        model.0.borrow_mut().fail = true;
        assert_eq!(a.write(1, &[7; 512], 612), Err(Error::Transport(4)));
        let calls = model.0.borrow().calls.len();
        let window = model.0.borrow().window;
        assert_eq!(b.write(1, &[6; 512], 612), Err(Error::NeedsRecovery));
        assert_eq!(model.0.borrow().calls.len(), calls);
        assert_eq!(model.0.borrow().window, window);
    }
    #[test]
    fn desktop_system_profile_uses_logical_zero_while_legacy_still_uses_physical16() {
        let (_, model) = setup();
        let mut io = StoreRegion::for_profile(
            model.clone(),
            model.clone(),
            100,
            Profile::Desktop(ev_store::desktop::Region::System),
        )
        .unwrap();
        io.read(0, &mut [0; 512], 612).unwrap();
        assert_eq!(model.0.borrow().calls[0].0, Request::Read { sector: 0 });
        assert_eq!(io.read(14, &mut [0; 512], 612), Err(Error::Bounds));
        let (mut legacy, old) = setup();
        legacy.read(0, &mut [0; 512], 612).unwrap();
        assert_eq!(old.0.borrow().calls[0].0, Request::Read { sector: 16 });
    }
    struct BusyModel {
        reply: ev_userspace_runtime::Reply,
        busy: usize,
        calls: Vec<(u64, [u8; 8], u64)>,
        ticks: u64,
        stall: bool,
    }
    impl DesktopRuntime for BusyModel {
        fn clock(&mut self) -> ev_userspace_runtime::Reply {
            ev_userspace_runtime::Reply {
                status: 0,
                value: self.ticks,
                capability: 0,
            }
        }
        fn call(
            &mut self,
            endpoint: u64,
            bytes: [u8; 8],
            deadline: u64,
        ) -> ev_userspace_runtime::Reply {
            self.calls.push((endpoint, bytes, deadline));
            if self.busy > 0 {
                self.busy -= 1;
                ev_userspace_runtime::Reply {
                    status: 2,
                    value: 0,
                    capability: 0,
                }
            } else {
                self.reply
            }
        }
        fn yield_now(&mut self) -> ev_userspace_runtime::Reply {
            if !self.stall {
                self.ticks += 1;
            }
            ev_userspace_runtime::Reply {
                status: 0,
                value: 0,
                capability: 0,
            }
        }
    }
    #[test]
    fn sustained_transport_bounds_each_operation_and_keeps_its_first_deadline() {
        let request = Request::Read { sector: 0 }.encode();
        let success = ev_userspace_runtime::Reply {
            status: 0,
            value: u64::from_le_bytes(Request::Read { sector: 0 }.success().encode()),
            capability: 0,
        };
        let model = || BusyModel {
            reply: success,
            busy: 0,
            calls: Vec::new(),
            ticks: 5000,
            stall: false,
        };
        // Ordinary finite constructors do not silently opt in to a session.
        assert!(DesktopEndpoint::new(256, 0).is_none());
        assert!(DesktopEndpoint::for_session(0).is_none());
        for deadline in [0, 5000, 6025, u64::MAX] {
            let mut runtime = model();
            assert_eq!(
                desktop_exchange(&mut runtime, 256, request, deadline, 0, &mut 0),
                Err(DesktopTransportError::Deadline)
            );
            assert!(runtime.calls.is_empty());
        }
        let mut runtime = BusyModel {
            busy: 10,
            ..model()
        };
        assert_eq!(
            desktop_exchange(&mut runtime, 256, request, 5003, 0, &mut 0),
            Err(DesktopTransportError::Deadline)
        );
        assert_eq!(runtime.calls.len(), 3);
        assert!(runtime.calls.iter().all(|call| call.2 == 5003));
        let mut runtime = model();
        assert!(desktop_exchange(&mut runtime, 256, request, 5512, 0, &mut 0).is_ok());
        assert_eq!(runtime.calls.len(), 1);
        let mut runtime = model();
        assert_eq!(
            desktop_exchange(&mut runtime, 256, request, 5512, 0, &mut 5001),
            Err(DesktopTransportError::Clock)
        );
        assert!(runtime.calls.is_empty());
    }
    #[test]
    fn desktop_busy_retry_preserves_absolute_deadline_and_never_retries_accepted_failure() {
        let request = Request::Write { sector: 0 }.encode();
        let success = ev_userspace_runtime::Reply {
            status: 0,
            value: u64::from_le_bytes(Request::Write { sector: 0 }.success().encode()),
            capability: 0,
        };
        let mut model = BusyModel {
            reply: success,
            busy: 3,
            calls: Vec::new(),
            ticks: 1,
            stall: false,
        };
        let mut last = 0;
        assert_eq!(
            desktop_exchange(&mut model, 256, request, 612, 100, &mut last),
            Ok(success.value.to_le_bytes())
        );
        assert_eq!(model.calls.len(), 4);
        assert!(model.calls.iter().all(|call| *call == (256, request, 612)));
        model.ticks = 0;
        assert_eq!(
            desktop_exchange(&mut model, 256, request, 612, 100, &mut last),
            Err(DesktopTransportError::Clock)
        );
        assert_eq!(model.calls.len(), 4);
        for status in [1, 3, 4, 5, 6] {
            let mut model = BusyModel {
                reply: ev_userspace_runtime::Reply { status, ..success },
                busy: 0,
                calls: Vec::new(),
                ticks: 1,
                stall: false,
            };
            assert!(desktop_exchange(&mut model, 256, request, 612, 100, &mut 0).is_err());
            assert_eq!(model.calls.len(), 1);
        }
        let mut model = BusyModel {
            reply: success,
            busy: 5000,
            calls: Vec::new(),
            ticks: 1,
            stall: true,
        };
        assert_eq!(
            desktop_exchange(&mut model, 256, request, 612, 100, &mut 0),
            Err(DesktopTransportError::BusyBudget)
        );
        assert_eq!(model.calls.len(), 4096);
    }
}

#[cfg(test)]
mod native_region_tests {
    use super::*;
    #[test]
    fn native_grant_policy_is_exact_local_window_and_keeps_desktop_regions_distinct() {
        let p = Profile::Native(ev_store::native::Region::GrantPolicy);
        for local in 0..14 {
            assert_eq!(p.sector(local), Some(48 + local as u32));
        }
        for local in [14, 15, 48, u32::MAX as u64, u64::MAX] {
            assert_eq!(p.sector(local), None);
        }
        assert_eq!(
            Profile::Desktop(ev_store::desktop::Region::System).sector(0),
            Some(0)
        );
    }
}
