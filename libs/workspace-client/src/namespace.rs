//! Internal namespace metadata client. The actual held endpoint supplies the
//! directory scope; object IDs/names and DatasetId never grant File contents.
use crate::TransportError;
use ev_userspace_contract::workspace::{
    self as wire, Deadline, Operation, Outcome, Request, Response,
};

pub trait Link {
    fn now(&mut self) -> Result<u64, TransportError>;
    /// Own and retain the exact window through the underlying RPC. Ok requires
    /// exact scalar64 reply/returned credit, not a timeout or remote error.
    fn exchange(
        &mut self,
        request: Request,
        frame: &[u8; 256],
    ) -> Result<[u8; 256], TransportError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Fenced,
    Exhausted,
    Clock,
    Deadline,
    Codec(wire::Error),
    Transport(TransportError),
    Dataset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Uncertain,
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retained {
    pub request: Request,
    pub frame: [u8; 256],
}
pub struct Client<L> {
    link: L,
    next_request: u64,
    next_operation: u64,
    last_clock: Option<u64>,
    dataset: Option<wire::DatasetId>,
    retained: Option<Retained>,
    closed: bool,
}
fn settles(request: Request, response: Response) -> bool {
    !matches!(
        response.outcome,
        Outcome::Accepted | Outcome::Uncertain | Outcome::Corrupt
    ) && !(response.outcome == Outcome::Stale && request.operation_id != 0)
}
impl<L: Link> Client<L> {
    /// Once per actual route/incarnation. There is no safe link extraction or
    /// reset that could discard a retained loan or reuse mutation counters.
    pub fn new(link: L) -> Self {
        Self {
            link,
            next_request: 1,
            next_operation: 1,
            last_clock: None,
            dataset: None,
            retained: None,
            closed: false,
        }
    }
    pub const fn state(&self) -> State {
        if self.closed {
            State::Closed
        } else if self.retained.is_some() {
            State::Uncertain
        } else {
            State::Ready
        }
    }
    pub fn retained(&self) -> Option<Retained> {
        self.retained
    }
    pub const fn dataset(&self) -> Option<wire::DatasetId> {
        self.dataset
    }
    pub fn issue(&mut self, operation: Operation, deadline: Deadline) -> Result<Response, Error> {
        if self.closed || self.retained.is_some() {
            return Err(Error::Fenced);
        }
        if matches!(operation, Operation::QueryOperation) {
            return Err(Error::Codec(wire::Error::Opcode));
        }
        if self.next_request == u64::MAX || self.next_operation == u64::MAX {
            return Err(Error::Exhausted);
        }
        let mutation = !matches!(
            operation,
            Operation::Inspect { .. } | Operation::List { .. }
        );
        let request = Request {
            request_id: self.next_request,
            operation_id: if mutation { self.next_operation } else { 0 },
            deadline,
            operation,
        };
        let frame = request.encode().map_err(Error::Codec)?;
        let now = self.link.now().map_err(Error::Transport)?;
        if now == u64::MAX || self.last_clock.is_some_and(|last| now < last) {
            return Err(Error::Clock);
        }
        self.last_clock = Some(now);
        if !deadline.is_live(now) || deadline.tick() - now > 8192 {
            return Err(Error::Deadline);
        }
        self.next_request += 1;
        if mutation {
            self.next_operation += 1;
        }
        self.retained = Some(Retained { request, frame });
        let raw = self
            .link
            .exchange(request, &frame)
            .map_err(Error::Transport)?;
        let response = wire::client_decode(request, &raw, 0).map_err(Error::Codec)?;
        if self.dataset.is_some_and(|id| id != response.dataset) {
            return Err(Error::Dataset);
        }
        if matches!(response.outcome, Outcome::Completed | Outcome::End) {
            self.dataset = Some(response.dataset);
        }
        if settles(request, response) {
            self.retained = None;
        }
        Ok(response)
    }
}

/// Actual one-thread mapped-window boundary. No safe constructor, clone,
/// extraction, reset, retry or unfence API exists.
#[allow(unsafe_code)]
mod native {
    use super::*;
    use core::marker::PhantomData;
    use ev_userspace_runtime as rt;
    pub struct NativeLink {
        address: usize,
        endpoint: u64,
        last_request: u64,
        retained: Option<Retained>,
        dataset: Option<wire::DatasetId>,
        _one_owner: PhantomData<*mut ()>,
    }
    impl NativeLink {
        /// # Safety
        /// Exactly8192 initialized RW/NX bytes remain mapped and exclusively
        /// owned at address, paired with the actual Namespace SEND. No File2
        /// client, preview, Root Selection publication or other local reference
        /// aliases this window. The admitted one-thread process keeps all
        /// backing/endpoint/mappings live even through quarantine. The actual
        /// server returns credit only after it finishes window access. Construct
        /// once per admitted route/incarnation; never use this to reset counters.
        pub unsafe fn from_admitted_mapping(
            address: usize,
            extent: usize,
            endpoint: u64,
        ) -> Result<Self, TransportError> {
            if address == 0
                || !address.is_multiple_of(4096)
                || extent != 8192
                || matches!(endpoint, 0 | u64::MAX)
                || address
                    .checked_add(extent)
                    .is_none_or(|end| end > 1usize << 47)
            {
                return Err(TransportError::Mapping);
            }
            Ok(Self {
                address,
                endpoint,
                last_request: 0,
                retained: None,
                dataset: None,
                _one_owner: PhantomData,
            })
        }
        fn close(&mut self) -> Result<(), TransportError> {
            if self.retained.is_some() || self.endpoint == 0 {
                return Err(TransportError::Correlation);
            }
            let endpoint = self.endpoint;
            self.endpoint = 0;
            let r = rt::call(rt::syscall::CLOSE, endpoint, 0, 0);
            if r.status != 0 || r.value != 0 || r.capability != 0 {
                return Err(TransportError::Correlation);
            }
            Ok(())
        }
    }
    impl Link for NativeLink {
        fn now(&mut self) -> Result<u64, TransportError> {
            let r = rt::monotonic();
            if r.status != 0 || r.capability != 0 || r.value == u64::MAX {
                Err(TransportError::Clock)
            } else {
                Ok(r.value)
            }
        }
        fn exchange(
            &mut self,
            request: Request,
            frame: &[u8; 256],
        ) -> Result<[u8; 256], TransportError> {
            if self.endpoint == 0
                || self.retained.is_some()
                || request.request_id <= self.last_request
                || Request::decode(frame) != Ok(request)
            {
                return Err(TransportError::Correlation);
            }
            self.last_request = request.request_id;
            self.retained = Some(Retained {
                request,
                frame: *frame,
            });
            for (i, byte) in frame
                .iter()
                .copied()
                .chain(core::iter::repeat_n(0, 3840))
                .enumerate()
            {
                // SAFETY: unique initialized retained first page before any RPC
                // acceptance. Volatile byte writes create no aliased references.
                unsafe { ((self.address + i) as *mut u8).write_volatile(byte) };
            }
            let reply = rt::rpc::call(
                self.endpoint,
                request.request_id.to_le_bytes(),
                request.deadline.tick(),
            )
            .map_err(|_| TransportError::Rpc)?;
            if u64::from_le_bytes(reply) != request.request_id {
                return Err(TransportError::Correlation);
            }
            let raw = core::array::from_fn(|i| {
                // SAFETY: exact scalar reply returns the actual admitted server
                // credit. The mapping remains owned, no new call is accepted.
                unsafe { ((self.address + i) as *const u8).read_volatile() }
            });
            let response =
                wire::client_decode(request, &raw, 0).map_err(|_| TransportError::Correlation)?;
            if self.dataset.is_some_and(|id| id != response.dataset) {
                return Err(TransportError::Correlation);
            }
            if matches!(response.outcome, Outcome::Completed | Outcome::End) {
                self.dataset = Some(response.dataset);
            }
            if settles(request, response) {
                self.retained = None;
            }
            Ok(raw)
        }
    }
    impl Client<NativeLink> {
        /// Closes this local Namespace SEND only when all loans settled. It
        /// neither unmaps backing nor proves remote actor/device retirement.
        pub fn close_quiescent(&mut self) -> Result<(), TransportError> {
            if self.closed || self.retained.is_some() {
                return Err(TransportError::Correlation);
            }
            self.closed = true;
            self.link.close()
        }
    }
}
pub use native::NativeLink;

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    #[derive(Clone, Copy)]
    enum Reply {
        Good,
        Malformed,
        WrongId,
        WrongDataset,
        Uncertain,
        Stale,
        Remote,
    }
    struct Peer<'a> {
        calls: &'a Cell<u64>,
        reply: Reply,
        now: u64,
    }
    impl Link for Peer<'_> {
        fn now(&mut self) -> Result<u64, TransportError> {
            Ok(self.now)
        }
        fn exchange(&mut self, r: Request, _: &[u8; 256]) -> Result<[u8; 256], TransportError> {
            self.calls.set(self.calls.get() + 1);
            if matches!(self.reply, Reply::Remote) {
                return Err(TransportError::Rpc);
            }
            let mut response = Response {
                request_id: r.request_id,
                operation_id: r.operation_id,
                outcome: match self.reply {
                    Reply::Uncertain => Outcome::Uncertain,
                    Reply::Stale => Outcome::Stale,
                    _ => Outcome::Denied,
                },
                namespace_revision: 9,
                dataset: wire::DatasetId([1; 16]),
                entry: None,
                next_cursor: None,
            };
            if matches!(self.reply, Reply::WrongId) {
                response.request_id += 1;
            }
            if matches!(self.reply, Reply::WrongDataset) {
                response.dataset = wire::DatasetId([2; 16]);
            }
            let mut b = response.encode().unwrap();
            if matches!(self.reply, Reply::Malformed) {
                b[255] = 1;
            }
            Ok(b)
        }
    }
    fn operation() -> Operation {
        Operation::Create {
            directory: wire::ObjectId {
                slot: 256,
                generation: 0x1234,
            },
            kind: wire::Kind::File,
            name: wire::Name::new(b"text.txt").unwrap(),
            expected_namespace_revision: 9,
        }
    }
    fn cut() -> Deadline {
        Deadline::new(100).unwrap()
    }
    #[test]
    fn exact_requests_non_authorizing_ids_and_definitive_denials_can_settle() {
        let calls = Cell::new(0);
        let mut client = Client::new(Peer {
            calls: &calls,
            reply: Reply::Good,
            now: 1,
        });
        for _ in 0..2 {
            assert_eq!(
                client.issue(operation(), cut()).unwrap().outcome,
                Outcome::Denied
            );
            assert_eq!(client.state(), State::Ready);
        }
        assert_eq!(calls.get(), 2);
        assert_eq!(client.next_request, 3);
        assert_eq!(client.next_operation, 3);
    }
    #[test]
    fn malformed_wrong_correlation_remote_and_uncertain_never_reuse_or_allocate_new_ids() {
        for reply in [
            Reply::Malformed,
            Reply::WrongId,
            Reply::Remote,
            Reply::Uncertain,
            Reply::Stale,
        ] {
            let calls = Cell::new(0);
            let mut client = Client::new(Peer {
                calls: &calls,
                reply,
                now: 1,
            });
            let _ = client.issue(operation(), cut());
            assert_eq!(client.state(), State::Uncertain);
            let old = client.retained().unwrap();
            assert_eq!(old.request.operation_id, 1);
            assert_eq!(Request::decode(&old.frame), Ok(old.request));
            assert_eq!(client.issue(operation(), cut()), Err(Error::Fenced));
            assert_eq!(client.retained(), Some(old));
            assert_eq!(calls.get(), 1);
            assert_eq!(client.next_operation, 2);
        }
    }
    #[test]
    fn deadline_and_clock_refusal_before_acceptance_have_no_effect_and_dataset_changes_fence() {
        let calls = Cell::new(0);
        let mut client = Client::new(Peer {
            calls: &calls,
            reply: Reply::Good,
            now: 100,
        });
        assert_eq!(client.issue(operation(), cut()), Err(Error::Deadline));
        assert_eq!(calls.get(), 0);
        assert_eq!(client.next_operation, 1);
        client.link.now = 1;
        client.last_clock = Some(2);
        assert_eq!(client.issue(operation(), cut()), Err(Error::Clock));
        assert_eq!(calls.get(), 0);
        client.last_clock = None;
        client.dataset = Some(wire::DatasetId([1; 16]));
        client.link.reply = Reply::WrongDataset;
        assert_eq!(client.issue(operation(), cut()), Err(Error::Dataset));
        assert_eq!(client.state(), State::Uncertain);
        assert_eq!(calls.get(), 1);
    }
}
