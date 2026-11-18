//! Bounded userspace File@2 gateway over the actual workspace Dataset engine.
//! Native adapters must capture real endpoint/caller/incarnation/lease identities,
//! own shared loans and device/window quiescence, and enforce actual deadlines.
//! This safe core is not a kernel RPC actor or a capability issuer.
#![no_std]
#![forbid(unsafe_code)]

pub mod backend;
pub mod control;
pub mod legacy;
#[cfg(feature = "native-actor")]
pub mod legacy_device;
pub mod namespace;
pub use namespace::{
    NamespaceBinding, NamespaceDispatch, NamespaceKey, NamespacePending, NamespaceRights,
};

use ev_userspace_contract::{
    file_v2 as wire,
    workspace::{Error as CodecError, Outcome},
};
use ev_workspace_store::{
    ClientRequest, CommitVerifier, Dataset, Error as StoreError, Kind, Metadata, ObjectId,
    OperationId, Receipt, ReceiptKind, SectorIo, StageInfo,
};
use sha2::{Digest, Sha256};

pub const MAX_ROUTES: usize = 8;
pub const CHUNK_BYTES: usize = 4096;
pub const VERIFY_CHUNKS_PER_STEP: u16 = 1;
const _: () = assert!(ev_workspace_store::REQUIRED_SECTORS == 152_322);
type Hash = [u8; 32];
fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn finite(n: u64) -> bool {
    n != 0 && n != u64::MAX
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointId {
    object: u64,
    generation: u64,
}
impl EndpointId {
    /// Actual receive identity supplied by the trusted adapter, never a packet.
    pub fn new(object: u64, generation: u64) -> Option<Self> {
        (finite(object) && finite(generation)).then_some(Self { object, generation })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    process: u64,
    incarnation: u64,
}
impl Caller {
    /// Actual authenticated origin supplied by the trusted adapter.
    pub fn new(process: u64, incarnation: u64) -> Option<Self> {
        (finite(process) && incarnation != u64::MAX).then_some(Self {
            process,
            incarnation,
        })
    }
    fn bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&self.process.to_le_bytes());
        bytes[8..].copy_from_slice(&self.incarnation.to_le_bytes());
        bytes
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rights {
    ReadOnly,
    ReadWrite,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub endpoint: EndpointId,
    pub caller: Caller,
    pub lease_epoch: u64,
    pub object: ObjectId,
    pub rights: Rights,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Captured {
    pub endpoint: EndpointId,
    pub caller: Caller,
    pub lease_epoch: u64,
    pub now: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteKey {
    slot: u8,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    Unsupported,
    Invalid,
    Stale,
    AlreadyBound,
    Capacity,
    StorageFenced,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Protocol(CodecError),
    Loan,
    NoCommit,
}

pub enum Loan<'a> {
    None,
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// Definitive pre-I/O refusal or exact completed service result. The native
    /// adapter still owns transport acknowledgement and the actual memory loan.
    Complete { frame: [u8; 256], read_bytes: u32 },
    /// Not a completion/loan-return acknowledgement. The original request,
    /// proposal and actual shared/window ownership must remain retained.
    Accepted { frame: [u8; 256] },
    /// Never turn this into an ordinary completion or silently reuse its frame.
    Retained { frame: [u8; 256] },
}
impl Dispatch {
    pub fn frame(&self) -> &[u8; 256] {
        match self {
            Self::Complete { frame, .. } | Self::Accepted { frame } | Self::Retained { frame } => {
                frame
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    nonce: u64,
    fingerprint: Hash,
    response: wire::Response,
    verification: bool,
}
#[derive(Clone, Copy)]
struct Route {
    binding: Binding,
    key: RouteKey,
    backend_epoch: u64,
    active: bool,
    last_nonce: u64,
    last: Option<Record>,
}
#[derive(Clone, Copy)]
struct Transfer {
    owner: RouteKey,
    token: u64,
    stage: StageInfo,
}
#[derive(Clone, Copy)]
struct Pending {
    request: wire::Request,
    owner: RouteKey,
    object: ObjectId,
    global: Option<OperationId>,
    fingerprint: Hash,
    snapshot_bytes: usize,
    uncertain: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingInfo {
    pub request: wire::Request,
    pub object: ObjectId,
    pub fingerprint: Hash,
    pub snapshot_bytes: usize,
    pub uncertain: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireError {
    Stale,
    Active,
    Busy,
    StorageFenced,
    Uncertain,
}
#[derive(Clone, Copy)]
struct Seal {
    request: control::Request,
    status: control::Status,
}
struct Commit {
    verifier: CommitVerifier,
    publish_ready: bool,
}
/// Private RAM proof over one exact immutable fully-written stage. Each wire
/// Verify supplies a distinct finite request; no accepted request is renewed.
struct PreparedVerification {
    owner: RouteKey,
    token: u64,
    stage: StageInfo,
    verifier: CommitVerifier,
}
impl PreparedVerification {
    fn matches(&self, transfer: Transfer) -> bool {
        self.owner == transfer.owner && self.token == transfer.token && self.stage == transfer.stage
    }
}

/// Caller-owned resident scratch. Never put a complete document on a service stack.
pub struct Scratch {
    chunk: [u8; CHUNK_BYTES],
}
impl Scratch {
    pub const fn empty() -> Self {
        Self {
            chunk: [0; CHUNK_BYTES],
        }
    }
}

pub struct Gateway<'store, 'scratch, D: SectorIo> {
    store: Dataset<'store, D>,
    scratch: &'scratch mut Scratch,
    routes: [Option<Route>; MAX_ROUTES],
    generations: [u64; MAX_ROUTES],
    transfer: Option<Transfer>,
    next_transfer: u64,
    pending: Option<Pending>,
    commit: Option<Commit>,
    prepared: Option<PreparedVerification>,
    namespace: namespace::State,
    retirement_fenced: bool,
    seal: Option<Seal>,
}
impl<'store, 'scratch, D: SectorIo> Gateway<'store, 'scratch, D> {
    pub fn new(store: Dataset<'store, D>, scratch: &'scratch mut Scratch) -> Self {
        Self {
            store,
            scratch,
            routes: [None; MAX_ROUTES],
            generations: [0; MAX_ROUTES],
            transfer: None,
            next_transfer: 1,
            pending: None,
            commit: None,
            prepared: None,
            namespace: namespace::State::new(),
            retirement_fenced: false,
            seal: None,
        }
    }
    /// A terminal captured-Root seal attempt has no unseal/reset path. This
    /// state is descriptive; it proves no Block drain or physical device stop.
    pub const fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }

    /// Called only by the trusted native adapter after authenticating the
    /// actual Root control receiver/origin. Tokens/frames grant no authority.
    /// Capture the immutable request BEFORE checking state; even a refusal or
    /// expiry permanently closes admission. No pending work is acknowledged or
    /// aborted here. Applied follows one actual flush under the original cut.
    pub fn quiesce(
        &mut self,
        request: control::Request,
        now: u64,
        legacy_fenced: bool,
    ) -> control::Status {
        use control::{Command, Status};
        if !matches!(request.command, Command::Quiesce { .. }) || request.encode().is_err() {
            return Status::Malformed;
        }
        if let Some(seal) = self.seal {
            return if seal.request == request {
                seal.status
            } else {
                Status::Stale
            };
        }
        self.seal = Some(Seal {
            request,
            status: Status::Uncertain,
        });
        let status = if !request.deadline.is_live(now) {
            Status::Deadline
        } else if self.retirement_fenced
            || legacy_fenced
            || self.store.is_poisoned()
            || self.store.needs_mirror_recovery()
        {
            Status::Storage
        } else if self.pending.is_some()
            || self.commit.is_some()
            || self.namespace.pending().is_some()
            || self.transfer.is_some()
            || self.prepared.is_some()
        {
            Status::Busy
        } else {
            match self.store.pending_stage() {
                Ok(Some(_)) => Status::Busy,
                Err(_) => Status::Storage,
                Ok(None) => match self.store.sync_quiescent(request.deadline.tick()) {
                    Ok(()) => Status::Applied,
                    Err(_) => Status::Uncertain,
                },
            }
        };
        self.seal.as_mut().unwrap().status = status;
        status
    }

    /// Trusted Root binding API, never reachable from an ordinary File frame.
    pub fn bind(&mut self, binding: Binding) -> Result<RouteKey, BindError> {
        if !finite(binding.lease_epoch) {
            return Err(BindError::Invalid);
        }
        if self.seal.is_some()
            || self.retirement_fenced
            || self.pending.is_some()
            || self.commit.is_some()
            || self.namespace.pending().is_some()
            || self.store.is_poisoned()
            || self.store.needs_mirror_recovery()
        {
            return Err(BindError::StorageFenced);
        }
        for route in self.routes.iter().flatten() {
            if route.binding.endpoint == binding.endpoint && route.binding.caller == binding.caller
            {
                if binding.lease_epoch <= route.binding.lease_epoch {
                    return Err(BindError::Stale);
                }
                if route.active {
                    return Err(BindError::AlreadyBound);
                }
            }
        }
        let metadata = self
            .store
            .metadata(binding.object)
            .map_err(|_| BindError::Stale)?;
        if metadata.kind != Kind::File
            || self
                .store
                .is_trashed(binding.object)
                .map_err(|_| BindError::StorageFenced)?
        {
            return Err(BindError::Invalid);
        }
        let slot = (0..MAX_ROUTES)
            .find(|&i| {
                self.generations[i] < u64::MAX - 1
                    && self.routes[i].is_none_or(|r| {
                        !r.active
                            && self.pending.is_none_or(|p| p.owner != r.key)
                            && self.transfer.is_none_or(|t| t.owner != r.key)
                    })
            })
            .ok_or(BindError::Capacity)?;
        self.generations[slot] += 1;
        let key = RouteKey {
            slot: slot as u8,
            generation: self.generations[slot],
        };
        // Trusted durable monotonic scope, frozen once per binding. A cold
        // Kernel may reuse diagnostic PID/endpoint/lease integers; after any
        // prior mutation its next operation strictly exceeds that old scope.
        let backend_epoch = self
            .store
            .next_operation()
            .map_err(|_| BindError::StorageFenced)?
            .get();
        self.routes[slot] = Some(Route {
            binding,
            key,
            backend_epoch,
            active: true,
            last_nonce: 0,
            last: None,
        });
        Ok(key)
    }
    /// Trusted Root adapter only, after actual control-route authentication.
    /// Compatibility is checked before any route generation or storage access.
    pub fn bind_contract(
        &mut self,
        binding: Binding,
        requirement: control::FileRequirement,
    ) -> Result<RouteKey, BindError> {
        if !requirement.supported_by(wire::SUPPORT) {
            return Err(BindError::Unsupported);
        }
        self.bind(binding)
    }
    /// Retiring an actual grant/endpoint is the adapter's separate obligation.
    /// This never aborts accepted storage work or proves hardware quiescence.
    pub fn revoke(&mut self, key: RouteKey) -> Result<(), BindError> {
        if self.seal.is_some() {
            return Err(BindError::StorageFenced);
        }
        let row = self
            .routes
            .get_mut(usize::from(key.slot))
            .and_then(Option::as_mut)
            .filter(|r| r.key == key && r.active)
            .ok_or(BindError::Stale)?;
        row.active = false;
        Ok(())
    }
    /// Trusted supervisor reconciliation AFTER independent actual endpoint,
    /// client and loan retirement. Never reachable from an ordinary File frame.
    /// Logical revoke alone cannot satisfy that adapter obligation. Pending or
    /// uncertain work is never cleared here; it needs independent recovery.
    pub fn retire_quiescent(&mut self, key: RouteKey, deadline: u64) -> Result<(), RetireError> {
        if self.seal.is_some()
            || self.retirement_fenced
            || self.store.is_poisoned()
            || self.store.needs_mirror_recovery()
        {
            return Err(RetireError::StorageFenced);
        }
        let route = self
            .routes
            .get(usize::from(key.slot))
            .and_then(|r| *r)
            .filter(|r| r.key == key)
            .ok_or(RetireError::Stale)?;
        if route.active {
            return Err(RetireError::Active);
        }
        if self.pending.is_some() || self.commit.is_some() || self.namespace.pending().is_some() {
            return Err(RetireError::Busy);
        }
        let stage = self
            .store
            .pending_stage()
            .map_err(|_| RetireError::StorageFenced)?;
        match (stage, self.transfer) {
            (Some(stage), Some(transfer)) if transfer.owner == key => {
                if stage.id != transfer.stage.id
                    || stage.object != route.binding.object
                    || stage.expected_revision != transfer.stage.expected_revision
                    || stage.length != transfer.stage.length
                    || stage.sha256 != transfer.stage.sha256
                {
                    return Err(RetireError::StorageFenced);
                }
                let operation = self
                    .store
                    .next_operation()
                    .map_err(|_| RetireError::StorageFenced)?;
                let result = self.store.abort(operation, stage.id, deadline);
                match result {
                    Ok(receipt)
                        if receipt.kind == ReceiptKind::Aborted
                            && receipt.operation == operation
                            && receipt.object == stage.object
                            && receipt.stage == stage.id
                            && receipt.object_revision == stage.expected_revision => {}
                    _ => {
                        self.retirement_fenced = true;
                        return Err(RetireError::Uncertain);
                    }
                }
                self.transfer = None;
                self.prepared = None;
            }
            (Some(_), Some(_)) => return Err(RetireError::Busy),
            // A cold orphan or inconsistent stage must never be guessed to
            // belong to this caller or silently discarded by route retirement.
            (Some(_), None) | (None, Some(_)) => return Err(RetireError::StorageFenced),
            (None, None) => (),
        }
        if self.store.sync_quiescent(deadline).is_err() {
            self.retirement_fenced = true;
            return Err(RetireError::Uncertain);
        }
        self.routes[usize::from(key.slot)] = None;
        Ok(())
    }
    pub fn pending(&self) -> Option<PendingInfo> {
        self.pending.map(|p| PendingInfo {
            request: p.request,
            object: p.object,
            fingerprint: p.fingerprint,
            snapshot_bytes: p.snapshot_bytes,
            uncertain: p.uncertain,
        })
    }
    /// Trusted-owner inspection only; never an ordinary request method.
    pub fn pending_snapshot(&self) -> Option<&[u8]> {
        self.pending
            .map(|p| &self.scratch.chunk[..p.snapshot_bytes])
    }
    pub fn backend_receipt(&self) -> Result<Option<Receipt>, StoreError<D::Error>> {
        self.store.last_receipt()
    }
    /// Read-only trusted control-plane metadata, not an ordinary File selector.
    pub fn dataset_id(&self) -> [u8; 16] {
        self.store.dataset_id().bytes()
    }
    pub fn namespace_revision(&self) -> u64 {
        self.store.namespace_revision()
    }
    pub fn owner_metadata(&self, object: ObjectId) -> Result<Metadata, StoreError<D::Error>> {
        self.store.metadata(object)
    }
    pub fn owner_name(&self, object: ObjectId) -> Result<&str, StoreError<D::Error>> {
        self.store.name(object)
    }
    pub fn owner_trashed(&self, object: ObjectId) -> Result<bool, StoreError<D::Error>> {
        self.store.is_trashed(object)
    }
    /// Trusted adapter installs namespace-only rights on an independently
    /// authenticated directory route. This never mints File access.
    pub fn bind_namespace(&mut self, binding: NamespaceBinding) -> Result<NamespaceKey, BindError> {
        if self.seal.is_some() || self.retirement_fenced || self.pending.is_some() {
            return Err(BindError::StorageFenced);
        }
        self.namespace.bind(&self.store, binding)
    }
    pub fn revoke_namespace(&mut self, key: NamespaceKey) -> Result<(), BindError> {
        if self.seal.is_some() {
            return Err(BindError::StorageFenced);
        }
        self.namespace.revoke(key)
    }
    /// Metadata-route retirement only, after the trusted adapter separately
    /// proves the old actual caller and all its shared-window work stopped.
    pub fn check_namespace_quiescent(&self) -> Result<(), RetireError> {
        if self.seal.is_some()
            || self.retirement_fenced
            || self.store.is_poisoned()
            || self.store.needs_mirror_recovery()
        {
            return Err(RetireError::StorageFenced);
        }
        if self.pending.is_some() || self.commit.is_some() || self.namespace.pending().is_some() {
            return Err(RetireError::Busy);
        }
        Ok(())
    }
    pub fn retire_namespace_quiescent(&mut self, key: NamespaceKey) -> Result<(), RetireError> {
        self.check_namespace_quiescent()?;
        self.namespace.retire_quiescent(key)
    }
    pub fn namespace_pending(&self) -> Option<NamespacePending> {
        self.namespace.pending()
    }
    pub fn handle_namespace(
        &mut self,
        captured: Captured,
        frame: &[u8],
        capabilities: usize,
    ) -> Result<NamespaceDispatch, CodecError> {
        if self.seal.is_some() {
            if self.pending.is_some() || self.namespace.pending().is_some() {
                return Ok(NamespaceDispatch::Retained);
            }
            if capabilities != 0 {
                return Err(CodecError::CapabilityCount);
            }
            let request = ev_userspace_contract::workspace::Request::decode(frame)?;
            return namespace::State::refused(&self.store, request, Outcome::Cancelled);
        }
        if self.retirement_fenced {
            return Ok(NamespaceDispatch::Retained);
        }
        if self.pending.is_some() {
            if capabilities != 0 {
                return Err(CodecError::CapabilityCount);
            }
            let request = ev_userspace_contract::workspace::Request::decode(frame)?;
            return namespace::State::refused(&self.store, request, Outcome::Busy);
        }
        self.namespace
            .handle(&mut self.store, captured, frame, capabilities)
    }
    /// Descriptive handoff paired with an independently installed File SEND.
    /// This encodes an existing live binding; it never installs authority.
    pub fn bound_selection(
        &self,
        key: RouteKey,
        request_id: u64,
        target_thread: u64,
    ) -> Result<[u8; 256], BindError> {
        use ev_userspace_contract::workspace::{Name, ObjectId as WireObject};
        use ev_workspace_client::selection::{Access, Selection};
        if self.seal.is_some()
            || !finite(request_id)
            || !finite(target_thread)
            || self.pending.is_some()
        {
            return Err(BindError::Invalid);
        }
        let route = self
            .routes
            .iter()
            .flatten()
            .copied()
            .find(|r| r.key == key && r.active)
            .ok_or(BindError::Stale)?;
        let metadata = self.metadata(route).map_err(|_| BindError::StorageFenced)?;
        let name = self
            .store
            .name(route.binding.object)
            .map_err(|_| BindError::StorageFenced)?;
        Selection {
            request_id,
            receiver_process: route.binding.caller.process,
            receiver_thread: target_thread,
            registered_incarnation: route.binding.caller.incarnation,
            lease_epoch: route.binding.lease_epoch,
            dataset: self.dataset_id(),
            object: WireObject {
                slot: metadata.id.slot,
                generation: metadata.id.generation,
            },
            access: match route.binding.rights {
                Rights::ReadOnly => Access::ReadOnly,
                Rights::ReadWrite => Access::ReadWrite,
            },
            length: metadata.length.try_into().map_err(|_| BindError::Invalid)?,
            revision: metadata.revision,
            digest: metadata.sha256,
            name: Name::new(name.as_bytes()).map_err(|_| BindError::Invalid)?,
        }
        .encode()
        .map_err(|_| BindError::Invalid)
    }
    pub fn bound_selection_v2(
        &self,
        key: RouteKey,
        request_id: u64,
        target_thread: u64,
    ) -> Result<[u8; 256], BindError> {
        use ev_workspace_client::selection::{Selection, SelectionV2};
        let old = self.bound_selection(key, request_id, target_thread)?;
        SelectionV2 {
            selection: Selection::decode(&old).map_err(|_| BindError::Invalid)?,
            file: wire::SUPPORT,
        }
        .encode()
        .map_err(|_| BindError::Invalid)
    }
    /// Consuming the safe core does not establish actual endpoint/device stop.
    /// The trusted adapter must first retire those owners. Unknown execution is
    /// deliberately retained in Self rather than handing out another writer.
    #[allow(clippy::result_large_err)]
    pub fn into_storage(self) -> Result<Dataset<'store, D>, Self> {
        if self.seal.is_some()
            || self.retirement_fenced
            || self.pending.is_some()
            || self.prepared.is_some()
            || self.namespace.pending().is_some()
        {
            Err(self)
        } else {
            Ok(self.store)
        }
    }

    fn route(&self, captured: Captured) -> Option<Route> {
        self.routes.iter().flatten().copied().find(|r| {
            r.active
                && r.binding.endpoint == captured.endpoint
                && r.binding.caller == captured.caller
                && r.binding.lease_epoch == captured.lease_epoch
        })
    }
    fn metadata(&self, route: Route) -> Result<Metadata, Outcome> {
        let metadata = self
            .store
            .metadata(route.binding.object)
            .map_err(|_| Outcome::Stale)?;
        if metadata.kind != Kind::File
            || self
                .store
                .is_trashed(route.binding.object)
                .map_err(|_| Outcome::Corrupt)?
        {
            return Err(Outcome::Denied);
        }
        Ok(metadata)
    }
    fn response(request: wire::Request, outcome: Outcome) -> wire::Response {
        wire::Response {
            request_id: request.request_id,
            operation_id: request.operation_id,
            outcome,
            revision: 0,
            transfer_id: 0,
            offset: 0,
            length: 0,
            file_length: 0,
            digest: [0; 32],
        }
    }
    fn client_scope(route: Route) -> [u8; 16] {
        // Correlation only. Authorization still compares the complete actual
        // endpoint/caller/incarnation/lease tuple, not a hash from the packet.
        let mut digest = Sha256::new();
        digest.update(b"ev.workspace.service.caller-route@1");
        digest.update(route.binding.caller.bytes());
        digest.update(route.binding.endpoint.object.to_le_bytes());
        digest.update(route.binding.endpoint.generation.to_le_bytes());
        digest.update(route.binding.lease_epoch.to_le_bytes());
        let full: Hash = digest.finalize().into();
        full[..16].try_into().unwrap()
    }
    fn complete(
        request: wire::Request,
        response: wire::Response,
        read_bytes: u32,
    ) -> Result<Dispatch, Reject> {
        let frame = response
            .matches(request)
            .and_then(wire::Response::encode)
            .map_err(Reject::Protocol)?;
        Ok(Dispatch::Complete { frame, read_bytes })
    }
    fn refused(request: wire::Request, outcome: Outcome) -> Result<Dispatch, Reject> {
        Self::complete(request, Self::response(request, outcome), 0)
    }
    fn held(request: wire::Request, uncertain: bool) -> Result<Dispatch, Reject> {
        let frame = Self::response(
            request,
            if uncertain {
                Outcome::Uncertain
            } else {
                Outcome::Accepted
            },
        )
        .encode()
        .map_err(Reject::Protocol)?;
        Ok(if uncertain {
            Dispatch::Retained { frame }
        } else {
            Dispatch::Accepted { frame }
        })
    }
    fn remember(
        &mut self,
        route: Route,
        request: wire::Request,
        fingerprint: Hash,
        response: wire::Response,
    ) {
        let row = self.routes[usize::from(route.key.slot)].as_mut().unwrap();
        row.last_nonce = request.operation_id;
        row.last = Some(Record {
            nonce: request.operation_id,
            fingerprint,
            response,
            verification: matches!(request.method, wire::Method::Verify { .. }),
        });
    }
    fn finish(
        &mut self,
        route: Route,
        request: wire::Request,
        fingerprint: Hash,
        response: wire::Response,
        read_bytes: u32,
    ) -> Result<Dispatch, Reject> {
        match Self::complete(request, response, read_bytes) {
            Ok(result) => {
                if request.operation_id != 0 {
                    self.remember(route, request, fingerprint, response);
                }
                self.pending = None;
                self.commit = None;
                Ok(result)
            }
            Err(_) => {
                self.pending.as_mut().unwrap().uncertain = true;
                Self::held(request, true)
            }
        }
    }
    fn preflight_failure(
        &mut self,
        route: Route,
        request: wire::Request,
        fingerprint: Hash,
        snapshot_bytes: usize,
        outcome: Outcome,
    ) -> Result<Dispatch, Reject> {
        if matches!(outcome, Outcome::Uncertain | Outcome::Corrupt) {
            self.pending = Some(Pending {
                request,
                owner: route.key,
                object: route.binding.object,
                global: None,
                fingerprint,
                snapshot_bytes,
                uncertain: true,
            });
            Self::held(request, true)
        } else {
            Self::refused(request, outcome)
        }
    }
    fn transfer(&self, route: Route, token: u64, revision: u64) -> Result<Transfer, Outcome> {
        let transfer = self
            .transfer
            .filter(|t| {
                t.owner == route.key
                    && t.token == token
                    && t.stage.object == route.binding.object
                    && t.stage.expected_revision == revision
            })
            .ok_or(Outcome::Denied)?;
        let stage = self
            .store
            .pending_stage()
            .map_err(|_| Outcome::Uncertain)?
            .ok_or(Outcome::Stale)?;
        if stage.id != transfer.stage.id
            || stage.object != transfer.stage.object
            || stage.expected_revision != transfer.stage.expected_revision
            || stage.length != transfer.stage.length
            || stage.sha256 != transfer.stage.sha256
        {
            return Err(Outcome::Uncertain);
        }
        Ok(Transfer { stage, ..transfer })
    }
    fn validation_error(error: &StoreError<D::Error>) -> Option<Outcome> {
        match error {
            StoreError::Conflict
            | StoreError::OutOfOrder
            | StoreError::InvalidChunk
            | StoreError::InvalidStage
            | StoreError::Incomplete => Some(Outcome::Conflict),
            StoreError::StaleOperation | StoreError::InvalidObject | StoreError::StaleObject => {
                Some(Outcome::Stale)
            }
            StoreError::NoSpace | StoreError::Capacity | StoreError::Exhausted => {
                Some(Outcome::NoSpace)
            }
            StoreError::Busy => Some(Outcome::Busy),
            StoreError::Hidden | StoreError::NotFile | StoreError::NotDirectory => {
                Some(Outcome::Denied)
            }
            StoreError::Unsupported => Some(Outcome::Unsupported),
            _ => None,
        }
    }
    fn failed(
        &mut self,
        route: Route,
        request: wire::Request,
        fingerprint: Hash,
        error: StoreError<D::Error>,
    ) -> Result<Dispatch, Reject> {
        if !self.store.is_poisoned()
            && let Some(outcome) = Self::validation_error(&error)
        {
            let response = Self::response(request, outcome);
            if request.operation_id != 0 {
                self.remember(route, request, fingerprint, response);
            }
            self.pending = None;
            self.commit = None;
            return Self::complete(request, response, 0);
        }
        self.pending.as_mut().unwrap().uncertain = true;
        Self::held(request, true)
    }
    fn query(&self, route: Route, request: wire::Request) -> Result<Dispatch, Reject> {
        if let Some(pending) = self
            .pending
            .filter(|p| p.owner == route.key && p.request.operation_id == request.operation_id)
        {
            return Self::held(request, pending.uncertain);
        }
        let Some(record) = route.last.filter(|r| r.nonce == request.operation_id) else {
            return Self::refused(request, Outcome::Stale);
        };
        let mut response = record.response;
        response.request_id = request.request_id;
        if response.outcome == Outcome::Completed && !record.verification {
            if let Some(transfer) = self.transfer.filter(|t| t.owner == route.key) {
                let stage = self
                    .store
                    .pending_stage()
                    .map_err(|_| Reject::NoCommit)?
                    .filter(|s| s.id == transfer.stage.id)
                    .ok_or(Reject::NoCommit)?;
                response.revision = stage.expected_revision;
                response.transfer_id = transfer.token;
                response.offset = stage.written as u32;
                response.length = 0;
                response.file_length = stage.length as u32;
                response.digest = stage.sha256;
            } else {
                response.offset = 0;
                response.length = 0;
            }
        }
        Self::complete(request, response, 0)
    }

    pub fn handle(
        &mut self,
        captured: Captured,
        bytes: &[u8],
        capabilities: usize,
        mut loan: Loan<'_>,
    ) -> Result<Dispatch, Reject> {
        if capabilities != 0 {
            return Err(Reject::Protocol(CodecError::CapabilityCount));
        }
        let request = wire::Request::decode(bytes).map_err(Reject::Protocol)?;
        let Some(route) = self.route(captured) else {
            return Self::refused(request, Outcome::Denied);
        };
        if self.seal.is_some() {
            if let Some(pending) = self.pending {
                if pending.owner == route.key
                    && pending.request.operation_id == request.operation_id
                {
                    return Self::held(request, true);
                }
                return Self::refused(request, Outcome::Busy);
            }
            return Self::refused(request, Outcome::Cancelled);
        }
        if self.retirement_fenced {
            return Self::held(request, true);
        }
        if self.namespace.pending().is_some() {
            return Self::refused(request, Outcome::Busy);
        }
        if let Some(pending) = self.pending {
            if pending.owner == route.key && pending.request.operation_id == request.operation_id {
                return Self::held(request, pending.uncertain);
            }
            return Self::refused(request, Outcome::Busy);
        }
        if !request.deadline.is_live(captured.now) {
            return Self::refused(request, Outcome::Cancelled);
        }
        if matches!(request.method, wire::Method::QueryOperation) {
            if !matches!(loan, Loan::None) {
                return Err(Reject::Loan);
            }
            return self.query(route, request);
        }
        let metadata = match self.metadata(route) {
            Ok(value) => value,
            Err(outcome) => return Self::refused(request, outcome),
        };
        if !matches!(request.method, wire::Method::Read { .. })
            && route.binding.rights != Rights::ReadWrite
        {
            return Self::refused(request, Outcome::Denied);
        }
        if let wire::Method::Read { offset, length } = request.method {
            if request.expected_revision != metadata.revision {
                return Self::refused(request, Outcome::Conflict);
            }
            let Loan::Read(output) = &mut loan else {
                return Err(Reject::Loan);
            };
            if output.len() < length as usize || output.len() > CHUNK_BYTES {
                return Err(Reject::Loan);
            }
            self.pending = Some(Pending {
                request,
                owner: route.key,
                object: route.binding.object,
                global: None,
                fingerprint: hash(bytes),
                snapshot_bytes: 0,
                uncertain: false,
            });
            let count = match self.store.read(
                route.binding.object,
                request.expected_revision,
                u64::from(offset),
                &mut self.scratch.chunk[..length as usize],
                request.deadline.tick(),
            ) {
                Ok(count) => count,
                Err(error) => return self.failed(route, request, hash(bytes), error),
            };
            let response = wire::Response {
                revision: metadata.revision,
                offset,
                length: count as u32,
                file_length: metadata.length as u32,
                digest: hash(&self.scratch.chunk[..count]),
                ..Self::response(request, Outcome::Completed)
            };
            let result = self.finish(route, request, hash(bytes), response, count as u32)?;
            if matches!(result, Dispatch::Complete { .. }) {
                output[..count].copy_from_slice(&self.scratch.chunk[..count]);
            }
            return Ok(result);
        }
        let snapshot_bytes = if let wire::Method::WriteChunk { length, digest, .. } = request.method
        {
            let Loan::Write(input) = loan else {
                return Err(Reject::Loan);
            };
            if input.len() != length as usize {
                return Err(Reject::Loan);
            }
            self.scratch.chunk[..input.len()].copy_from_slice(input);
            if hash(&self.scratch.chunk[..input.len()]) != digest {
                return Self::refused(request, Outcome::Conflict);
            }
            input.len()
        } else {
            if !matches!(loan, Loan::None) {
                return Err(Reject::Loan);
            }
            0
        };
        let mut digest = Sha256::new();
        digest.update(bytes);
        digest.update(&self.scratch.chunk[..snapshot_bytes]);
        let fingerprint: Hash = digest.finalize().into();
        if request.operation_id <= route.last_nonce {
            if let Some(record) = route.last.filter(|r| r.nonce == request.operation_id) {
                return if record.fingerprint == fingerprint {
                    Self::complete(request, record.response, 0)
                } else {
                    Self::refused(request, Outcome::Conflict)
                };
            }
            return Self::refused(request, Outcome::Stale);
        }
        if request.expected_revision != metadata.revision {
            return Self::refused(request, Outcome::Conflict);
        }
        let transfer = match request.method {
            wire::Method::WriteChunk {
                transfer_id,
                offset,
                length,
                ..
            } => {
                let transfer = match self.transfer(route, transfer_id, request.expected_revision) {
                    Ok(value) => value,
                    Err(outcome) => {
                        return self.preflight_failure(
                            route,
                            request,
                            fingerprint,
                            snapshot_bytes,
                            outcome,
                        );
                    }
                };
                if transfer.stage.written != u64::from(offset)
                    || u64::from(offset) + u64::from(length) > transfer.stage.length
                    || (!offset.is_multiple_of(CHUNK_BYTES as u32))
                    || (length as usize != CHUNK_BYTES
                        && u64::from(offset) + u64::from(length) != transfer.stage.length)
                {
                    return Self::refused(request, Outcome::Conflict);
                }
                Some(transfer)
            }
            wire::Method::Commit {
                transfer_id,
                length,
                digest,
            }
            | wire::Method::Verify {
                transfer_id,
                length,
                digest,
                ..
            } => {
                let transfer = match self.transfer(route, transfer_id, request.expected_revision) {
                    Ok(value) => value,
                    Err(outcome) => {
                        return self.preflight_failure(
                            route,
                            request,
                            fingerprint,
                            snapshot_bytes,
                            outcome,
                        );
                    }
                };
                if transfer.stage.length != u64::from(length)
                    || transfer.stage.sha256 != digest
                    || transfer.stage.written != transfer.stage.length
                {
                    return Self::refused(request, Outcome::Conflict);
                }
                Some(transfer)
            }
            wire::Method::Abort { transfer_id } => Some(
                match self.transfer(route, transfer_id, request.expected_revision) {
                    Ok(value) => value,
                    Err(outcome) => {
                        return self.preflight_failure(
                            route,
                            request,
                            fingerprint,
                            snapshot_bytes,
                            outcome,
                        );
                    }
                },
            ),
            wire::Method::BeginWrite { .. } => {
                if self.transfer.is_some()
                    || self
                        .store
                        .pending_stage()
                        .map_err(|_| Reject::NoCommit)?
                        .is_some()
                {
                    return Self::refused(request, Outcome::Busy);
                }
                None
            }
            _ => return Err(Reject::Protocol(CodecError::Opcode)),
        };
        if self.store.needs_mirror_recovery() {
            return Self::refused(request, Outcome::Busy);
        }
        if let wire::Method::Verify { offset, .. } = request.method {
            return self.verify(route, request, fingerprint, transfer.unwrap(), offset);
        }
        if matches!(request.method, wire::Method::Commit { .. })
            && self.prepared.as_ref().is_some_and(|prepared| {
                !prepared.matches(transfer.unwrap()) || !prepared.verifier.progress().complete
            })
        {
            return Self::refused(request, Outcome::Conflict);
        }
        let global = match self.store.next_operation() {
            Ok(value) => value.for_request(
                ClientRequest::new(
                    Self::client_scope(route),
                    route.backend_epoch,
                    request.operation_id,
                )
                .unwrap(),
            ),
            Err(_) => return Self::refused(request, Outcome::Busy),
        };
        self.pending = Some(Pending {
            request,
            owner: route.key,
            object: route.binding.object,
            global: Some(global),
            fingerprint,
            snapshot_bytes,
            uncertain: false,
        });
        if let wire::Method::Commit { .. } = request.method {
            self.commit = if let Some(prepared) = self.prepared.take() {
                // The exact owner/token/stage and complete progress were
                // checked before accepting this new finite Commit request.
                Some(Commit {
                    verifier: prepared.verifier,
                    publish_ready: true,
                })
            } else {
                // Historical clients retain the original single-request
                // verification/publication behavior and original cut.
                let verifier = match self.store.begin_verification(transfer.unwrap().stage.id) {
                    Ok(value) => value,
                    Err(error) => return self.failed(route, request, fingerprint, error),
                };
                Some(Commit {
                    verifier,
                    publish_ready: false,
                })
            };
            return Self::held(request, false);
        }
        let token = self.next_transfer;
        let result = match request.method {
            wire::Method::BeginWrite { length, digest } => {
                if !finite(token) || token == u64::MAX - 1 {
                    self.pending = None;
                    return Self::refused(request, Outcome::NoSpace);
                }
                self.store.begin_write(
                    global,
                    route.binding.object,
                    request.expected_revision,
                    u64::from(length),
                    digest,
                    request.deadline.tick(),
                )
            }
            wire::Method::WriteChunk { offset, .. } => self.store.write_chunk(
                global,
                transfer.unwrap().stage.id,
                u64::from(offset),
                &self.scratch.chunk[..snapshot_bytes],
                request.deadline.tick(),
            ),
            wire::Method::Abort { .. } => {
                self.store
                    .abort(global, transfer.unwrap().stage.id, request.deadline.tick())
            }
            _ => unreachable!(),
        };
        let receipt = match result {
            Ok(value) => value,
            Err(error) => return self.failed(route, request, fingerprint, error),
        };
        let mut response = Self::response(request, Outcome::Completed);
        response.revision = request.expected_revision;
        let valid = receipt.object == route.binding.object
            && receipt.operation == global
            && receipt.object_revision == request.expected_revision;
        if !valid {
            self.pending.as_mut().unwrap().uncertain = true;
            return Self::held(request, true);
        }
        match request.method {
            wire::Method::BeginWrite { length, digest } => {
                let Some(stage) = self.store.pending_stage().ok().flatten().filter(|s| {
                    s.id == receipt.stage
                        && s.object == route.binding.object
                        && s.expected_revision == request.expected_revision
                        && s.length == u64::from(length)
                        && s.sha256 == digest
                        && s.written == 0
                        && receipt.kind == ReceiptKind::Begun
                }) else {
                    self.pending.as_mut().unwrap().uncertain = true;
                    return Self::held(request, true);
                };
                self.transfer = Some(Transfer {
                    owner: route.key,
                    token,
                    stage,
                });
                self.next_transfer += 1;
                response.transfer_id = token;
                response.file_length = length;
                response.digest = digest;
            }
            wire::Method::WriteChunk {
                transfer_id,
                offset,
                length,
                digest,
            } => {
                if receipt.kind != ReceiptKind::Chunk
                    || receipt.stage != transfer.unwrap().stage.id
                    || receipt.bytes != u64::from(offset) + u64::from(length)
                {
                    self.pending.as_mut().unwrap().uncertain = true;
                    return Self::held(request, true);
                }
                response.transfer_id = transfer_id;
                response.offset = offset;
                response.length = length;
                response.file_length = transfer.unwrap().stage.length as u32;
                response.digest = digest;
            }
            wire::Method::Abort { transfer_id } => {
                if receipt.kind != ReceiptKind::Aborted
                    || receipt.stage != transfer.unwrap().stage.id
                {
                    self.pending.as_mut().unwrap().uncertain = true;
                    return Self::held(request, true);
                }
                self.transfer = None;
                self.prepared = None;
                response.transfer_id = transfer_id;
            }
            _ => unreachable!(),
        }
        self.finish(route, request, fingerprint, response, 0)
    }

    /// One bounded prepublication verification request. The only persistent
    /// effects are the private verifier progress and scoped RAM response cache;
    /// it cannot write/flush, publish data or allocate a durable operation.
    fn verify(
        &mut self,
        route: Route,
        request: wire::Request,
        fingerprint: Hash,
        transfer: Transfer,
        offset: u32,
    ) -> Result<Dispatch, Reject> {
        if let Some(prepared) = self.prepared.as_ref() {
            if !prepared.matches(transfer)
                || prepared.verifier.progress().complete
                || prepared.verifier.progress().verified_bytes != u64::from(offset)
            {
                return Self::refused(request, Outcome::Conflict);
            }
        } else if offset != 0 {
            return Self::refused(request, Outcome::Conflict);
        }
        self.pending = Some(Pending {
            request,
            owner: route.key,
            object: route.binding.object,
            global: None,
            fingerprint,
            snapshot_bytes: 0,
            uncertain: false,
        });
        if self.prepared.is_none() {
            let verifier = match self.store.begin_verification(transfer.stage.id) {
                Ok(value) => value,
                Err(error) => return self.failed(route, request, fingerprint, error),
            };
            self.prepared = Some(PreparedVerification {
                owner: route.key,
                token: transfer.token,
                stage: transfer.stage,
                verifier,
            });
        }
        let progress = match self.store.verify_step(
            &mut self.prepared.as_mut().unwrap().verifier,
            VERIFY_CHUNKS_PER_STEP,
            request.deadline.tick(),
        ) {
            Ok(value) => value,
            Err(error) => return self.failed(route, request, fingerprint, error),
        };
        let expected = (u64::from(offset) + CHUNK_BYTES as u64).min(transfer.stage.length);
        if progress.verified_bytes != expected
            || progress.total_bytes != transfer.stage.length
            || progress.complete != (expected == transfer.stage.length)
        {
            self.pending.as_mut().unwrap().uncertain = true;
            return Self::held(request, true);
        }
        let response = wire::Response {
            revision: request.expected_revision,
            transfer_id: transfer.token,
            offset: expected as u32,
            file_length: transfer.stage.length as u32,
            digest: transfer.stage.sha256,
            ..Self::response(request, Outcome::Completed)
        };
        self.finish(route, request, fingerprint, response, 0)
    }

    /// Trusted continuation tick. It never accepts a renewed deadline or a wire
    /// global-operation selector. One verification step reads one chunk; final
    /// metadata publication is separate and still needs target-time admission.
    pub fn poll_commit(&mut self, now: u64) -> Result<Dispatch, Reject> {
        let pending = self.pending.ok_or(Reject::NoCommit)?;
        if self.seal.is_some() {
            self.pending.as_mut().unwrap().uncertain = true;
            return Self::held(pending.request, true);
        }
        if pending.uncertain {
            return Self::held(pending.request, true);
        }
        if !pending.request.deadline.is_live(now) {
            self.pending.as_mut().unwrap().uncertain = true;
            return Self::held(pending.request, true);
        }
        let route = self.routes[usize::from(pending.owner.slot)]
            .filter(|r| r.key == pending.owner)
            .ok_or(Reject::NoCommit)?;
        let work = self.commit.as_mut().ok_or(Reject::NoCommit)?;
        if !work.publish_ready {
            match self.store.verify_step(
                &mut work.verifier,
                VERIFY_CHUNKS_PER_STEP,
                pending.request.deadline.tick(),
            ) {
                Ok(progress) => {
                    work.publish_ready = progress.complete;
                    return Self::held(pending.request, false);
                }
                Err(error) => {
                    return self.failed(route, pending.request, pending.fingerprint, error);
                }
            }
        }
        let receipt = match self.store.commit_verified(
            pending.global.unwrap(),
            &work.verifier,
            pending.request.deadline.tick(),
        ) {
            Ok(value) => value,
            Err(error) => return self.failed(route, pending.request, pending.fingerprint, error),
        };
        let transfer = self.transfer.ok_or(Reject::NoCommit)?;
        let metadata = match self.store.metadata(pending.object) {
            Ok(value) => value,
            Err(error) => return self.failed(route, pending.request, pending.fingerprint, error),
        };
        if receipt.kind != ReceiptKind::Committed
            || receipt.object != pending.object
            || receipt.operation != pending.global.unwrap()
            || receipt.stage != transfer.stage.id
            || metadata.revision != pending.request.expected_revision + 1
            || metadata.length != transfer.stage.length
            || metadata.sha256 != transfer.stage.sha256
        {
            self.pending.as_mut().unwrap().uncertain = true;
            return Self::held(pending.request, true);
        }
        let response = wire::Response {
            revision: metadata.revision,
            transfer_id: transfer.token,
            file_length: metadata.length as u32,
            digest: metadata.sha256,
            ..Self::response(pending.request, Outcome::Completed)
        };
        let result = self.finish(route, pending.request, pending.fingerprint, response, 0)?;
        if matches!(result, Dispatch::Complete { .. }) {
            self.transfer = None;
        }
        Ok(result)
    }
}

#[cfg(test)]
extern crate std;
#[cfg(all(test, feature = "native-actor"))]
#[path = "native_origin_tests.rs"]
mod native_origin_tests;
#[cfg(test)]
mod tests;
