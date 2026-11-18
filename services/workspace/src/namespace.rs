//! Directory-scoped metadata authority. Names and object IDs never grant File
//! READ/EDIT, mint endpoints, purge entries or establish a reclaim fence.
use crate::{BindError, Caller, Captured, EndpointId, Hash, finite, hash};
use ev_userspace_contract::workspace as wire;
use ev_workspace_store::{
    ClientRequest, Dataset, Error, Kind, Metadata, Name, ObjectId, OperationId, SectorIo,
};
use sha2::{Digest, Sha256};

pub const MAX_NAMESPACE_ROUTES: usize = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceRights {
    Inspect,
    Manage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceBinding {
    pub endpoint: EndpointId,
    pub caller: Caller,
    pub lease_epoch: u64,
    pub directory: ObjectId,
    pub rights: NamespaceRights,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceKey {
    slot: u8,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// One fixed frame avoids heap allocation and keeps ownership explicit. The
// actual linked stack census includes this bounded by-value result.
#[allow(clippy::large_enum_variant)]
pub enum NamespaceDispatch {
    Complete {
        frame: [u8; 256],
    },
    /// Original accepted frame/global mapping stays retained. No loan return.
    Retained,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespacePending {
    pub request: wire::Request,
    pub frame: [u8; 256],
    pub fingerprint: Hash,
    pub global_operation: Option<u64>,
    /// Observational failure only: upper16 phase, lower16 class. No recovery,
    /// authority, success or frame-return decision may depend on this witness.
    pub failure: u32,
}
#[derive(Clone, Copy)]
struct Record {
    nonce: u64,
    fingerprint: Hash,
    response: wire::Response,
}
#[derive(Clone, Copy)]
struct Route {
    binding: NamespaceBinding,
    key: NamespaceKey,
    backend_epoch: u64,
    active: bool,
    last_nonce: u64,
    last: Option<Record>,
}
#[derive(Clone, Copy)]
struct Pending {
    owner: NamespaceKey,
    info: NamespacePending,
}
pub(crate) struct State {
    routes: [Option<Route>; MAX_NAMESPACE_ROUTES],
    generations: [u64; MAX_NAMESPACE_ROUTES],
    pending: Option<Pending>,
}
impl State {
    pub const fn new() -> Self {
        Self {
            routes: [None; MAX_NAMESPACE_ROUTES],
            generations: [0; MAX_NAMESPACE_ROUTES],
            pending: None,
        }
    }
    pub fn pending(&self) -> Option<NamespacePending> {
        self.pending.map(|p| p.info)
    }
    pub fn bind<D: SectorIo>(
        &mut self,
        store: &Dataset<'_, D>,
        binding: NamespaceBinding,
    ) -> Result<NamespaceKey, BindError> {
        if !finite(binding.lease_epoch) {
            return Err(BindError::Invalid);
        }
        if self.pending.is_some() || store.is_poisoned() || store.needs_mirror_recovery() {
            return Err(BindError::StorageFenced);
        }
        for row in self.routes.iter().flatten() {
            if row.binding.endpoint == binding.endpoint && row.binding.caller == binding.caller {
                if binding.lease_epoch <= row.binding.lease_epoch {
                    return Err(BindError::Stale);
                }
                if row.active {
                    return Err(BindError::AlreadyBound);
                }
            }
        }
        if store
            .metadata(binding.directory)
            .map_err(|_| BindError::Stale)?
            .kind
            != Kind::Directory
            || store
                .is_trashed(binding.directory)
                .map_err(|_| BindError::StorageFenced)?
        {
            return Err(BindError::Invalid);
        }
        let slot = (0..MAX_NAMESPACE_ROUTES)
            .find(|&i| {
                self.generations[i] < u64::MAX - 1 && self.routes[i].is_none_or(|r| !r.active)
            })
            .ok_or(BindError::Capacity)?;
        let backend_epoch = store
            .next_operation()
            .map_err(|_| BindError::StorageFenced)?
            .get();
        self.generations[slot] += 1;
        let key = NamespaceKey {
            slot: slot as u8,
            generation: self.generations[slot],
        };
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
    pub fn revoke(&mut self, key: NamespaceKey) -> Result<(), BindError> {
        let row = self
            .routes
            .get_mut(usize::from(key.slot))
            .and_then(Option::as_mut)
            .filter(|r| r.key == key && r.active)
            .ok_or(BindError::Stale)?;
        row.active = false;
        Ok(())
    }
    pub fn retire_quiescent(&mut self, key: NamespaceKey) -> Result<(), crate::RetireError> {
        if self.pending.is_some() {
            return Err(crate::RetireError::Busy);
        }
        let row = self
            .routes
            .get(usize::from(key.slot))
            .and_then(|r| *r)
            .filter(|r| r.key == key)
            .ok_or(crate::RetireError::Stale)?;
        if row.active {
            return Err(crate::RetireError::Active);
        }
        self.routes[usize::from(key.slot)] = None;
        Ok(())
    }
    fn response<D: SectorIo>(
        store: &Dataset<'_, D>,
        request: wire::Request,
        outcome: wire::Outcome,
    ) -> wire::Response {
        wire::Response {
            request_id: request.request_id,
            operation_id: request.operation_id,
            outcome,
            namespace_revision: store.namespace_revision(),
            dataset: wire::DatasetId(store.dataset_id().bytes()),
            entry: None,
            next_cursor: None,
        }
    }
    fn complete(
        request: wire::Request,
        response: wire::Response,
    ) -> Result<NamespaceDispatch, wire::Error> {
        let frame = response.encode()?;
        wire::client_decode(request, &frame, 0)?;
        Ok(NamespaceDispatch::Complete { frame })
    }
    pub fn refused<D: SectorIo>(
        store: &Dataset<'_, D>,
        request: wire::Request,
        outcome: wire::Outcome,
    ) -> Result<NamespaceDispatch, wire::Error> {
        Self::complete(request, Self::response(store, request, outcome))
    }
    fn scoped<D: SectorIo>(
        store: &Dataset<'_, D>,
        root: ObjectId,
        mut object: ObjectId,
    ) -> Result<bool, Error<D::Error>> {
        // Every parent edge is resident metadata. Exact generation is checked
        // before any object can be considered inside this admitted directory.
        for _ in 0..=ev_workspace_store::MAX_DEPTH {
            let metadata = store.metadata(object)?;
            if object == root {
                return Ok(true);
            }
            if object == ObjectId::ROOT {
                return Ok(false);
            }
            object = metadata.parent;
        }
        Ok(false)
    }
    fn entry<D: SectorIo>(
        store: &Dataset<'_, D>,
        metadata: Metadata,
    ) -> Result<wire::Entry, Error<D::Error>> {
        let id = metadata.id;
        let name = if id == ObjectId::ROOT {
            wire::Name::root()
        } else {
            wire::Name::new(store.name(id)?.as_bytes()).map_err(|_| Error::Corrupt)?
        };
        Ok(wire::Entry {
            object: wire_id(id),
            parent: wire_id(metadata.parent),
            revision: metadata.revision,
            size: metadata.length.try_into().map_err(|_| Error::Corrupt)?,
            kind: match metadata.kind {
                Kind::File => wire::Kind::File,
                Kind::Directory => wire::Kind::Directory,
            },
            state: if store.is_trashed(id)? {
                wire::EntryState::Trashed
            } else {
                wire::EntryState::Live
            },
            name,
        })
    }
    fn scope(route: Route) -> Hash {
        let mut h = Sha256::new();
        h.update(b"ev.workspace.namespace.request.v1");
        h.update(route.binding.caller.bytes());
        for n in [
            route.binding.endpoint.object,
            route.binding.endpoint.generation,
            route.binding.lease_epoch,
            u64::from(route.binding.directory.slot),
            route.binding.directory.generation,
        ] {
            h.update(n.to_le_bytes());
        }
        h.finalize().into()
    }
    fn outcome<E>(error: &Error<E>) -> Option<wire::Outcome> {
        Some(match error {
            Error::Conflict
            | Error::Collision
            | Error::Depth
            | Error::NotTrashed
            | Error::NotEmpty => wire::Outcome::Conflict,
            Error::InvalidObject | Error::StaleObject | Error::StaleOperation => {
                wire::Outcome::Stale
            }
            Error::NoSpace
            | Error::Capacity
            | Error::Exhausted
            | Error::EntryLimit
            | Error::DirectoryLimit => wire::Outcome::NoSpace,
            Error::Hidden | Error::NotDirectory | Error::NotFile | Error::FenceRequired => {
                wire::Outcome::Denied
            }
            Error::Busy => wire::Outcome::Busy,
            Error::Unsupported => wire::Outcome::Unsupported,
            _ => return None,
        })
    }
    fn remember(&mut self, route: Route, fingerprint: Hash, response: wire::Response) {
        let row = self.routes[usize::from(route.key.slot)].as_mut().unwrap();
        row.last_nonce = response.operation_id;
        row.last = Some(Record {
            nonce: response.operation_id,
            fingerprint,
            response,
        });
    }
    pub fn handle<D: SectorIo>(
        &mut self,
        store: &mut Dataset<'_, D>,
        captured: Captured,
        bytes: &[u8],
        capabilities: usize,
    ) -> Result<NamespaceDispatch, wire::Error> {
        if capabilities != 0 {
            return Err(wire::Error::CapabilityCount);
        }
        let request = wire::Request::decode(bytes)?;
        let Some(route) = self.routes.iter().flatten().copied().find(|r| {
            r.active
                && r.binding.endpoint == captured.endpoint
                && r.binding.caller == captured.caller
                && r.binding.lease_epoch == captured.lease_epoch
        }) else {
            return Self::refused(store, request, wire::Outcome::Denied);
        };
        if let Some(pending) = self.pending {
            return if pending.owner == route.key {
                Ok(NamespaceDispatch::Retained)
            } else {
                Self::refused(store, request, wire::Outcome::Busy)
            };
        }
        if !request.deadline.is_live(captured.now) {
            return Self::refused(store, request, wire::Outcome::Cancelled);
        }
        if matches!(request.operation, wire::Operation::QueryOperation) {
            let Some(record) = route.last.filter(|r| r.nonce == request.operation_id) else {
                return Self::refused(store, request, wire::Outcome::Stale);
            };
            let mut response = record.response;
            response.request_id = request.request_id;
            return Self::complete(request, response);
        }
        let mutation = !matches!(
            request.operation,
            wire::Operation::Inspect { .. } | wire::Operation::List { .. }
        );
        if mutation && route.binding.rights != NamespaceRights::Manage {
            return Self::refused(store, request, wire::Outcome::Denied);
        }
        let fingerprint = hash(bytes);
        if mutation && request.operation_id <= route.last_nonce {
            return match route.last.filter(|r| r.nonce == request.operation_id) {
                Some(r) if r.fingerprint == fingerprint => Self::complete(request, r.response),
                Some(_) => Self::refused(store, request, wire::Outcome::Conflict),
                None => Self::refused(store, request, wire::Outcome::Stale),
            };
        }
        // Object and destination are untrusted descriptive selectors constrained
        // to the actual endpoint's fixed directory before durable allocation.
        let (object, destination, expected) = match request.operation {
            wire::Operation::Inspect { object } => (object, None, None),
            wire::Operation::List {
                directory,
                expected_namespace_revision,
                ..
            }
            | wire::Operation::Create {
                directory,
                expected_namespace_revision,
                ..
            } => (directory, None, Some(expected_namespace_revision)),
            wire::Operation::Rename {
                object,
                expected_namespace_revision,
                ..
            }
            | wire::Operation::Trash {
                object,
                expected_namespace_revision,
            } => (object, None, Some(expected_namespace_revision)),
            wire::Operation::Move {
                object,
                destination,
                expected_namespace_revision,
            }
            | wire::Operation::Restore {
                object,
                destination,
                expected_namespace_revision,
                ..
            } => (object, Some(destination), Some(expected_namespace_revision)),
            wire::Operation::QueryOperation => unreachable!(),
        };
        if expected.is_some_and(|n| n != store.namespace_revision()) {
            return Self::refused(store, request, wire::Outcome::Conflict);
        }
        let object = store_id(object);
        let scope = Self::scoped(store, route.binding.directory, object).and_then(|inside| {
            if !inside {
                Ok(false)
            } else if let Some(to) = destination {
                Self::scoped(store, route.binding.directory, store_id(to))
            } else {
                Ok(true)
            }
        });
        match scope {
            Ok(true) => {}
            Ok(false) => return Self::refused(store, request, wire::Outcome::Denied),
            Err(e) => {
                return Self::refused(
                    store,
                    request,
                    Self::outcome(&e).unwrap_or(wire::Outcome::Busy),
                );
            }
        }
        if mutation
            && object == route.binding.directory
            && !matches!(request.operation, wire::Operation::Create { .. })
        {
            return Self::refused(store, request, wire::Outcome::Denied);
        }
        if !mutation {
            let mut response = Self::response(store, request, wire::Outcome::Completed);
            let metadata = match request.operation {
                wire::Operation::Inspect { .. } => store.metadata(object).map(Some),
                wire::Operation::List { cursor, .. } => store.list(object, cursor, true),
                _ => unreachable!(),
            };
            match metadata.and_then(|m| m.map(|m| Self::entry(store, m)).transpose()) {
                Ok(Some(entry)) => {
                    if matches!(request.operation, wire::Operation::List { .. }) {
                        response.next_cursor = Some(entry.object.slot);
                    }
                    response.entry = Some(entry);
                }
                Ok(None) => response.outcome = wire::Outcome::End,
                Err(e) => {
                    return Self::refused(
                        store,
                        request,
                        Self::outcome(&e).unwrap_or(wire::Outcome::Busy),
                    );
                }
            }
            return Self::complete(request, response);
        }
        if store.needs_mirror_recovery() || store.is_poisoned() {
            return Self::refused(store, request, wire::Outcome::Busy);
        }
        let mut scope = [0; 16];
        scope.copy_from_slice(&Self::scope(route)[..16]);
        let global = match store.next_operation() {
            Ok(op) => op.for_request(
                ClientRequest::new(scope, route.backend_epoch, request.operation_id).unwrap(),
            ),
            Err(_) => return Self::refused(store, request, wire::Outcome::Busy),
        };
        self.pending = Some(Pending {
            owner: route.key,
            info: NamespacePending {
                request,
                frame: bytes.try_into().unwrap(),
                fingerprint,
                global_operation: Some(global.get()),
                failure: 0,
            },
        });
        let result = Self::mutate(store, global, request, object);
        let mut response = Self::response(store, request, wire::Outcome::Completed);
        match result {
            Ok(receipt) => match store
                .metadata(receipt.object)
                .and_then(|m| Self::entry(store, m))
            {
                Ok(entry) => response.entry = Some(entry),
                Err(_) => {
                    self.pending.as_mut().unwrap().info.failure = 2 << 16;
                    return Ok(NamespaceDispatch::Retained);
                }
            },
            Err(e) => {
                let code = match &e {
                    Error::Io(_) => 1,
                    Error::NeedsRecovery => 2,
                    Error::InvalidDeadline => 3,
                    Error::Unsupported => 4,
                    Error::Corrupt => 5,
                    Error::OutOfOrder => 6,
                    Error::HashMismatch => 7,
                    Error::StaleOperation => 8,
                    Error::Exhausted => 9,
                    _ => 255,
                };
                self.pending.as_mut().unwrap().info.failure = (1 << 16) | code;
                if !store.is_poisoned() {
                    if let Some(outcome) = Self::outcome(&e) {
                        response.outcome = outcome;
                    } else {
                        return Ok(NamespaceDispatch::Retained);
                    }
                } else {
                    return Ok(NamespaceDispatch::Retained);
                }
            }
        }
        let complete = match Self::complete(request, response) {
            Ok(v) => v,
            Err(_) => {
                self.pending.as_mut().unwrap().info.failure = 3 << 16;
                return Ok(NamespaceDispatch::Retained);
            }
        };
        self.remember(route, fingerprint, response);
        self.pending = None;
        Ok(complete)
    }
    fn mutate<D: SectorIo>(
        store: &mut Dataset<'_, D>,
        global: OperationId,
        request: wire::Request,
        object: ObjectId,
    ) -> Result<ev_workspace_store::Receipt, Error<D::Error>> {
        let cut = request.deadline.tick();
        match request.operation {
            wire::Operation::Create {
                kind,
                name,
                expected_namespace_revision,
                ..
            } => store.create(
                global,
                expected_namespace_revision,
                object,
                Name::new(name.as_str()).unwrap(),
                match kind {
                    wire::Kind::File => Kind::File,
                    wire::Kind::Directory => Kind::Directory,
                },
                cut,
            ),
            wire::Operation::Rename {
                name,
                expected_namespace_revision,
                ..
            } => store.rename(
                global,
                expected_namespace_revision,
                object,
                Name::new(name.as_str()).unwrap(),
                cut,
            ),
            wire::Operation::Move {
                destination,
                expected_namespace_revision,
                ..
            } => {
                let name = Name::new(store.name(object)?).ok_or(Error::Corrupt)?;
                store.move_object(
                    global,
                    expected_namespace_revision,
                    object,
                    store_id(destination),
                    name,
                    cut,
                )
            }
            wire::Operation::Trash {
                expected_namespace_revision,
                ..
            } => store.trash(global, expected_namespace_revision, object, cut),
            wire::Operation::Restore {
                destination,
                name,
                expected_namespace_revision,
                ..
            } => store.restore_at(
                global,
                expected_namespace_revision,
                object,
                store_id(destination),
                Name::new(name.as_str()).unwrap(),
                cut,
            ),
            _ => Err(Error::Unsupported),
        }
    }
}
fn store_id(id: wire::ObjectId) -> ObjectId {
    ObjectId::new(id.slot, id.generation).expect("decoded wire object")
}
fn wire_id(id: ObjectId) -> wire::ObjectId {
    wire::ObjectId {
        slot: id.slot,
        generation: id.generation,
    }
}
