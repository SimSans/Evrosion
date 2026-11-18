//! Internal bounded authority tables. Caller supplies a trusted protection-domain
//! identity; raw handles alone never identify their owner. No userspace ABI yet.
//! One mutable owner serializes all mutations. Retained nodes preserve ancestry
//! after handles close. Explicit lifecycle collection can reclaim unreachable
//! lineage and explicitly dead, unreferenced object descriptors. Domain and
//! object identities carry generations so reuse cannot revive retired identities.
//! Managed creation binds distinct objects beneath a live Job creator; ordinary
//! derivation stays within one object and only attenuates existing rights.
use core::{num::NonZeroU16, ops::BitOr};
pub const MAX_SPACES: usize = 40;
pub const MAX_CAPS: usize = 16;
pub const MAX_NODES: usize = 256;
pub const MAX_OBJECTS: usize = 64;
/// Ordinary process domains retain MAX_CAPS. Only the trusted custody/Root
/// factory selects one of these fixed wider domains; no syscall selects class.
pub const MAX_CONTROL_CAPS: usize = 64;
pub const MAX_CONTROL_SPACES: usize = 4;
/// Physical metadata capacity, distinct from the effective legacy envelopes.
/// The default Kernel keeps the exact original arrays; only the selected M8
/// build carries the larger storage. Ordinary domains always remain16 slots.
pub const SPACE_STORAGE_CAPACITY: usize = if cfg!(feature = "workspace-authority") {
    64
} else {
    MAX_SPACES
};
pub const OBJECT_STORAGE_CAPACITY: usize = if cfg!(feature = "workspace-authority") {
    96
} else {
    MAX_OBJECTS
};
const NODE_STORAGE_CAPACITY: usize = if cfg!(feature = "workspace-authority") {
    512
} else {
    MAX_NODES
};
const CONTROL_STORAGE_CAPACITY: usize = if cfg!(feature = "workspace-authority") {
    96
} else {
    MAX_CONTROL_CAPS
};
const EXTRA_CONTROL_CAPS: usize = CONTROL_STORAGE_CAPACITY - MAX_CAPS;
#[cfg(feature = "workspace-authority")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedEnvelope {
    workspace: bool,
    workspace_controls: [bool; MAX_CONTROL_SPACES],
}
const _: () = assert!(
    SPACE_STORAGE_CAPACITY < 256 && OBJECT_STORAGE_CAPACITY < 256 && CONTROL_STORAGE_CAPACITY < 256
);
const MAX_GENERATION: u64 = u64::MAX >> 8;
const MAX_OBJECT_GENERATION: usize = (usize::MAX >> 8) + 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u16);
impl Rights {
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const MAP: Self = Self(4);
    pub const SEND: Self = Self(8);
    pub const RECEIVE: Self = Self(16);
    pub const DERIVE: Self = Self(32);
    pub const TRANSFER: Self = Self(64);
    pub const REVOKE: Self = Self(128);
    pub const CONTROL: Self = Self(256);
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !511 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}
impl BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Memory,
    Endpoint,
    Process,
    Thread,
    Job,
    Mutex,
    IoPorts,
    Display,
}
impl Kind {
    /// Shared validation for manifest descriptions and actual minting.
    pub fn permits(self, rights: Rights) -> bool {
        self.allowed().contains(rights)
    }
    fn allowed(self) -> Rights {
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL;
        common
            | match self {
                Self::Memory | Self::Display => Rights::READ | Rights::WRITE | Rights::MAP,
                Self::Endpoint => Rights::SEND | Rights::RECEIVE,
                Self::Mutex => Rights::from_bits(0).unwrap(),
                Self::IoPorts => Rights::READ | Rights::WRITE,
                _ => Rights::READ,
            }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceId(usize, u64);
/// Public-shaped input only: decoding does not grant authority. A live matching
/// generation in the caller's trusted table is required on every operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSpace,
    InvalidHandle,
    Revoked,
    DeadObject,
    WrongKind,
    Denied,
    Capacity,
    GenerationExhausted,
    DestinationNotEmpty,
    SpaceBusy,
    ObjectBusy,
}
#[derive(Clone, Copy)]
struct Object {
    kind: Kind,
    live: bool,
}
/// Compact private link; public lineage identities remain zero-based usize.
/// Every constructor checks both the declared node bound and integer width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NodeIndex(NonZeroU16);
impl NodeIndex {
    fn checked(index: usize) -> Option<Self> {
        if index >= NODE_STORAGE_CAPACITY {
            return None;
        }
        Some(Self(NonZeroU16::new(
            u16::try_from(index).ok()?.checked_add(1)?,
        )?))
    }
    fn index(self) -> usize {
        usize::from(self.0.get()) - 1
    }
}
fn node_index(index: usize) -> NodeIndex {
    NodeIndex::checked(index).expect("previously bounded node slot")
}
const _: () = assert!(NODE_STORAGE_CAPACITY <= u16::MAX as usize);
#[derive(Clone, Copy)]
struct Node {
    object: usize,
    parent: Option<NodeIndex>,
    rights: Rights,
    live: bool,
}
#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    node: Option<NodeIndex>,
}
const EMPTY: Slot = Slot {
    generation: 0,
    node: None,
};
/// Borrowed authorization. Keeping it live prevents table mutation/revocation.
/// Object identity is diagnostic, not a standalone grant or a durable handle.
pub struct Access<'a> {
    object: &'a Object,
    identity: usize,
    rights: Rights,
    node: usize,
    lineage_root: usize,
}
impl Access<'_> {
    /// Diagnostic boot-local ancestry identity, never authority on its own.
    pub fn lineage_root(&self) -> usize {
        self.lineage_root
    }
    pub fn is_root(&self) -> bool {
        self.node == self.lineage_root
    }
    pub fn kind(&self) -> Kind {
        self.object.kind
    }
    /// Generation-tagged boot-local object identity, never authority by itself.
    /// The low eight bits name the descriptor slot; upper bits encode generation
    /// minus one. First-generation identities remain exactly 0..MAX_OBJECTS.
    /// Cached backends must compare the complete identity, not just its slot.
    pub fn identity(&self) -> usize {
        self.identity
    }
    pub fn rights(&self) -> Rights {
        self.rights
    }
}
#[derive(Clone, Copy)]
pub struct Derivation {
    pub source: Handle,
    pub kind: Kind,
    pub rights: Rights,
}
/// A complete, atomically installed batch. Handles remain destination-local.
pub struct GrantBatch {
    handles: [Handle; CONTROL_STORAGE_CAPACITY],
    count: usize,
}
impl GrantBatch {
    pub fn handles(&self) -> &[Handle] {
        &self.handles[..self.count]
    }
}
/// Private branch handles pin the complete revocation boundary through collection.
/// Both batches are local to their respective trusted domains, not detached node IDs.
pub struct ScopedGrants {
    pub branches: GrantBatch,
    pub grants: GrantBatch,
}
pub struct Authority {
    #[cfg(feature = "workspace-authority")]
    envelope: SelectedEnvelope,
    spaces: [bool; SPACE_STORAGE_CAPACITY],
    closed: [bool; SPACE_STORAGE_CAPACITY],
    space_generations: [u64; SPACE_STORAGE_CAPACITY],
    slots: [[Slot; MAX_CAPS]; SPACE_STORAGE_CAPACITY],
    control_owners: [Option<usize>; MAX_CONTROL_SPACES],
    control_slots: [[Slot; EXTRA_CONTROL_CAPS]; MAX_CONTROL_SPACES],
    nodes: [Option<Node>; NODE_STORAGE_CAPACITY],
    objects: [Option<Object>; OBJECT_STORAGE_CAPACITY],
    object_generations: [usize; OBJECT_STORAGE_CAPACITY],
}
impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}
impl Authority {
    /// Read-only bounded metadata counts, never authority or a quiescence proof.
    /// Live domains, installed handles, retained nodes and object descriptors.
    pub fn metadata_usage(&self) -> (usize, usize, usize, usize) {
        (
            self.spaces
                .iter()
                .zip(self.closed.iter())
                .filter(|(used, closed)| **used && !**closed)
                .count(),
            self.slots
                .iter()
                .flatten()
                .chain(self.control_slots.iter().flatten())
                .filter(|slot| slot.node.is_some())
                .count(),
            self.nodes.iter().flatten().count(),
            self.objects.iter().flatten().count(),
        )
    }
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "workspace-authority")]
            envelope: SelectedEnvelope {
                workspace: false,
                workspace_controls: [false; MAX_CONTROL_SPACES],
            },
            spaces: [false; SPACE_STORAGE_CAPACITY],
            closed: [false; SPACE_STORAGE_CAPACITY],
            space_generations: [0; SPACE_STORAGE_CAPACITY],
            slots: [[EMPTY; MAX_CAPS]; SPACE_STORAGE_CAPACITY],
            control_owners: [None; MAX_CONTROL_SPACES],
            control_slots: [[EMPTY; EXTRA_CONTROL_CAPS]; MAX_CONTROL_SPACES],
            nodes: [None; NODE_STORAGE_CAPACITY],
            objects: [None; OBJECT_STORAGE_CAPACITY],
            object_generations: [0; OBJECT_STORAGE_CAPACITY],
        }
    }
    /// Trusted once-only factory for the independently verified M8 graph.
    /// No syscall or userspace scalar selects this profile. Existing new() and
    /// existing control-space factory keep their legacy effective limits even
    /// in this build; ordinary processes never obtain a wider handle table.
    #[cfg(feature = "workspace-authority")]
    pub const fn for_workspace_profile() -> Self {
        let mut table = Self::new();
        table.envelope.workspace = true;
        table
    }
    fn space_limit(&self) -> usize {
        #[cfg(feature = "workspace-authority")]
        if self.envelope.workspace {
            return SPACE_STORAGE_CAPACITY;
        }
        MAX_SPACES
    }
    fn object_limit(&self) -> usize {
        #[cfg(feature = "workspace-authority")]
        if self.envelope.workspace {
            return OBJECT_STORAGE_CAPACITY;
        }
        MAX_OBJECTS
    }
    fn node_limit(&self) -> usize {
        #[cfg(feature = "workspace-authority")]
        if self.envelope.workspace {
            return NODE_STORAGE_CAPACITY;
        }
        MAX_NODES
    }
    /// Trusted M8 custody/Root factory. It cannot upgrade an existing domain or
    /// an Authority initialized for a legacy profile. Recycle preserves class.
    #[cfg(feature = "workspace-authority")]
    pub fn create_workspace_control_space(&mut self) -> Result<SpaceId, Error> {
        if !self.envelope.workspace {
            return Err(Error::Denied);
        }
        let space = self.create_control_space()?;
        let bank = self.bank(space.0).ok_or(Error::InvalidSpace)?;
        self.envelope.workspace_controls[bank] = true;
        Ok(space)
    }
    /// Copy fixed metadata for a crate-private staged admission transaction.
    /// This does not copy hardware, mappings or resource ownership and must not
    /// become an independently executing authority instance. The trusted caller
    /// commits the staged metadata only after every participating table passes
    /// validation under the same serialized owner; rejected staging is discarded.
    pub(crate) fn staged_copy(&self) -> Self {
        Self {
            #[cfg(feature = "workspace-authority")]
            envelope: self.envelope,
            spaces: self.spaces,
            closed: self.closed,
            space_generations: self.space_generations,
            slots: self.slots,
            control_owners: self.control_owners,
            control_slots: self.control_slots,
            nodes: self.nodes,
            objects: self.objects,
            object_generations: self.object_generations,
        }
    }
    /// Trusted kernel bootstrap creation, not callable by a userspace request.
    pub fn create_space(&mut self) -> Result<SpaceId, Error> {
        let index = self.spaces[..self.space_limit()]
            .iter()
            .position(|s| !s)
            .ok_or(Error::Capacity)?;
        self.spaces[index] = true;
        self.space_generations[index] = 1;
        Ok(SpaceId(index, 1))
    }
    /// Trusted bootstrap/custody factory only. A closed control domain retains
    /// its physical bank and every slot generation; only explicit recycle_space
    /// reopens that same domain. Ordinary CreateProcess never calls this API.
    pub fn create_control_space(&mut self) -> Result<SpaceId, Error> {
        let index = self.spaces[..self.space_limit()]
            .iter()
            .position(|used| !used)
            .ok_or(Error::Capacity)?;
        let bank = self
            .control_owners
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.spaces[index] = true;
        self.space_generations[index] = 1;
        self.control_owners[bank] = Some(index);
        Ok(SpaceId(index, 1))
    }
    /// Read-only actual domain bound, not a caller-supplied class or authority.
    pub fn slot_capacity(&self, space: SpaceId) -> Result<usize, Error> {
        Ok(self.capacity(self.space(space)?))
    }
    fn bank(&self, space: usize) -> Option<usize> {
        self.control_owners
            .iter()
            .position(|owner| *owner == Some(space))
    }
    fn capacity(&self, space: usize) -> usize {
        if let Some(bank) = self.bank(space) {
            #[cfg(feature = "workspace-authority")]
            if self.envelope.workspace_controls[bank] {
                return CONTROL_STORAGE_CAPACITY;
            }
            let _ = bank;
            MAX_CONTROL_CAPS
        } else {
            MAX_CAPS
        }
    }
    fn entries(&self, space: usize) -> impl Iterator<Item = &Slot> {
        self.slots[space]
            .iter()
            .chain(
                self.bank(space)
                    .into_iter()
                    .flat_map(|bank| self.control_slots[bank].iter()),
            )
            .take(self.capacity(space))
    }
    fn slot(&self, space: usize, index: usize) -> Option<&Slot> {
        if index >= self.capacity(space) {
            return None;
        }
        if index < MAX_CAPS {
            self.slots[space].get(index)
        } else {
            self.control_slots
                .get(self.bank(space)?)?
                .get(index - MAX_CAPS)
        }
    }
    fn slot_mut(&mut self, space: usize, index: usize) -> Option<&mut Slot> {
        if index >= self.capacity(space) {
            return None;
        }
        if index < MAX_CAPS {
            self.slots[space].get_mut(index)
        } else {
            let bank = self.bank(space)?;
            self.control_slots[bank].get_mut(index - MAX_CAPS)
        }
    }
    fn space(&self, id: SpaceId) -> Result<usize, Error> {
        if self.spaces.get(id.0) == Some(&true)
            && self.space_generations[id.0] == id.1
            && !self.closed[id.0]
        {
            Ok(id.0)
        } else {
            Err(Error::InvalidSpace)
        }
    }
    pub fn is_live_space(&self, id: SpaceId) -> bool {
        self.space(id).is_ok()
    }
    /// Internal activation check: the complete domain must still contain exactly
    /// this batch, including current handle generations. No extra grants allowed.
    pub(crate) fn require_exact_handles(
        &self,
        owner: SpaceId,
        handles: &[Handle],
    ) -> Result<(), Error> {
        let space = self.space(owner)?;
        if handles.is_empty()
            || handles.len() > self.capacity(space)
            || self.entries(space).filter(|s| s.node.is_some()).count() != handles.len()
        {
            return Err(Error::Denied);
        }
        let mut seen = [false; CONTROL_STORAGE_CAPACITY];
        for handle in handles {
            let (slot, _) = self.locate(owner, *handle)?;
            if seen[slot] {
                return Err(Error::Denied);
            }
            seen[slot] = true;
        }
        Ok(())
    }
    /// Trusted read-only escrow preflight. Empty receipts must not strand an
    /// untracked handle in a private mailbox domain during typed configuration.
    pub(crate) fn require_empty_space(&self, owner: SpaceId) -> Result<(), Error> {
        let space = self.space(owner)?;
        if self.entries(space).any(|slot| slot.node.is_some()) {
            Err(Error::DestinationNotEmpty)
        } else {
            Ok(())
        }
    }
    /// Exact live parent/object/rights relation, not merely matching object kind.
    pub(crate) fn require_child(
        &self,
        owner: SpaceId,
        handle: Handle,
        parent_owner: SpaceId,
        parent: Handle,
        kind: Kind,
        rights: Rights,
    ) -> Result<(), Error> {
        let (index, node) = self.live_node(parent_owner, parent)?;
        let (_, child) = self.live_node(owner, handle)?;
        if child.parent != Some(node_index(index))
            || child.object != node.object
            || child.rights != rights
        {
            return Err(Error::Denied);
        }
        self.authorize(owner, handle, kind, rights)?;
        Ok(())
    }
    /// Trusted lifecycle operation after process quiescence. Close local handles
    /// without revoking grants already delegated/moved elsewhere. Retain lineage
    /// and domain generation. Only explicit recycle_space may reopen the slot,
    /// always under a different identity; callers must finish external teardown.
    pub fn close_space(&mut self, id: SpaceId) -> Result<usize, Error> {
        if self.spaces.get(id.0) != Some(&true) || self.space_generations[id.0] != id.1 {
            return Err(Error::InvalidSpace);
        }
        let mut count = 0;
        for index in 0..self.capacity(id.0) {
            if self.slot_mut(id.0, index).unwrap().node.take().is_some() {
                count += 1;
            }
        }
        self.closed[id.0] = true;
        Ok(count)
    }
    /// Trusted lifecycle operation after external process/IPC/mapping teardown.
    /// No implicit reuse in create_space. Preserve handle generations as well as
    /// changing the domain generation; stale identities never name the new owner.
    pub fn recycle_space(&mut self, old: SpaceId) -> Result<SpaceId, Error> {
        if self.spaces.get(old.0) != Some(&true) || self.space_generations[old.0] != old.1 {
            return Err(Error::InvalidSpace);
        }
        if !self.closed[old.0] || self.entries(old.0).any(|s| s.node.is_some()) {
            return Err(Error::SpaceBusy);
        }
        let generation = old.1.checked_add(1).ok_or(Error::GenerationExhausted)?;
        self.space_generations[old.0] = generation;
        self.closed[old.0] = false;
        Ok(SpaceId(old.0, generation))
    }
    /// Bounded mark/sweep of lineage only. Every extant table handle (including
    /// private IPC escrow) retains its complete ancestry, even when revoked.
    /// Borrowed Access values exclude this mutation. No object descriptor,
    /// physical resource, process or external reference is reclaimed here.
    pub fn collect_lineage(&mut self) -> Result<usize, Error> {
        let mut reachable = [false; NODE_STORAGE_CAPACITY];
        for slot in self
            .slots
            .iter()
            .flatten()
            .chain(self.control_slots.iter().flatten())
        {
            let mut current = slot.node.map(NodeIndex::index);
            for _ in 0..NODE_STORAGE_CAPACITY {
                let Some(index) = current else {
                    break;
                };
                let node = self
                    .nodes
                    .get(index)
                    .and_then(|n| *n)
                    .ok_or(Error::Revoked)?;
                reachable[index] = true;
                current = node.parent.map(NodeIndex::index);
            }
            if current.is_some() {
                return Err(Error::Revoked);
            }
        }
        let mut reclaimed = 0;
        for (node, keep) in self.nodes.iter_mut().zip(reachable) {
            if !keep && node.take().is_some() {
                reclaimed += 1;
            }
        }
        Ok(reclaimed)
    }
    /// Explicit descriptor collection, separate from lineage and physical
    /// teardown. Only dead descriptors with no remaining node reference may be
    /// reclaimed. Every node pins its object, including closed ancestors and
    /// private escrow ancestry not yet removed by collect_lineage(). Live but
    /// unreachable objects stay retained; revocation alone does not destroy one.
    ///
    /// Existing Access borrows exclude collection. Cached backend/lease identities
    /// remain distinguishable after reuse by the retained generation counter.
    /// This operation never frees backing, mappings, DMA, threads or processes,
    /// and certifies no hardware/reference quiescence beyond this metadata table.
    pub fn collect_dead_objects(&mut self) -> Result<usize, Error> {
        let mut referenced = [false; OBJECT_STORAGE_CAPACITY];
        // Validate the whole table before collecting anything. Corrupt/dangling
        // references cannot turn into permission to reclaim another descriptor.
        for start in 0..NODE_STORAGE_CAPACITY {
            if self.nodes[start].is_none() {
                continue;
            }
            let mut current = Some(start);
            for _ in 0..NODE_STORAGE_CAPACITY {
                let Some(index) = current else { break };
                let node = self
                    .nodes
                    .get(index)
                    .and_then(|node| *node)
                    .ok_or(Error::Revoked)?;
                self.object_identity(node.object)?;
                referenced[node.object] = true;
                current = node.parent.map(NodeIndex::index);
            }
            if current.is_some() {
                return Err(Error::Revoked);
            }
        }
        for (slot, object) in self.objects.iter().enumerate() {
            if object.is_some() {
                self.object_identity(slot)?;
            }
        }
        let mut reclaimed = 0;
        for (object, referenced) in self.objects.iter_mut().zip(referenced) {
            if !referenced && object.is_some_and(|object| !object.live) {
                *object = None;
                reclaimed += 1;
            }
        }
        Ok(reclaimed)
    }
    /// Trusted registry retirement after its actual resource has independently
    /// stopped and released backing. This is not a userspace operation accepting
    /// diagnostic integers. The registry must retain this exact object identity
    /// and kind from creation; a slot alone can never authorize retirement.
    ///
    /// Even an unreachable/revoked node prevents retirement until every handle
    /// has closed and collect_lineage() has removed its nodes. Thus this cannot
    /// invalidate an escaped live capability. Only descriptor liveness changes;
    /// hardware/process/IPC quiescence and accounting remain the caller's duty.
    pub(crate) fn retire_unreferenced_object(
        &mut self,
        identity: usize,
        expected: Kind,
    ) -> Result<(), Error> {
        let slot = identity & 255;
        if self.object_identity(slot)? != identity {
            return Err(Error::DeadObject);
        }
        if self.objects[slot].ok_or(Error::DeadObject)?.kind != expected {
            return Err(Error::WrongKind);
        }
        if self.nodes.iter().flatten().any(|node| node.object == slot) {
            return Err(Error::ObjectBusy);
        }
        self.objects[slot].as_mut().unwrap().live = false;
        Ok(())
    }
    fn prepare_object(&self) -> Result<(usize, usize), Error> {
        let slot = self.objects[..self.object_limit()]
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self.object_generations[slot]
            .checked_add(1)
            .filter(|generation| *generation <= MAX_OBJECT_GENERATION)
            .ok_or(Error::GenerationExhausted)?;
        Ok((slot, generation))
    }
    fn object_identity(&self, slot: usize) -> Result<usize, Error> {
        self.objects
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::DeadObject)?;
        let generation = self.object_generations[slot];
        if generation == 0 || generation > MAX_OBJECT_GENERATION {
            return Err(Error::DeadObject);
        }
        Ok(((generation - 1) << 8) | slot)
    }
    fn prepare_slot(&self, owner: SpaceId) -> Result<(usize, u64), Error> {
        let space = self.space(owner)?;
        let slot = self
            .entries(space)
            .position(|s| s.node.is_none())
            .ok_or(Error::Capacity)?;
        let generation = self.slot(space, slot).unwrap().generation;
        if generation >= MAX_GENERATION {
            return Err(Error::GenerationExhausted);
        }
        Ok((slot, generation + 1))
    }
    fn install(&mut self, owner: SpaceId, slot: (usize, u64), node: usize) -> Handle {
        *self.slot_mut(owner.0, slot.0).unwrap() = Slot {
            generation: slot.1,
            node: Some(node_index(node)),
        };
        Handle((slot.1 << 8) | slot.0 as u64)
    }
    fn locate(&self, owner: SpaceId, handle: Handle) -> Result<(usize, usize), Error> {
        let space = self.space(owner)?;
        let slot = (handle.0 & 255) as usize;
        let entry = self.slot(space, slot).ok_or(Error::InvalidHandle)?;
        if entry.generation == 0 || entry.generation != handle.0 >> 8 {
            return Err(Error::InvalidHandle);
        }
        Ok((slot, entry.node.ok_or(Error::InvalidHandle)?.index()))
    }
    fn live_node(&self, owner: SpaceId, handle: Handle) -> Result<(usize, Node), Error> {
        let (_, index) = self.locate(owner, handle)?;
        let node = self.nodes[index].ok_or(Error::InvalidHandle)?;
        let mut ancestor = Some(index);
        for _ in 0..NODE_STORAGE_CAPACITY {
            let Some(current) = ancestor else { break };
            let parent = self
                .nodes
                .get(current)
                .and_then(|n| *n)
                .ok_or(Error::Revoked)?;
            if !parent.live {
                return Err(Error::Revoked);
            }
            // Creation ancestry can cross object identities. Destroying a
            // creator object invalidates its descendants just as revoking its
            // node does, even when their own object descriptors remain live.
            if !self
                .objects
                .get(parent.object)
                .and_then(|o| *o)
                .ok_or(Error::DeadObject)?
                .live
            {
                return Err(Error::DeadObject);
            }
            self.object_identity(parent.object)?;
            ancestor = parent.parent.map(NodeIndex::index);
        }
        if ancestor.is_some() {
            return Err(Error::Revoked);
        }
        Ok((index, node))
    }
    /// Trusted bootstrap mint only. Runtime creation must require an allocator /
    /// creator capability before this primitive is exposed across a boundary.
    pub fn create_root(
        &mut self,
        owner: SpaceId,
        kind: Kind,
        rights: Rights,
    ) -> Result<Handle, Error> {
        if !kind.allowed().contains(rights) {
            return Err(Error::Denied);
        }
        let slot = self.prepare_slot(owner)?;
        let (object, generation) = self.prepare_object()?;
        let node = self.nodes[..self.node_limit()]
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.object_generations[object] = generation;
        self.objects[object] = Some(Object { kind, live: true });
        self.nodes[node] = Some(Node {
            object,
            parent: None,
            rights,
            live: true,
        });
        Ok(self.install(owner, slot, node))
    }
    /// Create one bounded managed object beneath a live Job CONTROL grant.
    /// The initial handle stays in the caller's domain; cross-domain delegation
    /// still requires explicit DERIVE/TRANSFER rights. This is object creation,
    /// not a same-object derivation: creation ancestry ensures revoking/destroying
    /// the creator invalidates all managed descendants. Physical Memory and
    /// Thread creation remain unsupported here. The trusted registry caller must
    /// separately bind and budget the corresponding live scheduler/IPC object.
    pub fn create_managed(
        &mut self,
        owner: SpaceId,
        creator: Handle,
        kind: Kind,
        rights: Rights,
    ) -> Result<Handle, Error> {
        let parent = self
            .authorize(owner, creator, Kind::Job, Rights::CONTROL)?
            .node;
        if !matches!(
            kind,
            Kind::Job | Kind::Process | Kind::Endpoint | Kind::Mutex
        ) || rights.bits() == 0
            || !kind.permits(rights)
        {
            return Err(Error::Denied);
        }
        let slot = self.prepare_slot(owner)?;
        let (object, generation) = self.prepare_object()?;
        let node = self.nodes[..self.node_limit()]
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        // No fallible work remains. The exclusive borrow serializes creation
        // with creator revocation and publishes only the complete local grant.
        self.object_generations[object] = generation;
        self.objects[object] = Some(Object { kind, live: true });
        self.nodes[node] = Some(Node {
            object,
            parent: Some(node_index(parent)),
            rights,
            live: true,
        });
        Ok(self.install(owner, slot, node))
    }
    pub fn authorize(
        &self,
        owner: SpaceId,
        handle: Handle,
        kind: Kind,
        required: Rights,
    ) -> Result<Access<'_>, Error> {
        let (index, node) = self.live_node(owner, handle)?;
        let object = self.objects[node.object]
            .as_ref()
            .ok_or(Error::DeadObject)?;
        if object.kind != kind {
            return Err(Error::WrongKind);
        }
        if !node.rights.contains(required) {
            return Err(Error::Denied);
        }
        let mut lineage_root = index;
        for _ in 0..NODE_STORAGE_CAPACITY {
            match self.nodes[lineage_root].ok_or(Error::Revoked)?.parent {
                Some(parent) => lineage_root = parent.index(),
                None => break,
            }
        }
        Ok(Access {
            object,
            identity: self.object_identity(node.object)?,
            rights: node.rights,
            node: index,
            lineage_root,
        })
    }
    /// Trusted bootstrap transaction. Preflight every source, slot generation
    /// and lineage allocation before any mutation. The destination must be empty
    /// and distinct from custody. No thread may be scheduled before its caller's
    /// remaining bootstrap checks complete. Does not reclaim retained metadata.
    pub fn derive_into_empty(
        &mut self,
        owner: SpaceId,
        destination: SpaceId,
        requests: &[Derivation],
    ) -> Result<GrantBatch, Error> {
        Ok(self
            .derive_transaction(owner, None, destination, requests)?
            .grants)
    }
    /// Atomically pin one private revocation branch per requested object and
    /// derive the exact requested user grants beneath them. Kernel-only branch
    /// custody and user destination must be empty and distinct from each other
    /// and the source. Extra branch rights never appear in user grants.
    pub fn derive_scoped_into_empty(
        &mut self,
        owner: SpaceId,
        branches: SpaceId,
        destination: SpaceId,
        requests: &[Derivation],
    ) -> Result<ScopedGrants, Error> {
        self.derive_transaction(owner, Some(branches), destination, requests)
    }
    fn derive_transaction(
        &mut self,
        owner: SpaceId,
        branches: Option<SpaceId>,
        destination: SpaceId,
        requests: &[Derivation],
    ) -> Result<ScopedGrants, Error> {
        self.space(owner)?;
        self.space(destination)?;
        if owner == destination || self.entries(destination.0).any(|s| s.node.is_some()) {
            return Err(Error::DestinationNotEmpty);
        }
        if let Some(branches) = branches {
            self.space(branches)?;
            if branches == owner
                || branches == destination
                || self.entries(branches.0).any(|s| s.node.is_some())
            {
                return Err(Error::DestinationNotEmpty);
            }
        }
        if requests.is_empty()
            || requests.len() > self.capacity(destination.0)
            || branches.is_some_and(|branch| requests.len() > self.capacity(branch.0))
        {
            return Err(Error::Capacity);
        }
        let mut parents = [0; CONTROL_STORAGE_CAPACITY];
        let mut objects = [0; CONTROL_STORAGE_CAPACITY];
        let mut vacant = [0; 2 * CONTROL_STORAGE_CAPACITY];
        let branch_rights = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
        for (i, request) in requests.iter().enumerate() {
            let (parent, source) = self.live_node(owner, request.source)?;
            if self.objects[source.object].ok_or(Error::DeadObject)?.kind != request.kind {
                return Err(Error::WrongKind);
            }
            let extra = if branches.is_some() {
                branch_rights
            } else {
                Rights::DERIVE | Rights::TRANSFER
            };
            if !source.rights.contains(extra | request.rights) {
                return Err(Error::Denied);
            }
            if self.slot(destination.0, i).unwrap().generation >= MAX_GENERATION
                || branches.is_some_and(|b| self.slot(b.0, i).unwrap().generation >= MAX_GENERATION)
            {
                return Err(Error::GenerationExhausted);
            }
            parents[i] = parent;
            objects[i] = source.object;
        }
        let required = requests.len() * if branches.is_some() { 2 } else { 1 };
        let mut found = 0;
        for (i, node) in self.nodes[..self.node_limit()].iter().enumerate() {
            if node.is_none() {
                vacant[found] = i;
                found += 1;
                if found == required {
                    break;
                }
            }
        }
        if found != required {
            return Err(Error::Capacity);
        }
        // No fallible work remains. Exclusive mutation linearizes both levels.
        let mut handles = [Handle(0); CONTROL_STORAGE_CAPACITY];
        let mut pinned = [Handle(0); CONTROL_STORAGE_CAPACITY];
        for (i, request) in requests.iter().enumerate() {
            let parent = if let Some(branches) = branches {
                let branch = vacant[requests.len() + i];
                self.nodes[branch] = Some(Node {
                    object: objects[i],
                    parent: Some(node_index(parents[i])),
                    rights: request.rights | branch_rights,
                    live: true,
                });
                pinned[i] = self.install(
                    branches,
                    (i, self.slot(branches.0, i).unwrap().generation + 1),
                    branch,
                );
                branch
            } else {
                parents[i]
            };
            self.nodes[vacant[i]] = Some(Node {
                object: objects[i],
                parent: Some(node_index(parent)),
                rights: request.rights,
                live: true,
            });
            handles[i] = self.install(
                destination,
                (i, self.slot(destination.0, i).unwrap().generation + 1),
                vacant[i],
            );
        }
        Ok(ScopedGrants {
            branches: GrantBatch {
                handles: pinned,
                count: if branches.is_some() {
                    requests.len()
                } else {
                    0
                },
            },
            grants: GrantBatch {
                handles,
                count: requests.len(),
            },
        })
    }
    /// Atomically invalidate a bounded group of local REVOKE handles. Preflight
    /// uses slot generations and local rights, deliberately allowing already
    /// revoked/dead ancestry: repeated teardown can only remove authority.
    /// Caller retains private branch handles until external teardown completes.
    pub fn revoke_batch(&mut self, owner: SpaceId, handles: &[Handle]) -> Result<(), Error> {
        let space = self.space(owner)?;
        if handles.is_empty() || handles.len() > self.capacity(space) {
            return Err(Error::Capacity);
        }
        let mut indices = [0; CONTROL_STORAGE_CAPACITY];
        for (i, handle) in handles.iter().enumerate() {
            let (_, index) = self.locate(owner, *handle)?;
            let node = self.nodes[index].ok_or(Error::InvalidHandle)?;
            if !node.rights.contains(Rights::REVOKE) {
                return Err(Error::Denied);
            }
            indices[i] = index;
        }
        for index in &indices[..handles.len()] {
            // Existence established above; no concurrent mutation is possible.
            self.nodes[*index].as_mut().unwrap().live = false;
        }
        Ok(())
    }
    /// Attenuation retains source authority and creates a revocable descendant.
    /// Cross-domain delegation additionally requires TRANSFER.
    pub fn derive(
        &mut self,
        owner: SpaceId,
        handle: Handle,
        destination: SpaceId,
        rights: Rights,
    ) -> Result<Handle, Error> {
        let (parent, source) = self.live_node(owner, handle)?;
        let required = if owner == destination {
            Rights::DERIVE
        } else {
            Rights::DERIVE | Rights::TRANSFER
        };
        if !source.rights.contains(required) || !source.rights.contains(rights) {
            return Err(Error::Denied);
        }
        let slot = self.prepare_slot(destination)?;
        let node = self.nodes[..self.node_limit()]
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.nodes[node] = Some(Node {
            object: source.object,
            parent: Some(node_index(parent)),
            rights,
            live: true,
        });
        Ok(self.install(destination, slot, node))
    }
    /// Atomic move within this serialization domain; no duplicate source remains.
    pub fn transfer(
        &mut self,
        owner: SpaceId,
        handle: Handle,
        destination: SpaceId,
    ) -> Result<Handle, Error> {
        let (node, source) = self.live_node(owner, handle)?;
        if !source.rights.contains(Rights::TRANSFER) {
            return Err(Error::Denied);
        }
        let slot = self.prepare_slot(destination)?;
        let (old, _) = self.locate(owner, handle)?;
        let new = self.install(destination, slot, node);
        self.slot_mut(owner.0, old).unwrap().node = None;
        Ok(new)
    }
    /// Explicit derived move: require the source's live DERIVE|TRANSFER and
    /// requested subset, allocate a revocable child, then consume the source
    /// local handle. Ordinary transfer remains rights-preserving. All fallible
    /// work precedes mutation; no source claim/slot/node changes on refusal.
    /// This is a kernel table operation, not a syscall accepting user domains.
    pub fn transfer_attenuated(
        &mut self,
        owner: SpaceId,
        handle: Handle,
        destination: SpaceId,
        kind: Kind,
        rights: Rights,
    ) -> Result<Handle, Error> {
        let (parent, source) = self.live_node(owner, handle)?;
        if self.objects[source.object].ok_or(Error::DeadObject)?.kind != kind {
            return Err(Error::WrongKind);
        }
        if !source.rights.contains(Rights::DERIVE | Rights::TRANSFER)
            || !source.rights.contains(rights)
            || !kind.permits(rights)
        {
            return Err(Error::Denied);
        }
        let slot = self.prepare_slot(destination)?;
        let node = self.nodes[..self.node_limit()]
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let (old, _) = self.locate(owner, handle)?;
        self.nodes[node] = Some(Node {
            object: source.object,
            parent: Some(node_index(parent)),
            rights,
            live: true,
        });
        let new = self.install(destination, slot, node);
        self.slot_mut(owner.0, old).unwrap().node = None;
        Ok(new)
    }
    /// Closing a handle does not revoke surviving descendants. Retained lineage
    /// permits an authorized ancestor to revoke them after intermediates close.
    pub fn close(&mut self, owner: SpaceId, handle: Handle) -> Result<(), Error> {
        let (slot, _) = self.locate(owner, handle)?;
        self.slot_mut(owner.0, slot).unwrap().node = None;
        Ok(())
    }
    /// Invalidates this grant and its whole descendant subtree at one mutation.
    pub fn revoke(&mut self, owner: SpaceId, handle: Handle) -> Result<(), Error> {
        let (node, source) = self.live_node(owner, handle)?;
        if !source.rights.contains(Rights::REVOKE) {
            return Err(Error::Denied);
        }
        self.nodes[node].as_mut().ok_or(Error::InvalidHandle)?.live = false;
        Ok(())
    }
    /// Internal descriptor lifetime proof; real object teardown/quiescence must
    /// be integrated before this models physical memory or an active process.
    pub fn destroy(&mut self, owner: SpaceId, handle: Handle) -> Result<(), Error> {
        let (_, node) = self.live_node(owner, handle)?;
        if !node.rights.contains(Rights::CONTROL) {
            return Err(Error::Denied);
        }
        self.objects[node.object]
            .as_mut()
            .ok_or(Error::DeadObject)?
            .live = false;
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    pub(crate) fn unchanged(a: &Authority, before: &Authority) {
        #[cfg(feature = "workspace-authority")]
        assert_eq!(a.envelope, before.envelope);
        assert_eq!(a.spaces, before.spaces);
        assert_eq!(a.closed, before.closed);
        assert_eq!(a.space_generations, before.space_generations);
        assert_eq!(a.object_generations, before.object_generations);
        assert_eq!(a.control_owners, before.control_owners);
        for (after, before) in a
            .control_slots
            .iter()
            .flatten()
            .zip(before.control_slots.iter().flatten())
        {
            assert_eq!(
                (after.generation, after.node),
                (before.generation, before.node)
            );
        }
        for (after, before) in a.slots.iter().flatten().zip(before.slots.iter().flatten()) {
            assert_eq!(
                (after.generation, after.node),
                (before.generation, before.node)
            );
        }
        for (after, before) in a.nodes.iter().zip(&before.nodes) {
            assert_eq!(
                after.map(|n| (n.object, n.parent, n.rights, n.live)),
                before.map(|n| (n.object, n.parent, n.rights, n.live))
            );
        }
        for (after, before) in a.objects.iter().zip(&before.objects) {
            assert_eq!(
                after.map(|o| (o.kind, o.live)),
                before.map(|o| (o.kind, o.live))
            );
        }
    }
    #[test]
    fn control_banks_are_bounded_retained_and_generation_safe_without_widening_children() {
        let mut a = Authority::new();
        let ordinary = a.create_space().unwrap();
        assert_eq!(a.slot_capacity(ordinary), Ok(MAX_CAPS));
        let root = a
            .create_root(ordinary, Kind::Memory, Kind::Memory.allowed())
            .unwrap();
        for _ in 1..MAX_CAPS {
            a.derive(ordinary, root, ordinary, Rights::READ).unwrap();
        }
        let before = a.staged_copy();
        assert_eq!(
            a.derive(ordinary, root, ordinary, Rights::READ),
            Err(Error::Capacity)
        );
        unchanged(&a, &before);
        let controls: [SpaceId; MAX_CONTROL_SPACES] =
            core::array::from_fn(|_| a.create_control_space().unwrap());
        assert!(
            controls
                .iter()
                .all(|space| a.slot_capacity(*space) == Ok(MAX_CONTROL_CAPS))
        );
        let handles: [Handle; MAX_CONTROL_CAPS] =
            core::array::from_fn(|_| a.derive(ordinary, root, controls[0], Rights::READ).unwrap());
        assert_eq!(
            handles[MAX_CONTROL_CAPS - 1].0 & 255,
            (MAX_CONTROL_CAPS - 1) as u64
        );
        let before = a.staged_copy();
        assert_eq!(
            a.derive(ordinary, root, controls[0], Rights::READ),
            Err(Error::Capacity)
        );
        assert_eq!(a.create_control_space(), Err(Error::Capacity));
        unchanged(&a, &before);
        assert_eq!(a.close_space(controls[0]), Ok(MAX_CONTROL_CAPS));
        assert_eq!(a.slot_capacity(controls[0]), Err(Error::InvalidSpace));
        let before = a.staged_copy();
        assert_eq!(a.create_control_space(), Err(Error::Capacity));
        unchanged(&a, &before); // Closing does not silently free/reassign a bank.
        assert_eq!(a.collect_lineage(), Ok(MAX_CONTROL_CAPS));
        let next = a.recycle_space(controls[0]).unwrap();
        assert_ne!(next, controls[0]);
        assert_eq!(a.slot_capacity(next), Ok(MAX_CONTROL_CAPS));
        for old in handles {
            assert_eq!(
                a.authorize(controls[0], old, Kind::Memory, Rights::READ)
                    .err(),
                Some(Error::InvalidSpace)
            );
            assert_eq!(
                a.authorize(next, old, Kind::Memory, Rights::READ).err(),
                Some(Error::InvalidHandle)
            );
            let fresh = a.derive(ordinary, root, next, Rights::READ).unwrap();
            assert_ne!(fresh, old);
            assert_eq!(fresh.0 & 255, old.0 & 255);
            assert_eq!(fresh.0 >> 8, 2);
        }
        assert_eq!(a.slot_capacity(ordinary), Ok(MAX_CAPS));
    }
    #[test]
    fn control_scoped_batch_preflights_high_slots_and_preserves_v1_capacity() {
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        let branches = a.create_control_space().unwrap();
        let destination = a.create_control_space().unwrap();
        let ordinary = a.create_space().unwrap();
        let source = a
            .create_root(owner, Kind::Memory, Kind::Memory.allowed())
            .unwrap();
        let requests = [Derivation {
            source,
            kind: Kind::Memory,
            rights: Rights::READ,
        }; 24];
        let before = a.staged_copy();
        assert_eq!(
            a.derive_scoped_into_empty(owner, branches, ordinary, &requests)
                .err(),
            Some(Error::Capacity)
        );
        unchanged(&a, &before);
        let mut wrong = requests;
        wrong[23].kind = Kind::Endpoint;
        assert_eq!(
            a.derive_scoped_into_empty(owner, branches, destination, &wrong)
                .err(),
            Some(Error::WrongKind)
        );
        unchanged(&a, &before);
        a.slot_mut(branches.0, 23).unwrap().generation = MAX_GENERATION;
        let before = a.staged_copy();
        assert_eq!(
            a.derive_scoped_into_empty(owner, branches, destination, &requests)
                .err(),
            Some(Error::GenerationExhausted)
        );
        unchanged(&a, &before);
        a.slot_mut(branches.0, 23).unwrap().generation = 0;
        let grants = a
            .derive_scoped_into_empty(owner, branches, destination, &requests)
            .unwrap();
        assert_eq!(
            (
                grants.grants.handles().len(),
                grants.branches.handles().len()
            ),
            (24, 24)
        );
        a.require_exact_handles(destination, grants.grants.handles())
            .unwrap();
        let lineage = a
            .authorize(owner, source, Kind::Memory, Rights::READ)
            .unwrap()
            .lineage_root();
        for handle in grants.grants.handles() {
            assert_eq!(
                a.authorize(destination, *handle, Kind::Memory, Rights::READ)
                    .unwrap()
                    .lineage_root(),
                lineage
            );
        }
        a.revoke_batch(branches, grants.branches.handles()).unwrap();
        for handle in grants.grants.handles() {
            assert_eq!(
                a.authorize(destination, *handle, Kind::Memory, Rights::READ)
                    .err(),
                Some(Error::Revoked)
            );
        }
        assert!(
            a.authorize(owner, source, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert_eq!(a.close_space(destination), Ok(24));
        assert_eq!(a.close_space(branches), Ok(24));
        assert_eq!(a.collect_lineage(), Ok(48));
        let next_destination = a.recycle_space(destination).unwrap();
        let next_branches = a.recycle_space(branches).unwrap();
        let next = a
            .derive_scoped_into_empty(owner, next_branches, next_destination, &requests)
            .unwrap();
        for (old, new) in grants.grants.handles().iter().zip(next.grants.handles()) {
            assert_ne!(old, new);
            assert_eq!(
                a.authorize(next_destination, *old, Kind::Memory, Rights::READ)
                    .err(),
                Some(Error::InvalidHandle)
            );
        }
    }
    #[test]
    fn high_control_slots_pin_dead_objects_until_exact_close_and_collection() {
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        let handles: [Handle; MAX_OBJECTS] = core::array::from_fn(|_| {
            a.create_root(owner, Kind::Memory, Kind::Memory.allowed())
                .unwrap()
        });
        let last = handles[MAX_OBJECTS - 1];
        a.destroy(owner, last).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        assert_eq!(a.collect_dead_objects(), Ok(0));
        a.close(owner, last).unwrap();
        assert_eq!(a.collect_lineage(), Ok(1));
        assert_eq!(a.collect_dead_objects(), Ok(1));
        let fresh = a
            .create_root(owner, Kind::Memory, Kind::Memory.allowed())
            .unwrap();
        assert_eq!(
            a.authorize(owner, fresh, Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
            256 + MAX_OBJECTS - 1
        );
        assert_ne!(fresh, last);
        assert_eq!(
            a.authorize(owner, last, Kind::Memory, Rights::READ).err(),
            Some(Error::InvalidHandle)
        );
    }
    #[test]
    fn compact_node_links_check_bound_width_zero_and_keep_exact_public_indices() {
        assert_eq!(NodeIndex::checked(0).unwrap().0.get(), 1);
        assert_eq!(
            NodeIndex::checked(NODE_STORAGE_CAPACITY - 1)
                .unwrap()
                .index(),
            NODE_STORAGE_CAPACITY - 1
        );
        assert!(NodeIndex::checked(NODE_STORAGE_CAPACITY).is_none());
        assert!(NodeIndex::checked(usize::MAX).is_none());
        assert!(NonZeroU16::new(0).is_none());
        assert_eq!(core::mem::size_of::<Option<NodeIndex>>(), 2);
        assert_eq!(core::mem::size_of::<Slot>(), 16);
        assert_eq!(core::mem::size_of::<Node>(), 16);
        assert!(
            core::mem::size_of::<Authority>()
                < if cfg!(feature = "workspace-authority") {
                    32 * 1024
                } else {
                    20 * 1024
                }
        );
        std::println!(
            "CAPACITY Authority={} Slot={} Node={} GrantBatch={}",
            core::mem::size_of::<Authority>(),
            core::mem::size_of::<Slot>(),
            core::mem::size_of::<Node>(),
            core::mem::size_of::<GrantBatch>()
        );
    }
    #[test]
    fn attenuated_move_preflights_generation_and_node_capacity_without_mutation() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let target = a.create_space().unwrap();
        let root = a
            .create_root(owner, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let source = a
            .derive(
                owner,
                root,
                owner,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        a.slots[target.0][0].generation = MAX_GENERATION;
        let before = a.staged_copy();
        assert_eq!(
            a.transfer_attenuated(owner, source, target, Kind::Endpoint, Rights::SEND),
            Err(Error::GenerationExhausted)
        );
        unchanged(&a, &before);
        a.slots[target.0][0].generation = 0;
        while let Ok(temporary) = a.derive(owner, root, owner, Rights::SEND) {
            a.close(owner, temporary).unwrap();
        }
        let before = a.staged_copy();
        assert_eq!(
            a.transfer_attenuated(owner, source, target, Kind::Endpoint, Rights::SEND),
            Err(Error::Capacity)
        );
        unchanged(&a, &before);
        a.collect_lineage().unwrap();
        let leaf = a
            .transfer_attenuated(owner, source, target, Kind::Endpoint, Rights::SEND)
            .unwrap();
        assert_eq!(
            a.authorize(target, leaf, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights(),
            Rights::SEND
        );
        assert_eq!(
            a.authorize(owner, source, Kind::Endpoint, Rights::SEND)
                .err(),
            Some(Error::InvalidHandle)
        );
    }
    #[test]
    fn explicit_derived_move_cannot_change_kind_amplify_or_hide_ordinary_transfer_rights() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let target = a.create_space().unwrap();
        let root = a
            .create_root(owner, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let source = a
            .derive(owner, root, owner, Rights::SEND | Rights::TRANSFER)
            .unwrap();
        for (kind, rights, error) in [
            (Kind::Endpoint, Rights::SEND, Error::Denied),
            (Kind::Memory, Rights::READ, Error::WrongKind),
        ] {
            let before = a.staged_copy();
            assert_eq!(
                a.transfer_attenuated(owner, source, target, kind, rights),
                Err(error)
            );
            unchanged(&a, &before);
        }
        let ordinary = a.transfer(owner, source, target).unwrap();
        assert_eq!(
            a.authorize(target, ordinary, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .rights()
                .bits(),
            72
        );
        let source = a
            .derive(
                owner,
                root,
                owner,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let before = a.staged_copy();
        assert_eq!(
            a.transfer_attenuated(owner, source, target, Kind::Endpoint, Rights::RECEIVE),
            Err(Error::Denied)
        );
        unchanged(&a, &before);
    }
    fn creator() -> (Authority, SpaceId, Handle) {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let job = a
            .create_root(owner, Kind::Job, Kind::Job.allowed())
            .unwrap();
        (a, owner, job)
    }
    #[test]
    fn initial_object_identities_stay_compatible_and_reuse_preserves_generation() {
        let mut a = Authority::new();
        let owner = a.create_control_space().unwrap();
        let handles: [Handle; MAX_OBJECTS] = core::array::from_fn(|slot| {
            let handle = a
                .create_root(owner, Kind::Memory, Rights::READ | Rights::CONTROL)
                .unwrap();
            assert_eq!(
                a.authorize(owner, handle, Kind::Memory, Rights::READ)
                    .unwrap()
                    .identity(),
                slot
            );
            handle
        });
        for handle in handles {
            a.destroy(owner, handle).unwrap();
            a.close(owner, handle).unwrap();
        }
        assert_eq!(a.collect_dead_objects(), Ok(0));
        assert_eq!(a.collect_lineage(), Ok(MAX_OBJECTS));
        assert_eq!(a.collect_dead_objects(), Ok(MAX_OBJECTS));
        assert_eq!(a.object_generations[..MAX_OBJECTS], [1; MAX_OBJECTS]);
        assert!(a.object_generations[MAX_OBJECTS..].iter().all(|g| *g == 0));
        let staged = a.staged_copy();
        unchanged(&a, &staged);
        let replacement = a.create_root(owner, Kind::Endpoint, Rights::SEND).unwrap();
        let identity = a
            .authorize(owner, replacement, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity();
        assert_eq!(identity, 256);
        assert_eq!(identity & 255, 0);
        assert_eq!(a.object_generations[0], 2);
        assert_eq!(staged.object_generations[0], 1);
        assert!(staged.objects[0].is_none());
    }
    #[test]
    fn queued_escrow_and_closed_ancestor_nodes_pin_dead_descriptors() {
        use crate::{
            ipc::{Mailbox, Outgoing, Reclaimed},
            time::Deadline,
        };
        let (mut a, owner, sender, memory) = setup();
        let endpoint = a
            .create_root(owner, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let send = a.derive(owner, endpoint, sender, Rights::SEND).unwrap();
        let payload = a
            .derive(owner, memory, sender, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let mut queue = Mailbox::new(&mut a, owner, endpoint).unwrap();
        let ticket = queue
            .send(
                &mut a,
                sender,
                send,
                Outgoing {
                    bytes: b"pinned",
                    capability: Some(payload),
                    deadline: Deadline::after(0, 10).unwrap(),
                },
                0,
            )
            .unwrap();
        a.destroy(owner, memory).unwrap();
        a.close(owner, memory).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        assert_eq!(a.collect_dead_objects(), Ok(0));
        queue.receiver_died(owner).unwrap();
        assert_eq!(
            queue.reclaim(&mut a, sender, ticket, 0),
            Ok(Reclaimed::Invalidated)
        );
        // Closing escrow releases the last handle, but separate lineage
        // collection must still remove both the leaf and its closed ancestor.
        assert_eq!(a.collect_dead_objects(), Ok(0));
        assert_eq!(a.collect_lineage(), Ok(2));
        assert_eq!(a.collect_dead_objects(), Ok(1));
        assert!(
            a.authorize(owner, endpoint, Kind::Endpoint, Rights::RECEIVE)
                .is_ok()
        );
        assert!(
            a.authorize(sender, send, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        queue.retire_empty(&mut a).unwrap();
    }
    #[test]
    fn distinct_managed_child_nodes_pin_destroyed_creator_descriptors() {
        let (mut a, owner, job) = creator();
        let child = a
            .create_managed(owner, job, Kind::Job, Kind::Job.allowed())
            .unwrap();
        let process = a
            .create_managed(owner, child, Kind::Process, Rights::READ)
            .unwrap();
        let child_id = a
            .authorize(owner, child, Kind::Job, Rights::CONTROL)
            .unwrap()
            .identity();
        a.destroy(owner, child).unwrap();
        a.close(owner, child).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        assert_eq!(a.collect_dead_objects(), Ok(0));
        assert_eq!(
            a.authorize(owner, process, Kind::Process, Rights::READ)
                .err(),
            Some(Error::DeadObject)
        );
        a.close(owner, process).unwrap();
        assert_eq!(a.collect_dead_objects(), Ok(0));
        assert_eq!(a.collect_lineage(), Ok(2));
        assert_eq!(a.collect_dead_objects(), Ok(1));
        // The child's Process object was not explicitly destroyed; neither
        // revocation nor an empty reference graph authorizes automatic death.
        assert!(a.objects[child_id & 255].is_none());
        assert_eq!(a.objects.iter().flatten().count(), 2);
        assert!(a.authorize(owner, job, Kind::Job, Rights::CONTROL).is_ok());
    }
    #[test]
    fn unreferenced_registry_retirement_requires_exact_kind_generation_and_zero_nodes() {
        let (mut a, owner, job) = creator();
        let process = a
            .create_managed(owner, job, Kind::Process, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let identity = a
            .authorize(owner, process, Kind::Process, Rights::READ)
            .unwrap()
            .identity();
        for (candidate, kind, expected) in [
            (identity, Kind::Process, Error::ObjectBusy),
            (identity, Kind::Endpoint, Error::WrongKind),
            (identity + 256, Kind::Process, Error::DeadObject),
            (usize::MAX, Kind::Process, Error::DeadObject),
        ] {
            let before = a.staged_copy();
            assert_eq!(a.retire_unreferenced_object(candidate, kind), Err(expected));
            unchanged(&a, &before);
        }
        a.close(owner, process).unwrap();
        let before = a.staged_copy();
        assert_eq!(
            a.retire_unreferenced_object(identity, Kind::Process),
            Err(Error::ObjectBusy)
        );
        unchanged(&a, &before);
        assert_eq!(a.collect_lineage(), Ok(1));
        assert_eq!(a.collect_dead_objects(), Ok(0));
        a.retire_unreferenced_object(identity, Kind::Process)
            .unwrap();
        a.retire_unreferenced_object(identity, Kind::Process)
            .unwrap();
        assert_eq!(a.collect_dead_objects(), Ok(1));
        let replacement = a
            .create_managed(owner, job, Kind::Process, Rights::READ)
            .unwrap();
        let next = a
            .authorize(owner, replacement, Kind::Process, Rights::READ)
            .unwrap()
            .identity();
        assert_ne!(identity, next);
        assert_eq!(identity & 255, next & 255);
        let before = a.staged_copy();
        assert_eq!(
            a.retire_unreferenced_object(identity, Kind::Process),
            Err(Error::DeadObject)
        );
        unchanged(&a, &before);
    }
    #[test]
    fn registry_retirement_cannot_bypass_revoked_or_escrow_node_pins() {
        use crate::{
            ipc::{Mailbox, Outgoing, Reclaimed},
            time::Deadline,
        };
        let (mut a, owner, job) = creator();
        let sender = a.create_space().unwrap();
        let process = a
            .create_managed(owner, job, Kind::Process, Kind::Process.allowed())
            .unwrap();
        let identity = a
            .authorize(owner, process, Kind::Process, Rights::READ)
            .unwrap()
            .identity();
        let endpoint = a
            .create_root(owner, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let send = a.derive(owner, endpoint, sender, Rights::SEND).unwrap();
        let payload = a
            .derive(owner, process, sender, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let mut queue = Mailbox::new(&mut a, owner, endpoint).unwrap();
        let ticket = queue
            .send(
                &mut a,
                sender,
                send,
                Outgoing {
                    bytes: &[],
                    capability: Some(payload),
                    deadline: Deadline::after(0, 10).unwrap(),
                },
                0,
            )
            .unwrap();
        a.revoke(owner, process).unwrap();
        a.close(owner, process).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        let before = a.staged_copy();
        assert_eq!(
            a.retire_unreferenced_object(identity, Kind::Process),
            Err(Error::ObjectBusy)
        );
        unchanged(&a, &before);
        queue.receiver_died(owner).unwrap();
        assert_eq!(
            queue.reclaim(&mut a, sender, ticket, 0),
            Ok(Reclaimed::Invalidated)
        );
        assert_eq!(
            a.retire_unreferenced_object(identity, Kind::Process),
            Err(Error::ObjectBusy)
        );
        assert_eq!(a.collect_lineage(), Ok(2));
        a.retire_unreferenced_object(identity, Kind::Process)
            .unwrap();
        assert_eq!(a.collect_dead_objects(), Ok(1));
        queue.retire_empty(&mut a).unwrap();
        assert!(a.authorize(owner, job, Kind::Job, Rights::CONTROL).is_ok());
    }
    #[test]
    fn repeated_managed_object_lifetime_reuses_capacity_without_aliasing_stale_ids() {
        let (mut a, owner, job) = creator();
        let peer = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        let receiver = a.create_space().unwrap();
        let escrow = a.create_space().unwrap();
        let mut previous = None;
        for generation in 1..=512 {
            let handle = a
                .create_managed(owner, job, Kind::Endpoint, Kind::Endpoint.allowed())
                .unwrap();
            let identity = a
                .authorize(owner, handle, Kind::Endpoint, Rights::SEND)
                .unwrap()
                .identity();
            assert_eq!(identity, ((generation - 1) << 8) | 2);
            if let Some((old_handle, old_identity)) = previous {
                assert_ne!(old_identity, identity);
                assert_eq!(old_identity & 255, identity & 255);
                assert_eq!(
                    a.authorize(owner, old_handle, Kind::Endpoint, Rights::SEND)
                        .err(),
                    Some(Error::InvalidHandle)
                );
            }
            let delegated = a
                .derive(owner, handle, receiver, Rights::SEND | Rights::TRANSFER)
                .unwrap();
            let moved = a.transfer(receiver, delegated, escrow).unwrap();
            a.destroy(owner, handle).unwrap();
            assert_eq!(
                a.authorize(escrow, moved, Kind::Endpoint, Rights::SEND)
                    .err(),
                Some(Error::DeadObject)
            );
            a.close(owner, handle).unwrap();
            a.close(escrow, moved).unwrap();
            assert_eq!(a.collect_dead_objects(), Ok(0));
            assert_eq!(a.collect_lineage(), Ok(2));
            assert_eq!(a.collect_dead_objects(), Ok(1));
            assert_eq!(a.objects.iter().flatten().count(), 2);
            assert_eq!(a.nodes.iter().flatten().count(), 2);
            assert!(a.authorize(owner, job, Kind::Job, Rights::CONTROL).is_ok());
            assert!(a.authorize(owner, peer, Kind::Memory, Rights::READ).is_ok());
            previous = Some((handle, identity));
        }
    }
    #[test]
    fn object_generation_exhaustion_and_late_allocation_failure_are_atomic() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        a.object_generations[0] = MAX_OBJECT_GENERATION - 1;
        let last = a
            .create_root(owner, Kind::Memory, Rights::READ | Rights::CONTROL)
            .unwrap();
        assert_eq!(
            a.authorize(owner, last, Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
            usize::MAX & !255
        );
        a.destroy(owner, last).unwrap();
        a.close(owner, last).unwrap();
        assert_eq!(a.collect_lineage(), Ok(1));
        assert_eq!(a.collect_dead_objects(), Ok(1));
        let before = a.staged_copy();
        assert_eq!(
            a.create_root(owner, Kind::Endpoint, Rights::SEND),
            Err(Error::GenerationExhausted)
        );
        unchanged(&a, &before);
        for managed in [false, true] {
            let (mut a, owner, job) = creator();
            a.object_generations[1] = 7;
            let first = a.nodes[0];
            a.nodes.fill(first);
            let before = a.staged_copy();
            let result = if managed {
                a.create_managed(owner, job, Kind::Endpoint, Rights::SEND)
            } else {
                a.create_root(owner, Kind::Endpoint, Rights::SEND)
            };
            assert_eq!(result, Err(Error::Capacity));
            unchanged(&a, &before);
            a.nodes[1] = None;
            a.object_generations[1] = MAX_OBJECT_GENERATION;
            let before = a.staged_copy();
            let result = if managed {
                a.create_managed(owner, job, Kind::Endpoint, Rights::SEND)
            } else {
                a.create_root(owner, Kind::Endpoint, Rights::SEND)
            };
            assert_eq!(result, Err(Error::GenerationExhausted));
            unchanged(&a, &before);
        }
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        a.object_generations[0] = usize::MAX;
        let before = a.staged_copy();
        assert_eq!(
            a.create_root(owner, Kind::Memory, Rights::READ),
            Err(Error::GenerationExhausted)
        );
        unchanged(&a, &before);
    }
    #[test]
    fn object_collection_preflight_rejects_corruption_without_partial_collection() {
        for corruption in 0..6 {
            let mut a = Authority::new();
            let owner = a.create_space().unwrap();
            let dead = a.create_root(owner, Kind::Memory, Rights::CONTROL).unwrap();
            a.destroy(owner, dead).unwrap();
            a.close(owner, dead).unwrap();
            assert_eq!(a.collect_lineage(), Ok(1));
            let live = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
            let (_, live_node) = a.locate(owner, live).unwrap();
            match corruption {
                0 => a.nodes[live_node].as_mut().unwrap().object = MAX_OBJECTS,
                1 => a.nodes[live_node].as_mut().unwrap().object = MAX_OBJECTS - 1,
                2 => a.object_generations[1] = 0,
                3 => a.object_generations[0] = 0,
                4 => {
                    a.nodes[live_node].as_mut().unwrap().parent =
                        Some(NodeIndex(NonZeroU16::new(MAX_NODES as u16 + 1).unwrap()))
                }
                _ => a.nodes[live_node].as_mut().unwrap().parent = Some(node_index(live_node)),
            }
            let before = a.staged_copy();
            assert_eq!(
                a.collect_dead_objects(),
                Err(if corruption < 4 {
                    Error::DeadObject
                } else {
                    Error::Revoked
                })
            );
            unchanged(&a, &before);
        }
    }
    #[test]
    fn stale_mailbox_and_rpc_routes_cannot_bind_a_replacement_endpoint_by_slot() {
        use crate::{
            ipc::{Error as IpcError, Mailbox, Outgoing},
            rpc::{Error as RpcError, MessageShape, Policy, Rpc},
            scheduler::Scheduler,
            time::Deadline,
        };
        use core::num::NonZeroU64;
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let old = a
            .create_root(owner, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let cached = a
            .authorize(owner, old, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity();
        let mut mailbox = Mailbox::new(&mut a, owner, old).unwrap();
        let mut scheduler = Scheduler::new();
        let job = scheduler.create_job().unwrap();
        let process = scheduler.create_process(job).unwrap();
        let caller = scheduler.create_thread(process).unwrap();
        let callee = scheduler.create_thread(process).unwrap();
        let mut rpc = Rpc::new(NonZeroU64::new(27).unwrap());
        for thread in [caller, callee] {
            rpc.register_thread(&a, &scheduler, thread, job, owner, None)
                .unwrap();
        }
        rpc.bind_endpoint(&a, owner, old, callee, Policy::new(8, 0).unwrap())
            .unwrap();
        a.destroy(owner, old).unwrap();
        a.close(owner, old).unwrap();
        assert_eq!(a.collect_lineage(), Ok(1));
        assert_eq!(a.collect_dead_objects(), Ok(1));
        let replacement = a
            .create_root(owner, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let current = a
            .authorize(owner, replacement, Kind::Endpoint, Rights::SEND)
            .unwrap()
            .identity();
        assert_eq!(cached & 255, current & 255);
        assert_ne!(cached, current);
        let deadline = Deadline::after(0, 10).unwrap();
        assert_eq!(
            mailbox.send(
                &mut a,
                owner,
                replacement,
                Outgoing {
                    bytes: b"new",
                    capability: None,
                    deadline,
                },
                0
            ),
            Err(IpcError::WrongEndpoint)
        );
        assert_eq!(
            mailbox.receive(&mut a, owner, replacement, 0),
            Err(IpcError::WrongEndpoint)
        );
        assert_eq!(
            rpc.begin(
                &a,
                caller,
                replacement,
                deadline,
                MessageShape {
                    bytes: 8,
                    capabilities: 0
                },
                0
            ),
            Err(RpcError::UnknownEndpoint)
        );
        assert_eq!(rpc.outstanding(), 0);
        rpc.bind_endpoint(&a, owner, replacement, callee, Policy::new(8, 0).unwrap())
            .unwrap();
        let call = rpc
            .begin(
                &a,
                caller,
                replacement,
                deadline,
                MessageShape {
                    bytes: 8,
                    capabilities: 0,
                },
                0,
            )
            .unwrap();
        assert!(rpc.complete(callee, call, 1).unwrap().deliver_reply);
        mailbox.receiver_died(owner).unwrap();
        mailbox.retire_empty(&mut a).unwrap();
    }
    #[test]
    fn stale_memory_backend_and_mapping_lease_cannot_alias_a_replacement_descriptor() {
        use crate::{
            memory::BootstrapFrames,
            memory_object::{Error as MemoryError, MemoryObject},
        };
        use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
        let mut frames = BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: 4096,
                end: 65536,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        );
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let (mut old, old_cap) =
            MemoryObject::new(&mut a, owner, frames.allocate().unwrap()).unwrap();
        let old_lease = old.map(&a, owner, old_cap, false).unwrap();
        let cached = a
            .authorize(owner, old_cap, Kind::Memory, Rights::READ)
            .unwrap()
            .identity();
        // Adversarial stale-cache model only: physical frames and the old lease
        // remain retained. No hardware mapping/backing is removed or recycled,
        // and descriptor collection alone must never imply those operations.
        a.destroy(owner, old_cap).unwrap();
        a.close(owner, old_cap).unwrap();
        assert_eq!(a.collect_lineage(), Ok(1));
        assert_eq!(a.collect_dead_objects(), Ok(1));
        let (mut replacement, cap) =
            MemoryObject::new(&mut a, owner, frames.allocate().unwrap()).unwrap();
        let current = a
            .authorize(owner, cap, Kind::Memory, Rights::READ)
            .unwrap()
            .identity();
        assert_eq!(cached & 255, current & 255);
        assert_ne!(cached, current);
        assert!(old.owns_mapping(&old_lease));
        assert!(!replacement.owns_mapping(&old_lease));
        assert_eq!(
            replacement.validate_mapping(&a, &old_lease),
            Err(MemoryError::WrongObject)
        );
        assert_eq!(
            old.map(&a, owner, cap, false).err(),
            Some(MemoryError::WrongObject)
        );
        let (error, old_lease) = replacement.unmap(old_lease).unwrap_err();
        assert_eq!(error, MemoryError::WrongObject);
        old.unmap(old_lease).unwrap();
        // Metadata collection has not returned or recycled either backing frame.
        assert_eq!(frames.total_frames() - frames.remaining_frames(), 2);
        let lease = replacement.map(&a, owner, cap, false).unwrap();
        assert_eq!(replacement.validate_mapping(&a, &lease), Ok(()));
        replacement.unmap(lease).unwrap();
    }
    #[test]
    fn managed_creation_requires_live_job_control_and_supported_exact_rights() {
        let (mut a, owner, job) = creator();
        let other = a.create_space().unwrap();
        let weak = a.derive(owner, job, owner, Rights::READ).unwrap();
        let wrong = a
            .create_root(owner, Kind::Process, Rights::CONTROL)
            .unwrap();
        for (space, source, kind, rights, expected) in [
            (
                other,
                job,
                Kind::Endpoint,
                Rights::SEND,
                Error::InvalidHandle,
            ),
            (
                owner,
                Handle(u64::MAX),
                Kind::Endpoint,
                Rights::SEND,
                Error::InvalidHandle,
            ),
            (owner, weak, Kind::Endpoint, Rights::SEND, Error::Denied),
            (owner, wrong, Kind::Endpoint, Rights::SEND, Error::WrongKind),
            (owner, job, Kind::Memory, Rights::READ, Error::Denied),
            (owner, job, Kind::Thread, Rights::READ, Error::Denied),
            (owner, job, Kind::Process, Rights::SEND, Error::Denied),
            (owner, job, Kind::Endpoint, Rights::READ, Error::Denied),
            (owner, job, Kind::Job, Rights(0), Error::Denied),
            (owner, job, Kind::Job, Rights(512), Error::Denied),
        ] {
            let before = a.staged_copy();
            assert_eq!(a.create_managed(space, source, kind, rights), Err(expected));
            unchanged(&a, &before);
        }
        // CONTROL explicitly permits supported object creation; it does not
        // grant a right to move or amplify ordinary existing-object grants.
        let control = a.derive(owner, job, owner, Rights::CONTROL).unwrap();
        let endpoint = a
            .create_managed(owner, control, Kind::Endpoint, Rights::SEND)
            .unwrap();
        assert!(
            a.authorize(owner, endpoint, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(a.transfer(owner, endpoint, other), Err(Error::Denied));
        assert_eq!(
            a.derive(owner, endpoint, other, Rights::SEND),
            Err(Error::Denied)
        );
        assert_eq!(
            a.derive(owner, control, owner, Rights::SEND),
            Err(Error::Denied)
        );
    }
    #[test]
    fn managed_creation_ancestry_survives_delegation_transfer_and_collection() {
        let (mut a, owner, job) = creator();
        let receiver = a.create_space().unwrap();
        let final_owner = a.create_space().unwrap();
        let peer = a.create_root(owner, Kind::Endpoint, Rights::SEND).unwrap();
        let child = a
            .create_managed(owner, job, Kind::Job, Kind::Job.allowed())
            .unwrap();
        let endpoint = a
            .create_managed(owner, child, Kind::Endpoint, Kind::Endpoint.allowed())
            .unwrap();
        let process = a
            .create_managed(owner, child, Kind::Process, Rights::READ)
            .unwrap();
        let delegated = a
            .derive(owner, endpoint, receiver, Rights::SEND | Rights::TRANSFER)
            .unwrap();
        let moved = a.transfer(receiver, delegated, final_owner).unwrap();
        let root_identity = a
            .authorize(owner, job, Kind::Job, Rights::CONTROL)
            .unwrap()
            .lineage_root();
        let access = a
            .authorize(final_owner, moved, Kind::Endpoint, Rights::SEND)
            .unwrap();
        assert_eq!(access.lineage_root(), root_identity);
        assert!(!access.is_root());
        assert_ne!(
            access.identity(),
            a.authorize(owner, job, Kind::Job, Rights::CONTROL)
                .unwrap()
                .identity()
        );
        a.close(owner, child).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        assert!(
            a.authorize(owner, process, Kind::Process, Rights::READ)
                .is_ok()
        );
        a.revoke(owner, job).unwrap();
        for (space, handle, kind, rights) in [
            (owner, endpoint, Kind::Endpoint, Rights::SEND),
            (owner, process, Kind::Process, Rights::READ),
            (final_owner, moved, Kind::Endpoint, Rights::SEND),
        ] {
            assert_eq!(
                a.authorize(space, handle, kind, rights).err(),
                Some(Error::Revoked)
            );
        }
        assert!(
            a.authorize(owner, peer, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(
            a.create_managed(owner, job, Kind::Process, Rights::READ),
            Err(Error::Revoked)
        );
    }
    #[test]
    fn destroying_creator_object_invalidates_distinct_managed_descendants() {
        let (mut a, owner, job) = creator();
        let receiver = a.create_space().unwrap();
        let child = a
            .create_managed(owner, job, Kind::Job, Kind::Job.allowed())
            .unwrap();
        let process = a
            .create_managed(owner, child, Kind::Process, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let moved = a.transfer(owner, process, receiver).unwrap();
        a.destroy(owner, child).unwrap();
        assert_eq!(
            a.authorize(receiver, moved, Kind::Process, Rights::READ)
                .err(),
            Some(Error::DeadObject)
        );
        assert_eq!(
            a.create_managed(owner, child, Kind::Endpoint, Rights::SEND),
            Err(Error::DeadObject)
        );
        // Siblings under the still-live Job are unaffected by child destruction.
        let sibling = a
            .create_managed(owner, job, Kind::Process, Rights::READ)
            .unwrap();
        assert!(
            a.authorize(owner, sibling, Kind::Process, Rights::READ)
                .is_ok()
        );
        a.destroy(owner, job).unwrap();
        assert_eq!(
            a.authorize(owner, sibling, Kind::Process, Rights::READ)
                .err(),
            Some(Error::DeadObject)
        );
    }
    #[test]
    fn managed_creation_preflights_slots_generations_objects_and_last_node() {
        for exhausted in 0..4 {
            let (mut a, owner, job) = creator();
            match exhausted {
                0 => {
                    for _ in 1..MAX_CAPS {
                        a.derive(owner, job, owner, Rights::READ).unwrap();
                    }
                }
                1 => a.slots[owner.0][1].generation = MAX_GENERATION,
                2 => {
                    let first = a.objects[0];
                    a.objects.fill(first);
                }
                _ => {
                    let first = a.nodes[0];
                    a.nodes.fill(first);
                }
            }
            let before = a.staged_copy();
            assert_eq!(
                a.create_managed(owner, job, Kind::Endpoint, Rights::SEND),
                Err(if exhausted == 1 {
                    Error::GenerationExhausted
                } else {
                    Error::Capacity
                })
            );
            unchanged(&a, &before);
            assert!(a.authorize(owner, job, Kind::Job, Rights::CONTROL).is_ok());
        }
    }
    #[test]
    fn managed_metadata_staging_is_isolated_until_trusted_commit() {
        let (a, owner, job) = creator();
        let mut staged = a.staged_copy();
        let endpoint = staged
            .create_managed(owner, job, Kind::Endpoint, Rights::SEND)
            .unwrap();
        assert_eq!(
            a.authorize(owner, endpoint, Kind::Endpoint, Rights::SEND)
                .err(),
            Some(Error::InvalidHandle)
        );
        assert!(
            staged
                .authorize(owner, endpoint, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(a.objects.iter().flatten().count(), 1);
        assert_eq!(staged.objects.iter().flatten().count(), 2);
    }
    fn setup() -> (Authority, SpaceId, SpaceId, Handle) {
        let mut a = Authority::new();
        let s = a.create_space().unwrap();
        let d = a.create_space().unwrap();
        let h = a
            .create_root(s, Kind::Memory, Kind::Memory.allowed())
            .unwrap();
        (a, s, d, h)
    }
    fn error(a: &Authority, s: SpaceId, h: Handle, kind: Kind, rights: Rights) -> Option<Error> {
        a.authorize(s, h, kind, rights).err()
    }
    #[test]
    fn scoped_grants_revoke_delegated_and_moved_descendants_but_preserve_roots_and_peers() {
        let (mut a, s, d, root) = setup();
        let branches = a.create_space().unwrap();
        let service = a.create_space().unwrap();
        let peer = a.derive(s, root, service, Rights::READ).unwrap();
        let requests = [Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ | Rights::DERIVE | Rights::TRANSFER,
        }; 2];
        let batch = a
            .derive_scoped_into_empty(s, branches, d, &requests)
            .unwrap();
        let delegated = a
            .derive(d, batch.grants.handles()[0], service, Rights::READ)
            .unwrap();
        let moved = a.transfer(d, batch.grants.handles()[1], service).unwrap();
        a.close_space(d).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        a.revoke_batch(branches, batch.branches.handles()).unwrap();
        a.revoke_batch(branches, batch.branches.handles()).unwrap();
        for h in [delegated, moved] {
            assert_eq!(
                error(&a, service, h, Kind::Memory, Rights::READ),
                Some(Error::Revoked)
            );
        }
        assert!(
            a.authorize(service, peer, Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert!(a.derive(s, root, service, Rights::READ).is_ok());
        assert_eq!(
            a.derive(service, moved, service, Rights::READ),
            Err(Error::Revoked)
        );
    }
    #[test]
    fn scoped_transaction_preflights_both_tables_and_all_node_capacity() {
        let (mut a, s, d, root) = setup();
        let branches = a.create_space().unwrap();
        let requests = [Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ,
        }; 2];
        a.slots[branches.0][1].generation = MAX_GENERATION;
        assert!(matches!(
            a.derive_scoped_into_empty(s, branches, d, &requests),
            Err(Error::GenerationExhausted)
        ));
        assert!(
            a.slots[d.0]
                .iter()
                .all(|s| s.node.is_none() && s.generation == 0)
        );
        assert!(a.slots[branches.0].iter().all(|s| s.node.is_none()));
        a.slots[branches.0][1].generation = 0;
        // Three vacant nodes: a two-grant direct batch would fit, a scoped one must fail.
        for i in 1..MAX_NODES - 3 {
            a.nodes[i] = a.nodes[0];
        }
        assert!(matches!(
            a.derive_scoped_into_empty(s, branches, d, &requests),
            Err(Error::Capacity)
        ));
        assert!(
            a.slots
                .iter()
                .skip(1)
                .flatten()
                .all(|s| s.node.is_none() && s.generation == 0)
        );
        assert_eq!(a.collect_lineage(), Ok(MAX_NODES - 4));
        assert!(
            a.derive_scoped_into_empty(s, branches, d, &requests)
                .is_ok()
        );
    }
    #[test]
    fn scoped_transaction_denies_missing_revoke_and_domain_aliases_without_mutation() {
        let (mut a, s, d, root) = setup();
        let branches = a.create_space().unwrap();
        let weak = a
            .create_root(
                s,
                Kind::Endpoint,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let first = Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ,
        };
        let last = Derivation {
            source: weak,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        };
        assert!(matches!(
            a.derive_scoped_into_empty(s, branches, d, &[first, last]),
            Err(Error::Denied)
        ));
        for b in [s, d] {
            assert!(matches!(
                a.derive_scoped_into_empty(s, b, d, &[first]),
                Err(Error::DestinationNotEmpty)
            ));
        }
        let batch = a
            .derive_scoped_into_empty(s, branches, d, &[first])
            .unwrap();
        for right in [Rights::DERIVE, Rights::TRANSFER, Rights::REVOKE] {
            assert_eq!(
                error(&a, d, batch.grants.handles()[0], Kind::Memory, right),
                Some(Error::Denied)
            );
        }
    }
    #[test]
    fn batch_revocation_is_atomic_on_late_invalid_or_unprivileged_handles() {
        let (mut a, s, d, root) = setup();
        let good = a.derive(s, root, d, Rights::READ | Rights::REVOKE).unwrap();
        let weak = a.derive(s, root, d, Rights::READ).unwrap();
        for (bad, expected) in [(Handle(0), Error::InvalidHandle), (weak, Error::Denied)] {
            assert_eq!(a.revoke_batch(d, &[good, bad]), Err(expected));
            assert!(a.authorize(d, good, Kind::Memory, Rights::READ).is_ok());
        }
        a.revoke(s, root).unwrap();
        // Repeating teardown after a separate ancestor revocation must still succeed.
        assert_eq!(a.revoke_batch(d, &[good, good]), Ok(()));
        assert_eq!(a.revoke_batch(d, &[]), Err(Error::Capacity));
        assert_eq!(
            a.revoke_batch(d, &[good; MAX_CAPS + 1]),
            Err(Error::Capacity)
        );
    }
    #[test]
    fn private_branches_pin_lineage_and_stale_teardown_cannot_revoke_replacement() {
        let (mut a, s, mut d, root) = setup();
        let mut branches = a.create_space().unwrap();
        let request = Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ,
        };
        let mut stale = None;
        for _ in 0..512 {
            let batch = a
                .derive_scoped_into_empty(s, branches, d, &[request])
                .unwrap();
            if let Some((old_space, old_handle)) = stale {
                assert_eq!(
                    a.revoke_batch(old_space, batch.branches.handles()),
                    Err(Error::InvalidSpace)
                );
                assert_eq!(
                    a.revoke_batch(branches, &[old_handle]),
                    Err(Error::InvalidHandle)
                );
                assert!(
                    a.authorize(d, batch.grants.handles()[0], Kind::Memory, Rights::READ)
                        .is_ok()
                );
            }
            stale = Some((branches, batch.branches.handles()[0]));
            a.close_space(d).unwrap();
            assert_eq!(a.collect_lineage(), Ok(1));
            // Private branch remains pinned even after every user handle disappears.
            assert_eq!(a.revoke_batch(branches, batch.branches.handles()), Ok(()));
            a.close_space(branches).unwrap();
            assert_eq!(a.collect_lineage(), Ok(1));
            d = a.recycle_space(d).unwrap();
            branches = a.recycle_space(branches).unwrap();
        }
    }
    #[test]
    fn explicit_domain_reuse_rejects_old_ids_and_handles() {
        let (mut a, s, d, root) = setup();
        assert_eq!(a.recycle_space(d), Err(Error::SpaceBusy));
        let old = a.derive(s, root, d, Rights::READ).unwrap();
        a.close_space(d).unwrap();
        let next = a.recycle_space(d).unwrap();
        assert_ne!(d, next);
        assert_eq!(d.0, next.0);
        let new = a.derive(s, root, next, Rights::READ).unwrap();
        assert_ne!(old, new);
        assert_eq!(a.close_space(d), Err(Error::InvalidSpace));
        assert_eq!(a.recycle_space(d), Err(Error::InvalidSpace));
        assert_eq!(
            error(&a, d, new, Kind::Memory, Rights::READ),
            Some(Error::InvalidSpace)
        );
        assert_eq!(
            error(&a, next, old, Kind::Memory, Rights::READ),
            Some(Error::InvalidHandle)
        );
        assert!(a.authorize(next, new, Kind::Memory, Rights::READ).is_ok());
    }
    #[test]
    fn domain_generation_exhaustion_keeps_the_retired_slot_closed() {
        let (mut a, _, d, _) = setup();
        a.space_generations[d.0] = u64::MAX;
        let last = SpaceId(d.0, u64::MAX);
        a.close_space(last).unwrap();
        assert_eq!(a.recycle_space(last), Err(Error::GenerationExhausted));
        assert!(!a.is_live_space(last));
        assert_eq!(a.space_generations[d.0], u64::MAX);
    }
    #[test]
    fn collection_preserves_closed_ancestor_and_revocation_until_last_leaf_closes() {
        let (mut a, s, d, root) = setup();
        let branch = a.derive(s, root, d, Rights::READ | Rights::DERIVE).unwrap();
        let leaf = a.derive(d, branch, d, Rights::READ).unwrap();
        a.close(d, branch).unwrap();
        assert_eq!(a.collect_lineage(), Ok(0));
        a.revoke(s, root).unwrap();
        assert_eq!(
            error(&a, d, leaf, Kind::Memory, Rights::READ),
            Some(Error::Revoked)
        );
        a.close(d, leaf).unwrap();
        assert_eq!(a.collect_lineage(), Ok(2));
        assert_eq!(a.nodes.iter().flatten().count(), 1);
        a.close(s, root).unwrap();
        assert_eq!(a.collect_lineage(), Ok(1));
        assert_eq!(a.objects.iter().flatten().count(), 1);
    }
    #[test]
    fn repeated_batch_reuse_exceeds_both_original_capacity_limits() {
        let (mut a, s, mut d, root) = setup();
        let request = Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ,
        };
        for _ in 0..512 {
            let batch = a.derive_into_empty(s, d, &[request; 2]).unwrap();
            let stale = batch.handles()[0];
            let old = d;
            a.close_space(d).unwrap();
            assert_eq!(a.collect_lineage(), Ok(2));
            d = a.recycle_space(d).unwrap();
            assert_eq!(
                error(&a, old, stale, Kind::Memory, Rights::READ),
                Some(Error::InvalidSpace)
            );
            assert_eq!(
                error(&a, d, stale, Kind::Memory, Rights::READ),
                Some(Error::InvalidHandle)
            );
            assert_eq!(a.nodes.iter().flatten().count(), 1);
        }
    }
    #[test]
    fn corrupt_reachable_lineage_is_rejected_before_collection_mutates_anything() {
        let (mut a, s, d, root) = setup();
        let unused = a.derive(s, root, d, Rights::READ).unwrap();
        a.close(d, unused).unwrap();
        let (_, root_node) = a.locate(s, root).unwrap();
        a.nodes[root_node].as_mut().unwrap().parent = Some(node_index(root_node));
        assert_eq!(a.collect_lineage(), Err(Error::Revoked));
        assert_eq!(a.nodes.iter().flatten().count(), 2);
    }
    #[test]
    fn batch_late_failure_leaves_no_grant_or_metadata_and_can_retry() {
        let (mut a, s, d, root) = setup();
        let endpoint = a
            .create_root(
                s,
                Kind::Endpoint,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )
            .unwrap();
        let mut requests = [
            Derivation {
                source: root,
                kind: Kind::Memory,
                rights: Rights::READ,
            },
            Derivation {
                source: endpoint,
                kind: Kind::Endpoint,
                rights: Rights::RECEIVE,
            },
        ];
        let before = a.nodes.iter().flatten().count();
        assert_eq!(
            a.derive_into_empty(s, d, &requests).err(),
            Some(Error::Denied)
        );
        assert_eq!(a.nodes.iter().flatten().count(), before);
        assert!(
            a.slots[d.0]
                .iter()
                .all(|s| s.node.is_none() && s.generation == 0)
        );
        requests[1].rights = Rights::SEND;
        let batch = a.derive_into_empty(s, d, &requests).unwrap();
        assert_eq!(batch.handles().len(), 2);
        assert!(
            a.authorize(d, batch.handles()[0], Kind::Memory, Rights::READ)
                .is_ok()
        );
        assert!(
            a.authorize(d, batch.handles()[1], Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
        assert_eq!(
            a.derive_into_empty(s, d, &requests).err(),
            Some(Error::DestinationNotEmpty)
        );
        assert_eq!(a.nodes.iter().flatten().count(), before + 2);
    }
    #[test]
    fn batch_generation_and_node_exhaustion_are_atomic() {
        let (mut a, s, d, root) = setup();
        let request = Derivation {
            source: root,
            kind: Kind::Memory,
            rights: Rights::READ,
        };
        a.slots[d.0][1].generation = MAX_GENERATION;
        assert_eq!(
            a.derive_into_empty(s, d, &[request; 2]).err(),
            Some(Error::GenerationExhausted)
        );
        assert_eq!(a.nodes.iter().flatten().count(), 1);
        assert!(a.slots[d.0].iter().all(|s| s.node.is_none()));
        a.slots[d.0][1].generation = 0;
        for _ in 1..MAX_NODES - 1 {
            let h = a.derive(s, root, s, Rights::READ).unwrap();
            a.close(s, h).unwrap();
        }
        let before = a.nodes.iter().flatten().count();
        assert_eq!(
            a.derive_into_empty(s, d, &[request; 2]).err(),
            Some(Error::Capacity)
        );
        assert_eq!(a.nodes.iter().flatten().count(), before);
        assert!(a.slots[d.0].iter().all(|s| s.node.is_none()));
        assert!(a.derive_into_empty(s, d, &[request]).is_ok());
    }
    #[test]
    fn batch_rejects_wrong_kind_closed_destination_empty_and_oversized_requests() {
        let (mut a, s, d, root) = setup();
        let mut request = Derivation {
            source: root,
            kind: Kind::Endpoint,
            rights: Rights::READ,
        };
        assert_eq!(
            a.derive_into_empty(s, d, &[request]).err(),
            Some(Error::WrongKind)
        );
        request.kind = Kind::Memory;
        assert_eq!(a.derive_into_empty(s, d, &[]).err(), Some(Error::Capacity));
        assert_eq!(
            a.derive_into_empty(s, d, &[request; MAX_CAPS + 1]).err(),
            Some(Error::Capacity)
        );
        assert_eq!(
            a.derive_into_empty(s, s, &[request]).err(),
            Some(Error::DestinationNotEmpty)
        );
        a.close_space(d).unwrap();
        assert_eq!(
            a.derive_into_empty(s, d, &[request]).err(),
            Some(Error::InvalidSpace)
        );
        assert_eq!(a.nodes.iter().flatten().count(), 1);
    }
    #[test]
    fn diagnostic_lineage_root_tracks_ancestry_without_granting_authority() {
        let (mut a, s, d, root) = setup();
        let child = a.derive(s, root, d, Rights::READ | Rights::DERIVE).unwrap();
        let grandchild = a.derive(d, child, d, Rights::READ).unwrap();
        let root_access = a.authorize(s, root, Kind::Memory, Rights::READ).unwrap();
        let child_access = a
            .authorize(d, grandchild, Kind::Memory, Rights::READ)
            .unwrap();
        assert!(root_access.is_root());
        assert!(!child_access.is_root());
        assert_eq!(root_access.lineage_root(), child_access.lineage_root());
        assert_eq!(root_access.identity(), child_access.identity());
    }
    #[test]
    fn closed_domain_loses_local_handles_but_transferred_descendants_survive() {
        let (mut a, s, d, root) = setup();
        let derived = a
            .derive(s, root, s, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let moved = a.transfer(s, derived, d).unwrap();
        assert_eq!(a.close_space(s), Ok(1));
        assert!(!a.is_live_space(s));
        assert_eq!(
            error(&a, s, root, Kind::Memory, Rights::READ),
            Some(Error::InvalidSpace)
        );
        assert!(a.authorize(d, moved, Kind::Memory, Rights::READ).is_ok());
        assert_eq!(a.transfer(d, moved, s), Err(Error::InvalidSpace));
        assert_eq!(
            a.create_root(s, Kind::Memory, Rights::READ),
            Err(Error::InvalidSpace)
        );
        assert_eq!(a.close_space(s), Ok(0));
        assert_ne!(a.create_space().unwrap(), s);
        assert_eq!(
            a.close_space(SpaceId(usize::MAX, 0)),
            Err(Error::InvalidSpace)
        );
    }
    #[test]
    fn owner_table_generation_kind_and_rights_are_all_required() {
        let (mut a, s, d, h) = setup();
        assert_eq!(
            error(&a, d, h, Kind::Memory, Rights::READ),
            Some(Error::InvalidHandle)
        );
        assert_eq!(
            error(&a, s, Handle(u64::MAX), Kind::Memory, Rights::READ),
            Some(Error::InvalidHandle)
        );
        assert_eq!(
            error(&a, s, h, Kind::Endpoint, Rights::SEND),
            Some(Error::WrongKind)
        );
        let read = a.derive(s, h, d, Rights::READ).unwrap();
        assert_eq!(
            error(&a, d, read, Kind::Memory, Rights::WRITE),
            Some(Error::Denied)
        );
        assert_eq!(a.derive(d, read, s, Rights::READ), Err(Error::Denied));
        assert_eq!(a.derive(s, h, d, Rights::SEND), Err(Error::Denied));
        assert!(Rights::from_bits(512).is_none());
    }
    #[test]
    fn attenuation_and_cross_domain_transfer_authority_are_independent() {
        let (mut a, s, d, h) = setup();
        let local = a.derive(s, h, s, Rights::READ | Rights::DERIVE).unwrap();
        assert!(a.derive(s, local, s, Rights::READ).is_ok());
        assert_eq!(a.derive(s, local, d, Rights::READ), Err(Error::Denied));
        assert_eq!(a.transfer(s, local, d), Err(Error::Denied));
        assert_eq!(a.revoke(s, local), Err(Error::Denied));
        assert_eq!(a.destroy(s, local), Err(Error::Denied));
    }
    #[test]
    fn revocation_reaches_closed_intermediates_without_affecting_siblings() {
        let (mut a, s, d, h) = setup();
        let middle = a
            .derive(s, h, d, Rights::READ | Rights::DERIVE | Rights::REVOKE)
            .unwrap();
        let leaf = a.derive(d, middle, d, Rights::READ).unwrap();
        let sibling = a.derive(s, h, d, Rights::READ).unwrap();
        a.revoke(d, middle).unwrap();
        assert_eq!(
            error(&a, d, leaf, Kind::Memory, Rights::READ),
            Some(Error::Revoked)
        );
        assert!(a.authorize(d, sibling, Kind::Memory, Rights::READ).is_ok());
        a.close(d, middle).unwrap();
        a.revoke(s, h).unwrap();
        assert_eq!(
            error(&a, d, sibling, Kind::Memory, Rights::READ),
            Some(Error::Revoked)
        );
        assert_eq!(a.derive(s, h, d, Rights::READ), Err(Error::Revoked));
    }
    #[test]
    fn closing_live_intermediate_retains_ancestry_and_slot_reuse_rejects_stale_handle() {
        let (mut a, s, d, h) = setup();
        let middle = a.derive(s, h, d, Rights::READ | Rights::DERIVE).unwrap();
        let leaf = a.derive(d, middle, d, Rights::READ).unwrap();
        a.close(d, middle).unwrap();
        let replacement = a.derive(s, h, d, Rights::READ).unwrap();
        assert_ne!(middle, replacement);
        assert_eq!(
            error(&a, d, middle, Kind::Memory, Rights::READ),
            Some(Error::InvalidHandle)
        );
        assert!(a.authorize(d, leaf, Kind::Memory, Rights::READ).is_ok());
        a.revoke(s, h).unwrap();
        assert_eq!(
            error(&a, d, leaf, Kind::Memory, Rights::READ),
            Some(Error::Revoked)
        );
    }
    #[test]
    fn transfer_is_atomic_and_keeps_lineage() {
        let (mut a, s, d, h) = setup();
        let grant = a.derive(s, h, s, Rights::READ | Rights::TRANSFER).unwrap();
        let moved = a.transfer(s, grant, d).unwrap();
        assert_eq!(
            error(&a, s, grant, Kind::Memory, Rights::READ),
            Some(Error::InvalidHandle)
        );
        assert_eq!(
            a.authorize(d, moved, Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
            a.authorize(s, h, Kind::Memory, Rights::READ)
                .unwrap()
                .identity()
        );
        a.revoke(s, h).unwrap();
        assert_eq!(
            error(&a, d, moved, Kind::Memory, Rights::READ),
            Some(Error::Revoked)
        );
    }
    #[test]
    fn full_destination_never_strands_or_duplicates_source_authority() {
        let (mut a, s, d, h) = setup();
        for _ in 0..MAX_CAPS {
            a.derive(s, h, d, Rights::READ).unwrap();
        }
        assert_eq!(a.transfer(s, h, d), Err(Error::Capacity));
        assert!(a.authorize(s, h, Kind::Memory, Rights::READ).is_ok());
        let nodes = a.nodes.iter().flatten().count();
        assert_eq!(a.derive(s, h, d, Rights::READ), Err(Error::Capacity));
        assert_eq!(a.nodes.iter().flatten().count(), nodes);
    }
    #[test]
    fn dead_objects_and_generation_exhaustion_never_restore_authority() {
        let (mut a, s, d, h) = setup();
        let leaf = a.derive(s, h, d, Rights::READ).unwrap();
        a.destroy(s, h).unwrap();
        assert_eq!(
            error(&a, d, leaf, Kind::Memory, Rights::READ),
            Some(Error::DeadObject)
        );
        a.close(d, leaf).unwrap();
        a.slots[d.0][0].generation = MAX_GENERATION;
        assert_eq!(
            a.create_root(d, Kind::Endpoint, Rights::SEND),
            Err(Error::GenerationExhausted)
        );
        assert_eq!(a.objects.iter().flatten().count(), 1);
    }
    #[test]
    fn retained_lineage_capacity_and_invalid_domains_fail_without_mutation() {
        let (mut a, s, d, h) = setup();
        for _ in 1..MAX_NODES {
            let cap = a.derive(s, h, d, Rights::READ).unwrap();
            a.close(d, cap).unwrap();
        }
        assert_eq!(a.derive(s, h, d, Rights::READ), Err(Error::Capacity));
        assert_eq!(
            a.transfer(s, h, SpaceId(usize::MAX, 0)),
            Err(Error::InvalidSpace)
        );
        assert!(a.authorize(s, h, Kind::Memory, Rights::READ).is_ok());
    }
}

#[cfg(test)]
mod mutex_kind_tests {
    use super::*;
    #[test]
    fn managed_mutex_is_creator_scoped_and_has_no_memory_or_endpoint_rights() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let creator = a
            .create_root(owner, Kind::Job, Rights::CONTROL | Rights::REVOKE)
            .unwrap();
        for right in [
            Rights::READ,
            Rights::WRITE,
            Rights::MAP,
            Rights::SEND,
            Rights::RECEIVE,
        ] {
            assert!(!Kind::Mutex.permits(right));
            assert_eq!(
                a.create_managed(owner, creator, Kind::Mutex, right),
                Err(Error::Denied)
            );
        }
        let mutex = a
            .create_managed(owner, creator, Kind::Mutex, Rights::CONTROL)
            .unwrap();
        assert!(
            a.authorize(owner, mutex, Kind::Mutex, Rights::CONTROL)
                .is_ok()
        );
        a.revoke(owner, creator).unwrap();
        assert_eq!(
            a.authorize(owner, mutex, Kind::Mutex, Rights::CONTROL)
                .err(),
            Some(Error::Revoked)
        );
    }
}

#[cfg(test)]
mod io_ports_kind_tests {
    use super::*;
    #[test]
    fn io_ports_have_no_memory_map_or_endpoint_rights_and_job_control_cannot_mint_hardware() {
        assert!(Kind::IoPorts.permits(Rights::READ | Rights::WRITE | Rights::CONTROL));
        for right in [Rights::MAP, Rights::SEND, Rights::RECEIVE] {
            assert!(!Kind::IoPorts.permits(right));
        }
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let creator = a.create_root(owner, Kind::Job, Rights::CONTROL).unwrap();
        assert_eq!(
            a.create_managed(owner, creator, Kind::IoPorts, Rights::READ | Rights::WRITE),
            Err(Error::Denied)
        );
        let cap = a
            .create_root(
                owner,
                Kind::IoPorts,
                Rights::READ | Rights::WRITE | Rights::CONTROL,
            )
            .unwrap();
        assert_eq!(
            a.authorize(owner, cap, Kind::Memory, Rights::READ).err(),
            Some(Error::WrongKind)
        );
    }
}

#[cfg(all(test, feature = "workspace-authority"))]
mod workspace_tests;
