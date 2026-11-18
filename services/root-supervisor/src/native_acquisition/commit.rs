//! Persist one prior authorized decision with a resident continuation. Owner
//! transitions use the same canonical Store/stream bodies as consuming callers.
#![allow(clippy::result_large_err)] // Rejections retain the exact actual owner.
use super::*;
use ev_content_store::{Backend, TransferCut};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Empty,
    Authorized,
    Checking,
    Validated,
    Writing,
    Reading,
    Ready,
    Published,
    Fenced,
}
#[allow(clippy::large_enum_variant)] // Exactly one actual affine IO owner.
enum Owner<B: Backend> {
    Store(Store<B>),
    Put(Put<B>),
    Read(Read<B>),
}
#[must_use = "retain the actual commit owner until publication or abandonment"]
pub struct Commit<B: Backend> {
    phase: Phase,
    cold: Cold<B>,
    owner: Option<Owner<B>>,
    next: Option<Snapshot>,
    prepared: Option<AuthorizationBinding>,
    transfer: Option<TransferCut>,
    failed: bool,
}
impl<B: Backend> Commit<B> {
    pub const fn empty() -> Self {
        Self {
            phase: Phase::Empty,
            cold: Cold::empty(),
            owner: None,
            next: None,
            prepared: None,
            transfer: None,
            failed: false,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.phase == Phase::Empty
            && self.owner.is_none()
            && self.cold.is_empty()
            && self.next.is_none()
            && self.prepared.is_none()
    }
    pub fn has_authorized(&self) -> bool {
        self.phase == Phase::Authorized
            && self.prepared.is_some()
            && self.next.is_some()
            && self.owner.is_none()
            && self.cold.is_empty()
            && !self.failed
    }
    /// Discard only prepared metadata with no actual IO owner.
    pub fn discard_authorized(&mut self) -> bool {
        if !self.has_authorized() {
            return false;
        }
        self.clear_abandoned();
        true
    }
    /// Consume the already-authorized resident result only on its bound head.
    /// No new clock decision or second Snapshot is created here.
    #[inline(never)]
    pub fn begin_authorized(
        &mut self,
        store: Store<B>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !self.has_authorized()
            || store.has_unresolved_io()
            || store.authorization_binding() != self.prepared
        {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(Fault::Phase),
            });
        }
        let next = self.next.take().unwrap();
        self.prepared = None;
        self.phase = Phase::Empty;
        store.begin_record_into(next.record, self, transfer, now)
    }
    fn take_store(&mut self) -> Store<B> {
        match self.owner.take().unwrap() {
            Owner::Store(s) => s,
            _ => unreachable!("internal commit Store phase"),
        }
    }
    fn take_put(&mut self) -> Put<B> {
        match self.owner.take().unwrap() {
            Owner::Put(p) => p,
            _ => unreachable!("internal commit Put phase"),
        }
    }
    fn take_read(&mut self) -> Read<B> {
        match self.owner.take().unwrap() {
            Owner::Read(r) => r,
            _ => unreachable!("internal commit Read phase"),
        }
    }
    #[inline(never)]
    fn check_done(&mut self) -> Result<bool, Failure<B::Error>> {
        let Some(result) = self.cold.checked_into(&mut self.next) else {
            return Err(Failure::Policy(Fault::Phase));
        };
        match result {
            Ok(store) => {
                self.owner = Some(Owner::Store(store));
                self.phase = Phase::Validated;
                Ok(false)
            }
            Err(r) => {
                self.owner = Some(Owner::Store(r.owner));
                self.phase = Phase::Fenced;
                Err(r.error)
            }
        }
    }
    #[inline(never)]
    fn reserve(&mut self, b: &mut Buffers, now: u64) -> Result<bool, Failure<B::Error>> {
        self.next
            .as_ref()
            .unwrap()
            .record
            .encode(&mut b.checkpoint)
            .map_err(Failure::Policy)?;
        let hash = digest(&b.checkpoint);
        let store = self.take_store();
        match store.begin_put(CHECKPOINT_BYTES as u64, hash, self.transfer.unwrap(), now) {
            Ok(put) => {
                self.owner = Some(Owner::Put(put));
                self.phase = Phase::Writing;
                Ok(false)
            }
            Err(r) => {
                self.owner = Some(Owner::Store(r.owner));
                self.phase = Phase::Fenced;
                Err(r.error)
            }
        }
    }
    #[inline(never)]
    fn seal(&mut self, now: u64) -> Result<bool, Failure<B::Error>> {
        let put = self.take_put();
        match put.seal(now) {
            Ok(read) => {
                self.owner = Some(Owner::Read(read));
                self.phase = Phase::Reading;
                Ok(false)
            }
            Err(r) => {
                self.owner = Some(Owner::Store(r.owner));
                self.phase = Phase::Fenced;
                Err(r.error)
            }
        }
    }
    /// One actual4KiB object step or bounded metadata operation. Branch-local
    /// frames never carry a live Cold/Commit workspace by value through crypto.
    #[inline(never)]
    pub fn step(&mut self, b: &mut Buffers, now: u64) -> Result<bool, Failure<B::Error>> {
        if self.failed {
            return Err(Failure::Policy(Fault::Phase));
        }
        let result = match self.phase {
            Phase::Checking => match self.cold.step(b, now) {
                Ok(true) => self.check_done(),
                Ok(false) => Ok(false),
                Err(e) => Err(e),
            },
            Phase::Validated => self.reserve(b, now),
            Phase::Writing => {
                let Some(Owner::Put(put)) = self.owner.as_mut() else {
                    unreachable!()
                };
                if put.remaining() == 0 {
                    self.seal(now)
                } else {
                    match self.next.as_ref().unwrap().record.encode(&mut b.checkpoint) {
                        Ok(()) => put.write_chunk(&b.checkpoint, now).map(|()| false),
                        Err(e) => Err(Failure::Policy(e)),
                    }
                }
            }
            Phase::Reading => {
                let Some(Owner::Read(read)) = self.owner.as_mut() else {
                    unreachable!()
                };
                if read.remaining() == 0 {
                    self.phase = Phase::Ready;
                    Ok(true)
                } else {
                    read.read_chunk(&mut b.checkpoint, now).map(|_| false)
                }
            }
            Phase::Ready | Phase::Published => Ok(true),
            Phase::Empty | Phase::Authorized | Phase::Fenced => Err(Failure::Policy(Fault::Phase)),
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Actual runtime path: the next snapshot remains resident while the same
    /// Read publishes its verified checkpoint through the canonical journal.
    #[inline(never)]
    pub fn publish_in_place(
        &mut self,
        now: u64,
        b: &mut [u8; CHECKPOINT_BYTES],
    ) -> Option<Result<Store<B>, Rejected<B>>> {
        if self.is_empty() {
            return None;
        }
        if self.failed || self.phase != Phase::Ready {
            return self.abandon_in_place().map(|owner| {
                Err(Rejected {
                    owner,
                    error: Failure::Policy(Fault::Phase),
                })
            });
        }
        match self.publish_step(now, b) {
            Ok(()) => self.take_published().map(Ok),
            Err(error) => self
                .abandon_in_place()
                .map(|owner| Err(Rejected { owner, error })),
        }
    }
    #[inline(never)]
    pub fn publish_step(
        &mut self,
        now: u64,
        b: &mut [u8; CHECKPOINT_BYTES],
    ) -> Result<(), Failure<B::Error>> {
        if self.failed || self.phase != Phase::Ready {
            return Err(Failure::Policy(Fault::Phase));
        }
        let Some(Owner::Read(read)) = self.owner.as_mut() else {
            return Err(Failure::Policy(Fault::Phase));
        };
        let result = read.publish_snapshot_step(&mut self.next, now, b);
        if result.is_ok() {
            self.phase = Phase::Published;
        } else {
            self.failed = true;
            self.phase = Phase::Fenced;
        }
        result
    }
    #[inline(never)]
    pub fn take_published(&mut self) -> Option<Store<B>> {
        if self.failed || self.phase != Phase::Published {
            return None;
        }
        let read = self.take_read();
        self.next = None;
        self.prepared = None;
        self.phase = Phase::Empty;
        self.transfer = None;
        Some(read.abandon())
    }
    pub fn publication_in_place(&mut self) -> Option<Result<Publication<B>, Rejected<B>>> {
        if self.is_empty() {
            return None;
        }
        if !self.failed && self.phase == Phase::Ready {
            let read = self.take_read();
            let next = self.next.take().unwrap();
            self.phase = Phase::Empty;
            self.transfer = None;
            return Some(Ok(Publication { read, next }));
        }
        self.abandon_in_place().map(|owner| {
            Err(Rejected {
                owner,
                error: Failure::Policy(Fault::Phase),
            })
        })
    }
    pub fn publication(mut self) -> Result<Publication<B>, Rejected<B>> {
        self.publication_in_place()
            .expect("consuming commit retains its actual owner")
    }
    pub fn abandon_in_place(&mut self) -> Option<Store<B>> {
        let store = if !self.cold.is_empty() {
            self.cold.abandon_in_place()
        } else {
            self.owner.take().map(|owner| match owner {
                Owner::Store(s) => s,
                Owner::Put(p) => p.abandon(),
                Owner::Read(r) => r.abandon(),
            })
        };
        self.clear_abandoned();
        store
    }
    fn clear_abandoned(&mut self) {
        self.next = None;
        self.prepared = None;
        self.phase = Phase::Empty;
        self.transfer = None;
    }
    /// Same terminal owner projection as abandon→into_arena→into_backend,
    /// without returning metadata that the caller immediately discards.
    #[inline(never)]
    pub fn abandon_backend(&mut self) -> Option<B> {
        let backend = if !self.cold.is_empty() {
            self.cold.abandon_backend()
        } else {
            self.owner.take().map(|owner| match owner {
                Owner::Store(store) => store.into_arena().into_backend(),
                Owner::Put(put) => put.into_backend(),
                Owner::Read(read) => read.into_backend(),
            })
        };
        self.clear_abandoned();
        backend
    }
    pub fn abandon(mut self) -> Store<B> {
        self.abandon_in_place()
            .expect("consuming commit retains its actual owner")
    }
}
impl Decision {
    #[inline(never)]
    pub fn begin_into<B: Backend>(
        self,
        store: Store<B>,
        workspace: &mut Commit<B>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !workspace.is_empty()
            || store.arena.published_metadata() != Some(self.prior)
            || store.arena.head_digest() != self.head
            || store
                .state
                .as_ref()
                .is_none_or(|s| s.record.revision != self.revision)
        {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(Fault::Phase),
            });
        }
        store.begin_record_into(self.next.record, workspace, transfer, now)
    }
    pub fn begin<B: Backend>(
        self,
        store: Store<B>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<Commit<B>, Rejected<B>> {
        let mut workspace = Commit::empty();
        self.begin_into(store, &mut workspace, transfer, now)?;
        Ok(workspace)
    }
}
impl<B: Backend> Store<B> {
    /// Canonical record/owner handoff shared by remote and local selection
    /// decisions. The same Cold reconstructs/checks all replay and material.
    #[inline(never)]
    pub(super) fn begin_record_into(
        self,
        next: codec::Record,
        workspace: &mut Commit<B>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !workspace.is_empty() {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(Fault::Phase),
            });
        }
        Cold::check_record_into(self, next, &mut workspace.cold, transfer, now)?;
        workspace.transfer = Some(transfer);
        workspace.phase = Phase::Checking;
        workspace.failed = false;
        Ok(())
    }
    /// Resident output for the SAME authorization logic as `authorize`.
    /// On refusal no ready decision is exposed and the occupied workspace is
    /// never replaced. It retains no borrowed material or extra Backend.
    pub fn authorize_into<C: QualifiedClock>(
        &self,
        remote: Remote<'_>,
        clock: &mut C,
        workspace: &mut Commit<B>,
    ) -> Result<(), Fault> {
        if !workspace.is_empty() {
            return Err(Fault::Phase);
        }
        let binding = self.authorization_binding().ok_or(Fault::Unprovisioned)?;
        self.authorize_snapshot(remote, clock, &mut workspace.next)?;
        if self.authorization_binding() != Some(binding) {
            workspace.next = None;
            return Err(Fault::Phase);
        }
        workspace.prepared = Some(binding);
        workspace.phase = Phase::Authorized;
        workspace.failed = false;
        Ok(())
    }
    /// Explicit initial provisioning only; never selected by an open failure.
    #[inline(never)]
    pub fn provision_into(
        self,
        rom: Object,
        workspace: &mut Commit<B>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !workspace.is_empty()
            || self.state.is_some()
            || self.arena.published_metadata().is_some()
        {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(Fault::Phase),
            });
        }
        // The private initial-only Cold mode authenticates the actual stored
        // ROM before constructing/encoding any initial replay checkpoint.
        Cold::check_initial_into(self, rom, &mut workspace.cold, transfer, now)?;
        workspace.transfer = Some(transfer);
        workspace.phase = Phase::Checking;
        workspace.failed = false;
        Ok(())
    }
    pub fn provision(
        self,
        rom: Object,
        transfer: TransferCut,
        now: u64,
    ) -> Result<Commit<B>, Rejected<B>> {
        let mut workspace = Commit::empty();
        self.provision_into(rom, &mut workspace, transfer, now)?;
        Ok(workspace)
    }
}
