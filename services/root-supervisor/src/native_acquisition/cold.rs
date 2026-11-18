//! Bounded cold authentication, without a self-referential Root/Package view.
#![allow(clippy::result_large_err)] // Exact actual owner is retained on refusal.
use super::*;
use ev_content_store::{Backend, TransferCut};
use ev_release_trust::{
    metadata as md,
    signature::{self, Envelope, Role},
    verifier::{self, ReplayState, TrustedRoot},
};
pub const ROOT_BUFFER: usize = signature::HEADER_BYTES
    + md::ROOT_BYTES
    + signature::MAX_SIGNATURES * signature::SIGNATURE_BYTES;
pub const TARGET_BUFFER: usize = signature::HEADER_BYTES
    + md::HEADER_BYTES
    + md::MAX_TARGETS * md::TARGET_BYTES
    + signature::MAX_SIGNATURES * signature::SIGNATURE_BYTES;
pub const LINK_BUFFER: usize = signature::HEADER_BYTES
    + md::HEADER_BYTES
    + md::LINK_BYTES
    + signature::MAX_SIGNATURES * signature::SIGNATURE_BYTES;
/// Caller-owned private storage, intended for resident placement. No reference
/// to these bytes is retained between steps; complete hashes are checked again
/// before scoped parsing, so swapping/mixing work buffers cannot create trust.
pub struct Buffers {
    pub checkpoint: [u8; CHECKPOINT_BYTES],
    pub root: [u8; ROOT_BUFFER],
    pub next_root: [u8; ROOT_BUFFER],
    pub targets: [u8; TARGET_BUFFER],
    pub snapshot: [u8; LINK_BUFFER],
    pub timestamp: [u8; LINK_BUFFER],
    pub chunk: [u8; 4096],
}
impl Buffers {
    pub const fn empty() -> Self {
        Self {
            checkpoint: [0; CHECKPOINT_BYTES],
            root: [0; ROOT_BUFFER],
            next_root: [0; ROOT_BUFFER],
            targets: [0; TARGET_BUFFER],
            snapshot: [0; LINK_BUFFER],
            timestamp: [0; LINK_BUFFER],
            chunk: [0; 4096],
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Empty,
    InitialRecord,
    Checkpoint,
    Root(usize),
    Metadata(usize),
    Content(usize),
    LocalRoot(usize),
    LocalTargets(usize),
    Done,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ordinary,
    InitialRom,
}
#[allow(clippy::large_enum_variant)] // One mutually exclusive affine owner; no heap or duplicated Backend storage.
enum Owner<B: Backend> {
    Store(Store<B>),
    Read(Read<B>),
}
#[must_use = "retain the actual cold-open owner until finish or explicit abandon"]
pub struct Cold<B: Backend> {
    owner: Option<Owner<B>>,
    record: Option<codec::Record>,
    replay: Option<ReplayState>,
    history: Option<ReplayState>,
    phase: Phase,
    mode: Mode,
    object: Option<Object>,
    offset: usize,
    root_len: usize,
    transfer: Option<TransferCut>,
    failed: bool,
    pending_completion: bool,
}
// Empty is distinct from a refusal retaining the actual affine backend.
pub(super) type Checked<B> = Option<Result<(Store<B>, Snapshot), Rejected<B>>>;
impl<B: Backend> Store<B> {
    /// Ordinary open never formats or reconstructs trust on refusal.
    pub fn begin_cold(self, transfer: TransferCut, now: u64) -> Result<Cold<B>, Rejected<B>> {
        let mut workspace = Cold::empty();
        self.begin_cold_into(&mut workspace, transfer, now)?;
        Ok(workspace)
    }
    /// Initialize only an actually empty resident workspace. Refusal returns
    /// the incoming Store and never replaces a retained owner already there.
    #[inline(never)]
    pub fn begin_cold_into(
        mut self,
        workspace: &mut Cold<B>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !workspace.is_empty() {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(Fault::Phase),
            });
        }
        let Some(object) = self.arena.published_metadata() else {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(Fault::Unprovisioned),
            });
        };
        if object.length() != CHECKPOINT_BYTES as u64 {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(Fault::Checkpoint),
            });
        }
        if let Err(error) = Self::cold_entry(&mut self, transfer, now) {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(error),
            });
        }
        workspace.record = None;
        workspace.initialize_store(self, object, Phase::Checkpoint, transfer, Mode::Ordinary);
        Ok(())
    }
    fn cold_entry(store: &mut Store<B>, transfer: TransferCut, now: u64) -> Result<(), Fault> {
        store.observe(now)?;
        transfer.child(now, 1024).map_err(|_| Fault::Clock)?;
        Ok(())
    }
}
impl<B: Backend> Cold<B> {
    /// No fabricated Object, TransferCut, Store or ready state in an empty slot.
    pub const fn empty() -> Self {
        Self {
            owner: None,
            record: None,
            replay: None,
            history: None,
            phase: Phase::Empty,
            mode: Mode::Ordinary,
            object: None,
            offset: 0,
            root_len: 0,
            transfer: None,
            failed: false,
            pending_completion: false,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.owner.is_none()
    }
    fn initialize_store(
        &mut self,
        store: Store<B>,
        object: Object,
        phase: Phase,
        transfer: TransferCut,
        mode: Mode,
    ) {
        debug_assert!(self.is_empty());
        self.replay = None;
        self.history = None;
        self.phase = phase;
        self.mode = mode;
        self.object = Some(object);
        self.offset = 0;
        self.root_len = 0;
        self.transfer = Some(transfer);
        self.failed = false;
        self.pending_completion = false;
        self.owner = Some(Owner::Store(store));
    }
    fn clear_metadata(&mut self) {
        self.record = None;
        self.replay = None;
        self.history = None;
        self.phase = Phase::Empty;
        self.mode = Mode::Ordinary;
        self.object = None;
        self.offset = 0;
        self.root_len = 0;
        self.transfer = None;
        self.failed = false;
        self.pending_completion = false;
    }

    fn reader(&self) -> Option<&Read<B>> {
        match self.owner.as_ref()? {
            Owner::Read(r) => Some(r),
            _ => None,
        }
    }
    fn reader_mut(&mut self) -> Option<&mut Read<B>> {
        match self.owner.as_mut()? {
            Owner::Read(r) => Some(r),
            _ => None,
        }
    }
    fn take_reader(&mut self) -> Read<B> {
        match self.owner.take().unwrap() {
            Owner::Read(r) => r,
            _ => unreachable!("internal cold reader phase"),
        }
    }
    fn take_store(&mut self) -> Store<B> {
        match self.owner.take().unwrap() {
            Owner::Store(s) => s,
            _ => unreachable!("internal cold store phase"),
        }
    }

    // Preserve the prior consuming internal API for callers outside the new
    // resident execution path; the actual runtime uses check_record_into.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn check_record(
        store: Store<B>,
        record: codec::Record,
        transfer: TransferCut,
        now: u64,
    ) -> Result<Self, Rejected<B>> {
        let mut workspace = Self::empty();
        Self::check_record_into(store, record, &mut workspace, transfer, now)?;
        Ok(workspace)
    }
    #[inline(never)]
    pub(super) fn check_record_into(
        mut store: Store<B>,
        record: codec::Record,
        workspace: &mut Self,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !workspace.is_empty() {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(Fault::Phase),
            });
        }
        if let Err(e) = record.validate() {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(e),
            });
        }
        let object = record.roots[0].unwrap();
        if let Err(error) = Store::cold_entry(&mut store, transfer, now) {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(error),
            });
        }
        workspace.record = Some(record);
        workspace.initialize_store(store, object, Phase::Root(0), transfer, Mode::Ordinary);
        Ok(())
    }
    /// Private explicit virgin-provision entry only. No initial replay or
    /// placeholder Record exists until actual ROM readback and authentication.
    #[inline(never)]
    pub(super) fn check_initial_into(
        mut store: Store<B>,
        rom: Object,
        workspace: &mut Self,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<B>> {
        if !workspace.is_empty()
            || store.state.is_some()
            || store.arena.published_metadata().is_some()
        {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(Fault::Phase),
            });
        }
        if rom.length() != ROM_ROOT.len() as u64 || rom.sha256() != digest(ROM_ROOT) {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(Fault::Root),
            });
        }
        if let Err(error) = Store::cold_entry(&mut store, transfer, now) {
            return Err(Rejected {
                owner: store,
                error: Failure::Policy(error),
            });
        }
        workspace.initialize_store(store, rom, Phase::Root(0), transfer, Mode::InitialRom);
        Ok(())
    }
    fn start(&mut self, object: Object, phase: Phase, now: u64) -> Result<(), Failure<B::Error>> {
        if !matches!(self.owner, Some(Owner::Store(_))) {
            return Err(Failure::Policy(Fault::Phase));
        }
        self.transfer
            .expect("occupied cold transfer")
            .child(now, 1024)
            .map_err(|_| Failure::Policy(Fault::Clock))?;
        self.object = Some(object);
        self.phase = phase;
        self.offset = 0;
        Ok(())
    }
    #[inline(never)]
    fn open_scheduled(&mut self, now: u64) -> Result<(), Failure<B::Error>> {
        let store = self.take_store();
        match store.begin_read(
            self.object.expect("scheduled object"),
            self.transfer.expect("scheduled transfer"),
            now,
        ) {
            Ok(reader) => {
                self.owner = Some(Owner::Read(reader));
                Ok(())
            }
            Err(rejected) => {
                self.owner = Some(Owner::Store(rejected.owner));
                self.failed = true;
                Err(rejected.error)
            }
        }
    }
    fn policy<T>(&mut self, result: Result<T, Fault>) -> Result<T, Failure<B::Error>> {
        result.map_err(|e| {
            self.failed = true;
            Failure::Policy(e)
        })
    }
    #[inline(never)]
    pub fn step(&mut self, b: &mut Buffers, now: u64) -> Result<bool, Failure<B::Error>> {
        if self.failed || self.is_empty() {
            return Err(Failure::Policy(Fault::Phase));
        }
        if self.phase == Phase::Done {
            return Ok(true);
        }
        if self.phase == Phase::InitialRecord {
            self.build_initial(now)?;
            return Ok(true);
        }
        let result = if self.pending_completion {
            let Some(Owner::Store(store)) = self.owner.as_mut() else {
                return Err(Failure::Policy(Fault::Phase));
            };
            let checked =
                Store::cold_entry(store, self.transfer.expect("original cold transfer"), now)
                    .map_err(Failure::Policy);
            match checked {
                Err(e) => Err(e),
                Ok(()) => {
                    self.pending_completion = false;
                    self.complete(b, now)
                }
            }
        } else if matches!(self.owner, Some(Owner::Store(_))) {
            self.open_scheduled(now)
        } else {
            self.read_step(b, now)
        };
        if result.is_err() {
            self.failed = true;
        }
        result?;
        Ok(self.phase == Phase::Done)
    }
    #[inline(never)]
    fn read_step(&mut self, b: &mut Buffers, now: u64) -> Result<(), Failure<B::Error>> {
        let remaining = self
            .reader()
            .ok_or(Failure::Policy(Fault::Phase))?
            .remaining() as usize;
        let count = remaining.min(4096);
        let end = self
            .offset
            .checked_add(count)
            .ok_or(Failure::Policy(Fault::Checkpoint))?;
        let out = match self.phase {
            Phase::Checkpoint => b.checkpoint.get_mut(self.offset..end),
            Phase::Root(_) => b.next_root.get_mut(self.offset..end),
            Phase::Metadata(0) => b.targets.get_mut(self.offset..end),
            Phase::Metadata(1) => b.snapshot.get_mut(self.offset..end),
            Phase::Metadata(2) => b.timestamp.get_mut(self.offset..end),
            Phase::Content(_) => b.chunk.get_mut(..count),
            Phase::LocalRoot(_) => b.root.get_mut(self.offset..end),
            Phase::LocalTargets(_) => b.targets.get_mut(self.offset..end),
            _ => None,
        };
        let Some(out) = out else {
            self.failed = true;
            return Err(Failure::Policy(Fault::Capacity));
        };
        if let Err(e) = self.reader_mut().unwrap().read_chunk(out, now) {
            self.failed = true;
            return Err(e);
        }
        self.offset = end;
        if self.reader().unwrap().remaining() != 0 {
            return Ok(());
        }
        match self.take_reader().finish() {
            Ok(v) => self.owner = Some(Owner::Store(v.store)),
            Err(r) => {
                self.owner = Some(Owner::Store(r.owner));
                self.failed = true;
                return Err(r.error);
            }
        }
        self.pending_completion = true;
        Ok(())
    }
    #[inline(never)]
    fn complete(&mut self, b: &mut Buffers, now: u64) -> Result<(), Failure<B::Error>> {
        match self.phase {
            Phase::Checkpoint => self.complete_checkpoint(b, now),
            Phase::Root(index) => self.complete_root(b, now, index),
            Phase::Metadata(index) => self.complete_metadata(b, now, index),
            Phase::Content(index) => self.next_content(index + 1, now),
            Phase::LocalRoot(index) => self.local_root(b, index, now),
            Phase::LocalTargets(index) => self.local_targets(b, index, now),
            Phase::Done => Ok(()),
            Phase::Empty | Phase::InitialRecord => Err(Failure::Policy(Fault::Phase)),
        }
    }
    #[inline(never)]
    fn complete_checkpoint(&mut self, b: &mut Buffers, now: u64) -> Result<(), Failure<B::Error>> {
        if digest(&b.checkpoint) != self.object.expect("occupied cold object").sha256() {
            return Err(Failure::Policy(Fault::Checkpoint));
        }
        let record = self.policy(codec::Record::decode(&b.checkpoint))?;
        let first = record.roots[0].unwrap();
        self.record = Some(record);
        self.start(first, Phase::Root(0), now)
    }
    #[inline(never)]
    fn complete_root(
        &mut self,
        b: &mut Buffers,
        now: u64,
        index: usize,
    ) -> Result<(), Failure<B::Error>> {
        let n = self.object.expect("occupied cold object").length() as usize;
        let raw = b
            .next_root
            .get(..n)
            .ok_or(Failure::Policy(Fault::Capacity))?;
        if digest(raw) != self.object.expect("occupied cold object").sha256() {
            return Err(Failure::Policy(Fault::Root));
        }
        if self.mode == Mode::InitialRom {
            if index != 0 || self.record.is_some() || self.replay.is_some() || raw != ROM_ROOT {
                return Err(Failure::Policy(Fault::Root));
            }
            let root = TrustedRoot::provisioned(raw, binding())
                .map_err(|_| Failure::Policy(Fault::Root))?;
            self.replay = Some(ReplayState::initial(&root));
            self.phase = Phase::InitialRecord;
            return Ok(());
        }
        if index == 0 {
            if raw != ROM_ROOT {
                return Err(Failure::Policy(Fault::Root));
            }
            let root = TrustedRoot::provisioned(raw, binding())
                .map_err(|_| Failure::Policy(Fault::Root))?;
            // Temporary continuity traversal only. It is never returned
            // as retained state and never selected on an open error.
            self.history = Some(ReplayState::initial(&root));
        } else {
            if digest(&b.root[..self.root_len])
                != self.record.as_ref().unwrap().roots[index - 1]
                    .unwrap()
                    .sha256()
            {
                return Err(Failure::Policy(Fault::Root));
            }
            let old = TrustedRoot::provisioned(&b.root[..self.root_len], binding())
                .map_err(|_| Failure::Policy(Fault::Root))?;
            let next = verifier::advance_root(
                &old,
                self.history.as_ref().ok_or(Failure::Policy(Fault::Root))?,
                raw,
            )
            .map_err(|_| Failure::Policy(Fault::Root))?;
            if !next.changed {
                return Err(Failure::Policy(Fault::Root));
            }
            self.history = Some(next.proposed);
        }
        b.root[..n].copy_from_slice(raw);
        b.root[n..].fill(0);
        self.root_len = n;
        let record = self.record.as_ref().unwrap();
        if index + 1 < record.root_count() {
            return self.start(
                record.roots[index + 1].unwrap(),
                Phase::Root(index + 1),
                now,
            );
        }
        let root = TrustedRoot::provisioned(&b.root[..n], binding())
            .map_err(|_| Failure::Policy(Fault::Root))?;
        self.replay = Some(
            ev_release_trust::checkpoint::decode(&root, &record.replay)
                .map_err(|_| Failure::Policy(Fault::Checkpoint))?,
        );
        if let Some(object) = record.metadata[0] {
            self.start(object, Phase::Metadata(0), now)
        } else {
            let state = self.replay.as_ref().unwrap();
            if state.roles().iter().any(Option::is_some)
                || state.targets().iter().any(Option::is_some)
            {
                return Err(Failure::Policy(Fault::Metadata));
            }
            self.next_content(0, now)
        }
    }
    #[inline(never)]
    fn build_initial(&mut self, now: u64) -> Result<(), Failure<B::Error>> {
        if self.mode != Mode::InitialRom
            || self.record.is_some()
            || self.replay.is_none()
            || !matches!(self.owner, Some(Owner::Store(_)))
        {
            self.failed = true;
            return Err(Failure::Policy(Fault::Phase));
        }
        let result = (|| {
            let Some(Owner::Store(store)) = self.owner.as_mut() else {
                unreachable!()
            };
            Store::cold_entry(store, self.transfer.unwrap(), now).map_err(Failure::Policy)?;
            if store.state.is_some() || store.arena.published_metadata().is_some() {
                return Err(Failure::Policy(Fault::Phase));
            }
            let replay = self.replay.as_ref().unwrap();
            let mut encoded = [0; 1024];
            ev_release_trust::checkpoint::encode(replay, &mut encoded);
            let mut roots = [None; MAX_ROOT_MATERIALS];
            roots[0] = self.object;
            let record = codec::Record {
                revision: 1,
                replay: encoded,
                roots,
                metadata: [None; 3],
                candidate: None,
                active: None,
                known_good: None,
                authorizations: [None; 3],
            };
            record.validate().map_err(Failure::Policy)?;
            self.record = Some(record);
            self.phase = Phase::Done;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    #[inline(never)]
    fn complete_metadata(
        &mut self,
        b: &mut Buffers,
        now: u64,
        index: usize,
    ) -> Result<(), Failure<B::Error>> {
        let record = self.record.as_ref().unwrap();
        let n = self.object.expect("occupied cold object").length() as usize;
        let bytes = match index {
            0 => &b.targets[..n],
            1 => &b.snapshot[..n],
            _ => &b.timestamp[..n],
        };
        if digest(bytes) != self.object.expect("occupied cold object").sha256() {
            return Err(Failure::Policy(Fault::Metadata));
        }
        if index < 2 {
            return self.start(
                record.metadata[index + 1].unwrap(),
                Phase::Metadata(index + 1),
                now,
            );
        }
        self.authenticate_metadata(b)?;
        self.next_content(0, now)
    }
    #[inline(never)]
    fn authenticate_metadata(&self, b: &Buffers) -> Result<(), Failure<B::Error>> {
        let fail = || Failure::Policy(Fault::Metadata);
        let r = self.record.as_ref().unwrap();
        let state = self.replay.as_ref().unwrap();
        if digest(&b.root[..self.root_len]) != r.roots[r.root_count() - 1].unwrap().sha256() {
            return Err(fail());
        }
        for (i, bytes) in [
            b.targets.as_slice(),
            b.snapshot.as_slice(),
            b.timestamp.as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let o = r.metadata[i].unwrap();
            if digest(&bytes[..o.length() as usize]) != o.sha256() {
                return Err(fail());
            }
        }
        let root =
            TrustedRoot::provisioned(&b.root[..self.root_len], binding()).map_err(|_| fail())?;
        let root_envelope = Envelope::parse(root.bytes()).map_err(|_| fail())?;
        let keys = md::Root::parse(&root_envelope).map_err(|_| fail())?;
        let t = Envelope::parse(&b.targets[..r.metadata[0].unwrap().length() as usize])
            .map_err(|_| fail())?;
        let s = Envelope::parse(&b.snapshot[..r.metadata[1].unwrap().length() as usize])
            .map_err(|_| fail())?;
        let ts = Envelope::parse(&b.timestamp[..r.metadata[2].unwrap().length() as usize])
            .map_err(|_| fail())?;
        if s.role() != Role::Snapshot || ts.role() != Role::Timestamp {
            return Err(fail());
        }
        let targets = md::Targets::parse(&t).map_err(|_| fail())?;
        let snapshot = md::Linked::parse(&s).map_err(|_| fail())?;
        let timestamp = md::Linked::parse(&ts).map_err(|_| fail())?;
        if !snapshot.link().matches(&t, targets.common().version)
            || !timestamp.link().matches(&s, snapshot.common().version)
        {
            return Err(fail());
        }
        for (i, (e, c, id)) in [
            (t, targets.common(), targets.identity()),
            (
                s,
                snapshot.common(),
                md::Identity::of(&s, snapshot.common().version),
            ),
            (
                ts,
                timestamp.common(),
                md::Identity::of(&ts, timestamp.common().version),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            if c.binding != binding()
                || c.root_version != root.common().version
                || state.roles()[i] != Some(id)
            {
                return Err(fail());
            }
            keys.authenticate(&e).map_err(|_| fail())?;
        }
        for target in targets.iter() {
            let spec = target.spec();
            if !state.targets().iter().flatten().any(|f| {
                f.name == spec.name && f.version == spec.version && f.identity == target.identity()
            }) {
                return Err(fail());
            }
        }
        if let Some(c) = r.candidate {
            let name = logical_target_name();
            if targets.count() != 1
                || !targets.iter().any(|t| {
                    let s = t.spec();
                    s.name == name
                        && s.version == c.version
                        && s.sha256 == c.package
                        && s.length == c.object.length()
                        && s.build == c.build
                        && s.source_revision == c.source
                        && s.contract == c.descriptor
                })
            {
                return Err(fail());
            }
        }
        Ok(())
    }
    #[inline(never)]
    fn local_root(&mut self, b: &Buffers, index: usize, now: u64) -> Result<(), Failure<B::Error>> {
        let auth = self.record.as_ref().unwrap().authorizations[index]
            .ok_or(Failure::Policy(Fault::Metadata))?;
        self.root_len = auth.root.length() as usize;
        let raw = b
            .root
            .get(..self.root_len)
            .ok_or(Failure::Policy(Fault::Capacity))?;
        if digest(raw) != auth.root.sha256() {
            return Err(Failure::Policy(Fault::Root));
        }
        // The same actual immutable Object was already authenticated in the
        // full ROM-root succession chain. Never trust an unrelated self key.
        if !self
            .record
            .as_ref()
            .unwrap()
            .roots
            .contains(&Some(auth.root))
        {
            return Err(Failure::Policy(Fault::Root));
        }
        TrustedRoot::provisioned(raw, binding()).map_err(|_| Failure::Policy(Fault::Root))?;
        self.start(auth.targets, Phase::LocalTargets(index), now)
    }
    #[inline(never)]
    fn local_targets(
        &mut self,
        b: &Buffers,
        index: usize,
        now: u64,
    ) -> Result<(), Failure<B::Error>> {
        self.authenticate_local_target(b, index)?;
        let r = self.record.as_ref().unwrap();
        let content = [r.candidate, r.active, r.known_good][index]
            .ok_or(Failure::Policy(Fault::Candidate))?;
        self.start(content.object, Phase::Content(index), now)
    }
    #[inline(never)]
    fn authenticate_local_target(
        &self,
        b: &Buffers,
        index: usize,
    ) -> Result<(), Failure<B::Error>> {
        let fail = || Failure::Policy(Fault::Metadata);
        let r = self.record.as_ref().unwrap();
        let auth = r.authorizations[index].ok_or_else(fail)?;
        let content = [r.candidate, r.active, r.known_good][index].ok_or_else(fail)?;
        let root_bytes = b.root.get(..self.root_len).ok_or_else(fail)?;
        let targets_bytes = b
            .targets
            .get(..auth.targets.length() as usize)
            .ok_or_else(fail)?;
        if digest(root_bytes) != auth.root.sha256()
            || digest(targets_bytes) != auth.targets.sha256()
        {
            return Err(fail());
        }
        let root = TrustedRoot::provisioned(root_bytes, binding()).map_err(|_| fail())?;
        let re = Envelope::parse(root.bytes()).map_err(|_| fail())?;
        let keys = md::Root::parse(&re).map_err(|_| fail())?;
        let e = Envelope::parse(targets_bytes).map_err(|_| fail())?;
        let targets = md::Targets::parse(&e).map_err(|_| fail())?;
        if targets.common().binding != binding()
            || targets.common().root_version != root.common().version
            || targets.count() != 1
        {
            return Err(fail());
        }
        keys.authenticate(&e).map_err(|_| fail())?;
        let state = self.replay.as_ref().unwrap();
        if root.identity() == state.root() {
            let role_floor = state.roles()[0].ok_or_else(fail)?;
            if targets.common().version > role_floor.version
                || targets.common().version == role_floor.version
                    && targets.identity() != role_floor
            {
                // A retained local proof may be older, but cannot claim a
                // future or equivocating role version never accepted by this
                // same Root history. Different authenticated historical Roots
                // have separate role-version domains across rotation.
                return Err(fail());
            }
        }
        let target = targets.iter().next().ok_or_else(fail)?;
        let spec = target.spec();
        if spec.name != logical_target_name()
            || spec.version != content.version
            || spec.sha256 != content.package
            || spec.length != content.object.length()
            || spec.build != content.build
            || spec.source_revision != content.source
            || spec.contract != content.descriptor
        {
            return Err(fail());
        }
        let floor = state
            .targets()
            .iter()
            .flatten()
            .find(|f| f.name == spec.name)
            .ok_or_else(fail)?;
        if floor.version < spec.version
            || floor.version == spec.version && floor.identity != target.identity()
        {
            return Err(fail());
        }
        // Already accepted local content does not reapply current remote expiry
        // or require obsolete role versions to equal the latest role floors.
        // LOCAL selected/KG flags still depend on the Root-owned media boundary.
        Ok(())
    }
    #[inline(never)]
    fn next_content(&mut self, from: usize, now: u64) -> Result<(), Failure<B::Error>> {
        let r = self.record.as_ref().unwrap();
        let all = [r.candidate, r.active, r.known_good];
        for i in from..3 {
            if let Some(c) = all[i] {
                if all[..i]
                    .iter()
                    .enumerate()
                    .any(|(j, p)| *p == Some(c) && r.authorizations[j] == r.authorizations[i])
                {
                    continue;
                }
                let auth = r.authorizations[i].ok_or(Failure::Policy(Fault::Metadata))?;
                return if i == 0 {
                    self.start(c.object, Phase::Content(i), now)
                } else {
                    self.start(auth.root, Phase::LocalRoot(i), now)
                };
            }
        }
        self.phase = Phase::Done;
        Ok(())
    }
    pub fn finish(mut self) -> Result<Store<B>, Rejected<B>> {
        self.finish_in_place()
            .expect("consuming occupied cold owner")
    }
    pub fn finish_in_place(&mut self) -> Option<Result<Store<B>, Rejected<B>>> {
        if self.is_empty() {
            return None;
        }
        if self.failed || self.phase != Phase::Done {
            return Some(Err(Rejected {
                owner: self.abandon_in_place().unwrap(),
                error: Failure::Policy(Fault::Phase),
            }));
        }
        let mut store = self.take_store();
        store.state = Some(Snapshot {
            record: self.record.take().unwrap(),
            replay: self.replay.take().unwrap(),
        });
        self.clear_metadata();
        Some(Ok(store))
    }
    // Compatibility wrapper; resident callers use checked_in_place.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn checked(mut self) -> Result<(Store<B>, Snapshot), Rejected<B>> {
        self.checked_in_place()
            .expect("consuming occupied cold owner")
    }
    pub(super) fn checked_in_place(&mut self) -> Checked<B> {
        let mut next = None;
        self.checked_into(&mut next)
            .map(|result| result.map(|store| (store, next.take().expect("checked snapshot"))))
    }
    /// Move validated metadata directly to an empty resident destination. An
    /// occupied destination is never overwritten, including on refusal.
    pub(super) fn checked_into(
        &mut self,
        next: &mut Option<Snapshot>,
    ) -> Option<Result<Store<B>, Rejected<B>>> {
        if self.is_empty() {
            return None;
        }
        if next.is_some() || self.failed || self.phase != Phase::Done {
            return Some(Err(Rejected {
                owner: self.abandon_in_place().unwrap(),
                error: Failure::Policy(Fault::Phase),
            }));
        }
        *next = Some(Snapshot {
            record: self.record.take().unwrap(),
            replay: self.replay.take().unwrap(),
        });
        let store = self.take_store();
        self.clear_metadata();
        Some(Ok(store))
    }
    pub fn abandon(mut self) -> Store<B> {
        self.abandon_in_place()
            .expect("consuming occupied cold owner")
    }
    pub fn abandon_in_place(&mut self) -> Option<Store<B>> {
        let store = match self.owner.take()? {
            Owner::Read(read) => read.abandon(),
            Owner::Store(store) => store,
        };
        self.clear_metadata();
        Some(store)
    }
    /// Same terminal Backend projection as Main; retain actual poison/high-water.
    #[inline(never)]
    pub fn abandon_backend(&mut self) -> Option<B> {
        let backend = match self.owner.take()? {
            Owner::Read(read) => read.into_backend(),
            Owner::Store(store) => store.into_arena().into_backend(),
        };
        self.clear_metadata();
        Some(backend)
    }
}

#[cfg(test)]
mod inplace_tests {
    use super::*;
    use crate::native_acquisition::tests::{Disk, format, transfer};
    fn ready() -> Store<Disk> {
        let t = transfer();
        let mut put = format()
            .begin_put(ROM_ROOT.len() as u64, digest(ROM_ROOT), t, 1)
            .unwrap_or_else(|_| panic!("ROM reserve"));
        put.write_chunk(ROM_ROOT, 1)
            .unwrap_or_else(|_| panic!("ROM write"));
        let mut read = put.seal(1).unwrap_or_else(|_| panic!("ROM seal"));
        let mut bytes = [0; 4096];
        while read.remaining() != 0 {
            let n = read.remaining().min(4096) as usize;
            read.read_chunk(&mut bytes[..n], 1)
                .unwrap_or_else(|_| panic!("ROM read"));
        }
        let stored = read.finish().unwrap_or_else(|_| panic!("ROM verify"));
        let mut commit = stored
            .store
            .provision(stored.object, t, 1)
            .unwrap_or_else(|_| panic!("ROM provision"));
        let mut b = Buffers::empty();
        while !commit
            .step(&mut b, 1)
            .unwrap_or_else(|_| panic!("ROM commit"))
        {}
        commit
            .publication()
            .unwrap_or_else(|_| panic!("ROM publication"))
            .publish(1, &mut b.checkpoint)
            .unwrap_or_else(|_| panic!("ROM ACK"))
    }
    #[test]
    fn empty_workspace_has_no_fake_owner_and_all_in_place_exits_are_total() {
        let mut c = Cold::<Disk>::empty();
        let mut b = Buffers::empty();
        assert!(c.is_empty());
        assert!(c.finish_in_place().is_none());
        assert!(c.checked_in_place().is_none());
        assert!(c.abandon_in_place().is_none());
        assert!(matches!(
            c.step(&mut b, 1),
            Err(Failure::Policy(Fault::Phase))
        ));
        assert!(c.is_empty());
    }
    #[test]
    fn occupied_workspace_refuses_both_reinitializers_and_keeps_exact_original_head() {
        let original = ready();
        let old = original.arena.head_digest();
        let mut c = Cold::empty();
        original
            .begin_cold_into(&mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!("cold"));
        let incoming = ready();
        let mut put = incoming
            .begin_put(1, digest(b"x"), transfer(), 1)
            .unwrap_or_else(|_| panic!("new head"));
        put.write_chunk(b"x", 1).unwrap_or_else(|_| panic!());
        let incoming = put.abandon();
        let new = incoming.arena.head_digest();
        assert_ne!(old, new);
        let refused = incoming
            .begin_cold_into(&mut c, transfer(), 1)
            .err()
            .unwrap();
        assert_eq!(refused.owner.arena.head_digest(), new);
        assert!(!c.is_empty());
        let record = crate::native_acquisition::tests::retained_snapshot(false).record;
        let refused = Cold::check_record_into(refused.owner, record, &mut c, transfer(), 1)
            .err()
            .unwrap();
        assert_eq!(refused.owner.arena.head_digest(), new);
        let returned = c.abandon_in_place().unwrap();
        assert_eq!(returned.arena.head_digest(), old);
        assert!(c.is_empty());
        assert!(c.abandon_in_place().is_none());
    }
    #[test]
    fn exact_successful_finish_and_incomplete_refusal_each_empty_only_the_consumed_workspace() {
        let store = ready();
        let head = store.arena.head_digest();
        let mut c = Cold::empty();
        store
            .begin_cold_into(&mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        let refused = c.finish_in_place().unwrap().err().unwrap();
        assert_eq!(refused.owner.arena.head_digest(), head);
        assert!(c.is_empty());
        refused
            .owner
            .begin_cold_into(&mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        let mut b = Buffers::empty();
        while !c.step(&mut b, 1).unwrap_or_else(|_| panic!("cold step")) {}
        let reopened = c
            .finish_in_place()
            .unwrap()
            .unwrap_or_else(|_| panic!("cold finish"));
        assert_eq!(reopened.arena.head_digest(), head);
        assert!(reopened.snapshot().is_some());
        assert!(c.is_empty());
        assert!(c.finish_in_place().is_none());
        reopened
            .begin_cold_into(&mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        while !c.step(&mut b, 1).unwrap_or_else(|_| panic!()) {}
        let (store, snapshot) = c.checked_in_place().unwrap().unwrap_or_else(|_| panic!());
        assert_eq!(store.arena.head_digest(), head);
        assert_eq!(snapshot.revision(), 1);
        assert!(c.is_empty());
    }
    #[test]
    fn consuming_compatibility_wrappers_use_the_same_authenticated_continuation() {
        let mut store = ready();
        let head = store.arena.head_digest();
        let record = store.state.take().unwrap().record;
        let mut cold =
            Cold::check_record(store, record, transfer(), 1).unwrap_or_else(|_| panic!());
        let mut b = Buffers::empty();
        while !cold.step(&mut b, 1).unwrap_or_else(|_| panic!()) {}
        let (store, snapshot) = cold.checked().unwrap_or_else(|_| panic!());
        assert_eq!(store.arena.head_digest(), head);
        assert_eq!(snapshot.revision(), 1);
    }
    #[test]
    fn read_acquisition_refusal_clears_only_staged_metadata_and_returns_the_exact_store() {
        let mut store = ready();
        let head = store.arena.head_digest();
        let record = store.state.take().unwrap().record;
        let mut cold = Cold::empty();
        let rejected = Cold::check_record_into(store, record, &mut cold, transfer(), 0)
            .err()
            .unwrap();
        assert!(matches!(rejected.error, Failure::Policy(Fault::Clock)));
        assert_eq!(rejected.owner.arena.head_digest(), head);
        assert!(rejected.owner.poisoned());
        assert!(cold.is_empty());
        assert!(cold.record.is_none());
        assert!(cold.object.is_none());
        assert!(cold.transfer.is_none());
        assert!(cold.finish_in_place().is_none());
        ready()
            .begin_cold_into(&mut cold, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        assert!(!cold.is_empty());
        assert!(cold.abandon_in_place().is_some());
    }
    fn virgin_rom() -> Stored<Disk> {
        let mut put = format()
            .begin_put(ROM_ROOT.len() as u64, digest(ROM_ROOT), transfer(), 1)
            .unwrap_or_else(|_| panic!());
        put.write_chunk(ROM_ROOT, 1).unwrap_or_else(|_| panic!());
        let mut read = put.seal(1).unwrap_or_else(|_| panic!());
        let mut b = [0; 4096];
        let n = read.remaining() as usize;
        read.read_chunk(&mut b[..n], 1).unwrap_or_else(|_| panic!());
        read.finish().unwrap_or_else(|_| panic!())
    }
    #[test]
    fn initial_mode_has_no_placeholder_state_and_authenticates_before_building_the_record() {
        let v = virgin_rom();
        let mut c = Cold::empty();
        let mut b = Buffers::empty();
        Cold::check_initial_into(v.store, v.object, &mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        assert!(c.record.is_none() && c.replay.is_none());
        assert!(matches!(c.owner, Some(Owner::Store(_))));
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        assert!(c.record.is_none() && c.replay.is_none());
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        assert!(c.pending_completion && c.replay.is_none());
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        assert!(c.phase == Phase::InitialRecord);
        assert!(c.record.is_none() && c.replay.is_some());
        assert!(c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        let mut next = None;
        let store = c
            .checked_into(&mut next)
            .unwrap()
            .unwrap_or_else(|_| panic!());
        let next = next.unwrap();
        assert_eq!(next.revision(), 1);
        assert_eq!(next.replay.utc_floor(), 0);
        assert!(next.candidate().is_none());
        assert!(store.arena.published_metadata().is_none());
    }
    #[test]
    fn foreign_or_missing_rom_and_changed_completed_bytes_never_initialize_replay() {
        let v = virgin_rom();
        let wrong = Object::checked(v.object.start(), v.object.length(), [9; 32]).unwrap();
        let head = v.store.arena.head_digest();
        let mut c = Cold::empty();
        let rejected = Cold::check_initial_into(v.store, wrong, &mut c, transfer(), 1)
            .err()
            .unwrap();
        assert_eq!(rejected.owner.arena.head_digest(), head);
        assert!(c.is_empty());
        let missing = Object::checked(7000, ROM_ROOT.len() as u64, digest(ROM_ROOT)).unwrap();
        Cold::check_initial_into(rejected.owner, missing, &mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        let mut b = Buffers::empty();
        assert!(c.step(&mut b, 1).is_err());
        assert!(c.replay.is_none() && c.record.is_none());
        let _ = c.abandon_in_place();
        let v = virgin_rom();
        Cold::check_initial_into(v.store, v.object, &mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        b.next_root[0] ^= 1;
        assert!(c.step(&mut b, 1).is_err());
        assert!(c.replay.is_none() && c.record.is_none());
    }
    #[test]
    fn original_cut_is_rechecked_between_readback_and_deferred_crypto() {
        let v = virgin_rom();
        let head = v.store.arena.head_digest();
        let mut c = Cold::empty();
        let mut b = Buffers::empty();
        Cold::check_initial_into(
            v.store,
            v.object,
            &mut c,
            TransferCut::new(1, 4).unwrap(),
            1,
        )
        .unwrap_or_else(|_| panic!());
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        assert!(!c.step(&mut b, 1).unwrap_or_else(|_| panic!()));
        assert!(c.step(&mut b, 4).is_err());
        assert!(c.replay.is_none() && c.record.is_none());
        assert!(c.step(&mut b, 1).is_err());
        assert_eq!(c.abandon_in_place().unwrap().arena.head_digest(), head);
    }
    #[test]
    fn ordinary_invalid_replay_never_falls_back_to_initial_mode() {
        let mut store = ready();
        let mut record = store.state.take().unwrap().record;
        record.replay.fill(0);
        let mut c = Cold::empty();
        let mut b = Buffers::empty();
        Cold::check_record_into(store, record, &mut c, transfer(), 1).unwrap_or_else(|_| panic!());
        let mut failed = false;
        for _ in 0..20 {
            match c.step(&mut b, 1) {
                Err(_) => {
                    failed = true;
                    break;
                }
                Ok(true) => panic!("invalid replay accepted"),
                Ok(false) => (),
            }
        }
        assert!(failed && c.replay.is_none());
        assert!(c.mode == Mode::Ordinary);
        assert!(c.finish_in_place().unwrap().is_err());
    }
    #[test]
    fn checked_destination_refuses_overwrite_without_losing_either_authenticated_state() {
        let store = ready();
        let head = store.arena.head_digest();
        let mut c = store.begin_cold(transfer(), 1).unwrap_or_else(|_| panic!());
        let mut b = Buffers::empty();
        while !c.step(&mut b, 1).unwrap_or_else(|_| panic!()) {}
        let mut next = Some(crate::native_acquisition::tests::retained_snapshot(false));
        let original = next.as_ref().unwrap().candidate();
        let rejected = c.checked_into(&mut next).unwrap().err().unwrap();
        assert_eq!(rejected.owner.arena.head_digest(), head);
        assert_eq!(next.as_ref().unwrap().candidate(), original);
        assert!(c.is_empty());
    }
    #[test]
    fn published_floor_cannot_be_reinitialized_even_without_a_ready_cache() {
        // TEST prior UTC knowledge, not a live-provider qualification. It is
        // persisted through the real canonical checkpoint and journal pointer.
        let mut store = ready();
        let mut next = store.take_snapshot().unwrap();
        let rom = next.record.roots[0].unwrap();
        let root = TrustedRoot::provisioned(ROM_ROOT, binding()).unwrap();
        next.replay =
            ReplayState::restored(&root, *next.replay.roles(), *next.replay.targets(), 1234)
                .unwrap();
        ev_release_trust::checkpoint::encode(&next.replay, &mut next.record.replay);
        next.record.revision += 1;
        let mut b = Buffers::empty();
        next.record.encode(&mut b.checkpoint).unwrap();
        let mut put = store
            .begin_put(
                CHECKPOINT_BYTES as u64,
                digest(&b.checkpoint),
                transfer(),
                1,
            )
            .unwrap_or_else(|_| panic!());
        put.write_chunk(&b.checkpoint, 1)
            .unwrap_or_else(|_| panic!());
        let mut read = put.seal(1).unwrap_or_else(|_| panic!());
        read.read_chunk(&mut b.checkpoint, 1)
            .unwrap_or_else(|_| panic!());
        let mut store = read
            .publish_snapshot(next, 1, &mut b.checkpoint)
            .unwrap_or_else(|_| panic!());
        let head = store.arena.head_digest();
        let retained = store.take_snapshot().unwrap();
        assert_eq!(retained.replay.utc_floor(), 1234);
        let mut c = Cold::empty();
        let rejected = Cold::check_initial_into(store, rom, &mut c, transfer(), 1)
            .err()
            .unwrap();
        assert!(c.is_empty());
        assert_eq!(rejected.owner.arena.head_digest(), head);
        rejected
            .owner
            .begin_cold_into(&mut c, transfer(), 1)
            .unwrap_or_else(|_| panic!());
        while !c.step(&mut b, 1).unwrap_or_else(|_| panic!()) {}
        let restored = c.finish_in_place().unwrap().unwrap_or_else(|_| panic!());
        assert_eq!(restored.snapshot().unwrap().replay.utc_floor(), 1234);
    }
    #[test]
    fn retained_proof_steps_keep_original_cut_and_refuse_late_crypto_without_publication() {
        for local_targets in [false, true] {
            for completion in [false, true] {
                for bad in [9, transfer().end(), u64::MAX] {
                    let store = crate::native_acquisition::tests::retained_store(ready(), true);
                    let old_head = store.arena.published_metadata();
                    let old_replay = *store.snapshot().unwrap().replay();
                    let mut cold = store
                        .begin_cold(transfer(), 10)
                        .unwrap_or_else(|_| panic!("cold"));
                    let mut buffers = Buffers::empty();
                    let mut reached = false;
                    for _ in 0..2048 {
                        let phase = if local_targets {
                            Phase::LocalTargets(1)
                        } else {
                            Phase::LocalRoot(1)
                        };
                        if cold.phase == phase && cold.pending_completion == completion {
                            reached = true;
                            break;
                        }
                        assert!(
                            !cold
                                .step(&mut buffers, 10)
                                .unwrap_or_else(|_| panic!("proof traversal"))
                        );
                    }
                    assert!(reached);
                    assert!(matches!(
                        cold.step(&mut buffers, bad),
                        Err(Failure::Policy(Fault::Clock))
                    ));
                    assert_eq!(cold.transfer.map(TransferCut::end), Some(transfer().end()));
                    let rejected = cold
                        .finish_in_place()
                        .unwrap()
                        .err()
                        .expect("no successful authentication");
                    assert_eq!(rejected.owner.arena.published_metadata(), old_head);
                    assert_eq!(*rejected.owner.snapshot().unwrap().replay(), old_replay);
                    assert!(cold.is_empty());
                }
            }
        }
    }
}
