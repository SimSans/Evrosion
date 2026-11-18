//! Exact production continuation used by the private Root controller. No IO
//! owner is replaced on failure, and no open error selects provisioning.
#![forbid(unsafe_code)]
use crate::{native_acquisition as acq, native_plan::storage::content};
use ev_content_store::{Arena, Backend, Provisioner, TransferCut};
use ev_store::GenerationManifest;
use sha2::{Digest, Sha256};
mod fetch;
mod health;
pub mod progress;
/// Separate whole-volume class: ceil(7950/8)*1024+8192=1,026,048, rounded to2^20.
/// Metadata/RPC/Hello/Stop cuts and CPU quotas are unchanged.
pub const PROVISION_TICKS: u64 = 1 << 20;
pub const INSPECT_TICKS: u64 = 1 << 20;
/// New remote-work class: Inspect +four <=65536 network objects +bounded
/// object readback/image sealing and publication, rounded up once. No existing
/// operation cut is extended, and all actual storage/network RPCs stay<=1024.
pub const FETCH_TICKS: u64 = 1 << 21;
pub const VOLUME_SECTORS: u64 = ev_store::REQUIRED_SECTORS + ev_content_store::OBJECT_SECTORS;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Initialize,
    Inspect,
    Fetch,
    /// Local authenticated health/fault evidence; original Inspect whole cut.
    Local,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Clock,
    Storage,
    Authentication,
    NotBlank,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Idle,
    Opening,
    Scanning,
    Formatting,
    WritingRoot,
    Checkpoint,
    Authenticating,
    Complete,
    Failed,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub revision: u64,
    pub utc_floor: u64,
    pub candidate: u64,
    pub active: u64,
    pub known_good: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Complete(Summary),
    Unformatted,
    Cancelled,
    Failed(Failure),
}
pub struct Rejected<B> {
    pub backend: B,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Empty,
    Start,
    Scan,
    Store,
    Put,
    Read,
    Provision,
    Commit,
    Publish,
    Published,
    Cold,
    Done,
}
#[allow(clippy::large_enum_variant)] // At most one exact IO owner, never a copied Cold/Commit.
enum Io<B: Backend> {
    Backend(B),
    Scan(Provisioner<B>),
    Store(acq::Store<B>),
    Put(acq::Put<B>),
    Read(acq::Read<B>),
}
pub struct Update<B: Backend> {
    phase: Phase,
    io: Option<Io<B>>,
    commit: acq::Commit<B>,
    cold: acq::Cold<B>,
    command: Option<Command>,
    transfer: Option<TransferCut>,
    last: u64,
    stage: Stage,
    remaining: u64,
    outcome: Option<Outcome>,
    root: Option<ev_content_store::Object>,
    settled_auth_refusal: bool,
    clock_fenced: bool,
}
impl<B: Backend> Default for Update<B> {
    fn default() -> Self {
        Self::new()
    }
}
impl<B: Backend> Update<B> {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Empty,
            io: None,
            commit: acq::Commit::empty(),
            cold: acq::Cold::empty(),
            command: None,
            transfer: None,
            last: 0,
            stage: Stage::Idle,
            remaining: 0,
            outcome: None,
            root: None,
            settled_auth_refusal: false,
            clock_fenced: false,
        }
    }
    pub fn busy(&self) -> bool {
        self.io.is_some() || !self.commit.is_empty() || !self.cold.is_empty()
    }
    pub fn active(&self) -> bool {
        self.busy() && self.outcome.is_none()
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }
    pub fn original_cut(&self) -> Option<u64> {
        self.transfer.map(TransferCut::end)
    }
    pub fn scanned(&self) -> u64 {
        if self.command == Some(Command::Initialize) {
            VOLUME_SECTORS - self.remaining
        } else {
            0
        }
    }
    #[allow(clippy::result_large_err)] // Exact backend returned on refusal.
    pub fn begin(&mut self, backend: B, command: Command, now: u64) -> Result<(), Rejected<B>> {
        let span = match command {
            Command::Initialize => PROVISION_TICKS,
            Command::Inspect | Command::Local => INSPECT_TICKS,
            Command::Fetch => FETCH_TICKS,
        };
        let transfer = now
            .checked_add(span)
            .filter(|end| *end != u64::MAX)
            .and_then(|end| TransferCut::new(now, end).ok());
        let regressed = now < self.last;
        self.last = self.last.max(now);
        if self.busy() || regressed || transfer.is_none() {
            return Err(Rejected { backend });
        }
        self.command = Some(command);
        self.transfer = transfer;
        self.outcome = None;
        self.root = None;
        self.settled_auth_refusal = false;
        self.clock_fenced = false;
        self.phase = Phase::Start;
        self.io = Some(Io::Backend(backend));
        self.remaining = if command == Command::Initialize {
            VOLUME_SECTORS
        } else {
            0
        };
        self.stage = if command == Command::Initialize {
            Stage::Scanning
        } else {
            Stage::Opening
        };
        Ok(())
    }
    fn observe(&mut self, now: u64) -> bool {
        if now < self.last || self.transfer.is_none_or(|t| now >= t.end()) || now == u64::MAX {
            self.clock_fenced = true;
            self.last = self.last.max(now);
            if !matches!(self.outcome, Some(Outcome::Failed(_))) {
                self.fail(Failure::Clock);
            }
            return false;
        }
        self.last = now;
        true
    }
    fn fail(&mut self, reason: Failure) {
        self.outcome = Some(Outcome::Failed(reason));
        self.stage = Stage::Failed;
    }
    fn authentication_failed(&mut self, error: acq::Failure<B::Error>) {
        self.settled_auth_refusal = matches!(self.command, Some(Command::Inspect | Command::Fetch))
            && matches!(
                error,
                acq::Failure::Policy(
                    acq::Fault::Root
                        | acq::Fault::Metadata
                        | acq::Fault::Checkpoint
                        | acq::Fault::Candidate
                ) | acq::Failure::Storage(ev_content_store::Error::Hash)
            );
        self.fail(Failure::Authentication);
    }
    /// Fresh actual read after the synchronous step and before success/restore.
    pub fn observe_after(&mut self, now: u64) {
        if self.busy() {
            self.observe(now);
        }
    }
    fn backend(&mut self) -> B {
        match self.io.take().unwrap() {
            Io::Backend(b) => b,
            _ => unreachable!("internal update Backend phase"),
        }
    }
    fn store(&mut self) -> acq::Store<B> {
        match self.io.take().unwrap() {
            Io::Store(s) => s,
            _ => unreachable!("internal update Store phase"),
        }
    }
    fn put(&mut self) -> acq::Put<B> {
        match self.io.take().unwrap() {
            Io::Put(p) => p,
            _ => unreachable!("internal update Put phase"),
        }
    }
    fn read(&mut self) -> acq::Read<B> {
        match self.io.take().unwrap() {
            Io::Read(r) => r,
            _ => unreachable!("internal update Read phase"),
        }
    }
    #[inline(never)]
    fn start(&mut self, now: u64) {
        let backend = self.backend();
        let transfer = self.transfer.unwrap();
        if self.command == Some(Command::Initialize) {
            match Provisioner::new(backend, creation_manifest(), transfer) {
                Ok(p) => {
                    self.io = Some(Io::Scan(p));
                    self.phase = Phase::Scan;
                }
                Err(r) => {
                    self.io = Some(Io::Backend(r.backend));
                    self.fail(Failure::Storage);
                }
            }
        } else {
            match Arena::open(
                backend,
                creation_manifest(),
                transfer.metadata(now).unwrap(),
            ) {
                Ok(arena) => match acq::Store::from_arena(arena).begin_cold_into(
                    &mut self.cold,
                    transfer,
                    now,
                ) {
                    Ok(()) => {
                        self.stage = Stage::Authenticating;
                        self.phase = Phase::Cold;
                    }
                    Err(r) => {
                        self.io = Some(Io::Store(r.owner));
                        self.fail(Failure::Authentication);
                    }
                },
                Err(r) => {
                    if matches!(
                        r.error,
                        ev_content_store::Error::Store(ev_store::Error::Unformatted)
                    ) {
                        self.outcome = Some(Outcome::Unformatted);
                        self.stage = Stage::Complete;
                        self.phase = Phase::Done;
                    } else {
                        self.fail(Failure::Storage);
                    }
                    self.io = Some(Io::Backend(r.backend));
                }
            }
        }
    }
    #[inline(never)]
    fn format(&mut self, now: u64) {
        let Some(Io::Scan(p)) = self.io.take() else {
            unreachable!()
        };
        match p.finish(self.transfer.unwrap().metadata(now).unwrap()) {
            Ok(arena) => {
                self.io = Some(Io::Store(acq::Store::from_arena(arena)));
                self.phase = Phase::Store;
                self.stage = Stage::WritingRoot;
            }
            Err(r) => {
                self.io = Some(Io::Backend(r.backend));
                self.fail(Failure::Storage);
            }
        }
    }
    #[inline(never)]
    fn reserve_root(&mut self, now: u64) {
        let store = self.store();
        match store.begin_put(
            acq::ROM_ROOT.len() as u64,
            Sha256::digest(acq::ROM_ROOT).into(),
            self.transfer.unwrap(),
            now,
        ) {
            Ok(p) => {
                self.io = Some(Io::Put(p));
                self.phase = Phase::Put;
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
            }
        }
    }
    #[inline(never)]
    fn seal_root(&mut self, now: u64) {
        let put = self.put();
        match put.seal(now) {
            Ok(r) => {
                self.io = Some(Io::Read(r));
                self.phase = Phase::Read;
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
            }
        }
    }
    #[inline(never)]
    fn finish_root(&mut self) {
        let read = self.read();
        match read.finish() {
            Ok(stored) => {
                self.root = Some(stored.object);
                self.io = Some(Io::Store(stored.store));
                self.phase = Phase::Provision;
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
            }
        }
    }
    #[inline(never)]
    fn provision_root(&mut self, now: u64) {
        let store = self.store();
        match store.provision_into(
            self.root.unwrap(),
            &mut self.commit,
            self.transfer.unwrap(),
            now,
        ) {
            Ok(()) => {
                self.phase = Phase::Commit;
                self.stage = Stage::Checkpoint;
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
            }
        }
    }
    #[inline(never)]
    fn publish(&mut self, b: &mut acq::Buffers, now: u64) {
        match self.commit.publish_step(now, &mut b.checkpoint) {
            Ok(()) => self.phase = Phase::Published,
            Err(_) => self.fail(Failure::Storage),
        }
    }
    #[inline(never)]
    fn finish_publish(&mut self) {
        if let Some(store) = self.commit.take_published() {
            self.completed(&store);
            self.io = Some(Io::Store(store));
            self.phase = Phase::Done;
        } else {
            self.fail(Failure::Storage);
        }
    }
    #[inline(never)]
    fn finish_cold(&mut self) {
        match self.cold.finish_in_place() {
            Some(Ok(store)) => {
                self.completed(&store);
                self.io = Some(Io::Store(store));
                self.phase = Phase::Done;
            }
            Some(Err(r)) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
            }
            None => self.fail(Failure::Authentication),
        }
    }
    /// One canonical8-sector scan,4KiB data step, or bounded metadata operation.
    /// Workspaces stay resident even while trust verification calls cryptography.
    #[inline(never)]
    pub fn step(&mut self, b: &mut acq::Buffers, now: u64) {
        if !self.active() || !self.observe(now) {
            return;
        }
        match self.phase {
            Phase::Start => self.start(now),
            Phase::Scan => {
                let Some(Io::Scan(p)) = self.io.as_mut() else {
                    unreachable!()
                };
                if p.remaining() == 0 {
                    self.format(now);
                } else {
                    let result = p.scan(self.transfer.unwrap().child(now, 1024).unwrap());
                    self.remaining = p.remaining();
                    match result {
                        Ok(()) => {
                            self.remaining = p.remaining();
                            if self.remaining == 0 {
                                self.stage = Stage::Formatting;
                            }
                        }
                        Err(e) => self.fail(if matches!(e, ev_content_store::Error::NotBlank) {
                            Failure::NotBlank
                        } else {
                            Failure::Storage
                        }),
                    }
                }
            }
            Phase::Store => self.reserve_root(now),
            Phase::Put => {
                let Some(Io::Put(p)) = self.io.as_mut() else {
                    unreachable!()
                };
                if p.remaining() == 0 {
                    self.seal_root(now);
                } else if p.write_chunk(acq::ROM_ROOT, now).is_err() {
                    self.fail(Failure::Storage);
                }
            }
            Phase::Read => {
                let Some(Io::Read(r)) = self.io.as_mut() else {
                    unreachable!()
                };
                if r.remaining() == 0 {
                    self.finish_root();
                } else if r.read_chunk(&mut b.chunk, now).is_err() {
                    self.fail(Failure::Storage);
                }
            }
            Phase::Commit => match self.commit.step(b, now) {
                Ok(true) => self.phase = Phase::Publish,
                Ok(false) => (),
                Err(_) => self.fail(Failure::Storage),
            },
            Phase::Provision => self.provision_root(now),
            Phase::Publish => self.publish(b, now),
            Phase::Published => self.finish_publish(),
            Phase::Cold => match self.cold.step(b, now) {
                Ok(true) => self.finish_cold(),
                Ok(false) => (),
                Err(error) => self.authentication_failed(error),
            },
            Phase::Empty | Phase::Done => (),
        }
    }
    fn completed(&mut self, store: &acq::Store<B>) {
        let s = store.snapshot().unwrap();
        self.outcome = Some(Outcome::Complete(Summary {
            revision: s.revision(),
            utc_floor: s.replay().utc_floor(),
            candidate: s.candidate().map_or(0, |v| v.version),
            active: s.active().map_or(0, |v| v.version),
            known_good: s.known_good().map_or(0, |v| v.version),
        }));
        self.stage = Stage::Complete;
    }
    /// Failed owners never reach this restore boundary; actual poison remains.
    pub fn take_completed(&mut self) -> Option<B> {
        if !matches!(
            self.outcome,
            Some(Outcome::Complete(_) | Outcome::Unformatted | Outcome::Cancelled)
        ) {
            return None;
        }
        match self.io.take()? {
            Io::Store(s) => {
                self.phase = Phase::Empty;
                Some(s.into_arena().into_backend())
            }
            Io::Backend(b) => {
                self.phase = Phase::Empty;
                Some(b)
            }
            other => {
                self.io = Some(other);
                None
            }
        }
    }
    pub fn snapshot_into(&mut self, target: &mut Option<acq::Snapshot>) -> bool {
        if !matches!(self.outcome, Some(Outcome::Complete(_))) {
            return false;
        }
        match self.io.as_mut() {
            Some(Io::Store(store)) => store.snapshot_into(target),
            _ => false,
        }
    }
    /// A completed cold authentication can feed the actual image continuation
    /// without returning/reopening or duplicating the sole Backend. These are
    /// local retained objects, never a new remote acceptance decision.
    pub fn retained_snapshot(&self) -> Option<&acq::Snapshot> {
        if !matches!(self.outcome, Some(Outcome::Complete(_))) {
            return None;
        }
        match self.io.as_ref() {
            Some(Io::Store(store)) => store.snapshot(),
            _ => None,
        }
    }
    #[inline(never)]
    pub fn begin_retained_read(&mut self, content: acq::Content, now: u64) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        let member = self.retained_snapshot().is_some_and(|s| {
            [s.candidate(), s.active(), s.known_good()]
                .into_iter()
                .flatten()
                .any(|c| c == content)
        });
        if !member || self.phase != Phase::Done {
            return Err(Failure::Authentication);
        }
        match self
            .store()
            .begin_read(content.object, self.transfer.unwrap(), now)
        {
            Ok(read) => {
                self.io = Some(Io::Read(read));
                self.root = Some(content.object);
                Ok(())
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
    pub fn retained_remaining(&self) -> Option<u64> {
        match self.io.as_ref() {
            Some(Io::Read(read)) if matches!(self.outcome, Some(Outcome::Complete(_))) => {
                Some(read.remaining())
            }
            _ => None,
        }
    }
    #[inline(never)]
    pub fn read_retained_chunk(&mut self, out: &mut [u8], now: u64) -> Result<usize, Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.retained_remaining().is_none() {
            return Err(Failure::Authentication);
        }
        let Some(Io::Read(read)) = self.io.as_mut() else {
            return Err(Failure::Authentication);
        };
        match read.read_chunk(out, now) {
            Ok(n) => Ok(n),
            Err(_) => {
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
    #[inline(never)]
    pub fn finish_retained_read(&mut self, now: u64) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.retained_remaining() != Some(0) {
            return Err(Failure::Authentication);
        }
        match self.read().finish() {
            Ok(stored) => {
                let valid = Some(stored.object) == self.root;
                self.io = Some(Io::Store(stored.store));
                self.root = None;
                if valid {
                    Ok(())
                } else {
                    self.fail(Failure::Authentication);
                    Err(Failure::Authentication)
                }
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
                Err(Failure::Authentication)
            }
        }
    }
    /// A semantic refusal is not unresolved IO. Only terminal read-only
    /// NotBlank or authenticated-read rejection can reach this boundary. No
    /// Arena/Store/transport fence is cleared and no mutating error is allowed.
    #[inline(never)]
    pub fn release_settled_refusal(&mut self) -> Option<B> {
        if self.clock_fenced {
            return None;
        }
        if self.outcome == Some(Outcome::Failed(Failure::NotBlank)) && self.phase == Phase::Scan {
            let Some(Io::Scan(provisioner)) = self.io.as_ref() else {
                return None;
            };
            if provisioner.has_unresolved_io() {
                return None;
            }
            let Some(Io::Scan(provisioner)) = self.io.take() else {
                unreachable!()
            };
            self.phase = Phase::Empty;
            return Some(provisioner.into_backend());
        }
        if self.outcome != Some(Outcome::Failed(Failure::Authentication))
            || !self.settled_auth_refusal
        {
            return None;
        }
        let store = if matches!(self.io, Some(Io::Store(_))) {
            Some(self.store())
        } else {
            self.cold.abandon_in_place()
        };
        let store = store?;
        if store.has_unresolved_io() {
            self.io = Some(Io::Store(store));
            return None;
        }
        self.phase = Phase::Empty;
        Some(store.into_arena().into_backend())
    }
    /// Only between completed children; failed/unknown owners remain fenced.
    #[inline(never)]
    pub fn cancel(&mut self) -> bool {
        let prepared = self.command == Some(Command::Fetch)
            && !self.clock_fenced
            && self.commit.has_authorized()
            && matches!(self.outcome, Some(Outcome::Complete(_)))
            && matches!(self.io.as_ref(), Some(Io::Store(store)) if !store.has_unresolved_io());
        if (!self.active() && !prepared) || self.phase == Phase::Published {
            return false;
        }
        if prepared && !self.commit.discard_authorized() {
            return false;
        }
        let backend = if let Some(io) = self.io.take() {
            match io {
                Io::Backend(b) => b,
                Io::Scan(p) => p.into_backend(),
                Io::Store(s) => s.into_arena().into_backend(),
                Io::Put(p) => p.into_backend(),
                Io::Read(r) => r.into_backend(),
            }
        } else {
            let backend = if !self.commit.is_empty() {
                self.commit.abandon_backend()
            } else {
                self.cold.abandon_backend()
            };
            let Some(backend) = backend else {
                self.fail(Failure::Storage);
                return false;
            };
            backend
        };
        self.io = Some(Io::Backend(backend));
        self.phase = Phase::Done;
        self.outcome = Some(Outcome::Cancelled);
        self.stage = Stage::Complete;
        true
    }
}
/// Stable creation identity excludes current executable/startup/banks/candidates.
pub fn creation_manifest() -> GenerationManifest {
    let mut h = Sha256::new();
    h.update(b"evrosion.root.update.namespace.v1\0");
    h.update(acq::HELLO_APP);
    h.update(acq::binding().namespace);
    let namespace = h.finalize().into();
    let mut h = Sha256::new();
    h.update(b"evrosion.root.update.volume.v1\0");
    h.update(ev_content_store::FORMAT_ABI);
    h.update(acq::ROM_ROOT);
    h.update(acq::logical_target_name());
    content::creation_manifest(namespace, h.finalize().into()).unwrap()
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
