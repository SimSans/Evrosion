//! Affine bounded object IO over the canonical content-store implementation.
//! Unknown mutations keep that exact Arena/Backend and its poison/high-water.
#![allow(clippy::result_large_err)] // No heap; every error retains the actual owner.
use super::*;
use ev_content_store::{Arena, Backend, OwnedReader, OwnedStage, TransferCut};
use ev_release_trust::verifier::ReplayState;
pub struct Snapshot {
    pub(super) record: codec::Record,
    pub(super) replay: ReplayState,
}
impl Snapshot {
    pub fn revision(&self) -> u64 {
        self.record.revision
    }
    pub fn replay(&self) -> &ReplayState {
        &self.replay
    }
    pub fn candidate(&self) -> Option<Content> {
        self.record.candidate
    }
    pub fn active(&self) -> Option<Content> {
        self.record.active
    }
    pub fn known_good(&self) -> Option<Content> {
        self.record.known_good
    }
    /// Exact last continuity material retained by authenticated cold state.
    /// Its Object identity is not a substitute for reading/checking its bytes.
    pub fn authorization(&self, content: Content) -> Option<Authorization> {
        self.record.authorization(content)
    }
    pub fn current_root_object(&self) -> Option<Object> {
        self.record.roots.iter().flatten().last().copied()
    }
    /// Authenticated immutable metadata reference: Targets, Snapshot, Timestamp.
    /// Callers must still read and verify the object's actual bytes.
    pub fn metadata_object(&self, index: usize) -> Option<Object> {
        self.record.metadata.get(index).copied().flatten()
    }
}
pub struct Store<B: Backend> {
    pub(super) arena: Arena<B>,
    pub(super) state: Option<Snapshot>,
    pub(super) last: u64,
    pub(super) fenced: bool,
}
pub enum Failure<E> {
    Storage(ev_content_store::Error<E>),
    Policy(Fault),
}
pub struct Rejected<B: Backend> {
    pub owner: Store<B>,
    pub error: Failure<B::Error>,
}
pub struct Stored<B: Backend> {
    pub store: Store<B>,
    pub object: Object,
}
/// Affine publication prepared only by the coordinator's authenticated path.
/// Completion persists that prior decision; it creates no new fresh-time claim.
pub struct Publication<B: Backend> {
    pub(super) read: Read<B>,
    pub(super) next: Snapshot,
}
impl<B: Backend> Publication<B> {
    /// Cancel only the unpublished checkpoint reservation. The exact Arena,
    /// append high-water and any uncertainty fence remain with its real owner.
    pub fn abandon(self) -> Store<B> {
        self.read.abandon()
    }
    pub fn publish(
        self,
        now: u64,
        private_buffer: &mut [u8; CHECKPOINT_BYTES],
    ) -> Result<Store<B>, Rejected<B>> {
        self.read.publish_snapshot(self.next, now, private_buffer)
    }
}
pub struct Put<B: Backend> {
    stage: OwnedStage<B>,
    state: Option<Snapshot>,
    transfer: TransferCut,
    last: u64,
    fenced: bool,
    failed: bool,
}
pub struct Read<B: Backend> {
    // Exactly one actual owner. During the synchronous canonical transition
    // its local Verified owns that same Arena; no callback/yield exposes a gap.
    reader: Option<OwnedReader<B>>,
    arena: Option<Arena<B>>,
    state: Option<Snapshot>,
    transfer: TransferCut,
    last: u64,
    fenced: bool,
    failed: bool,
}
impl<B: Backend> Store<B> {
    /// Actual Arena owner only. An ordinary open error cannot call this with a
    /// replacement backend: the caller must retain the rejected owner instead.
    /// No trusted state is inferred until authenticated cold open completes.
    pub fn from_arena(arena: Arena<B>) -> Self {
        Self {
            arena,
            state: None,
            last: 0,
            fenced: false,
        }
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.state.as_ref()
    }
    /// Extract already-authenticated state without cloning or reinjection.
    /// Returning the Backend never makes this snapshot a later write decision.
    pub fn take_snapshot(&mut self) -> Option<Snapshot> {
        self.state.take()
    }
    /// Same extraction into resident storage; an occupied destination refuses.
    pub fn snapshot_into(&mut self, target: &mut Option<Snapshot>) -> bool {
        if target.is_some() || self.state.is_none() {
            return false;
        }
        *target = self.state.take();
        true
    }
    pub fn into_arena(self) -> Arena<B> {
        self.arena
    }
    pub fn poisoned(&self) -> bool {
        self.fenced || self.arena.poisoned()
    }
    pub fn has_unresolved_io(&self) -> bool {
        self.poisoned() || self.arena.has_unresolved_io()
    }
    pub(super) fn observe(&mut self, now: u64) -> Result<(), Fault> {
        if self.fenced || now == u64::MAX || now < self.last {
            self.fenced = true;
            return Err(Fault::Clock);
        }
        self.last = now;
        Ok(())
    }
    pub fn begin_put(
        mut self,
        length: u64,
        hash: [u8; 32],
        transfer: TransferCut,
        now: u64,
    ) -> Result<Put<B>, Rejected<B>> {
        if let Err(e) = self.observe(now) {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(e),
            });
        }
        let cut = match transfer.metadata(now) {
            Ok(v) => v,
            Err(_) => {
                return Err(Rejected {
                    owner: self,
                    error: Failure::Policy(Fault::Clock),
                });
            }
        };
        let expected = self.arena.head_digest();
        match self
            .arena
            .begin_owned(expected, length, hash, transfer, cut)
        {
            Ok(stage) => Ok(Put {
                stage,
                state: self.state,
                transfer,
                last: now,
                fenced: self.fenced,
                failed: false,
            }),
            Err(r) => Err(Rejected {
                owner: Self {
                    arena: r.arena,
                    state: self.state,
                    last: now,
                    fenced: self.fenced,
                },
                error: Failure::Storage(r.error),
            }),
        }
    }
    pub fn begin_read(
        mut self,
        object: Object,
        transfer: TransferCut,
        now: u64,
    ) -> Result<Read<B>, Rejected<B>> {
        if let Err(e) = self.observe(now) {
            return Err(Rejected {
                owner: self,
                error: Failure::Policy(e),
            });
        }
        let cut = match transfer.child(now, 1024) {
            Ok(v) => v,
            Err(_) => {
                return Err(Rejected {
                    owner: self,
                    error: Failure::Policy(Fault::Clock),
                });
            }
        };
        match self.arena.reader_owned(object, transfer, cut) {
            Ok(reader) => Ok(Read {
                reader: Some(reader),
                arena: None,
                state: self.state,
                transfer,
                last: now,
                fenced: self.fenced,
                failed: false,
            }),
            Err(r) => Err(Rejected {
                owner: Self {
                    arena: r.arena,
                    state: self.state,
                    last: now,
                    fenced: self.fenced,
                },
                error: Failure::Storage(r.error),
            }),
        }
    }
}
impl<B: Backend> Put<B> {
    // Same terminal projection as the reviewed Main resource refinement.
    #[inline(always)]
    pub(crate) fn into_backend(self) -> B {
        self.stage.abandon().into_backend()
    }
    pub fn remaining(&self) -> u64 {
        self.stage.remaining()
    }
    pub fn write_chunk(&mut self, bytes: &[u8], now: u64) -> Result<(), Failure<B::Error>> {
        if self.failed || now == u64::MAX || now < self.last {
            self.fenced |= now < self.last || now == u64::MAX;
            self.failed = true;
            return Err(Failure::Policy(Fault::Clock));
        }
        self.last = now;
        let cut = self.transfer.child(now, 1024).map_err(|_| {
            self.failed = true;
            Failure::Policy(Fault::Clock)
        })?;
        self.stage.write_chunk(bytes, cut).map_err(|e| {
            self.failed = true;
            Failure::Storage(e)
        })
    }
    pub fn seal(mut self, now: u64) -> Result<Read<B>, Rejected<B>> {
        if self.failed || now == u64::MAX || now < self.last {
            self.fenced |= now < self.last || now == u64::MAX;
            let owner = self.abandon();
            return Err(Rejected {
                owner,
                error: Failure::Policy(Fault::Phase),
            });
        }
        let cut = match self.transfer.child(now, 1024) {
            Ok(v) => v,
            Err(_) => {
                return Err(Rejected {
                    owner: self.abandon(),
                    error: Failure::Policy(Fault::Clock),
                });
            }
        };
        match self.stage.seal(cut) {
            Ok(reader) => Ok(Read {
                reader: Some(reader),
                arena: None,
                state: self.state,
                transfer: self.transfer,
                last: now,
                fenced: self.fenced,
                failed: false,
            }),
            Err(r) => Err(Rejected {
                owner: Store {
                    arena: r.arena,
                    state: self.state,
                    last: now,
                    fenced: self.fenced,
                },
                error: Failure::Storage(r.error),
            }),
        }
    }
    pub fn abandon(self) -> Store<B> {
        Store {
            arena: self.stage.abandon(),
            state: self.state,
            last: self.last,
            fenced: self.fenced,
        }
    }
}
impl<B: Backend> Read<B> {
    #[inline(always)]
    pub(crate) fn into_backend(self) -> B {
        let arena = if let Some(reader) = self.reader {
            debug_assert!(self.arena.is_none());
            reader.abandon()
        } else {
            self.arena.expect("actual finished reader Arena")
        };
        arena.into_backend()
    }
    /// Metadata for bounded staging of this SAME reader. Not a verified-object
    /// receipt: finish must still authenticate every actual stored body byte.
    pub fn expected_object(&self) -> Option<Object> {
        (!self.failed)
            .then(|| self.reader.as_ref().map(OwnedReader::expected_object))
            .flatten()
    }
    pub fn remaining(&self) -> u64 {
        self.reader.as_ref().map_or(0, OwnedReader::remaining)
    }
    pub fn read_chunk(&mut self, out: &mut [u8], now: u64) -> Result<usize, Failure<B::Error>> {
        if self.failed || now == u64::MAX || now < self.last {
            self.fenced |= now < self.last || now == u64::MAX;
            self.failed = true;
            return Err(Failure::Policy(Fault::Clock));
        }
        self.last = now;
        let cut = self.transfer.child(now, 1024).map_err(|_| {
            self.failed = true;
            Failure::Policy(Fault::Clock)
        })?;
        let result = match self.reader.as_mut() {
            Some(reader) => reader.read_chunk(out, cut).map_err(Failure::Storage),
            None => Err(Failure::Policy(Fault::Phase)),
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish(mut self) -> Result<Stored<B>, Rejected<B>> {
        if self.failed || self.reader.is_none() {
            return Err(Rejected {
                owner: self.abandon(),
                error: Failure::Policy(Fault::Phase),
            });
        }
        match self.reader.take().unwrap().finish() {
            Ok(v) => {
                let (arena, object) = v.release();
                Ok(Stored {
                    store: Store {
                        arena,
                        state: self.state,
                        last: self.last,
                        fenced: self.fenced,
                    },
                    object,
                })
            }
            Err(r) => Err(Rejected {
                owner: Store {
                    arena: r.arena,
                    state: self.state,
                    last: self.last,
                    fenced: self.fenced,
                },
                error: Failure::Storage(r.error),
            }),
        }
    }
    pub fn abandon(mut self) -> Store<B> {
        let arena = if let Some(reader) = self.reader.take() {
            debug_assert!(self.arena.is_none());
            reader.abandon()
        } else {
            self.arena.take().expect("actual finished reader Arena")
        };
        Store {
            arena,
            state: self.state,
            last: self.last,
            fenced: self.fenced,
        }
    }
    pub(super) fn publish_snapshot(
        self,
        next: Snapshot,
        now: u64,
        b: &mut [u8; CHECKPOINT_BYTES],
    ) -> Result<Store<B>, Rejected<B>> {
        self.publish_snapshot_in_place(&mut Some(next), now, b)
    }
    pub(super) fn publish_snapshot_in_place(
        mut self,
        next: &mut Option<Snapshot>,
        now: u64,
        b: &mut [u8; CHECKPOINT_BYTES],
    ) -> Result<Store<B>, Rejected<B>> {
        match self.publish_snapshot_step(next, now, b) {
            Ok(()) => Ok(self.abandon()),
            Err(error) => Err(Rejected {
                owner: self.abandon(),
                error,
            }),
        }
    }
    /// Status-only actual runtime path. Snapshot stays resident above journal
    /// IO. Every outcome restores the exact Arena before returning to Root.
    #[inline(never)]
    pub(super) fn publish_snapshot_step(
        &mut self,
        next: &mut Option<Snapshot>,
        now: u64,
        b: &mut [u8; CHECKPOINT_BYTES],
    ) -> Result<(), Failure<B::Error>> {
        let result = self.publish_snapshot_body(next, now, b);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    #[inline(never)]
    fn publish_snapshot_body(
        &mut self,
        next: &mut Option<Snapshot>,
        now: u64,
        b: &mut [u8; CHECKPOINT_BYTES],
    ) -> Result<(), Failure<B::Error>> {
        if self.failed || self.fenced || now == u64::MAX || now < self.last {
            self.fenced |= now == u64::MAX || now < self.last;
            return Err(Failure::Policy(Fault::Clock));
        }
        let Some(snapshot) = next.as_ref() else {
            return Err(Failure::Policy(Fault::Phase));
        };
        if self.reader.is_none() || self.arena.is_some() {
            return Err(Failure::Policy(Fault::Phase));
        }
        let cut = self
            .transfer
            .metadata(now)
            .map_err(|_| Failure::Policy(Fault::Clock))?;
        self.last = now;
        ev_release_trust::checkpoint::encode(
            &snapshot.replay,
            (&mut b[..1024]).try_into().unwrap(),
        );
        if b[..1024] != snapshot.record.replay || snapshot.record.encode(b).is_err() {
            return Err(Failure::Policy(Fault::Checkpoint));
        }
        let hash = digest(b);
        let verified = match self.reader.take().unwrap().finish() {
            Ok(v) => v,
            Err(r) => {
                self.arena = Some(r.arena);
                return Err(Failure::Storage(r.error));
            }
        };
        if verified.object().length() != CHECKPOINT_BYTES as u64
            || verified.object().sha256() != hash
        {
            let (arena, _) = verified.release();
            self.arena = Some(arena);
            return Err(Failure::Policy(Fault::Checkpoint));
        }
        let expected = verified.current_head();
        match verified.publish(expected, cut) {
            Ok((arena, _)) => {
                self.arena = Some(arena);
                self.state = next.take();
                Ok(())
            }
            Err(r) => {
                self.arena = Some(r.arena);
                Err(Failure::Storage(r.error))
            }
        }
    }
}
