//! Tick-sized work with the same affine backend retained by value. These
//! adapters reuse the borrowed protocol; they never reconstruct cached state.
// Failure carries the exact live arena/IO owner. Boxing or dropping it would
// defeat the no-heap ownership boundary these consuming transitions provide.
#![allow(clippy::result_large_err)]
use crate::*;

/// A failed consuming transition retains its actual arena, including poison,
/// append high-water and published head. It is not a fresh/open-ready backend.
pub struct RejectedArena<B: Backend> {
    pub arena: Arena<B>,
    pub error: Error<B::Error>,
}
pub struct OwnedStage<B: Backend> {
    arena: Arena<B>,
    object: Object,
    transfer: TransferCut,
    written: u64,
    hash: Sha256,
}
pub struct OwnedReader<B: Backend> {
    arena: Arena<B>,
    object: Object,
    transfer: TransferCut,
    read: u64,
    hash: Sha256,
}
pub struct OwnedVerified<B: Backend> {
    arena: Arena<B>,
    object: Object,
    transfer: TransferCut,
}
impl<B: Backend> Arena<B> {
    pub fn begin_owned(
        mut self,
        expected: [u8; 32],
        length: u64,
        hash: [u8; 32],
        transfer: TransferCut,
        cut: MetadataCut,
    ) -> Result<OwnedStage<B>, RejectedArena<B>> {
        let result = self
            .begin(expected, length, hash, transfer, cut)
            .map(|s| (s.object, s.transfer, s.written, s.hash));
        match result {
            Ok((object, transfer, written, hash)) => Ok(OwnedStage {
                arena: self,
                object,
                transfer,
                written,
                hash,
            }),
            Err(error) => Err(RejectedArena { arena: self, error }),
        }
    }
    pub fn reader_owned(
        mut self,
        object: Object,
        transfer: TransferCut,
        cut: IoCut,
    ) -> Result<OwnedReader<B>, RejectedArena<B>> {
        let result = self
            .reader(object, transfer, cut)
            .map(|r| (r.object, r.transfer, r.read, r.hash));
        match result {
            Ok((object, transfer, read, hash)) => Ok(OwnedReader {
                arena: self,
                object,
                transfer,
                read,
                hash,
            }),
            Err(error) => Err(RejectedArena { arena: self, error }),
        }
    }
}
impl<B: Backend> OwnedStage<B> {
    pub fn remaining(&self) -> u64 {
        self.object.length - self.written
    }
    pub fn reserved_head(&self) -> [u8; 32] {
        self.arena.head_digest()
    }
    /// At a completed step, ownership may return to the controller/UI loop.
    /// A failed/uncertain child remains fenced inside this same arena/backend.
    pub fn write_chunk(&mut self, bytes: &[u8], cut: IoCut) -> Result<(), Error<B::Error>> {
        let mut borrowed = Stage {
            arena: &mut self.arena,
            object: self.object,
            transfer: self.transfer,
            written: self.written,
            hash: core::mem::replace(&mut self.hash, Sha256::new()),
        };
        let result = borrowed.write_chunk(bytes, cut);
        self.written = borrowed.written;
        self.hash = borrowed.hash;
        result
    }
    // Fuse this ownership wrapper with its caller, keeping the original
    // borrowed Stage transition below it. This avoids a second large caller
    // result slot; protocol/IO and actual Arena ownership are unchanged.
    #[inline(always)]
    pub fn seal(mut self, cut: IoCut) -> Result<OwnedReader<B>, RejectedArena<B>> {
        let result = Stage {
            arena: &mut self.arena,
            object: self.object,
            transfer: self.transfer,
            written: self.written,
            hash: self.hash,
        }
        .seal(cut)
        .map(|r| (r.object, r.transfer, r.read, r.hash));
        match result {
            Ok((object, transfer, read, hash)) => Ok(OwnedReader {
                arena: self.arena,
                object,
                transfer,
                read,
                hash,
            }),
            Err(error) => Err(RejectedArena {
                arena: self.arena,
                error,
            }),
        }
    }
    /// Abandon only this unpublished reservation. The durable high-water and
    /// every uncertain-operation fence survive; no extent becomes reusable.
    pub fn abandon(self) -> Arena<B> {
        self.arena
    }
}
impl<B: Backend> OwnedReader<B> {
    /// Expected immutable reservation identity only. Full read/hash completion
    /// is still required to produce OwnedVerified; this grants no trust.
    pub fn expected_object(&self) -> Object {
        self.object
    }
    pub fn remaining(&self) -> u64 {
        self.object.length - self.read
    }
    pub fn read_chunk(&mut self, out: &mut [u8], cut: IoCut) -> Result<usize, Error<B::Error>> {
        let mut borrowed = Reader {
            arena: &mut self.arena,
            object: self.object,
            transfer: self.transfer,
            read: self.read,
            hash: core::mem::replace(&mut self.hash, Sha256::new()),
        };
        let result = borrowed.read_chunk(out, cut);
        self.read = borrowed.read;
        self.hash = borrowed.hash;
        result
    }
    pub fn finish(mut self) -> Result<OwnedVerified<B>, RejectedArena<B>> {
        let result = Reader {
            arena: &mut self.arena,
            object: self.object,
            transfer: self.transfer,
            read: self.read,
            hash: self.hash,
        }
        .finish()
        .map(|v| (v.object, v.transfer));
        match result {
            Ok((object, transfer)) => Ok(OwnedVerified {
                arena: self.arena,
                object,
                transfer,
            }),
            Err(error) => Err(RejectedArena {
                arena: self.arena,
                error,
            }),
        }
    }
    pub fn abandon(self) -> Arena<B> {
        self.arena
    }
}
impl<B: Backend> OwnedVerified<B> {
    pub fn object(&self) -> Object {
        self.object
    }
    pub fn current_head(&self) -> [u8; 32] {
        self.arena.head_digest()
    }
    /// Complete hash readback remains separate from publisher/time authority.
    pub fn release(self) -> (Arena<B>, Object) {
        (self.arena, self.object)
    }
    pub fn publish(
        mut self,
        expected: [u8; 32],
        cut: MetadataCut,
    ) -> Result<(Arena<B>, Object), RejectedArena<B>> {
        let result = stream::Verified {
            arena: &mut self.arena,
            object: self.object,
            transfer: self.transfer,
        }
        .publish(expected, cut);
        match result {
            Ok(object) => Ok((self.arena, object)),
            Err(error) => Err(RejectedArena {
                arena: self.arena,
                error,
            }),
        }
    }
}
