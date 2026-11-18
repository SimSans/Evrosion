//! Bounded, persistent userspace workspace over one exclusively owned region.
//!
//! This crate supplies storage, not capabilities. The integrating service must
//! authenticate each route, serialize its persistent operation IDs, and retain
//! device/window ownership through uncertain completion. Existing File-v1 and
//! Store-v2 regions are never interpreted, formatted or migrated here.
#![no_std]
#![forbid(unsafe_code)]

mod codec;
mod engine;
pub use engine::{CommitVerifier, Dataset, ProvisionProgress, Provisioning, VerificationProgress};
pub use ev_store::{Sector, SectorIo};

pub const FORMAT_VERSION: u16 = 1;
pub const MAX_ENTRIES: usize = 256;
pub const MAX_DIRECTORIES: usize = 32;
pub const MAX_DEPTH: usize = 8;
pub const MAX_NAME: usize = 96;
pub const CHUNK_BYTES: usize = 4096;
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const USABLE_BYTES: u64 = 64 * 1024 * 1024;
pub const STAGING_RESERVE_BYTES: u64 = 2 * 1024 * 1024;
pub const USABLE_CHUNKS: u32 = (USABLE_BYTES / CHUNK_BYTES as u64) as u32;
pub const POOL_CHUNKS: u32 = USABLE_CHUNKS + (STAGING_RESERVE_BYTES / CHUNK_BYTES as u64) as u32;
pub const CATALOG_SECTORS: u64 = MAX_ENTRIES as u64 / 2;
pub const DATA_START: u64 = 2 + 2 * CATALOG_SECTORS;
pub const CHUNK_SECTORS: u64 = 9;
pub const REQUIRED_SECTORS: u64 = DATA_START + POOL_CHUNKS as u64 * CHUNK_SECTORS;
pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatasetId([u8; 16]);
impl DatasetId {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        bytes.iter().any(|b| *b != 0).then_some(Self(bytes))
    }
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Descriptive identity only. Slot zero/generation one is the implicit root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId {
    pub slot: u16,
    pub generation: u64,
}
impl ObjectId {
    pub const ROOT: Self = Self {
        slot: 0,
        generation: 1,
    };
    pub const fn new(slot: u16, generation: u64) -> Option<Self> {
        if slot as usize <= MAX_ENTRIES
            && generation != 0
            && generation != u64::MAX
            && (slot != 0 || generation == 1)
        {
            Some(Self { slot, generation })
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRequest {
    caller: [u8; 16],
    lease_epoch: u64,
    nonce: u64,
}
impl ClientRequest {
    /// Trusted adapter supplies authenticated incarnation/lease identity. These
    /// bytes never authenticate an app and must not be copied from its packet.
    pub fn new(caller: [u8; 16], lease_epoch: u64, nonce: u64) -> Option<Self> {
        (caller.iter().any(|b| *b != 0)
            && lease_epoch != 0
            && lease_epoch != u64::MAX
            && nonce != 0
            && nonce != u64::MAX)
            .then_some(Self {
                caller,
                lease_epoch,
                nonce,
            })
    }
    pub const fn caller(self) -> [u8; 16] {
        self.caller
    }
    pub const fn lease_epoch(self) -> u64 {
        self.lease_epoch
    }
    pub const fn nonce(self) -> u64 {
        self.nonce
    }
}

/// Global operation IDs are allocated ONLY by the serialized trusted owner.
/// Client correlation nonces are separately scoped and may repeat across apps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId {
    value: u64,
    request: Option<ClientRequest>,
}
impl OperationId {
    pub const fn new(value: u64) -> Option<Self> {
        if value != 0 && value != u64::MAX {
            Some(Self {
                value,
                request: None,
            })
        } else {
            None
        }
    }
    pub const fn get(self) -> u64 {
        self.value
    }
    pub const fn for_request(mut self, request: ClientRequest) -> Self {
        self.request = Some(request);
        self
    }
    pub const fn client_request(self) -> Option<ClientRequest> {
        self.request
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name {
    bytes: [u8; MAX_NAME],
    length: u8,
}
impl Name {
    /// UTF-8 byte-exact names; no implicit normalization/case folding. Slash,
    /// controls, empty names and dot/dot-dot are rejected before device effects.
    pub fn new(value: &str) -> Option<Self> {
        if value.is_empty()
            || value.len() > MAX_NAME
            || matches!(value, "." | "..")
            || value
                .chars()
                .any(|c| c == '/' || c == '\\' || c.is_control())
        {
            return None;
        }
        let mut result = Self::EMPTY;
        result.bytes[..value.len()].copy_from_slice(value.as_bytes());
        result.length = value.len() as u8;
        Some(result)
    }
    const EMPTY: Self = Self {
        bytes: [0; MAX_NAME],
        length: 0,
    };
    pub fn as_str(&self) -> &str {
        // Construction and disk decoding validate UTF-8 before publication.
        core::str::from_utf8(self.as_bytes()).expect("validated workspace name")
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    File = 1,
    Directory = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub id: ObjectId,
    pub parent: ObjectId,
    pub kind: Kind,
    /// True for direct removal. A descendant of a trashed directory is hidden
    /// even if its own bit is false; use Dataset::is_trashed for effective state.
    pub directly_trashed: bool,
    pub revision: u64,
    pub length: u64,
    pub sha256: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptKind {
    Created = 1,
    Renamed,
    Moved,
    Trashed,
    Restored,
    Purged,
    Begun,
    Chunk,
    Committed,
    Aborted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub operation: OperationId,
    pub sequence: u64,
    pub kind: ReceiptKind,
    pub object: ObjectId,
    pub object_revision: u64,
    pub namespace_revision: u64,
    pub stage: u64,
    /// Confirmed stage offset, or committed exact file length.
    pub bytes: u64,
    pub replayed: bool,
}

/// Integration assertion, NOT kernel authority or evidence of hardware stop.
/// The trusted owner must revoke/retire old grants and fence future delegation
/// of this exact object for the entire purge. The epoch is local audit data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimFence {
    pub object: ObjectId,
    pub namespace_revision: u64,
    pub authority_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageInfo {
    pub id: u64,
    pub object: ObjectId,
    pub expected_revision: u64,
    pub length: u64,
    pub written: u64,
    pub sha256: Digest,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    NeedsRecovery,
    InvalidDeadline,
    Capacity,
    NotBlank,
    Unformatted,
    ProvisioningRequired,
    Unsupported,
    Corrupt,
    InvalidName,
    InvalidObject,
    StaleObject,
    NotDirectory,
    NotFile,
    Hidden,
    Collision,
    Depth,
    DirectoryLimit,
    EntryLimit,
    NoSpace,
    Busy,
    Conflict,
    StaleOperation,
    OutOfOrder,
    Exhausted,
    InvalidChunk,
    InvalidStage,
    Incomplete,
    HashMismatch,
    NotTrashed,
    NotEmpty,
    FenceRequired,
}
pub struct RejectedDevice<D: SectorIo> {
    pub device: D,
    pub error: Error<D::Error>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    generation: u64,
    kind: u8,
    trashed: bool,
    parent: ObjectId,
    revision: u64,
    name: Name,
    length: u64,
    start: u32,
    chunks: u32,
    stamp: u64,
    digest: Digest,
}
impl Entry {
    const EMPTY: Self = Self {
        generation: 0,
        kind: 0,
        trashed: false,
        parent: ObjectId::ROOT,
        revision: 0,
        name: Name::EMPTY,
        length: 0,
        start: 0,
        chunks: 0,
        stamp: 0,
        digest: [0; 32],
    };
    fn id(&self, index: usize) -> ObjectId {
        ObjectId {
            slot: (index + 1) as u16,
            generation: self.generation,
        }
    }
    fn metadata(&self, index: usize) -> Metadata {
        Metadata {
            id: self.id(index),
            parent: self.parent,
            kind: if self.kind == 1 {
                Kind::File
            } else {
                Kind::Directory
            },
            directly_trashed: self.trashed,
            revision: self.revision,
            length: self.length,
            sha256: self.digest,
        }
    }
}

/// Allocate this once in caller-owned resident storage (a target static owner,
/// or host heap). Open/format borrow it; no API returns a catalog/document-sized
/// value. Chunk I/O is bounded and uses this resident verification buffer.
pub struct Scratch {
    entries: [Entry; MAX_ENTRIES],
    sector: Sector,
    chunk: [u8; CHUNK_BYTES],
}
impl Scratch {
    pub const fn empty() -> Self {
        Self {
            entries: [Entry::EMPTY; MAX_ENTRIES],
            sector: [0; 512],
            chunk: [0; CHUNK_BYTES],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stage {
    id: u64,
    object: ObjectId,
    expected: u64,
    length: u64,
    written: u64,
    start: u32,
    chunks: u32,
    digest: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Root {
    dataset: DatasetId,
    sequence: u64,
    namespace: u64,
    catalog: u8,
    catalog_digest: Digest,
    last_operation: u64,
    fingerprint: Digest,
    receipt: Option<Receipt>,
    stage: Option<Stage>,
}

fn chunks_for(bytes: u64) -> u32 {
    bytes.div_ceil(CHUNK_BYTES as u64) as u32
}
fn valid_deadline<E>(deadline: u64) -> Result<(), Error<E>> {
    if deadline == 0 || deadline == u64::MAX {
        Err(Error::InvalidDeadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
