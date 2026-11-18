//! Read-only coexistence with the original File-v1 envelopes in Store-v2.
//!
//! The trusted native Workspace adapter supplies its one exclusively owned
//! LegacyFileIo window/Files endpoint and the ORIGINAL format-creation manifests.
//! Neither a current ABI manifest nor an app packet can select a namespace. The
//! adapter must stop every old writer before constructing this owner, retain
//! actual RPC/window ownership on ambiguous transport failure, and enforce the
//! original protected selection and revocation policy before issuing a route.
//! This module grants no capability and changes no remembered READ policy.
//!
//! Volume/local identity is preserved explicitly: EVRO-USERS-VOL01 / 1 (Notes)
//! or / 2 (Private). File@2 projects these to that same 16-byte dataset field,
//! slot 1/2, generation 1. This is an adapter identity, NEVER a Dataset row or a
//! writable duplicate. Old apps still refuse the new Dataset format. App-private
//! scalar/session-note regions and System are outside this backend's slice.
//!
//! Open never formats, seeds, repairs or recovers media. Store's exact mutable
//! namespace check precedes recovery; the private region wrapper rejects every
//! write/flush without calling the underlying backend. Pending publication is
//! unavailable and requires separate trusted recovery on an owned copy. A
//! device read error fences this owner until native quiescence/reconciliation;
//! reconstructing an aliased backend is not a recovery procedure.
use ev_file::Envelope;
pub use ev_file::desktop::Object;
use ev_store::{GenerationManifest, Sector, SectorIo, Store, desktop::Region};
use ev_userspace_contract::{
    file_v2 as wire,
    workspace::{Deadline, Error as CodecError, ObjectId, Outcome},
};
use sha2::{Digest, Sha256};

pub const ORIGINAL_VOLUME: [u8; 16] = *b"EVRO-USERS-VOL01";
pub const LEGACY_LOGICAL_SECTORS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub volume: [u8; 16],
    pub local: u64,
    pub projected_object: ObjectId,
}
impl Identity {
    pub const fn for_object(object: Object) -> Self {
        let slot = match object {
            Object::Notes => 1,
            Object::Private => 2,
        };
        Self {
            volume: ORIGINAL_VOLUME,
            local: slot as u64,
            projected_object: ObjectId {
                slot,
                generation: 1,
            },
        }
    }
}

/// Original immutable namespace proofs, captured by trusted Root/native code.
/// These values are not accepted from the File@2 wire or inferred from M8's ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalCreation {
    notes: GenerationManifest,
    private: GenerationManifest,
}
impl OriginalCreation {
    /// Exact historical reference constructor from File's desktop actor:
    /// generation1, per-local cohort, unresolved image22/health33 and the
    /// unchanged base bootstrap ABI. This is explicitly NOT the M8 Root/service
    /// ABI. Other constructors remain unavailable unless separately configured
    /// and verified by trusted native code; media bytes never select a profile.
    pub fn reference_desktop() -> Self {
        fn manifest(object: Object) -> GenerationManifest {
            GenerationManifest {
                generation: ev_store::GenerationId::new(1).unwrap(),
                cohort: [object.stable_id() as u8; 32],
                supervisor_image: [0x22; 32],
                abi: ev_userspace_contract::ABI,
                health_contract: [0x33; 32],
                health_version: 1,
                required_checks: 3,
            }
        }
        Self::new(manifest(Object::Notes), manifest(Object::Private)).unwrap()
    }
    pub fn new(notes: GenerationManifest, private: GenerationManifest) -> Option<Self> {
        (notes.valid()
            && private.valid()
            && notes.health_version == 1
            && private.health_version == 1)
            .then_some(Self { notes, private })
    }
    fn manifest(&self, object: Object) -> &GenerationManifest {
        match object {
            Object::Notes => &self.notes,
            Object::Private => &self.private,
        }
    }
}

/// Validated source metadata. The native route retains this exact value from
/// inspect; scalar app fields cannot replace its identity, length or full hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub identity: Identity,
    pub counter: u64,
    pub length: u32,
    pub digest: [u8; 32],
    /// Diagnostic provenance only, never a File@2 operation selector.
    pub global_operation: u64,
}

/// Caller-owned bounded envelope storage; no document or volume is copied to
/// the native stack. The native adapter must census actual linked stack use.
pub struct Scratch {
    bytes: [u8; ev_store::PAYLOAD_BYTES],
}
impl Scratch {
    pub const fn new() -> Self {
        Self {
            bytes: [0; ev_store::PAYLOAD_BYTES],
        }
    }
}
impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Snapshot<'a> {
    pub metadata: Metadata,
    payload: &'a [u8],
}
impl Snapshot<'_> {
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// Every variant means unavailable, never empty/fresh media. A transport error
/// additionally prevents reuse of this owner and its captured window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    Capacity,
    Deadline,
    Unformatted,
    UnknownFormat,
    ForeignNamespace,
    Corrupt,
    RecoveryRequired,
    Envelope,
    Transport,
    Fenced,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    Protocol(CodecError),
    Unavailable(Unavailable),
}

/// One non-Clone backend/window owner. Each operation creates only a temporary
/// exclusive reborrow of ONE region, so two live Store regions cannot alias it.
pub struct Owner<D: SectorIo> {
    backend: D,
    creation: OriginalCreation,
    fenced: bool,
}
impl<D: SectorIo> Owner<D> {
    /// `backend` is the already-authorized logical Files slice (0..14,16..30),
    /// not a raw disk. Native code must exclude every external backend alias.
    pub const fn new(backend: D, creation: OriginalCreation) -> Self {
        Self {
            backend,
            creation,
            fenced: false,
        }
    }
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }
    pub fn inspect<'a>(
        &mut self,
        object: Object,
        deadline: Deadline,
        scratch: &'a mut Scratch,
    ) -> Result<Snapshot<'a>, Unavailable> {
        if self.fenced {
            return Err(Unavailable::Fenced);
        }
        if self.backend.sectors() < LEGACY_LOGICAL_SECTORS {
            return Err(Unavailable::Capacity);
        }
        let result = read_envelope(
            &mut self.backend,
            object,
            self.creation.manifest(object),
            deadline.tick(),
            &mut scratch.bytes,
        );
        let length = match result {
            Ok(length) => length,
            Err(error) => {
                self.fenced |= error == Unavailable::Transport;
                return Err(error);
            }
        };
        let envelope =
            Envelope::decode(&scratch.bytes[..length]).map_err(|_| Unavailable::Envelope)?;
        let payload = envelope.payload();
        Ok(Snapshot {
            metadata: Metadata {
                identity: Identity::for_object(object),
                counter: envelope.counter(),
                length: payload.len() as u32,
                digest: Sha256::digest(payload).into(),
                global_operation: envelope.global_operation(),
            },
            payload,
        })
    }

    /// Serve a complete bounded File@2 Read from the original immutable view.
    /// `expected` is retained native route metadata, not an app's declaration.
    /// The native adapter still authenticates/revokes that route, owns the loan,
    /// captures an actual clock, and retains ambiguous transport ownership.
    /// All non-Read methods return Denied BEFORE any backend/window I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn file2_read(
        &mut self,
        object: Object,
        expected: Metadata,
        request: wire::Request,
        now: u64,
        scratch: &mut Scratch,
        out: &mut [u8],
    ) -> Result<wire::Response, ReadError> {
        request.encode().map_err(ReadError::Protocol)?;
        let wire::Method::Read { offset, length } = request.method else {
            return Ok(refusal(request, Outcome::Denied));
        };
        if !request.deadline.is_live(now) {
            return Ok(refusal(request, Outcome::Cancelled));
        }
        if expected.identity != Identity::for_object(object)
            || request.expected_revision != expected.counter
        {
            return Ok(refusal(request, Outcome::Stale));
        }
        if out.len() < length as usize || out.len() > wire::MAX_CHUNK_BYTES as usize {
            return Err(ReadError::Protocol(CodecError::Bounds));
        }
        let snapshot = self
            .inspect(object, request.deadline, scratch)
            .map_err(ReadError::Unavailable)?;
        if snapshot.metadata != expected {
            return Ok(refusal(request, Outcome::Stale));
        }
        if offset > snapshot.metadata.length {
            return Ok(refusal(request, Outcome::Denied));
        }
        let start = offset as usize;
        let count = (length as usize).min(snapshot.payload.len() - start);
        let chunk = &snapshot.payload[start..start + count];
        // Clear the complete caller loan on success, including empty EOF, so
        // a shorter original read cannot disclose a previous sibling chunk.
        out.fill(0);
        out[..count].copy_from_slice(chunk);
        Ok(wire::Response {
            request_id: request.request_id,
            operation_id: 0,
            outcome: Outcome::Completed,
            revision: snapshot.metadata.counter,
            transfer_id: 0,
            offset,
            length: count as u32,
            file_length: snapshot.metadata.length,
            digest: Sha256::digest(chunk).into(),
        })
    }
}

fn refusal(request: wire::Request, outcome: Outcome) -> wire::Response {
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

enum ReadOnlyError<E> {
    Device(E),
    Blocked,
    Bounds,
}
struct ReadOnlyRegion<'a, D: SectorIo> {
    backend: &'a mut D,
    region: Region,
}
impl<D: SectorIo> SectorIo for ReadOnlyRegion<'_, D> {
    type Error = ReadOnlyError<D::Error>;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, local: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        let wire = self
            .region
            .wire_sector(local)
            .ok_or(ReadOnlyError::Bounds)?;
        self.backend
            .read(u64::from(wire), out, deadline)
            .map_err(ReadOnlyError::Device)
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> Result<(), Self::Error> {
        Err(ReadOnlyError::Blocked)
    }
    fn flush(&mut self, _: u64) -> Result<(), Self::Error> {
        Err(ReadOnlyError::Blocked)
    }
}

// Keep Store's bounded root/sector metadata in a separate native stack phase.
// There is no whole-store/volume scratch allocation or caller document copy.
#[inline(never)]
fn read_envelope<D: SectorIo>(
    backend: &mut D,
    object: Object,
    creation: &GenerationManifest,
    deadline: u64,
    bytes: &mut [u8; ev_store::PAYLOAD_BYTES],
) -> Result<usize, Unavailable> {
    let region = ReadOnlyRegion {
        backend,
        region: match object {
            Object::Notes => Region::FileA,
            Object::Private => Region::FileB,
        },
    };
    let mut store = Store::open_mutable_namespace(region, creation, deadline)
        .map_err(|rejected| unavailable(rejected.error))?;
    store
        .read_mutable(ev_store::ObjectId::user_data(), bytes, deadline)
        .map_err(unavailable)
}

fn unavailable<E>(error: ev_store::Error<ReadOnlyError<E>>) -> Unavailable {
    match error {
        ev_store::Error::Io(ReadOnlyError::Device(_)) => Unavailable::Transport,
        ev_store::Error::Io(ReadOnlyError::Blocked)
        | ev_store::Error::NeedsRecovery
        | ev_store::Error::RecoveryRequired => Unavailable::RecoveryRequired,
        ev_store::Error::Capacity | ev_store::Error::Io(ReadOnlyError::Bounds) => {
            Unavailable::Capacity
        }
        ev_store::Error::InvalidDeadline => Unavailable::Deadline,
        ev_store::Error::Unformatted => Unavailable::Unformatted,
        ev_store::Error::Unsupported => Unavailable::UnknownFormat,
        ev_store::Error::Conflict => Unavailable::ForeignNamespace,
        _ => Unavailable::Corrupt,
    }
}

#[cfg(test)]
#[path = "legacy_tests.rs"]
mod tests;
