//! Append-only immutable bytes and a journaled pointer, not release authority.
//! The adapter owns actual exclusive physical authority and deadline enforcement.
#![no_std]
#![forbid(unsafe_code)]
mod codec;
mod owned;
mod provision;
mod stream;
pub use ev_store::Sector;
use ev_store::{BootPolicy, GenerationManifest, ObjectId, Request, SectorIo, Store};
pub use owned::{OwnedReader, OwnedStage, OwnedVerified, RejectedArena};
pub use provision::Provisioner;
use sha2::{Digest, Sha256};
pub use stream::{Reader, Stage, Verified};

/// Stable on-disk/profile identity, independent of a Root executable/startup ABI.
pub const FORMAT_ABI_DESCRIPTION: &[u8] = b"Evrosion Root content format1; Storev2 user object1 mutable256 EVCTRS01; highwater64@16 revision64@24 objectflag8@32 zeroreserved; objectref@40 start64 sectors64 length64 sha256[32]; EVCOBJ01 sector512 version1 ref@16 zeroreserved SHA256first480@480; payload SHA256 length1..262144 zero tail; append reservation durable before writes; payload flush headerlast flush fullhashreadback; noGC nooverwrite; Root namespace checkpoint physical128..141 objects256..8191; no boot health admission or root-startup ABI";
pub const FORMAT_ABI: [u8; 32] = [
    193, 120, 66, 34, 105, 136, 87, 63, 161, 45, 14, 62, 184, 138, 80, 195, 180, 225, 150, 45, 99,
    186, 232, 85, 242, 174, 134, 74, 12, 137, 169, 206,
];
pub const CHECKPOINT_PHYSICAL_START: u64 = 128;
pub const OBJECT_PHYSICAL_START: u64 = 256;
pub const OBJECT_SECTORS: u64 = 8192 - OBJECT_PHYSICAL_START;
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024;
pub const MAX_CHUNK_BYTES: usize = 4096;
pub const MAX_CHILD_TICKS: u64 = 1024;
pub const MAX_METADATA_TICKS: u64 = 8192;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Checkpoint,
    Objects,
}
/// A single owner must exclude all other physical writers. Devices exclusively
/// reborrow it; sequential scopes cannot alias one shared Block window.
pub trait Backend {
    type Error;
    type Device<'a>: SectorIo<Error = Self::Error>
    where
        Self: 'a;
    fn device(&mut self, area: Area) -> Self::Device<'_>;
    /// Conservative adapter evidence, never inferred from a semantic error.
    /// False requires no pending shared-window/transport work or poison. The
    /// exclusive caller still validates its own policy/transaction fences.
    fn has_unresolved_io(&self) -> bool {
        true
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    Store(ev_store::Error<E>),
    Geometry,
    Deadline,
    Corrupt,
    Foreign,
    NotBlank,
    Bounds,
    Conflict,
    NoSpace,
    Recovery,
    Incomplete,
    Hash,
    Exhausted,
}
pub struct Rejected<B: Backend> {
    pub backend: B,
    pub error: Error<B::Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferCut {
    start: u64,
    end: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoCut {
    transfer: TransferCut,
    end: u64,
}
/// Store metadata transaction horizon only. The actual backend independently
/// captures each physical RPC child at <=1024 ticks before window publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataCut {
    transfer: TransferCut,
    end: u64,
}
impl TransferCut {
    pub fn new(start: u64, end: u64) -> Result<Self, Error<core::convert::Infallible>> {
        if start >= end || end == u64::MAX {
            return Err(Error::Deadline);
        }
        Ok(Self { start, end })
    }
    pub fn child(self, now: u64, budget: u64) -> Result<IoCut, Error<core::convert::Infallible>> {
        if now < self.start || now >= self.end || !(1..=MAX_CHILD_TICKS).contains(&budget) {
            return Err(Error::Deadline);
        }
        let end = now
            .checked_add(budget)
            .ok_or(Error::Deadline)?
            .min(self.end);
        Ok(IoCut {
            transfer: self,
            end,
        })
    }
    pub fn metadata(self, now: u64) -> Result<MetadataCut, Error<core::convert::Infallible>> {
        if now < self.start || now >= self.end {
            return Err(Error::Deadline);
        }
        let end = now
            .checked_add(MAX_METADATA_TICKS)
            .ok_or(Error::Deadline)?
            .min(self.end);
        Ok(MetadataCut {
            transfer: self,
            end,
        })
    }
    pub fn end(self) -> u64 {
        self.end
    }
}
impl MetadataCut {
    fn check<E>(self, original: TransferCut) -> Result<u64, Error<E>> {
        if self.transfer != original {
            Err(Error::Deadline)
        } else {
            Ok(self.end)
        }
    }
    pub fn end(self) -> u64 {
        self.end
    }
}
impl IoCut {
    fn check<E>(self, original: TransferCut) -> Result<u64, Error<E>> {
        if self.transfer != original {
            Err(Error::Deadline)
        } else {
            Ok(self.end)
        }
    }
    pub fn end(self) -> u64 {
        self.end
    }
}
/// Content identity and a physical append extent, never executable authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    start: u64,
    sectors: u64,
    length: u64,
    hash: [u8; 32],
}
impl Object {
    /// Syntax-only reconstruction of a retained reference. This proves neither
    /// stored bytes nor publisher trust; Arena::reader must verify the whole object.
    pub fn checked(
        start: u64,
        length: u64,
        hash: [u8; 32],
    ) -> Result<Self, Error<core::convert::Infallible>> {
        let object = Self {
            start,
            sectors: length.div_ceil(512) + 1,
            length,
            hash,
        };
        if !object.valid(OBJECT_SECTORS) {
            return Err(Error::Bounds);
        }
        Ok(object)
    }
    pub fn length(self) -> u64 {
        self.length
    }
    pub fn sha256(self) -> [u8; 32] {
        self.hash
    }
    pub fn start(self) -> u64 {
        self.start
    }
    pub fn sectors(self) -> u64 {
        self.sectors
    }
    fn valid(self, high: u64) -> bool {
        self.length > 0
            && self.length <= MAX_OBJECT_BYTES
            && self.hash != [0; 32]
            && self.sectors == self.length.div_ceil(512) + 1
            && self
                .start
                .checked_add(self.sectors)
                .is_some_and(|e| e <= high && high <= OBJECT_SECTORS)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Head {
    high: u64,
    revision: u64,
    published: Option<Object>,
}
impl Head {
    const EMPTY: Self = Self {
        high: 0,
        revision: 0,
        published: None,
    };
    fn digest(self) -> [u8; 32] {
        Sha256::digest(codec::encode_head(self)).into()
    }
}
/// Open metadata is deliberately unverified object metadata. Only a complete
/// Reader yields Verified, which retains this actual backend's exclusive borrow.
pub struct Arena<B: Backend> {
    backend: B,
    creation: GenerationManifest,
    head: Head,
    poisoned: bool,
}
impl<B: Backend> Arena<B> {
    pub fn open(
        mut backend: B,
        creation: GenerationManifest,
        cut: MetadataCut,
    ) -> Result<Self, Rejected<B>> {
        let result = Self::load(&mut backend, creation, cut.end);
        match result {
            Ok(head) => Ok(Self {
                backend,
                creation,
                head,
                poisoned: false,
            }),
            Err(error) => Err(Rejected { backend, error }),
        }
    }
    fn load(
        backend: &mut B,
        creation: GenerationManifest,
        deadline: u64,
    ) -> Result<Head, Error<B::Error>> {
        {
            let d = backend.device(Area::Objects);
            if d.sectors() != OBJECT_SECTORS {
                return Err(Error::Geometry);
            }
        }
        let d = backend.device(Area::Checkpoint);
        if d.sectors() != ev_store::REQUIRED_SECTORS {
            return Err(Error::Geometry);
        }
        let mut store = Store::open_mutable_namespace(d, &creation, deadline)
            .map_err(|r| Error::Store(r.error))?;
        let mut bytes = [0; 256];
        if store
            .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
            .map_err(Error::Store)?
            != 256
        {
            return Err(Error::Corrupt);
        }
        codec::decode_head(&bytes).ok_or(Error::Corrupt)
    }
    pub fn into_backend(self) -> B {
        self.backend
    }
    /// Read-only facts about this exact retained owner. This grants no device
    /// borrow or IO access; mutation still requires the sole mutable Arena.
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn has_unresolved_io(&self) -> bool {
        self.poisoned || self.backend.has_unresolved_io()
    }
    pub fn head_digest(&self) -> [u8; 32] {
        self.head.digest()
    }
    pub fn reserved_sectors(&self) -> u64 {
        self.head.high
    }
    pub fn published_metadata(&self) -> Option<Object> {
        self.head.published
    }
    fn healthy(&self) -> Result<(), Error<B::Error>> {
        if self.poisoned {
            Err(Error::Recovery)
        } else {
            Ok(())
        }
    }
    fn commit(&mut self, next: Head, cut: MetadataCut) -> Result<(), Error<B::Error>> {
        self.healthy()?;
        // Poison before the first possibly accepted Store operation. A failed
        // read/open is also conservatively fenced; cold Store recovery is sole resolution.
        self.poisoned = true;
        let d = self.backend.device(Area::Checkpoint);
        let mut store = Store::open_mutable_namespace(d, &self.creation, cut.end)
            .map_err(|r| Error::Store(r.error))?;
        let mut old = [0; 256];
        if store
            .read_mutable(ObjectId::user_data(), &mut old, cut.end)
            .map_err(Error::Store)?
            != 256
            || codec::decode_head(&old) != Some(self.head)
        {
            return Err(Error::Conflict);
        }
        let bytes = codec::encode_head(next);
        let id = store.next_operation().map_err(Error::Store)?;
        store
            .execute(
                id,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &bytes,
                },
                cut.end,
            )
            .map_err(Error::Store)?;
        let mut check = [0; 256];
        if store
            .read_mutable(ObjectId::user_data(), &mut check, cut.end)
            .map_err(Error::Store)?
            != 256
            || check != bytes
        {
            return Err(Error::Corrupt);
        }
        self.head = next;
        self.poisoned = false;
        Ok(())
    }
    pub fn begin(
        &mut self,
        expected: [u8; 32],
        length: u64,
        hash: [u8; 32],
        transfer: TransferCut,
        cut: MetadataCut,
    ) -> Result<Stage<'_, B>, Error<B::Error>> {
        self.healthy()?;
        cut.check::<B::Error>(transfer)?;
        if expected != self.head.digest() {
            return Err(Error::Conflict);
        }
        let sectors = length.div_ceil(512).checked_add(1).ok_or(Error::Bounds)?;
        let high = self.head.high.checked_add(sectors).ok_or(Error::NoSpace)?;
        let object = Object {
            start: self.head.high,
            sectors,
            length,
            hash,
        };
        if length == 0 || length > MAX_OBJECT_BYTES || hash == [0; 32] {
            return Err(Error::Bounds);
        }
        if high > OBJECT_SECTORS {
            return Err(Error::NoSpace);
        }
        let next = Head {
            high,
            revision: self
                .head
                .revision
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .ok_or(Error::Exhausted)?,
            published: self.head.published,
        };
        self.commit(next, cut)?;
        Ok(Stage {
            arena: self,
            object,
            transfer,
            written: 0,
            hash: Sha256::new(),
        })
    }
    pub fn reader(
        &mut self,
        object: Object,
        transfer: TransferCut,
        cut: IoCut,
    ) -> Result<Reader<'_, B>, Error<B::Error>> {
        self.healthy()?;
        cut.check::<B::Error>(transfer)?;
        if !object.valid(self.head.high) {
            return Err(Error::Bounds);
        }
        self.poisoned = true;
        let mut header = [0; 512];
        self.backend
            .device(Area::Objects)
            .read(object.start, &mut header, cut.end)
            .map_err(Error::Io)?;
        if codec::decode_object(&header) != Some(object) {
            return Err(Error::Corrupt);
        }
        self.poisoned = false;
        Ok(Reader {
            arena: self,
            object,
            transfer,
            read: 0,
            hash: Sha256::new(),
        })
    }
}
#[cfg(test)]
mod tests;
