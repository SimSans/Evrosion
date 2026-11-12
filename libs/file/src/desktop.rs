//! Two explicit desktop objects, each backed by a separate unchanged Store-v2
//! region. Endpoint binding selects object and rights, never packet object IDs.
use crate::{Bindings, Error, Gateway, Request, Response};
use ev_store::{SectorIo, Store};
use sha2::{Digest, Sha256};
pub const SEED_NOTES: &[u8] = b"Notes: Evrosion is yours.";
pub const SEED_PRIVATE: &[u8] = b"Private: keep this separate.";
pub const READY: [u8; 8] = *b"EVFLRDY1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    Notes,
    Private,
}
impl Object {
    pub const fn stable_id(self) -> u64 {
        match self {
            Self::Notes => 1,
            Self::Private => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopBindings {
    notes: Bindings,
    private: Bindings,
}
impl DesktopBindings {
    pub fn new(notes_ro: u64, notes_rw: u64, private_ro: u64, private_rw: u64) -> Option<Self> {
        let roles = [notes_ro, notes_rw, private_ro, private_rw];
        for (i, role) in roles.iter().enumerate() {
            if *role == 0 || roles[..i].contains(role) {
                return None;
            }
        }
        Some(Self {
            notes: Bindings::new(notes_ro, notes_rw)?,
            private: Bindings::new(private_ro, private_rw)?,
        })
    }
    pub fn object(self, received_on: u64) -> Option<Object> {
        if received_on == self.notes.readonly || received_on == self.notes.read_write {
            Some(Object::Notes)
        } else if received_on == self.private.readonly || received_on == self.private.read_write {
            Some(Object::Private)
        } else {
            None
        }
    }
    pub fn readonly(self, object: Object) -> u64 {
        match object {
            Object::Notes => self.notes.readonly,
            Object::Private => self.private.readonly,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataField {
    Counter,
    Digest0,
    Digest1,
    Digest2,
    Digest3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataQuery {
    field: MetadataField,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    Header,
    Reserved,
    Field,
}
impl MetadataQuery {
    pub const fn counter() -> Self {
        Self {
            field: MetadataField::Counter,
        }
    }
    pub fn digest_word(index: u8) -> Option<Self> {
        Some(Self {
            field: match index {
                0 => MetadataField::Digest0,
                1 => MetadataField::Digest1,
                2 => MetadataField::Digest2,
                3 => MetadataField::Digest3,
                _ => return None,
            },
        })
    }
    pub fn encode(self) -> [u8; 8] {
        [
            b'F',
            b'M',
            b'Q',
            b'1',
            match self.field {
                MetadataField::Counter => 0,
                MetadataField::Digest0 => 1,
                MetadataField::Digest1 => 2,
                MetadataField::Digest2 => 3,
                MetadataField::Digest3 => 4,
            },
            0,
            0,
            0,
        ]
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, QueryError> {
        if &bytes[..4] != b"FMQ1" {
            return Err(QueryError::Header);
        }
        if bytes[5..].iter().any(|b| *b != 0) {
            return Err(QueryError::Reserved);
        }
        Ok(Self {
            field: match bytes[4] {
                0 => MetadataField::Counter,
                1 => MetadataField::Digest0,
                2 => MetadataField::Digest1,
                3 => MetadataField::Digest2,
                4 => MetadataField::Digest3,
                _ => return Err(QueryError::Field),
            },
        })
    }
    fn value(self, counter: u64, digest: [u8; 32]) -> u64 {
        let index = match self.field {
            MetadataField::Counter => return counter,
            MetadataField::Digest0 => 0,
            MetadataField::Digest1 => 1,
            MetadataField::Digest2 => 2,
            MetadataField::Digest3 => 3,
        };
        u64::from_le_bytes(digest[index * 8..index * 8 + 8].try_into().unwrap())
    }
}
/// Both stores have the same bounded region-token type but disjoint ownership.
/// A source cannot select its peer by object name, sector or global operation.
pub struct DesktopGateway<D: SectorIo> {
    notes: Gateway<D>,
    private: Gateway<D>,
    bindings: DesktopBindings,
}
impl<D: SectorIo> DesktopGateway<D> {
    pub fn new(notes: Store<D>, private: Store<D>, bindings: DesktopBindings) -> Self {
        Self {
            notes: Gateway::new(notes, bindings.notes),
            private: Gateway::new(private, bindings.private),
            bindings,
        }
    }
    pub fn into_stores(self) -> (Store<D>, Store<D>) {
        (self.notes.into_store(), self.private.into_store())
    }
    pub fn handle_frame(
        &mut self,
        received_on: u64,
        frame: &[u8],
        deadline: u64,
    ) -> Result<Response, Error<D::Error>> {
        match self.bindings.object(received_on).ok_or(Error::Denied)? {
            Object::Notes => self.notes.handle_frame(received_on, frame, deadline),
            Object::Private => self.private.handle_frame(received_on, frame, deadline),
        }
    }
    /// Actual Store read and envelope validation on EVERY query. No shared App
    /// frame access or cached seed/descriptor fields can answer these words.
    /// Root uses counter-before,4 digest words,counter-after while its exclusively
    /// retained RW authority is quiescent. This is a bounded coherent-read profile,
    /// not a general multiwriter snapshot or a grant from a digest.
    pub fn metadata_word(
        &mut self,
        received_on: u64,
        query: MetadataQuery,
        deadline: u64,
    ) -> Result<u64, Error<D::Error>> {
        let object = self.bindings.object(received_on).ok_or(Error::Denied)?;
        if received_on != self.bindings.readonly(object) {
            return Err(Error::Denied);
        }
        let gateway = match object {
            Object::Notes => &mut self.notes,
            Object::Private => &mut self.private,
        };
        let Response::Read { counter, payload } =
            gateway.handle(received_on, Request::Read, deadline)?
        else {
            return Err(Error::Denied);
        };
        Ok(query.value(counter, Sha256::digest(payload.as_slice()).into()))
    }
}

#[cfg(test)]
mod tests;
