//! Exact descriptive metadata paired with an independently transferred File
//! SEND capability. This frame never contains a handle or grants edit rights.
use ev_userspace_contract::workspace::{Error, Name, ObjectId};
pub const BYTES: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Access {
    ReadOnly = 1,
    ReadWrite = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub request_id: u64,
    pub receiver_process: u64,
    pub receiver_thread: u64,
    pub registered_incarnation: u64,
    pub lease_epoch: u64,
    pub dataset: [u8; 16],
    pub object: ObjectId,
    pub access: Access,
    pub length: u32,
    pub revision: u64,
    pub digest: [u8; 32],
    pub name: Name,
}
/// Descriptive File@2 compatibility paired with a separately transferred SEND.
/// It never grants rights or authenticates a loaded service by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionV2 {
    pub selection: Selection,
    pub file: ev_userspace_contract::file_v2::Support,
}
fn put(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
impl Selection {
    pub fn encode(self) -> Result<[u8; BYTES], Error> {
        if [
            self.request_id,
            self.receiver_process,
            self.receiver_thread,
            self.lease_epoch,
        ]
        .into_iter()
        .any(|v| matches!(v, 0 | u64::MAX))
            || self.registered_incarnation == u64::MAX
            || self.revision == u64::MAX
            || self.dataset == [0; 16]
            || self.object.slot == 0
        {
            return Err(Error::Identity);
        }
        self.object.validate()?;
        if self.length > 1_048_576 {
            return Err(Error::Bounds);
        }
        let name = self.name.as_bytes();
        Name::new(name)?;
        let mut b = [0; BYTES];
        b[..8].copy_from_slice(b"EVF2SEL1");
        for (at, value) in [
            (8, self.request_id),
            (16, self.receiver_process),
            (24, self.receiver_thread),
            (32, self.registered_incarnation),
            (40, self.lease_epoch),
            (72, self.object.generation),
            (80, self.revision),
        ] {
            put(&mut b, at, value);
        }
        b[48..64].copy_from_slice(&self.dataset);
        b[64..66].copy_from_slice(&self.object.slot.to_le_bytes());
        b[66] = self.access as u8;
        b[67] = name.len() as u8;
        b[68..72].copy_from_slice(&self.length.to_le_bytes());
        b[88..120].copy_from_slice(&self.digest);
        b[120..120 + name.len()].copy_from_slice(name);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BYTES {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVF2SEL1" {
            return Err(Error::Magic);
        }
        let length = usize::from(b[67]);
        if length > 96 {
            return Err(Error::Name);
        }
        let access = match b[66] {
            1 => Access::ReadOnly,
            3 => Access::ReadWrite,
            _ => return Err(Error::Reserved),
        };
        let s = Self {
            request_id: word(b, 8),
            receiver_process: word(b, 16),
            receiver_thread: word(b, 24),
            registered_incarnation: word(b, 32),
            lease_epoch: word(b, 40),
            dataset: b[48..64].try_into().unwrap(),
            object: ObjectId {
                slot: u16::from_le_bytes(b[64..66].try_into().unwrap()),
                generation: word(b, 72),
            },
            access,
            length: u32::from_le_bytes(b[68..72].try_into().unwrap()),
            revision: word(b, 80),
            digest: b[88..120].try_into().unwrap(),
            name: Name::new(&b[120..120 + length])?,
        };
        if s.encode()?.as_slice() != b {
            return Err(Error::Reserved);
        }
        Ok(s)
    }
    /// Cross-check actual inbox payload and independently queried self facts.
    /// Authority still comes solely from the received capability + server route.
    pub fn matches_receiver(self, nonce: u64, process: u64, thread: u64, registered: u64) -> bool {
        (
            self.request_id,
            self.receiver_process,
            self.receiver_thread,
            self.registered_incarnation,
        ) == (nonce, process, thread, registered)
    }
    /// Closed descriptive exception for the original File1 readonly bridge.
    /// Actual SEND/route authority remains independent; this never enables edits.
    pub fn is_legacy_file1_readonly(self) -> bool {
        self.access == Access::ReadOnly
            && self.dataset == *b"EVRO-USERS-VOL01"
            && matches!(self.object.slot, 1 | 2)
            && self.object.generation == 1
    }
}
impl SelectionV2 {
    pub fn encode(self) -> Result<[u8; BYTES], Error> {
        if self.file.major != ev_userspace_contract::file_v2::VERSION {
            return Err(Error::Reserved);
        }
        let mut bytes = self.selection.encode()?;
        bytes[..8].copy_from_slice(b"EVF2SEL2");
        bytes[216..218].copy_from_slice(&self.file.major.to_le_bytes());
        bytes[218..220].copy_from_slice(&self.file.minor.to_le_bytes());
        put(&mut bytes, 224, self.file.features);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVF2SEL2" {
            return Err(Error::Magic);
        }
        let mut legacy: [u8; BYTES] = bytes.try_into().unwrap();
        legacy[..8].copy_from_slice(b"EVF2SEL1");
        legacy[216..].fill(0);
        let value = Self {
            selection: Selection::decode(&legacy)?,
            file: ev_userspace_contract::file_v2::Support {
                major: u16::from_le_bytes(bytes[216..218].try_into().unwrap()),
                minor: u16::from_le_bytes(bytes[218..220].try_into().unwrap()),
                features: word(bytes, 224),
            },
        };
        if value.encode()?.as_slice() != bytes {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Selection {
        Selection {
            request_id: 1,
            receiver_process: 0x10002,
            receiver_thread: 0x20003,
            registered_incarnation: 9,
            lease_epoch: 7,
            dataset: [4; 16],
            object: ObjectId {
                slot: 256,
                generation: 33,
            },
            access: Access::ReadOnly,
            length: 1_048_576,
            revision: 19,
            digest: [8; 32],
            name: Name::new("draft é.txt".as_bytes()).unwrap(),
        }
    }
    #[test]
    fn exact_selected_object_and_unicode_name_survive_without_a_wire_handle() {
        let s = example();
        assert_eq!(Selection::decode(&s.encode().unwrap()), Ok(s));
        assert!(s.matches_receiver(1, 0x10002, 0x20003, 9));
        for fields in [
            (2, 0x10002, 0x20003, 9),
            (1, 0x10003, 0x20003, 9),
            (1, 0x10002, 0x20004, 9),
            (1, 0x10002, 0x20003, 10),
        ] {
            assert!(!s.matches_receiver(fields.0, fields.1, fields.2, fields.3));
        }
    }
    #[test]
    fn version2_support_is_exact_reserved_and_never_accepted_as_selection1() {
        let value = SelectionV2 {
            selection: example(),
            file: ev_userspace_contract::file_v2::SUPPORT,
        };
        let bytes = value.encode().unwrap();
        assert_eq!(SelectionV2::decode(&bytes), Ok(value));
        assert!(Selection::decode(&bytes).is_err());
        assert!(SelectionV2::decode(&value.selection.encode().unwrap()).is_err());
        for at in (220..224).chain(232..BYTES) {
            let mut bad = bytes;
            bad[at] = 1;
            assert!(SelectionV2::decode(&bad).is_err());
        }
        let mut bad = bytes;
        bad[216] = 1;
        assert!(SelectionV2::decode(&bad).is_err());
        for length in 0..BYTES {
            assert!(SelectionV2::decode(&bytes[..length]).is_err());
        }
        let no_feature = SelectionV2 {
            file: ev_userspace_contract::file_v2::Support {
                major: 2,
                minor: 0,
                features: 0,
            },
            ..value
        };
        let decoded = SelectionV2::decode(&no_feature.encode().unwrap()).unwrap();
        assert!(!decoded.file.supports(2, 1, 1));
    }
    #[test]
    fn only_the_closed_original_identity_can_describe_legacy_readonly() {
        let old = Selection {
            dataset: *b"EVRO-USERS-VOL01",
            object: ObjectId {
                slot: 1,
                generation: 1,
            },
            ..example()
        };
        assert!(old.is_legacy_file1_readonly());
        assert!(
            !Selection {
                access: Access::ReadWrite,
                ..old
            }
            .is_legacy_file1_readonly()
        );
        assert!(
            !Selection {
                dataset: [8; 16],
                ..old
            }
            .is_legacy_file1_readonly()
        );
        assert!(
            !Selection {
                object: ObjectId {
                    slot: 3,
                    generation: 1
                },
                ..old
            }
            .is_legacy_file1_readonly()
        );
        assert!(
            !Selection {
                object: ObjectId {
                    slot: 1,
                    generation: 2
                },
                ..old
            }
            .is_legacy_file1_readonly()
        );
    }
    #[test]
    fn reserved_bytes_bad_names_truncation_and_unknown_permissions_refuse() {
        let s = example();
        let frame = s.encode().unwrap();
        for at in 120 + s.name.as_bytes().len()..BYTES {
            let mut bad = frame;
            bad[at] = 1;
            assert!(Selection::decode(&bad).is_err());
        }
        for length in [0, 255, 257] {
            let input = [0; 257];
            assert!(Selection::decode(&input[..length]).is_err());
        }
        for rights in [0, 2, 4, 255] {
            let mut bad = frame;
            bad[66] = rights;
            assert!(Selection::decode(&bad).is_err());
        }
        let mut bad = frame;
        bad[67] = 97;
        assert!(Selection::decode(&bad).is_err());
    }
}
