//! Internal Root-only binding control. Parsing is not Root authentication.
//! The native adapter must receive on dedicated V5 role16, whose SEND belongs
//! only to Root, and validate actual ServingOrigin before accessing its window.
use crate::{Rights, legacy};
use ev_userspace_contract::workspace::{Deadline, ObjectId};

pub const FRAME_BYTES: usize = 256;
pub const FILE_SLOTS: usize = 4;
/// Slot0 is Files' namespace window, never an installable File target.
pub const FIRST_FILE_SLOT: u8 = 1;
#[path = "file_contract.rs"]
mod file_contract;
pub use file_contract::{BindContractResponse, FileContractResponse, FileRequirement};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Magic,
    Opcode,
    Reserved,
    Identity,
    Scope,
    Correlation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bind {
    pub slot: u8,
    pub dataset: [u8; 16],
    pub object: ObjectId,
    pub target_process: u64,
    pub target_thread: u64,
    /// The actual registered immediate token, explicitly0 when unregistered.
    pub target_registered_token: u64,
    pub lease_epoch: u64,
    pub rights: Rights,
}
/// Explicit Root-only original-volume selection. This command has no writable
/// variant, and source metadata never supplies an original namespace proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyBind {
    pub slot: u8,
    pub object: legacy::Object,
    pub target_process: u64,
    pub target_thread: u64,
    pub target_registered_token: u64,
    pub lease_epoch: u64,
    pub expected: legacy::Metadata,
}
impl LegacyBind {
    /// Descriptive bytes only; actual SEND transfer and Kernel44 nonce remain
    /// Root's independent obligation after the service reports Applied.
    pub fn selection(self, request_id: u64) -> Result<[u8; FRAME_BYTES], Error> {
        use ev_userspace_contract::workspace::Name;
        use ev_workspace_client::selection::{Access, Selection};
        if request_id == 0
            || request_id >= u64::from(u32::MAX)
            || self.slot < FIRST_FILE_SLOT
            || usize::from(self.slot) >= FILE_SLOTS
            || self.expected.identity != legacy::Identity::for_object(self.object)
        {
            return Err(Error::Scope);
        }
        Selection {
            request_id,
            receiver_process: self.target_process,
            receiver_thread: self.target_thread,
            registered_incarnation: self.target_registered_token,
            lease_epoch: self.lease_epoch,
            dataset: self.expected.identity.volume,
            object: self.expected.identity.projected_object,
            access: Access::ReadOnly,
            length: self.expected.length,
            revision: self.expected.counter,
            digest: self.expected.digest,
            name: Name::new(match self.object {
                legacy::Object::Notes => b"Notes",
                legacy::Object::Private => b"Private",
            })
            .map_err(|_| Error::Scope)?,
        }
        .encode()
        .map_err(|_| Error::Scope)
    }
}
/// Descriptive exact old-owner correlation, not a kernel retirement proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredOwner {
    pub process: u64,
    pub thread: u64,
    pub registered: u64,
}
impl RetiredOwner {
    fn valid(self) -> bool {
        finite(self.process) && finite(self.thread) && self.registered != u64::MAX
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Bind(Bind),
    /// Read-only loaded File@2 compatibility probe, only on the actual Root
    /// control route. Token correlates the reply and grants no authority.
    FileContract {
        token: u64,
    },
    BindContract {
        bind: Bind,
        requirement: FileRequirement,
    },
    /// Terminal seal request on the existing captured Root-only route. Token
    /// is correlation only; it supplies no shutdown or device authority.
    Quiesce {
        token: u64,
    },
    LegacyInspect {
        object: legacy::Object,
        lease_epoch: u64,
    },
    BindLegacyReadOnly(LegacyBind),
    Revoke {
        slot: u8,
        lease_epoch: u64,
    },
    /// Only the measured Root may issue this AFTER actual kernel branch/loan
    /// retirement. The wire does not manufacture that proof inside Workspace.
    ReconcileFile {
        slot: u8,
        lease_epoch: u64,
        old: RetiredOwner,
        grant_nonce: u32,
    },
    ResetFilesNamespace {
        lease_epoch: u64,
        old: RetiredOwner,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: u64,
    pub deadline: Deadline,
    pub command: Command,
}
fn word(b: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap())
}
fn put(b: &mut [u8], offset: usize, value: u64) {
    b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn finite(value: u64) -> bool {
    value != 0 && value != u64::MAX
}
fn legacy_object(local: u64) -> Result<legacy::Object, Error> {
    match local {
        1 => Ok(legacy::Object::Notes),
        2 => Ok(legacy::Object::Private),
        _ => Err(Error::Scope),
    }
}
fn encode_legacy_metadata(
    bytes: &mut [u8; FRAME_BYTES],
    metadata: legacy::Metadata,
) -> Result<(), Error> {
    let object = legacy_object(metadata.identity.local)?;
    if metadata.identity != legacy::Identity::for_object(object)
        || metadata.counter == u64::MAX
        || metadata.length > ev_file::MAX_PAYLOAD as u32
        || (metadata.counter == 0) != (metadata.global_operation == 0)
        || metadata.global_operation == u64::MAX
    {
        return Err(Error::Scope);
    }
    bytes[64..80].copy_from_slice(&metadata.identity.volume);
    put(bytes, 80, metadata.identity.local);
    put(bytes, 88, metadata.counter);
    bytes[96..100].copy_from_slice(&metadata.length.to_le_bytes());
    bytes[104..136].copy_from_slice(&metadata.digest);
    put(bytes, 136, metadata.global_operation);
    Ok(())
}
fn decode_legacy_metadata(bytes: &[u8]) -> Result<legacy::Metadata, Error> {
    let object = legacy_object(word(bytes, 80))?;
    let mut identity = legacy::Identity::for_object(object);
    identity.volume = bytes[64..80].try_into().unwrap();
    Ok(legacy::Metadata {
        identity,
        counter: word(bytes, 88),
        length: u32::from_le_bytes(bytes[96..100].try_into().unwrap()),
        digest: bytes[104..136].try_into().unwrap(),
        global_operation: word(bytes, 136),
    })
}
impl Request {
    pub const fn lease_epoch(self) -> u64 {
        match self.command {
            Command::Bind(b) => b.lease_epoch,
            Command::BindContract { bind, .. } => bind.lease_epoch,
            Command::Quiesce { token } | Command::FileContract { token } => token,
            Command::BindLegacyReadOnly(b) => b.lease_epoch,
            Command::LegacyInspect { lease_epoch, .. } => lease_epoch,
            Command::Revoke { lease_epoch, .. } => lease_epoch,
            Command::ReconcileFile { lease_epoch, .. }
            | Command::ResetFilesNamespace { lease_epoch, .. } => lease_epoch,
        }
    }
    pub fn encode(self) -> Result<[u8; FRAME_BYTES], Error> {
        if !finite(self.request_id) || !finite(self.lease_epoch()) {
            return Err(Error::Identity);
        }
        let mut b = [0; FRAME_BYTES];
        b[..8].copy_from_slice(b"EVWSCT01");
        put(&mut b, 16, self.request_id);
        put(&mut b, 24, self.deadline.tick());
        put(&mut b, 32, self.lease_epoch());
        match self.command {
            Command::Quiesce { .. } => b[8] = 7,
            Command::FileContract { .. } => b[8] = 8,
            Command::Bind(bind) | Command::BindContract { bind, .. } => {
                if bind.slot < FIRST_FILE_SLOT
                    || usize::from(bind.slot) >= FILE_SLOTS
                    || !finite(bind.target_process)
                    || !finite(bind.target_thread)
                    || bind.target_registered_token == u64::MAX
                    || bind.dataset == [0; 16]
                    || bind.object.validate().is_err()
                {
                    return Err(Error::Scope);
                }
                b[8] = 1;
                b[9] = bind.slot;
                b[10] = match bind.rights {
                    Rights::ReadOnly => 1,
                    Rights::ReadWrite => 2,
                };
                put(&mut b, 40, bind.target_process);
                put(&mut b, 48, bind.target_thread);
                put(&mut b, 56, bind.target_registered_token);
                b[64..80].copy_from_slice(&bind.dataset);
                b[80..82].copy_from_slice(&bind.object.slot.to_le_bytes());
                put(&mut b, 88, bind.object.generation);
                if let Command::BindContract { requirement, .. } = self.command {
                    b[8] = 9;
                    b[104..106]
                        .copy_from_slice(&ev_userspace_contract::file_v2::VERSION.to_le_bytes());
                    b[106..108].copy_from_slice(&requirement.minimum_minor.to_le_bytes());
                    put(&mut b, 112, requirement.features);
                    b[120..122].copy_from_slice(&2u16.to_le_bytes());
                }
            }
            Command::LegacyInspect { object, .. } => {
                b[8] = 5;
                b[64..80].copy_from_slice(&legacy::ORIGINAL_VOLUME);
                put(&mut b, 80, object.stable_id());
            }
            Command::BindLegacyReadOnly(bind) => {
                if bind.slot < FIRST_FILE_SLOT
                    || usize::from(bind.slot) >= FILE_SLOTS
                    || !finite(bind.target_process)
                    || !finite(bind.target_thread)
                    || bind.target_registered_token == u64::MAX
                    || bind.expected.identity != legacy::Identity::for_object(bind.object)
                {
                    return Err(Error::Scope);
                }
                b[8] = 6;
                b[9] = bind.slot;
                b[10] = 1; // exact ReadOnly; a writable flag fails canonical decode
                put(&mut b, 40, bind.target_process);
                put(&mut b, 48, bind.target_thread);
                put(&mut b, 56, bind.target_registered_token);
                encode_legacy_metadata(&mut b, bind.expected)?;
            }
            Command::Revoke { slot, .. } => {
                if usize::from(slot) >= FILE_SLOTS {
                    return Err(Error::Scope);
                }
                b[8] = 2;
                b[9] = slot;
            }
            Command::ReconcileFile {
                slot,
                old,
                grant_nonce,
                ..
            } => {
                if usize::from(slot) >= FILE_SLOTS
                    || !old.valid()
                    || matches!(grant_nonce, 0 | u32::MAX)
                {
                    return Err(Error::Scope);
                }
                b[8] = 3;
                b[9] = slot;
                put(&mut b, 40, old.process);
                put(&mut b, 48, old.thread);
                put(&mut b, 56, old.registered);
                b[96..100].copy_from_slice(&grant_nonce.to_le_bytes());
            }
            Command::ResetFilesNamespace { old, .. } => {
                if !old.valid() {
                    return Err(Error::Scope);
                }
                b[8] = 4;
                put(&mut b, 40, old.process);
                put(&mut b, 48, old.thread);
                put(&mut b, 56, old.registered);
            }
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != FRAME_BYTES {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVWSCT01" {
            return Err(Error::Magic);
        }
        let command = match b[8] {
            1 | 9 => {
                let bind = Bind {
                    slot: b[9],
                    dataset: b[64..80].try_into().unwrap(),
                    object: ObjectId {
                        slot: u16::from_le_bytes(b[80..82].try_into().unwrap()),
                        generation: word(b, 88),
                    },
                    target_process: word(b, 40),
                    target_thread: word(b, 48),
                    target_registered_token: word(b, 56),
                    lease_epoch: word(b, 32),
                    rights: match b[10] {
                        1 => Rights::ReadOnly,
                        2 => Rights::ReadWrite,
                        _ => return Err(Error::Scope),
                    },
                };
                if b[8] == 9 {
                    if u16::from_le_bytes(b[104..106].try_into().unwrap())
                        != ev_userspace_contract::file_v2::VERSION
                        || u16::from_le_bytes(b[120..122].try_into().unwrap()) != 2
                    {
                        return Err(Error::Scope);
                    }
                    Command::BindContract {
                        bind,
                        requirement: FileRequirement {
                            minimum_minor: u16::from_le_bytes(b[106..108].try_into().unwrap()),
                            features: word(b, 112),
                        },
                    }
                } else {
                    Command::Bind(bind)
                }
            }
            2 => Command::Revoke {
                slot: b[9],
                lease_epoch: word(b, 32),
            },
            3 => Command::ReconcileFile {
                slot: b[9],
                lease_epoch: word(b, 32),
                old: RetiredOwner {
                    process: word(b, 40),
                    thread: word(b, 48),
                    registered: word(b, 56),
                },
                grant_nonce: u32::from_le_bytes(b[96..100].try_into().unwrap()),
            },
            4 => Command::ResetFilesNamespace {
                lease_epoch: word(b, 32),
                old: RetiredOwner {
                    process: word(b, 40),
                    thread: word(b, 48),
                    registered: word(b, 56),
                },
            },
            5 => Command::LegacyInspect {
                object: legacy_object(word(b, 80))?,
                lease_epoch: word(b, 32),
            },
            6 => {
                let expected = decode_legacy_metadata(b)?;
                Command::BindLegacyReadOnly(LegacyBind {
                    slot: b[9],
                    object: legacy_object(expected.identity.local)?,
                    target_process: word(b, 40),
                    target_thread: word(b, 48),
                    target_registered_token: word(b, 56),
                    lease_epoch: word(b, 32),
                    expected,
                })
            }
            7 => Command::Quiesce { token: word(b, 32) },
            8 => Command::FileContract { token: word(b, 32) },
            _ => return Err(Error::Opcode),
        };
        let value = Self {
            request_id: word(b, 16),
            deadline: Deadline::new(word(b, 24)).map_err(|_| Error::Identity)?,
            command,
        };
        if value.encode()?.as_slice() != b {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Applied = 0,
    Denied = 1,
    Stale = 2,
    Busy = 3,
    Malformed = 4,
    Storage = 5,
    Scope = 6,
    Uncertain = 7,
    Unavailable = 8,
    Deadline = 9,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub lease_epoch: u64,
    pub status: Status,
}
impl Response {
    pub fn encode(self) -> Result<[u8; FRAME_BYTES], Error> {
        if !finite(self.request_id) || !finite(self.lease_epoch) {
            return Err(Error::Identity);
        }
        let mut b = [0; FRAME_BYTES];
        b[..8].copy_from_slice(b"EVWSCA01");
        b[8] = self.status as u8;
        put(&mut b, 16, self.request_id);
        put(&mut b, 32, self.lease_epoch);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != FRAME_BYTES {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVWSCA01" {
            return Err(Error::Magic);
        }
        let status = match b[8] {
            0 => Status::Applied,
            1 => Status::Denied,
            2 => Status::Stale,
            3 => Status::Busy,
            4 => Status::Malformed,
            5 => Status::Storage,
            6 => Status::Scope,
            7 => Status::Uncertain,
            8 => Status::Unavailable,
            9 => Status::Deadline,
            _ => return Err(Error::Opcode),
        };
        let value = Self {
            request_id: word(b, 16),
            lease_epoch: word(b, 32),
            status,
        };
        if value.encode()?.as_slice() != b {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
    pub fn matches(self, request: Request) -> Result<Self, Error> {
        if self.request_id != request.request_id || self.lease_epoch != request.lease_epoch() {
            Err(Error::Correlation)
        } else {
            Ok(self)
        }
    }
}

/// Distinct original-volume inspection result. It cannot be decoded as a new
/// Dataset namespace response and never changes Root's ordinary Dataset ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyResponse {
    pub request_id: u64,
    pub lease_epoch: u64,
    pub status: Status,
    pub metadata: Option<legacy::Metadata>,
}
impl LegacyResponse {
    pub fn encode(self) -> Result<[u8; FRAME_BYTES], Error> {
        if !finite(self.request_id)
            || !finite(self.lease_epoch)
            || (self.status == Status::Applied) != self.metadata.is_some()
        {
            return Err(Error::Identity);
        }
        let mut bytes = [0; FRAME_BYTES];
        bytes[..8].copy_from_slice(b"EVWLGA01");
        bytes[8] = self.status as u8;
        put(&mut bytes, 16, self.request_id);
        put(&mut bytes, 32, self.lease_epoch);
        if let Some(metadata) = self.metadata {
            encode_legacy_metadata(&mut bytes, metadata)?;
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FRAME_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVWLGA01" {
            return Err(Error::Magic);
        }
        let status = match bytes[8] {
            0 => Status::Applied,
            1 => Status::Denied,
            2 => Status::Stale,
            3 => Status::Busy,
            4 => Status::Malformed,
            5 => Status::Storage,
            6 => Status::Scope,
            7 => Status::Uncertain,
            8 => Status::Unavailable,
            9 => Status::Deadline,
            _ => return Err(Error::Opcode),
        };
        let value = Self {
            request_id: word(bytes, 16),
            lease_epoch: word(bytes, 32),
            status,
            metadata: (status == Status::Applied)
                .then(|| decode_legacy_metadata(bytes))
                .transpose()?,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
    pub fn matches(self, request: Request) -> Result<Self, Error> {
        let Command::LegacyInspect { object, .. } = request.command else {
            return Err(Error::Correlation);
        };
        if self.request_id != request.request_id
            || self.lease_epoch != request.lease_epoch()
            || self
                .metadata
                .is_some_and(|m| m.identity != legacy::Identity::for_object(object))
        {
            return Err(Error::Correlation);
        }
        Ok(self)
    }
}

#[cfg(test)]
#[path = "legacy_control_tests.rs"]
mod legacy_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn bind() -> Request {
        Request {
            request_id: 0x0102030405060708,
            deadline: Deadline::new(100).unwrap(),
            command: Command::Bind(Bind {
                slot: 3,
                dataset: [8; 16],
                object: ObjectId {
                    slot: 256,
                    generation: 7,
                },
                target_process: 33,
                target_thread: 44,
                target_registered_token: 0,
                lease_epoch: 12,
                rights: Rights::ReadWrite,
            }),
        }
    }
    #[test]
    fn exact_bind_revoke_and_response_correlation_are_separate_from_authentication() {
        for request in [
            bind(),
            Request {
                command: Command::Revoke {
                    slot: 3,
                    lease_epoch: 12,
                },
                ..bind()
            },
        ] {
            let b = request.encode().unwrap();
            assert_eq!(Request::decode(&b), Ok(request));
            let r = Response {
                request_id: request.request_id,
                lease_epoch: 12,
                status: Status::Applied,
            };
            assert_eq!(
                Response::decode(&r.encode().unwrap())
                    .unwrap()
                    .matches(request),
                Ok(r)
            );
            assert!(Request::decode(&r.encode().unwrap()).is_err());
        }
        let response = Response {
            request_id: 1,
            lease_epoch: 12,
            status: Status::Applied,
        };
        assert_eq!(response.matches(bind()), Err(Error::Correlation));
    }
    #[test]
    fn unknown_roles_padding_rights_and_truncation_fail_closed() {
        let b = bind().encode().unwrap();
        for i in (11..16).chain(82..88).chain(96..FRAME_BYTES) {
            let mut bad = b;
            bad[i] = 1;
            assert_eq!(Request::decode(&bad), Err(Error::Reserved));
        }
        for i in 0..FRAME_BYTES {
            assert_eq!(Request::decode(&b[..i]), Err(Error::Length));
        }
        for (offset, value) in [(8, 0), (8, 5), (9, 4), (10, 0), (10, 3)] {
            let mut bad = b;
            bad[offset] = value;
            assert!(Request::decode(&bad).is_err());
        }
        let mut bad = b;
        put(&mut bad, 56, u64::MAX);
        assert!(Request::decode(&bad).is_err());
    }
    #[test]
    fn revoke_cannot_smuggle_bind_target_or_dataset_fields() {
        let r = Request {
            command: Command::Revoke {
                slot: 0,
                lease_epoch: 7,
            },
            ..bind()
        };
        let b = r.encode().unwrap();
        for i in [10, 40, 48, 56, 64, 80, 88, 255] {
            let mut bad = b;
            bad[i] = 1;
            assert_eq!(Request::decode(&bad), Err(Error::Reserved));
        }
    }
    #[test]
    fn retirement_requires_exact_full_old_owner_and_nonce_and_never_a_wire_proof_flag() {
        let old = RetiredOwner {
            process: 0x1_0000_0003,
            thread: 0x2_0000_0004,
            registered: 0,
        };
        let file = Request {
            command: Command::ReconcileFile {
                slot: 2,
                lease_epoch: 12,
                old,
                grant_nonce: 0x8000_0001,
            },
            ..bind()
        };
        let namespace = Request {
            command: Command::ResetFilesNamespace {
                lease_epoch: 12,
                old,
            },
            ..bind()
        };
        for request in [file, namespace] {
            let bytes = request.encode().unwrap();
            assert_eq!(Request::decode(&bytes), Ok(request));
            for offset in [10, 11, 15, 64, 80, 88, 100, 255] {
                let mut invalid = bytes;
                invalid[offset] = 1;
                assert_eq!(Request::decode(&invalid), Err(Error::Reserved));
            }
            let response = Response {
                request_id: request.request_id,
                lease_epoch: 12,
                status: Status::Uncertain,
            };
            assert_eq!(
                Response::decode(&response.encode().unwrap())
                    .unwrap()
                    .matches(request),
                Ok(response)
            );
        }
        for (nonce, old) in [
            (0, old),
            (u32::MAX, old),
            (3, RetiredOwner { process: 0, ..old }),
            (
                3,
                RetiredOwner {
                    registered: u64::MAX,
                    ..old
                },
            ),
        ] {
            assert!(
                Request {
                    command: Command::ReconcileFile {
                        slot: 0,
                        lease_epoch: 12,
                        old,
                        grant_nonce: nonce
                    },
                    ..bind()
                }
                .encode()
                .is_err()
            );
        }
        let mut namespace_bytes = namespace.encode().unwrap();
        namespace_bytes[9] = 1;
        assert_eq!(Request::decode(&namespace_bytes), Err(Error::Reserved));
    }
}
