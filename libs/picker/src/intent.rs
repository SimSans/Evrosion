//! Durable per-user READ intent DATA, not a serialized capability or permission
//! to mint one. Trusted policy storage/index and actual runtime authority remain
//! necessary. Initial policy pins package and rechecks the approved file revision
//! at activation; it promises no immutable snapshot after a live object grant.
use super::*;
pub const BYTES: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Temporary,
    Invalid,
    Integrity,
    Revoked,
    StalePolicy,
    Subject,
    Resource,
    Denied,
    Exhausted,
}
/// Data read from the authoritative per-user latest-policy index. Constructing
/// or copying this snapshot does not authenticate that index or grant authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyHead {
    pub user: UserId,
    pub grant_serial: u64,
    pub revision: u64,
    pub record_digest: [u8; 32],
}
/// Canonical immutable policy metadata. Accessors do not expose mutation or
/// turn a decoded record into authority.
/// ```compile_fail,E0616
/// use ev_picker::intent::Record;
/// fn replace_subject(record: &mut Record) { record.app = record.app(); }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    grant_serial: u64,
    policy_revision: u64,
    user: UserId,
    app: AppRef,
    object: ObjectId,
    revision: Revision,
    approver: UserId,
    origin: Origin,
    action: [u8; 32],
    revoked: bool,
}

impl Record {
    /// A proposal to the ONE trusted grant-policy service, only when the owner
    /// explicitly chose Remember. Persist with existing E-010/E-019 operations;
    /// this constructor does not write, authenticate consent or create a cap.
    pub fn proposed(
        request: &ReadDelivery<'_>,
        grant_serial: u64,
        policy_revision: u64,
    ) -> Result<Self, Error> {
        let s = request.selection;
        if s.persistence != Persistence::RememberPerUser {
            return Err(Error::Temporary);
        }
        if !valid_number(grant_serial) || !valid_number(policy_revision) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            grant_serial,
            policy_revision,
            user: s.requester.user,
            app: s.requester.app,
            object: s.object.object,
            revision: s.object.revision,
            approver: request.consent.approver,
            origin: request.consent.origin,
            action: s.digest,
            revoked: false,
        })
    }
    pub const fn grant_serial(&self) -> u64 {
        self.grant_serial
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub const fn user(&self) -> UserId {
        self.user
    }
    /// Subject metadata only; possession creates no runtime authority.
    pub const fn app(&self) -> AppRef {
        self.app
    }
    /// Stable selected File identity, never a path/handle or raw disk selector.
    pub const fn object(&self) -> ObjectId {
        self.object
    }
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub const fn approver(&self) -> UserId {
        self.approver
    }
    pub const fn origin(&self) -> Origin {
        self.origin
    }
    pub const fn action_digest(&self) -> [u8; 32] {
        self.action
    }
    pub const fn revoked(&self) -> bool {
        self.revoked
    }
    pub fn head(&self) -> PolicyHead {
        let bytes = self.encode();
        let mut record_digest = [0; 32];
        record_digest.copy_from_slice(&bytes[224..]);
        PolicyHead {
            user: self.user,
            grant_serial: self.grant_serial,
            revision: self.policy_revision,
            record_digest,
        }
    }
    /// Only metadata; persist a new durable version and revoke already-created
    /// runtime branches separately. Old active records must fail latest-index
    /// validation; a valid checksum is neither authenticity nor rollback defense.
    pub fn revoke(&mut self) -> Result<(), Error> {
        let next = self
            .policy_revision
            .checked_add(1)
            .filter(|n| valid_number(*n))
            .ok_or(Error::Exhausted)?;
        self.policy_revision = next;
        self.revoked = true;
        Ok(())
    }
    /// Policy precondition only, NOT a mint API. The trusted activation service
    /// must supply its authoritative latest record revision, current actual
    /// user/AppIdentity+package and live incarnation, revalidate source authority,
    /// then use the existing capability delegation/transfer mechanism.
    /// Session/PID/boot/monotonic approval deadline are deliberately not stored.
    pub fn validate_activation(
        &self,
        latest: PolicyHead,
        current: Requester,
        object: ObjectView,
    ) -> Result<(), Error> {
        if self.revoked {
            return Err(Error::Revoked);
        }
        if latest != self.head() {
            return Err(Error::StalePolicy);
        }
        if !current.alive || current.user != self.user || current.app != self.app {
            return Err(Error::Subject);
        }
        if object.object != self.object || object.revision != self.revision {
            return Err(Error::Resource);
        }
        if !object.readable {
            return Err(Error::Denied);
        }
        Ok(())
    }
    pub fn encode(&self) -> [u8; BYTES] {
        let mut b = [0; BYTES];
        b[..8].copy_from_slice(b"EVGINT01");
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10] = 1; // semantic File READ, not a raw kernel Endpoint rights mask.
        b[11] = if self.revoked { 2 } else { 1 };
        b[12] = match self.origin {
            Origin::TrustedPicker => 1,
            Origin::ExplicitOwnerAction => 2,
        };
        b[13] = 1; // UntilRevoked policy; never a persisted monotonic timestamp.
        b[16..24].copy_from_slice(&self.grant_serial.to_le_bytes());
        b[24..32].copy_from_slice(&self.policy_revision.to_le_bytes());
        b[32..48].copy_from_slice(&self.user.0);
        b[48..64].copy_from_slice(&self.app.app.bytes());
        b[64..96].copy_from_slice(&self.app.package.0);
        b[96..112].copy_from_slice(&self.object.volume.0);
        b[112..120].copy_from_slice(&self.object.local.to_le_bytes());
        b[120..128].copy_from_slice(&self.revision.counter.to_le_bytes());
        b[128..160].copy_from_slice(&self.revision.content.0);
        b[160..176].copy_from_slice(&self.approver.0);
        b[176..208].copy_from_slice(&self.action);
        let sum: [u8; 32] = Sha256::digest(&b[..224]).into();
        b[224..].copy_from_slice(&sum);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BYTES
            || &b[..8] != b"EVGINT01"
            || b[8..10] != 1u16.to_le_bytes()
            || b[10] != 1
            || !matches!(b[11], 1 | 2)
            || !matches!(b[12], 1 | 2)
            || b[13] != 1
            || b[14..16].iter().chain(&b[208..224]).any(|n| *n != 0)
        {
            return Err(Error::Invalid);
        }
        let sum: [u8; 32] = Sha256::digest(&b[..224]).into();
        if b[224..] != sum {
            return Err(Error::Integrity);
        }
        let id = |offset: usize| -> Result<[u8; 16], Error> {
            b[offset..offset + 16]
                .try_into()
                .map_err(|_| Error::Invalid)
        };
        let hash = |offset: usize| -> Result<[u8; 32], Error> {
            b[offset..offset + 32]
                .try_into()
                .map_err(|_| Error::Invalid)
        };
        let word = |offset: usize| -> Result<u64, Error> {
            Ok(u64::from_le_bytes(
                b[offset..offset + 8]
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            ))
        };
        let grant_serial = word(16)?;
        let policy_revision = word(24)?;
        if !valid_number(grant_serial) || !valid_number(policy_revision) {
            return Err(Error::Invalid);
        }
        let user = UserId::new(id(32)?).ok_or(Error::Invalid)?;
        let app = AppRef {
            app: AppId::new(id(48)?).ok_or(Error::Invalid)?,
            package: ContentDigest::new(hash(64)?).ok_or(Error::Invalid)?,
        };
        let object = ObjectId::new(VolumeId::new(id(96)?).ok_or(Error::Invalid)?, word(112)?)
            .ok_or(Error::Invalid)?;
        let revision = Revision::new(
            word(120)?,
            ContentDigest::new(hash(128)?).ok_or(Error::Invalid)?,
        )
        .ok_or(Error::Invalid)?;
        let approver = UserId::new(id(160)?).ok_or(Error::Invalid)?;
        let action = hash(176)?;
        if approver != user || action.iter().all(|n| *n == 0) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            grant_serial,
            policy_revision,
            user,
            app,
            object,
            revision,
            approver,
            origin: if b[12] == 1 {
                Origin::TrustedPicker
            } else {
                Origin::ExplicitOwnerAction
            },
            action,
            revoked: b[11] == 2,
        })
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;

    #[test]
    fn decoded_subject_and_resource_views_cannot_mutate_the_canonical_record() {
        let original = Record {
            grant_serial: 7,
            policy_revision: 9,
            user: UserId::new([1; 16]).unwrap(),
            app: AppRef {
                app: AppId::new([2; 16]).unwrap(),
                package: ContentDigest::new([3; 32]).unwrap(),
            },
            object: ObjectId::new(VolumeId::new([4; 16]).unwrap(), 11).unwrap(),
            revision: Revision::new(12, ContentDigest::new([5; 32]).unwrap()).unwrap(),
            approver: UserId::new([1; 16]).unwrap(),
            origin: Origin::ExplicitOwnerAction,
            action: [6; 32],
            revoked: false,
        };
        let before = original.encode();
        let decoded = Record::decode(&before).unwrap();
        assert_eq!(decoded.app(), original.app);
        assert_eq!(decoded.object(), original.object);
        assert_eq!(decoded.revision(), original.revision);
        assert_eq!(decoded.approver(), original.approver);
        assert_eq!(decoded.origin(), Origin::ExplicitOwnerAction);
        assert_eq!(decoded.action_digest(), original.action);

        let mut detached = decoded.app();
        detached.package = ContentDigest::new([0x71; 32]).unwrap();
        assert_ne!(detached, decoded.app());
        assert_eq!(decoded.encode(), before);
        assert_eq!(&before[..8], b"EVGINT01");
        assert_eq!(&before[48..64], &decoded.app().app.bytes());
        assert_eq!(&before[64..96], &decoded.app().package.bytes());
        assert_eq!(&before[96..112], &decoded.object().volume().bytes());
        assert_eq!(
            &before[120..128],
            &decoded.revision().counter().to_le_bytes()
        );
        assert_eq!(&before[128..160], &decoded.revision().content().bytes());
        assert_eq!(&before[160..176], &decoded.approver().bytes());
        assert_eq!(&before[176..208], &decoded.action_digest());
    }
}
