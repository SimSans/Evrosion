//! Bounded application-registry metadata, independent of package bytes and live
//! handles. Prepare a new record, durably publish it through the actual Store,
//! then replace the old runtime snapshot. An indeterminate write requires Store
//! recovery/reopen; preparing or encoding this value proves no persistence.
//!
//! The trusted installer owns the registry object and namespace. It checks
//! package requirements, actual ELF admission, provenance/update permission and
//! quiesces/revokes the previous incarnation before changing live activation.
//! Nothing here converts a package's claimed AppId or declarations into grants.
use crate::{AppId, CompatiblePackage, DataSchema};
use sha2::{Digest, Sha256};

pub const BYTES: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    Digest,
    Stale,
    Exhausted,
    Identity,
    State,
    Data,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRef {
    digest: [u8; 32],
    schema: DataSchema,
}
impl VersionRef {
    pub fn from_package(compatible: &CompatiblePackage<'_, '_>) -> Self {
        let package = compatible.package();
        Self {
            digest: package.id().bytes(),
            schema: package.app().data_schema,
        }
    }
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
    pub const fn schema(self) -> DataSchema {
        self.schema
    }
    /// Recheck the full immutable package and its actual declared data interval
    /// after resolving a durable reference; disk metadata alone is not admission.
    pub fn matches(self, package: &CompatiblePackage<'_, '_>) -> bool {
        self == Self::from_package(package)
    }
}

/// One canonical AppIdentity's durable activation head. Package content is an
/// immutable object resolved separately by its entire hash; no path/PID/handle
/// appears here. Removed applications retain their data schema and identity.
#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    app: AppId,
    revision: u64,
    data_epoch: u32,
    installed: bool,
    active: Option<VersionRef>,
    previous: Option<VersionRef>,
    staged: Option<VersionRef>,
}
impl Record {
    /// Trusted registry has established that this AppId is unallocated. The
    /// data owner supplies the actual schema of its newly created empty data
    /// namespace; no existing identity/data may be assumed from a package claim.
    pub fn install(package: &CompatiblePackage<'_, '_>, data_epoch: u32) -> Result<Self, Error> {
        let version = VersionRef::from_package(package);
        if !version.schema.reads(data_epoch) {
            return Err(Error::Data);
        }
        Ok(Self {
            app: package.package().app().claimed_app,
            revision: 1,
            data_epoch,
            installed: true,
            active: None,
            previous: None,
            staged: Some(version),
        })
    }
    pub const fn app(&self) -> AppId {
        self.app
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn data_epoch(&self) -> u32 {
        self.data_epoch
    }
    pub const fn installed(&self) -> bool {
        self.installed
    }
    pub const fn active(&self) -> Option<VersionRef> {
        self.active
    }
    pub const fn previous(&self) -> Option<VersionRef> {
        self.previous
    }
    pub const fn staged(&self) -> Option<VersionRef> {
        self.staged
    }
    fn next(&self, expected: u64) -> Result<Self, Error> {
        if expected != self.revision {
            return Err(Error::Stale);
        }
        let revision = self
            .revision
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Exhausted)?;
        Ok(Self {
            app: self.app,
            revision,
            data_epoch: self.data_epoch,
            installed: self.installed,
            active: self.active,
            previous: self.previous,
            staged: self.staged,
        })
    }
    /// Explicit owner-authorized replacement of this existing identity. Staging
    /// leaves the running/active version unchanged until separate activation.
    pub fn stage(&self, expected: u64, package: &CompatiblePackage<'_, '_>) -> Result<Self, Error> {
        let mut next = self.next(expected)?;
        if !self.installed {
            return Err(Error::State);
        }
        next.stage_package(package)?;
        Ok(next)
    }
    /// Reinstallation is separate from update and preserves the actual data
    /// schema/tombstone identity; an incompatible package cannot erase the data.
    pub fn reinstall(
        &self,
        expected: u64,
        package: &CompatiblePackage<'_, '_>,
    ) -> Result<Self, Error> {
        let mut next = self.next(expected)?;
        if self.installed {
            return Err(Error::State);
        }
        next.stage_package(package)?;
        next.installed = true;
        Ok(next)
    }
    fn stage_package(&mut self, package: &CompatiblePackage<'_, '_>) -> Result<(), Error> {
        if package.package().app().claimed_app != self.app {
            return Err(Error::Identity);
        }
        let version = VersionRef::from_package(package);
        if !version.schema.reads(self.data_epoch) {
            return Err(Error::Data);
        }
        self.staged = Some(version);
        Ok(())
    }
    /// Candidate's actual executable and grants must be prepared before durable
    /// publication. A changed data epoch is rechecked at this final snapshot.
    pub fn activate(&self, expected: u64) -> Result<Self, Error> {
        let mut next = self.next(expected)?;
        if !self.installed {
            return Err(Error::State);
        }
        let candidate = self.staged.ok_or(Error::State)?;
        if !candidate.schema.reads(self.data_epoch) {
            return Err(Error::Data);
        }
        if self.active != Some(candidate) {
            next.previous = self.active.or(self.previous);
        }
        next.active = Some(candidate);
        next.staged = None;
        Ok(next)
    }
    /// This changes no application data. If the previous package cannot read
    /// the actual data epoch, rollback refuses instead of silently destroying it.
    pub fn rollback(&self, expected: u64) -> Result<Self, Error> {
        let mut next = self.next(expected)?;
        if !self.installed || self.active.is_none() {
            return Err(Error::State);
        }
        let previous = self.previous.ok_or(Error::State)?;
        if !previous.schema.reads(self.data_epoch) {
            return Err(Error::Data);
        }
        next.active = Some(previous);
        next.previous = self.active;
        next.staged = None;
        Ok(next)
    }
    /// Live quiescence/revocation happens under the trusted lifecycle owner.
    /// Immutable package garbage collection is separate; user data is retained.
    pub fn remove(&self, expected: u64) -> Result<Self, Error> {
        let mut next = self.next(expected)?;
        if !self.installed {
            return Err(Error::State);
        }
        next.previous = self.active.or(self.previous);
        next.active = None;
        next.staged = None;
        next.installed = false;
        Ok(next)
    }
    /// The data owner has actually committed a migration in its transaction.
    /// Never call from an untrusted App assertion or just a manifest declaration.
    pub fn data_migrated(&self, expected: u64, epoch: u32) -> Result<Self, Error> {
        let mut next = self.next(expected)?;
        let active = self.active.ok_or(Error::State)?;
        if epoch < self.data_epoch || epoch != active.schema.current {
            return Err(Error::Data);
        }
        if self.staged.is_some_and(|s| !s.schema.reads(epoch)) {
            return Err(Error::Data);
        }
        next.data_epoch = epoch;
        Ok(next)
    }
    pub fn encode(&self) -> [u8; BYTES] {
        let mut b = [0; BYTES];
        b[..8].copy_from_slice(b"EVAPP001");
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10] = u8::from(self.installed)
            | (u8::from(self.active.is_some()) << 1)
            | (u8::from(self.previous.is_some()) << 2)
            | (u8::from(self.staged.is_some()) << 3);
        b[16..32].copy_from_slice(&self.app.bytes());
        b[32..40].copy_from_slice(&self.revision.to_le_bytes());
        b[40..44].copy_from_slice(&self.data_epoch.to_le_bytes());
        for (slot, version) in b[48..168].as_chunks_mut::<40>().0.iter_mut().zip([
            self.active,
            self.previous,
            self.staged,
        ]) {
            if let Some(v) = version {
                slot[..32].copy_from_slice(&v.digest);
                slot[32..36].copy_from_slice(&v.schema.current.to_le_bytes());
                slot[36..40].copy_from_slice(&v.schema.oldest_readable.to_le_bytes());
            }
        }
        let digest = checksum(&b);
        b[224..].copy_from_slice(&digest);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BYTES
            || &b[..8] != b"EVAPP001"
            || b[8..10] != 1u16.to_le_bytes()
            || b[10] & !15 != 0
            || b[11..16]
                .iter()
                .chain(&b[44..48])
                .chain(&b[168..224])
                .any(|v| *v != 0)
        {
            return Err(Error::Format);
        }
        let bytes: &[u8; BYTES] = b.try_into().map_err(|_| Error::Format)?;
        if b[224..] != checksum(bytes) {
            return Err(Error::Digest);
        }
        let app = AppId::new(b[16..32].try_into().unwrap()).ok_or(Error::Identity)?;
        let revision = u64::from_le_bytes(b[32..40].try_into().unwrap());
        if revision == 0 || revision == u64::MAX {
            return Err(Error::Exhausted);
        }
        let mut versions = [None; 3];
        for (i, slot) in b[48..168].as_chunks::<40>().0.iter().enumerate() {
            if b[10] & (2 << i) == 0 {
                if slot.iter().any(|v| *v != 0) {
                    return Err(Error::Format);
                }
                continue;
            }
            let schema = DataSchema {
                current: u32::from_le_bytes(slot[32..36].try_into().unwrap()),
                oldest_readable: u32::from_le_bytes(slot[36..40].try_into().unwrap()),
            };
            if schema.oldest_readable == 0 || schema.oldest_readable > schema.current {
                return Err(Error::Data);
            }
            versions[i] = Some(VersionRef {
                digest: slot[..32].try_into().unwrap(),
                schema,
            });
        }
        let record = Self {
            app,
            revision,
            data_epoch: u32::from_le_bytes(b[40..44].try_into().unwrap()),
            installed: b[10] & 1 != 0,
            active: versions[0],
            previous: versions[1],
            staged: versions[2],
        };
        if (!record.installed && (record.active.is_some() || record.staged.is_some()))
            || (record.installed && record.active.is_none() && record.staged.is_none())
            || record
                .active
                .is_some_and(|v| !v.schema.reads(record.data_epoch))
            || record
                .staged
                .is_some_and(|v| !v.schema.reads(record.data_epoch))
        {
            return Err(Error::State);
        }
        Ok(record)
    }
}
fn checksum(bytes: &[u8; BYTES]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"evrosion.app-registry.v1\0");
    hash.update(&bytes[..224]);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn version(d: u8, current: u32, oldest_readable: u32) -> VersionRef {
        VersionRef {
            digest: [d; 32],
            schema: DataSchema {
                current,
                oldest_readable,
            },
        }
    }
    fn initial() -> Record {
        Record {
            app: AppId::new([1; 16]).unwrap(),
            revision: 1,
            data_epoch: 1,
            installed: true,
            active: None,
            previous: None,
            staged: Some(version(1, 1, 1)),
        }
    }
    fn reseal(b: &mut [u8; BYTES]) {
        let digest = checksum(b);
        b[224..].copy_from_slice(&digest);
    }
    #[test]
    fn activation_is_separate_and_staging_does_not_replace_the_active_version() {
        let first = initial();
        assert_eq!(first.active(), None);
        let active = first.activate(1).unwrap();
        assert_eq!(active.active(), Some(version(1, 1, 1)));
        assert_eq!(first.active(), None);
        let mut staged = active.next(2).unwrap();
        staged.staged = Some(version(2, 1, 1));
        assert_eq!(staged.active(), active.active());
        let updated = staged.activate(3).unwrap();
        assert_eq!(updated.active(), Some(version(2, 1, 1)));
        assert_eq!(updated.previous(), Some(version(1, 1, 1)));
        let rolled = updated.rollback(4).unwrap();
        assert_eq!(rolled.active(), Some(version(1, 1, 1)));
        assert_eq!(rolled.previous(), Some(version(2, 1, 1)));
        assert!(matches!(rolled.rollback(4), Err(Error::Stale)));
    }
    #[test]
    fn removal_preserves_identity_data_epoch_and_recovery_reference() {
        let active = initial().activate(1).unwrap();
        let removed = active.remove(2).unwrap();
        assert!(!removed.installed());
        assert_eq!(removed.active(), None);
        assert_eq!(removed.staged(), None);
        assert_eq!(removed.data_epoch(), 1);
        assert_eq!(removed.app(), active.app());
        assert_eq!(removed.previous(), active.active());
        assert!(matches!(removed.rollback(3), Err(Error::State)));
        assert!(matches!(removed.activate(3), Err(Error::State)));
        assert_eq!(Record::decode(&removed.encode()).unwrap(), removed);
    }
    #[test]
    fn incompatible_data_rollback_refuses_without_mutating_either_version() {
        let mut next = initial().activate(1).unwrap().next(2).unwrap();
        next.staged = Some(version(2, 2, 1));
        let active = next.activate(3).unwrap();
        let migrated = active.data_migrated(4, 2).unwrap();
        let before = migrated.encode();
        assert!(matches!(migrated.rollback(5), Err(Error::Data)));
        assert_eq!(migrated.encode(), before);
        assert_eq!(Record::decode(&before).unwrap(), migrated);
        assert!(matches!(migrated.data_migrated(5, 1), Err(Error::Data)));
    }
    #[test]
    fn stale_or_exhausted_metadata_preconditions_never_modify_old_head() {
        let mut record = initial();
        let old = record.encode();
        assert!(matches!(record.activate(0), Err(Error::Stale)));
        assert_eq!(record.encode(), old);
        record.revision = u64::MAX - 1;
        let old = record.encode();
        assert!(matches!(
            record.activate(u64::MAX - 1),
            Err(Error::Exhausted)
        ));
        assert_eq!(record.encode(), old);
    }
    #[test]
    fn corruption_unknown_fields_and_resealed_invalid_state_fail_closed() {
        let good = initial().encode();
        assert_eq!(Record::decode(&good).unwrap(), initial());
        for i in 0..BYTES {
            let mut b = good;
            b[i] ^= 0x80;
            assert!(Record::decode(&b).is_err(), "{i}");
        }
        for i in [8, 11, 44, 168, 223] {
            let mut b = good;
            b[i] = 255;
            reseal(&mut b);
            assert!(Record::decode(&b).is_err());
        }
        for flags in [0, 1, 8, 16, 255] {
            let mut b = good;
            b[10] = flags;
            reseal(&mut b);
            assert!(Record::decode(&b).is_err());
        }
        let mut b = good;
        b[88..120].fill(1);
        reseal(&mut b);
        assert!(Record::decode(&b).is_err());
    }
}
