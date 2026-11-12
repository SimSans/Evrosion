//! Bounded durable application-registry publication; no installer or grant path.
//!
//! One trusted installer owns this whole Store region EXCLUSIVELY. Immutable
//! package references resolve actual parsed bytes and current host requirements;
//! a metadata update is neither executable admission nor authorization. Stop and
//! revoke any old runtime separately before exposing a changed activation head.
//! No method claims package publisher authentication or changes App data.
#![no_std]
#![forbid(unsafe_code)]
use ev_store::{BootPolicy, GenerationManifest, ObjectId, OperationId, Request, SectorIo, Store};
use ev_zion::{
    AppId, CompatiblePackage, Contracts, Package,
    lifecycle::{self, Record},
};
use sha2::{Digest as _, Sha256};

pub mod app_data;
pub mod region;
#[cfg(test)]
mod tests;

// Exact existing StoreV2 payload, not the journal/root envelope capacity.
const _: () = assert!(ev_store::PAYLOAD_BYTES == 256 && lifecycle::BYTES == 256);
type Digest = [u8; 32];

/// Resolver retains actual immutable complete package containers. The bridge
/// parses/hashes bytes or reuses a validated view of the EXACT immutable backing
/// slice, then compares the FULL package ID, actual AppId, schema and current
/// host compatibility. Caller-provided parsed struct fields, paths
/// and claimed digest tags are never sufficient to satisfy a durable ref.
/// ```compile_fail,E0616
/// use ev_zion::Package;
/// fn forge(package: &mut Package<'_>) { package.id = package.id(); }
/// ```
/// ```compile_fail,E0594
/// use ev_zion::Package;
/// fn forge(package: &mut Package<'_>) { package.app().abi = [9; 32]; }
/// ```
pub trait Packages {
    fn resolve(&self, digest: Digest) -> Option<&[u8]>;
    /// Optional fully parsed immutable view. Reuse requires pointer AND length
    /// equality with `resolve`; a detached or differently backed view cannot
    /// replace resolved bytes. Current identity/compatibility checks still run.
    fn parsed(&self, _digest: Digest) -> Option<&Package<'_>> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub app: AppId,
    pub abi: Digest,
    pub platform: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    pub revision: u64,
    pub base_head: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Install {
        package: Digest,
        data_epoch: u32,
    },
    Stage {
        package: Digest,
    },
    Activate,
    /// Stage and activate in ONE durable Store operation. Lifecycle revision
    /// advances twice, exactly as the existing Record stage/activate APIs do.
    Replace {
        package: Digest,
    },
    Rollback,
    Remove,
    Reinstall {
        package: Digest,
    },
    /// Only the trusted actual data owner may assert an already committed
    /// migration; this bridge does not execute or invent a migration.
    DataMigrated {
        epoch: u32,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Store(ev_store::Error<E>),
    Metadata(lifecycle::Error),
    Package(ev_zion::Error),
    MissingPackage,
    WrongPackage,
    Identity,
    Stale,
    NeedsRecovery,
    RecoveryConflict,
    Readback,
}

pub struct Rejected<D: SectorIo> {
    pub device: D,
    pub policy: Policy,
    pub pending: Option<Prepared>,
    pub error: Error<D::Error>,
}

/// Move-only intent. Fields cannot be synthesized by ordinary callers. Retain
/// this exact operation/payload through recovery; never allocate a fresh ID to
/// retry an unresolved publication.
/// ```compile_fail
/// use ev_app_registry::Prepared;
/// fn duplicate(intent: Prepared) { let first = intent; let second = intent; }
/// ```
#[derive(Debug)]
pub struct Prepared {
    policy: Policy,
    base: Expected,
    operation: OperationId,
    bytes: [u8; lifecycle::BYTES],
}
impl Prepared {
    pub const fn operation(&self) -> OperationId {
        self.operation
    }
    pub fn after(&self) -> Record {
        Record::decode(&self.bytes).expect("prepared canonical metadata")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    pub operation: OperationId,
    pub sequence: u64,
    pub revision: u64,
    pub recovered: bool,
}

/// Durable outcome AFTER Store recovery and an exact fresh readback. These
/// labels describe publication only, never whether application code ran.
// Bounded canonical256-byte retry intent stays owned without alloc/Box.
#[allow(clippy::large_enum_variant)]
pub enum Resolution {
    Committed(Published),
    Unpublished(Prepared),
    NoPending,
}

pub struct Registry<D: SectorIo> {
    store: Store<D>,
    policy: Policy,
    record: Option<Record>,
    pending: Option<Prepared>,
}
impl<D: SectorIo> Registry<D> {
    /// Explicit blank-only allocation. `manifest` is the trusted enclosing Store
    /// format context, left Pending with KnownGood=None; it is NOT app health.
    // Return the actual backend and bounded pending intent on every refusal.
    #[allow(clippy::result_large_err)]
    pub fn format_new(
        device: D,
        policy: Policy,
        manifest: GenerationManifest,
        deadline: u64,
    ) -> Result<Self, Rejected<D>> {
        let store =
            match Store::format_new(device, manifest, &[], BootPolicy::new(1).unwrap(), deadline) {
                Ok(s) => s,
                Err(rejected) => {
                    return Err(Rejected {
                        device: rejected.device,
                        policy,
                        pending: None,
                        error: Error::Store(rejected.error),
                    });
                }
            };
        Ok(Self {
            store,
            policy,
            record: None,
            pending: None,
        })
    }
    // Return the actual backend and bounded pending intent on every refusal.
    #[allow(clippy::result_large_err)]
    // This constructor returns the full owner. Inline it at bounded scoped
    // ownership boundaries so a second Registry Result frame is not retained.
    #[inline(always)]
    pub fn open(
        device: D,
        policy: Policy,
        packages: &impl Packages,
        contracts: &impl Contracts,
        deadline: u64,
    ) -> Result<Self, Rejected<D>> {
        // A cold open has no retained uncertain intent. Keep its actual owner
        // path separate from resume's larger (Registry, Resolution) result so
        // ordinary Root operations do not copy a recovery tuple on every open.
        let mut store = match Store::open(device, deadline) {
            Ok(store) => store,
            Err(rejected) => {
                return Err(Rejected {
                    device: rejected.device,
                    policy,
                    pending: None,
                    error: Error::Store(rejected.error),
                });
            }
        };
        let record = match load(&mut store, policy, packages, contracts, deadline) {
            Ok(record) => record,
            Err(error) => {
                return Err(Rejected {
                    device: store.into_device(),
                    policy,
                    pending: None,
                    error,
                });
            }
        };
        Ok(Self {
            store,
            policy,
            record,
            pending: None,
        })
    }
    /// Open and use the sole Registry owner within one bounded storage frame.
    /// Only the device and the operation's owned result escape. In particular,
    /// callers need not retain large Store/Registry recovery results on their
    /// already-live runtime stack. A refused operation returns its exact backend
    /// and any unresolved move-only publication intent; no recovery is inferred.
    #[inline(never)]
    #[allow(clippy::result_large_err)]
    pub fn with_open<T>(
        device: D,
        policy: Policy,
        packages: &impl Packages,
        contracts: &impl Contracts,
        deadline: u64,
        operation: impl FnOnce(&mut Self) -> Result<T, Error<D::Error>>,
    ) -> Result<(D, T), Rejected<D>> {
        let mut registry = Self::open(device, policy, packages, contracts, deadline)?;
        let outcome = operation(&mut registry);
        let (device, policy, pending) = registry.into_parts();
        match outcome {
            Ok(value) if pending.is_none() => Ok((device, value)),
            Ok(_) => Err(Rejected {
                device,
                policy,
                pending,
                error: Error::NeedsRecovery,
            }),
            Err(error) => Err(Rejected {
                device,
                policy,
                pending,
                error,
            }),
        }
    }
    /// Caller has independently restored a usable, fenced device/backend after
    /// the old writer stopped. This performs ordinary Store recovery, NOT an
    /// unbounded transport retry or hardware reset. On every refusal, the actual
    /// device and move-only pending intent are returned without fabrication.
    // Return the actual backend and bounded pending intent on every refusal.
    #[allow(clippy::result_large_err)]
    pub fn resume(
        device: D,
        policy: Policy,
        pending: Option<Prepared>,
        packages: &impl Packages,
        contracts: &impl Contracts,
        deadline: u64,
    ) -> Result<(Self, Resolution), Rejected<D>> {
        if pending
            .as_ref()
            .is_some_and(|intent| intent.policy != policy)
        {
            return Err(Rejected {
                device,
                policy,
                pending,
                error: Error::RecoveryConflict,
            });
        }
        let mut store = match Store::open(device, deadline) {
            Ok(s) => s,
            Err(rejected) => {
                return Err(Rejected {
                    device: rejected.device,
                    policy,
                    pending,
                    error: Error::Store(rejected.error),
                });
            }
        };
        let record = match load(&mut store, policy, packages, contracts, deadline) {
            Ok(r) => r,
            Err(error) => {
                return Err(Rejected {
                    device: store.into_device(),
                    policy,
                    pending,
                    error,
                });
            }
        };
        if let Some(intent) = &pending {
            let check = Record::decode(&intent.bytes)
                .map_err(Error::Metadata)
                .and_then(|record| revalidate(&record, policy, packages, contracts));
            if let Err(error) = check {
                return Err(Rejected {
                    device: store.into_device(),
                    policy,
                    pending,
                    error,
                });
            }
        }
        let registry = Self {
            store,
            policy,
            record,
            pending: None,
        };
        let resolution = match pending {
            None => Resolution::NoPending,
            Some(intent) => {
                let next = match registry.store.next_operation() {
                    Ok(next) => next,
                    Err(error) => {
                        return Err(Rejected {
                            device: registry.store.into_device(),
                            policy,
                            pending: Some(intent),
                            error: Error::Store(error),
                        });
                    }
                };
                let actual = head(policy, registry.record.as_ref(), next);
                if next == intent.operation && actual == intent.base {
                    Resolution::Unpublished(intent)
                } else if intent.operation.get().checked_add(1) == Some(next.get())
                    && registry
                        .record
                        .as_ref()
                        .is_some_and(|r| r.encode() == intent.bytes)
                {
                    Resolution::Committed(Published {
                        operation: intent.operation,
                        sequence: next.get(),
                        revision: registry.record.as_ref().unwrap().revision(),
                        recovered: true,
                    })
                } else {
                    return Err(Rejected {
                        device: registry.store.into_device(),
                        policy,
                        pending: Some(intent),
                        error: Error::RecoveryConflict,
                    });
                }
            }
        };
        // No health or known-good transition is performed by this registry.
        Ok((registry, resolution))
    }
    pub fn expected(&self) -> Result<Expected, Error<D::Error>> {
        if self.pending.is_some() {
            return Err(Error::NeedsRecovery);
        }
        let next = self.store.next_operation().map_err(Error::Store)?;
        Ok(head(self.policy, self.record.as_ref(), next))
    }
    pub fn record(&self) -> Result<Option<&Record>, Error<D::Error>> {
        self.expected()?;
        Ok(self.record.as_ref())
    }
    pub fn prepare(
        &self,
        expected: Expected,
        change: Change,
        packages: &impl Packages,
        contracts: &impl Contracts,
    ) -> Result<Prepared, Error<D::Error>> {
        if self.expected()? != expected {
            return Err(Error::Stale);
        }
        if let Some(record) = &self.record {
            revalidate(record, self.policy, packages, contracts)?;
        }
        let old = || {
            self.record
                .as_ref()
                .ok_or(Error::Metadata(lifecycle::Error::State))
        };
        let next = match change {
            Change::Install {
                package,
                data_epoch,
            } => {
                if self.record.is_some() {
                    return Err(Error::Metadata(lifecycle::Error::State));
                }
                with_package(package, self.policy, packages, contracts, |actual| {
                    Record::install(actual, data_epoch).map_err(Error::Metadata)
                })
            }
            Change::Stage { package } => {
                let old = old()?;
                with_package(package, self.policy, packages, contracts, |actual| {
                    old.stage(expected.revision, actual)
                        .map_err(Error::Metadata)
                })
            }
            Change::Activate => old()?.activate(expected.revision).map_err(Error::Metadata),
            Change::Replace { package } => {
                let old = old()?;
                with_package(package, self.policy, packages, contracts, |actual| {
                    let staged = old
                        .stage(expected.revision, actual)
                        .map_err(Error::Metadata)?;
                    staged.activate(staged.revision()).map_err(Error::Metadata)
                })
            }
            Change::Rollback => old()?.rollback(expected.revision).map_err(Error::Metadata),
            Change::Remove => old()?.remove(expected.revision).map_err(Error::Metadata),
            Change::Reinstall { package } => {
                let old = old()?;
                with_package(package, self.policy, packages, contracts, |actual| {
                    old.reinstall(expected.revision, actual)
                        .map_err(Error::Metadata)
                })
            }
            Change::DataMigrated { epoch } => old()?
                .data_migrated(expected.revision, epoch)
                .map_err(Error::Metadata),
        }?;
        revalidate(&next, self.policy, packages, contracts)?;
        Ok(Prepared {
            policy: self.policy,
            base: expected,
            operation: self.store.next_operation().map_err(Error::Store)?,
            bytes: next.encode(),
        })
    }
    pub fn publish(
        &mut self,
        intent: Prepared,
        packages: &impl Packages,
        contracts: &impl Contracts,
        deadline: u64,
    ) -> Result<Published, Error<D::Error>> {
        if intent.policy != self.policy
            || self.expected()? != intent.base
            || self.store.next_operation().map_err(Error::Store)? != intent.operation
        {
            return Err(Error::Stale);
        }
        let after = Record::decode(&intent.bytes).map_err(Error::Metadata)?;
        revalidate(&after, self.policy, packages, contracts)?;
        if let Some(current) = &self.record {
            revalidate(current, self.policy, packages, contracts)?;
        }
        // Publish owns the intent before touching the backend. Every error from
        // execute/readback leaves it retained and requires explicit recovery.
        self.pending = Some(intent);
        let intent = self.pending.as_ref().unwrap();
        let receipt = self
            .store
            .execute(
                intent.operation,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &intent.bytes,
                },
                deadline,
            )
            .map_err(Error::Store)?;
        let mut actual = [0; lifecycle::BYTES];
        let len = self
            .store
            .read_mutable(ObjectId::user_data(), &mut actual, deadline)
            .map_err(Error::Store)?;
        if len != lifecycle::BYTES || actual != intent.bytes {
            return Err(Error::Readback);
        }
        let record = Record::decode(&actual).map_err(Error::Metadata)?;
        let published = Published {
            operation: receipt.operation,
            sequence: receipt.sequence,
            revision: record.revision(),
            recovered: false,
        };
        self.record = Some(record);
        self.pending = None;
        Ok(published)
    }
    /// Consuming extraction keeps unresolved intent with its only device owner.
    /// Caller must fence/stop this writer and restore the backend before resume.
    pub fn into_parts(self) -> (D, Policy, Option<Prepared>) {
        (self.store.into_device(), self.policy, self.pending)
    }
}
fn with_package<T, E>(
    id: Digest,
    policy: Policy,
    packages: &impl Packages,
    contracts: &impl Contracts,
    inspect: impl FnOnce(&CompatiblePackage<'_, '_>) -> Result<T, Error<E>>,
) -> Result<T, Error<E>> {
    let bytes = packages.resolve(id).ok_or(Error::MissingPackage)?;
    let fresh;
    let package = match packages.parsed(id) {
        Some(package) if core::ptr::eq(package.bytes(), bytes) => package,
        _ => {
            fresh = Package::parse(bytes).map_err(Error::Package)?;
            &fresh
        }
    };
    if package.id().bytes() != id {
        return Err(Error::WrongPackage);
    }
    if package.app().claimed_app != policy.app {
        return Err(Error::Identity);
    }
    let compatible = package
        .compatible(policy.platform, policy.abi, contracts)
        .map_err(Error::Package)?;
    inspect(&compatible)
}
fn revalidate<E>(
    record: &Record,
    policy: Policy,
    packages: &impl Packages,
    contracts: &impl Contracts,
) -> Result<(), Error<E>> {
    if record.app() != policy.app {
        return Err(Error::Identity);
    }
    for version in [record.active(), record.previous(), record.staged()]
        .into_iter()
        .flatten()
    {
        with_package(version.digest(), policy, packages, contracts, |actual| {
            if version.matches(actual) {
                Ok(())
            } else {
                Err(Error::WrongPackage)
            }
        })?;
    }
    Ok(())
}
fn load<D: SectorIo>(
    store: &mut Store<D>,
    policy: Policy,
    packages: &impl Packages,
    contracts: &impl Contracts,
    deadline: u64,
) -> Result<Option<Record>, Error<D::Error>> {
    let mut bytes = [0; lifecycle::BYTES];
    let len = store
        .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
        .map_err(Error::Store)?;
    if len == 0 {
        return Ok(None);
    }
    if len != lifecycle::BYTES {
        return Err(Error::Readback);
    }
    let record = Record::decode(&bytes).map_err(Error::Metadata)?;
    revalidate(&record, policy, packages, contracts)?;
    Ok(Some(record))
}
fn head(policy: Policy, record: Option<&Record>, next: OperationId) -> Expected {
    let revision = record.map_or(0, Record::revision);
    let mut hash = Sha256::new();
    hash.update(b"evrosion.app-registry.head.v1\0");
    hash.update(policy.app.bytes());
    hash.update(policy.abi);
    hash.update(policy.platform.to_le_bytes());
    hash.update(revision.to_le_bytes());
    hash.update(next.get().to_le_bytes());
    if let Some(record) = record {
        hash.update(record.encode());
    }
    Expected {
        revision,
        base_head: hash.finalize().into(),
    }
}
