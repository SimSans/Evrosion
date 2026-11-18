//! Exact caller-owned cold namespace validation before Store recovery writes.
use super::*;
use ev_store::MutablePayload;

impl<D: SectorIo> Registry<D> {
    /// Open the independently owned mutable-only registry namespace. The caller
    /// supplies its original creation manifest, never a descriptor inferred from
    /// the disk or the currently offered package. Committed metadata and a
    /// checksum/base-bound pending mutation must both resolve canonical actual
    /// packages under the current policy before Store may recover anything.
    ///
    /// This is a cold constructor without a retained `Prepared` intent. It does
    /// not allocate/format, admit an executable, or establish update permission.
    #[inline(always)]
    #[allow(clippy::result_large_err)]
    pub fn open_checked(
        device: D,
        policy: Policy,
        original_creation: &GenerationManifest,
        packages: &impl Packages,
        contracts: &impl Contracts,
        deadline: u64,
    ) -> Result<Self, Rejected<D>> {
        let mut payload_error = None;
        let opened = Store::open_mutable_namespace_checked(
            device,
            original_creation,
            |payload| {
                let result = match payload {
                    MutablePayload::Committed(bytes) => {
                        checked_record(bytes, policy, packages, contracts).map(|_| ())
                    }
                    MutablePayload::Pending {
                        committed,
                        proposed,
                    } => checked_pending(committed, proposed, policy, packages, contracts),
                };
                match result {
                    Ok(()) => true,
                    Err(error) => {
                        payload_error = Some(error);
                        false
                    }
                }
            },
            deadline,
        );
        let mut store = match opened {
            Ok(store) => store,
            Err(rejected) => {
                return Err(Rejected {
                    device: rejected.device,
                    policy,
                    pending: None,
                    error: payload_error.unwrap_or(Error::Store(rejected.error)),
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

    /// Scoped checked cold open. As with `with_open`, the actual backend and
    /// any unresolved move-only publication intent escape on every refusal.
    #[inline(never)]
    #[allow(clippy::result_large_err)]
    pub fn with_open_checked<T>(
        device: D,
        policy: Policy,
        original_creation: &GenerationManifest,
        packages: &impl Packages,
        contracts: &impl Contracts,
        deadline: u64,
        operation: impl FnOnce(&mut Self) -> Result<T, Error<D::Error>>,
    ) -> Result<(D, T), Rejected<D>> {
        let mut registry = Self::open_checked(
            device,
            policy,
            original_creation,
            packages,
            contracts,
            deadline,
        )?;
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
}

fn checked_record<E>(
    bytes: &[u8],
    policy: Policy,
    packages: &impl Packages,
    contracts: &impl Contracts,
) -> Result<Option<Record>, Error<E>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != lifecycle::BYTES {
        return Err(Error::Readback);
    }
    let record = Record::decode(bytes).map_err(Error::Metadata)?;
    revalidate(&record, policy, packages, contracts)?;
    Ok(Some(record))
}

fn checked_pending<E>(
    committed: &[u8],
    proposed: &[u8],
    policy: Policy,
    packages: &impl Packages,
    contracts: &impl Contracts,
) -> Result<(), Error<E>> {
    let before = checked_record(committed, policy, packages, contracts)?;
    let after =
        checked_record(proposed, policy, packages, contracts)?.ok_or(Error::RecoveryConflict)?;
    // Preserve the same transition language as prepare(). A checksum alone must
    // not let a stale canonical lifecycle head rewind this namespace on replay.
    let matches = match before {
        None => match after.staged() {
            Some(version) => {
                with_package(version.digest(), policy, packages, contracts, |actual| {
                    Ok(Record::install(actual, after.data_epoch()).as_ref() == Ok(&after))
                })?
            }
            None => false,
        },
        Some(before) => {
            let revision = before.revision();
            let simple = [
                before.activate(revision),
                before.rollback(revision),
                before.remove(revision),
                before.data_migrated(revision, after.data_epoch()),
            ]
            .iter()
            .any(|result| result.as_ref() == Ok(&after));
            if simple {
                true
            } else if let Some(version) = after.staged().or(after.active()) {
                with_package(version.digest(), policy, packages, contracts, |actual| {
                    let staged = before.stage(revision, actual);
                    let replacement = staged
                        .as_ref()
                        .map_err(|error| *error)
                        .and_then(|record| record.activate(record.revision()));
                    Ok(staged.as_ref() == Ok(&after)
                        || replacement.as_ref() == Ok(&after)
                        || before.reinstall(revision, actual).as_ref() == Ok(&after))
                })?
            } else {
                false
            }
        }
    };
    if matches {
        Ok(())
    } else {
        Err(Error::RecoveryConflict)
    }
}
