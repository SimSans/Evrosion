//! Latest owner policy exclusively reborrows State's ONE backend. Uncertain
//! publication retains its exact prepared operation and fences data/remints.
use super::*;
use ev_grant_policy::{self as grants, Expected, FreshReadHandoff, PolicyOwner, Scope};
use ev_picker::{Delivery, ObjectView, ReadDelivery, Requester, UserId, intent::Record};
#[derive(Clone, Copy, Debug)]
pub struct GrantSnapshot {
    pub expected: Option<Expected>,
    pub record: Option<Record>,
}
impl GrantSnapshot {
    pub fn requester_revision(self) -> u64 {
        self.expected.map_or(1, |head| head.revision.max(1))
    }
}
impl<T: Wire, W: Window> State<T, W> {
    fn grant_scope(packages: &impl Sources, owner: UserId) -> Scope {
        Scope {
            user: owner,
            app: packages.app(),
        }
    }
    pub fn grants_fenced(&self) -> bool {
        self.grant_fenced || self.grant_pending.is_some() || self.recovery_required()
    }
    pub fn grant_snapshot(
        &mut self,
        packages: &impl Sources,
        owner: UserId,
        deadline: u64,
    ) -> Result<GrantSnapshot, Error> {
        self.invalidate_health_reads();
        self.usable()?;
        let result = PolicyOwner::with_open(
            self.backend.device(Region::GrantPolicy, true),
            Self::grant_scope(packages, owner),
            deadline,
            |p| {
                Ok(GrantSnapshot {
                    expected: Some(p.expected()?),
                    record: p.record()?,
                })
            },
        );
        match release(result, false) {
            Ok(value) => Ok(value),
            Err(rejected) => {
                if rejected.unformatted {
                    let mut device = self.backend.device(Region::GrantPolicy, false);
                    ev_store::desktop::require_blank(&mut device, deadline)
                        .map_err(|_| self.fail())?;
                    Ok(GrantSnapshot {
                        expected: None,
                        record: None,
                    })
                } else {
                    if let Some(pending) = rejected.pending {
                        self.grant_pending = Some(pending);
                    }
                    Err(self.fail())
                }
            }
        }
    }
    /// Explicit owner allocation of an EMPTY policy namespace grants no READ.
    pub fn grant_initialize(
        &mut self,
        packages: &impl Sources,
        owner: UserId,
        deadline: u64,
    ) -> Result<(), Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if self.grants_fenced()
            || self
                .grant_snapshot(packages, owner, deadline)?
                .expected
                .is_some()
        {
            return Err(Error::State);
        }
        let scope = Self::grant_scope(packages, owner);
        let context = packages.grant_format_manifest(owner.bytes());
        let result = PolicyOwner::format_empty(
            self.backend.device(Region::GrantPolicy, true),
            scope,
            context,
            deadline,
        )
        .map(|policy| {
            let (_device, _scope, pending) = policy.into_parts();
            pending
        })
        .map_err(|rejected| rejected.pending);
        match result {
            Ok(pending) => {
                if pending.is_some() {
                    return Err(self.fail());
                }
                // Reopen through the same sole backend and read the actual
                // durable empty policy before acknowledging initialization.
                let actual = self.grant_snapshot(packages, owner, deadline)?;
                if actual.record.is_some() || actual.expected.is_none_or(|e| e.revision != 0) {
                    return Err(self.fail());
                }
                Ok(())
            }
            Err(pending) => {
                self.grant_pending = pending;
                Err(self.fail())
            }
        }
    }
    /// Called INSIDE Picker's validated ReadDelivery handoff, before actual44.
    pub fn grant_remember(
        &mut self,
        packages: &impl Sources,
        owner: UserId,
        expected: Expected,
        delivery: &ReadDelivery<'_>,
        deadline: u64,
    ) -> Result<grants::Published, Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if self.grants_fenced() || !Self::grant_package(packages, delivery.selection().requester())
        {
            return Err(Error::State);
        }
        let mut entered = false;
        let result = PolicyOwner::with_open(
            self.backend.device(Region::GrantPolicy, true),
            Self::grant_scope(packages, owner),
            deadline,
            |p| {
                entered = true;
                let intent = p.prepare_remember(expected, delivery)?;
                p.publish(intent, deadline)
            },
        );
        let result = release(result, entered);
        self.finish_grant(result)
    }
    pub fn grant_prepare_revoke(
        &mut self,
        packages: &impl Sources,
        owner: UserId,
        expected: Expected,
        deadline: u64,
    ) -> Result<(), Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if self.grants_fenced() {
            return Err(Error::State);
        }
        let mut entered = false;
        let result = PolicyOwner::with_open(
            self.backend.device(Region::GrantPolicy, true),
            Self::grant_scope(packages, owner),
            deadline,
            |p| {
                entered = true;
                p.prepare_revoke(expected)
            },
        );
        let result = release(result, entered);
        let intent = self.finish_grant(result)?;
        self.grant_pending = Some(intent);
        self.grant_fenced = true;
        self.fence();
        Ok(())
    }
    /// Caller has inhibited, settled accepted work, stopped/reaped the App and
    /// retired its actual capability branches before this durable tombstone.
    pub fn grant_commit_revoke(
        &mut self,
        packages: &impl Sources,
        owner: UserId,
        deadline: u64,
    ) -> Result<grants::Published, Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if !self.grant_fenced || self.grant_pending.is_none() {
            return Err(Error::State);
        }
        let pending = &mut self.grant_pending;
        let mut entered = false;
        let result = PolicyOwner::with_open(
            self.backend.device(Region::GrantPolicy, true),
            Self::grant_scope(packages, owner),
            deadline,
            |p| {
                entered = true;
                p.publish(pending.take().expect("retained grant tombstone"), deadline)
            },
        );
        let result = release(result, entered);
        let published = self.finish_grant(result)?;
        self.grant_fenced = false;
        Ok(published)
    }
    pub fn grant_remint<H: FreshReadHandoff>(
        &mut self,
        packages: &impl Sources,
        owner: UserId,
        current: Requester,
        object: ObjectView,
        deadline: u64,
        handoff: &mut H,
    ) -> Result<Delivery<H::Ticket, H::Error>, Error> {
        self.invalidate_health_reads();
        self.usable()?;
        if self.grants_fenced() || !Self::grant_package(packages, current) {
            return Err(Error::State);
        }
        let mut entered = false;
        let result = PolicyOwner::with_open(
            self.backend.device(Region::GrantPolicy, true),
            Self::grant_scope(packages, owner),
            deadline,
            |p| {
                entered = true;
                p.remint(current, object, deadline, handoff)
            },
        );
        let result = release(result, entered);
        self.finish_grant(result)
    }
    fn grant_package(packages: &impl Sources, current: Requester) -> bool {
        current.app.app == packages.app()
            && packages
                .source(current.app.package.bytes())
                .is_some_and(|source| packages.checked_source(source).is_ok())
    }
    fn finish_grant<V>(&mut self, result: Result<V, GrantFailure>) -> Result<V, Error> {
        match result {
            Ok(value) => Ok(value),
            Err(rejected) => {
                if let Some(intent) = rejected.pending {
                    self.grant_pending = Some(intent);
                }
                if rejected.uncertain {
                    self.grant_fenced = true;
                    Err(self.fail())
                } else {
                    Err(Error::State)
                }
            }
        }
    }
}
struct GrantFailure {
    pending: Option<grants::Prepared>,
    uncertain: bool,
    unformatted: bool,
}
// The retained failure owns the exact uncertain Prepared intent. Boxing or
// discarding that owner would weaken bounded no-heap recovery semantics.
#[allow(clippy::result_large_err)]
fn release<D: ev_store::SectorIo, V>(
    result: Result<(D, V), grants::Rejected<D>>,
    entered: bool,
) -> Result<V, GrantFailure> {
    result.map(|(_device, value)| value).map_err(|rejected| {
        let unformatted = matches!(
            rejected.error,
            grants::Error::Store(ev_store::Error::Unformatted)
        );
        let uncertain = !entered
            || matches!(
                rejected.error,
                grants::Error::Store(_)
                    | grants::Error::NeedsRecovery
                    | grants::Error::Readback
                    | grants::Error::Corrupt
                    | grants::Error::RecoveryConflict
            );
        GrantFailure {
            pending: rejected.pending,
            uncertain,
            unformatted,
        }
    })
}
