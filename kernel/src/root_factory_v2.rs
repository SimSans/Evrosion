//! Trusted kernel Root bootstrap factory ONLY. No scalar syscall exposes it.
//! Requires Runtime's ignored create_control_space/slot_capacity overlay.
use crate::{
    capability::{Authority, Error, SpaceId},
    incarnation::Target,
    scheduler::{JobId, ProcessId},
};
/// Immutable domain identity receipt, not a capability or scheduler admission.
/// Keep custody/branches kernel-private through the full Root epoch.
pub struct RootDomains {
    custody: SpaceId,
    branches: SpaceId,
    destination: SpaceId,
}
impl RootDomains {
    /// Selected boot factory after independent typed V5 verification. Authority
    /// must itself have been constructed for the selected workspace envelope.
    /// A default/legacy Authority refuses before any bank is committed.
    #[cfg(feature = "workspace-authority")]
    pub fn allocate_workspace(
        a: &mut Authority,
        _manifest: &crate::root_manifest_v5::CurrentRoot<'_>,
    ) -> Result<Self, Error> {
        let mut staged = a.staged_copy();
        let custody = staged.create_workspace_control_space()?;
        let branches = staged.create_workspace_control_space()?;
        let destination = staged.create_workspace_control_space()?;
        let result = Self {
            custody,
            branches,
            destination,
        };
        *a = staged;
        Ok(result)
    }
    /// Boot-only fresh creation. The actual objects and backing are separately
    /// created/retained by verified resource factories IN this custody domain.
    /// One exclusive Authority borrow spans bank reservation and publication.
    pub fn allocate(a: &mut Authority) -> Result<Self, Error> {
        let mut staged = a.staged_copy();
        let custody = staged.create_control_space()?;
        let branches = staged.create_control_space()?;
        let destination = staged.create_control_space()?;
        let result = Self {
            custody,
            branches,
            destination,
        };
        *a = staged;
        Ok(result)
    }
    pub fn custody(&self) -> SpaceId {
        self.custody
    }
    /// Process/Job must be actual held scheduler identities from the same boot
    /// factory. Custodian.prepare independently validates actual Job/limits and
    /// complete source set. Constructing Target never schedules the process.
    pub fn into_target(self, process: ProcessId, job: JobId) -> (SpaceId, Target) {
        (
            self.custody,
            Target {
                process,
                job,
                branches: self.branches,
                destination: self.destination,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_v2_factory_uses_only_three_explicit_control_banks() {
        let mut a = Authority::new();
        let domains = RootDomains::allocate(&mut a).unwrap();
        assert_eq!(a.slot_capacity(domains.custody()), Ok(64));
        let mut scheduler = crate::scheduler::Scheduler::new();
        let job = scheduler.create_job().unwrap();
        let process = scheduler.create_held_process(job).unwrap();
        let (_, target) = domains.into_target(process, job);
        assert_eq!(a.slot_capacity(target.branches), Ok(64));
        assert_eq!(a.slot_capacity(target.destination), Ok(64));
        let ordinary = a.create_space().unwrap();
        assert_eq!(a.slot_capacity(ordinary), Ok(16));
        a.create_control_space().unwrap();
        assert_eq!(a.create_control_space(), Err(Error::Capacity));
    }
    #[test]
    fn root_v2_factory_failure_cannot_leak_partially_reserved_banks() {
        let mut a = Authority::new();
        a.create_control_space().unwrap();
        a.create_control_space().unwrap();
        let before = a.metadata_usage();
        assert!(matches!(
            RootDomains::allocate(&mut a),
            Err(Error::Capacity)
        ));
        assert_eq!(a.metadata_usage(), before);
        a.create_control_space().unwrap();
        a.create_control_space().unwrap();
        assert_eq!(a.create_control_space(), Err(Error::Capacity));
    }
}
