//! Internal capability-bound one-page allocator. Hardware must zero the returned
//! object before exposing its mapping or capability to userspace.
use crate::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    memory::BootstrapFrames,
    memory_object::MemoryObject,
    scheduler::{JobId, Resource, Scheduler},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Denied,
    Budget,
    Exhausted,
    Capacity,
}
pub struct Domain {
    owner: SpaceId,
    custodian: SpaceId,
    job: JobId,
    identity: usize,
}
pub struct Anonymous {
    pub object: MemoryObject,
    pub capability: Handle,
    pub custody: Handle,
}
impl Domain {
    /// Trusted binding between one protection domain and its existing Job.
    pub fn bind(
        authority: &mut Authority,
        scheduler: &Scheduler,
        owner: SpaceId,
        custodian: SpaceId,
        job: JobId,
    ) -> Result<(Self, Handle), Error> {
        scheduler
            .usage(job, Resource::Frames)
            .map_err(|_| Error::Denied)?;
        let cap = authority
            .create_root(owner, Kind::Job, Rights::CONTROL)
            .map_err(|_| Error::Capacity)?;
        let identity = authority
            .authorize(owner, cap, Kind::Job, Rights::CONTROL)
            .unwrap()
            .identity();
        Ok((
            Self {
                owner,
                custodian,
                job,
                identity,
            },
            cap,
        ))
    }
    pub fn allocate(
        &self,
        authority: &mut Authority,
        scheduler: &mut Scheduler,
        frames: &mut BootstrapFrames,
        caller: SpaceId,
        cap: Handle,
    ) -> Result<Anonymous, Error> {
        if caller != self.owner
            || authority
                .authorize(caller, cap, Kind::Job, Rights::CONTROL)
                .map(|a| a.identity())
                != Ok(self.identity)
        {
            return Err(Error::Denied);
        }
        scheduler
            .charge_frames(self.job, 1)
            .map_err(|_| Error::Budget)?;
        let frame = match frames.allocate() {
            Ok(frame) => frame,
            Err(_) => {
                scheduler.release_frames(self.job, 1).unwrap();
                return Err(Error::Exhausted);
            }
        };
        let (mut object, custody) = match MemoryObject::new(authority, self.custodian, frame) {
            Ok(pair) => pair,
            Err((_, frame)) => {
                frames
                    .reclaim(frame)
                    .expect("unpublished allocation rollback");
                scheduler.release_frames(self.job, 1).unwrap();
                return Err(Error::Capacity);
            }
        };
        let capability = match authority.derive(
            self.custodian,
            custody,
            self.owner,
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::CONTROL,
        ) {
            Ok(cap) => cap,
            Err(_) => {
                let frame = object.destroy(authority, self.custodian, custody).unwrap();
                authority.close(self.custodian, custody).unwrap();
                frames.reclaim(frame).expect("unpublished object rollback");
                scheduler.release_frames(self.job, 1).unwrap();
                return Err(Error::Capacity);
            }
        };
        Ok(Anonymous {
            object,
            capability,
            custody,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::Limits;
    use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
    fn frames(count: u64) -> BootstrapFrames {
        BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: 4096,
                end: 8192 + count * 4096,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        )
    }
    #[test]
    fn allocation_authority_budget_and_physical_failure_preserve_charges() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let custodian = a.create_space().unwrap();
        let mut s = Scheduler::new();
        let job = s.create_job_with_limits(Limits::new(10, 1, 1, 1)).unwrap();
        let (domain, cap) = Domain::bind(&mut a, &s, owner, custodian, job).unwrap();
        let mut f = frames(0);
        assert_eq!(
            domain
                .allocate(&mut a, &mut s, &mut f, custodian, cap)
                .err(),
            Some(Error::Denied)
        );
        let held = f.allocate().unwrap();
        assert_eq!(
            domain.allocate(&mut a, &mut s, &mut f, owner, cap).err(),
            Some(Error::Exhausted)
        );
        assert_eq!(s.usage(job, Resource::Frames), Ok(0));
        f.reclaim(held).unwrap();
        s.charge_frames(job, 1).unwrap();
        assert_eq!(
            domain.allocate(&mut a, &mut s, &mut f, owner, cap).err(),
            Some(Error::Budget)
        );
        assert_eq!(f.remaining_frames(), 1);
        assert_eq!(s.usage(job, Resource::Frames), Ok(1));
        s.release_frames(job, 1).unwrap();
        let mut allocation = domain.allocate(&mut a, &mut s, &mut f, owner, cap).unwrap();
        assert_eq!(s.usage(job, Resource::Frames), Ok(1));
        assert!(
            a.authorize(owner, allocation.capability, Kind::Memory, Rights::REVOKE)
                .is_err()
        );
        a.close_space(owner).unwrap();
        let frame = allocation
            .object
            .destroy(&mut a, custodian, allocation.custody)
            .unwrap();
        f.reclaim(frame).unwrap();
        s.release_frames(job, 1).unwrap();
        assert_eq!(f.remaining_frames(), 1);
        assert_eq!(s.usage(job, Resource::Frames), Ok(0));
    }
    #[test]
    fn receiver_table_failure_rolls_back_after_object_creation() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let custodian = a.create_space().unwrap();
        let mut s = Scheduler::new();
        let job = s.create_job().unwrap();
        let (domain, cap) = Domain::bind(&mut a, &s, owner, custodian, job).unwrap();
        let root = a
            .create_root(owner, Kind::Memory, Rights::READ | Rights::DERIVE)
            .unwrap();
        for _ in 2..crate::capability::MAX_CAPS {
            a.derive(owner, root, owner, Rights::READ).unwrap();
        }
        let mut f = frames(1);
        let before = f.remaining_frames();
        assert_eq!(
            domain.allocate(&mut a, &mut s, &mut f, owner, cap).err(),
            Some(Error::Capacity)
        );
        assert_eq!(f.remaining_frames(), before);
        assert_eq!(s.usage(job, Resource::Frames), Ok(0));
        a.close(owner, root).unwrap();
        assert!(domain.allocate(&mut a, &mut s, &mut f, owner, cap).is_ok());
    }
    #[test]
    fn descriptor_capacity_failure_returns_frame_and_ancestor_charge() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let custodian = a.create_space().unwrap();
        let mut s = Scheduler::new();
        let parent = s.create_job().unwrap();
        let job = s.create_child_job(parent, Limits::UNLIMITED).unwrap();
        let (domain, cap) = Domain::bind(&mut a, &s, owner, custodian, job).unwrap();
        for _ in 1..crate::capability::MAX_OBJECTS {
            let handle = a
                .create_root(custodian, Kind::Memory, Rights::READ)
                .unwrap();
            // Retained object descriptors, rather than local handle slots, are
            // the resource this case must exhaust. Their bounds now differ.
            a.close(custodian, handle).unwrap();
        }
        let mut f = frames(1);
        let before = f.remaining_frames();
        assert_eq!(
            domain.allocate(&mut a, &mut s, &mut f, owner, cap).err(),
            Some(Error::Capacity)
        );
        assert_eq!(f.remaining_frames(), before);
        assert_eq!(s.usage(job, Resource::Frames), Ok(0));
        assert_eq!(s.usage(parent, Resource::Frames), Ok(0));
    }
}
