//! One-page Internal Memory Object with capability-checked bounded map leases.
//! Use one Authority instance and serialized hardware owner for its lifetime.
//! A lease owns a mapping claim, not the backing frame. Hardware must remove the
//! mapping and quiesce every user before returning the lease. Frame bytes are
//! zeroed by the hardware boundary before publishing a mapping capability.
use crate::{
    capability::{Authority, Error as CapError, Handle, Kind, Rights, SpaceId},
    memory::PhysicalFrame,
};
pub const MAX_MAPPINGS: usize = 8;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Authority(CapError),
    WrongObject,
    Capacity,
    Busy,
    InvalidLease,
    Overflow,
}
impl From<CapError> for Error {
    fn from(e: CapError) -> Self {
        Self::Authority(e)
    }
}
#[derive(Debug)]
pub struct MappingLease {
    object: usize,
    frame: u64,
    token: u64,
    writable: bool,
    owner: SpaceId,
    capability: Handle,
}
impl MappingLease {
    pub fn physical(&self) -> u64 {
        self.frame
    }
    pub fn writable(&self) -> bool {
        self.writable
    }
}
pub struct MemoryObject {
    identity: usize,
    frame: Option<PhysicalFrame>,
    leases: [Option<u64>; MAX_MAPPINGS],
    sequence: u64,
}
impl MemoryObject {
    /// Trusted bootstrap factory. On capacity failure the frame stays owned by
    /// the caller. Runtime creation still needs an allocator capability/budget.
    pub fn new(
        authority: &mut Authority,
        owner: SpaceId,
        frame: PhysicalFrame,
    ) -> Result<(Self, Handle), (CapError, PhysicalFrame)> {
        let cap = match authority.create_root(
            owner,
            Kind::Memory,
            Rights::READ
                | Rights::WRITE
                | Rights::MAP
                | Rights::DERIVE
                | Rights::TRANSFER
                | Rights::REVOKE
                | Rights::CONTROL,
        ) {
            Ok(cap) => cap,
            Err(e) => return Err((e, frame)),
        };
        let identity = authority
            .authorize(owner, cap, Kind::Memory, Rights::CONTROL)
            .expect("new object authority")
            .identity();
        Ok((
            Self {
                identity,
                frame: Some(frame),
                leases: [None; MAX_MAPPINGS],
                sequence: 0,
            },
            cap,
        ))
    }
    fn authorized(
        &self,
        authority: &Authority,
        owner: SpaceId,
        cap: Handle,
        rights: Rights,
    ) -> Result<(), Error> {
        if authority
            .authorize(owner, cap, Kind::Memory, rights)?
            .identity()
            != self.identity
        {
            return Err(Error::WrongObject);
        }
        Ok(())
    }
    pub fn map(
        &mut self,
        authority: &Authority,
        owner: SpaceId,
        cap: Handle,
        writable: bool,
    ) -> Result<MappingLease, Error> {
        let rights = Rights::MAP | Rights::READ;
        self.authorized(
            authority,
            owner,
            cap,
            if writable {
                rights | Rights::WRITE
            } else {
                rights
            },
        )?;
        let slot = self
            .leases
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let token = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        self.leases[slot] = Some(token);
        self.sequence = token;
        Ok(MappingLease {
            object: self.identity,
            frame: self.frame.as_ref().expect("live backing").start(),
            token,
            writable,
            owner,
            capability: cap,
        })
    }
    pub fn owns_mapping(&self, lease: &MappingLease) -> bool {
        lease.object == self.identity
    }
    pub fn validate_mapping(
        &self,
        authority: &Authority,
        lease: &MappingLease,
    ) -> Result<(), Error> {
        if lease.object != self.identity
            || Some(lease.frame) != self.frame.as_ref().map(PhysicalFrame::start)
        {
            return Err(Error::WrongObject);
        }
        if !self.leases.contains(&Some(lease.token)) {
            return Err(Error::InvalidLease);
        }
        let rights = Rights::READ | Rights::MAP;
        self.authorized(
            authority,
            lease.owner,
            lease.capability,
            if lease.writable {
                rights | Rights::WRITE
            } else {
                rights
            },
        )
    }
    pub fn unmap(&mut self, lease: MappingLease) -> Result<(), (Error, MappingLease)> {
        if lease.object != self.identity
            || Some(lease.frame) != self.frame.as_ref().map(PhysicalFrame::start)
        {
            return Err((Error::WrongObject, lease));
        }
        let Some(slot) = self.leases.iter().position(|s| *s == Some(lease.token)) else {
            return Err((Error::InvalidLease, lease));
        };
        self.leases[slot] = None;
        Ok(())
    }
    /// No backing frame can be released while any mapping claim is live.
    /// Descriptor invalidation precedes ownership return. Failure leaves Self intact.
    pub fn destroy(
        &mut self,
        authority: &mut Authority,
        owner: SpaceId,
        cap: Handle,
    ) -> Result<PhysicalFrame, Error> {
        self.authorized(authority, owner, cap, Rights::CONTROL)?;
        if self.leases.iter().any(Option::is_some) {
            return Err(Error::Busy);
        }
        authority.destroy(owner, cap)?;
        Ok(self.frame.take().expect("live backing"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Error as CapError;
    use crate::memory::BootstrapFrames;
    use ev_boot_contract::{MemoryKind, MemoryMap, MemoryRegion};
    fn frames() -> BootstrapFrames {
        BootstrapFrames::new(
            MemoryMap::validate([MemoryRegion {
                start: 4096,
                end: 32768,
                kind: MemoryKind::Usable,
            }])
            .unwrap(),
        )
    }
    #[test]
    fn live_lease_validation_observes_revocation_and_domain_closure() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let peer = a.create_space().unwrap();
        let mut f = frames();
        let (mut object, cap) = MemoryObject::new(&mut a, owner, f.allocate().unwrap()).unwrap();
        let branch = a
            .derive(
                owner,
                cap,
                peer,
                Rights::READ | Rights::MAP | Rights::REVOKE,
            )
            .unwrap();
        let lease = object.map(&a, peer, branch, false).unwrap();
        assert_eq!(object.validate_mapping(&a, &lease), Ok(()));
        a.revoke(peer, branch).unwrap();
        assert_eq!(
            object.validate_mapping(&a, &lease),
            Err(Error::Authority(CapError::Revoked))
        );
        assert_eq!(object.destroy(&mut a, owner, cap).err(), Some(Error::Busy));
        object.unmap(lease).unwrap();
        let branch = a
            .derive(owner, cap, peer, Rights::READ | Rights::MAP)
            .unwrap();
        let lease = object.map(&a, peer, branch, false).unwrap();
        a.close_space(peer).unwrap();
        assert_eq!(
            object.validate_mapping(&a, &lease),
            Err(Error::Authority(CapError::InvalidSpace))
        );
        object.unmap(lease).unwrap();
        assert!(object.destroy(&mut a, owner, cap).is_ok());
    }
    #[test]
    fn af009_mapping_requires_right_object_map_and_access_rights() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let peer = a.create_space().unwrap();
        let mut f = frames();
        let (mut object, cap) = MemoryObject::new(&mut a, owner, f.allocate().unwrap()).unwrap();
        assert_eq!(
            object.map(&a, peer, cap, false).err(),
            Some(Error::Authority(CapError::InvalidHandle))
        );
        let read = a.derive(owner, cap, peer, Rights::READ).unwrap();
        assert_eq!(
            object.map(&a, peer, read, false).err(),
            Some(Error::Authority(CapError::Denied))
        );
        let mapped = a
            .derive(owner, cap, peer, Rights::READ | Rights::MAP)
            .unwrap();
        assert_eq!(
            object.map(&a, peer, mapped, true).err(),
            Some(Error::Authority(CapError::Denied))
        );
        let lease = object.map(&a, peer, mapped, false).unwrap();
        assert!(!lease.writable());
        let unrelated = a
            .create_root(peer, Kind::Memory, Rights::READ | Rights::MAP)
            .unwrap();
        assert_eq!(
            object.map(&a, peer, unrelated, false).err(),
            Some(Error::WrongObject)
        );
        object.unmap(lease).unwrap();
        a.revoke(owner, cap).unwrap();
        assert_eq!(
            object.map(&a, peer, mapped, false).err(),
            Some(Error::Authority(CapError::Revoked))
        );
    }
    #[test]
    fn backing_cannot_be_destroyed_until_every_mapping_returns() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let mut f = frames();
        let (mut object, cap) = MemoryObject::new(&mut a, owner, f.allocate().unwrap()).unwrap();
        let read = object.map(&a, owner, cap, false).unwrap();
        let write = object.map(&a, owner, cap, true).unwrap();
        assert_eq!(read.physical(), write.physical());
        let error = object.destroy(&mut a, owner, cap).err().unwrap();
        assert_eq!(error, Error::Busy);
        object.unmap(read).unwrap();
        let error = object.destroy(&mut a, owner, cap).err().unwrap();
        assert_eq!(error, Error::Busy);
        object.unmap(write).unwrap();
        let frame = object
            .destroy(&mut a, owner, cap)
            .unwrap_or_else(|_| panic!("quiescent object"));
        assert_eq!(
            a.authorize(owner, cap, Kind::Memory, Rights::READ).err(),
            Some(CapError::DeadObject)
        );
        f.reclaim(frame).unwrap();
        assert_eq!(f.remaining_frames(), 7);
    }
    #[test]
    fn map_capacity_sequence_and_foreign_leases_fail_without_losing_claims() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let mut f = frames();
        let (mut object, cap) = MemoryObject::new(&mut a, owner, f.allocate().unwrap()).unwrap();
        let (mut other, _) = MemoryObject::new(&mut a, owner, f.allocate().unwrap()).unwrap();
        let leases: [_; MAX_MAPPINGS] =
            core::array::from_fn(|_| object.map(&a, owner, cap, false).unwrap());
        assert_eq!(
            object.map(&a, owner, cap, false).err(),
            Some(Error::Capacity)
        );
        for lease in leases {
            let (error, lease) = other.unmap(lease).unwrap_err();
            assert_eq!(error, Error::WrongObject);
            object.unmap(lease).unwrap();
        }
        object.sequence = u64::MAX;
        assert_eq!(
            object.map(&a, owner, cap, false).err(),
            Some(Error::Overflow)
        );
        assert!(object.leases.iter().all(Option::is_none));
    }

    #[test]
    fn two_process_shared_buffer_retains_parent_charge_until_both_leases_return() {
        // Portable ownership/accounting model only: no hardware PTE, ATA command
        // or physical zeroing/durability acceptance is inferred from this test.
        use crate::scheduler::{Limits, Resource, Scheduler};
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let driver = a.create_space().unwrap();
        let client = a.create_space().unwrap();
        let mut scheduler = Scheduler::new();
        let parent = scheduler
            .create_job_with_limits(Limits::new(1024, 1, 2, 2))
            .unwrap();
        scheduler.charge_frames(parent, 1).unwrap();
        let mut allocator = frames();
        let before = allocator.remaining_frames();
        let (mut object, root) =
            MemoryObject::new(&mut a, owner, allocator.allocate().unwrap()).unwrap();
        let rights = Rights::READ | Rights::WRITE | Rights::MAP;
        let driver_cap = a.derive(owner, root, driver, rights).unwrap();
        let client_cap = a.derive(owner, root, client, rights).unwrap();
        let driver_lease = object.map(&a, driver, driver_cap, true).unwrap();
        let client_lease = object.map(&a, client, client_cap, true).unwrap();
        assert_eq!(driver_lease.physical(), client_lease.physical());
        assert_eq!(scheduler.usage(parent, Resource::Frames), Ok(1));
        assert_eq!(object.destroy(&mut a, owner, root), Err(Error::Busy));
        // Retiring a process closes its domain, invalidating its lease without
        // authorizing backing reuse or invalidating the independent live peer.
        a.close_space(driver).unwrap();
        assert!(object.validate_mapping(&a, &driver_lease).is_err());
        assert_eq!(object.validate_mapping(&a, &client_lease), Ok(()));
        object.unmap(driver_lease).unwrap();
        assert_eq!(object.destroy(&mut a, owner, root), Err(Error::Busy));
        assert_eq!(scheduler.usage(parent, Resource::Frames), Ok(1));
        object.unmap(client_lease).unwrap();
        let frame = object.destroy(&mut a, owner, root).unwrap();
        assert!(allocator.owns(&frame));
        allocator.reclaim(frame).unwrap();
        scheduler.release_frames(parent, 1).unwrap();
        assert_eq!(allocator.remaining_frames(), before);
        assert_eq!(scheduler.usage(parent, Resource::Frames), Ok(0));
    }
}
