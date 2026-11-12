//! Bounded capability-controlled logical mutexes for userspace threads.
//! A single serialized kernel dispatcher mutates these tables. No Rust/kernel
//! lock survives return to userspace; only the exact logical owner/lease does.
use crate::{
    capability::{self, Authority, Handle, Kind, MAX_OBJECTS, Rights, SpaceId},
    rpc::{self, LockClass, Rpc},
    scheduler::{self, Scheduler, ThreadId},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority(capability::Error),
    Scheduler(scheduler::Error),
    Rpc(rpc::Error),
    UnknownObject,
    AlreadyRegistered,
    InvalidClass,
    Busy,
    AlreadyOwned,
    StaleLease,
    NotOwner,
    Identity,
    SequenceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rpc::{MessageShape, Policy},
        scheduler::{JobId, ProcessId},
        time::Deadline,
    };
    use core::num::NonZeroU64;
    // Host-only logical state model. No user hardware executes and no protected
    // application data is repaired by any of these ownership/poison assertions.
    struct Fixture {
        a: Authority,
        s: Scheduler,
        rpc: Rpc,
        mutexes: Registry,
        domains: [SpaceId; 2],
        jobs: [JobId; 2],
        processes: [ProcessId; 2],
        threads: [ThreadId; 2],
        caps: [Handle; 2],
        endpoint: Handle,
        current: Option<ThreadId>,
    }
    fn fixture() -> Fixture {
        let mut a = Authority::new();
        let domains = [a.create_space().unwrap(), a.create_space().unwrap()];
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL;
        let cap = a.create_root(domains[0], Kind::Mutex, common).unwrap();
        let alias = a
            .derive(domains[0], cap, domains[1], Rights::CONTROL)
            .unwrap();
        let receive = a
            .create_root(
                domains[1],
                Kind::Endpoint,
                common | Rights::SEND | Rights::RECEIVE,
            )
            .unwrap();
        let endpoint = a
            .derive(domains[1], receive, domains[0], Rights::SEND)
            .unwrap();
        let mut s = Scheduler::new();
        let jobs = [s.create_job().unwrap(), s.create_job().unwrap()];
        let processes = jobs.map(|job| s.create_process(job).unwrap());
        let threads = processes.map(|process| s.create_thread(process).unwrap());
        let mut rpc = Rpc::new(NonZeroU64::new(80).unwrap());
        for i in 0..2 {
            rpc.register_thread(&a, &s, threads[i], jobs[i], domains[i], None)
                .unwrap();
        }
        rpc.bind_endpoint(
            &a,
            domains[1],
            receive,
            threads[1],
            Policy::new(8, 0).unwrap(),
        )
        .unwrap();
        let mut mutexes = Registry::new();
        mutexes
            .register(
                &a,
                domains[0],
                cap,
                LockClass {
                    rank: 10,
                    no_ipc_wait: true,
                },
            )
            .unwrap();
        Fixture {
            a,
            s,
            rpc,
            mutexes,
            domains,
            jobs,
            processes,
            threads,
            caps: [cap, alias],
            endpoint,
            current: None,
        }
    }
    impl Fixture {
        fn run(&mut self, index: usize) {
            if self.current.take().is_some() {
                self.s.yield_cpu(0).unwrap();
            }
            for _ in 0..scheduler::MAX_THREADS {
                let actual = self.s.dispatch(0).unwrap().unwrap().thread;
                if actual == self.threads[index] {
                    self.current = Some(actual);
                    return;
                }
                self.s.yield_cpu(0).unwrap();
            }
            panic!("model thread not dispatchable");
        }
        fn acquire(&mut self, index: usize) -> Result<Acquired, Error> {
            self.mutexes
                .acquire(&self.a, &self.s, &mut self.rpc, 0, self.caps[index])
        }
        fn call(&mut self) -> Result<crate::rpc::CallId, rpc::Error> {
            self.rpc.begin(
                &self.a,
                self.threads[0],
                self.endpoint,
                Deadline::after(0, 10).unwrap(),
                MessageShape {
                    bytes: 8,
                    capabilities: 0,
                },
                1,
            )
        }
    }
    #[test]
    fn real_ownership_survives_user_yield_excludes_peer_and_blocks_ipc() {
        let mut f = fixture();
        f.run(0);
        let acquired = f.acquire(0).unwrap();
        assert!(!acquired.abandoned);
        assert_eq!(f.call(), Err(rpc::Error::DangerousLock));
        assert_eq!(f.rpc.outstanding(), 0);
        f.run(1);
        assert_eq!(f.acquire(1), Err(Error::Busy));
        assert_eq!(
            f.mutexes.release(&f.s, &mut f.rpc, 0, acquired.lease),
            Err(Error::NotOwner)
        );
        assert_eq!(f.mutexes.metadata_usage(), (1, 1, 0));
        f.run(0);
        assert_eq!(f.acquire(0), Err(Error::AlreadyOwned));
        f.mutexes
            .release(&f.s, &mut f.rpc, 0, acquired.lease)
            .unwrap();
        assert_eq!(
            f.mutexes.release(&f.s, &mut f.rpc, 0, acquired.lease),
            Err(Error::StaleLease)
        );
        assert!(f.call().is_ok());
    }
    #[test]
    fn wrong_kind_forged_weak_unregistered_and_nonrunner_inputs_do_not_commit() {
        let mut f = fixture();
        assert_eq!(
            f.acquire(0),
            Err(Error::Scheduler(scheduler::Error::CpuIdle))
        );
        f.run(0);
        let memory =
            f.a.create_root(f.domains[0], Kind::Memory, Rights::CONTROL)
                .unwrap();
        let weak =
            f.a.derive(f.domains[0], f.caps[0], f.domains[0], Rights::DERIVE)
                .unwrap();
        let unknown =
            f.a.create_root(f.domains[0], Kind::Mutex, Rights::CONTROL)
                .unwrap();
        for (cap, error) in [
            (memory, Error::Authority(capability::Error::WrongKind)),
            (weak, Error::Authority(capability::Error::Denied)),
            (
                Handle(u64::MAX),
                Error::Authority(capability::Error::InvalidHandle),
            ),
            (unknown, Error::UnknownObject),
        ] {
            assert_eq!(
                f.mutexes.acquire(&f.a, &f.s, &mut f.rpc, 0, cap),
                Err(error)
            );
            assert_eq!(
                (f.mutexes.metadata_usage(), f.mutexes.sequence),
                ((1, 0, 0), 0)
            );
        }
        assert_eq!(
            f.mutexes
                .acquire(&f.a, &f.s, &mut f.rpc, scheduler::MAX_CPUS, f.caps[0]),
            Err(Error::Scheduler(scheduler::Error::InvalidCpu))
        );
        assert_eq!(f.acquire(0).unwrap().lease.scalar(), 1);
    }
    #[test]
    fn transfer_or_revocation_cannot_strand_live_owner_lease() {
        for revoke in [false, true] {
            let mut f = fixture();
            f.run(0);
            let acquired = f.acquire(0).unwrap();
            if revoke {
                f.a.revoke(f.domains[0], f.caps[0]).unwrap();
            } else {
                f.a.transfer(f.domains[0], f.caps[0], f.domains[1]).unwrap();
            }
            assert!(f.acquire(0).is_err());
            assert_eq!(f.call(), Err(rpc::Error::DangerousLock));
            f.mutexes
                .release(&f.s, &mut f.rpc, 0, acquired.lease)
                .unwrap();
            assert_eq!(f.mutexes.metadata_usage(), (1, 0, 0));
            assert!(f.call().is_ok());
        }
    }
    #[test]
    fn lock_class_is_immutable_and_lifo_failure_keeps_both_owners() {
        let mut f = fixture();
        f.run(0);
        assert_eq!(
            f.mutexes.register(
                &f.a,
                f.domains[0],
                f.caps[0],
                LockClass {
                    rank: 99,
                    no_ipc_wait: false
                }
            ),
            Err(Error::AlreadyRegistered)
        );
        let high =
            f.a.create_root(f.domains[0], Kind::Mutex, Rights::CONTROL)
                .unwrap();
        f.mutexes
            .register(
                &f.a,
                f.domains[0],
                high,
                LockClass {
                    rank: 20,
                    no_ipc_wait: false,
                },
            )
            .unwrap();
        let low_lease = f.acquire(0).unwrap().lease;
        let high_lease = f
            .mutexes
            .acquire(&f.a, &f.s, &mut f.rpc, 0, high)
            .unwrap()
            .lease;
        assert_eq!(
            f.mutexes.release(&f.s, &mut f.rpc, 0, low_lease),
            Err(Error::Rpc(rpc::Error::LockOrder))
        );
        assert_eq!(f.mutexes.metadata_usage(), (2, 2, 0));
        f.mutexes.release(&f.s, &mut f.rpc, 0, high_lease).unwrap();
        f.mutexes.release(&f.s, &mut f.rpc, 0, low_lease).unwrap();
        let high_lease = f
            .mutexes
            .acquire(&f.a, &f.s, &mut f.rpc, 0, high)
            .unwrap()
            .lease;
        let serial = f.mutexes.sequence;
        assert_eq!(f.acquire(0), Err(Error::Rpc(rpc::Error::LockOrder)));
        assert_eq!(f.mutexes.sequence, serial);
        f.mutexes.release(&f.s, &mut f.rpc, 0, high_lease).unwrap();
        assert_eq!(f.acquire(0).unwrap().lease.scalar(), serial + 1);
    }
    #[test]
    fn death_requires_verified_rpc_retirement_and_poison_survives_reacquire() {
        let mut f = fixture();
        f.run(0);
        let old = f.acquire(0).unwrap();
        assert_eq!(
            f.mutexes.owner_died(&f.s, &f.rpc, f.threads[0]),
            Err(Error::Rpc(rpc::Error::PeerStillLive))
        );
        f.s.exit(0).unwrap();
        f.current = None;
        f.s.terminate_process(f.processes[0]).unwrap();
        assert_eq!(
            f.mutexes.owner_died(&f.s, &f.rpc, f.threads[0]),
            Err(Error::Rpc(rpc::Error::PeerStillLive))
        );
        assert_eq!(f.mutexes.metadata_usage(), (1, 1, 0));
        f.rpc.peer_died(&f.s, f.threads[0], 1).unwrap();
        assert_eq!(f.mutexes.owner_died(&f.s, &f.rpc, f.threads[0]), Ok(1));
        f.run(1);
        let fresh = f.acquire(1).unwrap();
        assert!(fresh.abandoned);
        assert!(fresh.lease.scalar() > old.lease.scalar());
        assert_eq!(
            f.mutexes.release(&f.s, &mut f.rpc, 0, old.lease),
            Err(Error::StaleLease)
        );
        f.mutexes.release(&f.s, &mut f.rpc, 0, fresh.lease).unwrap();
        assert!(f.acquire(1).unwrap().abandoned);
    }
    #[test]
    fn stale_thread_and_lease_cannot_release_replacement_after_scheduler_reuse() {
        let mut f = fixture();
        f.run(0);
        let old = f.acquire(0).unwrap();
        let old_thread = f.threads[0];
        f.s.exit(0).unwrap();
        f.current = None;
        f.s.terminate_process(f.processes[0]).unwrap();
        f.rpc.peer_died(&f.s, old_thread, 1).unwrap();
        f.mutexes.owner_died(&f.s, &f.rpc, old_thread).unwrap();
        f.rpc.forget_thread(&f.s, old_thread).unwrap();
        f.s.reclaim_process(f.processes[0]).unwrap();
        let process = f.s.create_process(f.jobs[0]).unwrap();
        let thread = f.s.create_thread(process).unwrap();
        assert_ne!(thread, old_thread);
        f.threads[0] = thread;
        f.rpc
            .register_thread(&f.a, &f.s, thread, f.jobs[0], f.domains[0], None)
            .unwrap();
        f.run(0);
        let fresh = f.acquire(0).unwrap();
        assert!(fresh.abandoned);
        assert!(f.mutexes.owner_died(&f.s, &f.rpc, old_thread).is_err());
        assert_eq!(
            f.mutexes.release(&f.s, &mut f.rpc, 0, old.lease),
            Err(Error::StaleLease)
        );
        assert_eq!(f.mutexes.metadata_usage(), (1, 1, 1));
        f.mutexes.release(&f.s, &mut f.rpc, 0, fresh.lease).unwrap();
    }
    #[test]
    fn sequence_exhaustion_is_atomic_and_does_not_prevent_existing_release() {
        let mut f = fixture();
        f.run(0);
        let current = f.acquire(0).unwrap();
        f.mutexes.sequence = u64::MAX;
        f.mutexes
            .release(&f.s, &mut f.rpc, 0, current.lease)
            .unwrap();
        assert_eq!(f.acquire(0), Err(Error::SequenceExhausted));
        assert_eq!(f.mutexes.metadata_usage(), (1, 0, 0));
        assert!(f.call().is_ok());
    }
    #[test]
    fn retirement_pins_are_atomic_and_object_reuse_preserves_serial_history() {
        let mut f = fixture();
        f.run(0);
        let old = f.acquire(0).unwrap();
        assert_eq!(
            f.mutexes.retire(&mut f.a, f.domains[0], f.caps[0]),
            Err(Error::Busy)
        );
        f.mutexes.release(&f.s, &mut f.rpc, 0, old.lease).unwrap();
        assert_eq!(
            f.mutexes.retire(&mut f.a, f.domains[0], f.caps[0]),
            Err(Error::Authority(capability::Error::ObjectBusy))
        );
        assert!(
            f.a.authorize(f.domains[0], f.caps[0], Kind::Mutex, Rights::CONTROL)
                .is_ok()
        );
        let object =
            f.a.authorize(f.domains[0], f.caps[0], Kind::Mutex, Rights::CONTROL)
                .unwrap()
                .identity();
        f.a.close(f.domains[1], f.caps[1]).unwrap();
        f.mutexes.retire(&mut f.a, f.domains[0], f.caps[0]).unwrap();
        let next =
            f.a.create_root(f.domains[0], Kind::Mutex, Rights::CONTROL)
                .unwrap();
        assert_ne!(
            f.a.authorize(f.domains[0], next, Kind::Mutex, Rights::CONTROL)
                .unwrap()
                .identity(),
            object
        );
        f.mutexes
            .register(
                &f.a,
                f.domains[0],
                next,
                LockClass {
                    rank: 10,
                    no_ipc_wait: true,
                },
            )
            .unwrap();
        let lease = f
            .mutexes
            .acquire(&f.a, &f.s, &mut f.rpc, 0, next)
            .unwrap()
            .lease;
        assert!(lease.scalar() > old.lease.scalar());
        assert_eq!(
            f.mutexes.release(&f.s, &mut f.rpc, 0, old.lease),
            Err(Error::StaleLease)
        );
        f.mutexes.release(&f.s, &mut f.rpc, 0, lease).unwrap();
    }
    #[test]
    fn late_rpc_lock_capacity_failure_preserves_mutex_owner_and_serial() {
        let mut f = fixture();
        f.run(0);
        let mut held = [None; rpc::MAX_LOCKS];
        for (i, slot) in held.iter_mut().enumerate() {
            let cap = if i == 0 {
                f.caps[0]
            } else {
                let cap =
                    f.a.create_root(f.domains[0], Kind::Mutex, Rights::CONTROL)
                        .unwrap();
                f.mutexes
                    .register(
                        &f.a,
                        f.domains[0],
                        cap,
                        LockClass {
                            rank: (i as u16 + 1) * 10,
                            no_ipc_wait: false,
                        },
                    )
                    .unwrap();
                cap
            };
            *slot = Some(
                f.mutexes
                    .acquire(&f.a, &f.s, &mut f.rpc, 0, cap)
                    .unwrap()
                    .lease,
            );
        }
        let overflow =
            f.a.create_root(f.domains[0], Kind::Mutex, Rights::CONTROL)
                .unwrap();
        f.mutexes
            .register(
                &f.a,
                f.domains[0],
                overflow,
                LockClass {
                    rank: (rpc::MAX_LOCKS as u16 + 1) * 10,
                    no_ipc_wait: false,
                },
            )
            .unwrap();
        let serial = f.mutexes.sequence;
        assert_eq!(
            f.mutexes.acquire(&f.a, &f.s, &mut f.rpc, 0, overflow),
            Err(Error::Rpc(rpc::Error::Overloaded))
        );
        assert_eq!(f.mutexes.sequence, serial);
        assert_eq!(
            f.mutexes.metadata_usage(),
            (rpc::MAX_LOCKS + 1, rpc::MAX_LOCKS, 0)
        );
        for lease in held.into_iter().rev().flatten() {
            f.mutexes.release(&f.s, &mut f.rpc, 0, lease).unwrap();
        }
        assert_eq!(
            f.mutexes
                .acquire(&f.a, &f.s, &mut f.rpc, 0, overflow)
                .unwrap()
                .lease
                .scalar(),
            serial + 1
        );
    }
}
impl From<capability::Error> for Error {
    fn from(e: capability::Error) -> Self {
        Self::Authority(e)
    }
}
impl From<scheduler::Error> for Error {
    fn from(e: scheduler::Error) -> Self {
        Self::Scheduler(e)
    }
}
impl From<rpc::Error> for Error {
    fn from(e: rpc::Error) -> Self {
        Self::Rpc(e)
    }
}

/// Untrusted scalar input, not a bearer capability. Only its exact live owning
/// scheduler thread may release it. Copies/replays cannot create another owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease(u64);
impl Lease {
    pub const fn from_scalar(value: u64) -> Self {
        Self(value)
    }
    pub const fn scalar(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acquired {
    pub lease: Lease,
    /// A previous owner died. Ownership is granted, but protected userspace data
    /// may be inconsistent; this never certifies data repair or recovery.
    pub abandoned: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    thread: ThreadId,
    object: usize,
    lease: Lease,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mutex {
    object: usize,
    class: LockClass,
    owner: Option<Owner>,
    abandoned: bool,
}

pub struct Registry {
    entries: [Option<Mutex>; MAX_OBJECTS],
    sequence: u64,
}
impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
impl Registry {
    /// Once per retained synchronization-object lifetime, never a userspace
    /// restart/serial reset. Retirement preserves the monotonic lease sequence.
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_OBJECTS],
            sequence: 0,
        }
    }
    pub fn metadata_usage(&self) -> (usize, usize, usize) {
        (
            self.entries.iter().flatten().count(),
            self.entries
                .iter()
                .flatten()
                .filter(|m| m.owner.is_some())
                .count(),
            self.entries
                .iter()
                .flatten()
                .filter(|m| m.abandoned)
                .count(),
        )
    }
    fn index(object: usize) -> Result<usize, Error> {
        let index = object & 255;
        if index >= MAX_OBJECTS {
            Err(Error::UnknownObject)
        } else {
            Ok(index)
        }
    }
    fn object(&self, a: &Authority, space: SpaceId, cap: Handle) -> Result<(usize, Mutex), Error> {
        let object = a
            .authorize(space, cap, Kind::Mutex, Rights::CONTROL)?
            .identity();
        let slot = Self::index(object)?;
        let mutex = self.entries[slot]
            .filter(|m| m.object == object)
            .ok_or(Error::UnknownObject)?;
        Ok((slot, mutex))
    }
    /// Trusted kernel binding; class is immutable for this full object identity.
    /// No syscall accepts a rank or NO_IPC_WAIT bit from the caller.
    pub fn register(
        &mut self,
        a: &Authority,
        space: SpaceId,
        cap: Handle,
        class: LockClass,
    ) -> Result<(), Error> {
        let object = a
            .authorize(space, cap, Kind::Mutex, Rights::CONTROL)?
            .identity();
        if class.rank == 0 {
            return Err(Error::InvalidClass);
        }
        let slot = Self::index(object)?;
        if self.entries[slot].is_some() {
            return Err(Error::AlreadyRegistered);
        }
        self.entries[slot] = Some(Mutex {
            object,
            class,
            owner: None,
            abandoned: false,
        });
        Ok(())
    }
    /// Bounded try-acquire. Busy rejects before ownership/lock-stack changes;
    /// waiting queues and priority inheritance are separate later mechanisms.
    pub fn acquire(
        &mut self,
        a: &Authority,
        s: &Scheduler,
        rpc: &mut Rpc,
        cpu: usize,
        cap: Handle,
    ) -> Result<Acquired, Error> {
        let thread = s.running_thread(cpu)?;
        let space = rpc.checked_thread_domain(s, thread)?;
        let (slot, mutex) = self.object(a, space, cap)?;
        if let Some(owner) = mutex.owner {
            return Err(if owner.thread == thread {
                Error::AlreadyOwned
            } else {
                Error::Busy
            });
        }
        let serial = self
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        // All object/ownership/counter checks precede the fallible RPC rank and
        // NO_IPC_WAIT tracking. No fallible work follows successful enter_lock.
        rpc.enter_lock(thread, mutex.class)?;
        let lease = Lease(serial);
        self.entries[slot].as_mut().unwrap().owner = Some(Owner {
            thread,
            object: mutex.object,
            lease,
        });
        self.sequence = serial;
        Ok(Acquired {
            lease,
            abandoned: mutex.abandoned,
        })
    }
    /// Release reduces ownership, so no capability reauthorization is needed.
    /// A transferred/revoked acquisition cap cannot strand its live owner. The
    /// serial is bound to the actual registered running thread and full object.
    pub fn release(
        &mut self,
        s: &Scheduler,
        rpc: &mut Rpc,
        cpu: usize,
        lease: Lease,
    ) -> Result<(), Error> {
        let thread = s.running_thread(cpu)?;
        rpc.checked_thread_domain(s, thread)?;
        let (slot, mutex, owner) = self
            .entries
            .iter()
            .enumerate()
            .find_map(|(slot, m)| {
                m.and_then(|m| {
                    m.owner
                        .filter(|owner| owner.lease == lease)
                        .map(|owner| (slot, m, owner))
                })
            })
            .ok_or(Error::StaleLease)?;
        if owner.thread != thread {
            return Err(Error::NotOwner);
        }
        if owner.object != mutex.object {
            return Err(Error::Identity);
        }
        // leave_lock preflights exact LIFO rank before changing the RPC stack.
        // Clearing the logical owner is infallible after that single commit.
        rpc.leave_lock(thread, mutex.class.rank)?;
        self.entries[slot].as_mut().unwrap().owner = None;
        Ok(())
    }
    /// Call after actual Scheduler termination AND Rpc::peer_died, before RPC
    /// forgetting or scheduler ID reuse. That verified transition clears the
    /// dead thread's lock stack; no userspace death claim can release an owner.
    pub fn owner_died(
        &mut self,
        s: &Scheduler,
        rpc: &Rpc,
        thread: ThreadId,
    ) -> Result<usize, Error> {
        rpc.verified_dead(s, thread)?;
        let mut released = 0;
        for mutex in self.entries.iter_mut().flatten() {
            if mutex.owner.is_some_and(|owner| owner.thread == thread) {
                mutex.owner = None;
                mutex.abandoned = true;
                released += 1;
            }
        }
        Ok(released)
    }
    /// Retire an unowned object only when this CONTROL handle is its last
    /// lineage reference. Foreign/queued grants cause atomic ObjectBusy; callers
    /// must independently finish all process/IPC lifetime cleanup first.
    pub fn retire(&mut self, a: &mut Authority, space: SpaceId, cap: Handle) -> Result<(), Error> {
        let (slot, mutex) = self.object(a, space, cap)?;
        if mutex.owner.is_some() {
            return Err(Error::Busy);
        }
        let mut staged = a.staged_copy();
        staged.close(space, cap)?;
        staged.collect_lineage()?;
        staged.retire_unreferenced_object(mutex.object, Kind::Mutex)?;
        staged.collect_dead_objects()?;
        *a = staged;
        self.entries[slot] = None;
        Ok(())
    }
}
