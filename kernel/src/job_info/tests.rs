use super::*;
use crate::{
    capability::{Error as CapError, Kind, Rights, SpaceId},
    scheduler::{JobId, Limits},
};

const COMMON: Rights = Rights::from_bits(481).unwrap();
struct Fixture {
    a: Authority,
    s: Scheduler,
    r: Registry<'static>,
    caller: Metadata,
    owner: SpaceId,
    parent: JobId,
    peer: JobId,
    parent_cap: Handle,
    peer_cap: Handle,
    peer_root: Handle,
}
impl Fixture {
    fn new() -> Self {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let domain = a.create_space().unwrap();
        let mut s = Scheduler::new();
        let parent = s
            .create_job_with_limits(Limits::new(1000, 100, 4, 8))
            .unwrap();
        let job = s
            .create_child_job(parent, Limits::new(100, 10, 1, 2))
            .unwrap();
        let peer = s
            .create_child_job(parent, Limits::new(200, 20, 1, 2))
            .unwrap();
        let process = s.create_process(job).unwrap();
        let thread = s.create_thread(process).unwrap();
        let other = s.create_process(peer).unwrap();
        let other_thread = s.create_thread(other).unwrap();
        s.charge_frames(job, 3).unwrap();
        s.charge_frames(peer, 5).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
        s.charge_cpu(0, 2).unwrap();
        assert_eq!(s.dispatch(1).unwrap().unwrap().thread, other_thread);
        s.charge_cpu(1, 3).unwrap();
        let mut r = Registry::new();
        let parent_root = a.create_root(owner, Kind::Job, COMMON).unwrap();
        let peer_root = a.create_root(owner, Kind::Job, COMMON).unwrap();
        r.register_job(&a, owner, parent_root, parent).unwrap();
        r.register_job(&a, owner, peer_root, peer).unwrap();
        let parent_cap = a
            .derive(owner, parent_root, domain, Rights::CONTROL)
            .unwrap();
        let peer_cap = a.derive(owner, peer_root, domain, Rights::CONTROL).unwrap();
        Self {
            a,
            s,
            r,
            caller: Metadata {
                process,
                thread,
                job,
                domain,
                frames: 3,
            },
            owner,
            parent,
            peer,
            parent_cap,
            peer_cap,
            peer_root,
        }
    }
    fn query(&self, cap: Handle, field: u64) -> Result<u64, Error> {
        inspect(&self.a, &self.s, &self.r, self.caller, cap, field)
    }
}

#[test]
fn current_job_needs_no_registry_cap_and_explicit_control_reads_hierarchical_facts() {
    let f = Fixture::new();
    // There is deliberately no Registry row/cap for the actual caller Job.
    let before = (
        f.a.metadata_usage(),
        f.s.metadata_usage(),
        f.r.metadata_usage(),
    );
    let current = [f.caller.job.diagnostic_id(), 2, 3, 1, 1, 100, 10, 1, 2];
    let parent = [f.parent.diagnostic_id(), 5, 8, 2, 2, 1000, 100, 4, 8];
    let peer = [f.peer.diagnostic_id(), 3, 5, 1, 1, 200, 20, 1, 2];
    for field in 0..=8 {
        assert_eq!(f.query(Handle(0), field), Ok(current[field as usize]));
        assert_eq!(f.query(f.parent_cap, field), Ok(parent[field as usize]));
        assert_eq!(f.query(f.peer_cap, field), Ok(peer[field as usize]));
    }
    assert_eq!(
        before,
        (
            f.a.metadata_usage(),
            f.s.metadata_usage(),
            f.r.metadata_usage()
        )
    );
    assert_eq!(f.s.usage(f.parent, Resource::CpuTicks), Ok(5));
    assert_eq!(f.s.usage(f.parent, Resource::Frames), Ok(8));
}

#[test]
fn wrong_kind_insufficient_closed_foreign_and_unknown_controls_never_select_a_job() {
    let mut f = Fixture::new();
    let memory =
        f.a.create_root(f.caller.domain, Kind::Memory, Rights::CONTROL)
            .unwrap();
    let weak =
        f.a.derive(f.owner, f.peer_root, f.caller.domain, Rights::READ)
            .unwrap();
    let unknown =
        f.a.create_root(f.caller.domain, Kind::Job, Rights::CONTROL)
            .unwrap();
    let foreign = f.a.create_space().unwrap();
    // Domain-local handles may share integers. Choose an actually vacant local
    // slot to prove the foreign handle itself confers no ambient access.
    let mut foreign_cap = Handle(0);
    for _ in 0..10 {
        foreign_cap =
            f.a.derive(f.owner, f.peer_root, foreign, Rights::CONTROL)
                .unwrap();
    }
    for field in 0..=8 {
        assert_eq!(
            f.query(memory, field),
            Err(Error::Service(service::Error::Authority(
                CapError::WrongKind
            )))
        );
        assert_eq!(
            f.query(weak, field),
            Err(Error::Service(service::Error::Authority(CapError::Denied)))
        );
        assert_eq!(
            f.query(unknown, field),
            Err(Error::Service(service::Error::UnknownObject))
        );
        assert!(f.query(foreign_cap, field).is_err());
        // The low-byte local cap must not authorize a truncated high generation.
        assert!(f.query(Handle(f.peer_cap.0 | (1 << 63)), field).is_err());
        assert!(f.query(Handle(u64::MAX), field).is_err());
    }
    f.a.close(f.caller.domain, f.peer_cap).unwrap();
    assert!(f.query(f.peer_cap, 0).is_err());
    assert_eq!(f.query(Handle(0), 1), Ok(2));
}

#[test]
fn revoked_control_denies_every_field_without_affecting_self_or_ancestor() {
    let mut f = Fixture::new();
    f.a.revoke(f.owner, f.peer_root).unwrap();
    for field in 0..=8 {
        assert_eq!(
            f.query(f.peer_cap, field),
            Err(Error::Service(service::Error::Authority(CapError::Revoked)))
        );
    }
    assert_eq!(f.query(Handle(0), 1), Ok(2));
    assert_eq!(f.query(f.parent_cap, 1), Ok(5));
}

#[test]
fn reclaimed_scheduler_binding_cannot_alias_a_replacement_even_for_diagnostic_field() {
    let mut f = Fixture::new();
    let old = f.s.create_job_with_limits(Limits::new(7, 8, 1, 1)).unwrap();
    let cap =
        f.a.create_root(f.caller.domain, Kind::Job, Rights::CONTROL)
            .unwrap();
    f.r.register_job(&f.a, f.caller.domain, cap, old).unwrap();
    assert_eq!(f.query(cap, 0), Ok(old.diagnostic_id()));
    f.s.reclaim_job(old).unwrap();
    let replacement =
        f.s.create_job_with_limits(Limits::new(9, 10, 1, 1))
            .unwrap();
    assert_ne!(old.diagnostic_id(), replacement.diagnostic_id());
    for field in 0..=8 {
        assert_eq!(
            f.query(cap, field),
            Err(Error::Scheduler(scheduler::Error::InvalidId))
        );
    }
    assert_eq!(
        f.s.job_limits(replacement).unwrap().limit(Resource::Frames),
        10
    );
}

#[test]
fn malformed_field_and_stale_or_inconsistent_dispatch_context_are_read_only_denials() {
    let mut f = Fixture::new();
    for field in [9, 256, u64::MAX] {
        assert_eq!(f.query(Handle(0), field), Err(Error::InvalidField));
        assert_eq!(f.query(f.parent_cap, field), Err(Error::InvalidField));
    }
    let mut wrong = f.caller;
    wrong.job = f.peer;
    assert_eq!(
        inspect(&f.a, &f.s, &f.r, wrong, Handle(0), 0),
        Err(Error::Caller)
    );
    f.s.yield_cpu(0).unwrap();
    assert_eq!(f.query(Handle(0), 0), Err(Error::Caller));
    f.s.dispatch(0).unwrap().unwrap();
    f.a.close_space(f.caller.domain).unwrap();
    assert_eq!(f.query(Handle(0), 0), Err(Error::Caller));
    assert_eq!(f.s.usage(f.parent, Resource::CpuTicks), Ok(5));
}
