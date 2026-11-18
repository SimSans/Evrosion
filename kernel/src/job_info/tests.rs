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

struct ProcessFixture {
    a: Authority,
    s: Scheduler,
    r: Registry<'static>,
    caller: Metadata,
    job: Handle,
    process: Handle,
    target: Metadata,
}
impl ProcessFixture {
    fn new(active: bool) -> Self {
        use crate::service::{Role, SERVICE_LIMITS, ServiceImage};
        use sha2::{Digest, Sha256};
        let mut a = Authority::new();
        let domain = a.create_control_space().unwrap();
        let parent_cap = a.create_root(domain, Kind::Job, COMMON).unwrap();
        let image_cap = a.create_root(domain, Kind::Memory, Rights::READ).unwrap();
        let mut s = Scheduler::new();
        let parent = s
            .create_job_with_limits(Limits::new(1000, 128, 4, 8))
            .unwrap();
        let process = s.create_process(parent).unwrap();
        let thread = s.create_thread(process).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
        let caller = Metadata {
            process,
            thread,
            job: parent,
            domain,
            frames: 0,
        };
        let mut r = Registry::new();
        r.register_job(&a, domain, parent_cap, parent).unwrap();
        let bytes = include_bytes!("../../fixtures/bootstrap-static-v1.elf");
        let roles = [
            Role {
                selector: 3,
                kind: Kind::Endpoint,
                rights: Rights::RECEIVE | Rights::CONTROL,
            },
            Role {
                selector: 4,
                kind: Kind::Endpoint,
                rights: Rights::SEND,
            },
        ];
        let image =
            ServiceImage::verify(bytes, Sha256::digest(bytes).into(), SERVICE_LIMITS, &roles)
                .unwrap();
        r.register_image(&a, domain, image_cap, image).unwrap();
        let job = r.create_job(&mut a, &mut s, domain, parent_cap, 0).unwrap();
        let process = r
            .create_process(&mut a, &mut s, domain, job, image_cap)
            .unwrap();
        let target = if active {
            r.model_admit_for_grant_test(&a, &mut s, domain, process)
                .unwrap()
        } else {
            r.metadata(&a, domain, process).unwrap()
        };
        Self {
            a,
            s,
            r,
            caller,
            job,
            process,
            target,
        }
    }
    fn query(&self, handle: Handle, field: u64) -> Result<u64, Error> {
        inspect_process(&self.a, &self.s, &self.r, self.caller, handle, field)
    }
}

#[test]
fn process_control_queries_exact_active_job_without_extra_rights_or_metadata_changes() {
    let mut f = ProcessFixture::new(true);
    let before = (
        f.a.metadata_usage(),
        f.s.metadata_usage(),
        f.r.metadata_usage(),
    );
    for field in 0..=8 {
        assert_eq!(
            f.query(f.process, field),
            inspect(&f.a, &f.s, &f.r, f.caller, f.job, field)
        );
    }
    assert_eq!(
        before,
        (
            f.a.metadata_usage(),
            f.s.metadata_usage(),
            f.r.metadata_usage()
        )
    );
    let weak =
        f.a.derive(f.caller.domain, f.process, f.caller.domain, Rights::CONTROL)
            .unwrap();
    for field in 0..=8 {
        assert!(f.query(weak, field).is_ok());
    }
    assert!(
        f.a.authorize(f.caller.domain, weak, Kind::Job, Rights::CONTROL)
            .is_err()
    );
    assert!(
        f.a.authorize(f.caller.domain, weak, Kind::Process, Rights::READ)
            .is_err()
    );
    // Host-only lifetime precondition probe: closing a local Job handle does
    // not revoke the retained actual Job or its live ProcessCONTROL. This does
    // not change any actual Root setup/retirement path.
    f.a.close(f.caller.domain, f.job).unwrap();
    assert!(inspect(&f.a, &f.s, &f.r, f.caller, f.job, 0).is_err());
    assert_eq!(f.query(f.process, 0), Ok(f.target.job.diagnostic_id()));
    assert_eq!(
        f.s.usage(f.target.job, Resource::Frames),
        Ok(f.target.frames)
    );
}

#[test]
fn process_job_query_rejects_zero_wrong_kind_weak_unknown_foreign_closed_and_revoked_caps() {
    let mut f = ProcessFixture::new(true);
    let weak =
        f.a.derive(f.caller.domain, f.process, f.caller.domain, Rights::READ)
            .unwrap();
    let unknown =
        f.a.create_root(f.caller.domain, Kind::Process, Rights::CONTROL)
            .unwrap();
    let foreign = f.a.create_space().unwrap();
    let mut foreign_cap = Handle(0);
    for _ in 0..12 {
        foreign_cap =
            f.a.derive(f.caller.domain, f.process, foreign, Rights::CONTROL)
                .unwrap();
    }
    for field in 0..=8 {
        for cap in [
            Handle(0),
            Handle(f.target.process.diagnostic_id()),
            Handle(f.target.job.diagnostic_id()),
            f.job,
            weak,
            unknown,
            foreign_cap,
            Handle(f.process.0 | (1 << 63)),
            Handle(u64::MAX),
        ] {
            assert!(f.query(cap, field).is_err(), "handle {cap:?} field {field}");
        }
    }
    let closed =
        f.a.derive(f.caller.domain, f.process, f.caller.domain, Rights::CONTROL)
            .unwrap();
    f.a.close(f.caller.domain, closed).unwrap();
    let replacement =
        f.a.derive(f.caller.domain, f.process, f.caller.domain, Rights::CONTROL)
            .unwrap();
    assert_ne!(closed, replacement);
    assert_eq!(closed.0 & 255, replacement.0 & 255);
    for field in 0..=8 {
        assert!(f.query(closed, field).is_err());
        assert!(f.query(replacement, field).is_ok());
    }
    f.a.revoke(f.caller.domain, f.process).unwrap();
    for field in 0..=8 {
        assert!(f.query(replacement, field).is_err());
    }
}

#[test]
fn retained_stopped_job_is_readable_but_held_retired_and_reused_targets_are_denied() {
    let f = ProcessFixture::new(false);
    for field in 0..=8 {
        assert!(f.query(f.process, field).is_err());
    }
    let mut f = ProcessFixture::new(true);
    f.s.terminate_process(f.target.process).unwrap();
    for field in 0..=8 {
        assert_eq!(
            f.query(f.process, field),
            inspect(&f.a, &f.s, &f.r, f.caller, f.job, field)
        );
    }
    // Closing setup-only Job CONTROL leaves the retained association and
    // accounting intact. It does not make a stopped process a live grant target.
    f.a.close(f.caller.domain, f.job).unwrap();
    assert_eq!(f.query(f.process, 0), Ok(f.target.job.diagnostic_id()));
    assert!(
        f.r.active_metadata(&f.a, &f.s, f.caller.domain, f.process)
            .is_err()
    );
    f.r.retire(&mut f.a, &f.s, f.caller.domain, f.process)
        .unwrap();
    for field in 0..=8 {
        assert!(f.query(f.process, field).is_err());
    }
    // Only the portable host scheduler/metadata ownership gates are exercised.
    // No physical backing, accepted RPC or device owner exists in this fixture.
    f.s.release_frames(f.target.job, f.target.frames).unwrap();
    f.s.reclaim_process(f.target.process).unwrap();
    let new_process = f.s.create_process(f.target.job).unwrap();
    let _new_thread = f.s.create_thread(new_process).unwrap();
    assert_ne!(new_process, f.target.process);
    for field in 0..=8 {
        assert!(f.query(f.process, field).is_err());
    }
    assert_eq!(f.s.process_job(new_process), Ok(f.target.job));
}

#[test]
fn process_job_info_validates_fields_and_actual_running_caller_before_target_read() {
    let mut f = ProcessFixture::new(true);
    let before = (
        f.a.metadata_usage(),
        f.s.metadata_usage(),
        f.r.metadata_usage(),
    );
    for field in [9, 256, u64::MAX] {
        assert_eq!(f.query(f.process, field), Err(Error::InvalidField));
    }
    let mut wrong = f.caller;
    wrong.job = f.target.job;
    assert_eq!(
        inspect_process(&f.a, &f.s, &f.r, wrong, f.process, 0),
        Err(Error::Caller)
    );
    assert_eq!(
        before,
        (
            f.a.metadata_usage(),
            f.s.metadata_usage(),
            f.r.metadata_usage()
        )
    );
    f.s.yield_cpu(0).unwrap();
    assert_eq!(f.query(f.process, 0), Err(Error::Caller));
    f.s.dispatch(0).unwrap();
    f.a.close_space(f.caller.domain).unwrap();
    assert_eq!(f.query(f.process, 0), Err(Error::Caller));
    assert_eq!(
        (
            crate::capability::MAX_CAPS,
            crate::capability::MAX_CONTROL_CAPS,
            crate::capability::MAX_NODES
        ),
        (16, 64, 256)
    );
}

#[test]
fn active_registry_record_cannot_alias_a_reused_scheduler_process_generation() {
    let mut f = ProcessFixture::new(true);
    // Deliberately retain the old active Registry row while replacing portable
    // scheduler descriptors. This is corruption/fault-injection evidence, not
    // a permitted actual image/device lifetime transition.
    f.s.terminate_process(f.target.process).unwrap();
    f.s.release_frames(f.target.job, f.target.frames).unwrap();
    f.s.reclaim_process(f.target.process).unwrap();
    let replacement = f.s.create_process(f.target.job).unwrap();
    let thread = f.s.create_thread(replacement).unwrap();
    assert_ne!(replacement, f.target.process);
    assert_ne!(thread, f.target.thread);
    for field in 0..=8 {
        assert!(f.query(f.process, field).is_err());
    }
    assert_eq!(f.s.process_job(replacement), Ok(f.target.job));
}
