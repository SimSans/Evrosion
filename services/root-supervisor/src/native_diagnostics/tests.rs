//! Synthetic boundary tests and real Store-library tests; no physical collector
//! or graphical/persistence integration acceptance follows from these fixtures.
extern crate std;
use super::*;
use ev_diagnostics::{Component, inspector::Usage};
use ev_userspace_contract::root_v2::graph::Child;
use std::{collections::VecDeque, string::String, vec, vec::Vec};
fn ok(value: u64) -> Reply {
    Reply {
        status: 0,
        value,
        capability: 0,
    }
}
struct Model {
    fault: [u64; 24],
    jobs: [u64; 9],
    calls: Vec<(u64, u64, u64)>,
    clock: u64,
    clocks: VecDeque<u64>,
    no_fault: bool,
    overrides: Vec<(u64, u64, Reply)>,
}
impl Model {
    fn new() -> Self {
        let mut fault = [0; 24];
        fault[..9].copy_from_slice(&[
            17,
            0x20002,
            0x30003,
            14,
            4,
            0x8000400000,
            0x8000001234,
            0x8000103f00,
            0x202,
        ]);
        for (i, v) in fault[9..].iter_mut().enumerate() {
            *v = 0x12345670 + i as u64;
        }
        Self {
            fault,
            jobs: [17, 9, 23, 0, 0, 16384, 32, 1, 1],
            calls: Vec::new(),
            clock: 100,
            clocks: VecDeque::new(),
            no_fault: false,
            overrides: Vec::new(),
        }
    }
}
impl Boundary for Model {
    fn call(&mut self, number: u64, cap: u64, field: u64) -> Reply {
        self.calls.push((number, cap, field));
        if let Some((_, _, reply)) = self
            .overrides
            .iter()
            .find(|(n, f, _)| (*n, *f) == (number, field))
        {
            return *reply;
        }
        match number {
            syscall::MONOTONIC => {
                let value = self.clocks.pop_front().unwrap_or(self.clock);
                self.clock += 1;
                ok(value)
            }
            syscall::FAULT_INFO if cap == 100 => {
                if self.no_fault {
                    Reply {
                        status: 2,
                        value: 0,
                        capability: 0,
                    }
                } else {
                    ok(self.fault[field as usize])
                }
            }
            syscall::JOB_INFO if cap == 200 || cap == 0 => ok(self.jobs[field as usize]),
            syscall::PROCESS_JOB_INFO if cap == 100 => ok(self.jobs[field as usize]),
            _ => Reply {
                status: 1,
                value: 0,
                capability: 0,
            },
        }
    }
}
fn target() -> StoppedTarget {
    StoppedTarget {
        process_control: 100,
        job_authority: JobAuthority::Delegated(200),
        identity: Identity {
            process: 0x20002,
            thread: 0x30003,
        },
    }
}
#[test]
fn retained_process_control_collects_stopped_job_without_job_handle_or_raw_id() {
    let mut target = target();
    target.job_authority = JobAuthority::ProcessControl(target.process_control);
    let mut c = Collector::new(Model::new());
    let captured = c.fault(&target, provenance()).unwrap().unwrap();
    assert_eq!(captured.job.diagnostic_id, 17);
    assert_eq!(captured.crash.capture().process, target.identity.process);
    let model = c.into_boundary();
    assert!(!model.calls.iter().any(|&(n, _, _)| n == syscall::JOB_INFO));
    assert_eq!(
        model
            .calls
            .iter()
            .filter(|&&(n, _, _)| n == syscall::PROCESS_JOB_INFO)
            .count(),
        10
    );
    for authority in [
        JobAuthority::Current,
        JobAuthority::ProcessControl(0),
        JobAuthority::ProcessControl(999),
    ] {
        target.job_authority = authority;
        let mut c = Collector::new(Model::new());
        assert!(matches!(
            c.fault(&target, provenance()),
            Err(Error::Authority)
        ));
        assert!(c.into_boundary().calls.is_empty());
    }
}
fn provenance() -> Provenance {
    Provenance {
        component: Component::Application(ev_zion::AppId::new([7; 16]).unwrap()),
        image: [2; 32],
        package: Some([3; 32]),
        component_build: [4; 32],
        generation: None,
        epoch: 501,
        incarnation: 1,
    }
}
#[test]
fn full_actual_field_contract_and_crosschecks_precede_retirement() {
    let mut collector = Collector::new(Model::new());
    let result = collector.fault(&target(), provenance()).unwrap().unwrap();
    let captured = result.crash.capture();
    assert_eq!(
        (captured.job, captured.process, captured.thread),
        (17, 0x20002, 0x30003)
    );
    assert_eq!(
        (
            captured.vector,
            captured.error,
            captured.address,
            captured.instruction,
            captured.stack,
            captured.flags
        ),
        (14, 4, 0x8000400000, 0x8000001234, 0x8000103f00, 0x202)
    );
    assert_eq!(
        captured.registers,
        core::array::from_fn(|i| 0x12345670 + i as u64)
    );
    assert_eq!(Crash::decode(&result.crash.encode()), Ok(result.crash));
    assert!(result.first_tick <= result.job.first_tick && result.job.last_tick <= result.last_tick);
    let model = collector.into_boundary();
    assert!(model.calls.iter().all(|&(n, _, _)| {
        [syscall::MONOTONIC, syscall::JOB_INFO, syscall::FAULT_INFO].contains(&n)
    }));
    assert_eq!(
        model
            .calls
            .iter()
            .filter(|&&(n, _, _)| n == syscall::FAULT_INFO)
            .count(),
        27
    );
    assert!(
        !model
            .calls
            .iter()
            .any(|&(n, _, _)| n == syscall::REAP || n == syscall::CLOSE)
    );
}
#[test]
fn owner_stop_is_not_a_crash_and_permission_failure_is_not_no_fault() {
    let mut model = Model::new();
    model.no_fault = true;
    let mut c = Collector::new(model);
    assert!(c.fault(&target(), provenance()).unwrap().is_none());
    assert_eq!(c.into_boundary().calls.len(), 2);
    let mut target = target();
    target.process_control = 999;
    assert!(
        Collector::new(Model::new())
            .fault(&target, provenance())
            .is_err()
    );
}
#[test]
fn stale_identity_mismatched_job_and_abi_pollution_are_refused() {
    let mut model = Model::new();
    model.fault[2] += 1;
    assert!(matches!(
        Collector::new(model).fault(&target(), provenance()),
        Err(Error::Identity)
    ));
    let mut model = Model::new();
    model.jobs[0] += 1;
    assert!(matches!(
        Collector::new(model).fault(&target(), provenance()),
        Err(Error::Identity)
    ));
    let mut model = Model::new();
    model.overrides.push((
        syscall::FAULT_INFO,
        9,
        Reply {
            status: 0,
            value: 7,
            capability: 999,
        },
    ));
    assert!(matches!(
        Collector::new(model).fault(&target(), provenance()),
        Err(Error::Abi { field: 9, .. })
    ));
    let mut model = Model::new();
    model.overrides.push((
        syscall::FAULT_INFO,
        0,
        Reply {
            status: 2,
            value: 9,
            capability: 0,
        },
    ));
    assert!(matches!(
        Collector::new(model).fault(&target(), provenance()),
        Err(Error::Abi { field: 0, .. })
    ));
}
#[test]
fn job_observation_has_explicit_interval_limits_and_no_raw_id_lookup() {
    let mut c = Collector::new(Model::new());
    let row = c.job(JobAuthority::Delegated(200)).unwrap();
    assert_eq!(
        (row.diagnostic_id, row.first_tick, row.last_tick),
        (17, 100, 101)
    );
    assert_eq!(
        row.subtree,
        Usage {
            cpu_ticks: 9,
            frames: 23,
            processes: 0,
            threads: 0
        }
    );
    assert_eq!(
        row.limits,
        Usage {
            cpu_ticks: 16384,
            frames: 32,
            processes: 1,
            threads: 1
        }
    );
    let model = c.into_boundary();
    assert!(
        model
            .calls
            .iter()
            .filter(|&&(n, _, _)| n == syscall::JOB_INFO)
            .all(|&(_, cap, _)| cap == 200)
    );
    assert!(matches!(
        Collector::new(Model::new()).job(JobAuthority::Delegated(0)),
        Err(Error::Authority)
    ));
    assert!(
        Collector::new(Model::new())
            .job(JobAuthority::Delegated(17))
            .is_err()
    );
    let mut model = Model::new();
    model.clocks = VecDeque::from([20, 19]);
    assert!(matches!(
        Collector::new(model).job(JobAuthority::Current),
        Err(Error::Clock)
    ));
}
#[test]
fn service_provenance_does_not_invent_package_or_generation() {
    let p = service_provenance(Child::Shell, [2; 32], [4; 32], 501, 1).unwrap();
    assert_eq!(
        p.component,
        Component::Service(Child::Shell.image().selector() as u16)
    );
    assert_eq!(p.package, None);
    assert_eq!(p.generation, None);
    assert_eq!(
        service_provenance(Child::App, [2; 32], [4; 32], 501, 1),
        Err(Error::Identity)
    );
}
#[test]
fn framing_keeps_rejected_current_bytes_and_requires_complete_ordered_end() {
    use framing::*;
    for kind in [Kind::Crash, Kind::Job, Kind::System] {
        let payload: Vec<u8> = (0..kind.bytes()).map(|n| n as u8).collect();
        let mut tx = Tx::new(kind, 1).unwrap();
        let mut decoder = Decoder::new();
        let mut frames = 0;
        loop {
            let frame = tx.current(&payload).unwrap().unwrap();
            assert_eq!(tx.current(&payload).unwrap(), Some(frame));
            let completed = decoder.accept(frame).unwrap();
            frames += 1;
            let finished = tx.accepted().unwrap();
            if let Some(completed) = completed {
                assert!(finished);
                assert_eq!(&completed.bytes[..kind.bytes()], payload);
                assert_eq!(completed.serial, 1);
                break;
            }
            assert!(!finished);
        }
        assert_eq!(frames, kind.bytes() / 4 + 2);
        assert_eq!(tx.current(&payload).unwrap(), None);
        assert!(!decoder.pending());
        let begin = Tx::new(kind, 1)
            .unwrap()
            .current(&payload)
            .unwrap()
            .unwrap();
        assert!(matches!(decoder.accept(begin), Err(Error::Serial)));
    }
}
#[test]
fn malformed_partial_or_mixed_reports_never_emit_complete_records() {
    use framing::*;
    let payload = [7; CRASH_BYTES];
    let begin = Tx::new(Kind::Crash, 1)
        .unwrap()
        .current(&payload)
        .unwrap()
        .unwrap();
    for frame in [
        [b'N', b'C', 1, 255, 1, 0, 0, 0],
        [b'N', b'C', 1, 2, 7, 7, 7, 7],
        [b'N', b'J', 1, 1, 7, 7, 7, 7],
    ] {
        let mut decoder = Decoder::new();
        assert!(decoder.accept(begin).unwrap().is_none());
        assert!(matches!(decoder.accept(frame), Err(Error::Order)));
        assert!(decoder.pending());
        assert!(decoder.failed());
        assert!(decoder.accept([b'N', b'C', 1, 1, 7, 7, 7, 7]).is_err());
    }
    let mut decoder = Decoder::new();
    decoder.accept(begin).unwrap();
    assert!(matches!(decoder.accept(begin), Err(Error::Busy)));
    assert!(Tx::new(Kind::Crash, 0).is_err());
    assert!(
        Tx::new(Kind::Crash, 1)
            .unwrap()
            .current(&[0; JOB_BYTES])
            .is_err()
    );
}
fn row() -> presentation::Row {
    let job = Collector::new(Model::new())
        .job(JobAuthority::Delegated(200))
        .unwrap();
    presentation::Row::new(
        presentation::Role::Application,
        target().identity,
        true,
        [2; 32],
        Some([3; 32]),
        job,
    )
    .unwrap()
}
#[test]
fn job_wire_and_text_preserve_units_identity_and_unknown_system() {
    use presentation::*;
    let r = row();
    let bytes = r.encode();
    assert_eq!(Row::decode(&bytes), Ok(r));
    let mut bad = bytes;
    bad[13] = 1;
    assert_eq!(Row::decode(&bad), Err(Error::Wire));
    let mut bad = bytes;
    bad[12] &= !1;
    bad[72..104].fill(0);
    assert_eq!(Row::decode(&bad), Err(Error::Package));
    let mut out = String::new();
    let app = AppState {
        id: [7; 16],
        installed: true,
        active: Some([3; 32]),
        staged: None,
        previous: None,
        revision: 2,
    };
    inspector(&mut out, &app, &system::State::NotCollected, &[r]).unwrap();
    for expected in [
        "Application",
        "registry revision=2",
        "unknown",
        "no matched durable selection/admission",
        "subtree CPU 9/16384 ticks",
        "RAM 23/32 frames (92 KiB)",
        "observed ticks 100..101",
    ] {
        assert!(out.contains(expected), "{expected}");
    }
    let mut out = String::new();
    let captured = Collector::new(Model::new())
        .fault(&target(), provenance())
        .unwrap()
        .unwrap();
    crash(&mut out, &captured.crash).unwrap();
    assert!(out.contains("r15=0x0000000012345670"));
    assert!(out.contains("rax=0x000000001234567e"));
    assert!(out.contains("actual System generation unknown"));
    struct Refuses;
    impl core::fmt::Write for Refuses {
        fn write_str(&mut self, _: &str) -> core::fmt::Result {
            Err(core::fmt::Error)
        }
    }
    assert!(r.write(&mut Refuses).is_err());
    assert!(
        inspector(
            &mut String::new(),
            &app,
            &system::State::NotCollected,
            &[r, r]
        )
        .is_err()
    );
}
#[derive(Clone)]
struct Disk {
    sectors: Vec<ev_store::Sector>,
    writes: usize,
    flushes: usize,
    fail_write: Option<usize>,
}
impl Disk {
    fn blank() -> Self {
        Self {
            sectors: vec![[0; 512]; ev_store::REQUIRED_SECTORS as usize],
            writes: 0,
            flushes: 0,
            fail_write: None,
        }
    }
}
impl ev_store::SectorIo for Disk {
    type Error = ();
    fn sectors(&self) -> u64 {
        self.sectors.len() as u64
    }
    fn read(&mut self, lba: u64, out: &mut ev_store::Sector, _: u64) -> Result<(), ()> {
        *out = *self.sectors.get(lba as usize).ok_or(())?;
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &ev_store::Sector, _: u64) -> Result<(), ()> {
        self.writes += 1;
        if self.fail_write == Some(self.writes) {
            return Err(());
        }
        *self.sectors.get_mut(lba as usize).ok_or(())? = *bytes;
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), ()> {
        self.flushes += 1;
        Ok(())
    }
}
fn generation() -> ev_store::GenerationManifest {
    ev_store::GenerationManifest {
        generation: ev_store::GenerationId::new(1).unwrap(),
        cohort: [1; 32],
        supervisor_image: [2; 32],
        abi: [3; 32],
        health_contract: [4; 32],
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    }
}
fn formatted() -> ev_store::Store<Disk> {
    ev_store::Store::format_new(
        Disk::blank(),
        generation(),
        b"owner data",
        ev_store::BootPolicy::new(2).unwrap(),
        1000,
    )
    .unwrap_or_else(|_| panic!("test Store format"))
}
#[test]
fn real_system_store_unformatted_inspection_never_formats() {
    let disk = Disk::blank();
    let before = disk.sectors.clone();
    let (disk, state) = system::inspect(disk, 1000);
    assert!(matches!(state, system::State::Unformatted));
    assert_eq!(disk.sectors, before);
    assert_eq!((disk.writes, disk.flushes), (0, 0));
}
#[test]
fn real_committed_metadata_is_read_only_and_not_current_execution_attestation() {
    let disk = formatted().into_device();
    let before = disk.clone();
    let (disk, state) = system::inspect(disk, 1000);
    assert!(matches!(state,system::State::Committed{selected,..} if selected==generation()));
    assert_eq!(disk.sectors, before.sectors);
    assert_eq!((disk.writes, disk.flushes), (before.writes, before.flushes));
    let mut text = String::new();
    state.write(&mut text).unwrap();
    assert!(text.contains("not current-execution attestation"));
    assert!(text.contains("Current Native boot System generation: unknown"));
}
#[test]
fn real_pending_journal_recovery_is_refused_before_any_inspector_write() {
    let mut disk = formatted().into_device();
    disk.writes = 0;
    disk.flushes = 0;
    disk.fail_write = Some(2);
    let mut store = ev_store::Store::open(disk, 1000).unwrap_or_else(|_| panic!("test Store open"));
    assert!(
        store
            .execute(
                store.next_operation().unwrap(),
                ev_store::Request::WriteMutable {
                    object: ev_store::ObjectId::user_data(),
                    bytes: b"new owner data"
                },
                1000
            )
            .is_err()
    );
    let mut disk = store.into_device();
    disk.fail_write = None;
    let before = disk.clone();
    let (disk, state) = system::inspect(disk, 1000);
    assert!(matches!(state, system::State::NeedsRecovery));
    assert_eq!(disk.sectors, before.sectors);
    assert_eq!((disk.writes, disk.flushes), (before.writes, before.flushes));
}
#[test]
fn outbox_cannot_replace_accepted_work_and_archive_never_silently_overwrites() {
    use framing::*;
    let captured = Collector::new(Model::new())
        .fault(&target(), provenance())
        .unwrap()
        .unwrap()
        .crash;
    let mut archive = CrashArchive::new();
    let index = archive.push(captured).unwrap();
    assert_eq!(archive.push(captured), Err(ArchiveError::Duplicate));
    let mut box_ = Outbox::new();
    box_.start(Kind::Crash, 1, archive.payload(index).unwrap())
        .unwrap();
    let frame = box_.current().unwrap();
    assert_eq!(box_.start(Kind::Job, 2, &[0; JOB_BYTES]), Err(Error::Busy));
    assert_eq!(box_.current().unwrap(), frame);
    let mut decoder = Decoder::new();
    let mut frames = 0;
    while let Some(frame) = box_.current().unwrap() {
        decoder.accept(frame).unwrap();
        box_.accepted().unwrap();
        frames += 1;
    }
    assert_eq!(frames, 106);
    assert!(!box_.pending());
    assert!(!decoder.pending());
    let mut changed = captured.capture();
    changed.process += 1;
    let second = Crash::new(captured.provenance(), changed).unwrap();
    archive.push(second).unwrap();
    changed.process += 1;
    let third = Crash::new(captured.provenance(), changed).unwrap();
    assert_eq!(archive.push(third), Err(ArchiveError::Full));
    assert_eq!(Crash::decode(archive.payload(index).unwrap()), Ok(captured));
    assert_eq!(Crash::decode(&archive.remove(index).unwrap()), Ok(captured));
    archive.push(third).unwrap();
}
#[test]
fn actual_send_adapter_advances_only_canonical_acceptance_not_full_or_error() {
    use framing::*;
    struct Sender {
        replies: VecDeque<Reply>,
        calls: Vec<(u64, u64, u64)>,
    }
    impl Boundary for Sender {
        fn call(&mut self, n: u64, h: u64, v: u64) -> Reply {
            self.calls.push((n, h, v));
            self.replies.pop_front().unwrap()
        }
    }
    let mut sender = Sender {
        replies: VecDeque::from([
            Reply {
                status: 2,
                value: 0,
                capability: 0,
            },
            ok(0),
            Reply {
                status: 1,
                value: 0,
                capability: 0,
            },
        ]),
        calls: Vec::new(),
    };
    let mut box_ = Outbox::new();
    box_.start(Kind::Crash, 1, &[7; CRASH_BYTES]).unwrap();
    let begin = box_.current().unwrap();
    assert_eq!(tick(&mut box_, &mut sender, 300), Ok(Progress::Busy));
    assert_eq!(box_.current().unwrap(), begin);
    assert_eq!(tick(&mut box_, &mut sender, 300), Ok(Progress::Accepted));
    assert_eq!(sender.calls[0], sender.calls[1]);
    let payload = box_.current().unwrap();
    assert!(tick(&mut box_, &mut sender, 300).is_err());
    assert_eq!(box_.current().unwrap(), payload);
    assert!(box_.pending());
    assert!(
        sender
            .calls
            .iter()
            .all(|&(n, h, _)| n == syscall::SEND && h == 300)
    );
}

#[test]
fn v4_service_provenance_uses_exact_roles_and_never_names_a_legacy_service_or_package() {
    use ev_userspace_contract::root_v4::graph::Child as C;
    for (child, role) in [(C::NetDriver, 23), (C::NetService, 24)] {
        let p = network_service_provenance(child, [2; 32], [3; 32], 501, 1).unwrap();
        assert_eq!(p.component, Component::Service(role));
        assert_eq!(p.package, None);
        assert_eq!(p.generation, None);
    }
    assert_eq!(
        network_service_provenance(C::App, [2; 32], [3; 32], 501, 1),
        Err(Error::Identity)
    );
}

#[cfg(feature = "native-network")]
#[test]
fn fixed_inspector_profiles_remain_readonly_for_clean_foreign_and_pending_v1_v2() {
    for version in [1, 2] {
        let mut manifest = generation();
        manifest.health_version = version;
        let make = if version == 1 {
            ev_store::Store::format_new
        } else {
            ev_store::Store::format_new_downloaded_v2
        };
        let disk = make(
            Disk::blank(),
            manifest,
            b"owner data",
            ev_store::BootPolicy::new(2).unwrap(),
            1000,
        )
        .unwrap_or_else(|_| panic!("fixed fixture profile"))
        .into_device();
        let inspect = if version == 1 {
            system::inspect
        } else {
            system::inspect_downloaded_v2
        };
        let foreign = if version == 1 {
            system::inspect_downloaded_v2
        } else {
            system::inspect
        };
        let before = disk.clone();
        let (disk, result) = foreign(disk, 1000);
        assert!(matches!(result, system::State::Unavailable));
        assert_eq!(disk.sectors, before.sectors);
        assert_eq!((disk.writes, disk.flushes), (before.writes, before.flushes));
        let (mut disk, result) = inspect(disk, 1000);
        assert!(matches!(result,system::State::Committed {selected,..} if selected==manifest));
        disk.writes = 0;
        disk.flushes = 0;
        disk.fail_write = Some(2);
        let open = if version == 1 {
            ev_store::Store::open
        } else {
            ev_store::Store::open_downloaded_v2
        };
        let mut store = open(disk, 1000).unwrap_or_else(|_| panic!("fixed profile open"));
        assert!(
            store
                .execute(
                    store.next_operation().unwrap(),
                    ev_store::Request::WriteMutable {
                        object: ev_store::ObjectId::user_data(),
                        bytes: b"pending owner data"
                    },
                    1000
                )
                .is_err()
        );
        let mut disk = store.into_device();
        disk.fail_write = None;
        let before = disk.clone();
        let (disk, result) = inspect(disk, 1000);
        assert!(matches!(result, system::State::NeedsRecovery));
        assert_eq!(disk.sectors, before.sectors);
        assert_eq!((disk.writes, disk.flushes), (before.writes, before.flushes));
    }
}
