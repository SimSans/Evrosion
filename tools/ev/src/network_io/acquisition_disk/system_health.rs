//! Read-only captured-media joins for the actual downloaded System workflow.
//! These checks attest captured bytes; live health still needs actual VM facts.
use super::*;
use ev_store::{GenerationId, GenerationManifest, LastFailureReason};
use ev_userspace_contract::root_v4::{self, graph::Child};

pub(crate) struct Expected<'a> {
    pub selected: u64,
    pub known_good: Option<u64>,
    pub active: u64,
    pub candidate: u64,
    pub failed_child: bool,
    pub boot_serial: u64,
    pub saved: Saved<'a>,
}
pub(crate) struct Captured {
    pub proof: Value,
    pub replay: [u8; 1024],
    pub selected: GenerationManifest,
    pub active: GenerationManifest,
    pub probe: Vec<u8>,
    pub failure: Option<ev_store::LastFailure>,
    pub child_summary: Option<[u8; 256]>,
}

pub(crate) fn verify_probe(
    captured: &mut Captured,
    admitted: Option<ev_store::AdmissionReport>,
) -> Result<()> {
    let wanted = admitted.map(ev_root_supervisor::native_plan::system::probe);
    let expected = wanted.as_ref().map_or(
        ev_root_supervisor::native_plan::system::INITIAL_PAYLOAD,
        |bytes| bytes.as_slice(),
    );
    if captured.probe != expected {
        return Err("System durable probe differs from exact actual healthy admission".into());
    }
    captured.proof["probe"] = json!({"sha256":hex(&hash(&captured.probe)),
        "bytes":captured.probe.len(),"exact_full_payload_checked":true,
        "generation":admitted.map(|a|a.generation.get()),"boot_serial":admitted.map(|a|a.boot_serial),
        "process_stamp":admitted.map(|a|a.process_stamp)});
    Ok(())
}

fn manifest(
    banks: &Packages<'_>,
    content: acq::Content,
    artifact: &[u8],
) -> Result<GenerationManifest> {
    let package = ev_zion::Package::parse(artifact).map_err(|e| format!("System Zion: {e:?}"))?;
    package
        .check_requirements(1, ev_userspace_contract::ABI, &Contracts)
        .map_err(|e| format!("System Zion requirements: {e:?}"))?;
    if package.id().bytes() != content.package
        || content.object.sha256() != content.package
        || content.object.length() != artifact.len() as u64
        || package.app().claimed_app != banks.app()
        || package.app().build_id != content.build
        || content.source != banks.catalogue().base().kernel_input()
    {
        return Err("System content/package/source association differs".into());
    }
    let mut images = vec![banks.catalogue().base().root_image()];
    for child in [
        Child::Shell,
        Child::Input,
        Child::File,
        Child::Block,
        Child::Display,
    ] {
        images.push(
            banks
                .catalogue()
                .base()
                .images()
                .nth(child.index())
                .ok_or("System component missing")?
                .image,
        );
    }
    images.push(package.executable().digest);
    let mut h = Sha256::new();
    h.update(b"evrosion.V4.downloaded-cohort.recipe.v2\0");
    h.update(2u16.to_le_bytes());
    h.update(hash(
        ev_root_supervisor::downloaded_health::HEALTH_DESCRIPTION,
    ));
    h.update(ev_root_supervisor::native_plan::system::catalogue_recipe(
        banks,
    ));
    h.update(root_v4::ABI);
    h.update(ev_userspace_contract::ABI);
    for image in images {
        h.update(image);
    }
    for digest in [
        content.package,
        content.build,
        content.source,
        content.descriptor,
        content.object.sha256(),
    ] {
        h.update(digest);
    }
    h.update(content.object.length().to_le_bytes());
    h.update(content.version.to_le_bytes());
    Ok(GenerationManifest {
        generation: GenerationId::new(content.version).ok_or("System generation invalid")?,
        cohort: h.finalize().into(),
        supervisor_image: banks.catalogue().base().root_image(),
        abi: root_v4::ABI,
        health_contract: hash(ev_root_supervisor::downloaded_health::HEALTH_DESCRIPTION),
        health_version: 2,
        required_checks: 3,
    })
}

fn cold(bytes: &[u8]) -> Result<acq::Store<Media<'_>>> {
    shape(bytes)?;
    let cut = TransferCut::new(1, CUT).map_err(|_| "System audit cut")?;
    let arena = Arena::open(
        Media {
            bytes,
            reads: 0,
            writes: 0,
        },
        ev_root_supervisor::native_update::creation_manifest(),
        cut.metadata(1).unwrap(),
    )
    .map_err(|_| "System content Arena cold open")?;
    let mut opening = acq::Store::from_arena(arena)
        .begin_cold(cut, 1)
        .map_err(|_| "System signed content cold begin")?;
    let mut buffers = acq::Buffers::empty();
    for _ in 0..16384 {
        if opening
            .step(&mut buffers, 1)
            .map_err(|_| "System signed content cold verify")?
        {
            return opening
                .finish()
                .map_err(|_| "System signed content cold finish".into());
        }
    }
    Err("System signed content cold bound".into())
}

pub(crate) fn inspect(
    before: &[u8],
    after: &[u8],
    banks: &Packages<'_>,
    creation: &NamespaceCreation,
    artifacts: &[&[u8]],
    expected: Expected<'_>,
    allow_note_change: bool,
) -> Result<Captured> {
    creation.check_current(banks)?;
    let changed = changes(before, after, |s| {
        content_sector(s)
            || [Region::System, Region::AppRegistry]
                .into_iter()
                .any(|r| region_sector(s, r))
            || allow_note_change && region_sector(s, Region::SessionNote)
    })?;
    let mut content = cold(after)?;
    let snapshot = content
        .snapshot()
        .ok_or("System audit authenticated snapshot absent")?;
    if snapshot.active().map(|c| c.version) != Some(expected.active)
        || snapshot.candidate().map(|c| c.version) != Some(expected.candidate)
        || snapshot.known_good().map(|c| c.version) != expected.known_good
        || snapshot.replay().utc_floor() == 0
    {
        return Err("System acquisition active/candidate/KnownGood/floor differs".into());
    }
    let role_version = if expected.candidate == 2 {
        1
    } else if expected.candidate == 3 {
        2
    } else {
        return Err("System unexpected candidate version".into());
    };
    if snapshot.replay().root().version != 1
        || snapshot
            .replay()
            .roles()
            .iter()
            .any(|r| r.is_none_or(|id| id.version != role_version))
        || snapshot
            .replay()
            .targets()
            .iter()
            .flatten()
            .map(|t| t.version)
            .collect::<Vec<_>>()
            != [expected.candidate]
    {
        return Err(
            "System real remote replay floors did not advance to the exact B/C phase".into(),
        );
    }
    let mut replay = [0; 1024];
    ev_release_trust::checkpoint::encode(snapshot.replay(), &mut replay);
    let members = [
        snapshot.candidate(),
        snapshot.active(),
        snapshot.known_good(),
    ];
    let member = |version| {
        members
            .into_iter()
            .flatten()
            .find(|c| c.version == version)
            .ok_or("System retained member absent")
    };
    let selected_content = member(expected.selected)?;
    let active_content = member(expected.active)?;
    let known_content = expected.known_good.map(member).transpose()?;
    let artifact = |c: acq::Content| {
        artifacts
            .iter()
            .copied()
            .find(|b| hash(b) == c.package)
            .ok_or("System actual public artifact absent")
    };
    let selected = manifest(banks, selected_content, artifact(selected_content)?)?;
    let active = manifest(banks, active_content, artifact(active_content)?)?;
    let known_good = known_content
        .map(|c| manifest(banks, c, artifact(c)?))
        .transpose()?;
    let floor = snapshot.replay().utc_floor();
    // Re-read every distinct retained member through the production full-hash
    // reader, rather than trusting a package label or current candidate alone.
    let mut objects = Vec::new();
    for (i, c) in members.into_iter().enumerate() {
        if let Some(c) = c
            && !members[..i].contains(&Some(c))
        {
            let (next, object) = read_exact(
                content,
                c.object,
                artifact(c)?,
                TransferCut::new(1, CUT).unwrap(),
            )?;
            content = next;
            objects.push(object);
        }
    }
    let mut media = Media {
        bytes: after,
        reads: 0,
        writes: 0,
    };
    let mut system = Store::open_downloaded_v2(media.region(Region::System), CUT)
        .map_err(|r| format!("System actual journal open: {:?}", r.error))?;
    if system
        .selected_manifest(CUT)
        .map_err(|e| format!("System selected: {e:?}"))?
        != selected
        || system
            .known_good_manifest(CUT)
            .map_err(|e| format!("System KnownGood: {e:?}"))?
            != known_good
        || system
            .committed_boot_serial()
            .map_err(|e| format!("System serial: {e:?}"))?
            != expected.boot_serial
    {
        return Err("System manifest/KnownGood/charged serial differs".into());
    }
    let failure = system
        .last_failure()
        .map_err(|e| format!("System LAST failure: {e:?}"))?;
    if !matches!(system.boot_plan(CUT), Err(ev_store::Error::Phase)) {
        return Err("System retained unfinished boot admission/health transaction".into());
    }
    let mut probe = [0; 256];
    let probe_bytes = system
        .read_mutable(ObjectId::user_data(), &mut probe, CUT)
        .map_err(|e| format!("System durable probe read: {e:?}"))?;
    let probe = probe[..probe_bytes].to_vec();
    let _ = system;
    let mut child_summary = None;
    if expected.failed_child {
        let failure = failure.ok_or("System lost actual child failure")?;
        if failure.generation.get() != 3
            || failure.reason != LastFailureReason::CriticalComponentFault
            || failure.process_stamp.is_none()
            || failure.supervisor_image != selected.supervisor_image
            || failure.attempts == 0
            || failure.boot_serial == 0
            || failure.boot_serial > expected.boot_serial
        {
            return Err("System child failure identity/reason differs".into());
        }
        let evidence = failure
            .evidence
            .ok_or("System child fault summary reference absent")?;
        if evidence.bytes != 256 {
            return Err("System child summary extent".into());
        }
        // Object offsets are logical within the independently bounded content
        // area. Construct only through the checked public Object parser below.
        let object = Object::checked(
            evidence.object_start as u64,
            evidence.bytes as u64,
            evidence.sha256,
        )
        .map_err(|_| "System child summary object bounds")?;
        let mut reader = content
            .begin_read(object, TransferCut::new(1, CUT).unwrap(), 1)
            .map_err(|_| "System child summary read begin")?;
        let mut bytes = [0; 256];
        if reader
            .read_chunk(&mut bytes, 1)
            .map_err(|_| "System child summary read")?
            != 256
            || reader.remaining() != 0
        {
            return Err("System child summary short read".into());
        }
        let stored = reader
            .finish()
            .map_err(|_| "System child summary full hash")?;
        content = stored.store;
        let word = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let c = member(3)?;
        let failed_manifest = manifest(banks, c, artifact(c)?)?;
        let elf = ev_zion::Package::parse(artifact(c)?)
            .map_err(|_| "C summary package")?
            .executable()
            .digest;
        if &bytes[..8] != b"EVCFAULT"
            || bytes[8] != 1
            || bytes[9..16] != [0; 7]
            || word(16) != 3
            || word(24) != failure.boot_serial
            || bytes[32..64] != failure.process_stamp.unwrap()
            || bytes[64..96] != failure.supervisor_image
            || bytes[96..128] != elf
            || word(128) == 0
            || word(136) == 0
            || word(144) == u64::MAX
            || word(152) != 6
            || word(160) != 0
            || bytes[184..216] != failed_manifest.cohort
            || bytes[216..] != [0; 40]
        {
            return Err("System genuine C UD fault summary facts differ".into());
        }
        child_summary = Some(bytes);
    } else if failure.is_some() {
        return Err("System unexpected LAST failure".into());
    }
    let mut registry_store = open_original_region(&mut media, creation, Region::AppRegistry)?;
    let registry = ev_zion::lifecycle::Record::decode(&body(&mut registry_store)?)
        .map_err(|_| "System Registry decode")?;
    let device = registry_store.into_device();
    struct Sources<'a, 'b> {
        banks: &'a Packages<'b>,
        artifacts: &'a [&'a [u8]],
    }
    impl ev_app_registry::Packages for Sources<'_, '_> {
        fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
            self.banks
                .slot(digest)
                .map(|s| self.banks.bytes(s))
                .or_else(|| self.artifacts.iter().copied().find(|b| hash(b) == digest))
        }
    }
    let resolved = Registry::open(
        device,
        Policy {
            app: banks.app(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        },
        &Sources { banks, artifacts },
        &Contracts,
        CUT,
    )
    .map_err(|r| format!("System Registry package resolution: {:?}", r.error))?;
    let (_, _, pending) = resolved.into_parts();
    if pending.is_some() {
        return Err("System Registry retained pending publication".into());
    }
    if registry.active().map(|r| r.digest()) != Some(active_content.package) {
        return Err("System Registry and acquisition active disagree".into());
    }
    let data = AppDataEnvelope::decode(&body(&mut open_original_region(
        &mut media,
        creation,
        Region::AppData,
    )?)?)
    .map_err(|_| "System scalar decode")?;
    let note = NoteDataEnvelope::decode(&body(&mut open_original_region(
        &mut media,
        creation,
        Region::SessionNote,
    )?)?)
    .map_err(|_| "System Note decode")?;
    if data.app() != banks.app()
        || data.value() != expected.saved.value
        || data.counter() != expected.saved.data_counter
        || note.app() != banks.app()
        || note.note() != expected.saved.note
        || note.counter() != expected.saved.note_counter
    {
        return Err("System lost later owner Note/scalar data".into());
    }
    let backend = content.into_arena().into_backend();
    if media.writes != 0 || backend.writes != 0 {
        return Err("System audit attempted media repair/write".into());
    }
    Ok(Captured {
        proof: json!({"kind":"readonly-actual-System-and-signed-retained-members","namespace_creation":creation.proof(),"selected":expected.selected,
        "known_good":expected.known_good,"active":expected.active,"candidate":expected.candidate,"boot_serial":expected.boot_serial,
        "utc_floor":floor,"replay_sha256":hex(&hash(&replay)),"objects":objects,"note":note.note(),"note_counter":note.counter(),
        "value":data.value(),"data_counter":data.counter(),"child_failure_checked":expected.failed_child,
        "changed_sectors":changed,"all_unrelated_bytes_unchanged":true,"observer_mutations":0,
        "live_health_or_remote_authority_claim":false}),
        replay,
        selected,
        active,
        probe,
        failure,
        child_summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_requires_full_exact_actual_admission_and_keeps_retained_b_serial_distinct() {
        let selected = GenerationManifest {
            generation: GenerationId::new(2).unwrap(),
            cohort: [1; 32],
            supervisor_image: [2; 32],
            abi: [3; 32],
            health_contract: [4; 32],
            health_version: 2,
            required_checks: 3,
        };
        let admitted = ev_store::AdmissionReport {
            generation: selected.generation,
            boot_serial: 1,
            process_stamp: [5; 32],
            cohort: selected.cohort,
            supervisor_image: selected.supervisor_image,
            abi: selected.abi,
            health_contract: selected.health_contract,
            health_version: 2,
        };
        let probe = ev_root_supervisor::native_plan::system::probe(admitted).to_vec();
        let capture = |probe| Captured {
            proof: json!({}),
            replay: [0; 1024],
            selected,
            active: selected,
            probe,
            failure: None,
            child_summary: None,
        };
        assert!(verify_probe(&mut capture(probe.clone()), Some(admitted)).is_ok());
        for at in 0..probe.len() {
            let mut bad = probe.clone();
            bad[at] ^= 1;
            assert!(verify_probe(&mut capture(bad), Some(admitted)).is_err());
        }
        let mut later = admitted;
        later.boot_serial = 3;
        assert!(verify_probe(&mut capture(probe.clone()), Some(later)).is_err());
        let mut c = admitted;
        c.generation = GenerationId::new(3).unwrap();
        assert!(verify_probe(&mut capture(probe), Some(c)).is_err());
        let initial = ev_root_supervisor::native_plan::system::INITIAL_PAYLOAD.to_vec();
        assert!(verify_probe(&mut capture(initial.clone()), None).is_ok());
        assert!(verify_probe(&mut capture(initial), Some(admitted)).is_err());
    }
}

#[cfg(test)]
mod health_policy_phase_tests {
    use ev_kernel::scheduler::{Limits, Resource, Scheduler, State};

    // Actual Core scheduler, one sampled tick per serialized execution step.
    // This bounds this two-peer work model, never the complete guest latency.
    fn remaining_work(phase: u64, residual: u64, work: u64, abuse: bool) -> (bool, u64) {
        let mut s = Scheduler::new();
        let boot = s
            .create_job_with_limits(Limits::new(262144, 1024, 10, 10))
            .unwrap();
        s.configure_cpu_budget(boot, 256, 256).unwrap();
        let service = s
            .create_child_job(boot, Limits::new(16384, 32, 1, 1))
            .unwrap();
        s.configure_cpu_budget(service, 64, 256).unwrap();
        let process = s.create_process(service).unwrap();
        let thread = s.create_thread(process).unwrap();
        let prior = 64 - residual;
        assert!(
            prior <= phase,
            "one BSP cannot consume more sampled ticks than elapsed phase"
        );
        for tick in 0..prior {
            s.advance(tick).unwrap();
            assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
            s.charge_cpu(0, 1).unwrap();
            s.yield_cpu(0).unwrap();
        }
        s.advance(phase).unwrap();
        assert_eq!(
            s.cpu_budget(service).unwrap().unwrap().remaining_ticks,
            residual
        );
        let hostile = if abuse {
            let job = s
                .create_child_job(boot, Limits::new(16384, 32, 1, 1))
                .unwrap();
            s.configure_cpu_budget(job, 64, 256).unwrap();
            let process = s.create_process(job).unwrap();
            Some((job, s.create_thread(process).unwrap()))
        } else {
            None
        };
        let deadline = phase + ev_root_supervisor::downloaded_health::PROGRESS_TICKS;
        let mut done = 0;
        for tick in phase..deadline {
            s.advance(tick).unwrap();
            if let Some(dispatch) = s.dispatch(0).unwrap() {
                s.charge_cpu(0, 1).unwrap();
                if dispatch.thread == thread {
                    done += 1;
                } else {
                    assert_eq!(Some(dispatch.thread), hostile.map(|(_, thread)| thread));
                }
                s.yield_cpu(0).unwrap();
            }
            let service_used = s.usage(service, Resource::CpuTicks).unwrap();
            let hostile_used =
                hostile.map_or(0, |(job, _)| s.usage(job, Resource::CpuTicks).unwrap());
            assert_eq!(
                s.usage(boot, Resource::CpuTicks).unwrap(),
                service_used + hostile_used
            );
            assert_eq!(service_used, prior + done);
            if done == work {
                return (tick + 1 < deadline, tick + 1 - phase);
            }
        }
        assert_eq!(s.state(thread), Ok(State::Ready));
        (false, deadline - phase)
    }

    #[test]
    fn health_v2_all256_phase_offsets_and_feasible_residuals_keep_charges_with_abusive_peer() {
        let mut feasible = 0;
        for phase in 0..256 {
            for residual in [0, 1, 64] {
                // Exhausted/one-left at the very beginning of a period cannot
                // be manufactured by a single BSP before enough actual ticks.
                if 64 - residual > phase {
                    continue;
                }
                feasible += 1;
                let (timely, elapsed) = remaining_work(phase, residual, 64, true);
                assert!(timely, "phase{phase} residual{residual} elapsed{elapsed}");
                assert!(elapsed < 512);
            }
        }
        assert_eq!(feasible, 641);
        let (timely, elapsed) = remaining_work(64, 0, 64, true);
        assert!(timely && elapsed > 64 && elapsed < 512);
    }

    #[test]
    fn health_v2_is_bounded_failure_policy_not_a_hard_service_guarantee() {
        let (timely, elapsed) = remaining_work(64, 0, 129, true);
        assert!(!timely);
        assert_eq!(elapsed, 512);
    }

    #[test]
    fn health_v2_fresh_child_credit_does_not_bypass_exhausted_actual_boot_ancestor() {
        let mut s = Scheduler::new();
        let boot = s
            .create_job_with_limits(Limits::new(262144, 1024, 10, 10))
            .unwrap();
        s.configure_cpu_budget(boot, 256, 256).unwrap();
        for child in 0..4 {
            let job = s
                .create_child_job(boot, Limits::new(16384, 32, 1, 1))
                .unwrap();
            s.configure_cpu_budget(job, 64, 256).unwrap();
            let process = s.create_process(job).unwrap();
            let thread = s.create_thread(process).unwrap();
            for step in 0..64 {
                s.advance(child * 64 + step).unwrap();
                assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
                s.charge_cpu(0, 1).unwrap();
                s.yield_cpu(0).unwrap();
            }
            s.terminate_process(process).unwrap();
        }
        assert_eq!(s.cpu_budget(boot).unwrap().unwrap().remaining_ticks, 0);
        let fresh = s
            .create_child_job(boot, Limits::new(16384, 32, 1, 1))
            .unwrap();
        s.configure_cpu_budget(fresh, 64, 256).unwrap();
        let process = s.create_process(fresh).unwrap();
        let thread = s.create_thread(process).unwrap();
        assert_eq!(s.cpu_budget(fresh).unwrap().unwrap().remaining_ticks, 64);
        assert_eq!(s.dispatch(0), Ok(None));
        assert_eq!(s.state(thread), Ok(State::Ready));
        s.advance(256).unwrap();
        assert_eq!(s.usage(boot, Resource::CpuTicks).unwrap(), 256);
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
    }
}

pub(crate) mod selector;

pub(crate) mod first_use;
