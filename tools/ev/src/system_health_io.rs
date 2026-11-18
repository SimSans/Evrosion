//! Actual System guest workflow. Captured media, authenticated sender records,
//! real scanout and complete retirement are independent required joins.
use crate::{
    acquisition_io as common,
    boot::ChildGuard,
    build::{Manifest, Result},
    download_fixture::{self, Author, FixturePhase, Server},
    network_io::{
        acquisition_disk::{NamespaceCreation, Saved, system_health as disk_check},
        components::Context,
    },
    network_mode::Mode,
    qmp::{Key, Qmp},
    storage,
};
use ev_diagnostics::{
    owner::{Action, Phase as OwnerPhase},
    system::{Phase as HealthPhase, Snapshot},
};
use ev_graphics::{
    native::Build,
    session::{Focus, SaveState},
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) const LATER_NOTE: &str = "M6 keep42 later";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Phase {
    SelectB,
    HealthyAndStageC,
    FaultC,
    Recovery,
    FinalB,
}
impl Phase {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SelectB => "select-b",
            Self::HealthyAndStageC => "healthy-b-stage-c",
            Self::FaultC => "fault-c",
            Self::Recovery => "owner-recovery",
            Self::FinalB => "final-b",
        }
    }
    pub(crate) fn mode(self) -> Mode {
        match self {
            Self::SelectB => Mode::Standalone,
            Self::Recovery => Mode::Recovery,
            _ => Mode::SystemManaged,
        }
    }
    pub(crate) fn fixture(self) -> &'static str {
        self.mode().fixture()
    }
    pub(crate) fn offline(self) -> bool {
        self != Self::HealthyAndStageC
    }
    fn initial_release(self) -> Option<FixturePhase> {
        (!self.offline()).then_some(FixturePhase::B)
    }
    fn subject_release(self) -> Option<FixturePhase> {
        match self {
            Self::HealthyAndStageC | Self::FinalB => Some(FixturePhase::B),
            Self::FaultC => Some(FixturePhase::C),
            Self::SelectB | Self::Recovery => None,
        }
    }
    fn mode_number(self) -> u64 {
        match self.mode() {
            Mode::Standalone => 0,
            Mode::SystemManaged => 1,
            Mode::Recovery => 2,
        }
    }
}
fn snapshots(serial: &[u8], build: &str) -> Result<Vec<Snapshot>> {
    // Validate the shared typed-report sequence and canonical owner text too.
    // Individual decodes alone cannot reject replay/gaps or changed origins.
    crate::native3_diagnostics::owners(serial, build)?;
    let root = common_prefix(serial, build)?;
    let mut out = Vec::new();
    for (at, line) in std::str::from_utf8(common::complete(serial))
        .map_err(|_| "System serial UTF8")?
        .lines()
        .enumerate()
    {
        if line.starts_with("EVROSION_NATIVE_SYSTEM ") {
            let crate::native_diagnostics::Event::Report(r) =
                crate::native_diagnostics::parse(line, build, at)?
            else {
                return Err("System typed report missing".into());
            };
            if r.origin != (root.root_process, root.root_thread) {
                return Err("System typed report is not from the actual current Root".into());
            }
            out.push(
                Snapshot::decode(&r.bytes).map_err(|e| format!("System snapshot decode: {e:?}"))?,
            );
        }
    }
    Ok(out)
}
fn common_prefix(serial: &[u8], build: &str) -> Result<crate::native3_protocol::CommonPrefix> {
    let mut found = None;
    for line in std::str::from_utf8(common::complete(serial))
        .map_err(|_| "System prefix UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(row) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if found.replace(row).is_some() {
                return Err("System duplicate actual Root prefix".into());
            }
        }
    }
    found.ok_or("System actual Root prefix absent".into())
}
fn digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err("System digest extent".into());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "System digest encoding")?;
    }
    Ok(bytes)
}
/// The wire slot is a physical registration in this Root incarnation, not a
/// release generation. Cold loading visits candidate, active, then KnownGood;
/// C may register first, and a later fresh B boot may run B from slot2.
fn registered_subject<'a>(
    serial: &[u8],
    build: &str,
    actions: &'a [crate::downloaded_protocol::Action],
) -> Result<Option<&'a crate::downloaded_protocol::Action>> {
    if actions.is_empty() {
        return Ok(None);
    }
    let starts: Vec<_> = actions.iter().filter(|a| a.kind == "start").collect();
    if starts.len() != 1 || actions.len() > 3 {
        return Err("System needs one actual registered downloaded subject".into());
    }
    let subject = starts[0];
    let root = common_prefix(serial, build)?;
    let registrations: Vec<_> = crate::image_protocol::records(serial, build)?
        .into_iter()
        .filter(|r| {
            r.op == 6
                && r.status == 0
                && r.phase == 4
                && r.elf_sha256 == subject.elf_sha256
                && r.content_sha256 == subject.content_sha256
                && r.declared_package_id == subject.declared_package_id
        })
        .collect();
    if registrations.len() != 1
        || registrations[0].process != root.root_process
        || registrations[0].thread != root.root_thread
        || !(1..=2).contains(&registrations[0].slot)
        || registrations[0].slot != subject.slot
        || actions
            .iter()
            .zip(["start", "stop", "reap"])
            .any(|(a, kind)| {
                a.kind != kind
                    || a.slot != subject.slot
                    || a.process != subject.process
                    || a.thread != subject.thread
                    || a.job != subject.job
                    || a.elf_sha256 != subject.elf_sha256
                    || a.content_sha256 != subject.content_sha256
                    || a.declared_package_id != subject.declared_package_id
            })
    {
        return Err("System current Root registration and App lifetime differ".into());
    }
    Ok(Some(subject))
}
fn matches_produced_subject(
    subject: &crate::downloaded_protocol::Action,
    elf: &str,
    content: &str,
) -> Result<()> {
    if subject.elf_sha256 != elf
        || subject.content_sha256 != content
        || subject.declared_package_id != content
    {
        return Err(
            "System actual downloaded execution differs from produced signed artifact".into(),
        );
    }
    Ok(())
}
fn phase_subject<'a>(
    serial: &[u8],
    build: &str,
    phase: Phase,
    bundle: &download_fixture::Bundle,
    actions: &'a [crate::downloaded_protocol::Action],
) -> Result<Option<&'a crate::downloaded_protocol::Action>> {
    let subject = registered_subject(serial, build, actions)?;
    match (phase.subject_release(), subject) {
        (None, Some(_)) => Err("System no-App phase executed downloaded code".into()),
        (Some(release), Some(subject)) => {
            let index = match release {
                FixturePhase::B => 0,
                FixturePhase::C => 1,
            };
            let download = &bundle.downloads[index];
            let elf = common::hash(&common::bounded(&download.component.image, 1024 * 1024)?);
            let content = common::hash(&common::bounded(&download.package, 262144)?);
            matches_produced_subject(subject, &elf, &content)?;
            Ok(Some(subject))
        }
        (_, None) => Ok(None),
    }
}
/// General Store/wire support for v1 does not authorize its old64 policy in the
/// downloaded v2 checker. Check semantics before reconstructing any admission.
fn current_health_manifest(manifest: &ev_store::GenerationManifest) -> Result<()> {
    if !manifest.valid()
        || manifest.health_version != 2
        || manifest.health_contract
            != <[u8; 32]>::from(Sha256::digest(
                ev_root_supervisor::downloaded_health::HEALTH_DESCRIPTION,
            ))
        || manifest.abi != ev_userspace_contract::root_v4::ABI
    {
        return Err("System manifest differs from downloaded healthv2 contract".into());
    }
    Ok(())
}
fn admission_stamp(
    root: &crate::native3_protocol::CommonPrefix,
    subject: &crate::downloaded_protocol::Action,
    manifest: &ev_store::GenerationManifest,
    boot_serial: u64,
) -> Result<[u8; 32]> {
    current_health_manifest(manifest)?;
    let mut hash = Sha256::new();
    hash.update(b"evrosion.V4.downloaded-cohort.actual-admission.v2\0");
    hash.update(manifest.health_version.to_le_bytes());
    hash.update(manifest.health_contract);
    for bytes in [
        manifest.cohort,
        digest(&root.root_manifest)?,
        digest(&root.root_image)?,
        digest(&subject.elf_sha256)?,
    ] {
        hash.update(bytes);
    }
    for value in [
        manifest.generation.get(),
        boot_serial,
        root.root_epoch,
        root.root_incarnation,
        root.root_process,
        root.root_thread,
        subject.process,
        subject.thread,
    ] {
        hash.update(value.to_le_bytes());
    }
    Ok(hash.finalize().into())
}
fn wire_manifest(m: &ev_store::GenerationManifest) -> ev_diagnostics::system::Manifest {
    ev_diagnostics::system::Manifest {
        generation: m.generation.get(),
        cohort: m.cohort,
        supervisor_image: m.supervisor_image,
        abi: m.abi,
        health_contract: m.health_contract,
        health_version: m.health_version,
        required_checks: m.required_checks,
    }
}
fn wire_failure(f: ev_store::LastFailure) -> ev_diagnostics::system::Failure {
    use ev_store::LastFailureReason as Reason;
    ev_diagnostics::system::Failure {
        generation: f.generation.get(),
        boot_serial: f.boot_serial,
        attempts: f.attempts,
        reason: match f.reason {
            Reason::ProcessFault => 1,
            Reason::MissingProgress => 2,
            Reason::StorageFailure => 3,
            Reason::AttemptBudgetExhausted => 4,
            Reason::CriticalComponentFault => 5,
        },
        supervisor_image: f.supervisor_image,
        process_stamp: f.process_stamp,
        operation: f.operation.get(),
        sequence: f.sequence,
    }
}
/// Independently recompute the current admission from actual Kernel Root and
/// downloaded-subject identities; durable next selection is a separate input.
pub(crate) fn admission_join(
    context: &Context,
    serial: &[u8],
    build: &str,
    phase: Phase,
    selected_manifest: &ev_store::GenerationManifest,
    active_manifest: &ev_store::GenerationManifest,
    failure: Option<ev_store::LastFailure>,
) -> Result<Option<ev_store::AdmissionReport>> {
    current_health_manifest(selected_manifest)?;
    current_health_manifest(active_manifest)?;
    if !identities(context, serial, build, phase)? {
        return Err("System admission actual source identities absent".into());
    }
    let root = common_prefix(serial, build)?;
    let systems = snapshots(serial, build)?;
    let final_system = systems.last().ok_or("System final typed snapshot absent")?;
    let known_good = if phase == Phase::SelectB {
        None
    } else {
        Some(2)
    };
    if final_system.selected != Some(wire_manifest(selected_manifest))
        || final_system.known_good != known_good
        || final_system.last_failure != failure.map(wire_failure)
    {
        return Err(
            "System typed final selection/KnownGood/failure differs from actual disk".into(),
        );
    }
    let expected = match phase {
        Phase::SelectB | Phase::Recovery => None,
        _ => {
            let actions = crate::downloaded_protocol::records(serial, build, false)?;
            let subject = registered_subject(serial, build, &actions)?
                .ok_or("System admission needs one exact actual downloaded subject")?;
            let boot_serial = match phase {
                Phase::HealthyAndStageC => 1,
                Phase::FaultC => 2,
                Phase::FinalB => 3,
                _ => unreachable!(),
            };
            Some(ev_store::AdmissionReport {
                generation: active_manifest.generation,
                boot_serial,
                process_stamp: admission_stamp(&root, subject, active_manifest, boot_serial)?,
                cohort: active_manifest.cohort,
                supervisor_image: active_manifest.supervisor_image,
                abi: active_manifest.abi,
                health_contract: active_manifest.health_contract,
                health_version: active_manifest.health_version,
            })
        }
    };
    let mut admitted = false;
    let mut last_phase = 0;
    for system in &systems {
        if system.selected.is_some_and(|m| {
            m != wire_manifest(selected_manifest) && m != wire_manifest(active_manifest)
        }) {
            return Err(
                "System typed selected manifest differs from authenticated retained member".into(),
            );
        }
        match (system.current, expected) {
            (None, _) if !admitted => (),
            (Some(current), Some(actual))
                if current.manifest
                    == ev_root_supervisor::native_plan::system::manifest_digest(
                        active_manifest,
                    )
                    && current.generation == actual.generation.get()
                    && current.boot_serial == actual.boot_serial
                    && current.process_stamp == actual.process_stamp
                    && current.phase as u64 >= last_phase =>
            {
                admitted = true;
                last_phase = current.phase as u64;
            }
            _ => {
                return Err(
                    "System current admission changed or differs from actual Root/subject".into(),
                );
            }
        }
    }
    let wanted_phase = if phase == Phase::FaultC {
        HealthPhase::Failed
    } else {
        HealthPhase::Healthy
    };
    if expected.is_some() && final_system.current.is_none_or(|c| c.phase != wanted_phase) {
        return Err("System final actual admission health phase differs".into());
    }
    if phase == Phase::FaultC
        && failure.is_none_or(|f| {
            expected.is_none_or(|a| {
                f.process_stamp != Some(a.process_stamp) || f.boot_serial != a.boot_serial
            })
        })
    {
        return Err("System actual C admission and durable failure differ".into());
    }
    Ok(expected)
}
/// Gate one first-B cold UI finish using the same authenticated typed reports
/// and actual-admission join as the System workflow. GUI readiness is separate.
pub(crate) fn cold_b_ready(
    context: &Context,
    serial: &[u8],
    build: &str,
    disk: &storage::Disk,
) -> Result<bool> {
    let systems = snapshots(serial, build)?;
    if systems.last().is_none_or(|s| !healthy(s, 2)) {
        return Ok(false);
    }
    let bytes = disk.bytes()?;
    let Some(selected) = disk_check::selector::joined_known_good(&bytes, &context.packages()?, 2)?
    else {
        return Ok(false);
    };
    admission_join(
        context,
        serial,
        build,
        Phase::HealthyAndStageC,
        &selected,
        &selected,
        None,
    )?
    .ok_or("owner cold lacks exact current healthy admission")?;
    Ok(true)
}
fn healthy(s: &Snapshot, generation: u64) -> bool {
    s.current
        .is_some_and(|c| c.generation == generation && c.phase == HealthPhase::Healthy)
        && s.known_good == Some(generation)
}
fn selected(s: &Snapshot, generation: u64) -> bool {
    s.selected.is_some_and(|m| m.generation == generation)
}
fn reply(rows: &[crate::native_protocol::StateRecord], op: &str) -> Result<bool> {
    let rows: Vec<_> = rows
        .iter()
        .filter(|r| r.fields.get("op").is_some_and(|v| v == op))
        .collect();
    if rows.len() > 1 {
        return Err(format!("System command replay {op}"));
    }
    if let Some(row) = rows.first() {
        if !row.is(op) {
            return Err(format!("System command refused {op}"));
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
fn identities(context: &Context, serial: &[u8], build: &str, phase: Phase) -> Result<bool> {
    let mut common_row = None;
    let mut shell = None;
    for line in std::str::from_utf8(common::complete(serial))
        .map_err(|_| "System prefix UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if common_row.is_some()
                || c.mode != phase.mode_number()
                || c.root_image != context.images[0]
                || c.root_manifest != context.root_manifest
                || c.block_image != context.images[4]
                || c.root_frames != context.root_frames
                || c.block_frames != context.block_frames
            {
                return Err("System actual source/mode/Root/Block differs".into());
            }
            common_row = Some(c);
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let crate::native3_protocol::Event::Critical(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if phase == Phase::Recovery || shell.is_some() || c.image != context.images[1] {
                return Err("System actual Shell differs/replayed/in recovery".into());
            }
            shell = Some(c);
        }
    }
    Ok(common_row.is_some() && (phase == Phase::Recovery || shell.is_some()))
}
struct State {
    stage: u8,
    typed: usize,
    inputs: Vec<Value>,
    scanout: common::State,
    prompt: Option<u64>,
    finished: bool,
    app: Option<u64>,
    audits: Vec<Value>,
    published: bool,
    document: crate::document_update::Edit,
}
impl State {
    fn new() -> Self {
        Self {
            stage: 0,
            typed: 0,
            inputs: Vec::new(),
            scanout: common::State::new(common::Phase::Cold),
            prompt: None,
            finished: false,
            app: None,
            audits: Vec::new(),
            published: false,
            document: crate::document_update::Edit::new(),
        }
    }
    fn send(&mut self, input: &mut impl Write, bytes: &[u8], origin: Instant) -> Result<()> {
        input
            .write_all(bytes)
            .and_then(|()| input.flush())
            .map_err(|e| e.to_string())?;
        self.inputs.push(json!({"stage":self.stage,"elapsed_ms":origin.elapsed().as_millis(),
            "device":"owned QEMU UART","bytes_hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),
            "scripted_input":true,"human_consent_claim":false}));
        if bytes == b"finish\n" {
            self.finished = true;
            self.stage = 250;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // One exact actual App/frame/scanout state.
    fn view(
        &mut self,
        serial: &[u8],
        build: &str,
        qmp: &mut Qmp,
        dir: &Path,
        note: &[u8],
        focus: Focus,
        save: SaveState,
    ) -> Result<bool> {
        let Some(app) = self.app else {
            return Ok(false);
        };
        if let Some((s, _)) = self.scanout.view(
            serial,
            build,
            qmp,
            dir,
            Some(common::view(Build::B, focus, note, save)),
            Some(app),
        )? {
            self.scanout.min_frame = s.frame;
            return Ok(true);
        }
        Ok(false)
    }
}
/// This same-source workflow formatted its namespaces in the actual original
/// Standalone boot. Verify that retained creator cohort independently; keep the
/// current context for System admission, package and probe checks.
fn retain_namespace_creation(
    root: &Path,
    current_manifest: &Manifest,
    current: &Context,
    experiment: &Path,
    directory: &Path,
    document: bool,
) -> Result<NamespaceCreation> {
    let origin: Manifest = serde_json::from_slice(&common::bounded(
        &experiment.join("namespace-origin-manifest.json"),
        1024 * 1024,
    )?)
    .map_err(|e| format!("namespace origin manifest: {e}"))?;
    origin.validate_policy_rows()?;
    if origin.fixture.as_deref()
        != Some(if document {
            Mode::Standalone.document_fixture()
        } else {
            Mode::Standalone.fixture()
        })
        || origin.profile != current_manifest.profile
        || origin.source_sha256 != current_manifest.source_sha256
        || origin.source_revision != current_manifest.source_revision
        || origin.source_dirty != current_manifest.source_dirty
        || origin.source_inputs != current_manifest.source_inputs
    {
        return Err("namespace origin is not the exact same-source Standalone cohort".into());
    }
    let retained = storage::directory_beneath(directory, Path::new("namespace-origin"))?;
    let original = if document {
        Context::retain_document_mode(root, &origin, &retained, Mode::Standalone)?
    } else {
        Context::retain_mode(root, &origin, &retained, Mode::Standalone, false)?
    };
    NamespaceCreation::checked(&original.packages()?, &current.packages()?)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    phase: Phase,
    experiment: &Path,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    supervise_profile(
        command, serial, errors, timeout, build, directory, clock, root, manifest, phase,
        experiment, disk, false,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise_document(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    phase: Phase,
    experiment: &Path,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    supervise_profile(
        command, serial, errors, timeout, build, directory, clock, root, manifest, phase,
        experiment, disk, true,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise_profile(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    phase: Phase,
    experiment: &Path,
    disk: &storage::Disk,
    document: bool,
) -> Result<ExitStatus> {
    if timeout != Duration::from_secs(common::TIMEOUT_SECONDS) {
        return Err("System original600s cut required".into());
    }
    let (plan, bundle) = common::Plan::load(root, experiment, manifest)?;
    if bundle.document != document {
        return Err("System explicit package profile differs".into());
    }
    let context = if document {
        Context::retain_document_mode(root, manifest, directory, phase.mode())?
    } else {
        Context::retain_mode(root, manifest, directory, phase.mode(), false)?
    };
    let creation =
        retain_namespace_creation(root, manifest, &context, experiment, directory, document)?;
    common::absent_from_banks(&context, &bundle)?;
    let authority = if phase.offline() {
        None
    } else {
        Some(common::authority(root, &plan.authority_workspace)?)
    };
    let fixture = if let Some(initial) = phase.initial_release() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let release = download_fixture::sign_phase(
            root,
            &bundle,
            authority
                .as_ref()
                .ok_or("System initial B authority absent")?,
            initial,
            Author {
                version: initial.initial_metadata_version(),
                not_before: now.saturating_sub(5),
                expires: now.checked_add(595).ok_or("B expiry overflow")?,
            },
            &experiment.join("phase-b"),
        )?;
        // This is a fresh serving incarnation. Establish its real B state
        // before later publishing C; no guest reacquisition or floor reset.
        Some(Server::start(release)?)
    } else {
        None
    };
    let origin = Instant::now();
    let deadline = origin
        .checked_add(timeout)
        .ok_or("System host cut overflow")?;
    let mut state = State::new();
    let serial_path = serial;
    let mut qmp = None;
    let mut actual = None;
    let result = (|| {
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        if phase.offline() {
            clock.verify_and_start_acquisition_cold(&mut child.0, directory)?;
        } else {
            clock.verify_and_start(&mut child.0, directory)?;
        }
        qmp = Some(Qmp::connect_at(directory, deadline, origin)?);
        let qmp = qmp.as_mut().unwrap();
        let mut input = child.0.stdin.take().ok_or("System UART absent")?;
        loop {
            let bytes = common::bounded(serial, 1024 * 1024)?;
            let _ = common::bounded(errors, 1024 * 1024)?;
            let serial = common::complete(&bytes);
            if identities(&context, serial, build, phase)? && !state.finished {
                let systems = snapshots(serial, build)?;
                let rows = crate::native_protocol::states_network(serial, build)?;
                let actions = crate::downloaded_protocol::records(serial, build, false)?;
                state.app =
                    phase_subject(serial, build, phase, &bundle, &actions)?.map(|a| a.process);
                let stage = state.stage;
                match phase {
                    Phase::SelectB => match stage {
                        0 => {
                            state.send(&mut input, b"system init\n", origin)?;
                            state.stage = 1;
                        }
                        1 if reply(&rows, "system-init")?
                            && systems.iter().any(|s| {
                                selected(s, 2) && s.current.is_none() && s.known_good.is_none()
                            }) =>
                        {
                            state.send(&mut input, b"finish\n", origin)?;
                        }
                        _ => (),
                    },
                    Phase::HealthyAndStageC if document => match stage {
                        0 if systems.iter().any(|s| healthy(s, 2))
                            && state.app.is_some_and(|app| {
                                crate::session_io::ProbeUi::parse(serial, build)
                                    .is_ok_and(|ui| ui.note_complete(app, 1, 1).is_some())
                            })
                            && state.document.observer.closed(
                                serial,
                                build,
                                qmp,
                                state.app.unwrap(),
                            )? =>
                        {
                            qmp.set_running(false)?;
                            let audited = (|| {
                                disk.capture(experiment, "healthy-b-before-later-edit.raw")?;
                                let bytes = disk.bytes()?;
                                let before = common::bounded(
                                    &experiment.join("data-before.raw"),
                                    storage::DISK_BYTES as u64,
                                )?;
                                let b = common::bounded(&bundle.downloads[0].package, 262144)?;
                                let mut proof = disk_check::inspect(
                                    &before,
                                    &bytes,
                                    &context.packages()?,
                                    &creation,
                                    &[&b],
                                    disk_check::Expected {
                                        selected: 2,
                                        known_good: Some(2),
                                        active: 2,
                                        candidate: 2,
                                        failed_child: false,
                                        boot_serial: 1,
                                        saved: Saved {
                                            note: common::NOTE,
                                            note_counter: 1,
                                            value: 1001,
                                            data_counter: 0,
                                        },
                                    },
                                    false,
                                )?;
                                let admitted = admission_join(
                                    &context,
                                    serial,
                                    build,
                                    phase,
                                    &proof.selected,
                                    &proof.active,
                                    proof.failure,
                                )?;
                                disk_check::verify_probe(&mut proof, admitted)?;
                                crate::native3_disk::document(
                                    &bytes,
                                    0,
                                    ev_file::desktop::SEED_NOTES,
                                )?;
                                storage::json_new(
                                    &experiment.join("healthy-b-before-edit-audit.json"),
                                    &proof.proof,
                                )?;
                                Ok::<_, String>(proof.proof)
                            })();
                            qmp.set_running(true)?;
                            state.audits.push(audited?);
                            state.document.begin_after_closed(qmp)?;
                            state.stage = 1;
                        }
                        1 if state.document.tick(
                            serial,
                            build,
                            qmp,
                            state
                                .app
                                .ok_or("document healthy B actual process absent")?,
                            disk,
                            experiment,
                        )? =>
                        {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_err(|e| e.to_string())?
                                .as_secs();
                            let release = download_fixture::sign_phase(
                                root,
                                &bundle,
                                authority.as_ref().unwrap(),
                                FixturePhase::C,
                                Author {
                                    version: 2,
                                    not_before: now.saturating_sub(5),
                                    expires: now.checked_add(595).ok_or("C expiry overflow")?,
                                },
                                &experiment.join("phase-c"),
                            )?;
                            fixture.as_ref().unwrap().replace_phase(release)?;
                            state.published = true;
                            state.send(&mut input, b"update-fetch\n", origin)?;
                            state.stage = 4;
                        }
                        4 if reply(&rows, "update-fetch")? => {
                            state.send(&mut input, b"system stage\n", origin)?;
                            state.stage = 5;
                        }
                        5 if reply(&rows, "system-stage")? => {
                            state.send(&mut input, b"system activate\n", origin)?;
                            state.stage = 6;
                        }
                        6 if reply(&rows, "system-activate")?
                            && systems.iter().any(|s| selected(s, 3) && healthy(s, 2)) =>
                        {
                            state.send(&mut input, b"finish\n", origin)?;
                        }
                        _ => (),
                    },
                    Phase::HealthyAndStageC => match stage {
                        0 if systems.iter().any(|s| healthy(s, 2))
                            && state.view(
                                serial,
                                build,
                                qmp,
                                directory,
                                common::NOTE.as_bytes(),
                                Focus::Note,
                                SaveState::Saved,
                            )? =>
                        {
                            qmp.set_running(false)?;
                            let audited = (|| {
                                disk.capture(experiment, "healthy-b-before-later-edit.raw")?;
                                let bytes = disk.bytes()?;
                                let before = common::bounded(
                                    &experiment.join("data-before.raw"),
                                    storage::DISK_BYTES as u64,
                                )?;
                                let b = common::bounded(&bundle.downloads[0].package, 262144)?;
                                let mut proof = disk_check::inspect(
                                    &before,
                                    &bytes,
                                    &context.packages()?,
                                    &creation,
                                    &[&b],
                                    disk_check::Expected {
                                        selected: 2,
                                        known_good: Some(2),
                                        active: 2,
                                        candidate: 2,
                                        failed_child: false,
                                        boot_serial: 1,
                                        saved: Saved {
                                            note: common::NOTE,
                                            note_counter: 1,
                                            value: 1001,
                                            data_counter: 0,
                                        },
                                    },
                                    false,
                                )?;
                                let admitted = admission_join(
                                    &context,
                                    serial,
                                    build,
                                    phase,
                                    &proof.selected,
                                    &proof.active,
                                    proof.failure,
                                )?;
                                disk_check::verify_probe(&mut proof, admitted)?;
                                storage::json_new(
                                    &experiment.join("healthy-b-before-edit-audit.json"),
                                    &proof.proof,
                                )?;
                                Ok::<_, String>(proof.proof)
                            })();
                            qmp.set_running(true)?;
                            state.audits.push(audited?);
                            state.typed = common::NOTE.len();
                            qmp.ascii(LATER_NOTE.as_bytes()[state.typed])?;
                            state.typed += 1;
                            state.stage = 1;
                        }
                        1 if state.view(
                            serial,
                            build,
                            qmp,
                            directory,
                            &LATER_NOTE.as_bytes()[..state.typed],
                            Focus::Note,
                            SaveState::Unsaved,
                        )? =>
                        {
                            if state.typed < LATER_NOTE.len() {
                                qmp.ascii(LATER_NOTE.as_bytes()[state.typed])?;
                                state.typed += 1;
                            } else {
                                common::tap(qmp, Key::Tab)?;
                                state.stage = 2;
                            }
                        }
                        2 if state.view(
                            serial,
                            build,
                            qmp,
                            directory,
                            LATER_NOTE.as_bytes(),
                            Focus::Save,
                            SaveState::Unsaved,
                        )? =>
                        {
                            common::tap(qmp, Key::Enter)?;
                            state.stage = 3;
                        }
                        3 if state.view(
                            serial,
                            build,
                            qmp,
                            directory,
                            LATER_NOTE.as_bytes(),
                            Focus::Save,
                            SaveState::Saved,
                        )? =>
                        {
                            let ui = crate::session_io::ProbeUi::parse(serial, build)?;
                            if ui.note_complete(state.app.unwrap(), 2, 2).is_some() {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map_err(|e| e.to_string())?
                                    .as_secs();
                                let release = download_fixture::sign_phase(
                                    root,
                                    &bundle,
                                    authority.as_ref().unwrap(),
                                    FixturePhase::C,
                                    Author {
                                        version: 2,
                                        not_before: now.saturating_sub(5),
                                        expires: now.checked_add(595).ok_or("C expiry overflow")?,
                                    },
                                    &experiment.join("phase-c"),
                                )?;
                                fixture.as_ref().unwrap().replace_phase(release)?;
                                state.published = true;
                                state.send(&mut input, b"update-fetch\n", origin)?;
                                state.stage = 4;
                            }
                        }
                        4 if reply(&rows, "update-fetch")? => {
                            state.send(&mut input, b"system stage\n", origin)?;
                            state.stage = 5;
                        }
                        5 if reply(&rows, "system-stage")? => {
                            state.send(&mut input, b"system activate\n", origin)?;
                            state.stage = 6;
                        }
                        6 if reply(&rows, "system-activate")?
                            && systems.iter().any(|s| selected(s, 3) && healthy(s, 2)) =>
                        {
                            state.send(&mut input, b"finish\n", origin)?;
                        }
                        _ => (),
                    },
                    Phase::FaultC => {
                        if systems.iter().any(|s| {
                            selected(s, 2)
                                && s.known_good == Some(2)
                                && s.current.is_some_and(|c| {
                                    c.generation == 3 && c.phase == HealthPhase::Failed
                                })
                                && s.last_failure
                                    .is_some_and(|f| f.generation == 3 && f.reason == 5)
                        }) {
                            state.send(&mut input, b"finish\n", origin)?;
                        }
                    }
                    Phase::Recovery => {
                        if state.stage == 0
                            && systems.iter().any(|s| {
                                selected(s, 2) && s.known_good == Some(2) && s.current.is_none()
                            })
                        {
                            state.send(&mut input, b"recover good\n", origin)?;
                            state.stage = 1;
                        }
                        for event in crate::native3_diagnostics::owners(serial, build)? {
                            if event.prompt.phase == OwnerPhase::Armed
                                && state.prompt != Some(event.prompt.prompt_serial)
                            {
                                if state.stage != 1 || event.prompt.action != Action::RecoverGood {
                                    return Err("System unexpected owner confirmation".into());
                                }
                                state.prompt = Some(event.prompt.prompt_serial);
                                let mut line = b"approve ".to_vec();
                                line.extend_from_slice(&event.prompt.token);
                                line.push(b'\n');
                                state.send(&mut input, &line, origin)?;
                                state.stage = 2;
                            }
                            if event.prompt.phase == OwnerPhase::Completed
                                && state.prompt == Some(event.prompt.prompt_serial)
                                && state.stage == 2
                            {
                                state.send(&mut input, b"finish\n", origin)?;
                            }
                        }
                    }
                    Phase::FinalB if document => {
                        let app = state.app;
                        match stage {
                            0 if systems.iter().any(|s| selected(s, 2) && healthy(s, 2))
                                && app.is_some_and(|app| {
                                    crate::session_io::ProbeUi::parse(serial, build)
                                        .is_ok_and(|ui| ui.note_complete(app, 1, 1).is_some())
                                })
                                && state.document.observer.closed(
                                    serial,
                                    build,
                                    qmp,
                                    app.unwrap(),
                                )? =>
                            {
                                common::tap(qmp, Key::Enter)?;
                                state.stage = 1;
                            }
                            1 if state.document.observer.observe(
                                serial,
                                build,
                                qmp,
                                app.ok_or("document final B process absent")?,
                                ev_graphics::shell::Screen::Picker {
                                    selected: ev_graphics::shell::FileChoice::Notes,
                                },
                                |_| true,
                            )? =>
                            {
                                common::tap(qmp, Key::Enter)?;
                                state.stage = 2;
                            }
                            2 if state.document.observer.observe(
                                serial,
                                build,
                                qmp,
                                app.ok_or("document final B process absent")?,
                                ev_graphics::shell::Screen::AppRunning,
                                |v| {
                                    v.state == ev_userspace_contract::document::State::Saved
                                        && v.choice
                                            == ev_userspace_contract::document::Choice::Notes
                                        && v.access == ev_userspace_contract::document::Access::Edit
                                        && v.revision == 1
                                        && v.text.as_bytes()
                                            == crate::document_update::LATER_DOCUMENT
                                },
                            )? =>
                            {
                                let proof = crate::native3_disk::document(
                                    &disk.bytes()?,
                                    1,
                                    crate::document_update::LATER_DOCUMENT,
                                )?;
                                storage::json_new(
                                    &experiment.join("offline-recovered-document-audit.json"),
                                    &proof,
                                )?;
                                state.send(&mut input, b"finish\n", origin)?;
                            }
                            _ => (),
                        }
                    }
                    Phase::FinalB => {
                        if systems.iter().any(|s| selected(s, 2) && healthy(s, 2))
                            && state.view(
                                serial,
                                build,
                                qmp,
                                directory,
                                LATER_NOTE.as_bytes(),
                                Focus::Note,
                                SaveState::Saved,
                            )?
                        {
                            let ui = crate::session_io::ProbeUi::parse(serial, build)?;
                            if ui.note_complete(state.app.unwrap(), 1, 1).is_some() {
                                state.send(&mut input, b"finish\n", origin)?;
                            }
                        }
                    }
                }
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                // Exit may occur after the loop's read or after sending finish.
                // Only a post-exit read can attest the complete retirement tail.
                let bytes = common::bounded(serial_path, 1024 * 1024)?;
                let _ = common::bounded(errors, 1024 * 1024)?;
                actual = Some(finished(
                    &context,
                    &bytes,
                    build,
                    status,
                    phase,
                    &bundle,
                    &state,
                    fixture.as_ref(),
                    experiment,
                    directory,
                    document,
                )?);
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!("System original600s bound stage{}", state.stage));
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    storage::json_new(
        &directory.join("system-health-qmp.json"),
        &json!({"transcript":qmp.as_ref().map(Qmp::transcript),"offline_precont_link_down":phase.offline()}),
    )?;
    let fixture_record = fixture.as_ref().map(Server::snapshot).transpose();
    storage::json_new(
        &directory.join("system-health-observer.json"),
        &json!({"schema":1,"phase":phase,"passed":result.is_ok(),
        "error":result.as_ref().err(),"stage":state.stage,"inputs":state.inputs,"captures":state.scanout.captures,
        "audits":state.audits,"document_captures":state.document.observer.captures,"document_profile":document,"fixture":fixture_record.as_ref().ok(),"actual":actual,"scripted_input":true,"human_consent_claim":false,
        "complete_guest_retirement_claim":result.is_ok(),"whole_M6_acceptance":false}),
    )?;
    result
}
#[allow(clippy::too_many_arguments)]
fn finished(
    context: &Context,
    serial: &[u8],
    build: &str,
    status: ExitStatus,
    phase: Phase,
    bundle: &download_fixture::Bundle,
    state: &State,
    fixture: Option<&Server>,
    experiment: &Path,
    directory: &Path,
    document: bool,
) -> Result<Value> {
    if !state.finished
        || status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS)
        || serial.last() != Some(&b'\n')
        || !identities(context, serial, build, phase)?
    {
        return Err("System missing exact finish/source/retirement".into());
    }
    let retention = if phase == Phase::Recovery {
        crate::session_protocol::retention_network_recovery(serial, build)?
    } else {
        crate::session_protocol::retention(serial, build)?
    };
    if retention.omitted != 0 {
        return Err("System trace incomplete".into());
    }
    let document_serial;
    let serial = if document {
        document_serial = crate::document_io::without_observations(serial, build)?;
        document_serial.as_slice()
    } else {
        serial
    };
    let protocol = crate::session_protocol::without_network_diagnostics(serial, build)?;
    if phase == Phase::Recovery {
        crate::boot_protocol::check_network_recovery(&protocol, build, status.code())?;
    } else {
        crate::boot_protocol::check_network(&protocol, build, status.code())?;
    }
    let native = if phase == Phase::Recovery {
        crate::native3_protocol::record_network_recovery(serial, build)?
    } else {
        crate::native_protocol::record_network(serial, build)?
    };
    let faults = if phase == Phase::FaultC { 1 } else { 0 };
    if native.counts["faults"] != faults
        || native.counts["restarts"] != 0
        || native.counts["grants"]
            != if document {
                match phase {
                    Phase::HealthyAndStageC => 2,
                    Phase::FinalB => 1,
                    _ => 0,
                }
            } else {
                0
            }
        || native.counts["readonly_rejections"] != 0
        || native.counts["app_a_starts"] != 0
        || native.counts["app_b_starts"] != 0
        || !native.actions.is_empty()
    {
        return Err("System actor/fault/grant accounting differs".into());
    }
    let expected_starts = match phase {
        Phase::Recovery => 2,
        Phase::SelectB => 8,
        _ => 9,
    };
    if native.counts["starts"] != expected_starts
        || native.counts["processes"] != expected_starts
        || native.counts["calls"] == 0
        || native.counts["calls"] != native.counts["replies"]
    {
        return Err("System actual graph/matched RPC differs".into());
    }
    let expected_actions = if matches!(phase, Phase::Recovery | Phase::SelectB) {
        0
    } else {
        3
    };
    if native.downloaded_actions.len() != expected_actions {
        return Err("System downloaded lifetime count differs".into());
    }
    let subject = phase_subject(serial, build, phase, bundle, &native.downloaded_actions)?;
    for (action, kind) in native
        .downloaded_actions
        .iter()
        .zip(["start", "stop", "reap"])
    {
        if action.kind != kind
            || Some(action.process) != state.app
            || subject.is_none_or(|s| action.slot != s.slot)
        {
            return Err("System actual downloaded lifetime identity differs".into());
        }
    }
    let profiles =
        crate::native_profile::finished_network(serial, build, faults, Some(phase.mode_number()))?;
    let ui = crate::session_io::ProbeUi::parse(serial, build)?.finish()?;
    let systems = snapshots(serial, build)?;
    if systems.is_empty() {
        return Err("System actual typed snapshots absent".into());
    }
    let proofs = crate::time_proof_protocol::records(serial, build)?;
    let time = crate::time_protocol::records(serial, build)?;
    if !crate::tc_protocol::records(serial, build)?.is_empty() {
        return Err("System observed an unsolicited explicit time-check".into());
    }
    if phase.offline() && !proofs.is_empty() {
        return Err("System offline boot attempted fresh remote time".into());
    }
    if phase == Phase::HealthyAndStageC {
        if !state.published {
            return Err("System C never published".into());
        }
        let lengths = common::validate_fixture(
            &fixture.ok_or("System C server absent")?.actual_snapshot()?,
            &experiment.join("phase-c"),
        )?;
        if proofs.len() != 4
            || proofs
                .iter()
                .zip([(1, 1), (2, lengths[0] as u64), (3, 11), (1, 2)])
                .any(|(p, (stage, arg))| p.stage != stage || p.result != 0 || p.argument != arg)
            || time
                .first()
                .is_none_or(|p| p.stage != 1 || p.result != 0 || p.elapsed_seconds != 0)
            || !time.iter().any(|p| p.stage == 2 && p.elapsed_seconds > 0)
            || time.iter().any(|p| p.stage == 3 || p.result != 0)
        {
            return Err("System C lacks actual private proof/healthy elapsed source phases".into());
        }
    }
    let owner_expected = if phase == Phase::Recovery {
        vec![crate::native3_diagnostics::OwnerExpected {
            action: Action::RecoverGood,
            outcome: OwnerPhase::Completed,
        }]
    } else {
        Vec::new()
    };
    let owner =
        crate::native3_diagnostics::retain_owners(serial, build, &owner_expected, directory)?;
    if phase != Phase::Recovery {
        let network = crate::network_protocol::records(serial, build)?;
        if network
            .last()
            .is_none_or(|r| r.stage != 7 || r.result != 0 || r.argument != 2)
        {
            return Err("System lacks actual cooperative NIC Stop/scrub".into());
        }
    } else if !crate::network_protocol::records(serial, build)?.is_empty() {
        return Err("System recovery unexpectedly started networking".into());
    }
    Ok(
        json!({"native":native,"profiles":profiles,"ui":ui,"snapshots_checked":systems.len(),"retention":retention,
        "owner":owner,"time_proof":proofs,"elapsed_source":time,
        "complete_Kernel_retirement":true,"actual_downloaded_faults":faults}),
    )
}

/// Join the durable bounded summary to the actual Kernel capture and actual
/// downloaded lifetime. A digest alone does not establish that origin.
pub(crate) fn fault_summary_join(path: &Path, build: &str, summary: &[u8; 256]) -> Result<()> {
    let serial = common::bounded(path, 1024 * 1024)?;
    let mut faults = Vec::new();
    let mut common_row = None;
    for (at, line) in std::str::from_utf8(&serial)
        .map_err(|_| "System fault serial UTF8")?
        .lines()
        .enumerate()
    {
        if line.starts_with("EVROSION_NATIVE_FAULT ") {
            let crate::native_diagnostics::Event::Fault(f) =
                crate::native_diagnostics::parse(line, build, at)?
            else {
                unreachable!()
            };
            faults.push(f);
        }
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if common_row.replace(c).is_some() {
                return Err("System fault duplicate actual Root".into());
            }
        }
    }
    if faults.len() != 1 {
        return Err("System needs one actual complete Kernel child fault".into());
    }
    let fault = &faults[0];
    let root = common_row.ok_or("System fault actual Root absent")?;
    if !matches_fault(summary, fault, root.root_epoch, root.root_incarnation) {
        return Err("System durable summary differs from actual Kernel fault facts".into());
    }
    let actions = crate::downloaded_protocol::records(&serial, build, true)?;
    let subject = registered_subject(&serial, build, &actions)?;
    if actions.len() != 3
        || subject.is_none_or(|a| {
            a.process != fault.words[1]
                || a.thread != fault.words[2]
                || a.job != fault.words[0]
                || digest(&a.elf_sha256).ok() != Some(fault.image)
        })
    {
        return Err("System durable fault is not the actual downloaded C incarnation".into());
    }
    Ok(())
}

fn matches_fault(
    summary: &[u8; 256],
    fault: &crate::native_diagnostics::Fault,
    epoch: u64,
    incarnation: u64,
) -> bool {
    let word = |at| u64::from_le_bytes(summary[at..at + 8].try_into().unwrap());
    fault.actor == 5
        && fault.epoch == epoch
        && fault.incarnation == incarnation
        && fault.image == summary[96..128]
        && [128, 136, 152, 160, 168, 176]
            .into_iter()
            .zip(1..=6)
            .all(|(at, index)| word(at) == fault.words[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn admission_fixture() -> (
        Context,
        String,
        String,
        ev_store::GenerationManifest,
        Snapshot,
    ) {
        let build = "aa".repeat(32);
        let manifest = ev_store::GenerationManifest {
            generation: ev_store::GenerationId::new(2).unwrap(),
            cohort: [0x11; 32],
            supervisor_image: [0x22; 32],
            abi: ev_userspace_contract::root_v4::ABI,
            health_contract: Sha256::digest(
                ev_root_supervisor::downloaded_health::HEALTH_DESCRIPTION,
            )
            .into(),
            health_version: 2,
            required_checks: 3,
        };
        let context = Context {
            images: core::array::from_fn(|i| match i {
                0 => "22".repeat(32),
                1 => "88".repeat(32),
                4 => "99".repeat(32),
                _ => "ab".repeat(32),
            }),
            root_manifest: "55".repeat(32),
            root_frames: 40,
            block_frames: 20,
            package_pages: [1, 1],
            banks: None,
        };
        let prefix = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode=1 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20\nEVROSION_M5_NATIVE_CRITICAL_READY protocol=1 build={build} process=21 thread=121 image_sha256={} tick=10\nEVROSION_M6_IMAGE protocol=1 build={build} op=6 slot=1 phase=4 status=0 reason=0 process=20 thread=120 job=3 tick=9 original_cut=10000 external_frames=2 root_cr3=4096 table=8192 control=12288 declared_bytes=4096 pages=1 verified_bytes=4096 elf_sha256={} content_sha256={} declared_package_id={} returned_memory_capability=0\nEVROSION_M6_DOWNLOADED_ACTION protocol=1 build={build} action=start slot=1 process=30 thread=130 job=7 elf_sha256={} content_sha256={} declared_package_id={}\n",
            context.images[0],
            context.root_manifest,
            context.images[4],
            context.images[1],
            "66".repeat(32),
            "77".repeat(32),
            "77".repeat(32),
            "66".repeat(32),
            "77".repeat(32),
            "77".repeat(32)
        );
        let mut snapshot = Snapshot::new(ev_diagnostics::system::State::Committed, 10, 20);
        snapshot.selected = Some(wire_manifest(&manifest));
        snapshot.known_good = Some(2);
        snapshot.current = Some(ev_diagnostics::system::Admission {
            manifest: ev_root_supervisor::native_plan::system::manifest_digest(&manifest),
            generation: 2,
            boot_serial: 1,
            process_stamp: digest(
                "cc1ce1f74242b8fbc31dbffa50e67a0e575f77f7aa8ad005f816184f9749b04f",
            )
            .unwrap(),
            phase: HealthPhase::Healthy,
        });
        (context, build, prefix, manifest, snapshot)
    }
    fn report(build: &str, s: Snapshot, n: u32, process: u64) -> String {
        format!(
            "EVROSION_NATIVE_SYSTEM protocol=1 build={build} report={n} root_process={process} root_thread=120 bytes={}\n",
            s.encode()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
    fn subject_bundle() -> (std::path::PathBuf, download_fixture::Bundle) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = crate::build::unique_directory(&root.join("build/test-tmp"), "subject-slot-test")
            .unwrap();
        let component = |label: &str| {
            let image = dir.join(format!("{label}.elf"));
            std::fs::write(&image, format!("bounded {label} ELF identity model")).unwrap();
            download_fixture::Component {
                label: label.into(),
                feature: label.into(),
                image_sha256: Sha256::digest(std::fs::read(&image).unwrap()).into(),
                unstripped_sha256: [1; 32],
                image,
                unstripped: dir.join(format!("{label}.unstripped")),
                descriptor: [2; 32],
                image_pages: 1,
                private_frames: 7,
                stack_report: dir.join(format!("{label}.stack")),
            }
        };
        let download = |label: &str| {
            let package = dir.join(format!("{label}.zion"));
            std::fs::write(&package, format!("bounded {label} package identity model")).unwrap();
            let hash: [u8; 32] = Sha256::digest(std::fs::read(&package).unwrap()).into();
            download_fixture::Download {
                component: component(label),
                package,
                package_sha256: hash,
                package_id: hash,
                build: [3; 32],
                app: [4; 16],
            }
        };
        let bundle = download_fixture::Bundle {
            schema: 1,
            document: false,
            purpose: "bounded identity/slot model; not release authentication".into(),
            source_sha256: "ab".repeat(32),
            compiled_into_kernel: false,
            references: [component("reference-a"), component("reference-b")],
            downloads: [download("downloaded-b"), download("downloaded-c")],
        };
        (dir, bundle)
    }
    #[test]
    fn cold_c_slot1_and_final_b_slot2_bind_phase_artifacts_and_exact_registered_lifetimes() {
        let (dir, bundle) = subject_bundle();
        let (_, build, prefix, _, _) = admission_fixture();
        for (phase, slot, index) in [(Phase::FaultC, 1, 1), (Phase::FinalB, 2, 0)] {
            let d = &bundle.downloads[index];
            let elf = common::hash(&std::fs::read(&d.component.image).unwrap());
            let package = common::hash(&std::fs::read(&d.package).unwrap());
            let prefix = prefix
                .replace("slot=1", &format!("slot={slot}"))
                .replace(&"66".repeat(32), &elf)
                .replace(&"77".repeat(32), &package);
            let start = prefix.lines().last().unwrap();
            let serial = format!(
                "{prefix}{}\n{}\n",
                start.replace("action=start", "action=stop"),
                start.replace("action=start", "action=reap")
            );
            let actions =
                crate::downloaded_protocol::records(serial.as_bytes(), &build, true).unwrap();
            let subject = phase_subject(serial.as_bytes(), &build, phase, &bundle, &actions)
                .unwrap()
                .unwrap();
            assert_eq!(
                (subject.slot, subject.process, subject.thread, subject.job),
                (slot, 30, 130, 7)
            );
            let wrong_phase = if phase == Phase::FaultC {
                Phase::FinalB
            } else {
                Phase::FaultC
            };
            assert!(
                phase_subject(serial.as_bytes(), &build, wrong_phase, &bundle, &actions).is_err()
            );
            for no_app in [Phase::SelectB, Phase::Recovery] {
                assert!(
                    phase_subject(serial.as_bytes(), &build, no_app, &bundle, &actions).is_err()
                );
            }
            for bad in [
                serial.replace(
                    &format!("action=start slot={slot}"),
                    &format!("action=start slot={}", 3 - slot),
                ),
                serial.replace("action=stop slot=", "action=reap slot="),
                serial.replace(
                    &format!("action=stop slot={slot} process=30"),
                    &format!("action=stop slot={slot} process=31"),
                ),
                serial.replacen("thread=130 job=7", "thread=131 job=7", 1),
                serial.replacen("thread=130 job=7", "thread=130 job=8", 1),
                serial.replace(
                    "reason=0 process=20 thread=120",
                    "reason=0 process=21 thread=120",
                ),
                serial.replace(
                    &format!("elf_sha256={elf}"),
                    &format!("elf_sha256={}", "44".repeat(32)),
                ),
                serial.replace(
                    &format!("content_sha256={package}"),
                    &format!("content_sha256={}", "44".repeat(32)),
                ),
                serial.replace(
                    &format!("declared_package_id={package}"),
                    &format!("declared_package_id={}", "44".repeat(32)),
                ),
            ] {
                let checked = crate::downloaded_protocol::records(bad.as_bytes(), &build, true)
                    .and_then(|actions| {
                        phase_subject(bad.as_bytes(), &build, phase, &bundle, &actions).map(|_| ())
                    });
                assert!(checked.is_err());
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn actual_registered_slot_is_independent_of_c_admission_serial_and_final_b_serial() {
        let (context, build, prefix, selected, mut snapshot) = admission_fixture();
        for (phase, slot, generation, boot_serial) in
            [(Phase::FaultC, 1, 3, 2), (Phase::FinalB, 2, 2, 3)]
        {
            let prefix = prefix.replace("slot=1", &format!("slot={slot}"));
            let actions =
                crate::downloaded_protocol::records(prefix.as_bytes(), &build, false).unwrap();
            let subject = registered_subject(prefix.as_bytes(), &build, &actions)
                .unwrap()
                .unwrap();
            let mut active = selected;
            active.generation = ev_store::GenerationId::new(generation).unwrap();
            let root = common_prefix(prefix.as_bytes(), &build).unwrap();
            let stamp = admission_stamp(&root, subject, &active, boot_serial).unwrap();
            let failure = (phase == Phase::FaultC).then_some(ev_store::LastFailure {
                generation: active.generation,
                boot_serial,
                attempts: 1,
                reason: ev_store::LastFailureReason::CriticalComponentFault,
                evidence: None,
                supervisor_image: active.supervisor_image,
                process_stamp: Some(stamp),
                operation: ev_store::OperationId::new(1).unwrap(),
                sequence: 1,
            });
            snapshot.current = Some(ev_diagnostics::system::Admission {
                manifest: ev_root_supervisor::native_plan::system::manifest_digest(&active),
                generation,
                boot_serial,
                process_stamp: stamp,
                phase: if phase == Phase::FaultC {
                    HealthPhase::Failed
                } else {
                    HealthPhase::Healthy
                },
            });
            snapshot.last_failure = failure.map(wire_failure);
            let serial = prefix + &report(&build, snapshot, 1, 20);
            assert!(
                admission_join(
                    &context,
                    serial.as_bytes(),
                    &build,
                    phase,
                    &selected,
                    &active,
                    failure
                )
                .unwrap()
                .is_some()
            );
            let bad = serial.replace(
                &format!("action=start slot={slot}"),
                &format!("action=start slot={}", 3 - slot),
            );
            assert!(
                admission_join(
                    &context,
                    bad.as_bytes(),
                    &build,
                    phase,
                    &selected,
                    &active,
                    failure
                )
                .is_err()
            );
        }
    }
    #[test]
    fn healthy_admission_binds_actual_subject_root_manifest_serial_and_all_stamp_fields() {
        let (context, build, prefix, manifest, snapshot) = admission_fixture();
        let check = |prefix: &str, s| {
            admission_join(
                &context,
                (prefix.to_owned() + &report(&build, s, 1, 20)).as_bytes(),
                &build,
                Phase::HealthyAndStageC,
                &manifest,
                &manifest,
                None,
            )
        };
        assert!(check(&prefix, snapshot).unwrap().is_some());
        for change in 0..4 {
            let mut bad = snapshot;
            let current = bad.current.as_mut().unwrap();
            match change {
                0 => current.process_stamp[0] ^= 1,
                1 => current.manifest[0] ^= 1,
                2 => current.boot_serial = 2,
                _ => current.generation = 3,
            };
            assert!(check(&prefix, bad).is_err());
        }
        for bad in [
            prefix.replace("root_epoch=4", "root_epoch=5"),
            prefix.replace("root_incarnation=2", "root_incarnation=3"),
            prefix.replace("process=30 thread=130", "process=31 thread=130"),
        ] {
            assert!(check(&bad, snapshot).is_err());
        }
        let mut next = manifest;
        next.generation = ev_store::GenerationId::new(3).unwrap();
        next.cohort = [0x12; 32];
        let mut selected_next = snapshot;
        selected_next.selected = Some(wire_manifest(&next));
        assert!(
            admission_join(
                &context,
                (prefix + &report(&build, selected_next, 1, 20)).as_bytes(),
                &build,
                Phase::HealthyAndStageC,
                &next,
                &manifest,
                None
            )
            .is_ok()
        );
    }
    #[test]
    fn downloaded_health_v2_refuses_old_or_foreign_semantics_before_admission_join() {
        let (context, build, prefix, manifest, snapshot) = admission_fixture();
        let serial = prefix + &report(&build, snapshot, 1, 20);
        assert!(current_health_manifest(&manifest).is_ok());
        for field in 0..5 {
            let mut bad = manifest;
            match field {
                0 => bad.health_version = 1,
                1 => bad.health_version = 3,
                2 => bad.health_contract[0] ^= 1,
                3 => bad.abi[0] ^= 1,
                _ => {
                    bad.health_version = 1;
                    bad.health_contract = [0x44; 32];
                }
            }
            assert!(current_health_manifest(&bad).is_err());
            for selected in [true, false] {
                assert!(
                    admission_join(
                        &context,
                        serial.as_bytes(),
                        &build,
                        Phase::HealthyAndStageC,
                        if selected { &bad } else { &manifest },
                        if selected { &manifest } else { &bad },
                        None
                    )
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn typed_system_report_rejects_wrong_root_origin_gap_and_replay() {
        let (_, build, prefix, _, snapshot) = admission_fixture();
        assert!(
            snapshots(
                (prefix.clone() + &report(&build, snapshot, 1, 21)).as_bytes(),
                &build
            )
            .is_err()
        );
        assert!(
            snapshots(
                (prefix.clone() + &report(&build, snapshot, 2, 20)).as_bytes(),
                &build
            )
            .is_err()
        );
        let good = prefix + &report(&build, snapshot, 1, 20);
        assert!(snapshots((good + &report(&build, snapshot, 1, 20)).as_bytes(), &build).is_err());
    }
    #[test]
    fn fault_summary_must_match_actual_incarnation_and_every_preserved_core_fact() {
        let mut words = [0; 24];
        words[..7].copy_from_slice(&[7, 31, 41, 0, 9, 0x1234, 0]);
        let fault = crate::native_diagnostics::Fault {
            actor: 5,
            image: [0x42; 32],
            epoch: 4,
            incarnation: 2,
            words,
            at: 0,
        };
        let mut bytes = [0; 256];
        bytes[96..128].fill(0x42);
        for (at, index) in [128, 136, 152, 160, 168, 176].into_iter().zip(1..=6) {
            bytes[at..at + 8].copy_from_slice(&words[index].to_le_bytes());
        }
        assert!(matches_fault(&bytes, &fault, 4, 2)); // actual vector0/nullRIP remain representable
        for at in [96, 128, 136, 152, 160, 168, 176] {
            let mut bad = bytes;
            bad[at] ^= 1;
            assert!(!matches_fault(&bad, &fault, 4, 2));
        }
        assert!(!matches_fault(&bytes, &fault, 5, 2));
        assert!(!matches_fault(&bytes, &fault, 4, 3));

        // Exercise the complete join too: Register belongs to Root20/120,
        // while the separate faulted App31/41/Job7 occupies physical slot1.
        let (_, build, prefix, _, _) = admission_fixture();
        let prefix = prefix
            .replace(&"66".repeat(32), &"42".repeat(32))
            .replace("process=30 thread=130", "process=31 thread=41");
        let start = prefix.lines().last().unwrap();
        let serial = format!(
            "{prefix}EVROSION_NATIVE_FAULT protocol=1 build={build} actor=5 image_sha256={} root_epoch=4 root_incarnation=2 words={}\n{}\n{}\n",
            "42".repeat(32),
            words
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            start.replace("action=start", "action=stop"),
            start.replace("action=start", "action=reap")
        );
        let dir = crate::build::unique_directory(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/test-tmp"),
            "fault-slot-test",
        )
        .unwrap();
        let path = dir.join("serial.log");
        std::fs::write(&path, &serial).unwrap();
        assert!(fault_summary_join(&path, &build, &bytes).is_ok());
        for bad in [
            serial.replace("action=stop slot=1", "action=stop slot=2"),
            serial.replace("thread=41 job=7", "thread=41 job=8"),
            serial.replace(
                "reason=0 process=20 thread=120",
                "reason=0 process=21 thread=120",
            ),
            serial.replace("actor=5 image_sha256=42", "actor=5 image_sha256=43"),
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(fault_summary_join(&path, &build, &bytes).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn offline_and_mode_selection_are_explicit_and_cannot_fall_back_to_standalone() {
        for phase in [
            Phase::SelectB,
            Phase::HealthyAndStageC,
            Phase::FaultC,
            Phase::Recovery,
            Phase::FinalB,
        ] {
            assert_eq!(Mode::from_fixture(phase.fixture()), Some(phase.mode()));
            assert_eq!(phase.offline(), phase != Phase::HealthyAndStageC);
            assert_eq!(
                phase.initial_release(),
                if phase == Phase::HealthyAndStageC {
                    Some(FixturePhase::B)
                } else {
                    None
                }
            );
            assert_eq!(
                phase
                    .initial_release()
                    .map(FixturePhase::initial_metadata_version),
                (phase == Phase::HealthyAndStageC).then_some(1)
            );
        }
        assert_eq!(Phase::FaultC.mode(), Mode::SystemManaged);
        assert_eq!(Phase::Recovery.mode(), Mode::Recovery);
    }

    #[test]
    fn system_health_command_preserves_explicit_signer_and_rejects_ambiguous_options() {
        use crate::cli::{Cli, parse};
        let parsed = |words: &[&str]| parse(words.iter().map(std::ffi::OsString::from));
        assert_eq!(
            parsed(&[
                "test",
                "system-health",
                "--authority-root",
                "/owned/signing workspace"
            ])
            .unwrap(),
            Cli::SystemHealth(crate::cli::AcquisitionOptions {
                authority_root: Some("/owned/signing workspace".into())
            })
        );
        for words in [
            vec!["test", "system-health", "--authority-root"],
            vec!["test", "system-health", "--authority-root", ""],
            vec![
                "test",
                "system-health",
                "--authority-root",
                "a",
                "--authority-root",
                "b",
            ],
            vec!["test", "system-health", "--disk", "/personal/disk"],
        ] {
            assert!(parsed(&words).is_err());
        }
    }
}
