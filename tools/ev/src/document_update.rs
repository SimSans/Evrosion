//! Signed downloaded native document update qualification. Host stimuli and
//! references join actual protected input/Present observations with original
//! scanout and independently opened Store bytes; none grants authority.
use crate::{
    build::{self, Result},
    qmp::{Key, Qmp},
    storage,
};
use ev_graphics::shell::{FileChoice, Screen};
use ev_userspace_contract::document::{Access, Choice, Focus, Snapshot, State};
use serde_json::{Value, json};
use std::{fs, path::Path};
pub(crate) const LATER_DOCUMENT: &[u8] = b"M7_keep03_later";

pub(crate) struct Observer {
    nonce: u32,
    capture: u32,
    shell_frame: u64,
    pub(crate) captures: Vec<Value>,
}
impl Observer {
    pub(crate) fn new() -> Self {
        Self {
            nonce: 0,
            capture: 100,
            shell_frame: 0,
            captures: Vec::new(),
        }
    }
    /// A matching named state and actual protected surface precede original
    /// full-scanout validation. The caller supplies the expected process/state.
    pub(crate) fn observe(
        &mut self,
        serial: &[u8],
        build: &str,
        qmp: &mut Qmp,
        process: u64,
        screen: Screen,
        accept: impl Fn(&Snapshot) -> bool,
    ) -> Result<bool> {
        use crate::desktop_protocol::{self, Producer, StepKind};
        let observed = crate::document_io::records(serial, build)?;
        let latest = observed.last();
        if screen == Screen::AppRunning
            && latest
                .is_none_or(|o| o.process != process || o.nonce <= self.nonce || !accept(&o.view))
        {
            return Ok(false);
        }
        let ui = crate::session_io::ProbeUi::parse(serial, build)?;
        let text = std::str::from_utf8(crate::acquisition_io::complete(serial))
            .map_err(|_| "document update UTF8")?;
        let steps = text
            .lines()
            .enumerate()
            .filter(|(_, l)| l.starts_with("EVROSION_M4_DESKTOP_STEP "))
            .map(|(line, l)| desktop_protocol::step_line(l, build).map(|s| (line, s)))
            .collect::<Result<Vec<_>>>()?;
        let producer = if screen == Screen::AppRunning {
            Producer::App
        } else {
            Producer::Shell
        };
        let picker = matches!(screen, Screen::Picker { .. });
        let Some((line, step)) = steps.iter().rev().find(|(_, s)| {
            s.producer == producer
                && s.kind
                    == if picker {
                        StepKind::PickerReady
                    } else {
                        StepKind::Frame
                    }
        }) else {
            return Ok(false);
        };
        let reference = crate::session_reference::Reference::document(
            screen,
            if screen == Screen::AppRunning {
                latest.map(|o| o.view)
            } else {
                None
            },
            Access::Edit,
            ui.cursor(),
        )?;
        if screen == Screen::AppRunning {
            let Some((shell_line, shell)) = steps
                .iter()
                .rev()
                .find(|(_, s)| s.producer == Producer::Shell && s.kind == StepKind::Frame)
            else {
                return Ok(false);
            };
            if latest.is_none_or(|o| o.frame != step.frame)
                || step.app_process != process
                || !reference.fresh_app_ready(step, *line, shell, *shell_line, &ui)?
            {
                return Ok(false);
            }
        } else if !shell_input_ready(
            &ui,
            step.shell_process,
            step.frame,
            self.shell_frame,
            *line,
            picker,
        ) || reference.surface_hash(Producer::Shell, step.frame)? != step.surface_sha256
        {
            return Ok(false);
        }
        self.capture += 1;
        if self.capture > 164 {
            return Err("document update original scanout bound64".into());
        }
        qmp.set_running(false)?;
        let captured = qmp.capture(self.capture);
        qmp.set_running(true)?;
        let (path, pixels) = captured?;
        let validated = reference.validate(&pixels);
        self.captures.push(json!({"state":latest.map(|o|json!({"state":format!("{:?}",o.view.state),"focus":format!("{:?}",o.view.focus),"revision":o.view.revision,"text_sha256":crate::acquisition_io::hash(o.view.text.as_bytes()),"process":o.process,"frame":o.frame,"nonce":o.nonce})),"step":step,"path":path.file_name(),"sha256":build::hash_file(&path)?,"pixels":validated.as_ref().ok(),"error":validated.as_ref().err()}));
        validated?;
        if screen == Screen::AppRunning {
            self.nonce = latest.unwrap().nonce;
        } else {
            self.shell_frame = step.frame;
        }
        Ok(true)
    }
    pub(crate) fn closed(
        &mut self,
        serial: &[u8],
        build: &str,
        qmp: &mut Qmp,
        process: u64,
    ) -> Result<bool> {
        self.observe(serial, build, qmp, process, Screen::AppRunning, |v| {
            v.state == State::Closed && v.choice == Choice::None
        })
    }
}
fn shell_input_ready(
    ui: &crate::session_io::ProbeUi,
    shell: u64,
    frame: u64,
    previous_frame: u64,
    step_line: usize,
    picker: bool,
) -> bool {
    // PickerReady is emitted after its matching protected barrier. Ordinary
    // Frame is emitted before that barrier. The actual shell/frame binding and
    // strictly new displayed frame remain mandatory for either ordering.
    frame > previous_frame
        && ui.cursor().is_some()
        && ui.ready(shell, frame, if picker { 0 } else { step_line })
}
pub(crate) struct Edit {
    pub(crate) observer: Observer,
    stage: u8,
    typed: usize,
}
impl Edit {
    pub(crate) fn new() -> Self {
        Self {
            observer: Observer::new(),
            stage: 0,
            typed: 0,
        }
    }
    pub(crate) fn begin_after_closed(&mut self, qmp: &mut Qmp) -> Result<()> {
        if self.stage != 0 {
            return Err("document edit started twice".into());
        }
        crate::acquisition_io::tap(qmp, Key::Enter)?;
        self.stage = 1;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tick(
        &mut self,
        serial: &[u8],
        build: &str,
        qmp: &mut Qmp,
        process: u64,
        disk: &storage::Disk,
        evidence: &Path,
    ) -> Result<bool> {
        let stage = self.stage;
        let picker = matches!(stage, 1 | 11);
        if stage == 0 {
            return Ok(false);
        }
        if stage == 13 {
            return Ok(true);
        }
        let screen = if picker {
            Screen::Picker {
                selected: FileChoice::Notes,
            }
        } else {
            Screen::AppRunning
        };
        let ready =
            self.observer
                .observe(serial, build, qmp, process, screen, |v| match stage {
                    2 => {
                        v.state == State::Saved
                            && v.choice == Choice::Notes
                            && v.access == Access::Edit
                            && v.revision == 0
                            && v.text.as_bytes() == ev_file::desktop::SEED_NOTES
                    }
                    3 | 6 => v.focus == Focus::SelectAll,
                    4 => v.focus == Focus::Text && v.anchor == 0,
                    5 => {
                        v.state == State::Dirty
                            && v.text.as_bytes() == &LATER_DOCUMENT[..self.typed]
                    }
                    7 => v.focus == Focus::Save,
                    8 | 12 => {
                        v.state == State::Saved
                            && v.revision == 1
                            && v.text.as_bytes() == LATER_DOCUMENT
                    }
                    9 => v.focus == Focus::Close,
                    10 => v.state == State::Closed,
                    _ => true,
                })?;
        if !ready {
            return Ok(false);
        }
        match stage {
            1 | 11 => crate::acquisition_io::tap(qmp, Key::Enter)?,
            2 => {
                qmp.set_running(false)?;
                let capture = disk.capture(evidence, "healthy-b-before-document-save.raw");
                qmp.set_running(true)?;
                capture?;
                crate::native3_disk::document(&disk.bytes()?, 0, ev_file::desktop::SEED_NOTES)?;
                crate::acquisition_io::tap(qmp, Key::Tab)?;
            }
            3 | 7 | 9 | 10 => crate::acquisition_io::tap(qmp, Key::Enter)?,
            4 => {
                qmp.ascii(LATER_DOCUMENT[0])?;
                self.typed = 1;
            }
            5 if self.typed < LATER_DOCUMENT.len() => {
                qmp.ascii(LATER_DOCUMENT[self.typed])?;
                self.typed += 1;
                return Ok(false);
            }
            5 | 6 => crate::acquisition_io::tap(qmp, Key::Tab)?,
            8 => {
                qmp.set_running(false)?;
                let audit = (|| {
                    disk.capture(evidence, "healthy-b-after-document-save.raw")?;
                    let before = crate::acquisition_io::bounded(
                        &evidence.join("healthy-b-before-document-save.raw"),
                        storage::DISK_BYTES as u64,
                    )?;
                    let after = disk.bytes()?;
                    let proof = save_delta(&before, &after)?;
                    storage::json_new(&evidence.join("document-save-disk-audit.json"), &proof)
                })();
                qmp.set_running(true)?;
                audit?;
                crate::acquisition_io::tap(qmp, Key::Tab)?;
            }
            12 => {
                let saved = crate::acquisition_io::bounded(
                    &evidence.join("healthy-b-after-document-save.raw"),
                    storage::DISK_BYTES as u64,
                )?;
                if disk.bytes()? != saved {
                    return Err("document close/reopen changed retained bytes".into());
                }
                self.stage = 13;
                return Ok(true);
            }
            _ => return Err("document update edit stage invalid".into()),
        }
        self.stage += 1;
        Ok(false)
    }
}
pub(crate) fn save_delta(before: &[u8], after: &[u8]) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("document update save snapshots extent".into());
    }
    if before[..32 * 512] != after[..32 * 512] || before[46 * 512..] != after[46 * 512..] {
        return Err("document update Save changed bytes outside selected Notes Store".into());
    }
    let old = crate::native3_disk::document(before, 0, ev_file::desktop::SEED_NOTES)?;
    let saved = crate::native3_disk::document(after, 1, LATER_DOCUMENT)?;
    Ok(
        json!({"before":old,"after":saved,"exact_selected_file_counter":1,"all_bytes_outside_Notes_Store_unchanged":true,"private_note_and_scalar_unchanged":true,"observer_mutations":0}),
    )
}

use crate::{
    acquisition_io::{self, Plan},
    boot::{self, DocumentAcquisitionBoot, DocumentUpdateBoot},
    build::Manifest,
    cli::{AcquisitionOptions, BootOptions, BuildOptions},
    download_fixture,
    network_io::{
        acquisition_disk::{self as disk_check, system_health as system_disk},
        components::Context,
    },
    network_mode::Mode,
    system_health_io::{self, Phase},
};
fn manifest(
    root: &Path,
    evidence: &Path,
    mode: Mode,
    source: &(String, Vec<build::SourceInput>),
) -> Result<(std::path::PathBuf, Manifest, Context)> {
    build::build(&BuildOptions {
        root: Some(root.to_owned()),
        release: true,
        fixture: Some(mode.document_fixture().into()),
    })?;
    let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
    let m: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    m.validate_policy_rows()?;
    if m.profile != "release"
        || m.fixture.as_deref() != Some(mode.document_fixture())
        || m.source_sha256 != source.0
        || m.source_inputs != source.1
    {
        return Err("System exact mode/source/profile differs".into());
    }
    let dir = storage::directory_beneath(evidence, Path::new(mode.document_fixture()))?;
    let path = dir.join("manifest.json");
    storage::immutable_new(&path, &bytes)?;
    let kernel = build::verify_artifact(&root.join("build/m0"), &m.kernel)?;
    let status = std::process::Command::new("python3")
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg(kernel)
        .arg(dir.join("kernel-stack.json"))
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("System selected actual Kernel linked stack refuses".into());
    }
    let context = Context::retain_document_mode(
        root,
        &m,
        &storage::directory_beneath(&dir, Path::new("component-preflight"))?,
        mode,
    )?;
    Ok((path, m, context))
}
pub(crate) fn run(options: &AcquisitionOptions) -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let signer = options.authority_root.as_ref().map_or_else(
        || Ok(root.clone()),
        |p| fs::canonicalize(p).map_err(|e| e.to_string()),
    )?;
    let _authority = acquisition_io::authority(&root, &signer)?;
    let parent = storage::directory_beneath(&root, Path::new("build/m7/evidence"))?;
    let evidence = build::unique_directory(&parent, "document-update")?;
    println!("Evidence: {}", evidence.display());
    let source = build::source_inputs(&root)?;
    storage::json_new(
        &evidence.join("source-before.json"),
        &json!({"sha256":source.0,"inputs":source.1}),
    )?;
    let mut owned_disk = None;
    let mut phases = Vec::new();
    let result: Result<()> = (|| {
        let (standalone_path, standalone, context) =
            manifest(&root, &evidence, Mode::Standalone, &source)?;
        let (managed_path, managed, managed_context) =
            manifest(&root, &evidence, Mode::SystemManaged, &source)?;
        let (recovery_path, recovery, recovery_context) =
            manifest(&root, &evidence, Mode::Recovery, &source)?;
        if context.images != managed_context.images || context.images != recovery_context.images {
            return Err("System mode set changes protected actual component images".into());
        }
        let bundle_dir = root
            .join("build/m6/downloads")
            .join(evidence.file_name().ok_or("System evidence name")?);
        let bundle = download_fixture::produce_document(&root, &bundle_dir, &source.0)?;
        acquisition_io::absent_from_banks(&context, &bundle)?;
        let make_plan = |m: &Manifest| Plan {
            schema: 1,
            source_sha256: m.source_sha256.clone(),
            build_id: m.build_id.clone(),
            bundle_directory: bundle_dir.clone(),
            authority_workspace: signer.clone(),
            public_root_sha256: acquisition_io::hash(_authority.root()),
            downloaded_elf_sha256: bundle.downloads[0]
                .component
                .image_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            downloaded_package_sha256: bundle.downloads[0]
                .package_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        };
        let (seed, seed_proof) = crate::native_seed::checkpoint(&root, &evidence)?;
        storage::json_new(&evidence.join("seed-proof.json"), &seed_proof)?;
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&seed)?;
        owned_disk = Some(disk);
        let disk = owned_disk.as_ref().unwrap();
        let options = BootOptions {
            timeout_seconds: acquisition_io::TIMEOUT_SECONDS,
            ..BootOptions::default()
        };
        let setup = storage::directory_beneath(&evidence, Path::new("online-b-acquisition"))?;
        storage::json_new(
            &setup.join("acquisition-plan.json"),
            &serde_json::to_value(make_plan(&standalone)).map_err(|e| e.to_string())?,
        )?;
        disk.capture(&setup, "data-before.raw")?;
        let boot = boot::boot_document_acquisition(
            &options,
            DocumentAcquisitionBoot {
                manifest: &standalone_path,
                evidence: &setup,
                disk,
                phase: acquisition_io::Phase::Online,
            },
        );
        let capture = disk.capture(&setup, "data-after.raw");
        phases.push(json!({"phase":"actual-online-B-acquisition","passed":boot.is_ok(),"error":boot.as_ref().err(),"capture_error":capture.as_ref().err()}));
        boot?;
        capture?;
        let baseline = fs::read(setup.join("setup-baseline.raw")).map_err(|e| e.to_string())?;
        let b = fs::read(bundle.downloads[0].package.clone()).map_err(|e| e.to_string())?;
        let c = fs::read(bundle.downloads[1].package.clone()).map_err(|e| e.to_string())?;
        let release_bytes = ["root.bin", "targets.bin", "snapshot.bin", "timestamp.bin"]
            .map(|name| fs::read(setup.join("phase-b").join(name)).map_err(|e| e.to_string()));
        let [rb, tb, sb, tsb] = release_bytes;
        let (rb, tb, sb, tsb) = (rb?, tb?, sb?, tsb?);
        let audit = disk_check::online(
            &baseline,
            &disk.bytes()?,
            &context.packages()?,
            disk_check::Release {
                root: &rb,
                targets: &tb,
                snapshot: &sb,
                timestamp: &tsb,
                artifact: &b,
            },
            disk_check::Expected {
                registry_revision: 4,
                registry_active: bundle.downloads[0].package_id,
                registry_staged: None,
                registry_previous: Some(
                    context
                        .packages()?
                        .digest(ev_root_supervisor::native_plan::Slot::A),
                ),
                trust_active: Some(2),
                known_good: None,
                saved: disk_check::Saved {
                    note: acquisition_io::NOTE,
                    note_counter: 1,
                    value: 1001,
                    data_counter: 0,
                },
            },
        )?;
        storage::json_new(&setup.join("acquisition-disk-audit.json"), &audit.proof)?;
        let mut previous_replay = Some(audit.replay());
        let mut failure = None;
        let mut healthy_b = None;
        for phase in [
            Phase::SelectB,
            Phase::HealthyAndStageC,
            Phase::FaultC,
            Phase::Recovery,
            Phase::FinalB,
        ] {
            let (mp, m, ctx) = match phase.mode() {
                Mode::Standalone => (&standalone_path, &standalone, &context),
                Mode::SystemManaged => (&managed_path, &managed, &managed_context),
                Mode::Recovery => (&recovery_path, &recovery, &recovery_context),
            };
            let dir = storage::directory_beneath(&evidence, Path::new(phase.name()))?;
            storage::json_new(
                &dir.join("acquisition-plan.json"),
                &serde_json::to_value(make_plan(m)).map_err(|e| e.to_string())?,
            )?;
            storage::immutable_new(
                &dir.join("namespace-origin-manifest.json"),
                &fs::read(&standalone_path).map_err(|e| e.to_string())?,
            )?;
            disk.capture(&dir, "data-before.raw")?;
            let before = disk.bytes()?;
            let boot = boot::boot_document_update(
                &options,
                DocumentUpdateBoot {
                    manifest: mp,
                    evidence: &dir,
                    disk,
                    phase,
                },
            );
            let captured = disk.capture(&dir, "data-after.raw");
            let after = disk.bytes();
            phases.push(json!({"phase":phase,"passed":boot.is_ok(),"error":boot.as_ref().err(),"capture_error":captured.as_ref().err()}));
            boot?;
            captured?;
            let after = after?;
            let (
                selected,
                known_good,
                active,
                candidate,
                boot_serial,
                failed_child,
                note,
                note_counter,
            ) = match phase {
                Phase::SelectB => (2, None, 2, 2, 0, false, acquisition_io::NOTE, 1),
                Phase::HealthyAndStageC => (3, Some(2), 2, 3, 1, false, acquisition_io::NOTE, 1),
                Phase::FaultC | Phase::Recovery => {
                    (2, Some(2), 3, 3, 2, true, acquisition_io::NOTE, 1)
                }
                Phase::FinalB => (2, Some(2), 2, 3, 3, true, acquisition_io::NOTE, 1),
            };
            let creation =
                disk_check::NamespaceCreation::checked(&context.packages()?, &ctx.packages()?)?;
            let audit_before = if phase == Phase::HealthyAndStageC {
                acquisition_io::bounded(
                    &dir.join("healthy-b-after-document-save.raw"),
                    storage::DISK_BYTES as u64,
                )?
            } else {
                before.clone()
            };
            let mut audited = system_disk::inspect(
                &audit_before,
                &after,
                &ctx.packages()?,
                &creation,
                &[&b, &c],
                system_disk::Expected {
                    selected,
                    known_good,
                    active,
                    candidate,
                    boot_serial,
                    failed_child,
                    saved: disk_check::Saved {
                        note,
                        note_counter,
                        value: 1001,
                        data_counter: 0,
                    },
                },
                false,
            )?;
            let document = crate::native3_disk::document(
                &after,
                u64::from(phase != Phase::SelectB),
                if phase == Phase::SelectB {
                    ev_file::desktop::SEED_NOTES
                } else {
                    LATER_DOCUMENT
                },
            )?;
            audited.proof["selected_document"] = document;
            audited.proof["comparison_baseline"] = json!(if phase == Phase::HealthyAndStageC {
                "healthy-b-after-document-save.raw (actual capture; earlier boot/admission and File-only save independently audited)"
            } else {
                "data-before.raw"
            });
            let serial =
                acquisition_io::bounded(&dir.join("boot/run-001/serial.log"), 1024 * 1024)?;
            let admitted = system_health_io::admission_join(
                ctx,
                &serial,
                &m.build_id,
                phase,
                &audited.selected,
                &audited.active,
                audited.failure,
            )?;
            audited.proof["actual_current_admission"] = json!(
                admitted.map(|a| json!({
                "generation":a.generation.get(),"boot_serial":a.boot_serial,
                "process_stamp":a.process_stamp,"actual_Root_and_downloaded_subject_joined":true}))
            );
            if phase == Phase::HealthyAndStageC {
                healthy_b = admitted;
            }
            let probe_admission = match phase {
                Phase::SelectB => None,
                Phase::FinalB => admitted,
                _ => healthy_b,
            };
            if phase != Phase::SelectB && probe_admission.is_none() {
                return Err("System exact healthy B probe admission absent".into());
            }
            system_disk::verify_probe(&mut audited, probe_admission)?;
            if phase == Phase::FaultC {
                let summary = audited
                    .child_summary
                    .as_ref()
                    .ok_or("System child summary absent")?;
                crate::system_health_io::fault_summary_join(
                    &dir.join("boot/run-001/serial.log"),
                    &m.build_id,
                    summary,
                )?;
            }
            if let Some(old) = previous_replay
                && phase != Phase::HealthyAndStageC
                && old != audited.replay
            {
                return Err("System local boot/recovery changed remote replay floors".into());
            }
            if let Some(old) = failure
                && audited.failure != Some(old)
            {
                return Err("System recovery lost original LAST child-fault facts".into());
            }
            if failed_child {
                failure = audited.failure;
            }
            previous_replay = Some(audited.replay);
            if audited.selected.generation.get() != selected {
                return Err("System selected identity mismatch".into());
            }
            storage::json_new(
                &dir.join("System-and-content-disk-audit.json"),
                &audited.proof,
            )?;
        }
        Ok(())
    })();
    let seal = owned_disk.as_ref().map_or(Ok(()), storage::Disk::seal);
    let postflight = build::source_inputs(&root).and_then(|actual| {
        storage::json_new(
            &evidence.join("source-after.json"),
            &json!({"sha256":actual.0,"inputs":actual.1,"unchanged":actual==source}),
        )?;
        if actual == source {
            Ok(())
        } else {
            Err("System source changed during execution".into())
        }
    });
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"actual-native-document-signed-six-boot-update-health-recovery",
        "passed":result.is_ok()&&seal.is_ok()&&postflight.is_ok(),"error":result.as_ref().err(),"seal_error":seal.as_ref().err(),
        "source_postflight_error":postflight.as_ref().err(),"phases":phases,"scripted_input":true,"human_consent_claim":false,
        "same_owned_disk":true,"same_source_three_explicit_mode_images":true,"whole_M7_acceptance":false,"expected_selected_file_content_sha256":acquisition_io::hash(LATER_DOCUMENT),"saved_private_note_preserved":result.is_ok(),"physical_qualification":false}),
    )?;
    result?;
    seal?;
    postflight
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn picker_ready_uses_prior_exact_barrier_and_still_refuses_stale_or_other_frames() {
        // Retained parser fixture only; this is no new VM or input approval.
        let raw = include_str!("../../../tests/fixtures/m6-session-exercise-parser.serial");
        let build = raw
            .lines()
            .find(|l| l.starts_with("EVROSION_BOOT "))
            .unwrap()
            .split(' ')
            .find_map(|s| s.strip_prefix("build="))
            .unwrap();
        let mut prefix = String::new();
        let mut ready = None;
        for (line, row) in raw.split_inclusive('\n').enumerate() {
            prefix.push_str(row);
            let row = row.trim_end_matches(['\r', '\n']);
            if row.starts_with("EVROSION_M4_DESKTOP_STEP ") && row.contains("step=picker_ready ") {
                ready = Some((
                    line,
                    crate::desktop_protocol::step_line(row, build).unwrap(),
                ));
                break;
            }
        }
        let (ready_line, step) = ready.unwrap();
        let ui = crate::session_io::ProbeUi::parse(prefix.as_bytes(), build).unwrap();
        assert!(!ui.ready(step.shell_process, step.frame, ready_line));
        assert!(shell_input_ready(
            &ui,
            step.shell_process,
            step.frame,
            0,
            ready_line,
            true
        ));
        assert!(!shell_input_ready(
            &ui,
            step.shell_process,
            step.frame,
            step.frame,
            ready_line,
            true
        ));
        assert!(!shell_input_ready(
            &ui,
            step.shell_process + 1000,
            step.frame,
            0,
            ready_line,
            true
        ));
        assert!(!shell_input_ready(
            &ui,
            step.shell_process,
            step.frame + 1,
            0,
            ready_line,
            true
        ));
        assert!(!shell_input_ready(
            &ui,
            step.shell_process,
            step.frame,
            0,
            ready_line,
            false
        ));
        let frame_line = prefix
            .lines()
            .enumerate()
            .find_map(|(line, row)| {
                if !row.starts_with("EVROSION_M4_DESKTOP_STEP ") {
                    return None;
                }
                let row = crate::desktop_protocol::step_line(row, build).unwrap();
                (row.producer == crate::desktop_protocol::Producer::Shell
                    && row.kind == crate::desktop_protocol::StepKind::Frame
                    && row.frame == step.frame)
                    .then_some(line)
            })
            .unwrap();
        assert!(frame_line < ready_line);
        assert!(shell_input_ready(
            &ui,
            step.shell_process,
            step.frame,
            0,
            frame_line,
            false
        ));
    }
}
