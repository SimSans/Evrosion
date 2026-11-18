//! Mode-independent immutable System recipes and actual Root admission stamps.
//! Metadata creates no authority; the actual Native startup manifest is checked
//! against its raw mode-bound catalogue before these helpers are called.
#![forbid(unsafe_code)]
use super::{Packages, Slot as AppSlot};
use ev_diagnostics::system::Phase;
use ev_store::{AdmissionReport, BootPlan, GenerationId, GenerationManifest};
use ev_userspace_contract::{
    Context,
    root_v2::{self, native},
};
use sha2::{Digest as _, Sha256};
pub const INITIAL_PAYLOAD: &[u8] = b"System pending; no admitted health";
pub const HEALTH_DESCRIPTION:&[u8]=b"evrosion.internal.native-system.health.v1; version3/profile3; protected common Root/Block/Display/File/Input bootstrap before normal System admission; actual Root identity and bootstrap manifest bound to durable BeginBoot/Admission and immutable selected cohort; first fresh live Root observation after Admission anchors one64tick deadline with no reset/extension; authentic current Shell GenericReady and CriticalReady after protected Present; actual Root GenericReady then graph-gated CriticalReady; actual durable System-only mutable probe and fresh Root/allcriticalservice liveness before KnownGood; child PF captured beforeReap separately; live Root without validcriticalprogress at deadline records MissingProgress, never fake RootProcessFault; running admitted generation distinct from nextselection; independent Root/Block recovery; ordinary owner/transition/UART work deferred during Managed probation; App mutation and queued activation require the same available normal graph, Healthy for SystemManaged; Standalone remains normal and Recovery cannot launch Apps; no App/File data mutation";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Good,
    Bad,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Generation,
    Manifest,
    Identity,
}
/// One normal-graph gate shared by Shell launch, owner App mutations and
/// already-queued activation. Selection of a next generation is not admission.
pub const fn can_launch(
    mode: native::catalogue::BootMode,
    bootstrapping: bool,
    blocked: bool,
    shell_started: bool,
    phase: Option<Phase>,
) -> bool {
    !bootstrapping
        && !blocked
        && shell_started
        && matches!(
            (mode, phase),
            (native::catalogue::BootMode::Standalone, _)
                | (
                    native::catalogue::BootMode::SystemManaged,
                    Some(Phase::Healthy)
                )
        )
}
/// Health/receive/output still progress; ordinary owner work must not occupy
/// the one anchored critical-initialization window.
pub const fn defer_owner_work(mode: native::catalogue::BootMode, phase: Option<Phase>) -> bool {
    matches!(
        (mode, phase),
        (
            native::catalogue::BootMode::SystemManaged,
            Some(Phase::Probation)
        )
    )
}
pub fn health_contract() -> [u8; 32] {
    Sha256::digest(HEALTH_DESCRIPTION).into()
}
pub fn catalogue_recipe(packages: &Packages<'_>) -> [u8; 32] {
    let (a, b, c) = packages.catalogue().cohort_parts();
    let mut h = Sha256::new();
    h.update(b"evrosion.native.mode-independent-catalogue.v1\0");
    h.update(a);
    h.update([0; 32]);
    h.update(b);
    h.update([0; 2]);
    h.update(c);
    h.finalize().into()
}
pub fn manifest(
    packages: &Packages<'_>,
    slot: Slot,
    generation: u64,
) -> Result<GenerationManifest, Error> {
    // The V4 System cohort/health recipe is not yet implemented. Metadata
    // compatibility cannot convert it into an admitted Native3 generation.
    if packages.is_network() {
        return Err(Error::Manifest);
    }
    let generation = GenerationId::new(generation).ok_or(Error::Generation)?;
    let cat = packages.catalogue();
    let selected = match slot {
        Slot::Good => {
            let shell = cat
                .base()
                .images()
                .nth(root_v2::graph::Child::Shell.index())
                .unwrap();
            native::catalogue::AppImage {
                image: shell.image,
                descriptor: shell.descriptor,
                abi: shell.abi,
                limits: shell.limits,
                roles: shell.roles,
            }
        }
        Slot::Bad => cat.bad_shell(),
    };
    let mut h = Sha256::new();
    h.update(b"evrosion.native.system.cohort.v1\0");
    h.update(native::PROFILE.to_le_bytes());
    h.update(generation.get().to_le_bytes());
    for digest in [
        cat.base().root_image(),
        cat.base().kernel_input(),
        catalogue_recipe(packages),
        native::ABI,
        Sha256::digest(native::layout_description()).into(),
        Sha256::digest(root_v2::graph::description()).into(),
        packages.digest(AppSlot::A),
        packages.digest(AppSlot::B),
        selected.image,
        selected.descriptor,
        selected.abi,
        selected.roles,
        health_contract(),
    ] {
        h.update(digest);
    }
    for limit in selected.limits {
        h.update(limit.to_le_bytes());
    }
    h.update(8u64.to_le_bytes());
    Ok(GenerationManifest {
        generation,
        cohort: h.finalize().into(),
        supervisor_image: cat.base().root_image(),
        abi: native::ABI,
        health_contract: health_contract(),
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    })
}
pub fn resolve(packages: &Packages<'_>, selected: &GenerationManifest) -> Result<Slot, Error> {
    [Slot::Good, Slot::Bad]
        .into_iter()
        .find(|slot| {
            manifest(packages, *slot, selected.generation.get()).is_ok_and(|m| m == *selected)
        })
        .ok_or(Error::Manifest)
}
/// Canonical Native reference to the full System manifest, distinct from Store
/// on-disk encoding/checksum and from namespace original-creation provenance.
pub fn manifest_digest(m: &GenerationManifest) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"evrosion.native.system.manifest-reference.v1\0");
    h.update(m.generation.get().to_le_bytes());
    for d in [m.cohort, m.supervisor_image, m.abi, m.health_contract] {
        h.update(d);
    }
    h.update(m.health_version.to_le_bytes());
    h.update(m.required_checks.to_le_bytes());
    h.finalize().into()
}
pub fn admission(
    packages: &Packages<'_>,
    context: Context,
    process: u64,
    thread: u64,
    plan: BootPlan,
) -> Result<AdmissionReport, Error> {
    resolve(packages, &plan.manifest)?;
    if process == 0
        || process != context.process
        || thread == 0
        || plan.serial == 0
        || plan.attempt == 0
        || context.epoch == 0
        || context.incarnation == 0
        || context.manifest == [0; 32]
    {
        return Err(Error::Identity);
    }
    let mut h = Sha256::new();
    h.update(b"evrosion.actual.native-system.admission.v1\0");
    for d in [
        packages.catalogue().base().kernel_input(),
        context.manifest,
        manifest_digest(&plan.manifest),
        plan.manifest.cohort,
        plan.manifest.supervisor_image,
        plan.manifest.abi,
    ] {
        h.update(d);
    }
    for value in [
        plan.manifest.generation.get(),
        plan.serial,
        process,
        thread,
        context.epoch,
        context.incarnation,
    ] {
        h.update(value.to_le_bytes());
    }
    Ok(AdmissionReport {
        generation: plan.manifest.generation,
        boot_serial: plan.serial,
        process_stamp: h.finalize().into(),
        cohort: plan.manifest.cohort,
        supervisor_image: plan.manifest.supervisor_image,
        abi: plan.manifest.abi,
        health_contract: plan.manifest.health_contract,
        health_version: plan.manifest.health_version,
    })
}
pub fn probe(admitted: AdmissionReport) -> [u8; 256] {
    let mut b = [0; 256];
    b[..8].copy_from_slice(b"EVSYSPR1");
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[10..12].copy_from_slice(&256u16.to_le_bytes());
    b[16..24].copy_from_slice(&admitted.generation.get().to_le_bytes());
    b[24..32].copy_from_slice(&admitted.boot_serial.to_le_bytes());
    for (i, d) in [
        admitted.process_stamp,
        admitted.cohort,
        admitted.supervisor_image,
        admitted.abi,
        admitted.health_contract,
    ]
    .into_iter()
    .enumerate()
    {
        b[32 + i * 32..64 + i * 32].copy_from_slice(&d);
    }
    b
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use native::catalogue::BootMode;
    #[test]
    fn managed_apps_require_actual_healthy_admission() {
        for phase in [None, Some(Phase::Probation), Some(Phase::Failed)] {
            assert!(!can_launch(
                BootMode::SystemManaged,
                false,
                false,
                true,
                phase
            ));
        }
        assert!(can_launch(
            BootMode::SystemManaged,
            false,
            false,
            true,
            Some(Phase::Healthy)
        ));
    }
    #[test]
    fn unavailable_normal_graph_cannot_launch_even_with_healthy_metadata() {
        for mode in [BootMode::Standalone, BootMode::SystemManaged] {
            for (bootstrapping, blocked, shell_started) in [
                (true, false, true),
                (false, true, true),
                (false, false, false),
            ] {
                assert!(!can_launch(
                    mode,
                    bootstrapping,
                    blocked,
                    shell_started,
                    Some(Phase::Healthy)
                ));
            }
        }
    }
    #[test]
    fn standalone_retains_normal_launch_without_system_admission() {
        assert!(can_launch(BootMode::Standalone, false, false, true, None));
        assert!(!defer_owner_work(BootMode::Standalone, None));
    }
    #[test]
    fn recovery_never_becomes_a_normal_app_graph() {
        for phase in [
            None,
            Some(Phase::Probation),
            Some(Phase::Healthy),
            Some(Phase::Failed),
        ] {
            assert!(!can_launch(BootMode::Recovery, false, false, true, phase));
            assert!(!defer_owner_work(BootMode::Recovery, phase));
        }
    }
    #[test]
    fn only_actual_managed_probation_defers_ordinary_owner_work() {
        assert!(defer_owner_work(
            BootMode::SystemManaged,
            Some(Phase::Probation)
        ));
        for phase in [None, Some(Phase::Healthy), Some(Phase::Failed)] {
            assert!(!defer_owner_work(BootMode::SystemManaged, phase));
        }
    }
}
