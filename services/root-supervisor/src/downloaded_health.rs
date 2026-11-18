//! Private V4 prototype: the existing System Store is the durable generation
//! transaction. Signed local identity, explicit selection, actual admission,
//! probation, durable probe and KnownGood remain different facts.
#![forbid(unsafe_code)]
#[path = "downloaded_health/notice.rs"]
pub mod notice;
use crate::{
    native_acquisition::{Content, Snapshot},
    native_image::{Images, Io},
    native_plan::{
        Packages,
        state::{State, SystemChange},
    },
    native_sources::Member,
};
use ev_block_service::store_io::{Window, Wire};
use ev_store::{
    AdmissionReport, BootPlan, CriticalFaultReport, FailureEvidence, GenerationId,
    GenerationManifest, HealthOutcome, HealthReport,
};
use ev_userspace_contract::{
    Context,
    root_v4::{self, graph::Child},
};
use sha2::{Digest, Sha256};
/// Separately versioned M6 downloaded-cohort failure policy; no hard real-time
/// success guarantee follows from the unchanged CPU allowance ceilings.
pub const HEALTH_VERSION: u16 = 2;
pub const PROGRESS_TICKS: u64 = 512;
pub const HEALTH_DESCRIPTION:&[u8]=b"evrosion.V4.downloaded-cohort.health.v2; exact protected Kernel/Root/common5 plus authenticated downloaded required subject; explicit selection; durable BeginBoot/attempt/serial then actual Root+subject admission; GenericReady is never health; seven current actual startup/liveness identities; genuine Root Shell downloaded-subject Critical progress within one fixed maximum512tick window anchored at first fresh actual Root LIVE after durable Admission and bounded by originalcut; no reset or extension; durable System-only probe flush+readback; fresh actual same-incarnation all-seven liveness before health decision; optional NIC unavailable does not prevent offline boot; child fault distinct from Root ProcessFault; immutable bounded256byte child identity/core-fault summary published before hash reference in canonical System journal; protected KnownGood and data remain; no fresh remote time needed for local recovery";
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Profile,
    Content,
    Manifest,
    Storage,
    Clock,
    Phase,
    Progress,
    Probe,
    Fault,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub process: u64,
    pub thread: u64,
    pub image: [u8; 32],
}
impl Identity {
    fn valid(self) -> bool {
        self.process != 0 && self.thread != 0 && self.image != [0; 32]
    }
}
/// Role order is closed: actual Root, Shell, Input, File, Block, Display and
/// downloaded required subject. NIC actors remain optional for offline use.
#[derive(Clone, Copy)]
pub struct Cohort {
    manifest: GenerationManifest,
    content: Content,
    images: [[u8; 32]; 7],
}
impl Cohort {
    pub fn checked<I: Io>(
        banks: &Packages<'_>,
        snapshot: &Snapshot,
        images: &Images<I>,
        member: Member,
    ) -> Result<Self, Error> {
        if !banks.is_network() {
            return Err(Error::Profile);
        }
        member.check(images).map_err(|_| Error::Identity)?;
        let content = member.content();
        Member::capture(images, member.kernel_slot(), snapshot, content)
            .map_err(|_| Error::Content)?;
        let package = images
            .package(member.kernel_slot())
            .map_err(|_| Error::Content)?;
        let mut actual = [[0; 32]; 7];
        actual[0] = banks.catalogue().base().root_image();
        for (i, child) in [
            Child::Shell,
            Child::Input,
            Child::File,
            Child::Block,
            Child::Display,
        ]
        .into_iter()
        .enumerate()
        {
            actual[i + 1] = banks
                .catalogue()
                .base()
                .images()
                .nth(child.index())
                .ok_or(Error::Profile)?
                .image;
        }
        actual[6] = package.executable().digest;
        let generation = GenerationId::new(content.version).ok_or(Error::Manifest)?;
        let mut h = Sha256::new();
        h.update(b"evrosion.V4.downloaded-cohort.recipe.v2\0");
        h.update(HEALTH_VERSION.to_le_bytes());
        h.update(hash(HEALTH_DESCRIPTION));
        // Bind the exact V4 catalogue recipe with its existing explicit mode/
        // measurement masks. Selection and recovery modes share one cohort;
        // actual admission still binds the exact current bootstrap manifest.
        // The bundled App image does not name the running downloaded subject.
        h.update(crate::native_plan::system::catalogue_recipe(banks));
        h.update(root_v4::ABI);
        h.update(ev_userspace_contract::ABI);
        for image in actual {
            h.update(image)
        }
        for digest in [
            content.package,
            content.build,
            content.source,
            content.descriptor,
            content.object.sha256(),
        ] {
            h.update(digest)
        }
        h.update(content.object.length().to_le_bytes());
        h.update(generation.get().to_le_bytes());
        let manifest = GenerationManifest {
            generation,
            cohort: h.finalize().into(),
            supervisor_image: actual[0],
            abi: root_v4::ABI,
            health_contract: hash(HEALTH_DESCRIPTION),
            health_version: HEALTH_VERSION,
            required_checks: 3,
        };
        Ok(Self {
            manifest,
            content,
            images: actual,
        })
    }
    pub fn manifest(&self) -> GenerationManifest {
        self.manifest
    }
    pub fn content(&self) -> Content {
        self.content
    }
    pub fn matches(&self, m: &GenerationManifest) -> bool {
        self.manifest == *m
    }
    fn admission(
        &self,
        context: Context,
        root: Identity,
        subject: Identity,
        plan: BootPlan,
    ) -> Result<AdmissionReport, Error> {
        if !self.matches(&plan.manifest)
            || plan.serial == 0
            || plan.attempt == 0
            || context.process != root.process
            || !root.valid()
            || !subject.valid()
            || root.process == subject.process
            || root.thread == subject.thread
            || root.image != self.images[0]
            || subject.image != self.images[6]
            || context.epoch == 0
            || context.incarnation == 0
            || context.manifest == [0; 32]
        {
            return Err(Error::Identity);
        }
        let mut h = Sha256::new();
        h.update(b"evrosion.V4.downloaded-cohort.actual-admission.v2\0");
        h.update(self.manifest.health_version.to_le_bytes());
        h.update(self.manifest.health_contract);
        for d in [
            self.manifest.cohort,
            context.manifest,
            root.image,
            subject.image,
        ] {
            h.update(d)
        }
        for n in [
            plan.manifest.generation.get(),
            plan.serial,
            context.epoch,
            context.incarnation,
            root.process,
            root.thread,
            subject.process,
            subject.thread,
        ] {
            h.update(n.to_le_bytes())
        }
        Ok(AdmissionReport {
            generation: self.manifest.generation,
            boot_serial: plan.serial,
            process_stamp: h.finalize().into(),
            cohort: self.manifest.cohort,
            supervisor_image: root.image,
            abi: self.manifest.abi,
            health_contract: self.manifest.health_contract,
            health_version: self.manifest.health_version,
        })
    }
}
/// Not Clone: charge BeginBoot before starting the actual downloaded process.
pub struct BootTicket {
    cohort: Cohort,
    plan: BootPlan,
}
/// Constructed only after the matching Admission journal operation ACKs.
pub struct Admitted {
    cohort: Cohort,
    report: AdmissionReport,
    root: Identity,
    subject: Identity,
}
impl<T: Wire, W: Window> State<T, W> {
    /// Explicit owner initialization only. Existing System initialization still
    /// refuses V4; this typed path requires fully associated downloaded content.
    pub fn system_initialize_downloaded(
        &mut self,
        cohort: &Cohort,
        deadline: u64,
    ) -> Result<(), Error> {
        if self
            .system_snapshot(deadline)
            .map_err(|_| Error::Storage)?
            .is_some()
        {
            return Err(Error::Phase);
        }
        // Own private State implementation lives in the sibling state module; the
        // small adapter is defined there to preserve its sole Backend owner.
        self.initialize_downloaded_manifest(cohort.manifest, deadline)
            .map_err(|_| Error::Storage)
    }
    pub fn system_begin_downloaded(
        &mut self,
        cohort: Cohort,
        deadline: u64,
    ) -> Result<BootTicket, Error> {
        let before = self
            .system_snapshot(deadline)
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Manifest)?;
        if before.selected != Some(cohort.manifest) {
            return Err(Error::Manifest);
        }
        let view = self
            .system_apply(
                SystemChange::BeginBoot(cohort.manifest.generation),
                deadline,
            )
            .map_err(|_| Error::Storage)?;
        let plan = view.boot_plan.ok_or(Error::Manifest)?;
        if !cohort.matches(&plan.manifest) {
            return Err(Error::Manifest);
        }
        Ok(BootTicket { cohort, plan })
    }
    pub fn system_admit_downloaded(
        &mut self,
        ticket: BootTicket,
        context: Context,
        root: Identity,
        subject: Identity,
        deadline: u64,
    ) -> Result<Admitted, Error> {
        let report = ticket
            .cohort
            .admission(context, root, subject, ticket.plan)?;
        self.system_apply(SystemChange::Admission(report), deadline)
            .map_err(|_| Error::Storage)?;
        Ok(Admitted {
            cohort: ticket.cohort,
            report,
            root,
            subject,
        })
    }
    pub fn system_fail_component(
        &mut self,
        report: CriticalFaultReport,
        deadline: u64,
    ) -> Result<(), Error> {
        self.apply_component_fault(report, deadline)
            .map_err(|_| Error::Storage)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Authenticated startup readiness for this exact live incarnation.
    Generic,
    /// Defined by this contract only for Root, Shell and downloaded subject.
    Critical,
}
const STARTUP_MASK: u8 = 0x7f;
const CRITICAL_MASK: u8 = (1 << 0) | (1 << 1) | (1 << 6);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Probation,
    Ready,
    Probe,
    Decided,
    Faulted,
    Fenced,
}
/// Provider boundary: the Root adapter must collect these observations through
/// actual CONTROL/identity calls, not event payload PID/image labels or a cache.
pub trait Observer {
    type Error;
    fn observe(&mut self, index: usize) -> Result<(Identity, u64), Self::Error>;
}
pub struct Probation {
    cohort: Cohort,
    report: AdmissionReport,
    identities: [Identity; 7],
    generic: u8,
    critical: u8,
    phase: Phase,
    first: u64,
    last: u64,
    deadline: u64,
    probe: Option<[u8; 32]>,
    original_cut: u64,
}
impl Admitted {
    pub fn report(&self) -> AdmissionReport {
        self.report
    }
    pub fn probation<O: Observer>(
        &self,
        observer: &mut O,
        original_cut: u64,
    ) -> Result<Probation, Error> {
        let mut ids = [self.root; 7];
        let mut first = None;
        let mut last = 0;
        for i in 0..7 {
            let (id, at) = observer.observe(i).map_err(|_| Error::Identity)?;
            if !id.valid()
                || id.image != self.cohort.images[i]
                || i == 0 && id != self.root
                || i == 6 && id != self.subject
                || at == u64::MAX
                || first.is_some() && at < last
                || at >= original_cut
            {
                return Err(Error::Identity);
            }
            if ids[..i]
                .iter()
                .any(|old| old.process == id.process || old.thread == id.thread)
            {
                return Err(Error::Identity);
            }
            ids[i] = id;
            if first.is_none() {
                first = Some(at)
            }
            last = at;
        }
        let first = first.ok_or(Error::Identity)?;
        let deadline = first
            .checked_add(PROGRESS_TICKS)
            .map(|end| end.min(original_cut))
            .filter(|end| first < *end && *end != u64::MAX)
            .ok_or(Error::Clock)?;
        if last >= deadline {
            return Err(Error::Clock);
        }
        self.probation_bound(ids, first, original_cut)
    }
    /// Actual Root LIVE anchors the one progress interval. The adapter supplies
    /// identities obtained from each actual admitted CONTROL, including a child
    /// which may already have faulted. This records probation, never child LIVE
    /// or critical success; promotion independently observes every actor anew.
    pub fn probation_bound(
        &self,
        ids: [Identity; 7],
        first: u64,
        original_cut: u64,
    ) -> Result<Probation, Error> {
        let deadline = first
            .checked_add(PROGRESS_TICKS)
            .map(|end| end.min(original_cut))
            .filter(|end| first < *end && *end != u64::MAX)
            .ok_or(Error::Clock)?;
        if first == u64::MAX || ids[0] != self.root || ids[6] != self.subject {
            return Err(Error::Identity);
        }
        for (i, id) in ids.iter().enumerate() {
            if !id.valid()
                || id.image != self.cohort.images[i]
                || ids[..i]
                    .iter()
                    .any(|old| old.process == id.process || old.thread == id.thread)
            {
                return Err(Error::Identity);
            }
        }
        Ok(Probation {
            cohort: self.cohort,
            report: self.report,
            identities: ids,
            generic: 0,
            critical: 0,
            phase: Phase::Probation,
            first,
            last: first,
            deadline,
            probe: None,
            original_cut,
        })
    }
}
impl Probation {
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if now == u64::MAX || now < self.last {
            self.phase = Phase::Fenced;
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(())
    }
    /// Caller supplies the protected actual event sender. Ready before matching
    /// Generic, duplicates, old incarnations and out-of-window progress refuse.
    pub fn progress(
        &mut self,
        index: usize,
        sender: Identity,
        kind: Progress,
        now: u64,
    ) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase != Phase::Probation
            || now >= self.deadline
            || self.identities.get(index) != Some(&sender)
        {
            return Err(Error::Progress);
        }
        let bit = 1u8 << index;
        match kind {
            Progress::Generic => {
                if self.generic & bit != 0 {
                    return Err(Error::Progress);
                }
                self.generic |= bit
            }
            Progress::Critical => {
                if CRITICAL_MASK & bit == 0 || self.generic & bit == 0 || self.critical & bit != 0 {
                    return Err(Error::Progress);
                }
                self.critical |= bit
            }
        }
        if self.generic == STARTUP_MASK && self.critical == CRITICAL_MASK {
            self.phase = Phase::Ready
        }
        Ok(())
    }
    pub fn probe_payload(&self) -> Result<[u8; 256], Error> {
        if self.phase != Phase::Ready {
            return Err(Error::Phase);
        }
        Ok(crate::native_plan::system::probe(self.report))
    }
    /// A real System WriteMutable/flush/readback ACK must precede this comparison.
    /// The actual State adapter performs that operation; arbitrary payload bytes
    /// are not an independently authorized success report.
    pub fn commit_probe<T: Wire, W: Window>(
        &mut self,
        state: &mut State<T, W>,
        now: u64,
        deadline: u64,
    ) -> Result<(), Error> {
        self.observe(now)?;
        if deadline <= now || deadline > self.original_cut {
            self.phase = Phase::Fenced;
            return Err(Error::Clock);
        }
        let payload = self.probe_payload()?;
        state
            .system_apply(SystemChange::Probe(payload), deadline)
            .map_err(|_| {
                self.phase = Phase::Fenced;
                Error::Storage
            })?;
        let actual = state.system_probe_digest(deadline).map_err(|_| {
            self.phase = Phase::Fenced;
            Error::Storage
        })?;
        if actual != hash(&payload) {
            self.phase = Phase::Fenced;
            return Err(Error::Probe);
        }
        self.probe = Some(actual);
        self.phase = Phase::Probe;
        Ok(())
    }
    pub fn health<O: Observer>(&mut self, observer: &mut O) -> Result<HealthReport, Error> {
        if self.phase != Phase::Probe {
            return Err(Error::Phase);
        }
        for i in 0..7 {
            let (id, now) = observer.observe(i).map_err(|_| {
                self.phase = Phase::Fenced;
                Error::Identity
            })?;
            self.observe(now)?;
            if id != self.identities[i] || now >= self.original_cut {
                self.phase = Phase::Fenced;
                return Err(Error::Identity);
            }
        }
        self.phase = Phase::Decided;
        Ok(HealthReport {
            admitted: self.report,
            outcome: HealthOutcome::CriticalPassed,
            observed_checks: 3,
            storage_probe: self.probe.ok_or(Error::Probe)?,
        })
    }
    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
    pub fn missing_progress(&mut self, now: u64) -> Result<HealthReport, Error> {
        self.observe(now)?;
        if !matches!(self.phase, Phase::Probation | Phase::Ready) || now < self.deadline {
            return Err(Error::Phase);
        }
        self.phase = Phase::Decided;
        Ok(HealthReport {
            admitted: self.report,
            outcome: HealthOutcome::MissingProgress,
            observed_checks: 0,
            storage_probe: [0; 32],
        })
    }
    pub fn fault(
        &mut self,
        index: usize,
        actual: Identity,
        fault: Fault,
        now: u64,
    ) -> Result<FaultCapsule, Error> {
        self.observe(now)?;
        if matches!(self.phase, Phase::Decided | Phase::Faulted)
            || index == 0
            || self.identities.get(index) != Some(&actual)
            || fault.tick < self.first
            || fault.tick > now
            || fault.vector > 255
        {
            return Err(Error::Fault);
        }
        self.phase = Phase::Faulted;
        Ok(FaultCapsule {
            report: self.report,
            cohort: self.cohort.manifest.cohort,
            actual,
            fault,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Actual scalar capture observation tick; Kernel does not expose the
    /// exception occurrence tick. The full register Crash is retained separately.
    pub tick: u64,
    pub vector: u64,
    pub error: u64,
    pub address: u64,
    pub instruction: u64,
}
pub struct FaultCapsule {
    report: AdmissionReport,
    cohort: [u8; 32],
    actual: Identity,
    fault: Fault,
}
impl FaultCapsule {
    pub fn encode(&self) -> [u8; 256] {
        let mut b = [0; 256];
        b[..8].copy_from_slice(b"EVCFAULT");
        b[8] = 1;
        for (at, n) in [
            (16, self.report.generation.get()),
            (24, self.report.boot_serial),
            (128, self.actual.process),
            (136, self.actual.thread),
            (144, self.fault.tick),
            (152, self.fault.vector),
            (160, self.fault.error),
            (168, self.fault.address),
            (176, self.fault.instruction),
        ] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes())
        }
        for (at, h) in [
            (32, self.report.process_stamp),
            (64, self.report.supervisor_image),
            (96, self.actual.image),
            (184, self.cohort),
        ] {
            b[at..at + 32].copy_from_slice(&h)
        }
        b
    }
    /// The object must come from the actual complete immutable Arena readback,
    /// whose exact payload is compared here before System references it.
    #[allow(clippy::result_large_err)]
    // Rejection retains the exact actual Arena owner.
    pub fn finish_into<B: ev_content_store::Backend>(
        &self,
        read: crate::native_acquisition::Read<B>,
        owner: &mut Option<crate::native_acquisition::Store<B>>,
        report: &mut Option<CriticalFaultReport>,
    ) -> Result<(), crate::native_acquisition::Rejected<B>> {
        use crate::native_acquisition::{Failure, Fault, Rejected};
        if owner.is_some() || report.is_some() {
            return Err(Rejected {
                owner: read.abandon(),
                error: Failure::Policy(Fault::Phase),
            });
        }
        let stored = read.finish()?;
        let Some(verified) = self.checked_readback(stored.object) else {
            return Err(Rejected {
                owner: stored.store,
                error: Failure::Policy(Fault::Checkpoint),
            });
        };
        *owner = Some(stored.store);
        *report = Some(verified);
        Ok(())
    }
    /// Private validation shared only by adapters which have just completed the
    /// canonical Reader. This is not a public object-coordinate health receipt.
    pub(crate) fn checked_readback(
        &self,
        object: ev_content_store::Object,
    ) -> Option<CriticalFaultReport> {
        if object.length() != 256
            || object.sha256() != hash(&self.encode())
            || object.start() > u32::MAX as u64
        {
            return None;
        }
        Some(CriticalFaultReport {
            admitted: self.report,
            evidence: FailureEvidence {
                object_start: object.start() as u32,
                bytes: 256,
                sha256: object.sha256(),
            },
        })
    }
}
#[cfg(test)]
mod tests;

/// Local evidence of the actual durable System KnownGood and current Registry
/// selection; not a fresh release decision or a serialized authority token.
pub struct HealthReceipt {
    pub(crate) selected: crate::native_plan::state::RegistrySelection,
    pub(crate) cohort: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) mutations: u64,
}
impl Probation {
    pub fn commit_health<T: Wire, W: Window, O: Observer>(
        &mut self,
        state: &mut State<T, W>,
        observer: &mut O,
        sources: &impl crate::native_sources::Sources,
        deadline: u64,
    ) -> Result<HealthReceipt, Error> {
        if deadline > self.original_cut || deadline <= self.last {
            self.phase = Phase::Fenced;
            return Err(Error::Clock);
        }
        let report = self.health(observer)?;
        state
            .commit_downloaded_health_receipt(&self.cohort, report, sources, deadline)
            .map_err(|_| {
                self.phase = Phase::Fenced;
                Error::Storage
            })
    }
}
