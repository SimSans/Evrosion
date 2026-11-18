//! Actual V4 downloaded System cohort. Selection is next-boot state; only a
//! cold managed execution can charge/admit the required downloaded subject.
use super::*;
use ev_diagnostics::system::Phase;
use ev_root_supervisor::{
    downloaded_health::{self as health, Cohort, Observer, Probation, Progress},
    native_plan::state::{SystemChange, SystemView},
    native_sources::{DownloadedSlot, Resolver},
    native_update as update,
};
use ev_userspace_contract::root_v2::native::catalogue::BootMode;
use sha2::{Digest as _, Sha256};
const CHILDREN: [Child; 6] = [
    Child::Shell,
    Child::Input,
    Child::File,
    Child::Block,
    Child::Display,
    Child::App,
];
#[derive(Clone, Copy)]
enum Beginning {
    Prepare,
    Retain,
    Start,
}
pub(super) struct Downloaded {
    cohort: Option<Cohort>,
    source: Option<AppSource>,
    beginning: Beginning,
    probation: Option<Probation>,
    original_cut: u64,
    stop_subject: bool,
    health_receipt: Option<health::HealthReceipt>,
    joining: bool,
    release_subject: bool,
    metadata: ev_diagnostics::system::State,
    notice: health::notice::Pending,
    admitted_subject: Option<health::notice::Subject>,
}
impl Downloaded {
    pub(super) const fn new() -> Self {
        Self {
            cohort: None,
            source: None,
            beginning: Beginning::Prepare,
            probation: None,
            original_cut: 0,
            stop_subject: false,
            health_receipt: None,
            joining: false,
            release_subject: false,
            metadata: ev_diagnostics::system::State::NotCollected,
            notice: health::notice::Pending::new(),
            admitted_subject: None,
        }
    }
    pub(super) fn joining(&self) -> bool {
        self.joining
    }
    pub(super) fn discard_notice(&mut self) {
        self.notice.discard();
        self.admitted_subject = None;
    }
}
/// Cached read-only presentation. A missing head is explicitly distinguished
/// from a verified blank System; commands still perform their real Store guards.
pub(super) struct SystemProjection<'a> {
    pub(super) mode: BootMode,
    pub(super) metadata: ev_diagnostics::system::State,
    pub(super) head: Option<&'a SystemView>,
    pub(super) current: Option<ev_diagnostics::system::Admission>,
    pub(super) selected_package: Option<[u8; 32]>,
    pub(super) busy: bool,
    pub(super) blocked: bool,
}
/// Controls and immutable images are captured from the current actual graph.
/// Each observation rechecks CONTROL identity and LIVE; payload IDs are unused.
struct Live {
    controls: [u64; 7],
    ids: [health::Identity; 7],
    bound: u64,
}
impl Observer for Live {
    type Error = ();
    fn observe(&mut self, index: usize) -> Result<(health::Identity, u64), ()> {
        let expected = *self.ids.get(index).ok_or(())?;
        let at = if index == 0 {
            const CANARY: u64 = 0x63d1_f08a_974c_2be5;
            let r = rt::call4(syscall::PROCESS_IDENTITY, 0, 0, 0, CANARY);
            if r.status != 0
                || (r.value, r.capability) != (expected.process, expected.thread)
                || r.serial == CANARY
            {
                return Err(());
            }
            r.serial
        } else {
            let control = self.controls[index];
            let id = rt::call(syscall::PROCESS_IDENTITY, control, 0, 0);
            let state = rt::call(syscall::OBSERVE, control, 0, 0);
            if id.status != 0
                || (id.value, id.capability) != (expected.process, expected.thread)
                || state.status != 0
                || state.value != 0
                || state.capability != 0
            {
                return Err(());
            }
            now()
        };
        if at == u64::MAX || (self.bound != 0 && at >= self.bound) {
            return Err(());
        }
        Ok((expected, at))
    }
}
impl Root<'_> {
    fn native_downloaded_notice_subject(&self) -> Option<health::notice::Subject> {
        let n = self.native.as_ref()?;
        let s = &n.system;
        if s.mode != BootMode::SystemManaged {
            return None;
        }
        let source = s.downloaded.source?;
        if n.running != Some(source) {
            return None;
        }
        let actor = self.actors[Child::App.index()]?;
        let current = health::notice::Subject::checked(
            s.downloaded.cohort.as_ref()?,
            source,
            DataIdentity {
                process: actor.identity.process,
                thread: actor.identity.thread,
            },
            actor.control,
            self.app_epoch,
        )?;
        (s.downloaded.admitted_subject == Some(current)).then_some(current)
    }
    /// Called only for this actual sender's genuine EVGADON1 after Present.
    /// Generic/Note/Present/Critical work still follows the ordinary handlers.
    pub(in crate::desktop) fn native_downloaded_frame_done(&mut self) -> bool {
        let n = self.native.as_ref().unwrap();
        if n.system.mode != BootMode::SystemManaged
            || n.running.is_none()
            || n.running != n.system.downloaded.source
        {
            return false;
        }
        if n.system.blocked || n.state.recovery_required() || n.system.phase == Some(Phase::Failed)
        {
            self.native
                .as_mut()
                .unwrap()
                .system
                .downloaded
                .notice
                .discard();
            return true;
        }
        let Some(subject) = self.native_downloaded_notice_subject() else {
            let s = &mut self.native.as_mut().unwrap().system;
            s.downloaded.notice.discard();
            return s.phase == Some(Phase::Probation) || s.downloaded.joining;
        };
        let n = self.native.as_mut().unwrap();
        let s = &mut n.system;
        if s.phase == Some(Phase::Probation) || s.downloaded.joining {
            s.downloaded.notice.capture(subject, self.owned_launch);
            return true;
        }
        s.downloaded.notice.pending()
    }
    #[inline(never)]
    /// Requires the caller's ordinary fanout credit. This single native_tick
    /// caller already reserved App/Shell; only that caller may end the batch.
    pub(super) fn native_downloaded_notice_tick(&mut self) -> bool {
        if !self
            .native
            .as_ref()
            .unwrap()
            .system
            .downloaded
            .notice
            .pending()
        {
            return false;
        }
        let n = self.native.as_ref().unwrap();
        if n.system.blocked || n.state.recovery_required() || n.system.phase == Some(Phase::Failed)
        {
            self.native
                .as_mut()
                .unwrap()
                .system
                .downloaded
                .notice
                .discard();
            return false;
        }
        let Some(subject) = self.native_downloaded_notice_subject() else {
            self.native
                .as_mut()
                .unwrap()
                .system
                .downloaded
                .notice
                .discard();
            return false;
        };
        if self.app_notified {
            self.native
                .as_mut()
                .unwrap()
                .system
                .downloaded
                .notice
                .discard();
            return false;
        }
        if !self
            .native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .notice
            .ready(subject)
        {
            return false;
        }
        if self
            .delivery_reservation(crate::desktop::delivery::Peer::Shell)
            .is_none()
        {
            return false;
        }
        let actor = self.child(Child::App);
        let alive = rt::call(syscall::OBSERVE, actor.control, 0, 0);
        if alive.status != 0 || alive.value != 0 || alive.capability != 0 {
            self.native
                .as_mut()
                .unwrap()
                .system
                .downloaded
                .notice
                .discard();
            return false;
        }
        if let Some(message) = self
            .native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .notice
            .take(subject)
        {
            self.app_notified = true;
            self.control_shell(message);
            return true;
        }
        false
    }
    pub(super) fn native_downloaded_system_projection(&self) -> SystemProjection<'_> {
        let n = self.native.as_ref().unwrap();
        let s = &n.system;
        let blocked = s.blocked || n.state.recovery_required();
        SystemProjection {
            mode: s.mode,
            metadata: if blocked {
                ev_diagnostics::system::State::NeedsRecovery
            } else {
                s.downloaded.metadata
            },
            head: s.view.as_ref(),
            current: self.native_system_snapshot(),
            selected_package: s
                .view
                .as_ref()
                .and_then(|v| v.selected.as_ref())
                .and_then(|m| self.native_downloaded_resolve(m))
                .map(|(_, cohort)| cohort.content().package),
            busy: s.bootstrapping
                || s.needs_admission
                || s.downloaded.joining
                || s.phase == Some(Phase::Probation)
                || n.state.transition_pending()
                || n.starting
                || n.updates.engine.busy()
                || n.updates.command.is_some(),
            blocked,
        }
    }
    fn native_downloaded_cohort(&self, source: AppSource) -> Result<Cohort, ()> {
        let AppSource::Downloaded(slot) = source else {
            return Err(());
        };
        let n = self.native.as_ref().unwrap();
        let member = n.updates.members()[slot.index()].ok_or(())?;
        Cohort::checked(
            &n.packages,
            n.updates.identity_snapshot().ok_or(())?,
            &n.images,
            member,
        )
        .map_err(|_| ())
    }
    fn native_downloaded_resolve(
        &self,
        manifest: &ev_store::GenerationManifest,
    ) -> Option<(AppSource, Cohort)> {
        [DownloadedSlot::B, DownloadedSlot::C]
            .into_iter()
            .find_map(|slot| {
                let source = AppSource::Downloaded(slot);
                self.native_downloaded_cohort(source)
                    .ok()
                    .filter(|c| c.matches(manifest))
                    .map(|c| (source, c))
            })
    }
    fn native_downloaded_live(&self, cohort: &Cohort) -> Live {
        let (root, _) = self.native_self_live();
        let mut ids = [health::Identity {
            process: root.process,
            thread: root.thread,
            image: cohort.manifest().supervisor_image,
        }; 7];
        let mut controls = [0; 7];
        for (i, child) in CHILDREN.into_iter().enumerate() {
            let actor = self.child(child);
            ids[i + 1] = health::Identity {
                process: actor.identity.process,
                thread: actor.identity.thread,
                image: self.native_downloaded_image(child),
            };
            controls[i + 1] = actor.control;
        }
        Live {
            controls,
            ids,
            bound: self.bound,
        }
    }
    fn native_downloaded_image(&self, child: Child) -> [u8; 32] {
        if child == Child::App {
            let n = self.native.as_ref().unwrap();
            let source = n.preparing.or(n.running).unwrap_or_else(|| fail(1050));
            let sources = Resolver::from_members(&n.packages, &n.images, n.updates.members())
                .unwrap_or_else(|_| fail(1050));
            return sources
                .checked_source(source)
                .unwrap_or_else(|_| fail(1050))
                .executable()
                .digest;
        }
        self.catalogue.images().nth(child.index()).unwrap().image
    }
    pub(super) fn native_downloaded_prepare(&mut self) {
        let mode = self.native.as_ref().unwrap().system.mode;
        let deadline = self.storage_deadline();
        let result = if mode == BootMode::Recovery {
            self.native
                .as_mut()
                .unwrap()
                .state
                .system_readonly_snapshot(deadline)
        } else if mode == BootMode::Standalone {
            // Standalone observes committed metadata without replay or writes.
            self.native
                .as_mut()
                .unwrap()
                .state
                .system_readonly_snapshot(deadline)
        } else {
            self.native
                .as_mut()
                .unwrap()
                .state
                .system_snapshot(deadline)
        };
        match result {
            Ok(view) => {
                let selected = view.and_then(|v| v.selected);
                let resolved = selected.and_then(|m| self.native_downloaded_resolve(&m));
                let s = &mut self.native.as_mut().unwrap().system;
                s.view = view;
                s.downloaded.metadata = if view.is_some() {
                    ev_diagnostics::system::State::Committed
                } else {
                    ev_diagnostics::system::State::Unformatted
                };
                if mode == BootMode::SystemManaged {
                    if let Some((source, cohort)) = resolved {
                        s.downloaded.cohort = Some(cohort);
                        s.downloaded.source = Some(source);
                        s.needs_admission = true;
                    } else {
                        s.blocked = true;
                    }
                }
            }
            Err(_) => self.native.as_mut().unwrap().system.blocked = true,
        }
        if mode != BootMode::Recovery {
            let view = self.native.as_ref().unwrap().system.view;
            if let Some(view) = view
                && self.native_downloaded_retain_prior_good(view).is_err()
            {
                self.native.as_mut().unwrap().system.blocked = true;
            }
        }
        if !self.native.as_ref().unwrap().system.downloaded.joining {
            self.native_queue_system_snapshot();
        }
    }
    /// Recover the interrupted cross-namespace ACK gap before another selected
    /// content can replace active B. Authority comes from the real durable
    /// System KnownGood manifest and current Registry, never cached GUI health.
    fn native_downloaded_retain_prior_good(&mut self, view: SystemView) -> Result<(), ()> {
        let Some(generation) = view.known_good else {
            return Ok(());
        };
        let source = [DownloadedSlot::B, DownloadedSlot::C]
            .into_iter()
            .find(|slot| slot.version() == generation)
            .map(AppSource::Downloaded)
            .ok_or(())?;
        let cohort = self.native_downloaded_cohort(source)?;
        let n = self.native.as_mut().unwrap();
        if n.updates
            .identity_snapshot()
            .is_some_and(|s| s.known_good() == Some(cohort.content()))
        {
            return Ok(());
        }
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let receipt = n
            .with_sources(|state, sources| {
                state.retained_downloaded_health(&cohort, sources, deadline)
            })
            .and_then(|r| r)
            .map_err(|_| ())?;
        self.native_downloaded_arm_join(receipt, false)
    }
    #[inline(never)]
    fn native_downloaded_prepare_subject(&mut self) -> Result<(), ()> {
        let source = self
            .native
            .as_ref()
            .unwrap()
            .system
            .downloaded
            .source
            .ok_or(())?;
        self.native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .discard_notice();
        let cut = self.storage_deadline();
        // Registry publication below prepares the actual held subject. No
        // Start occurs before both selected retention and durable BeginBoot.
        let n = self.native.as_mut().unwrap();
        let change = n
            .with_sources(|state, sources| {
                let current = state.active_source(sources)?;
                if current == Some(source) {
                    return Ok(None);
                }
                let record = state.record().ok_or(native_plan::state::Error::State)?;
                let wanted = sources
                    .source_digest(source)
                    .ok_or(native_plan::state::Error::Package)?;
                let change = if record.staged().is_some_and(|r| r.digest() == wanted) {
                    ev_app_registry::Change::Activate
                } else if record.previous().is_some_and(|r| r.digest() == wanted) {
                    ev_app_registry::Change::Rollback
                } else {
                    return Err(native_plan::state::Error::State);
                };
                let target = state.prepare_source(sources, change, cut)?;
                if target != Some(source) {
                    return Err(native_plan::state::Error::State);
                }
                Ok(Some(change))
            })
            .and_then(|r| r)
            .map_err(|_| ())?;
        self.app_epoch = self
            .app_epoch
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(())?;
        self.app_notified = false;
        self.owned_launch = true;
        self.native.as_mut().unwrap().preparing = Some(source);
        self.prepare(Child::App);
        self.reset(Producer::App, self.app_epoch);
        if change.is_some() {
            self.native
                .as_mut()
                .unwrap()
                .with_sources(|state, sources| state.commit(sources, cut))
                .and_then(|r| r)
                .map_err(|_| ())?;
        }
        Ok(())
    }
    #[inline(never)]
    fn native_downloaded_begin(&mut self) -> Result<(), ()> {
        let n = self.native.as_ref().unwrap();
        let cohort = n.system.downloaded.cohort.ok_or(())?;
        let source = n.system.downloaded.source.ok_or(())?;
        if n.preparing != Some(source) || self.child(Child::App).identity.process != 0 {
            return Err(());
        }
        // The original whole cut includes the read-only preload. No startup
        // health clock or deadline is renewed to pay for synchronous Store IO.
        let cut = self.storage_deadline();
        let reads = self
            .native
            .as_mut()
            .unwrap()
            .with_sources(|state, sources| state.prepare_health_reads(sources, source, cut))
            .and_then(|r| r)
            .map_err(|_| ())?;
        let ticket = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_begin_downloaded(cohort, cut)
            .map_err(|_| ())?;
        self.native_start_system_shell();
        self.start(Child::App);
        let actor = self.child(Child::App);
        let subject = actor.identity;
        let notice_subject = health::notice::Subject::checked(
            &cohort,
            source,
            DataIdentity {
                process: subject.process,
                thread: subject.thread,
            },
            actor.control,
            self.app_epoch,
        )
        .ok_or(())?;
        {
            let n = self.native.as_mut().unwrap();
            n.with_sources(|state, sources| {
                state.admit_health_subject(
                    sources,
                    source,
                    DataIdentity {
                        process: subject.process,
                        thread: subject.thread,
                    },
                    reads,
                )
            })
            .and_then(|r| r)
            .map_err(|_| ())?;
            n.preparing = None;
            n.running = Some(source);
            n.starting = true;
            n.app_settled = false;
        }
        let mut live = self.native_downloaded_live(&cohort);
        let context = self.bootstrap.context();
        let admitted = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_admit_downloaded(ticket, context, live.ids[0], live.ids[6], cut)
            .map_err(|_| ())?;
        let view = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_snapshot(cut)
            .map_err(|_| ())?;
        let (_, first) = live.observe(0)?;
        // Exact admitted identities are retained even if the subject faults
        // before its first successful LIVE query. No child LIVE is invented.
        let mut probation = admitted
            .probation_bound(live.ids, first, cut)
            .map_err(|_| ())?;
        probation
            .progress(0, live.ids[0], Progress::Generic, first)
            .map_err(|_| ())?;
        for index in 2..=5 {
            if !self.child(CHILDREN[index - 1]).ready {
                return Err(());
            }
            probation
                .progress(index, live.ids[index], Progress::Generic, first)
                .map_err(|_| ())?;
        }
        // Root's named startup/check progress is a local controller action after
        // actual manifest/authority, common startup and durable admission checks.
        probation
            .progress(0, live.ids[0], Progress::Critical, first)
            .map_err(|_| ())?;
        let s = &mut self.native.as_mut().unwrap().system;
        s.view = view;
        s.current = Some(admitted.report());
        s.downloaded.admitted_subject = Some(notice_subject);
        s.manifest = Some(cohort.manifest());
        s.phase = Some(Phase::Probation);
        s.needs_admission = false;
        s.downloaded.original_cut = cut;
        s.downloaded.probation = Some(probation);
        Ok(())
    }
    pub(super) fn native_downloaded_event(&mut self, child: Child, bytes: [u8; 8]) -> bool {
        let critical = bytes == *b"EVSHCRD1" && child == Child::Shell
            || bytes == *b"EVAPCRD1" && child == Child::App;
        let generic = bytes == *b"EVSHRDY1" && child == Child::Shell
            || bytes == *b"EVGARDY1" && child == Child::App;
        if !critical && !generic {
            return false;
        }
        let Some(index) = CHILDREN.iter().position(|c| *c == child).map(|i| i + 1) else {
            return critical;
        };
        let actor = self.child(child);
        let actual = health::Identity {
            process: actor.identity.process,
            thread: actor.identity.thread,
            image: self.native_downloaded_image(child),
        };
        let tick = now();
        if let Some(probation) = self
            .native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .probation
            .as_mut()
        {
            let _rejected_or_recorded = probation.progress(
                index,
                actual,
                if critical {
                    Progress::Critical
                } else {
                    Progress::Generic
                },
                tick,
            );
        }
        critical
    }
    /// Bounded local authentication owns the same Backend/IO/chunk/Commit as
    /// network acquisition. Failure retains that owner and denies all State IO.
    #[inline(never)]
    fn native_downloaded_content_begin(&mut self) -> Result<(), ()> {
        let n = self.native.as_mut().unwrap();
        if n.updates.command.is_some() || n.updates.engine.busy() || n.updates.rejected.is_some() {
            return Err(());
        }
        let backend = n.state.take_content_backend(true).map_err(|_| ())?;
        if let Err(r) = n
            .updates
            .engine
            .begin(backend, update::Command::Local, now())
        {
            if let Err(owner) = n.state.restore_content_backend(r.backend) {
                n.updates.rejected = Some(owner);
            }
            return Err(());
        }
        self.native_downloaded_content_run()?;
        if self
            .native
            .as_ref()
            .unwrap()
            .updates
            .engine
            .authorization_store()
            .is_none()
        {
            return Err(());
        }
        Ok(())
    }
    #[inline(never)]
    fn native_downloaded_content_run(&mut self) -> Result<(), ()> {
        loop {
            let n = self.native.as_mut().unwrap();
            if !n.updates.engine.active() {
                break;
            }
            if !rt::execution::live(self.bound, now()) {
                return Err(());
            }
            n.updates.engine.step(&mut n.updates.buffers, now());
            n.updates.engine.observe_after(now());
            pause();
        }
        if !matches!(
            self.native.as_ref().unwrap().updates.engine.outcome(),
            Some(update::Outcome::Complete(_))
        ) {
            return Err(());
        }
        Ok(())
    }
    #[inline(never)]
    fn native_downloaded_content_return(&mut self) -> Result<(), ()> {
        let n = self.native.as_mut().unwrap();
        n.updates.snapshot = None;
        if !n.updates.engine.snapshot_into(&mut n.updates.snapshot) {
            return Err(());
        }
        let backend = n.updates.engine.take_completed().ok_or(())?;
        if let Err(owner) = n.state.restore_content_backend(backend) {
            n.updates.rejected = Some(owner);
            return Err(());
        }
        Ok(())
    }
    // Keep the borrowed source Resolver frame out of the later affine commit call.
    #[inline(never)]
    fn native_downloaded_registry_selection(
        &mut self,
    ) -> Result<native_plan::state::RegistrySelection, ()> {
        self.native
            .as_mut()
            .unwrap()
            .with_sources(|state, sources| state.registry_selection(sources))
            .and_then(|r| r)
            .map_err(|_| ())?
            .ok_or(())
    }
    #[inline(never)]
    fn native_downloaded_retain_selection(&mut self) -> Result<(), ()> {
        let selection = self.native_downloaded_registry_selection()?;
        self.native_downloaded_content_begin()?;
        let n = self.native.as_mut().unwrap();
        let decision = n
            .updates
            .engine
            .authorization_store()
            .ok_or(())?
            .reconcile_selection(&n.state, selection)
            .map_err(|_| ())?;
        if let Some(decision) = decision {
            n.updates
                .engine
                .begin_selection_decision(decision, &n.state, now())
                .map_err(|_| ())?;
            self.native_downloaded_content_run()?;
        }
        self.native_downloaded_content_return()
    }
    #[inline(never)]
    fn native_downloaded_arm_join(
        &mut self,
        receipt: health::HealthReceipt,
        release_subject: bool,
    ) -> Result<(), ()> {
        let n = self.native.as_mut().unwrap();
        if n.updates.command.is_some()
            || n.updates.engine.busy()
            || n.updates.rejected.is_some()
            || n.system.downloaded.health_receipt.is_some()
        {
            return Err(());
        }
        n.system.downloaded.health_receipt = Some(receipt);
        n.system.downloaded.joining = true;
        n.system.downloaded.release_subject = release_subject;
        let backend = n.state.take_content_backend(true).map_err(|_| ())?;
        if let Err(r) = n
            .updates
            .engine
            .begin(backend, update::Command::Local, now())
        {
            if let Err(owner) = n.state.restore_content_backend(r.backend) {
                n.updates.rejected = Some(owner);
            }
            return Err(());
        }
        Ok(())
    }
    #[inline(never)]
    fn native_downloaded_join_tick(&mut self) -> Result<(), ()> {
        // Local authentication/publication continues the original cut captured
        // once at arm. No accepted IO or consumed receipt is retried on failure.
        self.native_downloaded_content_run()?;
        let n = self.native.as_mut().unwrap();
        let receipt = n.system.downloaded.health_receipt.take().ok_or(())?;
        n.updates
            .engine
            .begin_known_good(receipt, &n.state, now())
            .map_err(|_| ())?;
        self.native_downloaded_content_run()?;
        self.native_downloaded_content_return()?;
        let deadline = self.storage_deadline();
        let release = self
            .native
            .as_ref()
            .unwrap()
            .system
            .downloaded
            .release_subject;
        if release && self.actors[Child::App.index()].is_some() {
            let cohort = self
                .native
                .as_ref()
                .unwrap()
                .system
                .downloaded
                .cohort
                .ok_or(())?;
            self.native
                .as_mut()
                .unwrap()
                .with_sources(|state, sources| {
                    state.release_health_subject(&cohort, sources, deadline)
                })
                .and_then(|r| r)
                .map_err(|_| ())?;
            if let Some(subject) = self.native_downloaded_notice_subject() {
                self.native
                    .as_mut()
                    .unwrap()
                    .system
                    .downloaded
                    .notice
                    .release(subject);
            } else {
                self.native
                    .as_mut()
                    .unwrap()
                    .system
                    .downloaded
                    .notice
                    .discard();
            }
        }
        let n = self.native.as_mut().unwrap();
        n.system.view = n.state.system_snapshot(deadline).map_err(|_| ())?;
        n.system.downloaded.joining = false;
        n.system.downloaded.release_subject = false;
        n.system.pending_snapshot = true;
        Ok(())
    }
    #[inline(never)]
    fn native_downloaded_fault_object(
        &mut self,
        capsule: &health::FaultCapsule,
    ) -> Result<ev_store::CriticalFaultReport, ()> {
        self.native_downloaded_content_begin()?;
        let n = self.native.as_mut().unwrap();
        let bytes = capsule.encode();
        n.updates
            .engine
            .begin_fetch_put(256, Sha256::digest(bytes).into(), now())
            .map_err(|_| ())?;
        n.updates
            .engine
            .write_fetch_chunk(&bytes, now())
            .map_err(|_| ())?;
        n.updates.engine.seal_fetch_object(now()).map_err(|_| ())?;
        if n.updates
            .engine
            .read_retained_chunk(&mut n.updates.buffers.chunk, now())
            .map_err(|_| ())?
            != 256
        {
            return Err(());
        }
        let report = n
            .updates
            .engine
            .finish_fault_capsule(capsule, now())
            .map_err(|_| ())?;
        self.native_downloaded_content_return()?;
        Ok(report)
    }
    /// Called before diagnostics/reap while actual fault CONTROL is retained.
    /// Canonical no-fault2 is an ordinary stop and creates no fault capsule.
    pub(in crate::desktop) fn native_downloaded_stopped(&mut self, child: Child) {
        if self.native.as_ref().unwrap().system.phase != Some(Phase::Probation) {
            return;
        }
        self.native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .notice
            .discard();
        let Some(index) = CHILDREN.iter().position(|c| *c == child).map(|i| i + 1) else {
            return;
        };
        let actor = self.child(child);
        let mut words = [0; 6];
        for (i, word) in words.iter_mut().enumerate() {
            let r = rt::call(syscall::OBSERVE, actor.control, i as u64 + 1, 0);
            if r.status != 0 || r.capability != 0 {
                let s = &mut self.native.as_mut().unwrap().system;
                s.blocked = true;
                s.phase = Some(Phase::Failed);
                s.downloaded.probation = None;
                return;
            }
            *word = r.value;
        }
        if (words[0], words[1]) != (actor.identity.process, actor.identity.thread) {
            self.native.as_mut().unwrap().system.blocked = true;
            return;
        }
        let tick = now();
        let actual = health::Identity {
            process: words[0],
            thread: words[1],
            image: self.native_downloaded_image(child),
        };
        let capsule = self
            .native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .probation
            .as_mut()
            .ok_or(health::Error::Phase)
            .and_then(|probation| {
                probation.fault(
                    index,
                    actual,
                    health::Fault {
                        tick,
                        vector: words[2],
                        error: words[3],
                        address: words[4],
                        instruction: words[5],
                    },
                    tick,
                )
            });
        let result = capsule
            .map_err(|_| ())
            .and_then(|c| self.native_downloaded_fault_object(&c))
            .and_then(|report| {
                let deadline = self.storage_deadline();
                self.native
                    .as_mut()
                    .unwrap()
                    .state
                    .system_fail_component(report, deadline)
                    .map_err(|_| ())
            });
        let deadline = self.storage_deadline();
        let view = self
            .native
            .as_mut()
            .unwrap()
            .state
            .system_snapshot(deadline)
            .ok()
            .flatten();
        let s = &mut self.native.as_mut().unwrap().system;
        s.view = view;
        s.phase = Some(Phase::Failed);
        s.blocked = result.is_err();
        s.downloaded.probation = None;
        s.pending_snapshot = true;
    }
    pub(in crate::desktop) fn native_downloaded_failure_contained(&self) -> bool {
        let s = &self.native.as_ref().unwrap().system;
        s.mode == BootMode::SystemManaged && s.phase == Some(Phase::Failed)
    }
    pub(super) fn native_downloaded_tick(&mut self) {
        let s = &self.native.as_ref().unwrap().system;
        if s.bootstrapping || s.blocked {
            return;
        }
        if s.downloaded.joining {
            if self.native_downloaded_join_tick().is_err() {
                self.native.as_mut().unwrap().system.blocked = true;
            }
            return;
        }
        if s.downloaded.stop_subject {
            if let Some(app) = self.actors[Child::App.index()] {
                let r = rt::call(syscall::STOP_PROCESS, app.control, 0, 0);
                if r.value != 0 || r.capability != 0 || !matches!(r.status, 0 | 2) {
                    self.native.as_mut().unwrap().system.blocked = true;
                } else if r.status == 0 {
                    self.native.as_mut().unwrap().system.downloaded.stop_subject = false;
                }
            } else {
                self.native.as_mut().unwrap().system.downloaded.stop_subject = false;
            }
            return;
        }
        if s.needs_admission
            && !self.native_output_pending()
            && self.native.as_ref().unwrap().report.is_none()
        {
            let step = self.native.as_ref().unwrap().system.downloaded.beginning;
            let result = match step {
                Beginning::Prepare => self.native_downloaded_prepare_subject(),
                Beginning::Retain => self.native_downloaded_retain_selection(),
                Beginning::Start => self.native_downloaded_begin(),
            };
            if result.is_err() {
                self.native.as_mut().unwrap().system.blocked = true;
            } else {
                self.native.as_mut().unwrap().system.downloaded.beginning = match step {
                    Beginning::Prepare => Beginning::Retain,
                    Beginning::Retain | Beginning::Start => Beginning::Start,
                };
            }
            return;
        }
        if self.native.as_ref().unwrap().system.phase == Some(Phase::Probation) {
            let p = self
                .native
                .as_ref()
                .unwrap()
                .system
                .downloaded
                .probation
                .as_ref()
                .unwrap();
            let expired = now() >= p.deadline();
            if (p.ready() || expired) && self.native_downloaded_decide(expired).is_err() {
                self.native.as_mut().unwrap().system.blocked = true;
            }
        }
        if self.native.as_ref().unwrap().system.pending_snapshot && !self.native_output_pending() {
            self.native.as_mut().unwrap().system.pending_snapshot = false;
            self.native_queue_system_snapshot();
        }
    }
    #[inline(never)]
    fn native_downloaded_decide(&mut self, expired: bool) -> Result<(), ()> {
        let cohort = self
            .native
            .as_ref()
            .unwrap()
            .system
            .downloaded
            .cohort
            .ok_or(())?;
        let mut live = self.native_downloaded_live(&cohort);
        let mut probation = self
            .native
            .as_mut()
            .unwrap()
            .system
            .downloaded
            .probation
            .take()
            .ok_or(())?;
        let result = self.native_downloaded_decide_probation(&mut probation, &mut live, expired);
        if result.is_err() {
            self.native.as_mut().unwrap().system.downloaded.probation = Some(probation);
        }
        result
    }
    fn native_downloaded_decide_probation(
        &mut self,
        probation: &mut Probation,
        live: &mut Live,
        expired: bool,
    ) -> Result<(), ()> {
        if expired && !probation.ready() {
            self.native
                .as_mut()
                .unwrap()
                .system
                .downloaded
                .notice
                .discard();
            for i in 0..7 {
                live.observe(i)?;
            }
            let report = probation.missing_progress(now()).map_err(|_| ())?;
            let deadline = self.storage_deadline();
            let view = self
                .native
                .as_mut()
                .unwrap()
                .state
                .system_apply(SystemChange::Health(report), deadline)
                .map_err(|_| ())?;
            let s = &mut self.native.as_mut().unwrap().system;
            s.view = Some(view);
            s.phase = Some(Phase::Failed);
            s.pending_snapshot = true;
            s.downloaded.stop_subject = true;
            // A live missing-progress subject is ordinarily stopped, never a
            // manufactured exception. The failure selection precedes stop.
            return Ok(());
        }
        let cut = self.native.as_ref().unwrap().system.downloaded.original_cut;
        let n = self.native.as_mut().unwrap();
        probation
            .commit_probe(&mut n.state, now(), cut)
            .map_err(|_| ())?;
        let sources =
            Resolver::from_members(&n.packages, &n.images, n.updates.members()).map_err(|_| ())?;
        let receipt = probation
            .commit_health(&mut n.state, live, &sources, cut)
            .map_err(|_| ())?;
        // A matching System ACK is the health authority. Keep its compact
        // move-only receipt and original Local owner resident for the next tick.
        // Ordinary launch/owner work stays deferred until both durable refs join.
        self.native.as_mut().unwrap().system.phase = Some(Phase::Healthy);
        self.native_downloaded_arm_join(receipt, true)?;
        Ok(())
    }
    pub(super) fn native_downloaded_command(&mut self, command: Command) {
        #[cfg(not(feature = "native-owner-ui"))]
        {
            let p = self.native_downloaded_system_projection();
            let _cached_readonly = (
                p.mode,
                p.metadata,
                p.head,
                p.selected_package,
                p.current,
                p.busy,
                p.blocked,
            );
        }
        let n = self.native.as_ref().unwrap();
        if n.system.mode == BootMode::Recovery
            || n.system.bootstrapping
            || n.system.blocked
            || n.system.phase == Some(Phase::Probation)
            || n.transition.is_some()
            || n.starting
            || n.updates.engine.busy()
            || n.updates.command.is_some()
        {
            self.native_report(name(command), "busy");
            return;
        }
        let source = {
            let record = n.state.record();
            let staged = record
                .and_then(|r| r.staged())
                .and_then(|p| n.report_source(p.digest()));
            let active = record
                .and_then(|r| r.active())
                .and_then(|p| n.report_source(p.digest()));
            if command == Command::SystemStage {
                staged
            } else {
                active
                    .filter(|s| matches!(s, AppSource::Downloaded(_)))
                    .or(staged)
            }
        };
        let deadline = self.storage_deadline();
        // Resolve the very cohort this command will publish before any setup
        // creation. Activate names the actual System staged manifest; its
        // candidate need not be the Registry's current active/staged package.
        let cohort = if command == Command::SystemActivate {
            self.native
                .as_ref()
                .unwrap()
                .system
                .view
                .and_then(|v| v.staged)
                .and_then(|m| self.native_downloaded_resolve(&m))
                .map(|(_, cohort)| cohort)
        } else {
            source.and_then(|s| self.native_downloaded_cohort(s).ok())
        };
        let Some(cohort) = cohort else {
            self.native_report(name(command), "refused");
            return;
        };
        // Explicit owner System intent is bound to this actual Registry head
        // and checked downloaded candidate. Blank Note preparation precedes
        // System mutation; the final readonly check remains the actual gate.
        let intent = self.native.as_ref().unwrap().state.record().map(|record| {
            native_plan::state::StartupSelection::new(record.revision(), cohort.content().package)
        });
        let ready = intent.is_some_and(|intent| {
            self.native
                .as_mut()
                .unwrap()
                .with_sources(|state, sources| {
                    state.prepare_startup_setup(sources, intent, deadline)
                })
                .is_ok_and(|r| r == Ok(native_plan::state::SetupHint::Ready))
        });
        if !ready {
            let result = if self.native.as_ref().unwrap().state.recovery_required() {
                "recovery"
            } else {
                "refused"
            };
            self.native_report(name(command), result);
            return;
        }
        let result: Result<Option<SystemView>, ()> = match command {
            Command::SystemInitialize => {
                let state = &mut self.native.as_mut().unwrap().state;
                state
                    .system_initialize_downloaded(&cohort, deadline)
                    .map_err(|_| ())
                    .and_then(|()| state.system_snapshot(deadline).map_err(|_| ()))
            }
            Command::SystemStage | Command::SystemActivate => {
                let change = if command == Command::SystemStage {
                    SystemChange::Stage(cohort.manifest())
                } else {
                    SystemChange::Activate(cohort.manifest().generation)
                };
                self.native
                    .as_mut()
                    .unwrap()
                    .state
                    .system_apply(change, deadline)
                    .map(Some)
                    .map_err(|_| ())
            }
            _ => Err(()),
        };
        let success = result.is_ok();
        if let Ok(view) = result {
            let s = &mut self.native.as_mut().unwrap().system;
            s.view = view;
            s.downloaded.metadata = if view.is_some() {
                ev_diagnostics::system::State::Committed
            } else {
                ev_diagnostics::system::State::Unavailable
            };
            s.pending_snapshot = true;
        }
        // Current running cohort/admission never changes after owner selection.
        self.native_report(name(command), if success { "ok" } else { "refused" });
    }
}
