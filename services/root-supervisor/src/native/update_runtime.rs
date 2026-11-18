//! Actual Root-only owned content continuation. The resident bytes are private
//! to this Root incarnation; no heap, window alias or static package borrow.
use super::*;
use ev_root_supervisor::{native_acquisition as acq, native_update as update};
type Backend<'a> = native_plan::storage::content::OwnedBackend<
    ev_block_service::store_io::DesktopEndpoint,
    storage::RootWindow<'a>,
>;
mod remote;
pub(super) struct Owner<'a> {
    pub(super) engine: update::Update<Backend<'a>>,
    pub(super) buffers: acq::Buffers,
    pub(super) command: Option<Command>,
    completed_at: Option<u64>,
    terminal_queued: bool,
    reports: update::progress::Reports,
    next_progress: u64,
    pub(super) rejected: Option<Backend<'a>>,
    pub(super) snapshot: Option<acq::Snapshot>,
    cold: ev_root_supervisor::native_cold::Loader,
    fetch: ev_root_supervisor::native_fetch::Fetch,
    selection: Option<native_plan::state::RegistrySelection>,
    remote: Option<remote::Mode>,
    selection_checked: bool,
    selection_committing: bool,
    remote_failed: bool,
}
const WORDS: usize = core::mem::size_of::<Owner<'static>>().div_ceil(16);
static STORAGE: super::resident::slot::Slot<WORDS> = super::resident::slot::Slot::new();
/// # Safety
/// Once per actual private V4 Root, before any IO. The actual Backend's window
/// and startup lifetime bound the scoped owner; no typed static borrow escapes.
#[inline(never)]
pub(super) unsafe fn owner<'a>(_: &storage::Backend<'a>) -> &'a mut Owner<'a> {
    let mut claim = STORAGE.claim::<Owner<'a>>().unwrap_or_else(|_| fail(1026));
    let p = claim.pointer();
    // SAFETY: exhaustive distinct fields, permanent claim, no reference exists.
    // Buffers contains only byte arrays, so zero initialization is fully valid
    // and does not create a17KiB automatic constructor temporary.
    let _: fn(Owner<'a>) = |Owner {
                                engine: _,
                                buffers: _,
                                command: _,
                                completed_at: _,
                                terminal_queued: _,
                                reports: _,
                                next_progress: _,
                                rejected: _,
                                snapshot: _,
                                cold: _,
                                fetch: _,
                                selection: _,
                                remote: _,
                                selection_checked: _,
                                selection_committing: _,
                                remote_failed: _,
                            }| {};
    // SAFETY: the exhaustive pattern above and each distinct field below cover
    // this one aligned claim; zero is valid for every Buffers byte array.
    unsafe {
        core::ptr::addr_of_mut!((*p).engine).write(update::Update::new());
        core::ptr::addr_of_mut!((*p).buffers).write_bytes(0, 1);
        core::ptr::addr_of_mut!((*p).command).write(None);
        core::ptr::addr_of_mut!((*p).completed_at).write(None);
        core::ptr::addr_of_mut!((*p).terminal_queued).write(false);
        core::ptr::addr_of_mut!((*p).reports).write(update::progress::Reports::new());
        core::ptr::addr_of_mut!((*p).next_progress).write(512);
        core::ptr::addr_of_mut!((*p).rejected).write(None);
        core::ptr::addr_of_mut!((*p).snapshot).write(None);
        core::ptr::addr_of_mut!((*p).cold).write(ev_root_supervisor::native_cold::Loader::new());
        core::ptr::addr_of_mut!((*p).fetch).write(ev_root_supervisor::native_fetch::Fetch::new());
        core::ptr::addr_of_mut!((*p).selection).write(None);
        core::ptr::addr_of_mut!((*p).remote).write(None);
        core::ptr::addr_of_mut!((*p).selection_checked).write(false);
        core::ptr::addr_of_mut!((*p).selection_committing).write(false);
        core::ptr::addr_of_mut!((*p).remote_failed).write(false);
        claim.initialized()
    }
}
impl Owner<'_> {
    #[cfg(feature = "native-owner-ui")]
    pub(super) fn connection_fenced(&self) -> bool {
        self.rejected.is_some()
            || matches!(
                self.engine.outcome(),
                Some(update::Outcome::Failed(
                    update::Failure::Clock | update::Failure::Storage
                ))
            )
    }
    #[cfg(feature = "native-owner-ui")]
    pub(super) fn connection_unformatted(&self) -> bool {
        self.command.is_none()
            && !self.engine.busy()
            && self.rejected.is_none()
            && matches!(self.engine.outcome(), Some(update::Outcome::Unformatted))
    }
    #[cfg(feature = "native-owner-ui")]
    pub(super) fn connection_checking(&self) -> bool {
        self.fetch.checking()
    }

    pub(super) fn members(&self) -> [Option<ev_root_supervisor::native_sources::Member>; 2] {
        self.cold.members().unwrap_or([None; 2])
    }
    pub(super) fn bindings(&self) -> [Option<(usize, acq::Content)>; 2] {
        self.cold.bindings().unwrap_or([None; 2])
    }
    pub(super) fn snapshot(&self) -> Option<&acq::Snapshot> {
        if self.command.is_some() || self.engine.busy() || self.rejected.is_some() {
            return None;
        }
        self.identity_snapshot()
            .filter(|_| matches!(self.engine.outcome(), Some(update::Outcome::Complete(_))))
    }
    /// Prior authenticated sealed identity remains local even after a later
    /// refusal or while IO is unavailable. Provenance must still contain an App
    /// fault then; State independently fences all IO on the actual Backend.
    /// This metadata cannot authorize a new repository decision.
    pub(super) fn identity_snapshot(&self) -> Option<&acq::Snapshot> {
        self.snapshot.as_ref()
    }
    fn queue(&mut self, stage: u8, result: u8, progress: u32, issued: u64) -> bool {
        self.reports.push(stage, result, progress, issued)
    }
    fn flush(&mut self, events: u64) {
        if let Some(p) = self.reports.attempt(now()) {
            let r = rt::send(events, p.bytes);
            self.reports.complete(r.status, r.value, r.capability);
        }
    }
    fn terminal(&mut self, tick: u64) {
        let Some(outcome) = self.engine.outcome() else {
            return;
        };
        let issued = *self.completed_at.get_or_insert(tick);
        if self.terminal_queued {
            return;
        }
        let progress = self.engine.scanned() as u32;
        let (stage, result, arg) = match outcome {
            update::Outcome::Complete(s) => {
                if self.command == Some(Command::UpdateInitialize) {
                    (3, 0, progress)
                } else {
                    let Ok(revision) = u32::try_from(s.revision) else {
                        self.reports.push(0, 0, 0, issued);
                        self.terminal_queued = true;
                        return;
                    };
                    (4, 0, revision)
                }
            }
            update::Outcome::Unformatted => (5, 6, progress),
            update::Outcome::Cancelled => (5, 5, progress),
            update::Outcome::Failed(reason) => (
                5,
                match reason {
                    update::Failure::Clock => 1,
                    update::Failure::Storage => 2,
                    update::Failure::Authentication => 3,
                    update::Failure::NotBlank => 4,
                },
                progress,
            ),
        };
        self.terminal_queued = self.queue(stage, result, arg, issued);
    }
}
impl Root<'_> {
    /// Before the first AppRegistry lookup. Only Block is running, so every
    /// bounded child finishes before yielding; no lifecycle/UI pump can alias
    /// this exact pre-open Backend or the shared private chunk.
    #[inline(never)]
    pub(super) fn native_cold_startup(&mut self) -> bool {
        if !self.native_cold_mount() {
            self.native.as_mut().unwrap().state.refuse_content_startup();
            return false;
        }
        let deadline = self.storage_deadline();
        self.native
            .as_mut()
            .unwrap()
            .with_sources(|state, sources| state.open(sources, deadline))
            .is_ok_and(|result| result.is_ok())
    }
    #[inline(never)]
    fn native_cold_begin(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        if n.images.initialize(now()).is_err() {
            return false;
        }
        let Ok(backend) = n.state.take_content_backend(true) else {
            return false;
        };
        if let Err(r) = n
            .updates
            .engine
            .begin(backend, update::Command::Inspect, now())
        {
            n.updates.rejected = Some(r.backend);
            return false;
        }
        true
    }
    // The Backend handoff's large return slots must not stay on the stack
    // above unrelated canonical IO/crypto continuations.
    #[inline(never)]
    fn native_cold_mount(&mut self) -> bool {
        if !self.native_cold_begin() {
            return false;
        }
        let n = self.native.as_mut().unwrap();
        while n.updates.engine.active() {
            n.updates.engine.step(&mut n.updates.buffers, now());
            n.updates.engine.observe_after(now());
            pause();
        }
        match n.updates.engine.outcome() {
            Some(update::Outcome::Complete(_)) => loop {
                let result = n.updates.cold.step(
                    &mut n.updates.engine,
                    &mut n.images,
                    &mut n.updates.buffers,
                    now(),
                );
                n.updates.engine.observe_after(now());
                if !matches!(
                    n.updates.engine.outcome(),
                    Some(update::Outcome::Complete(_))
                ) {
                    return false;
                }
                match result {
                    Ok(true) => break,
                    Ok(false) => pause(),
                    Err(_) => return false,
                }
            },
            // Unformatted checkpoint detection performs no write and grants
            // no blank-volume/provisioning authority. A saved downloaded
            // registry will still refuse against the banks-only resolver.
            Some(update::Outcome::Unformatted) => (),
            _ => return false,
        }
        self.native_cold_return()
    }
    #[inline(never)]
    fn native_cold_return(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        if matches!(
            n.updates.engine.outcome(),
            Some(update::Outcome::Complete(_))
        ) && !n.updates.engine.snapshot_into(&mut n.updates.snapshot)
        {
            return false;
        }
        let Some(backend) = n.updates.engine.take_completed() else {
            return false;
        };
        if let Err(owner) = n.state.restore_content_backend(backend) {
            n.updates.rejected = Some(owner);
            return false;
        }
        true
    }
    pub(super) fn native_update_command(&mut self, command: Command) -> bool {
        if command == Command::UpdateFetch {
            self.native_fetch_command();
            return true;
        }
        let pending = self.native.as_ref().unwrap().updates.command.is_some();
        if command == Command::Cancel && pending {
            if self.native.as_ref().unwrap().updates.remote.is_some() {
                // A live affine time/network exchange cannot be discarded by
                // the ordinary disk-only cancellation path.
                self.native_report("cancel", "busy");
                return true;
            }
            let n = self.native.as_mut().unwrap();
            let cancelled = n.updates.engine.cancel();
            if cancelled {
                n.updates.command = Some(Command::Cancel);
            }
            self.native_report("cancel", if cancelled { "ok" } else { "recovery" });
            return true;
        }
        if !matches!(command, Command::UpdateInitialize | Command::UpdateInspect) {
            if pending && command != Command::Finish {
                self.native_report(name(command), "busy");
                return true;
            }
            if command == Command::Finish
                && (self.native.as_ref().unwrap().updates.remote.is_some()
                    || self.native.as_ref().unwrap().updates.engine.active()
                    || self.native.as_ref().unwrap().updates.reports.pending())
            {
                self.native_report("finish", "busy");
                return true;
            }
            return false;
        }
        let n = self.native.as_ref().unwrap();
        if pending
            || n.updates.engine.busy()
            || n.updates.rejected.is_some()
            || n.network_time.active()
            || n.transition.is_some()
            || n.starting
            || self.pending.is_some()
            || self.hide_pending
            || self.shell_recovering
            || self.delivery_pending()
        {
            self.native_report(name(command), "busy");
            return true;
        }
        let n = self.native.as_mut().unwrap();
        let Ok(backend) = n.state.take_content_backend(true) else {
            self.native_report(name(command), "refused");
            return true;
        };
        let tick = now();
        let operation = if command == Command::UpdateInitialize {
            update::Command::Initialize
        } else {
            update::Command::Inspect
        };
        match n.updates.engine.begin(backend, operation, tick) {
            Ok(()) => {
                n.updates.command = Some(command);
                n.updates.completed_at = None;
                n.updates.terminal_queued = false;
                n.updates.next_progress = 512;
                if command == Command::UpdateInitialize {
                    n.updates.queue(1, 0, 0, tick);
                }
            }
            Err(r) => {
                if let Err(owner) = n.state.restore_content_backend(r.backend) {
                    n.updates.rejected = Some(owner);
                }
                self.native_report(name(command), "refused");
            }
        }
        true
    }
    #[inline(never)]
    pub(super) fn native_update_tick(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        n.updates.flush(self.bootstrap.handle(Role::Events));
        let Some(command) = n.updates.command else {
            return false;
        };
        if n.updates.remote.is_some() {
            return self.native_fetch_tick(command);
        }
        let tick = now();
        if n.updates.engine.active() {
            n.updates.engine.step(&mut n.updates.buffers, tick);
            n.updates.engine.observe_after(now());
        }
        if n.updates.engine.active() {
            let scanned = n.updates.engine.scanned();
            if scanned >= n.updates.next_progress {
                // A busy diagnostic never stalls scan counters or renews IO.
                n.updates.next_progress = (scanned / 512 + 1) * 512;
                let _ = n.updates.queue(2, 0, scanned as u32, tick);
            }
            return true;
        }
        self.native_update_complete(command)
    }
    // Completed Snapshot/Backend handoff cannot inflate a frame retained above
    // the unrelated IO/crypto stepping branch.
    #[inline(never)]
    fn native_update_complete(&mut self, command: Command) -> bool {
        let n = self.native.as_mut().unwrap();
        n.updates.terminal(now());
        // Restore the actual owner independently of diagnostic capacity.
        if matches!(
            n.updates.engine.outcome(),
            Some(update::Outcome::Complete(_))
        ) && n.updates.engine.busy()
        {
            n.updates.snapshot = None;
            n.updates.engine.snapshot_into(&mut n.updates.snapshot);
        } else if matches!(
            n.updates.engine.outcome(),
            Some(update::Outcome::Unformatted)
        ) {
            n.updates.snapshot = None;
        }
        if let Some(backend) = n.updates.engine.take_completed()
            && let Err(owner) = n.state.restore_content_backend(backend)
        {
            n.updates.rejected = Some(owner);
        }
        if let Some(backend) = n.updates.engine.release_settled_refusal()
            && let Err(owner) = n.state.restore_content_backend(backend)
        {
            n.updates.rejected = Some(owner);
        }
        if !n.updates.terminal_queued {
            return true;
        }
        n.updates.command = None;
        let result = match n.updates.engine.outcome() {
            _ if n.updates.rejected.is_some() => "recovery",
            Some(update::Outcome::Complete(_)) if n.updates.snapshot().is_some() => "ok",
            Some(update::Outcome::Unformatted | update::Outcome::Cancelled) => "refused",
            Some(update::Outcome::Failed(_)) if !n.updates.engine.busy() => "refused",
            _ => "recovery",
        };
        if command != Command::Cancel {
            self.native_report(name(command), result);
        }
        true
    }
}
