//! Actual owner-only acquisition and local selected-source durability. All
//! continuations borrow the existing single IO/chunk/image/client owners.
use super::*;
use ev_root_supervisor::{native_fetch as fetch, native_sources::Member};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Fetch,
    Selection,
}
impl Root<'_> {
    pub(super) fn native_fetch_command(&mut self) {
        let n = self.native.as_ref().unwrap();
        let blocked = n.updates.command.is_some()
            || n.updates.engine.busy()
            || n.updates.rejected.is_some()
            || n.network_time.active()
            || n.transition.is_some()
            || n.starting
            || self.pending.is_some()
            || self.hide_pending
            || self.shell_recovering
            || self.delivery_pending();
        if blocked {
            self.native_report("update-fetch", "busy");
            return;
        }
        // Only this explicit owner Fetch can prepare a genuinely blank
        // protected baseline; no content/network/floor work has started yet.
        if !self.native_fetch_setup() {
            let result = if self.native.as_ref().unwrap().state.recovery_required() {
                "recovery"
            } else {
                "refused"
            };
            self.native_report("update-fetch", result);
            return;
        }
        let n = self.native.as_ref().unwrap();
        if n.network.phase() != ev_root_supervisor::native_network::Phase::Running
            || !n.network_transfer.succeeded()
            || n.network_client.quarantined()
            || n.network_clock.failed()
            || n.images.failed()
        {
            self.native_report("update-fetch", "refused");
            return;
        }
        if !self.native_remote_begin(Command::UpdateFetch, Mode::Fetch) {
            self.native_report("update-fetch", "refused");
        }
    }
    pub(in crate::desktop::native) fn native_fetch_setup(&mut self) -> bool {
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        n.state.prepare_fetch_setup(&n.packages, deadline).is_ok()
    }
    /// Called after actual held-before-publication activation and UI startup.
    /// Delay its final owner ACK until selected retention is durable. This is
    /// local prior selection, never probation, health or KnownGood promotion.
    pub(in crate::desktop::native) fn native_selection_after_start(
        &mut self,
        command: Option<Command>,
    ) -> bool {
        let Some(command) = command else { return false };
        if !matches!(command, Command::Activate | Command::Rollback)
            || !matches!(
                self.native.as_ref().unwrap().running,
                Some(AppSource::Downloaded(_))
            )
        {
            return false;
        }
        if !self.native_remote_begin(command, Mode::Selection) {
            self.native_report(name(command), "recovery");
        }
        true
    }
    #[inline(never)]
    fn native_remote_begin(&mut self, command: Command, mode: Mode) -> bool {
        let n = self.native.as_mut().unwrap();
        if n.updates.command.is_some() || n.updates.engine.busy() || n.updates.rejected.is_some() {
            return false;
        }
        // Receipt and selected identity come from the actual current Registry
        // and retained immutable Images, immediately before the exclusive loan.
        let Ok((selection, selected)) = n
            .with_sources(|state, sources| {
                let selection = state.registry_selection(sources)?;
                let selected = state
                    .active_source(sources)?
                    .and_then(|s| sources.source_digest(s).map(|digest| (s, digest)));
                Ok::<_, native_plan::state::Error>((selection, selected))
            })
            .and_then(|v| v)
        else {
            return false;
        };
        let Ok(backend) = n.state.take_content_backend(true) else {
            return false;
        };
        let tick = now();
        if let Err(r) = n
            .updates
            .engine
            .begin(backend, update::Command::Fetch, tick)
        {
            if let Err(owner) = n.state.restore_content_backend(r.backend) {
                n.updates.rejected = Some(owner);
            }
            return false;
        }
        n.updates.fetch = fetch::Fetch::new();
        if mode == Mode::Fetch && n.updates.fetch.begin(tick, selected).is_err() {
            n.updates.engine.refuse_fetch(now());
            n.updates.remote_failed = true;
        } else {
            n.updates.remote_failed = false;
        }
        n.updates.selection = selection;
        n.updates.selection_checked = false;
        n.updates.selection_committing = false;
        n.updates.remote = Some(mode);
        n.updates.command = Some(command);
        true
    }
    /// Separate branch frames keep Snapshot/Decision return slots out of the
    /// ordinary IO/crypto stepping call chain. No second owner/workspace exists.
    #[inline(never)]
    pub(super) fn native_fetch_tick(&mut self, command: Command) -> bool {
        if self.native.as_ref().unwrap().updates.remote_failed {
            return self.native_fetch_return(command);
        }
        if !self.native.as_ref().unwrap().updates.selection_checked {
            return self.native_fetch_selection(command);
        }
        if self.native.as_ref().unwrap().updates.remote == Some(Mode::Selection) {
            return self.native_fetch_return(command);
        }
        let n = self.native.as_mut().unwrap();
        if n.updates.fetch.waiting_time() {
            if !n.network_time.active() && n.updates.fetch.time_finished().is_err() {
                self.native_fetch_refused();
            }
            return true;
        }
        let scope = n.packages.catalogue().network().unwrap().network_policy();
        let result = n.updates.fetch.step(
            &mut n.updates.engine,
            &mut n.network_client,
            scope,
            &mut n.images,
            &mut n.updates.buffers,
            now(),
        );
        n.updates.engine.observe_after(now());
        match result {
            Ok(fetch::Event::Working) => (),
            Ok(fetch::Event::NeedTime) => {
                let n = self.native.as_mut().unwrap();
                let armed = n
                    .updates
                    .engine
                    .original_cut()
                    .is_some_and(|cut| n.network_time.arm_for_fetch(cut));
                if !armed || n.updates.fetch.time_armed().is_err() {
                    self.native_fetch_refused();
                }
            }
            Ok(fetch::Event::NeedPreparation) => self.native_fetch_prepare(),
            Ok(fetch::Event::NeedAuthorization) => self.native_fetch_authorize(),
            Ok(fetch::Event::Published { slot }) => {
                if !self.native_fetch_member(slot) {
                    self.native_fetch_refused();
                } else {
                    return self.native_fetch_return(command);
                }
            }
            Err(_) => self.native_fetch_refused(),
        }
        true
    }
    #[inline(never)]
    fn native_fetch_selection(&mut self, _command: Command) -> bool {
        let n = self.native.as_mut().unwrap();
        if n.updates.engine.active() {
            n.updates.engine.step(&mut n.updates.buffers, now());
            n.updates.engine.observe_after(now());
            return true;
        }
        if n.updates.engine.authorization_store().is_none() {
            self.native_fetch_refused();
            return true;
        }
        if n.updates.selection_committing {
            n.updates.selection_committing = false;
            n.updates.selection_checked = true;
            return true;
        }
        let Some(receipt) = n.updates.selection.take() else {
            n.updates.selection_checked = true;
            return true;
        };
        let decision = n
            .updates
            .engine
            .authorization_store()
            .unwrap()
            .reconcile_selection(&n.state, receipt);
        match decision {
            Ok(Some(decision)) => {
                if n.updates
                    .engine
                    .begin_selection_decision(decision, &n.state, now())
                    .is_err()
                {
                    self.native_fetch_refused();
                } else {
                    n.updates.selection_committing = true;
                }
            }
            Ok(None) => n.updates.selection_checked = true,
            Err(_) => self.native_fetch_refused(),
        }
        true
    }
    #[inline(never)]
    fn native_fetch_prepare(&mut self) {
        let n = self.native.as_mut().unwrap();
        let result = n
            .updates
            .fetch
            .preparation_input(&n.updates.buffers)
            .ok()
            .zip(n.updates.engine.authorization_store())
            .ok_or(acq::Fault::Phase)
            .and_then(|((root, bundle), store)| {
                n.network_time.prepare_remote_metadata(
                    &mut n.network_clock,
                    self.bootstrap.handle(Role::RtcPorts),
                    store,
                    root,
                    bundle,
                )
            });
        match result {
            Ok(preparation) => {
                if n.updates
                    .fetch
                    .prepared(preparation, &n.updates.engine)
                    .is_err()
                {
                    self.native_fetch_refused();
                }
            }
            Err(_) => self.native_fetch_refused(),
        }
    }
    #[inline(never)]
    fn native_fetch_authorize(&mut self) {
        let n = self.native.as_mut().unwrap();
        let result = n
            .updates
            .fetch
            .remote(&n.updates.buffers, &n.images)
            .ok()
            .zip(n.updates.engine.authorization_parts())
            .ok_or(acq::Fault::Phase)
            .and_then(|(remote, (store, workspace))| {
                n.network_time.authorize_remote_into(
                    &mut n.network_clock,
                    self.bootstrap.handle(Role::RtcPorts),
                    store,
                    remote,
                    workspace,
                )
            });
        match result {
            Ok(()) => {
                if n.updates.engine.begin_prepared_fetch(now()).is_err()
                    || n.updates.fetch.decision_started().is_err()
                {
                    self.native_fetch_refused();
                }
            }
            Err(_) => self.native_fetch_refused(),
        }
    }

    #[inline(never)]
    fn native_fetch_member(&mut self, slot: usize) -> bool {
        let n = self.native.as_mut().unwrap();
        let Ok(content) = n.updates.fetch.published_content() else {
            return false;
        };
        let Some(snapshot) = n.updates.engine.retained_snapshot() else {
            return false;
        };
        let Ok(member) = Member::capture(&n.images, slot, snapshot, content) else {
            return false;
        };
        n.updates.cold.adopt(&n.images, member).is_ok()
    }
    fn native_fetch_refused(&mut self) {
        let n = self.native.as_mut().unwrap();
        n.updates.fetch.refuse();
        n.updates.engine.refuse_fetch(now());
        n.updates.engine.observe_after(now());
        n.updates.remote_failed = true;
    }
    #[inline(never)]
    fn native_fetch_return(&mut self, command: Command) -> bool {
        let n = self.native.as_mut().unwrap();
        let successful = !n.updates.remote_failed;
        if successful {
            n.updates.snapshot = None;
            if !n.updates.engine.snapshot_into(&mut n.updates.snapshot) {
                self.native_fetch_refused();
                return true;
            }
        }
        if let Some(backend) = n
            .updates
            .engine
            .take_completed()
            .or_else(|| n.updates.engine.release_settled_refusal())
            && let Err(owner) = n.state.restore_content_backend(backend)
        {
            n.updates.rejected = Some(owner);
        }
        let healthy = !n.updates.engine.busy() && n.updates.rejected.is_none();
        let mode = n.updates.remote.take();
        n.updates.command = None;
        n.updates.selection = None;
        if successful && healthy && mode == Some(Mode::Fetch) {
            let package = n.updates.fetch.published_content().unwrap().package;
            let deadline = self.storage_deadline();
            let n = self.native.as_mut().unwrap();
            let staged = n
                .with_sources(|state, sources| {
                    state.metadata(
                        sources,
                        ev_app_registry::Change::Stage { package },
                        deadline,
                    )
                })
                .is_ok_and(|result| result.is_ok());
            self.native_report(name(command), if staged { "ok" } else { "recovery" });
        } else {
            self.native_report(
                name(command),
                if successful && healthy {
                    "ok"
                } else if healthy {
                    "refused"
                } else {
                    "recovery"
                },
            );
        }
        true
    }
}
