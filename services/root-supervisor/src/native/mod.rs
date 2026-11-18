//! Native owner policy adapter. Package bytes and System window have named
//! retained owners; actual execution IDs come only from ProcessIdentity38.
use super::*;
use ev_root_supervisor::native_plan::{
    self, Packages, Slot,
    owner::{Command, Lines},
    state::{Identity as DataIdentity, State},
};
use ev_root_supervisor::native_sources::{Source as AppSource, Sources};
use ev_userspace_contract::{
    app_data::{Refusal, Request as DataRequest, Response},
    root_v2::native as abi,
};
#[cfg(feature = "native-owner-ui")]
mod connection_runtime;
mod diagnostics;
#[cfg(feature = "native-network")]
mod downloaded_runtime;
#[cfg(feature = "native-network")]
mod image_runtime;
#[cfg(feature = "native-network")]
mod network_probe;
#[cfg(feature = "native-network")]
mod network_recovery;
#[cfg(feature = "native-network")]
mod network_runtime;
mod owner_runtime;
#[cfg(any(feature = "native-network", feature = "document-workflow"))]
mod resident;
mod storage;
mod system_runtime;
#[cfg(feature = "native-network")]
mod time_runtime;
#[cfg(feature = "native-network")]
mod update_runtime;
#[cfg(feature = "native-network")]
mod vm_entropy;
#[cfg(feature = "native-network")]
mod vm_rtc;

#[derive(Clone, Copy)]
struct Transition {
    target: Option<AppSource>,
    command: Command,
    from_shell: bool,
}
pub(super) struct Controller<'a> {
    #[cfg(feature = "native-owner-ui")]
    connection: connection_runtime::Owner,
    packages: Packages<'a>,
    #[cfg(feature = "native-network")]
    images: ev_root_supervisor::native_image::Images<image_runtime::Kernel>,
    #[cfg(feature = "native-network")]
    network: ev_root_supervisor::native_network::State,
    #[cfg(feature = "native-network")]
    network_recovery: network_recovery::Recovery,
    #[cfg(feature = "native-network")]
    #[cfg_attr(not(feature = "native-network-negative"), allow(dead_code))]
    network_probe: network_probe::Probe,
    #[cfg(feature = "native-network")]
    network_client: network_runtime::Client,
    #[cfg(feature = "native-network")]
    network_random: vm_entropy::Random,
    #[cfg(feature = "native-network")]
    network_clock: vm_rtc::Source,
    #[cfg(feature = "native-network")]
    network_time: time_runtime::Time,
    #[cfg(feature = "native-network")]
    updates: &'a mut update_runtime::Owner<'a>,
    #[cfg(feature = "native-network")]
    network_transfer: ev_root_supervisor::native_network::transfer::Transfer,
    #[cfg(feature = "native-network")]
    network_report: Option<(ev_root_supervisor::native_network::transfer::Progress, u64)>,
    #[cfg(feature = "native-network")]
    network_diagnostic: Option<ev_net_driver::diagnostic::Pending>,
    #[cfg(feature = "native-network")]
    network_diagnostic_reported: bool,
    #[cfg(feature = "native-network")]
    network_failure: Option<(u8, u8)>,
    #[cfg(feature = "native-network")]
    network_failure_reported: bool,
    #[cfg(feature = "native-network")]
    network_report_failed: bool,
    state: State<ev_block_service::store_io::DesktopEndpoint, storage::RootWindow<'a>>,
    #[cfg(feature = "native-session")]
    note_window: storage::NoteWindow,
    #[cfg(feature = "native-session")]
    note_reply: Option<delivery::RetainedReply>,
    #[cfg(feature = "native-session")]
    delivery_failure: Option<&'static str>,
    lines: Lines,
    transition: Option<Transition>,
    running: Option<AppSource>,
    #[cfg(feature = "document-workflow")]
    focused_input_minor: u16,
    preparing: Option<AppSource>,
    starting: bool,
    app_settled: bool,
    command_after_start: Option<Command>,
    input_bytes: usize,
    report: Option<abi::report::Frames>,
    report_frame: Option<[u8; 8]>,
    report_serial: u32,
    finish_after_report: bool,
    boot_launch_pending: bool,
    diagnostics: diagnostics::Diagnostics,
    system: system_runtime::System,
    owner_flow: owner_runtime::Owner,
}
impl Controller<'_> {
    #[cfg(feature = "document-workflow")]
    pub(super) fn focused_input_minor(&self) -> u16 {
        self.focused_input_minor
    }
    #[cfg(feature = "document-workflow")]
    fn capture_input_profile(&mut self, source: AppSource) {
        self.focused_input_minor = self
            .with_sources(|_, sources| {
                sources
                    .checked_source(source)
                    .ok()
                    .and_then(|p| {
                        p.app()
                            .contracts()
                            .find(|c| c.name == "ev.internal.focused-input" && c.major == 1)
                    })
                    .map_or(0, |c| c.minimum_minor)
            })
            .unwrap_or(0);
    }

    #[cfg(feature = "native-session")]
    pub(super) fn input_ready(&self) -> bool {
        let ready = self.app_settled && self.running.is_some();
        #[cfg(feature = "native-network")]
        let ready = ready && !self.system.downloaded.joining();
        #[cfg(feature = "native-session")]
        {
            ready && self.note_reply.is_none()
        }
        #[cfg(not(feature = "native-session"))]
        {
            ready
        }
    }
    #[cfg(feature = "native-session")]
    pub(super) fn state_fence_for_delivery(&mut self) {
        self.state.fence();
    }
    pub(super) fn running_package(&self) -> Option<[u8; 32]> {
        self.running.and_then(|source| self.source_digest(source))
    }
    /// Projection of already-retained metadata only; this never creates a
    /// resolver, image or permission from a label in a diagnostic frame.
    fn report_source(&self, digest: [u8; 32]) -> Option<AppSource> {
        if let Some(bank) = self.packages.slot(digest) {
            return Some(AppSource::Bank(bank));
        }
        #[cfg(feature = "native-network")]
        for (index, binding) in self.updates.bindings().into_iter().enumerate() {
            if let Some((slot, content)) = binding
                && content.package == digest
                && self.images.registered_capability(slot).is_some()
            {
                return Some(AppSource::Downloaded(if index == 0 {
                    ev_root_supervisor::native_sources::DownloadedSlot::B
                } else {
                    ev_root_supervisor::native_sources::DownloadedSlot::C
                }));
            }
        }
        None
    }
    fn source_digest(&self, source: AppSource) -> Option<[u8; 32]> {
        #[cfg(feature = "native-network")]
        {
            ev_root_supervisor::native_sources::Resolver::from_members(
                &self.packages,
                &self.images,
                self.updates.members(),
            )
            .ok()?
            .source_digest(source)
        }
        #[cfg(not(feature = "native-network"))]
        {
            self.packages.source_digest(source)
        }
    }
    #[cfg(feature = "document-workflow")]
    pub(super) fn document_snapshot(&self) -> [u8; 256] {
        self.note_window.snapshot()
    }
    #[cfg(feature = "native-network")]
    fn with_sources<R>(
        &mut self,
        f: impl FnOnce(
            &mut State<ev_block_service::store_io::DesktopEndpoint, storage::RootWindow<'_>>,
            &ev_root_supervisor::native_sources::Resolver<'_, '_, image_runtime::Kernel>,
        ) -> R,
    ) -> Result<R, native_plan::state::Error> {
        let sources = ev_root_supervisor::native_sources::Resolver::from_members(
            &self.packages,
            &self.images,
            self.updates.members(),
        )
        .map_err(|_| native_plan::state::Error::Package)?;
        Ok(f(&mut self.state, &sources))
    }
    #[cfg(not(feature = "native-network"))]
    fn with_sources<R>(
        &mut self,
        f: impl FnOnce(
            &mut State<ev_block_service::store_io::DesktopEndpoint, storage::RootWindow<'_>>,
            &Packages<'_>,
        ) -> R,
    ) -> Result<R, native_plan::state::Error> {
        Ok(f(&mut self.state, &self.packages))
    }
    pub(super) fn app_stopped(&mut self) {
        #[cfg(feature = "native-network")]
        self.system.downloaded.discard_notice();
        self.state.fence();
        self.running = None;
        self.starting = false;
        self.app_settled = false;
        self.command_after_start = None;
    }
}
fn name(c: Command) -> &'static str {
    match c {
        #[cfg(feature = "native-network-negative")]
        Command::NetDestination
        | Command::NetEndurance
        | Command::NetEnduranceStop
        | Command::NetPending
        | Command::NetDriverStop
        | Command::NetServiceStop => "cancel",
        Command::InstallA => "install",
        Command::StageB => "stage",
        Command::Activate => "activate",
        Command::Rollback => "rollback",
        Command::Remove => "remove",
        Command::ReinstallA => "reinstall",
        Command::Inspect => "inspect",
        Command::Cancel => "cancel",
        Command::Finish => "finish",
        Command::CrashShell => "crash-shell",
        #[cfg(feature = "document-workflow")]
        Command::CrashApp => "crash-app",
        #[cfg(feature = "native-network")]
        Command::TimeProbe => "time-probe",
        #[cfg(feature = "native-network")]
        Command::TimeCheck => "time-check",
        #[cfg(feature = "native-network")]
        Command::UpdateInitialize => "update-init",
        #[cfg(feature = "native-network")]
        Command::UpdateInspect => "update-inspect",
        #[cfg(feature = "native-network")]
        Command::UpdateFetch => "update-fetch",
        Command::InitializeGrants => "initialize-grants",
        Command::RememberNotes | Command::RememberPrivate => "remember",
        Command::RevokeGrant => "revoke",
        Command::SystemInitialize => "system-init",
        Command::SystemStage => "system-stage",
        Command::SystemActivate => "system-activate",
        Command::RecoverGood => "recover-good",
        Command::Continue => "cancel",
    }
}
fn report_slot(slot: Option<AppSource>) -> abi::report::Slot {
    match slot {
        None => abi::report::Slot::None,
        Some(AppSource::Bank(Slot::A)) => abi::report::Slot::A,
        Some(AppSource::Bank(Slot::B)) => abi::report::Slot::B,
        Some(AppSource::Downloaded(ev_root_supervisor::native_sources::DownloadedSlot::B)) => {
            abi::report::Slot::DownloadedB
        }
        Some(AppSource::Downloaded(ev_root_supervisor::native_sources::DownloadedSlot::C)) => {
            abi::report::Slot::DownloadedC
        }
    }
}
impl Root<'_> {
    pub(super) fn native_image(&self) -> u64 {
        let n = self.native.as_ref().unwrap();
        match n.preparing.or(n.running).unwrap_or_else(|| fail(940)) {
            AppSource::Bank(Slot::A) => self.bootstrap.handle(Role::AppImage),
            AppSource::Bank(Slot::B) => self.bootstrap.extra(abi::ExtraRole::AppBImage),
            #[cfg(feature = "native-network")]
            AppSource::Downloaded(source) => n.updates.bindings()[source.index()]
                .and_then(|(slot, _)| n.images.registered_capability(slot))
                .unwrap_or_else(|| fail(1043)),
            #[cfg(not(feature = "native-network"))]
            AppSource::Downloaded(_) => fail(1043),
        }
    }
    fn native_report(&mut self, op: &str, result: &str) {
        #[cfg(feature = "native-owner-ui")]
        self.native_connection_report(op, result);
        let n = self.native.as_ref().unwrap();
        let record = n.state.record();
        let active = record
            .and_then(|r| r.active())
            .and_then(|v| n.report_source(v.digest()));
        let staged = record
            .and_then(|r| r.staged())
            .and_then(|v| n.report_source(v.digest()));
        let previous = record
            .and_then(|r| r.previous())
            .and_then(|v| n.report_source(v.digest()));
        let actor = self.actors[Child::App.index()];
        let id = actor.map(|a| a.identity).unwrap_or(Identity {
            process: 0,
            thread: 0,
        });
        let data = n.state.data();
        let operation = match op {
            "open" => abi::report::Operation::Open,
            "boot" => abi::report::Operation::Boot,
            "install" => abi::report::Operation::Install,
            "stage" => abi::report::Operation::Stage,
            "activate" => abi::report::Operation::Activate,
            "rollback" => abi::report::Operation::Rollback,
            "remove" => abi::report::Operation::Remove,
            "reinstall" => abi::report::Operation::Reinstall,
            "inspect" => abi::report::Operation::Inspect,
            "cancel" => abi::report::Operation::Cancel,
            "finish" => abi::report::Operation::Finish,
            "crash-shell" => abi::report::Operation::CrashShell,
            "crash-app" => abi::report::Operation::CrashApp,
            "time-probe" => abi::report::Operation::TimeProbe,
            "time-check" => abi::report::Operation::TimeCheck,
            "update-init" => abi::report::Operation::UpdateInitialize,
            "update-inspect" => abi::report::Operation::UpdateInspect,
            "update-fetch" => abi::report::Operation::UpdateFetch,
            "initialize-grants" => abi::report::Operation::InitializeGrants,
            "remember" => abi::report::Operation::Remember,
            "revoke" => abi::report::Operation::Revoke,
            "system-init" => abi::report::Operation::SystemInitialize,
            "system-stage" => abi::report::Operation::SystemStage,
            "system-activate" => abi::report::Operation::SystemActivate,
            "recover-good" => abi::report::Operation::RecoverGood,
            _ => abi::report::Operation::Invalid,
        };
        let result = match result {
            "ok" => abi::report::ResultCode::Ok,
            "busy" => abi::report::ResultCode::Busy,
            "recovery" => abi::report::ResultCode::Recovery,
            _ => abi::report::ResultCode::Refused,
        };
        let snapshot = abi::report::Snapshot {
            operation,
            result,
            installed: record.is_some_and(|r| r.installed()),
            active: report_slot(active),
            staged: report_slot(staged),
            previous: report_slot(previous),
            process: id.process,
            thread: id.thread,
            revision: record.map_or(0, |r| r.revision()),
            data_epoch: data.map_or(0, |d| d.schema_epoch()),
            data_counter: data.map_or(0, |d| d.counter()),
            value: data.map_or(0, |d| d.value()),
            mutations: n.state.mutations(),
            recovery: n.state.recovery_required(),
        };
        let n = self.native.as_mut().unwrap();
        require(n.report.is_none(), 942);
        n.report_serial = n.report_serial.checked_add(1).unwrap_or_else(|| fail(943));
        #[cfg(feature = "native-network")]
        let frames = abi::report::Frames::new_v4(n.report_serial, snapshot);
        #[cfg(not(feature = "native-network"))]
        let frames = abi::report::Frames::new(n.report_serial, snapshot);
        n.report = Some(frames.unwrap_or_else(|_| fail(943)));
    }
    fn native_report_tick(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        let Some(report) = n.report.as_mut() else {
            return false;
        };
        if n.report_frame.is_none() {
            n.report_frame = report.next_frame();
        }
        let bytes = n.report_frame.unwrap_or_else(|| fail(962));
        let r = rt::send(self.bootstrap.handle(Role::Events), bytes);
        require(
            r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
            963,
        );
        if r.status == 0 {
            n.report_frame = None;
            if report.complete() {
                n.report = None;
            }
        }
        true
    }
    pub(super) fn native_launch(&mut self, from_shell: bool) {
        #[cfg(feature = "native-session")]
        let delivery_ready = self.delivery_healthy(delivery::Peer::Shell);
        #[cfg(not(feature = "native-session"))]
        let delivery_ready = true;
        if !self.native_system_can_launch() || !delivery_ready {
            if from_shell && self.actors[Child::Shell.index()].is_some() {
                self.control_shell(RootControl::LaunchRefused);
            }
            return;
        }
        if self.actors[Child::App.index()].is_some() {
            return;
        }
        if self.native.as_ref().unwrap().report.is_some() {
            // The queued snapshot binds the actual App at its first accepted
            // frame. Do not change that incarnation before its complete End.
            // A real Shell Launch remains pending until the snapshot drains.
            if from_shell {
                self.launch_pending = true;
            }
            return;
        }
        #[cfg(feature = "native-session")]
        if from_shell
            && !self
                .native
                .as_mut()
                .unwrap()
                .with_sources(|state, sources| state.active_source(sources))
                .is_ok_and(|r| r.is_ok_and(|s| s.is_some()))
        {
            use native_plan::state::BundledLaunch;
            let plan = {
                let n = self.native.as_ref().unwrap();
                n.state.bundled_launch(&n.packages)
            };
            if matches!(plan, Ok(BundledLaunch::Install)) {
                // This explicit bundled launch authorizes a NEW namespace;
                // failures never format an existing/corrupt namespace.
                let deadline = self.storage_deadline();
                let n = self.native.as_mut().unwrap();
                if n.state.install(&n.packages, deadline).is_err() {
                    self.control_shell(RootControl::LaunchRefused);
                    return;
                }
            }
            match plan {
                Ok(BundledLaunch::Install | BundledLaunch::ActivateA) => {
                    // Installation publishes stagedA, not activeA. Capture a
                    // new finite cut for the distinct prepared activation,
                    // then let the ordinary held-image-before-commit flow run.
                    let deadline = self.storage_deadline();
                    let n = self.native.as_mut().unwrap();
                    match n
                        .with_sources(|state, sources| {
                            state.prepare_source(
                                sources,
                                ev_app_registry::Change::Activate,
                                deadline,
                            )
                        })
                        .and_then(|result| result)
                    {
                        Ok(Some(AppSource::Bank(Slot::A))) => {
                            n.state.fence();
                            n.transition = Some(Transition {
                                target: Some(AppSource::Bank(Slot::A)),
                                command: Command::Activate,
                                from_shell: true,
                            });
                        }
                        _ => {
                            self.control_shell(RootControl::LaunchRefused);
                        }
                    }
                    return;
                }
                Ok(BundledLaunch::Start(_)) => (),
                Err(_) => {
                    self.control_shell(RootControl::LaunchRefused);
                    return;
                }
            }
        }
        let n = self.native.as_mut().unwrap();
        let active = n
            .with_sources(|state, sources| state.active_source(sources))
            .ok()
            .and_then(Result::ok)
            .flatten();
        if n.transition.is_some() || n.starting || active.is_none() {
            if from_shell {
                self.control_shell(RootControl::LaunchRefused);
            }
            return;
        }
        if self.hide_pending {
            if from_shell {
                self.launch_pending = true;
            }
            return;
        }
        self.native_start(active.unwrap(), from_shell);
    }
    fn native_start(&mut self, slot: AppSource, from_shell: bool) {
        self.app_notified = false;
        self.owned_launch = !from_shell;
        self.app_epoch = self
            .app_epoch
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .unwrap_or_else(|| fail(944));
        self.native.as_mut().unwrap().preparing = Some(slot);
        self.prepare(Child::App);
        self.reset(Producer::App, self.app_epoch);
        self.start(Child::App);
        let actual = self.child(Child::App).identity;
        let n = self.native.as_mut().unwrap();
        n.with_sources(|state, sources| {
            state.admit_source(
                sources,
                slot,
                DataIdentity {
                    process: actual.process,
                    thread: actual.thread,
                },
            )
        })
        .and_then(|result| result)
        .unwrap_or_else(|_| fail(945));
        #[cfg(feature = "document-workflow")]
        n.capture_input_profile(slot);
        n.preparing = None;
        n.running = Some(slot);
        n.starting = true;
        n.app_settled = false;
    }
    pub(super) fn native_data(&mut self, bytes: [u8; 8]) {
        let actual = self.child(Child::App).identity;
        #[cfg(feature = "native-session")]
        let Some((_, reply_ticket)) = self.delivery_reservation(delivery::Peer::App) else {
            return;
        };
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let response = match DataRequest::decode(&bytes, 0) {
            Ok(request) => n
                .with_sources(|state, sources| {
                    state.data_request(
                        sources,
                        DataIdentity {
                            process: actual.process,
                            thread: actual.thread,
                        },
                        request,
                        deadline,
                    )
                })
                .unwrap_or(Response::Refused(Refusal::Denied)),
            Err(_) => Response::Refused(Refusal::Malformed),
        };
        #[cfg(feature = "native-session")]
        self.delivery_publish(
            reply_ticket,
            response.encode(),
            deadline,
            delivery::Kind::Data,
        );
        #[cfg(not(feature = "native-session"))]
        send(
            self.channels[Channel::AppControl.index()],
            response.encode(),
            self.bound,
        );
    }
    #[cfg(feature = "document-workflow")]
    pub(super) fn native_document_allowed(
        &mut self,
        requester: ev_picker::Requester,
        access: ev_userspace_contract::document::Access,
    ) -> bool {
        self.native
            .as_mut()
            .unwrap()
            .with_sources(|_, sources| {
                use ev_zion::Capability;
                let Some(source) = sources.source(requester.app.package.bytes()) else {
                    return false;
                };
                let Ok(package) = sources.checked_source(source) else {
                    return false;
                };
                requester.alive
                    && ["ev.app.document", "ev.ui.document"].iter().all(|name| {
                        package
                            .app()
                            .contracts()
                            .any(|c| c.name == *name && c.major == 1)
                    })
                    && package.app().claimed_app.bytes() == requester.app.app.bytes()
                    && package.app().capability_requests().any(|c| {
                        c.capability
                            == if access == ev_userspace_contract::document::Access::Edit {
                                Capability::SelectedFileEdit
                            } else {
                                Capability::SelectedFileRead
                            }
                    })
            })
            .unwrap_or(false)
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_note(&mut self, bytes: [u8; 8]) {
        use ev_userspace_contract::session_note::{Operation, Outcome, Refusal, Request};
        let Ok(request) = Request::decode(&bytes, 0) else {
            return;
        };
        let Some((target, ticket)) = self.delivery_reservation(delivery::Peer::App) else {
            return;
        };
        if self.native_note_reply_pending() {
            let response = self
                .native
                .as_mut()
                .unwrap()
                .with_sources(|state, sources| {
                    state
                        .note_busy(
                            sources,
                            DataIdentity {
                                process: target.process,
                                thread: target.thread,
                            },
                            request,
                        )
                        .response
                        .encode()
                })
                .unwrap_or_else(|_| request.reply(Outcome::Refused(Refusal::Denied)).encode());
            self.delivery_publish(ticket, response, self.deadline(), delivery::Kind::Data);
            return;
        }
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let proposal = (request.operation() == Operation::Write).then(|| n.note_window.snapshot());
        // No lifecycle/event pump can run across this actual Store/child owner.
        let reply = n
            .with_sources(|state, sources| {
                state.note_request(
                    sources,
                    DataIdentity {
                        process: target.process,
                        thread: target.thread,
                    },
                    request,
                    proposal.as_ref(),
                    deadline,
                )
            })
            .unwrap_or(ev_root_supervisor::native_plan::state::NoteReply {
                response: request.reply(Outcome::Refused(Refusal::Denied)),
                bytes: None,
            });
        n.note_reply = Some(delivery::RetainedReply::new(ticket, target, reply.bytes));
        self.delivery_publish(
            ticket,
            reply.response.encode(),
            deadline,
            delivery::Kind::Note,
        );
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_prepare_note_reply(&mut self, entry: delivery::Entry) -> bool {
        let n = self.native.as_mut().unwrap();
        let Some(reply) = n.note_reply.as_ref() else {
            return false;
        };
        if !reply.ready(entry) {
            return false;
        }
        if let Some(bytes) = reply.body() {
            n.note_window.publish(bytes);
        }
        true
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_note_delivery(
        &mut self,
        entry: delivery::Entry,
        outcome: delivery::Outcome,
    ) {
        let n = self.native.as_mut().unwrap();
        if n.note_reply
            .as_mut()
            .is_some_and(|reply| reply.complete(entry, outcome))
        {
            n.note_reply = None;
        }
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_cancel_note_reply(&mut self, target: delivery::Target) {
        let n = self.native.as_mut().unwrap();
        if n.note_reply
            .as_ref()
            .is_some_and(|reply| reply.cancelled_target(target))
        {
            n.note_reply = None;
        }
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_note_reply_pending(&self) -> bool {
        self.native.as_ref().is_some_and(|n| n.note_reply.is_some())
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_delivery_start_failed(&mut self) {
        if let Some(n) = self.native.as_mut() {
            n.app_settled = false;
            if n.starting {
                n.delivery_failure = Some(n.command_after_start.take().map_or("boot", name));
                n.starting = false;
            }
        }
    }

    fn native_command(&mut self, command: Command) {
        #[cfg(feature = "native-network-negative")]
        if self.native_negative_command(command) {
            return;
        }
        #[cfg(feature = "native-network")]
        if self.native_update_command(command) {
            return;
        }
        #[cfg(feature = "native-network")]
        if command == Command::TimeProbe {
            self.native_time_probe_command();
            return;
        }
        #[cfg(feature = "native-network")]
        if command == Command::TimeCheck {
            self.native_time_check_command();
            return;
        }
        if matches!(
            command,
            Command::InstallA
                | Command::StageB
                | Command::ReinstallA
                | Command::Activate
                | Command::Rollback
                | Command::Remove
        ) && !self.native_system_can_launch()
        {
            self.native_report(name(command), "refused");
            return;
        }
        match command {
            Command::SystemInitialize | Command::SystemStage | Command::SystemActivate => {
                self.native_system_command(command);
                return;
            }
            Command::InitializeGrants
            | Command::RememberNotes
            | Command::RememberPrivate
            | Command::RevokeGrant
            | Command::RecoverGood => {
                self.native_owner_command(command);
                return;
            }
            Command::Continue => {
                self.native_command(Command::Finish);
                return;
            }
            _ => (),
        }
        if self.native.as_ref().unwrap().system.mode() == abi::catalogue::BootMode::Recovery
            && !matches!(
                command,
                Command::Finish | Command::Inspect | Command::Cancel
            )
        {
            self.native_report(name(command), "refused");
            return;
        }
        #[cfg(feature = "native-session")]
        if matches!(command, Command::Activate | Command::Rollback)
            && !self.delivery_healthy(delivery::Peer::Shell)
        {
            self.native_report(name(command), "refused");
            return;
        }
        let deadline = self.storage_deadline();
        let busy = self
            .native
            .as_ref()
            .is_some_and(|n| n.transition.is_some() || n.starting)
            || (command == Command::Finish
                && (self.pending.is_some() || self.hide_pending || self.shell_recovering || {
                    #[cfg(feature = "native-session")]
                    {
                        self.delivery_pending()
                    }
                    #[cfg(not(feature = "native-session"))]
                    {
                        false
                    }
                }));
        if busy {
            self.native_report(name(command), "busy");
            return;
        }
        #[cfg(feature = "native-network")]
        if command == Command::Finish && self.native_network_receipt_pending() {
            self.native_report("finish", "busy");
            return;
        }
        #[cfg(feature = "native-network")]
        if command == Command::Finish && !self.native_network_shutdown() {
            self.native_report("finish", "refused");
            return;
        }
        match command {
            #[cfg(feature = "native-network")]
            Command::TimeProbe => unreachable!(),
            #[cfg(feature = "native-network")]
            Command::TimeCheck => unreachable!(),
            #[cfg(feature = "native-network")]
            Command::UpdateInitialize | Command::UpdateInspect | Command::UpdateFetch => {
                unreachable!()
            }
            Command::SystemInitialize
            | Command::SystemStage
            | Command::SystemActivate
            | Command::InitializeGrants
            | Command::RememberNotes
            | Command::RememberPrivate
            | Command::RevokeGrant
            | Command::RecoverGood
            | Command::Continue => unreachable!(),
            #[cfg(feature = "native-network-negative")]
            Command::NetDestination
            | Command::NetEndurance
            | Command::NetEnduranceStop
            | Command::NetPending
            | Command::NetDriverStop
            | Command::NetServiceStop => unreachable!(),
            Command::Inspect => self.native.as_mut().unwrap().diagnostics.inspect_next = Some(0),
            Command::Cancel => self.native_report(name(command), "ok"),
            #[cfg(feature = "document-workflow")]
            Command::CrashApp => {
                let allowed = self.actors[Child::App.index()]
                    .map(|a| self.requester(a))
                    .is_some_and(|requester| {
                        self.native
                            .as_mut()
                            .unwrap()
                            .with_sources(|_, sources| {
                                sources
                                    .source(requester.app.package.bytes())
                                    .and_then(|source| sources.checked_source(source).ok())
                                    .is_some_and(|package| {
                                        package
                                            .app()
                                            .contracts()
                                            .any(|c| c.name == "ev.test.document" && c.major == 1)
                                    })
                            })
                            .unwrap_or(false)
                    });
                if allowed {
                    self.queue_control(
                        delivery::Peer::App,
                        ev_userspace_contract::document_test::Command::CrashApplication.encode(),
                        delivery::Kind::Control,
                    );
                    self.native_report("crash-app", "ok");
                } else {
                    self.native_report("crash-app", "refused");
                }
            }
            Command::CrashShell => {
                if self.actors[Child::Shell.index()].is_some() {
                    self.control_shell(RootControl::CrashShell);
                    self.native_report(name(command), "ok");
                } else {
                    self.native_report(name(command), "refused");
                }
            }
            Command::Finish => {
                // This is a requested Native shutdown only. The executor must
                // still stop all actual peers, settle calls and retire owners.
                self.native_report("finish", "ok");
                self.native.as_mut().unwrap().finish_after_report = true;
            }
            Command::InstallA | Command::StageB | Command::ReinstallA => {
                let n = self.native.as_mut().unwrap();
                let result = match command {
                    Command::InstallA => n.state.install(&n.packages, deadline),
                    Command::StageB | Command::ReinstallA => {
                        let change = if command == Command::StageB {
                            ev_app_registry::Change::Stage {
                                package: n.packages.digest(Slot::B),
                            }
                        } else {
                            ev_app_registry::Change::Reinstall {
                                package: n.packages.digest(Slot::A),
                            }
                        };
                        n.with_sources(|state, sources| state.metadata(sources, change, deadline))
                            .and_then(|result| result)
                    }
                    _ => unreachable!(),
                };
                self.native_report(name(command), if result.is_ok() { "ok" } else { "refused" });
            }
            Command::Activate | Command::Rollback | Command::Remove => {
                let change = match command {
                    Command::Activate => ev_app_registry::Change::Activate,
                    Command::Rollback => ev_app_registry::Change::Rollback,
                    _ => ev_app_registry::Change::Remove,
                };
                let n = self.native.as_mut().unwrap();
                match n
                    .with_sources(|state, sources| state.prepare_source(sources, change, deadline))
                    .and_then(|result| result)
                {
                    Ok(target) => {
                        n.state.fence();
                        n.transition = Some(Transition {
                            target,
                            command,
                            from_shell: false,
                        });
                    }
                    Err(_) => self.native_report(name(command), "refused"),
                }
            }
        }
    }
    fn native_transition(&mut self) {
        let Some(t) = self.native.as_ref().unwrap().transition else {
            return;
        };
        // A prepared App mutation cannot bypass the same graph/admission gate
        // used by its command and ordinary Shell launch. Retain it until ready.
        if !self.native_system_can_launch() {
            return;
        }
        if let Some(app) = self.actors[Child::App.index()] {
            let r = rt::call(syscall::STOP_PROCESS, app.control, 0, 0);
            require(r.value == 0 && r.capability == 0, 946);
            require(matches!(r.status, 0 | 2), 947);
            return;
        }
        if self.hide_pending || self.shell_recovering {
            return;
        }
        // The exact held image is created BEFORE publication. Its mutable
        // executable owner remains kernel-retained, and it has not run yet.
        if let Some(slot) = t.target {
            self.app_notified = false;
            self.owned_launch = !t.from_shell;
            self.app_epoch = self
                .app_epoch
                .checked_add(1)
                .filter(|n| *n != u32::MAX)
                .unwrap_or_else(|| fail(948));
            self.native.as_mut().unwrap().preparing = Some(slot);
            self.prepare(Child::App);
            self.reset(Producer::App, self.app_epoch);
        }
        let deadline = self.storage_deadline();
        let n = self.native.as_mut().unwrap();
        let success = n
            .with_sources(|state, sources| state.commit(sources, deadline))
            .is_ok_and(|result| result.is_ok());
        n.transition = None;
        if !success {
            if self.actors[Child::App.index()].is_some() {
                self.native_discard_held();
            }
            self.native_report(name(t.command), "refused");
            return;
        }
        if let Some(slot) = t.target {
            self.start(Child::App);
            let actual = self.child(Child::App).identity;
            let n = self.native.as_mut().unwrap();
            n.with_sources(|state, sources| {
                state.admit_source(
                    sources,
                    slot,
                    DataIdentity {
                        process: actual.process,
                        thread: actual.thread,
                    },
                )
            })
            .and_then(|result| result)
            .unwrap_or_else(|_| fail(949));
            #[cfg(feature = "document-workflow")]
            n.capture_input_profile(slot);
            n.preparing = None;
            n.running = Some(slot);
            n.starting = true;
            n.app_settled = false;
            n.command_after_start = Some(t.command);
        } else {
            self.native_report(name(t.command), "ok");
        }
    }
    fn native_discard_held(&mut self) {
        let app = self.child(Child::App);
        require(app.identity.process == 0, 950);
        loop {
            let r = rt::call(syscall::STOP_PROCESS, app.control, 0, 0);
            if r.status == 0 {
                break;
            }
            require(r.status == 2 && rt::execution::live(self.bound, now()), 951);
            pause();
        }
        loop {
            let r = rt::call(syscall::REAP, app.control, 0, 0);
            if r.status == 0 {
                break;
            }
            require(r.status == 2 && rt::execution::live(self.bound, now()), 952);
            pause();
        }
        checked(syscall::CLOSE, app.control, 0, 0);
        require(app.job != 0, 1122); // Held candidates retain setup authority.
        checked(syscall::CLOSE, app.job, 0, 0);
        #[cfg(feature = "native-session")]
        self.delivery_cancel_actor(Child::App, app);
        self.actors[Child::App.index()] = None;
        self.native.as_mut().unwrap().preparing = None;
    }
    pub(super) fn native_settled(&mut self, message: RootControl) {
        if matches!(message,RootControl::AppStarted(epoch)|RootControl::AppRestored(epoch) if epoch==self.app_epoch)
        {
            self.native.as_mut().unwrap().app_settled = true;
        }
    }
    #[cfg(feature = "native-session")]
    pub(super) fn native_progress_only(&mut self) {
        if self.delivery_waiting_ui() || self.delivery_quarantining() {
            self.native_diagnostic_flush_only();
            self.native_report_tick();
            return;
        }
        self.native_system_tick();
        if !self.native_diagnostic_tick() {
            self.native_report_tick();
        }
    }
    pub(super) fn native_tick(&mut self) {
        #[cfg(feature = "native-session")]
        if self.delivery_waiting_ui()
            || self.delivery_quarantining()
            || self.delivery_outbox_pending()
        {
            // Required current-clock System health/fault/phase work still runs
            // through progress_only; ordinary owner/transition/UART/network
            // work cannot consume a retained producer output's original cut.
            self.native_progress_only();
            return;
        }
        // Health observes its original deadline even while a long diagnostic
        // is draining. Owner flow must run AFTER that drain, or its one-outbox
        // prompt completion wait would deadlock the very output it awaits.
        self.native_system_tick();
        #[cfg(feature = "native-network")]
        if self.native_downloaded_notice_tick() {
            // The new finite Shell control gets its normal outbound attempt
            // before ordinary network/owner/transition/UART work can begin.
            return;
        }
        #[cfg(feature = "native-network")]
        if !self.native_system_defers_owner_work() && self.native_network_tick() {
            return;
        }
        if self.native_diagnostic_tick() {
            return;
        }
        if self.native_report_tick() {
            return;
        }
        #[cfg(feature = "native-owner-ui")]
        if self.native_connection_tick() {
            return;
        }
        #[cfg(feature = "native-network")]
        if self.native_update_tick() {
            if self.native.as_ref().unwrap().report.is_none() {
                self.native_console_tick();
            }
            return;
        }
        if self.native.as_ref().unwrap().system.bootstrapping
            || self.native_system_defers_owner_work()
        {
            // Actual receive/lifecycle work ran in Root::tick; health and
            // pending diagnostics/reports above still drain during probation.
            // Do not let ordinary owner commands consume its fixed64tick cut.
            return;
        }
        #[cfg(feature = "native-session")]
        if let Some(operation) = self.native.as_mut().unwrap().delivery_failure.take() {
            self.native_report(operation, "refused");
            return;
        }
        if self.native_owner_tick() {
            return;
        }
        if self.native.as_ref().unwrap().finish_after_report {
            #[cfg(feature = "native-session")]
            if self.delivery_pending() {
                return;
            }
            // Ordinary receive above drained one slot. Never block on a full
            // self-owned mailbox: retain the request and retry next tick.
            let r = rt::send(self.bootstrap.handle(Role::Events), *b"EVNFIN01");
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                964,
            );
            if r.status == 0 {
                rt::exit(0);
            }
            return;
        }
        if self.launch_pending && !self.hide_pending && self.native_system_can_launch() {
            self.launch_pending = false;
            self.native.as_mut().unwrap().boot_launch_pending = false;
            self.native_launch(true);
            return;
        }
        if self.native.as_ref().unwrap().boot_launch_pending && self.native_system_can_launch() {
            self.native.as_mut().unwrap().boot_launch_pending = false;
            self.native_launch(false);
            return;
        }
        self.native_transition();
        if self.native.as_ref().unwrap().report.is_some() {
            return;
        }
        // Report completion only after actual typed data replies, Ready and
        // first Present. A queued metadata publication is never a launch fact.
        if self.app_notified
            && self
                .native
                .as_ref()
                .is_some_and(|n| n.starting && n.app_settled)
        {
            let n = self.native.as_mut().unwrap();
            n.starting = false;
            let command = n.command_after_start.take();
            #[cfg(feature = "native-network")]
            if self.native_selection_after_start(command) {
                return;
            }
            self.native_report(command.map_or("boot", name), "ok");
            return;
        }
        self.native_console_tick();
    }
    fn native_console_tick(&mut self) {
        let uart = self.bootstrap.handle(Role::OwnerUart);
        let status = rt::call4(syscall::PORT_INPUT, uart, 0x3fd, 1, 0);
        require(
            status.status == 0
                && status.value <= 255
                && status.capability == 0
                && status.serial == 0,
            953,
        );
        if status.value & 1 == 0 {
            return;
        }
        let n = self.native.as_mut().unwrap();
        // Finite fixtures keep4096 lifetime bytes; a sustained session keeps a
        // checked cumulative count. Per-line/gate bounds remain independent.
        let next_input = ev_root_supervisor::native_diagnostics::session::next_input_count(
            n.input_bytes,
            cfg!(feature = "native-session"),
        )
        .unwrap_or_else(|| fail(954));
        let input = rt::call4(syscall::PORT_INPUT, uart, 0x3f8, 1, 0);
        require(
            input.status == 0 && input.value <= 255 && input.capability == 0 && input.serial == 0,
            955,
        );
        n.input_bytes = next_input;
        match n.lines.push(input.value as u8) {
            Ok(Some(command)) => self.native_command(command),
            Err(_) => self.native_report("invalid", "refused"),
            Ok(None) => (),
        }
    }
}
/// # Safety
/// Named selected loader owns the readonly Native3(720/2560) or V4(912/4096)
/// startup/catalogue and both exact immutable bank extents, guards and zero tails.
/// The unique System window is retained RW and never aliased into App.
pub(super) unsafe fn run(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == profile::STARTUP_SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record > 509 * 4096
            && record < (1 << 47) - 4096
            && rt::execution::validate(bound, now(), cfg!(feature = "native-session")).is_ok()
            && bound.checked_add(1024).is_some(),
        956,
    );
    let base = record - 509 * 4096;
    // SAFETY: exact retained Native startup page, independently syntax checked.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, profile::STARTUP_SIZE) };
    let bootstrap = profile::NativeFullGraph::parse(bytes).unwrap_or_else(|_| fail(957));
    // SAFETY: exact readonly catalogue at page507, no mutable App window alias.
    let catbytes = unsafe {
        core::slice::from_raw_parts((base + 507 * 4096) as *const u8, profile::CATALOGUE_SIZE)
    };
    #[cfg(feature = "native-network")]
    let parsed =
        native_plan::verify_network(catbytes, bootstrap.context()).unwrap_or_else(|_| fail(958));
    #[cfg(not(feature = "native-network"))]
    let parsed = if cfg!(feature = "native-session") {
        native_plan::verify_session(catbytes, bootstrap.context())
    } else {
        native_plan::verify(catbytes, bootstrap.context())
    }
    .unwrap_or_else(|_| fail(958));
    // SAFETY: named loader validated physical1..63-page banks, exact lengths,
    // guards, full hash and zero tails before dispatch. Parser rechecks contents.
    let a = unsafe {
        core::slice::from_raw_parts(
            (base + 384 * 4096) as *const u8,
            parsed.package_a_bytes() as usize,
        )
    };
    // SAFETY: same independently owned readonly B bank, disjoint from A.
    let b = unsafe {
        core::slice::from_raw_parts(
            (base + 304 * 4096) as *const u8,
            parsed.package_b_bytes() as usize,
        )
    };
    #[cfg(feature = "native-network")]
    let packages =
        Packages::verify_network(catbytes, bootstrap.context(), a, b).unwrap_or_else(|_| fail(959));
    #[cfg(not(feature = "native-network"))]
    let packages = if cfg!(feature = "native-session") {
        Packages::verify_session(catbytes, bootstrap.context(), a, b)
    } else {
        Packages::verify(catbytes, bootstrap.context(), a, b)
    }
    .unwrap_or_else(|_| fail(959));
    #[cfg(feature = "native-network")]
    let catalogue = profile::Catalogue::from_network(parsed);
    #[cfg(not(feature = "native-network"))]
    let catalogue = root_v2::catalogue::Catalogue::decode(packages.catalogue().base().bytes())
        .unwrap_or_else(|_| fail(960));
    let context = bootstrap.context();
    let mut epoch = [0; 16];
    epoch[..8].copy_from_slice(&context.epoch.to_le_bytes());
    epoch[8..].copy_from_slice(&context.incarnation.to_le_bytes());
    // SAFETY: this is the only Rust owner of the actual admitted System window;
    // all region stores exclusively reborrow its blocked transport.
    let window = unsafe { storage::RootWindow::new(record) };
    let owner = UserId::new(*b"EVROSION-OWNER01").unwrap();
    #[cfg(any(feature = "native-network", feature = "document-workflow"))]
    // SAFETY: actual immutable admitted startup/catalogue and private claim
    // remain owned through this Root execution; called once before any child.
    let root = unsafe { resident::initialize_root(bootstrap, catalogue, bound, epoch, owner) };
    #[cfg(not(any(feature = "native-network", feature = "document-workflow")))]
    let mut root = Root {
        #[cfg(feature = "native-session")]
        delivery: core::cell::RefCell::new(delivery::State::new()),
        bootstrap: Bootstrap::Native(bootstrap),
        catalogue,
        channels: [0; profile::CHANNEL_SLOTS],
        actors: [None; COUNT],
        bound,
        app_epoch: 0,
        shell_epoch: 1,
        request: 0,
        pending: None,
        picker: Picker::new(PickerEpoch::new(epoch).unwrap(), 131072).unwrap(),
        owner,
        session: SessionId::new(epoch).unwrap(),
        boot: BootEpoch::new(epoch).unwrap(),
        last_cancel: false,
        hide_pending: false,
        launch_pending: false,
        app_notified: false,
        input_epoch: 1,
        shell_recovering: false,
        native: None,
        owned_launch: false,
    };
    #[cfg(feature = "native-network")]
    root.native_retire_legacy_bad_shell_source();
    root.native_boot_prefix();
    // Reuse actual SystemBlock in the preserved first15 canonical channels;
    // V4 appends16/17 without occupying Events15. Role tags create no endpoint.
    let backend = storage::backend(root.channels[Channel::SystemBlock.index()], window, bound)
        .unwrap_or_else(|| fail(961));
    // Retain this sole backend/controller owner in place. Root borrows it;
    // moving a duplicate Controller into the already-live Root inflated the
    // guarded userspace stack while package and Store validation nested below.
    let mode = packages.catalogue().boot_mode();
    #[cfg(not(feature = "native-network"))]
    let mut native = Controller {
        packages,
        #[cfg(feature = "native-network")]
        network: ev_root_supervisor::native_network::State::new(),
        #[cfg(feature = "native-network")]
        // SAFETY: V4 admission supplies the unique retained Client505 page,
        // distinct from RootSystem508/Note506 and the Service/Driver NIC page.
        network_client: unsafe { network_runtime::client(record, root.channels[Channel::NetClientRpc.index()]) },
        #[cfg(feature = "native-network")]
        network_random: vm_entropy::Random::unavailable(ev_time_contract::Domain::new(context.epoch).unwrap_or_else(|_| fail(1022))),
        #[cfg(feature = "native-network")]
        network_transfer: ev_root_supervisor::native_network::transfer::Transfer::new(),
        #[cfg(feature = "native-network")]
        network_report: None,
        #[cfg(feature = "native-network")]
        network_failure: None,
        #[cfg(feature = "native-network")]
        network_failure_reported: false,
        #[cfg(feature = "native-network")]
        network_report_failed: false,
        state: State::new(backend),
        #[cfg(feature = "native-session")]
        // SAFETY: exact measured Root506 claim is retained until shutdown.
        note_window: unsafe { storage::NoteWindow::new(record) },
        #[cfg(feature = "native-session")]
        note_reply: None,
        #[cfg(feature = "native-session")]
        delivery_failure: None,
        lines: Lines::new(),
        transition: None,
        running: None,
        #[cfg(feature="document-workflow")]
        focused_input_minor:0,
        preparing: None,
        starting: false,
        app_settled: false,
        command_after_start: None,
        input_bytes: 0,
        report: None,
        report_frame: None,
        report_serial: 0,
        finish_after_report: false,
        boot_launch_pending: false,
        diagnostics: diagnostics::Diagnostics::new(),
        system: system_runtime::System::new(mode, bound),
        owner_flow: owner_runtime::Owner::new(),
    };
    #[cfg(not(feature = "native-network"))]
    {
        root.native = Some(&mut native);
    }
    #[cfg(feature = "native-network")]
    // SAFETY: named V4 startup/private .bss and actual package/backend borrows
    // remain owned through this Root incarnation; exactly one initializer.
    {
        // SAFETY: forwards the exact retained V4 package/window/private-storage
        // contract above, with scoped borrows and one claim before child start.
        root.native = Some(unsafe {
            resident::initialize(
                packages,
                backend,
                record,
                root.channels[Channel::NetClientRpc.index()],
                root.bootstrap.handle(Role::CreatorJob),
                context,
                mode,
                bound,
            )
        });
    }
    #[cfg(feature = "native-network")]
    let opened = mode == abi::catalogue::BootMode::Recovery || root.native_cold_startup();
    #[cfg(not(feature = "native-network"))]
    let opened = if mode == abi::catalogue::BootMode::Recovery {
        true
    } else {
        let deadline = root.storage_deadline();
        let n = root.native.as_mut().unwrap();
        n.state.open(&n.packages, deadline).is_ok()
    };
    if mode != abi::catalogue::BootMode::Recovery {
        root.native_common_graph();
    }
    #[cfg(feature = "native-network")]
    if mode != abi::catalogue::BootMode::Recovery {
        root.native_network_start();
    }
    root.native_system_prepare();
    if mode == abi::catalogue::BootMode::Standalone {
        // The actual initial readonlySystem snapshot completes before Shell.
        while root.native_output_pending() {
            root.tick();
        }
        let _canary = root.native_self_live();
        root.native_start_system_shell();
        root.wait_ready(Child::Shell);
    }
    root.native.as_mut().unwrap().system.bootstrapping = false;
    root.native_report("open", if opened { "ok" } else { "recovery" });
    if opened && mode == abi::catalogue::BootMode::Standalone && !cfg!(feature = "native-session") {
        root.native.as_mut().unwrap().boot_launch_pending = true;
    }
    loop {
        root.tick();
    }
}
