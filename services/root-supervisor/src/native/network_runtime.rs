//! Actual V4 lifecycle: private qualified random owner, protected control
//! window, joined Start ACK/Ready and cooperative real device Stop/scrub.
use super::*;
use ev_net_driver::{
    protocol::{WINDOW_BYTES, Window as WindowIo},
    pump::ProtectedRpc,
};
use ev_root_supervisor::native_network::transfer::{Error as TransferError, Progress};
use ev_root_supervisor::native_network::{Identity as NetworkIdentity, Node, Phase};
pub(super) struct Window {
    address: usize,
}
impl WindowIo for Window {
    type Error = ();
    fn read(&mut self, n: usize) -> Result<u8, ()> {
        if n >= WINDOW_BYTES {
            return Err(());
        }
        // SAFETY: exact admitted V4 Client505 mapping remains owned throughout
        // protected RPC and cannot be republished after an unknown completion.
        Ok(unsafe { ((self.address + n) as *const u8).read_volatile() })
    }
    fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
        if n >= WINDOW_BYTES {
            return Err(());
        }
        // SAFETY: same unique retained page; no shared Rust reference crosses
        // independently mutable process memory or an actual syscall.
        unsafe { ((self.address + n) as *mut u8).write_volatile(b) };
        Ok(())
    }
}
pub(super) type Client = ev_root_supervisor::native_network::client::Client<Window, ProtectedRpc>;
/// # Safety
/// Actual V4 admission retains Client505 at exactly four pages below startup.
pub(super) unsafe fn client(record: u64, endpoint: u64) -> Client {
    Client::new(
        Window {
            address: (record - 4 * 4096) as usize,
        },
        ProtectedRpc::new(endpoint).unwrap_or_else(|| fail(1023)),
    )
}
fn node(child: Child) -> Option<Node> {
    match child {
        Child::NetDriver => Some(Node::Driver),
        Child::NetService => Some(Node::Service),
        _ => None,
    }
}
fn identity(actor: Actor) -> NetworkIdentity {
    NetworkIdentity {
        control: actor.control,
        process: actor.identity.process,
        thread: actor.identity.thread,
    }
}
impl Root<'_> {
    pub(super) fn native_network_start(&mut self) {
        let cut = self.storage_deadline();
        self.native
            .as_mut()
            .unwrap()
            .network
            .begin(now(), cut)
            .unwrap_or_else(|_| fail(1020));
        for child in [Child::NetDriver, Child::NetService] {
            self.prepare(child);
            self.start(child);
            let actual = identity(self.child(child));
            self.native
                .as_mut()
                .unwrap()
                .network
                .bind(node(child).unwrap(), actual)
                .unwrap_or_else(|_| fail(1021));
            loop {
                let n = &mut self.native.as_mut().unwrap().network;
                if n.expire(now()).is_err()
                    || (child == Child::NetDriver && n.prepared())
                    || (child == Child::NetService && n.waiting())
                {
                    break;
                }
                self.tick();
            }
            if self.native.as_ref().unwrap().network.unavailable() {
                break;
            }
        }
        if self.native.as_ref().unwrap().network.waiting() {
            self.native_network_initialize();
        }
        while self.native_network_receipt_pending() {
            self.tick();
        }
    }
    fn native_network_initialize(&mut self) {
        let n = self.native.as_mut().unwrap();
        let catalogue = n.packages.catalogue().network().unwrap();
        // This actual image is admitted only by the trusted, exact reviewed
        // NetworkBoot launcher. Hash/CPUID alone cannot authenticate that host.
        // No physical-host or arbitrary-QEMU qualification is implied here.
        if n.network_random
            .reseed_after_reviewed_vm_launch(catalogue.device(), now)
            .is_err()
        {
            n.network_random.source_failed();
            self.native_network_failure(1, 1);
            return; // unseeded, device still Prepared; healthy shutdown remains possible
        }
        // A fresh provider domain is generated once per Root incarnation.
        // RTC failure withholds security time, independently of local UI/NIC.
        let _ = n.network_clock.bind_domain(&mut n.network_random);
        let _ = n
            .network_clock
            .sample(self.bootstrap.handle(Role::RtcPorts));
        let mut seed = [0; 8];
        if n.network_random.fill(now(), &mut seed).is_err() {
            n.network_random.source_failed();
            self.native_network_failure(1, 1);
            return;
        }
        let issued = now();
        let cut = issued
            .checked_add(1024)
            .filter(|n| *n != u64::MAX)
            .unwrap_or_else(|| fail(1024));
        let accepted = n.network.initialize(issued, cut).is_ok()
            && n.network_client
                .initialize(&seed, catalogue.network_policy(), issued, cut)
                .is_ok();
        for byte in &mut seed {
            // SAFETY: private local protocol seed, never exposed as a reference
            // across IPC; erase the temporary independently of optimization.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        let actual = identity(self.child(Child::NetService));
        let n = self.native.as_mut().unwrap();
        if !accepted || n.network.initialized(actual, now()).is_err() {
            n.network.fail();
            n.network_random.source_failed();
            self.native_network_failure(1, 3);
            return;
        }
        // Never receive/lifecycle-pump while Client505 is loaned. The exact
        // protected reply above retired it before accepting the Ready event.
        while self.native.as_ref().unwrap().network.phase() == Phase::Initializing {
            self.tick();
            if self.native.as_mut().unwrap().network.expire(now()).is_err() {
                break;
            }
        }
        if self.native.as_ref().unwrap().network.phase() != Phase::Running {
            self.native.as_mut().unwrap().network_random.source_failed();
            self.native_network_failure(1, 2);
        } else {
            self.native_network_report(Progress {
                stage: 1,
                result: 0,
                argument: 1,
            });
        }
    }
    pub(super) fn native_network_receipt_pending(&self) -> bool {
        self.native.as_ref().is_some_and(|n| {
            n.network_report.is_some()
                || n.network_failure.is_some()
                || n.network_clock.pending()
                || n.network_time.pending()
        })
    }
    pub(super) fn native_network_report(&mut self, progress: Progress) {
        let n = self.native.as_mut().unwrap();
        if n.network_report.is_some() {
            n.network_report_failed = true;
            return;
        }
        let Some(cut) = now().checked_add(4096).filter(|n| *n != u64::MAX) else {
            n.network_report_failed = true;
            return;
        };
        n.network_report = Some((progress, cut));
    }
    fn native_network_transfer_diagnostic(&mut self, error: TransferError) {
        let n = self.native.as_mut().unwrap();
        if n.network_diagnostic_reported {
            return;
        }
        let Some(operation) = n.network_client.last_operation() else {
            return;
        };
        let diagnostic = match error {
            TransferError::Client(error) => error.diagnostic(operation),
            TransferError::Counter => {
                u8::try_from(n.network_transfer.calls())
                    .ok()
                    .and_then(|calls| {
                        ev_net_driver::diagnostic::Diagnostic::checked(
                            3,
                            operation as u8,
                            9,
                            n.network_transfer.last_tcp().unwrap_or(255),
                            calls,
                            0,
                        )
                    })
            }
            _ => None,
        };
        let Some(diagnostic) = diagnostic else {
            return;
        };
        n.network_diagnostic_reported = true;
        n.network_diagnostic = ev_net_driver::diagnostic::Pending::new(diagnostic, now());
    }
    fn native_network_failure(&mut self, stage: u8, result: u8) {
        let n = self.native.as_mut().unwrap();
        n.network_time.source_failed(false);
        n.network_random.source_failed();
        if !n.network_failure_reported && n.network_failure.is_none() {
            n.network_failure = Some((stage, result));
        }
    }
    /// One diagnostic SEND attempt per ordinary tick, exact retained frame/cut.
    /// Success consumes it once even if preemption crossed the source cut;
    /// this scalar ABI has no Kernel-atomic caller acceptance-deadline argument.
    pub(super) fn native_network_tick(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        if let Some(pending) = n.network_diagnostic.as_mut() {
            if let Some(bytes) = pending.bytes(now()) {
                let r = rt::send(self.bootstrap.handle(Role::Events), bytes);
                if r.status == 0 && r.value == 0 && r.capability == 0 {
                    pending.accepted();
                } else if r.status != 2 || r.value != 0 || r.capability != 0 {
                    pending.discard();
                }
                return true;
            }
            if !pending.pending() {
                n.network_diagnostic = None;
            }
        }
        if n.network_clock.failed() {
            n.network_time.source_failed(true);
        }
        if n.network_clock.flush(self.bootstrap.handle(Role::Events)) {
            return true;
        }
        if n.network_time.flush(self.bootstrap.handle(Role::Events)) {
            return true;
        }
        if n.network_clock.due() {
            let _ = self.native_elapsed();
        }
        let pending = self.native.as_ref().unwrap().network_report;
        if let Some((progress, cut)) = pending {
            if now() >= cut {
                let n = self.native.as_mut().unwrap();
                n.network_report = None;
                n.network_report_failed = true;
            } else {
                let reply = rt::send(self.bootstrap.handle(Role::Events), progress.encode());
                let n = self.native.as_mut().unwrap();
                if reply.status == 0 && reply.value == 0 && reply.capability == 0 {
                    n.network_report = None;
                } else if reply.status != 2 || reply.value != 0 || reply.capability != 0 {
                    n.network_report = None;
                    n.network_report_failed = true;
                }
            }
            return true;
        }
        if let Some((stage, result)) = self.native.as_mut().unwrap().network_failure.take() {
            self.native.as_mut().unwrap().network_failure_reported = true;
            self.native_network_report(Progress {
                stage: 8,
                result,
                argument: u32::from(stage),
            });
            return true;
        }
        // One bounded physical chunk per normal Root turn. It does not wait
        // for network work or prevent unrelated local owner/App work afterward.
        self.native_network_recovery_tick();
        #[cfg(feature = "native-network-negative")]
        if self.native_negative_tick() {
            return true;
        }
        let n = self.native.as_ref().unwrap();
        if n.network.phase() != Phase::Running {
            return false;
        }
        if n.network_transfer.finished() {
            if n.network_transfer.succeeded() && n.network_time.active() {
                let n = self.native.as_mut().unwrap();
                let catalogue = n.packages.catalogue().network().unwrap();
                let scope = catalogue.network_policy();
                // Only the explicit complete owner time-probe command arms
                // this exchange after Hello. Its unqualified candidate never changes health,
                // grant, boot or release-admission policy.
                let _ = n.network_time.tick(
                    &mut n.network_client,
                    &mut n.network_random,
                    &mut n.network_clock,
                    self.bootstrap.handle(Role::RtcPorts),
                    catalogue.device(),
                    scope,
                );
            }
            return false;
        }
        if !n.network_transfer.started() {
            if !self.actors[Child::Shell.index()].is_some_and(|a| a.ready) {
                return false;
            }
            let issued = now();
            let Some(cut) = issued.checked_add(8192).filter(|n| *n != u64::MAX) else {
                self.native_network_failure(2, 2);
                return false;
            };
            if self
                .native
                .as_mut()
                .unwrap()
                .network_transfer
                .begin(issued, cut)
                .is_err()
            {
                self.native_network_failure(2, 2);
                return false;
            }
        }
        let n = self.native.as_mut().unwrap();
        let stage = n.network_transfer.stage();
        let policy = n.packages.catalogue().network().unwrap().network_policy();
        match n
            .network_transfer
            .step(&mut n.network_client, policy, now())
        {
            Ok(Some(progress)) => self.native_network_report(progress),
            Ok(None) => (),
            Err(error) => {
                n.network_transfer.fail();
                self.native_network_transfer_diagnostic(error);
                let result = match error {
                    TransferError::Expired | TransferError::Clock => 2,
                    TransferError::Client(
                        ev_root_supervisor::native_network::client::Error::Remote(
                            ev_net_driver::control::Status::Refused,
                        ),
                    ) => 1,
                    _ => 3,
                };
                self.native_network_failure(stage, result);
            }
        }
        false
    }
    /// Only native_command's authenticated owner UART line invokes this hook.
    /// No App/Shell event or packet nominates a nonce/time authority.
    pub(super) fn native_time_probe_command(&mut self) {
        let n = self.native.as_ref().unwrap();
        let ready = n.network.phase() == Phase::Running
            && n.network_transfer.succeeded()
            && !n.network_client.quarantined()
            && !n.network_clock.failed()
            && !n.state.content_busy()
            && n.transition.is_none()
            && !n.starting;
        if !ready {
            self.native_report("time-probe", "refused");
            return;
        }
        for child in [Child::NetDriver, Child::NetService] {
            let Some(actor) = self.actors[child.index()] else {
                self.native_report("time-probe", "refused");
                return;
            };
            if !actor.ready {
                self.native_report("time-probe", "refused");
                return;
            }
            let r = rt::call(syscall::OBSERVE, actor.control, 0, 0);
            if r.status != 0 || r.value != 0 || r.capability != 0 {
                self.native_report("time-probe", "refused");
                return;
            }
        }
        let accepted = self.native.as_mut().unwrap().network_time.arm();
        // Only arm acceptance is acknowledged here. TP3 remains explicitly
        // unqualified and an actual committed floor/provider gate is absent.
        self.native_report("time-probe", if accepted { "ok" } else { "refused" });
    }
    pub(super) fn native_time_check_command(&mut self) {
        let n = self.native.as_mut().unwrap();
        let accepted = !n.state.content_busy()
            && n.transition.is_none()
            && !n.starting
            && n.network_time
                .check(&mut n.network_clock, self.bootstrap.handle(Role::RtcPorts));
        self.native_report("time-check", if accepted { "ok" } else { "refused" });
    }
    pub(super) fn native_network_shutdown(&mut self) -> bool {
        let n = self.native.as_mut().unwrap();
        if n.network.recovery_without_start(
            n.system.mode(),
            [
                self.actors[Child::NetDriver.index()].is_some(),
                self.actors[Child::NetService.index()].is_some(),
            ],
        ) {
            return true;
        }
        if n.network.shutdown_complete() {
            return true;
        }
        n.network_time.stop();
        n.network_random.source_failed();
        let issued = now();
        let Some(cut) = issued.checked_add(8192).filter(|n| *n != u64::MAX) else {
            return false;
        };
        if n.network.begin_shutdown_v2(issued, cut).is_err() {
            return false;
        }
        let first = issued.checked_add(1024).unwrap().min(cut);
        if n.network_client.shutdown_begin(cut, issued, first).is_err() {
            n.network.fail();
            self.native_network_failure(7, 3);
            return false;
        }
        let mut complete = false;
        for _ in 0..128 {
            let tick = now();
            if n.network.expire(tick).is_err() {
                break;
            }
            let Some(child) = tick
                .checked_add(1024)
                .filter(|v| *v != u64::MAX)
                .map(|v| v.min(cut))
            else {
                break;
            };
            match n.network_client.shutdown_step(tick, child) {
                Ok(true) => {
                    complete = true;
                    break;
                }
                Ok(false) => (),
                Err(_) => break,
            }
        }
        if !complete {
            n.network.fail();
            self.native_network_failure(7, 3);
            return false;
        }
        let actual = identity(self.child(Child::NetService));
        let n = self.native.as_mut().unwrap();
        if n.network.hardware_stopped(actual, now()).is_err() {
            n.network.fail();
            return false;
        }
        // Driver ACK established actual STOP + packet RAM scrub/readback, and
        // Service permanently latched no-more-pump before invoking that call.
        // Fence both actual CPUs before declaring the Root shutdown eligible.
        let Some(cpu_cut) = now().checked_add(512).filter(|n| *n != u64::MAX) else {
            return false;
        };
        for child in [Child::NetService, Child::NetDriver] {
            loop {
                if now() >= cpu_cut {
                    self.native.as_mut().unwrap().network.fail();
                    return false;
                }
                let r = rt::call4(syscall::STOP_PROCESS, self.child(child).control, 0, 0, 0);
                if r.status == 0 && r.value == 0 && r.capability == 0 && r.serial == 0 {
                    break;
                }
                if r.status != 2 || r.value != 0 || r.capability != 0 || r.serial != 0 {
                    self.native.as_mut().unwrap().network.fail();
                    return false;
                }
                pause();
            }
        }
        let complete = self
            .native
            .as_mut()
            .unwrap()
            .network
            .cpus_stopped(now())
            .is_ok();
        if complete {
            self.native_network_report(Progress {
                stage: 7,
                result: 0,
                argument: 2,
            });
        }
        complete
    }
    pub(in crate::desktop) fn native_network_event(
        &mut self,
        child: Child,
        bytes: [u8; 8],
    ) -> bool {
        let Some(node) = node(child) else {
            return false;
        };
        let actor = self.child(child);
        // Root.receive authenticated this exact current child PID/TID before
        // dispatching here. Valid NE is observability only: no Ready/random/
        // health/quiescence state transition is driven by its scalar bytes.
        if ev_net_driver::diagnostic::Diagnostic::decode(bytes).is_some_and(|d| {
            (child == Child::NetDriver && d.layer() == 1)
                || (child == Child::NetService && d.layer() == 2)
        }) {
            return true;
        }
        let accepted = self
            .native
            .as_mut()
            .unwrap()
            .network
            .event(node, identity(actor), bytes, now())
            .is_ok();
        if accepted && child == Child::NetDriver {
            self.actors[child.index()].as_mut().unwrap().ready = true;
        }
        if accepted
            && child == Child::NetService
            && self.native.as_ref().unwrap().network.phase() == Phase::Running
        {
            self.actors[child.index()].as_mut().unwrap().ready = true;
        }
        if !accepted {
            self.native.as_mut().unwrap().network_random.source_failed();
            self.native_network_failure(1, 4);
        }
        true
    }
    pub(in crate::desktop) fn native_network_stopped(&mut self, child: Child) -> bool {
        let Some(node) = node(child) else {
            return false;
        };
        let actor = self.child(child);
        let n = &mut self.native.as_mut().unwrap().network;
        let _ = n.stopped(node, identity(actor));
        self.native.as_mut().unwrap().network_random.source_failed();
        if self.native.as_ref().unwrap().network.hardware_debt() {
            self.native_network_failure(7, 4);
            self.native.as_mut().unwrap().network_recovery.arm(now());
        }
        let n = &mut self.native.as_mut().unwrap().network;
        if n.reported(node) {
            return true;
        }
        if self.native_diagnostic_stopped(child) {
            self.native.as_mut().unwrap().network.mark_reported(node);
        }
        // Actual CPU death does not stop the NIC. Do not REAP/CLOSE/recreate
        // either participant or release any hardware/window/image owner.
        true
    }
    pub(super) fn native_child_digest(&self, child: Child) -> Option<[u8; 32]> {
        if let Some(digest) = self.native_system_image_digest(child) {
            return Some(digest);
        }
        let c = self.native.as_ref()?.packages.catalogue().network()?;
        match child {
            Child::NetDriver => Some(c.net_driver().image),
            Child::NetService => Some(c.net_service().image),
            _ => None,
        }
    }
}
