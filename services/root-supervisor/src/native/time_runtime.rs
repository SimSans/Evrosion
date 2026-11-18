//! Actual private Root time exchange. A verified candidate is not Qualified
//! time or publication authority; no durable floor is invented here.
use super::*;
use ev_root_supervisor::native_network::time_exchange::{Exchange, diagnostics::Diagnostics};
use ev_time_contract::Instant;
use ev_time_proof::{Anchor, Client, ClockModel, NonceSource, Policy, Request};
pub(super) mod qualified;

/// One actual qualified source output, drawn only after the captured RTC
/// origin. This is not another generator or a caller-selected nonce API.
struct FreshNonce {
    bytes: [u8; 32],
    available: bool,
}
impl FreshNonce {
    const fn empty() -> Self {
        Self {
            bytes: [0; 32],
            available: false,
        }
    }
    fn draw(random: &mut vm_entropy::Random) -> Result<Self, Error> {
        let mut source = Self {
            bytes: [0; 32],
            available: false,
        };
        let receipt = random
            .fill(now(), &mut source.bytes)
            .map_err(|_| Error::Entropy)?;
        if receipt.bytes != 32 || receipt.seed_generation == 0 || receipt.request == 0 {
            return Err(Error::Entropy);
        }
        source.available = true;
        Ok(source)
    }
    fn erase(&mut self) {
        self.bytes.fill(0);
        core::hint::black_box(&self.bytes);
        self.available = false;
    }
}
impl Drop for FreshNonce {
    fn drop(&mut self) {
        self.erase();
    }
}
impl NonceSource for FreshNonce {
    type Error = ();
    fn fresh_nonce(&mut self, out: &mut [u8; 32]) -> Result<(), ()> {
        if !self.available {
            return Err(());
        }
        out.copy_from_slice(&self.bytes);
        self.erase();
        Ok(())
    }
}
#[derive(Debug)]
pub(super) enum Error {
    Clock,
    Entropy,
    Policy,
    Proof,
    Exchange,
}
/// The minimum1/2 rate is an explicit conditional healthy trusted-Linux/QEMU
/// assumption, not derived from a synchronization flag or a finite benchmark.
/// The reviewed profile's proof/pause/negative/refresh gates are retained
/// separately. Only qualified::Clock binds an actual authenticated Store floor
/// to a fresh current observation; diagnostics never qualify their consumer.
fn policy() -> Result<Policy, Error> {
    Policy::new(
        ClockModel::one_second_floor(1, 2).map_err(|_| Error::Policy)?,
        30,
        60,
        1,
        10,
    )
    .map_err(|_| Error::Policy)
}
pub(super) struct Time {
    exchange: Exchange,
    verifier: Option<Client<FreshNonce>>,
    request: Option<Request>,
    anchor: Option<Anchor>,
    post_crypto: Option<Instant>,
    armed: bool,
    started: bool,
    failed: bool,
    halted: bool,
    stage: u8,
    final_report: bool,
    reports: Diagnostics,
    checked: bool,
    check_reports: u8,
    check_report: Option<([u8; 8], u64)>,
    exchange_report: Option<([u8; 8], u64)>,
    parent_cut: u64,
    exchange_cut: u64,
}
impl Time {
    /// Fresh metadata authentication permits bounded preparation only. Final
    /// full-package authorization and durability remain independent gates.
    pub(super) fn prepare_remote_metadata<B: ev_content_store::Backend>(
        &mut self,
        source: &mut vm_rtc::Source,
        rtc: u64,
        store: &ev_root_supervisor::native_acquisition::Store<B>,
        current_root: &[u8],
        bundle: ev_release_trust::verifier::Bundle<'_>,
    ) -> Result<
        ev_root_supervisor::native_acquisition::Preparation,
        ev_root_supervisor::native_acquisition::Fault,
    > {
        let mut clock = qualified::Clock::new(self, source, rtc, store)
            .map_err(|_| ev_root_supervisor::native_acquisition::Fault::Time)?;
        clock.prepare(current_root, bundle)
    }
    /// New remote authorization only, bound to the exact authenticated Store.
    /// No caller-selected floor, detached local identity or cached UTC input.
    pub(super) fn authorize_remote_into<B: ev_content_store::Backend>(
        &mut self,
        source: &mut vm_rtc::Source,
        rtc: u64,
        store: &ev_root_supervisor::native_acquisition::Store<B>,
        remote: ev_root_supervisor::native_acquisition::Remote<'_>,
        workspace: &mut ev_root_supervisor::native_acquisition::Commit<B>,
    ) -> Result<(), ev_root_supervisor::native_acquisition::Fault> {
        let mut clock = qualified::Clock::new(self, source, rtc, store)
            .map_err(|_| ev_root_supervisor::native_acquisition::Fault::Time)?;
        clock.authorize_into(remote, workspace)
    }
    pub(super) const fn new() -> Self {
        Self {
            exchange: Exchange::new(),
            verifier: None,
            request: None,
            anchor: None,
            post_crypto: None,
            armed: false,
            started: false,
            failed: false,
            halted: false,
            stage: 1,
            final_report: false,
            reports: Diagnostics::new(),
            checked: false,
            check_reports: 0,
            check_report: None,
            exchange_report: None,
            parent_cut: 0,
            exchange_cut: 0,
        }
    }
    pub(super) fn arm(&mut self) -> bool {
        self.arm_with_cut(0)
    }
    /// Exactly one fresh proof inside the already captured fetch operation.
    /// A delayed start cannot renew that parent's original absolute cut.
    pub(super) fn arm_for_fetch(&mut self, original_fetch_cut: u64) -> bool {
        let tick = now();
        if original_fetch_cut == u64::MAX || tick >= original_fetch_cut {
            return false;
        }
        self.arm_with_cut(original_fetch_cut)
    }
    fn arm_with_cut(&mut self, parent_cut: u64) -> bool {
        if self.halted
            || self.active()
            || self.pending()
            || self.request.is_some()
            || self.verifier.as_ref().is_some_and(Client::has_pending)
        {
            return false;
        }
        // A new proof replaces the old affine Anchor; an expired anchor is
        // never reopened. Client sequence, last nonce and elapsed history stay.
        self.exchange = Exchange::new();
        self.anchor = None;
        self.post_crypto = None;
        self.started = false;
        self.failed = false;
        self.stage = 1;
        self.final_report = false;
        self.checked = false;
        self.parent_cut = parent_cut;
        self.exchange_cut = 0;
        self.armed = true;
        true
    }
    /// Excludes another high-level user of the same sole TCP/client owner.
    pub(super) fn active(&self) -> bool {
        self.armed && !self.terminal()
    }
    fn terminal(&self) -> bool {
        self.failed || (self.anchor.is_some() && self.post_crypto.is_some())
    }
    pub(super) fn stop(&mut self) {
        // Ordinary step returns only after each protected call is quiescent;
        // an unknown Client result separately pins that actual owner. Dropping
        // this local challenge never acknowledges/retries accepted peer work.
        self.exchange.abandon();
        self.verifier = None;
        self.request = None;
        self.anchor = None;
        self.post_crypto = None;
        self.failed = true;
        self.halted = true;
    }
    pub(super) fn tick(
        &mut self,
        client: &mut network_runtime::Client,
        random: &mut vm_entropy::Random,
        clock: &mut vm_rtc::Source,
        rtc: u64,
        device: ev_userspace_contract::root_v4::catalogue::DeviceWitness,
        scope: ev_userspace_contract::root_v4::catalogue::NetworkPolicy<'_>,
    ) -> Result<(), Error> {
        if !self.active() {
            return Ok(());
        }
        let result = self.inner(client, random, clock, rtc, device, scope);
        if let Err(ref error) = result {
            self.fail(error);
        }
        result
    }
    fn fail(&mut self, error: &Error) {
        if self.started && !self.final_report {
            let result = match error {
                Error::Clock => 1,
                Error::Entropy => 2,
                Error::Policy => 3,
                Error::Proof => 4,
                Error::Exchange => 5,
            };
            // Reuse the existing TP failure timestamp; diagnostics introduce
            // no extra guest clock/packet read or protected call.
            let tick = now();
            if matches!(error, Error::Exchange)
                && let Some(failure) = self.exchange.failure()
                && let Some(cut) = tick.checked_add(512).filter(|n| *n != u64::MAX)
            {
                let (error, detail) = failure.error();
                self.exchange_report = Some((
                    [
                        b'T',
                        b'E',
                        1,
                        failure.phase(),
                        failure.tcp().unwrap_or(255),
                        failure.calls(),
                        error,
                        detail,
                    ],
                    cut,
                ));
            }
            let _ = self.reports.push(4, result, u32::from(self.stage), tick);
            self.final_report = true;
        }
        // A malformed proof consumes its challenge but may be followed by a
        // genuinely fresh explicit request. Clock/source/transport uncertainty
        // permanently closes this adapter; never reconstruct a fresh Client.
        self.halted |= !matches!(error, Error::Proof);
        self.exchange.abandon();
        self.request = None;
        self.anchor = None;
        self.post_crypto = None;
        self.failed = true;
        if self.halted {
            self.verifier = None;
        }
    }
    pub(super) fn source_failed(&mut self, clock: bool) {
        self.fail(if clock {
            &Error::Clock
        } else {
            &Error::Exchange
        });
    }
    pub(super) fn pending(&self) -> bool {
        self.reports.pending() || self.check_report.is_some() || self.exchange_report.is_some()
    }
    /// One explicit check after a private proof. An expired/failed anchor
    /// cannot become fresh again; no durable floor or UTC label is created.
    pub(super) fn check(&mut self, clock: &mut vm_rtc::Source, rtc: u64) -> bool {
        if self.checked || self.anchor.is_none() || self.post_crypto.is_none() {
            return false;
        }
        self.checked = true;
        let (result, elapsed) = match clock.sample(rtc) {
            Ok(sample) => {
                let result = match self.anchor.as_mut().unwrap().observe_post_crypto(sample) {
                    Ok(()) => 0,
                    Err(ev_time_proof::Error::Age) => 2,
                    Err(_) => 3,
                };
                (result, sample.tick())
            }
            Err(_) => {
                self.halted = true;
                (1, 0)
            }
        };
        if result != 0 {
            self.failed = true;
            self.post_crypto = None;
        }
        // One check per Anchor, at most four diagnostics per Root lifetime.
        // Later actual checks still consume/fence their Anchor normally.
        if self.check_reports == 4 {
            return true;
        }
        let (Ok(elapsed), Some(cut)) = (
            u32::try_from(elapsed),
            now().checked_add(4096).filter(|n| *n != u64::MAX),
        ) else {
            return false;
        };
        let mut body = [b'T', b'C', 1, result, 0, 0, 0, 0];
        body[4..].copy_from_slice(&elapsed.to_le_bytes());
        self.check_report = Some((body, cut));
        self.check_reports += 1;
        true
    }
    pub(super) fn flush(&mut self, events: u64) -> bool {
        if let Some((body, cut)) = self.exchange_report {
            let tick = now();
            if tick < cut - 512 || tick >= cut {
                self.exchange_report = None;
                return false;
            }
            let r = rt::send(events, body);
            if r.status != 2 || r.value != 0 || r.capability != 0 {
                self.exchange_report = None;
            }
            return true;
        }
        if let Some((body, cut)) = self.check_report {
            let tick = now();
            if tick < cut - 4096 || tick >= cut {
                self.check_report = None;
                return false;
            }
            let r = rt::send(events, body);
            if r.status != 2 || r.value != 0 || r.capability != 0 {
                self.check_report = None;
            }
            return true;
        }
        let Some(entry) = self.reports.front(now()) else {
            return false;
        };
        let r = rt::send(events, entry.bytes);
        // Only canonical Busy keeps the exact unaccepted front entry. Actual
        // success is consumed once even if preemption crossed its local cut.
        if r.status != 2 || r.value != 0 || r.capability != 0 {
            self.reports.retire();
        }
        true
    }
    fn inner(
        &mut self,
        client: &mut network_runtime::Client,
        random: &mut vm_entropy::Random,
        clock: &mut vm_rtc::Source,
        rtc: u64,
        device: ev_userspace_contract::root_v4::catalogue::DeviceWitness,
        scope: ev_userspace_contract::root_v4::catalogue::NetworkPolicy<'_>,
    ) -> Result<(), Error> {
        let tick = now();
        if !self.started {
            let mut cut = tick
                .checked_add(8192)
                .filter(|n| *n != u64::MAX)
                .ok_or(Error::Clock)?;
            if self.parent_cut != 0 {
                cut = cut.min(self.parent_cut);
            }
            self.exchange
                .start(tick, cut)
                .map_err(|_| Error::Exchange)?;
            self.exchange_cut = cut;
            self.started = true;
        }
        if self.exchange.ready() && self.request.is_none() {
            let origin = clock.sample(rtc).map_err(|_| Error::Clock)?;
            // The owner may have waited beyond the boot seed's finite TTL.
            // Reacquire once here, after the origin and before publication:
            // the affine Request/verifier prevents this path from repeating
            // for any accepted challenge. This retains the same generator,
            // generation/request high-waters, RTC domain and original cut.
            random
                .reseed_after_reviewed_vm_launch(device, now)
                .map_err(|_| Error::Entropy)?;
            // Policy is fixed before nonce publication. Staging cannot be
            // constructed from downloaded bytes or an externally chosen nonce.
            if self.verifier.is_none() {
                self.verifier = Some(
                    Client::new(FreshNonce::empty(), origin, policy()?)
                        .map_err(|_| Error::Policy)?,
                );
            }
            let request = self
                .verifier
                .as_mut()
                .unwrap()
                .begin_after(origin, |source| {
                    *source = FreshNonce::draw(random).map_err(|_| ())?;
                    Ok(())
                })
                .map_err(|_| Error::Entropy)?;
            // Diagnostic retention never limits security operations. Preserve
            // the bounded lifetime FIFO; sequence history remains u64 in Client.
            if let Ok(sequence) = u32::try_from(request.sequence()) {
                let _ = self.reports.push(1, 0, sequence, now());
            }
            self.stage = 2;
            self.exchange
                .publish(request.nonce())
                .map_err(|_| Error::Exchange)?;
            self.request = Some(request);
        }
        self.exchange
            .step(client, scope, now())
            .map_err(|_| Error::Exchange)?;
        if let Some(bytes) = self.exchange.response() {
            let _ = self.reports.push(2, 0, bytes.len() as u32, now());
            self.stage = 3;
            let received = clock.sample(rtc).map_err(|_| Error::Clock)?;
            let verifier = self.verifier.as_mut().ok_or(Error::Proof)?;
            let request = self.request.take().ok_or(Error::Proof)?;
            let mut anchor = verifier
                .finish(request, received, bytes)
                .map_err(|_| Error::Proof)?;
            // Crypto may be preempted. These actual reads follow verification;
            // the later durable-publication adapter MUST take another fresh read
            // and use its actual committed floor. No stored read authorizes it.
            let post = clock.sample(rtc).map_err(|_| Error::Clock)?;
            anchor.observe_post_crypto(post).map_err(|_| Error::Proof)?;
            let decision = clock.sample(rtc).map_err(|_| Error::Clock)?;
            anchor
                .observe_post_crypto(decision)
                .map_err(|_| Error::Proof)?;
            // Verification may be preempted. Neither an accepted exchange nor
            // its parent fetch obtains a later cut by finishing cryptography.
            if now() >= self.exchange_cut {
                return Err(Error::Proof);
            }
            let _ = self.reports.push(3, 0, 11, now());
            self.final_report = true;
            self.anchor = Some(anchor);
            self.post_crypto = Some(decision);
        }
        Ok(())
    }
}
