//! Sealed bootstrap custody lifecycle; hardware teardown remains an explicit
//! typed trust boundary. One trusted owner retains this non-Clone record and
//! the SAME Authority/Scheduler for its boot lifetime. No userspace constructor,
//! mutation, recovery override or reset operation belongs to this interface.
use crate::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest::Manifest,
    capability::{Authority, SpaceId},
    incarnation::{self, Active, Bindings, Target, Token},
    loaded_image::LoadedExecutable,
    restart::{self, Budget},
    scheduler::{self, Resource, Scheduler},
};
use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Sealed,
    Spawning,
    Prepared,
    Active,
    Revoking,
    Quiescent,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    Restart(restart::RecoveryRequired),
    CounterExhausted,
    Preparation(incarnation::Error),
    Scheduler(scheduler::Error),
    Integrity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Phase,
    StaleAttempt,
    StaleToken,
    ForeignBinding,
    NotQuiescent,
    RecoveryRequired(Recovery),
}

/// Unique kernel attempt permit; dropping it fails closed in Spawning. Its
/// diagnostic epoch/number are not authority, and cannot construct another one.
#[must_use = "prepare this admitted attempt or abandon it after trusted cleanup"]
#[derive(Debug)]
pub struct Attempt {
    epoch: NonZeroU64,
    number: u64,
    custody: SpaceId,
    manifest: [u8; 32],
}
impl Attempt {
    pub fn epoch(&self) -> NonZeroU64 {
        self.epoch
    }
    pub fn number(&self) -> u64 {
        self.number
    }
}

/// A consumed witness of actual complete incarnation teardown, not readiness.
///
/// # Safety
/// A production implementer must be private to the trusted hardware controller,
/// non-Clone/non-Copy, and constructible only after its exact truthful token's
/// ENTIRE bootstrap-managed graph has stopped. It must prove no CPU/AP can resume
/// any old context; retained controller CR3 is active; IRQ/DMA operations are
/// fenced/drained; IPC, RPC, queued capabilities and mappings are retired; every
/// executable/data backing is scrubbed and returned; and all live old-incarnation
/// authority/reference leases are gone. Inert revoked metadata/diagnostic records
/// may remain solely for the matching binding/Scheduler checks below. The SAME
/// Authority/Scheduler and immutable generation selection must remain retained.
/// token() must be stable and truthful. A timeout or revoked flag alone is never
/// sufficient. Consuming this receipt must not recycle any backing a second time.
#[allow(unsafe_code)] // Trust-contract declaration only; no unsafe policy instructions.
pub unsafe trait QuiescentIncarnation {
    fn token(&self) -> Token;
}

/// Failed acceptance returns both sole owners so legitimate incomplete cleanup
/// can finish and retry; a foreign/stale receipt never advances current custody.
pub struct RejectedReceipt<'a, W> {
    pub binding: Bindings<'a>,
    pub receipt: W,
    pub error: Error,
}

pub struct Custodian<'a> {
    epoch: NonZeroU64,
    sequence: u64,
    manifest: crate::root_selection::Selection<'a>,
    custody: SpaceId,
    catalog: &'a [CatalogEntry],
    budget: Budget,
    last_tick: Option<u64>,
    phase: Phase,
    current: Option<Token>,
    recovery: Option<Recovery>,
}
impl<'a> Custodian<'a> {
    /// Independent typed V5 selection through this same retained attempt,
    /// incarnation, restart budget and teardown machine. No legacy cast/reset.
    #[cfg(feature = "workspace-authority")]
    pub fn new_root_v5(
        epoch: NonZeroU64,
        manifest: &'a crate::root_manifest_v5::CurrentRoot<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self::new_selected(
            epoch,
            crate::root_selection::Selection::V5(manifest),
            custody,
            catalog,
        )
    }
    /// Trusted once-per-boot construction over verified immutable boot selection.
    /// Epoch uniqueness/authentication belongs to that producer, not this core.
    /// Keep custody private: never export its domain or grant a BAC mutation cap.
    pub fn new(
        epoch: NonZeroU64,
        manifest: &'a Manifest<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self::new_selected(
            epoch,
            crate::root_selection::Selection::V1(manifest),
            custody,
            catalog,
        )
    }
    /// Same immutable custody, Budget, epoch and phase machine; only the typed
    /// measured record format changes. No reset or second active Root is added.
    pub fn new_root_v2(
        epoch: NonZeroU64,
        manifest: &'a crate::root_manifest_v2::CurrentRoot<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self::new_selected(
            epoch,
            crate::root_selection::Selection::V2(manifest),
            custody,
            catalog,
        )
    }
    /// Native profile2 selects the same sealed custody/attempt/budget owner.
    /// A different immutable profile does not permit a second active Root or
    /// an incarnation counter/recovery latch reset within this owner.
    pub fn new_native_root(
        epoch: NonZeroU64,
        manifest: &'a crate::root_manifest_v2::NativeRoot<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self::new_selected(
            epoch,
            crate::root_selection::Selection::Native(manifest),
            custody,
            catalog,
        )
    }
    /// The new record shares this exact custody/budget/phase machine. It is
    /// neither a second active Root nor a reset of incarnation/recovery state.
    pub fn new_root_v4(
        epoch: NonZeroU64,
        manifest: &'a crate::root_manifest_v4::CurrentRoot<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self::new_selected(
            epoch,
            crate::root_selection::Selection::V4(manifest),
            custody,
            catalog,
        )
    }
    fn new_selected(
        epoch: NonZeroU64,
        manifest: crate::root_selection::Selection<'a>,
        custody: SpaceId,
        catalog: &'a [CatalogEntry],
    ) -> Self {
        Self {
            epoch,
            sequence: 0,
            manifest,
            custody,
            catalog,
            budget: Budget::new(manifest.restart_policy()),
            last_tick: None,
            phase: Phase::Sealed,
            current: None,
            recovery: None,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn epoch(&self) -> NonZeroU64 {
        self.epoch
    }
    pub fn last_attempt(&self) -> u64 {
        self.sequence
    }
    pub fn current(&self) -> Option<Token> {
        self.current
    }
    pub fn recovery_required(&self) -> Option<Recovery> {
        self.recovery
    }
    fn fail(&mut self, reason: Recovery) -> Error {
        if self.recovery.is_none() {
            self.recovery = Some(reason);
        }
        self.phase = Phase::RecoveryRequired;
        Error::RecoveryRequired(self.recovery.unwrap())
    }
    fn healthy(&self) -> Result<(), Error> {
        match self.recovery {
            Some(reason) => Err(Error::RecoveryRequired(reason)),
            None => Ok(()),
        }
    }
    /// Return the permit BEFORE any replacement allocation/spawn. Initial launch
    /// is free; every later attempt charges this same retained sliding-window
    /// Budget, even if the caller's spawn fails and is subsequently abandoned.
    pub fn begin(&mut self, now: u64) -> Result<Attempt, Error> {
        self.healthy()?;
        if !matches!(self.phase, Phase::Sealed | Phase::Quiescent) {
            return Err(Error::Phase);
        }
        if self.current.is_some() {
            return Err(self.fail(Recovery::Integrity));
        }
        if self.last_tick.is_some_and(|last| now < last) {
            return Err(self.fail(Recovery::Restart(
                restart::RecoveryRequired::ClockWentBackwards,
            )));
        }
        self.last_tick = Some(now);
        let Some(number) = self.sequence.checked_add(1) else {
            return Err(self.fail(Recovery::CounterExhausted));
        };
        if self.sequence != 0
            && let Err(reason) = self.budget.admit(now)
        {
            return Err(self.fail(Recovery::Restart(reason)));
        }
        self.sequence = number;
        self.phase = Phase::Spawning;
        Ok(Attempt {
            epoch: self.epoch,
            number,
            custody: self.custody,
            manifest: self.manifest.digest(),
        })
    }
    fn attempt(&self, attempt: &Attempt) -> Result<(), Error> {
        if attempt.epoch != self.epoch
            || attempt.number != self.sequence
            || attempt.custody != self.custody
            || attempt.manifest != self.manifest.digest()
        {
            return Err(Error::StaleAttempt);
        }
        self.healthy()?;
        if self.phase != Phase::Spawning || self.current.is_some() {
            return Err(Error::Phase);
        }
        Ok(())
    }
    /// Abandon only an UNPREPARED attempt. Trusted caller preconditions: every
    /// partially allocated target stayed held, no root grants were installed,
    /// all private hardware/IPC references were cleaned and charges returned.
    /// This does not prove those external facts, refund Budget, or reset sequence.
    pub fn abandon_unprepared(&mut self, attempt: Attempt) -> Result<(), Error> {
        self.attempt(&attempt)?;
        self.phase = Phase::Quiescent;
        Ok(())
    }
    pub fn prepare(
        &mut self,
        attempt: Attempt,
        authority: &mut Authority,
        scheduler: &Scheduler,
        target: Target,
    ) -> Result<(Bindings<'a>, Token), Error> {
        self.attempt(&attempt)?;
        let Some(previous) = self.sequence.checked_sub(1) else {
            return Err(self.fail(Recovery::Integrity));
        };
        let mut binding = Bindings::new_after_sequence(
            self.epoch,
            previous,
            self.manifest,
            self.custody,
            self.catalog,
        );
        let token = binding
            .prepare(authority, scheduler, target)
            .map_err(|error| self.fail(Recovery::Preparation(error)))?;
        if token.number() != self.sequence {
            return Err(self.fail(Recovery::Integrity));
        }
        self.current = Some(token);
        self.phase = Phase::Prepared;
        Ok((binding, token))
    }
    fn matching(&self, token: Token) -> Result<(), Error> {
        if self.current != Some(token) {
            return Err(Error::StaleToken);
        }
        self.healthy()
    }
    /// Confirms the actual private-constructor Active owner, never a caller bool.
    /// A duplicate matching confirmation is harmless and creates no new root.
    pub fn confirm_active<L: LoadedExecutable>(
        &mut self,
        active: &Active<'a, L>,
    ) -> Result<(), Error> {
        self.matching(active.token())?;
        if !active.sealed_context_matches(self.epoch, self.manifest, self.custody, self.catalog) {
            return Err(Error::ForeignBinding);
        }
        if active.phase() == incarnation::Phase::RecoveryRequired {
            return Err(self.fail(Recovery::Integrity));
        }
        if !matches!(self.phase, Phase::Prepared | Phase::Active)
            || active.phase() != incarnation::Phase::Active
        {
            return Err(Error::Phase);
        }
        self.phase = Phase::Active;
        Ok(())
    }
    /// Latch an actual failed current binding after rejected activation. This
    /// accepts evidence of failure only; it cannot reset, refund or unlock a root.
    pub fn report_failure(&mut self, binding: &Bindings<'a>) -> Result<(), Error> {
        let token = binding.current_token().ok_or(Error::StaleToken)?;
        self.matching(token)?;
        if !binding.sealed_context_matches(self.epoch, self.manifest, self.custody, self.catalog) {
            return Err(Error::ForeignBinding);
        }
        if binding.phase() != incarnation::Phase::RecoveryRequired {
            return Err(Error::Phase);
        }
        let reason = binding.failure().ok_or(Error::Phase)?;
        self.fail(Recovery::Preparation(reason));
        Ok(())
    }
    /// Fence custodian creation first; the controller must then inhibit/revoke
    /// the matching Active owner and tear down its complete managed graph.
    pub fn begin_revocation(&mut self, token: Token) -> Result<(), Error> {
        self.matching(token)?;
        if !matches!(
            self.phase,
            Phase::Prepared | Phase::Active | Phase::Revoking
        ) {
            return Err(Error::Phase);
        }
        self.phase = Phase::Revoking;
        Ok(())
    }
    /// Require actual revoked binding ownership, current generational scheduler
    /// identities/zero LIVE aggregate charges and a consumed physical witness.
    /// CPU ticks are historical use; they are deliberately not refunded/zeroed.
    #[allow(clippy::result_large_err)] // Failure must retain binding and typed witness without a heap.
    pub fn accept_quiescence<W: QuiescentIncarnation>(
        &mut self,
        scheduler: &Scheduler,
        binding: Bindings<'a>,
        receipt: W,
    ) -> Result<(), RejectedReceipt<'a, W>> {
        let checked = self.check_quiescence(scheduler, &binding, &receipt);
        if let Err(error) = checked {
            return Err(RejectedReceipt {
                binding,
                receipt,
                error,
            });
        }
        self.current = None;
        self.phase = Phase::Quiescent;
        Ok(())
    }
    fn check_quiescence<W: QuiescentIncarnation>(
        &mut self,
        scheduler: &Scheduler,
        binding: &Bindings<'a>,
        receipt: &W,
    ) -> Result<(), Error> {
        let token = receipt.token();
        self.matching(token)?;
        if binding.current_token() != Some(token) {
            return Err(Error::StaleToken);
        }
        if !binding.sealed_context_matches(self.epoch, self.manifest, self.custody, self.catalog) {
            return Err(Error::ForeignBinding);
        }
        if let Some(reason) = binding.failure() {
            return Err(self.fail(Recovery::Preparation(reason)));
        }
        if self.phase != Phase::Revoking || binding.phase() != incarnation::Phase::Revoked {
            return Err(Error::NotQuiescent);
        }
        if scheduler
            .process_job(token.process())
            .map_err(|error| self.fail(Recovery::Scheduler(error)))?
            != token.job()
        {
            return Err(self.fail(Recovery::Integrity));
        }
        if !scheduler.process_terminated(token.process()) {
            return Err(Error::NotQuiescent);
        }
        for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
            if scheduler
                .usage(token.job(), resource)
                .map_err(|error| self.fail(Recovery::Scheduler(error)))?
                != 0
            {
                return Err(Error::NotQuiescent);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap_manifest,
        capability::{Kind, Rights},
        loaded_image::{Information, LoadedExecutable},
        scheduler::{Limits, ThreadId},
    };
    use sha2::{Digest, Sha256};
    const BYTES: &[u8; 232] = include_bytes!("../fixtures/bootstrap-static-v1.bin");
    const ELF: &[u8; 8200] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
    fn manifest() -> Manifest<'static> {
        measured(BYTES)
    }
    fn measured(bytes: &[u8]) -> Manifest<'_> {
        bootstrap_manifest::verify(bytes, Sha256::digest(bytes).into(), ELF, [42; 32]).unwrap()
    }
    struct Fixture {
        a: Authority,
        s: Scheduler,
        custody: SpaceId,
        catalog: [CatalogEntry; 2],
    }
    fn fixture() -> Fixture {
        let mut a = Authority::new();
        let custody = a.create_space().unwrap();
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
        let memory = a
            .create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap();
        let endpoint = a
            .create_root(custody, Kind::Endpoint, common | Rights::SEND)
            .unwrap();
        Fixture {
            a,
            s: Scheduler::new(),
            custody,
            catalog: [
                CatalogEntry {
                    selector: 1,
                    root: memory,
                    kind: Kind::Memory,
                },
                CatalogEntry {
                    selector: 2,
                    root: endpoint,
                    kind: Kind::Endpoint,
                },
            ],
        }
    }
    fn target(a: &mut Authority, s: &mut Scheduler, m: &Manifest<'_>) -> (Target, ThreadId) {
        let branches = a.create_space().unwrap();
        let destination = a.create_space().unwrap();
        let job = s.create_job_with_limits(m.limits()).unwrap();
        let process = s.create_held_process(job).unwrap();
        let thread = s.create_thread(process).unwrap();
        (
            Target {
                process,
                job,
                destination,
                branches,
            },
            thread,
        )
    }
    struct ModelImage(Information);
    // SAFETY: host-only metadata model. No hardware root is dereferenced or
    // executed; this stands in for uniquely retained initialized backing only.
    #[allow(unsafe_code)]
    unsafe impl LoadedExecutable for ModelImage {
        fn information(&self) -> Information {
            self.0
        }
    }
    struct Receipt(Token);
    // SAFETY: host-only model witness exercises the portable evidence gate, not
    // actual CPU/IPC/DMA/frame quiescence. These tests perform no hardware access
    // and cannot establish AF-007 physical recovery acceptance.
    #[allow(unsafe_code)]
    unsafe impl QuiescentIncarnation for Receipt {
        fn token(&self) -> Token {
            self.0
        }
    }
    fn image(s: &mut Scheduler, m: &Manifest<'_>, t: Target) -> ModelImage {
        let plan = crate::executable::Image::from_manifest(m).unwrap();
        s.charge_frames(t.job, plan.required_frames()).unwrap();
        ModelImage(Information {
            process: t.process,
            manifest: m.digest(),
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames: plan.required_frames(),
            startup: None,
        })
    }
    #[test]
    fn singleton_owned_activation_and_typed_quiescence_preserve_sequence_and_custody() {
        let m = manifest();
        let mut f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let permit = c.begin(0).unwrap();
        assert_eq!(
            (permit.epoch().get(), permit.number(), c.phase()),
            (7, 1, Phase::Spawning)
        );
        assert_eq!(c.begin(0).err(), Some(Error::Phase));
        let (t, thread) = target(&mut f.a, &mut f.s, &m);
        let (binding, token) = c.prepare(permit, &mut f.a, &f.s, t).unwrap();
        assert_eq!(c.current(), Some(token));
        assert_eq!(f.s.dispatch(0), Ok(None));
        let owner = image(&mut f.s, &m, t);
        let mut active = binding
            .activate(&f.a, &mut f.s, token, thread, owner)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        c.confirm_active(&active).unwrap();
        c.confirm_active(&active).unwrap();
        assert_eq!(c.phase(), Phase::Active);
        assert_eq!(f.s.dispatch(0).unwrap().unwrap().thread, thread);
        f.s.charge_cpu(0, 3).unwrap();
        f.s.yield_cpu(0).unwrap();
        assert_eq!(c.begin(1).err(), Some(Error::Phase));
        c.begin_revocation(token).unwrap();
        active.revoke(&mut f.a, &mut f.s, token).unwrap();
        assert_eq!(c.begin(1).err(), Some(Error::Phase));
        f.s.terminate_process(t.process).unwrap();
        let (binding, _image) = active
            .finish(&f.s, token)
            .unwrap_or_else(|_| panic!("not retired"));
        let rejected = c
            .accept_quiescence(&f.s, binding, Receipt(token))
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::NotQuiescent);
        assert_eq!((c.phase(), c.current()), (Phase::Revoking, Some(token)));
        f.s.release_frames(t.job, 9).unwrap();
        c.accept_quiescence(&f.s, rejected.binding, rejected.receipt)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!((c.phase(), c.current()), (Phase::Quiescent, None));
        assert_eq!(f.s.usage(t.job, Resource::CpuTicks), Ok(3));
        for (entry, rights) in f.catalog.iter().zip([Rights::READ, Rights::SEND]) {
            assert!(
                f.a.authorize(f.custody, entry.root, entry.kind, rights)
                    .is_ok()
            );
        }
        let next = c.begin(1).unwrap();
        assert_eq!(next.number(), 2);
        let (t, _) = target(&mut f.a, &mut f.s, &m);
        let (mut binding, current) = c.prepare(next, &mut f.a, &f.s, t).unwrap();
        assert_eq!(current.number(), 2);
        assert_eq!(c.begin_revocation(token), Err(Error::StaleToken));
        let rejected = c
            .accept_quiescence(&f.s, binding, Receipt(token))
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::StaleToken);
        assert_eq!((c.phase(), c.current()), (Phase::Prepared, Some(current)));
        binding = rejected.binding;
        c.begin_revocation(current).unwrap();
        binding.revoke(&mut f.a, current).unwrap();
        f.s.terminate_process(t.process).unwrap();
        c.accept_quiescence(&f.s, binding, Receipt(current))
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(c.begin(2).unwrap().number(), 3);
    }
    #[test]
    fn failed_unprepared_spawns_are_charged_before_allocation_and_never_refunded() {
        let m = manifest();
        let f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let initial = c.begin(0).unwrap();
        c.abandon_unprepared(initial).unwrap();
        for now in 1..=3 {
            let permit = c.begin(now).unwrap();
            assert_eq!(permit.number(), now + 1);
            c.abandon_unprepared(permit).unwrap();
        }
        let reason = Recovery::Restart(restart::RecoveryRequired::BudgetExhausted);
        assert_eq!(c.begin(4).err(), Some(Error::RecoveryRequired(reason)));
        assert_eq!(c.begin(600).err(), Some(Error::RecoveryRequired(reason)));
        assert_eq!(
            (c.phase(), c.last_attempt(), c.recovery_required()),
            (Phase::RecoveryRequired, 4, Some(reason))
        );
    }
    #[test]
    fn initial_launch_is_free_even_with_zero_replacement_policy() {
        let mut bytes = *BYTES;
        bytes[112] = 0;
        let m = measured(&bytes);
        let f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let initial = c.begin(10).unwrap();
        c.abandon_unprepared(initial).unwrap();
        assert_eq!(
            c.begin(10).err(),
            Some(Error::RecoveryRequired(Recovery::Restart(
                restart::RecoveryRequired::BudgetExhausted
            )))
        );
    }
    #[test]
    fn initial_clock_reversal_deadline_overflow_and_counter_exhaustion_latch() {
        for case in 0..3 {
            let m = manifest();
            let f = fixture();
            let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
            let (now, reason) = match case {
                0 => {
                    let permit = c.begin(10).unwrap();
                    c.abandon_unprepared(permit).unwrap();
                    (
                        9,
                        Recovery::Restart(restart::RecoveryRequired::ClockWentBackwards),
                    )
                }
                1 => {
                    let permit = c.begin(u64::MAX).unwrap();
                    c.abandon_unprepared(permit).unwrap();
                    (
                        u64::MAX,
                        Recovery::Restart(restart::RecoveryRequired::DeadlineOverflow),
                    )
                }
                _ => {
                    c.sequence = u64::MAX;
                    (0, Recovery::CounterExhausted)
                }
            };
            assert_eq!(c.begin(now).err(), Some(Error::RecoveryRequired(reason)));
            assert_eq!(
                c.begin(u64::MAX).err(),
                Some(Error::RecoveryRequired(reason))
            );
        }
    }
    #[test]
    fn stale_permits_and_foreign_actual_active_owners_do_not_change_current_state() {
        let m = manifest();
        let mut f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let initial = c.begin(0).unwrap();
        let mut foreign = Custodian::new(NonZeroU64::new(8).unwrap(), &m, f.custody, &f.catalog);
        let old = foreign.begin(0).unwrap();
        assert_eq!(c.abandon_unprepared(old), Err(Error::StaleAttempt));
        assert_eq!((c.phase(), c.last_attempt()), (Phase::Spawning, 1));
        let (t, thread) = target(&mut f.a, &mut f.s, &m);
        let (binding, token) = c.prepare(initial, &mut f.a, &f.s, t).unwrap();
        let (other, other_thread) = target(&mut f.a, &mut f.s, &m);
        let mut other_binding =
            Bindings::new(NonZeroU64::new(8).unwrap(), &m, f.custody, &f.catalog);
        let other_token = other_binding.prepare(&mut f.a, &f.s, other).unwrap();
        let other_image = image(&mut f.s, &m, other);
        let foreign_active = other_binding
            .activate(&f.a, &mut f.s, other_token, other_thread, other_image)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(c.confirm_active(&foreign_active), Err(Error::StaleToken));
        assert_eq!((c.phase(), c.current()), (Phase::Prepared, Some(token)));
        let image = image(&mut f.s, &m, t);
        let active = binding
            .activate(&f.a, &mut f.s, token, thread, image)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        c.confirm_active(&active).unwrap();
    }
    #[test]
    fn prepared_targets_stay_held_and_preparation_integrity_failure_latches_recovery() {
        let m = manifest();
        let mut f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let permit = c.begin(0).unwrap();
        let (mut t, _) = target(&mut f.a, &mut f.s, &m);
        t.process = f.s.create_process(t.job).unwrap();
        assert_eq!(
            c.prepare(permit, &mut f.a, &f.s, t).err(),
            Some(Error::RecoveryRequired(Recovery::Preparation(
                incarnation::Error::Scheduler(scheduler::Error::NotHeld)
            )))
        );
        assert_eq!(c.current(), None);
        assert_eq!(f.s.dispatch(0), Ok(None));
        assert!(matches!(
            c.begin(100).err(),
            Some(Error::RecoveryRequired(_))
        ));
    }
    #[test]
    fn incomplete_revocation_or_live_descendant_job_charges_return_both_owners() {
        let m = manifest();
        let mut f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let permit = c.begin(0).unwrap();
        let (t, _) = target(&mut f.a, &mut f.s, &m);
        let (binding, token) = c.prepare(permit, &mut f.a, &f.s, t).unwrap();
        c.begin_revocation(token).unwrap();
        let mut rejected = c
            .accept_quiescence(&f.s, binding, Receipt(token))
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::NotQuiescent);
        rejected.binding.revoke(&mut f.a, token).unwrap();
        let rejected = c
            .accept_quiescence(&f.s, rejected.binding, rejected.receipt)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::NotQuiescent);
        f.s.terminate_process(t.process).unwrap();
        let child_job =
            f.s.create_child_job(t.job, Limits::new(1, 1, 1, 1))
                .unwrap();
        let child = f.s.create_process(child_job).unwrap();
        f.s.create_thread(child).unwrap();
        f.s.charge_frames(child_job, 1).unwrap();
        let rejected = c
            .accept_quiescence(&f.s, rejected.binding, rejected.receipt)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::NotQuiescent);
        f.s.terminate_process(child).unwrap();
        let rejected = c
            .accept_quiescence(&f.s, rejected.binding, rejected.receipt)
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::NotQuiescent);
        f.s.release_frames(child_job, 1).unwrap();
        c.accept_quiescence(&f.s, rejected.binding, rejected.receipt)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(c.phase(), Phase::Quiescent);
    }
    #[test]
    fn foreign_revoked_binding_with_equal_numeric_token_does_not_certify_this_owner() {
        let m = manifest();
        let other_m = manifest();
        let mut f = fixture();
        let mut other = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let permit = c.begin(0).unwrap();
        let (t, _) = target(&mut f.a, &mut f.s, &m);
        let (_binding, token) = c.prepare(permit, &mut f.a, &f.s, t).unwrap();
        c.begin_revocation(token).unwrap();
        let (target, _) = target(&mut other.a, &mut other.s, &other_m);
        let mut foreign = Bindings::new(
            NonZeroU64::new(7).unwrap(),
            &other_m,
            other.custody,
            &other.catalog,
        );
        let foreign_token = foreign.prepare(&mut other.a, &other.s, target).unwrap();
        assert_eq!(foreign_token, token); // IDs are instance-local; context is not.
        foreign.revoke(&mut other.a, foreign_token).unwrap();
        other.s.terminate_process(target.process).unwrap();
        let rejected = c
            .accept_quiescence(&other.s, foreign, Receipt(foreign_token))
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::ForeignBinding);
        assert_eq!((c.phase(), c.current()), (Phase::Revoking, Some(token)));
    }
    #[test]
    fn rejected_activation_integrity_is_actual_failure_evidence_not_a_replacement_gate() {
        let m = manifest();
        let mut f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let permit = c.begin(0).unwrap();
        let (t, thread) = target(&mut f.a, &mut f.s, &m);
        let (binding, token) = c.prepare(permit, &mut f.a, &f.s, t).unwrap();
        assert_eq!(c.report_failure(&binding), Err(Error::Phase));
        let mut model = image(&mut f.s, &m, t);
        model.0.manifest[0] ^= 1;
        let rejected = binding
            .activate(&f.a, &mut f.s, token, thread, model)
            .err()
            .unwrap();
        assert_eq!(rejected.error, incarnation::Error::ImageMismatch);
        c.report_failure(&rejected.binding).unwrap();
        let reason = Recovery::Preparation(incarnation::Error::ImageMismatch);
        assert_eq!(c.recovery_required(), Some(reason));
        assert_eq!(c.begin(100).err(), Some(Error::RecoveryRequired(reason)));
        assert_eq!(
            c.begin_revocation(token),
            Err(Error::RecoveryRequired(reason))
        );
        assert_eq!(f.s.dispatch(0), Ok(None));
    }
    #[test]
    fn prematurely_recycled_scheduler_generations_cannot_satisfy_old_quiescence() {
        let m = manifest();
        let mut f = fixture();
        let mut c = Custodian::new(NonZeroU64::new(7).unwrap(), &m, f.custody, &f.catalog);
        let permit = c.begin(0).unwrap();
        let (t, _) = target(&mut f.a, &mut f.s, &m);
        let (mut binding, token) = c.prepare(permit, &mut f.a, &f.s, t).unwrap();
        c.begin_revocation(token).unwrap();
        binding.revoke(&mut f.a, token).unwrap();
        f.s.terminate_process(t.process).unwrap();
        f.s.reclaim_process(t.process).unwrap();
        f.s.reclaim_job(t.job).unwrap();
        let job = f.s.create_job_with_limits(m.limits()).unwrap();
        let process = f.s.create_held_process(job).unwrap();
        assert_ne!((job, process), (t.job, t.process));
        let rejected = c
            .accept_quiescence(&f.s, binding, Receipt(token))
            .err()
            .unwrap();
        assert_eq!(
            rejected.error,
            Error::RecoveryRequired(Recovery::Scheduler(scheduler::Error::InvalidId))
        );
        assert_eq!(
            (c.phase(), c.current()),
            (Phase::RecoveryRequired, Some(token))
        );
        assert!(matches!(
            c.begin(100).err(),
            Some(Error::RecoveryRequired(_))
        ));
    }
}

#[cfg(test)]
mod root_v2_tests {
    use super::*;
    use crate::{
        root_manifest_v2,
        root_producer_v2::{Description, Identity, encode_current},
    };
    #[test]
    fn root_v2_capacity_failure_uses_same_custodian_and_latches_without_dispatch() {
        let desc = Description::full_graph(
            [4096, 256, 7, 7],
            3,
            60,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        let bytes =
            encode_current(include_bytes!("../fixtures/bootstrap-static-v1.elf"), &desc).unwrap();
        let manifest = root_manifest_v2::verify(
            bytes.bytes(),
            bytes.digest(),
            include_bytes!("../fixtures/bootstrap-static-v1.elf"),
        )
        .unwrap()
        .current_profile()
        .unwrap();
        let mut a = Authority::new();
        let custody = a.create_space().unwrap();
        let branches = a.create_space().unwrap();
        let destination = a.create_space().unwrap();
        let mut s = Scheduler::new();
        let job = s
            .create_job_with_limits(manifest.manifest().limits())
            .unwrap();
        let process = s.create_held_process(job).unwrap();
        s.create_thread(process).unwrap();
        let mut c = Custodian::new_root_v2(NonZeroU64::new(33).unwrap(), &manifest, custody, &[]);
        let attempt = c.begin(0).unwrap();
        let before = a.metadata_usage();
        let result = c.prepare(
            attempt,
            &mut a,
            &s,
            Target {
                process,
                job,
                destination,
                branches,
            },
        );
        assert!(matches!(
            result,
            Err(Error::RecoveryRequired(Recovery::Preparation(
                crate::incarnation::Error::Binding(crate::bootstrap_binding::Error::RootV2(
                    crate::root_binding_v2::Error::Capacity
                ))
            )))
        ));
        assert_eq!(a.metadata_usage(), before);
        assert_eq!(c.last_attempt(), 1);
        assert_eq!(c.phase(), Phase::RecoveryRequired);
        assert!(c.current().is_none());
        assert!(c.begin(1).is_err());
        assert_eq!(s.dispatch(0), Ok(None));
    }
}
