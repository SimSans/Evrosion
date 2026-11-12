//! Internal restart admission primitive for future sealed bootstrap custody.
//!
//! This neither creates a supervisor nor grants authority. The custodian must
//! own one budget per boot epoch, supply trusted monotonic ticks, and call admit
//! after revocation/quiescence but BEFORE attempting each replacement spawn.
//! Initial launch is separate. Failed spawn attempts are never refunded.
use crate::time::Deadline;

pub const MAX_ATTEMPTS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum InvalidPolicy {
    Capacity,
    EmptyWindow,
}

/// Manifest policy, with window duration already converted to clock ticks.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    attempts: u8,
    window_ticks: u64,
}

impl Policy {
    pub fn new(attempts: u8, window_ticks: u64) -> Result<Self, InvalidPolicy> {
        if usize::from(attempts) > MAX_ATTEMPTS {
            return Err(InvalidPolicy::Capacity);
        }
        if window_ticks == 0 {
            return Err(InvalidPolicy::EmptyWindow);
        }
        Ok(Self {
            attempts,
            window_ticks,
        })
    }
}

/// Structured reasons for the future independent recovery/diagnostic path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryRequired {
    BudgetExhausted,
    ClockWentBackwards,
    DeadlineOverflow,
}

/// Bounded, allocation-free sliding window. Not Clone: custody must retain the
/// same instance across failed incarnations. There is deliberately no reset API.
pub struct Budget {
    policy: Policy,
    expiries: [Option<Deadline>; MAX_ATTEMPTS],
    last_tick: Option<u64>,
    recovery: Option<RecoveryRequired>,
}

impl Budget {
    /// Trusted boot construction only; never expose this as a userspace reset.
    pub const fn new(policy: Policy) -> Self {
        Self {
            policy,
            expiries: [None; MAX_ATTEMPTS],
            last_tick: None,
            recovery: None,
        }
    }

    pub fn recovery_required(&self) -> Option<RecoveryRequired> {
        self.recovery
    }

    /// Consume one replacement attempt in (now - window, now]. Exactly at an
    /// old attempt's expiry it no longer counts. Any failure latches recovery;
    /// elapsed time cannot silently re-enable automatic restart afterwards.
    pub fn admit(&mut self, now: u64) -> Result<(), RecoveryRequired> {
        if let Some(reason) = self.recovery {
            return Err(reason);
        }
        if self.last_tick.is_some_and(|last| now < last) {
            return self.fail(RecoveryRequired::ClockWentBackwards);
        }
        self.last_tick = Some(now);
        for expiry in &mut self.expiries {
            if expiry.is_some_and(|deadline| deadline.reached(now)) {
                *expiry = None;
            }
        }
        let charged = self.expiries.iter().filter(|e| e.is_some()).count();
        if charged >= usize::from(self.policy.attempts) {
            return self.fail(RecoveryRequired::BudgetExhausted);
        }
        let Some(deadline) = Deadline::after(now, self.policy.window_ticks) else {
            return self.fail(RecoveryRequired::DeadlineOverflow);
        };
        // Policy validation and charged < attempts guarantee a free slot.
        for expiry in &mut self.expiries {
            if expiry.is_none() {
                *expiry = Some(deadline);
                return Ok(());
            }
        }
        self.fail(RecoveryRequired::BudgetExhausted)
    }

    fn fail(&mut self, reason: RecoveryRequired) -> Result<(), RecoveryRequired> {
        self.recovery = Some(reason);
        Err(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(attempts: u8, window: u64) -> Budget {
        Budget::new(Policy::new(attempts, window).unwrap())
    }

    #[test]
    fn failed_spawns_consume_budget_and_exhaustion_stays_latched() {
        let mut b = budget(3, 60);
        // No completion/refund call: failures after admission still count.
        for now in [0, 1, 2] {
            assert_eq!(b.admit(now), Ok(()));
        }
        assert_eq!(b.admit(3), Err(RecoveryRequired::BudgetExhausted));
        assert_eq!(b.admit(600), Err(RecoveryRequired::BudgetExhausted));
        assert_eq!(
            b.recovery_required(),
            Some(RecoveryRequired::BudgetExhausted)
        );
    }

    #[test]
    fn exact_expiry_releases_only_the_expired_attempt() {
        let mut b = budget(3, 60);
        for now in [0, 30, 59, 60] {
            assert_eq!(b.admit(now), Ok(()));
        }
        assert_eq!(b.admit(61), Err(RecoveryRequired::BudgetExhausted));
    }

    #[test]
    fn fixed_window_boundary_cannot_admit_a_double_burst() {
        let mut b = budget(3, 60);
        for now in [58, 59, 59] {
            assert_eq!(b.admit(now), Ok(()));
        }
        assert_eq!(b.admit(60), Err(RecoveryRequired::BudgetExhausted));
    }

    #[test]
    fn zero_policy_disables_restarts_and_all_slots_can_be_used() {
        assert_eq!(
            budget(0, 1).admit(0),
            Err(RecoveryRequired::BudgetExhausted)
        );
        let mut b = budget(MAX_ATTEMPTS as u8, 1);
        for _ in 0..MAX_ATTEMPTS {
            assert_eq!(b.admit(0), Ok(()));
        }
        for _ in 0..MAX_ATTEMPTS {
            assert_eq!(b.admit(1), Ok(()));
        }
        assert_eq!(b.admit(1), Err(RecoveryRequired::BudgetExhausted));
    }

    #[test]
    fn invalid_manifest_policy_is_rejected() {
        assert!(matches!(Policy::new(9, 60), Err(InvalidPolicy::Capacity)));
        assert!(matches!(Policy::new(3, 0), Err(InvalidPolicy::EmptyWindow)));
        assert!(matches!(Policy::new(0, 0), Err(InvalidPolicy::EmptyWindow)));
    }

    #[test]
    fn backwards_clock_requires_recovery_without_overwriting_reason() {
        let mut b = budget(3, 60);
        assert_eq!(b.admit(100), Ok(()));
        assert_eq!(b.admit(99), Err(RecoveryRequired::ClockWentBackwards));
        assert_eq!(b.admit(u64::MAX), Err(RecoveryRequired::ClockWentBackwards));
    }

    #[test]
    fn deadline_overflow_is_finite_and_max_tick_is_not_a_sentinel() {
        let mut b = budget(3, 60);
        assert_eq!(b.admit(u64::MAX - 60), Ok(()));
        assert_eq!(
            b.admit(u64::MAX - 59),
            Err(RecoveryRequired::DeadlineOverflow)
        );
        assert_eq!(b.admit(u64::MAX), Err(RecoveryRequired::DeadlineOverflow));
    }

    #[test]
    fn exhaustive_small_traces_match_counting_history_oracle() {
        // Oracle retains all accepted timestamps, rather than recycling slots.
        // Enumerate 4^6 monotonic traces for each capacity 0..=8.
        for capacity in 0..=MAX_ATTEMPTS {
            for trace in 0u32..4096 {
                let mut b = budget(capacity as u8, 7);
                let mut history = [None; 6];
                let mut denied = false;
                let mut now = 0;
                for step in 0..6 {
                    now += [0, 1, 3, 8][((trace >> (step * 2)) & 3) as usize];
                    let recent = history.iter().flatten().filter(|&&t| now - t < 7).count();
                    denied |= recent >= capacity;
                    let expected = if denied {
                        Err(RecoveryRequired::BudgetExhausted)
                    } else {
                        history[step] = Some(now);
                        Ok(())
                    };
                    assert_eq!(
                        b.admit(now),
                        expected,
                        "capacity={capacity} trace={trace} step={step}"
                    );
                }
            }
        }
    }
}
