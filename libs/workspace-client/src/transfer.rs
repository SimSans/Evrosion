//! Finite whole-file policy, separate from each newly issued File2 RPC.
//!
//! Capture once before loading or freezing a Save. Progress, focus, hashing,
//! Commit continuation and readback never extend `whole_cut`. A returned cut
//! belongs to one NEW request and must be identical in its header and actual
//! RPC. It cannot replace the cut of any accepted/retained request. The owning
//! FileClient still retains its exact request and window on uncertainty; this
//! helper is neither a retry mechanism nor a loan-return/retirement receipt.

use ev_userspace_contract::workspace::Deadline;

pub const FILE_RPC_TICKS: u64 = 8192;
pub const CHUNK_BYTES: u64 = 4096;
pub const EXTRA_CHUNK_TICKS: u64 = 512;
pub const MAX_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_TRANSFER_TICKS: u64 = 138_752;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Clock,
    Overflow,
    Expired,
    Fenced,
}

/// A size-bounded scheduling allowance, not a measured throughput guarantee.
/// Empty files and files up to one chunk retain the original8192-tick horizon.
pub fn horizon_ticks(bytes: u64) -> Result<u64, Error> {
    if bytes > MAX_TRANSFER_BYTES {
        return Err(Error::Bounds);
    }
    let extra_chunks = bytes.div_ceil(CHUNK_BYTES).saturating_sub(1);
    Ok(FILE_RPC_TICKS + extra_chunks * EXTRA_CHUNK_TICKS)
}

/// This value deliberately cannot be copied/cloned. Retain the same owner
/// through every phase, and fence it on any failed or uncertain completion.
#[derive(Debug)]
pub struct Transfer {
    whole_cut: Deadline,
    last_clock: u64,
    fenced: bool,
}
impl Transfer {
    pub fn capture(now: u64, bytes: u64) -> Result<Self, Error> {
        let ticks = horizon_ticks(bytes)?;
        if now == u64::MAX {
            return Err(Error::Clock);
        }
        let end = now
            .checked_add(ticks)
            .filter(|end| *end != u64::MAX)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            whole_cut: Deadline::new(end).map_err(|_| Error::Overflow)?,
            last_clock: now,
            fenced: false,
        })
    }
    pub const fn whole_cut(&self) -> Deadline {
        self.whole_cut
    }
    pub const fn fenced(&self) -> bool {
        self.fenced
    }
    pub fn fence(&mut self) {
        self.fenced = true;
    }
    /// Check completion/hash work against the same whole cut without creating
    /// a new request. This does not acknowledge completion or return any loan.
    pub fn check(&mut self, now: u64) -> Result<(), Error> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        let result = if now == u64::MAX || now < self.last_clock {
            Err(Error::Clock)
        } else if !self.whole_cut.is_live(now) {
            Err(Error::Expired)
        } else {
            Ok(())
        };
        match result {
            Ok(()) => self.last_clock = now,
            Err(_) => self.fence(),
        }
        result
    }
    /// Call only before a distinct new request, after prior completion returned
    /// its loan. Expiry or an invalid/backward clock permanently fences this
    /// transfer. No method renews its whole horizon or clears this fence.
    pub fn next_request(&mut self, now: u64) -> Result<Deadline, Error> {
        self.check(now)?;
        // Subtract before adding: a valid near-MAX whole_cut can still clamp
        // the request without overflowing now+FILE_RPC_TICKS.
        let span = (self.whole_cut.tick() - now).min(FILE_RPC_TICKS);
        Ok(Deadline::new(now + span).expect("live finite whole cut bounds request"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_files_keep_original_horizon_and_maximum_is_finite() {
        for bytes in [0, 1, 15, 4095, 4096] {
            assert_eq!(horizon_ticks(bytes), Ok(FILE_RPC_TICKS));
        }
        assert_eq!(horizon_ticks(4097), Ok(8704));
        assert_eq!(horizon_ticks(MAX_TRANSFER_BYTES), Ok(MAX_TRANSFER_TICKS));
        assert_eq!(horizon_ticks(MAX_TRANSFER_BYTES + 1), Err(Error::Bounds));
        assert_eq!(horizon_ticks(u64::MAX), Err(Error::Bounds));
        // All permitted sizes are monotonic and remain within the hard ceiling.
        let mut previous = 0;
        for bytes in 0..=MAX_TRANSFER_BYTES {
            let ticks = horizon_ticks(bytes).unwrap();
            assert!((previous..=MAX_TRANSFER_TICKS).contains(&ticks));
            previous = ticks;
        }
    }

    #[test]
    fn new_requests_are_clamped_and_whole_horizon_never_moves() {
        let mut t = Transfer::capture(100, MAX_TRANSFER_BYTES).unwrap();
        let whole = t.whole_cut();
        assert_eq!(whole.tick(), 100 + MAX_TRANSFER_TICKS);
        for now in [100, 500, 10_000, whole.tick() - 8192, whole.tick() - 1] {
            let cut = t.next_request(now).unwrap();
            assert_eq!(cut.tick(), whole.tick().min(now + FILE_RPC_TICKS));
            assert!(cut.is_live(now));
            assert!(cut.tick() - now <= FILE_RPC_TICKS);
            assert_eq!(t.whole_cut(), whole);
        }
        assert_eq!(t.next_request(whole.tick()), Err(Error::Expired));
        assert_eq!(t.next_request(whole.tick() - 1), Err(Error::Fenced));
        assert_eq!(t.whole_cut(), whole);
    }

    #[test]
    fn overflow_reserved_clock_and_backward_time_cannot_reopen_a_transfer() {
        assert!(matches!(Transfer::capture(u64::MAX, 0), Err(Error::Clock)));
        for now in [u64::MAX - FILE_RPC_TICKS, u64::MAX - 1] {
            assert!(matches!(Transfer::capture(now, 0), Err(Error::Overflow)));
        }
        let mut near_max = Transfer::capture(u64::MAX - FILE_RPC_TICKS - 1, 0).unwrap();
        assert_eq!(
            near_max.next_request(u64::MAX - 2).unwrap().tick(),
            u64::MAX - 1
        );
        for bad in [99, u64::MAX] {
            let mut t = Transfer::capture(100, MAX_TRANSFER_BYTES).unwrap();
            assert_eq!(t.next_request(bad), Err(Error::Clock));
            assert_eq!(t.next_request(101), Err(Error::Fenced));
        }
    }

    #[test]
    fn explicit_uncertainty_fence_preserves_cut_and_never_issues_again() {
        let mut t = Transfer::capture(100, MAX_TRANSFER_BYTES).unwrap();
        let whole = t.whole_cut();
        let original = t.next_request(200).unwrap();
        t.fence();
        t.fence();
        assert!(t.fenced());
        assert_eq!(t.next_request(201), Err(Error::Fenced));
        assert_eq!(t.whole_cut(), whole);
        assert_eq!(original.tick(), 200 + FILE_RPC_TICKS);
    }

    #[test]
    fn final_hash_or_completion_work_does_not_gain_a_fresh_horizon() {
        let mut t = Transfer::capture(100, 4096).unwrap();
        let cut = t.next_request(101).unwrap();
        assert_eq!(t.check(cut.tick() - 1), Ok(()));
        assert_eq!(t.whole_cut(), cut);
        assert_eq!(t.check(cut.tick()), Err(Error::Expired));
        assert_eq!(t.check(100), Err(Error::Fenced));
    }
}
