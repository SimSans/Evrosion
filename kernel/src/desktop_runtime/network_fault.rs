//! A failed NIC graph remains unavailable until a real device-quiescence path
//! exists. Thread death is not a STOP/readback/reset receipt. Failure classes
//! never clear and recreation stays forbidden. The separate captured-Root join
//! may discharge retirement only after actual graph exclusion + physical work.
#[derive(Clone, Copy)]
struct Fence {
    pair: [u64; 4],
    cut: u64,
    first: u64,
}
#[derive(Default)]
pub(super) struct Latch {
    failed: u8,
    exited: u8,
    #[cfg(feature = "test-m6-network-negative")]
    controller_stopped: u8,
    fence: Option<Fence>,
    discharged: bool,
}
impl Latch {
    fn bit(actor: usize) -> u8 {
        match actor {
            7 => 1,
            8 => 2,
            _ => 0,
        }
    }
    /// Slots7/8 are the immutable V4 Driver/Service actor slots, not PIDs.
    pub fn record(&mut self, actor: usize) {
        self.failed |= Self::bit(actor);
    }
    /// Voluntary CPU exit is a separate actual observation, never a fault.
    /// Retain the first termination class and exactly the same hardware debt.
    pub fn record_exit(&mut self, actor: usize) -> bool {
        let bit = Self::bit(actor);
        if bit == 0 {
            return false;
        }
        if self.failed & bit == 0 {
            self.exited |= bit;
        }
        self.failed |= bit;
        true
    }
    /// Test-controller process stop is distinct from a voluntary user Exit or
    /// fault. Only the explicit captured-call fixture invokes this operation.
    #[cfg(feature = "test-m6-network-negative")]
    pub fn record_controller_stop(&mut self, actor: usize) -> bool {
        let bit = Self::bit(actor);
        if bit == 0 {
            return false;
        }
        if self.failed & bit == 0 {
            self.controller_stopped |= bit;
        }
        self.failed |= bit;
        true
    }
    pub fn blocks_retirement(&self, actor: usize) -> bool {
        self.failed != 0 && !self.discharged && matches!(actor, 7 | 8)
    }
    pub fn blocks_creation(&self, actor: usize) -> bool {
        self.failed != 0 && matches!(actor, 7 | 8)
    }
    /// Additional V4 profile fence; actual IoPorts kind/rights/lineage/range
    /// and live Scheduler/RPC caller checks still follow before any hardware I/O.
    /// Root's retained NIC capability operates only in this exclusive stage.
    pub fn permits_port(&self, actor: usize, port: u64, now: u64) -> bool {
        if !(0x300..0x320).contains(&port) {
            return true;
        }
        if actor == 0 {
            return !self.discharged
                && self
                    .fence
                    .is_some_and(|fence| now >= fence.first && now < fence.cut);
        }
        self.failed == 0
    }
    /// Only the Runtime's captured actual Root/pair/no-work boundary calls this.
    /// Pair values are actual retained process/thread identities, never caller
    /// labels. The single token is scoped to this one Root and one failed graph.
    pub fn begin_retirement(&mut self, pair: [u64; 4], now: u64, cut: u64) -> Result<u64, u64> {
        if self.failed == 0 || self.discharged || self.fence.is_some() {
            return Err(2);
        }
        if pair.contains(&0) || pair[0] == pair[2] || pair[1] == pair[3] {
            return Err(1);
        }
        if now == u64::MAX || cut == u64::MAX || cut <= now || cut - now > 8192 {
            return Err(4);
        }
        self.fence = Some(Fence {
            pair,
            cut,
            first: now,
        });
        Ok(1)
    }
    /// Does not itself prove device I/O. The sealed trusted Root adapter must
    /// consume its move-only actual Stopped<Mediated> before this call, just as
    /// nominal NW7 trusts that exact source's Driver STOP/readback join.
    pub fn finish_retirement(&mut self, pair: [u64; 4], token: u64, now: u64) -> Result<u64, u64> {
        let fence = self.fence.ok_or(2u64)?;
        if self.discharged || token != 1 || pair != fence.pair {
            return Err(1);
        }
        if now < fence.first || now >= fence.cut || now == u64::MAX {
            return Err(4);
        }
        self.discharged = true;
        self.fence = None;
        Ok(0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn either_actual_network_fault_keeps_both_hardware_participants_owned() {
        for failed in [7, 8] {
            let mut l = Latch::default();
            assert!(!l.blocks_retirement(7));
            assert!(!l.blocks_retirement(8));
            l.record(failed);
            assert!(l.blocks_retirement(7));
            assert!(l.blocks_retirement(8));
            // An unrelated fault/replacement cannot clear prior uncertainty.
            l.record(5);
            l.record(0);
            assert!(l.blocks_retirement(7));
            assert!(l.blocks_retirement(8));
        }
    }
    #[test]
    fn non_network_faults_do_not_manufacture_a_network_failure() {
        let mut l = Latch::default();
        for actor in [0, 1, 2, 3, 4, 5, 6, 9, usize::MAX] {
            l.record(actor);
        }
        for actor in 0..10 {
            assert!(!l.blocks_retirement(actor));
        }
    }
    #[test]
    fn latch_does_not_block_unrelated_owned_processes() {
        let mut l = Latch::default();
        l.record(7);
        l.record(8);
        for actor in [0, 1, 2, 3, 4, 5, 6, 9] {
            assert!(!l.blocks_retirement(actor));
        }
    }
    #[test]
    fn actual_exit_keeps_both_owners_without_manufacturing_a_fault_class() {
        for actor in [7, 8] {
            let mut fault = Latch::default();
            fault.record(actor);
            let mut exit = Latch::default();
            assert!(exit.record_exit(actor));
            assert_eq!(fault.failed, exit.failed);
            assert_eq!(fault.exited, 0);
            assert_eq!(exit.exited, Latch::bit(actor));
            for other in [7, 8] {
                assert!(exit.blocks_retirement(other));
            }
            // No later observation can replace the first retained cause.
            exit.record(actor);
            assert_eq!(exit.exited, Latch::bit(actor));
            fault.record_exit(actor);
            assert_eq!(fault.exited, 0);
        }
    }
    #[test]
    fn non_network_exit_cannot_latch_device_debt_or_claim_network_identity() {
        let mut l = Latch::default();
        for actor in [0, 1, 2, 3, 4, 5, 6, 9, usize::MAX] {
            assert!(!l.record_exit(actor));
        }
        assert_eq!((l.failed, l.exited), (0, 0));
    }
    #[test]
    fn retirement_requires_one_failed_exact_pair_and_never_permits_recreation() {
        let pair = [11, 21, 12, 22];
        let mut latch = Latch::default();
        assert_eq!(latch.begin_retirement(pair, 100, 8292), Err(2));
        latch.record_exit(7);
        let cause = (latch.failed, latch.exited);
        assert_eq!(latch.finish_retirement(pair, 1, 100), Err(2));
        assert_eq!(latch.begin_retirement(pair, 100, 8292), Ok(1));
        assert_eq!(latch.begin_retirement(pair, 101, 8293), Err(2));
        assert!(latch.blocks_retirement(7) && latch.blocks_retirement(8));
        for wrong in [[0, 21, 12, 22], [12, 22, 11, 21], [11, 21, 13, 23]] {
            assert_eq!(latch.finish_retirement(wrong, 1, 101), Err(1));
        }
        for token in [0, 2, u64::MAX] {
            assert_eq!(latch.finish_retirement(pair, token, 101), Err(1));
        }
        assert_eq!(latch.finish_retirement(pair, 1, 101), Ok(0));
        assert!(!latch.blocks_retirement(7) && !latch.blocks_retirement(8));
        assert!(latch.blocks_creation(7) && latch.blocks_creation(8));
        assert_eq!((latch.failed, latch.exited), cause);
        assert_eq!(latch.finish_retirement(pair, 1, 102), Err(2));
        assert_eq!(latch.begin_retirement(pair, 102, 8294), Err(2));
    }
    #[test]
    fn original_retirement_cut_never_renews_after_clock_refusal() {
        for tick in [99, 8292, u64::MAX] {
            let mut latch = Latch::default();
            latch.record(8);
            let pair = [1, 2, 3, 4];
            latch.begin_retirement(pair, 100, 8292).unwrap();
            assert_eq!(latch.finish_retirement(pair, 1, tick), Err(4));
            assert_eq!(latch.fence.unwrap().cut, 8292);
            assert_eq!(latch.begin_retirement(pair, 101, 8293), Err(2));
            assert!(latch.blocks_retirement(7) && latch.blocks_retirement(8));
        }
    }
    #[test]
    fn malformed_pair_or_unbounded_cut_cannot_arm_a_fence() {
        for pair in [[0, 2, 3, 4], [1, 0, 3, 4], [1, 2, 1, 4], [1, 2, 3, 2]] {
            let mut latch = Latch::default();
            latch.record(7);
            assert_eq!(latch.begin_retirement(pair, 100, 8292), Err(1));
            assert!(latch.fence.is_none());
        }
        for cut in [0, 100, 8293, u64::MAX] {
            let mut latch = Latch::default();
            latch.record(7);
            assert_eq!(latch.begin_retirement([1, 2, 3, 4], 100, cut), Err(4));
            assert!(latch.fence.is_none());
        }
    }
    #[test]
    fn only_actual_root_can_use_nic_ports_inside_the_armed_exclusive_cut() {
        let mut latch = Latch::default();
        assert!(!latch.permits_port(0, 0x300, 100));
        assert!(latch.permits_port(7, 0x300, 100));
        latch.record(7);
        assert!(!latch.permits_port(0, 0x300, 100));
        for actor in 1..=8 {
            assert!(!latch.permits_port(actor, 0x300, 100));
        }
        let pair = [11, 21, 12, 22];
        latch.begin_retirement(pair, 100, 8292).unwrap();
        for port in 0x300..0x320 {
            assert!(latch.permits_port(0, port, 100));
            assert!(!latch.permits_port(0, port, 99));
            assert!(!latch.permits_port(0, port, 8292));
            assert!(!latch.permits_port(0, port, u64::MAX));
            for actor in 1..=8 {
                assert!(!latch.permits_port(actor, port, 101));
            }
        }
        // Ordinary local actual port permits still require their normal
        // authority, but a NIC failure does not fence storage/Input/UART.
        for port in [0x60, 0x64, 0x1e8, 0x3f8, 0x3fd] {
            assert!(latch.permits_port(0, port, 101));
            assert!(latch.permits_port(1, port, 101));
        }
        latch.finish_retirement(pair, 1, 101).unwrap();
        for actor in 0..=8 {
            assert!(!latch.permits_port(actor, 0x300, 102));
        }
        assert!(latch.blocks_creation(7) && latch.blocks_creation(8));
    }
}

#[cfg(all(test, feature = "test-m6-network-negative"))]
mod negative_tests {
    use super::*;
    #[test]
    fn controller_stop_is_distinct_immutable_cause_and_never_undoes_debt() {
        for actor in [7, 8] {
            let mut l = Latch::default();
            assert!(l.record_controller_stop(actor));
            assert_eq!(l.failed, Latch::bit(actor));
            assert_eq!(l.exited, 0);
            assert_eq!(l.controller_stopped, Latch::bit(actor));
            l.record_exit(actor);
            l.record(actor);
            assert_eq!(l.exited, 0);
            assert_eq!(l.controller_stopped, Latch::bit(actor));
            for owner in [7, 8] {
                assert!(l.blocks_retirement(owner));
                assert!(l.blocks_creation(owner));
            }
            let pair = [1, 2, 3, 4];
            l.begin_retirement(pair, 100, 8292).unwrap();
            l.finish_retirement(pair, 1, 101).unwrap();
            assert_eq!(l.controller_stopped, Latch::bit(actor));
            for owner in [7, 8] {
                assert!(l.blocks_creation(owner));
            }
        }
        let mut l = Latch::default();
        l.record(7);
        l.record_controller_stop(7);
        assert_eq!(l.controller_stopped, 0);
        for actor in [0, 1, 2, 3, 4, 5, 6, 9] {
            assert!(!l.record_controller_stop(actor));
        }
    }
}
