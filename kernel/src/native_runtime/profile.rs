//! Actual captured-trap census. Fixed actor-slot totals span replacements;
//! current sampled identities/Job usage are reported separately by the caller.
use ev_kernel::scheduler::{ProcessId, ThreadId};
#[derive(Default)]
pub(crate) struct Slot {
    identity: Option<(ProcessId, ThreadId)>,
    pub incarnations: u64,
    pub captures: u64,
    pub syscalls: u64,
    pub irqs: u64,
    pub faults: u64,
    pub port_in: u64,
    pub port_out: u64,
    pub yields: u64,
    pub continuations: u64,
    pub charged_cpu_ticks: u64,
}
pub(crate) const SLOTS: usize = if cfg!(feature = "test-m6-network") {
    9
} else {
    7
};
pub(crate) struct Profile {
    pub started: u64,
    pub slots: [Slot; SLOTS],
}
impl Profile {
    pub fn new(started: u64) -> Self {
        Self {
            started,
            slots: core::array::from_fn(|_| Slot::default()),
        }
    }
    pub fn captured(
        &mut self,
        index: usize,
        process: ProcessId,
        thread: ThreadId,
        vector: u64,
        number: u64,
    ) {
        let slot = &mut self.slots[index];
        if slot.identity != Some((process, thread)) {
            slot.identity = Some((process, thread));
            slot.incarnations += 1;
        }
        slot.captures += 1;
        match vector {
            32 => slot.irqs += 1,
            128 => {
                slot.syscalls += 1;
                match number {
                    ev_userspace_contract::syscall::PORT_INPUT
                    | ev_userspace_contract::syscall::PORT_INPUT_WORDS4
                    | ev_userspace_contract::syscall::PORT_INPUT_BYTES4 => slot.port_in += 1,
                    ev_userspace_contract::syscall::PORT_OUTPUT
                    | ev_userspace_contract::syscall::PORT_OUTPUT_WORDS4
                    | ev_userspace_contract::syscall::PORT_OUTPUT_BYTES4 => slot.port_out += 1,
                    ev_userspace_contract::syscall::YIELD => slot.yields += 1,
                    _ => {}
                }
            }
            _ => slot.faults += 1,
        }
    }
    pub fn charged(&mut self, index: usize, ticks: u64) {
        self.slots[index].charged_cpu_ticks += ticks;
    }
    pub fn continued(&mut self, index: usize) {
        self.slots[index].continuations += 1;
    }
}
