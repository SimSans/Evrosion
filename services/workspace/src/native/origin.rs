//! Captured current serving-call origin. No payload nominates a caller or PID.
use super::{now, require};
use ev_userspace_contract::syscall;
use ev_userspace_runtime as rt;

#[derive(Clone, Copy)]
pub struct Origin {
    pub process: u64,
    pub thread: u64,
    pub registered: u64,
    pub epoch: u64,
    pub serial: u64,
    pub endpoint: u64,
    pub deadline: u64,
    pub status: u64,
}
/// Pin only after the actual dedicated Root-only receiver has authenticated
/// its first live caller. A registered token alone is never Root-role proof.
#[derive(Clone, Copy)]
pub struct RootSession {
    process: u64,
    thread: u64,
    registered: u64,
    endpoint: u64,
    epoch: u64,
}
impl RootSession {
    pub fn new(origin: Origin) -> Self {
        Self {
            process: origin.process,
            thread: origin.thread,
            registered: origin.registered,
            endpoint: origin.endpoint,
            epoch: origin.epoch,
        }
    }
    pub fn matches(self, origin: Origin) -> bool {
        (
            self.process,
            self.thread,
            self.registered,
            self.endpoint,
            self.epoch,
        ) == (
            origin.process,
            origin.thread,
            origin.registered,
            origin.endpoint,
            origin.epoch,
        )
    }
}
pub fn negotiate() {
    let reply = rt::call4(syscall::SERVING_ORIGIN_INFO, 0, 0, 0, 0);
    require(
        reply.status == 0
            && reply.value == syscall::SERVING_ORIGIN_V1
            && reply.capability == 0
            && reply.serial == 0,
        1220,
    );
}
pub fn capture(endpoint: u64, nonce: u64) -> Option<Origin> {
    let mut values = [0; 8];
    for (field, value) in values.iter_mut().enumerate() {
        let reply = rt::call(syscall::SERVING_ORIGIN, endpoint, nonce, field as u64);
        if reply.status != 0 || reply.capability != 0 {
            return None;
        }
        *value = reply.value;
    }
    let inherited = rt::rpc_deadline();
    let status = rt::call(syscall::SERVING_ORIGIN, endpoint, nonce, 7);
    if inherited.status != 0
        || inherited.capability != 0
        || status.status != 0
        || status.capability != 0
        || status.value != values[7]
        || inherited.value != values[6]
        || values[0] == 0
        || values[0] == u64::MAX
        || values[1] == 0
        || values[1] == u64::MAX
        || values[2] == u64::MAX
        || values[3] == 0
        || values[3] == u64::MAX
        || values[4] != nonce
        || values[5] == u64::MAX
        || values[6] == 0
        || values[6] == u64::MAX
    {
        return None;
    }
    Some(Origin {
        process: values[0],
        thread: values[1],
        registered: values[2],
        epoch: values[3],
        serial: values[4],
        endpoint: values[5],
        deadline: values[6],
        status: values[7],
    })
}
impl Origin {
    pub fn live(self) -> bool {
        self.status == 0 && rt::execution::accepts_deadline(0, now(), self.deadline, 8192)
    }
    pub fn same_call(self, other: Self) -> bool {
        self.process == other.process
            && self.thread == other.thread
            && self.registered == other.registered
            && self.epoch == other.epoch
            && self.serial == other.serial
            && self.endpoint == other.endpoint
            && self.deadline == other.deadline
    }
}
