//! Actual stopped controls stay held through diagnostics and Kernel retirement.
//! No Ready, close or packet token substitutes for returned RPC/escrow credit.
use super::*;
#[derive(Clone, Copy)]
struct Attempt {
    window: u64,
    count: u8,
    by: u64,
    recorded: bool,
    fenced: bool,
}
impl Attempt {
    const EMPTY: Self = Self {
        window: 0,
        count: 0,
        by: 0,
        recorded: false,
        fenced: false,
    };
}
#[derive(Clone, Copy)]
struct Record {
    identity: Identity,
    role: u8,
    image: [u8; 32],
    epoch: u64,
    job: [u64; 9],
    fault: Option<[u64; 24]>,
}
impl Record {
    fn valid(&self) -> bool {
        self.identity.valid()
            && usize::from(self.role) < graph::CHILDREN.len()
            && self.image != [0; 32]
            && self.epoch != 0
            && self.job[0] != 0
            && self.fault.is_none_or(|f| {
                (f[0], f[1], f[2]) == (self.job[0], self.identity.process, self.identity.thread)
            })
    }
}
pub(super) struct State {
    attempts: [Attempt; 11],
    records: [Option<Record>; 2],
    next_record: usize,
}
impl State {
    pub const fn new() -> Self {
        Self {
            attempts: [Attempt::EMPTY; 11],
            records: [None; 2],
            next_record: 0,
        }
    }
}
impl Root<'_> {
    fn capture_stopped(&mut self, child: Child, actor: Actor) {
        let mut job = [0; 9];
        for (field, value) in job.iter_mut().enumerate() {
            let reply = rt::call(s::PROCESS_JOB_INFO, actor.control, field as u64, 0);
            require(reply.status == 0 && reply.capability == 0, 1653);
            *value = reply.value;
        }
        let mut fault = [0; 24];
        let mut complete = true;
        for (field, value) in fault.iter_mut().enumerate() {
            let reply = rt::call(s::FAULT_INFO, actor.control, field as u64, 0);
            if reply.status == 1 && reply.value == 0 && reply.capability == 0 {
                complete = false;
                break;
            }
            require(reply.status == 0 && reply.capability == 0, 1654);
            *value = reply.value;
        }
        let record = Record {
            identity: actor.identity,
            role: child.index() as u8,
            image: self.catalogue.image(child.image_slot()).image,
            epoch: self.bootstrap.context().epoch,
            job,
            fault: if complete { Some(fault) } else { None },
        };
        require(record.valid(), 1661);
        // Explicit bounded volatile history, not a durable crash archive/export.
        self.recovery.records[self.recovery.next_record] = Some(record);
        self.recovery.next_record = (self.recovery.next_record + 1) % 2;
    }
    pub(super) fn recovery_tick(&mut self) {
        for child in [Child::Shell, Child::Input] {
            let Some(old) = self.actors[child.index()].filter(|a| a.failed) else {
                continue;
            };
            let mut attempt = self.recovery.attempts[child.index()];
            if attempt.fenced {
                continue;
            }
            if attempt.by == 0 {
                let tick = now();
                if tick.saturating_sub(attempt.window) >= self.catalogue.restart_window() {
                    attempt.window = tick;
                    attempt.count = 0;
                }
                if attempt.count >= self.catalogue.restart_attempts() {
                    attempt.fenced = true;
                    self.recovery.attempts[child.index()] = attempt;
                    continue;
                }
                attempt.by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
                attempt.recorded = false;
            }
            if now() >= attempt.by {
                attempt.fenced = true;
                self.status=b"Retirement deadline expired; old owner/credits remain retained; no replacement";
                self.owner.dirty = true;
                self.recovery.attempts[child.index()] = attempt;
                continue;
            }
            if !attempt.recorded {
                self.capture_stopped(child, old);
                attempt.recorded = true;
            }
            let reaped = rt::call(s::REAP, old.control, 0, 0);
            if reaped.status == 2 {
                require(reaped.value == 0 && reaped.capability == 0, 1655);
                self.recovery.attempts[child.index()] = attempt;
                continue;
            }
            require(
                reaped.status == 0 && reaped.value == 0 && reaped.capability == 0,
                1656,
            );
            checked(s::CLOSE, old.control, 0, 0);
            let denied = rt::call(s::PROCESS_JOB_INFO, old.control, 0, 0);
            require(
                denied.status == 1 && denied.value == 0 && denied.capability == 0,
                1657,
            );
            self.actors[child.index()] = None;
            self.prepare(child);
            let next_epoch = old
                .mapping_epoch
                .checked_add(1)
                .filter(|v| *v != u32::MAX)
                .unwrap_or_else(|| rt::exit(1658));
            self.actors[child.index()].as_mut().unwrap().mapping_epoch = next_epoch;
            if child == Child::Shell {
                self.outbox.retire(4);
                let replacement = self.actor(child).identity;
                let policy = self.policy.as_mut().unwrap();
                let next = ev_workspace_root::policy::owner(replacement);
                policy
                    .desktop
                    .replace_shell(policy.shell, next)
                    .unwrap_or_else(|_| rt::exit(1659));
                policy.shell = next;
                self.scene_dirty = true;
                self.status=b"Shell restarted from measured image; independent applications retain their processes";
            } else {
                let lifetime = self
                    .input
                    .lifetime
                    .checked_add(1)
                    .filter(|v| *v != u32::MAX)
                    .unwrap_or_else(|| rt::exit(1660));
                self.input = Input::new();
                self.input.lifetime = lifetime;
                self.cancel_owner();
                self.status=b"Input restarted; prior consent cancelled and fresh physical release is required";
            }
            attempt.count += 1;
            attempt.by = 0;
            attempt.recorded = false;
            self.recovery.attempts[child.index()] = attempt;
            self.owner.dirty = true;
        }
    }
}
