//! Cap-free synchronous calls. Busy2 is retryable only under the kernel's
//! rejection-before-accept contract. Accepted timeout/death/other errors are
//! returned once; this transport never infers nonexecution from those errors.
use crate::Reply;
const MAX_REJECTIONS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Deadline,
    BusyLimit,
    Remote(u64),
    Clock(Reply),
    Yield(Reply),
    AbiViolation(Reply),
}
trait Boundary {
    fn clock(&mut self) -> Reply;
    fn invoke(&mut self, endpoint: u64, bytes: [u8; 8], deadline: u64) -> Reply;
    fn yield_now(&mut self) -> Reply;
}
struct Syscalls;
impl Boundary for Syscalls {
    fn clock(&mut self) -> Reply {
        crate::monotonic()
    }
    fn invoke(&mut self, endpoint: u64, bytes: [u8; 8], deadline: u64) -> Reply {
        crate::call(
            crate::syscall::RPC_CALL,
            endpoint,
            u64::from_le_bytes(bytes),
            deadline,
        )
    }
    fn yield_now(&mut self) -> Reply {
        crate::yield_now()
    }
}
/// Retain the exact request/window/surface until this returns. Rejected Busy
/// changes no call/queue/wait/window ownership. No retry follows any other result.
pub fn call(endpoint: u64, bytes: [u8; 8], absolute_deadline: u64) -> Result<[u8; 8], Error> {
    drive(&mut Syscalls, endpoint, bytes, absolute_deadline)
}
fn drive(
    boundary: &mut impl Boundary,
    endpoint: u64,
    bytes: [u8; 8],
    deadline: u64,
) -> Result<[u8; 8], Error> {
    if deadline == 0 || deadline == u64::MAX {
        return Err(Error::Deadline);
    }
    let mut last_clock = None;
    for _ in 0..MAX_REJECTIONS {
        let clock = boundary.clock();
        if clock.status != 0
            || clock.capability != 0
            || clock.value == u64::MAX
            || last_clock.is_some_and(|last| clock.value < last)
        {
            return Err(Error::Clock(clock));
        }
        last_clock = Some(clock.value);
        if clock.value >= deadline {
            return Err(Error::Deadline);
        }
        let reply = boundary.invoke(endpoint, bytes, deadline);
        match reply {
            Reply {
                status: 0,
                value,
                capability: 0,
            } => return Ok(value.to_le_bytes()),
            Reply {
                status: 2,
                value: 0,
                capability: 0,
            } => {}
            Reply {
                status,
                value: 0,
                capability: 0,
            } if status != 0 => return Err(Error::Remote(status)),
            other => return Err(Error::AbiViolation(other)),
        }
        let yielded = boundary.yield_now();
        if yielded.status != 0 || yielded.value != 0 || yielded.capability != 0 {
            return Err(Error::Yield(yielded));
        }
    }
    Err(Error::BusyLimit)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{collections::VecDeque, vec::Vec};
    fn reply(status: u64, value: u64, capability: u64) -> Reply {
        Reply {
            status,
            value,
            capability,
        }
    }
    struct Script {
        clocks: VecDeque<Reply>,
        replies: VecDeque<Reply>,
        yielded: Reply,
        calls: Vec<(u64, [u8; 8], u64)>,
        yields: usize,
    }
    impl Script {
        fn new(clocks: &[u64], replies: &[Reply]) -> Self {
            Self {
                clocks: clocks.iter().map(|n| reply(0, *n, 0)).collect(),
                replies: replies.iter().copied().collect(),
                yielded: reply(0, 0, 0),
                calls: Vec::new(),
                yields: 0,
            }
        }
    }
    impl Boundary for Script {
        fn clock(&mut self) -> Reply {
            self.clocks.pop_front().expect("unexpected clock")
        }
        fn invoke(&mut self, cap: u64, bytes: [u8; 8], deadline: u64) -> Reply {
            self.calls.push((cap, bytes, deadline));
            self.replies.pop_front().expect("unexpected reissue")
        }
        fn yield_now(&mut self) -> Reply {
            self.yields += 1;
            self.yielded
        }
    }
    #[test]
    fn only_preaccept_busy_retries_the_identical_payload_and_absolute_deadline() {
        let bytes = *b"request1";
        let mut script = Script::new(
            &[1, 2, 3],
            &[reply(2, 0, 0), reply(2, 0, 0), reply(0, 99, 0)],
        );
        assert_eq!(drive(&mut script, 7, bytes, 4), Ok(99u64.to_le_bytes()));
        assert_eq!(script.calls, [(7, bytes, 4); 3]);
        assert_eq!(script.yields, 2);
    }
    #[test]
    fn busy_never_extends_deadline_and_expiry_precedes_any_next_acceptance() {
        let mut script = Script::new(&[1, 4], &[reply(2, 0, 0)]);
        assert_eq!(drive(&mut script, 7, [1; 8], 4), Err(Error::Deadline));
        assert_eq!(script.calls.len(), 1);
        let mut invalid = Script::new(&[], &[]);
        for stop in [0, u64::MAX] {
            assert_eq!(drive(&mut invalid, 7, [1; 8], stop), Err(Error::Deadline));
        }
    }
    #[test]
    fn accepted_failure_or_malformed_busy_is_never_reissued() {
        for r in [
            reply(1, 0, 0),
            reply(3, 0, 0),
            reply(4, 0, 0),
            reply(2, 1, 0),
            reply(2, 0, 7),
            reply(0, 0, 7),
        ] {
            let mut script = Script::new(&[1], &[r]);
            assert!(drive(&mut script, 7, [1; 8], 4).is_err());
            assert_eq!(script.calls.len(), 1);
            assert_eq!(script.yields, 0);
        }
    }
    #[test]
    fn broken_clock_or_yield_cannot_hide_a_new_attempt() {
        let mut script = Script::new(&[2, 1], &[reply(2, 0, 0)]);
        assert!(matches!(
            drive(&mut script, 7, [1; 8], 4),
            Err(Error::Clock(_))
        ));
        assert_eq!(script.calls.len(), 1);
        let mut script = Script::new(&[1], &[reply(2, 0, 0)]);
        script.yielded = reply(0, 1, 0);
        assert!(matches!(
            drive(&mut script, 7, [1; 8], 4),
            Err(Error::Yield(_))
        ));
        assert_eq!(script.calls.len(), 1);
    }
}
