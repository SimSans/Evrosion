//! Internal discipline-fixture operations. No user identity/entry/stack pointer
//! is accepted by spawn; actual thread/domain/role validation stays in kernel.
use super::{CapReply, Reply, call, call4, syscall};
use core::{marker::PhantomData, num::NonZeroU64};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidArgument,
    Status(u64),
    AbiViolation(CapReply),
}
fn raw(reply: Reply) -> CapReply {
    CapReply {
        status: reply.status,
        value: reply.value,
        capability: reply.capability,
        serial: 0,
    }
}
fn failure(reply: Reply) -> Error {
    if reply.status != 0 && reply.value == 0 && reply.capability == 0 {
        Error::Status(reply.status)
    } else {
        Error::AbiViolation(raw(reply))
    }
}

/// This serial is not bearer authority: reply checks actual servicing thread,
/// endpoint, CallId and prior delivery. A failed reply retains the input nonce.
#[derive(Debug, PartialEq, Eq)]
pub struct ReplyNonce(NonZeroU64);
#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    pub bytes: [u8; 8],
    pub nonce: ReplyNonce,
}
#[derive(Debug, PartialEq, Eq)]
pub struct RejectedReply {
    pub error: Error,
    pub nonce: ReplyNonce,
}
fn received(reply: CapReply) -> Result<Option<Received>, Error> {
    match reply.status {
        0 if reply.capability == 0 && reply.serial != 0 => Ok(Some(Received {
            bytes: reply.value.to_le_bytes(),
            nonce: ReplyNonce(NonZeroU64::new(reply.serial).unwrap()),
        })),
        2 if reply.value == 0 && reply.capability == 0 && reply.serial == 0 => Ok(None),
        status if status != 0 && reply.value == 0 && reply.capability == 0 && reply.serial == 0 => {
            Err(Error::Status(status))
        }
        _ => Err(Error::AbiViolation(reply)),
    }
}
pub fn receive(endpoint: u64) -> Result<Option<Received>, Error> {
    received(call4(syscall::RECEIVE_RPC, endpoint, 0, 0, 0))
}
fn replied(reply: CapReply, nonce: ReplyNonce) -> Result<(), RejectedReply> {
    if reply.status == 0 && reply.value == 0 && reply.capability == 0 && reply.serial == 0 {
        Ok(())
    } else {
        let error = if reply.status != 0
            && reply.value == 0
            && reply.capability == 0
            && reply.serial == 0
        {
            Error::Status(reply.status)
        } else {
            Error::AbiViolation(reply)
        };
        Err(RejectedReply { error, nonce })
    }
}
pub fn reply(endpoint: u64, bytes: [u8; 8], nonce: ReplyNonce) -> Result<(), RejectedReply> {
    let reply = call4(
        syscall::REPLY_RPC,
        endpoint,
        u64::from_le_bytes(bytes),
        0,
        nonce.0.get(),
    );
    replied(reply, nonce)
}
fn spawned(reply: Reply) -> Result<u64, Error> {
    if reply.status == 0 && reply.value != 0 && reply.capability == 0 {
        Ok(reply.value)
    } else {
        Err(failure(reply))
    }
}
/// Request only declared local role1/2. The kernel chooses its previously
/// measured entry/bootstrap and validated private stack, never a userspace PID,
/// domain, code address or stack pointer. Returned ID is diagnostic only.
pub fn spawn(local_role: u64) -> Result<u64, Error> {
    if !matches!(local_role, 1 | 2) {
        return Err(Error::InvalidArgument);
    }
    spawned(call(syscall::SPAWN, local_role, 0, 0))
}

/// The kernel's actual lease, bound to running thread, full object identity and
/// LIFO acquisition. No Drop syscall, implicit repair, Copy/Clone or cross-thread
/// ownership migration is permitted. Explicit release failure returns this guard.
/// ```compile_fail
/// fn require_copy<T: Copy>() {} require_copy::<ev_userspace_runtime::discipline::MutexGuard>();
/// ```
/// ```compile_fail
/// fn require_send<T: Send>() {} require_send::<ev_userspace_runtime::discipline::MutexGuard>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {} require_sync::<ev_userspace_runtime::discipline::MutexGuard>();
/// ```
#[must_use = "explicitly release the actual mutex lease before making synchronous calls"]
#[derive(Debug, PartialEq, Eq)]
pub struct MutexGuard {
    lease: NonZeroU64,
    marker: PhantomData<*mut ()>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Acquired {
    pub guard: MutexGuard,
    pub abandoned: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub struct RejectedGuard {
    pub error: Error,
    pub guard: MutexGuard,
}
fn acquired(reply: Reply) -> Result<Acquired, Error> {
    if reply.status == 0 && reply.value != 0 && reply.capability <= 1 {
        Ok(Acquired {
            guard: MutexGuard {
                lease: NonZeroU64::new(reply.value).unwrap(),
                marker: PhantomData,
            },
            abandoned: reply.capability == 1,
        })
    } else {
        Err(failure(reply))
    }
}
pub fn mutex_acquire(capability: u64) -> Result<Acquired, Error> {
    acquired(call(syscall::MUTEX_ACQUIRE, capability, 0, 0))
}
fn released(reply: Reply, guard: MutexGuard) -> Result<(), RejectedGuard> {
    if reply.status == 0 && reply.value == 0 && reply.capability == 0 {
        Ok(())
    } else {
        Err(RejectedGuard {
            error: failure(reply),
            guard,
        })
    }
}
impl MutexGuard {
    pub fn release(self) -> Result<(), RejectedGuard> {
        let reply = call(syscall::MUTEX_RELEASE, self.lease.get(), 0, 0);
        released(reply, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scalar(status: u64, value: u64, capability: u64) -> Reply {
        Reply {
            status,
            value,
            capability,
        }
    }
    fn cap(status: u64, value: u64, capability: u64, serial: u64) -> CapReply {
        CapReply {
            status,
            value,
            capability,
            serial,
        }
    }
    fn nonce() -> ReplyNonce {
        ReplyNonce(NonZeroU64::new(7).unwrap())
    }
    fn guard() -> MutexGuard {
        MutexGuard {
            lease: NonZeroU64::new(9).unwrap(),
            marker: PhantomData,
        }
    }
    #[test]
    fn nonce_delivery_never_accepts_authority_or_missing_correlation() {
        let bytes = *b"EV\x01\x01\x07\0\0\0";
        assert_eq!(
            received(cap(0, u64::from_le_bytes(bytes), 0, 7)),
            Ok(Some(Received {
                bytes,
                nonce: nonce()
            }))
        );
        assert_eq!(received(cap(2, 0, 0, 0)), Ok(None));
        assert_eq!(received(cap(1, 0, 0, 0)), Err(Error::Status(1)));
        for reply in [
            cap(0, 7, 1, 7),
            cap(0, 7, 0, 0),
            cap(2, 1, 0, 0),
            cap(2, 0, 0, 7),
            cap(1, 0, 1, 0),
        ] {
            assert_eq!(received(reply), Err(Error::AbiViolation(reply)));
        }
        assert_eq!(replied(cap(0, 0, 0, 0), nonce()), Ok(()));
        assert_eq!(
            replied(cap(11, 0, 0, 0), nonce()),
            Err(RejectedReply {
                error: Error::Status(11),
                nonce: nonce()
            })
        );
        assert_eq!(
            replied(cap(0, 0, 0, 7), nonce()),
            Err(RejectedReply {
                error: Error::AbiViolation(cap(0, 0, 0, 7)),
                nonce: nonce()
            })
        );
    }
    #[test]
    fn mutex_lease_is_actual_nonzero_and_release_failure_preserves_guard() {
        assert_eq!(
            acquired(scalar(0, 9, 0)),
            Ok(Acquired {
                guard: guard(),
                abandoned: false
            })
        );
        assert_eq!(
            acquired(scalar(0, 9, 1)),
            Ok(Acquired {
                guard: guard(),
                abandoned: true
            })
        );
        assert_eq!(acquired(scalar(2, 0, 0)), Err(Error::Status(2)));
        for reply in [scalar(0, 0, 0), scalar(0, 9, 2), scalar(1, 9, 0)] {
            assert_eq!(acquired(reply), Err(Error::AbiViolation(raw(reply))));
        }
        assert_eq!(released(scalar(0, 0, 0), guard()), Ok(()));
        assert_eq!(
            released(scalar(1, 0, 0), guard()),
            Err(RejectedGuard {
                error: Error::Status(1),
                guard: guard()
            })
        );
        let bad = scalar(0, 0, 1);
        assert_eq!(
            released(bad, guard()),
            Err(RejectedGuard {
                error: Error::AbiViolation(raw(bad)),
                guard: guard()
            })
        );
    }
    #[test]
    fn spawn_reply_is_diagnostic_and_arbitrary_decode_is_total() {
        assert_eq!(spawned(scalar(0, 257, 0)), Ok(257));
        assert_eq!(spawned(scalar(1, 0, 0)), Err(Error::Status(1)));
        assert!(spawned(scalar(0, 0, 0)).is_err());
        assert!(spawned(scalar(0, 257, 1)).is_err());
        let mut state = 0x123456789abcdefu64;
        for _ in 0..8192 {
            let mut fields = [0; 4];
            for field in &mut fields {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *field = state;
            }
            let reply = cap(fields[0], fields[1], fields[2], fields[3]);
            let _ = received(reply);
            let _ = replied(reply, nonce());
            let reply = scalar(fields[0], fields[1], fields[2]);
            let _ = acquired(reply);
            let _ = released(reply, guard());
            let _ = spawned(reply);
        }
    }
}
