//! Ownership-bearing Internal cap_echo transport. Wrappers are deliberately not
//! Copy/Clone: status tags return either the original, recovered or returned
//! handle, or an explicit no-refund/pending state. A wrapper does not prove a
//! handle live: original authority can be revoked while a call is rejected.
use super::{CapReply, call4, syscall};
use core::num::NonZeroU64;
use ev_userspace_contract::cap_echo::{SyncTransport, TransportOutcome};

/// An installed userspace handle intended for the exact Memory READ|TRANSFER
/// contract. Construction checks nonzero only; kernel authorization must verify
/// actual kind/rights, generation and ownership on every operation.
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<ev_userspace_runtime::cap_echo::MemoryReadTransfer>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct MemoryReadTransfer(NonZeroU64);
impl MemoryReadTransfer {
    pub fn from_raw(handle: u64) -> Option<Self> {
        NonZeroU64::new(handle).map(Self)
    }
    pub fn as_raw(&self) -> u64 {
        self.0.get()
    }
    pub fn into_raw(self) -> u64 {
        self.0.get()
    }
}

/// Identifies one queued recovery attempt; it grants no memory authority. The
/// kernel correlates it to the actual calling thread/domain and retained ticket.
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<ev_userspace_runtime::cap_echo::RecoveryToken>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryToken(NonZeroU64);
impl RecoveryToken {
    pub fn from_raw(serial: u64) -> Option<Self> {
        NonZeroU64::new(serial).map(Self)
    }
    pub fn as_raw(&self) -> u64 {
        self.0.get()
    }
}

/// The exact request serial returned at delivery. A stale serial must reject
/// before moving the service's handle or completing any subsequent call.
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<ev_userspace_runtime::cap_echo::ReplyToken>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ReplyToken(NonZeroU64);
impl ReplyToken {
    pub fn from_raw(serial: u64) -> Option<Self> {
        NonZeroU64::new(serial).map(Self)
    }
    pub fn as_raw(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nonzero opaque reason supplied independently of the ownership phase.
    Remote(u64),
    /// No execution/ownership claim may be inferred from a broken ABI tuple.
    AbiViolation(CapReply),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub endpoint: u64,
}

fn call_outcome(
    reply: CapReply,
    original: MemoryReadTransfer,
) -> TransportOutcome<MemoryReadTransfer, RecoveryToken, Error> {
    use syscall::cap_phase as phase;
    let error = Error::Remote(reply.value);
    match reply.status {
        phase::RETURNED if reply.capability != 0 && reply.serial == 0 => {
            TransportOutcome::Returned {
                bytes: reply.value.to_le_bytes(),
                capability: MemoryReadTransfer::from_raw(reply.capability).unwrap(),
            }
        }
        phase::REJECTED
            if reply.value != 0 && reply.capability == original.as_raw() && reply.serial == 0 =>
        {
            TransportOutcome::Rejected { error, original }
        }
        phase::QUEUED_RECOVERED
            if reply.value != 0 && reply.capability != 0 && reply.serial == 0 =>
        {
            TransportOutcome::QueuedFailure {
                error,
                recovered: MemoryReadTransfer::from_raw(reply.capability).unwrap(),
            }
        }
        phase::DELIVERED_FAILURE
            if reply.value != 0 && reply.capability == 0 && reply.serial == 0 =>
        {
            TransportOutcome::DeliveredFailure { error }
        }
        phase::QUEUED_INVALIDATED
            if reply.value != 0 && reply.capability == 0 && reply.serial == 0 =>
        {
            TransportOutcome::QueuedInvalidated { error }
        }
        phase::QUEUED_PENDING if reply.value != 0 && reply.capability == 0 && reply.serial != 0 => {
            TransportOutcome::QueuedPending {
                error,
                recovery: RecoveryToken::from_raw(reply.serial).unwrap(),
            }
        }
        _ => TransportOutcome::Indeterminate {
            error: Error::AbiViolation(reply),
        },
    }
}

impl SyncTransport for Endpoint {
    type Capability = MemoryReadTransfer;
    type Recovery = RecoveryToken;
    type Error = Error;

    fn call(
        &mut self,
        request: [u8; 8],
        capability: MemoryReadTransfer,
        absolute_deadline: u64,
    ) -> TransportOutcome<Self::Capability, Self::Recovery, Self::Error> {
        let reply = call4(
            syscall::RPC_CALL_CAP,
            self.endpoint,
            u64::from_le_bytes(request),
            absolute_deadline,
            capability.as_raw(),
        );
        call_outcome(reply, capability)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    pub bytes: [u8; 8],
    pub capability: MemoryReadTransfer,
    pub reply: ReplyToken,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Received(Received),
    Rejected { error: Error },
    Indeterminate { error: Error },
}

fn receive_outcome(reply: CapReply) -> ReceiveOutcome {
    match reply.status {
        0 if reply.capability != 0 && reply.serial != 0 => ReceiveOutcome::Received(Received {
            bytes: reply.value.to_le_bytes(),
            capability: MemoryReadTransfer::from_raw(reply.capability).unwrap(),
            reply: ReplyToken::from_raw(reply.serial).unwrap(),
        }),
        1 if reply.value != 0 && reply.capability == 0 && reply.serial == 0 => {
            ReceiveOutcome::Rejected {
                error: Error::Remote(reply.value),
            }
        }
        _ => ReceiveOutcome::Indeterminate {
            error: Error::AbiViolation(reply),
        },
    }
}

pub fn receive(endpoint: u64) -> ReceiveOutcome {
    receive_outcome(call4(syscall::RPC_RECEIVE_CAP, endpoint, 0, 0, 0))
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReplyOutcome {
    Accepted,
    /// Retry may retain the same request token. A retained token never promises
    /// the reservation remains live; kernel correlation is checked again.
    Rejected {
        error: Error,
        original: MemoryReadTransfer,
        reply: ReplyToken,
    },
    Late {
        error: Error,
        retained: MemoryReadTransfer,
    },
    Indeterminate {
        error: Error,
    },
}

fn reply_outcome(reply: CapReply, original: MemoryReadTransfer, token: ReplyToken) -> ReplyOutcome {
    use syscall::cap_reply_phase as phase;
    match reply.status {
        phase::ACCEPTED if reply.value == 0 && reply.capability == 0 && reply.serial == 0 => {
            ReplyOutcome::Accepted
        }
        phase::REJECTED
            if reply.value != 0 && reply.capability == original.as_raw() && reply.serial == 0 =>
        {
            ReplyOutcome::Rejected {
                error: Error::Remote(reply.value),
                original,
                reply: token,
            }
        }
        phase::LATE_RETAINED
            if reply.value != 0 && reply.capability == original.as_raw() && reply.serial == 0 =>
        {
            ReplyOutcome::Late {
                error: Error::Remote(reply.value),
                retained: original,
            }
        }
        _ => ReplyOutcome::Indeterminate {
            error: Error::AbiViolation(reply),
        },
    }
}

pub fn reply(
    endpoint: u64,
    bytes: [u8; 8],
    capability: MemoryReadTransfer,
    token: ReplyToken,
) -> ReplyOutcome {
    let reply = call4(
        syscall::RPC_REPLY_CAP,
        endpoint,
        u64::from_le_bytes(bytes),
        capability.as_raw(),
        token.as_raw(),
    );
    reply_outcome(reply, capability, token)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Recovered {
        capability: MemoryReadTransfer,
    },
    Invalidated {
        error: Error,
    },
    Pending {
        error: Error,
        recovery: RecoveryToken,
    },
    /// Retains the request token for diagnostics/retry; it grants no authority.
    Rejected {
        error: Error,
        recovery: RecoveryToken,
    },
    Indeterminate {
        error: Error,
    },
}

fn recovery_outcome(reply: CapReply, original: RecoveryToken) -> RecoveryOutcome {
    use syscall::cap_phase as phase;
    match reply.status {
        phase::QUEUED_RECOVERED
            if reply.value == 0 && reply.capability != 0 && reply.serial == 0 =>
        {
            RecoveryOutcome::Recovered {
                capability: MemoryReadTransfer::from_raw(reply.capability).unwrap(),
            }
        }
        phase::QUEUED_INVALIDATED
            if reply.value != 0 && reply.capability == 0 && reply.serial == 0 =>
        {
            RecoveryOutcome::Invalidated {
                error: Error::Remote(reply.value),
            }
        }
        phase::QUEUED_PENDING
            if reply.value != 0 && reply.capability == 0 && reply.serial == original.as_raw() =>
        {
            RecoveryOutcome::Pending {
                error: Error::Remote(reply.value),
                recovery: original,
            }
        }
        phase::REJECTED if reply.value != 0 && reply.capability == 0 && reply.serial == 0 => {
            RecoveryOutcome::Rejected {
                error: Error::Remote(reply.value),
                recovery: original,
            }
        }
        _ => RecoveryOutcome::Indeterminate {
            error: Error::AbiViolation(reply),
        },
    }
}

pub fn reclaim(recovery: RecoveryToken) -> RecoveryOutcome {
    let reply = call4(syscall::RPC_RECLAIM_CAP, recovery.as_raw(), 0, 0, 0);
    recovery_outcome(reply, recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::cap_echo::{self, ClientOutcome};

    fn memory() -> MemoryReadTransfer {
        MemoryReadTransfer::from_raw(512).unwrap()
    }
    fn token() -> ReplyToken {
        ReplyToken::from_raw(19).unwrap()
    }
    fn recovery() -> RecoveryToken {
        RecoveryToken::from_raw(19).unwrap()
    }
    fn raw(status: u64, value: u64, capability: u64, serial: u64) -> CapReply {
        CapReply {
            status,
            value,
            capability,
            serial,
        }
    }

    #[test]
    fn call_phases_preserve_original_recovered_returned_and_absent_ownership() {
        let bytes = cap_echo::Response { value: 7 }.encode();
        assert_eq!(
            call_outcome(raw(0, u64::from_le_bytes(bytes), 1024, 0), memory()),
            TransportOutcome::Returned {
                bytes,
                capability: MemoryReadTransfer::from_raw(1024).unwrap()
            }
        );
        assert_eq!(
            call_outcome(raw(1, 1, 512, 0), memory()),
            TransportOutcome::Rejected {
                error: Error::Remote(1),
                original: memory()
            }
        );
        assert_eq!(
            call_outcome(raw(2, 4, 1024, 0), memory()),
            TransportOutcome::QueuedFailure {
                error: Error::Remote(4),
                recovered: MemoryReadTransfer::from_raw(1024).unwrap()
            }
        );
        assert_eq!(
            call_outcome(raw(3, 4, 0, 0), memory()),
            TransportOutcome::DeliveredFailure {
                error: Error::Remote(4)
            }
        );
        assert_eq!(
            call_outcome(raw(4, 7, 0, 0), memory()),
            TransportOutcome::QueuedInvalidated {
                error: Error::Remote(7)
            }
        );
        assert_eq!(
            call_outcome(raw(5, 8, 0, 19), memory()),
            TransportOutcome::QueuedPending {
                error: Error::Remote(8),
                recovery: recovery()
            }
        );
        assert!(MemoryReadTransfer::from_raw(0).is_none());
        assert!(RecoveryToken::from_raw(0).is_none());
        assert!(ReplyToken::from_raw(0).is_none());
        assert_eq!(memory().into_raw(), 512);
    }

    #[test]
    fn broken_call_tuples_never_fabricate_capability_or_delivery_state() {
        for reply in [
            raw(0, 7, 0, 0),
            raw(0, 7, 512, 1),
            raw(1, 0, 512, 0),
            raw(1, 1, 0, 0),
            raw(1, 1, 513, 0),
            raw(1, 1, 512, 1),
            raw(2, 0, 513, 0),
            raw(2, 1, 0, 0),
            raw(2, 1, 513, 1),
            raw(3, 0, 0, 0),
            raw(3, 1, 512, 0),
            raw(3, 1, 0, 1),
            raw(4, 0, 0, 0),
            raw(4, 1, 512, 0),
            raw(4, 1, 0, 1),
            raw(5, 0, 0, 19),
            raw(5, 1, 512, 19),
            raw(5, 1, 0, 0),
            raw(6, 1, 512, 19),
            raw(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        ] {
            assert_eq!(
                call_outcome(reply, memory()),
                TransportOutcome::Indeterminate {
                    error: Error::AbiViolation(reply),
                }
            );
        }
    }

    #[test]
    fn generated_client_preserves_returned_authority_even_with_wrong_direction_body() {
        struct Fake;
        impl SyncTransport for Fake {
            type Capability = MemoryReadTransfer;
            type Recovery = RecoveryToken;
            type Error = Error;
            fn call(
                &mut self,
                _: [u8; 8],
                original: Self::Capability,
                _: u64,
            ) -> TransportOutcome<Self::Capability, Self::Recovery, Self::Error> {
                call_outcome(
                    raw(
                        0,
                        u64::from_le_bytes(cap_echo::Request { value: 7 }.encode()),
                        1024,
                        0,
                    ),
                    original,
                )
            }
        }
        assert_eq!(
            cap_echo::client_call(&mut Fake, 7, memory(), 100),
            ClientOutcome::InvalidReply {
                error: cap_echo::DecodeError::Opcode,
                returned: MemoryReadTransfer::from_raw(1024).unwrap(),
            }
        );
    }

    #[test]
    fn receive_only_claims_authority_and_reply_token_as_one_complete_delivery() {
        let bytes = cap_echo::Request { value: 7 }.encode();
        assert_eq!(
            receive_outcome(raw(0, u64::from_le_bytes(bytes), 512, 19)),
            ReceiveOutcome::Received(Received {
                bytes,
                capability: memory(),
                reply: token()
            })
        );
        assert_eq!(
            receive_outcome(raw(1, 2, 0, 0)),
            ReceiveOutcome::Rejected {
                error: Error::Remote(2)
            }
        );
        for reply in [
            raw(0, 7, 0, 19),
            raw(0, 7, 512, 0),
            raw(1, 0, 0, 0),
            raw(1, 1, 512, 0),
            raw(1, 1, 0, 19),
            raw(2, 1, 512, 19),
        ] {
            assert_eq!(
                receive_outcome(reply),
                ReceiveOutcome::Indeterminate {
                    error: Error::AbiViolation(reply),
                }
            );
        }
    }

    #[test]
    fn timely_reply_consumes_while_rejection_and_late_acknowledgement_retain_handle() {
        assert_eq!(
            reply_outcome(raw(0, 0, 0, 0), memory(), token()),
            ReplyOutcome::Accepted
        );
        assert_eq!(
            reply_outcome(raw(1, 2, 512, 0), memory(), token()),
            ReplyOutcome::Rejected {
                error: Error::Remote(2),
                original: memory(),
                reply: token()
            }
        );
        assert_eq!(
            reply_outcome(raw(2, 4, 512, 0), memory(), token()),
            ReplyOutcome::Late {
                error: Error::Remote(4),
                retained: memory()
            }
        );
        for reply in [
            raw(0, 1, 0, 0),
            raw(0, 0, 512, 0),
            raw(0, 0, 0, 19),
            raw(1, 0, 512, 0),
            raw(1, 1, 513, 0),
            raw(1, 1, 512, 19),
            raw(2, 0, 512, 0),
            raw(2, 1, 513, 0),
            raw(2, 1, 512, 19),
            raw(3, 1, 512, 0),
        ] {
            assert_eq!(
                reply_outcome(reply, memory(), token()),
                ReplyOutcome::Indeterminate {
                    error: Error::AbiViolation(reply),
                }
            );
        }
    }

    #[test]
    fn pending_recovery_uses_exact_serial_and_never_refunds_from_a_reason_boolean() {
        assert_eq!(
            recovery_outcome(raw(2, 0, 1024, 0), recovery()),
            RecoveryOutcome::Recovered {
                capability: MemoryReadTransfer::from_raw(1024).unwrap()
            }
        );
        assert_eq!(
            recovery_outcome(raw(4, 7, 0, 0), recovery()),
            RecoveryOutcome::Invalidated {
                error: Error::Remote(7)
            }
        );
        assert_eq!(
            recovery_outcome(raw(5, 8, 0, 19), recovery()),
            RecoveryOutcome::Pending {
                error: Error::Remote(8),
                recovery: recovery()
            }
        );
        assert_eq!(
            recovery_outcome(raw(1, 9, 0, 0), recovery()),
            RecoveryOutcome::Rejected {
                error: Error::Remote(9),
                recovery: recovery()
            }
        );
        for reply in [
            raw(2, 1, 1024, 0),
            raw(2, 0, 0, 0),
            raw(2, 0, 1024, 19),
            raw(4, 0, 0, 0),
            raw(4, 7, 512, 0),
            raw(4, 7, 0, 19),
            raw(5, 8, 0, 18),
            raw(5, 0, 0, 19),
            raw(5, 8, 512, 19),
            raw(1, 9, 512, 0),
            raw(1, 9, 0, 19),
            raw(0, 0, 512, 0),
        ] {
            assert_eq!(
                recovery_outcome(reply, recovery()),
                RecoveryOutcome::Indeterminate {
                    error: Error::AbiViolation(reply),
                }
            );
        }
    }

    #[test]
    fn arbitrary_scalar_reply_tuples_and_opaque_reasons_decode_without_panics() {
        let mut state = 0x91e10da5u64;
        for _ in 0..8192 {
            let mut parts = [0; 4];
            for part in &mut parts {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *part = state;
            }
            let reply = raw(parts[0], parts[1], parts[2], parts[3]);
            let _ = call_outcome(reply, memory());
            let _ = receive_outcome(reply);
            let _ = reply_outcome(reply, memory(), token());
            let _ = recovery_outcome(reply, recovery());
            // Error reason bit patterns never change ownership classification.
            let reason = state.max(1);
            assert_eq!(
                call_outcome(raw(3, reason, 0, 0), memory()),
                TransportOutcome::DeliveredFailure {
                    error: Error::Remote(reason)
                }
            );
            assert_eq!(
                call_outcome(raw(4, reason, 0, 0), memory()),
                TransportOutcome::QueuedInvalidated {
                    error: Error::Remote(reason)
                }
            );
        }
    }
}
