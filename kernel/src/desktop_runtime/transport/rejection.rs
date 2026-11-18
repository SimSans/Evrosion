//! Exact static projections for preaccept scalar-status1 observations only.
//! No message payload, shared window, seed or authorization is reconstructed.
use ev_kernel::{capability, ipc, rpc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Code {
    pub branch: u8,
    pub reason: u8,
    pub detail: u8,
}
pub(super) const WIRE: Code = Code {
    branch: 1,
    reason: 0,
    detail: 0,
};
pub(super) const DELIVERY: Code = Code {
    branch: 2,
    reason: 0,
    detail: 0,
};
pub(super) fn mailbox(error: ipc::Error) -> Code {
    use ipc::Error;
    let reason = match error {
        Error::Authority(_) => 1,
        Error::WrongEndpoint => 2,
        Error::WrongOwner => 3,
        Error::Full => 4,
        Error::Empty => 5,
        Error::TooLarge => 6,
        Error::Expired => 7,
        Error::Closed => 8,
        Error::ClockReversed => 9,
        Error::SequenceExhausted => 10,
        Error::InvalidTicket => 11,
        Error::NotReclaimable => 12,
        Error::NotManaged => 13,
        Error::RestrictedBinding => 14,
    };
    let detail = if let Error::Authority(error) = error {
        capability(error)
    } else {
        0
    };
    Code {
        branch: 3,
        reason,
        detail,
    }
}
fn capability(error: capability::Error) -> u8 {
    use capability::Error;
    match error {
        Error::InvalidSpace => 1,
        Error::InvalidHandle => 2,
        Error::Revoked => 3,
        Error::DeadObject => 4,
        Error::WrongKind => 5,
        Error::Denied => 6,
        Error::Capacity => 7,
        Error::GenerationExhausted => 8,
        Error::DestinationNotEmpty => 9,
        Error::SpaceBusy => 10,
        Error::ObjectBusy => 11,
    }
}
pub(super) fn rpc(error: rpc::Error) -> Code {
    use rpc::Error;
    let reason = match error {
        Error::PermissionDenied => 1,
        Error::Identity => 2,
        Error::AlreadyRegistered => 3,
        Error::UnknownThread => 4,
        Error::UnknownEndpoint => 5,
        Error::AlreadyBound => 6,
        Error::IncarnationMismatch => 7,
        Error::WouldBlock => 8,
        Error::Overloaded => 9,
        Error::AlreadyWaiting => 10,
        Error::DangerousLock => 11,
        Error::LockOrder => 12,
        Error::DeadlockDetected => 13,
        Error::DepthExceeded => 14,
        Error::DeadlineExtended => 15,
        Error::DeadlineExceeded => 16,
        Error::Cancelled => 17,
        Error::PeerDied => 18,
        Error::PeerStillLive => 19,
        Error::MalformedMessage => 20,
        Error::ClockReversed => 21,
        Error::SequenceExhausted => 22,
        Error::StaleCall => 23,
        Error::WrongCaller => 24,
        Error::WrongCallee => 25,
    };
    Code {
        branch: 4,
        reason,
        detail: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_error_projections_distinguish_authority_clock_and_parent_cut() {
        use capability::Error as Cap;
        let caps = [
            Cap::InvalidSpace,
            Cap::InvalidHandle,
            Cap::Revoked,
            Cap::DeadObject,
            Cap::WrongKind,
            Cap::Denied,
            Cap::Capacity,
            Cap::GenerationExhausted,
            Cap::DestinationNotEmpty,
            Cap::SpaceBusy,
            Cap::ObjectBusy,
        ];
        for (i, error) in caps.into_iter().enumerate() {
            assert_eq!(
                mailbox(ipc::Error::Authority(error)),
                Code {
                    branch: 3,
                    reason: 1,
                    detail: (i + 1) as u8
                }
            );
        }
        use ipc::Error as Ipc;
        let ipc = [
            Ipc::WrongEndpoint,
            Ipc::WrongOwner,
            Ipc::Full,
            Ipc::Empty,
            Ipc::TooLarge,
            Ipc::Expired,
            Ipc::Closed,
            Ipc::ClockReversed,
            Ipc::SequenceExhausted,
            Ipc::InvalidTicket,
            Ipc::NotReclaimable,
            Ipc::NotManaged,
            Ipc::RestrictedBinding,
        ];
        for (i, error) in ipc.into_iter().enumerate() {
            assert_eq!(
                mailbox(error),
                Code {
                    branch: 3,
                    reason: (i + 2) as u8,
                    detail: 0
                }
            );
        }
        use rpc::Error as Rpc;
        let rpc = [
            Rpc::PermissionDenied,
            Rpc::Identity,
            Rpc::AlreadyRegistered,
            Rpc::UnknownThread,
            Rpc::UnknownEndpoint,
            Rpc::AlreadyBound,
            Rpc::IncarnationMismatch,
            Rpc::WouldBlock,
            Rpc::Overloaded,
            Rpc::AlreadyWaiting,
            Rpc::DangerousLock,
            Rpc::LockOrder,
            Rpc::DeadlockDetected,
            Rpc::DepthExceeded,
            Rpc::DeadlineExtended,
            Rpc::DeadlineExceeded,
            Rpc::Cancelled,
            Rpc::PeerDied,
            Rpc::PeerStillLive,
            Rpc::MalformedMessage,
            Rpc::ClockReversed,
            Rpc::SequenceExhausted,
            Rpc::StaleCall,
            Rpc::WrongCaller,
            Rpc::WrongCallee,
        ];
        for (i, error) in rpc.into_iter().enumerate() {
            assert_eq!(
                super::rpc(error),
                Code {
                    branch: 4,
                    reason: (i + 1) as u8,
                    detail: 0
                }
            );
        }
        assert_eq!(
            WIRE,
            Code {
                branch: 1,
                reason: 0,
                detail: 0
            }
        );
        assert_eq!(
            DELIVERY,
            Code {
                branch: 2,
                reason: 0,
                detail: 0
            }
        );
    }
}
