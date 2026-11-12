//! Internal x86-64 saved user context and total scalar syscall decoding.
//! No user pointers are dereferenced and no public ABI stability is promised.
use crate::capability::{Handle, Rights};
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserContext {
    pub registers: [u64; 15],
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub flags: u64,
    pub rsp: u64,
    pub ss: u64,
}
impl UserContext {
    pub const ZERO: Self = Self {
        registers: [0; 15],
        vector: 0,
        error: 0,
        rip: 0,
        cs: 35,
        flags: 0x202,
        rsp: 0,
        ss: 27,
    };
    pub fn new(entry: u64, stack: u64) -> Option<Self> {
        let frame = Self {
            rip: entry,
            rsp: stack,
            ..Self::ZERO
        };
        frame.resumable().then_some(frame)
    }
    pub fn resumable(&self) -> bool {
        (4096..1 << 47).contains(&self.rip)
            && (4096..1 << 47).contains(&self.rsp)
            && self.cs == 35
            && self.ss == 27
            && self.flags & 0x202 == 0x202
            && self.flags & ((3 << 12) | (1 << 14) | (1 << 17)) == 0
    }
    pub fn ordinary_user_fault(&self) -> bool {
        self.cs & 3 == 3
            && matches!(
                self.vector,
                0 | 1 | 3 | 4 | 5 | 6 | 7 | 10 | 11 | 12 | 13 | 14 | 16 | 17 | 19
            )
    }
}
/// Exact four-output Native3 Root-self reply. Only the captured runtime may
/// call this after actualRoot/cap0 validation; numbers convey no authority.
pub fn reply_native_root_identity(frame: &mut UserContext, process: u64, thread: u64, tick: u64) {
    frame.registers[14] = 0;
    frame.registers[9] = process;
    frame.registers[11] = thread;
    frame.registers[5] = tick;
}
const _: () = assert!(core::mem::size_of::<UserContext>() == 176);
const _: () = assert!(core::mem::offset_of!(UserContext, rip) == 136);
#[derive(Debug, PartialEq, Eq)]
pub enum Call {
    Yield,
    EnqueueManagedRead {
        process: Handle,
        source: Handle,
        inbox: Handle,
        nonce: u32,
    },
    InhibitManagedProcess(Handle),
    DisplayInfo {
        capability: Handle,
        field: u64,
    },
    PortInput {
        capability: Handle,
        port: u64,
        width: u64,
    },
    PortOutput {
        capability: Handle,
        port: u64,
        width: u64,
        value: u64,
    },
    MutexAcquire(Handle),
    MutexRelease(u64),
    Spawn(u64),
    ReplyRpc {
        endpoint: Handle,
        value: u64,
        serial: u64,
    },
    ReceiveRpc(Handle),
    Exit(u64),
    Send {
        endpoint: Handle,
        value: u64,
        capability: Option<Handle>,
    },
    Receive(Handle),
    ReceiveEvent(Handle),
    StopProcess(Handle),
    ProcessIdentity(Handle),
    ObserveField {
        process: Handle,
        field: u64,
    },
    ReceiveWait {
        endpoint: Handle,
        ticks: u64,
    },
    ReceiverWaiting,
    Inspect {
        capability: Handle,
        rights: Rights,
    },
    JobInfo {
        capability: Handle,
        field: u64,
    },
    FaultInfo {
        capability: Handle,
        field: u64,
    },
    Quanta,
    ReceiveFault(Handle),
    Reclaim(u64),
    Revoke(Handle),
    Allocate(Handle),
    Free(Handle),
    MapShared {
        capability: Handle,
        writable: bool,
    },
    CreateJob {
        creator: Handle,
        template: u64,
    },
    CreateProcess {
        job: Handle,
        image: Handle,
    },
    Delegate {
        process: Handle,
        source: Handle,
        selector: u64,
    },
    Start(Handle),
    CreateEndpoint(Handle),
    Close(Handle),
    Observe(Handle),
    BindReceiver {
        endpoint: Handle,
        process: Handle,
    },
    Rpc {
        endpoint: Handle,
        value: u64,
        deadline: u64,
    },
    RpcCap {
        endpoint: Handle,
        value: u64,
        deadline: u64,
        capability: Handle,
    },
    ReceiveCap(Handle),
    ReplyCap {
        endpoint: Handle,
        value: u64,
        capability: Handle,
        serial: u64,
    },
    ReclaimCap(u64),
    Monotonic,
    RpcDeadline,
    Reap(Handle),
}
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidCall;
pub fn decode(frame: &UserContext) -> Result<Call, InvalidCall> {
    let a = frame.registers[8];
    let b = frame.registers[9];
    let c = frame.registers[11];
    let d = frame.registers[5]; // Saved R10; only the cap ABI declares this operand.
    use ev_userspace_contract::syscall;
    Ok(match frame.registers[14] {
        0 => Call::Yield,
        syscall::DISPLAY_INFO if (1..=6).contains(&b) && c == 0 => Call::DisplayInfo {
            capability: Handle(a),
            field: b,
        },
        syscall::JOB_INFO if b <= 8 && c == 0 => Call::JobInfo {
            capability: Handle(a),
            field: b,
        },
        syscall::ENQUEUE_MANAGED_READ if d > 0 && d < u32::MAX as u64 => Call::EnqueueManagedRead {
            process: Handle(a),
            source: Handle(b),
            inbox: Handle(c),
            nonce: d as u32,
        },
        syscall::INHIBIT_MANAGED_PROCESS if b == 0 && c == 0 => {
            Call::InhibitManagedProcess(Handle(a))
        }
        syscall::STOP_PROCESS if b == 0 && c == 0 => Call::StopProcess(Handle(a)),
        syscall::PROCESS_IDENTITY if b == 0 && c == 0 => Call::ProcessIdentity(Handle(a)),
        syscall::RECEIVE_EVENT if b == 0 && c == 0 && d == 0 => Call::ReceiveEvent(Handle(a)),
        syscall::PORT_INPUT if b <= u16::MAX as u64 && matches!(c, 1 | 2 | 4) && d == 0 => {
            Call::PortInput {
                capability: Handle(a),
                port: b,
                width: c,
            }
        }
        syscall::PORT_OUTPUT
            if b <= u16::MAX as u64
                && matches!(c, 1 | 2 | 4)
                && d <= match c {
                    1 => u8::MAX as u64,
                    2 => u16::MAX as u64,
                    _ => u32::MAX as u64,
                } =>
        {
            Call::PortOutput {
                capability: Handle(a),
                port: b,
                width: c,
                value: d,
            }
        }
        syscall::MUTEX_ACQUIRE if b == 0 && c == 0 => Call::MutexAcquire(Handle(a)),
        syscall::MUTEX_RELEASE if b == 0 && c == 0 => Call::MutexRelease(a),
        syscall::SPAWN if (1..=2).contains(&a) && b == 0 && c == 0 => Call::Spawn(a),
        syscall::REPLY_RPC if c == 0 && d != 0 => Call::ReplyRpc {
            endpoint: Handle(a),
            value: b,
            serial: d,
        },
        syscall::RECEIVE_RPC if b == 0 && c == 0 && d == 0 => Call::ReceiveRpc(Handle(a)),
        1 => Call::Exit(a),
        2 => Call::Send {
            endpoint: Handle(a),
            value: b,
            capability: (c != 0).then_some(Handle(c)),
        },
        3 => Call::Receive(Handle(a)),
        4 => {
            let rights =
                Rights::from_bits(u16::try_from(b).map_err(|_| InvalidCall)?).ok_or(InvalidCall)?;
            // Inspect is a query about an existing live capability. All known
            // rights are meaningful inputs; the handler still authorizes every
            // requested bit against the actual caller/object. Decoding grants
            // nothing, and checked conversion above rejects truncation.
            if b == 0 {
                return Err(InvalidCall);
            }
            Call::Inspect {
                capability: Handle(a),
                rights,
            }
        }
        5 => Call::Quanta,
        6 => Call::ReceiveFault(Handle(a)),
        7 if (1..=10000).contains(&b) => Call::ReceiveWait {
            endpoint: Handle(a),
            ticks: b,
        },
        8 => Call::ReceiverWaiting,
        9 => Call::Reclaim(a),
        11 => Call::Revoke(Handle(a)),
        12 => Call::Allocate(Handle(a)),
        13 => Call::Free(Handle(a)),
        10 if b == 1 || b == 2 => Call::MapShared {
            capability: Handle(a),
            writable: b == 2,
        },
        syscall::CREATE_JOB if c == 0 => Call::CreateJob {
            creator: Handle(a),
            template: b,
        },
        syscall::CREATE_PROCESS if c == 0 => Call::CreateProcess {
            job: Handle(a),
            image: Handle(b),
        },
        syscall::DELEGATE => Call::Delegate {
            process: Handle(a),
            source: Handle(b),
            selector: c,
        },
        syscall::START if b == 0 && c == 0 => Call::Start(Handle(a)),
        syscall::CREATE_ENDPOINT if b == 0 && c == 0 => Call::CreateEndpoint(Handle(a)),
        syscall::CLOSE if b == 0 && c == 0 => Call::Close(Handle(a)),
        syscall::OBSERVE if b == 0 && c == 0 => Call::Observe(Handle(a)),
        syscall::FAULT_INFO if b <= 23 && c == 0 => Call::FaultInfo {
            capability: Handle(a),
            field: b,
        },
        syscall::OBSERVE if (1..=6).contains(&b) && c == 0 => Call::ObserveField {
            process: Handle(a),
            field: b,
        },
        syscall::BIND_RECEIVER if c == 0 => Call::BindReceiver {
            endpoint: Handle(a),
            process: Handle(b),
        },
        syscall::RPC_CALL => Call::Rpc {
            endpoint: Handle(a),
            value: b,
            deadline: c,
        },
        syscall::RPC_CALL_CAP => Call::RpcCap {
            endpoint: Handle(a),
            value: b,
            deadline: c,
            capability: Handle(d),
        },
        syscall::RPC_RECEIVE_CAP if b == 0 && c == 0 && d == 0 => Call::ReceiveCap(Handle(a)),
        syscall::RPC_REPLY_CAP if d != 0 => Call::ReplyCap {
            endpoint: Handle(a),
            value: b,
            capability: Handle(c),
            serial: d,
        },
        syscall::RPC_RECLAIM_CAP if a != 0 && b == 0 && c == 0 && d == 0 => Call::ReclaimCap(a),
        syscall::MONOTONIC if a == 0 && b == 0 && c == 0 => Call::Monotonic,
        syscall::RPC_DEADLINE if a == 0 && b == 0 && c == 0 => Call::RpcDeadline,
        syscall::REAP if b == 0 && c == 0 => Call::Reap(Handle(a)),
        _ => return Err(InvalidCall),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fault_info_is_bounded_scalar_and_keeps_legacy_observe_unchanged() {
        let mut frame = UserContext::ZERO;
        frame.registers[14] = ev_userspace_contract::syscall::FAULT_INFO;
        frame.registers[8] = u64::MAX;
        frame.registers[5] = u64::MAX;
        for field in 0..=23 {
            frame.registers[9] = field;
            assert_eq!(
                decode(&frame),
                Ok(Call::FaultInfo {
                    capability: Handle(u64::MAX),
                    field,
                })
            );
        }
        for field in [24, 1 << 32, u64::MAX] {
            frame.registers[9] = field;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        frame.registers[9] = 7;
        frame.registers[11] = 1;
        assert_eq!(decode(&frame), Err(InvalidCall));
        frame.registers[11] = 0;
        frame.registers[14] = ev_userspace_contract::syscall::OBSERVE;
        assert_eq!(decode(&frame), Err(InvalidCall));
        frame.registers[9] = 6;
        assert_eq!(
            decode(&frame),
            Ok(Call::ObserveField {
                process: Handle(u64::MAX),
                field: 6,
            })
        );
    }
    #[test]
    fn job_info_decodes_only_total_fields_and_zero_reserved_without_truncating_handles() {
        let mut frame = UserContext::ZERO;
        frame.registers[14] = ev_userspace_contract::syscall::JOB_INFO;
        // This is a legacy scalar operation: R10 is compiler-live, not a hidden
        // authority operand. Full-width handles reach actual authorization.
        for r10 in [0, u64::MAX] {
            frame.registers[5] = r10;
            for handle in [0, 256, 256 | (1 << 63), u64::MAX] {
                frame.registers[8] = handle;
                for field in 0..=8 {
                    frame.registers[9] = field;
                    assert_eq!(
                        decode(&frame),
                        Ok(Call::JobInfo {
                            capability: Handle(handle),
                            field,
                        })
                    );
                    assert_eq!(frame.registers[5], r10);
                }
            }
        }
        for field in [9, 256, u64::MAX] {
            frame.registers[9] = field;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        frame.registers[9] = 0;
        for reserved in [1, 256, 0x8000100000, u64::MAX] {
            frame.registers[11] = reserved;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
    }
    #[test]
    fn display_info_is_scalar_and_rejects_pointer_shaped_extra_operands() {
        use ev_userspace_contract::syscall;
        let mut frame = UserContext::ZERO;
        frame.registers[14] = syscall::DISPLAY_INFO;
        frame.registers[8] = 257;
        // R10 is compiler-live in the scalar ABI, never a hidden display input.
        frame.registers[5] = u64::MAX;
        for field in 1..=6 {
            frame.registers[9] = field;
            assert_eq!(
                decode(&frame),
                Ok(Call::DisplayInfo {
                    capability: Handle(257),
                    field,
                })
            );
        }
        for field in [0, 7, u64::MAX] {
            frame.registers[9] = field;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        frame.registers[9] = 1;
        frame.registers[11] = 0x8000100000;
        assert_eq!(decode(&frame), Err(InvalidCall));
    }
    #[test]
    fn discipline_calls_cannot_select_user_addresses_or_foreign_contexts() {
        use ev_userspace_contract::syscall;
        let mut f = UserContext::ZERO;
        f.registers[14] = syscall::SPAWN;
        for role in [1, 2] {
            f.registers[8] = role;
            assert_eq!(decode(&f), Ok(Call::Spawn(role)));
        }
        for role in [0, 3, u64::MAX] {
            f.registers[8] = role;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[8] = 257;
        f.registers[14] = syscall::RECEIVE_RPC;
        assert_eq!(decode(&f), Ok(Call::ReceiveRpc(Handle(257))));
        for index in [9, 11, 5] {
            f.registers[index] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[index] = 0;
        }
        f.registers[14] = syscall::REPLY_RPC;
        f.registers[9] = 42;
        assert_eq!(decode(&f), Err(InvalidCall));
        f.registers[5] = u64::MAX;
        assert_eq!(
            decode(&f),
            Ok(Call::ReplyRpc {
                endpoint: Handle(257),
                value: 42,
                serial: u64::MAX
            })
        );
        f.registers[11] = 1;
        assert_eq!(decode(&f), Err(InvalidCall));
    }
    #[test]
    fn capability_calls_use_full_r10_and_reject_reserved_scalar_inputs() {
        use ev_userspace_contract::syscall;
        let mut frame = UserContext::ZERO;
        frame.registers[8] = 257;
        frame.registers[9] = 0xfeedbeef;
        frame.registers[11] = 900;
        frame.registers[5] = u64::MAX;
        frame.registers[14] = syscall::RPC_CALL_CAP;
        assert_eq!(
            decode(&frame),
            Ok(Call::RpcCap {
                endpoint: Handle(257),
                value: 0xfeedbeef,
                deadline: 900,
                capability: Handle(u64::MAX)
            })
        );
        frame.registers[14] = syscall::RPC_REPLY_CAP;
        assert_eq!(
            decode(&frame),
            Ok(Call::ReplyCap {
                endpoint: Handle(257),
                value: 0xfeedbeef,
                capability: Handle(900),
                serial: u64::MAX
            })
        );
        frame.registers[5] = 0;
        assert_eq!(decode(&frame), Err(InvalidCall));
        frame.registers[9] = 0;
        frame.registers[11] = 0;
        for number in [syscall::RPC_RECEIVE_CAP, syscall::RPC_RECLAIM_CAP] {
            frame.registers[14] = number;
            assert!(decode(&frame).is_ok());
            for index in [9, 11, 5] {
                frame.registers[index] = 1;
                assert_eq!(decode(&frame), Err(InvalidCall));
                frame.registers[index] = 0;
            }
        }
        frame.registers[8] = 0;
        assert_eq!(decode(&frame), Err(InvalidCall));
    }
    #[test]
    fn service_calls_use_shared_numbers_and_reject_nonzero_reserved_arguments() {
        use ev_userspace_contract::syscall;
        let mut f = UserContext::ZERO;
        f.registers[8] = 256;
        for number in [
            syscall::START,
            syscall::CREATE_ENDPOINT,
            syscall::CLOSE,
            syscall::STOP_PROCESS,
            syscall::PROCESS_IDENTITY,
        ] {
            f.registers[14] = number;
            f.registers[9] = 0;
            f.registers[11] = 0;
            assert!(decode(&f).is_ok());
            f.registers[9] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[9] = 0;
            f.registers[11] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[14] = syscall::DELEGATE;
        f.registers[9] = 257;
        f.registers[11] = u64::MAX;
        assert_eq!(
            decode(&f),
            Ok(Call::Delegate {
                process: Handle(256),
                source: Handle(257),
                selector: u64::MAX
            })
        );
        // The policy layer rejects unknown full-width role IDs; decoder never
        // truncates them into a different valid role or dereferences a pointer.
    }
    #[test]
    fn protected_deadline_query_rejects_any_supplied_context_argument() {
        let mut frame = UserContext::ZERO;
        frame.registers[14] = ev_userspace_contract::syscall::RPC_DEADLINE;
        assert_eq!(decode(&frame), Ok(Call::RpcDeadline));
        for index in [8, 9, 11] {
            frame.registers[index] = u64::MAX;
            assert_eq!(decode(&frame), Err(InvalidCall));
            frame.registers[index] = 0;
        }
    }
    #[test]
    fn privileged_or_noncanonical_contexts_cannot_resume() {
        let good = UserContext::new(0x8000001000, 0x8000006000).unwrap();
        for bad in [
            UserContext {
                rip: 1 << 47,
                ..good
            },
            UserContext {
                rsp: u64::MAX,
                ..good
            },
            UserContext { cs: 8, ..good },
            UserContext { ss: 16, ..good },
            UserContext {
                flags: 0x3202,
                ..good
            },
            UserContext {
                flags: 0x4202,
                ..good
            },
            UserContext {
                flags: 0x20202,
                ..good
            },
            UserContext { flags: 2, ..good },
        ] {
            assert!(!bad.resumable());
        }
    }
    #[test]
    fn containment_never_accepts_kernel_faults_or_machine_failures() {
        let good = UserContext {
            vector: 14,
            ..UserContext::ZERO
        };
        assert!(good.ordinary_user_fault());
        assert!(UserContext { vector: 1, ..good }.ordinary_user_fault());
        for vector in [2, 8, 18, 32, 128, 255] {
            assert!(!UserContext { vector, ..good }.ordinary_user_fault());
        }
        assert!(!UserContext { cs: 8, ..good }.ordinary_user_fault());
    }
    #[test]
    fn receive_wait_rejects_unbounded_or_zero_duration() {
        let mut frame = UserContext::ZERO;
        frame.registers[14] = 7;
        frame.registers[8] = 256;
        for ticks in [0, 10001, u64::MAX] {
            frame.registers[9] = ticks;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        for ticks in [1, 10000] {
            frame.registers[9] = ticks;
            assert_eq!(
                decode(&frame),
                Ok(Call::ReceiveWait {
                    endpoint: Handle(256),
                    ticks
                })
            );
        }
    }
    #[test]
    fn scalar_decoder_rejects_unknown_calls_and_truncated_or_excess_rights() {
        let mut f = UserContext::ZERO;
        for number in [127, 128, u64::MAX] {
            f.registers[14] = number;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[14] = 4;
        for rights in [0, 512, 1024, 0x10001, u64::MAX] {
            f.registers[9] = rights;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[8] = 256;
        f.registers[9] = 1;
        assert_eq!(
            decode(&f),
            Ok(Call::Inspect {
                capability: Handle(256),
                rights: Rights::READ
            })
        );
        f.registers[14] = 2;
        f.registers[9] = 42;
        f.registers[11] = 0;
        assert_eq!(
            decode(&f),
            Ok(Call::Send {
                endpoint: Handle(256),
                value: 42,
                capability: None
            })
        );
        f.registers[11] = 512;
        assert_eq!(
            decode(&f),
            Ok(Call::Send {
                endpoint: Handle(256),
                value: 42,
                capability: Some(Handle(512))
            })
        );
    }
    #[test]
    fn inspect_decodes_each_known_nonempty_mask_without_inventing_authority() {
        let mut frame = UserContext::ZERO;
        frame.registers[14] = ev_userspace_contract::syscall::INSPECT;
        frame.registers[8] = 256;
        for bits in 1..=511u16 {
            frame.registers[9] = u64::from(bits);
            assert_eq!(
                decode(&frame),
                Ok(Call::Inspect {
                    capability: Handle(256),
                    rights: Rights::from_bits(bits).unwrap(),
                })
            );
        }
    }
    #[test]
    fn decoded_selected_send_inspection_still_enforces_rights_and_live_revocation() {
        use crate::capability::{Authority, Kind};
        let mut authority = Authority::new();
        let owner = authority.create_space().unwrap();
        let app = authority.create_space().unwrap();
        let endpoint = authority
            .create_root(
                owner,
                Kind::Endpoint,
                Rights::SEND
                    | Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::TRANSFER
                    | Rights::REVOKE,
            )
            .unwrap();
        let branch = authority
            .derive(
                owner,
                endpoint,
                owner,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
            )
            .unwrap();
        let selected = authority.derive(owner, branch, app, Rights::SEND).unwrap();
        let mut frame = UserContext::ZERO;
        frame.registers[14] = ev_userspace_contract::syscall::INSPECT;
        frame.registers[8] = selected.0;
        for bit in [1, 2, 4, 8, 16, 32, 64, 128, 256, 8 | 1, 8 | 256] {
            frame.registers[9] = bit;
            let Call::Inspect { capability, rights } = decode(&frame).unwrap() else {
                panic!("known inspection mask did not reach authorization");
            };
            assert_eq!(
                authority
                    .authorize(app, capability, Kind::Endpoint, rights)
                    .is_ok(),
                bit == 8,
                "mask {bit}"
            );
        }
        authority.revoke(owner, branch).unwrap();
        frame.registers[9] = 8;
        let Call::Inspect { capability, rights } = decode(&frame).unwrap() else {
            panic!("inspection decoding must not claim liveness");
        };
        assert!(
            authority
                .authorize(app, capability, Kind::Endpoint, rights)
                .is_err()
        );
        assert!(
            authority
                .authorize(owner, endpoint, Kind::Endpoint, Rights::SEND)
                .is_ok()
        );
    }
}

/// Kernel-owned legacy extended context. No user-provided restore images.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxState(pub [u8; 512]);
impl FxState {
    pub const CLEAN: Self = {
        let mut bytes = [0; 512];
        bytes[0] = 0x7f;
        bytes[1] = 0x03; // x87 default control, empty abridged tag.
        bytes[24] = 0x80;
        bytes[25] = 0x1f; // MXCSR: exceptions masked, round nearest.
        Self(bytes)
    };
}
const _: () = assert!(core::mem::size_of::<FxState>() == 512);
const _: () = assert!(core::mem::align_of::<FxState>() == 16);

#[cfg(test)]
mod mutex_scalar_tests {
    use super::*;
    #[test]
    fn mutex_calls_carry_only_capability_or_lease_never_class() {
        let mut frame = UserContext::ZERO;
        frame.registers[8] = 257;
        for (number, expected) in [
            (30, Call::MutexAcquire(Handle(257))),
            (31, Call::MutexRelease(257)),
        ] {
            frame.registers[14] = number;
            assert_eq!(decode(&frame), Ok(expected));
            frame.registers[9] = 10;
            assert!(decode(&frame).is_err());
            frame.registers[9] = 0;
            frame.registers[11] = 1;
            assert!(decode(&frame).is_err());
            frame.registers[11] = 0;
        }
    }
}

#[cfg(test)]
mod port_scalar_tests {
    use super::*;
    use ev_userspace_contract::syscall;
    #[test]
    fn port_operands_reject_truncation_overflow_and_undeclared_inputs() {
        let mut f = UserContext::ZERO;
        f.registers[8] = u64::MAX; // Handles remain full width for authority lookup.
        for width in [1, 2, 4] {
            f.registers[14] = syscall::PORT_INPUT;
            f.registers[9] = 0x1e8;
            f.registers[11] = width;
            f.registers[5] = 0;
            assert_eq!(
                decode(&f),
                Ok(Call::PortInput {
                    capability: Handle(u64::MAX),
                    port: 0x1e8,
                    width
                })
            );
            f.registers[5] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[5] = 0;
            f.registers[14] = syscall::PORT_OUTPUT;
            let max = match width {
                1 => u8::MAX as u64,
                2 => u16::MAX as u64,
                _ => u32::MAX as u64,
            };
            for value in [0, max] {
                f.registers[5] = value;
                assert_eq!(
                    decode(&f),
                    Ok(Call::PortOutput {
                        capability: Handle(u64::MAX),
                        port: 0x1e8,
                        width,
                        value
                    })
                );
            }
            f.registers[5] = max + 1;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        for number in [syscall::PORT_INPUT, syscall::PORT_OUTPUT] {
            f.registers[14] = number;
            f.registers[5] = 0;
            for port in [65536, u64::MAX] {
                f.registers[9] = port;
                f.registers[11] = 1;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[9] = 0;
            for width in [0, 3, 5, 8, u64::MAX] {
                f.registers[11] = width;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
        }
    }
}

#[cfg(test)]
mod process_event_scalar_tests {
    use super::*;
    use ev_userspace_contract::syscall;
    #[test]
    fn control_and_origin_calls_accept_no_caller_identity_or_truncated_selector() {
        let mut frame = UserContext::ZERO;
        frame.registers[8] = u64::MAX;
        frame.registers[5] = 0xfeed_face;
        for (number, expected) in [
            (syscall::STOP_PROCESS, Call::StopProcess(Handle(u64::MAX))),
            (
                syscall::PROCESS_IDENTITY,
                Call::ProcessIdentity(Handle(u64::MAX)),
            ),
        ] {
            frame.registers[14] = number;
            assert_eq!(decode(&frame), Ok(expected));
            for index in [9, 11] {
                frame.registers[index] = u64::MAX;
                assert_eq!(decode(&frame), Err(InvalidCall));
                frame.registers[index] = 0;
            }
        }
        frame.registers[14] = syscall::OBSERVE;
        assert_eq!(decode(&frame), Ok(Call::Observe(Handle(u64::MAX))));
        for field in 1..=6 {
            frame.registers[9] = field;
            assert_eq!(
                decode(&frame),
                Ok(Call::ObserveField {
                    process: Handle(u64::MAX),
                    field
                })
            );
        }
        for field in [7, 0x100000001, u64::MAX] {
            frame.registers[9] = field;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        frame.registers[9] = 0;
        frame.registers[5] = 0;
        frame.registers[14] = syscall::RECEIVE_EVENT;
        assert_eq!(decode(&frame), Ok(Call::ReceiveEvent(Handle(u64::MAX))));
        for index in [9, 11, 5] {
            frame.registers[index] = 1;
            assert_eq!(decode(&frame), Err(InvalidCall));
            frame.registers[index] = 0;
        }
    }
}

#[cfg(test)]
mod native_self_reply_tests {
    use super::*;
    #[test]
    fn actual_shared_self_reply_changes_exactly_four_declared_outputs_and_preserves_context() {
        let mut f = UserContext {
            registers: core::array::from_fn(|i| 0x92a4_671e_85c0_0000 + i as u64),
            vector: 128,
            error: 7,
            rip: 0x8000001000,
            cs: 35,
            flags: 0x202,
            rsp: 0x8000103000,
            ss: 27,
        };
        let before = f;
        reply_native_root_identity(&mut f, 258, 770, 12345);
        assert_eq!(
            (
                f.registers[14],
                f.registers[9],
                f.registers[11],
                f.registers[5]
            ),
            (0, 258, 770, 12345)
        );
        for i in 0..15 {
            if ![14, 9, 11, 5].contains(&i) {
                assert_eq!(f.registers[i], before.registers[i]);
            }
        }
        assert_eq!(
            (f.vector, f.error, f.rip, f.cs, f.flags, f.rsp, f.ss),
            (
                before.vector,
                before.error,
                before.rip,
                before.cs,
                before.flags,
                before.rsp,
                before.ss
            )
        );
    }
}
