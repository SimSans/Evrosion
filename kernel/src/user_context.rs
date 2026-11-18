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
/// Exact selected-session reply, after independent captured-Root and lifecycle
/// validation. Neither a stale fourth input nor a capability may escape.
#[cfg(feature = "workspace-authority")]
pub fn reply_session_power(frame: &mut UserContext, status: u64, value: u64) {
    frame.registers[14] = status;
    frame.registers[9] = if status == 0 { value } else { 0 };
    frame.registers[11] = 0;
    frame.registers[5] = 0;
}
#[cfg(all(test, feature = "workspace-authority"))]
#[path = "session_power_abi_tests.rs"]
mod session_power_abi_tests;
const _: () = assert!(core::mem::size_of::<UserContext>() == 176);
const _: () = assert!(core::mem::offset_of!(UserContext, rip) == 136);
#[derive(Debug, PartialEq, Eq)]
pub enum Call {
    #[cfg(feature = "workspace-authority")]
    SessionPowerInfo {
        restart: bool,
    },
    #[cfg(feature = "workspace-authority")]
    SessionPowerReady {
        nonce: u64,
        frame: u64,
        input: u64,
    },
    #[cfg(feature = "workspace-authority")]
    SessionPower {
        operation: u64,
        block: Handle,
        nic: Handle,
        extra: u64,
    },
    #[cfg(feature = "workspace-authority")]
    ManagedSendRetire {
        process: Handle,
        nonce: u32,
    },
    #[cfg(feature = "workspace-authority")]
    ManagedSendRetireInfo,
    NetworkNegativeProbe {
        operation: u64,
        cut: u64,
    },
    NetworkRetirement {
        operation: u64,
        driver: Handle,
        service: Handle,
        extra: u64,
    },
    ImageControl {
        creator: Handle,
        operation: ev_userspace_contract::root_v4::dynamic::Operation,
        operand: u64,
        extra: u64,
    },
    #[cfg(feature = "workspace-authority")]
    PrepareWorkspaceProcess {
        creator: Handle,
        process: Handle,
    },
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
    PortByteBatchInfo,
    PortInputBytes4 {
        capability: Handle,
        port: u64,
        deadline: u64,
    },
    PortOutputBytes4 {
        capability: Handle,
        port: u64,
        deadline: u64,
        value: u64,
    },
    PortBatchInfo,
    PortWords256Info,
    PortInputWords256 {
        capability: Handle,
        port: u64,
        deadline: u64,
        buffer: u64,
    },
    PortOutputWords256 {
        capability: Handle,
        port: u64,
        deadline: u64,
        buffer: u64,
    },
    PortInputWords4 {
        capability: Handle,
        port: u64,
        deadline: u64,
    },
    PortOutputWords4 {
        capability: Handle,
        port: u64,
        deadline: u64,
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
    ServingOrigin {
        endpoint: Handle,
        nonce: u64,
        field: u64,
    },
    ServingOriginInfo,
    SelfIdentity {
        field: u64,
    },
    SelfIdentityInfo,
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
    ProcessJobInfo {
        capability: Handle,
        field: u64,
    },
    ProcessJobInfoInfo,
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
        #[cfg(feature = "workspace-authority")]
        syscall::MANAGED_SEND_RETIRE
            if a != 0 && b > 0 && b < u32::MAX as u64 && c == 0 && d == 0 =>
        {
            Call::ManagedSendRetire {
                process: Handle(a),
                nonce: b as u32,
            }
        }
        #[cfg(feature = "workspace-authority")]
        syscall::MANAGED_SEND_RETIRE_INFO if a == 0 && b == 0 && c == 0 && d == 0 => {
            Call::ManagedSendRetireInfo
        }
        syscall::NETWORK_NEGATIVE_PROBE
            if (1..=4).contains(&a) && b == 0 && c == 0 && d > 0 && d < u64::MAX =>
        {
            Call::NetworkNegativeProbe {
                operation: a,
                cut: d,
            }
        }
        syscall::NETWORK_RETIREMENT
            if a <= 1 && b > 0 && c > 0 && b != c && d > 0 && d < u64::MAX =>
        {
            Call::NetworkRetirement {
                operation: a,
                driver: Handle(b),
                service: Handle(c),
                extra: d,
            }
        }
        #[cfg(feature = "workspace-authority")]
        syscall::IMAGE_CONTROL if b == 9 && a > 0 && c > 0 && c < u64::MAX && d == 0 => {
            Call::PrepareWorkspaceProcess {
                creator: Handle(a),
                process: Handle(c),
            }
        }
        syscall::IMAGE_CONTROL => {
            let operation =
                ev_userspace_contract::root_v4::dynamic::Operation::decode(b).ok_or(InvalidCall)?;
            if a == 0 || !operation.operands(c, d) {
                return Err(InvalidCall);
            }
            Call::ImageControl {
                creator: Handle(a),
                operation,
                operand: c,
                extra: d,
            }
        }
        0 => Call::Yield,
        syscall::DISPLAY_INFO if (1..=6).contains(&b) && c == 0 => Call::DisplayInfo {
            capability: Handle(a),
            field: b,
        },
        syscall::JOB_INFO if b <= 8 && c == 0 => Call::JobInfo {
            capability: Handle(a),
            field: b,
        },
        syscall::PROCESS_JOB_INFO if b <= 8 && c == 0 => Call::ProcessJobInfo {
            capability: Handle(a),
            field: b,
        },
        syscall::PROCESS_JOB_INFO_INFO if a == 0 && b == 0 && c == 0 && d == 0 => {
            Call::ProcessJobInfoInfo
        }
        syscall::SERVING_ORIGIN if a != 0 && b != 0 && c < 8 => Call::ServingOrigin {
            endpoint: Handle(a),
            nonce: b,
            field: c,
        },
        syscall::SERVING_ORIGIN_INFO if a == 0 && b == 0 && c == 0 && d == 0 => {
            Call::ServingOriginInfo
        }
        syscall::SELF_IDENTITY if a <= 2 && b == 0 && c == 0 => Call::SelfIdentity { field: a },
        syscall::SELF_IDENTITY_INFO if a == 0 && b == 0 && c == 0 && d == 0 => {
            Call::SelfIdentityInfo
        }
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
        syscall::PORT_BYTE_BATCH_INFO if a == 0 && b == 0 && c == 0 && d == 0 => {
            Call::PortByteBatchInfo
        }
        syscall::PORT_INPUT_BYTES4 if b <= u16::MAX as u64 && c > 0 && c < u64::MAX && d == 0 => {
            Call::PortInputBytes4 {
                capability: Handle(a),
                port: b,
                deadline: c,
            }
        }
        syscall::PORT_OUTPUT_BYTES4
            if b <= u16::MAX as u64 && c > 0 && c < u64::MAX && d <= u32::MAX as u64 =>
        {
            Call::PortOutputBytes4 {
                capability: Handle(a),
                port: b,
                deadline: c,
                value: d,
            }
        }
        syscall::PORT_BATCH_INFO if a == 0 && b == 0 && c == 0 && d == 0 => Call::PortBatchInfo,
        syscall::PORT_WORDS256_INFO if a == 0 && b == 0 && c == 0 && d == 0 => {
            Call::PortWords256Info
        }
        #[cfg(feature = "workspace-authority")]
        syscall::SESSION_POWER_INFO if a <= 1 && b == 0 && c == 0 && d == 0 => {
            Call::SessionPowerInfo { restart: a == 1 }
        }
        #[cfg(feature = "workspace-authority")]
        syscall::SESSION_POWER_INFO
            if a == syscall::SESSION_POWER_READY_QUERY
                && crate::session_power::Readiness::decode(b, c, d).is_some() =>
        {
            Call::SessionPowerReady {
                nonce: b,
                frame: c,
                input: d,
            }
        }
        #[cfg(feature = "workspace-authority")]
        syscall::SESSION_POWER if a <= 2 && b != 0 && c != 0 && b != c && d > 0 && d < u64::MAX => {
            Call::SessionPower {
                operation: a,
                block: Handle(b),
                nic: Handle(c),
                extra: d,
            }
        }
        syscall::PORT_INPUT_WORDS256 if b <= u16::MAX as u64 && c > 0 && c < u64::MAX => {
            Call::PortInputWords256 {
                capability: Handle(a),
                port: b,
                deadline: c,
                buffer: d,
            }
        }
        syscall::PORT_OUTPUT_WORDS256 if b <= u16::MAX as u64 && c > 0 && c < u64::MAX => {
            Call::PortOutputWords256 {
                capability: Handle(a),
                port: b,
                deadline: c,
                buffer: d,
            }
        }
        syscall::PORT_INPUT_WORDS4 if b <= u16::MAX as u64 && c > 0 && c < u64::MAX && d == 0 => {
            Call::PortInputWords4 {
                capability: Handle(a),
                port: b,
                deadline: c,
            }
        }
        syscall::PORT_OUTPUT_WORDS4 if b <= u16::MAX as u64 && c > 0 && c < u64::MAX => {
            Call::PortOutputWords4 {
                capability: Handle(a),
                port: b,
                deadline: c,
                value: d,
            }
        }
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
    fn managed_retirement_numbers_hash_and_profile_scoping_are_additive() {
        use ev_userspace_contract::syscall;
        use sha2::{Digest, Sha256};
        assert_eq!(
            [
                syscall::MANAGED_SEND_RETIRE,
                syscall::MANAGED_SEND_RETIRE_INFO
            ],
            [61, 62]
        );
        assert_eq!(syscall::MANAGED_SEND_RETIRE_V1, 0x0000_0001_0003_0001);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(syscall::MANAGED_SEND_RETIRE_ABI_DESCRIPTION)),
            syscall::MANAGED_SEND_RETIRE_ABI
        );
        let mut f = UserContext::ZERO;
        f.registers[14] = syscall::MANAGED_SEND_RETIRE_INFO;
        #[cfg(feature = "workspace-authority")]
        {
            assert_eq!(decode(&f), Ok(Call::ManagedSendRetireInfo));
            for r in [8, 9, 11, 5] {
                f.registers[r] = 1;
                assert_eq!(decode(&f), Err(InvalidCall));
                f.registers[r] = 0;
            }
            f.registers[14] = syscall::MANAGED_SEND_RETIRE;
            f.registers[8] = (1u64 << 48) | 257;
            for nonce in [1, u32::MAX as u64 - 1] {
                f.registers[9] = nonce;
                assert_eq!(
                    decode(&f),
                    Ok(Call::ManagedSendRetire {
                        process: Handle((1u64 << 48) | 257),
                        nonce: nonce as u32
                    })
                );
            }
            for nonce in [0, u32::MAX as u64, 1u64 << 32, u64::MAX] {
                f.registers[9] = nonce;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[9] = 1;
            for r in [11, 5] {
                f.registers[r] = 1;
                assert_eq!(decode(&f), Err(InvalidCall));
                f.registers[r] = 0;
            }
            f.registers[8] = 0;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        #[cfg(not(feature = "workspace-authority"))]
        {
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[14] = syscall::MANAGED_SEND_RETIRE;
            f.registers[8] = 257;
            f.registers[9] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
    }
    #[test]
    fn self_identity_extension_has_exact_field_shape_and_independent_negotiation() {
        use ev_userspace_contract::syscall;
        use sha2::{Digest, Sha256};
        assert_eq!(
            [syscall::SELF_IDENTITY, syscall::SELF_IDENTITY_INFO],
            [59, 60]
        );
        assert_eq!(syscall::SELF_IDENTITY_V1, 0x0000_0001_0003_0001);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(syscall::SELF_IDENTITY_ABI_DESCRIPTION)),
            syscall::SELF_IDENTITY_ABI
        );
        let mut f = UserContext::ZERO;
        f.registers[14] = syscall::SELF_IDENTITY_INFO;
        assert_eq!(decode(&f), Ok(Call::SelfIdentityInfo));
        for r in [8, 9, 11, 5] {
            f.registers[r] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[r] = 0;
        }
        f.registers[14] = syscall::SELF_IDENTITY;
        f.registers[5] = u64::MAX;
        for field in 0..3 {
            f.registers[8] = field;
            assert_eq!(decode(&f), Ok(Call::SelfIdentity { field }));
        }
        for field in [3, 256, u64::MAX] {
            f.registers[8] = field;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[8] = 0;
        for r in [9, 11] {
            f.registers[r] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[r] = 0;
        }
    }
    #[test]
    fn serving_origin_negotiation_is_additive_and_full_width_scalar_shape_is_exact() {
        use ev_userspace_contract::syscall;
        use sha2::{Digest, Sha256};
        assert_eq!(
            [syscall::SERVING_ORIGIN, syscall::SERVING_ORIGIN_INFO],
            [57, 58]
        );
        assert_eq!(syscall::SERVING_ORIGIN_V1, 0x0000_0001_0008_0001);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(syscall::SERVING_ORIGIN_ABI_DESCRIPTION)),
            syscall::SERVING_ORIGIN_ABI
        );
        let mut frame = UserContext::ZERO;
        frame.registers[14] = syscall::SERVING_ORIGIN_INFO;
        assert_eq!(decode(&frame), Ok(Call::ServingOriginInfo));
        for register in [8, 9, 11, 5] {
            frame.registers[register] = 1;
            assert_eq!(decode(&frame), Err(InvalidCall));
            frame.registers[register] = 0;
        }
        frame.registers[14] = syscall::SERVING_ORIGIN;
        frame.registers[8] = u64::MAX;
        frame.registers[9] = (1u64 << 48) + 1;
        for field in 0..8 {
            for compiler_live in [0, 1, u64::MAX] {
                frame.registers[11] = field;
                frame.registers[5] = compiler_live;
                assert_eq!(
                    decode(&frame),
                    Ok(Call::ServingOrigin {
                        endpoint: Handle(u64::MAX),
                        nonce: (1u64 << 48) + 1,
                        field
                    })
                );
                assert_eq!(frame.registers[5], compiler_live);
            }
        }
        for (register, value) in [(8, 0), (9, 0), (11, 8), (11, u64::MAX)] {
            let mut bad = frame;
            bad.registers[register] = value;
            assert_eq!(decode(&bad), Err(InvalidCall));
        }
        // A new descriptor must never reinterpret Receive34's four-output ABI.
        frame = UserContext::ZERO;
        frame.registers[14] = syscall::RECEIVE_RPC;
        frame.registers[8] = 0x1234;
        assert_eq!(decode(&frame), Ok(Call::ReceiveRpc(Handle(0x1234))));
        for register in [9, 11, 5] {
            let mut bad = frame;
            bad.registers[register] = 1;
            assert_eq!(decode(&bad), Err(InvalidCall));
        }
    }
    #[test]
    fn image_control52_is_total_typed_and_cannot_wrap_an_unknown_op_into_cleanup() {
        use ev_userspace_contract::root_v4::dynamic::Operation;
        let mut f = UserContext::ZERO;
        f.registers[14] = ev_userspace_contract::syscall::IMAGE_CONTROL;
        f.registers[8] = 123;
        for (op, operand, extra) in [
            (0, 0, 0),
            (1, 100, 0),
            (2, 1, 4096u64 << 32),
            (3, 2, 0),
            (4, 1, 0),
            (5, 1, 0),
            (6, 1, 0),
            (7, 2, 0),
            (8, 0, 0),
        ] {
            f.registers[9] = op;
            f.registers[11] = operand;
            f.registers[5] = extra;
            assert_eq!(
                decode(&f),
                Ok(Call::ImageControl {
                    creator: Handle(123),
                    operation: Operation::decode(op).unwrap(),
                    operand,
                    extra
                })
            );
        }
        for op in [9, 255, 256, u32::MAX as u64, u64::MAX] {
            f.registers[9] = op;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[9] = 0;
        f.registers[11] = 0;
        f.registers[5] = 0;
        f.registers[8] = 0;
        assert_eq!(decode(&f), Err(InvalidCall));
        for id in [53, 54, u64::MAX] {
            f.registers[14] = id;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
    }
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
    fn process_job_info_extension_is_negotiated_and_preserves_full_width_scalar_operands() {
        use ev_userspace_contract::syscall;
        use sha2::{Digest, Sha256};
        assert_eq!(
            (
                syscall::JOB_INFO,
                syscall::NETWORK_NEGATIVE_PROBE,
                syscall::PROCESS_JOB_INFO,
                syscall::PROCESS_JOB_INFO_INFO
            ),
            (42, 54, 55, 56)
        );
        assert_eq!(syscall::PROCESS_JOB_INFO_V1, 0x0000_0001_0009_0003);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(syscall::PROCESS_JOB_INFO_ABI_DESCRIPTION)),
            syscall::PROCESS_JOB_INFO_ABI
        );
        assert_ne!(syscall::PROCESS_JOB_INFO_ABI, syscall::PORT_BATCH_ABI);
        let mut frame = UserContext::ZERO;
        frame.registers[14] = syscall::PROCESS_JOB_INFO;
        for r10 in [0, 1, u64::MAX] {
            frame.registers[5] = r10;
            for capability in [0, 256, 256 | (1 << 63), u64::MAX] {
                frame.registers[8] = capability;
                for field in 0..=8 {
                    frame.registers[9] = field;
                    assert_eq!(
                        decode(&frame),
                        Ok(Call::ProcessJobInfo {
                            capability: Handle(capability),
                            field
                        })
                    );
                    assert_eq!(frame.registers[5], r10);
                }
            }
        }
        for field in [9, 256, 1 << 63, u64::MAX] {
            frame.registers[9] = field;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        frame.registers[9] = 0;
        for reserved in [1, 256, 1 << 63, u64::MAX] {
            frame.registers[11] = reserved;
            assert_eq!(decode(&frame), Err(InvalidCall));
        }
        frame = UserContext::ZERO;
        frame.registers[14] = syscall::PROCESS_JOB_INFO_INFO;
        assert_eq!(decode(&frame), Ok(Call::ProcessJobInfoInfo));
        for index in [8, 9, 11, 5] {
            for reserved in [1, 256, 1 << 63, u64::MAX] {
                frame.registers[index] = reserved;
                assert_eq!(decode(&frame), Err(InvalidCall));
            }
            frame.registers[index] = 0;
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
    fn sector_decode_preserves_full_byte_address_and_denies_malformed_negotiation() {
        let mut f = UserContext::ZERO;
        f.registers[14] = syscall::PORT_WORDS256_INFO;
        assert_eq!(decode(&f), Ok(Call::PortWords256Info));
        for register in [8, 9, 11, 5] {
            f.registers[register] = 1;
            assert!(decode(&f).is_err());
            f.registers[register] = 0;
        }
        for number in [syscall::PORT_INPUT_WORDS256, syscall::PORT_OUTPUT_WORDS256] {
            f.registers[14] = number;
            f.registers[8] = u64::MAX;
            f.registers[9] = 65535;
            f.registers[11] = 1;
            for address in [0, 1, 0x8000003001, u64::MAX] {
                f.registers[5] = address;
                let expected = if number == syscall::PORT_INPUT_WORDS256 {
                    Call::PortInputWords256 {
                        capability: Handle(u64::MAX),
                        port: 65535,
                        deadline: 1,
                        buffer: address,
                    }
                } else {
                    Call::PortOutputWords256 {
                        capability: Handle(u64::MAX),
                        port: 65535,
                        deadline: 1,
                        buffer: address,
                    }
                };
                assert_eq!(decode(&f), Ok(expected)); // Actual ownership is a later independent join.
            }
            f.registers[9] = 65536;
            assert!(decode(&f).is_err());
            f.registers[9] = 0x1e8;
            for cut in [0, u64::MAX] {
                f.registers[11] = cut;
                assert!(decode(&f).is_err());
            }
        }
    }
    #[test]
    fn byte_batch_negotiation_and_operands_are_total_and_never_truncate() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(syscall::PORT_BYTE_BATCH_ABI_DESCRIPTION)),
            syscall::PORT_BYTE_BATCH_ABI
        );
        let mut f = UserContext::ZERO;
        f.registers[14] = syscall::PORT_BYTE_BATCH_INFO;
        assert_eq!(decode(&f), Ok(Call::PortByteBatchInfo));
        for register in [8, 9, 11, 5] {
            for value in [1, u64::MAX] {
                f.registers[register] = value;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[register] = 0;
        }
        for number in [syscall::PORT_INPUT_BYTES4, syscall::PORT_OUTPUT_BYTES4] {
            f.registers[14] = number;
            f.registers[8] = u64::MAX;
            f.registers[9] = 65535;
            f.registers[11] = 1;
            assert!(decode(&f).is_ok()); // Full-width handle is checked by authority.
            for port in [65536, 1 << 32, u64::MAX] {
                f.registers[9] = port;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[9] = 0x310;
            for cut in [0, u64::MAX] {
                f.registers[11] = cut;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[11] = 512;
        }
        f.registers[5] = u32::MAX as u64;
        assert!(
            matches!(decode(&f),Ok(Call::PortOutputBytes4{value,..}) if value==u32::MAX as u64)
        );
        for high in [1 << 32, u64::MAX] {
            f.registers[5] = high;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
        f.registers[14] = syscall::PORT_INPUT_BYTES4;
        for extra in [1, u32::MAX as u64, u64::MAX] {
            f.registers[5] = extra;
            assert_eq!(decode(&f), Err(InvalidCall));
        }
    }
    #[test]
    fn negotiated_word_batch_has_exact_shape_and_separate_identity() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(syscall::PORT_BATCH_ABI_DESCRIPTION)),
            syscall::PORT_BATCH_ABI
        );
        assert_eq!(syscall::PORT_BATCH_V1, 0x0000_0001_0004_0002);
        let mut f = UserContext::ZERO;
        f.registers[14] = syscall::PORT_BATCH_INFO;
        assert_eq!(decode(&f), Ok(Call::PortBatchInfo));
        for register in [8, 9, 11, 5] {
            f.registers[register] = 1;
            assert_eq!(decode(&f), Err(InvalidCall));
            f.registers[register] = 0;
        }
        for number in [syscall::PORT_INPUT_WORDS4, syscall::PORT_OUTPUT_WORDS4] {
            f.registers[14] = number;
            f.registers[8] = u64::MAX;
            f.registers[9] = 0x1e8;
            f.registers[11] = 1024;
            assert!(decode(&f).is_ok());
            for port in [65536, u64::MAX] {
                f.registers[9] = port;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[9] = 0x1e8;
            for cut in [0, u64::MAX] {
                f.registers[11] = cut;
                assert_eq!(decode(&f), Err(InvalidCall));
            }
            f.registers[11] = 1024;
        }
        f.registers[5] = u64::MAX;
        assert!(matches!(
            decode(&f),
            Ok(Call::PortOutputWords4 {
                value: u64::MAX,
                ..
            })
        ));
        f.registers[14] = syscall::PORT_INPUT_WORDS4;
        assert_eq!(decode(&f), Err(InvalidCall));
    }
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

#[cfg(test)]
mod network_retirement_tests {
    use super::*;
    #[test]
    fn fixed_scalar_retirement_decode_requires_exact_operation_pair_and_extra() {
        for operation in [0, 1] {
            let mut f = UserContext::ZERO;
            f.registers[14] = ev_userspace_contract::syscall::NETWORK_RETIREMENT;
            f.registers[8] = operation;
            f.registers[9] = 7;
            f.registers[11] = 8;
            f.registers[5] = 8192;
            assert_eq!(
                decode(&f),
                Ok(Call::NetworkRetirement {
                    operation,
                    driver: Handle(7),
                    service: Handle(8),
                    extra: 8192,
                })
            );
            for (index, value) in [(8, 2), (9, 0), (11, 0), (11, 7), (5, 0), (5, u64::MAX)] {
                let mut bad = f;
                bad.registers[index] = value;
                assert_eq!(decode(&bad), Err(InvalidCall));
            }
        }
    }
}

#[cfg(test)]
mod negative_probe_decode_tests {
    use super::*;
    #[test]
    fn only_exact_finite_root_probe_arm_shape_decodes() {
        for operation in 1..=4 {
            let mut f = UserContext::ZERO;
            f.registers[14] = ev_userspace_contract::syscall::NETWORK_NEGATIVE_PROBE;
            f.registers[8] = operation;
            f.registers[5] = 8192;
            assert_eq!(
                decode(&f),
                Ok(Call::NetworkNegativeProbe {
                    operation,
                    cut: 8192
                })
            );
            for (index, value) in [(8, 0), (8, 5), (9, 1), (11, 1), (5, 0), (5, u64::MAX)] {
                let mut bad = f;
                bad.registers[index] = value;
                assert_eq!(decode(&bad), Err(InvalidCall));
            }
        }
    }
}

#[cfg(all(test, feature = "workspace-authority"))]
mod workspace_prepare_decode_tests {
    use super::*;
    #[test]
    fn prepare9_carries_only_actual_creator_and_process_caps_and_preserves_legacy_operations() {
        let mut frame = UserContext::ZERO;
        frame.registers[14] = ev_userspace_contract::syscall::IMAGE_CONTROL;
        frame.registers[8] = 17;
        frame.registers[9] = 9;
        frame.registers[11] = 23;
        assert_eq!(
            decode(&frame),
            Ok(Call::PrepareWorkspaceProcess {
                creator: Handle(17),
                process: Handle(23)
            })
        );
        for (register, value) in [(8, 0), (9, 10), (11, 0), (11, u64::MAX), (5, 1)] {
            let mut bad = frame;
            bad.registers[register] = value;
            assert_eq!(decode(&bad), Err(InvalidCall));
        }
        frame.registers[9] = 0;
        frame.registers[11] = 0;
        assert_eq!(
            decode(&frame),
            Ok(Call::ImageControl {
                creator: Handle(17),
                operation: ev_userspace_contract::root_v4::dynamic::Operation::Initialize,
                operand: 0,
                extra: 0
            })
        );
    }
}
