//! Internal scalar call numbers, shared by userspace transport and kernel decode.
//! Additive bringup operations; this is not a Stable public ABI.
pub const YIELD: u64 = 0;
pub const EXIT: u64 = 1;
pub const SEND: u64 = 2;
pub const RECEIVE: u64 = 3;
/// Query a known nonempty rights mask on an actual installed live capability.
/// Decoding accepts all current rights; each handler still authorizes the whole
/// requested mask. This additive Internal query preserves original READ/WRITE
/// inputs and never grants rights, accepts unknown bits or truncates operands.
pub const INSPECT: u64 = 4;
/// Read a stopped child's actual captured user-fault context through its live
/// Process CONTROL handle. Fields 0..23 are Job/Process/Thread, fault facts,
/// RIP/RSP/RFLAGS and the 15 captured GPRs. No user pointer or raw PID lookup.
pub const FAULT_INFO: u64 = 43;
pub const CREATE_JOB: u64 = 14;
pub const CREATE_PROCESS: u64 = 15;
pub const DELEGATE: u64 = 16;
pub const START: u64 = 17;
pub const CREATE_ENDPOINT: u64 = 18;
pub const CLOSE: u64 = 19;
pub const OBSERVE: u64 = 20;
pub const BIND_RECEIVER: u64 = 21;
pub const RPC_CALL: u64 = 22;
pub const MONOTONIC: u64 = 23;
pub const REAP: u64 = 24;
//25..28 reserved by the separate capability-bearing RPC transport.
pub const RPC_DEADLINE: u64 = 29;

/// Capability-bearing operations use a separate four-scalar ABI with R10.
/// Legacy `call` operations preserve R10 unchanged.
pub const RPC_CALL_CAP: u64 = 25;
pub const RPC_RECEIVE_CAP: u64 = 26;
pub const RPC_REPLY_CAP: u64 = 27;
pub const RPC_RECLAIM_CAP: u64 = 28;

/// Exact ownership tags for RPC_CALL_CAP. Error reasons are returned in RSI;
/// these tags must never be inferred from a success/failure boolean.
pub mod cap_phase {
    pub const RETURNED: u64 = 0;
    pub const REJECTED: u64 = 1;
    pub const QUEUED_RECOVERED: u64 = 2;
    pub const DELIVERED_FAILURE: u64 = 3;
    pub const QUEUED_INVALIDATED: u64 = 4;
    pub const QUEUED_PENDING: u64 = 5;
}

/// RPC_REPLY_CAP tags are separate from CALL ownership states.
pub mod cap_reply_phase {
    pub const ACCEPTED: u64 = 0;
    pub const REJECTED: u64 = 1;
    pub const LATE_RETAINED: u64 = 2;
}

/// Mutex acquire returns RSI=lease serial, RDX=abandoned (0/1); release takes the lease.
pub const MUTEX_ACQUIRE: u64 = 30;
pub const MUTEX_RELEASE: u64 = 31;

/// Spawn only a declared local role using the fixture's measured entry/stack.
pub const SPAWN: u64 = 32;
/// Complete the actually received call nonce through its incoming endpoint.
pub const REPLY_RPC: u64 = 33;
/// Receive one cap-free RPC and return its protected nonce in R10.
pub const RECEIVE_RPC: u64 = 34;

/// Mediated port operations: cap/port/width, plus output value in R10.
/// Input requires zero R10. Both return status/RSI value and clear RDX/R10.
pub const PORT_INPUT: u64 = 35;
pub const PORT_OUTPUT: u64 = 36;

/// Process CONTROL requests, with no caller PID, thread or ready assertion.
pub const STOP_PROCESS: u64 = 37;
/// Actual admitted process/thread diagnostics in RSI/RDX. ChildCONTROL and
/// oldDesktop/provider preserve legacy R10. Native3 Root cap0 uses call4 and
/// returns the actual syscall capture tick in R10; this is timing, not authority.
/// Native Root may use capability0 for its actual dispatched self identity.
/// Child lookup still requires its live Process CONTROL capability; returned
/// diagnostic integers never confer authority.
pub const PROCESS_IDENTITY: u64 = 38;
/// Exact event origin: endpoint only; body RSI, sender process RDX/thread R10.
/// This is a four-output call; diagnostics grant no authority.
pub const RECEIVE_EVENT: u64 = 39;

/// Inspect only the caller's authorized, actually installed Display aperture.
/// Fields1..6 return user address, width, height, stride, bytes and pixel format.
/// Scalar ABI: no user pointer or R10 operand; possession is checked in kernel.
pub const DISPLAY_INFO: u64 = 40;

/// Read-only Job information. RDI0 selects the actual dispatched caller's Job;
/// any other value must be a live Job CONTROL capability in that caller's domain.
/// RSI fields:0 diagnostic ID;1..4 CPU/frame/process/thread usage;5..8 limits.
/// RDX is reserved zero. Scalar status/value returns clear RDX and preserve R10.
/// Diagnostic IDs are never accepted as authority or scheduler lookup operands.
pub const JOB_INFO: u64 = 42;

/// Native3 Root-only managed READ handoff. Actual App CONTROL / FileRO SEND
/// source / bound GrantInbox SEND / fresh authenticated App Open nonce in R10.
/// Acceptance returns only ticket metadata, never a capability.
pub const ENQUEUE_MANAGED_READ: u64 = 44;
/// Native3 Root-only one-way dispatch inhibition of the current live App.
/// Legacy scalar ProcessCONTROL/0/0; preserves R10. Already accepted caller work
/// must complete before ordinary stop/revoke/reap and durable acknowledgement.
pub const INHIBIT_MANAGED_PROCESS: u64 = 45;
