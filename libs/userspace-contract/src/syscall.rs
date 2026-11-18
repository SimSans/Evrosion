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

/// Additive Internal port-word-batch v1. Negotiate INFO before any device I/O;
/// an older kernel rejects the unknown operation without executing a port op.
/// INFO requires all four operands zero and returns this exact descriptor.
pub const PORT_BATCH_INFO: u64 = 46;
pub const PORT_BATCH_V1: u64 = 0x0000_0001_0004_0002;
/// cap / same word port / absolute finite deadline / zero. Returns four
/// little-endian u16 reads packed in RSI. Width and count are fixed by opcode.
pub const PORT_INPUT_WORDS4: u64 = 47;
/// cap / same word port / absolute finite deadline / four packed LE u16 words.
/// Both batch operations clear RDX/R10; original scalar35/36 stay unchanged.
pub const PORT_OUTPUT_WORDS4: u64 = 48;
pub const PORT_BATCH_MAX_TICKS: u64 = 1024;
/// Additive Internal byte-port batch, negotiated separately from Word4.
/// All INFO operands must be zero. Fixed count4, width1, same port.
pub const PORT_BYTE_BATCH_INFO: u64 = 49;
pub const PORT_BYTE_BATCH_V1: u64 = 0x0000_0001_0004_0001;
/// cap / byte port / absolute finite deadline / zero; four LE bytes in RSI.
pub const PORT_INPUT_BYTES4: u64 = 50;
/// cap / byte port / absolute finite deadline / four LE bytes, upper32 zero.
pub const PORT_OUTPUT_BYTES4: u64 = 51;
/// V4-only fixed private control page.
pub const IMAGE_CONTROL: u64 = 52;
/// V4 captured Root only: operation0 begins bounded failed-NIC retirement using
/// exact Driver/Service CONTROLs and original absolute cut; operation1 joins the
/// same pair/token after trusted Root physical STOP/scrub/readback. No new grant.
pub const NETWORK_RETIREMENT: u64 = 53;
/// Explicit negative-fixture only; ordinary V4 rejects it. Captured Root arms
/// bounded read-only observations/one current-call stop, never App authority.
pub const NETWORK_NEGATIVE_PROBE: u64 = 54;
pub const PORT_BATCH_ABI_DESCRIPTION: &[u8] = b"Evrosion Internal port-word-batch v1; INFO46 all4zero returns0x0000000100040002; INPUT47 cap,port,absoluteDeadline,zero returns4LEWord packedRSI; OUTPUT48 cap,port,absoluteDeadline,4LEWord packedR10; fixedsameport count4 width2; actualrunningScheduler/Rpcdomain livefullIoPortscap generation/range/direction; capturedfinitefuturedeadline max1024 beforeanyIO; IF0 fixed4instructions no userpointer/devicepolicy; statusoutputs clearRDXR10; old35/36 unchanged; negotiation beforeanyPIO required by native-session Block";

/// SHA256 of the separate extension description; original bootstrap hashes stay unchanged.
pub const PORT_BATCH_ABI: [u8; 32] = [
    0x43, 0xef, 0xed, 0xc0, 0x50, 0x6d, 0x45, 0x8f, 0xd1, 0x00, 0x3b, 0xca, 0x8b, 0xcc, 0xc0, 0xe0,
    0xf1, 0x26, 0x3a, 0xea, 0xa2, 0x58, 0x50, 0x05, 0xe4, 0xc3, 0xb5, 0xf9, 0x0e, 0x47, 0x90, 0x6d,
];

/// Separate additive byte-batch identity; the Word4 description/hash is unchanged.
pub const PORT_BYTE_BATCH_ABI_DESCRIPTION: &[u8] = b"Evrosion Internal port-byte-batch v1; INFO49 all4zero returns0x0000000100040001; INPUT50 cap,port,absoluteDeadline,zero returns4LEByte packedRSI upper32zero; OUTPUT51 cap,port,absoluteDeadline,4LEByte packedR10 upper32zero; fixedsameport count4 width1; actualrunningScheduler/Rpcdomain livefullIoPortscap generation/range/direction; capturedfinitefuturedeadline max1024 beforeanyIO; IF0 fixed4instructions no userpointer/devicepolicy; statusoutputs clearRDXR10; old35/36/46/47/48 unchanged; negotiation beforeanyPIO required by byte-batch NIC driver";
pub const PORT_BYTE_BATCH_ABI: [u8; 32] = [
    0x65, 0x20, 0xd4, 0xe1, 0x9f, 0xd5, 0x63, 0xae, 0x94, 0x81, 0x94, 0xbb, 0x1c, 0xec, 0x7c, 0x5b,
    0x2f, 0x17, 0x59, 0xe8, 0x3c, 0xf8, 0xea, 0x79, 0x65, 0xc6, 0xbd, 0x02, 0x91, 0x09, 0x26, 0x54,
];

/// Additive read-only native-profile query through an existing live Process
/// CONTROL capability. cap/field0..8/zero; R10 is legacy compiler-live state.
/// Actual admitted retained Process resolves its Job, including stopped before
/// retirement; no PID lookup,
/// zero/self shortcut, new right or Job capability. JOB_INFO42 is unchanged.
pub const PROCESS_JOB_INFO: u64 = 55;
/// Negotiate before QUERY55: all four operands zero; returns descriptor in RSI,
/// clears RDX/R10. Unsupported/older profiles refuse rather than guessing.
pub const PROCESS_JOB_INFO_INFO: u64 = 56;
pub const PROCESS_JOB_INFO_V1: u64 = 0x0000_0001_0009_0003;
pub const PROCESS_JOB_INFO_ABI_DESCRIPTION: &[u8] = b"Evrosion Internal process-job-info v1; INFO56 all4zero returns0x0000000100090003 clearRDXR10; QUERY55 liveProcessCONTROL,field0..8,zero scalar preservesR10 clearsRDX; actualcapturedRunningCaller/domain fullProcessObjectGeneration ActiveRegistry currentProcessThreadJobSchedulerAssociation notHeldOrRetired retainedStoppedBeforeRetirementAllowed; field0 diagnosticJob1..4usage5..8limits sameJOB_INFO42; noRawPidLookup noSelfZero noNewCapabilityOrRights; nativeProfileOnly; existing42/bootstrapABI unchanged; queryOnlyNoLifecycleChange";
pub const PROCESS_JOB_INFO_ABI: [u8; 32] = [
    0x9b, 0x4e, 0x53, 0x57, 0xbf, 0x8d, 0x5c, 0x9b, 0x58, 0x42, 0x9e, 0x0d, 0x60, 0x1f, 0xbc, 0x60,
    0x68, 0x49, 0x96, 0x21, 0x73, 0x1c, 0xc0, 0x0f, 0xbf, 0xf8, 0x73, 0x6e, 0xf6, 0xaa, 0x80, 0xfe,
];

/// Native-only read-only immediate caller provenance for the exact currently
/// delivered serving call. QUERY capRECEIVE/actualReceiveNonce/field0..7;
/// scalar status/value clearsRDX and preserves compiler-liveR10. No PID inputs.
pub const SERVING_ORIGIN: u64 = 57;
/// Negotiate all four zero operands; returns the exact descriptor in RSI.
pub const SERVING_ORIGIN_INFO: u64 = 58;
pub const SERVING_ORIGIN_V1: u64 = 0x0000_0001_0008_0001;
pub const SERVING_ORIGIN_ABI_DESCRIPTION:&[u8]=b"Evrosion Internal serving-origin v1; INFO58 all4zero returns0x0000000100080001 scalarclearRDXpreserveR10; QUERY57 actualRECEIVEendpoint,actualReceiveRPCnonce,field0..7 scalarclearRDXpreserveR10; capturedrunningreceiver sameAuthorityScheduler registeredSpaceJobThreadGenerations notTerminated; actualnativependingcallee delivered nonce servingCall fullendpointobject join; fields0immediateCallerProcessDiagnostic1immediateCallerThreadDiagnostic2registeredImmediateCallerIncarnationNumberOr0NotAncestor3callEpoch4callSerial5fullEndpointObjectIdentity6originalDeadline7status0live1cancelled2expired3peerDied; retainedCallThread sameScheduler; terminalcontext remainsreadonly while actualcalleeexecutionreservation retained; noPidLookup noPayloadIdentity noNewAuthority noCompletionWakeReleaseOrCreditBypass; nativeProfileOnly; legacyReceive34bodyRSInonceR10RDX0 andalloldnumbers unchanged";
pub const SERVING_ORIGIN_ABI: [u8; 32] = [
    0xea, 0x24, 0xcd, 0xa4, 0x7d, 0xa0, 0x45, 0x2d, 0x84, 0x1b, 0xbb, 0xa5, 0x50, 0x9a, 0xb7, 0x57,
    0xb2, 0x4c, 0x83, 0x21, 0xa9, 0x4b, 0xba, 0xd4, 0xeb, 0xbe, 0xdc, 0x5e, 0x9f, 0x14, 0xe5, 0xb8,
];

/// Actual captured self coordinates, not an authority or a caller-ID lookup.
/// Only the selected M8 profile implements this separately negotiated extension.
pub const SELF_IDENTITY: u64 = 59;
pub const SELF_IDENTITY_INFO: u64 = 60;
pub const SELF_IDENTITY_V1: u64 = 0x0000_0001_0003_0001;
pub const SELF_IDENTITY_ABI_DESCRIPTION: &[u8] = b"Evrosion Internal self-identity v1; INFO60 all4zero returns0x0000000100030001 scalarclearRDXpreserveR10; QUERY59 field0..2,zero,zero scalarclearRDXpreserveR10; actualcapturedRunningThreadDomain matchedAuthorityScheduler RpcRegistration fullProcessThreadJobGenerations notTerminated; fields0actualProcessDiagnostic1actualThreadDiagnostic2registeredIncarnationNumberOr0 notUniqueRootRoleProof; noPidThreadDomainInputs noRawIdLookup noCapabilitiesOrRights noLifecycleChange; M8workspaceProfileOnly olderprofilesrefuse; PROCESS_IDENTITY38 andoldbootstrapABI unchanged";
pub const SELF_IDENTITY_ABI: [u8; 32] = [
    0x1c, 0x82, 0x99, 0xe7, 0xb0, 0x1d, 0x26, 0x53, 0xd2, 0xdc, 0x2c, 0x3f, 0x2d, 0x57, 0x3f, 0xae,
    0x78, 0xf7, 0x3b, 0xdc, 0x91, 0x28, 0x3b, 0x1a, 0xac, 0xb6, 0x40, 0xf7, 0x9f, 0x30, 0x5b, 0x9f,
];

/// Negotiated selected M8 private managed-SEND owner retirement.
pub const MANAGED_SEND_RETIRE: u64 = 61;
pub const MANAGED_SEND_RETIRE_INFO: u64 = 62;
pub const MANAGED_SEND_RETIRE_V1: u64 = 0x0000_0001_0003_0001;
pub const MANAGED_SEND_RETIRE_ABI_DESCRIPTION:&[u8]=b"Evrosion Internal M8 managed-send-retire v1; INFO62 all4zero returns0x0000000100030001 scalarclearRDXpreserveR10; RETIRE61 actualProcessCONTROL,exactissued44nonce32,zero,zero; capturedactualRunningRootToken/fullProcessThreadSpaceJob only noPidInputs; exactownedprivateActiveGrantBranch revokesallretainedescapedSENDdescendants withoutrevokingRootsourceMasterorWorkspaceRX; withdrawactualundeliveredselectedescrow orretainowner; RSI0Drained1RevokedPending2Retained onlystatus0validatedrequest; DrainedrequiresactualretainednativeRPC/windowcreditsnone andactualselectedinboxsettled; deadlineorReleaseACKalone neverreturnscredit; nofreshgrant/rebinduntilDrained; noDurableStageAbort/noBlockDeviceQuiescence implied independentServiceAdminreconciliationrequired; additiveM8physicalprofileonly old44/default/olderprofilesunknown61/62 unchanged";
pub const MANAGED_SEND_RETIRE_ABI: [u8; 32] = [
    0x66, 0xc3, 0x88, 0x3a, 0xae, 0x36, 0xb8, 0x00, 0x8f, 0x2a, 0x5d, 0xd8, 0x39, 0xb5, 0xc3, 0x45,
    0x3a, 0xe6, 0xec, 0xb1, 0x38, 0xc7, 0xca, 0x24, 0x46, 0x6e, 0x0f, 0x13, 0x1f, 0x01, 0xdb, 0x47,
];

/// Additive selected-M8 fixed sector PIO. These calls never interpret the VA
/// as authority: actual Running Block/private-owner and IoPorts proofs remain
/// Kernel obligations. INFO has no I/O and requires all four operands zero.
pub const PORT_INPUT_WORDS256: u64 = 63;
pub const PORT_OUTPUT_WORDS256: u64 = 64;
pub const PORT_WORDS256_INFO: u64 = 65;
pub const PORT_WORDS256_V1: u64 = 0x0000_0001_0100_0002;
pub const PORT_WORDS256_COUNT: usize = 256;
pub const PORT_WORDS256_BYTES: usize = 512;
pub const PORT_WORDS256_MAX_PAGES: usize = 2;
pub const PORT_WORDS256_MAX_TICKS: u64 = PORT_BATCH_MAX_TICKS;
/// Selected M8 captured-Root checked VM shutdown, additive and negotiated.
pub const SESSION_POWER_INFO: u64 = 66;
pub const SESSION_POWER: u64 = 67;
pub const SESSION_POWER_V1: u64 = 0x0000_0001_0001_0001;
/// INFO66(1,0,0,0) explicitly queries the selected checked-restart adapter.
/// INFO66(0,0,0,0) keeps its exact old shutdown-only response above.
pub const SESSION_POWER_RESTART_V1: u64 = 0x0000_0001_0001_0003;
/// Optional selected-Root diagnostic, INFO66(2,nonce,frame,input_snapshot).
/// Reports only post-attest pacing metadata, with no authority or power effect.
/// Snapshot bits0..31=barrier sequence,32/33=main/keypad Enter held,
/// 34..36=pointer held,37..39=pointer released,40=restart intent,
/// 41/42=main/keypad prior-break knowledge; rest zero.
/// Old queries0/1 and all power control behavior are unchanged.
pub const SESSION_POWER_READY_QUERY: u64 = 2;
/// CONTROL67(operation,actualBlockCONTROL,actualNicCONTROL,extra).
/// BEGIN0 freezes device CPUs under extra=original finite cut<=8192 only
/// after all other actors and accepted work settle; successRSI=token1.
/// BEGIN_RESTART1 has the same finite fence, but captures restart intent once.
/// It is Unsupported unless the explicit restart query succeeds. COMPLETE2
/// cannot change the captured intent and requires token1 and the same
/// actual controls/cut after trusted Root physical FLUSH/STOP/scrub/readback.
/// All source/device owners stay pinned through the final power action.
/// Generic EXIT never means shutdown. Status3 means sticky partial/frozen
/// transition and forbids a new begin; status1/2/4 are denied/busy/expired.
/// capIo / same width2 port / original absolute cut / private512-byte VA.
/// Byte alignment is sufficient; Kernel uses aligned scratch and byte copies.
/// Success and errors clear value/capability/serial; no caller PID or mapping.
pub const PORT_WORDS256_ABI_DESCRIPTION: &[u8] = b"Evrosion Internal M8 port-words256 v1; INFO65 all4zero returns0x0000000101000002; INPUT63 capIo,port,absoluteCut,ownPrivateBufferVA; OUTPUT64 sameoperands; fixedsameport count256 width2 littleendian512bytes; selectedBlockOnly actualcapturedRunningThreadSpaceJob andretainedprivateImageOwner; independentlyliveIoPortscap fullgeneration/range/direction width2; VAbytealigned noWordAlignmentRequired Kernelalignedscratch bytecopies entire512bytecontiguousvirtualspan atmost2actualprivateRWNXRAMpages samecapturedowner; reject sharedSurface/FileFrame/bootstrap/MMIO/foreign/unmapped/guard/overflow beforeanyIO; capturedfinitefuturecut max1024 beforeanyIO no deadline renewal; Outputcopies512privatebytes beforeIO Inputpublishes512privatebytes onlyafterfixed256IO; IF0 fixed256instructions noallocation/noDMA/noNewMapping/noPidLookup/noVAauthority/noPartitionPolicy; successstatus0value0cap0serial0 errorsalloutputs0; negotiationbeforeuse olderprofilesunknown63/64/65; old35/36 Word4/Byte4 andallRootbootstrapABIs unchanged";
pub const PORT_WORDS256_ABI: [u8; 32] = [
    0x2b, 0x60, 0x49, 0xdc, 0x7d, 0xbb, 0x58, 0x26, 0x19, 0x38, 0xd1, 0x45, 0x2e, 0x40, 0xc6, 0x00,
    0x25, 0x08, 0x42, 0x9e, 0xdb, 0x77, 0x49, 0xbb, 0x43, 0xbe, 0xbc, 0x5e, 0x7a, 0x6c, 0xec, 0x1d,
];

#[cfg(test)]
mod words256_tests {
    use super::*;
    #[test]
    fn sector_words_are_fixed_width_and_additive_to_every_prior_port_operation() {
        assert_eq!(
            [
                PORT_INPUT_WORDS256,
                PORT_OUTPUT_WORDS256,
                PORT_WORDS256_INFO
            ],
            [63, 64, 65]
        );
        assert_eq!(PORT_WORDS256_V1 >> 32, 1);
        assert_eq!((PORT_WORDS256_V1 >> 16) & 0xffff, 256);
        assert_eq!(PORT_WORDS256_V1 & 0xffff, 2);
        assert_eq!(PORT_WORDS256_BYTES, PORT_WORDS256_COUNT * 2);
        assert_eq!(PORT_WORDS256_MAX_PAGES, 2);
        assert_eq!(PORT_WORDS256_MAX_TICKS, 1024);
        assert_eq!(
            [
                PORT_INPUT,
                PORT_OUTPUT,
                PORT_BATCH_INFO,
                PORT_INPUT_WORDS4,
                PORT_OUTPUT_WORDS4,
                PORT_BYTE_BATCH_INFO,
                PORT_INPUT_BYTES4,
                PORT_OUTPUT_BYTES4
            ],
            [35, 36, 46, 47, 48, 49, 50, 51]
        );
        assert_ne!(PORT_WORDS256_V1, PORT_BATCH_V1);
        assert_ne!(PORT_WORDS256_ABI, PORT_BATCH_ABI);
        assert_ne!(PORT_WORDS256_ABI, PORT_BYTE_BATCH_ABI);
    }
}

#[cfg(test)]
mod byte_batch_tests {
    use super::*;
    #[test]
    fn byte_batch_is_additive_to_word_scalar_and_dynamic_control_numbers() {
        assert_eq!(
            [
                PORT_INPUT,
                PORT_OUTPUT,
                PORT_BATCH_INFO,
                PORT_INPUT_WORDS4,
                PORT_OUTPUT_WORDS4,
                PORT_BYTE_BATCH_INFO,
                PORT_INPUT_BYTES4,
                PORT_OUTPUT_BYTES4,
                IMAGE_CONTROL
            ],
            [35, 36, 46, 47, 48, 49, 50, 51, 52]
        );
        assert_eq!(PORT_BATCH_V1, 0x0000_0001_0004_0002);
        assert_eq!(PORT_BYTE_BATCH_V1, 0x0000_0001_0004_0001);
        assert_ne!(PORT_BATCH_ABI, PORT_BYTE_BATCH_ABI);
    }
}
