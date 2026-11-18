#![no_std]
#![no_main]

#[cfg(any(feature = "test-m3-pio-write", feature = "test-m3-pio-verify"))]
mod block_runtime;
#[cfg(any(feature = "test-m3-pio-write", feature = "test-m3-pio-verify"))]
mod block_transport_runtime;
mod bootstrap_proof;
mod cap_runtime;
mod capabilities;
mod custodian_runtime;
#[cfg(feature = "test-m4-desktop")]
mod desktop_runtime;
#[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
mod display_runtime;
mod executable_runtime;
mod firmware;
#[cfg(any(feature = "test-m4-display", feature = "test-m4-desktop"))]
mod graphics_image;
#[cfg(feature = "test-m4-display")]
mod graphics_runtime;
#[cfg(feature = "test-m5-ipc-bench")]
mod ipc_bench_observation;
mod ipc_discipline_runtime;
mod messaging;
#[cfg(feature = "test-m5-native")]
mod native_runtime;
mod paging;
#[cfg(any(
    feature = "test-m3-pio-write",
    feature = "test-m3-pio-verify",
    feature = "test-m4-desktop"
))]
mod port_io;
mod preempt;
#[cfg(feature = "test-m5-provider")]
mod provider_observation;
#[cfg(any(feature = "test-m5-provider", feature = "test-m5-ipc-bench"))]
mod provider_runtime;
mod scheduling;
mod serial;
mod service_restart;
mod service_runtime;
#[cfg(feature = "test-m6-session")]
mod session_log;
mod smp;
mod supervisor_runtime;
mod threads;
mod timer;
mod traps;
mod user_runtime;
mod user_space;
#[cfg(feature = "test-m8-workspace")]
#[allow(dead_code)] // Mechanism-only builds typecheck this separate gated runner.
mod workspace_runtime;

use core::fmt::Write;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};
use ev_boot_contract::{BootError, BootInfoV0};
use ev_kernel::memory::{BootstrapFrames, FRAME_SIZE};
use ev_test_protocol as protocol;

const BUILD_ID: &str = match option_env!("EVROSION_BUILD_ID") {
    Some(id) => id,
    None => "unrecorded",
};
#[cfg(feature = "test-m5-native")]
const SOURCE_SHA256: &str = match option_env!("EVROSION_SOURCE_SHA256") {
    Some(value) => value,
    None => "unrecorded-native-source",
};
ev_boot_contract::entry_point!(crate::evrosion_kernel_entry);

#[cfg(feature = "test-m6-session")]
fn session_observation(
    serial: &mut impl Write,
    retained: &mut session_log::Retention,
    observation: &desktop_runtime::Observation,
) {
    use desktop_runtime::Observation;
    let final_record = match observation {
        Observation::NativeMemory(_)
        | Observation::NativeCommonPrefix(_)
        | Observation::SessionUiCounts(_)
        | Observation::SessionWindowPadding(_) => true,
        #[cfg(feature = "test-m6-network")]
        Observation::StartupPhase(_) | Observation::StartupPhaseCounts { .. } => true,
        #[cfg(feature = "test-m6-network")]
        Observation::StartupCpu(_) | Observation::StartupCpuCounts { .. } => true,
        Observation::NativeState(event) => {
            event.snapshot.operation.name() == "finish" && event.snapshot.result.name() == "ok"
        }
        #[cfg(feature = "test-m6-network")]
        Observation::SessionDynamicImage(event) => event.op == 0,
        _ => false,
    };
    let mut measure = session_log::Measure::default();
    desktop_observation(&mut measure, observation);
    let bytes = measure
        .finish()
        .expect("complete bounded session observation");
    match retained
        .record(bytes, final_record)
        .expect("checked session retention accounting")
    {
        session_log::Decision::Emit => desktop_observation(serial, observation),
        session_log::Decision::FirstOmission => {
            writeln!(serial, "EVROSION_M6_LOG_BOUND protocol=1 build={BUILD_ID} observation={} retained={} detail_bytes={}",retained.observed,retained.retained,retained.detail_bytes).expect("one complete session log boundary");
        }
        session_log::Decision::Omit => {}
    }
}

#[cfg(feature = "test-m4-desktop")]
fn desktop_observation(serial: &mut impl Write, observation: &desktop_runtime::Observation) {
    match observation {
        desktop_runtime::Observation::Step(step) => {
            let stage = match step.kind {
                desktop_runtime::StepKind::Frame => "frame",
                desktop_runtime::StepKind::PickerReady => "picker_ready",
                desktop_runtime::StepKind::PickerHeld => "picker_held",
            };
            let producer = match step.producer {
                desktop_runtime::Producer::App => "app",
                desktop_runtime::Producer::Shell => "shell",
            };
            write!(serial, "EVROSION_M4_DESKTOP_STEP protocol=1 build={BUILD_ID} step={stage} frame={} width={} height={} app_process={} shell_process={} display_process={} grants={} producer={producer} surface_sha256=", step.frame, step.width, step.height, step.app_process, step.shell_process, step.display_process, step.grants).expect("bounded actual desktop step");
            for byte in step.surface_sha256 {
                write!(serial, "{byte:02x}").expect("bounded actual desktop surface digest");
            }
            writeln!(serial, " held_ticks={}", step.held_ticks)
                .expect("complete actual desktop step");
        }
        desktop_runtime::Observation::Lifecycle(event) => {
            let actor = match event.actor {
                desktop_runtime::Producer::App => "app",
                desktop_runtime::Producer::Shell => "shell",
            };
            let (kind, vector, error, address) = match event.fault {
                Some(record) => {
                    assert_eq!(
                        (record.process, record.thread),
                        (event.process, event.thread)
                    );
                    ("fault", record.vector, record.error, record.address)
                }
                None => ("restart", 0, 0, 0),
            };
            writeln!(serial, "EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={BUILD_ID} event={kind} actor={actor} process={} thread={} replacement={} display_process={} grants={} vector={vector} error={error} address={address}", event.process, event.thread, event.replacement, event.display_process, event.grants).expect("bounded actual desktop lifecycle");
        }
        desktop_runtime::Observation::VoluntaryExit(event) => {
            writeln!(serial, "EVROSION_M4_DESKTOP_EXIT protocol=1 build={BUILD_ID} actor=app process={} thread={} code={} instruction={} calls={} replies={}", event.process, event.thread, event.code, event.instruction, event.calls, event.replies).expect("bounded actual desktop voluntary exit");
        }

        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeState(event) => {
            let snapshot = event.snapshot;
            write!(serial,"EVROSION_NATIVE_STATE protocol=1 build={BUILD_ID} report={} op={} result={} installed={} active={} staged={} previous={} process={} thread={} revision={} data_epoch={} data_counter={} value={} mutations={} recovery={} actual_process={} actual_thread={} actual_image_sha256=",
                event.report,snapshot.operation.name(),snapshot.result.name(),u8::from(snapshot.installed),
                snapshot.active.name(),snapshot.staged.name(),snapshot.previous.name(),snapshot.process,
                snapshot.thread,snapshot.revision,snapshot.data_epoch,snapshot.data_counter,snapshot.value,
                snapshot.mutations,u8::from(snapshot.recovery),event.actual_process,event.actual_thread)
                .expect("bounded complete Native state report");
            for byte in event.actual_image_sha256 {
                write!(serial, "{byte:02x}").expect("actual Native report image digest");
            }
            writeln!(serial, " identity_matches={}", event.identity_matches)
                .expect("complete framed Native state diagnostic");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionRpc(event) => {
            let phase = match event.phase {
                desktop_runtime::SessionRpcPhase::Accepted => "accepted",
                desktop_runtime::SessionRpcPhase::Completed => "completed",
                desktop_runtime::SessionRpcPhase::Terminal => "terminal",
                desktop_runtime::SessionRpcPhase::Quiescent => "quiescent",
            };
            writeln!(serial, "EVROSION_M6_RPC protocol=1 build={BUILD_ID} phase={phase} call_epoch={} call={} caller_process={} caller_thread={} callee_process={} callee_thread={} endpoint={} request={:016x} started={} tick={} deadline={} status={} callee_cpu={} scheduler_tick={} quota={} period={} window_start={} window_end={} used={} reserved={} remaining={}", event.call_epoch,event.call,event.caller_process,event.caller_thread,event.callee_process,event.callee_thread,event.endpoint,event.request,event.started,event.tick,event.deadline,event.status,event.callee_cpu,event.scheduler_tick,event.budget.quota_ticks,event.budget.period_ticks,event.budget.window_start,event.budget.window_end,event.budget.consumed_ticks,event.budget.reserved_ticks,event.budget.remaining_ticks).expect("bounded actual session RPC trace");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionAsyncExpiry(event) => {
            writeln!(serial, "EVROSION_M6_ASYNC_EXPIRED protocol=1 build={BUILD_ID} sequence={} endpoint={} ticket={} sender_process={} sender_thread={} receiver_process={} receiver_thread={} deadline={} tick={} value={:016x}", event.sequence,event.endpoint,event.ticket,event.sender_process,event.sender_thread,event.receiver_process,event.receiver_thread,event.deadline,event.tick,event.value).expect("bounded queued scalar expiry observation");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionBarrier(event) => {
            writeln!(serial, "EVROSION_M6_BARRIER protocol=1 build={BUILD_ID} count={} call_epoch={} call={} endpoint={} caller_process={} caller_thread={} callee_process={} callee_thread={} frame={} sequence={} flags={} buttons={} request={:016x} reply={:016x} tick={}", event.count,event.call_epoch,event.call,event.endpoint,event.caller_process,event.caller_thread,event.callee_process,event.callee_thread,event.frame,event.sequence,event.flags,event.buttons,event.request,event.reply,event.tick).expect("bounded matched session barrier observation");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionCursor(event) => {
            writeln!(serial, "EVROSION_M6_CURSOR protocol=1 build={BUILD_ID} count={} call_epoch={} call={} endpoint={} caller_process={} caller_thread={} callee_process={} callee_thread={} x={} y={} sequence={} request={:016x} reply={:016x} tick={}", event.count,event.call_epoch,event.call,event.endpoint,event.caller_process,event.caller_thread,event.callee_process,event.callee_thread,event.x,event.y,event.sequence,event.request,event.reply,event.tick).expect("bounded matched session cursor observation");
        }
        #[cfg(feature = "test-m7-document-observe")]
        desktop_runtime::Observation::Document(event) => {
            write!(serial,"EVROSION_M7_DOCUMENT protocol=1 build={BUILD_ID} process={} thread={} endpoint={} ticket={} nonce={} tick={} frame={} bytes=",event.process,event.thread,event.endpoint,event.ticket,event.nonce,event.tick,event.frame).expect("bounded actual document observation");
            for byte in event.bytes {
                write!(serial, "{byte:02x}").expect("document byte");
            }
            writeln!(serial).expect("document record");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionNote(event) => {
            let phase = match event.phase {
                desktop_runtime::SessionNotePhase::Request => "request",
                desktop_runtime::SessionNotePhase::Accepted => "accepted",
                desktop_runtime::SessionNotePhase::Delivered => "delivered",
            };
            writeln!(serial, "EVROSION_M6_NOTE protocol=1 build={BUILD_ID} phase={phase} count={} endpoint={} ticket={} sender_process={} sender_thread={} receiver_process={} receiver_thread={} nonce={} opcode={} message={:016x} tick={}", event.count,event.endpoint,event.ticket,event.sender_process,event.sender_thread,event.receiver_process,event.receiver_thread,event.nonce,event.opcode,event.message,event.tick).expect("bounded actual session Note delivery observation");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionUiCounts(event) => {
            writeln!(serial, "EVROSION_M6_UI_COUNTS protocol=1 build={BUILD_ID} phase={} barriers={} cursors={} note_requests={} note_accepted={} note_delivered={}", event.phase,event.barriers,event.cursors,event.note_requests,event.note_accepted,event.note_delivered).expect("actual cumulative session UI counts");
        }
        #[cfg(feature = "test-m6-session")]
        desktop_runtime::Observation::SessionWindowPadding(event) => {
            writeln!(serial, "EVROSION_M6_WINDOW_PADDING protocol=1 build={BUILD_ID} start=256 end=4096 nonzero={} first={} status=observed", event.nonzero,event.first).expect("actual untrusted App window padding observation");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionDynamicImage(event) => {
            write!(serial, "EVROSION_M6_IMAGE protocol=1 build={BUILD_ID} op={} slot={} phase={} status={} reason={} process={} thread={} job={} tick={} original_cut={} external_frames={} root_cr3={} table={} control={} declared_bytes={} pages={} verified_bytes={} elf_sha256=", event.op,event.slot,event.phase,event.status,event.reason,event.process,event.thread,event.job,event.tick,event.original_cut,event.external_frames,event.root_cr3,event.table,event.control,event.declared_bytes,event.pages,event.verified_bytes).expect("actual bounded dynamic-image state");
            for byte in event.elf_sha256 {
                write!(serial, "{byte:02x}").expect("verified dynamic ELF digest");
            }
            write!(serial, " content_sha256=").expect("dynamic content digest key");
            for byte in event.content_sha256 {
                write!(serial, "{byte:02x}").expect("verified dynamic content digest");
            }
            write!(serial, " declared_package_id=").expect("declared package identity key");
            for byte in event.declared_package_id {
                write!(serial, "{byte:02x}").expect("declared package identity");
            }
            writeln!(
                serial,
                " returned_memory_capability={}",
                event.returned_memory_capability
            )
            .expect("actual dynamic-image result, not release acceptance");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionNetworkProgress(event) => {
            writeln!(serial,"EVROSION_M6_NETWORK_PROGRESS protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} stage={} result={} argument={}", event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.stage,event.result,event.argument).expect("bounded actually accepted Root network policy diagnostic");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionTimeProgress(event) => {
            writeln!(serial,"EVROSION_M6_TIME_PROGRESS protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} stage={} result={} elapsed_seconds={}", event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.stage,event.result,event.argument).expect("bounded actually accepted Root elapsed diagnostic, not UTC qualification");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionUpdateProgress(event) => {
            writeln!(serial,"EVROSION_M6_UPDATE_PROGRESS protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} stage={} result={} progress={}", event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.stage,event.result,event.argument).expect("actual local preparation progress, not UTC/release/health authority");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionRpcRejection(event) => {
            writeln!(serial,"EVROSION_M6_RPC_REJECTION protocol=1 build={BUILD_ID} actor={} process={} thread={} capability={} wire={} endpoint={} deadline={} tick={} branch={} reason={} detail={} parent_call={} parent_deadline={} parent_delivered={}", event.actor,event.process,event.thread,event.capability,event.wire,event.endpoint,event.deadline,event.tick,event.branch,event.reason,event.detail,event.parent_call,event.parent_deadline,event.parent_delivered).expect("actual bounded RPC rejection provenance, not retry or quiescence authority");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionTimeExchange(event) => {
            writeln!(serial,"EVROSION_M6_TIME_EXCHANGE protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} phase={} tcp={} calls={} error={} detail={}", event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.phase,event.tcp,event.calls,event.error,event.detail).expect("actual bounded private exchange failure snapshot");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionRestart(event) => {
            writeln!(serial,"EVROSION_M6_RESTART protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} mode={} generation={}",event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.mode,event.generation).expect("actual Root restart intent, not successful cleanup or power authority");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionTimeCheck(event) => {
            writeln!(serial,"EVROSION_M6_TIME_CHECK protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} stage={} result={} elapsed_seconds={} utc=unqualified", event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.stage,event.result,event.argument).expect("fresh elapsed/anchor diagnostic, not qualified UTC");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionTimeProof(event) => {
            writeln!(serial,"EVROSION_M6_TIME_PROOF protocol=1 build={BUILD_ID} root_process={} root_thread={} endpoint={} ticket={} tick={} stage={} result={} argument={} utc=unqualified", event.root_process,event.root_thread,event.endpoint,event.ticket,event.tick,event.stage,event.result,event.argument).expect("actual Root private proof diagnostic, never qualified UTC");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionNetworkError(event) => {
            let actor = match event.actor {
                0 => "root",
                7 => "net_driver",
                8 => "net_service",
                _ => unreachable!("actual accepted network diagnostic sender"),
            };
            writeln!(serial,"EVROSION_M6_NETWORK_ERROR protocol=1 build={BUILD_ID} actor={actor} process={} thread={} endpoint={} ticket={} tick={} layer={} operation={} class={} detail={} subdetail={} progress={}",event.process,event.thread,event.endpoint,event.ticket,event.tick,event.layer,event.operation,event.class,event.detail,event.subdetail,event.progress).expect("actual sender network error diagnostic, not quiescence");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionNetworkExit(event) => {
            let actor = match event.actor {
                7 => "net_driver",
                8 => "net_service",
                _ => panic!("actual optional network actor index"),
            };
            writeln!(serial, "EVROSION_M6_NETWORK_EXIT protocol=1 build={BUILD_ID} actor={actor} process={} thread={} code={} instruction={} tick={} calls={} replies={} hardware_quiescence=unproved",event.process,event.thread,event.code,event.instruction,event.tick,event.calls,event.replies).expect("actual optional network CPU exit, not device quiescence");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::SessionDownloadedAction(event) => {
            let action = match event.kind {
                desktop_runtime::NativeActionKind::Start => "start",
                desktop_runtime::NativeActionKind::Stop => "stop",
                desktop_runtime::NativeActionKind::Reap => "reap",
            };
            write!(serial,"EVROSION_M6_DOWNLOADED_ACTION protocol=1 build={BUILD_ID} action={action} slot={} process={} thread={} job={} elf_sha256=",event.slot,event.process,event.thread,event.job).expect("actual downloaded action");
            for byte in event.elf_sha256 {
                write!(serial, "{byte:02x}").expect("actual sealed ELF");
            }
            write!(serial, " content_sha256=").expect("downloaded content key");
            for byte in event.content_sha256 {
                write!(serial, "{byte:02x}").expect("actual sealed content");
            }
            write!(serial, " declared_package_id=").expect("declared downloaded package key");
            for byte in event.declared_package_id {
                write!(serial, "{byte:02x}").expect("declared package identity");
            }
            writeln!(serial).expect("complete downloaded action");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeAction(event) => {
            let action = match event.kind {
                desktop_runtime::NativeActionKind::Start => "start",
                desktop_runtime::NativeActionKind::Stop => "stop",
                desktop_runtime::NativeActionKind::Reap => "reap",
            };
            write!(serial, "EVROSION_M5_NATIVE_ACTION protocol=1 build={BUILD_ID} action={action} process={} thread={} image_sha256=",event.process,event.thread).expect("bounded native action");
            for byte in event.image_sha256 {
                write!(serial, "{byte:02x}").expect("native actual image digest");
            }
            writeln!(serial).expect("complete native action");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeCrash(event) => {
            native_diagnostic(serial, "CRASH", event);
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeJob(event) => {
            native_diagnostic(serial, "JOB", event);
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeSystem(event) => {
            native_diagnostic(serial, "SYSTEM", event);
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::StartupPhase(event) => {
            writeln!(serial,"EVROSION_M6_STARTUP_PHASE protocol=1 build={BUILD_ID} phase={} wire={} tick={} process={} thread={} peer_process={} peer_thread={} endpoint={} ticket={} call_epoch={} call={} value={:016x}",event.phase,event.wire,event.tick,event.process,event.thread,event.peer_process,event.peer_thread,event.endpoint,event.ticket,event.call_epoch,event.call,event.value).expect("bounded retained actual startup phase");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::StartupCpu(event) => {
            write!(serial,"EVROSION_M6_STARTUP_CPU protocol=1 build={BUILD_ID} phase={} tick={} process={} thread={} app_job={} ticket={} call_epoch={} call={}",event.phase,event.tick,event.process,event.thread,event.job,event.ticket,event.call_epoch,event.call).expect("bounded two-point CPU identity");
            if let Some(cpu) = event.sample {
                writeln!(serial," cpu_valid=true sampled_job={} app_charged_cpu={} scheduler_tick={} quota={} period={} window_start={} window_end={} consumed={} reserved={} remaining={}",cpu.job,cpu.charged,cpu.scheduler_tick,cpu.budget.quota_ticks,cpu.budget.period_ticks,cpu.budget.window_start,cpu.budget.window_end,cpu.budget.consumed_ticks,cpu.budget.reserved_ticks,cpu.budget.remaining_ticks).expect("bounded actual App Job sampled CPU facts");
            } else {
                writeln!(serial, " cpu_valid=false").expect("explicit unavailable CPU facts");
            }
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::StartupCpuCounts {
            observed,
            retained,
            duplicates,
            overflow,
        } => {
            writeln!(serial,"EVROSION_M6_STARTUP_CPU_COUNTS protocol=1 build={BUILD_ID} capacity={} observed={observed} retained={retained} duplicates={duplicates} overflow={overflow} closed=true",ev_kernel::startup_trace::CPU_CAPACITY).expect("bounded two-point CPU counts");
        }
        #[cfg(feature = "test-m6-network")]
        desktop_runtime::Observation::StartupPhaseCounts {
            observed,
            retained,
            overflow,
        } => {
            writeln!(serial,"EVROSION_M6_STARTUP_PHASE_COUNTS protocol=1 build={BUILD_ID} capacity={} observed={observed} retained={retained} overflow={overflow} closed=true",ev_kernel::startup_trace::CAPACITY).expect("bounded retained startup counts");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeMemory(event) => {
            let phase = match event.phase {
                desktop_runtime::NativeMemoryPhase::Before => "before",
                desktop_runtime::NativeMemoryPhase::Held => "held",
                desktop_runtime::NativeMemoryPhase::After => "after",
            };
            writeln!(serial,"EVROSION_M5_NATIVE_MEMORY protocol=1 build={BUILD_ID} phase={phase} total_frames={} remaining_frames={}",event.total_frames,event.remaining_frames).expect("actual bootstrap arena snapshot");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeCriticalReady(event) => {
            write!(serial,"EVROSION_M5_NATIVE_CRITICAL_READY protocol=1 build={BUILD_ID} process={} thread={} image_sha256=",event.process,event.thread).expect("actual critical Ready");
            for byte in event.image_sha256 {
                write!(serial, "{byte:02x}").expect("actual critical image");
            }
            writeln!(serial, " tick={}", event.tick).expect("actual critical acceptance tick");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeCommonPrefix(event) => {
            write!(serial,"EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={BUILD_ID} mode={} root_process={} root_thread={} root_image_sha256=",event.mode,event.root_process,event.root_thread).expect("actual common Root prefix");
            for byte in event.root_image_sha256 {
                write!(serial, "{byte:02x}").expect("actual common Root image");
            }
            write!(
                serial,
                " root_epoch={} root_incarnation={} root_manifest_sha256=",
                event.root_epoch, event.root_incarnation
            )
            .expect("actual common Root binding");
            for byte in event.root_manifest_sha256 {
                write!(serial, "{byte:02x}").expect("actual common Root manifest");
            }
            write!(
                serial,
                " block_process={} block_thread={} block_image_sha256=",
                event.block_process, event.block_thread
            )
            .expect("actual common Block prefix");
            for byte in event.block_image_sha256 {
                write!(serial, "{byte:02x}").expect("actual common Block image");
            }
            writeln!(
                serial,
                " system_endpoint={} root_frames={} block_frames={}",
                event.system_endpoint, event.root_frames, event.block_frames
            )
            .expect("complete actual preselection prefix");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeSelfIdentity(event) => {
            write!(serial,"EVROSION_M5_NATIVE_SELF_IDENTITY protocol=1 build={BUILD_ID} sequence={} process={} thread={} root_epoch={} root_incarnation={} root_manifest_sha256=",event.sequence,event.process,event.thread,event.root_epoch,event.root_incarnation).expect("actual Root self query");
            for byte in event.root_manifest_sha256 {
                write!(serial, "{byte:02x}").expect("actual Root self manifest");
            }
            writeln!(serial, " tick={}", event.tick).expect("actual Root liveness tick");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeOwnerPrompt(event) => {
            let prompt = ev_diagnostics::owner::Prompt::decode(&event.bytes)
                .expect("validated actual owner prompt");
            native_diagnostic(serial, "OWNER_PROMPT", event);
            let mut text = OwnerText {
                output: serial,
                report: event.report,
                line: 0,
                beginning: true,
            };
            prompt
                .write(&mut text)
                .expect("canonical actual owner UART output");
            assert!(text.beginning, "owner prompt ends on a complete line");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeManagedRead(event) => {
            write!(serial,"EVROSION_M5_NATIVE_MANAGED_READ protocol=1 build={BUILD_ID} root_process={} root_thread={} process={} thread={} image_sha256=",event.root_process,event.root_thread,event.process,event.thread).expect("actual managed read origin");
            for byte in event.image_sha256 {
                write!(serial, "{byte:02x}").expect("managed read actual image");
            }
            writeln!(
                serial,
                " source_endpoint={} inbox_endpoint={} nonce={} ticket={}",
                event.source_endpoint, event.inbox_endpoint, event.nonce, event.ticket
            )
            .expect("actual accepted managed read");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeInhibit(event) => {
            write!(serial,"EVROSION_M5_NATIVE_INHIBIT protocol=1 build={BUILD_ID} root_process={} root_thread={} process={} thread={} image_sha256=",event.root_process,event.root_thread,event.process,event.thread).expect("actual inhibit origin");
            for byte in event.image_sha256 {
                write!(serial, "{byte:02x}").expect("inhibited actual image");
            }
            writeln!(serial, " outbound_pending={}", event.outbound_pending)
                .expect("actual dispatch inhibition");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeFault(event) => {
            write!(
                serial,
                "EVROSION_NATIVE_FAULT protocol=1 build={BUILD_ID} actor={} image_sha256=",
                event.actor
            )
            .expect("native actual fault envelope");
            for byte in event.image_sha256 {
                write!(serial, "{byte:02x}").expect("native fault image");
            }
            write!(
                serial,
                " root_epoch={} root_incarnation={} words=",
                event.root_epoch, event.root_incarnation
            )
            .expect("native fault fields");
            for (i, word) in event.words.iter().enumerate() {
                if i != 0 {
                    write!(serial, ",").expect("native fault delimiter");
                }
                write!(serial, "{word}").expect("native fault word");
            }
            writeln!(serial).expect("native complete actual fault");
        }
        #[cfg(feature = "test-m5-native")]
        desktop_runtime::Observation::NativeJobField(event) => {
            writeln!(serial,"EVROSION_NATIVE_JOB_FIELD protocol=1 build={BUILD_ID} sequence={} root_process={} root_thread={} capability={} field={} value={} tick={} status={} denial={}", event.sequence,event.root_process,event.root_thread,event.capability,event.field,event.value,event.tick,event.status,event.denial).expect("bounded native actual Job query");
        }
    }
}

/// Prefix each canonical prompt line without a buffer or competing user UART
/// writer. The complete callback runs under the existing captured IF0 owner.
#[cfg(feature = "test-m5-native")]
struct OwnerText<'a, W: core::fmt::Write> {
    output: &'a mut W,
    report: u32,
    line: u32,
    beginning: bool,
}
#[cfg(feature = "test-m5-native")]
impl<W: core::fmt::Write> core::fmt::Write for OwnerText<'_, W> {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        for part in value.split_inclusive('\n') {
            if self.beginning {
                assert!(self.line < 32, "finite owner prompt lines");
                write!(
                    self.output,
                    "EVROSION_NATIVE_OWNER_TEXT protocol=1 build={BUILD_ID} report={} line={} text=",
                    self.report, self.line
                )?;
                self.beginning = false;
            }
            self.output.write_str(part)?;
            if part.ends_with('\n') {
                self.line += 1;
                self.beginning = true;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "test-m5-native")]
fn native_diagnostic<const N: usize>(
    serial: &mut impl core::fmt::Write,
    kind: &str,
    event: &desktop_runtime::NativeDiagnostic<N>,
) {
    write!(serial,"EVROSION_NATIVE_{kind} protocol=1 build={BUILD_ID} report={} root_process={} root_thread={} bytes=",event.report,event.root_process,event.root_thread).expect("bounded authenticated native diagnostic");
    for byte in &event.bytes {
        write!(serial, "{byte:02x}").expect("native diagnostic payload");
    }
    writeln!(serial).expect("complete native diagnostic");
}

/// Keep the consumed map's construction scratch out of the retained runtime
/// frame. The same checked one-time take transfers the sole allocator owner.
#[cfg_attr(
    any(feature = "test-m6-network", feature = "test-m7-document"),
    inline(never)
)]
#[cfg_attr(
    not(any(feature = "test-m6-network", feature = "test-m7-document")),
    inline(always)
)]
fn bootstrap_frames(map: &mut ev_boot_contract::MemoryMap) -> BootstrapFrames {
    BootstrapFrames::new(
        map.take()
            .expect("validated bootstrap map transferred exactly once"),
    )
}

/// First kernel-owned entry, with no loader-specific types. Retained for GDB.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn evrosion_kernel_entry(boot: Result<&mut BootInfoV0, BootError>) -> ! {
    // The desktop observer permits at most 256 checkpoints. The current writer's
    // worst STEP is 448 bytes including CRLF; reserve another 64 * 512 bytes for
    // lifecycle and 16 KiB for preludes/final diagnostics: 160 KiB total, below
    // this finite 256 KiB budget and the unchanged 1 MiB host capture limit.
    // Other profiles keep 8 KiB. This counter allocates no log buffer.
    // Finite Native proofs include at most512 Job query observations. Sustained
    // sessions retain384KiB of complete observations plus64KiB of fixed final
    // snapshots; an explicit omission boundary/summary replaces lifetime log
    // exhaustion. The remaining64KiB covers boot/retirement output. Formatting
    // is measured before emission without allocating a stack log buffer.
    let serial_budget = if cfg!(feature = "test-m5-native") {
        512 * 1024
    } else if cfg!(feature = "test-m4-desktop") {
        256 * 1024
    } else if cfg!(any(
        feature = "test-m5-ipc-bench",
        feature = "test-m5-provider"
    )) {
        32 * 1024
    } else {
        8192
    };
    let mut serial = serial::Serial::initialize(serial_budget);
    let result = (|| -> core::fmt::Result {
        writeln!(
            serial,
            "EVROSION_BOOT protocol={} build={BUILD_ID}",
            protocol::VERSION
        )?;
        let boot = match boot {
            Ok(boot) => boot,
            Err(error) => {
                writeln!(serial, "EVROSION_BOOT_ERROR reason={error:?}")?;
                writeln!(serial, "{}", protocol::FAIL)?;
                finish(false);
            }
        };
        let framebuffer = if cfg!(feature = "test-no-framebuffer") {
            None
        } else {
            boot.framebuffer
        };
        match framebuffer {
            Some(fb) => writeln!(
                serial,
                "EVROSION_FRAMEBUFFER present=true width={} height={} stride={} format={}",
                fb.width,
                fb.height,
                fb.stride,
                fb.format.name()
            )?,
            None => writeln!(
                serial,
                "EVROSION_FRAMEBUFFER present=false width=0 height=0 stride=0 format=none"
            )?,
        }
        writeln!(
            serial,
            "EVROSION_MEMORY regions={} usable_bytes={}",
            boot.memory.regions().len(),
            boot.memory.usable_bytes()
        )?;
        writeln!(serial, "{}", protocol::ENTERED)?;
        if cfg!(feature = "test-panic") {
            evrosion_deliberate_panic();
        }
        // Boot has one mutable allocator owner, interrupts disabled, and no APs.
        // These frames are only claimed: no physical address is dereferenced.
        let mut frames = bootstrap_frames(&mut boot.memory);
        let first = frames.allocate().expect("bootstrap needs a first frame");
        let second = frames.allocate().expect("bootstrap needs a second frame");
        assert!(first.start() < second.start());
        for frame in [&first, &second] {
            assert_eq!(frame.start() % FRAME_SIZE, 0);
            assert!(frame.start() >= FRAME_SIZE);
            assert!(
                frame.start() + FRAME_SIZE <= boot.kernel_physical_range.start
                    || frame.start() >= boot.kernel_physical_range.end
            );
        }
        writeln!(
            serial,
            "EVROSION_M1_BOOTSTRAP status=PASS page_size={} allocated=2 total={} remaining={} first={:#x} second={:#x}",
            FRAME_SIZE,
            frames.total_frames(),
            frames.remaining_frames(),
            first.start(),
            second.start()
        )?;
        let offset = boot
            .physical_memory_offset
            .expect("M1 requires the bootstrap direct map");
        // SAFETY: sole ring-0 boot CPU, interrupts disabled by the adapter. The
        // validated loader contract supplies a writable physical offset mapping;
        // reserved loader pages and all allocator claims remain retained.
        let proof = unsafe {
            traps::install();
            if cfg!(feature = "test-unexpected-fault") {
                // Deliberately unarmed invalid opcode: must report failure and
                // halt through the owned exception entry, never resume.
                core::arch::asm!("ud2", options(noreturn));
            }
            paging::prove(offset, &mut frames)
        };
        writeln!(
            serial,
            "EVROSION_M1_PAGING status=PASS roots=2 map_unmap=true remap=true zeroed=true permissions=true restored=true root_a={:#x} root_b={:#x} virtual={:#x}",
            proof.root_a, proof.root_b, proof.virtual_address
        )?;
        writeln!(
            serial,
            "EVROSION_M1_FAULTS status=PASS readonly=true noexecute=true unmapped=true recovered={}",
            proof.faults
        )?;
        // SAFETY: same sole-CPU bootstrap state and retained mappings as above;
        // owned exception tables and paging mode checks have completed.
        let user = unsafe { user_space::prove(offset, &mut frames) };
        writeln!(
            serial,
            "EVROSION_M1_USER status=PASS roots=2 cpl=3 private=true kernel_denied=true wx=true stack=true io_denied=true traps={} root_a={:#x} root_b={:#x}",
            user.traps, user.roots[0], user.roots[1]
        )?;
        // SAFETY: sole Q35 bootstrap CPU, owned IDT, no other driver or AP;
        // all previous proofs restored IF=0 and original kernel mappings.
        let time = unsafe { timer::prove() };
        writeln!(
            serial,
            "EVROSION_M1_TIMER status=PASS ticks={} deadline={} masked_bound=true interrupts_off=true",
            time.ticks, time.deadline
        )?;
        // SAFETY: firmware tables remain reserved and the trusted loader direct
        // map is retained. Discovery validates every table before interpretation.
        let topology = unsafe {
            firmware::discover(
                offset,
                boot.acpi_rsdp.expect("ACPI RSDP required for CPU topology"),
                &frames,
            )
        }
        .expect("valid firmware CPU topology");
        writeln!(
            serial,
            "EVROSION_M1_TOPOLOGY status=PASS enabled={} bsp={} lapic={:#x}",
            topology.topology.cpus().len(),
            topology.bsp,
            topology.topology.lapic
        )?;
        // SAFETY: BSP bootstrap proofs finished with IF off; all frames remain
        // retained. The new AP uses private entry state and parks before return.
        match unsafe { smp::prove(offset, &topology.topology, topology.bsp, &mut frames) } {
            Some(proof) => writeln!(
                serial,
                "EVROSION_M1_SMP status=PASS online=2 ap={} root={:#x} shared={} parked=true",
                proof.ap, proof.root, proof.count
            )?,
            None => writeln!(serial, "EVROSION_M1_SMP status=SKIP reason=single_cpu")?,
        }
        let dispatches = scheduling::prove();
        writeln!(
            serial,
            "EVROSION_M1_SCHEDULER status=PASS scope=policy threads=2 jobs=2 dispatches={dispatches} signal=true deadline=true stale_rejected=true"
        )?;
        // SAFETY: BSP with IF=0 and AP parked; allocator and loader maps retained.
        let threads = unsafe { threads::prove(offset, &mut frames) };
        writeln!(
            serial,
            "EVROSION_M1_THREADS status=PASS threads=2 dispatches={} switches={} guards={} registers=true stacks=true signal=true deadline=true exited=true",
            threads.dispatches, threads.switches, threads.guards
        )?;
        // SAFETY: BSP, prior contexts exited, AP parked and IRQ0 initialized.
        let preempt = unsafe { preempt::prove(offset, &mut frames) };
        writeln!(
            serial,
            "EVROSION_M1_PREEMPT status=PASS threads=2 quanta={} dispatches={} progress=true restored=true",
            preempt.quanta, preempt.dispatches
        )?;
        capabilities::prove();
        writeln!(
            serial,
            "EVROSION_M1_CAPS status=PASS scope=tables attenuation=true transfer=true revocation=true stale=true denial=true lifetime=true"
        )?;
        messaging::prove();
        writeln!(
            serial,
            "EVROSION_M1_IPC status=PASS scope=mailbox bounded=true escrow=true delivery=true deadline=true death_return=true"
        )?;
        bootstrap_proof::prove();
        writeln!(
            serial,
            "EVROSION_M2_BINDING status=PASS scope=fixture grants=2 measured=true resolved=true atomic=true attenuated=true revoked=true"
        )?;
        writeln!(
            serial,
            "EVROSION_M2_LIFETIME status=PASS scope=authority cycles=64 reclaimed=128 old_space_denied=true stale_handles_denied=true"
        )?;
        bootstrap_proof::prove_scopes();
        writeln!(
            serial,
            "EVROSION_M2_SCOPES status=PASS scope=authority cycles=64 revoked=128 roots_preserved=true peers_preserved=true stale_revoke_denied=true"
        )?;
        bootstrap_proof::prove_incarnation();
        writeln!(
            serial,
            "EVROSION_M2_INCARNATION status=PASS scope=prepared bindings=2 held=true stale_events_denied=true limits=true revoked=true"
        )?;
        // SAFETY: BSP IF=0, AP parked; retained roots and initialized IRQ/TSS.
        let runtime = unsafe { user_runtime::prove(offset, &mut frames) };
        #[cfg(feature = "test-m8-workspace-run")]
        if cfg!(feature = "test-m8-workspace-run") {
            let assets = workspace_runtime::embedded_assets();
            writeln!(
                serial,
                "EVROSION_M8_KERNEL_RUN phase=selected build={BUILD_ID} actual_bundle=true legacy_root_cast=false"
            )?;
            // SAFETY: primitive user/FX/trap/timer proofs restored controller
            // CR3/IF0, APs parked; actual V5 inputs and allocator remain retained.
            let proof = unsafe {
                workspace_runtime::run(
                    offset,
                    &mut frames,
                    framebuffer.expect("V5 actual GOP framebuffer"),
                    &assets,
                    2_000_000,
                    &mut serial,
                )
            };
            writeln!(
                serial,
                "EVROSION_M8_KERNEL_RUN phase=ended root_exited={} starts={} calls={} replies={} retained={} scope=execution_only clean_shutdown={}",
                proof.root_exited,
                proof.starts,
                proof.calls,
                proof.replies,
                proof.retained,
                proof.checked_shutdown
            )?;
            // Retained sources are deliberately not a normal-cleanup or
            // recovery PASS. Qualification must inspect actual earlier events.
            if proof.checked_restart {
                writeln!(
                    serial,
                    "EVROSION_M8_SESSION_POWER phase=platform_restart_requested adapter=q35_ich9 port=0x0cf9 value=0x0f actual_second_boot_required=true"
                )?;
                reference_q35_restart();
            }
            finish(proof.checked_shutdown);
        }
        // Keep M1's allocator-start assumptions stable. The independent loader
        // proof reuses and returns frames only after M1 has captured its counts.
        // SAFETY: initialized user boundary, NX/WP and retained direct map;
        // BSP IF=0, AP parked and exclusive bootstrap frames.
        unsafe {
            executable_runtime::prove(offset, &mut frames);
        }
        writeln!(
            serial,
            "EVROSION_M2_EXECUTABLE status=PASS scope=loader segments=2 pages=5 frames=9 cpl3=5 measured=true zeroed=true wx=true guarded=true reclaimed=true"
        )?;
        // SAFETY: M1 and loader probes returned; controller owns original CR3,
        // IF=0, parked AP and all allocator/authority/scheduler transitions.
        unsafe {
            executable_runtime::prove_activation(offset, &mut frames);
        }
        writeln!(
            serial,
            "EVROSION_M2_ACTIVATION status=PASS scope=fixture attempts=2 admitted=1 rejected=1 cpl3=1 rechecked=true stale_denied=true inhibited=true peers_preserved=true frames=18 reclaimed=true"
        )?;
        // SAFETY: initialized ordinary user boundary, controller CR3/IF=0,
        // parked AP and exclusive frames. Each case fully retires before return.
        unsafe {
            supervisor_runtime::prove(offset, &mut frames);
        }
        writeln!(
            serial,
            "EVROSION_M2_SUPERVISOR status=PASS scope=bootstrap images=2 ready=2 faults=1 denied=4 readonly=true measured=true authority=true stopped=true reclaimed=true"
        )?;
        // SAFETY: prior proofs restored controller CR3 at IF=0; AP parked and
        // frames exclusively owned. This graph retains every executable image.
        unsafe {
            service_runtime::prove(offset, &mut frames);
        }
        writeln!(
            serial,
            "EVROSION_M2_SERVICES status=PASS scope=launch graphs=2 children=2 requests=5 replies=4 cancelled=1 faults=1 control_denied=8 service_denied=8 event_denied=6 delegated=4 observed=true held=true isolated=true measured=true reclaimed=true"
        )?;
        // SAFETY: prior graphs retired at IF=0, original CR3 current, AP parked;
        // the RPC graphs retain their roots and serialize waits with transport.
        let (rpc, rpc_timeout) = unsafe { service_runtime::prove_rpc(offset, &mut frames) };
        assert_eq!(
            (
                rpc.successes,
                rpc.blocks,
                rpc.wakes,
                rpc.denied,
                rpc.expired
            ),
            (3, 3, 3, 1, 1)
        );
        assert_eq!(
            (
                rpc_timeout.successes,
                rpc_timeout.blocks,
                rpc_timeout.wakes,
                rpc_timeout.denied,
                rpc_timeout.expired,
                rpc_timeout.timeouts,
                rpc_timeout.late
            ),
            (4, 5, 5, 1, 1, 1, 1)
        );
        assert!(
            rpc.stale >= 2
                && rpc_timeout.stale >= 2
                && rpc_timeout.busy >= 1
                && rpc.frames_balanced
                && rpc_timeout.frames_balanced
        );
        writeln!(
            serial,
            "EVROSION_M2_RPC status=PASS scope=transport successes=7 accepted=8 blocks=8 wakes=8 denied=2 expired=2 timeouts=1 busy=true late=1 stale=true reclaimed=true"
        )?;
        // SAFETY: prior roots retired; serialized BSP at IF=0, parked AP and
        // exclusive frames. Restart controller retains every image until stop.
        let restart = unsafe { service_restart::prove(offset, &mut frames) };
        assert_eq!(
            (
                restart.restarts,
                restart.faults,
                restart.peer_replies,
                restart.victim_replies,
                restart.starts
            ),
            (64, 64, 128, 64, 66)
        );
        assert!(
            restart.stale > 0
                && restart.frames_balanced
                && restart.metadata_balanced
                && restart.root_preserved
        );
        writeln!(
            serial,
            "EVROSION_M2_RESTART status=PASS scope=service cycles=64 faults=64 peer_replies=128 victim_replies=64 starts=66 stale=true root_preserved=true frames=true metadata=true reclaimed=true"
        )?;
        // SAFETY: previous graphs stopped; serialized BSP/controller CR3,
        // parked AP and exclusive frames. Custody controller retains all owners.
        let custody = unsafe { custodian_runtime::prove(offset, &mut frames) };
        assert_eq!(
            (
                custody.incarnations,
                custody.replacements,
                custody.root_faults,
                custody.graphs
            ),
            (4, 3, 4, 4)
        );
        assert_eq!(
            (
                custody.service_starts,
                custody.service_replies,
                custody.accepted_transfers,
                custody.rejected_transfers,
                custody.invalidated_transfers,
                custody.recovery_entries
            ),
            (8, 8, 4, 4, 4, 1)
        );
        assert!(
            custody.stale > 0
                && custody.frames_balanced
                && custody.metadata_balanced
                && custody.unique_active
                && custody.budget_latched
                && custody.authority_equal
                && custody.graph_retired
                && custody.recovery_independent
        );
        let failed = custody.failed_token.expect("retained failed Root token");
        let fault = custody
            .last_fault
            .expect("retained actual Root fault capsule");
        assert_eq!(failed.number(), 4);
        assert_eq!(fault.process, failed.process().diagnostic_id());
        assert_eq!((fault.vector, fault.error, fault.address), (14, 6, 0));
        assert_eq!(
            custody.recovery_reason,
            Some(ev_kernel::custodian::Recovery::Restart(
                ev_kernel::restart::RecoveryRequired::BudgetExhausted
            ))
        );
        writeln!(
            serial,
            "EVROSION_M2_CUSTODY status=PASS scope=graph incarnations=4 replacements=3 root_faults=4 graphs=4 service_starts=8 service_replies=8 accepted_transfers=4 rejected_transfers=4 invalidated_transfers=4 recovery=1 unique=true authority=true graph=true budget=true stale=true frames=true metadata=true independent=true"
        )?;
        // SAFETY: each explicit failure world retains exclusive controller/
        // allocator ownership and retires fully before the next case begins.
        let negatives = unsafe { custodian_runtime::prove_negatives(offset, &mut frames) };
        assert_eq!(
            (
                negatives.cases,
                negatives.fault_records,
                negatives.fatal_exits,
                negatives.watchdogs,
                negatives.interrupted,
                negatives.integrity_failures
            ),
            (11, 6, 4, 4, 6, 3)
        );
        assert_eq!(
            (
                negatives.attempts,
                negatives.restart_charges,
                negatives.held_targets,
                negatives.execution_admissions,
                negatives.active_incarnations,
                negatives.graphs
            ),
            (33, 24, 20, 16, 15, 14)
        );
        assert_eq!(
            (
                negatives.service_starts,
                negatives.service_replies,
                negatives.accepted_transfers,
                negatives.rejected_transfers,
                negatives.invalidated_transfers,
                negatives.recovery_entries
            ),
            (28, 28, 14, 14, 14, 11)
        );
        assert!(
            negatives.retired
                && negatives.frames_balanced
                && negatives.no_duplicate
                && negatives.budget_charged
                && negatives.selection_refused
                && negatives.no_speculative_grants
        );
        for (case, proof) in custodian_runtime::NEGATIVE_CASES
            .iter()
            .zip(negatives.results.iter())
        {
            assert_eq!(proof.recovery_entries, 1);
            assert!(proof.retired && proof.frames_balanced && proof.no_duplicate);
            match case {
                custodian_runtime::NegativeCase::FatalExit => assert!(matches!(
                    proof.last_failure,
                    Some(custodian_runtime::RootFailure::FatalExit { .. })
                )),
                custodian_runtime::NegativeCase::Watchdog => match proof.last_failure {
                    Some(custodian_runtime::RootFailure::Watchdog {
                        deadline,
                        observed,
                        dispatches,
                        cpu_ticks,
                        ..
                    }) => assert!(observed >= deadline && dispatches > 0 && cpu_ticks > 0),
                    _ => panic!("watchdog requires independently observed execution evidence"),
                },
                custodian_runtime::NegativeCase::Interrupted(stage) => {
                    assert_eq!(proof.interrupted_at, Some(*stage));
                    assert_eq!(proof.interrupted_attempt, Some(2));
                }
                custodian_runtime::NegativeCase::Selection(_) => {
                    assert!(
                        proof.refused_before_dispatch
                            && proof.no_speculative_grants
                            && proof.integrity_reason.is_some()
                    );
                    assert_eq!(
                        (
                            proof.execution_admissions,
                            proof.active_incarnations,
                            proof.graphs
                        ),
                        (0, 0, 0)
                    );
                    assert!(matches!(
                        proof.last_failure,
                        Some(custodian_runtime::RootFailure::Integrity(_))
                    ));
                }
            }
        }
        writeln!(
            serial,
            "EVROSION_M2_RECOVERY_CASES status=PASS scope=failure cases=11 faults=6 exits=4 watchdogs=4 interruptions=6 integrity=3 attempts=33 charged=24 held=20 admitted=16 active=15 graphs=14 starts=28 replies=28 transfers=14 rejected=14 invalidated=14 recovery=11 retired=true frames=true unique=true budget=true selection=true grants=true"
        )?;
        // SAFETY: prior failure worlds fully retired; same exclusive BSP,
        // parked AP, controller CR3 and physical allocator ownership.
        let caprpc = unsafe { cap_runtime::prove(offset, &mut frames) };
        assert_eq!(
            (
                caprpc.worlds,
                caprpc.accepted,
                caprpc.blocks,
                caprpc.wakes,
                caprpc.delivered,
                caprpc.returned
            ),
            (5, 8, 8, 8, 6, 4)
        );
        assert_eq!(
            (
                caprpc.queued_recovered,
                caprpc.delivered_no_refund,
                caprpc.timeouts,
                caprpc.server_faults,
                caprpc.late,
                caprpc.stale_serial,
                caprpc.wrong_object
            ),
            (2, 2, 2, 2, 1, 1, 1)
        );
        assert_eq!(
            (
                caprpc.preflight_rejected,
                caprpc.client_exits,
                caprpc.queued_invalidated,
                caprpc.queued_pending
            ),
            (3, 5, 0, 0)
        );
        assert!(caprpc.busy > 0 && caprpc.frames_balanced && caprpc.metadata_balanced);
        writeln!(
            serial,
            "EVROSION_M2_CAPRPC status=PASS scope=transport worlds=5 accepted=8 blocks=8 wakes=8 delivered=6 returned=4 refunded=2 no_refund=2 timeouts=2 faults=2 late=1 stale=1 wrong_object=1 rejected=3 busy=true exits=5 frames=true metadata=true"
        )?;
        // SAFETY: previous worlds stopped; exclusive BSP/controller CR3,
        // parked AP and frame ownership; measured thread stacks remain retained.
        let discipline = unsafe { ipc_discipline_runtime::prove(offset, &mut frames) };
        assert_eq!(
            (
                discipline.worlds,
                discipline.accepted,
                discipline.blocks,
                discipline.wakes,
                discipline.delivered,
                discipline.replies,
                discipline.contexts_verified
            ),
            (2, 10, 10, 10, 10, 10, 10)
        );
        assert_eq!(
            (discipline.spawned, discipline.exits, discipline.max_depth),
            (6, 2, 8)
        );
        assert_eq!(
            (
                discipline.mutex_acquired,
                discipline.mutex_released,
                discipline.dangerous_lock,
                discipline.cycle,
                discipline.deadline_extended,
                discipline.depth_exceeded,
                discipline.wrong_thread
            ),
            (1, 1, 1, 1, 1, 1, 1)
        );
        assert!(
            discipline.stack_policy && discipline.frames_balanced && discipline.metadata_balanced
        );
        writeln!(
            serial,
            "EVROSION_M2_IPC_DISCIPLINE status=PASS scope=threads worlds=2 calls=10 blocks=10 wakes=10 delivered=10 replies=10 contexts=10 spawned=6 exits=2 mutex_acquired=1 mutex_released=1 no_wait=1 cycles=1 extended=1 depth=1 wrong_thread=1 max_depth=8 stacks=true frames=true metadata=true"
        )?;
        #[cfg(all(feature = "test-m4-desktop", not(feature = "test-m5-native")))]
        {
            // SAFETY: preceding worlds retired; this controller exclusively
            // retains actual bootstrap RAM, GOP/device mappings and BSP/AP state.
            let desktop = unsafe {
                desktop_runtime::prove(
                    offset,
                    &mut frames,
                    framebuffer.expect("desktop requires an actual GOP framebuffer"),
                    |observation| desktop_observation(&mut serial, &observation),
                )
            };
            assert!(
                desktop.frames && desktop.metadata && desktop.guards && desktop.display_survived
            );
            assert_eq!(
                (desktop.faults, desktop.restarts, desktop.grants),
                (2, 2, 3)
            );
            writeln!(
                serial,
                "EVROSION_M4_DESKTOP status=PASS scope=graph processes={} starts={} faults={} restarts={} calls={} replies={} grants={} frames=true metadata=true guards=true display_survived=true",
                desktop.processes,
                desktop.starts,
                desktop.faults,
                desktop.restarts,
                desktop.calls,
                desktop.replies,
                desktop.grants
            )?;
        }
        #[cfg(feature = "test-m5-native")]
        {
            use supervisor_runtime::bundle as b;
            writeln!(
                serial,
                "EVROSION_M5_NATIVE_KERNEL_MEMORY protocol=1 build={BUILD_ID} physical_start={} physical_end={} virtual_start={} virtual_end={}",
                boot.kernel_physical_range.start,
                boot.kernel_physical_range.end,
                boot.kernel_virtual_range.start,
                boot.kernel_virtual_range.end
            )?;
            #[cfg(feature = "test-m6-network")]
            let profile = desktop_runtime::CommonProfile::Network {
                images: [
                    (b::M5_NATIVE_NET_DRIVER_IMAGE, b::M5_NATIVE_NET_DRIVER_SHA),
                    (b::M5_NATIVE_NET_SERVICE_IMAGE, b::M5_NATIVE_NET_SERVICE_SHA),
                ],
            };
            #[cfg(not(feature = "test-m6-network"))]
            let profile = desktop_runtime::CommonProfile::Native;
            let assets = native_runtime::Assets {
                common: desktop_runtime::CommonAssets {
                    profile,
                    root_image: b::M5_NATIVE_ROOT_IMAGE,
                    root_manifest: b::M5_NATIVE_ROOT_MANIFEST,
                    root_measurement: b::M5_NATIVE_ROOT_MEASUREMENT,
                    catalogue: b::M5_NATIVE_CATALOGUE,
                    catalogue_sha: b::M5_NATIVE_CATALOGUE_SHA,
                    images: [
                        (b::M5_NATIVE_SHELL_IMAGE, b::M5_NATIVE_SHELL_SHA),
                        (b::M5_NATIVE_INPUT_IMAGE, b::M5_NATIVE_INPUT_SHA),
                        (b::M5_NATIVE_FILE_IMAGE, b::M5_NATIVE_FILE_SHA),
                        (b::M5_NATIVE_BLOCK_IMAGE, b::M5_NATIVE_BLOCK_SHA),
                        (b::M5_NATIVE_APP_A_IMAGE, b::M5_NATIVE_APP_A_SHA),
                        (b::M5_NATIVE_DISPLAY_IMAGE, b::M5_NATIVE_DISPLAY_SHA),
                    ],
                    app_package: b::M5_NATIVE_PACKAGE_A,
                },
                app_b: (b::M5_NATIVE_APP_B_IMAGE, b::M5_NATIVE_APP_B_SHA),
                bad_shell: (b::M5_NATIVE_BAD_SHELL_IMAGE, b::M5_NATIVE_BAD_SHELL_SHA),
                packages: [b::M5_NATIVE_PACKAGE_A, b::M5_NATIVE_PACKAGE_B],
            };
            #[cfg(feature = "test-m6-session")]
            let mut retained_log = session_log::Retention::new();
            // SAFETY: all preceding actors retired; exact measured Native
            // assets and exclusively retained RAM/GOP/direct-map/BSP ownership.
            let native = unsafe {
                native_runtime::prove(
                    offset,
                    &mut frames,
                    framebuffer.expect("Native desktop requires actual GOP"),
                    &assets,
                    |observation| {
                        #[cfg(feature = "test-m6-session")]
                        session_observation(&mut serial, &mut retained_log, &observation);
                        #[cfg(not(feature = "test-m6-session"))]
                        desktop_observation(&mut serial, &observation);
                    },
                )
            };
            #[cfg(feature = "test-m6-session")]
            writeln!(
                serial,
                "EVROSION_M6_LOG protocol=1 build={BUILD_ID} observed={} retained={} omitted={} detail_bytes={} final_bytes={} omitted_bytes={} prefix_closed={}",
                retained_log.observed,
                retained_log.retained,
                retained_log.omitted,
                retained_log.detail_bytes,
                retained_log.final_bytes,
                retained_log.omitted_bytes,
                retained_log.prefix_closed
            )?;
            #[cfg(not(feature = "test-m6-network"))]
            let recovery = ev_userspace_contract::root_v2::native::catalogue::Catalogue::decode(
                b::M5_NATIVE_CATALOGUE,
            )
            .expect("actual Native catalogue")
            .boot_mode()
                == ev_userspace_contract::root_v2::native::catalogue::BootMode::Recovery;
            #[cfg(feature = "test-m6-network")]
            let recovery = ev_userspace_contract::root_v4::catalogue::Catalogue::decode(
                b::M5_NATIVE_CATALOGUE,
            )
            .expect("actual V4 catalogue")
            .boot_mode()
                == ev_userspace_contract::root_v4::catalogue::BootMode::Recovery;
            assert!(
                native.graph.frames
                    && native.graph.metadata
                    && native.graph.guards
                    && native.root_exit
                    && native.common_prefix
            );
            if recovery {
                assert_eq!((native.graph.processes, native.graph.starts), (2, 2));
                assert_eq!(
                    (
                        native.graph.faults,
                        native.graph.restarts,
                        native.graph.grants
                    ),
                    (0, 0, 0)
                );
                assert_eq!(native.app_starts, [0, 0]);
                assert_eq!(native.app_stops, [0, 0]);
                assert_eq!(native.app_reaps, [0, 0]);
                assert!(!native.graph.display_survived && native.graph.calls > 0);
            } else {
                assert!(native.graph.display_survived);
            }
            assert_eq!((native.bank_maps, native.bank_detaches), (2, 2));
            assert_eq!(native.bank_reclaimed, native.package_pages.iter().sum());
            #[cfg(not(feature = "test-m6-network-negative"))]
            assert_eq!(native.graph.calls, native.graph.replies);
            #[cfg(feature = "test-m6-network-negative")]
            assert_eq!(
                native.graph.calls,
                native
                    .graph
                    .replies
                    .checked_add(native.network_no_ack_returns)
                    .expect("bounded actual negative no-ACK accounting")
            );
            writeln!(
                serial,
                "{} protocol=1 build={BUILD_ID} status=PASS processes={} starts={} calls={} replies={} faults={} restarts={} grants={} app_a_starts={} app_b_starts={} app_a_stops={} app_b_stops={} app_a_reaps={} app_b_reaps={} app_a_process={} app_b_process={} app_a_thread={} app_b_thread={} package_a_pages={} package_b_pages={} bank_maps={} bank_detaches={} bank_reclaimed={} readonly_rejections={} root_exit=0 frames=true metadata=true guards=true {}",
                if recovery {
                    "EVROSION_M5_NATIVE_RECOVERY"
                } else {
                    "EVROSION_M5_NATIVE"
                },
                native.graph.processes,
                native.graph.starts,
                native.graph.calls,
                native.graph.replies,
                native.graph.faults,
                native.graph.restarts,
                native.graph.grants,
                native.app_starts[0],
                native.app_starts[1],
                native.app_stops[0],
                native.app_stops[1],
                native.app_reaps[0],
                native.app_reaps[1],
                native.last_process[0],
                native.last_process[1],
                native.last_thread[0],
                native.last_thread[1],
                native.package_pages[0],
                native.package_pages[1],
                native.bank_maps,
                native.bank_detaches,
                native.bank_reclaimed,
                native.readonly_rejections,
                if recovery {
                    "graphical=false"
                } else {
                    "display_survived=true"
                }
            )?;
        }
        #[cfg(feature = "test-m5-ipc-bench")]
        {
            use ev_kernel::{
                capability::{Kind, Rights},
                service::Role,
            };
            use provider_runtime::{ActorKind, ImageAsset};
            use supervisor_runtime::bundle as b;
            const fn endpoint(selector: u64, rights: u16) -> Role {
                Role {
                    selector,
                    kind: Kind::Endpoint,
                    rights: Rights::from_bits(rights).unwrap(),
                }
            }
            const SERVER: &[Role] = &[endpoint(1, 272), endpoint(2, 8)];
            const CLIENT: &[Role] = &[endpoint(1, 8), endpoint(2, 8), endpoint(3, 272)];
            let assets = provider_runtime::BenchmarkAssets {
                root_image: b::M5_IPC_ROOT_IMAGE,
                root_manifest: b::M5_IPC_ROOT_MANIFEST,
                root_measurement: b::M5_IPC_ROOT_MEASUREMENT,
                images: [
                    ImageAsset {
                        bytes: b::M5_IPC_SERVER_IMAGE,
                        sha: b::M5_IPC_SERVER_SHA,
                        descriptor: b::M5_IPC_SERVER_DESCRIPTOR,
                        roles: SERVER,
                        actor: ActorKind::Provider,
                    },
                    ImageAsset {
                        bytes: b::M5_IPC_CLIENT_IMAGE,
                        sha: b::M5_IPC_CLIENT_SHA,
                        descriptor: b::M5_IPC_CLIENT_DESCRIPTOR,
                        roles: CLIENT,
                        actor: ActorKind::Consumer,
                    },
                ],
            };
            // SAFETY: earlier protected worlds retired; sole BSP/direct-map/
            // allocator controller owns all actual retained source images.
            let proof = unsafe {
                provider_runtime::prove_benchmark(offset, &mut frames, &assets, |event| {
                    ipc_bench_observation::observation(&mut serial, BUILD_ID, event)
                })
            };
            ipc_bench_observation::footer(&mut serial, BUILD_ID, proof);
        }
        #[cfg(feature = "test-m5-provider")]
        {
            use ev_kernel::{
                capability::{Kind, Rights},
                service::Role,
            };
            use provider_runtime::{ActorKind, ImageAsset};
            use supervisor_runtime::bundle as b;
            const fn endpoint(selector: u64, rights: u16) -> Role {
                Role {
                    selector,
                    kind: Kind::Endpoint,
                    rights: Rights::from_bits(rights).unwrap(),
                }
            }
            const SERVER: &[Role] = &[endpoint(1, 272), endpoint(2, 8)];
            const CONSUMER: &[Role] = &[endpoint(1, 8), endpoint(2, 8), endpoint(3, 272)];
            let assets = provider_runtime::Assets {
                root_image: b::M5_PROVIDER_ROOT_IMAGE,
                root_manifest: b::M5_PROVIDER_ROOT_MANIFEST,
                root_measurement: b::M5_PROVIDER_ROOT_MEASUREMENT,
                images: [
                    ImageAsset {
                        bytes: b::M5_PROVIDER_A_IMAGE,
                        sha: b::M5_PROVIDER_A_SHA,
                        descriptor: b::M5_PROVIDER_A_DESCRIPTOR,
                        roles: SERVER,
                        actor: ActorKind::Provider,
                    },
                    ImageAsset {
                        bytes: b::M5_PROVIDER_B_IMAGE,
                        sha: b::M5_PROVIDER_B_SHA,
                        descriptor: b::M5_PROVIDER_B_DESCRIPTOR,
                        roles: SERVER,
                        actor: ActorKind::Provider,
                    },
                    ImageAsset {
                        bytes: b::M5_PROVIDER_CONSUMER_IMAGE,
                        sha: b::M5_PROVIDER_CONSUMER_SHA,
                        descriptor: b::M5_PROVIDER_CONSUMER_DESCRIPTOR,
                        roles: CONSUMER,
                        actor: ActorKind::Consumer,
                    },
                ],
            };
            // SAFETY: all earlier worlds retired; this sole BSP controller owns
            // the retained frames/direct map and every admitted process owner.
            let proof = unsafe {
                provider_runtime::prove(offset, &mut frames, &assets, |event| {
                    provider_observation::observation(&mut serial, BUILD_ID, event)
                })
            };
            provider_observation::footer(&mut serial, BUILD_ID, proof);
        }
        #[cfg(feature = "test-m4-display")]
        {
            // SAFETY: all prior worlds retired; the retained GOP/direct map,
            // allocator and BSP are exclusively owned here, with the AP parked.
            let graphics = unsafe {
                graphics_runtime::prove(
                    offset,
                    &mut frames,
                    framebuffer.expect("display proof requires a real GOP framebuffer"),
                    |present| {
                        write!(
                            serial,
                            "EVROSION_M4_PRESENT protocol=1 build={BUILD_ID} frame=1 width={} height={} app_process={} display_process={} surface_sha256=",
                            present.width, present.height, present.app_process, present.display_process
                        ).expect("bounded display Present record");
                        for byte in present.surface_sha256 {
                            write!(serial, "{byte:02x}").expect("bounded surface digest");
                        }
                        writeln!(serial).expect("complete display Present record");
                    },
                )
            };
            assert_eq!(
                (
                    graphics.worlds,
                    graphics.calls,
                    graphics.blocks,
                    graphics.wakes,
                    graphics.replies,
                    graphics.faults,
                    graphics.authority_denied,
                    graphics.mapped,
                    graphics.surface_pages,
                    graphics.display_tables,
                    graphics.max_pending
                ),
                (3, 2, 2, 2, 1, 2, 9, 6, 63, 6, 1)
            );
            assert!(graphics.peak_frames > 63 && graphics.peak_frames <= 128);
            assert_eq!(
                (graphics.app_fault.vector, graphics.app_fault.error),
                (14, 4)
            );
            assert_eq!(
                (graphics.display_fault.vector, graphics.display_fault.error),
                (14, 7)
            );
            assert!(graphics.app_fault.process != 0 && graphics.app_fault.thread != 0);
            assert!(graphics.display_fault.process != 0 && graphics.display_fault.thread != 0);
            assert!(graphics.frames && graphics.metadata && graphics.guards);
            writeln!(
                serial,
                "EVROSION_M4_DISPLAY status=PASS scope=surface worlds={} calls={} blocks={} wakes={} replies={} faults={} authority_denied={} mapped={} surface_pages={} display_tables={} peak_frames={} max_pending={} frames=true metadata=true guards=true",
                graphics.worlds,
                graphics.calls,
                graphics.blocks,
                graphics.wakes,
                graphics.replies,
                graphics.faults,
                graphics.authority_denied,
                graphics.mapped,
                graphics.surface_pages,
                graphics.display_tables,
                graphics.peak_frames,
                graphics.max_pending
            )?;
        }
        #[cfg(any(feature = "test-m3-pio-write", feature = "test-m3-pio-verify"))]
        if !cfg!(feature = "test-m3-store") {
            // SAFETY: ordinary proofs fully retired; exclusive BSP/controller
            // and allocator ownership, AP parked, isolated non-DMA test device.
            let block = unsafe { block_runtime::prove(offset, &mut frames) };
            assert_eq!(
                (
                    block.denied,
                    block.malformed,
                    block.direct_denied,
                    block.exits
                ),
                (4, 4, 1, 1)
            );
            assert!(block.frames && block.metadata);
            let write = cfg!(feature = "test-m3-pio-write");
            // Completion belongs to the selected measured actor's checked flow;
            // this record cannot serve as a generic device quiescence witness.
            writeln!(
                serial,
                "EVROSION_M3_BLOCK status=PASS scope=pio phase={} inputs={} outputs={} denied=4 malformed=4 direct_denied=1 exits=1 flushes={} frames=true metadata=true",
                if write { "write" } else { "verify" },
                block.inputs,
                block.outputs,
                u8::from(write)
            )?;
            // SAFETY: standalone actor fully retired; same exclusive hardware
            // boundary, with separately retained shared-buffer mapping leases.
            let shared = unsafe { block_transport_runtime::prove(offset, &mut frames) };
            let calls = if write { 4 } else { 2 };
            assert_eq!(
                (shared.calls, shared.blocks, shared.wakes, shared.replies),
                (calls, calls, calls, calls)
            );
            assert_eq!(
                (
                    shared.short_deadline_denied,
                    shared.authority_denied,
                    shared.malformed,
                    shared.mapped
                ),
                (1, 1, 2, 2)
            );
            assert!(shared.private_copy && shared.guards && shared.frames && shared.metadata);
            writeln!(
                serial,
                "EVROSION_M3_TRANSPORT status=PASS scope=shared phase={} calls={} blocks={} wakes={} replies={} short_deadline_denied=1 authority_denied=1 malformed=2 mapped=2 private_copy=true guards=true frames=true metadata=true",
                if write { "write" } else { "verify" },
                shared.calls,
                shared.blocks,
                shared.wakes,
                shared.replies
            )?;
        }
        #[cfg(feature = "test-m3-store")]
        if !cfg!(feature = "test-m3-generation") && !cfg!(feature = "test-m3-file") {
            use ev_userspace_contract::store_test::Mode;
            // SAFETY: preceding worlds retired; exclusive initialized BSP,
            // retained controller/direct map, inactive roots and owned frames.
            let store = unsafe { block_transport_runtime::prove_store(offset, &mut frames) };
            assert!(store.frames && store.metadata && store.guards);
            assert!(store.calls > 0);
            assert_eq!(
                (store.blocks, store.wakes, store.replies),
                (store.calls, store.calls, store.calls)
            );
            if store.control.mode == Mode::Cut {
                assert!(store.event.is_none());
                let fault = store.fault.expect("actual interrupted store fault");
                assert_eq!((fault.vector, fault.error), (6, 0));
                assert_eq!(
                    (fault.process, fault.thread),
                    (store.client_process, store.client_thread)
                );
                assert_eq!(store.mutations, store.control.cut);
                writeln!(
                    serial,
                    "EVROSION_M3_STORE_CUT protocol=1 build={BUILD_ID} status=PASS scope=journal cut={} calls={} blocks={} wakes={} replies={} mutations={} fault_vector=6 fault_error=0 process={} thread={} frames=true metadata=true guards=true",
                    store.control.cut,
                    store.calls,
                    store.blocks,
                    store.wakes,
                    store.replies,
                    store.mutations,
                    fault.process,
                    fault.thread
                )?;
                // The dedicated runner validates this exact bounded prefix and
                // abruptly kills/reaps its own QEMU. No orderly exit can flush
                // a device cache after the deliberate process interruption.
                loop {
                    // SAFETY: all users stopped, original CR3/IF0 retained.
                    unsafe {
                        core::arch::asm!("cli", "hlt", options(nomem, nostack));
                    }
                }
            }
            assert!(store.fault.is_none());
            let event = store.event.expect("actual store completion record");
            assert_eq!(
                (event.mode, event.mutations),
                (store.control.mode, store.mutations)
            );
            let phase = match event.mode {
                Mode::Init => "init",
                Mode::Recover => "recover",
                Mode::Commit => "commit",
                Mode::Verify => "verify",
                Mode::Cut => unreachable!(),
            };
            writeln!(
                serial,
                "EVROSION_M3_STORE status=PASS scope=journal phase={} calls={} blocks={} wakes={} replies={} mutations={} operation={} sequence={} pending=true replay_verified={} payload={} frames=true metadata=true guards=true",
                phase,
                store.calls,
                store.blocks,
                store.wakes,
                store.replies,
                store.mutations,
                event.operation,
                event.sequence,
                event.replayed(),
                if event.mode == Mode::Init {
                    "initial"
                } else {
                    "committed"
                }
            )?;
        }
        #[cfg(feature = "test-m3-generation")]
        if !cfg!(feature = "test-m3-owner") {
            use ev_userspace_contract::generation::Mode;
            // SAFETY: previous independent worlds fully retired; exclusive BSP,
            // controller CR3/direct-map/allocator ownership and parked AP.
            #[cfg(feature = "test-m3-progress")]
            let generation =
                unsafe { block_transport_runtime::prove_progress(offset, &mut frames) };
            #[cfg(not(feature = "test-m3-progress"))]
            let generation =
                unsafe { block_transport_runtime::prove_generation(offset, &mut frames) };
            let report = generation.report;
            assert!(
                generation.catalogue_readonly
                    && generation.frames
                    && generation.metadata
                    && generation.guards
            );
            assert!(generation.calls > 0);
            assert_eq!(
                (generation.blocks, generation.wakes, generation.replies),
                (generation.calls, generation.calls, generation.calls)
            );
            assert_eq!(
                (generation.mutations, generation.forged),
                (report.mutations, report.negatives)
            );
            let actual = u64::from(report.mode != Mode::Verify);
            let failed = u64::from(report.mode == Mode::FailB);
            let faulted = u64::from(report.mode == Mode::FailB && report.failure_reason == 1);
            assert_eq!(
                (generation.starts, generation.stops, generation.reaps),
                (actual, actual, actual)
            );
            assert_eq!(
                (generation.critical_ready, generation.faults),
                (actual - failed, faulted)
            );
            let phase = match report.mode {
                Mode::ProvisionA => "provision-a",
                Mode::FailB => "fail-b",
                Mode::AutoA => "auto-a",
                Mode::ManualA => "manual-a",
                Mode::Verify => "verify",
                Mode::OwnerPrepare3 | Mode::OwnerRecover => {
                    unreachable!("owner modes require owner proof")
                }
            };
            write!(
                serial,
                "EVROSION_M3_GENERATION status=PASS scope=cohort phase={} calls={} blocks={} wakes={} replies={} mutations={} starts={} ready={} critical_ready={} faults={} stops={} reaps={} forged={} catalogue=true frames=true metadata=true guards=true report=",
                phase,
                generation.calls,
                generation.blocks,
                generation.wakes,
                generation.replies,
                generation.mutations,
                generation.starts,
                generation.ready,
                generation.critical_ready,
                generation.faults,
                generation.stops,
                generation.reaps,
                generation.forged
            )?;
            // The canonical shared decoder requires the remaining256 bytes zero.
            // Encoding only meaningful bytes keeps diagnostics bounded/readable.
            for byte in &report.encode()[..256] {
                write!(serial, "{byte:02x}")?;
            }
            writeln!(serial)?;
            assert!(generation.elapsed_ticks < 2048);
            assert_eq!(generation.cpu_parent, generation.elapsed_ticks);
            assert_eq!(
                generation.cpu_driver + generation.cpu_client + generation.cpu_critical,
                generation.cpu_parent
            );
            assert!((1..=100_000).contains(&generation.transitions));
            assert_eq!(generation.max_pending, 1);
            writeln!(
                serial,
                "EVROSION_M3_GENERATION_BUDGET status=PASS elapsed_ticks={} limit_ticks=2048 driver_cpu={} controller_cpu={} critical_cpu={} parent_cpu={} transitions={} max_pending={} accounted=true bounded=true",
                generation.elapsed_ticks,
                generation.cpu_driver,
                generation.cpu_client,
                generation.cpu_critical,
                generation.cpu_parent,
                generation.transitions,
                generation.max_pending
            )?;
            if report.mode == Mode::FailB && report.failure_reason == 2 {
                assert!(generation.stopped_live);
                assert!(
                    generation.progress_observed_tick
                        >= generation.progress_start_tick.checked_add(64).unwrap()
                );
                assert!(generation.progress_stop_tick >= generation.progress_observed_tick);
                writeln!(
                    serial,
                    "EVROSION_M3_PROGRESS status=PASS start_tick={} observed_tick={} stop_tick={} wait_ticks=64 stopped_live=true fault=false",
                    generation.progress_start_tick,
                    generation.progress_observed_tick,
                    generation.progress_stop_tick
                )?;
            }
        }
        #[cfg(feature = "test-m3-file")]
        {
            use ev_userspace_contract::file_test::Mode;
            // SAFETY: preceding worlds retired; exclusive BSP/direct-map/frame
            // owner, inactive roots, AP parked and isolated non-DMA controller.
            let file = unsafe { block_transport_runtime::prove_file(offset, &mut frames) };
            assert!(file.frames && file.metadata && file.guards);
            assert_eq!(
                (file.blocks, file.wakes, file.replies),
                (file.calls, file.calls, file.calls)
            );
            assert_eq!(file.outer_calls + file.backend_calls, file.calls);
            assert_eq!(file.startup_calls + file.nested_calls, file.backend_calls);
            assert_eq!(
                file.pre_delivery_calls + file.delivered_nested_calls,
                file.nested_calls
            );
            assert!(file.delivered_nested_calls > 0);
            assert_eq!(file.outer_calls, file.report.requests);
            assert_eq!(
                (
                    file.max_pending,
                    file.mapped,
                    file.authority_denied,
                    file.block_denied
                ),
                (2, 4, 1, 1)
            );
            assert_eq!(file.snapshots, file.report.private_snapshot);
            assert_eq!((file.unbound_denied, file.bindings), (1, 2));
            assert_eq!(
                file.mutations,
                if file.control.mode == Mode::Write {
                    11
                } else {
                    0
                }
            );
            write!(
                serial,
                "EVROSION_M3_FILE status=PASS scope=object phase={} calls={} blocks={} wakes={} replies={} outer={} backend={} nested={} startup={} pre_delivery={} delivered_nested={} max_pending=2 mutations={} snapshots={} authority_denied=1 block_denied=1 unbound_denied=1 bindings=2 mapped=4 frames=true metadata=true guards=true report=",
                if file.control.mode == Mode::Write {
                    "write"
                } else {
                    "verify"
                },
                file.calls,
                file.blocks,
                file.wakes,
                file.replies,
                file.outer_calls,
                file.backend_calls,
                file.nested_calls,
                file.startup_calls,
                file.pre_delivery_calls,
                file.delivered_nested_calls,
                file.mutations,
                file.snapshots
            )?;
            for byte in file.report.encode() {
                write!(serial, "{byte:02x}")?;
            }
            writeln!(serial)?;
            assert!(file.elapsed_ticks < 2048);
            assert_eq!(file.cpu_parent, file.elapsed_ticks);
            assert_eq!(
                file.cpu_driver + file.cpu_server + file.cpu_client,
                file.cpu_parent
            );
            assert!((1..=100_000).contains(&file.transitions));
            writeln!(
                serial,
                "EVROSION_M3_FILE_BUDGET status=PASS elapsed_ticks={} limit_ticks=2048 driver_cpu={} server_cpu={} app_cpu={} parent_cpu={} transitions={} max_pending=2 accounted=true bounded=true",
                file.elapsed_ticks,
                file.cpu_driver,
                file.cpu_server,
                file.cpu_client,
                file.cpu_parent,
                file.transitions
            )?;
        }
        #[cfg(feature = "test-m3-owner")]
        {
            use ev_userspace_contract::generation::{Mode, OwnerDecision};
            // SAFETY: previous worlds retired; exclusive BSP/controller/direct
            // map and frame ownership, AP parked, separately scoped UART/ATA.
            let owner = unsafe { block_transport_runtime::prove_owner(offset, &mut frames) };
            let generation = &owner.generation;
            let report = generation.report;
            assert!(
                generation.catalogue_readonly
                    && generation.frames
                    && generation.metadata
                    && generation.guards
            );
            let active = u64::from(
                !matches!(report.mode, Mode::Verify | Mode::OwnerPrepare3)
                    && (report.mode != Mode::OwnerRecover
                        || report.owner_decision == OwnerDecision::Continue),
            );
            let failed = u64::from(report.mode == Mode::FailB);
            assert_eq!(
                (generation.starts, generation.stops, generation.reaps),
                (active, active, active)
            );
            assert_eq!(
                (generation.critical_ready, generation.faults),
                (active - failed, failed)
            );
            assert_eq!(
                (generation.mutations, generation.forged),
                (report.mutations, report.negatives)
            );
            assert_eq!(
                (generation.blocks, generation.wakes, generation.replies),
                (generation.calls, generation.calls, generation.calls)
            );
            let phase = match report.mode {
                Mode::ProvisionA => "provision-a",
                Mode::FailB => "fail-b",
                Mode::AutoA => "auto-a",
                Mode::ManualA => "manual-a",
                Mode::Verify => "verify",
                Mode::OwnerPrepare3 => "owner-prepare3",
                Mode::OwnerRecover => "owner-recover",
            };
            let decision = match report.owner_decision {
                OwnerDecision::None => "none",
                OwnerDecision::Continue => "continue",
                OwnerDecision::Cancel => "cancel",
                OwnerDecision::Timeout => "timeout",
                OwnerDecision::InputFault => "input-fault",
                OwnerDecision::InputBudget => "input-budget",
            };
            write!(
                serial,
                "EVROSION_M3_OWNER status=PASS scope=recovery phase={} decision={} calls={} blocks={} wakes={} replies={} mutations={} starts={} ready={} critical_ready={} faults={} stops={} reaps={} forged={} uart_inputs={} uart_outputs={} catalogue=true frames=true metadata=true guards=true report=",
                phase,
                decision,
                generation.calls,
                generation.blocks,
                generation.wakes,
                generation.replies,
                generation.mutations,
                generation.starts,
                generation.ready,
                generation.critical_ready,
                generation.faults,
                generation.stops,
                generation.reaps,
                generation.forged,
                owner.uart_inputs,
                owner.uart_outputs
            )?;
            for byte in &report.encode()[..256] {
                write!(serial, "{byte:02x}")?;
            }
            assert!(owner.uart_rx_len <= owner.uart_rx.len());
            write!(
                serial,
                " uart_rx_before_tx={} uart_rx=",
                owner.uart_rx_before_tx
            )?;
            for byte in &owner.uart_rx[..owner.uart_rx_len] {
                write!(serial, "{byte:02x}")?;
            }
            writeln!(serial)?;
            assert_eq!(
                (
                    owner.limit_ticks,
                    owner.transition_limit,
                    owner.parent_cpu_limit
                ),
                (65536, 8_000_000, 131072)
            );
            assert!(generation.elapsed_ticks < owner.limit_ticks);
            assert_eq!(generation.cpu_parent, generation.elapsed_ticks);
            assert_eq!(
                generation.cpu_driver + generation.cpu_client + generation.cpu_critical,
                generation.cpu_parent
            );
            assert!((1..=owner.transition_limit).contains(&generation.transitions));
            assert_eq!(generation.max_pending, 1);
            writeln!(
                serial,
                "EVROSION_M3_OWNER_BUDGET status=PASS elapsed_ticks={} limit_ticks=65536 driver_cpu={} controller_cpu={} critical_cpu={} parent_cpu={} parent_limit=131072 transitions={} transition_limit=8000000 max_pending={} accounted=true bounded=true",
                generation.elapsed_ticks,
                generation.cpu_driver,
                generation.cpu_client,
                generation.cpu_critical,
                generation.cpu_parent,
                generation.transitions,
                generation.max_pending
            )?;
        }
        writeln!(
            serial,
            "EVROSION_M1_RUNTIME status=PASS processes=6 faults={} survivors={} messages={} quanta={} isolated=true authority=true restored=true",
            runtime.faults, runtime.survivors, runtime.messages, runtime.quanta
        )?;
        writeln!(
            serial,
            "EVROSION_M1_WAITS status=PASS blocks={} signals={} deadlines={} idle_ticks={} retired=true",
            runtime.blocks, runtime.signals, runtime.deadlines, runtime.idle_ticks
        )?;
        writeln!(
            serial,
            "EVROSION_M1_RETIRE status=PASS processes={} reclaimed={} discarded={} closed=true quiescent=true",
            runtime.terminated, runtime.reclaimed, runtime.discarded
        )?;
        writeln!(
            serial,
            "EVROSION_M1_RECLAIM status=PASS frames={} reused={} zeroed=true restored=true",
            runtime.freed_frames, runtime.reused_frames
        )?;
        writeln!(
            serial,
            "EVROSION_M1_SHARED status=PASS objects={} maps={} denied={} busy=3 destroyed=3 zeroed=true",
            runtime.shared_objects, runtime.shared_maps, runtime.denied_maps
        )?;
        writeln!(
            serial,
            "EVROSION_M1_JOBS status=PASS jobs=9 frames=51 cpu_ticks={} hierarchy=true admission=true live_zero=true",
            runtime.quanta
        )?;
        writeln!(
            serial,
            "EVROSION_M1_REVOKE status=PASS invalidated={} denied={} faults=3 sibling_live=true",
            runtime.revoked_maps, runtime.revoked_denials
        )?;
        writeln!(
            serial,
            "EVROSION_M1_FX status=PASS processes=6 x87=true xmm=true mxcsr=true clean=true eager=true"
        )?;
        assert_eq!(runtime.notifications, 3);
        writeln!(
            serial,
            "EVROSION_M1_FAULT_DELIVERY status=PASS records=3 denied=3 consumed_once=true kernel_sender=true"
        )?;
        assert_eq!(runtime.anonymous_allocations, 6);
        assert_eq!(runtime.anonymous_frees, 6);
        writeln!(
            serial,
            "EVROSION_M1_ALLOC status=PASS allocated=6 freed=6 denied=3 zeroed=true unmapped=true rollback=true"
        )?;
        writeln!(serial, "{}", protocol::PASS)
    })();
    finish(result.is_ok())
}

/// M0 fault injection; enabled only in a separately identified test image.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn evrosion_deliberate_panic() -> ! {
    panic!("M0 deliberate panic: observable and symbolizable");
}

#[cfg(feature = "test-m8-workspace-run")]
fn reference_q35_restart() -> ! {
    #[cfg(feature = "qemu-test-exit")]
    {
        // SAFETY: selected Internal Q35 executor only, BSP controller IF0/APs
        // parked; exact captured Root checked COMPLETE has stopped every actor,
        // excluded IPC/window debt and performed ATA FLUSH/NIC STOP+scrub. No
        // ordinary caller receives this port or reaches this one-shot adapter.
        unsafe {
            core::arch::asm!("cli", "out dx, al", in("dx") 0x0cf9u16,
                in("al") 0x0fu8, options(nomem, nostack));
        }
        loop {
            // SAFETY: if reset does not happen, retain the quiesced machine;
            // never resume normal work or manufacture a successful boot.
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }
    #[cfg(not(feature = "qemu-test-exit"))]
    finish(false)
}

fn finish(passed: bool) -> ! {
    #[cfg(feature = "qemu-test-exit")]
    {
        let value = if passed {
            protocol::QEMU_PASS_VALUE
        } else {
            protocol::QEMU_FAIL_VALUE
        };
        // SAFETY: ring 0, QEMU test-only I/O port. This feature is absent in normal kernels.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") protocol::QEMU_EXIT_PORT,
            in("eax") value, options(nomem, nostack));
        }
    }
    let _ = passed;
    loop {
        // SAFETY: interrupts remain disabled; no scheduler is installed.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if PANICKING.swap(true, Ordering::Relaxed) {
        finish(false);
    }
    let mut serial = serial::Serial::initialize(1024);
    let _ = write!(
        serial,
        "EVROSION_PANIC protocol={} build={BUILD_ID} cpu=0 location=",
        protocol::VERSION
    );
    if let Some(location) = info.location() {
        let _ = write!(serial, "{}:{}", location.file(), location.line());
    } else {
        let _ = write!(serial, "unknown");
    }
    let _ = write!(serial, " message={}", info.message());
    let mut tail = serial::Serial::initialize(128);
    let _ = writeln!(tail, "\n{}", protocol::FAIL);
    finish(false)
}
