# ADR-0083 — Resident Root content provisioning and inspection

Status: Accepted Level B implementation staging; image admission and actual guest gates pending.
Date: 2026-11-13.

## Decision

The actual V4 Root controller exposes complete owner UART lines `update-init`
and `update-inspect`. Applications, Shell events and network packets cannot arm
them. The commands use the existing Root-only Block routes and the sole actual
State backend. They add no device, transport, application or executable authority.

Root moves that backend into a private resident continuation. State's existing
busy fence prevents other storage work while the same window/transport owner is
away. A successful operation returns that exact backend identity, mutation count
and poison state. Authenticated Snapshot extraction is consuming and has no
constructor, Clone or reinjection path. The resident getter refuses during active
work or retained uncertainty. A cached snapshot is local state, not a new remote
authorization; subsequent write decisions still require current-head checks and
fresh authentication.

`update-init` alone selects explicit new-volume provisioning. The canonical
Provisioner scans all 7,950 sectors: 14 checkpoint sectors and 7,936 immutable
object sectors, at most eight per step. Store's own full checkpoint-region blank
check remains mandatory before formatting. Ordinary open errors never select
formatting. An exact Unformatted result reads only the two zero root sectors;
it does not prove the rest of the volume blank. Root may return that unchanged
backend and accept a separate explicit init command, which still scans everything.

The creation manifest derives from FORMAT_ABI, the fixed Hello AppId, release
namespace, immutable independent development ROM Root and logical target name.
It excludes the current executable, startup ABI, A/B bank cohort and downloaded
candidate. A changed creation identity is foreign and is refused, never repaired
or formatted automatically.

After actual ROM object write, flush and complete readback, a private InitialRom
mode authenticates its exact length/hash/bytes, independent pin and self-quorum.
Only then does it construct ReplayState::initial and a complete canonical
checkpoint. There is no placeholder replay record to serialize. This mode is
reachable only through explicit provisioning with no ready state or published
checkpoint. Ordinary cold open always authenticates stored continuity and decodes
its exact retained roles, withdrawn-target floors and UTC floor; it never falls
back to initial state. The journal publishes only the verified checkpoint ref.

`update-inspect` performs actual Arena open/recovery and the common complete
cold authenticator. It is not a generic read-only disk command: canonical recovery
may finish a previously authorized journal transaction. It never accepts new
remote metadata, creates QualifiedTime, promotes an executable, or marks Active
or KnownGood. Expired metadata does not prohibit authentication/loading of a
previously authorized installed reference; new remote decisions retain the fresh
qualified callback boundary in [ADR-0082](ADR-0082-private-affine-time-client.md).

## Bounds and cancellation

Provisioning is a distinct whole-volume operation. Its one original cut is
1,048,576 PIT ticks: ceil(7950/8) × 1024 + 8192 = 1,026,048, rounded to 2^20.
The prior actual four-word PIO sample was about ten Block CPU ticks per sector;
the unchanged 64-per-256 child window can require about 318,000 elapsed ticks
before UI work. The new bound covers the complete scan rather than extending a
Hello, Stop, object-stage or metadata transaction. Whole cold inspection uses
the same finite class. Actual host workflow duration/progress remains a separate
measurement. No tick-to-UTC or calibrated host-time claim follows from this budget.

Every actual RPC child remains at most 1024 ticks and every metadata operation
at most 8192, clipped to the original whole cut. No step renews it. Crypto,
record construction, next-object opening, journal publication and completed-owner
extraction use separate bounded steps. The same logical owner and exact previous
published head survive these boundaries. CPU windows, Root's 512-frame quota,
Boot's 1024-frame quota, Root's 32 KiB stack and Kernel's 256 KiB stack are unchanged.

Cancellation runs only between completed children. It stops future work and
returns a known healthy owner; it never undoes completed IO, erases a reservation
or reuses an uncertain extent. After actual publication it refuses cancellation
rather than labelling a committed checkpoint unpublished. A cancelled first
initialization may leave a formatted but unpublished volume requiring explicit
recovery; there is no erase, rollback or autoformat shortcut. Failed/unknown
owners currently remain resident and State-busy until Root retirement.

## Resident representation and diagnostics

One permanent scoped claim holds the mutually exclusive actual IO owners and
private buffers. Exhaustive field initialization precedes the sole mutable
reference. Byte buffers initialize directly in private BSS; no typed static
Controller/package reference, self-reference, heap or large automatic buffer is
introduced. Cold/Commit workspaces stay resident. Existing consuming APIs delegate
to the same in-place protocol; they are not a parallel model. Actual journal ACK
alone consumes the next Snapshot. Every returned failure restores the exact Arena
before returning; an unknown final publication may cold-recover an old or new
complete checkpoint and is never retried as a reported success.

NR operations 22 (`update-init`) and 23 (`update-inspect`) report terminal local
results only. The separate Source UP8 packet is `[U,P,stage,result,progressLE32]`.
Stages 1/2 describe scan start/current progress, stage 3 local ROM checkpoint ready,
stage 4 authenticated cold revision, and stage 5 failure/cancellation/unformatted.
No field means UTC qualification, remote acceptance, admission or health.

At most 20 frames are created per Root lifetime. One immutable pending frame has
its original 4096-tick preaccept cut and at most one SEND attempt per actual tick.
Busy retains it; success consumes it even if preemption crossed the caller's
local cut. Scalar SEND has no Kernel-atomic caller deadline. Counters advance
despite logging pressure; terminal outcomes retain their original completion cut.
Diagnostic loss never authorizes or retries work. Root-origin/Events15 receipts
and readonly disk evidence remain separate host joins.

## Measured result and remaining gates

The first actual linked implementation correctly refused with 192 image pages,
198 private frames and a 116,280-byte resolved-reference stack census. In-place
owner handoffs and separated call frames reduced the final component to 165 image
pages / 171 private frames and 28,696 / 32,768 stack bytes (4,072 margin), ELF SHA256
`c97ba37d5255412b98279766a936a991621d2b65ea44181574e78140e8db8a8c`.
The selected 124/130 image/private admission bounds still refuse it. No bound was
raised by this decision. All intermediate failures remain retained. This census
is not a formal whole-program/runtime high-water bound. Fresh actual selected
Kernel census and image admission are mandatory before a guest run.

Final checks pass 171 Root network library tests, 81 legacy-session tests, 92 SDK
tests, strict host checks and all four actual Root bare target profiles. They
include every modeled Store interruption, original-cut/clock/initial-mode and
withdrawn-floor cases, actual same-disk saved-B pre-open composition, nine exact
update-engine and four UP queue tests. These tests do not establish actual guest
provisioning, downloaded executable health or complete M6 acceptance.

Checkpoint 1 retained a known settled-refusal gap: NotBlank and authentication refusals
retain the sole backend even when no unknown IO remains, blocking unrelated local
data for the rest of that Root lifetime. That negative acceptance gate is pending.
A separate reviewed change must distinguish a provably settled, unpoisoned refusal
from mutating/unknown uncertainty, return only the former exact backend, and prove
local data remains usable while unknown IO stays fenced. Startup must also restore
authenticated content/sealed Sources before a downloaded AppRegistry lookup; a
bank-only open failure must never be cleared into a fallback or format path.

## Separate settled-refusal refinement

The follow-up implementation distinguishes failure from unresolved IO. The content
Backend health hook defaults to unresolved for unreviewed adapters. The actual
Root adapter includes its permanent poison and explicit in-flight window/transport
state; a call settles only after its exact scoped reply and checked accounting.
State rechecks current recovery, registry/grant/System intents and exact identity
before accepting the same owner back. A live admitted Session is not an IO loan;
the one borrowed synchronous device excludes reentry while a real call is active.

Only terminal scan NotBlank, or an Inspect authentication/completed-hash refusal
with every Store/Arena/backend fence clear, can return that exact backend. The
semantic failure remains visible. No mutating storage error is whitelisted and no
fence is reset. A fresh post-IO clock observation is required even after semantic
failure; rollback, MAX or original-cut expiry permanently deny this release while
preserving its first error. Cached Snapshot access stays unavailable after refusal.

Five actual State/engine model regressions preserve saved scalar value 2026 and
the exact Note after these settled refusals. Unknown read/accepted-write reply
loss still blocks data and is never retried; changed current State intent fences
refuse owner restoration. Late-post-refusal clock cases remain fenced even after
a later valid sample. These tests close the component's settled-refusal model
gate; actual guest namespace/retirement validation remains separate.
