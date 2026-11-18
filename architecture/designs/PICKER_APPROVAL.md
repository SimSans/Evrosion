# Selected-file approval binding

Status: **Verified — bounded M4 selected READ**, 2026-10-27. This annex addresses
A-004 for the initial local picker. It does not close the general Trusted Control
Plane, destructive approvals, AI actions or durable grants.

The governing [A-004 finding](../plans/reviews/full-architecture-audit-v1.md)
requires approval to identify a stable object/action and to revalidate execution
preconditions; its action-register entry requires this before the trusted picker.
[E-025.52/.54](../plans/roadmap/E-025-initial-scope.md) and
[R-011.17](../plans/release-project/Evrosion_R-007_to_R-011_Superfile_v1.md)
require an actual selected-file grant. [E-017.72–76](../plans/experience/E-017-graphics-and-display.txt)
separately requires protected Trusted Control and fallback presentation. The
initial trusted Shell is part of this picker's trusted computing base; it does
not implement a general shell-independent secure-attention path.

## Exact action and identity

The [pure picker core](../../libs/picker/src/lib.rs) binds a bounded, non-Copy
approval to the following snapshot. These values describe policy; constructing
one, copying a digest or receiving a key frame creates no capability.

| Bound fact | Actual M4 source and limit |
|---|---|
| Approver and session | Source Root uses one fixed local owner identifier and a session/boot epoch derived from its measured Root context. This is not enrolled-user authentication or multi-user session management. |
| Requesting application | Stable AppId plus separate immutable package digest from the checked readonly desktop catalogue, and the actual retained App ProcessCONTROL/full process incarnation. Names and publisher claims are not authority. |
| Selected object | Stable profile volume identity plus local Notes/Private object identity, resolved through distinct immutable File READ endpoint objects. No path, raw LBA or app-supplied object selector is accepted. |
| Content and permission | Actual File envelope revision counter and SHA-256 payload digest. Root reads counter, four digest words and counter again through the selected File endpoint. Policy/permission revision 1 is fixed by this profile; no mutable permission database or concurrent external writer is admitted. Counter 0 is a valid seeded revision. |
| Operation and lifetime | READ only, this incarnation, bounded monotonic expiry, nonwrapping picker nonce and canonical action digest including the requester/object/revision/policy snapshot. An approval is consumed on validation failure or handoff attempt. |

[Source Root metadata/requester/select](../../services/root-supervisor/src/desktop.rs)
resolves current facts again at commit. The core rejects changed object/revision,
requester/AppId/package/incarnation/session, policy/permission, death, expiry,
clock reversal or a different action digest. Remember-per-user intent is a
separate [portable policy representation](../../libs/picker/src/intent.rs).
The later Native3 A-003 execution (local engineering archive)
proves remembered owner policy and cold fresh authority separately; no raw process
handle or live capability is persisted by this M4 picker.

## Actual presentation and fresh input

The [source Shell](../../services/desktop/src/shell.rs) and
[Shell policy](../../services/desktop/src/shell_policy.rs) render the selected
Notes/Private choice while the ordinary App rectangle is hidden. The Shell waits
for the protected Display Present reply, obtains the actual Input barrier for
that frame, and advertises S5 PickerReady only after both complete. The
[Input source](../../services/desktop/src/input.rs) drains pre-barrier bytes and
unsent keys without resetting held-key/release knowledge. A fresh eligible Enter
must follow the barrier's sequence floor and known actual release; queued,
held/repeated, unknown-release, replayed or pre-presentation Enter cannot approve.
Changing selection requires a new Present and barrier. Submission may render
Opening without arming a second approval; a stale Present completion cannot
reopen it.

The [kernel observation adapter](../../kernel/src/desktop_runtime/observation.rs)
correlates the actual App open event consumed by Root, current process/thread,
monotonic request, protected Shell Present, matching Input CallId/barrier and
actual S5 receipt. It retains that receipt across the subsequent Opening frame.
These receipts document provenance; a diagnostic tuple or screenshot is not a
permission to mint authority. Input-source/endpoint possession and actual
caller identity remain mandatory.

## Handoff and revocation

[Root's handoff](../../services/root-supervisor/src/desktop.rs) uses its real
App ProcessCONTROL, selected File source and dedicated managed grant inbox.
The [kernel grant adapter](../../kernel/src/desktop_runtime/grant.rs) independently
checks current Root/caller, live exact App incarnation, pending actual request,
selected endpoint identity, completed File metadata snapshot and empty route.
The [selected route](../../kernel/src/live_grant.rs) retains Registry/Scheduler,
full Root token and managed mailbox provenance. Queue acceptance and actual
receipt are distinct. The explicit attenuated receive installs exactly Endpoint
SEND8 at the actual App thread, consumes the one-shot source and preserves
revocation ancestry; ordinary transfer continues to preserve its original rights.

SEND8 permits a logical File READ only because that endpoint has an immutable
File-service object/access binding. It grants no File replacement method,
sibling-object selector, raw disk access, RECEIVE, DERIVE or TRANSFER. The actual
App checks these rights and reads the selected content before Root promotes its
pending private revocation branch. A replacement preserves the prior branch
until actual new receipt/read; cancellation keeps the existing selected object
and re-reads it. App stop/replacement revokes current and pending branches and
settles queued ownership before recycling. App/Shell replacement cannot restore
an old pending approval. Input-replacement cancellation and stale/release cases
also have source/model coverage; the accepted full VM specifically injects App
and Shell failures, not a physical Input restart.

The current File service has one serialized trusted writer, and the App receives
only READ endpoints. Root does not write while resolving/committing a picker
selection. This ownership boundary makes the two metadata snapshots coherent
through handoff. A future concurrent writer, mutable policy database or general
object replacement must add an atomic File-owner version/selection transaction
or equivalent serialization; counter-before/after alone is insufficient for
that stronger scope. The handoff is not a token-only generic mint API.

## Executed evidence and remaining boundaries

The full desktop physical proof (local engineering archive)
retains the actual source cohort, Hello.zion/catalogue, input/QMP/UART transcript,
20 unmodified captures and all failed transient captures. Fifteen required stages
pass exact complete scanout comparison. Held Enter spans 68 actual running guest
ticks with zero grants; later held checkpoints retain the prior grant count.
Fresh release/make installs Notes, cancellation preserves Notes, a new selection
installs Private, and App crash/relaunch requires a new Notes grant. Three actual
capability deliveries, two actual page faults and two actual replacements occur;
Display remains the same process. Cold read-only disk inspection preserves both
File objects and all System/guard regions.

Current core/startup checks (local engineering archive)
retain 355 kernel and 41 contract tests plus strict lint, including exact rights
and private-parent revocation. Consent/window checks (local engineering archive)
retain the 15 Shell/Desktop, 10 graphics and 138 frontend passing tests, one existing
ignored frontend test, target lint and the exact five-file correction. Earlier
portable authority/reuse evidence (local engineering archive)
records managed lifecycle/recycle coverage; portable negatives do not turn every
race into a separately executed physical claim.

The accepted profile is bounded BSP userspace with parked AP on controlled
QEMU/OVMF devices, no DMA and a fixed local owner/session. It claims neither
Secure Attention nor authentication/enrollment, shell-independent recovery UI,
protection against an arbitrary malicious trusted Shell, general privileged
settings/install/delete/AI consent, durable remembered grants, SMP races or
production hardware security. [M4 acceptance](../M4_ACCEPTANCE.md) is PASS for
this bounded profile after the current original surface regression (local engineering archive)
and formal reconciliation (local engineering archive).
The broader E-017 Trusted Control and Layer 3 owner-power requirements remain
intact and open for their actual protected control/recovery integration.
