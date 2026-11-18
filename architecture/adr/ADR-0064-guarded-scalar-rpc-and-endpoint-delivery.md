# ADR-0064 — Guarded scalar RPC and declared endpoint delivery

Status: Accepted implementation refinement; session integration and abuse-containment execution pending.
Date: 2026-11-12. Engineering mandate Level B; no foundational guarantee change.
Related: ADR-0037; ADR-0039; ADR-0040; ADR-0047; ADR-0056; M6-02.

## Decision

Use the existing canonical `Rpc` cancellation graph and actual mailbox ownership
for sustained-session scalar calls. An expired logical wait is not permission
to reuse memory that a callee can still write. Existing finite M0–M5 call paths
keep their ordinary scheduler deadline behavior; the separate M6 session profile
uses a guarded scheduler wait with the original finite operation deadline.

`Rpc::expire` still ends the logical wait and records its canonical outcome at
the actual deadline. The caller's guarded thread remains blocked until its
specific queued ticket is withdrawn, its actual callee acknowledges completion,
or that callee's exact scheduler identity has genuinely retired. This delays
caller resumption, not deadline observation, and grants no fresh operation time.
No timeout fabricates a successful reply, completion event or memory release.

The trusted `Rpc::complete_scalar` adapter accepts only the existing eight-byte,
zero-capability endpoint policy. For a queued cancelled request it preflights
the actual endpoint, original sender, ticket, length and absence of attachments,
then reuses `complete_with` and `withdraw_undelivered` in one serialized acceptance
transaction. The runtime must retain the actual CallId-to-Ticket association.
Delivered requests have no refundable queued ticket. A genuine late nonce ACK
releases the retained canonical reservation but its reply payload is discarded;
the original terminal status is returned once to the guarded caller. Retained
nested scalar reservations must settle before an ancestor ACK can release its
shared-memory credit. Stale calls, wrong callees, wrong queues and capability
attachments cannot substitute for this completion.

Actual intermediary death also retains the parent owner record while any of
that intermediary's accepted children remain in the existing Pending ledger.
Canonical `peer_died` may remove a dead callee's metadata before its descendants
acknowledge; inspecting only the surviving Rpc wait graph would miss that case.
The fixed leaf-first drain follows actual retained request owners, including
intermediaries whose own canonical record was retired. Buffer disjointness in
the old fixed graph is not an implicit condition of this guard.

The separate Native session Block profile wraps its existing `AtaPio` owner in
userspace `SessionDisk`. It validates fresh deadlines and geometry before shared
window access, reads into private storage, and publishes only after both the
command and final idle check complete. A command/idle failure retains its
original progress classification. One reset, re-identification and idle sequence
uses the original operation deadline plus 1,024 ticks; no read, write or flush
request is replayed. An error after an executed command stays `MayHaveExecuted`.
Reset cannot establish write rollback or durable Store consistency. The returned
backend Error2 requires the higher Store owner to remain poisoned until its
explicit recovery policy succeeds.

If that cleanup expires, overflows or fails, the wrapper permanently quarantines
its device owner. Later requests cannot touch a window or port. The actual actor
retains the received nonce and yields without acknowledging reusable memory;
the trusted outer quiescence owner must fence/retire it or fail the session.
This is a bounded PIO cleanup mechanism, not general driver reconstruction or
permission to repeat an uncertain mutation. Existing finite Block profiles retain
their original execution path. Host device models prove these control/data
conditions only; actual short-deadline QEMU/device execution remains required.

Session File metadata failures preserve the existing poisoned backend and return
the defined `FME1` error frame after child quiescence, rather than exit File or
invent a metadata word. Root refuses those exact defined error frames and the
kernel's diagnostic grant snapshot invalidates its partial counter/digest.
This old Internal raw-u64 metadata profile reserves error words that could also
be valid digest words. A collision is conservatively refused; it cannot grant
authority or fabricate content. This is not a fully tagged general metadata ABI;
a later versioned tagged/bulk representation must remove that ambiguity.

Actual session RPC observations use the existing restored-CR3/IF0 callback.
They cover at most the first 32 accepted calls to Block from any caller and each selected
call's one completed/quiescent outcome, plus the first 32 canonical terminal
outcomes across all routes: at most 96 lines per run. They record actual protected
identities, opaque request values, original deadlines, captured ticks and sampled
CPU counters. The separately recorded Scheduler tick identifies the age of its
window/accounting snapshot. These are bounded diagnostics, not health or timing
acceptance receipts; no competing userspace UART writer is introduced.

File, Block and Input must treat an already-expired inherited deadline as a
typed refusal, avoid new shared-window/device work and acknowledge the received
nonce. A local deadline failure must not become a critical-service assertion.
An operation already executing must reach a safe acknowledgement point or actual
retirement before its caller may reuse shared backing. In particular, this
adapter neither makes an ATA command reversible nor infers hardware quiescence.

## Aggregate storage cuts and queue expiry

The session profile distinguishes a bounded multi-sector transaction from each
actual child RPC. Actual startup execution exposed exhaustion of the previous
shared 512-tick cut during legitimate PIO work under the unchanged 64/256 Block
CPU allowance. The corrected logical-to-physical acknowledgement route then
reached real deadline cancellation and quiescent cleanup; this did not establish
successful startup or justify raising CPU quotas.

An explicitly selected storage adapter accepts an original aggregate cut at
most 8,192 ticks ahead. Before any shared-window publication it captures one
child cut, `min(original aggregate cut, actual now + 1,024)`. The accepted child
cut, request bytes and published proposal remain identical through pre-accept
Busy retries. Publication, a retry, a completion or a later clock observation
cannot recapture or extend that child. The canonical RPC ancestor check also
rejects a child beyond its actual incoming parent. File startup captures one
8,192-tick aggregate cut across both Store opens; each nested Block request uses
the clipped child cut. Four declared File transaction routes allow the bounded
aggregate, while ordinary Block, Present and Input RPC remain at 1,024 ticks.
The tight adapter and finite M0–M5 paths retain their existing bounds. Ambiguous
post-publication failures poison the owning backend before another window write.

Session asynchronous scalar queues also reclaim expired, still-undelivered
messages through the existing Mailbox owner. The exact sender generation,
ticket, endpoint queue, eight-byte payload and absence of capability escrow are
preflighted before mutation. Reclamation clears that accepted row once and
returns its actual queue credit; a stale ticket cannot release a later message.
RPC and Selected capability routes are excluded. Capability escrow retains its
ordinary explicit reclaim/death obligations and cannot be silently discarded
because a scalar TTL elapsed. The existing callback emits only the first 32
actual scalar-expiry receipts; it creates no source ACK or successful delivery.

Cleanup also runs at the actual session Receive syscall-capture tick. An
executor observation immediately before user resume cannot guarantee a queued
frame is still future when that user invokes Receive. The actual receiver and
endpoint are preflighted before mutation; expired scalar tickets and their
accepted ledger rows are reclaimed canonically, then this call returns NoData.
A later live frame stays queued for the next call. Finite profiles preserve
their original receive path. This avoids turning ordinary session queue expiry
into a fatal Root receive-contract error without inventing delivery or an ACK.

A finite queued-message TTL is not a guaranteed delivery interval. Root can
perform another bounded synchronous transaction before its next receive, so a
producer must handle missing delivery/ACK without replaying an accepted mutation
or treating timeout as permission to reuse memory that Root may already own.
User-facing failure/cancellation and fair scheduling between long source work
units remain integration obligations.

Bounded session UI observations join actual matched KBR2 and cursor RPCs and
actual Note request/ACK acceptance/delivery tickets with protected endpoint and
current process/thread identities. KBR2 samples additionally match the current
Shell's completed protected Present. Five cumulative counters never reset;
only their first32 events each are serialized, at most160 sampled rows, followed
by counts at checked finish or a diagnosed bound. These are diagnostic protocol
facts, not disk durability, focus/consent policy, source-body integrity or
successful whole-session acceptance. No shared Note body is read for a hash
while its cross-protocol ownership is unproven.

## Delivery declarations

Consolidate the fixed measured graph's existing numeric RPC/SEND lists into
`Channel::delivery`: scalar asynchronous delivery, scalar RPC, or selected
capability handoff. The actual retained Wire receives that mode from the typed
channel ledger; the external Root Events wire is asynchronous. Exact capability
authorization and live object identity remain mandatory. Mode only narrows
permitted operations and never interprets application packet policy.

The previous ordinary SEND and RPC-binding lists already rejected the proposed
App SEND-to-AppPresent and RPC-to-RootEvents examples before acceptance. This is
a maintainability refinement and explicit receiver-primitive validation, not
evidence that those examples were exploitable. GrantInbox stays a distinct
`SelectedReadRoute`; it does not gain ordinary scalar SEND or RPC. Existing
graph description bytes, service role bytes, syscall numbers and finite-profile
goldens are preserved.

## Bounds and remaining acceptance

Quiescence has a separate finite grace: 1,024 ticks after the original operation
deadline for expiry, or after first observation of another terminal outcome.
Repeated observations do not extend that cut. The current prototype returns a
checked grace failure with actual CallId/caller/callee identities while retaining
all owned mappings and reservations. The outer controller's terminal VM failure
path is fail-closed; it is not successful retirement, service reconstruction or
the final M6 hostile-App containment result. Targeted peer fencing, canonical
peer-death cleanup and useful unrelated-service survival still require actual
execution proof before that acceptance gate can pass.

Host Core tests exercise real scheduler guards, canonical RPC, actual Mailbox
withdrawal and the exact runtime Wire implementation. They cover queued versus
delivered expiry, nested reservations, stale tickets/nonces, wrong endpoint
owners, capability-route rejection and delivery-mode refusals without queue
mutation. They do not substitute for source-frozen linked stack checks, actual
short-deadline service execution, unresponsive-peer containment, ordinary finite
regressions or complete asynchronous-protocol failure/reclamation proof.
