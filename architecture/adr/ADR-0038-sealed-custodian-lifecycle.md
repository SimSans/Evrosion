# ADR-0038 — Sealed custodian lifecycle

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: ADR-0026, ADR-0031, ADR-0033, ADR-0036; ROOT_AUTHORITY_CUSTODY.md

## Decision

Retain one non-Clone custodian over the immutable measured manifest and custody
catalog for the boot lifetime. It owns the incarnation sequence, restart budget,
current token and recovery latch. Preparing a new binding does not create a new
budget or reset counters. This Level B refinement preserves the original BAC
guarantees and makes their lifecycle enforceable across separate loaded images.

Initial launch is free. Every later admitted attempt charges the same bounded
sliding window before allocation, including a failed spawn. An abandoned
unprepared attempt cannot refund admission. Clock reversal, counter exhaustion,
integrity damage or exhausted policy latches independent recovery; there is no
public reset or override. Userspace receives no custodian mutation capability.

## Activation and retirement

A move-only attempt permit binds the epoch, sequence, custody and measured
manifest. Preparation creates the exact existing Bindings token. Confirmation
requires the actual typed Active owner with the same sealed context, rather than
a caller-provided ready flag. Stale attempts, foreign bindings and old events
cannot advance current custody.

Revocation fences creation before the trusted controller stops the whole managed
graph. Replacement requires the consumed revoked Bindings, its current terminated
generational process identity, zero aggregate live process/thread/frame charges,
and a matching consumed physical quiescence witness. Historical CPU use remains
charged. Scheduler identities must remain available through this check; metadata
reclamation follows acceptance. Incomplete cleanup returns both sole owners for
retry without authorizing replacement.

## Explicit hardware trust boundary

The narrowly annotated unsafe `QuiescentIncarnation` trait declaration is a second
reviewed exception to portable `deny(unsafe_code)`, alongside ADR-0033's
`LoadedExecutable`. Neither declaration executes unsafe instructions. Portable
policy remains safe Rust; host-only model implementations are individually
annotated and do not certify physical teardown.

A production witness must have a private non-Clone constructor in the hardware
controller. Its stable token must describe the entire stopped incarnation graph:
no resumable CPU/AP contexts, retained controller CR3, fenced/drained IRQ and DMA,
retired IPC/RPC/escrow/mappings, no live authority or reference leases, and all
private backing scrubbed and returned exactly once. A deadline, revoked flag,
scheduler exit or balanced counters alone cannot construct this witness.

The same Authority, Scheduler and immutable generation selection remain retained.
The custodian checks the metadata conditions; the unsafe implementer proves the
external hardware conditions. This exposes the obligation instead of disguising
it as a safe callback that could accept an arbitrary boolean.

## Verification and scope

Host tests must cover multiple incarnations, stale/foreign receipt ownership,
incomplete cleanup, failed spawn charging, clock reversal, counter and budget
exhaustion, and a permanently latched recovery state. Actual Root catastrophe,
whole graph teardown, exact reconstitution and independent recovery must have
separate executed hardware evidence before claiming AF-007A–H or whole M2.
The existing parked-AP BSP proof does not establish general SMP or device DMA
quiescence. Current results belong in [M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).
