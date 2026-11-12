# ADR-0040 — Transactional capability RPC

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: ADR-0015, ADR-0037, IPC_DISCIPLINE.md; INV-AUTH-005, INV-IPC-005

## Decision

Add a closed generated cap_echo@1 contract and explicit ownership outcomes for
capability-bearing synchronous transport. Preserve echo@1's existing cap-free
contract. Use actual capability-table transfers and mailbox escrow, with the same
Authority, Scheduler and protected RPC owner throughout a call. No cloned tables
or caller-supplied readiness flags certify a transfer.

The initial contract carries one Memory READ|TRANSFER attachment in each
direction. Its mask is 65: TRANSFER is 64, whereas 128 is REVOKE. Independent
kernel-to-generated conformance and actual escrow tests guard this boundary.
Malformed body/count/kind/rights must fail before a handler or authority mutation.

## Protected identity and acceptance

The kernel derives actual registered caller/callee domains and protects CallId,
ancestry, deadline and incarnation. A received request returns its protected
serial; replies must present that serial from the actual callee. The closed Echo
profile also requires the same full generation-tagged Memory object on return.
This is a method requirement, not a restriction on every future capability RPC.

Request acceptance moves a handle into real mailbox escrow only after bounded
shape, authority, deadline and scheduler admission preflight. Rejection retains
the original installed handle; this does not promise that its authority remains
live after concurrent revocation.

Timely reply completion validates the protected reservation and deadline, then
invokes the actual transfer inside a non-reentrant acceptance transaction.
Transfer refusal leaves both source handle and reservation unchanged. No fallible
RPC work follows a successful transfer. The controller associates completion with
the matching Scheduler WaitTicket; no kernel lock spans userspace or an IPC wait.
Late acknowledgement retains the callee's handle and cannot install it into or
wake a newer call, including one on another route.

## Explicit ownership outcomes

The pointerless cap ABI uses R10 in addition to the legacy scalar operands.
CALL25, RECEIVE26, REPLY27 and RECLAIM28 are distinct operations; legacy calls
preserve R10. Deadline query29 exposes only the actual incoming protected context.

CALL distinguishes returned capability, rejected original, queued recovered
capability, delivered failure without refund, queued invalidation, and pending
queued recovery. Full destination/source tables preserve actual ownership rather
than inventing a return handle. Pending recovery uses a non-Copy diagnostic token
correlated with the actual caller and retained ticket; it grants no authority.

Timeout ends waiting, not execution. Queued work may be withdrawn only by its
exact unreceived ticket; delivered work is never refunded as if unexecuted.
Reply distinguishes consumed acceptance, rejection retaining input/token, and
late acknowledgement retaining the input capability. Invalid scalar result
combinations are indeterminate, never inferred to mean ownership was returned.
Generated clients retain genuinely returned authority even if response decoding
fails. Userspace wrappers are non-Copy ergonomics; kernel checks remain decisive.

## Verification and scope

Portable tests exercise actual escrow/transfer, table pressure, rollback,
revocation, death in either order, exact-object mismatch and old completion while
a caller waits on a different route. CPL3 clients/servers must separately prove
these transitions through actual syscalls, scheduling and fault handling before
hardware acceptance. Full chain/lock/depth AF-IPC tests and complete M2 acceptance
remain distinct gates, recorded in [M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).
