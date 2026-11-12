# ADR-0037 — Bounded synchronous service transport

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: E-008, E-015, A-012, ADR-0035; IPC_DISCIPLINE.md

## Decision

Connect generated typed clients to kernel-protected causal calls and actual
scheduler waits. Keep the existing bounded asynchronous path for events and
callbacks. The first synchronous contract uses the same generated Echo body
with a declared non-reentrant transport and finite absolute deadline.

The portable RPC owner records actual registered thread/domain/Job associations,
endpoint identity, origin, trace, parent call, depth, deadline and incarnation.
Userspace cannot supply this ancestry. One thread waits on one outgoing edge,
non-reentrant server reservations are bounded, and forward depth is at most eight.
Ancestor callbacks, extended descendant deadlines and NO_IPC_WAIT lock classes
are rejected before acceptance.

## Admission and waiting

The dispatcher validates live SEND authority, the actual receiver route, payload/
capability bounds and queue capacity, then preflights the scheduler's complete
block conditions. The serialized controller accepts the protected call and
cap-free message before blocking the actual caller with its unique WaitTicket.
An undispatched enqueue failure cancels and releases that private reservation.
No kernel lock spans user execution or an IPC wait.

A reply belongs to the actual servicing thread and exact protected CallId. The
dispatcher writes it into the matching saved caller context and wakes only its
WaitTicket. It does not also enqueue a duplicate asynchronous response. Generated
clients validate the versioned reply after transport succeeds.

## Deadline and failure behavior

Expiry ends the wait and notifies cancellation while retaining callee execution
ownership until acknowledgement or verified death. Late replies release only
their own reservations; they cannot deliver to or wake a later call. Queued
expired work is reclaimed before delivery. Verified peer death supplies
PEER_DIED through the same protected wait state. Call identity and clocks never
reset to permit a retry.

The hardware proof includes a separate first-reply-delay artifact. A distinct
timed-out value is followed by successful calls with different values; a real
late response must be discarded while subsequent calls remain correct. Immediate
expired deadlines and forged endpoint handles are separate rejected requests.
Strict evidence counts successful calls separately from all accepted waits.

The timeout fixture explicitly backpressures its first late response until the
real caller has attempted a second call against the retained reservation. Without
this ordering, scheduling could complete the late response before that probe and
make a correct transport fail a timing-dependent busy assertion. Echo retains
and retries a response after WOULD_BLOCK; the controller accepts nothing and
releases no reservation during backpressure. Deadline expiry, the actual busy
rejection and discarded late completion remain required executed transitions.

A read-only syscall exposes only the actual serving thread's protected incoming
deadline; callers cannot supply a CallId, ancestry or replacement deadline. It is
denied outside a serving reservation. The delayed artifact waits beyond that
value, while its caller supplies a finite admission margin. A one-tick caller
deadline could otherwise expire before acceptance, falsely exercising immediate
rejection instead of an accepted timeout. The query also supports legitimate
forward deadline propagation without trusting userspace-supplied ancestry.

## Acceptance scope

Host tests cover forward chains, cycles, depth nine, deadline extension, lock
classes, bounded shapes/backpressure, timeout/cancellation, stale completion and
peer isolation. Actual CPL3 proof connects generated clients, server execution,
blocked scheduling, timer expiry and matching replies. The initial Echo transport
is cap-free; general synchronous capability transfer and full service/BAC recovery
remain explicit M2 work. Executed results and remaining scope belong in
[M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).
