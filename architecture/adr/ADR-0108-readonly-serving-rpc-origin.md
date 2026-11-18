# ADR-0108 — Read-only serving RPC origin

Status: Accepted Level B implementation direction; native VM qualification pending.
Date: 2026-11-16. Related: ADR-0040/0064/0104/0105/0106; M8-04/05/08/10;
E-008; E-009.1–8/.19; INV-AUTH-002/003 and INV-IPC-002/005.

## Problem and decision

Legacy RECEIVE_RPC34 returns the actual eight-byte body in RSI and protected
call nonce in R10, with RDX zero. It supplies no immediate caller identity.
Native Workspace and Display need to bind an actually received request to its
actual current client before reading an associated shared window. A PID in the
packet or an ancestor trace origin cannot authenticate that caller.

Add two read-only Internal scalar operations, preserving every existing number,
bootstrap identity, Receive34 frame and scheduler/capability mechanism:

| Operation | Inputs | Successful outputs |
|---|---|---|
| SERVING_ORIGIN_INFO58 | All four operands zero | Status0, RSI descriptor0x0000000100080001, RDX0, scalar R10 preserved |
| SERVING_ORIGIN57 | Actual RECEIVE Endpoint capability, actual received full nonce, field0..7 | Status0, actual field in RSI, RDX0, compiler-live R10 preserved |

The separate description/hash is `SERVING_ORIGIN_ABI`, currently
`ea24cda47da0452d841bbba5509ab757b24c8321a94bbad4ebbedc5e9f14e5b8`.
Only the existing explicit native desktop executor implements these arms.
Other/older profiles refuse; consumers negotiate INFO before using QUERY.

| Field | Exact source |
|---|---|
|0| Immediate retained caller Thread's Process, resolved through the SAME Scheduler; diagnostic ID |
|1| Immediate retained caller Thread diagnostic ID, including its generation |
|2| Immediate registered Rpc::Thread.incarnation Token.number or0; never Context.root_incarnation |
|3| Retained CallId epoch |
|4| Retained CallId full serial |
|5| Full actual Endpoint object identity, including generation |
|6| Original accepted call's absolute deadline |
|7|0 live,1 cancelled,2 deadline exceeded,3 peer died |

The query takes no caller PID, thread, domain, incarnation, payload identity or
root assertion. It never returns a capability. None of these diagnostic numbers
authorize another resource or replace a live authority check.

## Required joins

Native dispatch derives the receiver from the actually running captured actor.
Its exact held Endpoint RECEIVE capability must resolve the live wire object,
receiver domain, bound thread and RPC delivery mode. The current pending row
must match that callee index, be delivered, match that wire, retain the exact
currently serving CallId, and have the full received nonce. Portable Rpc then
checks the held endpoint's full object identity against the retained Call's
endpoint and its registered route. Before actual Receive, wrong endpoint,
wrong caller, wrong nonce or unsupported field cannot pass this joined path.

`Rpc::serving_origin` independently checks the receiver's registered thread,
space, Job, Scheduler generations, actual Running CPU association and
nonterminated Process; its RECEIVE capability is reauthorized in that exact
live space. The caller is derived from Call/registered Thread and resolved
through that same Scheduler. Recycled/stale caller descriptors refuse rather
than naming replacement processes. Scheduler/Rpc/domain parameters supplied to
the portable accessor are trusted kernel captures, never wire arguments.

Cancellation/timeout ends a wait, not callee execution. Retained cancelled,
expired and peer-dead call context remains inspectable while the actual callee
execution reservation still exists. The query neither mutates outcomes nor
wakes, completes, releases credit, reuses a window or bypasses quiescence. An
as-yet unprocessed deadline can be reported expired without performing expire.
The original stored terminal outcome retains its normal precedence.

Completion/acknowledgement or actual callee retirement removes the reservation;
the old nonce then refuses. Full nonce/endpoint/thread generation checks prevent
reuse aliases. Read-only provenance cannot make a cancelled request live again
or turn a late reply into successful execution.

## Root anchoring and scope

Field2 is deliberately the registered immediate value. In the current desktop
executor, child registrations may share the captured Root/cohort token. Nonzero
field2 therefore does NOT prove that the immediate caller is Root. V5 services
must use their independently delegated Root-only control endpoint and actual
captured process/thread/lease anchor; app-controlled identity or a merely
nonzero token is insufficient. This extension changes no incarnation policy.

Portable tests cover actual cross-domain capabilities and distinct scheduler
processes, full-width nonces, nested immediate caller attribution, wrong
space/rights/endpoint/receiver, revoked capabilities, retained terminal context,
completion refusal and generation reuse. Decoder tests pin the exact additive
ABI and unchanged Receive34 shape. Native feature compilation checks the real
dispatch arms. These are not native delivery/VM, device or full M8 acceptance
proofs; actual wrong-caller/before-Receive/window fencing and joined runtime
qualification remain required with the supported V5 graph.
