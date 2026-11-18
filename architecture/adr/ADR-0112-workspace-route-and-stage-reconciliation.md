# ADR-0112 — Exact workspace route and stage reconciliation

Status: Accepted Internal Level B implementation; actual VM retirement pending.
Date: 2026-11-16
Related: ADR-0104/0105/0108/0110/0111; M8-03/04/08/13.

## Problem and separate proofs

Closing an Editor's local SEND handle or logically revoking its Workspace route
does not return an accepted RPC loan, retire escaped grant descendants or settle
durable staging. Previously the native service discarded its installed binding
on logical Revoke; a subsequent Bind could then overwrite Selection bytes while
the old grant or staged writer still existed. Files also retains an authenticated
namespace caller/session: restarting its process cannot simply choose a new first
caller on the old session.

Keep these facts separate: the cooperative Editor Released acknowledgment says
it stopped FileWindow access; Kernel managed-SEND retirement proves the exact
old branch/escrow/accepted-credit obligations drained; Workspace reconciliation
settles only its matching route and stage; actual backing flush has its own
completion. None of these alone supplies the other facts. A timeout never means
successful cancellation, stage abort or a reusable window.

## Root-only control and matching

Extend the Internal EVWSCT01 Root control with opcode3 `ReconcileFile` and opcode4
`ResetFilesNamespace`. Both use the existing256-byte frame on dedicated role16,
whose SEND belongs only to the measured Root controller. The native adapter
captures ServingOrigin before shared-window access and checks the actual serving
call and original deadline. Ordinary File and Files namespace frames cannot
select these commands. The immediate registered token is correlation, not Root
proof; exclusive actual capability distribution supplies the Root-only route.

ReconcileFile carries slot0..3, exact old process/thread/registered token, lease
and original32-bit grant nonce. It must match the retained installed binding and
zero-extended Bind request ID. Native Bind refuses wider IDs before installing
anything, rather than truncating Kernel44's nonce. Per-slot lease floors survive
retirement so a new request cannot reintroduce an old same-process lease. Full
File2 and namespace RPC request IDs remain64-bit.

Root constructs a private receipt only from its actual held Process CONTROL,
matching negotiated Kernel retirement response and original delivery journal.
A never-delivered rollback needs actual setup proof that no branch, escrow or
call was delivered. The serialized old-owner fields do not independently prove
Kernel retirement inside Workspace; this is an explicit trusted Root adapter
obligation. No user packet marker or caller-nominated PID can replace it.

## Reconciliation behavior

Logical Revoke marks the old route inactive but retains its native installed row.
Bind remains Busy until separate reconciliation. The safe gateway refuses active
routes, any pending file/namespace work or verifier, poisoned/mirror-recovery
state and prior retirement uncertainty. It never clears a pending request or
immutable proposal to make a retry succeed.

Only a known stage whose route key, stable object, base revision, full length and
digest match the old binding can be aborted. The trusted backend allocates the
abort's global operation; the wire cannot choose it. Exact durable Aborted receipt
is required. Another route's stage returns Busy; a cold orphan/inconsistent stage
remains preserved and fenced for independent recovery. Committed bytes, file
revision, object identity and namespace are not replaced by abandoned content.

`Dataset::sync_quiescent` requires live mirrored metadata and no stage, then waits
for the actual SectorIo flush under the original deadline. Any flush/receipt
ambiguity retains the route and permanently fences future binding and storage
handoff. Only after matching abort and flush does the gateway clear that route.
This method does not establish external device or shared-window owner retirement.

ResetFilesNamespace matches only the old retained Files caller/thread/lease.
After Root separately proves old caller and endpoint work stopped, it revokes and
retires the exact namespace key without disturbing Root's separate namespace or
minting File access. If Files never issued a request, explicit Root reset can be
a no-op only when no global pending/fenced work exists. It is not an automatic
first-caller reset. Dedicated fixed Files SEND and the new measured process still
determine the next possible caller.

The actual actor remains permanently quarantined after unknown accepted work;
it cannot service a new control message in that state. Busy/stale definite
responses and retained uncertainty are distinct. Unsupported hot reconciliation
requires independent process/device retirement and cold recovery. Every Root
control/namespace adapter must retain its own shared window on timeout, malformed
reply or Uncertain status; no fresh constructor or counter returns that credit.

## Evidence and remaining acceptance

Focused service25 and store15 tests include active/stale key refusal, exact
committed identity after retirement/cold open, known-stage abort without publish,
foreign-stage protection, accepted/uncertain verifier retention, actual flush
failure after persist, cold orphan preservation, separate namespace replacement
and namespace uncertainty. Earlier mutation/cut suites remain intact. Native
typecheck/strict lint/link and stack census are component preflight only.
Actual Kernel61 plus broker/service retirement, death/timeout behavior, checked
shutdown, cold recovery, protected discard consequences and sustained use still
need the integrated M8 VM evidence.
