# ADR-0107 — Read-only Job inspection through retained Process CONTROL

Status: Accepted Level B refinement; portable host qualification only.
Date: 2026-11-15
Related: ADR-0047/0103/0105; M8-01/05/08/12; E-004/E-007/E-009/E-015/E-020/E-023/E-026.

## Problem and evidence

The V4 graph supplies 29 startup handles, 17 channels and 16 child
Job/ProcessCONTROL handles. Before ADR-0103's source retirement, two retained
downloaded image handles reached its 64-slot boundary while selected delivery
needed an additional temporary slot. ADR-0103 retired one unused READ source,
leaving the accepted 0.3 live set at 63 before selected delivery. Larger
M8 graphs need deliberate handle lifetimes, not a broad capability-budget raise.

Root currently uses child Job CONTROL both for actual setup and for read-only
Job usage/limit inspection. The Kernel Registry already retains the admitted
process's exact generational Process/Thread/Job association independently of
the local userspace Job handle. The existing retained Process CONTROL can safely
select that same admitted process's Job for read-only facts without minting or
reconstructing a Job capability from a diagnostic integer.

## Decision and separate negotiated contract

Add two unused Internal scalar numbers, without changing existing numbers:

- `PROCESS_JOB_INFO = 55`: RDI is an installed retained Process CONTROL handle;
  RSI selects fields 0–8; RDX must be zero. As with existing scalar JobInfo,
  R10 is compiler-live and preserved. Success returns status 0 and the field
  value in RSI; denial returns status 1/value zero. RDX is cleared.
- `PROCESS_JOB_INFO_INFO = 56`: all four operands must be zero. Success returns
  descriptor `0x0000000100090003` in RSI and clears RDX/R10. A caller must check
  this exact descriptor before relying on query 55. Older or unsupported
  profiles refuse the unknown operation; they do not invent compatibility.

The separate extension has its own `PROCESS_JOB_INFO_ABI_DESCRIPTION` and SHA-256
`9b4e5357bf8d5c9b58429e0d601fbc6068499621731cc00fbff8736ef6aa80fe`.
Original bootstrap ABI and port-batch identity constants remain unchanged;
JobInfo42 keeps its original behavior. Changed source/build/Kernel artifacts
require their own distinct identities and qualification. This is an additive
Internal extension, not a new Stable platform API.

The two actual dispatch arms are confined to the existing `test-m5-native`
profile family, which includes the reference native/network/document profiles.
Other runtimes retain their unsupported-call fallback. INFO alone confers no
authority. QUERY still requires the complete retained Process CONTROL capability
in the actual dispatched caller's domain.

## Authority and lifetime checks

The kernel derives caller metadata from its captured current dispatch, never
from user-provided process, Job or domain numbers. The portable query verifies
that the caller's domain is live, its exact generational thread/process/Job
associations match, the process is not terminated and the thread is Running.
Domain association remains the trusted dispatch controller's responsibility;
the scheduler contains no separate user-selectable domain ownership table.

The Registry `retained_metadata` path authorizes full Process kind and CONTROL
rights on the exact domain-local handle/object generation. The row must have
been admitted and remain in its Active registry phase. Its actual scheduler
thread/process/Job generations must still match. This includes a terminated
process while its stopped context remains retained before registry retirement.
Held, retired, reclaimed, stale-generation and unknown rows fail. The separate
`active_metadata` path for live grants continues to deny terminated processes;
the diagnostic adapter never opens that grant path. Handle zero is not a self
shortcut, and raw PID/Job diagnostics are never lookup operands. Another domain's
equal numeric handle does not select that domain or its objects.

Only after these checks does the query read the same fields as JobInfo42:
0 is diagnostic Job identity; 1–4 are hierarchical CPU/frame/process/thread
usage; 5–8 are the corresponding declared limits. Full scheduler Job generation
is validated even for diagnostic field 0. The operation is read-only and neither
changes accounting nor installs capability slots, grants, new rights or authority
to create/restart/reap a Job. Invalid fields and reserved operands fail without
truncation or partial interpretation.

## Selected M8 handle lifetime

The isolated `workspace-runtime` Root feature consumes child Job CONTROL only
after CREATE_PROCESS, every DELEGATE/BIND_RECEIVER and actual START/ProcessIdentity.
It first negotiates descriptor56 and compares the exact Job identity returned by
both live controls. A held candidate retains its Job control until start or
explicit stopped/reaped discard. Other existing features retain their original
Job handles. The private Actor marker zero means consumed setup authority and
is never sent to JobInfo42, where zero means Root's own Job.

All graph endpoints are created through retained CreatorJob, not these child
handles. Restart creates a new bounded child Job through that creator. No
same-Job process creation/restart authority is required by this graph. The Kernel
Registry independently retains the old admitted Job/accounting, and its managed
Job collection refuses reclamation while process rows, accepted RPC references,
physical/authority owners or usage remain. Closing the userspace handle does
not refund ancestor CPU usage or bypass process/device/shared-window retirement.

Native diagnostics select the child's Job through retained Process CONTROL,
including the stopped crash-collection interval before REAP. The collector binds
that exact control to its captured fault identity and Job identity. REAP and
CONTROL closure still make the query fail. Cleanup skips an already-consumed
Job handle; held-candidate cleanup requires its retained nonzero setup handle.

This saves one Root-local capability per started child without raising ordinary
16/control64/node256 limits. It does not establish the final V5 graph budget or
any VM/runtime lifetime result. Those require actual optimized graph/resource,
crash/restart and repeated-retirement qualification.

## Validation and claim boundary

Portable host tests compare all nine fields with the old Job-capability query,
show that CONTROL alone suffices without becoming a Job/READ capability, and
check that metadata/accounting remain unchanged. Negative cases cover wrong
kind, insufficient rights, zero/unknown/foreign/closed/revoked handles, high
generation bits, closed/reused capability slots, held/retired/reaped
processes, retained stopped inspection and a retained active row with replaced scheduler generations.
Caller associations/running state and invalid fields are checked separately.
Existing capacity tests retain ordinary 16/control 64 behavior.

Decoder tests bind the separate descriptor hash and require exact INFO reserved
operands, full-width QUERY handles, fields 0–8, RDX zero and preserved scalar
R10. Original JobInfo42 tests and body remain unchanged. The first host run
retained an invalid zero-role fixture failure; it was corrected to the existing
verified two-role descriptor without weakening admission checks. All command
logs/receipts remain below the isolated M8 task directory.

Host mechanism/decoder tests do not execute the binary syscall adapter, execute selected Root handle retirement or qualify M8 VM/resource acceptance. Target compilation,
actual negotiated calls, optimized stack/image/frame/handle measurements,
negative VM behavior, restart/lifetime integration and current-source regression
remain necessary before this refinement is included in an accepted checkpoint.
