# ADR-0055 — Source Root self-notification progress

Status: Accepted bounded repair; source checks and five-cold System regression pass.
Date: 2026-11-11. Founder engineering mandate Level B.

## Measured failure

The third composed attempt (local engineering archive)
reaches actual App/Shell faults and replacement but stops at Shell restoration.
All651 RPCs complete and CPU quotas have room. **Events is full with four
messages**, unlike the empty RPC queues. Three accepted messages came from Root;
one came from the replacement Shell. Root's terminal RIP resolves in the exact
retained ELF to the blocking `desktop::send` retry, with SEND returning Busy.

The replacement Shell's second surface is independently verified as Home. Its
InputRestarted acknowledgement therefore still needs Root to consume it before
AppRestored, visible App chrome and another genuine App Present can complete.
The recovery handler sends InputRestarted then the unused EVSHNEW1 self-marker.
This source order and actual state identify a self-mailbox progress cycle; the
dynamic terminal payload was not separately logged. The observer correctly
rejects an old App frame rather than relabelling it restored.

The original failure diagnosis incorrectly said all queues were empty. The
immutable raw trace already contains the full Events state; a
correction record (local engineering archive)
preserves that distinction without rewriting the original evidence.

## Repair

Remove thirteen sends across nine obsolete marker kinds with no consumer in
Kernel, actor, host or generated Rust code: EVHOME01, EVAPNEW1, EVGRQUE1,
EVGRREF1, EVPICK01, EVSHNEW1, EVGRANT1, EVCANOK1 and EVAPDEAD. Actual readiness,
process lifecycle, protected Present, grant delivery and framed diagnostics
remain the evidence sources; these unused packets add no authority or proof.

EVHOLD01 has a real consumer and remains. Its original current-picker, readiness,
unsubmitted, interactive-mode and64-tick conditions stay fixed. Root attempts
one nonblocking send per ordinary tick. Success alone marks the existing
`held_reported` field; Busy leaves it false, so the next receive/tick can drain
Events and retry. No new queue, object, capability or wire field is needed.

The existing framed diagnostic/report and EVNFIN01 paths already retry without
blocking Root's ordinary event loop and remain intact. Peer-control sends,
Kernel observers, health/world deadlines, quotas and Present requirements are
unchanged. This repairs self-notification progress; it does not accept a
synthetic input or redraw, or declare broader transport behavior proved.

## Verification

Root42 and M4 policy19 tests, strict Native/M4 source-bin target checks and
formatting pass. Independent source/consumer and renderer reviews agree with
the recorded failure. Require fresh actual composed System execution and the
later M4/Native selected-file regressions, including real held64 evidence,
Shell/App restoration, full cleanup and source/disk joins. No complete System
or0.1 acceptance follows from the source repair alone.

The next actual five-cold System cohort (local engineering archive)
passes the strict full Shell/App restoration and all subsequent recovery phases,
with actual fresh App Present, ten validated timings and complete retirement.
No observer, deadline or resource condition was weakened for that pass. Later
M4/Native permission/current-source cumulative regressions remain separate gates.

Current-source regressions also pass: six-cold Native lifecycle (local engineering archive),
four-cold owner permissions (local engineering archive),
M4 surface (local engineering archive)
and full M4 desktop (local engineering archive).
These exercise genuine held64 notification, selected-file denial/cancel, cold policy,
App/Shell restoration and unchanged retirement bounds; final cumulative readiness
is recorded separately.
