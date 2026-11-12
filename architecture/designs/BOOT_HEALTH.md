# Initial boot-health contract

Status: Verified — bounded M3 engineering acceptance
Date: 2026-10-27
Audit action: A-014
Authority: E-012; E-019; E-025.34–44; ADR-0044

This is the bounded Internal reference-machine contract. It gives Started,
probation and KnownGood distinct meanings. It does not declare every future
service, production boot authentication or continuous post-promotion monitoring
implemented.

| State | Required facts |
|---|---|
| Selected | A coherent immutable manifest resolves to the retained kernel input, controller, driver, exact critical image, ABI and health contract. Selection alone says nothing about execution or health. |
| Started | BeginBoot has durably charged a fresh serial/attempt; the ordinary measured Registry has admitted and started the actual process/thread with the exact image and scoped grants. Held images and user-supplied identifiers do not count. |
| Probation | An Admission record durably binds that generation, serial, actual process stamp, image, cohort, ABI and health version. Existing KnownGood remains protected. Generic Ready records startup only. |
| Critical success | Authenticated events from the current actual process/thread deliver GenericReady then CriticalReady before its single progress deadline. Required check bits are satisfied, a durable mutable-object write/flush/readback probe succeeds, and a fresh lifecycle observation confirms the service is live. |
| KnownGood | A matching Health(CriticalPassed) operation commits durably. A boolean, event payload PID, stale serial or merely successful Start cannot promote a generation. |

The two named initial check families are `HEALTH_STORAGE=1` and
`HEALTH_SUPERVISOR=2`, giving required checks 3. The measured critical process
validates its startup and grants before emitting CriticalReady; the controller
independently performs the storage probe. The userspace controller owns policy;
the kernel supplies capability enforcement, actual admission/lifecycle/event
provenance and bounded diagnostic observations.

The first actual LIVE observation anchors one progress deadline at most 64 ticks
later, additionally bounded by the earlier retained controller stop. The physical
MissingProgress proof independently requires at least 64 actual live ticks.
Draining messages, unrelated events or another observation never extends it.
Clock reversal/overflow refuses success. A live process without timely critical
readiness produces `MissingProgress`, with the current matched admission and
storage probe. The controller commits failure/selection and stops/reaps the
live process through ordinary control capabilities. No exception or Fault Record
is invented. A genuine process fault instead records its actual process/thread,
vector, error, address and instruction and commits `ProcessFault`. Failed initial
probation without KnownGood latches recovery rather than inventing a good image.

The Store policy permits three consecutive pending-generation attempts in this
fixture. Boot serials, operation IDs and generation high-water values are durable
and never wrap. Attempts remain charged within the selected unsuccessful
probation; automatic retry cannot reset them. Matching successful health, staging/
activating a new generation, and explicit rollback/owner selection start a new
per-selection attempt state. Budget exhaustion selects
protected KnownGood or latches recovery. Its optional process stamp must be
truthful, including absence when no admission occurred. Portable tests cover
attempt exhaustion, interrupted publication/recovery and counter exhaustion;
the present physical suites prove first-fault and first-missing-progress
rollback, not repeated cold-attempt exhaustion. M2 Root Custodian restart tests
are a separate mechanism and do not substitute for that storage proof.

The committed LAST-failure capsule preserves failed generation/image, serial,
attempt, named cause, actual optional admission stamp and original operation/
sequence through later success and journal/manifest reuse. Automatic recovery
and explicit owner selection preserve mutable object bytes. Owner cancellation,
timeout, invalid input and EOF never authorize selection or writes.

Executed subset evidence is linked from [M3 progress](../../docs/release/0.1-preview.md#validation-and-provenance):
actual fault and missing-progress generations, current-v2 interruption/replay,
scoped File/Object access, owner UART commands and private-snapshot live CLI.
The [103-check cumulative gate](../../docs/release/0.1-preview.md#validation-and-provenance)
and [M3 reconciliation](../M3_ACCEPTANCE.md) now verify this bounded A-014 scope.
This does not certify continuous health monitoring or every physical exhaustion/
corruption branch.
