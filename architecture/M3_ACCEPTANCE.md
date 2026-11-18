# M3 persistent-machine engineering acceptance

Status: **PASS — bounded Internal reference-machine scope**, 2026-10-27.
The owner authorized continuous implementation through 0.1. M0 remains frozen
at `m0`; no historical proof, commit, push or publication is changed here.

The portable cumulative evidence (local engineering archive)
passes **103 checks**, **278 kernel host tests**, complete equivalence of **273
code inputs**, and unchanged separately recorded validator sources. It retains
16 preceding positive/expected-negative boot runs and eight storage workflows
covering 41 actual VMs. Raw snapshots, actual serial/input/results, manifests,
component images, logs and the tested uncommitted compiled source bytes are
preserved. Older component captures retain their original complete-tree hashes;
this gate explicitly verifies complete current-code equivalence rather than
claiming documentation fingerprints never changed.

| Required gate | Executed result |
|---|---|
| E-025.34–38 / R-011.16: persistent block path and logical File/Object boundary | Isolated userspace non-DMA PIO backend, protected shared transport, ordinary app→File→block nested calls and immutable scoped object bindings. VirtIO is preferred in E-025, not mandatory; ADR-0042 records this reference choice. |
| E-025.39 / AF-011: interruption-safe durable subset | Fifteen fresh VMs, six actual fault plus owned-QEMU abrupt kill/reap boundaries, original-ID replay, old/new committed data and write-refusing independent raw observers. |
| E-025.40–41 / AF-010: coherent immutable generations and KnownGood | Exact retained kernel/controller/driver/A/B/ABI/health binding, staged broken B, actual page fault, cold automatic A and manual A after fresh candidate activation. |
| E-025.41 / A-014: genuine health failure | Separately measured silent B remains live past its actual progress window; typed MissingProgress commits without a fabricated exception, then ordinary stop/reap and cold A. |
| E-025.42–43: usable independent recovery | Actual UART identifies failed B and pending3/KnownGood1; prompted complete commands cause actual A execution. Cancel, timeout, invalid input and EOF never authorize writes. Two actual live-stdin CLI recoveries use private imported working copies and preserve the source snapshot. |
| E-025.44: mutable state survives rollback | Data B and the original failure capsule survive automatic/manual recovery, success, journal/manifest reuse and unchanged cold Verify. |
| Resource, authority and lifetime guarantees | Actual protected calls/waits/replies, authenticated current process facts, frame/mapping retirement and child/ancestor CPU accounting remain checked. |

The cumulative runner deliberately labels its raw result a subset, rather than
automatically promoting a milestone. This separate reconciliation accepts the
composition against E-025.34–44 and R-011.16. M3 readiness
and the [boot-health contract](designs/BOOT_HEALTH.md) define the accepted limits.
A-014 is verified for concrete Started, probation and KnownGood criteria: exact
measured admission, timely current CriticalReady, durable storage probe and fresh
liveness before durable promotion. Generic Ready alone is insufficient.

Controlled pending attempts and nonwrapping serials are implemented and covered
by portable policy/publication tests. Repeated cold physical attempt exhaustion,
no-KnownGood and some corruption branches remain model coverage; no separate
physical claim is made. The actual suites prove first-fault and first-missing-
progress rollback. M2 Root-custodian retry limits are a different mechanism.

The File backend is one logical object with 224 payload bytes and bounded LAST
receipt retention, not a complete filesystem. Integrity checks and measured
local development bundles are not production publisher authentication. VM
restart/flush/interruption does not certify physical host power loss. Recovery
independence covers failed normal critical services and absence of desktop,
normal File service, network and AI; arbitrary storage corruption, DMA-bearing
Root recovery, general shared-buffer cancellation and SMP userspace need their
own proofs. Automated live stdin is not human-interaction acceptance.

The first cumulative selection failure (local engineering archive)
is preserved. Its nested evidence announcements were incorrectly treated as
multiple suites; 21 adversarial tests and the successful combined rerun verify
the corrected strict top-level selector. Earlier journal/deadline/retirement
failures remain linked from M3 progress.

M4 graphics/input/shell, M5 native `.zion` identity/lifecycle/picker/provider and
the complete 0.1 demonstration remain required. This acceptance advances the
engineering milestone; it does not declare a consumer-ready operating system.
