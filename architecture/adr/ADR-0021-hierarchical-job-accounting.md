# ADR-0021 — Hierarchical Job accounting and admission

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: E-023, PRE-M0 §43, ADR-0011, INV-RES-001–002

## Decision

Extend the scheduler's existing Job objects with bounded parent ancestry and
separate limits/usage for resident frame claims, live processes, live threads
and sampled CPU ticks. Do not introduce a second resource ownership model.
Parents exist before children, identities are retained, and ancestry traversal
is bounded by eight Job slots. Factories remain trusted bootstrap operations;
this does not expose an unguarded userspace Job creation or limit-changing API.

Admission preflights all affected resources at every ancestor before mutating
any count. Parent pressure, overflow or release underflow leaves the whole chain
unchanged. Process/thread slot and lifecycle checks precede charges. Thread exit
releases its live-thread charge; process retirement releases the process and
any remaining ready/blocked siblings together. Charges for retained backing may
outlive the process and remain attributed to its original Job until final release.
Metadata slots themselves are still retained, so live-resource budgets and fixed
slot capacity are distinct constraints.

The BSP runtime attributes its fourteen private frames and one shared backing
frame per pair to the two process Jobs under one parent. The shared frame remains
charged to its creator even while a peer holds a mapping/grant. Charges return
only after quiescent physical reclamation. IRQ0 samples charge the selected
process Job and all ancestors. Independent per-thread hardware tick counts must
match the Job ledger; cumulative CPU usage is not erased by process retirement.

## Verification and limits

Host tests cover sibling pressure at a parent limit, atomic multi-ancestor
rejection, underflow/overflow, slot-preserving process/thread admission failure,
retirement release and CPU attribution to the current process. Hardware checks
cover nine Jobs across three pairs, 45 attributed frame claims, rejection of an
extra frame beyond a child's limit, and zero remaining live frame/process/thread
charges after teardown. User CPU charges must match the runtime's IRQ count.

Ticks are samples of execution, not precise elapsed CPU time or wall-clock time.
The bootstrap runtime uses ample finite CPU limits; general quota replenishment,
throttling policy and accounting of controller/interrupt work remain pending.
Static bootstrap allocation is charged before processes run; a future public
allocator must combine admission, fallible allocation and rollback before
publishing a resource. Storage, device, GPU and network budgets remain separate
later mechanisms. This supplies the M1 Job/accounting skeleton, not the complete
E-023 resource-policy service or a claim of integrated M1 acceptance.
