# ADR-0101 — Phase-local bootstrap and update record storage

Status: Accepted and independently qualified Level B implementation refinement; adopted in engineering Main.
Date: 2026-11-15
Owners: Kernel and Root Supervisor maintainers
Related: ADR-0050, ADR-0065, M6-S03, INV-KERN-004, INV-RES-001, INV-LIFE-002, INV-LIFE-003, INV-LIFE-004

## Context

Accepted snapshot14's optimized reference Kernel census is 257,520 bytes
(257,824 in the negative profile) against a 262,144-byte boot stack. Root's
fixed-reference census is 31,368 against its guarded 32,768-byte private stack.
These are actual linked prologue/reference censuses, not formal worst-case or
runtime high-water bounds. The source/artifacts and original limits are retained.

The Kernel entry closure keeps temporary one-time memory-map construction
storage in the frame that also owns the long-running controller. Root constructs
and validates large immutable next-record values while retaining the affine
Store needed for the later canonical commit. Separating phases can reduce
overlapping scratch without changing ownership or admission semantics.

## Decision

1. Put the existing `MemoryMap::take()` and `BootstrapFrames::new()` sequence in
   a private helper kept out of line only for the M6 network profile and inlined
   for finite profiles. It consumes the same validated map once,
   with the same refusal/panic semantics, and returns the sole allocator owner.
   Temporary map construction ends before the runtime controller is entered.
2. Extract syntax-only next-record construction for Known Good and local
   selection decisions into private non-inlined helpers borrowing the same
   Store and State. Keep the existing binding, selected-content, genuine-health,
   revision-overflow and record-validation checks and their error mappings.
   Pass the resulting record and the same affine Store to the unchanged
   `begin_record_into` / Cold / Commit path.
3. Keep guarded stack sizes, image/admission/resource ceilings, protocol/ABI,
   checkpoint format, time/freshness rules and all authorization/recovery
   semantics unchanged. No heap, global mutable controller or copied Backend
   is introduced.

## Invariants preserved

The checked map transfer still cannot reset/duplicate the allocator. Store and
Backend ownership remain affine on success and refusal. Record preparation
grants no new authority or health status and performs no I/O. Full canonical
cold authentication, durable publication and readback remain required.
User data, replay floors and protected Known Good remain separate from candidate
selection. No network/update policy moves into the privileged core.

## Alternatives considered

Increasing stack budgets would leave avoidable overlapping scratch in place.
Removing validation, retirement, quota or health checks is unacceptable. A
non-inlined Store-extraction experiment did not improve the Root census and is
not adopted. More extensive resident-owner API changes would widen this repair
without evidence they are needed. The separate unsuccessful IPC experiments
remain outside Main and do not justify a change to scheduler/ABI behavior.

## Consequences and failure analysis

Only private function boundaries change. This depends on the pinned compiler's
actual linked output; future compiler/profile/source changes require a new
census. Additional function boundaries may affect code size or timing, so the
existing IPC and actual VM checks remain necessary. Return errors still retain
the same owner; no open failure provisions or resets trust/data.

## Verification

All seven actual optimized reference profiles pass: Root 28,296/32,768 bytes;
ordinary Kernel 238,032/262,144 and negative Kernel 238,352/262,144. Root image
and private-frame counts stay within the unchanged limits. Fourteen host/target
commands, signed B health/C failure/offline B recovery with later edits, owner
exercise/first-use/cold opening and six network failure/endurance workflows pass.
A fresh same-host source build at another path matches 127 entire target files.
The selected scoped IPC cohort shows no additional observed batch cost against
the prechange 0.2 replay; the remaining roughly 16% 0.1 gap is not fixed.

The stabilization record binds exact
source/artifacts, all receipts, analyzer limits, graphical Saved/cold reopening
and guarded Main adoption. Its separately tested host-only clock audit fix is
not a change to the guest mechanisms decided here.

Required checks include existing Root/Kernel host and refusal tests, strict
bare-metal checks, all seven affected reference profiles, actual signed B
health/C failure/offline B recovery with later edits, owner UI/data reopening,
network failure/endurance and an unchanged-method IPC comparison. Keep failed
attempts, existing analyzer limitations and complete process/resource retirement.

## Migration / rollback

There is no data/format/ABI migration. Preserve the three original source-file
preimages and adopt only after qualification; reverting those implementation
changes leaves existing data and the accepted snapshot14 available. Do not reset
the owner's working tree or label a new whole source as snapshot14.

## Expiry or review trigger

Review on compiler/profile changes, growth of the relevant controller/record
types, a stack/admission refusal, or a new asynchronous/interrupt/nesting path.
These censuses do not close the general worst-case stack-analysis obligation.
