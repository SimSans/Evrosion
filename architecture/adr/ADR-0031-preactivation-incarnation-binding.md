# ADR-0031 — Pre-activation incarnation binding and scheduler admission hold

Status: Accepted
Date: 2026-10-19
Owners: Project owner; kernel/platform maintainers
Related: ADR-0011, ADR-0027, ADR-0030, INV-AUTH-004, INV-AUTH-007, INV-KERN-004

## Problem

The measured manifest, authority branches and scheduler identities were separate
primitives. A lifecycle event could not identify which process, Job and measured
authority it concerned. The scheduler also made every newly created process's
threads eligible for dispatch, which is unsuitable while a bootstrap attempt is
still being validated.

This additive Internal mechanism implements part of the existing custody design.
It changes no foundational guarantee or historical acceptance. Existing M1 process
creation keeps its behavior; new bootstrap preparation opts into an admission hold.

## Held scheduler process

`create_held_process` creates an accounted process whose threads cannot dispatch on
any scheduler CPU slot. The hold is process-wide, including subsequently created
threads. Other processes continue to dispatch. Held processes can be terminated
with the existing balanced accounting. `held_process_job` rejects ordinary or
terminated processes and returns the actual Job; `job_limits` exposes its bounds.

There is deliberately no hold-release API yet. Releasing admission must be coupled
to verified executable loading and the eventual activation transaction, not a
caller-supplied boolean. The library gate is exercised in the kernel fixture; it
does not yet launch a real supervisor or configure its hardware address space.

## Bound identity

`incarnation::Bindings` is a non-Clone boot-lifetime record. It borrows the measured
manifest and trusted catalog, retains the custody domain and keeps at most one
current binding. A trusted boot owner supplies a nonzero boot epoch and must retain
one record with the same Authority and Scheduler instances. Boot epoch generation
and singleton sealed runtime ownership remain integration requirements; this API
does not manufacture entropy or enforce global uniqueness across kernel objects.

Preparation validates the held process's actual Job and exact manifest Job limits.
Under an immutable scheduler borrow and exclusive authority borrow, it reserves a
checked incarnation number and atomically installs the measured scoped grants.
Only after success does it publish a token containing:

- boot epoch and incarnation number;
- actual scheduler process and Job identities;
- measured manifest and actual authority-set digests;
- generation-checked destination and private branch domains.

The destination-to-process association is established by this trusted binding;
there is no userspace API accepting arbitrary target IDs. Scheduler/authority IDs
remain instance-local. Token copies are kernel event identifiers, not capabilities,
duplicated custody records or serializable durable grants. Every event checks the
entire identity. Private branch handles are retained inside the record; only exact
destination-local user grants can be retrieved for a matching bound token.

## State and failure boundary

The current phases are **Empty → Bound → Revoked**, with a latched
**RecoveryRequired** state for integrity/installation/sequence failures. Bound is
not ACTIVE. Invalid process/Job descriptions create no authority and consume no
number. An installation attempt reserves its number before minting; failure
publishes no token, preserves atomic grant installation and latches its diagnostic.
Counters never wrap. Subsequent calls cannot reset recovery or its first reason.

Revocation checks the token before touching authority, then revokes the complete
branch group and updates the phase under the same exclusive borrow. Matching
repeated teardown is harmless. If private branch custody was damaged, the record
latches recovery rather than reporting successful revocation. Further teardown
may still attempt to remove authority; it cannot clear the recovery latch.

No replacement or reset operation exists yet, even after revocation. Private
branches remain pinned. Revocation does not prove stopped CPUs, unmapped memory,
drained IPC/DMA or resource quiescence. The next lifecycle integration must obtain
actual teardown evidence before releasing this record for another attempt and
must consume the existing restart budget before replacement creation. It must not
add a generic `quiescent=true` escape hatch or recreate the record to reset it.

## Validation and remaining work

Host tests cover all eight token components, Job/limit mismatch, unheld/terminated
processes, every scheduler CPU slot, new siblings, unaffected peer dispatch,
sequence overflow, digest failure without partial grants, latched diagnostics,
group revocation, pinned branch lifetime and refusal to treat revocation as a
replacement permit.

The kernel fixture prepares two isolated simulated epochs, verifies foreign-epoch
events are rejected while current grants remain valid, checks held processes do
not dispatch while a peer does, rejects a wrong Job budget, and revokes each group
while preserving custody roots. These are prepared fixtures, not a reboot,
supervisor crash/replacement or SMP runtime proof. The image bytes remain `abc`.
Strict serial/evidence parsing and the cumulative regression guard these claims.
Executed evidence is linked in M2 progress.

Remaining work: trusted boot epoch/bundle selection, sealed runtime ownership,
validated executable/address-space construction, atomic activation, real
revocation/quiescence, repeated descriptor lifetime, restart admission integration
and independent recovery. Full AF-007A–H remains pending.
