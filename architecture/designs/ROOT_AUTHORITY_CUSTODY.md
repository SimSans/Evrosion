# Root Authority Custody & Reconstitution

Extracted from the [Pre-M0 implementation package](../plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This is a public technical edition of the canonical record. Published source
hashes and original lineage are recorded in the architecture source map.

Status: Verified for the bounded Internal M2 profile: AF-007A–H pass the
[accepted cumulative gate](../M2_ACCEPTANCE.md). Userspace runs on the BSP with
AP parked and no delegated device/DMA authority. Production generation/epoch
authentication and M3 persistent rollback remain separate. Dated sections below
preserve their original checkpoint scope.
Maturity: Internal. Related action: A-001.

## 7. Decision summary

Evrosion will use a tiny kernel mechanism called the **Bootstrap Authority Custodian** (BAC) to hold sealed custody of the initial authority roots described by the immutable Bootstrap Manifest.

At most one **Root Incarnation** is active at a time.

The Root Supervisor receives derived, incarnation-scoped capabilities. It never receives ownership of the sealed custody domain itself. If it fails, the kernel revokes the entire failed incarnation subtree, proves quiescence, increments the incarnation number, and creates a fresh Root Supervisor with a capability set whose canonical digest exactly matches the manifest.

This is custody and reconstitution—not a permanent all-powerful kernel policy engine.

## 8. Goals and non-goals

### Goals

- Root authority is not trapped in one fragile userspace process.
- Restart never duplicates authority.
- The canonical initial authority set is deterministic and auditable.
- Catastrophic supervisor failure has a bounded recovery path.
- The kernel mechanism remains policy-poor.
- Capability lineage supports reliable revocation and testing.

### Non-goals

- Keeping all userspace services alive across Root Supervisor catastrophe.
- Persisting runtime capability handles across boots.
- Giving the kernel knowledge of high-level service policy.
- Making the Root Supervisor omnipotent outside the manifest-defined bootstrap domain.
- Solving durable user grants; that remains A-003.

## 9. Objects and records

### 9.1 Bootstrap Manifest

An immutable, measured boot artifact containing:

- root supervisor image digest;
- allowed executable object;
- canonical list of bootstrap object selectors;
- rights and constraints for each derived capability;
- initial Job resource limits;
- restart budget and escalation policy;
- contract/ABI fingerprints;
- expected canonical authority-set digest.

The manifest contains descriptions, not runtime handles.

### 9.2 Bootstrap Authority Custodian

A kernel object created once per boot epoch. It contains:

- sealed references to bootstrap authority roots;
- the measured manifest digest;
- boot epoch;
- current incarnation counter;
- state machine state;
- active Root Incarnation Token, if any;
- a restart-rate counter;
- bounded audit records.

No userspace task receives a capability that can mutate, duplicate or destroy the BAC.

### 9.3 Root Incarnation Token

A unique, non-transferable kernel token bound to:

```text
boot_epoch
incarnation_number
root_process_object
root_job_object
manifest_digest
authority_set_digest
```

All capabilities minted for the incarnation are descendants of its revocation node.

## 10. State machine

```text
SEALED
  → SPAWNING
  → ACTIVE
  → REVOKING
  → QUIESCENT
  → SPAWNING (next incarnation)

Repeated failure or integrity failure:
  → RECOVERY_REQUIRED
```

Only kernel transitions may change this state.

### 10.1 Initial activation

1. Verify the Bootstrap Manifest and root image against the selected System Generation.
2. Construct the bootstrap objects and sealed BAC.
3. Create a fresh root Job and Root Supervisor process.
4. Increment the incarnation counter from zero to one.
5. Create a Root Incarnation Token.
6. Mint the exact manifest-described derived capability set into a previously empty root capability table.
7. Canonically hash object class, stable boot-local object identity, rights, constraints and lineage root.
8. Compare with the expected authority-set digest.
9. Mark ACTIVE and schedule the process only after the comparison succeeds.

### 10.2 Failure and reconstitution

Root failure includes unhandled fault, explicit fatal exit, integrity check failure, lost mandatory heartbeat after independent liveness confirmation, or kernel-detected corruption of its execution context.

On failure:

1. Atomically change ACTIVE → REVOKING. No new grants may derive from the failed incarnation.
2. Deschedule the failed root thread(s).
3. Revoke the incarnation lineage node. All descendant capability lookups begin failing.
4. Terminate or quarantine the failed root Job and its bootstrap-managed descendants.
5. Drain in-flight IPC and DMA according to object-specific revocation rules.
6. Wait for kernel reference quiescence; bounded timeouts escalate to forced teardown or recovery.
7. Assert that no live capability remains under the old incarnation node.
8. Mark QUIESCENT.
9. Apply the restart budget. If exceeded, enter RECOVERY_REQUIRED.
10. Create a fresh root Job/process from immutable measured content.
11. Increment the incarnation counter and mint the exact canonical set.
12. Compare the new digest with the manifest and previous expected digest.
13. Mark ACTIVE only if all checks pass.

There is never a state with two ACTIVE incarnation tokens.

## 11. Delegation and service lifetime

The Root Supervisor may attenuate and delegate capabilities to the service graph. Those grants remain descendants of the current Root Incarnation Token.

For the first implementation, catastrophic Root Supervisor failure tears down and reconstructs the entire bootstrap-managed userspace graph. This is intentionally conservative. It avoids orphaned authority, ambiguous ownership and attempts to infer which old delegations are safe.

Later, selected services may survive root reconstitution only through a separate, explicitly designed stable-custody contract and ADR. Survival must never be inferred merely because a process is still running.

Ordinary non-root service crashes do not trigger this global path; their supervisor restarts them inside the current incarnation and unrelated services continue.

## 12. Concurrency and atomicity requirements

- The ACTIVE token pointer is changed with one kernel synchronization domain.
- Capability derivation checks the token state before commit and is linearized with transition to REVOKING.
- Revocation marks descendants invalid before teardown begins.
- A capability lookup racing revocation either completes under the old valid epoch before the revocation linearization point or fails; it cannot acquire post-revocation authority.
- Root process scheduling begins only after the complete capability table and digest are committed.
- Recovery creation is idempotent for a specific `(boot_epoch, incarnation_number)`.

## 13. Failure policy

| Failure | Required response |
|---|---|
| Root crashes once | Revoke, quiesce, reconstruct |
| Root crash loop exceeds budget | Enter independent recovery path; preserve diagnostics |
| Manifest digest mismatch | Refuse activation; recovery |
| Authority-set digest mismatch | Refuse scheduling; destroy attempted incarnation; recovery |
| Old descendants fail to quiesce | Forced teardown if safe; otherwise recovery/panic with failure capsule |
| BAC internal invariant violation | Kernel panic into recovery; never mint speculative authority |
| Root requests authority absent from manifest | Deny and audit |
| Stale message/capability from old incarnation | Reject by incarnation/revocation validation |

Recommended initial restart budget: **3 reconstitutions in 60 seconds**, then recovery. This is policy data in the manifest and may change without changing the mechanism.

## 14. Security argument

- **No trapped authority:** canonical roots remain sealed in the kernel BAC.
- **No duplication:** one ACTIVE token plus lineage-wide revocation before replacement.
- **No amplification:** the manifest bounds every minted right; derived capabilities cannot exceed it.
- **No serialized secrets:** persistent manifest records selectors and rights, not handles.
- **Small trusted mechanism:** the kernel knows object identity, lineage, rights, epochs and digests—not service policy.
- **Auditable recovery:** each transition records boot epoch, incarnation, reason and set digest in a bounded flight recorder.

## 15. Required tests

- **AF-007A:** Kill Root Supervisor; exactly one replacement reaches ACTIVE.
- **AF-007B:** Count all live descendants before and after failure; no old-incarnation capability remains usable.
- **AF-007C:** New authority-set digest exactly equals the manifest digest.
- **AF-007D:** Race capability transfer against root death; result is either completed-before-revocation then revoked, or rejected.
- **AF-007E:** Inject failure during each reconstitution step; never observe two active incarnations.
- **AF-007F:** Corrupt the manifest or expected set digest; boot/restart refuses activation.
- **AF-007G:** Trigger restart budget; system enters recovery rather than looping forever.
- **AF-007H:** Crash an ordinary service; unrelated services survive and root incarnation is unchanged.

## Implementation refinement — 2026-10-16

[ADR-0026](../adr/ADR-0026-bounded-restart-admission.md) specifies sliding-window
admission before every replacement attempt, including failed creation, with
latched recovery on exhaustion or clock failure. The manifest supplies policy;
the initial implementation accepts at most eight attempts per window. This
clarifies previously unspecified budget semantics; all custody, quiescence,
unique-incarnation and independent-recovery requirements above remain binding.
The portable primitive is not evidence of AF-007G system recovery.

## Manifest implementation — 2026-10-18

[ADR-0027](../adr/ADR-0027-measured-bootstrap-manifest.md) defines the first
Internal measured manifest parser. It preserves image/ABI/authority digests,
selectors, rights, constraints, Job limits and restart policy. Expected manifest
measurement comes from trusted boot selection; parsing never creates authority.
The validated manifest borrows the exact image and manifest bytes immutably.
Live selector resolution, actual authority-set comparison, boot/incarnation
binding and executable launch remain required before scheduling a supervisor.

## Authority binding implementation — 2026-10-18

[ADR-0028](../adr/ADR-0028-atomic-bootstrap-authority-binding.md) resolves manifest
selectors against live kernel-held root capabilities, hashes the actual object and
original custody-lineage identities, and atomically derives the requested grants
into an empty destination. Whole-object grants are supported; subranges are
rejected until enforcement exists. The equal-set digest refers to stable custody
roots; epoch/incarnation binding remains separate. Full sealed BAC ownership,
incarnation-scoped revocation, quiescence and supervisor launch are still pending.

## Authority metadata lifetime — 2026-10-18

[ADR-0029](../adr/ADR-0029-generation-safe-authority-reuse.md), recorded as SUP-012,
adds explicit generation-safe domain reuse and bounded collection of lineage
unreachable from all capability tables. It preserves delegated ancestry and
escrow. This does not recycle objects, scheduler IDs or physical resources.
Future detached incarnation-revocation references must pin nodes or carry node
generations; bare lineage indices may not outlive collection.

## Incarnation revocation refinement — 2026-10-18

[ADR-0030](../adr/ADR-0030-pinned-incarnation-authority-branches.md), SUP-013,
implements the single logical incarnation revocation boundary as an atomically
revoked group of per-object branches pinned in a kernel-only capability domain.
This retains the original custody roots, exact manifest grants and all-descendant
invalidation. Stale domain/handle generations cannot revoke replacement branches.
Full boot-epoch/process/Job token binding, sealed runtime ownership, scheduling,
quiescence and recovery remain required; the authority fixture does not prove them.

## Pre-activation binding — 2026-10-19

[ADR-0031](../adr/ADR-0031-preactivation-incarnation-binding.md) binds a prepared
process/Job, boot epoch, counter, measured digests and authority domains to one
kernel event token. An explicit scheduler admission hold prevents dispatch;
matching revocation invalidates the pinned branches. Bound is not ACTIVE, and
Revoked is not QUIESCENT. No release, reset or replacement API exists before real
executable validation and external teardown are connected. Boot epoch uniqueness
and sealed singleton ownership still belong to trusted runtime integration.

## Measured executable loading — 2026-10-19

[ADR-0032](../adr/ADR-0032-measured-static-executable-loading.md) validates a
bounded static ELF64 image from the exact measured manifest bytes and loads a
private inactive root with final W^X flags, zero fill and a guarded NX stack.
The current bound token can request the plan. The standalone CPL3 loader proof
is separate from supervisor dispatch; admission stays held until owned loaded-root
integration, live authority revalidation and atomic activation are implemented.

## Owned-image activation — 2026-10-19

[ADR-0033](../adr/ADR-0033-owned-image-incarnation-activation.md) transfers a bound
record and typed hardware image owner into one Active record after revalidating
measurements, exact live grants/ancestry and scheduler/thread/frame admission.
Revocation inhibits dispatch first and retains the image through process retirement;
hardware reclamation still requires actual CR3/CPU/reference quiescence. No reset
or replacement permit follows from Revoked. The admitted fixture is not yet the
real Root Supervisor or a full AF-007 recovery proof.

## Source-built supervisor bootstrap — 2026-10-19

[ADR-0034](../adr/ADR-0034-source-built-supervisor-bootstrap.md) adds the first
separate Rust Root Supervisor startup skeleton and one shared Internal startup/
event codec. A source-built development bundle supplies exact measured artifacts.
A token-derived read-only/NX startup page carries explicit grants; activation
checks its digest/address/length before dispatch. Actual user faults use the
ordinary trap boundary and drive inhibition/revocation/stop before reclamation.
This establishes bootstrap execution only. Production generation/epoch trust,
sealed singleton custody, managed graph recovery and AF-007A–H remain pending.

## Supervisor created services — 2026-10-26

[ADR-0035](../adr/ADR-0035-supervisor-created-service-graphs.md) connects Job
CONTROL creation, creator-rooted object ancestry and exact child-role admission
to a separate source-built Echo service. Root can observe ordinary child failure
while retaining its own incarnation; pending cap-free requests are reclaimed.
This does not authorize replacement of Root or complete service/BAC recovery.

## Retained custodian and ordinary replacement — 2026-10-27

[ADR-0036](../adr/ADR-0036-generation-safe-service-retirement.md) adds explicit
generation-safe service metadata reclamation. An ordinary replacement retains its
Job, logical endpoints and accumulated CPU usage. A physical 64-replacement proof
now preserves Root and a responsive unrelated peer; evidence is linked from
[M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance). This exercises AF-007H's service
boundary, while whole Root catastrophe has separate requirements above.

[ADR-0038](../adr/ADR-0038-sealed-custodian-lifecycle.md) implements the portable
non-Clone custodian lifecycle over the same immutable manifest/catalog. It retains
one current token, a monotonic sequence, charged restart policy and permanent
recovery latch. Replacement requires exact revoked binding ownership, retained
terminated scheduler identities, zero live aggregate resources and a consumed
typed physical quiescence witness. Ten host tests cover these gates; actual whole
Root graph teardown, reconstitution and independent recovery remain pending.
