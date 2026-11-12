Public technical edition. Editorial changes remove development-workspace instructions; technical requirements and clause identities remain. The source map records actual edition hashes.

# Evrosion PRE-M0 Implementation Package v1

**Status:** Canonical implementation-entry package

**Date:** 2026-09-20

**Project phase:** PRE-M0 complete on paper; M0 implementation may begin

**Authority:** Derived from the Evrosion handoff, Foundations F-001–F-014, Universal Rules U-000–U-018, E-001–E-026, and Full Architecture Audit v1

**Audience:** Project owner, maintainers, contributors, reviewers

---

## 0. Executive decision

Evrosion is ready to leave architecture-only work and begin M0.

This package closes the PRE-M0 work identified by the architecture audit:

1. architecture index;
2. invariant register;
3. glossary;
4. ADR policy and template;
5. temporary-exception policy and register;
6. Root Authority Custody & Reconstitution design;
7. IPC reentrancy/deadlock discipline;
8. initial repository structure;
9. exact M0 toolchain, UEFI/QEMU and debugging plan;
10. M0 acceptance gate and first architecture-fitness tests;
11. an ordered maintainers implementation brief.

The core architecture is not reopened by this document. Where implementation choices remain provisional, they are explicitly labelled **M0 implementation choices**, not permanent platform contracts.

The governing rule from this point onward is:

> **Architecture should increasingly be challenged by running code, tests, fault injection and measurement.**

---

# Part I — Project law and governance

## 1. Document authority and change rules

Evrosion distinguishes three classes of decision:

| Class | Meaning | Change threshold |
|---|---|---|
| Invariant | A law that makes Evrosion recognizably Evrosion | Evidence of contradiction, security failure or unbuildability; ADR required |
| Contract | A versioned boundary relied on by another component | Compatibility analysis, tests and ADR required |
| Implementation | A replaceable realization behind a boundary | Normal engineering review and tests |

The architecture documents describe intent and boundaries. Running behavior does not silently rewrite them. If code and architecture differ, the discrepancy must produce one of three outcomes:

1. fix the code;
2. revise the architecture through an ADR supported by evidence; or
3. record a narrow, expiring exception.

No temporary shortcut becomes precedent merely because it shipped.

### 1.1 Decision states

All public platform surfaces use one of these maturity states:

- **Internal:** may change freely; no external compatibility promise.
- **Preview:** intentionally exposed for testing; changes require migration notes.
- **Stable:** compatibility is promised and enforced by automated tests.
- **Deprecated:** still compatible during a declared window; replacement documented.
- **Removed:** permitted only after the compatibility window ends.

Nothing is called Stable without an automated compatibility test.

---

## 2. Architecture Index

The eventual repository file is `architecture/ARCHITECTURE_INDEX.md`. Until the original E-documents are imported, this table is the canonical routing index.

| ID | Subject | Locked direction | Primary implementation owners | Earliest proof |
|---|---|---|---|---|
| F-001–F-014 | Foundations | Human-first, owner-sovereign, explainable, resilient, local-first | Whole project | Every milestone review |
| U-000–U-018 | Universal rules | Simplicity, control, reversibility, privacy, transparent state | Whole project | Every architecture fitness review |
| E-001 | Overall architecture | Capability-based adaptive microkernel/component architecture | `kernel/`, `services/` | M1–M2 |
| E-002 | Kernel | Mechanisms only; policy and most drivers in userspace | `kernel/` | M1 |
| E-003 | Platforms | x86-64 + UEFI + QEMU first | `platform/x86_64/`, `tools/ev/` | M0 |
| E-004 | Execution | Job → Process → Kernel Thread → User Tasks | `kernel/`, `platform/` | M1–M2 |
| E-005 | Memory | Object-based memory; userspace policy | `kernel/mm/`, future memory service | M1–M2 |
| E-006 | Drivers | Userspace-first driver hosts and declarative matching | `drivers/`, `services/` | after M2 |
| E-007 | Services | Capability-routed supervised service graph | `services/`, `idl/` | M2 |
| E-008 | IPC | Sync control + async rings + Memory Objects | `kernel/ipc/`, `idl/`, `libs/` | M1–M2 |
| E-009 | Security | Capability-first; identity is not authority; no ambient root | `kernel/cap/`, trusted services | M1–M5 |
| E-010 | Storage | Transactional, integrity-first, generation-aware | storage services | M3 |
| E-011 | Networking | Intent/session model; userspace networking | network services | M6+ |
| E-012 | Boot/recovery | Verified, health-gated System Generations and Known Good | boot, lifecycle, recovery | M3–M5 |
| E-013 | Languages | Rust internally; minimal assembly; language-neutral stable boundary | whole repository | M0 onward |
| E-014 | Build | Hermetic, reproducible, content-addressed; stable `ev` frontend | `tools/ev/`, CI | M0 onward |
| E-015 | API/ABI | Small kernel ABI; versioned typed contracts; IDL source of truth | `idl/`, `platform/` | M2 onward |
| E-016 | Applications | Immutable capability-native `.sion` package; data separate | package/runtime services | M5 |
| E-017 | Graphics | Capability-isolated surface graph; software fallback | graphics services | M4 |
| E-018 | Media | Capability-routed media fabric; bounded RT paths | media services | post-M5 |
| E-019 | Lifecycle | Shared transactional lifecycle with probation and rollback | lifecycle services | M3–M5 |
| E-020 | Diagnostics | Capability-secured state, events and traces | kernel + services | M0 onward |
| E-021 | AI | Optional, capability-mediated, never authoritative | AI services | post-0.1 |
| E-022 | Compatibility | Foreign systems adapted outside native core | compatibility realms | post-native slice |
| E-023 | Resources | Hierarchical Job contracts and causal QoS | kernel + resource policy | M1 onward |
| E-024 | Extensions | Typed extension points; discovery separate from binding | platform services | after stable contracts |
| E-025 | Initial scope | Architecture-complete, feature-minimal bring-up | milestone governance | M0–M5 |
| E-026 | Evolution | Stable laws, replaceable implementations, side-by-side migration | whole project | continuous |

### 2.1 Audit action register

| ID | Required before | Status after this package | Location/next action |
|---|---|---|---|
| A-001 Root Authority | M2 | **Designed** | Part II; implement and test in M1/M2 |
| A-002 Non-godlike AI | E-021 implementation | Deferred intentionally | AI annex before implementation |
| A-003 Durable grants | M5 | Deferred intentionally | storage/security annex |
| A-004 TOCTOU-safe approval | Trusted picker or privileged approval | Deferred intentionally | trusted-control annex |
| A-005 Time | M6 | Deferred intentionally | X-001 |
| A-006 Entropy | Security/networking | Deferred intentionally | X-002 |
| A-007 Users/sessions | Multi-user desktop | Deferred intentionally | X-003 |
| A-008 Suspend/resume | Laptop support | Deferred intentionally | X-004 |
| A-009 Virtualization | VM fallback | Deferred intentionally | X-005 |
| A-010 Encryption keys | Real user-data protection | Deferred intentionally | X-006 |
| A-011 Global text/IME | Consumer desktop | Deferred intentionally | X-007 |
| A-012 IPC deadlock | M2 service graph | **Designed** | Part III; implement incrementally |
| A-013 Identity taxonomy | M5 | Initial glossary only | formalize before M5 |
| A-014 Boot health | M3 | Deferred intentionally | define with lifecycle implementation |
| A-015 Governance files | Serious implementation growth | **Defined** | Part I; split into repository files |

---

## 3. Invariant Register

The eventual repository file is `architecture/INVARIANTS.md`. Each invariant must acquire one or more automated proofs as the relevant subsystem appears.

### Authority and ownership

- **INV-AUTH-001 — No ambient authority.** A task receives no authority merely because it exists, has a name, belongs to a user, or runs in Layer 3.
- **INV-AUTH-002 — Capability possession is necessary.** Protected operations require an appropriate live capability.
- **INV-AUTH-003 — No rights amplification.** Derivation and transfer may preserve or attenuate rights, never increase them.
- **INV-AUTH-004 — Identity is not authority.** Identity may inform policy; it never substitutes for a capability check.
- **INV-AUTH-005 — Layer 3 is owner sovereignty, not global process elevation.** Deliberate owner action can authorize dangerous operations, but unrelated processes remain confined.
- **INV-AUTH-006 — Authority is explicit and attributable.** Capability lineage and the authorizing action must be observable where security-sensitive.
- **INV-AUTH-007 — Restart cannot multiply authority.** Reconstitution yields exactly one active bootstrap authority domain.
- **INV-AUTH-008 — Runtime handles are not durable policy.** Capability handles are never serialized as durable grants.

### Kernel and isolation

- **INV-KERN-001 — The kernel owns mechanism, not high-level policy.** Scheduling primitives, memory mappings, IPC, capabilities, interrupts and hardware isolation belong in kernel; ordinary policy does not.
- **INV-KERN-002 — Userspace-first drivers and services.** Kernel residence requires measured necessity and an ADR.
- **INV-KERN-003 — Fault containment.** A normal userspace fault must not crash or corrupt the kernel or unrelated protection domains.
- **INV-KERN-004 — Kernel interfaces are bounded.** User-controlled lengths, queues, recursion and allocation requests have explicit limits.
- **INV-KERN-005 — Unsafe code is localized and justified.** Each unsafe block states the safety invariant it relies upon.

### IPC and contracts

- **INV-IPC-001 — Commands use IPC, authority uses capabilities, bulk data uses Memory Objects/shared memory.**
- **INV-IPC-002 — Public messages are typed and versioned.** IDL is the source of truth once an interface crosses a component boundary.
- **INV-IPC-003 — Queues are bounded.** Overload produces backpressure or explicit failure, not silent unbounded growth.
- **INV-IPC-004 — Deadlines use monotonic time.** Wall-clock changes cannot extend or shorten correctness deadlines.
- **INV-IPC-005 — Timeout is not proof of non-execution.** Retry semantics must be explicit and idempotent where needed.
- **INV-IPC-006 — Sync waits cannot hold dangerous locks.** Locking and RPC rules in Part III are mandatory.

### Resources and lifecycle

- **INV-RES-001 — Job is the accounting and fairness boundary.** Resource use remains attributable through descendants.
- **INV-RES-002 — Resources retain distinct semantics.** CPU, memory, storage, GPU, network and power are not flattened into one fake priority number.
- **INV-LIFE-001 — Program and system content is immutable.** Mutation creates new content or a new generation.
- **INV-LIFE-002 — Durable state is explicit and separate.** Repair or rollback of system content does not silently erase user data.
- **INV-LIFE-003 — Activation is health-gated.** New generations pass probation before becoming Known Good.
- **INV-LIFE-004 — Known Good is protected.** A failed candidate cannot destroy the last bootable generation.
- **INV-LIFE-005 — Recovery is independent.** Recovery cannot require the normal desktop, store, AI service or network.

### Platform evolution

- **INV-EVO-001 — Freeze contracts, not implementations.** Internals remain replaceable behind tested boundaries.
- **INV-EVO-002 — Stable means tested compatibility.** A Stable contract has automated compatibility fixtures.
- **INV-EVO-003 — Version identities remain separate.** Release, System Generation, Platform API Level, contract version, ABI fingerprint, package version and state-schema epoch are not conflated.
- **INV-EVO-004 — Native software pays no optional tax.** Compatibility, AI and extensions are outside native fast paths unless explicitly invoked.
- **INV-EVO-005 — Provider discovery grants no authority.** Binding is a separate authorized act.
- **INV-EVO-006 — One canonical mechanism per concern.** Duplicate capability, lifecycle, observability, package or resource models require explicit justification.

### User guarantees

- **INV-USER-001 — No mandatory cloud, account, telemetry or advertising.** Core local operation does not depend on them.
- **INV-USER-002 — Protection never becomes ownership denial.** The owner can deliberately cross safety boundaries through the appropriate responsibility layer.
- **INV-USER-003 — Automation remains explainable and overridable.** The system reports what happened and exposes manual control appropriate to the layer.
- **INV-USER-004 — Accessibility is a platform contract.** It is not an optional theme or late UI patch.
- **INV-USER-005 — Failure degrades components before the whole machine.** Recovery and isolation are default design inputs.

### M0-specific proofs

- **INV-M0-001 — The same source and lock state produces byte-identical unsigned disk images.**
- **INV-M0-002 — Boot success is machine-detectable.** A stable serial marker and QEMU exit status identify success.
- **INV-M0-003 — Panic is machine-detectable and symbolizable.** Panic output includes build identity and address/context sufficient for offline symbolization.
- **INV-M0-004 — Boot information is validated before use.** Framebuffer and memory-map inputs are bounds-checked.

---

## 4. Glossary

The eventual repository file is `architecture/glossary.md`.

| Term | Canonical meaning |
|---|---|
| Absolute Access | Layer 3 owner mode; permits deliberate system-level authority after explicit warning. It is not ambient root. |
| ABI fingerprint | Generated identifier for a concrete binary contract layout/toolchain combination. |
| AppIdentity | Stable identity assigned to a packaged application; identity alone grants no rights. |
| Architecture Fitness Test | Executable test that continuously checks an architectural claim. |
| Authority | The right to perform an operation on an object or service. |
| Bootstrap Authority Custodian (BAC) | Kernel-owned, sealed custody object containing the canonical roots from which one Root Supervisor incarnation is authorized. |
| Bootstrap Manifest | Immutable, measured description of the initial userspace image, bootstrap objects, rights and resource limits. |
| Capability | Unforgeable kernel-managed reference to an object plus rights and constraints. |
| Capability lineage | Parent/child derivation relationship used to prove non-amplification and perform revocation. |
| Compatibility Capsule | Versioned adapter preserving an older platform contract without freezing its implementation inside the native core. |
| Compatibility Cohort | Components that must activate and roll back together. |
| Contract | Versioned typed boundary between components. |
| Durable grant record | Persistent policy record from which fresh runtime capabilities may be minted after validation. It is not a serialized capability handle. |
| Evrosion Release | Human/project release identity, distinct from a concrete installed generation. |
| Failure Capsule | Structured diagnostic bundle describing a failure, its causal context and relevant bounded state. |
| Flight Recorder | Bounded rolling diagnostic buffer designed to preserve recent events around failure. |
| Generation | Immutable versioned collection of deployable system content. |
| Job | Hierarchical ownership, accounting, lifetime and resource-policy container for processes and child Jobs. |
| Known Good | A System Generation that passed declared health gates and is retained as a rollback target. |
| Memory Object | Kernel object representing memory that can be mapped or shared only through capabilities. |
| Platform API Level | Human-facing compatibility level for the supported developer platform surface. |
| Preview API | Deliberately exposed but not yet Stable contract; migration is expected. |
| Protection domain | Isolation boundary with its own address space and authority set. |
| Provider Binding | Authorized selection of a provider for an extension point; distinct from discovery. |
| Root Incarnation | One active execution epoch of the Root Supervisor. |
| Root Supervisor | First userspace supervisor. It builds and monitors the initial service graph using an explicitly bounded bootstrap authority set. It is not a Unix root account. |
| Secure Attention | Unspoofable transition into the trusted control environment. |
| Stable API | Contract backed by compatibility tests and a declared compatibility policy. |
| System Generation | Concrete immutable bootable system implementation. |
| Trusted Control | OS-owned environment for sensitive approvals and recovery actions. |

---

## 5. Architecture Decision Records

Directory: `architecture/adr/`

File naming:

```text
ADR-NNNN-short-kebab-title.md
```

States:

```text
Proposed → Accepted → Superseded | Rejected
```

An ADR is required when a change:

- alters an invariant or stable contract;
- adds code to the privileged kernel;
- introduces a new cross-system mechanism;
- creates a long-lived dependency or on-disk format;
- adds a permanent service boundary;
- changes authority flow, recovery, or compatibility promises;
- knowingly trades away a stated architecture property.

An ADR is not required for ordinary implementation details behind existing boundaries.

### 5.1 ADR template

```markdown
# ADR-NNNN — Title

Status: Proposed
Date: YYYY-MM-DD
Owners: ...
Related: E-..., INV-..., issue/PR ...

## Context

What concrete problem or evidence requires a decision?

## Decision

State the decision precisely.

## Invariants preserved

- INV-...

## Alternatives considered

Describe realistic alternatives and why they were not selected.

## Consequences

Positive, negative and operational consequences.

## Security and failure analysis

Authority changes, trust boundaries, failure modes and recovery.

## Verification

Tests, measurements and observability proving the decision works.

## Migration / rollback

How to adopt, reverse or supersede the decision.

## Expiry or review trigger

Evidence or milestone that forces reconsideration, if any.
```

---

## 6. Temporary architecture exceptions

Directory: `architecture/exceptions/`

Temporary exceptions exist so prototypes do not lie about architecture compliance. Every exception must be narrow, owned and expiring.

Required fields:

```markdown
# EXC-NNNN — Title

Status: Active | Resolved | Expired
Opened: YYYY-MM-DD
Owner: ...
Target removal: milestone/date
Affected invariants: INV-...
Scope: exact files/components

## Temporary deviation
## Why it is necessary now
## Risk and containment
## Removal plan
## Test preventing scope expansion
## Resolution evidence
```

Rules:

1. No exception may say “temporary” without a removal trigger.
2. An exception cannot authorize ambient root, silent rights amplification, or destruction of the last Known Good generation.
3. CI lists all active and expired exceptions.
4. An expired exception fails the architecture fitness suite.
5. Expanding scope requires editing the exception and review; scope does not grow implicitly.

Initial register:

| ID | Exception | Target removal | Status |
|---|---|---|---|
| EXC-0001 | `rust-osdev/bootloader` supplies the M0 UEFI loader and temporary boot-info format | Before Evrosion declares its boot contract Preview | Active |
| EXC-0002 | Host QEMU/OVMF packages are accepted in local M0 development rather than fully hermetic tool artifacts | Before release CI/reproducibility is declared production-grade | Active |

Neither exception changes Evrosion's architectural contracts. Both are replaceable tooling/bring-up choices.

---

# Part II — Root Authority Custody & Reconstitution

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

---

# Part III — IPC reentrancy and deadlock discipline

## 16. Decision summary

Evrosion supports bounded synchronous control RPC because it makes small control interactions understandable and efficient. Synchronous calls may form a forward chain, but reentrant callbacks into an ancestor are forbidden. A thread blocked on a synchronous reply does not dispatch unrelated requests.

Asynchronous messages and shared-memory rings are the default for events, streaming, fan-out, high-latency work and any operation likely to call back.

## 17. Message modes

| Mode | Use | Blocking | Payload |
|---|---|---|---|
| Sync RPC | Small, bounded control query/command | Caller waits | Small typed message + limited capability transfer |
| Async channel | Events, work submission, callbacks, fan-out | No mandatory wait | Bounded typed message |
| Shared ring | High-rate streams | Producer/consumer backpressure | Fixed descriptors, not large copies |
| Memory Object | Bulk data | Mapping-dependent | Pages/regions under explicit capability |

## 18. Mandatory rules

1. **No synchronous RPC while holding a dangerous lock.** Dangerous includes global locks, capability-table write locks, address-space locks, scheduler locks, allocator locks, device state locks, filesystem transaction locks and any lock whose owner may need IPC progress.
2. **No synchronous callback into an ancestor.** If A synchronously calls B and B needs A, B must use an asynchronous response path, a pre-supplied data object, or return a continuation request.
3. **Forward nesting is bounded.** Initial maximum synchronous depth is 8. The limit is explicit protocol failure, not stack exhaustion.
4. **One blocked request, one wait edge.** A blocked thread cannot secretly service other sync requests.
5. **All waits have an absolute monotonic deadline.** `NO_DEADLINE` is prohibited across protection-domain boundaries except in early boot code covered by an exception.
6. **Cancellation is cooperative and explicit.** A timeout/cancel stops the caller waiting; it does not prove the callee never executed.
7. **Queues are bounded.** Each endpoint declares message count, byte and capability-transfer limits.
8. **Backpressure is visible.** Full queues return `WOULD_BLOCK`, `OVERLOADED` or wait only within the caller's deadline.
9. **Capability transfer is transactional with message acceptance.** A rejected message cannot strand or duplicate transferred authority.
10. **Protocol decoding is total and defensive.** Unknown fields follow declared version rules; malformed inputs fail without partial side effects.

## 19. Causal call context

Every cross-domain sync call carries kernel-protected metadata:

```text
trace_id              random/monotonic boot-unique identifier
call_id               unique within trace
parent_call_id        previous edge, if any
origin_job_id         stable boot-local origin
current_depth         bounded integer
absolute_deadline     monotonic timestamp
cancellation_token    revocable wait context
root_incarnation      if bootstrap-managed
```

Userspace may read appropriate diagnostic fields but cannot forge kernel causal ancestry.

The deadline may only stay the same or become earlier as a call moves forward.

## 20. Reentrancy model

The initial platform contract is **non-reentrant synchronous endpoints**:

- An endpoint handler processes one request according to its declared concurrency policy.
- A handler may call a lower-level service synchronously if it holds no forbidden lock and preserves the causal context.
- The lower service may not synchronously call any ancestor in the active chain.
- Notifications and callbacks use a separate asynchronous endpoint.
- If a protocol truly needs reentrancy later, it requires an explicit contract annotation, proof of state safety and an ADR. It is not the default.

## 21. Lock discipline

Kernel and system services maintain a lock-class registry with numeric ranks.

Rules:

- acquire locks in increasing rank order;
- never acquire an equal/lower rank while holding a higher rank unless the same lock's documented primitive permits it;
- no IPC wait while holding a lock marked `NO_IPC_WAIT`;
- no page fault or allocation capable of external pager/service IPC while holding pager-critical locks;
- interrupt context never performs blocking IPC;
- real-time media paths never perform blocking IPC or allocation;
- lock guards are dropped before generated client stubs can issue sync RPC.

Development builds track held lock classes per thread and trap violations at the call boundary.

## 22. Cycle detection

### Development builds

The kernel maintains a bounded wait-for graph for live synchronous calls:

```text
caller thread → callee endpoint/servicing thread
```

Before committing a wait edge, bounded cycle detection checks whether the edge reaches an ancestor. If yes, the call fails with `DEADLOCK_DETECTED`, records the causal chain and optionally traps under the test profile.

### Production builds

Production retains:

- depth limits;
- ancestor identity tokens;
- deadlines;
- lock assertions where cheap;
- bounded queues;
- structured deadlock/timeout diagnostics.

The full graph may be disabled or sampled if measurement shows unacceptable cost. Semantics do not change.

## 23. Timeouts, cancellation and retries

Canonical statuses:

```text
OK
WOULD_BLOCK
OVERLOADED
DEADLINE_EXCEEDED
CANCELLED
DEADLOCK_DETECTED
PEER_DIED
MALFORMED_MESSAGE
VERSION_MISMATCH
PERMISSION_DENIED
```

Rules:

- A deadline expiry ends the wait and requests cancellation.
- The callee checks cancellation at defined safe points.
- Side-effecting requests include a caller-generated idempotency key when retry is permitted.
- Protocol documentation declares each operation `READ_ONLY`, `IDEMPOTENT`, `AT_MOST_ONCE_WITHIN_PEER_LIFETIME`, or `NON_RETRYABLE`.
- Cross-crash exactly-once execution is not promised. Durable operations use transactional state plus durable operation IDs.

## 24. Queue policy

Every endpoint declares:

```text
max_messages
max_bytes
max_capabilities_per_message
overflow_behavior
priority/fairness class
```

Memory charged for queued messages is attributed to the sender's Job until accepted, then to the receiver according to contract. A low-authority sender cannot exhaust unbounded receiver memory.

## 25. Required tests

- **AF-IPC-001:** Generated client attempts sync RPC while holding `NO_IPC_WAIT` lock; development kernel rejects it.
- **AF-IPC-002:** A→B→C succeeds within depth and deadline.
- **AF-IPC-003:** C→A synchronous callback is rejected as a cycle.
- **AF-IPC-004:** Depth 9 is rejected when maximum is 8.
- **AF-IPC-005:** Descendant deadline cannot exceed parent deadline.
- **AF-IPC-006:** Full queue produces explicit backpressure without memory growth.
- **AF-IPC-007:** Timeout followed by retry cannot duplicate an idempotent operation.
- **AF-IPC-008:** Malformed length/capability count is rejected before side effects.
- **AF-IPC-009:** Receiver death returns transferred capabilities according to declared transactional semantics; no duplicate live handle exists.
- **AF-IPC-010:** Fuzzed message decoder never panics, escapes bounds or partially commits invalid input.

---

# Part IV — Repository and M0 implementation blueprint

## 26. Repository structure

Use this exact initial shape. Empty future areas get a short `README.md`, not invented implementation.

```text
evrosion/
├── .cargo/
│   └── config.toml
├── .github/
│   └── workflows/
│       └── ci.yml
├── architecture/
│   ├── ARCHITECTURE_INDEX.md
│   ├── INVARIANTS.md
│   ├── glossary.md
│   ├── adr/
│   │   ├── README.md
│   │   └── ADR-0000-template.md
│   ├── exceptions/
│   │   ├── REGISTER.md
│   │   ├── EXC-0001-temporary-bootloader.md
│   │   └── EXC-0002-host-qemu-ovmf.md
│   └── designs/
│       ├── ROOT_AUTHORITY_CUSTODY.md
│       └── IPC_DISCIPLINE.md
├── boot/
│   └── image-builder/
├── kernel/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── arch/
│       │   └── x86_64/
│       ├── boot.rs
│       ├── console/
│       │   ├── mod.rs
│       │   └── serial.rs
│       └── panic.rs
├── platform/
│   └── README.md
├── services/
│   └── README.md
├── drivers/
│   └── README.md
├── libs/
│   ├── boot-contract/
│   └── test-protocol/
├── apps/
│   └── README.md
├── idl/
│   └── README.md
├── tools/
│   └── ev/
│       ├── Cargo.toml
│       └── src/
├── tests/
│   ├── architecture/
│   │   ├── README.md
│   │   └── m0_boot.rs
│   ├── host/
│   └── fixtures/
├── third_party/
│   └── README.md
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── LICENSES/
├── README.md
└── rust-toolchain.toml
```

Folder rules:

- no `misc`, `utils`, `temp`, `old`, or `final2` directories;
- reusable code goes in a named library with one documented responsibility;
- a new top-level directory requires an ADR or architecture-index update;
- service boundaries require failure/isolation justification;
- generated files go under `build/` or `target/` and are never hand-edited.

## 27. M0 technical choices

These choices are concrete enough to implement and explicitly replaceable:

| Area | M0 choice | Status |
|---|---|---|
| Primary language | Rust 2024 edition, `#![no_std]`, minimal `unsafe` | Architectural direction |
| Toolchain | `nightly-2026-07-06`, with `rust-src`, `rustfmt`, `clippy`, `llvm-tools-preview`; targets `x86_64-unknown-none` and `x86_64-unknown-uefi` | Pinned M0 implementation choice |
| Boot image | `rust-osdev/bootloader = 0.11.17`, UEFI disk image only | Temporary EXC-0001 |
| Build backend | Cargo workspace and locked dependencies, hidden behind `ev` | Replaceable implementation |
| Host frontend | Rust CLI named `ev` | Stable command intent; flags Internal during M0 |
| Emulator | `qemu-system-x86_64`, Q35 machine, TCG default, optional KVM | Replaceable development tool |
| Firmware | OVMF code image discovered by `ev bootstrap/doctor`; per-run writable vars copy if needed | Temporary EXC-0002 |
| Debugger | GDB remote stub; QEMU `-S -gdb tcp:127.0.0.1:1234` | M0 implementation |
| Logs | COM1 serial to stdio/file, structured stable success marker | M0 contract |
| Test exit | `isa-debug-exit` device plus serial marker | Test-only mechanism |
| Image output | `build/m0/evrosion-x86_64-uefi.img` | Internal layout |
| Symbols | Unstripped ELF retained separately; disk image may contain stripped/loadable kernel | M0 requirement |

Why use the temporary bootloader crate: it already builds UEFI disk images and hands the kernel a framebuffer and memory map. M0 exists to prove Evrosion's build/boot/observe/debug loop, not to spend the first month writing a custom loader. Its boot-info layout is not an Evrosion Stable ABI and must remain behind `libs/boot-contract`.

### 27.1 `rust-toolchain.toml`

```toml
[toolchain]
channel = "nightly-2026-07-06"
components = ["rust-src", "rustfmt", "clippy", "llvm-tools-preview"]
targets = ["x86_64-unknown-none", "x86_64-unknown-uefi"]
profile = "minimal"
```

The version is deliberately pinned rather than `nightly`. Update only through a tested dependency/toolchain change.

### 27.2 Dependency policy

- Exact resolution is committed in `Cargo.lock`.
- Direct dependencies specify bounded compatible versions; security/reproducibility review owns upgrades.
- Git dependencies require a full commit hash and justification.
- Vendoring is optional in local M0 and required before declaring fully offline/hermetic release builds.
- `cargo audit`-style host checks are useful but do not replace review of `no_std` code and unsafe boundaries.
- Every dependency must have a license record and a removal/replaceability assessment.

## 28. `ev` command contract for M0

`ev` is the stable human-facing entry point. During M0 the detailed flags remain Internal.

### `ev bootstrap`

Responsibilities:

1. verify supported host OS/architecture;
2. install/verify the pinned Rust toolchain through `rustup`;
3. verify QEMU, OVMF, GDB and required host utilities;
4. locate firmware without hard-coding one distro path;
5. create `.ev/config.toml` with resolved local paths;
6. never require global root privileges after host packages exist;
7. print exact corrective commands if something is missing.

Initial Debian/Ubuntu/Pop!_OS/Kubuntu host hint:

```bash
sudo apt update
sudo apt install qemu-system-x86 ovmf gdb
```

This is a host bootstrap convenience, not a reproducibility claim.

### `ev doctor`

Read-only checks with clear PASS/WARN/FAIL output:

- pinned `rustc` and `cargo` active;
- required rustup components/targets present;
- QEMU binary launches and supports required devices;
- readable OVMF code firmware exists;
- GDB is available;
- KVM access detected but optional;
- output directory writable;
- lockfile present and clean;
- no expired architecture exceptions.

### `ev build [--profile dev|release]`

- build host tools;
- build the freestanding kernel;
- build the UEFI disk image;
- preserve unstripped symbols;
- write `build/m0/manifest.json` containing source revision, dirty-state flag, toolchain identity, dependency-lock digest, artifact digests and build profile;
- never sign canonical unsigned artifacts as part of compilation.

### `ev image`

- produce the disk image from already built inputs or trigger the necessary build;
- normalize timestamps, ordering, volume identifiers and other nondeterministic metadata;
- write SHA-256 digest beside the image;
- support `ev image --verify-reproducible`, which performs two clean builds in separate directories and byte-compares outputs.

### `ev run`

- invoke QEMU with deterministic baseline hardware;
- connect serial output to terminal and `build/m0/serial.log`;
- use TCG by default for portability and deterministic CI behavior;
- accept `--kvm` as an opt-in acceleration flag;
- propagate a meaningful exit code;
- on failure, print paths to log, image, symbols and manifest.

Baseline conceptual invocation:

```bash
qemu-system-x86_64 \
  -machine q35,accel=tcg \
  -cpu max \
  -m 256M \
  -nodefaults \
  -no-reboot \
  -no-shutdown \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive format=raw,file="build/m0/evrosion-x86_64-uefi.img" \
  -serial stdio \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -display gtk
```

`ev` constructs arguments directly rather than passing an interpolated shell command. Actual firmware drive details may include a disposable VARS image depending on the OVMF package.

### `ev debug kernel`

1. start QEMU paused with the GDB stub bound only to loopback;
2. load the unstripped kernel ELF;
3. connect GDB to `127.0.0.1:1234`;
4. set a breakpoint at `evrosion_kernel_entry`;
5. provide helper commands for panic and exception handlers;
6. preserve the exact QEMU command and symbol path in the build manifest.

Conceptual additions:

```text
-S -gdb tcp:127.0.0.1:1234
```

### `ev test architecture --milestone M0`

- build and boot under a timeout;
- parse the serial protocol;
- assert required markers and fields;
- assert successful debug-exit result;
- run the reproducible-image check;
- produce JUnit-compatible host output plus a human summary.

## 29. Boot contract

`libs/boot-contract` prevents the temporary external boot-info type from leaking through the kernel.

The internal Evrosion `BootInfoV0` contains validated copies/views of:

```text
magic
schema_version
structure_size
boot_generation_id
memory_regions[]
framebuffer: address, byte_length, width, height, stride, pixel_format
physical_memory_offset if configured
kernel_physical_range
kernel_virtual_range
command_line as bounded UTF-8 or explicit bytes
bootloader_identity
```

Rules:

- conversion happens once at kernel entry;
- every address/length arithmetic operation is checked;
- overlapping or impossible memory regions are rejected or quarantined;
- framebuffer absence is allowed and produces serial-only operation;
- unknown future fields are ignored only according to version rules;
- no `bootloader` crate type crosses beyond the adapter module;
- the M0 schema is Internal and may be replaced.

## 30. Kernel M0 behavior

Ordered boot path:

1. enter `evrosion_kernel_entry` with interrupts disabled;
2. validate and adapt boot information;
3. initialize COM1 serial output without allocation;
4. print a structured boot header;
5. install the minimum panic handler;
6. validate framebuffer metadata and print it; optionally clear/draw one diagnostic color without requiring it for success;
7. print the exact success marker;
8. issue the test exit code under test profile, otherwise halt in a low-power loop.

Required serial form:

```text
EVROSION_BOOT protocol=1 build=<build-id>
EVROSION_FRAMEBUFFER present=<true|false> width=<n> height=<n> stride=<n> format=<name>
Evrosion kernel entered.
EVROSION_M0_RESULT status=PASS code=0
```

Panic form:

```text
EVROSION_PANIC protocol=1 build=<build-id> cpu=<n> location=<file:line|unknown> message=<bounded>
```

Panic output must avoid allocation and recursive locking. If serial initialization failed, the handler uses the simplest available emergency write path.

## 31. Reproducibility rules

The M0 reproducibility claim applies to the **unsigned canonical disk image** built from the same:

- source revision and recorded dirty state;
- pinned Rust toolchain;
- Cargo.lock;
- build profile and declared environment inputs;
- bootloader version;
- normalized image parameters.

The build must eliminate or normalize:

- filesystem timestamps;
- random volume IDs;
- directory-entry ordering;
- absolute workspace paths embedded in released sections;
- host locale/timezone;
- nondeterministic parallel ordering;
- build timestamps not derived from a declared source epoch.

Debug symbol bundles may be checked separately if host paths prevent byte identity at first. Any such limitation needs an exception; it must not weaken the disk-image check.

## 32. Observability requirements

M0 establishes the beginning of E-020, not a full diagnostics service.

It must provide:

- human-readable serial log;
- machine-parseable stable markers;
- build ID in normal boot and panic output;
- unstripped symbols retained by the build;
- GDB breakpoint at a stable internal entry symbol;
- explicit panic path;
- artifact manifest and SHA-256 digests;
- timeout detection on the host.

Secrets never belong in logs. Even before secrets exist, logging APIs should accept structured fields so later redaction does not require rewriting the system.

---

# Part V — M0 scope, tests and delivery

## 33. M0 goal

> **Reliably build, boot, observe and debug Evrosion.**

M0 is complete when a clean supported Linux host can run:

```text
ev bootstrap
ev doctor
ev build
ev run
ev debug kernel
ev test architecture --milestone M0
```

and the kernel reaches:

```text
Evrosion kernel entered.
```

under x86-64 UEFI QEMU with validated framebuffer metadata, useful serial/panic output, usable symbols and repeatable image generation.

## 34. M0 acceptance gate

Every item is mandatory unless explicitly marked stretch.

### Build

- [ ] Fresh clone plus documented host prerequisites succeeds.
- [ ] Pinned Rust toolchain is installed/verified automatically.
- [ ] `Cargo.lock` is committed.
- [ ] `ev build` creates kernel ELF, symbols, disk image and manifest.
- [ ] Build errors are actionable and do not dump unexplained raw command noise.

### Boot

- [ ] QEMU uses x86-64 Q35 and UEFI/OVMF.
- [ ] Kernel entry is reached on TCG without KVM.
- [ ] Serial prints protocol header, framebuffer record and exact success marker.
- [ ] Framebuffer metadata is validated; missing framebuffer degrades to serial-only.
- [ ] Test profile exits QEMU automatically and distinctly on pass/fail.

### Debug

- [ ] `ev debug kernel` pauses before kernel execution.
- [ ] GDB loads the correct unstripped ELF and hits `evrosion_kernel_entry`.
- [ ] A deliberate panic emits build ID, bounded message and source location where available.
- [ ] At least one backtrace/symbolization workflow is documented and demonstrated.

### Reproducibility

- [ ] Two clean image builds in separate paths are byte-identical.
- [ ] Artifact SHA-256 digests and input manifest are emitted.
- [ ] Dirty source state is recorded and visibly warned.

### Governance

- [ ] Architecture files from Part I are split into the repository.
- [ ] Both active exceptions exist with removal milestones.
- [ ] CI checks formatting, host unit tests, M0 boot test and exception expiry.
- [ ] No public surface is mislabeled Stable.

## 35. Explicitly not in M0

Do not add these to “make M0 impressive”:

- scheduler beyond the minimum execution needed by the boot path;
- userspace processes or Root Supervisor implementation;
- production capability tables;
- general allocator if fixed/static storage suffices;
- filesystem, networking, USB or real-hardware drivers;
- graphical shell, input stack or UI toolkit;
- package manager or `.sion` encoder;
- AI, compatibility layers, accounts, telemetry or update service;
- custom bootloader unless the temporary loader blocks M0;
- stable public ABI.

The correct M0 is small, boring, repeatable and debuggable.

## 36. Architecture fitness matrix

| Test | First milestone | M0 action |
|---|---:|---|
| AF-001 Boot reaches kernel deterministically | M0 | **Implement now** |
| AF-002 User fault does not crash kernel | M2 | Register only |
| AF-003 No cap → denied | M1 | Register only |
| AF-004 Transfer grants only transferred right | M1/M2 | Register only |
| AF-005 Attenuated cap cannot regain rights | M1/M2 | Register only |
| AF-006 Service crash isolation | M2 | Register only |
| AF-007 Root restart exact authority | M2 | Design now; implement later |
| AF-008 Malformed IPC rejected | M1/M2 | Design/fuzz harness placeholder |
| AF-009 Memory Object requires cap | M1 | Register only |
| AF-010 Broken generation rollback | M3 | Register only |
| AF-011 Interrupted durable write atomic | M3 | Register only |
| AF-012 Graphical app crash isolation | M4/M5 | Register only |
| AF-013 Picker exact object grant | M5 | Register only |
| AF-014 Provider swap preserves contract | later | Register only |
| AF-015 Reproducible image | M0 | **Implement now** |
| AF-M0-016 Panic observable/symbolizable | M0 | **Implement now** |
| AF-M0-017 Framebuffer handoff validated | M0 | **Implement now** |

## 37. M0 test protocol

The host test runner launches QEMU with a hard deadline and captures serial bytes.

Pass requires all of:

1. `EVROSION_BOOT protocol=1` appears once;
2. exactly one `EVROSION_FRAMEBUFFER` record parses;
3. `Evrosion kernel entered.` appears once;
4. final result is `EVROSION_M0_RESULT status=PASS code=0`;
5. QEMU exits using the expected debug-exit status;
6. no `EVROSION_PANIC` appears;
7. the process finishes inside the declared timeout.

Separate negative test:

- compile a deliberate panic build;
- require `EVROSION_PANIC` with matching build ID;
- symbolize at least the panic entry/address using the retained ELF;
- require distinct failure exit status.

## 38. CI stages

Run in this order so failures are cheap and legible:

1. `cargo fmt --check`;
2. host-side unit tests for `ev`, manifest generation and parsers;
3. Clippy for host code with reviewed exceptions;
4. kernel compile;
5. image build;
6. M0 QEMU boot under TCG;
7. panic-path test;
8. reproducibility double-build;
9. governance checks: invalid links, duplicate invariant IDs, expired exceptions.

Nightly/toolchain upgrades run in a separate branch/job first. They do not float underneath normal CI.

## 39. Ordered implementation slices

Each slice must leave the repository green.

### Slice 0 — Repository/governance

- initialize git repository and Rust workspace;
- split Parts I–III into canonical architecture files;
- add README, licenses, `.gitignore`, toolchain pin and empty-area READMEs;
- add CI skeleton and architecture-register validator.

**Exit:** host checks run; no kernel yet.

### Slice 1 — `ev doctor` and command shell

- implement argument parsing without prematurely freezing external flags;
- implement environment discovery and human-readable diagnostics;
- implement process execution with argv arrays, captured exit status and structured errors.

**Exit:** `ev doctor` correctly diagnoses a prepared and an intentionally broken host.

### Slice 2 — Minimal kernel and UEFI image

- add `no_std`, `no_main` kernel;
- integrate pinned bootloader crate behind image builder;
- implement serial writer and boot-info adapter;
- build UEFI disk image through `ev build`.

**Exit:** image exists and manifest identifies inputs.

### Slice 3 — Deterministic QEMU run

- implement QEMU argv generation;
- implement serial capture, timeout and test-exit handling;
- emit required boot markers and halt/exit.

**Exit:** AF-001 passes repeatedly under TCG.

### Slice 4 — Panic and debug

- allocation-free panic output;
- retain symbols;
- implement paused QEMU plus GDB connection;
- prove breakpoint and panic symbolization.

**Exit:** positive and deliberate-panic tests pass.

### Slice 5 — Framebuffer and reproducibility

- validate framebuffer handoff and optionally draw diagnostic output;
- normalize disk image metadata;
- implement separate-directory double build and byte comparison.

**Exit:** AF-015 and AF-M0-017 pass.

### Slice 6 — M0 closeout

- run clean-host procedure;
- remove accidental scope growth;
- record timings and artifact sizes;
- resolve or retain documented exceptions;
- tag `m0` only after the acceptance gate is entirely green.

**Exit:** M0 is done; begin M1 kernel spine.

## 40. M0 completion evidence

Store under `build/m0/evidence/` in CI artifacts, not git:

```text
doctor.txt
build-manifest.json
serial-success.log
serial-panic.log
qemu-command.json
gdb-transcript.txt
image.sha256
reproducibility-report.json
test-results.xml
```

The M0 completion note records:

- source commit;
- toolchain and dependency lock digests;
- host/CI environment;
- pass/fail for every acceptance item;
- active exceptions;
- known limitations;
- measured cold/warm build time, image size and boot-to-marker time.

---

# Part VI — Initial implementation notes

## 41. Engineering workflow

1. Treat this package and E-001–E-026 as authoritative.
2. Do not redesign future subsystems during M0.
3. Implement one slice at a time and keep the repository runnable.
4. Before changing a locked invariant, stop and present evidence plus an ADR proposal.
5. Use temporary exceptions openly instead of hiding shortcuts.
6. Prefer the smallest implementation that proves the M0 contract.
7. Keep external bootloader types behind the boot-contract adapter.
8. Never add ambient authority, a Unix-style root shortcut or an unbounded queue.
9. Do not label any M0 platform interface Stable.
10. Run tests after every material change; diagnose failures before expanding scope.
11. Preserve user changes and keep commits/slices reviewable.
12. At the end of each slice, report: files changed, commands run, tests passed, remaining risks and the next slice.

## 42. Initial implementation checklist

Use Rust internally with minimal assembly and no public Rust ABI promise.
The initial target is x86-64, UEFI and QEMU/TCG. Cargo is a build backend behind
`ev`; bootloader types remain behind the boot-contract adapter. Keep governance,
locked toolchain, exception records, tests and observable/debuggable boot entry.
No ambient root, unbounded queues or premature Stable interfaces are permitted.

---

## 43. What comes immediately after M0

M1 proves the kernel spine:

- physical/virtual memory primitives;
- kernel object model;
- capability tables, derivation and revocation;
- threads and minimal scheduling;
- IPC primitive;
- exception/fault delivery;
- Job skeleton and resource attribution;
- architecture fitness tests AF-003, AF-005 and AF-009.

Root Supervisor implementation belongs to M2, using Part II as its governing design. Do not pull the service graph into M0.

---

# Part VII — Adversarial review

## 44. Likely failure modes and countermeasures

| Risk | Failure pattern | Countermeasure in this package |
|---|---|---|
| M0 becomes a desktop project | “While here” additions delay first boot | Explicit non-goals and slice gates |
| External bootloader becomes permanent API | Bootloader types spread through kernel | Boot-contract adapter + expiring EXC-0001 |
| `ev` becomes a shell-script pile | Quoting/path/error inconsistencies | Rust CLI, argv-based process launch, typed manifest |
| Reproducibility is claimed vaguely | Same source produces different image | Separate-directory byte comparison and normalized metadata |
| Root restart duplicates authority | Old grants remain while new root starts | Single active token, revocation, quiescence and digest equality |
| Root mechanism becomes god-policy | Kernel understands services/users | Manifest-driven object/rights mechanism only |
| Sync IPC deadlocks service graph | Callback cycles and locks across calls | Non-reentrant endpoints, causal chain, deadlines, lock assertions, cycle detection |
| Timeout causes duplicate work | Blind retries after unknown execution | Explicit retry class and idempotency keys |
| Architecture becomes decorative | Tests do not reference invariants | Fitness-test IDs and milestone gates |
| Temporary hacks become permanent | No owner/removal trigger | Exception register that expires in CI |
| Stable API grows too early | Prototype layout becomes promise | All M0 APIs Internal unless separately promoted |
| Solo-developer complexity explosion | Too many services/tools at once | Architecture-complete, feature-minimal sequencing |

## 45. Final readiness verdict

The PRE-M0 design package is complete enough to begin implementation.

No further broad architecture phase is justified before M0. The remaining uncertainty is best resolved by building the small boot path, measuring it and turning the stated claims into executable tests.

> **Next action: create the repository, use the technical checklist, execute Slice 0, and then build the damn OS.**

---

## 46. Tooling references checked for this package

- Rust `x86_64-unknown-none` target: <https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html>
- Rust UEFI targets: <https://doc.rust-lang.org/rustc/platform-support/unknown-uefi.html>
- `rust-osdev/bootloader` repository and usage: <https://github.com/rust-osdev/bootloader>
- `rust-osdev/bootloader` image creation documentation: <https://github.com/rust-osdev/bootloader/blob/main/docs/create-disk-image.md>
- QEMU system-emulation documentation: <https://qemu.readthedocs.io/en/master/system/>

Version note: this package pins `bootloader` 0.11.17 with `nightly-2026-07-06`, matching the project's published compatibility information available when this package was written. The pin must remain fixed until an explicitly tested upgrade.
