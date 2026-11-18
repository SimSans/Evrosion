# Invariant register

Extracted from the [Pre-M0 implementation package](plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This is the working canonical file; the imported package remains unchanged.

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
- **INV-IPC-006 — Sync waits cannot hold dangerous locks.** Locking and RPC rules in [IPC discipline](designs/IPC_DISCIPLINE.md) are mandatory.

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

## Verification status

Each invariant must acquire automated proofs as its subsystem appears.
The validator checks the register's structure and references. M0 acceptance
(tag `m0`) executed proofs for INV-M0-001 through INV-M0-004: byte-identical
unsigned images from two fresh clones on one prepared host (not yet hermetic or
independent-host; see EXC-0002), repeated machine-detected boots, deliberate
panic with build identity and symbolization, and validated boot information.
Authority, kernel, IPC, resource, lifecycle, evolution and user-guarantee proofs
remain pending until their milestones. Results are in
M0 readiness; coverage is tracked in
[architecture tests](../tests/architecture/README.md).

M1-01 adds bounded, safe-Rust bootstrap frame selection and real boot checks
(progress and limits), supporting INV-KERN-004,
INV-KERN-005 and the boot handoff portion of INV-M0-004. This is partial kernel
mechanism coverage, not a PASS for user isolation, capabilities or fault containment.

M1-02a adds bounded leaf ownership, validated direct-map arithmetic and local
hardware mapping/root-switch tests in the same progress record. This extends
partial mechanism coverage only; INV-KERN-003 user-fault containment and
authority/isolation proofs remain pending until user roots and exception handling.


M1-06b/c now adds bounded BSP hardware coverage for INV-KERN-003 and scalar
INV-AUTH-002/003 enforcement: private integer user contexts exchange attenuated
capabilities, survive ordinary peer faults, and block/wake on arrival or an
absolute deadline. Progress and limits links
executed evidence. This does not establish arbitrary-process isolation, physical
resource reclamation, SMP scheduling, supervisor fault subscriptions or full
M1 acceptance. The prior historical slice scopes remain as originally recorded.


M1 aggregate acceptance now covers the bounded kernel mechanisms above, including
physical reclamation, capability-routed fault diagnostics, runtime allocation,
x87/SSE isolation and hierarchical resource attribution. AF-003/005/009 have
executed host and CPL3 evidence. M1 readiness
records the final gate and explicit Internal/BSP limits; earlier paragraphs retain
their historical slice scope. BAC/restart, synchronous RPC and later subsystem
invariants remain pending their own proofs.


Current bounded M2–M5 execution coverage is reconciled in [M2](M2_ACCEPTANCE.md),
[M3](M3_ACCEPTANCE.md), [M4](M4_ACCEPTANCE.md) and [M5/0.1](M5_ACCEPTANCE.md).
The final current-code regression and readiness
retain actual authority/IPC/retirement, durable-cut and recovery negatives plus
native lifecycle, exact selected grants, App/Shell containment, diagnostics and
provider replacement. This does not promote every general invariant to universal
runtime coverage: Internal/BSP/non-DMA/fixed-owner limits and model-only branches
remain explicit. INV-M0-001 passes the two-clean-build comparison; measured
cross-context artifact differences remain under the active nonhermetic scope,
without waiving that comparison or claiming production-grade reproduction.

The later M6 readiness adds bounded reference
network/time/entropy, authenticated downloaded execution, signed recovery and
actual two-Linux whole-target reproduction for snapshot14. Earlier cross-context
differences retain their historical source scope. General invariant coverage,
hermetic production builds, physical hardware, full owner-layer/accessibility UX
and arbitrary common-root reconstruction remain separate obligations. The
[stabilization plan](M6_STABILIZATION_PLAN.md) qualifies changed source separately.
