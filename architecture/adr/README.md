# Architecture Decision Records

Extracted from the [Pre-M0 implementation package](../plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This public index links the accepted technical decisions. Published plan editions
and original source lineage are identified by the source map.

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

Copy [ADR-0000-template.md](ADR-0000-template.md) to the next unused numbered
filename. ADR-0000 is a template, not an accepted decision. Keep related invariant
IDs valid and link accepted records from the architecture index.

## Accepted records

- [ADR-0001: M0 kernel entry and compatible toolchain](ADR-0001-m0-kernel-and-toolchain.md)
  records the authorized boot implementation and the tested compiler pin adjustment.
- [ADR-0002: M0 acceptance](ADR-0002-m0-acceptance.md)
  records deterministic development images, verification and the local control surface.
- [ADR-0003: Preservation and bundled compatibility](ADR-0003-preservation-and-bundled-compatibility.md)
  integrates the owner-approved product amendment while preserving early milestone scope.
- [ADR-0004: M1 bootstrap physical frames](ADR-0004-m1-bootstrap-frames.md)
  records bounded frame allocation, the move-owned Internal handoff, and the
  distinction between selecting a frame and mapping or granting access to it.
- [ADR-0005: Bootstrap page-table ownership](ADR-0005-bootstrap-page-table-ownership.md)
  limits initial direct-map access and owned scratch roots, including local TLB
  invalidation and the remaining user-isolation boundary.
- [ADR-0006: Exception entry and protection probes](ADR-0006-exception-entry-and-protection-probes.md)
  records owned descriptors/stacks and exact fault matching with bounded failure.
- [ADR-0007: Bootstrap user address spaces](ADR-0007-bootstrap-user-address-spaces.md)
  records bounded private user mappings and exact CPL3 isolation fixtures.
- [ADR-0008: Bootstrap timer and deadlines](ADR-0008-bootstrap-timer-and-deadlines.md)
  records IRQ0 routing, monotonic ticks and finite waits when the clock stalls.
- [ADR-0009: Firmware CPU topology](ADR-0009-firmware-cpu-topology.md)
  records bounded ACPI enumeration as a prerequisite, separate from AP execution.
- [ADR-0010: Bounded second-CPU startup](ADR-0010-bounded-second-cpu-startup.md)
  records retained AP roots/entry state, shared work and finite handshake failure.
- [ADR-0011: Bounded scheduler state](ADR-0011-bounded-scheduler-state.md)
  records finite scheduling transitions and Job dispatch attribution before hardware context switching.

- [ADR-0012: Cooperative kernel contexts](ADR-0012-cooperative-kernel-contexts.md)
  records guarded stacks, the callee-saved switch and real-thread execution proof.

- [ADR-0013: Bootstrap timer preemption](ADR-0013-bootstrap-timer-preemption.md)
  records IRQ-driven kernel context resumption and finite stopped-clock failure.

- [ADR-0014: Bounded capability tables](ADR-0014-bounded-capability-tables.md)
  records explicit rights, atomic handle move and retained lineage revocation.

- [ADR-0015: Bounded mailbox escrow](ADR-0015-bounded-mailbox-escrow.md)
  records transactional capability delivery and timeout/death reclamation.

- [ADR-0016: Scheduled user runtime](ADR-0016-scheduled-user-runtime.md)
  records private CPL3 scheduling, scalar capability IPC and ordinary fault containment.

- [ADR-0017: Bounded receive waits](ADR-0017-bounded-receive-waits.md)
  records atomic predicate/enrollment, arrival and deadline wake, and finite idle-clock failure.

- [ADR-0018: Quiescent process retirement](ADR-0018-quiescent-process-retirement.md)
  records sibling cancellation, closed authority domains and actual peer-death escrow cleanup.

- [ADR-0019: Private frame reclamation](ADR-0019-private-frame-reclamation.md)
  records allocator provenance, inactive-root teardown and scrubbed reuse.

- [ADR-0020: Shared Memory Object leases](ADR-0020-shared-memory-object-leases.md)
  records capability-checked mappings and quiescent backing destruction.

- [ADR-0021: Hierarchical Job accounting](ADR-0021-hierarchical-job-accounting.md)
  records atomic resource admission, parent attribution and balanced lifetime release.

- [ADR-0022: Live mapping revocation](ADR-0022-live-mapping-revocation.md) records removal of invalid hardware mappings before user dispatch.

- [ADR-0023: Eager legacy extended contexts](ADR-0023-eager-legacy-extended-contexts.md) records isolated x87/XMM/MXCSR state and the Internal CPU feature boundary.

- [ADR-0024: Bounded fault notifications](ADR-0024-bounded-fault-notifications.md) records capability-routed, nonblocking process fault diagnostics.

- [ADR-0025: Anonymous allocation admission](ADR-0025-anonymous-allocation-admission.md) records charged runtime allocation, failure rollback and scrubbed free.

- [ADR-0026: Bounded restart admission](ADR-0026-bounded-restart-admission.md) records manifest policy, sliding-window admission and latched recovery; full BAC integration remains pending.

- [ADR-0027: Measured bootstrap manifest](ADR-0027-measured-bootstrap-manifest.md) records bounded canonical parsing, trusted expected measurements, immutable image/manifest borrows and authority-resolution limits.

- [ADR-0028: Atomic bootstrap authority binding](ADR-0028-atomic-bootstrap-authority-binding.md) records live object/lineage measurement, exact attenuation and all-or-nothing grant installation.

- [ADR-0029: Generation-safe authority reuse](ADR-0029-generation-safe-authority-reuse.md) narrows ADR-0014 retention: explicit domain generations and unreachable-lineage collection; physical/object/scheduler lifetime unchanged.

- [ADR-0030: Pinned incarnation authority branches](ADR-0030-pinned-incarnation-authority-branches.md) records atomic private-branch minting/revocation, exact user attenuation and stale teardown rejection.

- [ADR-0031: Pre-activation incarnation binding](ADR-0031-preactivation-incarnation-binding.md) records held scheduler processes, measured process/Job tokens and fail-closed lifecycle events.

- [ADR-0032: Measured static executable loading](ADR-0032-measured-static-executable-loading.md) records bounded ELF64 validation, private W^X page loading, zero fill and finite CPL3 execution.

- [ADR-0033: Owned-image incarnation activation](ADR-0033-owned-image-incarnation-activation.md) records exact live authority revalidation, retained hardware image ownership, atomic admission and stop-before-reclaim.
- [ADR-0034: Source-built Root Supervisor bootstrap](ADR-0034-source-built-supervisor-bootstrap.md) records the shared read-only startup contract, measured development bundle and real Rust userspace startup/fault boundary.

- [ADR-0035: Supervisor created service graphs](ADR-0035-supervisor-created-service-graphs.md) records creator authority, atomic child admission, generated Echo messages and ordinary child fault cleanup.

- [ADR-0036: Generation safe service retirement](ADR-0036-generation-safe-service-retirement.md) records explicit metadata reclamation, stale identity protection and retained logical endpoints.

- [ADR-0037: Bounded synchronous service transport](ADR-0037-bounded-synchronous-service-transport.md) connects protected causal calls to generated clients and actual scheduler waits.

- [ADR-0038: Sealed custodian lifecycle](ADR-0038-sealed-custodian-lifecycle.md) retains restart policy and exact incarnation ownership across replacement, with a consumed physical quiescence witness.

- [ADR-0039: Whole graph custody recovery](ADR-0039-whole-graph-custody-recovery.md) records transactional managed graph retirement and independently measured recovery admission.

- [ADR-0040: Transactional capability RPC](ADR-0040-transactional-capability-rpc.md) records exact protected completion, actual escrow ownership and explicit timeout/recovery outcomes.

- [ADR-0041: Mutex leases and IPC discipline](ADR-0041-mutex-leases-and-ipc-discipline.md) records actual lock ownership, nonce-aware replies and bounded guarded thread layouts.

- [ADR-0042: Scoped userspace PIO reference backend](ADR-0042-scoped-userspace-pio-reference-backend.md) records isolated device authority, the mediated instruction boundary and fresh-VM persistence verification.

- [ADR-0043: Bounded shared-buffer block transport](ADR-0043-bounded-shared-buffer-block-transport.md) records inactive mapping ownership, private sector staging and the first enforced buffer-lifetime profile.

- [ADR-0044: Durable generation publication and bound health](ADR-0044-durable-generation-publication-and-bound-health.md) records persistent operation identity, atomic COW publication, retained failure and authenticated service health.

- [ADR-0045: Scoped File/Object service](ADR-0045-scoped-file-object-service.md) records userspace endpoint-bound object access, server-assigned durable operation IDs, bounded logical retry and actual private-buffer/cold-reopen proof.

- [ADR-0046: Owned surfaces and userspace Display](ADR-0046-owned-surfaces-and-userspace-display.md) records bounded RAM extent leases, measured device-table admission and the first real scanout execution profile.

- [ADR-0047: Bounded desktop authority and live file grants](ADR-0047-bounded-desktop-authority-and-live-file-grants.md) records Root-only startup v2, compact control banks, sparse service rows and sustainable running-app selected READ delivery.

- [ADR-0048: Internal `.zion` package and activation metadata](ADR-0048-internal-zion-package-and-activation-metadata.md) records the shared AppIdentity key, self-contained container and bounded lifecycle metadata, with physical lifecycle integration still pending.
- [ADR-0049: Native Root package banks and durable App state](ADR-0049-native-root-package-banks-and-durable-app-state.md) defines the additive native profile, readonly complete packages and disjoint activation/private data, with actual lifecycle execution still required.

- [ADR-0050 — Measured Native Root stack budget](ADR-0050-measured-native-root-stack-budget.md)

- [ADR-0051 — Native scalar traps within preemptible quanta](ADR-0051-native-scalar-traps-within-preemptible-quanta.md)

- [ADR-0052 — Native System health and durable owner grants](ADR-0052-native-system-health-and-durable-owner-grants.md)

- [ADR-0053 — Measured Native Root image capacity](ADR-0053-measured-native-root-image-capacity.md)

- [ADR-0054 — Measured composed System execution budget](ADR-0054-measured-composed-system-execution-budget.md)

- [ADR-0055 — Source Root self-notification progress](ADR-0055-source-root-self-notification-progress.md)
