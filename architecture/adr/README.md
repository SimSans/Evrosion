# Architecture Decision Records

Extracted from the [Pre-M0 implementation package](../plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This is the working canonical file; the imported package remains unchanged.

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

- [ADR-0102: Native document editing and semantic contract](ADR-0102-native-document-editing-and-semantic-contract.md)
  records the selected0.3 document flow, compatible File storage and distinct
  edit-consent contract; runtime qualification is pending.

- [ADR-0101: Phase-local bootstrap and update record storage](ADR-0101-phase-local-bootstrap-and-update-record-storage.md)
  records the 0.2 stabilization refinement, unchanged ownership/checks and its
  source-bound qualification requirements.

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

- [ADR-0058: Bounded ISA network device choice](ADR-0058-bounded-isa-network-device.md)
  records the reviewed QEMU NE2000 source boundary, safe bounded packet helpers
  and required actual device retirement/integration proofs still pending.
- [ADR-0059: Time and entropy consumer contracts](ADR-0059-time-and-entropy-contracts.md)
  records same-boot monotonic/freshness/readiness types, with actual trusted
  provider, source and CSPRNG qualification still pending.

- [ADR-0056 — Renewable bounded CPU windows](ADR-0056-renewable-bounded-cpu-windows.md)

- [ADR-0064 — Guarded scalar RPC and declared endpoint delivery](ADR-0064-guarded-scalar-rpc-and-endpoint-delivery.md)

- [ADR-0061-sequenced-text-and-relative-pointer](ADR-0061-sequenced-text-and-relative-pointer.md).

- [ADR-0062-userspace-network-pio-adapter](ADR-0062-userspace-network-pio-adapter.md).

- [ADR-0063-bounded-userspace-network-stack](ADR-0063-bounded-userspace-network-stack.md).

- [ADR-0065-linear-borrowed-boot-handoff](ADR-0065-linear-borrowed-boot-handoff.md).

- [ADR-0060: Sustained developer-session execution profile](ADR-0060-sustained-developer-session-profile.md)

- [ADR-0067 — Retained exclusive blank observation for Native install](ADR-0067-retained-exclusive-blank-observation.md)

- [ADR-0066 — Session notes and a dedicated note window](ADR-0066-session-note-and-dedicated-window.md)

- [ADR-0068 — Sustained-session diagnostic retention](ADR-0068-sustained-session-diagnostic-retention.md)

- [ADR-0069 — V4 network graph admission](ADR-0069-v4-network-graph-admission.md)

- [ADR-0071 — Bounded private random generator](ADR-0071-private-random-generator.md)

- [ADR-0072 — Bounded common release metadata verifier](ADR-0072-bounded-release-metadata-verifier.md)

- [ADR-0073 — Async maintenance at each captured timer tick](ADR-0073-async-maintenance-per-captured-tick.md)

- [ADR-0074 — Reviewed developer-VM random source](ADR-0074-reviewed-vm-random-source.md)

- [ADR-0075 — Bounded four-word port operations](ADR-0075-bounded-four-word-port-operations.md)

- [ADR-0077 — Measured V4 Root image capacity](ADR-0077-measured-v4-root-image-capacity.md)

- [ADR-0078 — Private resident V4 Controller](ADR-0078-private-resident-v4-controller.md)

- [ADR-0079 — Scoped VM elapsed clock and read-only RTC](ADR-0079-scoped-vm-elapsed-clock.md)

- [ADR-0080 — Owned content continuations](ADR-0080-owned-content-continuations.md)

- [ADR-0082 — Private affine signed-time client staging](ADR-0082-private-affine-time-client.md)

- [ADR-0081 — Owned dynamic executable admission](ADR-0081-owned-dynamic-executable-admission.md)

- [ADR-0083 — Resident Root content provisioning and inspection](ADR-0083-resident-root-content-mount.md)

- [ADR-0084 — Measured V4 content-controller image capacity](ADR-0084-measured-v4-content-controller-capacity.md)

- [ADR-0085 — Monotonic local TCP ports](ADR-0085-monotonic-local-tcp-ports.md)

- [ADR-0086 — Coalescing bootstrap frame recycler](ADR-0086-coalescing-bootstrap-recycler.md)

- [ADR-0087 — Persistent private time challenge ownership](ADR-0087-persistent-private-time-challenges.md)

- [ADR-0088 — Authenticated local cold Source startup](ADR-0088-authenticated-cold-source-startup.md)

- [ADR-0089 — Qualified reviewed-VM clock bound to the actual Store](ADR-0089-qualified-vm-update-clock.md)

- [ADR-0090 — Durable local update selection](ADR-0090-durable-local-update-selection.md)

- [ADR-0091 — Bounded remote candidate acquisition](ADR-0091-bounded-remote-candidate-acquisition.md)

- [ADR-0092 — Downloaded cohort health and retained authorization](ADR-0092-downloaded-cohort-health-and-retained-authorization.md)

- [ADR-0093 — Measured V4 acquisition image capacity](ADR-0093-measured-v4-acquisition-capacity.md)

- [ADR-0094 — Measured V4 cohort-controller capacity](ADR-0094-measured-v4-cohort-controller-capacity.md)

- [ADR-0095 — Failed V4 NIC retirement through the captured Root](ADR-0095-failed-v4-nic-retirement.md)

- [ADR-0096 — Negotiated fixed byte-port groups](ADR-0096-negotiated-byte-port-groups.md)

- [ADR-0097 — Required-subject presentation ordering](ADR-0097-required-subject-presentation-ordering.md)

- [ADR-0098 — Measured V4 owner-controller image capacity](ADR-0098-measured-v4-owner-capacity.md)

- [ADR-0099 — Protected owner first-use preparation](ADR-0099-protected-owner-first-use-preparation.md)

- [ADR-0100 — Versioned downloaded-cohort startup policy](ADR-0100-versioned-downloaded-cohort-startup-policy.md)

- [ADR-0101 — Phase-local bootstrap and update-record storage](ADR-0101-phase-local-bootstrap-and-update-record-storage.md)

- [ADR-0102 — Native document editing and semantic contract](ADR-0102-native-document-editing-and-semantic-contract.md)

- [ADR-0103 — V4 bootstrap source retirement and grant headroom](ADR-0103-v4-bootstrap-source-retirement-and-grant-headroom.md)

- [ADR-0104 — Bounded workspace dataset and durable namespace](ADR-0104-bounded-workspace-dataset-and-durable-namespace.md)

- [ADR-0105 — Versioned workspace and larger-file contracts](ADR-0105-versioned-workspace-and-large-file-contracts.md)

- [ADR-0106 — Bounded workspace interaction and protected consent](ADR-0106-workspace-interaction-and-protected-consent.md)

- [ADR-0107 — Read-only Job inspection through retained Process CONTROL](ADR-0107-process-control-job-inspection.md)

- [ADR-0108 — Read-only serving RPC origin](ADR-0108-readonly-serving-rpc-origin.md)

- [ADR-0109 — Selected V5 workspace resource envelope](ADR-0109-selected-workspace-resource-envelope.md)

- [ADR-0110 — Native workspace clients and actual self identity](ADR-0110-native-workspace-clients-and-self-identity.md)

- [ADR-0112 — Exact workspace route and stage reconciliation](ADR-0112-workspace-route-and-stage-reconciliation.md)

- [ADR-0111: Managed SEND retirement and selected V5 physical ownership](ADR-0111-managed-send-retirement-and-selected-v5-runtime.md)

- [ADR-0113: Measured workspace bundle and owned development preview](ADR-0113-workspace-development-bundle-and-owned-preview.md)

- [ADR-0114 — Native paged semantics and scoped actions](ADR-0114-native-paged-semantics-and-scoped-actions.md)

- [ADR-0115: Selected V5 dynamic File App admission and retired buffer scrub](ADR-0115-selected-v5-dynamic-file-app-admission.md)

- [ADR-0116: Selected fixed-sector PIO over captured private RAM](ADR-0116-selected-fixed-sector-pio.md)

- [ADR-0117 — Measured Current package bank](ADR-0117-measured-current-package-bank.md)

- [ADR-0118 — Finite whole-file transfer horizons](ADR-0118-finite-whole-file-transfer-horizons.md)

- [ADR-0119 — Bounded staged File verification](ADR-0119-bounded-staged-file-verification.md)

- [ADR-0120](ADR-0120-isolated-external-app-private-allocation.md) — isolated external App private allocation and pre-replay payload checks (Internal Level B; native enrollment qualification pending).

- [ADR-0121 — Captured session power and terminal diagnostics](ADR-0121-captured-session-power-and-terminal-diagnostics.md)

- [ADR-0122 — Compact executable and retained analysis ELF](ADR-0122-compact-executable-and-retained-analysis-elf.md)

- [ADR-0123 — Authenticated File2.1 admission and versioned selection](ADR-0123-authenticated-file21-admission-and-versioned-selection.md)
- [ADR-0124 — Checked reference restart](ADR-0124-checked-reference-restart.md)
- [ADR-0125 — Measured nonexecuting external package ingress](ADR-0125-measured-nonexecuting-external-package-ingress.md)
- [ADR-0126 — Protected local development install and run](ADR-0126-protected-local-development-install-and-run.md)
