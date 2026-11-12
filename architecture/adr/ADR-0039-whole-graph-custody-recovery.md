# ADR-0039 — Whole graph custody recovery

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: ADR-0035–0038; ROOT_AUTHORITY_CUSTODY.md; INV-AUTH-003, INV-AUTH-007

## Decision

Connect the retained custodian to whole managed-graph retirement and a separately
measured minimal recovery executable. Preserve one Authority, Scheduler, Registry,
RPC owner, immutable boot selection and restart budget throughout replacement.
This implements the original BAC failure boundary; it does not move service policy
into the kernel or change the operating system's responsibility layers.

Ordinary service failure retains its unrelated peers and Root incarnation.
Catastrophic Root failure conservatively stops its entire managed graph. Creating
a fresh registry, allocator, clock or budget would conceal leaked ownership and
is not an accepted replacement mechanism.

## Trusted ownership and metadata

Registry Job bindings retain whether an object is externally sealed or managed.
Trusted Job forgetting stages scheduler reclamation and metadata changes together,
requires no process/child Job or causal RPC references, and retires only managed
authority objects. Unbinding the permanent creator object preserves that object.
Consumed CPU use remains attributed to the stable boot parent. Incarnation
selection advances exactly once after the old registry graph is empty; it cannot
reset generations, immutable images, limits or pooled domains.

A managed mailbox records its provenance at creation. Consuming retirement
requires closed/drained escrow and no retained capability nodes before retiring
its exact Endpoint descriptor. It returns an opaque, non-Clone closed-escrow
receipt. Reusing a receipt stages endpoint creation and domain-generation advance
together; refusal returns ownership without mutation. Ticket sequence and clock
remain monotonic. Permanent boot/event mailboxes cannot use managed retirement.
This receipt proves mailbox metadata retirement, not CPU or device quiescence.

## Catastrophe boundary

At the serialized controller boundary, fence creation and revoke Root branches,
then inhibit every retained graph process. Cleanup uses actual retained process
identities and executable owners, including held processes; revoked, moved or
closed public handles cannot authorize trusted teardown.

Retire execution and cancellation reservations before forgetting RPC rows. Never
wake terminated old-incarnation callers; suppress those diagnostic notifications
while retaining execution ownership until actual callee retirement. Drain accepted
capabilities before closing sender domains. Close failed Root authority domains
before collecting objects that their old handles still pin. Stop every executable,
restore the retained controller CR3, end leases, scrub/return backing and balance
live charges before constructing the private physical quiescence witness.

The old Root process and Job descriptors remain valid through custodian receipt
acceptance. Only afterward may they be reclaimed and closed Root domains recycled.
No replacement is admitted from a revoked flag, timeout or balanced counters alone.
The first hardware profile has a parked AP and no device/DMA grants; it cannot
certify arbitrary SMP, IRQ or DMA teardown.

## Independent recovery

A separate no_std executable receives only its measured Memory READ probe and
diagnostic Endpoint SEND. Its permanent custody roots are outside Root's revoked
tree. A distinct measured manifest and the existing owned executable admission
gate start it in the same Authority/Scheduler environment. The failed Root
custodian remains permanently latched; recovery does not recreate or reset it.

RecoveryReady acknowledges actual execution and startup-grant validation. The
trusted controller retains the real Root fault record, failed token and custodian
reason. This is a minimal independent recovery path, not the generation selection,
data preservation or recovery UI required for M3.

## Acceptance scope

The development profile admits an initial Root plus three replacements within a
finite window. Each Root creates two child services, completes generated calls,
moves a Process capability into a queue, then actually faults. Teardown must prove
old authority rejection, invalidated queue reclamation, fresh exact grants, one
active incarnation, resource baselines and eventual independent recovery without
a fifth Root. Transfer/revocation ordering is serialized; this is not a claim of
parallel CPU racing.

Failure injection at every reconstruction stage, corrupted boot selection,
production epoch/generation authentication and the complete AF-007/AF-IPC matrix
retain separate gates. Executed results belong in
[M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance); this decision alone is not PASS.
