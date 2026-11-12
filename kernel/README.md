# Kernel

Evrosion's Rust no_std/no_main x86-64 kernel implements bounded M1/M2 mechanisms.
The adapter supplies validated BootInfoV0, and COM1 diagnostics and strict test
markers report actual execution. `cargo ev build` creates the development UEFI
image; `cargo ev run` boots it. Without `qemu-test-exit`, the kernel halts after its
report. It includes mechanism tests and separately measured Rust userspace services.

Run `python3 tools/m2/binding.py` for cumulative host, QEMU, failure-image and
governance checks. See [M2 readiness](../docs/release/0.1-preview.md#validation-and-provenance) and the
[acceptance contract](../architecture/M2_ACCEPTANCE.md) for the accepted scope.

The portable library contains physical-frame ownership/recycling, mapping models,
capability tables with attenuated derivation and revocation, shared Memory Object
leases, hierarchical Job admission/accounting, scheduling and bounded wait queues.
An asynchronous mailbox owns transferred capabilities in escrow until delivery,
expiry or peer-death reclamation. Dynamic anonymous allocations require a bound
Job capability and roll back backing and charges on failure.

The hardware boundary owns GDT/TSS/IDT, guarded stacks, page tables, PIC/PIT timer
entry and exact protection probes. Real CPL3 contexts run under timer preemption,
with integer and x87/XMM/MXCSR state preserved. Scalar calls enforce the selected
process's authority; no user pointer is dereferenced by the call decoder. Ordinary
UD/PF/GP faults retire the process and deliver a bounded diagnostic to an authorized
observer. Quiescent teardown removes leases, zeroes and recycles backing. Revoked
live mappings disappear before another user dispatch.

ACPI topology and xAPIC startup bring up a second CPU with private entry state and
shared atomic work. It then parks. Userspace and mapping mutation are BSP-owned;
SMP scheduling, remote TLB shootdown and general AP interrupt recovery remain
future work. Metadata has explicit fixed capacities and retained identities.
Unsupported AVX/XSAVE and FSGSBASE stay disabled. TLS, arbitrary program loading
and SMP user scheduling remain separate work.

M2 adds measured static ELF64 loading and typed incarnation activation. Portable
implementations use safe Rust under `deny(unsafe_code)`; narrowly annotated
unsafe trait declarations describe loaded backing ownership and complete
incarnation quiescence. They perform no unsafe operations. Their hardware implementations retain the actual
loaded root through admission and stop. Host model implementations are test-only.
See [ADR-0033](../architecture/adr/ADR-0033-owned-image-incarnation-activation.md)
and [M2 progress](../docs/release/0.1-preview.md#validation-and-provenance) for scope and executed evidence.

The source-built Root Supervisor now enters through that gate with a shared
read-only/NX startup contract. Its development acceptance verifies explicit
grants, a typed Ready event, actual fault-driven stop and balanced reclamation.
Root creates/delegates typed Echo services. Actual capability-bearing calls,
waits/expiry/late isolation, mutex/forwarding/depth discipline, sustained service
replacement and whole Root graph recovery pass the bounded M2 gate. See
[ADR-0035](../architecture/adr/ADR-0035-supervisor-created-service-graphs.md),
[ADR-0037](../architecture/adr/ADR-0037-bounded-synchronous-service-transport.md) and
[ADR-0038](../architecture/adr/ADR-0038-sealed-custodian-lifecycle.md).

M3 adds scoped IoPorts authority and a binary-only instruction boundary under
[ADR-0042](../architecture/adr/ADR-0042-scoped-userspace-pio-reference-backend.md).
The userspace block driver owns the device protocol. The isolated storage
workflow now passes actual write/flush/readback and fresh-VM verification;
[block evidence](../docs/release/0.1-preview.md#validation-and-provenance) preserves
that bounded result. Complete persistent-machine acceptance remains pending. Device-free Root recovery receipts
cannot certify device-bearing teardown. See [M3 progress](../docs/release/0.1-preview.md#validation-and-provenance).

Read [E-002](../architecture/plans/core/E-002-kernel-architecture.txt), the
[invariants](../architecture/INVARIANTS.md) and the
[accepted ADRs](../architecture/adr/README.md) before changing privileged mechanisms.

M4 adds bounded RAM extent initialization and device Display ownership contracts.
`RamAccess` and `DisplayBacking` are narrowly annotated unsafe trait declarations
under the safe core; real pointer/MSR/page-table operations remain in binary HAL.
No model implementation is hardware evidence. See
[ADR-0046](../architecture/adr/ADR-0046-owned-surfaces-and-userspace-display.md).
