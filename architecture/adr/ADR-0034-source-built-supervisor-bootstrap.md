# ADR-0034 — Source-built Root Supervisor bootstrap

Status: Accepted
Date: 2026-10-19
Owners: Project owner; kernel/platform maintainers
Related: ADR-0027–0033, INV-AUTH-003, INV-AUTH-007, INV-KERN-005

## Decision

Replace the gap between admitted ELF fixtures and actual userspace code with a
separate Rust/no_std Root Supervisor startup executable. Use one shared Internal
codec for its startup record and versioned Ready event. The matching build tool
produces the executable and measured manifest; ordinary incarnation admission
retains the loaded root and revalidates its authority before dispatch.

This additive Level B integration preserves the custody, single-incarnation,
least-authority and quiescence requirements. It supersedes no foundation or
historical acceptance claim. It is a bootstrap skeleton, not completion of the
supervisor's process creation, service graph, automatic restart or AF-007 gates.

## Bundle and trust boundary

`cargo ev build` uses the repository-pinned compiler to build normal and separately
identified fault-injection variants from `services/root-supervisor`. Both are
validated by the kernel's authoritative manifest/ELF parser before embedding.
The normal variant contains no fault injection. The development kernel embeds
both exact artifacts and their manifest measurements; the build manifest records
all four ELF/manifest hashes and boot verifies them. No hand-assembled service
ELF, runtime host download or new third-party crate is involved.

The build producer explicitly requests two measured grants: a Memory READ handle
and an Endpoint SEND handle. The kernel resolves those against actual custody
roots; the receiver's RECEIVE/CONTROL rights stay kernel-owned. A name, process
identity or successful startup message grants no additional authority.

This is a source-built development bundle. It does not authenticate a production
SystemGeneration, seal the complete BAC, or generate a unique trusted boot epoch.
The acceptance controller uses an explicit deterministic isolated epoch. Direct
lint builds have empty bundle placeholders and must fail if actually executed;
only the recorded build frontend supplies the runnable matching bundle.

## Read-only startup record

`libs/userspace-contract` is a no_std, unsafe-free codec shared by the kernel,
producer and service. Its ABI fingerprint is SHA-256 of a pinned description,
checked by a producer test. A manifest with that measured fingerprint requests a
336-byte bootstrap record in window page 509, read-only and NX. Page 510 remains
the stack guard and page 511 is the private RW/NX stack. Image segments cannot
overlap the record; its additional physical frame is charged before loading.
The previous fixture ABI keeps its original layout and measurements.

The record contains version/length/reserved fields, boot epoch, incarnation,
diagnostic process identity, finite Job limits, both measured digests and up to
eight exact typed selector/handle/rights grants. It rejects zero identities,
invalid rights, duplicate or unsorted selectors, nonzero reserved bytes and
nonzero unused slots. Handles are volatile instance-local authority references,
not durable policy. RDI supplies the record address and RSI its exact length.

The held binding constructs the record from its current token and actual derived
handles. The hardware loader copies it into the zeroed final-permission page and
reads back every byte, including the zero tail. Loaded-image ownership now retains
the record's address, length and digest. Activation recomputes all three from the
current binding before releasing admission; a foreign or changed record stays
held. This extends the existing unsafe hardware ownership contract without adding
unsafe instructions to portable policy code.

## Execution and fault boundary

The service validates the record and required grant types/rights, probes permitted
READ, checks WRITE and an invalid handle are denied, and sends one versioned Ready
event through its SEND handle. Ready describes successful bootstrap validation,
not system readiness. The normal skeleton then yields through the Internal scalar
syscall ABI until future lifecycle operations are implemented.

The kernel reuses the existing CPL3 context/FX/trap runner. Every trap restores
the controller CR3 before scheduler, authority or mapping mutation. Timer IRQs,
a finite absolute startup deadline and a finite trap bound contain broken startup.
No user pointer is dereferenced in these kernel syscall operations. The event
travels through the existing capability-checked bounded mailbox and is decoded
with the shared versioned codec.

The separate fault build writes its read-only startup page after Ready. The actual
CPL3 page fault supplies process/thread, vector/error, fault address and instruction
for the existing structured diagnostic type. That fault drives dispatch inhibition,
whole-incarnation revocation and process retirement. The normal acceptance case
also stops explicitly after two yields. Only after original CR3 restoration,
parked APs, empty mailbox and ended image leases may either image's frames be
scrubbed/recycled and its Job's live resource charges returned to zero. CPU ticks
remain consumed historical usage. No DMA/device authority is granted here.

## Verification and remaining work

Host tests cover malformed records/events, exact service grants, ABI/measurement
binding, record-page frame budget and overlap, changed address/length/digest and
missing startup metadata. Strict protocol tests reject duplicate, malformed and
out-of-order supervisor records. Repeated one/two-CPU QEMU boots must execute both
actual Rust artifacts, observe Ready twice, deny four excess/invalid inspections,
capture the real read-only write fault and return all charged private frames.
Executed evidence is linked from [M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).

This is BSP execution with the AP parked and PCID off. Scheduler/object descriptors
remain retained. Sealed singleton custody, production epoch/bundle authentication,
service creation and typed echo/control IPC, managed service-graph teardown,
bounded replacement, independent recovery and full AF-007A–H remain pending.
Revoked still does not authorize a replacement incarnation.
