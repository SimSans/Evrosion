# ADR-0006 — Owned exception entry and bounded protection probes

Status: Accepted
Date: 2026-09-30
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-005, E-020, E-025.18, INV-KERN-003, INV-KERN-004, INV-KERN-005, INV-M0-002

## Context

The owner instructed continued implementation toward 0.1 without stopping at
each slice. Permission-bit inspection cannot establish actual access denial.
Exception entry is an M1-03 prerequisite of the remaining M1-02 isolation tests.

## Decision

Install kernel-owned GDT, TSS and IDT state on the bootstrap CPU with interrupts
disabled. Provide dedicated double-fault and NMI stacks and a reserved ring-0
entry stack. The TSS I/O bitmap lies beyond its limit, denying user I/O by default.
Keep device interrupts disabled until routing/timer work is implemented.

Use an assembly exception boundary that normalizes vector/error fields, saves
all general registers, clears DF and aligns the stack for the C ABI. The bare-metal
target has no red zone and uses soft float; no vector state is used by the Rust
handler. Return with IRETQ only after a validated, explicitly armed kernel test
fault. Do not rely on mutations to LLVM's by-value x86-interrupt arguments.

The temporary probe interface is private kernel test machinery. It accepts only
three exact code sites (read, write, instruction-fetch probe), expected CR2 and
page-fault error code, and one statically chosen recovery trampoline. Recovery
cannot be requested by userspace and must not skip arbitrary faulting instructions.
Unexpected/nested faults produce bounded serial failure output and halt.

## Invariants preserved

- INV-KERN-003: faults are observable; user containment remains a later proof.
- INV-KERN-004: fixed descriptor tables/stacks and one outstanding probe per CPU.
- INV-KERN-005: assembly and raw descriptor access stay in a documented boundary.
- INV-M0-002: an unexpected exception cannot emit a success result.

## Alternatives considered

Continuing to inspect permission bits would not prove hardware protection. An
exception handler that increments RIP unconditionally would hide real kernel
bugs. The fixed probe sites and exact error matching provide a narrower test path.

## Consequences and failure analysis

This is bootstrap-only: no AP uses these global tables or stacks. Probe recovery
is not a user pager, scheduler, syscall ABI or general kernel fault policy. GDT
user descriptors prepare the boundary but confer no process authority. The stack
entry ABI and offsets require assembly/layout checks and real QEMU tests. Register
state and the CPU's interrupt frame remain owned by the assembly entry until return.

## Verification

Host tests check gate/TSS encoding and recovery matching. QEMU must deny writes
to read-only supervisor pages with CR0.WP set, instruction fetch from NX pages,
and reads from unmapped pages. Exact fault addresses/error codes and continued
execution are checked. Bootstrap mapping and panic/serial/debug regressions remain.

## Migration / rollback

Preserve M0 evidence. Future per-CPU state, user traps and scheduling replace the
single boot probe with explicit process-fault delivery, retaining unexpected
kernel faults as fatal. No new external dependency or Stable interface is added.

## Review trigger

Review before AP startup, enabling interrupts, user entry, SIMD in handlers,
stack-layout changes or syscall ABI exposure.

## Technical references

- [AMD64 system programming manual](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2), exception frames and descriptor tables.
- [Rust bare-metal target](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html), C ABI, red zone and vector-state constraints.
- [x86_64 interrupt-frame notes](https://docs.rs/x86_64/latest/x86_64/structures/idt/struct.InterruptStackFrame.html), limitations of modifying LLVM interrupt arguments.
