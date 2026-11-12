# ADR-0012 — Cooperative kernel contexts on guarded stacks

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-025.23, ADR-0011

## Decision

Extend the bounded scheduler with a BSP-only hardware proof of two cooperative
kernel contexts. Retain one private page-table branch, two 16-KiB RW/NX supervisor
stacks and unmapped guard pages at each end. Preserve inherited privileged
mappings without editing them. Restore the original root when both workers exit;
no physical frame is reclaimed or exposed to userspace.

A small System V assembly boundary saves RSP and all six callee-saved registers.
Initial stack frames enter Rust with correct 16-byte call alignment and a fatal
return sentinel. Both contexts share CR3, kernel segments and IF=0. The bare-metal
kernel target has no red zone and uses soft-float; this boundary is not a SIMD,
userspace, asynchronous preemption or address-space switch contract.

The controller alone owns the Scheduler. It consumes a worker request only after
returning to its own boot stack. No mutable scheduler/context reference survives
the switch. Raw retained context slots and atomic request fields belong solely
to the BSP; parked APs and exception handlers never enter this cooperative path.
Each dispatch charges its immutable Process/Job owner through ADR-0011.

## Verification

Two real threads each yield sixteen times with distinct callee-saved register
sentinels and private local stack data. They then block; one resumes by signal,
the other by an absolute deadline advanced by the controller. Both exit, leaving
36 dispatches, 72 hardware switches and 18 dispatches per Job. Exact fault probes
verify all four stack boundaries are unmapped. A separate image corrupts saved
r12 after a yield; the resumed assembly probe must report the damage and the
kernel must fail with the expected diagnostic and QEMU exit status.

## Limits and next work

This establishes cooperative hardware contexts, not time slicing. Deadlines in
this fixture are deterministic logical ticks, not live timer-driven rescheduling.
It does not establish lost-wakeup-safe event queues, SMP scheduling, per-process
roots, CPU-time accounting or user-process fault containment. Retained slots and
frames are bootstrap resources. Next integrate timer-driven interruption and
process lifetime/authority before M1 acceptance. The AP fatal entry still cannot
serve as a general per-CPU scheduling/interrupt boundary.
