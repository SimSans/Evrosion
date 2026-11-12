# ADR-0024 — Bounded capability-routed fault notifications

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0015, ADR-0016, ADR-0018

## Decision

Retirement of an ordinarily faulting user process emits a fixed 48-byte diagnostic
record through a kernel-held SEND capability. An explicitly bound observer has
RECEIVE/CONTROL rights and receives process/thread diagnostic IDs, vector, error,
fault address and instruction address. IDs are descriptive, never authority.
Records contain scalar values and no copied user memory or kernel pointers.

Use the existing four-message, 64-byte mailbox with a finite absolute delivery
expiry. Publishing never waits. Full, closed or invalid observer channels count a
dropped diagnostic without delaying process containment. Receipt checks the
caller's trusted domain and endpoint rights. This replaces the runtime fixture's
ambient peer-state query. Ordinary syscall errors remain scalar return codes.

The bootstrap observer polls finitely; general observer service supervision and
restart belong to M2. Kernel faults, NMI, double fault and machine check retain
the fatal boundary rather than becoming ordinary process notifications.

## Verification

[Portable evidence](../../docs/release/0.1-preview.md#validation-and-provenance)
links 73 host tests and cumulative QEMU/debugger results. Actual UD, PF and GP
records reach surviving CPL3 processes once; missing receive authority is denied.
Host tests exercise malformed records, unauthorized publication/receipt, queue
exhaustion and dead-observer publication. The kernel preserves fault containment
when diagnostics cannot be queued.
