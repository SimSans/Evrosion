# ADR-0016 — Scheduled user contexts and scalar capability IPC

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-008, E-009, INV-KERN-003, ADR-0007, ADR-0013–0015

## Decision

Integrate the existing scheduler, private user roots, capability tables and
mailbox in a bounded BSP runtime proof. Each selected thread determines its
process, Job, root and capability space in kernel-owned state. Userspace supplies
operation arguments and handles, never a caller identity or a clock value.

An Internal DPL3 interrupt gate at vector 128 accepts scalar register arguments.
All other gates remain privileged. Unknown operations and unsupported rights
fail without authority mutation. Messages carry eight scalar bytes and at most
one moved capability; no user pointer is dereferenced. Existing endpoint rights,
escrow and absolute deadline checks remain the authorization boundary. This
fixture interface is not a versioned public service contract.

Every CPL3 IRQ, call or contained fault captures the 15 general registers and
the processor return frame on the owned TSS entry stack, then returns to one
serialized controller with interrupts disabled. IRQ0 is acknowledged before
returning. The controller handles the event, chooses a runnable thread, switches
CR3 and resumes a validated context with IRET. No Rust borrow of runtime state
survives mutation by an interrupt handler; captured results use separate static
slots. Context size and instruction offsets are compile-time checked.

The return frame requires canonical lower-half instruction/stack addresses,
the exact user selectors, IF set, and no IOPL, NT or VM privilege state. Ordinary
user exceptions terminate their selected thread; they do not use the earlier
exact-address bootstrap probe recovery. Kernel faults, NMI, double faults and
machine checks remain fatal. Debug exceptions caused by user single stepping
are ordinary user faults. Terminated threads cannot be dispatched again.

## Executable proof

Three pairs of private processes share the same virtual layout but distinct
physical code, data and stack pages. IRQ0 preempts both members at least twice.
One process sends a scalar message with an attenuated memory-descriptor grant.
The other receives it, rejects WRITE and accepts READ. The sender's old handle
fails after transfer. An unknown call and an invalid endpoint fail explicitly.

The sender then executes UD2, reads unmapped address zero, or executes CLI at
CPL3. Its peer observes the recorded fault through a fixture-only query,
continues checking private data, and exits successfully. All six threads must
reach Exited; all three messages must arrive; kernel root and IF are restored.
The query and per-thread tick counter are diagnostic fixture operations, not a
general fault-subscription or accounting API. A separate negative image executes
CPL0 UD2 with runtime active; the kernel must still report failure and exit.

## Limits

This is a finite hardware integration proof with built-in integer-only payloads.
It does not load arbitrary programs or preserve floating-point/SIMD, FS/GS base
or other extended per-thread state. Those must be implemented before executing
general untrusted applications. The AP remains parked. Controller and entry
stacks are privileged; user stacks have unmapped neighboring pages.

All mappings and frames remain retained. The transferred Memory descriptor does
not grant a memory-mapping syscall or prove shared Memory Objects. Fault records
are bounded kernel slots, not capability-routed supervisor notifications.
There are no scheduler wait queues: fixture polling, dispatch counts and message
deadlines are finite. Process teardown, mailbox cleanup on actual peer death,
memory reuse, CPU-time budgets, BAC custody, synchronous ancestry/deadlock rules,
and integrated M1 acceptance remain required. Service restart belongs to M2.
