# ADR-0008 — Bootstrap interrupt clock and bounded deadlines

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-004, E-025.18, INV-KERN-001, INV-KERN-004, INV-IPC-004

## Decision

For the first Q35 bootstrap timer proof, route the legacy PIT through the PIC to
owned IDT vector 32. Remap the PIC away from exception vectors; mask all inputs
except IRQ0. The handler only advances a monotonic tick counter and acknowledges
the interrupt; it does not allocate, format diagnostics, schedule or block.
CPU-local APIC timers and interrupt topology remain required before SMP scheduling.
This deliberately bounded bootstrap backend is not a general device-driver API.

Use absolute deadlines in clock ticks, with checked addition rejecting overflow.
Ticks never wrap. A deadline cannot be extended by retries. The bootstrap waiter
has both a deadline and a finite polling budget, so a stopped interrupt clock is
detected without an unbounded HLT. Tick units are explicit; no wall-clock or
nanosecond accuracy is claimed. Device calibration/high-resolution clocks follow.

The proof starts with interrupts disabled, initializes PIC/PIT, demonstrates a
bounded wait failure while IRQ0 is masked, then enables IRQ0 and IF for a finite
wait. It finishes with IF off and all PIC inputs masked. Other bootstrap code
retains its documented interrupt-disabled lifecycle until scheduling work.

## Verification and limits

Host tests cover exact deadline boundaries, overflow and finite poll exhaustion.
QEMU must deliver repeated interrupts, satisfy an eight-tick deadline and return
with IF cleared; the masked-clock probe must fail within its polling budget.
Previous allocator, paging, supervisor/user fault, panic and debugger checks remain.
This does not establish device routing, preemption, SMP time synchronization or
IPC deadline enforcement. Those need their own executed proofs.

## Sources

[Intel PIC specification](https://pdos.csail.mit.edu/6.828/2010/readings/hardware/8259A.pdf)
and [Intel PCH timer specification](https://cdrdv2-public.intel.com/635218/635218-008.pdf)
define initialization, acknowledgement and PIT mode 2 programming.
