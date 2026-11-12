# ADR-0010 — Bounded second-CPU startup proof

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-025.21, INV-KERN-004, INV-KERN-005

## Decision

Start one enabled non-BSP processor discovered by MADT on the Q35 xAPIC target.
Retain a below-1-MiB SIPI trampoline frame, private AP page tables, an AP stack,
GDT and fatal IDT. The AP root copies only privileged upper-half kernel mappings
and adds a single RX identity trampoline page. The trampoline GDT has accessed
bits preset, so descriptor loads need not write the RX page. No user branch or
loader-owned low-half mapping is granted to the AP.

The BSP temporarily maps the verified LAPIC MMIO page in a private supervisor
UC branch; require the APIC-base MSR to agree with firmware and xAPIC mode.
Use directed INIT/SIPI with bounded delivery polling and PIT-channel-2 delays.
All BSP/AP interrupt-enable flags remain clear. The AP has its own fatal-entry
IDT; it never enters the single-BSP exception globals or writes serial output.

The AP validates identity, root and stack, publishes readiness, and waits for a
release/acquire command. Both CPUs perform a finite atomic increment workload;
the BSP requires the exact total and AP completion before restoring its original
root. The AP then remains parked with IF off. All referenced frames and statics
remain retained. One-CPU boots explicitly skip this proof; a skip cannot satisfy
multicore acceptance.

## Limits

This proves second-CPU execution and bounded shared-memory coordination, not
SMP scheduling, general per-CPU exception recovery, APIC timer routing, cache
coherence on arbitrary hardware or TLB shootdown. An AP fault records failure
and halts; the BSP's finite waits turn failed startup into an observable failure.
The initial AP IDT uses the dedicated boot stack and fatal gates, without a TSS
or IST recovery policy; scheduler bringup must replace it before enabling AP IRQs
or entering userspace. More than two online CPUs and x2APIC startup follow later.

## Verification

Run one-CPU skips and repeated two-CPU boots; require a distinct AP identity,
owned root, valid dedicated stack, completed handshake and exact shared count.
Exercise an intentionally withheld AP command to verify finite failure handling.
Previous topology, timer, isolation, panic and debugger regressions remain.

## Reference

[Intel system programming manual](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
defines xAPIC delivery, INIT/SIPI transitions and processor startup ordering.
