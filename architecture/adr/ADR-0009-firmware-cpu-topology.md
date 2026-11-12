# ADR-0009 — Bounded firmware CPU topology

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-025.21, INV-KERN-004, INV-KERN-005, INV-M0-004

## Decision

Extend the Internal boot handoff with an optional physical ACPI RSDP address,
keeping the temporary loader type inside its adapter. Before dereference, require
the requested bytes to lie within one retained reserved memory region, validate
offset arithmetic, and bound each table read. This prevents reading allocator-owned
RAM; it does not make hostile firmware or MMIO pointers trustworthy. The existing
trusted-loader/platform assumption remains explicit.

Parse RSDP, RSDT/XSDT and MADT in allocation-free safe Rust. Check lengths,
signatures, checksums, pointer arithmetic, record sizes, duplicate enabled CPU
identities and CPU-count limits. Support enabled Local APIC and x2APIC records;
record the local APIC address, including a single valid override. Ignore disabled
CPUs until a separately designed hotplug path exists. Unknown bounded records
are skipped, never interpreted as processor records. Cap tables at 64 KiB,
root entries at 256 and enabled CPUs at 64 for this Internal bootstrap stage.

Read the BSP ID through CPUID and require it in the discovered enabled set.
Test firmware enumeration under both one- and two-CPU QEMU configurations.
Enumeration is a startup prerequisite, never proof that the second CPU executed.
No AP is started by this change; existing bootstrap globals stay single-CPU.

## Verification and limits

Host tests cover truncated/corrupt tables, lengths, reserved bytes, duplicate IDs,
capacity limits, disabled processors and LAPIC overrides. Real UEFI boots must
report the configured CPU count with a valid BSP and LAPIC address. AP startup,
per-CPU descriptors/stacks, APIC routing and synchronization remain pending.

## Reference

[ACPI 6.6, chapter 5](https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html)
defines the RSDP, root tables and MADT processor records. No AML interpreter or
firmware runtime service is added to the kernel.
