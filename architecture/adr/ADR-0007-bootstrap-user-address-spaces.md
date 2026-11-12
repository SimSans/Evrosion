# ADR-0007 — Bootstrap user address spaces and privilege tests

Status: Accepted
Date: 2026-09-30
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-005, E-025.18, E-025.23, INV-KERN-003, INV-KERN-004, INV-KERN-005

## Decision

Under the owner's instruction to continue through 0.1, extend the single-CPU
bootstrap proof with separately owned user roots. Select one unused lower-half
PML4 slot and attach private tables. Preserve boot mappings with the USER bit
cleared at every inherited root entry. Loader mappings may still occupy lower
addresses; they remain supervisor-only. This bounded test window is Internal,
not the eventual process layout or a user ABI.

Each root owns its code, data and stack frames. Zero before mapping, map code
read/execute and data/stack read/write with NX, and retain unmapped stack guards.
No writable/executable permission exists in the portable mapping API. Only the
new branch grants user access. Frame ownership transfers on map and remains
retained; allocator reuse and general Memory Object capabilities follow later.

Enter deterministic position-independent test code at CPL3 using IRETQ with
fixed user selectors, cleared general registers except explicit fixture inputs,
IF=0 and IOPL=0. TSS entry selects a dedicated supervisor stack. Exception entry
records only an exactly expected fault and returns through an assembly trampoline
to the saved bootstrap stack. Do not IRET into arbitrary kernel addresses or
pretend this is a scheduler or syscall ABI. Unexpected traps remain fatal.

## Proof obligations

Show distinct data at the same VA under two roots, denial of another root's
private-only page, kernel and physical-alias denial, code write denial, NX denial,
stack access/guards, user I/O denial, and continued execution of a healthy root
after a fault. All expected records require CPL3, exact RIP/vector/error/CR2
(where defined), user SS/RSP and non-elevated flags. Restore the original CR3.
No public syscall gate is installed and no user address is dereferenced in Rust.

## Limits and next work

This does not implement arbitrary process fault delivery, preemption, capabilities,
shared Memory Objects, frame reclamation, SMP or TLB shootdown. Interrupts remain
disabled and only finite trusted fixtures execute; QEMU's timeout bounds failure.
The M1 exit containment proof still needs the scheduler and fault-delivery path.
The saved stack and descriptors must become per-CPU before APs use them.

## Reference

[AMD64 System Programming](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf)
defines privilege transitions, TSS stack selection, paging and exception frames.
