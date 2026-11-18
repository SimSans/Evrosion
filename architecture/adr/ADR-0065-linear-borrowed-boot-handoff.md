# ADR-0065 — Linear borrowed boot handoff

Status: Accepted implementation refinement; isolated linked preflight passes, current integrated runtime validation pending.
Date: 2026-11-12. Founder engineering mandate Level B.
Related: ADR-0001/0004/0057; M6-02; the first M6 session stack-preflight refusal.

## Measured problem

The first actual M6 session image is refused before VM execution: its resolved
full-entry stack census is 264,960 bytes against the existing 262,144-byte boot
stack. The retained entry chain includes the loader adapter (12,544), Kernel
entry (12,560), entry closure (52,400), runtime world (138,192) and later channel
retirement (37,088) frames. These are actual linked fixed-frame measurements,
not a claim that every byte is simultaneously live or a formal high-water bound.

The validated handoff includes a fixed 512-entry memory map. Passing the entire
owned `Result<BootInfoV0, BootError>` through Kernel entry retains another large
frame throughout runtime. Increasing the boot stack would hide an avoidable
ownership/calling-convention cost. It would not improve that design.

## Decision

Keep one validated handoff object in the loader adapter. Change only the
Internal Rust handler contract to `Result<&mut BootInfoV0, BootError>`. The
borrow cannot outlive its adapter-owned value; Kernel entry never returns.
Validation errors still cross as their existing copied error value. The external
loader entry, temporary backend, firmware interaction, boot fields/layout,
schema, maximum regions and 256 KiB stack remain unchanged.

Preserve `BootstrapFrames::new(MemoryMap)` as a consuming ownership transfer.
Do not replace it with an allocator accepting a reusable shared map reference.
Add `MemoryMap::take(&mut self)` to transfer the existing non-Clone validated
map once. The old slot becomes an explicit empty placeholder: no regions, zero
usable bytes and no reserved-range witness. Further takes refuse with the
existing `EmptyMemoryMap` error. The sole allocator owns the actual map and all
existing cursor, frame-custody, reclamation and quiescence rules remain intact.
Revalidating a description of the same RAM still confers no physical authority,
as before; this API does not clone allocator state or reset an allocator cursor.

Boot diagnostics report the actual validated memory facts before transfer.
Subsequent memory-map checks use the allocator's retained map. Other boot fields
remain available through the borrowed handoff. No static mutable storage,
unchecked alias, heap allocation, new wire field or new loader feature is needed.
The named unstripped Kernel entry remains available for exact-artifact GDB.

## Evidence and limits

Eleven boot-contract tests pass, including actual adapter rejection/copy
ownership, one-time transfer with repeated refusal, and preservation of all 512
validated region classifications. Strict host and actual session-target checks
pass. GDB's complete type/layout output for `BootInfoV0` and `MemoryMap` is
identical in the old and new linked ELFs; the map remains 12,304 bytes with the
same field offsets. The failed candidate
and its original source are preserved; a separate direct-Cargo compile probe
uses that same candidate's actual retained component bundle with only this boot
handoff change. It is an optimization experiment, not a fresh source-pinned VM
or admission acceptance claim.

Its complete linked Kernel census falls to **251,696 bytes**, saving **13,264**
with **10,448 bytes** of headroom under the unchanged stack. The entry frame
falls to 64 bytes and the closure to 51,632; the adapter and large runtime/
retirement frames remain unchanged. Exact probe ELF SHA-256:
`16fc68189b60c5ffce5e0ef255f3d6595a5f82a24fa8d9595e9cee7968585ad8`.
No analyzer rule, reference edge or admitted bound is removed or increased.

This census retains its existing limitations around unresolved indirect calls,
cycles, raw assembly and interrupt/runtime high water. It does not make the
remaining large scratch frames desirable. Independent transaction/scratch work
may reduce those costs while preserving rollback and authority semantics.
Require the next frozen current-source linked preflight, exact symbols, normal
boot/serial/panic regressions and actual M6 session/resource/retirement checks
before claiming integrated acceptance. Prior immutable failure evidence and old
source pins remain valid for their original bytes.
