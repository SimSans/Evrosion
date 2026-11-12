# ADR-0005 — Bootstrap page-table ownership and mapping proof

Status: Accepted
Date: 2026-09-30
Owners: Project owner; kernel and boot-contract maintainers
Related: E-002, E-005, E-025.18, INV-KERN-001, INV-KERN-004, INV-KERN-005, INV-M0-004, INV-EVO-001, INV-EVO-002

## Context

The owner instructed continuation into M1-02 after bootstrap frame allocation
passed. Selecting a frame does not make it accessible. The temporary loader's
optional direct physical mapping supplies the initial page-table access path.
The boot contract already represents and validates its offset.

## Decision

Enable `Mapping::Dynamic` for physical memory inside the existing loader adapter.
Require page alignment and canonical checked arithmetic for the received offset.
Extend EXC-0001 explicitly for this M1 bootstrap use; keep the contract Internal.
Access only allocated usable frames and the current CR3 root, not arbitrary MMIO.

Build two owned four-level roots. Copy each loader PML4 entry unchanged, select a
zero upper-half entry, and attach private zeroed PDPT/PD/PT frames there. Limit
this first interface to one 2 MiB scratch window per root, with 4 KiB supervisor,
non-global, non-executable data mappings. Existing loader/kernel mappings are
shared and never edited or reclaimed. These are bootstrap roots, not user roots.

The portable leaf model consumes frame tokens on map and returns them on unmap.
Duplicate, missing and out-of-window operations fail without losing ownership.
Hardware writes use raw volatile accesses; no Rust references alias active page
tables. Invalidate the local TLB before returning a removed frame. CR3 switching
flushes non-global scratch translations.

Run only at boot with interrupts disabled and one CPU. Reject LA57 or PCID mode,
require NX enabled, and validate addresses against CPUID physical width. Set and
retain CR0.WP. Retain all claimed frames; no reusable physical allocator is added.
Restore the original CR3 before returning from the successful proof.

## Invariants preserved

- INV-KERN-001: translation and mapping enforcement are kernel mechanisms.
- INV-KERN-004: four owned tables and at most 512 data mappings per window.
- INV-KERN-005: safe host-testable ownership logic; documented x86-64 unsafe boundary.
- INV-M0-004: offset/range validation precedes use; the loader remains explicitly trusted.
- INV-EVO-001 / INV-EVO-002: loader configuration stays in its adapter; no Stable ABI claim.

## Alternatives considered

Editing the loader's hierarchy makes ownership unclear. Replacing every inherited
mapping immediately needs a complete kernel/stack/descriptor-table layout. Copying
only the root and owning a new branch permits a narrower real hardware proof first.

## Consequences and security

The direct map aliases physical RAM with kernel write access. It is privileged
bootstrap access, not proof of full W^X isolation or an acceptable user-space map.
Its aliases and inherited lower-half mappings must be excluded from future user
roots. No user-mode isolation, fault recovery, SMP shootdown, reclamation or shared
Memory Object authority is claimed. Initialization failure aborts boot and may
retain partial claims; it never reissues them. Device memory is not probed.

## Verification

Host tests cover address limits, ownership, permissions and map/unmap failures.
QEMU must verify zeroed data, scratch read/write, read-only/NX/supervisor entry
bits, unmap/remap to a different page, distinct contents across two roots and
restoration of original CR3. Faulting accesses await exception handling. Keep
bootstrap, panic, serial-only and debugger regressions.

## Migration / rollback

M1-02 remains ACTIVE after this substep. Later roots must own user mappings and
exclude privileged aliases; reusable allocators must import all retained claims.
M0 source/evidence stay frozen. No dependency version changes are needed.

## Expiry or review trigger

Review before user entry, AP startup, interrupts, table reclamation, page-size
changes, PCID, five-level paging or boot-contract Preview.

## Technical references

- [bootloader_api Mappings](https://docs.rs/bootloader_api/latest/bootloader_api/config/struct.Mappings.html), version 0.11.17: opt-in physical-memory offset mapping.
- [AMD64 system programming manual](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2), chapter 5: translation, permission bits and TLB invalidation.
