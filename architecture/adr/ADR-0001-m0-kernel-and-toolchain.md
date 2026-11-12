# ADR-0001 — M0 kernel entry and compatible toolchain

Status: Accepted
Date: 2026-09-21
Owners: Project owner; implementation maintained with kernel and boot adapter
Related: PRE-M0 implementation package, EXC-0001, INV-EVO-001, INV-EVO-002, INV-M0-004

## Context

The owner authorized the working boot in the approved Pre-M0 package. Slices 2
and 3 require the first privileged kernel entry, loader adapter, image and QEMU
check. This records that implementation decision; it grants no additional OS
service authority.

The original nightly-2026-07-06 pin fails to compile the published loader's
locked x86_64 0.15.5 dependency: six E0407 errors for Step::forward_overflowing
and Step::backward_overflowing. That dependency's source explicitly requires
nightly-2026-07-10 or later for those methods. The original plans remain intact.

## Decision

Use nightly-2026-07-10 for the workspace and nested loader build. Keep bootloader
and bootloader_api at exactly 0.11.17, with the published loader's own lockfile.
Retain the initial compiler failure in local build diagnostics. This narrowly
supersedes the original compiler date; no upstream crate sources are patched.

Implement a no_std, no_main x86_64 kernel with a static high-half ELF and debug
symbols. Disable interrupts, adapt the temporary loader metadata once, validate
memory/framebuffer ranges, and enter evrosion_kernel_entry with Evrosion types.
Keep COM1 output and panic reporting bounded and allocation-free. M0 test images
enable a dedicated QEMU exit feature; kernels without it halt after reporting.

## Invariants preserved

- INV-EVO-001: temporary loader types stay inside the boot-contract adapter.
- INV-EVO-002: the boot contract stays Internal; no Stable compatibility claim is made.
- INV-M0-004: boot metadata is checked before kernel use; loader trust is explicit.
- INV-KERN-005: privileged I/O and entry assembly have local safety explanations.
- INV-M0-002: serial records and QEMU status must agree before a boot passes.

## Alternatives considered

A patched loader dependency tree would add maintenance and privileged changes.
A separate older loader compiler would add a second toolchain and would still
need a compatible locked dependency graph. Moving the single pin four days
addresses the observed compiler error directly.

## Consequences

The loader and kernel are experimental privileged code. The adapter copies at
most 512 regions, sorts them, rejects overlaps and invalid arithmetic, and
validates a bounded optional framebuffer. BootInfoV0 is an Internal Rust type,
not an ABI stability promise. Boot generation and command line are absent in
this backend. No allocator, scheduling, userspace or device service is added.

## Security and failure analysis

The external loader must supply valid Rust references and mapped buffers;
metadata validation cannot prove arbitrary pointers safe. Unknown memory kinds
are reserved. Rejected metadata and panics cannot pass the host boot check.
QEMU runs without networking, with fresh firmware variables and temporary disk
writes. An unsigned manifest binds artifacts to source and build inputs; it is
not a release signature or secure-boot chain.

## Verification

Host adapter and serial protocol tests, target compilation, architecture checks,
and repeated QEMU/TCG boots are required. See the M0 progress record and the
generated build/m0 evidence for results. Image byte reproducibility and GDB
panic symbolization remain later M0 slices.

## Migration / rollback

The adapter macro and image builder are the backend replacement points. Revisit
the compiler pin through a tested lock/toolchain change. Reverting to July 6
alone restores the demonstrated upstream compilation failure.

## Expiry or review trigger

Review before boot-contract Preview or any expansion of privileged behavior.
