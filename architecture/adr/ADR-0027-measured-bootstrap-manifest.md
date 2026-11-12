# ADR-0027 — Measured bounded bootstrap manifest

Status: Accepted
Date: 2026-10-18
Owners: Project owner; kernel/platform maintainers
Related: A-001, ADR-0026, INV-AUTH-008, INV-KERN-004, INV-RES-001

## Context and decision

The [custody design](../designs/ROOT_AUTHORITY_CUSTODY.md) requires an immutable,
measured manifest before Root Supervisor activation. No parser existed. Implement
a small Internal binary format in `kernel/src/bootstrap_manifest.rs`, independent
of runtime handles and Rust struct layout. This is an incremental Level B
implementation under the accepted engineering direction; it changes no foundational guarantee.

Accept only canonical bytes: explicit little-endian fields, exact record count
and length, zero reserved bytes and strictly increasing unique object selectors.
Reject unknown versions, kinds, rights or constraints instead of silently skipping
them. Root executable and grant selectors are nonzero and distinct. Selectors name
boot catalog entries, never process handles or ambient permissions.

The caller supplies the expected manifest SHA-256 from trusted generation/boot
selection and the compiled ABI fingerprint. Compute the manifest and image hashes;
compare before returning a validated object. Keep immutable borrows of both byte
slices to prevent safe-code mutation between measurement and later consumption.
This is integrity verification relative to trusted inputs, not signature checking,
secure boot, executable validation or proof of selected-generation authenticity.

Reuse the already locked/inventoried RustCrypto `sha2` 0.10.9 with default features
disabled and `force-soft` enabled. This adds hashing to the kernel dependency graph
without a new crate/version, allocation, OS service or CPU-feature probe requirement.
Do not write a new cryptographic implementation. Software hashing is conservative
for early boot; no speed improvement is claimed or required for this bounded slice.

## Internal byte format

Maximum manifest size is 424 bytes: a 168-byte header and 1–8 32-byte grants.
Maximum nonempty image size for this initial slice is 1 MiB. These are explicit
implementation limits, not permanent OS limits; reconsider before larger programs.

| Header byte offset | Field |
|---|---|
| 0 | Eight bytes `EVBM0001` (format and version) |
| 8 | Root executable catalog selector, u64 |
| 16 | Root image SHA-256, 32 bytes |
| 48 | ABI fingerprint, 32 bytes |
| 80, 88, 96, 104 | Job CPU ticks, frames, processes, threads: four u64 limits |
| 112 | Restart attempts, u8 (0–8); seven reserved zero bytes |
| 120 | Restart window in trusted clock ticks, u64 greater than zero |
| 128 | Expected canonical authority-set digest, 32 bytes |
| 160 | Grant count, u8; seven reserved zero bytes |

Each grant: selector u64 at 0; kind u8 at 8 (Memory=1, Endpoint=2, Process=3,
Thread=4, Job=5); zero byte at 9; rights u16 at 10; four zero bytes at 12;
memory extent start/length u64 at 16/24. Both zero means whole object. Otherwise
only Memory accepts a nonempty, page-aligned, non-overflowing byte range. Rights
validation shares `Kind::permits` with the existing capability vocabulary;
successful parsing does not implement constrained minting or mapping enforcement.

All Job limits must be positive and finite; process/thread limits cannot exceed
the current scheduler capacities. The existing scheduler enforces admitted limits.
The existing restart budget consumes the parsed policy. Version 1 fixes escalation
to independent recovery as required by the custody design; there is no optional
ignore-exhaustion policy. This format creates no Stable ABI or disk commitment.

## Boundaries and risks

The parser grants no capabilities. The expected authority-set digest is preserved
but **not yet verified against live objects**. Future integration must resolve
selectors into sealed identities and custody lineage, enforce every constraint,
compute the actual canonical digest and compare it before scheduling. It must
also bind boot epoch and incarnation. Never substitute manifest self-consistency
for that independent comparison or drop unsupported constraints during minting.

The parser accepts image bytes, not necessarily a valid executable. The future
loader must validate executable structure, mappings, entry and required contracts.
Resource admission can still fail even when declared limits are valid. Failures
must unwind through custody; no fallback to unrestricted authority is allowed.
Borrowing protects against safe Rust mutation, not DMA or a broken trusted loader;
physical immutability/quiescence remains part of hardware integration.

## Alternatives and compatibility

- JSON/Serde in privileged bootstrap: unnecessary parser/allocation surface.
- Raw Rust layouts: padding, enum representation and compiler coupling violate
  language-neutral boundaries.
- Caller-supplied “already measured” booleans: cannot detect altered bytes here.
- New hashing code: unnecessary cryptographic implementation and review burden.

The format can be replaced before external use. Later versions must be explicit;
unknown formats fail closed. No previous accepted format is superseded. The
original imported custody requirements and restart semantics stay unchanged.

## Verification and next gate

Host tests cover a known SHA-256 vector, all single-bit manifest mutations,
every truncation, trailing data, invalid authenticated records, capacity limits,
bad image/ABI, 4,096 bounded malformed samples and real scheduler/restart-policy
consumption. Cross-target lint/build and the cumulative M1 gate check regression.
Evidence is in the [M2 progress record](../../docs/release/0.1-preview.md#validation-and-provenance).

No Root Supervisor boot, authority minting, AF-007F system-recovery acceptance or
full M2 completion is claimed. The next gate is trusted boot-bundle production,
sealed-object resolution, incarnation binding, actual executable launch and
fault-driven recovery. Revisit these limits and encoding at that integration gate.
