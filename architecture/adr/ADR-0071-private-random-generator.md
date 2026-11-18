# ADR-0071 — Bounded private random generator

Status: Accepted library mechanism; actual source/service integration incomplete

Date: 2026-11-12

Decision level: B

## Context

A-006 requires a real CSPRNG behind an authenticated security boundary. The
existing time-contract helper accounts for readiness and output but generates
no bytes. Raw hardware output, a saved seed and a nonzero seed label cannot
serve as the system random API or qualify entropy themselves.

## Decision

Use pinned `rand_chacha` 0.9.0's ChaCha20Rng inside `ev-random`, with default
features disabled, the existing same-boot accounting helper and pinned
`zeroize` 1.8.2 for the caller's seed buffer. This selects an existing generator
rather than implementing ChaCha or a new cryptographic construction. Standard
upstream substreams distinguish increasing seed generations within the boot;
they do not add entropy. Initialization remains unavailable until the trusted
adapter reports actual approved-source acquisition. No untrusted request may
nominate its seed.

Keep a finite 1 MiB output limit per seed, a 60,000-tick monotonic reseed cut and
a 4,096-byte request bound. Ticks assert no UTC confidence or fixed frequency.
Consume eligibility before generation; delivery failure never refunds output.
Do not expose clone, seek, internal state or replay APIs. Domain/clock faults,
source failure and exhausted eligibility fence output. A newer actual reseed is
required; request and generation counters never wrap or reset implicitly.

Malformed request lengths do not consume valid output, but still advance the
actual observed-clock high-water mark. Otherwise an invalid request at a later
instant could hide a subsequent clock regression. This refines the existing
consumer budget without changing the authority or entropy qualification rule.

The no-std dependency uses compile-time backend selection under current target
inputs, which do not enable AVX. ISA changes require explicit reconciliation
with saved execution context and actual linked admission. Seed input erasure
does not establish complete stack-copy erasure. The opaque upstream generator
does not promise zeroization on ordinary Drop; private service ownership and
actual post-quiescence RAM scrubbing remain required.

The [upstream generator documentation](https://docs.rs/rand_chacha/0.9.0/rand_chacha/)
and actual locked source were reviewed for generator choice, no-std operation
and backend selection. This is not an independent security audit, certification
or proof of the actual VM entropy path. Reviewed QEMU/package provenance remains
a separate source-qualification input, excluding deterministic seed/replay modes.

## Validation and remaining work

Seven generator and thirteen consumer-contract tests pass, including reference
output, refused/failed generation, delivery nonreplay, output/time exhaustion,
clock rollback after malformed input and cross-boot refusal. Host and bare-metal
strict checks pass. Deterministic test material is labelled and never establishes
adequate entropy.

The actual provider, authenticated service capability, source acquisition and
reseed, guest execution/stack evidence, missing-source injection and cold
trust-state checks remain required before M6-05 passes. This library is not yet
linked into the Root or network actor and changes no existing runtime grant.
