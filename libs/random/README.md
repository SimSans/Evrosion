# Bounded private random generator

`ev-random` wraps the pinned `rand_chacha` 0.9.0 `ChaCha20Rng` with the existing
same-boot entropy budget. It is allocation-free and `no_std`. It starts
unavailable on every construction; an authorized security adapter must acquire
and qualify fresh entropy before seeding it. This library does not authenticate
a provider, estimate entropy or grant a random-service capability.

Each generation selects a distinct upstream substream, has a 1 MiB output
budget and expires after 60,000 admitted monotonic ticks. Requests are at most
4,096 bytes. Reservation precedes generation; failed transport delivery cannot
refund or replay output. Clock regression, another boot domain, source failure
and exhausted eligibility refuse output. Invalid lengths preserve output bytes
and budget while still recording the actual clock observation. The seed input
buffer is erased on success and refusal. The wrapper exposes neither state nor
Clone, Debug, seek or refund operations.

The upstream generator is a reviewed implementation choice, not a claim of
independent audit or certified DRBG compliance. Its opaque RNG state does not
provide immediate zeroization on ordinary Rust Drop. It stays in the security
service's private memory, and actual stopped-process RAM scrubbing remains a
required ownership obligation. Temporary input erasure does not prove every
compiler-created secret copy was wiped.

The pinned [upstream documentation](https://docs.rs/rand_chacha/0.9.0/rand_chacha/)
describes the generator variants, reference vectors and seeding constraints.
The actual no-std dependency configuration selects `ppv-lite86`'s compile-time
backend. Current bare-metal inputs do not enable AVX; a future ISA-profile
change must reconcile backend and context-save policy before admission.

Ten focused tests use explicitly deterministic test seeds: a reference
ChaCha20 block, unavailable/failing sources, refusal erasure, nonreplayed output,
finite eligibility, generation separation and clock/request exhaustion. These
also check bounded four-word source acquisition, successful zero words, finite
failure and erasure of partial seeds. The acquisition helper requires independent
qualification before invocation; byte values and success flags do not supply it.
These are generator/accounting tests. Actual VM entropy qualification, an authenticated
service boundary, provider reseeding, cold trust-state tests and M6-05 acceptance
remain open. A saved seed or a successful test cannot supply those proofs.
