# ADR-0059 — Time, freshness and entropy contract groundwork

Status: Accepted — pure consumer contracts; provider/DRBG integration pending
Date: 2026-11-12
Related: M6-05; A-005/A-006; X-001/X-002; INV-IPC-004; E-019; R-003

## Decision

Introduce `ev-time-contract`, a dependency-free safe `no_std` contract crate.
Preserve the existing kernel monotonic timer and absolute-deadline mechanism.
Use explicit same-boot clock domains for consumer comparisons, qualified UTC
uncertainty windows for metadata freshness and separate nonsecret accounting
for an actual future cryptographic random service. No provider, CSPRNG,
signature verifier or persistence format is implemented by these types.

These are implementation refinements behind the existing architecture. A type
label is not provider authentication, capability authority, adequate entropy or
an independently verified UTC fact. The adapter must establish each of those
from actual execution and authenticated state before constructing trusted values.

## Time and durable trust state

Monotonic correctness deadlines never use wall time. Instants from different
boot domains cannot compare; overflow and regression refuse. Boot identities
come from the actual lifecycle, not an untrusted caller or a claimed random seed.
UTC, RTC, timezone/calendar conversion and compatibility clocks remain distinct.

A freshness provider must return Unknown, Tentative or a qualified UTC interval.
The qualified interval must cover every possible UTC value throughout its
declared observation/authorization window, including transport, drift and pause
uncertainty. A past UTC sample plus an arbitrary age allowance is insufficient.
The contract does not convert IRQ ticks to trusted elapsed UTC. If no source can
bound time through a VM pause or clock failure, confidence becomes unavailable.

Metadata is acceptable only if the whole possible UTC interval lies inside its
verified validity interval and at/above the committed trusted floor. Unknown,
tentative, expired, not-yet-valid, uncertain, stale and different-boot states are
explicit refusals for new authorization. Previously installed local software,
owner data and authorized Known Good recovery remain usable offline.

The release-trust owner persists the accepted floor with its exact successful
trust transaction and reopens it cold. Signature/version/root-rotation checks
remain separate R-003 verifier work. Ordinary Store counters and a saved lower
bound do not resist malicious whole-medium rollback. Unauthenticated RTC/NTP
cannot silently establish security UTC; the [NTP best practices](https://www.rfc-editor.org/rfc/rfc8633.html)
are relevant source-qualification guidance, not a substitute for an authenticated
and bounded provider. User calendar display may use explicitly tentative time.

## Entropy and random service

The security service must obtain approved actual entropy, instantiate/reseed a
reviewed CSPRNG and expose a bounded random API through authenticated authority.
It is not an ordinary replaceable extension provider and does not expose raw
hardware RNG output as the system API. Missing entropy is an explicit result;
timer/device counts, a statistical test, a fixed test seed or a saved seed alone
cannot promote the service to ready.

The new crate records no secret or random bytes. Output starts unavailable on
every cold construction. Only after actual successful reseeding may the provider
record a newer generation, finite output budget and absolute reseed deadline.
Each bounded request reserves before generation/delivery; failed delivery does
not refund output or authorize request regeneration. Source failure, stale boot,
clock regression or exhausted budget closes output until a fresh actual reseed.
The actual service must also bind requests to clients, serialized DRBG state,
per-Job limits and real delivery; counters alone do not prove that protocol.

Candidate x86 seed acquisition needs actual CPUID support, correct success-flag
handling, bounded retries and a declared hardware/VMM trust assumption. The
[Intel DRNG guide](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html)
distinguishes RDRAND/RDSEED use and failure; no source is selected merely because
an opcode exists. A DMA-backed virtual RNG needs its own DMA containment first.

In reviewed QEMU v10.2.1, [the TCG random helper](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/target/i386/tcg/int_helper.c)
calls [guest random](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/util/guest-random.c).
That path can use deterministic `-seed` generation or recorded replay instead
of the normal cryptographic backend. Security qualification must exclude those
modes and retain the actual binary, CPU features and invocation. Deterministic
model tests remain labelled as tests and cannot establish adequate entropy.

The eventual DRBG/source implementation choice must review the primary
[NIST90A](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final),
[90B](https://csrc.nist.gov/pubs/sp/800/90/b/final) and
[90C](https://csrc.nist.gov/pubs/sp/800/90/c/final) guidance and the selected
library's source, no_std behavior, bounds, license, known-answer/reseed tests and
security history. This ADR does not promise certification or choose a homemade
cryptographic algorithm.

## Validation and remaining gate

Portable tests cover cross-boot/regressed clocks, overflow, unknown/tentative
UTC, whole-window expiration uncertainty, a cold-restored floor, stale samples,
missing entropy, output exhaustion, failed delivery accounting and reseed
generation refusal. Those model tests do not close M6-05.

Actual provider/source qualification, cryptographic implementation review,
authenticated service/capability binding, cold trust-state recovery,
clock rollback/pause and missing-entropy fault injection remain required before
TLS, key generation or authenticated update freshness claims. Full calendar,
timezone, suspend and compatibility-clock behavior will be added when their
corresponding product scope needs them; no mutable wall time may change kernel
correctness deadlines in the meantime.
