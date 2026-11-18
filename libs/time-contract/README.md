# Time and entropy consumer contracts

Pure, Internal `no_std` consumer types for future authenticated userspace
providers. This crate has no clock driver, entropy collector, CSPRNG, signature
verifier, capability authority or Store backend. It does not close M6-05.

- Boot-domain instants and checked absolute deadlines cannot be compared across
  boots. The kernel's existing monotonic mechanism remains unchanged.
- Freshness checks require a qualified UTC interval covering the provider's
  entire declared observation window. Unknown and tentative RTC/network time,
  stale windows, uncertain expiration, rollback below a committed floor and
  different-boot samples refuse new metadata approval. No IRQ-to-UTC conversion
  or arbitrary stale-sample allowance is assumed.
- The recommended floor must be committed with the caller's exact accepted
  trust transaction. This does not resist malicious rollback of a whole disk.
  Authorized local Known Good boot is a separate operation.
- Entropy accounting starts unavailable after every cold construction. Only an
  actual approved source and successful reviewed CSPRNG reseed may precede a
  `reseeded` call. Request/output/time limits, newer seed generations, source
  failure and clock regression are explicit. A reservation is never refunded
  after a failed byte delivery; this library cannot generate any bytes.

A trust label or nonzero boot identifier is not an authentication token. Actual
adapters must authenticate the provider, bind the true lifecycle and handle
clock pause/drift and source/DRBG validation. No caller-supplied entropy count,
statistical test, saved seed or IRQ count establishes adequate entropy.

See [ADR-0059](../../architecture/adr/ADR-0059-time-and-entropy-contracts.md) for
the required provider and cold-state proofs still pending.

```bash
cargo test --locked --offline -p ev-time-contract
cargo clippy --all-targets --locked --offline -p ev-time-contract -- -D warnings
```
