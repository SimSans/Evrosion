# ADR-0089 — Qualified reviewed-VM clock bound to the actual Store

Status: Accepted Level B implementation refinement; actual joined remote decision and durable-floor VM gates remain pending.

## Decision

Use a private V4 Root clock adapter for new remote update decisions. Its sources
are the retained private nonce/signature client and actual read-only RTC owner
under the reviewed trusted Linux/QEMU/BOOTTIME launch profile. The minimum rate
of one half clock second per UTC second remains an explicit healthy trusted-host,
clock administration and suspend-accounting assumption. A finite pause observation
does not calibrate or prove that rate for arbitrary hosts or physical hardware.

The adapter borrows the actual authenticated Store and captures its current head,
published checkpoint, revision and committed UTC floor. It requires backend
quiescence and rechecks that exact binding on each callback. A detached LOCAL
identity Snapshot, author timestamp, cached UTC value, ready label or numeric
floor supplied by a caller cannot construct this adapter. Genesis floor zero is
read from a genuinely authenticated and published Store; there is no floor-zero
factory or ordinary-open-error initialization fallback.

Every callback samples the actual RTC, then asks the private Anchor for a bounded
interval at that observation with the actual committed floor. Authorization uses
only the same Store borrowed by construction. Existing metadata authorization
requires a fresh callback after cryptography and full package checks. Each
returned Decision remains affine and bound to its original head/revision; later
durable IO completes that decision and is not another fresh authorization.

Metadata authentication may first produce a preparation-only immutable target,
before spending a permanent executable slot. That permits no replay publication,
Register, activation or health claim. Final full-candidate authorization is still
required after actual artifact readback. The two defined proof phases capture
distinct fresh challenges, each clamped to the original once-captured fetch cut;
they never retry or regenerate an accepted challenge. Post-crypto work cannot
renew that cut. Counter, source, clock and transport fences remain intact.

Already accepted local identities and offline recovery use their existing cold
authentication path. They do not require a current network connection or this
freshness provider. Local provenance does not grant a new remote decision, and
neither an authenticated candidate nor its GUI readiness implies Known Good.

## Evidence and limits

The exact separately frozen VM gates demonstrate actual nonce-bound proof,
35-second pause/RTC advance and old-anchor expiry, missing-entropy refusal,
single-bit signature corruption refusal, and a new sequence2 proof after expiry.
Every successful gate includes normal full retirement and unchanged owned disks.
Their original sources, budgets, compact records and source-linked provider
assessment remain retained in the local engineering archive.

The Store binding test uses real signed retained state with a positive committed
floor, plus actual head changes, detached Snapshot removal and poison refusal.
Independent source review confirms the same-Store borrow and fresh callback
path. These checks do not close actual joined update authorization, floor
publication/cold reopening, negative checkpoint integration, physical execution,
or whole M6 acceptance. Those remain required engineering gates.
