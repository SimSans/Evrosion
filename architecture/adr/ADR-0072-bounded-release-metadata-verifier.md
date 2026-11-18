# ADR-0072 — Bounded common release metadata verifier

Status: Accepted library mechanism; persistence, provider and admission integration incomplete

Date: 2026-11-12

Decision level: B

## Decision

Implement the distinct Root, Targets, Snapshot and Timestamp responsibilities
from R-003 and E-019 in one allocation-free `ev-release-trust` verifier. Use an
explicit canonical Internal binary encoding with bounded records; do not claim
TUF wire compatibility or complete TUF compliance. Online retrieval and offline
bundle import must call this same verifier. A signing root is release authority,
separate from the OS Root process and its runtime capabilities.

Use pinned Ed25519-dalek2.2.0 strict individual verification and SHA-256. Reject
noncanonical, weak and mixed-torsion public keys. Canonical sorted signer IDs,
bounded counts, exact extents, reserved zero bytes, signed role/header fields
and role-separated key sets prevent ambiguous interpretation. Force the serial
curve backend for the current bare-metal context-save contract; automatic AVX
dispatch cannot silently exceed that contract. No cryptography is added to the
Kernel or used as a substitute for object ownership.

The caller independently provisions an exact trusted root and namespace,
channel and platform binding. A downloaded key list or self-signature cannot
establish initial trust. Require both old and new thresholds on every successive
root version. The bounded profile explicitly refuses Root quorums above4 so
disjoint old/new quorums fit the maximum8 signatures; never lower a requested
threshold. Historical expired intermediate roots may establish continuity,
while target acceptance checks the final root and every current role against
qualified time. Root-authorized per-role validity maxima and caller-selected
finite version-jump/artifact-size limits also apply.

Bind each exact signed envelope by hash, length and version through Timestamp
to Snapshot to Targets. Preserve per-role version/exact-identity floors and
per-target version/record floors across withdrawal and root rotation. Same
versions are idempotent only for the exact authenticated identity under current
trust and time checks. Never restore progress by resetting replay floors.

Return proposed immutable checkpoints without mutating caller state. The actual
adapter must commit exact metadata, replay/UTC floors and transaction ownership
atomically before acknowledging durable advancement. Validate acquired artifact
bytes against the accepted target separately. Successful signatures do not
prove cohort compatibility, ELF validity, immutable sealing, execution authority,
runtime health, Official provenance or successful activation.

## Evidence and open work

The exact wire/API and limits are in [the crate README](../../libs/release-trust/README.md).
Twenty-four real-signature tests and strict host/bare-metal checks pass. They
exercise a reference signature, malformed keys/signatures, old/new root quorums,
missing/skipped rotation, repository/link substitution, metadata/target replay,
expiry/unknown time and unchanged proposed state on refusal. The metadata links
and replay/rotation transitions also received implementation review. This is
engineering review, not an independent cryptographic security audit.

The frozen receipt is retained in the local engineering archive,
SHA-256 `dd02ef929ea12153bca643d7c4398a86b30d6145d9976ba23078dc5e16dfe13d`.

Actual trusted-time qualification, durable trust/object transactions, cold-state
reopening, missing-source tests, linked service stack/resource admission,
downloaded immutable image loading and end-to-end recovery remain required.
The library is not yet linked into the live Root. Local KnownGood boot remains
distinct from approval of fresh remotely acquired metadata. Store integrity
alone does not resist malicious rollback of an entire medium.
