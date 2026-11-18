# Bounded signed-update metadata

This `no_std`, safe Rust crate verifies a caller-provisioned release root and a
small signed repository state. It implements the Root / Targets / Snapshot /
Timestamp purposes required by R-003 §§4,12–17 and E-019 §§32–40. It uses the
existing pinned Ed25519 primitive, with canonical nonweak torsion-free keys and
strict individual signature verification. It is an internal format, **not a TUF
wire-compatible implementation** or a claim of full TUF compliance. The release
Root is signing authority, separate from the OS Root process and its capabilities.

Networking, TLS, hosting location and signing-key possession do not create
runtime capabilities. This crate performs no I/O, download, durable commit,
clock qualification, image loading, compatibility negotiation or activation.
A successful check does not make an owner/development key an Official Evrosion
key. The installed system and protected KnownGood boot remain separate from new
update freshness checks.

## Consumer boundary

1. Obtain an exact root independently of the downloaded repository. Call
   `TrustedRoot::provisioned(bytes, expected_binding)`. Its self-quorum checks
   consistency; it does not authenticate the initial choice of root. Never use
   this entry point to replace an existing root after a failed update.
2. Load the exact trusted atomic replay checkpoint. `ReplayState::initial` is
   for first provisioning only; `ReplayState::restored` checks the structure of
   an already trusted stored checkpoint. Neither function authenticates a disk.
3. For rotation, call `advance_root(old, state, candidate)` once per successive
   root version. Both the old and new Root thresholds must sign the same exact
   candidate envelope. The result contains a new root and **proposed** state.
   It changes no caller state or storage. Commit the exact root bytes and replay
   state atomically before acknowledging durable advancement. Repeat for each
   intermediate version; a skipped root fails.
4. Pass the complete immutable `verifier::Bundle { timestamp, snapshot, targets }`
   to `verify_bundle`, together with the current root/checkpoint, authenticated
   qualified time, the actual same-boot instant, and a finite `Policy`. It checks
   signatures, bindings, final-root version, exact links, replay and validity
   before returning `Verified`. Every error leaves the input state unchanged.
5. Reserve staging space from the caller's bounded resource policy. Check the
   returned target's declared length before download and use
   `Verified::verify_artifact(name, bytes)` on the exact immutable downloaded
   bytes. Atomically retain the accepted metadata/checkpoint with the actual
   authorized acquisition transaction. This helper does not commit an artifact.
6. Separately validate the actual System manifest, every required cohort member,
   actual provenance and compatibility contracts, ELF bounds, immutable sealing,
   W^X mappings, lifecycle publication, health and rollback ownership. A matching
   digest field is not proof that the referenced object was supplied or admitted.

All byte slices must remain actually immutable through the check. In particular,
a shared window still writable by an untrusted producer is unsuitable even if a
Rust reference was constructed to it. Bulk-credit/immutable snapshot ownership
belongs to the calling adapter.

## Replay and rotation rules

The checkpoint binds namespace, channel, platform, exact root identity, all three
non-root metadata identities, a UTC floor and up to eight retained target floors.
A role or target counter cannot decrease. Revalidation at the same version is
allowed only for the exact previous envelope/target-record identity, with all
current signature, root, link and time checks repeated. Even an additional valid
signature changes an envelope identity and requires a new metadata version.

Root rotation preserves all role, target and UTC floors; it does not authorize
resetting them. A new root therefore republishes changed role envelopes with
advanced versions. Per-target name/version/record floors survive withdrawal and
cannot be silently evicted for new names. Exhausted fixed capacity refuses.
Authorized local KnownGood recovery must not reset this checkpoint. Protection
against malicious rollback of the whole medium requires an external witness and
is not established here.

The finite caller policy limits each forward counter step and target byte size.
The version-step range is 1..=1,000,000; the exact configured bound is an explicit
implementation policy. Larger authenticated jumps fail closed instead of
poisoning an effectively unbounded counter. An offline client beyond that bound
needs a separately authorized checkpoint/recovery procedure. This availability
limit must not be hidden by resetting replay floors. The parser also refuses
zero and exhausted `u64::MAX` metadata/target versions.

## Freshness and the bounded root profile

The verifier uses `ev_time_contract::freshness::check`. Unknown/tentative time,
expired or uncertain metadata, stale samples, different boot domains, monotonic
regression and UTC rollback refuse. The provider's qualified UTC interval must
cover the whole declared same-boot validity window including drift and pause
uncertainty. Constructing a `Time::Qualified` value is not evidence that a provider
was authenticated or met this contract.

Each root authorizes four disjoint, nonempty key masks, thresholds and maximum
validity durations. This profile deliberately prevents routine online keys from
also being Root keys. Keys are sorted by their canonical key IDs, unused key
slots are zero, and every configured key belongs to exactly one role. A channel's
independently provisioned root must give its publishing roles their appropriate
separate keys; the crate does not inspect other installations' roots.

The whole root contains at most eight keys and each envelope at most eight
signatures. Root thresholds above four are explicitly rejected, never reduced,
so two disjoint old/new Root quorums can fit in one rotation envelope. This is a
bounded profile choice, not a limitation attributed to Ed25519 or TUF. Root key
count may exceed its threshold within the fixed total; every counted signer is
independent and duplicate IDs cannot count twice.

Root-authorized per-role validity maxima bound how long an online signer may
assert freshness. Historical intermediate roots may be expired during continuity
verification, which permits an old installation to traverse the required chain.
No update is accepted until the final root and all current roles pass the present
qualified-time check. `advance_root` alone is not a current-update decision.
Timestamp key compromise can still deny service inside these bounds; no signature
scheme forces a malicious server to provide a newer valid release.

## Canonical wire profile

All numbers are little endian. Every reserved byte is zero. Extents are exact,
with no trailing data or extensible unknown fields. The public encode helpers
construct payload bytes for a signing tool; parsing/verifying the final signed
envelope remains mandatory and no encoder result is authority.

The outer `EVRSG001` envelope is documented in `signature.rs`: 32-byte header,
1..4096 payload bytes and 1..8 sorted distinct 96-byte key-ID/signature records.
The role, algorithm, payload length and signature count are signed along with the
payload. Whole-envelope link identities include version, byte length and SHA256
of the entire envelope including its signature records.

Every payload starts with the following 160-byte common header:

| Offset | Field |
| --- | --- |
| 0 | `EVRMD001` (8 bytes) |
| 8 | Format version `u16=1` |
| 10 | Role byte, equal to the signed outer role |
| 11 | Five reserved bytes |
| 16 | Metadata version `u64` |
| 24 | Not-before UTC seconds `u64` |
| 32 | Exclusive expiry UTC seconds `u64` |
| 40 | Namespace identity (32 bytes) |
| 72 | Channel identity (32 bytes) |
| 104 | Platform identity (32 bytes) |
| 136 | Root version `u64` |
| 144 | Body-record count `u16` |
| 146 | Fourteen reserved bytes |

Binding identities are exact nonzero 32-byte values from the caller's canonical
namespace/channel/platform definitions, not URLs or peer claims. The exact root
version is itself inside every signed payload. A Root payload's root version
must equal its own metadata version.

Root payloads are exactly 448 bytes. After the common header are eight 32-byte
canonical public-key slots (count4..8, sorted by key ID), then four eight-byte
role-policy rows in role order. Each row is role byte, key-slot mask, threshold,
one reserved byte, and maximum validity seconds `u32`. All key slots outside the
count are zero; role masks are in range, disjoint and cover every present key.

Targets contain 0..8 sorted distinct 288-byte records after the common header:

| Offset in record | Field |
| --- | --- |
| 0 | Stable target-name identity (32 bytes) |
| 32 | Per-target version `u64` |
| 40 | Artifact length `u64` |
| 48 | Artifact SHA256 |
| 80 | Actual generation-manifest identity |
| 112 | Release identity |
| 144 | Source-revision descriptor identity |
| 176 | Build identity |
| 208 | Provenance-record identity |
| 240 | Compatibility-contract identity |
| 272 | Sixteen reserved bytes |

All 32-byte target identities are nonzero. All records in this bounded System
cohort must bind the same generation and release. Source/provenance/contract
identities are authenticated references; the caller must resolve and validate
the actual objects. An empty Targets set supports withdrawal while retaining
all existing target floors. This does not change or remove installed data.

Snapshot and Timestamp payloads are exactly 208 bytes. Their body is one
48-byte linked identity: version `u64`, envelope length `u64`, SHA256. Timestamp
links Snapshot; Snapshot links the complete Targets envelope. Each link must
match all three fields, in addition to the linked role's own signature checks.

## Validation scope

Tests use actual Ed25519 signing and verification with deterministic **test-only**
keys. They exercise successful chains and artifact verification, wrong key/role,
namespace/channel/platform substitution, mixed signed states, link hash/length/
version mismatch, expired/unknown/uncertain/stale time, UTC rollback, root
threshold continuity and missing intermediates, floor preservation, changed
same-version metadata, bounded fast-forward, withdrawal/capacity, malformed
canonical records and strict signature scalar/R rejection. Host footprint checks
bound the borrowed views/checkpoint; they are not a linked actor stack census.

The caller's persistent trust store, interruption protocol, actual provider
qualification, streaming staging, loaded-image admission, service CPU budgets,
actual linked stack/resource measurements and network/rollback guest acceptance
remain integration gates. This crate does not close M6-05/07/08 alone.

Primary design reference: [TUF Specification1.0.37, roles and client workflow](https://theupdateframework.github.io/specification/latest/).
This implementation intentionally uses its own fixed binary profile and stricter
exact-identity/counter/key-role bounds; no interoperable TUF client claim is made.
