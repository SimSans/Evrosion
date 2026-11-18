# ADR-0087 — Persistent private time challenge ownership

Status: Accepted Level B implementation refinement; repeated actual VM proof and UTC qualification remain pending.

## Reason

The initial private Root time path is deliberately one shot. Its authenticated
anchor expires after60 conditional elapsed seconds. Reconstructing a Client for
each later query would discard its challenge sequence, previous nonce and clock
history. A long lived owner session needs a genuinely new proof after expiry.

## Decision

Retain one private time Client for the Root incarnation. `Client::begin_after`
checks its original clock/state and pending challenge before invoking an adapter
callback to prepare its retained nonce source. Preparation failure permanently
fences the Client. The callback does not qualify entropy or accept an external
nonce for verification; the private Root callback draws only from its retained,
freshly reseeded qualified VM random owner after an actual RTC origin capture.

The Client's sequence, last nonce and elapsed history survive successful proofs
and malformed responses. Every attempted finish consumes its pending challenge.
An explicit later owner request may replace an expired or rejected proof with a
new affine request and newly verified Anchor. It cannot reopen an old Anchor.
Actual clock, entropy, policy or transport uncertainty closes this Root adapter;
it cannot obtain a new Client by resetting readiness.

The existing8192 whole-exchange cut and all child/RPC/CPU limits remain unchanged.
Each explicit new operation captures its own cut once. No accepted request or
protected-window work is retried by refreshing. Root still checks actual peer
readiness, network state, client quarantine, clock health and content ownership.

TP diagnostics keep their existing four-entry lifetime bound. Their refusal or
exhaustion cannot stop later verification or manufacture success. Client history
remains nonwrapping u64 even when a diagnostic cannot encode its sequence. A
refresh needs its own runtime evidence; a partial second TP transcript is not a
proof of completion.

TC checks remain once per Anchor with at most four created diagnostics per Root
lifetime. Exhausting that observation budget does not prevent actual checks or
clear a failed Anchor. The general Host parser retains the same four-record
bound; a specific one-pause goal still requires exactly one check. The repeated
proof gate must join a new nonce/sequence with a newly fresh actual check.

## Verification and limits

Twenty time-proof tests pass, including pending-callback exclusion, persistent
sequence/nonce history after failed replies, duplicate nonce refusal, preparation
failure, clock rollback and sequence exhaustion. Host strict checks and the actual
bare Root target pass. These are source/library checks, not repeated guest proof.

The separately frozen TimePause08 run proves the original anchor expires during
an actual35-second QMP pause and completes normal checked retirement. It predates
this refinement. Repeated proof/check, corrupt-response and missing-entropy VM
gates remain separate. No QualifiedWindow, durable floor fallback, remote update
authorization, service replacement or whole M6 acceptance is introduced here.
