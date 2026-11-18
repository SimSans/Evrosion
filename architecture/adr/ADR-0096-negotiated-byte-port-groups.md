# ADR-0096 — Negotiated fixed byte-port groups

Status: Proposed private implementation; actual VM qualification pending.
Date: 2026-11-13
Owners: Internal Kernel/userspace device boundary
Related: ADR-0056 bounded CPU windows; existing Internal Word4 port extension

## Context

A retained System6 acquisition attempt expired a NetService-to-Driver Poll at
its original 512-tick deadline. The authenticated Driver then reported the
device Deadline error and Root refused the fetch. The Host fixture had sent
the public 97,967-byte artifact response. This does not establish the frame
length or receive substage of that call. No System admission or startup-health
result was reached. Untimestamped Slirp errors are also retained.

The byte-mode NE2000 adapter reads each frame synchronously, with one clock
syscall and one byte-port syscall per byte, under a 64/256 CPU window. The
existing Word4 extension is width2 and cannot be reused for DCR0x48 byte mode.
The mechanism below reduces transitions without increasing the operation cut,
CPU quota, device extent, or authority.

## Decision

Add a separate negotiated Byte4 Internal extension: INFO49 requires four zero
operands and returns exactly 0x0000000100040001. INPUT50 takes the full live
capability, one 16-bit port, one finite absolute deadline, and zero; it returns
four little-endian bytes in the low32 bits of RSI. OUTPUT51 takes the same
capability/port/deadline and exactly32 packed bits, with the high32 bits zero.
Both operations clear the extended outputs. The original scalar35/36 and
Word4 INFO46/input47/output48 contracts and hashes remain unchanged.

The decoder rejects truncated ports, high output bits, reserved operands and
zero/MAX deadlines. Before any I/O, the actual running Scheduler/RPC domain,
full capability generation and lineage, IoPorts kind and direction, immutable
one-byte range, and finite future cut no more than1024 ticks are checked.
A non-cloneable borrowed permit remains live across exactly four AL IN or OUT
instructions at the same port at IF0. There are no user pointers, user-selected
counts, consecutive-port semantics, device policy, or batch progress receipts.
The existing width2 permits remain separately typed and strict.

The NIC adapter negotiates before its first PIO. It uses Byte4 only for fixed
four-byte data groups, retains scalar tails, counts every physical byte in its
existing step bound, yields before crossing a64-operation turn boundary, and
checks the original cut before and after each group. RX, TX, initial scrub and
STOP scrub retain byte mode, exact readback and their existing state machines.
Each runtime group uses the same supplied absolute cut. Cold initialization
may supply its existing8192 aggregate, which is too distant for a1024 batch
permit. Before any attempt, those groups instead select four guarded scalar
byte operations under that aggregate. There is no attempted-batch fallback.
No fresh deadline is minted inside data transfer, and the service's fixed512-
tick child and Kernel max1024 batch preflight remain unchanged.

## Security and failure analysis

An older or incompatible Kernel is refused before device I/O. A group rejected
at the boundary performs no port operation. Expiry during a fixed IF0 group can
leave at most four byte operations after the last precheck; the postcheck must
succeed before copying RX progress, advancing its ring boundary, acknowledging
STOP progress, or submitting a TX frame. The Driver remains quarantined after
unknown, partial, expired or regressed-clock work. There is no accepted I/O
retry, bank fallback, capability remint, packet publication after a failed
postcheck, or Host device-mode change. This does not make a partially executed
PIO transaction reversible or retract a transmitted packet.

## Alternatives considered

Increasing512 would conceal the mechanism and change an existing bound.
Word4 would violate actual byte-mode device semantics. Grouping clock checks
while retaining four separate byte syscalls saves fewer transitions. A broader
cooperative RX cursor remains an option if the fixed-group reduction cannot
complete actual large frames under the original cut and quota.

## Verification and limits

Core tests cover total numeric decoding, high bits, exact width/direction/range,
current domain, revocation, stop, quota exhaustion and original-cut expiry.
Device models cover full and wrapped frames, scalar tails, exact byte counts,
partial group failures, bounded midgroup expiry, no ring advance/retry, TX and
STOP/readback. Pure reply tests reject incompatible negotiation and noncanonical
outputs. Model transition counts are not measured VM timing. Fresh source pins,
three actual linked Kernel/Root/resource censuses and a separately approved
actual finite run are required before claiming that this resolves acquisition.

## Migration and review trigger

The extension is additive and separately negotiated. Reverting the caller and
new numeric operations restores the old behavior. Retain the failed source,
receipts and media. Reconsider cooperative RX if actual acquisition still
misses512; never compensate by renewing an accepted cut or increasing quota.

## 2026-11-14 private receive-clock refinement

The trusted Mediated backend may explicitly opt in to reusing the previous
successful POST clock before a later normal-RX four-byte group. The opt-in
promises the same actual Core's nondecreasing MONOTONIC clock and its actual-time
deadline check before every physical Byte4 group. Portable backends default to
false and retain every fresh PRE clock. This changes no Core opcode, negotiation,
capability, ABI hash, CPU quota, or original operation cut.

Reuse is limited to a subsequent group within one unstopped receive transfer,
when the retained successful POST sample gives a strictly positive remainder
no greater than1024 and the cut is not MAX. Each header, body and wrapped body
transfer starts again with a fresh first-group PRE check. Later preemption can
only reduce that remainder or make Core refuse before any I/O. There is no
fallback after an attempted batch. Every group's POST must still succeed before
its four bytes are copied into the private receive buffer. The physical four-step
budget and every64-operation yield plus post-yield clock are unchanged. Cold,
scalar, STOP and TX checks are retained.

The purpose is fewer redundant userspace clock traps under the existing
512-tick child and64/256 CPU window. A later Source09 Poll timeout had no retained
receive substage or per-call CPU sample; the separate failure-only diagnostic
completed all six boots without reproducing it. Neither observation establishes
the original cause or a fix. Models must compare exact payload, ring ownership,
physical port order and counts while enforcing Core's actual cut at every group,
including preemption between the cached sample and admission, partial errors,
expiry, reversal, default-false and first/cold checks. Fresh actual resources and
separate review remain required before a VM experiment or performance claim.
