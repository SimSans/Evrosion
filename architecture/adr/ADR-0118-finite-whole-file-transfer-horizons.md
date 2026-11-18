# ADR-0118 — Finite whole-file transfer horizons

Status: Accepted Internal Level B policy; new native1MiB qualification pending.
Date: 2026-11-16
Related: ADR-0109/0110/0116; M8-03/11/12/14.

## Evidence and decision

Retain the original8192-cut1MiB load failure in
`WORKSPACE_1M_INITIAL_CUT_FAILURE_01.json`: the archived Root09/Inspector04
cohort stopped before editing or Save, with the accepted Read deadline exceeded
and retained through the finite quiescence failure. The cold1MiB source and disk
remained exact, with no stage created. This is a failed runtime observation,
not a native1MiB success. The separate tiny15-byte Save/readback succeeded under
the original8192 cut after selected bulk PIO; neither result measures every
large-file phase.

The failed run retained1475 aggregate Block requests at tick24418. The pending
Editor Read was request150 with deadline23394, before all256 file chunks had
loaded. Aggregate counts include startup/metadata traffic and are not isolated
per-chunk latency measurements. This establishes that the original whole-file
cut is insufficient for that run without justifying renewal of that Read.

Separate the finite whole-file horizon from each new File2 RPC. The public
no_std SDK policy accepts at most1MiB and computes:

`8192 + 512 * max(ceil(bytes / 4096) - 1, 0)` ticks.

Empty and single-chunk files retain8192 ticks. The1MiB maximum is138752 ticks.
Capture the absolute whole cut once, before initial load or frozen Save hashing;
the same cut covers chunks, Commit and independent readback. It never advances
on progress, focus, rendering or reply. The allowance grows by one bounded
512-tick increment per extra4KiB chunk. This is a conservative finite policy
following the measured8192 failure, not a calibrated throughput guarantee: the
source request-count model estimates11533 Block requests for a full1MiB Save
and readback, compared with313 for the observed tiny Save/readback, including
one2304-read stage verification. The255 extra chunks receive130560 additional
ticks in total. This provides finite headroom for the extra chunk/verification/
readback work without pretending that a count ratio calibrates guest ticks or
bounds every request's worst-case latency. Actual Commit still must fit its own
original request cut.

Before each distinct new File2 request capture
`min(whole_cut, actual_now + 8192)`. Put that exact cut in the request Header and
actual scalar RPC. Do not renew, retry or substitute a request after acceptance
or uncertainty. The new Transfer owner is non-copyable, checks monotonic time
and final hash/completion work, and permanently fences on expiry/backward time
or explicit uncertainty. This policy value grants no capability, CPU, mapping,
loan return, cancellation or retirement proof.

## Accepted-operation and storage audit

Workspace's Transfer holds the exact owner/token/StageInfo; it does not retain a
Begin deadline for later distinct chunk requests. Every accepted request is
retained separately in Pending. Commit verification and final publication use
only `pending.request.deadline`, including after trusted continuation yields.
Expiry retains uncertainty; a later query does not release or renew that work.
The durable stage has no timer that is rewritten by this client policy.

Keep File2 admission at8192 and each Block child request at1024. Preserve all
existing wire, service, Kernel, bootstrap and Job envelopes. A large Commit
that cannot finish within its existing cut remains a real failure requiring a
separately reviewed protocol change, rather than an implicit continuation reset.

Editor retains its actual FileClient, loading selection/hash/offset, private
document bytes and transfer owner on failed load. Failed Save retains its
frozen proposal, bytes and uncertain phase. No new Save, reconstruction or
release bypass clears that state. Saved still follows exact committed revision
and full independent readback/hash validation.

## Required qualification

Test exact tiny/max/oversize/overflow bounds, monotonic and reserved clocks,
whole-cut clamping, terminal fencing and accepted-request retention. Validate
native Editor A/B strict lint, exact loaded ELF bytes and unchanged32KiB guarded
stack. Then measure actual1MiB load/edit/Save/readback with this policy, original
per-request cuts, independent cold bytes and retained first-failure evidence.
Stale writers, space/refusal/cancel/partial publication and recovery remain
separate required coverage. Portable tests or a longer whole horizon alone close
no M8 gate and do not qualify arbitrary application timing.

The later measured Commit failure and optional separately requested staged
verification are recorded in [ADR-0119](ADR-0119-bounded-staged-file-verification.md).
The original single accepted request's cut remains unchanged.
