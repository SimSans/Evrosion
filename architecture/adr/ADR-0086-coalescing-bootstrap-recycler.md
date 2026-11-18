# ADR-0086 — Coalescing bootstrap frame recycler

Status: Accepted Level B mechanism; fresh selected Kernel census and guest retirement proof pending.
Date: 2026-11-13.

## Measured refusal

The frozen V4 cohort `c8a84b29839ddad6da365bbee50732ac9f4e7323bb6839afd59af5b2b46fd35b`
has531 allocator-owned frames to return at ordinary no-App teardown. The old
recycler retained at most512 individual claims. Its admission preflight therefore
refused before a VM was started, although the actual Root170-page image and
29,864/32,768-byte stack census passed, and the selected Kernel census passed at
261,152/262,144 bytes. The original refusal and artifacts remain immutable in
the local engineering archive; the retirement preflight is
SHA256 `ab2cfe1bcd36c60cac364f0848ebf8fc77ff0ad674b627caaa8a041704071540`.
This is a metadata representation limit, not an exhausted physical-frame quota.

## Ownership and representation

Keep exactly512 fixed entries. Each entry now retains one contiguous run of
frames already returned to this exact allocator. Entries are packed and sorted
by physical address. Returning one affine PhysicalFrame verifies allocator
identity and absence of overlap before changing any entry or counter. An
adjacent claim extends its neighbor; a claim bridging two runs coalesces both.
A nonadjacent claim when all512 entries are occupied returns Capacity together
with the exact unchanged frame. Wrong-allocator and overlap refusals likewise
retain the rejected owner. There is no external free-by-address operation.

On x86-64, an optional run remains24 bytes, equal to the previous optional
PhysicalFrame entry. A separate64-bit recycled-frame count adds8 bytes to the
allocator. No metadata array, frame/process quota, stack, mapping capacity or
physical pool is increased. The validated map's2^52 address ceiling, exclusive
affine claims and overlap checks bound run endpoints and aggregate frame counts.
Reused-frame accounting remains cumulative and checked before consuming a run.
Allocation takes the lowest-address recycled frame before the existing bump
cursor; physical adjacency is still checked separately before contiguous use.

Bookkeeping never scrubs RAM or establishes quiescence. Existing trusted owners
must remove mappings and settle hardware/CPU/loan obligations before returning
their claims. Returned bytes still require verified initialization before user
exposure. No CPU exit, range adjacency or metadata merge substitutes for that
retirement proof.

## Conservative admission and refusal

`recycle_capacity()` remains the number of unused metadata entries: a lower
bound on additional arbitrary single-frame returns guaranteed to fit. Even when
an adjacent return might coalesce at capacity zero, existing whole-owner
capacity-before-scrub guards stay conservative. A batch is refused before any
scrub, Job uncharge or prefix return if that guarantee is insufficient. This
refinement does not promise that every fragmented graph can retire.

`recycled_frames()` reports actual retained frame claims independently of run
count. Memory-extent allocation uses that value to predict cumulative reuse
overflow before issuing a backing identity, charging a Job or allocating any
frame. Treating one64-frame run as one reused frame would permit a late partial
allocation; the new cross-consumer regression exercises exactly that boundary.

## Validation and remaining gates

Core tests cover4096 contiguous returns in one entry, sorted reallocation,
wrong owners, overlap,511/512-run boundaries, a bridge at full capacity and exact
Capacity/overflow refusal. The actual64-page extent regression fills512 truly
fragmented runs and verifies that rejection preserves its entire owner, RAM
read/write counts, allocator counters and Job charge. The same owner can be
released after independent bridge returns restore conservative capacity. A
second actual extent test sets the private reuse counter near exhaustion and
checks that a coalesced64-frame run refuses before any charge or allocation.
No production counter-reset or test setter is introduced.

An independently retained100,000-operation ownership stress test checks the
complete address partition and exact ownership on Capacity refusal. These are
portable mechanism tests. A new source-bound producer, selected Kernel stack
and actual retained-owner retirement preflight are mandatory before guest
execution. A Kernel census exceeding the unchanged256KiB limit must refuse;
this ADR authorizes neither a stack increase nor a weakened preflight. Actual
guest teardown, allocator return and subsequent reuse remain separate gates.
