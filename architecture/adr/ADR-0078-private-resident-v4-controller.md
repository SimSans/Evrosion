# ADR-0078 — Private resident V4 Controller

Status: Accepted Level B implementation refinement; final selected Kernel/VM verification pending.
Date: 2026-11-12.

## Measured problem

The linked V4 Root has a31,256-byte resolved fixed-prologue/code-reference stack
census against its unchanged32,768-byte guarded stack. `native::run` alone
retains15,632bytes. A separate compiler type-layout diagnostic identifies the
long-lived Controller at7,856bytes and Root at6,096bytes. Their13,952bytes account
for most of that frame. Controller includes actual policy, report/history,
owner consent, immutable package views, protected client and private RNG owners.
They remain live while Registry/Store calls require additional bounded scratch.

The original ELF SHA256 is
`8000d94a12731d35db08a0a688cc7a24349d204bc5e68646bafbbe7cc52fda6b`.
It and its exact census remain in the local engineering archive.
The separate `-Zprint-type-sizes` ELF is not substituted for that measured ELF.

## Decision and ownership

Only V4 places Controller in one private ELF `.bss` slot. Root itself remains
local, and its existing `Option<&mut Controller>` retains the sole actual scoped
borrow. Native3 and older profiles keep their existing local Controller.
No heap, new service, global Kernel state, shared window or authority grant is
introduced. The slot is part of this Root process's private RW/NX image, charged
by the existing loader before execution and retained through Root exit.

The backing is aligned uninitialized bytes sized from Controller's type. The
`Controller<'static>` type is used only for its size; no such value/reference is
constructed. The actual `Packages<'a>` and Root-window backend provide the
initializer's lifetime. It returns only `&'a mut Controller<'a>`; no borrow is
widened beyond its actual Root execution/mappings.

An atomic one-claim gate excludes every second initializer, including a claim
abandoned after partial initialization. Extent/alignment refusals precede the
claim. There is no reset, shared read or automatic typed Drop API. Each valid
field is written directly into its claimed place, without assuming zero bytes
are valid Rust values. One macro field list also forms an exhaustive Controller
pattern: adding a field fails compilation until its initializer is supplied.
Only after all fields are initialized and raw aliases surrendered does the
unsafe boundary create the sole mutable reference. Constructors publish no
child/device work or lifecycle pump. Failure keeps the claim permanently closed.

The byte slot never reads or drops a value after the scoped borrow ends. Actual
process retirement still requires stopped CPUs and the existing complete
loan/device teardown; the Kernel scrubs and returns every private frame. A new
Root incarnation needs its own freshly initialized private image. This does not
provide in-place Root reconstruction, automatic destructors or hardware recovery.

## Measured result and limits

The first relocated ELF has a23,128-byte resolved stack census, with9,640bytes of
reference margin. `native::run` falls to7,504bytes, demonstrating that a hidden
full-Controller construction temporary did not retain the old frame. The linked
RW segment has440 file bytes and11,968 memory bytes across3pages, including
linker `.bss` alignment. Total image/private loader counts become103/109 versus
101/107 before relocation, within ADR-0077's unchanged104/110 bounds.
The final linked ELF after the exhaustive-initializer check is SHA256
`57477871de755308f25deff68e1229a0d05b54ee3aa26128b999ae0db3e379d1`;
its stack and page counts above are unchanged.

No stack, CPU, lifetime/operation cut, quota or ordinary-actor capacity increases.
The unchanged32KiB user and256KiB Kernel stack admission checks still apply.
These are actual linked reference censuses, not formal recursion/interrupt or
runtime high-water proofs. Further code/state still needs measured admission;
the one remaining image-page margin is not promised future crypto capacity.

## Verification

The canonical host test `tests/host/test_root_resident_slot.py` compiles and runs
the exact unsafe helper with the pinned compiler and strict warnings. It covers
actual nonzero/scoped-reference initialization, independent size/alignment
refusal, abandoned claims, concurrent one-winner claims and compiler refusal of
an omitted initializer field. It preserves the frontend's `unsafe_code=forbid`.
Actual V4/Native3/older target checks and final constructor/page/stack census are
required. The subsequent source-frozen producer, selected Kernel census and VM
remain separate gates; relocation alone does not attest execution or whole M6.
