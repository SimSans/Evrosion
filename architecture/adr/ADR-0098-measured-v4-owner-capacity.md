# ADR-0098 — Measured V4 owner-controller image capacity

Status: Accepted Level B private implementation refinement. Parent independently
reviewed the exact proposal and authorized240/244/246. Fresh selected-source
checks, physical resource census and actual guest qualification remain required.
ADR-0094 and every earlier refused artifact remain historical evidence.

## Evidence and decision

The complete automatic-first-use/owner/Host04 diagnostic has an actual linked
Root ELF of 227 image pages: 189 RX, 11 RO/NX, 19 RW/NX and the existing 8-page
stack. Its text is 770,078 bytes, rodata 43,104 and RW memory 77,744. Its ELF is
`6441faafaea0469c89741d843d4460bebf5ae3ae65e89c1d1b5092d8873ffba0`.
The linked fixed-frame census is 31,368/32,768 bytes with no unresolved indirect
calls. The negative profile separately measures 224 pages and the same stack.
The actual owner producer has also refused under the unchanged 224-page ceiling.
Initial 233/230 frames in the diagnostic are image+6 inferences; they are not a
completed producer/admission or runtime high-water census.

The reference is joined draft17's 224 image / 228 owner / 230 initial profile.
The earlier Main baseline had208; ADR-0094 describes its private224 refinement.
These historical components are distinct from this newly joined owner source.
The reference private V4 ABI was `9e9006bcb7dcf8bd61e7a4ffcb6f321c3de9d93353c5ce0e3829ee6c89426550`
after the separately reviewed NIC refinement, not ADR-0094's earlier component ABI.

Set **240 image pages, 244 private mapping-owner slots and 246 initial private
frames**, only through the exact V4 constructor. This is one further 16-page
quantum after the 208→224 refinement, with 13 pages / 52 KiB over the measured
227-page owner (5.7% image headroom). It is not a promise to consume that headroom
or to admit every simultaneous maximum.

| Ceiling | Headroom over owner227 | Extra fixed mapping metadata versus224 |
|---|---:|---:|
| 227/228 | 0/1 pages | no practical integration margin |
| 232/236/238 | 5 pages / 20 KiB | 192 bytes |
| **240/244/246** | **13 pages / 52 KiB** | **384 bytes** |

232 was the smaller plausible eight-page alternative. The reviewed decision is240 because
232 leaves only five pages before the next profile change during the still
unqualified joined runtime. No hardware alignment requires either quantum;
the reviewed16-page decision is explicit maintenance headroom, not a physical
reservation. A later feature exceeding240 requires a new review, not another
silent increment. New retained Kernel ownership may enlarge live Kernel frames;
only a fresh linked selected-Kernel census can establish that it fits.

## Guarantees retained

Keep ordinary 64/68 and Native3 96/100/102 constructors and aliases unchanged.
Keep Root limits `[65536,512,10,10]`, Boot `[262144,1024,10,10]`, periodic execution
budgets/cumulative observations, child descriptors (32 frames; NetService64),
64-handle/object bounds, 29-of-32 V4 roles, one held replacement, package63-page
bounds, two lazy64-page dynamic owners and their two external frames unchanged.
No extra capability, actor, process/thread slot, CPU exemption, accepted-I/O retry
or deadline renewal follows. Keep Root32KiB/Kernel256KiB/child16KiB stacks, every
existing health cut including64, and existing512/1024/8192 cuts.

Image count is not a new virtual aperture. Actual owner LOADs occupy low pages
1..219 and stack256..263. Guards255/264, package windows304..366 and384..446 and
their guards, Root505..509 sources, bootstrap509/final stack511, and the separate
PD1 dynamic layout remain. Existing per-page checks and actual overlap guards
remain authoritative; W^X still permits only RX, RO/NX or RW/NX. Typed V4
manifest selection, actual allocation/ancestor charges, unique frame ownership,
physical detach/TLB boundary, stop/reap and complete reclamation remain required.

Root and children are actual Boot sibling jobs. With the proposed ceiling the
existing **partial** model subtotals become:

- Initial private Root246 + child ceilings288 + held App32 = **Boot566**.
- Root246 + dynamic table/control2 + two64-page dynamic owners = **Root376**.
- Boot566 + dynamic130 = **Boot696**.

These leave Root136 and Boot328 frames relative to those partial subtotals;
other shared RAM, immutable ROM package extents and allocator/metadata ownership
still require their real charges and the complete actual peak census. ROM banks
are charged to Boot by the current `NativeBacking::append(..., boot, ...)` call.
Do not advertise these partial sums as a simultaneous-package or total-RAM fit.
Correct the stale LAYOUT.md425-under-Root512 paragraph to this actual sibling
accounting; do not change the quota to accommodate its incorrect explanation.

## ABI and implementation scope

Change the SDK V4 capacity constant; keep owner=image+4 and initial=image+6.
Update the V4 description's capacity text, the dynamic description's
`outsideinitialLoadedImage230` to246, and both explicit SHA256 constants.
The dynamic24-byte physical-layout record stays byte-identical; V4 layout words
952/960/968 bind240/244/246, with all other layout bytes preserved. The Root
catalogue/manifest/authority hashes are regenerated from the new current ABI.

The exact independently recomputed descriptions are dynamic `3b3e1124c58b2e162af8ca16d2795101563d8c30dcb0297ed2e7fdf406807e91`
and V4 ABI `b4fd72518e6b786bb290f575e8c78c9cfeb9839ecd89857532779c023d99c7a6`.
Tests independently recompute these hashes; recorded hashes alone do not prove
actual runtime qualification.
The stable App/v1 ABI, data/Note schemas, publisher keys, durable counters and
saved bodies remain independent. Do not rewrite historical fixture/evidence
numbers or digests to imply they used the new profile.

The executable/runtime/Host constructors already alias the SDK V4 constants.
Review their reachability; no generic-limit, loader-permission, scheduler or
ownership bypass should be necessary. Required edits are the SDK two description
files, SDK V4 tests, Core V4 tests, V4 layout documentation and this new ADR/evidence
index. No generic/runtime/Host alias rewrite is required; the selected implementation
continues to derive those aliases from the SDK values.

## Required validation before adoption

1. SDK: exact240/244/246 and layout offsets, independently recomputed two digests,
   unchanged dynamic layout record/other layout fields, stable App ABI and child
   roles/limits. Old current224 ABI/catalogue/layout must be refused by current
   admission. Pure912-byte startup syntax has no ABI field and is not authority;
   do not claim that parser alone distinguishes two V4 revisions.
2. Core: admit exact240 and refuse241 before loading/allocation; include current
   owner227,232,239 and all retained historical boundary probes. Keep ordinary
   65 and Native97/above denials, typed-startup cross-profile denials, and
   malformed/overlap/W^X/stack/window guards. Prefer a boundary synthetic ELF with
   the actual eight-page Root stack and guards as well as the existing page-count
   fixture. A correctly rehashed manifest carrying the old224 ABI must return
   Abi/Profile refusal, not merely a stale checksum error.
3. Exercise all244 owner slots, exact full refusal returning the same owned frame,
   unmap and total reclamation. Update actual partial totals to566/376/696; prove
   exact remainingRoot136 admission, next-frame atomic refusal, and Boot saturation
   followed by child refusal without metadata/usage mutation. Keep the existing
   ancestor guards. Do not merely loosen stale literal expectations.
4. Full SDK/Core/Root/Host and relevant component models, strict/fmt checks; actual
   producer admission, package/image/descriptor/source identity, private/frame and
   Kernel fixed-frame census for all four declared recipes: network-owner,
   network-system-owner, network-recovery-owner and network-negative. Require
   unchanged32KiB Root/256KiB Kernel stack gates. Root's linked audit must have
   zero unresolved indirect calls. Kernel's resolved fixed-frame census retains
   its reported28 unresolved-function groups and5 cycles as explicit limitations
   of the accepted Internal measurement method, not a formal all-path proof.
   Preserve the reports, every refusal and actual runtime guard checks. Run
   normal/native-session/non-owner regressions too.
5. Only after a final joined source/artifact pin and coordinator review, run the
   owned healthy acquisition/coldB/C-fault/Recovery, owner first-use and warm GUI,
   first-four denials/retirement, LinkLoss/Endurance and full ordinary retirement
   gates. Actual physical/frame/metadata peaks, CPU accounting and accepted work
   remain independent evidence. The retained04 MissingProgress failure is not
   solved or excused by an image ceiling change.

## Simplification assessment

The one-claim resident owner, shared verification/publication and ref-only outbox
reduction are already retained. The tested fresh borrowed-head comparison saves
864 text bytes and is already included in227; it does not close the gap. This
owner needs8,222 additional text bytes removed to reach224 at unchanged RO/RW
sizes. Older SHA/Content outlining results came from different source versions;
they cannot be added as current measured savings and introduced extra crypto
serialization/stack review. No present measured pure simplification closes the
gap while retaining the actual fresh first-use guards and complete owner UI.
Removing those checks/UI behavior is a functional reduction; splitting the affine
Root backend/controller adds a new authority/lifetime design. Neither is a
smaller reviewed change than this bounded V4-only refinement. Do not churn more
micro-optimizations before measuring the complete approved feature set.


## Integration18 scope clarification

This joined copy corrects validation item4 under the independent parent review;
the sealed six-file capacity component and its original evidence stay unchanged.
Its Root reports have zero unresolved indirect calls and retain their reported
non-returning panic-cycle limitation. Its Kernel reports explicitly retain28
unresolved-function groups and5 cycles. The resolved fixed-frame numbers are
engineering measurements under the existing method, alongside actual stack/
layout guards; they are not a complete or formal bound over unclassified calls.
No report is silenced and no guard or quota is changed by this wording.
The component measurements do not qualify this later joined source. Fresh final
resources and actual runtime/retirement evidence remain separate requirements.
