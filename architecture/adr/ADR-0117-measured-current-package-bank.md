# ADR-0117 — Measured Current package bank

Status: Accepted Internal Level B refinement; new-cohort qualification pending.
Date: 2026-11-16
Related: ADR-0109/0111/0114/0115; M8-01/07/11/12/14.

## Evidence and decision

Actual A1 packages exceed the original Current bank. The readback-verified
`workspace-a1-bank-03` measurement retains Files104,770 bytes at0,
Editor118,932 at104,784 and Inspector84,386 at223,728: final end308,114.
The63-page bank holds258,048; its shortfall is50,066 bytes. Seventy-six pages
would be the minimum. Use79 pages/323,584 bytes, leaving15,470 bytes for this
measured cohort. Candidate remains63 pages/258,048; its118,932-byte package fits.
The earlier raw/encoded-size failures remain retained rather than passed.

Current Role19 moves from Root pages384..446 to368..446; Candidate Role20
stays304..366. Guards303,367 and447 remain absent;383 is now inside Current.
Other Root and child mappings are unchanged. Root has the same37 source objects
and channels. Exactly16 additional normal shared frames are charged to its
existing hierarchy; Root4096/Boot8192 frame budgets remain unchanged.

The individual Zion limit remains63 pages. The separate sealed/dynamic image
owner remains64 pages. Neither can consume the larger Current bank as one
larger executable. PackageBank exposes separate pages/capacity_bytes; placement
checks exact aligned offset+length against its actual bank while independently
retaining each package's old size cap and whole-byte/hash binding.

## Mechanism and compatibility

Preserve the ordinary MemoryExtent/OwnedRam64-page types and constructors.
Use a selected M8 shared-extent capacity80, with affine frame/lease ownership,
publication, failure debt, revocation and exact accounting. Other profiles keep
their old capacity and65-page refusal. The selected capacity must also refuse
81 pages before allocation. Dynamic images retain their separate64-page owners.

The larger resident frame metadata is real memory:16 additional
Option<PhysicalFrame> entries per37 backing slots nominally add14,208 bytes;
actual size and the complete linked stack must be measured. Do not raise or
remove the262,144-byte Kernel stack gate. Constructors should retain bounded
phase/resident ownership. Private Root/App stack guards remain unchanged.

The Root v5 description/hash changes because its mapped-bank contract changed:
`ca5e7fd0be762cb03684e0fb181dd41f01ab45f96c488c437fb9d24d3fd0c860`.
Base336 and child528 ABI hashes stay unchanged. Old Root06 experiments retain
their42b2 artifact pins; they do not qualify this new Root contract. The new
Root, producer, physical sources, source activation, package reader and native
mapping must agree before boot. Default/V1–V4 policy and saved data stay exact.

## Required qualification

Independently verify description hashes and exact catalogue boundary failures;
retain real encoded package readback and per-bank occupancy. Exercise selected
79-page initialize/map/foreign-lease/revoke/retire/accounting, failed publication
and ordinary64/65 refusal. Run default and selected regressions and actual native
ELF/stack preflight. Then boot the coherent A1 cohort and record whole-graph
frames/capabilities and actual semantic/recovery workflows. Source checks or
this numerical refinement do not complete any M8 gate.
