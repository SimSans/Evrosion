# ADR-0084 — Measured V4 content-controller image capacity

Status: Accepted Level B implementation refinement; fresh selected Kernel census and guest proof pending.
Date: 2026-11-13.

## Evidence

The actual linked SourceRoot content mount, authenticated cold inspection,
scoped downloaded-package resolver and resident update continuations require
165 PT_LOAD image pages and171 initial private frames. The retained component09
ELF is SHA256
`c97ba37d5255412b98279766a936a991621d2b65ea44181574e78140e8db8a8c`.
Its resolved fixed-prologue/reference stack census is28,696 of32,768 bytes.
Earlier116,280/50,328/48,680-byte stack refusals remain retained; resident
single-owner continuations reduced those frames without changing the protocol,
clock cuts or stack limit. The124-image/130-frame V4 admission ceiling honestly
refuses this component. A component census does not attest a linked Kernel or
guest execution.

The exact current source-module type probe at128 and180 private ownership slots
measures `PrivateUserMappings` at3,080/4,328 bytes, `PrivateUserRoot` and
`PrivateLoadedRoot` at3,424/4,672 bytes, and `PrivateLoadedImage` at3,528/4,776
bytes on x86-64. Each retained owner grows by1,248 bytes. The probe executes no
privileged functions. This metadata has real consequences for retained outer
owners and their call-chain copies; it is not an extra physical-page charge or
a substitute for the selected Kernel census. Probe commands, exact module and
library hashes, failures and results are retained in
the local engineering archive.

## Decision

Only an exact verified V4 Root manifest may admit up to176 image pages,
180 private mapping-owner slots and182 initial loader-owned frames. The existing
image-plus-four ownership-slot and image-plus-six loader-frame formulas remain.
These finite ceilings close the measured current admission gap; they are not a
promise that every simultaneous maximum fits the complete graph.

The V4 measured ABI,1024-byte layout and producer bind all three limits. The
producer reports actual image pages/private frames and the distinct limits.
The dynamic-image description explicitly keeps its two lazy page-table/control
frames outside this initial182-frame ceiling. Both optional64-page sealed
owners remain separately charged. Neither metadata capacity nor an image
preflight reserves physical RAM or waives ancestor admission.

Root's512-frame and Boot's1024-frame quotas,64 capabilities,32KiB Root stack,
256KiB Kernel stack, cumulative/periodic CPU limits and finite process/thread
budgets remain unchanged. Ordinary64-image/68-slot and Native3's96/100/102
constructors, all child limits,64-page dynamic extents, guards, W^X, page-table
geometry, mapping-owner retirement and physical accounting remain unchanged.
The existing ordinary metadata-size assertions remain intact.

The actual CreatorJob names Boot, so children are RootJob's siblings. The
portable topology test now charges the502-frame private-image subtotal through
that ancestor and models the separately charged130 dynamic frames: Root312,
Boot632. It also proves unchanged Root and ancestor saturation refuse without
partial charges. This is a defined subset of RAM ownership, not a whole-graph
physical peak bound. Actual package banks, shared buffers, tables, concurrent
replacements and runtime lifetimes still require measured admission and peak
accounting.

## Verification and remaining gates

Portable tests must admit exact V4 manifests through176 pages and refuse177,
retain ordinary/Native3 refusals, fill all180 ownership slots, return the exact
rejected frame and reclaim every retained claim after unmap/retirement. SDK
layout/digest, Core, producer and actual bare-target checks must pass.

A fresh selected linked V4 Kernel must include the larger retained owners and
both observer paths, retain actual world reachability and pass the unchanged
262,144-byte stack census before any VM. A refusal is preserved as evidence;
it requires a separately justified copy/scoping/residency refinement, never a
stack increase or weakened assertion. Subsequent guest evidence must measure
real Root/Boot frame usage and lifetime retirement. Source parsing, content
publication and these ceilings alone establish neither downloaded activation,
health/KG, physical PTE execution nor whole-M6 acceptance.
