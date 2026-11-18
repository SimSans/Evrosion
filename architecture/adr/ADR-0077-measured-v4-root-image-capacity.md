# ADR-0077 — Measured V4 Root image capacity

Status: Accepted Level B implementation refinement; actual selected Kernel/VM proof pending.
Date: 2026-11-12.

## Evidence

Qualified private random ownership, the protected Client505 control route,
explicit cooperative device shutdown and one bounded plaintext HTTP fixture
client bring the actual linked V4 SourceRoot to101 PT_LOAD pages:85 executable,
7 read-only,1 initialized writable and8 declared stack pages. Loading requires
107 private frames, including the existing bootstrap/stack and four page tables.
The previous96-image-page/102-frame bound correctly refuses this candidate.

The unchanged32KiB guarded Root stack passes the resolved fixed-prologue/code
reference census at31,256bytes, with1,512bytes of reference margin. This is not a
formal whole-program, recursion or runtime high-water proof. NetService remains
at35 image pages/41 private frames and7,360/16,384bytes of resolved stack.

Exact refused sources, ELF, logs and reports are retained in
the local engineering archive, SHA256
`44cd4755d757da95b92541a5022c875a3451bd457fd74666ae59363c3d8bd43a`.
The V4 Root ELF SHA256 is
`5a737848d33d5c0de99e47d13417611655a981a9cb6c3d14c1ced5527d39989d`.
This local component record does not attest a qualified-source guest execution.

## Decision

Permit at most104 image pages only through the exact verified V4 Root manifest
constructor, with108 private ownership slots and a110-frame loader ceiling.
The same two spare metadata slots and all existing bootstrap/page-table charges
remain. This closes the measured five-page admission gap; it is not promised
capacity for future crypto or other features. A separate security service solely
to save these five pages would add another startup, authority and recovery
dependency without a measured need.

The SDK ABI and1024-byte layout bind the exact limits in the previously zero
928..960 range. The Kernel parser and selected V4 outer Root image use the same
constants. Only that single Root owner grows. Existing actor arrays, ordinary
64-page/68-slot aliases and Native3's96-page/100-slot/102-frame owner stay intact.

Root's512-frame quota, cumulative/periodic CPU limits,32KiB guarded stack,
2MiB private virtual window, package banks, PTE permissions, W^X, authority,
startup identity and physical retirement remain unchanged. Every actual page
and table is still charged before allocation and returned once after actual
quiescence. No caller selects an arbitrary larger capacity.

## Verification and remaining gates

Portable tests exercise actual V4 manifests at64/96/97/101/104 pages and refuse
105, preserve old-profile refusals, check full108-slot ownership refusal and
reclamation, bind the SDK layout/ABI and retain the unchanged ancestor quotas.
Focused host and actual bare-target profile checks are required.

The actual selected V4 Kernel must still pass its unchanged256KiB linked stack
preflight after this larger generic owner is instantiated. The producer must
recheck the final Root and child ELFs, real guards/mappings and complete teardown
in the subsequent source-frozen VM. No network availability, device recovery,
TLS, update trust or whole-M6 acceptance follows from this capacity refinement.

## Measured supplements: read-only RTC and signed-time client

ADR0079's actual joined RTC candidate uses105 image pages/111 private frames and
correctly refuses the prior104/110 ceiling. Its approved V4-only staging ceiling
became108 image/112 owner/114 private frames. The original refusal and23,144/32,768
stack census remain retained; no old evidence was rewritten.

ADR0082's actual joined serial-backend time client then uses121 image pages/127
private frames and correctly refuses108/114. Permit only exact V4 Root at most
124 image pages,128 private ownership slots and130 loader-owned frames. This
closes the measured current gap, not a blanket allowance for future crypto or
features. The same SDK/Core constants, ABI, selected outer owner and producer
bind these limits. Root32KiB/Kernel256KiB stacks, Root512-frame quota, ordinary
64/68 and Native3's96/100/102 remain unchanged. Tests admit verified V4 through124
pages, refuse125 and retain every128-slot owner claim on full refusal/retirement.

The actual trusted CreatorJob names Boot: child Jobs are siblings of RootJob,
not its descendants. The portable quota scenario now follows that topology:
Root's process/thread usage is1, while Boot charges9 live or10 with one held
replacement. The450-frame sum of private image ceilings is only a Boot subtotal,
not Root512 usage or a complete shared/dynamic/physical peak proof. Root-owned
package/candidate buffers charge actual RootJob separately. No quota increase
or permission follows from this arithmetic. Actual allocation/retirement and
selected-factory stack evidence remain required before guest execution.
