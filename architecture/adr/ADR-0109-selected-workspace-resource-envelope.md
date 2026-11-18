# ADR-0109 — Selected V5 workspace resource envelope

Status: Accepted Level B implementation refinement; integrated runtime qualification pending.
Date: 2026-11-16
Related: ADR-0103/0104/0106/0107; M8-01/05/08/12/13.

## Evidence and decision

The V5 graph has eleven child actors and ten distinct executable images. Files,
two independently owned Editors, Inspector and Shell have separate process,
surface and endpoint owners. Root controls a separate protected plane. Workspace
has four selected-file routes, a separate Files namespace route and a Root-only
control route. Twenty-three child channels plus the protected Root event channel
must coexist with their exact owner domains. The old graph's object, lineage,
space and Root-handle ceilings cannot describe this graph.

Select a separately constructed `workspace-authority` profile:96 objects,
512 lineage nodes,64 spaces and96 handles for a trusted workspace control space.
Ordinary spaces remain16 handles. The default factories still enforce the old
64 objects/256 nodes/40 spaces/64 control handles even in a binary compiled with
the larger physical arrays. A userspace scalar cannot select the larger class.
Generation encoding, rights derivation, revocation and closed-space ownership
remain unchanged. The selected Registry independently admits only V5 service
roles; an ordinary descriptor does not become a workspace image by re-labeling.

These are finite engineering ceilings, not measured usage. The current graph
lower bounds are82 steady objects,86 with a held replacement,49 steady spaces,
52 during channel overlap,306 steady lineage nodes and340 with a held image.
Root needs at least71 live handles before temporary overlap and76 for held-image
scratch. Actual loader/graph census and failure cleanup must demonstrate headroom
on the frozen integrated build; these arithmetic lower bounds cannot pass M8-12.

## Hierarchical accounting and private memory

Root's Job is the ancestor of all child Jobs and owns shared backing. The Root
subtree frame ceiling is4096; Boot's is8192. The two Editor document buffers alone
require512 frames, so the old Root private-loader ceiling cannot serve as its
descendant subtree allowance. Shared/package backing must be charged once to its
actual owner; borrowing and alias mappings do not create free backing. The V5
creator cap selects RootJob rather than escaping to the legacy creator Job.

Root's private image/page/frame envelope stays240/244/246. The new ordinary UI
and Workspace images have96/100/102 ceilings. Display has80/84/88, including its
two independent framebuffer aperture page tables. Each Editor has384/388/390 and
a512-frame Job ceiling: its resident1MiB document is256 zero RW/NX pages64..319,
not a document-sized stack value. New actor stacks are eight guarded RW/NX pages
480..487; Root's eight pages remain256..263. Existing core image/stack admission
retains64 image pages and four stack pages256..259.

Root package banks are separate read-only63-page extents. The catalogue supplies
typed per-package bank and byte offset, exact byte length and digest. Encoded
packages must actually fit without overlap; metadata is not a substitute for
the bytes that Root and the loader verify. Root's protected surface, catalogue,
Workspace, network-client and legacy System I/O mappings have separate guards
and owners. Root holds the NIC backing cap without mapping it into Root.

## CPU and completion obligations

The initial contract declared cumulative CPU ceilings65536 for Root,16384 per
child and262144 for Boot. Actual second guest observation
the local engineering archive
reached all eleven started children by tick6550. At elapsed58000 ticks the
captured user IRQ charge was57887 for both Root's subtree and Boot, approximately
0.998 charged ticks per delivered timer tick. The old Root ceiling would stop
this observed graph around65.6 seconds; it cannot support a thirty-minute gate.
The60,070ms host observation timed out with no fatal guest line and did not
establish clean shutdown, child semantic health or long-run acceptance.

The authorized Level B refinement selects finite M8-only cumulative CPU limits
of4000000 for Root,8000000 for Boot and1000000 for each of the four child Job
templates. Frame/process/thread limits are unchanged. At the measured1000Hz
timer profile, thirty minutes is approximately1800000 ticks;4000000 leaves
finite Root-subtree headroom over that delivered-IRQ bound, while each child's
unchanged64/256 period quota bounds one child's share. The256-tick periods,
64-tick child quotas and256-tick Root quota remain unchanged. No cumulative
counter is reset during restart, replacement, period renewal or collection.
Exhaustion remains an explicit refusal. Actual host wall time and sustained
user IRQ accounting remain separate qualification facts.

The revised Root ABI is
`42b21f3574bb6bcc684f04c5375982e2a39e8302bb20ecc14c9e6d3ac43df10a`;
the revised528-byte child ABI is
`17508db0f38ec5a0426d11fdff9677063261a65f0461da2cc93a8235086f6f96`.
All selected artifacts/descriptors/catalogue must be rebuilt from the new
canonical contract. Block's new eight-role workspace parser, new three-role
Input and the separately selected network wrappers require exact selected
limits; old six/four-role actors and default factories retain their old
behavior. No startup packet can choose CPU or frame quotas.

The same short guest observation measured13 Jobs/12 processes/12 threads,
49 spaces,295 handles,306 lineage nodes,82 objects and1410 Root/Boot subtree
frames, with149 calls and149 replies and zero retained accepted windows at
the sample. This is a steady snapshot, not a held-replacement high-water or
failure recovery proof. The actual selected Kernel stack census after ending
constructor/initialization temporary lifetimes was151784/262144 bytes; the
earlier292240 and276096 byte failures are retained. Neither the stack nor
legacy resource limits were raised to pass those failures.

Actual ELF admission, mapped guard checks, resolved stack censuses, live high
water, held replacement overlap, timeout/death retirement and the full sustained
session remain required. Host tests and linked images establish component facts
only. Old qualified V4 runtime and original saved volumes remain preserved.
