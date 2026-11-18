# ADR-0047 — Bounded desktop authority and live selected-file grants

Status: Accepted implementation mechanism; bounded full desktop execution PASS.
Date: 2026-10-27. Owner mandate Level B, preserving foundational guarantees.

The full graphical graph needs separate Root, Shell, Display, Input, File, Block
and App processes. Combining Shell with Display would defeat E-017.35/.70.
The old eight-source Root fixture and globally object-indexed service tables
cannot express that graph sustainably. Held-only startup delegation also cannot
deliver a file selected after an application starts. Ordinary transfer preserves
rights, so it cannot be relabeled as an exact READ grant.

Root therefore has an explicitly selected bootstrap v2, with its own ABI and
authority digest domain. Its 720-byte readonly record permits 24 entries; the
initial graphical profile declares 18. Its manifest is measured by the same
Custodian/Bindings budget, token, sequencing and activation owner used before.
An ordinary service cannot select this format. Legacy v1 remains 336 bytes with
eight roles and unchanged ABI/digest bytes. Child services retain eight declared
startup roles and 16 capability slots.

The authority allocator has four trusted control banks of 64 slots for custody
and Root, instead of widening every application's table. Ordinary process
creation cannot request a control bank. Full domain/object generations, lineage
and handle encoding remain checked. Compact checked private node indices reduce
metadata size without narrowing public identities. Registry Job/Image/Process
records use bounded sparse rows keyed by full identity, rather than requiring a
low global object slot. Reuse must reject the entire stale generation.

The bounded implementation has 64 objects, 40 domains, 256 lineage nodes, 16
Registry rows per record class, 16 scheduler Jobs, 16 RPC routes and 512 recycled
RAM claims. The planning census includes seven actors, two surfaces, separate
system/File windows, live-grant escrow and provider replacement overlap. These
are implementation capacities, not permissions or permanent platform limits.
Actual linked actor footprints, maximum overlap and stack use must be measured
before the full physical graph is accepted. No capacity value proves admission.

A selected-file route consumes the actual Registry-created managed mailbox and
its escrow owner. It fixes the current full Root token and actual active target
Process/Thread/Job identity. A selected object fixes a real File READ endpoint
and the service-resolved object identity/revision/digest. Only a retained trusted
picker handoff can enqueue its source. The source moves to escrow with its
original rights; receive derives exactly Endpoint SEND, invalidates the source
and returns that installed handle to the actual target thread. Queue acceptance
is not delivery. Capacity failure keeps the queued owner; failure/refund and
late target death remain explicit.

Route retirement requires the retained exact stopped Registry/Scheduler owner
and a settled mailbox before forgetting the old process row. Revoked RX or a
closed public Process CONTROL handle must not prevent owner cleanup. Live,
queued, missing or recycled rows return the route owner on failure. Managed
retirement reuses the actual escrow and preserves its ticket clock; it never
constructs a second mailbox for the same endpoint.

The trusted Shell renders the precise picker choice, waits for its matching
protected Present reply and then obtains an Input barrier. The same PS/2 decoder
retains main/keypad Enter state across the barrier. Keys queued before the cut,
held Enter, unknown release history, replays and replacement cannot approve.
A fresh eligible Enter requests a grant; it does not mint one. Root separately
revalidates its retained live requester, actual File revision and policy before
the current-incarnation handoff. App or Input replacement cancels pending
approval; Shell replacement cannot restore an old approval. Remembered intent
is explicit per-user data, never a persisted live handle.

Shell and App have distinct parent-owned RAM surfaces. Display reads only the
surface whose sole writer is actually blocked in the corresponding protected
Present. Shell composition skips the visible App rectangle; an App Present
updates that rectangle. Visibility/session control reads neither surface.
Restoring App content requests another App Present rather than sampling a
runnable writer. App and Shell frame clocks reset independently only after
Root has settled the old call and stopped/detached its old writer.

System health probes and user File envelopes use disjoint Store-v2 regions on
the same disk. Endpoint identity selects the region/window and File object; an
App packet cannot supply an LBA or sibling-object selector. Root resolves File
metadata through bounded scalar requests, without mapping the mutable App/File
window. The initial profile keeps File writes under one serialized trusted
owner during selection; concurrent external writers require a stronger atomic
File-side version/selection transaction before they can be admitted.

The portable desktop source checks (local engineering archive)
retain 43 passing policy/graphics/input/picker tests, strict host lint and all
eight actor feature target checks with exact source bytes. The
merged portable core record (local engineering archive)
retains 344 kernel and 38 startup-contract tests, strict library/test lint and
exact source bytes. This includes capacity, generation reuse, legacy v1/Root v2
and 64 repeated managed grant lifecycle cycles. These checks do not accept
actual input/consent or the full M4 graph.
The existing surface VM proof (local engineering archive)
remains the separate, bounded physical component proof.

The actual full desktop graph (local engineering archive)
now passes one fresh VM: seven separate live actors, nine actual starts including
App/Shell replacement, 216 completed protected calls, three selected grants and
two actual contained page faults. All fifteen required screen stages match
1024000 actual pixels each. Cancel preserves the prior grant; the replacement
App starts without one, receives a fresh grant, and survives Shell replacement
with the same Display. Independent raw-disk checks preserve File contents and
all guards, leaving System untouched. Actual mapping/frame/metadata retirement
passes. This does not certify native install/update, general device recovery or
GUI Known Good health.

Integration fixes preserve those guarantees: retained regression controllers
borrow their unique metadata tables; desktop image admission checks each actor's
exact surface/scalar/device shape; submitted Opening acknowledgement cannot arm
another input gate; Inspect decodes known rights before actual authorization.
The linked full-entry census includes the loader and preceding tests: 226536
bytes under the unchanged 256KiB stack. It is not a formal whole-program bound.
Readable Hello uses native viewport pixels, while the first component renderer
retains its original layout. Preserved failure records and source checks are
linked from M4 progress.
