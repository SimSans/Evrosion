# ADR-0036 — Generation safe service retirement

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: ADR-0011, ADR-0014, ADR-0029, ADR-0035; SUP-014, SUP-015

## Decision

Reclaim explicitly retired scheduler and object metadata with checked generations,
and recycle closed service domains through the existing explicit domain API.
Ordinary service replacement retains its dedicated Job and logical endpoints.
This prevents repeated failures from exhausting otherwise empty bootstrap tables.

This Level B refinement supersedes permanent scheduler-slot retention in
ADR-0011 and object-descriptor retention in ADR-0014 only. Historical M0/M1
evidence and the original ADR text remain intact. Physical lifetime, capability
attenuation, creator ancestry and quiescence-before-replacement are unchanged.

## Scheduler identities

JobId, ProcessId and ThreadId contain a private slot and nonwrapping generation.
Every lookup and stored association validates both. First-generation diagnostic
IDs retain their previous values; later diagnostics encode the new generation.
Dispatch, initial admission, waits and wakeups cannot address an old generation.

`reclaim_process` requires actual termination, exited threads, no running CPU and
zero frame charges in its dedicated Job. It removes only that process and its
exited thread records. The dedicated-Job restriction is conservative bringup
scope. `reclaim_job` additionally requires zero live usage, no retained processes
and no child Jobs. Neither operation restores consumed ancestor CPU ticks or
resets clocks, cursors, wait sequences or generation counters. These operations
certify metadata conditions; the hardware owner still proves physical teardown.

## Object identities and registries

An object's copied boot-local identity encodes its generation and slot. Initial
identities remain 0 through 15, preserving existing manifest measurements.
Backends compare the complete identity, so an old mailbox, mapping lease, Memory
Object or RPC route cannot attach itself to a newly allocated object in that slot.
Service registry rows validate the full tag before using its low slot bits.

`collect_dead_objects` collects only explicitly dead descriptors with no remaining
node references. Even unreachable nodes must first pass ordinary lineage
collection; escrow and ancestor pins remain effective. A crate-private retirement
operation can mark a known object's exact generation/kind dead only when no node
references it. It cannot invalidate a live or escaped grant, authorize a user
diagnostic ID, or retire physical backing.

The service controller closes retired authority domains once, pools their exact
old SpaceIds and uses `recycle_space` in a staged creation transaction. Failed
creation commits neither pooled-domain consumption nor generation changes.
Forgetting a retired process requires its actual scheduler identity, completed
metadata retirement, balanced frame charges and closed domains; all public and
escaped control references must be gone before its object can be collected.

## IPC lifetime

A stopped server's closed, drained logical endpoint may be rebound through the
retained owner's CONTROL and the replacement's exact RECEIVE/CONTROL grant.
The same mailbox escrow and monotonic Ticket sequence survive. A stale Ticket or
old receiver-domain generation cannot consume replacement work.

RPC thread/route rows are forgotten only after verified peer death and removal
of every retained direct execution reference, including cancelled work awaiting
acknowledgement. Causal origin Job references remain visible for higher-level
Job retirement. RPC epoch, call sequence and clock persist across service restarts.
Timeout ends a wait; it does not certify execution completion.

## Bounds and verification

Capability slots grow from eight to sixteen per domain for the Root plus multiple
service control/endpoint handles. Bootstrap manifests and service startup records
still permit at most eight declared grants. Other bounds remain explicit; no
increase substitutes for reclaiming a retired instance.

The development registry has one immutable, trusted finite service profile;
userspace template zero cannot change it. The ordinary profile remains 128 CPU
ticks. The sustained 64-replacement workload selects 2,048 CPU ticks, retaining the
same Job throughout and charging every replacement to its accumulated history.
Its first physical run exhausted 128 ticks after 62 replacements; the failed
evidence is retained. A subsequent two-CPU run exhausted the responsive peer's
256-tick allowance after56 replacements. The stress profile and its measured
parent CPU budget now match the proof's fixed2,048-tick global deadline, keeping
the test finite without making QEMU polling/preemption variation its quota gate.
Ordinary production-policy selection and blocking idle receives remain separate
work. The selected limits are part of the measured service
descriptor and must exactly match its Job. No quota is reset or refunded.

Owned private mapping metadata uses 68 sparse entries rather than 512 dense
entries while retaining all 512 hardware virtual leaves, including bootstrap509
and stack511. The 64-image-page admission bound plus bootstrap/stack leaves fits
this explicit owner bound; capacity failures retain the incoming frame. Retirement
returns frames in virtual-address order. Actual target layouts are 1,640 bytes
for UserMappings, 1,856 for UserRoot and 1,960 for LoadedImage, reducing stack
pressure without enlarging the boot stack or virtual window.

Host tests exercise repeated lifetimes beyond table capacities, continuously
dispatchable peers, stale IDs/handles/domains/waits/calls, escaped references,
generation exhaustion, failed staged reuse, CPU history and retained mailbox
sequences. Actual repeated CPL3 restart and full Root graph recovery remain
separate integration gates recorded in [M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).
