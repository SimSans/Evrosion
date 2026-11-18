# ADR-0116 — Selected fixed-sector PIO over captured private RAM

Status: selected M8 mechanism implemented; actual linked and guest qualification pending.
Date: 2026-11-16
Related: ADR-0108/0109/0111; WORKSPACE_STORAGE; M8 normal-save and failure/recovery gates.

## Measured trigger and bounded addition

`PIO-01`: The original tiny-save guest run completed exactly304 Block requests
through durable Commit for15 bytes, leaving99 ticks before its original8192-tick
File operation cut and attempting none of the nine readback requests. The Editor
reported Recovery required. Independent cold decoding found revision2 and exact
bytes; this proves durable Commit, not Saved. Removing redundant unchanged-Saving
repaints alone still reached a final flush across the original cut and retained
the timed-out call/owners. Both failed artifacts remain under B8. No deadline,
cumulative CPU charge, scheduler quota, stack allowance or legacy format changes
follow from this mechanism. The backend's exact1MiB path still entails11533 Block
requests including readback; fewer traps are not proof that it meets8192 ticks.

`PIO-02`: Additive selected calls are INPUT63, OUTPUT64 and INFO65. INFO takes
four zero operands and reports `0x0000000101000002`. Data calls take held
IoPorts capability, same width2 port, original finite absolute cut and private
512-byte virtual address. Count256 and little-endian Word width are fixed;
no packet chooses width/count, Process, mapping, quota or disk partition.
Byte alignment is sufficient. The public description SHA is
`2b6049dc7dbb58261938d1452e40c6002508429edb7749bb43bebc5e7a6cec1d`.
Every data reply clears value/capability/serial. Older runtimes refuse the new
operations; selected Block negotiates before reset, IDENTIFY or other device I/O.

## Independent authority and RAM joins

`PIO-03`: Only the actual selected V5 Block actor with an admitted Running image
may enter this path. Its retained image metadata must match the captured
Process/Thread/Job/domain and actual Scheduler Running(0). The existing IoPorts
registry independently resolves the actual running thread's registered RPC
domain, full-generation held capability, immutable resource binding, range,
Word width and direction. It checks a future finite cut no further than the
existing1024-tick batch maximum. A buffer address supplies no port authority.
The actual live authority and resource binding remain borrowed across every
port operation. Revocation, wrong local rights/domain, stale bindings, stopped
thread, wrong range and an expired or renewed-too-far cut refuse before I/O.

`PIO-04`: Kernel joins the complete checked512-byte virtual span with at most
two affine private RAM claims of this exact captured physical image. Every
page must be privately owned RW/NX user RAM. Actual PML4/PDPT0/PD0 entries must
point to the same retained private table chain, excluding detached/rebound or
large-page paths. Actual retained leaf PTEs must
equal that claim's physical frame and flags, allowing only hardware A/D changes.
Both pages and direct-map addresses are checked before copy or device effects.
Shared Surface/File/Block windows, bootstrap, code, MMIO, guard/unmapped pages,
foreign windows, arithmetic overflow and a mismatching second page refuse.
A legitimate private RW/NX stack page is allowed by ownership and permissions;
numeric VA labels do not substitute for this proof. Current controller CR3,
IF0, PCID/LA57 exclusion and retained image claims are read back at capture;
the sole BSP executor retains AP exclusion and pins owners for the call.

`PIO-05`: A fixed aligned512-byte Kernel scratch area avoids casting an
unaligned user address to u16. Output snapshots all private source bytes before
the first OUT. Input completes all256 IN instructions into scratch before
publishing any byte to the private destination. Byte copies use exact borrowed
RAM frames and checked offsets. A post-IN unexpected hardware/access failure
retains owners fatally; it cannot become a pre-effect denial or reusable loan.
The HAL uses the same portable fixed256-word transfer core as model tests,
retaining its non-forgeable borrowed port permit throughout. No DMA, new mapping,
allocation, device command policy, retry, interrupt enable or partition lookup
is added to the privileged path.

## Userspace device policy, preservation and evidence

`PIO-06`: New Block feature `pio-words256` includes `workspace-driver`. Only
the exact `AtaPio<_,1>` workspace identity profile uses fixed-sector transfers;
the original `AtaPio<_,0>` path retains scalar/Word4 behavior even with this
feature enabled. A sector reserves the original256 poll/work units once and
uses one clock observation to clamp the authorization cut against the original
ATA/RPC deadline. All original command, identity, exact96MiB geometry, extent,
status, flush, reset/quarantine and uncertain-prefix rules remain unchanged.
The new adapter does not fall back to an old Kernel after failed negotiation.

`PIO-07`: Portable tests exercise real allocator-owned frame claims, actual PTE
decode, noncontiguous physical backing across an unaligned two-page span,
permission/foreign/overflow/second-page denial, retained ownership on access
failure, full fixed-count endian transfers and live range/rights/revocation/
Scheduler checks. ATA model tests run the actual state machine through
IDENTIFY/write/flush/readback, original work/cut clamps and partial-input/output
errors without replay. These are host mechanism/model tests, not guest PIO
acceptance. The new-feature native Block also requires12 canonical denial
probes for invalid private spans/cap/range/cut before any ATA command. Actual
Block READY and denial metrics are needed to establish those probes ran.

`PIO-08`: Each resource sample records successful input/output counts, denial
count, raw serialized TSC total/max for the actual IF0 fixed port loop, and a
separate preflight/copy/loop handler interval. The latter excludes outer syscall
entry/dispatch and the final accounting/return tail. TSC values are not
nanoseconds or Scheduler charges. IRQ charging remains captured-user-IRQ only;
256 IF0 operations may coalesce PIT delivery. Qualification must retain actual
linked full-entry stack census, source/artifact joins, guest denial results,
original-cut save/readback result, raw masking metrics and aligned host elapsed
versus guest ticks/IRQ charges. No throughput, latency, full1MiB save,30-minute
stability or unchanged timer-delivery claim follows from compilation alone.

The old Word4/Byte4 ABI and all V1–V4 factories, original saved volumes and exact
96MiB workspace disk identity remain distinct and unchanged. Timely service
fallback, device death/timeout, independent cold recovery and managed route
retirement remain required M8 work; Kernel owner retention is not their PASS.
