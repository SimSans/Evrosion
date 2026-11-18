# ADR-0121 — Captured session power and terminal diagnostics

Status: Accepted Internal Level B mechanism; actual shutdown qualification pending.
Date: 2026-11-16
Related: ADR-0112/0119/0120; INV-AUTH-001/002/005, INV-IPC-005,
INV-LIFE-002/005; M8-08/10/12/13.

Selected-platform extension: [ADR-0124](ADR-0124-checked-reference-restart.md)
adds explicitly negotiated checked reference restart. Query0/shutdown and
this ADR's authority, cut, physical proof and diagnostic guarantees retain
their original behavior. The shutdown-only wording below records this ADR's
initial boundary; no actual restart PASS follows from the extension.

## Problem and selected boundary

A generic Root EXIT previously ended the selected V5 executor with physical
owners retained. It remains a failure, never a clean shutdown. Normal STOP37
refuses active Block and NIC owners because stopping a CPU does not prove a
device idle. File61 proves an exact selected branch/loan retirement, not ATA
flush or NIC STOP. A graphical power label cannot substitute for those facts.

The actual 1 MiB component also exhausted the inherited serial quota partway
through periodic sample404040. Saved and independent exact cold revision3 are
recorded separately; no complete600-second diagnostic history is inferred.
Terminal evidence must remain available during the required sustained session.

## Captured power fence

Add negotiated INFO66 and CONTROL67 only to the selected M8 reference. INFO
advertises shutdown only. Restart remains explicitly Unsupported and required
future M8-10 work, not a smaller redefinition of that gate. Bootstrap ABIs and
all existing calls retain their identities and behavior.

CONTROL67 takes operation, actual held Block CONTROL, actual held NIC CONTROL
and extra. BEGIN0 uses extra as the original finite absolute cut (at most8192
ticks remaining). The executor validates the actual running Root through the
existing custodian-token/domain/job/scheduler Context proof, both full held
process objects and their exact admitted roles. All other admitted actors,
including Input and Display, must have exited. Canonical RPC outstanding work,
window records, mailbox entries/accepted ledgers and selected branch debt must
all be empty or actually drained. Numbers and a caller's asserted PID prove
none of this.

The one-use latch freezes before the first device CPU/grant effect. It then
stops actual Block/NIC CPUs, retaining their source, port and image owners.
This is exclusion, not a physical device receipt. Partial failure is sticky;
no new BEGIN, new cut, image replacement, ordinary RPC or mapping reuse can
clear it. Frozen Root may only use monotonic/yield, the narrow power operation
and its independently held bounded PIO rights under the same cut.

The trusted userspace Root performs actual ATA FLUSH with fresh idle/error
checks and NE2000 STOP plus16KiB scrub/readback through existing device helpers.
COMPLETE2 supplies the same actual pair and token1 before the original cut.
The Kernel rechecks full actual CPU/work/credit exclusion. Physical proof
remains attributable to the exact trusted Root source, as with existing scoped
network retirement; the latch is not hardware attestation. The selected QEMU
platform then emits a distinct checked-shutdown result and performs its debug
power exit. No successful return resumes Root, and generic EXIT is unchanged.
There is no physical-machine or general Kernel/Root replacement claim.

All67 replies, including malformed and denied requests, clear capability and
fourth-operand/serial outputs. A preflight caught preserved input R10 being
mistaken for a reply serial; explicit reply helper/ABI tests cover it.

## Complete diagnostic retention

Reuse the existing allocation-free sustained-session Retention/Measure types
for periodic V5 resource records. Measure complete CRLF byte cost first; retain
at most384KiB of ordinary complete observations, emit one explicit omission
boundary, and reserve64KiB for terminal ownership/debt snapshots and summary.
No partial resource line is emitted at the retention boundary. Omission counts
and bytes remain explicit; legitimate work continues after prefix closure.
This leaves the existing512KiB COM1 budget and4MiB host capture bound unchanged.
Other profiles retain their original observer behavior and accepted proofs.

## Required evidence

Strict decode/reserved/handle/output tests, captured-Root/foreign-control/debt
refusal, sticky cut/partial-failure cases and unchanged old-call regressions;
actual Root/Kernel linked image/guard/stack preflight; graphical confirmation,
dirty/uncertain/queued-input refusal and cancellation; real Workspace seal and
flush, actual device exclusion/FLUSH/STOP/scrub, checked platform exit and exact
independent cold bytes. Exercise retained terminal logging past prefix closure.
Restart, independent recovery, affected-service faults, complete accessible
confirmation and the30-minute session remain separate required qualification.
