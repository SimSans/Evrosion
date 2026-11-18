# ADR-0073 — Async maintenance at each captured timer tick

Status: Accepted bounded executor refinement; guest performance qualification pending

Date: 2026-11-12

Decision level: B

## Context

The session executor runs global queued-message expiry before every user
resume. A ready ATA sector read needs at least 543 scalar syscalls, including
256 data-port reads and 256 monotonic checks. Repeating global queue scans for
every port instruction adds work to an otherwise unchanged storage actor.

The actual controlled09 guest isolates an earlier empty-mailbox preflight
change. All 77 retained supervisor ELF/Zion files match08c byte-for-byte.
Initial30 Root-to-Block reads improve from median38 to31 charged CPU ticks;
wall-time median improves from228 to124.5 ticks. The unchanged8,192-tick GUI
install still expires during Registry blank inspection, before any Registry
write. This is an improvement, not successful installation or session proof.

## Decision and safety argument

Run global Async expiry once at each newly captured Kernel timer tick. Memoize
only the tick of a fully successful canonical scan, including its observations.
Use an initially absent value so tick0 cannot accidentally skip the first scan.
Repeated exact ticks may skip this maintenance; clock regression fails closed
without lowering the memo. An unsuccessful scan never establishes coverage.

All queue mutation is serialized by the sole captured-CPU controller. Canonical
Mailbox SEND refuses an incoming deadline at or before its actual capture tick.
Consequently, a newly accepted message after a successful scan at tickT has a
deadline strictly afterT and cannot introduce already-due Async work duringT.
Receive, withdrawal, reclaim and close remove debt; fresh/reused mailboxes are
empty. The memo records completed maintenance, never message ownership or credit.

Keep the real RECEIVE boundary's independent expiry check at its actual captured
tick: user execution may cross a cut after the executor's previous scan. Keep
canonical RPC outcomes, peer death, guarded cancellation and descendant drain
on every capture. Capability escrow and Selected delivery retain their existing
owners. This refinement changes no deadline, CPU quota, transaction allowance,
accepted-send identity, shared-memory loan or actual quiescence requirement.

## Validation and limits

The exact Wire implementation is hosted against real Authority/Mailbox owners.
A new regression proves that same-tick sends with past/equal deadlines refuse
without consuming credit; a future send remains queued, then actual RECEIVE at
its cut expires only that new ticket; a regressed clock cannot insert a message.
All434 portable Core tests and strict network/session/finite Native/desktop
target checks pass. Independent reviews confirmed the same-tick argument.

Controlled10 will apply only this executor refinement to the frozen09 source,
retaining unchanged actors, original driver deadline and finite budgets. Actual
latency, install completion, activation and the full interactive session remain
separate measured obligations. The independent GUI activation correction is
deliberately excluded from that causal comparison.

Both experiment receipts are retained in the local engineering archive.
