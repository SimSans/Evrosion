# ADR-0068 — Sustained-session diagnostic retention

Status: Accepted mechanism; linked and long-session runtime validation pending

Date: 2026-11-12

Decision level: B

## Context

Finite smoke profiles deliberately stop when their evidence budget is exhausted.
A sustained interactive OS cannot terminate after a fixed lifetime number of
keystrokes, Job queries, crashes or serial bytes. Nor may it allocate unlimited
logs or describe a sampled prefix as a complete process history.

## Decision

Under the separate M6 sustained profile, retain384KiB of complete diagnostic
observations and a64KiB reserve for fixed final memory/identity/UI totals and the
successful final finish state. Existing Native serial capacity stays512KiB;
the remaining64KiB covers boot and retirement. The host capture remains1MiB.
Existing finite profiles keep their original fail-on-budget proof semantics.

Measure a complete observation's actual COM1 byte cost, including LF-to-CRLF
conversion, before emitting it. A counting formatter avoids a new stack log
buffer or heap. Each observation remains bounded to8192bytes. Formatting and
ordinary output still have finite work limits; serial hardware failure and
impossible fixed-final accounting are internal failures, not silently accepted
I/O. The actual linked stack census remains mandatory after this change.

Once the next ordinary observation cannot fit, close the retained prefix once
and emit `EVROSION_M6_LOG_BOUND`. Omit whole later ordinary observations, with
checked cumulative record and byte counts. Do not resume a broken history when
a smaller record happens to fit. Fixed final ownership facts use their separate
reserve. Emit `EVROSION_M6_LOG` before Native completion, recording retained and
omitted totals. No diagnostic counter resets scheduler, CPU, memory, endpoint,
Store or operation-deadline state.

The session-only host parser validates the boundary, totals, ordering and
complete final facts. Retained actions still obey exact incarnation ordering;
an omitted suffix explicitly sets `history_complete=false`. Final cumulative
accounting must remain balanced, while a partial prefix cannot prove every
unrecorded lifecycle transition. Scripted conformance refuses any omitted
observation. The finite parser retains its original limits and rejects these
session records. Session parsing removes old demonstration lifetime caps without
removing canonical number, image, identity, fault, frame or counter checks.

Source-side input counters remain checked and cumulative; only the M6 lifetime
4096-byte cutoff is removed. Per-operation owner response deadlines and health
windows remain finite. The two volatile crash slots may roll only after prior
diagnostic framing has completed, preserving active output and rejecting
duplicates. This is bounded recent history, not a promise of durable archival.
Root's bounded outbox separately tracks queued, accepted, settled and failed
control messages; enqueue does not establish delivery or loan reclamation.
Each peer has eight output slots and an exact actual control/PID/TID target.
Pre-accept controls retain their original 512-tick cut. The first observed
successful SEND captures one separate 4096-tick UI settlement cut for every applied control
except deliberate CrashShell; Busy cannot renew either cut.
Root drains matching authenticated Shell acknowledgements against the exact
front control and actual Shell identity before testing that cut and does not start synchronous Store/owner work while it awaits settlement.
The4096tick value is initial bounded policy pending actual runtime measurement.
The scalar SEND ABI carries no caller deadline or acceptance timestamp. Source
cuts gate attempts before the syscall; preemption may cross a cut before Kernel
admission. A real success is consumed once even then. These are finite source
attempt/settlement policies, not atomic Kernel acceptance deadlines. Canonical
RPC deadlines and shared-loan custody remain separately enforced by the Kernel.
A failed Shell scope remains degraded until actual stop/replacement: this fixed
internal ACK protocol has no invented per-message nonce, so an expired ACK cannot
repair degraded health or establish a later same-valued control as complete.

Deferred ingress has eight slots, with at most four App items. Matching Shell
acknowledgements bypass capacity-blocked App work. Other deferred Shell commands
retain the receipt-time App identity, epochs, picker and readiness context plus
a checked UI revision advanced only by actual Shell control SEND acceptance;
a changed context refuses that old input rather than redirecting it to a new
App. When App ingress is exhausted, Root retains the first request and exact
old identity, fences new source work, then attempts existing CONTROL inhibition
and stop on ordinary ticks. Busy retains actual child/loan reservations. Only
actual stop/reap cancels that incarnation's queued requests and retained reply
body. This is overload quarantine, not successful request delivery. Foundation
tests cover peer ordering, capacity, old-incarnation cancellation, unchanged
retry cuts and retained failed Note replies; actual flood containment remains
a runtime acceptance requirement.

## Validation and remaining work

The exact allocation-free retention policy has host tests for more than10000
post-cap observations, whole-record omission, preserved final reserve, CRLF
counting and atomic invalid-accounting rejection. Host parser tests use clearly
marked transformed historical output to check complete versus partial history,
malformed bounds, replay, and session lifetime beyond finite proof caps. They
do not claim those operations ran in a VM.

The joined actual Kernel target check passes. Strict checks, a source-pinned
linked stack census, a guest session beyond the old lifetime caps, competing
abuse containment and clean resource retirement remain required before M6-02
acceptance. The Root outbox source adapter has focused strict target checks and foundation
tests. Its joined linked-stack/VM proof remains pending; bounded expiry alone
does not guarantee delivery through arbitrarily many consecutive operations.
