# ADR-0041 — Mutex leases and IPC discipline

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: ADR-0037, ADR-0040; IPC_DISCIPLINE.md; INV-IPC-005

## Decision

Use an explicit capability-controlled Mutex object and actual ownership leases
to enforce NO_IPC_WAIT. The kernel records application mutex ownership and
releases internal access guards before returning to userspace. Trusted binding
selects an immutable lock class; userspace cannot provide a class or a flag
claiming whether a dangerous lock is held.

Kind tag6 permits CONTROL and ordinary derivation/transfer/revocation rights.
Acquire30 validates a live CONTROL cap, actual running registered thread/domain,
exclusive ownership, class order and lease-counter capacity before commit.
Rpc::enter_lock must succeed before the infallible owner installation. This is
a bounded try-acquire mechanism; it does not introduce a kernel wait under a
userspace mutex.

Release31 uses the returned monotonic lease serial and actual owning thread.
Transferring or revoking the original capability cannot strand its owner: release
reduces ownership and does not require reauthorization of that original handle.
Stale, foreign-thread or out-of-order release changes neither ownership nor the
protected RPC lock stack. Verified Scheduler/RPC death clears ownership and marks
abandonment; the next acquisition reports that fact without claiming data repair.
Object reuse never resets the lease sequence.

## Generated calls and thread layout

The discipline clients use the existing generated cap-free Echo contract.
Nonce-aware RECEIVE34 and REPLY33 identify actual received work. Reply requires
the actual serving thread, incoming RECEIVE/CONTROL endpoint and exact delivered
CallId serial, then completes only its protected wait. An outgoing request grant
does not substitute for a reply lease. Legacy calls preserve R10.

The finite development depth profile runs three isolated processes with three
real threads each, using eight request endpoints and existing metadata limits.
Each measured ELF includes two additional zero-filled RW/NX stack segments and
unmapped guard holes, within the existing eight-segment/64-page loader bounds.
The original guarded stack remains the primary thread's stack. Thread budget is
charged on actual creation after initial one-thread executable admission.

Spawn32 selects only a declared local role from the actual primary thread. The
controller chooses the measured entry, retained bootstrap and validated stack
top; no user PID, domain, entry or stack address is accepted. RDX local role and
RCX process index are Internal fixture entry metadata. Endpoint receiver binding
is checked against the actual thread even when roles share a process domain.

At depth eight, the ninth attempt targets the declared rank-one endpoint. The
protected depth guard rejects before ancestor/capacity checks; the fixture does
not claim a ninth independent service route. The separate three-process chain
tests ancestor rejection and parent-deadline extension independently.

## Verification and scope

Portable tests cover exclusivity, refusal atomicity, cap transfer/revocation,
lease/order exhaustion, verified-death poisoning and stale object/thread/lease
generations. Actual source-built clients must hold the real mutex, observe
generated RPC denial, release it, and successfully forward A→B→C. The deeper
fixture must execute all eight edges through real scheduling and protected waits.
Hardware and cumulative results belong in M2 progress.
This record does not certify those pending executions or general thread creation.
