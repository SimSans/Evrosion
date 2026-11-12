# IPC reentrancy and deadlock discipline

Extracted from the [Pre-M0 implementation package](../plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This is a public technical edition of the canonical record. Published source
hashes and original lineage are recorded in the architecture source map.

Status: Verified for the bounded Internal M2 profile: AF-IPC-001–010 pass the
[accepted cumulative gate](../M2_ACCEPTANCE.md). Actual mutex/forwarding/depth
worlds and explicit READ_ONLY timeout replay are included. Side-effecting durable
operation IDs remain required before such methods; general mutating exactly-once
execution is not claimed.
Maturity: Internal. Related action: A-012.

## 16. Decision summary

Evrosion supports bounded synchronous control RPC because it makes small control interactions understandable and efficient. Synchronous calls may form a forward chain, but reentrant callbacks into an ancestor are forbidden. A thread blocked on a synchronous reply does not dispatch unrelated requests.

Asynchronous messages and shared-memory rings are the default for events, streaming, fan-out, high-latency work and any operation likely to call back.

## 17. Message modes

| Mode | Use | Blocking | Payload |
|---|---|---|---|
| Sync RPC | Small, bounded control query/command | Caller waits | Small typed message + limited capability transfer |
| Async channel | Events, work submission, callbacks, fan-out | No mandatory wait | Bounded typed message |
| Shared ring | High-rate streams | Producer/consumer backpressure | Fixed descriptors, not large copies |
| Memory Object | Bulk data | Mapping-dependent | Pages/regions under explicit capability |

## 18. Mandatory rules

1. **No synchronous RPC while holding a dangerous lock.** Dangerous includes global locks, capability-table write locks, address-space locks, scheduler locks, allocator locks, device state locks, filesystem transaction locks and any lock whose owner may need IPC progress.
2. **No synchronous callback into an ancestor.** If A synchronously calls B and B needs A, B must use an asynchronous response path, a pre-supplied data object, or return a continuation request.
3. **Forward nesting is bounded.** Initial maximum synchronous depth is 8. The limit is explicit protocol failure, not stack exhaustion.
4. **One blocked request, one wait edge.** A blocked thread cannot secretly service other sync requests.
5. **All waits have an absolute monotonic deadline.** `NO_DEADLINE` is prohibited across protection-domain boundaries except in early boot code covered by an exception.
6. **Cancellation is cooperative and explicit.** A timeout/cancel stops the caller waiting; it does not prove the callee never executed.
7. **Queues are bounded.** Each endpoint declares message count, byte and capability-transfer limits.
8. **Backpressure is visible.** Full queues return `WOULD_BLOCK`, `OVERLOADED` or wait only within the caller's deadline.
9. **Capability transfer is transactional with message acceptance.** A rejected message cannot strand or duplicate transferred authority.
10. **Protocol decoding is total and defensive.** Unknown fields follow declared version rules; malformed inputs fail without partial side effects.

## 19. Causal call context

Every cross-domain sync call carries kernel-protected metadata:

```text
trace_id              random/monotonic boot-unique identifier
call_id               unique within trace
parent_call_id        previous edge, if any
origin_job_id         stable boot-local origin
current_depth         bounded integer
absolute_deadline     monotonic timestamp
cancellation_token    revocable wait context
root_incarnation      if bootstrap-managed
```

Userspace may read appropriate diagnostic fields but cannot forge kernel causal ancestry.

The deadline may only stay the same or become earlier as a call moves forward.

## 20. Reentrancy model

The initial platform contract is **non-reentrant synchronous endpoints**:

- An endpoint handler processes one request according to its declared concurrency policy.
- A handler may call a lower-level service synchronously if it holds no forbidden lock and preserves the causal context.
- The lower service may not synchronously call any ancestor in the active chain.
- Notifications and callbacks use a separate asynchronous endpoint.
- If a protocol truly needs reentrancy later, it requires an explicit contract annotation, proof of state safety and an ADR. It is not the default.

## 21. Lock discipline

Kernel and system services maintain a lock-class registry with numeric ranks.

Rules:

- acquire locks in increasing rank order;
- never acquire an equal/lower rank while holding a higher rank unless the same lock's documented primitive permits it;
- no IPC wait while holding a lock marked `NO_IPC_WAIT`;
- no page fault or allocation capable of external pager/service IPC while holding pager-critical locks;
- interrupt context never performs blocking IPC;
- real-time media paths never perform blocking IPC or allocation;
- lock guards are dropped before generated client stubs can issue sync RPC.

Development builds track held lock classes per thread and trap violations at the call boundary.

## 22. Cycle detection

### Development builds

The kernel maintains a bounded wait-for graph for live synchronous calls:

```text
caller thread → callee endpoint/servicing thread
```

Before committing a wait edge, bounded cycle detection checks whether the edge reaches an ancestor. If yes, the call fails with `DEADLOCK_DETECTED`, records the causal chain and optionally traps under the test profile.

### Production builds

Production retains:

- depth limits;
- ancestor identity tokens;
- deadlines;
- lock assertions where cheap;
- bounded queues;
- structured deadlock/timeout diagnostics.

The full graph may be disabled or sampled if measurement shows unacceptable cost. Semantics do not change.

## 23. Timeouts, cancellation and retries

Canonical statuses:

```text
OK
WOULD_BLOCK
OVERLOADED
DEADLINE_EXCEEDED
CANCELLED
DEADLOCK_DETECTED
PEER_DIED
MALFORMED_MESSAGE
VERSION_MISMATCH
PERMISSION_DENIED
```

Rules:

- A deadline expiry ends the wait and requests cancellation.
- The callee checks cancellation at defined safe points.
- Side-effecting requests include a caller-generated idempotency key when retry is permitted.
- Protocol documentation declares each operation `READ_ONLY`, `IDEMPOTENT`, `AT_MOST_ONCE_WITHIN_PEER_LIFETIME`, or `NON_RETRYABLE`.
- Cross-crash exactly-once execution is not promised. Durable operations use transactional state plus durable operation IDs.

## 24. Queue policy

Every endpoint declares:

```text
max_messages
max_bytes
max_capabilities_per_message
overflow_behavior
priority/fairness class
```

Memory charged for queued messages is attributed to the sender's Job until accepted, then to the receiver according to contract. A low-authority sender cannot exhaust unbounded receiver memory.

## 25. Required tests

- **AF-IPC-001:** Generated client attempts sync RPC while holding `NO_IPC_WAIT` lock; development kernel rejects it.
- **AF-IPC-002:** A→B→C succeeds within depth and deadline.
- **AF-IPC-003:** C→A synchronous callback is rejected as a cycle.
- **AF-IPC-004:** Depth 9 is rejected when maximum is 8.
- **AF-IPC-005:** Descendant deadline cannot exceed parent deadline.
- **AF-IPC-006:** Full queue produces explicit backpressure without memory growth.
- **AF-IPC-007:** Timeout followed by retry cannot duplicate an idempotent operation.
- **AF-IPC-008:** Malformed length/capability count is rejected before side effects.
- **AF-IPC-009:** Receiver death returns transferred capabilities according to declared transactional semantics; no duplicate live handle exists.
- **AF-IPC-010:** Fuzzed message decoder never panics, escapes bounds or partially commits invalid input.
