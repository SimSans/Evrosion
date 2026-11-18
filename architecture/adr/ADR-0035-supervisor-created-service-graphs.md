# ADR-0035 — Supervisor created service graphs

Status: Accepted
Date: 2026-10-26
Owners: Project owner; kernel/platform maintainers
Related: ADR-0014, ADR-0015, ADR-0021, ADR-0030–0034; E-025.25–33

## Decision

The Root Supervisor creates bounded child Jobs, processes and endpoints through
explicit capabilities, delegates the measured service's declared roles, and starts
its retained executable only after complete admission checks. The first service
is a separate Rust Echo program using generated `ev.test.echo@1` messages.

This Level B refinement implements the existing service graph direction. It adds
creation ancestry across object kinds and keeps ordinary same-object derivation
and attenuation unchanged. It changes no foundation, Stable contract, milestone
exit criterion or historical acceptance evidence.

## Creation authority and ancestry

The development Root manifest adds Job CONTROL and READ on the measured Echo
image object. A selector or scheduler diagnostic ID is never a creation grant.
The kernel resolves an authorized object's identity through its retained registry
to the actual Job or immutable service descriptor.

`Authority::create_managed` requires live Job CONTROL and supports only Job,
Process and Endpoint creation. The new object's first grant remains in the
creator's domain and descends from the exact creator node. This is object
creation, with kind-specific rights and resource admission; it does not amplify
an existing object's grant or expose physical memory allocation. Cross-domain
delegation still requires DERIVE and TRANSFER, and rights attenuate normally.

Revoking an incarnation's Job branch therefore reaches objects subsequently
created through it, including delegated and transferred descendants. Destroying
an ancestor object also invalidates descendants: authorization now checks every
ancestor's object liveness as well as node liveness. Permanent custody roots and
unrelated branches remain intact.

The bounded bringup tables grow to 16 domains, 16 object descriptors and 64
lineage nodes. Each domain still has eight capability slots. These are explicit
capacity limits, with visible failure; scheduler and object descriptors remain
retained. They do not establish indefinite restart lifetime or permanent product
limits. Temporary creation handles can be closed without ending kernel ownership.

## Transactions and child admission

The portable service registry binds actual object identities to scheduler Jobs,
measured executable descriptors and managed process records. A descriptor binds
exact image bytes, shared startup ABI, finite limits and ordered typed roles.
Child authority identities are measured at admission because newly created
objects vary by instance; Root's fixed custody manifest retains its original
measurement semantics.

Creation stages private fixed metadata copies of Authority and Scheduler and
commits only after every check succeeds. No hardware backing is copied. Job
limits, descriptor capacity, capability slots, domain allocation, frame charges
and initial process/thread allocation cannot partially commit on failure.
Endpoint and mailbox escrow creation likewise form one transaction.

Each child begins held, with its own Job, authority domain and private revocation
branches. Delegation installs exactly the descriptor's roles. Initial admission
revalidates original image access, exact live role/source ancestry, complete
domain contents, immutable descriptor measurements, actual loaded root/entry/
stack/frame count, and the startup record's address/length/digest. Scheduler
release remains crate-private. Rejection preserves the loaded owner and hold.

The hardware controller retains backing in fixed slots and moves small exclusive
`ProcessImage` leases through admission and stop. Moving whole page-table owners
through result values caused stack exhaustion during initial integration; the
lease design removes those copies while preserving the existing stack guard.

## Messages and ordinary service failure

The IDL schema produces shared Rust request/response codecs and defensive client/
server stubs. The eight-byte Echo body carries magic, version, operation and a
little-endian u32. Async queues admit at most four messages with finite absolute
deadlines and zero transferred capabilities. A separate synchronous client and
protected causal-call implementation are prepared; actual synchronous dispatch
acceptance is a later integration gate.

The runtime derives caller identity from the dispatched process, checks the live
endpoint capability and keeps one receiver binding per mailbox. During held
setup, receive ownership can move only with both exact RECEIVE/CONTROL grants
and an empty queue. Malformed or premature lifecycle events are rejected before
queue acceptance. Root and Echo use one shared entry/scalar-syscall runtime,
including the explicit RSI/RDX reply outputs.

Ordinary child exit or user fault inhibits that child, revokes its private grants,
retires its scheduler state and leaves Root running to observe termination.
Already accepted responses remain available to their live receiver. The router
retains the actual sender and acceptance Ticket for each cap-free queued message;
receiver death reclaims pending work without pretending it executed. This keeps
bounded message bookkeeping balanced even if the sender is still alive.

Backing remains retained until scheduler retirement, original CR3 restoration,
parked APs, drained/closed IPC and ended image leases. Physical retirement scrubs
and returns frames before charges are balanced. Trusted metadata cleanup uses
the retained actual ProcessId, so closing a public control handle cannot strand
teardown. Closing a handle does not itself terminate a process or certify
quiescence.

## Acceptance and next scope

Host tests cover creator/ancestor revocation and destruction, late failure
atomicity, descriptor/role/measurement validation, exact held admission, escaped
grants, closed public handles and mailbox receive handoff. Generated decoders and
producers have malformed-input and consistency tests. The current integration
loads separate Rust Root/Echo images, performs typed exchanges and rejects excess
authority. A distinct fault artifact writes the unmapped zero page after replying;
Root observes the actual termination, and pending cap-free work is reclaimed.
Executed results are linked from M2 progress.

These graphs execute on the BSP with parked APs and PCID off. They are separate
development fixtures, not replacement incarnations. Multiple unrelated services,
ordinary restart, reusable descriptors, full synchronous transport/AF-IPC,
production epoch/generation trust, sealed BAC graph reconstruction and AF-007A–H
remain M2 work. The Internal scalar creation profile currently admits one child
per graph and one fixed finite child budget template.
