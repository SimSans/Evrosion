# ADR-0018 — Quiescent process retirement and escrow cleanup

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0014–0017, INV-KERN-003, INV-AUTH-003, INV-IPC-005

## Decision

Process retirement first rejects any process with a thread still running on any
CPU. This preflight leaves every sibling unchanged on failure. After hardware
contexts relinquish execution and the active user root is removed, a bounded
scheduler scan retires all ready/blocked siblings, clears wake state and prohibits
new threads in that process. Old wait tickets cannot resurrect retired threads.
Process and thread identities are retained and never recycled in this slice.

The trusted lifecycle owner closes the process capability space next. Local
handles become invalid and the domain cannot be reused. Closing is distinct
from revocation: grants already moved or delegated elsewhere stay valid under
their retained lineage. This preserves authority committed by successful IPC.
It does not change the meaning of an explicit ancestor revocation.

Receiver-death notification closes its endpoint. Accepted messages retain escrow
for living senders to reclaim. Messages from a dead sender can still be delivered
to a live receiver before their original deadline. If the receiver is closed or
the deadline expires and the sender is also dead, maintenance closes escrow
handles and discards the undeliverable message. Empty, closed mailboxes may retire
their private escrow domain. No cleanup recreates a capability or extends a
deadline. Stale/double reclamation fails. Maintenance is bounded by queue size.

The BSP user controller applies these operations after real user faults and
normal exits. Invalid return contexts use the same retirement path; a synthetic
vector-13 fault represents return validation failure. Pending receive state and
obsolete event registrations are removed. Two additional messages target the
process that will fault: the healthy peer reclaims one attenuated grant after
the fault, verifies its rights, rejects a repeated reclaim, and then exits.
The other message is discarded when both peers have died.

## Evidence boundaries

Host tests exercise multiple sibling states, a runner on another CPU, atomic
rejection, idempotence, stale wake tickets, closed-domain denial, retained
descendants, delivery from dead senders, expiry and both-peer escrow cleanup.
The hardware proof retires six actual CPL3 processes and verifies three returns
and three orphan discards across UD/PF/GP fault pairs. The AP remains parked;
remote stopping/IPIs and scheduler migration are not implemented by this proof.

Physical frames, capability object/node storage and process slots remain retained.
Their eventual reuse must follow mapping invalidation and quiescence. This is
not complete resource reclamation, a public process-control syscall, root
reconstitution or service supervision. Those limits remain visible in M1 status.
