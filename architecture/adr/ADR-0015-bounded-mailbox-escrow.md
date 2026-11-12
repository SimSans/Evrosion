# ADR-0015 — Bounded mailbox and capability escrow

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-008, E-009, IPC_DISCIPLINE §18, ADR-0014

## Decision

Introduce an Internal asynchronous mailbox with four message slots, 64 payload
bytes per message and at most one moved capability. A trusted kernel binding
associates one endpoint descriptor with its receiver and private escrow space.
The future object registry must enforce unique descriptor-to-mailbox binding;
all operations use the same Authority instance. This is not a public IPC ABI.

SEND/RECEIVE authorization must match the bound descriptor. The trusted caller
supplies sender/receiver identity and monotonic time; identities/times are not
accepted directly from userspace. Payloads are bounded slices, not user pointers.
A successful send moves capability authority into escrow and commits the queue
entry together. All validation, bounds and sequence checks happen before that
move; no fallible work follows it. Failed sends retain the source handle.
Delivery moves escrow authority to the receiver before removing the message.
A full receiver table leaves the message and escrow intact for retry.

Every message has an absolute finite deadline. Expired messages are not delivered
and cannot extend their deadline on retry. FIFO selection uses nonwrapping ticket
numbers; a full queue returns immediately. No operation waits or holds a lock
across a context switch. One mutable kernel owner serializes queue and authority
mutation. A rejected operation may advance observed time but cannot partially
change a message or capability transaction.

## Receiver death and timeout

A trusted receiver-death notification closes the mailbox. Original senders may
reclaim their undelivered escrow grants after closure or expiry. A full sender
table retains the escrow message until that sender frees a slot and retries.
An ancestor revocation or object death prevents delivery and reclamation reports
invalidation rather than recreating revoked authority. Already delivered messages
cannot be reclaimed; timeout never proves that earlier work did not execute.
Sender identity and ticket are checked before returning any authority.

The bootstrap mailbox and escrow are retained. Automatic cleanup when both peers
die, descriptor uniqueness, budget charges and physical object teardown belong
to process-lifetime integration. A simulated death notification does not prove
survival/restart of a real userspace process.

## Verification and remaining scope

Host tests cover unique escrow/delivery, FIFO retry, queue and payload bounds,
expired sends, full receiver/sender tables, denied transfer, revocation in escrow,
wrong owner/endpoint, stale tickets, time reversal and sequence exhaustion.
QEMU executes bounded delivery, full-queue atomicity, exact expiry and death-return
checks on the BSP. Scope is mailbox mechanisms. Scheduled-user IPC, wait/wake
integration, total syscall/wire decoding, synchronous ancestry/depth rules,
shared-memory bulk transfer and general fault delivery remain required later.
