# ADR-0043 — Bounded shared-buffer block transport

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: ADR-0033, ADR-0037, ADR-0042; E-008; E-010; INV-IPC-005

## Decision

Separate the first userspace block driver from its storage client. Use existing
protected synchronous RPC for an eight-byte generated backend envelope and one
prebound Memory Object for a 512-byte sector. Keep ATA commands and device bounds
in the driver. This is an Internal backend interface, not the application's
File/Object API. The kernel validates wire syntax and actual endpoint authority;
it accepts no user pointer, sector permission or ATA command as kernel policy.

The driver receives exact IoPorts READ/WRITE, Memory READ/WRITE/MAP and incoming
Endpoint RECEIVE/CONTROL roles. The client receives Memory READ/WRITE/MAP and
outgoing Endpoint SEND. The client gets no raw port, mapping-control, derivation,
transfer or thread-creation authority. Both actual Jobs admit one thread.
The kernel still independently denies attempts outside those capabilities.

## Mapping and retained ownership

Map the same initialized backing page at the otherwise vacant user page508,
before each owned executable is admitted. Private code, bootstrap509, guards and
stack511 cannot be changed through this API. Parent Job accounting retains the
single shared frame; child Jobs retain their exact private executable charges.
Mapping a shared page does not manufacture a second physical-frame allocation.

LoadedRoot exposes only narrow inactive map/validate/unmap operations. A rejected
map returns its original non-Clone MappingLease. Validation checks actual CR3,
the exact live Memory Object/lease and vacant mapping before PTE mutation.
Running keeps the unique executable borrow and exposes only a shared image
reference; no DerefMut or interior mutation bypass is introduced. Mutation is
available before admission or after finish returns the stopped image owner.

After both actual processes stop, return both mapping claims before destroying
the Memory Object. Scrub/read back the sole returned frame and release its parent
charge. Retire private images and their separate charges independently. Revoked
or closed role handles cannot strand cleanup: reducing ownership uses retained
actual identities and leases. A balanced counter alone is not quiescence.

## Buffer lifetime and deadlines

The first finite hardware fixture excludes admitted timeout/cancellation. It
rejects a call deadline at or before its fixed controller-stop deadline, before
RPC reservation, mailbox acceptance or Scheduler wait mutation. The controller
checks that stop bound before every dispatch and completion. Every accepted
deadline remains future on every successful redispatch. No Spawn/cancellation or
additional client mapping is admitted; the one actual client thread blocks until
a real protected reply or verified stopped-driver death.

Generic Rpc timeout semantics stay unchanged. This scoped fixture is not general
timeout-safe shared-memory transport. A general caller may become runnable after
timeout while delivered execution continues; call metadata alone cannot prevent
writes through a surviving RW mapping. General cancellation therefore requires
actual buffer ownership transfer/invalidation or another enforced lifetime
mechanism before client redispatch. It must receive separate evidence.

The driver copies writes to private 512-byte storage before issuing the ATA
command. Reads complete into private storage before publishing shared bytes and
replying. One nonce-bound reservation correlates actual receive, response and
WaitTicket wake. Legacy RPC22/clock/yield preserve R10; receive34/reply33 and
ports35/36 use the declared four-output ABI.

## Verification and limits

The write fixture deliberately poisons the shared sector after the measured
driver's private-copy checkpoint while the actual client remains blocked. Real
disk readback must still match the original record. This is a development-only
adversarial hook, not authority granted to applications. The page's remaining
guard bytes must stay zero. The read-only phase exercises its private read path.

Additional proofs require near-deadline and malformed preflight refusals with
unchanged buffers/queues/reservations, denied client port access, actual process
isolation, real waits/replies, exact mapping-owner rejection paths and final
frame/metadata restoration. Compile-fail checks guard the shared Running image
against mutable mapping access. Executed results belong in
M3 progress; this decision is not hardware PASS.

PIO avoids guest-memory DMA; it does not undo accepted disk work. Driver failure
after command issue remains indeterminate. This fixture cannot certify device
drain/reset, durable journal replay or device-bearing BAC reconstruction. Those
remain required before broader storage/recovery acceptance.
