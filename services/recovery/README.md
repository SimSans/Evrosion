# Independent recovery entry

A separate measured Rust/no_std executable using only the shared userspace
contract/runtime. It does not link the Root Supervisor, Echo service, normal
service graph, graphics, storage or network. See
[E-012.20–22](../../architecture/plans/platform/E-012-boot-and-recovery.txt)
and [Root custody](../../architecture/designs/ROOT_AUTHORITY_CUSTODY.md).

The trusted boot producer measures its own ELF/manifest against permanently
retained recovery roots: selector 1 Memory READ, selector 2 Endpoint SEND.
Startup accepts exactly those two roles, validates the read-only bootstrap page,
checks permitted READ and denied WRITE/invalid authority, sends RecoveryReady and
yields. Its finite Job limits are 64 CPU ticks, 16 frames, one process and one
thread. Its manifest disables recursive automatic recovery replacement.

RecoveryReady only acknowledges execution of this independent image. The trusted
controller retains the actual old token, fault record and custodian reason; the
program does not manufacture a failure capsule or reset failed Root custody.
This is an entry skeleton, not a recovery UI, generation selection, durable
rollback or complete M3 recovery environment. Those require separate acceptance.
