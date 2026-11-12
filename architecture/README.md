# Technical architecture

Evrosion places memory, scheduling, capability and protected IPC mechanisms in a
small kernel. Userspace services own drivers, files, display and higher-level
policy. Root Supervisor builds the measured service graph using explicit
bootstrap authority; it is not ambient authority available to ordinary programs.

Applications have stable AppIdentity and separate immutable package/build
identity. Declarations request capabilities; trusted policy and a live recipient
are required for delegation. Selected-file access supplies one scoped File
endpoint, not a global path or disk selector.

Jobs attribute resources to actual runtime owners. Stop/Reap and replacement
retire old authority before reuse. Durable permission policy is separate from
session handles and installation metadata.

System Generations name coherent immutable implementations. Actual critical
health and durable publication promote Known Good. User/app data remains
separate and must survive declared rollback. A GUI-ready marker or Store creation
context is not a health receipt.

Start with:

- [Invariants](INVARIANTS.md) and [governance](GOVERNANCE.md).
- [Accepted decisions](adr/README.md).
- [Technical source index](ARCHITECTURE_INDEX.md) and [source map](plans/source-map.json).
- [Root custody](designs/ROOT_AUTHORITY_CUSTODY.md),
  [IPC discipline](designs/IPC_DISCIPLINE.md),
  [boot health](designs/BOOT_HEALTH.md) and
  [selected-file approval](designs/PICKER_APPROVAL.md).
- [Current preview limits](../docs/release/0.1-preview.md).

Plans describe both implemented foundations and future product requirements.
The source map identifies each public technical edition; a plan is not evidence
that its future subsystem exists.
