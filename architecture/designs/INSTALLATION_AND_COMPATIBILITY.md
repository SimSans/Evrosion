# Installation, migration and Windows compatibility

Status: Accepted product direction; implementation DEFERRED
Authority: [ADR-0003](../adr/ADR-0003-preservation-and-bundled-compatibility.md)
Source: [Owner amendment, 2026-09-21](../plans/amendments/Evrosion_Data_Migration_and_Windows_Compatibility_Amendment_v1.md)

## ADR-0003.MIGRATION — Preserve data through OS replacement

Three kinds of state must remain distinguishable:

| State | Lifetime and authority |
|---|---|
| System Generations | Replaceable immutable OS content; health-gated activation and rollback |
| Durable User State | Documents, projects, media, saves and explicitly supported user configuration; retained through normal reinstall/recovery/update/rollback |
| Migration Source State | Original OS, personal data, layout and recovery references retained until validation and owner-authorized retirement |

A preservation-first installer inspects partition layout, supported filesystems,
encryption, available space and storage health before proposing operations.
Supported safe shrink/rearrangement can create room for Evrosion and durable
data. Unsupported operations must not be guessed. Preserve source state while
copying, inventorying and verifying personal files; then boot and health-check
Evrosion. Only after successful verification and explicit owner confirmation
may a distinct reclaim operation retire the source and expand destination storage.

### Required behavior

- Journal phases and completed operations durably. After power loss/crash/reboot,
  identify completed and pending work, resume safely and never repeat an
  irreversible operation based on an ambiguous state.
- Produce a migration manifest: source/destination mappings, file inventory,
  counts/bytes/sizes, supported metadata, content hashes where appropriate, and
  all skipped/failed/unverified items. Known failure or ambiguity prevents a
  “verified complete” result and source reclamation.
- A copy finishing is insufficient to retire the old OS. Require data verification,
  a successful Evrosion boot, relevant health checks and explicit owner authority.
- Recognize inadequate space, unsupported/damaged filesystems, locked encryption,
  unsafe resize/layout and hardware errors. Explain the specific constraint and
  offer space cleanup, another drive, verified backup, dual boot or an advanced
  manual installation as applicable.
- Access BitLocker/LUKS or other encrypted sources only after legitimate unlock.
  Do not imply inaccessible encrypted data can be recovered without its credentials.
- Offer migrate-files, keep-current-OS and explicit erase-disk choices. Advanced
  partition control is separate. Recommend verified external backup for high-risk
  migration while retaining the owner's ability to proceed where supported.
- Keep personal-data migration separate from app installation. Import supported
  saves/profile data intentionally; detecting or copying an app does not make it native.

### Future acceptance evidence

Interrupted/resumed migration at each phase; copy/hash/metadata failure; source
preservation when validation is incomplete; rollback boot; explicit reclamation
confirmation; insufficient-space and encrypted-volume cases; repeat recovery
without blind destructive replay; user-data survival through reinstall/rollback.
The supported disk/filesystem matrix and exact durable journal format are future
design decisions. None is claimed implemented by this document.

## ADR-0003.WINDOWS — Ready-to-use supported Windows software

Ordinary-user/general-use releases bundle the Windows Compatibility Runtime.
Launching supported `.exe`/installer software should identify requirements and
prepare an isolated environment without asking ordinary users to discover a
separate framework, select prefixes or understand DLL overrides.

The runtime may detect architecture, executable type, required components,
graphics/API needs, compatible profiles/workarounds and available native `.zion`
versions. Advanced inspection and overrides remain available. Publish actual
tested support and explain unsupported applications; this is not an all-Windows-
software guarantee.

### Architectural boundary

- Native apps call native APIs and acquire no compatibility ABI/runtime dependency.
  Foreign services activate on demand; measure native startup/memory impact.
- Windows behavior is translated through Evrosion platform services and scoped
  capabilities in isolated userspace realms. Expectations of Windows authority
  do not grant unrestricted host access. Layer 1/2/3 ownership rules still apply.
- Reuse/adapt/implement a provider where licensing, security, architecture and
  maintainability allow. No particular engine is constitutionally selected.
  Providers remain replaceable under E-026.
- Migration may report detected apps and later offer supported reinstall/reuse,
  safe library reuse and save/config import. Copying Program Files alone is not
  verified application migration.

### Future acceptance evidence

Fresh ordinary-user installation launching a declared supported app set without
separate framework setup; 32/64-bit/API/profile coverage as declared; updates and
failure recovery; file authority and realm isolation; native lifecycle/boot tests
with compatibility inactive; native dependency and measured overhead checks.

## Milestones and release gates

M0–M5 and Evrosion 0.1 retain their native architecture-proof requirements.
Stage migration and compatibility once storage/lifecycle/native applications
can support them. Do not mark either product gate PASS from design documents.
See [the current roadmap](../ROADMAP.md) and [release direction](../release/README.md).
