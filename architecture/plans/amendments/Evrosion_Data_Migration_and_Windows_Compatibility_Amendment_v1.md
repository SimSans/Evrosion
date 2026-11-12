Public technical edition. Editorial changes remove development-workspace instructions; technical requirements and clause identities remain. The source map records actual edition hashes.

# Evrosion Architecture / Product Amendment
## Data-Preserving Installation & Out-of-Box Windows Compatibility

**Status:** Accepted product-direction amendment  
**Date:** 2026-09-21  
**Purpose:** Add two product requirements to the Evrosion plan without reopening the broader architecture.

---

# A-001 — Data-Preserving Installation & Migration

## Core rule

Replacing an operating system must not inherently require destroying the user's personal data.

Evrosion should provide a preservation-first installation path that separates:

- operating-system replacement;
- user-data preservation;
- source-OS retirement.

The default user-facing goal is:

> Install Evrosion without requiring the user to wipe their personal files first, whenever the existing disk layout and available storage make safe migration possible.

## Intended migration flow

Conceptually:

```text
Existing Windows/Linux/etc. disk
        ↓
Inspect disk, partitions, filesystems, encryption and free space
        ↓
Determine whether safe in-place migration is possible
        ↓
Shrink/rearrange existing storage only through supported safe operations
        ↓
Create Evrosion system and durable user-data storage
        ↓
Install Evrosion into newly available space
        ↓
Copy/import the user's personal files
        ↓
Verify the migrated data
        ↓
Boot and health-check Evrosion
        ↓
Preserve the old operating system temporarily as rollback
        ↓
User confirms migration succeeded
        ↓
Retire/reclaim the old operating-system space
        ↓
Expand Evrosion/user-data storage where appropriate
```

## Destructive cleanup rule

Evrosion must not automatically destroy the source OS merely because a copy operation completed.

The old operating system and its data remain preserved until:

1. the migration has completed;
2. required verification has passed;
3. Evrosion has successfully booted and passed relevant health checks; and
4. the owner explicitly authorizes reclaiming the old system.

If verification is incomplete, failed, or ambiguous:

> Preserve the source OS.

## Verification

A migration should produce explicit evidence.

Where practical, verification should include:

- source file inventory;
- copied file count;
- total bytes;
- file size comparison;
- metadata preservation where supported;
- cryptographic hashing for migrated content where appropriate;
- failed/skipped item reporting;
- migration manifest;
- source and destination mapping.

The installer must never present a migration as safely complete when known copy or verification failures remain.

## Transactional / resumable behavior

Migration must be journaled.

If the machine loses power, crashes, or reboots midway through migration, Evrosion should be able to:

- determine what completed;
- determine what did not;
- resume safely;
- avoid blindly repeating destructive operations;
- preserve the original data while recovery is unresolved.

The migration system should follow the same general Evrosion philosophy as transactional updates and System Generations: incomplete state should be detectable and recoverable.

## Storage constraints

Evrosion cannot promise same-disk migration in every situation.

Examples that may require user action include:

- insufficient free space;
- unsupported filesystem;
- damaged filesystem;
- locked encryption;
- disk layout that cannot safely be resized;
- storage hardware errors.

In those cases, Evrosion should explain the exact constraint and offer safe alternatives such as:

- free additional space;
- connect another drive;
- make a verified external backup;
- keep the existing OS and dual boot;
- perform a manual/advanced installation.

## Encryption

Encrypted source filesystems must not be bypassed.

Examples include BitLocker and LUKS.

Where supported:

- require the user to unlock the volume through legitimate credentials/recovery material;
- read data only after the source filesystem is legitimately accessible;
- do not imply that Evrosion can recover inaccessible encrypted data.

## Data versus applications

Personal data migration and application compatibility are separate concerns.

The installer may migrate/import things such as:

- documents;
- photos;
- videos;
- music;
- downloads;
- projects;
- game saves;
- known safe user configuration;
- browser bookmarks/profile data where intentionally supported.

It must not pretend that copying an installed Windows application's files automatically makes it a native Evrosion application.

Windows applications are handled by the Windows compatibility subsystem described in A-002.

## Persistent user-state principle

Evrosion itself should architecturally separate replaceable system state from durable user data.

Conceptually:

```text
Replaceable / rollbackable Evrosion System Generations
                         │
                         ▼
              Durable User State
```

Therefore, once a machine already runs Evrosion, normal:

- reinstall;
- recovery;
- upgrade;
- rollback;
- generation replacement

should not require wiping the user's personal data.

## Backup reality

Same-disk migration is not a substitute for a backup.

If the physical SSD/HDD fails, both source and migrated copies can be lost.

Therefore Evrosion should strongly recommend — and eventually make easy — a verified external backup before high-risk disk migration, while still supporting preservation-first migration where the owner chooses to proceed without one.

## Suggested installer choices

A normal-user installer can expose choices conceptually like:

```text
● Migrate my files
  Install Evrosion alongside the current system,
  copy and verify personal data, then allow the old
  system to be removed after successful validation.

○ Keep my current OS
  Install Evrosion alongside it without removing it.

○ Erase disk and install Evrosion
  Delete existing contents and start clean.
```

Advanced users may access explicit partition controls.

## Product principle

> Replacing the operating system should not imply destroying the owner's data.

---

# A-002 — Out-of-Box Windows Compatibility

## Core rule

Windows compatibility is a built-in Evrosion product capability.

For normal user-facing Evrosion releases, supported Windows software should be runnable immediately after installation without requiring the user to separately discover, download, or configure a compatibility framework.

The intended experience is:

> Install Evrosion → open supported Windows software → Evrosion handles the compatibility environment.

## Architectural separation

Windows compatibility must remain isolated from native Evrosion architecture.

Conceptually:

```text
Native Evrosion applications
        │
        └── use native Evrosion APIs directly


Windows applications
        │
        ▼
Windows Compatibility Runtime
        │
        ▼
Evrosion platform services
```

Native applications must not depend on the compatibility runtime.

Native Evrosion software must not pay unnecessary:

- startup cost;
- memory cost;
- complexity;
- ABI constraints;
- security surface;
- compatibility debt

simply because Windows compatibility is present.

This preserves the existing Evrosion architectural law that native software does not pay for optional compatibility mechanisms.

## Product availability

For consumer-facing/general-use Evrosion releases, the Windows compatibility runtime should ship with the OS and be ready to use.

It should not be treated as:

- a separately installed compatibility pack;
- a post-install scavenger hunt;
- a third-party prerequisite;
- a hidden advanced-user feature.

## Early milestone staging

This requirement changes product priority, but it does not require broad Windows compatibility to block the earliest architecture-proof milestones.

Specifically:

- Evrosion 0.1 Developer Preview may still focus on proving the native architecture;
- M0–M5 architecture work remains valid;
- broad Windows compatibility may be implemented in staged form after the native platform spine is sufficiently stable;
- before Evrosion is positioned as a normal-user/daily-driver release, Windows compatibility should be bundled and operational out of the box.

Therefore:

> Windows compatibility is allowed to be staged during developer-preview milestones, but it is not optional in the intended end-user product.

## User experience

Ordinary users should not need to understand prefixes, DLL overrides, runtime selection, or compatibility internals just to launch common software.

Where possible Evrosion should automatically determine:

- 32-bit versus 64-bit application;
- executable/installer type;
- required Windows runtime components;
- graphics/API requirements;
- application-specific compatibility profile;
- whether a known compatibility workaround is needed;
- whether a native `.zion` version exists.

The simple user experience should be:

```text
Double-click supported .exe
        ↓
Evrosion identifies requirements
        ↓
Evrosion prepares isolated compatibility environment
        ↓
Application starts
```

Advanced users should still be able to inspect and override compatibility behavior.

## Isolation and authority

A Windows application does not gain unrestricted host authority merely because it expects Windows semantics.

The compatibility subsystem must translate Windows-facing behavior into Evrosion's authority/security model.

Where feasible:

- applications run with explicit scoped authority;
- compatibility environments remain isolated;
- file access is mediated by Evrosion policy;
- compatibility runtime bugs should not automatically imply unrestricted system access;
- Layer 1/2/3 user responsibility rules still apply.

Exact sandbox/security mechanics remain implementation work and must respect the existing capability architecture.

## Application migration relationship

During migration from Windows, Evrosion may detect installed Windows applications and report them.

Example:

```text
Windows applications detected: 73

Personal data:
VERIFIED FOR MIGRATION

Applications:
Compatibility status will be evaluated by Evrosion.
```

Evrosion should not pretend that copying `Program Files` constitutes application migration.

Instead it may later support:

- application detection;
- compatibility availability lookup;
- recreation of required compatibility environments;
- Steam/game library reuse where safe;
- preservation/import of application user data and saves;
- guided reinstall or reuse.

## Compatibility implementation freedom

This amendment defines the product requirement and architectural boundary, not the exact implementation.

Evrosion may reuse, adapt, integrate, or independently implement compatibility technologies where licensing, architecture, security, and maintainability permit.

The implementation remains replaceable under E-026.

Do not freeze a specific compatibility engine into the constitutional architecture merely because it ships first.

## Product principle

> Windows compatibility should feel like part of Evrosion, not like a separate compatibility project the user has to assemble.

---

# Interaction Between A-001 and A-002

These two requirements intentionally reinforce one another.

A Windows user should eventually be able to move from:

```text
Windows machine
```

to:

```text
Evrosion machine
```

with a flow approximately like:

```text
1. Installer preserves/migrates personal data.
2. Evrosion boots and validates the migration.
3. Old Windows installation remains temporarily recoverable.
4. Windows applications are detected.
5. Supported Windows applications can run through the built-in compatibility runtime.
6. User validates the new environment.
7. Old Windows system space is reclaimed only after explicit approval.
```

This should make switching operating systems dramatically less destructive and less intimidating than the traditional:

```text
Back everything up
→ wipe disk
→ reinstall
→ restore files
→ rebuild application environment manually
```

---

# Roadmap / Documentation Amendment

Relevant canonical technical documents should be updated to reflect these decisions.

## Required conceptual changes

1. Add a future **Data-Preserving Installation & Migration** subsystem/requirement.
2. Explicitly separate:
   - system generations;
   - durable user data;
   - migration source state.
3. Add migration journaling, verification, rollback/preservation, and explicit destructive confirmation as requirements.
4. Change Windows compatibility language from purely optional/later ecosystem work to:
   - staged during early developer milestones;
   - built-in first-class infrastructure for user-facing releases.
5. Preserve the rule that native Evrosion software does not depend on or pay for the Windows compatibility runtime.
6. Do not silently alter the current M0 completion criteria.
7. Do not force either feature into Evrosion 0.1 unless implementation evidence makes that sensible.
8. Ensure future release gates distinguish:
   - developer-preview readiness;
   - ordinary-user readiness.

---

# Integration status

The migration and compatibility requirements are integrated through ADR-0003.
Their implementation remains staged after early native milestones; neither
amendment silently changes the 0.1 gate. Preserve explicit migration authority,
source data and later ordinary-user compatibility requirements.
