# Temporary architecture exceptions

Extracted from Part I of the [Pre-M0 package](../plans/roadmap/PRE-M0-implementation-package-v1.md).
Exceptions are narrow, owned and expiring. They describe temporary implementation
choices and do not amend architectural contracts.

Required fields:

```markdown
# EXC-NNNN — Title

Status: Active | Resolved | Expired
Opened: YYYY-MM-DD
Owner: ...
Target removal: milestone/date
Affected invariants: INV-...
Scope: exact files/components

## Temporary deviation
## Why it is necessary now
## Risk and containment
## Removal plan
## Test preventing scope expansion
## Resolution evidence
```

Rules:

1. No exception may say “temporary” without a removal trigger.
2. An exception cannot authorize ambient root, silent rights amplification, or destruction of the last Known Good generation.
3. CI lists all active and expired exceptions.
4. An expired exception fails the architecture fitness suite.
5. Expanding scope requires editing the exception and review; scope does not grow implicitly.

## Initial records

| ID | Exception | Target removal | Status |
|---|---|---|---|
| EXC-0001 | [Temporary bootloader](EXC-0001-temporary-bootloader.md) | Before boot contract Preview | Active |
| EXC-0002 | [Host QEMU and OVMF](EXC-0002-host-qemu-ovmf.md) | Before production release CI or reproducibility | Active |

These records authorize the current M0 scope. The temporary loader, image build
and QEMU runner are implemented; both exceptions remain active with the stated
removal triggers. Neither is waived by local M0 acceptance.

## Machine-checked expiry

Add an `Expiry trigger:` field to each real exception. Supported values are:

- `boot-contract-preview`: expires when the boot contract becomes Preview or later.
- `production-release`: expires when either production-grade release flag is true.
- `milestone:M<N>`: expires when the declared milestone reaches M<N>.
- `date:YYYY-MM-DD`: expires on that UTC date, inclusive.

The first three use the reviewed [project status](../status.toml). Date triggers
use the current UTC date. Update status when advancing the project; CI cannot
infer that a release or compatibility promise has been made outside the repository.
Unknown triggers or invalid status values fail validation. Resolved exceptions
retain their record and resolution evidence.

Keep this table synchronized with record status. Fields use one `Name: value`
line each; scope is a comma-separated list of existing repository-relative paths.
The [validator](../../tools/check_architecture.py) prints active and expired
records and fails on expiry, missing fields, duplicate IDs or an inconsistent register.
