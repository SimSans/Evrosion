# EXC-0002 — Host-provided QEMU and OVMF

Status: Active
Opened: 2026-09-20
Owner: tools/ev and CI maintainers (project owner until assigned)
Target removal: Before release CI or reproducibility is declared production-grade
Expiry trigger: production-release
Affected invariants: INV-M0-001, INV-EVO-001
Scope: tools/ev/, .github/workflows/

## Temporary deviation

Local M0 development may discover QEMU and OVMF from host packages instead of
a fully pinned, hermetic tool environment. Slice 1 doctor discovers firmware and
queries QEMU features/versions; CI installs host packages for the prepared-host
check. Slice 3 runs Q35/TCG with no networking, per-run VARS copies and disposable
disk writes. Evidence records exact argv, QEMU/firmware hashes, serial output,
monotonic elapsed time, exit status and the build manifest.

## Why it is necessary now

Using the prepared host makes the first boot loop practical while the image
builder, runner and evidence format are developed.

## Risk and containment

Host emulator and firmware versions can change boot results. The ev doctor now
reports versions and firmware paths; the run evidence identifies inputs.
Original firmware templates and the canonical image are checked unchanged after
the VM run. This exception does not waive the
M0 double-build image comparison or permit claiming hermetic release builds.

## Removal plan

Pin, record and provision the full release environment, including emulator and
firmware inputs. Prove clean-environment reconstruction before setting either
production-grade release flag in the project status.

## Test preventing scope expansion

The architecture validator fails while this exception remains Active if either
production-grade flag is true. From Slices 1–5, add host diagnosis, input-manifest
and reproducibility tests before describing those behaviors as implemented.

## Resolution evidence

Pending. Host packages remain a local M0 development convenience.
