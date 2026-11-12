# ADR-0023 — Eager legacy extended user contexts

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0016, INV-KERN-003

## Decision

Each scheduled user thread owns a 512-byte, 16-byte-aligned FXSAVE image.
Initial images contain zero register storage, an empty x87 tag, default x87
control and default MXCSR. User-provided restore images are not accepted.

The assembly entry saves controller state and restores the selected thread before
IRET. Every scheduled CPL3 trap saves user extended state and restores controller
state before calling Rust. IF is clear throughout this transition; the BSP owns
the slots, and parked APs do not access them. Kernel interrupts and the separate
exact-fault probes do not use the scheduled-user state slot.

FXSR/SSE2 are checked before enabling CR0/CR4 support. XSAVE/AVX and FSGSBASE remain
disabled. FS/GS bases are initialized to zero and selectors reset on transitions.
There is no TLS base-setting ABI yet. Supporting AVX, TLS or concurrent dispatch
requires explicit extended-state and per-CPU entry work.

The layout follows the [Rust FXSR documentation](https://doc.rust-lang.org/src/core/stdarch/crates/core_arch/src/x86/fxsr.rs.html).
Keeping user FS/GS-base writes disabled until context management supports them
follows [Intel's FSGSBASE guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/guidance-enabling-fsgsbase.html).

## Verification

Six user contexts test clean initial state and distinct x87 values/control words,
XMM0/XMM15 values and MXCSR rounding modes across real interrupts and scalar
system calls. A separate negative image corrupts the saved XMM0 byte after an
actual timer preemption; userspace must detect it and produce a finite failure.
The cumulative runner is `python3 tools/m1/extended.py`; execution evidence is
required before the tracker marks this slice PASS.
