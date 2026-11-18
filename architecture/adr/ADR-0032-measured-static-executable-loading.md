# ADR-0032 — Measured static ELF64 loading

Status: Accepted
Date: 2026-10-19
Owners: Project owner; kernel/platform maintainers
Related: ADR-0007, ADR-0031, INV-AUTH-002, INV-KERN-004, INV-KERN-005

## Problem and decision

M1 copied a built-in assembly blob into private pages. M2 needs to validate and
load the exact executable bytes selected by a measured bootstrap manifest before
its held supervisor can become runnable. The first loader supports a deliberately
bounded static ELF64 subset and constructs owned private mappings. It does not
release process admission or satisfy whole-system supervisor/recovery acceptance.
This additive Internal decision implements the existing userspace direction;
it changes no foundational guarantee, public ABI or historical evidence.

## Measured load plan

`executable::Image::from_manifest` borrows the same immutable bytes already checked
against the manifest image measurement. It records the manifest digest, entry,
virtual window, exact page permissions and initialized byte slices. Parsing makes
no physical allocations or capability grants. The current bound incarnation can
request this plan with its complete token; malformed executable content latches
the existing recovery diagnostic while its process stays held.

The parser accepts x86-64, little-endian ELF64 ET_EXEC version 1 with OSABI/version
zero, a 64-byte ELF header and 1–8 fixed 56-byte program headers at offset 64.
Load segments must use 4 KiB alignment with page-aligned file offsets and virtual
addresses. They must be nonempty in memory, sorted and disjoint after rounding to
pages. File size must fit memory size and all file ranges must fit the measured
image (still at most 1 MiB). Every addition/range is checked before slicing.

Only PT_LOAD and PT_NULL are supported. PT_NULL's unused fields are ignored;
load-segment physical-address fields never select physical RAM. Interpreter,
dynamic linking, TLS and other program-header semantics are rejected explicitly.
Optional section headers are bounded to 256 fixed 64-byte entries with checked
file extent and string-table index; section contents do not drive loading.
Extended counts are unsupported. There is no relocation or rebasing interface.

Permissions must be exactly R, RX or RW. Unknown/extra rights and every writable
executable combination fail. The entry must fall in file-backed RX bytes, never
zero-fill, data, stack or an unmapped hole. At most 64 image pages fit a single
2 MiB window in a canonical lower-half PML4 slot 1–255. Page zero of that window
stays absent. Page 510 is the stack guard; page 511 is one RW/NX stack page.
No segment may reach either stack page. These are bringup capacities and a static
executable subset, not permanent Evrosion application or memory limits.

`required_frames` includes all image pages, the stack and four page-table frames.
The plan must fit the manifest's Job frame limit. Runtime admission must also
charge the Job's remaining frame budget before allocation. Page materialization
zeros the entire destination first, including BSS, file tails and page padding.

## Hardware boundary and lifetime

`UserRoot::load_image` checks the selected slot in the retained root and available
frames before allocating anything. Under exclusive BSP/allocator ownership it
creates a private inactive root, installs move-owned frames with final W^X flags,
copies the planned bytes and reads back every byte and leaf entry. It adds a
separate zeroed NX stack with its guard absent. Errors in slot/capacity preflight
leave the allocator unchanged; violated hardware/ownership invariants remain fatal
kernel errors, rather than publishing a partially loaded image.

`executable_runtime::LoadedImage` keeps root ownership private with its entry,
stack and manifest digest. This is the runtime object future activation must
retain/consume. The current finite loader proof calls the established standalone
trap boundary directly; it does not dispatch a supervisor or release its hold.
No public readiness boolean or scheduler release API was added.

The independent proof runs after M1 runtime measurements so its reclaimed frames
do not change that fixture's assumed starting pool. Its summary marker still
precedes the M1 summary records, which are emitted after both proofs return.
After every finite probe returns, the controller switches to its original CR3,
retires the inactive private root using the existing scrub/reclaim mechanism and
balances the Job frame charge. This relies on the existing BSP-only, parked-AP,
PCID-off hardware conditions. It is not an SMP shootdown or general DMA teardown
certificate. Future activation must couple this owned loaded root to the actual
token/process, recheck live authority, then release admission atomically.

## Evidence and limits

The independently encoded `bootstrap-static-v1.elf` fixture has two segments:
RX code and RW data with multi-page BSS. Its separate 232-byte measured manifest
preserves the original authority-set fixture. The old `abc` image/manifest and
all historical evidence remain unchanged. `tools/m2/executable_fixture.py`
checks exact bytes and hashes without silently regenerating artifacts or needing
a compiler. The fixture's success instruction offset is independently fixed.

Host tests cover header/version/machine/type errors, bounded tables, unsupported
semantics, all 512 tested permission values, overflow, capacity, overlapping pages,
guard windows, entry validation, measurement mismatch, exact zero fill, frame
budget boundaries, all 8,200 truncations and 8,192 bounded malformed headers.
Incarnation tests cover matching/stale plan requests and executable-failure latching.

The kernel fixture charges nine frames, loads five user pages, rejects a conflicting
root without allocating, executes five CPL3 runs, and reclaims all nine frames.
It verifies initialized data/BSS and stack use, denies RX writes, denies execution
from data/stack, and faults on the stack guard. Strict serial/evidence parsers and
the cumulative regression are required. Executed evidence is linked from
M2 progress. Actual Root Supervisor activation,
trusted bundle/epoch production, sealed singleton custody, real service protocols
and full AF-007 recovery remain pending.

## Format references

The standard layouts and load semantics were checked against the primary
[ELF header](https://gabi.xinuos.com/elf/02-eheader.html) and
[program loading](https://gabi.xinuos.com/elf/07-pheader.html) specifications.
The stricter subset and capacity choices above are Evrosion's Internal contract.
