# ADR-0020 — Shared Memory Object mapping leases

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: E-005, ADR-0014, ADR-0019, AF-009, INV-AUTH-002–003

## Decision

Introduce an Internal one-page Memory Object owning a physical frame and one
capability descriptor. A trusted bootstrap factory retains a CONTROL root in a
private kernel space. Processes receive explicit descendants, not that root.
The bounded Authority space capacity grows from four to eight to accommodate
process, private escrow and kernel lifetime domains without ambient grants.

Mapping requires the same live Memory descriptor, MAP and READ; writable
mapping additionally requires WRITE. Missing, wrong-object, revoked or
insufficient capabilities fail before a lease is created. Eight non-copyable
mapping leases are allowed per object. Tokens never wrap. A lease names the
backing and its granted writability but does not own the backing frame.

The BSP hardware boundary installs one shared leaf in each private user root,
with NX and the checked write bit. It invalidates the local translation when
installing a mapping. The backing is initialized before exposing any mapping.
Hardware must remove a mapping and quiesce users before surrendering its lease.
Private-root teardown refuses an outstanding shared lease. Object destruction
requires CONTROL and no live leases, invalidates the descriptor, then returns
the owned frame for scrubbing/recycling. Failure leaves the object intact.

## Executable proof

In each scheduled process pair the sender writes its writable shared page, then
transfers an attenuated READ|MAP capability through IPC. The receiver first
fails a mapping request without authority, later fails a writable request with
the read-only grant, maps read-only successfully, and reads the sender's actual
bytes at CPL3. Private process data remains isolated. Destruction while a lease
exists fails Busy. After both processes retire and their roots are inactive,
both leases return, the backing descriptor dies, and the scrubbed frame returns
to its originating allocator. Three objects, six maps, six denials and three
busy/destruction checks are required per boot.

Host AF-009 cases also cover MAP omission, wrong descriptor, stale/revoked
authority for new mappings, lease capacity/sequence limits, cross-object lease
return and blocking destruction until the final lease returns.

## Limits

This is a one-page bootstrap mechanism, not a general public memory allocator,
pager, executable shared mapping or multi-page object API. The runtime owner
serializes a single Authority instance and its bound object; numeric descriptor
identity is never a standalone grant. The AP does not use these roots.

Revocation denies new mappings but existing hardware mappings still require a
coordinated unmap/shootdown path. No userspace revoke syscall bypasses that future
coordinator. Remote TLB shootdown, object/lineage slot reuse, Job charges and
allocation policy remain unfinished. These limits prevent treating this slice
as complete memory/capability or integrated M1 acceptance.
