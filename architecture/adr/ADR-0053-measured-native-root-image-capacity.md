# ADR-0053 — Measured Native Root image capacity

Status: Accepted Level B mechanism refinement; physical execution pending.
Date: 2026-11-11.

## Evidence and decision

The second Native3 build passes the actual linked Root stack census at27,928 of
32,768bytes, with4,840bytes of reference margin. Its admitted ELF is351,320bytes,
below the unchanged1MiB image-file bound. Actual PT_LOAD needs65text,5read-only,
1data and8declared-stack pages:79image pages,85loader-owned private frames with
the existing bootstrap/stack and page-table overhead. The legacy64-image-page
parser rejects Capacity before any VM starts.

The immutable failed attempt (local engineering archive)
retains exact candidate sources, unstripped/admitted images, census and logs.
Compilation and this census do not attest execution or every indirect call path.

Permit at most96image pages only through verified Native Root admission, with
100private ownership slots and a102-frame loader bound. Existing Root512-frame
quota,32KiB guarded stack,2MiB virtual window, package-bank reservations, entry
permissions, W^X, startup checks and physical retirement remain enforced. Image
file bytes stay bounded independently. This changes implementation capacity
within existing authority/resource limits, without a foundational guarantee change.

## Ownership and compatibility

Use capacity-parameterized private mappings, physical user roots and loaded-image
owners. Existing aliases/defaults retain64image pages and68private slots. Only
the separately retained NativeRootImage uses the larger owner. The runtime
already borrows that Native owner; existing child actor arrays must not grow.
Borrowed directory/leaf access and scalar checks stay narrow, capacity-aware and
tied to the same actual owner.

Ordinary services and older Root admission retain their rejection bounds. No
arbitrary caller chooses a larger capacity, no page metadata is dropped to fit
an image, and shared package leases remain separately owned. Every admitted page
and table is charged before allocation and returned exactly once.

## Required verification

Require actual verified-manifest cases at64,79,96 and97image pages, older-profile
refusals,85required frames versus84/85-frame quotas, larger mapping fill/refusal/
unmap/ownership return, unchanged older actor sizes and all Core/target checks.
Recheck exact linked Kernel/Root stacks, real PTEs, guards, quotas and complete
physical/authority retirement in the subsequent VM. No Native3 permission/System
or whole0.1 acceptance follows from this refinement.
