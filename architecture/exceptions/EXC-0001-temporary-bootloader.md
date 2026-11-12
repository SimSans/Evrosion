# EXC-0001 — Temporary M0 bootloader

Status: Active
Opened: 2026-09-20
Owner: boot/image-builder and libs/boot-contract maintainers (project owner until assigned)
Target removal: Before Evrosion declares its boot contract Preview
Expiry trigger: boot-contract-preview
Affected invariants: INV-EVO-001, INV-EVO-002, INV-M0-004
Scope: boot/image-builder/, libs/boot-contract/

## Temporary deviation

M0 may use rust-osdev/bootloader 0.11.17 and its temporary handoff format. The
external handoff remains behind the image builder and boot-contract adapter.
Slices 2–3 now use these exact versions. The image builder compiles the published
UEFI loader using its own Cargo.lock, preserved under third_party alongside the
workspace lock inventory. This nested graph is not covered by the root lockfile
alone. A cold image-builder compilation needs network access to fetch it.

M1-02a scope review, 2026-09-30: the owner-authorized continuation enables the
same loader's optional physical offset mapping, solely through this adapter.
[ADR-0005](../adr/ADR-0005-bootstrap-page-table-ownership.md) limits its use to
bootstrap table/frame access and copied-root proofs. Inherited mappings remain
reserved; no user root or loader-memory reclamation is authorized by this
extension. The expiry trigger and dependency boundary are unchanged.

M1-02b scope review, 2026-10-01: the owner's continued 0.1 instruction also
authorizes [ADR-0007](../adr/ADR-0007-bootstrap-user-address-spaces.md). Private
user branches reuse the retained direct map for kernel-only table/frame access;
every inherited root entry is forced supervisor-only. No loader memory is
reclaimed, no external type crosses the adapter, and expiry remains unchanged.

M1-03c.1 scope review, 2026-10-01: [ADR-0009](../adr/ADR-0009-firmware-cpu-topology.md)
adds the optional ACPI RSDP physical address to the Internal adapter handoff.
Every table read requires retained reserved coverage and bounded direct-map
arithmetic. Firmware remains trusted platform input. No AML/runtime firmware
execution or external-type leakage is introduced; expiry is unchanged.

## Why it is necessary now

The approved M0 package prioritizes a repeatable build, boot, observation and
debugging loop. A custom production loader is outside this milestone.

## Risk and containment

The dependency controls privileged boot input. Pin its resolution and retain
debug symbols and build identity. Validate input at the adapter; never expose
the external format as an Evrosion Stable ABI. The loader remains trusted to
supply valid Rust references and mapped memory; arithmetic and metadata checks
cannot sanitize arbitrary unmapped pointers. License and notice records cover
both Cargo graphs, with missing upstream texts explicitly documented.

## Removal plan

Before boot-contract Preview, select and validate the Evrosion-owned contract
and loader strategy through an ADR, migrate the adapter, and remove reliance
on the temporary handoff. Record tests and the accepted decision here.

## Test preventing scope expansion

The architecture validator rejects direct bootloader dependencies outside
boot/image-builder and bootloader_api dependencies outside libs/boot-contract,
including Cargo dependency aliases. Adapter tests reject overlaps, invalid
ranges, arithmetic overflow and invalid framebuffer layouts. The kernel only
receives Evrosion BootInfoV0 through the adapter's entry macro; external types
appear only in that macro's hidden bridge. Dependency placement alone does not
prove safe boot behavior.

## Resolution evidence

Still Active. The adapter and repeated boot evidence establish the M0 development
path, not removal of the temporary dependency. See [M0 progress](../../docs/release/0.1-preview.md#validation-and-provenance)
and [ADR-0001](../adr/ADR-0001-m0-kernel-and-toolchain.md).
