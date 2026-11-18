# ADR-0103 — V4 bootstrap source retirement and grant headroom

Status: Accepted Level B; bounded VM qualification PASS.
Date: 2026-11-15
Related: ADR-0102, M7-03/07/08, INV-AUTH-002, INV-LIFE-002

## Context

The failed source09 final offline-B run preserves its document and becomes
healthy, but fresh selected-File delivery is refused. Earlier healthy B can
select, save and reopen. Actual retained image handles and the source graph
identify a capacity boundary: V4 delivers29 startup handles, creates17 channel
handles and retains16 job/ProcessCONTROL handles for eight children. Two retained
downloaded images occupy all64 Root slots. The existing atomic selected handoff
needs one temporary Root-local child and correctly refuses at capacity.

## Decision

After full V4 startup/package verification and before channel/child allocation,
close Root's unused BadShellImage READ-only destination handle. V4 uses verified
downloaded System cohorts; its legacy Good/Bad System slot is unavailable. Make
the network-profile image/digest helpers explicitly reflect that distinction.
Native3 keeps its existing legacy Good/Bad path and source handle.

Use the existing CLOSE operation. Kernel custody and immutable image backing
remain owned; closing the local handle neither revokes nor destroys the source.
Keep mapped PackageA/PackageB handles and Catalogue diagnostics intact. Preserve
the64-slot limit, all other sources, actual requester/rights/selection checks
and atomic handoff. The resulting live set has63 slots before selected delivery.
This supplies the reference workflow's headroom, without reserving every future
allocation combination or increasing resource/authority budgets.

## Verification

Retain failed source09 and its raw media. The portable transaction test must
refuse at64 without a partial parent/source mutation, then deliver and retire a
grant after closing only the unused READ source while custody remains valid.
Check mapping lifetime, dynamic image permits and shutdown ancestry separately.

Rebuild/measure affected V4 profiles. A new exact-source signed six-boot run on
a new owned disk must preserve later document edits through healthy B, actual C
failure, independent offline recovery and final B with both images retained.
Do not rewrite old System manifests, creators or source identities to move the
failed disk to a different Root image. General Root replacement remains outside
this qualification. No new capability primitive, permissive fallback, storage
format or public contract maturity is introduced.

The M7 acceptance (local engineering archive)
retains the actual source10 six-boot pass and final11 host-only transfer, including
final B selected delivery with both downloaded images retained.
