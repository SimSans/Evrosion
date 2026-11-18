# ADR-0125 — Measured nonexecuting external package ingress

Status: Accepted Internal Level B refinement; native installation remains pending.
Date: 2026-11-16
Related: ADR-0111/0113/0120/0122/0123; INV-AUTH-001/002/004,
INV-LIFE-001/002, INV-EVO-006.

## Boundary

An independent external App needs explicitly retained package bytes before any
protected install decision. Relabelling EditorCandidate would replace an existing
software identity and would preload executable software into the startup graph.
The ingress is therefore a separate measured input. It adds no actor, grant,
endpoint, startup role, package bank, physical frame allowance or boot execution.
All four existing package records, their original locations and Candidate's
relationship to Editor remain unchanged.

## Closed optional record

The existing 12KiB V5 catalogue has a separate optional 192-byte record immediately
after its four-entry placement table. Existing `encode(Description)` preserves
the absent encoding; `encode_with_ingress(Description, Option<ExternalIngress>)`
adds the record only when explicitly supplied. The remaining tail stays zero.
The absent record and bank contents retain their old byte representation. An old
decoder rejects a present record through its existing reserved-zero check.

The record has magic `EVXING01`, versionu16@8=1, sizeu16@10=192,
provenanceu8@12=1 (`LocalOwnerDevelopment`), banku8@13=Candidate,
offsetu32@16, full package lengthu64@24, AppId@32, full Zion SHA256@48,
build@80 and executable SHA256@112. Other bytes are zero. The provenance label
describes the supplied local development input; it authenticates neither a
publisher claim nor permission to install. Unknown magic, version, source,
bank, reserved data or noncanonical metadata refuses the complete catalogue.

Ingress starts exactly at the 16-byte-aligned end of the original Candidate.
Checked arithmetic requires the complete package to fit the existing 258048-byte
Candidate bank. No gap, overlap, alternative bank or partial package is accepted.
The ingress AppId and package digest must differ from all four existing records.
The 63-page individual package bound also applies. Capacity failure refuses;
there is no automatic bank growth or replacement of Candidate.

## Producer and actual Kernel joins

The strict bundle input has optional `external_ingress` with actual path and
canonical SHA256. A Zion input cannot carry an ELF analysis sidecar. The producer
reads bounded regular full bytes, verifies the supplied hash, parses the complete
container and joins its AppId/build/executable hash and selected FileApp6 ABI and
descriptor. It copies the unchanged full package as `ExternalIngress.zion` and
records its exact measured tail placement separately. Transporting requirements
does not assert that those contracts or requested capabilities are loaded or
granted; protected Root installation must check them later.

The catalogue measurement includes the record. Kernel Assets independently joins
the actual optional bytes, complete length/hash, canonical placement, original
packages and the existing READ/MAP-only Candidate role before actor admission.
An occupied record without bytes, bytes without a record, or changed/truncated
bytes refuses. The actual backing factory fills and reads back only this checked
tail of its existing initialized Candidate extent before any process mapping.
Existing readonly Root mappings remain the only admitted package-bank access.
The ingress is excluded from all ten startup images and all eleven children.

The generated Rust bundle adds a typed `M8_EXTERNAL_INGRESS` optional constant.
For older generated sources, `kernel/build.rs` appends explicit typed `None`
only to its `OUT_DIR` copy when the exact declaration is absent. The retained
producer source is unchanged. A present catalogue with this compatibility None
still fails the actual Assets join. Explicit new Some/None declarations remain
byte exact; no metadata is inferred from package bytes or unused RAM. This
source adapter, its source hash and producer input remain part of the existing
reproducibility recipe. An old Kernel still rejects present catalogue metadata.

## Qualification and limits

Structural tests cover old absence, unchanged original records/graph counts,
unknown metadata, aliases, alignment, overlap, exact bank end, overflow, missing
or unexpected blob, full-byte tampering/truncation, actual Zion/descriptor joins
and legacy generated-source adaptation. Strict host and selected bare checks
remain component evidence. No ingress component test establishes protected owner
approval, enrollment, private allocation, dynamic transfer, first Start, native
SDK execution, publisher signature, cold availability or M8 acceptance. The same
package bytes must be explicitly retained for any later cold registry reopen.
