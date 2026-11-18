# ADR-0122 — Compact executable and retained analysis ELF

Status: Accepted Internal Level B refinement; actual bundle and VM qualification remain separate.
Date: 2026-11-16
Related: ADR-0113/0117/0119/0121; INV-EVO-006; M8 actual-artifact admission.

## Problem and retained constraints

The current Files, bounded-Verify Editor and Root-proxy Inspector symbol-bearing
ELFs encode into actual Zion packages of104770,123372 and110474 bytes. Their
sixteen-byte-aligned Current bank ends at338634, exceeding the unchanged79-page
323584-byte bank by15050 bytes. Symbol and section metadata increases retained
file size without necessarily being part of the loaded executable. Expanding
the physical bank, Kernel capacities or an ABI is unnecessary if the exact
loaded image can be preserved with a smaller file.

The existing linked stack census requires actual symbols, including `_start`.
Discarding symbols and skipping that census would weaken existing preflight.
Running it on a different executable would give an unrelated result.

## Refinement

An ELF artifact input may explicitly provide a nonrecursive `analysis` object
containing a path and canonical SHA-256. The ordinary path/hash still identifies
the actual executable. Both files must be bounded regular ELF inputs, at most
two MiB each. No producer-side implicit stripping or analysis discovery occurs.
Old inputs without the optional object preserve their existing analysis path;
a stripped executable without its needed symbols fails the existing census.
Analysis objects on Zion package inputs are refused.

Before any sidecar is used for analysis, the producer checks both actual hashes
and compares executable entry, the entire ordered program-header table byte for
byte, and every literal PT_LOAD payload byte. This includes PT_NULL header
metadata, permissions, addresses, physical-address metadata, file offsets and
lengths, zero-fill extents and alignments. These exact requirements are stricter
than a comparison which permits rewritten file offsets. Truncated, foreign,
unsupported or mismatched inputs refuse. Unloaded section and symbol metadata
may differ; the comparison never assumes that such metadata is loaded.

The accepted symbol ELF is copied into the exclusive output and pinned there.
The existing stack auditor runs on that retained file. A separate equivalence
record and the bundle retain both hashes, exact comparison scope, and the
census result. Explicit EditorCandidate inputs receive the same analysis check
and census. The actual compact ELF alone supplies ServiceImage admission,
descriptor, package executable bytes, catalogue identity and Kernel input.
Source/debug artifacts remain independently retained in their existing paths.

The sidecar is trusted explicit build-analysis material, as symbol metadata in
the former single ELF already was. Loaded-byte equality does not authenticate
symbol names or prove arbitrary symbol-table annotations. The census retains
its fixed-prologue/resolved-reference scope and its stated indirect-call,
recursion, assembly and asynchronous-nesting limitations. It supplies no formal
whole-program stack bound, WCET or runtime high-water measurement.

## Actual prototype and qualification

Outside-source prototype02 uses the pinned toolchain's `llvm-objcopy
--strip-all` on the independently retained compiled Apps. Entry, every program
header and literal LOAD bytes match both the existing symbol ELF and full debug
ELF. Latest Inspector hash is checked against its passed ELF preflight. Actual
Zion encoding/readback and ServiceImage admission produce:

| Package | Actual compact package bytes | Bank offset |
|---|---:|---:|
| Files |91850|0|
| Editor |108412|91856|
| Inspector |100058|200272|
| EditorCandidate |108412|0 in Candidate|

The Current bank ends at300330, leaving23254 bytes. Candidate remains within
its independent63-page258048-byte bank. Individual package caps, page mappings,
frame quotas, ABI and all original disk data remain unchanged. The old
symbol-bearing package attempt and its honest bank refusal are retained too.
The current auditor independently refuses the stripped Inspector without a
symbol sidecar; that failed negative control is retained.

Focused regression checks cover exact equivalence, unloaded metadata changes,
entry/program-header/PT_NULL/payload tampering, malformed/truncated/foreign
files, hashes, missing symbols, schema recursion and package-input refusal.
Actual compact bundle preparation must additionally retain successful sidecar
censuses and typed catalogue/package joins. Packaging and preflight do not
claim actual native runtime admission, physical device behavior, installation
or the complete M8 acceptance gate.

## Alternatives

Keeping only stripped ELF bytes would lose the required linked-symbol census.
Keeping only a full symbol ELF in the physical package would retain the measured
bank overflow. Increasing the bank would change retained mappings and budgets
without addressing metadata overhead. Unchecked analysis paths or hash-only
sidecar comparison would permit a census of different code. Source-side hidden
stripping would obscure which executable was actually measured.
