# ADR-0057 — Reproducible target build context

Status: Accepted implementation refinement; complete current-source M6-03 validation pending.
Date: 2026-11-12. Founder engineering mandate Level B.
Related: M6-03; EXC-0002; ADR-0052; the M5 build-context comparison.

## Problem and evidence

The M5 comparison (local engineering archive)
records the same exact source and recipe BuildID in two prepared Linux contexts,
with different full Kernel, loader and unsigned-image bytes. Cargo/toolchain
source paths enter diagnostic strings and embedded unstripped userspace ELFs.
Even one context's normal and fresh builds differ in private LLVM symbol names.
Recipe identity alone therefore does not imply artifact-byte identity; actual
full artifact digests remain authoritative for admission and symbol binding.

Controlled offline builds of an owned 0.1 baseline isolate these causes without
changing Kernel, SDK or service source. Mapping external source roots removes
their original paths. Disabling incremental compilation makes repeated cold,
warm and clean-target builds at one path equal. Two different source/Cargo-cache
paths still produce different private LLVM promotion suffixes in the Kernel's
symbol tables while every loaded and debug section, component and loader is
equal. A pinned-compiler cwd-remapping probe does not repair this. Compiling the
Kernel with one codegen unit makes its entire unstripped ELF equal across those
two paths. This supports avoiding the observed cross-unit promotion mechanism;
no comparison strips or normalizes symbol names.

The completed baseline experiment also compares actual whole target files from
prepared Ubuntu 26.04 and a separately kernelled Ubuntu 24.04 KVM environment.
All 74 target binaries match across contexts and the latter's cold/warm builds;
6 verified context JSON/log artifacts remain separately identified. Both builds
use the same complete 878-file input set, including the new helper. A new writable
overlay preserves the historical Ubuntu disk as backing-only; no compiled target
products are imported into the guest.

These experiments justify the build policy. They do not establish current M6
runtime acceptance or the complete current-source M6-03 gate.

## Decision

Apply one explicit compiler-context policy at the frontend's owned target Cargo
build boundary. Preserve existing target, relocation, code-model, frame-pointer,
linker, optimization, debug and ABI choices except the Kernel codegen-unit count.

- Map repository sources to `/evrosion`, registry sources to
  `/cargo/registry/src`, and the pinned compiler sysroot to `/rust`. Map existing
  lexical and canonical aliases; more specific external roots take precedence
  when private caches live inside the checkout. Preserve complete debug symbols.
- Set `CARGO_INCREMENTAL=0` for recorded target builds. Retain Cargo's ordinary
  dependency cache; it must produce the same bytes as a clean target directory.
- Set `codegen-units=1` for recorded `ev-kernel` builds only. Component builds
  keep their existing codegen policy. This is a real compilation change requiring
  current target/resource/runtime validation, not output-file postprocessing.
- Carry external mappings through the upstream EFI builder's separate
  target-specific rustflags. It intentionally clears generic encoded rustflags
  before nested Cargo. Keep `/debug:none` for the EFI binary as before and use a
  new image-builder cache generation so an older cached EFI cannot bypass the
  new flags. Do not remove Kernel or component symbol/debug sections.
- Remove inherited target-directory overrides from those owned nested builds
  and reject unrecorded profile, target, linker and compiler-wrapper overrides
  before building. Record policy, environment and actual complete artifacts.

The helper uses encoded arguments for source-root paths, including spaces. The
pinned upstream nested EFI argument transport requires whitespace-free external
Cargo/sysroot paths; reject unsupported roots clearly before compilation. This
is a declared tool limitation, not permission to omit a mapping.

Generated GDB commands map each virtual source prefix back to the actual pinned
local source tree. They still load and inspect the exact retained unstripped
Kernel artifact; a rebuilt or nearby ELF cannot replace its symbol authority.

## Versioned compilation inputs

Historical builds fingerprinted every Git-enumerated working file, including
archived execution reports. The archive subsequently exceeds 2.5 GiB and
retaining a report about a build changes that build's next recipe identity. This
creates a proof-of-own-code feedback loop and unnecessary source transfers.
The compact, independently checked Native seed and M2 serial fixtures replace
the former runtime/test reads of historical proof archives. The obsolete seed
decoder/tests are retained verbatim locally; original reports remain untouched.

Current manifests explicitly declare
`source_input_policy=git-working-tree-v2-no-archived-evidence`. Exclude only the
exact top-level `docs/status/evidence/` archival-output subtree before reading
files or computing the source digest. All other tracked/unignored files remain
selected, including compiler and generator code, templates, tests, compact
fixtures, manifests/locks, architecture and ordinary documentation. Neighboring
and nested lookalike paths remain included. NUL-delimited Git paths retain
their literal whitespace rather than being trimmed.

Keep the canonical path-length/path/SHA-256 source digest. Bind the new policy
explicitly in the `m0-v3` build-recipe domain and emit it in each manifest.
Historical manifests with no field default to `git-working-tree-v1` and retain
their original `m0-v2` recipe semantics. Unknown policy names refuse during
deserialization. Validate canonical sorted/unique inventory rows against the
declared policy before accepting source identities; v2 cannot list archived
outputs. The comparator independently checks the canonical digest, requires
the same normalized policy and recomputes the v2 scope-bound recipe.

This is an input/output boundary, not removal of a build dependency by fiat.
Any future compilation fixture must live in an ordinary reviewed fixture path.
Actual execution inputs, acquired bundles and imported disks retain their own
explicit receipt/hash validation. Final current builds must succeed with the
archival subtree absent. Whole-repository documentary inventories may retain
exact archive references separately without embedding their bodies in source
bundles. Existing dirty-tree/dirty-lock checks, old source pins and immutable
reports remain intact. No official release/publishing action is implied.

## Validation and claim boundary

Host tests cover preserved target flags, external and nested-root precedence,
unsupported EFI argument paths, ambient overrides, Kernel-only codegen policy
and commands outside the compiler boundary. Strict frontend checks remain
required. The existing one-host reproducibility command now also validates full
source/recipe identity, verifies every recorded artifact digest, compares all
binary components by their exact logical path within the cohort, and requires a
warm rebuild to match before the deliberate dirty-source negative. Its existing
clean two-clone gate and honest one-prepared-host scope remain. Context JSON/log
artifacts are verified and listed separately from target code. Missing, duplicate,
extra, stale-digest, escaping/symlinked artifacts and symbol/debug-only differences
have focused adversarial tests. Controlled experiments retain failures as well
as successful comparisons.

M6-03 additionally requires one frozen current source/input set, cold/warm and
clean-target builds at distinct paths, actual builds in both declared supported
Linux contexts, matching Kernel/loader/admitted-component/unsigned-image bytes,
and correctly bound usable symbols. Report exact contexts, commands, toolchain
inputs and all artifacts. A compiler probe, older baseline, equal loaded segments
or a shared recipe BuildID cannot satisfy that gate. New Kernel code generation
also needs the actual M6 admission/stack/runtime regressions before acceptance.

Retain new evidence through explicit immutable file/blob indexes and hashes.
Reference existing immutable reports by exact identity rather than embedding
their bodies recursively. This policy does not make the prepared toolchain or
host environment hermetic, retire EXC-0002 automatically, or authorize a public
release/signature/push.
