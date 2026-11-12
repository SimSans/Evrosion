# Licenses

The founder approved formal application of the accepted R-006 split to this
public source snapshot on 2026-11-12. [LICENSE_POLICY.md](../LICENSE_POLICY.md)
explains the fixed scope; [REUSE.toml](../REUSE.toml) records file-level assignments.
Cargo packages remain `publish = false`; source licensing does not promise a
Stable API or authorize an Official signed image release.

- [GPL-3.0-only](GPL-3.0-only.txt): first-party Core software outside the fixed
  interface subset.
- [Apache-2.0](Apache-2.0.txt): first-party software/interfaces in `idl/`,
  `tools/idl/`, `libs/userspace-contract/`, `libs/userspace-runtime/`,
  `libs/app-identity/`, `libs/userspace-graphics/` and `libs/graphics/`.
- [CC-BY-4.0](CC-BY-4.0.txt): eligible first-party documentation prose, including
  prose within the interface subset.

These are standard license texts. Existing third-party notices, source assets
and license texts retain their upstream terms. No homemade license, CLA, ECA,
commercial license or trademark/certification agreement is created here.
Substantial outside code contributions remain subject to the unfinished R-006
contributor-rights process described in [CONTRIBUTING](../CONTRIBUTING.md).

## Third-party material

The [dependency inventory](../third_party/cargo-dependencies.json) records both
locked Cargo graphs, exact resolved packages/checksums, upstream declarations,
notice hashes and local license paths. Texts under `LICENSES/third-party/` were
copied unchanged from their recorded upstream sources. The inventory documents
shared bootloader repository licenses, the usize_conversions declaration with a
standard Apache text, and the Noto bitmap/glyph notices. See
[inventory details](../third_party/README.md).

For new dependencies, record the exact version/source, license, provenance,
required notices, use and replacement scope before redistribution. Preserve
upstream attribution and license texts. The inventory is not a standards SBOM or
a complete production redistribution audit; binary release packaging and
project-specific legal instruments remain separate work.
