# License policy

The founder approved formal application of the accepted R-006 license split to
this public source snapshot on 2026-11-12. The standard license texts and
file-level assignments are recorded in [LICENSES](LICENSES/README.md) and
[REUSE.toml](REUSE.toml). This policy explains their scope; it does not replace
the license texts or change third-party terms.

## First-party scope

| Material | License |
|---|---|
| Core software, services, applications, build/test tools and other first-party software outside the fixed interface roots below | GPL-3.0-only |
| Software, interface definitions and fixtures in the seven fixed roots below | Apache-2.0 |
| Eligible first-party documentation prose, including prose READMEs within interface roots | CC-BY-4.0 |
| Third-party dependencies, imported assets and their notices | Their recorded upstream terms; unchanged |

The fixed Apache-2.0 roots are:

```text
idl/
tools/idl/
libs/userspace-contract/
libs/userspace-runtime/
libs/app-identity/
libs/userspace-graphics/
libs/graphics/
```

This is an explicit list, not a rule that all libraries or future interfaces are
permissively licensed. In particular, the package parser/producer in `libs/zion`
and the `apps/hello` demonstration remain Core software. A license assignment
does not promote an Internal API to Preview or Stable or promise ABI compatibility.

File-level annotations distinguish software from prose. Existing third-party
license texts, notices and recorded provenance take precedence for the material
they cover. See the [dependency inventory](third_party/README.md) for both locked
Cargo graphs. Licensing the source does not certify production redistribution,
security, hardware or signed Official release status.

## Contributions and other legal instruments

Substantial external code is not mergeable until the R-006 contributor-rights
and provenance process is active. The current source license application does
not create a contributor agreement, copyright assignment, commercial license,
Foundation transfer or trademark/certification agreement. See
[CONTRIBUTING](CONTRIBUTING.md) and [LEGAL](LEGAL.md).
