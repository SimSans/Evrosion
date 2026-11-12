# Current implementation roadmap

This roadmap applies accepted amendments to the
[E-025 scope](plans/roadmap/E-025-initial-scope.md), PRE-M0 and R-011. The table
records the original engineering checkpoint. This public technical edition has
its own source identity and validation; the [source map](plans/source-map.json)
records actual edition hashes and original source lineage.

| Gate | Current state | Scope |
|---|---|---|
| M0 — Toolchain & Boot | PASS, historical engineering | 21 PRE-M0 acceptance gates; [executed readiness](../docs/release/0.1-preview.md#validation-and-provenance) |
| M1 — Kernel Spine | PASS | [Combined acceptance](M1_ACCEPTANCE.md) and [executed readiness](../docs/release/0.1-preview.md#validation-and-provenance); bounded Internal runtime |
| M2 — Userspace | PASS | [Acceptance](M2_ACCEPTANCE.md) and [readiness](../docs/release/0.1-preview.md#validation-and-provenance): explicit authority, isolated services, typed RPC, ordinary/whole-graph restart and bounded IPC discipline |
| M3 — Persistence | PASS | [Acceptance](M3_ACCEPTANCE.md) and [readiness](../docs/release/0.1-preview.md#validation-and-provenance): scoped File/Object, interruption-safe durable subset, measured fault/progress rollback and independent owner recovery |
| M4 — Graphics | PASS | [Acceptance](M4_ACCEPTANCE.md): actual seven-process desktop, fresh-input picker, selected File reads, App/Shell recovery and matching surface isolation regression |
| M5 — Native Platform | PASS, bounded Internal | [Acceptance](M5_ACCEPTANCE.md): native lifecycle/data, exact grants, diagnostics/inspection, provider replacement and real System recovery |
| 0.1 developer preview | PASS, local engineering | [Readiness](../docs/release/0.1-preview.md#validation-and-provenance): coherent demonstration, current cumulative/security checks and fresh supported-Linux guide; owner release/publication separate |
| M6 /0.2 — Connected Developer Alpha | PLANNED | [Execution plan](M6_PLAN.md): interactive use, one virtual network path, authenticated update/recovery and one qualified physical target; all runtime gates TODO |
| Further user-value slices | DEFERRED | Work beyond the declared 0.2 scope selected from evidence and owner priority |
| ADR-0003.MIGRATION | DEFERRED | Preservation-first installer; journal, verify, retain source, explicit reclaim authority |
| ADR-0003.WINDOWS | DEFERRED | Bundled operational Windows runtime for ordinary-user releases; native independence |

Next is M6-02, sustained interactive operation. The
[road to 0.2](M6_PLAN.md) records dependencies, acceptance tests and future
hardware inputs. Runtime implementation has not started.

## Accepted clarification of older statements

- E-025.80 (“Compatibility Comes Later”) and E-025.118 define early implementation
  ordering. They do not make supported Windows compatibility optional in the
  eventual ordinary-user product. ADR-0003 supplies that later release obligation.
- E-022.1's native independence and on-demand activation remain unchanged. A
  bundled provider can remain inactive while only native apps are running.
- E-010/E-012.25/E-019 durable data, reinstall and recovery rules now explicitly
  include the foreign-OS migration design in ADR-0003.
- R-010's `.zion` supersedes the `.sion` spelling in older imports. The archived
  E-series files retain the old text as provenance, not current package naming.

No existing M0–M5 or 0.1 completion criterion changed. Ordinary-user readiness
gains explicit migration and bundled-compatibility product gates, with future
tests. No dates, complete Windows compatibility claim, implementation engine or
stable on-disk format are implied. Public M0 hosting/legal/trust gates are distinct
from M0 engineering and from a consumer release.
