# Current implementation roadmap

This working roadmap applies accepted amendments to the preserved
[E-025 scope](plans/roadmap/E-025-initial-scope.md), PRE-M0 and R-011. Imported
sources are historical. The source map identifies the actual public planning editions.

This table tracks implementation checkpoints. The complete architectural
direction continues through [E-026](plans/roadmap/E-026-long-term-architecture.md),
the E/R documents and [foundations](plans/foundations/foundational-requirements.txt),
mapped by the [architecture index](ARCHITECTURE_INDEX.md). The absence of a later
release row does not mean the architecture is unwritten.

| Gate | Current state | Scope |
|---|---|---|
| M0 — Toolchain & Boot | PASS, tag `m0` | 21 PRE-M0 acceptance gates; executed readiness |
| M1 — Kernel Spine | PASS | [Combined acceptance](M1_ACCEPTANCE.md) and executed readiness; bounded Internal runtime |
| M2 — Userspace | PASS | [Acceptance](M2_ACCEPTANCE.md) and readiness: explicit authority, isolated services, typed RPC, ordinary/whole-graph restart and bounded IPC discipline |
| M3 — Persistence | PASS | [Acceptance](M3_ACCEPTANCE.md) and readiness: scoped File/Object, interruption-safe durable subset, measured fault/progress rollback and independent owner recovery |
| M4 — Graphics | PASS | [Acceptance](M4_ACCEPTANCE.md): actual seven-process desktop, fresh-input picker, selected File reads, App/Shell recovery and matching surface isolation regression |
| M5 — Native Platform | PASS, bounded Internal | [Acceptance](M5_ACCEPTANCE.md): native lifecycle/data, exact grants, diagnostics/inspection, provider replacement and real System recovery |
| 0.1 developer preview | PASS, local engineering | Readiness: coherent demonstration, current cumulative/security checks and fresh supported-Linux guide; owner release/publication separate |
| M6 /0.2 — Connected Developer Alpha | PASS, bounded local VM engineering | Readiness: sustained interaction, scoped virtual networking, authenticated downloaded execution, signed update/offline recovery, two-Linux reproduction and preserving Main integration; physical M6-09 explicitly deferred |
| Accepted 0.2 stabilization | PASS, bounded engineering | Current record: alignment, measured IPC limit, improved stack margins, independent qualification and usable graphical walkthrough |
| M7 /0.3 native document workflow | PASS, bounded VM engineering | [Owner-selected plan](M7_PLAN.md): explicit selected-document editing, accessible contracts, durable save/reopen and failed-update recovery; progress |
| M8 /0.4 — Recoverable Native Desktop Workspace | ACTIVE; integrated qualification incomplete | [Substantial checkpoint plan](M8_PLAN.md): real files/folders, larger documents, concurrent native windows, three-layer controls, semantic accessibility, service/update recovery and native developer/build path |
| ADR-0003.MIGRATION | DEFERRED | Preservation-first installer; journal, verify, retain source, explicit reclaim authority |
| ADR-0003.WINDOWS | DEFERRED | Bundled operational Windows runtime for ordinary-user releases; native independence |

M6-01 through M6-08 and M6-10 pass in the declared virtual scope on 2026-11-15.
The owner-approved [virtual acceptance amendment](plans/amendments/2026-11-12-m6-virtual-acceptance.md)
defers physical qualification; it is not a physical PASS. The accepted snapshot
and historical proofs remain intact while separately qualified stabilization
results are separately recorded. The public [implementation status](../docs/status/PROJECT_STATUS.md)
records current scope. Public release, official signing and general Kernel/Root replacement are
separate gates.

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
