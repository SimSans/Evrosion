# Audit action register

Extracted from the [Pre-M0 implementation package](plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This is the working canonical file; the imported package remains unchanged.

| ID | Required before | Implementation status | Location/next action |
|---|---|---|---|
| A-001 Root Authority | M2 | **Verified — bounded M2** | [Custody design](designs/ROOT_AUTHORITY_CUSTODY.md), [accepted AF-007A–H scope](M2_ACCEPTANCE.md) |
| A-002 Non-godlike AI | E-021 implementation | Deferred intentionally | AI annex before implementation |
| A-003 Durable grants | M5 | **Verified — bounded Native3 execution** | Four actual cold VMs (local engineering archive): explicit owner consent, durable publication/readback, cold fresh READ remint, live inhibit/stop/reap before tombstone and cold denial/cancel with unchanged disk. Fixed local trusted owner route; general enrollment/Trusted Control remains future scope. |
| A-004 TOCTOU-safe approval | Trusted picker or privileged approval | **Verified — bounded M4 selected READ** | [Approval binding](designs/PICKER_APPROVAL.md), [formal M4 acceptance/limits](M4_ACCEPTANCE.md); broader Trusted Control/destructive/AI approvals remain open |
| A-005 Time | M6 | **Verified — bounded M6 reference contracts** | M6 readiness and its canonical evidence bind actual signed-time/freshness, rollback/refusal, pause/refresh and cold trust-state tests under declared host/QEMU assumptions. Manual-session UTC qualification remains false; general trusted time and physical providers need separate proof. |
| A-006 Entropy | Security/networking | **Verified — bounded M6 reference source/consumer** | M6 readiness, [ADR-0071](adr/ADR-0071-private-random-generator.md) and [ADR-0074](adr/ADR-0074-reviewed-vm-random-source.md): actual reviewed VM source, private generator, accounting and missing-source refusal are qualified for this profile; arbitrary physical entropy and host independence are not established. |
| A-007 Users/sessions | Multi-user desktop | Deferred intentionally | X-003 |
| A-008 Suspend/resume | Laptop support | Deferred intentionally | X-004 |
| A-009 Virtualization | VM fallback | Deferred intentionally | X-005 |
| A-010 Encryption keys | Real user-data protection | Deferred intentionally | X-006 |
| A-011 Global text/IME | Consumer desktop | Deferred intentionally | X-007 |
| A-012 IPC deadlock | M2 service graph | **Verified — bounded M2** | [IPC design](designs/IPC_DISCIPLINE.md), [accepted AF-IPC-001–010 scope](M2_ACCEPTANCE.md) |
| A-013 Identity taxonomy | M5 | **Defined — bounded M5 taxonomy** | [Identity taxonomy](designs/IDENTITY_TAXONOMY.md): lifetimes, bindings, visibility, durable ownership and grant targets; future identity services remain deferred. Bounded A-003 execution is separately verified. |
| A-014 Boot health | M3 | **Verified — bounded M3** | [Initial boot-health contract](designs/BOOT_HEALTH.md), [acceptance and limits](M3_ACCEPTANCE.md); exact Started/probation/KnownGood criteria, actual fault/progress and owner execution, plus cumulative regression |
| A-015 Governance files | Serious implementation growth | Files extracted | [Governance](GOVERNANCE.md), registers, templates and validator added in Slice 0 |

“Designed” does not mean implemented or tested. Other annex names in this table
are planned work, not existing files.
