# Release and project direction

Technical publication editions of the eight R-series packets are available in
[release-project](../plans/release-project/). Their hashes are recorded in the
[source map](../plans/source-map.json). The privacy supplement remains separate and unnumbered.

| Source | Direction relevant now |
|---|---|
| [R-001](../plans/release-project/Evrosion_R-001_Economic_Independence_v1.md), [R-002](../plans/release-project/Evrosion_R-002_Founder_Stewardship_Foundation_Governance_v1.md) | Economic independence and founder stewardship |
| [R-003](../plans/release-project/Evrosion_R-003_Official_Releases_Distribution_Updates_and_Release_Trust_v1.md), [R-004](../plans/release-project/Evrosion_R-004_Security_Vulnerability_Disclosure_and_Incident_Response_v1.md) | Release trust, updates, vulnerability disclosure and incidents |
| [R-005](../plans/release-project/Evrosion_R-005_Public_Release_GitHub_and_Community_Growth_v1_2.md) | Public release and community growth: GitHub as the whole public home until about 0.9; repository public after M0 once publication prerequisites are ready; 0.1 as a Developer Preview; reviewable contributions with human accountability |
| [R-006](../plans/release-project/Evrosion_R-006_Licensing_Contributor_Rights_and_Trademark_Policy_v1.md) | Licensing/contributor/trademark direction; approved source license split; separate contributor and legal instruments remain pending |
| [R-007–R-011 superfile](../plans/release-project/Evrosion_R-007_to_R-011_Superfile_v1.md) | Git workflow, project context, documentation and distinct engineering/public/preview gates |
| [Certified Privacy & Diagnostic Integrity](../plans/release-project/Evrosion_Certified_Privacy_Diagnostic_Integrity_v1.md) | Local operation and explicit diagnostic authority |

R-010 confirms Git/Markdown as canonical and a compact tracker as the status
index. The existing architecture index remains the entry point for architecture.
The later packets use `.zion` as the application format name, superseding
`.sion` in older imported plans. No application format is implemented by M0.

R-011 separates M0 engineering acceptance, public M0 readiness and the 0.1
developer preview. A kernel boot proves neither a complete milestone nor a
public release. R-006 design acceptance does not itself apply a license to
existing first-party files or create binding contributor/legal agreements.

## Product amendment

The owner supplied the [Data Migration and Windows Compatibility amendment](../plans/amendments/Evrosion_Data_Migration_and_Windows_Compatibility_Amendment_v1.md)
on 2026-09-21. It is integrated by [ADR-0003](../adr/ADR-0003-preservation-and-bundled-compatibility.md),
the [canonical design](../designs/INSTALLATION_AND_COMPATIBILITY.md) and
[current roadmap](../ROADMAP.md).
It preserves M0–M5 and the 0.1 engineering scope. Product implementation is deferred.

Its local A-001/A-002 headings collide with existing audit-action identifiers.
Use ADR-0003.MIGRATION and ADR-0003.WINDOWS as the unambiguous tracker references.
The amendment's local headings do not replace the existing A-001 custody action.
No installer, partition migration or Windows runtime implementation is started.

## Distinct release gates

| Gate | Required evidence and scope |
|---|---|
| M0 engineering | PRE-M0 acceptance; PASS at frozen tag `m0` |
| Public M0 release | Separate R-011/R-003/R-006 repository, licensing, provenance and release-trust work; local acceptance alone is insufficient |
| Evrosion 0.1 developer preview | E-025 native architecture proof; broad migration/Windows support is not added to this gate |
| Ordinary-user/general-use release | Native readiness plus evidence for preservation-first installation and an operational bundled Windows runtime for the declared supported app set |

Ordinary-user migration evidence must cover journaling, interrupted recovery,
verified personal data, source preservation and explicit owner authorization
before reclaiming the old OS. Compatibility evidence must cover launch after a
fresh install, tested app/API coverage, authority/isolation and native independence.
The two product requirements remain DEFERRED until those proofs exist.

E-025's “later” compatibility statements retain their early ordering meaning;
any interpretation as optional forever for ordinary-user releases is superseded
by ADR-0003. Bundling does not require always-running compatibility daemons.
