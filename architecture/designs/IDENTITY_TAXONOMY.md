# Identity taxonomy

Status: **Defined — bounded M5 identity taxonomy**, 2026-11-11. This completes
A-013's documentation outcome; it does not claim future identity services.
Bounded A-003 runtime acceptance has its own separate execution evidence.

The [original identity audit/action A-013](../plans/reviews/full-architecture-audit-v1.md)
and [Pre-M0 register](../plans/roadmap/PRE-M0-implementation-package-v1.md) ask which
identities are stable/reboot-local, cryptographically bound/user-visible, may own
durable state and may be targets of grants. These are separate questions.
An identity names something; possession of its byte encoding grants no rights.
Kernel-managed actual capabilities authorize operations. Publisher signing,
package compatibility, diagnostics, source hashes and permission policy are not
interchangeable with such capabilities.

| Class / actual representation | Lifetime and persistence | Binding and presentation | Durable ownership / grant use |
|---|---|---|---|
| Machine | Planned persistent machine principal; current controlled QEMU profile does not implement production machine enrollment. Device replacement/clone lifecycle remains future explicit policy. | No TPM/attestation claim. A disk volume ID or build digest is not authenticated Machine identity. User-visible device name will be a label. | May eventually scope machine configuration. Current fixed profile must not mint grants merely from a claimed machine name. |
| User / current `ev_picker::UserId` | Stable intended owner principal. Current proof uses one fixed local `EVROSION-OWNER01`; no multi-user login/enrollment/recovery-key service is claimed. | Actual trusted owner-UART/picker route supplies current owner; nonzero 16-byte constructor does not authenticate anyone. A display name is separate. | May own app data/configuration and durable grant policy. Subject/approver must be explicit; claimed UserId never substitutes for actual trusted owner context. |
| Login/session / `SessionId`, Root bootstrap epoch/incarnation | Runtime session/Root-incarnation context. Expires on its defined logout/restart/boot boundary; never serialized as a permanent permission. Current bootstrap projection is boot-local, not claimed globally unique across all physical boots. | Actual trusted bootstrap/execution context supplies it. Diagnostic bytes are not a capability or authentication secret. | Owns temporary approvals/leases, not the durable grant itself. A new session revalidates durable policy and obtains fresh live authority. |
| AppIdentity / `ev_app_identity::AppId` | Stable 16-byte app key across rename/update/process replacement. Distinct from package, release version, current image, publisher or user installation. | Bound by trusted actual package/installation/provenance checks; a package's claim cannot take over an existing namespace. Show readable name plus identity when useful. | Can name app-private namespace and durable policy subject. Actual user/install/package checks and capabilities govern access. Stable ID alone is not permission. |
| Immutable package / `ev_zion::PackageId`, version and publisher claim | Package ID is the digest of a complete immutable container; changes with content. Version is release metadata; publisher identity/claim remains separate. | Exact package bytes/hash/parser and real ELF admission establish content binding; owner development is distinct provenance, not a forged signature. Current Internal integrity is not production publisher authentication. | Immutable package may be retained by activation/rollback refs. Declarations request capabilities; they do not grant them. Initial remembered READ pins the full package ID deliberately. |
| Service identity / measured image + role/contract | Logical service/contract can remain stable while actual process changes. Each running service has a new actual Process/Thread/Job incarnation. | Actual measured ServiceImage/role/ABI admission and typed contract endpoint establish binding. Display names do not select an authorized process. | Service state has an explicit trusted owner; live endpoint/CONTROL caps authorize interaction. Persisted service policy reconstitutes fresh endpoints, not saved handles. |
| Driver package / image/package/ABI | Immutable package/build identity; live driver/device binding is incarnation-local and replaceable under recovery rules. | Exact executable/descriptor and device assignment are separate from a driver name. Current controlled PIO proof is not broad hardware or DMA isolation. | May have explicit driver configuration; no authority follows from a package claim. Actual device/IO/memory capabilities authorize each live driver. |
| Extension identity / declarative extension manifest | Planned stable logical extension identity, distinct from its immutable package/build, the contracts it provides and its current process. General identity allocation/registry is not implemented by the bounded provider fixture. | Trusted actual package/manifest/provenance admission must bind the claim. A declared extension name or provides-list alone is not authority. | May name explicitly owned private versioned state and configuration under E-024/E-019. It receives only deliberately routed/invocation-scoped capabilities, with no accidental host authority. |
| Extension Point / versioned contract identity | Contract name+major semantics may be stable across provider updates; binding/configuration lifetime is separate. The 0.1 test is one contract, not a public registry. | Exact actual contract/version/schema compatibility, not name-only discovery. Provider selection is SourceRoot policy. | Durable binding, where implemented, is a distinct policy state type using common durability. Discovery and contract identity grant nothing. |
| Provider identity / actual measured A/B image and live process | Package/image identity can persist; chosen live receiver/process is replaceable. Consumer's live SEND endpoint can remain stable across A→B. | Actual process/image descriptor and authorized endpoint binding establish execution; consumer need not know implementation changed. | Does not inherit arbitrary durable state or grants by sharing a contract string. Binding owner explicitly chooses provider and retires old authority. |
| Compatibility realm | Future explicit isolation/namespace identity; no foreign compatibility runtime is required or claimed by 0.1. | Planned realm identity must be bound to actual authorized realm/job/service and owner policy; foreign SID/path/name alone is not native authority. | A realm may own scoped state/configuration. Cross-realm grants remain explicit native capabilities; do not create ambient global storage. |
| AI session / action context | Future short-lived delegated session/action identity. Normally ephemeral unless owner explicitly promotes a durable policy under its own rules. | Actual authorized invocation/session and canonical action approvals, not generated text, would establish provenance. No 0.1 AI service is implied. | Does not own permanent broad authority by default. AI-generated instructions are not consent; only explicit bounded capabilities/action grants authorize effects. |
| Build ID / measured build input + actual ELF/package identities | Concrete build provenance, distinct from stable AppId and human release version. Can be retained for diagnostics/reproduction. Native3 App package build identity binds its actual content independently of unrelated OS/document inputs; the full OS source recipe remains separately recorded. | Full actual source/artifact hash binding, with stated Internal signing/provenance maturity. A digest authenticates neither publisher nor owner. | Owns no permission. Build changes require compatibility/ref retention, not app-data erasure or namespace takeover. Record it in crash/inspection artifacts. |
| System Generation / `ev_store::GenerationId` + coherent immutable manifest | Concrete bootable system cohort; admitted boot serial/incarnation is runtime-local. Protected Known Good is a generation whose declared health passed, not simply a higher counter or release label. | Actual kernel/Root/images/ABI/health manifest and admitted execution/health reports must match; checksums/host expected values are not health. | Owns replaceable system content. Durable user/app/policy state is separate and survives rollback. Grant availability is revalidated in the returned actual system. |
| Store creation context | Persistent format/creator provenance of one namespace, not an admitted running System Generation. | Existing Native format context names catalogue/creator; explicit `format-context-only; no admitted health`. It does not promote Known Good. | Must not become stable AppId or replace current Root admission. Long-lived namespaces need explicit stable owner/schema compatibility across component replacement. |
| Stable File object / `VolumeId` + local object ID + revision counter/content SHA | Object identity can persist across reboot; revision identifies content/version. Paths/labels/LBAs are different concepts. | Trusted File-owner metadata plus exact endpoint/object binding; checksum of a supplied tuple is not authority. | Durable grant may name this resource/scope. Actual File READ endpoint cap grants only the bounded object/method; no sibling selector or raw disk rights. |
| Durable grant / scope+grant serial+policy revision+record digest | Explicit UntilRevoked policy survives session/boot; revision/tombstone/latest authoritative index prevent stale in-process policy reuse. The bounded Native3 proof pins owner/App/package/object/revision and executes cold remint and revocation. | Actual remembered consent and sole trusted Store publication, not arbitrary copied EVGINT01 bytes. Media checksums do not solve malicious whole-disk snapshot rollback. | Grants no live access by itself. Trusted activation revalidates current subject/resource/source authority and mints a fresh revocable runtime branch. |
| Live Process/Thread/Job and capability handles | Kernel-registry incarnation-local runtime objects. Reuse/stop/reap invalidates old authority under actual generational/domain checks. Diagnostic numeric IDs may be retained in records but never accepted as CONTROL. | Actual scheduler/Registry-derived caller and installed live capability; no user-supplied PID lookup as authority. | Jobs account resources and own runtime descendants. A saved numeric handle cannot own or recreate durable rights. Fresh activation uses actual capabilities. |

Three consequences for current implementation:

1. Cold remembered-grant activation accepts a **new actual incarnation** after
   owner/App/package/resource/latest-policy validation; it never resurrects an old
   session/ProcessCONTROL/endpoint handle. Remove/revoke semantics remain explicit
   and app-private data survives ordinary rollback/reinstall.
2. A generation rollback changes running system implementation, not the durable
   identity of the owner's documents or app data. Native3 separates App content
   identity from the OS source recipe ([ADR-0052](../adr/ADR-0052-native-system-health-and-durable-owner-grants.md)).
   Changed package content still requires retention/compatibility handling; it
   never permits resetting the owner's data.
3. Inspector/crash artifacts must label actual generation/admission availability.
   Use unavailable/not-admitted where appropriate rather than invent a healthy
   generation from Native Store creation Generation1 or a GUIReady marker.

This annex completes A-013's required lifetime/persistence/binding definitions.
Actual implementation and evidence still determine which bindings are proved.
Deferred Machine/login/realm/AI infrastructure is not fabricated or made an extra
0.1 feature requirement. The A-003 execution proof (local engineering archive)
separately verifies explicit consent, durable publication, cold fresh-capability
delivery, live revocation and cold denial in four actual VMs. This is a bounded
fixed-owner proof; it does not implement production enrollment or Trusted Control.

## Sources and implementation boundaries

- [Glossary](../glossary.md), [invariants](../INVARIANTS.md) and
  [security/permissions E-009](../plans/core/E-009-security-and-permissions.txt)
  define identity versus authority, owner control and explicit capability grants.
- [Application model E-016](../plans/experience/E-016-application-and-software-model.txt)
  and [lifecycle E-019](../plans/platform/E-019-update-and-lifecycle.txt) separate
  stable app identity, immutable content, user data and system implementation.
- [Modularity E-024](../plans/core/E-024-modularity-and-extensibility.md), especially
  .12/.19–.23/.93, distinguishes extension manifest identity, immutable package,
  stable typed Extension Point and separately authorized Provider Binding.
- [ADR-0048](../adr/ADR-0048-internal-zion-package-and-activation-metadata.md) and
  [ADR-0049](../adr/ADR-0049-native-root-package-banks-and-durable-app-state.md)
  define the bounded actual AppId/package/lifecycle/data representation.
  Native lifecycle execution (local engineering archive)
  proves its exact retained six-phase cohort, not future grant runtime behavior.
- Actual types are [AppId](../../libs/app-identity/src/lib.rs),
  [picker identity/approval metadata](../../libs/picker/src/lib.rs),
  [durable policy intent](../../libs/picker/src/intent.rs),
  [package/lifecycle metadata](../../libs/zion/src/lib.rs),
  [app-private data](../../libs/app-registry/src/app_data.rs),
  [Store generation/admission types](../../libs/store/src/lib.rs), and
  [durable grant-policy bridge](../../libs/grant-policy/src/lib.rs).
- [Selected-file approval](PICKER_APPROVAL.md) defines the actual fixed owner,
  immutable permission revision 1 and incarnation-local M4 READ proof. It leaves
  durable grants and general Trusted Control open. [Boot health](BOOT_HEALTH.md)
  defines actual Started/probation/KnownGood separately from creation provenance.
