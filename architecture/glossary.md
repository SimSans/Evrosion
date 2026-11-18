# Glossary

Extracted from the [Pre-M0 implementation package](plans/roadmap/PRE-M0-implementation-package-v1.md) on 2026-09-20.
This is the working canonical file; the imported package remains unchanged.

| Term | Canonical meaning |
|---|---|
| Absolute Access | Layer 3 owner mode; permits deliberate system-level authority after explicit warning. It is not ambient root. |
| ABI fingerprint | Generated identifier for a concrete binary contract layout/toolchain combination. |
| AppIdentity | Stable identity assigned to a packaged application, distinct from its package/build/publisher or live process; identity alone grants no rights. See [identity taxonomy](designs/IDENTITY_TAXONOMY.md). |
| Architecture Fitness Test | Executable test that continuously checks an architectural claim. |
| Authority | The right to perform an operation on an object or service. |
| Bootstrap Authority Custodian (BAC) | Kernel-owned, sealed custody object containing the canonical roots from which one Root Supervisor incarnation is authorized. |
| Bootstrap Manifest | Immutable, measured description of the initial userspace image, bootstrap objects, rights and resource limits. |
| Build ID | Concrete build provenance/content identity, separate from stable AppIdentity, human release version and runtime authority. |
| Capability | Unforgeable kernel-managed reference to an object plus rights and constraints. |
| Capability lineage | Parent/child derivation relationship used to prove non-amplification and perform revocation. |
| Compatibility Capsule | Versioned adapter preserving an older platform contract without freezing its implementation inside the native core. |
| Compatibility Cohort | Components that must activate and roll back together. |
| Contract | Versioned typed boundary between components. |
| Durable grant record | Persistent policy record from which fresh runtime capabilities may be minted after validation. It is not a serialized capability handle. |
| Durable User State | Personal data and intentionally supported app/user configuration, separate from replaceable System Generations and retained through normal reinstall/recovery/rollback. |
| Evrosion Release | Human/project release identity, distinct from a concrete installed generation. |
| Failure Capsule | Structured diagnostic bundle describing a failure, its causal context and relevant bounded state. |
| Flight Recorder | Bounded rolling diagnostic buffer designed to preserve recent events around failure. |
| Generation | Immutable versioned collection of deployable system content. |
| Job | Hierarchical ownership, accounting, lifetime and resource-policy container for processes and child Jobs. |
| Known Good | A System Generation that passed declared health gates and is retained as a rollback target. |
| Login Session | Runtime user/session context; distinct from durable user identity and never a serialized capability or permanent grant. |
| Memory Object | Kernel object representing memory that can be mapped or shared only through capabilities. |
| Migration Source State | Original OS, data, disk layout and recovery references retained until migration verification, Evrosion health checks and explicit owner authority permit reclamation. |
| Ordinary-user release | General-use product release with tested native readiness plus the preservation/migration and bundled Windows product gates; distinct from 0.1 architecture-proof preview. |
| Package identity | Digest of a complete immutable package container; separate from stable AppIdentity, publisher claim, version and live image/process identity. |
| Platform API Level | Human-facing compatibility level for the supported developer platform surface. |
| Preview API | Deliberately exposed but not yet Stable contract; migration is expected. |
| Protection domain | Isolation boundary with its own address space and authority set. |
| Provider Binding | Authorized selection of a provider for an extension point; distinct from discovery. |
| Root Incarnation | One active execution epoch of the Root Supervisor. |
| Root Supervisor | First userspace supervisor. It builds and monitors the initial service graph using an explicitly bounded bootstrap authority set. It is not a Unix root account. |
| Secure Attention | Unspoofable transition into the trusted control environment. |
| Stable API | Contract backed by compatibility tests and a declared compatibility policy. |
| System Generation | Concrete immutable bootable system implementation. |
| Trusted Control | OS-owned environment for sensitive approvals and recovery actions. |
| Windows Compatibility Runtime | Replaceable userspace provider/realms for supported Windows software, bundled for ordinary-user releases and activated on demand without native-app dependency. |
| `.zion` | Current native package format name under R-010; older imported `.sion` spellings are historical. No Stable format is established by M0. |

Product terms above follow [ADR-0003](adr/ADR-0003-preservation-and-bundled-compatibility.md).
Identity lifetimes, bindings, visibility, durable ownership and grant semantics
are defined in the [identity taxonomy](designs/IDENTITY_TAXONOMY.md). It distinguishes
implemented bounded types from future Machine/login/realm/AI services.
