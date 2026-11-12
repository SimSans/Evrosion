# Evrosion R-003 — Official Releases, Distribution, Updates & Release Trust

**Status:** ACCEPTED DESIGN DIRECTION  
**Series:** R — Release, Project & Sustainability  
**Decision:** R-003

> **Core rule:** “Official Evrosion” is a cryptographic property, not a logo, filename, website claim, or UI string.

## 1. Purpose

R-003 defines what makes a build official, how users verify Evrosion, how official updates are distributed, how Stable and Experimental/Beta differ, how rollback works, and how update behavior changes across Layers 1–3.

The goals are:

- simple trust for ordinary users;
- independent verification for technical users;
- open forks/custom builds;
- strong resistance to impersonation;
- safe, recoverable updates;
- reproducible official releases;
- no update-driven telemetry;
- no loss of owner control.

## 2. Trust terminology

### Official Evrosion Release
A build whose artifacts and release metadata are authenticated by the official Evrosion release trust infrastructure.

“Official” means **Evrosion actually released this exact artifact**.

### Stable Release
An Official Evrosion release that passed Stable release gates and belongs to the normal supported Stable channel.

### Experimental / Beta Release
An Official Evrosion pre-release build from the public development channel. It is authentic Evrosion software, but explicitly less tested and outside the normal Stable support/certification envelope.

### Evrosion Certified Device
A device/configuration satisfying separate Evrosion hardware/software certification requirements.

An official Stable image on generic hardware is official software, but the hardware is not automatically Evrosion Certified.

### Unofficial / Owner-Modified
A fork, local build, modified image, custom kernel, or other system not authenticated as an official Evrosion release.

“Unofficial” does not mean malicious. It means Evrosion did not sign that exact artifact as an official release.

## 3. Official locations are discovery, not the root of trust

Official releases should be published through the Evrosion website, official GitHub/source organization, and future mirrors/update infrastructure.

However, hosting location alone does not make an artifact official.

A compromised website, GitHub account, CDN, or mirror must not be enough to create a trusted Evrosion release.

## 4. Cryptographic release identity

Every official release must carry authenticated metadata binding at least:

- release identity;
- channel;
- System Generation;
- architecture/platform target;
- source revision;
- Build ID;
- artifact hashes and sizes;
- build/provenance identity;
- relevant API/compatibility identities;
- release metadata version.

Changing the artifact or authenticated metadata must invalidate the proof of official origin.

## 5. Trust chain

Conceptually:

```text
trusted Evrosion release root
        ↓
authenticated release/update metadata
        ↓
authenticated boot/install artifact
        ↓
verified boot stage where supported
        ↓
Evrosion System Generation
        ↓
Trusted Control reports actual trust state
```

On appropriate hardware, UEFI Secure Boot or an equivalent verified-boot mechanism should authenticate the first Evrosion boot component before execution.

## 6. Forks remain allowed

A Layer 3 owner or downstream fork may replace/remove Evrosion verification, install another trust root, or build a custom system.

That is allowed.

It simply changes the trust state:

```text
Official Evrosion: NO
Trust: Owner Modified / Unofficial
```

Removing verification does not magically create an official build.

## 7. UI text is not proof

A malicious fork can draw “Official Evrosion ✓” in its own UI.

Therefore official status must come from the trusted release/boot chain and, where applicable, Trusted Control/Secure Attention rather than normal application text.

## 8. Self-verification bootstrapping problem

An untrusted installer cannot reliably prove itself honest.

If malicious code is already running before verification, it can simply modify the verifier to display “valid.”

Therefore Evrosion must support multiple verification paths:

### Platform-verified path
Certified/configured firmware authenticates the Evrosion boot image before it executes.

### External verification path
Before reboot/wipe, the user verifies the image using an official Evrosion writer/verifier, an existing trusted Evrosion installation, standard cryptographic tools, or another trusted device.

### Unverified boot path
If neither exists, the installer must not falsely claim hardware-backed authenticity.

## 9. Offline verification

Basic authenticity verification must not require internet access.

A legitimate image can carry signed release metadata and be verified against a previously trusted Evrosion public root before disk modification begins.

Conceptually:

```text
boot installer
→ verify trusted signature information
→ show result
→ only then allow destructive disk changes
```

## 10. Online verification adds freshness

Network access may additionally determine:

- revoked/replaced signing keys;
- withdrawn releases;
- newer trust metadata;
- obsolete releases;
- newer updates.

Therefore:

```text
offline = authenticity under locally trusted root
online  = authenticity + current freshness/revocation knowledge
```

These must not be misrepresented as the same guarantee.

## 11. Invalid/unverified installer

If official verification fails, show a serious warning.

Owner sovereignty remains intact: where technically possible, the owner may deliberately **Proceed Anyway**.

The result remains unofficial/owner-modified. An override cannot manufacture an Evrosion signature.

## 12. Update security is more than signing a binary

A correctly signed artifact can still be old, replayed, from the wrong channel, or mixed with inconsistent metadata.

The official updater therefore needs signed repository-state metadata with protections equivalent in purpose to TUF:

- trusted root metadata;
- authenticated targets;
- consistent repository snapshots;
- freshness/timestamp information;
- versioning;
- expiration;
- key rotation/revocation;
- optional signature thresholds/role separation.

Exact implementation is deferred.

## 13. Required update-threat protections

The updater should defend against:

- artifact tampering;
- compromised mirrors/CDNs;
- rollback to obsolete vulnerable releases;
- freeze attacks;
- mix-and-match repository states;
- signing-key compromise;
- Stable/Beta channel substitution.

## 14. Local rollback is different from a malicious rollback attack

Evrosion intentionally supports:

```text
new Generation fails
→ return to local Known Good
```

That is authorized recovery.

The updater must distinguish this from a remote source falsely presenting an old release as current.

## 15. Stable and Experimental signing are separated

Stable and Experimental/Beta must use distinct authenticated release roles/identities.

Compromise of Beta release authority must not automatically authorize a Stable release.

## 16. Signing security

Stable signing credentials are high-value security infrastructure.

Locked principles:

- protect Stable credentials more strongly than normal developer credentials;
- never keep them casually in source control;
- do not expose them to arbitrary CI jobs;
- separate Stable and Beta identities;
- support rotation/revocation;
- define compromise recovery before mature public Stable releases.

Exact use of hardware tokens, offline keys, threshold signing, etc. is deferred.

## 17. Root-of-trust recovery

Before large public distribution, Evrosion must define how to recover from compromised signing authority, including:

- key replacement;
- revocation;
- authenticated trust-root succession;
- withdrawal of bad releases;
- out-of-band recovery if the highest trust root is catastrophically compromised.

## 18. Reproducible releases

Official Stable releases must be reproducible.

Given the defined source, build environment, dependencies and instructions, independent parties should be able to recreate bit-for-bit identical canonical unsigned release artifacts.

Signing/provenance remains a separate step.

## 19. Why reproducibility matters

A signature proves:

> Evrosion approved this artifact.

It does not alone prove:

> This binary corresponds to the public source.

Independent reproducibility checks that second claim.

A mismatch is a release-security incident until explained.

## 20. Build provenance

Stable releases should publish machine-readable provenance identifying:

- source revision;
- build process;
- builder identity where applicable;
- build inputs/dependencies;
- toolchain/build-environment identities;
- final artifact digests.

SLSA/in-toto style provenance is the preferred precedent. Exact format remains replaceable.

## 21. Future release transparency

At meaningful scale, Evrosion should strongly consider an append-only public transparency log for release/signing events.

This would allow independent observers to detect unexpected signing events.

Sigstore/Rekor is a useful precedent, but no specific transparency-log implementation is locked here.

## 22. Official release manifest

Every official release should publish a manifest containing or referencing:

- human release version;
- System Generation;
- Platform API Level where applicable;
- source revision;
- Build ID;
- architecture;
- channel;
- artifact hashes;
- provenance;
- release notes;
- known issues;
- required migrations;
- security relevance;
- optional component changes.

This preserves E-026's rule that Release, System Generation, API level, ABI identity and other version identities are not one overloaded number.


## 23. Channels

Evrosion begins with only two public channels:

### Stable
Normal supported releases for ordinary use.

### Experimental / Beta
One explicit opt-in pre-release stream for developers, testers and enthusiasts.

No needless maze of nightly/canary/insider tiers unless future evidence justifies it.

Both Stable and Experimental/Beta remain open source and publicly cloneable/buildable.

A future paid developer product may sell infrastructure/services, never source-code access.

## 24. Beta is opt-in

Experimental/Beta must never silently become the normal user's channel.

It should be clearly labeled as less tested.

Layer 1 should not casually expose Beta as a normal update choice; Beta belongs in advanced Layer 2/3 workflows unless later evidence supports another design.

## 25. Stable release gates

Stable promotion eventually requires an appropriate set of:

- build success;
- architecture fitness tests;
- subsystem tests;
- update and rollback tests;
- storage/durability tests where relevant;
- reproducibility checks;
- provenance generation;
- release metadata/signing;
- security checks;
- QEMU/hardware regression tests;
- known-issue review.

The gate grows with Evrosion maturity. M0 does not require enterprise ceremony.

Experimental builds may have lighter gates, but “experimental” must never mean arbitrary unreviewed binaries under the official signing identity.

## 26. Layer 1 update behavior

Layer 1 is fully automatic by default:

```text
discover
→ authenticate
→ download
→ verify
→ stage
→ checkpoint
→ activate at a safe opportunity
→ health-check
→ commit or rollback
```

Layer 1 users should not be repeatedly asked technical update questions.

Automatic does **not** mean Evrosion may destroy active unsaved work or reboot recklessly.

## 27. Layer 2 update behavior

Layer 2 proactively offers authenticated Stable updates:

```text
Install Now
Later
Skip
Details
```

The UI should explain security fixes, reliability fixes, driver/hardware changes and optional new features.

Security urgency may be strongly communicated, but the owner retains the choice.

## 28. Layer 3 update behavior

Layer 3 is fully manual by default:

- no automatic update checks;
- no automatic downloads;
- no update push notifications;
- no automatic activation;

unless the owner explicitly enables them.

Layer 3 owners may pin generations, use official Stable/Beta, custom repositories, local packages or custom trust roots.

## 29. Update privacy

Update checking must not become disguised telemetry.

Requests should include only what is technically necessary, such as architecture/platform class, channel and compatibility identity.

Avoid unnecessary stable device IDs, user identities, app inventories or behavioral history.

Network operators will inevitably observe incidental transport data such as IP addresses; R-003 does not pretend otherwise.

## 30. Continuous Stable evolution

Evrosion prefers one continuously advancing Stable platform composed of health-gated System Generations.

Major human-facing versions such as 1.0 → 2.0 may mark milestones, but they should not automatically create separate permanent servicing forks.

The user should not need to reinstall or repurchase Evrosion merely because the marketing version changes.

## 31. Core vs optional updates

### Core platform
Kernel, recovery, security infrastructure, core runtime, required services/contracts, migrations and update machinery move coherently where correctness requires it.

### Optional features/components
New apps, optional UI experiences, optional AI/services, themes and nonessential tools may be installed, skipped, removed or deferred where safe.

## 32. Avoid infinite component combinations

Evrosion must not promise support for arbitrary combinations such as:

```text
old kernel + new storage + old security service + new ABI
```

Core compatibility cohorts/System Generations remain coherent.

Optionality is preserved only where dependency/security constraints permit it.

## 33. Long-gap upgrades

A machine may stay offline for years.

Prefer recovery/migration rather than forced reinstall.

Depending on compatibility windows, the updater may:

- jump directly;
- traverse bridge generations;
- perform schema migrations;
- use a signed offline upgrade bundle.

## 34. Hardware longevity

Evrosion should not abandon hardware merely to sell new machines.

Prefer graceful degradation, software fallbacks and optional feature disablement before dropping hardware.

Eternal support is not promised where continued support becomes technically impossible, insecure or disproportionately damaging to the platform.

Any end of hardware support must be explicit and technically justified.

## 35. Always retain one Known Good

Every supported installation must always retain at least one protected Known Good System Generation.

The current Known Good cannot be ordinary garbage-collected until a newer generation:

```text
boots
→ passes probation/health gates
→ is promoted to Known Good
```

Only then may it replace the prior rollback anchor.

## 36. Failed update behavior

If a new generation fails:

```text
failed generation
→ preserve diagnostics
→ quarantine/mark failure as appropriate
→ boot Known Good
```

Layer 1 performs recovery automatically wherever possible.

Layer 2 exposes additional details/control.

Layer 3 may override policy.

## 37. Known Good beats disk pressure

Never delete the last Known Good merely to force an update through.

If staging cannot safely fit, defer the update or resolve noncritical storage according to the responsibility layer.

## 38. Download and activation are separate

Evrosion distinguishes:

```text
discover
download
verify
stage
activate
commit
```

Downloaded software is not automatically the active OS.

## 39. Mirrors are not trust roots

CDNs, third-party mirrors, universities or community mirrors may distribute Evrosion without becoming release authorities.

Clients independently authenticate metadata and artifacts.

## 40. GitHub is not the root of trust

GitHub is important for public development/distribution, but compromising the GitHub organization must not automatically grant the ability to produce a trusted Stable release.

## 41. Source identity

Stable releases must identify the exact source revision used to build them.

Eventually, the source revision/release process itself should have authenticated source provenance rather than relying only on a mutable tag name.

## 42. Owner-defined Layer 3 trust

Layer 3 may install an owner trust root:

```text
Owner Verified
Root: user's key
```

That may be fully verified cryptographically while remaining distinct from Official Evrosion.

## 43. Offline operation

An already-installed official Evrosion generation must not require a cloud service to remain bootable or valid.

Offline signed update bundles may be supported.

## 44. Release withdrawal

A severely broken official release may later be marked:

```text
WITHDRAWN — DO NOT INSTALL
```

Withdrawal changes current recommendation/update metadata; it does not erase the historical fact that Evrosion signed that release.

Layer 3 owners retain the ability to deliberately use historical artifacts where available.

## 45. Critical security updates

Security fixes remain free.

Activation still follows responsibility layers:

- Layer 1: automatic;
- Layer 2: prominent recommendation + user decision;
- Layer 3: manual unless explicitly configured otherwise.

## 46. Human-readable release notes

Stable updates should present short understandable sections such as:

```text
Security
Reliability
Hardware / Drivers
System
Optional Features
```

Technical details remain available underneath.

## 47. Signing is not runtime root

An official signature proves origin/release authorization.

It does not grant the signed program unrestricted runtime capabilities.

Release authenticity and runtime authority remain separate.

## 48. Incident response

Before mature Stable distribution, Evrosion must document response procedures for:

- signing-key theft;
- repository compromise;
- malicious signed artifact;
- build-system compromise;
- provenance/reproducibility mismatch;
- update-metadata compromise.

Conceptually:

```text
stop publication
→ identify affected authority
→ revoke/rotate
→ withdraw bad release
→ publish corrected metadata
→ notify users
→ provide Known Good recovery
→ preserve forensic evidence
→ post-incident review
```


## 49. Deferred implementation choices

R-003 does **not** yet freeze:

- signature algorithm;
- key type/storage;
- signer count/threshold;
- exact TUF implementation;
- transparency-log technology;
- provenance format;
- SBOM format;
- mirror/CDN topology;
- release cadence;
- version-number syntax;
- Beta cadence;
- delta-update format;
- installer image format;
- Secure Boot enrollment mechanism.

The implementation can evolve while preserving the semantics above.

## 50. Adversarial review

### Fake UI says “Official”
**Fix:** trust comes from verified release/boot state, not arbitrary UI text.

### Fake installer modifies its own verifier
**Fix:** strong proof needs platform verification or an external trusted verifier. An already-untrusted program cannot prove itself honest.

### Compromised mirror serves malware
**Fix:** independently authenticated artifacts and repository metadata.

### Mirror serves an old but valid signed release
**Fix:** signed version/freshness/expiry metadata and rollback/freeze protection.

### Beta key is stolen
**Fix:** Beta authority cannot sign Stable.

### Stable key is compromised
**Fix:** key rotation/revocation and explicit compromise-recovery procedures.

### Official binary differs from source
**Fix:** reproducible canonical artifacts + published provenance.

### GitHub is compromised
**Fix:** GitHub is not the release trust root.

### Update optionality creates a permanent combinatorial mess
**Fix:** coherent core generations; optional components only where safe.

### Layer 1 update destroys active work
**Fix:** automatic maintenance waits for safe activation opportunities.

### Disk cleanup destroys recovery
**Fix:** last Known Good is protected.

### Updater becomes telemetry
**Fix:** data-minimized update queries; no unnecessary stable identity.

### Project pretends a withdrawn release never existed
**Fix:** withdrawals alter current recommendation, not signed history.

### “Official” software automatically gets root
**Fix:** signing authority and runtime capability authority remain separate.

## 51. Research basis

R-003 deliberately builds on mature industry work:

### The Update Framework (TUF)
Signed Root/Targets/Snapshot/Timestamp metadata, expiry/versioning, role separation and compromise recovery.

- https://theupdateframework.io/docs/security/
- https://theupdateframework.io/docs/metadata/
- https://theupdateframework.io/docs/faq/
- https://theupdateframework.io/spec/

### Reproducible Builds
Definition of independently recreatable bit-for-bit artifacts from defined source/environment/instructions.

- https://reproducible-builds.org/docs/definition/

### SLSA
Build/source provenance and progressively stronger software-supply-chain integrity.

- https://slsa.dev/spec/v1.2/
- https://slsa.dev/spec/v1.2/provenance
- https://slsa.dev/spec/v1.2/build-track-basics

### UEFI Secure Boot
Platform authentication of UEFI images before execution.

- https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html

### Sigstore / Rekor
Append-only cryptographically verifiable software-signature transparency.

- https://docs.sigstore.dev/logging/overview/
- https://docs.sigstore.dev/about/security/

### in-toto
Supply-chain step and artifact attestation.

- https://in-toto.io/docs/getting-started/

## 52. Locked R-003 laws

1. Official Evrosion is cryptographically authenticated, not merely branded.
2. Official site/GitHub are discovery/distribution locations, not the sole root of trust.
3. Forks/custom builds remain allowed but cannot authenticate as Official Evrosion without official release authority.
4. Official, Stable, Experimental and Certified are distinct concepts.
5. Installer authenticity is checked before destructive installation where a trusted verification path exists.
6. Basic authenticity can be verified offline; network access adds freshness/revocation knowledge.
7. An untrusted self-verifying installer cannot be treated as a complete proof of itself.
8. Invalid/unverified software may still be deliberately used by the owner, but remains unofficial.
9. Update security must resist stale/replayed/inconsistent repositories, not just modified binaries.
10. Stable and Experimental signing authority are separated.
11. Stable signing receives stronger protection than ordinary developer credentials.
12. Official Stable releases are reproducible.
13. Stable releases publish build provenance.
14. Stable and Experimental/Beta source remain open and public.
15. Experimental/Beta is explicit opt-in and clearly marked unstable.
16. Layer 1 performs fully automatic authenticated Stable maintenance with safe activation and rollback.
17. Layer 2 offers Install Now / Later / Skip / Details.
18. Layer 3 is fully manual by default.
19. Update checks are data-minimized and do not become mandatory telemetry.
20. Evrosion prefers one continuously advancing Stable platform instead of permanent servicing branches for every marketing release.
21. Core platform updates move in coherent tested System Generations.
22. Optional features are individually controllable where technically safe.
23. Every supported installation always retains one protected Known Good generation.
24. Failed generations fall back to Known Good where policy permits.
25. Mirrors/CDNs distribute but do not define trust.
26. Official installed systems remain useful offline.
27. Layer 3 may define owner trust roots without those builds becoming Official Evrosion.
28. Release signatures do not grant ambient runtime authority.
29. Release/update/build compromise recovery must exist before mature public Stable distribution.
30. Exact implementation mechanisms remain replaceable.

## 53. Final principle

> **Evrosion should be easy for a normal person to trust, difficult for an attacker to impersonate, possible for an expert to verify independently, and impossible for the update system to quietly take ownership away from the person using the machine.**

# R-003 COMPLETE — RELEASE TRUST & UPDATE DIRECTION LOCKED
