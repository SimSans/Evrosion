# Evrosion — Certified Privacy, Diagnostic Integrity & OEM Support Evidence

**Status:** Accepted architectural/release direction  
**Scope:** Evrosion Certified devices, OEM support, local observability, optional telemetry, Layer 3 / owner-modified systems  
**Relationship to architecture:** Builds on E-009 (capability-first authority), E-012 (verified generations/recovery), E-020 (structured observability / Failure Capsules), and the Layer 3 ownership model.  
**Purpose:** Give Evrosion and OEM partners enough trustworthy evidence to diagnose failures and determine support responsibility without mandatory telemetry, hidden surveillance, or permanent punishment for owner modification.

---

## 1. Core Principle

> **Observable to the owner. Verifiable to support. Silent to the network unless the owner authorizes transmission.**

Evrosion shall maintain rich local observability while transmitting no mandatory diagnostic, behavioral, usage, advertising, reliability, or crash telemetry.

When the owner requests support, Evrosion may create a cryptographically verifiable diagnostic package. The owner must be able to inspect what will be sent, but included certified evidence must not be editable without invalidating its integrity.

The goal is **tamper-evidence, not owner-hostile tamper-proofing**.

The owner remains free to delete local records, disable diagnostic facilities where Layer 3 permits it, replace software, or refuse transmission. Evrosion and an OEM are correspondingly free to classify missing, altered, or unverifiable evidence as incomplete rather than accepting it as certified diagnostic proof.

---

## 2. Privacy Covenant

An Evrosion Certified system shall obey the following rules:

1. No mandatory diagnostic telemetry.
2. No behavioral or advertising telemetry.
3. No hidden OEM reporting channel.
4. No special ambient OEM authority.
5. OEM utilities use the normal Evrosion capability system.
6. Refusing optional data sharing must not disable:
   - core OS functionality;
   - security updates;
   - local ownership/control;
   - ordinary recovery.
7. Observability is local by default.
8. Diagnostic information leaves the machine only through:
   - an explicit owner-authorized support action;
   - an explicitly enabled voluntary reliability program;
   - a clearly disclosed managed-device policy on an organization-owned or organization-managed system.
9. The owner must be able to inspect the data categories and, for support packages, the exact human-readable contents being transmitted.
10. Evrosion Certified OEMs may not bypass these rules with preinstalled privileged software.

Violation of this covenant may be grounds for loss of **Evrosion Certified** status.

---

## 3. Separate Three Things

Evrosion must not merge these into one mechanism.

### 3.1 Local Observability

Always-local system information used for debugging, recovery, and owner inspection.

Examples:

- structured crashes;
- Failure Capsules;
- driver failures;
- firmware versions;
- system generation;
- update/rollback results;
- storage health;
- hardware fault reports;
- resource pressure;
- boot trust state;
- relevant Layer/certification state.

Local observability does **not** imply network transmission.

### 3.2 Support Diagnostics

A diagnostic package generated because the owner explicitly requests support.

Support diagnostics may contain detailed per-machine information when it is necessary for the support case.

Transmission is explicit and case-scoped.

### 3.3 Voluntary Reliability Telemetry

A separate opt-in program intended for fleet-level reliability statistics.

It should be minimized, aggregated/pseudonymized where practical, and avoid permanent device identifiers unless a narrowly defined engineering need requires them.

Raw support Failure Capsules must not silently become reliability telemetry.

---

## 4. The Support Package Must Be Inspectable but Not Editable

Before transmission, Evrosion shows the owner a human-readable view of the exact diagnostic package.

Example:

```text
Support request:
Lenovo / Case #EVR-48291

Included:
- Device model
- Relevant firmware versions
- System Generation
- Kernel Build ID
- Boot/certification state
- GPU driver version
- Failure Capsule #183
- NVMe health result

Not included:
- Documents
- Browser history
- Passwords
- Secret Vault contents
- Unrelated application content
```

The owner may:

- inspect it;
- expand individual records;
- choose among allowed diagnostic scopes before package construction;
- decline optional sections;
- cancel the support request;
- save a local copy where permitted;
- refuse to transmit anything.

The owner may **not edit individual fields of an included certified record and still have that record validate as authentic**.

If the owner needs to provide commentary, corrections, or context, that is attached as a separate **Owner Statement** rather than rewriting the signed machine evidence.

This cleanly separates:

> **What the machine recorded**

from:

> **What the owner says happened**

Both are useful. They are not the same evidence.

---

## 5. Canonical Diagnostic Records

Trusted diagnostic records should use a canonical machine-readable representation.

A record should conceptually contain:

```text
record_version
record_type
record_id
sequence
monotonic_time
wall_time_if_available

system_generation
kernel_build_id
relevant_component_build_ids

boot_trust_state
certification_state
layer_state_when_relevant

hardware_model_class
relevant_firmware_versions

event/failure_type
structured_event_payload

previous_record_digest
record_digest
integrity_metadata
```

Only information relevant to the event should be captured.

Secrets, arbitrary user memory, document contents, passwords, encryption keys, and unrelated application data are forbidden unless a separate explicit diagnostic grant authorizes a narrowly scoped collection for a specific support purpose.

---

## 6. Tamper-Evident Integrity Chain

Trusted records should be chained cryptographically.

Conceptually:

```text
Record N digest =
HASH(
    canonical_record_N
    + digest_of_record_N-1
)
```

Periodic trusted checkpoints bind the current chain head to a trusted signing/attestation mechanism.

This gives support several useful properties:

- changing an old included record breaks verification;
- inserting a fabricated historical record breaks verification;
- reordering records breaks verification;
- replacing signed evidence breaks verification;
- deleting part of an expected continuity window can be detected when continuity proofs/checkpoints are available.

This is **not** intended to make deletion impossible.

If the owner deliberately destroys local history, the correct result is:

```text
DIAGNOSTIC HISTORY INCOMPLETE
```

not:

```text
OWNER IS FORBIDDEN FROM DELETING THEIR OWN DATA
```

---

## 7. Hardware-Backed Attestation

On Evrosion Certified hardware, the strongest support evidence should be anchored below the ordinary mutable OS when suitable hardware exists.

A TPM, secure element, TEE, or equivalent mechanism may provide a hardware-backed **Diagnostic Attestation Key** or attestation capability.

Its purpose is narrow:

> **prove the integrity/state of diagnostic evidence**

It must not grant Evrosion, the OEM, or a remote party authority over the machine.

The key/capability should be:

- non-exportable where supported;
- usable only through a narrow trusted interface;
- unable to read arbitrary user data;
- unable to initiate network communication;
- unable to grant capabilities;
- unable to block Layer 3;
- unable to modify the OS;
- unable to become a surveillance channel.

The owner may disable, erase, or invalidate the local attestation facility where the platform permits it.

Doing so simply means future support evidence may be classified as **unattested** until the certified attestation environment is legitimately restored or reprovisioned.

---

## 8. Measured Boot / Certified-State Binding

A valid support package must not merely say:

```text
certified = true
```

because mutable software could lie.

Where supported, trusted evidence should bind to measured/verified boot state.

A verifier should be able to determine whether the relevant record originated while the machine was:

```text
EVROSION_CERTIFIED
OWNER_VERIFIED
OWNER_MODIFIED
PLATFORM_MODIFIED
UNVERIFIABLE
```

A hardware-backed measurement/attestation mechanism may bind:

- boot-chain measurements;
- trusted root/key;
- system generation/build identity;
- relevant firmware measurements;
- certification state.

This allows Layer 3 to remain fully functional while preventing an owner-modified system from falsely presenting itself as the certified OEM configuration.

---

## 9. Layer 3 Behavior

Entering Layer 3 does not transmit anything.

Entering Layer 3 does not permanently blacklist the machine.

Entering Layer 3 does not create a hidden remote record.

Instead, when the owner changes protected/certified software, the **current local certification state** becomes:

```text
OWNER_MODIFIED / EVROSION_UNCERTIFIED
```

Trusted diagnostic evidence generated in that state identifies it honestly.

If Layer 3 software prevents trusted recording, destroys the records, or invalidates attestation, support receives:

```text
HISTORY INCOMPLETE
```

or:

```text
UNVERIFIABLE
```

rather than a forged `EVROSION_CERTIFIED` result.

This is the essential security property.

---

## 10. No Permanent "Sinner Bit"

Evrosion shall not maintain a permanent punitive flag equivalent to:

```text
this owner entered Layer 3 once
```

Current certification is based on current verifiable state.

If the owner restores:

- canonical platform firmware where required;
- official trusted boot configuration;
- an official System Generation;
- required certified drivers/components;
- required certification settings;

then the machine may return to:

```text
EVROSION_CERTIFIED
```

Historical Failure Capsules relevant to an existing support case may still truthfully show the state in which that failure occurred.

That is evidence of an event, not permanent punishment.

---

## 11. Support-Case Binding

A support package should be generated for a specific support interaction rather than reused as a universal identity document.

Where practical, the support endpoint provides a fresh challenge/nonce.

The generated package binds to:

```text
support_provider
case_identifier
challenge
package_creation_time
selected_diagnostic_scope
integrity_chain/checkpoints
attestation_state
```

The final package is digitally signed.

This prevents straightforward replay of an old valid package as if it described a new incident.

---

## 12. Human View and Machine View Must Match

The owner-facing inspector must decode the same canonical payload that is signed and transmitted.

Evrosion must not show the user a sanitized summary while secretly sending a richer hidden payload.

Architecture rule:

> **One package. Two representations. Same information.**

The machine representation exists for reliable verification.

The human representation exists for owner comprehension.

Any fields that cannot be meaningfully presented to a normal user should still be visible in an advanced/raw view.

---

## 13. Selective Scope, Not Field Forgery

Privacy requires the owner to control scope.

Diagnostic integrity requires the owner not to rewrite evidence.

Therefore support collection uses **selectable evidence groups**.

Example:

```text
Required for this support workflow:
[x] System / build identity
[x] Certification state
[x] Relevant crash capsule

Optional:
[ ] Extended storage health
[ ] Extended GPU diagnostics
[ ] Recent related driver events
```

The owner may deselect optional groups.

If a required group is refused, transmission does not proceed or support explains that the case cannot be diagnosed with certified evidence.

Once a group is selected, its signed records are included unchanged.

This avoids the false choice between:

- "support gets everything", and
- "the owner can forge the diagnostic package".

---

## 14. Owner Statements

Owners need a legitimate way to dispute or explain machine evidence.

Every support package may contain an unsigned or separately owner-signed section:

```text
OWNER STATEMENT
```

Example:

> The GPU failure began before I installed the custom compositor. I restored the certified system afterward and reproduced it twice.

Support sees:

1. certified machine evidence;
2. owner-supplied explanation.

Evrosion never silently rewrites one into the other.

---

## 15. Verification Results

The OEM/Evrosion verifier should produce narrow factual states rather than a vague pass/fail.

Suggested states:

```text
VERIFIED_CERTIFIED
Evidence integrity valid; relevant state was certified.

VERIFIED_OWNER_MODIFIED
Evidence integrity valid; relevant state was owner-modified.

VERIFIED_PLATFORM_MODIFIED
Evidence integrity valid; relevant platform/firmware was modified.

INCOMPLETE
Evidence is valid where present, but required continuity/evidence is missing.

INVALID_INTEGRITY
Included evidence was altered or failed cryptographic verification.

UNATTESTED
Package may contain useful diagnostics but lacks a trusted certification proof.

UNSUPPORTED_VERSION
Evidence format/version cannot currently be verified.
```

`OWNER_MODIFIED` is not synonymous with "owner caused the failure."

That question requires causal diagnosis.

---

## 16. Causation, Not Punishment

Evrosion/OEM support must distinguish:

```text
machine was modified
```

from:

```text
modification caused this failure
```

Diagnostic evidence may establish facts such as:

- the machine was in Layer 3;
- a custom kernel was running;
- platform firmware was modified;
- a storage failure occurred;
- a driver crashed;
- a firmware flash immediately preceded a failure.

It should not automatically infer legal/warranty causation merely from Layer 3 having existed.

Support policy and applicable law determine responsibility.

This protects both sides:

- OEMs do not have to support owner-created software failures.
- Owners are not automatically blamed for unrelated hardware defects.

---

## 17. Data Minimization & Identity

Support diagnostics and reliability telemetry have different identity requirements.

### Support case

A support case may require device identity, serial number, purchase/warranty information, or OEM-specific identifiers.

These are disclosed only when required for the requested support workflow and shown to the owner before transmission.

### Voluntary reliability program

The reliability program should avoid stable global device identifiers by default.

Where attestation is useful, prefer privacy-preserving or case-scoped mechanisms so attestation proves:

```text
this is valid evidence from a qualifying platform/state
```

without unnecessarily proving:

```text
this exact person/device has appeared in every telemetry event for years
```

The exact privacy-preserving attestation mechanism remains an implementation choice.

---

## 18. Local Outgoing-Data Ledger

Evrosion should maintain an owner-visible local record of diagnostic/telemetry transmissions.

Example:

```text
2029-04-18 14:03
Recipient: Lenovo Support
Purpose: Support Case EVR-48291
Package digest: ...
Authorization: Send Once
Result: Delivered
```

For an optional reliability program:

```text
2029-04-18 18:00
Recipient: Evrosion Reliability
Purpose: Opt-in reliability report
Categories: GPU crash aggregate, update result
Result: Delivered
```

This ledger belongs to the owner.

It is not itself a remote telemetry mechanism.

---

## 19. OEM Rules

An OEM participating in Evrosion Certified must agree that:

1. OEM support/telemetry applications receive no ambient privilege.
2. OEM applications use ordinary Evrosion capabilities.
3. OEM background telemetry is optional unless required by a clearly disclosed managed-enterprise policy.
4. Declining optional telemetry cannot disable core hardware or Evrosion security updates.
5. Support diagnostics must use the owner-authorized support path or another equally transparent capability-mediated mechanism.
6. OEM software may not secretly create a second diagnostic stream outside Evrosion's privacy controls.
7. The OEM may verify signed support evidence.
8. The OEM may classify unverifiable evidence as unverifiable.
9. The OEM may not equate mere historical Layer 3 use with automatic causation.
10. OEM software must not weaken the owner's right to return to a certified configuration.

---

## 20. Managed Enterprise Devices

Organization-managed devices are a distinct case.

An organization may explicitly configure fleet health, inventory, update reporting, security monitoring, or other telemetry when it owns or legitimately manages the device.

Evrosion must make this state visible:

```text
THIS DEVICE IS MANAGED BY EXAMPLE CORP.
```

The system should expose:

- what management authority exists;
- what categories may be collected;
- where data is sent;
- which controls belong to the organization versus the local user.

Managed-device policy must not be disguised as ordinary consumer telemetry.

---

## 21. Candidate Technical Building Blocks

The semantic design is more important than the exact encoding, and implementations remain replaceable.

Suitable existing technical precedents include:

- TPM measured boot and PCR/event-log attestation;
- hardware-backed key attestation;
- hash-chained append-only records;
- canonical CBOR or another deterministic serialization;
- COSE signatures or an equivalent standard signed-object format;
- challenge-bound support attestations;
- rotating/checkpointed local logs.

The initial implementation should prefer mature standard cryptography rather than inventing Evrosion-specific cryptographic primitives.

Encoding choices are not part of the permanent architectural law unless later frozen through the normal contract/versioning process.

---

## 22. Failure Semantics

The support system must fail safely and honestly.

If signing fails:

```text
UNATTESTED
```

If the hash chain fails:

```text
INVALID_INTEGRITY
```

If required history is missing:

```text
INCOMPLETE
```

If the system is owner-modified:

```text
VERIFIED_OWNER_MODIFIED
```

If the package is perfectly valid:

```text
VERIFIED_CERTIFIED
```

Never silently upgrade weak evidence into strong evidence.

Never prevent the owner from using the machine merely because attestation or diagnostics are unavailable.

---

## 23. What This Mechanism Must Never Become

The diagnostic integrity system shall not become:

- a permanent remote tracking identifier;
- an undeletable behavioral history;
- an advertising identifier;
- a mandatory cloud account dependency;
- a remote kill switch;
- an OEM backdoor;
- a DRM system;
- a mechanism that grants authority over the owner's machine;
- a permanent punishment for Layer 3;
- a secret data channel;
- proof that modification automatically caused an unrelated failure.

Its job is narrow:

> **When the owner chooses to present machine evidence for support, allow both sides to know whether that evidence is genuine and what state the machine was actually in.**

---

## 24. Locked Direction

The accepted direction is:

> **Evrosion is locally observable and network-silent by default. Support packages are explicitly authorized, fully inspectable by the owner, and cryptographically tamper-evident. The owner may refuse or destroy evidence, but cannot alter certified evidence while preserving its validity. Layer 3 never transmits anything automatically and creates no permanent punitive flag. Certification is based on verifiable state, while support responsibility is determined from evidence and causation rather than mere historical modification.**

---

## 25. Research Basis / Precedents

This direction intentionally follows established technical ideas while applying Evrosion's ownership model:

- Android hardware-backed key attestation demonstrates that a verifier can obtain hardware-backed claims about boot/root-of-trust state while distinguishing verified, user-rooted, and unverified boot states.
- Trusted Computing Group PC Client specifications define measured-boot event logs and TPM quote verification based on hashes extended into Platform Configuration Registers.
- IETF COSE (RFC 9052) defines standard structures for signing CBOR objects and is one viable building block for signed diagnostic capsules.
- Evrosion's own E-009 and E-020 provide the architectural basis: explicit authority, local auditability, structured events/traces, Flight Recorders, and Failure Capsules.

### References

- Android Open Source Project — Key and ID Attestation  
  https://source.android.com/docs/security/features/keystore/attestation

- Trusted Computing Group — PC Client Reference Integrity Manifest Specification  
  https://trustedcomputinggroup.org/resource/tcg-pc-client-reference-integrity-manifest-specification/

- IETF RFC 9052 — CBOR Object Signing and Encryption (COSE)  
  https://www.rfc-editor.org/rfc/rfc9052.html

---

# End State

This mechanism gives Evrosion all three properties simultaneously:

```text
OWNER PRIVACY
+
OEM-DIAGNOSTIC USEFULNESS
+
SUPPORT-EVIDENCE INTEGRITY
```

without sacrificing Layer 3 or creating mandatory telemetry.
