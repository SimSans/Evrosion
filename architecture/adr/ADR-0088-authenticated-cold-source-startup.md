# ADR-0088 — Authenticated local cold Source startup

Status: Accepted Level B implementation refinement; fresh selected Kernel and guest proof pending.
Date: 2026-11-13.

## Required order and authority

The first AppRegistry lookup previously used only the two compiled banks. That
would reject a saved downloaded package before authenticated content and its
sealed resolver existed. No later clearing of that recovery fence is valid.

For V4, start the actual Block service, claim the existing image-control owner,
and take the exact State Backend before any State.open. Run the production
content Inspect continuation: authenticate the stored checkpoint, ROM Root
continuity, every replay/withdrawal floor, signed metadata associations and
actual referenced object hashes. This is local cold authentication; it needs
neither network access nor fresh UTC. It does not accept a new remote release.

For each distinct candidate/active/KnownGood B or C Content, use the canonical
acquisition Reader over that same resident engine IO slot. Stream at most4KiB
per step through the existing private chunk into actual IMAGE_CONTROL52.
Deduplicate equal retained references; conflicting contents for one logical
version refuse. Two permanent image owners remain the limit. No Store, Backend,
buffer or Package borrow is duplicated or held through a self-reference.

The initial image Header comes from bounded, untrusted first-chunk Zion syntax.
The complete index must fit4KiB. This extracts no executable or release
authority. Actual reader completion verifies the full object, Kernel sealing
checks the real package/ELF hashes and mapping transition, and a full immutable
Zion parse plus Downloaded::from_images rechecks App, package, build, descriptor,
source, version, schema, requirements and exact Snapshot membership before
Register. No compiled bank supplies a downloaded Header or borrowed bytes.

Only after those operations complete does Root extract the typed authenticated
Snapshot, restore the exact healthy Backend, construct a scoped Resolver and
perform the first State.open. Running/preparing/transition selectors use the
distinct Source enum. A downloaded start uses its actual registered image
capability, never a bank-B label. Data, Note, grant policy and application
diagnostics resolve through the same current scoped Source view.

An unformatted checkpoint makes no write or blank-volume claim; explicit
update-init remains necessary to provision content. A saved downloaded registry
cannot resolve against that banks-only case. Corrupt/missing authenticated
content, unknown IO, image or association failure refuses startup and retains
the actual owners. It never formats, resets replay state or retries accepted
work. The original finite Inspect cut also covers streaming/sealing; every
child remains bounded by1024 and metadata by8192, with no renewed whole cut.

## Local identity and new decisions

The retained local identity Snapshot is separate from the current successful
Inspect/remote decision boundary. A later known-clean NotBlank or authentication
refusal or settled cancellation may return its exact healthy Backend and preserve
the previously authenticated sealed identity. Local data/Note remain usable.
Immutable identity/provenance remains observable while IO is unavailable, so an
App fault during content work can be contained. A failed engine does not expose
current-auth state; State's active, unknown or rejected Backend fences still
block data/Note IO. No cached local identity authorizes a new release, resets a
floor or creates health/KnownGood. Cold loading likewise preserves prior lifecycle
labels; neither signatures nor sealing promote them.

## Explicit profile and observations

V4 currently verifies Standalone only. Its System constructor and mode accessor
check that exact stored mode and absence of managed admission state. System
initialize/stage/activate and SelectKnownGood entry points refuse until a real
supported V4 System recipe exists. Shared readiness, readonly diagnostics and
the finite M5 System behavior remain. This is an existing profile boundary,
not a substitute for System recovery or critical health proof.

V4 opts into NR version2 with distinct slots None0/A1/B2/DownloadedB3/DownloadedC4.
Its three-bit fields occupy11/14/17 and recovery20; bits21 and above are reserved.
Root emission, Kernel decoding and selected-network Host parsing must opt in.
Default constructors/decoders remain exact version1 with the original two-bit
fields and golden bytes. The V4 ABI binds the suffix. These diagnostic labels
confer no image or lifecycle authority; actual downloaded actions remain joined
to Kernel-retained object identities and process/thread receipts separately.

## Measured implementation

The first actual linked cold join used183 image pages and189 initial private
frames, refusing the unchanged176/182 bounds; its resolved stack was30,376 of
32,768 bytes. A callback-sharing experiment reduced one page but introduced an
unresolved indirect edge. It was reverted; its30,408-byte result is not an
equivalent complete stack preflight.

Explicit validated V4 profile gates removed unselectable managed code, but that
link exposed a34,232-byte stack refusal. Separating pre-open Backend begin and
return frames from the IO loop restored a narrow32,552-byte pass. Finally,
forcing the existing OwnedStage::seal ownership wrapper to inline eliminates
an intermediate large return slot, while preserving the canonical borrowed
Stage operation. Put::seal falls from12,064 to8,608 bytes without changing IO,
ownership, cut or publication semantics.

Retained component07 is175 image pages/181 initial private frames and a resolved
28,696/32,768-byte stack census, margin4,072, with zero unresolved indirect calls.
Its ELF SHA256 is
`20ae24a1695d1dc1c741c980fc0707e068bc22530417c8072e8b1b6014f42294`.
The subsequent local-identity eligibility/cancellation correction is retained as
component08:175/181 pages,29,672/32,768 stack, margin3,096 and zero unresolved
indirect calls, ELF SHA256
`39180edd57e562c414eeb2e15e57488f00d23c7225129c297949378142557230`.
All component inputs are unchanged before/after each retained link. Earlier
refusals remain in the local engineering archive.
No image/mapping capacity, quota, stack, CPU window or physical pool is enlarged.
The one-page image margin provides no allowance for future code.

## Validation and remaining proof

Tests use actual signed B/C material and real Store/Arena cold bytes with an
explicit physical-image IO model. They cover distinct registered slots, repeated
reference deduplication, foreign membership, malformed prefix/index, original
cut failure and same-disk SavedB startup before first Registry lookup. Saved2077
and Note survive a later settled refusal; unknown IO retains the Backend and
denies access. These tests do not establish actual PTE execution or health.

A fresh source-bound producer and selected Kernel census must pass before any
guest run. Actual cold downloaded launch, protected presentation, bad-C fault,
health/KnownGood transition, full retirement and negative corruption/interruption
work remain separate gates. New remote acceptance still requires fresh actual
qualified time and the consumed decision/publication boundary from ADR-0082.


## Optional staged candidate rejection isolation

The cold image continuation distinguishes a clean package syntax, ABI/schema or
mandatory contract refusal from a missing/uncertain immutable reader, mismatched
header binding, failed object hash, storage response or expired original cut.
Only the former can be isolated, and only when the exact authenticated candidate
is distinct from both acquisition active and Known Good. A required retained
member still refuses the entire cold join. This does not implement general
corrupt-object recovery: content authentication precedes this continuation and
must still succeed for every retained reference.

A malformed first-chunk index opens no image slot. Its existing affine content
reader must drain through bounded reads and successful whole-object completion
before an independent retained member or the exact Backend becomes usable. A
later clean refusal after Kernel Verify keeps its permanent Root read-only,
non-executable reader and slot until normal Root retirement; it is never
Registered, recycled or exposed through the downloaded Resolver. The same two
slots, private 4 KiB chunk, original whole cut, child cuts and resource budgets
remain in force. Each accepted cohort completes its own association before
Register. Hash, IO, ownership and header/content binding errors remain fatal and
are never reclassified as a clean syntax refusal.

Rejected candidate metadata, publisher proofs, replay floors, active/Known Good
references and owner namespaces remain unchanged. This continuation neither
chooses another System cohort nor clears a recovery fence. If protected System
selection still names rejected C, that exact cohort cannot resolve and normal
startup stays blocked. The owner must explicitly use protected Recovery to
SelectKnownGood; a later normal B cold opening can then use the independently
valid, untouched Registry B and acquisition Known Good despite optional staged C.
No Host reset, checkpoint edit, automatic rollback or signature bypass is part of
that operation. An invalid member named by acquisition active or Known Good
remains a separate fail-closed limitation.

For a parse-valid package, exact App/Content version, build, declared source and
descriptor associations are checked before ABI/data-schema or mandatory-contract
compatibility. A compound wrong-source or wrong-version plus incompatible ABI or
contract therefore remains a binding refusal; compatibility must not hide the
known identity failure. `Schema` now denotes ABI/data-schema compatibility only.

The isolated component regressions exercise real Store/Arena reads, image
continuations and Resolver membership with explicitly synthetic, already-admitted
image-loader preconditions. They cover prefix/ELF/ABI/contract rejection,
independent B registration, both required membership fences, full-hash and lost-IO
refusal, immutable ownership/header binding refusal, and expiration during prefix
drain. They do not prove cryptographic admission, actual mappings, protected
Recovery gestures, same-disk reopening or physical retirement. Separate genuine
signed persisted-media runtime evidence and all selected Root/Kernel resource
censuses remain required before integration.
