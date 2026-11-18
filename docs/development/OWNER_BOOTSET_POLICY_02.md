# Internal owner boot-set policy 2

This unreleased 0.2 owner interface adds presentation update code9,
`SetupRequired`, to the existing four-bit Update field. Request protocol1,
eight-byte bodies, old update codes0–8 and Note/scalar schemas remain unchanged.
This setup policy adds no syscall or capability route; separately reviewed V4
capacity metadata follows ADR-0098. Root, Shell and graphics are built as one coherent protected
source/image set. Values10–15 remain invalid. Setup is part of Root's transient
presentation context, together with the actual Registry revision, so old settled
controls cannot approve after prerequisites or the current head change. A cached
setup hint is presentation only, never selection authority.

On a new workspace, Connection and updates may show “Ready for first use.”
Fetch explicitly prepares the protected bundled-A Registry/scalar baseline only
when Root holds its existing private proof that both complete regions were
blank. This stages the protected package without running App code. It does not
reinstall a tombstone, reset an existing namespace, change a publisher pin or
lower a replay floor. No content/network request starts before this prerequisite
succeeds. The same explicit preparation policy applies to the owner Fetch line.

Use after restart, and the explicit owner System initialization/stage/activation
commands, can prepare only a genuinely all-blank Note namespace. Root captures
its current Registry revision and the exact checked downloaded candidate digest
as a typed preparation intent. Actual readonly Registry/head, scalar/schema and
Note checks run through the same affine backend. A missing Note must pass its
whole-region blank scan before the existing stable App/schema manifest and empty
initial envelope can be formatted and read back. This is trusted namespace
creation under the explicit owner action, before the separate System journal
mutation. It creates no App request, nonce, successful Read, Critical signal,
health receipt or KnownGood claim. After preparation, another actual readonly
check gates System publication under the same original storage cut. Cached setup
hints never authorize creation or selection, and no idle UI frame reads Store.

Existing valid Note data stays unchanged. Partial preparation is retained rather
than rolled back or reformatted. Corrupt, dirty, nonblank-unformatted or uncertain
media stays fenced and preserved; an error is never permission to overwrite it.
No unknown IO completion is retried automatically. Probation refuses setup
before IO and retains its existing zero-IO read and authenticated Busy behavior.
A clean prerequisite refusal does not latch recovery. Opening Hello remains an
ordinary way to establish its Note, but is not a required first-use ritual.

Host `boot-set.json` schema2 marks this first-use policy boundary. Previous
unreleased schema1 sets are left untouched and refused before loading their
artifacts or changing their media. A new Host does not claim an old retained
Root implements this correction. Preserve `build/m6/network-session/data.raw`,
`owner.json`, the matching `boot-set` and their recorded artifacts/downloads.
Use the matching original workspace/set for inspection and an explicitly
reviewed recovery procedure; this launcher does not migrate, rename or reformat
it automatically. A fresh independent workspace can start a new owned session
without overwriting the old data. Do not delete an ownership record or boot set
to force a reset. Schema2 is Host policy metadata, not a disk-format migration or
publisher-pin change.

Within one supported set, authenticated restart reuses the same exclusive owned
disk and exact three retained modes. An old/corrupt/foreign set or mismatched
selection still refuses without automatic repair. This document is a source
contract, not an actual first-use VM or complete M6 acceptance claim.

The protected preparation decision and its validation boundaries are documented
in [ADR-0099](../../architecture/adr/ADR-0099-protected-owner-first-use-preparation.md).
