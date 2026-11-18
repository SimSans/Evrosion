# ADR-0090 — Durable local update selection

Status: Accepted Level B implementation refinement; joined VM activation, later-candidate and recovery gates remain pending.

## Decision

Before a downloaded candidate is replaced, retain the actual Registry selection
in the acquisition checkpoint's active field. Registry activation remains the
owner's explicit operation. Acquisition, executable registration, selection and
Known Good health remain separate decisions.

The native State can mint a move-only local RegistrySelection only from its
record retained after a genuine Registry open or successful publication ACK.
It rechecks the full current package/source and compatibility, installed state,
App identity and active version reference. Staging or a process label alone
does not create a selection. Unsettled registry, grant or System intent and
recovery fences refuse the receipt.

The receipt binds the complete Registry record digest, the private backend
identity and the next nonwrapping content-loan sequence. After that exact owner
moves into the authenticated acquisition Store, reconciliation checks the
current State record and intent fences, current loan, actual retained backend
and authenticated candidate/active/Known Good membership. The selected package
must already be authenticated local content. No receipt accepts new remote
bytes or substitutes for the qualified clock.

A compact SelectionDecision retains this receipt and the exact Store binding
through consumption. It rechecks the same State/backend/loan and original
head/revision before delegating to the canonical record/Commit implementation
shared with remote Decision. It constructs no additional trusted Snapshot;
the existing cold-check workspace reconstructs that state. Another Store with byte-identical
media cannot consume the decision. Arena exposes only a shared reference to
its retained backend for this private origin comparison; it grants no mutable
device borrow. Reconciliation changes only acquisition revision and active
content. Candidate, Known Good, metadata, trust roots, replay state and UTC
floor remain exact.

If Registry activation succeeds but acquisition retention has not yet completed,
the old candidate remains retained. A later fetch first authenticates that
checkpoint and reconciles the genuine current Registry selection. It must
complete this durable publication before replacing a sole candidate. Failure
refuses the replacement and retains the real affine owner and existing fences.
Offline startup may resolve the selected package from that retained candidate;
it never needs a current network clock merely to reopen accepted local content.

## Evidence and limits

Composition tests use the actual signed release fixtures, content Arena,
Registry activation and canonical acquisition publication, with model media and
a test clock. They check active-only publication and authenticated cold reopen,
unchanged replay/floor/candidate/Known Good, no-op behavior, stale Registry
records, foreign State/backend, a later loan, recovery fences, changed heads
and consumption against an independently owned byte-identical Store.

These are implementation tests. They do not establish actual guest selection,
later C acquisition, health eligibility, Known Good recovery or M6 completion.
Those remain joined VM gates. No checkpoint format, root capability, package
capacity, CPU budget, physical qualification or foundational guarantee changes.
