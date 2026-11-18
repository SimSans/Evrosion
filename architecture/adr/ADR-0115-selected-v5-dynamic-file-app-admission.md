# ADR-0115 — Selected V5 dynamic File App admission and retired buffer scrub

Status: selected M8 mechanism implementation; linked and actual guest qualification pending.
Date: 2026-11-16
Related: ADR-0109/0111/0112/0113; M8 signed update, held candidate and app replacement gates.

## Independent selected factory

`V5-DYN-01`: Only the selected V5 runtime accepts dynamic2 through syscall52.
Initialize returns version2. The strict256-byte header uses `EVDYN002`; layout
metadata uses `EVDYNP02`, independently from V4's version1 header and descriptor.
The old52 operations0..8 and V4 admission remain unchanged. The public dynamic2
contract description SHA is
`e4f4c287d9e7b67e8d9d15ae20d960e2c57e4896a012e2cf2246832bccb3d857`.
The existing catalogue dynamic record is descriptive canonical metadata;
Initialize's actual result is the negotiation authority. Root must refuse a
version mismatch before writing a dynamic control or staging window.

`V5-DYN-02`: A new permit borrows only an active typed CurrentRootV5. It checks
the actual captured Running thread, its same Scheduler Process/Job, exact
current Root Token and destination, immutable Root limits, and CreatorJob's
exact two-hop custody/bootstrap lineage. It also revalidates every original37
full-generation source, private branch and installed grant. Additional live
service/endpoint handles do not become bootstrap sources. A stale token,
ordinary caller, Creator alias, nonrunning thread, or revocation of any original
source denies the operation. A V4 permit cannot enter the selected registry,
and the selected permit cannot register through the old V4 App7 factory.

`V5-DYN-03`: Two bounded move-only owners retain actual charged RAM. Only one
writer can exist at a time. The independently owned PD1 leaf and private control
page cost two additional RootJob/Boot frames; the maximum package owner is64
pages (262144 bytes). The Root package bank is separately bounded to63 pages
(258048 bytes). The same low-level captured fixed-geometry DynamicLeaf mechanism
is reused with compile-time geometry joins; no V4 manifest, Root selection,
loaded image provenance or service profile is cast into V5.

Actual full package and ELF hashes are checked after all writable aliases are
revoked and detached, including actual leaf readback and controller CR3/TLB
boundary. Root receives only the actual installed Memory capability. Short
immutable views borrow the exact retained sealed owner during independent
Kernel descriptor verification and private loading; no static slice or mutable
package reference is retained by the Registry. Errors keep frame charges and
hardware debts. Unknown PTE state stops the selected controller with all owners
retained. Readonly package views remain pinned for Root's lifetime; live Root
cannot recycle them merely by unregistering a descriptor.

`V5-DYN-04`: The selected sealed factory fixes ImageSlot::Editor as a resource
and role shape: six File App grants,1M cumulative CPU,512 frames, one Process and
Thread,384 image/388 private/390 loader pages, eight stack pages480..487 and
exact guards/startup/entry/Surface/File loan reservations. The descriptor hashes
the distinct M8.v5 domain, actual ELF SHA, RootV5 ABI,336-byte child ABI, slot,
all13 normalized profile values, exact limits and six kind/rights triples.
The independently streamed public SDK transcript must match the actual Kernel
ServiceImage verification. No packet chooses quota, roles or layout.

This shape is not an AppId. Root independently verifies the actual signed
package, publisher policy, app identity, permissions, visible labels, candidate
selection and persisted KnownGood state. A separately signed external File App
must retain its own identity; admission cannot label it as the built-in Editor.
Neither a successful Kernel registration nor a compiled candidate in the boot
catalogue proves signed update success.

## Actual held ownership and replacement

`V5-HOLD-01`: One additional File App process may be held while both declared
Editor instances are live. The extra record begins without an instance binding.
Its first trusted Surface grant binds only an actual full source object for
EditorOne or EditorTwo; every subsequent grant must match that same declared
instance. The held process cannot execute. No packet ordinal, name or PID
selects its source or target. Job creation still selects one closed template.

`V5-HOLD-02`: Dynamic2 PrepareProcess operation9 takes the actual held
ProcessCONTROL as its operand and requires extra0, an actual current Root plus
Creator permit, and all six exact trusted grants. It builds the typed bootstrap,
loads/readbacks actual private file bytes/BSS/stack/guards/W^X, and retains that
same physical owner in bounded resident storage. The prepared process remains
Held and receives no Surface or FileFrame mappings. Repeating preparation is
idempotent for that same retained process, never a quota refund or reread of a
mutable candidate. Preparing incomplete grants refuses before physical loading.
Physical load failure is a fatal retained-owner path, never reuse of a partially
prepared allocation. A distinct `prepared_private_held` diagnostic records this
physical phase separately from CreateProcess's metadata/frame charge.

`V5-HOLD-03`: Start refuses until the exact old target process is stopped,
reaped and its final ProcessCONTROL closed, allowing its retained Registry row
to be collected. Only then may the held actor occupy that declared slot, map
its exact fixed shared extents and enter ordinary checked Registry admission.
It uses the same Process/Job, original grants, bootstrap and prepared private
owner. It does not substitute a new process or reset cumulative accounting.
Cancellation retains a prepared owner's actual private pages until actual
Stop/Reap teardown; it never scrubs the still-live old target's shared buffers.

`V5-SCRUB-01`: After actual old CPU/accepted-call/selected-delivery retirement
and physical shared PTE detachment, Reap zeros and reads back only that app's
exact source Surface and FileFrame extents (Shell has only its Surface). The
actual custody source grants produce live writable extent leases; wrong extent,
readonly/revoked lease, access failure and readback mismatch cannot count as a
successful scrub. The generic owned RAM scrub retains all leases, backing and
quota on errors; the native caller treats any error as a fatal retained-owner
path. The old record remains present until scrub completes. It never modifies
Dataset sectors or another app's extents.

This is CPU RAM clearing under the sole captured controller, with APs parked.
It does not prove device quiescence, release a Workspace stage, reconcile an old
File lease, or remove a Display model. Root must complete the independent61
managed SEND drain, Workspace route/stage reconciliation and DisplayRemove
owner acknowledgment before replacement. Block/NetDriver hot replacement stays
refused without an actual device stop protocol.

## Required evidence

`V5-DYN-PROOF-01`: Portable tests use real Authority/Scheduler/allocator/Registry
and sealed owners to check selected/legacy separation, captured Running Root,
full source revocation, six-role/high-page admission, descriptor substitution,
owner pinning, exact frame charges, and SDK transcript joins. Owned RAM tests
check wrong/readonly/revoked leases, partial write/read errors, corrupt readback,
unchanged unrelated bytes and retained charges. These are host mechanism tests,
not physical loading, accepted RPC/window draining or device proof.

Actual selected native linking and the unchanged full-entry256KiB stack gate
must pass after this addition. A guest must then demonstrate physical held
preparation while the old app continues, refusal of premature Start, exact
retirement/scrub, promotion/admission of the same prepared process, signed good
and bad candidate behavior, persisted KnownGood and independent cold recovery
of unchanged workspace data. Those gates remain pending until retained actual
receipts prove them. Existing folder-create native evidence does not establish
any dynamic52, held candidate, Save, reclamation or signed update gate.
