# ADR-0111 — Managed SEND retirement and selected V5 physical ownership

Status: selected M8 implementation; host and target checks are separate from actual guest qualification.

## Decision

The new V5 physical runner is a separate `workspace_runtime` with eleven child
processes and Root. It consumes actual producer bytes through
`EVROSION_WORKSPACE_BUNDLE` under `test-m8-workspace-run`; missing images,
manifests, catalogue or package bytes have no placeholder fallback. The ordinary
mechanism feature can type-check this code without asserting guest execution.

`V5-RUN-01`: Before selecting larger Authority storage, independently hash the
actual Root/image/catalogue/package bytes, verify EVBM0005/profile5, strict Root
ABI and all37 source roles, canonical graph/layout and per-image descriptors,
per-instance source transcripts, and exact package bank/offset/length joins.
Create the real source objects in the same closed order and independently bind
all full generation identities through the typed Custodian. The host source
identity dry-run predicts metadata allocation only; boot must realize it.

`V5-RUN-02`: Each physical image retains a closed private owner (Core68,
UI/Workspace100, Display84, Editor388, Root244) and actual initialized shared
extent leases. Loading copies file bytes, zeros and checks BSS, checks W^X and
guards, and installs/readbacks only the selected fixed mappings. Registry
admission still requires exact typed336/528-byte child startup or1104-byte Root
startup. Whole graph/image arrays remain in once-claimed resident storage;
linked stack measurement is required before physical execution qualification.

`V5-RUN-03`: The source CreatorJob is the actual RootJob. Shared extent frames
are charged to that same Root subtree. V5 Root admission borrows the actual
published extent owners and allocator, checks each full custody source and
charged Job, and requires exact private plus shared Scheduler usage. Omitted,
unrelated or wrong-Job backing refuses admission while retaining both owners.
Old `activate`/`admit_bootstrap` still require exact private-only initial frames.
Root's4096-frame subtree limit is distinct from its246 private loader frames;
the rationale and immutable four Job templates are in ADR-0109.

## Exact selected grant ownership

`SEND-RETIRE-01`: Syscall44's nonce is a bounded Root-issued counter, not a
client/backend journal operation ID. The selected FIFO payload is its exact
zero-extended eight-byte LE value. Four fixed App inboxes retain a private
`ActiveGrantBranch` owner and actual Ticket. App-held SEND aliases and escaped
descendants all descend from this private parent; Root's source master and
Workspace RECEIVE do not. A later object binding to the same endpoint cannot
proceed merely because an App sent a Release ACK.

`SEND-RETIRE-02`: Only the new selected runtime implements
`MANAGED_SEND_RETIRE=61` and `MANAGED_SEND_RETIRE_INFO=62`. INFO requires four
zero operands and returns descriptor `0x0000000100030001`. RETIRE takes an
actual held ProcessCONTROL handle, the exact old44 nonce in1..u32::MAX-1, zero,
zero. The runtime obtains actual caller Process/Thread/Space/Job and Root Token
from the dispatched owner. The journal additionally checks Root's current
Running Scheduler row, token destination and exact retained target full
Process object/Registry row. No PID or packet identity lookup is accepted.

`SEND-RETIRE-03`: Status0 RSI states are0Drained,1RevokedPending,2Retained.
Invalid caller/handle/nonce/route returns a nonzero syscall status before
revocation. Retained keeps the exact private branch owner after a failed
revocation. RevokedPending means that authority decreased but actual selected
escrow or accepted execution/window references still remain. Drained requires
the exact branch revoked, actual undelivered Ticket withdrawn or actual FIFO
delivery observed, empty selected inbox, and no retained native accepted RPC
snapshot referring to the App thread or FileLease endpoint. Snapshots come
only from actual `Rpc::Call` rows and survive in native Pending ownership until
its canonical completion/withdrawal/verified callee death releases that row.
Timeout, caller cancellation and cooperative Release ACK never return credit.

`SEND-RETIRE-04`: A new44 grant refuses while the preceding owner is not
Drained, or while a selected Ticket/accepted App call remains. After Drained,
independent Workspace administrative reconciliation must abort its exact known
stage, complete actual flush, and retire the old route before a new object is
bound.61 does not certify durable stage cleanup, Block flush, device stop, or
durable recovery. Unknown/cold orphan staging remains fenced for independent
recovery. All preexisting syscall numbers, Receive34 and old44 behavior remain
unchanged; old physical profiles refuse61/62.

`SEND-RETIRE-05`: Actual stopped App replacement retains the fixed source
endpoints. A move-only `StoppedSelectedRoute` can be produced only from the
same terminated retained Registry/Scheduler identity and settled escrow. Its
typed rebind validates the new actual ProcessCONTROL/RX endpoint and preserves
selected policy and monotonically increasing Ticket history. Ordinary mailbox
reopen/rebind continues refusing selected inboxes. Missing/recycled old rows
cannot construct this receipt. Root closes and replaces ordinary control
bindings only after Stop/Observe/diagnostics/Reap and Process close.

## Limits and evidence

`V5-RUN-04`: Active Block/NetDriver hot replacement is refused in the first
runner: no device-stop protocol yet certifies actual ATA/NE2000 quiescence.
Their device/backing owners remain pinned. Actual in-flight Block death and
timeout plus independent cold data recovery remain required M8 gates. Healthy
checked poweroff after completed flush and no accepted work is a different
claim from reclaiming and reusing a live graph.

`V5-RUN-05`: PIT divisor1193 gives about1000Hz. Cumulative Job CPU counters are
not reset. Root65536/child16384 remain finite until actual user-IRQ versus wall
measurement supports an explicit selected-profile revision. The runner emits
per-actor charged IRQ counts, Scheduler subtree usage/highwater and elapsed
ticks; it does not claim the30-minute gate from a short host or guest run.
Root exit, finite cut or missed quiescence ends with owned resources retained;
there is no successful reusable-graph cleanup marker.

Portable retirement tests exercise real Authority, Registry, selected escrow
and Rpc rows, including escaped SEND revocation, forged caller/nonce/control,
delivered timeout with retained snapshots, exact new grants and selected
replacement Ticket history. They use explicit host admission metadata and do
not qualify physical loading or device behavior. Shared admission tests use
actual portable allocator claims, byte initialization/readback and published
MemoryExtent owners; wrong Job/source, omitted owners and unowned charge deny.
Actual run-only link, stack census, full cohort boot and all fault/cold recovery
transcripts remain separate qualification gates.

The negotiated retirement ABI SHA256 is
`66c3883aae36b8008f2a5dd839b5c3453ae6ecb138c7ca24466e0f131f01db47`;
its authoritative literal description and hash are in
`libs/userspace-contract/src/syscall.rs`.
