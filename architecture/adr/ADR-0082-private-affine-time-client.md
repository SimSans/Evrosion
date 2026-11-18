# ADR-0082 — Private affine signed-time client staging

Status: Accepted Level B implementation staging; actual provider/guest/durable-publication gates pending.
Date: 2026-11-12.

## Decision

The V4 Root alone performs one bounded signed-time exchange only after the
independent Hello transaction succeeds and an explicit complete owner UART
`time-probe` line arms it. The Hello network probe does no automatic time work. It reuses the sole Client505 owner and existing
protected NetService route; no new MemoryObject, transport alias, service,
capability or application network authority is created. The current profile
remains a trusted owner-controlled reference developer VM. This slice never
constructs QualifiedWindow or publishes durable release/trust state.

The pure `native_network::time_exchange` handles untrusted HTTP bytes, not time
verification. It initiates ordinary Close, waits for actual TCP Closed, then
connects the same independently scoped10.0.2.2:8080 destination. DNS results never
choose the time authority. One original8192-PIT-tick transport cut bounds at
most128 real protected calls; each child cut is at most1024 and never beyond that
original cut. Pending is an explicit quiescent result, not a retry of an accepted
unknown call. Partial Write acknowledgements advance only the actual accepted
prefix. Unknown completion leaves the existing Client505 owner quarantined.

The actual private `native::time_runtime` captures an RTC origin before obtaining
fresh output from the Root's already qualified private Random. Its one-shot
NonceSource can be constructed only through that actual fill path, checks the
actual generation/request/32-byte receipt and transfers its one output into
Client.begin. Its staging bytes are erased on all outcomes. It is not a second
generator, chosen-nonce verifier, restored-ready state or nonce refund mechanism.
The private Client and non-cloneable Request retain matching affine challenge
state across the subsequent bounded ordinary-tick steps.

An owner may arm this exchange after the boot seed's finite60,000-PIT-tick
eligibility has expired. Once TCP is actually closed and before the private
challenge is published, Root captures the RTC origin and performs one fresh
bounded acquisition/reseed under the same reviewed launch/profile. It retains
the actual generator's monotonic seed generation and lifetime request sequence;
there is no fresh generator, reset RTC domain or deterministic fallback. The
same private Request/verifier prevents reacquisition for an accepted challenge.
Acquisition failure terminates this attempt, and the original8192 exchange cut
still includes acquisition/scheduling time. No existing Anchor or durable floor
is reset or restored by this operation.

Only `/time/<64 lowercase hexadecimal nonce>` is requested. The untrusted host
relay encodes the existing1024-byte draft11 request and sends it to the explicit
162.159.200.1:2003 endpoint. The independently provisioned Cloudflare key remains
compiled into ev-time-proof; neither relay, HTTP peer, DNS nor downloaded metadata
can replace it. Provider disappearance/profile changes refuse without fallback.

A separate HTTP parser requires200, exactly one bounded Content-Length,
uncompressed/nonchunked framing and actual EOF. It copies at most864 body bytes
into private Root storage, permits at most512 header bytes and128 bytes per line,
and rejects truncation, excess bytes, ambiguous framing or overflow. No borrowed
ClientWindow view survives an RPC or reaches the signature verifier. The existing
Hello28-byte equality proof remains independent.

Client.finish consumes the pending challenge before any attempted verification,
checks the exact pinned-key delegation/signature/nonce path and original exchange
policy, then yields only an Anchor. Actual RTC samples after cryptography and at
the next local decision point pass Anchor.observe_post_crypto, enforcing domain,
monotonicity, initial exchange and maximum age without inventing a durable floor.
The Anchor remains a private unqualified candidate. Network/source failure or
shutdown invalidates it. Cancelling this local candidate cannot acknowledge,
release or replay unknown actual protected peer work.

## Conditional clock model and publication boundary

The fixed policy uses one-second floor quantization, a conservative minimum rate
of1/2, exchange30seconds, anchor age60seconds, future window1second and signed
radius at most10seconds. ADR0079 records the source mechanism and actual read-only
host observations. The rate is an explicit healthy trusted-Linux/QEMU contract,
including clocksource, privileged clock administration and correct suspend
accounting. It is not inferred from NTP labels, MAXFREQ/tolerance or finite tests.
No PIT-to-UTC conversion is used.

This implementation does not have a qualified-provider gate or an actual durable
floor and cannot supply security time. A new remote update decision must first
complete all material, hash, signature and relationship checks. A fresh qualified
provider callback then authorizes that exact prior head, immutable material
references, proposed state and retained floor. The affine Decision and Commit
persist this already-authorized transaction. A later pause delays durability;
neither the durable acknowledgement nor activation claims new UTC freshness.
A cached decision cannot authorize another head or a newly started decision.

Finite original I/O cuts, poison, interruption and cold revalidation are separate
requirements. Failed or uncertain I/O never reports a new publication and retains
the actual ownership debt. An uncertain final publication may recover the old or
new complete checkpoint; ordinary cold reopen authenticates the actual committed
material and floors without requiring network time. Host/VM pause, suspend and interruption tests
remain required. No zero/fictitious floor is passed to Anchor.window to simulate
a qualified provider. This Level B decision boundary follows
[E-019.41–43](../plans/platform/E-019-update-and-lifecycle.txt), where freshness
affects new update decisions; it does not waive those requirements.
Installed software, local data and recovery remain usable when remote time is
unavailable. Separate authenticated TP diagnostics below retain factual unqualified outcomes;
NW and TM records are not repurposed as verification/UTC evidence.

## Actual linked resource result

The first serial-backend linked joined Root requires121 image pages and127
private frames:102text,7ro,4rw and8declared stack pages. Its ELF SHA256 is
`e153a27dfc96041402335a88fd326415160a0fa46f6ccd3a2cc5a3e89b007a0a`, retained
in the local engineering archive. It correctly refuses108/114.
The unchanged32KiB linked resolved-reference stack census is23,144bytes, with
9,624bytes margin. This is not a runtime high-water/formal whole-program bound.
The linked actual private Client begin/finish, packet verification and strict
Ed25519 path remain present and reachable. No guest execution is claimed.

The manual first build flags omitted the already required serial-curve config;
the bare-metal compile guard refused and the parallel unsupported SIMD codegen
also failed. Those logs remain retained. The corrected measurement uses the
exact producer's pinned serial backend; no ISA/context/crypto check is weakened.
The measured V4-only124/128/130 supplement is documented in ADR0077. Root512 and
Boot1024 accounting are distinct; unchanged32KiB Root and256KiB Kernel stack
preflights remain mandatory on the actual new selected factory before any VM.

## Verification

Tests exercise all fragment splits of the actual public signed packet, the864B
body limit, truncation at every prefix, duplicate/negative/oversize headers,
compression/chunking, malformed status and excess bytes. A coupled real Packet /
Client model exercises actual Close→Closed→Connect, partial accepted writes,
immutable original cuts, exact public nonce URI, real EOF and affine verification
of the preserved public fixture. Expiry/regression and unknown completion tests
confirm no replay or reuse of a quarantined window. Public fixture tests are not
fresh entropy or an actual provider/guest claim.

## Bounded TP diagnostics

Source Root sends `[T,P,stage,result,argLE32]` only on its existing Events route.
Stage1 is actual private Client issuance with its u32 sequence; stage2 is actual
private response length1..864; stage3 is verified-unqualified draft profile11.
Positive stages have result0. Stage4 reports the failed stage1..3 with result
clock1/entropy2/policy3/proof4/exchange5. No UTC-qualified value exists. The Kernel
observer must authenticate actual Root origin and the Host retains the full
public nonce/request/response from its separate untrusted fixture ledger.

At most4 immutable lifetime frames are retained, each with its original4096-tick
local preaccept cut. Received and verified may queue together; one ordinary-tick
SEND attempt preserves canonical Busy without extending its cut. Success retires
exactly once even across preemption; scalar SEND has no Kernel-atomic caller cut.
Expired/refused/unaccepted frames disappear without fabricating success, and
retention still drains after the private Time state is terminal. Pending TP rows
are included in ordinary shutdown receipt draining. A terminal3/4 ends reporting;
normal owner shutdown quietly invalidates the private Anchor and produces no
new failure. Later source failure likewise cannot retroactively make an old
verified-unqualified row a current qualified-time grant. These records do not
relax transport cuts, create UTC authority or acknowledge unknown peer loans.

## Explicit owner arm

Only the actual native-network Root owner-console Lines path accepts the complete
`time-probe` command, with no arguments/prefix/partial/end-of-input approval. It
requires successful Hello, the retained Running network state, nonquarantined
sole Client, healthy RTC source, no busy content backend or transition, cached
Ready and fresh actual ProcessCONTROL observation of both network actors. The
arm is accepted at most once for this Root. Repeated/busy/unavailable requests
produce a readable refusal without RNG output, new accepted work or debt reset.
No App/Shell event or packet can invoke this hook.

The existing NR payload appends Operation21 `time-probe` without changing older
IDs, bytes or framing. NRok means only arm acceptance. TP3 is the separate
verified-unqualified attempt result; neither label is UTC or a human-consent
claim. Future content/network users must exclude Time.active so high-level TCP
protocols do not interleave over the same sole client owner.
