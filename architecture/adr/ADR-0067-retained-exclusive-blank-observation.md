# ADR-0067 — Retained exclusive blank observation for Native install

Status: Accepted implementation refinement; controlled execution validation pending.
Date: 2026-11-12. Engineering mandate Level B; no foundational guarantee change.
Related: ADR-0049; ADR-0052; ADR-0064; M6-02.

## Measured problem

Isolated session probe06 reaches protected Home and reports successful cold
open with no recovery requirement. Install then reaches its original 8,192-tick
aggregate cut: actual Root→Block call130 reads RootSystem logical27
(AppRegistry local11, physical75), starts at tick16,648 and expires at16,849.
Block has consumed its actual64/256 window. Source refuses Install, reports five
completed backend mutations and recovery required, then refuses Activate. The
conformance driver times out waiting for its expected App. The original FAIL,
all source inputs, artifacts, logs and before/after disks remain retained; it is
not successful session acceptance.

`State::open` had already read both complete fourteen-sector AppRegistry/AppData
regions before privately recording `blank=true`. Install repeated that entire
28-sector scan, after which each `Store::format_new` again checks its own complete
region. Probe06 sampled Root reads consume24–26 charged Block ticks apiece
(median24); elapsed intervals vary24–216 with window position. Removing28 reads
therefore saves approximately672–728 charged ticks, or2,688–2,912 ticks of quota
opportunity at a25% allowance. This is an estimate from real samples, not an
independently timed whole-scan interval or a guarantee that Install will fit.

## Decision and ownership scope

Remove only Install's repeated both-region scan. Retain the private observation
made by successful `State::open`. Retain EACH actual `Store::format_new` full
blank check before that Store writes anything. Do not weaken Store validation,
format after failed open, extend any accepted operation, increase8,192/1,024
transaction/child cuts or increase CPU quotas.

This reuse applies to the closed Native RootSystem graph and its owned VM disk:

- One move-only Backend serializes access to AppRegistry and AppData. The closed
  route grants no competing child writer to those physical regions, and no
  concurrent host process writes the owned runner disk.
- Only successful cold open can create private blank credit. Install requires
  that credit, no record and no pending publication. With no active record,
  `admit` cannot create a data Session; data requests cannot write before install.
- System, remembered grants and session Note operations use disjoint regions.
  Their metadata or successful writes cannot substitute for AppRegistry/AppData
  blank credit or modify those regions.
- Successful install consumes blank state. Any failed or unknown mutation fences
  the owner through existing recovery/Backend poison before another install or
  open may issue I/O. No accepted write or flush is replayed to obtain an ACK.

This is a private exclusive-writer observation, not a generally fresh cached
view of arbitrary devices. If an outside writer violates that scope between
open and install, each Store's actual blank check still refuses to erase its
foreign region. The other region may already have been formatted before that
refusal: this operation is not a cross-volume atomic transaction. It requires
explicit recovery and must not report a successful install or silently repair
or retry the partial allocation.

## Verification and remaining acceptance

Host tests execute actual State→Backend→Store operations and inspect their real
transport requests. They cover every sector of both nonblank cold regions,
missing/failed observations, foreign writes after observation, lost write/flush
replies, retry fencing, cold reopen, and disjoint System/grant writes while no
App data Session exists. Model tests do not prove actual device execution.

Require strict session and finite Native/M4 Source checks, then a separate cold
probe07 from the exact probe06 source with only this production change. Preserve
that original result and its source/stack/artifact identities before any further
refinement. Neither this optimization nor a passing isolated old-UI probe closes
current-source M6 session, hostile-peer containment, network, recovery or full
retirement gates.

The Probe06 retention record is in the local engineering archive,
SHA-256 `b1b8182c9c711e8ecce61d221f167f0b2442b0fe88f0b82d86cf6e2a8d077a7d`;
its portable archive SHA-256 is
`fc2a55e3a8c92c7a310127aeb4dc445a8b931ab0be5e565771d047ae60b3fa25`.
These archives retain local diagnostics; durable status publication
requires an explicit retained evidence record, without changing the old failure.
