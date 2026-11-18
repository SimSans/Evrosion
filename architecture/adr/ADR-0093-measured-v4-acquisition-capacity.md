# ADR-0093 — Measured V4 acquisition image capacity

Status: Accepted Level B implementation refinement; fresh complete-image Kernel census and actual guest load/retirement remain required.

## Evidence

The integrated V4 updater includes bounded network downloads, metadata
authentication before permanent image preparation, fresh actual-Store-bound
authorization, candidate publication and durable Registry selection. After
removing duplicate authorization results and unnecessary cancellation-owner
returns, its actual release component uses 198 image pages, 204 initial private
frames and a resolved 30,760/32,768-byte userspace stack with no unresolved
indirect calls. The 176-page ceiling from ADR-0084 refuses this component before
VM execution. The earlier cold-only component fits that old ceiling; it does
not contain the full acquisition path.

Same-source private compiler experiments preserve the rejected alternatives.
Root-only size optimization reaches 176 pages but 41,128 stack bytes; the
stronger size setting reaches 172 pages but 41,624 stack bytes. Neither is
accepted. A medium address-model experiment fails the actual high-address ELF
link with out-of-range 32-bit relocations. The release optimization and large
address model therefore retain their existing policy. Both experiment reports
are retained in the local engineering archive.

## Decision

An exact verified V4 Root manifest may admit at most 208 image pages, 212
private mapping-owner slots and 214 initial loader-owned private frames. The
image-plus-four/image-plus-six formulas remain. This is a bounded adjustment to
the measured internal profile. It neither reserves those physical frames nor
promises that every simultaneous maximum will fit the graph.

The SDK ABI, layout record and producer bind these limits explicitly. The
dynamic-image description distinguishes its two lazy control/table frames from
the initial 214-frame ceiling, with an updated description digest. Existing
content namespace identity and App ABI remain independent of this Root build.

Root's 512-frame and Boot's 1,024-frame quotas, 64 capabilities, 32 KiB Root
stack, 256 KiB Kernel stack, CPU accounting, process/thread limits, W^X, guards,
fixed virtual layout, child limits and two 64-page dynamic extents remain.
Ordinary 64-page and Native3 96-page constructors retain their independent
bounds. Every actual allocation, ancestor charge and physical retirement still
has to succeed. No general Kernel/Root replacement claim follows.

## Checks and required joins

SDK tests bind the new layout and digest. Core tests admit the actual manifest
shape through 208 pages and refuse 209 before loading; ordinary and Native3
constructors continue refusing their over-limit inputs. The complete 212-slot
mapping owner is exercised through capacity refusal, exact rejected-frame
retention, unmap and full reclamation.

The topology test charges the defined 534-frame initial private-image subtotal
to the actual Boot ancestor, then models both dynamic extents/control frames:
Root 344, Boot 664. Root and ancestor saturation still refuse without partial
charges. These subtotals exclude other ownership families and are not a complete
physical peak measurement. The SDK's 97 tests and Core's 454 tests pass, as do
their strict host checks.

A fresh exact-source complete producer must measure the larger retained Core
owners, preserve both observer paths and actual world reachability, and pass
the unchanged 262,144-byte Kernel census before VM execution. The selected Root
must separately pass its image/frame and 32 KiB stack checks. Actual acquisition,
selection, offline cold loading, graph peak admission and complete frame/metadata
retirement remain joined VM gates. Any refusal remains retained; no artifact
or selection-pointer fallback is permitted.

## First complete-image refusal and IPC retirement refinement

The first frozen acquisition source (`cbcbb732f84f4b96…`) builds, but its
selected Kernel census is 264,224/262,144 bytes. It refuses before VM. The
retained cleanup chain includes a 37,664-byte `Mailbox::retire_managed` frame;
larger V4 owners are still live in its outer frames.

Retirement previously returned a full staged Authority inside a Result before
committing it, retaining an unnecessary large return slot alongside the private
transaction. Keep one staged Authority and return only Result<(), Error> from
the checked transaction. All mutations still apply to that private copy. The
live Authority changes only after every close/collection/object check succeeds;
failure returns the unchanged Mailbox and leaves every Authority field and
generation unchanged. Early unmanaged/undrained refusal order remains.

The 33 IPC tests, all 454 Core tests and strict checks pass. Existing hostile
retirement failures now compare every Authority field/generation as well as the
Mailbox and metadata counters. This implementation refinement changes no IPC
wire, authority, ownership, retirement precondition or stack bound. A second
fresh frozen source and selected linked census are required; the refused first
source and all its artifacts remain intact.
