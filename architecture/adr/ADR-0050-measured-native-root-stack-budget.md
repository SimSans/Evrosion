# ADR-0050 — Measured Native Root stack budget

Status: Accepted bounded implementation refinement. Date: 2026-11-11.
Founder mandate Level B; no foundational guarantee or public Stable ABI changes.

The first actual Native Root failed72 bytes below its guarded16KiB user stack
before Home. The immutable failed run (local engineering archive)
retains the actual binary, fault, preceding worlds, disk and source inputs. The
separate256KiB kernel stack passed its own linked preflight; increasing that
stack would not address the user fault.

A compact immutable parsed package, a uniquely borrowed controller, separated
boot/storage scopes and a dedicated no-pending registry open removed avoidable
copies. A scoped registry boundary preserves the actual device and uncertain
intent on every refusal. These improvements are tested independently; eager
package integrity checks and publication recovery semantics remain intact. The
corrected linked census, including shrink-wrapped prologues, fell from28,176 to
16,616 bytes. The latter still exceeds16KiB by232 bytes before required crash
capture and Job inspection are added.

Further compiler annotation tuning would leave little margin and make valid
storage recovery depend on incidental frame layouts. Rewriting the trusted
Picker solely to shrink its pinned security state would expand the risk and
review scope. Allocating an untracked heap or mutable global controller would
obscure ownership. We instead assign the explicit Native Root profile32KiB of
private stack, pages256..263, with absent guards255 and264. Entry RSP is the
measured top, relative0x108000. Every page is initialized zero, user RW/NX, owned
by the actual Root image and retired with it.

The four extra4KiB pages are charged to that Root Job and its ancestors. Existing
Root limits512frames and producer private admission64frames stay unchanged;
there is no pool increase. Old Desktop Root, ordinary services, applications and
the provider fixture keep their16KiB stacks and upper guard260. The kernel keeps
its256KiB stack. The Native ABI fingerprint and full layout measurement now name
this layout explicitly; startup720, manifest880,21roles and catalogue2048 sizes
remain unchanged. Old Desktop720/784 golden encodings remain byte-identical.

Admission checks actual linked Native Root prologues against the explicit32KiB
budget before a VM starts, independently checks all8 zeroed RW/NX LOAD pages and
both guards, and retains the report. The kernel checks the actual Native Root
upper guard264 while preserving guard260 for other actors. Actual VM acceptance
must additionally prove the four-page accounting increase, all physical detach
and retirement, and the complete lifecycle. Static reference/cycle analysis is
supporting preflight, not a formal recursion/indirect-call or high-water bound.

This supersedes ADR-0049's initial assumption that no Native Root stack growth
would be necessary. It does not accept M5 or0.1, weaken a resource quota, or change
the authorization/recovery model. The prior failures and measurements remain
historical evidence.
