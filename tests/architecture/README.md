# Architecture fitness tests

## Slice 0: repository checks

Run `python3 tools/check_architecture.py` from the repository root.
This standard-library Python helper is limited to repository governance; the ev
frontend and future OS implementation use Rust.

The checker validates required governance files, unique invariant/ADR/exception
IDs, invariant references, local inline Markdown link targets and heading
anchors, exception metadata/expiry/register consistency, imported source hashes,
and temporary bootloader dependency placement. Source plans are checked against
their inventory; their historical prose is not linted as current governance.

Canonical documentation uses inline Markdown links and ATX headings. Code fences
are excluded from prose checks. External URLs are not fetched, and the checker
is not a complete Markdown renderer or a proof of architecture semantics.

Exception conditions read [status.toml](../../architecture/status.toml).
Reviews must update those declarations when advancing a milestone or contract.
Regression tests mutate copies under a temporary directory to check that broken
records actually fail:

`python3 -m unittest discover -s tests/host -p 'test_*.py' -v`

## System proof coverage

`cargo ev build` followed by `cargo ev test boot` runs the actual AF-001 path.
The default requires three fresh Q35/TCG boots and preserves serial, exact argv,
firmware/artifact hashes, timeout/exit status and JSON results in build/m0.
Host protocol tests and timeout tests also exercise negative results.
`cargo ev test m0` runs the full M0 suite; executed results and evidence paths
are in M0 readiness.

| Proof | Earliest implementation | Current status |
|---|---|---|
| AF-001: observable UEFI/QEMU boot | M0 Slice 3 | Passed locally: three fresh TCG boots; CI configured |
| AF-M0-016: deliberate panic and symbols | M0 Slice 4 | Passed at M0 acceptance: build ID, bounded message and source location; GDB source/backtrace workflow |
| AF-015: byte-identical unsigned images | M0 Slice 5 | Passed at M0 acceptance: two fresh clones on one prepared host; not hermetic or independent-host (EXC-0002) |
| AF-M0-017: validated framebuffer | M0 Slices 2 and 5 | Passed at M0 acceptance: validated framebuffer/memory handoff, negative cases and a serial-only fixture; no physical GPU coverage |
| AF-003/005/009: capability denial, attenuation and Memory Object authority | M1 | [Executed host and CPL3 evidence](../../architecture/M1_ACCEPTANCE.md); aggregate acceptance PASS (local engineering archive) |
| M1-01 bootstrap physical frames | M1 | Host boundary tests and real boot proof PASS; frame selection only; see the mapping substep below |
| M1-02a owned scratch roots | M1 | Host ownership and QEMU map/unmap/remap/root-switch proof PASS; later isolation, fault and reclamation proofs are linked from the M1 acceptance contract |
| AF-007A–H: root reconstitution | M2 | [Bounded executed acceptance](../../architecture/M2_ACCEPTANCE.md) |
| AF-IPC-001–010: synchronous IPC discipline | M2 | [Bounded executed acceptance](../../architecture/M2_ACCEPTANCE.md) |
| AF-010/011: generation rollback and interrupted durable subset | M3 | [Bounded executed acceptance](../../architecture/M3_ACCEPTANCE.md); physical cold attempt exhaustion remains model-only |
| AF-012/013: graphical app isolation and exact picker grant | M4–M5 | [Bounded M5 acceptance](../../architecture/M5_ACCEPTANCE.md): actual crash/restoration, selected-only READ and durable owner-policy regression |
| AF-014: provider replacement | M5 / 0.1 | Actual replacement PASS (local engineering archive): unchanged consumer/contract, real A retirement/B binding |

The complete matrix and acceptance gates are in the
[Pre-M0 package](../../architecture/plans/roadmap/PRE-M0-implementation-package-v1.md).
