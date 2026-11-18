# Bounded M5 Native lifecycle acceptance

Accepted 2026-11-11 for the Native lifecycle subtask. M5 and0.1 remain active.
The immutable physical proof (local engineering archive)
retains744 files,428 compiled sources and every1,077 manifest input hash, including
actual executables, complete packages, image, raw VM output, scanouts and disks.
Kernel SHA256 is `5a55dd4440569dc6b0f6c07d61ecb666d115e1a0f243a260b7be3bee5a931f02`.

Six cold Q35/TCG/OVMF VMs share one runner-owned persistent disk, initialized by
copying the exact accepted M4 disk. The original checkpoint is untouched. All
normal operations are performed by the source-built userspace Root and Block
service; host observers cannot write or repair the Store.

| Phase | Proven behavior |
|---|---|
| Install | Actual A activation and15 complete graphical stages, fresh picker consent,3selected READ deliveries and denied writes, real App/Shell faults and replacements, surviving Display. |
| Update | Cold A opens1001; staging B preserves A's live identity; explicit activation retires A and starts B, which durably saves2026. |
| Rollback | Cold B reads2026; A replaces B and reads that same saved value. |
| Remove | App authority/process retire; tombstone and separate private data remain. |
| Reinstall | Cold Home has no installed App; explicit reinstall/activation starts A with2026. |
| Verify/cancel | Cold A opens2026; inspect, cancel and finish leave the entire disk unchanged. |

Each phase independently validates package/container/ELF/descriptor association,
current ABI and declarations, actual process/thread/image start-stop-reap receipts,
matched calls, guarded mappings, readonly banks and full resource retirement.
Raw AppRegistry64..77 and AppData80..93 have expected exact heads/operations;
Notes32..45, Private48..61, System16..29 and every other protected byte remain
unchanged. App data advances once from1001 to2026; registry revision reaches8.

The full phase has9 actual starts,382 matched calls,2faults/restarts and3READ-only
negative results. It finishes in7,193 guest ticks within the unchanged16,384-tick
world limit. Actual syscall/port/continuation/timer quota measurements are retained;
these sampled ticks are not calibrated wall CPU milliseconds or boot latency.
The Native Root's guarded32KiB layout and actual Kernel's256KiB preflight pass.
Reference stack censuses retain their indirect/recursion/high-water limitations.

This closes bounded execution of the native package/lifecycle/data mechanism under
ADR48–51 and the relevant E-025.56–.59 plumbing. It does not close A-003 durable
owner File policy, A-013 taxonomy, live full crash/Job inspection, provider
replacement, actual System health/Known Good composition, or cumulative0.1 release
readiness. Source-built package banks remain development deployment; no general
consumer installer, production publisher authentication or host power-loss claim.
Previous failed attempts remain immutable and linked from the project tracker.
