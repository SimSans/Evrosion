# Performance baselines

The accepted reference record (local engineering archive)
joins the complete five-cold System proof and five separate checked IPC samples.
These values describe the retained source/artifact cohorts on the current host;
final whole0.1 readiness remains separate.

| Measured operation | Retained bound |
| --- | --- |
| SystemFull spawn to first Home receipt |33.2427–33.2474s; includes firmware, conformance preludes and explicit System initialization |
| First App stimulus to receipt |5.7728–5.7782s active; includes install and activate |
| Relaunch stimulus to App receipt |1.3179–1.3246s active |
| Shell fault stimulus to restored App receipt |1.2214–1.2266s active |
| Other basic response samples |0.2444–1.3969s active across the separately labelled focus/content/cancel/containment samples |
| Kernel ELF / UEFI image |43,462,288 /45,154,304bytes |
| Held-point Kernel/system base-RAM interval |45,150,208–56,360,960bytes; exact final arena return |
| Median five-sample4096-RPC host batch |796,507,362–798,666,597ns |
| Amortized median host batch per checked RPC |194.4598–194.9870μs; includes barriers, scheduling, framing and delivery |

The IPC guest delivered-IRQ spans are792,794,808,782,794; median794. They are a
separate counter sample. They do not calibrate physical time. The full ten
presentation intervals, individual five IPC brackets, environment and precise
uncertainty remain in the record; the table rounds values for reading.

Evrosion 0.1 records regression baselines required by [R-011.28](architecture/plans/release-project/Evrosion_R-007_to_R-011_Superfile_v1.md). Preserve the measurement context and uncertainty with each number. These measurements do not establish a hardware speed target or complete 0.1 acceptance.

Use the exact retained source/build manifest, ELF/image hashes, toolchain/profile, firmware, QEMU version and command, fixture/phase, disk starting state, serial log, observer records and QMP transcript. The current reference runner uses Q35/TCG, CPU `max`, one virtual CPU and 256MiB base RAM. Compare the same fixture and starting state; include the host/environment record when comparing runs. TCG results describe this reference workload. Keyboard/UART commands are recorded test stimuli; these automated runs do not certify human participation.

| R-011.28 baseline | Measurement and retained evidence | Acceptance |
| --- | --- | --- |
| Boot duration | `owned_spawn_to_first_home_present` in `boot/run-001/performance.json`: host spawn bracket to first complete, validated Home Present receipt; matching unmodified scanout. Includes firmware, Kernel conformance preludes and any fixture-specific provisioning. | Complete accepted run; expected metric present and valid. Report its interval and fixture, never whole workflow duration as boot latency. |
| Image size | Verified `kernel_elf_bytes` and `uefi_image_bytes` in `memory-image-baseline.json`, joined to exact manifest hashes. | Artifacts reverified. External data disks and retained debug/symbol artifacts remain separately labelled; this is not installed-storage usage. |
| Kernel/system memory | Three actual allocator snapshots plus validated retained Kernel input range; `resident_ram_interval` in the same baseline file. | Complete before/held/after sequence, held ownership, exact final frame return, exact input/ELF byte-length match and fixed-memory command/QMP checks. Report lower/upper bytes and unattributed envelope. |
| IPC microbenchmark | Separate source-built client/server/Root: 64 warmups, 4,096 checked SDK RPC roundtrips, actual counter/route brackets, Source clock sample and host serial-availability bounds. | Five actual samples pass source, counter, cleanup and positive host-duration checks in the linked record. The ten-call provider replacement test remains separate functional evidence. |
| App launch | `stimulus_to_hello_present` and `stimulus_to_relaunched_without_grant_present`: recorded action to expected App receipt with actual identity and pixel checks. | Exact action/starting state retained. The first Native action includes install+activate; label that complete operation. The relaunch sample is a distinct cached/persistent-state workload. |
| Frame/basic responsiveness | Other `stimulus_to_<stage>_present` records for content, focus, cancellation, containment and restoration. | Expected semantic stage, identity, protected Present and actual scanout checks pass. These are response bounds, not refresh rate or raw compositor/display latency. |

The host ledger uses monotonic nanoseconds as a storage unit. Begin brackets surround actual process spawn or the complete keyboard/UART action. End brackets surround host availability of a complete authenticated Present receipt, using the previous serial-read start and current read completion. Polling sleeps target 4ms, but scheduling, serial output and observer work can widen uncertainty. Nanosecond units do not imply nanosecond precision. The endpoint includes receipt transport and observation; it does not locate the exact guest Present instruction or panel scanout time.

QMP `stop`/`cont` acknowledgements alone do not establish pause boundaries. The ledger retains command-send times and successful `query-status` observations. It subtracts a conservative pause interval: guaranteed overlap between confirmed paused and resume-send, possible overlap between stop-send and confirmed running. Publish both wall and active min/max plus excluded-pause bounds. Incomplete/reordered transitions make a timing record invalid. Running-VM host scheduling, TCG, source diagnostics and I/O overhead remain in the observation.

The held memory point follows actual RootExit0 with zero outstanding RPC, before final common-owner teardown. Some earlier App incarnations may already be retired. The lower bound adds disjoint reserved ELF input pages and currently allocated Usable-arena frames. The upper bound is configured base RAM minus actual free Usable frames; it conservatively includes Kernel BSS/COW, loader, firmware and address-hole uncertainty. Kernel virtual image span and hierarchical Job charges are separate dimensions. This is neither peak usage, host RSS nor an exact attribution of all reserved RAM; device VRAM is outside the base-RAM scope.

Current latency hooks cover Native `install-full` and composed System `system-full` through the shared desktop observer, alongside the old desktop reference path. Other cold phases have no latency ledger yet. Their absence is not a zero-latency result. The separate IPC sample retains delivered guest IRQ ticks and exact `(last-first)/4096` ratios. IRQ counts exclude undelivered time during interrupt-masked Kernel work; a zero span is below resolution, not 0ns. Its separate host bounds bracket complete Before/After serial availability using the preceding read start and current read end. They include Root barriers, scheduling, sample framing and serial delivery uncertainty. Require a positive guaranteed host lower bound in every sample; coalesced reads remain unresolved. An amortized batch duration per RPC is distinct from exact client-only or physical latency.

Publish values only after complete source-bound execution, independent functional/durable-state validation and immutable evidence retention. Require the expected nonempty timing names, every `valid=true`, ordered finite bounds, matching observer stages/captures and complete QMP transitions. Keep failed or incomplete runs as failures. Retain individual samples and any declared summary; do not silently select the fastest result. Performance acceptance remains separate from functional conformance and requires every R-011.28 row to have accepted evidence.
