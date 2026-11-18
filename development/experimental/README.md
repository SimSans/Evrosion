# Optional 0.4 experiments

These source patches preserve isolated work that is outside the default build. Version 0.4 remains unfinished; the accepted runtime is 0.3 and all full 0.4 engineering gates remain open.

| Patch | Paths | Applicability and status |
| --- | ---: | --- |
| `reclaim-frozen-04.patch` | 27 | Current 0.4 tree. Compiled and checked on its archived base; native permanent removal, higher-generation reuse and separate cold reopening remain unverified. Five heading corrections already present in the public tree are omitted. |
| `reclaim-observer-08.patch` | 4 | Requires the reclamation patch. Host observer source only; the native attempts did not qualify permanent removal or reuse. |
| `root-loss-independent-recovery.patch` | 8 | Separate experiment on current 0.4. Bounded native proof on its archived base covers a saved 15-byte file and separate healthy recovery. Unsaved buffers, in-place reconstruction, existing 0.3-data scenarios and full recovery acceptance remain unqualified. Current reader code is preserved. |
| `kernel-present-trace-final.patch` | 6 | Current 0.4 tree. Diagnostic Kernel instrumentation; it excludes the Display fix already in the default development tree. |
| `kernel-present-trace-earlier-01.patch` | 2 | Apply after the final Kernel diagnostic patch to reconstruct the earlier diagnostic variant. |
| `trusted-attention-partial.patch` | 17 | Existing patch preserved unchanged. Partial implementation; native runtime unverified. |

Use a separate branch or copy for an experiment. Reclamation, Root-loss and attention patches overlap; their combined application has not been qualified. The observer depends on reclamation even though its four host file edits also match the unmodified tree.

The manifest records patch hashes, required patches, exact public preimages and postimages, archived base identifiers and qualification limits. Public license metadata and source formatting are retained where they differ from the archived base. Each patch passed an application check in a temporary copy, including its stated prerequisites; no experimental code was merged and no build or runtime validation was run for publication.

To inspect applicability without changing files:

```sh
git apply --check development/experimental/reclaim-frozen-04.patch
```
