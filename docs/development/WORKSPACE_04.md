# Native workspace development

The 0.4 workspace is unfinished. It provides Files, Editor, Inspector and Shell components with explicit contracts and protected operations. It uses a feature-gated host frontend and runner-owned data; it is not an ordinary-user installer.

On a host prepared using the quickstart, inspect its actual options with:

```bash
cargo run -p ev --features workspace -- workspace --help
```

`packages`, `prepare`, `build`, `preview` and `rebuild` require explicit input/output paths. Use the printed help and the corresponding source in `tools/ev/src/workspace.rs`. Package creation, a native link and a passing host test do not prove a guest workflow passed. The observer scenarios qualify bounded reference behavior and retain their own scanout, logs and owned disks.

Do not point workflows at personal or physical disks. Preview owns a new 96 MiB data disk and private firmware variables. Existing data must remain associated with its retained executable cohort; a missing or inconsistent retained cohort is preserved and refused, never silently reset.

The default source contains the joined workspace implementation and the checked Display row-checkpoint change. Experimental deltas are preserved separately in `development/experimental/` with their exact applicability and incomplete runtime status. Permanent removal/reuse has not passed its native warm/cold workflow. All fourteen full release gates remain open; see the M8 plan and progress record.
