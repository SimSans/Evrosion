# Host tests

The CLI, doctor, process and boot integration tests are registered in tools/ev/Cargo.toml
and run with `cargo test --locked --offline`. Fetch dependencies first
with `cargo fetch --locked` on a clean host.

Prepared/broken host fixtures use an injected Runner and temporary paths; they do
not uninstall tools, mutate global environment variables or depend on local KVM.
The fixtures check discovery and result interpretation. CI also checks a real
prepared Linux host and a deliberately invalid firmware override.

Process tests use standard Linux utilities and Python to check argv handling,
both captured streams, nonzero statuses, missing executables and the output cap.
Boot tests reject duplicate/missing/wrong-build records, panics, wrong exit status,
invalid framebuffer fields and artifact tampering. Real child-process tests
verify timeout/output-limit termination and reaping. Adapter tests live under
libs/boot-contract and run in the default host workspace test selection.

The architecture checker's Python unittest suite exercises rejected mutations
of repository copies. Run
`python3 -m unittest discover -s tests/host -p 'test_*.py' -v`.
