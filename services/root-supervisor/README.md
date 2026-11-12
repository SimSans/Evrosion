# Root Supervisor

The first separate Rust/no_std userspace startup executable. `cargo ev build`
builds and measures it with the pinned compiler and embeds the matching Internal
development bundle in the kernel. `python3 tools/m2/binding.py` runs cumulative
host, lint and repeated QEMU acceptance, including a separately built fault variant.

The kernel supplies a versioned, read-only/NX record with exact scoped handles in
RDI/RSI. The shared `ev-userspace-contract` codec validates it. Startup uses only
Memory READ and Endpoint SEND, checks denied authority, sends typed Ready, then
yields. Ready means the startup contract was validated. The fault variant writes
the record to exercise actual user-fault handling; normal code excludes that path.

Separate graph artifacts receive explicit Job CONTROL and measured image READ.
They create Jobs/processes/channels, delegate exact service roles and launch typed
Echo traffic. The synchronous variant tests actual block/wake and a delayed reply
after timeout. The sustained variant replaces one faulting service 64 times while
another responds, retaining Root identity and accumulated Job CPU charges. Each
artifact is built and measured separately; test injections are explicit features.

Whole Root graph reconstitution, production epoch/generation authentication and
independent recovery remain open. See
[ADR-0035](../../architecture/adr/ADR-0035-supervisor-created-service-graphs.md)
and [M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).
