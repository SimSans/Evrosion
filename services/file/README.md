# Scoped File actors

The accepted standalone M3 `server`/`app` proof profiles remain separate from the
new full-desktop profiles. The generated File-v1 protocol still carries logical
read/replace operations and per-object counters, without global volume operation
IDs, sector pointers or object selectors.

`desktop` opens existing Notes/FileA and Private/FileB Store-v2 volumes;
`desktop-provision` explicitly requires both regions blank before initializing
their measured seed envelopes. Neither falls back to format after open failure.
These are separate measured images; choosing a profile is a trusted startup
decision, not an application flag or capability.

Four actual receive endpoints fix Notes/Private and RO/RW. The actor privately
copies normal256-byte requests before backend I/O. Scalar `FMQ1` metadata calls
on the RO endpoints read real envelope counters and SHA-256 payload words without
loading/storing the App window. Ready events are `EVFLRDY1` after successful
initialization and actual receiver binding. Unexpected failures refuse rather
than fabricate readiness or metadata.

See [the full profile contract](../block/DESKTOP_STORAGE.md) for exact roles,
shared-window/lifetime restrictions, scalar codec/error semantics, seed and
metadata identities, provisional data-container scope and remaining physical
integration proofs. Host/target checks are not integrated VM acceptance.
