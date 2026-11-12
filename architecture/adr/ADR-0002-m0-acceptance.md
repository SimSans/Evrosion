# ADR-0002 — M0 acceptance

Status: Accepted bounded engineering scope. Public technical edition.

M0 acceptance requires an observable UEFI kernel entry, validated boot handoff,
serial/framebuffer diagnostics, usable symbols/debugging, pinned inputs and
repeatable build/test evidence. The normal frontend must distinguish guest
protocol/exit outcomes from host success and preserve failed attempts.

M0 is a kernel/toolchain engineering gate. It is not a desktop, hardware,
production-authentication or public-release certification. Later milestone
mechanisms and source publication have their own evidence and readiness checks.

Build/run/debug tools are replaceable development infrastructure. They must not
become a runtime OS dependency or silently redefine the architecture. Artifact,
source and environment identities remain explicit. Historical gate results do
not automatically accept a differently edited publication snapshot.
