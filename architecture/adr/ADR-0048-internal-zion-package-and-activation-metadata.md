# ADR-0048 — Internal `.zion` package and activation metadata

Status: Accepted bounded implementation; physical native lifecycle pending.
Date: 2026-10-27. Owner mandate Level B, preserving E-016/R-009 guarantees.

The native application needs a self-contained identity and content object rather
than treating an ELF path or process ID as AppIdentity. The safe `ev-zion` reader
therefore validates an immutable bounded manifest, one ELF64, contained resources,
requirements and exact content hashes. A deterministic host producer re-parses
its output. Neither parser nor producer installs, executes scripts or grants
capabilities. The current spelling is `.zion` under the existing rename record.

`ev-app-identity::AppId` owns the single stable 16-byte key shared by package and
picker policy. Publisher claim, package/build digest, release version, user
session and live process/incarnation remain separate. An untrusted claimed key
cannot take over an existing application's namespace, data or remembered intent.
Local owner development is a distinct provenance path, not a forged publisher.

The initial Internal limits are 2 MiB per package, 4 KiB manifest, 16 entries,
eight contracts and eight capability requests. Versioned canonical fields,
checked contiguous extents and strict paths reject ambiguity and aliasing.
Unknown required semantics/major/ABI/contract requirements fail; target platform
does not create an arbitrary upper compatibility bound. A compatibility result
is metadata evidence only. Actual ELF W^X/entry/stack/quota admission and trusted
installation/update permission remain mandatory before activation.

A separate 256-byte application-registry head stores stable AppId, nonwrapping
revision, actual data schema and active/previous/staged package references.
Staging leaves the active version unchanged. Explicit activation, rollback,
removal and reinstallation prepare replacement snapshots. Removal retains data
identity/schema; incompatible rollback refuses instead of erasing data. Each
reference must be resolved against the actual compatible immutable package.
No handle, path or process ID is persisted as runtime authority.

The metadata library performs no I/O. A future trusted lifecycle owner must
publish through a separate Store-v2 region, recover indeterminate writes, read
back committed state and stop/revoke old live incarnations before reuse. Tests
of snapshot preparation are not an interrupted installation or live update proof.

The actual desktop development producer packages its measured six-role Hello
ELF and a resource, then binds AppId/package/build identity into Root's measured
readonly catalogue. Kernel backing verifies the retained package bytes' SHA;
package policy stays outside the generic kernel mechanisms. Native capability
declarations remain requests; a selected File still requires the actual trusted
picker and exact live-process handoff.

Portable source evidence (local engineering archive)
retains 20 package/lifecycle tests, ten picker regressions, two host producer/
ELF-admission tests and strict host/bare-metal checks. The
actual desktop graph (local engineering archive)
now executes Hello with its exact package/image/catalogue binding. This is
development-bundle deployment, not durable installation. Persistent
installation/activation/update/rollback/removal, Job inspection and live provider
replacement remain required for M5/0.1. The parsed-view API also needs immutable
field access before it is used by the trusted persistent lifecycle owner; a
source-bound candidate has been reviewed without changing the container format.
