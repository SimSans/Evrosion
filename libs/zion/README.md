# Internal native `.zion` container

`ev-zion` is a bounded, safe `no_std` reader and a deterministic host producer.
It preserves the native package requirements in E-016 and R-009; `.zion` is the
current spelling recorded in the supersession registry. Parsing checks integrity
and requirements, and grants no namespace, publisher, update or runtime authority.

One canonical `ev-app-identity::AppId` is shared with the picker. Stable AppId,
publisher claim, exact package hash, build identity, release version and live
process/incarnation are separate values. An untrusted claimed AppId cannot
inherit an existing application's private data or remembered grants.

The initial Internal format has a 96-byte header, sorted unique manifest TLVs
and 128-byte entry rows. It contains one ELF64 and up to 15 resources, all in
contiguous checked extents with content hashes. The bounds are 2 MiB total,
4 KiB manifest and eight required contracts/capability requests. These are
implementation limits, not permanent platform limits. Paths reject traversal,
absolute names, aliases, duplicates and ambiguous encodings rather than extract
or normalize them. Packages contain no install script or external payload URL.

Unknown major/schema/required semantics fail. Known additive optional fields
may be ignored. Platform minimum, ABI, required contract major/minor and features
must pass `compatible` before lifecycle metadata can be staged. Target platform
does not impose a default maximum. Actual ELF W^X/entry/stack/quota admission and
trusted owner/update permission remain separate mandatory checks. Capabilities
are semantic requests; a selected File is granted only by the real trusted flow.

`lifecycle::Record` is a 256-byte, integrity-checked metadata head for one stable
AppId. It prepares install, stage, activate, replace, rollback, removal and
reinstallation snapshots with nonwrapping revision preconditions. Staging keeps
the current version active. Removal retains identity/data schema; incompatible
data rollback refuses instead of erasing data. Persistent references contain
package hashes and schema intervals, never handles, paths or process IDs.

Preparation does not publish a durable change. A trusted registry owner must
write through an independently scoped Store-v2 region, recover indeterminate
writes, reopen/read back the committed record and resolve each full package
reference against the actual compatible immutable package. It must revoke and
quiesce live incarnations when activation/removal requires it. This library
does not claim those I/O or live-process boundaries have been integrated yet.

The frontend's `native_package` producer validates the actual measured six-role
Hello ELF, packages it with a resource and rechecks the resulting container.
The full desktop producer can bind its AppId, package hash and build identity
into Root's measured readonly catalogue. It performs no privileged installation.

Portable checks currently cover 20 package/lifecycle cases and strict host/
bare-metal lint. Actual package-backed graphical launch, persistent lifecycle,
Job inspection and provider replacement remain M5/0.1 integration work. See
[project status](../../docs/status/PROJECT_STATUS.md).
