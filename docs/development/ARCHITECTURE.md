# Architecture overview

Evrosion's destination is an OS that configures and repairs ordinary operation
with little effort while preserving full deliberate owner control. The three
responsibility layers share one system. Local/offline operation, accessibility,
data preservation and expansion are foundational; the small kernel is a means
to those product guarantees.

The [architecture index](../../architecture/ARCHITECTURE_INDEX.md) is the canonical
map. [Invariants](../../architecture/INVARIANTS.md), [governance](../../architecture/GOVERNANCE.md)
and accepted [ADRs](../../architecture/adr/README.md) define the boundaries and
change process. This overview routes to them rather than replacing the plans.

The current graphical development path is:

```text
UEFI → kernel → explicit initial Root authority → SourceRoot policy
                                  ↓
                    isolated Shell / Input / Display
                    File / Block / packaged Hello
                                  ↓
                capability-routed typed requests/replies
```

The kernel owns mechanisms: address-space isolation, capability enforcement,
object lifetime, scheduling/Job accounting and IPC. Root Supervisor builds the
service graph and owns explicit lifecycle/policy decisions under its bounded
bootstrap capabilities. Root is a userspace supervisor, not ambient authority
available to ordinary processes.

Applications are identified by stable AppId and separate immutable `.zion`
package/build identity. Declarations request capabilities. Actual delegation
requires trusted policy and a live recipient: the selected-file path gives one
readonly File endpoint for the approved stable object rather than broad storage.
See the [identity taxonomy](../../architecture/designs/IDENTITY_TAXONOMY.md),
[approval binding](../../architecture/designs/PICKER_APPROVAL.md) and
[package guide](ZION.md).

Jobs attribute resources to the actual hierarchy. Crashes and Stop/Reap retire
live authority; replacement must not duplicate it. Durable permission policy is
separate from runtime handles and from installation metadata. The grant-policy
library has a [four-cold-VM execution proof](../release/0.1-preview.md#validation-and-provenance)
for explicit remember, fresh cold remint, live revocation and cold denial. Its
fixed local owner route is separate from future production Trusted Control.

System Generations are coherent immutable bootable implementations. Declared
health, protected KnownGood and independent recovery support return from a bad
generation. User/app data belongs to separate durable state and survives normal
rollback. GUI readiness or an app Store's format context is not System health.
See [boot health](../../architecture/designs/BOOT_HEALTH.md) and
[M3 acceptance](../../architecture/M3_ACCEPTANCE.md).

The current QEMU proof is bounded BSP userspace with controlled devices and no
DMA/general hardware qualification. Broader self-configuration, protected owner
controls, preservation-first installation and bundled Windows compatibility
remain product work. Their staging after the native proof does not remove them
from Evrosion's destination.
