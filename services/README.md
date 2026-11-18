# Services

Isolated, supervised userspace services, beginning in M2.
Follow [E-007](../architecture/plans/core/E-007-system-service-architecture.txt)
and [Root Authority Custody](../architecture/designs/ROOT_AUTHORITY_CUSTODY.md).
Each service boundary needs an authority and failure-containment justification.

[Root Supervisor](root-supervisor/README.md) is the first source-built bootstrap
executable. It creates and delegates isolated Echo services, observes faults and
replaces a victim while another service remains responsive. Generated calls use
actual bounded scheduler waits, deadlines and late-reply rejection. Whole Root
device-free incarnation recovery is qualified within the
M2 acceptance bounds. General reconstruction of
the device-bearing shared Root/storage base remains separate work; later native
and downloaded-cohort recovery does not imply that broader proof.

[Desktop actors](desktop/README.md) begin M4 with separate measured App/Display
images. The complete bounded shell/input/picker/crash/relaunch gate passed M4;
M6 readiness adds the connected developer alpha
and records its current scope. These milestones do not qualify arbitrary hardware
or a complete consumer desktop.
