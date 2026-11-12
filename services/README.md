# Services

Isolated, supervised userspace services, beginning in M2.
Follow [E-007](../architecture/plans/core/E-007-system-service-architecture.txt)
and [Root Authority Custody](../architecture/designs/ROOT_AUTHORITY_CUSTODY.md).
Each service boundary needs an authority and failure-containment justification.

[Root Supervisor](root-supervisor/README.md) is the first source-built bootstrap
executable. It creates and delegates isolated Echo services, observes faults and
replaces a victim while another service remains responsive. Generated calls use
actual bounded scheduler waits, deadlines and late-reply rejection. Whole Root
incarnation recovery remains separate M2 work; see the
[executed checkpoints](../docs/release/0.1-preview.md#validation-and-provenance).

[Desktop actors](desktop/README.md) begin M4 with separate measured App/Display
images. The complete shell/input/picker/crash/relaunch gate remains pending.
