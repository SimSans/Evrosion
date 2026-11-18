//! Exact private Core debt/fence state tests; not hardware execution or the
//! actual captured Runtime's process/queue exclusion gate.
#[path = "network_fault.rs"]
#[expect(
    unexpected_cfgs,
    reason = "The imported Kernel source has a Kernel-only negative fixture feature; this Host target runs the ordinary fence cases"
)]
mod network_fault;
