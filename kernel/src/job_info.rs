//! Read-only Job facts selected by actual dispatch or an explicit CONTROL cap.
//! Numeric diagnostics never become scheduler identity/authority lookup inputs.
use crate::{
    capability::{Authority, Handle},
    scheduler::{self, JobId, Resource, Scheduler, State},
    service::{self, Metadata, Registry},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidField,
    Caller,
    Service(service::Error),
    Scheduler(scheduler::Error),
}
impl From<service::Error> for Error {
    fn from(error: service::Error) -> Self {
        Self::Service(error)
    }
}
impl From<scheduler::Error> for Error {
    fn from(error: scheduler::Error) -> Self {
        Self::Scheduler(error)
    }
}

/// Query retained usage/limits without changing authority or accounting.
///
/// `actual_caller` MUST come from the kernel's captured, authenticated dispatch,
/// never a userspace PID/Job/domain tuple. Full scheduler associations and a live
/// running thread are checked here; scheduler metadata has no domain ownership
/// table, so only the controller may supply its actual domain association.
/// Handle zero means this actual Job. Every nonzero handle instead requires
/// live Job CONTROL and the Registry's exact full-object/generation binding.
/// Quotas are the queried Job's declared limits; usage includes its descendants.
pub fn inspect(
    authority: &Authority,
    scheduler: &Scheduler,
    registry: &Registry<'_>,
    actual_caller: Metadata,
    capability: Handle,
    field: u64,
) -> Result<u64, Error> {
    if field > 8 {
        return Err(Error::InvalidField);
    }
    if !authority.is_live_space(actual_caller.domain)
        || scheduler.thread_process(actual_caller.thread)? != actual_caller.process
        || scheduler.process_job(actual_caller.process)? != actual_caller.job
        || scheduler.process_terminated(actual_caller.process)
        || !matches!(scheduler.state(actual_caller.thread)?, State::Running(_))
    {
        return Err(Error::Caller);
    }
    let job = if capability.0 == 0 {
        actual_caller.job
    } else {
        registry.job_id(authority, actual_caller.domain, capability)?
    };
    // Validate the full scheduler generation even for field0. A stale retained
    // Registry binding cannot return a diagnostic for a replacement Job slot.
    let limits = scheduler.job_limits(job)?;
    let resource = match field {
        0 => return Ok(job.diagnostic_id()),
        1 | 5 => Resource::CpuTicks,
        2 | 6 => Resource::Frames,
        3 | 7 => Resource::Processes,
        4 | 8 => Resource::Threads,
        _ => return Err(Error::InvalidField),
    };
    if field <= 4 {
        Ok(scheduler.usage(job, resource)?)
    } else {
        Ok(limits.limit(resource))
    }
}

/// Additive, read-only ProcessCONTROL route to the retained admitted process's
/// actual retained Job. Handle zero has no self shortcut here. The registry
/// authenticates the complete domain-local capability/object generation and
/// admitted process/thread/Job associations; diagnostic PIDs are never operands.
/// A stopped process remains inspectable only before registry retirement/reap.
/// This neither installs a Job capability nor permits creation, stop or reap.
pub fn inspect_process(
    authority: &Authority,
    scheduler: &Scheduler,
    registry: &Registry<'_>,
    actual_caller: Metadata,
    capability: Handle,
    field: u64,
) -> Result<u64, Error> {
    if field > 8 {
        return Err(Error::InvalidField);
    }
    validate_caller(authority, scheduler, actual_caller)?;
    let target =
        registry.retained_metadata(authority, scheduler, actual_caller.domain, capability)?;
    read_job(scheduler, target.job, field)
}

fn validate_caller(
    authority: &Authority,
    scheduler: &Scheduler,
    actual_caller: Metadata,
) -> Result<(), Error> {
    if !authority.is_live_space(actual_caller.domain)
        || scheduler.thread_process(actual_caller.thread)? != actual_caller.process
        || scheduler.process_job(actual_caller.process)? != actual_caller.job
        || scheduler.process_terminated(actual_caller.process)
        || !matches!(scheduler.state(actual_caller.thread)?, State::Running(_))
    {
        return Err(Error::Caller);
    }
    Ok(())
}

fn read_job(scheduler: &Scheduler, job: JobId, field: u64) -> Result<u64, Error> {
    // Validate the full scheduler generation even for field0. A stale retained
    // Registry binding cannot return a diagnostic for a replacement Job slot.
    let limits = scheduler.job_limits(job)?;
    let resource = match field {
        0 => return Ok(job.diagnostic_id()),
        1 | 5 => Resource::CpuTicks,
        2 | 6 => Resource::Frames,
        3 | 7 => Resource::Processes,
        4 | 8 => Resource::Threads,
        _ => return Err(Error::InvalidField),
    };
    if field <= 4 {
        Ok(scheduler.usage(job, resource)?)
    } else {
        Ok(limits.limit(resource))
    }
}

#[cfg(test)]
mod tests;
