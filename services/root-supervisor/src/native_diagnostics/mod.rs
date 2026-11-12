//! Actual capability-authorized Native diagnostics collector. Collection uses actual
//! scalar syscalls and retained CONTROL caps; IDs and formatted text confer no authority.
#![forbid(unsafe_code)]
pub use ev_diagnostics::{framing, live};
pub mod presentation;
pub mod system;
use ev_diagnostics::{
    Capture, Crash, Provenance,
    inspector::{Job, Usage},
};
use ev_userspace_runtime::{Reply, syscall};

pub trait Boundary {
    fn call(&mut self, number: u64, capability: u64, field: u64) -> Reply;
}
pub struct Syscalls;
impl Boundary for Syscalls {
    fn call(&mut self, number: u64, capability: u64, field: u64) -> Reply {
        ev_userspace_runtime::call(number, capability, field, 0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobAuthority {
    Current,
    Delegated(u64),
}
impl JobAuthority {
    fn handle(self) -> Result<u64, Error> {
        match self {
            Self::Current => Ok(0),
            Self::Delegated(0) => Err(Error::Authority),
            Self::Delegated(handle) => Ok(handle),
        }
    }
}
pub use ev_diagnostics::live::Identity;
/// Construct only from the Root's retained Actor controls and actual admitted
/// ProcessIdentity response. Integers in this struct do not bypass Kernel checks.
pub struct StoppedTarget {
    pub process_control: u64,
    pub job_control: u64,
    pub identity: Identity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    Identity,
    Clock,
    Rejected {
        number: u64,
        field: u64,
        status: u64,
    },
    Abi {
        number: u64,
        field: u64,
        reply: Reply,
    },
    Crash(ev_diagnostics::Error),
}
pub struct Captured {
    pub crash: Crash,
    pub job: Job,
    pub first_tick: u64,
    pub last_tick: u64,
}
pub struct Collector<B> {
    boundary: B,
}
impl<B: Boundary> Collector<B> {
    pub fn new(boundary: B) -> Self {
        Self { boundary }
    }
    pub fn into_boundary(self) -> B {
        self.boundary
    }
    fn query(&mut self, number: u64, handle: u64, field: u64) -> Result<u64, Error> {
        let reply = self.boundary.call(number, handle, field);
        if reply.capability != 0 || (reply.status != 0 && reply.value != 0) {
            return Err(Error::Abi {
                number,
                field,
                reply,
            });
        }
        if reply.status != 0 {
            return Err(Error::Rejected {
                number,
                field,
                status: reply.status,
            });
        }
        Ok(reply.value)
    }
    fn now(&mut self) -> Result<u64, Error> {
        self.query(syscall::MONOTONIC, 0, 0)
    }
    #[inline(never)]
    pub fn job(&mut self, authority: JobAuthority) -> Result<Job, Error> {
        let handle = authority.handle()?;
        let first_tick = self.now()?;
        let mut values = [0u64; 9];
        for (field, value) in values.iter_mut().enumerate() {
            *value = self.query(syscall::JOB_INFO, handle, field as u64)?;
        }
        if values[0] == 0 || self.query(syscall::JOB_INFO, handle, 0)? != values[0] {
            return Err(Error::Identity);
        }
        let last_tick = self.now()?;
        if last_tick < first_tick {
            return Err(Error::Clock);
        }
        Ok(Job {
            diagnostic_id: values[0],
            first_tick,
            last_tick,
            subtree: Usage {
                cpu_ticks: values[1],
                frames: values[2],
                processes: values[3],
                threads: values[4],
            },
            limits: Usage {
                cpu_ticks: values[5],
                frames: values[6],
                processes: values[7],
                threads: values[8],
            },
        })
    }
    /// Run while the actual stopped process/image/context remains retained,
    /// before REAP or CLOSE. No retry, user pointer or raw-ID lookup is issued.
    /// Canonical no-fault2 on field0 is a normal STOP/Exit, never a fabricated Crash.
    #[inline(never)]
    pub fn fault(
        &mut self,
        target: &StoppedTarget,
        provenance: Provenance,
    ) -> Result<Option<Captured>, Error> {
        if target.process_control == 0
            || target.job_control == 0
            || target.identity.process == 0
            || target.identity.thread == 0
        {
            return Err(Error::Authority);
        }
        let first_tick = self.now()?;
        let first = self
            .boundary
            .call(syscall::FAULT_INFO, target.process_control, 0);
        if first.status == 2 && first.value == 0 && first.capability == 0 {
            return Ok(None);
        }
        if first.status != 0 && first.value == 0 && first.capability == 0 {
            return Err(Error::Rejected {
                number: syscall::FAULT_INFO,
                field: 0,
                status: first.status,
            });
        }
        if first.status != 0 || first.capability != 0 || first.value == 0 {
            return Err(Error::Abi {
                number: syscall::FAULT_INFO,
                field: 0,
                reply: first,
            });
        }
        let mut words = [0u64; 24];
        words[0] = first.value;
        for (field, value) in words.iter_mut().enumerate().skip(1) {
            *value = self.query(syscall::FAULT_INFO, target.process_control, field as u64)?;
        }
        if (words[1], words[2]) != (target.identity.process, target.identity.thread) {
            return Err(Error::Identity);
        }
        let job = self.job(JobAuthority::Delegated(target.job_control))?;
        if job.diagnostic_id != words[0] {
            return Err(Error::Identity);
        }
        for (field, expected) in words.iter().enumerate().take(3) {
            if self.query(syscall::FAULT_INFO, target.process_control, field as u64)? != *expected {
                return Err(Error::Identity);
            }
        }
        let last_tick = self.now()?;
        if last_tick < first_tick {
            return Err(Error::Clock);
        }
        let capture = Capture {
            job: words[0],
            process: words[1],
            thread: words[2],
            vector: words[3],
            error: words[4],
            address: words[5],
            instruction: words[6],
            stack: words[7],
            flags: words[8],
            registers: words[9..].try_into().unwrap(),
        };
        let crash = Crash::new(provenance, capture).map_err(Error::Crash)?;
        Ok(Some(Captured {
            crash,
            job,
            first_tick,
            last_tick,
        }))
    }
}
/// Uses the already checked immutable source package. No generation identity is
/// inferred from Native registry state, volume layout, Ready or this constructor.
pub fn application_provenance(
    package: &ev_zion::Package<'_>,
    epoch: u64,
    incarnation: u64,
) -> Provenance {
    Provenance {
        component: ev_diagnostics::Component::Application(package.app().claimed_app),
        image: package.executable().digest,
        package: Some(package.id().bytes()),
        component_build: package.app().build_id,
        generation: None,
        epoch,
        incarnation,
    }
}
/// Source-defined service role and measured cohort-input identity. `build` is
/// the catalogue's build-input identity, not the final linked Kernel build ID.
pub fn service_provenance(
    child: ev_userspace_contract::root_v2::graph::Child,
    image: [u8; 32],
    build: [u8; 32],
    epoch: u64,
    incarnation: u64,
) -> Result<Provenance, Error> {
    use ev_userspace_contract::root_v2::graph::Child;
    if child == Child::App {
        return Err(Error::Identity);
    }
    Ok(Provenance {
        component: ev_diagnostics::Component::Service(child.image().selector() as u16),
        image,
        package: None,
        component_build: build,
        generation: None,
        epoch,
        incarnation,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Idle,
    Busy,
    Accepted,
    Finished,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    Authority,
    Reply(ev_userspace_runtime::Reply),
    Framing(framing::Error),
}
/// One actual ordinary SEND attempt. Only canonical success advances; Full2
/// retains exact bytes. The Root event loop supplies future fair retries.
pub fn tick(
    outbox: &mut framing::Outbox,
    boundary: &mut impl Boundary,
    events: u64,
) -> Result<Progress, SendError> {
    if events == 0 {
        return Err(SendError::Authority);
    }
    let Some(frame) = outbox.current().map_err(SendError::Framing)? else {
        return Ok(Progress::Idle);
    };
    let reply = boundary.call(
        ev_userspace_runtime::syscall::SEND,
        events,
        u64::from_le_bytes(frame),
    );
    if reply.value != 0 || reply.capability != 0 {
        return Err(SendError::Reply(reply));
    }
    match reply.status {
        0 => Ok(if outbox.accepted().map_err(SendError::Framing)? {
            Progress::Finished
        } else {
            Progress::Accepted
        }),
        2 => Ok(Progress::Busy),
        _ => Err(SendError::Reply(reply)),
    }
}

#[cfg(test)]
mod tests;
