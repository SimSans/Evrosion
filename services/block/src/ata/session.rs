//! Sustained-profile request ownership over the same bounded ATA engine.
//! A recovered error certifies only reset/idle quiescence, never write rollback.
use super::{AtaPio, Error, Failure, Ports, Progress};
use ev_userspace_contract::block::{Request, Response};

const CLEANUP_TICKS: u64 = 1024;

pub trait SessionWindow {
    fn snapshot(&self) -> [u8; 512];
    fn publish(&self, bytes: &[u8; 512]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quarantine {
    pub operation: Failure,
    pub cleanup: Failure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Complete(Response),
    /// This request issued no command and touched no shared window. The
    /// initialized owner was idle before acceptance was refused.
    Refused(Failure),
    /// The original operation failed. Device reset, re-identification and idle
    /// completed; no operation was replayed and uncertain data stays uncertain.
    Recovered(Failure),
    /// Do not acknowledge this request or reuse its window. The owner must be
    /// fenced/retired or terminate its session through the trusted controller.
    Quarantined(Quarantine),
}

pub struct SessionDisk<P, const PROFILE: u8 = 0> {
    disk: AtaPio<P, PROFILE>,
    quarantine: Option<Quarantine>,
}

impl<P: Ports, const PROFILE: u8> SessionDisk<P, PROFILE> {
    /// Consumes the actual driver owner; the caller initializes its device
    /// identity before serving. This creates no port permission or buffer lease.
    #[allow(clippy::result_large_err)] // Refusal returns the unique physical driver owner.
    pub fn new(disk: AtaPio<P, PROFILE>) -> Result<Self, AtaPio<P, PROFILE>> {
        if !matches!(disk.state, super::State::Ready(_)) {
            return Err(disk);
        }
        Ok(Self {
            disk,
            quarantine: None,
        })
    }

    pub fn command<W: SessionWindow>(
        &mut self,
        request: Request,
        window: &W,
        deadline: u64,
    ) -> SessionOutcome {
        if let Some(quarantine) = self.quarantine {
            return SessionOutcome::Quarantined(quarantine);
        }
        let admission = self.disk.io.now().map_err(Error::Io).and_then(|now| {
            if deadline == 0 || deadline == u64::MAX || now >= deadline {
                Err(Error::Deadline)
            } else {
                Ok(())
            }
        });
        if let Err(error) = admission {
            return SessionOutcome::Refused(Failure {
                error,
                progress: Progress::NotIssued,
            });
        }
        match self.disk.info() {
            Ok(info) if request.in_bounds(info.sectors) => {}
            Ok(_) => {
                return SessionOutcome::Refused(Failure {
                    error: Error::Bounds,
                    progress: Progress::NotIssued,
                });
            }
            Err(failure) => return SessionOutcome::Refused(failure),
        }
        let mut read = [0; 512];
        let result = match request {
            Request::Read { sector } => self.disk.read_sector(sector, &mut read, deadline),
            Request::Write { sector } => {
                let private = window.snapshot();
                self.disk.write_sector(sector, &private, deadline)
            }
            Request::Flush => self.disk.flush(deadline),
        }
        .and_then(|()| {
            self.disk.idle(deadline).map_err(|mut failure| {
                // The command preceding this idle check already executed. Do not
                // turn its uncertain durability into a NotIssued claim.
                failure.progress = Progress::MayHaveExecuted;
                failure
            })
        });
        if let Err(operation) = result {
            // A single cleanup cut derived from the ORIGINAL request. Refused
            // cleanup/late observation never restarts or extends this budget.
            let cleanup = deadline
                .checked_add(CLEANUP_TICKS)
                .filter(|cut| *cut != u64::MAX)
                .ok_or(Failure {
                    error: Error::Deadline,
                    progress: Progress::NotIssued,
                })
                .and_then(|cut| {
                    self.disk.reset(cut)?;
                    self.disk.identify(cut)?;
                    self.disk.idle(cut)
                });
            return match cleanup {
                Ok(()) => SessionOutcome::Recovered(operation),
                Err(cleanup) => {
                    let quarantine = Quarantine { operation, cleanup };
                    self.quarantine = Some(quarantine);
                    SessionOutcome::Quarantined(quarantine)
                }
            };
        }
        if matches!(request, Request::Read { .. }) {
            window.publish(&read);
        }
        SessionOutcome::Complete(request.success())
    }

    #[cfg(test)]
    pub(super) fn into_inner(self) -> AtaPio<P, PROFILE> {
        self.disk
    }
}
