//! Bounded textual presentation of explicitly collected actual Job data.
//! Formatting cannot collect authority, discover Jobs, infer health or grant access.
use core::fmt::{self, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub cpu_ticks: u64,
    pub frames: u64,
    pub processes: u64,
    pub threads: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub diagnostic_id: u64,
    /// Bounds the separate authoritative reads; this is not an atomic snapshot.
    pub first_tick: u64,
    pub last_tick: u64,
    /// Hierarchical accounting includes this Job's descendants.
    pub subtree: Usage,
    pub limits: Usage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Clock,
    Capacity,
    Duplicate,
}
pub const MAX_JOBS: usize = 16;
pub struct Jobs {
    rows: [Option<Job>; MAX_JOBS],
    count: usize,
}
impl Default for Jobs {
    fn default() -> Self {
        Self::new()
    }
}
impl Jobs {
    pub const fn new() -> Self {
        Self {
            rows: [None; MAX_JOBS],
            count: 0,
        }
    }
    /// Trusted collector must query with actual Job capability; these scalar
    /// diagnostics are not accepted by kernel operations as authority.
    pub fn push(&mut self, job: Job) -> Result<(), Error> {
        if job.diagnostic_id == 0 {
            return Err(Error::Identity);
        }
        if job.first_tick > job.last_tick {
            return Err(Error::Clock);
        }
        if self.rows[..self.count]
            .iter()
            .flatten()
            .any(|row| row.diagnostic_id == job.diagnostic_id)
        {
            return Err(Error::Duplicate);
        }
        if self.count == MAX_JOBS {
            return Err(Error::Capacity);
        }
        self.rows[self.count] = Some(job);
        self.count += 1;
        Ok(())
    }
    pub fn rows(&self) -> impl Iterator<Item = &Job> {
        self.rows[..self.count].iter().flatten()
    }
    pub fn write(&self, out: &mut impl Write) -> fmt::Result {
        writeln!(
            out,
            "Evrosion Jobs: subtree usage; CPU ticks and 4 KiB RAM frames. Rows are observed over the stated tick interval."
        )?;
        for row in self.rows() {
            writeln!(
                out,
                "Job {} | observed ticks {}..{} | CPU {}/{} ticks | RAM {}/{} frames ({} KiB) | processes {}/{} | threads {}/{}",
                row.diagnostic_id,
                row.first_tick,
                row.last_tick,
                row.subtree.cpu_ticks,
                row.limits.cpu_ticks,
                row.subtree.frames,
                row.limits.frames,
                u128::from(row.subtree.frames) * 4,
                row.subtree.processes,
                row.limits.processes,
                row.subtree.threads,
                row.limits.threads
            )?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn row(id: u64) -> Job {
        Job {
            diagnostic_id: id,
            first_tick: 10,
            last_tick: 12,
            subtree: Usage {
                cpu_ticks: 13,
                frames: 7,
                processes: 2,
                threads: 3,
            },
            limits: Usage {
                cpu_ticks: 500,
                frames: 32,
                processes: 4,
                threads: 8,
            },
        }
    }
    #[test]
    fn bad_or_duplicate_observations_cannot_replace_a_prior_row() {
        let mut jobs = Jobs::new();
        jobs.push(row(17)).unwrap();
        assert_eq!(jobs.push(row(17)), Err(Error::Duplicate));
        assert_eq!(jobs.push(row(0)), Err(Error::Identity));
        let mut clock = row(18);
        clock.first_tick = 13;
        assert_eq!(jobs.push(clock), Err(Error::Clock));
        assert_eq!(
            jobs.rows().copied().collect::<std::vec::Vec<_>>(),
            [row(17)]
        );
        for id in 18..33 {
            jobs.push(row(id)).unwrap();
        }
        assert_eq!(jobs.push(row(33)), Err(Error::Capacity));
        assert_eq!(jobs.rows().count(), 16);
    }
    #[test]
    fn textual_units_hierarchy_and_read_interval_are_explicit_and_overflow_safe() {
        let mut jobs = Jobs::new();
        let mut r = row(0x10001);
        r.subtree.frames = u64::MAX;
        jobs.push(r).unwrap();
        let mut text = std::string::String::new();
        jobs.write(&mut text).unwrap();
        assert!(text.contains("subtree usage"));
        assert!(text.contains("observed ticks 10..12"));
        assert!(text.contains("CPU 13/500 ticks"));
        assert!(text.contains("73786976294838206460 KiB"));
        assert!(text.contains("processes 2/4 | threads 3/8"));
        struct Refuses;
        impl fmt::Write for Refuses {
            fn write_str(&mut self, _: &str) -> fmt::Result {
                Err(fmt::Error)
            }
        }
        assert_eq!(jobs.write(&mut Refuses), Err(fmt::Error));
    }
}
