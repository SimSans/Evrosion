//! Bounded textual inspector from explicitly collected rows, never raw-ID discovery.
use crate::{
    framing::JOB_BYTES,
    inspector::{Job, Usage},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub process: u64,
    pub thread: u64,
}
use core::fmt::{self, Write};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Boot,
    Root,
    Shell,
    Input,
    File,
    Block,
    Application,
    Display,
    NetDriver,
    NetService,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Boot => "Boot",
            Self::Root => "Root",
            Self::Shell => "Shell",
            Self::Input => "Input",
            Self::File => "File",
            Self::Block => "Block",
            Self::Application => "Application",
            Self::Display => "Display",
            Self::NetDriver => "NetDriver",
            Self::NetService => "NetService",
        }
    }
    fn code(self) -> u64 {
        self as u64
    }
    fn parse(value: u64) -> Option<Self> {
        Some(match value {
            0 => Self::Boot,
            1 => Self::Root,
            2 => Self::Shell,
            3 => Self::Input,
            4 => Self::File,
            5 => Self::Block,
            6 => Self::Application,
            7 => Self::Display,
            8 => Self::NetDriver,
            9 => Self::NetService,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Clock,
    Package,
    Wire,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub role: Role,
    pub identity: Identity,
    pub started: bool,
    pub image: [u8; 32],
    pub package: Option<[u8; 32]>,
    pub job: Job,
}
impl Row {
    pub fn new(
        role: Role,
        identity: Identity,
        started: bool,
        image: [u8; 32],
        package: Option<[u8; 32]>,
        job: Job,
    ) -> Result<Self, Error> {
        if job.diagnostic_id == 0 {
            return Err(Error::Identity);
        }
        if job.first_tick > job.last_tick {
            return Err(Error::Clock);
        }
        if package == Some([0; 32]) || matches!(role, Role::Application) != package.is_some() {
            return Err(Error::Package);
        }
        if role == Role::Boot {
            if identity
                != (Identity {
                    process: 0,
                    thread: 0,
                })
                || started
                || image != [0; 32]
            {
                return Err(Error::Identity);
            }
        } else {
            if image == [0; 32] {
                return Err(Error::Identity);
            }
            if started {
                if identity.process == 0 || (role != Role::Root && identity.thread == 0) {
                    return Err(Error::Identity);
                }
            } else if identity
                != (Identity {
                    process: 0,
                    thread: 0,
                })
            {
                return Err(Error::Identity);
            }
        }
        Ok(Self {
            role,
            identity,
            started,
            image,
            package,
            job,
        })
    }
    pub fn encode(self) -> [u8; JOB_BYTES] {
        let mut out = [0; JOB_BYTES];
        out[..8].copy_from_slice(b"EVJOB001");
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[10..12].copy_from_slice(&(JOB_BYTES as u16).to_le_bytes());
        out[12] = u8::from(self.package.is_some()) | (u8::from(self.started) << 1);
        for (offset, value) in [
            (16, self.role.code()),
            (24, self.identity.process),
            (32, self.identity.thread),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out[40..72].copy_from_slice(&self.image);
        if let Some(package) = self.package {
            out[72..104].copy_from_slice(&package);
        }
        for (index, value) in [
            self.job.diagnostic_id,
            self.job.first_tick,
            self.job.last_tick,
            self.job.subtree.cpu_ticks,
            self.job.subtree.frames,
            self.job.subtree.processes,
            self.job.subtree.threads,
            self.job.limits.cpu_ticks,
            self.job.limits.frames,
            self.job.limits.processes,
            self.job.limits.threads,
        ]
        .into_iter()
        .enumerate()
        {
            out[104 + index * 8..112 + index * 8].copy_from_slice(&value.to_le_bytes());
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOB_BYTES
            || &bytes[..8] != b"EVJOB001"
            || bytes[8..10] != 1u16.to_le_bytes()
            || bytes[10..12] != (JOB_BYTES as u16).to_le_bytes()
            || bytes[12] & !3 != 0
            || bytes[13..16] != [0; 3]
        {
            return Err(Error::Wire);
        }
        let word = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let package = if bytes[12] & 1 != 0 {
            Some(bytes[72..104].try_into().unwrap())
        } else {
            if bytes[72..104] != [0; 32] {
                return Err(Error::Wire);
            }
            None
        };
        Self::new(
            Role::parse(word(16)).ok_or(Error::Wire)?,
            Identity {
                process: word(24),
                thread: word(32),
            },
            bytes[12] & 2 != 0,
            bytes[40..72].try_into().unwrap(),
            package,
            Job {
                diagnostic_id: word(104),
                first_tick: word(112),
                last_tick: word(120),
                subtree: Usage {
                    cpu_ticks: word(128),
                    frames: word(136),
                    processes: word(144),
                    threads: word(152),
                },
                limits: Usage {
                    cpu_ticks: word(160),
                    frames: word(168),
                    processes: word(176),
                    threads: word(184),
                },
            },
        )
    }
    pub fn write(&self, out: &mut impl Write) -> fmt::Result {
        write!(
            out,
            "{} | Job {} | ",
            self.role.name(),
            self.job.diagnostic_id
        )?;
        if self.started {
            write!(out, "process {} | ", self.identity.process)?;
            if self.identity.thread == 0 {
                write!(out, "thread unknown | ")?;
            } else {
                write!(out, "thread {} | ", self.identity.thread)?;
            }
        } else if self.role == Role::Boot {
            write!(out, "container Job | ")?;
        } else {
            write!(out, "held, not started | ")?;
        }
        writeln!(
            out,
            "observed ticks {}..{} | subtree CPU {}/{} ticks | RAM {}/{} frames ({} KiB) | processes {}/{} | threads {}/{}",
            self.job.first_tick,
            self.job.last_tick,
            self.job.subtree.cpu_ticks,
            self.job.limits.cpu_ticks,
            self.job.subtree.frames,
            self.job.limits.frames,
            u128::from(self.job.subtree.frames) * 4,
            self.job.subtree.processes,
            self.job.limits.processes,
            self.job.subtree.threads,
            self.job.limits.threads
        )?;
        if self.role != Role::Boot {
            write!(out, "  measured executable SHA256 ")?;
            hex(out, &self.image)?;
            writeln!(out)?;
        }
        if let Some(package) = self.package {
            write!(out, "  package SHA256 ")?;
            hex(out, &package)?;
            writeln!(out)?;
        }
        Ok(())
    }
}
pub fn hex(out: &mut impl Write, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod role_tests {
    use super::*;
    fn job() -> Job {
        Job {
            diagnostic_id: 3,
            first_tick: 4,
            last_tick: 5,
            subtree: Usage {
                cpu_ticks: 1,
                frames: 2,
                processes: 1,
                threads: 1,
            },
            limits: Usage {
                cpu_ticks: 16384,
                frames: 64,
                processes: 1,
                threads: 1,
            },
        }
    }
    #[test]
    fn additive_network_roles_preserve_all_previous_codes_and_roundtrip_without_packages() {
        for (code, role) in [
            Role::Boot,
            Role::Root,
            Role::Shell,
            Role::Input,
            Role::File,
            Role::Block,
            Role::Application,
            Role::Display,
            Role::NetDriver,
            Role::NetService,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(role.code(), code as u64);
            assert_eq!(Role::parse(code as u64), Some(role));
        }
        for role in [Role::NetDriver, Role::NetService] {
            let row = Row::new(
                role,
                Identity {
                    process: 7,
                    thread: 8,
                },
                true,
                [1; 32],
                None,
                job(),
            )
            .unwrap();
            assert_eq!(Row::decode(&row.encode()), Ok(row));
            assert_eq!(
                Row::new(role, row.identity, true, row.image, Some([2; 32]), job()),
                Err(Error::Package)
            );
            let mut bytes = row.encode();
            bytes[16..24].copy_from_slice(&10u64.to_le_bytes());
            assert_eq!(Row::decode(&bytes), Err(Error::Wire));
        }
    }
}
