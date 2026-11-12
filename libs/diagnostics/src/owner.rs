//! Canonical trusted-owner prompt metadata. Encoding grants no consent or
//! authority. One authenticated complete Root report is printed synchronously;
//! only its actual completed output permits the Source to drain/arm its gate.
use crate::live::hex;
use core::fmt::{self, Write};
pub const BYTES: usize = 416;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    RememberRead = 1,
    RevokeRead = 2,
    RecoverGood = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Display,
    Armed,
    Confirmed,
    Cancelled,
    Refused,
    Expired,
    Completed,
    Recovery,
}
impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Display => "display",
            Self::Armed => "armed",
            Self::Confirmed => "confirmed",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Completed => "completed",
            Self::Recovery => "recovery",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub action: Action,
    pub phase: Phase,
    pub prompt_serial: u64,
    pub open_nonce: u64,
    pub owner: [u8; 16],
    pub app: [u8; 16],
    pub package: [u8; 32],
    pub process: u64,
    pub thread: u64,
    pub volume: [u8; 16],
    pub object: u64,
    pub object_counter: u64,
    pub object_digest: [u8; 32],
    pub permission_revision: u64,
    pub grant_serial: u64,
    pub policy_revision: u64,
    pub head_digest: [u8; 32],
    pub action_digest: [u8; 32],
    pub token: [u8; 64],
    pub current_admitted_gen: u64,
    pub selected_next_gen: u64,
    pub known_good: u64,
    pub last_failed_gen: u64,
    pub response_budget_ticks: u64,
    pub current_package: [u8; 32],
    pub app_epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Wire,
    Reserved,
    Identity,
    Action,
    Token,
}
fn put(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
impl Prompt {
    fn validate(&self) -> Result<(), Error> {
        if self.prompt_serial == 0
            || self.owner == [0; 16]
            || self.head_digest == [0; 32]
            || self.action_digest == [0; 32]
            || self.response_budget_ticks == 0
        {
            return Err(Error::Identity);
        }
        if !self
            .token
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(Error::Token);
        }
        if (self.process == 0) != (self.thread == 0) {
            return Err(Error::Identity);
        }
        if (self.process == 0) != (self.current_package == [0; 32])
            || (self.process == 0) != (self.app_epoch == 0)
        {
            return Err(Error::Identity);
        }
        if self.action == Action::RememberRead && self.current_package != self.package {
            return Err(Error::Identity);
        }
        match self.action {
            Action::RememberRead | Action::RevokeRead => {
                if self.app == [0; 16]
                    || self.package == [0; 32]
                    || self.volume == [0; 16]
                    || self.object == 0
                    || self.object_digest == [0; 32]
                    || self.permission_revision == 0
                {
                    return Err(Error::Action);
                }
                if self.action == Action::RememberRead
                    && (self.open_nonce == 0 || self.process == 0)
                {
                    return Err(Error::Action);
                }
                if self.action == Action::RevokeRead
                    && (self.grant_serial == 0 || self.policy_revision == 0)
                {
                    return Err(Error::Action);
                }
            }
            Action::RecoverGood => {
                if self.app != [0; 16]
                    || self.package != [0; 32]
                    || self.process != 0
                    || self.thread != 0
                    || self.volume != [0; 16]
                    || self.object != 0
                    || self.object_counter != 0
                    || self.object_digest != [0; 32]
                    || self.permission_revision != 0
                    || self.open_nonce != 0
                    || self.grant_serial != 0
                    || self.policy_revision != 0
                    || self.known_good == 0
                {
                    return Err(Error::Action);
                }
            }
        }
        Ok(())
    }
    pub fn encode(self) -> Result<[u8; BYTES], Error> {
        self.validate()?;
        let mut b = [0; BYTES];
        b[..8].copy_from_slice(b"EVOWNR01");
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(&(BYTES as u16).to_le_bytes());
        b[12] = self.action as u8;
        b[13] = self.phase as u8;
        b[32..48].copy_from_slice(&self.owner);
        b[48..64].copy_from_slice(&self.app);
        b[64..96].copy_from_slice(&self.package);
        b[112..128].copy_from_slice(&self.volume);
        b[144..176].copy_from_slice(&self.object_digest);
        b[200..232].copy_from_slice(&self.head_digest);
        b[232..264].copy_from_slice(&self.action_digest);
        b[264..328].copy_from_slice(&self.token);
        for (at, value) in [
            (16, self.prompt_serial),
            (24, self.open_nonce),
            (96, self.process),
            (104, self.thread),
            (128, self.object),
            (136, self.object_counter),
            (176, self.permission_revision),
            (184, self.grant_serial),
            (192, self.policy_revision),
            (328, self.current_admitted_gen),
            (336, self.selected_next_gen),
            (344, self.known_good),
            (352, self.last_failed_gen),
            (360, self.response_budget_ticks),
        ] {
            put(&mut b, at, value);
        }
        b[368..400].copy_from_slice(&self.current_package);
        put(&mut b, 400, self.app_epoch);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BYTES
            || &b[..8] != b"EVOWNR01"
            || b[8..10] != 1u16.to_le_bytes()
            || b[10..12] != (BYTES as u16).to_le_bytes()
        {
            return Err(Error::Wire);
        }
        if b[14..16] != [0; 2] || b[408..].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        let action = match b[12] {
            1 => Action::RememberRead,
            2 => Action::RevokeRead,
            3 => Action::RecoverGood,
            _ => return Err(Error::Action),
        };
        let phase = match b[13] {
            0 => Phase::Display,
            1 => Phase::Armed,
            2 => Phase::Confirmed,
            3 => Phase::Cancelled,
            4 => Phase::Refused,
            5 => Phase::Expired,
            6 => Phase::Completed,
            7 => Phase::Recovery,
            _ => return Err(Error::Action),
        };
        let p = Self {
            action,
            phase,
            prompt_serial: word(b, 16),
            open_nonce: word(b, 24),
            owner: b[32..48].try_into().unwrap(),
            app: b[48..64].try_into().unwrap(),
            package: b[64..96].try_into().unwrap(),
            process: word(b, 96),
            thread: word(b, 104),
            volume: b[112..128].try_into().unwrap(),
            object: word(b, 128),
            object_counter: word(b, 136),
            object_digest: b[144..176].try_into().unwrap(),
            permission_revision: word(b, 176),
            grant_serial: word(b, 184),
            policy_revision: word(b, 192),
            head_digest: b[200..232].try_into().unwrap(),
            action_digest: b[232..264].try_into().unwrap(),
            token: b[264..328].try_into().unwrap(),
            current_admitted_gen: word(b, 328),
            selected_next_gen: word(b, 336),
            known_good: word(b, 344),
            last_failed_gen: word(b, 352),
            response_budget_ticks: word(b, 360),
            current_package: b[368..400].try_into().unwrap(),
            app_epoch: word(b, 400),
        };
        p.validate()?;
        Ok(p)
    }
    /// Called only by the actual authenticated complete-report UART callback.
    /// Every phase has canonical human output. Display binds the complete
    /// action; Armed is printed only after the Source's fresh gate is armed.
    pub fn write(&self, out: &mut impl Write) -> fmt::Result {
        if self.phase != Phase::Display {
            return match self.phase {
                Phase::Armed => {
                    writeln!(
                        out,
                        "Owner action {} is ARMED. Enter the exact confirmation line now:",
                        self.prompt_serial
                    )?;
                    write!(out, "approve ")?;
                    out.write_str(core::str::from_utf8(&self.token).map_err(|_| fmt::Error)?)?;
                    writeln!(out)?;
                    writeln!(
                        out,
                        "The confirmation window is {} ticks from arming.",
                        self.response_budget_ticks
                    )
                }
                Phase::Confirmed => writeln!(
                    out,
                    "Owner action {}: confirmation accepted; applying the displayed action.",
                    self.prompt_serial
                ),
                Phase::Completed => match self.action {
                    Action::RememberRead => writeln!(
                        out,
                        "Owner action {} completed: remembered READ policy verified and fresh access enqueued.",
                        self.prompt_serial
                    ),
                    Action::RevokeRead => writeln!(
                        out,
                        "Owner action {} completed: READ access revoked and saved policy disabled.",
                        self.prompt_serial
                    ),
                    Action::RecoverGood => writeln!(
                        out,
                        "Owner action {} completed: protected Good {} selected for the next boot.",
                        self.prompt_serial, self.known_good
                    ),
                },
                Phase::Recovery => writeln!(
                    out,
                    "Owner action {} requires recovery. Storage may have changed; inspect or recover before retrying.",
                    self.prompt_serial
                ),
                Phase::Refused => writeln!(
                    out,
                    "Owner action {}: completion refused; inspect current state before trying again.",
                    self.prompt_serial
                ),
                Phase::Cancelled => writeln!(
                    out,
                    "Owner action {} cancelled before confirmation; request a new prompt to try again.",
                    self.prompt_serial
                ),
                Phase::Expired => writeln!(
                    out,
                    "Owner action {}: confirmation expired; request a new prompt to try again.",
                    self.prompt_serial
                ),
                Phase::Display => unreachable!(),
            };
        }
        writeln!(
            out,
            "Evrosion owner action {:?}; explicit approval required.",
            self.action
        )?;
        write!(out, "Owner ")?;
        hex(out, &self.owner)?;
        if self.action == Action::RecoverGood {
            writeln!(
                out,
                "; select protected Good {} for next boot; selected={} failed={} current-admitted={} (0 unknown).",
                self.known_good,
                self.selected_next_gen,
                self.last_failed_gen,
                self.current_admitted_gen
            )?;
        } else {
            write!(out, "; AppId ")?;
            hex(out, &self.app)?;
            write!(out, "; package ")?;
            hex(out, &self.package)?;
            writeln!(
                out,
                "; current process/thread {}/{}; Open nonce {}.",
                self.process, self.thread, self.open_nonce
            )?;
            write!(out, "Current package ")?;
            hex(out, &self.current_package)?;
            writeln!(out, "; app epoch {}.", self.app_epoch)?;
            write!(out, "File volume ")?;
            hex(out, &self.volume)?;
            write!(
                out,
                " object {} revision {} SHA256 ",
                self.object, self.object_counter
            )?;
            hex(out, &self.object_digest)?;
            writeln!(
                out,
                "; permission revision {}; READ only; until explicitly revoked; grant serial {} latest policy revision {}.",
                self.permission_revision, self.grant_serial, self.policy_revision
            )?;
        }
        write!(out, "Exact action ")?;
        hex(out, &self.action_digest)?;
        writeln!(
            out,
            ". Wait for ARMED; then enter the complete line within {} ticks:",
            self.response_budget_ticks
        )?;
        write!(out, "approve ")?;
        out.write_str(core::str::from_utf8(&self.token).map_err(|_| fmt::Error)?)?;
        writeln!(out)
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;
    fn remember() -> Prompt {
        Prompt {
            action: Action::RememberRead,
            phase: Phase::Display,
            prompt_serial: 1,
            open_nonce: 2,
            owner: [1; 16],
            app: [2; 16],
            package: [3; 32],
            process: 4,
            thread: 5,
            volume: [6; 16],
            object: 1,
            object_counter: 0,
            object_digest: [7; 32],
            permission_revision: 1,
            grant_serial: 1,
            policy_revision: 0,
            head_digest: [8; 32],
            action_digest: [9; 32],
            token: [b'a'; 64],
            current_admitted_gen: 1,
            selected_next_gen: 2,
            known_good: 1,
            last_failed_gen: 0,
            response_budget_ticks: 4096,
            current_package: [3; 32],
            app_epoch: 1,
        }
    }
    #[test]
    fn prompt_preserves_subject_and_actual_current_package_without_conflating_them() {
        let p = remember();
        assert_eq!(Prompt::decode(&p.encode().unwrap()), Ok(p));
        let mut mismatched = p;
        mismatched.current_package = [0x45; 32];
        assert_eq!(mismatched.encode(), Err(Error::Identity));
        mismatched.action = Action::RevokeRead;
        mismatched.policy_revision = 1;
        let bytes = mismatched.encode().unwrap();
        assert_eq!(Prompt::decode(&bytes), Ok(mismatched));
        let mut text = String::new();
        mismatched.write(&mut text).unwrap();
        assert!(text.contains("current process/thread 4/5"));
        assert!(text.contains("Current package 45454545"));
        let mut reserved = bytes;
        reserved[408] = 1;
        assert_eq!(Prompt::decode(&reserved), Err(Error::Reserved));
    }
    #[test]
    fn uncertain_terminal_is_explicit_and_recovery_accepts_no_selected_generation() {
        let mut p = remember();
        p.phase = Phase::Recovery;
        assert_eq!(
            Prompt::decode(&p.encode().unwrap()).unwrap().phase,
            Phase::Recovery
        );
        assert_eq!(p.phase.name(), "recovery");
        p.action = Action::RecoverGood;
        p.phase = Phase::Display;
        p.open_nonce = 0;
        p.app = [0; 16];
        p.package = [0; 32];
        p.process = 0;
        p.thread = 0;
        p.volume = [0; 16];
        p.object = 0;
        p.object_digest = [0; 32];
        p.permission_revision = 0;
        p.grant_serial = 0;
        p.policy_revision = 0;
        p.current_package = [0; 32];
        p.app_epoch = 0;
        p.current_admitted_gen = 0;
        p.selected_next_gen = 0;
        assert_eq!(Prompt::decode(&p.encode().unwrap()), Ok(p));
        p.known_good = 0;
        assert_eq!(p.encode(), Err(Error::Action));
    }
    #[test]
    fn readable_status_distinguishes_enqueue_next_boot_and_uncertain_publication() {
        let mut p = remember();
        let original = p.encode().unwrap();
        for phase in [
            Phase::Display,
            Phase::Armed,
            Phase::Confirmed,
            Phase::Cancelled,
            Phase::Refused,
            Phase::Expired,
            Phase::Completed,
            Phase::Recovery,
        ] {
            p.phase = phase;
            let bytes = p.encode().unwrap();
            let mut text = String::new();
            p.write(&mut text).unwrap();
            assert!(!text.is_empty());
            assert!(text.ends_with('\n'));
            assert_eq!(p.encode().unwrap(), bytes);
            if phase == Phase::Armed {
                assert!(text.contains("is ARMED"));
                assert!(text.contains("approve aaaaaaaaaa"));
                assert!(text.contains("ticks from arming"));
            }
            if phase == Phase::Completed {
                assert!(text.contains("fresh access enqueued"));
                assert!(!text.contains("delivered"));
            }
            if phase == Phase::Recovery {
                assert!(text.contains("Storage may have changed"));
                assert!(!text.contains("completed"));
            }
        }
        p.phase = Phase::Display;
        assert_eq!(p.encode().unwrap(), original);
        p.phase = Phase::Completed;
        p.action = Action::RecoverGood;
        let mut text = String::new();
        p.write(&mut text).unwrap();
        assert!(text.contains("for the next boot"));
    }
}
