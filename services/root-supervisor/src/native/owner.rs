//! Complete bounded owner command lines. Parsing is neither authority nor IO;
//! no prefix, partial line, invalid byte or end-of-input approves an action.
#![forbid(unsafe_code)]
pub const MAX_LINE: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    #[cfg(feature = "native-network-negative")]
    NetDestination,
    #[cfg(feature = "native-network-negative")]
    NetEndurance,
    #[cfg(feature = "native-network-negative")]
    NetEnduranceStop,
    #[cfg(feature = "native-network-negative")]
    NetPending,
    #[cfg(feature = "native-network-negative")]
    NetDriverStop,
    #[cfg(feature = "native-network-negative")]
    NetServiceStop,
    InstallA,
    StageB,
    Activate,
    Rollback,
    Remove,
    ReinstallA,
    Inspect,
    Cancel,
    Finish,
    CrashShell,
    #[cfg(feature = "document-workflow")]
    CrashApp,
    #[cfg(feature = "native-network")]
    TimeProbe,
    #[cfg(feature = "native-network")]
    TimeCheck,
    #[cfg(feature = "native-network")]
    UpdateInitialize,
    #[cfg(feature = "native-network")]
    UpdateInspect,
    #[cfg(feature = "native-network")]
    UpdateFetch,
    SystemInitialize,
    SystemStage,
    SystemActivate,
    RecoverGood,
    Continue,
    InitializeGrants,
    RememberNotes,
    RememberPrivate,
    RevokeGrant,
}

#[cfg(all(test, feature = "native-network"))]
mod update_command_tests {
    use super::*;
    #[test]
    fn explicit_update_commands_require_complete_exact_owner_lines() {
        for (line, command) in [
            (b"update-init\n".as_slice(), Command::UpdateInitialize),
            (b"update-inspect\n".as_slice(), Command::UpdateInspect),
            (b"update-fetch\n".as_slice(), Command::UpdateFetch),
            (b"system init\n".as_slice(), Command::SystemInitialize),
            (b"system stage\n".as_slice(), Command::SystemStage),
            (b"system activate\n".as_slice(), Command::SystemActivate),
        ] {
            let mut lines = Lines::new();
            for &byte in &line[..line.len() - 1] {
                assert_eq!(lines.push(byte), Ok(None));
            }
            assert_eq!(lines.end_of_input(), Err(Error::Incomplete));
            for &byte in line {
                let result = lines.push(byte);
                if byte == b'\n' {
                    assert_eq!(result, Ok(Some(command)));
                } else {
                    assert_eq!(result, Ok(None));
                }
            }
        }
        for bad in [
            b"update-ini\n".as_slice(),
            b"update-init now\n",
            b"update-inspect format\n",
            b"update-inspect\0\n",
            b"update-fetch now\n",
            b"update-fetc\n",
        ] {
            let mut lines = Lines::new();
            for &byte in bad {
                let result = lines.push(byte);
                if byte == b'\n' {
                    assert!(result.is_err());
                }
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Invalid,
    Incomplete,
}
pub struct Lines {
    bytes: [u8; MAX_LINE],
    length: usize,
    invalid: bool,
}
impl Default for Lines {
    fn default() -> Self {
        Self::new()
    }
}
impl Lines {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_LINE],
            length: 0,
            invalid: false,
        }
    }
    pub fn push(&mut self, byte: u8) -> Result<Option<Command>, Error> {
        if byte == b'\r' || byte == b'\n' {
            let result = if self.invalid {
                Err(Error::Invalid)
            } else {
                parse(&self.bytes[..self.length]).map(Some)
            };
            self.length = 0;
            self.invalid = false;
            return result;
        }
        if !(byte == b'\t' || (b' '..=b'~').contains(&byte)) {
            self.invalid = true;
            return Ok(None);
        }
        if self.length == MAX_LINE {
            self.invalid = true;
            return Ok(None);
        }
        self.bytes[self.length] = byte;
        self.length += 1;
        Ok(None)
    }
    pub fn end_of_input(&mut self) -> Result<(), Error> {
        let incomplete = self.length != 0 || self.invalid;
        self.length = 0;
        self.invalid = false;
        if incomplete {
            Err(Error::Incomplete)
        } else {
            Ok(())
        }
    }
}
fn parse(bytes: &[u8]) -> Result<Command, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
    let mut words = text.split([' ', '\t']).filter(|w| !w.is_empty());
    let a = words.next().ok_or(Error::Invalid)?;
    let b = words.next();
    if words.next().is_some() {
        return Err(Error::Invalid);
    }
    match (a, b) {
        #[cfg(feature = "native-network-negative")]
        ("net-destination", None) => Ok(Command::NetDestination),
        #[cfg(feature = "native-network-negative")]
        ("net-endurance", None) => Ok(Command::NetEndurance),
        #[cfg(feature = "native-network-negative")]
        ("net-endurance-stop", None) => Ok(Command::NetEnduranceStop),
        #[cfg(feature = "native-network-negative")]
        ("net-pending", None) => Ok(Command::NetPending),
        #[cfg(feature = "native-network-negative")]
        ("net-driver-stop", None) => Ok(Command::NetDriverStop),
        #[cfg(feature = "native-network-negative")]
        ("net-service-stop", None) => Ok(Command::NetServiceStop),
        ("install", Some("a")) => Ok(Command::InstallA),
        ("stage", Some("b")) => Ok(Command::StageB),
        ("activate", None) => Ok(Command::Activate),
        ("rollback", None) => Ok(Command::Rollback),
        ("remove", None) => Ok(Command::Remove),
        ("reinstall", Some("a")) => Ok(Command::ReinstallA),
        ("inspect", None) => Ok(Command::Inspect),
        ("cancel", None) => Ok(Command::Cancel),
        ("finish", None) => Ok(Command::Finish),
        ("crash", Some("shell")) => Ok(Command::CrashShell),
        #[cfg(feature = "document-workflow")]
        ("crash", Some("app")) => Ok(Command::CrashApp),
        #[cfg(feature = "native-network")]
        ("time-probe", None) => Ok(Command::TimeProbe),
        #[cfg(feature = "native-network")]
        ("time-check", None) => Ok(Command::TimeCheck),
        #[cfg(feature = "native-network")]
        ("update-init", None) => Ok(Command::UpdateInitialize),
        #[cfg(feature = "native-network")]
        ("update-inspect", None) => Ok(Command::UpdateInspect),
        #[cfg(feature = "native-network")]
        ("update-fetch", None) => Ok(Command::UpdateFetch),
        ("system", Some("init")) => Ok(Command::SystemInitialize),
        #[cfg(feature = "native-network")]
        ("system", Some("stage")) => Ok(Command::SystemStage),
        ("system", Some("stage-bad")) => Ok(Command::SystemStage),
        ("system", Some("activate")) => Ok(Command::SystemActivate),
        ("recover", Some("good")) => Ok(Command::RecoverGood),
        ("continue", None) => Ok(Command::Continue),
        ("initialize", Some("grants")) => Ok(Command::InitializeGrants),
        ("remember", Some("notes")) => Ok(Command::RememberNotes),
        ("remember", Some("private")) => Ok(Command::RememberPrivate),
        ("revoke", Some("grant")) => Ok(Command::RevokeGrant),
        _ => Err(Error::Invalid),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_lines_only_and_no_eof_or_noise_approval() {
        let mut p = Lines::new();
        for &b in b"install a" {
            assert_eq!(p.push(b), Ok(None));
        }
        assert_eq!(p.end_of_input(), Err(Error::Incomplete));
        for &b in b" \tstage\t b\r" {
            let r = p.push(b);
            if b == b'\r' {
                assert_eq!(r, Ok(Some(Command::StageB)));
            } else {
                assert_eq!(r, Ok(None));
            }
        }
        for &b in b"\x1binstall a\n" {
            let r = p.push(b);
            if b == b'\n' {
                assert_eq!(r, Err(Error::Invalid));
            }
        }
    }
    #[cfg(feature = "native-network")]
    #[test]
    fn time_probe_requires_exact_complete_owner_line_and_never_prefix_or_argument() {
        let mut p = Lines::new();
        for &b in b"time-probe" {
            assert_eq!(p.push(b), Ok(None));
        }
        assert_eq!(p.end_of_input(), Err(Error::Incomplete));
        for bad in [
            b"time-prob\n".as_slice(),
            b"time-probe now\n",
            b"time-probe\0\n",
        ] {
            for &b in bad {
                let r = p.push(b);
                if b == b'\n' {
                    assert!(r.is_err());
                }
            }
        }
        for &b in b"time-probe\n" {
            let r = p.push(b);
            if b == b'\n' {
                assert_eq!(r, Ok(Some(Command::TimeProbe)));
            } else {
                assert_eq!(r, Ok(None));
            }
        }
    }
    #[test]
    fn overlong_and_extra_words_do_not_truncate_to_command() {
        let mut p = Lines::new();
        for _ in 0..MAX_LINE + 1 {
            assert_eq!(p.push(b'a'), Ok(None));
        }
        assert_eq!(p.push(b'\n'), Err(Error::Invalid));
        for &b in b"activate now\n" {
            let r = p.push(b);
            if b == b'\n' {
                assert_eq!(r, Err(Error::Invalid));
            }
        }
        assert_eq!(p.push(b'\n'), Err(Error::Invalid));
    }
}

#[cfg(all(test, feature = "native-network-negative"))]
mod negative_tests {
    extern crate std;
    use super::*;
    use std::borrow::ToOwned;
    #[test]
    fn captured_stop_commands_are_complete_exact_owner_lines() {
        for (name, expected) in [
            ("net-destination", Command::NetDestination),
            ("net-endurance", Command::NetEndurance),
            ("net-endurance-stop", Command::NetEnduranceStop),
            ("net-pending", Command::NetPending),
            ("net-driver-stop", Command::NetDriverStop),
            ("net-service-stop", Command::NetServiceStop),
        ] {
            for input in [
                name.to_owned() + " extra\n",
                name.to_owned() + "\0\n",
                name[..name.len() - 1].to_owned() + "\n",
            ] {
                let mut lines = Lines::new();
                for byte in input.bytes() {
                    if byte == b'\n' {
                        assert!(lines.push(byte).is_err());
                    } else {
                        let _ = lines.push(byte);
                    }
                }
            }
            let mut lines = Lines::new();
            for byte in name.bytes() {
                assert_eq!(lines.push(byte), Ok(None));
            }
            assert_eq!(lines.end_of_input(), Err(Error::Incomplete));
            let mut lines = Lines::new();
            for byte in name.bytes() {
                assert_eq!(lines.push(byte), Ok(None));
            }
            assert_eq!(lines.push(b'\n'), Ok(Some(expected)));
        }
    }
}
