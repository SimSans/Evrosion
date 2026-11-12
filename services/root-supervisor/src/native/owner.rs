//! Complete bounded owner command lines. Parsing is neither authority nor IO;
//! no prefix, partial line, invalid byte or end-of-input approves an action.
#![forbid(unsafe_code)]
pub const MAX_LINE: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
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
        ("system", Some("init")) => Ok(Command::SystemInitialize),
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
