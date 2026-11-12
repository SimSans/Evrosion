//! Fixed-channel desktop control data. Epochs and request numbers correlate
//! messages; the kernel-owned endpoint and live process checks supply authority.
use crate::shell_policy::Command;
use ev_graphics::shell::FileChoice;
use ev_input::KeyEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    Counter,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootControl {
    AppStarted(u32),
    AppStopped(u32),
    PickFile(u32),
    FileDelivered(u32),
    FileRefused(u32),
    InputRestarted(u32),
    AppRestored(u32),
    CrashShell,
    LaunchRefused,
    OwnerFilePending(u32),
    OwnerFileDelivered(u32),
    OwnerFileRefused(u32),
    ManagedFilePending(u32),
    ManagedFileDelivered(u32),
    ManagedFileRefused(u32),
    OwnerActionPending(u32),
    OwnerActionDone(u32),
}
impl RootControl {
    pub fn encode(self) -> Result<[u8; 8], Error> {
        let (op, word) = match self {
            Self::AppStarted(n) => (1, n),
            Self::AppStopped(n) => (2, n),
            Self::PickFile(n) => (3, n),
            Self::FileDelivered(n) => (4, n),
            Self::FileRefused(n) => (5, n),
            Self::InputRestarted(n) => (6, n),
            Self::AppRestored(n) => (7, n),
            Self::CrashShell => (8, 0),
            Self::LaunchRefused => (9, 0),
            Self::OwnerFilePending(n) => (10, n),
            Self::OwnerFileDelivered(n) => (11, n),
            Self::OwnerFileRefused(n) => (12, n),
            Self::ManagedFilePending(n) => (13, n),
            Self::ManagedFileDelivered(n) => (14, n),
            Self::ManagedFileRefused(n) => (15, n),
            Self::OwnerActionPending(n) => (16, n),
            Self::OwnerActionDone(n) => (17, n),
        };
        if op <= 7 || op >= 10 {
            counter(word)?;
        }
        Ok(frame(b'R', op, 0, word))
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[0] != b'R' || b[2] != 0 || b[3] != 0 {
            return Err(Error::Format);
        }
        let word = word(b);
        let message = match b[1] {
            1 => Self::AppStarted(word),
            2 => Self::AppStopped(word),
            3 => Self::PickFile(word),
            4 => Self::FileDelivered(word),
            5 => Self::FileRefused(word),
            6 => Self::InputRestarted(word),
            7 => Self::AppRestored(word),
            8 if word == 0 => Self::CrashShell,
            9 if word == 0 => Self::LaunchRefused,
            10 => Self::OwnerFilePending(word),
            11 => Self::OwnerFileDelivered(word),
            12 => Self::OwnerFileRefused(word),
            13 => Self::ManagedFilePending(word),
            14 => Self::ManagedFileDelivered(word),
            15 => Self::ManagedFileRefused(word),
            16 => Self::OwnerActionPending(word),
            17 => Self::OwnerActionDone(word),
            _ => return Err(Error::Format),
        };
        message.encode()?;
        Ok(message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellCommand {
    Launch,
    Forward(KeyEvent),
    Select { request: u32, file: FileChoice },
    Cancel(u32),
    Repaint,
    PickerReady(u32),
    ControlSettled(RootControl),
}
impl ShellCommand {
    pub fn from_policy(command: Command) -> Self {
        match command {
            Command::Launch => Self::Launch,
            Command::Forward(key) => Self::Forward(key),
            // Root must match this request against its retained live requester.
            // The reducer's epoch is never serialized as bearer authority.
            Command::Select { request, file, .. } => Self::Select { request, file },
            Command::Cancel { request } => Self::Cancel(request),
        }
    }
    pub fn encode(self) -> Result<[u8; 8], Error> {
        Ok(match self {
            Self::Launch => frame(b'S', 1, 0, 0),
            Self::Forward(event) => event.encode().map_err(|_| Error::Format)?,
            Self::Select { request, file } => {
                counter(request)?;
                frame(
                    b'S',
                    2,
                    if file == FileChoice::Notes { 1 } else { 2 },
                    request,
                )
            }
            Self::Cancel(request) => {
                counter(request)?;
                frame(b'S', 3, 0, request)
            }
            Self::Repaint => frame(b'S', 4, 0, 0),
            Self::PickerReady(n) => {
                counter(n)?;
                frame(b'S', 5, 0, n)
            }
            Self::ControlSettled(control) => {
                if control == RootControl::CrashShell {
                    return Err(Error::Format);
                }
                let encoded = control.encode()?;
                frame(b'S', 6, encoded[1], word(encoded))
            }
        })
    }
    pub fn decode(b: [u8; 8]) -> Result<Self, Error> {
        if b[0] == b'K' {
            return KeyEvent::decode(b)
                .map(Self::Forward)
                .map_err(|_| Error::Format);
        }
        if b[0] != b'S' || b[3] != 0 {
            return Err(Error::Format);
        }
        let word = word(b);
        let command = match (b[1], b[2], word) {
            (1, 0, 0) => Self::Launch,
            (2, 1, n) => Self::Select {
                request: n,
                file: FileChoice::Notes,
            },
            (2, 2, n) => Self::Select {
                request: n,
                file: FileChoice::Private,
            },
            (3, 0, n) => Self::Cancel(n),
            (4, 0, 0) => Self::Repaint,
            (5, 0, n) => Self::PickerReady(n),
            (6, op, n) => Self::ControlSettled(RootControl::decode(frame(b'R', op, 0, n))?),
            _ => return Err(Error::Format),
        };
        command.encode()?;
        Ok(command)
    }
}

/// Shell-only visibility control. Changing visibility never reads App RAM.
/// A newly shown App must provide another actual protected Present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowControl {
    pub visible: bool,
    pub sequence: u32,
}
impl WindowControl {
    pub fn request(self) -> Result<[u8; 8], Error> {
        self.encode(1)
    }
    pub fn reply(self) -> Result<[u8; 8], Error> {
        self.encode(2)
    }
    fn encode(self, op: u8) -> Result<[u8; 8], Error> {
        counter(self.sequence)?;
        Ok(frame(b'W', op, u8::from(self.visible), self.sequence))
    }
    pub fn parse_request(b: [u8; 8]) -> Result<Self, Error> {
        Self::parse(b, 1)
    }
    pub fn parse_reply(b: [u8; 8]) -> Result<Self, Error> {
        Self::parse(b, 2)
    }
    fn parse(b: [u8; 8], op: u8) -> Result<Self, Error> {
        if b[0] != b'W' || b[1] != op || b[2] > 1 || b[3] != 0 {
            return Err(Error::Format);
        }
        let control = Self {
            visible: b[2] == 1,
            sequence: word(b),
        };
        control.encode(op)?;
        Ok(control)
    }
}
fn counter(n: u32) -> Result<(), Error> {
    if n == 0 || n == u32::MAX {
        Err(Error::Counter)
    } else {
        Ok(())
    }
}
fn frame(tag: u8, op: u8, selector: u8, word: u32) -> [u8; 8] {
    let mut b = [tag, op, selector, 0, 0, 0, 0, 0];
    b[4..].copy_from_slice(&word.to_le_bytes());
    b
}
fn word(b: [u8; 8]) -> u32 {
    u32::from_le_bytes(b[4..].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_messages_never_accept_reserved_fields_unknown_op_or_wrapping_ids() {
        for message in [
            RootControl::AppStarted(1),
            RootControl::AppStopped(3),
            RootControl::PickFile(4),
            RootControl::FileDelivered(4),
            RootControl::FileRefused(4),
            RootControl::InputRestarted(1),
        ] {
            let bytes = message.encode().unwrap();
            assert_eq!(RootControl::decode(bytes), Ok(message));
            for index in [0, 2, 3] {
                let mut bad = bytes;
                bad[index] ^= 0x80;
                assert!(RootControl::decode(bad).is_err());
            }
        }
        for n in [0, u32::MAX] {
            assert!(RootControl::AppStarted(n).encode().is_err());
            assert!(RootControl::decode(frame(b'R', 3, 0, n)).is_err());
        }
        assert!(RootControl::decode(frame(b'R', 6, 0, 0)).is_err());
        assert!(RootControl::decode(frame(b'R', 8, 0, 1)).is_err());
        assert_eq!(
            RootControl::decode(frame(b'R', 9, 0, 0)),
            Ok(RootControl::LaunchRefused)
        );
        assert!(RootControl::decode(frame(b'R', 9, 0, 1)).is_err());
        assert!(RootControl::decode(frame(b'R', 10, 0, 0)).is_err());
    }
    #[test]
    fn selection_cannot_encode_writes_or_an_unspecified_object() {
        for file in [FileChoice::Notes, FileChoice::Private] {
            let c = ShellCommand::Select { request: 7, file };
            assert_eq!(ShellCommand::decode(c.encode().unwrap()), Ok(c));
        }
        for file in [0, 3, 255] {
            assert!(ShellCommand::decode(frame(b'S', 2, file, 7)).is_err());
        }
        for n in [0, u32::MAX] {
            assert!(ShellCommand::Cancel(n).encode().is_err());
        }
        assert!(ShellCommand::decode(frame(b'S', 1, 0, 7)).is_err());
    }
    #[test]
    fn window_ack_is_distinct_from_request_and_carries_exact_revision() {
        let w = WindowControl {
            visible: true,
            sequence: 7,
        };
        assert_eq!(WindowControl::parse_request(w.request().unwrap()), Ok(w));
        assert_eq!(WindowControl::parse_reply(w.reply().unwrap()), Ok(w));
        assert!(WindowControl::parse_reply(w.request().unwrap()).is_err());
        assert!(WindowControl::parse_request(frame(b'W', 1, 2, 7)).is_err());
        assert!(
            WindowControl {
                sequence: u32::MAX,
                ..w
            }
            .reply()
            .is_err()
        );
    }
    #[test]
    fn lifecycle_settlement_binds_exact_control_kind_and_incarnation() {
        for control in [
            RootControl::AppStopped(3),
            RootControl::AppRestored(5),
            RootControl::InputRestarted(7),
        ] {
            let command = ShellCommand::ControlSettled(control);
            assert_eq!(ShellCommand::decode(command.encode().unwrap()), Ok(command));
        }
        let old = ShellCommand::ControlSettled(RootControl::AppStopped(3))
            .encode()
            .unwrap();
        assert_ne!(
            ShellCommand::decode(old),
            Ok(ShellCommand::ControlSettled(RootControl::AppStopped(4)))
        );
        assert!(
            ShellCommand::ControlSettled(RootControl::CrashShell)
                .encode()
                .is_err()
        );
        assert!(ShellCommand::decode(frame(b'S', 6, 6, 0)).is_err());
    }
}
