//! Interpret Root-paired selection metadata before constructing a native File
//! client. These descriptive facts do not prove sender/endpoint authority: the
//! caller still owns actual capability delivery, self identity and route checks.
use ev_userspace_contract::{file_v2 as file, workspace::Error as CodecError};
use ev_workspace_client::{
    native::SelfFacts,
    selection::{Access, Selection, SelectionV2},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Codec(CodecError),
    MissingStagedVerify,
    OldWorkspaceSelection,
    Receiver,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub selection: Selection,
    pub file: Option<file::Support>,
}
pub fn supports_staged_verify(support: Option<file::Support>) -> bool {
    support.is_some_and(|s| s.supports(file::VERSION, 1, file::FEATURE_STAGED_VERIFY))
}
impl Admitted {
    /// Compatibility/metadata comparison only. Actual writable authority is
    /// independently confined by the received capability and installed route.
    pub fn supports_staged_write(self) -> bool {
        self.selection.access == Access::ReadWrite && supports_staged_verify(self.file)
    }
}

pub fn decode(bytes: &[u8], nonce: u64, facts: SelfFacts) -> Result<Admitted, Error> {
    // Exact magic dispatch prevents malformed V2 from falling back to SEL1.
    let admitted = match bytes.get(..8) {
        Some(b"EVF2SEL2") => {
            let value = SelectionV2::decode(bytes).map_err(Error::Codec)?;
            if !supports_staged_verify(Some(value.file)) {
                return Err(Error::MissingStagedVerify);
            }
            Admitted {
                selection: value.selection,
                file: Some(value.file),
            }
        }
        Some(b"EVF2SEL1") => {
            let selection = Selection::decode(bytes).map_err(Error::Codec)?;
            if !selection.is_legacy_file1_readonly() {
                return Err(Error::OldWorkspaceSelection);
            }
            Admitted {
                selection,
                file: None,
            }
        }
        _ => return Err(Error::Codec(CodecError::Magic)),
    };
    if !admitted.selection.matches_receiver(
        nonce,
        facts.process,
        facts.thread,
        facts.registered_incarnation,
    ) {
        return Err(Error::Receiver);
    }
    Ok(admitted)
}
