//! An explicit source-built V4 boot mode. Selecting a fixture never edits a
//! catalogue after measurement and never implies System admission or health.
use ev_userspace_contract::root_v4::catalogue::BootMode;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Standalone,
    SystemManaged,
    Recovery,
}
impl Mode {
    pub(crate) const fn fixture(self) -> &'static str {
        match self {
            Self::Standalone => "m6-network",
            Self::SystemManaged => "m6-network-system",
            Self::Recovery => "m6-network-recovery",
        }
    }
    pub(crate) const ALL: [Self; 3] = [Self::Standalone, Self::SystemManaged, Self::Recovery];
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Standalone => 0,
            Self::SystemManaged => 1,
            Self::Recovery => 2,
        }
    }
    pub(crate) const fn document_fixture(self) -> &'static str {
        match self {
            Self::Standalone => "m7-document-network",
            Self::SystemManaged => "m7-document-system",
            Self::Recovery => "m7-document-recovery",
        }
    }
    pub(crate) fn from_document_fixture(fixture: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.document_fixture() == fixture)
    }
    pub(crate) const fn owner_fixture(self) -> &'static str {
        match self {
            Self::Standalone => "m6-network-owner",
            Self::SystemManaged => "m6-network-system-owner",
            Self::Recovery => "m6-network-recovery-owner",
        }
    }
    pub(crate) fn from_owner_fixture(fixture: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.owner_fixture() == fixture)
    }
    pub(crate) fn from_fixture(fixture: &str) -> Option<Self> {
        [Self::Standalone, Self::SystemManaged, Self::Recovery]
            .into_iter()
            .find(|mode| mode.fixture() == fixture)
    }
    pub(crate) const fn boot_mode(self) -> BootMode {
        match self {
            Self::Standalone => BootMode::Standalone,
            Self::SystemManaged => BootMode::SystemManaged,
            Self::Recovery => BootMode::Recovery,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_declared_fixture_selects_only_its_exact_measured_mode() {
        for (mode, wire) in [
            (Mode::Standalone, BootMode::Standalone),
            (Mode::SystemManaged, BootMode::SystemManaged),
            (Mode::Recovery, BootMode::Recovery),
        ] {
            assert_eq!(Mode::from_fixture(mode.fixture()), Some(mode));
            assert_eq!(mode.boot_mode(), wire);
            assert_eq!(Mode::from_owner_fixture(mode.owner_fixture()), Some(mode));
            assert_eq!(Mode::from_owner_fixture(mode.fixture()), None);
            assert_eq!(Mode::from_fixture(mode.owner_fixture()), None);
        }
        for unknown in [
            "m5-native-system",
            "m6-network-system-extra",
            "m6-network-recovery ",
            "",
            "m6-network-SYSTEM",
        ] {
            assert_eq!(Mode::from_fixture(unknown), None);
        }
    }
}
