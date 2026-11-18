//! Closed immutable metadata profiles. Declarations do not grant capabilities;
//! actual compatibility still uses the loaded Root's supported contracts.
#![forbid(unsafe_code)]
use ev_zion::{AppDescriptor, Capability};
/// Read-only inspection of the two known metadata formats. This never
/// describes a running Root's support; guest admission uses native_plan::Contracts.
pub struct KnownContracts;
impl ev_zion::Contracts for KnownContracts {
    fn supported(&self, name: &str, major: u16) -> Option<ev_zion::ContractSupport> {
        (major == 1
            && matches!(
                name,
                "ev.app.document"
                    | "ev.app.private-data"
                    | "ev.app.session-note"
                    | "ev.internal.file"
                    | "ev.internal.focused-input"
                    | "ev.internal.surface-present"
                    | "ev.test.document"
                    | "ev.ui.document"
            ))
        .then_some(ev_zion::ContractSupport {
            minor: u16::from(name == "ev.internal.focused-input"),
            features: 0,
        })
    }
}
pub fn downloaded(a: &AppDescriptor<'_>) -> bool {
    let document = a.version.minor == 3;
    if a.version.major != 0
        || !matches!(a.version.minor, 2 | 3)
        || !matches!(a.version.patch, 1 | 2)
    {
        return false;
    }
    let names: &[&str] = if document {
        &[
            "ev.app.document",
            "ev.app.private-data",
            "ev.app.session-note",
            "ev.internal.file",
            "ev.internal.focused-input",
            "ev.internal.surface-present",
            "ev.test.document",
            "ev.ui.document",
        ]
    } else {
        &[
            "ev.app.private-data",
            "ev.app.session-note",
            "ev.internal.file",
            "ev.internal.focused-input",
            "ev.internal.surface-present",
        ]
    };
    let caps: &[Capability] = if document {
        &[
            Capability::SelectedFileRead,
            Capability::AppPrivateData,
            Capability::OwnSurfacePresent,
            Capability::FocusedInput,
            Capability::Diagnostics,
            Capability::SelectedFileEdit,
        ]
    } else {
        &[
            Capability::SelectedFileRead,
            Capability::AppPrivateData,
            Capability::OwnSurfacePresent,
            Capability::FocusedInput,
            Capability::Diagnostics,
        ]
    };
    a.contracts().count() == names.len()
        && a.contracts().zip(names).all(|(c, n)| {
            c.name == *n
                && c.major == 1
                && c.minimum_minor == u16::from(document && *n == "ev.internal.focused-input")
                && c.features == 0
        })
        && a.capability_requests().count() == caps.len()
        && a.capability_requests()
            .zip(caps)
            .enumerate()
            .all(|(i, (c, k))| {
                c.capability == *k && c.required == (i != 0 && (!document || i != 5))
            })
}
