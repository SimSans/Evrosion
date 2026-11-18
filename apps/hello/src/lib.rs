//! Native Hello identity-independent view helpers; no storage authority here.
#![no_std]
#![forbid(unsafe_code)]
pub mod document;
pub mod document_control;
#[cfg(feature = "native-session")]
pub mod editor;
/// Stable identity shared by the source package producer and this App's note
/// client. It never identifies or selects another App's namespace on the wire.
pub const APP_ID: [u8; 16] = [
    0x62, 0xc0, 0x76, 0x7e, 0x6c, 0x18, 0x45, 0x9c, 0x91, 0xe6, 0xeb, 0x8b, 0x94, 0x89, 0x58, 0xf2,
];
use ev_userspace_contract::file::{ErrorCode, Payload, Response};
pub const INITIAL_VALUE: u32 = 1001;
pub const UPDATED_VALUE: u32 = 2026;
#[derive(Debug, PartialEq, Eq)]
pub enum StartupError {
    Bootstrap(ev_userspace_contract::Error),
    Limits,
    Roles,
}
pub fn startup(bytes: &[u8]) -> Result<ev_userspace_contract::Bootstrap<'_>, StartupError> {
    use ev_userspace_contract::root_v2::{
        catalogue::CHILD_LIMITS,
        graph::{self, Child},
    };
    let bootstrap =
        ev_userspace_contract::Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    for (index, limit) in CHILD_LIMITS.into_iter().enumerate() {
        if bytes[40 + index * 8..48 + index * 8] != limit.to_le_bytes() {
            return Err(StartupError::Limits);
        }
    }
    let expected = graph::grants(Child::App);
    let count = bootstrap.grants().count();
    let dedicated = cfg!(feature = "native-session") && count == 7;
    if count != expected.len() && !dedicated {
        return Err(StartupError::Roles);
    }
    let mut handles = [0; 7];
    for (index, actual) in bootstrap.grants().enumerate() {
        let (kind, rights) = expected
            .get(index)
            .map(|role| (role.kind, role.rights))
            .unwrap_or((1, 7));
        if actual.selector != (index + 1) as u64
            || actual.kind != kind
            || actual.rights != rights
            || handles[..index].contains(&actual.handle)
        {
            return Err(StartupError::Roles);
        }
        handles[index] = actual.handle;
    }
    Ok(bootstrap)
}

pub fn allowed_saved_value(value: u32) -> bool {
    matches!(value, INITIAL_VALUE | UPDATED_VALUE)
}
pub fn read_only_refused(response: Response) -> bool {
    matches!(
        response,
        Response::Error {
            code: ErrorCode::Denied
        }
    )
}
pub fn unchanged_file(before: &(u64, Payload), after: &(u64, Payload)) -> bool {
    before == after
}
#[cfg(feature = "native-a")]
pub fn build() -> ev_graphics::native::Build {
    ev_graphics::native::Build::A
}
#[cfg(all(feature = "native-b", not(feature = "native-a")))]
pub fn build() -> ev_graphics::native::Build {
    ev_graphics::native::Build::B
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_six_roles_require_exact_limits_and_no_ambient_private_data_handle() {
        use ev_userspace_contract::{
            Context, Grant, encode,
            root_v2::{
                catalogue::CHILD_LIMITS,
                graph::{self, Child},
            },
        };
        let expected = graph::grants(Child::App);
        let grants: [Grant; 6] = core::array::from_fn(|i| Grant {
            selector: (i + 1) as u64,
            handle: 512 + i as u64,
            kind: expected[i].kind,
            rights: expected[i].rights,
        });
        let context = Context {
            epoch: 1,
            incarnation: 1,
            process: 7,
            limits: CHILD_LIMITS,
            manifest: [1; 32],
            authority: [2; 32],
        };
        assert!(startup(&encode(context, &grants).unwrap()).is_ok());
        assert!(startup(&encode(context, &grants[..5]).unwrap()).is_err());
        for i in 0..6 {
            let mut wrong = grants;
            wrong[i].rights ^= 256;
            if let Ok(bytes) = encode(context, &wrong) {
                assert!(startup(&bytes).is_err());
            }
        }
        let mut wrong = context;
        wrong.limits[0] = 2048;
        assert!(startup(&encode(wrong, &grants).unwrap()).is_err());
    }
    #[test]
    fn rollback_a_must_read_updated_private_value_and_only_real_ro_denial_passes() {
        assert!(allowed_saved_value(1001));
        assert!(allowed_saved_value(2026));
        assert!(!allowed_saved_value(0));
        assert!(read_only_refused(Response::Error {
            code: ErrorCode::Denied
        }));
        for code in [
            ErrorCode::Malformed,
            ErrorCode::Io,
            ErrorCode::NeedsRecovery,
        ] {
            assert!(!read_only_refused(Response::Error { code }));
        }
        assert!(!read_only_refused(Response::Replaced {
            counter: 1,
            replayed: false
        }));
        let before = (0, Payload::new(b"Notes").unwrap());
        assert!(unchanged_file(&before, &before));
        assert!(!unchanged_file(&before, &(1, before.1)));
        assert!(!unchanged_file(
            &before,
            &(0, Payload::new(b"Private").unwrap())
        ));
    }
}
