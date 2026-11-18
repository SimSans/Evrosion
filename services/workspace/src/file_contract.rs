//! Distinct read-only File@2 support reply on the existing Root-only route.
//! Parsing and token correlation supply no actual caller, loaded service,
//! binding, SEND capability or edit authority. Native delivery authenticates
//! the dedicated receiver and captured Root session before calling `loaded`.
use super::{Command, Error, FRAME_BYTES, Request, Status, finite, put, word};
use ev_userspace_contract::file_v2::{self as file, Support};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRequirement {
    pub minimum_minor: u16,
    pub features: u64,
}
impl FileRequirement {
    pub const fn supported_by(self, support: Support) -> bool {
        support.supports(file::VERSION, self.minimum_minor, self.features)
    }
}
/// Distinct successful versioned Bind reply. An old generic Applied response
/// cannot qualify; the actual Kernel44 SEND handoff remains Root's obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindContractResponse {
    pub request_id: u64,
    pub lease_epoch: u64,
    pub status: Status,
    pub support: Option<Support>,
}
impl BindContractResponse {
    pub fn loaded(request: Request, status: Status) -> Result<Self, Error> {
        let Command::BindContract { bind, requirement } = request.command else {
            return Err(Error::Correlation);
        };
        request.encode()?;
        if status == Status::Applied && !requirement.supported_by(file::SUPPORT) {
            return Err(Error::Scope);
        }
        Ok(Self {
            request_id: request.request_id,
            lease_epoch: bind.lease_epoch,
            status,
            support: (status == Status::Applied).then_some(file::SUPPORT),
        })
    }
    pub fn encode(self) -> Result<[u8; FRAME_BYTES], Error> {
        let mut bytes = FileContractResponse {
            request_id: self.request_id,
            token: self.lease_epoch,
            status: self.status,
            support: self.support,
        }
        .encode()?;
        bytes[..8].copy_from_slice(b"EVWFBA01");
        if self.status == Status::Applied {
            bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FRAME_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVWFBA01" {
            return Err(Error::Magic);
        }
        let mut probe: [u8; FRAME_BYTES] = bytes.try_into().unwrap();
        probe[..8].copy_from_slice(b"EVWFCA01");
        probe[56..58].fill(0);
        let p = FileContractResponse::decode(&probe)?;
        let value = Self {
            request_id: p.request_id,
            lease_epoch: p.token,
            status: p.status,
            support: p.support,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
    pub fn matches(self, request: Request) -> Result<Self, Error> {
        self.encode()?;
        request.encode()?;
        let Command::BindContract { bind, requirement } = request.command else {
            return Err(Error::Correlation);
        };
        if self.request_id != request.request_id
            || self.lease_epoch != bind.lease_epoch
            || self.support.is_some_and(|s| !requirement.supported_by(s))
        {
            return Err(Error::Correlation);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileContractResponse {
    pub request_id: u64,
    pub token: u64,
    pub status: Status,
    pub support: Option<Support>,
}
impl FileContractResponse {
    /// This implementation's loaded handler supports bounded staged Verify.
    /// Native adapter calls only after actual role16/ServingOrigin checks.
    /// Sealed/error replies have no support payload and never unseal anything.
    pub fn loaded(request: Request, status: Status) -> Result<Self, Error> {
        let Command::FileContract { token } = request.command else {
            return Err(Error::Correlation);
        };
        request.encode()?;
        Ok(Self {
            request_id: request.request_id,
            token,
            status,
            support: (status == Status::Applied).then_some(file::SUPPORT),
        })
    }
    pub fn encode(self) -> Result<[u8; FRAME_BYTES], Error> {
        if !finite(self.request_id)
            || !finite(self.token)
            || (self.status == Status::Applied) != self.support.is_some()
        {
            return Err(Error::Identity);
        }
        let mut bytes = [0; FRAME_BYTES];
        bytes[..8].copy_from_slice(b"EVWFCA01");
        bytes[8] = self.status as u8;
        put(&mut bytes, 16, self.request_id);
        put(&mut bytes, 32, self.token);
        if let Some(support) = self.support {
            if support.major != file::VERSION {
                return Err(Error::Scope);
            }
            bytes[40..42].copy_from_slice(&support.major.to_le_bytes());
            bytes[42..44].copy_from_slice(&support.minor.to_le_bytes());
            put(&mut bytes, 48, support.features);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FRAME_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVWFCA01" {
            return Err(Error::Magic);
        }
        let status = match bytes[8] {
            0 => Status::Applied,
            1 => Status::Denied,
            2 => Status::Stale,
            3 => Status::Busy,
            4 => Status::Malformed,
            5 => Status::Storage,
            6 => Status::Scope,
            7 => Status::Uncertain,
            8 => Status::Unavailable,
            9 => Status::Deadline,
            _ => return Err(Error::Opcode),
        };
        let value = Self {
            request_id: word(bytes, 16),
            token: word(bytes, 32),
            status,
            support: (status == Status::Applied).then(|| Support {
                major: u16::from_le_bytes(bytes[40..42].try_into().unwrap()),
                minor: u16::from_le_bytes(bytes[42..44].try_into().unwrap()),
                features: word(bytes, 48),
            }),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
    pub fn matches(self, request: Request) -> Result<Self, Error> {
        self.encode()?;
        let Command::FileContract { token } = request.command else {
            return Err(Error::Correlation);
        };
        request.encode()?;
        if self.request_id != request.request_id || self.token != token {
            return Err(Error::Correlation);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::workspace::Deadline;

    fn request() -> Request {
        Request {
            request_id: 0x0102_0304_0506_0708,
            deadline: Deadline::new(100).unwrap(),
            command: Command::FileContract { token: 29 },
        }
    }
    #[test]
    fn exact_probe_is_distinct_canonical_and_has_no_binding_or_io_fields() {
        let r = request();
        let bytes = r.encode().unwrap();
        assert_eq!(bytes[8], 8);
        assert_eq!(Request::decode(&bytes), Ok(r));
        assert_eq!(r.lease_epoch(), 29);
        for at in (9..16).chain(40..FRAME_BYTES) {
            let mut bad = bytes;
            bad[at] = 1;
            assert_eq!(Request::decode(&bad), Err(Error::Reserved));
        }
        let reply = FileContractResponse::loaded(r, Status::Applied).unwrap();
        assert_eq!(reply.support, Some(file::SUPPORT));
        let wire = reply.encode().unwrap();
        assert_eq!(
            FileContractResponse::decode(&wire).unwrap().matches(r),
            Ok(reply)
        );
        assert!(super::super::Response::decode(&wire).is_err());
        assert!(super::super::LegacyResponse::decode(&wire).is_err());
        for at in (9..16).chain(24..32).chain(44..48).chain(56..FRAME_BYTES) {
            let mut bad = wire;
            bad[at] = 1;
            assert_eq!(FileContractResponse::decode(&bad), Err(Error::Reserved));
        }
        for length in 0..FRAME_BYTES {
            assert_eq!(
                FileContractResponse::decode(&wire[..length]),
                Err(Error::Length)
            );
        }
    }
    #[test]
    fn token_request_kind_status_and_support_are_exactly_correlated() {
        let r = request();
        let reply = FileContractResponse::loaded(r, Status::Applied).unwrap();
        assert!(
            FileContractResponse {
                request_id: 3,
                ..reply
            }
            .matches(r)
            .is_err()
        );
        assert!(
            FileContractResponse { token: 30, ..reply }
                .matches(r)
                .is_err()
        );
        let other = Request {
            command: Command::Quiesce { token: 29 },
            ..r
        };
        assert!(reply.matches(other).is_err());
        assert!(FileContractResponse::loaded(other, Status::Applied).is_err());
        assert!(
            FileContractResponse {
                support: None,
                ..reply
            }
            .encode()
            .is_err()
        );
        assert!(
            FileContractResponse {
                support: None,
                ..reply
            }
            .matches(r)
            .is_err()
        );
        assert!(
            FileContractResponse {
                status: Status::Denied,
                ..reply
            }
            .encode()
            .is_err()
        );
        for status in [
            Status::Denied,
            Status::Stale,
            Status::Busy,
            Status::Malformed,
            Status::Storage,
            Status::Scope,
            Status::Uncertain,
            Status::Unavailable,
            Status::Deadline,
        ] {
            let no = FileContractResponse::loaded(r, status).unwrap();
            assert!(no.support.is_none());
            assert_eq!(
                FileContractResponse::decode(&no.encode().unwrap())
                    .unwrap()
                    .matches(r),
                Ok(no)
            );
            let mut bad = no.encode().unwrap();
            bad[48] = 1;
            assert_eq!(FileContractResponse::decode(&bad), Err(Error::Reserved));
        }
        let old = FileContractResponse {
            support: Some(Support {
                major: 2,
                minor: 0,
                features: 0,
            }),
            ..reply
        };
        assert_eq!(
            FileContractResponse::decode(&old.encode().unwrap()),
            Ok(old)
        );
        assert!(
            !old.support
                .unwrap()
                .supports(2, 1, file::FEATURE_STAGED_VERIFY)
        );
        assert!(old.support.unwrap().supports(2, 0, 0));
        let foreign = FileContractResponse {
            support: Some(Support {
                major: 1,
                minor: 1,
                features: 1,
            }),
            ..reply
        };
        assert!(foreign.encode().is_err());
    }
    #[test]
    fn versioned_bind_requires_distinct_reply_and_exact_requirements_before_selection2() {
        let bind = super::super::Bind {
            slot: 1,
            dataset: [8; 16],
            object: ev_userspace_contract::workspace::ObjectId {
                slot: 1,
                generation: 1,
            },
            target_process: 2,
            target_thread: 3,
            target_registered_token: 4,
            lease_epoch: 5,
            rights: crate::Rights::ReadWrite,
        };
        let required = FileRequirement {
            minimum_minor: 1,
            features: file::FEATURE_STAGED_VERIFY,
        };
        let r = Request {
            command: Command::BindContract {
                bind,
                requirement: required,
            },
            ..request()
        };
        let frame = r.encode().unwrap();
        assert_eq!(frame[8], 9);
        assert_eq!(Request::decode(&frame), Ok(r));
        for at in (108..112).chain(122..FRAME_BYTES) {
            let mut bad = frame;
            bad[at] = 1;
            assert!(Request::decode(&bad).is_err());
        }
        for at in [104, 120] {
            let mut bad = frame;
            bad[at] = 3;
            assert!(Request::decode(&bad).is_err());
        }
        let reply = BindContractResponse::loaded(r, Status::Applied).unwrap();
        let bytes = reply.encode().unwrap();
        assert_eq!(
            BindContractResponse::decode(&bytes).unwrap().matches(r),
            Ok(reply)
        );
        assert!(FileContractResponse::decode(&bytes).is_err());
        assert!(super::super::Response::decode(&bytes).is_err());
        assert!(
            reply
                .matches(Request {
                    command: Command::Bind(bind),
                    ..r
                })
                .is_err()
        );
        assert!(
            BindContractResponse {
                support: Some(Support {
                    major: 2,
                    minor: 0,
                    features: 0
                }),
                ..reply
            }
            .matches(r)
            .is_err()
        );
        for status in [Status::Denied, Status::Unavailable, Status::Uncertain] {
            let no = BindContractResponse::loaded(r, status).unwrap();
            assert!(no.support.is_none());
            assert_eq!(
                BindContractResponse::decode(&no.encode().unwrap())
                    .unwrap()
                    .matches(r),
                Ok(no)
            );
        }
        let unsupported = Request {
            command: Command::BindContract {
                bind,
                requirement: FileRequirement {
                    minimum_minor: 1,
                    features: 2,
                },
            },
            ..r
        };
        assert!(BindContractResponse::loaded(unsupported, Status::Applied).is_err());
        assert!(BindContractResponse::loaded(unsupported, Status::Unavailable).is_ok());
    }
}
