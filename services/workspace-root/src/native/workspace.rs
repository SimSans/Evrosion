use super::*;
use ev_userspace_contract::workspace::{
    self as ns, DatasetId, Deadline, Operation, Outcome, Response,
};
use ev_workspace_root::requirements::{FileSupport, ServiceIdentity};
use ev_workspace_service::control;
const ADDRESS: usize = BASE + 503 * 4096;
struct Exchange {
    endpoint: u64,
    request: u64,
    cut: u64,
    frame: [u8; 256],
}
pub(super) struct Workspace {
    request: u64,
    operation: u64,
    pub dataset: Option<DatasetId>,
    fenced: bool,
    retained: Option<Exchange>,
    probe_attempted: bool,
    file: Option<FileSupport>,
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            request: 0,
            operation: 0,
            dataset: None,
            fenced: false,
            retained: None,
            probe_attempted: false,
            file: None,
        }
    }
    fn next(&mut self) -> Result<u64, ()> {
        if self.fenced || self.retained.is_some() {
            return Err(());
        }
        self.request = self
            .request
            .checked_add(1)
            .filter(|v| *v < u64::from(u32::MAX))
            .ok_or(())?;
        Ok(self.request)
    }
    fn exchange(
        &mut self,
        endpoint: u64,
        request: u64,
        cut: u64,
        bytes: [u8; 256],
    ) -> Result<[u8; 256], ()> {
        if self.fenced || self.retained.is_some() {
            return Err(());
        }
        self.retained = Some(Exchange {
            endpoint,
            request,
            cut,
            frame: bytes,
        });
        for (i, byte) in bytes
            .into_iter()
            .chain(core::iter::repeat_n(0, 3840))
            .enumerate()
        {
            // SAFETY: actual Root503..504 initialized RW window. One Root
            // transport serializes Namespace and Bind; no other local client.
            unsafe { ((ADDRESS + i) as *mut u8).write_volatile(byte) };
        }
        match rt::rpc::call(endpoint, request.to_le_bytes(), cut) {
            Ok(reply) if u64::from_le_bytes(reply) == request => {}
            _ => {
                self.fenced = true;
                return Err(());
            }
        }
        // The exact original request/cut remains stored across uncertainty.
        // A real reply does not permit replacing any retained correlation.
        if self.retained.as_ref().is_none_or(|held| {
            held.endpoint != endpoint
                || held.request != request
                || held.cut != cut
                || held.frame != bytes
        }) {
            self.fenced = true;
            return Err(());
        }
        Ok(core::array::from_fn(|i| {
            // SAFETY: exact correlated RPC returned real server access credit.
            unsafe { ((ADDRESS + i) as *const u8).read_volatile() }
        }))
    }
    pub fn namespace(&mut self, endpoint: u64, operation: Operation) -> Result<Response, ()> {
        self.namespace_until(
            endpoint,
            operation,
            deadline(v5::resources::FILE_TRANSACTION_TICKS),
        )
    }
    pub fn namespace_until(
        &mut self,
        endpoint: u64,
        operation: Operation,
        cut: u64,
    ) -> Result<Response, ()> {
        if now() >= cut {
            return Err(());
        }
        let request_id = self.next()?;
        let mutating = !matches!(
            operation,
            Operation::Inspect { .. } | Operation::List { .. }
        );
        if mutating {
            self.operation = self
                .operation
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .ok_or(())?;
        }
        let request = ns::Request {
            request_id,
            operation_id: if mutating { self.operation } else { 0 },
            deadline: Deadline::new(cut).map_err(|_| ())?,
            operation,
        };
        let bytes = self.exchange(
            endpoint,
            request_id,
            request.deadline.tick(),
            request.encode().map_err(|_| ())?,
        )?;
        let response = ns::client_decode(request, &bytes, 0).map_err(|_| {
            self.fenced = true;
        })?;
        if self.dataset.is_some_and(|old| old != response.dataset) {
            self.fenced = true;
            return Err(());
        }
        if matches!(response.outcome, Outcome::Completed | Outcome::End) {
            self.dataset = Some(response.dataset);
        }
        if matches!(
            response.outcome,
            Outcome::Accepted | Outcome::Uncertain | Outcome::Corrupt
        ) || (response.outcome == Outcome::Stale && request.operation_id != 0)
        {
            self.fenced = true;
        } else {
            self.retained = None;
        }
        Ok(response)
    }
    /// Same sole transport/counter/fence as Dataset traffic, with the distinct
    /// original-volume reply parser. Never changes this owner's Dataset ID.
    pub fn legacy_inspect_until(
        &mut self,
        endpoint: u64,
        object: ev_workspace_service::legacy::Object,
        lease_epoch: u64,
        cut: u64,
    ) -> Result<control::LegacyResponse, ()> {
        if now() >= cut {
            return Err(());
        }
        let request = control::Request {
            request_id: self.next()?,
            deadline: Deadline::new(cut).map_err(|_| ())?,
            command: control::Command::LegacyInspect {
                object,
                lease_epoch,
            },
        };
        let bytes = self.exchange(
            endpoint,
            request.request_id,
            cut,
            request.encode().map_err(|_| ())?,
        )?;
        let response = control::LegacyResponse::decode(&bytes)
            .and_then(|r| r.matches(request))
            .map_err(|_| {
                self.fenced = true;
            })?;
        if response.status == control::Status::Uncertain {
            self.fenced = true;
        } else {
            self.retained = None;
        }
        Ok(response)
    }
    pub fn control_until(
        &mut self,
        endpoint: u64,
        command: control::Command,
        cut: u64,
    ) -> Result<control::Response, ()> {
        if matches!(
            command,
            control::Command::LegacyInspect { .. }
                | control::Command::FileContract { .. }
                | control::Command::BindContract { .. }
        ) {
            return Err(());
        }
        if now() >= cut {
            return Err(());
        }
        let request = control::Request {
            request_id: self.next()?,
            deadline: Deadline::new(cut).map_err(|_| ())?,
            command,
        };
        let bytes = self.exchange(
            endpoint,
            request.request_id,
            request.deadline.tick(),
            request.encode().map_err(|_| ())?,
        )?;
        let response = control::Response::decode(&bytes)
            .and_then(|r| r.matches(request))
            .map_err(|_| {
                self.fenced = true;
            })?;
        if response.status == control::Status::Uncertain {
            self.fenced = true;
        } else {
            self.retained = None;
        }
        Ok(response)
    }
    pub fn file_support_for(
        &mut self,
        actual: ServiceIdentity,
    ) -> Result<ev_userspace_contract::file_v2::Support, ()> {
        if self.fenced || self.retained.is_some() || !service_live(actual) {
            self.fenced = true;
            return Err(());
        }
        self.file
            .as_ref()
            .ok_or(())?
            .for_service(actual)
            .map_err(|_| {
                self.fenced = true;
            })
    }
    pub fn probe_file_contract(
        &mut self,
        actual: ServiceIdentity,
        token: u64,
        cut: u64,
    ) -> Result<(), ()> {
        if self.probe_attempted || now() >= cut || !service_live(actual) {
            return Err(());
        }
        self.probe_attempted = true;
        let request = control::Request {
            request_id: self.next()?,
            deadline: Deadline::new(cut).map_err(|_| ())?,
            command: control::Command::FileContract { token },
        };
        let bytes = self.exchange(
            actual.endpoint,
            request.request_id,
            cut,
            request.encode().map_err(|_| ())?,
        )?;
        let response = control::FileContractResponse::decode(&bytes)
            .and_then(|reply| reply.matches(request))
            .map_err(|_| {
                self.fenced = true;
            })?;
        if response.status != control::Status::Applied || !service_live(actual) || now() >= cut {
            self.fenced = true;
            return Err(());
        }
        self.file = Some(
            FileSupport::observed(actual, response.support.ok_or(())?).map_err(|_| {
                self.fenced = true;
            })?,
        );
        self.retained = None;
        Ok(())
    }
    pub fn bind_contract_until(
        &mut self,
        service: ServiceIdentity,
        bind: control::Bind,
        requirement: control::FileRequirement,
        cut: u64,
    ) -> Result<control::Response, ()> {
        let support = self.file_support_for(service)?;
        if !requirement.supported_by(support) || now() >= cut {
            return Err(());
        }
        let request = control::Request {
            request_id: self.next()?,
            deadline: Deadline::new(cut).map_err(|_| ())?,
            command: control::Command::BindContract { bind, requirement },
        };
        let bytes = self.exchange(
            service.endpoint,
            request.request_id,
            cut,
            request.encode().map_err(|_| ())?,
        )?;
        let response = control::BindContractResponse::decode(&bytes)
            .and_then(|r| r.matches(request))
            .map_err(|_| {
                self.fenced = true;
            })?;
        if response.status == control::Status::Uncertain
            || !service_live(service)
            || response.status == control::Status::Applied && response.support != Some(support)
        {
            self.fenced = true;
            return Err(());
        }
        self.retained = None;
        Ok(control::Response {
            request_id: response.request_id,
            lease_epoch: response.lease_epoch,
            status: response.status,
        })
    }
}
fn service_live(service: ServiceIdentity) -> bool {
    if !service.valid() {
        return false;
    }
    let identity = rt::call4(s::PROCESS_IDENTITY, service.control, 0, 0, 0);
    let observed = rt::call4(s::OBSERVE, service.control, 0, 0, 0);
    identity.status == 0
        && identity.serial == 0
        && identity.value == service.identity.process
        && identity.capability == service.identity.thread
        && observed.status == 0
        && observed.value == 0
        && observed.capability == 0
        && observed.serial == 0
}
