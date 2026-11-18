//! The sole raw-memory boundary for an admitted two-page File2 window.
#![allow(unsafe_code)]
use super::*;
use core::marker::PhantomData;
use ev_userspace_runtime as rt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfFacts {
    pub process: u64,
    pub thread: u64,
    pub registered_incarnation: u64,
}
/// Negotiate the M8-only read-only self extension before using surface metadata.
/// These descriptive IDs never prove Root's role or grant access to another actor.
pub fn self_facts() -> Result<SelfFacts, TransportError> {
    let info = rt::call4(rt::syscall::SELF_IDENTITY_INFO, 0, 0, 0, 0);
    if info.status != 0
        || info.value != rt::syscall::SELF_IDENTITY_V1
        || info.capability != 0
        || info.serial != 0
    {
        return Err(TransportError::Correlation);
    }
    let mut fields = [0; 3];
    for (field, out) in fields.iter_mut().enumerate() {
        let reply = rt::call(rt::syscall::SELF_IDENTITY, field as u64, 0, 0);
        if reply.status != 0 || reply.capability != 0 {
            return Err(TransportError::Correlation);
        }
        *out = reply.value;
    }
    if fields[0] == 0 || fields[1] == 0 {
        return Err(TransportError::Correlation);
    }
    Ok(SelfFacts {
        process: fields[0],
        thread: fields[1],
        registered_incarnation: fields[2],
    })
}

/// Owns a retained mapping and endpoint. No Send/Sync or safe address constructor.
/// Dropping this value does not prove quiescence or permit physical retirement.
pub struct NativeLink {
    address: usize,
    endpoint: u64,
    last_request: u64,
    retained: Option<Pending>,
    readable: usize,
    _single_owner: PhantomData<*mut ()>,
}
impl NativeLink {
    pub(crate) fn close_quiescent(&mut self) -> Result<(), TransportError> {
        if self.retained.is_some() || self.endpoint == 0 {
            return Err(TransportError::Correlation);
        }
        let r = rt::call(rt::syscall::CLOSE, self.endpoint, 0, 0);
        if r.status != 0 || r.value != 0 || r.capability != 0 {
            return Err(TransportError::Correlation);
        }
        self.endpoint = 0;
        Ok(())
    }
    /// # Safety
    /// Caller retains exactly8192 initialized RW/NX mapped bytes at address,
    /// matching this incarnation's admitted File2 MemoryObject and exact-object
    /// SEND endpoint. No other local writer/reference aliases them. The server
    /// accesses the window only during this endpoint's accepted RPC and returns
    /// credit before an exact reply; until then caller never edits or unmaps it.
    /// Mapping/backing/endpoint live through this value, including quarantine.
    /// Construction occurs once per admitted route/incarnation, never to reset
    /// uncertain operations or reuse counters. Scalars establish no authority.
    pub unsafe fn from_admitted_mapping(
        address: usize,
        extent: usize,
        endpoint: u64,
    ) -> Result<Self, TransportError> {
        if address == 0
            || !address.is_multiple_of(4096)
            || extent != WINDOW_BYTES
            || endpoint == 0
            || endpoint == u64::MAX
            || address
                .checked_add(extent)
                .is_none_or(|end| end > 1usize << 47)
        {
            return Err(TransportError::Mapping);
        }
        Ok(Self {
            address,
            endpoint,
            last_request: 0,
            retained: None,
            readable: 0,
            _single_owner: PhantomData,
        })
    }
}
impl Link for NativeLink {
    fn now(&mut self) -> Result<u64, TransportError> {
        let reply = rt::monotonic();
        if reply.status != 0 || reply.capability != 0 || reply.value == u64::MAX {
            return Err(TransportError::Clock);
        }
        Ok(reply.value)
    }
    fn exchange(
        &mut self,
        request_id: u64,
        control: &[u8; wire::FRAME_BYTES],
        bulk: &[u8],
        deadline: Deadline,
    ) -> Result<[u8; wire::FRAME_BYTES], TransportError> {
        if self.endpoint == 0
            || self.retained.is_some()
            || request_id == 0
            || request_id == u64::MAX
            || request_id <= self.last_request
            || bulk.len() > CHUNK_BYTES
        {
            return Err(TransportError::Correlation);
        }
        let request = Request::decode(control).map_err(|_| TransportError::Correlation)?;
        if request.request_id != request_id || request.deadline != deadline {
            return Err(TransportError::Correlation);
        }
        match request.method {
            Method::WriteChunk { length, digest, .. }
                if bulk.len() == length as usize
                    && <[u8; 32]>::from(Sha256::digest(bulk)) == digest => {}
            Method::WriteChunk { .. } => return Err(TransportError::Correlation),
            _ if !bulk.is_empty() => return Err(TransportError::Correlation),
            _ => (),
        }
        self.retained = Some(Pending::new(request).map_err(|_| TransportError::Correlation)?);
        self.readable = 0;
        self.last_request = request_id;
        for (offset, &byte) in control.iter().enumerate() {
            // SAFETY: independently admitted sole-writer extent, no accepted
            // loan at this transition. Volatile access creates no Rust alias.
            unsafe { (self.address as *mut u8).add(offset).write_volatile(byte) };
        }
        for (offset, &byte) in bulk.iter().enumerate() {
            // SAFETY: at most4096 bytes in the retained second page; this is
            // before the exact endpoint can acquire its server read credit.
            unsafe {
                (self.address as *mut u8)
                    .add(BULK_OFFSET + offset)
                    .write_volatile(byte)
            };
        }
        let reply = rt::rpc::call(self.endpoint, request_id.to_le_bytes(), deadline.tick())
            .map_err(|_| TransportError::Rpc)?;
        if u64::from_le_bytes(reply) != request_id {
            return Err(TransportError::Correlation);
        }
        let response = core::array::from_fn(|offset| {
            // SAFETY: exact scalar reply returns credit under the independently
            // admitted route contract. The mapping remains retained and no
            // references/volatile reads are carried across another syscall.
            unsafe { (self.address as *const u8).add(offset).read_volatile() }
        });
        let decoded = self
            .retained
            .as_mut()
            .unwrap()
            .observe(&response, 0)
            .map_err(|_| TransportError::Correlation)?;
        if self.retained.as_ref().unwrap().completion_observed() {
            if decoded.outcome == Outcome::Completed
                && matches!(request.method, Method::Read { .. })
            {
                if decoded
                    .offset
                    .checked_add(decoded.length)
                    .is_none_or(|end| end > decoded.file_length)
                {
                    return Err(TransportError::Correlation);
                }
                self.readable = decoded.length as usize;
            }
            self.retained = None;
        }
        Ok(response)
    }
    fn read_bulk(&mut self, out: &mut [u8]) -> Result<(), TransportError> {
        if self.retained.is_some() || out.len() > self.readable || out.len() > CHUNK_BYTES {
            return Err(TransportError::Mapping);
        }
        for (offset, byte) in out.iter_mut().enumerate() {
            // SAFETY: exact correlated response validated, returned read credit
            // and <=4096 bytes in retained second page; no accepted new call.
            *byte = unsafe {
                (self.address as *const u8)
                    .add(BULK_OFFSET + offset)
                    .read_volatile()
            };
        }
        Ok(())
    }
}
