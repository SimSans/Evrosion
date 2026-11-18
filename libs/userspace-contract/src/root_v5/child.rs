//! Additive 16-grant service record for selected M8 Workspace/Display actors.
//! Ordinary <=8 actors retain strict v1 bytes/ABI; no old parser is widened.
use super::{Context, Error, GRANT_BYTES, Grant, HEADER, Record, encode_record, graph};
pub const MAX_GRANTS: usize = 16;
pub const SIZE: usize = HEADER + MAX_GRANTS * GRANT_BYTES;
pub const ABI_DESCRIPTION: &[u8] = b"Evrosion Internal M8 service bootstrap v5; EVSRVC05 version5/profile5 readonly528 header144 max16 canonical24byte grants; selectedWorkspace16/Display10 only; actualContext epoch/incarnation/process/limits/descriptor/authority; selectedM8finiteCPU1000000 perchild noreset legacyCPUunchanged; monotonic selectors nohandlealiases reservedzero exactcount/shape; metadata and parsedIDs grant noauthority; ordinaryV1 336/max8 ABI unchanged noV1cast; childstack480..487 guards479/488 startup509 temporaryentrystack511; Origin57 INFO58 negotiated descriptor0000000100080001 actualservingendpoint+nonce notpacketcaller; actualmeasuredimage/template/custody/mappings and Start establishexecution";
pub const ABI: [u8; 32] = [
    0x17, 0x50, 0x8d, 0xb0, 0xf3, 0x8e, 0xc5, 0xa0, 0x42, 0x6d, 0x11, 0xfd, 0xff, 0x96, 0x77, 0x06,
    0x32, 0x61, 0xa6, 0x5f, 0x04, 0x61, 0xda, 0x2c, 0xc9, 0x3a, 0x82, 0x35, 0x08, 0x6f, 0x6f, 0x96,
];
pub struct Bootstrap<'a>(Record<'a>);
impl<'a> Bootstrap<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Record::parse(bytes, b"EVSRVC05", SIZE, MAX_GRANTS).map(Self)
    }
    pub fn context(&self) -> Context {
        self.0.context()
    }
    pub fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
        self.0.grants()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0.bytes
    }
}
pub const fn extended(child: graph::Child) -> bool {
    matches!(child, graph::Child::Workspace | graph::Child::Display)
}
pub const fn abi(child: graph::Child) -> [u8; 32] {
    if extended(child) { ABI } else { crate::ABI }
}
pub const fn startup_size(child: graph::Child) -> usize {
    if extended(child) { SIZE } else { crate::SIZE }
}
pub const fn startup_version(child: graph::Child) -> u16 {
    if extended(child) { 5 } else { 1 }
}
pub struct Profile<'a> {
    bootstrap: Bootstrap<'a>,
    child: graph::Child,
}
impl<'a> Profile<'a> {
    pub fn parse(child: graph::Child, bytes: &'a [u8]) -> Result<Self, Error> {
        if !extended(child) {
            return Err(Error::Profile);
        }
        let bootstrap = Bootstrap::parse(bytes)?;
        if bootstrap.context().limits != child.limits() {
            return Err(Error::Limits);
        }
        if bootstrap.0.count != graph::grants(child).len() {
            return Err(Error::Roles);
        }
        for (index, (actual, expected)) in bootstrap.grants().zip(graph::grants(child)).enumerate()
        {
            if (actual.selector, actual.kind, actual.rights)
                != (index as u64 + 1, expected.kind, expected.rights)
            {
                return Err(Error::Roles);
            }
        }
        Ok(Self { bootstrap, child })
    }
    pub const fn child(&self) -> graph::Child {
        self.child
    }
    pub fn context(&self) -> Context {
        self.bootstrap.context()
    }
    pub fn handle(&self, selector: u64) -> Option<u64> {
        self.bootstrap
            .grants()
            .find(|g| g.selector == selector)
            .map(|g| g.handle)
    }
    pub fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
        self.bootstrap.grants()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bootstrap.bytes()
    }
}
pub fn encode_profile(
    child: graph::Child,
    context: Context,
    handles: &[u64],
) -> Result<[u8; SIZE], Error> {
    if !extended(child) {
        return Err(Error::Profile);
    }
    if handles.len() != graph::grants(child).len() {
        return Err(Error::Roles);
    }
    let mut grants = [Grant {
        selector: 0,
        handle: 0,
        kind: 0,
        rights: 0,
    }; MAX_GRANTS];
    for (index, expected) in graph::grants(child).enumerate() {
        grants[index] = Grant {
            selector: index as u64 + 1,
            handle: handles[index],
            kind: expected.kind,
            rights: expected.rights,
        };
    }
    let b = encode_record(b"EVSRVC05", MAX_GRANTS, context, &grants[..handles.len()])?;
    Profile::parse(child, &b)?;
    Ok(b)
}
