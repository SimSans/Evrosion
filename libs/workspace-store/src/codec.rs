use crate::*;
use sha2::{Digest as _, Sha256};

pub(crate) fn hash(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}
pub(crate) fn fingerprint(kind: u8, numbers: &[u64], bytes: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(b"ev.workspace.operation.v1");
    h.update([kind]);
    for number in numbers {
        h.update(number.to_le_bytes());
    }
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}
fn put16(out: &mut [u8], at: usize, v: u16) {
    out[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(out: &mut [u8], at: usize, v: u32) {
    out[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(out: &mut [u8], at: usize, v: u64) {
    out[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn get16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn get32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn get64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn digest(bytes: &[u8], at: usize) -> Digest {
    bytes[at..at + 32].try_into().unwrap()
}

pub(crate) fn root(value: &Root, out: &mut Sector) {
    out.fill(0);
    out[..8].copy_from_slice(b"EVWROT01");
    put16(out, 8, FORMAT_VERSION);
    out[16..32].copy_from_slice(&value.dataset.0);
    put64(out, 32, value.sequence);
    put64(out, 40, value.namespace);
    out[48] = value.catalog;
    put64(out, 56, value.last_operation);
    out[64..96].copy_from_slice(&value.fingerprint);
    out[96..128].copy_from_slice(&value.catalog_digest);
    if let Some(r) = value.receipt {
        out[50] = r.kind as u8;
        put16(out, 128, r.object.slot);
        put64(out, 136, r.object.generation);
        put64(out, 144, r.object_revision);
        put64(out, 152, r.namespace_revision);
        put64(out, 160, r.stage);
        put64(out, 168, r.bytes);
        put64(out, 176, r.sequence);
        if let Some(request) = r.operation.request {
            out[280..296].copy_from_slice(&request.caller);
            put64(out, 296, request.lease_epoch);
            put64(out, 304, request.nonce);
            out[312] = 1;
        }
    }
    if let Some(s) = value.stage {
        out[49] = 1;
        put64(out, 192, s.id);
        put16(out, 200, s.object.slot);
        put64(out, 208, s.object.generation);
        put64(out, 216, s.expected);
        put64(out, 224, s.length);
        put64(out, 232, s.written);
        put32(out, 240, s.start);
        put32(out, 244, s.chunks);
        out[248..280].copy_from_slice(&s.digest);
    }
    let sum = hash(&out[..480]);
    out[480..].copy_from_slice(&sum);
}
pub(crate) fn unsupported(bytes: &Sector) -> bool {
    (&bytes[..8] == b"EVWROT01" || &bytes[..8] == b"EVWPRV01") && get16(bytes, 8) != FORMAT_VERSION
}
pub(crate) fn provision(dataset: DatasetId, out: &mut Sector) {
    out.fill(0);
    out[..8].copy_from_slice(b"EVWPRV01");
    put16(out, 8, FORMAT_VERSION);
    out[16..32].copy_from_slice(&dataset.0);
    put64(out, 32, REQUIRED_SECTORS);
    put64(out, 40, DATA_START);
    put64(out, 48, USABLE_BYTES);
    put64(out, 56, STAGING_RESERVE_BYTES);
    let sum = hash(&out[..480]);
    out[480..].copy_from_slice(&sum);
}
pub(crate) fn decode_provision(bytes: &Sector) -> Option<DatasetId> {
    if &bytes[..8] != b"EVWPRV01" {
        return None;
    }
    let dataset = DatasetId::new(bytes[16..32].try_into().ok()?)?;
    let mut canonical = [0; 512];
    provision(dataset, &mut canonical);
    (canonical == *bytes).then_some(dataset)
}
pub(crate) fn decode_root(bytes: &Sector) -> Option<Root> {
    if &bytes[..8] != b"EVWROT01"
        || get16(bytes, 8) != FORMAT_VERSION
        || hash(&bytes[..480]) != digest(bytes, 480)
    {
        return None;
    }
    let sequence = get64(bytes, 32);
    let namespace = get64(bytes, 40);
    let last_operation = get64(bytes, 56);
    if sequence == 0
        || sequence == u64::MAX
        || namespace == 0
        || namespace == u64::MAX
        || bytes[48] > 1
        || last_operation == u64::MAX
        || last_operation.checked_add(1) != Some(sequence)
        || namespace > sequence
    {
        return None;
    }
    let kind = match bytes[50] {
        0 => None,
        1 => Some(ReceiptKind::Created),
        2 => Some(ReceiptKind::Renamed),
        3 => Some(ReceiptKind::Moved),
        4 => Some(ReceiptKind::Trashed),
        5 => Some(ReceiptKind::Restored),
        6 => Some(ReceiptKind::Purged),
        7 => Some(ReceiptKind::Begun),
        8 => Some(ReceiptKind::Chunk),
        9 => Some(ReceiptKind::Committed),
        10 => Some(ReceiptKind::Aborted),
        _ => return None,
    };
    let receipt = if let Some(kind) = kind {
        if get64(bytes, 176) != sequence || get64(bytes, 152) != namespace {
            return None;
        }
        let mut operation = OperationId::new(last_operation)?;
        match bytes[312] {
            0 => (),
            1 => {
                operation = operation.for_request(ClientRequest::new(
                    bytes[280..296].try_into().ok()?,
                    get64(bytes, 296),
                    get64(bytes, 304),
                )?)
            }
            _ => return None,
        }
        Some(Receipt {
            operation,
            sequence,
            kind,
            object: ObjectId::new(get16(bytes, 128), get64(bytes, 136))?,
            object_revision: get64(bytes, 144),
            namespace_revision: namespace,
            stage: get64(bytes, 160),
            bytes: get64(bytes, 168),
            replayed: false,
        })
    } else {
        if last_operation != 0 {
            return None;
        }
        None
    };
    let stage = match bytes[49] {
        0 => None,
        1 => {
            let s = Stage {
                id: get64(bytes, 192),
                object: ObjectId::new(get16(bytes, 200), get64(bytes, 208))?,
                expected: get64(bytes, 216),
                length: get64(bytes, 224),
                written: get64(bytes, 232),
                start: get32(bytes, 240),
                chunks: get32(bytes, 244),
                digest: digest(bytes, 248),
            };
            if OperationId::new(s.id).is_none()
                || s.id > last_operation
                || s.object.slot == 0
                || s.expected == 0
                || s.expected == u64::MAX
                || s.length > MAX_FILE_BYTES
                || s.chunks != chunks_for(s.length)
                || s.written > s.length
                || (s.written != s.length && !s.written.is_multiple_of(CHUNK_BYTES as u64))
                || !extent(s.start, s.chunks)
            {
                return None;
            }
            Some(s)
        }
        _ => return None,
    };
    let value = Root {
        dataset: DatasetId::new(bytes[16..32].try_into().ok()?)?,
        sequence,
        namespace,
        catalog: bytes[48],
        catalog_digest: digest(bytes, 96),
        last_operation,
        fingerprint: digest(bytes, 64),
        receipt,
        stage,
    };
    let mut canonical = [0; 512];
    root(&value, &mut canonical);
    (canonical == *bytes).then_some(value)
}
pub(crate) fn extent(start: u32, chunks: u32) -> bool {
    if chunks == 0 {
        start == 0
    } else {
        start.checked_add(chunks).is_some_and(|v| v <= POOL_CHUNKS)
    }
}
pub(crate) fn entry(value: &Entry, index: usize, out: &mut [u8]) {
    out.fill(0);
    out[..8].copy_from_slice(b"EVWENT01");
    put16(out, 8, FORMAT_VERSION);
    put16(out, 10, (index + 1) as u16);
    out[12] = value.kind;
    out[13] = u8::from(value.trashed);
    out[14] = value.name.length;
    put64(out, 16, value.generation);
    put64(out, 24, value.parent.generation);
    put16(out, 32, value.parent.slot);
    put64(out, 40, value.revision);
    put64(out, 48, value.length);
    put32(out, 56, value.start);
    put32(out, 60, value.chunks);
    put64(out, 64, value.stamp);
    out[72..104].copy_from_slice(&value.digest);
    out[104..200].copy_from_slice(&value.name.bytes);
    let sum = hash(&out[..224]);
    out[224..256].copy_from_slice(&sum);
}
pub(crate) fn decode_entry(bytes: &[u8], index: usize) -> Option<Entry> {
    if bytes.len() != 256
        || &bytes[..8] != b"EVWENT01"
        || get16(bytes, 8) != FORMAT_VERSION
        || get16(bytes, 10) as usize != index + 1
        || hash(&bytes[..224]) != digest(bytes, 224)
        || bytes[13] > 1
        || bytes[12] > 2
        || bytes[14] as usize > MAX_NAME
    {
        return None;
    }
    let mut value = Entry {
        generation: get64(bytes, 16),
        kind: bytes[12],
        trashed: bytes[13] != 0,
        parent: ObjectId::new(get16(bytes, 32), get64(bytes, 24))?,
        revision: get64(bytes, 40),
        name: Name::EMPTY,
        length: get64(bytes, 48),
        start: get32(bytes, 56),
        chunks: get32(bytes, 60),
        stamp: get64(bytes, 64),
        digest: digest(bytes, 72),
    };
    value.name.length = bytes[14];
    value.name.bytes.copy_from_slice(&bytes[104..200]);
    if value.generation == u64::MAX {
        return None;
    }
    if value.kind == 0 {
        let empty = Entry {
            generation: value.generation,
            ..Entry::EMPTY
        };
        if value != empty {
            return None;
        }
    } else {
        if value.generation == 0 || value.revision == 0 || value.revision == u64::MAX {
            return None;
        }
        let text = core::str::from_utf8(value.name.as_bytes()).ok()?;
        if Name::new(text) != Some(value.name) {
            return None;
        }
        if value.kind == 2 {
            if value.length != 0
                || value.start != 0
                || value.chunks != 0
                || value.stamp != 0
                || value.digest != [0; 32]
            {
                return None;
            }
        } else if value.length > MAX_FILE_BYTES
            || value.chunks != chunks_for(value.length)
            || !extent(value.start, value.chunks)
            || (value.length != 0 && OperationId::new(value.stamp).is_none())
        {
            return None;
        }
    }
    let mut canonical = [0; 256];
    entry(&value, index, &mut canonical);
    (canonical == bytes).then_some(value)
}
pub(crate) fn chunk_header(
    object: ObjectId,
    stamp: u64,
    index: u32,
    length: usize,
    digest: Digest,
    out: &mut Sector,
) {
    out.fill(0);
    out[..8].copy_from_slice(b"EVWCHK01");
    put16(out, 8, FORMAT_VERSION);
    put16(out, 10, object.slot);
    put64(out, 16, object.generation);
    put64(out, 24, stamp);
    put32(out, 32, index);
    put32(out, 36, length as u32);
    out[40..72].copy_from_slice(&digest);
    let sum = hash(&out[..480]);
    out[480..].copy_from_slice(&sum);
}
pub(crate) fn decode_chunk_header(
    bytes: &Sector,
    object: ObjectId,
    stamp: u64,
    index: u32,
    length: usize,
) -> Option<Digest> {
    if hash(&bytes[..480]) != digest(bytes, 480) {
        return None;
    }
    let sum = digest(bytes, 40);
    let mut canonical = [0; 512];
    chunk_header(object, stamp, index, length, sum, &mut canonical);
    (canonical == *bytes).then_some(sum)
}
