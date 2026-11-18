use crate::{Head, Object};
use sha2::{Digest, Sha256};
fn put(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
fn get(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn object(b: &mut [u8], p: usize, o: Object) {
    put(b, p, o.start);
    put(b, p + 8, o.sectors);
    put(b, p + 16, o.length);
    b[p + 24..p + 56].copy_from_slice(&o.hash);
}
fn read(b: &[u8], p: usize) -> Object {
    Object {
        start: get(b, p),
        sectors: get(b, p + 8),
        length: get(b, p + 16),
        hash: b[p + 24..p + 56].try_into().unwrap(),
    }
}
pub(crate) fn encode_head(h: Head) -> [u8; 256] {
    let mut b = [0; 256];
    b[..8].copy_from_slice(b"EVCTRS01");
    b[8] = 1;
    put(&mut b, 16, h.high);
    put(&mut b, 24, h.revision);
    if let Some(o) = h.published {
        b[32] = 1;
        object(&mut b, 40, o);
    }
    b
}
pub(crate) fn decode_head(b: &[u8; 256]) -> Option<Head> {
    if &b[..8] != b"EVCTRS01"
        || b[8] != 1
        || b[9..16]
            .iter()
            .chain(b[33..40].iter())
            .chain(b[96..].iter())
            .any(|v| *v != 0)
        || b[32] > 1
    {
        return None;
    }
    let h = Head {
        high: get(b, 16),
        revision: get(b, 24),
        published: if b[32] == 1 {
            Some(read(b, 40))
        } else {
            if b[40..96].iter().any(|v| *v != 0) {
                return None;
            }
            None
        },
    };
    if h.high > crate::OBJECT_SECTORS
        || h.revision == u64::MAX
        || (h.high == 0 && h != Head::EMPTY)
        || h.high == 1
        || (h.revision == 0 && h != Head::EMPTY)
        || (h.published.is_some() && h.revision < 2)
        || h.published.is_some_and(|o| !o.valid(h.high))
    {
        None
    } else {
        Some(h)
    }
}
pub(crate) fn encode_object(o: Object) -> [u8; 512] {
    let mut b = [0; 512];
    b[..8].copy_from_slice(b"EVCOBJ01");
    b[8] = 1;
    object(&mut b, 16, o);
    let hash = Sha256::digest(&b[..480]);
    b[480..].copy_from_slice(&hash);
    b
}
pub(crate) fn decode_object(b: &[u8; 512]) -> Option<Object> {
    if &b[..8] != b"EVCOBJ01"
        || b[8] != 1
        || b[9..16].iter().chain(b[72..480].iter()).any(|v| *v != 0)
        || Sha256::digest(&b[..480])[..] != b[480..]
    {
        return None;
    }
    let o = read(b, 16);
    if o.valid(crate::OBJECT_SECTORS) {
        Some(o)
    } else {
        None
    }
}
