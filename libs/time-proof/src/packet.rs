//! Closed observed Cloudflare IETF draft11 profile. Not RFC10049 version1.
use ed25519_dalek::{Signature, VerifyingKey};
use ev_release_trust::signature::PublicKey;
use sha2::{Digest, Sha512};
pub const PROTOCOL: u32 = 0x8000_000b;
pub const PUBLIC_KEY: [u8; 32] = [
    208, 96, 251, 115, 124, 143, 243, 17, 28, 225, 153, 118, 205, 235, 141, 217, 41, 75, 188, 53,
    85, 161, 200, 236, 61, 34, 252, 253, 25, 127, 239, 56,
];
pub const MAX_PATH_DEPTH: usize = 16;
pub const MAX_REPLY_BYTES: usize = 352 + MAX_PATH_DEPTH * 32;
const MAX_TAGS: usize = 8;
const CERT_DOMAIN: &[u8] = b"RoughTime v1 delegation signature--\0";
const RESPONSE_DOMAIN: &[u8] = b"RoughTime v1 response signature\0";
const fn tag(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}
const SIG: u32 = tag(b"SIG\0");
const VER: u32 = tag(b"VER\0");
const PATH: u32 = tag(b"PATH");
const SREP: u32 = tag(b"SREP");
const CERT: u32 = tag(b"CERT");
const INDX: u32 = tag(b"INDX");
const PUBK: u32 = tag(b"PUBK");
const MINT: u32 = tag(b"MINT");
const MAXT: u32 = tag(b"MAXT");
const RADI: u32 = tag(b"RADI");
const MIDP: u32 = tag(b"MIDP");
const ROOT: u32 = tag(b"ROOT");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    Length,
    Frame,
    Count,
    Order,
    Offset,
    Tags,
    Version,
    Key,
    Signature,
    Delegation,
    Radius,
    Overflow,
    Path,
    Nonce,
}
fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn exact<const N: usize>(b: &[u8]) -> Result<[u8; N], PacketError> {
    b.try_into().map_err(|_| PacketError::Length)
}
struct Message<'a> {
    bytes: &'a [u8],
    count: usize,
    body: usize,
}
impl<'a> Message<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, PacketError> {
        if b.len() < 4 || !b.len().is_multiple_of(4) {
            return Err(PacketError::Length);
        }
        let n = u32at(b, 0) as usize;
        if n == 0 || n > MAX_TAGS {
            return Err(PacketError::Count);
        }
        let body = 8 * n;
        if b.len() < body {
            return Err(PacketError::Length);
        }
        let extent = b.len() - body;
        let mut previous = 0;
        for i in 0..n - 1 {
            let end = u32at(b, 4 + i * 4) as usize;
            if !end.is_multiple_of(4) || end < previous || end > extent {
                return Err(PacketError::Offset);
            }
            previous = end;
        }
        let mut prior = None;
        for i in 0..n {
            let t = u32at(b, 4 * n + i * 4);
            if prior.is_some_and(|p| p >= t) {
                return Err(PacketError::Order);
            }
            prior = Some(t);
        }
        Ok(Self {
            bytes: b,
            count: n,
            body,
        })
    }
    fn required(&self, tags: &[u32]) -> Result<(), PacketError> {
        if self.count != tags.len() {
            return Err(PacketError::Tags);
        }
        for (i, t) in tags.iter().enumerate() {
            if u32at(self.bytes, 4 * self.count + i * 4) != *t {
                return Err(PacketError::Tags);
            }
        }
        Ok(())
    }
    fn get(&self, tag: u32) -> Result<&'a [u8], PacketError> {
        for i in 0..self.count {
            if u32at(self.bytes, 4 * self.count + i * 4) == tag {
                let start = if i == 0 {
                    0
                } else {
                    u32at(self.bytes, 4 * i) as usize
                };
                let end = if i + 1 == self.count {
                    self.bytes.len() - self.body
                } else {
                    u32at(self.bytes, 4 * (i + 1)) as usize
                };
                return Ok(&self.bytes[self.body + start..self.body + end]);
            }
        }
        Err(PacketError::Tags)
    }
}
fn verify_signature(
    key: PublicKey,
    domain: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PacketError> {
    let mut preimage = [0u8; 128];
    let length = domain
        .len()
        .checked_add(message.len())
        .ok_or(PacketError::Length)?;
    if length > preimage.len() {
        return Err(PacketError::Length);
    }
    preimage[..domain.len()].copy_from_slice(domain);
    preimage[domain.len()..length].copy_from_slice(message);
    VerifyingKey::from_bytes(&key.bytes())
        .map_err(|_| PacketError::Key)?
        .verify_strict(
            &preimage[..length],
            &Signature::from_bytes(&exact(signature)?),
        )
        .map_err(|_| PacketError::Signature)
}
#[derive(Clone, Copy)]
pub(crate) struct SignedTime {
    pub earliest: u64,
    pub latest: u64,
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()[..32].try_into().unwrap()
}
pub(crate) fn verify(
    key: PublicKey,
    nonce: &[u8; 32],
    bytes: &[u8],
    max_radius: u32,
) -> Result<SignedTime, PacketError> {
    if bytes.len() < 12 || bytes.len() > MAX_REPLY_BYTES {
        return Err(PacketError::Length);
    }
    if &bytes[..8] != b"ROUGHTIM" || u32at(bytes, 8) as usize != bytes.len() - 12 {
        return Err(PacketError::Frame);
    }
    let outer = Message::parse(&bytes[12..])?;
    outer.required(&[SIG, VER, PATH, SREP, CERT, INDX])?;
    if u32::from_le_bytes(exact(outer.get(VER)?)?) != PROTOCOL {
        return Err(PacketError::Version);
    }
    let cert = Message::parse(outer.get(CERT)?)?;
    cert.required(&[SIG, tag(b"DELE")])?;
    let delegation = cert.get(tag(b"DELE"))?;
    let delegated = Message::parse(delegation)?;
    delegated.required(&[PUBK, MINT, MAXT])?;
    let public = PublicKey::parse(exact(delegated.get(PUBK)?)?).map_err(|_| PacketError::Key)?;
    verify_signature(key, CERT_DOMAIN, delegation, cert.get(SIG)?)?;
    let signed = outer.get(SREP)?;
    verify_signature(public, RESPONSE_DOMAIN, signed, outer.get(SIG)?)?;
    let srep = Message::parse(signed)?;
    srep.required(&[RADI, MIDP, ROOT])?;
    let midpoint = u64::from_le_bytes(exact(srep.get(MIDP)?)?);
    let radius = u32::from_le_bytes(exact(srep.get(RADI)?)?);
    let min = u64::from_le_bytes(exact(delegated.get(MINT)?)?);
    let max = u64::from_le_bytes(exact(delegated.get(MAXT)?)?);
    if min > max || midpoint < min || midpoint > max {
        return Err(PacketError::Delegation);
    }
    if radius == 0 || radius > max_radius {
        return Err(PacketError::Radius);
    }
    let path = outer.get(PATH)?;
    if !path.len().is_multiple_of(32) || path.len() / 32 > MAX_PATH_DEPTH {
        return Err(PacketError::Path);
    }
    let mut index = u32::from_le_bytes(exact(outer.get(INDX)?)?);
    let mut root = hash(&[&[0], nonce]);
    for sibling in path.as_chunks::<32>().0 {
        root = if index & 1 == 0 {
            hash(&[&[1], &root, sibling])
        } else {
            hash(&[&[1], sibling, &root])
        };
        index >>= 1;
    }
    if index != 0 {
        return Err(PacketError::Path);
    }
    if root != exact::<32>(srep.get(ROOT)?)? {
        return Err(PacketError::Nonce);
    }
    Ok(SignedTime {
        earliest: midpoint
            .checked_sub(u64::from(radius))
            .ok_or(PacketError::Overflow)?,
        latest: midpoint
            .checked_add(u64::from(radius))
            .ok_or(PacketError::Overflow)?,
    })
}
pub(crate) fn request(nonce: &[u8; 32], out: &mut [u8; 1024]) {
    out.fill(0);
    out[..8].copy_from_slice(b"ROUGHTIM");
    out[8..12].copy_from_slice(&1012u32.to_le_bytes());
    out[12..16].copy_from_slice(&4u32.to_le_bytes());
    for (i, end) in [4u32, 36, 68].into_iter().enumerate() {
        out[16 + i * 4..20 + i * 4].copy_from_slice(&end.to_le_bytes());
    }
    for (i, t) in [VER, tag(b"SRV\0"), tag(b"NONC"), tag(b"ZZZZ")]
        .into_iter()
        .enumerate()
    {
        out[28 + i * 4..32 + i * 4].copy_from_slice(&t.to_le_bytes());
    }
    out[44..48].copy_from_slice(&PROTOCOL.to_le_bytes());
    out[48..80].copy_from_slice(&hash(&[&[255], &PUBLIC_KEY]));
    out[80..112].copy_from_slice(nonce);
}
