//! Explicit public-transport fault injection. This verifies signatures only;
//! it creates no private challenge, Anchor, time interval or UTC authority.
use super::Result;
use ed25519_dalek::{Signature, VerifyingKey};
use ev_release_trust::signature::PublicKey;
use std::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Mutation {
    pub original: Vec<u8>,
    pub mutated: Vec<u8>,
    pub signature_offset: usize,
    pub bit_mask: u8,
}
fn tag(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}
fn number(b: &[u8], at: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or("signature witness extent")?
            .try_into()
            .unwrap(),
    ) as usize)
}
struct Message<'a> {
    bytes: &'a [u8],
    tags: Vec<(u32, Range<usize>)>,
}
impl<'a> Message<'a> {
    fn parse(bytes: &'a [u8], required: &[[u8; 4]]) -> Result<Self> {
        if bytes.len() < 4 || !bytes.len().is_multiple_of(4) {
            return Err("signature witness message length".into());
        }
        let count = number(bytes, 0)?;
        if count != required.len() || count == 0 || count > 8 || bytes.len() < 8 * count {
            return Err("signature witness tags/count".into());
        }
        let body = 8 * count;
        let extent = bytes.len() - body;
        let mut tags = Vec::new();
        let mut before = 0;
        let mut prior = None;
        for (i, wanted) in required.iter().enumerate() {
            let t = number(bytes, 4 * count + 4 * i)? as u32;
            let end = if i + 1 == count {
                extent
            } else {
                number(bytes, 4 * (i + 1))?
            };
            if t != tag(wanted)
                || prior.is_some_and(|p| p >= t)
                || !end.is_multiple_of(4)
                || end < before
                || end > extent
            {
                return Err("signature witness canonical tag/offset".into());
            }
            tags.push((t, body + before..body + end));
            before = end;
            prior = Some(t);
        }
        Ok(Self { bytes, tags })
    }
    fn range(&self, name: &[u8; 4]) -> Result<Range<usize>> {
        self.tags
            .iter()
            .find(|(t, _)| *t == tag(name))
            .map(|(_, r)| r.clone())
            .ok_or_else(|| "signature witness missing field".into())
    }
    fn field(&self, name: &[u8; 4]) -> Result<&'a [u8]> {
        Ok(&self.bytes[self.range(name)?])
    }
}
fn verify(key: [u8; 32], domain: &[u8], body: &[u8], signature: &[u8]) -> Result<()> {
    let key = PublicKey::parse(key).map_err(|_| "signature witness key")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "signature witness width")?;
    let bytes = [domain, body].concat();
    VerifyingKey::from_bytes(&key.bytes())
        .map_err(|_| "signature witness key")?
        .verify_strict(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| "signature witness verification".into())
}
fn signatures(bytes: &[u8]) -> Result<Range<usize>> {
    if !(12..=ev_time_proof::MAX_REPLY_BYTES).contains(&bytes.len())
        || &bytes[..8] != b"ROUGHTIM"
        || number(bytes, 8)? != bytes.len() - 12
    {
        return Err("signature witness framing".into());
    }
    let outer = Message::parse(
        &bytes[12..],
        &[*b"SIG\0", *b"VER\0", *b"PATH", *b"SREP", *b"CERT", *b"INDX"],
    )?;
    if outer.field(b"VER\0")? != ev_time_proof::PROTOCOL.to_le_bytes() {
        return Err("signature witness version".into());
    }
    let cert = Message::parse(outer.field(b"CERT")?, &[*b"SIG\0", *b"DELE"])?;
    let delegation = cert.field(b"DELE")?;
    let delegated = Message::parse(delegation, &[*b"PUBK", *b"MINT", *b"MAXT"])?;
    verify(
        ev_time_proof::PUBLIC_KEY,
        b"RoughTime v1 delegation signature--\0",
        delegation,
        cert.field(b"SIG\0")?,
    )?;
    verify(
        delegated
            .field(b"PUBK")?
            .try_into()
            .map_err(|_| "signature witness delegated key")?,
        b"RoughTime v1 response signature\0",
        outer.field(b"SREP")?,
        outer.field(b"SIG\0")?,
    )?;
    let range = outer.range(b"SIG\0")?;
    if range.len() != 64 {
        return Err("signature witness width".into());
    }
    Ok(12 + range.start..12 + range.end)
}
pub(crate) fn checked(original: &[u8]) -> Result<Mutation> {
    let range = signatures(original)?;
    let mut mutated = original.to_vec();
    mutated[range.start] ^= 1;
    if signatures(&mutated).is_ok() {
        return Err("signature mutation failed to invalidate signature".into());
    }
    Ok(Mutation {
        original: original.to_vec(),
        mutated,
        signature_offset: range.start,
        bit_mask: 1,
    })
}
/// Public signatures only. Nonce ownership, actual origin and a trusted time
/// interval still belong exclusively to the guest's affine Client/Anchor.
pub(crate) fn verify_original(original: &[u8]) -> Result<()> {
    signatures(original).map(|_| ())
}
/// Public transport correlation only. The guest still owns its affine nonce,
/// private challenge, clock and authorization; this returns none of those.
pub(crate) fn verify_public_nonce(original: &[u8], nonce: &[u8; 32]) -> Result<()> {
    use sha2::{Digest, Sha512};
    verify_original(original)?;
    let outer = Message::parse(
        &original[12..],
        &[*b"SIG\0", *b"VER\0", *b"PATH", *b"SREP", *b"CERT", *b"INDX"],
    )?;
    let signed = Message::parse(outer.field(b"SREP")?, &[*b"RADI", *b"MIDP", *b"ROOT"])?;
    let path = outer.field(b"PATH")?;
    if !path.len().is_multiple_of(32) || path.len() > 32 * 32 {
        return Err("public time transport path extent".into());
    }
    let mut index = u32::from_le_bytes(
        outer
            .field(b"INDX")?
            .try_into()
            .map_err(|_| "public time index width")?,
    );
    let digest = |parts: &[&[u8]]| -> [u8; 32] {
        let mut hash = Sha512::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize()[..32].try_into().unwrap()
    };
    let mut root = digest(&[&[0], nonce]);
    for sibling in path.as_chunks::<32>().0 {
        root = if index & 1 == 0 {
            digest(&[&[1], &root, sibling])
        } else {
            digest(&[&[1], sibling, &root])
        };
        index >>= 1;
    }
    if index != 0 || signed.field(b"ROOT")? != root {
        return Err("public time response differs from actual request nonce".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_public_signature_bit_changes_without_a_challenge_or_clock_factory() {
        let original = include_bytes!("../../../../libs/time-proof/tests/fixtures/response.bin");
        let m = checked(original).unwrap();
        assert_eq!(m.original.len(), m.mutated.len());
        assert_eq!(
            m.original
                .iter()
                .zip(&m.mutated)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(i, _)| i)
                .collect::<Vec<_>>(),
            [m.signature_offset]
        );
        assert_eq!(
            m.original[m.signature_offset] ^ m.mutated[m.signature_offset],
            1
        );
        assert!(checked(&m.mutated).is_err());
        for end in 0..original.len() {
            assert!(checked(&original[..end]).is_err());
        }
        let mut bad = original.to_vec();
        bad[8] ^= 1;
        assert!(checked(&bad).is_err());
        let mut bad = original.to_vec();
        bad[12..16].copy_from_slice(&9u32.to_le_bytes());
        assert!(checked(&bad).is_err());
    }
    #[test]
    fn public_transport_correlation_never_creates_a_guest_challenge_or_anchor() {
        let packet = include_bytes!("../../../../libs/time-proof/tests/fixtures/response.bin");
        let nonce = include_bytes!("../../../../libs/time-proof/tests/fixtures/nonce.bin");
        verify_public_nonce(packet, nonce).unwrap();
        let mut wrong = *nonce;
        wrong[0] ^= 1;
        assert!(verify_public_nonce(packet, &wrong).is_err());
        let mut changed = packet.to_vec();
        changed[24] ^= 1;
        assert!(verify_public_nonce(&changed, nonce).is_err());
    }
}
