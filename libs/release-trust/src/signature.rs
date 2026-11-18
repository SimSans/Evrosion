//! Canonical bounded Ed25519 envelope with distinct metadata-role domains.
//! A checked KeySet validates configuration syntax, not its authority. The
//! caller must obtain that exact set from independently provisioned/rotated
//! trusted roots; a downloaded key list cannot authorize itself.
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const HEADER_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 96;
pub const MAX_SIGNATURES: usize = 8;
pub const MAX_KEYS: usize = 8;
pub const MAX_PAYLOAD_BYTES: usize = 4096;
pub const MAX_ENVELOPE_BYTES: usize =
    HEADER_BYTES + MAX_PAYLOAD_BYTES + MAX_SIGNATURES * SIGNATURE_BYTES;
const MAGIC: &[u8; 8] = b"EVRSG001";
const ALGORITHM: u8 = 1; // Ed25519, strict individual verification.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Root = 1,
    Targets = 2,
    Snapshot = 3,
    Timestamp = 4,
}
impl Role {
    fn parse(byte: u8) -> Result<Self, Error> {
        match byte {
            1 => Ok(Self::Root),
            2 => Ok(Self::Targets),
            3 => Ok(Self::Snapshot),
            4 => Ok(Self::Timestamp),
            _ => Err(Error::Role),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Reserved,
    Algorithm,
    Role,
    SignerOrder,
    Key,
    KeyCount,
    DuplicateKey,
    Threshold,
}

/// Canonical, nonweak public-key encoding. This is still public data and does
/// not establish that the owner trusts it for any release role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);
impl PublicKey {
    pub fn parse(bytes: [u8; 32]) -> Result<Self, Error> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Key)?;
        if key.is_weak()
            || !key.to_edwards().is_torsion_free()
            || key.to_edwards().compress().to_bytes() != bytes
        {
            return Err(Error::Key);
        }
        Ok(Self(bytes))
    }
    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn id(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"evrosion.release.ed25519.key-id.v1\0");
        hash.update([ALGORITHM]);
        hash.update(self.0);
        hash.finalize().into()
    }
}

/// Borrowed immutable configuration, checked for nonzero bounded threshold
/// and duplicate canonical keys. No root, role or freshness policy is inferred
/// merely by constructing it.
pub struct KeySet<'a> {
    role: Role,
    keys: &'a [PublicKey],
    required: u8,
}
impl<'a> KeySet<'a> {
    pub fn checked_configuration(
        role: Role,
        keys: &'a [PublicKey],
        required: u8,
    ) -> Result<Self, Error> {
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(Error::KeyCount);
        }
        if required == 0 || usize::from(required) > keys.len() {
            return Err(Error::Threshold);
        }
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].contains(key) {
                return Err(Error::DuplicateKey);
            }
        }
        Ok(Self {
            role,
            keys,
            required,
        })
    }
    /// Every signature is checked individually with the upstream strict API.
    /// Unknown/new-root signatures do not count toward this set. A malformed
    /// extra signature also does not erase a valid independent quorum.
    pub fn verify(&self, envelope: &Envelope<'_>) -> Result<(), Error> {
        if envelope.role != self.role {
            return Err(Error::Role);
        }
        let mut valid = 0;
        for signed in envelope.signatures() {
            let Some(public) = self.keys.iter().find(|key| key.id() == signed.key) else {
                continue;
            };
            let key = VerifyingKey::from_bytes(&public.0).map_err(|_| Error::Key)?;
            let signature = Signature::from_bytes(&signed.bytes);
            if key
                .verify_strict(envelope.signed_bytes(), &signature)
                .is_ok()
            {
                valid += 1;
            }
        }
        if valid < usize::from(self.required) {
            Err(Error::Threshold)
        } else {
            Ok(())
        }
    }
}

pub struct Signed {
    pub key: [u8; 32],
    pub bytes: [u8; 64],
}
/// Parsing validates only canonical encoding. It grants neither trust in the
/// payload nor authority to execute it. The borrowed bytes must remain actually
/// immutable throughout verification; an untrusted shared window is unsuitable.
#[derive(Clone, Copy)]
pub struct Envelope<'a> {
    bytes: &'a [u8],
    role: Role,
    payload: usize,
    count: usize,
}
impl<'a> Envelope<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != MAGIC || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != 1 {
            return Err(Error::Version);
        }
        let role = Role::parse(bytes[10])?;
        if bytes[11] != ALGORITHM {
            return Err(Error::Algorithm);
        }
        let payload = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let count = usize::from(bytes[16]);
        if bytes[17..HEADER_BYTES].iter().any(|&byte| byte != 0) {
            return Err(Error::Reserved);
        }
        if payload == 0
            || payload > MAX_PAYLOAD_BYTES
            || !(1..=MAX_SIGNATURES).contains(&count)
            || bytes.len() != HEADER_BYTES + payload + count * SIGNATURE_BYTES
        {
            return Err(Error::Length);
        }
        let value = Self {
            bytes,
            role,
            payload,
            count,
        };
        let mut previous = None;
        for signed in value.signatures() {
            if previous.is_some_and(|p| p >= signed.key) {
                return Err(Error::SignerOrder);
            }
            previous = Some(signed.key);
        }
        Ok(value)
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[HEADER_BYTES..HEADER_BYTES + self.payload]
    }
    pub fn signed_bytes(&self) -> &'a [u8] {
        &self.bytes[..HEADER_BYTES + self.payload]
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn signatures(&self) -> impl ExactSizeIterator<Item = Signed> + '_ {
        self.bytes[HEADER_BYTES + self.payload..]
            .as_chunks::<SIGNATURE_BYTES>()
            .0
            .iter()
            .map(|chunk| Signed {
                key: chunk[..32].try_into().unwrap(),
                bytes: chunk[32..].try_into().unwrap(),
            })
    }
    pub fn signature_count(&self) -> usize {
        self.count
    }
}

/// Canonical header for a signing tool. Sign this exact header followed by the
/// exact payload, then append sorted key-id/signature records. The role,
/// algorithm, payload length and signature count are inside the signed domain.
pub fn header(role: Role, payload: usize, signatures: usize) -> Result<[u8; HEADER_BYTES], Error> {
    if payload == 0 || payload > MAX_PAYLOAD_BYTES || !(1..=MAX_SIGNATURES).contains(&signatures) {
        return Err(Error::Length);
    }
    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10] = role as u8;
    bytes[11] = ALGORITHM;
    bytes[12..16].copy_from_slice(&(payload as u32).to_le_bytes());
    bytes[16] = signatures as u8;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
