//! Canonical App-private metadata model; encoding is not durable publication.
//! The actual namespace/data owner must validate identity and commit/read back
//! through its scoped backend. This type grants no authority, changes no schema,
//! and is not a migration, initialization or successful-write receipt.
#![forbid(unsafe_code)]
use ev_zion::AppId;
use sha2::{Digest as _, Sha256};
pub const BYTES: usize = 256;
const PAYLOAD: usize = 224;
const MAGIC: &[u8; 8] = b"EVADATA1";
const DOMAIN: &[u8] = b"evrosion.app-data-envelope.v1\0";
const _: () = assert!(BYTES <= ev_store::PAYLOAD_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Format,
    Reserved,
    Integrity,
    Identity,
    Epoch,
    Counter,
    Stale,
}
/// Plain immutable metadata, not a capability or a persistence receipt. Identity
/// and schema remain fixed across checked value replacements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppDataEnvelope {
    app: AppId,
    schema_epoch: u32,
    counter: u64,
    value: u32,
}
impl AppDataEnvelope {
    /// Pure preparation for a genuinely new namespace. Counter0 means initial
    /// state only; caller must separately establish blank allocation and durable
    /// completion before treating any encoded bytes as stored data.
    pub fn initial(app: AppId, schema_epoch: u32, value: u32) -> Result<Self, Error> {
        if schema_epoch == 0 {
            return Err(Error::Epoch);
        }
        Ok(Self {
            app,
            schema_epoch,
            counter: 0,
            value,
        })
    }
    pub const fn app(&self) -> AppId {
        self.app
    }
    pub const fn schema_epoch(&self) -> u32 {
        self.schema_epoch
    }
    pub const fn counter(&self) -> u64 {
        self.counter
    }
    pub const fn value(&self) -> u32 {
        self.value
    }
    pub fn checked_replace(
        &self,
        expected_app: AppId,
        expected_epoch: u32,
        expected_counter: u64,
        value: u32,
    ) -> Result<Self, Error> {
        if expected_app != self.app {
            return Err(Error::Identity);
        }
        if expected_epoch != self.schema_epoch {
            return Err(Error::Epoch);
        }
        if expected_counter != self.counter {
            return Err(Error::Stale);
        }
        let counter = self
            .counter
            .checked_add(1)
            .filter(|c| *c != u64::MAX)
            .ok_or(Error::Counter)?;
        Ok(Self {
            app: self.app,
            schema_epoch: self.schema_epoch,
            counter,
            value,
        })
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(BYTES as u16).to_le_bytes());
        bytes[16..32].copy_from_slice(&self.app.bytes());
        bytes[32..36].copy_from_slice(&self.schema_epoch.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.counter.to_le_bytes());
        bytes[48..52].copy_from_slice(&self.value.to_le_bytes());
        let digest = checksum(&bytes);
        bytes[PAYLOAD..].copy_from_slice(&digest);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; BYTES] = bytes.try_into().map_err(|_| Error::Length)?;
        if &bytes[..8] != MAGIC
            || bytes[8..10] != 1u16.to_le_bytes()
            || bytes[10..12] != (BYTES as u16).to_le_bytes()
        {
            return Err(Error::Format);
        }
        if bytes[224..] != checksum(bytes) {
            return Err(Error::Integrity);
        }
        if bytes[12..16]
            .iter()
            .chain(&bytes[36..40])
            .chain(&bytes[52..224])
            .any(|b| *b != 0)
        {
            return Err(Error::Reserved);
        }
        let app = AppId::new(bytes[16..32].try_into().unwrap()).ok_or(Error::Identity)?;
        let schema_epoch = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        if schema_epoch == 0 {
            return Err(Error::Epoch);
        }
        let counter = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        if counter == u64::MAX {
            return Err(Error::Counter);
        }
        Ok(Self {
            app,
            schema_epoch,
            counter,
            value: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
        })
    }
}
fn checksum(bytes: &[u8; BYTES]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(&bytes[..PAYLOAD]);
    hash.finalize().into()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn app() -> AppId {
        AppId::new([7; 16]).unwrap()
    }
    fn seal(bytes: &mut [u8; BYTES]) {
        let sum = checksum(bytes);
        bytes[224..].copy_from_slice(&sum);
    }
    #[test]
    fn initial_is_not_a_receipt_and_replacement_keeps_namespace_and_epoch() {
        let initial = AppDataEnvelope::initial(app(), 1, 0).unwrap();
        assert_eq!(initial.counter(), 0);
        let next = initial.checked_replace(app(), 1, 0, u32::MAX).unwrap();
        assert_eq!(
            (
                next.app(),
                next.schema_epoch(),
                next.counter(),
                next.value()
            ),
            (app(), 1, 1, u32::MAX)
        );
        assert_eq!(AppDataEnvelope::decode(&next.encode()), Ok(next));
        assert_eq!(initial.value(), 0);
        assert_eq!(
            initial.checked_replace(AppId::new([8; 16]).unwrap(), 1, 0, 2),
            Err(Error::Identity)
        );
        assert_eq!(initial.checked_replace(app(), 2, 0, 2), Err(Error::Epoch));
        assert_eq!(initial.checked_replace(app(), 1, 1, 2), Err(Error::Stale));
    }
    #[test]
    fn every_byte_bit_corruption_length_and_canonical_reserved_field_refuses() {
        let encoded = AppDataEnvelope::initial(app(), 1, 42).unwrap().encode();
        for len in 0..BYTES {
            assert_eq!(AppDataEnvelope::decode(&encoded[..len]), Err(Error::Length));
        }
        assert_eq!(AppDataEnvelope::decode(&[0; BYTES + 1]), Err(Error::Length));
        for i in 0..BYTES {
            for bit in 0..8 {
                let mut b = encoded;
                b[i] ^= 1 << bit;
                assert!(AppDataEnvelope::decode(&b).is_err());
            }
        }
        for i in (12..16).chain(36..40).chain(52..224) {
            let mut b = encoded;
            b[i] = 1;
            seal(&mut b);
            assert_eq!(AppDataEnvelope::decode(&b), Err(Error::Reserved));
        }
    }
    #[test]
    fn resealed_invalid_identity_epoch_counter_and_version_fail_closed() {
        let encoded = AppDataEnvelope::initial(app(), 1, 42).unwrap().encode();
        let mut b = encoded;
        b[16..32].fill(0);
        seal(&mut b);
        assert_eq!(AppDataEnvelope::decode(&b), Err(Error::Identity));
        let mut b = encoded;
        b[32..36].fill(0);
        seal(&mut b);
        assert_eq!(AppDataEnvelope::decode(&b), Err(Error::Epoch));
        let mut b = encoded;
        b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        seal(&mut b);
        assert_eq!(AppDataEnvelope::decode(&b), Err(Error::Counter));
        let mut b = encoded;
        b[8..10].copy_from_slice(&2u16.to_le_bytes());
        seal(&mut b);
        assert_eq!(AppDataEnvelope::decode(&b), Err(Error::Format));
        assert_eq!(AppDataEnvelope::initial(app(), 0, 42), Err(Error::Epoch));
    }
    #[test]
    fn counter_never_wraps_and_all_u32_values_and_valid_epoch_boundaries_survive() {
        let mut b = AppDataEnvelope::initial(app(), u32::MAX, u32::MAX)
            .unwrap()
            .encode();
        b[40..48].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        seal(&mut b);
        let final_state = AppDataEnvelope::decode(&b).unwrap();
        assert_eq!(final_state.schema_epoch(), u32::MAX);
        assert_eq!(final_state.value(), u32::MAX);
        assert_eq!(
            final_state.checked_replace(app(), u32::MAX, u64::MAX - 1, 0),
            Err(Error::Counter)
        );
        assert_eq!(final_state.encode(), b);
    }
}
