//! Canonical session-note data, distinct from the scalar v1 envelope. This is
//! metadata preparation/validation, never authority or a durable-write receipt.
//! The actual owner selects the namespace from authenticated App identity and
//! commits/readbacks through its own Store. Checksums detect corruption, not
//! malicious substitution. No package/build ID, handle, session or sector is stored.
use ev_zion::AppId;
use sha2::{Digest as _, Sha256};

pub const BYTES: usize = 256;
pub const VERSION: u16 = 2;
pub const SCHEMA_EPOCH: u32 = 2;
pub const MAX_NOTE_BYTES: usize = 128;
/// Stable creation-format identity, independent of the current Root startup ABI,
/// executable, package or build. This describes data interpretation only.
pub const FORMAT_ABI_DESCRIPTION: &[u8] = b"Evrosion session note format2; Store mutable object1; envelope256 EVADATA2; LE version16=2 extent16=256; zero12..16; AppId16@16; schema32=2@32; length16@36 zero38..40; revision64@40 noMAX; printableASCII32..126 max128@48 zero-pad; zero176..224; SHA256(domain evrosion.session-note-envelope.v2 NUL + bytes0..224)@224; empty revision0; exact expected-previous CAS; creation metadata only, no authority or health";
/// SHA256 of the exact format descriptor; never a permission or health claim.
pub const FORMAT_ABI: [u8; 32] = [
    0xdf, 0x17, 0x06, 0x63, 0xa5, 0x95, 0x2f, 0x31, 0x56, 0x2e, 0x41, 0xf5, 0xc0, 0x0f, 0x81, 0x07,
    0xe0, 0x72, 0x83, 0x4c, 0x6e, 0xcd, 0xfc, 0xfb, 0x7e, 0xa3, 0x99, 0xe6, 0xa7, 0xa1, 0x54, 0x56,
];
const MAGIC: &[u8; 8] = b"EVADATA2";
const DOMAIN: &[u8] = b"evrosion.session-note-envelope.v2\0";
const BODY_BYTES: usize = 224;
const TEXT_START: usize = 48;
const TEXT_END: usize = TEXT_START + MAX_NOTE_BYTES;
const _: () = assert!(BYTES == ev_store::PAYLOAD_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Format,
    Reserved,
    Integrity,
    Identity,
    Schema,
    Counter,
    Stale,
    NoteLength,
    NoteCharacter,
}

/// Plain immutable data. The counter is the note's logical revision, separate
/// from Store operation IDs and sequences. Revision0 is initial preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteDataEnvelope {
    app: AppId,
    counter: u64,
    length: u16,
    note: [u8; MAX_NOTE_BYTES],
}

fn text(note: &str) -> Result<(u16, [u8; MAX_NOTE_BYTES]), Error> {
    if note.len() > MAX_NOTE_BYTES {
        return Err(Error::NoteLength);
    }
    // The current renderer/input supports this printable UTF-8 subset. No
    // control, escape, DEL, embedded NUL or unrenderable multibyte character.
    if !note.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(Error::NoteCharacter);
    }
    let mut bytes = [0; MAX_NOTE_BYTES];
    bytes[..note.len()].copy_from_slice(note.as_bytes());
    Ok((note.len() as u16, bytes))
}

impl NoteDataEnvelope {
    /// Only for an explicitly new blank note namespace. This neither converts
    /// scalar v1 data nor initializes/publishes any actual Store by itself.
    pub fn initial(app: AppId, note: &str) -> Result<Self, Error> {
        let (length, note) = text(note)?;
        Ok(Self {
            app,
            counter: 0,
            length,
            note,
        })
    }
    pub const fn app(&self) -> AppId {
        self.app
    }
    pub const fn schema_epoch(&self) -> u32 {
        SCHEMA_EPOCH
    }
    pub const fn counter(&self) -> u64 {
        self.counter
    }
    pub fn note(&self) -> &str {
        core::str::from_utf8(&self.note[..usize::from(self.length)])
            .expect("validated printable ASCII")
    }
    /// Pure CAS preparation. A client may submit this proposed next envelope;
    /// Root must independently reopen current data, use the trusted AppId and
    /// expected previous counter, and require exact proposal equality before
    /// durable publication/readback. A client checksum selects no namespace.
    pub fn checked_replace(
        &self,
        expected_app: AppId,
        expected_counter: u64,
        note: &str,
    ) -> Result<Self, Error> {
        if expected_app != self.app {
            return Err(Error::Identity);
        }
        if expected_counter != self.counter {
            return Err(Error::Stale);
        }
        let counter = self
            .counter
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Counter)?;
        let (length, note) = text(note)?;
        Ok(Self {
            app: self.app,
            counter,
            length,
            note,
        })
    }
    /// Write requests carry a proposed next envelope. Revision0 cannot be a
    /// replacement; the actual server validates this CAS base against fresh data.
    pub fn expected_previous_counter(&self) -> Result<u64, Error> {
        self.counter.checked_sub(1).ok_or(Error::Counter)
    }
    pub fn encode(&self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(BYTES as u16).to_le_bytes());
        bytes[16..32].copy_from_slice(&self.app.bytes());
        bytes[32..36].copy_from_slice(&SCHEMA_EPOCH.to_le_bytes());
        bytes[36..38].copy_from_slice(&self.length.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.counter.to_le_bytes());
        bytes[TEXT_START..TEXT_END].copy_from_slice(&self.note);
        let digest = checksum(&bytes);
        bytes[BODY_BYTES..].copy_from_slice(&digest);
        bytes
    }
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; BYTES] = input.try_into().map_err(|_| Error::Length)?;
        if &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_le_bytes()
            || bytes[10..12] != (BYTES as u16).to_le_bytes()
        {
            return Err(Error::Format);
        }
        if bytes[BODY_BYTES..] != checksum(bytes) {
            return Err(Error::Integrity);
        }
        if bytes[12..16]
            .iter()
            .chain(&bytes[38..40])
            .chain(&bytes[TEXT_END..BODY_BYTES])
            .any(|byte| *byte != 0)
        {
            return Err(Error::Reserved);
        }
        let app = AppId::new(bytes[16..32].try_into().unwrap()).ok_or(Error::Identity)?;
        if bytes[32..36] != SCHEMA_EPOCH.to_le_bytes() {
            return Err(Error::Schema);
        }
        let counter = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        if counter == u64::MAX {
            return Err(Error::Counter);
        }
        let length = u16::from_le_bytes(bytes[36..38].try_into().unwrap());
        if usize::from(length) > MAX_NOTE_BYTES {
            return Err(Error::NoteLength);
        }
        let note: [u8; MAX_NOTE_BYTES] = bytes[TEXT_START..TEXT_END].try_into().unwrap();
        if !note[..usize::from(length)]
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
        {
            return Err(Error::NoteCharacter);
        }
        if note[usize::from(length)..].iter().any(|byte| *byte != 0) {
            return Err(Error::Reserved);
        }
        Ok(Self {
            app,
            counter,
            length,
            note,
        })
    }
}
fn checksum(bytes: &[u8; BYTES]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(&bytes[..BODY_BYTES]);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app() -> AppId {
        AppId::new([0x35; 16]).unwrap()
    }
    fn seal(bytes: &mut [u8; BYTES]) {
        let sum = checksum(bytes);
        bytes[BODY_BYTES..].copy_from_slice(&sum);
    }
    #[test]
    fn stable_format_abi_has_an_independent_golden_digest() {
        // Golden obtained independently with Python hashlib, rather than the
        // envelope checksum helper or current Root startup ABI.
        let expected = [
            0xdf, 0x17, 0x06, 0x63, 0xa5, 0x95, 0x2f, 0x31, 0x56, 0x2e, 0x41, 0xf5, 0xc0, 0x0f,
            0x81, 0x07, 0xe0, 0x72, 0x83, 0x4c, 0x6e, 0xcd, 0xfc, 0xfb, 0x7e, 0xa3, 0x99, 0xe6,
            0xa7, 0xa1, 0x54, 0x56,
        ];
        let actual: [u8; 32] = Sha256::digest(FORMAT_ABI_DESCRIPTION).into();
        assert_eq!(actual, expected);
        assert_eq!(FORMAT_ABI, expected);
    }
    #[test]
    fn empty_and_exact_maximum_ascii_roundtrip_and_checked_cas_keep_identity_schema() {
        let initial = NoteDataEnvelope::initial(app(), "").unwrap();
        assert_eq!(initial.counter(), 0);
        assert_eq!(initial.note(), "");
        assert_eq!(initial.expected_previous_counter(), Err(Error::Counter));
        let maximum = core::str::from_utf8(&[b'~'; MAX_NOTE_BYTES]).unwrap();
        let next = initial.checked_replace(app(), 0, maximum).unwrap();
        assert_eq!(next.counter(), 1);
        assert_eq!(next.expected_previous_counter(), Ok(0));
        assert_eq!(next.schema_epoch(), 2);
        assert_eq!(next.app(), app());
        assert_eq!(next.note(), maximum);
        assert_eq!(NoteDataEnvelope::decode(&next.encode()), Ok(next));
        assert_eq!(initial.note(), "");
        assert_eq!(
            initial.checked_replace(AppId::new([1; 16]).unwrap(), 0, "note"),
            Err(Error::Identity)
        );
        assert_eq!(initial.checked_replace(app(), 1, "note"), Err(Error::Stale));
    }
    #[test]
    fn scalar_v1_is_never_reinterpreted_as_note_data() {
        let scalar = crate::app_data::AppDataEnvelope::initial(app(), 1, 1001)
            .unwrap()
            .encode();
        assert_eq!(NoteDataEnvelope::decode(&scalar), Err(Error::Format));
        let note = NoteDataEnvelope::initial(app(), "1001").unwrap().encode();
        assert_eq!(
            crate::app_data::AppDataEnvelope::decode(&note),
            Err(crate::app_data::Error::Format)
        );
    }
    #[test]
    fn control_del_non_ascii_and_overlength_text_cannot_enter_the_envelope() {
        for note in [
            "\0",
            "line\nfeed",
            "\r",
            "\t",
            "\u{1b}",
            "\u{7f}",
            "é",
            "🦀",
        ] {
            assert_eq!(
                NoteDataEnvelope::initial(app(), note),
                Err(Error::NoteCharacter)
            );
        }
        let too_long = core::str::from_utf8(&[b' '; MAX_NOTE_BYTES + 1]).unwrap();
        assert_eq!(
            NoteDataEnvelope::initial(app(), too_long),
            Err(Error::NoteLength)
        );
    }
    #[test]
    fn every_byte_bit_corruption_and_wrong_extent_refuses() {
        let encoded = NoteDataEnvelope::initial(app(), "actual note")
            .unwrap()
            .encode();
        for len in 0..BYTES {
            assert_eq!(
                NoteDataEnvelope::decode(&encoded[..len]),
                Err(Error::Length)
            );
        }
        assert_eq!(
            NoteDataEnvelope::decode(&[0; BYTES + 1]),
            Err(Error::Length)
        );
        for i in 0..BYTES {
            for bit in 0..8 {
                let mut bytes = encoded;
                bytes[i] ^= 1 << bit;
                assert!(NoteDataEnvelope::decode(&bytes).is_err());
            }
        }
    }
    #[test]
    fn resealing_does_not_authorize_noncanonical_fields_or_future_schemas() {
        let encoded = NoteDataEnvelope::initial(app(), "note").unwrap().encode();
        for index in (12..16).chain(38..40).chain(TEXT_START + 4..BODY_BYTES) {
            let mut bytes = encoded;
            bytes[index] = 1;
            seal(&mut bytes);
            assert_eq!(NoteDataEnvelope::decode(&bytes), Err(Error::Reserved));
        }
        for (range, value, error) in [(16..32, 0, Error::Identity), (32..36, 0, Error::Schema)] {
            let mut bytes = encoded;
            bytes[range].fill(value);
            seal(&mut bytes);
            assert_eq!(NoteDataEnvelope::decode(&bytes), Err(error));
        }
        let mut bytes = encoded;
        bytes[36..38].copy_from_slice(&129u16.to_le_bytes());
        seal(&mut bytes);
        assert_eq!(NoteDataEnvelope::decode(&bytes), Err(Error::NoteLength));
        let mut bytes = encoded;
        bytes[TEXT_START] = 0xff;
        seal(&mut bytes);
        assert_eq!(NoteDataEnvelope::decode(&bytes), Err(Error::NoteCharacter));
    }
    #[test]
    fn revision_exhaustion_never_wraps_or_mutates_retained_note() {
        let mut bytes = NoteDataEnvelope::initial(app(), "last valid")
            .unwrap()
            .encode();
        bytes[40..48].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        seal(&mut bytes);
        let final_note = NoteDataEnvelope::decode(&bytes).unwrap();
        assert_eq!(
            final_note.checked_replace(app(), u64::MAX - 1, "replacement"),
            Err(Error::Counter)
        );
        assert_eq!(final_note.encode(), bytes);
        assert_eq!(final_note.note(), "last valid");
        bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        seal(&mut bytes);
        assert_eq!(NoteDataEnvelope::decode(&bytes), Err(Error::Counter));
    }
}
