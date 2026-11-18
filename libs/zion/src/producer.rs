//! Deterministic host-only fixture producer. It performs no installation,
//! network access, script execution, permission grant or publisher verification.
use crate::*;
use std::vec::Vec;

pub struct Spec<'a> {
    pub app: AppId,
    pub name: &'a str,
    pub source: &'a str,
    pub publisher: Option<[u8; 16]>,
    pub version: Version,
    pub build_id: [u8; 32],
    pub platform: Platform,
    pub abi: [u8; 32],
    pub data_schema: DataSchema,
    pub entrypoint: &'a str,
    pub contracts: &'a [Contract<'a>],
    pub capabilities: &'a [CapabilityRequest],
}
pub struct Resource<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

/// Resource order is canonical path order, strictly after the entrypoint.
/// Reject rather than normalize traversal, duplicate or ambiguous paths.
pub fn build(spec: &Spec<'_>, executable: &[u8], resources: &[Resource<'_>]) -> Result<Vec<u8>> {
    if resources.len() >= MAX_ENTRIES
        || spec.contracts.len() > MAX_REQUIREMENTS
        || spec.capabilities.len() > MAX_REQUIREMENTS
    {
        return Err(Error::Bounds);
    }
    let mut manifest = Vec::new();
    tlv(&mut manifest, 1, REQUIRED, &spec.app.bytes())?;
    tlv(&mut manifest, 2, REQUIRED, spec.name.as_bytes())?;
    tlv(&mut manifest, 3, REQUIRED, spec.source.as_bytes())?;
    if let Some(publisher) = spec.publisher {
        tlv(&mut manifest, 4, 0, &publisher)?;
    }
    let mut version = [0; 12];
    version[..4].copy_from_slice(&spec.version.major.to_le_bytes());
    version[4..8].copy_from_slice(&spec.version.minor.to_le_bytes());
    version[8..].copy_from_slice(&spec.version.patch.to_le_bytes());
    tlv(&mut manifest, 5, REQUIRED, &version)?;
    tlv(&mut manifest, 6, REQUIRED, &spec.build_id)?;
    let mut platform = [0; 8];
    platform[..4].copy_from_slice(&spec.platform.minimum.to_le_bytes());
    platform[4..].copy_from_slice(&spec.platform.target.to_le_bytes());
    tlv(&mut manifest, 7, REQUIRED, &platform)?;
    tlv(&mut manifest, 8, REQUIRED, &[1, 0, 0, 0])?;
    tlv(&mut manifest, 9, REQUIRED, &spec.abi)?;
    let mut schema = [0; 8];
    schema[..4].copy_from_slice(&spec.data_schema.current.to_le_bytes());
    schema[4..].copy_from_slice(&spec.data_schema.oldest_readable.to_le_bytes());
    tlv(&mut manifest, 10, REQUIRED, &schema)?;
    tlv(&mut manifest, 11, REQUIRED, spec.entrypoint.as_bytes())?;
    let mut contracts = std::vec![0; 8 + 64 * spec.contracts.len()];
    contracts[..2].copy_from_slice(&(spec.contracts.len() as u16).to_le_bytes());
    for (row, value) in contracts[8..]
        .as_chunks_mut::<64>()
        .0
        .iter_mut()
        .zip(spec.contracts)
    {
        if value.name.len() > 48 {
            return Err(Error::Field);
        }
        row[0] = value.name.len() as u8;
        row[1] = 1;
        row[2..4].copy_from_slice(&value.major.to_le_bytes());
        row[4..6].copy_from_slice(&value.minimum_minor.to_le_bytes());
        row[8..16].copy_from_slice(&value.features.to_le_bytes());
        row[16..16 + value.name.len()].copy_from_slice(value.name.as_bytes());
    }
    tlv(&mut manifest, 12, REQUIRED, &contracts)?;
    let mut capabilities = std::vec![0; 8 + 8 * spec.capabilities.len()];
    capabilities[..2].copy_from_slice(&(spec.capabilities.len() as u16).to_le_bytes());
    for (row, value) in capabilities[8..]
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(spec.capabilities)
    {
        let code = match value.capability {
            Capability::SelectedFileRead => 1,
            Capability::AppPrivateData => 2,
            Capability::OwnSurfacePresent => 3,
            Capability::FocusedInput => 4,
            Capability::Diagnostics => 5,
            Capability::SelectedFileEdit => 6,
            Capability::UnknownOptional(n) => n,
        };
        row[..2].copy_from_slice(&code.to_le_bytes());
        row[2..4].copy_from_slice(&u16::from(value.required).to_le_bytes());
    }
    tlv(&mut manifest, 13, REQUIRED, &capabilities)?;
    let count = resources.len() + 1;
    let table_len = count.checked_mul(ENTRY).ok_or(Error::Overflow)?;
    let mut cursor = HEADER
        .checked_add(manifest.len())
        .and_then(|n| n.checked_add(table_len))
        .ok_or(Error::Overflow)?;
    let mut table = std::vec![0; table_len];
    for (index, row) in table.as_chunks_mut::<ENTRY>().0.iter_mut().enumerate() {
        let (kind, path, body) = if index == 0 {
            (1, spec.entrypoint, executable)
        } else {
            (2, resources[index - 1].path, resources[index - 1].bytes)
        };
        if path.len() > 64 || body.len() > MAX_BYTES {
            return Err(Error::Bounds);
        }
        row[0] = kind;
        row[2..4].copy_from_slice(&(path.len() as u16).to_le_bytes());
        row[4..8].copy_from_slice(
            &u32::try_from(cursor)
                .map_err(|_| Error::Overflow)?
                .to_le_bytes(),
        );
        row[8..12].copy_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| Error::Overflow)?
                .to_le_bytes(),
        );
        row[16..48].copy_from_slice(&sha(body));
        row[48..48 + path.len()].copy_from_slice(path.as_bytes());
        cursor = cursor.checked_add(body.len()).ok_or(Error::Overflow)?;
    }
    if cursor > MAX_BYTES {
        return Err(Error::Bounds);
    }
    let mut output = std::vec![0; HEADER];
    output[..8].copy_from_slice(b"EVZION01");
    output[8..10].copy_from_slice(&1_u16.to_le_bytes());
    output[12..14].copy_from_slice(&(HEADER as u16).to_le_bytes());
    output[16..20].copy_from_slice(&(cursor as u32).to_le_bytes());
    output[20..24].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    output[24..26].copy_from_slice(&(count as u16).to_le_bytes());
    output[26..28].copy_from_slice(&1_u16.to_le_bytes());
    output[32..64].copy_from_slice(&sha(&manifest));
    output[64..96].copy_from_slice(&sha(&table));
    output.extend_from_slice(&manifest);
    output.extend_from_slice(&table);
    output.extend_from_slice(executable);
    for resource in resources {
        output.extend_from_slice(resource.bytes);
    }
    Package::parse(&output)?;
    Ok(output)
}

fn tlv(out: &mut Vec<u8>, tag: u16, flags: u16, value: &[u8]) -> Result<()> {
    let end = out
        .len()
        .checked_add(8)
        .and_then(|n| n.checked_add(value.len()))
        .ok_or(Error::Overflow)?;
    if end > MAX_MANIFEST {
        return Err(Error::Bounds);
    }
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}
