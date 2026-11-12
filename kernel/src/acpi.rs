//! Allocation-free ACPI topology parser. Inputs are byte slices, never pointers.
pub const MAX_TABLE: usize = 65536;
pub const MAX_ROOT_ENTRIES: usize = 256;
pub const MAX_CPUS: usize = 64;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    Signature,
    Checksum,
    Address,
    Duplicate,
    Capacity,
    Missing,
    Reserved,
}
fn u32_at(data: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or(Error::Length)?
            .try_into()
            .map_err(|_| Error::Length)?,
    ))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8)
            .ok_or(Error::Length)?
            .try_into()
            .map_err(|_| Error::Length)?,
    ))
}
fn checksum(data: &[u8]) -> Result<(), Error> {
    if data.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0 {
        Ok(())
    } else {
        Err(Error::Checksum)
    }
}
fn address(value: u64) -> Result<u64, Error> {
    if value > 0 && value < 1 << 52 {
        Ok(value)
    } else {
        Err(Error::Address)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Root {
    pub address: u64,
    pub extended: bool,
}
pub fn rsdp(data: &[u8]) -> Result<Root, Error> {
    if data.len() < 20 {
        return Err(Error::Length);
    }
    if &data[..8] != b"RSD PTR " {
        return Err(Error::Signature);
    }
    checksum(&data[..20])?;
    if data[15] >= 2 {
        let length = u32_at(data, 20)? as usize;
        if !(36..=4096).contains(&length) || data.len() != length {
            return Err(Error::Length);
        }
        checksum(data)?;
        if data[33..36] != [0; 3] {
            return Err(Error::Reserved);
        }
        let xsdt = u64_at(data, 24)?;
        if xsdt != 0 {
            return Ok(Root {
                address: address(xsdt)?,
                extended: true,
            });
        }
    } else if data[15] != 0 || data.len() != 20 {
        return Err(Error::Length);
    }
    Ok(Root {
        address: address(u32_at(data, 16)? as u64)?,
        extended: false,
    })
}
pub fn table_length(header: &[u8]) -> Result<usize, Error> {
    if header.len() < 36 {
        return Err(Error::Length);
    }
    let length = u32_at(header, 4)? as usize;
    if !(36..=MAX_TABLE).contains(&length) {
        return Err(Error::Length);
    }
    Ok(length)
}
fn table<'a>(data: &'a [u8], signature: &[u8; 4]) -> Result<&'a [u8], Error> {
    if table_length(data)? != data.len() {
        return Err(Error::Length);
    }
    if &data[..4] != signature {
        return Err(Error::Signature);
    }
    checksum(data)?;
    Ok(data)
}
pub struct RootEntries {
    addresses: [u64; MAX_ROOT_ENTRIES],
    count: usize,
}
impl RootEntries {
    pub fn addresses(&self) -> &[u64] {
        &self.addresses[..self.count]
    }
}
pub fn root_entries(data: &[u8], extended: bool) -> Result<RootEntries, Error> {
    let data = table(data, if extended { b"XSDT" } else { b"RSDT" })?;
    let width = if extended { 8 } else { 4 };
    let size = data.len() - 36;
    if !size.is_multiple_of(width) {
        return Err(Error::Length);
    }
    let count = size / width;
    if count > MAX_ROOT_ENTRIES {
        return Err(Error::Capacity);
    }
    let mut result = RootEntries {
        addresses: [0; MAX_ROOT_ENTRIES],
        count,
    };
    for i in 0..count {
        let value = address(if extended {
            u64_at(data, 36 + i * width)?
        } else {
            u32_at(data, 36 + i * width)? as u64
        })?;
        if result.addresses[..i].contains(&value) {
            return Err(Error::Duplicate);
        }
        result.addresses[i] = value;
    }
    Ok(result)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cpu {
    pub apic_id: u32,
    pub uid: u32,
}
#[derive(Debug)]
pub struct Topology {
    pub lapic: u64,
    cpus: [Cpu; MAX_CPUS],
    count: usize,
}
impl Topology {
    pub fn cpus(&self) -> &[Cpu] {
        &self.cpus[..self.count]
    }
}
pub fn madt(data: &[u8]) -> Result<Topology, Error> {
    let data = table(data, b"APIC")?;
    if data.len() < 44 {
        return Err(Error::Length);
    }
    let mut result = Topology {
        lapic: u32_at(data, 36)? as u64,
        cpus: [Cpu { apic_id: 0, uid: 0 }; MAX_CPUS],
        count: 0,
    };
    let mut at = 44;
    let mut override_seen = false;
    while at < data.len() {
        let length = *data.get(at + 1).ok_or(Error::Length)? as usize;
        if length < 2 {
            return Err(Error::Length);
        }
        let entry = data.get(at..at + length).ok_or(Error::Length)?;
        let cpu = match entry[0] {
            0 => {
                if length != 8 {
                    return Err(Error::Length);
                }
                if u32_at(entry, 4)? & 1 != 0 {
                    Some(Cpu {
                        apic_id: entry[3] as u32,
                        uid: entry[2] as u32,
                    })
                } else {
                    None
                }
            }
            9 => {
                if length != 16 {
                    return Err(Error::Length);
                }
                if entry[2..4] != [0; 2] {
                    return Err(Error::Reserved);
                }
                if u32_at(entry, 8)? & 1 != 0 {
                    Some(Cpu {
                        apic_id: u32_at(entry, 4)?,
                        uid: u32_at(entry, 12)?,
                    })
                } else {
                    None
                }
            }
            5 => {
                if length != 12 {
                    return Err(Error::Length);
                }
                if entry[2..4] != [0; 2] {
                    return Err(Error::Reserved);
                }
                if override_seen {
                    return Err(Error::Duplicate);
                }
                override_seen = true;
                result.lapic = u64_at(entry, 4)?;
                None
            }
            _ => None,
        };
        if let Some(cpu) = cpu {
            if result
                .cpus()
                .iter()
                .any(|old| old.apic_id == cpu.apic_id || old.uid == cpu.uid)
            {
                return Err(Error::Duplicate);
            }
            if result.count == MAX_CPUS {
                return Err(Error::Capacity);
            }
            result.cpus[result.count] = cpu;
            result.count += 1;
        }
        at += length;
    }
    address(result.lapic)?;
    if !result.lapic.is_multiple_of(4096) {
        return Err(Error::Address);
    }
    if result.count == 0 {
        return Err(Error::Missing);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};
    fn fix(data: &mut [u8], index: usize) {
        data[index] = 0;
        data[index] = 0u8.wrapping_sub(data.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    }
    fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = vec![0; 36];
        v[..4].copy_from_slice(sig);
        v.extend_from_slice(body);
        let len = v.len() as u32;
        v[4..8].copy_from_slice(&len.to_le_bytes());
        fix(&mut v, 9);
        v
    }
    fn apic(records: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 8];
        b[..4].copy_from_slice(&0xfee00000u32.to_le_bytes());
        b.extend_from_slice(records);
        sdt(b"APIC", &b)
    }
    #[test]
    fn rsdp_checks_both_checksums_and_root_fallback() {
        let mut r = vec![0; 36];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[15] = 2;
        r[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        r[20..24].copy_from_slice(&36u32.to_le_bytes());
        r[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        fix(&mut r[..20], 8);
        fix(&mut r, 32);
        assert_eq!(
            rsdp(&r).unwrap(),
            Root {
                address: 0x2000,
                extended: true
            }
        );
        for n in 0..36 {
            assert!(rsdp(&r[..n]).is_err());
        }
        r[10] ^= 1;
        assert_eq!(rsdp(&r).unwrap_err(), Error::Checksum);
        r[10] ^= 1;
        r[24..32].fill(0);
        fix(&mut r, 32);
        assert_eq!(
            rsdp(&r).unwrap(),
            Root {
                address: 0x1000,
                extended: false
            }
        );
        r[15] = 0;
        fix(&mut r[..20], 8);
        assert!(rsdp(&r[..20]).is_ok());
    }
    #[test]
    fn roots_reject_bad_bounds_checksum_addresses_and_duplicates() {
        let table = sdt(b"XSDT", &0x1000u64.to_le_bytes());
        assert_eq!(root_entries(&table, true).unwrap().addresses(), &[0x1000]);
        assert!(root_entries(&sdt(b"XSDT", &[0; 7]), true).is_err());
        assert!(root_entries(&sdt(b"XSDT", &[0; 8]), true).is_err());
        let mut duplicate = 0x1000u64.to_le_bytes().to_vec();
        duplicate.extend_from_slice(&0x1000u64.to_le_bytes());
        assert!(matches!(
            root_entries(&sdt(b"XSDT", &duplicate), true),
            Err(Error::Duplicate)
        ));
        let mut bad = table.clone();
        bad[9] ^= 1;
        assert!(matches!(root_entries(&bad, true), Err(Error::Checksum)));
        let mut bad = table;
        bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(table_length(&bad).is_err());
    }
    #[test]
    fn madt_enumerates_enabled_cpus_and_validates_overrides() {
        let mut records = vec![0, 8, 0, 0, 1, 0, 0, 0, 0, 8, 1, 1, 0, 0, 0, 0, 9, 16, 0, 0];
        records.extend_from_slice(&256u32.to_le_bytes());
        records.extend_from_slice(&1u32.to_le_bytes());
        records.extend_from_slice(&2u32.to_le_bytes());
        records.extend_from_slice(&[5, 12, 0, 0]);
        records.extend_from_slice(&0xfee01000u64.to_le_bytes());
        let data = apic(&records);
        let parsed = madt(&data).unwrap();
        assert_eq!(
            parsed.cpus(),
            &[
                Cpu { apic_id: 0, uid: 0 },
                Cpu {
                    apic_id: 256,
                    uid: 2
                }
            ]
        );
        assert_eq!(parsed.lapic, 0xfee01000);
        for n in 0..data.len() {
            assert!(madt(&data[..n]).is_err());
        }
        records.extend_from_slice(&[0, 8, 0, 0, 1, 0, 0, 0]);
        assert!(matches!(madt(&apic(&records)), Err(Error::Duplicate)));
    }
    #[test]
    fn malformed_records_and_capacity_fail_without_unbounded_parsing() {
        for record in [
            &[0, 0][..],
            &[0, 1],
            &[0, 8, 0],
            &[9, 16, 0, 0],
            &[5, 12, 0, 0],
        ] {
            assert!(madt(&apic(record)).is_err());
        }
        let mut records = Vec::new();
        for i in 0..=MAX_CPUS {
            records.extend_from_slice(&[0, 8, i as u8, i as u8, 1, 0, 0, 0]);
        }
        assert!(matches!(madt(&apic(&records)), Err(Error::Capacity)));
        let mut records = vec![0, 8, 0, 0, 1, 0, 0, 0];
        let mut override_record = vec![5, 12, 0, 0];
        override_record.extend_from_slice(&0xfee00000u64.to_le_bytes());
        records.extend_from_slice(&override_record);
        records.extend_from_slice(&override_record);
        assert!(matches!(madt(&apic(&records)), Err(Error::Duplicate)));
    }
}
