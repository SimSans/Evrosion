//! Deterministic unsigned development media. All metadata is explicit; no byte patching.
use std::{
    fs::{File, OpenOptions},
    io::{self, Seek, SeekFrom},
    path::Path,
};

#[derive(Debug)]
struct Epoch;
impl fatfs::TimeProvider for Epoch {
    fn get_current_date(&self) -> fatfs::Date {
        fatfs::Date {
            year: 1980,
            month: 1,
            day: 1,
        }
    }
    fn get_current_date_time(&self) -> fatfs::DateTime {
        fatfs::DateTime {
            date: self.get_current_date(),
            time: fatfs::Time {
                hour: 0,
                min: 0,
                sec: 0,
                millis: 0,
            },
        }
    }
}

pub fn create(kernel: &Path, loader: &Path, output: &Path) -> io::Result<()> {
    const MIB: u64 = 1024 * 1024;
    let fat_path = output.with_extension("fat");
    let fat = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&fat_path)?;
    let size =
        (kernel.metadata()?.len() + loader.metadata()?.len() + 65536).div_ceil(MIB) * MIB + MIB;
    fat.set_len(size)?;
    fatfs::format_volume(
        &fat,
        fatfs::FormatVolumeOptions::new()
            .volume_id(0x45564d30)
            .volume_label(*b"EVROSION M0"),
    )?;
    let fs = fatfs::FileSystem::new(&fat, fatfs::FsOptions::new().time_provider(&Epoch))?;
    {
        let root = fs.root_dir();
        root.create_dir("EFI")?.create_dir("BOOT")?;
        io::copy(
            &mut File::open(loader)?,
            &mut root.create_file("EFI/BOOT/BOOTX64.EFI")?,
        )?;
        io::copy(
            &mut File::open(kernel)?,
            &mut root.create_file("kernel-x86_64")?,
        )?;
    }
    fs.unmount()?;
    let mut disk = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(output)?;
    let disk_size = size + 65536;
    disk.set_len(disk_size)?;
    gpt::mbr::ProtectiveMBR::with_lb_size(((disk_size / 512) - 1) as u32)
        .overwrite_lba0(&mut disk)?;
    let block = gpt::disk::LogicalBlockSize::Lb512;
    let mut table = gpt::GptConfig::new()
        .writable(true)
        .initialized(false)
        .logical_block_size(block)
        .create_from_device(
            Box::new(&mut disk),
            Some(uuid::Uuid::from_u128(0x4556524f53494f4e8000000000000001)),
        )?;
    table.update_partitions(Default::default())?;
    let id = table.add_partition("Evrosion boot", size, gpt::partition_types::EFI, 0, None)?;
    let mut partitions = table.partitions().clone();
    let partition = partitions
        .get_mut(&id)
        .ok_or_else(|| io::Error::other("missing EFI partition"))?;
    partition.part_guid = uuid::Uuid::from_u128(0x4556524f53494f4e8000000000000002);
    let offset = partition.bytes_start(block)?;
    table.update_partitions(partitions)?;
    table.write()?;
    disk.seek(SeekFrom::Start(offset))?;
    io::copy(&mut File::open(&fat_path)?, &mut disk)?;
    disk.sync_all()?;
    std::fs::remove_file(fat_path)?;
    Ok(())
}
