use std::{path::PathBuf, process::ExitCode};
mod disk;

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 3 {
        eprintln!("Usage: ev-image-builder KERNEL_ELF OUTPUT_IMAGE LOADER_EVIDENCE_DIRECTORY");
        return ExitCode::from(2);
    }
    let kernel = PathBuf::from(&arguments[0]);
    let image = PathBuf::from(&arguments[1]);
    if !kernel.is_file() {
        eprintln!("Kernel ELF does not exist: {}", kernel.display());
        return ExitCode::FAILURE;
    }
    let loader_evidence = PathBuf::from(&arguments[2]);
    let builder = bootloader::UefiBoot::new(&kernel);
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        builder.create_pxe_tftp_folder(&loader_evidence)?;
        disk::create(&kernel, &loader_evidence.join("bootloader"), &image)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!("UEFI image: {}", image.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("UEFI image creation failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}
