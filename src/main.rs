use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use sudo;

#[derive(Parser, Debug)]
#[command(version, about = "A simple ISO writer utility")]
struct Args {
    /// Path to the ISO image
    iso_path: PathBuf,

    /// Device path to write to (e.g. /dev/sdb)
    device_path: PathBuf,

    /// Verify write with SHA-256 checksum (format: "sha256:abcdef...")
    #[arg(short, long)]
    checksum: Option<String>,

    #[arg(long, conflicts_with("checksum"))]
    compute_checksum: bool,

    /// Disable confirmation prompt (DANGEROUS)
    #[arg(short, long)]
    force: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate paths
    if !args.iso_path.exists() {
        anyhow::bail!("ISO file not found");
    }
    if !args.device_path.exists() {
        anyhow::bail!("Device not found");
    }

    // Elevate privileges for device access
    if let Err(e) = sudo::escalate_if_needed() {
        anyhow::bail!("Failed to escalate privileges: {}", e);
    }

    // Confirm with user
    if !args.force {
        println!("WARNING: This will DESTROY ALL DATA on {}", 
            args.device_path.display());
        print!("Are you sure you want to continue? (y/N): ");
        std::io::stdout().flush()?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Aborted");
            return Ok(());
        }
    }

    // Get ISO metadata
    let iso_metadata = std::fs::metadata(&args.iso_path)?;
    let total_size = iso_metadata.len();

    // Open ISO file
    let mut iso_file = File::open(&args.iso_path)
        .context("Failed to open ISO file")?;

    // Open device
    let mut device = File::create(&args.device_path)
        .context("Failed to open device")?;

    // Write ISO to device
    let pb = setup_progress_bar(total_size, "Writing");
    copy_with_progress(&mut iso_file, &mut device, &pb)
        .context("Failed to write image")?;

    pb.set_message("Flushing");
    device.sync_all().context("Failed to sync device")?;
    pb.finish_with_message("Flushing completed");

     // Checksum verification
    if let Some(checksum) = &args.checksum {
        verify(checksum, &args.device_path, total_size)?;
    }
    else if args.compute_checksum {
        verify_computed(&args.iso_path, &args.device_path, total_size)?;
    }

    println!("\nSuccessfully wrote {} to {}",
        args.iso_path.display(),
        args.device_path.display());

    Ok(())
}

fn copy_with_progress(
    source: &mut File,
    dest: &mut File,
    pb: &ProgressBar,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
    let mut written: u64 = 0;
    loop {
        let bytes_read = source.read(&mut buffer)
            .context("Failed to read from source")?;

        if bytes_read == 0 {
            break;
        }

        dest.write_all(&buffer[..bytes_read])
            .context("Failed to write to destination")?;

        written += bytes_read as u64;
        pb.inc(bytes_read as u64);

        // Sync data every 10MB
        if written >= 10 * 1024 * 1024 {
            dest.sync_data().context("Failed to sync data")?;
            written = 0;
        }
    }
    Ok(())
}

fn verify_computed(src: &PathBuf, dest: &PathBuf, total_size: u64) -> Result<()> {
    // Calculate checksums
    // Source checksum
    let pb = setup_progress_bar(total_size, "Calculating source checksum");
    let checksum_src = calculate_device_sha256(src, total_size, &pb).context("Failed to calculate src checksum")?;
    pb.finish_with_message(format!("Source checksum: {}", &checksum_src));

    // Destination checksum
    let pb = setup_progress_bar(total_size, "Calculating dest checksum");
    let checksum_dest = calculate_device_sha256(dest, total_size, &pb).context("Failed to calculate dest checksum")?;
    pb.finish_with_message(format!("Dest checksum: {}", &checksum_dest));

    // Compare checksums
    if checksum_dest != checksum_src {
        anyhow::bail!(
            "Checksum mismatch!\nExpected: {}\nActual:   {}",
            checksum_src,
            checksum_dest
        );
    }
    pb.finish_with_message("Verification successful");

    Ok(())
    
}

fn verify(checksum: &str, path: &PathBuf, total_size: u64) -> Result<()> {
    let (algo, expected) = parse_checksum(checksum)
        .context("Invalid checksum format")?;

    if algo != "sha256" {
        anyhow::bail!("Unsupported checksum algorithm: {}", algo);
    }

    let pb = setup_progress_bar(total_size, "Verifying");
    let actual = calculate_device_sha256(path, total_size, &pb)
        .context("Verification failed")?;

    if actual != expected {
        anyhow::bail!(
            "Checksum mismatch!\nExpected: {}\nActual:   {}",
            expected,
            actual
        );
    }
    pb.finish_with_message("Verification successful");

    Ok(())
}

fn parse_checksum(input: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = input.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Checksum must be in format 'algorithm:hash'");
    }
    Ok((parts[0].to_lowercase(), parts[1].to_lowercase()))
}

fn calculate_device_sha256(
    path: &PathBuf,
    length: u64,
    pb: &ProgressBar,
) -> Result<String> {
    let mut device = File::open(path)
        .context(format!("Failed to open file or device for verification: {:?}", path.to_str()))?;
    
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
    let mut bytes_remaining = length;

    while bytes_remaining > 0 {
        let read_size = buffer.len().min(bytes_remaining as usize);
        let bytes_read = device.read(&mut buffer[..read_size])
            .context("Failed to read from device during verification")?;
        
        hasher.update(&buffer[..bytes_read]);
        pb.inc(bytes_read as u64);
        bytes_remaining -= bytes_read as u64;
    }

    Ok(hex::encode(hasher.finalize()))
}

fn setup_progress_bar(total: u64, prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("{{spinner:.green}} {} [{{wide_bar:.cyan/blue}}] {{bytes}}/{{total_bytes}} ({{eta}})", prefix))
        .expect("Invalid progress template")
        .progress_chars("#>-"));
    pb
}
