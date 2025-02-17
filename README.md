# retcher

A simple ISO writer utility.

## Introduction

Retcher is a command-line utility that allows you to write ISO images to block devices, such as USB drives or hard drives. It provides a simple and efficient way to create bootable media from ISO files.

## Features

*   Writes ISO images to block devices
*   Verifies write integrity with SHA-256 checksums
*   Supports disabling the confirmation prompt for automated usage
*   Displays a progress bar during the writing process
*   Handles privilege escalation with sudo when needed

## Usage

```
retcher <iso_path> <device_path> [options]
```

*   `<iso_path>`: Path to the ISO image file.
*   `<device_path>`: Path to the block device (e.g., /dev/sdb).

### Options

*   `-c, --checksum <checksum>`: Verify write with SHA-256 checksum (format: "sha256:abcdef...")
*   `--compute-checksum`: Compute checksum of source and destination and verify
*   `-f, --force`: Disable confirmation prompt (DANGEROUS)

## License

This project is licensed under the MIT License. See the LICENSE file for details.
