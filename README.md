# Download Manager

> **Fork Notice**: This is a fork of [Joeljaison391/Downloads-Organizer](https://github.com/Joeljaison391/Downloads-Organizer) with the following enhancements:
> - **Custom rules via JSON** — Define your own organization rules with regex patterns
> - **Run-once mode** — Organizes existing files and exits by default (use `--daemon` for continuous monitoring)
> - **Platform-specific config** — Rules loaded from `~/.config/download-organizer/` (Linux), `~/Library/Application Support/` (macOS), or `%APPDATA%` (Windows)
> - **Organize on startup** — Existing files are organized when the program runs, not just new downloads

<p align="center">
  <img src="https://res.cloudinary.com/dxraggwp4/image/upload/v1735143608/DownloadOrganizer/pcholwjlzqhit0fn5yb0.png" alt="Logo" width="600" height="350">
</p>

## Overview
<p align="left">
  <img src="https://res.cloudinary.com/dxraggwp4/image/upload/v1735143605/DownloadOrganizer/dkcvtkacj4rqh6bhtbnq.png" alt="Banner" width="100">
</p>
A lightweight Rust-based file monitoring and organizing tool designed to automatically segregate files downloaded into appropriate folders based on their type. The program monitors the **Downloads** folder for file events and organizes files into categories like Images, Videos, Documents, Archives, Audio, and Others.

## Features
- **Custom Rules**: Define your own organization rules via JSON configuration with regex pattern matching.
- **Run-Once Mode**: By default, organizes existing files and exits. Use `--daemon` for continuous monitoring.
- **File Monitoring**: In daemon mode, monitors the Downloads folder for new files and organizes them based on file type.
- **Stability Check**: Waits for file stability before processing (e.g., for partially downloaded files).
- **File Categorization**: Automatically moves files into appropriate subfolders (e.g., Images, Videos, Documents).
- **Unused File Management**: Identifies unused files (30+ days old) and moves them to the `Unused` folder.
- **Weekly Reports**: Automatically generates a detailed weekly report summarizing the files in the Downloads folder.
- **Desktop Notifications**: Sends notifications for file organization and report generation.
- **Logging**: Logs errors and events for easy debugging.
- **Charts and Visuals**: Weekly reports include interactive charts (file type distribution, file sizes) for better visualization.

## Usage

```bash
# Organize existing files once and exit (default)
downloadManager

# Run in daemon mode (continuous monitoring)
downloadManager --daemon
downloadManager -d

# Show help
downloadManager --help
```

## Custom Rules Configuration

The rules format is compatible with [RegExp Download Organizer](https://chromewebstore.google.com/detail/regexp-download-organizer/oamembonjndgangicfphlckkdmagpjlg), a Chrome extension that organizes downloads automatically. This tool lets you run the same rules manually or as a background service, useful for organizing files from other sources or re-organizing existing downloads.

Create a `download_rules.json` file to define custom organization rules. The program searches for this file in the following locations (in priority order):

| Priority | Location | Notes |
|----------|----------|-------|
| 1 | Platform config dir | `~/.config/download-organizer/` (Linux), `~/Library/Application Support/download-organizer/` (macOS), `%APPDATA%\download-organizer\` (Windows) |
| 2 | Executable directory | Portable mode — place rules next to the binary |
| 3 | Downloads folder | Fallback location |

### Rules Format

```json
[
  {
    "description": "Linux installers (.deb, .rpm, .AppImage)",
    "enabled": true,
    "filename": ".*\\.(deb|rpm|AppImage|run)$",
    "mime": "application/(x-debian-package|x-rpm)",
    "pattern": "Organized/Installers/Linux/"
  },
  {
    "description": "PDF documents",
    "enabled": true,
    "filename": ".*\\.pdf$",
    "mime": "application/pdf",
    "pattern": "Organized/Documents/PDFs/"
  }
]
```

### Rule Properties

| Property | Description |
|----------|-------------|
| `description` | Human-readable description of the rule |
| `enabled` | Set to `false` to disable a rule without deleting it |
| `filename` | Regex pattern to match against filenames |
| `mime` | MIME type pattern (reserved for future use) |
| `pattern` | Target directory path (relative to Downloads folder) |

Rules are evaluated in order — the first matching rule wins. If no custom rule matches, the default categorization is used.

## Default File Types

If no custom rules are configured, files are organized into these categories:

1. **Images**: `.jpg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.svg`, `.webp`
2. **Videos**: `.mp4`, `.mkv`, `.avi`, `.mov`, `.flv`, `.wmv`, `.webm`, `.mpeg`
3. **Documents**: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.txt`, `.csv`
4. **Archives**: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`, `.xz`
5. **Others**: Any files not matching the above categories.

## Installation

### Requirements
- **Operating System**: Windows, Linux, or macOS
- **Rust**: [Install Rust](https://www.rust-lang.org/) (for building from source)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/talpah/Downloads-Organizer.git
   cd Downloads-Organizer
   ```
2. Build the project:
   ```bash
   cargo build --release
   ```
3. Run the executable:
   ```bash
   ./target/release/downloadManager
   ```

## Systemd Service (Linux)

To run as a user service in daemon mode:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/download-organizer.service << 'EOF'
[Unit]
Description=Downloads Organizer
After=default.target

[Service]
ExecStart=%h/Applications/Downloads-Organizer/target/release/downloadManager --daemon
Restart=on-failure

[Install]
WantedBy=default.target
EOF

systemctl --user enable download-organizer
systemctl --user start download-organizer
```

## Task Scheduler Setup (Windows)
1. Open Task Scheduler (`Win + R`, type `taskschd.msc`, and press Enter).
2. Create a new task and name it (e.g., **Download Manager**).
3. Set the trigger to **At system startup**.
4. In the Actions tab, select **Start a program** and browse to the executable path.
5. Add `--daemon` to the arguments field for continuous monitoring.
6. Save and test the task.

## Weekly Report

### Features:
- **Summary**: Total files and size in the Downloads folder, number and size of unused files.
- **Breakdown**: File type distribution (count and size), unused file statistics.
- **Visualizations**: Pie chart for file type distribution, bar chart for file sizes.

The report is saved as `Weekly_Report.html` in the Downloads directory.

## Logging

Error logs are saved in the home directory as `file_monitor_logs.txt`:
- **Linux/macOS**: `~/file_monitor_logs.txt`
- **Windows**: `C:\Users\<YourUsername>\file_monitor_logs.txt`

## Benchmark Testing

To test the program's performance:
```bash
cargo run --bin benchmark
```

### Benchmark Results
- **CPU Usage**: Peaks around ~0.77% during active monitoring.
- **Memory Usage**: Stable at ~13 MB during file monitoring.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
