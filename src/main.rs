mod report;

use notify::{Watcher, RecursiveMode, RecommendedWatcher, Config};
use std::io::Write;
use std::sync::mpsc::channel;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, Instant};
use notify_rust::Notification;
use chrono::{Local, Duration, Datelike};
use report::generate_html_report;
use serde::Deserialize;
use regex::Regex;

/// Represents a single rule from the JSON configuration
#[derive(Debug, Deserialize)]
struct Rule {
    description: String,
    enabled: bool,
    filename: String,
    #[serde(default)]
    mime: Option<String>,
    pattern: String,
}

/// A compiled rule with pre-compiled regex for performance
struct CompiledRule {
    description: String,
    regex: Regex,
    target_path: String,
}

/// Load and compile rules from the JSON configuration file
fn load_rules(rules_path: &Path) -> Vec<CompiledRule> {
    let mut compiled_rules = Vec::new();

    match fs::read_to_string(rules_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<Rule>>(&content) {
                Ok(rules) => {
                    for rule in rules {
                        if !rule.enabled {
                            continue;
                        }
                        match Regex::new(&rule.filename) {
                            Ok(regex) => {
                                compiled_rules.push(CompiledRule {
                                    description: rule.description,
                                    regex,
                                    target_path: rule.pattern,
                                });
                            }
                            Err(e) => {
                                eprintln!("Invalid regex in rule '{}': {}", rule.description, e);
                                log_error(&format!("Invalid regex in rule '{}': {}", rule.description, e));
                            }
                        }
                    }
                    println!("Loaded {} rules from {}", compiled_rules.len(), rules_path.display());
                    log_event(&format!("Loaded {} rules from {}", compiled_rules.len(), rules_path.display()));
                }
                Err(e) => {
                    eprintln!("Failed to parse rules JSON: {}", e);
                    log_error(&format!("Failed to parse rules JSON: {}", e));
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read rules file {}: {}", rules_path.display(), e);
            log_error(&format!("Failed to read rules file: {}", e));
        }
    }

    compiled_rules
}

/// Find matching rule for a filename, returns the target path
fn find_matching_rule<'a>(filename: &str, rules: &'a [CompiledRule]) -> Option<&'a str> {
    for rule in rules {
        if rule.regex.is_match(filename) {
            return Some(&rule.target_path);
        }
    }
    None
}

const RULES_FILENAME: &str = "download_rules.json";
const APP_NAME: &str = "download-organizer";

/// Organize all existing files in the downloads folder on startup
fn organize_existing_files(downloads_folder: &Path, rules: &[CompiledRule]) -> Result<usize, std::io::Error> {
    let mut count = 0;

    for entry in fs::read_dir(downloads_folder)? {
        let entry = entry?;
        let path = entry.path();

        // Skip directories and special files
        if !path.is_file() {
            continue;
        }

        // Skip temporary files
        if let Some(ext) = path.extension() {
            if ext == "tmp" || ext == "crdownload" || ext == "part" {
                continue;
            }
        }

        // Skip hidden files
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') {
                continue;
            }
        }

        let file_name = match path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => continue,
        };

        // Check if file matches any rule
        if let Some(target_dir) = find_matching_rule(&file_name, rules) {
            let target_path = downloads_folder.join(target_dir);
            fs::create_dir_all(&target_path)?;

            let new_path = target_path.join(&*file_name);

            // Don't move if already in the right place
            if new_path != path {
                fs::rename(&path, &new_path)?;
                println!("  Moved '{}' → {}", file_name, target_dir);
                log_event(&format!("Organized existing file '{}' to '{}'", file_name, target_dir));
                count += 1;
            }
        }
    }

    Ok(count)
}

/// Find the rules file in standard locations
/// Search order:
/// 1. Platform config directory (e.g., ~/.config/download-organizer/ on Linux)
/// 2. Executable's directory (for portable installs)
/// 3. Downloads folder (fallback)
fn find_rules_file(downloads_folder: &Path) -> Option<std::path::PathBuf> {
    let candidates: Vec<std::path::PathBuf> = vec![
        // 1. Platform config directory
        dirs::config_dir().map(|p| p.join(APP_NAME).join(RULES_FILENAME)),
        // 2. Executable's directory
        std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join(RULES_FILENAME))),
        // 3. Downloads folder (fallback)
        Some(downloads_folder.join(RULES_FILENAME)),
    ]
    .into_iter()
    .flatten()
    .collect();

    for path in candidates {
        if path.exists() {
            return Some(path);
        }
    }

    // Return the config dir path for helpful error message (where user should put the file)
    dirs::config_dir().map(|p| p.join(APP_NAME).join(RULES_FILENAME))
}

fn print_usage() {
    println!("Usage: downloadManager [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -d, --daemon    Run in daemon mode (continuous monitoring)");
    println!("  -h, --help      Show this help message");
    println!();
    println!("By default, organizes existing files once and exits.");
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let daemon_mode = args.iter().any(|a| a == "-d" || a == "--daemon");
    let show_help = args.iter().any(|a| a == "-h" || a == "--help");

    if show_help {
        print_usage();
        return Ok(());
    }

    let downloads_folder = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .expect("Failed to locate Downloads folder");
    let unused_folder = downloads_folder.join("Unused");
    let report_file = downloads_folder.join("Weekly_Report.html");
    let report_status_file = downloads_folder.join("report_status.txt");

    // Find and load custom rules from standard locations
    let rules = if let Some(rules_file) = find_rules_file(&downloads_folder) {
        println!("Looking for rules at: {}", rules_file.display());
        load_rules(&rules_file)
    } else {
        Vec::new()
    };

    if rules.is_empty() {
        println!("No custom rules loaded. Using default file organization.");
        println!("To use custom rules, place {} in one of:", RULES_FILENAME);
        if let Some(config_dir) = dirs::config_dir() {
            println!("  - {}", config_dir.join(APP_NAME).display());
        }
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                println!("  - {}", exe_dir.display());
            }
        }
        println!("  - {}", downloads_folder.display());
    }

    fs::create_dir_all(&unused_folder)?;

    // Generate initial report if it doesn't exist
    if !report_file.exists() {
        println!("Generating initial report...");
        generate_html_report(&downloads_folder, &report_file)?;
        println!("Initial report generated: {}", report_file.display());
    }

    // Generate weekly report if it's a new week
    if is_new_week(&report_status_file) {
        println!("Generating weekly report...");
        generate_html_report(&downloads_folder, &report_file)?;
        update_report_status(&report_status_file);
        println!("Weekly report generated: {}", report_file.display());
    }

    // Organize existing files
    if !rules.is_empty() {
        println!("Organizing existing files...");
        let organized = organize_existing_files(&downloads_folder, &rules)?;
        if organized > 0 {
            println!("Organized {} existing file(s).", organized);
        } else {
            println!("No files needed organizing.");
        }
    }

    // Exit here unless daemon mode is requested
    if !daemon_mode {
        println!("Done. Use --daemon to run in continuous monitoring mode.");
        return Ok(());
    }

    // Setup folder monitoring (daemon mode)
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).map_err(|e| {
        eprintln!("Error creating file watcher: {}", e);
        e
    })?;

    watcher.watch(&downloads_folder, RecursiveMode::Recursive).map_err(|e| {
        eprintln!("Error watching folder: {}", e);
        e
    })?;

    println!("Monitoring folder: {}", downloads_folder.display());

    let mut last_scan = Instant::now();

    for event in rx {
        let elapsed = last_scan.elapsed().as_secs();
        println!("Elapsed time since last scan: {} seconds", elapsed);

        match event {
            Ok(event) => {
                if let Some(path) = event.paths.first() {
                    if path.starts_with(&unused_folder) {
                        continue; // Skip unused folder events
                    }

                    if let Err(e) = handle_file_event(path, &downloads_folder, &rules) {
                        log_error(&e.to_string());
                        eprintln!("Error handling file: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("File watcher error: {}", e);
            }
        }

        if elapsed >= 60 {
            println!("Starting periodic scan for unused files...");
            log_event("Starting periodic scan for unused files...");
            if let Err(e) = handle_unused_files_recursively(&downloads_folder, &unused_folder, &rules) {
                log_error(&e.to_string());
                eprintln!("Error during periodic scan: {}", e);
            }
            println!("Periodic scan completed.");
            log_event("Periodic scan completed.");
            last_scan = Instant::now();
        }
    }

    Ok(())
}

fn is_new_week(report_status_file: &Path) -> bool {
    let today = Local::now().date_naive();
    let week_start = today - chrono::Duration::days(today.weekday().num_days_from_sunday() as i64);

    if report_status_file.exists() {
        let data = fs::read_to_string(report_status_file).unwrap_or_default();
        if let Ok(last_generated) = data.parse::<chrono::NaiveDate>() {
            return last_generated < week_start;
        }
    }

    true
}

fn update_report_status(report_status_file: &Path) {
    let today = Local::now().date_naive();
    fs::write(report_status_file, today.format("%Y-%m-%d").to_string()).unwrap();
}

fn handle_file_event(path: &Path, downloads_folder: &Path, rules: &[CompiledRule]) -> Result<(), std::io::Error> {
    if !path.is_file() {
        return Ok(()); // Skip directories or non-files
    }

    if let Some(extension) = path.extension() {
        if extension == "tmp" {
            println!("Ignoring temporary file: {}", path.display());
            return Ok(());
        }
    }

    println!("Detected file event: {}", path.display());
    log_event(&format!("Detected file event: {}", path.display()));

    let mut prev_size = 0;
    loop {
        match fs::metadata(path) {
            Ok(metadata) => {
                let current_size = metadata.len();
                if current_size == prev_size {
                    break;
                }
                prev_size = current_size;
                println!("Waiting for file stability: {}", path.display());
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    println!("File renamed or deleted: {}", path.display());
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        }
    }

    move_file_to_specific_folder(path, downloads_folder, rules)?;

    Ok(())
}

fn handle_unused_files_recursively(downloads_folder: &Path, unused_folder: &Path, rules: &[CompiledRule]) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(downloads_folder)? {
        let entry = entry?;
        let path = entry.path();

        if path == *unused_folder {
            continue;
        }

        if path.is_dir() {
            handle_unused_files_recursively(&path, unused_folder, rules)?;
        } else if path.is_file() {
            println!("Checking file for unused status: {}", path.display());
            log_event(&format!("Checking file for unused status: {}", path.display()));
            move_unused_files(&path, unused_folder, rules)?;
        }
    }
    Ok(())
}

fn move_file_to_specific_folder(path: &Path, downloads_folder: &Path, rules: &[CompiledRule]) -> Result<(), std::io::Error> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "Failed to get file name")
    })?;
    let file_name_str = file_name.to_string_lossy();

    // Try to match against custom rules first
    let target_dir: String = if let Some(rule_path) = find_matching_rule(&file_name_str, rules) {
        rule_path.to_string()
    } else {
        // Fall back to default categorization
        match path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => match ext.to_lowercase().as_str() {
                "jpg" | "png" | "gif" | "bmp" | "tiff" | "svg" | "webp" => "Images",
                "mp4" | "mkv" | "avi" | "mov" | "flv" | "wmv" | "webm" | "mpeg" => "Videos",
                "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "csv" => "Documents",
                "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" => "Archives",
                _ => "Others",
            },
            None => "Others",
        }.to_string()
    };

    let target_path = downloads_folder.join(&target_dir);
    fs::create_dir_all(&target_path)?;

    let new_path = target_path.join(file_name);

    if new_path != path {
        fs::rename(path, &new_path)?;
        println!("Moved '{}' to '{}'", path.display(), target_dir);
        log_event(&format!("Moved '{}' to '{}'", path.display(), target_dir));

        send_notification(&file_name_str, &target_dir)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    Ok(())
}

fn move_unused_files(path: &Path, unused_folder: &Path, rules: &[CompiledRule]) -> Result<(), std::io::Error> {
    let cutoff_time = SystemTime::now() - Duration::days(30).to_std().unwrap();

    if let Ok(metadata) = fs::metadata(&path) {
        if let Ok(modified) = metadata.modified() {
            if modified < cutoff_time {
                let file_name = path.file_name().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Failed to get file name")
                })?;
                let file_name_str = file_name.to_string_lossy();

                // Try to match against custom rules first
                let target_dir: String = if let Some(rule_path) = find_matching_rule(&file_name_str, rules) {
                    rule_path.to_string()
                } else {
                    // Fall back to default categorization
                    match path.extension().and_then(|ext| ext.to_str()) {
                        Some(ext) => match ext.to_lowercase().as_str() {
                            "jpg" | "png" | "gif" | "bmp" | "tiff" | "svg" | "webp" => "Images",
                            "mp4" | "mkv" | "avi" | "mov" | "flv" | "wmv" | "webm" | "mpeg" => "Videos",
                            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => "Documents",
                            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" => "Archives",
                            _ => "Others",
                        },
                        None => "Others",
                    }.to_string()
                };

                let target_path = unused_folder.join(&target_dir);
                fs::create_dir_all(&target_path)?;

                let new_path = target_path.join(file_name);

                fs::rename(path, &new_path)?;
                println!("Moved '{}' to 'Unused/{}'", path.display(), target_dir);
                log_event(&format!("Moved '{}' to 'Unused/{}'", path.display(), target_dir));

                send_notification(
                    &file_name_str,
                    &format!("Unused/{}", target_dir),
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            }
        }
    }

    Ok(())
}

fn log_error(message: &str) {
    if let Some(logs_dir) = dirs::home_dir().map(|dir| dir.join("file_monitor_logs.txt")) {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&logs_dir) {
            let _ = writeln!(
                file,
                "[{}] ERROR: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                message
            );
        }
    }
}

fn log_event(message: &str) {
    if let Some(logs_dir) = dirs::home_dir().map(|dir| dir.join("file_monitor_logs.txt")) {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&logs_dir) {
            let _ = writeln!(
                file,
                "[{}] EVENT: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                message
            );
        }
    }
}

fn send_notification(file_name: &str, target_dir: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Notification::new()
        .summary("File Moved")
        .body(&format!("'{}' has been moved to '{}'.", file_name, target_dir))
        .show()?;
    Ok(())
}
