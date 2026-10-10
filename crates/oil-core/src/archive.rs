//! # In-Memory ZIP Archive Scanner & Bomb Mitigation
//!
//! GDD §4 & §6 — Stream-based in-memory archive extraction and inspection.
//! Prevents disk quarantine, applies strict anti-bomb thresholds,
//! and recursively audits nested binaries.

use crate::io::dual_hash;
use crate::ioc::scan_iocs;
use crate::models::{FileIdentity, PeAutopsy, ScanReport, Tier};
use crate::pe::analyze_pe;
use crate::risk::evaluate_risk;
use std::io::{Cursor, Read};
use std::path::Path;
use thiserror::Error;
use zip::ZipArchive;

/// Maximum number of files permitted in a single archive scan.
pub const MAX_ARCHIVE_FILES: usize = 1_000;

/// Maximum cumulative uncompressed byte size allowed (512 MB).
pub const MAX_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum single-file compression ratio (e.g. 1000:1).
pub const MAX_COMPRESSION_RATIO: f64 = 1_000.0;

/// Maximum nested archive depth.
pub const MAX_NESTING_DEPTH: u32 = 3;

#[derive(Error, Debug)]
pub enum ArchiveError {
    #[error("Corrupted or malformed ZIP format: {0}")]
    MalformedZip(String),
    #[error("Archive is encrypted with password")]
    EncryptedArchive,
    #[error("Archive bomb threshold exceeded: {0}")]
    BombThresholdExceeded(String),
}

/// Maximum single-file uncompressed size permitted (128 MB).
pub const MAX_SINGLE_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Tracking struct for cumulative decompression budget across nested archives.
pub struct ArchiveBudget {
    pub remaining_bytes: u64,
}

impl Default for ArchiveBudget {
    fn default() -> Self {
        Self {
            remaining_bytes: MAX_UNCOMPRESSED_BYTES,
        }
    }
}

/// Fast magic bytes check to determine if data is a ZIP archive.
pub fn is_zip_archive(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    // Standard ZIP local file header: PK\x03\x04
    // Empty archive header: PK\x05\x06
    // Spanned archive header: PK\x07\x08
    &data[0..4] == b"PK\x03\x04" || &data[0..4] == b"PK\x05\x06" || &data[0..4] == b"PK\x07\x08"
}

/// Checks whether a file name or extension suggests an executable / script / binary payload.
fn is_executable_or_script(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".sys")
        || lower.ends_with(".scr")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".ps1")
        || lower.ends_with(".vbs")
        || lower.ends_with(".js")
        || lower.ends_with(".msi")
        || lower.ends_with(".com")
}

/// Scans a ZIP archive entirely in memory with a global decompression budget and bomb mitigations.
pub fn scan_zip_archive(
    data: &[u8],
    archive_path: &Path,
    current_depth: u32,
) -> Result<ScanReport, ArchiveError> {
    let mut budget = ArchiveBudget::default();
    scan_zip_archive_internal(data, archive_path, current_depth, &mut budget)
}

fn scan_zip_archive_internal(
    data: &[u8],
    archive_path: &Path,
    current_depth: u32,
    budget: &mut ArchiveBudget,
) -> Result<ScanReport, ArchiveError> {
    if current_depth > MAX_NESTING_DEPTH {
        return Err(ArchiveError::BombThresholdExceeded(format!(
            "Recursion depth exceeded limit of {}",
            MAX_NESTING_DEPTH
        )));
    }

    let cursor = Cursor::new(data);
    let mut zip = ZipArchive::new(cursor)
        .map_err(|e| ArchiveError::MalformedZip(e.to_string()))?;

    let file_count = zip.len();
    if file_count > MAX_ARCHIVE_FILES {
        return Err(ArchiveError::BombThresholdExceeded(format!(
            "Archive contains {} entries (limit is {})",
            file_count, MAX_ARCHIVE_FILES
        )));
    }

    let (sha256, blake3) = dual_hash(data);
    let identity = FileIdentity {
        path: archive_path.to_path_buf(),
        size_bytes: data.len() as u64,
        sha256,
        blake3,
    };

    let mut files_scanned = 0;
    let mut files_skipped = 0;
    let mut skip_reasons = Vec::new();
    let mut all_evidence = Vec::new();
    let mut worst_tier = Tier::NoIndicatorsFound;
    let mut primary_autopsy: Option<PeAutopsy> = None;

    for i in 0..file_count {
        let mut file = match zip.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                files_skipped += 1;
                skip_reasons.push(format!("Entry #{}: Failed to read index ({})", i, e));
                if worst_tier < Tier::Inconclusive {
                    worst_tier = Tier::Inconclusive;
                }
                continue;
            }
        };

        let file_name = file.name().to_string();

        if file.is_dir() {
            continue;
        }

        // Check password encryption
        if file.encrypted() {
            files_skipped += 1;
            skip_reasons.push(format!("{}: Encrypted file (cannot inspect)", file_name));
            if worst_tier < Tier::Inconclusive {
                worst_tier = Tier::Inconclusive;
            }
            continue;
        }

        let compressed_size = file.compressed_size();

        // Bounded stream decompression (do not trust header file.size())
        let mut file_buf = Vec::new();
        let mut bounded_reader = (&mut file).take(MAX_SINGLE_FILE_BYTES + 1);
        if let Err(e) = bounded_reader.read_to_end(&mut file_buf) {
            files_skipped += 1;
            skip_reasons.push(format!("{}: Read error ({})", file_name, e));
            if worst_tier < Tier::Inconclusive {
                worst_tier = Tier::Inconclusive;
            }
            continue;
        }

        let actual_bytes = file_buf.len() as u64;

        // Anti-Bomb Check 1: Single file limit breach
        if actual_bytes > MAX_SINGLE_FILE_BYTES {
            return Err(ArchiveError::BombThresholdExceeded(format!(
                "{}: Decompressed payload exceeded single-file {} MB limit",
                file_name,
                MAX_SINGLE_FILE_BYTES / 1024 / 1024
            )));
        }

        // Anti-Bomb Check 2: Global budget across all files and nesting levels
        if budget.remaining_bytes < actual_bytes {
            return Err(ArchiveError::BombThresholdExceeded(format!(
                "Global archive decompression budget exhausted ({} MB cumulative limit)",
                MAX_UNCOMPRESSED_BYTES / 1024 / 1024
            )));
        }
        budget.remaining_bytes -= actual_bytes;

        // Anti-Bomb Check 3: Actual measured compression ratio
        if compressed_size > 0 && actual_bytes > 1_048_576 {
            let actual_ratio = actual_bytes as f64 / compressed_size as f64;
            if actual_ratio > MAX_COMPRESSION_RATIO {
                return Err(ArchiveError::BombThresholdExceeded(format!(
                    "{}: Actual measured compression ratio {:.1}:1 exceeds limit of {:.0}:1",
                    file_name, actual_ratio, MAX_COMPRESSION_RATIO
                )));
            }
        }

        // Check if nested archive
        if is_zip_archive(&file_buf) {
            let nested_path = archive_path.join(&file_name);
            match scan_zip_archive_internal(&file_buf, &nested_path, current_depth + 1, budget) {
                Ok(nested_report) => {
                    files_scanned += nested_report.files_scanned;
                    files_skipped += nested_report.files_skipped;
                    skip_reasons.extend(nested_report.skip_reasons);
                    all_evidence.extend(nested_report.evidence);
                    if nested_report.verdict > worst_tier {
                        worst_tier = nested_report.verdict;
                    }
                }
                Err(e) => {
                    files_skipped += 1;
                    skip_reasons.push(format!("{}: Nested scan failed ({})", file_name, e));
                    if worst_tier < Tier::Inconclusive {
                        worst_tier = Tier::Inconclusive;
                    }
                }
            }
            continue;
        }

        let entry_hint = crate::risk::detect_format_hint(Some(Path::new(&file_name)), &file_buf, false);

        // If inner file is an unsupported container/archive format, we cannot inspect its contents:
        if let crate::risk::FileFormatHint::UnsupportedContainer(container_name) = entry_hint {
            files_skipped += 1;
            skip_reasons.push(format!("{}: Unsupported container format ({})", file_name, container_name));
            if worst_tier < Tier::Inconclusive {
                worst_tier = Tier::Inconclusive;
            }
            continue;
        }

        // Check if file is executable or contains PE magic or script
        let is_pe_header = file_buf.len() > 2 && &file_buf[0..2] == b"MZ";
        let should_analyze = is_pe_header
            || is_executable_or_script(&file_name)
            || matches!(entry_hint, crate::risk::FileFormatHint::Script | crate::risk::FileFormatHint::CorruptExecutable(_));

        if !should_analyze {
            // Text, images, audio, readmes etc.
            continue;
        }

        files_scanned += 1;
        let mut file_evidence = Vec::new();

        // Stage 1: PE Autopsy
        let pe_result = analyze_pe(&file_buf);
        let is_pe = match pe_result {
            Some((autopsy, pe_ev)) => {
                file_evidence.extend(pe_ev);
                if primary_autopsy.is_none() {
                    primary_autopsy = Some(autopsy);
                }
                true
            }
            None => false,
        };

        // Stage 2: IOC Scan
        let ioc_ev = scan_iocs(&file_buf);
        file_evidence.extend(ioc_ev);

        // Stage 3: Risk Evaluation
        let format_hint = crate::risk::detect_format_hint(Some(Path::new(&file_name)), &file_buf, is_pe);
        let eval = evaluate_risk(&file_evidence, is_pe, &format_hint);
        if eval.tier > worst_tier {
            worst_tier = eval.tier;
        }

        // Prefix file name to evidence explanations so user knows which inner file contained the artifact
        for mut item in file_evidence {
            item.explanation = format!("[{}] {}", file_name, item.explanation);
            all_evidence.push(item);
        }
    }

    // Epistemic Guard: If files were skipped or encrypted and no high-risk/suspicious findings,
    // the archive CANNOT be declared clean (NoIndicatorsFound). It must be INCONCLUSIVE.
    if worst_tier == Tier::NoIndicatorsFound && files_skipped > 0 {
        worst_tier = Tier::Inconclusive;
    }

    let verdict_summary = match worst_tier {
        Tier::HighRisk => {
            let note = if files_skipped > 0 {
                format!(" (Caution: {} uninspected/encrypted entries were also skipped).", files_skipped)
            } else {
                String::new()
            };
            format!(
                "Archive contains high-risk malicious artifacts in extracted binaries (Scanned {} files).{}",
                files_scanned, note
            )
        }
        Tier::Suspicious => {
            let note = if files_skipped > 0 {
                format!(" ({} entries skipped).", files_skipped)
            } else {
                String::new()
            };
            format!(
                "Archive contains suspicious indicators or structural anomalies (Scanned {} files).{}",
                files_scanned, note
            )
        }
        Tier::Inconclusive => {
            format!(
                "Archive inspection incomplete (Skipped or encrypted {} files; Scanned {} files).",
                files_skipped, files_scanned
            )
        }
        Tier::NoIndicatorsFound => {
            if files_scanned == 0 {
                "Archive contains zero executable or script payloads.".to_string()
            } else {
                format!(
                    "Zero threat IOCs observed across all {} inspected files in archive.",
                    files_scanned
                )
            }
        }
    };

    Ok(ScanReport {
        identity,
        autopsy: primary_autopsy,
        evidence: all_evidence,
        verdict: worst_tier,
        verdict_summary,
        files_scanned,
        files_skipped,
        skip_reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::generate_bench_stealer;
    use crate::models::EvidenceKind;
    use std::io::Write;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn create_test_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in files {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
        buf
    }

    #[test]
    fn test_zip_with_clean_files() {
        let zip_data = create_test_zip(&[
            ("readme.txt", b"Just a normal game readme"),
            ("game.ini", b"[Settings]\nresolution=1920x1080"),
        ]);

        let report = scan_zip_archive(&zip_data, Path::new("test_clean.zip"), 0).unwrap();
        assert_eq!(report.verdict, Tier::NoIndicatorsFound);
    }

    #[test]
    fn test_zip_with_stealer_inside() {
        let stealer_pe = generate_bench_stealer();
        let zip_data = create_test_zip(&[
            ("readme.txt", b"Crack instructions"),
            ("patch_installer.exe", &stealer_pe),
        ]);

        let report = scan_zip_archive(&zip_data, Path::new("test_trojan.zip"), 0).unwrap();
        assert_eq!(report.verdict, Tier::HighRisk);
        assert!(report.evidence.iter().any(|e| e.explanation.contains("patch_installer.exe")));
        assert!(report.evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::DiscordWebhook { .. })));
    }

    #[test]
    fn test_zip_nesting_detection() {
        // Inner zip contains stealer
        let inner_zip = create_test_zip(&[("inner_stealer.exe", &generate_bench_stealer())]);
        // Outer zip contains inner zip
        let outer_zip = create_test_zip(&[
            ("notes.txt", b"outer notes"),
            ("nested.zip", &inner_zip),
        ]);

        let report = scan_zip_archive(&outer_zip, Path::new("outer.zip"), 0).unwrap();
        assert_eq!(report.verdict, Tier::HighRisk);
        assert!(report.files_scanned >= 1);
    }

    #[test]
    fn test_encrypted_zip_yields_inconclusive() {
        let mut buf = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_deprecated_encryption(b"secret_password");

        writer.start_file("locked_malware.exe", options).unwrap();
        writer.write_all(b"MZfakeencryptedcontent").unwrap();
        writer.finish().unwrap();

        let report = scan_zip_archive(&buf, Path::new("locked.zip"), 0).unwrap();
        assert_eq!(report.verdict, Tier::Inconclusive);
        assert!(report.files_skipped >= 1);
        assert!(report.skip_reasons.iter().any(|r| r.contains("cannot inspect") || r.contains("Encrypted") || r.contains("Failed to read")));
    }

    #[test]
    fn test_encrypted_zip_with_stealer_preserves_high_risk() {
        let mut buf = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        let enc_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_deprecated_encryption(b"password123");
        let plain_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        writer.start_file("secret.doc", enc_options).unwrap();
        writer.write_all(b"secret payload").unwrap();

        let stealer_pe = generate_bench_stealer();
        writer.start_file("trojan.exe", plain_options).unwrap();
        writer.write_all(&stealer_pe).unwrap();

        writer.finish().unwrap();

        let report = scan_zip_archive(&buf, Path::new("mixed.zip"), 0).unwrap();
        assert_eq!(report.verdict, Tier::HighRisk);
        assert_eq!(report.files_skipped, 1);
        assert!(report.verdict_summary.contains("uninspected/encrypted"));
    }
}
