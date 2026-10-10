use oil_core::lab::*;
use oil_core::models::Tier;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_bench_clean_zero_false_positive() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&generate_bench_clean()).unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert_eq!(
        report.verdict,
        Tier::NoIndicatorsFound,
        "Clean binary must yield NO INDICATORS FOUND"
    );
    assert!(report.autopsy.is_some(), "Must parse as valid PE");
}

#[test]
fn test_bench_stealer_high_risk() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&generate_bench_stealer()).unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert_eq!(
        report.verdict,
        Tier::HighRisk,
        "Stealer (webhook + Chrome path) must trigger HIGH RISK"
    );
    assert!(
        report.evidence.iter().any(|e| matches!(&e.kind, oil_core::models::EvidenceKind::DiscordWebhook { .. })),
        "Must flag Discord Webhook"
    );
    assert!(
        report.evidence.iter().any(|e| matches!(&e.kind, oil_core::models::EvidenceKind::CredentialPath { .. })),
        "Must flag Credential Path"
    );
}

#[test]
fn test_bench_single_ioc_suspicious() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&generate_bench_single_ioc()).unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert_eq!(
        report.verdict,
        Tier::Suspicious,
        "Single isolated webhook without exfiltration combo must be SUSPICIOUS (not HighRisk)"
    );
}

#[test]
fn test_bench_entropy_suspicious() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&generate_bench_entropy()).unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert_eq!(
        report.verdict,
        Tier::Suspicious,
        "High entropy section (> 7.5) must trigger SUSPICIOUS"
    );
    assert!(
        report.evidence.iter().any(|e| matches!(&e.kind, oil_core::models::EvidenceKind::HighEntropySection { .. })),
        "Must flag HighEntropySection evidence"
    );
}

#[test]
fn test_bench_corrupt_non_panic() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"MZ\0\0TruncatedCorruptHeaderData").unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert!(
        report.autopsy.is_none(),
        "Corrupted PE must not panic and report autopsy as None"
    );
    assert_eq!(
        report.verdict,
        Tier::Inconclusive,
        "Corrupted PE binary must yield INCONCLUSIVE (epistemic honesty)"
    );
}

#[test]
fn test_bench_zipbomb_inconclusive() {
    use std::io::Cursor;
    use zip::write::{SimpleFileOptions, ZipWriter};

    let mut buf = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(&mut buf));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // Exceed max archive entries limit (1001 entries > 1000 limit)
    for i in 0..1005 {
        writer.start_file(format!("dummy_{}.txt", i), options).unwrap();
        writer.write_all(b"0").unwrap();
    }
    writer.finish().unwrap();

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&buf).unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert_eq!(
        report.verdict,
        Tier::Inconclusive,
        "Exceeding entry limits must trigger INCONCLUSIVE"
    );
    assert!(report.verdict_summary.contains("Inconclusive") || report.verdict_summary.contains("inconclusive"));
}

#[test]
fn test_bench_diff_drm_bypass_verdict() {
    use oil_core::lab::create_minimal_pe;
    use oil_core::models::PatchCategory;

    // Original: JZ +10 (74 0A)
    let orig_pe = create_minimal_pe(".text", b"\x74\x0A\x90\x90\x90\xC3Normal Code Flow");
    // Patched: JMP +10 (EB 0A) - classic DRM bypass
    let patch_pe = create_minimal_pe(".text", b"\xEB\x0A\x90\x90\x90\xC3Normal Code Flow");

    let mut orig_file = NamedTempFile::new().unwrap();
    orig_file.write_all(&orig_pe).unwrap();

    let mut patch_file = NamedTempFile::new().unwrap();
    patch_file.write_all(&patch_pe).unwrap();

    let diff_report = oil_core::diff::diff_binaries(orig_file.path(), patch_file.path()).unwrap();
    assert_eq!(diff_report.verdict, Tier::NoIndicatorsFound);
    assert!(!diff_report.patches.is_empty());
    assert_eq!(diff_report.patches[0].category, PatchCategory::DrmBypass);
    assert!(!diff_report.delta_fingerprint.is_empty());
}

#[test]
fn test_bench_diff_code_injection_verdict() {
    use oil_core::lab::create_minimal_pe;
    use oil_core::models::PatchCategory;

    // Original code
    let orig_pe = create_minimal_pe(".text", b"\x55\x48\x89\xE5\x90\xC3Original Code Flow");
    // Patched: Far JMP outside bounds (E9 00 00 50 04) - code injection hook
    let patch_pe = create_minimal_pe(".text", b"\xE9\x00\x00\x50\x04\xC3Original Code Flow");

    let mut orig_file = NamedTempFile::new().unwrap();
    orig_file.write_all(&orig_pe).unwrap();

    let mut patch_file = NamedTempFile::new().unwrap();
    patch_file.write_all(&patch_pe).unwrap();

    let diff_report = oil_core::diff::diff_binaries(orig_file.path(), patch_file.path()).unwrap();
    assert_eq!(diff_report.verdict, Tier::HighRisk);
    assert!(!diff_report.patches.is_empty());
    assert_eq!(diff_report.patches[0].category, PatchCategory::CodeInjection);
}

#[test]
fn test_bench_corrupt_exe_extension_inconclusive() {
    let dir = tempfile::tempdir().unwrap();
    let corrupt_path = dir.path().join("fake_driver.sys");
    std::fs::write(&corrupt_path, b"NOT_A_PE_HEADER_JUST_GARBAGE").unwrap();

    let report = oil_core::scan_path(&corrupt_path).unwrap();
    assert_eq!(
        report.verdict,
        Tier::Inconclusive,
        "Binary with executable extension but invalid PE structure must be INCONCLUSIVE"
    );
    assert!(report.verdict_summary.contains("corrupt") || report.verdict_summary.contains("invalid"));
}

#[test]
fn test_bench_unsupported_containers_inconclusive() {
    // 1. 7z magic
    let dir = tempfile::tempdir().unwrap();
    let p_7z = dir.path().join("archive.7z");
    std::fs::write(&p_7z, b"7z\xbc\xaf\x27\x1c\x00\x00\x00\x00compressed data").unwrap();
    let r_7z = oil_core::scan_path(&p_7z).unwrap();
    assert_eq!(r_7z.verdict, Tier::Inconclusive, "7z container must yield INCONCLUSIVE");

    // 2. RAR magic
    let p_rar = dir.path().join("archive.rar");
    std::fs::write(&p_rar, b"Rar!\x1a\x07\x00\x00\x00\x00compressed data").unwrap();
    let r_rar = oil_core::scan_path(&p_rar).unwrap();
    assert_eq!(r_rar.verdict, Tier::Inconclusive, "RAR container must yield INCONCLUSIVE");
}

#[test]
fn test_bench_zip_containing_unsupported_container_inconclusive() {
    use std::io::Cursor;
    use zip::write::{SimpleFileOptions, ZipWriter};

    let mut buf = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(&mut buf));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // Inner file is an unsupported 7z container
    writer.start_file("malware_container.7z", options).unwrap();
    writer.write_all(b"7z\xbc\xaf\x27\x1c\x00\x00internal payload").unwrap();
    writer.finish().unwrap();

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&buf).unwrap();

    let report = oil_core::scan_path(file.path()).unwrap();
    assert_eq!(
        report.verdict,
        Tier::Inconclusive,
        "ZIP containing unsupported archive (7z) must yield INCONCLUSIVE (cannot declare clean)"
    );
    assert!(report.files_skipped > 0);
}


