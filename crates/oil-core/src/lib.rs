//! # Oil Core
//!
//! Context-aware binary forensic triage engine.
//! Pure analysis engine library — zero UI, zero side-effects.

pub mod archive;
pub mod diff;
pub mod hunt;
pub mod io;
pub mod ioc;
pub mod lab;
pub mod models;
pub mod pe;
pub mod risk;
pub mod wintrust;

use std::path::Path;
use models::ScanReport;

/// High-level entrypoint: perform a complete triage scan of a file or archive.
pub fn scan_path(path: &Path) -> Result<ScanReport, io::IoError> {
    // 1. Stage 0: Hybrid I/O & Dual Hashing
    let (identity, file_data) = io::identify_file(path)?;
    let bytes = file_data.as_bytes();

    // Check if target is a ZIP archive (In-Memory Archive Scan)
    if archive::is_zip_archive(bytes) {
        match archive::scan_zip_archive(bytes, path, 0) {
            Ok(report) => return Ok(report),
            Err(e) => {
                return Ok(ScanReport {
                    identity,
                    autopsy: None,
                    evidence: Vec::new(),
                    verdict: models::Tier::Inconclusive,
                    verdict_summary: format!("Archive analysis inconclusive: {}", e),
                    files_scanned: 0,
                    files_skipped: 1,
                    skip_reasons: vec![e.to_string()],
                });
            }
        }
    }

    // Check if target is a Windows Shortcut (.lnk)
    let is_lnk = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
        || (bytes.len() >= 76 && bytes.starts_with(&[0x4C, 0x00, 0x00, 0x00]));

    if is_lnk {
        if let Some(info) = hunt::parse_lnk_bytes(bytes) {
            let script_target = info
                .arguments
                .as_ref()
                .and_then(|a| hunt::extract_file_path_from_cmd(a));
            let resolved = script_target.or(info.target_path);
            if let Some(ref target) = resolved {
                if target.exists() && target.is_file() {
                    match scan_path(target) {
                        Ok(mut target_report) => {
                            target_report.verdict_summary = format!(
                                "Shortcut target ('{}') triaged: {}",
                                target.display(),
                                target_report.verdict_summary
                            );
                            return Ok(target_report);
                        }
                        Err(e) => {
                            return Ok(ScanReport {
                                identity,
                                autopsy: None,
                                evidence: Vec::new(),
                                verdict: models::Tier::Inconclusive,
                                verdict_summary: format!(
                                    "Failed to triage shortcut target '{}': {}",
                                    target.display(),
                                    e
                                ),
                                files_scanned: 0,
                                files_skipped: 1,
                                skip_reasons: vec![e.to_string()],
                            });
                        }
                    }
                } else {
                    return Ok(ScanReport {
                        identity,
                        autopsy: None,
                        evidence: Vec::new(),
                        verdict: models::Tier::Inconclusive,
                        verdict_summary: format!(
                            "Shortcut (.lnk) target binary missing on disk: '{}'",
                            target.display()
                        ),
                        files_scanned: 0,
                        files_skipped: 1,
                        skip_reasons: vec![format!("Target binary '{}' not found", target.display())],
                    });
                }
            }
        }
    }

    let mut all_evidence = Vec::new();

    // 2. Stage 1: PE Autopsy
    let pe_result = pe::analyze_pe(bytes);
    let (mut autopsy, is_pe) = match pe_result {
        Some((autopsy, pe_evidence)) => {
            all_evidence.extend(pe_evidence);
            (Some(autopsy), true)
        }
        None => (None, false),
    };

    // Stage 1.5: Authenticode Cryptographic Verification via WinVerifyTrust
    if is_pe {
        let trust_status = wintrust::verify_authenticode(path);
        if let Some(ref mut pe_auto) = autopsy {
            match trust_status {
                wintrust::TrustStatus::Valid => {
                    pe_auto.signature_valid = Some(true);
                    pe_auto.signature_signer = Some("Verified Windows Authenticode (WinVerifyTrust)".to_string());
                    if let Some(ev) = all_evidence.iter_mut().find(|e| matches!(e.kind, models::EvidenceKind::SignatureStatus { .. })) {
                        ev.kind = models::EvidenceKind::SignatureStatus {
                            valid: true,
                            signer: pe_auto.signature_signer.clone(),
                            detail: "Cryptographically verified via WinVerifyTrust".to_string(),
                        };
                        ev.is_threat_signal = false;
                        ev.explanation = "Authenticode digital signature cryptographically verified against Windows Trust Provider.".to_string();
                    }
                }
                wintrust::TrustStatus::NotSigned => {
                    pe_auto.signature_valid = Some(false);
                    pe_auto.signature_signer = None;
                    if let Some(ev) = all_evidence.iter_mut().find(|e| matches!(e.kind, models::EvidenceKind::SignatureStatus { .. })) {
                        ev.kind = models::EvidenceKind::SignatureStatus {
                            valid: false,
                            signer: None,
                            detail: "Binary is not signed (no embedded Authenticode structure)".to_string(),
                        };
                    }
                }
                wintrust::TrustStatus::BadDigest => {
                    pe_auto.signature_valid = Some(false);
                    pe_auto.signature_signer = Some("Tampered Signature (BadDigest hash mismatch)".to_string());
                    if let Some(ev) = all_evidence.iter_mut().find(|e| matches!(e.kind, models::EvidenceKind::SignatureStatus { .. })) {
                        ev.kind = models::EvidenceKind::SignatureStatus {
                            valid: false,
                            signer: pe_auto.signature_signer.clone(),
                            detail: "Tampered binary (BadDigest hash mismatch)".to_string(),
                        };
                        ev.is_threat_signal = true;
                        ev.explanation = "Binary contents modified after signing (Authenticode hash mismatch).".to_string();
                    }
                }
                wintrust::TrustStatus::UntrustedRoot => {
                    pe_auto.signature_valid = Some(false);
                    pe_auto.signature_signer = Some("Untrusted Root Certificate / Self-Signed".to_string());
                    if let Some(ev) = all_evidence.iter_mut().find(|e| matches!(e.kind, models::EvidenceKind::SignatureStatus { .. })) {
                        ev.kind = models::EvidenceKind::SignatureStatus {
                            valid: false,
                            signer: pe_auto.signature_signer.clone(),
                            detail: "Untrusted root certificate".to_string(),
                        };
                    }
                }
                wintrust::TrustStatus::Distrusted => {
                    pe_auto.signature_valid = Some(false);
                    pe_auto.signature_signer = Some("Explicitly Distrusted or Revoked Certificate".to_string());
                    if let Some(ev) = all_evidence.iter_mut().find(|e| matches!(e.kind, models::EvidenceKind::SignatureStatus { .. })) {
                        ev.kind = models::EvidenceKind::SignatureStatus {
                            valid: false,
                            signer: pe_auto.signature_signer.clone(),
                            detail: "Explicitly distrusted or revoked certificate".to_string(),
                        };
                        ev.is_threat_signal = true;
                    }
                }
                _ => {}
            }
        }
    }

    // 3. Stage 2: IOC Extraction
    let ioc_evidence = ioc::scan_iocs(bytes);
    all_evidence.extend(ioc_evidence);

    // Check for DLL Sideloading / Proxy Hook if target is a candidate DLL
    if is_pe && hunt::is_sideload_candidate_path(path) {
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = file_name.to_lowercase();
            let shadows_system = !lower.starts_with("steam_api") && !lower.starts_with("fakenvapi");
            all_evidence.push(models::Evidence {
                kind: models::EvidenceKind::DllProxyHook {
                    dll_name: file_name.to_string(),
                    shadows_system,
                },
                is_threat_signal: true,
                explanation: if shadows_system {
                    format!(
                        "File '{}' shadows a standard Windows system DLL in an application directory. \
                         Commonly used for proxy hooking, mod loading, or DLL search-order hijacking.",
                        file_name
                    )
                } else {
                    format!(
                        "File '{}' matches known gaming platform emulator/proxy hook signatures.",
                        file_name
                    )
                },
            });
        }
    }

    // 4. Stage 3: Combinatorial Risk Evaluation with Format Hint
    let format_hint = risk::detect_format_hint(Some(path), bytes, is_pe);
    let evaluation = risk::evaluate_risk(&all_evidence, is_pe, &format_hint);

    Ok(ScanReport {
        identity,
        autopsy,
        evidence: all_evidence,
        verdict: evaluation.tier,
        verdict_summary: evaluation.summary,
        files_scanned: 1,
        files_skipped: 0,
        skip_reasons: Vec::new(),
    })
}

/// Scans a raw in-memory byte buffer without writing anything to disk.
pub fn scan_bytes(bytes: &[u8], name_hint: &str) -> ScanReport {
    let (sha256, blake3) = io::dual_hash(bytes);
    let identity = models::FileIdentity {
        path: std::path::PathBuf::from(name_hint),
        size_bytes: bytes.len() as u64,
        sha256,
        blake3,
    };

    let mut all_evidence = Vec::new();

    // Stage 1: PE Autopsy
    let pe_result = pe::analyze_pe(bytes);
    let (autopsy, is_pe) = match pe_result {
        Some((autopsy, pe_evidence)) => {
            all_evidence.extend(pe_evidence);
            (Some(autopsy), true)
        }
        None => (None, false),
    };

    // Stage 2: IOC Extraction
    let ioc_evidence = ioc::scan_iocs(bytes);
    all_evidence.extend(ioc_evidence);

    // Check for DLL Sideloading / Proxy Hook if target is a candidate DLL
    let path_hint = std::path::Path::new(name_hint);
    if is_pe && hunt::is_sideload_candidate_path(path_hint) {
        if let Some(file_name) = path_hint.file_name().and_then(|n| n.to_str()) {
            let lower = file_name.to_lowercase();
            let shadows_system = !lower.starts_with("steam_api") && !lower.starts_with("fakenvapi");
            all_evidence.push(models::Evidence {
                kind: models::EvidenceKind::DllProxyHook {
                    dll_name: file_name.to_string(),
                    shadows_system,
                },
                is_threat_signal: true,
                explanation: if shadows_system {
                    format!(
                        "File '{}' shadows a standard Windows system DLL in an application directory. \
                         Commonly used for proxy hooking, mod loading, or DLL search-order hijacking.",
                        file_name
                    )
                } else {
                    format!(
                        "File '{}' matches known gaming platform emulator/proxy hook signatures.",
                        file_name
                    )
                },
            });
        }
    }

    // Format hint & risk evaluation
    let format_hint = risk::detect_format_hint(Some(path_hint), bytes, is_pe);
    let evaluation = risk::evaluate_risk(&all_evidence, is_pe, &format_hint);

    ScanReport {
        identity,
        autopsy,
        evidence: all_evidence,
        verdict: evaluation.tier,
        verdict_summary: evaluation.summary,
        files_scanned: 1,
        files_skipped: 0,
        skip_reasons: Vec::new(),
    }
}
