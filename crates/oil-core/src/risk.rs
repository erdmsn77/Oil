//! # Combinatorial Risk Engine
//!
//! GDD §1.1 & §3.5 — Stage 3: Decision Engine
//! Evaluates accumulated evidence from PE Autopsy and IOC scanning,
//! strictly enforcing multi-signal combinations and avoiding single-signal false alarms.

use crate::models::{Evidence, EvidenceKind, Tier};
use std::path::Path;

/// High-level format classification to ensure epistemic honesty during triage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileFormatHint {
    /// Valid PE binary validated by parser.
    PeExecutable,
    /// Has PE magic (MZ) or executable extension, but PE parsing failed.
    CorruptExecutable(String),
    /// Container or compressed archive formats that cannot be inspected without dedicated unpackers.
    UnsupportedContainer(&'static str),
    /// Windows Shell Shortcut (.lnk)
    WindowsShortcut,
    /// Script or command file (.ps1, .bat, .cmd, .vbs, .js, .hta)
    Script,
    /// Non-executable data or media (.txt, .json, .png, etc.)
    NonExecutableData,
}

/// Detects the format classification from optional file path, raw bytes, and PE parser result.
pub fn detect_format_hint(path: Option<&Path>, bytes: &[u8], is_pe: bool) -> FileFormatHint {
    if is_pe {
        return FileFormatHint::PeExecutable;
    }

    // 1. Check for PE magic (MZ)
    let has_mz = bytes.len() >= 2 && &bytes[0..2] == b"MZ";
    if has_mz {
        return FileFormatHint::CorruptExecutable(
            "File begins with MZ DOS signature but PE parser failed to validate structure".to_string(),
        );
    }

    // Extension check if path provided
    let ext = path
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    if ["exe", "dll", "sys", "scr", "cpl", "ocx"].contains(&ext.as_str()) {
        return FileFormatHint::CorruptExecutable(format!(
            "File has .{} extension but does not contain a valid PE binary header",
            ext
        ));
    }

    // 2. Magic byte / extension checks for containers
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") || ext == "7z" {
        return FileFormatHint::UnsupportedContainer("7-Zip Archive (.7z)");
    }
    if bytes.starts_with(b"Rar!\x1a\x07\x00") || bytes.starts_with(b"Rar!\x1a\x07\x01\x00") || ext == "rar" {
        return FileFormatHint::UnsupportedContainer("RAR Archive (.rar)");
    }
    if bytes.starts_with(b"MSCF") || ext == "cab" {
        return FileFormatHint::UnsupportedContainer("Microsoft Cabinet (.cab)");
    }
    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        || ["docm", "xlsm", "pptm", "dotm", "xltm"].contains(&ext.as_str())
    {
        return FileFormatHint::UnsupportedContainer("Office Macro / OLE Compound Document");
    }
    if bytes.starts_with(&[0x1F, 0x8B]) || ext == "gz" || ext == "tgz" {
        return FileFormatHint::UnsupportedContainer("Gzip Compressed Archive (.tar.gz)");
    }
    if bytes.starts_with(b"BZh") || ext == "bz2" {
        return FileFormatHint::UnsupportedContainer("Bzip2 Compressed Archive (.tar.bz2)");
    }
    if bytes.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) || ext == "xz" {
        return FileFormatHint::UnsupportedContainer("XZ Compressed Archive (.tar.xz)");
    }
    if ext == "tar" {
        return FileFormatHint::UnsupportedContainer("Tar Archive (.tar)");
    }
    if ext == "jar" {
        return FileFormatHint::UnsupportedContainer("Java Archive (.jar)");
    }
    if ext == "iso" || ext == "img" || ext == "vhd" || ext == "vhdx" {
        return FileFormatHint::UnsupportedContainer("Disk Image (.iso/.img)");
    }
    if bytes.len() >= 0x9005 {
        for &offset in &[0x8000, 0x8800, 0x9000] {
            if bytes.len() >= offset + 6 && &bytes[offset + 1..offset + 6] == b"CD001" {
                return FileFormatHint::UnsupportedContainer("ISO 9660 Disk Image (.iso)");
            }
        }
    }
    if bytes.starts_with(b"\x7fELF") {
        return FileFormatHint::UnsupportedContainer("Linux ELF Executable");
    }
    if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) || bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
        return FileFormatHint::UnsupportedContainer("macOS Mach-O Executable");
    }

    // 3. Windows Shortcut (.lnk)
    if (bytes.len() >= 76 && bytes.starts_with(&[0x4C, 0x00, 0x00, 0x00])) || ext == "lnk" {
        return FileFormatHint::WindowsShortcut;
    }

    // 4. Scripts
    if ["ps1", "bat", "cmd", "vbs", "js", "hta", "wsf"].contains(&ext.as_str()) {
        return FileFormatHint::Script;
    }

    FileFormatHint::NonExecutableData
}

/// Results of the risk engine evaluation.
#[derive(Debug, Clone)]
pub struct RiskEvaluation {
    pub tier: Tier,
    pub summary: String,
    pub primary_reasons: Vec<String>,
}

/// Evaluates a list of evidence items against the Decision Matrix.
pub fn evaluate_risk(
    evidence: &[Evidence],
    is_pe: bool,
    format_hint: &FileFormatHint,
) -> RiskEvaluation {
    // Epistemic Guard 1: Corrupted or truncated PE binaries
    if let FileFormatHint::CorruptExecutable(ref reason) = format_hint {
        if evidence.is_empty() {
            return RiskEvaluation {
                tier: Tier::Inconclusive,
                summary: format!("Malformed or corrupted executable: {}", reason),
                primary_reasons: vec![reason.clone()],
            };
        }
    }

    // Epistemic Guard 2: Unsupported containers / archives
    if let FileFormatHint::UnsupportedContainer(container_name) = format_hint {
        if evidence.is_empty() {
            return RiskEvaluation {
                tier: Tier::Inconclusive,
                summary: format!(
                    "Unsupported container format '{}': compressed internal files cannot be triaged without dedicated unpacker.",
                    container_name
                ),
                primary_reasons: vec![
                    format!(
                        "File is a {} container. Static analysis cannot inspect internal compressed streams without unpacking.",
                        container_name
                    ),
                ],
            };
        }
    }

    // Epistemic Guard 3: Windows Shell Shortcuts (.lnk) without direct target triage
    if let FileFormatHint::WindowsShortcut = format_hint {
        if evidence.is_empty() {
            return RiskEvaluation {
                tier: Tier::Inconclusive,
                summary: "Windows Shortcut (.lnk) target binary could not be resolved for triage.".to_string(),
                primary_reasons: vec![
                    "File is a Windows Shell Link (.lnk). Target binary must be inspected directly.".to_string(),
                ],
            };
        }
    }

    // Epistemic Guard 4: Non-executable files with zero indicators
    if !is_pe && evidence.is_empty() {
        let (summary, reason) = match format_hint {
            FileFormatHint::Script => (
                "Script file with zero threat indicators observed.".to_string(),
                "Zero matched dropper patterns, webhooks, or obfuscated commands.".to_string(),
            ),
            _ => (
                "Non-executable file with zero threat indicators observed.".to_string(),
                "File contains no executable structure and zero matched threat indicators.".to_string(),
            ),
        };
        return RiskEvaluation {
            tier: Tier::NoIndicatorsFound,
            summary,
            primary_reasons: vec![reason],
        };
    }

    // ──────────────────────────────────────────────
    // 1. SIGNAL EXTRACTORS
    // ──────────────────────────────────────────────
    let mut has_webhook_or_telegram = false;
    let mut credential_paths = Vec::new();
    let mut has_powershell_dropper = false;
    let mut has_injection_import = false;
    let mut has_network_import = false;
    let mut has_rwx_section = false;
    let mut has_high_entropy_section = false;
    let mut has_extreme_entropy = false;
    let mut has_codeless_container = false;
    let mut has_overlay_anomaly = false;
    let mut has_crypter_profile = false;
    let mut has_yara_match = false;
    let mut has_valid_signature = false;
    let mut has_sensitive_api = false;
    let mut has_sideload_proxy = false;
    let mut sideload_shadows_system = false;
    let mut sideload_dll_name = String::new();

    let mut reasons = Vec::new();

    for item in evidence {
        match &item.kind {
            EvidenceKind::DiscordWebhook { url, .. } => {
                has_webhook_or_telegram = true;
                reasons.push(format!("Discord webhook reference: '{}'", url));
            }
            EvidenceKind::TelegramToken { token, .. } => {
                has_webhook_or_telegram = true;
                reasons.push(format!("Telegram bot token reference: '{}'", token));
            }
            EvidenceKind::CredentialPath { path, .. } => {
                credential_paths.push(path.clone());
                reasons.push(format!("Browser credential database reference: '{}'", path));
            }
            EvidenceKind::PowerShellCommand { fragment, .. } => {
                has_powershell_dropper = true;
                reasons.push(format!("PowerShell dropper indicator: '{}'", fragment));
            }
            EvidenceKind::InjectionImport { dll, functions } => {
                has_injection_import = true;
                reasons.push(format!("Process injection APIs from '{}' ({:?})", dll, functions));
            }
            EvidenceKind::NetworkImport { dll, functions } => {
                has_network_import = true;
                reasons.push(format!("Socket/network API imports from '{}' ({:?})", dll, functions));
            }
            EvidenceKind::SensitiveApiImport { dll, functions } => {
                has_sensitive_api = true;
                reasons.push(format!("Cryptographic/DPAPI API imports from '{}' ({:?})", dll, functions));
            }
            EvidenceKind::SignatureStatus { valid, .. } => {
                if *valid {
                    has_valid_signature = true;
                    reasons.push("Authenticode digital signature directory verified.".to_string());
                }
            }
            EvidenceKind::RwxSection { name } => {
                has_rwx_section = true;
                reasons.push(format!("Self-modifying RWX section: '{}'", name));
            }
            EvidenceKind::HighEntropySection { name, entropy } if item.is_threat_signal => {
                if name == "NO_EXEC_CODE" {
                    has_codeless_container = true;
                    reasons.push(format!("Codeless payload container (zero code sections, max entropy {:.2})", entropy));
                } else if *entropy >= 7.95 {
                    has_extreme_entropy = true;
                    reasons.push(format!("Near-maximal section entropy in '{}' ({:.2})", name, entropy));
                } else {
                    has_high_entropy_section = true;
                    reasons.push(format!("High-entropy section '{}' ({:.2})", name, entropy));
                }
            }
            EvidenceKind::Overlay { size_bytes } if item.is_threat_signal => {
                has_overlay_anomaly = true;
                reasons.push(format!("High-entropy unmapped overlay ({} bytes appended)", size_bytes));
            }
            EvidenceKind::CrypterProfile { indicators } => {
                has_crypter_profile = true;
                reasons.push(format!("Crypter profile: {:?}", indicators));
            }
            EvidenceKind::YaraMatch { rule_name, .. } => {
                has_yara_match = true;
                reasons.push(format!("YARA signature match: '{}'", rule_name));
            }
            EvidenceKind::DllProxyHook { dll_name, shadows_system } => {
                has_sideload_proxy = true;
                sideload_shadows_system = sideload_shadows_system || *shadows_system;
                sideload_dll_name = dll_name.clone();
                if *shadows_system {
                    reasons.push(format!("DLL proxy hook shadowing system library '{}'", dll_name));
                } else {
                    reasons.push(format!("Known platform emulator/proxy hook '{}'", dll_name));
                }
            }
            _ => {}
        }
    }

    // Measure distinct browser/vault families targeted
    let mut browser_families = std::collections::HashSet::new();
    for p in &credential_paths {
        let lower = p.to_lowercase();
        if lower.contains("chrome") {
            browser_families.insert("Chrome");
        } else if lower.contains("edge") {
            browser_families.insert("Edge");
        } else if lower.contains("firefox") || lower.contains("mozilla") {
            browser_families.insert("Firefox");
        } else if lower.contains("opera") {
            browser_families.insert("Opera");
        } else if lower.contains("brave") {
            browser_families.insert("Brave");
        } else if lower.contains("vivaldi") {
            browser_families.insert("Vivaldi");
        } else if lower.contains("wallet") {
            browser_families.insert("CryptoWallet");
        }
    }
    let distinct_browser_targets = browser_families.len();

    // ──────────────────────────────────────────────
    // 2. WEIGHTED THREAT SCORING MODEL
    // ──────────────────────────────────────────────
    let mut threat_score: u32 = 0;
    let mut score_breakdown: Vec<String> = Vec::new();

    // 1. Smoking Guns
    if has_yara_match {
        threat_score = threat_score.saturating_add(100);
        score_breakdown.push("+100: Signature match for known malicious family (YARA)".to_string());
    }

    if has_webhook_or_telegram {
        threat_score = threat_score.saturating_add(25);
        score_breakdown.push("+25: Exfiltration endpoint observed (Discord/Telegram)".to_string());
    }

    // 2. Credential targets & browser family diversification
    if distinct_browser_targets >= 3 {
        threat_score = threat_score.saturating_add(50);
        score_breakdown.push(format!(
            "+50: Universal credential harvesting targeting {} browser/vault families ({:?})",
            distinct_browser_targets, browser_families
        ));
    } else if distinct_browser_targets == 2 {
        threat_score = threat_score.saturating_add(25);
        score_breakdown.push(format!(
            "+25: Multi-browser targeting across 2 distinct competitor families ({:?})",
            browser_families
        ));
    } else if distinct_browser_targets == 1 {
        // Single browser family (e.g. Chrome/CEF). Common in CEF/Electron apps (Steam, VS Code, FDM)
        threat_score = threat_score.saturating_add(5);
        score_breakdown.push(format!(
            "+5: Single browser/vault reference observed ({:?}) — consistent with CEF/Electron framework",
            browser_families
        ));
    }

    // Synergy 1: Infostealer combination (Exfil endpoint + Credential targets)
    if has_webhook_or_telegram && !credential_paths.is_empty() {
        threat_score = threat_score.saturating_add(35);
        score_breakdown.push("+35 Synergy: Infostealer pattern (Exfiltration channel + Credential targets)".to_string());
    }

    // Synergy 2: Harvester combination (Multi-family credentials + Outbound network sockets)
    if distinct_browser_targets >= 2 && has_network_import {
        threat_score = threat_score.saturating_add(25);
        score_breakdown.push("+25 Synergy: Multi-browser harvester with network socket capability".to_string());
    }

    // Synergy 3: Harvester with DPAPI unprotect capability
    if distinct_browser_targets >= 2 && has_sensitive_api {
        threat_score = threat_score.saturating_add(10);
        score_breakdown.push("+10 Synergy: Multi-browser harvester with DPAPI/crypto unprotect capability".to_string());
    }

    // 3. Execution & Staging
    if has_powershell_dropper {
        threat_score = threat_score.saturating_add(30);
        score_breakdown.push("+30: Encoded/hidden PowerShell command dropper indicator".to_string());
        if has_webhook_or_telegram || has_injection_import {
            threat_score = threat_score.saturating_add(25);
            score_breakdown.push("+25 Synergy: Stager/dropper paired with payload delivery".to_string());
        }
    }

    if has_injection_import {
        threat_score = threat_score.saturating_add(25);
        score_breakdown.push("+25: Process injection API imports".to_string());
        if has_rwx_section || has_crypter_profile {
            threat_score = threat_score.saturating_add(35);
            score_breakdown.push("+35 Synergy: Process injection paired with memory modification/crypter stub".to_string());
        }
        if has_network_import {
            threat_score = threat_score.saturating_add(20);
            score_breakdown.push("+20 Synergy: Process injection APIs paired with outbound network capabilities".to_string());
        }
    }

    // 4. Memory & Packing Anomalies
    if has_rwx_section {
        threat_score = threat_score.saturating_add(25);
        score_breakdown.push("+25: Self-modifying RWX memory section".to_string());
    }

    if has_crypter_profile {
        threat_score = threat_score.saturating_add(35);
        score_breakdown.push("+35: Crypter structural profile (minimal loader + encrypted payload)".to_string());
    }

    if has_codeless_container {
        threat_score = threat_score.saturating_add(30);
        score_breakdown.push("+30: Codeless encrypted container structure (zero executable sections, high entropy data carrier)".to_string());
    } else if has_extreme_entropy {
        threat_score = threat_score.saturating_add(25);
        score_breakdown.push("+25: Near-maximal section entropy (>= 7.95, embedded compressed or encrypted resource blob)".to_string());
    } else if has_high_entropy_section {
        threat_score = threat_score.saturating_add(20);
        score_breakdown.push("+20: High-entropy section (Shannon entropy > 7.5)".to_string());
    }

    if has_overlay_anomaly {
        threat_score = threat_score.saturating_add(20);
        score_breakdown.push("+20: High-entropy unmapped overlay past PE image end".to_string());
    }

    // 5. DLL Proxy Hook / Sideloading
    if has_sideload_proxy {
        if sideload_shadows_system {
            threat_score = threat_score.saturating_add(25);
            score_breakdown.push(format!(
                "+25: DLL search-order hijacking / proxy hook shadowing system library ('{}')",
                sideload_dll_name
            ));
        } else {
            threat_score = threat_score.saturating_add(10);
            score_breakdown.push(format!(
                "+10: Application directory DLL proxy hook / sideload trap ('{}')",
                sideload_dll_name
            ));
        }

        // Synergy: Proxy DLL combined with process injection (Hostile Loader pattern)
        if has_injection_import {
            threat_score = threat_score.saturating_add(25);
            score_breakdown.push(
                "+25 Synergy: DLL proxy hook paired with process injection APIs (Hostile Sideload Loader)".to_string(),
            );
        }

        // Synergy: Proxy DLL combined with credential harvesting or exfiltration
        if has_webhook_or_telegram || distinct_browser_targets >= 2 {
            threat_score = threat_score.saturating_add(30);
            score_breakdown.push(
                "+30 Synergy: DLL proxy hook paired with credential harvesting/exfiltration (Trojan Proxy)".to_string(),
            );
        }
    }

    // 6. Digital Signature Mitigation
    let is_confirmed_hostile = has_yara_match
        || (has_webhook_or_telegram && !credential_paths.is_empty())
        || (has_injection_import && (has_rwx_section || has_crypter_profile || has_sideload_proxy))
        || (has_injection_import && has_network_import)
        || (distinct_browser_targets >= 3 && has_network_import)
        || has_codeless_container;

    if has_valid_signature && !is_confirmed_hostile {
        let mitigation = if has_extreme_entropy { 5 } else { 15 };
        threat_score = threat_score.saturating_sub(mitigation);
        score_breakdown.push(format!("-{} Mitigation: Authenticode digital signature verified", mitigation));
    }

    // ──────────────────────────────────────────────
    // 3. DECISION TIERS (Thresholds: >=60 HighRisk, 20..59 Suspicious, <20 NoIndicatorsFound)
    // ──────────────────────────────────────────────
    if threat_score >= 60 {
        let summary = if has_yara_match {
            "High-confidence signature match detected for known malicious payload.".to_string()
        } else if has_webhook_or_telegram && !credential_paths.is_empty() {
            "Confirmed infostealer pattern: Exfiltration pipe paired with credential database targets.".to_string()
        } else if has_sideload_proxy && has_injection_import {
            format!(
                "Hostile DLL sideloading proxy loader detected ('{}' paired with process injection APIs).",
                sideload_dll_name
            )
        } else if has_sideload_proxy && (has_webhook_or_telegram || distinct_browser_targets >= 2) {
            format!(
                "Trojan DLL proxy hook detected ('{}' paired with harvesting/exfiltration).",
                sideload_dll_name
            )
        } else if has_injection_import && (has_rwx_section || has_crypter_profile) {
            "Process injection loader pattern: Injection APIs combined with self-modifying or crypter unpacking profile.".to_string()
        } else if distinct_browser_targets >= 2 && has_network_import {
            format!(
                "Hostile multi-browser credential harvesting pattern ({:?}) paired with network socket APIs.",
                browser_families
            )
        } else if has_injection_import && has_network_import {
            "Hostile remote injection pattern: Process injection APIs paired with outbound network capabilities.".to_string()
        } else {
            format!("High-risk multi-vector threat profile observed (Threat Score: {}/100).", threat_score)
        };

        reasons.extend(score_breakdown);
        return RiskEvaluation {
            tier: Tier::HighRisk,
            summary,
            primary_reasons: reasons,
        };
    }

    if threat_score >= 20 {
        let summary = if has_crypter_profile {
            "Suspicious crypter/packer structural anomaly detected.".to_string()
        } else if has_sideload_proxy && has_rwx_section {
            format!("Self-modifying runtime-unpacked proxy DLL detected ('{}').", sideload_dll_name)
        } else if has_sideload_proxy && has_high_entropy_section {
            format!("Packed/encrypted proxy DLL detected ('{}').", sideload_dll_name)
        } else if has_sideload_proxy && sideload_shadows_system {
            format!(
                "DLL search-order hijacking / proxy hook detected ('{}' shadowing system library).",
                sideload_dll_name
            )
        } else if has_webhook_or_telegram {
            "Isolated webhook reference found without confirming harvesting combination.".to_string()
        } else if distinct_browser_targets >= 2 {
            "Multi-browser path strings detected across distinct competitor families.".to_string()
        } else if has_injection_import && has_network_import {
            "Suspicious capability: Process injection APIs paired with outbound network capabilities.".to_string()
        } else if has_injection_import {
            "Process injection API imports detected in executable.".to_string()
        } else if has_powershell_dropper {
            "Hidden or encoded PowerShell invocation fragment observed.".to_string()
        } else if has_rwx_section {
            "RWX memory permissions detected (common in runtime unpackers).".to_string()
        } else if has_codeless_container {
            "Codeless data carrier or encrypted payload container detected (zero executable code sections, near-maximal entropy).".to_string()
        } else if has_extreme_entropy {
            "High-entropy section detected within valid binary (embedded compressed data or encrypted resource blob).".to_string()
        } else {
            "Structural anomalies detected in PE headers or section entropy.".to_string()
        };

        reasons.extend(score_breakdown);
        return RiskEvaluation {
            tier: Tier::Suspicious,
            summary,
            primary_reasons: reasons,
        };
    }

    // — NO INDICATORS FOUND —
    RiskEvaluation {
        tier: Tier::NoIndicatorsFound,
        summary: "Zero threat IOCs or structural anomalies observed.".to_string(),
        primary_reasons: vec![
            "Coherent PE section structure and entropy within normal distribution.".to_string(),
            "Zero matched stealer patterns, exfiltration pipes, or injection anomalies.".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::StringEncoding;

    fn decode_test_str(s: &[u8]) -> String {
        s.iter().map(|&b| b ^ 0xAA).map(|c| c as char).collect()
    }

    #[test]
    fn test_high_risk_webhook_plus_credential() {
        let chrome_path = decode_test_str(b"\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb");
        let evidence = vec![
            Evidence {
                kind: EvidenceKind::DiscordWebhook {
                    url: "https://discord.com/api/webhooks/123/abc".to_string(),
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: chrome_path,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(eval.tier, Tier::HighRisk);
    }

    #[test]
    fn test_suspicious_isolated_webhook() {
        let evidence = vec![Evidence {
            kind: EvidenceKind::DiscordWebhook {
                url: "https://discord.com/api/webhooks/123/abc".to_string(),
                encoding: StringEncoding::Ascii,
            },
            is_threat_signal: true,
            explanation: "test".to_string(),
        }];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(eval.tier, Tier::Suspicious);
    }

    #[test]
    fn test_normal_networking_is_not_suspicious() {
        // Legitimate app with ws2_32 network import alone must NOT be suspicious
        let evidence = vec![Evidence {
            kind: EvidenceKind::NetworkImport {
                dll: "ws2_32.dll".to_string(),
                functions: vec!["socket".to_string(), "connect".to_string()],
            },
            is_threat_signal: true,
            explanation: "test".to_string(),
        }];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(eval.tier, Tier::NoIndicatorsFound);
    }

    #[test]
    fn test_corrupt_mz_is_inconclusive() {
        let hint = FileFormatHint::CorruptExecutable("Corrupted DOS header".to_string());
        let eval = evaluate_risk(&[], false, &hint);
        assert_eq!(eval.tier, Tier::Inconclusive);
    }

    #[test]
    fn test_unsupported_archive_format_is_inconclusive() {
        let hint_7z = FileFormatHint::UnsupportedContainer("7-Zip Archive (.7z)");
        let eval_7z = evaluate_risk(&[], false, &hint_7z);
        assert_eq!(eval_7z.tier, Tier::Inconclusive);

        let hint_rar = FileFormatHint::UnsupportedContainer("RAR Archive (.rar)");
        let eval_rar = evaluate_risk(&[], false, &hint_rar);
        assert_eq!(eval_rar.tier, Tier::Inconclusive);
    }

    #[test]
    fn test_shortcut_format_is_inconclusive_without_target() {
        let hint = FileFormatHint::WindowsShortcut;
        let eval = evaluate_risk(&[], false, &hint);
        assert_eq!(eval.tier, Tier::Inconclusive);
    }

    #[test]
    fn test_cef_electron_app_single_browser_not_suspicious() {
        // CEF/Electron app (Steam, VS Code, FDM): single Chrome string + ws2_32 + CryptUnprotectData + Valid Signature
        let chrome_path = decode_test_str(b"\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb");
        let evidence = vec![
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: chrome_path,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::NetworkImport {
                    dll: "ws2_32.dll".to_string(),
                    functions: vec!["socket".to_string(), "connect".to_string()],
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::SensitiveApiImport {
                    dll: "crypt32.dll".to_string(),
                    functions: vec!["CryptUnprotectData".to_string()],
                },
                is_threat_signal: false,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::SignatureStatus {
                    valid: true,
                    signer: None,
                    detail: "Signed binary".to_string(),
                },
                is_threat_signal: false,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::NoIndicatorsFound,
            "Signed CEF/Electron app with single browser framework path must yield NO INDICATORS FOUND"
        );
    }

    #[test]
    fn test_multi_browser_harvester_with_network_is_high_risk() {
        // Multi-browser harvester targeting Chrome + Firefox + Edge + networking
        let chrome_path = decode_test_str(b"\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb");
        let firefox_cookies = decode_test_str(b"\xe7\xc5\xd0\xc3\xc6\xc6\xcb\xf6\xec\xc3\xd8\xcf\xcc\xc5\xd2\xf6\xfa\xd8\xc5\xcc\xc3\xc6\xcf\xd9\xf6\xc9\xc5\xc5\xc1\xc3\xcf\xd9\x84\xd9\xdb\xc6\xc3\xde\xcf");
        let edge_path = decode_test_str(b"\xe7\xc3\xc9\xd8\xc5\xd9\xc5\xcc\xde\xf6\xef\xce\xcd\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb");

        let evidence = vec![
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: chrome_path,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: firefox_cookies,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: edge_path,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::NetworkImport {
                    dll: "ws2_32.dll".to_string(),
                    functions: vec!["send".to_string(), "connect".to_string()],
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::HighRisk,
            "Multi-browser credential harvesting across 3 distinct families with networking must be HIGH RISK"
        );
    }

    #[test]
    fn test_multi_browser_without_network_is_suspicious() {
        // Multi-browser targeting 2 competitor families without networking
        let chrome_path = decode_test_str(b"\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb");
        let firefox_key4 = decode_test_str(b"\xe7\xc5\xd0\xc3\xc6\xc6\xcb\xf6\xec\xc3\xd8\xcf\xcc\xc5\xd2\xf6\xfa\xd8\xc5\xcc\xc3\xc6\xcf\xd9\xf6\xc1\xcf\xd3\x9e\x84\xce\xc8");

        let evidence = vec![
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: chrome_path,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::CredentialPath {
                    path: firefox_key4,
                    encoding: StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::Suspicious,
            "Targeting 2 competitor browser families without confirmed exfiltration must be SUSPICIOUS"
        );
    }

    #[test]
    fn test_process_injection_plus_rwx_is_high_risk() {
        let evidence = vec![
            Evidence {
                kind: EvidenceKind::InjectionImport {
                    dll: "kernel32.dll".to_string(),
                    functions: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string()],
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::RwxSection {
                    name: ".text".to_string(),
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::HighRisk,
            "Process injection APIs combined with self-modifying RWX section must be HIGH RISK"
        );
    }

    #[test]
    fn test_game_resource_section_entropy_not_suspicious() {
        // High entropy in non-executable resource section (.rsrc) must NOT trigger SUSPICIOUS
        let evidence = vec![Evidence {
            kind: EvidenceKind::HighEntropySection {
                name: ".rsrc".to_string(),
                entropy: 7.94,
            },
            is_threat_signal: false,
            explanation: "Resource section with compressed images".to_string(),
        }];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::NoIndicatorsFound,
            "Non-executable .rsrc section with compressed image entropy must yield NO INDICATORS FOUND"
        );
    }

    #[test]
    fn test_packed_code_section_entropy_is_suspicious() {
        // High entropy in executable or packed section MUST trigger SUSPICIOUS
        let evidence = vec![Evidence {
            kind: EvidenceKind::HighEntropySection {
                name: ".text".to_string(),
                entropy: 7.85,
            },
            is_threat_signal: true,
            explanation: "Executable section with high entropy".to_string(),
        }];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::Suspicious,
            "Executable section with high entropy must yield SUSPICIOUS"
        );
    }

    #[test]
    fn test_dll_proxy_hook_shadowing_system_is_suspicious() {
        // DLL shadowing system library (e.g. version.dll, dxgi.dll) alone must be SUSPICIOUS
        let evidence = vec![Evidence {
            kind: EvidenceKind::DllProxyHook {
                dll_name: "version.dll".to_string(),
                shadows_system: true,
            },
            is_threat_signal: true,
            explanation: "test".to_string(),
        }];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::Suspicious,
            "Proxy DLL shadowing system library alone must yield SUSPICIOUS"
        );
        assert_eq!(
            eval.summary,
            "DLL search-order hijacking / proxy hook detected ('version.dll' shadowing system library)."
        );
    }

    #[test]
    fn test_platform_proxy_hook_alone_is_no_indicators_found() {
        // Platform emulator/proxy hook (steam_api) alone without system shadowing remains NO INDICATORS FOUND
        let evidence = vec![Evidence {
            kind: EvidenceKind::DllProxyHook {
                dll_name: "steam_api64.dll".to_string(),
                shadows_system: false,
            },
            is_threat_signal: true,
            explanation: "test".to_string(),
        }];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::NoIndicatorsFound,
            "Platform hook alone without malicious payload must yield NO INDICATORS FOUND"
        );
    }

    #[test]
    fn test_injection_plus_network_synergy_and_mitigation_rejection() {
        // Process injection APIs (CreateRemoteThread) paired with outbound network (ws2_32.dll)
        let evidence = vec![
            Evidence {
                kind: EvidenceKind::InjectionImport {
                    dll: "kernel32.dll".to_string(),
                    functions: vec!["CreateRemoteThread".to_string(), "VirtualAllocEx".to_string()],
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::NetworkImport {
                    dll: "ws2_32.dll".to_string(),
                    functions: vec!["connect".to_string(), "send".to_string()],
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::SignatureStatus {
                    valid: true,
                    signer: None,
                    detail: "Signed".to_string(),
                },
                is_threat_signal: false,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        // Score: +25 (injection) + 20 (synergy: injection + network) = 45 -> Suspicious
        // is_confirmed_hostile prevents digital signature mitigation discount
        assert_eq!(eval.tier, Tier::Suspicious);
        assert!(eval.primary_reasons.iter().any(|r| r.contains("+20 Synergy: Process injection APIs paired with outbound network capabilities")));
        assert!(!eval.primary_reasons.iter().any(|r| r.contains("-15 Mitigation")));
        assert_eq!(
            eval.summary,
            "Suspicious capability: Process injection APIs paired with outbound network capabilities."
        );
    }

    #[test]
    fn test_dll_proxy_hook_plus_injection_is_high_risk() {
        // Proxy DLL combined with process injection APIs must trigger HIGH RISK
        let evidence = vec![
            Evidence {
                kind: EvidenceKind::DllProxyHook {
                    dll_name: "version.dll".to_string(),
                    shadows_system: true,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::InjectionImport {
                    dll: "kernel32.dll".to_string(),
                    functions: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string()],
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::HighRisk,
            "Proxy DLL with injection imports must yield HIGH RISK"
        );
        assert!(eval.summary.contains("Hostile DLL sideloading proxy loader"));
    }

    #[test]
    fn test_dll_proxy_hook_plus_rwx_is_suspicious() {
        // Proxy DLL combined with self-modifying RWX memory must trigger SUSPICIOUS
        let evidence = vec![
            Evidence {
                kind: EvidenceKind::DllProxyHook {
                    dll_name: "steam_api64.dll".to_string(),
                    shadows_system: false,
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
            Evidence {
                kind: EvidenceKind::RwxSection {
                    name: "WUS1".to_string(),
                },
                is_threat_signal: true,
                explanation: "test".to_string(),
            },
        ];
        let eval = evaluate_risk(&evidence, true, &FileFormatHint::PeExecutable);
        assert_eq!(
            eval.tier,
            Tier::Suspicious,
            "Proxy DLL with RWX section must yield SUSPICIOUS"
        );
        assert!(eval.summary.contains("Self-modifying runtime-unpacked proxy DLL"));
    }
}

