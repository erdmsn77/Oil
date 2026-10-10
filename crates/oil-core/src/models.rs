//! # Oil Core — Data Models & Contracts
//!
//! Every module in oil-core produces and consumes these types.
//! The CLI layer reads them and renders the forensic dossier.
//! No UI logic, no terminal colors, no side-effects here.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ──────────────────────────────────────────────
//  VERDICT TIERS (GDD §2)
// ──────────────────────────────────────────────

/// The 4 forensic decision tiers.
/// Ordered by severity — `HighRisk` is the worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    /// Zero matched threat IOCs, zero structural anomalies.
    NoIndicatorsFound = 0,
    /// Scan could not be completed (encrypted archive, corrupt PE, limits).
    Inconclusive = 1,
    /// Anomalies detected but no confirmed hostile combination.
    Suspicious = 2,
    /// Direct smoking-gun artifacts or high-confidence pattern match.
    HighRisk = 3,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::NoIndicatorsFound => write!(f, "NO INDICATORS FOUND"),
            Tier::Inconclusive => write!(f, "INCONCLUSIVE"),
            Tier::Suspicious => write!(f, "SUSPICIOUS"),
            Tier::HighRisk => write!(f, "HIGH RISK"),
        }
    }
}

// ──────────────────────────────────────────────
//  EVIDENCE ITEMS
// ──────────────────────────────────────────────

/// Category of a single piece of evidence found during analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceKind {
    // — IOC hits (Stage 2) —
    /// Discord webhook URL reference found in binary.
    DiscordWebhook { url: String, encoding: StringEncoding },
    /// Telegram bot token reference found.
    TelegramToken { token: String, encoding: StringEncoding },
    /// Cryptocurrency wallet address pattern.
    CryptoWallet { address: String, coin: String, encoding: StringEncoding },
    /// Browser credential database path reference.
    CredentialPath { path: String, encoding: StringEncoding },
    /// Encoded PowerShell command reference.
    PowerShellCommand { fragment: String, encoding: StringEncoding },
    /// YARA rule match.
    YaraMatch { rule_name: String, namespace: String },

    // — PE structural anomalies (Stage 1) —
    /// Section with Shannon entropy above threshold.
    HighEntropySection { name: String, entropy: f64 },
    /// Section with Read-Write-Execute permissions.
    RwxSection { name: String },
    /// Overlay bytes appended past the PE image end.
    Overlay { size_bytes: u64 },
    /// Suspicious network-related DLL import in an offline tool context.
    NetworkImport { dll: String, functions: Vec<String> },
    /// Injection-related API imports (e.g. VirtualAllocEx, WriteProcessMemory).
    InjectionImport { dll: String, functions: Vec<String> },
    /// Sensitive cryptographic or DPAPI API imports (e.g. CryptUnprotectData).
    SensitiveApiImport { dll: String, functions: Vec<String> },
    /// Digital signature status.
    SignatureStatus { valid: bool, signer: Option<String>, detail: String },
    /// Crypter structural profile match (tiny stub + large encrypted resource).
    CrypterProfile { indicators: Vec<String> },
    /// DLL Sideloading / Proxy Hook indicator (shadows a system or platform library).
    DllProxyHook { dll_name: String, shadows_system: bool },

    // — Informational (not threat signals) —
    /// Purely informational note for user education.
    InfoNote { message: String },
}

/// How the string was encoded in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    XorSingleByte { key: u8 },
}

impl std::fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringEncoding::Ascii => write!(f, "ASCII"),
            StringEncoding::Utf16Le => write!(f, "UTF-16LE"),
            StringEncoding::XorSingleByte { key } => write!(f, "XOR(0x{:02X})", key),
        }
    }
}

/// A single piece of forensic evidence with its severity contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// What was found.
    pub kind: EvidenceKind,
    /// Is this a positive threat signal or a neutral/informational observation?
    pub is_threat_signal: bool,
    /// Human-readable explanation for the output dossier.
    pub explanation: String,
}

// ──────────────────────────────────────────────
//  PE SECTION INFO
// ──────────────────────────────────────────────

/// Structural information about a single PE section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub pointer_to_raw_data: u64,
    pub virtual_address: u64,
    pub entropy: f64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

// ──────────────────────────────────────────────
//  FILE IDENTIFICATION
// ──────────────────────────────────────────────

/// Basic identification of the scanned target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIdentity {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub blake3: String,
}

// ──────────────────────────────────────────────
//  PE AUTOPSY RESULT
// ──────────────────────────────────────────────

/// Full result of PE structural analysis (Stage 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAutopsy {
    /// Is this actually a valid PE file?
    pub is_pe: bool,
    /// Is 64-bit?
    pub is_64bit: bool,
    /// Entry point RVA.
    pub entry_point: u64,
    /// All sections with entropy and permissions.
    pub sections: Vec<SectionInfo>,
    /// Imported DLLs and their functions.
    pub imports: Vec<ImportEntry>,
    /// Exported functions (for DLL analysis).
    pub exports: Vec<String>,
    /// Overlay size (bytes past PE image end). 0 means no overlay.
    pub overlay_size: u64,
    /// Digital signature status.
    pub signature_valid: Option<bool>,
    pub signature_signer: Option<String>,
    /// Authenticode security directory (file offset, size in bytes).
    pub security_directory: Option<(u64, u64)>,
}

/// A single imported DLL and its function list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<String>,
}

// ──────────────────────────────────────────────
//  SCAN REPORT (final output of oil scan)
// ──────────────────────────────────────────────

/// The complete forensic report for a single scanned target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Target file identification.
    pub identity: FileIdentity,
    /// PE structural analysis (None if not a PE file).
    pub autopsy: Option<PeAutopsy>,
    /// All evidence items collected across all stages.
    pub evidence: Vec<Evidence>,
    /// Final verdict tier (computed by risk engine).
    pub verdict: Tier,
    /// Factual summary for the verdict.
    pub verdict_summary: String,
    /// Files scanned in this run.
    pub files_scanned: u32,
    /// Files skipped (with reasons).
    pub files_skipped: u32,
    /// Reasons for skipped files.
    pub skip_reasons: Vec<String>,
}

// ──────────────────────────────────────────────
//  DIFF REPORT (output of oil diff — v1 later)
// ──────────────────────────────────────────────

/// Classification of a patched byte region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchCategory {
    /// Conditional branch inversion, NOP padding, force-return success.
    DrmBypass,
    /// Jump/call to new section, entry point hijack, new TLS callback.
    CodeInjection,
    /// Authenticode security directory certificate table.
    DigitalSignature,
    /// Does not match known patterns.
    Unknown,
}

impl std::fmt::Display for PatchCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchCategory::DrmBypass => write!(f, "DRM_BYPASS"),
            PatchCategory::CodeInjection => write!(f, "CODE_INJECTION"),
            PatchCategory::DigitalSignature => write!(f, "DIGITAL_SIGNATURE"),
            PatchCategory::Unknown => write!(f, "UNKNOWN_PATCH"),
        }
    }
}

/// A single contiguous range of altered bytes between original and patched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRegion {
    /// Offset in the file where the patch starts.
    pub offset: u64,
    /// Section name containing this patch.
    pub section: String,
    /// Number of bytes altered.
    pub size: u64,
    /// Original bytes (hex string).
    pub original_bytes: String,
    /// Patched bytes (hex string).
    pub patched_bytes: String,
    /// Disassembled instruction summary (if in code section).
    pub disassembly: Option<String>,
    /// Semantic classification.
    pub category: PatchCategory,
}

/// Complete diff report between original and patched binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub original: FileIdentity,
    pub patched: FileIdentity,
    /// Were new sections added?
    pub new_sections: Vec<String>,
    /// Was the entry point changed?
    pub entry_point_changed: bool,
    /// Were new imports added?
    pub new_imports: Vec<ImportEntry>,
    /// Was overlay added?
    pub overlay_delta: i64,
    /// All patch regions with semantic classification.
    pub patches: Vec<PatchRegion>,
    /// SHA-256 of the raw delta (delta fingerprint).
    pub delta_fingerprint: String,
    /// Final verdict.
    pub verdict: Tier,
    pub verdict_summary: String,
}
