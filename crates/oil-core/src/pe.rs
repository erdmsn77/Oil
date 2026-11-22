//! # PE Autopsy — Structural Binary Analysis
//!
//! GDD §3.2 — Stage 1: PE Autopsy
//! Zero-copy PE parsing: sections, entropy, overlay, imports, exports.

use crate::io::shannon_entropy;
use crate::models::{Evidence, EvidenceKind, ImportEntry, PeAutopsy, SectionInfo};
use goblin::pe::PE;

/// Known networking DLLs that should not appear in offline utilities.
const NETWORK_DLLS: &[&str] = &[
    "ws2_32.dll",
    "wsock32.dll",
    "wininet.dll",
    "winhttp.dll",
    "urlmon.dll",
];

/// Known remote process injection APIs (cross-process memory allocation/write/execution).
const INJECTION_APIS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
];

/// Known credential/crypto APIs.
const CREDENTIAL_APIS: &[&str] = &["CryptUnprotectData", "CertOpenStore", "CertOpenSystemStore"];

/// Minimum import set that suggests a crypter stub.
const CRYPTER_MINIMAL_IMPORTS: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
];

/// High entropy threshold for section anomaly.
const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

/// Known packer or crypter section name prefixes.
const PACKER_SECTION_PREFIXES: &[&str] = &[
    "upx", "wus", "mpress", "aspack", "themida", "vmp", "pec", "nsp", "fsg", "mew", "pack",
    "baymax",
];

/// Checks if a section name matches known packer/crypter signatures.
fn is_packer_section_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let trimmed = lower.trim_start_matches('.').trim();
    PACKER_SECTION_PREFIXES
        .iter()
        .any(|&p| trimmed.starts_with(p))
}

/// Core Steamworks C-API export names.
pub const STEAMWORKS_CORE_EXPORTS: &[&str] = &[
    "SteamAPI_Init",
    "SteamAPI_Shutdown",
    "SteamAPI_RestartAppIfNecessary",
    "SteamAPI_ReleaseCurrentThreadMemory",
    "SteamAPI_RunCallbacks",
    "SteamAPI_IsSteamRunning",
    "SteamClient",
    "SteamUser",
    "SteamFriends",
    "SteamUtils",
    "SteamMatchmaking",
    "SteamUserStats",
    "SteamApps",
    "SteamNetworking",
    "SteamRemoteStorage",
    "SteamScreenshots",
    "SteamHTTP",
    "SteamController",
    "SteamUGC",
    "SteamInput",
    "SteamGameServer_Init",
    "SteamGameServer_Shutdown",
    "SteamGameServer_RunCallbacks",
    "CreateInterface",
    "SteamInternal_CreateInterface",
    "SteamInternal_ContextInit",
];

/// Core Epic Online Services (EOS) C-API export names.
pub const EOS_CORE_EXPORTS: &[&str] = &[
    "EOS_Initialize",
    "EOS_Shutdown",
    "EOS_Platform_Create",
    "EOS_Platform_Release",
    "EOS_Platform_Tick",
    "EOS_Platform_GetEcomInterface",
    "EOS_Platform_GetAuthInterface",
    "EOS_Platform_GetConnectInterface",
    "EOS_Platform_GetAchievementsInterface",
    "EOS_Platform_GetFriendsInterface",
    "EOS_Platform_GetUserInfoInterface",
    "EOS_Platform_GetPresenceInterface",
    "EOS_Platform_GetStatsInterface",
    "EOS_Platform_GetLeaderboardsInterface",
    "EOS_Platform_GetMetricsInterface",
    "EOS_Platform_GetPlayerDataStorageInterface",
    "EOS_Platform_GetTitleStorageInterface",
    "EOS_Platform_GetUIInterface",
    "EOS_Platform_GetP2PInterface",
    "EOS_Platform_GetSessionsInterface",
    "EOS_Platform_GetLobbyInterface",
    "EOS_Platform_GetAntiCheatClientInterface",
    "EOS_Platform_GetAntiCheatServerInterface",
    "EOS_EResult_ToString",
    "EOS_ByteArray_ToString",
    "EOS_Logging_SetCallback",
];

/// Detects gaming platform / Steam / Epic Online Services emulator profile (e.g. Goldberg, ColdAPI, ScreamAPI, Nemirtingas).
///
/// An emulator binary typically:
/// 1. Exports multiple Steamworks or EOS C-API functions (or sits behind a proxy hook).
/// 2. Contains specific configuration and redirection string anchors (`steam_settings`,
///    `EOS_settings`, `ScreamAPI`, `NemirtingasEpicEmu`, `epic_emu.ini`, `disable_networking`, etc.).
pub fn detect_emulator_profile(exports: &[String], data: &[u8]) -> Option<Evidence> {
    use aho_corasick::{AhoCorasick, MatchKind};
    use std::sync::OnceLock;

    static SCANNER: OnceLock<AhoCorasick> = OnceLock::new();
    let scanner = SCANNER.get_or_init(|| {
        let patterns = &[
            // Steam / Goldberg / ColdAPI (0..=9)
            "steam_settings",
            "steam_interfaces.txt",
            "steam_appid.txt",
            "disable_networking",
            "local_save",
            "goldberg",
            "coldapi",
            "coldstorage",
            "smartsteamemu",
            "steam_emu.ini",
            // Epic Games / EOS / ScreamAPI / Nemirtingas (10..=17)
            "eos_settings",
            "epic_emu.ini",
            "nemirtingasepicemu",
            "screamapi",
            "acidicoala",
            "koaloader",
            "eos_interfaces.txt",
            "_o.dll",
            // Generic author markers (18)
            "nemirtingas",
        ];
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(patterns)
            .expect("Valid emulator patterns")
    });

    let mut matched_indices = std::collections::BTreeSet::new();
    for mat in scanner.find_iter(data) {
        matched_indices.insert(mat.pattern().as_usize());
    }

    let mut indicators = Vec::new();
    for &idx in &matched_indices {
        let desc = match idx {
            0 => "Goldberg/Generic 'steam_settings' configuration folder reference",
            1 => "Steamworks interface definition file ('steam_interfaces.txt')",
            2 => "Steam AppID configuration hook ('steam_appid.txt')",
            3 => "Goldberg 'disable_networking' offline lock",
            4 => "Goldberg local offline save redirection ('local_save')",
            5 => "Goldberg Steam Emulator binary stamp",
            6 => "ColdAPI Steam Emulator marker",
            7 => "ColdAPI local storage redirection ('ColdStorage')",
            8 => "SmartSteamEmu emulator marker",
            9 => "ALI213/CODEX configuration file ('steam_emu.ini')",
            10 => "Epic Online Services 'EOS_settings' configuration folder reference",
            11 => "Epic Emulator configuration file ('epic_emu.ini')",
            12 => "Nemirtingas Epic Emulator metadata ('NemirtingasEpicEmu')",
            13 => "ScreamAPI (Epic Online Services DLC unlocker) marker",
            14 => "Acidicoala (ScreamAPI / Koaloader author) signature",
            15 => "Koaloader universal proxy hook signature",
            16 => "EOS interface definition file ('eos_interfaces.txt')",
            17 => "Proxy DLL redirection target marker ('_o.dll')",
            18 => "Nemirtingas emulator marker",
            _ => "Unknown emulator marker",
        };
        indicators.push(desc.to_string());
    }

    let steam_export_matches = exports
        .iter()
        .filter(|exp| {
            exp.starts_with("SteamAPI_")
                || exp.starts_with("SteamInternal_")
                || exp.starts_with("SteamGameServer_")
                || STEAMWORKS_CORE_EXPORTS.contains(&exp.as_str())
        })
        .count();

    if steam_export_matches > 0 {
        indicators.push(format!(
            "Exports {} Steamworks C-API functions",
            steam_export_matches
        ));
    }

    let eos_export_matches = exports
        .iter()
        .filter(|exp| exp.starts_with("EOS_") || EOS_CORE_EXPORTS.contains(&exp.as_str()))
        .count();

    if eos_export_matches > 0 {
        indicators.push(format!(
            "Exports {} Epic Online Services (EOS) C-API functions",
            eos_export_matches
        ));
    }

    // Qualify as emulator profile:
    // 1. Steamworks profile: >=3 Steam exports OR (>=1 Steam export + Steam marker) OR >=2 Steam markers
    let is_steam_profile = steam_export_matches >= 3
        || (steam_export_matches >= 1
            && (matched_indices.range(0..=9).next().is_some() || matched_indices.contains(&18)))
        || matched_indices.range(0..=9).count() >= 2;

    // 2. EOS profile: >=3 EOS exports OR (>=1 EOS export + EOS marker) OR >=2 EOS markers
    let is_eos_profile = eos_export_matches >= 3
        || (eos_export_matches >= 1 && matched_indices.range(10..=17).next().is_some())
        || matched_indices.range(10..=17).count() >= 2;

    if !is_steam_profile && !is_eos_profile && matched_indices.len() < 2 {
        return None;
    }

    let name = if matched_indices.contains(&13) || matched_indices.contains(&14) {
        "ScreamAPI (Epic DLC Unlocker)".to_string()
    } else if matched_indices.contains(&12) {
        "Nemirtingas Epic Games Emulator".to_string()
    } else if is_eos_profile {
        if eos_export_matches >= 3 {
            "Epic Online Services (EOS) Emulator".to_string()
        } else {
            "Epic Games Platform Emulator".to_string()
        }
    } else if matched_indices.contains(&5)
        || matched_indices.contains(&3)
        || matched_indices.contains(&4)
        || matched_indices.contains(&0)
    {
        "Goldberg Steam Emulator".to_string()
    } else if matched_indices.contains(&6) || matched_indices.contains(&7) {
        "ColdAPI Steam Emulator".to_string()
    } else if matched_indices.contains(&8) {
        "SmartSteamEmu".to_string()
    } else if matched_indices.contains(&18) {
        "Nemirtingas Steam Emulator".to_string()
    } else if matched_indices.contains(&9) {
        "CODEX/ALI213 Steam Emulator".to_string()
    } else if steam_export_matches >= 3 {
        "Steamworks C-API Emulator / Wrapper".to_string()
    } else {
        "Gaming Platform Emulator".to_string()
    };

    Some(Evidence {
        kind: EvidenceKind::EmulatorProfile {
            name: name.clone(),
            is_legitimate: true,
            indicators: indicators.clone(),
        },
        is_threat_signal: false,
        explanation: format!(
            "Identified {} with {} forensic indicators. Benign offline gaming emulator profile.",
            name,
            indicators.len()
        ),
    })
}

/// Perform a full PE autopsy on raw file bytes.
/// Returns the autopsy result and any evidence items discovered.
pub fn analyze_pe(data: &[u8]) -> Option<(PeAutopsy, Vec<Evidence>)> {
    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return None,
    };

    let mut evidence = Vec::new();

    // Check if binary is a .NET / CLR managed assembly
    // 1. Data Directory index 14 is IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR Header)
    // 2. Or imports mscoree.dll (_CorExeMain / _CorDllMain)
    let is_clr_binary = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|opt| {
            opt.data_directories
                .data_directories
                .get(14)
                .and_then(|entry| entry.as_ref())
                .map(|(_, d)| d.virtual_address > 0 && d.size > 0)
        })
        .unwrap_or(false)
        || pe
            .imports
            .iter()
            .any(|imp| imp.dll.to_lowercase() == "mscoree.dll");

    // — Sections —
    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(
                &s.name[..s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len())],
            )
            .to_string();

            let offset = s.pointer_to_raw_data as usize;
            let size = s.size_of_raw_data as usize;
            let end = offset.saturating_add(size);
            let section_data = if end <= data.len() {
                &data[offset..end]
            } else if offset < data.len() {
                &data[offset..]
            } else {
                &[]
            };

            let entropy = shannon_entropy(section_data);
            let chars = s.characteristics;
            let readable = chars & 0x4000_0000 != 0;
            let writable = chars & 0x8000_0000 != 0;
            let executable = chars & 0x2000_0000 != 0;

            SectionInfo {
                name,
                virtual_size: s.virtual_size as u64,
                raw_size: s.size_of_raw_data as u64,
                pointer_to_raw_data: s.pointer_to_raw_data as u64,
                virtual_address: s.virtual_address as u64,
                entropy,
                readable,
                writable,
                executable,
            }
        })
        .collect();

    // Check for high-entropy sections
    for section in &sections {
        if section.entropy > HIGH_ENTROPY_THRESHOLD {
            let is_packer = is_packer_section_name(&section.name);
            let lower_name = section.name.trim().to_lowercase();
            let is_rsrc =
                lower_name == ".rsrc" || lower_name.starts_with(".rsrc") || lower_name == "rsrc";
            let is_extreme_entropy = section.entropy >= 7.95 && !is_rsrc;

            // High entropy is an active threat signal if the section contains executable code,
            // matches known packer signatures (UPX, WUS, Baymax, etc.), or exhibits near-maximal
            // entropy (>= 7.95) outside resource sections (e.g. codeless encrypted payload blocks).
            // Non-executable resource sections (.rsrc with compressed splash/icons)
            // in modern games and desktop apps have high entropy naturally without being malicious.
            // In .NET / CLR assemblies, the .text section houses dense CLI metadata streams (#~, #Strings,
            // #US, #Blob), method headers, and IL bytecodes which naturally reach up to 7.85 entropy without packing.
            let is_threat = if is_clr_binary
                && !is_packer
                && section.name == ".text"
                && section.entropy <= 7.85
            {
                false
            } else {
                section.executable || is_packer || is_extreme_entropy
            };

            let explanation = if is_threat {
                if is_extreme_entropy && !section.executable && !is_packer {
                    format!(
                        "Non-resource data section '{}' exhibits near-maximal entropy ({:.2} >= 7.95). \
                         Indicates encrypted shellcode, packed binary payload, or codeless data block.",
                        section.name, section.entropy
                    )
                } else {
                    format!(
                        "Executable or packed section '{}' has {:.2} entropy (threshold: {:.1}). \
                         High entropy indicates packed, encrypted, or obfuscated machine code.",
                        section.name, section.entropy, HIGH_ENTROPY_THRESHOLD
                    )
                }
            } else if is_clr_binary && section.name == ".text" {
                format!(
                    "Executable section '{}' in .NET/CLR assembly has {:.2} entropy. \
                     Consistent with dense CLI metadata streams and IL bytecode.",
                    section.name, section.entropy
                )
            } else {
                format!(
                    "Resource/data section '{}' has {:.2} entropy (threshold: {:.1}). \
                     Consistent with compressed images, audio, or container assets.",
                    section.name, section.entropy, HIGH_ENTROPY_THRESHOLD
                )
            };

            evidence.push(Evidence {
                kind: EvidenceKind::HighEntropySection {
                    name: section.name.clone(),
                    entropy: section.entropy,
                },
                is_threat_signal: is_threat,
                explanation,
            });
        }

        // RWX section
        if section.readable && section.writable && section.executable {
            evidence.push(Evidence {
                kind: EvidenceKind::RwxSection {
                    name: section.name.clone(),
                },
                is_threat_signal: true,
                explanation: format!(
                    "Section '{}' has Read-Write-Execute permissions. \
                     Self-modifying code or runtime unpacking likely.",
                    section.name
                ),
            });
        }
    }

    // — Abnormal section layout detection —
    let has_executable_section = sections.iter().any(|s| s.executable);
    let total_sections = sections.len();
    if !sections.is_empty() && !has_executable_section {
        let max_entropy = sections.iter().map(|s| s.entropy).fold(0.0f64, f64::max);
        if max_entropy > 7.5 {
            evidence.push(Evidence {
                kind: EvidenceKind::HighEntropySection {
                    name: "NO_EXEC_CODE".to_string(),
                    entropy: max_entropy,
                },
                is_threat_signal: true,
                explanation: format!(
                    "Abnormal section structure: Zero executable (.text) sections in binary (Total sections: {}). \
                     Highest section entropy is {:.2}. Indicates codeless data carrier or encrypted payload container.",
                    total_sections, max_entropy
                ),
            });
        }
    }

    // — Imports —
    let mut import_map: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for imp in &pe.imports {
        let dll_name = imp.dll.to_lowercase();
        import_map
            .entry(dll_name)
            .or_default()
            .push(imp.name.to_string());
    }

    let mut imports = Vec::new();
    for (dll_name, functions) in import_map {
        // Check for network imports
        if NETWORK_DLLS.iter().any(|&d| dll_name == d) {
            evidence.push(Evidence {
                kind: EvidenceKind::NetworkImport {
                    dll: dll_name.clone(),
                    functions: functions.clone(),
                },
                is_threat_signal: true,
                explanation: format!(
                    "Imports networking library '{}'. \
                     Offline tools should not need socket or HTTP APIs.",
                    dll_name
                ),
            });
        }

        // Check for injection APIs
        let injection_funcs: Vec<String> = functions
            .iter()
            .filter(|f| INJECTION_APIS.iter().any(|&api| f.contains(api)))
            .cloned()
            .collect();
        if !injection_funcs.is_empty() {
            evidence.push(Evidence {
                kind: EvidenceKind::InjectionImport {
                    dll: dll_name.clone(),
                    functions: injection_funcs,
                },
                is_threat_signal: true,
                explanation: format!(
                    "Imports process injection APIs from '{}'. \
                     These are commonly used for code injection attacks.",
                    dll_name
                ),
            });
        }

        // Check for cryptographic / certificate / DPAPI APIs (informational, not standalone threat)
        let cred_funcs: Vec<String> = functions
            .iter()
            .filter(|f| CREDENTIAL_APIS.iter().any(|&api| f.contains(api)))
            .cloned()
            .collect();
        if !cred_funcs.is_empty() {
            evidence.push(Evidence {
                kind: EvidenceKind::SensitiveApiImport {
                    dll: dll_name.clone(),
                    functions: cred_funcs.clone(),
                },
                is_threat_signal: false,
                explanation: format!(
                    "Imports cryptographic / certificate APIs from '{}' ({:?}).",
                    dll_name, cred_funcs
                ),
            });
        }

        imports.push(ImportEntry {
            dll_name,
            functions,
        });
    }

    // — Crypter profile detection —
    let total_import_count: usize = imports.iter().map(|i| i.functions.len()).sum();
    let has_only_loader = total_import_count <= 5
        && imports.iter().all(|i| {
            i.functions.iter().all(|f| {
                CRYPTER_MINIMAL_IMPORTS.iter().any(|&api| f.contains(api))
                    || f.starts_with("Ordinal")
            })
        });

    let has_high_entropy_section = sections.iter().any(|s| s.entropy > HIGH_ENTROPY_THRESHOLD);

    if has_only_loader && has_high_entropy_section && !imports.is_empty() && !is_clr_binary {
        let mut indicators = vec![
            "Minimal import table (only loader APIs)".to_string(),
            "High-entropy section present".to_string(),
        ];
        if total_import_count <= 3 {
            indicators.push(format!(
                "Only {} total imported functions",
                total_import_count
            ));
        }
        evidence.push(Evidence {
            kind: EvidenceKind::CrypterProfile { indicators },
            is_threat_signal: true,
            explanation: "Structural profile matches known crypter/packer stubs: \
                         minimal imports combined with encrypted data sections."
                .to_string(),
        });
    }

    // — Exports —
    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| n.to_string()))
        .collect();

    // — Gaming Platform / Steam Emulator Profile —
    if let Some(emu_evidence) = detect_emulator_profile(&exports, data) {
        evidence.push(emu_evidence);
    }

    // — Overlay (isolating Authenticode Certificate Table to prevent false positives) —
    let last_section_end = pe
        .sections
        .iter()
        .map(|s| (s.pointer_to_raw_data as u64).saturating_add(s.size_of_raw_data as u64))
        .max()
        .unwrap_or(0);

    // Security Directory (index 4 in Data Directories)
    // In Microsoft PE/COFF specification, VirtualAddress in directory 4 is the RAW FILE OFFSET
    // where the Attribute Certificate Table begins.
    let (cert_table_offset, cert_table_size) = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|opt| {
            opt.data_directories
                .data_directories
                .get(4)
                .and_then(|entry| entry.as_ref())
                .map(|(_, d)| (d.virtual_address as u64, d.size as u64))
        })
        .unwrap_or((0, 0));

    let data_len = data.len() as u64;
    let has_security_dir_entry = cert_table_offset > 0 || cert_table_size > 0;
    let cert_table_in_bounds = cert_table_offset > 0
        && cert_table_size >= 8
        && cert_table_offset
            .checked_add(cert_table_size)
            .map(|end| end <= data_len)
            .unwrap_or(false);

    let cert_table_end = if cert_table_in_bounds {
        cert_table_offset.saturating_add(cert_table_size)
    } else {
        0
    };

    let image_end = last_section_end.max(cert_table_end);

    let overlay_size = if data_len > image_end && image_end > 0 {
        data_len.saturating_sub(image_end)
    } else {
        0
    };

    if overlay_size > 1024 {
        // Only flag meaningful non-certificate overlays (> 1 KB)
        let overlay_data = usize::try_from(image_end)
            .ok()
            .and_then(|offset| data.get(offset..))
            .unwrap_or(&[]);
        let overlay_entropy = shannon_entropy(overlay_data);

        let mut explanation = format!(
            "Unmapped overlay detected: {} bytes appended past PE image end.",
            overlay_size
        );
        if overlay_entropy > HIGH_ENTROPY_THRESHOLD {
            explanation.push_str(&format!(
                " Overlay entropy: {:.2} (high — may contain encrypted payload).",
                overlay_entropy
            ));
        }

        evidence.push(Evidence {
            kind: EvidenceKind::Overlay {
                size_bytes: overlay_size,
            },
            is_threat_signal: overlay_entropy > HIGH_ENTROPY_THRESHOLD,
            explanation,
        });
    }

    // Static PE parsing can only observe the presence of an embedded certificate table;
    // cryptographic validity must be established by WinVerifyTrust in scan_path.
    if cert_table_in_bounds {
        evidence.push(Evidence {
            kind: EvidenceKind::SignatureStatus {
                valid: false,
                signer: None,
                detail: format!(
                    "Unverified Authenticode security directory ({} bytes at offset 0x{:X})",
                    cert_table_size, cert_table_offset
                ),
            },
            is_threat_signal: false,
            explanation: format!(
                "Binary contains embedded Authenticode certificate structure ({} bytes; not cryptographically verified in static/in-memory analysis).",
                cert_table_size
            ),
        });
    } else if has_security_dir_entry {
        evidence.push(Evidence {
            kind: EvidenceKind::SignatureStatus {
                valid: false,
                signer: None,
                detail: format!(
                    "Malformed or out-of-bounds Authenticode security directory ({} bytes at offset 0x{:X})",
                    cert_table_size, cert_table_offset
                ),
            },
            is_threat_signal: false,
            explanation: "PE security directory entry is malformed, truncated, or points outside file bounds.".to_string(),
        });
    }

    let security_directory = if cert_table_in_bounds {
        Some((cert_table_offset, cert_table_size))
    } else {
        None
    };

    let signature_valid = if cert_table_in_bounds {
        None
    } else {
        Some(false)
    };

    let autopsy = PeAutopsy {
        is_pe: true,
        is_64bit: pe.is_64,
        entry_point: pe.entry as u64,
        sections,
        imports,
        exports,
        overlay_size,
        signature_valid,
        signature_signer: None,
        security_directory,
    };

    Some((autopsy, evidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::generate_bench_clean;

    #[test]
    fn test_pe_autopsy_valid_bench() {
        let data = generate_bench_clean();
        let result = analyze_pe(&data);
        assert!(result.is_some());
        let (autopsy, evidence) = result.unwrap();
        assert!(autopsy.is_pe);
        assert_eq!(autopsy.overlay_size, 0);
        assert!(evidence.is_empty());
    }

    #[test]
    fn test_pe_autopsy_corrupt_data() {
        let corrupt = b"MZ\x00\x00corrupted junk data that is not a valid PE";
        let result = analyze_pe(corrupt);
        assert!(result.is_none());
    }

    #[test]
    fn test_clr_assembly_with_dense_metadata_not_threat() {
        let mut data = generate_bench_clean();
        // OptionalHeader begins at 0x98. Data directories start at 0x108 in PE32+.
        // Directory 14 (CLR header) is at 0x108 + 14 * 8 = 0x178.
        if data.len() >= 0x180 {
            data[0x178..0x17C].copy_from_slice(&0x2000u32.to_le_bytes());
            data[0x17C..0x180].copy_from_slice(&0x48u32.to_le_bytes());
        }

        let result = analyze_pe(&data);
        assert!(result.is_some());
        let (_autopsy, evidence) = result.unwrap();
        assert!(!evidence.iter().any(|e| e.is_threat_signal));
    }

    #[test]
    fn test_baymax_packer_section_is_threat() {
        use crate::lab::create_minimal_pe;
        let mut payload = vec![0u8; 512];
        let mut state: u32 = 12345;
        for b in payload.iter_mut() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (state >> 24) as u8;
        }
        let pe_data = create_minimal_pe("baymax0", &payload);
        let result = analyze_pe(&pe_data);
        assert!(result.is_some());
        let (_, evidence) = result.unwrap();
        assert!(evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::HighEntropySection { name, .. } if name == "baymax0") && e.is_threat_signal));
    }

    #[test]
    fn test_extreme_entropy_non_rsrc_is_threat() {
        use crate::lab::create_minimal_pe;
        let mut payload = Vec::with_capacity(2048);
        for i in 0..2048 {
            payload.push((i % 256) as u8);
        }
        let mut pe_data = create_minimal_pe(".rdata", &payload);
        // Set characteristics to INITIALIZED_DATA | READ (non-executable)
        pe_data[0x1AC..0x1B0].copy_from_slice(&0x40000040u32.to_le_bytes());

        let result = analyze_pe(&pe_data);
        assert!(result.is_some());
        let (autopsy, evidence) = result.unwrap();
        assert!(!autopsy.sections[0].executable);
        assert!(autopsy.sections[0].entropy >= 7.95);
        assert!(evidence.iter().any(
            |e| matches!(&e.kind, EvidenceKind::HighEntropySection { name, .. } if name == ".rdata")
                && e.is_threat_signal
        ));
    }

    #[test]
    fn test_extreme_entropy_rsrc_is_not_threat() {
        use crate::lab::create_minimal_pe;
        let mut payload = Vec::with_capacity(2048);
        for i in 0..2048 {
            payload.push((i % 256) as u8);
        }
        let mut pe_data = create_minimal_pe(".rsrc", &payload);
        // Set characteristics to INITIALIZED_DATA | READ (non-executable)
        pe_data[0x1AC..0x1B0].copy_from_slice(&0x40000040u32.to_le_bytes());

        let result = analyze_pe(&pe_data);
        assert!(result.is_some());
        let (autopsy, evidence) = result.unwrap();
        assert!(!autopsy.sections[0].executable);
        assert!(autopsy.sections[0].entropy >= 7.95);
        assert!(!evidence.iter().any(
            |e| matches!(&e.kind, EvidenceKind::HighEntropySection { name, .. } if name == ".rsrc")
                && e.is_threat_signal
        ));
    }

    #[test]
    fn test_detect_emulator_profile_goldberg() {
        let exports = vec![
            "SteamAPI_Init".to_string(),
            "SteamAPI_Shutdown".to_string(),
            "SteamClient".to_string(),
        ];
        let mut data = vec![0u8; 1024];
        data[100..114].copy_from_slice(b"steam_settings");
        data[200..220].copy_from_slice(b"steam_interfaces.txt");

        let evidence = detect_emulator_profile(&exports, &data);
        assert!(evidence.is_some());
        let ev = evidence.unwrap();
        if let EvidenceKind::EmulatorProfile {
            name,
            is_legitimate,
            indicators,
        } = ev.kind
        {
            assert_eq!(name, "Goldberg Steam Emulator");
            assert!(is_legitimate);
            assert!(indicators.len() >= 2);
        } else {
            panic!("Expected EmulatorProfile");
        }
    }

    #[test]
    fn test_detect_emulator_profile_screamapi_and_eos() {
        let exports = vec![
            "EOS_Initialize".to_string(),
            "EOS_Shutdown".to_string(),
            "EOS_Platform_Create".to_string(),
            "EOS_Platform_GetEcomInterface".to_string(),
        ];
        let mut data = vec![0u8; 1024];
        data[100..109].copy_from_slice(b"screamapi");
        data[200..210].copy_from_slice(b"acidicoala");

        let evidence = detect_emulator_profile(&exports, &data);
        assert!(evidence.is_some());
        let ev = evidence.unwrap();
        if let EvidenceKind::EmulatorProfile {
            name,
            is_legitimate,
            indicators,
        } = ev.kind
        {
            assert_eq!(name, "ScreamAPI (Epic DLC Unlocker)");
            assert!(is_legitimate);
            assert!(indicators.len() >= 2);
        } else {
            panic!("Expected EmulatorProfile for ScreamAPI");
        }
    }

    #[test]
    fn unverified_security_directory_does_not_claim_valid_signature() {
        use crate::lab::create_minimal_pe;
        use crate::models::Tier;

        // High-entropy executable payload (+20 Suspicious) with an unverified certificate table.
        let mut payload = Vec::with_capacity(2048);
        for i in 0..2048 {
            payload.push(((i * 73 + 19) % 256) as u8);
        }
        let mut pe_data = create_minimal_pe(".text", &payload);

        let cert_offset = pe_data.len() as u32;
        let cert_size = 64u32;
        pe_data[0x128..0x12C].copy_from_slice(&cert_offset.to_le_bytes());
        pe_data[0x12C..0x130].copy_from_slice(&cert_size.to_le_bytes());

        let mut mock_cert = vec![0x30u8; cert_size as usize];
        mock_cert[0..4].copy_from_slice(&cert_size.to_le_bytes());
        mock_cert[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        mock_cert[6..8].copy_from_slice(&0x0002u16.to_le_bytes());
        pe_data.extend_from_slice(&mock_cert);

        let (autopsy, evidence) = analyze_pe(&pe_data).expect("valid synthetic PE");
        assert_eq!(
            autopsy.security_directory,
            Some((cert_offset as u64, cert_size as u64))
        );
        assert_ne!(
            autopsy.signature_valid,
            Some(true),
            "Static PE parsing must not mark an unverified certificate table as valid"
        );
        assert!(evidence
            .iter()
            .any(|e| matches!(&e.kind, EvidenceKind::SignatureStatus { valid: false, .. })));

        // End-to-end in-memory scan must not apply -15 signature mitigation without WinVerifyTrust.
        let report = crate::scan_bytes(&pe_data, "packed_unverified.exe");
        assert_eq!(
            report.verdict,
            Tier::Suspicious,
            "Unverified security directory must not downgrade packed binary below SUSPICIOUS"
        );
    }

    #[test]
    fn oversized_security_directory_fails_closed() {
        use crate::lab::create_minimal_pe;
        use crate::models::Tier;

        let mut pe_data = create_minimal_pe(".text", b"\x90\x90\x90\xC3sample_code");
        let overlay_start = pe_data.len() as u32;

        // Append a 2048-byte high-entropy overlay past the last section.
        let mut overlay = Vec::with_capacity(2048);
        for i in 0..2048 {
            overlay.push(((i * 131 + 7) % 256) as u8);
        }
        pe_data.extend_from_slice(&overlay);

        // Forge Security Directory with overflowing size (u32::MAX).
        pe_data[0x128..0x12C].copy_from_slice(&overlay_start.to_le_bytes());
        pe_data[0x12C..0x130].copy_from_slice(&u32::MAX.to_le_bytes());

        // Either rejected as malformed PE (INCONCLUSIVE) or exposes the full overlay without valid signature.
        match analyze_pe(&pe_data) {
            None => {
                let report = crate::scan_bytes(&pe_data, "oversized_cert.exe");
                assert_eq!(
                    report.verdict,
                    Tier::Inconclusive,
                    "Rejected PE with overflowing security directory must fail closed as INCONCLUSIVE"
                );
            }
            Some((autopsy, evidence)) => {
                assert_eq!(autopsy.security_directory, None);
                assert_eq!(autopsy.signature_valid, Some(false));
                assert_eq!(autopsy.overlay_size, 2048);
                assert!(evidence.iter().any(|e| matches!(
                    &e.kind,
                    EvidenceKind::Overlay { size_bytes: 2048 }
                ) && e.is_threat_signal));
            }
        }
    }

    #[test]
    fn security_directory_past_eof_fails_closed() {
        use crate::lab::create_minimal_pe;
        use crate::models::Tier;

        let mut pe_data = create_minimal_pe(".text", b"\x90\x90\xC3sample_code");
        let past_eof = (pe_data.len() as u32).saturating_add(0x1000);
        pe_data[0x128..0x12C].copy_from_slice(&past_eof.to_le_bytes());
        pe_data[0x12C..0x130].copy_from_slice(&64u32.to_le_bytes());

        match analyze_pe(&pe_data) {
            None => {
                let report = crate::scan_bytes(&pe_data, "past_eof_cert.exe");
                assert_eq!(report.verdict, Tier::Inconclusive);
            }
            Some((autopsy, evidence)) => {
                assert_eq!(autopsy.security_directory, None);
                assert_eq!(autopsy.signature_valid, Some(false));
                assert!(evidence.iter().any(|e| matches!(
                    &e.kind,
                    EvidenceKind::SignatureStatus { valid: false, .. }
                )));
            }
        }
    }

    #[test]
    fn truncated_security_directory_does_not_hide_overlay() {
        use crate::lab::create_minimal_pe;

        let mut pe_data = create_minimal_pe(".text", b"\x90\x90\x90\xC3sample_code");
        let overlay_start = pe_data.len() as u32;

        // Append a 2048-byte high-entropy overlay past the last section.
        let mut overlay = Vec::with_capacity(2048);
        for i in 0..2048 {
            overlay.push(((i * 131 + 7) % 256) as u8);
        }
        pe_data.extend_from_slice(&overlay);

        // Truncated security directory (< 8-byte WIN_CERTIFICATE header) inside file bounds.
        pe_data[0x128..0x12C].copy_from_slice(&overlay_start.to_le_bytes());
        pe_data[0x12C..0x130].copy_from_slice(&4u32.to_le_bytes());

        match analyze_pe(&pe_data) {
            None => {
                let report = crate::scan_bytes(&pe_data, "truncated_cert.exe");
                assert_eq!(report.verdict, crate::models::Tier::Inconclusive);
            }
            Some((autopsy, evidence)) => {
                assert_eq!(autopsy.security_directory, None);
                assert_eq!(autopsy.signature_valid, Some(false));
                assert_eq!(autopsy.overlay_size, 2048);
                assert!(evidence.iter().any(|e| matches!(
                    &e.kind,
                    EvidenceKind::Overlay { size_bytes: 2048 }
                ) && e.is_threat_signal));
                assert!(evidence.iter().any(|e| matches!(
                    &e.kind,
                    EvidenceKind::SignatureStatus { valid: false, .. }
                )));
            }
        }
    }

    #[test]
    fn pe_boundary_edge_cases_never_panic_and_fail_closed() {
        use crate::models::Tier;

        let mut mz_lfanew_zero = vec![0u8; 64];
        mz_lfanew_zero[0..2].copy_from_slice(b"MZ");

        let mut mz_lfanew_max = vec![0u8; 64];
        mz_lfanew_max[0..2].copy_from_slice(b"MZ");
        mz_lfanew_max[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());

        let mut mz_lfanew_past_eof = vec![0u8; 64];
        mz_lfanew_past_eof[0..2].copy_from_slice(b"MZ");
        mz_lfanew_past_eof[0x3C..0x40].copy_from_slice(&0x2000u32.to_le_bytes());

        let mut truncated_pe = vec![0u8; 0x90];
        truncated_pe[0..2].copy_from_slice(b"MZ");
        truncated_pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        truncated_pe[0x80..0x84].copy_from_slice(b"PE\0\0");

        for malformed in [
            &[][..],
            &[0x4D][..],
            b"MZ".as_slice(),
            mz_lfanew_zero.as_slice(),
            mz_lfanew_max.as_slice(),
            mz_lfanew_past_eof.as_slice(),
            truncated_pe.as_slice(),
        ] {
            assert!(
                analyze_pe(malformed).is_none(),
                "Malformed PE input of len {} must return None",
                malformed.len()
            );
        }

        for mz_corrupt in [
            b"MZ".as_slice(),
            mz_lfanew_zero.as_slice(),
            mz_lfanew_max.as_slice(),
            mz_lfanew_past_eof.as_slice(),
            truncated_pe.as_slice(),
        ] {
            let report = crate::scan_bytes(mz_corrupt, "truncated.exe");
            assert_eq!(
                report.verdict,
                Tier::Inconclusive,
                "Malformed MZ input of len {} must yield INCONCLUSIVE",
                mz_corrupt.len()
            );
        }
    }
}
