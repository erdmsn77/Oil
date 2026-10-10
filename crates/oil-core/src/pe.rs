//! # PE Autopsy — Structural Binary Analysis
//!
//! GDD §3.2 — Stage 1: PE Autopsy
//! Zero-copy PE parsing: sections, entropy, overlay, imports, exports.

use crate::io::shannon_entropy;
use crate::models::{
    Evidence, EvidenceKind, ImportEntry, PeAutopsy, SectionInfo,
};
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
const CREDENTIAL_APIS: &[&str] = &[
    "CryptUnprotectData",
    "CertOpenStore",
    "CertOpenSystemStore",
];

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
    "upx", "wus", "mpress", "aspack", "themida", "vmp", "pec", "nsp", "fsg", "mew", "pack", "baymax",
];

/// Checks if a section name matches known packer/crypter signatures.
fn is_packer_section_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let trimmed = lower.trim_start_matches('.').trim();
    PACKER_SECTION_PREFIXES.iter().any(|&p| trimmed.starts_with(p))
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
        || pe.imports.iter().any(|imp| imp.dll.to_lowercase() == "mscoree.dll");

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
            let is_rsrc = lower_name == ".rsrc" || lower_name.starts_with(".rsrc") || lower_name == "rsrc";
            let is_extreme_entropy = section.entropy >= 7.95 && !is_rsrc;

            // High entropy is an active threat signal if the section contains executable code,
            // matches known packer signatures (UPX, WUS, Baymax, etc.), or exhibits near-maximal
            // entropy (>= 7.95) outside resource sections (e.g. codeless encrypted payload blocks).
            // Non-executable resource sections (.rsrc with compressed splash/icons)
            // in modern games and desktop apps have high entropy naturally without being malicious.
            // In .NET / CLR assemblies, the .text section houses dense CLI metadata streams (#~, #Strings,
            // #US, #Blob), method headers, and IL bytecodes which naturally reach up to 7.85 entropy without packing.
            let is_threat = if is_clr_binary && !is_packer && section.name == ".text" && section.entropy <= 7.85 {
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
    let mut import_map: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for imp in &pe.imports {
        let dll_name = imp.dll.to_lowercase();
        import_map.entry(dll_name).or_default().push(imp.name.to_string());
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
            indicators.push(format!("Only {} total imported functions", total_import_count));
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

    let cert_table_end = if cert_table_offset > 0 && cert_table_size > 0 && cert_table_offset < data.len() as u64 {
        cert_table_offset.saturating_add(cert_table_size).min(data.len() as u64)
    } else {
        0
    };

    let image_end = last_section_end.max(cert_table_end);

    let overlay_size = if (data.len() as u64) > image_end && image_end > 0 {
        (data.len() as u64).saturating_sub(image_end)
    } else {
        0
    };

    if overlay_size > 1024 {
        // Only flag meaningful non-certificate overlays (> 1 KB)
        let overlay_offset = image_end.min(data.len() as u64) as usize;
        let overlay_data = &data[overlay_offset..];
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

    let has_authenticode = cert_table_offset > 0 && cert_table_size > 0;
    if has_authenticode {
        evidence.push(Evidence {
            kind: EvidenceKind::SignatureStatus {
                valid: true,
                signer: None,
                detail: format!(
                    "Authenticode security directory present ({} bytes at offset 0x{:X})",
                    cert_table_size, cert_table_offset
                ),
            },
            is_threat_signal: false,
            explanation: format!(
                "Binary contains embedded Authenticode certificate structure ({} bytes; unverified certificate table).",
                cert_table_size
            ),
        });
    }

    let security_directory = if cert_table_offset > 0 && cert_table_size > 0 {
        Some((cert_table_offset, cert_table_size))
    } else {
        None
    };

    let autopsy = PeAutopsy {
        is_pe: true,
        is_64bit: pe.is_64,
        entry_point: pe.entry as u64,
        sections,
        imports,
        exports,
        overlay_size,
        signature_valid: Some(has_authenticode),
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
        assert!(evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::HighEntropySection { name, .. } if name == ".rdata") && e.is_threat_signal));
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
        assert!(!evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::HighEntropySection { name, .. } if name == ".rsrc") && e.is_threat_signal));
    }
}
