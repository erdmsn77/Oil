//! # Windows Persistence & DLL Sideloading Auditor (`oil hunt`)
//!
//! GDD §7 — Read-only forensic inspection of startup mechanisms,
//! Run registry keys, startup folders, and DLL sideloading traps.

use crate::models::{ScanReport, Tier};
use crate::scan_path;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Source where a persistent program was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceSource {
    RegistryHkcuRun,
    RegistryHklmRun,
    StartupFolder,
    DllSideloadTrap { host_directory: PathBuf },
}

impl std::fmt::Display for PersistenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceSource::RegistryHkcuRun => write!(f, "HKCU\\...\\Run"),
            PersistenceSource::RegistryHklmRun => write!(f, "HKLM\\...\\Run"),
            PersistenceSource::StartupFolder => write!(f, "Startup Folder"),
            PersistenceSource::DllSideloadTrap { .. } => write!(f, "DLL Sideloading Trap"),
        }
    }
}

/// A discovered persistence or sideloading entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceItem {
    pub source: PersistenceSource,
    pub entry_name: String,
    pub command_line: String,
    pub resolved_path: Option<PathBuf>,
    pub scan_report: Option<ScanReport>,
}

/// Summary report of the hunt audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub items: Vec<PersistenceItem>,
    pub total_inspected: usize,
    pub high_risk_count: usize,
    pub suspicious_count: usize,
    pub no_indicators_count: usize,
}

/// Known DLL filenames frequently abused for DLL sideloading/proxying in game and app directories.
pub const SIDELOAD_CANDIDATE_DLLS: &[&str] = &[
    // Windows Core & Subsystem APIs
    "version.dll",
    "winmm.dll",
    "uxtheme.dll",
    "dwmapi.dll",
    "dbghelp.dll",
    "msimg32.dll",
    "cryptbase.dll",
    "wldp.dll",
    "userenv.dll",
    "netapi32.dll",
    "winspool.drv",
    // DirectX & Graphics Infrastructure
    "dxgi.dll",
    "d3d12.dll",
    "d3d11.dll",
    "d3d9.dll",
    "d3d8.dll",
    "ddraw.dll",
    "d3dcompiler_47.dll",
    "d3dcompiler_46.dll",
    "d3dcompiler_43.dll",
    // Vendor GPU & Upscaler Interceptors
    "nvapi64.dll",
    "nvapi.dll",
    "fakenvapi.dll",
    "amd_fidelityfx_dx12.dll",
    // Input & Audio Hooks (Game Modding / ASI Loaders / Cracks)
    "dinput8.dll",
    "dinput.dll",
    "xinput1_3.dll",
    "xinput1_4.dll",
    "xinput9_1_0.dll",
    "dsound.dll",
    // Steam & Game Media Interceptors
    "steam_api64.dll",
    "steam_api.dll",
    "bink2w64.dll",
    "binkw64.dll",
    "binkw32.dll",
];

/// Checks if a file path is a sideload/proxy candidate located outside standard Windows system directories.
pub fn is_sideload_candidate_path(path: &Path) -> bool {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_lowercase(),
        None => return false,
    };

    if !SIDELOAD_CANDIDATE_DLLS.iter().any(|&c| c.eq_ignore_ascii_case(&file_name)) {
        return false;
    }

    // Legitimate system libraries reside in Windows system folders (System32, SysWOW64, WinSxS)
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.contains("windows\\system32")
        || path_str.contains("windows\\syswow64")
        || path_str.contains("windows\\winsxs")
        || path_str.contains("windows/system32")
        || path_str.contains("windows/syswow64")
        || path_str.contains("windows/winsxs")
    {
        return false;
    }

    true
}

/// Expands common Windows environment variables like %windir%, %APPDATA%, %ProgramFiles%.
pub fn expand_env_vars(s: &str) -> String {
    let mut result = s.to_string();
    if let Ok(windir) = std::env::var("windir") {
        result = result.replace("%windir%", &windir).replace("%WINDIR%", &windir);
    }
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        result = result.replace("%SystemRoot%", &sysroot).replace("%SYSTEMROOT%", &sysroot);
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        result = result.replace("%APPDATA%", &appdata).replace("%appdata%", &appdata);
    }
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        result = result.replace("%LOCALAPPDATA%", &localappdata).replace("%localappdata%", &localappdata);
    }
    if let Ok(progfiles) = std::env::var("ProgramFiles") {
        result = result.replace("%ProgramFiles%", &progfiles);
    }
    result
}

/// Extracts the actual binary file path from a raw command line string.
/// Handles environment variables (%windir%), quotes, and argument trailing.
pub fn extract_file_path_from_cmd(cmd: &str) -> Option<PathBuf> {
    let expanded = expand_env_vars(cmd);
    let trimmed = expanded.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('"') {
        if let Some(end_idx) = trimmed[1..].find('"') {
            let path_str = &trimmed[1..=end_idx];
            let p = PathBuf::from(path_str);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // Try whitespace-delimited tokens from longest to shortest
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    for i in (1..=tokens.len()).rev() {
        let candidate = tokens[..i].join(" ");
        let p = PathBuf::from(&candidate);
        if p.exists() && p.is_file() {
            return Some(p);
        }
    }

    let first = tokens.first()?;
    let p = PathBuf::from(first);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Parsed information from a Windows Shell Link (.lnk) file.
#[derive(Debug, Clone)]
pub struct LnkInfo {
    pub target_path: Option<PathBuf>,
    pub arguments: Option<String>,
    pub full_command: String,
}

/// Fallback search for drive-letter paths (e.g. C:\...) in raw bytes (ASCII and UTF-16LE).
pub fn find_drive_path_in_bytes(data: &[u8]) -> Option<PathBuf> {
    // 1. ASCII search
    for i in 0..data.len().saturating_sub(4) {
        if data[i].is_ascii_alphabetic() && data[i + 1] == b':' && data[i + 2] == b'\\' {
            let mut end = i + 3;
            while end < data.len() {
                let b = data[end];
                if b == 0 || b == b'"' || b < 0x20 || b == b'<' || b == b'>' || b == b'|' {
                    break;
                }
                end += 1;
            }
            if end - i >= 4 {
                let candidate = String::from_utf8_lossy(&data[i..end]).trim().to_string();
                let p = PathBuf::from(&candidate);
                if p.exists()
                    || candidate.ends_with(".exe")
                    || candidate.ends_with(".vbs")
                    || candidate.ends_with(".bat")
                {
                    return Some(p);
                }
            }
        }
    }

    // 2. UTF-16LE search
    for i in 0..data.len().saturating_sub(8) {
        if data[i].is_ascii_alphabetic()
            && data[i + 1] == 0
            && data[i + 2] == b':'
            && data[i + 3] == 0
            && data[i + 4] == b'\\'
            && data[i + 5] == 0
        {
            let mut end = i + 6;
            let mut chars = vec![data[i] as u16, b':' as u16, b'\\' as u16];
            while end + 2 <= data.len() {
                let code = u16::from_le_bytes([data[end], data[end + 1]]);
                if code == 0
                    || code == b'"' as u16
                    || code < 0x20
                    || code == b'<' as u16
                    || code == b'>' as u16
                    || code == b'|' as u16
                {
                    break;
                }
                chars.push(code);
                end += 2;
            }
            if chars.len() >= 4 {
                let candidate = String::from_utf16_lossy(&chars).trim().to_string();
                let p = PathBuf::from(&candidate);
                if p.exists()
                    || candidate.ends_with(".exe")
                    || candidate.ends_with(".vbs")
                    || candidate.ends_with(".bat")
                {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Parses Windows Shell Link (.lnk) binary format to resolve target executable and arguments.
pub fn parse_lnk_bytes(data: &[u8]) -> Option<LnkInfo> {
    if data.len() < 76 {
        return None;
    }

    // LinkCLSID: {00021401-0000-0000-C000-000000000046}
    let clsid = &data[4..20];
    if clsid != [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ] {
        return None;
    }

    let flags = u32::from_le_bytes(data[20..24].try_into().ok()?);
    let has_id_list = (flags & 0x01) != 0;
    let has_link_info = (flags & 0x02) != 0;
    let is_unicode = (flags & 0x80) != 0;

    let mut offset = 76usize;

    if has_id_list {
        if offset + 2 > data.len() {
            return None;
        }
        let id_list_size = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
        offset = offset.saturating_add(2).saturating_add(id_list_size);
    }

    let mut target_path: Option<PathBuf> = None;

    if has_link_info && offset + 28 <= data.len() {
        let info_start = offset;
        let info_size =
            u32::from_le_bytes(data[info_start..info_start + 4].try_into().ok()?) as usize;
        let header_size =
            u32::from_le_bytes(data[info_start + 4..info_start + 8].try_into().ok()?) as usize;
        let info_flags = u32::from_le_bytes(data[info_start + 8..info_start + 12].try_into().ok()?);

        if (info_flags & 0x01) != 0 {
            // Local base path offset
            let local_base_path_off =
                u32::from_le_bytes(data[info_start + 16..info_start + 20].try_into().ok()?) as usize;
            let path_start = info_start.saturating_add(local_base_path_off);
            if path_start < data.len() {
                if let Some(nul_pos) = data[path_start..].iter().position(|&b| b == 0) {
                    let path_str = String::from_utf8_lossy(&data[path_start..path_start + nul_pos])
                        .trim()
                        .to_string();
                    if !path_str.is_empty() {
                        target_path = Some(PathBuf::from(path_str));
                    }
                }
            }

            if header_size >= 0x24 && info_start + 32 <= data.len() {
                let uni_off =
                    u32::from_le_bytes(data[info_start + 28..info_start + 32].try_into().ok()?) as usize;
                if uni_off > 0 {
                    let uni_start = info_start.saturating_add(uni_off);
                    if uni_start + 2 <= data.len() {
                        let mut chars = Vec::new();
                        let mut p = uni_start;
                        while p + 2 <= data.len() {
                            let code = u16::from_le_bytes([data[p], data[p + 1]]);
                            if code == 0 {
                                break;
                            }
                            chars.push(code);
                            p += 2;
                        }
                        let path_str = String::from_utf16_lossy(&chars).trim().to_string();
                        if !path_str.is_empty() {
                            target_path = Some(PathBuf::from(path_str));
                        }
                    }
                }
            }
        }
        offset = info_start.saturating_add(info_size);
    }

    let read_string_data = |off: &mut usize| -> Option<String> {
        if *off + 2 > data.len() {
            return None;
        }
        let cch = u16::from_le_bytes(data[*off..*off + 2].try_into().ok()?) as usize;
        *off += 2;
        if is_unicode {
            let byte_len = cch.saturating_mul(2);
            if *off + byte_len > data.len() {
                return None;
            }
            let u16_slice = &data[*off..*off + byte_len];
            *off += byte_len;
            let u16_chars: Vec<u16> = u16_slice
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&u16_chars))
        } else {
            if *off + cch > data.len() {
                return None;
            }
            let s = String::from_utf8_lossy(&data[*off..*off + cch]).to_string();
            *off += cch;
            Some(s)
        }
    };

    let _name = if (flags & 0x04) != 0 {
        read_string_data(&mut offset)
    } else {
        None
    };
    let rel_path = if (flags & 0x08) != 0 {
        read_string_data(&mut offset)
    } else {
        None
    };
    let _working_dir = if (flags & 0x10) != 0 {
        read_string_data(&mut offset)
    } else {
        None
    };
    let args = if (flags & 0x20) != 0 {
        read_string_data(&mut offset)
    } else {
        None
    };

    if target_path.is_none() {
        if let Some(ref r) = rel_path {
            target_path = Some(PathBuf::from(r));
        }
    }

    if target_path.is_none() {
        target_path = find_drive_path_in_bytes(data);
    }

    let full_command = match (&target_path, &args) {
        (Some(t), Some(a)) => format!("\"{}\" {}", t.display(), a),
        (Some(t), None) => format!("\"{}\"", t.display()),
        (None, Some(a)) => a.clone(),
        (None, None) => String::new(),
    };

    Some(LnkInfo {
        target_path,
        arguments: args,
        full_command,
    })
}

/// Performs a complete read-only persistence audit across Windows startup mechanisms.
pub fn run_persistence_audit() -> HuntReport {
    let mut items = Vec::new();

    // ──────────────────────────────────────────────
    // 1. REGISTRY RUN KEYS (Windows-only)
    // ──────────────────────────────────────────────
    #[cfg(windows)]
    {
        audit_registry_run_keys(&mut items);
    }

    // ──────────────────────────────────────────────
    // 2. STARTUP FOLDERS
    // ──────────────────────────────────────────────
    audit_startup_folders(&mut items);

    // ──────────────────────────────────────────────
    // 3. STATISTICAL AGGREGATION
    // ──────────────────────────────────────────────
    let mut high_risk_count = 0;
    let mut suspicious_count = 0;
    let mut no_indicators_count = 0;

    for item in &items {
        if let Some(ref report) = item.scan_report {
            match report.verdict {
                Tier::HighRisk => high_risk_count += 1,
                Tier::Suspicious => suspicious_count += 1,
                Tier::NoIndicatorsFound => no_indicators_count += 1,
                Tier::Inconclusive => {}
            }
        }
    }

    HuntReport {
        total_inspected: items.len(),
        items,
        high_risk_count,
        suspicious_count,
        no_indicators_count,
    }
}

#[cfg(windows)]
fn audit_registry_run_keys(items: &mut Vec<PersistenceItem>) {
    use winreg::enums::*;
    use winreg::RegKey;

    let targets = [
        (
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            PersistenceSource::RegistryHkcuRun,
        ),
        (
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            PersistenceSource::RegistryHkcuRun,
        ),
        (
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            PersistenceSource::RegistryHklmRun,
        ),
        (
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            PersistenceSource::RegistryHklmRun,
        ),
    ];

    for (root, subkey, source) in targets {
        let base = RegKey::predef(root);
        if let Ok(key) = base.open_subkey(subkey) {
            for val in key.enum_values().flatten() {
                let name = val.0;
                let cmd_line: String = match key.get_value(&name) {
                    Ok(val) => val,
                    Err(_) => continue,
                };

                let mut resolved = extract_file_path_from_cmd(&cmd_line);
                // If resolved path is a shortcut (.lnk), resolve its target binary
                if let Some(ref p) = resolved {
                    if p.extension()
                        .and_then(|e| e.to_str())
                        .map(|s| s.eq_ignore_ascii_case("lnk"))
                        .unwrap_or(false)
                    {
                        if let Ok(lnk_bytes) = std::fs::read(p) {
                            if let Some(info) = parse_lnk_bytes(&lnk_bytes) {
                                resolved = info.target_path.or_else(|| Some(p.clone()));
                            }
                        }
                    }
                }

                let scan_report = resolved.as_ref().and_then(|p| scan_path(p).ok());

                items.push(PersistenceItem {
                    source: source.clone(),
                    entry_name: name,
                    command_line: cmd_line,
                    resolved_path: resolved,
                    scan_report,
                });
            }
        }
    }
}

fn audit_startup_folders(items: &mut Vec<PersistenceItem>) {
    let mut folder_paths = Vec::new();

    if let Ok(appdata) = std::env::var("APPDATA") {
        folder_paths.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }

    if let Ok(progdata) = std::env::var("ProgramData") {
        folder_paths.push(PathBuf::from(progdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }

    for folder in folder_paths {
        if !folder.exists() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(&folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    // Check if entry is a Windows Shortcut (.lnk)
                    let is_lnk = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|s| s.eq_ignore_ascii_case("lnk"))
                        .unwrap_or(false);

                    if is_lnk {
                        if let Ok(lnk_bytes) = std::fs::read(&path) {
                            if let Some(info) = parse_lnk_bytes(&lnk_bytes) {
                                let script_target = info
                                    .arguments
                                    .as_ref()
                                    .and_then(|a| extract_file_path_from_cmd(a));
                                let resolved_path = script_target.or(info.target_path.clone());
                                let scan_report =
                                    resolved_path.as_ref().and_then(|p| scan_path(p).ok());

                                items.push(PersistenceItem {
                                    source: PersistenceSource::StartupFolder,
                                    entry_name: file_name,
                                    command_line: if !info.full_command.is_empty() {
                                        info.full_command
                                    } else {
                                        path.display().to_string()
                                    },
                                    resolved_path,
                                    scan_report,
                                });
                                continue;
                            }
                        }
                    }

                    let scan_report = scan_path(&path).ok();

                    items.push(PersistenceItem {
                        source: PersistenceSource::StartupFolder,
                        entry_name: file_name,
                        command_line: path.display().to_string(),
                        resolved_path: Some(path),
                        scan_report,
                    });
                }
            }
        }
    }
}

/// Audits a specific application directory (e.g. a game folder) for proxy/sideloaded DLL traps.
pub fn audit_directory_for_sideloads(dir: &Path) -> Vec<PersistenceItem> {
    let mut items = Vec::new();
    if !dir.exists() || !dir.is_dir() {
        return items;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();

                if SIDELOAD_CANDIDATE_DLLS.contains(&name.as_str()) {
                    let scan_report = scan_path(&path).ok();
                    items.push(PersistenceItem {
                        source: PersistenceSource::DllSideloadTrap {
                            host_directory: dir.to_path_buf(),
                        },
                        entry_name: name,
                        command_line: path.display().to_string(),
                        resolved_path: Some(path),
                        scan_report,
                    });
                }
            }
        }
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_extract_quoted_path() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"dummy").unwrap();

        let cmd = format!("\"{}\" --silent -autostart", tmp.path().display());
        let extracted = extract_file_path_from_cmd(&cmd);
        assert_eq!(extracted, Some(tmp.path().to_path_buf()));
    }

    #[test]
    fn test_audit_directory_detects_candidate_dll() {
        let temp_dir = tempfile::tempdir().unwrap();
        let version_dll = temp_dir.path().join("version.dll");
        std::fs::write(&version_dll, b"dummy content").unwrap();

        let items = audit_directory_for_sideloads(temp_dir.path());
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_name, "version.dll");
        assert!(matches!(items[0].source, PersistenceSource::DllSideloadTrap { .. }));
    }

    #[test]
    fn test_is_sideload_candidate_path() {
        // App directory proxy DLLs -> true
        assert!(is_sideload_candidate_path(Path::new("C:\\Games\\Doom\\dxgi.dll")));
        assert!(is_sideload_candidate_path(Path::new("C:\\Games\\Doom\\version.dll")));
        assert!(is_sideload_candidate_path(Path::new("C:\\Games\\Doom\\fakenvapi.dll")));
        assert!(is_sideload_candidate_path(Path::new("C:\\Games\\Doom\\dinput8.dll")));

        // Legitimate Windows system directory DLLs -> false
        assert!(!is_sideload_candidate_path(Path::new("C:\\Windows\\System32\\dxgi.dll")));
        assert!(!is_sideload_candidate_path(Path::new("C:\\Windows\\SysWOW64\\version.dll")));

        // Unrelated non-candidate DLLs -> false
        assert!(!is_sideload_candidate_path(Path::new("C:\\Games\\Doom\\my_custom_mod.dll")));
    }
}
