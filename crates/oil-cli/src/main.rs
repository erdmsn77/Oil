pub mod lang;
mod output;

use clap::{Parser, Subcommand};
use colored::Colorize;
use lang::Language;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "oil")]
#[command(version = "0.1.0")]
#[command(about = "The Frictionless Reverse-Engineering & Binary Forensic Triage Engine", long_about = None)]
struct Cli {
    /// Interface language (tr, en, or auto)
    #[arg(long, global = true, value_name = "LANG")]
    lang: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a binary, directory, or archive for threat indicators
    Scan {
        /// Path to target file or directory
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Perform semantic patch diffing between original and cracked binary
    Diff {
        /// Path to original binary
        #[arg(value_name = "ORIGINAL")]
        original: PathBuf,
        /// Path to patched/cracked binary
        #[arg(value_name = "PATCHED")]
        patched: PathBuf,
    },
    /// Audit Windows persistence (Run keys, Startup) and proxy DLL sideloads
    Hunt {
        /// Optional directory to audit for proxy DLL sideloading traps
        #[arg(short, long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Run built-in synthetic benchmark harness
    Lab,
}

/// Intelligently parses user input to extract a valid target path,
/// automatically handling quotes, trailing whitespace, or accidental double-pastes.
fn clean_input_path(input: &str) -> Option<PathBuf> {
    let mut trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    // PowerShell drag-and-drop prefix: & 'C:\path' or & "C:\path"
    if trimmed.starts_with('&') {
        trimmed = trimmed[1..].trim();
    }

    // 1. Direct path check (unquoted or normally quoted)
    let direct_str = trimmed.trim_matches('"').trim_matches('\'').trim();
    let direct = PathBuf::from(direct_str);
    if direct.exists() {
        return Some(direct);
    }

    // 2. Accidental double-paste or concatenated quotes: e.g. "C:\path"C:\path"
    for token in trimmed.split('"') {
        let clean = token.trim().trim_matches('\'').trim();
        if !clean.is_empty() {
            let p = PathBuf::from(clean);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // 3. Split by whitespace in case multiple paths were pasted
    for token in trimmed.split_whitespace() {
        let clean = token.trim().trim_matches('"').trim_matches('\'').trim();
        if !clean.is_empty() {
            let p = PathBuf::from(clean);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // 4. If it looks like a file path (has slashes, backslashes, colon or dot extension),
    // return it so run_scan can show a clear "Hata: Hedef bulunamadı: ..." message.
    if direct_str.contains('\\')
        || direct_str.contains('/')
        || direct_str.contains(':')
        || direct_str.contains('.')
    {
        return Some(direct);
    }

    None
}

fn collect_executable_targets(dir: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(dir, 0, max_depth, &mut files);
    files.sort();
    files
}

fn collect_recursive(dir: &Path, current_depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
    if current_depth > max_depth {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                let is_executable = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| {
                        let ext_lower = ext.to_lowercase();
                        matches!(
                            ext_lower.as_str(),
                            "exe" | "dll" | "sys" | "scr" | "lnk" | "zip"
                        )
                    })
                    .unwrap_or(false);

                if is_executable {
                    out.push(p);
                }
            } else if p.is_dir() {
                let dir_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !dir_name.starts_with('$')
                    && !dir_name.eq_ignore_ascii_case("System Volume Information")
                {
                    collect_recursive(&p, current_depth + 1, max_depth, out);
                }
            }
        }
    }
}

fn run_scan(path: &Path, lang: Language) -> bool {
    if !path.exists() {
        if lang.is_turkish() {
            eprintln!("Hata: Hedef bulunamadı: {}", path.display());
        } else {
            eprintln!("Error: Target not found: {}", path.display());
        }
        return false;
    }

    if path.is_dir() {
        let targets = collect_executable_targets(path, 5);
        if targets.is_empty() {
            if lang.is_turkish() {
                println!(
                    "Dizinde çalıştırılabilir dosya bulunamadı (.exe, .dll, .lnk, .zip): {}",
                    path.display()
                );
            } else {
                println!(
                    "No executable targets (.exe, .dll, .lnk, .zip) found in: {}",
                    path.display()
                );
            }
            return true;
        }

        if lang.is_turkish() {
            println!(
                "\nKlasör Taraması Başlatıldı: '{}' ({} dosya)",
                path.display(),
                targets.len()
            );
        } else {
            println!(
                "\nDirectory Scan Initiated: '{}' ({} files)",
                path.display(),
                targets.len()
            );
        }

        let mut reports: Vec<oil_core::models::ScanReport> = Vec::new();
        let mut dedupe_info: Vec<(usize, PathBuf, Option<PathBuf>)> = Vec::new();
        let mut seen_hashes: std::collections::HashMap<
            String,
            (PathBuf, oil_core::models::ScanReport),
        > = std::collections::HashMap::new();
        let mut duplicate_count = 0;

        for (i, p) in targets.iter().enumerate() {
            let dual_hash = oil_core::io::dual_hash_file(p).ok();
            if let Some((ref sha256, _)) = dual_hash {
                if let Some((first_path, cached_report)) = seen_hashes.get(sha256) {
                    duplicate_count += 1;
                    dedupe_info.push((i, p.clone(), Some(first_path.clone())));
                    reports.push(cached_report.clone());
                    continue;
                }
            }

            match oil_core::scan_path(p) {
                Ok(report) => {
                    dedupe_info.push((i, p.clone(), None));
                    seen_hashes.insert(
                        report.identity.sha256.clone(),
                        (p.to_path_buf(), report.clone()),
                    );
                    reports.push(report);
                }
                Err(e) => {
                    if lang.is_turkish() {
                        eprintln!("Dosya okunurken hata oluştu {}: {}", p.display(), e);
                    } else {
                        eprintln!("Error reading file {}: {}", p.display(), e);
                    }
                    let (sha256, blake3) = oil_core::io::dual_hash_file(p)
                        .unwrap_or_else(|_| (String::new(), String::new()));
                    let err_report = oil_core::models::ScanReport {
                        identity: oil_core::models::FileIdentity {
                            path: p.clone(),
                            size_bytes: 0,
                            sha256,
                            blake3,
                        },
                        autopsy: None,
                        evidence: Vec::new(),
                        verdict: oil_core::models::Tier::Inconclusive,
                        verdict_summary: if lang.is_turkish() {
                            format!("Dosya okuma hatası: {}", e)
                        } else {
                            format!("Failed to read file: {}", e)
                        },
                        files_scanned: 0,
                        files_skipped: 1,
                        skip_reasons: vec![e.to_string()],
                    };
                    dedupe_info.push((i, p.clone(), None));
                    reports.push(err_report);
                }
            }
        }

        // ── Directory Correlation Analysis (Sideloading Suite Evaluation) ──
        oil_core::risk::correlate_sideloading_suite(&mut reports);

        // Print dossiers with correlated verdicts
        for (idx, report) in reports.iter().enumerate() {
            let (_, ref p, ref dup) = dedupe_info[idx];
            if lang.is_turkish() {
                println!(
                    "\n[{}/{}] Taranıyor: {}",
                    idx + 1,
                    targets.len(),
                    p.display()
                );
            } else {
                println!(
                    "\n[{}/{}] Scanning: {}",
                    idx + 1,
                    targets.len(),
                    p.display()
                );
            }
            if let Some(ref first_path) = dup {
                if lang.is_turkish() {
                    println!(
                        "  {} SHA-256 Eşleşti ({}...): '{}' ile birebir aynı dosya (analiz atlandı).",
                        "[+]".green().bold(),
                        &report.identity.sha256[..12],
                        first_path.display()
                    );
                } else {
                    println!(
                        "  {} SHA-256 Match ({}...): Exact duplicate of '{}' (cached).",
                        "[+]".green().bold(),
                        &report.identity.sha256[..12],
                        first_path.display()
                    );
                }
            } else {
                output::print_dossier(report);
            }
        }

        // Calculate statistics after correlation
        let mut no_indicators = 0;
        let mut suspicious = 0;
        let mut high_risk = 0;
        let mut inconclusive = 0;
        for r in &reports {
            match r.verdict {
                oil_core::models::Tier::HighRisk => high_risk += 1,
                oil_core::models::Tier::Suspicious => suspicious += 1,
                oil_core::models::Tier::NoIndicatorsFound => no_indicators += 1,
                oil_core::models::Tier::Inconclusive => inconclusive += 1,
            }
        }

        let proxy_hook_count = reports
            .iter()
            .map(|r| {
                r.evidence
                    .iter()
                    .filter(|e| {
                        matches!(&e.kind, oil_core::models::EvidenceKind::DllProxyHook { .. })
                    })
                    .count()
            })
            .sum();

        let has_stealer_ioc = reports.iter().any(|r| {
            r.evidence.iter().any(|e| {
                matches!(
                    &e.kind,
                    oil_core::models::EvidenceKind::DiscordWebhook { .. }
                        | oil_core::models::EvidenceKind::TelegramToken { .. }
                        | oil_core::models::EvidenceKind::CredentialPath { .. }
                        | oil_core::models::EvidenceKind::YaraMatch { .. }
                )
            })
        });

        // Executive summary box at the end of directory audit
        output::print_directory_summary_box(
            path,
            targets.len(),
            no_indicators,
            suspicious,
            high_risk,
            inconclusive,
            proxy_hook_count,
            duplicate_count,
            has_stealer_ioc,
            lang,
        );

        // Print flagged files priority breakdown table
        let flagged_reports: Vec<&oil_core::models::ScanReport> = reports
            .iter()
            .filter(|r| {
                matches!(
                    r.verdict,
                    oil_core::models::Tier::Suspicious | oil_core::models::Tier::HighRisk
                ) || r
                    .evidence
                    .iter()
                    .any(|e| matches!(e.kind, oil_core::models::EvidenceKind::DllProxyHook { .. }))
            })
            .collect();

        if !flagged_reports.is_empty() {
            println!(
                "{}",
                "───────────────────────────────────────────────────────────────".yellow()
            );
            if lang.is_turkish() {
                println!(
                    "  {} ÖNCELİKLİ RAPOR: ŞÜPHELİ VE RİSKLİ DOSYALAR ({} adet)",
                    "[!]".yellow().bold(),
                    flagged_reports.len()
                );
            } else {
                println!(
                    "  {} PRIORITY BREAKDOWN: FLAGGED & ANOMALOUS FILES ({} total)",
                    "[!]".yellow().bold(),
                    flagged_reports.len()
                );
            }
            println!(
                "{}",
                "───────────────────────────────────────────────────────────────".yellow()
            );
            for (idx, r) in flagged_reports.iter().enumerate() {
                let v_str = if lang.is_turkish() {
                    match r.verdict {
                        oil_core::models::Tier::HighRisk => "[YÜKSEK RİSK]".red().bold(),
                        oil_core::models::Tier::Suspicious => "[ŞÜPHELİ]".yellow().bold(),
                        _ => "[DİKKAT]".cyan().bold(),
                    }
                } else {
                    match r.verdict {
                        oil_core::models::Tier::HighRisk => "[HIGH RISK]".red().bold(),
                        oil_core::models::Tier::Suspicious => "[SUSPICIOUS]".yellow().bold(),
                        _ => "[NOTICE]".cyan().bold(),
                    }
                };

                let is_signed = r.autopsy.as_ref().and_then(|a| a.signature_valid) == Some(true);
                let priority_badge = if r.verdict_summary.contains("Untrusted Sideloading Loader")
                    || r.verdict_summary.contains("Local Hook")
                {
                    if lang.is_turkish() {
                        "[YEREL KANCA]".yellow().bold()
                    } else {
                        "[LOCAL HOOK]".yellow().bold()
                    }
                } else if r.verdict == oil_core::models::Tier::HighRisk {
                    if lang.is_turkish() {
                        "[ZARARLI YÜKLEYİCİ]".red().bold()
                    } else {
                        "[HOSTILE LOADER]".red().bold()
                    }
                } else if is_signed {
                    if lang.is_turkish() {
                        "[İMZALI]".cyan().bold()
                    } else {
                        "[VENDOR SIGNED]".cyan().bold()
                    }
                } else if lang.is_turkish() {
                    "[İMZASIZ ANOMALİ]".yellow().bold()
                } else {
                    "[UNSIGNED ANOMALY]".yellow().bold()
                };

                println!(
                    "  [{}] {} {} {}",
                    (idx + 1).to_string().cyan().bold(),
                    v_str,
                    priority_badge,
                    r.identity.path.display().to_string().bold()
                );
                let (en_reason, tr_reason) = if r
                    .verdict_summary
                    .contains("Untrusted Sideloading Loader")
                    || r.verdict_summary.contains("Local Hook")
                {
                    (
                        "Local Hook: Unsigned proxy DLL paired with loader (zero network, possible license hook).",
                        "Yerel Kanca: İmzasız proxy DLL ve loader ikilisi (sıfır ağ, olası lisans kancası)."
                    )
                } else if r.verdict_summary.contains("Hostile DLL Sideloading Suite") {
                    (
                        "Hostile Sideloading Suite: Unsigned proxy DLL paired with loader (network/injection IOC match).",
                        "Zararlı Yan Yükleme: İmzasız proxy DLL ve zararlı loader (ağ/enjeksiyon IOC eşleşti)."
                    )
                } else if r.verdict_summary.contains("search-order hijacking")
                    || r.verdict_summary.contains("proxy hook")
                {
                    (
                        "Windows system DLL shadowing / proxy hook (e.g. shadows 'version.dll').",
                        "Windows sistem DLL gölgeleme / proxy hook ('version.dll' kütüphanesini taklit ediyor)."
                    )
                } else if r
                    .verdict_summary
                    .contains("Process injection APIs paired with outbound network")
                {
                    if is_signed {
                        (
                            "Legitimate vendor telemetry/injection infrastructure (Verified signature present).",
                            "Meşru lisans/güncelleme altyapısı (Doğrulanmış üretici imzası mevcut)."
                        )
                    } else {
                        (
                            "Hostile capability combo: Process injection APIs paired with outbound network.",
                            "Şüpheli yetenek kombinasyonu: Süreç enjeksiyon API'leri ve dış ağ bağlantısı."
                        )
                    }
                } else if r.verdict_summary.contains("RWX memory permissions") {
                    (
                        "RWX (Read-Write-Execute) memory permissions (runtime unpacker pattern).",
                        "RWX (Okuma-Yazma-Çalıştırma) bellek izinleri (unpacker yapısı).",
                    )
                } else if r.verdict_summary.contains("Codeless data carrier") {
                    if is_signed {
                        (
                            "Codeless encrypted container (Verified vendor signature present).",
                            "Kodsuz şifreli veri konteyneri (Doğrulanmış üretici imzası mevcut).",
                        )
                    } else {
                        (
                            "Codeless encrypted payload carrier (no executable code section).",
                            "Kodsuz şifreli veri taşıyıcı (kod bölümü yok, saf payload konteyneri)."
                        )
                    }
                } else if r
                    .verdict_summary
                    .contains("High-entropy section detected within valid binary")
                    || r.verdict_summary.contains("Near-maximal section entropy")
                {
                    if is_signed {
                        (
                            "High-entropy section: Embedded license blob or compressed assets (Signed).",
                            "Bölüm içinde yüksek entropi: Gömülü lisans veya sıkıştırılmış kaynak (İmzalı)."
                        )
                    } else {
                        (
                            "High-entropy section (embedded encrypted payload or packer).",
                            "Bölüm içinde yüksek entropi (gömülü şifreli veri veya paketleyici).",
                        )
                    }
                } else {
                    (r.verdict_summary.as_str(), r.verdict_summary.as_str())
                };

                let reason = if lang.is_turkish() {
                    tr_reason
                } else {
                    en_reason
                };
                println!("      -> {}", reason);
            }
            println!(
                "{}",
                "═══════════════════════════════════════════════════════════════".cyan()
            );
            println!();
        }

        handle_post_scan_navigation(
            &reports,
            path,
            targets.len(),
            no_indicators,
            suspicious,
            high_risk,
            inconclusive,
            proxy_hook_count,
            duplicate_count,
            has_stealer_ioc,
            lang,
        );

        true
    } else {
        match oil_core::scan_path(path) {
            Ok(report) => {
                output::print_dossier(&report);
                // Executive summary box at the end of single file audit
                output::print_single_summary_box(&report, lang);
                true
            }
            Err(e) => {
                if lang.is_turkish() {
                    eprintln!("Dosya taranırken hata oluştu {}: {}", path.display(), e);
                } else {
                    eprintln!("Error scanning file {}: {}", path.display(), e);
                }
                false
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_post_scan_navigation(
    reports: &[oil_core::models::ScanReport],
    dir_path: &Path,
    total: usize,
    no_indicators: usize,
    suspicious: usize,
    high_risk: usize,
    inconclusive: usize,
    proxy_hook_count: usize,
    duplicate_count: usize,
    has_stealer_ioc: bool,
    lang: Language,
) {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return;
    }

    let flagged_reports: Vec<&oil_core::models::ScanReport> = reports
        .iter()
        .filter(|r| {
            matches!(
                r.verdict,
                oil_core::models::Tier::Suspicious | oil_core::models::Tier::HighRisk
            ) || r
                .evidence
                .iter()
                .any(|e| matches!(e.kind, oil_core::models::EvidenceKind::DllProxyHook { .. }))
        })
        .collect();

    loop {
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".cyan()
        );
        if lang.is_turkish() {
            println!("  {}", "[HIZLI ADLİ NAVİGASYON]".cyan().bold());
            println!(
                "{}",
                "═══════════════════════════════════════════════════════════════".cyan()
            );
            println!(
                "  {} Şüpheli Dosyaları İncele ({} dosya)",
                "[1]".green().bold(),
                flagged_reports.len()
            );
            println!(
                "  {} Taranan Tüm Dosyaları Listele ({} dosya)",
                "[2]".green().bold(),
                total
            );
            println!(
                "  {} Ekranı Temizle ve Özet Raporu Göster",
                "[3]".green().bold()
            );
            println!("  {} Ana Menüye Dön / Devam Et", "[4]".dimmed());
            println!();
            print!("{} ", "Navigasyon Seçimi >".green().bold());
        } else {
            println!("  {}", "[FORENSIC NAVIGATION & AUDIT BAR]".cyan().bold());
            println!(
                "{}",
                "═══════════════════════════════════════════════════════════════".cyan()
            );
            println!(
                "  {} Inspect Flagged / Suspicious Files ({} files)",
                "[1]".green().bold(),
                flagged_reports.len()
            );
            println!(
                "  {} List All Scanned Files ({} files)",
                "[2]".green().bold(),
                total
            );
            println!(
                "  {} Clear Console & Show Executive Summary",
                "[3]".green().bold()
            );
            println!("  {} Return to Main Menu / Continue", "[4]".dimmed());
            println!();
            print!("{} ", "Navigation Choice >".green().bold());
        }
        let _ = std::io::stdout().flush();

        let mut choice = String::new();
        if std::io::stdin().read_line(&mut choice).is_err() {
            break;
        }
        let trimmed = choice.trim();
        if trimmed.is_empty()
            || trimmed == "4"
            || trimmed.eq_ignore_ascii_case("q")
            || trimmed.eq_ignore_ascii_case("exit")
        {
            break;
        }

        match trimmed {
            "1" => {
                if flagged_reports.is_empty() {
                    if lang.is_turkish() {
                        println!(
                            "\n[OK] Klasörde herhangi bir şüpheli veya riskli dosya bulunmuyor."
                        );
                    } else {
                        println!("\n[OK] Zero flagged or suspicious files found in directory.");
                    }
                } else {
                    println!();
                    println!(
                        "{}",
                        "───────────────────────────────────────────────────────────────".yellow()
                    );
                    if lang.is_turkish() {
                        println!(
                            "  {} ŞÜPHELİ VE RİSKLİ DOSYALAR ({} adet)",
                            "[!]".yellow().bold(),
                            flagged_reports.len()
                        );
                    } else {
                        println!(
                            "  {} FLAGGED / SUSPICIOUS FILES ({} total)",
                            "[!]".yellow().bold(),
                            flagged_reports.len()
                        );
                    }
                    println!(
                        "{}",
                        "───────────────────────────────────────────────────────────────".yellow()
                    );
                    for (idx, r) in flagged_reports.iter().enumerate() {
                        let v_str = if lang.is_turkish() {
                            match r.verdict {
                                oil_core::models::Tier::HighRisk => "[YÜKSEK RİSK]".red().bold(),
                                oil_core::models::Tier::Suspicious => "[ŞÜPHELİ]".yellow().bold(),
                                _ => "[DİKKAT]".cyan().bold(),
                            }
                        } else {
                            match r.verdict {
                                oil_core::models::Tier::HighRisk => "[HIGH RISK]".red().bold(),
                                oil_core::models::Tier::Suspicious => {
                                    "[SUSPICIOUS]".yellow().bold()
                                }
                                _ => "[NOTICE]".cyan().bold(),
                            }
                        };

                        let is_signed =
                            r.autopsy.as_ref().and_then(|a| a.signature_valid) == Some(true);
                        let priority_badge =
                            if r.verdict_summary.contains("Untrusted Sideloading Loader")
                                || r.verdict_summary.contains("Local Hook")
                            {
                                if lang.is_turkish() {
                                    "[YEREL KANCA]".yellow().bold()
                                } else {
                                    "[LOCAL HOOK]".yellow().bold()
                                }
                            } else if r.verdict == oil_core::models::Tier::HighRisk {
                                if lang.is_turkish() {
                                    "[ZARARLI YÜKLEYİCİ]".red().bold()
                                } else {
                                    "[HOSTILE LOADER]".red().bold()
                                }
                            } else if is_signed {
                                if lang.is_turkish() {
                                    "[İMZALI]".cyan().bold()
                                } else {
                                    "[VENDOR SIGNED]".cyan().bold()
                                }
                            } else if lang.is_turkish() {
                                "[İMZASIZ ANOMALİ]".yellow().bold()
                            } else {
                                "[UNSIGNED ANOMALY]".yellow().bold()
                            };

                        println!(
                            "  [{}] {} {} {}",
                            (idx + 1).to_string().cyan().bold(),
                            v_str,
                            priority_badge,
                            r.identity.path.display().to_string().bold()
                        );
                        let (en_reason, tr_reason) = if r
                            .verdict_summary
                            .contains("Untrusted Sideloading Loader")
                            || r.verdict_summary.contains("Local Hook")
                        {
                            (
                                "Local Hook: Unsigned proxy DLL paired with loader (zero network, possible license hook).",
                                "Yerel Kanca: İmzasız proxy DLL ve loader ikilisi (sıfır ağ, olası lisans kancası)."
                            )
                        } else if r.verdict_summary.contains("Hostile DLL Sideloading Suite") {
                            (
                                "Hostile Sideloading Suite: Unsigned proxy DLL paired with hostile loader (network/injection IOCs).",
                                "Zararlı Yan Yükleme: İmzasız proxy DLL ve zararlı loader ikilisi (ağ/enjeksiyon IOC)."
                            )
                        } else if r.verdict_summary.contains("search-order hijacking")
                            || r.verdict_summary.contains("proxy hook")
                        {
                            (
                                "Windows system DLL shadowing / proxy hook (e.g. shadows 'version.dll').",
                                "Sistem DLL gölgeleme / proxy hook ('version.dll' sistem kütüphanesini taklit ediyor)."
                            )
                        } else if r
                            .verdict_summary
                            .contains("Process injection APIs paired with outbound network")
                        {
                            (
                                "Hostile capability combo: Process injection APIs paired with outbound network.",
                                "Şüpheli yetenek kombinasyonu: Süreç enjeksiyon API'leri ve dış ağ bağlantısı."
                            )
                        } else if r.verdict_summary.contains("RWX memory permissions") {
                            (
                                "RWX (Read-Write-Execute) memory permissions (runtime unpacker pattern).",
                                "RWX (Okuma-Yazma-Çalıştırma) bellek izinleri (unpacker yapısı)."
                            )
                        } else if r.verdict_summary.contains("Codeless data carrier") {
                            (
                                "Codeless encrypted payload carrier (no executable code section).",
                                "Kodsuz şifreli veri taşıyıcı (kod bölümü yok, saf payload konteyneri)."
                            )
                        } else if r
                            .verdict_summary
                            .contains("High-entropy section detected within valid binary")
                            || r.verdict_summary.contains("Near-maximal section entropy")
                        {
                            (
                                "High-entropy section (embedded encrypted payload or packer).",
                                "Bölüm içinde yüksek entropi (gömülü sıkıştırılmış veri veya lisans)."
                            )
                        } else {
                            (r.verdict_summary.as_str(), r.verdict_summary.as_str())
                        };

                        let reason = if lang.is_turkish() {
                            tr_reason
                        } else {
                            en_reason
                        };
                        println!("      -> {}", reason);
                    }
                    println!(
                        "{}",
                        "───────────────────────────────────────────────────────────────".yellow()
                    );
                    if lang.is_turkish() {
                        println!(
                            "Detaylı otopsi için dosya no [1-{}]: (Geri dönmek için Enter)",
                            flagged_reports.len()
                        );
                        print!("{} ", "Dosya No >".bold());
                    } else {
                        println!(
                            "Enter file number for deep autopsy [1-{}]: (Press Enter to go back)",
                            flagged_reports.len()
                        );
                        print!("{} ", "File # >".bold());
                    }
                    let _ = std::io::stdout().flush();
                    let mut num_str = String::new();
                    let _ = std::io::stdin().read_line(&mut num_str);
                    if let Ok(num) = num_str.trim().parse::<usize>() {
                        if num >= 1 && num <= flagged_reports.len() {
                            println!();
                            println!(
                                "{}",
                                "───────────────────────────────────────────────────────────────"
                                    .cyan()
                            );
                            if lang.is_turkish() {
                                println!(
                                    "  DOSYA DETAY OTOPSİSİ [#{}] - {}",
                                    num,
                                    flagged_reports[num - 1].identity.path.display()
                                );
                            } else {
                                println!(
                                    "  FILE AUTOPSY DOSSIER [#{}] - {}",
                                    num,
                                    flagged_reports[num - 1].identity.path.display()
                                );
                            }
                            println!(
                                "{}",
                                "───────────────────────────────────────────────────────────────"
                                    .cyan()
                            );
                            output::print_dossier(flagged_reports[num - 1]);
                        }
                    }
                }
            }
            "2" => {
                println!();
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".cyan()
                );
                if lang.is_turkish() {
                    println!("  TARANAN TÜM DOSYALAR ({} dosya)", total);
                } else {
                    println!("  ALL SCANNED FILES COMPACT STATUS ({} files)", total);
                }
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".cyan()
                );
                for (idx, r) in reports.iter().enumerate() {
                    let badge = if lang.is_turkish() {
                        match r.verdict {
                            oil_core::models::Tier::HighRisk => "[!] [YÜKSEK RİSK]".red().bold(),
                            oil_core::models::Tier::Suspicious => "[!] [ŞÜPHELİ]".yellow().bold(),
                            oil_core::models::Tier::NoIndicatorsFound => {
                                "[+] [GÖSTERGE BULUNAMADI]".green().bold()
                            }
                            oil_core::models::Tier::Inconclusive => {
                                "[-] [KARARSIZ]".magenta().bold()
                            }
                        }
                    } else {
                        match r.verdict {
                            oil_core::models::Tier::HighRisk => "[!] [HIGH RISK]".red().bold(),
                            oil_core::models::Tier::Suspicious => {
                                "[!] [SUSPICIOUS]".yellow().bold()
                            }
                            oil_core::models::Tier::NoIndicatorsFound => {
                                "[+] [NO INDICATORS FOUND]".green().bold()
                            }
                            oil_core::models::Tier::Inconclusive => {
                                "[-] [INCONCLUSIVE]".magenta().bold()
                            }
                        }
                    };
                    let fname = r
                        .identity
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("?");
                    println!("  {:3}. {} {}", idx + 1, badge, fname);
                }
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".cyan()
                );
            }
            "3" => {
                print!("\x1B[2J\x1B[1;1H");
                let _ = std::io::stdout().flush();
                output::print_directory_summary_box(
                    dir_path,
                    total,
                    no_indicators,
                    suspicious,
                    high_risk,
                    inconclusive,
                    proxy_hook_count,
                    duplicate_count,
                    has_stealer_ioc,
                    lang,
                );
            }
            _ => {
                if lang.is_turkish() {
                    println!("Geçersiz seçim. [1-4] arasında bir numara giriniz.");
                } else {
                    println!("Invalid choice. Enter a number between 1 and 4.");
                }
            }
        }
        println!();
    }
}

fn run_diff(original: &Path, patched: &Path, lang: Language) -> bool {
    if !original.exists() {
        if lang.is_turkish() {
            eprintln!("Hata: Orijinal dosya bulunamadı: {}", original.display());
        } else {
            eprintln!("Error: Original binary not found: {}", original.display());
        }
        return false;
    }
    if !patched.exists() {
        if lang.is_turkish() {
            eprintln!("Hata: Yamalı dosya bulunamadı: {}", patched.display());
        } else {
            eprintln!("Error: Patched binary not found: {}", patched.display());
        }
        return false;
    }

    match oil_core::diff::diff_binaries(original, patched) {
        Ok(report) => {
            output::print_diff_dossier(&report, lang);
            true
        }
        Err(e) => {
            if lang.is_turkish() {
                eprintln!("Hata: İkili yama analizi başarısız: {}", e);
            } else {
                eprintln!("Error: Binary diff analysis failed: {}", e);
            }
            false
        }
    }
}

fn run_hunt(dir: Option<PathBuf>, lang: Language) {
    let mut report = oil_core::hunt::run_persistence_audit();
    if let Some(d) = dir {
        if d.exists() && d.is_dir() {
            let sideloads = oil_core::hunt::audit_directory_for_sideloads(&d);
            report.total_inspected += sideloads.len();
            for item in sideloads {
                if let Some(ref scan) = item.scan_report {
                    match scan.verdict {
                        oil_core::models::Tier::HighRisk => report.high_risk_count += 1,
                        oil_core::models::Tier::Suspicious => report.suspicious_count += 1,
                        oil_core::models::Tier::NoIndicatorsFound => {
                            report.no_indicators_count += 1
                        }
                        oil_core::models::Tier::Inconclusive => {}
                    }
                }
                report.items.push(item);
            }
        }
    }
    output::print_hunt_dossier(&report, lang);
}

fn print_pumpjack_banner(lang: Language) {
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────────────────────".cyan()
    );
    if lang.is_turkish() {
        println!(
            "{}{}",
            "             .---.                    ".cyan(),
            "OIL // GÜVENLİK, MOD & YAMA ANALİZİ (v0.1.0)".bold()
        );
        println!(
            "{}{}",
            "            /     \\========[+]        ".cyan(),
            "Mod, Crack & İkili Dosya İnceleme Motoru".dimmed()
        );
        println!(
            "{}{}",
            "      __   /   o   \\        |         ".cyan(),
            "Zararlı Yazılım & DLL Kancası Tespiti".dimmed()
        );
        println!(
            "{}{}",
            "     |  | /_________\\       |         ".cyan(),
            "Sıfır Bulut Bağımlılığı • Bellek İçi Analiz".dimmed()
        );
        println!(
            "{}{}",
            "     |  |     | |           |         ".cyan(),
            "Çevrimdışı Çalışma • Fail-Closed Model".dimmed()
        );
        println!("{}", "    /|  |\\   /   \\         / \\".cyan());
    } else {
        println!(
            "{}{}",
            "             .---.                    ".cyan(),
            "OIL // BINARY, MOD & PATCH SECURITY (v0.1.0)".bold()
        );
        println!(
            "{}{}",
            "            /     \\========[+]        ".cyan(),
            "Mod, Crack & Binary Inspection Engine".dimmed()
        );
        println!(
            "{}{}",
            "      __   /   o   \\        |         ".cyan(),
            "Malware & DLL Sideloading Detection".dimmed()
        );
        println!(
            "{}{}",
            "     |  | /_________\\       |         ".cyan(),
            "Zero Cloud Dependency • In-Memory Analysis".dimmed()
        );
        println!(
            "{}{}",
            "     |  |     | |           |         ".cyan(),
            "Offline Execution • Fail-Closed Model".dimmed()
        );
        println!("{}", "    /|  |\\   /   \\         / \\".cyan());
    }
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────────────────────".cyan()
    );
}

fn print_menu(lang: Language) {
    println!();
    print_pumpjack_banner(lang);
    println!();
    if lang.is_turkish() {
        println!(
            "  {}",
            "────────────────────────────────────────────────────────────────────────────".dimmed()
        );
        println!(
            "  {}  {}",
            "[1]".green().bold(),
            "Dosya veya klasör tara".bold()
        );
        println!(
            "       {}",
            "Bir .exe, .dll, .zip veya klasörü sürükle/yapıştır, ne olduğunu öğren.".dimmed()
        );
        println!();
        println!(
            "  {}  {}",
            "[2]".green().bold(),
            "Bilgisayarımda gizli tehdit var mı?".bold()
        );
        println!(
            "       {}",
            "Windows başlangıcına ve sistem klasörlerine yerleşmiş şüpheli dosyaları bul.".dimmed()
        );
        println!();
        println!(
            "  {}  {}",
            "[3]".green().bold(),
            "Orijinal ile crack farkını göster".bold()
        );
        println!(
            "       {}",
            "Orijinal dosya ile yamalı/kırılmış dosyayı karşılaştır, neyin değiştiğini gör."
                .dimmed()
        );
        println!();
        println!("  {}  {}", "[4]".dimmed(), "Çıkış".dimmed());
        println!(
            "  {}",
            "────────────────────────────────────────────────────────────────────────────".dimmed()
        );
        println!();
        println!(
            "  {}",
            "İpucu: Dosya veya klasörü doğrudan bu pencereye sürükleyip bırakabilirsiniz.".yellow()
        );
    } else {
        println!(
            "  {}",
            "────────────────────────────────────────────────────────────────────────────".dimmed()
        );
        println!(
            "  {}  {}",
            "[1]".green().bold(),
            "Scan a file or folder".bold()
        );
        println!(
            "       {}",
            "Drag/paste any .exe, .dll, .zip or folder to find out what's inside.".dimmed()
        );
        println!();
        println!(
            "  {}  {}",
            "[2]".green().bold(),
            "Check my PC for hidden threats".bold()
        );
        println!(
            "       {}",
            "Find suspicious files planted in Windows startup or system folders.".dimmed()
        );
        println!();
        println!(
            "  {}  {}",
            "[3]".green().bold(),
            "Compare original vs. cracked file".bold()
        );
        println!(
            "       {}",
            "See exactly what changed between the original and the patched/cracked version."
                .dimmed()
        );
        println!();
        println!("  {}  {}", "[4]".dimmed(), "Exit".dimmed());
        println!(
            "  {}",
            "────────────────────────────────────────────────────────────────────────────".dimmed()
        );
        println!();
        println!(
            "  {}",
            "Hint: Drag and drop any file or folder directly into this window!".yellow()
        );
    }
    println!();
}

fn run_interactive_mode(lang: Language) {
    use colored::Colorize;
    use std::io::{stdin, stdout, Write};

    print_menu(lang);

    loop {
        print!("  {} ❯ ", "oil".green().bold());
        let _ = stdout().flush();

        let mut line = String::new();
        if stdin().read_line(&mut line).is_err() {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            println!();
            continue;
        }

        if trimmed == "4"
            || trimmed.eq_ignore_ascii_case("q")
            || trimmed.eq_ignore_ascii_case("exit")
        {
            if lang.is_turkish() {
                println!("  Oil kapatılıyor...");
            } else {
                println!("  Exiting Oil...");
            }
            break;
        }

        if trimmed.eq_ignore_ascii_case("help")
            || trimmed.eq_ignore_ascii_case("m")
            || trimmed.eq_ignore_ascii_case("menu")
        {
            print_menu(lang);
            continue;
        }

        match trimmed {
            "1" => {
                if lang.is_turkish() {
                    print!(
                        "  {} ❯ ",
                        "Taranacak hedef yol (dosya / klasör)".cyan().bold()
                    );
                } else {
                    print!("  {} ❯ ", "Target path (file / folder)".cyan().bold());
                }
                let _ = stdout().flush();
                let mut p_str = String::new();
                let _ = stdin().read_line(&mut p_str);
                if let Some(path) = clean_input_path(&p_str) {
                    run_scan(&path, lang);
                } else if lang.is_turkish() {
                    eprintln!("  Hata: Geçersiz veya boş dosya yolu.");
                } else {
                    eprintln!("  Error: Invalid or empty path.");
                }
            }
            "2" => {
                if lang.is_turkish() {
                    println!("\n  Bilgisayarda gizli tehditler aranıyor...\n");
                } else {
                    println!("\n  Scanning for hidden threats on this PC...\n");
                }
                run_hunt(None, lang);
            }
            "3" => {
                if lang.is_turkish() {
                    print!("\n  {} ❯ ", "Orijinal dosya yolu".cyan().bold());
                    let _ = stdout().flush();
                    let mut o_str = String::new();
                    let _ = stdin().read_line(&mut o_str);
                    let orig = clean_input_path(&o_str);

                    print!("  {} ❯ ", "Yamalı / crack dosya yolu".cyan().bold());
                    let _ = stdout().flush();
                    let mut p_str = String::new();
                    let _ = stdin().read_line(&mut p_str);
                    let patched = clean_input_path(&p_str);

                    if let (Some(o), Some(p)) = (orig, patched) {
                        run_diff(&o, &p, lang);
                    } else {
                        eprintln!("  Hata: Dosya yolları geçerli değil.");
                    }
                } else {
                    print!("\n  {} ❯ ", "Original binary path".cyan().bold());
                    let _ = stdout().flush();
                    let mut o_str = String::new();
                    let _ = stdin().read_line(&mut o_str);
                    let orig = clean_input_path(&o_str);

                    print!("  {} ❯ ", "Patched / cracked binary path".cyan().bold());
                    let _ = stdout().flush();
                    let mut p_str = String::new();
                    let _ = stdin().read_line(&mut p_str);
                    let patched = clean_input_path(&p_str);

                    if let (Some(o), Some(p)) = (orig, patched) {
                        run_diff(&o, &p, lang);
                    } else {
                        eprintln!("  Error: Invalid file paths.");
                    }
                }
            }
            // Hidden developer command — not shown in menu
            "lab" => {
                output::run_lab_suite();
            }
            user_input => {
                // Drag & drop or direct path typed
                if let Some(path) = clean_input_path(user_input) {
                    run_scan(&path, lang);
                } else if lang.is_turkish() {
                    println!(
                        "  {} {}",
                        format!("Geçersiz seçim: '{}'.", user_input).red(),
                        "Menü: 'm' / 'help'".dimmed()
                    );
                } else {
                    println!(
                        "  {} {}",
                        format!("Invalid choice: '{}'.", user_input).red(),
                        "Menu: 'm' / 'help'".dimmed()
                    );
                }
            }
        }

        println!();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let detected_lang = Language::detect();

    // 1. Drag & Drop onto oil.exe icon in Windows Explorer
    if args.len() >= 2 {
        let first = args[1].trim_matches('"').trim_matches('\'');
        let is_subcommand_or_flag = matches!(
            first,
            "scan"
                | "diff"
                | "hunt"
                | "lab"
                | "help"
                | "-h"
                | "--help"
                | "-V"
                | "--version"
                | "--lang"
        );

        if !is_subcommand_or_flag {
            if detected_lang.is_turkish() {
                println!(
                    "OIL // Doğrudan Hedef İncelemesi {}\n",
                    "(Sürükle & Bırak Modu)".dimmed()
                );
            } else {
                println!(
                    "OIL // Direct Target Inspection {}\n",
                    "(Drag & Drop Mode)".dimmed()
                );
            }
            for arg in &args[1..] {
                if let Some(candidate) = clean_input_path(arg) {
                    run_scan(&candidate, detected_lang);
                }
            }
            if detected_lang.is_turkish() {
                println!(
                    "\n[Tarama tamamlandı. Başka bir dosya sürükleyin veya çıkmak için Enter'a basın]"
                );
                print!(
                    "{}: ",
                    "Seçim veya Dosya Yolu (Enter: Çıkış)".green().bold()
                );
            } else {
                println!("\n[Scan complete. Drag another file or press Enter to exit]");
                print!("{}: ", "Choice or File Path (Enter: Exit)".green().bold());
            }
            let _ = std::io::stdout().flush();
            let mut buf = String::new();
            if std::io::stdin().read_line(&mut buf).is_ok() {
                let trimmed = buf.trim();
                if !trimmed.is_empty() && trimmed != "q" && trimmed != "5" && trimmed != "exit" {
                    if let Some(next_candidate) = clean_input_path(trimmed) {
                        run_scan(&next_candidate, detected_lang);
                    }
                    // Transition directly into continuous interactive mode
                    run_interactive_mode(detected_lang);
                }
            }
            return;
        }
    }

    // 2. Direct double-click without arguments
    if args.len() <= 1 {
        run_interactive_mode(detected_lang);
        return;
    }

    // 3. Standard CLI invocation
    let cli = Cli::parse();
    let lang = Language::resolve(cli.lang.as_deref());

    match cli.command {
        Some(Commands::Scan { path }) => {
            if !run_scan(&path, lang) {
                std::process::exit(1);
            }
        }
        Some(Commands::Diff { original, patched }) => {
            if !run_diff(&original, &patched, lang) {
                std::process::exit(1);
            }
        }
        Some(Commands::Hunt { dir }) => {
            run_hunt(dir, lang);
        }
        Some(Commands::Lab) => {
            output::run_lab_suite();
        }
        None => {
            run_interactive_mode(lang);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_pumpjack_banner_no_panic() {
        print_pumpjack_banner(Language::Turkish);
        print_pumpjack_banner(Language::English);
    }

    #[test]
    fn test_clean_input_path() {
        assert_eq!(clean_input_path(""), None);
        assert_eq!(clean_input_path("   "), None);
        assert_eq!(clean_input_path("invalid_choice_no_extension"), None);
        assert!(clean_input_path("Cargo.toml").is_some());
        assert_eq!(
            clean_input_path("& 'C:\\path\\file.exe'"),
            Some(PathBuf::from("C:\\path\\file.exe"))
        );
    }
}
