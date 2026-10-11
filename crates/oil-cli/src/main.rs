mod output;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "oil")]
#[command(version = "0.1.0")]
#[command(about = "The Frictionless Reverse-Engineering & Binary Forensic Triage Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    if direct_str.contains('\\') || direct_str.contains('/') || direct_str.contains(':') || direct_str.contains('.') {
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
                if !dir_name.starts_with('$') && !dir_name.eq_ignore_ascii_case("System Volume Information") {
                    collect_recursive(&p, current_depth + 1, max_depth, out);
                }
            }
        }
    }
}

fn run_scan(path: &Path) -> bool {
    if !path.exists() {
        eprintln!(
            "Error: Target not found / {}: {}",
            "Hedef bulunamadı".dimmed(),
            path.display()
        );
        return false;
    }

    if path.is_dir() {
        let targets = collect_executable_targets(path, 5);
        if targets.is_empty() {
            println!(
                "No executable targets (.exe, .dll, .lnk, .zip) found in / {}: {}",
                "Hedef bulunamadı".dimmed(),
                path.display()
            );
            return true;
        }

        println!(
            "\nDirectory Scan Initiated / {}: '{}' ({} files / {})",
            "Klasör Taraması Başlatıldı".dimmed(),
            path.display(),
            targets.len(),
            "dosya".dimmed()
        );

        let mut reports: Vec<oil_core::models::ScanReport> = Vec::new();
        let mut dedupe_info: Vec<(usize, PathBuf, Option<PathBuf>)> = Vec::new();
        let mut seen_hashes: std::collections::HashMap<String, (PathBuf, oil_core::models::ScanReport)> = std::collections::HashMap::new();
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
                    seen_hashes.insert(report.identity.sha256.clone(), (p.to_path_buf(), report.clone()));
                    reports.push(report);
                }
                Err(e) => {
                    eprintln!(
                        "Error reading file {} ({}): {}",
                        p.display(),
                        "Dosya okunurken hata oluştu".dimmed(),
                        e
                    );
                    let (sha256, blake3) = oil_core::io::dual_hash_file(p).unwrap_or_else(|_| (String::new(), String::new()));
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
                        verdict_summary: format!("Failed to read file / {}: {}", "Dosya okuma hatası".dimmed(), e),
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
            println!(
                "\n[{}/{}] Scanning / {}: {}",
                idx + 1,
                targets.len(),
                "Taranıyor".dimmed(),
                p.display()
            );
            if let Some(ref first_path) = dup {
                println!(
                    "  {} SHA-256 Match ({}...): Exact duplicate of '{}'. {}",
                    "[+]".green().bold(),
                    &report.identity.sha256[..12],
                    first_path.display(),
                    format!("(Birebir aynı dosya - analiz atlandı)").dimmed()
                );
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
                    .filter(|e| matches!(&e.kind, oil_core::models::EvidenceKind::DllProxyHook { .. }))
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
            println!("{}", "───────────────────────────────────────────────────────────────".yellow());
            println!(
                "  {} PRIORITY BREAKDOWN: FLAGGED & ANOMALOUS FILES ({} total) {}",
                "[!]".yellow().bold(),
                flagged_reports.len(),
                format!("// Şüpheli ve Riskli Dosyalar").dimmed()
            );
            println!("{}", "───────────────────────────────────────────────────────────────".yellow());
            for (idx, r) in flagged_reports.iter().enumerate() {
                let v_str = match r.verdict {
                    oil_core::models::Tier::HighRisk => format!("{} {}", "[HIGH RISK]".red().bold(), format!("[YÜKSEK RİSK]").red().dimmed()),
                    oil_core::models::Tier::Suspicious => format!("{} {}", "[SUSPICIOUS]".yellow().bold(), format!("[ŞÜPHELİ]").yellow().dimmed()),
                    _ => format!("{} {}", "[NOTICE]".cyan().bold(), format!("[DİKKAT]").cyan().dimmed()),
                };

                let is_signed = r.autopsy.as_ref().and_then(|a| a.signature_valid) == Some(true);
                let priority_badge = if r.verdict_summary.contains("Untrusted Sideloading Loader")
                    || r.verdict_summary.contains("Local Hook")
                {
                    format!("{} {}", "[LOCAL HOOK]".yellow().bold(), format!("[YEREL KANCA]").yellow().dimmed())
                } else if r.verdict == oil_core::models::Tier::HighRisk {
                    format!("{} {}", "[HOSTILE LOADER]".red().bold(), format!("[ZARARLI YÜKLEYİCİ]").red().dimmed())
                } else if is_signed {
                    format!("{} {}", "[VENDOR SIGNED]".cyan().bold(), format!("[İMZALI KORUMA]").cyan().dimmed())
                } else {
                    format!("{} {}", "[UNSIGNED ANOMALY]".yellow().bold(), format!("[İMZASIZ ANOMALİ]").yellow().dimmed())
                };

                println!(
                    "  [{}] {} {} {}",
                    (idx + 1).to_string().cyan().bold(),
                    v_str,
                    priority_badge,
                    r.identity.path.display().to_string().bold()
                );
                let (en_reason, tr_reason) = if r.verdict_summary.contains("Untrusted Sideloading Loader")
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
                } else if r.verdict_summary.contains("search-order hijacking") || r.verdict_summary.contains("proxy hook") {
                    (
                        "Windows system DLL shadowing / proxy hook (e.g. shadows 'version.dll').",
                        "Windows sistem DLL gölgeleme / proxy hook ('version.dll' kütüphanesini taklit ediyor)."
                    )
                } else if r.verdict_summary.contains("Process injection APIs paired with outbound network") {
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
                        "RWX (Okuma-Yazma-Çalıştırma) bellek izinleri (unpacker yapısı)."
                    )
                } else if r.verdict_summary.contains("Codeless data carrier") {
                    if is_signed {
                        (
                            "Codeless encrypted container (Verified vendor signature present).",
                            "Kodsuz şifreli veri konteyneri (Doğrulanmış üretici imzası mevcut)."
                        )
                    } else {
                        (
                            "Codeless encrypted payload carrier (no executable code section).",
                            "Kodsuz şifreli veri taşıyıcı (kod bölümü yok, saf payload konteyneri)."
                        )
                    }
                } else if r.verdict_summary.contains("High-entropy section detected within valid binary") || r.verdict_summary.contains("Near-maximal section entropy") {
                    if is_signed {
                        (
                            "High-entropy section: Embedded license blob or compressed assets (Signed).",
                            "Bölüm içinde yüksek entropi: Gömülü lisans veya sıkıştırılmış kaynak (İmzalı)."
                        )
                    } else {
                        (
                            "High-entropy section (embedded encrypted payload or packer).",
                            "Bölüm içinde yüksek entropi (gömülü şifreli veri veya paketleyici)."
                        )
                    }
                } else {
                    (r.verdict_summary.as_str(), "")
                };

                println!("      -> {}", en_reason);
                if !tr_reason.is_empty() {
                    println!("         {}", format!("({})", tr_reason).dimmed());
                }
            }
            println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
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
        );

        true
    } else {
        match oil_core::scan_path(path) {
            Ok(report) => {
                output::print_dossier(&report);
                // Executive summary box at the end of single file audit
                output::print_single_summary_box(&report);
                true
            }
            Err(e) => {
                eprintln!(
                    "Error scanning file {} ({}): {}",
                    path.display(),
                    "Dosya taranırken hata oluştu".dimmed(),
                    e
                );
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
        println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
        println!(
            "  {} {}",
            "[FORENSIC NAVIGATION & AUDIT BAR]".cyan().bold(),
            format!("// [HIZLI ADLİ NAVİGASYON]").cyan().dimmed()
        );
        println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
        println!(
            "  {} Inspect Flagged / Suspicious Files {} ({} files / {})",
            "[1]".green().bold(),
            format!("/ Şüpheli Dosyaları İncele").dimmed(),
            flagged_reports.len(),
            "dosya".dimmed()
        );
        println!(
            "  {} List All Scanned Files {} ({} files / {})",
            "[2]".green().bold(),
            format!("/ Taranan Tüm Dosyaları Listele").dimmed(),
            total,
            "dosya".dimmed()
        );
        println!(
            "  {} Clear Console & Show Executive Summary {}",
            "[3]".green().bold(),
            format!("/ Başa Dön ve Özet Raporu Göster").dimmed()
        );
        println!(
            "  {} Return to Main Menu / Continue {}",
            "[4]".dimmed(),
            format!("/ Ana Menüye Dön").dimmed()
        );
        println!();
        print!(
            "{} / {}: ",
            "Navigation Choice".green().bold(),
            "Navigasyon Seçimi >".green().dimmed()
        );
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
                    println!(
                        "\n[OK] Zero flagged or suspicious files found in directory. {}",
                        format!("(Klasörde herhangi bir şüpheli veya riskli dosya bulunmuyor.)").dimmed()
                    );
                } else {
                    println!();
                    println!("{}", "───────────────────────────────────────────────────────────────".yellow());
                    println!(
                        "  {} FLAGGED / SUSPICIOUS FILES ({} total) {}",
                        "[!]".yellow().bold(),
                        flagged_reports.len(),
                        format!("// Şüpheli Dosyalar").dimmed()
                    );
                    println!("{}", "───────────────────────────────────────────────────────────────".yellow());
                    for (idx, r) in flagged_reports.iter().enumerate() {
                        let v_str = match r.verdict {
                            oil_core::models::Tier::HighRisk => format!("{} {}", "[HIGH RISK]".red().bold(), format!("[YÜKSEK RİSK]").red().dimmed()),
                            oil_core::models::Tier::Suspicious => format!("{} {}", "[SUSPICIOUS]".yellow().bold(), format!("[ŞÜPHELİ]").yellow().dimmed()),
                            _ => format!("{} {}", "[NOTICE]".cyan().bold(), format!("[DİKKAT]").cyan().dimmed()),
                        };

                        let priority_badge = if r.verdict_summary.contains("Untrusted Sideloading Loader")
                            || r.verdict_summary.contains("Local Hook")
                        {
                            format!("{} {}", "[LOCAL HOOK]".yellow().bold(), format!("[YEREL KANCA]").yellow().dimmed())
                        } else if r.verdict == oil_core::models::Tier::HighRisk {
                            format!("{} {}", "[HOSTILE LOADER]".red().bold(), format!("[ZARARLI YÜKLEYİCİ]").red().dimmed())
                        } else if r.autopsy.as_ref().and_then(|a| a.signature_valid) == Some(true) {
                            format!("{} {}", "[VENDOR SIGNED]".cyan().bold(), format!("[İMZALI KORUMA]").cyan().dimmed())
                        } else {
                            format!("{} {}", "[UNSIGNED ANOMALY]".yellow().bold(), format!("[İMZASIZ ANOMALİ]").yellow().dimmed())
                        };

                        println!(
                            "  [{}] {} {} {}",
                            (idx + 1).to_string().cyan().bold(),
                            v_str,
                            priority_badge,
                            r.identity.path.display().to_string().bold()
                        );
                        let (en_reason, tr_reason) = if r.verdict_summary.contains("Untrusted Sideloading Loader")
                            || r.verdict_summary.contains("Local Hook")
                        {
                            (
                                "Local Hook: Unsigned proxy DLL paired with loader (zero network, possible license hook).",
                                "Yerel Kanca: İmzasız proxy DLL ve loader ikilisi (sıfır ağ, olası lisans baypası)."
                            )
                        } else if r.verdict_summary.contains("Hostile DLL Sideloading Suite") {
                            (
                                "Hostile Sideloading Suite: Unsigned proxy DLL paired with hostile loader (network/injection IOCs).",
                                "Zararlı Yan Yükleme: İmzasız proxy DLL ve zararlı loader ikilisi (ağ/enjeksiyon IOC)."
                            )
                        } else if r.verdict_summary.contains("search-order hijacking") || r.verdict_summary.contains("proxy hook") {
                            (
                                "Windows system DLL shadowing / proxy hook (e.g. shadows 'version.dll').",
                                "Sistem DLL gölgeleme / proxy hook ('version.dll' sistem kütüphanesini taklit ediyor)."
                            )
                        } else if r.verdict_summary.contains("Process injection APIs paired with outbound network") {
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
                        } else if r.verdict_summary.contains("High-entropy section detected within valid binary") || r.verdict_summary.contains("Near-maximal section entropy") {
                            (
                                "High-entropy section (embedded encrypted payload or packer).",
                                "Bölüm içinde yüksek entropi (gömülü sıkıştırılmış veri veya lisans)."
                            )
                        } else {
                            (r.verdict_summary.as_str(), "")
                        };

                        println!("      -> {}", en_reason);
                        if !tr_reason.is_empty() {
                            println!("         {}", format!("({})", tr_reason).dimmed());
                        }
                    }
                    println!("{}", "───────────────────────────────────────────────────────────────".yellow());
                    println!(
                        "Enter file number for deep autopsy [1-{}]: {}",
                        flagged_reports.len(),
                        format!("(Detaylı otopsi için dosya no)").dimmed()
                    );
                    println!("{}", "(Press Enter to go back / Geri dönmek için Enter)".dimmed());
                    print!("{} / {}: ", "File #".bold(), "Dosya No >".dimmed());
                    let _ = std::io::stdout().flush();
                    let mut num_str = String::new();
                    let _ = std::io::stdin().read_line(&mut num_str);
                    if let Ok(num) = num_str.trim().parse::<usize>() {
                        if num >= 1 && num <= flagged_reports.len() {
                            println!();
                            println!("{}", "───────────────────────────────────────────────────────────────".cyan());
                            println!(
                                "  FILE AUTOPSY DOSSIER [#{}] / {}: {}",
                                num,
                                format!("DOSYA DETAYI").dimmed(),
                                flagged_reports[num - 1].identity.path.display()
                            );
                            println!("{}", "───────────────────────────────────────────────────────────────".cyan());
                            output::print_dossier(flagged_reports[num - 1]);
                        }
                    }
                }
            }
            "2" => {
                println!();
                println!("{}", "───────────────────────────────────────────────────────────────".cyan());
                println!(
                    "  ALL SCANNED FILES COMPACT STATUS ({} files) {}",
                    total,
                    format!("// Taranan Tüm Dosyalar").dimmed()
                );
                println!("{}", "───────────────────────────────────────────────────────────────".cyan());
                for (idx, r) in reports.iter().enumerate() {
                    let badge = match r.verdict {
                        oil_core::models::Tier::HighRisk => format!("{} {}", "[!] [HIGH RISK]".red().bold(), format!("[YÜKSEK RİSK]").red().dimmed()),
                        oil_core::models::Tier::Suspicious => format!("{} {}", "[!] [SUSPICIOUS]".yellow().bold(), format!("[ŞÜPHELİ]").yellow().dimmed()),
                        oil_core::models::Tier::NoIndicatorsFound => format!("{} {}", "[+] [NO INDICATORS]".green().bold(), format!("[BELİRTİSİZ]").green().dimmed()),
                        oil_core::models::Tier::Inconclusive => format!("{} {}", "[-] [INCONCLUSIVE]".magenta().bold(), format!("[KARARSIZ]").magenta().dimmed()),
                    };
                    let fname = r
                        .identity
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("?");
                    println!("  {:3}. {} {}", idx + 1, badge, fname);
                }
                println!("{}", "───────────────────────────────────────────────────────────────".cyan());
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
                );
            }
            _ => {
                println!(
                    "Invalid choice. Enter [1-4] {}.",
                    format!("(Geçersiz seçim. [1-4] arasında bir numara giriniz.)").dimmed()
                );
            }
        }
        println!();
    }
}

fn run_diff(original: &Path, patched: &Path) -> bool {
    if !original.exists() {
        eprintln!(
            "Error: Original binary not found / {}: {}",
            "Orijinal dosya bulunamadı".dimmed(),
            original.display()
        );
        return false;
    }
    if !patched.exists() {
        eprintln!(
            "Error: Patched binary not found / {}: {}",
            "Yamalı dosya bulunamadı".dimmed(),
            patched.display()
        );
        return false;
    }

    match oil_core::diff::diff_binaries(original, patched) {
        Ok(report) => {
            output::print_diff_dossier(&report);
            true
        }
        Err(e) => {
            eprintln!(
                "Error: Binary diff analysis failed / {}: {}",
                "İkili yama analizi başarısız".dimmed(),
                e
            );
            false
        }
    }
}

fn run_hunt(dir: Option<PathBuf>) {
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
                        oil_core::models::Tier::NoIndicatorsFound => report.no_indicators_count += 1,
                        oil_core::models::Tier::Inconclusive => {}
                    }
                }
                report.items.push(item);
            }
        }
    }
    output::print_hunt_dossier(&report);
}

fn print_menu() {
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".cyan());
    println!("{}", "   OIL // Binary Forensic Triage & Semantic Patch Engine (v0.1.0)".bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════════".cyan());
    println!();
    println!("Select an action or paste a target file/folder path directly:");
    println!("{}", "İşlem seçin veya taranacak dosya/klasör yolunu doğrudan yapıştırın:\n".dimmed());
    println!("  {} Scan File or Folder {}", "[1]".green().bold(), format!("/ Dosya veya Klasör Tara").dimmed());
    println!("  {} Windows Persistence & Proxy DLL Audit {}", "[2]".green().bold(), format!("/ Kalıcılık & DLL Denetimi").dimmed());
    println!("  {} Semantic Patch Diff {}", "[3]".green().bold(), format!("/ İki Dosyayı Semantik Karşılaştır").dimmed());
    println!("  {} Benchmark Lab Suite {}", "[4]".green().bold(), format!("/ Dahili Test Laboratuvarı").dimmed());
    println!("  {} Exit {}\n", "[5]".dimmed(), format!("/ Çıkış").dimmed());
    println!("{}", "Hint: Drag and drop any file or folder directly into this window!".yellow());
    println!("{}", "İpucu: Herhangi bir dosyayı doğrudan bu pencereye sürükleyip bırakabilirsiniz.".yellow().dimmed());
    println!();
}

fn run_interactive_mode() {
    use colored::Colorize;
    use std::io::{stdin, stdout, Write};

    print_menu();

    loop {
        print!(
            "{} / {}: ",
            "Choice or File Path".green().bold(),
            "Seçim veya Dosya Yolu >".green().dimmed()
        );
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

        if trimmed == "5" || trimmed.eq_ignore_ascii_case("q") || trimmed.eq_ignore_ascii_case("exit") {
            println!("Exiting Oil... {}", "(Sonlandırılıyor)".dimmed());
            break;
        }

        if trimmed.eq_ignore_ascii_case("help") || trimmed.eq_ignore_ascii_case("m") || trimmed.eq_ignore_ascii_case("menu") {
            print_menu();
            continue;
        }

        match trimmed {
            "1" => {
                print!(
                    "Drag/paste target path / {}: ",
                    "Taranacak dosya/klasör yolunu girin".dimmed()
                );
                let _ = stdout().flush();
                let mut p_str = String::new();
                let _ = stdin().read_line(&mut p_str);
                if let Some(path) = clean_input_path(&p_str) {
                    run_scan(&path);
                } else {
                    eprintln!(
                        "Error: Invalid or empty path / {}",
                        "Hata: Geçersiz veya boş dosya yolu.".dimmed()
                    );
                }
            }
            "2" => {
                println!(
                    "\nAuditing Windows persistence points & proxy DLL hooks... {}\n",
                    "(Kalıcılık noktaları ve kancalar denetleniyor)".dimmed()
                );
                run_hunt(None);
            }
            "3" => {
                print!(
                    "\nOriginal binary path / {}: ",
                    "Orijinal dosya yolu".dimmed()
                );
                let _ = stdout().flush();
                let mut o_str = String::new();
                let _ = stdin().read_line(&mut o_str);
                let orig = clean_input_path(&o_str);

                print!(
                    "Patched binary path / {}: ",
                    "Yamalı dosya yolu".dimmed()
                );
                let _ = stdout().flush();
                let mut p_str = String::new();
                let _ = stdin().read_line(&mut p_str);
                let patched = clean_input_path(&p_str);

                if let (Some(o), Some(p)) = (orig, patched) {
                    run_diff(&o, &p);
                } else {
                    eprintln!(
                        "Error: Invalid file paths / {}",
                        "Hata: Dosya yolları geçerli değil.".dimmed()
                    );
                }
            }
            "4" => {
                output::run_lab_suite();
            }
            user_input => {
                // Drag & drop or direct path typed
                if let Some(path) = clean_input_path(user_input) {
                    run_scan(&path);
                } else {
                    println!(
                        "{} {}",
                        format!("Invalid choice / Geçersiz seçim: '{}'.", user_input).red(),
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

    // 1. Drag & Drop onto oil.exe icon in Windows Explorer
    if args.len() >= 2 {
        let first = args[1].trim_matches('"').trim_matches('\'');
        let is_subcommand_or_flag = matches!(
            first,
            "scan" | "diff" | "hunt" | "lab" | "help" | "-h" | "--help" | "-V" | "--version"
        );

        if !is_subcommand_or_flag {
            println!(
                "OIL // Direct Target Inspection {}\n",
                "(Drag & Drop Mode / Sürükle & Bırak Modu)".dimmed()
            );
            for arg in &args[1..] {
                if let Some(candidate) = clean_input_path(arg) {
                    run_scan(&candidate);
                }
            }
            println!(
                "\n[Scan complete. Drag another file or press Enter to exit / {}]",
                "Tarama tamamlandı. Enter: Çıkış".dimmed()
            );
            print!(
                "{} / {}: ",
                "Choice or File Path (Enter: Exit)".green().bold(),
                "Seçim veya Dosya Yolu >".green().dimmed()
            );
            let _ = std::io::stdout().flush();
            let mut buf = String::new();
            if std::io::stdin().read_line(&mut buf).is_ok() {
                let trimmed = buf.trim();
                if !trimmed.is_empty() && trimmed != "q" && trimmed != "5" && trimmed != "exit" {
                    if let Some(next_candidate) = clean_input_path(trimmed) {
                        run_scan(&next_candidate);
                    }
                    // Transition directly into continuous interactive mode
                    run_interactive_mode();
                }
            }
            return;
        }
    }

    // 2. Direct double-click without arguments
    if args.len() <= 1 {
        run_interactive_mode();
        return;
    }

    // 3. Standard CLI invocation
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            if !run_scan(&path) {
                std::process::exit(1);
            }
        }
        Commands::Diff { original, patched } => {
            if !run_diff(&original, &patched) {
                std::process::exit(1);
            }
        }
        Commands::Hunt { dir } => {
            run_hunt(dir);
        }
        Commands::Lab => {
            output::run_lab_suite();
        }
    }
}
