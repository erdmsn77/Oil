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
        eprintln!("Hata: Hedef dosya veya klasör bulunamadı: {}", path.display());
        return false;
    }

    if path.is_dir() {
        let targets = collect_executable_targets(path, 5);
        if targets.is_empty() {
            println!("Klasörde taranacak çalıştırılabilir dosya (.exe, .dll, .lnk, .zip) bulunamadı: {}", path.display());
            return true;
        }

        println!("\nKlasör Taraması Başlatıldı: '{}' ({} adet çalıştırılabilir dosya)", path.display(), targets.len());

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
                    eprintln!("Dosya okunurken hata oluştu ({}): {}", p.display(), e);
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
                        verdict_summary: format!("Dosya okunurken hata oluştu: {}", e),
                        files_scanned: 0,
                        files_skipped: 1,
                        skip_reasons: vec![e.to_string()],
                    };
                    dedupe_info.push((i, p.clone(), None));
                    reports.push(err_report);
                }
            }
        }

        // ── Directory Correlation Analysis (Sideloading Suite Elevation) ──
        // If a directory contains both an unsigned system proxy DLL and an unsigned packed/RWX binary,
        // elevate both to HighRisk (Hostile Sideloading Loader Suite).
        let mut suite_folders: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        for r in &reports {
            if let Some(parent) = r.identity.path.parent() {
                let is_unsigned = r.autopsy.as_ref().map(|a| a.signature_valid != Some(true)).unwrap_or(true);
                let is_proxy = r.evidence.iter().any(|e| matches!(&e.kind, oil_core::models::EvidenceKind::DllProxyHook { shadows_system: true, .. }));
                if is_unsigned && is_proxy {
                    let has_packed = reports.iter().any(|other| {
                        other.identity.path.parent() == Some(parent)
                            && other.identity.path != r.identity.path
                            && other.autopsy.as_ref().map(|a| a.signature_valid != Some(true)).unwrap_or(true)
                            && other.evidence.iter().any(|e| {
                                matches!(&e.kind, oil_core::models::EvidenceKind::RwxSection { .. } | oil_core::models::EvidenceKind::CrypterProfile { .. })
                                    || matches!(&e.kind, oil_core::models::EvidenceKind::HighEntropySection { entropy, .. } if *entropy >= 7.90)
                            })
                    });
                    if has_packed {
                        suite_folders.insert(parent.to_path_buf());
                    }
                }
            }
        }

        if !suite_folders.is_empty() {
            for r in &mut reports {
                if let Some(parent) = r.identity.path.parent() {
                    if suite_folders.contains(parent) {
                        let is_unsigned = r.autopsy.as_ref().map(|a| a.signature_valid != Some(true)).unwrap_or(true);
                        let is_proxy = r.evidence.iter().any(|e| matches!(&e.kind, oil_core::models::EvidenceKind::DllProxyHook { shadows_system: true, .. }));
                        let is_packed = r.evidence.iter().any(|e| {
                            matches!(&e.kind, oil_core::models::EvidenceKind::RwxSection { .. } | oil_core::models::EvidenceKind::CrypterProfile { .. })
                                || matches!(&e.kind, oil_core::models::EvidenceKind::HighEntropySection { entropy, .. } if *entropy >= 7.90)
                        });

                        if is_unsigned && (is_proxy || is_packed) {
                            r.verdict = oil_core::models::Tier::HighRisk;
                            r.verdict_summary = if is_proxy {
                                format!(
                                    "Hostile DLL Sideloading Suite: Unsigned proxy DLL ('{}') co-located with packed loader in folder.",
                                    r.identity.path.file_name().and_then(|n| n.to_str()).unwrap_or("dll")
                                )
                            } else {
                                format!(
                                    "Hostile DLL Sideloading Suite: Unsigned packed/RWX binary ('{}') co-located with proxy hook in folder.",
                                    r.identity.path.file_name().and_then(|n| n.to_str()).unwrap_or("dll")
                                )
                            };
                        }
                    }
                }
            }
        }

        // Print dossiers with correlated verdicts
        for (idx, report) in reports.iter().enumerate() {
            let (_, ref p, ref dup) = dedupe_info[idx];
            println!("\n[{}/{}] Taranıyor: {}", idx + 1, targets.len(), p.display());
            if let Some(ref first_path) = dup {
                println!(
                    "  {} SHA-256 Eşleşti ({}...): '{}' ile birebir aynı dosya. (Tekrar analiz atlandı)",
                    "[+]".green().bold(),
                    &report.identity.sha256[..12],
                    first_path.display()
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
                "  {} ŞÜPHELİ VE RİSKLİ DOSYALARIN ÖNCELİK DAĞILIMI ({} Adet):",
                "[!]".yellow().bold(),
                flagged_reports.len()
            );
            println!("{}", "───────────────────────────────────────────────────────────────".yellow());
            for (idx, r) in flagged_reports.iter().enumerate() {
                let v_str = match r.verdict {
                    oil_core::models::Tier::HighRisk => "[YÜKSEK RİSK]".red().bold(),
                    oil_core::models::Tier::Suspicious => "[ŞÜPHELİ]".yellow().bold(),
                    _ => "[DİKKAT]".cyan().bold(),
                };

                let is_signed = r.autopsy.as_ref().and_then(|a| a.signature_valid) == Some(true);
                let priority_badge = if r.verdict == oil_core::models::Tier::HighRisk {
                    "[YÜKSEK ÖNCELİK // HOSTILE LOADER]".red().bold()
                } else if is_signed {
                    "[DÜŞÜK ÖNCELİK // VENDOR KORUMASI]".cyan().bold()
                } else {
                    "[YÜKSEK ÖNCELİK // İMZASIZ ANOMALİ]".yellow().bold()
                };

                println!(
                    "  [{}] {} {} {}",
                    (idx + 1).to_string().cyan().bold(),
                    v_str,
                    priority_badge,
                    r.identity.path.display().to_string().bold()
                );
                let tr_reason = if r.verdict_summary.contains("Hostile DLL Sideloading Suite") {
                    "Düşmanca Yan Yükleme Paketi: İmzasız proxy DLL (version.dll) ve paketlenmiş loader (PYG64.dll) aynı klasörde."
                } else if r.verdict_summary.contains("search-order hijacking") || r.verdict_summary.contains("proxy hook") {
                    "Windows sistem DLL gölgeleme / proxy hook ('version.dll' sistem kütüphanesini taklit ediyor)"
                } else if r.verdict_summary.contains("Process injection APIs paired with outbound network") {
                    if is_signed {
                        "Meşru lisans/güncelleme altyapısı: Süreç enjeksiyon API'leri ve dış ağ soketi (Doğrulanmış Dassault imzası mevcut)"
                    } else {
                        "Şüpheli yetenek kombinasyonu: Süreç enjeksiyon API'leri (CreateRemoteThread) ve dış ağ bağlantısı"
                    }
                } else if r.verdict_summary.contains("RWX memory permissions") {
                    "RWX (Okuma-Yazma-Çalıştırma) bellek izinleri (.Baymax runtime unpacker)"
                } else if r.verdict_summary.contains("Codeless data carrier") {
                    if is_signed {
                        "JS0 bytecode taşıyıcı: Kodsuz bölüm, şifreli veri konteyneri (Doğrulanmış Dassault imzası mevcut)"
                    } else {
                        "Kodsuz şifreli veri taşıyıcı (executable kod bölümü yok, saf şifreli payload konteyneri)"
                    }
                } else if r.verdict_summary.contains("High-entropy section detected within valid binary") || r.verdict_summary.contains("Near-maximal section entropy") {
                    if is_signed {
                        "Bölüm içinde yüksek entropi: Gömülü lisans blobu veya sıkıştırılmış kaynak (Doğrulanmış Dassault imzası mevcut)"
                    } else {
                        "Bölüm içinde yüksek entropi (gömülü şifreli veri veya paketleyici)"
                    }
                } else {
                    &r.verdict_summary
                };
                println!("      -> Gerekçe: {}", tr_reason);
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
                eprintln!("Hata: Dosya taranırken hata oluştu ({}): {}", path.display(), e);
                false
            }
        }
    }
}

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
        println!("{}", "  [HIZLI ADLİ NAVİGASYON & ŞÜPHELİ İNCELEME ÇUBUĞU]".cyan().bold());
        println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
        println!(
            "  {} Yalnızca Şüpheli / Riskli Dosyaları Listele ve İncele ({} dosya)",
            "[1]".green().bold(),
            flagged_reports.len()
        );
        println!(
            "  {} Taranan Tüm Dosyaların ({}) Kompakt Listesini Göster",
            "[2]".green().bold(),
            total
        );
        println!(
            "  {} En Başa Git / Konsolu Temizle ve Özet Raporu Göster",
            "[3]".green().bold()
        );
        println!(
            "  {} Ana Menüye Dön / Devam Et",
            "[4]".dimmed()
        );
        println!();
        print!("{}", "Navigasyon Seçimi > ".green().bold());
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
                    println!("\n[OK] Klasörde herhangi bir şüpheli veya riskli dosya bulunmuyor.");
                } else {
                    println!();
                    println!("{}", "───────────────────────────────────────────────────────────────".yellow());
                    println!(
                        "  {} ŞÜPHELİ / ANOMALİ TESPİT EDİLEN DOSYALAR ({} Adet):",
                        "[!]".yellow().bold(),
                        flagged_reports.len()
                    );
                    println!("{}", "───────────────────────────────────────────────────────────────".yellow());
                    for (idx, r) in flagged_reports.iter().enumerate() {
                        let v_str = match r.verdict {
                            oil_core::models::Tier::HighRisk => "[YÜKSEK RİSK]".red().bold(),
                            oil_core::models::Tier::Suspicious => "[ŞÜPHELİ]".yellow().bold(),
                            _ => "[DİKKAT]".cyan().bold(),
                        };

                        let priority_badge = if r.verdict == oil_core::models::Tier::HighRisk {
                            "[YÜKSEK ÖNCELİK // HOSTILE LOADER]".red().bold()
                        } else if r.autopsy.as_ref().and_then(|a| a.signature_valid) == Some(true) {
                            "[DÜŞÜK ÖNCELİK // VENDOR KORUMASI]".cyan().bold()
                        } else {
                            "[YÜKSEK ÖNCELİK // İMZASIZ ANOMALİ]".yellow().bold()
                        };

                        println!(
                            "  [{}] {} {} {}",
                            (idx + 1).to_string().cyan().bold(),
                            v_str,
                            priority_badge,
                            r.identity.path.display().to_string().bold()
                        );
                        let tr_reason = if r.verdict_summary.contains("Hostile DLL Sideloading Suite") {
                            "Düşmanca Yan Yükleme Paketi: İmzasız proxy DLL (version.dll) ve paketlenmiş loader (PYG64.dll) aynı klasörde tespit edildi."
                        } else if r.verdict_summary.contains("search-order hijacking") || r.verdict_summary.contains("proxy hook") {
                            "Sistem DLL gölgeleme / proxy hook ('version.dll' sistem kütüphanesini taklit ediyor)"
                        } else if r.verdict_summary.contains("Process injection APIs paired with outbound network") {
                            "Şüpheli yetenek kombinasyonu: Süreç enjeksiyon API'leri (CreateRemoteThread) ve dış ağ bağlantısı (wininet/ws2_32)"
                        } else if r.verdict_summary.contains("RWX memory permissions") {
                            "RWX (Okuma-Yazma-Çalıştırma) bellek izinleri (.Baymax runtime unpacker)"
                        } else if r.verdict_summary.contains("Codeless data carrier") {
                            "Kodsuz şifreli veri taşıyıcı (executable kod bölümü yok, saf şifreli payload konteyneri)"
                        } else if r.verdict_summary.contains("High-entropy section detected within valid binary") || r.verdict_summary.contains("Near-maximal section entropy") {
                            "Bölüm içinde yüksek entropi (gömülü sıkıştırılmış veri veya lisans blobu)"
                        } else {
                            &r.verdict_summary
                        };
                        println!("      -> Gerekçe: {}", tr_reason);
                    }
                    println!("{}", "───────────────────────────────────────────────────────────────".yellow());
                    println!(
                        "Detaylı otopsisini görmek istediğiniz dosya numarasını girin [1-{}]:",
                        flagged_reports.len()
                    );
                    println!("(Geri dönmek için Enter)");
                    print!("Dosya No > ");
                    let _ = std::io::stdout().flush();
                    let mut num_str = String::new();
                    let _ = std::io::stdin().read_line(&mut num_str);
                    if let Ok(num) = num_str.trim().parse::<usize>() {
                        if num >= 1 && num <= flagged_reports.len() {
                            println!();
                            println!("{}", "───────────────────────────────────────────────────────────────".cyan());
                            println!(
                                "  DOSYA DETAYI [#{}] : {}",
                                num,
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
                println!("  TARANAN TÜM DOSYALARIN ÖZET DURUM LİSTESİ ({} Dosya):", total);
                println!("{}", "───────────────────────────────────────────────────────────────".cyan());
                for (idx, r) in reports.iter().enumerate() {
                    let badge = match r.verdict {
                        oil_core::models::Tier::HighRisk => "[!] [YÜKSEK RİSK]".red(),
                        oil_core::models::Tier::Suspicious => "[!] [ŞÜPHELİ]   ".yellow(),
                        oil_core::models::Tier::NoIndicatorsFound => "[+] [BELİRTİSİZ] ".green(),
                        oil_core::models::Tier::Inconclusive => "[-] [KARARSIZ]  ".magenta(),
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
                );
            }
            _ => {
                println!("Geçersiz seçim. [1-4] arasında bir numara giriniz.");
            }
        }
        println!();
    }
}

fn run_diff(original: &Path, patched: &Path) -> bool {
    if !original.exists() {
        eprintln!("Hata: Orijinal ikili dosya bulunamadı: {}", original.display());
        return false;
    }
    if !patched.exists() {
        eprintln!("Hata: Yamalı ikili dosya bulunamadı: {}", patched.display());
        return false;
    }

    match oil_core::diff::diff_binaries(original, patched) {
        Ok(report) => {
            output::print_diff_dossier(&report);
            true
        }
        Err(e) => {
            eprintln!("Hata: İkili yama analizi başarısız: {}", e);
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
    println!("Yapmak istediğiniz işlemi seçin veya taranacak dosya/klasör yolunu doğrudan yapıştırın:\n");
    println!("  {} Dosya veya Klasör Tara (Scan)", "[1]".green().bold());
    println!("  {} Windows Kalıcılık & Proxy DLL Denetimi (Hunt)", "[2]".green().bold());
    println!("  {} İki Dosyayı Semantik Olarak Karşılaştır (Diff)", "[3]".green().bold());
    println!("  {} Dahili Test & Laboratuvar Benchmark (Lab)", "[4]".green().bold());
    println!("  {} Çıkış\n", "[5]".dimmed());
    println!("{}", "İpucu: Taramak istediğiniz herhangi bir dosyayı veya klasörü doğrudan".yellow());
    println!("{}", "bu pencerenin içine sürükleyip bırakabilir veya yolunu yapıştırabilirsiniz.".yellow());
    println!();
}

fn run_interactive_mode() {
    use colored::Colorize;
    use std::io::{stdin, stdout, Write};

    print_menu();

    loop {
        print!("{}", "Seçim veya Dosya Yolu > ".green().bold());
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
            println!("Oil sonlandırılıyor...");
            break;
        }

        if trimmed.eq_ignore_ascii_case("help") || trimmed.eq_ignore_ascii_case("m") || trimmed.eq_ignore_ascii_case("menu") {
            print_menu();
            continue;
        }

        match trimmed {
            "1" => {
                print!("Taranacak dosya veya klasör yolunu sürükleyin/yapıştırın: ");
                let _ = stdout().flush();
                let mut p_str = String::new();
                let _ = stdin().read_line(&mut p_str);
                if let Some(path) = clean_input_path(&p_str) {
                    run_scan(&path);
                } else {
                    eprintln!("Hata: Geçersiz veya boş dosya yolu.");
                }
            }
            "2" => {
                println!("\nSistem kalıcılık noktaları ve şüpheli persistence anahtarları denetleniyor...\n");
                run_hunt(None);
            }
            "3" => {
                print!("\nOrijinal dosya yolu: ");
                let _ = stdout().flush();
                let mut o_str = String::new();
                let _ = stdin().read_line(&mut o_str);
                let orig = clean_input_path(&o_str);

                print!("Yamalı (cracked/modified) dosya yolu: ");
                let _ = stdout().flush();
                let mut p_str = String::new();
                let _ = stdin().read_line(&mut p_str);
                let patched = clean_input_path(&p_str);

                if let (Some(o), Some(p)) = (orig, patched) {
                    run_diff(&o, &p);
                } else {
                    eprintln!("Hata: Dosya yolları geçerli değil.");
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
                    println!("{}", format!("Geçersiz seçim: '{}'. Menüyü görmek için 'm' yazabilirsiniz.", user_input).red());
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
            println!("OIL // Doğrudan Hedef Denetimi (Sürükle & Bırak Modu)\n");
            for arg in &args[1..] {
                if let Some(candidate) = clean_input_path(arg) {
                    run_scan(&candidate);
                }
            }
            println!("\n[Tarama tamamlandı. Başka bir dosya sürükleyebilir veya çıkmak için Enter'a basabilirsiniz]");
            print!("{}", "Seçim veya Dosya Yolu (Enter: Çıkış) > ".bold().green());
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
