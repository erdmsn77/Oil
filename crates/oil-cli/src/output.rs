//! # Forensic Dossier Output Formatter
//!
//! GDD §5.1 & §5.2 — Renders the scan report into the distinctive
//! cyber-forensic terminal output format.

use colored::Colorize;
use oil_core::models::{DiffReport, EvidenceKind, PatchCategory, ScanReport, Tier};

/// Renders a full forensic dossier for a scan report.
pub fn print_dossier(report: &ScanReport) {
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".dimmed());
    println!("{}", "OIL FORENSIC TRIAGE ENGINE v0.1.0".bright_blue().bold());
    println!(
        "{} {} [Size: {} KB]",
        "TARGET:".green().bold(),
        report.identity.path.display().to_string().cyan().bold(),
        report.identity.size_bytes / 1024
    );
    println!("SHA-256: {}", report.identity.sha256);
    println!("BLAKE3:  {}", report.identity.blake3);
    println!();

    // ──────────────────────────────────────────────
    // 1. SMOKING GUN (Only if critical threats found)
    // ──────────────────────────────────────────────
    let critical_items: Vec<_> = report
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                &e.kind,
                EvidenceKind::DiscordWebhook { .. }
                    | EvidenceKind::TelegramToken { .. }
                    | EvidenceKind::CredentialPath { .. }
                    | EvidenceKind::YaraMatch { .. }
            )
        })
        .collect();

    if !critical_items.is_empty() && report.verdict >= Tier::Suspicious {
        if report.verdict == Tier::HighRisk {
            println!("{}", "SMOKING GUN (CRITICAL ARTIFACTS FOUND):".red().bold());
        } else {
            println!("{}", "OBSERVED INDICATORS (ISOLATED / CONTEXTUAL):".yellow().bold());
        }
        for item in &critical_items {
            match &item.kind {
                EvidenceKind::DiscordWebhook { url, encoding } => {
                    println!(
                        "  {} [SIPHON PIPE] Discord Webhook URL reference ({}):",
                        "[ALERT]".red().bold(),
                        encoding
                    );
                    println!("    '{}'", url.yellow());
                }
                EvidenceKind::TelegramToken { token, encoding } => {
                    println!(
                        "  {} [SIPHON PIPE] Telegram Bot token reference ({}):",
                        "[ALERT]".red().bold(),
                        encoding
                    );
                    println!("    '{}'", token.yellow());
                }
                EvidenceKind::CredentialPath { path, encoding } => {
                    println!(
                        "  {} [CREDENTIAL TARGET] Harvester path reference ({}):",
                        "[ALERT]".red().bold(),
                        encoding
                    );
                    println!("    '{}'", path.yellow());
                }
                EvidenceKind::YaraMatch { rule_name, namespace } => {
                    println!(
                        "  {} [YARA SIGNATURE] Rule match: '{}/{}'",
                        "[ALERT]".red().bold(),
                        namespace,
                        rule_name.yellow()
                    );
                }
                _ => {}
            }
        }
        println!();
    }

    // ──────────────────────────────────────────────
    // 2. THE AUTOPSY (Structural Anatomy)
    // ──────────────────────────────────────────────
    println!("{}", "THE AUTOPSY:".bold());
    if let Some(ref autopsy) = report.autopsy {
        let sec_summary: Vec<String> = autopsy
            .sections
            .iter()
            .map(|s| {
                if s.entropy > 7.5 {
                    format!("{} ({:.2} - high)", s.name, s.entropy).red().to_string()
                } else {
                    format!("{} ({:.2})", s.name, s.entropy)
                }
            })
            .collect();

        println!("  • Sections: {}", sec_summary.join(", "));

        let net_imports: Vec<_> = autopsy
            .imports
            .iter()
            .filter(|i| {
                ["ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll"]
                    .contains(&i.dll_name.as_str())
            })
            .collect();

        if !net_imports.is_empty() {
            let has_injection = report
                .evidence
                .iter()
                .any(|e| matches!(&e.kind, EvidenceKind::InjectionImport { .. }));
            let has_theft = report.evidence.iter().any(|e| {
                matches!(
                    &e.kind,
                    EvidenceKind::DiscordWebhook { .. }
                        | EvidenceKind::TelegramToken { .. }
                        | EvidenceKind::CredentialPath { .. }
                        | EvidenceKind::SensitiveApiImport { .. }
                )
            });

            let dll_list = net_imports
                .iter()
                .map(|i| i.dll_name.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            if has_injection || has_theft {
                println!(
                    "  {} Network Imports: {} (Associated with exfiltration / injection signals)",
                    "[!]".red().bold(),
                    dll_list.red()
                );
            } else {
                println!("  • Network Imports: {}", dll_list.bright_blue());
            }
        } else {
            println!("  • Network Capabilities: None (Zero socket or HTTP APIs)");
        }

        let injection_items: Vec<_> = report
            .evidence
            .iter()
            .filter_map(|e| match &e.kind {
                EvidenceKind::InjectionImport { dll, functions } => Some((dll, functions)),
                _ => None,
            })
            .collect();

        if !injection_items.is_empty() {
            for (dll, funcs) in injection_items {
                println!(
                    "  {} Process Injection Imports: {} ({})",
                    "[!]".red().bold(),
                    dll.red(),
                    funcs.join(", ").red()
                );
            }
        }

        if autopsy.overlay_size > 0 {
            println!(
                "  • Overlay: {} bytes appended past PE image end",
                autopsy.overlay_size
            );
        } else {
            println!("  • Overlay: None");
        }

        if let Some(true) = autopsy.signature_valid {
            if let Some(ref signer) = autopsy.signature_signer {
                println!("  • Digital Signature: Valid Authenticode signature ({}).", signer.green());
            } else {
                println!("  • Digital Signature: Valid Authenticode security directory present.");
            }
        } else if let Some(false) = autopsy.signature_valid {
            if let Some(ref detail) = autopsy.signature_signer {
                println!("  • Digital Signature: Invalid or unverified Authenticode signature ({}).", detail.yellow());
            } else {
                println!("  • Digital Signature: Missing or invalid Authenticode signature.");
            }
            println!(
                "    {}",
                "Context: Code patches invalidate original vendor signatures. This alone does not indicate malice."
                    .dimmed()
            );
        } else {
            println!("  • Digital Signature: Missing signature directory (unsigned / modified).");
            println!(
                "    {}",
                "Context: Code patches invalidate original vendor signatures. This alone does not indicate malice."
                    .dimmed()
            );
        }

        // Check for DLL Proxy Hook / Sideloading trap
        for item in &report.evidence {
            if let EvidenceKind::DllProxyHook { dll_name, shadows_system } = &item.kind {
                if *shadows_system {
                    println!(
                        "  {} DLL Proxy Hook: Shadows Windows System DLL '{}' in application folder",
                        "[!]".yellow().bold(),
                        dll_name.yellow().bold()
                    );
                } else {
                    println!(
                        "  • Platform Hook / Emulator: Known game/platform proxy hook '{}'",
                        dll_name.cyan().bold()
                    );
                }
            }
        }
    } else {
        println!("  • Format: Non-PE or raw data file.");
    }
    println!();

    // ──────────────────────────────────────────────
    // 3. THE VERDICT
    // ──────────────────────────────────────────────
    println!("{}", "THE VERDICT:".bold());
    match report.verdict {
        Tier::HighRisk => {
            println!("  {}", "[HIGH RISK]".red().bold());
            println!("  Factual Summary: {}", report.verdict_summary.red());
            println!(
                "  {}",
                "Action: User discretion advised. Execution not recommended."
                    .yellow()
                    .bold()
            );
        }
        Tier::Suspicious => {
            println!("  {}", "[SUSPICIOUS]".yellow().bold());
            println!("  Factual Summary: {}", report.verdict_summary.yellow());
            println!(
                "  {}",
                "Notice: Anomalies observed. Review evidence above before launching."
                    .dimmed()
            );
        }
        Tier::NoIndicatorsFound => {
            println!("  {}", "[NO INDICATORS FOUND]".bright_blue().bold());
            println!("  Factual Summary: {}", report.verdict_summary);
            println!(
                "  {}",
                "Notice: Static analysis is limited to observable artifacts and known IOCs."
                    .dimmed()
            );
        }
        Tier::Inconclusive => {
            println!("  {}", "[INCONCLUSIVE]".magenta().bold());
            println!("  Reason: {}", report.verdict_summary);
        }
    }

    println!();
    println!(
        "Scanned: {} file | Skipped: {}",
        report.files_scanned, report.files_skipped
    );
    println!();
}

/// Runs the synthetic test benchmarks and renders the GHOST LAB status board.
pub fn run_lab_suite() {
    println!();
    println!("{}", "OIL // SYNTHETIC FORENSIC LAB HARNESS (GHOST LAB)".bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".dimmed());
    println!("Testing against safe, in-memory synthetic PE benchmarks...");
    println!();

    let tests: [(&str, Box<dyn Fn() -> Vec<u8>>, Tier, &str); 4] = [
        (
            "bench_clean",
            Box::new(oil_core::lab::generate_bench_clean),
            Tier::NoIndicatorsFound,
            "Baseline zero-false-positive check",
        ),
        (
            "bench_stealer",
            Box::new(oil_core::lab::generate_bench_stealer),
            Tier::HighRisk,
            "Webhook + Chrome path stealer pattern",
        ),
        (
            "bench_single_ioc",
            Box::new(oil_core::lab::generate_bench_single_ioc),
            Tier::Suspicious,
            "Isolated webhook without exfiltration combo",
        ),
        (
            "bench_entropy",
            Box::new(oil_core::lab::generate_bench_entropy),
            Tier::Suspicious,
            "High entropy (>7.8) packer/crypter profile",
        ),
    ];

    let mut all_passed = true;
    let temp_dir = std::env::temp_dir();

    for (name, generator, expected_tier, desc) in tests {
        let dummy_path = temp_dir.join(format!("oil_lab_{}.exe", name));
        let data = generator();
        if std::fs::write(&dummy_path, &data).is_err() {
            eprintln!("Failed to write temporary test file");
            continue;
        }

        match oil_core::scan_path(&dummy_path) {
            Ok(report) => {
                let passed = report.verdict == expected_tier;
                if passed {
                    println!(
                        "  {} {:<18} {} [Tier: {}] — {}",
                        "[OK]".green().bold(),
                        name.cyan(),
                        "PASSED".green(),
                        report.verdict.to_string().bright_blue(),
                        desc.dimmed()
                    );
                } else {
                    all_passed = false;
                    println!(
                        "  {} {:<18} {} (Expected {}, got {})",
                        "[-]".red().bold(),
                        name.red(),
                        "FAILED".red(),
                        expected_tier,
                        report.verdict
                    );
                }
            }
            Err(e) => {
                all_passed = false;
                println!("  {} {:<18} ERROR: {}", "[!]".red().bold(), name, e);
            }
        }

        let _ = std::fs::remove_file(&dummy_path);
    }

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".dimmed());
    if all_passed {
        println!(
            "{}",
            "LAB VERDICT: ALL BENCHMARKS VERIFIED (0 False Positives, Multi-signal Logic Confirmed)"
                .green()
                .bold()
        );
    } else {
        println!("{}", "LAB VERDICT: BENCHMARK REGRESSION DETECTED".red().bold());
    }
    println!();
}

/// Renders the forensic dossier for oil diff (Semantic Patch Analysis).
pub fn print_diff_dossier(report: &DiffReport) {
    println!();
    println!("{}", "OIL // Binary & Crack Forensic Triage Engine v0.1.0".bold());
    println!("{}", "Diff Mode: Semantic Patch Analysis".cyan());
    println!(
        "Base (Original):  {} [SHA-256: {}]",
        report.original.path.display().to_string().cyan(),
        report.original.sha256
    );
    println!(
        "Target (Patched): {} [SHA-256: {}]",
        report.patched.path.display().to_string().cyan(),
        report.patched.sha256
    );
    println!();

    // ──────────────────────────────────────────────
    // 1. STRUCTURAL DELTA
    // ──────────────────────────────────────────────
    println!("{}", "STRUCTURAL DELTA:".bold());
    if report.new_sections.is_empty() {
        println!("  • New Sections: None");
    } else {
        println!(
            "  {} New Sections: {}",
            "[!]".red().bold(),
            report.new_sections.join(", ").red()
        );
    }

    if report.entry_point_changed {
        println!("  {} Entry Point: CHANGED", "[!]".red().bold());
    } else {
        println!("  • Entry Point: Unchanged");
    }

    if report.new_imports.is_empty() {
        println!("  • Import Table: Identical (Zero new networking or injection APIs)");
    } else {
        println!(
            "  {} Import Table EXPANDED: {}",
            "[!]".red().bold(),
            report
                .new_imports
                .iter()
                .map(|i| format!("{}: {:?}", i.dll_name, i.functions))
                .collect::<Vec<_>>()
                .join(", ")
                .red()
        );
    }

    if report.overlay_delta > 0 {
        println!(
            "  • Overlay: Added {} bytes past PE image end",
            report.overlay_delta
        );
    } else {
        println!("  • Overlay: None added");
    }
    println!();

    // ──────────────────────────────────────────────
    // 2. DIRTY BYTES
    // ──────────────────────────────────────────────
    println!(
        "{} ({} patch regions detected):",
        "DIRTY BYTES".bold(),
        report.patches.len()
    );
    if report.patches.is_empty() {
        println!("  • Zero altered byte ranges (Files are identical).");
    } else {
        for (idx, patch) in report.patches.iter().enumerate() {
            let cat_label = match patch.category {
                PatchCategory::DrmBypass => "DRM_BYPASS".green().bold(),
                PatchCategory::CodeInjection => "CODE_INJECTION".red().bold(),
                PatchCategory::DigitalSignature => "DIGITAL_SIGNATURE".cyan().bold(),
                PatchCategory::Unknown => "UNKNOWN_PATCH".yellow().bold(),
            };

            println!(
                "  Region {} [Offset 0x{:X}, {} bytes in {}]:",
                idx + 1,
                patch.offset,
                patch.size,
                patch.section
            );
            if let Some(ref disasm) = patch.disassembly {
                println!("    - Instruction: {}", disasm.cyan());
            }
            println!("    - Classification: {}", cat_label);
        }
    }
    println!();

    // ──────────────────────────────────────────────
    // 3. DELTA FINGERPRINT
    // ──────────────────────────────────────────────
    println!(
        "DELTA FINGERPRINT (SHA-256 of patch delta): {}",
        report.delta_fingerprint.bright_blue()
    );
    println!();

    // ──────────────────────────────────────────────
    // 4. THE VERDICT
    // ──────────────────────────────────────────────
    println!("{}", "THE VERDICT:".bold());
    match report.verdict {
        Tier::HighRisk => {
            println!("  {}", "[HIGH RISK]".red().bold());
            println!("  Factual Summary: {}", report.verdict_summary.red());
        }
        Tier::Suspicious => {
            println!("  {}", "[SUSPICIOUS]".yellow().bold());
            println!("  Factual Summary: {}", report.verdict_summary.yellow());
        }
        Tier::NoIndicatorsFound => {
            println!("  {}", "[NO INDICATORS FOUND]".bright_blue().bold());
            println!("  Factual Summary: {}", report.verdict_summary);
        }
        Tier::Inconclusive => {
            println!("  {}", "[INCONCLUSIVE]".magenta().bold());
            println!("  Reason: {}", report.verdict_summary);
        }
    }
    println!();
}

/// Renders the forensic dossier for oil hunt (Persistence and Sideloading Audit).
pub fn print_hunt_dossier(report: &oil_core::hunt::HuntReport) {
    println!();
    println!("{}", "OIL // Windows Persistence & Sideloading Audit (oil hunt)".bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".dimmed());
    println!(
        "Inspected {} persistence mechanisms (Registry Run keys, Startup folders)...",
        report.total_inspected
    );
    println!();

    if report.items.is_empty() {
        println!("  • Zero persistence entries discovered in standard locations.");
    } else {
        for (idx, item) in report.items.iter().enumerate() {
            let status_badge = if let Some(ref scan) = item.scan_report {
                match scan.verdict {
                    Tier::HighRisk => "[HIGH RISK]".red().bold(),
                    Tier::Suspicious => "[SUSPICIOUS]".yellow().bold(),
                    Tier::NoIndicatorsFound => "[NO INDICATORS FOUND]".bright_blue().bold(),
                    Tier::Inconclusive => "[INCONCLUSIVE]".magenta().bold(),
                }
            } else {
                "[FILE NOT FOUND / UNRESOLVED]".dimmed()
            };

            println!(
                "  {} [{}] {} (Source: {})",
                format!("#{}", idx + 1).bold(),
                item.entry_name.cyan(),
                status_badge,
                item.source.to_string().dimmed()
            );
            println!("    Command: {}", item.command_line.dimmed());
            if let Some(ref p) = item.resolved_path {
                println!("    Resolved: {}", p.display().to_string().cyan());
            }
            if let Some(ref scan) = item.scan_report {
                if scan.verdict == Tier::HighRisk || scan.verdict == Tier::Suspicious {
                    println!("    Verdict Note: {}", scan.verdict_summary.red());
                }
            }
            println!();
        }
    }

    println!("{}", "═══════════════════════════════════════════════════════════════".dimmed());
    println!("PERSISTENCE AUDIT SUMMARY:");
    println!("  • Total Inspected: {}", report.total_inspected);
    println!("  • No Indicators:   {}", report.no_indicators_count.to_string().bright_blue());
    println!("  • Suspicious:      {}", report.suspicious_count.to_string().yellow());
    println!("  • High Risk:       {}", report.high_risk_count.to_string().red().bold());
    println!();
}

/// Renders a human-readable, high-impact Turkish executive summary card for a single file.
pub fn print_single_summary_box(report: &ScanReport) {
    let file_name = report
        .identity
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Hedef Dosya");

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("{}", "               ADLİ TARAMA SONUÇ ÖZETİ".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("  Hedef Dosya   : {}", file_name.bold());

    match report.verdict {
        Tier::HighRisk => {
            println!("  NİHAİ DURUM   : {}", "[ALERT] [YÜKSEK RİSK // TEHLİKELİ DOSYA]".red().bold());
            println!("{}", "───────────────────────────────────────────────────────────────".dimmed());
            println!("  ÖZET DEĞERLENDİRME:");
            let has_stealer = report.evidence.iter().any(|e| {
                matches!(
                    &e.kind,
                    EvidenceKind::DiscordWebhook { .. }
                        | EvidenceKind::TelegramToken { .. }
                        | EvidenceKind::CredentialPath { .. }
                        | EvidenceKind::YaraMatch { .. }
                )
            });
            if has_stealer {
                println!("  • DİKKAT! Bu dosyada bilgi çalıcı (Stealer), zararlı webhook veya");
                println!("    veri sızdırma mekanizmaları tespit edildi!");
                println!("  • TAVSİYE: Dosyayı KESİNLİKLE ÇALIŞTIRMAYINIZ ve sistemden siliniz!");
            } else {
                println!("  • DİKKAT! Bu dosyada yüksek riskli tehdit göstergesi veya zararlı");
                println!("    kod yapısı (süreç enjeksiyonu / düşmanca yükleyici) tespit edildi!");
                println!("  • TAVSİYE: Güvenilmeyen bir kaynaktan geldiyse çalıştırmayınız.");
            }
        }
        Tier::Suspicious => {
            println!("  NİHAİ DURUM   : {}", "[NOTICE] [ŞÜPHELİ // DİKKAT GEREKTİRİR]".yellow().bold());
            println!("{}", "───────────────────────────────────────────────────────────────".dimmed());
            println!("  ÖZET DEĞERLENDİRME:");
            if report.verdict_summary.contains("Untrusted Sideloading Loader")
                || report.verdict_summary.contains("Local Hook")
            {
                println!("  • Yerel lisans kancası veya mod mekanizması (Sıfır dış ağ soketi/API'si).");
                println!("  • TAVSİYE: Yalnızca güvenilir çevrimdışı kullanım için değerlendiriniz.");
            } else {
                println!("  • Dosyada sıra dışı anomali, şüpheli ağ veya yüksek entropi görüldü.");
                println!("  • TAVSİYE: Bilinmeyen veya şüpheli bir kaynaktan geldiyse dikkatli olunuz.");
            }
        }
        Tier::NoIndicatorsFound => {
            println!("  NİHAİ DURUM   : {}", "[NO THREAT INDICATORS OBSERVED]".green().bold());
            println!("{}", "───────────────────────────────────────────────────────────────".dimmed());
            println!("  ÖZET DEĞERLENDİRME:");
            println!("  • Dosyada bilinen hiçbir trojan, şifre/veri çalıcı (stealer), arka");
            println!("    kapı veya fidye yazılımı izine rastlanmadı. Bilinen tehdit göstergesi tespit edilmedi.");
        }
        Tier::Inconclusive => {
            println!("  NİHAİ DURUM   : {}", "[NOTICE] [KARARSIZ // SIKIŞTIRILMIŞ ARŞİV]".magenta().bold());
            println!("{}", "───────────────────────────────────────────────────────────────".dimmed());
            println!("  ÖZET DEĞERLENDİRME:");
            println!("  • Bu dosya doğrudan çalışan bir PE binary değil (Örn: .7z arşivi).");
            println!("  • NE YAPMALISINIZ?: Arşivi bir klasöre çıkartıp içindeki dosyaları");
            println!("    veya klasörü buraya sürükleyin.");
        }
    }

    let proxy_hooks = report
        .evidence
        .iter()
        .filter(|e| matches!(&e.kind, EvidenceKind::DllProxyHook { .. }))
        .count();
    if proxy_hooks > 0 {
        println!("  • Proxy / Sideloading: {} adet DLL kancası tespit edildi.", proxy_hooks);
    }

    println!();
    println!("  {} Teknik hash ve bellek analizi için terminali yukarı kaydırabilirsiniz.", "[NOTICE]".cyan());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!();
}

/// Renders a human-readable, high-impact Turkish executive summary card for a directory audit.
#[allow(clippy::too_many_arguments)]
pub fn print_directory_summary_box(
    dir_path: &std::path::Path,
    total: usize,
    no_indicators: usize,
    suspicious: usize,
    high_risk: usize,
    inconclusive: usize,
    proxy_hook_count: usize,
    duplicate_count: usize,
    has_stealer_ioc: bool,
) {
    let dir_name = dir_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Hedef Klasör");

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("{}", "         KLASÖR ADLİ TARAMA GENEL SONUÇ RAPORU".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("  Hedef Klasör  : {}", dir_name.bold());
    if duplicate_count > 0 {
        let unique = total.saturating_sub(duplicate_count);
        println!(
            "  Taranan Dosya : {} adet çalıştırılabilir dosya ({} benzersiz, {} tekrarlanan hash)",
            total, unique, duplicate_count
        );
    } else {
        println!("  Taranan Dosya : {} adet çalıştırılabilir dosya (.exe / .dll)", total);
    }

    if proxy_hook_count > 0 {
        if high_risk > 0 {
            println!(
                "  İstatistik    : {} Belirtisiz | {} Şüpheli | {} Yüksek Risk ({} Proxy Hook dahil) | {} Kararsız",
                no_indicators, suspicious, high_risk, proxy_hook_count, inconclusive
            );
        } else {
            println!(
                "  İstatistik    : {} Belirtisiz | {} Şüpheli ({} Proxy Hook dahil) | {} Yüksek Risk | {} Kararsız",
                no_indicators, suspicious, proxy_hook_count, high_risk, inconclusive
            );
        }
    } else {
        println!(
            "  İstatistik    : {} Belirtisiz | {} Şüpheli | {} Yüksek Risk | {} Kararsız",
            no_indicators, suspicious, high_risk, inconclusive
        );
    }
    println!("{}", "───────────────────────────────────────────────────────────────".dimmed());

    if high_risk > 0 {
        println!("  NİHAİ KARAR   : {}", "[ALERT] [YÜKSEK RİSK // TEHLİKELİ DOSYA BULUNDU]".red().bold());
        println!("  ÖZET DEĞERLENDİRME:");
        println!("  • DİKKAT! Klasör içinde {} adet TEHLİKELİ dosya tespit edildi!", high_risk);
        if has_stealer_ioc {
            println!("  • Bilgi çalıcı (stealer) veya zararlı veri sızdırma mekanizması tespit edildi. ÇALIŞTIRMAYINIZ!");
        } else {
            println!("  • Düşmanca süreç enjeksiyonu veya zararlı kod yapısı tespit edildi. ÇALIŞTIRMAYINIZ!");
        }
    } else if suspicious > 0 {
        println!("  NİHAİ KARAR   : {}", "[NOTICE] [ŞÜPHELİ // İNCELEME GEREKTİRİR]".yellow().bold());
        println!("  ÖZET DEĞERLENDİRME:");
        println!("  • Klasör içinde {} adet şüpheli anomali tespit edildi.", suspicious);
        println!("  • Bilinmeyen veya şüpheli bir kaynaktan indirdiyseniz dikkatli olunuz.");
    } else {
        println!("  NİHAİ KARAR   : {}", "[NO THREAT INDICATORS OBSERVED]".green().bold());
        println!("  ÖZET DEĞERLENDİRME:");
        println!("  • Taranan {} dosyanın hiçbirinde şifre/veri çalıcı (stealer), trojan", total);
        println!("    veya zararlı yazılım izine rastlanmadı. Klasörde bilinen tehdit göstergesi tespit edilmedi.");
    }

    if proxy_hook_count > 0 {
        println!("  • Proxy / Sideloading: {} adet sistem/platform DLL kancası tespit edildi.", proxy_hook_count);
        if high_risk == 0 {
            println!("    (Sıfır dış ağ bağlantısı: Yerel lisans kancası veya platform emülatörü olabilir).");
        }
    }

    println!();
    println!("  {} Aşağıdaki Hızlı Navigasyon menüsünü kullanarak şüpheli dosyaları doğrudan inceleyebilirsiniz.", "[NOTICE]".cyan());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!();
}

/// Alias for `print_directory_summary_box`
#[allow(dead_code, clippy::too_many_arguments)]
#[inline]
pub fn print_directory_summary(
    dir_path: &std::path::Path,
    total: usize,
    no_indicators: usize,
    suspicious: usize,
    high_risk: usize,
    inconclusive: usize,
    proxy_hook_count: usize,
    duplicate_count: usize,
    has_stealer_ioc: bool,
) {
    print_directory_summary_box(
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

#[cfg(test)]
mod tests {
    use super::*;
    use oil_core::models::{FileIdentity, ScanReport, Tier};
    use std::path::PathBuf;

    #[test]
    fn test_no_forbidden_emojis_in_output_rs() {
        let content = include_str!("output.rs");
        let forbidden_emojis = ['📊', '💡', '✔', '✖', '⚠', '🚨', '🎯', '✓'];
        for emoji in forbidden_emojis {
            // Count occurrences outside test module
            let test_mod_start = content.find("#[cfg(test)]").unwrap_or(content.len());
            let non_test_content = &content[..test_mod_start];
            assert!(
                !non_test_content.contains(emoji),
                "Forbidden emoji '{}' found in output.rs!",
                emoji
            );
        }
    }

    #[test]
    fn test_epistemic_honesty_no_forbidden_words() {
        let content = include_str!("output.rs");
        let test_mod_start = content.find("#[cfg(test)]").unwrap_or(content.len());
        let non_test_content = &content[..test_mod_start];

        assert!(
            !non_test_content.contains("Temiz |"),
            "Forbidden phrase 'Temiz |' found in output.rs"
        );
        assert!(
            !non_test_content.contains("GÜVENLİ"),
            "Forbidden word 'GÜVENLİ' found in output.rs"
        );
        assert!(
            !non_test_content.contains("temiz görünüyor"),
            "Forbidden phrase 'temiz görünüyor' found in output.rs"
        );
        assert!(
            !non_test_content.contains("Temiz görünüyor"),
            "Forbidden phrase 'Temiz görünüyor' found in output.rs"
        );
    }

    #[test]
    fn test_print_single_and_directory_summary_boxes() {
        let report = ScanReport {
            identity: FileIdentity {
                path: PathBuf::from("test.exe"),
                size_bytes: 1024,
                sha256: "0".repeat(64),
                blake3: "0".repeat(64),
            },
            autopsy: None,
            evidence: vec![],
            verdict: Tier::NoIndicatorsFound,
            verdict_summary: "No indicators".into(),
            files_scanned: 1,
            files_skipped: 0,
            skip_reasons: vec![],
        };

        // Smoke tests ensuring no panic and proper formatting
        print_single_summary_box(&report);
        print_directory_summary_box(
            &PathBuf::from("C:\\test\\dir"),
            10,
            8,
            1,
            1,
            0,
            2,
            0,
            false,
        );

        // High risk with stealer
        let stealer_report = ScanReport {
            identity: FileIdentity {
                path: PathBuf::from("stealer.exe"),
                size_bytes: 2048,
                sha256: "1".repeat(64),
                blake3: "1".repeat(64),
            },
            autopsy: None,
            evidence: vec![oil_core::models::Evidence {
                kind: EvidenceKind::DiscordWebhook {
                    url: "https://discord.com/api/webhooks/123/xyz".into(),
                    encoding: oil_core::models::StringEncoding::Ascii,
                },
                is_threat_signal: true,
                explanation: "test".into(),
            }],
            verdict: Tier::HighRisk,
            verdict_summary: "Stealer detected".into(),
            files_scanned: 1,
            files_skipped: 0,
            skip_reasons: vec![],
        };
        print_single_summary_box(&stealer_report);
        print_directory_summary_box(
            &PathBuf::from("C:\\test\\dir"),
            10,
            7,
            1,
            2,
            0,
            0,
            0,
            true,
        );

        // High risk without stealer (e.g. process injection)
        let injection_report = ScanReport {
            identity: FileIdentity {
                path: PathBuf::from("injector.exe"),
                size_bytes: 2048,
                sha256: "2".repeat(64),
                blake3: "2".repeat(64),
            },
            autopsy: None,
            evidence: vec![oil_core::models::Evidence {
                kind: EvidenceKind::InjectionImport {
                    dll: "kernel32.dll".into(),
                    functions: vec!["CreateRemoteThread".into()],
                },
                is_threat_signal: true,
                explanation: "test".into(),
            }],
            verdict: Tier::HighRisk,
            verdict_summary: "Injection detected".into(),
            files_scanned: 1,
            files_skipped: 0,
            skip_reasons: vec![],
        };
        print_single_summary_box(&injection_report);
        print_directory_summary_box(
            &PathBuf::from("C:\\test\\dir"),
            10,
            7,
            1,
            2,
            0,
            0,
            0,
            false,
        );
    }
}




