//! # Forensic Dossier Output Formatter
//!
//! GDD §5.1 & §5.2 — Renders the scan report into the distinctive
//! cyber-forensic terminal output format.

use crate::lang::Language;
use colored::Colorize;
use oil_core::models::{DiffReport, EvidenceKind, PatchCategory, ScanReport, Tier};

/// Renders a full forensic dossier for a scan report.
pub fn print_dossier(report: &ScanReport) {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".dimmed()
    );
    println!(
        "{}",
        "OIL FORENSIC TRIAGE ENGINE v0.1.0".bright_blue().bold()
    );
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
            println!(
                "{}",
                "OBSERVED INDICATORS (ISOLATED / CONTEXTUAL):"
                    .yellow()
                    .bold()
            );
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
                EvidenceKind::YaraMatch {
                    rule_name,
                    namespace,
                } => {
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
                    format!("{} ({:.2} - high)", s.name, s.entropy)
                        .red()
                        .to_string()
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
                println!(
                    "  • Digital Signature: Valid Authenticode signature ({}) {}",
                    signer.green(),
                    "(Doğrulanmış Windows Authenticode İmzası)"
                        .to_string()
                        .green()
                        .dimmed()
                );
            } else {
                println!(
                    "  • Digital Signature: Valid Authenticode security directory present. {}",
                    "(Doğrulanmış Authenticode Güvenlik Dizini)"
                        .to_string()
                        .green()
                        .dimmed()
                );
            }
        } else if let Some(false) = autopsy.signature_valid {
            if let Some(ref detail) = autopsy.signature_signer {
                println!(
                    "  • Digital Signature: Invalid or unverified Authenticode signature ({}) {}",
                    detail.yellow(),
                    "(Doğrulanmamış veya Geçersiz İmza)"
                        .to_string()
                        .yellow()
                        .dimmed()
                );
            } else {
                println!(
                    "  • Digital Signature: Missing or invalid Authenticode signature. {}",
                    "(Eksik veya Geçersiz Authenticode İmzası)"
                        .to_string()
                        .yellow()
                        .dimmed()
                );
            }
            println!(
                "    {}",
                "Context: Code patches invalidate original vendor signatures. This alone does not indicate malice."
                    .dimmed()
            );
            println!(
                "    {}",
                "(Not: Kod yamaları orijinal üretici imzasını bozar. Bu durum tek başına zararlı anlamına gelmez.)"
                    .dimmed()
            );
        } else {
            println!(
                "  • Digital Signature: Missing signature directory (unsigned / modified). {}",
                "(İmzasız veya Değiştirilmiş İkili Dosya)"
                    .to_string()
                    .dimmed()
            );
            println!(
                "    {}",
                "Context: Code patches invalidate original vendor signatures. This alone does not indicate malice."
                    .dimmed()
            );
            println!(
                "    {}",
                "(Not: Kod yamaları orijinal üretici imzasını bozar. Bu durum tek başına zararlı anlamına gelmez.)"
                    .dimmed()
            );
        }

        // Check for DLL Proxy Hook / Sideloading trap
        for item in &report.evidence {
            if let EvidenceKind::DllProxyHook {
                dll_name,
                shadows_system,
            } = &item.kind
            {
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

        // Check for Emulator Profile (Goldberg, ColdAPI, SmartSteamEmu, etc.)
        for item in &report.evidence {
            if let EvidenceKind::EmulatorProfile {
                name,
                is_legitimate,
                indicators,
            } = &item.kind
            {
                if *is_legitimate {
                    println!(
                        "  • Gaming Platform Emulator: {} {}",
                        name.cyan().bold(),
                        "(Doğrulanmış Emülatör Mimarisi)"
                            .to_string()
                            .cyan()
                            .dimmed()
                    );
                    for ind in indicators {
                        println!("    └─ {}", ind.dimmed());
                    }
                } else {
                    println!(
                        "  {} Suspicious/Hollow Gaming Emulator: {}",
                        "[!]".yellow().bold(),
                        name.yellow().bold()
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
                "Notice: Anomalies observed. Review evidence above before launching.".dimmed()
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
    println!(
        "{}",
        "OIL // SYNTHETIC FORENSIC LAB HARNESS (GHOST LAB)".bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".dimmed()
    );
    println!("Testing against safe, in-memory synthetic PE benchmarks...");
    println!();
    type LabBenchmarkCase = (&'static str, Box<dyn Fn() -> Vec<u8>>, Tier, &'static str);
    let tests: [LabBenchmarkCase; 4] = [
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
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".dimmed()
    );
    if all_passed {
        println!(
            "{}",
            "LAB VERDICT: ALL BENCHMARKS VERIFIED (0 False Positives, Multi-signal Logic Confirmed)"
                .green()
                .bold()
        );
    } else {
        println!(
            "{}",
            "LAB VERDICT: BENCHMARK REGRESSION DETECTED".red().bold()
        );
    }
    println!();
}

/// Renders the forensic dossier for oil diff (Semantic Patch Analysis).
pub fn print_diff_dossier(report: &DiffReport, lang: Language) {
    println!();
    if lang.is_turkish() {
        println!(
            "{}",
            "OIL // Orijinal & Yama / Crack Karşılaştırma Analizi (v0.1.0)".bold()
        );
        println!("{}", "Fark Analizi: Semantik İkili Yama İncelemesi".cyan());
        println!(
            "Orijinal Dosya:  {} [SHA-256: {}]",
            report.original.path.display().to_string().cyan(),
            report.original.sha256
        );
        println!(
            "Yamalı Dosya:    {} [SHA-256: {}]",
            report.patched.path.display().to_string().cyan(),
            report.patched.sha256
        );
        println!();

        // 1. YAPISAL DEĞİŞİKLİKLER
        println!("{}", "YAPISAL DEĞİŞİKLİKLER:".bold());
        if report.new_sections.is_empty() {
            println!("  • Yeni Bölümler: Yok");
        } else {
            println!(
                "  {} Yeni Bölümler: {}",
                "[!]".red().bold(),
                report.new_sections.join(", ").red()
            );
        }

        if report.entry_point_changed {
            println!(
                "  {} Giriş Noktası (Entry Point): DEĞİŞTİ",
                "[!]".red().bold()
            );
        } else {
            println!("  • Giriş Noktası (Entry Point): Değişmedi");
        }

        if report.new_imports.is_empty() {
            println!(
                "  • Dış Fonksiyonlar (Import): Birebir aynı (Yeni ağ veya enjeksiyon API'si yok)"
            );
        } else {
            println!(
                "  {} Dış Fonksiyonlar GENİŞLETİLDİ: {}",
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
                "  • Ek Veri (Overlay): Dosya sonuna {} bayt veri eklendi",
                report.overlay_delta
            );
        } else {
            println!("  • Ek Veri (Overlay): Eklenmedi");
        }
        println!();

        // 2. DEĞİŞTİRİLEN BAYTLAR
        println!(
            "{} ({} yama bölgesi tespit edildi):",
            "DEĞİŞTİRİLEN BAYTLAR".bold(),
            report.patches.len()
        );
        if report.patches.is_empty() {
            println!("  • Değiştirilen bayt aralığı yok (Dosyalar birebir aynı).");
        } else {
            for (idx, patch) in report.patches.iter().enumerate() {
                let cat_label = match patch.category {
                    PatchCategory::DrmBypass => "LİSANS_KİLİDİ_BYPASS".green().bold(),
                    PatchCategory::CodeInjection => "KOD_ENJEKSİYONU".red().bold(),
                    PatchCategory::DigitalSignature => "DİJİTAL_İMZA".cyan().bold(),
                    PatchCategory::Unknown => "BİLİNMEYEN_YAMA".yellow().bold(),
                };

                println!(
                    "  Bölge {} [Ofset 0x{:X}, {} bayt, Bölüm: {}]:",
                    idx + 1,
                    patch.offset,
                    patch.size,
                    patch.section
                );
                if let Some(ref disasm) = patch.disassembly {
                    println!("    - Talimat: {}", disasm.cyan());
                }
                println!("    - Sınıflandırma: {}", cat_label);
            }
        }
        println!();

        // 3. YAMA PARMAK İZİ
        println!(
            "YAMA PARMAK İZİ (Delta SHA-256): {}",
            report.delta_fingerprint.bright_blue()
        );
        println!();

        // 4. KARAR
        println!("{}", "SONUÇ VE KARAR:".bold());
        match report.verdict {
            Tier::HighRisk => {
                println!("  {}", "[YÜKSEK RİSK]".red().bold());
                println!("  Özet: {}", report.verdict_summary.red());
            }
            Tier::Suspicious => {
                println!("  {}", "[ŞÜPHELİ]".yellow().bold());
                println!("  Özet: {}", report.verdict_summary.yellow());
            }
            Tier::NoIndicatorsFound => {
                println!("  {}", "[GÖSTERGE BULUNAMADI]".bright_blue().bold());
                println!("  Özet: {}", report.verdict_summary);
            }
            Tier::Inconclusive => {
                println!("  {}", "[KARARSIZ]".magenta().bold());
                println!("  Neden: {}", report.verdict_summary);
            }
        }
    } else {
        println!(
            "{}",
            "OIL // Binary & Patch Comparison Analysis (v0.1.0)".bold()
        );
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

        // 1. STRUCTURAL DELTA
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

        // 2. DIRTY BYTES
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

        // 3. DELTA FINGERPRINT
        println!(
            "DELTA FINGERPRINT (SHA-256 of patch delta): {}",
            report.delta_fingerprint.bright_blue()
        );
        println!();

        // 4. THE VERDICT
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
    }
    println!();
}

/// Renders the forensic dossier for oil hunt (Persistence and Sideloading Audit).
pub fn print_hunt_dossier(report: &oil_core::hunt::HuntReport, lang: Language) {
    println!();
    if lang.is_turkish() {
        println!(
            "{}",
            "OIL // Windows Başlangıç & Sistem Denetimi (v0.1.0)".bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".dimmed()
        );
        println!(
            "{} adet başlangıç mekanizması denetlendi (Kayıt Defteri Run anahtarları, Başlangıç klasörleri)...",
            report.total_inspected
        );
    } else {
        println!(
            "{}",
            "OIL // Windows Persistence & Sideloading Audit (v0.1.0)".bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".dimmed()
        );
        println!(
            "Inspected {} persistence mechanisms (Registry Run keys, Startup folders)...",
            report.total_inspected
        );
    }
    println!();

    if report.items.is_empty() {
        if lang.is_turkish() {
            println!("  • Standart konumlarda herhangi bir başlangıç girdisi bulunamadı.");
        } else {
            println!("  • Zero persistence entries discovered in standard locations.");
        }
    } else {
        for (idx, item) in report.items.iter().enumerate() {
            let status_badge = if let Some(ref scan) = item.scan_report {
                match scan.verdict {
                    Tier::HighRisk => {
                        if lang.is_turkish() {
                            "[YÜKSEK RİSK]".red().bold()
                        } else {
                            "[HIGH RISK]".red().bold()
                        }
                    }
                    Tier::Suspicious => {
                        if lang.is_turkish() {
                            "[ŞÜPHELİ]".yellow().bold()
                        } else {
                            "[SUSPICIOUS]".yellow().bold()
                        }
                    }
                    Tier::NoIndicatorsFound => {
                        if lang.is_turkish() {
                            "[BULGU YOK]".bright_blue().bold()
                        } else {
                            "[NO INDICATORS FOUND]".bright_blue().bold()
                        }
                    }
                    Tier::Inconclusive => {
                        if lang.is_turkish() {
                            "[KARARSIZ]".magenta().bold()
                        } else {
                            "[INCONCLUSIVE]".magenta().bold()
                        }
                    }
                }
            } else if lang.is_turkish() {
                "[DOSYA BULUNAMADI / ÇÖZÜLEMEDİ]".dimmed()
            } else {
                "[FILE NOT FOUND / UNRESOLVED]".dimmed()
            };

            let source_label = if lang.is_turkish() {
                "Kaynak"
            } else {
                "Source"
            };
            let cmd_label = if lang.is_turkish() {
                "Komut"
            } else {
                "Command"
            };
            let res_label = if lang.is_turkish() {
                "Konum"
            } else {
                "Resolved"
            };
            let note_label = if lang.is_turkish() {
                "Karar Notu"
            } else {
                "Verdict Note"
            };

            println!(
                "  {} [{}] {} ({}: {})",
                format!("#{}", idx + 1).bold(),
                item.entry_name.cyan(),
                status_badge,
                source_label,
                item.source.to_string().dimmed()
            );
            println!("    {}: {}", cmd_label, item.command_line.dimmed());
            if let Some(ref p) = item.resolved_path {
                println!("    {}: {}", res_label, p.display().to_string().cyan());
            }
            if let Some(ref scan) = item.scan_report {
                if scan.verdict == Tier::HighRisk || scan.verdict == Tier::Suspicious {
                    println!("    {}: {}", note_label, scan.verdict_summary.red());
                }
            }
            println!();
        }
    }

    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".dimmed()
    );
    let accounted = report.no_indicators_count + report.suspicious_count + report.high_risk_count;
    let unresolved_count = report.total_inspected.saturating_sub(accounted);

    if lang.is_turkish() {
        println!("{}", "BAŞLANGIÇ & GİZLİ TEHDİT ÖZETİ:".bold());
        println!("  • Toplam Denetlenen:     {}", report.total_inspected);
        println!(
            "  • Tehlike Bulgusu Yok:   {}",
            report.no_indicators_count.to_string().bright_blue()
        );
        println!(
            "  • Şüpheli:               {}",
            report.suspicious_count.to_string().yellow()
        );
        println!(
            "  • Yüksek Risk:           {}",
            report.high_risk_count.to_string().red().bold()
        );
        if unresolved_count > 0 {
            println!(
                "  • Çözümlenemeyen / Boş:  {}",
                unresolved_count.to_string().dimmed()
            );
        }
    } else {
        println!("{}", "PERSISTENCE AUDIT SUMMARY:".bold());
        println!("  • Total Inspected:       {}", report.total_inspected);
        println!(
            "  • No Indicators Found:   {}",
            report.no_indicators_count.to_string().bright_blue()
        );
        println!(
            "  • Suspicious:            {}",
            report.suspicious_count.to_string().yellow()
        );
        println!(
            "  • High Risk:             {}",
            report.high_risk_count.to_string().red().bold()
        );
        if unresolved_count > 0 {
            println!(
                "  • Unresolved / Missing:  {}",
                unresolved_count.to_string().dimmed()
            );
        }
    }
    println!();
}

/// Renders a human-readable, high-impact executive summary card for a single file.
pub fn print_single_summary_box(report: &ScanReport, lang: Language) {
    let file_name = report
        .identity
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("target");

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".cyan()
    );
    if lang.is_turkish() {
        println!("   {}", "MOD, CRACK VE DOSYA ANALİZ ÖZETİ".cyan().bold());
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".cyan()
        );
        println!("  Hedef Dosya: {}", file_name.bold());

        match report.verdict {
            Tier::HighRisk => {
                println!("  Karar: {}", "[YÜKSEK RİSK]".red().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  DEĞERLENDİRME:");
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
                    println!("  • KRİTİK: Bilgi çalıcı, zararlı webhook veya veri sızdırma mekanizması tespit edildi!");
                    println!(
                        "  • EYLEM: Dosyayı ÇALIŞTIRMAYINIZ; karantinaya alınız veya siliniz."
                    );
                } else {
                    println!("  • KRİTİK: Yüksek riskli süreç enjeksiyonu veya zararlı yükleyici yapısı tespit edildi!");
                    println!("  • EYLEM: Güvenilmeyen bir kaynaktan geldiyse çalıştırmayınız.");
                }
            }
            Tier::Suspicious => {
                println!("  Karar: {}", "[ŞÜPHELİ]".yellow().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  DEĞERLENDİRME:");
                if report
                    .verdict_summary
                    .contains("Untrusted Sideloading Loader")
                    || report.verdict_summary.contains("Local Hook")
                {
                    println!("  • Yerel lisans kancası veya mod mekanizması (Sıfır dış ağ soketi/API'si).");
                    println!(
                        "  • EYLEM: Yalnızca güvenilir çevrimdışı kullanım için değerlendiriniz."
                    );
                } else {
                    println!(
                        "  • Yapısal anomali, şüpheli ağ importu veya yüksek entropi görüldü."
                    );
                    println!("  • EYLEM: Kaynağı doğrulanmadıkça dikkatli olunuz.");
                }
            }
            Tier::NoIndicatorsFound => {
                println!("  Karar: {}", "[GÖSTERGE BULUNAMADI]".green().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  DEĞERLENDİRME:");
                println!("  • Bilinen trojan, veri çalıcı veya zararlı yazılım göstergesine rastlanmadı.");
            }
            Tier::Inconclusive => {
                println!("  Karar: {}", "[KARARSIZ]".magenta().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  DEĞERLENDİRME:");
                println!("  • Hedef çalıştırılabilir PE binary değil veya biçim çözümlenemedi.");
                println!("  • EYLEM: Arşiv ise içeriği çıkartıp taranmasını sağlayınız.");
            }
        }

        let proxy_hooks = report
            .evidence
            .iter()
            .filter(|e| matches!(&e.kind, EvidenceKind::DllProxyHook { .. }))
            .count();
        if proxy_hooks > 0 {
            println!(
                "  • Yan Yükleme Kancası: {} adet sistem DLL kancası tespit edildi.",
                proxy_hooks
            );
        }

        if let Some((emu_name, is_legit)) = report.evidence.iter().find_map(|e| {
            if let EvidenceKind::EmulatorProfile {
                name,
                is_legitimate,
                ..
            } = &e.kind
            {
                Some((name, *is_legitimate))
            } else {
                None
            }
        }) {
            if is_legit {
                println!(
                    "  • Oyun Platformu Emülatörü: {} {}",
                    emu_name.cyan().bold(),
                    "(Doğrulanmış Profil)".cyan().dimmed()
                );
            } else {
                println!(
                    "  • Oyun Platformu Emülatörü: {} {}",
                    emu_name.yellow().bold(),
                    "(Şüpheli / İçi Boş)".yellow().dimmed()
                );
            }
        }

        println!();
        println!(
            "  {} Teknik analiz için terminali yukarı kaydırabilirsiniz.",
            "[BİLGİ]".cyan()
        );
    } else {
        println!(
            "   {}",
            "MOD, CRACK & BINARY ANALYSIS SUMMARY".cyan().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".cyan()
        );
        println!("  Target: {}", file_name.bold());

        match report.verdict {
            Tier::HighRisk => {
                println!("  Verdict: {}", "[HIGH RISK]".red().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  ASSESSMENT:");
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
                    println!(
                        "  • CRITICAL: Infostealer, malicious webhook, or data siphon observed!"
                    );
                    println!("  • ACTION: DO NOT EXECUTE. Delete or quarantine immediately.");
                } else {
                    println!("  • CRITICAL: High-risk hostile payload / code injection structure detected!");
                    println!("  • ACTION: Execution not recommended unless strictly trusted.");
                }
            }
            Tier::Suspicious => {
                println!("  Verdict: {}", "[SUSPICIOUS]".yellow().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  ASSESSMENT:");
                if report
                    .verdict_summary
                    .contains("Untrusted Sideloading Loader")
                    || report.verdict_summary.contains("Local Hook")
                {
                    println!(
                        "  • Untrusted local hook / license emulator (Zero network capabilities)."
                    );
                    println!(
                        "  • ACTION: Safe for offline use; evaluate provenance before executing."
                    );
                } else {
                    println!("  • Structural anomaly, suspicious network import, or high entropy section.");
                    println!("  • ACTION: Exercise caution if origin is untrusted or unknown.");
                }
            }
            Tier::NoIndicatorsFound => {
                println!("  Verdict: {}", "[NO INDICATORS FOUND]".green().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  ASSESSMENT:");
                println!(
                    "  • No known trojans, infostealers, backdoors, or ransomware traces found."
                );
            }
            Tier::Inconclusive => {
                println!("  Verdict: {}", "[INCONCLUSIVE]".magenta().bold());
                println!(
                    "{}",
                    "───────────────────────────────────────────────────────────────".dimmed()
                );
                println!("  ASSESSMENT:");
                println!(
                    "  • Target is not an executable PE binary or format cannot be determined."
                );
                println!("  • ACTION: Extract contents to a folder and scan directory.");
            }
        }

        let proxy_hooks = report
            .evidence
            .iter()
            .filter(|e| matches!(&e.kind, EvidenceKind::DllProxyHook { .. }))
            .count();
        if proxy_hooks > 0 {
            println!(
                "  • Sideloading Hook: {} system/platform DLL hook(s) detected.",
                proxy_hooks
            );
        }

        if let Some((emu_name, is_legit)) = report.evidence.iter().find_map(|e| {
            if let EvidenceKind::EmulatorProfile {
                name,
                is_legitimate,
                ..
            } = &e.kind
            {
                Some((name, *is_legitimate))
            } else {
                None
            }
        }) {
            if is_legit {
                println!(
                    "  • Gaming Platform Emulator: {} {}",
                    emu_name.cyan().bold(),
                    "(Verified Profile)".cyan().dimmed()
                );
            } else {
                println!(
                    "  • Gaming Platform Emulator: {} {}",
                    emu_name.yellow().bold(),
                    "(Suspicious / Hollow)".yellow().dimmed()
                );
            }
        }

        println!();
        println!("  {} Scroll up for hashes & PE autopsy.", "[NOTICE]".cyan());
    }
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".cyan()
    );
    println!();
}

/// Renders a human-readable, high-impact executive summary card for a directory audit.
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
    lang: Language,
) {
    let dir_name = dir_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Target Directory");

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".cyan()
    );
    if lang.is_turkish() {
        println!("  {}", "KLASÖR MOD & CRACK ANALİZ RAPORU".cyan().bold());
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".cyan()
        );
        println!("  Hedef Klasör: {}", dir_name.bold());
        if duplicate_count > 0 {
            let unique = total.saturating_sub(duplicate_count);
            println!(
                "  Taranan: {} çalıştırılabilir dosya ({} benzersiz, {} kopya)",
                total, unique, duplicate_count
            );
        } else {
            println!("  Taranan: {} çalıştırılabilir dosya (.exe / .dll)", total);
        }

        if proxy_hook_count > 0 {
            println!(
                "  İstatistik: {} Gösterge Bulunamadı | {} Şüpheli ({} Proxy Kanca) | {} Yüksek Risk | {} Kararsız",
                no_indicators, suspicious, proxy_hook_count, high_risk, inconclusive
            );
        } else {
            println!(
                "  İstatistik: {} Gösterge Bulunamadı | {} Şüpheli | {} Yüksek Risk | {} Kararsız",
                no_indicators, suspicious, high_risk, inconclusive
            );
        }
        println!(
            "{}",
            "───────────────────────────────────────────────────────────────".dimmed()
        );

        if high_risk > 0 {
            println!("  Nihai Durum: {}", "[YÜKSEK RİSK]".red().bold());
            println!("  DEĞERLENDİRME:");
            println!(
                "  • UYARI: Klasörde {} adet yüksek riskli dosya tespit edildi!",
                high_risk
            );
            if has_stealer_ioc {
                println!("  • Bilgi çalıcı veya zararlı veri sızdırma mekanizması tespit edildi. ÇALIŞTIRMAYINIZ!");
            } else {
                println!("  • Düşmanca süreç enjeksiyonu veya zararlı yükleyici yapısı tespit edildi. ÇALIŞTIRMAYINIZ!");
            }
        } else if suspicious > 0 {
            println!("  Nihai Durum: {}", "[ŞÜPHELİ]".yellow().bold());
            println!("  DEĞERLENDİRME:");
            println!(
                "  • Klasörde {} adet şüpheli dosya/anomali gözlemlendi.",
                suspicious
            );
            println!("  • Güvenilmeyen bir kaynaktan indirildiyse dikkatli olunuz.");
        } else {
            println!("  Nihai Durum: {}", "[GÖSTERGE BULUNAMADI]".green().bold());
            println!("  DEĞERLENDİRME:");
            println!(
                "  • Taranan {} dosyanın hiçbirinde trojan veya zararlı yazılım göstergesine rastlanmadı.",
                total
            );
        }

        if proxy_hook_count > 0 {
            println!(
                "  • Yan Yükleme: {} adet platform/sistem DLL kancası tespit edildi.",
                proxy_hook_count
            );
            if high_risk == 0 {
                println!("    Sıfır dış ağ: muhtemelen yerel lisans kancası veya mod emülatörü.");
            }
        }

        println!();
        println!(
            "  {} Dosyaları incelemek için aşağıdaki menüyü kullanın.",
            "[BİLGİ]".cyan()
        );
    } else {
        println!(
            "  {}",
            "DIRECTORY MOD & CRACK ANALYSIS SUMMARY".cyan().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".cyan()
        );
        println!("  Target: {}", dir_name.bold());
        if duplicate_count > 0 {
            let unique = total.saturating_sub(duplicate_count);
            println!(
                "  Scanned: {} executables ({} unique, {} duplicates)",
                total, unique, duplicate_count
            );
        } else {
            println!("  Scanned: {} executables (.exe / .dll)", total);
        }

        if proxy_hook_count > 0 {
            println!(
                "  Stats: {} No Indicators | {} Suspicious (incl. {} Proxy Hooks) | {} High Risk | {} Inconclusive",
                no_indicators, suspicious, proxy_hook_count, high_risk, inconclusive
            );
        } else {
            println!(
                "  Stats: {} No Indicators | {} Suspicious | {} High Risk | {} Inconclusive",
                no_indicators, suspicious, high_risk, inconclusive
            );
        }
        println!(
            "{}",
            "───────────────────────────────────────────────────────────────".dimmed()
        );

        if high_risk > 0 {
            println!("  Final Verdict: {}", "[HIGH RISK]".red().bold());
            println!("  ASSESSMENT:");
            println!(
                "  • ALERT: {} dangerous file(s) identified in folder!",
                high_risk
            );
            if has_stealer_ioc {
                println!(
                    "  • Infostealer or malicious exfiltration channel detected. DO NOT EXECUTE!"
                );
            } else {
                println!("  • Hostile process injection or malicious loader structure detected. DO NOT EXECUTE!");
            }
        } else if suspicious > 0 {
            println!("  Final Verdict: {}", "[SUSPICIOUS]".yellow().bold());
            println!("  ASSESSMENT:");
            println!("  • {} anomalous file(s) observed.", suspicious);
            println!("  • Exercise caution if downloaded from an untrusted source.");
        } else {
            println!(
                "  Final Verdict: {}",
                "[NO INDICATORS FOUND]".green().bold()
            );
            println!("  ASSESSMENT:");
            println!(
                "  • No infostealers, trojans, or malware traces found in {} scanned file(s).",
                total
            );
        }

        if proxy_hook_count > 0 {
            println!(
                "  • Sideloading: {} platform/system DLL hook(s) detected.",
                proxy_hook_count
            );
            if high_risk == 0 {
                println!("    Zero outbound network: likely local license hook or emulator.");
            }
        }

        println!();
        println!(
            "  {} Use Navigation menu below to inspect files.",
            "[NOTICE]".cyan()
        );
    }
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════".cyan()
    );
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
    lang: Language,
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
        lang,
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

        // Smoke tests ensuring no panic and proper formatting in both languages
        print_single_summary_box(&report, Language::English);
        print_single_summary_box(&report, Language::Turkish);
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
            Language::English,
        );
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
            Language::Turkish,
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
        print_single_summary_box(&stealer_report, Language::English);
        print_single_summary_box(&stealer_report, Language::Turkish);
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
            Language::English,
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
        print_single_summary_box(&injection_report, Language::Turkish);
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
            Language::Turkish,
        );

        let hunt_report = oil_core::hunt::HuntReport {
            items: vec![],
            total_inspected: 21,
            high_risk_count: 1,
            suspicious_count: 0,
            no_indicators_count: 14,
        };
        print_hunt_dossier(&hunt_report, Language::English);
        print_hunt_dossier(&hunt_report, Language::Turkish);

        let diff_report = DiffReport {
            original: FileIdentity {
                path: PathBuf::from("orig.exe"),
                size_bytes: 1024,
                sha256: "0".repeat(64),
                blake3: "0".repeat(64),
            },
            patched: FileIdentity {
                path: PathBuf::from("patched.exe"),
                size_bytes: 1024,
                sha256: "1".repeat(64),
                blake3: "1".repeat(64),
            },
            new_sections: vec![],
            entry_point_changed: false,
            new_imports: vec![],
            overlay_delta: 0,
            patches: vec![],
            delta_fingerprint: "0".repeat(64),
            verdict: Tier::NoIndicatorsFound,
            verdict_summary: "Identical".into(),
        };
        print_diff_dossier(&diff_report, Language::English);
        print_diff_dossier(&diff_report, Language::Turkish);
    }
}
