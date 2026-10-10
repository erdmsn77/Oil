# OIL // Binary Forensic Triage & Semantic Patch Engine

[![Build and sign release](https://github.com/erdmsn77/oil/actions/workflows/release-sign.yml/badge.svg)](https://github.com/erdmsn77/oil/actions/workflows/release-sign.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](https://www.rust-lang.org/)

**Oil** is a high-performance, context-aware binary forensic triage and semantic patch engine written in Rust. Designed for reverse engineers, malware analysts, and incident responders, Oil rapidly inspects untrusted executables, archives, and directories to separate benign code modifications from hostile capabilities.

Zero bloat, zero cloud dependencies, sub-millisecond execution.

---

## Key Capabilities

### 1. PE Deep Autopsy & Anomaly Detection
- **Shannon Entropy Profiling**: Evaluates per-section entropy to pinpoint packed, compressed, or encrypted sections.
- **RWX Memory Permissions**: Detects self-modifying code blocks and runtime unpackers (e.g. `.Baymax`).
- **Codeless Container Identification**: Flags binaries that lack executable code sections but harbor near-maximal entropy data blocks.
- **Digital Signature Verification**: Cryptographically validates Authenticode signatures via native Windows Trust Provider (`WinVerifyTrust` FFI) against trusted Root CAs.

### 2. Threat Vector & IOC Extraction
- **Infostealer Indicators**: Detects exfiltration channels (Discord Webhook URLs, Telegram Bot API tokens) across ASCII and UTF-16LE encodings.
- **Credential Harvesters**: Identifies hardcoded paths to SQLite credential databases across Chrome, Edge, Firefox, Brave, and crypto wallets.
- **Process Injection & Stagers**: Flags process memory manipulation imports (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) and encoded PowerShell dropper fragments.

### 3. DLL Search-Order Hijacking & Sideloading Detection
- **System DLL Shadowing**: Detects application-directory proxy DLLs shadowing core Windows system libraries (`version.dll`, `dbghelp.dll`, etc.).
- **Directory Correlation Analysis**: Correlates co-located unsigned proxy hooks with packed/RWX binaries, elevating hostile loader suites to `HIGH RISK`.

### 4. Semantic Binary Diffing & Patch Classification
- **Disassembly Engine**: Powered by `iced-x86` for full x86/x64 instruction-level analysis.
- **Smart Patch Classifier**: Differentiates between benign DRM bypasses (e.g. `JNE` to `JMP`, `XOR EAX, EAX; RET`) and hostile code caves or external trampoline jumps.

### 5. Safe In-Memory Archive Inspection
- **Defensive Unpacking**: Inspects `.zip` archives directly in memory without writing files to disk.
- **Zip-Bomb & Resource Guard**: Enforces global cumulative decompression budgets and hard file count limits.
- **Encrypted Entry Triage**: Safely tags password-protected archives as `INCONCLUSIVE` without generating false-clean verdicts.

---

## Architecture

Oil is designed with a strict library/CLI architectural boundary:

```
oil/
├── crates/
│   ├── oil-core/    # Pure forensic analysis engine (zero UI, zero side-effects)
│   │   ├── src/
│   │   │   ├── archive.rs   # Zip inspection & memory budgeting
│   │   │   ├── diff.rs      # Semantic binary diffing & patch classification
│   │   │   ├── hunt.rs      # DLL proxy hunting & LNK parsing
│   │   │   ├── io.rs        # Dual hashing (SHA-256 + BLAKE3) & entropy
│   │   │   ├── ioc.rs       # Aho-Corasick multi-pattern string scanner
│   │   │   ├── pe.rs        # Goblin PE parser & structural autopsy
│   │   │   ├── risk.rs      # Decision matrix & combinatorial threat scoring
│   │   │   └── wintrust.rs  # Native Windows Authenticode verification FFI
│   │
│   └── oil-cli/     # Terminal interface & forensic dossier formatter
│       └── src/
│           ├── main.rs      # Interactive CLI, directory triage & caching
│           └── output.rs    # ANSI forensic dossiers & executive summary cards
```

---

## Installation & Build

### Prerequisites
- [Rust 1.75+](https://www.rust-lang.org/tools/install) (2021 Edition)
- Windows (x86_64) for native Authenticode verification features

### Build from Source
```bash
git clone https://github.com/erdmsn77/oil.git
cd oil

# Run all test suites (77 unit and integration tests)
cargo test --workspace

# Build optimized release binary
cargo build --release
```

The compiled binary will be placed at `target/release/oil.exe`.

---

## Usage

```bash
# Scan a single executable or archive
oil scan C:\Path\To\Binary.exe

# Scan an entire directory with SHA-256 deduplication and suite correlation
oil scan C:\Path\To\SoftwareDirectory

# Semantically compare an original binary against a modified/patched binary
oil diff clean_target.exe modified_target.exe

# Audit directory for DLL search-order hijacking / proxy DLLs
oil hunt C:\Path\To\ApplicationDirectory
```

---

## Epistemic Honesty Principles

Oil adheres strictly to epistemic safety rules in binary forensics:
- **Zero False-Clean Claims**: A binary with zero matched IOCs is labeled `NO INDICATORS FOUND`, never "Safe" or "Clean".
- **Evidence-Backed Verdicts**: Every verdict is accompanied by verifiable Shannon entropy scores, section names, imported API lists, and cryptographic signature statuses.
- **Priority-Separated Triage**: Signed vendor protections (e.g. proprietary bytecode or encrypted licensing blobs) are clearly distinguished from unsigned hostile loader suites.

---

## License

This project is licensed under the [MIT License](LICENSE).
