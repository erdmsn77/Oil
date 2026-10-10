//! # Semantic Patch Classifier & Binary Diff Engine (`oil diff`)
//!
//! GDD §4 — Differentiates benign reverse-engineering DRM bypasses
//! from malicious code injections by disassembling modified byte regions
//! using `iced-x86` and comparing macro PE structures.

use crate::io::{identify_file, IoError};
use crate::models::{
    DiffReport, ImportEntry, PatchCategory, PatchRegion, Tier,
};
use crate::pe::analyze_pe;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Compares an original binary with a patched/cracked binary and performs semantic analysis.
pub fn diff_binaries(original_path: &Path, patched_path: &Path) -> Result<DiffReport, IoError> {
    let (original_ident, orig_data) = identify_file(original_path)?;
    let (patched_ident, patch_data) = identify_file(patched_path)?;

    let orig_bytes = orig_data.as_bytes();
    let patch_bytes = patch_data.as_bytes();

    let orig_pe = analyze_pe(orig_bytes).map(|(a, _)| a);
    let patch_pe = analyze_pe(patch_bytes).map(|(a, _)| a);

    // ──────────────────────────────────────────────
    // 1. MACRO-STRUCTURAL CHECKS
    // ──────────────────────────────────────────────
    let mut new_sections = Vec::new();
    let mut entry_point_changed = false;
    let mut new_imports = Vec::new();
    let mut overlay_delta: i64 = 0;

    let is_64bit = orig_pe.as_ref().map(|p| p.is_64bit).unwrap_or(true);

    if let (Some(ref orig), Some(ref patch)) = (&orig_pe, &patch_pe) {
        // Section diff
        let orig_sec_names: Vec<_> = orig.sections.iter().map(|s| &s.name).collect();
        for sec in &patch.sections {
            if !orig_sec_names.contains(&&sec.name) {
                new_sections.push(sec.name.clone());
            }
        }

        // Entry point change
        if orig.entry_point != patch.entry_point {
            entry_point_changed = true;
        }

        // Import table expansion
        let orig_dlls: Vec<_> = orig.imports.iter().map(|i| &i.dll_name).collect();
        for imp in &patch.imports {
            if !orig_dlls.contains(&&imp.dll_name) {
                new_imports.push(imp.clone());
            } else {
                // Check if specific dangerous functions were added to an existing DLL
                if let Some(orig_imp) = orig.imports.iter().find(|i| i.dll_name == imp.dll_name) {
                    let added_funcs: Vec<_> = imp
                        .functions
                        .iter()
                        .filter(|f| !orig_imp.functions.contains(f))
                        .cloned()
                        .collect();
                    if !added_funcs.is_empty() {
                        new_imports.push(ImportEntry {
                            dll_name: imp.dll_name.clone(),
                            functions: added_funcs,
                        });
                    }
                }
            }
        }

        // Overlay delta
        overlay_delta = patch.overlay_size as i64 - orig.overlay_size as i64;
    }

    // ──────────────────────────────────────────────
    // 2. BYTE RANGE EXTRACTION & DISASSEMBLY
    // ──────────────────────────────────────────────
    let patches = extract_and_classify_patches(
        orig_bytes,
        patch_bytes,
        is_64bit,
        orig_pe.as_ref(),
        patch_pe.as_ref(),
    );

    // ──────────────────────────────────────────────
    // 3. DELTA FINGERPRINT (SHA-256 of the patch delta)
    // ──────────────────────────────────────────────
    let mut delta_hasher = Sha256::new();
    for p in &patches {
        delta_hasher.update(&p.offset.to_le_bytes());
        delta_hasher.update(&p.size.to_le_bytes());

        let o_start = (p.offset as usize).min(orig_bytes.len());
        let o_end = (p.offset as usize).saturating_add(p.size as usize).min(orig_bytes.len());
        delta_hasher.update(&orig_bytes[o_start..o_end]);

        let p_start = (p.offset as usize).min(patch_bytes.len());
        let p_end = (p.offset as usize).saturating_add(p.size as usize).min(patch_bytes.len());
        delta_hasher.update(&patch_bytes[p_start..p_end]);
    }
    let delta_fingerprint = format!("{:x}", delta_hasher.finalize());

    // ──────────────────────────────────────────────
    // 4. VERDICT COMPUTATION
    // ──────────────────────────────────────────────
    let mut has_code_injection = false;
    let mut has_drm_bypass = false;
    let mut has_digital_signature = false;
    let mut has_unknown_patch = false;

    for p in &patches {
        match p.category {
            PatchCategory::CodeInjection => has_code_injection = true,
            PatchCategory::DrmBypass => has_drm_bypass = true,
            PatchCategory::DigitalSignature => has_digital_signature = true,
            PatchCategory::Unknown => has_unknown_patch = true,
        }
    }

    // Check for high risk conditions:
    // New section added + networking/injection APIs, or entry point moved to new section
    let has_suspicious_new_imports = new_imports.iter().any(|i| {
        ["ws2_32.dll", "wininet.dll", "urlmon.dll"].contains(&i.dll_name.as_str())
    });

    let (verdict, verdict_summary) = if has_code_injection
        || (!new_sections.is_empty() && has_suspicious_new_imports)
        || (entry_point_changed && !new_sections.is_empty())
    {
        (
            Tier::HighRisk,
            "Code injection or structural hijack detected: Entry point redirection, new executable sections, or foreign network imports.".to_string(),
        )
    } else if !new_sections.is_empty() || overlay_delta > 1024 || has_suspicious_new_imports || has_unknown_patch {
        (
            Tier::Suspicious,
            if has_unknown_patch && has_drm_bypass {
                "Mixed patch semantics: verified DRM bypass accompanied by unverified or unknown byte modifications.".to_string()
            } else if has_unknown_patch {
                "Localized byte modifications observed that do not match standard DRM bypass templates.".to_string()
            } else {
                "Structural expansions observed (new sections or expanded overlay/imports) that require scrutiny.".to_string()
            },
        )
    } else if has_drm_bypass || has_digital_signature || patches.is_empty() {
        (
            Tier::NoIndicatorsFound,
            "Patch semantics match known benign DRM bypass patterns or Authenticode digital signature structures.".to_string(),
        )
    } else {
        (
            Tier::Suspicious,
            "Localized byte modifications observed that do not strictly match standard DRM bypass templates.".to_string(),
        )
    };

    Ok(DiffReport {
        original: original_ident,
        patched: patched_ident,
        new_sections,
        entry_point_changed,
        new_imports,
        overlay_delta,
        patches,
        delta_fingerprint,
        verdict,
        verdict_summary,
    })
}

/// Identifies contiguous altered byte spans and disassembles them with iced-x86.
fn extract_and_classify_patches(
    orig: &[u8],
    patched: &[u8],
    is_64bit: bool,
    orig_pe: Option<&crate::models::PeAutopsy>,
    patch_pe: Option<&crate::models::PeAutopsy>,
) -> Vec<PatchRegion> {
    let min_len = orig.len().min(patched.len());
    let mut regions = Vec::new();

    let mut i = 0;
    while i < min_len {
        if orig[i] != patched[i] {
            let start = i;
            // Coalesce changes separated by <= 4 identical bytes into the same patch region
            let mut end = i;
            while end < min_len {
                if orig[end] != patched[end] {
                    i = end;
                } else if end - i > 4 {
                    break;
                }
                end += 1;
            }
            let patch_end = i + 1;
            let size = (patch_end - start) as u64;

            let orig_slice = &orig[start..patch_end];
            let patch_slice = &patched[start..patch_end];

            let (section_name, section_bounds, rva) = if let Some(pe) = orig_pe {
                pe.sections.iter().find(|s| {
                    let raw_start = s.pointer_to_raw_data;
                    let raw_end = raw_start.saturating_add(s.raw_size);
                    (start as u64) >= raw_start && (start as u64) < raw_end
                }).map(|s| {
                    let offset_in_sec = (start as u64).saturating_sub(s.pointer_to_raw_data);
                    let rva = s.virtual_address.saturating_add(offset_in_sec);
                    let bounds = (s.virtual_address, s.virtual_address.saturating_add(s.virtual_size));
                    (s.name.clone(), Some(bounds), rva)
                }).unwrap_or_else(|| {
                    let first_sec_start = pe.sections.iter().map(|s| s.pointer_to_raw_data).min().unwrap_or(0x200);
                    if (start as u64) < first_sec_start {
                        ("[PE_HEADER]".to_string(), None, start as u64)
                    } else {
                        (".unknown".to_string(), None, start as u64)
                    }
                })
            } else {
                (".text".to_string(), None, start as u64)
            };

            let (disasm, category) = if section_name == "[PE_HEADER]" {
                let has_sec_dir = patch_pe.and_then(|p| p.security_directory).is_some();
                let desc = if has_sec_dir {
                    format!("PE header structure modification (DataDirectory / Checksum update, {} bytes)", size)
                } else {
                    format!("PE header structure modification ({} bytes)", size)
                };
                let cat = if has_sec_dir {
                    PatchCategory::DigitalSignature
                } else {
                    PatchCategory::Unknown
                };
                (Some(desc), cat)
            } else {
                classify_patch_bytes(orig, patched, start, patch_end, rva, is_64bit, section_bounds)
            };

            let encoded_orig = if orig_slice.len() > 64 {
                format!("{} ... ({} bytes total)", hex_encode(&orig_slice[..64]), size)
            } else {
                hex_encode(orig_slice)
            };
            let encoded_patch = if patch_slice.len() > 64 {
                format!("{} ... ({} bytes total)", hex_encode(&patch_slice[..64]), size)
            } else {
                hex_encode(patch_slice)
            };

            regions.push(PatchRegion {
                offset: start as u64,
                section: section_name,
                size,
                original_bytes: encoded_orig,
                patched_bytes: encoded_patch,
                disassembly: disasm,
                category,
            });

            i = patch_end;
        } else {
            i += 1;
        }
    }

    // Capture appended tail payload past original EOF
    if patched.len() > min_len {
        let start = min_len;
        let patch_slice = &patched[start..];
        let total_size = patch_slice.len() as u64;

        let sec_dir = patch_pe.and_then(|p| p.security_directory);

        if let Some((cert_offset, cert_size)) = sec_dir {
            let cert_start = cert_offset as usize;
            let cert_end = (cert_offset.saturating_add(cert_size) as usize).min(patched.len());

            if cert_size > 0 && cert_start < patched.len() && cert_end > start {
                // Pre-certificate appended data (if any, beyond 8-byte alignment)
                if cert_start > start && (cert_start - start) > 8 {
                    let pre_slice = &patched[start..cert_start];
                    let pre_size = pre_slice.len() as u64;
                    let pre_entropy = crate::io::shannon_entropy(pre_slice);
                    let encoded_pre = if pre_slice.len() > 64 {
                        format!("{} ... ({} bytes total)", hex_encode(&pre_slice[..64]), pre_size)
                    } else {
                        hex_encode(pre_slice)
                    };
                    regions.push(PatchRegion {
                        offset: start as u64,
                        section: "[EOF_APPENDED]".to_string(),
                        size: pre_size,
                        original_bytes: String::new(),
                        patched_bytes: encoded_pre,
                        disassembly: Some(format!(
                            "Appended tail data past original EOF ({} bytes, entropy: {:.2})",
                            pre_size, pre_entropy
                        )),
                        category: PatchCategory::Unknown,
                    });
                }

                // Authenticode certificate table region
                let actual_cert_start = if cert_start > start && (cert_start - start) <= 8 {
                    start
                } else {
                    cert_start.max(start)
                };
                let cert_slice = &patched[actual_cert_start..cert_end];
                let cert_slice_size = cert_slice.len() as u64;
                let cert_entropy = crate::io::shannon_entropy(cert_slice);
                let encoded_cert = if cert_slice.len() > 64 {
                    format!("{} ... ({} bytes total)", hex_encode(&cert_slice[..64]), cert_slice_size)
                } else {
                    hex_encode(cert_slice)
                };
                regions.push(PatchRegion {
                    offset: actual_cert_start as u64,
                    section: "[AUTHENTICODE_SIGNATURE]".to_string(),
                    size: cert_slice_size,
                    original_bytes: String::new(),
                    patched_bytes: encoded_cert,
                    disassembly: Some(format!(
                        "Authenticode digital signature table ({} bytes at offset 0x{:X}, entropy: {:.2})",
                        cert_slice_size, actual_cert_start, cert_entropy
                    )),
                    category: PatchCategory::DigitalSignature,
                });

                // Post-certificate appended data (if any)
                if cert_end < patched.len() {
                    let post_slice = &patched[cert_end..];
                    let post_size = post_slice.len() as u64;
                    let post_entropy = crate::io::shannon_entropy(post_slice);
                    let encoded_post = if post_slice.len() > 64 {
                        format!("{} ... ({} bytes total)", hex_encode(&post_slice[..64]), post_size)
                    } else {
                        hex_encode(post_slice)
                    };
                    regions.push(PatchRegion {
                        offset: cert_end as u64,
                        section: "[EOF_APPENDED]".to_string(),
                        size: post_size,
                        original_bytes: String::new(),
                        patched_bytes: encoded_post,
                        disassembly: Some(format!(
                            "Appended tail data past Authenticode signature ({} bytes, entropy: {:.2})",
                            post_size, post_entropy
                        )),
                        category: PatchCategory::Unknown,
                    });
                }
            } else {
                let entropy = crate::io::shannon_entropy(patch_slice);
                let encoded_patch = if patch_slice.len() > 64 {
                    format!("{} ... ({} bytes total)", hex_encode(&patch_slice[..64]), total_size)
                } else {
                    hex_encode(patch_slice)
                };
                regions.push(PatchRegion {
                    offset: start as u64,
                    section: "[EOF_APPENDED]".to_string(),
                    size: total_size,
                    original_bytes: String::new(),
                    patched_bytes: encoded_patch,
                    disassembly: Some(format!(
                        "Appended tail data past original EOF ({} bytes, entropy: {:.2})",
                        total_size, entropy
                    )),
                    category: PatchCategory::Unknown,
                });
            }
        } else {
            let entropy = crate::io::shannon_entropy(patch_slice);
            let encoded_patch = if patch_slice.len() > 64 {
                format!("{} ... ({} bytes total)", hex_encode(&patch_slice[..64]), total_size)
            } else {
                hex_encode(patch_slice)
            };
            regions.push(PatchRegion {
                offset: start as u64,
                section: "[EOF_APPENDED]".to_string(),
                size: total_size,
                original_bytes: String::new(),
                patched_bytes: encoded_patch,
                disassembly: Some(format!(
                    "Appended tail data past original EOF ({} bytes, entropy: {:.2})",
                    total_size, entropy
                )),
                category: PatchCategory::Unknown,
            });
        }
    } else if orig.len() > min_len {
        let start = min_len;
        let orig_slice = &orig[start..];
        let size = orig_slice.len() as u64;

        let is_orig_cert = orig_pe
            .and_then(|p| p.security_directory)
            .map(|(offset, s)| s > 0 && offset >= start as u64)
            .unwrap_or(false);

        let section_name = if is_orig_cert {
            "[AUTHENTICODE_STRIPPED]".to_string()
        } else {
            "[EOF_TRUNCATED]".to_string()
        };

        let disasm = if is_orig_cert {
            format!("Original Authenticode digital signature stripped ({} bytes)", size)
        } else {
            format!("Truncated tail data past patched EOF ({} bytes removed)", size)
        };

        let encoded_orig = if orig_slice.len() > 64 {
            format!("{} ... ({} bytes total)", hex_encode(&orig_slice[..64]), size)
        } else {
            hex_encode(orig_slice)
        };

        regions.push(PatchRegion {
            offset: start as u64,
            section: section_name,
            size,
            original_bytes: encoded_orig,
            patched_bytes: String::new(),
            disassembly: Some(disasm),
            category: PatchCategory::Unknown,
        });
    }

    regions
}

/// Decodes instructions using iced-x86 and determines whether the modification is a DRM bypass.
fn classify_patch_bytes(
    orig: &[u8],
    patched: &[u8],
    start: usize,
    patch_end: usize,
    rip: u64,
    is_64bit: bool,
    section_bounds: Option<(u64, u64)>,
) -> (Option<String>, PatchCategory) {
    let bitness = if is_64bit { 64 } else { 32 };
    let patch_bytes = &patched[start..patch_end];

    // 1. Check for NOP padding (e.g. 0x90)
    let is_all_nops = patch_bytes.iter().all(|&b| b == 0x90);
    if is_all_nops && !patch_bytes.is_empty() {
        let disasm = format!("Replaced {} bytes with NOP padding", patch_bytes.len());
        return (Some(disasm), PatchCategory::DrmBypass);
    }

    // Decode instructions with context (up to 16 bytes from start)
    let orig_ctx = &orig[start..orig.len().min(start + 16)];
    let patch_ctx = &patched[start..patched.len().min(start + 16)];

    let mut orig_decoder = Decoder::with_ip(bitness, orig_ctx, rip, DecoderOptions::NONE);
    let mut orig_instructions = Vec::new();
    while orig_decoder.can_decode() {
        let mut instr = Instruction::default();
        orig_decoder.decode_out(&mut instr);
        orig_instructions.push(instr);
    }

    let mut patch_decoder = Decoder::with_ip(bitness, patch_ctx, rip, DecoderOptions::NONE);
    let mut patch_instructions = Vec::new();
    while patch_decoder.can_decode() {
        let mut instr = Instruction::default();
        patch_decoder.decode_out(&mut instr);
        patch_instructions.push(instr);
    }

    // 2. Check for code injection branch (JMP / CALL to outside section or distant memory, or indirect control flow)
    // CRITICAL: Must be evaluated BEFORE local branch checks so JZ -> JMP(distant) cannot whitewash as DRM_BYPASS.
    if let Some(patch_first) = patch_instructions.first() {
        if patch_first.flow_control() == FlowControl::IndirectBranch
            || patch_first.flow_control() == FlowControl::IndirectCall
        {
            let disasm = format!("Indirect control flow hijack: {:?}", patch_first.mnemonic());
            return (Some(disasm), PatchCategory::CodeInjection);
        }

        if patch_first.flow_control() == FlowControl::UnconditionalBranch
            || patch_first.flow_control() == FlowControl::Call
        {
            let target = patch_first.near_branch_target();
            if let Some((sec_start, sec_end)) = section_bounds {
                if target < sec_start || target >= sec_end {
                    let disasm = format!(
                        "Branch outside code section bounds [0x{:X}..0x{:X}]: {:?} to 0x{:X}",
                        sec_start, sec_end, patch_first.mnemonic(), target
                    );
                    return (Some(disasm), PatchCategory::CodeInjection);
                }
            } else if target.abs_diff(rip) > 0x100000 {
                let disasm = format!("Distant branch outside code bounds: {:?} 0x{:X}", patch_first.mnemonic(), target);
                return (Some(disasm), PatchCategory::CodeInjection);
            }
        }
    }

    // 3. 16-byte limit check: Non-NOP patches exceeding 16 bytes cannot be assumed benign DRM bypasses
    if patch_bytes.len() > 16 {
        let disasm = format!("Large patch region ({} bytes altered, exceeds 16-byte DRM template limit)", patch_bytes.len());
        return (Some(disasm), PatchCategory::Unknown);
    }

    // 4. Check for local conditional jump modification (JZ -> JNZ, JZ -> JMP within section)
    if let (Some(orig_first), Some(patch_first)) = (orig_instructions.first(), patch_instructions.first()) {
        let orig_is_jcc = orig_first.is_jcc_short_or_near();
        let patch_is_jcc = patch_first.is_jcc_short_or_near();
        let patch_is_jmp = patch_first.mnemonic() == Mnemonic::Jmp
            && patch_first.flow_control() == FlowControl::UnconditionalBranch;

        if orig_is_jcc && (patch_is_jmp || patch_is_jcc) {
            let is_valid_drm_target = if patch_is_jmp {
                let orig_target = orig_first.near_branch_target();
                let patch_target = patch_first.near_branch_target();
                patch_target == orig_target || patch_target.abs_diff(rip) <= 32
            } else {
                true
            };

            if is_valid_drm_target {
                let disasm = format!(
                    "{:?} → {:?}",
                    orig_first.mnemonic(),
                    patch_first.mnemonic()
                );
                return (Some(disasm), PatchCategory::DrmBypass);
            } else {
                let disasm = format!(
                    "Intrasection hook: {:?} redirected to 0x{:X} (code cave)",
                    patch_first.mnemonic(),
                    patch_first.near_branch_target()
                );
                return (Some(disasm), PatchCategory::CodeInjection);
            }
        }

        // 5. Check for return value forcing: exact XOR reg, reg / MOV reg, 0/1 followed by RET, or immediate RET
        let is_ret_override = if patch_instructions.len() >= 2 {
            let first = &patch_instructions[0];
            let second = &patch_instructions[1];
            let is_xor_self = first.mnemonic() == Mnemonic::Xor && first.op0_register() == first.op1_register();
            let is_mov_const = first.mnemonic() == Mnemonic::Mov;
            (is_xor_self || is_mov_const) && second.mnemonic() == Mnemonic::Ret
        } else if patch_instructions.len() == 1 {
            patch_instructions[0].mnemonic() == Mnemonic::Ret
        } else {
            false
        };

        if is_ret_override {
            let disasm = "Forced return success (XOR reg, reg / RET)".to_string();
            return (Some(disasm), PatchCategory::DrmBypass);
        }
    }

    // 6. Check single instruction immediate value alteration (e.g. license check CMP/TEST/MOV operand 0 -> 1)
    if patch_bytes.len() <= 4 {
        if let (Some(orig_first), Some(patch_first)) = (orig_instructions.first(), patch_instructions.first()) {
            let has_imm = is_immediate_op(patch_first.op0_kind())
                || is_immediate_op(patch_first.op1_kind());

            if orig_first.mnemonic() == patch_first.mnemonic()
                && has_imm
                && matches!(patch_first.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Mov)
            {
                let disasm = format!(
                    "Immediate operand alteration: {:?} ({} bytes)",
                    patch_first.mnemonic(),
                    patch_bytes.len()
                );
                return (Some(disasm), PatchCategory::DrmBypass);
            }
        }

        // If forward decoding didn't yield CMP/TEST/MOV immediate, check backwards up to 4 bytes for enclosing instruction
        let patch_len = patch_bytes.len();
        for back in 1..=4 {
            if start >= back {
                let back_start = start - back;
                let back_rva = rip.saturating_sub(back as u64);
                let back_orig_ctx = &orig[back_start..orig.len().min(back_start + 16)];
                let back_patch_ctx = &patched[back_start..patched.len().min(back_start + 16)];

                let mut b_orig_dec = Decoder::with_ip(bitness, back_orig_ctx, back_rva, DecoderOptions::NONE);
                let mut b_patch_dec = Decoder::with_ip(bitness, back_patch_ctx, back_rva, DecoderOptions::NONE);

                let mut b_orig_instr = Instruction::default();
                let mut b_patch_instr = Instruction::default();

                if b_orig_dec.can_decode() && b_patch_dec.can_decode() {
                    b_orig_dec.decode_out(&mut b_orig_instr);
                    b_patch_dec.decode_out(&mut b_patch_instr);

                    // Ensure this instruction spans across the ENTIRE patch region
                    let has_imm = is_immediate_op(b_patch_instr.op0_kind())
                        || is_immediate_op(b_patch_instr.op1_kind());

                    if b_orig_instr.len() >= back + patch_len
                        && b_patch_instr.len() >= back + patch_len
                        && b_orig_instr.len() == b_patch_instr.len()
                        && b_orig_instr.mnemonic() == b_patch_instr.mnemonic()
                        && has_imm
                        && matches!(b_patch_instr.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Mov)
                    {
                        let disasm = format!(
                            "Immediate operand alteration in {:?} (offset -{} from opcode)",
                            b_patch_instr.mnemonic(),
                            back
                        );
                        return (Some(disasm), PatchCategory::DrmBypass);
                    }
                }
            }
        }

        let disasm = format!("Unverified short modification ({} bytes altered)", patch_bytes.len());
        return (Some(disasm), PatchCategory::Unknown);
    }

    (None, PatchCategory::Unknown)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

fn is_immediate_op(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_nop_patch_as_drm_bypass() {
        // Original: CMP EAX, 0; JZ +5 (83 F8 00 74 05)
        let orig = b"\x83\xF8\x00\x74\x05";
        // Patched: NOP NOP NOP NOP NOP (90 90 90 90 90)
        let patch = b"\x90\x90\x90\x90\x90";

        let (disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, None);
        assert_eq!(category, PatchCategory::DrmBypass);
        assert!(disasm.unwrap().contains("NOP"));
    }

    #[test]
    fn test_classify_jcc_to_jmp_as_drm_bypass() {
        // Original: JZ +10 (74 0A)
        let orig = b"\x74\x0A";
        // Patched: JMP +10 (EB 0A)
        let patch = b"\xEB\x0A";

        let (disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, None);
        assert_eq!(category, PatchCategory::DrmBypass);
        let text = disasm.unwrap();
        assert!(text.contains("Jmp") && (text.contains("Je") || text.contains("Jz")));
    }

    #[test]
    fn test_classify_distant_jump_as_code_injection() {
        // Patched with a JMP to 0x5000000 (distant address): E9 F5 FF FF 04
        let orig = b"\x55\x48\x89\xE5\x90";
        // JMP 0x05001005 (far away)
        let patch = b"\xE9\x00\x00\x50\x04";

        let (_disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, None);
        assert_eq!(category, PatchCategory::CodeInjection);
    }

    #[test]
    fn test_classify_jump_outside_section_as_code_injection() {
        let orig = b"\x55\x48\x89\xE5\x90";
        // Relative jump to 0x3005 which is outside [0x1000..0x2000]
        let patch = b"\xE9\x00\x20\x00\x00";

        let (_disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::CodeInjection);
    }

    #[test]
    fn test_classify_large_patch_as_unknown() {
        let orig = &[0xAA; 24];
        let patch = &[0xBB; 24];

        let (_disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::Unknown);
    }

    #[test]
    fn test_classify_xor_eax_ret_as_drm_bypass() {
        // XOR EAX, EAX (31 C0); RET (C3)
        let orig = b"\x83\xF8\x00\x74\x05";
        let patch = b"\x31\xC0\xC3";

        let (disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::DrmBypass);
        assert!(disasm.unwrap().contains("Forced return success"));
    }

    #[test]
    fn test_classify_jcc_to_distant_jump_as_code_injection() {
        // Original: JZ +10 (74 0A)
        let orig = b"\x74\x0A";
        // Patched: Far JMP outside section bounds (E9 00 00 50 04)
        let patch = b"\xE9\x00\x00\x50\x04";

        let (_disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::CodeInjection, "Distant jump must not be classified as DRM bypass even if original was JCC");
    }

    #[test]
    fn test_unverified_4byte_modification_is_unknown() {
        let orig = b"\x90\x90\x90\x90";
        // Patched: INT 3 breakpoint traps or arbitrary bytes
        let patch = b"\xCC\xCC\xCC\xCC";

        let (_disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::Unknown, "Arbitrary 4-byte alterations must not be blindly treated as DRM bypass");
    }

    #[test]
    fn test_unknown_patch_not_whitewashed_by_drm_bypass() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        // Construct two binaries: both have a valid DRM bypass (74 0A -> EB 0A) AND an unknown large patch (24 bytes)
        let mut orig_bytes = vec![0x90; 256];
        let mut patch_bytes = vec![0x90; 256];

        // DRM bypass at offset 16
        orig_bytes[16..18].copy_from_slice(b"\x74\x0A");
        patch_bytes[16..18].copy_from_slice(b"\xEB\x0A");

        // Unknown patch at offset 100
        orig_bytes[100..124].copy_from_slice(&[0xAA; 24]);
        patch_bytes[100..124].copy_from_slice(&[0xBB; 24]);

        let mut orig_file = NamedTempFile::new().unwrap();
        orig_file.write_all(&orig_bytes).unwrap();

        let mut patch_file = NamedTempFile::new().unwrap();
        patch_file.write_all(&patch_bytes).unwrap();

        let report = diff_binaries(orig_file.path(), patch_file.path()).unwrap();
        assert_eq!(
            report.verdict,
            Tier::Suspicious,
            "A DRM bypass must NOT whitewash unverified unknown patches"
        );
        assert!(report.verdict_summary.contains("Mixed patch semantics"));
    }

    #[test]
    fn test_appended_tail_payload_detected_as_suspicious() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let orig_bytes = vec![0x90; 128];
        let mut patch_bytes = vec![0x90; 128];

        // Append 32 bytes past EOF
        let appended_payload = vec![0x90; 32];
        patch_bytes.extend_from_slice(&appended_payload);

        let mut orig_file = NamedTempFile::new().unwrap();
        orig_file.write_all(&orig_bytes).unwrap();

        let mut patch_file = NamedTempFile::new().unwrap();
        patch_file.write_all(&patch_bytes).unwrap();

        let report = diff_binaries(orig_file.path(), patch_file.path()).unwrap();
        assert_eq!(report.verdict, Tier::Suspicious, "Appended tail bytes must yield Suspicious tier, avoiding false positive HighRisk");
        let tail_patch = report.patches.iter().find(|p| p.section == "[EOF_APPENDED]");
        assert!(tail_patch.is_some(), "Must detect appended tail patch region");
        assert_eq!(tail_patch.unwrap().category, PatchCategory::Unknown);
    }

    #[test]
    fn test_classify_indirect_jump_as_code_injection() {
        // Original: JZ +10 (74 0A)
        let orig = b"\x74\x0A";
        // Patched: JMP RAX (FF E0) - indirect control flow hijack
        let patch = b"\xFF\xE0";

        let (disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::CodeInjection, "Indirect jumps must be classified as CodeInjection");
        assert!(disasm.unwrap().contains("Indirect control flow hijack"));
    }

    #[test]
    fn test_classify_intrasection_code_cave_jump_as_code_injection() {
        // Original: JZ +10 (74 0A) - near target is rip + 2 + 10 = 0x100C
        let orig = b"\x74\x0A";
        // Patched: JMP +0x500 within same section (E9 FB 04 00 00) - jumps to 0x1500 (code cave)
        let patch = b"\xE9\xFB\x04\x00\x00";

        let (disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::CodeInjection, "Intrasection redirect to code cave must be classified as CodeInjection");
        assert!(disasm.unwrap().contains("Intrasection hook"));
    }

    #[test]
    fn test_mov_register_swap_not_classified_as_drm_bypass() {
        // Original: MOV EAX, ECX (89 C8)
        let orig = b"\x89\xC8";
        // Patched: MOV EAX, EDX (89 D0) - register alteration without immediate operand
        let patch = b"\x89\xD0";

        let (_disasm, category) = classify_patch_bytes(orig, patch, 0, patch.len(), 0x1000, true, Some((0x1000, 0x2000)));
        assert_eq!(category, PatchCategory::Unknown, "Register-altering MOV must not be classified as DRM bypass");
    }

    #[test]
    fn test_high_entropy_tail_payload_detected_as_suspicious() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let orig_bytes = vec![0x90; 128];
        let mut patch_bytes = vec![0x90; 128];

        // Append 64 bytes of pseudo-random bytes
        let mut high_entropy_payload = Vec::with_capacity(64);
        for i in 0..64u8 {
            high_entropy_payload.push(i.wrapping_mul(73).wrapping_add(19));
        }
        patch_bytes.extend_from_slice(&high_entropy_payload);

        let mut orig_file = NamedTempFile::new().unwrap();
        orig_file.write_all(&orig_bytes).unwrap();

        let mut patch_file = NamedTempFile::new().unwrap();
        patch_file.write_all(&patch_bytes).unwrap();

        let report = diff_binaries(orig_file.path(), patch_file.path()).unwrap();
        assert_eq!(report.verdict, Tier::Suspicious);
        let tail_patch = report.patches.iter().find(|p| p.section == "[EOF_APPENDED]");
        assert!(tail_patch.is_some(), "Must detect appended tail patch region");
        assert_eq!(tail_patch.unwrap().category, PatchCategory::Unknown);
        assert!(tail_patch.unwrap().disassembly.as_ref().unwrap().contains("entropy"));
    }

    #[test]
    fn test_appended_authenticode_signature_classified_as_digital_signature() {
        use tempfile::NamedTempFile;
        use std::io::Write;
        use crate::lab::create_minimal_pe;

        // Create a valid original minimal PE
        let orig_bytes = create_minimal_pe(".text", b"\x90\x90\x90\x90\xC3NormalFunction");
        let mut patch_bytes = orig_bytes.clone();

        let cert_offset = orig_bytes.len() as u32;
        let cert_size = 64u32;

        // Set Optional Header DataDirectory[4] (Security Directory) in patch_bytes
        // Offset 0x128 is DataDirectory[4] VirtualAddress (raw file offset), 0x12C is Size
        patch_bytes[0x128..0x12C].copy_from_slice(&cert_offset.to_le_bytes());
        patch_bytes[0x12C..0x130].copy_from_slice(&cert_size.to_le_bytes());

        // Append 64 bytes of mock Authenticode WIN_CERTIFICATE data
        let mut mock_cert = vec![0x30; cert_size as usize]; // 0x30 is standard ASN.1 SEQUENCE start
        mock_cert[0..4].copy_from_slice(&(cert_size).to_le_bytes()); // dwLength
        mock_cert[4..6].copy_from_slice(&0x0200u16.to_le_bytes()); // wRevision = WIN_CERT_REVISION_2_0
        mock_cert[6..8].copy_from_slice(&0x0002u16.to_le_bytes()); // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        patch_bytes.extend_from_slice(&mock_cert);

        let mut orig_file = NamedTempFile::new().unwrap();
        orig_file.write_all(&orig_bytes).unwrap();

        let mut patch_file = NamedTempFile::new().unwrap();
        patch_file.write_all(&patch_bytes).unwrap();

        let report = diff_binaries(orig_file.path(), patch_file.path()).unwrap();
        assert_eq!(
            report.verdict,
            Tier::NoIndicatorsFound,
            "Appended Authenticode digital signature must NOT trigger false positive Suspicious or HighRisk"
        );

        let sig_patch = report.patches.iter().find(|p| p.section == "[AUTHENTICODE_SIGNATURE]");
        assert!(sig_patch.is_some(), "Must detect Authenticode signature section");
        let sig = sig_patch.unwrap();
        assert_eq!(sig.category, PatchCategory::DigitalSignature);
        assert_eq!(sig.offset, cert_offset as u64);
        assert_eq!(sig.size, cert_size as u64);
        assert!(sig.disassembly.as_ref().unwrap().contains("Authenticode digital signature table"));
    }

    #[test]
    fn test_appended_authenticode_signature_plus_drm_bypass_verdict() {
        use tempfile::NamedTempFile;
        use std::io::Write;
        use crate::lab::create_minimal_pe;

        // Original binary with conditional branch JZ +10 (74 0A) in .text
        let orig_bytes = create_minimal_pe(".text", b"\x74\x0A\x90\x90\x90\xC3NormalFunction");
        let mut patch_bytes = orig_bytes.clone();

        // 1. DRM bypass: JZ -> JMP (74 0A -> EB 0A) inside .text section (raw offset 0x200)
        patch_bytes[0x200..0x202].copy_from_slice(b"\xEB\x0A");

        // 2. Authenticode certificate table appended at EOF
        let cert_offset = orig_bytes.len() as u32;
        let cert_size = 64u32;
        patch_bytes[0x128..0x12C].copy_from_slice(&cert_offset.to_le_bytes());
        patch_bytes[0x12C..0x130].copy_from_slice(&cert_size.to_le_bytes());

        let mut mock_cert = vec![0x30; cert_size as usize];
        mock_cert[0..4].copy_from_slice(&cert_size.to_le_bytes());
        mock_cert[4..6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
        mock_cert[6..8].copy_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        patch_bytes.extend_from_slice(&mock_cert);

        let mut orig_file = NamedTempFile::new().unwrap();
        orig_file.write_all(&orig_bytes).unwrap();

        let mut patch_file = NamedTempFile::new().unwrap();
        patch_file.write_all(&patch_bytes).unwrap();

        let report = diff_binaries(orig_file.path(), patch_file.path()).unwrap();
        assert_eq!(
            report.verdict,
            Tier::NoIndicatorsFound,
            "DRM bypass combined with Authenticode signature must evaluate to NO INDICATORS FOUND"
        );
        assert!(
            report.patches.iter().any(|p| p.category == PatchCategory::DrmBypass),
            "Must detect DRM bypass"
        );
        assert!(
            report.patches.iter().any(|p| p.category == PatchCategory::DigitalSignature),
            "Must detect DigitalSignature"
        );
    }
}
