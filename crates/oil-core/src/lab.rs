//! # Oil Lab — Synthetic Test Fixtures Generator & Benchmark Runner
//!
//! GDD §6 & §10 — Generates safe synthetic mock PEs in-memory
//! to validate all 4 forensic tiers without requiring live malware samples.



/// Crafts a minimal, valid x64 PE executable byte buffer.
pub fn create_minimal_pe(section_name: &str, payload: &[u8]) -> Vec<u8> {
    let mut pe = Vec::new();

    // ──────────────────────────────────────────────
    // 1. DOS Header (64 bytes)
    // ──────────────────────────────────────────────
    pe.extend_from_slice(b"MZ"); // e_magic
    pe.resize(0x3C, 0); // pad to e_lfanew offset
    pe.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew -> 0x80
    pe.resize(0x80, 0); // pad DOS stub up to 0x80

    // ──────────────────────────────────────────────
    // 2. PE Signature (4 bytes)
    // ──────────────────────────────────────────────
    pe.extend_from_slice(b"PE\0\0");

    // ──────────────────────────────────────────────
    // 3. File Header (20 bytes)
    // ──────────────────────────────────────────────
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: x86_64
    pe.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
    pe.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    pe.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    pe.extend_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader (240 bytes for PE32+)
    pe.extend_from_slice(&0x0022u16.to_le_bytes()); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // ──────────────────────────────────────────────
    // 4. Optional Header (PE32+ 240 bytes)
    // ──────────────────────────────────────────────
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic: PE32+ (64-bit)
    pe.extend_from_slice(&[1, 0]); // Linker version
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfCode
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    pe.extend_from_slice(&0x00400000u64.to_le_bytes()); // ImageBase
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    pe.extend_from_slice(&[6, 0, 0, 0]); // OS Version
    pe.extend_from_slice(&[0, 0, 0, 0]); // Image Version
    pe.extend_from_slice(&[6, 0, 0, 0]); // Subsystem Version
    pe.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    pe.extend_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    pe.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    pe.extend_from_slice(&3u16.to_le_bytes()); // Subsystem: Windows CUI (Console)
    pe.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfStackReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfStackCommit
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfHeapReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfHeapCommit
    pe.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    pe.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // 16 Data Directories (8 bytes each = 128 bytes of zeros)
    pe.resize(pe.len() + 128, 0);

    // ──────────────────────────────────────────────
    // 5. Section Header (40 bytes)
    // ──────────────────────────────────────────────
    let mut sec_name = [0u8; 8];
    for (i, b) in section_name.as_bytes().iter().take(8).enumerate() {
        sec_name[i] = *b;
    }
    pe.extend_from_slice(&sec_name); // Name
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    let raw_size = ((payload.len() + 0x1FF) / 0x200 * 0x200).max(0x200) as u32;
    pe.extend_from_slice(&raw_size.to_le_bytes()); // SizeOfRawData
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    pe.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
    pe.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics: CODE | EXECUTE | READ

    // Pad headers to FileAlignment (0x200 = 512 bytes)
    pe.resize(0x200, 0);

    // ──────────────────────────────────────────────
    // 6. Section Data
    // ──────────────────────────────────────────────
    pe.extend_from_slice(payload);
    // Pad section data to FileAlignment
    pe.resize(0x200 + raw_size as usize, 0);

    pe
}

fn decode_fixture(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|&b| b ^ 0xAA).collect()
}

/// Generates the bench_clean synthetic binary.
pub fn generate_bench_clean() -> Vec<u8> {
    create_minimal_pe(".text", b"\x90\x90\x90\xC3Hello Clean Game World")
}

/// Generates the bench_stealer synthetic binary (Discord webhook + Chrome path).
pub fn generate_bench_stealer() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x90\x90\x90\xC3");
    payload.extend_from_slice(&decode_fixture(b"\xc2\xde\xde\xda\xd9\x90\x85\x85\xce\xc3\xd9\xc9\xc5\xd8\xce\x84\xc9\xc5\xc7\x85\xcb\xda\xc3\x85\xdd\xcf\xc8\xc2\xc5\xc5\xc1\xd9\x85\x9b\x9b\x92\x98\x99\x9d\x9e\x93\x98\x92\x99\x9d\x9e\x93\x85\xd9\xcb\xc7\xda\xc6\xcf\xf5\xcc\xcb\xc1\xcf\xf5\xde\xc5\xc1\xcf\xc4\xf5\x9b\x98\x99\x9e\x9f"));
    payload.extend_from_slice(b"\0\0");
    payload.extend_from_slice(&decode_fixture(b"\xeb\xda\xda\xee\xcb\xde\xcb\xf6\xe6\xc5\xc9\xcb\xc6\xf6\xed\xc5\xc5\xcd\xc6\xcf\xf6\xe9\xc2\xd8\xc5\xc7\xcf\xf6\xff\xd9\xcf\xd8\x8a\xee\xcb\xde\xcb\xf6\xee\xcf\xcc\xcb\xdf\xc6\xde\xf6\xe6\xc5\xcd\xc3\xc4\x8a\xee\xcb\xde\xcb"));
    create_minimal_pe(".text", &payload)
}

/// Generates the bench_single_ioc synthetic binary (isolated webhook only -> SUSPICIOUS).
pub fn generate_bench_single_ioc() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x90\x90\x90\xC3");
    payload.extend_from_slice(&decode_fixture(b"\xc2\xde\xde\xda\xd9\x90\x85\x85\xce\xc3\xd9\xc9\xc5\xd8\xce\x84\xc9\xc5\xc7\x85\xcb\xda\xc3\x85\xdd\xcf\xc8\xc2\xc5\xc5\xc1\xd9\x85\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x85\xc3\xd9\xc5\xc6\xcb\xde\xcf\xce\xf5\xc2\xc5\xc5\xc1"));
    create_minimal_pe(".text", &payload)
}

/// Generates the bench_entropy synthetic binary (pseudo-random bytes -> entropy > 7.8).
pub fn generate_bench_entropy() -> Vec<u8> {
    let mut payload = Vec::with_capacity(1024);
    // Linear congruential generator for high entropy pseudo-randomness
    let mut state: u32 = 123456789;
    for _ in 0..1024 {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        payload.push((state >> 24) as u8);
    }
    create_minimal_pe(".pack", &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goblin_parse() {
        let bytes = generate_bench_clean();
        let res = goblin::pe::PE::parse(&bytes);
        println!("Goblin parse result: {:?}", res);
        assert!(res.is_ok());
    }
}
