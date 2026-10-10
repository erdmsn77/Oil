//! # Hybrid File I/O & Dual Hashing
//!
//! GDD §3.1 — Stage 0: Hybrid I/O
//! - Files < 1 MB: heap read (`std::fs::read`)
//! - Files > 1 MB: memory-mapped read (`memmap2`)
//! - Dual hashing: SHA-256 (VirusTotal compat) + BLAKE3 (speed)

use crate::models::FileIdentity;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use thiserror::Error;

/// Threshold: files smaller than this are read into heap memory.
/// Files larger are memory-mapped for zero-copy access.
const MMAP_THRESHOLD: u64 = 1_048_576; // 1 MB

#[derive(Error, Debug)]
pub enum IoError {
    #[error("File not found: {0}")]
    NotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("I/O error reading {path}: {source}")]
    ReadError {
        path: String,
        source: io::Error,
    },
    #[error("File is empty: {0}")]
    EmptyFile(String),
}

/// The raw bytes of a file, either owned (heap) or borrowed (mmap).
/// This enum lets us return a uniform `&[u8]` slice regardless of strategy.
pub enum FileData {
    /// Small file: owned Vec on the heap.
    Heap(Vec<u8>),
    /// Large file: memory-mapped, zero-copy.
    Mapped(Mmap),
}

impl FileData {
    /// Get a byte slice of the file contents.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            FileData::Heap(v) => v.as_slice(),
            FileData::Mapped(m) => m.as_ref(),
        }
    }

    /// File size in bytes.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Is the file empty?
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

/// Read a file using the hybrid strategy (heap for small, mmap for large).
pub fn read_file(path: &Path) -> Result<FileData, IoError> {
    let metadata = fs::metadata(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => IoError::NotFound(path.display().to_string()),
        io::ErrorKind::PermissionDenied => {
            IoError::PermissionDenied(path.display().to_string())
        }
        _ => IoError::ReadError {
            path: path.display().to_string(),
            source: e,
        },
    })?;

    let size = metadata.len();

    if size == 0 {
        return Err(IoError::EmptyFile(path.display().to_string()));
    }

    if size < MMAP_THRESHOLD {
        // Small file: read into heap
        let data = fs::read(path).map_err(|e| IoError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(FileData::Heap(data))
    } else {
        // Large file: memory-map
        let file = File::open(path).map_err(|e| IoError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;
        // SAFETY: We only read the file; we never write.
        // Risk: if another process truncates the file while mapped,
        // we could get a SIGBUS/access violation. This is acceptable
        // for a read-only forensic tool scanning local files.
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| IoError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(FileData::Mapped(mmap))
    }
}

/// Compute SHA-256 and BLAKE3 hashes of a byte slice.
/// Returns (sha256_hex, blake3_hex).
pub fn dual_hash(data: &[u8]) -> (String, String) {
    // SHA-256 (VirusTotal / MalwareBazaar compatibility)
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    };

    // BLAKE3 (speed — cryptographic, 4x faster than SHA-256)
    let b3 = blake3::hash(data).to_hex().to_string();

    (sha256, b3)
}

/// Compute dual hashes directly from a file on disk.
/// Returns (sha256_hex, blake3_hex).
pub fn dual_hash_file(path: &Path) -> Result<(String, String), IoError> {
    let data = read_file(path)?;
    Ok(dual_hash(data.as_bytes()))
}

/// Build a `FileIdentity` from a file path.
/// Reads the file and computes dual hashes.
pub fn identify_file(path: &Path) -> Result<(FileIdentity, FileData), IoError> {
    let data = read_file(path)?;
    let (sha256, blake3) = dual_hash(data.as_bytes());

    let identity = FileIdentity {
        path: path.to_path_buf(),
        size_bytes: data.len() as u64,
        sha256,
        blake3,
    };

    Ok((identity, data))
}

/// Compute Shannon entropy of a byte slice.
/// Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly random).
/// Used in PE Autopsy to detect packed/encrypted sections.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_dual_hash_known_value() {
        // SHA-256 of "hello" is well-known
        let data = b"hello";
        let (sha, b3) = dual_hash(data);
        assert_eq!(
            sha,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(!b3.is_empty());
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All zeros → entropy 0.0
        let data = vec![0u8; 1024];
        let e = shannon_entropy(&data);
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_random() {
        // All 256 byte values equally → entropy ≈ 8.0
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(e > 7.99, "Entropy of uniform distribution should be ~8.0, got {e}");
    }

    #[test]
    fn test_read_small_file() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"small file content").unwrap();
        let data = read_file(f.path()).unwrap();
        assert!(matches!(data, FileData::Heap(_)));
        assert_eq!(data.as_bytes(), b"small file content");
    }

    #[test]
    fn test_identify_file() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"test content for identity").unwrap();
        let (identity, data) = identify_file(f.path()).unwrap();
        assert_eq!(identity.size_bytes, 25);
        assert!(!identity.sha256.is_empty());
        assert!(!identity.blake3.is_empty());
        assert_eq!(data.len(), 25);
    }

    #[test]
    fn test_empty_file_error() {
        let f = NamedTempFile::new().unwrap();
        // File is empty (0 bytes)
        let result = read_file(f.path());
        assert!(result.is_err());
    }
}
