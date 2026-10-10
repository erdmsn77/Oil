//! # Native Windows Authenticode Signature Verification via WinVerifyTrust
//!
//! Provides cryptographic validation of Authenticode signatures using the Windows Trust Provider.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TrustStatus {
    /// Cryptographically verified against a trusted Windows root CA.
    Valid,
    /// Signed by an untrusted or self-signed root certificate.
    UntrustedRoot,
    /// Binary contents modified/tampered after signing (hash digest mismatch).
    BadDigest,
    /// Explicitly revoked or distrusted certificate.
    Distrusted,
    /// Binary is not signed (no embedded Authenticode structure).
    NotSigned,
    /// Verification failed with system error code.
    Failed(i32),
    /// Non-Windows platform or offline mode.
    Unsupported,
}

#[cfg(windows)]
pub fn verify_authenticode(path: &Path) -> TrustStatus {
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    struct GUID {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_STATEACTION_IGNORE: u32 = 0;
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;

    #[repr(C)]
    struct WINTRUST_FILE_INFO {
        cb_struct: u32,
        pcwsz_file_path: *const u16,
        h_file: *mut std::ffi::c_void,
        pg_known_subject: *const GUID,
    }

    #[repr(C)]
    struct WINTRUST_DATA {
        cb_struct: u32,
        p_policy_callback_data: *mut std::ffi::c_void,
        p_sip_client_data: *mut std::ffi::c_void,
        dw_ui_choice: u32,
        fdw_revocation_checks: u32,
        dw_union_choice: u32,
        p_file: *mut WINTRUST_FILE_INFO,
        dw_state_action: u32,
        h_wvt_state_data: *mut std::ffi::c_void,
        pwsz_url_reference: *mut u16,
        dw_prov_flags: u32,
        dw_ui_context: u32,
        p_signature_settings: *mut std::ffi::c_void,
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(
            hwnd: *mut std::ffi::c_void,
            pg_action_id: *const GUID,
            p_wvt_data: *mut WINTRUST_DATA,
        ) -> i32;
    }

    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide_path.push(0);

    let mut file_info = WINTRUST_FILE_INFO {
        cb_struct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwsz_file_path: wide_path.as_ptr(),
        h_file: std::ptr::null_mut(),
        pg_known_subject: std::ptr::null(),
    };

    let mut trust_data = WINTRUST_DATA {
        cb_struct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        p_policy_callback_data: std::ptr::null_mut(),
        p_sip_client_data: std::ptr::null_mut(),
        dw_ui_choice: WTD_UI_NONE,
        fdw_revocation_checks: WTD_REVOKE_NONE,
        dw_union_choice: WTD_CHOICE_FILE,
        p_file: &mut file_info,
        dw_state_action: WTD_STATEACTION_IGNORE,
        h_wvt_state_data: std::ptr::null_mut(),
        pwsz_url_reference: std::ptr::null_mut(),
        dw_prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dw_ui_context: 0,
        p_signature_settings: std::ptr::null_mut(),
    };

    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data,
        )
    };

    match status as u32 {
        0 => TrustStatus::Valid,
        0x800B_0100 => TrustStatus::NotSigned,       // TRUST_E_NOSIGNATURE
        0x800B_0004 => TrustStatus::BadDigest,       // TRUST_E_BAD_DIGEST
        0x800B_0109 => TrustStatus::UntrustedRoot,   // CERT_E_UNTRUSTEDROOT
        0x800B_0111 => TrustStatus::Distrusted,      // TRUST_E_EXPLICIT_DISTRUST
        _ => TrustStatus::Failed(status),
    }
}

#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path) -> TrustStatus {
    TrustStatus::Unsupported
}
