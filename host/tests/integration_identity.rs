//! Identity and boot status integration tests — TSR-IVG-01, CG-01.
//!
//! Tests device identity verification (BootStatus), and certificate
//! validity checking.

use scorehsm_host::{
    backend::sw::SoftwareBackend, backend::HsmBackend, error::HsmError, types::BootStatus,
};

// ── TSR-IVG-01: Device Identity ────────────────────────────────────────────

/// ITP-IVG-01-a: Software backend reports unverified boot status.
#[test]
fn itp_identity_sw_backend_not_verified() {
    let b = SoftwareBackend::new();
    let status = b.boot_status().unwrap();
    assert!(!status.verified, "software backend has no secure boot");
    assert_eq!(status.firmware_version, 0);
}

/// ITP-IVG-01-b: BootStatus fields are accessible and correct types.
#[test]
fn itp_identity_boot_status_fields() {
    let status = BootStatus {
        verified: true,
        firmware_version: 42,
    };
    assert!(status.verified);
    assert_eq!(status.firmware_version, 42);
}

/// ITP-IVG-01-c: DeviceIdentityChanged error variant exists and formats correctly.
#[test]
fn itp_identity_changed_error() {
    let err = HsmError::DeviceIdentityChanged;
    let msg = format!("{err}");
    assert!(msg.contains("identity changed"), "error message: {msg}");
}

/// ITP-IVG-01-d: HardwareFault error variant exists.
#[test]
fn itp_identity_hardware_fault_error() {
    let err = HsmError::HardwareFault;
    let msg = format!("{err}");
    assert!(msg.contains("hardware fault"), "error message: {msg}");
}

// ── CG-01: Certificate Validity (compile-time gate for cert feature) ───────

/// ITP-CG-01-a: CertificateExpired error variant exists and formats correctly.
#[test]
fn itp_cert_expired_error() {
    let err = HsmError::CertificateExpired;
    let msg = format!("{err}");
    assert!(msg.contains("expired"), "error message: {msg}");
}

/// ITP-CG-01-b: CertificateNotYetValid error variant exists.
#[test]
fn itp_cert_not_yet_valid_error() {
    let err = HsmError::CertificateNotYetValid;
    let msg = format!("{err}");
    assert!(msg.contains("not yet valid"), "error message: {msg}");
}

/// ITP-CG-01-c: ClockUnavailable error variant exists.
#[test]
fn itp_cert_clock_unavailable_error() {
    let err = HsmError::ClockUnavailable;
    let msg = format!("{err}");
    assert!(msg.contains("clock"), "error message: {msg}");
}
