//! X.509 certificate management tests — HSM-REQ-018.
//!
//! Uses `rcgen` to generate deterministic test certificates so no external
//! CA tooling is required in CI.
//!
//! Feature-gated: `cargo test --features certs`

use p256::elliptic_curve::sec1::ToEncodedPoint;
use scorehsm_host::cert::{extract_ec_public_key, parse_der, verify_cert_signature, verify_chain};

// ── rcgen helpers ─────────────────────────────────────────────────────────────

/// Build an rcgen key pair from a known P-256 scalar so tests are deterministic.
fn rcgen_keypair_from_scalar(scalar: &[u8; 32]) -> rcgen::KeyPair {
    use p256::pkcs8::EncodePrivateKey;
    let sk = p256::SecretKey::from_bytes(scalar.into()).unwrap();
    let pem = sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
    rcgen::KeyPair::from_pem(&pem).unwrap()
}

const ROOT_SCALAR: [u8; 32] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

const LEAF_SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Generate a self-signed root CA certificate DER.
fn make_root_cert_der() -> (Vec<u8>, [u8; 65]) {
    let kp = rcgen_keypair_from_scalar(&ROOT_SCALAR);
    let mut params = rcgen::CertificateParams::new(vec!["root-ca".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&kp).unwrap();
    let der = cert.der().to_vec();

    // Extract public key from scalar for verification
    let sk = p256::SecretKey::from_bytes(&ROOT_SCALAR.into()).unwrap();
    let encoded = sk.public_key().to_encoded_point(false);
    let mut pk = [0u8; 65];
    pk.copy_from_slice(encoded.as_bytes());

    (der, pk)
}

/// Generate a leaf certificate signed by the root.
fn make_leaf_cert_der(root_kp: &rcgen::KeyPair) -> Vec<u8> {
    let leaf_kp = rcgen_keypair_from_scalar(&LEAF_SCALAR);
    let params = rcgen::CertificateParams::new(vec!["leaf-device".to_string()]).unwrap();
    let root_params = {
        let mut p = rcgen::CertificateParams::new(vec!["root-ca".to_string()]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p
    };
    let root_cert = root_params.self_signed(root_kp).unwrap();
    params
        .signed_by(&leaf_kp, &root_cert, root_kp)
        .unwrap()
        .der()
        .to_vec()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A valid DER certificate is parsed successfully.
#[test]
fn test_cert_parse_der_valid() {
    let (der, _) = make_root_cert_der();
    assert!(
        parse_der(&der).is_ok(),
        "valid DER cert must parse successfully"
    );
}

/// Invalid DER bytes are rejected.
#[test]
fn test_cert_parse_der_invalid() {
    let garbage = vec![0x30u8, 0x04, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_der(&garbage).is_err(), "garbage DER must be rejected");
}

/// extract_ec_public_key returns a 65-byte point for an ECDSA-P256 cert.
#[test]
fn test_cert_extract_ec_public_key() {
    let (der, expected_pk) = make_root_cert_der();
    let cert = parse_der(&der).unwrap();
    let pk = extract_ec_public_key(&cert).unwrap();
    assert_eq!(pk.len(), 65);
    assert_eq!(
        pk, expected_pk,
        "extracted public key must match known scalar"
    );
}

/// A self-signed certificate signature is verified correctly.
#[test]
fn test_cert_verify_self_signed() {
    let (der, root_pk) = make_root_cert_der();
    let cert = parse_der(&der).unwrap();
    let result = verify_cert_signature(&cert, &root_pk).unwrap();
    assert!(result, "self-signed certificate signature must verify");
}

/// A self-signed chain of length 1 is accepted by verify_chain.
#[test]
fn test_cert_verify_chain_single() {
    let (der, root_pk) = make_root_cert_der();
    let cert = parse_der(&der).unwrap();
    assert!(
        verify_chain(&[cert], &root_pk).is_ok(),
        "single self-signed cert must verify against trust anchor"
    );
}

/// A two-level chain (leaf signed by root) is verified correctly.
#[test]
fn test_cert_verify_chain_two_level() {
    let root_kp = rcgen_keypair_from_scalar(&ROOT_SCALAR);
    let leaf_der = make_leaf_cert_der(&root_kp);
    let (root_der, root_pk) = make_root_cert_der();

    let leaf = parse_der(&leaf_der).unwrap();
    let root = parse_der(&root_der).unwrap();

    // Chain: [leaf, root] — leaf signed by root, root signed by trust anchor
    assert!(
        verify_chain(&[leaf, root], &root_pk).is_ok(),
        "two-level chain must verify"
    );
}

/// An empty certificate chain returns an error.
#[test]
fn test_cert_verify_chain_empty_rejected() {
    let (_, root_pk) = make_root_cert_der();
    assert!(
        verify_chain(&[], &root_pk).is_err(),
        "empty chain must be rejected"
    );
}
