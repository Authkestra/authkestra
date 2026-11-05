//! Tests verifying hardening in facade examples (CWE-287 subject verification,
//! CWE-321 dynamic token signing secret resolution, fallback behavior).

#[allow(dead_code, unused_imports)]
#[path = "../examples/axum_op_server_attestation.rs"]
mod axum_attestation;

#[allow(dead_code, unused_imports)]
#[path = "../examples/actix_op_server_attestation.rs"]
mod actix_attestation;

use authkestra_op::attestation::{PrincipalType, SecondFactorProof, SecondFactorVerifier};
use authkestra_op::OpError;
use std::sync::Mutex;

/// Global lock ensuring environment variable test cases run serially without race conditions.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper creating a SecondFactorProof with kind and value.
fn make_proof(kind: &str, value: &str) -> SecondFactorProof {
    serde_json::from_value(serde_json::json!({
        "kind": kind,
        "value": value,
    }))
    .expect("valid SecondFactorProof")
}

/// Tests that the actual Axum and Actix DemoOtpVerifier implementations allow valid demo subject and principal type.
#[tokio::test]
async fn test_example_demo_otp_verifier_allows_valid_demo_subject_and_type() {
    let proof = make_proof("demo_otp", "123456");

    let axum_verifier = axum_attestation::DemoOtpVerifier;
    let res_axum = axum_verifier
        .verify("user-42", PrincipalType::Device, &proof)
        .await;
    assert!(res_axum.is_ok());

    let actix_verifier = actix_attestation::DemoOtpVerifier;
    let res_actix = actix_verifier
        .verify("user-42", PrincipalType::Device, &proof)
        .await;
    assert!(res_actix.is_ok());
}

/// Tests that the actual Axum and Actix DemoOtpVerifier implementations reject arbitrary or empty subjects.
#[tokio::test]
async fn test_example_demo_otp_verifier_rejects_arbitrary_subject() {
    let proof = make_proof("demo_otp", "123456");

    let axum_verifier = axum_attestation::DemoOtpVerifier;
    let res = axum_verifier
        .verify("attacker-99", PrincipalType::Device, &proof)
        .await;
    assert!(matches!(res, Err(OpError::SecondFactorFailed)));

    let empty_res = axum_verifier
        .verify("", PrincipalType::Device, &proof)
        .await;
    assert!(matches!(empty_res, Err(OpError::SecondFactorFailed)));

    let actix_verifier = actix_attestation::DemoOtpVerifier;
    let res_actix = actix_verifier
        .verify("attacker-99", PrincipalType::Device, &proof)
        .await;
    assert!(matches!(res_actix, Err(OpError::SecondFactorFailed)));
}

/// Tests that the actual Axum and Actix DemoOtpVerifier implementations reject unauthorized principal types.
#[tokio::test]
async fn test_example_demo_otp_verifier_rejects_unauthorized_principal_type() {
    let proof = make_proof("demo_otp", "123456");

    let axum_verifier = axum_attestation::DemoOtpVerifier;
    let res = axum_verifier
        .verify("user-42", PrincipalType::Service, &proof)
        .await;
    assert!(matches!(res, Err(OpError::SecondFactorFailed)));

    let actix_verifier = actix_attestation::DemoOtpVerifier;
    let res_actix = actix_verifier
        .verify("user-42", PrincipalType::Service, &proof)
        .await;
    assert!(matches!(res_actix, Err(OpError::SecondFactorFailed)));
}

/// Tests that the actual Axum and Actix DemoOtpVerifier implementations reject invalid proof kinds or values.
#[tokio::test]
async fn test_example_demo_otp_verifier_rejects_invalid_proof() {
    let axum_verifier = axum_attestation::DemoOtpVerifier;

    let wrong_otp = make_proof("demo_otp", "000000");
    let res = axum_verifier
        .verify("user-42", PrincipalType::Device, &wrong_otp)
        .await;
    assert!(matches!(res, Err(OpError::SecondFactorFailed)));

    let wrong_kind = make_proof("sms_otp", "123456");
    let res2 = axum_verifier
        .verify("user-42", PrincipalType::Device, &wrong_kind)
        .await;
    assert!(matches!(res2, Err(OpError::SecondFactorFailed)));

    let actix_verifier = actix_attestation::DemoOtpVerifier;
    let res_actix = actix_verifier
        .verify("user-42", PrincipalType::Device, &wrong_otp)
        .await;
    assert!(matches!(res_actix, Err(OpError::SecondFactorFailed)));
}

/// Tests that resolve_token_secret selects valid configured keys, falls back to secondary valid key when primary is short,
/// and falls back to random 32-byte ephemeral key when neither is valid.
#[test]
fn test_resolve_token_secret_configured_and_fallback_behavior() {
    let _lock = ENV_LOCK.lock().unwrap();

    // 1. Primary valid (>= 32 bytes)
    std::env::set_var(
        "AUTHKESTRA_TOKEN_SECRET",
        "custom-valid-secret-key-that-is-at-least-32-bytes-long",
    );
    std::env::remove_var("JWT_SECRET");
    let secret = axum_attestation::resolve_token_secret();
    assert_eq!(
        secret,
        b"custom-valid-secret-key-that-is-at-least-32-bytes-long"
    );

    // 2. Primary too short (< 32 bytes), secondary valid (>= 32 bytes) -> must pick secondary!
    std::env::set_var("AUTHKESTRA_TOKEN_SECRET", "too-short");
    std::env::set_var(
        "JWT_SECRET",
        "fallback-valid-secret-key-at-least-32-bytes-long",
    );
    let secret_fallback = axum_attestation::resolve_token_secret();
    assert_eq!(
        secret_fallback,
        b"fallback-valid-secret-key-at-least-32-bytes-long"
    );

    // 3. Both unset -> generates random 32-byte ephemeral key through resolve_token_secret
    std::env::remove_var("AUTHKESTRA_TOKEN_SECRET");
    std::env::remove_var("JWT_SECRET");
    let key1 = axum_attestation::resolve_token_secret();
    let key2 = axum_attestation::resolve_token_secret();
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    assert_ne!(key1, key2);
    assert_ne!(key1, vec![0u8; 32]);
    assert_ne!(key1, b"0123456789abcdef0123456789abcdef");

    // Clean up env vars after test
    std::env::remove_var("AUTHKESTRA_TOKEN_SECRET");
    std::env::remove_var("JWT_SECRET");
}
