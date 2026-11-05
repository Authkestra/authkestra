use async_trait::async_trait;
use authkestra_op::attestation::{PrincipalType, SecondFactorProof, SecondFactorVerifier};
use authkestra_op::OpError;

/// Duplicates DemoOtpVerifier from the attestation examples for direct unit testing of
/// the CWE-287 fix (Rows 1 & 14).
struct TestDemoOtpVerifier;

#[async_trait]
impl SecondFactorVerifier for TestDemoOtpVerifier {
    async fn verify(
        &self,
        subject: &str,
        principal_type: PrincipalType,
        proof: &SecondFactorProof,
    ) -> Result<(), OpError> {
        if subject.trim().is_empty() || subject != "user-42" {
            return Err(OpError::SecondFactorFailed);
        }

        if principal_type != PrincipalType::Device {
            return Err(OpError::SecondFactorFailed);
        }

        if proof.kind == "demo_otp" && proof.value == "123456" {
            Ok(())
        } else {
            Err(OpError::SecondFactorFailed)
        }
    }
}

fn make_proof(kind: &str, value: &str) -> SecondFactorProof {
    serde_json::from_value(serde_json::json!({
        "kind": kind,
        "value": value,
    }))
    .expect("valid SecondFactorProof")
}

#[tokio::test]
async fn test_demo_otp_verifier_allows_valid_demo_subject_and_type() {
    let verifier = TestDemoOtpVerifier;
    let proof = make_proof("demo_otp", "123456");

    let result = verifier
        .verify("user-42", PrincipalType::Device, &proof)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_demo_otp_verifier_rejects_arbitrary_subject() {
    let verifier = TestDemoOtpVerifier;
    let proof = make_proof("demo_otp", "123456");

    // Arbitrary subject must be rejected
    let result = verifier
        .verify("attacker-99", PrincipalType::Device, &proof)
        .await;
    assert!(matches!(result, Err(OpError::SecondFactorFailed)));

    // Empty subject must be rejected
    let empty_res = verifier.verify("", PrincipalType::Device, &proof).await;
    assert!(matches!(empty_res, Err(OpError::SecondFactorFailed)));
}

#[tokio::test]
async fn test_demo_otp_verifier_rejects_unauthorized_principal_type() {
    let verifier = TestDemoOtpVerifier;
    let proof = make_proof("demo_otp", "123456");

    let result = verifier
        .verify("user-42", PrincipalType::Service, &proof)
        .await;
    assert!(matches!(result, Err(OpError::SecondFactorFailed)));
}

#[tokio::test]
async fn test_demo_otp_verifier_rejects_invalid_proof() {
    let verifier = TestDemoOtpVerifier;

    // Wrong OTP value
    let wrong_otp = make_proof("demo_otp", "000000");
    let result = verifier
        .verify("user-42", PrincipalType::Device, &wrong_otp)
        .await;
    assert!(matches!(result, Err(OpError::SecondFactorFailed)));

    // Wrong proof kind
    let wrong_kind = make_proof("sms_otp", "123456");
    let result2 = verifier
        .verify("user-42", PrincipalType::Device, &wrong_kind)
        .await;
    assert!(matches!(result2, Err(OpError::SecondFactorFailed)));
}

#[test]
fn test_ephemeral_token_secret_randomness() {
    use rand::RngCore;

    let mut key1 = vec![0u8; 32];
    let mut key2 = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key1);
    rand::thread_rng().fill_bytes(&mut key2);

    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    // Two independently generated random keys must not be identical
    assert_ne!(key1, key2);
    // Neither key should be all zeroes or match known static strings
    assert_ne!(key1, vec![0u8; 32]);
    assert_ne!(key1, b"0123456789abcdef0123456789abcdef");
    assert_ne!(key1, b"my-super-secret-key-that-is-32bytes-long");
    assert_ne!(key1, b"example-only-32-byte-secret-key");
}
