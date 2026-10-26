pub mod error;
pub use error::CryptoError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EdDsaVerifyError {
    #[error("key error: {0}")]
    Key(#[from] EdDsaKeyError),
    #[error("signature error: {0}")]
    Signature(String),
}

#[derive(Debug, Error)]
pub enum EdDsaKeyError {
    #[error("OKP 'x' is not valid base64url: {0}")]
    Base64(String),
    #[error("an Ed25519 public key must be exactly 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("OKP 'x' is not a valid Ed25519 point")]
    InvalidPoint,
    #[error("Ed25519 public key is a low-order point; no private key exists for it, so a signature under it proves nothing")]
    LowOrderPoint,
}

/// Extracts an Ed25519 verifying key from a base64url-encoded `x` string, **rejecting low-order ("weak") keys**.
///
/// This check (authkestra#242, authkestra#256) must run before any verification
/// attempt, so that the key is rejected on its own merits rather than on whichever signature
/// bytes happened to accompany it.
pub fn parse_ed25519_verifying_key_strict(x_b64: &str) -> Result<VerifyingKey, EdDsaKeyError> {
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| EdDsaKeyError::Base64(e.to_string()))?;

    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EdDsaKeyError::InvalidLength(x_bytes.len()))?;

    let key = VerifyingKey::from_bytes(&x_arr).map_err(|_| EdDsaKeyError::InvalidPoint)?;

    if key.is_weak() {
        tracing::warn!(
            target: "authkestra_crypto",
            "rejecting Ed25519 key: it is a low-order (weak) point, for which no private key \
             exists — a signature under it would prove possession of nothing, so it is refused \
             before verification is even attempted (authkestra#242)"
        );
        return Err(EdDsaKeyError::LowOrderPoint);
    }

    Ok(key)
}

/// Verifies an Ed25519 signature over `signing_input` under the public key
/// encoded in `x_b64`, using **strict** verification.
///
/// This is a lower-level, JWS-framing-agnostic sibling of
/// [`parse_ed25519_verifying_key_strict`]: it takes an already-split
/// signing input and base64url-encoded signature, and knows nothing about
/// JWT/JWS headers or claims — callers own that layer. It exists so that
/// more than one call site (currently `authkestra-op::strict_jws`'s
/// JWS-shaped gate, and DPoP proof verification in `authkestra-engine`) can
/// share one implementation of the actual strict-EdDSA check rather than
/// each re-deriving it.
///
/// "Strict" matters for the same reason it does in
/// [`parse_ed25519_verifying_key_strict`] (authkestra#242 / authkestra#256):
/// non-strict Ed25519 verification (`ed25519_dalek::Verifier::verify`) does
/// not check whether the signature's `R` component is a low-order point,
/// so a forged `(R = identity, S = 0)` signature satisfies the verification
/// equation for *any* message under a low-order public key. This function
/// rejects the low-order public key case via
/// [`parse_ed25519_verifying_key_strict`] and additionally guards a
/// low-order `R` under an otherwise-legitimate key by using
/// [`ed25519_dalek::VerifyingKey::verify_strict`] rather than `verify`.
pub fn verify_ed25519_signature_strict(
    signing_input: &[u8],
    signature_b64: &str,
    x_b64: &str,
) -> Result<(), EdDsaVerifyError> {
    let key = parse_ed25519_verifying_key_strict(x_b64)?;

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|e| {
        EdDsaVerifyError::Signature(format!("signature is not valid base64url: {e}"))
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        EdDsaVerifyError::Signature(format!(
            "an Ed25519 signature must be exactly 64 bytes, got {}",
            signature_bytes.len()
        ))
    })?;

    key.verify_strict(signing_input, &signature).map_err(|_| {
        // `verify_strict` folds "the equation did not hold" and "R is a
        // low-order point" into a single opaque error. Recompute the
        // latter so operators can tell routine signature failures from an
        // attempted low-order forgery, which is an attack signal and not
        // noise. `VerifyingKey::from_bytes` is reused purely as a
        // compressed-Edwards-point decoder here — `R` has the same
        // encoding as a public key, and `is_weak()` is the only
        // small-order predicate `ed25519-dalek` exposes publicly.
        let r_is_small_order = signature_bytes
            .get(..32)
            .and_then(|r| <[u8; 32]>::try_from(r).ok())
            .and_then(|r| VerifyingKey::from_bytes(&r).ok())
            .is_some_and(|r| r.is_weak());

        if r_is_small_order {
            tracing::warn!(
                target: "authkestra_crypto",
                "rejecting EdDSA signature: its R component is a low-order point — strict \
                 verification refuses these because they carry no proof of possession \
                 (authkestra#242)"
            );
        }

        EdDsaVerifyError::Signature(
            "Ed25519 signature did not verify under strict verification".to_string(),
        )
    })
}

/// 12-byte nonce size standard for AES-256-GCM (NIST SP 800-38D).
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// 16-byte authentication tag size standard for AES-256-GCM.
pub const AES_GCM_TAG_SIZE: usize = 16;

/// Minimum valid ciphertext length (nonce + tag = 28 bytes).
pub const AES_GCM_MIN_CIPHERTEXT_SIZE: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;

/// Encrypts `plaintext` using AES-256-GCM with the provided 32-byte `key`.
///
/// Generates a cryptographically secure random 12-byte nonce and prepends it
/// to the resulting ciphertext + 16-byte authentication tag.
///
/// Output format: `[12-byte nonce | ciphertext + 16-byte tag]`.
pub fn encrypt_aes_256_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut combined = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(combined)
}

/// Decrypts `ciphertext` using AES-256-GCM with the provided 32-byte `key`.
///
/// Expects the input to follow the `[12-byte nonce | ciphertext + 16-byte tag]` format.
/// Returns [`CryptoError::CiphertextTooShort`] if input length is less than 28 bytes.
/// Returns [`CryptoError::Decryption`] if authentication tag verification fails (e.g. tampering or wrong key).
pub fn decrypt_aes_256_gcm(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < AES_GCM_MIN_CIPHERTEXT_SIZE {
        return Err(CryptoError::CiphertextTooShort(ciphertext.len()));
    }

    let (nonce_bytes, payload) = ciphertext.split_at(AES_GCM_NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key.into());

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity point: the canonical universal low-order vector.
    const IDENTITY: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    #[test]
    fn rejects_low_order_identity_point() {
        let x_b64 = URL_SAFE_NO_PAD.encode(IDENTITY);
        let err =
            parse_ed25519_verifying_key_strict(&x_b64).expect_err("should reject low order point");
        assert!(matches!(err, EdDsaKeyError::LowOrderPoint));
    }

    #[test]
    fn accepts_valid_point() {
        // A valid Ed25519 point (signing key scalar = 7)
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let x_b64 = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
        let key = parse_ed25519_verifying_key_strict(&x_b64).expect("should accept valid point");
        assert_eq!(key.as_bytes(), verifying.as_bytes());
    }

    #[test]
    fn rejects_invalid_length() {
        let x_b64 = URL_SAFE_NO_PAD.encode([0u8; 31]);
        let err = parse_ed25519_verifying_key_strict(&x_b64).expect_err("should reject short key");
        assert!(matches!(err, EdDsaKeyError::InvalidLength(31)));
    }

    /// Pins that the universal low-order forgery — the one the non-strict
    /// `ed25519_dalek::Verifier::verify` accepts — is refused here.
    #[test]
    fn verify_ed25519_signature_strict_rejects_the_universal_forgery() {
        use ed25519_dalek::Verifier;

        let weak = VerifyingKey::from_bytes(&IDENTITY).expect("identity is a valid Edwards point");
        assert!(weak.is_weak(), "the identity point must be low-order");

        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY);

        assert!(
            weak.verify(b"signing-input", &Signature::from_bytes(&forged))
                .is_ok(),
            "precondition: the NON-strict verifier accepts this forgery — if this ever fails, \
             upstream changed and this test no longer proves what it claims"
        );

        let x_b64 = URL_SAFE_NO_PAD.encode(IDENTITY);
        let sig_b64 = URL_SAFE_NO_PAD.encode(forged);
        let err = verify_ed25519_signature_strict(b"signing-input", &sig_b64, &x_b64)
            .expect_err("the universal forgery must be refused");

        assert!(
            matches!(&err, EdDsaVerifyError::Key(EdDsaKeyError::LowOrderPoint)),
            "expected a Key(LowOrderPoint) rejection, got {err:?}"
        );
    }

    /// Positive control: a verifier that rejects everything is not a verifier.
    #[test]
    fn verify_ed25519_signature_strict_accepts_a_genuine_signature() {
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let key = signing.verifying_key();
        assert!(!key.is_weak());

        let signature = signing.sign(b"signing-input");

        let x_b64 = URL_SAFE_NO_PAD.encode(key.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        verify_ed25519_signature_strict(b"signing-input", &sig_b64, &x_b64)
            .expect("a genuine Ed25519 signature must verify");
    }

    /// A genuine key with someone else's signature is a `Signature` error,
    /// not a `Key` error — callers need this distinction to tell "the key
    /// is unusable" apart from "this particular signature doesn't match".
    #[test]
    fn verify_ed25519_signature_strict_classifies_a_mismatched_signature_as_signature_error() {
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);

        let wrong_signature = other.sign(b"signing-input");

        let x_b64 = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(wrong_signature.to_bytes());
        let err = verify_ed25519_signature_strict(b"signing-input", &sig_b64, &x_b64)
            .expect_err("a signature from a different key must be refused");

        assert!(
            matches!(err, EdDsaVerifyError::Signature(_)),
            "expected a Signature rejection, got {err:?}"
        );
    }

    const TEST_KEY: [u8; 32] = [42u8; 32];
    const ALT_KEY: [u8; 32] = [99u8; 32];

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Authkestra Zero-Trust Token Vault payload";
        let encrypted = encrypt_aes_256_gcm(plaintext, &TEST_KEY).expect("encryption succeeds");
        assert!(encrypted.len() >= AES_GCM_MIN_CIPHERTEXT_SIZE);

        let decrypted = decrypt_aes_256_gcm(&encrypted, &TEST_KEY).expect("decryption succeeds");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let plaintext = b"";
        let encrypted = encrypt_aes_256_gcm(plaintext, &TEST_KEY).expect("encryption succeeds");
        assert_eq!(encrypted.len(), AES_GCM_MIN_CIPHERTEXT_SIZE);

        let decrypted = decrypt_aes_256_gcm(&encrypted, &TEST_KEY).expect("decryption succeeds");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let plaintext = b"critical financial instruction: transfer $50";
        let mut encrypted = encrypt_aes_256_gcm(plaintext, &TEST_KEY).expect("encryption succeeds");

        // Tamper with ciphertext payload byte
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01;

        let err =
            decrypt_aes_256_gcm(&encrypted, &TEST_KEY).expect_err("tampered ciphertext must fail");
        assert!(matches!(err, CryptoError::Decryption(_)));
    }

    #[test]
    fn test_tampered_nonce_rejected() {
        let plaintext = b"secret token";
        let mut encrypted = encrypt_aes_256_gcm(plaintext, &TEST_KEY).expect("encryption succeeds");

        // Tamper with nonce byte (first 12 bytes)
        encrypted[0] ^= 0xff;

        let err = decrypt_aes_256_gcm(&encrypted, &TEST_KEY).expect_err("tampered nonce must fail");
        assert!(matches!(err, CryptoError::Decryption(_)));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let plaintext = b"super secret api token";
        let encrypted = encrypt_aes_256_gcm(plaintext, &TEST_KEY).expect("encryption succeeds");

        let err = decrypt_aes_256_gcm(&encrypted, &ALT_KEY).expect_err("wrong key must fail");
        assert!(matches!(err, CryptoError::Decryption(_)));
    }

    #[test]
    fn test_short_ciphertext_rejected() {
        assert!(matches!(
            decrypt_aes_256_gcm(&[], &TEST_KEY),
            Err(CryptoError::CiphertextTooShort(0))
        ));
        assert!(matches!(
            decrypt_aes_256_gcm(&[0u8; 11], &TEST_KEY),
            Err(CryptoError::CiphertextTooShort(11))
        ));
        assert!(matches!(
            decrypt_aes_256_gcm(&[0u8; 27], &TEST_KEY),
            Err(CryptoError::CiphertextTooShort(27))
        ));
    }

    #[test]
    fn test_nonce_uniqueness() {
        let plaintext = b"identical plaintext";
        let enc1 = encrypt_aes_256_gcm(plaintext, &TEST_KEY).unwrap();
        let enc2 = encrypt_aes_256_gcm(plaintext, &TEST_KEY).unwrap();

        assert_ne!(
            enc1[..AES_GCM_NONCE_SIZE],
            enc2[..AES_GCM_NONCE_SIZE],
            "nonces must be unique per encryption"
        );
        assert_ne!(enc1, enc2, "ciphertexts must differ due to random nonces");
    }
}
