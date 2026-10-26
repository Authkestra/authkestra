use thiserror::Error;

/// Errors arising from cryptographic operations in `authkestra-crypto-util`.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES-256-GCM encryption error: {0}")]
    Encryption(String),

    #[error("AES-256-GCM decryption error: {0}")]
    Decryption(String),

    #[error(
        "ciphertext too short: expected at least 28 bytes (12-byte nonce + 16-byte tag), got {0}"
    )]
    CiphertextTooShort(usize),

    #[error("invalid key length: expected 32 bytes")]
    InvalidKeyLength,
}
