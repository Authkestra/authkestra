use crate::error::McpError;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonicalizes a JSON value into deterministic UTF-16 code unit sorted bytes per RFC 8785.
pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, McpError> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| McpError::Canonicalization(e.to_string()))
}

/// Convenience alias for [`canonicalize_json`].
pub fn canonicalize_arguments(arguments: &Value) -> Result<Vec<u8>, McpError> {
    canonicalize_json(arguments)
}

/// Canonicalizes approval arguments only when JCS preserves their handler-visible values.
pub(crate) fn canonicalize_approval_arguments(arguments: &Value) -> Result<Vec<u8>, McpError> {
    let canonical = canonicalize_json(arguments)?;
    let roundtrip: Value = serde_json::from_slice(&canonical)
        .map_err(|e| McpError::Canonicalization(e.to_string()))?;

    // Number equality alone treats -0.0 and 0.0 as equal. Their serialized
    // representations also distinguish integer and float values for handlers.
    fn same_values(original: &Value, roundtrip: &Value) -> bool {
        match (original, roundtrip) {
            (Value::Number(a), Value::Number(b)) => a.to_string() == b.to_string(),
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same_values(x, y))
            }
            (Value::Object(a), Value::Object(b)) => {
                a.len() == b.len()
                    && a.iter().all(|(key, value)| {
                        b.get(key).is_some_and(|other| same_values(value, other))
                    })
            }
            _ => original == roundtrip,
        }
    }

    if !same_values(arguments, &roundtrip) {
        tracing::warn!("approval arguments contain values changed by JCS canonicalization");
        return Err(McpError::InvalidArguments(
            "Approval arguments must retain their JSON values and numeric types under JCS; encode affected numbers as strings".to_string(),
        ));
    }
    Ok(canonical)
}

/// Computes the deterministic SHA-256 challenge digest binding:
/// `(session_id, tool_name, jcs_canonical_arguments, expires_at)`.
///
/// Output format is the lowercase 64-character hexadecimal SHA-256 hash of:
/// `[session_id] + ":" + [tool_name] + ":" + [jcs_canonical_arguments] + ":" + [expires_at]`.
pub fn compute_challenge_digest(
    session_id: &str,
    tool_name: &str,
    jcs_canonical_arguments: &[u8],
    expires_at: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(b":");
    hasher.update(tool_name.as_bytes());
    hasher.update(b":");
    hasher.update(jcs_canonical_arguments);
    hasher.update(b":");
    hasher.update(expires_at.to_string().as_bytes());
    hex::encode(hasher.finalize())
}
