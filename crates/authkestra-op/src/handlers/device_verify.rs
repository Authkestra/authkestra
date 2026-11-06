use crate::device::{DeviceCodeStatus, DeviceCodeStore};
use crate::error::OpError;
use authkestra_engine::auth::state::Identity;
use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Request payload for the device verification endpoint.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceVerifyRequest {
    /// The user code provided by the device.
    pub user_code: String,
    /// Whether the user approved or denied the request.
    pub approve: bool,
    /// Optional session-bound CSRF token.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Computes RFC 2104 HMAC-SHA256 over the given message parts.
fn hmac_sha256(secret: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(secret);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Generates a session-bound HMAC-SHA256 CSRF token for device verification.
pub fn generate_csrf_token(secret: &[u8], session_id: &str) -> String {
    let mac = hmac_sha256(secret, &[b":device_verify_csrf:", session_id.as_bytes()]);
    URL_SAFE_NO_PAD.encode(mac)
}

/// Verifies a session-bound CSRF token in constant-time.
pub fn verify_csrf_token(secret: &[u8], session_id: &str, token: &str) -> bool {
    let expected = generate_csrf_token(secret, session_id);
    if token.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in token.as_bytes().iter().zip(expected.as_bytes().iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Response payload for a successful device verification request.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct DeviceVerifyResponse {
    /// Indicates whether the verification was processed successfully.
    pub success: bool,
}

/// Handles a device verification (user approval) request.
pub async fn handle_device_verify(
    req: DeviceVerifyRequest,
    identity: Identity,
    devices: &mut dyn DeviceCodeStore,
) -> Result<DeviceVerifyResponse, OpError> {
    tracing::debug!(user_code = %req.user_code, approve = req.approve, "processing device verification");
    let mut session = match devices.get_by_user_code(&req.user_code).await {
        Ok(Some(s)) => s,
        _ => {
            tracing::warn!(user_code = %req.user_code, "device code not found or invalid during verification");
            return Err(OpError::InvalidCode);
        }
    };

    match session.status {
        DeviceCodeStatus::Pending => {}
        _ => {
            tracing::warn!(user_code = %req.user_code, "device code session not in pending state");
            return Err(OpError::InvalidCode);
        }
    }

    if req.approve {
        session.status = DeviceCodeStatus::Approved(identity.clone());
    } else {
        session.status = DeviceCodeStatus::Denied;
    }

    devices.update_device_code(session).await.map_err(|e| match e {
        authkestra_engine::store::StoreError::NotFound => {
            tracing::warn!(error = %e, "Failed to update device code: record missing or no longer pending");
            OpError::InvalidCode
        }
        other => {
            tracing::error!(error = %other, "Storage failure while updating device code");
            OpError::Storage
        }
    })?;
    tracing::info!(user_code = %req.user_code, approved = req.approve, user_id = %identity.external_id, "device code verification succeeded");

    Ok(DeviceVerifyResponse { success: true })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::device::DeviceCodeSession;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_handle_device_verify_approve() {
        let mut devices = authkestra_engine::store::memory::MemoryStore::<
            crate::device::DeviceCodeSession,
        >::new();
        let session = DeviceCodeSession::new(
            "dev123".to_string(),
            "USER123".to_string(),
            "client1".to_string(),
            "openid".to_string(),
            Utc::now() + Duration::seconds(600),
            DeviceCodeStatus::Pending,
        );
        devices.store_device_code(session).await.unwrap();

        let identity = Identity {
            provider_id: "test".to_string(),
            external_id: "user1".to_string(),
            username: Some("user1".to_string()),
            email: None,
            attributes: HashMap::new(),
        };

        let req = DeviceVerifyRequest {
            user_code: "USER123".to_string(),
            approve: true,
            csrf_token: None,
        };

        let res = handle_device_verify(req, identity.clone(), &mut devices)
            .await
            .unwrap();
        assert!(res.success);

        let updated = devices.get_device_code("dev123").await.unwrap().unwrap();
        assert!(matches!(updated.status, DeviceCodeStatus::Approved(_)));

        // Attempting to verify again must fail because it's no longer Pending
        let req2 = DeviceVerifyRequest {
            user_code: "USER123".to_string(),
            approve: true,
            csrf_token: None,
        };
        let err = handle_device_verify(req2, identity, &mut devices)
            .await
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidCode));
    }

    /// Verifies that `update_device_code` rejects missing or non-pending sessions.
    #[tokio::test]
    async fn test_update_device_code_rejects_non_pending() {
        let mut devices = authkestra_engine::store::memory::MemoryStore::<
            crate::device::DeviceCodeSession,
        >::new();
        let mut session = DeviceCodeSession::new(
            "dev456".to_string(),
            "USER456".to_string(),
            "client1".to_string(),
            "openid".to_string(),
            Utc::now() + Duration::seconds(600),
            DeviceCodeStatus::Denied,
        );

        // Not in store yet -> update fails
        let err = devices
            .update_device_code(session.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            authkestra_engine::store::StoreError::NotFound
        ));

        // Stored as Denied (not Pending) -> update fails
        devices.store_device_code(session.clone()).await.unwrap();
        session.status = DeviceCodeStatus::Approved(Identity {
            provider_id: "test".to_string(),
            external_id: "user2".to_string(),
            username: None,
            email: None,
            attributes: HashMap::new(),
        });
        let err = devices.update_device_code(session).await.unwrap_err();
        assert!(matches!(
            err,
            authkestra_engine::store::StoreError::NotFound
        ));
    }

    #[test]
    fn test_csrf_token_roundtrip_and_rejection() {
        let secret = b"super_secret_session_encryption_key_32b";
        let session_id = "session_xyz_123";
        let token = generate_csrf_token(secret, session_id);

        assert!(verify_csrf_token(secret, session_id, &token));
        assert!(!verify_csrf_token(
            b"wrong_secret_key_32b_wrong_wrong",
            session_id,
            &token
        ));
        assert!(!verify_csrf_token(secret, "different_session_id", &token));
        assert!(!verify_csrf_token(
            secret,
            session_id,
            "invalid_tampered_token"
        ));
    }

    #[test]
    fn test_csrf_token_matches_independent_hmac_sha256_vector() {
        // Independently computed HMAC-SHA256(key = b"0123456789abcdef0123456789abcdef",
        // msg = b":device_verify_csrf:sess-123") encoded with base64url (no padding).
        let secret = b"0123456789abcdef0123456789abcdef";
        let session_id = "sess-123";
        let expected = "1ytV69E_pRrfmT0DREnh80xPd4GGsdkhCBS9SrjwiHg";
        assert_eq!(generate_csrf_token(secret, session_id), expected);
        assert!(verify_csrf_token(secret, session_id, expected));
    }

    #[tokio::test]
    async fn test_handle_device_verify_deny() {
        let mut devices = authkestra_engine::store::memory::MemoryStore::<
            crate::device::DeviceCodeSession,
        >::new();
        let session = DeviceCodeSession::new(
            "dev456".to_string(),
            "DENY123".to_string(),
            "client1".to_string(),
            "openid".to_string(),
            Utc::now() + Duration::seconds(600),
            DeviceCodeStatus::Pending,
        );
        devices.store_device_code(session).await.unwrap();

        let identity = Identity {
            provider_id: "test".to_string(),
            external_id: "user1".to_string(),
            username: Some("user1".to_string()),
            email: None,
            attributes: HashMap::new(),
        };

        let req = DeviceVerifyRequest {
            user_code: "DENY123".to_string(),
            approve: false,
            csrf_token: None,
        };

        let res = handle_device_verify(req, identity, &mut devices)
            .await
            .unwrap();
        assert!(res.success);

        let updated = devices.get_device_code("dev456").await.unwrap().unwrap();
        assert!(matches!(updated.status, DeviceCodeStatus::Denied));
    }

    #[tokio::test]
    async fn test_handle_device_verify_invalid_code() {
        let mut devices = authkestra_engine::store::memory::MemoryStore::<
            crate::device::DeviceCodeSession,
        >::new();
        let identity = Identity {
            provider_id: "test".to_string(),
            external_id: "user1".to_string(),
            username: Some("user1".to_string()),
            email: None,
            attributes: HashMap::new(),
        };
        let req = DeviceVerifyRequest {
            user_code: "NONEXISTENT".to_string(),
            approve: true,
            csrf_token: None,
        };
        let err = handle_device_verify(req, identity, &mut devices)
            .await
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidCode));
    }
}
