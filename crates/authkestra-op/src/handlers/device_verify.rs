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

/// Generates a session-bound CSRF token for device verification.
pub fn generate_csrf_token(secret: &[u8], session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b":device_verify_csrf:");
    hasher.update(session_id.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
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

    devices.update_device_code(session).await?;
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

        let res = handle_device_verify(req, identity, &mut devices)
            .await
            .unwrap();
        assert!(res.success);

        let updated = devices.get_device_code("dev123").await.unwrap().unwrap();
        assert!(matches!(updated.status, DeviceCodeStatus::Approved(_)));
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
