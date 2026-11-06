use crate::auth::error::AuthError;
use crate::auth::state::Identity;
use crate::auth::SameSite;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Configuration for session cookies.
#[derive(Clone)]
pub struct SessionConfig {
    /// The name of the session cookie.
    pub cookie_name: String,
    /// Whether the cookie should only be sent over HTTPS.
    pub secure: bool,
    /// Whether the cookie should be inaccessible to client-side scripts.
    pub http_only: bool,
    /// The `SameSite` attribute for the cookie.
    pub same_site: SameSite,
    /// The path for which the cookie is valid.
    pub path: String,
    /// The maximum age of the session.
    pub max_age: Option<chrono::Duration>,
    /// Key used to encrypt intermediate OAuth state cookies.
    /// Must be 32 bytes for AES-256-GCM.
    pub state_encryption_key: [u8; 32],
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("cookie_name", &self.cookie_name)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("path", &self.path)
            .field("max_age", &self.max_age)
            .field("state_encryption_key", &"[REDACTED]")
            .finish()
    }
}

impl SessionConfig {
    /// Creates a new SessionConfig with an explicit 32-byte encryption key.
    pub fn new(state_encryption_key: [u8; 32]) -> Self {
        Self {
            cookie_name: "authkestra_session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
            state_encryption_key,
        }
    }
}

/// Returns a config with a freshly generated random 32-byte `state_encryption_key`.
///
/// Each call generates a different key. Create the config once and share it.
/// Use [`SessionConfig::new`] with an explicit key when several instances must
/// decrypt each other's OAuth state cookies, or when in-flight logins must
/// survive a restart.
impl Default for SessionConfig {
    /// Generates a default [`SessionConfig`] with a random 32-byte `state_encryption_key`.
    fn default() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self::new(key)
    }
}

/// Validates that a redirect URL is a safe application-relative path.
///
/// Disallows protocol-relative URLs (`//`), backslash escapes (`/\`),
/// backslashes anywhere in the path, and ASCII control characters.
pub fn is_safe_relative_url(url: &str) -> bool {
    url.starts_with('/')
        && !url.starts_with("//")
        && !url.starts_with("/\\")
        && !url.contains('\\')
        && !url.chars().any(|c| c.is_control())
}

/// Returns the first safe relative URL among `stored` and `default`, or `"/"`.
pub fn resolve_redirect_target(stored: Option<&str>, default: &str) -> String {
    if let Some(url) = stored.filter(|u| is_safe_relative_url(u)) {
        return url.to_string();
    }
    if is_safe_relative_url(default) {
        return default.to_string();
    }
    tracing::debug!("redirect default rejected; falling back to '/'");
    "/".to_string()
}

/// Represents an active user session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Session {
    /// Unique session identifier.
    pub id: String,
    /// The identity associated with this session.
    pub identity: Identity,
    /// When the session expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Trait for implementing session persistence.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Load a session by its ID.
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError>;
    /// Save or update a session.
    async fn save_session(&self, session: &Session) -> Result<(), AuthError>;
    /// Delete a session by its ID.
    async fn delete_session(&self, id: &str) -> Result<(), AuthError>;
}

#[async_trait]
impl<S: crate::store::KvStore<Session>> SessionStore for S {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        let session = self
            .get(id)
            .await
            .map_err(|e| AuthError::Session(e.to_string()))?;
        if let Some(ref s) = session {
            if s.expires_at <= chrono::Utc::now() {
                tracing::debug!("session expired in KvStore blanket load_session; deleting");
                let _ = self.delete(id).await;
                return Ok(None);
            }
        }
        Ok(session)
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let ttl_secs = (session.expires_at - chrono::Utc::now()).num_seconds();
        let ttl = std::time::Duration::from_secs(if ttl_secs > 0 { ttl_secs as u64 } else { 0 });
        self.set(&session.id, session.clone(), ttl)
            .await
            .map_err(|e| AuthError::Session(e.to_string()))
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        self.delete(id)
            .await
            .map_err(|e| AuthError::Session(e.to_string()))
    }
}

impl Session {
    /// Creates a new Session.
    pub fn new(id: String, identity: Identity, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            id,
            identity,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;
    use crate::store::KvStore;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    /// Verifies that `SessionConfig::default` generates distinct random keys and redacts Debug output.
    #[test]
    fn test_session_config_default_generates_random_keys() {
        let c1 = SessionConfig::default();
        let c2 = SessionConfig::default();
        assert_ne!(c1.state_encryption_key, c2.state_encryption_key);
        assert_ne!(c1.state_encryption_key, [0u8; 32]);
        let dbg = format!("{c1:?}");
        assert!(dbg.contains("[REDACTED]"));
    }

    /// Verifies that `SessionConfig::new` preserves an explicit key.
    #[test]
    fn test_session_config_new_preserves_explicit_key() {
        let key = [42u8; 32];
        let cfg = SessionConfig::new(key);
        assert_eq!(cfg.state_encryption_key, key);
    }

    #[test]
    fn session_config_debug_redacts_state_encryption_key() {
        let mut config = SessionConfig::default();
        config.state_encryption_key = [0x42; 32];
        let debug_output = format!("{config:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("66"));
    }

    /// Verifies relative URL validation and `resolve_redirect_target` fallback rules.
    #[test]
    fn test_is_safe_relative_url() {
        assert!(is_safe_relative_url("/"));
        assert!(is_safe_relative_url("/dashboard"));
        assert!(is_safe_relative_url("/app/settings?tab=security"));
        assert!(is_safe_relative_url("/path#fragment"));

        // Open redirect attack vectors
        assert!(!is_safe_relative_url(""));
        assert!(!is_safe_relative_url("https://attacker.com"));
        assert!(!is_safe_relative_url("http://attacker.com"));
        assert!(!is_safe_relative_url("//attacker.com"));
        assert!(!is_safe_relative_url("//evil.com/path"));
        assert!(!is_safe_relative_url("/\\attacker.com"));
        assert!(!is_safe_relative_url("/foo\\bar"));
        assert!(!is_safe_relative_url("javascript:alert(1)"));
        assert!(!is_safe_relative_url("/path\r\nLocation: attacker.com"));
        assert!(!is_safe_relative_url("/path\x00null"));

        assert_eq!(
            resolve_redirect_target(Some("/profile"), "/default"),
            "/profile"
        );
        assert_eq!(
            resolve_redirect_target(Some("https://evil.com"), "/default"),
            "/default"
        );
        assert_eq!(resolve_redirect_target(Some("https://evil.com"), ""), "/");
        assert_eq!(resolve_redirect_target(None, "/home"), "/home");
        assert_eq!(resolve_redirect_target(None, ""), "/");
    }

    /// Verifies that expired sessions in `KvStore` blanket `SessionStore` impl are rejected and removed.
    #[tokio::test]
    async fn test_kv_store_session_store_expired_session_is_rejected_and_deleted() {
        let store = MemoryStore::<Session>::new();
        let identity = Identity {
            provider_id: "test".to_string(),
            external_id: "user1".to_string(),
            username: Some("user1".to_string()),
            email: None,
            attributes: HashMap::new(),
        };

        // Save expired session directly into KV store
        let expired_session = Session::new(
            "sess_expired".to_string(),
            identity.clone(),
            Utc::now() - Duration::minutes(10),
        );
        // Put in KV store with positive TTL so it's physically present
        store
            .set(
                &expired_session.id,
                expired_session.clone(),
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // load_session via SessionStore trait should reject and delete it
        let loaded = store.load_session("sess_expired").await.unwrap();
        assert!(loaded.is_none(), "expired session must return None");

        // Verify it was cleaned up
        let raw = store.get("sess_expired").await.unwrap();
        assert!(raw.is_none(), "expired session should have been deleted");

        // Valid session works
        let valid_session = Session::new(
            "sess_valid".to_string(),
            identity,
            Utc::now() + Duration::minutes(30),
        );
        store.save_session(&valid_session).await.unwrap();
        let loaded_valid = store.load_session("sess_valid").await.unwrap();
        assert!(loaded_valid.is_some());
        assert_eq!(loaded_valid.unwrap().id, "sess_valid");
    }
}
