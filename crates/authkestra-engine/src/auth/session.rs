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

impl Default for SessionConfig {
    fn default() -> Self {
        let mut key = [0u8; 32];
        // In a real app, this should be loaded from env.
        // For default/dev, we use a fixed but "not secure" key or random.
        // To support horizontal scaling, it MUST be consistent across instances.
        key.copy_from_slice(b"static_key_change_in_production!");

        Self {
            cookie_name: "authkestra_session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
            state_encryption_key: key,
        }
    }
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
        self.get(id)
            .await
            .map_err(|e| AuthError::Session(e.to_string()))
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

    #[test]
    fn session_config_debug_redacts_state_encryption_key() {
        let mut config = SessionConfig::default();
        config.state_encryption_key = [0x42; 32];
        let debug_output = format!("{config:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("66"));
    }
}
