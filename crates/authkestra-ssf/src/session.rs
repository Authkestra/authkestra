//! Session revocation handler for Shared Signals Framework (SSF) and CAEP events.

use async_trait::async_trait;
use authkestra_engine::auth::SessionStore;
use std::sync::Arc;

use crate::caep::{CaepEvent, ChangeType};
use crate::receiver::{HandlerError, SetHandler};
use crate::set::SecurityEventToken;
use crate::subject::SubjectIdentifier;

/// An SSF event handler that revokes active sessions in a [`SessionStore`]
/// upon receiving CAEP `SessionRevoked` or `CredentialChange` events.
pub struct SessionRevocationHandler {
    session_store: Arc<dyn SessionStore>,
}

impl SessionRevocationHandler {
    /// Creates a new `SessionRevocationHandler` backed by the provided [`SessionStore`].
    pub fn new(session_store: Arc<dyn SessionStore>) -> Self {
        Self { session_store }
    }

    /// Resolves a session or user identifier string from the event subject or SET-level claims.
    pub fn extract_identifier(set: &SecurityEventToken, event: &CaepEvent) -> Option<String> {
        let subject_opt = event.subject().or(set.sub_id.as_ref());
        if let Some(subject) = subject_opt {
            match subject {
                SubjectIdentifier::Opaque { id } => return Some(id.clone()),
                SubjectIdentifier::IssSub { sub, .. } => return Some(sub.clone()),
                SubjectIdentifier::Email { email } => return Some(email.clone()),
                SubjectIdentifier::PhoneNumber { phone_number } => {
                    return Some(phone_number.clone())
                }
                SubjectIdentifier::Other { raw, .. } => {
                    if let Some(id) = raw.get("id").and_then(|v| v.as_str()) {
                        return Some(id.to_string());
                    }
                    if let Some(sid) = raw.get("session_id").and_then(|v| v.as_str()) {
                        return Some(sid.to_string());
                    }
                }
            }
        }
        set.sub.clone()
    }
}

#[async_trait]
impl SetHandler for SessionRevocationHandler {
    async fn handle(
        &self,
        set: &SecurityEventToken,
        event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        let (should_revoke, reason) = match event {
            CaepEvent::SessionRevoked(_) => (true, "SessionRevoked"),
            CaepEvent::CredentialChange(cc) => {
                let matches_change =
                    matches!(cc.change_type, ChangeType::Revoke | ChangeType::Delete);
                (matches_change, "CredentialChange")
            }
            _ => (false, "none"),
        };

        if !should_revoke {
            return Ok(());
        }

        let Some(session_id) = Self::extract_identifier(set, event) else {
            tracing::warn!(
                target: "authkestra_ssf",
                iss = %set.iss,
                jti = %set.jti,
                event_type = %event.event_type_uri(),
                "SessionRevocationHandler: no identifier could be resolved from subject or sub claims"
            );
            return Ok(());
        };

        tracing::info!(
            target: "authkestra_ssf",
            session_id = %session_id,
            reason = %reason,
            iss = %set.iss,
            jti = %set.jti,
            event_type = %event.event_type_uri(),
            "SessionRevocationHandler: revoking session"
        );

        self.session_store
            .delete_session(&session_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    target: "authkestra_ssf",
                    session_id = %session_id,
                    error = %e,
                    "SessionRevocationHandler: failed to delete session from store"
                );
                HandlerError::Internal(format!("Failed to delete session: {e}"))
            })?;

        tracing::info!(
            target: "authkestra_ssf",
            session_id = %session_id,
            "SessionRevocationHandler: session deleted successfully"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caep::{CaepMetadata, CredentialChange, CredentialType, SessionRevoked};
    use authkestra_engine::auth::state::Identity;
    use authkestra_engine::auth::Session;
    use authkestra_engine::chrono::{Duration, Utc};
    use authkestra_engine::store::memory::MemoryStore;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn test_session_revocation_on_session_revoked() {
        let store = Arc::new(MemoryStore::<Session>::new());
        let session = Session::new(
            "sess-123".to_string(),
            Identity {
                provider_id: "test".to_string(),
                external_id: "user-1".to_string(),
                email: None,
                username: None,
                attributes: Default::default(),
            },
            Utc::now() + Duration::hours(1),
        );
        store.save_session(&session).await.unwrap();
        assert!(store.load_session("sess-123").await.unwrap().is_some());

        let handler = SessionRevocationHandler::new(store.clone());

        let mut set = SecurityEventToken::new(
            "https://idp.example.com",
            "jti-1",
            Utc::now().timestamp(),
            BTreeMap::new(),
        );
        set.sub_id = Some(SubjectIdentifier::Opaque {
            id: "sess-123".to_string(),
        });

        let event = CaepEvent::SessionRevoked(SessionRevoked {
            metadata: CaepMetadata::default(),
        });

        handler.handle(&set, &event).await.unwrap();

        assert!(store.load_session("sess-123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_session_revocation_on_credential_change_revoke() {
        let store = Arc::new(MemoryStore::<Session>::new());
        let session = Session::new(
            "sess-456".to_string(),
            Identity {
                provider_id: "test".to_string(),
                external_id: "user-2".to_string(),
                email: None,
                username: None,
                attributes: Default::default(),
            },
            Utc::now() + Duration::hours(1),
        );
        store.save_session(&session).await.unwrap();

        let handler = SessionRevocationHandler::new(store.clone());

        let mut set = SecurityEventToken::new(
            "https://idp.example.com",
            "jti-2",
            Utc::now().timestamp(),
            BTreeMap::new(),
        );
        set.sub = Some("sess-456".to_string());

        let event = CaepEvent::CredentialChange(CredentialChange::new(
            CredentialType::Password,
            ChangeType::Revoke,
        ));

        handler.handle(&set, &event).await.unwrap();

        assert!(store.load_session("sess-456").await.unwrap().is_none());
    }
}
