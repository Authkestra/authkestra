//! Session revocation handler for Shared Signals Framework (SSF) and CAEP events.

use async_trait::async_trait;
use authkestra_engine::auth::SessionStore;
use std::sync::Arc;

use crate::caep::{CaepEvent, ChangeType};
use crate::receiver::{HandlerError, SetHandler};
use crate::set::SecurityEventToken;
use crate::subject::SubjectIdentifier;

/// Resolves SSF / CAEP subject identifiers to local session IDs.
///
/// By default, [`SessionRevocationHandler`] only revokes sessions where the subject
/// is an explicit session identifier (e.g. [`SubjectIdentifier::Opaque`] or `"session_id"`).
/// User-scoped subjects ([`SubjectIdentifier::IssSub`], [`SubjectIdentifier::Email`], etc.)
/// cannot be mapped to individual session IDs without application-specific indexing or bindings.
/// Applications wishing to revoke all sessions for a user upon receiving user-scoped events
/// can implement this trait and register it via [`SessionRevocationHandler::with_resolver`].
#[async_trait]
pub trait SessionSubjectResolver: Send + Sync + 'static {
    /// Resolves the provided subject identifier (or SET-level claims) to one or more active session IDs.
    async fn resolve_sessions(
        &self,
        set: &SecurityEventToken,
        event: &CaepEvent,
        subject: Option<&SubjectIdentifier>,
    ) -> Result<Vec<String>, HandlerError>;
}

/// An SSF event handler that revokes active sessions in a [`SessionStore`]
/// upon receiving CAEP `SessionRevoked` or `CredentialChange` events.
pub struct SessionRevocationHandler {
    session_store: Arc<dyn SessionStore>,
    resolver: Option<Arc<dyn SessionSubjectResolver>>,
}

impl SessionRevocationHandler {
    /// Creates a new `SessionRevocationHandler` backed by the provided [`SessionStore`].
    /// Direct opaque session identifiers will be deleted, while user-scoped identifiers will fail
    /// closed with [`HandlerError::Rejected`].
    pub fn new(session_store: Arc<dyn SessionStore>) -> Self {
        Self {
            session_store,
            resolver: None,
        }
    }

    /// Creates a new `SessionRevocationHandler` with a custom [`SessionSubjectResolver`]
    /// for resolving user-scoped subject identifiers into local session IDs.
    pub fn with_resolver(
        session_store: Arc<dyn SessionStore>,
        resolver: Arc<dyn SessionSubjectResolver>,
    ) -> Self {
        Self {
            session_store,
            resolver: Some(resolver),
        }
    }

    /// Resolves a direct session identifier string from an opaque subject identifier or returns None.
    /// User-scoped subjects without an explicit resolver reject with [`HandlerError::Rejected`].
    pub fn extract_identifier(
        set: &SecurityEventToken,
        event: &CaepEvent,
    ) -> Result<Option<String>, HandlerError> {
        let subject_opt = event.subject().or(set.sub_id.as_ref());
        if let Some(subject) = subject_opt {
            match subject {
                SubjectIdentifier::Opaque { id } => return Ok(Some(id.clone())),
                SubjectIdentifier::Other { raw, .. } => {
                    if let Some(sid) = raw.get("session_id").and_then(|v| v.as_str()) {
                        return Ok(Some(sid.to_string()));
                    }
                    if let Some(id) = raw.get("id").and_then(|v| v.as_str()) {
                        return Ok(Some(id.to_string()));
                    }
                    return Err(HandlerError::Rejected(
                        "Unsupported subject identifier in Other format: missing 'session_id' or 'id'".to_string()
                    ));
                }
                SubjectIdentifier::IssSub { sub, iss } => {
                    return Err(HandlerError::Rejected(format!(
                        "Cannot resolve user-scoped IssSub subject (iss: {iss}, sub: {sub}) to session IDs without a configured SessionSubjectResolver"
                    )));
                }
                SubjectIdentifier::Email { email } => {
                    return Err(HandlerError::Rejected(format!(
                        "Cannot resolve user-scoped Email subject ({email}) to session IDs without a configured SessionSubjectResolver"
                    )));
                }
                SubjectIdentifier::PhoneNumber { phone_number } => {
                    return Err(HandlerError::Rejected(format!(
                        "Cannot resolve user-scoped PhoneNumber subject ({phone_number}) to session IDs without a configured SessionSubjectResolver"
                    )));
                }
            }
        }
        if let Some(ref sub) = set.sub {
            return Ok(Some(sub.clone()));
        }
        Ok(None)
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

        let session_ids = if let Some(ref resolver) = self.resolver {
            let subject_opt = event.subject().or(set.sub_id.as_ref());
            resolver.resolve_sessions(set, event, subject_opt).await?
        } else {
            match Self::extract_identifier(set, event)? {
                Some(id) => vec![id],
                None => {
                    tracing::warn!(
                        target: "authkestra_ssf",
                        iss = %set.iss,
                        jti = %set.jti,
                        event_type = %event.event_type_uri(),
                        "SessionRevocationHandler: no identifier could be resolved from subject or sub claims"
                    );
                    return Ok(());
                }
            }
        };

        if session_ids.is_empty() {
            tracing::warn!(
                target: "authkestra_ssf",
                iss = %set.iss,
                jti = %set.jti,
                event_type = %event.event_type_uri(),
                "SessionRevocationHandler: subject resolver returned 0 session IDs"
            );
            return Ok(());
        }

        for session_id in session_ids {
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
        }

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

    #[tokio::test]
    async fn test_session_revocation_rejects_user_scoped_without_resolver() {
        let store = Arc::new(MemoryStore::<Session>::new());
        let handler = SessionRevocationHandler::new(store);

        let mut set = SecurityEventToken::new(
            "https://idp.example.com",
            "jti-iss-sub",
            Utc::now().timestamp(),
            BTreeMap::new(),
        );
        set.sub_id = Some(SubjectIdentifier::IssSub {
            iss: "https://idp.example.com".to_string(),
            sub: "user-42".to_string(),
        });

        let event = CaepEvent::SessionRevoked(SessionRevoked {
            metadata: CaepMetadata::default(),
        });

        let err = handler.handle(&set, &event).await.unwrap_err();
        match err {
            HandlerError::Rejected(msg) => {
                assert!(msg.contains("Cannot resolve user-scoped IssSub subject"));
            }
            other => panic!("Expected HandlerError::Rejected, got {other:?}"),
        }

        // Test with Email
        set.sub_id = Some(SubjectIdentifier::Email {
            email: "alice@example.com".to_string(),
        });
        let err = handler.handle(&set, &event).await.unwrap_err();
        assert!(matches!(err, HandlerError::Rejected(_)));

        // Test with PhoneNumber
        set.sub_id = Some(SubjectIdentifier::PhoneNumber {
            phone_number: "+15551234567".to_string(),
        });
        let err = handler.handle(&set, &event).await.unwrap_err();
        assert!(matches!(err, HandlerError::Rejected(_)));
    }

    struct MockUserSessionResolver;

    #[async_trait]
    impl SessionSubjectResolver for MockUserSessionResolver {
        async fn resolve_sessions(
            &self,
            _set: &SecurityEventToken,
            _event: &CaepEvent,
            subject: Option<&SubjectIdentifier>,
        ) -> Result<Vec<String>, HandlerError> {
            match subject {
                Some(SubjectIdentifier::Email { email }) if email == "alice@example.com" => {
                    Ok(vec![
                        "sess-alice-web".to_string(),
                        "sess-alice-mobile".to_string(),
                    ])
                }
                _ => Ok(vec![]),
            }
        }
    }

    #[tokio::test]
    async fn test_session_revocation_with_custom_resolver() {
        let store = Arc::new(MemoryStore::<Session>::new());
        for id in ["sess-alice-web", "sess-alice-mobile", "sess-bob"] {
            let session = Session::new(
                id.to_string(),
                Identity {
                    provider_id: "test".to_string(),
                    external_id: "ext".to_string(),
                    email: None,
                    username: None,
                    attributes: Default::default(),
                },
                Utc::now() + Duration::hours(1),
            );
            store.save_session(&session).await.unwrap();
        }

        let handler = SessionRevocationHandler::with_resolver(
            store.clone(),
            Arc::new(MockUserSessionResolver),
        );

        let mut set = SecurityEventToken::new(
            "https://idp.example.com",
            "jti-email-event",
            Utc::now().timestamp(),
            BTreeMap::new(),
        );
        set.sub_id = Some(SubjectIdentifier::Email {
            email: "alice@example.com".to_string(),
        });

        let event = CaepEvent::SessionRevoked(SessionRevoked {
            metadata: CaepMetadata::default(),
        });

        handler.handle(&set, &event).await.unwrap();

        // Alice's two sessions should be deleted, Bob's remains
        assert!(store
            .load_session("sess-alice-web")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .load_session("sess-alice-mobile")
            .await
            .unwrap()
            .is_none());
        assert!(store.load_session("sess-bob").await.unwrap().is_some());
    }
}
