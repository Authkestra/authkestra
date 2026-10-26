#![cfg(feature = "session")]

use std::collections::BTreeMap;
use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::{Session, SessionStore};
use authkestra_engine::chrono::{Duration, Utc};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_ssf::{
    CaepEvent, ChangeType, CredentialChange, CredentialType, PushReceiver, SecurityEventToken,
    SessionRevocationHandler, SessionRevoked, SetHandler, SetVerifier, SubjectIdentifier,
    SET_MEDIA_TYPE,
};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::json;

const ISSUER: &str = "https://issuer.example.com";
const AUDIENCE: &str = "https://receiver.example.com";
const SECRET: &[u8] = b"a-very-secret-key-for-empirical-testing-256";

fn make_test_session(id: &str) -> Session {
    Session::new(
        id.to_string(),
        Identity {
            provider_id: "test".to_string(),
            external_id: format!("user-{}", id),
            email: Some(format!("{}@example.com", id)),
            username: Some(id.to_string()),
            attributes: Default::default(),
        },
        Utc::now() + Duration::hours(1),
    )
}

#[tokio::test]
async fn test_challenger_session_revoked_and_credential_change_deletions() {
    let store = Arc::new(MemoryStore::<Session>::new());
    let handler = SessionRevocationHandler::new(store.clone());

    // 1. SessionRevoked event deletes session
    let s1 = make_test_session("sess-revoke-1");
    store.save_session(&s1).await.unwrap();
    assert!(store.load_session("sess-revoke-1").await.unwrap().is_some());

    let mut set1 =
        SecurityEventToken::new(ISSUER, "jti-1", Utc::now().timestamp(), BTreeMap::new());
    set1.sub_id = Some(SubjectIdentifier::Opaque {
        id: "sess-revoke-1".to_string(),
    });
    let ev1 = CaepEvent::SessionRevoked(SessionRevoked::default());
    handler
        .handle(&set1, &ev1)
        .await
        .expect("handle SessionRevoked");
    assert!(
        store.load_session("sess-revoke-1").await.unwrap().is_none(),
        "SessionRevoked must actively delete session from store"
    );

    // 2. CredentialChange with ChangeType::Revoke deletes session
    let s2 = make_test_session("sess-cred-revoke");
    store.save_session(&s2).await.unwrap();
    assert!(store
        .load_session("sess-cred-revoke")
        .await
        .unwrap()
        .is_some());

    let mut set2 =
        SecurityEventToken::new(ISSUER, "jti-2", Utc::now().timestamp(), BTreeMap::new());
    set2.sub = Some("sess-cred-revoke".to_string());
    let ev2 = CaepEvent::CredentialChange(CredentialChange::new(
        CredentialType::Password,
        ChangeType::Revoke,
    ));
    handler
        .handle(&set2, &ev2)
        .await
        .expect("handle CredentialChange Revoke");
    assert!(
        store
            .load_session("sess-cred-revoke")
            .await
            .unwrap()
            .is_none(),
        "CredentialChange Revoke must actively delete session from store"
    );

    // 3. CredentialChange with ChangeType::Delete deletes session
    let s3 = make_test_session("sess-cred-delete");
    store.save_session(&s3).await.unwrap();
    assert!(store
        .load_session("sess-cred-delete")
        .await
        .unwrap()
        .is_some());

    let mut set3 =
        SecurityEventToken::new(ISSUER, "jti-3", Utc::now().timestamp(), BTreeMap::new());
    set3.sub_id = Some(SubjectIdentifier::IssSub {
        iss: ISSUER.to_string(),
        sub: "sess-cred-delete".to_string(),
    });
    let ev3 = CaepEvent::CredentialChange(CredentialChange::new(
        CredentialType::Fido2Platform,
        ChangeType::Delete,
    ));
    handler
        .handle(&set3, &ev3)
        .await
        .expect("handle CredentialChange Delete");
    assert!(
        store
            .load_session("sess-cred-delete")
            .await
            .unwrap()
            .is_none(),
        "CredentialChange Delete must actively delete session from store"
    );

    // 4. CredentialChange with ChangeType::Create does NOT delete session
    let s4 = make_test_session("sess-cred-create");
    store.save_session(&s4).await.unwrap();
    let mut set4 =
        SecurityEventToken::new(ISSUER, "jti-4", Utc::now().timestamp(), BTreeMap::new());
    set4.sub = Some("sess-cred-create".to_string());
    let ev4 = CaepEvent::CredentialChange(CredentialChange::new(
        CredentialType::Fido2Platform,
        ChangeType::Create,
    ));
    handler
        .handle(&set4, &ev4)
        .await
        .expect("handle CredentialChange Create");
    assert!(
        store
            .load_session("sess-cred-create")
            .await
            .unwrap()
            .is_some(),
        "CredentialChange Create must NOT delete session from store"
    );

    // 5. CredentialChange with ChangeType::Update does NOT delete session
    let s5 = make_test_session("sess-cred-update");
    store.save_session(&s5).await.unwrap();
    let mut set5 =
        SecurityEventToken::new(ISSUER, "jti-5", Utc::now().timestamp(), BTreeMap::new());
    set5.sub = Some("sess-cred-update".to_string());
    let ev5 = CaepEvent::CredentialChange(CredentialChange::new(
        CredentialType::Password,
        ChangeType::Update,
    ));
    handler
        .handle(&set5, &ev5)
        .await
        .expect("handle CredentialChange Update");
    assert!(
        store
            .load_session("sess-cred-update")
            .await
            .unwrap()
            .is_some(),
        "CredentialChange Update must NOT delete session from store"
    );
}

#[tokio::test]
async fn test_challenger_push_receiver_end_to_end_verification_and_rejections() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(DecodingKey::from_secret(SECRET))
        .build()
        .expect("verifier build");

    let store = Arc::new(MemoryStore::<Session>::new());
    let s1 = make_test_session("active-session-99");
    store.save_session(&s1).await.unwrap();
    assert!(store
        .load_session("active-session-99")
        .await
        .unwrap()
        .is_some());

    let handler = Arc::new(SessionRevocationHandler::new(store.clone()));
    let receiver = PushReceiver::new(Arc::new(verifier)).with_handler(handler);

    // A. Valid signed SET delivery -> 202 Accepted and session deleted
    let now = Utc::now().timestamp();
    let header = Header {
        typ: Some("secevent+jwt".to_string()),
        ..Header::new(Algorithm::HS256)
    };
    let claims = json!({
        "iss": ISSUER,
        "jti": "jti-valid-push",
        "iat": now,
        "aud": AUDIENCE,
        "events": {
            authkestra_ssf::EVENT_TYPE_SESSION_REVOKED: {
                "subject": { "format": "opaque", "id": "active-session-99" },
                "initiating_entity": "policy",
                "event_timestamp": now
            }
        }
    });
    let valid_token = encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap();

    let resp_ok = receiver
        .receive(Some(SET_MEDIA_TYPE), valid_token.as_bytes())
        .await;
    assert_eq!(resp_ok.status(), 202);
    assert!(store
        .load_session("active-session-99")
        .await
        .unwrap()
        .is_none());

    // B. Replayed SET delivery -> 202 Accepted (idempotent, per RFC 8935 §2)
    let resp_replay = receiver
        .receive(Some(SET_MEDIA_TYPE), valid_token.as_bytes())
        .await;
    assert_eq!(resp_replay.status(), 202);

    // C. Malformed token (garbage string) -> 400 Bad Request
    let resp_garbage = receiver
        .receive(Some(SET_MEDIA_TYPE), b"definitely-not-a-jwt")
        .await;
    assert_eq!(resp_garbage.status(), 400);

    // D. Truncated token -> 400 Bad Request
    let resp_truncated = receiver
        .receive(Some(SET_MEDIA_TYPE), b"eyJhbGciOiJIUzI1NiJ9.")
        .await;
    assert_eq!(resp_truncated.status(), 400);

    // E. Invalid signature (signed with different key) -> 400 Bad Request
    let bad_token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(b"wrong-secret-key-wrong-secret-key-256"),
    )
    .unwrap();
    let resp_bad_sig = receiver
        .receive(Some(SET_MEDIA_TYPE), bad_token.as_bytes())
        .await;
    assert_eq!(resp_bad_sig.status(), 400);

    // F. Invalid content type -> 400 Bad Request
    let resp_ct_json = receiver
        .receive(Some("application/json"), valid_token.as_bytes())
        .await;
    assert_eq!(resp_ct_json.status(), 400);

    let resp_ct_none = receiver.receive(None, valid_token.as_bytes()).await;
    assert_eq!(resp_ct_none.status(), 400);
}
