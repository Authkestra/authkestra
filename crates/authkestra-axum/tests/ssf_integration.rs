use authkestra_axum::ssf_axum_router;
use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::{Session, SessionStore};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_ssf::{
    session::SessionRevocationHandler, PushReceiver, SetVerifier, EVENT_TYPE_SESSION_REVOKED,
    SET_MEDIA_TYPE,
};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

const ISSUER: &str = "https://idp.example.com/";
const AUDIENCE: &str = "https://sp.example.com/caep";
const SECRET: &[u8] = b"a-test-secret-key-for-testing-ssf-routes-256";

fn mint_test_set(session_id: &str) -> String {
    let now = Utc::now().timestamp();
    let header = Header {
        typ: Some("secevent+jwt".to_string()),
        ..Header::new(Algorithm::HS256)
    };
    let claims = json!({
        "iss": ISSUER,
        "jti": format!("jti-{}", uuid::Uuid::new_v4()),
        "iat": now,
        "aud": AUDIENCE,
        "events": {
            EVENT_TYPE_SESSION_REVOKED: {
                "subject": { "format": "opaque", "id": session_id },
                "initiating_entity": "policy",
                "event_timestamp": now
            }
        }
    });

    encode(&header, &claims, &EncodingKey::from_secret(SECRET)).expect("valid JWT")
}

#[tokio::test]
async fn test_axum_ssf_receiver_routes_and_revocation() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(DecodingKey::from_secret(SECRET))
        .build()
        .expect("verifier build");

    let session_store = Arc::new(MemoryStore::<Session>::new());
    let session = Session::new(
        "sess-axum-1".to_string(),
        Identity {
            provider_id: "test".to_string(),
            external_id: "user-1".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        },
        Utc::now() + Duration::hours(1),
    );
    session_store.save_session(&session).await.unwrap();
    assert!(session_store
        .load_session("sess-axum-1")
        .await
        .unwrap()
        .is_some());

    let revocation_handler = Arc::new(SessionRevocationHandler::new(session_store.clone()));
    let receiver = Arc::new(PushReceiver::new(Arc::new(verifier)).with_handler(revocation_handler));

    let app = ssf_axum_router(receiver);

    let token = mint_test_set("sess-axum-1");

    // 1. Post to /.well-known/ssf/events
    let req = Request::builder()
        .method("POST")
        .uri("/.well-known/ssf/events")
        .header(header::CONTENT_TYPE, SET_MEDIA_TYPE)
        .body(Body::from(token))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Verify session revoked from store
    assert!(session_store
        .load_session("sess-axum-1")
        .await
        .unwrap()
        .is_none());

    // 2. Add second session and post to /ssf/events
    let session2 = Session::new(
        "sess-axum-2".to_string(),
        Identity {
            provider_id: "test".to_string(),
            external_id: "user-2".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        },
        Utc::now() + Duration::hours(1),
    );
    session_store.save_session(&session2).await.unwrap();

    let token2 = mint_test_set("sess-axum-2");
    let req2 = Request::builder()
        .method("POST")
        .uri("/ssf/events")
        .header(header::CONTENT_TYPE, SET_MEDIA_TYPE)
        .body(Body::from(token2))
        .unwrap();

    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::ACCEPTED);
    assert!(session_store
        .load_session("sess-axum-2")
        .await
        .unwrap()
        .is_none());

    // 3. Post with wrong content-type -> 400 Bad Request
    let req_bad = Request::builder()
        .method("POST")
        .uri("/ssf/events")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("not-a-token"))
        .unwrap();

    let resp_bad = app.oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::BAD_REQUEST);
}
