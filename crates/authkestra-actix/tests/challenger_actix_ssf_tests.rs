use actix_web::{http::header, http::StatusCode, test, App};
use authkestra_actix::ssf_actix_scope;
use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::{Session, SessionStore};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_ssf::{
    session::SessionRevocationHandler, PushReceiver, SetVerifier, EVENT_TYPE_CREDENTIAL_CHANGE,
    SET_MEDIA_TYPE,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;

const ISSUER: &str = "https://idp.example.com/";
const AUDIENCE: &str = "https://sp.example.com/caep";
const SECRET: &[u8] = b"a-test-secret-key-for-testing-ssf-routes-256";

fn mint_credential_change_set(session_id: &str) -> String {
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
            EVENT_TYPE_CREDENTIAL_CHANGE: {
                "subject": { "format": "opaque", "id": session_id },
                "credential_type": "password",
                "change_type": "revoke",
                "initiating_entity": "admin",
                "event_timestamp": now
            }
        }
    });

    encode(&header, &claims, &EncodingKey::from_secret(SECRET)).expect("valid JWT")
}

#[actix_web::test]
async fn test_challenger_actix_push_receiver_malformed_and_invalid_content_types() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(DecodingKey::from_secret(SECRET))
        .build()
        .expect("verifier build");

    let session_store = Arc::new(MemoryStore::<Session>::new());
    let session = Session::new(
        "sess-actix-cred-revoke".to_string(),
        Identity {
            provider_id: "test".to_string(),
            external_id: "user-actix-1".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        },
        Utc::now() + Duration::hours(1),
    );
    session_store.save_session(&session).await.unwrap();
    assert!(session_store
        .load_session("sess-actix-cred-revoke")
        .await
        .unwrap()
        .is_some());

    let revocation_handler = Arc::new(SessionRevocationHandler::new(session_store.clone()));
    let receiver = Arc::new(PushReceiver::new(Arc::new(verifier)).with_handler(revocation_handler));

    let app = test::init_service(App::new().service(ssf_actix_scope(receiver))).await;

    // 1. Valid CredentialChange Revoke event -> 202 Accepted & session deleted
    let cred_token = mint_credential_change_set("sess-actix-cred-revoke");
    let req_cred = test::TestRequest::post()
        .uri("/.well-known/ssf/events")
        .insert_header((header::CONTENT_TYPE, SET_MEDIA_TYPE))
        .set_payload(cred_token)
        .to_request();

    let resp_cred = test::call_service(&app, req_cred).await;
    assert_eq!(resp_cred.status(), StatusCode::ACCEPTED);
    assert!(
        session_store
            .load_session("sess-actix-cred-revoke")
            .await
            .unwrap()
            .is_none(),
        "CredentialChange Revoke must delete session from store in Actix"
    );

    // 2. Malformed token (garbage bytes) with valid Content-Type -> 400 Bad Request
    let req_garbage = test::TestRequest::post()
        .uri("/ssf/events")
        .insert_header((header::CONTENT_TYPE, SET_MEDIA_TYPE))
        .set_payload("this-is-not-a-valid-jwt-token-at-all")
        .to_request();

    let resp_garbage = test::call_service(&app, req_garbage).await;
    assert_eq!(resp_garbage.status(), StatusCode::BAD_REQUEST);

    // 3. Truncated JWT token -> 400 Bad Request
    let req_truncated = test::TestRequest::post()
        .uri("/.well-known/ssf/events")
        .insert_header((header::CONTENT_TYPE, SET_MEDIA_TYPE))
        .set_payload("eyJhbGciOiJIUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCJ9.")
        .to_request();

    let resp_truncated = test::call_service(&app, req_truncated).await;
    assert_eq!(resp_truncated.status(), StatusCode::BAD_REQUEST);

    // 4. Invalid signature (signed with untrusted secret) -> 400 Bad Request
    let untrusted_header = Header {
        typ: Some("secevent+jwt".to_string()),
        ..Header::new(Algorithm::HS256)
    };
    let untrusted_claims = json!({
        "iss": ISSUER,
        "jti": "jti-untrusted-actix",
        "iat": Utc::now().timestamp(),
        "aud": AUDIENCE,
        "events": {}
    });
    let untrusted_token = encode(
        &untrusted_header,
        &untrusted_claims,
        &EncodingKey::from_secret(b"wrong-untrusted-secret-key-32-bytes!"),
    )
    .unwrap();

    let req_untrusted = test::TestRequest::post()
        .uri("/ssf/events")
        .insert_header((header::CONTENT_TYPE, SET_MEDIA_TYPE))
        .set_payload(untrusted_token)
        .to_request();

    let resp_untrusted = test::call_service(&app, req_untrusted).await;
    assert_eq!(resp_untrusted.status(), StatusCode::BAD_REQUEST);

    // 5. Invalid Content-Type: missing Content-Type header -> 400 Bad Request
    let req_no_ct = test::TestRequest::post()
        .uri("/ssf/events")
        .set_payload("any-payload")
        .to_request();

    let resp_no_ct = test::call_service(&app, req_no_ct).await;
    assert_eq!(resp_no_ct.status(), StatusCode::BAD_REQUEST);

    // 6. Invalid Content-Type: text/plain -> 400 Bad Request
    let req_text = test::TestRequest::post()
        .uri("/ssf/events")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("any-payload")
        .to_request();

    let resp_text = test::call_service(&app, req_text).await;
    assert_eq!(resp_text.status(), StatusCode::BAD_REQUEST);
}
