use actix_web::dev::Service;
use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use async_trait::async_trait;
use authkestra_actix::devsig::{refusal_response, DeviceSignatureAuth};
use authkestra_devsig::{IssuerJwks, Refusal, ReplayError, ReplayStore, VerifierConfig};
use std::sync::Arc;
use std::time::Duration;

struct DummyStore;
#[async_trait]
impl ReplayStore for DummyStore {
    async fn put_if_absent(&self, _jti: &str, _ttl: Duration) -> Result<bool, ReplayError> {
        Ok(true)
    }
}

#[actix_web::test]
async fn test_devsig_rejects_missing_signature() {
    let config = VerifierConfig::new(
        vec!["http://issuer".to_string()],
        vec![],
        Duration::from_secs(5),
        Duration::from_secs(60),
        "audience",
    );
    let jwks = Arc::new(IssuerJwks::new());
    let store = Arc::new(DummyStore);

    let layer = DeviceSignatureAuth::new(config, jwks, store);

    let app = test::init_service(
        App::new()
            .wrap(layer)
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let err = app.call(req).await.unwrap_err();
    let res = err.error_response();

    // Device-signature profile v1: a JSON body a client can sort by, and a challenge.
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(
        res.headers().get("www-authenticate").unwrap(),
        r#"DeviceSignature error="missing_credential""#
    );
    let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
    assert_eq!(body, r#"{"error":"missing_credential"}"#);
}

#[actix_web::test]
async fn refusal_response_answers_the_application_refusals_in_profile_v1_shape() {
    let res = refusal_response(Refusal::device_revoked());
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(res.headers().get("www-authenticate").is_none());
    let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
    assert_eq!(body, r#"{"error":"device_revoked"}"#);

    let res = refusal_response(Refusal::insufficient_user_authentication());
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers().get("www-authenticate").unwrap(),
        r#"DeviceSignature error="insufficient_user_authentication""#
    );
}

#[actix_web::test]
async fn test_devsig_rejects_too_large_body() {
    let config = VerifierConfig::new(
        vec!["http://issuer".to_string()],
        vec![],
        Duration::from_secs(5),
        Duration::from_secs(60),
        "audience",
    );
    let jwks = Arc::new(IssuerJwks::new());
    let store = Arc::new(DummyStore);

    let layer = DeviceSignatureAuth::new(config, jwks, store).max_body_size(10);

    let app = test::init_service(
        App::new()
            .wrap(layer)
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .set_payload("this body is clearly more than 10 bytes")
        .to_request();
    let err = app.call(req).await.unwrap_err();
    let res = err.error_response();

    // Not an authentication failure, so no challenge; still the profile v1 JSON body.
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(res.headers().get("www-authenticate").is_none());
    let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
    assert_eq!(body, r#"{"error":"body_too_large"}"#);
}
