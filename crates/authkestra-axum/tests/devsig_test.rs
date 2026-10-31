use async_trait::async_trait;
use authkestra_axum::devsig::{refusal_response, DeviceSignatureLayer};
use authkestra_devsig::{IssuerJwks, Refusal, ReplayError, ReplayStore, VerifierConfig};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

struct DummyStore;
#[async_trait]
impl ReplayStore for DummyStore {
    async fn put_if_absent(&self, _jti: &str, _ttl: Duration) -> Result<bool, ReplayError> {
        Ok(true)
    }
}

#[tokio::test]
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

    let layer = DeviceSignatureLayer::new(config, jwks, store);

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();

    // Device-signature profile v1: a JSON body a client can sort by, and a challenge.
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(res.headers()["content-type"], "application/json");
    assert_eq!(
        res.headers()["www-authenticate"],
        r#"DeviceSignature error="missing_credential""#
    );
    assert_eq!(body_of(res).await, r#"{"error":"missing_credential"}"#);
}

#[tokio::test]
async fn refusal_response_answers_the_application_refusals_in_profile_v1_shape() {
    let res = refusal_response(Refusal::device_revoked());
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(res.headers().get("www-authenticate").is_none());
    assert_eq!(body_of(res).await, r#"{"error":"device_revoked"}"#);

    let res = refusal_response(Refusal::insufficient_user_authentication());
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers()["www-authenticate"],
        r#"DeviceSignature error="insufficient_user_authentication""#
    );
    assert_eq!(
        body_of(res).await,
        r#"{"error":"insufficient_user_authentication"}"#
    );
}

async fn body_of(res: axum::response::Response) -> String {
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
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

    let layer = DeviceSignatureLayer::new(config, jwks, store).max_body_size(10);

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let req = Request::builder()
        .uri("/")
        .body(Body::from("this body is clearly more than 10 bytes"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();

    // Not an authentication failure, so no challenge; still the profile v1 JSON body.
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(res.headers().get("www-authenticate").is_none());
    assert_eq!(body_of(res).await, r#"{"error":"body_too_large"}"#);
}
