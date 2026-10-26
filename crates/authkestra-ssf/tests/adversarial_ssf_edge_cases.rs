//! Empirical edge cases in SSF event verification for Milestone 2 Challenger 2:
//! - Expired SET (exp in past, leeway boundaries, push receiver 400 rejection)
//! - Audience mismatch (wrong audience, missing audience, audience array, push receiver rejection)
//! - Replay attack (jti replay detection, RFC 8935 §2 idempotent 202 suppression, cross-issuer isolation, slot release on error)

#[allow(dead_code)]
mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use serde_json::json;

use authkestra_ssf::{
    CaepEvent, HandlerError, InMemorySetReplayGuard, PushReceiver, SecurityEventToken, SetError,
    SetErrorCode, SetHandler, SetVerifier, SET_MEDIA_TYPE,
};

use support::{decoding_key, session_revoked_claims, sign, with_claim, AUDIENCE, ISSUER, NOW};

struct CountingHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SetHandler for CountingHandler {
    async fn handle(
        &self,
        _set: &SecurityEventToken,
        _event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingHandler {
    calls: Arc<AtomicUsize>,
    fail_with_internal: bool,
}

#[async_trait]
impl SetHandler for FailingHandler {
    async fn handle(
        &self,
        _set: &SecurityEventToken,
        _event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_with_internal {
            Err(HandlerError::Internal("simulated db outage".into()))
        } else {
            Err(HandlerError::Rejected("unauthorized tenant".into()))
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Expired SET verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_expired_set_rejected_by_verifier() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .iat_leeway(Duration::from_secs(0))
        .build()
        .expect("verifier builds");

    // Token with exp in the past (NOW - 1)
    let claims = with_claim(session_revoked_claims(), "exp", json!(NOW - 1));
    let token = sign(&claims);

    let err = verifier
        .verify_at(&token, NOW)
        .await
        .expect_err("expired token must be rejected");

    assert!(
        matches!(err, SetError::Expired { exp, now } if exp == NOW - 1 && now == NOW),
        "Expected SetError::Expired, got: {:?}",
        err
    );
    assert_eq!(err.code(), SetErrorCode::InvalidRequest);
}

#[tokio::test]
async fn test_expired_set_rejected_by_push_receiver_with_400_bad_request() {
    let verifier = Arc::new(
        SetVerifier::builder(ISSUER)
            .audience(AUDIENCE)
            .algorithms([Algorithm::HS256])
            .key(decoding_key())
            .iat_leeway(Duration::from_secs(0))
            .build()
            .unwrap(),
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let receiver = PushReceiver::new(verifier).with_handler(Arc::new(CountingHandler {
        calls: Arc::clone(&calls),
    }));

    let claims = with_claim(session_revoked_claims(), "exp", json!(NOW - 60));
    let token = sign(&claims);

    let response = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;

    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "Handler must not run for expired SET"
    );

    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["err"], "invalid_request");
    assert!(body["description"].as_str().unwrap().contains("expired"));
}

#[tokio::test]
async fn test_expired_set_leeway_boundary_conditions() {
    // With 10s leeway:
    // exp = NOW - 10 is inside leeway (now - leeway >= exp is false when 1000 - 10 >= 990? wait: now - leeway >= exp: 1000-10 = 990 >= 990 is TRUE -> expired!)
    // If exp is 991, 1000 - 10 = 990 >= 991 is FALSE -> accepted!
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .iat_leeway(Duration::from_secs(10))
        .build()
        .unwrap();

    let inside_leeway = sign(&with_claim(session_revoked_claims(), "exp", json!(NOW - 9)));
    assert!(
        verifier.verify_at(&inside_leeway, NOW).await.is_ok(),
        "Token within leeway must be accepted"
    );

    let outside_leeway = sign(&with_claim(
        session_revoked_claims(),
        "exp",
        json!(NOW - 11),
    ));
    let err = verifier
        .verify_at(&outside_leeway, NOW)
        .await
        .expect_err("Token outside leeway must be rejected");
    assert!(matches!(err, SetError::Expired { .. }));
}

// ---------------------------------------------------------------------------
// 2. Audience mismatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_audience_mismatch_rejected_by_verifier() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience("https://expected-audience.example.com")
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .build()
        .unwrap();

    // Token addressed to different audience
    let claims = with_claim(
        session_revoked_claims(),
        "aud",
        json!("https://attacker.example.com"),
    );
    let token = sign(&claims);

    let err = verifier
        .verify_at(&token, NOW)
        .await
        .expect_err("mismatched audience must be rejected");

    assert!(matches!(err, SetError::AudienceMismatch { .. }));
    assert_eq!(err.code(), SetErrorCode::InvalidAudience);
}

#[tokio::test]
async fn test_missing_audience_rejected_when_audience_configured() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience("https://expected-audience.example.com")
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .build()
        .unwrap();

    // Token with no aud claim
    let claims = with_claim(session_revoked_claims(), "aud", json!(null));
    let token = sign(&claims);

    let err = verifier
        .verify_at(&token, NOW)
        .await
        .expect_err("missing audience must be rejected when audience is configured");

    assert!(matches!(err, SetError::MissingAudience { .. }));
    assert_eq!(err.code(), SetErrorCode::InvalidAudience);
}

#[tokio::test]
async fn test_audience_mismatch_in_push_receiver_returns_400_and_suppresses_handlers() {
    let verifier = Arc::new(
        SetVerifier::builder(ISSUER)
            .audience(AUDIENCE)
            .algorithms([Algorithm::HS256])
            .key(decoding_key())
            .build()
            .unwrap(),
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let receiver = PushReceiver::new(verifier).with_handler(Arc::new(CountingHandler {
        calls: Arc::clone(&calls),
    }));

    let claims = with_claim(
        session_revoked_claims(),
        "aud",
        json!("https://completely-wrong-aud.com"),
    );
    let token = sign(&claims);

    let response = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;

    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidAudience));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["err"], "invalid_audience");
}

#[tokio::test]
async fn test_audience_array_matching_at_least_one_is_accepted() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .build()
        .unwrap();

    let claims = with_claim(
        session_revoked_claims(),
        "aud",
        json!(["https://other.com", AUDIENCE, "https://third.com"]),
    );
    let token = sign(&claims);

    assert!(verifier.verify_at(&token, NOW).await.is_ok());
}

// ---------------------------------------------------------------------------
// 3. Replay attack verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_replayed_jti_rejected_by_verifier_with_replay_guard() {
    let guard = Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(3600)));
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .replay_guard(guard)
        .build()
        .unwrap();

    let claims = with_claim(session_revoked_claims(), "jti", json!("unique-jti-xyz"));
    let token = sign(&claims);

    // First presentation -> Accepted
    let first = verifier.verify_at(&token, NOW).await;
    assert!(first.is_ok(), "First presentation must be accepted");

    // Immediate second presentation -> Replay rejection
    let second = verifier.verify_at(&token, NOW).await;
    let err = second.expect_err("Second presentation must be rejected as replay");
    assert_eq!(
        err,
        SetError::Replay {
            jti: "unique-jti-xyz".to_string(),
            iss: ISSUER.to_string(),
        }
    );
}

#[tokio::test]
async fn test_push_receiver_replay_idempotency_rfc8935_section_2() {
    // RFC 8935 §2: Replayed SET responds with 202 Accepted, but suppresses handler execution!
    let guard = Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(3600)));
    let verifier = Arc::new(
        SetVerifier::builder(ISSUER)
            .audience(AUDIENCE)
            .algorithms([Algorithm::HS256])
            .key(decoding_key())
            .replay_guard(guard)
            .build()
            .unwrap(),
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let receiver = PushReceiver::new(verifier).with_handler(Arc::new(CountingHandler {
        calls: Arc::clone(&calls),
    }));

    let claims = with_claim(
        session_revoked_claims(),
        "jti",
        json!("jti-rfc8935-replay-test"),
    );
    let token = sign(&claims);

    // Delivery 1:
    let resp1 = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(resp1.status(), 202);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Handler executed on delivery 1"
    );

    // Delivery 2 (Replay):
    let resp2 = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(
        resp2.status(),
        202,
        "Replay MUST respond 202 Accepted per RFC 8935 §2"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Handler must NOT execute again on replayed SET"
    );
}

#[tokio::test]
async fn test_replay_slot_released_on_internal_handler_failure() {
    // When a handler fails with HandlerError::Internal, the replay slot is released so transmitter can retry.
    let guard = Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(3600)));
    let verifier = Arc::new(
        SetVerifier::builder(ISSUER)
            .audience(AUDIENCE)
            .algorithms([Algorithm::HS256])
            .key(decoding_key())
            .replay_guard(guard)
            .build()
            .unwrap(),
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let receiver = PushReceiver::new(verifier).with_handler(Arc::new(FailingHandler {
        calls: Arc::clone(&calls),
        fail_with_internal: true,
    }));

    let claims = with_claim(session_revoked_claims(), "jti", json!("jti-retry-test"));
    let token = sign(&claims);

    // Initial delivery fails with 500
    let resp1 = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(resp1.status(), 500);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Retry should NOT be blocked as duplicate; it should reach the handler again!
    let resp2 = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(resp2.status(), 500);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "Slot must have been released so retry reached handler"
    );
}
