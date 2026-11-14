//! Adapter-level tests for RFC 9470 step-up challenges (`insufficient_user_authentication`)
//! and RFC 9449 §9 resource-side `DPoP-Nonce` challenges (`use_dpop_nonce`) through Actix's
//! [`Auth`] extractor.

use std::sync::Arc;
use std::time::Duration;

use actix_web::{
    http::{header, StatusCode},
    test, web, App, HttpResponse, Responder,
};
use authkestra_actix::Auth;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::token::dpop::compute_jwk_thumbprint;
use authkestra_engine::token::dpop_nonce::{DpopNonces, DPOP_NONCE_HEADER};
use authkestra_engine::token::jwk::Jwk;
use authkestra_resource::jwt::{Jwks, JwtStrategy, ValidationConfig};
use authkestra_resource::{DpopJtiRecord, Guard, StepUpRequirement};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ISSUER_KID: &str = "resource-issuer-kid";
const RESOURCE_ORIGIN: &str = "https://api.example.com";

const ISSUER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD76aCNgcdhMRlN
07vKPEPvP1u8R8xs1R0uzb2Ldn3xmrKo9YEbM7zHInUzKM6JGnnMCgfYbHWO9atT
VnrREfSwa25I8zMLAPDNBQAefNoIKssz6XaFAn+6Ia5LeIJYWIbLFB2l4BToGrPI
ZLO9wULu++BT+g7K2UKYyeYJ3sIpF1/O/8IygrQDwoe+dgd3X/phg1SSlrfYbkjv
ZwIlkxkV0I+EZt6SbqfN+WnOhDsm5FVdYSLofCAjhfcMZmnwWeTJ0WHnejH3hURt
be1pWLEr+4HgsIrB2tfujTRRYylCd0fiEUvsBnUgiaDS2z2AG/JqYPniWXTHYQeP
Bbi8B3oZAgMBAAECggEAEkJ1Fii86Vs4GrNxIlezs2bv6PH52/4nFT5Jwc8DEkUM
s/FGrFB326XQYbbQoLC7+RmVh78V1tjRFDN5p8ehyTtiRTSmo6Kr8apt/6e8XJjw
fXjr07iShkz8b6FCrnFtRNFWlFBNp6TO2QTOn/+fEMhOUnv2wEaW/JDu5RKB151C
rpQ23jSMxLx9G8VvFiuKSS1iU/Sf8OTz4C0bueDSnzIahtj3rJyTmxd4mdBR8XAV
+xdwKKeGrZJ/i5iV/DDK0/2HyKV+8lb/ayDM9WudTFIka8/VB7WeQCuC3Ke9loly
vKnmVv9IS29YE9PgdkMIuQxDS3mso/F38gCfJ9nx0QKBgQD+iyT4ZslSzkQTDezc
FVJgObDqFUVF/onnXsfKwKCoWymJ5K/Udbh05oaysT774fHwroGx3fpyuXMj540a
/TPczluFtPatrJzIDXjObk2uWb/jTs1D2Yn8tYCN2N9T0BPfGbFT6oAKQw5Neun3
hgEKg+E7/muBFPSy7Z/vO5Pi6QKBgQD9WqEDh8JamUPbuI51WU11QXwfoXzpuQZP
knENDPRoR+FoNKe2lZn7cRSLdg8wGUYW779zaECnconPAm7GqMqsHhDSKEzFwhjA
RSKbTQGpp/qui0ys0aIotWTyt4HmnAYEDHOOylPwpK/qTvcm6kSr+7SmhdFzfDQW
oYrNJcZ/sQKBgQDZp1NikEmf474z6NlbS2QX4dzUHIISmteCnvoJ9fKqYuE/BuwO
qOakFyagj40Cxq4hlqZR2DS6erbowatXo6EAMvfxec7grNOXAGYHZixIZHf/Pzen
x9EE5JJbOFGmkisbvxVxYvg/Th1hxTNgsxYazq/+o8t7IdcnVKdIYlJPWQKBgFsB
U/cFq/2JMkPZnmpuopEs7Z4bDtiRmr+4dZ1feud+cmxRBbFjOYWFUADsbnYzjeat
RdL5rse3L+NJF2uKtApxXk9vJGyg1O0zqEOqvJ8pdLV/2hH1107SIanB2wpwHwUT
R+sRqGc3cO00Yjj7S6GPb4ulY+AczEUYz9fy6sNxAoGBAJ4GAPAdFjQGGVYL+Gyl
EnTo6yMtr5GFyj7jfIgZ3OuvBOjbK/gAjGR0LvTWuEmP39hD8syWAx4wNXiXLpMd
2dbFRFjSHP7Q+NDbbc6XDH7zs8iAphevSEcvO5HOb4I+T2CrfH51iNVpkydv6+PF
Bme708uVnhzVSbG9qN6kD9Nk
-----END PRIVATE KEY-----
";

const DPOP_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkY9zPQCZIf1NMDnK
44MN+AmCVP/JTC4OEBjtcJMah8ahRANCAAQBjtX7ev4QV+DwqUrBLOFOwBnVngju
ZaoTPr5K9e2ZNnz4FLjxxXr+cvkIuwdO83BpSPWdfGmUgQsj22fqefan
-----END PRIVATE KEY-----
";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn protected(Auth(claims): Auth<Claims>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({ "sub": claims.sub }))
}

fn issuer_jwks() -> (EncodingKey, Jwk) {
    let enc = EncodingKey::from_rsa_pem(ISSUER_KEY_PEM.as_bytes()).unwrap();
    let mut jt_jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&enc, Algorithm::RS256).unwrap();
    jt_jwk.common.key_id = Some(ISSUER_KID.to_string());
    jt_jwk.common.key_algorithm = Some(jsonwebtoken::jwk::KeyAlgorithm::RS256);
    let engine_jwk: Jwk = serde_json::from_value(serde_json::to_value(jt_jwk).unwrap()).unwrap();
    (enc, engine_jwk)
}

fn dpop_key_and_jkt() -> (EncodingKey, jsonwebtoken::jwk::Jwk, String) {
    let enc = EncodingKey::from_ec_pem(DPOP_KEY_PEM.as_bytes()).unwrap();
    let jt_jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&enc, Algorithm::ES256).unwrap();
    let jkt = compute_jwk_thumbprint(&jt_jwk).expect("ES256 JWK must compute RFC 7638 thumbprint");
    (enc, jt_jwk, jkt)
}

fn sign_access_token(
    enc: &EncodingKey,
    sub: &str,
    acr: Option<&str>,
    auth_time: Option<i64>,
    cnf_jkt: Option<&str>,
) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(ISSUER_KID.to_string());
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "sub": sub,
        "exp": (now + 600) as usize,
    });
    if let Some(acr) = acr {
        claims["acr"] = serde_json::json!(acr);
    }
    if let Some(auth_time) = auth_time {
        claims["auth_time"] = serde_json::json!(auth_time);
    }
    if let Some(jkt) = cnf_jkt {
        claims["cnf"] = serde_json::json!({ "jkt": jkt });
    }
    jsonwebtoken::encode(&header, &claims, enc).unwrap()
}

fn dpop_proof(
    enc: &EncodingKey,
    jwk: &jsonwebtoken::jwk::Jwk,
    htu: &str,
    access_token: &str,
    jti: &str,
    nonce: Option<&str>,
) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk.clone());
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    let mut claims = serde_json::json!({
        "htm": "GET",
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "jti": jti,
        "ath": ath,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = serde_json::json!(nonce);
    }
    jsonwebtoken::encode(&header, &claims, enc).unwrap()
}

#[actix_web::test]
async fn resource_step_up_answers_rfc9470_challenge_then_accepts_elevated_token() {
    let (enc, jwk) = issuer_jwks();
    let config = ValidationConfig::builder()
        .static_jwks(Jwks::from_keys(vec![jwk]))
        .build();
    let strategy = JwtStrategy::<Claims>::new(config).with_step_up(
        StepUpRequirement::new()
            .with_acr_values("2")
            .with_max_age(300),
    );
    let guard = Arc::new(Guard::builder().strategy(strategy).build());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(guard))
            .route("/protected", web::get().to(protected)),
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    let low_acr = sign_access_token(&enc, "alice", Some("1"), Some(now), None);
    let refused = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("Bearer {low_acr}")))
            .to_request(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let www_auth = refused
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("RFC 9470 challenge requires WWW-Authenticate")
        .to_str()
        .unwrap()
        .to_string();
    assert!(www_auth.starts_with("Bearer "), "{www_auth}");
    assert!(
        www_auth.contains("error=\"insufficient_user_authentication\""),
        "{www_auth}"
    );
    assert!(www_auth.contains("acr_values=\"2\""), "{www_auth}");
    assert!(www_auth.contains("max_age=\"300\""), "{www_auth}");
    let body: serde_json::Value = test::read_body_json(refused).await;
    assert_eq!(body["error"], "insufficient_user_authentication");

    let high_acr = sign_access_token(&enc, "alice", Some("2"), Some(now), None);
    let ok = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("Bearer {high_acr}")))
            .to_request(),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let ok_body: serde_json::Value = test::read_body_json(ok).await;
    assert_eq!(ok_body["sub"], "alice");
}

#[actix_web::test]
async fn resource_dpop_nonce_challenges_without_burning_jti_then_accepts_retry() {
    let (enc, jwk) = issuer_jwks();
    let (dpop_enc, dpop_jwk, jkt) = dpop_key_and_jkt();
    let nonces = DpopNonces::new(
        b"0123456789abcdef0123456789abcdef",
        Duration::from_secs(300),
    );
    let config = ValidationConfig::builder()
        .static_jwks(Jwks::from_keys(vec![jwk]))
        .require_dpop(true)
        .dpop_resource_origin(RESOURCE_ORIGIN)
        .build();
    let strategy = JwtStrategy::<Claims>::new(config)
        .with_dpop_replay_store(Arc::new(MemoryStore::<DpopJtiRecord>::new()))
        .with_dpop_nonces(nonces.clone());
    let guard = Arc::new(Guard::builder().strategy(strategy).build());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(guard))
            .route("/protected", web::get().to(protected)),
    )
    .await;

    let access_token = sign_access_token(&enc, "alice", None, None, Some(&jkt));
    let htu = format!("{RESOURCE_ORIGIN}/protected");

    // 1. Missing nonce -> 401 WWW-Authenticate: DPoP error="use_dpop_nonce" + DPoP-Nonce
    let missing_nonce = dpop_proof(&dpop_enc, &dpop_jwk, &htu, &access_token, "res-jti-1", None);
    let refused = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("DPoP {access_token}")))
            .insert_header(("DPoP", missing_nonce))
            .to_request(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let www_auth = refused
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("resource DPoP challenge requires WWW-Authenticate")
        .to_str()
        .unwrap()
        .to_string();
    assert!(www_auth.starts_with("DPoP "), "{www_auth}");
    assert!(www_auth.contains("error=\"use_dpop_nonce\""), "{www_auth}");
    let served_nonce = refused
        .headers()
        .get(DPOP_NONCE_HEADER)
        .expect("resource use_dpop_nonce challenge must carry DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();
    let refused_body: serde_json::Value = test::read_body_json(refused).await;
    assert_eq!(refused_body["error"], "use_dpop_nonce");

    // 2. Nonce from two windows earlier is also refused without burning the jti
    let stale_nonce = nonces.issue_at(chrono::Utc::now().timestamp() - 600);
    let stale_proof = dpop_proof(
        &dpop_enc,
        &dpop_jwk,
        &htu,
        &access_token,
        "res-jti-1",
        Some(&stale_nonce),
    );
    let refused_stale = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("DPoP {access_token}")))
            .insert_header(("DPoP", stale_proof))
            .to_request(),
    )
    .await;
    assert_eq!(refused_stale.status(), StatusCode::UNAUTHORIZED);
    let stale_body: serde_json::Value = test::read_body_json(refused_stale).await;
    assert_eq!(stale_body["error"], "use_dpop_nonce");

    // 3. Retry with served nonce succeeds (even reusing res-jti-1 since challenges did not spend it)
    let retry_proof = dpop_proof(
        &dpop_enc,
        &dpop_jwk,
        &htu,
        &access_token,
        "res-jti-1",
        Some(&served_nonce),
    );
    let ok = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("DPoP {access_token}")))
            .insert_header(("DPoP", retry_proof))
            .to_request(),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let ok_body: serde_json::Value = test::read_body_json(ok).await;
    assert_eq!(ok_body["sub"], "alice");
}
