//! Device-signature profile v1: the shared conformance vectors
//! (`conformance/devsig-profile-v1/vectors.json`).
//!
//! - [`vectors_file_is_fresh`] regenerates the file from `profile_v1_mint` and fails when the
//!   committed copy differs (`AUTHKESTRA_UPDATE_VECTORS=1` rewrites it).
//! - [`every_vector_reaches_its_expected_verdict`] runs every vector through
//!   [`authkestra_devsig::verify_at`] and compares the result — the identity, or the refusal's
//!   status, body and challenge — with the expectation written in the file.
//! - [`the_refusal_table_matches_the_crate`] checks the file's refusal table against
//!   [`VerifyError::refusal`], so the table other projects vendor cannot drift from what the
//!   adapters answer.

mod profile_v1_mint;

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use authkestra_devsig::{
    verify_at, InMemoryReplayStore, IssuerJwks, Refusal, ReplayStore, SignedRequest,
    UnavailableReplayStore, VerifierConfig, VerifyError,
};
use jsonwebtoken::Algorithm;
use serde_json::{json, Value};

use profile_v1_mint::*;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/devsig-profile-v1/vectors.json"
);

// ---------------------------------------------------------------------------------------------
// The file, generated.
// ---------------------------------------------------------------------------------------------

/// One request and the verdict profile v1 requires for it.
struct Vector {
    id: &'static str,
    description: &'static str,
    /// `false` for what a verifier MAY support (an EdDSA device key); `true` for what every
    /// profile v1 verifier MUST get right.
    required: bool,
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    body: Option<&'static str>,
    signature: Option<String>,
    attestation: Option<String>,
    seen_jtis: Vec<&'static str>,
    replay_store_available: bool,
    expect: Value,
}

impl Vector {
    fn new(
        id: &'static str,
        description: &'static str,
        method: &'static str,
        path: &'static str,
    ) -> Self {
        Self {
            id,
            description,
            required: true,
            method,
            path,
            query: None,
            body: None,
            signature: None,
            attestation: None,
            seen_jtis: Vec::new(),
            replay_store_available: true,
            expect: Value::Null,
        }
    }

    fn query(mut self, query: &'static str) -> Self {
        self.query = Some(query);
        self
    }

    fn body(mut self, body: &'static str) -> Self {
        self.body = Some(body);
        self
    }

    fn signed(mut self, signature: String, attestation: String) -> Self {
        self.signature = Some(signature);
        self.attestation = Some(attestation);
        self
    }

    fn accept(mut self, device: &Key, role: &str) -> Self {
        self.expect = json!({
            "outcome": "accept",
            "sub": SUBJECT,
            "did": DEVICE,
            "jkt": device.thumbprint(),
            "role": role,
        });
        self
    }

    fn refuse(mut self, error: &str) -> Self {
        self.expect = json!({
            "outcome": "refuse",
            "status": 401,
            "error": error,
            "body": { "error": error },
            "www_authenticate": format!("DeviceSignature error=\"{error}\""),
        });
        self
    }

    fn to_json(&self) -> Value {
        let mut headers = serde_json::Map::new();
        if let Some(signature) = &self.signature {
            headers.insert("X-Signature".into(), json!(signature));
        }
        if let Some(attestation) = &self.attestation {
            headers.insert("X-Attestation".into(), json!(attestation));
        }
        json!({
            "id": self.id,
            "description": self.description,
            "required": self.required,
            "now": NOW,
            "request": {
                "method": self.method,
                "path": self.path,
                "query": self.query,
                "body": self.body,
                "headers": headers,
            },
            "replay": {
                "store": if self.replay_store_available { "available" } else { "unavailable" },
                "seen_jtis": self.seen_jtis,
            },
            "expect": self.expect,
        })
    }
}

fn refusal_row(error: &str, status: u16, client_action: &str, produced_by: &str) -> Value {
    json!({
        "error": error,
        "status": status,
        "www_authenticate": status == 401,
        "client_action": client_action,
        "produced_by": produced_by,
    })
}

/// The refusal table of `docs/rfc-014-devsig-profile-v1.md` §6, by hand.
fn refusal_table() -> Value {
    let v = "verifier";
    json!([
        refusal_row("missing_credential", 401, "key_lost", v),
        refusal_row("malformed", 401, "none", v),
        refusal_row("bad_alg", 401, "none", v),
        refusal_row("untrusted_issuer", 401, "none", v),
        refusal_row("unknown_kid", 401, "renew", v),
        refusal_row("bad_attestation", 401, "none", v),
        refusal_row("attestation_expired", 401, "renew", v),
        refusal_row("device_not_active", 401, "renew", v),
        refusal_row("bad_jwk", 401, "key_lost", v),
        refusal_row("key_not_bound", 401, "key_lost", v),
        refusal_row("bad_signature", 401, "none", v),
        refusal_row("signature_expired", 401, "none", v),
        refusal_row("lifetime_too_long", 401, "none", v),
        refusal_row("method_mismatch", 401, "none", v),
        refusal_row("path_mismatch", 401, "none", v),
        refusal_row("audience_mismatch", 401, "none", v),
        refusal_row("query_mismatch", 401, "none", v),
        refusal_row("body_mismatch", 401, "none", v),
        refusal_row("replay_detected", 401, "none", v),
        refusal_row("body_too_large", 413, "none", "adapter"),
        refusal_row("device_revoked", 403, "revoked", "application"),
        refusal_row(
            "insufficient_user_authentication",
            401,
            "step_up",
            "application"
        ),
    ])
}

fn vectors(m: &Mint) -> Vec<Vector> {
    let att = m.attestation(&m.device);
    let sig = |jti: &str, method: &str, path: &str, query: Option<&str>, body: Option<&str>| {
        m.signature_with(
            &m.device,
            &m.signature_claims(jti, method, path, query, body),
        )
    };
    let get = |jti: &str| sig(jti, "GET", "/accounts", None, None);
    let with_claims = |jti: &str, edit: &dyn Fn(&mut Value)| {
        let mut claims = m.signature_claims(jti, "GET", "/accounts", None, None);
        edit(&mut claims);
        m.signature_with(&m.device, &claims)
    };
    let att_with = |edit: &dyn Fn(&mut Value)| {
        let mut claims = m.attestation_claims(&m.device);
        edit(&mut claims);
        m.attestation_with(&m.es256, Some(m.es256.kid), &claims)
    };
    const BODY: &str = r#"{"amount":"125.00","to":"acct-42"}"#;

    let mut v = vec![
        // --- Accepted ---
        Vector::new("accept-get", "A GET with no query and no body: no qsh, no bdh. att.role is absent, so the ambient key signed.", "GET", "/accounts")
            .signed(get("jti-accept-get"), att.clone())
            .accept(&m.device, "ambient"),
        Vector::new("accept-post-query-body", "A POST with a query and a JSON body: qsh and bdh are the hex SHA-256 of the raw query and body bytes.", "POST", "/transfers")
            .query("dry_run=false&currency=XAF")
            .body(BODY)
            .signed(sig("jti-accept-post", "POST", "/transfers", Some("dry_run=false&currency=XAF"), Some(BODY)), att.clone())
            .accept(&m.device, "ambient"),
        Vector::new("accept-percent-encoded-path", "pth is the path exactly as sent, percent-encoding included, without the query.", "GET", "/files/annual%20report.pdf")
            .signed(sig("jti-accept-pct", "GET", "/files/annual%20report.pdf", None, None), att.clone())
            .accept(&m.device, "ambient"),
        Vector::new("accept-empty-query", "A request URL ending in a bare `?` has no query: the signature carries no qsh.", "GET", "/accounts")
            .query("")
            .signed(get("jti-accept-empty-query"), att.clone())
            .accept(&m.device, "ambient"),
        Vector::new("accept-user-present-role", "att.role = \"user_present\": the user-present key signed; the identity's role says so.", "POST", "/transfers/confirm")
            .body(BODY)
            .signed(
                m.signature_with(&m.device_user_present, &m.signature_claims("jti-accept-up", "POST", "/transfers/confirm", None, Some(BODY))),
                {
                    let mut claims = m.attestation_claims(&m.device_user_present);
                    claims["att"] = json!({ "status": "active", "role": "user_present" });
                    m.attestation_with(&m.es256, Some(m.es256.kid), &claims)
                },
            )
            .accept(&m.device_user_present, "user_present"),
        Vector::new("accept-eddsa-issuer", "The attestation is signed EdDSA, with a kid.", "GET", "/accounts")
            .signed(get("jti-accept-eddsa-issuer"), m.attestation_with(&m.eddsa, Some(m.eddsa.kid), &m.attestation_claims(&m.device)))
            .accept(&m.device, "ambient"),
        Vector::new("accept-rs256-issuer", "The attestation is signed RS256, with a kid.", "GET", "/accounts")
            .signed(get("jti-accept-rs256-issuer"), m.attestation_with(&m.rs256, Some(m.rs256.kid), &m.attestation_claims(&m.device)))
            .accept(&m.device, "ambient"),
        Vector::new("accept-skew-within-tolerance", "iat is 20 s in the future: within the 30 s tolerance.", "GET", "/accounts")
            .signed(with_claims("jti-accept-skew", &|c| { c["iat"] = json!(NOW + 20); c["exp"] = json!(NOW + 140); }), att.clone())
            .accept(&m.device, "ambient"),
        Vector::new("accept-attestation-extra-attributes", "att carries application attributes beside status; they are surfaced, not interpreted.", "GET", "/accounts")
            .signed(get("jti-accept-attrs"), att_with(&|c| { c["att"] = json!({ "status": "active", "kyc_level": 2, "roles": ["customer"] }); }))
            .accept(&m.device, "ambient"),
        {
            let mut v = Vector::new("accept-eddsa-device", "OPTIONAL: the device key is Ed25519 (EdDSA). Clients sign ES256; a verifier MAY accept EdDSA device keys.", "GET", "/accounts")
                .signed(
                    m.signature_with(&m.device_eddsa, &m.signature_claims("jti-accept-eddsa-device", "GET", "/accounts", None, None)),
                    m.attestation(&m.device_eddsa),
                )
                .accept(&m.device_eddsa, "ambient");
            v.required = false;
            v
        },
        // --- Presence ---
        Vector::new("missing-signature", "Only the attestation: it is public, so alone it is a bearer token.", "GET", "/accounts")
            .refuse("missing_credential"),
        Vector::new("missing-attestation", "Only the signature: an anonymous key.", "GET", "/accounts")
            .refuse("missing_credential"),
        Vector::new("empty-signature-header", "An empty header is an absent credential, not a malformed one.", "GET", "/accounts")
            .signed(String::new(), att.clone())
            .refuse("missing_credential"),
        // --- Shape and algorithm ---
        Vector::new("malformed-attestation-two-segments", "The attestation is not a compact JWS.", "GET", "/accounts")
            .signed(get("jti-malformed-segments"), "eyJhbGciOiJFUzI1NiJ9.e30".to_owned())
            .refuse("malformed"),
        Vector::new("malformed-att-is-a-string", "att is a key-role string instead of an object (the shape profile v1 retires).", "GET", "/accounts")
            .signed(get("jti-malformed-att-string"), att_with(&|c| { c["att"] = json!("ambient"); }))
            .refuse("malformed"),
        Vector::new("malformed-top-level-status", "status sits at the top level and att is missing (the shape profile v1 retires).", "GET", "/accounts")
            .signed(get("jti-malformed-top-status"), att_with(&|c| {
                c.as_object_mut().expect("object").remove("att");
                c["status"] = json!("active");
            }))
            .refuse("malformed"),
        Vector::new("bad-alg-none-attestation", "The attestation says alg none.", "GET", "/accounts")
            .signed(get("jti-bad-alg-none"), {
                let claims = m.attestation_claims(&m.device);
                format!(
                    "{}.{}.{}",
                    b64url(json!({ "alg": "none", "kid": m.es256.kid }).to_string().as_bytes()),
                    b64url(claims.to_string().as_bytes()),
                    b64url(b"not-a-signature"),
                )
            })
            .refuse("bad_alg"),
        Vector::new("bad-alg-hs256-signature", "The request signature uses a symmetric algorithm.", "GET", "/accounts")
            .signed(
                {
                    let claims = m.signature_claims("jti-bad-alg-hs256", "GET", "/accounts", None, None);
                    let input = format!(
                        "{}.{}",
                        b64url(json!({ "alg": "HS256", "jwk": m.device.jwk }).to_string().as_bytes()),
                        b64url(claims.to_string().as_bytes()),
                    );
                    let mac = jsonwebtoken::crypto::sign(input.as_bytes(), &jsonwebtoken::EncodingKey::from_secret(b"shared"), Algorithm::HS256).expect("hmac");
                    format!("{input}.{mac}")
                },
                att.clone(),
            )
            .refuse("bad_alg"),
        Vector::new("bad-alg-rs256-device", "The device signs RS256: profile v1 allows RS256 for issuers only.", "GET", "/accounts")
            .signed(m.signature_with(&m.rs256.key, &m.signature_claims("jti-bad-alg-rs256-device", "GET", "/accounts", None, None)), att.clone())
            .refuse("bad_alg"),
        // --- Attestation trust ---
        Vector::new("untrusted-issuer", "The attestation names an issuer the verifier does not trust.", "GET", "/accounts")
            .signed(get("jti-untrusted-issuer"), att_with(&|c| { c["iss"] = json!(OTHER_ISSUER); }))
            .refuse("untrusted_issuer"),
        Vector::new("unknown-kid", "The attestation's kid is not in the issuer's JWKS.", "GET", "/accounts")
            .signed(get("jti-unknown-kid"), m.attestation_with(&m.es256, Some("issuer-es256-2026-retired"), &m.attestation_claims(&m.device)))
            .refuse("unknown_kid"),
        Vector::new("missing-kid", "The attestation header has no kid: profile v1 requires one.", "GET", "/accounts")
            .signed(get("jti-missing-kid"), m.attestation_with(&m.es256, None, &m.attestation_claims(&m.device)))
            .refuse("unknown_kid"),
        Vector::new("bad-attestation-signature", "The attestation claims a trusted kid but another key signed it.", "GET", "/accounts")
            .signed(get("jti-bad-attestation"), {
                let impostor = IssuerKey { iss: ISSUER, kid: m.es256.kid, key: m.impostor.clone() };
                m.attestation_with(&impostor, Some(m.es256.kid), &m.attestation_claims(&m.device))
            })
            .refuse("bad_attestation"),
        Vector::new("attestation-expired", "The attestation expired an hour ago.", "GET", "/accounts")
            .signed(get("jti-att-expired"), att_with(&|c| { c["iat"] = json!(NOW - 90_000); c["exp"] = json!(NOW - 3_600); }))
            .refuse("attestation_expired"),
        Vector::new("device-not-active", "att.status is \"suspended\".", "GET", "/accounts")
            .signed(get("jti-not-active"), att_with(&|c| { c["att"] = json!({ "status": "suspended" }); }))
            .refuse("device_not_active"),
        Vector::new("device-status-missing", "att has no status: fail closed.", "GET", "/accounts")
            .signed(get("jti-status-missing"), att_with(&|c| { c["att"] = json!({ "role": "ambient" }); }))
            .refuse("device_not_active"),
        // --- The binding ---
        Vector::new("key-not-bound", "THE critical case: the victim's genuine attestation with a request genuinely signed by the attacker's own key. Both signatures verify; only the thumbprint check refuses.", "GET", "/accounts")
            .signed(m.signature_with(&m.attacker, &m.signature_claims("jti-key-not-bound", "GET", "/accounts", None, None)), att.clone())
            .refuse("key_not_bound"),
        Vector::new("bad-jwk-private-member", "The embedded jwk carries a private member d.", "GET", "/accounts")
            .signed({
                let claims = m.signature_claims("jti-bad-jwk-d", "GET", "/accounts", None, None);
                let mut jwk = m.device.jwk.clone();
                jwk["d"] = json!(b64url(&[7u8; 32]));
                jws(&json!({ "alg": "ES256", "jwk": jwk }), &claims, &m.device)
            }, att.clone())
            .refuse("bad_jwk"),
        Vector::new("bad-jwk-missing", "The signature header has no jwk.", "GET", "/accounts")
            .signed(jws(&json!({ "alg": "ES256" }), &m.signature_claims("jti-bad-jwk-missing", "GET", "/accounts", None, None), &m.device), att.clone())
            .refuse("bad_jwk"),
        // --- The request signature ---
        Vector::new("bad-signature", "The claims were changed after signing (another jti), the signature kept.", "GET", "/accounts")
            .signed({
                let signed = get("jti-bad-signature");
                let parts: Vec<&str> = signed.split('.').collect();
                let edited = m.signature_claims("jti-bad-signature-edited", "GET", "/accounts", None, None);
                format!("{}.{}.{}", parts[0], b64url(edited.to_string().as_bytes()), parts[2])
            }, att.clone())
            .refuse("bad_signature"),
        // --- Freshness ---
        Vector::new("signature-expired", "exp passed 90 s ago, beyond the 30 s tolerance.", "GET", "/accounts")
            .signed(with_claims("jti-sig-expired", &|c| { c["iat"] = json!(NOW - 210); c["exp"] = json!(NOW - 90); }), att.clone())
            .refuse("signature_expired"),
        Vector::new("signature-from-the-future", "iat is 120 s ahead, beyond the 30 s tolerance.", "GET", "/accounts")
            .signed(with_claims("jti-sig-future", &|c| { c["iat"] = json!(NOW + 120); c["exp"] = json!(NOW + 240); }), att.clone())
            .refuse("signature_expired"),
        Vector::new("lifetime-too-long", "exp - iat is one hour: profile v1 allows 300 s.", "GET", "/accounts")
            .signed(with_claims("jti-lifetime", &|c| { c["exp"] = json!(NOW + 3_590); }), att.clone())
            .refuse("lifetime_too_long"),
        // --- Request binding ---
        Vector::new("method-mismatch", "Signed for DELETE, sent as GET.", "GET", "/accounts")
            .signed(sig("jti-method", "DELETE", "/accounts", None, None), att.clone())
            .refuse("method_mismatch"),
        Vector::new("path-mismatch", "Signed for /accounts/1, sent to /accounts/2.", "GET", "/accounts/2")
            .signed(sig("jti-path", "GET", "/accounts/1", None, None), att.clone())
            .refuse("path_mismatch"),
        Vector::new("audience-mismatch", "Signed for another API.", "GET", "/accounts")
            .signed(with_claims("jti-aud", &|c| { c["aud"] = json!("https://other-api.example"); }), att.clone())
            .refuse("audience_mismatch"),
        Vector::new("query-altered", "The query was changed after signing.", "GET", "/accounts")
            .query("limit=1000")
            .signed(sig("jti-query-altered", "GET", "/accounts", Some("limit=10"), None), att.clone())
            .refuse("query_mismatch"),
        Vector::new("query-unsigned", "The request has a query but the signature has no qsh.", "GET", "/accounts")
            .query("limit=10")
            .signed(get("jti-query-unsigned"), att.clone())
            .refuse("query_mismatch"),
        Vector::new("query-stray-qsh", "The signature has a qsh but the request has no query: the query was stripped.", "GET", "/accounts")
            .signed(sig("jti-query-stray", "GET", "/accounts", Some("limit=10"), None), att.clone())
            .refuse("query_mismatch"),
        Vector::new("body-altered", "The body was changed after signing.", "POST", "/transfers")
            .body(r#"{"amount":"999999.00","to":"acct-666"}"#)
            .signed(sig("jti-body-altered", "POST", "/transfers", None, Some(BODY)), att.clone())
            .refuse("body_mismatch"),
        Vector::new("body-unsigned", "The request has a body but the signature has no bdh.", "POST", "/transfers")
            .body(BODY)
            .signed(sig("jti-body-unsigned", "POST", "/transfers", None, None), att.clone())
            .refuse("body_mismatch"),
        Vector::new("body-stray-bdh", "The signature has a bdh but the request has no body: the body was stripped, so a signed write would replay as an empty one.", "POST", "/transfers")
            .signed(sig("jti-body-stray", "POST", "/transfers", None, Some(BODY)), att.clone())
            .refuse("body_mismatch"),
        // --- Replay ---
        {
            let mut v = Vector::new("replay", "The jti was already used.", "GET", "/accounts")
                .signed(get("jti-replayed"), att.clone())
                .refuse("replay_detected");
            v.seen_jtis = vec!["jti-replayed"];
            v
        },
        {
            let mut v = Vector::new("replay-store-unavailable", "The replay store cannot be reached: fail closed, exactly like a replay.", "GET", "/accounts")
                .signed(get("jti-store-down"), att.clone())
                .refuse("replay_detected");
            v.replay_store_available = false;
            v
        },
    ];
    v.sort_by_key(|v| !v.required);
    v
}

fn generate() -> String {
    let m = Mint::new();
    let file = json!({
        "profile": "devsig-profile-v1",
        "spec": "docs/rfc-014-devsig-profile-v1.md",
        "generated_by": "crates/authkestra-devsig/tests/profile_v1.rs (AUTHKESTRA_UPDATE_VECTORS=1 cargo test -p authkestra-devsig --test profile_v1)",
        "note": "Every key and credential here is a fixed TEST value that protects nothing. Run each vector with a fresh replay store seeded with replay.seen_jtis (or one that always fails when replay.store is \"unavailable\"), at the Unix time `now`.",
        "verifier": {
            "trusted_issuers": [ISSUER],
            "audience": AUDIENCE,
            "attestation_algs": ["ES256", "EdDSA", "RS256"],
            "device_algs": ["ES256", "EdDSA"],
            "clock_skew_secs": 30,
            "max_signature_lifetime_secs": 300,
            "signature_header": "X-Signature",
            "attestation_header": "X-Attestation",
        },
        "issuer_keys": m.issuer_keys(),
        "refusals": refusal_table(),
        "legacy_aliases": {
            "replay": "replay_detected",
            "mismatch": "method_mismatch | path_mismatch | audience_mismatch | query_mismatch | body_mismatch",
            "DEVICE_REVOKED": "device_revoked",
        },
        "vectors": vectors(&m).iter().map(Vector::to_json).collect::<Vec<_>>(),
    });
    let mut text = serde_json::to_string_pretty(&file).expect("serialize vectors");
    text.push('\n');
    text
}

#[test]
fn vectors_file_is_fresh() {
    let generated = generate();
    if std::env::var_os("AUTHKESTRA_UPDATE_VECTORS").is_some() {
        std::fs::write(VECTORS, &generated).expect("write vectors.json");
        return;
    }
    let committed = std::fs::read_to_string(VECTORS).expect("read vectors.json");
    assert!(
        committed == generated,
        "conformance/devsig-profile-v1/vectors.json is stale: run \
         AUTHKESTRA_UPDATE_VECTORS=1 cargo test -p authkestra-devsig --test profile_v1 \
         and commit the result"
    );
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(generate(), generate());
}

// ---------------------------------------------------------------------------------------------
// The file, run.
// ---------------------------------------------------------------------------------------------

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("read vectors.json"))
        .expect("vectors.json is JSON")
}

fn algs(value: &Value) -> Vec<Algorithm> {
    value
        .as_array()
        .expect("alg list")
        .iter()
        .map(|a| Algorithm::from_str(a.as_str().expect("alg name")).expect("known alg"))
        .collect()
}

fn config(file: &Value) -> VerifierConfig {
    let v = &file["verifier"];
    VerifierConfig::new(
        v["trusted_issuers"]
            .as_array()
            .expect("issuers")
            .iter()
            .map(|i| i.as_str().expect("issuer").to_owned()),
        algs(&v["attestation_algs"]),
        Duration::from_secs(v["clock_skew_secs"].as_u64().expect("skew")),
        Duration::from_secs(v["max_signature_lifetime_secs"].as_u64().expect("lifetime")),
        v["audience"].as_str().expect("audience"),
    )
    .with_device_algs(algs(&v["device_algs"]))
}

async fn jwks(file: &Value) -> IssuerJwks {
    let jwks = IssuerJwks::new();
    for key in file["issuer_keys"].as_array().expect("issuer keys") {
        jwks.insert(
            key["iss"].as_str().expect("iss"),
            key["kid"].as_str().expect("kid"),
            serde_json::from_value(key["jwk"].clone()).expect("issuer jwk"),
        )
        .await;
    }
    jwks
}

fn header<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    headers
        .as_object()
        .expect("headers")
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_str())
}

/// Runs one vector at `now` with a fresh replay store, as the file's `note` prescribes.
async fn run(
    vector: &Value,
    config: &VerifierConfig,
    jwks: &IssuerJwks,
    now: SystemTime,
) -> Result<authkestra_devsig::DeviceIdentity, VerifyError> {
    let request = &vector["request"];
    let signed = SignedRequest {
        signature: header(&request["headers"], "X-Signature"),
        attestation: header(&request["headers"], "X-Attestation"),
        method: request["method"].as_str().expect("method"),
        path: request["path"].as_str().expect("path"),
        query: request["query"].as_str(),
        body: request["body"].as_str().map(str::as_bytes),
    };

    let store: Box<dyn ReplayStore> = if vector["replay"]["store"] == "unavailable" {
        Box::new(UnavailableReplayStore)
    } else {
        let store = InMemoryReplayStore::new();
        for jti in vector["replay"]["seen_jtis"].as_array().expect("seen jtis") {
            store
                .put_if_absent(jti.as_str().expect("jti"), Duration::from_secs(600))
                .await
                .expect("seed replay store");
        }
        Box::new(store)
    };
    verify_at(&signed, config, jwks, store.as_ref(), now).await
}

fn vector_now(vector: &Value) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(vector["now"].as_u64().expect("now"))
}

#[tokio::test]
async fn every_vector_reaches_its_expected_verdict() {
    let file = load();
    let config = config(&file);
    let jwks = jwks(&file).await;
    let vectors = file["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 40,
        "the vector set shrank to {}",
        vectors.len()
    );

    let mut failures = Vec::new();
    for vector in vectors {
        let got = match run(vector, &config, &jwks, vector_now(vector)).await {
            Ok(identity) => json!({
                "outcome": "accept",
                "sub": identity.subject,
                "did": identity.device,
                "jkt": identity.key_thumbprint,
                "role": identity.key_role().as_str(),
            }),
            Err(error) => {
                let refusal = error.refusal();
                json!({
                    "outcome": "refuse",
                    "status": refusal.status,
                    "error": refusal.error,
                    "body": serde_json::from_str::<Value>(&refusal.body()).expect("JSON body"),
                    "www_authenticate": refusal.www_authenticate(),
                })
            }
        };
        if got != vector["expect"] {
            failures.push(format!(
                "{}: expected {} got {got}",
                vector["id"], vector["expect"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "vectors failed:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn an_accepted_vector_is_refused_a_second_time() {
    // The vectors each get a fresh store; this checks the store is really consulted.
    let file = load();
    let (config, jwks) = (config(&file), jwks(&file).await);
    let vector = &file["vectors"][0];
    let request = &vector["request"];
    let signed = SignedRequest {
        signature: header(&request["headers"], "X-Signature"),
        attestation: header(&request["headers"], "X-Attestation"),
        method: request["method"].as_str().expect("method"),
        path: request["path"].as_str().expect("path"),
        query: request["query"].as_str(),
        body: request["body"].as_str().map(str::as_bytes),
    };
    let store = InMemoryReplayStore::new();
    let now = vector_now(vector);
    verify_at(&signed, &config, &jwks, &store, now)
        .await
        .expect("first use is accepted");
    assert_eq!(
        verify_at(&signed, &config, &jwks, &store, now).await,
        Err(VerifyError::ReplayDetected)
    );
}

#[tokio::test]
async fn a_clock_before_the_epoch_is_a_refusal_not_a_panic() {
    let file = load();
    let (config, jwks) = (config(&file), jwks(&file).await);
    let before = UNIX_EPOCH - Duration::from_secs(1);
    assert_eq!(
        run(&file["vectors"][0], &config, &jwks, before).await,
        Err(VerifyError::AttestationExpired)
    );
}

#[test]
fn the_verifier_block_is_profile_v1s_defaults() {
    let file = load();
    let from_file = config(&file);
    let profile = VerifierConfig::profile_v1([ISSUER], AUDIENCE);
    assert_eq!(from_file.allowed_algs, profile.allowed_algs);
    assert_eq!(from_file.device_algs(), profile.device_algs());
    assert_eq!(from_file.max_clock_skew, profile.max_clock_skew);
    assert_eq!(
        from_file.max_signature_lifetime,
        profile.max_signature_lifetime
    );
    assert_eq!(from_file.audience, profile.audience);
    assert_eq!(from_file.trusted_issuers, profile.trusted_issuers);
}

#[test]
fn the_refusal_table_matches_the_crate() {
    let file = load();
    let every_verify_error = [
        VerifyError::MissingCredential,
        VerifyError::Malformed(String::new()),
        VerifyError::BadAlg(String::new()),
        VerifyError::UntrustedIssuer(String::new()),
        VerifyError::UnknownKid(String::new()),
        VerifyError::BadAttestation(String::new()),
        VerifyError::AttestationExpired,
        VerifyError::DeviceNotActive,
        VerifyError::BadJwk(String::new()),
        VerifyError::KeyNotBound,
        VerifyError::BadSignature(String::new()),
        VerifyError::SignatureExpired,
        VerifyError::LifetimeTooLong,
        VerifyError::MethodMismatch,
        VerifyError::PathMismatch,
        VerifyError::AudienceMismatch,
        VerifyError::QueryMismatch,
        VerifyError::BodyMismatch,
        VerifyError::ReplayDetected,
        VerifyError::BodyTooLarge(1),
    ];
    let mut refusals: Vec<Refusal> = every_verify_error
        .iter()
        .map(VerifyError::refusal)
        .collect();
    refusals.push(Refusal::device_revoked());
    refusals.push(Refusal::insufficient_user_authentication());

    let table = file["refusals"].as_array().expect("refusal table");
    assert_eq!(
        table.len(),
        refusals.len(),
        "one row per refusal, no more, no less"
    );
    for refusal in refusals {
        let row = table
            .iter()
            .find(|row| row["error"] == refusal.error)
            .unwrap_or_else(|| panic!("{} has no row in the refusal table", refusal.error));
        assert_eq!(row["status"], refusal.status, "{}", refusal.error);
        assert_eq!(
            row["www_authenticate"],
            refusal.www_authenticate().is_some(),
            "{}",
            refusal.error
        );
    }
}
