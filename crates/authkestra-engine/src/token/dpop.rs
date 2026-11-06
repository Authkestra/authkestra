//! RFC 9449 DPoP (Demonstrating Proof-of-Possession) proof verification.
//!
//! This module verifies a single DPoP proof JWT and reports the RFC 7638
//! thumbprint of its embedded public key — nothing more. It does not issue
//! tokens, does not stamp a `cnf` claim, and does not track replay: those
//! are call-site concerns (see below), kept out of this module so it stays
//! a pure, independently-testable function.
//!
//! ## Why this lives in `authkestra-engine`, not `authkestra-op`
//!
//! DPoP applies at both ends of a token's life — issuance in
//! `authkestra-op` and verification in `authkestra-resource` — and neither
//! crate depends on the other. `authkestra-engine` is the one crate both
//! already depend on, so this is where a proof verifier usable from either
//! side has to live.
//!
//! ## Relationship to `authkestra-op`'s enrolment/attestation verifiers
//!
//! [`verify_dpop_proof`] follows the same shape as
//! `authkestra_op::attestation::verify_challenge_signature` — peek the raw
//! `alg` before trusting `jsonwebtoken`'s typed API (whose `Algorithm`
//! deserializer hard-fails on `"none"` or an unrecognised value), derive
//! the algorithm from the key rather than the header, and use
//! [`authkestra_crypto_util::verify_ed25519_signature_strict`] ahead of
//! `jsonwebtoken::decode` so a low-order key or a low-order signature `R`
//! can never satisfy proof of possession (authkestra#242 / authkestra#256).
//! The logic is **reimplemented here, not imported**: `authkestra-op`'s
//! version is crate-private and `authkestra-engine` cannot depend on
//! `authkestra-op` without inverting the dependency graph. Only the
//! genuinely shared low-level primitive
//! (`authkestra_crypto_util::verify_ed25519_signature_strict`) is reused;
//! `authkestra-op::strict_jws` itself is untouched by this work.
//!
//! ## What callers still have to do
//!
//! - **Replay protection.** A DPoP proof's `jti` is client-generated, so
//!   there is nothing for this server to have stored ahead of time — the
//!   check is "was this `jti` already claimed", which is the shape
//!   [`crate::store::AtomicInsert`] provides, not [`crate::store::AtomicConsume`].
//!   Call `insert_if_absent(jti, ..., max_age)` after a proof verifies and
//!   treat `Ok(false)` as a replay.
//! - **Binding the `jkt` into an issued token**, and **comparing a proof's
//!   `jkt` against an access token's `cnf.jkt`** — both call sites already
//!   have everything needed for this ([`crate::token::TokenManager::issue_user_token_with_extra`]
//!   and [`crate::token::cert_binding::constant_time_eq`] respectively).

use authkestra_crypto_util::verify_ed25519_signature_strict;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

/// JWK members that indicate private or symmetric key material. Mirrors
/// `authkestra_op::attestation::PRIVATE_JWK_MEMBERS` — a JWK embedded in a
/// DPoP proof header is exactly as attacker-controlled as one submitted to
/// the enrolment ceremony that constant guards, and `jsonwebtoken::jwk::Jwk`
/// silently drops unknown members on a typed parse, so this check must run
/// against the raw JSON before that parse happens.
const PRIVATE_JWK_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// A DPoP proof that has passed signature, `typ`, `htm`/`htu`, freshness,
/// and (when requested) `ath` verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// The RFC 7638 SHA-256 thumbprint of the proof's embedded public key —
    /// the value to stamp into (or compare against) an access token's
    /// `cnf.jkt`.
    pub jkt: String,
    /// The proof's `jti` claim — pass this to a replay guard.
    pub jti: String,
    /// The proof's `iat` claim (Unix seconds), already checked against
    /// `max_age` by [`verify_dpop_proof`] — exposed for callers that want
    /// to log or further reason about it.
    pub iat: i64,
}

/// Why a DPoP proof was refused.
#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    #[error("dpop proof is not a well-formed compact JWS: {0}")]
    Malformed(String),
    #[error("dpop proof header typ must be \"dpop+jwt\"")]
    WrongTyp,
    #[error("dpop proof alg is not permitted: {0}")]
    UnsupportedAlgorithm(String),
    #[error("dpop proof header carries no jwk, or jwk is malformed: {0}")]
    MissingOrInvalidJwk(String),
    #[error("dpop proof jwk carries a private or symmetric-secret component: {0}")]
    PrivateOrSymmetricJwk(String),
    #[error("dpop proof key is unsafe to use: {0}")]
    WeakKey(String),
    #[error("dpop proof signature is invalid: {0}")]
    BadSignature(String),
    #[error("dpop proof htm does not match the request method")]
    WrongHtm,
    #[error("dpop proof htu does not match the request URI")]
    WrongHtu,
    #[error("dpop proof iat is outside the allowed freshness window")]
    Stale,
    #[error("dpop proof ath does not match the presented access token")]
    AthMismatch,
    #[error("dpop proof thumbprint could not be computed: {0}")]
    ThumbprintFailed(String),
    #[error("dpop proof jti is too long ({0} bytes, max {MAX_JTI_LEN})")]
    JtiTooLong(usize),
}

/// The largest `jti` this module accepts. RFC 9449 places no length limit
/// on `jti` itself, but this module documents it as a value callers pass
/// straight through to a replay-guard store as a key — and the MySQL
/// `AtomicInsert` backend's key column is `VARCHAR(255)` (see
/// `crate::store::sql::session`), so an unbounded `jti` is a
/// client-controlled way to make that store call fail. Rejecting it here,
/// before any store is ever involved, is a single, explicit check rather
/// than every possible backend needing its own truncation-or-error policy.
const MAX_JTI_LEN: usize = 255;

/// The DPoP proof's payload claims (RFC 9449 §4.2).
#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
}

/// Verifies a DPoP proof JWT (RFC 9449 §4.3).
///
/// `expected_htm` is compared case-insensitively (§4.2: "the value of the
/// HTTP method") and always checked — a caller always knows the current
/// request's method unambiguously, so there's no case where skipping it
/// would be appropriate.
///
/// `expected_htu`, when `Some`, is compared against the proof's own `htu`
/// with both sides stripped of query and fragment first, per §4.3 step 6,
/// using `url::Url` for canonicalization — pass in the request's URI as
/// received, not pre-stripped. `None` skips the `htu` check entirely: a
/// resource server protecting many routes behind a reverse proxy or load
/// balancer often cannot reliably reconstruct the exact absolute URL the
/// client used (scheme and authority depend on the TLS-termination point,
/// which isn't always visible to application code), unlike an
/// authorization server's `/token` endpoint, which has exactly one, known,
/// statically configured absolute URL. Skipping `htu` still leaves `jti`
/// replay tracking and (when the caller supplies it) `ath` binding to
/// prevent a captured proof from being reused — see the caller's own
/// threat-model notes for what's traded away by not also checking `htu`.
///
/// `expected_ath` should be `Some(base64url(SHA256(access_token)))` when
/// verifying a proof presented alongside an access token (the resource
/// server case, §4.3 step 12), and `None` at the token endpoint, where no
/// access token exists yet for the proof to bind to.
///
/// `max_age` is both the proof-freshness window (§4.3 step 11) and, by
/// convention, the TTL a caller should pass to
/// [`crate::store::AtomicInsert::insert_if_absent`] when recording the
/// `jti` — a proof can never be usefully replayed after its own freshness
/// window has elapsed, since it would independently fail this check first.
///
/// Does **not** check replay — see the module doc.
pub fn verify_dpop_proof(
    compact_jws: &str,
    expected_htm: &str,
    expected_htu: Option<&str>,
    expected_ath: Option<&str>,
    max_age: chrono::Duration,
) -> Result<VerifiedDpopProof, DpopError> {
    // Logged once here rather than at each of the eleven rejection points
    // inside. Every `DpopError` variant already names the check that failed
    // — `WrongHtm`, `WrongHtu`, `Stale`, `AthMismatch`, `JtiTooLong(n)`,
    // `UnsupportedAlgorithm(alg)` — so one line at the boundary carries the
    // same information as eleven near-identical ones, and cannot drift out
    // of step with the checks the way per-site logging does. Callers see
    // only that verification failed (the adapters map every variant onto one
    // `invalid_dpop_proof` response, deliberately), so without this the
    // reason existed nowhere at all (#353).
    //
    // `compact_jws` is never logged: the proof is a credential.
    let outcome = verify_dpop_proof_inner(
        compact_jws,
        expected_htm,
        expected_htu,
        expected_ath,
        max_age,
    );
    // Computed once outside the fields rather than inline in both arms. A
    // call inside a `tracing` field expands into regions that no test can
    // fully execute, so it reads as permanently uncovered however well the
    // function is exercised; a plain binding is both covered and used twice.
    let ath_bound = expected_ath.is_some();
    match &outcome {
        Ok(proof) => tracing::debug!(
            jti = ?proof.jti,
            htm = %expected_htm,
            htu = ?expected_htu,
            ath_bound,
            "DPoP proof verified"
        ),
        Err(error) => tracing::warn!(
            %error,
            htm = %expected_htm,
            htu = ?expected_htu,
            ath_bound,
            "DPoP proof rejected"
        ),
    }
    outcome
}

/// The verification itself. Split out so [`verify_dpop_proof`] can report the
/// outcome in one place; see the comment there.
fn verify_dpop_proof_inner(
    compact_jws: &str,
    expected_htm: &str,
    expected_htu: Option<&str>,
    expected_ath: Option<&str>,
    max_age: chrono::Duration,
) -> Result<VerifiedDpopProof, DpopError> {
    let mut parts = compact_jws.split('.');
    let header_b64 = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DpopError::Malformed("missing header segment".to_string()))?;
    if parts.next().filter(|s| !s.is_empty()).is_none() {
        return Err(DpopError::Malformed("missing payload segment".to_string()));
    }
    if parts.next().filter(|s| !s.is_empty()).is_none() {
        return Err(DpopError::Malformed(
            "missing signature segment".to_string(),
        ));
    }
    if parts.next().is_some() {
        return Err(DpopError::Malformed(
            "compact JWS has more than three segments".to_string(),
        ));
    }

    let header_bytes = base64_decode(header_b64)
        .map_err(|e| DpopError::Malformed(format!("header is not valid base64url: {e}")))?;
    let header_json: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| DpopError::Malformed(format!("header is not valid JSON: {e}")))?;

    // `typ` is a MUST per RFC 9449 §4.2 — it's what stops a proof from
    // being confused with any other kind of JWT this server might accept.
    let typ = header_json.get("typ").and_then(Value::as_str);
    if typ != Some("dpop+jwt") {
        return Err(DpopError::WrongTyp);
    }

    // Peeked before the typed jsonwebtoken API touches it: `Algorithm`'s
    // deserializer hard-fails on `"none"` or an unrecognised value, which
    // would otherwise collapse a `bad_alg` case into an opaque parse error
    // rather than the specific rejection this reports.
    let raw_alg = header_json
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::UnsupportedAlgorithm("missing".to_string()))?;
    if ["none", "HS256", "HS384", "HS512"]
        .iter()
        .any(|bad| raw_alg.eq_ignore_ascii_case(bad))
    {
        return Err(DpopError::UnsupportedAlgorithm(raw_alg.to_string()));
    }

    let jwk_json = header_json
        .get("jwk")
        .ok_or_else(|| DpopError::MissingOrInvalidJwk("no jwk in header".to_string()))?;
    let jwk_obj = jwk_json
        .as_object()
        .ok_or_else(|| DpopError::MissingOrInvalidJwk("jwk is not a JSON object".to_string()))?;
    for member in PRIVATE_JWK_MEMBERS {
        if jwk_obj.contains_key(member) {
            return Err(DpopError::PrivateOrSymmetricJwk(member.to_string()));
        }
    }
    let jwk: Jwk = serde_json::from_value(jwk_json.clone())
        .map_err(|e| DpopError::MissingOrInvalidJwk(e.to_string()))?;

    let algorithm = expected_algorithm(&jwk)?;

    // Strict EdDSA gate ahead of `jsonwebtoken`'s non-strict backend
    // (authkestra#242 / authkestra#256) — a no-op for non-Ed25519 keys,
    // since only an OctetKeyPair/Ed25519 key reaches that backend at all.
    if let AlgorithmParameters::OctetKeyPair(params) = &jwk.algorithm {
        let signing_input = compact_jws
            .rsplit_once('.')
            .map(|(input, _sig)| input)
            .expect("already validated as header.payload.signature above");
        let signature_b64 = compact_jws
            .rsplit_once('.')
            .map(|(_input, sig)| sig)
            .expect("already validated as header.payload.signature above");

        verify_ed25519_signature_strict(signing_input.as_bytes(), signature_b64, &params.x)
            .map_err(|e| match e {
                authkestra_crypto_util::EdDsaVerifyError::Key(key_err) => {
                    DpopError::WeakKey(key_err.to_string())
                }
                authkestra_crypto_util::EdDsaVerifyError::Signature(msg) => {
                    DpopError::BadSignature(msg)
                }
            })?;
    }

    let decoding_key =
        DecodingKey::from_jwk(&jwk).map_err(|e| DpopError::MissingOrInvalidJwk(e.to_string()))?;
    let mut validation = Validation::new(algorithm);
    // DPoP proofs carry `iat`, not `exp` — freshness is checked explicitly
    // below against `max_age`, not via jsonwebtoken's `exp`/`nbf` handling.
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let data = jsonwebtoken::decode::<DpopClaims>(compact_jws, &decoding_key, &validation)
        .map_err(|e| DpopError::BadSignature(e.to_string()))?;
    let claims = data.claims;

    if claims.jti.len() > MAX_JTI_LEN {
        return Err(DpopError::JtiTooLong(claims.jti.len()));
    }

    if !claims.htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DpopError::WrongHtm);
    }
    if let Some(expected_htu) = expected_htu {
        if canonicalize_htu(&claims.htu) != canonicalize_htu(expected_htu) {
            return Err(DpopError::WrongHtu);
        }
    }

    let now = chrono::Utc::now().timestamp();
    // A small allowance for clock skew between client and server on the
    // "not yet valid" side; the "too old" side is exactly `max_age`.
    // Reject non-positive or out-of-range timestamps and use `checked_sub` so an
    // extreme negative `iat` cannot overflow `now - claims.iat` in release builds.
    const CLOCK_SKEW_ALLOWANCE_SECS: i64 = 5;
    if claims.iat <= 0
        || chrono::DateTime::<chrono::Utc>::from_timestamp(claims.iat, 0).is_none()
        || claims.iat > now.saturating_add(CLOCK_SKEW_ALLOWANCE_SECS)
    {
        return Err(DpopError::Stale);
    }
    let Some(age) = now.checked_sub(claims.iat) else {
        return Err(DpopError::Stale);
    };
    if age > max_age.num_seconds() {
        return Err(DpopError::Stale);
    }

    if let Some(expected) = expected_ath {
        let actual = claims.ath.as_deref().ok_or(DpopError::AthMismatch)?;
        if !crate::token::cert_binding::constant_time_eq(actual, expected) {
            return Err(DpopError::AthMismatch);
        }
    }

    let jkt = compute_jwk_thumbprint(&jwk)?;

    Ok(VerifiedDpopProof {
        jkt,
        jti: claims.jti,
        iat: claims.iat,
    })
}

/// Computes the RFC 7638 SHA-256 JWK thumbprint of a DPoP proof's embedded
/// public key — the value that becomes (or is compared against) `cnf.jkt`.
///
/// Unlike `authkestra_op::attestation::compute_cnf_jkt`, this does not need
/// a `catch_unwind` guard: verified directly against the pinned
/// `jsonwebtoken = "11"` source (`jwk.rs`), `Jwk::thumbprint()` in this
/// version returns `Err(InvalidKeyFormat)` for a structurally-inconsistent
/// key (e.g. `kty: EC` with `crv: Ed25519`) rather than panicking — that
/// panic was specific to the 10.4.0-era implementation.
pub fn compute_jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
        .map_err(|e| DpopError::ThumbprintFailed(e.to_string()))
}

/// The algorithm a given public key can plausibly have been used with —
/// derived from the key itself, never trusted from the (attacker-supplied)
/// header, mirroring `authkestra_op::attestation::expected_algorithm`.
fn expected_algorithm(jwk: &Jwk) -> Result<Algorithm, DpopError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => match &params.curve {
            EllipticCurve::P256 => Ok(Algorithm::ES256),
            EllipticCurve::P384 => Ok(Algorithm::ES384),
            other => Err(DpopError::UnsupportedAlgorithm(format!("{other:?}"))),
        },
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        AlgorithmParameters::OctetKeyPair(params) => {
            if params.curve == EllipticCurve::Ed25519 {
                Ok(Algorithm::EdDSA)
            } else {
                Err(DpopError::UnsupportedAlgorithm(format!(
                    "OKP curve {:?}",
                    params.curve
                )))
            }
        }
        other => Err(DpopError::UnsupportedAlgorithm(format!("{other:?}"))),
    }
}

/// Strips query and fragment from a URI for `htu` comparison (RFC 9449
/// §4.3 step 6). Falls back to comparing the original, unmodified string
/// (no case-folding or other normalization) if it does not parse as a URL
/// at all — that failure mode still compares two unparsed strings
/// consistently rather than panicking or silently accepting a mismatch.
fn canonicalize_htu(uri: &str) -> String {
    match url::Url::parse(uri) {
        Ok(mut url) => {
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => uri.to_string(),
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    fn b64_json(v: &Value) -> String {
        b64(serde_json::to_vec(v).unwrap().as_slice())
    }

    /// Builds a real, well-formed, genuinely-signed DPoP proof so tests
    /// exercise the actual signature path rather than stubbing it out.
    struct ProofBuilder {
        signing_key: SigningKey,
        htm: String,
        htu: String,
        iat: i64,
        jti: String,
        ath: Option<String>,
        typ_override: Option<String>,
        alg_override: Option<String>,
    }

    impl ProofBuilder {
        fn new() -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&[7u8; 32]),
                htm: "POST".to_string(),
                htu: "https://as.example.com/token".to_string(),
                iat: chrono::Utc::now().timestamp(),
                jti: "proof-jti-1".to_string(),
                ath: None,
                typ_override: None,
                alg_override: None,
            }
        }

        fn build(self) -> String {
            let verifying = self.signing_key.verifying_key();
            let jwk = serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64(verifying.as_bytes()),
            });
            let header = serde_json::json!({
                "typ": self.typ_override.unwrap_or_else(|| "dpop+jwt".to_string()),
                "alg": self.alg_override.unwrap_or_else(|| "EdDSA".to_string()),
                "jwk": jwk,
            });
            let mut payload = serde_json::json!({
                "htm": self.htm,
                "htu": self.htu,
                "iat": self.iat,
                "jti": self.jti,
            });
            if let Some(ath) = self.ath {
                payload["ath"] = serde_json::Value::String(ath);
            }

            let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
            let signature = self.signing_key.sign(signing_input.as_bytes());
            format!("{signing_input}.{}", b64(&signature.to_bytes()))
        }
    }

    #[test]
    fn accepts_a_genuine_fresh_proof_and_reports_the_correct_jkt() {
        let builder = ProofBuilder::new();
        let expected_jkt = compute_jwk_thumbprint(
            &serde_json::from_value(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64(builder.signing_key.verifying_key().as_bytes()),
            }))
            .unwrap(),
        )
        .unwrap();
        let proof = ProofBuilder::new().build();

        let verified = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect("a genuine, fresh proof must be accepted");

        assert_eq!(verified.jkt, expected_jkt);
        assert_eq!(verified.jti, "proof-jti-1");
    }

    #[test]
    fn htm_comparison_is_case_insensitive() {
        let proof = ProofBuilder::new().build();
        verify_dpop_proof(
            &proof,
            "post",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect("htm must compare case-insensitively");
    }

    #[test]
    fn rejects_wrong_htm() {
        let proof = ProofBuilder::new().build();
        let err = verify_dpop_proof(
            &proof,
            "GET",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a mismatched htm must be refused");
        assert!(matches!(err, DpopError::WrongHtm));
    }

    #[test]
    fn htu_comparison_ignores_query_and_fragment() {
        let proof = ProofBuilder::new().build();
        verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token?foo=bar#frag"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect("htu must compare ignoring query/fragment");
    }

    #[test]
    fn rejects_wrong_htu() {
        let proof = ProofBuilder::new().build();
        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/other-path"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a mismatched htu must be refused");
        assert!(matches!(err, DpopError::WrongHtu));
    }

    /// A resource server protecting many routes behind a proxy or load
    /// balancer often can't reliably reconstruct the exact absolute URL a
    /// client used — `expected_htu: None` lets such a caller skip this one
    /// check while still getting every other one (`htm`, freshness, and
    /// whatever `ath`/replay checks it layers on top itself).
    #[test]
    fn expected_htu_none_skips_the_check_entirely() {
        let proof = ProofBuilder::new().build();
        verify_dpop_proof(&proof, "POST", None, None, chrono::Duration::seconds(60))
            .expect("None must skip the htu check regardless of the proof's own htu");
    }

    #[test]
    fn rejects_a_stale_proof() {
        let mut builder = ProofBuilder::new();
        builder.iat = chrono::Utc::now().timestamp() - 120;
        let proof = builder.build();

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a proof older than max_age must be refused");
        assert!(matches!(err, DpopError::Stale));
    }

    #[test]
    fn rejects_a_proof_too_far_in_the_future() {
        let mut builder = ProofBuilder::new();
        builder.iat = chrono::Utc::now().timestamp() + 3600;
        let proof = builder.build();

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a proof from the future must be refused");
        assert!(matches!(err, DpopError::Stale));
    }

    /// authkestra#277 review: none of `verify_dpop_proof`'s six distinct
    /// `Malformed` production sites (missing header/payload/signature
    /// segment, too many segments, header not valid base64url, header not
    /// valid JSON) had test coverage. Covers the structural (segment-count)
    /// cases here; the two content-level cases (bad base64url, bad JSON)
    /// get their own tests below since they need a well-formed segment
    /// count to reach.
    #[test]
    fn rejects_malformed_compact_jws_segment_shapes() {
        let cases: [(&str, &str); 4] = [
            ("", "empty string has no segments at all"),
            ("only-one-segment", "missing payload and signature segments"),
            ("header-only.payload-only", "missing signature segment"),
            ("a.b.c.d", "more than three segments"),
        ];
        for (proof, description) in cases {
            let err = verify_dpop_proof(
                proof,
                "POST",
                Some("https://as.example.com/token"),
                None,
                chrono::Duration::seconds(60),
            )
            .expect_err(&format!(
                "case ({description}) must be rejected as malformed"
            ));
            assert!(
                matches!(err, DpopError::Malformed(_)),
                "case ({description}): expected Malformed, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_a_header_segment_that_is_not_valid_base64url() {
        // `!` is outside the base64url alphabet (A-Z, a-z, 0-9, -, _).
        let proof = "!!!not-base64url!!!.payload.signature";
        let err = verify_dpop_proof(
            proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a header segment that isn't valid base64url must be rejected");
        assert!(matches!(err, DpopError::Malformed(_)));
    }

    #[test]
    fn rejects_a_header_segment_that_decodes_but_is_not_valid_json() {
        let header_b64 = b64(b"not valid json at all");
        let proof = format!("{header_b64}.payload.signature");
        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a header that decodes but isn't valid JSON must be rejected");
        assert!(matches!(err, DpopError::Malformed(_)));
    }

    #[test]
    fn rejects_wrong_typ() {
        let mut builder = ProofBuilder::new();
        builder.typ_override = Some("JWT".to_string());
        let proof = builder.build();

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a non-dpop+jwt typ must be refused");
        assert!(matches!(err, DpopError::WrongTyp));
    }

    /// The algorithm-confusion gate (RFC 9449 requires an asymmetric
    /// signature) rejects `alg: none` and every HMAC algorithm, regardless
    /// of case — `alg_override` lets a test declare a header `alg` the
    /// embedded (still-Ed25519) key never actually signs with, exercising
    /// the peek-before-parse rejection in isolation from the key itself.
    #[test]
    fn rejects_alg_none_and_hmac_algorithms_case_insensitively() {
        for bad_alg in ["none", "None", "NONE", "HS256", "hs256", "Hs384", "HS512"] {
            let mut builder = ProofBuilder::new();
            builder.alg_override = Some(bad_alg.to_string());
            let proof = builder.build();

            let err = verify_dpop_proof(
                &proof,
                "POST",
                Some("https://as.example.com/token"),
                None,
                chrono::Duration::seconds(60),
            )
            .expect_err(&format!("alg {bad_alg:?} must be refused"));
            assert!(
                matches!(err, DpopError::UnsupportedAlgorithm(_)),
                "alg {bad_alg:?}: expected UnsupportedAlgorithm, got {err:?}"
            );
        }
    }

    #[test]
    fn checks_ath_when_requested() {
        let mut builder = ProofBuilder::new();
        builder.ath = Some("correct-ath".to_string());
        let proof = builder.build();

        verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            Some("correct-ath"),
            chrono::Duration::seconds(60),
        )
        .expect("a matching ath must be accepted");

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            Some("wrong-ath"),
            chrono::Duration::seconds(60),
        )
        .expect_err("a mismatched ath must be refused");
        assert!(matches!(err, DpopError::AthMismatch));
    }

    #[test]
    fn requires_ath_when_caller_expects_one() {
        let proof = ProofBuilder::new().build(); // no ath in the proof
        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            Some("expected-ath"),
            chrono::Duration::seconds(60),
        )
        .expect_err("a missing ath must be refused when the caller expects one");
        assert!(matches!(err, DpopError::AthMismatch));
    }

    #[test]
    fn rejects_a_low_order_key() {
        // The identity point: the canonical universal low-order vector.
        let identity = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(&identity),
        });
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": jwk,
        });
        let payload = serde_json::json!({
            "htm": "POST",
            "htu": "https://as.example.com/token",
            "iat": chrono::Utc::now().timestamp(),
            "jti": "j1",
        });
        let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
        // The universal forgery: R = identity, S = 0.
        let mut forged_sig = [0u8; 64];
        forged_sig[..32].copy_from_slice(&identity);
        let proof = format!("{signing_input}.{}", b64(&forged_sig));

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a low-order key must be refused");
        assert!(matches!(err, DpopError::WeakKey(_)));
    }

    #[test]
    fn rejects_a_private_jwk_member() {
        let builder = ProofBuilder::new();
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64(builder.signing_key.verifying_key().as_bytes()),
                "d": "smuggled-private-scalar",
            },
        });
        let payload = serde_json::json!({
            "htm": "POST",
            "htu": "https://as.example.com/token",
            "iat": chrono::Utc::now().timestamp(),
            "jti": "j1",
        });
        let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
        let signature = builder.signing_key.sign(signing_input.as_bytes());
        let proof = format!("{signing_input}.{}", b64(&signature.to_bytes()));

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a jwk carrying a private component must be refused");
        assert!(matches!(err, DpopError::PrivateOrSymmetricJwk(_)));
    }

    #[test]
    fn rejects_a_missing_jwk() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
        });
        let payload = serde_json::json!({
            "htm": "POST",
            "htu": "https://as.example.com/token",
            "iat": chrono::Utc::now().timestamp(),
            "jti": "j1",
        });
        let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
        // The signature content doesn't matter — this must be rejected
        // before signature verification, for lack of a key to verify with.
        let proof = format!("{signing_input}.{}", b64(&[0u8; 64]));

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("a proof with no embedded jwk must be refused");
        assert!(matches!(err, DpopError::MissingOrInvalidJwk(_)));
    }

    /// Every other test in this module signs with Ed25519 via
    /// `ProofBuilder`. ES256 (an EC P-256 key) is the algorithm most
    /// real-world DPoP clients actually use, and exercises a genuinely
    /// different code path: `expected_algorithm`'s `EllipticCurve` arm and
    /// `jsonwebtoken`'s ECDSA verifier, neither of which the strict-EdDSA
    /// gate (a no-op for non-OKP keys) touches at all.
    #[test]
    fn accepts_a_genuine_es256_proof() {
        use jsonwebtoken::{Algorithm as JwtAlgorithm, EncodingKey, Header};
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::elliptic_curve::{JwkEcKey, PublicKey as P256PublicKey};
        use p256::pkcs8::EncodePrivateKey;
        use rand_core::OsRng;

        let signing_key = P256SigningKey::random(&mut OsRng);
        let public_key: P256PublicKey<p256::NistP256> = signing_key.verifying_key().into();
        let public_jwk: Jwk =
            serde_json::from_value(serde_json::to_value(JwkEcKey::from(&public_key)).unwrap())
                .expect("a p256 public JwkEcKey must parse as a jsonwebtoken Jwk");

        let mut header = Header::new(JwtAlgorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(public_jwk);

        let claims = serde_json::json!({
            "htm": "POST",
            "htu": "https://as.example.com/token",
            "iat": chrono::Utc::now().timestamp(),
            "jti": "es256-proof-1",
        });

        let pkcs8_der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let proof = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(&pkcs8_der))
            .expect("encoding a genuine ES256 JWS must succeed");

        let verified = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect("a genuine ES256 proof must be accepted");
        assert_eq!(verified.jti, "es256-proof-1");
    }

    /// authkestra#277 review: a `jti` this module hands to a downstream
    /// replay-guard store must not be unbounded — the MySQL `AtomicInsert`
    /// backend's key column is `VARCHAR(255)`, so a longer `jti` would
    /// otherwise fail there instead of being cleanly refused here.
    #[test]
    fn rejects_a_jti_longer_than_the_max() {
        let mut builder = ProofBuilder::new();
        builder.jti = "j".repeat(MAX_JTI_LEN + 1);
        let proof = builder.build();

        let err = verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect_err("an over-long jti must be refused");
        assert!(matches!(err, DpopError::JtiTooLong(len) if len == MAX_JTI_LEN + 1));
    }

    #[test]
    fn a_jti_at_exactly_the_max_length_is_accepted() {
        let mut builder = ProofBuilder::new();
        builder.jti = "j".repeat(MAX_JTI_LEN);
        let proof = builder.build();

        verify_dpop_proof(
            &proof,
            "POST",
            Some("https://as.example.com/token"),
            None,
            chrono::Duration::seconds(60),
        )
        .expect("a jti at exactly the max length must be accepted");
    }

    /// `canonicalize_htu`'s non-URL fallback compares the original strings
    /// as-is — no case-folding, matching the (corrected) doc comment. Calls
    /// the private function directly since there is no other way to
    /// observe this branch: both sides of `verify_dpop_proof`'s comparison
    /// always run through the same fallback together.
    #[test]
    fn canonicalize_htu_falls_back_to_exact_comparison_for_non_urls() {
        assert_eq!(canonicalize_htu("not-a-url"), "not-a-url");
        assert_ne!(canonicalize_htu("not-a-url"), canonicalize_htu("Not-A-Url"));
    }

    #[test]
    fn thumbprint_matches_a_known_rfc7638_test_vector() {
        // The exact example key and thumbprint from RFC 7638 §3.1.
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        }))
        .unwrap();
        assert_eq!(
            compute_jwk_thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// #353: the adapters map every `DpopError` onto a single
    /// `invalid_dpop_proof` response, so before this the reason a proof was
    /// refused existed nowhere at all. The reason is reported once at the
    /// boundary, and this asserts it actually says which check failed.
    ///
    /// Installing a subscriber also makes the instrumentation genuinely run:
    /// `tracing` skips its field expressions entirely when none is present,
    /// so without this the fields are never evaluated by any test.
    #[test]
    fn a_rejected_proof_reports_which_check_failed() {
        let proof = ProofBuilder::new().build();

        let (result, logs) = crate::test_support::capture(|| {
            // Signed for POST, presented as GET.
            verify_dpop_proof(&proof, "GET", None, None, chrono::Duration::seconds(60))
        });

        assert!(matches!(result, Err(DpopError::WrongHtm)));
        assert!(
            logs.contains("DPoP proof rejected"),
            "the rejection should be reported; got:\n{logs}"
        );
        // `%error` renders `DpopError`'s `Display`, so the line carries the
        // reason in prose rather than as a variant name — which is what an
        // operator wants, and is the whole point of logging it here.
        assert!(
            logs.contains("htm does not match the request method"),
            "the log must name the check that failed, not just that one did; got:\n{logs}"
        );
        assert!(
            !logs.contains(&proof),
            "the proof is a credential and must never be logged:\n{logs}"
        );
    }

    /// The accepting side of the same boundary.
    #[test]
    fn an_accepted_proof_is_logged_at_debug_without_the_proof_itself() {
        let proof = ProofBuilder::new().build();

        let (result, logs) = crate::test_support::capture(|| {
            verify_dpop_proof(
                &proof,
                "POST",
                Some("https://as.example.com/token"),
                None,
                chrono::Duration::seconds(60),
            )
        });

        assert!(result.is_ok(), "the fixture must produce a valid proof");
        assert!(
            logs.contains("DPoP proof verified"),
            "a successful verification should be visible at debug; got:\n{logs}"
        );
        assert!(
            !logs.contains(&proof),
            "the proof must never be logged:\n{logs}"
        );
    }

    #[test]
    fn rejects_extreme_negative_iat_without_overflow() {
        for bad_iat in [i64::MIN, i64::MIN + 1, -1, 0] {
            let mut builder = ProofBuilder::new();
            builder.iat = bad_iat;
            let proof = builder.build();

            let err = verify_dpop_proof(
                &proof,
                "POST",
                Some("https://as.example.com/token"),
                None,
                chrono::Duration::seconds(60),
            )
            .expect_err("extreme/non-positive iat must be rejected as stale");
            assert!(
                matches!(err, DpopError::Stale),
                "expected DpopError::Stale for iat={bad_iat}, got {err:?}"
            );
        }
    }
}
