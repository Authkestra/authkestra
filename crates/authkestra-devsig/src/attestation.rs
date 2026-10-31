//! Parsing and trust verification of `X-Attestation`.

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::config::VerifierConfig;
use crate::eddsa::{verify_jws_signature, VerifyFailure};
use crate::error::VerifyError;
use crate::jwks::IssuerJwks;
use crate::jws_util::{decode_json_segment, parse_and_check_alg, split_compact, RawJws};

#[derive(Debug, Deserialize)]
struct Cnf {
    jkt: String,
}

#[derive(Debug, Deserialize)]
struct RawAttestationClaims {
    iss: String,
    sub: String,
    cnf: Cnf,
    did: String,
    iat: i64,
    exp: i64,
    att: Value,
}

/// The attestation, once trust has been fully established.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AttestationClaims {
    pub sub: String,
    /// `cnf.jkt` — threaded into the binding check as the value the signature's embedded `jwk`
    /// must thumbprint-match.
    pub jkt: String,
    pub did: String,
    pub att: Value,
}

/// Result of the cheap, parse-only step: split the compact JWS and validate `alg`. No trust
/// decisions are made here — that's [`verify_trust`].
#[non_exhaustive]
pub struct ParsedAttestation<'a> {
    raw: RawJws<'a>,
    alg: Algorithm,
    kid: Option<String>,
    claims_json: Value,
}

/// Splits the attestation into compact-JWS segments and checks `alg`.
pub fn parse<'a>(
    token: &'a str,
    allowed_algs: &[Algorithm],
) -> Result<ParsedAttestation<'a>, VerifyError> {
    let raw = split_compact(token)?;
    let header_json = decode_json_segment(raw.header_b64)?;
    let alg = parse_and_check_alg(&header_json, allowed_algs)?;
    let kid = header_json
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string);
    let claims_json = decode_json_segment(raw.payload_b64)?;
    Ok(ParsedAttestation {
        raw,
        alg,
        kid,
        claims_json,
    })
}

/// Attestation trust: `iss` trusted, `kid` resolves in the cached Issuer JWKS, signature valid,
/// not expired (with skew), and `att.status == "active"` — in that order.
pub async fn verify_trust(
    parsed: &ParsedAttestation<'_>,
    config: &VerifierConfig,
    jwks: &IssuerJwks,
    now: i64,
) -> Result<AttestationClaims, VerifyError> {
    let raw_claims: RawAttestationClaims = serde_json::from_value(parsed.claims_json.clone())
        .map_err(|e| VerifyError::Malformed(format!("invalid attestation claims: {e}")))?;

    // Profile v1: `att` is an object of attributes. A bare string (a key role) or a top-level
    // `status` beside a missing `att` are the two shapes this profile exists to retire, and both
    // are refused as malformed rather than read as an inactive device, so a client built against
    // either sees the shape error instead of a renewal loop.
    if !raw_claims.att.is_object() {
        return Err(VerifyError::Malformed(
            "attestation att claim must be a JSON object".to_string(),
        ));
    }

    if !config.trusted_issuers.contains(&raw_claims.iss) {
        tracing::debug!(target: "authkestra_devsig", iss = %raw_claims.iss, "attestation rejected: untrusted issuer");
        return Err(VerifyError::UntrustedIssuer(raw_claims.iss));
    }

    let kid = parsed
        .kid
        .as_deref()
        .ok_or_else(|| VerifyError::UnknownKid("attestation header has no kid".to_string()))?;

    let jwk: Jwk = jwks
        .get(&raw_claims.iss, kid)
        .await
        .ok_or_else(|| VerifyError::UnknownKid(kid.to_string()))?;

    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| VerifyError::BadAttestation(format!("issuer key unusable: {e}")))?;

    // Strict EdDSA here too. The issuer key comes from the cached JWKS rather than from the
    // request, so this is defence in depth rather than a live exposure — but a low-order key that
    // reached the JWKS would let anyone mint attestations for any subject, and the check is free
    // now that `crate::eddsa` exists. See that module's docs (authkestra#242).
    let signing_input = format!("{}.{}", parsed.raw.header_b64, parsed.raw.payload_b64);
    let ok = verify_jws_signature(
        parsed.alg,
        &jwk,
        &decoding_key,
        parsed.raw.signature_b64,
        signing_input.as_bytes(),
    )
    .map_err(|failure| match failure {
        VerifyFailure::Key(reason) => {
            tracing::warn!(
                target: "authkestra_devsig",
                iss = %raw_claims.iss,
                kid,
                "attestation rejected: the issuer key resolved from the JWKS is unusable or unsafe"
            );
            VerifyError::BadAttestation(format!("issuer key unusable: {reason}"))
        }
        VerifyFailure::Backend(reason) => {
            VerifyError::BadAttestation(format!("signature verification error: {reason}"))
        }
    })?;
    if !ok {
        return Err(VerifyError::BadAttestation(
            "signature does not verify".to_string(),
        ));
    }

    let skew = config.max_clock_skew.as_secs() as i64;
    if now < raw_claims.iat - skew || now > raw_claims.exp + skew {
        return Err(VerifyError::AttestationExpired);
    }

    let status = raw_claims
        .att
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if status != "active" {
        tracing::debug!(target: "authkestra_devsig", did = %raw_claims.did, status, "attestation rejected: device not active");
        return Err(VerifyError::DeviceNotActive);
    }

    Ok(AttestationClaims {
        sub: raw_claims.sub,
        jkt: raw_claims.cnf.jkt,
        did: raw_claims.did,
        att: raw_claims.att,
    })
}
