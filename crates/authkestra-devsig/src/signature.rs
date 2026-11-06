//! Parsing and verification of `X-Signature`: the binding check, the signature itself,
//! freshness, and request binding.
//!
//! ## A note on wire format
//!
//! `X-Signature` is an **ordinary, non-detached compact JWS** — `header.payload.signature`, all
//! three segments present, the claims travelling in the payload like any other JWS. (An earlier
//! design considered an RFC 7515 Appendix F *detached*-payload JWS with an empty payload segment,
//! on the theory that the verifier could "reconstruct" the signed content from the live request.
//! That does not work as stated: `mth`/`pth`/`qsh`/`bdh` genuinely are derivable from the request,
//! but `iat`, `exp`, and `jti` are chosen by the signing device, and a truly empty payload gives
//! the verifier no channel to learn what values it picked. Appendix F only helps when the
//! detached content is available to the verifier some other way; here it isn't, for three of the
//! claims — so the claims travel in the payload as normal, and request-binding is enforced by
//! cross-checking the token's claimed `mth`/`pth`/`qsh`/`bdh`/`aud` against the live request,
//! which is what `verify_bound_and_signed` below does.)
//!
//! The signing input is reconstructed from the **raw base64url segments as received on the
//! wire** (`format!("{header_b64}.{payload_b64}")`), never by re-serializing the parsed JSON —
//! key ordering, whitespace, and numeric formatting are not guaranteed stable across a
//! decode/re-encode round trip, and re-serializing risks silently producing different bytes than
//! what was actually signed.

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::VerifierConfig;
use crate::eddsa::{verify_jws_signature, VerifyFailure};
use crate::error::VerifyError;
use crate::jws_util::{
    constant_time_eq, decode_json_segment, parse_and_check_alg, reject_private_jwk_members,
    split_compact, RawJws,
};
use crate::request::SignedRequest;

#[derive(Debug, Deserialize)]
struct RawSignatureClaims {
    iat: i64,
    exp: i64,
    jti: String,
    mth: String,
    pth: String,
    #[serde(default)]
    qsh: Option<String>,
    #[serde(default)]
    bdh: Option<String>,
    aud: String,
}

/// Result of the cheap, parse-only step: split the compact JWS, validate `alg`, and locate the
/// (still untrusted) embedded `jwk`. No cryptographic or binding decisions are made here — that's
/// [`verify_bound_and_signed`].
#[non_exhaustive]
pub struct ParsedSignature<'a> {
    raw: RawJws<'a>,
    alg: Algorithm,
    jwk_json: Value,
}

/// Splits `token` into compact-JWS segments, checks `alg`, and locates the `jwk` header member
/// (existence only — its contents are untrusted until the binding check).
pub fn parse<'a>(
    token: &'a str,
    allowed_algs: &[Algorithm],
) -> Result<ParsedSignature<'a>, VerifyError> {
    let raw = split_compact(token)?;
    let header_json = decode_json_segment(raw.header_b64)?;
    let alg = parse_and_check_alg(&header_json, allowed_algs)?;
    let jwk_json = header_json
        .get("jwk")
        .cloned()
        .ok_or_else(|| VerifyError::BadJwk("signature header has no embedded jwk".to_string()))?;
    Ok(ParsedSignature { raw, alg, jwk_json })
}

/// What `verify()` needs from a request signature that passed every check.
#[non_exhaustive]
pub struct VerifiedSignature {
    pub jti: String,
    pub exp: i64,
    pub jwk_thumbprint: String,
}

/// The binding check, the request signature, freshness, and request binding, in that order.
///
/// `cnf_jkt` is the attestation's confirmation-key thumbprint — already trusted by the time this
/// is called — the value the embedded `jwk` must thumbprint-match.
pub fn verify_bound_and_signed(
    parsed: &ParsedSignature<'_>,
    request: &SignedRequest<'_>,
    config: &VerifierConfig,
    cnf_jkt: &str,
    now: i64,
) -> Result<VerifiedSignature, VerifyError> {
    // --- THE BINDING (the security-critical step) ---
    reject_private_jwk_members(&parsed.jwk_json)?;

    let jwk: Jwk = serde_json::from_value(parsed.jwk_json.clone())
        .map_err(|e| VerifyError::BadJwk(format!("embedded jwk does not parse: {e}")))?;

    let type_matches_alg = matches!(
        (&jwk.algorithm, parsed.alg.family()),
        (AlgorithmParameters::EllipticCurve(_), AlgorithmFamily::Ec)
            | (AlgorithmParameters::RSA(_), AlgorithmFamily::Rsa)
            | (AlgorithmParameters::OctetKeyPair(_), AlgorithmFamily::Ed)
    );
    if !type_matches_alg {
        return Err(VerifyError::BadJwk(format!(
            "embedded jwk type does not match header alg {:?}",
            parsed.alg
        )));
    }

    // `jsonwebtoken` 10.4.0's `Jwk::thumbprint()` PANICS (not a `Result`) on a
    // structurally-inconsistent kty/crv pairing — `AlgorithmParameters::EllipticCurve` with
    // `curve: Ed25519`, or `AlgorithmParameters::OctetKeyPair` with a Weierstrass curve
    // (P-256/P-384/P-521). Both `EllipticCurveKeyParameters` and `OctetKeyPairParameters` share
    // the same `EllipticCurve` enum for their `crv` field, so serde happily deserializes e.g.
    // `{"kty":"EC","crv":"Ed25519", ...}` into a well-typed `Jwk` — the inconsistency only
    // surfaces inside `thumbprint()`'s match, as an unconditional `panic!`. Since `jwk` here
    // comes straight from the attacker-controlled signature header (this function runs *before*
    // the jwk is trusted — that's the whole point of the binding check below), a crafted
    // kty/crv mismatch would otherwise let a single malformed request panic the verifying task.
    // Reject it as `bad_jwk` before ever calling `thumbprint()`.
    if !curve_is_consistent(&jwk.algorithm) {
        return Err(VerifyError::BadJwk(
            "embedded jwk has an inconsistent kty/crv pairing (e.g. an EC key claiming the \
             Ed25519 curve, or an OKP key claiming a Weierstrass curve)"
                .to_string(),
        ));
    }

    // Belt and braces: guard the call itself too, in case some other input this crate hasn't
    // enumerated also panics inside `thumbprint()`. A caught panic here still must not be able to
    // reach the caller as an actual unwind — it becomes an ordinary `bad_jwk` rejection instead.
    let thumbprint = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        jwk.thumbprint(ThumbprintHash::SHA256)
    }))
    .map_err(|_| {
        tracing::error!(
            target: "authkestra_devsig",
            "embedded jwk panicked inside jsonwebtoken::jwk::Jwk::thumbprint() -- rejecting as \
             bad_jwk instead of propagating the panic"
        );
        VerifyError::BadJwk("embedded jwk is not a supported/consistent key shape".to_string())
    })?
    .map_err(|e| VerifyError::BadJwk(format!("jwk thumbprint failed: {e}")))?;
    if !constant_time_eq(&thumbprint, cnf_jkt) {
        tracing::warn!(
            target: "authkestra_devsig",
            "device-signature rejected: embedded jwk thumbprint does not match attestation cnf.jkt \
             (key_not_bound) — this is the forgery the binding check exists to catch"
        );
        return Err(VerifyError::KeyNotBound);
    }

    // --- REQUEST SIGNATURE ---
    // Only trust `jwk` as a decoding key *after* the binding check above has tied it to the
    // attestation — verifying against an as-yet-unbound key would tell us nothing (an attacker's
    // own key verifies its own signature just fine; that's precisely what the binding check
    // catches).
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        VerifyError::BadJwk(format!("embedded jwk unusable as a decoding key: {e}"))
    })?;

    // EdDSA goes through this crate's own *strict* verifier rather than `jsonwebtoken`'s
    // non-strict one — see `crate::eddsa` for why that distinction is load-bearing precisely
    // here, where `jwk` is attacker-supplied (authkestra#242).
    let signing_input = format!("{}.{}", parsed.raw.header_b64, parsed.raw.payload_b64);
    let sig_ok = verify_jws_signature(
        parsed.alg,
        &jwk,
        &decoding_key,
        parsed.raw.signature_b64,
        signing_input.as_bytes(),
    )
    .map_err(|failure| match failure {
        // A key that cannot be used, or must not be used, is a `bad_jwk` — reporting it as
        // `bad_signature` would blame the signature for a defect that is in the key.
        VerifyFailure::Key(reason) => VerifyError::BadJwk(reason),
        VerifyFailure::Backend(reason) => {
            VerifyError::BadSignature(format!("verification error: {reason}"))
        }
    })?;
    if !sig_ok {
        return Err(VerifyError::BadSignature(
            "signature does not verify".to_string(),
        ));
    }

    // Only parse (and trust) the claims once the signature over them has been verified.
    let claims_json = decode_json_segment(parsed.raw.payload_b64)?;
    let claims: RawSignatureClaims = serde_json::from_value(claims_json)
        .map_err(|e| VerifyError::Malformed(format!("invalid signature claims: {e}")))?;

    // --- FRESHNESS ---
    let skew = config.max_clock_skew.as_secs() as i64;
    if now < claims.iat - skew || now > claims.exp + skew {
        return Err(VerifyError::SignatureExpired);
    }
    let lifetime = claims.exp - claims.iat;
    if lifetime < 0 || lifetime as u64 > config.max_signature_lifetime.as_secs() {
        return Err(VerifyError::LifetimeTooLong);
    }

    // --- REQUEST BINDING ---
    if claims.mth != request.method {
        return Err(VerifyError::MethodMismatch);
    }
    if claims.pth != request.path {
        return Err(VerifyError::PathMismatch);
    }
    if claims.aud != config.audience {
        return Err(VerifyError::AudienceMismatch);
    }
    if request.query.is_some() || claims.qsh.is_some() {
        match (request.query, &claims.qsh) {
            (Some(query), Some(qsh)) => {
                let computed = hex_sha256(query.as_bytes());
                if !constant_time_eq(qsh, &computed) {
                    tracing::warn!(target: "authkestra_devsig", "query string hash mismatch");
                    return Err(VerifyError::QueryMismatch);
                }
            }
            _ => {
                tracing::warn!(
                    target: "authkestra_devsig",
                    request_has_query = request.query.is_some(),
                    claims_has_qsh = claims.qsh.is_some(),
                    "query hash stripping or unexpected query parameter detected"
                );
                return Err(VerifyError::QueryMismatch);
            }
        }
    }

    if request.body.is_some() || claims.bdh.is_some() {
        match (request.body, &claims.bdh) {
            (Some(body), Some(bdh)) => {
                let computed = hex_sha256(body);
                if !constant_time_eq(bdh, &computed) {
                    tracing::warn!(target: "authkestra_devsig", "body digest hash mismatch");
                    return Err(VerifyError::BodyMismatch);
                }
            }
            _ => {
                tracing::warn!(
                    target: "authkestra_devsig",
                    request_has_body = request.body.is_some(),
                    claims_has_bdh = claims.bdh.is_some(),
                    "body digest stripping or unexpected body detected"
                );
                return Err(VerifyError::BodyMismatch);
            }
        }
    }

    Ok(VerifiedSignature {
        jti: claims.jti,
        exp: claims.exp,
        jwk_thumbprint: thumbprint,
    })
}

/// Whether `algorithm`'s kty/crv pairing is one `jsonwebtoken::jwk::Jwk::thumbprint()` can
/// actually compute without panicking (see the safety note at its call site above). RSA and
/// octet (symmetric) keys have no `crv` field at all and are always safe here — the family
/// mismatch that would make a symmetric key reach this point at all is already rejected earlier.
fn curve_is_consistent(algorithm: &AlgorithmParameters) -> bool {
    match algorithm {
        AlgorithmParameters::EllipticCurve(p) => !matches!(p.curve, EllipticCurve::Ed25519),
        AlgorithmParameters::OctetKeyPair(p) => matches!(p.curve, EllipticCurve::Ed25519),
        AlgorithmParameters::RSA(_) | AlgorithmParameters::OctetKey(_) => true,
        _ => false,
    }
}


fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
