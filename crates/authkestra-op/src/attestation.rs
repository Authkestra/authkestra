//! Device/service attestation issuance — the Issuer side of the
//! device-bound-signature authentication method.
//!
//! This is an extension, not new infrastructure: `authkestra-op` already
//! owns signing-key management, rotation, JWKS publication and discovery.
//! What is added here is the enrolment/re-issuance ceremony that binds a
//! caller-held public key to an identity, plus attestation minting on top
//! of the existing `TokenManager`.
//!
//! See the design spec this implements (`authkestra-device-signature-spec.md`
//! §5.6/§5.6.1) referenced from
//! <https://github.com/marcjazz/authkestra/issues/136>.

use crate::error::OpError;
use async_trait::async_trait;
use authkestra_engine::store::{AtomicConsume, KvStore};
use base64::Engine;
use chrono::{DateTime, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// Distinguishes a real end-user device from a backend service asserting it
/// has verified one (spec §5.6.1). Carried through the enrolment ceremony
/// into the issued attestation's `principal_type` claim so a verifier never
/// has to guess — or conflate — which kind of caller it is looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    /// A real end-user device: the private key lives in hardware-backed
    /// storage (Secure Enclave / StrongBox / Keystore) on a phone.
    Device,
    /// A backend service (e.g. a BFF) asserting that it verified a device
    /// signature and is now forwarding that fact under its own key. See
    /// spec §5.6.1 — this is a different claim than "a device signed this"
    /// and must not be conflated with it.
    Service,
}

impl PrincipalType {
    /// The wire value used in JSON claims. Written by hand (rather than via
    /// `serde_json::to_value`) so minting an attestation never has a
    /// fallible serialization step for what is, in practice, an infallible
    /// two-variant enum.
    fn as_str(self) -> &'static str {
        match self {
            PrincipalType::Device => "device",
            PrincipalType::Service => "service",
        }
    }
}

/// Configuration for the attestation ceremony. Deliberately separate from
/// `OpConfig`: that type describes standard OAuth2/OIDC provider behavior
/// that every existing handler already depends on, and this extension
/// should not force every call site to grow new fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttestationConfig {
    /// Lifetime, in seconds, of an issued attestation. ADR 0014 decision
    /// point 6 chose **24 hours** as the default: short enough that a
    /// revoked device's worst-case transacting window is bounded, long
    /// enough that a user offline for a working day does not return to a
    /// dead app.
    pub attestation_ttl_secs: u64,
    /// After this many seconds, the OP recommends the client silently
    /// attempt re-issuance in the background. Returned to the client as
    /// `reissue_after` (see `AttestationResponse`) so the checkpoint lives
    /// in one place — server config — rather than as a client-hardcoded
    /// magic number. ADR 0014 recommends the halfway point (12h of a 24h
    /// lifetime).
    pub attestation_reissue_after_secs: u64,
    /// Lifetime, in seconds, of an enrolment/re-issuance challenge (spec
    /// §5.6 steps 3-5). This is a proof-of-possession nonce, not a
    /// session — keep it short (minutes, not hours).
    pub challenge_ttl_secs: u64,
}

/// An opaque second-factor proof submitted alongside an enrolment request.
/// `authkestra-op` does not interpret this — it hands it to whatever
/// [`SecondFactorVerifier`] the host application configured. See that
/// trait's docs for why this is a pluggable hook rather than a built-in SMS
/// OTP implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecondFactorProof {
    /// Application-defined discriminator (e.g. `"sms_otp"`,
    /// `"bootstrap_secret"`, `"admin_approval"`). Opaque to `authkestra-op`.
    pub kind: String,
    /// Application-defined proof value, interpreted only by the configured
    /// `SecondFactorVerifier`.
    pub value: String,
}

/// Verifies a caller's second factor before the OP will issue an enrolment
/// challenge.
///
/// **Why this is a trait and not a built-in SMS-OTP implementation**: a
/// device can receive an SMS OTP, but a service principal (spec §5.6.1)
/// cannot — there is no phone to text. Rather than hardcode one mechanism
/// and bolt on a special case for services, `authkestra-op` stays agnostic
/// and lets the host application supply whatever verification makes sense
/// per `PrincipalType`: an SMS/TOTP check for devices, and — for
/// services — an out-of-band admin approval or a one-time bootstrap secret
/// consumed exactly once. This is the most idiomatic shape for a generic
/// auth framework that should not hardcode a telecom integration. See the
/// PR description for the alternatives considered.
#[async_trait]
pub trait SecondFactorVerifier: Send + Sync {
    /// Returns `Ok(())` if `proof` is a valid second factor for `subject`
    /// enrolling a principal of `principal_type` with authorized `attributes`. Any `Err` is surfaced to
    /// the caller as `OpError::SecondFactorFailed` — implementations should
    /// log their own specifics and not leak them into the OAuth-shaped
    /// error response.
    async fn verify(
        &self,
        subject: &str,
        principal_type: PrincipalType,
        proof: &SecondFactorProof,
        attributes: &Value,
    ) -> Result<(), OpError>;
}

/// Supplies the current status/attributes for a principal at re-issuance
/// time.
///
/// `authkestra-op` does not own KYC level, role assignments, or device
/// revocation state — the host application does. Without this hook,
/// re-issuance would have to either blindly copy the previous attestation's
/// `att` claim forward (silently missing an attribute change, and, worse,
/// silently re-attesting a device the application has since revoked) or
/// require a full second-factor ceremony every 12 hours (defeating the
/// point of "silent" re-issue). Implementing this trait is optional: if
/// none is configured, re-issuance falls back to copying the previous `att`
/// claim forward unchanged, which is still bound by proof-of-possession —
/// just blind to revocation between full ceremonies.
#[async_trait]
pub trait AttestationStatusProvider: Send + Sync {
    /// Returns `Ok(Some(attributes))` to allow re-issuance with the given
    /// (possibly updated) `att` claim, or `Ok(None)` if this principal is no
    /// longer active — re-issuance is then refused with
    /// `OpError::PrincipalRevoked`.
    async fn current_attributes(
        &self,
        subject: &str,
        principal_id: &str,
        principal_type: PrincipalType,
    ) -> Result<Option<Value>, OpError>;
}

/// A server-generated, single-use, short-TTL enrolment/re-issuance
/// challenge — the proof-of-possession nonce at the heart of spec §5.6
/// steps 3-5. **Never accept a client-chosen value in its place**; that
/// does not satisfy proof-of-possession (conformance case 21).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EnrolmentChallenge {
    /// The opaque, server-generated challenge value.
    pub challenge: String,
    /// The identity this key will be bound to at completion.
    pub subject: String,
    /// Opaque device/service identifier, carried into the attestation's
    /// `did` claim.
    pub principal_id: String,
    /// Device vs. service (spec §5.6.1).
    pub principal_type: PrincipalType,
    /// The public JWK submitted with this challenge, as raw JSON. Kept raw
    /// (not just the typed, already-validated form) so it is re-validated
    /// from scratch at completion — see `parse_public_jwk`'s doc for why a
    /// value should never be trusted just because it was accepted once.
    pub public_jwk: Value,
    /// The `att` claim this attestation will carry once minted.
    pub attributes: Value,
    /// When this challenge expires.
    pub expires_at: DateTime<Utc>,
}

impl EnrolmentChallenge {
    /// Creates a new enrolment/re-issuance challenge.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from outside
    /// this crate, but `EnrolmentChallengeStore` implementations must be
    /// able to reconstruct a challenge from their own storage — this is the
    /// seam that makes that possible (authkestra#268).
    pub fn new(
        challenge: String,
        subject: String,
        principal_id: String,
        principal_type: PrincipalType,
        public_jwk: Value,
        attributes: Value,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            challenge,
            subject,
            principal_id,
            principal_type,
            public_jwk,
            attributes,
            expires_at,
        }
    }

    /// Returns true if this challenge is expired as of `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Storage interface for enrolment/re-issuance challenges.
///
/// `consume_challenge` **must** be atomic, for the same reason
/// `AuthorizationCodeStore::consume_code` must be: a check-then-delete
/// implemented as two separate storage calls is a TOCTOU race that permits
/// challenge replay (conformance case 24).
#[async_trait]
pub trait EnrolmentChallengeStore: Send + Sync {
    /// Persists a newly issued challenge.
    async fn store_challenge(&self, challenge: EnrolmentChallenge) -> Result<(), OpError>;

    /// Atomically retrieves and invalidates a challenge by its value.
    /// Returns `Ok(None)` if it does not exist, is already used, or is
    /// expired — callers map that to `OpError::InvalidChallenge` without
    /// distinguishing which case occurred, to avoid leaking timing/existence
    /// information to a potential attacker.
    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> Result<Option<EnrolmentChallenge>, OpError>;
}

/// Blanket impl over any backend that is a `KvStore` with atomic consume —
/// exactly the shape `AuthorizationCodeStore` already uses (`code.rs`) for
/// the same single-use/short-TTL requirement. Copied deliberately rather
/// than inventing a new storage abstraction.
#[async_trait]
impl<S> EnrolmentChallengeStore for S
where
    S: KvStore<EnrolmentChallenge> + AtomicConsume<EnrolmentChallenge>,
{
    async fn store_challenge(&self, challenge: EnrolmentChallenge) -> Result<(), OpError> {
        tracing::debug!(
            principal_type = ?challenge.principal_type,
            "storing enrolment challenge"
        );
        let ttl = challenge
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        let key = challenge.challenge.clone();
        self.set(&key, challenge, ttl).await.map_err(|e| {
            tracing::error!(error = %e, "failed to store enrolment challenge");
            OpError::Storage
        })
    }

    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> Result<Option<EnrolmentChallenge>, OpError> {
        tracing::trace!("attempting to consume enrolment challenge");
        self.consume(challenge).await.map_err(|e| {
            tracing::error!(error = %e, "failed to consume enrolment challenge");
            OpError::Storage
        })
    }
}

/// The raw JWK member names that must never appear on a key a caller
/// submits for enrolment: the private/secret components of every key type
/// this method could plausibly be asked to accept (RFC 7518 §6.2.2/§6.3.2),
/// plus the symmetric key value `k`. Checked against the **raw JSON**
/// before any typed parse touches the value — `jsonwebtoken::jwk::Jwk`
/// silently drops unknown members (including a smuggled `d`) because its
/// typed struct has no field for them, so a check performed only after
/// typed parsing would miss exactly the attack this exists to catch.
const PRIVATE_JWK_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// Validates a caller-submitted public JWK and returns its typed form.
///
/// Rejects:
/// - anything that isn't a JSON object,
/// - any private or symmetric-secret component (see `PRIVATE_JWK_MEMBERS`),
/// - anything that doesn't parse as a `jsonwebtoken::jwk::Jwk`,
/// - symmetric (`oct`) keys outright — this method is asymmetric-only
///   (spec §5.7.1: no HMAC anywhere in this path, since the verifier would
///   need the same secret).
pub fn parse_public_jwk(raw: &Value) -> Result<Jwk, OpError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| OpError::BadJwk("jwk must be a JSON object".to_string()))?;

    for member in PRIVATE_JWK_MEMBERS {
        if obj.contains_key(member) {
            return Err(OpError::BadJwk(format!(
                "jwk carries a private or symmetric-secret component: {member}"
            )));
        }
    }

    let jwk: Jwk = serde_json::from_value(raw.clone())
        .map_err(|e| OpError::BadJwk(format!("failed to parse jwk: {e}")))?;

    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(_) | AlgorithmParameters::RSA(_) => Ok(jwk),
        AlgorithmParameters::OctetKeyPair(params) => {
            // `crv` is checked first, and non-Ed25519 is a hard refusal rather
            // than a pass-through (authkestra#256). `jsonwebtoken`'s
            // `OctetKeyPairParameters::curve` is the *shared* `EllipticCurve`
            // enum, so `{"kty":"OKP","crv":"P-256"}` deserialises happily into
            // this variant — while `expected_algorithm` maps every
            // `OctetKeyPair` to `Algorithm::EdDSA` and
            // `DecodingKey::from_jwk` sends every `OctetKeyPair` to
            // `from_ed_components`, both regardless of `crv`. So `x` is
            // interpreted as Ed25519 bytes whatever `crv` claims, and a
            // low-order check written as `if crv == Ed25519 { ... }` is
            // simply skipped by setting `crv` to anything else. Refusing the
            // key outright is what makes the check below unavoidable.
            if params.curve != jsonwebtoken::jwk::EllipticCurve::Ed25519 {
                tracing::warn!(
                    curve = ?params.curve,
                    "rejecting OKP jwk: Ed25519 is the only OKP curve this OP verifies, and every \
                     OKP key is decoded as Ed25519 downstream — accepting another `crv` would let \
                     a key skip the low-order check while still reaching the Ed25519 verifier \
                     (authkestra#256)"
                );
                return Err(OpError::BadJwk(format!(
                    "Ed25519 is the only supported OKP curve, got {:?}",
                    params.curve
                )));
            }

            authkestra_crypto_util::parse_ed25519_verifying_key_strict(&params.x).map_err(|e| {
                tracing::warn!(
                    error = %e,
                    "rejecting OKP jwk at ingest; a low-order point here would let the OP mint an \
                     attestation for a key no private key exists for (authkestra#256)"
                );
                OpError::BadJwk(e.to_string())
            })?;

            Ok(jwk)
        }
        AlgorithmParameters::OctetKey(_) => Err(OpError::BadJwk(
            "symmetric keys are never valid for device/service attestation".to_string(),
        )),
        _ => Err(OpError::BadJwk(
            "Unsupported algorithm parameter".to_string(),
        )),
    }
}

/// Computes the RFC 7638 SHA-256 thumbprint of a public JWK — the value
/// that becomes `cnf.jkt` on the issued attestation. **Always called by the
/// OP itself, on a JWK it just validated proof-of-possession over — never
/// accept this value as caller input.** Accepting a caller-supplied
/// `cnf.jkt` lets an attacker bind someone else's key to their own identity
/// (spec §5.6 requirement 3); this is the single most security-critical
/// rule in this file.
///
/// **Guarded against a real panic, not just a hypothetical one.** This
/// workspace pins `jsonwebtoken = "10.4.0"` (a shared workspace-wide pin;
/// bumping it as a side effect of this one extension is out of scope — see
/// the PR description), and on that version `Jwk::thumbprint()` does not
/// return `Err` on a structurally-inconsistent key — it **panics**
/// (`panic!("EllipticCurve can't contain this curve type")`) on a shape like
/// `kty: "EC"` paired with `crv: "Ed25519"`. `parse_public_jwk` validates the
/// *outer* `AlgorithmParameters` variant (EC/RSA/OctetKeyPair, never
/// symmetric) but does not — and, given the private-field-smuggling
/// precedent in this same file, *should not be assumed to* — catch every
/// internally-inconsistent shape a caller could submit. Since the `jwk`
/// reaching this function is attacker-controlled by construction (that is
/// the entire premise of the ceremony this file implements), an unguarded
/// call here is a crash-on-attacker-input denial of service on whichever
/// route calls it — and, at the time this was written, one call site
/// (`handle_reissue_start`) called this function **before** the presented
/// attestation is even validated, making it reachable pre-auth. Fixed here,
/// once, in the shared function, rather than trusting every present and
/// future call site to remember to guard it individually.
pub fn compute_cnf_jkt(jwk: &Jwk) -> Result<String, OpError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        jwk.thumbprint(ThumbprintHash::SHA256)
    })) {
        Ok(Ok(thumbprint)) => Ok(thumbprint),
        Ok(Err(e)) => Err(OpError::BadJwk(format!("jwk thumbprint failed: {e}"))),
        Err(_panic) => {
            tracing::warn!(
                "jwk.thumbprint() panicked on a structurally-inconsistent key; rejecting as \
                 bad_jwk instead of propagating the panic (see this function's doc comment)"
            );
            Err(OpError::BadJwk(
                "jwk is structurally inconsistent (e.g. a kty/crv mismatch) and its thumbprint \
                 cannot be computed"
                    .to_string(),
            ))
        }
    }
}

/// Constant-time comparison for the `cnf.jkt` thumbprint check (spec §6.5).
/// A short, dependency-free byte-XOR loop rather than pulling in `subtle`
/// for a single fixed-length hex-string comparison.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The algorithm a given public key can plausibly have been used with. This
/// is **derived from the key itself**, never from an attacker-controlled
/// header — the same "alg comes from configuration, never from the token"
/// rule the request-signature verifier follows (spec §6.3).
fn expected_algorithm(jwk: &Jwk) -> Result<Algorithm, OpError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            EllipticCurve::P256 => Ok(Algorithm::ES256),
            EllipticCurve::P384 => Ok(Algorithm::ES384),
            EllipticCurve::P521 => Err(OpError::BadJwk(
                "P-521 has no corresponding jsonwebtoken::Algorithm".to_string(),
            )),
            EllipticCurve::Ed25519 => Err(OpError::BadJwk(
                "Ed25519 must be represented as an OctetKeyPair, not an EllipticCurve key"
                    .to_string(),
            )),
            _ => Err(OpError::BadJwk("Unsupported elliptic curve".to_string())),
        },
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        AlgorithmParameters::OctetKeyPair(_) => Ok(Algorithm::EdDSA),
        AlgorithmParameters::OctetKey(_) => {
            unreachable!("symmetric keys are rejected by parse_public_jwk before this is reached")
        }
        _ => Err(OpError::BadJwk(
            "Unsupported algorithm parameter".to_string(),
        )),
    }
}

/// The payload shape a challenge signature must carry.
#[derive(Debug, Deserialize)]
struct ChallengePayload {
    challenge: String,
}

/// Verifies `compact_jws` is a valid signature, produced by the private key
/// matching `jwk`, over a payload of `{"challenge": "..."}`. Returns the
/// signed challenge value on success — callers must still check it equals
/// the challenge they consumed (see `handlers::enrolment::handle_complete_challenge`).
///
/// Peeks the raw `alg` from the wire bytes before handing off to
/// `jsonwebtoken`'s typed API: its `Algorithm` deserializer hard-fails on
/// `"none"` or an unrecognised value, which would otherwise collapse a
/// `bad_alg` case into an opaque parse failure rather than the specific
/// rejection reason a conformant implementation should report.
pub(crate) fn verify_challenge_signature(compact_jws: &str, jwk: &Jwk) -> Result<String, OpError> {
    let header_b64 = compact_jws
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(OpError::ChallengeSignatureInvalid)?;

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| OpError::ChallengeSignatureInvalid)?;

    let header_json: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| OpError::ChallengeSignatureInvalid)?;

    let raw_alg = header_json
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(OpError::ChallengeSignatureInvalid)?;

    if raw_alg.eq_ignore_ascii_case("none") || matches!(raw_alg, "HS256" | "HS384" | "HS512") {
        return Err(OpError::BadAlg(raw_alg.to_string()));
    }

    let algorithm = expected_algorithm(jwk)?;

    // Strict EdDSA gate, ahead of `jsonwebtoken`'s non-strict backend
    // (authkestra#256). A no-op for non-OKP keys. Runs before `decode` so a
    // low-order key or a low-order `R` can never satisfy proof of possession;
    // see `strict_jws`'s module doc for why this gates rather than replaces.
    if let Err(rejection) = crate::strict_jws::ensure_strict_eddsa_signature(compact_jws, jwk) {
        return Err(match rejection {
            // A bad KEY is not a bad signature: surfacing this as
            // `ChallengeSignatureInvalid` would hide that the key is the defect.
            crate::strict_jws::StrictEdDsaRejection::Key(msg) => {
                tracing::warn!(error = %msg, "enrolment challenge key refused before verification");
                OpError::BadJwk(msg)
            }
            crate::strict_jws::StrictEdDsaRejection::Signature(msg) => {
                tracing::warn!(error = %msg, "enrolment challenge signature failed strict EdDSA verification");
                OpError::ChallengeSignatureInvalid
            }
        });
    }

    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| OpError::BadJwk(e.to_string()))?;

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false; // the challenge's own TTL is enforced by the challenge store's consume, not by this token
    validation.required_spec_claims.clear();

    let data = jsonwebtoken::decode::<ChallengePayload>(compact_jws, &decoding_key, &validation)
        .map_err(|_| OpError::ChallengeSignatureInvalid)?;

    Ok(data.claims.challenge)
}

/// Builds the `extra` claim map for a device/service attestation (spec
/// §3.3): `cnf.jkt`, `did`, `principal_type`, `att`. Shared by every path
/// that mints an attestation so the claim shape can't drift between them.
pub(crate) fn attestation_extra_claims(
    jkt: &str,
    principal_id: &str,
    principal_type: PrincipalType,
    attributes: Value,
) -> std::collections::HashMap<String, Value> {
    let mut extra = std::collections::HashMap::new();
    extra.insert("cnf".to_string(), serde_json::json!({ "jkt": jkt }));
    extra.insert("did".to_string(), Value::String(principal_id.to_string()));
    extra.insert(
        "principal_type".to_string(),
        Value::String(principal_type.as_str().to_string()),
    );
    extra.insert("att".to_string(), attributes);
    extra
}

impl AttestationConfig {
    /// Creates a new AttestationConfig.
    pub fn new() -> Self {
        Self {
            attestation_ttl_secs: 86_400,
            attestation_reissue_after_secs: 43_200,
            challenge_ttl_secs: 300,
        }
    }
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_public_jwk_rejects_low_order_ed25519_key() {
        // The identity point: the canonical universal low-order vector.
        let identity_b64 = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let jwk_json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": identity_b64
        });

        let err = super::parse_public_jwk(&jwk_json).expect_err("should reject low order point");
        assert!(
            err.to_string().contains("low-order"),
            "expected low-order point rejection, got: {}",
            err
        );
    }

    use super::*;

    fn valid_ec_jwk() -> Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        })
    }

    #[test]
    fn parse_public_jwk_accepts_valid_ec_key() {
        let jwk = parse_public_jwk(&valid_ec_jwk()).unwrap();
        assert!(matches!(
            jwk.algorithm,
            AlgorithmParameters::EllipticCurve(_)
        ));
    }

    #[test]
    fn parse_public_jwk_rejects_private_component_d() {
        let mut raw = valid_ec_jwk();
        raw["d"] = Value::String("smuggled-private-scalar".to_string());

        let err = parse_public_jwk(&raw).unwrap_err();
        assert!(matches!(err, OpError::BadJwk(_)));
    }

    #[test]
    fn parse_public_jwk_rejects_symmetric_key() {
        let raw = serde_json::json!({ "kty": "oct", "k": "c2VjcmV0" });
        let err = parse_public_jwk(&raw).unwrap_err();
        assert!(matches!(err, OpError::BadJwk(_)));
    }

    #[test]
    fn parse_public_jwk_rejects_non_object() {
        let raw = serde_json::json!("not-an-object");
        let err = parse_public_jwk(&raw).unwrap_err();
        assert!(matches!(err, OpError::BadJwk(_)));
    }

    #[test]
    fn thumbprint_is_stable_for_the_same_key() {
        let jwk = parse_public_jwk(&valid_ec_jwk()).unwrap();
        let jkt1 = compute_cnf_jkt(&jwk).unwrap();
        let jkt2 = compute_cnf_jkt(&jwk).unwrap();
        assert_eq!(jkt1, jkt2);
        // RFC 7638 test vector shape check: URL-safe base64, no padding.
        assert!(!jkt1.contains('='));
    }

    /// Regression guard for the panic this crate's `jsonwebtoken` 10.4.0 pin
    /// has on a structurally-inconsistent key. Constructs a JWK that passes
    /// `parse_public_jwk` (its `kty` selects the `EllipticCurve` variant,
    /// which is an allowed outer shape) but whose `crv` claims a curve
    /// `jsonwebtoken`'s `thumbprint()` cannot handle for that variant — the
    /// exact shape that used to `panic!` rather than return `Err`.
    #[test]
    fn compute_cnf_jkt_rejects_inconsistent_curve_without_panicking() {
        let raw = serde_json::json!({
            "kty": "EC",
            "crv": "Ed25519",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        });
        let jwk = parse_public_jwk(&raw).expect(
            "the outer kty selects a permitted AlgorithmParameters variant; the crv \
             inconsistency only surfaces inside thumbprint() itself, which is exactly what \
             this test exists to prove is now guarded",
        );

        let result = compute_cnf_jkt(&jwk);

        assert!(
            matches!(result, Err(OpError::BadJwk(_))),
            "a jwk whose thumbprint cannot be computed must be rejected as bad_jwk, not panic \
             and not be silently accepted; got {result:?}"
        );
    }

    #[test]
    fn constant_time_eq_matches_string_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
