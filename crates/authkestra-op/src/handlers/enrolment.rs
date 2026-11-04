//! Enrolment and re-issuance endpoint handlers for device/service
//! attestations (spec §5.6). Framework-agnostic, like every other handler in
//! this crate — `authkestra-axum`/`authkestra-actix` wrap these into routes.

use crate::attestation::{
    attestation_extra_claims, compute_cnf_jkt, constant_time_eq, parse_public_jwk,
    verify_challenge_signature, AttestationConfig, AttestationStatusProvider, EnrolmentChallenge,
    EnrolmentChallengeStore, PrincipalType, SecondFactorProof, SecondFactorVerifier,
};
use crate::error::OpError;
use authkestra_engine::token::TokenManager;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The wire `typ` header on every attestation this crate issues (spec
/// §3.3). Shared as a constant so enrolment and re-issuance can never
/// accidentally drift apart on it.
const ATTESTATION_TYP: &str = "webank-attest+jws";

/// Request to begin enrolment of a brand-new device or service key (spec
/// §5.6 steps 1-3). The caller submits its freshly-generated public key, an
/// identity claim, and a second factor; the OP responds with a
/// server-generated single-use challenge.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct EnrolStartRequest {
    /// The identity this key will be bound to at completion.
    pub subject: String,
    /// Opaque device/service identifier, carried into the attestation's
    /// `did` claim.
    pub principal_id: String,
    /// Whether this is a real end-user device or a backend service
    /// asserting it verified one (spec §5.6.1).
    pub principal_type: PrincipalType,
    /// The freshly-generated public JWK — exactly what will later appear in
    /// the protected header of every request signature this key produces.
    /// Re-validated at every use (see `parse_public_jwk`).
    pub public_jwk: Value,
    /// Application-defined attributes for the attestation's `att` claim
    /// (e.g. `kyc_level`, `roles`, `status`).
    pub attributes: Value,
    /// The caller's second-factor proof, interpreted by whichever
    /// `SecondFactorVerifier` the host application configured.
    pub second_factor: SecondFactorProof,
    /// **Deliberately ignored.** A caller may attempt to suggest its own
    /// `cnf.jkt`; the OP always computes it fresh from `public_jwk` at
    /// completion (spec §5.6 requirement 3 — accepting caller input here
    /// would let an attacker bind someone else's key to their own
    /// identity). Present on the request type only so this property is
    /// observable/testable rather than simply having nowhere to put it —
    /// see conformance case 23 and this module's tests.
    #[serde(default)]
    pub requested_cnf_jkt: Option<String>,
}

/// Request to re-issue a near-expiry attestation without repeating the full
/// second-factor ceremony (ADR 0014 decision point 6: 24h lifetime, silent
/// re-issue at the 12h mark). The caller re-submits its public key; the OP
/// checks it against the presented attestation's `cnf.jkt` using the exact
/// same thumbprint-binding check the request-signature verifier performs on
/// every ordinary request (spec §4 step 4) — proving continued possession
/// of the same key stands in for the second factor here, on the reasoning
/// that the second factor was already verified once, at initial enrolment,
/// and this ceremony's job is to prove *continuity*, not re-establish
/// identity from scratch.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ReissueStartRequest {
    /// The current, still cryptographically valid attestation being
    /// renewed.
    pub attestation: String,
    /// The same public JWK the presented attestation is bound to.
    pub public_jwk: Value,
    /// Deliberately ignored — see `EnrolStartRequest::requested_cnf_jkt`.
    #[serde(default)]
    pub requested_cnf_jkt: Option<String>,
}

/// A server-generated, single-use, short-TTL proof-of-possession challenge.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct ChallengeResponse {
    /// The challenge value to sign with the new private key.
    pub challenge: String,
    /// Seconds until this challenge expires. It is also single-use,
    /// whichever comes first.
    pub expires_in: u64,
}

/// Request to complete an enrolment or re-issuance ceremony.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct CompleteChallengeRequest {
    /// The challenge value previously issued.
    pub challenge: String,
    /// Compact JWS whose payload is `{"challenge": "<challenge>"}`, signed
    /// by the *new* private key. A client-chosen nonce in place of the
    /// server's challenge does not satisfy proof-of-possession
    /// (conformance case 21) — this is why `challenge` must match what
    /// `EnrolmentChallengeStore` actually issued, not merely be *a* valid
    /// signature.
    pub challenge_signature: String,
}

/// The issued attestation, its lifetime, and a server-recommended
/// re-issuance checkpoint.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AttestationResponse {
    /// Compact JWS attestation (spec §3.3), `typ: "webank-attest+jws"`.
    pub attestation: String,
    /// Seconds until the attestation expires.
    pub expires_in: u64,
    /// When the client should silently attempt re-issuance
    /// (`handle_reissue_start` / `handle_complete_challenge`). Computed from
    /// `AttestationConfig::attestation_reissue_after_secs` so the interval
    /// is owned by server config, not duplicated as a client constant.
    pub reissue_after: DateTime<Utc>,
}

/// Begins enrolment for a brand-new device or service key (spec §5.6 steps
/// 1-3).
///
/// Verifies the second factor **before** issuing a challenge. The ceremony
/// diagram in the spec shows the second factor checked after the signed
/// challenge comes back (step 6), but doing it eagerly here means an
/// invalid OTP/bootstrap-secret never consumes a single-use challenge, and
/// — for factors like an SMS OTP that are themselves single-use — avoids
/// a design where the same OTP would need to be checked twice. The
/// two-factor requirement is preserved either way: if the second factor
/// fails, no challenge is ever issued, so completion is unreachable.
pub async fn handle_enrol_start(
    req: EnrolStartRequest,
    second_factor: &dyn SecondFactorVerifier,
    challenges: &dyn EnrolmentChallengeStore,
    config: &AttestationConfig,
) -> Result<ChallengeResponse, OpError> {
    // Validate now so a malformed/private-key-carrying JWK is rejected
    // before we ever touch the second factor or the challenge store.
    parse_public_jwk(&req.public_jwk)?;

    second_factor
        .verify(
            &req.subject,
            req.principal_type,
            &req.second_factor,
            &req.attributes,
        )
        .await?;

    tracing::info!(
        subject = %req.subject,
        principal_id = %req.principal_id,
        principal_type = ?req.principal_type,
        "second factor verified; issuing enrolment challenge"
    );

    issue_challenge(
        req.subject,
        req.principal_id,
        req.principal_type,
        req.public_jwk,
        req.attributes,
        challenges,
        config,
    )
    .await
}

/// Begins re-issuance of a near-expiry attestation.
pub async fn handle_reissue_start(
    req: ReissueStartRequest,
    tokens: &TokenManager,
    status: Option<&dyn AttestationStatusProvider>,
    challenges: &dyn EnrolmentChallengeStore,
    config: &AttestationConfig,
) -> Result<ChallengeResponse, OpError> {
    let claims = tokens.validate_token(&req.attestation, None).map_err(|e| {
        tracing::warn!(error = ?e, "presented attestation failed validation at re-issuance");
        OpError::AttestationInvalid
    })?;

    let jwk = parse_public_jwk(&req.public_jwk)?;
    let jkt = compute_cnf_jkt(&jwk)?;

    let bound_jkt = claims
        .extra
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .ok_or(OpError::AttestationInvalid)?;

    // THE BINDING CHECK — identical in spirit to spec §4 step 4. Presenting
    // a valid attestation is not enough; the caller must also hold the
    // private key it is bound to.
    if !constant_time_eq(&jkt, bound_jkt) {
        tracing::warn!("re-issuance key does not match attestation's cnf.jkt");
        return Err(OpError::KeyNotBound);
    }

    let principal_type_str = claims
        .extra
        .get("principal_type")
        .and_then(Value::as_str)
        .ok_or(OpError::AttestationInvalid)?;
    let principal_type = match principal_type_str {
        "device" => PrincipalType::Device,
        "service" => PrincipalType::Service,
        _ => return Err(OpError::AttestationInvalid),
    };

    let principal_id = claims
        .extra
        .get("did")
        .and_then(Value::as_str)
        .ok_or(OpError::AttestationInvalid)?
        .to_string();

    let subject = claims.sub;

    let attributes = match status {
        Some(provider) => provider
            .current_attributes(&subject, &principal_id, principal_type)
            .await?
            .ok_or(OpError::PrincipalRevoked)?,
        None => claims.extra.get("att").cloned().unwrap_or(Value::Null),
    };

    tracing::info!(
        subject = %subject,
        principal_id = %principal_id,
        principal_type = ?principal_type,
        "re-issuance binding verified; issuing challenge"
    );

    issue_challenge(
        subject,
        principal_id,
        principal_type,
        req.public_jwk,
        attributes,
        challenges,
        config,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn issue_challenge(
    subject: String,
    principal_id: String,
    principal_type: PrincipalType,
    public_jwk: Value,
    attributes: Value,
    challenges: &dyn EnrolmentChallengeStore,
    config: &AttestationConfig,
) -> Result<ChallengeResponse, OpError> {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);

    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs as i64);

    challenges
        .store_challenge(EnrolmentChallenge {
            challenge: challenge.clone(),
            subject,
            principal_id,
            principal_type,
            public_jwk,
            attributes,
            expires_at,
        })
        .await?;

    Ok(ChallengeResponse {
        challenge,
        expires_in: config.challenge_ttl_secs,
    })
}

/// Completes an enrolment or re-issuance ceremony: consumes the (single-use)
/// challenge, verifies the signature was produced by the private key
/// matching the JWK submitted when the challenge was requested, computes
/// `cnf.jkt` itself from that JWK — **never from anything in this
/// request** — and mints the attestation.
///
/// Shared by both flows deliberately: by the time a challenge exists, the
/// only remaining question is proof-of-possession, which is identical
/// whether this is a first enrolment or a renewal.
pub async fn handle_complete_challenge(
    req: CompleteChallengeRequest,
    challenges: &dyn EnrolmentChallengeStore,
    tokens: &TokenManager,
    config: &AttestationConfig,
) -> Result<AttestationResponse, OpError> {
    let challenge = challenges
        .consume_challenge(&req.challenge)
        .await?
        .ok_or(OpError::InvalidChallenge)?;

    if challenge.is_expired(Utc::now()) {
        return Err(OpError::InvalidChallenge);
    }

    // Re-validate from scratch — never trust that a JWK is still safe just
    // because it was accepted when the challenge was issued.
    let jwk = parse_public_jwk(&challenge.public_jwk)?;

    let signed_challenge = verify_challenge_signature(&req.challenge_signature, &jwk)?;
    if !constant_time_eq(&signed_challenge, &challenge.challenge) {
        tracing::warn!("challenge signature payload does not match the issued challenge");
        return Err(OpError::ChallengeSignatureInvalid);
    }

    // THE SECURITY-CRITICAL STEP: cnf.jkt is computed here, by the OP, from
    // the JWK it just verified possession of. It is never taken from
    // anywhere in `req` — there is nowhere in `CompleteChallengeRequest` a
    // caller even could put one, and `EnrolStartRequest::requested_cnf_jkt`
    // / `ReissueStartRequest::requested_cnf_jkt` are read nowhere in this
    // module (see the tests below).
    let jkt = compute_cnf_jkt(&jwk)?;

    let extra = attestation_extra_claims(
        &jkt,
        &challenge.principal_id,
        challenge.principal_type,
        challenge.attributes.clone(),
    );

    let attestation = tokens
        .issue_custom_token(
            challenge.subject.clone(),
            config.attestation_ttl_secs,
            ATTESTATION_TYP,
            extra,
        )
        .map_err(|e| OpError::TokenIssuance(e.to_string()))?;

    tracing::info!(
        subject = %challenge.subject,
        principal_id = %challenge.principal_id,
        principal_type = ?challenge.principal_type,
        "issued attestation"
    );

    Ok(AttestationResponse {
        attestation,
        expires_in: config.attestation_ttl_secs,
        reissue_after: Utc::now() + Duration::seconds(config.attestation_reissue_after_secs as i64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pre-auth cost-amplification regression guard: `handle_reissue_start`
    /// must validate the presented `attestation` BEFORE doing any work on
    /// the caller-supplied `public_jwk` (parsing it, computing its
    /// thumbprint). This was flagged in review — `parse_public_jwk` and
    /// `compute_cnf_jkt` used to run first, letting any unauthenticated
    /// caller force JSON parsing and a SHA-256 computation on every hit to
    /// this endpoint just by supplying a garbage `attestation`.
    ///
    /// Proven here by supplying BOTH an invalid attestation AND a
    /// malformed public_jwk (one `parse_public_jwk` would itself reject
    /// with `OpError::BadJwk`) in the same request. If attestation
    /// validation still ran first, the error must be `AttestationInvalid`
    /// — never `BadJwk`, which would only surface if `parse_public_jwk`
    /// had already run, meaning the old, vulnerable order had regressed.
    #[tokio::test]
    async fn reissue_validates_attestation_before_touching_the_presented_jwk() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();

        let malformed_jwk = serde_json::json!({"this": "is not a valid jwk"});

        let err = handle_reissue_start(
            ReissueStartRequest {
                attestation: "not.a.valid.jws".to_string(),
                public_jwk: malformed_jwk,
                requested_cnf_jkt: None,
            },
            &tokens,
            None,
            &challenges,
            &config,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, OpError::AttestationInvalid),
            "expected AttestationInvalid (attestation checked first); got {err:?} — \
             a BadJwk error here would mean parse_public_jwk ran before attestation \
             validation, i.e. the pre-auth cost-amplification vector has regressed"
        );
    }
    use async_trait::async_trait;
    use authkestra_engine::store::memory::MemoryStore;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::{JwkEcKey, PublicKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;

    fn test_config() -> AttestationConfig {
        AttestationConfig {
            attestation_ttl_secs: 86_400,
            attestation_reissue_after_secs: 43_200,
            challenge_ttl_secs: 300,
        }
    }

    /// A fresh EC P-256 keypair plus its public JWK as raw JSON, matching
    /// the shape a real device/service would submit.
    struct TestKey {
        /// PKCS#8 DER-encoded private key, as `jsonwebtoken::EncodingKey`
        /// expects for `from_ec_der`.
        pkcs8_der: Vec<u8>,
        public_jwk: Value,
    }

    fn generate_test_key() -> TestKey {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key: PublicKey<p256::NistP256> = signing_key.verifying_key().into();
        let jwk_ec_key = JwkEcKey::from(&public_key);
        let public_jwk = serde_json::to_value(&jwk_ec_key).unwrap();
        let pkcs8_der = signing_key.to_pkcs8_der().unwrap();

        TestKey {
            pkcs8_der: pkcs8_der.as_bytes().to_vec(),
            public_jwk,
        }
    }

    /// Signs `{"challenge": challenge}` with the test key's private key,
    /// exactly as a real device would when completing the ceremony.
    fn sign_challenge(key: &TestKey, challenge: &str) -> String {
        let encoding_key = EncodingKey::from_ec_der(&key.pkcs8_der);
        let header = Header::new(Algorithm::ES256);
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "challenge": challenge }),
            &encoding_key,
        )
        .unwrap()
    }

    struct AlwaysPassSecondFactor;

    #[async_trait]
    impl SecondFactorVerifier for AlwaysPassSecondFactor {
        async fn verify(
            &self,
            _subject: &str,
            _principal_type: PrincipalType,
            _proof: &SecondFactorProof,
            _attributes: &Value,
        ) -> Result<(), OpError> {
            Ok(())
        }
    }

    struct AlwaysFailSecondFactor;

    #[async_trait]
    impl SecondFactorVerifier for AlwaysFailSecondFactor {
        async fn verify(
            &self,
            _subject: &str,
            _principal_type: PrincipalType,
            _proof: &SecondFactorProof,
            _attributes: &Value,
        ) -> Result<(), OpError> {
            Err(OpError::SecondFactorFailed)
        }
    }

    fn test_tokens() -> TokenManager {
        TokenManager::new(b"super_secret_key_that_is_long_enough_for_hmac", None)
    }

    // ---------------------------------------------------------------------
    // authkestra#256: low-order Ed25519 keys must never be enrolled.
    // ---------------------------------------------------------------------

    /// The Ed25519 identity point, encoded as a compressed Edwards point.
    ///
    /// This is the *universal* forgery vector, and it is deliberately not the
    /// all-zero encoding: the all-zero encoding is an order-4 point that only
    /// verifies for roughly one message in four, whereas the identity
    /// verifies for every message.
    const IDENTITY_POINT: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The canned signature `(R = identity, S = 0)`.
    ///
    /// Under **non-strict** Ed25519 verification both sides of
    /// `[S]B - [k]A == R` collapse to the identity for every challenge scalar
    /// `k`, so this single 64-byte constant verifies against the identity
    /// public key for *any* message. No private key exists for that public
    /// key — not "is unknown", does not exist.
    fn forged_universal_signature() -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&IDENTITY_POINT);
        sig
    }

    /// A compact JWS whose signature is the canned universal forgery.
    fn forged_challenge_jws(challenge: &str) -> String {
        let header = b64(br#"{"alg":"EdDSA"}"#);
        let payload = b64(serde_json::json!({ "challenge": challenge })
            .to_string()
            .as_bytes());
        format!("{header}.{payload}.{}", b64(&forged_universal_signature()))
    }

    /// Runs the whole enrolment ceremony with `public_jwk` and returns
    /// whichever step refused it — or `Ok(())` if an attestation was minted,
    /// which for a forged key is the vulnerability.
    async fn attempt_forged_enrolment(public_jwk: Value) -> Result<String, OpError> {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "victim".to_string(),
                principal_id: "attacker-device".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk,
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await?;

        let signature = forged_challenge_jws(&start_res.challenge);

        let complete_res = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await?;

        Ok(complete_res.attestation)
    }

    /// The exact vector authkestra#256 names: `crv: "Ed25519"` carrying the
    /// identity point. Closed at ingest by #261; this pins it so the gate
    /// cannot be removed silently.
    #[tokio::test]
    async fn enrolment_refuses_the_low_order_identity_point() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(&IDENTITY_POINT),
        });

        match attempt_forged_enrolment(jwk).await {
            Err(OpError::BadJwk(msg)) => assert!(
                msg.contains("low-order"),
                "expected the key to be refused as low-order, got: {msg}"
            ),
            Err(other) => panic!(
                "expected BadJwk(low-order); got {other:?} — the key must be \
                 refused on its own merits, not as a bad signature"
            ),
            Ok(attestation) => panic!(
                "VULNERABLE: the OP minted an attestation for a low-order key \
                 nobody holds a private key for: {attestation}"
            ),
        }
    }

    /// The same forgery smuggled past a `crv`-equality gate.
    ///
    /// `jsonwebtoken`'s `OctetKeyPairParameters::curve` is the *shared*
    /// `EllipticCurve` enum, so `{"kty":"OKP","crv":"P-256"}` deserialises to
    /// the `OctetKeyPair` variant carrying `P256`. `expected_algorithm` maps
    /// **every** `OctetKeyPair` to `Algorithm::EdDSA`, and
    /// `DecodingKey::from_jwk` sends every `OctetKeyPair` to
    /// `from_ed_components` regardless of `crv` — so `x` is interpreted as
    /// Ed25519 bytes either way. A low-order check written as
    /// `if params.curve == Ed25519` therefore never runs for this key, while
    /// the Ed25519 verifier still does.
    #[tokio::test]
    async fn enrolment_refuses_a_low_order_key_smuggled_past_the_crv_gate() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "P-256",
            "x": b64(&IDENTITY_POINT),
        });

        match attempt_forged_enrolment(jwk).await {
            Err(OpError::BadJwk(_)) => {}
            Err(other) => panic!("expected BadJwk; got {other:?}"),
            Ok(attestation) => panic!(
                "VULNERABLE: an OKP key with a non-Ed25519 `crv` bypassed the \
                 low-order gate and the OP minted an attestation for it: {attestation}"
            ),
        }
    }

    /// The proof-of-possession check must refuse the forgery *on its own*.
    ///
    /// Regression guard with teeth: on `main` before this fix, the
    /// `crv`-confusion vector below reached
    /// [`verify_challenge_signature`] and it returned `Ok("CHAL")` — the
    /// forged signature verified. The full ceremony was saved only
    /// incidentally, by [`compute_cnf_jkt`] later failing with
    /// `InvalidKeyFormat` because `jsonwebtoken` will not thumbprint an OKP
    /// key whose `crv` is not Ed25519. That is an accident of an unrelated
    /// downstream step, not a security control, and it would evaporate the
    /// moment thumbprinting grew support for another OKP curve. This test
    /// asserts the *verifier itself* refuses these keys, so the fix cannot
    /// silently regress into depending on that accident again.
    #[test]
    fn challenge_signature_verification_itself_refuses_low_order_keys() {
        for crv in ["Ed25519", "P-256", "P-384", "P-521"] {
            // Deliberately built with `serde_json::from_value` rather than
            // `parse_public_jwk`: routing through ingest would make this test
            // vacuous, because ingest refuses these keys first and
            // `verify_challenge_signature` would never run. The point here is
            // the second gate, so the first one is bypassed on purpose.
            let jwk: Jwk = serde_json::from_value(
                serde_json::json!({"kty":"OKP","crv":crv,"x": b64(&IDENTITY_POINT)}),
            )
            .expect("test jwk must parse");

            let outcome = verify_challenge_signature(&forged_challenge_jws("CHAL"), &jwk);

            assert!(
                outcome.is_err(),
                "VULNERABLE: verify_challenge_signature accepted the universal low-order \
                 forgery for crv={crv}: {outcome:?}"
            );
            // A bad KEY, not a bad signature — the classification convention
            // this crate shares with authkestra-devsig.
            assert!(
                matches!(outcome, Err(OpError::BadJwk(_))),
                "expected BadJwk for crv={crv}, got {outcome:?}"
            );
        }
    }

    /// Positive control for the second gate: a genuine Ed25519 signature must
    /// survive `verify_challenge_signature` unchanged.
    #[test]
    fn challenge_signature_verification_still_accepts_a_genuine_ed25519_signature() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(signing.verifying_key().as_bytes()),
        }))
        .unwrap();

        let header = b64(br#"{"alg":"EdDSA"}"#);
        let payload = b64(serde_json::json!({ "challenge": "CHAL" })
            .to_string()
            .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = ed25519_dalek::Signer::sign(&signing, signing_input.as_bytes());

        let out =
            verify_challenge_signature(&format!("{signing_input}.{}", b64(&sig.to_bytes())), &jwk)
                .expect("a genuine Ed25519 challenge signature must still verify");
        assert_eq!(out, "CHAL");
    }

    /// Positive control: a fix that rejects everything is not a fix. A genuine
    /// Ed25519 device key must still complete the ceremony end to end.
    #[tokio::test]
    async fn genuine_ed25519_key_still_enrols_end_to_end() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let public_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(signing.verifying_key().as_bytes()),
        });

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-ed".to_string(),
                principal_id: "device-ed".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: public_jwk.clone(),
                attributes: serde_json::json!({"kyc_level": 3}),
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .expect("a genuine Ed25519 key must be accepted at enrolment start");

        let header = b64(br#"{"alg":"EdDSA"}"#);
        let payload = b64(serde_json::json!({ "challenge": start_res.challenge })
            .to_string()
            .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = ed25519_dalek::Signer::sign(&signing, signing_input.as_bytes());
        let jws = format!("{signing_input}.{}", b64(&sig.to_bytes()));

        let complete_res = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: jws,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .expect("a genuine Ed25519 signature must complete the ceremony");

        let claims = tokens
            .validate_token(&complete_res.attestation, None)
            .unwrap();
        assert_eq!(claims.sub, "user-ed");
        assert_eq!(claims.extra.get("did").unwrap(), "device-ed");

        let expected_jkt = compute_cnf_jkt(&parse_public_jwk(&public_jwk).unwrap()).unwrap();
        assert_eq!(claims.extra.get("cnf").unwrap()["jkt"], expected_jkt);
    }

    #[tokio::test]
    async fn full_enrolment_ceremony_issues_attestation_bound_to_the_real_key() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-1".to_string(),
                principal_id: "device-1".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: key.public_jwk.clone(),
                attributes: serde_json::json!({"kyc_level": 2}),
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(&key, &start_res.challenge);

        let complete_res = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap();

        assert_eq!(complete_res.expires_in, 86_400);

        let claims = tokens
            .validate_token(&complete_res.attestation, None)
            .unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.extra.get("did").unwrap(), "device-1");
        assert_eq!(claims.extra.get("principal_type").unwrap(), "device");
        assert_eq!(claims.extra.get("att").unwrap()["kyc_level"], 2);

        let expected_jkt = compute_cnf_jkt(&parse_public_jwk(&key.public_jwk).unwrap()).unwrap();
        assert_eq!(claims.extra.get("cnf").unwrap()["jkt"], expected_jkt);

        let header = jsonwebtoken::decode_header(&complete_res.attestation).unwrap();
        assert_eq!(header.typ.as_deref(), Some("webank-attest+jws"));
    }

    /// The security-critical property (spec §5.6 requirement 3, conformance
    /// case 23): a caller that supplies its own `cnf.jkt` gets ignored, not
    /// honoured. This proves it end-to-end rather than just at the unit
    /// level of `compute_cnf_jkt`.
    #[tokio::test]
    async fn caller_supplied_cnf_jkt_is_ignored_not_honoured() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let attacker_supplied_jkt = "attacker-chosen-thumbprint-value";

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-2".to_string(),
                principal_id: "device-2".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: key.public_jwk.clone(),
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "000000".to_string(),
                },
                // The attacker tries to bind an arbitrary thumbprint —
                // e.g. the thumbprint of a victim's key — to their own
                // identity/device.
                requested_cnf_jkt: Some(attacker_supplied_jkt.to_string()),
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(&key, &start_res.challenge);

        let complete_res = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap();

        let claims = tokens
            .validate_token(&complete_res.attestation, None)
            .unwrap();
        let issued_jkt = claims.extra.get("cnf").unwrap()["jkt"].as_str().unwrap();

        let real_jkt = compute_cnf_jkt(&parse_public_jwk(&key.public_jwk).unwrap()).unwrap();

        assert_eq!(
            issued_jkt, real_jkt,
            "cnf.jkt must equal the real key's thumbprint"
        );
        assert_ne!(
            issued_jkt, attacker_supplied_jkt,
            "cnf.jkt must NEVER equal a caller-supplied value"
        );
    }

    #[tokio::test]
    async fn enrolment_fails_closed_when_second_factor_rejected() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let config = test_config();
        let key = generate_test_key();

        let err = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-3".to_string(),
                principal_id: "device-3".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: key.public_jwk,
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "wrong".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysFailSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::SecondFactorFailed));
    }

    /// Conformance case 22: a signature over the right challenge, but by a
    /// *different* key than the one submitted at start, must be rejected.
    #[tokio::test]
    async fn completion_rejects_signature_from_a_different_key() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let submitted_key = generate_test_key();
        let attacker_key = generate_test_key();

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-4".to_string(),
                principal_id: "device-4".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: submitted_key.public_jwk,
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        // Signed with a DIFFERENT key than the one submitted.
        let signature = sign_challenge(&attacker_key, &start_res.challenge);

        let err = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::ChallengeSignatureInvalid));
    }

    /// Conformance case 24: a challenge is single-use.
    #[tokio::test]
    async fn challenge_cannot_be_replayed() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-5".to_string(),
                principal_id: "device-5".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: key.public_jwk.clone(),
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(&key, &start_res.challenge);

        handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge.clone(),
                challenge_signature: signature.clone(),
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap();

        let err = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::InvalidChallenge));
    }

    /// Conformance case 21 (spirit of it, at the completion boundary): a
    /// signature over a client-chosen value that was never actually issued
    /// as a challenge does not satisfy proof-of-possession.
    #[tokio::test]
    async fn completion_rejects_a_challenge_that_was_never_issued() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let client_chosen_challenge = "attacker-chosen-nonce";
        let signature = sign_challenge(&key, client_chosen_challenge);

        let err = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: client_chosen_challenge.to_string(),
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::InvalidChallenge));
    }

    struct StaticStatus(Option<Value>);

    #[async_trait]
    impl AttestationStatusProvider for StaticStatus {
        async fn current_attributes(
            &self,
            _subject: &str,
            _principal_id: &str,
            _principal_type: PrincipalType,
        ) -> Result<Option<Value>, OpError> {
            Ok(self.0.clone())
        }
    }

    async fn enrol_full(
        challenges: &dyn EnrolmentChallengeStore,
        tokens: &TokenManager,
        config: &AttestationConfig,
        key: &TestKey,
        subject: &str,
        principal_id: &str,
    ) -> AttestationResponse {
        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: subject.to_string(),
                principal_id: principal_id.to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: key.public_jwk.clone(),
                attributes: serde_json::json!({"kyc_level": 1}),
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            challenges,
            config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(key, &start_res.challenge);

        handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            challenges,
            tokens,
            config,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn reissue_with_the_same_key_succeeds_and_refreshes_attributes() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let first = enrol_full(&challenges, &tokens, &config, &key, "user-6", "device-6").await;

        let status = StaticStatus(Some(serde_json::json!({"kyc_level": 3})));

        let reissue_start = handle_reissue_start(
            ReissueStartRequest {
                attestation: first.attestation,
                public_jwk: key.public_jwk.clone(),
                requested_cnf_jkt: None,
            },
            &tokens,
            Some(&status),
            &challenges,
            &config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(&key, &reissue_start.challenge);

        let reissued = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: reissue_start.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap();

        let claims = tokens.validate_token(&reissued.attestation, None).unwrap();
        assert_eq!(claims.sub, "user-6");
        assert_eq!(claims.extra.get("did").unwrap(), "device-6");
        assert_eq!(claims.extra.get("att").unwrap()["kyc_level"], 3);
    }

    /// The security-critical property mirrored into re-issuance: presenting
    /// a valid attestation together with a *different* key must fail,
    /// exactly like presenting someone else's attestation with an
    /// attacker's key fails ordinary request verification (spec §4 step 4
    /// / conformance case 4).
    #[tokio::test]
    async fn reissue_rejects_a_different_key_than_the_attestation_is_bound_to() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let enrolled_key = generate_test_key();
        let attacker_key = generate_test_key();

        let first = enrol_full(
            &challenges,
            &tokens,
            &config,
            &enrolled_key,
            "user-7",
            "device-7",
        )
        .await;

        let err = handle_reissue_start(
            ReissueStartRequest {
                attestation: first.attestation,
                public_jwk: attacker_key.public_jwk,
                requested_cnf_jkt: None,
            },
            &tokens,
            None,
            &challenges,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::KeyNotBound));
    }

    #[tokio::test]
    async fn reissue_is_refused_when_status_provider_reports_revoked() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let first = enrol_full(&challenges, &tokens, &config, &key, "user-8", "device-8").await;

        let status = StaticStatus(None);

        let err = handle_reissue_start(
            ReissueStartRequest {
                attestation: first.attestation,
                public_jwk: key.public_jwk,
                requested_cnf_jkt: None,
            },
            &tokens,
            Some(&status),
            &challenges,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::PrincipalRevoked));
    }

    #[tokio::test]
    async fn reissue_without_a_status_provider_copies_previous_attributes_forward() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let first = enrol_full(&challenges, &tokens, &config, &key, "user-9", "device-9").await;

        let reissue_start = handle_reissue_start(
            ReissueStartRequest {
                attestation: first.attestation,
                public_jwk: key.public_jwk.clone(),
                requested_cnf_jkt: None,
            },
            &tokens,
            None,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(&key, &reissue_start.challenge);

        let reissued = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: reissue_start.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap();

        let claims = tokens.validate_token(&reissued.attestation, None).unwrap();
        assert_eq!(claims.extra.get("att").unwrap()["kyc_level"], 1);
    }

    /// Conformance case 5/19 spirit, applied to challenge signing: `alg:
    /// none` (or a symmetric alg) must never be accepted, even though the
    /// key itself would otherwise be valid.
    #[tokio::test]
    async fn completion_rejects_alg_none_on_the_challenge_signature() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-10".to_string(),
                principal_id: "device-10".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: key.public_jwk.clone(),
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        // Hand-build `header.payload.signature` with alg "none" and an
        // empty signature segment, as an attacker would.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"challenge":"{}"}}"#, start_res.challenge));
        let forged = format!("{header}.{payload}.");

        let err = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: forged,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::BadAlg(_)));
    }

    #[tokio::test]
    async fn enrol_start_rejects_a_jwk_with_a_smuggled_private_component() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let config = test_config();
        let mut jwk = generate_test_key().public_jwk;
        jwk["d"] = Value::String("smuggled-private-scalar".to_string());

        let err = handle_enrol_start(
            EnrolStartRequest {
                subject: "user-11".to_string(),
                principal_id: "device-11".to_string(),
                principal_type: PrincipalType::Device,
                public_jwk: jwk,
                attributes: Value::Null,
                second_factor: SecondFactorProof {
                    kind: "sms_otp".to_string(),
                    value: "123456".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, OpError::BadJwk(_)));
    }

    #[tokio::test]
    async fn service_principal_enrolment_carries_principal_type_through() {
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let tokens = test_tokens();
        let config = test_config();
        let key = generate_test_key();

        let start_res = handle_enrol_start(
            EnrolStartRequest {
                subject: "bff-1".to_string(),
                principal_id: "svc-bff-1".to_string(),
                principal_type: PrincipalType::Service,
                public_jwk: key.public_jwk.clone(),
                attributes: serde_json::json!({"roles": ["ingress"]}),
                second_factor: SecondFactorProof {
                    kind: "bootstrap_secret".to_string(),
                    value: "one-time-secret".to_string(),
                },
                requested_cnf_jkt: None,
            },
            &AlwaysPassSecondFactor,
            &challenges,
            &config,
        )
        .await
        .unwrap();

        let signature = sign_challenge(&key, &start_res.challenge);

        let complete_res = handle_complete_challenge(
            CompleteChallengeRequest {
                challenge: start_res.challenge,
                challenge_signature: signature,
            },
            &challenges,
            &tokens,
            &config,
        )
        .await
        .unwrap();

        let claims = tokens
            .validate_token(&complete_res.attestation, None)
            .unwrap();
        assert_eq!(claims.extra.get("principal_type").unwrap(), "service");
        assert_eq!(claims.extra.get("did").unwrap(), "svc-bff-1");
    }

    struct AttributeGatedSecondFactor;

    #[async_trait]
    impl SecondFactorVerifier for AttributeGatedSecondFactor {
        async fn verify(
            &self,
            _subject: &str,
            _principal_type: PrincipalType,
            _proof: &SecondFactorProof,
            attributes: &Value,
        ) -> Result<(), OpError> {
            if attributes.get("role").and_then(|v| v.as_str()) == Some("admin") {
                return Err(OpError::SecondFactorFailed);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_second_factor_validates_attributes() {
        let config = test_config();
        let challenges = MemoryStore::<EnrolmentChallenge>::new();
        let key = generate_test_key();

        // Request with disallowed attribute "role": "admin"
        let bad_req = EnrolStartRequest {
            subject: "user-1".to_string(),
            principal_id: "device-1".to_string(),
            principal_type: PrincipalType::Device,
            public_jwk: key.public_jwk.clone(),
            second_factor: SecondFactorProof {
                kind: "otp".to_string(),
                value: "123456".to_string(),
            },
            attributes: serde_json::json!({ "role": "admin" }),
            requested_cnf_jkt: None,
        };

        let err = handle_enrol_start(bad_req, &AttributeGatedSecondFactor, &challenges, &config)
            .await
            .unwrap_err();
        assert!(matches!(err, OpError::SecondFactorFailed));

        // Request with allowed attributes
        let good_req = EnrolStartRequest {
            subject: "user-1".to_string(),
            principal_id: "device-1".to_string(),
            principal_type: PrincipalType::Device,
            public_jwk: key.public_jwk,
            second_factor: SecondFactorProof {
                kind: "otp".to_string(),
                value: "123456".to_string(),
            },
            attributes: serde_json::json!({ "role": "developer" }),
            requested_cnf_jkt: None,
        };

        let start_res =
            handle_enrol_start(good_req, &AttributeGatedSecondFactor, &challenges, &config)
                .await
                .unwrap();
        assert!(!start_res.challenge.is_empty());
    }
}
