use crate::config::OpConfig;
use crate::store::OpStore;
use authkestra_engine::token::TokenManager;
use serde::Serialize;

/// Request payload for the userinfo endpoint.
#[derive(Debug)]
#[non_exhaustive]
pub struct UserInfoRequest {
    /// The access token provided in the Authorization header.
    pub access_token: String,
    /// Whether the token arrived under the `DPoP` auth-scheme rather than
    /// `Bearer` (RFC 9449 §7.1).
    ///
    /// Tracked separately from `dpop_proof` because the two mismatches this
    /// endpoint must reject are different: a DPoP-bound token presented as
    /// `Bearer` (caught by this flag being `false`), and the `DPoP` scheme
    /// used for a token that is not bound at all (caught by it being
    /// `true`). A single `Option<proof>` cannot distinguish them.
    pub presented_as_dpop: bool,
    /// The request's `DPoP` header, if any.
    pub dpop_proof: Option<String>,
    /// The HTTP method of this userinfo request, for the proof's `htm`.
    pub htm: Option<String>,
    /// The absolute URL of this userinfo request, for the proof's `htu`.
    ///
    /// `None` skips the `htu` check — see
    /// `authkestra_resource::ValidationConfig::dpop_resource_origin` for why
    /// a resource server usually cannot reconstruct this behind a reverse
    /// proxy, and what forwarding it leaves open.
    pub htu: Option<String>,
}

/// Success response for the userinfo endpoint.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct UserInfoResponse {
    /// Subject identifier.
    pub sub: String,
    /// End-User's preferred e-mail address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// End-User's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Any other claims.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Error response for the userinfo endpoint.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct UserInfoErrorResponse {
    /// The error code.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: String,
}

/// Handles userinfo requests.
///
/// `/userinfo` is a protected resource, so an access token this OP issued
/// with a `cnf.jkt` confirmation claim must be proven here the same way
/// `authkestra-resource` proves one — otherwise a stolen DPoP-bound token
/// is refused at a hardened resource server and accepted at the issuing
/// OP's own endpoint, which is the weaker of the two paths an attacker
/// gets to choose from.
pub async fn handle_userinfo<S: OpStore + ?Sized>(
    req: UserInfoRequest,
    _config: &OpConfig,
    tokens: &TokenManager,
    op_store: &mut S,
) -> Result<UserInfoResponse, UserInfoErrorResponse> {
    tracing::debug!("Processing userinfo request");

    // 1. Verify token
    let claims = match tokens.validate_token(&req.access_token, None) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = ?e, "Invalid access token provided to userinfo endpoint");
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "The access token is invalid or expired".to_string(),
            });
        }
    };

    // 1b. RFC 9449 §7.1 key binding, before any claim of this token is
    // acted on.
    verify_dpop_binding(&req, claims.extra.get("cnf"), op_store).await?;

    // 2. Check scopes
    let scope_str = claims.scope.unwrap_or_default();
    let scopes: Vec<&str> = scope_str.split_whitespace().collect();

    if !scopes.contains(&"openid") {
        tracing::warn!("Token lacks openid scope for userinfo endpoint");
        return Err(UserInfoErrorResponse {
            error: "insufficient_scope".to_string(),
            error_description: "The access token requires the openid scope".to_string(),
        });
    }

    // 3. Build response based on identity
    let identity = match claims.identity {
        Some(id) => id,
        None => {
            tracing::warn!("Token lacks identity information");
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "The access token does not contain user identity".to_string(),
            });
        }
    };

    let mut response = UserInfoResponse {
        sub: identity.external_id,
        email: None,
        name: None,
        extra: std::collections::HashMap::new(),
    };

    if scopes.contains(&"email") {
        response.email = identity.email;
    }

    if scopes.contains(&"profile") {
        response.name = identity.username;
        // Optionally populate other profile claims from attributes
    }

    tracing::info!(sub = %response.sub, "Successfully returned userinfo");

    Ok(response)
}

/// Reads `cnf.jkt` — the single "is this token DPoP-bound" predicate, so the
/// scheme check and the proof check cannot drift on what "bound" means.
fn dpop_bound_jkt(cnf: Option<&serde_json::Value>) -> Option<&str> {
    cnf.and_then(|v| v.get("jkt")).and_then(|v| v.as_str())
}

/// Enforces RFC 9449 §7.1 for a userinfo request, in both directions.
///
/// - Token not bound, presented as `Bearer` — nothing to check.
/// - Token **bound**, presented as `Bearer` — refused. This is the case
///   that matters: without it a stolen DPoP-bound access token is fully
///   usable at this endpoint just by dropping the scheme down to `Bearer`,
///   which defeats the binding entirely.
/// - Token not bound, presented as `DPoP` — refused. The RFC expects a
///   server handling the `DPoP` scheme to validate a proof; silently
///   ignoring one would let a client believe it had sender-constrained a
///   request that in fact was not.
/// - Token bound, presented as `DPoP` — the proof must verify, bind to this
///   token via `ath`, carry the same key as `cnf.jkt`, and have a `jti` not
///   already spent.
async fn verify_dpop_binding<S: OpStore + ?Sized>(
    req: &UserInfoRequest,
    cnf: Option<&serde_json::Value>,
    op_store: &mut S,
) -> Result<(), UserInfoErrorResponse> {
    let bound_jkt = dpop_bound_jkt(cnf);

    let expected_jkt = match (bound_jkt, req.presented_as_dpop) {
        (None, false) => return Ok(()),
        (None, true) => {
            tracing::warn!(
                "userinfo request used the DPoP auth-scheme for a token with no cnf.jkt"
            );
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "This access token is not DPoP-bound; present it as Bearer"
                    .to_string(),
            });
        }
        (Some(_), false) => {
            tracing::warn!(
                "DPoP-bound access token presented to userinfo under the Bearer scheme; \
                 refusing rather than honouring a binding the request never proved"
            );
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description:
                    "This access token is DPoP-bound and must be presented with the DPoP scheme"
                        .to_string(),
            });
        }
        (Some(jkt), true) => jkt,
    };

    let Some(proof) = req.dpop_proof.as_deref() else {
        tracing::warn!("DPoP-bound access token presented to userinfo with no DPoP proof header");
        return Err(UserInfoErrorResponse {
            error: "invalid_token".to_string(),
            error_description: "A DPoP proof is required for this access token".to_string(),
        });
    };

    // `ath` is what stops a proof minted for one access token being replayed
    // with another: it is the SHA-256 of this exact token.
    let ath =
        authkestra_engine::token::cert_binding::x5t_s256_thumbprint(req.access_token.as_bytes());

    let verified = match authkestra_engine::token::dpop::verify_dpop_proof(
        proof,
        req.htm.as_deref().unwrap_or("GET"),
        req.htu.as_deref(),
        Some(&ath),
        chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS),
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e, "Invalid DPoP proof at userinfo");
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "The DPoP proof is invalid".to_string(),
            });
        }
    };

    if !crate::attestation::constant_time_eq(&verified.jkt, expected_jkt) {
        tracing::warn!("DPoP proof key does not match the access token's cnf.jkt at userinfo");
        return Err(UserInfoErrorResponse {
            error: "invalid_token".to_string(),
            error_description: "The DPoP proof key does not match this access token".to_string(),
        });
    }

    // Anchored to the proof's own `iat`, not `Utc::now()`: anchoring to now
    // lets the replay record expire before the proof's own freshness
    // boundary (`iat + max_age`) whenever the request is processed even
    // slightly after `iat`, leaving a narrow but real replay window. Same
    // reasoning, and the same `+ 1s` boundary guard, as the `/token` and
    // resource-server paths.
    let iat_dt =
        chrono::DateTime::<chrono::Utc>::from_timestamp(verified.iat, 0).ok_or_else(|| {
            UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "The DPoP proof is invalid".to_string(),
            }
        })?;
    let expires_at = iat_dt
        + chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS)
        + chrono::Duration::seconds(1);

    match op_store
        .check_and_record_dpop_jti(&verified.jti, expires_at)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!("Replayed DPoP proof at userinfo");
            Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "This DPoP proof has already been used".to_string(),
            })
        }
        // Fails closed, and distinguishably: a replay store that is down is
        // an availability problem, not a bad token, so it must not be
        // reported to the client as one.
        Err(e) => {
            tracing::error!(error = ?e, "DPoP replay store unavailable at userinfo");
            Err(UserInfoErrorResponse {
                error: "temporarily_unavailable".to_string(),
                error_description: "Unable to verify the DPoP proof at this time".to_string(),
            })
        }
    }
}

impl UserInfoRequest {
    /// Creates a new `UserInfoRequest` for a token presented as `Bearer`.
    ///
    /// A DPoP-bound token presented this way is **refused** by
    /// [`handle_userinfo`]; use [`UserInfoRequest::new_dpop`] for the
    /// `DPoP` auth-scheme.
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            presented_as_dpop: false,
            dpop_proof: None,
            htm: None,
            htu: None,
        }
    }

    /// Creates a new `UserInfoRequest` for a token presented under the
    /// `DPoP` auth-scheme (RFC 9449 §7.1), carrying the proof from the
    /// request's `DPoP` header and the request's own method/URL for the
    /// proof's `htm`/`htu` claims.
    pub fn new_dpop(
        access_token: String,
        dpop_proof: Option<String>,
        htm: Option<String>,
        htu: Option<String>,
    ) -> Self {
        Self {
            access_token,
            presented_as_dpop: true,
            dpop_proof,
            htm,
            htu,
        }
    }
}

impl UserInfoErrorResponse {
    /// Creates a new UserInfoErrorResponse.
    pub fn new(error: String, error_description: String) -> Self {
        Self {
            error,
            error_description,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use authkestra_engine::auth::state::Identity;

    fn test_config() -> OpConfig {
        OpConfig {
            issuer: "https://op.example.com".to_string(),
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        }
    }

    fn test_tokens() -> TokenManager {
        TokenManager::new(b"secret", Some("issuer".to_string()))
    }

    /// A store whose `check_and_record_dpop_jti` is the trait's
    /// fail-closed default — exactly right for the non-DPoP tests: they
    /// must never reach it, and if a refactor makes them, they fail loudly
    /// rather than silently skipping the binding check.
    fn test_store() -> crate::store::CompositeOpStore<
        authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
        authkestra_engine::store::memory::MemoryStore<crate::code::AuthorizationCode>,
        authkestra_engine::store::memory::MemoryStore<crate::refresh::RefreshToken>,
        authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
    > {
        crate::store::CompositeOpStore::new(
            authkestra_engine::store::memory::MemoryStore::new(),
            authkestra_engine::store::memory::MemoryStore::new(),
            authkestra_engine::store::memory::MemoryStore::new(),
            authkestra_engine::store::memory::MemoryStore::new(),
        )
    }

    fn test_identity() -> Identity {
        Identity {
            provider_id: "local".to_string(),
            external_id: "user-123".to_string(),
            email: Some("user@example.com".to_string()),
            username: Some("Test User".to_string()),
            attributes: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_missing_openid_scope() {
        let config = test_config();
        let tokens = test_tokens();

        // Issue token without openid scope
        let access_token = tokens
            .issue_user_token(test_identity(), 3600, Some("profile".to_string()), None)
            .unwrap();

        let req = UserInfoRequest::new(access_token);

        let result = handle_userinfo(req, &config, &tokens, &mut test_store()).await;
        assert_eq!(result.unwrap_err().error, "insufficient_scope");
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let config = test_config();
        let tokens = test_tokens();

        let req = UserInfoRequest::new("invalid.token.here".to_string());

        let result = handle_userinfo(req, &config, &tokens, &mut test_store()).await;
        assert_eq!(result.unwrap_err().error, "invalid_token");
    }

    #[tokio::test]
    async fn test_successful_userinfo() {
        let config = test_config();
        let tokens = test_tokens();

        // Issue token with openid, profile, email scopes
        let access_token = tokens
            .issue_user_token(
                test_identity(),
                3600,
                Some("openid profile email".to_string()),
                None,
            )
            .unwrap();

        let req = UserInfoRequest::new(access_token);

        let result = handle_userinfo(req, &config, &tokens, &mut test_store())
            .await
            .unwrap();
        assert_eq!(result.sub, "user-123");
        assert_eq!(result.email.as_deref(), Some("user@example.com"));
        assert_eq!(result.name.as_deref(), Some("Test User"));
    }

    #[tokio::test]
    async fn test_successful_userinfo_no_email_scope() {
        let config = test_config();
        let tokens = test_tokens();

        // Issue token with openid, profile scopes (NO email)
        let access_token = tokens
            .issue_user_token(
                test_identity(),
                3600,
                Some("openid profile".to_string()),
                None,
            )
            .unwrap();

        let req = UserInfoRequest::new(access_token);

        let result = handle_userinfo(req, &config, &tokens, &mut test_store())
            .await
            .unwrap();
        assert_eq!(result.sub, "user-123");
        assert_eq!(result.email, None); // Should be None because email scope wasn't requested
        assert_eq!(result.name.as_deref(), Some("Test User"));
    }

    // ---- RFC 9449 §7.1 key binding at /userinfo (authkestra#291) ----

    mod dpop_binding {
        use super::*;
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};

        fn b64(bytes: &[u8]) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        }
        fn b64_json(v: &serde_json::Value) -> String {
            b64(serde_json::to_vec(v).unwrap().as_slice())
        }

        /// A real Ed25519-signed DPoP proof for a *resource* request, so it
        /// carries `ath` — the claim that binds a proof to one specific
        /// access token, which the token-endpoint proofs in `token.rs` have
        /// no need for.
        struct ResourceProof {
            key: SigningKey,
            jti: String,
            ath: Option<String>,
            htm: String,
        }

        impl ResourceProof {
            fn new(jti: &str, access_token: &str) -> Self {
                Self::with_key_seed(7, jti, Some(access_token))
            }
            fn with_key_seed(seed: u8, jti: &str, access_token: Option<&str>) -> Self {
                Self {
                    key: SigningKey::from_bytes(&[seed; 32]),
                    jti: jti.to_string(),
                    ath: access_token.map(|t| {
                        authkestra_engine::token::cert_binding::x5t_s256_thumbprint(t.as_bytes())
                    }),
                    htm: "GET".to_string(),
                }
            }
            fn jwk(&self) -> serde_json::Value {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": b64(self.key.verifying_key().as_bytes()),
                })
            }
            fn jkt(&self) -> String {
                authkestra_engine::token::dpop::compute_jwk_thumbprint(
                    &serde_json::from_value(self.jwk()).unwrap(),
                )
                .unwrap()
            }
            fn build(&self) -> String {
                let header = serde_json::json!({
                    "typ": "dpop+jwt", "alg": "EdDSA", "jwk": self.jwk(),
                });
                let mut payload = serde_json::json!({
                    "htm": self.htm,
                    "htu": "https://op.example.com/userinfo",
                    "iat": chrono::Utc::now().timestamp(),
                    "jti": self.jti,
                });
                if let Some(ath) = &self.ath {
                    payload["ath"] = serde_json::Value::String(ath.clone());
                }
                let input = format!("{}.{}", b64_json(&header), b64_json(&payload));
                let sig = self.key.sign(input.as_bytes());
                format!("{input}.{}", b64(&sig.to_bytes()))
            }
        }

        /// Issues an access token carrying `cnf.jkt`, exactly as
        /// `/token` does for a DPoP request.
        fn bound_token(tokens: &TokenManager, jkt: &str) -> String {
            let mut extra = std::collections::HashMap::new();
            crate::handlers::token::merge_dpop_cnf(&mut extra, Some(jkt));
            tokens
                .issue_user_token_with_extra(
                    test_identity(),
                    3600,
                    Some("openid profile email".to_string()),
                    None,
                    extra,
                )
                .unwrap()
        }

        /// The `CompositeOpStore` shape with a real replay store wired.
        /// Aliased because the fully-spelled generic is what clippy's
        /// `type_complexity` lint objects to, and naming it also documents
        /// which slot the replay store occupies.
        type StoreWithReplay = crate::store::CompositeOpStore<
            authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
            authkestra_engine::store::memory::MemoryStore<crate::code::AuthorizationCode>,
            authkestra_engine::store::memory::MemoryStore<crate::refresh::RefreshToken>,
            authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
            authkestra_engine::store::traits::NoClientAssertionStore,
            authkestra_engine::store::memory::MemoryStore<crate::dpop::DpopJtiRecord>,
        >;

        fn store_with_replay() -> StoreWithReplay {
            test_store().with_dpop_replay_store(authkestra_engine::store::memory::MemoryStore::<
                crate::dpop::DpopJtiRecord,
            >::new())
        }

        /// **The finding.** A DPoP-bound access token must not be usable at
        /// `/userinfo` just by presenting it as `Bearer`. Before
        /// authkestra#291 this returned 200 with the user's claims, so a
        /// stolen bound token was refused at a hardened resource server and
        /// accepted at the issuing OP's own endpoint.
        #[tokio::test]
        async fn dpop_bound_token_presented_as_bearer_is_refused() {
            let tokens = test_tokens();
            let proof = ResourceProof::with_key_seed(7, "j1", None);
            let token = bound_token(&tokens, &proof.jkt());

            let err = handle_userinfo(
                UserInfoRequest::new(token),
                &test_config(),
                &tokens,
                &mut store_with_replay(),
            )
            .await
            .expect_err("a bound token must not be accepted as Bearer");
            assert_eq!(err.error, "invalid_token");
            assert!(
                err.error_description.contains("DPoP"),
                "the error must say why: {}",
                err.error_description
            );
        }

        /// The other direction of RFC 9449 §7.1: a server handling the
        /// `DPoP` scheme is expected to validate a proof, so accepting the
        /// scheme for an unbound token would let a client believe it had
        /// sender-constrained a request that in fact was not.
        #[tokio::test]
        async fn dpop_scheme_for_an_unbound_token_is_refused() {
            let tokens = test_tokens();
            let token = tokens
                .issue_user_token(test_identity(), 3600, Some("openid".to_string()), None)
                .unwrap();
            let proof = ResourceProof::new("j2", &token);

            let err = handle_userinfo(
                UserInfoRequest::new_dpop(
                    token,
                    Some(proof.build()),
                    Some("GET".to_string()),
                    None,
                ),
                &test_config(),
                &tokens,
                &mut store_with_replay(),
            )
            .await
            .expect_err("the DPoP scheme must not be accepted for an unbound token");
            assert_eq!(err.error, "invalid_token");
        }

        /// The positive path: bound token + a valid proof for the same key,
        /// bound to this token via `ath`.
        #[tokio::test]
        async fn dpop_bound_token_with_a_matching_proof_succeeds() {
            let tokens = test_tokens();
            let seed_proof = ResourceProof::with_key_seed(7, "j3", None);
            let token = bound_token(&tokens, &seed_proof.jkt());
            let proof = ResourceProof::new("j3", &token);

            let resp = handle_userinfo(
                UserInfoRequest::new_dpop(
                    token,
                    Some(proof.build()),
                    Some("GET".to_string()),
                    None,
                ),
                &test_config(),
                &tokens,
                &mut store_with_replay(),
            )
            .await
            .expect("a bound token with a matching proof must be accepted");
            assert_eq!(resp.sub, "user-123");
        }

        /// A proof for a *different* key than the token's `cnf.jkt` — the
        /// stolen-token-plus-attacker's-own-proof case.
        #[tokio::test]
        async fn a_proof_for_a_different_key_is_refused() {
            let tokens = test_tokens();
            let victim = ResourceProof::with_key_seed(7, "j4", None);
            let token = bound_token(&tokens, &victim.jkt());
            // Attacker holds the token string but signs with their own key.
            let attacker = ResourceProof::with_key_seed(11, "j4", Some(&token));

            let err = handle_userinfo(
                UserInfoRequest::new_dpop(
                    token,
                    Some(attacker.build()),
                    Some("GET".to_string()),
                    None,
                ),
                &test_config(),
                &tokens,
                &mut store_with_replay(),
            )
            .await
            .expect_err("a proof for another key must be refused");
            assert_eq!(err.error, "invalid_token");
        }

        /// `ath` is what stops a proof minted for one access token being
        /// presented with another. Here the proof is validly signed by the
        /// right key but its `ath` names a different token.
        #[tokio::test]
        async fn a_proof_whose_ath_names_another_token_is_refused() {
            let tokens = test_tokens();
            let seed = ResourceProof::with_key_seed(7, "j5", None);
            let token = bound_token(&tokens, &seed.jkt());
            let other_token = bound_token(&tokens, &seed.jkt());
            let proof = ResourceProof::with_key_seed(7, "j5", Some(&other_token));

            let err = handle_userinfo(
                UserInfoRequest::new_dpop(
                    token,
                    Some(proof.build()),
                    Some("GET".to_string()),
                    None,
                ),
                &test_config(),
                &tokens,
                &mut store_with_replay(),
            )
            .await
            .expect_err("a proof bound to a different access token must be refused");
            assert_eq!(err.error, "invalid_token");
        }

        /// RFC 9449 §11.1: the same proof must not work twice.
        #[tokio::test]
        async fn a_replayed_proof_is_refused() {
            let tokens = test_tokens();
            let seed = ResourceProof::with_key_seed(7, "j6", None);
            let token = bound_token(&tokens, &seed.jkt());
            let proof = ResourceProof::new("j6", &token).build();
            let mut store = store_with_replay();

            let first = handle_userinfo(
                UserInfoRequest::new_dpop(
                    token.clone(),
                    Some(proof.clone()),
                    Some("GET".to_string()),
                    None,
                ),
                &test_config(),
                &tokens,
                &mut store,
            )
            .await;
            assert!(first.is_ok(), "first presentation must succeed");

            let err = handle_userinfo(
                UserInfoRequest::new_dpop(token, Some(proof), Some("GET".to_string()), None),
                &test_config(),
                &tokens,
                &mut store,
            )
            .await
            .expect_err("replaying the same proof must be refused");
            assert_eq!(err.error, "invalid_token");
        }

        /// A replay store that is down is an availability problem, not a bad
        /// token, and must not be reported to the client as one. The
        /// fail-closed `NoDpopReplayStore` default stands in for an outage.
        #[tokio::test]
        async fn an_unavailable_replay_store_is_not_reported_as_an_invalid_token() {
            let tokens = test_tokens();
            let seed = ResourceProof::with_key_seed(7, "j7", None);
            let token = bound_token(&tokens, &seed.jkt());
            let proof = ResourceProof::new("j7", &token).build();

            let err = handle_userinfo(
                UserInfoRequest::new_dpop(token, Some(proof), Some("GET".to_string()), None),
                &test_config(),
                &tokens,
                &mut test_store(),
            )
            .await
            .expect_err("must fail closed");
            assert_eq!(
                err.error, "temporarily_unavailable",
                "an outage must be distinguishable from a bad proof"
            );
        }
    }
}
