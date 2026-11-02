use crate::client::{ClientRegistration, GrantType, TokenEndpointAuthMethod};
use crate::client_assertion::{
    peek_client_assertion_subject, verify_client_assertion, CLIENT_ASSERTION_TYPE_JWT_BEARER,
};
use crate::config::OpConfig;
use crate::error::OpError;
use crate::refresh::RefreshToken;
use crate::store::OpStore;
use authkestra_engine::token::cert_binding::x5t_s256_thumbprint;
use authkestra_engine::token::{Audience, Claims, TokenManager};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;

fn user_token_audience(client_id: &str, allowed_audiences: &[String]) -> Audience {
    match allowed_audiences {
        [] => {
            tracing::debug!(
                "No resource audiences configured; defaulting access token audience to client_id"
            );
            Audience::Single(client_id.to_string())
        }
        [audience] => {
            tracing::debug!("Selected the configured access token audience");
            Audience::Single(audience.clone())
        }
        audiences => {
            tracing::debug!(
                audience_count = audiences.len(),
                "Selected configured access token audiences"
            );
            Audience::Multiple(audiences.to_vec())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubjectTokenClientBinding {
    Audience,
    SignedClientId,
}

fn subject_token_client_binding(
    token: &str,
    claims: &Claims,
    subject_token_type: &str,
    client_id: &str,
) -> Option<SubjectTokenClientBinding> {
    if claims
        .aud
        .as_ref()
        .is_some_and(|aud| aud.contains(client_id))
    {
        return Some(SubjectTokenClientBinding::Audience);
    }

    (subject_token_type == "urn:ietf:params:oauth:token-type:access_token"
        && jsonwebtoken::decode_header(token)
            .ok()
            .is_some_and(|header| header.typ.as_deref() == Some("at+jwt"))
        && claims
            .extra
            .get("client_id")
            .and_then(serde_json::Value::as_str)
            == Some(client_id))
    .then_some(SubjectTokenClientBinding::SignedClientId)
}

fn subject_token_dpop_binding_matches(claims: &Claims, dpop_jkt: Option<&str>) -> bool {
    claims
        .extra
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(serde_json::Value::as_str)
        .is_none_or(|expected_jkt| dpop_jkt == Some(expected_jkt))
}

#[cfg(test)]
mod user_token_audience_tests {
    use super::{
        subject_token_client_binding, subject_token_dpop_binding_matches, user_token_audience,
        SubjectTokenClientBinding, TokenManager,
    };
    use authkestra_engine::token::Audience;

    #[test]
    fn uses_configured_audiences_and_preserves_the_empty_default() {
        assert_eq!(
            user_token_audience("app", &[]),
            Audience::Single("app".to_string())
        );
        assert_eq!(
            user_token_audience("app", &["api".to_string()]),
            Audience::Single("api".to_string())
        );
        assert_eq!(
            user_token_audience("app", &["api".to_string(), "ledger".to_string()]),
            Audience::Multiple(vec!["api".to_string(), "ledger".to_string()])
        );
    }

    #[test]
    fn token_exchange_binding_accepts_only_the_matching_access_token_client() {
        use authkestra_engine::auth::state::Identity;
        use authkestra_engine::token::Audience;
        use std::collections::HashMap;

        let tokens = TokenManager::new(b"token-exchange-test-secret", Some("issuer".into()));
        let access_token = tokens
            .issue_access_token(
                Identity {
                    provider_id: "test".into(),
                    external_id: "user-1".into(),
                    email: None,
                    username: None,
                    attributes: HashMap::new(),
                },
                "client-a",
                Audience::Single("resource-api".into()),
                3600,
                None,
                HashMap::new(),
            )
            .expect("issue access token");
        let claims = tokens
            .validate_token(&access_token, None)
            .expect("validate access token");
        let access_token_type = "urn:ietf:params:oauth:token-type:access_token";

        assert_eq!(
            subject_token_client_binding(&access_token, &claims, access_token_type, "client-a"),
            Some(SubjectTokenClientBinding::SignedClientId)
        );
        assert_eq!(
            subject_token_client_binding(&access_token, &claims, access_token_type, "client-b"),
            None
        );
        assert_eq!(
            subject_token_client_binding(
                &access_token,
                &claims,
                "urn:ietf:params:oauth:token-type:id_token",
                "client-a"
            ),
            None
        );
    }

    #[test]
    fn token_exchange_requires_the_subject_tokens_dpop_key() {
        use authkestra_engine::auth::state::Identity;
        use std::collections::HashMap;

        let tokens = TokenManager::new(b"dpop-binding-test-secret", Some("issuer".into()));
        let bound = tokens
            .issue_access_token(
                Identity {
                    provider_id: "test".into(),
                    external_id: "user-1".into(),
                    email: None,
                    username: None,
                    attributes: HashMap::new(),
                },
                "client-a",
                Audience::Single("resource-api".into()),
                3600,
                None,
                HashMap::from([("cnf".to_string(), serde_json::json!({"jkt": "key-a"}))]),
            )
            .unwrap();
        let bound_claims = tokens.validate_token(&bound, None).unwrap();
        assert!(!subject_token_dpop_binding_matches(&bound_claims, None));
        assert!(!subject_token_dpop_binding_matches(
            &bound_claims,
            Some("key-b")
        ));
        assert!(subject_token_dpop_binding_matches(
            &bound_claims,
            Some("key-a")
        ));

        let unbound = tokens
            .issue_access_token(
                Identity {
                    provider_id: "test".into(),
                    external_id: "user-1".into(),
                    email: None,
                    username: None,
                    attributes: HashMap::new(),
                },
                "client-a",
                Audience::Single("resource-api".into()),
                3600,
                None,
                HashMap::new(),
            )
            .unwrap();
        let unbound_claims = tokens.validate_token(&unbound, None).unwrap();
        assert!(subject_token_dpop_binding_matches(&unbound_claims, None));
    }
}

/// Request payload for the token endpoint.
#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TokenRequest {
    /// OAuth2 grant type.
    pub grant_type: String,
    /// The authorization code received from the authorization endpoint.
    pub code: Option<String>,
    /// The device code received from the device authorization endpoint.
    pub device_code: Option<String>,
    /// The redirect URI used in the authorization request.
    pub redirect_uri: Option<String>,
    /// The client identifier (can also be provided via Basic Auth).
    pub client_id: Option<String>,
    /// The client secret (can also be provided via Basic Auth).
    pub client_secret: Option<String>,
    /// The PKCE code verifier used if a challenge was provided.
    pub code_verifier: Option<String>,
    /// The requested scope.
    pub scope: Option<String>,
    /// The refresh token (for refresh_token grant type).
    pub refresh_token: Option<String>,

    // Token Exchange fields (RFC 8693)
    /// The subject token being exchanged.
    pub subject_token: Option<String>,
    /// An identifier that indicates the type of the security token in the `subject_token` parameter.
    pub subject_token_type: Option<String>,
    /// The actor token being used for delegation.
    pub actor_token: Option<String>,
    /// An identifier that indicates the type of the security token in the `actor_token` parameter.
    pub actor_token_type: Option<String>,
    /// An identifier for the type of the requested security token.
    pub requested_token_type: Option<String>,
    /// The logical name of the target service where the client intends to use the requested security token.
    pub audience: Option<String>,

    // Asymmetric client authentication (RFC 7523 §2.2)
    /// The JWT the client signed with its own private key to authenticate
    /// itself. See [`crate::client_assertion`].
    pub client_assertion: Option<String>,
    /// Must be
    /// [`crate::client_assertion::CLIENT_ASSERTION_TYPE_JWT_BEARER`] when
    /// `client_assertion` is present.
    pub client_assertion_type: Option<String>,

    // DPoP (RFC 9449)
    /// The RFC 7638 thumbprint of a verified DPoP proof's embedded key,
    /// once `handle_token_with_client_cert` has verified the request's
    /// `DPoP` header and checked its `jti` for replay — `None` otherwise.
    ///
    /// `#[serde(skip)]` is load-bearing, not incidental: this is never a
    /// form field a client submits. Without it, a client could set
    /// `dpop_jkt=<anything>` directly and bind a token to a key it never
    /// proved possession of, bypassing DPoP verification entirely.
    /// `pub(crate)` for the same reason — populated exactly once, by
    /// `handle_token_with_client_cert` before grant dispatch, and read only
    /// by the grant handlers in this crate.
    #[serde(skip)]
    pub(crate) dpop_jkt: Option<String>,
}

impl TokenRequest {
    /// Creates a new token request with only `grant_type` set; every other
    /// field starts `None` and, since all fields here are `pub`, can be set
    /// directly on the returned value.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from outside
    /// this crate, so downstream code that builds a `TokenRequest`
    /// programmatically (e.g. in tests) had no way to construct one at all
    /// (authkestra#268).
    pub fn new(grant_type: String) -> Self {
        Self {
            grant_type,
            code: None,
            device_code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        }
    }

    /// The RFC 7638 thumbprint of the verified DPoP proof's embedded key
    /// this request was presented with, or `None` if it wasn't
    /// DPoP-bound. `None` both before `handle_token_with_client_cert` has
    /// verified a proof and for a request with no `DPoP` header at all.
    ///
    /// Read-only: the field itself stays `pub(crate)` so a client can
    /// never set it directly (see its doc comment for why that's
    /// forgery-proof), but an `OpStore::handle_*_grant` override outside
    /// this crate that delegates to a `default_handle_*` free function and
    /// post-processes the result still needs to be able to tell whether
    /// the request it just handled was DPoP-bound — e.g. to stamp its own
    /// additional claims alongside `cnf.jkt` via [`merge_dpop_cnf`].
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }
}

/// Success response for the token endpoint.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: String,
    /// The type of the token, typically "Bearer".
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// The ID token, if `openid` scope was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The refresh token, if `offline_access` was requested or using refresh grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The scope of the granted tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The type of token issued in `access_token`, as an RFC 8693 §3 URN
    /// (e.g. `urn:ietf:params:oauth:token-type:access_token`).
    ///
    /// REQUIRED by RFC 8693 §2.2.1 on a `token-exchange` grant response, so
    /// the client can tell what it actually got back. `None` — and omitted
    /// from the wire response — for every other grant, whose response shape
    /// is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
}

/// Error response for the token endpoint.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct TokenErrorResponse {
    /// The OAuth2 error code.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: String,
}

/// Processes a token exchange request (`/token` endpoint).
///
/// This handles different OAuth2 grant types such as `authorization_code`,
/// `client_credentials`, and `refresh_token`, issuing appropriate access tokens,
/// ID tokens, and refresh tokens based on the request and client configuration.
///
/// This is a thin wrapper around
/// [`handle_token_with_client_cert`] that always passes `None` for the
/// caller's mTLS client certificate — kept so every existing call site
/// (this crate's own extensive `handle_token` test suite among them, plus
/// any downstream integrator) keeps compiling unchanged. Callers that want
/// RFC 8705 certificate-bound `client_credentials` tokens (issue #224) call
/// [`handle_token_with_client_cert`] directly instead.
#[allow(clippy::too_many_arguments)]
pub async fn handle_token(
    req: TokenRequest,
    auth_header: Option<&str>,
    config: &OpConfig,
    op_store: &mut dyn OpStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    handle_token_with_client_cert(req, auth_header, config, op_store, tokens, None, None).await
}

/// Same as [`handle_token`], but additionally takes the DER bytes of the
/// mTLS client certificate presented on the current connection, if any.
///
/// This crate does not terminate TLS itself; `client_cert_der` is whatever
/// the caller's HTTP framework adapter surfaced for this request — see
/// `authkestra_engine::token::cert_binding::ClientCertificateDer`'s doc
/// comment for how `authkestra-axum`/`authkestra-actix` source it, and note
/// neither does so automatically without a host-supplied mTLS-terminating
/// layer.
///
/// `client_cert_der` only affects the `client_credentials` grant (see
/// [`handle_client_credentials`]), which stamps an RFC 8705 §3
/// `cnf.x5t#S256` confirmation claim onto the issued access token when a
/// certificate is present. It is ignored by every other grant type.
///
/// `dpop_header` is the raw value of the request's `DPoP` header, if any
/// (RFC 9449) — unlike `client_cert_der`, this affects *every* grant type:
/// a verified proof is recorded here (once, before dispatch) as
/// `req.dpop_jkt`, which every grant handler reads to stamp `cnf.jkt` onto
/// the token it issues and report `token_type: "DPoP"` instead of
/// `"Bearer"`. See `crate::dpop` for the replay-tracking half of this.
#[allow(clippy::too_many_arguments)]
pub async fn handle_token_with_client_cert(
    mut req: TokenRequest,
    auth_header: Option<&str>,
    config: &OpConfig,
    op_store: &mut dyn OpStore,
    tokens: &TokenManager,
    client_cert_der: Option<&[u8]>,
    dpop_header: Option<&str>,
) -> Result<TokenResponse, TokenErrorResponse> {
    tracing::debug!(grant_type = %req.grant_type, "Processing token request");

    // 0. Work out which credential — if any — the request presents.
    let credential = extract_credential(
        req.client_secret.as_deref(),
        req.client_assertion.as_deref(),
        req.client_assertion_type.as_deref(),
        auth_header,
    )?;

    let client_id = match resolve_client_id(req.client_id.as_deref(), &credential) {
        Some(id) => id,
        None => {
            tracing::debug!("Missing client_id in token request");
            return Err(TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
    };

    // 1. Client validation
    let client = match op_store.find_client(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            // Not "during token exchange": this is the token endpoint's own
            // client lookup and fires for every grant type. The message was
            // mislabelling every unknown-client rejection here, which nothing
            // noticed because the branch had no test.
            tracing::error!(client_id = %client_id, "Unknown client ID at the token endpoint");
            return Err(TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error finding client");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    // 2. Client authentication, against the one method this client is bound
    //    to. A credential of a different kind is a failure and never a
    //    fallback — see `authenticate_client`.
    if let Err(e) = authenticate_client(&client, &credential, config, op_store).await {
        tracing::warn!(client_id = %client_id, error = %e, "Client authentication failed");
        return Err(TokenErrorResponse {
            error: "invalid_client".to_string(),
            error_description: "Client authentication failed".to_string(),
        });
    }

    // 3. DPoP (RFC 9449) — verified once, here, before any grant runs, so
    //    every grant handler downstream just reads `req.dpop_jkt` rather
    //    than each needing its own copy of proof verification and replay
    //    checking. `expected_ath: None` since no access token exists yet
    //    for the proof to bind to — that check is `authkestra-resource`'s
    //    job, on the *next* request the client makes with the token this
    //    one issues.
    if let Some(proof) = dpop_header {
        let verified = match authkestra_engine::token::dpop::verify_dpop_proof(
            proof,
            "POST",
            Some(&config.token_endpoint()),
            None,
            chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(client_id = %client_id, error = %e, "DPoP proof verification failed");
                return Err(TokenErrorResponse {
                    error: "invalid_dpop_proof".to_string(),
                    error_description: "The presented DPoP proof is invalid".to_string(),
                });
            }
        };

        // Anchored to the proof's own `iat`, not the current time: a proof
        // remains fresh (and so, re-presentable) up to `iat + max_age`
        // regardless of how long after `iat` it happens to first arrive
        // here. Anchoring to `Utc::now()` instead would let the replay
        // record expire before that fixed freshness boundary whenever this
        // request is processed even slightly after `iat` (network delay,
        // queuing, or a fresh `iat` up to `CLOCK_SKEW_ALLOWANCE_SECS` in
        // this server's future) — a real, if narrow, window in which the
        // same jti could be replayed after its record expired but before
        // `verify_dpop_proof` would independently reject it as stale. The
        // extra second guards the exact boundary instant itself.
        let expires_at = chrono::DateTime::<Utc>::from_timestamp(verified.iat, 0)
            .unwrap_or_else(Utc::now)
            + chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS)
            + chrono::Duration::seconds(1);
        match op_store
            .check_and_record_dpop_jti(&verified.jti, expires_at)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    client_id = %client_id,
                    "DPoP proof jti has already been spent — replay refused"
                );
                return Err(TokenErrorResponse {
                    error: "invalid_dpop_proof".to_string(),
                    error_description: "The presented DPoP proof has already been used".to_string(),
                });
            }
            Err(e) => {
                tracing::error!(client_id = %client_id, error = ?e, "DPoP replay check failed");
                return Err(TokenErrorResponse {
                    error: "invalid_dpop_proof".to_string(),
                    error_description: "The presented DPoP proof could not be verified".to_string(),
                });
            }
        }

        req.dpop_jkt = Some(verified.jkt);
    }

    match req.grant_type.as_str() {
        "authorization_code" => {
            // Routed through the `OpStore` seam (mirrors `handle_refresh_token`
            // and `handle_token_exchange`) so an integrator can stamp custom
            // claims onto, or create session state for, tokens issued by the
            // authorization-code flow, without forking this crate. The
            // default implementation reproduces the built-in behavior below
            // via `default_handle_authorization_code`.
            op_store
                .handle_authorization_code_grant(req, client_id, client, config, tokens)
                .await
        }
        "client_credentials" => {
            handle_client_credentials(req, client_id, client, config, tokens, client_cert_der).await
        }
        "refresh_token" => {
            // Routed through the `OpStore` seam (mirrors `handle_custom_grant`)
            // so an integrator can substitute its own refresh handling —
            // e.g. to re-mint an `id_token` or apply a custom rotation
            // policy — without forking this crate. The default
            // implementation reproduces the built-in behavior below via
            // `default_handle_refresh_token`.
            op_store
                .handle_refresh_token(req, client_id, client, config, tokens)
                .await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code(req, client_id, client, config, op_store, tokens).await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            // Routed through the `OpStore` seam (mirrors `handle_refresh_token`)
            // so an integrator can stamp custom claims onto the exchanged
            // token, or issue an id_token differently, without forking this
            // crate. The default implementation reproduces the built-in
            // behavior below via `default_handle_token_exchange`.
            op_store
                .handle_token_exchange(req, client_id, client, config, tokens)
                .await
        }
        _ => {
            if !client.allows_grant_type(&crate::client::GrantType::Custom(req.grant_type.clone()))
            {
                tracing::error!(client_id = %client_id, grant_type = %req.grant_type, "Client not authorized for custom grant");
                return Err(TokenErrorResponse {
                    error: "unauthorized_client".to_string(),
                    error_description: "Client is not authorized to use this grant type"
                        .to_string(),
                });
            }

            // Forward any other grant type to the custom grant handler
            op_store
                .handle_custom_grant(
                    &req.grant_type,
                    req.clone(),
                    client_id,
                    client,
                    config,
                    tokens,
                )
                .await
        }
    }
}

/// The one credential a token request presents, and where it came from.
///
/// One value rather than a handful of `Option`s, so that "presented two
/// credentials" is a case the code has to answer explicitly instead of an
/// undocumented precedence order — and so the transport (`Basic` header vs
/// request body) survives long enough to be checked against what the client
/// registered.
#[derive(Debug)]
pub(crate) enum PresentedCredential {
    /// A shared secret in the `Authorization: Basic` header. Carries the
    /// `client_id` too, since that header is where it came from.
    SecretBasic { client_id: String, secret: String },
    /// A shared secret in the `client_secret` form field.
    SecretPost { secret: String },
    /// A JWT assertion signed by the client's own private key (RFC 7523).
    Assertion(String),
    /// No credential at all: a public client, or an unauthenticated request.
    NoCredential,
}

/// Extracts the credential the request presents, refusing more than one.
///
/// RFC 6749 §2.3 forbids a client from using more than one authentication
/// method in a single request, and RFC 7521 §4.2 repeats it for assertions.
/// Accepting several and picking a winner by precedence is exactly how a
/// downgrade slips in — an attacker holding a leaked secret appends it to a
/// request and the weaker credential wins — so this is a hard error.
///
/// Note that `client_id` is not a credential: sending it in the body
/// alongside a `Basic` header, or alongside an assertion, is fine.
pub(crate) fn extract_credential(
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
    auth_header: Option<&str>,
) -> Result<PresentedCredential, TokenErrorResponse> {
    let basic = auth_header
        .and_then(|auth| auth.strip_prefix("Basic "))
        .and_then(|stripped| {
            base64::engine::general_purpose::STANDARD
                .decode(stripped)
                .ok()
        })
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|creds| {
            creds
                .split_once(':')
                .map(|(id, secret)| (id.to_string(), secret.to_string()))
        });

    // An empty `client_secret=` form field is not a presented credential; some
    // HTTP clients emit one for an absent value.
    let post = client_secret
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let assertion = match client_assertion {
        Some(assertion) => match client_assertion_type {
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) => Some(assertion.to_string()),
            _ => {
                tracing::debug!(
                    "client_assertion presented with a missing or unsupported \
                     client_assertion_type"
                );
                return Err(TokenErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: format!(
                        "client_assertion_type must be {CLIENT_ASSERTION_TYPE_JWT_BEARER}"
                    ),
                });
            }
        },
        None => None,
    };

    let presented =
        u8::from(basic.is_some()) + u8::from(post.is_some()) + u8::from(assertion.is_some());
    if presented > 1 {
        tracing::debug!(
            presented,
            "token request presents more than one client authentication method"
        );
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Only one client authentication method may be used per request"
                .to_string(),
        });
    }

    Ok(match (basic, post, assertion) {
        (Some((client_id, secret)), _, _) => PresentedCredential::SecretBasic { client_id, secret },
        (_, Some(secret), _) => PresentedCredential::SecretPost { secret },
        (_, _, Some(assertion)) => PresentedCredential::Assertion(assertion),
        (None, None, None) => PresentedCredential::NoCredential,
    })
}

/// Works out which client the request claims to be.
///
/// With an assertion and no `client_id` parameter — which RFC 7521 §4.2 makes
/// optional — the `sub` is read out of the *unverified* assertion. That is
/// safe because it only chooses which registration to verify against: the
/// assertion must then be signed by that client's registered key, and its
/// `iss`/`sub` re-checked against that client's `client_id`. Naming someone
/// else's `client_id` here just picks the key the forgery will fail against.
pub(crate) fn resolve_client_id(
    req_client_id: Option<&str>,
    credential: &PresentedCredential,
) -> Option<String> {
    match credential {
        PresentedCredential::SecretBasic { client_id, .. } => Some(client_id.clone()),
        PresentedCredential::Assertion(assertion) => req_client_id
            .map(|s| s.to_string())
            .or_else(|| peek_client_assertion_subject(assertion)),
        _ => req_client_id.map(|s| s.to_string()),
    }
}

/// Authenticates the client against the single method its registration names.
///
/// The shape of this match is the security property: a registration binds one
/// method, and a credential of any other kind is rejected outright rather than
/// verified on its own merits. Without that, a `private_key_jwt` client whose
/// (unused, perhaps long-forgotten) secret leaked could be impersonated with
/// that secret, and a `client_secret_*` client with a stale registered key
/// could be impersonated with an assertion — a downgrade in both directions.
///
/// `token_endpoint_auth_method: None` is the pre-existing behaviour for
/// registrations that predate the field, preserved exactly: a stored secret
/// hash means a secret is required (from either transport, since those
/// registrations never said which), and no stored hash means no client
/// authentication. Such a registration is never accepted via
/// `private_key_jwt` — asymmetric authentication has to be opted into.
pub(crate) async fn authenticate_client(
    client: &ClientRegistration,
    credential: &PresentedCredential,
    config: &OpConfig,
    op_store: &mut dyn OpStore,
) -> Result<(), OpError> {
    use PresentedCredential as Cred;
    use TokenEndpointAuthMethod as Method;

    match (client.token_endpoint_auth_method, credential) {
        (Some(Method::PrivateKeyJwt), Cred::Assertion(assertion)) => {
            // RFC 7523 §3 accepts the token endpoint URL as `aud`; OIDC Core
            // §9 also allows the issuer identifier, and real clients emit
            // both.
            let verified = verify_client_assertion(
                assertion,
                client,
                &[config.token_endpoint(), config.issuer.clone()],
            )?;

            // Spending the `jti` is what turns a captured assertion from a
            // bearer credential valid for its whole lifetime into a
            // single-use one.
            if !op_store
                .record_client_assertion_jti(&verified.jti, verified.expires_at)
                .await?
            {
                tracing::warn!(
                    client_id = %client.client_id,
                    "client assertion jti has already been spent — replay refused"
                );
                return Err(OpError::ClientAssertionReplayed);
            }

            tracing::info!(
                client_id = %client.client_id,
                "client authenticated via private_key_jwt"
            );
            Ok(())
        }
        (Some(Method::ClientSecretBasic), Cred::SecretBasic { secret, .. })
        | (Some(Method::ClientSecretPost), Cred::SecretPost { secret }) => {
            if client.verify_secret(secret) {
                Ok(())
            } else {
                Err(OpError::InvalidClientCredentials)
            }
        }
        (Some(Method::NoAuth), Cred::NoCredential) => Ok(()),

        // Registered for one method, presenting another — including the right
        // secret over the wrong transport, which OIDC Core §9 treats as two
        // distinct methods.
        (Some(_), _) => Err(OpError::AuthMethodNotPermitted),

        // --- Registrations predating `token_endpoint_auth_method` ---
        (None, Cred::Assertion(_)) => Err(OpError::AuthMethodNotPermitted),
        (None, Cred::SecretBasic { secret, .. }) | (None, Cred::SecretPost { secret }) => {
            if client.client_secret_hash.is_none() {
                // Public client: a secret it never registered is ignored, as
                // it always has been.
                Ok(())
            } else if client.verify_secret(secret) {
                Ok(())
            } else {
                Err(OpError::InvalidClientCredentials)
            }
        }
        (None, Cred::NoCredential) => {
            if client.client_secret_hash.is_some() {
                Err(OpError::InvalidClientCredentials)
            } else {
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_device_code(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    op_store: &mut dyn OpStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::device::DeviceCodeStatus;

    if !client.allows_grant_type(&GrantType::DeviceCode) {
        tracing::error!(client_id = %client_id, "Client not authorized for device_code grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use device_code grant type".to_string(),
        });
    }

    let device_code_str = match req.device_code.as_deref() {
        Some(c) => c,
        None => {
            tracing::debug!("Missing device_code in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "device_code is required".to_string(),
            });
        }
    };

    let session = match op_store.get_device_code(device_code_str).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid device code".to_string(),
            });
        }
        Err(_) => {
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    if session.client_id != client_id {
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Device code issued to a different client".to_string(),
        });
    }

    if session.is_expired(Utc::now()) {
        return Err(TokenErrorResponse {
            error: "expired_token".to_string(),
            error_description: "Device code expired".to_string(),
        });
    }

    match session.status {
        DeviceCodeStatus::Pending => {
            let now = Utc::now();
            let mut updated = session.clone();
            updated.last_polled_at = Some(now);
            let _ = op_store.store_device_code(updated).await;

            if let Some(last_poll) = session.last_polled_at {
                if now < last_poll + chrono::Duration::seconds(5) {
                    return Err(TokenErrorResponse {
                        error: "slow_down".to_string(),
                        error_description: "Polling too frequently".to_string(),
                    });
                }
            }

            Err(TokenErrorResponse {
                error: "authorization_pending".to_string(),
                error_description: "User has not yet approved the request".to_string(),
            })
        }
        DeviceCodeStatus::Denied | DeviceCodeStatus::Approved(_) => {
            // Atomically consume to prevent race conditions
            let consumed = match op_store.consume_device_code(device_code_str).await {
                Ok(Some(s)) => s,
                _ => {
                    return Err(TokenErrorResponse {
                        error: "invalid_grant".to_string(),
                        error_description: "Device code is invalid or already consumed".to_string(),
                    });
                }
            };

            if let DeviceCodeStatus::Approved(identity) = consumed.status {
                let expires_in = config.access_token_ttl_secs;
                let scope_opt = if session.scope.is_empty() {
                    None
                } else {
                    Some(session.scope.clone())
                };

                let mut extra = HashMap::new();
                merge_dpop_cnf(&mut extra, req.dpop_jkt.as_deref());

                let access_token = match tokens.issue_access_token(
                    identity.clone(),
                    &client_id,
                    user_token_audience(&client_id, &client.allowed_audiences),
                    expires_in,
                    scope_opt.clone(),
                    extra,
                ) {
                    Ok(t) => t,
                    Err(_) => {
                        return Err(TokenErrorResponse {
                            error: "server_error".to_string(),
                            error_description: "Failed to issue access token".to_string(),
                        });
                    }
                };

                let id_token = if session.scope.contains("openid") {
                    let id_extra = crate::amr_acr::amr_acr_extra_claims(&identity);
                    match tokens.issue_id_token_with_extra(
                        identity.clone(),
                        &client_id,
                        None,
                        expires_in,
                        id_extra,
                    ) {
                        Ok(t) => Some(t),
                        Err(_) => {
                            return Err(TokenErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Failed to issue ID token".to_string(),
                            });
                        }
                    }
                } else {
                    None
                };

                let mut issued_refresh_token = None;
                if session.scope.contains("offline_access") {
                    let refresh_val = uuid::Uuid::new_v4().to_string();
                    // RFC 9449 §5: a refresh token minted alongside a
                    // DPoP-bound access token must itself be bound to the
                    // same key, so `default_handle_refresh_token` can
                    // enforce continuity on every future rotation.
                    let rt = RefreshToken::new(
                        refresh_val.clone(),
                        client_id.clone(),
                        identity,
                        session.scope,
                        Utc::now() + chrono::Duration::days(30),
                        req.dpop_jkt.clone(),
                    );
                    match store_refresh_token_verifying_dpop_binding(op_store, rt).await {
                        RefreshTokenStoreOutcome::Stored => {
                            issued_refresh_token = Some(refresh_val)
                        }
                        RefreshTokenStoreOutcome::NonFatalStorageFailure => {}
                        RefreshTokenStoreOutcome::DpopBindingFailed => {
                            return Err(TokenErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Failed to persist DPoP token binding"
                                    .to_string(),
                            });
                        }
                    }
                }

                Ok(TokenResponse {
                    access_token,
                    token_type: if req.dpop_jkt.is_some() {
                        "DPoP".to_string()
                    } else {
                        "Bearer".to_string()
                    },
                    expires_in,
                    id_token,
                    refresh_token: issued_refresh_token,
                    scope: scope_opt,
                    issued_token_type: None,
                })
            } else {
                Err(TokenErrorResponse {
                    error: "access_denied".to_string(),
                    error_description: "User denied the request".to_string(),
                })
            }
        }
    }
}

/// The built-in `authorization_code` grant (RFC 6749 §4.1) handling.
///
/// This is the default body for
/// [`crate::store::OpStore::handle_authorization_code_grant`] — split out
/// as a free function so the trait's default method can call it without
/// duplicating the logic, while `handle_token` reaches it exclusively
/// through the trait method (so an override actually takes effect).
///
/// `pub` (not `pub(crate)`), mirroring `default_handle_token_exchange`, so
/// an `OpStore::handle_authorization_code_grant` override outside this
/// crate can delegate to it and post-process the result — e.g. stamping
/// extra claims via `TokenManager::issue_user_token_with_extra`, or
/// creating session state — instead of having to reimplement code
/// consumption, PKCE verification, and redirect_uri/client_id validation
/// from scratch.
#[allow(clippy::too_many_arguments)]
pub async fn default_handle_authorization_code<S: OpStore + ?Sized>(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    op_store: &mut S,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    if !client.allows_grant_type(&GrantType::AuthorizationCode) {
        tracing::error!(client_id = %client_id, "Client not authorized for authorization_code grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use authorization_code grant type"
                .to_string(),
        });
    }

    let code_str = req.code.as_ref().unwrap();
    let req_redirect_uri = req.redirect_uri.as_deref().unwrap_or("");

    // 3. Consume the code atomically
    let auth_code = match op_store.consume_code(code_str).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!("Invalid or expired authorization code");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Authorization code is invalid or already used".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error consuming authorization code");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    // Check expiration explicitly just in case the store didn't
    if chrono::Utc::now() > auth_code.expires_at {
        tracing::warn!("Authorization code expired");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code has expired".to_string(),
        });
    }

    // 4. Validate code was issued to this client
    if auth_code.client_id != client_id {
        tracing::warn!(
            expected_client = %auth_code.client_id,
            actual_client = %client_id,
            "Client ID mismatch during token exchange"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code was not issued to this client".to_string(),
        });
    }

    // 5. Validate redirect_uri matches. Deliberately an exact string
    // comparison, and deliberately *not* routed through
    // `ClientRegistration::allows_redirect_uri`: RFC 6749 §4.1.3 requires the
    // token request to repeat the identical value from the authorization
    // request, which is a different question from whether the client was
    // allowed to use it at all. The RFC 8252 §7.3 loopback any-port carve-out
    // (authkestra#291) has no business here — `auth_code.redirect_uri` already
    // holds the concrete port the client presented at `/authorize`, so
    // ignoring the port would only let one loopback port be swapped for
    // another mid-flow.
    if auth_code.redirect_uri != req_redirect_uri {
        tracing::warn!(
            expected_uri = %auth_code.redirect_uri,
            actual_uri = %req_redirect_uri,
            "Redirect URI mismatch during token exchange"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Redirect URI does not match the one used during authorization"
                .to_string(),
        });
    }

    // 6. PKCE Enforcement
    if let Some(challenge) = &auth_code.code_challenge {
        let verifier = req.code_verifier.as_deref().unwrap_or("");
        if verifier.is_empty() {
            tracing::debug!("Missing code_verifier for PKCE-secured code");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "code_verifier is required".to_string(),
            });
        }

        let method = auth_code.code_challenge_method.as_deref().unwrap_or("");
        if method != "S256" {
            tracing::error!(
                method = %method,
                "Unsupported PKCE challenge method in stored authorization code. Only S256 is allowed."
            );
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Unsupported PKCE challenge method".to_string(),
            });
        }

        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, verifier.as_bytes());
        let hash = hasher.finalize();
        let computed_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        if computed_challenge != *challenge {
            tracing::warn!("PKCE S256 code challenge mismatch");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "code_verifier is invalid".to_string(),
            });
        }
    } else {
        // PKCE is mandatory for every client, per OAuth 2.1 §4.1
        // (authkestra#273): `client.require_pkce` no longer gates this. In
        // ordinary operation `handle_authorize` never stores a code without
        // a challenge, so this only fires for a code that reached storage
        // by some other path (a legacy pre-#273 code, or a downstream
        // `OpStore::store_code` override) — reject it rather than silently
        // skip PKCE verification for it.
        tracing::warn!("PKCE is mandatory but the stored authorization code has no code_challenge");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "PKCE is required".to_string(),
        });
    }

    // 7. Issue tokens
    let expires_in = config.access_token_ttl_secs;
    let scope_opt = if auth_code.scope.is_empty() {
        None
    } else {
        Some(auth_code.scope.clone())
    };

    let mut extra = HashMap::new();
    merge_dpop_cnf(&mut extra, req.dpop_jkt.as_deref());

    let access_token = match tokens.issue_access_token(
        auth_code.identity.clone(),
        &client_id,
        user_token_audience(&client_id, &client.allowed_audiences),
        expires_in,
        scope_opt.clone(),
        extra,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    let id_token = if auth_code.scope.contains("openid") {
        let id_extra = crate::amr_acr::amr_acr_extra_claims(&auth_code.identity);
        match tokens.issue_id_token_with_extra(
            auth_code.identity.clone(),
            &client_id,
            auth_code.nonce.clone(),
            expires_in,
            id_extra,
        ) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    // Issue refresh token if requested
    let mut issued_refresh_token = None;
    if auth_code.scope.contains("offline_access") {
        let refresh_val = uuid::Uuid::new_v4().to_string();
        // RFC 9449 §5: see the identical comment in `handle_device_code`.
        let rt_model = RefreshToken::new(
            refresh_val.clone(),
            client_id.clone(),
            auth_code.identity.clone(),
            auth_code.scope.clone(),
            Utc::now() + chrono::Duration::days(30),
            req.dpop_jkt.clone(),
        );
        match store_refresh_token_verifying_dpop_binding(op_store, rt_model).await {
            RefreshTokenStoreOutcome::Stored => issued_refresh_token = Some(refresh_val),
            RefreshTokenStoreOutcome::NonFatalStorageFailure => {}
            RefreshTokenStoreOutcome::DpopBindingFailed => {
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to persist DPoP token binding".to_string(),
                });
            }
        }
    }

    tracing::info!(
        client_id = %client_id,
        "Successfully exchanged authorization code for tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: if req.dpop_jkt.is_some() {
            "DPoP".to_string()
        } else {
            "Bearer".to_string()
        },
        expires_in,
        id_token,
        refresh_token: issued_refresh_token,
        scope: scope_opt,
        issued_token_type: None,
    })
}

/// Merges a DPoP `cnf.jkt` confirmation member (RFC 9449 §6.1) into an
/// `extra` claims map, preserving whatever the `cnf` object already holds.
///
/// A plain `extra.insert("cnf", json!({"jkt": ...}))` would silently
/// clobber an existing `cnf.x5t#S256` (RFC 8705) if a request is both
/// mTLS-bound and DPoP-bound — the spec requires both confirmation members
/// to coexist in one `cnf` object, not overwrite each other. A no-op when
/// `dpop_jkt` is `None`, so every call site can call this unconditionally.
///
/// `pub`, not `pub(crate)`: an `OpStore::handle_*_grant` override outside
/// this crate that delegates to a `default_handle_*` free function and
/// then stamps its own additional claims onto the result needs this same
/// merge — otherwise it would have to hand-roll the `cnf` merge itself and
/// risk reintroducing the exact clobber this function exists to prevent.
/// [`TokenRequest::dpop_jkt`] is the read-only accessor such an override
/// reads the key from.
pub fn merge_dpop_cnf(extra: &mut HashMap<String, serde_json::Value>, dpop_jkt: Option<&str>) {
    let Some(jkt) = dpop_jkt else {
        return;
    };
    let cnf = extra
        .entry("cnf".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if let Some(obj) = cnf.as_object_mut() {
        obj.insert(
            "jkt".to_string(),
            serde_json::Value::String(jkt.to_string()),
        );
    }
}

/// What happened when [`store_refresh_token_verifying_dpop_binding`] tried
/// to persist a freshly minted refresh token.
enum RefreshTokenStoreOutcome {
    /// Stored, and — if it was meant to be DPoP-bound — confirmed bound.
    Stored,
    /// Persistence could not be confirmed, but nothing positively
    /// disproves it either. Two cases: the store call itself failed for a
    /// token that was never meant to be DPoP-bound, or — since
    /// authkestra#290's review — the DPoP read-back probe could not be
    /// completed at all (it errored, or found no row yet). Every call site
    /// already tolerates this exactly as it did before this feature
    /// existed: log it, omit `refresh_token` from the response, and
    /// otherwise succeed.
    ///
    /// That "omit" is the whole reason the inconclusive cases land here
    /// rather than on `Stored`: at the two pre-consumption call sites
    /// nothing has been spent yet, so declining to *advertise* a binding
    /// no read has confirmed costs at most a re-authentication. At
    /// `default_handle_refresh_token`'s rotation site this arm and
    /// `Stored` have identical bodies and the response returns the rotated
    /// token either way, so an unconfirmable probe there cannot destroy
    /// the session of a predecessor token that has already been consumed.
    NonFatalStorageFailure,
    /// The token was meant to be DPoP-bound (`jkt: Some(_)`) but the
    /// read-back *positively* found a different (or absent) `jkt` on the
    /// stored row — never tolerated, unlike the case above, because
    /// silently issuing a refresh token whose RFC 9449 §5 continuity
    /// guarantee doesn't actually exist is exactly the silent security gap
    /// this check exists to catch. Deliberately distinct from a read-back
    /// that simply couldn't be completed (see `store_refresh_token_
    /// verifying_dpop_binding`'s doc comment): only a row that was actually
    /// read, and actually disagrees with what was written, proves the
    /// binding didn't persist.
    DpopBindingFailed,
}

/// Stores a freshly minted refresh token, then — only when it's meant to
/// be DPoP-bound — reads it back and confirms the binding actually
/// persisted.
///
/// A backend can silently drop `jkt` on write without `store_token`
/// itself ever returning an error — accepting a token with
/// `jkt: Some(_)` and simply never persisting that field.
/// `authkestra-store-sqlx`'s `SqlxOpStore` was exactly that case when this
/// check was written (authkestra#286): its schema had no `jkt` column.
/// authkestra#287 has since given it one and wired
/// `store_token`/`get_token`/`consume_token` to it, so that in-tree example
/// no longer applies — but any out-of-crate `RefreshTokenStore` written
/// against the pre-0.7 `RefreshToken`, or any hand-managed SQL schema that
/// skipped the 0.7 `ALTER`s, still behaves exactly this way. If nothing
/// ever checked, that token's RFC 9449 §5 continuity guarantee
/// would quietly not exist: `default_handle_refresh_token` would see
/// `jkt: None` on redemption and treat it as though it never asked for a
/// DPoP-bound refresh token in the first place, while the client's
/// response here claimed `token_type: "DPoP"` and a `cnf.jkt`-bound
/// access token. Reading the write back and refusing loudly is what turns
/// that silent security gap into a visible failure — the same principle
/// this crate already applies to every other silent-degradation risk in
/// this feature (`NoDpopReplayStore` failing closed rather than accepting
/// an unverifiable proof, the consume-before-validate ordering fix, and
/// so on).
///
/// Three outcomes, not two. Only a read-back that actually returns a row
/// with the *wrong* `jkt` counts as a confirmed drop and yields
/// [`RefreshTokenStoreOutcome::DpopBindingFailed`]. A read-back that
/// errors, or that (unlike the write moments earlier) finds no row at all,
/// is inconclusive — most plausibly a transient read issue, a pool blip,
/// or a read served by a lagging replica the just-completed write hasn't
/// reached — and yields
/// [`RefreshTokenStoreOutcome::NonFatalStorageFailure`].
///
/// Inconclusive is deliberately neither of the other two (authkestra#290
/// review). Reporting it as `DpopBindingFailed` would fail
/// `default_handle_refresh_token`'s rotation path *after* it has already
/// consumed the single-use predecessor token, destroying a live session
/// over a read hiccup. But reporting it as `Stored` is wrong in the other
/// direction: `store_token` returning `Ok` proves a write happened, not
/// that `jkt` survived it — and a store that silently drops `jkt` is the
/// exact failure this probe exists to catch, so an unreadable probe
/// against such a store must not be read as confirmation. Routing it to
/// `NonFatalStorageFailure` gives each call site the right answer without
/// a parameter: the pre-consumption sites omit the unconfirmed token, and
/// the rotation site (where that arm is a no-op) is unaffected.
async fn store_refresh_token_verifying_dpop_binding<S: OpStore + ?Sized>(
    op_store: &mut S,
    rt: RefreshToken,
) -> RefreshTokenStoreOutcome {
    let token = rt.token.clone();
    let expected_jkt = rt.jkt.clone();
    let dpop_bound = expected_jkt.is_some();

    if let Err(e) = op_store.store_token(rt).await {
        tracing::error!(error = ?e, "Failed to store refresh token");
        return if dpop_bound {
            RefreshTokenStoreOutcome::DpopBindingFailed
        } else {
            RefreshTokenStoreOutcome::NonFatalStorageFailure
        };
    }

    if !dpop_bound {
        return RefreshTokenStoreOutcome::Stored;
    }

    match op_store.get_token(&token).await {
        Ok(Some(stored)) if stored.jkt == expected_jkt => RefreshTokenStoreOutcome::Stored,
        Ok(Some(stored)) => {
            tracing::error!(
                expected_jkt = ?expected_jkt,
                stored_jkt = ?stored.jkt,
                "refresh token's DPoP binding did not survive storage — the configured \
                 RefreshTokenStore silently dropped `jkt`, which would let this token be \
                 redeemed without RFC 9449 §5 continuity enforcement; refusing rather than \
                 handing back a token whose response claims a binding storage doesn't have"
            );
            RefreshTokenStoreOutcome::DpopBindingFailed
        }
        Ok(None) => {
            // Inconclusive, not a confirmed drop: `store_token` already
            // returned `Ok`, so this is most plausibly a lagging read
            // replica. But it is equally the shape of a store that simply
            // didn't persist, so don't *advertise* a binding nothing has
            // confirmed — `NonFatalStorageFailure` omits the refresh token
            // at the pre-consumption call sites while leaving the rotation
            // path (which treats it identically to `Stored`) untouched.
            tracing::warn!(
                "could not confirm refresh token's DPoP binding: the token was not found on \
                 read-back immediately after a successful write (possible replica lag); \
                 omitting the unconfirmed refresh token rather than advertising a binding \
                 no read has confirmed"
            );
            RefreshTokenStoreOutcome::NonFatalStorageFailure
        }
        Err(e) => {
            // Same reasoning as `Ok(None)` above. Notably *not* treated as
            // proof the write is fine: a store whose `store_token` drops
            // `jkt` is exactly what this probe hunts for, and its
            // `get_token` erroring tells us nothing either way.
            tracing::warn!(
                error = ?e,
                "could not confirm refresh token's DPoP binding after a successful write; \
                 omitting the unconfirmed refresh token rather than advertising a binding \
                 no read has confirmed"
            );
            RefreshTokenStoreOutcome::NonFatalStorageFailure
        }
    }
}

/// Handles the `client_credentials` grant (RFC 6749 §4.4).
///
/// `client_cert_der`, if present, is the DER-encoded mTLS client certificate
/// presented on the current connection — see
/// [`handle_token_with_client_cert`]'s doc comment for where it comes from.
/// When present, the issued access token is bound to it per RFC 8705 §3: a
/// `cnf: {"x5t#S256": "<thumbprint>"}` confirmation claim is stamped onto
/// the token, and a resource server that requires certificate binding
/// (`authkestra_resource::jwt::ValidationConfig::require_cert_binding`)
/// rejects the token unless the *same* certificate is presented on the
/// connection used to redeem it. Generic mTLS between services proves who
/// opened the connection; it does not by itself prove the presenter is who
/// the token was issued to — this claim is what closes that gap (see issue
/// #224).
///
/// Binding is presence-triggered: any certificate the caller supplies is
/// bound, unconditionally. Whether certificate binding should instead be an
/// explicit opt-in *per client* (a new `ClientRegistration` field) is a
/// deliberate design choice left open here for a maintainer decision — see
/// the PR description.
async fn handle_client_credentials(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    tokens: &TokenManager,
    client_cert_der: Option<&[u8]>,
) -> Result<TokenResponse, TokenErrorResponse> {
    if !client.allows_grant_type(&GrantType::ClientCredentials) {
        tracing::error!(client_id = %client_id, "Client not authorized for client_credentials grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use client_credentials grant type"
                .to_string(),
        });
    }

    let expires_in = config.access_token_ttl_secs;
    let requested_scope = req.scope.clone();
    // Validate that requested scopes are allowed for this client
    if let Some(ref scopes) = requested_scope {
        let requested: Vec<&str> = scopes.split_whitespace().collect();
        for s in requested {
            if !client.scopes.contains(&s.to_string()) {
                tracing::warn!(client_id = %client_id, scope = %s, "Client requested unauthorized scope");
                return Err(TokenErrorResponse {
                    error: "invalid_scope".to_string(),
                    error_description: format!("Scope {} is not allowed for this client", s),
                });
            }
        }
    }

    // Determine the resource audience for the new token, mirroring the
    // `client.allowed_audiences` check `default_handle_token_exchange`
    // already performs (RFC 8707 resource indicators). When the caller
    // doesn't request an audience, keep the pre-existing behavior of
    // scoping the token to the client's own `client_id` rather than
    // defaulting to `config.issuer` — unlike token-exchange, there is no
    // established convention here and changing the no-audience default
    // would be a silent behavioral break for existing integrators.
    let aud = if let Some(requested_aud) = req.audience.clone() {
        if !client.allowed_audiences.contains(&requested_aud) {
            tracing::warn!(
                client_id = %client_id,
                audience = %requested_aud,
                "Requested audience is not allowed for this client"
            );
            return Err(TokenErrorResponse {
                error: "invalid_target".to_string(),
                error_description: "Requested audience is not allowed".to_string(),
            });
        }
        tracing::debug!(client_id = %client_id, audience = %requested_aud, "Issuing client_credentials token bound to requested audience");
        requested_aud
    } else {
        tracing::debug!(client_id = %client_id, "No audience requested; defaulting client_credentials token audience to client_id");
        client_id.clone()
    };

    // RFC 8705 §3: stamp a certificate-bound `cnf.x5t#S256` confirmation
    // claim when the connection presented an mTLS client certificate, so
    // the token is proof-of-possession-bound rather than a plain replayable
    // bearer token for its whole TTL.
    let mut extra = HashMap::new();
    if let Some(cert_der) = client_cert_der {
        let thumbprint = x5t_s256_thumbprint(cert_der);
        tracing::debug!(
            client_id = %client_id,
            x5t_s256 = %thumbprint,
            "Binding client_credentials access token to presented mTLS client certificate (RFC 8705)"
        );
        extra.insert(
            "cnf".to_string(),
            serde_json::json!({ "x5t#S256": thumbprint }),
        );
    }
    merge_dpop_cnf(&mut extra, req.dpop_jkt.as_deref());

    let access_token = match tokens.issue_client_token_with_extra(
        &client_id,
        expires_in,
        requested_scope.clone(),
        Some(aud),
        extra,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token for client credentials");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    tracing::info!(
        client_id = %client_id,
        certificate_bound = client_cert_der.is_some(),
        "Successfully issued tokens for client credentials grant"
    );

    Ok(TokenResponse {
        access_token,
        token_type: if req.dpop_jkt.is_some() {
            "DPoP".to_string()
        } else {
            "Bearer".to_string()
        },
        expires_in,
        id_token: None, // client credentials does not issue ID tokens
        refresh_token: None,
        scope: requested_scope,
        issued_token_type: None,
    })
}

#[allow(clippy::too_many_arguments)]
/// The built-in `refresh_token` grant handling.
///
/// This is the default body for [`crate::store::OpStore::handle_refresh_token`]
/// — split out as a free function so the trait's default method can call it
/// without duplicating the logic, while `handle_token` reaches it exclusively
/// through the trait method (so an override actually takes effect).
pub(crate) async fn default_handle_refresh_token<S: OpStore + ?Sized>(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    op_store: &mut S,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    if !client.allows_grant_type(&GrantType::RefreshToken) {
        tracing::error!(client_id = %client_id, "Client not authorized for refresh_token grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use refresh_token grant type"
                .to_string(),
        });
    }

    if !tokens.has_issuer() {
        tracing::error!(client_id = %client_id, "Cannot refresh access token without issuer configuration");
        return Err(TokenErrorResponse {
            error: "server_error".to_string(),
            error_description: "Access token issuer is not configured".to_string(),
        });
    }

    let refresh_token_str = match req.refresh_token.as_deref() {
        Some(t) => t,
        None => {
            tracing::debug!("Missing refresh_token in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "refresh_token is required".to_string(),
            });
        }
    };

    // Looked up first, *not* consumed yet: every check below (client_id,
    // expiry, DPoP continuity) runs against this non-destructive read.
    // Consumption — the actual single-use, atomic revoke-and-return — only
    // happens once every check has passed. Doing it in the other order
    // (consume first, validate after, as this function used to) means any
    // one of these checks failing after consumption permanently destroys a
    // refresh token that was otherwise still valid. For the DPoP check in
    // particular, that inverts the feature's own threat model: an attacker
    // holding nothing but a leaked token *string* (no key at all) could
    // send one request with no `DPoP` header and permanently log the
    // legitimate holder out — turning a leaked-but-otherwise-useless token
    // into a working denial-of-service weapon. The same trap would catch a
    // legitimate client behind a proxy that strips the header. Validating
    // first means a request that fails never has a side effect on a token
    // it had no right to consume.
    let candidate = match op_store.get_token(refresh_token_str).await {
        Ok(Some(rt)) => rt,
        Ok(None) => {
            tracing::warn!("Invalid refresh token (unknown, revoked, or expired)");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid refresh token".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Failed to look up refresh token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    if candidate.client_id != client_id {
        tracing::warn!("Refresh token issued to a different client");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Invalid refresh token".to_string(),
        });
    }

    if chrono::Utc::now() > candidate.expires_at {
        tracing::warn!("Refresh token expired");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Refresh token expired".to_string(),
        });
    }

    // RFC 9449 §5: a refresh token that was bound to a DPoP key when issued
    // MUST continue to be redeemed with a proof for that *same* key on
    // every rotation — a request that omits DPoP entirely, or presents a
    // proof for a different key, is refused rather than silently falling
    // back to a plain bearer token or re-binding to whatever key the
    // presenter happens to hold. Without this, an exfiltrated DPoP-bound
    // refresh token could be redeemed with the attacker's own key (or no
    // proof at all), which is exactly the theft scenario DPoP exists to
    // close for public clients (authkestra#274). A `candidate.jkt` of
    // `None` means this refresh token was never DPoP-bound — that behavior
    // is unchanged from before this feature existed.
    if let Some(expected_jkt) = &candidate.jkt {
        if req.dpop_jkt.as_deref() != Some(expected_jkt.as_str()) {
            tracing::warn!(
                client_id = %client_id,
                "Refresh token is DPoP-bound but the request's proof key does not match"
            );
            return Err(TokenErrorResponse {
                error: "invalid_dpop_proof".to_string(),
                error_description: "This refresh token is bound to a different DPoP key"
                    .to_string(),
            });
        }
    }
    // RFC 6749 §6: a refresh token's scope is fixed at issuance, but the
    // client's *registration* is not — an operator can narrow `scopes` at
    // any time, and authkestra#278 made that narrowing the mechanism for
    // revoking a scope. Without re-checking here, a refresh token issued
    // before the narrowing keeps minting access tokens for the removed
    // scope indefinitely, rotating a fresh 30-day token forward on every
    // use, so the narrowing never takes effect for exactly the clients
    // that already hold long-lived credentials. Every sibling grant
    // already validates against the live registration (`handle_authorize`,
    // `handle_device_authorization`, `handle_client_credentials`,
    // `default_handle_token_exchange`); this was the one path that did
    // not.
    //
    // Checked here, against the non-destructive `candidate`, rather than
    // after `consume_token` below: a request that is refused must not
    // destroy the token it had no right to consume (authkestra#287).
    for scope in candidate.scope.split_whitespace() {
        if !client.allows_scope(scope) {
            tracing::warn!(
                client_id = %client_id,
                scope = %scope,
                "Refresh token carries a scope the client is no longer registered for"
            );
            return Err(TokenErrorResponse {
                error: "invalid_scope".to_string(),
                error_description: format!("Scope {} is not allowed for this client", scope),
            });
        }
    }

    // Carries the rotated token's binding forward. Deliberately reads from
    // `candidate.jkt` rather than `req.dpop_jkt` when the token was already
    // bound (the branch above already proved they're equal) — the stored,
    // trusted value is preferred over re-deriving it from client input.
    // When `candidate.jkt` is `None`, this is the first time the client has
    // presented a DPoP proof for this token lineage, so `req.dpop_jkt`
    // (possibly still `None`) begins the binding going forward.
    let jkt = candidate.jkt.clone().or_else(|| req.dpop_jkt.clone());

    // All checks passed — now, and only now, perform the actual single-use
    // consumption. `consume_token`'s atomicity is still what prevents two
    // concurrent requests presenting the same token from both succeeding:
    // if a concurrent request already won that race between the `get_token`
    // above and this call, this returns `Ok(None)` and the loser (this
    // request) is correctly refused, with no destructive effect of its own.
    let old_rt = match op_store.consume_token(refresh_token_str).await {
        Ok(Some(rt)) => rt,
        Ok(None) => {
            tracing::warn!("Refresh token was consumed by a concurrent request");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid refresh token".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Failed to consume refresh token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    let new_refresh_val = uuid::Uuid::new_v4().to_string();
    let new_rt = RefreshToken::new(
        new_refresh_val.clone(),
        client_id.clone(),
        old_rt.identity.clone(),
        old_rt.scope.clone(),
        chrono::Utc::now() + chrono::Duration::days(30),
        jkt.clone(),
    );

    match store_refresh_token_verifying_dpop_binding(op_store, new_rt).await {
        RefreshTokenStoreOutcome::Stored => {}
        // Pre-existing behavior for this grant, unrelated to DPoP: a plain
        // storage failure here is logged but doesn't fail the request —
        // the client still gets a `refresh_token` in the response even
        // though it wasn't actually persisted. Not this fix's concern.
        RefreshTokenStoreOutcome::NonFatalStorageFailure => {}
        RefreshTokenStoreOutcome::DpopBindingFailed => {
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to persist DPoP token binding".to_string(),
            });
        }
    }

    let expires_in = config.access_token_ttl_secs;
    let scope_opt = if old_rt.scope.is_empty() {
        None
    } else {
        Some(old_rt.scope.clone())
    };

    let mut extra = HashMap::new();
    merge_dpop_cnf(&mut extra, jkt.as_deref());

    let access_token = match tokens.issue_access_token(
        old_rt.identity.clone(),
        &client_id,
        user_token_audience(&client_id, &client.allowed_audiences),
        expires_in,
        scope_opt.clone(),
        extra,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    // Per OIDC Core §12.2, an id_token MAY be re-minted on refresh; a client
    // that never requested `openid` gets none, mirroring how
    // `default_handle_authorization_code` gates `issue_id_token` on the same
    // scope check. Refresh tokens don't carry a `nonce` (only auth codes do,
    // reflecting the original `/authorize` request) — Core §12.2 lists
    // `nonce` as OPTIONAL on a refreshed id_token, so omitting it is
    // conformant, not a shortcut.
    let id_token = if old_rt.scope.contains("openid") {
        let id_extra = crate::amr_acr::amr_acr_extra_claims(&old_rt.identity);
        match tokens.issue_id_token_with_extra(
            old_rt.identity.clone(),
            &client_id,
            None,
            expires_in,
            id_extra,
        ) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    tracing::info!(
        client_id = %client_id,
        "Successfully refreshed tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: if jkt.is_some() {
            "DPoP".to_string()
        } else {
            "Bearer".to_string()
        },
        expires_in,
        id_token,
        refresh_token: Some(new_refresh_val),
        scope: scope_opt,
        issued_token_type: None,
    })
}

/// The built-in `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)
/// grant handling.
///
/// This is the default body for [`crate::store::OpStore::handle_token_exchange`]
/// — split out as a free function so the trait's default method can call it
/// without duplicating the logic, while `handle_token` reaches it exclusively
/// through the trait method (so an override actually takes effect).
///
/// `pub` (not `pub(crate)`) so an `OpStore::handle_token_exchange` override
/// outside this crate can delegate to it and post-process the result — e.g.
/// stamping extra claims via `TokenManager::issue_user_token_with_extra` —
/// instead of having to reimplement the RFC 8693 validation (subject-token
/// validation, audience binding, scope intersection,
/// `subject_token_type`/`requested_token_type` checks) from scratch.
pub async fn default_handle_token_exchange(
    req: TokenRequest,
    client_id: String,
    client: crate::client::ClientRegistration,
    config: &OpConfig,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::client::GrantType;
    // Captured up front: several `req` fields below are moved out
    // (`req.audience`, `req.scope`) before the access token is issued, and
    // `dpop_jkt` is needed at that point.
    let dpop_jkt = req.dpop_jkt.clone();

    if !config.token_exchange_enabled {
        tracing::warn!("Token exchange is disabled globally");
        return Err(TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Token exchange is not enabled on this authorization server"
                .to_string(),
        });
    }

    if !client.allows_grant_type(&GrantType::TokenExchange) {
        tracing::error!(client_id = %client_id, "Client not authorized for token_exchange grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use token_exchange grant type"
                .to_string(),
        });
    }

    if req.actor_token.is_some() || req.actor_token_type.is_some() {
        tracing::debug!("Delegation (actor_token) is not supported");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "actor_token is not supported".to_string(),
        });
    }

    let subject_token_type = req.subject_token_type.as_deref().unwrap_or("");
    if subject_token_type != "urn:ietf:params:oauth:token-type:access_token"
        && subject_token_type != "urn:ietf:params:oauth:token-type:id_token"
    {
        tracing::debug!(subject_token_type = %subject_token_type, "Unsupported subject_token_type");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Unsupported subject_token_type".to_string(),
        });
    }

    let requested_token_type = req
        .requested_token_type
        .as_deref()
        .unwrap_or("urn:ietf:params:oauth:token-type:access_token");
    if requested_token_type != "urn:ietf:params:oauth:token-type:access_token"
        && requested_token_type != "urn:ietf:params:oauth:token-type:id_token"
    {
        tracing::debug!(requested_token_type = %requested_token_type, "Unsupported requested_token_type");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description:
                "Unsupported requested_token_type. Only access_token and id_token are supported."
                    .to_string(),
        });
    }

    let subject_token_str = match req.subject_token.as_deref() {
        Some(t) => t,
        None => {
            tracing::debug!("Missing subject_token in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "subject_token is required".to_string(),
            });
        }
    };

    let claims: Claims = match tokens.validate_token(subject_token_str, None) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = ?e, "Failed to validate subject_token");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "subject_token is invalid".to_string(),
            });
        }
    };

    if !subject_token_dpop_binding_matches(&claims, dpop_jkt.as_deref()) {
        tracing::warn!(client_id = %client_id, "Subject token is DPoP-bound but the exchange proof key does not match");
        return Err(TokenErrorResponse {
            error: "invalid_dpop_proof".to_string(),
            error_description: "The subject token is bound to a different DPoP key".to_string(),
        });
    }

    // Bind the exchange to the requesting client through `aud`, or through
    // the signed `client_id` on this issuer's RFC 9068 access tokens.
    let client_binding =
        subject_token_client_binding(subject_token_str, &claims, subject_token_type, &client_id);
    if let Some(binding) = client_binding {
        tracing::debug!(?binding, "Subject token authorized for client exchange");
    } else {
        tracing::error!(
            client_id = %client_id,
            "Client is not authorized to exchange this token"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Client is not authorized to exchange this token".to_string(),
        });
    }

    // Determine the resource audience for the new token
    let new_aud = if let Some(requested_aud) = req.audience {
        if !client.allowed_audiences.contains(&requested_aud) {
            tracing::warn!(
                client_id = %client_id,
                audience = %requested_aud,
                "Requested audience is not allowed for this client"
            );
            return Err(TokenErrorResponse {
                error: "invalid_target".to_string(),
                error_description: "Requested audience is not allowed".to_string(),
            });
        }
        Some(requested_aud)
    } else {
        Some(config.issuer.clone())
    };

    // Scope narrowing logic
    let original_scope = claims.scope.unwrap_or_default();
    let original_scopes: Vec<&str> = original_scope.split_whitespace().collect();
    let requested_scope = req.scope.unwrap_or_default();
    let requested_scopes: Vec<&str> = if requested_scope.is_empty() {
        original_scopes.clone()
    } else {
        requested_scope.split_whitespace().collect()
    };

    let mut intersected_scopes = Vec::new();
    for s in requested_scopes {
        if original_scopes.contains(&s) && client.scopes.contains(&s.to_string()) {
            intersected_scopes.push(s.to_string());
        }
    }

    // If a scope was requested but intersection is empty, it's an error.
    if !requested_scope.is_empty() && intersected_scopes.is_empty() {
        tracing::warn!("Requested scope resulted in empty intersection");
        return Err(TokenErrorResponse {
            error: "invalid_scope".to_string(),
            error_description: "Requested scope is invalid, unknown, or malformed".to_string(),
        });
    }

    let final_scope_str = if intersected_scopes.is_empty() {
        None
    } else {
        Some(intersected_scopes.join(" "))
    };

    let identity = match claims.identity {
        Some(id) => id,
        None => {
            tracing::warn!("subject_token does not contain an identity");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "subject_token is missing identity".to_string(),
            });
        }
    };

    let expires_in = config.access_token_ttl_secs;
    let granted_openid = final_scope_str
        .as_deref()
        .is_some_and(|s| s.split_whitespace().any(|scope| scope == "openid"));

    // Per OIDC Core §12.2 / RFC 8693 §2.1, an id_token accompanies the
    // access token when the `openid` scope is in the final granted scope —
    // mirroring how `default_handle_authorization_code` and
    // `default_handle_refresh_token` gate `issue_id_token` on the same
    // check. `requested_token_type: id_token` is a client signal that it
    // wants one, but the crate's `TokenResponse` always carries an
    // `access_token`; id_token issuance itself stays scope-gated so it does
    // not depend on which requested_token_type value was sent. No nonce is
    // reflected, since RFC 8693 exchange requests don't carry one.
    let id_token = if granted_openid {
        let id_extra = crate::amr_acr::amr_acr_extra_claims(&identity);
        match tokens.issue_id_token_with_extra(
            identity.clone(),
            &client_id,
            None,
            expires_in,
            id_extra,
        ) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token during exchange");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    let mut extra = HashMap::new();
    merge_dpop_cnf(&mut extra, dpop_jkt.as_deref());

    let access_token = match tokens.issue_user_token_with_extra(
        identity,
        expires_in,
        final_scope_str.clone(),
        new_aud,
        extra,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token during exchange");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    tracing::info!(
        client_id = %client_id,
        "Successfully exchanged token"
    );

    Ok(TokenResponse {
        access_token,
        token_type: if dpop_jkt.is_some() {
            "DPoP".to_string()
        } else {
            "Bearer".to_string()
        },
        expires_in,
        id_token,
        refresh_token: None,
        scope: final_scope_str,
        // RFC 8693 §2.2.1: REQUIRED on a token-exchange response. `access_token`
        // always carries an access token here regardless of the requested
        // `requested_token_type` — see the id_token issuance comment above for
        // why that value doesn't change which field the access token lives in.
        issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
    })
}

#[cfg(test)]
#[allow(deprecated)] // `require_pkce` (authkestra#273) — these fixtures don't exercise it
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, GrantType};
    use crate::code::{AuthorizationCode, AuthorizationCodeStore};

    use crate::refresh::{RefreshToken, RefreshTokenStore};
    use authkestra_engine::auth::state::Identity;
    use authkestra_engine::store::KvStore;
    use authkestra_engine::token::TokenManager;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    pub(crate) fn test_config(token_exchange_enabled: bool) -> OpConfig {
        OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "custom".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled,
        }
    }

    pub(crate) fn test_tokens() -> TokenManager {
        TokenManager::new(
            b"super_secret_key_that_is_long_enough_for_hmac",
            Some("https://auth.example.com".to_string()),
        )
    }

    fn test_identity() -> Identity {
        Identity {
            provider_id: "test".to_string(),
            external_id: "user123".to_string(),
            username: Some("user123".to_string()),
            email: None,
            attributes: HashMap::new(),
        }
    }

    fn issue_subject_token(
        tokens: &TokenManager,
        client_id: &str,
        scope: Option<String>,
    ) -> String {
        tokens
            .issue_user_token(test_identity(), 3600, scope, Some(client_id.to_string()))
            .unwrap()
    }

    /// Like `issue_subject_token`, but mints a subject token whose `aud`
    /// claim is a JSON array (RFC 7519 §4.1.3), the shape a stock Keycloak
    /// realm with multiple `oidc-audience-mapper` entries produces. Built by
    /// hand with `jsonwebtoken::encode` because `TokenManager`'s issuance
    /// methods only ever emit a single-string `aud`. The signing secret
    /// below must match `test_tokens()`'s so `TokenManager::validate_token`
    /// can verify the result.
    fn issue_subject_token_multi_aud(audiences: &[&str], scope: Option<String>) -> String {
        let now = chrono::Utc::now().timestamp() as usize;
        let raw_claims = serde_json::json!({
            "sub": "user123",
            "aud": audiences,
            "exp": now + 3600,
            "iat": now,
            "scope": scope,
            "identity": {
                "provider_id": "test",
                "external_id": "user123",
                "email": null,
                "username": "user123",
                "attributes": {}
            }
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &raw_claims,
            &jsonwebtoken::EncodingKey::from_secret(
                b"super_secret_key_that_is_long_enough_for_hmac",
            ),
        )
        .unwrap()
    }

    // --- Pre-existing restored tests ---

    #[tokio::test]
    async fn test_invalid_grant_type() {
        let req = TokenRequest {
            grant_type: "invalid".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "unauthorized_client");
    }

    #[tokio::test]
    async fn test_authorization_code_grant_rejected_when_client_not_granted() {
        // `client1` is registered without `authorization_code` in its
        // `grant_types` — unlike `handle_device_code`,
        // `handle_client_credentials`, `default_handle_refresh_token`, and
        // `default_handle_token_exchange`, `default_handle_authorization_code`
        // must reject this the same way, before ever looking up a code.
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("some-code".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::ClientCredentials],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
        assert_eq!(
            err.error_description,
            "Client is not authorized to use authorization_code grant type"
        );
    }

    #[tokio::test]
    async fn test_successful_exchange_with_pkce() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let verifier = "test_verifier";
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code({
                let mut auth_code = AuthorizationCode::new(
                    "code1".to_string(),
                    "client1".to_string(),
                    "https://cb".to_string(),
                    "openid".to_string(),
                    test_identity(),
                    Utc::now() + Duration::minutes(5),
                    false,
                );
                auth_code.code_challenge = Some(challenge);
                auth_code.code_challenge_method = Some("S256".to_string());
                auth_code
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: Some(verifier.to_string()),
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert!(res.is_ok());
    }

    // --- OpStore::handle_authorization_code_grant override seam (issue #237) ---

    /// A minimal `OpStore` wrapper that delegates every method to an inner
    /// `OpStore` except `handle_authorization_code_grant`, which it
    /// overrides with a canned response. Proves the override actually
    /// reaches the dispatch site in `handle_token`, not just that the trait
    /// compiles. Mirrors `OverridingRefreshStore` above.
    struct OverridingAuthorizationCodeStore<Inner> {
        inner: Inner,
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::client::ClientStore for OverridingAuthorizationCodeStore<Inner> {
        async fn find_client(
            &mut self,
            client_id: &str,
        ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError> {
            self.inner.find_client(client_id).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::code::AuthorizationCodeStore
        for OverridingAuthorizationCodeStore<Inner>
    {
        async fn store_code(
            &mut self,
            code: AuthorizationCode,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_code(code).await
        }

        async fn consume_code(
            &mut self,
            code: &str,
        ) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
            self.inner.consume_code(code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> RefreshTokenStore for OverridingAuthorizationCodeStore<Inner> {
        async fn store_token(
            &mut self,
            token: RefreshToken,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_token(token).await
        }

        async fn get_token(
            &mut self,
            token: &str,
        ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            self.inner.get_token(token).await
        }

        async fn revoke_token(
            &mut self,
            token: &str,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.revoke_token(token).await
        }

        async fn consume_token(
            &mut self,
            token: &str,
        ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            self.inner.consume_token(token).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::device::DeviceCodeStore for OverridingAuthorizationCodeStore<Inner> {
        async fn store_device_code(
            &mut self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_device_code(session).await
        }

        async fn get_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.get_device_code(device_code).await
        }

        async fn get_by_user_code(
            &mut self,
            user_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.get_by_user_code(user_code).await
        }

        async fn update_device_code(
            &mut self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.update_device_code(session).await
        }

        async fn delete_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.delete_device_code(device_code).await
        }

        async fn consume_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.consume_device_code(device_code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> OpStore for OverridingAuthorizationCodeStore<Inner> {
        async fn handle_authorization_code_grant(
            &mut self,
            _req: TokenRequest,
            _client_id: String,
            _client: ClientRegistration,
            _config: &OpConfig,
            _tokens: &TokenManager,
        ) -> Result<TokenResponse, TokenErrorResponse> {
            Ok(TokenResponse {
                access_token: "overridden-ac-access-token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 42,
                id_token: Some("overridden-ac-id-token".to_string()),
                refresh_token: Some("overridden-ac-refresh-token".to_string()),
                scope: Some("overridden-ac-scope".to_string()),
                issued_token_type: None,
            })
        }
    }

    fn auth_code_test_client() -> ClientRegistration {
        ClientRegistration {
            client_id: "client1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec!["https://cb".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        }
    }

    fn auth_code_test_req(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        }
    }

    #[tokio::test]
    async fn test_authorization_code_is_overridable_by_op_store() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                auth_code_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut store =
            OverridingAuthorizationCodeStore {
                inner:
                    crate::store::CompositeOpStore::new(
                        clients,
                        authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                        authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                        authkestra_engine::store::memory::MemoryStore::<
                            crate::device::DeviceCodeSession,
                        >::new(),
                    ),
            };

        // Deliberately a code no store has ever issued: if dispatch fell
        // through to the built-in handler instead of the override, this
        // would fail closed with `invalid_grant`, not succeed.
        let req = auth_code_test_req("no-such-code");

        let res = handle_token(req, None, &test_config(false), &mut store, &test_tokens()).await;

        let resp =
            res.expect("the override should have been invoked instead of the built-in handler");
        assert_eq!(resp.access_token, "overridden-ac-access-token");
        assert_eq!(resp.id_token.as_deref(), Some("overridden-ac-id-token"));
        assert_eq!(
            resp.refresh_token.as_deref(),
            Some("overridden-ac-refresh-token")
        );
    }

    #[tokio::test]
    async fn test_authorization_code_default_behavior_is_unchanged_without_override() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    scopes: vec!["openid".to_string(), "offline_access".to_string()],
                    ..auth_code_test_client()
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        // PKCE is mandatory (authkestra#273), so this fixture needs a real
        // challenge/verifier pair — unrelated to what this test actually
        // covers (OpStore default-dispatch behavior), but required to reach
        // that code path at all.
        let verifier = "test_verifier";
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code({
                let mut auth_code = AuthorizationCode::new(
                    "code-default".to_string(),
                    "client1".to_string(),
                    "https://cb".to_string(),
                    "openid offline_access".to_string(),
                    test_identity(),
                    Utc::now() + Duration::minutes(5),
                    false,
                );
                auth_code.code_challenge = Some(challenge);
                auth_code.code_challenge_method = Some("S256".to_string());
                auth_code
            })
            .await
            .unwrap();

        // A store that does NOT override `handle_authorization_code_grant`
        // — this is the compatibility guarantee: it must behave identically
        // to before the trait method existed.
        let res = handle_token(
            TokenRequest {
                code_verifier: Some(verifier.to_string()),
                ..auth_code_test_req("code-default")
            },
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(resp.scope.as_deref(), Some("openid offline_access"));
        assert!(resp.id_token.is_some());
        assert!(resp.refresh_token.is_some());
        // The code was consumed (single-use) by the exchange above.
        assert!(codes.consume_code("code-default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_invalid_pkce_verifier() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code({
                let mut auth_code = AuthorizationCode::new(
                    "code1".to_string(),
                    "client1".to_string(),
                    "https://cb".to_string(),
                    "openid".to_string(),
                    test_identity(),
                    Utc::now() + Duration::minutes(5),
                    false,
                );
                auth_code.code_challenge = Some("valid_challenge".to_string());
                auth_code.code_challenge_method = Some("S256".to_string());
                auth_code
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: Some("wrong_verifier".to_string()),
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_redirect_uri_mismatch() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code(AuthorizationCode::new(
                "code1".to_string(),
                "client1".to_string(),
                "https://cb".to_string(),
                "".to_string(),
                test_identity(),
                Utc::now() + Duration::minutes(5),
                false,
            ))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://wrong".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_reject_plain_pkce_method() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code({
                let mut auth_code = AuthorizationCode::new(
                    "code1".to_string(),
                    "client1".to_string(),
                    "https://cb".to_string(),
                    "".to_string(),
                    test_identity(),
                    Utc::now() + Duration::minutes(5),
                    false,
                );
                auth_code.code_challenge = Some("challenge".to_string());
                auth_code.code_challenge_method = Some("plain".to_string());
                auth_code
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: Some("challenge".to_string()),
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "server_error");
    }

    /// authkestra#273: PKCE is mandatory at redemption too, not just at
    /// `/authorize`. `handle_authorize` never stores a challenge-less code
    /// any more, but a code can still reach storage without one via a
    /// legacy pre-#273 row or a downstream `OpStore::store_code` override —
    /// this must not be treated as "PKCE wasn't required for this client".
    #[tokio::test]
    async fn test_pkce_is_mandatory_at_redemption_even_for_a_challenge_less_code() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code(AuthorizationCode::new(
                "code1".to_string(),
                "client1".to_string(),
                "https://cb".to_string(),
                "".to_string(),
                test_identity(),
                Utc::now() + Duration::minutes(5),
                false,
            ))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens(),
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.error, "invalid_grant");
        // `invalid_grant` alone is produced by several other rejection
        // paths in this function (expired code, wrong client, redirect_uri
        // mismatch, ...) — pin the description too so this test actually
        // proves the PKCE-mandatory-at-redemption guard fired, not just
        // that *some* rejection did.
        assert_eq!(err.error_description, "PKCE is required");
    }

    #[tokio::test]
    async fn test_client_credentials() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::ClientCredentials],
                    scopes: vec!["custom".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let req = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: Some("custom".to_string()),
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        let resp = res.unwrap();
        // Read via the serialized wire shape, not the Rust field directly,
        // so this assertion compiles unmodified: `issued_token_type` is
        // RFC 8693 §2.2.1's requirement for the token-exchange grant only —
        // client_credentials must keep an identical response shape.
        let value = serde_json::to_value(&resp).unwrap();
        assert!(value.get("issued_token_type").is_none());
    }

    /// Builds the same single-client store `test_client_credentials` above
    /// uses, factored out so the certificate-binding tests below don't
    /// repeat it. `allowed_audiences` defaults empty; callers that need a
    /// specific audience build their own store inline (see the audience
    /// tests below).
    async fn client_credentials_store(
        client_id: &str,
    ) -> crate::store::CompositeOpStore<
        authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
        authkestra_engine::store::memory::MemoryStore<crate::code::AuthorizationCode>,
        authkestra_engine::store::memory::MemoryStore<crate::refresh::RefreshToken>,
        authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
    > {
        client_credentials_store_with_audiences(client_id, vec![]).await
    }

    /// As [`client_credentials_store`], but lets the caller set
    /// `allowed_audiences` — needed by the audience-enforcement tests and by
    /// [`test_client_credentials_stamps_cnf_and_honors_audience_together`],
    /// which exercises both #223 and #224 on the same request.
    async fn client_credentials_store_with_audiences(
        client_id: &str,
        allowed_audiences: Vec<String>,
    ) -> crate::store::CompositeOpStore<
        authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
        authkestra_engine::store::memory::MemoryStore<crate::code::AuthorizationCode>,
        authkestra_engine::store::memory::MemoryStore<crate::refresh::RefreshToken>,
        authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
    > {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                client_id,
                ClientRegistration {
                    client_id: client_id.to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::ClientCredentials],
                    scopes: vec!["custom".to_string()],
                    require_pkce: false,
                    allowed_audiences,
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        crate::store::CompositeOpStore::new(
            clients,
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
        )
    }

    fn client_credentials_request(client_id: &str) -> TokenRequest {
        client_credentials_request_with_audience(client_id, None)
    }

    /// As [`client_credentials_request`], but lets the caller set the
    /// requested `audience`.
    fn client_credentials_request_with_audience(
        client_id: &str,
        audience: Option<&str>,
    ) -> TokenRequest {
        TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some(client_id.to_string()),
            client_secret: None,
            code_verifier: None,
            scope: Some("custom".to_string()),
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: audience.map(|a| a.to_string()),
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        }
    }

    /// Issue #224: a `client_credentials` token issued over a connection
    /// that presented an mTLS client certificate must carry an RFC 8705 §3
    /// `cnf.x5t#S256` confirmation claim whose value is the base64url
    /// SHA-256 thumbprint of that certificate's DER bytes.
    ///
    /// This is the test that fails against the pre-fix behavior: before
    /// this change, `handle_client_credentials` always called
    /// `tokens.issue_client_token` (no `extra` claims at all), so no amount
    /// of certificate presentation ever produced a `cnf` claim.
    #[tokio::test]
    async fn test_client_credentials_stamps_cnf_x5t_s256_when_certificate_presented() {
        let mut store = client_credentials_store("client1").await;

        let cert_der = b"a fake DER-encoded mTLS client certificate for testing";
        let expected_thumbprint =
            authkestra_engine::token::cert_binding::x5t_s256_thumbprint(cert_der);

        let tokens = test_tokens();
        let resp = handle_token_with_client_cert(
            client_credentials_request("client1"),
            None,
            &test_config(false),
            &mut store,
            &tokens,
            Some(cert_der),
            None,
        )
        .await
        .expect("client_credentials with a presented certificate should succeed");

        let claims = tokens
            .validate_token(&resp.access_token, Some("client1"))
            .expect("issued token must validate");

        let cnf = claims
            .extra
            .get("cnf")
            .expect("a certificate was presented; the token must carry a cnf claim");
        assert_eq!(
            cnf.get("x5t#S256").and_then(|v| v.as_str()),
            Some(expected_thumbprint.as_str()),
            "cnf.x5t#S256 must be the SHA-256/base64url thumbprint of the presented certificate's DER bytes"
        );
    }

    /// Companion to the test above: with no certificate presented on the
    /// connection, `client_credentials` keeps issuing a plain bearer token
    /// with no `cnf` claim at all — this feature must be additive, not
    /// force certificate binding onto every deployment.
    #[tokio::test]
    async fn test_client_credentials_omits_cnf_when_no_certificate_presented() {
        let mut store = client_credentials_store("client1").await;

        let tokens = test_tokens();
        let resp = handle_token_with_client_cert(
            client_credentials_request("client1"),
            None,
            &test_config(false),
            &mut store,
            &tokens,
            None,
            None,
        )
        .await
        .expect("client_credentials with no certificate should still succeed");

        let claims = tokens
            .validate_token(&resp.access_token, Some("client1"))
            .expect("issued token must validate");
        assert!(
            !claims.extra.contains_key("cnf"),
            "no certificate was presented; the token must not carry a cnf claim"
        );
    }

    /// `handle_token` (the plain 5-argument entry point every existing
    /// caller uses) must keep behaving exactly like passing `None` to
    /// `handle_token_with_client_cert` — no `cnf` claim, ever.
    #[tokio::test]
    async fn test_handle_token_without_cert_param_never_stamps_cnf() {
        let mut store = client_credentials_store("client1").await;

        let tokens = test_tokens();
        let resp = handle_token(
            client_credentials_request("client1"),
            None,
            &test_config(false),
            &mut store,
            &tokens,
        )
        .await
        .unwrap();

        let claims = tokens
            .validate_token(&resp.access_token, Some("client1"))
            .unwrap();
        assert!(!claims.extra.contains_key("cnf"));
    }

    /// Regression test for #223: `client_credentials` must reject a
    /// requested `audience` that isn't in `client.allowed_audiences`, using
    /// the same `invalid_target` error shape as
    /// `default_handle_token_exchange`'s equivalent check.
    #[tokio::test]
    async fn test_client_credentials_rejects_disallowed_audience() {
        let mut store =
            client_credentials_store_with_audiences("client1", vec!["serviceA".to_string()]).await;

        let res = handle_token(
            client_credentials_request_with_audience("client1", Some("serviceB")),
            None,
            &test_config(false),
            &mut store,
            &test_tokens(),
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.error, "invalid_target");
    }

    /// Regression test for #223: an audience that IS in
    /// `client.allowed_audiences` must be honored and land in the issued
    /// token's `aud` claim, instead of always being overwritten with the
    /// caller's own `client_id`.
    #[tokio::test]
    async fn test_client_credentials_allowed_audience_lands_in_aud() {
        let mut store =
            client_credentials_store_with_audiences("client1", vec!["serviceA".to_string()]).await;

        let tokens = test_tokens();
        let res = handle_token(
            client_credentials_request_with_audience("client1", Some("serviceA")),
            None,
            &test_config(false),
            &mut store,
            &tokens,
        )
        .await;
        let resp = res.unwrap();
        let claims = tokens.validate_token(&resp.access_token, None).unwrap();
        assert!(claims
            .aud
            .as_ref()
            .is_some_and(|aud| aud.contains("serviceA")));
    }

    /// #223 and #224 land in the same statement in `handle_client_credentials`
    /// and were merged by hand rather than by git's automatic resolution —
    /// this test is the reason: a request carrying BOTH a requested
    /// `audience` and a presented client certificate must get a token with
    /// the requested `aud` AND a `cnf.x5t#S256` claim. Before the merge was
    /// fixed, whichever side's PR happened to win the conflict would compile
    /// fine while silently dropping the other feature.
    #[tokio::test]
    async fn test_client_credentials_stamps_cnf_and_honors_audience_together() {
        let mut store =
            client_credentials_store_with_audiences("client1", vec!["serviceA".to_string()]).await;

        let cert_der = b"a fake DER-encoded mTLS client certificate for testing";
        let expected_thumbprint =
            authkestra_engine::token::cert_binding::x5t_s256_thumbprint(cert_der);

        let tokens = test_tokens();
        let resp = handle_token_with_client_cert(
            client_credentials_request_with_audience("client1", Some("serviceA")),
            None,
            &test_config(false),
            &mut store,
            &tokens,
            Some(cert_der),
            None,
        )
        .await
        .expect("a request with both an allowed audience and a certificate should succeed");

        let claims = tokens.validate_token(&resp.access_token, None).unwrap();
        assert!(
            claims
                .aud
                .as_ref()
                .is_some_and(|aud| aud.contains("serviceA")),
            "the requested audience must still land in aud when a certificate is also presented"
        );
        let cnf = claims
            .extra
            .get("cnf")
            .expect("a certificate was presented; the token must still carry a cnf claim");
        assert_eq!(
            cnf.get("x5t#S256").and_then(|v| v.as_str()),
            Some(expected_thumbprint.as_str()),
            "cnf.x5t#S256 must still be stamped when an audience is also requested"
        );
    }

    #[tokio::test]
    async fn test_refresh_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::RefreshToken],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt1".to_string(),
                "client1".to_string(),
                test_identity(),
                "openid".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: Some("rt1".to_string()),
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert!(res.is_ok());
        let resp = res.unwrap();
        assert!(resp.refresh_token.is_some());
        // Read via the serialized wire shape, not the Rust field directly,
        // so this assertion compiles unmodified: `issued_token_type` is
        // RFC 8693 §2.2.1's requirement for the token-exchange grant only —
        // refresh_token must keep an identical response shape.
        let value = serde_json::to_value(&resp).unwrap();
        assert!(value.get("issued_token_type").is_none());
    }

    // --- OpStore::handle_refresh_token override seam (issue #189) ---

    /// A minimal `OpStore` wrapper that delegates every method to an inner
    /// `OpStore` except `handle_refresh_token`, which it overrides with a
    /// canned response. Proves the override actually reaches the dispatch
    /// site in `handle_token`, not just that the trait compiles.
    struct OverridingRefreshStore<Inner> {
        inner: Inner,
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::client::ClientStore for OverridingRefreshStore<Inner> {
        async fn find_client(
            &mut self,
            client_id: &str,
        ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError> {
            self.inner.find_client(client_id).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::code::AuthorizationCodeStore for OverridingRefreshStore<Inner> {
        async fn store_code(
            &mut self,
            code: AuthorizationCode,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_code(code).await
        }

        async fn consume_code(
            &mut self,
            code: &str,
        ) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
            self.inner.consume_code(code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> RefreshTokenStore for OverridingRefreshStore<Inner> {
        async fn store_token(
            &mut self,
            token: RefreshToken,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_token(token).await
        }

        async fn get_token(
            &mut self,
            token: &str,
        ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            self.inner.get_token(token).await
        }

        async fn revoke_token(
            &mut self,
            token: &str,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.revoke_token(token).await
        }

        async fn consume_token(
            &mut self,
            token: &str,
        ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            self.inner.consume_token(token).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::device::DeviceCodeStore for OverridingRefreshStore<Inner> {
        async fn store_device_code(
            &mut self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_device_code(session).await
        }

        async fn get_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.get_device_code(device_code).await
        }

        async fn get_by_user_code(
            &mut self,
            user_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.get_by_user_code(user_code).await
        }

        async fn update_device_code(
            &mut self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.update_device_code(session).await
        }

        async fn delete_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.delete_device_code(device_code).await
        }

        async fn consume_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.consume_device_code(device_code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> OpStore for OverridingRefreshStore<Inner> {
        async fn handle_refresh_token(
            &mut self,
            _req: TokenRequest,
            _client_id: String,
            _client: ClientRegistration,
            _config: &OpConfig,
            _tokens: &TokenManager,
        ) -> Result<TokenResponse, TokenErrorResponse> {
            Ok(TokenResponse {
                access_token: "overridden-access-token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 42,
                id_token: Some("overridden-id-token".to_string()),
                refresh_token: Some("overridden-refresh-token".to_string()),
                scope: Some("overridden-scope".to_string()),
                issued_token_type: None,
            })
        }
    }

    /// authkestra#278 made narrowing a client's registered `scopes` the way
    /// to revoke a scope. A refresh token issued before the narrowing must
    /// not keep minting access tokens for the removed scope.
    #[tokio::test]
    async fn test_refresh_token_rejects_a_scope_the_client_lost() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        let mut narrowed = refresh_test_client();
        // The operator has since revoked `profile`.
        narrowed.scopes = vec!["openid".to_string()];
        clients
            .set(
                "client1",
                narrowed,
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-narrowed".to_string(),
                "client1".to_string(),
                test_identity(),
                "openid profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-narrowed"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        let err = res.expect_err("a revoked scope must not be renewable");
        assert_eq!(err.error, "invalid_scope");
        assert!(
            err.error_description.contains("profile"),
            "the error must name the offending scope, not just the class: {}",
            err.error_description
        );
    }

    /// The placement half of the fix, and the reason the check sits against
    /// the non-destructive `candidate` rather than after `consume_token`:
    /// a request that is refused must not destroy the token it had no right
    /// to consume (authkestra#287). Moving the check below `consume_token`
    /// passes the test above and fails this one.
    #[tokio::test]
    async fn test_refresh_token_scope_rejection_does_not_consume_the_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        let mut narrowed = refresh_test_client();
        narrowed.scopes = vec!["openid".to_string()];
        clients
            .set(
                "client1",
                narrowed.clone(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-survives".to_string(),
                "client1".to_string(),
                test_identity(),
                "openid profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let mut store = crate::store::CompositeOpStore::new(
            clients.clone(),
            authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
            refresh.clone(),
            authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
        );

        let err = handle_token(
            refresh_test_req("rt-survives"),
            None,
            &test_config(false),
            &mut store,
            &test_tokens(),
        )
        .await
        .expect_err("must be refused");
        assert_eq!(err.error, "invalid_scope");

        // The refused request must have left the token intact.
        assert!(
            crate::refresh::RefreshTokenStore::get_token(&mut refresh, "rt-survives")
                .await
                .unwrap()
                .is_some(),
            "a refused request must not consume the refresh token"
        );

        // And once the operator restores the scope, the very same token
        // still works — proving the rejection was non-destructive rather
        // than merely leaving a row behind.
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let ok = handle_token(
            refresh_test_req("rt-survives"),
            None,
            &test_config(false),
            &mut store,
            &test_tokens(),
        )
        .await;
        assert!(
            ok.is_ok(),
            "the same token must still be redeemable after the scope is restored"
        );
    }

    fn refresh_test_client() -> ClientRegistration {
        ClientRegistration {
            client_id: "client1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![GrantType::RefreshToken],
            // Registered for the scopes these fixtures' refresh tokens
            // carry. Previously `vec![]`, which authkestra#278 made
            // self-contradictory: a client registered for no scopes can no
            // longer obtain a scoped token in the first place, so the
            // fixture described a state the OP cannot produce.
            scopes: vec!["openid".to_string(), "profile".to_string()],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        }
    }

    fn refresh_test_req(refresh_token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: Some(refresh_token.to_string()),
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        }
    }

    #[tokio::test]
    async fn test_refresh_without_issuer_preserves_the_refresh_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh = authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-no-issuer".to_string(),
                "client1".to_string(),
                test_identity(),
                "profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let mut store = crate::store::CompositeOpStore::new(
            clients,
            authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
            refresh,
            authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
        );
        let error = default_handle_refresh_token(
            refresh_test_req("rt-no-issuer"),
            "client1".to_string(),
            refresh_test_client(),
            &test_config(false),
            &mut store,
            &TokenManager::new(b"test-secret", None),
        )
        .await
        .expect_err("issuance requires an issuer");

        assert_eq!(error.error, "server_error");
        assert!(store.get_token("rt-no-issuer").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_refresh_token_is_overridable_by_op_store() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut store =
            OverridingRefreshStore {
                inner:
                    crate::store::CompositeOpStore::new(
                        clients,
                        authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                        authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                        authkestra_engine::store::memory::MemoryStore::<
                            crate::device::DeviceCodeSession,
                        >::new(),
                    ),
            };

        // Deliberately a token no store has ever issued: if dispatch fell
        // through to the built-in handler instead of the override, this
        // would fail closed with `invalid_grant`, not succeed.
        let req = refresh_test_req("no-such-token");

        let res = handle_token(req, None, &test_config(false), &mut store, &test_tokens()).await;

        let resp =
            res.expect("the override should have been invoked instead of the built-in handler");
        assert_eq!(resp.access_token, "overridden-access-token");
        assert_eq!(resp.id_token.as_deref(), Some("overridden-id-token"));
        assert_eq!(
            resp.refresh_token.as_deref(),
            Some("overridden-refresh-token")
        );
    }

    #[tokio::test]
    async fn test_refresh_token_default_behavior_is_unchanged_without_override() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        // Non-openid scope: the built-in handler's `id_token: None` is a
        // fixed point here regardless of whether a later change teaches it
        // to issue one for the `openid` scope.
        refresh
            .store_token(RefreshToken::new(
                "rt-default".to_string(),
                "client1".to_string(),
                test_identity(),
                "profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        // A store that does NOT override `handle_refresh_token` — this is
        // the compatibility guarantee: it must behave identically to before
        // the trait method existed.
        let res = handle_token(
            refresh_test_req("rt-default"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(resp.scope.as_deref(), Some("profile"));
        assert_eq!(resp.id_token, None);
        assert_ne!(resp.refresh_token.as_deref(), Some("rt-default"));
        // The old refresh token was consumed (single-use rotation).
        assert!(refresh.get_token("rt-default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_unknown_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("does-not-exist"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_expired_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        // `store_token` derives the underlying KV TTL from `expires_at`, so
        // an already-past `expires_at` would get evicted at the storage
        // layer before the handler's own expiry check ever runs. Write
        // through `set` directly with a real TTL so the token is still
        // present, and the handler's `Utc::now() > expires_at` check
        // (`handlers/token.rs`, `default_handle_refresh_token`) is what
        // rejects it.
        refresh
            .set(
                "rt-expired",
                RefreshToken::new(
                    "rt-expired".to_string(),
                    "client1".to_string(),
                    test_identity(),
                    "profile".to_string(),
                    Utc::now() - Duration::minutes(1),
                    None,
                ),
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-expired"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        let err = res.unwrap_err();
        assert_eq!(err.error, "invalid_grant");
        assert_eq!(err.error_description, "Refresh token expired");
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_replay_of_a_rotated_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-once".to_string(),
                "client1".to_string(),
                test_identity(),
                "profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let mut store = crate::store::CompositeOpStore::new(
            clients,
            authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
            refresh,
            authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
        );
        let tokens = test_tokens();

        let first = handle_token(
            refresh_test_req("rt-once"),
            None,
            &test_config(false),
            &mut store,
            &tokens,
        )
        .await;
        assert!(first.is_ok());

        // Replaying the now-rotated token must fail, not succeed a second
        // time.
        let second = handle_token(
            refresh_test_req("rt-once"),
            None,
            &test_config(false),
            &mut store,
            &tokens,
        )
        .await;
        assert_eq!(second.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_issues_id_token_when_openid_scope_present() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-openid".to_string(),
                "client1".to_string(),
                test_identity(),
                "openid profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-openid"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert!(
            resp.id_token.is_some(),
            "openid scope should get a refreshed id_token"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_omits_id_token_without_openid_scope() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-no-openid".to_string(),
                "client1".to_string(),
                test_identity(),
                "profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-no-openid"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(
            resp.id_token, None,
            "no openid scope should mean no id_token, same as before this feature existed"
        );
    }

    // --- `acr`/`amr` ID token claims ---
    //
    // `Engine::authenticate` stamps `IDENTITY_ATTR_AMR` (and, when this
    // engine's step-up tier is satisfied,
    // `IDENTITY_ATTR_STEP_UP_SATISFIED`) onto `Identity::attributes`; these
    // exercise the other end, `crate::amr_acr::amr_acr_extra_claims`, through
    // an actual issued ID token rather than just the unit tests in
    // `amr_acr`. The refresh-token grant is used as the vehicle since it's
    // the simplest of the four `issue_id_token_with_extra` call sites to
    // stand a fixture up for; all four share the same helper, so this
    // exercises them equally.

    /// An identity carrying the `attributes` `Engine::authenticate` would
    /// have stamped for a given login outcome.
    fn identity_with_amr(amr: &str, step_up_satisfied: bool) -> Identity {
        let mut attributes = HashMap::new();
        attributes.insert(
            authkestra_engine::auth::state::IDENTITY_ATTR_AMR.to_string(),
            amr.to_string(),
        );
        if step_up_satisfied {
            attributes.insert(
                authkestra_engine::auth::state::IDENTITY_ATTR_STEP_UP_SATISFIED.to_string(),
                "true".to_string(),
            );
        }
        Identity {
            provider_id: "test".to_string(),
            external_id: "user123".to_string(),
            username: Some("user123".to_string()),
            email: None,
            attributes,
        }
    }

    /// Issues a refresh-token-grant ID token for `identity` and returns its
    /// decoded claims, so a test can inspect `extra["amr"]`/`extra["acr"]`.
    async fn id_token_claims_for(identity: Identity) -> authkestra_engine::token::Claims {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken::new(
                "rt-amr".to_string(),
                "client1".to_string(),
                identity,
                "openid profile".to_string(),
                Utc::now() + Duration::days(1),
                None,
            ))
            .await
            .unwrap();

        let tokens = test_tokens();
        let res = handle_token(
            refresh_test_req("rt-amr"),
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens,
        )
        .await
        .unwrap();

        let id_token = res
            .id_token
            .expect("openid scope requested, id_token expected");
        tokens
            .validate_token(&id_token, None)
            .expect("issued id_token should validate against the issuer's own key")
    }

    #[tokio::test]
    async fn primary_only_identity_gets_single_factor_acr_and_no_mfa_marker() {
        let claims = id_token_claims_for(identity_with_amr("password", false)).await;

        assert_eq!(claims.extra.get("amr"), Some(&serde_json::json!(["pwd"])));
        assert_eq!(
            claims.extra.get("acr"),
            Some(&serde_json::json!(crate::amr_acr::ACR_SINGLE_FACTOR))
        );
    }

    #[tokio::test]
    async fn step_up_identity_gets_mfa_acr_and_both_methods_plus_marker() {
        let claims = id_token_claims_for(identity_with_amr("password totp", true)).await;

        assert_eq!(
            claims.extra.get("amr"),
            Some(&serde_json::json!(["pwd", "otp", "totp", "mfa"]))
        );
        assert_eq!(
            claims.extra.get("acr"),
            Some(&serde_json::json!(crate::amr_acr::ACR_MFA))
        );
    }

    /// `auth_time` has to survive the round-trip into a real issued token,
    /// not just the unit tests: it is the value a relying party compares
    /// against `max_age`, and the refresh-token grant used here is exactly
    /// the case where it must report the *original* authentication rather
    /// than when this later token was minted.
    #[tokio::test]
    async fn auth_time_survives_into_an_issued_token_unchanged() {
        let authenticated_at = 1_757_843_000_i64;
        let mut identity = identity_with_amr("password", false);
        identity.attributes.insert(
            authkestra_engine::auth::state::IDENTITY_ATTR_AUTH_TIME.to_string(),
            authenticated_at.to_string(),
        );

        let claims = id_token_claims_for(identity).await;

        assert_eq!(
            claims.extra.get("auth_time"),
            Some(&serde_json::json!(authenticated_at)),
            "auth_time must report when the user authenticated, not when this \
             refreshed token was issued"
        );
        assert!(
            (claims.iat as i64) > authenticated_at,
            "the fixture is only meaningful if iat and auth_time actually differ"
        );
    }

    /// The two outcomes above must actually differ — pinning that directly
    /// guards against a regression that makes both branches converge (e.g.
    /// `step_up_satisfied` silently defaulting to the same value either
    /// way) even if each assertion above still individually passed.
    #[tokio::test]
    async fn primary_only_and_step_up_ids_are_visibly_different() {
        let single = id_token_claims_for(identity_with_amr("password", false)).await;
        let stepped_up = id_token_claims_for(identity_with_amr("password totp", true)).await;

        assert_ne!(single.extra.get("amr"), stepped_up.extra.get("amr"));
        assert_ne!(single.extra.get("acr"), stepped_up.extra.get("acr"));
    }

    #[tokio::test]
    async fn an_identity_with_no_amr_attribute_gets_neither_claim() {
        // `test_identity()` carries empty `attributes` — the shape of an
        // `Identity` that never passed through `Engine::authenticate` (e.g.
        // a federated login handed straight to `handle_authorize`).
        let claims = id_token_claims_for(test_identity()).await;

        assert!(!claims.extra.contains_key("amr"));
        assert!(!claims.extra.contains_key("acr"));
    }

    // --- OpStore::handle_token_exchange override seam (issue #204) ---

    /// A minimal `OpStore` wrapper that delegates every method to an inner
    /// `OpStore` except `handle_token_exchange`, which it overrides with a
    /// canned response. Proves the override actually reaches the dispatch
    /// site in `handle_token`, not just that the trait compiles.
    struct OverridingTokenExchangeStore<Inner> {
        inner: Inner,
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::client::ClientStore for OverridingTokenExchangeStore<Inner> {
        async fn find_client(
            &mut self,
            client_id: &str,
        ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError> {
            self.inner.find_client(client_id).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::code::AuthorizationCodeStore for OverridingTokenExchangeStore<Inner> {
        async fn store_code(
            &mut self,
            code: AuthorizationCode,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_code(code).await
        }

        async fn consume_code(
            &mut self,
            code: &str,
        ) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
            self.inner.consume_code(code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> RefreshTokenStore for OverridingTokenExchangeStore<Inner> {
        async fn store_token(
            &mut self,
            token: RefreshToken,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_token(token).await
        }

        async fn get_token(
            &mut self,
            token: &str,
        ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            self.inner.get_token(token).await
        }

        async fn revoke_token(
            &mut self,
            token: &str,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.revoke_token(token).await
        }

        async fn consume_token(
            &mut self,
            token: &str,
        ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            self.inner.consume_token(token).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::device::DeviceCodeStore for OverridingTokenExchangeStore<Inner> {
        async fn store_device_code(
            &mut self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.store_device_code(session).await
        }

        async fn get_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.get_device_code(device_code).await
        }

        async fn get_by_user_code(
            &mut self,
            user_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.get_by_user_code(user_code).await
        }

        async fn update_device_code(
            &mut self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.update_device_code(session).await
        }

        async fn delete_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<(), authkestra_engine::store::StoreError> {
            self.inner.delete_device_code(device_code).await
        }

        async fn consume_device_code(
            &mut self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
        {
            self.inner.consume_device_code(device_code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> OpStore for OverridingTokenExchangeStore<Inner> {
        async fn handle_token_exchange(
            &mut self,
            _req: TokenRequest,
            _client_id: String,
            _client: ClientRegistration,
            _config: &OpConfig,
            _tokens: &TokenManager,
        ) -> Result<TokenResponse, TokenErrorResponse> {
            Ok(TokenResponse {
                access_token: "overridden-tx-access-token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 42,
                id_token: Some("overridden-tx-id-token".to_string()),
                refresh_token: None,
                scope: Some("overridden-scope".to_string()),
                issued_token_type: None,
            })
        }
    }

    #[tokio::test]
    async fn test_token_exchange_is_overridable_by_op_store() {
        let tokens = test_tokens();
        // A subject_token this store's dispatch would reject outright if it
        // ever reached the built-in handler (feature disabled below): if
        // dispatch fell through to `default_handle_token_exchange` instead
        // of the override, this would fail closed with
        // `unsupported_grant_type`, not succeed.
        let subject_token = issue_subject_token(&tokens, "client1", None);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let mut store =
            OverridingTokenExchangeStore {
                inner:
                    crate::store::CompositeOpStore::new(
                        clients,
                        authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                        authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                        authkestra_engine::store::memory::MemoryStore::<
                            crate::device::DeviceCodeSession,
                        >::new(),
                    ),
            };

        let res = handle_token(
            default_tx_req(&subject_token),
            None,
            // Token exchange disabled globally: the built-in handler would
            // refuse with `unsupported_grant_type` before doing anything
            // else, so a success proves the override intercepted the call
            // before that built-in check ever ran.
            &test_config(false),
            &mut store,
            &tokens,
        )
        .await;

        let resp =
            res.expect("the override should have been invoked instead of the built-in handler");
        assert_eq!(resp.access_token, "overridden-tx-access-token");
        assert_eq!(resp.id_token.as_deref(), Some("overridden-tx-id-token"));
        assert_eq!(resp.scope.as_deref(), Some("overridden-scope"));
    }

    #[tokio::test]
    async fn test_token_exchange_default_behavior_is_unchanged_without_override() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        // A store that does NOT override `handle_token_exchange` — this is
        // the compatibility guarantee: it must behave identically to before
        // the trait method existed.
        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(resp.scope.as_deref(), Some("profile"));
        assert_eq!(resp.id_token, None);
        assert_eq!(resp.refresh_token, None);
    }

    #[tokio::test]
    async fn test_tx_issued_token_type_present_and_correct() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        let resp = res.unwrap();
        // Read via the serialized wire shape rather than the Rust field
        // directly, so this test compiles unmodified: RFC 8693 §2.2.1 makes
        // `issued_token_type` a REQUIRED response parameter on a
        // token-exchange grant response, and its absence on the wire is
        // exactly the gap this test guards against.
        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            value.get("issued_token_type").and_then(|v| v.as_str()),
            Some("urn:ietf:params:oauth:token-type:access_token"),
        );
    }

    // --- Token Exchange DoD Tests ---

    fn default_tx_req(subject_token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            device_code: None,
            subject_token: Some(subject_token.to_string()),
            subject_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        }
    }

    #[tokio::test]
    async fn test_tx_cross_client_rejection() {
        let tokens = test_tokens();
        // Issued to 'client2'
        let subject_token = issue_subject_token(&tokens, "client2", None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    /// #206: a subject token whose `aud` is a JSON array must exchange
    /// successfully when the requesting client_id is *any one* of the
    /// listed audiences, not just when it's the sole audience.
    #[tokio::test]
    async fn test_tx_multi_audience_subject_token_allowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token_multi_aud(&["client1", "client2"], None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert!(
            res.is_ok(),
            "client1 is a member of the array aud, exchange should succeed: {res:?}"
        );
    }

    /// #206 companion: when the requesting client_id is absent from the
    /// subject token's array `aud`, exchange must still be rejected —
    /// membership, not mere array-shape acceptance, is the check.
    #[tokio::test]
    async fn test_tx_multi_audience_subject_token_disallowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token_multi_aud(&["client2", "client3"], None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_tx_scope_escalation_narrow() {
        let tokens = test_tokens();
        let subject_token =
            issue_subject_token(&tokens, "client1", Some("scopeA scopeB".to_string()));
        let mut req = default_tx_req(&subject_token);
        req.scope = Some("scopeA scopeC".to_string()); // requesting scopeC which token doesn't have

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["scopeA".to_string(), "scopeC".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        let res = res.unwrap();
        // Should only grant scopeA
        assert_eq!(res.scope.unwrap(), "scopeA");
    }

    #[tokio::test]
    async fn test_tx_zero_overlap_reject() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("scopeA".to_string()));
        let mut req = default_tx_req(&subject_token);
        req.scope = Some("scopeB".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["scopeB".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_scope");
    }

    #[tokio::test]
    async fn test_tx_feature_disabled() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_tx_actor_token_rejected() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.actor_token = Some("some_actor_token".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn test_tx_subject_token_type_invalid() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.subject_token_type = Some("urn:ietf:params:oauth:token-type:saml2".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn test_tx_requested_token_type_invalid() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.requested_token_type = Some("urn:ietf:params:oauth:token-type:saml2".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn test_tx_audience_allowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.audience = Some("serviceA".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec!["serviceA".to_string()],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert!(res.is_ok());
        let claim = tokens
            .validate_token(&res.unwrap().access_token, None)
            .unwrap();
        assert!(claim.aud.unwrap().contains("serviceA"));
    }

    #[tokio::test]
    async fn test_tx_audience_disallowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.audience = Some("serviceB".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec!["serviceA".to_string()],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_target");
    }

    #[tokio::test]
    async fn test_tx_default_audience() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let req = default_tx_req(&subject_token);
        // No audience requested

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert!(res.is_ok());
        let claim = tokens
            .validate_token(&res.unwrap().access_token, None)
            .unwrap();
        // default aud should be config.issuer
        assert!(claim.aud.unwrap().contains("https://auth.example.com"));
    }

    #[tokio::test]
    async fn test_tx_missing_identity_reject() {
        let tokens = test_tokens();
        // Issue token WITHOUT identity (using raw token creation or simulating it)
        // Since test_tokens().issue_user_token always embeds identity, we just simulate by passing a token with valid signature but no identity
        // Actually, we can just use `issue_client_token` which creates a token with no `identity` claim!
        let subject_token = tokens
            .issue_client_token("client2", 3600, None, Some("client1".to_string()))
            .unwrap();
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_tx_issues_id_token_when_openid_scope_granted() {
        let tokens = test_tokens();
        let subject_token =
            issue_subject_token(&tokens, "client1", Some("openid profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["openid".to_string(), "profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;

        let resp = res.unwrap();
        assert!(
            resp.id_token.is_some(),
            "openid scope should get an id_token from the token-exchange grant, mirroring \
             default_handle_authorization_code and default_handle_refresh_token"
        );
    }

    #[tokio::test]
    async fn test_tx_omits_id_token_without_openid_scope() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(
            resp.id_token, None,
            "no openid scope should mean no id_token, same as before this feature existed"
        );
    }

    #[tokio::test]
    async fn test_tx_requested_token_type_id_token_accepted() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("openid".to_string()));
        let mut req = default_tx_req(&subject_token);
        req.requested_token_type = Some("urn:ietf:params:oauth:token-type:id_token".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;

        assert!(
            res.is_ok(),
            "requested_token_type: id_token must be accepted per RFC 8693 §2.1, got {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_custom_grant_fallback() {
        let tokens = test_tokens();
        let req = TokenRequest {
            grant_type: "urn:custom:grant".to_string(),
            code: None,
            device_code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::Custom("urn:custom:grant".to_string())],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        // With the default implementation, custom grants should return unsupported_grant_type
        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        assert_eq!(res.unwrap_err().error, "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_custom_grant_unauthorized() {
        let tokens = test_tokens();
        let req = TokenRequest {
            grant_type: "urn:custom:grant".to_string(),
            code: None,
            device_code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
            dpop_jkt: None,
        };

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    // Crucially, this client is NOT authorized for the custom grant type
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &mut crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        let err = res.unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
    }

    // --- DPoP (RFC 9449) proof wiring — authkestra#274 Phase B ---

    mod dpop_wiring_tests {
        use super::*;
        use crate::dpop::DpopJtiRecord;
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};

        fn b64(bytes: &[u8]) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        }
        fn b64_json(v: &serde_json::Value) -> String {
            b64(serde_json::to_vec(v).unwrap().as_slice())
        }

        /// Builds a real, genuinely Ed25519-signed DPoP proof for the OP's
        /// token endpoint. Mirrors `authkestra_engine::token::dpop`'s own
        /// `ProofBuilder` test helper, which is private to that crate's test
        /// module and so re-authored here rather than shared.
        struct DpopProofBuilder {
            signing_key: SigningKey,
            htu: String,
            jti: String,
        }

        impl DpopProofBuilder {
            fn new(htu: &str, jti: &str) -> Self {
                Self::with_key_seed(9, htu, jti)
            }

            /// As [`Self::new`], but lets the caller pick which fixed key
            /// this proof is signed with — needed by tests that must prove
            /// two proofs are bound to the *same* key (reuse a seed) or
            /// deliberately different ones (use distinct seeds).
            fn with_key_seed(seed: u8, htu: &str, jti: &str) -> Self {
                Self {
                    signing_key: SigningKey::from_bytes(&[seed; 32]),
                    htu: htu.to_string(),
                    jti: jti.to_string(),
                }
            }

            fn jwk(&self) -> serde_json::Value {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": b64(self.signing_key.verifying_key().as_bytes()),
                })
            }

            fn expected_jkt(&self) -> String {
                authkestra_engine::token::dpop::compute_jwk_thumbprint(
                    &serde_json::from_value(self.jwk()).unwrap(),
                )
                .unwrap()
            }

            fn build(&self) -> String {
                let header = serde_json::json!({
                    "typ": "dpop+jwt",
                    "alg": "EdDSA",
                    "jwk": self.jwk(),
                });
                let payload = serde_json::json!({
                    "htm": "POST",
                    "htu": self.htu,
                    "iat": chrono::Utc::now().timestamp(),
                    "jti": self.jti,
                });
                let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
                let signature = self.signing_key.sign(signing_input.as_bytes());
                format!("{signing_input}.{}", b64(&signature.to_bytes()))
            }
        }

        /// As [`client_credentials_store`], but with a real `DpopReplayStore`
        /// wired via `with_dpop_replay_store` instead of the fail-closed
        /// `NoDpopReplayStore` default — needed by every test in this module
        /// that expects a presented proof to actually be accepted.
        async fn client_credentials_store_with_dpop_replay(
            client_id: &str,
        ) -> crate::store::CompositeOpStore<
            authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
            authkestra_engine::store::memory::MemoryStore<crate::code::AuthorizationCode>,
            authkestra_engine::store::memory::MemoryStore<crate::refresh::RefreshToken>,
            authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
            authkestra_engine::store::traits::NoClientAssertionStore,
            authkestra_engine::store::memory::MemoryStore<DpopJtiRecord>,
        > {
            client_credentials_store(client_id)
                .await
                .with_dpop_replay_store(authkestra_engine::store::memory::MemoryStore::<
                    DpopJtiRecord,
                >::new())
        }

        /// A valid DPoP proof on a `client_credentials` request must bind the
        /// issued token to the proof's key (`cnf.jkt`) and switch
        /// `token_type` to `"DPoP"`.
        #[tokio::test]
        async fn client_credentials_stamps_cnf_jkt_and_dpop_token_type() {
            let mut store = client_credentials_store_with_dpop_replay("client1").await;
            let tokens = test_tokens();
            let proof_builder = DpopProofBuilder::new("https://auth.example.com/token", "jti-1");
            let proof = proof_builder.build();

            let resp = handle_token_with_client_cert(
                client_credentials_request("client1"),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect("a valid, fresh DPoP proof must be accepted");

            assert_eq!(resp.token_type, "DPoP");

            let claims = tokens
                .validate_token(&resp.access_token, Some("client1"))
                .expect("issued token must validate");
            let cnf = claims
                .extra
                .get("cnf")
                .expect("a DPoP proof was presented; the token must carry a cnf claim");
            assert_eq!(
                cnf.get("jkt").and_then(|v| v.as_str()),
                Some(proof_builder.expected_jkt().as_str()),
            );
        }

        /// Companion regression: no `DPoP` header at all keeps issuing a
        /// plain bearer token, exactly like before Phase B — proves the
        /// feature is additive.
        #[tokio::test]
        async fn client_credentials_without_dpop_header_stays_bearer() {
            let mut store = client_credentials_store_with_dpop_replay("client1").await;
            let tokens = test_tokens();

            let resp = handle_token_with_client_cert(
                client_credentials_request("client1"),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                None,
            )
            .await
            .unwrap();

            assert_eq!(resp.token_type, "Bearer");
            let claims = tokens
                .validate_token(&resp.access_token, Some("client1"))
                .unwrap();
            assert!(!claims.extra.contains_key("cnf"));
        }

        /// RFC 9449 §11.1: a replayed `jti` must be rejected, not silently
        /// accepted a second time.
        #[tokio::test]
        async fn a_replayed_dpop_proof_jti_is_rejected() {
            let mut store = client_credentials_store_with_dpop_replay("client1").await;
            let tokens = test_tokens();
            let proof =
                DpopProofBuilder::new("https://auth.example.com/token", "jti-replay").build();

            handle_token_with_client_cert(
                client_credentials_request("client1"),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect("first presentation of a fresh proof must succeed");

            let err = handle_token_with_client_cert(
                client_credentials_request("client1"),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect_err("replaying the same proof's jti must be rejected");

            assert_eq!(err.error, "invalid_dpop_proof");
        }

        /// A deployment that has not wired a `DpopReplayStore` (the
        /// `NoDpopReplayStore` default) must fail closed rather than accept
        /// a proof it cannot guarantee is single-use.
        #[tokio::test]
        async fn no_dpop_replay_store_wired_fails_closed() {
            // Deliberately the plain `client_credentials_store`, not the
            // `_with_dpop_replay` variant — this store's `P` generic
            // parameter defaults to `NoDpopReplayStore`.
            let mut store = client_credentials_store("client1").await;
            let tokens = test_tokens();
            let proof = DpopProofBuilder::new("https://auth.example.com/token", "jti-1").build();

            let err = handle_token_with_client_cert(
                client_credentials_request("client1"),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect_err("no replay store is wired; the proof must be refused");

            assert_eq!(err.error, "invalid_dpop_proof");
        }

        /// A proof whose `htu` doesn't match the token endpoint must be
        /// rejected — proves `expected_htu` is actually threaded from
        /// `config.token_endpoint()`, not hardcoded or ignored.
        #[tokio::test]
        async fn a_proof_for_the_wrong_endpoint_is_rejected() {
            let mut store = client_credentials_store_with_dpop_replay("client1").await;
            let tokens = test_tokens();
            let proof =
                DpopProofBuilder::new("https://not-this-server.example.com/token", "jti-1").build();

            let err = handle_token_with_client_cert(
                client_credentials_request("client1"),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect_err("a proof bound to a different htu must be refused");

            assert_eq!(err.error, "invalid_dpop_proof");
        }

        /// The `authorization_code` grant must also stamp `cnf.jkt` /
        /// `token_type: "DPoP"` — proves the wiring generalizes past
        /// `client_credentials` (the only grant with pre-existing `extra`
        /// claims machinery) to the other four grant handlers that had none.
        #[tokio::test]
        #[allow(deprecated)] // `require_pkce` (authkestra#273) — superseded by mandatory PKCE
        async fn authorization_code_stamps_cnf_jkt_and_dpop_token_type() {
            let clients = authkestra_engine::store::memory::MemoryStore::<
                crate::client::ClientRegistration,
            >::new();
            clients
                .set(
                    "client1",
                    ClientRegistration {
                        client_id: "client1".to_string(),
                        client_secret_hash: None,
                        redirect_uris: vec!["https://cb".to_string()],
                        grant_types: vec![GrantType::AuthorizationCode],
                        scopes: vec!["openid".to_string()],
                        require_pkce: true,
                        allowed_audiences: vec![],
                        token_endpoint_auth_method: None,
                        jwks: None,
                    },
                    std::time::Duration::from_secs(31536000),
                )
                .await
                .unwrap();

            let verifier = "test_verifier";
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, verifier.as_bytes());
            let challenge =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

            let mut codes = authkestra_engine::store::memory::MemoryStore::<
                crate::code::AuthorizationCode,
            >::new();
            codes
                .store_code({
                    let mut auth_code = AuthorizationCode::new(
                        "code1".to_string(),
                        "client1".to_string(),
                        "https://cb".to_string(),
                        "openid".to_string(),
                        test_identity(),
                        Utc::now() + Duration::minutes(5),
                        false,
                    );
                    auth_code.code_challenge = Some(challenge);
                    auth_code.code_challenge_method = Some("S256".to_string());
                    auth_code
                })
                .await
                .unwrap();

            let mut store = crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
                ),
            )
            .with_dpop_replay_store(authkestra_engine::store::memory::MemoryStore::<
                DpopJtiRecord,
            >::new());

            let tokens = test_tokens();
            let proof_builder = DpopProofBuilder::new("https://auth.example.com/token", "jti-ac-1");
            let proof = proof_builder.build();

            let req = TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("code1".to_string()),
                redirect_uri: Some("https://cb".to_string()),
                client_id: Some("client1".to_string()),
                client_secret: None,
                code_verifier: Some(verifier.to_string()),
                scope: None,
                refresh_token: None,
                subject_token: None,
                subject_token_type: None,
                device_code: None,
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                audience: None,
                client_assertion: None,
                client_assertion_type: None,
                dpop_jkt: None,
            };

            let resp = handle_token_with_client_cert(
                req,
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect("a valid DPoP proof must be accepted on the authorization_code grant");

            assert_eq!(resp.token_type, "DPoP");
            let claims = tokens
                .validate_token(&resp.access_token, Some("client1"))
                .unwrap();
            assert_eq!(
                claims
                    .extra
                    .get("cnf")
                    .and_then(|c| c.get("jkt"))
                    .and_then(|v| v.as_str()),
                Some(proof_builder.expected_jkt().as_str()),
            );
        }

        // --- Refresh token DPoP key continuity (RFC 9449 §5) ---

        /// Registers a client authorized for `authorization_code` +
        /// `refresh_token` with `offline_access` allowed, and stores one
        /// ready-to-redeem PKCE-protected authorization code for it. Every
        /// continuity test below starts from this same fixture, then
        /// exercises a different combination of DPoP proofs across the
        /// initial grant and the subsequent refresh.
        async fn dpop_refresh_continuity_store() -> (
            crate::store::CompositeOpStore<
                authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
                authkestra_engine::store::memory::MemoryStore<crate::code::AuthorizationCode>,
                authkestra_engine::store::memory::MemoryStore<crate::refresh::RefreshToken>,
                authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
                authkestra_engine::store::traits::NoClientAssertionStore,
                authkestra_engine::store::memory::MemoryStore<DpopJtiRecord>,
            >,
            String,
        ) {
            let clients = authkestra_engine::store::memory::MemoryStore::<
                crate::client::ClientRegistration,
            >::new();
            clients
                .set(
                    "client1",
                    ClientRegistration {
                        client_id: "client1".to_string(),
                        client_secret_hash: None,
                        redirect_uris: vec!["https://cb".to_string()],
                        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                        scopes: vec!["openid".to_string(), "offline_access".to_string()],
                        require_pkce: true,
                        allowed_audiences: vec![],
                        token_endpoint_auth_method: None,
                        jwks: None,
                    },
                    std::time::Duration::from_secs(31536000),
                )
                .await
                .unwrap();

            let verifier = "test_verifier".to_string();
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, verifier.as_bytes());
            let challenge =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

            let mut codes = authkestra_engine::store::memory::MemoryStore::<
                crate::code::AuthorizationCode,
            >::new();
            codes
                .store_code({
                    let mut auth_code = AuthorizationCode::new(
                        "code1".to_string(),
                        "client1".to_string(),
                        "https://cb".to_string(),
                        "openid offline_access".to_string(),
                        test_identity(),
                        Utc::now() + Duration::minutes(5),
                        false,
                    );
                    auth_code.code_challenge = Some(challenge);
                    auth_code.code_challenge_method = Some("S256".to_string());
                    auth_code
                })
                .await
                .unwrap();

            let store = crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
                ),
            )
            .with_dpop_replay_store(authkestra_engine::store::memory::MemoryStore::<
                DpopJtiRecord,
            >::new());

            (store, verifier)
        }

        fn dpop_refresh_continuity_code_req(verifier: &str) -> TokenRequest {
            TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some("code1".to_string()),
                redirect_uri: Some("https://cb".to_string()),
                client_id: Some("client1".to_string()),
                client_secret: None,
                code_verifier: Some(verifier.to_string()),
                scope: None,
                refresh_token: None,
                subject_token: None,
                subject_token_type: None,
                device_code: None,
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                audience: None,
                client_assertion: None,
                client_assertion_type: None,
                dpop_jkt: None,
            }
        }

        fn dpop_refresh_continuity_refresh_req(refresh_token: &str) -> TokenRequest {
            TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: Some("client1".to_string()),
                client_secret: None,
                code_verifier: None,
                scope: None,
                refresh_token: Some(refresh_token.to_string()),
                subject_token: None,
                subject_token_type: None,
                device_code: None,
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                audience: None,
                client_assertion: None,
                client_assertion_type: None,
                dpop_jkt: None,
            }
        }

        /// A refresh token minted alongside a DPoP-bound access token must
        /// itself be bound: redeeming it with a fresh proof for the *same*
        /// key must succeed, keep binding the rotated access token to that
        /// key, and hand back a rotated refresh token that still carries
        /// the binding forward.
        #[tokio::test]
        #[allow(deprecated)]
        async fn refresh_token_rotation_succeeds_with_the_same_dpop_key() {
            let (mut store, verifier) = dpop_refresh_continuity_store().await;
            let tokens = test_tokens();

            let issue_proof =
                DpopProofBuilder::with_key_seed(11, "https://auth.example.com/token", "jti-issue");
            let issued = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&issue_proof.build()),
            )
            .await
            .expect("issuing the code grant with a DPoP proof must succeed");
            let refresh_token = issued
                .refresh_token
                .expect("offline_access must yield a refresh token");
            assert_eq!(issued.token_type, "DPoP");

            let rotate_proof = DpopProofBuilder::with_key_seed(
                11,
                "https://auth.example.com/token",
                "jti-rotate-same-key",
            );
            let rotated = handle_token_with_client_cert(
                dpop_refresh_continuity_refresh_req(&refresh_token),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&rotate_proof.build()),
            )
            .await
            .expect("rotating with a proof for the same key must succeed");

            assert_eq!(rotated.token_type, "DPoP");
            let claims = tokens
                .validate_token(&rotated.access_token, Some("client1"))
                .unwrap();
            assert_eq!(
                claims
                    .extra
                    .get("cnf")
                    .and_then(|c| c.get("jkt"))
                    .and_then(|v| v.as_str()),
                Some(issue_proof.expected_jkt().as_str()),
                "the rotated access token must stay bound to the refresh token's original key"
            );
        }

        /// RFC 9449 §5: redeeming a DPoP-bound refresh token with a proof
        /// for a *different* key must be refused — otherwise an exfiltrated
        /// refresh token could simply be re-keyed by whoever stole it.
        #[tokio::test]
        #[allow(deprecated)]
        async fn refresh_token_rotation_rejects_a_different_dpop_key() {
            let (mut store, verifier) = dpop_refresh_continuity_store().await;
            let tokens = test_tokens();

            let issue_proof = DpopProofBuilder::with_key_seed(
                11,
                "https://auth.example.com/token",
                "jti-issue-2",
            );
            let issued = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&issue_proof.build()),
            )
            .await
            .expect("issuing the code grant with a DPoP proof must succeed");
            let refresh_token = issued.refresh_token.unwrap();

            let attacker_proof = DpopProofBuilder::with_key_seed(
                22,
                "https://auth.example.com/token",
                "jti-rotate-wrong-key",
            );
            let err = handle_token_with_client_cert(
                dpop_refresh_continuity_refresh_req(&refresh_token),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&attacker_proof.build()),
            )
            .await
            .expect_err("a proof for a different key must be refused");

            assert_eq!(err.error, "invalid_dpop_proof");
        }

        /// RFC 9449 §5, the other half of the same requirement: omitting
        /// DPoP entirely on a bound refresh token must not silently fall
        /// back to issuing a plain bearer token.
        #[tokio::test]
        #[allow(deprecated)]
        async fn refresh_token_rotation_rejects_a_missing_dpop_proof() {
            let (mut store, verifier) = dpop_refresh_continuity_store().await;
            let tokens = test_tokens();

            let issue_proof = DpopProofBuilder::with_key_seed(
                11,
                "https://auth.example.com/token",
                "jti-issue-3",
            );
            let issued = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&issue_proof.build()),
            )
            .await
            .expect("issuing the code grant with a DPoP proof must succeed");
            let refresh_token = issued.refresh_token.unwrap();

            let err = handle_token_with_client_cert(
                dpop_refresh_continuity_refresh_req(&refresh_token),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                None,
            )
            .await
            .expect_err("omitting DPoP on a bound refresh token must be refused");

            assert_eq!(err.error, "invalid_dpop_proof");
        }

        /// A failed DPoP continuity check (wrong key, or no proof at all)
        /// must NOT consume the refresh token. Validation runs before
        /// `consume_token`, specifically so a request that has no right to
        /// redeem the token can't destroy it as a side effect of trying —
        /// otherwise a bare stolen token *string* (no key needed at all)
        /// would let an attacker permanently log the legitimate holder out
        /// with a single throwaway request, and a legitimate client behind
        /// a header-stripping proxy would lose its session irrecoverably
        /// the first time it forgot to attach DPoP. This proves the token
        /// survives a failed attempt and a correct retry still succeeds.
        #[tokio::test]
        #[allow(deprecated)]
        async fn refresh_token_survives_a_failed_dpop_attempt_and_a_correct_retry_still_succeeds() {
            let (mut store, verifier) = dpop_refresh_continuity_store().await;
            let tokens = test_tokens();

            let issue_proof = DpopProofBuilder::with_key_seed(
                11,
                "https://auth.example.com/token",
                "jti-issue-4",
            );
            let issued = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&issue_proof.build()),
            )
            .await
            .expect("issuing the code grant with a DPoP proof must succeed");
            let refresh_token = issued.refresh_token.unwrap();

            // First: an attacker holding only the token string, no key.
            let attacker_attempt = handle_token_with_client_cert(
                dpop_refresh_continuity_refresh_req(&refresh_token),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                None,
            )
            .await
            .expect_err("a missing proof must be refused");
            assert_eq!(attacker_attempt.error, "invalid_dpop_proof");

            // Then: the legitimate client, presenting the correct key,
            // using that exact same still-unconsumed refresh token.
            let retry_proof = DpopProofBuilder::with_key_seed(
                11,
                "https://auth.example.com/token",
                "jti-retry-after-failed-attempt",
            );
            let retried = handle_token_with_client_cert(
                dpop_refresh_continuity_refresh_req(&refresh_token),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&retry_proof.build()),
            )
            .await
            .expect("the refresh token must still be valid after a failed attempt by someone else");
            assert_eq!(retried.token_type, "DPoP");
        }

        /// Companion regression: a refresh token minted *without* DPoP
        /// (no proof presented on the original grant) stays an ordinary
        /// bearer token — rotating it with no DPoP header keeps working
        /// exactly as it did before this feature existed.
        #[tokio::test]
        #[allow(deprecated)]
        async fn refresh_token_rotation_without_prior_binding_is_unaffected() {
            let (mut store, verifier) = dpop_refresh_continuity_store().await;
            let tokens = test_tokens();

            let issued = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                None,
            )
            .await
            .expect("issuing the code grant with no DPoP proof must still succeed");
            assert_eq!(issued.token_type, "Bearer");
            let refresh_token = issued.refresh_token.unwrap();

            let rotated = handle_token_with_client_cert(
                dpop_refresh_continuity_refresh_req(&refresh_token),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                None,
            )
            .await
            .expect("rotating an unbound refresh token with no DPoP proof must still succeed");
            assert_eq!(rotated.token_type, "Bearer");
        }

        // --- Fail-closed guard against a backend that silently drops `jkt` ---

        /// Wraps any `OpStore` but strips `jkt` on every `store_token`
        /// call before delegating — simulating exactly what
        /// `authkestra-store-sqlx`'s `RefreshTokenStore` impl does today (accepts
        /// a DPoP-bound `RefreshToken`, reports success, never persists
        /// the binding). Everything else forwards unchanged, including
        /// `check_and_record_dpop_jti`, which must still reach the inner
        /// store's real replay guard for a DPoP proof to verify at all.
        struct JktDroppingRefreshStore<Inner> {
            inner: Inner,
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> crate::client::ClientStore for JktDroppingRefreshStore<Inner> {
            async fn find_client(
                &mut self,
                client_id: &str,
            ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError>
            {
                self.inner.find_client(client_id).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> crate::code::AuthorizationCodeStore for JktDroppingRefreshStore<Inner> {
            async fn store_code(
                &mut self,
                code: AuthorizationCode,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.store_code(code).await
            }

            async fn consume_code(
                &mut self,
                code: &str,
            ) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError>
            {
                self.inner.consume_code(code).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> RefreshTokenStore for JktDroppingRefreshStore<Inner> {
            async fn store_token(
                &mut self,
                token: RefreshToken,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                let mut stripped = token;
                stripped.jkt = None;
                self.inner.store_token(stripped).await
            }

            async fn get_token(
                &mut self,
                token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                self.inner.get_token(token).await
            }

            async fn revoke_token(
                &mut self,
                token: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.revoke_token(token).await
            }

            async fn consume_token(
                &mut self,
                token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                self.inner.consume_token(token).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> crate::device::DeviceCodeStore for JktDroppingRefreshStore<Inner> {
            async fn store_device_code(
                &mut self,
                session: crate::device::DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.store_device_code(session).await
            }

            async fn get_device_code(
                &mut self,
                device_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                self.inner.get_device_code(device_code).await
            }

            async fn get_by_user_code(
                &mut self,
                user_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                self.inner.get_by_user_code(user_code).await
            }

            async fn update_device_code(
                &mut self,
                session: crate::device::DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.update_device_code(session).await
            }

            async fn delete_device_code(
                &mut self,
                device_code: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.delete_device_code(device_code).await
            }

            async fn consume_device_code(
                &mut self,
                device_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                self.inner.consume_device_code(device_code).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> OpStore for JktDroppingRefreshStore<Inner> {
            async fn check_and_record_dpop_jti(
                &mut self,
                jti: &str,
                expires_at: chrono::DateTime<Utc>,
            ) -> Result<bool, authkestra_engine::store::StoreError> {
                self.inner.check_and_record_dpop_jti(jti, expires_at).await
            }
        }

        /// The regression test for the exact silent gap this whole round
        /// of fixes is about: a `RefreshTokenStore` that reports
        /// `store_token` success but doesn't actually persist `jkt` must
        /// not result in a response that claims `token_type: "DPoP"` while
        /// the stored token has no binding at all. `default_handle_
        /// authorization_code` must catch this and fail loudly instead.
        #[tokio::test]
        #[allow(deprecated)]
        async fn a_backend_that_silently_drops_jkt_fails_the_request_instead_of_lying() {
            let (inner, verifier) = dpop_refresh_continuity_store().await;
            let mut store = JktDroppingRefreshStore { inner };
            let tokens = test_tokens();

            let proof =
                DpopProofBuilder::new("https://auth.example.com/token", "jti-drop-1").build();

            let err = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect_err(
                "a store that silently drops the DPoP binding must fail the request, not \
                 succeed as though the binding was persisted",
            );

            assert_eq!(err.error, "server_error");
        }

        // --- An unconfirmable read-back is neither a confirmed failure nor
        // a confirmation (authkestra#290 review, findings #2 and #3) ---

        /// Wraps any `OpStore`, persisting `store_token` faithfully (so
        /// the binding really *is* stored) but answering every `get_token`
        /// with `Ok(None)` — the shape a read served by a lagging replica
        /// produces immediately after a write lands on the primary, and
        /// equally the shape of a store that quietly persisted nothing.
        ///
        /// Only the authorization-code path is exercised with this, and
        /// that path calls `get_token` exactly once (the confirmation
        /// probe), so blanketing the method is unambiguous here in a way
        /// it would not be on the rotation path, which also uses
        /// `get_token` for its pre-consumption candidate lookup.
        struct UnreadableProbeStore<Inner> {
            inner: Inner,
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> crate::client::ClientStore for UnreadableProbeStore<Inner> {
            async fn find_client(
                &mut self,
                client_id: &str,
            ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError>
            {
                self.inner.find_client(client_id).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> crate::code::AuthorizationCodeStore for UnreadableProbeStore<Inner> {
            async fn store_code(
                &mut self,
                code: AuthorizationCode,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.store_code(code).await
            }

            async fn consume_code(
                &mut self,
                code: &str,
            ) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError>
            {
                self.inner.consume_code(code).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> RefreshTokenStore for UnreadableProbeStore<Inner> {
            async fn store_token(
                &mut self,
                token: RefreshToken,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.store_token(token).await
            }

            async fn get_token(
                &mut self,
                _token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                Ok(None)
            }

            async fn revoke_token(
                &mut self,
                token: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.revoke_token(token).await
            }

            async fn consume_token(
                &mut self,
                token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                self.inner.consume_token(token).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> crate::device::DeviceCodeStore for UnreadableProbeStore<Inner> {
            async fn store_device_code(
                &mut self,
                session: crate::device::DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.store_device_code(session).await
            }

            async fn get_device_code(
                &mut self,
                device_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                self.inner.get_device_code(device_code).await
            }

            async fn get_by_user_code(
                &mut self,
                user_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                self.inner.get_by_user_code(user_code).await
            }

            async fn update_device_code(
                &mut self,
                session: crate::device::DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.update_device_code(session).await
            }

            async fn delete_device_code(
                &mut self,
                device_code: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                self.inner.delete_device_code(device_code).await
            }

            async fn consume_device_code(
                &mut self,
                device_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                self.inner.consume_device_code(device_code).await
            }
        }

        #[async_trait::async_trait]
        impl<Inner: OpStore> OpStore for UnreadableProbeStore<Inner> {
            async fn check_and_record_dpop_jti(
                &mut self,
                jti: &str,
                expires_at: chrono::DateTime<Utc>,
            ) -> Result<bool, authkestra_engine::store::StoreError> {
                self.inner.check_and_record_dpop_jti(jti, expires_at).await
            }
        }

        /// The call-site half of findings #2 and #3, which the helper-level
        /// tests below cannot see: what the *client* actually receives.
        ///
        /// An authorization-code exchange requesting `offline_access` with
        /// a valid DPoP proof, against a store whose confirmation read-back
        /// comes back empty, must return a successful response that simply
        /// omits `refresh_token` — not a token whose advertised binding no
        /// read has confirmed, and not a `server_error` either.
        ///
        /// This pins the fix in both directions at once. Route the
        /// inconclusive arm back to `Stored` and the `refresh_token`
        /// assertion fails on `Some(_)`; route it to `DpopBindingFailed`
        /// (the pre-authkestra#290 behaviour) and the `expect` fails on
        /// `server_error`.
        #[tokio::test]
        #[allow(deprecated)]
        async fn an_unconfirmable_read_back_omits_the_refresh_token_instead_of_advertising_it() {
            let (inner, verifier) = dpop_refresh_continuity_store().await;
            let mut store = UnreadableProbeStore { inner };
            let tokens = test_tokens();

            let proof =
                DpopProofBuilder::new("https://auth.example.com/token", "jti-unreadable-1").build();

            let issued = handle_token_with_client_cert(
                dpop_refresh_continuity_code_req(&verifier),
                None,
                &test_config(false),
                &mut store,
                &tokens,
                None,
                Some(&proof),
            )
            .await
            .expect(
                "an unconfirmable read-back must not fail a request whose write succeeded — \
                 that is the session-destroying behaviour authkestra#290 finding #1 removed",
            );

            assert_eq!(
                issued.token_type, "DPoP",
                "the access token is still DPoP-bound; only the refresh token is in doubt"
            );
            assert!(
                issued.refresh_token.is_none(),
                "a refresh token whose DPoP binding no read has confirmed must be omitted, \
                 not advertised: got {:?}",
                issued.refresh_token
            );
        }

        // --- The read-back confirmation probe itself failing must not be
        // treated as a confirmed dropped binding (PR #290 review) ---

        /// What `get_token` should hand back when used as a canned
        /// confirmation-probe result below.
        enum ProbeOutcome {
            TransientError,
            NotFoundYet,
        }

        /// A minimal `OpStore` whose `store_token` always succeeds and
        /// whose `get_token` always returns one canned, configurable
        /// result. Used to unit test `store_refresh_token_verifying_
        /// dpop_binding` directly rather than through the full
        /// token-endpoint flow: the two probe outcomes under test (a
        /// transient error, and "not found yet") are specifically about
        /// the read-back call that happens *after* a successful write, and
        /// reproducing that ordering through a real store would require
        /// distinguishing it from the *other* `get_token` call rotation
        /// already makes (the candidate lookup, before consuming) — this
        /// mock sidesteps that by testing the function in isolation.
        struct CannedGetTokenStore {
            probe: ProbeOutcome,
        }

        #[async_trait::async_trait]
        impl crate::client::ClientStore for CannedGetTokenStore {
            async fn find_client(
                &mut self,
                _client_id: &str,
            ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError>
            {
                unimplemented!("not exercised by this test")
            }
        }

        #[async_trait::async_trait]
        impl crate::code::AuthorizationCodeStore for CannedGetTokenStore {
            async fn store_code(
                &mut self,
                _code: AuthorizationCode,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                unimplemented!("not exercised by this test")
            }

            async fn consume_code(
                &mut self,
                _code: &str,
            ) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError>
            {
                unimplemented!("not exercised by this test")
            }
        }

        #[async_trait::async_trait]
        impl RefreshTokenStore for CannedGetTokenStore {
            async fn store_token(
                &mut self,
                _token: RefreshToken,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                Ok(())
            }

            async fn get_token(
                &mut self,
                _token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                match self.probe {
                    ProbeOutcome::TransientError => Err(
                        authkestra_engine::store::StoreError::Internal("transient".into()),
                    ),
                    ProbeOutcome::NotFoundYet => Ok(None),
                }
            }

            async fn revoke_token(
                &mut self,
                _token: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                unimplemented!("not exercised by this test")
            }

            async fn consume_token(
                &mut self,
                _token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                unimplemented!("not exercised by this test")
            }
        }

        #[async_trait::async_trait]
        impl crate::device::DeviceCodeStore for CannedGetTokenStore {
            async fn store_device_code(
                &mut self,
                _session: crate::device::DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                unimplemented!("not exercised by this test")
            }

            async fn get_device_code(
                &mut self,
                _device_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                unimplemented!("not exercised by this test")
            }

            async fn get_by_user_code(
                &mut self,
                _user_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                unimplemented!("not exercised by this test")
            }

            async fn update_device_code(
                &mut self,
                _session: crate::device::DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                unimplemented!("not exercised by this test")
            }

            async fn delete_device_code(
                &mut self,
                _device_code: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
                unimplemented!("not exercised by this test")
            }

            async fn consume_device_code(
                &mut self,
                _device_code: &str,
            ) -> Result<
                Option<crate::device::DeviceCodeSession>,
                authkestra_engine::store::StoreError,
            > {
                unimplemented!("not exercised by this test")
            }
        }

        #[async_trait::async_trait]
        impl OpStore for CannedGetTokenStore {}

        fn dpop_bound_refresh_token() -> RefreshToken {
            RefreshToken::new(
                "rt-1".to_string(),
                "client1".to_string(),
                test_identity(),
                "openid offline_access".to_string(),
                Utc::now() + Duration::days(30),
                Some("expected-jkt".to_string()),
            )
        }

        /// The write already succeeded (`store_token` returned `Ok`) by
        /// the time this probe runs; an error reading it back — a pool
        /// blip, say — is not evidence the binding was dropped and must
        /// not be reported as `DpopBindingFailed`. This is the exact
        /// regression flagged in PR #290's review: the prior version of
        /// this function mapped *any* `Err` from the probe to
        /// `DpopBindingFailed`, which for `default_handle_refresh_token`'s
        /// rotation path — which calls this only after already consuming
        /// the single-use predecessor token — would destroy a session on a
        /// transient read failure despite the write having succeeded.
        #[tokio::test]
        async fn a_transient_error_on_the_confirmation_read_does_not_fail_the_binding() {
            let mut store = CannedGetTokenStore {
                probe: ProbeOutcome::TransientError,
            };

            let outcome =
                store_refresh_token_verifying_dpop_binding(&mut store, dpop_bound_refresh_token())
                    .await;

            assert!(
                matches!(outcome, RefreshTokenStoreOutcome::NonFatalStorageFailure),
                "a transient read error confirming a binding that was already \
                 successfully written is inconclusive: neither a confirmed failure \
                 (which would destroy an already-rotated session) nor a confirmation \
                 (which would advertise a binding no read has seen)"
            );
        }

        /// As above, but the probe read finds no row at all rather than
        /// erroring outright — the shape a lagging read replica produces
        /// immediately after a write lands on the primary. Same fix, same
        /// reasoning: the write already succeeded, so this is inconclusive,
        /// not a positive signal the binding was dropped.
        #[tokio::test]
        async fn a_confirmation_read_that_finds_nothing_yet_does_not_fail_the_binding() {
            let mut store = CannedGetTokenStore {
                probe: ProbeOutcome::NotFoundYet,
            };

            let outcome =
                store_refresh_token_verifying_dpop_binding(&mut store, dpop_bound_refresh_token())
                    .await;

            assert!(
                matches!(outcome, RefreshTokenStoreOutcome::NonFatalStorageFailure),
                "a confirmation read that simply hasn't caught up to an already-successful \
                 write is inconclusive: neither a confirmed failure nor a confirmation"
            );
        }
    }
}

#[cfg(test)]
#[allow(deprecated)] // `require_pkce` (authkestra#273) — these fixtures don't exercise it
mod device_tests;

#[cfg(test)]
#[allow(deprecated)] // `require_pkce` (authkestra#273) — these fixtures don't exercise it
mod client_auth_tests;

#[cfg(test)]
mod log_level_policy_tests;

impl TokenResponse {
    /// Creates a new TokenResponse.
    pub fn new(access_token: String, token_type: String, expires_in: u64) -> Self {
        Self {
            access_token,
            token_type,
            expires_in,
            refresh_token: None,
            id_token: None,
            scope: None,
            issued_token_type: None,
        }
    }
}

impl TokenErrorResponse {
    /// Creates a new TokenErrorResponse.
    pub fn new(error: String, error_description: String) -> Self {
        Self {
            error,
            error_description,
        }
    }
}
