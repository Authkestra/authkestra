use crate::client::GrantType;
use crate::code::AuthorizationCode;
use crate::config::OpConfig;
use crate::error::OpError;
use crate::store::OpStore;
use authkestra_engine::auth::state::{Identity, IDENTITY_ATTR_AUTH_TIME};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;

/// Represents an incoming OAuth2/OIDC authorization request.
#[derive(Debug, serde::Deserialize)]
#[non_exhaustive]
pub struct AuthorizeRequest {
    /// Client ID requesting authorization.
    pub client_id: String,
    /// The redirect URI the client is asking to be sent back to. Matched
    /// against the registration by
    /// [`crate::client::ClientRegistration::allows_redirect_uri`] — exactly,
    /// save for a loopback IP URI's port (RFC 8252 §7.3).
    pub redirect_uri: String,
    /// Response type (must be "code").
    pub response_type: String,
    /// Space-delimited scopes requested. Defaults to empty when the client
    /// omits the parameter entirely — RFC 6749 §3.3 makes this legal, and
    /// nothing here distinguishes "omitted" from "explicitly empty"
    /// (authkestra#280): both mean no scope requested, and neither is an
    /// error. Plain `String` rather than `Option<String>` precisely because
    /// that distinction is never made — there is no default-*value* branch
    /// (as opposed to default-*absence*) implemented, so a `None` variant
    /// would carry no information a `""` doesn't already carry.
    #[serde(default)]
    pub scope: String,
    /// Optional opaque state parameter.
    pub state: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method ("S256").
    pub code_challenge_method: Option<String>,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// OIDC Core §3.1.2.1 `max_age`: the maximum number of seconds since the
    /// End-User's last authentication that the relying party will accept.
    /// `Some(0)` is a legal, meaningful value ("always require a fresh
    /// authentication") and must not be treated the same as `None`
    /// ("no freshness requirement was requested") — see
    /// [`handle_authorize`]'s enforcement of it.
    #[serde(default)]
    pub max_age: Option<i64>,
    /// OIDC Core §3.1.2.1 `prompt`: a space-delimited list of one or more of
    /// `none`, `login`, `consent`, `select_account`. Kept as the raw string
    /// (mirroring [`scope`](Self::scope)) rather than parsed here — the
    /// values this handler actually acts on (`none`, `login`) are read out
    /// of it directly in [`handle_authorize`].
    #[serde(default)]
    pub prompt: Option<String>,
}

/// The result of an authorization request handler.
///
/// `#[non_exhaustive]` for the same reason as
/// [`Jwk`](authkestra_engine::token::jwk::Jwk) and
/// [`MfaTokenClaims`](authkestra_engine::auth::state::MfaTokenClaims):
/// [`ReauthenticationRequired`] is the first addition since this enum
/// shipped, and it should not be the last variant this framework ever needs
/// to signal at `/authorize` — the next one should cost downstream match
/// arms nothing beyond adding a wildcard once, here.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthorizeOutcome {
    /// redirect_uri was valid; caller should redirect the browser here.
    Redirect(String),
    /// client_id or redirect_uri could not be verified — do NOT redirect.
    DirectError(OpError),
    /// The request's `max_age` or `prompt=login` requires a fresher proof of
    /// authentication than the presented `Identity` carries. The host
    /// application must re-run its own login UI and call [`handle_authorize`]
    /// again with a freshly authenticated `Identity` — `authkestra-op` owns
    /// no login UI (decision 0005) and cannot perform the re-authentication
    /// itself. See `docs/rfc-007-max-age-reauth.md`.
    ///
    /// Distinct from a `login_required` error [`Redirect`](Self::Redirect):
    /// that outcome is for when the *client* explicitly forbade interaction
    /// (`prompt=none`) and re-authentication would otherwise be needed —
    /// OIDC Core §3.1.2.1 requires the error go back to the client via
    /// redirect, not to the host application as this variant does.
    ///
    /// Boxed: [`ReauthenticationRequired`] carries a whole [`AuthorizeRequest`]
    /// back, which otherwise makes this the dominant variant's size and
    /// bloats every `AuthorizeOutcome` — including the far more common
    /// [`Redirect`](Self::Redirect) — to match.
    ReauthenticationRequired(Box<ReauthenticationRequired>),
}

/// Payload for [`AuthorizeOutcome::ReauthenticationRequired`]. See that
/// variant's doc comment for when this is returned instead of a redirect.
///
/// `#[non_exhaustive]`, constructed via [`ReauthenticationRequired::new`],
/// for the same reason as [`AuthorizeOutcome`] itself.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReauthenticationRequired {
    /// The original request, handed back unmodified so the host application
    /// does not need to independently persist or re-derive it while it
    /// round-trips through its own login UI (e.g. as query parameters on its
    /// own redirect to that UI, restored when the user returns and
    /// `handle_authorize` is called a second time).
    ///
    /// Deliberately does *not* carry the `Identity` that was presented to
    /// this call: that identity — and anything it asserted, including
    /// [`IDENTITY_ATTR_STEP_UP_SATISFIED`](authkestra_engine::auth::state::IDENTITY_ATTR_STEP_UP_SATISFIED)
    /// — is discarded here. There is nowhere in `authkestra-op` for it to be
    /// carried forward to the retry, so whether the fresh authentication the
    /// host application performs satisfies step-up again depends entirely on
    /// what that fresh login flow actually runs, not on what the stale one
    /// asserted. See `docs/rfc-007-max-age-reauth.md` §5 for why this is the
    /// right answer to "does a `max_age` re-auth reset step-up state?".
    pub request: AuthorizeRequest,
    /// `true` when `max_age` requested a freshness that the presented
    /// identity's `auth_time` — or its complete absence — does not satisfy.
    /// See [`handle_authorize`] for exactly how this is computed, including
    /// the deliberate choice to fail closed when `auth_time` is missing.
    pub max_age_exceeded: bool,
    /// `true` when the request's `prompt` parameter contained `login`,
    /// which forces re-authentication unconditionally, independent of
    /// `max_age`/`auth_time` entirely.
    pub prompt_login: bool,
}

impl ReauthenticationRequired {
    /// Creates a new payload for [`AuthorizeOutcome::ReauthenticationRequired`].
    pub fn new(request: AuthorizeRequest, max_age_exceeded: bool, prompt_login: bool) -> Self {
        Self {
            request,
            max_age_exceeded,
            prompt_login,
        }
    }
}

/// Validates an incoming authorization request, enforces PKCE, and issues an authorization code.
pub async fn handle_authorize(
    req: AuthorizeRequest,
    identity: Identity,
    config: &OpConfig,
    op_store: &mut dyn OpStore,
) -> AuthorizeOutcome {
    // 1. Look up client_id
    tracing::debug!(client_id = %req.client_id, "Looking up client for authorization request");
    let client = match op_store.find_client(&req.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            tracing::error!(client_id = %req.client_id, "Unknown client ID requested");
            return AuthorizeOutcome::DirectError(OpError::UnknownClient(req.client_id));
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error finding client");
            return AuthorizeOutcome::DirectError(e.into());
        }
    };

    // 2. Validate the redirect_uri against the registration. Exact, except
    // for a loopback IP URI's port (RFC 8252 §7.3, authkestra#291) — the
    // carve-out lives in `allows_redirect_uri`, not here. Everything
    // downstream (the redirect built below, and the value recorded on the
    // code) uses the URI *as presented*, so the ephemeral port survives to
    // `/token`.
    if !client.allows_redirect_uri(&req.redirect_uri) {
        tracing::warn!(
            client_id = %req.client_id,
            requested_uri = %req.redirect_uri,
            "Redirect URI mismatch"
        );
        return AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch);
    }

    // FROM HERE ON, all further errors are Redirect outcomes
    let parsed_uri = match url::Url::parse(&req.redirect_uri) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse matched redirect URI");
            return AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch);
        }
    };

    let error_redirect = |error: &str, description: &str| -> AuthorizeOutcome {
        let mut url = parsed_uri.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("error", error);
            query.append_pair("error_description", description);
            if let Some(ref s) = req.state {
                query.append_pair("state", s);
            }
        }
        AuthorizeOutcome::Redirect(url.into())
    };

    // 3. Validate requested scope against the client's registration
    // (authkestra#278). `req.scope` was previously copied verbatim into the
    // stored code — and from there into the eventual token — with no check
    // at all, letting any registered client request (and receive) a scope
    // it was never granted. Rejects on the first offending scope, naming it
    // specifically, mirroring `default_handle_client_credentials`'s
    // existing (and correct) scope check at the token endpoint.
    for s in req.scope.split_whitespace() {
        if !client.allows_scope(s) {
            tracing::warn!(client_id = %req.client_id, scope = %s, "Client requested unauthorized scope");
            return error_redirect(
                "invalid_scope",
                &format!("Scope {s} is not allowed for this client"),
            );
        }
        if !config.allows_scope(s) {
            tracing::warn!(client_id = %req.client_id, scope = %s, "Client requested scope not supported by provider");
            return error_redirect(
                "invalid_scope",
                &format!("Scope {s} is not supported by this provider"),
            );
        }
    }

    // 4. Check response_type == "code"
    if req.response_type != "code" {
        tracing::debug!(
            client_id = %req.client_id,
            response_type = %req.response_type,
            "Unsupported response type requested"
        );
        return error_redirect(
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    // 5. Check client allows AuthorizationCode grant type
    if !client.allows_grant_type(&GrantType::AuthorizationCode) {
        tracing::error!(
            client_id = %req.client_id,
            "Client is not permitted to use the authorization code grant"
        );
        return error_redirect(
            "unauthorized_client",
            "Client is not permitted to use the authorization code grant",
        );
    }

    // 6. PKCE requirements — mandatory for every client, per OAuth 2.1 §4.1
    // (authkestra#273). `client.require_pkce` no longer gates this: OAuth 2.1
    // does not grandfather in confidential clients or any other exemption,
    // and per-client opt-out was the exact gap #273 closes.
    if req.code_challenge.is_none() {
        tracing::debug!(client_id = %req.client_id, "Missing required code_challenge for PKCE");
        return error_redirect("invalid_request", "code_challenge is required");
    }
    if req.code_challenge_method.as_deref() != Some("S256") {
        tracing::debug!(client_id = %req.client_id, "Invalid code_challenge_method, S256 required");
        return error_redirect("invalid_request", "code_challenge_method must be S256");
    }

    // 7. Validate `prompt` (OIDC Core §3.1.2.1): a space-delimited list of
    // `none`, `login`, `consent`, `select_account`. `none` MUST NOT be
    // combined with any other value — the RP is asking for both "never
    // interact" and something else in the same breath, which is
    // unsatisfiable — so that combination is a request-shape error like any
    // other rejected above.
    let prompt_values: Vec<&str> = req
        .prompt
        .as_deref()
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();
    let prompt_none = prompt_values.contains(&"none");
    let prompt_login = prompt_values.contains(&"login");
    if prompt_none && prompt_values.len() > 1 {
        tracing::debug!(
            client_id = %req.client_id,
            prompt = ?req.prompt,
            "prompt=none combined with another prompt value"
        );
        return error_redirect(
            "invalid_request",
            "prompt=none must not be combined with any other prompt value",
        );
    }

    // 8. Enforce `max_age` / `prompt=login` freshness (OIDC Core §3.1.2.1).
    // `authkestra-op` cannot itself re-authenticate anyone — it owns no
    // login UI and no user table (decision 0005) — so the most it can do is
    // recognize that the presented `Identity` is not fresh enough and tell
    // the caller so, letting the caller (or the client, for `prompt=none`)
    // decide what happens next. See `docs/rfc-007-max-age-reauth.md`.
    let max_age_exceeded = if let Some(max_age) = req.max_age {
        match identity
            .attributes
            .get(IDENTITY_ATTR_AUTH_TIME)
            .and_then(|raw| raw.parse::<i64>().ok())
        {
            // `auth_time` is REQUIRED on the resulting ID token whenever
            // `max_age` was requested (OIDC Core §2). An identity with no
            // parseable `auth_time` — one that never passed through
            // `Engine::authenticate`, e.g. a federated identity handed
            // straight to this handler — cannot support that requirement at
            // all, so the request fails closed: treated as maximally stale
            // rather than silently honoured with no freshness evidence.
            None => true,
            // Inclusive (`>=`): an identity exactly `max_age` seconds old has
            // used up the allowance. The case this actually turns on is
            // `max_age=0`, where a strict `>` makes the answer depend on
            // sub-second timing the relying party cannot see — an
            // authentication landing in the same wall-clock second as the
            // request would give elapsed `0`, `0 > 0` is false, and a request
            // asking for maximum freshness would be honoured without any
            // re-authentication. A freshness control that intermittently
            // doesn't apply is worse than one that is merely strict, and
            // erring toward re-authentication is the right direction for a
            // security control.
            Some(auth_time) => Utc::now().timestamp() - auth_time >= max_age,
        }
    } else {
        false
    };

    if max_age_exceeded || prompt_login {
        if prompt_none {
            // The client explicitly forbade any interaction. OIDC Core
            // §3.1.2.1 is explicit that the correct response to
            // "re-authentication is needed, but you told me not to
            // interact" is the `login_required` error delivered to the
            // *client* via redirect — not a signal to the host application
            // to show its login UI, which is exactly the interaction
            // `prompt=none` ruled out.
            tracing::info!(
                client_id = %req.client_id,
                max_age_exceeded,
                prompt_login,
                "re-authentication required but prompt=none forbids interaction"
            );
            return error_redirect(
                "login_required",
                "re-authentication is required but prompt=none was requested",
            );
        }
        tracing::info!(
            client_id = %req.client_id,
            max_age_exceeded,
            prompt_login,
            "re-authentication required; deferring to the host application's login flow"
        );
        return AuthorizeOutcome::ReauthenticationRequired(Box::new(
            ReauthenticationRequired::new(req, max_age_exceeded, prompt_login),
        ));
    }

    // 9. Build an AuthorizationCode
    let code_val = {
        let mut rng = rand::rng();
        let mut code_bytes = [0u8; 32];
        rng.fill_bytes(&mut code_bytes);
        URL_SAFE_NO_PAD.encode(code_bytes)
    };

    let expires_at = Utc::now() + Duration::seconds(config.authorization_code_ttl_secs);

    let mut auth_code = AuthorizationCode::new(
        code_val.clone(),
        client.client_id.clone(),
        req.redirect_uri.clone(),
        req.scope.clone(),
        identity,
        expires_at,
        false,
    );
    auth_code.code_challenge = req.code_challenge.clone();
    auth_code.code_challenge_method = req.code_challenge_method.clone();
    auth_code.nonce = req.nonce.clone();

    // 10. Store the code
    if let Err(e) = op_store.store_code(auth_code).await {
        tracing::error!(error = ?e, client_id = %req.client_id, "Failed to store authorization code");
        return error_redirect("server_error", "Failed to store authorization code");
    }

    // 11. Return Redirect with code and state
    let mut url = parsed_uri;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("code", &code_val);
        if let Some(ref s) = req.state {
            query.append_pair("state", s);
        }
    }

    tracing::info!(client_id = %req.client_id, "Successfully issued authorization code");
    AuthorizeOutcome::Redirect(url.into())
}

#[cfg(test)]
#[allow(deprecated)] // `require_pkce` (authkestra#273) — these fixtures don't exercise it
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, GrantType};
    use crate::code::AuthorizationCodeStore;
    use authkestra_engine::store::KvStore;

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

    fn test_identity() -> Identity {
        Identity {
            provider_id: "local".to_string(),
            external_id: "user-123".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// #353 tier 4: the authorize endpoint's grant-authorization check had no
    /// test, so changing its log level surfaced it as uncovered. It is the
    /// same security property the token endpoint enforces — a client may only
    /// use the grants it is registered for — and belongs at `error!` because
    /// the registration is what has to change.
    #[tokio::test]
    async fn a_client_not_registered_for_the_code_grant_is_refused() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        #[allow(deprecated)] // `require_pkce` (authkestra#273) — not exercised here
        clients
            .set(
                "client1",
                crate::client::ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    // Registered for a different grant entirely.
                    grant_types: vec![crate::client::GrantType::ClientCredentials],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();

        let req = AuthorizeRequest {
            client_id: "client1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &test_config(), &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;

        // Redirected with an error rather than refused directly: the
        // redirect_uri was validated first, so the client learns why.
        match outcome {
            AuthorizeOutcome::Redirect(url) => assert!(
                url.contains("unauthorized_client"),
                "expected an unauthorized_client error redirect, got {url}"
            ),
            other => panic!("expected an error redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_client_direct_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "unknown".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        assert!(matches!(
            outcome,
            AuthorizeOutcome::DirectError(OpError::UnknownClient(_))
        ));
    }

    /// The actual regression test for authkestra#280: `AuthorizeRequest` is
    /// what `axum`'s and `actix`'s `Query` extractors deserialize from the
    /// request's query string via the same generic serde `Deserialize`
    /// derive exercised here — a JSON object is used purely as a
    /// dependency-free stand-in for "a request with no `scope` key at all",
    /// not because the real transport is JSON. Before this fix, a `String`
    /// field with no `#[serde(default)]` and no key present would fail
    /// deserialization outright, which is what turned an RFC-6749-legal
    /// omitted `scope` into a raw framework 400 instead of ever reaching
    /// `handle_authorize`.
    #[test]
    fn deserializes_successfully_when_scope_is_entirely_absent() {
        let json = serde_json::json!({
            "client_id": "client-1",
            "redirect_uri": "https://app.example.com/cb",
            "response_type": "code",
            // no "scope" key at all
        });
        let req: AuthorizeRequest =
            serde_json::from_value(json).expect("a missing scope must not fail deserialization");
        assert_eq!(req.scope, "");
    }

    #[tokio::test]
    async fn test_mismatched_redirect_uri_direct_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
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
        let config = test_config();

        // Exact match required, this has a trailing slash difference
        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb/".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        assert!(matches!(
            outcome,
            AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch)
        ));
    }

    #[tokio::test]
    async fn test_unsupported_response_type_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "token".to_string(), // not code
            scope: "openid".to_string(),
            state: Some("xyz".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=unsupported_response_type"));
            assert!(url.contains("state=xyz"));
            assert!(url.starts_with("https://app.example.com/cb?"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_missing_pkce_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None, // Missing PKCE
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_plain_pkce_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("plain".to_string()), // plain is rejected
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_successful_authorization() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string(), "profile".to_string()],
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
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid profile".to_string(),
            state: Some("abc".to_string()),
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes.clone(), authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.starts_with("https://app.example.com/cb?code="));
            assert!(url.contains("&state=abc"));

            // Extract code and verify it was persisted
            let code_val = url
                .split("code=")
                .nth(1)
                .unwrap()
                .split('&')
                .next()
                .unwrap();

            let persisted = codes.consume_code(code_val).await.unwrap().unwrap();
            assert_eq!(persisted.client_id, "client-1");
            assert_eq!(persisted.redirect_uri, "https://app.example.com/cb");
            assert_eq!(persisted.scope, "openid profile");
            assert_eq!(persisted.code_challenge, Some("s256challenge".to_string()));
            assert_eq!(persisted.identity.external_id, "user-123");
        } else {
            panic!("Expected Redirect");
        }
    }

    /// authkestra#291, end to end: a native app registered
    /// `http://127.0.0.1/callback` and binds whatever ephemeral port the OS
    /// hands it. RFC 8252 §7.3 makes accepting that a MUST, and before the fix
    /// this request could only ever be a `DirectError(RedirectUriMismatch)`.
    ///
    /// The second half of the assertion matters as much as the first: the
    /// browser is redirected to — and the code is persisted with — the
    /// *presented* URI including its port, not the registered portless one.
    /// That is what keeps `/token`'s exact `auth_code.redirect_uri !=
    /// req_redirect_uri` comparison (RFC 6749 §4.1.3) correct and untouched.
    #[tokio::test]
    async fn loopback_redirect_on_an_ephemeral_port_is_accepted() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "native-app",
                ClientRegistration {
                    client_id: "native-app".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["http://127.0.0.1/callback".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "native-app".to_string(),
            redirect_uri: "http://127.0.0.1:54321/callback".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: Some("abc".to_string()),
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes.clone(), authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;

        let AuthorizeOutcome::Redirect(url) = outcome else {
            panic!("expected a Redirect, got {outcome:?}");
        };
        assert!(
            url.starts_with("http://127.0.0.1:54321/callback?code="),
            "redirect must go to the presented port, got {url}"
        );

        let code_val = url
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let persisted = codes.consume_code(code_val).await.unwrap().unwrap();
        assert_eq!(persisted.redirect_uri, "http://127.0.0.1:54321/callback");
    }

    /// authkestra#280: an omitted `scope` (RFC 6749 §3.3 makes this legal)
    /// must not be an error at all — end to end, from deserialization
    /// through to a persisted code with `scope == ""`. Builds `req` via
    /// `serde_json::from_value` with no `scope` key present (rather than a
    /// struct literal) specifically so this test exercises the same
    /// deserialization path the `Query` extractors do, not just the
    /// handler's behavior given an already-empty `String`.
    #[tokio::test]
    async fn test_missing_scope_is_treated_as_no_scope_and_succeeds() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let mut codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req: AuthorizeRequest = serde_json::from_value(serde_json::json!({
            "client_id": "client-1",
            "redirect_uri": "https://app.example.com/cb",
            "response_type": "code",
            "code_challenge": "s256challenge",
            "code_challenge_method": "S256",
            // no "scope" key at all
        }))
        .expect("a missing scope must not fail deserialization");

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &mut crate::store::CompositeOpStore::new(
                clients,
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.starts_with("https://app.example.com/cb?code="));
            let code_val = url
                .split("code=")
                .nth(1)
                .unwrap()
                .split('&')
                .next()
                .unwrap();
            let persisted = codes.consume_code(code_val).await.unwrap().unwrap();
            assert_eq!(persisted.scope, "");
        } else {
            panic!("Expected Redirect, a missing scope must not be an error");
        }
    }

    #[tokio::test]
    async fn test_state_encoding() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        // State containing characters that require URL encoding
        let dangerous_state = "foo&bar=baz#123";

        // PKCE is mandatory (authkestra#273) regardless of `require_pkce`,
        // and unrelated to what this test actually covers (state encoding),
        // but required to reach the success path at all.
        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: Some(dangerous_state.to_string()),
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            let parsed = url::Url::parse(&url).expect("Should be a valid URL");

            // Check that `state` is perfectly preserved and there are no injected query params
            let mut state_found = false;
            let mut code_found = false;
            for (k, v) in parsed.query_pairs() {
                if k == "state" {
                    assert_eq!(v, dangerous_state);
                    state_found = true;
                }
                if k == "code" {
                    code_found = true;
                }
                if k == "error" || k == "bar" {
                    panic!("Injected parameter found!");
                }
            }
            assert!(state_found, "state parameter must be present");
            assert!(code_found, "code parameter must be present");
        } else {
            panic!("Expected Redirect");
        }
    }

    /// PKCE is mandatory regardless of `client.require_pkce` (authkestra#273):
    /// a client not opted into PKCE that still omits `code_challenge` (even
    /// while sending `code_challenge_method`) is rejected exactly like one
    /// that requires it.
    #[tokio::test]
    async fn test_pkce_method_without_challenge_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false, // no longer changes the outcome — PKCE is always required
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
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: Some("S256".to_string()), // Method provided without challenge
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &mut crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
            assert!(url.contains("error_description=code_challenge+is+required"));
        } else {
            panic!("Expected Redirect");
        }
    }

    /// The core regression test for authkestra#273: a client explicitly
    /// registered with `require_pkce: false` and sending no PKCE parameters
    /// at all must still be rejected, since OAuth 2.1 §4.1 makes PKCE
    /// mandatory unconditionally rather than an opt-in per client.
    #[tokio::test]
    async fn test_pkce_is_mandatory_even_when_client_does_not_require_it() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &mut crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
            assert!(url.contains("error_description=code_challenge+is+required"));
        } else {
            panic!("Expected Redirect");
        }
    }

    /// The core regression test for authkestra#278: a client registered
    /// with a narrow scope must not be able to request — and receive an
    /// authorization code for — a scope it was never granted.
    #[tokio::test]
    async fn test_scope_not_granted_to_client_is_rejected() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "admin".to_string(),
            state: None,
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &mut crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_scope"));
            assert!(url.contains("error_description=Scope+admin+is+not+allowed"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_scope_not_supported_by_provider_is_rejected() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string(), "custom_unsupported".to_string()],
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
        // test_config only supports "openid" and "profile"
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "custom_unsupported".to_string(),
            state: None,
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &mut crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_scope"));
            assert!(url.contains(
                "error_description=Scope+custom_unsupported+is+not+supported+by+this+provider"
            ));
        } else {
            panic!("Expected Redirect");
        }
    }

    /// A request mixing a granted and an ungranted scope must still be
    /// rejected — partial credit is not an option.
    #[tokio::test]
    async fn test_one_ungranted_scope_among_several_is_rejected() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid admin".to_string(),
            state: None,
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &mut crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_scope"));
        } else {
            panic!("Expected Redirect");
        }
    }

    // --- issue #381: `max_age` / `prompt=login` re-authentication ---

    /// Shared fixture for the tests below: registers "client-1" exactly as
    /// [`test_successful_authorization`] does, so each test only has to vary
    /// the `AuthorizeRequest` and `Identity`.
    async fn store_with_registered_client() -> crate::store::CompositeOpStore<
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
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
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

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        crate::store::CompositeOpStore::new(
            clients,
            codes,
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
        )
    }

    /// A minimal, otherwise-valid request against "client-1" — tests below
    /// clone this and override `max_age`/`prompt`.
    fn base_req() -> AuthorizeRequest {
        AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            max_age: None,
            prompt: None,
        }
    }

    /// `test_identity()` plus an `auth_time` `seconds_ago` seconds in the past.
    fn identity_with_auth_time(seconds_ago: i64) -> Identity {
        let mut identity = test_identity();
        identity.attributes.insert(
            IDENTITY_ATTR_AUTH_TIME.to_string(),
            (Utc::now().timestamp() - seconds_ago).to_string(),
        );
        identity
    }

    /// An identity authenticated well within `max_age` must be accepted
    /// exactly as if no freshness requirement had been requested — a code is
    /// issued, not a re-authentication demand.
    #[tokio::test]
    async fn fresh_enough_auth_satisfies_max_age() {
        let mut req = base_req();
        req.max_age = Some(3600);

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(5),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        assert!(
            matches!(outcome, AuthorizeOutcome::Redirect(ref url) if url.contains("code=")),
            "expected a code-issuing Redirect, got {outcome:?}"
        );
    }

    /// An identity whose `auth_time` is older than the requested `max_age`
    /// must not get a code — the host application has to re-authenticate it
    /// and call `handle_authorize` again.
    #[tokio::test]
    async fn stale_auth_triggers_reauthentication_required() {
        let mut req = base_req();
        req.max_age = Some(60);

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(120),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::ReauthenticationRequired(reauth) = outcome else {
            panic!("expected ReauthenticationRequired, got {outcome:?}");
        };
        assert!(reauth.max_age_exceeded);
        assert!(!reauth.prompt_login);
        // The original request is handed back unmodified, so the host
        // application can resume it after its own login UI completes.
        assert_eq!(reauth.request.client_id, "client-1");
        assert_eq!(reauth.request.max_age, Some(60));
    }

    /// `max_age=0` is a meaningful, legal request ("always re-authenticate")
    /// and must not be treated as "no `max_age` requested" — a naive
    /// `if max_age > 0` guard would silently skip enforcement entirely for
    /// this value.
    #[tokio::test]
    async fn max_age_zero_forces_reauthentication() {
        let mut req = base_req();
        req.max_age = Some(0);

        // Authenticated one second ago: not stale by any conventional
        // threshold, but `now - auth_time > 0` is still true.
        let outcome = handle_authorize(
            req,
            identity_with_auth_time(1),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::ReauthenticationRequired(reauth) = outcome else {
            panic!("expected ReauthenticationRequired, got {outcome:?}");
        };
        assert!(reauth.max_age_exceeded);
    }

    /// The case `max_age=0` actually turns on: an authentication landing in
    /// the *same wall-clock second* as the request. With a strict `>`
    /// comparison the elapsed time is `0`, `0 > 0` is false, and the request
    /// would be honoured without any re-authentication — so whether an RP
    /// asking for maximum freshness gets it would depend on sub-second
    /// timing it cannot see or control. A freshness control that
    /// intermittently doesn't apply is worse than one that is merely strict,
    /// so `max_age=0` always requires re-authentication.
    #[tokio::test]
    async fn max_age_zero_forces_reauthentication_even_within_the_same_second() {
        let mut req = base_req();
        req.max_age = Some(0);

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(0),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::ReauthenticationRequired(reauth) = outcome else {
            panic!("expected ReauthenticationRequired for max_age=0, got {outcome:?}");
        };
        assert!(reauth.max_age_exceeded);
    }

    /// The boundary is inclusive: an identity exactly `max_age` seconds old
    /// has used up the allowance. Erring toward re-authentication is the
    /// right direction for a freshness control, and it keeps the `max_age=0`
    /// rule above from being a special case bolted on the side.
    #[tokio::test]
    async fn an_identity_exactly_max_age_old_is_stale() {
        let mut req = base_req();
        req.max_age = Some(300);

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(300),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        assert!(
            matches!(outcome, AuthorizeOutcome::ReauthenticationRequired(_)),
            "expected ReauthenticationRequired at the exact boundary, got {outcome:?}"
        );
    }

    /// `prompt=login` forces re-authentication unconditionally — independent
    /// of `max_age`/`auth_time` freshness entirely, including for an
    /// identity that just authenticated.
    #[tokio::test]
    async fn prompt_login_forces_reauthentication_even_when_fresh() {
        let mut req = base_req();
        req.prompt = Some("login".to_string());

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(0),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::ReauthenticationRequired(reauth) = outcome else {
            panic!("expected ReauthenticationRequired, got {outcome:?}");
        };
        assert!(reauth.prompt_login);
        assert!(!reauth.max_age_exceeded);
    }

    /// OIDC Core §3.1.2.1: `prompt=none` MUST NOT cause any UI. When
    /// re-authentication would otherwise be required, the correct response
    /// is `login_required` returned to the *client* via redirect — never
    /// `AuthorizeOutcome::ReauthenticationRequired`, which would ask the host
    /// application to show interactive UI, exactly what `prompt=none` rules
    /// out.
    #[tokio::test]
    async fn prompt_none_with_stale_auth_yields_login_required_via_redirect() {
        let mut req = base_req();
        req.max_age = Some(60);
        req.prompt = Some("none".to_string());

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(120),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::Redirect(url) = outcome else {
            panic!("expected a Redirect carrying login_required, got {outcome:?}");
        };
        assert!(url.contains("error=login_required"));
    }

    /// OIDC Core §3.1.2.1: combining `none` with any other `prompt` value is
    /// an `invalid_request` error — the request asks for both "never
    /// interact" and something else at once.
    #[tokio::test]
    async fn prompt_none_combined_with_another_value_is_invalid_request() {
        let mut req = base_req();
        req.prompt = Some("none login".to_string());

        let outcome = handle_authorize(
            req,
            identity_with_auth_time(0),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::Redirect(url) = outcome else {
            panic!("expected a Redirect carrying invalid_request, got {outcome:?}");
        };
        assert!(url.contains("error=invalid_request"));
    }

    /// An identity that never passed through `Engine::authenticate` (e.g. a
    /// federated login handed straight to `handle_authorize`) carries no
    /// `auth_time` at all. `max_age` cannot be honoured against a freshness
    /// this crate has no evidence for, so this fails closed: treated as
    /// maximally stale rather than silently granting the code.
    #[tokio::test]
    async fn max_age_against_an_identity_with_no_auth_time_forces_reauthentication() {
        let mut req = base_req();
        req.max_age = Some(3600);

        let outcome = handle_authorize(
            req,
            test_identity(), // no IDENTITY_ATTR_AUTH_TIME attribute at all
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        let AuthorizeOutcome::ReauthenticationRequired(reauth) = outcome else {
            panic!("expected ReauthenticationRequired, got {outcome:?}");
        };
        assert!(reauth.max_age_exceeded);
    }

    /// No `max_age` and no `prompt=login` at all: existing behavior for
    /// every request that predates this feature is untouched, regardless of
    /// whether the identity carries `auth_time`.
    #[tokio::test]
    async fn no_freshness_request_is_unaffected_by_a_missing_auth_time() {
        let req = base_req();

        let outcome = handle_authorize(
            req,
            test_identity(),
            &test_config(),
            &mut store_with_registered_client().await,
        )
        .await;

        assert!(
            matches!(outcome, AuthorizeOutcome::Redirect(ref url) if url.contains("code=")),
            "expected a code-issuing Redirect, got {outcome:?}"
        );
    }
}
