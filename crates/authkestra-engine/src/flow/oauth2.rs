use crate::auth::{
    error::AuthError, state::Identity, state::OAuth2State, state::OAuthToken, ErasedOAuthFlow,
    OAuthProvider, UserMapper,
};
use crate::flow::{Flow, FlowContext, FlowResult};
use async_trait::async_trait;

/// Orchestrates the standard OAuth2 Authorization Code flow.
pub struct OAuth2Flow<P: OAuthProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
    scopes: Vec<String>,
    use_pkce: bool,
}

#[async_trait]
impl<P: OAuthProvider + 'static, M: UserMapper + 'static> Flow for OAuth2Flow<P, M> {
    fn id(&self) -> &str {
        self.provider.provider_id()
    }

    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError> {
        if let Some(_code) = ctx.params.get("code") {
            let _received_state = ctx.params.get("state").ok_or(AuthError::CsrfMismatch)?;

            // In the new model, expected_state must be provided via some context.
            // For now, if it's missing from ctx, we might need to adjust FlowContext.
            // But ErasedOAuthFlow is what the adapters use.
            Err(AuthError::Token(
                "Direct Flow execution not updated for encrypted state".to_string(),
            ))
        } else {
            // Assume initiation if no code is present
            let scopes_str = ctx.params.get("scopes").map(|s| s.as_str()).unwrap_or("");
            let scopes_vec: Vec<&str> = if scopes_str.is_empty() {
                Vec::new()
            } else {
                scopes_str.split(',').collect()
            };

            let pkce_challenge = ctx.params.get("pkce_challenge").map(|s| s.as_str());
            let (url, _state) = self.initiate_login(&scopes_vec, pkce_challenge);
            Ok(FlowResult::Redirect(url))
        }
    }
}

#[async_trait]
impl<P: OAuthProvider + 'static, M: UserMapper + 'static> ErasedOAuthFlow for OAuth2Flow<P, M> {
    fn provider_id(&self) -> String {
        self.provider.provider_id().to_string()
    }

    fn initiate_login(
        &self,
        scopes: &[&str],
        pkce_challenge: Option<&str>,
    ) -> (String, OAuth2State) {
        let effective_scopes = if !scopes.is_empty() {
            scopes
        } else {
            &self
                .scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
        };

        self.initiate_login(effective_scopes, pkce_challenge)
    }

    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &OAuth2State,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        let (identity, token, _) = self
            .finalize_login(code, received_state, expected_state)
            .await?;
        Ok((identity, token))
    }
}

impl<P: OAuthProvider> OAuth2Flow<P, ()> {
    /// Create a new `OAuth2Flow` with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
            scopes: Vec::new(),
            use_pkce: true,
        }
    }
}

impl<P: OAuthProvider, M: UserMapper> OAuth2Flow<P, M> {
    /// Create a new `OAuth2Flow` with the given provider and user mapper.
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
            scopes: Vec::new(),
            use_pkce: true,
        }
    }

    /// Set the scopes for the OAuth2 flow.
    pub fn with_scopes(mut self, scopes: Vec<impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Enable or disable PKCE for the OAuth2 flow.
    pub fn with_pkce(mut self, use_pkce: bool) -> Self {
        self.use_pkce = use_pkce;
        self
    }

    /// Whether PKCE is enabled for this OAuth2 flow.
    pub fn pkce_enabled(&self) -> bool {
        self.use_pkce
    }

    /// Generates the redirect URL and CSRF state.
    ///
    /// # PKCE Contract
    ///
    /// When PKCE is enabled (`self.pkce_enabled()`):
    /// - If `pkce_challenge` is `None`, a fresh PKCE challenge and matching `code_verifier`
    ///   are generated automatically and stored in the returned [`OAuth2State`].
    /// - If `pkce_challenge` is `Some`, the supplied challenge is sent to the provider and
    ///   `OAuth2State.code_verifier` is returned as `None`; the caller must populate
    ///   `OAuth2State.code_verifier` with the matching verifier before calling [`Self::finalize_login`].
    #[tracing::instrument(skip(self), fields(provider_id = %self.provider.provider_id()))]
    pub fn initiate_login(
        &self,
        scopes: &[&str],
        pkce_challenge: Option<&str>,
    ) -> (String, OAuth2State) {
        let state = uuid::Uuid::new_v4().to_string();
        // Always generated, and always handed to the provider. A provider that
        // has no use for it ignores it; one that validates an ID token needs it
        // regardless of whether it remembered to advertise that. Gating this
        // instead of the check below would let an out-of-tree OIDC provider
        // opt out of replay protection just by not overriding a default.
        let nonce = Some(uuid::Uuid::new_v4().to_string());

        let effective_scopes = if !scopes.is_empty() {
            scopes
        } else {
            &self
                .scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
        };

        let (effective_pkce_challenge, code_verifier) = if self.use_pkce {
            match pkce_challenge {
                Some(challenge) => {
                    tracing::debug!(
                        pkce_mode = "caller_supplied",
                        "using caller-supplied PKCE challenge"
                    );
                    (Some(challenge.to_string()), None)
                }
                None => {
                    tracing::debug!(
                        pkce_mode = "auto_generated",
                        "automatically generated PKCE challenge and verifier"
                    );
                    let pkce = crate::auth::pkce::Pkce::new();
                    (Some(pkce.code_challenge), Some(pkce.code_verifier))
                }
            }
        } else {
            tracing::debug!(
                pkce_mode = "disabled",
                has_supplied_challenge = pkce_challenge.is_some(),
                "PKCE disabled on flow"
            );
            (pkce_challenge.map(|s| s.to_string()), None)
        };

        tracing::debug!(scopes = ?effective_scopes, "generating authorization URL");

        let url = self.provider.get_authorization_url(
            &state,
            effective_scopes,
            effective_pkce_challenge.as_deref(),
            nonce.as_deref(),
        );

        let auth_state = OAuth2State {
            state: state.clone(),
            nonce,
            code_verifier,
            success_url: None,
            provider_id: self.provider.provider_id().to_string(),
            expires_at: chrono::Utc::now().timestamp() + 600,
        };

        tracing::info!("authorization login initiated successfully");
        (url, auth_state)
    }

    /// Completes the flow by exchanging the code.
    /// If a mapper is provided, it will also map the identity to a local user.
    #[tracing::instrument(skip(self, code, expected_state), fields(provider_id = %self.provider.provider_id()))]
    pub async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &OAuth2State,
    ) -> Result<(Identity, OAuthToken, Option<M::LocalUser>), AuthError> {
        if received_state != expected_state.state {
            tracing::error!("CSRF mismatch: received state does not match expected state");
            return Err(AuthError::CsrfMismatch);
        }

        if self.use_pkce && expected_state.code_verifier.is_none() {
            tracing::error!(
                provider_id = %self.provider.provider_id(),
                "PKCE is enabled, but code_verifier was omitted from the expected state"
            );
            return Err(AuthError::InvalidInput);
        }

        tracing::debug!("exchanging code for identity");
        let (identity, token) = self
            .provider
            .exchange_code_for_identity(
                code,
                expected_state.code_verifier.as_deref(),
                expected_state.nonce.as_deref(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to exchange code for identity");
                e
            })?;

        tracing::info!(user_id = %identity.external_id, "successfully retrieved identity from provider");

        // Re-check the nonce only for a provider that surfaces it.
        //
        // This is a second line of defence: a provider that validates an ID
        // token has already compared the nonce itself. Plain OAuth2 has no ID
        // token, so there is nothing to surface and nothing to compare —
        // enforcing it there rejected every login, because
        // `identity.attributes` is necessarily empty of a nonce.
        //
        // The gate is on the check rather than on generation so that a
        // provider which forgets to advertise itself loses only this redundant
        // re-check, never the nonce itself.
        if self.provider.validates_nonce() {
            if let Some(expected_nonce) = expected_state.nonce.as_deref() {
                if identity.attributes.get("nonce").map(|s| s.as_str()) != Some(expected_nonce) {
                    tracing::error!("nonce mismatch or missing in identity attributes");
                    return Err(AuthError::Token("Nonce mismatch".to_string()));
                }
            }
        }

        let local_user = if let Some(mapper) = &self.mapper {
            tracing::debug!("mapping user identity");
            Some(mapper.map_user(&identity).await.map_err(|e| {
                tracing::error!(error = %e, "failed to map user");
                e
            })?)
        } else {
            None
        };

        Ok((identity, token, local_user))
    }

    /// Refresh an access token using a refresh token.
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError> {
        self.provider.refresh_token(refresh_token).await
    }

    /// Revoke an access token.
    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        self.provider.revoke_token(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Provider, ProviderConfig};
    use async_trait::async_trait;
    use std::collections::HashMap;

    struct MockProvider {
        id: String,
        auth_url: String,
        expected_code: String,
        identity: Identity,
        token: OAuthToken,
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn config(&self) -> ProviderConfig {
            ProviderConfig {
                id: self.id.clone(),
                name: self.id.clone(),
                extra: HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl OAuthProvider for MockProvider {
        fn provider_id(&self) -> &str {
            &self.id
        }

        fn get_authorization_url(
            &self,
            state: &str,
            _scopes: &[&str],
            _code_challenge: Option<&str>,
            _nonce: Option<&str>,
        ) -> String {
            format!("{}?state={}", self.auth_url, state)
        }

        async fn exchange_code_for_identity(
            &self,
            code: &str,
            _code_verifier: Option<&str>,
            _nonce: Option<&str>,
        ) -> Result<(Identity, OAuthToken), AuthError> {
            if code == self.expected_code {
                Ok((self.identity.clone(), self.token.clone()))
            } else {
                Err(AuthError::Token("Invalid code".to_string()))
            }
        }
    }

    #[tokio::test]
    async fn test_oauth2_flow_initiate() {
        let provider = MockProvider {
            id: "mock".to_string(),
            auth_url: "http://mock/auth".to_string(),
            expected_code: "code123".to_string(),
            identity: Identity {
                provider_id: "mock".to_string(),
                external_id: "1".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            },
            token: OAuthToken {
                access_token: "acc".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: None,
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        };

        let flow = OAuth2Flow::new(provider).with_scopes(vec!["scope1"]);
        let (url, state) = flow.initiate_login(&["scope2"], None);
        assert!(url.contains("http://mock/auth?state="));
        assert_eq!(state.provider_id, "mock");
    }

    #[tokio::test]
    async fn test_oauth2_flow_finalize_success() {
        let provider = MockProvider {
            id: "mock".to_string(),
            auth_url: "http://mock/auth".to_string(),
            expected_code: "code123".to_string(),
            identity: Identity {
                provider_id: "mock".to_string(),
                external_id: "1".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            },
            token: OAuthToken {
                access_token: "acc".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: None,
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        };

        let flow = OAuth2Flow::new(provider);
        let expected_state = OAuth2State {
            state: "state123".to_string(),
            nonce: None,
            code_verifier: Some("verifier123".to_string()),
            success_url: None,
            provider_id: "mock".to_string(),
            expires_at: 0,
        };

        let (ident, tok, _) = flow
            .finalize_login("code123", "state123", &expected_state)
            .await
            .unwrap();
        assert_eq!(ident.external_id, "1");
        assert_eq!(tok.access_token, "acc");
    }

    #[tokio::test]
    async fn test_oauth2_flow_finalize_csrf_mismatch() {
        let provider = MockProvider {
            id: "mock".to_string(),
            auth_url: "http://mock/auth".to_string(),
            expected_code: "code123".to_string(),
            identity: Identity {
                provider_id: "mock".to_string(),
                external_id: "1".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            },
            token: OAuthToken {
                access_token: "acc".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: None,
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        };

        let flow = OAuth2Flow::new(provider);
        let expected_state = OAuth2State {
            state: "state123".to_string(),
            nonce: None,
            code_verifier: None,
            success_url: None,
            provider_id: "mock".to_string(),
            expires_at: 0,
        };

        let result = flow
            .finalize_login("code123", "wrong_state", &expected_state)
            .await;
        assert!(matches!(result, Err(AuthError::CsrfMismatch)));
    }

    fn mock(id: &str) -> MockProvider {
        MockProvider {
            id: id.to_string(),
            auth_url: "http://mock/auth".to_string(),
            expected_code: "code123".to_string(),
            identity: Identity {
                provider_id: id.to_string(),
                external_id: "1".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            },
            token: OAuthToken {
                access_token: "acc".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: None,
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        }
    }

    /// A provider that behaves like an OIDC one: it surfaces the nonce it was
    /// given in `Identity::attributes`, which is what the engine re-checks.
    struct NonceEchoing {
        inner: MockProvider,
        /// What to surface. `None` means "echo whatever was received".
        echo_instead: Option<String>,
    }

    #[async_trait]
    impl Provider for NonceEchoing {
        async fn config(&self) -> ProviderConfig {
            self.inner.config().await
        }
    }

    #[async_trait]
    impl OAuthProvider for NonceEchoing {
        fn validates_nonce(&self) -> bool {
            true
        }

        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn get_authorization_url(
            &self,
            state: &str,
            scopes: &[&str],
            code_challenge: Option<&str>,
            nonce: Option<&str>,
        ) -> String {
            self.inner
                .get_authorization_url(state, scopes, code_challenge, nonce)
        }

        async fn exchange_code_for_identity(
            &self,
            code: &str,
            code_verifier: Option<&str>,
            nonce: Option<&str>,
        ) -> Result<(Identity, OAuthToken), AuthError> {
            let (mut identity, token) = self
                .inner
                .exchange_code_for_identity(code, code_verifier, nonce)
                .await?;
            let surfaced = self
                .echo_instead
                .clone()
                .or_else(|| nonce.map(|n| n.to_string()));
            if let Some(value) = surfaced {
                identity.attributes.insert("nonce".to_string(), value);
            }
            Ok((identity, token))
        }
    }

    /// The regression this fix is for: a plain OAuth2 provider returns an
    /// identity with no nonce attribute, because it has no ID token to carry
    /// one. Enforcing the re-check there rejected every login.
    #[tokio::test]
    async fn a_plain_provider_can_complete_a_login() {
        let flow = OAuth2Flow::new(mock("plain"));
        let (_url, state) = flow.initiate_login(&["email"], None);

        let result = flow.finalize_login("code123", &state.state, &state).await;

        assert!(
            result.is_ok(),
            "a plain OAuth2 login should complete; got {:?}",
            result.err()
        );
    }

    /// Every provider is still handed a nonce, whatever the flag says.
    ///
    /// This is why the gate is on the check and not on generation: an
    /// out-of-tree OIDC provider that never overrides `validates_nonce` still
    /// receives a nonce to validate, so it cannot lose replay protection by
    /// omission.
    #[test]
    fn every_provider_still_receives_a_nonce() {
        let plain = OAuth2Flow::new(mock("plain"));
        let (_url, state) = plain.initiate_login(&["email"], None);
        assert!(
            state.nonce.is_some(),
            "a provider that does not advertise itself must still get a nonce"
        );
    }

    /// And the re-check still bites where it applies: a provider that claims to
    /// surface the nonce but surfaces the wrong one must be rejected.
    #[tokio::test]
    async fn a_wrong_nonce_is_still_rejected() {
        let flow = OAuth2Flow::new(NonceEchoing {
            inner: mock("oidc"),
            echo_instead: Some("not-the-nonce".to_string()),
        });
        let (_url, state) = flow.initiate_login(&["email"], None);

        let result = flow.finalize_login("code123", &state.state, &state).await;

        assert!(
            result.is_err(),
            "gating the check must not disable it where a provider opts in"
        );
    }

    /// The happy path for such a provider.
    #[tokio::test]
    async fn a_matching_nonce_is_accepted() {
        let flow = OAuth2Flow::new(NonceEchoing {
            inner: mock("oidc"),
            echo_instead: None, // echo what was received
        });
        let (_url, state) = flow.initiate_login(&["email"], None);

        let result = flow.finalize_login("code123", &state.state, &state).await;

        assert!(
            result.is_ok(),
            "a correctly echoed nonce should pass; got {:?}",
            result.err()
        );
    }

    /// Verifies that `OAuth2Flow::initiate_login` automatically generates a PKCE
    /// verifier and challenge when PKCE is enabled and none is supplied by the caller.
    #[tokio::test]
    async fn test_pkce_auto_generation_when_none_provided() {
        let flow = OAuth2Flow::new(mock("plain"));
        assert!(flow.pkce_enabled());
        let (_url, state) = flow.initiate_login(&["email"], None);
        assert!(state.code_verifier.is_some());
        assert!(!state.code_verifier.as_ref().unwrap().is_empty());
    }

    /// Verifies that `OAuth2Flow::finalize_login` rejects state missing a PKCE verifier
    /// when PKCE is enabled, and permits it when PKCE is explicitly disabled.
    #[tokio::test]
    async fn test_pkce_rejected_in_finalize_when_verifier_missing() {
        let flow = OAuth2Flow::new(mock("plain"));
        let state = OAuth2State {
            state: "s1".to_string(),
            nonce: None,
            code_verifier: None,
            success_url: None,
            provider_id: "plain".to_string(),
            expires_at: 0,
        };
        let err = flow
            .finalize_login("code123", "s1", &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidInput));

        // When PKCE disabled, missing verifier is allowed
        let flow_no_pkce = OAuth2Flow::new(mock("plain")).with_pkce(false);
        assert!(!flow_no_pkce.pkce_enabled());
        let ok = flow_no_pkce.finalize_login("code123", "s1", &state).await;
        assert!(ok.is_ok());
    }
}
