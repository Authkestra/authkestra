use crate::auth::session::{Session, SessionConfig, SessionStore};
use crate::auth::{AuthError, AuthInput, AuthMethod, AuthResult, ErasedOAuthFlow, Identity};
use crate::token::TokenManager;
use std::collections::HashMap;
use std::sync::Arc;

/// Marker for a missing component in the typestate pattern.
#[derive(Clone, Default, Debug)]
pub struct Missing;

/// Marker for a configured component in the typestate pattern.
#[derive(Clone, Debug)]
pub struct Configured<T>(pub T);

/// Trait for the session store state in the `Engine`.
pub trait SessionStoreState: Send + Sync + Clone {
    /// Returns the session store if configured.
    fn get_store(&self) -> Arc<dyn SessionStore>;
}

impl SessionStoreState for Configured<Arc<dyn SessionStore>> {
    fn get_store(&self) -> Arc<dyn SessionStore> {
        self.0.clone()
    }
}

/// Trait for the token manager state in the `Engine`.
pub trait TokenManagerState: Send + Sync + Clone {
    /// Returns the token manager if configured.
    fn get_manager(&self) -> Arc<TokenManager>;
}

impl TokenManagerState for Configured<Arc<TokenManager>> {
    fn get_manager(&self) -> Arc<TokenManager> {
        self.0.clone()
    }
}

/// The central orchestrator for Engine.
///
/// `Engine` ties together authentication methods, session management, and flows.
/// It is constructed using the [`EngineBuilder`] which uses the Typestate pattern
/// to ensure that certain methods are only available when the necessary components are configured.
pub struct Engine<S = Missing, T = Missing> {
    /// Map of registered OAuth providers.
    pub providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    /// Map of registered local authentication methods.
    pub auth_methods: HashMap<String, Arc<dyn AuthMethod>>,
    /// Map of methods explicitly registered for step-up (MFA) use.
    pub mfa_methods: HashMap<String, Arc<dyn AuthMethod>>,
    /// Internal secret for signing temporary MFA JWT tokens.
    pub mfa_jwt_secret: [u8; 32],
    /// The session storage backend.
    pub session_store: S,
    /// Configuration for session cookies.
    pub session_config: SessionConfig,
    /// Manager for JWT signing and verification.
    pub token_manager: T,
}

impl<S, T> Clone for Engine<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            providers: self.providers.clone(),
            auth_methods: self.auth_methods.clone(),
            mfa_methods: self.mfa_methods.clone(),
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: self.session_store.clone(),
            session_config: self.session_config.clone(),
            token_manager: self.token_manager.clone(),
        }
    }
}

impl Engine<Missing, Missing> {
    /// Start building a new `Engine`.
    pub fn builder() -> EngineBuilder<Missing, Missing> {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret);

        EngineBuilder {
            providers: HashMap::new(),
            auth_methods: HashMap::new(),
            mfa_methods: HashMap::new(),
            mfa_jwt_secret: secret,
            session_store: Missing,
            session_config: SessionConfig::default(),
            token_manager: Missing,
        }
    }
}

/// A builder for configuring and creating an [`Engine`] instance.
pub struct EngineBuilder<S = Missing, T = Missing> {
    providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    auth_methods: HashMap<String, Arc<dyn AuthMethod>>,
    mfa_methods: HashMap<String, Arc<dyn AuthMethod>>,
    mfa_jwt_secret: [u8; 32],
    session_store: S,
    session_config: SessionConfig,
    token_manager: T,
}

impl<S, T> EngineBuilder<S, T> {
    /// Register an OAuth provider flow.
    pub fn provider<F>(mut self, flow: F) -> Self
    where
        F: ErasedOAuthFlow + 'static,
    {
        let id = flow.provider_id();
        self.providers.insert(id, Arc::new(flow));
        self
    }

    /// Register a local authentication method.
    pub fn with_auth_method<M>(mut self, method: M) -> Self
    where
        M: AuthMethod + 'static,
    {
        self.auth_methods
            .insert(method.name().to_string(), Arc::new(method));
        self
    }

    /// Register a local authentication method to be used EXCLUSIVELY for step-up MFA challenges.
    pub fn with_mfa_method<M>(mut self, method: M) -> Self
    where
        M: AuthMethod + 'static,
    {
        self.mfa_methods
            .insert(method.name().to_string(), Arc::new(method));
        self
    }

    /// Register the TOTP authentication method.
    #[cfg(feature = "totp")]
    pub fn with_totp<C>(self, store: C) -> Self
    where
        C: crate::CredentialStore + 'static,
    {
        self.with_auth_method(crate::auth::totp::TotpAuthMethod::new(store))
    }

    /// Register the WebAuthn authentication method.
    #[cfg(feature = "webauthn")]
    pub fn with_webauthn<C>(self, webauthn: Arc<webauthn_rs::prelude::Webauthn>, store: C) -> Self
    where
        C: crate::CredentialStore + 'static,
    {
        self.with_auth_method(crate::auth::webauthn::WebAuthnAuthMethod::new(
            webauthn, store,
        ))
    }

    /// Set the session store.
    pub fn session_store(
        self,
        store: Arc<dyn SessionStore>,
    ) -> EngineBuilder<Configured<Arc<dyn SessionStore>>, T> {
        EngineBuilder {
            providers: self.providers,
            auth_methods: self.auth_methods,
            mfa_methods: self.mfa_methods,
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: Configured(store),
            session_config: self.session_config,
            token_manager: self.token_manager,
        }
    }

    /// Set the token manager.
    pub fn token_manager(
        self,
        manager: Arc<TokenManager>,
    ) -> EngineBuilder<S, Configured<Arc<TokenManager>>> {
        EngineBuilder {
            providers: self.providers,
            auth_methods: self.auth_methods,
            mfa_methods: self.mfa_methods,
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: self.session_store,
            session_config: self.session_config,
            token_manager: Configured(manager),
        }
    }

    /// Set the JWT secret for the default token manager.
    pub fn jwt_secret(self, secret: &[u8]) -> EngineBuilder<S, Configured<Arc<TokenManager>>> {
        self.token_manager(Arc::new(TokenManager::new(secret, None)))
    }

    /// Set the session configuration.
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    /// Build the `Engine`.
    pub fn build(self) -> Engine<S, T> {
        Engine {
            providers: self.providers,
            auth_methods: self.auth_methods,
            mfa_methods: self.mfa_methods,
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: self.session_store,
            session_config: self.session_config,
            token_manager: self.token_manager,
        }
    }
}

impl<S, T> Engine<S, T> {
    /// Attempt to authenticate a user.
    /// Returns `AuthResult::Success` if authentication is fully complete,
    /// or `AuthResult::MfaRequired` if a second factor is needed.
    // `input` is skipped, not merely unformatted: `AuthInput` carries
    // passwords and TOTP codes, and a span field would print them. The
    // method name is recorded instead, once it is known.
    #[tracing::instrument(
        skip(self, input),
        fields(auth_method = tracing::field::Empty, user_id = tracing::field::Empty)
    )]
    pub async fn authenticate(&self, input: AuthInput) -> Result<AuthResult, AuthError> {
        // Handle MFA Challenge Continuation
        if let AuthInput::MfaChallenge {
            mfa_token,
            challenge_input,
        } = input
        {
            // Verify MFA Token
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            // Stated rather than inherited, for the reason #350 gives: a
            // tolerance nobody wrote down is one nobody can review. This is
            // the last site that still took `jsonwebtoken`'s default
            // silently, and it matters more here than most — the 15-minute
            // TTL below is a deliberate bound on how long a half-completed
            // login stays resumable, and an unstated grace period quietly
            // widens it.
            //
            // The value is unchanged at `DEFAULT_LEEWAY_SECS`, so nothing
            // about today's behaviour moves. It is more tolerance than this
            // token needs, though: unlike an ID token or a client assertion,
            // this one is minted and verified by the same deployment with the
            // same secret, so the only clocks that can disagree belong to
            // instances of the same service. Tightening it is a deliberate
            // decision to make on its own, not a side effect of naming it.
            validation.leeway = crate::token::DEFAULT_LEEWAY_SECS;
            let token_data = jsonwebtoken::decode::<crate::auth::state::MfaTokenClaims>(
                &mfa_token,
                &jsonwebtoken::DecodingKey::from_secret(&self.mfa_jwt_secret),
                &validation,
            )
            .map_err(|e| {
                // The caller deliberately learns nothing beyond
                // `InvalidInput` — expired and forged must look alike from
                // outside. Server-side there is no such reason to discard
                // it, and "was that token stale or unsigned?" is the first
                // question anyone debugging a stalled second factor asks.
                tracing::warn!(error = %e, "MFA continuation token failed validation");
                AuthError::InvalidInput
            })?;

            if !token_data.claims.mfa_pending {
                tracing::warn!("token presented as an MFA continuation is not marked mfa_pending");
                return Err(AuthError::InvalidInput);
            }
            tracing::Span::current().record("user_id", token_data.claims.sub.as_str());
            tracing::debug!("resuming a login from a valid MFA continuation token");

            // Spelled with the shared constants rather than literals, so a
            // name here cannot drift from what the method's `name()` returns
            // and silently stop resolving.
            let method_name = match &*challenge_input {
                #[cfg(feature = "totp")]
                AuthInput::Totp { .. } => crate::auth::state::METHOD_NAME_TOTP,
                #[cfg(feature = "webauthn")]
                AuthInput::WebAuthnAuthentication { .. } => {
                    crate::auth::state::METHOD_NAME_WEBAUTHN
                }
                // A recovery code is a fallback *across* whichever factors an
                // account has, so it has to be dispatchable as a step-up.
                // Without this arm the enrolment probe below would advertise
                // it in `allowed_methods` — it reports `has_enrolled` true
                // whenever unredeemed codes exist — and then reject the reply
                // as `InvalidInput`, leaving the advertised fallback unusable
                // at precisely the moment somebody needs it.
                #[cfg(feature = "recovery-codes")]
                AuthInput::RecoveryCode { .. } => crate::auth::state::METHOD_NAME_RECOVERY_CODE,
                _ => "",
            };

            if method_name.is_empty() {
                tracing::warn!(
                    "MFA challenge carries an input that maps to no second factor \
                     this engine dispatches"
                );
                return Err(AuthError::InvalidInput);
            }
            tracing::Span::current().record("auth_method", method_name);

            if !token_data.claims.primary_method.is_empty()
                && token_data.claims.primary_method == method_name
            {
                tracing::warn!(
                    method = method_name,
                    primary_method = %token_data.claims.primary_method,
                    "MFA continuation attempted with the same method as primary authentication"
                );
                return Err(AuthError::InvalidInput);
            }

            if !token_data.claims.allowed_methods.is_empty()
                && !token_data
                    .claims
                    .allowed_methods
                    .iter()
                    .any(|m| m == method_name)
            {
                tracing::warn!(
                    method = method_name,
                    allowed_methods = ?token_data.claims.allowed_methods,
                    "MFA continuation method is not in allowed methods for this challenge"
                );
                return Err(AuthError::InvalidInput);
            }

            let method = self
                .auth_methods
                .get(method_name)
                .or_else(|| self.mfa_methods.get(method_name))
                .ok_or_else(|| {
                    tracing::error!(
                        method = method_name,
                        "MFA method is not registered on this engine"
                    );
                    AuthError::Internal(format!("MFA method {} not registered", method_name))
                })?;

            let mut identity = method.authenticate(*challenge_input).await.map_err(|e| {
                tracing::warn!(error = %e, method = method_name, "second factor rejected");
                e
            })?;

            if identity.external_id != token_data.claims.sub {
                // The second factor verified, but for a different user than
                // the one the continuation token was minted for.
                tracing::warn!(
                    token_sub = %token_data.claims.sub,
                    verified_user = %identity.external_id,
                    "second factor verified a different user than the MFA token names"
                );
                return Err(AuthError::Credentials("MFA token user mismatch".into()));
            }

            // Report the whole method chain — primary, carried across the
            // continuation round-trip in the MFA token, plus this step-up
            // factor — as `amr`, not just the factor that ran in this call.
            // A completed step-up always satisfies this engine's (binary)
            // step-up tier, regardless of which two methods were involved.
            // An empty `primary_method` means this token predates that field
            // (see `MfaTokenClaims::primary_method`) — we genuinely don't know
            // what ran first, so report only the factor this call verified
            // rather than inventing one or emitting an empty `amr` entry.
            let mut amr_methods = Vec::new();
            if !token_data.claims.primary_method.is_empty() {
                amr_methods.push(token_data.claims.primary_method.clone());
            }
            if token_data.claims.primary_method != method_name {
                amr_methods.push(method_name.to_string());
            }
            identity.attributes.insert(
                crate::auth::state::IDENTITY_ATTR_AMR.to_string(),
                amr_methods.join(" "),
            );
            identity.attributes.insert(
                crate::auth::state::IDENTITY_ATTR_STEP_UP_SATISFIED.to_string(),
                "true".to_string(),
            );
            // The step-up is what just completed, so it — not the earlier
            // primary factor — is when this user most recently proved
            // themselves. See `IDENTITY_ATTR_AUTH_TIME`.
            identity.attributes.insert(
                crate::auth::state::IDENTITY_ATTR_AUTH_TIME.to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );

            tracing::info!(
                method = method_name,
                "authentication completed via second factor"
            );
            return Ok(AuthResult::Success(identity));
        }

        // Primary Authentication
        let method_name = match &input {
            AuthInput::Password { .. } => "password",
            #[cfg(feature = "totp")]
            AuthInput::Totp { .. } => "totp", // Could theoretically be used as primary
            #[cfg(feature = "webauthn")]
            AuthInput::WebAuthnAuthentication { .. } => "webauthn",
            _ => "",
        };

        if method_name.is_empty() {
            tracing::warn!("authentication input maps to no primary method");
            return Err(AuthError::InvalidInput);
        }
        tracing::Span::current().record("auth_method", method_name);
        tracing::debug!("dispatching primary authentication");

        let method = self.auth_methods.get(method_name).ok_or_else(|| {
            // A configuration fault, not a credential one: the input named a
            // method this engine was never given. Distinguishing the two is
            // the point of logging it at `error!` rather than `warn!`.
            tracing::error!(
                method = method_name,
                "primary auth method is not registered, or is registered as step-up only"
            );
            AuthError::Internal(format!(
                "Primary auth method {} not registered or is step-up only",
                method_name
            ))
        })?;

        let mut identity = method.authenticate(input).await.map_err(|e| {
            tracing::warn!(error = %e, "primary authentication rejected");
            e
        })?;
        tracing::Span::current().record("user_id", identity.external_id.as_str());
        tracing::debug!("primary authentication succeeded; checking for enrolled second factors");

        // Check if user has MFA enrolled
        let mut enrolled_methods = Vec::new();
        for (name, m) in self.auth_methods.iter().chain(self.mfa_methods.iter()) {
            if name == "password" || name == method_name {
                continue;
            }
            if !enrolled_methods.contains(name)
                && m.has_enrolled(&identity.external_id).await.map_err(|e| {
                    tracing::error!(
                        error = %e,
                        method = %name,
                        user_id = %identity.external_id,
                        "failed to check MFA enrollment status in credential store"
                    );
                    e
                })?
            {
                enrolled_methods.push(name.clone());
            }
        }

        // If this method was already an MFA method (e.g. WebAuthn primary), we don't prompt for MFA again.
        // Or if the user has no other MFA methods enrolled.
        if enrolled_methods.is_empty() || method.is_mfa_equivalent() {
            // Two quite different reasons to skip the second factor, and an
            // operator asked "why was MFA not enforced for this user?" needs
            // to know which one applied.
            tracing::info!(
                mfa_equivalent = method.is_mfa_equivalent(),
                enrolled_methods = enrolled_methods.len(),
                "authentication completed without a second factor"
            );
            identity.attributes.insert(
                crate::auth::state::IDENTITY_ATTR_AMR.to_string(),
                method_name.to_string(),
            );
            identity.attributes.insert(
                crate::auth::state::IDENTITY_ATTR_AUTH_TIME.to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );
            if method.is_mfa_equivalent() {
                // No step-up ran, but the sole primary method already
                // provides step-up-equivalent assurance (e.g. this engine's
                // built-in WebAuthn), so the binary step-up tier is still
                // satisfied.
                identity.attributes.insert(
                    crate::auth::state::IDENTITY_ATTR_STEP_UP_SATISFIED.to_string(),
                    "true".to_string(),
                );
            }
            Ok(AuthResult::Success(identity))
        } else {
            // Issue MFA Token
            let exp = chrono::Utc::now() + chrono::Duration::minutes(15);
            let claims = crate::auth::state::MfaTokenClaims::new(
                identity.external_id.clone(),
                exp.timestamp() as usize,
                method_name,
            )
            .with_allowed_methods(enrolled_methods.clone());

            let mfa_token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(&self.mfa_jwt_secret),
            )
            // Not covered by a test, and deliberately so: HS256 signing
            // with a fixed 32-byte secret has no reachable failure mode, so
            // exercising this would mean contriving one. It is logged rather
            // than dropped because if it ever does fire, the login has
            // failed for a reason nothing else would explain.
            .map_err(|e| {
                tracing::error!(error = %e, "failed to mint the MFA continuation token");
                AuthError::Internal(e.to_string())
            })?;

            tracing::info!(
                allowed_methods = ?enrolled_methods,
                "primary authentication succeeded; a second factor is required"
            );
            Ok(AuthResult::MfaRequired {
                mfa_token,
                user_id: identity.external_id,
                allowed_methods: enrolled_methods,
            })
        }
    }

    /// Starts a WebAuthn authentication ceremony for a list of enrolled passkeys.
    #[cfg(feature = "webauthn")]
    pub fn start_webauthn(
        &self,
        passkeys: &[webauthn_rs::prelude::Passkey],
    ) -> Result<
        (
            webauthn_rs::prelude::RequestChallengeResponse,
            webauthn_rs::prelude::PasskeyAuthentication,
        ),
        AuthError,
    > {
        let method = self
            .auth_methods
            .get("webauthn")
            .ok_or_else(|| AuthError::Internal("WebAuthn method not registered".into()))?;

        let webauthn_starter = method.as_webauthn_starter().ok_or_else(|| {
            AuthError::Internal("WebAuthn method doesn't implement starter".into())
        })?;

        webauthn_starter.start_authentication(passkeys)
    }
}

// Methods available only when a session store is present
impl<T> Engine<Configured<Arc<dyn SessionStore>>, T> {
    /// Get the session store.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        self.session_store.0.clone()
    }

    /// Create a new session for the given identity.
    #[tracing::instrument(skip(self, identity), fields(user_id = %identity.external_id))]
    pub async fn create_session(&self, identity: Identity) -> Result<Session, AuthError> {
        let session_duration = self
            .session_config
            .max_age
            .unwrap_or(chrono::Duration::hours(24));
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            identity,
            expires_at: chrono::Utc::now() + session_duration,
        };

        tracing::debug!("creating new session");

        self.session_store
            .0
            .save_session(&session)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to save session");
                AuthError::Session(e.to_string())
            })?;

        tracing::info!("session created successfully");
        Ok(session)
    }
}

impl<S> Engine<S, Configured<Arc<TokenManager>>> {
    /// Get the token manager.
    pub fn token_manager(&self) -> Arc<TokenManager> {
        self.token_manager.0.clone()
    }

    /// Issue a JWT for the given identity.
    #[tracing::instrument(skip(self, identity), fields(user_id = %identity.external_id))]
    pub fn issue_token(
        &self,
        identity: Identity,
        expires_in_secs: u64,
    ) -> Result<String, AuthError> {
        tracing::debug!("issuing token for user");
        self.token_manager
            .0
            .issue_user_token(identity, expires_in_secs, None, None)
            .map_err(|e| {
                tracing::error!(error = %e, "failed to issue token");
                AuthError::Token(e.to_string())
            })
            .inspect(|_| {
                tracing::info!("token issued successfully");
            })
    }
}

/// Trait for Engine instances that have a session store configured.
pub trait HasSessionStore {
    /// Returns the session store.
    fn session_store(&self) -> Arc<dyn SessionStore>;
}

impl<T> HasSessionStore for Engine<Configured<Arc<dyn SessionStore>>, T> {
    fn session_store(&self) -> Arc<dyn SessionStore> {
        self.session_store.0.clone()
    }
}

/// Trait for Engine instances that have a token manager configured.
pub trait HasTokenManager {
    /// Returns the token manager.
    fn token_manager(&self) -> Arc<TokenManager>;
}

impl<S> HasTokenManager for Engine<S, Configured<Arc<TokenManager>>> {
    fn token_manager(&self) -> Arc<TokenManager> {
        self.token_manager.0.clone()
    }
}
