use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The [`Identity::attributes`] key [`Engine::authenticate`](crate::Engine::authenticate)
/// stamps with the space-delimited list of internal auth-method names that
/// authenticated this identity (e.g. `"password"`, or `"password totp"`
/// after a completed step-up) — in the order they ran, primary first.
///
/// This is the same "thread flow-local data through `Identity` without
/// changing its shape" idiom already used for `"nonce"` (see
/// `authkestra_engine::flow::oauth2`): a plain `HashMap<String, String>`
/// entry rather than a new struct field, so registering a claim consumer
/// (like `authkestra-op`'s `acr`/`amr` derivation) never requires touching
/// every `Identity { .. }` literal in the workspace.
///
/// Absent for any `Identity` that did not come from `Engine::authenticate`
/// (an OAuth-provider-sourced identity, for instance) — there is deliberately
/// no fallback value, since fabricating one would assert an auth method that
/// was never actually verified.
pub const IDENTITY_ATTR_AMR: &str = "amr";

/// The [`AuthMethod`](crate::auth::AuthMethod) name this workspace's WebAuthn
/// method reports, and which therefore appears in [`IDENTITY_ATTR_AMR`].
///
/// Defined unconditionally, *not* behind `#[cfg(feature = "webauthn")]`. The
/// name is half of a wire contract — `authkestra-op` turns it into the `amr`
/// claim of an issued ID token — and the crate that does that translation
/// depends on this one without enabling the method features. A gated constant
/// would be invisible exactly where it is needed.
pub const METHOD_NAME_WEBAUTHN: &str = "webauthn";

/// The [`AuthMethod`](crate::auth::AuthMethod) name this workspace's TOTP
/// method reports. Unconditional for the reason given on
/// [`METHOD_NAME_WEBAUTHN`].
pub const METHOD_NAME_TOTP: &str = "totp";

/// The name conventionally used for a password [`AuthMethod`](crate::auth::AuthMethod).
///
/// Unlike the other two this names no built-in: the framework owns no user
/// table and ships no password method, so this is the spelling an
/// application's own method is expected to use if it wants the standard
/// mapping. It is listed here because the mapping exists and something has to
/// be the single source of the string.
pub const METHOD_NAME_PASSWORD: &str = "password";

/// The [`AuthMethod`](crate::auth::AuthMethod) name this workspace's
/// magic-link method reports. Unconditional for the reason given on
/// [`METHOD_NAME_WEBAUTHN`].
pub const METHOD_NAME_MAGIC_LINK: &str = "magic-link";

/// The [`AuthMethod`](crate::auth::AuthMethod) name this workspace's
/// delivered one-time code method reports. Unconditional for the reason given
/// on [`METHOD_NAME_WEBAUTHN`].
///
/// One name for both channels: the channel rides on the identity's attributes
/// instead, because it changes the `amr` claim but not which method ran.
pub const METHOD_NAME_OTP: &str = "otp";

/// The [`AuthMethod`](crate::auth::AuthMethod) name this workspace's recovery
/// code method reports. Unconditional for the reason given on
/// [`METHOD_NAME_WEBAUTHN`].
pub const METHOD_NAME_RECOVERY_CODE: &str = "recovery-code";

/// The [`Identity::attributes`] key naming the channel a one-time code
/// arrived on, set to [`OTP_CHANNEL_EMAIL`] or [`OTP_CHANNEL_SMS`].
///
/// Unconditional, like the method names and for the same reason: `amr`
/// derivation lives in `authkestra-op`, which depends on this crate without
/// enabling `otp` and never sees the challenge. It needs this key because
/// RFC 8176 registers `sms` as its own value, so an emailed code and a texted
/// one are not the same claim.
pub const IDENTITY_ATTR_OTP_CHANNEL: &str = "otp_channel";

/// [`IDENTITY_ATTR_OTP_CHANNEL`]'s value for a code delivered to a mailbox.
pub const OTP_CHANNEL_EMAIL: &str = "email";

/// [`IDENTITY_ATTR_OTP_CHANNEL`]'s value for a code delivered to a phone.
pub const OTP_CHANNEL_SMS: &str = "sms";

/// Every auth-method name this workspace assigns a deliberate `amr` meaning
/// to.
///
/// This exists to be iterated by a test, not by production code. Adding a
/// built-in method means adding its name here, which fails
/// `authkestra-op`'s `every_first_party_method_name_has_a_deliberate_mapping`
/// until that crate states what the new method should emit on the wire. That
/// is the whole point: the alternative is a new method silently inheriting
/// pass-through, which is right for some methods and wrong for others, with
/// nothing to distinguish them. See issue #395.
pub const FIRST_PARTY_METHOD_NAMES: &[&str] = &[
    METHOD_NAME_PASSWORD,
    METHOD_NAME_TOTP,
    METHOD_NAME_WEBAUTHN,
    METHOD_NAME_MAGIC_LINK,
    METHOD_NAME_OTP,
    METHOD_NAME_RECOVERY_CODE,
];

/// The [`Identity::attributes`] key set to the literal `"true"` when this
/// identity's authentication satisfies this engine's step-up tier: either a
/// step-up (MFA) challenge was actually completed, or the sole primary
/// [`AuthMethod`](crate::auth::AuthMethod) reported
/// [`is_mfa_equivalent`](crate::auth::AuthMethod::is_mfa_equivalent). Absent
/// (never `"false"`) otherwise. See [`IDENTITY_ATTR_AMR`] for why this lives
/// in `attributes` rather than as a named field.
pub const IDENTITY_ATTR_STEP_UP_SATISFIED: &str = "step_up_satisfied";

/// The [`Identity::attributes`] key
/// [`Engine::authenticate`](crate::Engine::authenticate) stamps with the Unix
/// timestamp (seconds) at which this identity's authentication *completed* —
/// the basis for OIDC's `auth_time` claim (OIDC Core §2).
///
/// For a login that completed a step-up challenge this is when the *step-up*
/// finished, not when the primary factor ran: `auth_time` exists to answer
/// "how recently did this user prove themselves", and a re-authentication
/// gate asking that question means the most recent proof, not the first one.
///
/// Because this rides on the `Identity` itself, it survives being persisted
/// alongside a refresh token and travels with it — so a token minted by the
/// refresh-token or token-exchange grant reports when the user originally
/// authenticated rather than when that later token was issued, which is what
/// `auth_time` is defined to mean.
///
/// Absent for any `Identity` that did not come from `Engine::authenticate`,
/// for the same reason as [`IDENTITY_ATTR_AMR`]: a fabricated timestamp would
/// assert a freshness nothing actually verified.
pub const IDENTITY_ATTR_AUTH_TIME: &str = "auth_time";

/// A unified identity structure returned by all providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The provider identifier (e.g., "github", "google")
    pub provider_id: String,
    /// The unique ID of the user within the provider's system
    pub external_id: String,
    /// The user's email address, if available and authorized
    pub email: Option<String>,
    /// The user's username or display name, if available
    pub username: Option<String>,
    /// Additional provider-specific attributes. Also the carrier for a few
    /// pieces of flow-local bookkeeping that don't warrant their own named
    /// field — see [`IDENTITY_ATTR_AMR`] and [`IDENTITY_ATTR_STEP_UP_SATISFIED`].
    pub attributes: HashMap<String, String>,
}

/// The result of an authentication attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthResult {
    /// Authentication complete, issue a full session.
    Success(Identity),
    /// Primary authentication succeeded, but a second factor is required.
    MfaRequired {
        /// A temporary, short-lived token to bind the MFA submission to this session
        mfa_token: String,
        /// The external ID of the user trying to login
        user_id: String,
        /// A list of allowed second factors for this user
        allowed_methods: Vec<String>,
    },
}

/// Claims inside the temporary MFA JWT token.
///
/// `#[non_exhaustive]`, so construct one with [`MfaTokenClaims::new`] rather
/// than a struct literal. This type gains a field whenever a new piece of
/// state has to survive the step-up continuation round-trip — `primary_method`
/// below is the most recent — and without the attribute every one of those
/// additions is a breaking change for downstream code that had nothing to do
/// with the new field. Reading and assigning fields is unaffected; only
/// literal construction and exhaustive destructuring are restricted.
///
/// This matches what the rest of the crate already does — see `Jwk`, which
/// was given the same treatment for the same reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MfaTokenClaims {
    /// Subject (the user ID)
    pub sub: String,
    /// Must be true for MFA tokens
    pub mfa_pending: bool,
    /// Expiration timestamp
    pub exp: usize,
    /// The internal name of the primary [`AuthMethod`](crate::auth::AuthMethod)
    /// (e.g. `"password"`) that authenticated `sub` before this step-up
    /// challenge was issued. Carried across the continuation round-trip so
    /// that when the second factor completes, `Engine::authenticate` can
    /// report the *whole* method chain — primary and step-up — as this
    /// identity's `amr`, not just the second factor. See
    /// [`IDENTITY_ATTR_AMR`].
    ///
    /// `#[serde(default)]` so that an MFA continuation token minted by a
    /// version before this field existed still decodes across an upgrade:
    /// without it, anyone mid-step-up when the new binary rolls out would
    /// get an opaque "missing field" rejection and have to restart the
    /// login. Such a token yields an empty string, which
    /// `Engine::authenticate` drops from the method chain rather than
    /// reporting as a method — so the resulting `amr` names only the
    /// step-up factor that this call actually verified.
    #[serde(default)]
    pub primary_method: String,
    /// The list of enrolled MFA method names offered when this challenge was minted.
    /// Used by `Engine::authenticate` to restrict continuation inputs to authorized second factors.
    #[serde(default, alias = "available_methods")]
    pub allowed_methods: Vec<String>,
}

impl MfaTokenClaims {
    /// Creates the claims for a step-up continuation token: `sub` is the user
    /// the primary factor authenticated, `exp` the token's expiry as a Unix
    /// timestamp, and `primary_method` the internal name of the
    /// [`AuthMethod`](crate::auth::AuthMethod) that ran first (see
    /// [`primary_method`](Self::primary_method)).
    ///
    /// `mfa_pending` is set to `true`, which is the only value a real MFA
    /// token carries — [`Engine::authenticate`](crate::Engine::authenticate)
    /// rejects a token whose `mfa_pending` is `false`. The field stays public
    /// so a test can still construct the rejected shape by assigning to it.
    pub fn new(sub: impl Into<String>, exp: usize, primary_method: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            mfa_pending: true,
            exp,
            primary_method: primary_method.into(),
            allowed_methods: Vec::new(),
        }
    }

    /// Sets the allowed second-factor methods for this continuation challenge.
    pub fn with_allowed_methods(mut self, methods: Vec<String>) -> Self {
        self.allowed_methods = methods;
        self
    }

    /// Alias for `with_allowed_methods`.
    pub fn with_available_methods(mut self, methods: Vec<String>) -> Self {
        self.allowed_methods = methods;
        self
    }

    /// Returns the allowed continuation methods.
    pub fn available_methods(&self) -> &[String] {
        &self.allowed_methods
    }
}

/// Represents the tokens returned by an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// The access token used for API requests
    pub access_token: String,
    /// The type of token (usually "Bearer")
    pub token_type: String,
    /// Seconds until the access token expires
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// The refresh token used to obtain new access tokens
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The scopes granted by the user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The OIDC ID Token
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// Intermediate state for OAuth2/OIDC flows, stored in an encrypted cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2State {
    /// CSRF protection state parameter
    pub state: String,
    /// OIDC nonce to prevent replay attacks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// PKCE code verifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    /// Optional redirect URL to go back to after flow completion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_url: Option<String>,
    /// The provider identifier
    pub provider_id: String,
    /// Expiration timestamp (seconds since epoch)
    pub expires_at: i64,
}

impl OAuth2State {
    /// Encrypts the state into a base64-encoded string.
    pub fn encrypt(&self, key: &[u8; 32]) -> Result<String, crate::auth::error::AuthError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let json = serde_json::to_vec(self).map_err(|e| {
            crate::auth::error::AuthError::Token(format!("Failed to serialize state: {e}"))
        })?;

        let ciphertext = cipher
            .encrypt(&nonce, json.as_slice())
            .map_err(|e| crate::auth::error::AuthError::Token(format!("Encryption failed: {e}")))?;

        let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            combined,
        ))
    }

    /// Decrypts the state from a base64-encoded string.
    pub fn decrypt(encoded: &str, key: &[u8; 32]) -> Result<Self, crate::auth::error::AuthError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let combined = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|e| {
                crate::auth::error::AuthError::Token(format!("Failed to decode base64 state: {e}"))
            })?;

        if combined.len() < 12 {
            return Err(crate::auth::error::AuthError::Token(
                "Invalid encrypted state".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce_arr: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
            crate::auth::error::AuthError::Token("Invalid nonce length".to_string())
        })?;
        let nonce = Nonce::from(nonce_arr);
        let cipher = Aes256Gcm::new(key.into());

        let decrypted = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| crate::auth::error::AuthError::Token(format!("Decryption failed: {e}")))?;

        let state: Self = serde_json::from_slice(&decrypted).map_err(|e| {
            crate::auth::error::AuthError::Token(format!("Failed to deserialize state: {e}"))
        })?;

        if chrono::Utc::now().timestamp() > state.expires_at {
            return Err(crate::auth::error::AuthError::Token(
                "State expired".to_string(),
            ));
        }

        Ok(state)
    }
}
