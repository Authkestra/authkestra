use crate::auth::{error::AuthError, state::Identity};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod cert_binding;
pub mod dpop;
pub mod dpop_nonce;
pub mod sd_jwt;

/// The `aud` (audience) claim, per RFC 7519 §4.1.3: either a single
/// case-sensitive string, or a JSON array of such strings.
///
/// `#[serde(untagged)]` tries variants in declaration order on
/// deserialization, so a bare JSON string matches [`Audience::Single`]
/// first, and only a JSON array falls through to [`Audience::Multiple`].
/// Serialization is not affected by declaration order — each variant
/// serializes as its own shape — so a token minted with a single audience
/// still serializes as a bare string, not a one-element array, matching
/// every token this crate has ever issued.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /// True if `value` is present in this audience, whichever shape it was
    /// deserialized from. This is the "matches ANY" membership test that
    /// replaces exact-string-equality comparisons against `aud`.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::Single(s) => s == value,
            Audience::Multiple(values) => values.iter().any(|s| s == value),
        }
    }
}

/// Renders the audience for logging and display: a single audience as the
/// bare string, multiple as comma-separated values.
///
/// This exists so that code reading an `aud` claim has an ergonomic path
/// back to a string. Without it, every `format!("{}", claims.aud)` and
/// `tracing::info!(aud = %claims.aud)` at a call site that previously held
/// a `String` is a hard compile error with no one-line replacement. Use
/// [`Audience::contains`] for membership tests — do **not** parse this
/// output back apart, since an audience value may itself contain a comma.
impl std::fmt::Display for Audience {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Audience::Single(s) => f.write_str(s),
            Audience::Multiple(values) => {
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(value)?;
                }
                Ok(())
            }
        }
    }
}

/// Compares against a single audience string, so `claims.aud == "client"`
/// keeps compiling where `aud` used to be a `String`. Note this is exact
/// equality against a *single*-valued audience, not membership — a
/// [`Audience::Multiple`] never equals a bare `str`, even one it contains.
/// Use [`Audience::contains`] when you mean "is this one of the audiences".
impl PartialEq<str> for Audience {
    fn eq(&self, other: &str) -> bool {
        matches!(self, Audience::Single(s) if s == other)
    }
}

impl PartialEq<&str> for Audience {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<String> for Audience {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl From<String> for Audience {
    fn from(value: String) -> Self {
        Audience::Single(value)
    }
}

impl From<&str> for Audience {
    fn from(value: &str) -> Self {
        Audience::Single(value.to_string())
    }
}

/// Removes a caller-supplied `jti` from `extra`, if present as a JSON
/// string, so it can be assigned to the named `Claims::jti` field instead
/// of staying in the flattened `extra` map. Falls back to a generated
/// UUIDv4 when `extra` has no usable `"jti"` entry — either absent, or
/// present but not a JSON string (RFC 7519 §4.1.7 requires `jti` to be a
/// string).
///
/// This is the fix for #212: `Claims::extra` is `#[serde(flatten)]`ed
/// alongside the named `jti` field, so a `"jti"` entry left in `extra`
/// would serialize twice under the same key — a payload `TokenManager`
/// could mint but never decode again (`serde_json` hard-errors on a
/// literal duplicate field, flattened or not). Removing the key here,
/// unconditionally, guarantees the wire payload can never carry two `jti`
/// entries, and doubles as the override mechanism: a caller who needs a
/// non-UUID id format (e.g. CUID2) supplies it via `extra["jti"]` and it
/// is used verbatim.
fn take_jti(extra: &mut HashMap<String, serde_json::Value>) -> String {
    match extra.remove("jti") {
        Some(serde_json::Value::String(jti)) => jti,
        _ => uuid::Uuid::new_v4().to_string(),
    }
}

/// Every named field [`Claims`] serializes at the top level of the JWT
/// payload. `Claims::extra` is `#[serde(flatten)]`ed alongside them, so any
/// of these names *also* appearing in `extra` gets written twice under the
/// same key.
///
/// `jti` is deliberately **absent**: [`take_jti`] removes it from `extra`
/// before any collision check runs, which makes it a supported override
/// rather than a collision (#212).
///
/// `identity` **is** included even though it is
/// `skip_serializing_if = "Option::is_none"`, so an `extra["identity"]`
/// only duplicates on the paths that actually carry an identity. Rejecting
/// it unconditionally keeps one rule for every constructor instead of one
/// that silently depends on which `issue_*` was called; on the paths where
/// it does not duplicate, `extra["identity"]` is captured by the named
/// field on the way back in anyway, never by `extra`, so nothing could
/// have been reading it from where it was put.
pub(crate) const NAMED_CLAIM_FIELDS: &[&str] = &[
    "iss", "sub", "aud", "exp", "iat", "nbf", "scope", "identity",
];

/// Rejects any `extra` key that collides with a named [`Claims`] field.
///
/// This is the fix for #283, the general case #212 left open. `#212` only
/// removed `jti`; every other name in [`NAMED_CLAIM_FIELDS`] still
/// serialized twice, producing a payload `encode` accepts but no
/// `serde_json`-based decoder — including this crate's own
/// [`TokenManager::validate_token`] — can read back, because `serde_json`
/// hard-errors on a literal duplicate field whether or not it arrived via
/// a flattened map.
///
/// Failing here, at issuance, rather than silently stripping the keys is
/// the deliberate choice: the natural adapter for an embedder with an
/// existing typed claims struct is `extra = serde_json::to_value(&claims)?`,
/// which collides on `iss`/`sub`/`aud` and is silently wrong. Left to
/// strip, that mistake becomes a token missing the claims its author
/// believed it set; left as-is, it becomes every resource server rejecting
/// every token, diagnosed a process away from its cause. Returning an
/// error puts the failure at the call site that caused it.
///
/// All collisions are reported at once, in [`NAMED_CLAIM_FIELDS`]
/// declaration order, so the message is deterministic despite `extra`
/// being a [`HashMap`] and so a caller flattening a whole struct fixes
/// every key in one pass instead of one error at a time.
fn reject_named_claim_collisions(
    extra: &HashMap<String, serde_json::Value>,
) -> Result<(), AuthError> {
    let collisions: Vec<&str> = NAMED_CLAIM_FIELDS
        .iter()
        .copied()
        .filter(|name| extra.contains_key(*name))
        .collect();

    if collisions.is_empty() {
        return Ok(());
    }

    let joined = collisions.join(", ");
    tracing::warn!(
        colliding_keys = %joined,
        "rejecting token issuance: `extra` keys collide with named Claims fields"
    );
    Err(AuthError::Token(format!(
        "extra claim key(s) [{joined}] collide with named claims and would be serialized \
         twice, producing a token that cannot be decoded again; remove them from `extra` \
         (`jti` is the one supported override)"
    )))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct Claims {
    // Standard OIDC claims
    pub iss: Option<String>,
    pub sub: String,
    pub aud: Option<Audience>,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    pub jti: Option<String>,

    // Engine-specific core fields
    pub scope: Option<String>,
    /// Optional identity data for user-centric tokens.
    /// If None, this is likely a machine-to-machine token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,

    // Isolated custom claims
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Clock-skew allowance applied to `exp` and `nbf` when validating a JWT, in
/// seconds.
///
/// A token is accepted for this long *after* its `exp`, and this long *before*
/// its `nbf`, absorbing the disagreement between the issuer's clock and the
/// validator's. Sixty seconds is `jsonwebtoken`'s own default, which this
/// crate used implicitly — and silently — before it was named here (#350).
///
/// It is a single constant, and `authkestra-resource`'s [`ValidationConfig`]
/// defaults to it too, so the tolerance is stated once rather than restated
/// per validation site. Downstream code that needs to size a token's lifetime
/// against it can name it instead of hardcoding 60.
///
/// [`ValidationConfig`]: https://docs.rs/authkestra-resource
pub const DEFAULT_LEEWAY_SECS: u64 = 60;

#[derive(Clone)]
#[non_exhaustive]
pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: Option<String>,
    kid: Option<String>,
    alg: Algorithm,
    public_jwk: Option<crate::token::jwk::Jwk>,
    /// Clock-skew allowance for `exp`/`nbf`, in seconds. See
    /// [`TokenManager::with_leeway`].
    leeway: u64,
}

impl TokenManager {
    /// Creates a TokenManager for symmetric signing (HS256).
    pub fn new(secret: &[u8], issuer: Option<String>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer,
            kid: None,
            alg: Algorithm::HS256,
            public_jwk: None,
            leeway: DEFAULT_LEEWAY_SECS,
        }
    }

    /// Creates a TokenManager for asymmetric signing (RS256).
    /// `private_key_pem` must be a valid RSA private key in PEM format.
    /// OP/external verification should use this path; internal resource servers
    /// can continue to use `new` (HS256).
    pub fn new_asymmetric(
        private_key_pem: &[u8],
        issuer: Option<String>,
        kid: Option<String>,
    ) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|_| AuthError::Token("Invalid PEM UTF-8".into()))?;

        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem_str))
            .map_err(|e| AuthError::Token(format!("Failed to parse RSA key: {}", e)))?;

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use rsa::traits::PublicKeyParts;

        let n = URL_SAFE_NO_PAD.encode(rsa_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(rsa_key.e().to_bytes_be());

        let kid_val = kid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // `use` is declared explicitly so a relying party enforcing RFC 7517
        // §4.2 key-use separation (as this crate's own `Jwks::find_key` now
        // does) sees what this key is for instead of having to assume.
        let jwk = crate::token::jwk::Jwk::rsa(n, e)
            .with_kid(kid_val.clone())
            .with_alg("RS256")
            .with_use("sig");

        // The decoding key must come from the PUBLIC half. `DecodingKey::from_rsa_pem`
        // expects a public-key PEM; handed a private one it still constructs, but every
        // later `validate_token` fails with `InvalidSignature`. Deriving it from the JWK
        // we just built keeps both halves provably in sync with what `/jwks` publishes.
        let decoding_key = jwk.to_decoding_key()?;

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
            kid: Some(kid_val),
            alg: Algorithm::RS256,
            public_jwk: Some(jwk),
            leeway: DEFAULT_LEEWAY_SECS,
        })
    }

    /// Creates a TokenManager for asymmetric signing with Ed25519 (EdDSA).
    /// `private_key_pem` must be a valid Ed25519 private key in PKCS#8 PEM
    /// format (`-----BEGIN PRIVATE KEY-----`), e.g. as produced by
    /// `openssl genpkey -algorithm ed25519`.
    ///
    /// Mirrors `new_asymmetric` (RS256): OP/external verification should use
    /// this path when downstream resource servers require EdDSA-signed
    /// tokens; internal resource servers can continue to use `new` (HS256).
    /// The published JWK (`public_jwk`) is the OKP shape from RFC 8037, so
    /// pair this with #188 (`Jwk`'s OKP support) to publish a verifiable
    /// `/jwks.json` for the resulting deployment.
    pub fn new_ed25519(
        private_key_pem: &[u8],
        issuer: Option<String>,
        kid: Option<String>,
    ) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_ed_pem(private_key_pem)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|_| AuthError::Token("Invalid PEM UTF-8".into()))?;

        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem_str)
            .map_err(|e| AuthError::Token(format!("Failed to parse Ed25519 key: {}", e)))?;

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

        let kid_val = kid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Same `use` rationale as `new_asymmetric`.
        let jwk = crate::token::jwk::Jwk::ed25519(x)
            .with_kid(kid_val.clone())
            .with_alg("EdDSA")
            .with_use("sig");

        // Same rationale as `new_asymmetric`: derive the decoding key from
        // the JWK we just built (the public half) rather than from the
        // private PEM, so both provably agree with what `/jwks` publishes.
        // See the regression note on that constructor and the test below
        // named after it.
        let decoding_key = jwk.to_decoding_key()?;

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
            kid: Some(kid_val),
            alg: Algorithm::EdDSA,
            public_jwk: Some(jwk),
            leeway: DEFAULT_LEEWAY_SECS,
        })
    }

    /// Sets the clock-skew allowance applied to `exp` and `nbf` when
    /// validating, in seconds.
    ///
    /// Defaults to [`DEFAULT_LEEWAY_SECS`] (60), which is what this crate
    /// inherited from `jsonwebtoken` before the value was ever named (#350).
    /// A token therefore keeps validating for about a minute past its `exp`
    /// unless this is lowered.
    ///
    /// Set it to `0` when the issuer and the validator share a clock, or in a
    /// test that asserts a token is rejected once it expires — with the
    /// default, "issue a one-second token, sleep, assert rejection" passes
    /// when it should fail, and the time goes into looking for a bug that
    /// isn't there.
    ///
    /// ```
    /// # use authkestra_engine::token::TokenManager;
    /// let manager = TokenManager::new(b"secret", None).with_leeway(0);
    /// ```
    ///
    /// Raising it instead widens the window in which an expired token is
    /// still honoured, so it trades revocation latency for tolerance of
    /// badly-synchronised clocks.
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = seconds;
        self
    }

    /// The configured clock-skew allowance, in seconds.
    pub fn leeway(&self) -> u64 {
        self.leeway
    }

    pub fn public_jwk(&self) -> Option<crate::token::jwk::Jwk> {
        self.public_jwk.clone()
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// The issuer this manager stamps on the tokens it issues and requires on the tokens it
    /// validates, when one is configured.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Issues a token for a user identity.
    pub fn issue_user_token(
        &self,
        identity: Identity,
        expires_in_secs: u64,
        scope: Option<String>,
        aud: Option<String>,
    ) -> Result<String, AuthError> {
        self.issue_user_token_with_extra(identity, expires_in_secs, scope, aud, HashMap::new())
    }

    /// Issues an RFC 9068 access token from `issuer` for a client and its configured audiences.
    ///
    /// The issuer is passed in rather than read from the manager because RFC 9068 requires `iss`
    /// on every access token, while a manager may have been built without one: the caller (an
    /// OpenID Provider) always knows its own.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_access_token(
        &self,
        issuer: &str,
        identity: Identity,
        client_id: &str,
        audience: Audience,
        expires_in_secs: u64,
        scope: Option<String>,
        mut extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let audience_count = match &audience {
            Audience::Single(_) => 1,
            Audience::Multiple(audiences) => audiences.len(),
        };
        tracing::debug!(
            audience_count,
            has_key_id = self.kid.is_some(),
            "Issuing RFC 9068 access token"
        );
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;
        let jti = take_jti(&mut extra);
        extra.insert("client_id".to_string(), client_id.into());
        reject_named_claim_collisions(&extra)?;

        let claims = Claims {
            iss: Some(issuer.to_string()),
            sub: identity.external_id.clone(),
            aud: Some(audience),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(jti),
            scope,
            identity: Some(identity),
            extra,
        };

        let mut header = Header::new(self.alg);
        header.typ = Some("at+jwt".to_string());
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues a token for a user identity, stamping the given `extra` claims
    /// onto the token in addition to the standard/core claims.
    ///
    /// This lets a host application (e.g. a resource server built on top of
    /// this engine) attach domain-specific claims — such as `api_key_id`,
    /// `project_id`, or `roles` — so downstream consumers (an API gateway or
    /// authorization proxy) can read them directly off the token without a
    /// database round-trip. Keys in `extra` take precedence over any
    /// same-named field set elsewhere in `extra` by this method.
    ///
    /// # Errors
    ///
    /// `extra` **cannot** override the top-level standard claims, and
    /// trying is an error rather than a silent no-op: if `extra` contains
    /// any of [`NAMED_CLAIM_FIELDS`] (`iss`, `sub`, `aud`, `exp`, `iat`,
    /// `nbf`, `scope`, `identity`) this returns
    /// [`AuthError::Token`] naming every colliding key, and mints nothing.
    /// Those names are `#[serde(flatten)]`-adjacent to the named `Claims`
    /// fields, so letting them through would serialize each twice and
    /// produce a token this crate could sign but never decode (#283). If
    /// you are flattening an existing claims struct into `extra`, strip
    /// those keys first — the standard claims are set from this method's
    /// own parameters.
    ///
    /// `jti` is the one supported override: if `extra["jti"]` is a JSON
    /// string, it is removed from `extra` and used verbatim as the token's
    /// `jti` claim instead of a generated UUIDv4 — see [`take_jti`] for why
    /// this has to happen this way rather than leaving the key in `extra`.
    /// `nbf` (not-before, set to issuance time) and `identity` are
    /// unconditional parts of this token's contract and have no opt-out.
    pub fn issue_user_token_with_extra(
        &self,
        identity: Identity,
        expires_in_secs: u64,
        scope: Option<String>,
        aud: Option<String>,
        mut extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;
        let jti = take_jti(&mut extra);
        reject_named_claim_collisions(&extra)?;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub: identity.external_id.clone(),
            aud: aud.map(Audience::from),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(jti),
            scope,
            identity: Some(identity),
            extra,
        };

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues an OIDC-conformant ID token.
    pub fn issue_id_token(
        &self,
        identity: Identity,
        client_id: &str,
        nonce: Option<String>,
        expires_in_secs: u64,
    ) -> Result<String, AuthError> {
        self.issue_id_token_with_extra(identity, client_id, nonce, expires_in_secs, HashMap::new())
    }

    /// Issues an OIDC-conformant ID token, stamping the given `extra` claims
    /// onto the token in addition to the standard/core claims.
    ///
    /// `nonce` is a reserved claim key: `extra` is merged into the token
    /// first, then the explicit `nonce` parameter is applied on top. So if
    /// `nonce` is `Some(_)`, it always wins over any `"nonce"` entry passed
    /// in `extra`. If `nonce` is `None`, an `extra["nonce"]` value (if any)
    /// is left as-is. This preserves OIDC `nonce` semantics — it reflects
    /// what the client sent in the authorization request — and keeps it from
    /// being accidentally clobbered by unrelated custom claims.
    ///
    /// `jti` is likewise reserved: see
    /// [`Self::issue_user_token_with_extra`] for how `extra["jti"]`
    /// overrides the generated one. `nbf` and `identity` are unconditional
    /// on this path too, with no opt-out.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Token`] without minting anything if `extra`
    /// carries a key that collides with a named `Claims` field — see
    /// [`Self::issue_user_token_with_extra`] for the full rule and why it
    /// is an error rather than a silent strip.
    pub fn issue_id_token_with_extra(
        &self,
        identity: Identity,
        client_id: &str,
        nonce: Option<String>,
        expires_in_secs: u64,
        mut extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;
        let jti = take_jti(&mut extra);
        reject_named_claim_collisions(&extra)?;

        let mut claims = Claims {
            iss: self.issuer.clone(),
            sub: identity.external_id.clone(),
            aud: Some(Audience::from(client_id)),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(jti),
            scope: None,
            identity: Some(identity),
            extra,
        };

        if let Some(n) = nonce {
            claims
                .extra
                .insert("nonce".to_string(), serde_json::Value::String(n));
        }

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues a machine-to-machine (M2M) token for a client.
    pub fn issue_client_token(
        &self,
        client_id: &str,
        expires_in_secs: u64,
        scope: Option<String>,
        aud: Option<String>,
    ) -> Result<String, AuthError> {
        self.issue_client_token_with_extra(client_id, expires_in_secs, scope, aud, HashMap::new())
    }

    /// Issues a machine-to-machine (M2M) token for a client, stamping the
    /// given `extra` claims onto the token in addition to the standard/core
    /// claims. See [`Self::issue_user_token_with_extra`] for the rationale,
    /// including the `extra["jti"]` override.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Token`] without minting anything if `extra`
    /// carries a key that collides with a named `Claims` field — see
    /// [`Self::issue_user_token_with_extra`].
    pub fn issue_client_token_with_extra(
        &self,
        client_id: &str,
        expires_in_secs: u64,
        scope: Option<String>,
        aud: Option<String>,
        mut extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;
        let jti = take_jti(&mut extra);
        reject_named_claim_collisions(&extra)?;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub: client_id.to_string(),
            aud: aud.map(Audience::from),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(jti),
            scope,
            identity: None,
            extra,
        };

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues a token with an explicit `typ` header and no `aud`, for
    /// callers minting something that is not a standard OIDC ID/access/user
    /// token and needs its own wire-format `typ` so verifiers can tell it
    /// apart from those (e.g. `authkestra-op`'s device/service attestations,
    /// whose contract requires `typ: "webank-attest+jws"` rather than the
    /// default `"JWT"`). Additive alongside the `issue_*_token*` family
    /// above; those are unchanged. `extra["jti"]` is honored the same way
    /// as [`Self::issue_user_token_with_extra`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Token`] without minting anything if `extra`
    /// carries a key that collides with a named `Claims` field — see
    /// [`Self::issue_user_token_with_extra`].
    pub fn issue_custom_token(
        &self,
        sub: String,
        expires_in_secs: u64,
        typ: &str,
        mut extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let jti = take_jti(&mut extra);
        reject_named_claim_collisions(&extra)?;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub,
            aud: None,
            exp: now + expires_in_secs as usize,
            iat: now,
            nbf: Some(now),
            jti: Some(jti),
            scope: None,
            identity: None,
            extra,
        };

        let mut header = Header::new(self.alg);
        header.typ = Some(typ.to_string());
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Validates a token's signature and claims, returning them on success.
    ///
    /// # Clock skew
    ///
    /// `exp` and `nbf` are checked with a tolerance of
    /// [`TokenManager::leeway`] seconds, [`DEFAULT_LEEWAY_SECS`] by default,
    /// so a token is accepted for roughly a minute past its expiry unless
    /// [`TokenManager::with_leeway`] lowers it. This was inherited silently
    /// from `jsonwebtoken` until #350; it is set explicitly here now, so the
    /// window this crate honours no longer depends on a transitive
    /// dependency's default.
    ///
    /// # Required claims
    ///
    /// When `expected_aud` is `Some`, the token must contain an `aud` claim.
    /// When the manager has an issuer, the token must contain an `iss` claim.
    /// A token that lacks either required claim is rejected with [`AuthError::Token`].
    pub fn validate_token(
        &self,
        token: &str,
        expected_aud: Option<&str>,
    ) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(self.alg);
        validation.leeway = self.leeway;
        validation.validate_nbf = true;
        if let Some(aud) = expected_aud {
            validation.set_audience(&[aud]);
            validation.required_spec_claims.insert("aud".to_string());
        } else {
            validation.validate_aud = false;
        }
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
            validation.required_spec_claims.insert("iss".to_string());
        }

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        if expected_aud.is_some() && token_data.claims.aud.is_none() {
            return Err(AuthError::Token("Missing required aud claim".to_string()));
        }
        if self.issuer.is_some() && token_data.claims.iss.is_none() {
            return Err(AuthError::Token("Missing required iss claim".to_string()));
        }

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::auth::state::Identity;
    use std::collections::HashMap;

    /// Throwaway RSA-2048 private key, test-only.
    const TEST_RSA_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA5hJIcQ+2rxMz
VM8ZH5WAmguCr0xmNDAdy0IzzsUeFLG7BebB7izOkU36J4t8t5tUaQwrBMnx2Fvt
VqJjbdE242UDpvWF/8m9zJ2HR5298cbwT5cGMKLB0HWzDMahugs+Bbh2lCgwyLZk
Tr3Diwxp5SwFew/Wb+Ke9cNG9Hu5IFH3BCuJ839d9hfqisIeYrBPfb52xxckM37R
7zSGu/eDP/HZAeLkQuptZJW4A3u7xni14u4qyqXDqsHsYFNgJaxMSAwWgBRY6HNu
TnvBArTXCiVfL+F73B2L6mdYr64g+QS9nK9v97MlJu/E3mSduz54pren4mpCHc9m
/S2+VjCZAgMBAAECggEAASC9qQbGnL7XuExRDOIn/m4bWx92ehjo0lCTibhpY3LW
umbSbpfbhmmuSj3CjW9VZsaM3hBTgSjoTX72lbY/eIUXD7c0memUK5pV4XcEIrQw
AZlPIye6ckx4I7ZGnKasO8FoAel9dd7DXw36AuBK3LBzJwtzkEFsBc0e3/wixqmG
UJBbbt/+5ya7CxyjuePaQhKtkLD5R6DpvN2XnCYq5nHJNJdvSVg1pOzsTHYIf+Ee
2Rz42fGsfFKqeEQCcBFRZaGb/ELeP4c6UZdktZAvmHb1p1fursVZc6X9JXmiJ2OJ
Kv2H2tMKuysP8L0fXFOMgkH2SVt6rcdHkO6xhlhWsQKBgQDqR8rAJeEE5BFoXA8T
VVW6CLMlW51x4ey7PEGOaYh39dTG2Q+GZQBZ9G+SZk3f5Y85UCACSyc//4qaz/c3
0nWsegZ+JPyymmuc79wzIAFFvXB7pL6wyn0Ed1P620kOZTtA8iBcXrsuxL+KP7iu
MXfWmU1QiZpbndILtyDnY+70uwKBgQDSyCljWkydQCaPU+fiAXLxP8CvcJTSSNQD
mVUlwJ+OpHnU+Alsi1rBavMgUtLlYbFqzH7NmYrLC8Yadq3ZOwLt0VEK0r8qstAL
7QCDUD2WNuQjpZupRnXuMUl3iXB96i2gb+VQKGuUAJvVWjdIbYa4+Gu+sBMfcDcX
dBihDLuEuwKBgAgX4tEwfc2Fc3R/eaXZVNTQaB/qQk4k1+C//CPHUYeTXn5gEUE7
S//PiesszZPmgkQgmHp7zidP1KH0fT3Yb2g97ut8q54f54fMYXcCrAiUusYKsuu4
kwkMdkI8QRHWPW3I74VBYIYFFfjYqrCZ1OH8+cbGeiagFRmCggh8U0zxAoGAVW3u
6Ge22Z0gg8LcHsu7jG/sZq7Ygool8/d3fT+e669Z+ak2GJo6hF4WgClRdMqtn72W
PzpV+ImjFyK2v26dd0n48MwN0v56N/ss1Av3iiRhPtlmR6tZLNspDZvUzhPVvkrb
xCs9vtSoVEamVWKe0eVNthGjDoDqs0TInq2MavUCgYB6REavSJs/CLkSS7iimjxZ
G7g5YQi9/p1lXLOEUDiwEmvRr0XTwzzxUsIc535IXhh/ZUYpthenW+qBBzn85pEC
TowIqciHu5redqlQ8rITA8/AOY98vaDIhppDg1rfpnHHaZHFbXD/keYAEbhBtbvf
a0QMqKUcs8+YTy5R5K6qtw==
-----END PRIVATE KEY-----";

    /// Throwaway Ed25519 private key (PKCS#8 PEM), test-only. Generated with
    /// `openssl genpkey -algorithm ed25519`.
    const TEST_ED25519_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKIPR2jojpdobYr1M/pjIRuMONpZGYQ+y5yxSqKX9T9/
-----END PRIVATE KEY-----";

    /// A second, distinct throwaway Ed25519 private key, test-only — used to
    /// prove a token signed by one key is rejected by another key's manager.
    const TEST_ED25519_PRIVATE_KEY_PEM_B: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPlsnSfvh53rJ+Tlbo8e7cgq2mIkWQ1NCM5paVeinUh8
-----END PRIVATE KEY-----";

    #[test]
    fn test_claims_serialization() {
        let mut extra = HashMap::new();
        extra.insert(
            "custom".to_string(),
            serde_json::Value::String("value".to_string()),
        );

        let claims = Claims {
            iss: Some("issuer".to_string()),
            sub: "user123".to_string(),
            aud: Some(Audience::from("audience")),
            exp: 1000,
            iat: 500,
            nbf: Some(500),
            jti: Some("jti".to_string()),
            scope: Some("openid profile".to_string()),
            identity: Some(Identity {
                provider_id: "google".to_string(),
                external_id: "user123".to_string(),
                email: Some("user@example.com".to_string()),
                username: Some("user".to_string()),
                attributes: HashMap::new(),
            }),
            extra,
        };

        let serialized = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.iss, claims.iss);
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.extra.get("custom").unwrap(), "value");
    }

    #[test]
    fn test_token_manager_issuance() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.sub, "user123");
        assert!(claims.jti.is_some());
        assert!(claims.nbf.is_some());
    }

    #[test]
    fn access_tokens_include_client_audience_claim_and_type() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = test_identity();
        let token = manager
            .issue_access_token(
                "issuer",
                identity.clone(),
                "app-client",
                Audience::Multiple(vec!["api-a".into(), "api-b".into()]),
                3600,
                None,
                HashMap::new(),
            )
            .unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        let claims = manager.validate_token(&token, Some("api-b")).unwrap();
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(claims.sub, identity.external_id);
        let embedded_identity = claims
            .identity
            .expect("issued access token includes identity");
        assert_eq!(embedded_identity.provider_id, identity.provider_id);
        assert_eq!(embedded_identity.external_id, identity.external_id);
        assert_eq!(embedded_identity.username, identity.username);
        assert_eq!(embedded_identity.email, identity.email);
        assert_eq!(embedded_identity.attributes, identity.attributes);
        assert_eq!(
            claims.aud,
            Some(Audience::Multiple(vec!["api-a".into(), "api-b".into()]))
        );
        assert_eq!(
            claims.extra.get("client_id"),
            Some(&serde_json::json!("app-client"))
        );
    }

    #[test]
    fn access_tokens_carry_the_given_issuer_without_one_on_the_manager() {
        let manager = TokenManager::new(b"secret", None);
        let token = manager
            .issue_access_token(
                "https://op.example",
                test_identity(),
                "app-client",
                Audience::Single("api".into()),
                3600,
                None,
                HashMap::new(),
            )
            .expect("an access token without a manager issuer");

        let claims = manager.validate_token(&token, Some("api")).unwrap();
        assert_eq!(claims.iss.as_deref(), Some("https://op.example"));
    }

    #[test]
    fn test_token_manager_asymmetric_issuance() {
        let manager = TokenManager::new_asymmetric(
            TEST_RSA_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-kid-123".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        // Decode directly via jsonwebtoken to prove independent verification
        let jwk = manager.public_jwk().unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("my-kid-123"));

        let decoding_key = jwk.to_decoding_key().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["issuer"]);

        let token_data =
            jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.header.kid.as_deref(), Some("my-kid-123"));
    }

    /// Regression test for the asymmetric decoding key being derived from the
    /// private half instead of the public one.
    ///
    /// `test_token_manager_asymmetric_issuance` above verifies via the
    /// published JWK, which exercises `Jwk::to_decoding_key` rather than the
    /// manager's own `decoding_key` — so it stays green either way. This one
    /// goes through `validate_token`, which is the path `/reissue` and
    /// `/userinfo` actually take.
    #[test]
    fn test_asymmetric_manager_validates_its_own_tokens() {
        let manager = TokenManager::new_asymmetric(
            TEST_RSA_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-kid-123".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, Some("issuer".to_string()));

        // Same round trip for the attestation shape `/reissue` presents.
        let attestation = manager
            .issue_custom_token(
                "device-1".to_string(),
                60,
                "webank-attest+jws",
                HashMap::new(),
            )
            .unwrap();

        let attest_claims = manager.validate_token(&attestation, None).unwrap();
        assert_eq!(attest_claims.sub, "device-1");
    }

    #[test]
    fn test_issue_id_token() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_id_token(identity, "client-1", Some("nonce123".to_string()), 3600)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.aud, Some(Audience::from("client-1")));
        assert_eq!(claims.extra.get("nonce").unwrap(), "nonce123");
    }
    #[test]
    fn test_token_manager_audience_validation() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        // Issue token for "client-1"
        let token = manager
            .issue_id_token(identity, "client-1", None, 3600)
            .unwrap();

        // Validate with correct audience
        let claims = manager.validate_token(&token, Some("client-1")).unwrap();
        assert_eq!(claims.aud, Some(Audience::from("client-1")));

        // Validate with incorrect audience (should fail)
        let err = manager
            .validate_token(&token, Some("client-2"))
            .unwrap_err();
        assert!(err.to_string().contains("InvalidAudience"));
    }

    #[test]
    fn test_issue_custom_token_sets_typ_and_no_aud() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert("cnf".to_string(), serde_json::json!({"jkt": "abc"}));

        let token = manager
            .issue_custom_token("device-1".to_string(), 60, "webank-attest+jws", extra)
            .unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("webank-attest+jws"));

        let claims = manager.validate_token(&token, None).unwrap();
        assert_eq!(claims.sub, "device-1");
        assert_eq!(claims.aud, None);
        assert_eq!(claims.extra.get("cnf").unwrap()["jkt"], "abc");
    }

    /// Same jti-override coverage as
    /// `test_issue_user_token_with_extra_jti_override_no_duplicate_key`,
    /// exercised on `issue_custom_token`.
    #[test]
    fn test_issue_custom_token_jti_override_round_trips() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert(
            "jti".to_string(),
            serde_json::json!("caller-supplied-cuid2"),
        );

        let token = manager
            .issue_custom_token("device-1".to_string(), 60, "webank-attest+jws", extra)
            .unwrap();
        let claims = manager
            .validate_token(&token, None)
            .expect("TokenManager must be able to decode the token it just issued");

        assert_eq!(claims.jti, Some("caller-supplied-cuid2".to_string()));
        assert!(!claims.extra.contains_key("jti"));
    }

    #[test]
    fn test_issue_user_token_with_extra_round_trips_custom_claims() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert("api_key_id".to_string(), serde_json::json!("key-abc"));
        extra.insert("project_id".to_string(), serde_json::json!("proj-42"));

        let token = manager
            .issue_user_token_with_extra(identity, 3600, None, None, extra)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("api_key_id"),
            Some(&serde_json::json!("key-abc"))
        );
        assert_eq!(
            claims.extra.get("project_id"),
            Some(&serde_json::json!("proj-42"))
        );
    }

    #[test]
    fn test_issue_user_token_wrapper_still_has_empty_extra() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert!(claims.extra.is_empty());
    }

    /// Regression test for #212: `extra["jti"]` used to be merged onto the
    /// token alongside the named `Claims::jti` field via
    /// `#[serde(flatten)]`, producing a wire payload with two `"jti"` keys
    /// that `TokenManager` itself could not decode (serde hard-errors on a
    /// literal duplicate field). This asserts both halves of that bug are
    /// gone: the payload has exactly one `jti` key, and it carries the
    /// caller's value, not a generated one.
    #[test]
    fn test_issue_user_token_with_extra_jti_override_no_duplicate_key() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert(
            "jti".to_string(),
            serde_json::json!("caller-supplied-cuid2"),
        );

        let token = manager
            .issue_user_token_with_extra(identity, 3600, None, None, extra)
            .unwrap();

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(
            payload_json.matches("\"jti\"").count(),
            1,
            "wire payload must contain exactly one jti key, got: {payload_json}"
        );

        let claims = manager
            .validate_token(&token, None)
            .expect("TokenManager must be able to decode the token it just issued");
        assert_eq!(claims.jti, Some("caller-supplied-cuid2".to_string()));
    }

    /// Proves the default path (no `jti` in `extra`) is unchanged: a
    /// generated UUIDv4 is still stamped when the caller doesn't supply one.
    #[test]
    fn test_issue_user_token_with_extra_default_jti_is_still_generated_uuid() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token_with_extra(identity, 3600, None, None, HashMap::new())
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        let jti = claims.jti.expect("jti must still be generated by default");
        assert!(
            uuid::Uuid::parse_str(&jti).is_ok(),
            "default-path jti must still be a UUID, got: {jti}"
        );
    }

    #[test]
    fn test_issue_client_token_with_extra_round_trips_custom_claims() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert("roles".to_string(), serde_json::json!(["admin", "billing"]));

        let token = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("roles"),
            Some(&serde_json::json!(["admin", "billing"]))
        );
    }

    #[test]
    fn test_issue_client_token_wrapper_still_has_empty_extra() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let token = manager
            .issue_client_token("client-1", 3600, None, None)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert!(claims.extra.is_empty());
    }

    /// Same jti-override coverage as
    /// `test_issue_user_token_with_extra_jti_override_no_duplicate_key`,
    /// exercised on the client (M2M) token path.
    #[test]
    fn test_issue_client_token_with_extra_jti_override_round_trips() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert(
            "jti".to_string(),
            serde_json::json!("caller-supplied-cuid2"),
        );

        let token = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .unwrap();
        let claims = manager
            .validate_token(&token, None)
            .expect("TokenManager must be able to decode the token it just issued");

        assert_eq!(claims.jti, Some("caller-supplied-cuid2".to_string()));
        assert!(!claims.extra.contains_key("jti"));
    }

    #[test]
    fn test_issue_id_token_with_extra_round_trips_custom_claims() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert("org_id".to_string(), serde_json::json!("org-7"));

        let token = manager
            .issue_id_token_with_extra(
                identity,
                "client-1",
                Some("nonce123".to_string()),
                3600,
                extra,
            )
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("org_id"),
            Some(&serde_json::json!("org-7"))
        );
        assert_eq!(
            claims.extra.get("nonce"),
            Some(&serde_json::json!("nonce123"))
        );
    }

    #[test]
    fn test_issue_id_token_with_extra_explicit_nonce_wins_over_extra_nonce() {
        // Documents the precedence chosen in `issue_id_token_with_extra`:
        // the explicit `nonce` parameter always overrides a `"nonce"` entry
        // supplied via `extra`.
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert(
            "nonce".to_string(),
            serde_json::json!("attacker-supplied-nonce"),
        );

        let token = manager
            .issue_id_token_with_extra(
                identity,
                "client-1",
                Some("real-nonce".to_string()),
                3600,
                extra,
            )
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("nonce"),
            Some(&serde_json::json!("real-nonce"))
        );
    }

    /// Same jti-override coverage as
    /// `test_issue_user_token_with_extra_jti_override_no_duplicate_key`,
    /// exercised on the id-token path.
    #[test]
    fn test_issue_id_token_with_extra_jti_override_round_trips() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert(
            "jti".to_string(),
            serde_json::json!("caller-supplied-cuid2"),
        );

        let token = manager
            .issue_id_token_with_extra(identity, "client-1", None, 3600, extra)
            .unwrap();
        let claims = manager
            .validate_token(&token, None)
            .expect("TokenManager must be able to decode the token it just issued");

        assert_eq!(claims.jti, Some("caller-supplied-cuid2".to_string()));
        assert!(!claims.extra.contains_key("jti"));
    }

    #[test]
    fn test_token_manager_ed25519_issuance() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some("my-ed25519-kid"));
    }

    /// Proves #187 and #188 actually compose end-to-end: mint a token with
    /// the Ed25519 constructor, then verify it using ONLY the decoding key
    /// derived from the published JWK (the OKP shape `/jwks.json` would
    /// serve) — not the manager's own internal decoding key. This is the
    /// round trip a real resource server performs against a real JWKS
    /// endpoint.
    #[test]
    fn test_ed25519_token_round_trips_via_published_jwk() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let jwk = manager.public_jwk().unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("my-ed25519-kid"));

        let decoding_key = jwk.to_decoding_key().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["issuer"]);

        let token_data =
            jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.header.kid.as_deref(), Some("my-ed25519-kid"));
    }

    /// Same shape as `test_asymmetric_manager_validates_its_own_tokens`
    /// (RS256): goes through `validate_token`, the path `/reissue` and
    /// `/userinfo` actually take, rather than the published-JWK path above.
    #[test]
    fn test_ed25519_manager_validates_its_own_tokens() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, Some("issuer".to_string()));
    }

    /// `public_jwk()` for an Ed25519 manager must emit spec-correct OKP JSON
    /// (RFC 8037 §2): `kty: "OKP"`, `crv: "Ed25519"`, `x` present and
    /// base64url-encoded to exactly 32 bytes, and no stray RSA fields (`n`,
    /// `e`) on the wire.
    #[test]
    fn test_ed25519_public_jwk_is_spec_correct_okp_json() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let jwk = manager.public_jwk().unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.alg.as_deref(), Some("EdDSA"));
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.n.is_none());
        assert!(jwk.e.is_none());

        let x = jwk.x.as_ref().expect("OKP JWK must have 'x'");
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let decoded = URL_SAFE_NO_PAD
            .decode(x)
            .expect("'x' must be valid base64url (unpadded)");
        assert_eq!(decoded.len(), 32, "Ed25519 public key must be 32 bytes");

        let value = serde_json::to_value(&jwk).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("kty").unwrap(), "OKP");
        assert_eq!(obj.get("crv").unwrap(), "Ed25519");
        assert_eq!(obj.get("alg").unwrap(), "EdDSA");
        assert!(obj.contains_key("x"));
        assert!(
            !obj.contains_key("n"),
            "OKP JWK must not serialize the RSA 'n' field, got: {}",
            value
        );
        assert!(
            !obj.contains_key("e"),
            "OKP JWK must not serialize the RSA 'e' field, got: {}",
            value
        );
    }

    /// Same spec-correctness check for the RSA shape, unchanged by the OKP
    /// addition: no stray `crv`/`x` fields on the wire.
    #[test]
    fn test_rsa_public_jwk_still_omits_okp_fields() {
        let manager = TokenManager::new_asymmetric(
            TEST_RSA_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-kid-123".to_string()),
        )
        .unwrap();

        let jwk = manager.public_jwk().unwrap();
        let value = serde_json::to_value(&jwk).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("kty").unwrap(), "RSA");
        assert!(obj.contains_key("n"));
        assert!(obj.contains_key("e"));
        assert!(
            !obj.contains_key("crv"),
            "RSA JWK must not serialize the OKP 'crv' field, got: {}",
            value
        );
        assert!(
            !obj.contains_key("x"),
            "RSA JWK must not serialize the OKP 'x' field, got: {}",
            value
        );
    }

    /// Wrong-key rejection: a token signed by one Ed25519 manager must be
    /// rejected when verified against a *different* Ed25519 manager's
    /// published JWK — proving the JWKS round trip actually checks the
    /// signature rather than trivially accepting any well-formed EdDSA JWT.
    #[test]
    fn test_ed25519_token_rejected_by_wrong_key_jwk() {
        let signer = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("kid-a".to_string()),
        )
        .unwrap();
        let other = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM_B,
            Some("issuer".to_string()),
            Some("kid-b".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = signer.issue_user_token(identity, 3600, None, None).unwrap();

        // Verifying with the signer's own manager still works.
        assert!(signer.validate_token(&token, None).is_ok());

        // Verifying with a different key's manager must fail.
        let err = other.validate_token(&token, None).unwrap_err();
        assert!(err.to_string().contains("InvalidSignature"));

        // Same result going through the published-JWK path a real resource
        // server would use.
        let wrong_jwk = other.public_jwk().unwrap();
        let decoding_key = wrong_jwk.to_decoding_key().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["issuer"]);
        let err = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap_err();
        assert_eq!(
            err.kind(),
            &jsonwebtoken::errors::ErrorKind::InvalidSignature
        );
    }

    /// A tampered payload (claims byte flipped after signing, signature
    /// left as-is) must be rejected, whichever algorithm signed it —
    /// guards against a validator that only checks structural shape.
    #[test]
    fn test_ed25519_tampered_token_rejected() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Corrupt a single character in the base64url payload segment.
        let mut payload = parts[1].to_string();
        let last = payload.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        payload.push(replacement);
        parts[1] = &payload;
        let tampered = parts.join(".");

        let err = manager.validate_token(&tampered, None).unwrap_err();
        assert!(
            err.to_string().contains("InvalidSignature") || err.to_string().contains("Json"),
            "unexpected error for tampered token: {err}"
        );
    }

    /// #206 repro: a stock Keycloak realm with two `oidc-audience-mapper`
    /// entries mints `"aud"` as a JSON array (RFC 7519 §4.1.3 allows this).
    /// `validate_token` calls `jsonwebtoken::decode::<Claims>`, which
    /// deserializes the payload into `Claims` before any of
    /// `jsonwebtoken`'s own validation runs — so this fails at
    /// deserialization, not at a validation check, and `expected_aud: None`
    /// (which turns `Validation::validate_aud` off) makes no difference.
    #[test]
    fn test_validate_token_accepts_array_aud() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let raw_claims = serde_json::json!({
            "iss": "issuer",
            "sub": "user123",
            "aud": ["client-1", "client-2"],
            "exp": (chrono::Utc::now().timestamp() as usize) + 3600,
            "iat": chrono::Utc::now().timestamp() as usize,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &raw_claims,
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let claims = manager
            .validate_token(&token, None)
            .expect("multi-audience subject token must deserialize");
        let aud = claims.aud.expect("aud claim must be present");
        assert!(aud.contains("client-1"));
        assert!(aud.contains("client-2"));
        assert!(!aud.contains("client-3"));
    }

    /// Companion to `test_validate_token_accepts_array_aud`: a subject token
    /// with a plain string `aud` (the shape every token this crate has ever
    /// issued) must keep working exactly as before the `Audience` enum was
    /// introduced.
    #[test]
    fn test_validate_token_still_accepts_string_aud() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_id_token(identity, "client-1", None, 3600)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();
        let aud = claims.aud.expect("aud claim must be present");
        assert!(aud.contains("client-1"));
        assert!(!aud.contains("client-2"));
    }

    /// Serialization symmetry guarantee: a single audience must still
    /// serialize as a bare JSON string, not a one-element array, so every
    /// token this crate has ever issued (and any consumer relying on that
    /// shape) is unaffected by `Audience` gaining array support.
    #[test]
    fn test_audience_single_round_trips_as_bare_string() {
        let single = Audience::Single("client-1".to_string());
        let serialized = serde_json::to_string(&single).unwrap();
        assert_eq!(serialized, "\"client-1\"");

        let deserialized: Audience = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, single);

        let multiple = Audience::Multiple(vec!["client-1".to_string(), "client-2".to_string()]);
        let serialized_multi = serde_json::to_string(&multiple).unwrap();
        assert_eq!(serialized_multi, "[\"client-1\",\"client-2\"]");

        let deserialized_multi: Audience = serde_json::from_str(&serialized_multi).unwrap();
        assert_eq!(deserialized_multi, multiple);
    }

    fn test_identity() -> Identity {
        Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        }
    }

    /// The exact reproduction from #283, verbatim: a caller flattens its
    /// own typed claims struct into `extra`, three of whose keys collide
    /// with named `Claims` fields. Before the fix this returned `Ok` and
    /// minted a payload with `"iss"`, `"sub"` and `"aud"` written twice,
    /// which `validate_token` then refused to decode — an issuer-side
    /// mistake whose only symptom appeared in a different process. It must
    /// now fail at issuance, naming every colliding key.
    #[test]
    fn test_issue_custom_token_rejects_extra_colliding_with_named_claims() {
        let manager =
            TokenManager::new(b"probe-secret", Some("https://issuer.example".to_string()));

        let mut extra: HashMap<String, serde_json::Value> = HashMap::new();
        extra.insert("iss".into(), serde_json::json!("https://caller.example"));
        extra.insert("sub".into(), serde_json::json!("caller-subject"));
        extra.insert("aud".into(), serde_json::json!("caller-audience"));

        let err = manager
            .issue_custom_token("engine-subject".to_string(), 3600, "JWT", extra)
            .expect_err("extra colliding with named claims must not mint a token");

        let msg = err.to_string();
        for key in ["iss", "sub", "aud"] {
            assert!(
                msg.contains(key),
                "error must name every colliding key; `{key}` missing from: {msg}"
            );
        }
    }

    /// Every name in `NAMED_CLAIM_FIELDS` must be rejected, on every
    /// `extra`-taking issuance path. This is the assertion that keeps #283
    /// from regressing one field or one constructor at a time: adding a
    /// named field to `Claims` without adding it to `NAMED_CLAIM_FIELDS`
    /// leaves this test passing but the new field unguarded, which is why
    /// the companion test below pins the list against `Claims` itself.
    #[test]
    fn test_every_named_claim_field_is_rejected_on_every_issuance_path() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        for field in NAMED_CLAIM_FIELDS {
            let one = |value: serde_json::Value| {
                let mut extra = HashMap::new();
                extra.insert((*field).to_string(), value);
                extra
            };
            let probe = serde_json::json!("collides");

            assert!(
                manager
                    .issue_user_token_with_extra(
                        test_identity(),
                        3600,
                        None,
                        None,
                        one(probe.clone())
                    )
                    .is_err(),
                "issue_user_token_with_extra must reject extra[{field}]"
            );
            assert!(
                manager
                    .issue_id_token_with_extra(
                        test_identity(),
                        "client-1",
                        None,
                        3600,
                        one(probe.clone())
                    )
                    .is_err(),
                "issue_id_token_with_extra must reject extra[{field}]"
            );
            assert!(
                manager
                    .issue_client_token_with_extra("client-1", 3600, None, None, one(probe.clone()))
                    .is_err(),
                "issue_client_token_with_extra must reject extra[{field}]"
            );
            assert!(
                manager
                    .issue_custom_token("sub".to_string(), 3600, "JWT", one(probe.clone()))
                    .is_err(),
                "issue_custom_token must reject extra[{field}]"
            );
            assert!(
                manager
                    .issue_sd_jwt(
                        "sub".to_string(),
                        3600,
                        None,
                        None,
                        Vec::new(),
                        one(probe.clone())
                    )
                    .is_err(),
                "issue_sd_jwt must reject extra[{field}]"
            );
        }
    }

    /// Pins `NAMED_CLAIM_FIELDS` against what `Claims` actually serializes,
    /// rather than against a second hand-written list that would drift the
    /// same way the original one did. Serializing a `Claims` with an empty
    /// `extra` yields exactly the named keys; every one of them except
    /// `jti` (removed by `take_jti`, so a supported override rather than a
    /// collision) must be covered. A `Claims` field added later without a
    /// `NAMED_CLAIM_FIELDS` entry fails here.
    #[test]
    fn test_named_claim_fields_covers_every_serialized_claims_key() {
        let claims = Claims {
            iss: Some("issuer".to_string()),
            sub: "sub".to_string(),
            aud: Some(Audience::from("client-1")),
            exp: 0,
            iat: 0,
            nbf: Some(0),
            jti: Some("jti".to_string()),
            scope: Some("openid".to_string()),
            // `Some`, so the `skip_serializing_if` field is present in the
            // serialized form and therefore actually checked below.
            identity: Some(test_identity()),
            extra: HashMap::new(),
        };

        let serialized = serde_json::to_value(&claims).unwrap();
        let keys: Vec<&str> = serialized
            .as_object()
            .expect("Claims serializes as a JSON object")
            .keys()
            .map(String::as_str)
            .collect();

        for key in keys {
            assert!(
                key == "jti" || NAMED_CLAIM_FIELDS.contains(&key),
                "`Claims` serializes `{key}` but NAMED_CLAIM_FIELDS does not list it, so \
                 `extra[\"{key}\"]` would silently produce a duplicate key again (#283)"
            );
        }
    }

    /// The fix must not narrow what `extra` is actually for. Non-colliding
    /// custom claims still round-trip, and `jti` is still the one
    /// documented override rather than being caught by the new check.
    #[test]
    fn test_non_colliding_extra_and_jti_override_still_work() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert("api_key_id".to_string(), serde_json::json!("key-abc"));
        extra.insert("cnf".to_string(), serde_json::json!({"jkt": "abc"}));
        extra.insert(
            "jti".to_string(),
            serde_json::json!("caller-supplied-cuid2"),
        );

        let token = manager
            .issue_user_token_with_extra(test_identity(), 3600, None, None, extra)
            .expect("non-colliding extra plus a jti override must still issue");

        let claims = manager
            .validate_token(&token, None)
            .expect("TokenManager must be able to decode the token it just issued");

        assert_eq!(claims.jti, Some("caller-supplied-cuid2".to_string()));
        assert_eq!(
            claims.extra.get("api_key_id"),
            Some(&serde_json::json!("key-abc"))
        );
        assert_eq!(claims.extra.get("cnf").unwrap()["jkt"], "abc");
        assert!(!claims.extra.contains_key("jti"));
    }

    /// `nonce` is applied to `extra` by `issue_id_token_with_extra` after
    /// the collision check, and is not a named `Claims` field. Pins that
    /// the new check did not accidentally make the OIDC `nonce` path
    /// unreachable.
    #[test]
    fn test_id_token_nonce_still_stamped_after_collision_check() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let token = manager
            .issue_id_token_with_extra(
                test_identity(),
                "client-1",
                Some("nonce123".to_string()),
                3600,
                HashMap::new(),
            )
            .expect("id token issuance must be unaffected");

        let claims = manager.validate_token(&token, Some("client-1")).unwrap();
        assert_eq!(claims.extra.get("nonce").unwrap(), "nonce123");
    }
}
pub mod jwk;

/// Issue #350: the clock-skew tolerance applied to `exp`/`nbf` used to be
/// `jsonwebtoken`'s default, inherited silently — invisible from the
/// signature, absent from the docs, and with no way to change it.
#[cfg(test)]
mod leeway_tests {
    use super::*;
    use crate::auth::state::Identity;
    use jsonwebtoken::EncodingKey;
    use std::collections::HashMap;

    const SECRET: &[u8] = b"a-test-signing-key-for-leeway-tests";

    /// Mints an HS256 token whose `exp` is `seconds_ago` in the past.
    ///
    /// Signed here rather than through `issue_user_token`, which can only
    /// place `exp` at or after *now*: a zero TTL yields `exp == iat == now`,
    /// which is not yet expired even at zero tolerance. The alternative —
    /// issuing a one-second token and sleeping — is exactly the shape #350
    /// reports as confusing, and would make these tests slow and timing
    /// dependent for no gain.
    fn token_expired(seconds_ago: usize) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let claims = Claims {
            iss: None,
            sub: "user-1".to_string(),
            aud: Some(Audience::Single("api".to_string())),
            exp: now - seconds_ago,
            iat: now - seconds_ago - 1,
            nbf: None,
            jti: None,
            scope: None,
            identity: Some(Identity {
                provider_id: "test".to_string(),
                external_id: "user-1".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            }),
            extra: HashMap::new(),
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("signing should succeed")
    }

    fn manager() -> TokenManager {
        TokenManager::new(SECRET, None)
    }

    /// Pins the claim made in `DEFAULT_LEEWAY_SECS`'s own documentation.
    ///
    /// The value is now set explicitly at every validation site, so a change
    /// upstream would not alter behaviour — it would just quietly make the
    /// docs wrong about where the number came from. This keeps them honest.
    #[test]
    fn the_default_matches_the_jsonwebtoken_default_it_documents() {
        assert_eq!(
            Validation::new(Algorithm::HS256).leeway,
            DEFAULT_LEEWAY_SECS,
            "DEFAULT_LEEWAY_SECS no longer matches jsonwebtoken's default; \
             update the docs that say it does"
        );
    }

    /// The surprise reported in #350: a token that expired half a minute ago
    /// still validates, because the inherited tolerance covers it.
    #[test]
    fn a_token_expired_within_the_default_leeway_is_still_accepted() {
        assert!(
            manager()
                .validate_token(&token_expired(30), Some("api"))
                .is_ok(),
            "the documented 60s tolerance should still accept this token"
        );
    }

    /// The tolerance is a window, not a licence: past it, the token is gone.
    #[test]
    fn a_token_expired_beyond_the_default_leeway_is_rejected() {
        let err = manager()
            .validate_token(
                &token_expired(DEFAULT_LEEWAY_SECS as usize + 60),
                Some("api"),
            )
            .expect_err("beyond the tolerance the token must be refused");
        assert!(
            err.to_string().contains("ExpiredSignature"),
            "expected an expiry rejection, got: {err}"
        );
    }

    /// `with_leeway(0)` is the knob that makes validation behave the way the
    /// person writing "issue, expire, assert rejected" expected all along.
    /// Same token, both settings, so the contrast is the assertion.
    #[test]
    fn with_leeway_zero_rejects_a_token_the_default_would_accept() {
        let token = token_expired(5);

        assert!(
            manager().validate_token(&token, Some("api")).is_ok(),
            "precondition: the default tolerance accepts this token"
        );

        let err = manager()
            .with_leeway(0)
            .validate_token(&token, Some("api"))
            .expect_err("with no tolerance an expired token must be refused");
        assert!(
            err.to_string().contains("ExpiredSignature"),
            "expected an expiry rejection, got: {err}"
        );
    }

    /// A token still inside its lifetime is unaffected: this is a tolerance
    /// on expiry, not a cap on it.
    #[test]
    fn a_live_token_is_accepted_with_no_leeway_at_all() {
        let identity = Identity {
            provider_id: "test".to_string(),
            external_id: "user-1".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };
        let manager = manager().with_leeway(0);
        let token = manager
            .issue_user_token(identity, 3600, None, Some("api".to_string()))
            .expect("issuing should succeed");

        assert!(manager.validate_token(&token, Some("api")).is_ok());
    }

    #[test]
    fn the_configured_value_is_readable_back() {
        assert_eq!(manager().leeway(), DEFAULT_LEEWAY_SECS);
        assert_eq!(manager().with_leeway(5).leeway(), 5);
    }

    #[test]
    fn validate_token_enforces_not_before_claim() {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: Some("https://op.example".to_string()),
            sub: "user-1".to_string(),
            aud: Some(Audience::Single("api".to_string())),
            exp: now + 3600,
            iat: now,
            nbf: Some(now + 300),
            jti: None,
            scope: None,
            identity: None,
            extra: HashMap::new(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("signing should succeed");

        let err = TokenManager::new(SECRET, Some("https://op.example".to_string()))
            .with_leeway(0)
            .validate_token(&token, Some("api"))
            .expect_err("future nbf must be rejected");
        assert!(
            err.to_string().contains("ImmatureSignature"),
            "expected ImmatureSignature, got: {err}"
        );
    }

    #[test]
    fn validate_token_rejects_missing_or_null_aud_and_iss_when_configured() {
        let now = chrono::Utc::now().timestamp() as usize;
        let manager = TokenManager::new(SECRET, Some("https://op.example".to_string()));

        // Missing `aud` when `expected_aud` is provided
        let no_aud_payload = serde_json::json!({
            "iss": "https://op.example",
            "sub": "user-1",
            "exp": now + 3600,
            "iat": now,
        });
        let no_aud_token = encode(
            &Header::new(Algorithm::HS256),
            &no_aud_payload,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert!(manager.validate_token(&no_aud_token, Some("api")).is_err());

        // Missing `iss` when `manager.issuer` is configured
        let no_iss_payload = serde_json::json!({
            "sub": "user-1",
            "aud": "api",
            "exp": now + 3600,
            "iat": now,
        });
        let no_iss_token = encode(
            &Header::new(Algorithm::HS256),
            &no_iss_payload,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert!(manager.validate_token(&no_iss_token, Some("api")).is_err());
    }
}
