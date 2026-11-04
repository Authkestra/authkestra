use async_trait::async_trait;
use authkestra_engine::token::DEFAULT_LEEWAY_SECS;
use authkestra_engine::{
    error::AuthError,
    strategy::AuthenticationStrategy,
    token::{
        cert_binding::{constant_time_eq, x5t_s256_thumbprint, ClientCertificateDer},
        Claims,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::request::Parts;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during offline validation.
///
/// `#[non_exhaustive]` for the same reason [`ValidationConfig`] is (see its
/// doc comment): a new error condition — like [`ValidationError::
/// DpopReplayUnavailable`], added after this enum first shipped without
/// this attribute — must be addable without forcing every downstream
/// exhaustive `match` to break. That break was demonstrated in-tree:
/// adding that variant needed a new arm in `authkestra-oidc`'s own match
/// over this enum, in the same crate this ships from.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Key not found in JWKS")]
    KeyNotFound,
    #[error(
        "Token is missing a 'kid' header, which is required by this JWKS cache's strict validation policy"
    )]
    MissingKid,
    #[error("Token issuer {0:?} is not in the configured trust map; no JWKS is trusted for it")]
    UntrustedIssuer(String),
    #[error(
        "Token carries no string 'iss' claim, which is required to resolve a signing key when more than one issuer is trusted"
    )]
    MissingIssuer,
    #[error("PASETO error: {0}")]
    Paseto(String),
    #[error("Discovery error: {0}")]
    Discovery(#[from] AuthError),
    #[error("Validation error: {0}")]
    Validation(String),
    /// A DPoP proof's `jti` could not be checked for replay — the
    /// configured `DpopReplayStore` errored, or none is configured at all
    /// (the fail-closed `NoDpopReplayStore` default). Deliberately a
    /// distinct variant from `InvalidToken`: this is never "the credential
    /// is bad", it's "we could not determine whether it is", which
    /// `JwtStrategy::authenticate` must propagate as a hard `AuthError`
    /// rather than `Ok(None)` — see that method for why the distinction
    /// matters under `AuthPolicy::FirstSuccess`.
    #[error("DPoP replay protection could not be checked: {0}")]
    DpopReplayUnavailable(String),
}

pub use authkestra_engine::token::jwk::Jwk;

#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Fetches a JWKS with a default [`reqwest::Client`], i.e. the platform trust store.
    ///
    /// Use [`Jwks::fetch_with`] when the endpoint is served by a CA the platform store does
    /// not carry -- a JWKS published inside a cluster under a private CA, for example.
    pub async fn fetch(jwks_uri: &str) -> Result<Self, ValidationError> {
        Self::fetch_with(&reqwest::Client::new(), jwks_uri).await
    }

    /// Fetches a JWKS with a caller-supplied [`reqwest::Client`].
    ///
    /// The client carries the TLS trust configuration, proxy settings and timeouts, so this is
    /// the seam for reaching a JWKS endpoint whose certificate chains to a CA that is not in
    /// the platform trust store. `reqwest::Error` is already part of this crate's public API
    /// via [`ValidationError::Http`], so accepting a client here adds no new coupling.
    pub async fn fetch_with(
        client: &reqwest::Client,
        jwks_uri: &str,
    ) -> Result<Self, ValidationError> {
        // An unreachable, slow or malformed JWKS endpoint is among the most
        // common ways a resource server stops working, and this whole path
        // was silent: the error propagated as `ValidationError::Http` and was
        // only ever seen if some caller happened to log it.
        tracing::debug!(jwks_uri, "fetching JWKS");
        let jwks = match client.get(jwks_uri).send().await {
            Ok(response) => response.json::<Jwks>().await.map_err(|e| {
                tracing::warn!(jwks_uri, error = %e, "JWKS response was not a usable key set");
                ValidationError::Http(e)
            })?,
            Err(e) => {
                tracing::warn!(jwks_uri, error = %e, "could not reach the JWKS endpoint");
                return Err(ValidationError::Http(e));
            }
        };
        tracing::debug!(jwks_uri, keys = jwks.keys.len(), "fetched JWKS");
        Ok(jwks)
    }

    /// Selects the key a token should be verified against.
    ///
    /// Only keys that may actually *verify a signature* are considered
    /// ([`Jwk::is_usable_for_signature_verification`]). A JWKS commonly
    /// carries keys published for something else — a stock Keycloak realm
    /// serves an RSA signing key and an RSA encryption key side by side,
    /// identical in `kty` — and without this filter the `kid`-less fallback
    /// below picks whichever of them JWKS member order happens to put first,
    /// rejecting a good token with a bare `InvalidSignature` (#341). The
    /// filter applies to the `kid` branch too: a `kid` naming an encryption
    /// key is not a licence to verify with it.
    ///
    /// The `kid`-less fallback stays first-match, and so stays ambiguous when
    /// a JWKS holds several *signing* keys. That ambiguity is inherent, and
    /// [`JwksCache::require_kid`] is what closes it.
    pub fn find_key(&self, kid: Option<&str>) -> Option<&Jwk> {
        let mut usable = self.keys.iter().filter(|k| {
            if k.is_usable_for_signature_verification() {
                return true;
            }
            tracing::warn!(
                kid = ?k.kid,
                key_use = ?k.r#use,
                key_ops = ?k.key_ops,
                "skipping a JWKS key that is not published for signature verification"
            );
            false
        });

        match kid {
            Some(id) => usable.find(|k| k.kid.as_deref() == Some(id)),
            None => usable.next(),
        }
    }
}

#[non_exhaustive]
pub struct JwksCache {
    jwks_uri: String,
    jwks: RwLock<Option<(Jwks, Instant)>>,
    ttl: Duration,
    require_kid: bool,
    /// HTTP client used by [`JwksCache::refresh`]. Held for the cache's lifetime rather than
    /// rebuilt per refresh, so the connection pool survives across refreshes, and settable via
    /// [`JwksCache::with_client`] so a JWKS behind a private CA is reachable.
    client: reqwest::Client,
}

impl JwksCache {
    pub fn new(jwks_uri: String, refresh_interval: Duration) -> Self {
        Self {
            jwks_uri,
            jwks: RwLock::new(None),
            ttl: refresh_interval,
            require_kid: false,
            client: reqwest::Client::new(),
        }
    }

    /// Replaces the HTTP client used to fetch the JWKS.
    ///
    /// The default client trusts only the platform certificate store, which makes a JWKS served
    /// under a private CA unreachable -- the common shape being a resource server validating
    /// tokens against an issuer published inside its own cluster, where dialling the public
    /// hostname means leaving and re-entering the network just to fetch keys. Supplying a client
    /// built with that CA added (`reqwest::ClientBuilder::add_root_certificate`) keeps the trust
    /// change scoped to this one fetch, rather than pushing it onto the whole process through
    /// `SSL_CERT_FILE`, which replaces the trust store for every outbound connection.
    ///
    /// Mirrors [`Self::require_kid`]'s consuming-builder shape:
    ///
    /// ```no_run
    /// # use authkestra_resource::jwt::JwksCache;
    /// # use std::time::Duration;
    /// # fn client() -> reqwest::Client { reqwest::Client::new() }
    /// let cache = JwksCache::new("https://idp.internal/jwks".to_string(), Duration::from_secs(300))
    ///     .with_client(client())
    ///     .require_kid(true);
    /// ```
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// When set to `true`, tokens presented without a `kid` header will be rejected
    /// with [`ValidationError::MissingKid`] instead of silently falling back to the
    /// first key in the JWKS. This guards against key-confusion when the JWKS holds
    /// more than one key (e.g. during rotation).
    ///
    /// Defaults to `false` to preserve today's permissive fallback behavior.
    pub fn require_kid(mut self, value: bool) -> Self {
        self.require_kid = value;
        self
    }

    pub async fn get_jwks(&self) -> Result<Jwks, ValidationError> {
        {
            let read_guard = self.jwks.read().await;
            if let Some((jwks, last_updated)) = read_guard.as_ref() {
                if last_updated.elapsed() < self.ttl {
                    return Ok(jwks.clone());
                }
            }
        }

        self.refresh().await
    }

    pub async fn get_key(&self, kid: Option<&str>) -> Result<Option<Jwk>, ValidationError> {
        if kid.is_none() && self.require_kid {
            return Err(ValidationError::MissingKid);
        }

        let jwks = self.get_jwks().await?;
        if let Some(key) = jwks.find_key(kid) {
            return Ok(Some(key.clone()));
        }

        // If key not found, try refreshing once in case of rotation
        tracing::debug!(
            kid,
            "no key for this token in the cached JWKS; refreshing in case of rotation"
        );
        let jwks = self.refresh().await?;
        let key = jwks.find_key(kid).cloned();
        if key.is_none() {
            // Both mean "the endpoint answered and we still have no key", but
            // they are different faults and must not share a message: with no
            // `kid`, `find_key` falls back to the first key, so the only way
            // to get here is an empty key set — the token named nothing.
            match kid {
                Some(kid) => {
                    tracing::warn!(kid, "token names a key the issuer's JWKS does not contain")
                }
                None => tracing::warn!(
                    "token carries no kid and the issuer's JWKS has no key to fall back to"
                ),
            }
        }
        Ok(key)
    }

    pub async fn refresh(&self) -> Result<Jwks, ValidationError> {
        let mut write_guard = self.jwks.write().await;
        let jwks = Jwks::fetch_with(&self.client, &self.jwks_uri).await?;
        *write_guard = Some((jwks.clone(), Instant::now()));
        Ok(jwks)
    }
}

/// Resolves *which* JWKS a token must be verified against, from the token's own
/// `iss` claim.
///
/// This is the seam that lets one resource server trust several issuers (issue
/// #243). `JwtStrategy` uses a built-in implementation for the two configured
/// shapes — [`SingleJwksResolver`] for the classic one-issuer/one-JWKS setup and
/// [`IssuerTrustMap`] for a fixed set of issuers — and
/// [`JwtStrategy::with_resolver`] accepts any other implementation, which is
/// what issuers discovered at runtime (per-tenant, from a registry) need.
///
/// # Security contract for implementors
///
/// An implementation MUST return an error for an issuer it does not recognise.
/// It must **never** fall back to some default JWKS for an unknown `iss`: that
/// turns multi-issuer support into issuer confusion, because any issuer whose
/// keys the fallback endpoint publishes could then mint tokens claiming to come
/// from any other issuer.
///
/// Returning `Arc<JwksCache>` rather than a borrow is deliberate: a dynamic
/// resolver needs to hand out caches it created and stored behind its own lock,
/// which it cannot do by reference.
#[async_trait]
pub trait JwksResolver: Send + Sync {
    /// Resolve the JWKS cache for `issuer`, the token's *not yet verified* `iss`
    /// claim (`None` when the token carries no usable string `iss`).
    async fn resolve(&self, issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError>;
}

/// A [`JwksResolver`] that always resolves to a single JWKS, whatever the token
/// claims as its `iss`.
///
/// This is the pre-#243 behaviour and what `JwtStrategy::new` uses when no trust
/// map is configured: enforcing `iss` (if configured at all) is left entirely to
/// `Validation::set_issuer`, exactly as before. It is only safe *because* there
/// is one endpoint and therefore nothing to confuse — do not reuse it as the
/// default arm of a multi-issuer resolver.
#[non_exhaustive]
pub struct SingleJwksResolver {
    cache: Arc<JwksCache>,
}

impl SingleJwksResolver {
    /// Wrap an existing cache as a resolver.
    pub fn new(cache: Arc<JwksCache>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl JwksResolver for SingleJwksResolver {
    async fn resolve(&self, _issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError> {
        Ok(self.cache.clone())
    }
}

/// A fixed trust map of `iss` -> [`JwksCache`], for a resource server that
/// accepts tokens from a known set of issuers.
///
/// Lookup is exact-match on the `iss` string and has **no default arm**: an
/// unknown issuer yields [`ValidationError::UntrustedIssuer`] and a token with
/// no `iss` yields [`ValidationError::MissingIssuer`]. Each issuer keeps its own
/// cache, so JWKS fetching, TTL and rotation-triggered refresh stay per-endpoint
/// while remaining managed by this crate rather than duplicated by the caller.
///
/// A `BTreeMap` (rather than a `HashMap`) is used so the derived accepted-issuer
/// list handed to `Validation::set_issuer` — and anything logged from it — has a
/// stable order, which keeps failures reproducible.
#[derive(Default)]
#[non_exhaustive]
pub struct IssuerTrustMap {
    caches: BTreeMap<String, Arc<JwksCache>>,
}

impl IssuerTrustMap {
    /// Create an empty trust map. An empty map trusts nobody and rejects every
    /// token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `issuer`, verifying its tokens against `cache`.
    pub fn with_issuer(mut self, issuer: impl Into<String>, cache: Arc<JwksCache>) -> Self {
        self.caches.insert(issuer.into(), cache);
        self
    }

    /// The issuers this map trusts, in sorted order.
    pub fn issuers(&self) -> impl Iterator<Item = &str> {
        self.caches.keys().map(String::as_str)
    }
}

impl FromIterator<(String, Arc<JwksCache>)> for IssuerTrustMap {
    fn from_iter<T: IntoIterator<Item = (String, Arc<JwksCache>)>>(iter: T) -> Self {
        Self {
            caches: iter.into_iter().collect(),
        }
    }
}

#[async_trait]
impl JwksResolver for IssuerTrustMap {
    async fn resolve(&self, issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError> {
        let Some(issuer) = issuer else {
            tracing::warn!("rejecting token with no 'iss' claim: cannot select a signing key");
            return Err(ValidationError::MissingIssuer);
        };

        match self.caches.get(issuer) {
            Some(cache) => {
                tracing::debug!(issuer, "resolved JWKS for token issuer");
                Ok(cache.clone())
            }
            None => {
                // Deliberately no fallback: see the `JwksResolver` security contract.
                tracing::warn!(issuer, "rejecting token from an issuer that is not trusted");
                Err(ValidationError::UntrustedIssuer(issuer.to_string()))
            }
        }
    }
}

/// Configuration for JWT validation.
///
/// Construct this via [`ValidationConfig::builder`]. The type is
/// `#[non_exhaustive]` so that adding a validation knob is a non-breaking
/// change: `jwks_url` has no meaningful default (the builder panics if it is
/// unset), so there is deliberately no `Default` impl to spread from, which
/// left struct-literal construction as the only alternative to the builder —
/// and that made every new field a downstream compile error. `require_kid`
/// (PR #110) and `require_cert_binding` (PR #231, issue #224) were both added
/// that way already; see issue #247. Fields stay `pub` for reading and for
/// post-build mutation.
#[non_exhaustive]
pub struct ValidationConfig {
    pub jwks_url: String,
    pub refresh_interval: Duration,
    pub issuer: Option<String>,
    pub audience: Vec<String>,
    pub algorithms: Vec<Algorithm>,
    pub require_kid: bool,
    /// Clock-skew allowance applied to `exp` and `nbf`, in seconds.
    ///
    /// Defaults to [`DEFAULT_LEEWAY_SECS`] (60) — the same constant
    /// `TokenManager` uses, so a deployment does not have to discover that
    /// the two halves of the system agreed on a tolerance neither of them
    /// stated. Before #350 this was `jsonwebtoken`'s default, applied
    /// silently and with no way to change it.
    ///
    /// Set it to `0` where issuer and validator share a clock, or in tests
    /// that assert on expiry. Raising it widens the window in which an
    /// expired token is still honoured.
    pub leeway: u64,
    /// When `true`, enforce RFC 8705 §3.1 certificate binding: a token
    /// carrying a `cnf.x5t#S256` claim is only accepted if the same
    /// certificate (by SHA-256 thumbprint) was presented on the connection
    /// used to redeem it, and is rejected outright if no certificate was
    /// presented at all. Off by default for backward compatibility — with
    /// this `false`, a certificate-bound token is still accepted as a plain
    /// bearer token, same as before this option existed. See
    /// [`JwtStrategy`] and issue #224.
    pub require_cert_binding: bool,
    /// When `true`, enforce RFC 9449 DPoP key binding: a token carrying a
    /// `cnf.jkt` claim is only accepted if the request presents a `DPoP`
    /// header whose proof verifies for the same key, binds (`ath`) to
    /// *this* access token, and hasn't been seen before (tracked via
    /// [`JwtStrategy::with_dpop_replay_store`]). Off by default for
    /// backward compatibility — with this `false`, a DPoP-bound token's
    /// `cnf.jkt` is simply never checked, so it's accepted exactly as any
    /// other valid token is. Mirrors [`ValidationConfig::require_cert_binding`]'s
    /// design exactly: a token that carries *no* `cnf.jkt` at all is not
    /// DPoP-bound and this check is a no-op for it, regardless of this
    /// setting. See [`JwtStrategy`] and issue #274.
    ///
    /// One respect in which this is *not* "identical to before this option
    /// existed": this crate's `Authorization`-header parsing recognizes the
    /// `DPoP` auth-scheme unconditionally, not only when `require_dpop` is `true`
    /// (parsing the header can't yet know which setting applies). Before
    /// DPoP support existed at all, `Authorization: DPoP <token>` matched
    /// no recognized scheme and this strategy declined the request
    /// outright. Now, with `require_dpop` off, that same request is
    /// accepted — the token is still validated as an ordinary JWT either
    /// way, so this grants no capability a `Bearer`-scheme presentation of
    /// the same token didn't already have while the flag is off, but it is
    /// a genuinely new acceptance path, not merely "same as before" under
    /// a different label.
    ///
    /// `htm` (the request's HTTP method) is always checked. `htu` — the
    /// absolute URL the proof was minted for — is checked only when
    /// [`dpop_resource_origin`](Self::dpop_resource_origin) is configured;
    /// see that field for why it's opt-in rather than always-on. Without
    /// it, key binding, `ath`, and `jti` replay tracking together still
    /// mean a captured proof cannot be reused for a different token, or
    /// reused at all — but a legitimate holder of a still-fresh proof
    /// (a downstream service the request was forwarded to, say) could
    /// present the same token+proof pair to a *different* resource server
    /// within the proof's freshness window; `htu` is what closes that gap.
    pub require_dpop: bool,
    /// This resource server's own origin (scheme + host, e.g.
    /// `"https://api.example.com"` — no path, no trailing slash), used to
    /// reconstruct the current request's absolute URL and check it against
    /// a DPoP proof's `htu` claim (RFC 9449 §4.3 step 6).
    ///
    /// `None` (the default) skips the `htu` check entirely: unlike an
    /// authorization server's single, statically-known `/token` endpoint,
    /// a resource server protects many routes and commonly sits behind a
    /// reverse proxy or load balancer, where the exact absolute URL a
    /// client used isn't always reliably reconstructible from the request
    /// alone (the scheme in particular depends on where TLS terminates,
    /// which application code can't always see) — see
    /// `authkestra_engine::token::dpop::verify_dpop_proof`'s doc comment on
    /// its `expected_htu: None` case. A deployment that *can* state its own
    /// origin reliably (no proxy, or one that's configured to preserve or
    /// forward it accurately) should set this to close the cross-service
    /// forwarding gap [`require_dpop`](Self::require_dpop) documents.
    /// Only consulted when `require_dpop` is also `true`.
    pub dpop_resource_origin: Option<String>,
    /// Trust map of `iss` -> JWKS endpoint, for a resource server that accepts
    /// tokens from several issuers. Empty by default, which keeps the
    /// single-issuer `jwks_url` path unchanged. When non-empty, an `iss` absent
    /// from this map is rejected outright and never falls back to `jwks_url`.
    /// See [`IssuerTrustMap`] and issue #243.
    pub trusted_issuers: BTreeMap<String, String>,
}

impl ValidationConfig {
    /// Create a new builder for `ValidationConfig`.
    pub fn builder() -> ValidationConfigBuilder {
        ValidationConfigBuilder::default()
    }
}

/// A builder for configuring JWT validation.
#[derive(Default)]
#[non_exhaustive]
pub struct ValidationConfigBuilder {
    jwks_url: Option<String>,
    refresh_interval: Option<Duration>,
    issuer: Option<String>,
    audience: Vec<String>,
    algorithms: Vec<Algorithm>,
    require_kid: bool,
    // `Option`, not a bare `u64`: the builder derives `Default`, where a
    // `u64` would default to 0 and silently turn the documented 60-second
    // tolerance into none at all.
    leeway: Option<u64>,
    require_cert_binding: bool,
    require_dpop: bool,
    dpop_resource_origin: Option<String>,
    trusted_issuers: BTreeMap<String, String>,
}

impl ValidationConfigBuilder {
    /// Set the JWKS URL.
    ///
    /// Required unless at least one [`trusted_issuer`](Self::trusted_issuer) is
    /// configured, in which case each issuer brings its own endpoint and this
    /// one applies only to the issuer named by [`issuer`](Self::issuer).
    pub fn jwks_url(mut self, jwks_url: impl Into<String>) -> Self {
        self.jwks_url = Some(jwks_url.into());
        self
    }

    /// Set the refresh interval for the JWKS cache.
    pub fn refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = Some(interval);
        self
    }

    /// Set the expected issuer for the single JWKS set with
    /// [`jwks_url`](Self::jwks_url).
    ///
    /// This is the one-issuer form and is unchanged. Combined with
    /// [`trusted_issuer`](Self::trusted_issuer) entries it simply becomes one
    /// more entry of the trust map (`issuer` -> `jwks_url`).
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Trust `issuer` and verify its tokens against the JWKS published at
    /// `jwks_url`. May be called several times to trust several issuers; a
    /// repeated issuer replaces its previous endpoint.
    ///
    /// Once any entry is present the verifier is in multi-issuer mode: the
    /// token's `iss` claim selects the JWKS, an `iss` outside this map is
    /// rejected with [`ValidationError::UntrustedIssuer`], and a token with no
    /// `iss` at all is rejected with [`ValidationError::MissingIssuer`]. There
    /// is deliberately no fallback endpoint — see [`JwksResolver`].
    pub fn trusted_issuer(
        mut self,
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> Self {
        self.trusted_issuers.insert(issuer.into(), jwks_url.into());
        self
    }

    /// Trust several `(issuer, jwks_url)` pairs at once. Equivalent to calling
    /// [`trusted_issuer`](Self::trusted_issuer) for each pair.
    pub fn trusted_issuers(
        mut self,
        entries: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.trusted_issuers.extend(
            entries
                .into_iter()
                .map(|(issuer, url)| (issuer.into(), url.into())),
        );
        self
    }

    /// Add an expected audience. May be called multiple times to accept tokens scoped to
    /// any one of several audiences. Kept for backward compatibility with single-audience
    /// configuration; prefer [`ValidationConfigBuilder::audiences`] when adding more than one.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience.push(audience.into());
        self
    }

    /// Add multiple expected audiences at once. A token is accepted if its `aud` claim
    /// matches ANY of the configured audiences (e.g. a token valid for both a web app and
    /// a mobile client, or a gateway service that accepts several downstream audiences).
    pub fn audiences(mut self, audiences: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.audience.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Set the allowed algorithms.
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// When `true`, reject tokens that omit a `kid` header instead of silently falling back
    /// to the first key in the JWKS. Off by default for backward compatibility. See
    /// [`JwksCache::require_kid`].
    pub fn require_kid(mut self, value: bool) -> Self {
        self.require_kid = value;
        self
    }

    /// Sets the clock-skew allowance applied to `exp` and `nbf`, in seconds.
    ///
    /// Defaults to [`DEFAULT_LEEWAY_SECS`] (60). See
    /// [`ValidationConfig::leeway`].
    pub fn leeway(mut self, seconds: u64) -> Self {
        self.leeway = Some(seconds);
        self
    }

    /// When `true`, enforce RFC 8705 §3.1 certificate binding. See
    /// [`ValidationConfig::require_cert_binding`]. Off by default.
    pub fn require_cert_binding(mut self, value: bool) -> Self {
        self.require_cert_binding = value;
        self
    }

    /// When `true`, enforce RFC 9449 DPoP key binding. See
    /// [`ValidationConfig::require_dpop`]. Off by default. A deployment
    /// enabling this should also call
    /// [`JwtStrategy::with_dpop_replay_store`] — without one, the
    /// fail-closed [`crate::dpop::NoDpopReplayStore`] default refuses every
    /// DPoP-bound token outright.
    pub fn require_dpop(mut self, value: bool) -> Self {
        self.require_dpop = value;
        self
    }

    /// Set [`ValidationConfig::dpop_resource_origin`], enabling the `htu`
    /// half of the RFC 9449 DPoP check. `origin` is scheme + host only
    /// (e.g. `"https://api.example.com"`) — no path, no trailing slash;
    /// the request's own path is appended at check time. [`Self::build`]
    /// panics if `origin` is missing a scheme or ends with `/`.
    pub fn dpop_resource_origin(mut self, origin: impl Into<String>) -> Self {
        self.dpop_resource_origin = Some(origin.into());
        self
    }

    /// Build a `ValidationConfig`.
    ///
    /// # Panics
    ///
    /// Panics if neither a [`jwks_url`](Self::jwks_url) nor any
    /// [`trusted_issuer`](Self::trusted_issuer) was set, since there would then
    /// be no key material at all. A trust-map-only config leaves `jwks_url`
    /// empty; an empty `jwks_url` is never fetched from, it just means "no
    /// single-issuer endpoint".
    ///
    /// Also panics if [`dpop_resource_origin`](Self::dpop_resource_origin)
    /// isn't a bare `scheme://host` with no path, query, or fragment.
    /// Every one of those shapes is an easy typo
    /// (`"api.example.com"` with no scheme; `"https://api.example.com/"`
    /// with a trailing slash; `"https://api.example.com?x=1"` with a
    /// query) that would otherwise silently break *every* DPoP request
    /// once `require_dpop` is on, with nothing but a `tracing::warn!` per
    /// request to show for it — indistinguishable from an actual attack.
    /// Checking the shape here, once, at startup, is cheaper than
    /// debugging that in production. See the panicking checks themselves
    /// for exactly which failure mode each one closes.
    pub fn build(self) -> ValidationConfig {
        let jwks_url = match self.jwks_url {
            Some(jwks_url) => jwks_url,
            None => {
                assert!(
                    !self.trusted_issuers.is_empty(),
                    "JWKS URL must be set for ValidationConfig (or at least one trusted_issuer)"
                );
                String::new()
            }
        };

        if let Some(origin) = &self.dpop_resource_origin {
            let parsed = url::Url::parse(origin).unwrap_or_else(|e| {
                panic!(
                    "ValidationConfigBuilder::dpop_resource_origin must be a valid absolute \
                     URL (e.g. \"https://api.example.com\"), got {origin:?}: {e}"
                )
            });
            // `Url::parse` requires a scheme to succeed at all, and
            // normalizes it to lowercase — so this is naturally
            // case-insensitive, matching `strip_scheme_ci`'s treatment of
            // the `Authorization` header's own scheme elsewhere in this
            // file, and rejects non-HTTP schemes a resource server could
            // never actually be reached on.
            assert!(
                parsed.scheme() == "http" || parsed.scheme() == "https",
                "ValidationConfigBuilder::dpop_resource_origin must use http or https, got \
                 {origin:?}"
            );
            assert!(
                parsed.host().is_some(),
                "ValidationConfigBuilder::dpop_resource_origin must include a host, got \
                 {origin:?}"
            );
            // `htu` canonicalization (on the request side) strips query and
            // fragment before comparing, so either one here could never
            // survive into a match against a genuine proof — same
            // always-fails-every-request class as the other checks here.
            assert!(
                parsed.query().is_none() && parsed.fragment().is_none(),
                "ValidationConfigBuilder::dpop_resource_origin must not include a query or \
                 fragment, got {origin:?}"
            );
            // Checked on the raw string, not `parsed`: `Url::parse` treats
            // "https://api.example.com" and "https://api.example.com/" as
            // the same path ("/"), but the runtime check concatenates
            // this *string* directly with the request's own leading-`/`
            // path, so a trailing slash here still produces a `//` that a
            // genuine proof's `htu` never has, regardless of how `Url`
            // would normalize it.
            assert!(
                !origin.ends_with('/'),
                "ValidationConfigBuilder::dpop_resource_origin must not end with a trailing \
                 slash — it's joined directly with the request's own path, which always \
                 starts with one — got {origin:?}"
            );
        }

        ValidationConfig {
            jwks_url,
            refresh_interval: self
                .refresh_interval
                .unwrap_or_else(|| Duration::from_secs(3600)),
            issuer: self.issuer,
            audience: self.audience,
            algorithms: if self.algorithms.is_empty() {
                vec![Algorithm::RS256]
            } else {
                self.algorithms
            },
            require_kid: self.require_kid,
            leeway: self.leeway.unwrap_or(DEFAULT_LEEWAY_SECS),
            require_cert_binding: self.require_cert_binding,
            require_dpop: self.require_dpop,
            dpop_resource_origin: self.dpop_resource_origin,
            trusted_issuers: self.trusted_issuers,
        }
    }
}

/// A JWT authentication strategy that performs offline JWT validation using JWKS.
#[non_exhaustive]
pub struct JwtStrategy<I> {
    resolver: Box<dyn JwksResolver>,
    validation: Validation,
    require_cert_binding: bool,
    require_dpop: bool,
    dpop_resource_origin: Option<String>,
    dpop_replay_store: Arc<dyn crate::dpop::DpopReplayStore>,
    _marker: std::marker::PhantomData<I>,
}

impl<I> JwtStrategy<I> {
    /// Create a new `JwtStrategy` with the given `ValidationConfig`.
    ///
    /// With an empty [`ValidationConfig::trusted_issuers`] this is the classic
    /// single-issuer verifier and behaves exactly as it did before #243: one
    /// JWKS at `jwks_url`, and `iss` checked only if `issuer` was set.
    ///
    /// With a non-empty trust map it becomes a multi-issuer verifier — see
    /// [`ValidationConfigBuilder::trusted_issuer`].
    pub fn new(config: ValidationConfig) -> Self {
        let resolver = build_resolver(&config);
        Self {
            resolver,
            validation: build_validation(&config, !config.trusted_issuers.is_empty()),
            require_cert_binding: config.require_cert_binding,
            require_dpop: config.require_dpop,
            dpop_resource_origin: config.dpop_resource_origin,
            dpop_replay_store: Arc::new(crate::dpop::NoDpopReplayStore),
            _marker: std::marker::PhantomData,
        }
    }

    /// Create a `JwtStrategy` that resolves signing keys through a
    /// caller-supplied [`JwksResolver`], for issuers that are not known up front
    /// (per-tenant, fetched from a registry, ...).
    ///
    /// `config`'s `jwks_url` and `trusted_issuers` are ignored — the resolver
    /// owns key resolution entirely — but the rest of the config still applies,
    /// including the accepted-`iss` set fed to `Validation`. Note that if
    /// `config` names no issuers at all, `iss` is not checked by `Validation`
    /// and the resolver alone is the trust decision, so it must reject unknown
    /// issuers rather than defaulting.
    pub fn with_resolver(config: ValidationConfig, resolver: Box<dyn JwksResolver>) -> Self {
        Self {
            resolver,
            // Unconditionally multi-issuer: supplying your own resolver *is* the
            // multi-issuer case, whether or not a static trust map accompanies it.
            validation: build_validation(&config, true),
            require_cert_binding: config.require_cert_binding,
            require_dpop: config.require_dpop,
            dpop_resource_origin: config.dpop_resource_origin,
            dpop_replay_store: Arc::new(crate::dpop::NoDpopReplayStore),
            _marker: std::marker::PhantomData,
        }
    }

    /// Supplies the [`crate::dpop::DpopReplayStore`] this strategy checks
    /// DPoP proof `jti`s against, replacing the fail-closed
    /// [`crate::dpop::NoDpopReplayStore`] default.
    ///
    /// Only meaningful alongside [`ValidationConfig::require_dpop`] — without
    /// it, no token ever reaches the DPoP check this store backs, so a
    /// deployment that calls this but not `require_dpop` sees no effect.
    pub fn with_dpop_replay_store(mut self, store: Arc<dyn crate::dpop::DpopReplayStore>) -> Self {
        self.dpop_replay_store = store;
        self
    }
}

/// Builds the key-resolution half of a [`JwtStrategy`] from a config.
///
/// The two shapes are kept apart on purpose: with no trust map the resolver is
/// the identity-like [`SingleJwksResolver`], so the pre-#243 path keeps byte-for-byte
/// the same behaviour (including "no `iss` configured" meaning "`iss` not checked").
fn build_resolver(config: &ValidationConfig) -> Box<dyn JwksResolver> {
    let cache_for = |jwks_url: &str| {
        Arc::new(
            JwksCache::new(jwks_url.to_string(), config.refresh_interval)
                .require_kid(config.require_kid),
        )
    };

    if config.trusted_issuers.is_empty() {
        return Box::new(SingleJwksResolver::new(cache_for(&config.jwks_url)));
    }

    let mut caches: BTreeMap<String, Arc<JwksCache>> = config
        .trusted_issuers
        .iter()
        .map(|(issuer, jwks_url)| (issuer.clone(), cache_for(jwks_url)))
        .collect();

    // The single-issuer pair is folded in as one more trust-map entry, which is
    // what makes `issuer` + `jwks_url` "the one-entry case" rather than a second,
    // parallel mechanism. Without an `issuer` to name it, a `jwks_url` cannot be
    // folded in at all: using it as a default arm is exactly the issuer confusion
    // the trust map exists to prevent, so it is dropped loudly instead.
    match &config.issuer {
        Some(issuer) if !config.jwks_url.is_empty() => {
            caches
                .entry(issuer.clone())
                .or_insert_with(|| cache_for(&config.jwks_url));
        }
        None if !config.jwks_url.is_empty() => {
            tracing::warn!(
                jwks_url = %config.jwks_url,
                "ignoring jwks_url: with a trusted_issuers map configured and no issuer naming it, \
                 it could only act as a fallback for untrusted issuers, which is never allowed"
            );
        }
        _ => {}
    }

    Box::new(caches.into_iter().collect::<IssuerTrustMap>())
}

/// Builds the claim-validation half of a [`JwtStrategy`] from a config.
fn build_validation(config: &ValidationConfig, multi_issuer: bool) -> Validation {
    let mut validation = Validation::new(config.algorithms[0]);
    validation.algorithms = config.algorithms.clone();
    validation.validate_nbf = true;
    // Set explicitly rather than left to `jsonwebtoken`'s default, so the
    // window in which an expired token is still honoured is this crate's
    // decision and is visible in `ValidationConfig` (#350).
    validation.leeway = config.leeway;

    // `set_issuer` has always taken a slice; the pre-#243 config simply had no
    // way to express more than one name. Every trusted issuer goes in, so a
    // token verified with issuer B's key still has to *say* it came from B.
    let mut accepted_issuers: Vec<&String> = config.trusted_issuers.keys().collect();
    // The `!jwks_url.is_empty()` condition mirrors `build_resolver` exactly. Both
    // must agree on whether `config.issuer` is a resolvable issuer: `build_resolver`
    // folds it into the trust map only when there is a `jwks_url` for it, so adding
    // it here unconditionally would leave `Validation` accepting a name the resolver
    // can never resolve. That is fail-closed (the resolver errors first), but a
    // backstop widened past the thing it backstops is not one you want to keep —
    // and the same `Validation` is handed to third-party resolvers. Raised in
    // review of #243.
    if let Some(issuer) = config
        .issuer
        .as_ref()
        .filter(|issuer| !config.trusted_issuers.contains_key(*issuer))
        .filter(|_| !config.jwks_url.is_empty())
    {
        accepted_issuers.push(issuer);
    }

    if !accepted_issuers.is_empty() {
        validation.set_issuer(&accepted_issuers);
    }

    // In multi-issuer mode `iss` selects the key. In single-issuer mode, we now also
    // strictly require the `iss` claim if an issuer was configured, closing the legacy
    // laxity where an `iss`-less token was accepted.
    if multi_issuer || !accepted_issuers.is_empty() {
        validation.required_spec_claims.insert("iss".to_string());
    }

    if !config.audience.is_empty() {
        validation.set_audience(&config.audience);
    }

    validation
}

#[async_trait]
impl<I> AuthenticationStrategy<I> for JwtStrategy<I>
where
    I: for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    // `skip_all`: `parts` carries the `Authorization` header, and a derived
    // span field would print the bearer token. The span exists so the dozen
    // rejection events in this function can be correlated to one request,
    // which is what having none of them under a span cost (#353).
    #[tracing::instrument(skip_all, name = "jwt_authenticate")]
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(presented) = extract_presented_token(&parts.headers) {
            let token = presented.token();
            // Resolve once and reuse the same cache below: which JWKS applies is
            // a property of the token, so re-resolving for the `cnf` re-decode
            // could only introduce a discrepancy.
            let cache = match resolve_cache(token, self.resolver.as_ref()).await {
                Ok(cache) => cache,
                Err(
                    e @ (ValidationError::InvalidToken(_)
                    | ValidationError::Jwt(_)
                    | ValidationError::UntrustedIssuer(_)
                    | ValidationError::MissingIssuer),
                ) => {
                    tracing::debug!(error = %e, "could not read or trust the token's issuer; no identity");
                    return Ok(None);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not resolve a JWKS for the token's issuer; rejecting token");
                    return Err(AuthError::Token(e.to_string()));
                }
            };

            match validate_jwt_generic::<I>(token, &cache, &self.validation).await {
                Ok(claims) => {
                    if self.require_cert_binding || self.require_dpop {
                        // Re-decode as `CnfClaim` to read `cnf` regardless of
                        // what identity type `I` the caller asked for — `I`
                        // is not required to expose `cnf` itself, so this
                        // can't be read off of `claims` above. The token was
                        // already fully verified by the decode above; this
                        // second decode reuses the same cache/validation and
                        // cannot itself fail differently, short of key
                        // rotation racing between the two calls, which is
                        // treated the same as any other verification
                        // failure: reject. Shared between both checks below
                        // since a token can carry both `cnf.x5t#S256` and
                        // `cnf.jkt` at once (RFC 9449 §6.1).
                        let cnf_claim = match validate_jwt_generic::<CnfClaim>(
                            token,
                            &cache,
                            &self.validation,
                        )
                        .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to re-decode token while checking cnf-based binding");
                                return Ok(None);
                            }
                        };

                        if self.require_cert_binding {
                            let cert_der = parts
                                .extensions
                                .get::<ClientCertificateDer>()
                                .map(|c| c.0.as_slice());

                            if let Err(e) = verify_cert_binding(cert_der, cnf_claim.cnf.as_ref()) {
                                tracing::warn!(error = %e, "RFC 8705 certificate-binding check failed; rejecting token");
                                return Ok(None);
                            }
                        }

                        if self.require_dpop {
                            let is_dpop_bound = dpop_bound_jkt(cnf_claim.cnf.as_ref()).is_some();

                            // RFC 9449 §7.1, both directions of the same
                            // requirement: a DPoP-bound token MUST be
                            // presented via the `DPoP` auth-scheme, never
                            // `Bearer`, and a request presented via `DPoP`
                            // MUST carry a token that actually has a
                            // confirmation claim to check. The first is
                            // checked independently of whether a `DPoP`
                            // proof header also happens to be present,
                            // since accepting either scheme for a bound
                            // token would let a client (or attacker holding
                            // a stolen token) simply choose the scheme
                            // requiring no proof at all. Neither case falls
                            // out of `verify_dpop_binding` on its own: an
                            // absent `cnf.jkt` makes it a no-op by design
                            // (mirroring `verify_cert_binding`), which is
                            // correct for `Bearer` but not for `DPoP`.
                            match (presented, is_dpop_bound) {
                                (PresentedToken::Bearer(_), true) => {
                                    tracing::warn!(
                                        "token is DPoP-bound (cnf.jkt) but was presented via \
                                         the Bearer scheme, not DPoP; rejecting"
                                    );
                                    return Ok(None);
                                }
                                (PresentedToken::DPoP(_), false) => {
                                    tracing::warn!(
                                        "request used the DPoP auth-scheme but the token \
                                         carries no cnf.jkt confirmation claim; rejecting"
                                    );
                                    return Ok(None);
                                }
                                _ => {}
                            }

                            let dpop_header = match extract_dpop_header(&parts.headers) {
                                Ok(h) => h,
                                Err(e) => {
                                    tracing::warn!(error = %e, "malformed DPoP header; rejecting token");
                                    return Ok(None);
                                }
                            };

                            let htu = self
                                .dpop_resource_origin
                                .as_deref()
                                .map(|origin| format!("{origin}{}", parts.uri.path()));

                            match verify_dpop_binding(
                                dpop_header,
                                parts.method.as_str(),
                                htu.as_deref(),
                                token,
                                cnf_claim.cnf.as_ref(),
                                self.dpop_replay_store.as_ref(),
                            )
                            .await
                            {
                                Ok(()) => {}
                                // The credential itself is bad (missing/malformed
                                // proof, wrong key, wrong ath, already-used jti,
                                // wrong method) — decline this strategy, same as
                                // every other "invalid token" outcome above.
                                Err(e @ ValidationError::InvalidToken(_)) => {
                                    tracing::warn!(error = %e, "RFC 9449 DPoP binding check failed; rejecting token");
                                    return Ok(None);
                                }
                                // Replay protection could not be *checked* at
                                // all (store errored, or none is configured) —
                                // this is not "the token is invalid", it's "we
                                // don't know", and must not be reported as
                                // `Ok(None)`: under `AuthPolicy::FirstSuccess` a
                                // `Guard` chain would treat that as "this
                                // strategy declined, try the next one", letting
                                // a replay-store outage silently authenticate
                                // the request with the DPoP check skipped
                                // entirely. Propagating `Err` here matches how
                                // the JWKS-resolution failure above is already
                                // handled, for the identical reason.
                                Err(e) => {
                                    tracing::warn!(error = %e, "could not verify DPoP replay protection; rejecting request");
                                    return Err(AuthError::Token(e.to_string()));
                                }
                            }
                        }
                    }
                    Ok(Some(claims))
                }
                // A token that failed signature or claim validation. This
                // returns `Ok(None)` — "declined", so another strategy may
                // still run — and used to do so silently, which left the
                // resource server unable to answer the one question anyone
                // asks it: why was that token rejected? #335 is exactly that
                // question, and answering it took reading a dependency's
                // source. `debug!`, not `warn!`, to match the issuer-decline
                // above: under a first-success policy a decline is ordinary.
                Err(e @ (ValidationError::InvalidToken(_) | ValidationError::Jwt(_))) => {
                    tracing::debug!(error = %e, "token failed validation; no identity");
                    Ok(None)
                }
                // Everything else — a JWKS that could not be fetched, a key
                // that could not be found, replay protection that could not
                // be checked — is not "this credential is bad" but "we could
                // not tell", and is propagated as a hard error.
                Err(e) => {
                    tracing::warn!(error = %e, "could not determine whether the token is valid");
                    Err(AuthError::Token(e.to_string()))
                }
            }
        } else {
            Ok(None)
        }
    }
}

/// The subset of a token's claims this crate needs to check RFC 8705
/// certificate binding — just the `cnf` confirmation claim, decoded
/// independently of whatever identity type `I` a `JwtStrategy<I>` caller
/// asked for.
#[derive(Debug, Deserialize)]
struct CnfClaim {
    #[serde(default)]
    cnf: Option<serde_json::Value>,
}

/// Verifies RFC 8705 §3.1 certificate binding for a decoded token's `cnf`
/// claim.
///
/// - If the token carries no `cnf.x5t#S256` claim at all, it is not
///   certificate-bound; this always succeeds (nothing to check).
/// - If it does, `cert_der` — the DER bytes of the certificate presented on
///   the current connection, if any — must be present and its SHA-256
///   thumbprint must match, in constant time. A certificate-bound token is
///   **never** accepted as a plain bearer token: an absent certificate is
///   rejected exactly like a mismatched one.
pub fn verify_cert_binding(
    cert_der: Option<&[u8]>,
    cnf: Option<&serde_json::Value>,
) -> Result<(), ValidationError> {
    let expected = cnf.and_then(|v| v.get("x5t#S256")).and_then(|v| v.as_str());

    match (cert_der, expected) {
        (Some(cert_der), Some(expected)) => {
            let actual = x5t_s256_thumbprint(cert_der);
            if constant_time_eq(&actual, expected) {
                Ok(())
            } else {
                Err(ValidationError::InvalidToken(
                    "presented mTLS client certificate does not match the token's cnf.x5t#S256"
                        .to_string(),
                ))
            }
        }
        (None, Some(_)) => Err(ValidationError::InvalidToken(
            "token is certificate-bound (cnf.x5t#S256) but no client certificate was presented"
                .to_string(),
        )),
        (_, None) => Ok(()),
    }
}

/// The credential carried by a request's `Authorization` header, tagged by
/// which auth-scheme carried it.
///
/// RFC 9449 §7.1 requires a DPoP-bound access token be presented as
/// `Authorization: DPoP <token>`, never `Bearer <token>` — the two schemes
/// are not interchangeable spellings of "here is a token". A resource
/// server that pulled the token out without recording which scheme it
/// arrived under (as `authkestra_engine::strategy::utils::extract_bearer_token` alone does — it only
/// recognizes `Bearer`) could never enforce that distinction: nothing
/// among a token's own claims says which scheme it *arrived* under, only
/// [`JwtStrategy::authenticate`] observing the header directly can, and
/// only if this type keeps the two apart.
#[derive(Clone, Copy)]
enum PresentedToken<'a> {
    Bearer(&'a str),
    DPoP(&'a str),
}

impl<'a> PresentedToken<'a> {
    fn token(&self) -> &'a str {
        match self {
            PresentedToken::Bearer(t) | PresentedToken::DPoP(t) => t,
        }
    }
}

/// Reads the request's `Authorization` header, recognizing both the
/// `Bearer` and `DPoP` schemes (RFC 9449 §7.1) — unlike
/// `authkestra_engine::strategy::utils::extract_bearer_token`, which exists for every other strategy
/// in this workspace and has no reason to know about DPoP.
fn extract_presented_token(headers: &http::HeaderMap) -> Option<PresentedToken<'_>> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = strip_scheme_ci(value, "DPoP") {
        return Some(PresentedToken::DPoP(token));
    }
    if let Some(token) = strip_scheme_ci(value, "Bearer") {
        return Some(PresentedToken::Bearer(token));
    }
    None
}

/// Strips an `Authorization` header's auth-scheme token and the single
/// space after it, comparing the scheme case-insensitively per RFC 9110
/// §11.1 ("the auth-scheme value is case-insensitive"). A plain
/// `strip_prefix("DPoP ")` would silently reject `dpop <token>` — a
/// case a real client sending a lowercase scheme would hit with no
/// diagnostic at all, since a parse miss here just falls through to
/// `Ok(None)` ("no credential presented").
fn strip_scheme_ci<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let (candidate, rest) = value.split_at_checked(scheme.len())?;
    if !candidate.eq_ignore_ascii_case(scheme) {
        return None;
    }
    rest.strip_prefix(' ').map(str::trim)
}

/// Reads the request's `DPoP` header (RFC 9449 §4.1: exactly one is
/// expected). Returns `Ok(None)` if it's absent, `Ok(Some(value))` if
/// exactly one occurrence is present and valid ASCII, or `Err` in two
/// cases refused outright rather than tolerated: more than one occurrence
/// (ambiguous which is authoritative — a proxy bug or smuggling attempt
/// could produce this) and a value that isn't valid ASCII (treating it as
/// "no header" would silently accept as a plain bearer token what the
/// client believes is sender-constrained). Mirrors the identical helper in
/// `authkestra-axum`/`authkestra-actix`'s `/token` handlers.
fn extract_dpop_header(headers: &http::HeaderMap) -> Result<Option<&str>, ValidationError> {
    let mut dpop_headers = headers.get_all("DPoP").iter();
    match (dpop_headers.next(), dpop_headers.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(ValidationError::InvalidToken(
            "multiple DPoP headers were presented".to_string(),
        )),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| {
            ValidationError::InvalidToken("DPoP header value is not valid ASCII".to_string())
        }),
    }
}

/// RFC 9449 §4.2's `ath` claim is `base64url(SHA256(access_token))` — the
/// exact same computation `x5t_s256_thumbprint` already does, just over the
/// access token's UTF-8 bytes instead of a certificate's DER bytes. Reusing
/// it avoids a second three-line SHA-256-then-base64url helper for an
/// identical operation.
fn compute_ath(access_token: &str) -> String {
    x5t_s256_thumbprint(access_token.as_bytes())
}

/// Reads `cnf.jkt` out of a decoded token's `cnf` claim, if present — the
/// single "is this token DPoP-bound" predicate, shared by
/// [`JwtStrategy::authenticate`] (which needs it to decide whether the
/// `DPoP` auth-scheme is required) and [`verify_dpop_binding`] (which needs
/// it to know what key a presented proof must match). Kept as one function
/// so the two call sites can't drift apart on what "bound" means.
fn dpop_bound_jkt(cnf: Option<&serde_json::Value>) -> Option<&str> {
    cnf.and_then(|v| v.get("jkt")).and_then(|v| v.as_str())
}

/// Verifies RFC 9449 DPoP key binding for a decoded token's `cnf` claim.
///
/// - If the token carries no `cnf.jkt` claim at all, it is not DPoP-bound;
///   this always succeeds (nothing to check) — mirrors
///   [`verify_cert_binding`]'s identical "absent means not bound" shape.
///   `JwtStrategy::authenticate` is responsible for rejecting the *other*
///   mismatch this function can't see on its own — a request presented via
///   the `DPoP` auth-scheme for a token that isn't actually bound.
/// - If it is bound, `dpop_header` must be present, and the proof it
///   contains must: verify (signature, `typ`, freshness), bind to
///   `access_token` via `ath`, carry the same key as `cnf.jkt`, and — when
///   `htu` is `Some` — have been minted for this exact URL. `htu` is
///   `None` unless the caller configured
///   [`ValidationConfig::dpop_resource_origin`]; see that field's doc
///   comment for why it's opt-in.
/// - Finally, the proof's `jti` is checked and recorded via
///   `replay_store`: a DPoP-bound token is **never** accepted with a reused
///   proof, and a proof that can't be recorded at all (e.g. no replay store
///   configured) is refused rather than let through unchecked.
pub async fn verify_dpop_binding(
    dpop_header: Option<&str>,
    htm: &str,
    htu: Option<&str>,
    access_token: &str,
    cnf: Option<&serde_json::Value>,
    replay_store: &dyn crate::dpop::DpopReplayStore,
) -> Result<(), ValidationError> {
    let Some(expected_jkt) = dpop_bound_jkt(cnf) else {
        return Ok(());
    };

    let Some(proof) = dpop_header else {
        return Err(ValidationError::InvalidToken(
            "token is DPoP-bound (cnf.jkt) but no DPoP proof was presented".to_string(),
        ));
    };

    let ath = compute_ath(access_token);
    let verified = authkestra_engine::token::dpop::verify_dpop_proof(
        proof,
        htm,
        htu,
        Some(&ath),
        chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS),
    )
    .map_err(|e| ValidationError::InvalidToken(format!("invalid DPoP proof: {e}")))?;

    if !constant_time_eq(&verified.jkt, expected_jkt) {
        return Err(ValidationError::InvalidToken(
            "DPoP proof key does not match the token's cnf.jkt".to_string(),
        ));
    }

    // Anchored to the proof's own `iat`, not the current time — see the
    // identical comment on the OP-side `/token` DPoP check
    // (`authkestra_op::handlers::token::handle_token_with_client_cert`)
    // for the full reasoning: anchoring to `Utc::now()` instead would let
    // the replay record expire before the proof's own freshness boundary
    // (`iat + max_age`) whenever this request is processed even slightly
    // after `iat`, opening a real, if narrow, replay window. The extra
    // second guards the exact boundary instant itself.
    let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(verified.iat, 0)
        .unwrap_or_else(chrono::Utc::now)
        + chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS)
        + chrono::Duration::seconds(1);
    match replay_store
        .check_and_record_dpop_jti(&verified.jti, expires_at)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(ValidationError::InvalidToken(
            "DPoP proof has already been used".to_string(),
        )),
        Err(e) => Err(e),
    }
}

/// Reads the `iss` claim out of a JWT payload **without verifying the
/// signature**, returning `None` if there is no `iss` or it is not a string.
///
/// Only ever used to *select* which key to verify with, never to make a trust
/// decision on its own. That is safe because the value is re-checked after
/// verification: the payload this reads is the same signature-covered payload
/// `decode` parses, and `Validation`'s accepted-issuer set (populated from the
/// trust map by [`build_validation`]) rejects the token if its `iss` is not one
/// of the trusted names. So an attacker choosing `iss` only chooses which
/// issuer's key their signature must satisfy.
///
/// The payload is decoded by hand rather than via `jsonwebtoken`'s
/// signature-disabled decode path, which would need a dummy key and a second
/// `Validation` whose knobs could drift from the real one.
fn unverified_issuer(token: &str) -> Result<Option<String>, ValidationError> {
    let mut segments = token.split('.');
    let payload = match (segments.next(), segments.next(), segments.next()) {
        (Some(_), Some(payload), Some(_)) => payload,
        _ => {
            return Err(ValidationError::InvalidToken(
                "token is not a well-formed JWS compact serialization".to_string(),
            ))
        }
    };
    // Reject a fourth segment explicitly. Without this, `h.p1.p2.s` yields `p1`
    // here while `jsonwebtoken` (two `rsplitn(2, '.')` passes) reads `p2` as the
    // payload — so the issuer used to *select* a key and the claims that get
    // *validated* would come from different segments. That disagreement is the
    // classic select-one-key/validate-another setup. It is fail-closed today only
    // by accident (`decode_header` receives `"h.p1"`, whose `.` base64 rejects),
    // which is not a property worth resting on. Raised in review of #243.
    if segments.next().is_some() {
        return Err(ValidationError::InvalidToken(
            "token has more than three segments; a JWS compact serialization has exactly three"
                .to_string(),
        ));
    }

    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|e| {
        ValidationError::InvalidToken(format!("token payload is not valid base64url: {e}"))
    })?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).map_err(|e| {
        ValidationError::InvalidToken(format!("token payload is not a JSON object: {e}"))
    })?;

    Ok(claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string))
}

/// Resolves the JWKS cache a token must be verified against, from its own `iss`.
async fn resolve_cache(
    token: &str,
    resolver: &dyn JwksResolver,
) -> Result<Arc<JwksCache>, ValidationError> {
    let issuer = unverified_issuer(token)?;
    resolver.resolve(issuer.as_deref()).await
}

/// Validates a JWT, resolving the JWKS to verify it against from the token's
/// `iss` claim via `resolver`.
///
/// This is the multi-issuer counterpart of [`validate_jwt_generic`], for callers
/// that verify tokens outside a [`JwtStrategy`]. `validation` must still carry
/// the accepted-issuer set (see [`ValidationConfigBuilder::trusted_issuer`]):
/// the resolver decides *which key*, `validation` decides *which names are
/// acceptable*, and both must agree for a token to be accepted.
pub async fn validate_jwt_with_resolver<T>(
    token: &str,
    resolver: &dyn JwksResolver,
    validation: &Validation,
) -> Result<T, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    // Reported here rather than left to the callee: this happens *before*
    // `validate_jwt_generic`, so its span does not exist yet and its outcome
    // line never runs. `UntrustedIssuer` and `MissingIssuer` are exactly the
    // misconfigurations an operator needs named — a token from an issuer the
    // trust map does not carry is otherwise just "rejected".
    let cache = resolve_cache(token, resolver).await.inspect_err(|error| {
        tracing::warn!(%error, "could not resolve a JWKS for this token's issuer");
    })?;
    validate_jwt_generic::<T>(token, &cache, validation).await
}

/// Validates a JWT against the cached JWKS.
pub async fn validate_jwt(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<Claims, ValidationError> {
    validate_jwt_generic::<Claims>(token, cache, validation).await
}

/// Validates a JWT against the cached JWKS with generic claims.
#[tracing::instrument(
    name = "validate_jwt",
    // `token` is the credential and `cache` holds key material; neither is a
    // span field. `kid` and `alg` are not known until the header is decoded,
    // so they are declared empty and recorded once they are.
    skip_all,
    fields(kid = tracing::field::Empty, alg = tracing::field::Empty)
)]
pub async fn validate_jwt_generic<T>(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<T, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    // A span, because this is the one place every caller converges: both
    // `validate_jwt` and `validate_jwt_with_resolver` delegate here, so it is
    // where per-request events can be correlated. #353 named the absence of
    // one as what makes this path expensive to debug, and #335 is the
    // evidence — an `InvalidAlgorithm` that could only be diagnosed by
    // reading `jsonwebtoken`'s source.
    //
    // The outcome is reported once here rather than at each of the six ways
    // this can fail, matching `verify_dpop_proof` (#353 tier 1). Every one of
    // them arrived by `?` and emitted nothing, so a rejected token said only
    // that it was rejected.
    let outcome = validate_jwt_generic_inner::<T>(token, cache, validation).await;

    match &outcome {
        Ok(_) => tracing::debug!("token accepted"),
        Err(error) => tracing::warn!(%error, "token rejected"),
    }

    outcome
}

/// The validation itself. Split out so [`validate_jwt_generic`] can report the
/// outcome in one place; see the comment there.
async fn validate_jwt_generic_inner<T>(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<T, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    let header = decode_header(token)?;
    let kid = header.kid.as_deref();

    // Recorded as soon as they are known, so even a failure below carries the
    // two fields anyone debugging this actually asks for first.
    let span = tracing::Span::current();
    span.record("alg", tracing::field::debug(header.alg));
    if let Some(kid) = kid {
        span.record("kid", kid);
    }

    let jwk = cache
        .get_key(kid)
        .await?
        .ok_or(ValidationError::KeyNotFound)?;

    let decoding_key = jwk.to_decoding_key()?;
    let validation = narrow_to_header_family(validation, header.alg)?;
    let token_data = decode::<T>(token, &decoding_key, &validation)?;

    Ok(token_data.claims)
}

/// Restricts `validation` to the algorithms that share a key family with the
/// token header's own `alg`.
///
/// `jsonwebtoken` does not merely require that the header's `alg` be *among*
/// `validation.algorithms`; it requires that **every** entry of that list
/// belong to the same key family as the verifying key
/// (`decoding::verify_signature_body`). A policy naming more than one family
/// is therefore unverifiable by construction: whatever the token is signed
/// with, the first entry from another family fails the loop and the whole
/// decode returns `InvalidAlgorithm`.
///
/// That is exactly the policy an OIDC discovery document produces. Keycloak
/// advertises all twelve algorithms across the HMAC/RSA/EC/Ed families in
/// `id_token_signing_alg_values_supported`, so `authkestra-oidc`'s
/// discovery-derived default rejected *every* ID token from *every* Keycloak
/// deployment with a bare `InvalidAlgorithm` (#335). The same applied to a
/// `ValidationConfig` whose `algorithms` deliberately spans families, which
/// is the natural way to write "this resource server accepts RS256 or ES256".
///
/// # Why this does not weaken the policy
///
/// The set is only ever *narrowed*, and only to algorithms the caller already
/// listed — a token signed with an algorithm outside the caller's policy is
/// still rejected, by the explicit check below. What narrowing removes is
/// `jsonwebtoken`'s use of the list as a proxy for "which family is this key",
/// and that proxy is not what protects against algorithm confusion: each
/// verifier re-checks the key's own family when it is constructed
/// (`DecodingKey::family` → `ErrorKind::InvalidKeyFormat`), so an RSA JWK
/// presented for an `HS256` header still fails there, with the public key
/// never reaching the HMAC verifier.
fn narrow_to_header_family(
    validation: &Validation,
    header_alg: Algorithm,
) -> Result<Validation, ValidationError> {
    if !validation.algorithms.contains(&header_alg) {
        return Err(ValidationError::InvalidToken(format!(
            "token is signed with {header_alg:?}, which this validation policy does not accept \
             (accepted: {:?})",
            validation.algorithms
        )));
    }

    let mut narrowed = validation.clone();
    narrowed
        .algorithms
        .retain(|alg| alg.family() == header_alg.family());
    tracing::debug!(
        header_alg = ?header_alg,
        accepted = ?validation.algorithms,
        narrowed = ?narrowed.algorithms,
        "narrowed the accepted algorithm set to the token header's key family"
    );
    Ok(narrowed)
}

/// Validates a PASETO V4 Local/Public token.
/// Note: This implementation assumes V4 Public for parity with JWKS-like usage if applicable,
/// but PASETO usually handles its own keying. This is a placeholder for the requested logic.
pub async fn validate_paseto(_token: &str, _key: &[u8]) -> Result<Claims, ValidationError> {
    // PASETO validation logic using the `paseto` crate
    // For now, returning an error as PASETO JWKS integration is non-standard
    Err(ValidationError::Paseto(
        "PASETO validation not yet fully implemented with JWKS".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cnf_with_thumbprint(thumbprint: &str) -> serde_json::Value {
        serde_json::json!({ "x5t#S256": thumbprint })
    }

    #[test]
    fn accepts_when_no_cnf_claim_present_regardless_of_certificate() {
        // Not a certificate-bound token: nothing to check, with or without a
        // presented certificate.
        assert!(verify_cert_binding(None, None).is_ok());
        assert!(verify_cert_binding(Some(b"some-cert"), None).is_ok());
    }

    #[test]
    fn accepts_matching_certificate() {
        let cert_der = b"a fake DER-encoded certificate for testing";
        let thumbprint = x5t_s256_thumbprint(cert_der);
        let cnf = cnf_with_thumbprint(&thumbprint);

        assert!(verify_cert_binding(Some(cert_der), Some(&cnf)).is_ok());
    }

    #[test]
    fn rejects_mismatched_certificate() {
        let bound_cert = b"the certificate the token was actually bound to";
        let presented_cert = b"a different certificate presented on this connection";
        let thumbprint = x5t_s256_thumbprint(bound_cert);
        let cnf = cnf_with_thumbprint(&thumbprint);

        let err = verify_cert_binding(Some(presented_cert), Some(&cnf))
            .expect_err("a mismatched certificate must be rejected");
        assert!(matches!(err, ValidationError::InvalidToken(_)));
    }

    #[test]
    fn rejects_absent_certificate_for_a_certificate_bound_token() {
        let bound_cert = b"the certificate the token was actually bound to";
        let thumbprint = x5t_s256_thumbprint(bound_cert);
        let cnf = cnf_with_thumbprint(&thumbprint);

        // No certificate at all was presented on this connection.
        let err = verify_cert_binding(None, Some(&cnf)).expect_err(
            "a certificate-bound token must never be accepted with no certificate presented",
        );
        assert!(matches!(err, ValidationError::InvalidToken(_)));
    }

    #[test]
    fn accepts_when_cnf_is_present_but_has_no_x5t_s256_member() {
        // A `cnf` claim using a different confirmation method (e.g. `jkt`
        // for a key-bound token) is not an `x5t#S256` binding — but is
        // handled as "no certificate-binding claim" here, not "invalid",
        // since this function only speaks RFC 8705's `x5t#S256` shape.
        let cnf = serde_json::json!({ "jkt": "some-other-thumbprint" });
        assert!(verify_cert_binding(None, Some(&cnf)).is_ok());
        assert!(verify_cert_binding(Some(b"cert"), Some(&cnf)).is_ok());
    }

    /// Builds a JWS-shaped string with an arbitrary (unsigned) payload — enough
    /// for the pre-verification `iss` read, which never looks at the signature.
    fn token_with_payload(payload: serde_json::Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
            URL_SAFE_NO_PAD.encode(b"not-a-real-signature"),
        )
    }

    #[test]
    fn reads_the_issuer_out_of_an_unverified_payload() {
        let token =
            token_with_payload(serde_json::json!({ "iss": "https://a.example", "sub": "u" }));
        assert_eq!(
            unverified_issuer(&token).unwrap().as_deref(),
            Some("https://a.example")
        );
    }

    #[test]
    fn reports_no_issuer_when_the_claim_is_absent_or_not_a_string() {
        let no_iss = token_with_payload(serde_json::json!({ "sub": "u" }));
        assert_eq!(unverified_issuer(&no_iss).unwrap(), None);

        // RFC 7519 `iss` is a StringOrURI. `jsonwebtoken` tolerates an array
        // here, but an array names no single key to verify with, so it is
        // treated as "no issuer" and rejected by the resolver rather than
        // silently resolving to one of its members.
        let array_iss = token_with_payload(serde_json::json!({ "iss": ["a", "b"] }));
        assert_eq!(unverified_issuer(&array_iss).unwrap(), None);
    }

    #[test]
    fn rejects_a_token_that_is_not_a_well_formed_jws() {
        assert!(matches!(
            unverified_issuer("not.a-jwt"),
            Err(ValidationError::InvalidToken(_))
        ));
        assert!(matches!(
            unverified_issuer("aaa.!!!not-base64!!!.ccc"),
            Err(ValidationError::InvalidToken(_))
        ));
    }

    #[tokio::test]
    async fn trust_map_rejects_unknown_and_missing_issuers_without_falling_back() {
        let known = Arc::new(JwksCache::new(
            "https://a.example/jwks.json".to_string(),
            Duration::from_secs(60),
        ));
        let map = IssuerTrustMap::new().with_issuer("https://a.example", known);

        assert!(map.resolve(Some("https://a.example")).await.is_ok());
        assert!(matches!(
            map.resolve(Some("https://evil.example")).await,
            Err(ValidationError::UntrustedIssuer(iss)) if iss == "https://evil.example"
        ));
        assert!(matches!(
            map.resolve(None).await,
            Err(ValidationError::MissingIssuer)
        ));
    }

    // --- DPoP (RFC 9449) key binding — authkestra#274 Phase C ---

    mod dpop_binding_tests {
        use super::*;
        use crate::dpop::{DpopJtiRecord, NoDpopReplayStore};
        use authkestra_engine::store::memory::MemoryStore;
        use ed25519_dalek::{Signer, SigningKey};

        fn b64(bytes: &[u8]) -> String {
            URL_SAFE_NO_PAD.encode(bytes)
        }
        fn b64_json(v: &serde_json::Value) -> String {
            b64(serde_json::to_vec(v).unwrap().as_slice())
        }

        /// Builds a real, genuinely Ed25519-signed DPoP proof. Mirrors
        /// `authkestra_engine::token::dpop`'s own (private) `ProofBuilder`
        /// test helper — re-authored here since that one isn't reachable
        /// across the crate boundary.
        struct DpopProofBuilder {
            signing_key: SigningKey,
            jti: String,
            ath: Option<String>,
        }

        impl DpopProofBuilder {
            fn with_key_seed(seed: u8, jti: &str) -> Self {
                Self {
                    signing_key: SigningKey::from_bytes(&[seed; 32]),
                    jti: jti.to_string(),
                    ath: None,
                }
            }

            fn with_ath(mut self, ath: &str) -> Self {
                self.ath = Some(ath.to_string());
                self
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
                let mut payload = serde_json::json!({
                    "htm": "GET",
                    "htu": "https://resource.example.com/protected",
                    "iat": chrono::Utc::now().timestamp(),
                    "jti": self.jti,
                });
                if let Some(ath) = &self.ath {
                    payload["ath"] = serde_json::Value::String(ath.clone());
                }
                let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
                let signature = self.signing_key.sign(signing_input.as_bytes());
                format!("{signing_input}.{}", b64(&signature.to_bytes()))
            }
        }

        fn cnf_with_jkt(jkt: &str) -> serde_json::Value {
            serde_json::json!({ "jkt": jkt })
        }

        #[tokio::test]
        async fn accepts_when_no_cnf_jkt_present() {
            // Not a DPoP-bound token: nothing to check, with or without a
            // presented proof, and even with the fail-closed default store
            // wired — it must never be consulted for a token that isn't
            // DPoP-bound in the first place.
            assert!(
                verify_dpop_binding(None, "GET", None, "token", None, &NoDpopReplayStore)
                    .await
                    .is_ok()
            );
            assert!(verify_dpop_binding(
                Some("some-proof"),
                "GET",
                None,
                "token",
                Some(&serde_json::json!({ "x5t#S256": "unrelated" })),
                &NoDpopReplayStore,
            )
            .await
            .is_ok());
        }

        #[tokio::test]
        async fn accepts_a_valid_proof_bound_to_this_token() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            let builder = DpopProofBuilder::with_key_seed(11, "jti-1")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            verify_dpop_binding(
                Some(&builder.build()),
                "GET",
                None,
                access_token,
                Some(&cnf),
                &store,
            )
            .await
            .expect("a valid proof, bound to this token, for the cnf.jkt key must be accepted");
        }

        #[tokio::test]
        async fn rejects_a_missing_dpop_header_for_a_bound_token() {
            let builder = DpopProofBuilder::with_key_seed(11, "jti-2");
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err =
                verify_dpop_binding(None, "GET", None, "token", Some(&cnf), &NoDpopReplayStore)
                    .await
                    .expect_err("a DPoP-bound token presented with no proof must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_proof_for_a_different_key_than_cnf_jkt() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            let ath = x5t_s256_thumbprint(access_token.as_bytes());

            // `cnf.jkt` names the key from seed 11; the presented proof is
            // genuinely signed, just by a different key (seed 22).
            let bound = DpopProofBuilder::with_key_seed(11, "jti-3");
            let presented = DpopProofBuilder::with_key_seed(22, "jti-3").with_ath(&ath);
            let cnf = cnf_with_jkt(&bound.expected_jkt());

            let err = verify_dpop_binding(
                Some(&presented.build()),
                "GET",
                None,
                access_token,
                Some(&cnf),
                &store,
            )
            .await
            .expect_err("a proof for a different key than cnf.jkt must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_proof_bound_to_a_different_access_token() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let builder = DpopProofBuilder::with_key_seed(11, "jti-4")
                .with_ath(&x5t_s256_thumbprint(b"a-completely-different-token"));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(
                Some(&builder.build()),
                "GET",
                None,
                "the-actual-access-token",
                Some(&cnf),
                &store,
            )
            .await
            .expect_err("a proof whose ath binds a different access token must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_replayed_proof() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            let builder = DpopProofBuilder::with_key_seed(11, "jti-5")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());
            let proof = builder.build();

            verify_dpop_binding(Some(&proof), "GET", None, access_token, Some(&cnf), &store)
                .await
                .expect("first presentation of a fresh proof must succeed");

            let err =
                verify_dpop_binding(Some(&proof), "GET", None, access_token, Some(&cnf), &store)
                    .await
                    .expect_err("replaying the same proof must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn fails_closed_without_a_replay_store_wired() {
            let access_token = "the-access-token-string";
            let builder = DpopProofBuilder::with_key_seed(11, "jti-6")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(
                Some(&builder.build()),
                "GET",
                None,
                access_token,
                Some(&cnf),
                &NoDpopReplayStore,
            )
            .await
            .expect_err("no replay store is wired; an otherwise-valid proof must be refused");
            assert!(matches!(err, ValidationError::DpopReplayUnavailable(_)));
        }

        #[tokio::test]
        async fn rejects_a_proof_for_the_wrong_method() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            // `DpopProofBuilder::build` always signs "GET" as `htm`.
            let builder = DpopProofBuilder::with_key_seed(11, "jti-7")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(
                Some(&builder.build()),
                "POST",
                None,
                access_token,
                Some(&cnf),
                &store,
            )
            .await
            .expect_err("a proof signed for a different HTTP method must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }
    }

    mod dpop_header_tests {
        use super::{extract_dpop_header, ValidationError};

        #[test]
        fn no_header_is_none() {
            let headers = http::HeaderMap::new();
            assert_eq!(extract_dpop_header(&headers).unwrap(), None);
        }

        #[test]
        fn exactly_one_header_is_returned() {
            let mut headers = http::HeaderMap::new();
            headers.insert("DPoP", http::HeaderValue::from_static("proof-value"));
            assert_eq!(extract_dpop_header(&headers).unwrap(), Some("proof-value"));
        }

        /// RFC 9449 §4.1 expects exactly one `DPoP` header; a duplicate is
        /// refused outright rather than silently resolved by picking one.
        #[test]
        fn two_headers_are_rejected() {
            let mut headers = http::HeaderMap::new();
            headers.append("DPoP", http::HeaderValue::from_static("first"));
            headers.append("DPoP", http::HeaderValue::from_static("second"));
            let err =
                extract_dpop_header(&headers).expect_err("a duplicate header must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        /// A header value that isn't valid ASCII must be refused, not
        /// silently treated as "no header present".
        #[test]
        fn non_ascii_header_is_rejected() {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "DPoP",
                http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
            );
            let err =
                extract_dpop_header(&headers).expect_err("a non-ASCII header must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }
    }

    mod presented_token_tests {
        use super::{extract_presented_token, PresentedToken};

        fn authorization_headers(value: &str) -> http::HeaderMap {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_str(value).unwrap(),
            );
            headers
        }

        #[test]
        fn recognizes_bearer() {
            let headers = authorization_headers("Bearer abc123");
            assert!(matches!(
                extract_presented_token(&headers),
                Some(PresentedToken::Bearer("abc123"))
            ));
        }

        #[test]
        fn recognizes_dpop() {
            let headers = authorization_headers("DPoP abc123");
            assert!(matches!(
                extract_presented_token(&headers),
                Some(PresentedToken::DPoP("abc123"))
            ));
        }

        /// RFC 9110 §11.1: the auth-scheme token is case-insensitive. A
        /// client that lowercases (or otherwise re-cases) the scheme name
        /// must still be recognized, not silently treated as "no
        /// credential presented" — the DPoP scheme is new surface with no
        /// prior real-world clients to have already shaken this out.
        #[test]
        fn scheme_matching_is_case_insensitive() {
            for value in ["dpop abc123", "DPOP abc123", "DpoP abc123"] {
                assert!(
                    matches!(
                        extract_presented_token(&authorization_headers(value)),
                        Some(PresentedToken::DPoP("abc123"))
                    ),
                    "{value:?} must be recognized as the DPoP scheme"
                );
            }
            for value in ["bearer abc123", "BEARER abc123"] {
                assert!(
                    matches!(
                        extract_presented_token(&authorization_headers(value)),
                        Some(PresentedToken::Bearer("abc123"))
                    ),
                    "{value:?} must be recognized as the Bearer scheme"
                );
            }
        }

        #[test]
        fn unrecognized_scheme_is_none() {
            let headers = authorization_headers("Basic dXNlcjpwYXNz");
            assert!(extract_presented_token(&headers).is_none());
        }

        #[test]
        fn no_authorization_header_is_none() {
            assert!(extract_presented_token(&http::HeaderMap::new()).is_none());
        }
    }

    mod dpop_resource_origin_validation_tests {
        use super::ValidationConfig;

        #[test]
        fn a_well_formed_origin_is_accepted() {
            let config = ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("https://api.example.com")
                .build();
            assert_eq!(
                config.dpop_resource_origin.as_deref(),
                Some("https://api.example.com")
            );
        }

        /// A missing scheme would make every DPoP request fail: the
        /// reconstructed `htu` couldn't be parsed as an absolute URL,
        /// falling back to an exact-string comparison against the proof's
        /// genuine (scheme-carrying) `htu`, which can never match.
        #[test]
        #[should_panic(expected = "must be a valid absolute URL")]
        fn a_scheme_less_origin_panics() {
            ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("api.example.com")
                .build();
        }

        /// A trailing slash would double up with the request's own
        /// leading `/`, producing a `//` the genuine proof's `htu` never
        /// has — also failing every request.
        #[test]
        #[should_panic(expected = "trailing slash")]
        fn a_trailing_slash_origin_panics() {
            ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("https://api.example.com/")
                .build();
        }

        /// A query or fragment on the origin never survives `htu`
        /// canonicalization on the request side, so it could never match
        /// a genuine proof either — the same always-fails-every-request
        /// class as a missing scheme or a trailing slash.
        #[test]
        #[should_panic(expected = "query or fragment")]
        fn an_origin_with_a_query_panics() {
            ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("https://api.example.com?x=1")
                .build();
        }

        #[test]
        #[should_panic(expected = "query or fragment")]
        fn an_origin_with_a_fragment_panics() {
            ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("https://api.example.com#section")
                .build();
        }

        /// RFC 9110 §11.1's case-insensitive scheme applies just as much
        /// to this URL's own scheme as it does to the `Authorization`
        /// header's auth-scheme (`strip_scheme_ci`, elsewhere in this
        /// file) — `url::Url::parse` already normalizes it, so this must
        /// not panic.
        #[test]
        fn an_uppercase_scheme_is_accepted() {
            ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("HTTPS://api.example.com")
                .build();
        }

        #[test]
        #[should_panic(expected = "must use http or https")]
        fn a_non_http_scheme_panics() {
            ValidationConfig::builder()
                .jwks_url("https://issuer.example.com/.well-known/jwks.json")
                .dpop_resource_origin("ftp://api.example.com")
                .build();
        }
    }
}
