use serde::{Deserialize, Serialize};

/// Provider-level configuration used to answer discovery requests and
/// validate incoming `/authorize` and `/token` requests.
///
/// This is deliberately separate from any single `ClientRegistration` —
/// it describes what the *provider* supports, not what one client is
/// permitted to use (that's `ClientRegistration::scopes`/`grant_types`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpConfig {
    /// The issuer URL, used as the `iss` claim on issued tokens and as the
    /// base for discovery/JWKS endpoint URLs. No trailing slash.
    pub issuer: String,
    /// Scopes this provider is willing to grant, across all clients. A
    /// client's own `scopes` list (see `ClientRegistration`) is further
    /// restricted to a subset of this.
    pub scopes_supported: Vec<String>,
    /// Response types supported at `/authorize`. Start with `["code"]`
    /// only — no implicit or hybrid flows, per OAuth 2.1.
    pub response_types_supported: Vec<String>,
    /// Grant types supported at `/token`.
    pub grant_types_supported: Vec<String>,
    /// Signing algorithm for ID tokens. Must be an asymmetric algorithm
    /// (e.g. `"RS256"`) — see RFC-003 §4. Symmetric algorithms (`HS256`)
    /// are intentionally not valid here.
    pub id_token_signing_alg: String,
    /// Lifetime, in seconds, of issued authorization codes. Keep short
    /// (RFC-003 §7 recommends ≤60).
    pub authorization_code_ttl_secs: i64,
    /// Lifetime, in seconds, of issued access tokens.
    pub access_token_ttl_secs: u64,
    /// Lifetime, in seconds, of issued device codes.
    pub device_code_ttl_secs: u64,
    /// Whether the Token Exchange grant type (RFC 8693) is enabled.
    /// Default is false to prevent accidental exposure of delegation endpoints.
    #[serde(default)]
    pub token_exchange_enabled: bool,
}

impl OpConfig {
    /// Builds the well-known discovery document URL for this issuer.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }

    /// Builds the JWKS endpoint URL for this issuer.
    pub fn jwks_url(&self) -> String {
        format!("{}/jwks.json", self.issuer)
    }

    /// Builds the authorization endpoint URL for this issuer.
    pub fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.issuer)
    }

    /// Builds the token endpoint URL for this issuer.
    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer)
    }

    /// Builds the userinfo endpoint URL for this issuer.
    pub fn userinfo_endpoint(&self) -> String {
        format!("{}/userinfo", self.issuer)
    }

    /// Builds the device authorization endpoint URL for this issuer.
    pub fn device_authorization_endpoint(&self) -> String {
        format!("{}/device_authorization", self.issuer)
    }

    /// Builds the verification URI for the device flow.
    pub fn device_verification_uri(&self) -> String {
        format!("{}/device", self.issuer)
    }

    /// Returns true if the given scope is supported by the provider.
    /// If `scopes_supported` is unconfigured (empty), all scopes are permitted by the provider ceiling.
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.scopes_supported.is_empty() || self.scopes_supported.iter().any(|s| s == scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_urls() {
        let config = OpConfig {
            issuer: "http://example.com".into(),
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            id_token_signing_alg: "RS256".into(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 300,
            token_exchange_enabled: false,
        };

        assert_eq!(
            config.discovery_url(),
            "http://example.com/.well-known/openid-configuration"
        );
        assert_eq!(config.jwks_url(), "http://example.com/jwks.json");
        assert_eq!(
            config.authorization_endpoint(),
            "http://example.com/authorize"
        );
        assert_eq!(config.token_endpoint(), "http://example.com/token");
        assert_eq!(config.userinfo_endpoint(), "http://example.com/userinfo");
        assert_eq!(
            config.device_authorization_endpoint(),
            "http://example.com/device_authorization"
        );
        assert_eq!(
            config.device_verification_uri(),
            "http://example.com/device"
        );

        // When scopes_supported is empty, any scope is allowed
        assert!(config.allows_scope("openid"));
        assert!(config.allows_scope("custom"));

        // When scopes_supported is configured, only listed scopes are allowed
        let mut restricted = config;
        restricted.scopes_supported = vec!["openid".to_string(), "profile".to_string()];
        assert!(restricted.allows_scope("openid"));
        assert!(restricted.allows_scope("profile"));
        assert!(!restricted.allows_scope("admin"));
    }
}
