use serde::{Deserialize, Serialize};

/// OpenID Connect Discovery metadata document.
/// Served at `/.well-known/openid-configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OidcDiscovery {
    /// The OP's Issuer identifier.
    pub issuer: String,
    /// URL of the OP's OAuth 2.0 Authorization Endpoint.
    ///
    /// Omitted entirely (not sent as `null`) when this provider's
    /// `grant_types_supported` does not include `authorization_code` — e.g.
    /// a deployment that owns no users and only serves token-exchange
    /// and/or refresh_token grants has no `/authorize` route at all, so
    /// advertising one would point clients at an endpoint that 404s.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    /// JSON array of PKCE code challenge methods this OP supports (RFC 8414
    /// §2 / RFC 7636 §4.3).
    ///
    /// `handlers::authorize::handle_authorize` requires PKCE unconditionally
    /// for every client (authkestra#273) — this field exists so a
    /// spec-conformant client actually finds out, rather than discovering it
    /// only after being rejected. Omitted entirely, for the same reason
    /// `authorization_endpoint` is: a provider with no `authorization_code`
    /// grant has no `/authorize` endpoint for a `code_challenge_method` to
    /// apply to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// JSON array of JWS `alg` values this OP accepts in a DPoP proof's
    /// header (RFC 9449 §5).
    ///
    /// Opt-in via [`OidcDiscovery::with_dpop_support`], for the same reason
    /// `private_key_jwt` support is: `handlers::token::handle_token_with_client_cert`
    /// accepts a `DPoP` header unconditionally, but every request using one
    /// is refused with `invalid_dpop_proof` unless the deployment's
    /// `OpStore` also has a `DpopReplayStore` wired (it fails closed via
    /// `NoDpopReplayStore` otherwise — see `store::OpStore::check_and_record_dpop_jti`).
    /// A discovery document promising DPoP support the OP will reject at
    /// runtime is worse than one that stays quiet, so the decision belongs
    /// to whoever wired the store, exactly like `with_private_key_jwt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// URL of the OP's OAuth 2.0 Token Endpoint.
    pub token_endpoint: String,
    /// URL of the OP's OAuth 2.0 Device Authorization Endpoint (RFC 8628 §4).
    ///
    /// Populated from [`OpConfig::device_authorization_endpoint`] when
    /// `grant_types_supported` includes
    /// `"urn:ietf:params:oauth:grant-type:device_code"`, and omitted entirely
    /// (not sent as `null`) otherwise — mirroring [`Self::authorization_endpoint`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// URL of the OP's JSON Web Key Set document.
    pub jwks_uri: String,
    /// URL of the OP's UserInfo Endpoint.
    pub userinfo_endpoint: Option<String>,
    /// JSON array containing a list of the OAuth 2.0 scope values that this server supports.
    pub scopes_supported: Vec<String>,
    /// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
    pub response_types_supported: Vec<String>,
    /// JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
    pub response_modes_supported: Vec<String>,
    /// JSON array containing a list of the OAuth 2.0 grant type values that this OP supports.
    pub grant_types_supported: Vec<String>,
    /// JSON array containing a list of the Subject Identifier types that this OP supports.
    pub subject_types_supported: Vec<String>,
    /// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply.
    pub claims_supported: Vec<String>,
    /// URL of the OP's OAuth 2.0 revocation endpoint (RFC 7009), as defined
    /// by RFC 8414 §2.
    ///
    /// Omitted entirely (not sent as `null`) rather than populated from
    /// `OpConfig`, because whether a revocation route exists at all is not
    /// something `from_config` knows: `authkestra-op` does not ship a
    /// revocation handler itself, so this is only true once a consumer
    /// mounts its own RFC 7009 `/revoke` route on top of this crate's token
    /// endpoint and stores. See [`OidcDiscovery::with_revocation_endpoint`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
}

use crate::config::OpConfig;

impl OidcDiscovery {
    /// Creates a discovery document reflecting the provided OP configuration.
    pub fn from_config(config: &OpConfig) -> Self {
        let has_authorization_code_grant = config
            .grant_types_supported
            .iter()
            .any(|grant| grant == "authorization_code");
        let has_device_code_grant = config
            .grant_types_supported
            .iter()
            .any(|grant| grant == "urn:ietf:params:oauth:grant-type:device_code");
        tracing::debug!(
            has_authorization_code_grant,
            has_device_code_grant,
            "building OIDC discovery document from config"
        );

        Self {
            issuer: config.issuer.clone(),
            authorization_endpoint: has_authorization_code_grant
                .then(|| config.authorization_endpoint()),
            code_challenge_methods_supported: has_authorization_code_grant
                .then(|| vec!["S256".to_string()]),
            dpop_signing_alg_values_supported: None,
            token_endpoint: config.token_endpoint(),
            device_authorization_endpoint: has_device_code_grant
                .then(|| config.device_authorization_endpoint()),
            jwks_uri: config.jwks_url(),
            userinfo_endpoint: Some(config.userinfo_endpoint()),
            scopes_supported: config.scopes_supported.clone(),
            response_types_supported: config.response_types_supported.clone(),
            response_modes_supported: vec!["query".to_string()],
            grant_types_supported: config.grant_types_supported.clone(),
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec![config.id_token_signing_alg.clone()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "none".to_string(), // For public clients (PKCE)
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "name".to_string(),
                "email".to_string(),
            ],
            revocation_endpoint: None,
        }
    }

    /// Advertises `private_key_jwt` (RFC 7523 §2.2) in
    /// `token_endpoint_auth_methods_supported`.
    ///
    /// Opt-in rather than part of [`OidcDiscovery::from_config`], because
    /// whether this OP will actually honour an assertion is not something
    /// `OpConfig` knows: the token endpoint implements the method
    /// unconditionally, but it refuses every assertion unless the deployment's
    /// `OpStore` also tracks spent `jti`s (see
    /// `OpStore::record_client_assertion_jti`, which fails closed). A
    /// discovery document promising a method the OP will reject at runtime is
    /// worse than one that stays quiet, so the decision belongs to whoever
    /// wired the store — call this alongside
    /// `CompositeOpStore::with_client_assertion_store`.
    pub fn with_private_key_jwt(mut self) -> Self {
        let method = "private_key_jwt".to_string();
        if !self.token_endpoint_auth_methods_supported.contains(&method) {
            self.token_endpoint_auth_methods_supported.push(method);
        }
        self
    }

    /// Advertises DPoP support (RFC 9449 §5) with the algorithms
    /// `authkestra_engine::token::dpop::verify_dpop_proof` accepts.
    ///
    /// Opt-in for the same reason [`OidcDiscovery::with_private_key_jwt`]
    /// is — see this field's doc comment. Call alongside
    /// `CompositeOpStore::with_dpop_replay_store` once that's wired.
    ///
    /// **Resource-server note (authkestra#274 Phase C):** the bundled
    /// `authkestra-resource` `JwtStrategy` can check `cnf.jkt` too, but it
    /// is its own opt-in —
    /// `ValidationConfig::require_dpop`/`ValidationConfigBuilder::require_dpop`
    /// on that crate's side, off by default for the same backward-
    /// compatibility reason this method is. Calling `with_dpop_support`
    /// here only affects what this OP *advertises*; a deployment must
    /// separately enable `require_dpop` (and wire a
    /// `JwtStrategy::with_dpop_replay_store`) on the resource-server side
    /// for a DPoP-bound access token to actually be rejected there when
    /// presented without a matching proof. A client that sees DPoP
    /// advertised should not assume every resource server behind it has
    /// necessarily turned that check on.
    pub fn with_dpop_support(mut self) -> Self {
        self.dpop_signing_alg_values_supported = Some(vec![
            "ES256".to_string(),
            "ES384".to_string(),
            "RS256".to_string(),
            "EdDSA".to_string(),
        ]);
        self
    }

    /// Advertises `revocation_endpoint` (RFC 8414 §2) at the given URL.
    ///
    /// Opt-in rather than part of [`OidcDiscovery::from_config`] for the
    /// same reason `private_key_jwt` support is layered on via
    /// [`OidcDiscovery::with_private_key_jwt`] rather than baked into
    /// `from_config`: `OpConfig` has no notion of a revocation route, since
    /// `authkestra-op` doesn't implement RFC 7009 itself. A consumer that
    /// mounts its own `/revoke` handler on top of this crate's token
    /// endpoint and stores should call this once that route exists, rather
    /// than every `from_config` caller being forced to supply a URL for an
    /// endpoint that may not exist.
    pub fn with_revocation_endpoint(mut self, url: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(url.into());
        self
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_discovery_from_config() {
        let config = OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        };

        let doc = OidcDiscovery::from_config(&config);

        assert_eq!(doc.issuer, "https://auth.example.com");
        assert_eq!(
            doc.authorization_endpoint,
            Some("https://auth.example.com/authorize".to_string())
        );
        assert_eq!(doc.token_endpoint, "https://auth.example.com/token");
        assert_eq!(doc.jwks_uri, "https://auth.example.com/jwks.json");
        assert_eq!(
            doc.userinfo_endpoint,
            Some("https://auth.example.com/userinfo".to_string())
        );

        assert_eq!(doc.scopes_supported.len(), 2);
        assert!(doc.response_types_supported.contains(&"code".to_string()));
        assert!(doc
            .grant_types_supported
            .contains(&"authorization_code".to_string()));
        assert!(!doc
            .grant_types_supported
            .contains(&"client_credentials".to_string()));
        assert!(doc
            .id_token_signing_alg_values_supported
            .contains(&"RS256".to_string()));
    }

    fn discovery_config() -> OpConfig {
        OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec!["openid".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        }
    }

    /// The document must not promise a method the deployment may not have
    /// wired a replay store for — silence is the honest default.
    #[test]
    fn private_key_jwt_is_not_advertised_by_default() {
        let doc = OidcDiscovery::from_config(&discovery_config());
        assert!(!doc
            .token_endpoint_auth_methods_supported
            .contains(&"private_key_jwt".to_string()));
    }

    #[test]
    fn private_key_jwt_is_advertised_once_when_opted_in() {
        let doc = OidcDiscovery::from_config(&discovery_config())
            .with_private_key_jwt()
            .with_private_key_jwt();

        assert_eq!(
            doc.token_endpoint_auth_methods_supported
                .iter()
                .filter(|m| *m == "private_key_jwt")
                .count(),
            1
        );
        // The methods that were already supported are untouched.
        assert!(doc
            .token_endpoint_auth_methods_supported
            .contains(&"client_secret_basic".to_string()));
    }

    /// A discovery document must not promise DPoP support the OP will
    /// reject at runtime because no replay store is wired — same rationale
    /// as `private_key_jwt_is_not_advertised_by_default`.
    #[test]
    fn dpop_is_not_advertised_by_default() {
        let doc = OidcDiscovery::from_config(&discovery_config());
        assert_eq!(doc.dpop_signing_alg_values_supported, None);

        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json.get("dpop_signing_alg_values_supported").is_none(),
            "must be omitted (not null) when not opted in"
        );
    }

    #[test]
    fn dpop_is_advertised_once_opted_in() {
        let doc = OidcDiscovery::from_config(&discovery_config()).with_dpop_support();

        let algs = doc
            .dpop_signing_alg_values_supported
            .expect("must be Some once opted in");
        assert!(algs.contains(&"ES256".to_string()));
        assert!(algs.contains(&"EdDSA".to_string()));
    }

    /// A provider that serves no `authorization_code` grant (e.g. a
    /// token-exchange-only deployment with no `/authorize` route at all)
    /// must not advertise an `authorization_endpoint` that 404s. Asserted
    /// against the serialized JSON, not the Rust field, so this test's
    /// expectations hold regardless of whether the field is typed as a
    /// plain `String` or an omittable `Option<String>`.
    #[test]
    fn authorization_endpoint_omitted_when_no_auth_code_grant() {
        let mut config = discovery_config();
        config.grant_types_supported = vec![
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "refresh_token".to_string(),
        ];
        config.response_types_supported = vec![];

        let doc = OidcDiscovery::from_config(&config);
        let json = serde_json::to_value(&doc).unwrap();

        assert!(
            json.get("authorization_endpoint").is_none(),
            "a provider serving no authorization_code grant must not advertise \
             an authorization_endpoint that 404s; got {:?}",
            json.get("authorization_endpoint")
        );
    }

    /// A provider that does serve `authorization_code` must keep advertising
    /// `authorization_endpoint` exactly as before — byte-identical JSON, not
    /// just field presence.
    #[test]
    fn authorization_endpoint_present_and_byte_identical_when_auth_code_grant_supported() {
        let doc = OidcDiscovery::from_config(&discovery_config());
        let json = serde_json::to_value(&doc).unwrap();

        assert_eq!(
            json.get("authorization_endpoint"),
            Some(&serde_json::Value::String(
                "https://auth.example.com/authorize".to_string()
            ))
        );
    }

    /// authkestra#273: PKCE is mandatory at `/authorize` for every client —
    /// a provider that serves the `authorization_code` grant must advertise
    /// that, so a spec-conformant client finds out before being rejected
    /// rather than after.
    #[test]
    fn code_challenge_methods_supported_advertises_s256_when_auth_code_grant_supported() {
        let doc = OidcDiscovery::from_config(&discovery_config());
        assert_eq!(
            doc.code_challenge_methods_supported,
            Some(vec!["S256".to_string()])
        );
    }

    /// A provider with no `authorization_code` grant has no `/authorize`
    /// endpoint for a code challenge method to apply to — must be omitted
    /// entirely, mirroring `authorization_endpoint`'s own omission rule.
    #[test]
    fn code_challenge_methods_supported_omitted_when_no_auth_code_grant() {
        let mut config = discovery_config();
        config.grant_types_supported = vec![
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "refresh_token".to_string(),
        ];
        config.response_types_supported = vec![];

        let doc = OidcDiscovery::from_config(&config);
        assert_eq!(doc.code_challenge_methods_supported, None);

        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json.get("code_challenge_methods_supported").is_none(),
            "must be omitted (not null) when the provider has no authorization_code grant; got {:?}",
            json.get("code_challenge_methods_supported")
        );
    }

    /// `from_config` alone must not advertise a revocation endpoint:
    /// `authkestra-op` doesn't implement RFC 7009 itself, so promising one
    /// by default would point clients at a route that may not exist.
    #[test]
    fn revocation_endpoint_not_advertised_by_default() {
        let doc = OidcDiscovery::from_config(&discovery_config());

        // Assert on the field itself, not just the serialized key: a JSON-only
        // check would pass even if the field were removed entirely, since an
        // absent key is trivially absent.
        assert!(
            doc.revocation_endpoint.is_none(),
            "from_config must leave revocation_endpoint unset; got {:?}",
            doc.revocation_endpoint
        );

        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json.get("revocation_endpoint").is_none(),
            "revocation_endpoint must be omitted (not null) when not opted in; got {:?}",
            json.get("revocation_endpoint")
        );
    }

    #[test]
    fn revocation_endpoint_advertised_once_opted_in() {
        let doc = OidcDiscovery::from_config(&discovery_config())
            .with_revocation_endpoint("https://auth.example.com/oauth2/revoke");

        assert_eq!(
            doc.revocation_endpoint,
            Some("https://auth.example.com/oauth2/revoke".to_string())
        );

        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(
            json.get("revocation_endpoint"),
            Some(&serde_json::Value::String(
                "https://auth.example.com/oauth2/revoke".to_string()
            ))
        );
    }

    /// A discovery document that advertises `revocation_endpoint` must
    /// surface it back on deserialization (RFC 8414 §2).
    #[test]
    fn deserializes_revocation_endpoint_when_present() {
        let json = serde_json::json!({
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks.json",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
            "scopes_supported": ["openid"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "claims_supported": ["sub"],
            "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
        });

        let doc: OidcDiscovery = serde_json::from_value(json).unwrap();

        assert_eq!(
            doc.revocation_endpoint,
            Some("https://auth.example.com/oauth2/revoke".to_string())
        );
    }

    /// A discovery document with no `revocation_endpoint` field at all must
    /// still parse, with the field defaulting to `None`.
    #[test]
    fn deserializes_without_revocation_endpoint() {
        let json = serde_json::json!({
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks.json",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
            "scopes_supported": ["openid"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "claims_supported": ["sub"],
        });

        let doc: OidcDiscovery = serde_json::from_value(json).unwrap();

        assert_eq!(doc.revocation_endpoint, None);
    }

    #[test]
    fn device_authorization_endpoint_advertised_when_device_code_grant_supported() {
        let mut config = discovery_config();
        config.grant_types_supported = vec![
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ];

        let doc = OidcDiscovery::from_config(&config);
        assert_eq!(
            doc.device_authorization_endpoint,
            Some("https://auth.example.com/device_authorization".to_string())
        );

        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(
            json.get("device_authorization_endpoint"),
            Some(&serde_json::Value::String(
                "https://auth.example.com/device_authorization".to_string()
            ))
        );
    }

    #[test]
    fn device_authorization_endpoint_omitted_when_no_device_code_grant() {
        let doc = OidcDiscovery::from_config(&discovery_config());
        assert_eq!(doc.device_authorization_endpoint, None);

        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json.get("device_authorization_endpoint").is_none(),
            "device_authorization_endpoint must be omitted (not null) when device_code grant is not supported; got {:?}",
            json.get("device_authorization_endpoint")
        );
    }
}
