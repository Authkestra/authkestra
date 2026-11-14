//! Structured protected-resource refusals and RFC 9470 step-up challenges
//! (`WWW-Authenticate`, `DPoP-Nonce`, and JSON error bodies).
//!
//! Mirrors `authkestra_devsig::Refusal` for OAuth 2.0 / OIDC / DPoP resource
//! servers: instead of collapsing every verification failure to `Ok(None)` or
//! an untyped string, [`ResourceRefusal`] preserves the HTTP status, the
//! authentication scheme (`Bearer` vs `DPoP`), the OAuth error code
//! (`invalid_token`, `invalid_dpop_proof`, `use_dpop_nonce`,
//! `insufficient_user_authentication`), optional RFC 9470 `acr_values` /
//! `max_age` challenge parameters, and an optional fresh `DPoP-Nonce` header
//! value (RFC 9449 §9).

use std::time::{SystemTime, UNIX_EPOCH};

use super::dpop_nonce::USE_DPOP_NONCE;
use super::{Claims, DEFAULT_LEEWAY_SECS};

/// RFC 9470 §3 OAuth 2.0 step-up authentication challenge error code.
pub const INSUFFICIENT_USER_AUTHENTICATION: &str = "insufficient_user_authentication";

/// The authentication scheme named in a protected resource's
/// `WWW-Authenticate` challenge header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthScheme {
    /// `WWW-Authenticate: Bearer ...` (RFC 6750 §3).
    Bearer,
    /// `WWW-Authenticate: DPoP ...` (RFC 9449 §7.1).
    DPoP,
}

impl AuthScheme {
    /// Returns the wire scheme token (`"Bearer"` or `"DPoP"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthScheme::Bearer => "Bearer",
            AuthScheme::DPoP => "DPoP",
        }
    }
}

/// How a refused protected-resource request goes out on the wire (RFC 6750 §3,
/// RFC 9449 §7.1 / §9, and RFC 9470 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceRefusal {
    /// HTTP status code (`401` for client/credential challenges, `503` for
    /// temporary verification unavailability, `500` for internal errors).
    pub status: u16,
    /// The authentication scheme (`Bearer` or `DPoP`).
    pub scheme: AuthScheme,
    /// The OAuth error code (`invalid_token`, `invalid_dpop_proof`,
    /// `use_dpop_nonce`, `insufficient_user_authentication`, ...).
    pub error: String,
    /// Optional human-readable description.
    pub error_description: Option<String>,
    /// Optional RFC 9470 §3 `acr_values` parameter for step-up challenges.
    pub acr_values: Option<String>,
    /// Optional RFC 9470 §3 `max_age` parameter (seconds) for step-up challenges.
    pub max_age: Option<u64>,
    /// Optional fresh server-issued `DPoP-Nonce` header value (RFC 9449 §9).
    pub dpop_nonce: Option<String>,
}

impl ResourceRefusal {
    /// `401 invalid_token` under `scheme` (RFC 6750 §3.1 / RFC 9449 §7.1).
    pub fn invalid_token(scheme: AuthScheme, description: impl Into<String>) -> Self {
        Self {
            status: 401,
            scheme,
            error: "invalid_token".to_string(),
            error_description: Some(description.into()),
            acr_values: None,
            max_age: None,
            dpop_nonce: None,
        }
    }

    /// `401 invalid_dpop_proof` under the `DPoP` scheme (RFC 9449 §7.1).
    pub fn invalid_dpop_proof(description: impl Into<String>) -> Self {
        Self {
            status: 401,
            scheme: AuthScheme::DPoP,
            error: "invalid_dpop_proof".to_string(),
            error_description: Some(description.into()),
            acr_values: None,
            max_age: None,
            dpop_nonce: None,
        }
    }

    /// `401 use_dpop_nonce` under the `DPoP` scheme, carrying a fresh
    /// `DPoP-Nonce` response header value (RFC 9449 §9).
    pub fn use_dpop_nonce(fresh_nonce: impl Into<String>) -> Self {
        Self {
            status: 401,
            scheme: AuthScheme::DPoP,
            error: USE_DPOP_NONCE.to_string(),
            error_description: Some("Resource server requires nonce in DPoP proof".to_string()),
            acr_values: None,
            max_age: None,
            dpop_nonce: Some(fresh_nonce.into()),
        }
    }

    /// `401 insufficient_user_authentication` (RFC 9470 §3) step-up challenge.
    pub fn insufficient_user_authentication(
        scheme: AuthScheme,
        acr_values: Option<String>,
        max_age: Option<u64>,
        description: Option<String>,
    ) -> Self {
        Self {
            status: 401,
            scheme,
            error: INSUFFICIENT_USER_AUTHENTICATION.to_string(),
            error_description: description,
            acr_values,
            max_age,
            dpop_nonce: None,
        }
    }

    /// `503 temporarily_unavailable` when a dependency required to verify the
    /// credential (e.g. a JWKS endpoint or DPoP replay store) is unreachable.
    pub fn temporarily_unavailable(scheme: AuthScheme, description: impl Into<String>) -> Self {
        Self {
            status: 503,
            scheme,
            error: "temporarily_unavailable".to_string(),
            error_description: Some(description.into()),
            acr_values: None,
            max_age: None,
            dpop_nonce: None,
        }
    }

    /// `500 server_error` for internal authentication strategy failures.
    pub fn internal_error(description: impl Into<String>) -> Self {
        Self {
            status: 500,
            scheme: AuthScheme::Bearer,
            error: "server_error".to_string(),
            error_description: Some(description.into()),
            acr_values: None,
            max_age: None,
            dpop_nonce: None,
        }
    }

    /// Attaches a fresh `DPoP-Nonce` header value to this refusal.
    pub fn with_dpop_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.dpop_nonce = Some(nonce.into());
        self
    }

    /// Renders the `WWW-Authenticate` header value for a `401` refusal, or
    /// `None` for non-`401` statuses.
    pub fn www_authenticate(&self) -> Option<String> {
        if self.status != 401 {
            return None;
        }
        let mut params = vec![format!("error=\"{}\"", escape_quoted(&self.error))];
        if let Some(desc) = &self.error_description {
            params.push(format!("error_description=\"{}\"", escape_quoted(desc)));
        }
        if let Some(acr) = &self.acr_values {
            params.push(format!("acr_values=\"{}\"", escape_quoted(acr)));
        }
        if let Some(max_age) = self.max_age {
            params.push(format!("max_age=\"{max_age}\""));
        }
        Some(format!("{} {}", self.scheme.as_str(), params.join(", ")))
    }

    /// Renders the JSON response body for this refusal.
    pub fn body(&self) -> String {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "error".to_string(),
            serde_json::Value::String(self.error.clone()),
        );
        if let Some(desc) = &self.error_description {
            obj.insert(
                "error_description".to_string(),
                serde_json::Value::String(desc.clone()),
            );
        }
        if let Some(acr) = &self.acr_values {
            obj.insert(
                "acr_values".to_string(),
                serde_json::Value::String(acr.clone()),
            );
        }
        if let Some(max_age) = self.max_age {
            obj.insert("max_age".to_string(), serde_json::json!(max_age));
        }
        serde_json::Value::Object(obj).to_string()
    }
}

fn escape_quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// RFC 9470 OAuth 2.0 Step-Up Authentication Challenge requirement for a
/// protected resource route (`acr_values` and/or `max_age`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StepUpRequirement {
    /// Acceptable `acr` values (space-separated, in preference order per RFC 9470 §3).
    pub acr_values: Option<String>,
    /// Maximum allowable elapsed seconds since `auth_time` (RFC 9470 §3).
    pub max_age: Option<u64>,
}

impl StepUpRequirement {
    /// Creates an empty step-up requirement (no `acr_values`, no `max_age`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires the token's `acr` claim to match one of the space-separated
    /// values in `acr_values`.
    pub fn with_acr_values(mut self, acr_values: impl Into<String>) -> Self {
        self.acr_values = Some(acr_values.into());
        self
    }

    /// Requires the token's `auth_time` claim to be within `max_age` seconds of
    /// the verification time.
    pub fn with_max_age(mut self, max_age: u64) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Evaluates this requirement against decoded [`Claims`] at the current
    /// system clock time.
    pub fn check(&self, claims: &Claims, scheme: AuthScheme) -> Result<(), ResourceRefusal> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.check_at(claims, scheme, now)
    }

    /// Evaluates this requirement against decoded [`Claims`] at Unix epoch
    /// timestamp `now`.
    pub fn check_at(
        &self,
        claims: &Claims,
        scheme: AuthScheme,
        now: i64,
    ) -> Result<(), ResourceRefusal> {
        let token_acr = claims.extra.get("acr").and_then(|v| v.as_str());
        let auth_time = claims.extra.get("auth_time").and_then(|v| v.as_i64());
        self.check_values_at(token_acr, auth_time, scheme, now)
    }

    /// Evaluates this requirement against extracted `acr` and `auth_time`
    /// values at the current system clock time.
    pub fn check_values(
        &self,
        token_acr: Option<&str>,
        auth_time: Option<i64>,
        scheme: AuthScheme,
    ) -> Result<(), ResourceRefusal> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.check_values_at(token_acr, auth_time, scheme, now)
    }

    /// Evaluates this requirement against extracted `acr` and `auth_time`
    /// values at Unix epoch timestamp `now`.
    pub fn check_values_at(
        &self,
        token_acr: Option<&str>,
        auth_time: Option<i64>,
        scheme: AuthScheme,
        now: i64,
    ) -> Result<(), ResourceRefusal> {
        if let Some(required_acrs) = self.acr_values.as_deref().filter(|s| !s.is_empty()) {
            let matches_acr = token_acr
                .is_some_and(|actual| required_acrs.split_whitespace().any(|req| req == actual));
            if !matches_acr {
                tracing::info!(
                    token_acr = ?token_acr,
                    required_acr = %required_acrs,
                    "token does not satisfy route acr_values requirement; issuing RFC 9470 step-up challenge"
                );
                return Err(ResourceRefusal::insufficient_user_authentication(
                    scheme,
                    self.acr_values.clone(),
                    self.max_age,
                    Some("A higher authentication context class is required".to_string()),
                ));
            }
        }

        if let Some(max_age) = self.max_age {
            let fresh = auth_time.is_some_and(|at| {
                at <= now.saturating_add(DEFAULT_LEEWAY_SECS as i64)
                    && now.saturating_sub(at) <= max_age as i64
            });
            if !fresh {
                tracing::info!(
                    auth_time = ?auth_time,
                    max_age,
                    now,
                    "token auth_time does not satisfy route max_age requirement; issuing RFC 9470 step-up challenge"
                );
                return Err(ResourceRefusal::insufficient_user_authentication(
                    scheme,
                    self.acr_values.clone(),
                    self.max_age,
                    Some("Authentication is older than the maximum allowed age".to_string()),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_dpop_nonce_refusal_renders_challenge_and_nonce() {
        let refusal = ResourceRefusal::use_dpop_nonce("nonce-123");
        assert_eq!(refusal.status, 401);
        assert_eq!(refusal.dpop_nonce.as_deref(), Some("nonce-123"));
        assert_eq!(
            refusal.www_authenticate().as_deref(),
            Some(
                r#"DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof""#
            )
        );
    }

    #[test]
    fn step_up_requirement_checks_acr_and_max_age() {
        let req = StepUpRequirement::new()
            .with_acr_values("urn:authkestra:acr:mfa")
            .with_max_age(300);

        // Satisfies both
        assert!(req
            .check_values_at(
                Some("urn:authkestra:acr:mfa"),
                Some(1_000),
                AuthScheme::Bearer,
                1_200,
            )
            .is_ok());

        // Wrong ACR -> insufficient_user_authentication with acr_values and max_age
        let wrong_acr = req
            .check_values_at(
                Some("urn:authkestra:acr:single-factor"),
                Some(1_000),
                AuthScheme::Bearer,
                1_200,
            )
            .unwrap_err();
        assert_eq!(wrong_acr.status, 401);
        assert_eq!(wrong_acr.error, INSUFFICIENT_USER_AUTHENTICATION);
        assert_eq!(
            wrong_acr.acr_values.as_deref(),
            Some("urn:authkestra:acr:mfa")
        );
        assert_eq!(wrong_acr.max_age, Some(300));
        assert!(wrong_acr
            .www_authenticate()
            .unwrap()
            .contains(r#"acr_values="urn:authkestra:acr:mfa""#));

        // Stale auth_time -> insufficient_user_authentication
        let stale = req
            .check_values_at(
                Some("urn:authkestra:acr:mfa"),
                Some(1_000),
                AuthScheme::DPoP,
                1_400,
            )
            .unwrap_err();
        assert_eq!(stale.status, 401);
        assert_eq!(stale.scheme, AuthScheme::DPoP);
        assert_eq!(stale.error, INSUFFICIENT_USER_AUTHENTICATION);
    }
}
